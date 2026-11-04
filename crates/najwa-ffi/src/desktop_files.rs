//! Bounded, durable attachment preparation. Raw input is sanitized before it
//! reaches SQLCipher; the job and normal encrypted outbox survive restarts.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use najwa_core::{
    disappearing::{open_sealed_content, Opened, VolatileKeyCache},
    filetransfer::FileTransferManager,
};
use najwa_protocol::message::{
    file_transfer::{FileChunkWire, FileMetadata, MAX_CHUNK_SIZE},
    TextReplyContent,
};
use najwa_storage::types::{ContentType as StoredType, Message as StoredMessage, MessageDirection};
use std::collections::BTreeMap;

pub const MAX_BROWSER_FILE: usize = 8 * 1024 * 1024;
static FILE_BUSY: AtomicBool = AtomicBool::new(false);
struct Admission;
impl Drop for Admission {
    fn drop(&mut self) {
        FILE_BUSY.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub filename: String,
    pub size: u64,
    pub chunks: u32,
    pub available_chunks: u32,
    pub deposited_chunks: u32,
    pub complete: bool,
    pub supported: bool,
    /// S11 §4.1: incoming and incomplete after every FileChunkNack attempt.
    pub failed: bool,
}

pub(super) fn decode_id(v: &str) -> Result<[u8; 16]> {
    if v.len() != 32 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DesktopError::new("invalid_message"));
    }
    let mut id = [0; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16)
            .map_err(|_| DesktopError::new("invalid_message"))?;
    }
    Ok(id)
}
pub(super) fn filename(v: &str) -> String {
    let v: String = v
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("attachment")
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                // S11 §2.5: bidi and zero-width controls can disguise the extension.
                && !matches!(
                    c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{061C}'
                        | '\u{FEFF}'
                )
        })
        .take(120)
        .collect();
    let v = v.trim_matches([' ', '.']);
    if v.is_empty() {
        return "attachment".into();
    }
    // Windows reserved device names, with or without an extension (S11 §2.5).
    let stem = v.split('.').next().unwrap_or(v).trim_end().to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        format!("_{v}")
    } else {
        v.to_string()
    }
}
/// S11 §2.5: the WebP rename, fitted to the 255-byte `FileMetadata` bound by
/// truncating the base name on a UTF-8 boundary.
pub(super) fn metadata_filename(name: &str, webp: bool) -> String {
    let (base, extension) = if webp {
        (name.rsplit_once('.').map_or(name, |(stem, _)| stem), ".webp")
    } else {
        (name, "")
    };
    let mut end = base.len().min(255 - extension.len());
    while !base.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{extension}", &base[..end])
}
pub(super) fn visible_rows(
    db: &SqliteStorage,
    cache: &VolatileKeyCache,
    cid: i64,
) -> Result<Vec<StoredMessage>> {
    let mut result = Vec::new();
    for mut row in storage(db.browser_messages(cid))? {
        if row
            .disappear_at
            .is_some_and(|at| at <= najwa_crypto::time::now_ms())
        {
            cache.remove_key(&row.msg_id);
            continue;
        }
        if row.disappear_timer.is_some() {
            match open_sealed_content(cache, &row.msg_id, &row.content)
                .map_err(|_| DesktopError::new("storage_unavailable"))?
            {
                Opened::Plaintext(bytes) => row.content = bytes,
                Opened::Expired => continue,
            }
        }
        result.push(row);
    }
    Ok(result)
}
fn chunks(
    db: &SqliteStorage,
    row: &StoredMessage,
    meta: &FileMetadata,
) -> Result<BTreeMap<u32, (Vec<u8>, &'static str)>> {
    let mut chunks = BTreeMap::new();
    for stored in storage(db.attachment_rows(
        row.contact_id,
        &meta.session_id,
        row.direction == MessageDirection::Sent,
    ))? {
        let chunk = FileChunkWire::from_bytes(&stored.content)
            .map_err(|_| DesktopError::new("invalid_file"))?;
        if chunk.index >= meta.chunk_count {
            return Err(DesktopError::new("invalid_file"));
        }
        let expected = if chunk.index + 1 == meta.chunk_count {
            (meta.total_size as usize).saturating_sub(chunk.index as usize * MAX_CHUNK_SIZE)
        } else {
            MAX_CHUNK_SIZE
        };
        if chunk.data.len() != expected {
            return Err(DesktopError::new("invalid_file"));
        }
        if let Some((existing, _)) = chunks.get(&chunk.index) {
            if existing != &chunk.data {
                return Err(DesktopError::new("invalid_file"));
            }
        }
        chunks.insert(chunk.index, (chunk.data, status_name(stored.status)));
    }
    Ok(chunks)
}
pub(super) fn message_content(
    db: &SqliteStorage,
    row: &StoredMessage,
) -> Result<(String, Option<String>, Option<Attachment>)> {
    match row.content_type {
        StoredType::Text => Ok((
            String::from_utf8(row.content.clone())
                .map_err(|_| DesktopError::new("invalid_message"))?,
            None,
            None,
        )),
        StoredType::TextReply => {
            let reply = TextReplyContent::from_bytes(&row.content)
                .map_err(|_| DesktopError::new("invalid_message"))?;
            Ok((
                reply.text,
                Some(crate::hex_encode(&reply.reply_to_msg_id)),
                None,
            ))
        }
        StoredType::FileMetadata => {
            // S11 §4.4: an undecodable record is an unavailable file. It must not
            // fail the whole message list.
            let Ok(meta) = FileMetadata::from_bytes(&row.content) else {
                return Ok((
                    String::new(),
                    None,
                    Some(Attachment {
                        filename: "Unavailable file".into(),
                        size: 0,
                        chunks: 0,
                        available_chunks: 0,
                        deposited_chunks: 0,
                        complete: false,
                        supported: false,
                        failed: false,
                    }),
                ));
            };
            let supported =
                meta.total_size <= najwa_storage::transfers::MAX_TRANSFER && row.disappear_timer.is_none();
            let (available, deposited) = if supported {
                storage(db.attachment_progress(
                    row.contact_id,
                    &meta.session_id,
                    row.direction == MessageDirection::Sent,
                ))?
            } else {
                (0, 0)
            };
            Ok((
                String::new(),
                None,
                Some(Attachment {
                    filename: filename(&meta.filename),
                    size: meta.total_size,
                    chunks: meta.chunk_count,
                    available_chunks: available.min(meta.chunk_count),
                    deposited_chunks: deposited.min(meta.chunk_count),
                    complete: supported && available == meta.chunk_count,
                    supported,
                    // The receiver's watch ended (S11 §4.1); sent rows count
                    // deposit attempts in `retry_count` instead.
                    failed: supported
                        && available < meta.chunk_count
                        && row.direction == MessageDirection::Received
                        && row.retry_count
                            > najwa_protocol::message::file_transfer::NACK_MAX_ATTEMPTS as i32,
                }),
            ))
        }
        _ => Err(DesktopError::new("invalid_message")),
    }
}
fn parse_job(bytes: &[u8]) -> Result<(u32, FileMetadata, &[u8])> {
    if bytes.len() < 8 {
        return Err(DesktopError::new("invalid_file"));
    }
    let cursor = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    let len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let metadata = bytes
        .get(8..8 + len)
        .ok_or_else(|| DesktopError::new("invalid_file"))?;
    let meta = FileMetadata::from_bytes(metadata).map_err(|_| DesktopError::new("invalid_file"))?;
    let data = &bytes[8 + len..];
    if data.len() != meta.total_size as usize || data.len() > MAX_BROWSER_FILE {
        return Err(DesktopError::new("invalid_file"));
    }
    Ok((cursor, meta, data))
}
impl DesktopClient {
    pub fn queue_file(&self, contact: &str, input: &[u8], name: &str) -> Result<()> {
        let cid = positive_id(contact)?;
        if input.is_empty() || input.len() > MAX_BROWSER_FILE || name.len() > 255 {
            return Err(DesktopError::new("file_too_large"));
        }
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = app
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        if !contact_ready(db, cid)? {
            return Err(DesktopError::new("contact_pending"));
        }
        if storage(db.get_conversation_timer(cid))?.unwrap_or(0) != 0
            || storage(db.timer_change_pending(cid))?
        {
            return Err(DesktopError::new("file_timer_unsupported"));
        }
        let manager = FileTransferManager::new();
        let session = manager
            .start_send(input, &filename(name))
            .map_err(|_| DesktopError::new("unsupported_file"))?;
        if session.total_size > MAX_BROWSER_FILE as u64 {
            return Err(DesktopError::new("file_too_large"));
        }
        let name = metadata_filename(
            &session.file_name,
            session.file_type.mime_type() == "image/webp",
        );
        let meta = FileMetadata {
            session_id: session.transfer_id,
            filename: name,
            total_size: session.total_size,
            mime_type: session.file_type.mime_type().into(),
            chunk_count: session.total_chunks,
            sha256_hash: session.sha256_hash,
        };
        let encoded = meta.to_bytes();
        let mut job = Zeroizing::new(Vec::with_capacity(
            8 + encoded.len() + meta.total_size as usize,
        ));
        job.extend_from_slice(&0u32.to_be_bytes());
        job.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        job.extend_from_slice(&encoded);
        while let Some(chunk) = manager.next_chunk(&meta.session_id) {
            job.extend_from_slice(&chunk.data);
        }
        storage(db.stage_attachment(
            cid,
            &format!(
                "desktop:attachment-job:{cid}:{}",
                crate::hex_encode(&meta.session_id)
            ),
            &job,
        ))
    }
    pub fn download_file(&self, contact: &str, message: &str) -> Result<serde_json::Value> {
        let cid = positive_id(contact)?;
        let mid = positive_id(message)?;
        let _guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let cell = state_cell().read().unwrap();
        let app = cell
            .as_ref()
            .ok_or_else(|| DesktopError::new("unavailable"))?;
        let db = app
            .storage
            .as_ref()
            .ok_or_else(|| DesktopError::new("locked"))?;
        let row = storage(db.get_message(mid))?
            .filter(|m| {
                m.contact_id == cid
                    && m.content_type == StoredType::FileMetadata
                    && m.disappear_timer.is_none()
            })
            .ok_or_else(|| DesktopError::new("file_unavailable"))?;
        if row
            .disappear_at
            .is_some_and(|v| v <= najwa_crypto::time::now_ms())
        {
            return Err(DesktopError::new("file_unavailable"));
        }
        let meta = FileMetadata::from_bytes(&row.content)
            .map_err(|_| DesktopError::new("invalid_file"))?;
        if meta.total_size > MAX_BROWSER_FILE as u64 {
            return Err(DesktopError::new("file_too_large"));
        }
        let chunks = chunks(db, &row, &meta)?;
        if chunks.len() != meta.chunk_count as usize {
            return Err(DesktopError::new("file_unavailable"));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(meta.total_size as usize));
        for (chunk, _) in chunks.values() {
            bytes.extend_from_slice(chunk);
        }
        if bytes.len() as u64 != meta.total_size
            || najwa_crypto::hash::sha256(&bytes) != meta.sha256_hash
        {
            return Err(DesktopError::new("invalid_file"));
        }
        Ok(serde_json::json!({"filename":filename(&meta.filename),"data":STANDARD.encode(&bytes)}))
    }
    pub(super) fn prepare_attachments(&self) -> Result<()> {
        FILE_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DesktopError::new("busy"))?;
        let _admission = Admission;
        let mut guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, db, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell
                .as_ref()
                .ok_or_else(|| DesktopError::new("unavailable"))?;
            let service = app
                .service
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (
                app.runtime.handle().clone(),
                app.storage
                    .clone()
                    .ok_or_else(|| DesktopError::new("locked"))?,
                service,
            )
        };
        runtime.block_on(guard.cancellable(async {
            for key in storage(db.attachment_jobs())? {
                let cid = key
                    .split(':')
                    .nth(2)
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or_else(|| DesktopError::new("invalid_file"))?;
                let Some(contact) = storage(db.get_contact(cid))? else {
                    storage(db.delete_setting(&key))?;
                    continue;
                };
                if contact.blocked
                    || storage(db.get_conversation_timer(cid))?.unwrap_or(0) != 0
                    || storage(db.timer_change_pending(cid))?
                {
                    continue;
                }
                let Some(job) = storage(db.get_setting_raw(&key))?.map(Zeroizing::new) else {
                    continue;
                };
                // A job stored by an older build with metadata the parser refuses
                // (a name over 255 bytes) can never be sent. Drop it so it cannot
                // block every later job (S11 §4.2).
                let Ok((mut cursor, meta, data)) = parse_job(&job) else {
                    storage(db.delete_setting(&key))?;
                    continue;
                };
                let present = storage(db.attachment_rows(cid, &meta.session_id, true))?;
                for _ in 0..4 {
                    if cursor > meta.chunk_count {
                        storage(db.delete_setting(&key))?;
                        break;
                    }
                    let exists = if cursor == 0 {
                        storage(db.attachment_metadata_exists(cid, &meta.session_id))?
                    } else {
                        present.iter().any(|row| {
                            FileChunkWire::from_bytes(&row.content)
                                .is_ok_and(|c| c.index == cursor - 1)
                        })
                    };
                    if !exists {
                        let content = if cursor == 0 {
                            MessageContent::Raw {
                                content_type: 0x10,
                                bytes: meta.to_bytes(),
                                reply_to: None,
                            }
                        } else {
                            let index = cursor - 1;
                            let start = index as usize * MAX_CHUNK_SIZE;
                            let end = (start + MAX_CHUNK_SIZE).min(data.len());
                            MessageContent::Raw {
                                content_type: 0x11,
                                bytes: FileChunkWire {
                                    session_id: meta.session_id,
                                    index,
                                    data: data[start..end].to_vec(),
                                }
                                .to_bytes(),
                                reply_to: None,
                            }
                        };
                        if service.enqueue_message(cid as u64, content).await.is_err() {
                            break;
                        }
                    }
                    cursor += 1;
                    storage(db.advance_attachment(&key, cursor))?;
                    tokio::task::yield_now().await;
                }
            }
            Ok(())
        }))?
    }
}
