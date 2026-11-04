//! Resumable, encrypted staging with bounded reads/writes and ranged downloads.
use super::*;
use najwa_protocol::message::file_transfer::{FileChunkWire, FileMetadata, MAX_CHUNK_SIZE};
use najwa_storage::transfers::{Transfer, MAX_TRANSFER, UPLOAD_PART};
use najwa_storage::types::{ContentType as StoredType, MessageDirection};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(test)]
#[path = "desktop_transfer_tests.rs"]
mod tests;

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct UploadManifest {
    pub name: String,
    pub size: u64,
    pub hashes: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferView {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub uploaded: u64,
    pub phase: &'static str,
    pub parts: Vec<u32>,
    pub error: Option<String>,
}
#[derive(Serialize, Clone)]
pub struct DownloadInfo {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
}
static PREPARING: AtomicBool = AtomicBool::new(false);
struct Preparing;
impl Drop for Preparing {
    fn drop(&mut self) {
        PREPARING.store(false, Ordering::SeqCst);
    }
}
fn owner() -> Result<(OperationGuard, Arc<SqliteStorage>)> {
    let guard = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
    let cell = state_cell().read().unwrap();
    let app = cell
        .as_ref()
        .ok_or_else(|| DesktopError::new("unavailable"))?;
    Ok((
        guard,
        app.storage
            .clone()
            .ok_or_else(|| DesktopError::new("locked"))?,
    ))
}
fn view(db: &SqliteStorage, t: &Transfer) -> Result<TransferView> {
    let m: UploadManifest =
        serde_json::from_slice(&t.manifest).map_err(|_| DesktopError::new("invalid_file"))?;
    Ok(TransferView {
        id: t.id.clone(),
        filename: attachments::filename(&m.name),
        size: t.size,
        uploaded: t.received,
        phase: match t.state {
            0 => "uploading",
            1 => "preparing",
            2 => "queued",
            3 => "queued",
            _ => "failed",
        },
        parts: if t.state == 0 {
            storage(db.uploaded_parts(&t.id))?
        } else {
            Vec::new()
        },
        error: t.error.clone(),
    })
}
impl DesktopClient {
    pub fn begin_upload(&self, contact: &str, manifest: UploadManifest) -> Result<TransferView> {
        let cid = positive_id(contact)?;
        let (_guard, db) = owner()?;
        if manifest.size == 0
            || manifest.size > MAX_TRANSFER
            || manifest.name.len() > 255
            || manifest.hashes.len() != manifest.size.div_ceil(UPLOAD_PART as u64) as usize
            || manifest
                .hashes
                .iter()
                .any(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(DesktopError::new("file_too_large"));
        }
        if !contact_ready(&db, cid)? {
            return Err(DesktopError::new("contact_pending"));
        }
        if storage(db.get_conversation_timer(cid))?.unwrap_or(0) != 0
            || storage(db.timer_change_pending(cid))?
        {
            return Err(DesktopError::new("file_timer_unsupported"));
        }
        let bytes = serde_json::to_vec(&manifest).map_err(|_| DesktopError::new("invalid_file"))?;
        let fingerprint = najwa_crypto::hash::sha256(&bytes);
        let id = crate::hex_encode(&random_bytes::<16>());
        let t = storage(db.begin_transfer(&id, cid, &fingerprint, &bytes, manifest.size))?;
        view(&db, &t)
    }
    pub fn upload_part(&self, id: &str, part: u32, bytes: &[u8]) -> Result<()> {
        let (_guard, db) = owner()?;
        let t = storage(db.transfer(id))?.ok_or_else(|| DesktopError::new("file_unavailable"))?;
        let m: UploadManifest =
            serde_json::from_slice(&t.manifest).map_err(|_| DesktopError::new("invalid_file"))?;
        if m.hashes.get(part as usize)
            != Some(&crate::hex_encode(&najwa_crypto::hash::sha256(bytes)))
        {
            return Err(DesktopError::new("invalid_file"));
        }
        storage(db.put_upload_part(id, part, bytes))
    }
    pub fn seal_upload(&self, id: &str) -> Result<()> {
        let (_guard, db) = owner()?;
        storage(db.seal_upload(id))
    }
    pub fn list_transfers(&self, contact: &str) -> Result<Vec<TransferView>> {
        let cid = positive_id(contact)?;
        let (_guard, db) = owner()?;
        storage(db.transfers(Some(cid)))?
            .iter()
            .map(|t| view(&db, t))
            .collect()
    }
    pub fn cancel_upload(&self, id: &str, contact: &str) -> Result<()> {
        let cid = positive_id(contact)?;
        let (_guard, db) = owner()?;
        storage(db.cancel_transfer(id, cid))
    }
    /// S11 §4.1: request missing parts of quiet received files. Called by the
    /// per-second file worker while unlocked; scans at most once a minute.
    pub(super) fn request_missing_parts(&self) -> Result<()> {
        static LAST_SCAN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now = najwa_crypto::time::now();
        if now.saturating_sub(LAST_SCAN.load(Ordering::SeqCst)) < 60 {
            return Ok(());
        }
        LAST_SCAN.store(now, Ordering::SeqCst);
        let mut operation = OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
        let (runtime, service) = {
            let cell = state_cell().read().unwrap();
            let app = cell.as_ref().ok_or_else(|| DesktopError::new("unavailable"))?;
            let service = app.service.lock().unwrap().clone()
                .ok_or_else(|| DesktopError::new("not_connected"))?;
            (app.runtime.handle().clone(), service)
        };
        runtime.block_on(operation.cancellable(async {
            messaging(service.enqueue_file_nacks(now).await)
        }))?
    }
    pub(super) fn prepare_stream_transfers(&self) -> Result<()> {
        PREPARING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| DesktopError::new("busy"))?;
        let _admission = Preparing;
        let (guard, db) = owner()?;
        for t in storage(db.transfers(None))? {
            if guard.is_cancelled() {
                return Err(DesktopError::new("locked"));
            }
            if !storage(db.get_contact(t.contact))?.is_some_and(|c| !c.blocked) {
                continue;
            }
            if t.state == 1 {
                if let Err(error) = prepare(&db, &t, &guard) {
                    if guard.is_cancelled() {
                        return Err(DesktopError::new("locked"));
                    }
                    if matches!(
                        error.code,
                        "unsupported_file" | "file_too_large" | "invalid_file"
                    ) {
                        storage(db.fail_transfer(&t.id, error.code))?;
                        continue;
                    }
                    return Err(error);
                }
            }
            let t = storage(db.transfer(&t.id))?
                .ok_or_else(|| DesktopError::new("file_unavailable"))?;
            if t.state != 2 {
                continue;
            }
            // A record prepared by an older build can hold metadata the parser
            // refuses (a name over 255 bytes). Fail it so it cannot block every
            // later transfer (S11 §4.2).
            let Ok(meta) = FileMetadata::from_bytes(t.metadata.as_deref().unwrap_or_default())
            else {
                storage(db.fail_transfer(&t.id, "invalid_file"))?;
                continue;
            };
            let (runtime, service) = {
                let cell = state_cell().read().unwrap();
                let app = cell.as_ref().ok_or_else(|| DesktopError::new("locked"))?;
                let svc = app
                    .service
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| DesktopError::new("not_connected"))?;
                (app.runtime.handle().clone(), svc)
            };
            let mut cursor = t.cursor;
            for _ in 0..16 {
                if guard.is_cancelled() {
                    return Err(DesktopError::new("locked"));
                }
                if storage(db.pending_deposit_count())? >= 64 {
                    break;
                }
                let exists = if cursor == 0 {
                    storage(db.attachment_metadata_exists(t.contact, &meta.session_id))?
                } else {
                    storage(db.attachment_part(t.contact, &meta.session_id, true, cursor - 1))?
                        .is_some()
                };
                if !exists {
                    let content = if cursor == 0 {
                        MessageContent::Raw {
                            content_type: 0x10,
                            bytes: meta.to_bytes(),
                            reply_to: None,
                        }
                    } else {
                        let data = storage(db.transfer_part(&t.id, 1, cursor - 1))?
                            .ok_or_else(|| DesktopError::new("invalid_file"))?;
                        MessageContent::Raw {
                            content_type: 0x11,
                            bytes: FileChunkWire {
                                session_id: meta.session_id,
                                index: cursor - 1,
                                data,
                            }
                            .to_bytes(),
                            reply_to: None,
                        }
                    };
                    let mut operation =
                        OperationGuard::acquire().ok_or_else(|| DesktopError::new("locked"))?;
                    if runtime
                        .block_on(
                            operation
                                .cancellable(service.enqueue_message(t.contact as u64, content)),
                        )
                        .map_err(DesktopError::from)?
                        .is_err()
                    {
                        break;
                    }
                }
                cursor += 1;
                let done = cursor > meta.chunk_count;
                storage(db.advance_transfer(&t.id, cursor, done))?;
                if done {
                    break;
                }
            }
        }
        Ok(())
    }
    pub fn create_file_download(&self, contact: &str, message: &str) -> Result<serde_json::Value> {
        let cid = positive_id(contact)?;
        let mid = positive_id(message)?;
        let (guard, db) = owner()?;
        let (row, meta) = download_metadata(&db, cid, mid)?;
        let mut hash = Sha256::new();
        for index in 0..meta.chunk_count {
            if guard.is_cancelled() {
                return Err(DesktopError::new("locked"));
            }
            let data = download_part(&db, &row, &meta, index)?;
            hash.update(&data);
        }
        if hash.finalize().as_slice() != meta.sha256_hash {
            return Err(DesktopError::new("invalid_file"));
        }
        // A modified sender can skip sanitization, so check the assembled file
        // against the type its content shows (S11 §8, §9.6). A finding only
        // warns; the download is still offered.
        let mut file = Assembled {
            db: &db,
            row: &row,
            meta: &meta,
            guard: &guard,
            pos: 0,
            part: None,
        };
        let failed = || {
            DesktopError::new(if guard.is_cancelled() {
                "locked"
            } else {
                "storage_unavailable"
            })
        };
        let mut prefix = [0; 64];
        let n = file.read(&mut prefix).map_err(|_| failed())?;
        let kind = najwa_sanitize::detect_file_type(&prefix[..n]);
        let clean = najwa_sanitize::stream::verify_seekable(&mut file, &kind)
            .map_err(|_| failed())?
            .passed;
        let token = crate::hex_encode(&random_bytes::<32>());
        storage(db.create_download_grant(&najwa_crypto::hash::sha256(token.as_bytes()), cid, mid))?;
        Ok(
            serde_json::json!({"url":format!("/api/download/{token}"),"filename":attachments::filename(&meta.filename),"size":meta.total_size,"metadataWarning":!clean}),
        )
    }
    pub fn file_download_info(&self, token: &str) -> Result<DownloadInfo> {
        let (_guard, db) = owner()?;
        let (cid, mid) = grant(&db, token)?;
        let (_, meta) = download_metadata(&db, cid, mid)?;
        Ok(DownloadInfo {
            filename: attachments::filename(&meta.filename),
            size: meta.total_size,
            sha256: crate::hex_encode(&meta.sha256_hash),
        })
    }
    pub fn file_download_part(&self, token: &str, offset: u64) -> Result<Vec<u8>> {
        let (_guard, db) = owner()?;
        let (cid, mid) = grant(&db, token)?;
        let (row, meta) = download_metadata(&db, cid, mid)?;
        if offset >= meta.total_size {
            return Ok(Vec::new());
        }
        let data = download_part(&db, &row, &meta, (offset / MAX_CHUNK_SIZE as u64) as u32)?;
        Ok(data[(offset % MAX_CHUNK_SIZE as u64) as usize..].to_vec())
    }
}
fn grant(db: &SqliteStorage, token: &str) -> Result<(i64, i64)> {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DesktopError::new("file_unavailable"));
    }
    storage(db.download_grant(&najwa_crypto::hash::sha256(token.as_bytes())))?
        .ok_or_else(|| DesktopError::new("file_unavailable"))
}
fn download_metadata(
    db: &SqliteStorage,
    cid: i64,
    mid: i64,
) -> Result<(najwa_storage::types::Message, FileMetadata)> {
    let row = storage(db.get_message(mid))?
        .filter(|m| {
            m.contact_id == cid
                && m.content_type == StoredType::FileMetadata
                && m.disappear_timer.is_none()
                && m.disappear_at
                    .is_none_or(|v| v > najwa_crypto::time::now_ms())
        })
        .ok_or_else(|| DesktopError::new("file_unavailable"))?;
    let meta =
        FileMetadata::from_bytes(&row.content).map_err(|_| DesktopError::new("invalid_file"))?;
    if meta.total_size > MAX_TRANSFER {
        return Err(DesktopError::new("file_too_large"));
    }
    Ok((row, meta))
}
fn download_part(
    db: &SqliteStorage,
    row: &najwa_storage::types::Message,
    meta: &FileMetadata,
    index: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = storage(db.attachment_part(
        row.contact_id,
        &meta.session_id,
        row.direction == MessageDirection::Sent,
        index,
    ))?
    .ok_or_else(|| DesktopError::new("file_unavailable"))?;
    let chunk = FileChunkWire::from_bytes(&bytes).map_err(|_| DesktopError::new("invalid_file"))?;
    let expected = (meta.total_size - index as u64 * MAX_CHUNK_SIZE as u64)
        .min(MAX_CHUNK_SIZE as u64) as usize;
    if chunk.session_id != meta.session_id || chunk.index != index || chunk.data.len() != expected {
        return Err(DesktopError::new("invalid_file"));
    }
    Ok(Zeroizing::new(chunk.data))
}
/// Read-only, seekable view of a received file that holds one checked part in
/// memory at a time (S11 §2.4), for the metadata check at download.
struct Assembled<'a> {
    db: &'a SqliteStorage,
    row: &'a najwa_storage::types::Message,
    meta: &'a FileMetadata,
    guard: &'a OperationGuard,
    pos: u64,
    part: Option<(u32, Zeroizing<Vec<u8>>)>,
}
impl Read for Assembled<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.guard.is_cancelled() {
            return Err(std::io::Error::other("locked"));
        }
        if self.pos >= self.meta.total_size || out.is_empty() {
            return Ok(0);
        }
        let index = (self.pos / MAX_CHUNK_SIZE as u64) as u32;
        if self.part.as_ref().map(|p| p.0) != Some(index) {
            let data = download_part(self.db, self.row, self.meta, index)
                .map_err(|e| std::io::Error::other(e.code))?;
            self.part = Some((index, data));
        }
        let data = &self.part.as_ref().unwrap().1;
        let local = (self.pos % MAX_CHUNK_SIZE as u64) as usize;
        let n = out.len().min(data.len() - local);
        out[..n].copy_from_slice(&data[local..local + n]);
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for Assembled<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let next = match from {
            SeekFrom::Start(v) => v as i128,
            SeekFrom::Current(v) => self.pos as i128 + v as i128,
            SeekFrom::End(v) => self.meta.total_size as i128 + v as i128,
        };
        if next < 0 || next > MAX_TRANSFER as i128 {
            return Err(std::io::Error::other("invalid seek"));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}
fn prepare(db: &Arc<SqliteStorage>, t: &Transfer, guard: &OperationGuard) -> Result<()> {
    storage(db.reset_transfer_output(&t.id))?;
    let manifest: UploadManifest =
        serde_json::from_slice(&t.manifest).map_err(|_| DesktopError::new("invalid_file"))?;
    let mut input = StoreFile::new(db.clone(), t.id.clone(), 0, t.size, guard);
    let mut output = StoreFile::new(db.clone(), t.id.clone(), 1, 0, guard);
    let kind = najwa_sanitize::stream::sanitize_seekable(&mut input, &mut output).map_err(|e| {
        DesktopError::new(if matches!(e, najwa_sanitize::SanitizeError::Other(_)) {
            "storage_unavailable"
        } else {
            "unsupported_file"
        })
    })?;
    output
        .flush()
        .map_err(|_| DesktopError::new("storage_unavailable"))?;
    let size = output.len;
    if size == 0 || size > MAX_TRANSFER {
        return Err(DesktopError::new("file_too_large"));
    }
    let mut reader = StoreFile::new(db.clone(), t.id.clone(), 1, size, guard);
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0; 65536]);
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|_| DesktopError::new("storage_unavailable"))?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let name = attachments::metadata_filename(
        &attachments::filename(&manifest.name),
        kind == najwa_sanitize::FileType::WebP,
    );
    let meta = FileMetadata {
        session_id: attachments::decode_id(&t.id)?,
        filename: name,
        total_size: size,
        mime_type: kind.mime_type().into(),
        chunk_count: size.div_ceil(MAX_CHUNK_SIZE as u64) as u32,
        sha256_hash: hash.finalize().into(),
    };
    storage(db.finish_transfer_output(&t.id, &meta.to_bytes()))
}
struct StoreFile<'a> {
    db: Arc<SqliteStorage>,
    id: String,
    kind: u32,
    len: u64,
    pos: u64,
    part: Option<u32>,
    cache: Zeroizing<Vec<u8>>,
    dirty: bool,
    guard: &'a OperationGuard,
}
impl<'a> StoreFile<'a> {
    fn new(
        db: Arc<SqliteStorage>,
        id: String,
        kind: u32,
        len: u64,
        guard: &'a OperationGuard,
    ) -> Self {
        Self {
            db,
            id,
            kind,
            len,
            pos: 0,
            part: None,
            cache: Zeroizing::new(Vec::new()),
            dirty: false,
            guard,
        }
    }
    fn part_size(&self) -> usize {
        if self.kind == 0 {
            UPLOAD_PART
        } else {
            MAX_CHUNK_SIZE
        }
    }
    fn check(&self) -> std::io::Result<()> {
        if self.guard.is_cancelled() {
            // Not `Interrupted`: std read/write loops retry that kind forever.
            Err(std::io::Error::other("locked"))
        } else {
            Ok(())
        }
    }
    fn load(&mut self) -> std::io::Result<()> {
        self.check()?;
        let part = (self.pos / self.part_size() as u64) as u32;
        if self.part == Some(part) {
            return Ok(());
        }
        self.flush()?;
        self.cache = Zeroizing::new(
            self.db
                .transfer_part(&self.id, self.kind, part)
                .map_err(std::io::Error::other)?
                .unwrap_or_default(),
        );
        self.part = Some(part);
        Ok(())
    }
}
impl Read for StoreFile<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.check()?;
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        self.load()?;
        let local = (self.pos % self.part_size() as u64) as usize;
        if local >= self.cache.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "missing transfer part",
            ));
        }
        let n = out
            .len()
            .min(self.cache.len() - local)
            .min((self.len - self.pos) as usize);
        out[..n].copy_from_slice(&self.cache[local..local + n]);
        self.pos += n as u64;
        Ok(n)
    }
}
impl Write for StoreFile<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        if self.kind != 1 {
            return Err(std::io::Error::other("read only"));
        }
        if input.is_empty() {
            return Ok(0);
        }
        self.load()?;
        let local = (self.pos % self.part_size() as u64) as usize;
        let n = input.len().min(self.part_size() - local);
        if self.pos + n as u64 > MAX_TRANSFER {
            return Err(std::io::Error::other("file too large"));
        }
        if self.cache.len() < local + n {
            self.cache.resize(local + n, 0)
        }
        self.cache[local..local + n].copy_from_slice(&input[..n]);
        self.pos += n as u64;
        self.len = self.len.max(self.pos);
        self.dirty = true;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.check()?;
        if self.dirty {
            self.db
                .put_transfer_output(&self.id, self.part.unwrap(), &self.cache)
                .map_err(std::io::Error::other)?;
            self.dirty = false;
        }
        Ok(())
    }
}
impl Seek for StoreFile<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.check()?;
        let next = match from {
            SeekFrom::Start(v) => v as i128,
            SeekFrom::Current(v) => self.pos as i128 + v as i128,
            SeekFrom::End(v) => self.len as i128 + v as i128,
        };
        if next < 0 || next > MAX_TRANSFER as i128 {
            return Err(std::io::Error::other("invalid seek"));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}
