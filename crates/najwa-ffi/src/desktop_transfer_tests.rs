use super::*;
use najwa_core::storage::CoreStorage;
use najwa_storage::types::{MessageStatus, NewContact, NewMessage};
fn publish(directory: &std::path::Path, db: Arc<SqliteStorage>) {
    let mut app = state::AppState::new(directory.into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.storage = Some(db);
    app.db_key = Some(crate::state::test_key(14));
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
}
/// An unlocked profile with one contact ready for uploads, but no service.
fn ready_peer() -> (
    std::sync::MutexGuard<'static, ()>,
    tempfile::TempDir,
    Arc<SqliteStorage>,
    i64,
) {
    let serial = crate::callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    let remote = Ed25519KeyPair::from_seed(&[8; 32]);
    let cid = db
        .create_contact(&NewContact {
            pseudonym: [1; 32],
            their_ik_pub: remote.public().to_bytes(),
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: Some("File peer".into()),
        })
        .unwrap();
    let payload = signed_long_term(
        &remote,
        &[MailboxConfig::new("a".repeat(56), [4; 32], [5; 32])],
        "File peer",
    )
    .unwrap();
    db.set_setting(
        &format!("contact_targets:{cid}"),
        &vec![najwa_storage::contact_establishment::ContactTarget {
            onion: "a".repeat(56),
            deposit_capability: [5; 32],
            envelope_secret: [0; 32],
            mailbox_entry: payload.mailbox_entries[0].to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let spk = najwa_crypto::keys::X25519KeyPair::from_seed([9; 32]);
    let ratchet =
        najwa_protocol::ratchet::init::init_alice(&[10; 32], spk.public(), &[11; 32]).unwrap();
    runtime
        .block_on(CoreStorage::save_ratchet_state(&*db, cid as u64, &ratchet))
        .unwrap();
    drop(runtime);
    publish(directory.path(), db.clone());
    (serial, directory, db, cid)
}
/// Begin, upload and seal `source` as a one-part staged transfer.
fn stage(cid: i64, name: &str, source: &[u8]) -> String {
    let manifest = UploadManifest {
        name: name.into(),
        size: source.len() as u64,
        hashes: vec![crate::hex_encode(&najwa_crypto::hash::sha256(source))],
    };
    let id = DesktopClient
        .begin_upload(&cid.to_string(), manifest)
        .unwrap()
        .id;
    DesktopClient.upload_part(&id, 0, source).unwrap();
    DesktopClient.seal_upload(&id).unwrap();
    id
}
#[test]
fn webp_rename_of_a_255_byte_name_still_encodes_as_metadata() {
    let (_serial, _directory, db, cid) = ready_peer();
    let name = format!("{}abc", "\u{1F600}".repeat(63)); // 255 bytes, no '.'
    let id = stage(cid, &name, b"RIFF\x10\0\0\0WEBPVP8 \x04\0\0\0data");
    // Preparation succeeds; emission then waits for the absent service.
    assert_eq!(
        DesktopClient.prepare_stream_transfers().unwrap_err().code,
        "not_connected"
    );
    let t = db.transfer(&id).unwrap().unwrap();
    assert_eq!(t.state, 2, "{:?}", t.error);
    let meta = FileMetadata::from_bytes(t.metadata.as_ref().unwrap()).unwrap();
    // 250 bytes falls inside the 63rd emoji, so the base backs off to 248.
    assert_eq!(meta.filename, format!("{}.webp", "\u{1F600}".repeat(62)));
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}
#[test]
fn truncated_media_fails_only_its_own_transfer() {
    let (_serial, _directory, db, cid) = ready_peer();
    // An MP4 box announcing a 64-bit size that the file does not contain.
    let id = stage(cid, "clip.mp4", b"\0\0\0\x01ftypisom");
    DesktopClient.prepare_stream_transfers().unwrap();
    let t = db.transfer(&id).unwrap().unwrap();
    assert_eq!((t.state, t.error.as_deref()), (4, Some("unsupported_file")));
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}
#[test]
fn displayed_names_cannot_hide_their_extension_or_name_a_windows_device() {
    assert_eq!(attachments::filename("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
    assert_eq!(attachments::filename("a\u{200E}\u{2066}b\u{FEFF}.txt\u{2069}"), "ab.txt");
    assert_eq!(attachments::filename("\u{202E}."), "attachment");
    assert_eq!(attachments::filename("CON"), "_CON");
    assert_eq!(attachments::filename("nul.tar.gz"), "_nul.tar.gz");
    assert_eq!(attachments::filename("Com9 .txt"), "_Com9 .txt");
    assert_eq!(attachments::filename("lpt1"), "_lpt1");
    assert_eq!(attachments::filename("console.log"), "console.log");
    assert_eq!(attachments::filename("COM0.txt"), "COM0.txt");
}
#[test]
fn streamed_upload_download_and_grant_resume_after_restart_and_stop_at_lock() {
    let (_serial, directory, db, cid) = ready_peer();
    let mut source = b"RIFF\0\0\0\0WAVEfmt \x10\0\0\0".to_vec();
    source.extend_from_slice(&[1, 0, 1, 0, 0x44, 0xac, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]);
    source.extend_from_slice(b"data");
    source.extend_from_slice(&(3u32 * 1024 * 1024).to_le_bytes());
    source.resize(source.len() + 3 * 1024 * 1024, 0x42);
    let len = source.len() as u32 - 8;
    source[4..8].copy_from_slice(&len.to_le_bytes());
    let manifest = UploadManifest {
        name: "private.wav".into(),
        size: source.len() as u64,
        hashes: source
            .chunks(UPLOAD_PART)
            .map(|p| crate::hex_encode(&najwa_crypto::hash::sha256(p)))
            .collect(),
    };
    let id = DesktopClient
        .begin_upload(&cid.to_string(), manifest.clone())
        .unwrap()
        .id;
    DesktopClient
        .upload_part(&id, 0, &source[..UPLOAD_PART])
        .unwrap();
    assert_eq!(
        DesktopClient
            .upload_part(&id, 1, &[1, 2, 3])
            .unwrap_err()
            .code,
        "invalid_file"
    );
    drop(state_cell().write().unwrap().take());
    publish(directory.path(), db.clone());
    let resumed = DesktopClient
        .begin_upload(&cid.to_string(), manifest)
        .unwrap();
    assert_eq!(resumed.id, id);
    assert_eq!(resumed.parts, vec![0]);
    for (index, part) in source.chunks(UPLOAD_PART).enumerate().skip(1) {
        DesktopClient.upload_part(&id, index as u32, part).unwrap();
    }
    DesktopClient.seal_upload(&id).unwrap();
    assert_eq!(
        DesktopClient.prepare_stream_transfers().unwrap_err().code,
        "not_connected"
    );
    let t = db.transfer(&id).unwrap().unwrap();
    assert_eq!(t.state, 2);
    let meta = FileMetadata::from_bytes(t.metadata.as_ref().unwrap()).unwrap();
    assert_eq!(meta.total_size, source.len() as u64);
    assert_eq!(meta.sha256_hash, najwa_crypto::hash::sha256(&source));
    assert!(db.transfer_part(&id, 0, 0).unwrap().is_none());
    let base = NewMessage {
        contact_id: cid,
        msg_id: [2; 16],
        direction: MessageDirection::Received,
        content_type: StoredType::FileMetadata,
        flags: 0,
        content: meta.to_bytes(),
        file_path: None,
        timestamp: now() as i64,
        received_at: Some(now() as i64),
        status: MessageStatus::Delivered,
        reply_to_msg_id: None,
        disappear_timer: None,
        encrypted_blob: None,
        group_id: None,
        sender_display_name: None,
        origin_timestamp_ms: None,
        retry_wire_blob: None,
    };
    let mid = db.save_message(&base).unwrap();
    for index in 0..meta.chunk_count {
        let mut chunk = base.clone();
        chunk.msg_id = (index + 10)
            .to_be_bytes()
            .repeat(4)
            .try_into()
            .unwrap();
        chunk.content_type = StoredType::FileChunk;
        chunk.content = FileChunkWire {
            session_id: meta.session_id,
            index,
            data: db.transfer_part(&id, 1, index).unwrap().unwrap(),
        }
        .to_bytes();
        db.save_message(&chunk).unwrap();
    }
    let link = DesktopClient
        .create_file_download(&cid.to_string(), &mid.to_string())
        .unwrap();
    assert_eq!(link["metadataWarning"], false);
    let token = link["url"].as_str().unwrap().rsplit('/').next().unwrap();
    assert_eq!(
        DesktopClient.file_download_part(token, 19).unwrap(),
        source[19..MAX_CHUNK_SIZE]
    );
    drop(state_cell().write().unwrap().take());
    publish(directory.path(), db.clone());
    assert_eq!(
        DesktopClient.file_download_info(token).unwrap().size,
        source.len() as u64
    );
    let mut hash = Sha256::new();
    let mut offset = 0;
    loop {
        let part = DesktopClient.file_download_part(token, offset).unwrap();
        if part.is_empty() {
            break;
        }
        offset += part.len() as u64;
        hash.update(&part);
    }
    assert_eq!(hash.finalize().as_slice(), meta.sha256_hash);
    DesktopClient.lock().unwrap();
    assert_eq!(
        DesktopClient.file_download_part(token, 0).unwrap_err().code,
        "locked"
    );
    drop(state_cell().write().unwrap().take());
    publish(directory.path(), db.clone());
    db.delete_contact(cid).unwrap();
    assert!(DesktopClient.file_download_info(token).is_err());
    assert!(db.transfer(&id).unwrap().is_none());
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}

/// Store `data` as a received one-part file; return its metadata row id.
fn receive(db: &SqliteStorage, cid: i64, seed: u8, data: &[u8]) -> i64 {
    let meta = FileMetadata {
        session_id: [seed; 16],
        filename: "photo.jpg".into(),
        total_size: data.len() as u64,
        mime_type: "image/jpeg".into(),
        chunk_count: 1,
        sha256_hash: najwa_crypto::hash::sha256(data),
    };
    let mut row = NewMessage {
        contact_id: cid,
        msg_id: [seed; 16],
        direction: MessageDirection::Received,
        content_type: StoredType::FileMetadata,
        flags: 0,
        content: meta.to_bytes(),
        file_path: None,
        timestamp: now() as i64,
        received_at: Some(now() as i64),
        status: MessageStatus::Delivered,
        reply_to_msg_id: None,
        disappear_timer: None,
        encrypted_blob: None,
        group_id: None,
        sender_display_name: None,
        origin_timestamp_ms: None,
        retry_wire_blob: None,
    };
    let mid = db.save_message(&row).unwrap();
    row.msg_id[0] ^= 0xff;
    row.content_type = StoredType::FileChunk;
    row.content = FileChunkWire {
        session_id: meta.session_id,
        index: 0,
        data: data.to_vec(),
    }
    .to_bytes();
    db.save_message(&row).unwrap();
    mid
}
/// A modified sender can skip sanitization; the receiver checks the assembled
/// file and flags metadata for the UI without refusing the download (S11 §8).
#[test]
fn received_file_with_metadata_is_flagged_but_still_downloadable() {
    let (_serial, _directory, db, cid) = ready_peer();
    let exif = [
        0xFF, 0xD8, 0xFF, 0xE1, 0, 8, b'E', b'x', b'i', b'f', 0, 0, 0xFF, 0xD9,
    ];
    let clean = [0xFF, 0xD8, 0xFF, 0xDB, 0, 2, 0xFF, 0xD9];
    for (seed, data, warning) in [(1, &exif[..], true), (2, &clean[..], false)] {
        let mid = receive(&db, cid, seed, data);
        let link = DesktopClient
            .create_file_download(&cid.to_string(), &mid.to_string())
            .unwrap();
        assert_eq!(link["metadataWarning"], warning);
        let token = link["url"].as_str().unwrap().rsplit('/').next().unwrap();
        assert_eq!(DesktopClient.file_download_part(token, 0).unwrap(), data);
    }
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}

/// A lock must end reads of a staged file. `Interrupted` would make the std
/// read loops retry forever while the worker holds its operation guard.
#[test]
fn a_lock_ends_staged_file_reads_instead_of_spinning() {
    use std::io::Read;
    let _serial = crate::callback::tests::test_lock().lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = state::open_storage(directory.path(), &crate::state::test_key(14)).unwrap();
    assert!(state::allow_operations());
    let (ready, acquired) = std::sync::mpsc::channel();
    let (go, start) = std::sync::mpsc::channel::<()>();
    let (done, finished) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let guard = OperationGuard::acquire().unwrap();
        ready.send(()).unwrap();
        start.recv().unwrap();
        let mut file = StoreFile::new(db, "staged".into(), 0, 1024, &guard);
        let _ = done.send(file.read_to_end(&mut Vec::new()).is_err());
    });
    acquired.recv().unwrap();
    // The reader still holds its guard, so this drain times out; the
    // cancellation flag is what the read must observe.
    assert!(!state::cancel_operations(10));
    go.send(()).unwrap();
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_secs(5)),
        Ok(true),
        "a cancelled read must fail, not retry forever"
    );
    reader.join().unwrap();
    assert!(state::allow_operations());
}
