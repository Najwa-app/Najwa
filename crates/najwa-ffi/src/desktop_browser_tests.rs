use super::*;
use najwa_storage::types::{
    ContentType as StoredType, MessageDirection, MessageStatus, NewContact, NewMessage,
};

#[test]
fn local_contact_controls_and_qr_work_without_tor_and_delete_all_obligations() {
    let _serial = crate::callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    db.save_mailbox(&NewMailbox::with_cover_caps(
        "b".repeat(56),
        vec![1; 32],
        vec![2; 32],
        0,
        now() as i64,
    ))
    .unwrap();
    let mut app = state::AppState::new(dir.path().into()).unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.storage = Some(db.clone());
    app.db_key = Some(crate::state::test_key(14));
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let peer = Ed25519KeyPair::from_seed(&[8; 32]);
    let payload = HandshakePayload::create(
        &peer,
        &[MailboxConfig::new("a".repeat(56), [3; 32], [4; 32])],
        "Offline contact",
        24,
    )
    .unwrap();
    let qr = payload.to_qr_string().unwrap();
    let start = std::time::Instant::now();
    let contact = DesktopClient
        .accept_invitation(&qr, "Local person", false)
        .unwrap();
    let details = DesktopClient
        .invitation_details(&payload.to_uri().unwrap())
        .unwrap();
    assert_eq!(details["qrText"], qr);
    assert_eq!(details["expiresAt"], payload.expires_at);
    let cid = contact.parse::<i64>().unwrap();
    DesktopClient.manage_contact(&contact, "block", "").unwrap();
    let blocked = DesktopClient.contacts().unwrap().pop().unwrap();
    assert!(blocked.blocked);
    DesktopClient
        .manage_contact(&contact, "rename", "Renamed locally")
        .unwrap();
    DesktopClient
        .verify(&contact, &blocked.safety_number, true)
        .unwrap();
    assert!(
        db.get_contact(cid).unwrap().unwrap().blocked,
        "verification cannot undo blocking"
    );
    DesktopClient
        .manage_contact(&contact, "unblock", "")
        .unwrap();
    assert!(!db.get_contact(cid).unwrap().unwrap().blocked);
    db.set_setting_raw(&format!("session_ad:{cid}"), b"session data")
        .unwrap();
    db.set_setting(
        &format!("desktop:announced-current:{cid}"),
        &"old completion",
    )
    .unwrap();
    db.stage_attachment(
        cid,
        &format!("desktop:attachment-job:{cid}:fixture"),
        &[1, 2, 3],
    )
    .unwrap();
    DesktopClient
        .manage_contact(&contact, "delete", "")
        .unwrap();
    assert!(DesktopClient.contacts().unwrap().is_empty());
    for key in [
        format!("session_ad:{cid}"),
        format!("desktop:reciprocal:{cid}"),
        format!("desktop:announced-current:{cid}"),
        format!("contact_handshake:{cid}"),
    ] {
        assert!(db.get_setting_raw(&key).unwrap().is_none());
    }
    assert!(db.attachment_jobs().unwrap().is_empty());
    assert!(db.outgoing_frames().unwrap().is_empty());
    complete_announcement(&db, cid, "late network result").unwrap();
    assert!(db
        .get_setting_raw(&format!("desktop:announced-current:{cid}"))
        .unwrap()
        .is_none());
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "contact management never waits for Tor or the peer"
    );
    DesktopClient.lock().unwrap();
    drop(state_cell().write().unwrap().take());
    assert!(state::open_storage(dir.path(), &crate::state::test_key(14))
        .unwrap()
        .list_contacts()
        .unwrap()
        .is_empty());
}

#[test]
fn attachment_jobs_resume_and_downloads_verify_integrity_and_ownership() {
    use najwa_core::storage::CoreStorage;
    use najwa_protocol::message::file_transfer::{FileChunkWire, FileMetadata};
    let _serial = crate::callback::tests::test_lock().lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
    let cid = db
        .create_contact(&NewContact {
            pseudonym: [1; 32],
            their_ik_pub: Ed25519KeyPair::from_seed(&[8; 32]).public().to_bytes(),
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: Some("File peer".into()),
        })
        .unwrap();
    let remote = Ed25519KeyPair::from_seed(&[8; 32]);
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
    let mut app = state::AppState::new(dir.path().into()).unwrap();
    let spk = najwa_crypto::keys::X25519KeyPair::from_seed([9; 32]);
    let ratchet =
        najwa_protocol::ratchet::init::init_alice(&[10; 32], spk.public(), &[11; 32]).unwrap();
    app.runtime
        .block_on(CoreStorage::save_ratchet_state(&*db, cid as u64, &ratchet))
        .unwrap();
    app.runtime
        .block_on(CoreStorage::save_session_ad(
            &*db,
            cid as u64,
            b"test session",
        ))
        .unwrap();
    app.identity = Some(Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 1,
        version: 2,
    });
    app.storage = Some(db.clone());
    app.db_key = Some(crate::state::test_key(14));
    *state_cell().write().unwrap() = Some(app);
    assert!(state::allow_operations());
    let client = DesktopClient;
    client
        .queue_file(
            &cid.to_string(),
            include_bytes!("../../../apps/desktop/src/assets/najwa-mark.png"),
            "../photo.png",
        )
        .unwrap();
    let jobs = db.attachment_jobs().unwrap();
    assert_eq!(jobs.len(), 1);
    let original = db.get_setting_raw(&jobs[0]).unwrap().unwrap();
    db.advance_attachment(&jobs[0], 2).unwrap();
    let updated = db.get_setting_raw(&jobs[0]).unwrap().unwrap();
    assert_eq!(&updated[..4], &2u32.to_be_bytes());
    assert_eq!(&updated[4..], &original[4..]);
    let len = u32::from_be_bytes(original[4..8].try_into().unwrap()) as usize;
    let meta = FileMetadata::from_bytes(&original[8..8 + len]).unwrap();
    assert!(meta.filename.ends_with(".webp"));
    assert!(!meta.filename.contains('/'));
    let base = NewMessage {
        contact_id: cid,
        msg_id: [1; 16],
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
    assert_eq!(
        client
            .download_file(&cid.to_string(), &mid.to_string())
            .unwrap_err()
            .code,
        "file_unavailable"
    );
    let data = &original[8 + len..];
    for (index, chunk) in data
        .chunks(najwa_protocol::message::file_transfer::MAX_CHUNK_SIZE)
        .enumerate()
    {
        let mut row = base.clone();
        row.msg_id = [index as u8 + 2; 16];
        row.content_type = StoredType::FileChunk;
        row.content = FileChunkWire {
            session_id: meta.session_id,
            index: index as u32,
            data: chunk.to_vec(),
        }
        .to_bytes();
        db.save_message(&row).unwrap();
    }
    assert!(
        client.messages(&cid.to_string()).unwrap()[0]
            .attachment
            .as_ref()
            .unwrap()
            .complete
    );
    let downloaded = client
        .download_file(&cid.to_string(), &mid.to_string())
        .unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(downloaded["data"].as_str().unwrap())
            .unwrap(),
        data
    );
    assert_eq!(
        client
            .download_file("999", &mid.to_string())
            .unwrap_err()
            .code,
        "file_unavailable"
    );
    client
        .manage_contact(&cid.to_string(), "delete", "")
        .unwrap();
    // Not connected yet: Delete still seals the peer's RevocationNotice (S08 §7.1).
    assert_eq!(db.revocation_frames().unwrap().len(), 1);
    assert!(db.outgoing_frames().unwrap().is_empty());
    db.advance_attachment(&jobs[0], 3).unwrap();
    assert!(db.attachment_jobs().unwrap().is_empty());
    assert_eq!(
        client
            .download_file(&cid.to_string(), &mid.to_string())
            .unwrap_err()
            .code,
        "file_unavailable"
    );
    client.lock().unwrap();
    drop(state_cell().write().unwrap().take());
}
