use najwa_storage::prelude::*;

fn contact(db: &SqliteStorage) -> i64 {
    db.create_contact(&NewContact {
        pseudonym: [1; 32],
        their_ik_pub: [2; 32],
        their_device_pub: [2; 32],
        our_pseudonym: [3; 32],
        display_name: None,
    })
    .unwrap()
}

fn prekey() -> Prekey {
    Prekey {
        key_id: [1; 4],
        key_type: PrekeyType::Opk,
        private_key: vec![4; 32],
        public_key: vec![5; 32],
        signature: None,
        created_at: 1,
        expires_at: None,
        used: false,
        used_at: None,
        mailbox_id: None,
    }
}

fn message(cid: i64) -> NewMessage {
    NewMessage {
        contact_id: cid,
        msg_id: [6; 16],
        direction: MessageDirection::Received,
        content_type: ContentType::Text,
        flags: 0,
        content: b"ephemeral ciphertext".to_vec(),
        file_path: None,
        timestamp: 1,
        received_at: Some(1),
        status: MessageStatus::Delivered,
        reply_to_msg_id: None,
        disappear_timer: Some(10),
        encrypted_blob: None,
        group_id: None,
        sender_display_name: None,
        origin_timestamp_ms: None,
        retry_wire_blob: None,
    }
}

fn raw(path: &std::path::Path, key: &[u8; 32]) -> rusqlite::Connection {
    let db = rusqlite::Connection::open(path).unwrap();
    let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    db.pragma_update(None, "key", format!("x'{hex}'")).unwrap();
    db.execute_batch("PRAGMA cipher_page_size=4096; PRAGMA kdf_iter=256000; PRAGMA cipher_hmac_algorithm=HMAC_SHA256; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA256").unwrap();
    db
}

#[test]
fn rekey_preserves_old_prekeys_and_wrapped_volatile_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.db");
    let mut db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    db.save_prekey(&prekey()).unwrap();
    let cid = contact(&db);
    let msg = message(cid);
    let id = db.save_message(&msg).unwrap();
    db.set_message_disappear_at(id, u64::MAX / 2).unwrap();
    let nonce = [12; 24];
    let secret = [13; 32];
    let mut wrapped = nonce.to_vec();
    wrapped
        .extend(najwa_crypto::aead::encrypt(&[11; 32], &nonce, &secret, b"volatile-key").unwrap());
    db.save_volatile_key(&msg.msg_id, &wrapped, None).unwrap();
    db.rekey(&[14; 32]).unwrap();
    db.close().unwrap();
    assert!(SqliteStorage::open(&path, &[11; 32]).is_err());
    let db = SqliteStorage::open(&path, &[14; 32]).unwrap();
    assert_eq!(
        db.get_prekey(&[1; 4]).unwrap().unwrap().private_key,
        prekey().private_key
    );
    let saved = db.get_volatile_key(&msg.msg_id).unwrap().unwrap();
    let nonce = saved[..24].try_into().unwrap();
    assert_eq!(
        najwa_crypto::aead::decrypt(&[14; 32], &nonce, &saved[24..], b"volatile-key").unwrap(),
        secret
    );
}

#[test]
fn corrupt_inner_field_aborts_rekey_and_leaves_old_database_usable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.db");
    let mut db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    db.save_prekey(&prekey()).unwrap();
    {
        let raw = raw(&path, &[11; 32]);
        raw.execute("UPDATE prekeys SET private_key=X'01'", [])
            .unwrap();
    }
    assert!(db.rekey(&[14; 32]).is_err());
    db.save_prekey(&prekey()).unwrap();
    db.close().unwrap();
    let reopened = SqliteStorage::open(&path, &[11; 32]).unwrap();
    assert_eq!(
        reopened.get_prekey(&[1; 4]).unwrap().unwrap().private_key,
        prekey().private_key
    );
    assert!(SqliteStorage::open(&path, &[14; 32]).is_err());
}

#[test]
fn rekey_refuses_other_handles_then_succeeds_after_they_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.db");
    let mut first = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let other = SqliteStorage::open(&path, &[11; 32]).unwrap();
    first.save_prekey(&prekey()).unwrap();
    assert!(first.rekey(&[14; 32]).is_err());
    assert!(other.get_prekey(&[1; 4]).unwrap().is_some());
    other.close().unwrap();
    first.rekey(&[14; 32]).unwrap();
    assert!(first.get_prekey(&[1; 4]).unwrap().is_some());
}

#[test]
fn backup_preserves_secrets_excludes_disappearing_data_and_never_clobbers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.db");
    let db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let cid = contact(&db);
    db.save_prekey(&prekey()).unwrap();
    let msg = message(cid);
    let id = db.save_message(&msg).unwrap();
    db.set_message_disappear_at(id, u64::MAX / 2).unwrap();
    db.save_volatile_key(&msg.msg_id, b"wrapped key", None)
        .unwrap();
    db.buffer_outbound_repair(
        &OutboundRepairRecord {
            contact_id: cid,
            dh_pub: [7; 32],
            message_number: 0,
            msg_id: msg.msg_id,
            timestamp: 1,
            logical_seq: 1,
            content_type: 0,
            flags: 0,
            content: b"private plaintext".to_vec(),
            created_at: 1,
        },
        256,
    )
    .unwrap();
    let dest = dir.path().join("backup.db");
    db.backup(&dest).unwrap();
    let copy = SqliteStorage::open(&dest, &[11; 32]).unwrap();
    assert!(copy.get_prekey(&[1; 4]).unwrap().is_some());
    assert!(copy.get_message(id).unwrap().is_none());
    assert!(copy.get_all_volatile_keys().unwrap().is_empty());
    assert!(copy
        .get_outbound_repair_entry(cid, &[7; 32], 0)
        .unwrap()
        .is_none());
    copy.close().unwrap();
    let bytes = std::fs::read(&dest).unwrap();
    assert!(db.backup(&dest).is_err());
    assert_eq!(bytes, std::fs::read(&dest).unwrap());
    assert!(db.get_message(id).unwrap().is_some());
    assert!(SqliteStorage::open(&dest, &[99; 32]).is_err());
}

#[test]
fn read_and_explicit_deadlines_track_persisted_keys_and_deletion_removes_them() {
    let db = SqliteStorage::open_in_memory(&[11; 32]).unwrap();
    let cid = contact(&db);
    let msg = message(cid);
    let id = db.save_message(&msg).unwrap();
    db.set_message_disappear_at(id, u64::MAX / 2).unwrap();
    db.save_volatile_key(&msg.msg_id, b"wrapped key", None)
        .unwrap();
    db.mark_messages_read(cid).unwrap();
    let deadline = db.get_message(id).unwrap().unwrap().disappear_at.unwrap();
    assert_eq!(db.purge_expired_volatile_keys(deadline as u64).unwrap(), 1);
    db.save_volatile_key(&msg.msg_id, b"wrapped key", None)
        .unwrap();
    db.set_message_disappear_at(id, 100).unwrap();
    assert_eq!(db.purge_expired_volatile_keys(100).unwrap(), 1);
    db.save_volatile_key(&msg.msg_id, b"wrapped key", None)
        .unwrap();
    db.delete_message(id).unwrap();
    assert!(db.get_all_volatile_keys().unwrap().is_empty());
}

#[test]
fn sequence_exhaustion_does_not_wrap_or_modify_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seq.db");
    let db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let cid = contact(&db);
    let raw = raw(&path, &[11; 32]);
    raw.execute("UPDATE contacts SET next_outbound_seq=4294967294", [])
        .unwrap();
    assert_eq!(db.next_outbound_seq(cid).unwrap(), u32::MAX);
    assert!(db.next_outbound_seq(cid).is_err());
    assert_eq!(
        raw.query_row("SELECT next_outbound_seq FROM contacts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        u32::MAX as i64
    );
}

#[test]
fn reopening_pre_fix_schema_replaces_plaintext_repair_copies_and_purges_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let cid = contact(&db);
    let msg = message(cid);
    db.save_message(&msg).unwrap();
    let record = OutboundRepairRecord {
        contact_id: cid,
        dh_pub: [7; 32],
        message_number: 0,
        msg_id: msg.msg_id,
        timestamp: 1,
        logical_seq: 1,
        content_type: 0,
        flags: 0,
        content: b"legacy plaintext".to_vec(),
        created_at: 1,
    };
    db.buffer_outbound_repair(&record, 256).unwrap();
    db.close().unwrap();
    {
        let conn = raw(&path, &[11; 32]);
        conn.execute_batch("ALTER TABLE outbound_repair_records DROP COLUMN content_sealed")
            .unwrap();
        conn.execute(
            "UPDATE outbound_repair_records SET content=?1",
            [b"legacy plaintext".as_slice()],
        )
        .unwrap();
        conn.execute("INSERT INTO outbound_repair_records SELECT contact_id,dh_pub,1,zeroblob(16),timestamp,logical_seq,content_type,flags,content,created_at FROM outbound_repair_records",[]).unwrap();
    }
    let db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let (record, sealed) = db
        .get_outbound_repair_entry(cid, &[7; 32], 0)
        .unwrap()
        .unwrap();
    assert!(sealed);
    assert_eq!(record.content, msg.content);
    assert!(db
        .get_outbound_repair_entry(cid, &[7; 32], 1)
        .unwrap()
        .is_none());
}

#[test]
fn repair_records_require_a_matching_live_message_row() {
    let db = SqliteStorage::open_in_memory(&[11; 32]).unwrap();
    let cid = contact(&db);
    let record = OutboundRepairRecord {
        contact_id: cid,
        dh_pub: [7; 32],
        message_number: 0,
        msg_id: [9; 16],
        timestamp: 1,
        logical_seq: 1,
        content_type: 0,
        flags: 0,
        content: b"plaintext".to_vec(),
        created_at: 1,
    };
    assert!(db.buffer_outbound_repair(&record, 256).is_err());
}

#[test]
fn backups_are_consistent_while_another_connection_commits() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.db");
    let db = SqliteStorage::open(&path, &[11; 32]).unwrap();
    let cid = contact(&db);
    let writer = raw(&path, &[11; 32]);
    writer.execute_batch("UPDATE contacts SET display_name='0'; INSERT INTO settings VALUES ('generation',CAST('0' AS BLOB),0)").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = stop.clone();
    let worker = std::thread::spawn(move || {
        let mut writer = writer;
        let mut generation = 0;
        while !child_stop.load(Ordering::Relaxed) {
            generation += 1;
            let value = generation.to_string();
            let tx = writer.transaction().unwrap();
            tx.execute("UPDATE contacts SET display_name=?1", [&value])
                .unwrap();
            tx.execute(
                "UPDATE settings SET value=?1 WHERE key='generation'",
                [value.as_bytes()],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        generation
    });
    let mut generations = Vec::new();
    for n in 0..4 {
        let backup = dir.path().join(format!("snapshot-{n}.db"));
        db.backup(&backup).unwrap();
        let saved = SqliteStorage::open(&backup, &[11; 32]).unwrap();
        let contact_value = saved
            .get_contact(cid)
            .unwrap()
            .unwrap()
            .display_name
            .unwrap();
        let setting_value =
            String::from_utf8(saved.get_setting_raw("generation").unwrap().unwrap()).unwrap();
        generations.push((contact_value, setting_value));
    }
    stop.store(true, Ordering::Relaxed);
    assert!(
        worker.join().unwrap() > 0,
        "writer must run concurrently with backups"
    );
    for (contact, setting) in generations {
        assert_eq!(contact, setting, "backup mixed transaction generations");
    }
}
