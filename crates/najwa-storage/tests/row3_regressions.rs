use najwa_storage::prelude::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ObservedAllocator;
thread_local! {
    static OBSERVE_SIZE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MAX_ALLOCATION: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
static SECRET_PTR: AtomicUsize = AtomicUsize::new(0);
static SECRET_FREED: AtomicBool = AtomicBool::new(false);
static SECRET_WIPED: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if OBSERVE_SIZE.try_with(|v| v.get()).unwrap_or(false) {
            let _ = MAX_ALLOCATION.try_with(|v| v.set(v.get().max(layout.size())));
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == SECRET_PTR.load(Ordering::Relaxed) && layout.size() >= 32 {
            // Inspect exactly the 32 initialized Vec bytes BEFORE freeing them.
            // Never read freed memory, struct padding, or spare Vec capacity.
            let wiped = unsafe { std::slice::from_raw_parts(ptr, 32) }
                .iter()
                .all(|b| *b == 0);
            SECRET_WIPED.store(wiped, Ordering::Relaxed);
            SECRET_FREED.store(true, Ordering::Relaxed);
            SECRET_PTR.store(0, Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn contact(db: &SqliteStorage) -> i64 {
    db.create_contact(&NewContact {
        pseudonym: [1; 32],
        their_ik_pub: [2; 32],
        their_device_pub: [2; 32],
        our_pseudonym: [3; 32],
        display_name: Some("Synthetic review contact".into()),
    })
    .unwrap()
}

fn ratchet() -> RatchetState {
    RatchetState {
        dhs_private: Some(vec![4; 32]),
        dhs_public: Some(vec![5; 32]),
        dhr: Some(vec![6; 32]),
        rk: Some(vec![7; 32]),
        cks: Some(vec![8; 32]),
        ckr: Some(vec![9; 32]),
        ns: 1,
        nr: 0,
        pn: 0,
        prev_dhs_pub: None,
        established_at: 1,
        last_activity: 1,
    }
}

fn prekey() -> Prekey {
    Prekey {
        key_id: [1, 2, 3, 4],
        key_type: PrekeyType::Opk,
        private_key: vec![10; 32],
        public_key: vec![11; 32],
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
        msg_id: [12; 16],
        direction: MessageDirection::Sent,
        content_type: ContentType::Text,
        flags: 0,
        content: b"sealed content".to_vec(),
        file_path: None,
        timestamp: 1,
        received_at: None,
        status: MessageStatus::Sent,
        reply_to_msg_id: None,
        disappear_timer: Some(10),
        encrypted_blob: None,
        group_id: None,
        sender_display_name: None,
        origin_timestamp_ms: None,
        retry_wire_blob: None,
    }
}

#[test]
fn rekey_keeps_ratchets_readable_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let mut db = SqliteStorage::open(&path, &[21; 32]).unwrap();
    let cid = contact(&db);
    db.save_ratchet_state(cid, &ratchet()).unwrap();
    db.rekey(&[22; 32]).unwrap();
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().rk, ratchet().rk);
    db.close().unwrap();
    let reopened = SqliteStorage::open(&path, &[22; 32]).unwrap();
    assert_eq!(
        reopened.get_ratchet_state(cid).unwrap().unwrap().rk,
        ratchet().rk
    );
}

#[test]
fn rekey_keeps_new_prekeys_readable_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let mut db = SqliteStorage::open(&path, &[21; 32]).unwrap();
    db.rekey(&[22; 32]).unwrap();
    db.save_prekey(&prekey()).unwrap();
    db.close().unwrap();
    let reopened = SqliteStorage::open(&path, &[22; 32]).unwrap();
    assert_eq!(
        reopened
            .get_prekey(&prekey().key_id)
            .unwrap()
            .unwrap()
            .private_key,
        prekey().private_key
    );
}

#[test]
fn backup_is_encrypted_and_can_be_reopened() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteStorage::open(&dir.path().join("store.db"), &[23; 32]).unwrap();
    db.set_setting_raw("synthetic_secret", b"secret backup marker")
        .unwrap();
    let dest = dir.path().join("backup.db");
    db.backup(&dest).unwrap();
    let bytes = std::fs::read(&dest).unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "backup was written in plaintext"
    );
    let copy = SqliteStorage::open(&dest, &[23; 32]).unwrap();
    assert_eq!(
        copy.get_setting_raw("synthetic_secret").unwrap().unwrap(),
        b"secret backup marker"
    );
}

#[test]
fn deleting_disappearing_message_erases_repair_plaintext() {
    let db = SqliteStorage::open_in_memory(&[24; 32]).unwrap();
    let cid = contact(&db);
    let msg = message(cid);
    let repair = OutboundRepairRecord {
        contact_id: cid,
        dh_pub: [13; 32],
        message_number: 0,
        msg_id: msg.msg_id,
        timestamp: 1,
        logical_seq: 1,
        content_type: 0,
        flags: 0,
        content: b"original disappearing plaintext".to_vec(),
        created_at: 1,
    };
    let id = db
        .commit_sent(
            cid,
            &ratchet(),
            &msg,
            b"wire",
            Some((10, 100)),
            Some(&repair),
        )
        .unwrap();
    db.overwrite_message_content(id, &[]).unwrap();
    db.delete_message(id).unwrap();
    assert!(
        db.get_outbound_repair(cid, &repair.dh_pub, 0)
            .unwrap()
            .is_none(),
        "deleted plaintext is still recoverable through repair history"
    );
}

#[test]
fn ack_updated_deadline_also_expires_persisted_key() {
    let db = SqliteStorage::open_in_memory(&[24; 32]).unwrap();
    let cid = contact(&db);
    let msg = message(cid);
    let fallback = najwa_crypto::time::now_ms() as u64 + 604800000;
    db.commit_sent(cid, &ratchet(), &msg, b"wire", Some((10, fallback)), None)
        .unwrap();
    db.save_volatile_key(&msg.msg_id, b"wrapped volatile key", None)
        .unwrap();
    db.start_sender_disappear_on_ack(&msg.msg_id).unwrap();
    let expires_at = db
        .get_message_by_msg_id(&msg.msg_id)
        .unwrap()
        .unwrap()
        .disappear_at
        .unwrap();
    assert_eq!(
        db.purge_expired_volatile_keys(expires_at as u64).unwrap(),
        1
    );
    assert!(db.get_all_volatile_keys().unwrap().is_empty());
}

#[test]
fn cleanup_covers_both_dedup_caches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [24; 32];
    let db = SqliteStorage::open(&path, &key).unwrap();
    let cid = contact(&db);
    db.mark_msg_id_seen(cid, &[31; 16]).unwrap();
    db.mark_logical_msg_id_seen(cid, &[32; 16]).unwrap();
    let raw = raw_connection(&path, &key);
    let old = najwa_crypto::time::now() as i64 - 100 * 86400;
    raw.execute("UPDATE msg_id_cache_transport SET seen_at = ?1", [old])
        .unwrap();
    raw.execute("UPDATE msg_id_cache_logical SET seen_at = ?1", [old])
        .unwrap();
    db.cleanup_old_msg_ids(najwa_crypto::time::now() as i64 - 90 * 86400)
        .unwrap();
    assert!(!db.check_msg_id_seen(&[31; 16]).unwrap());
    assert!(!db.check_logical_msg_id_seen(cid, &[32; 16]).unwrap());
}

#[test]
fn retention_cleanup_keeps_spec_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [26; 32];
    let db = SqliteStorage::open(&path, &key).unwrap();
    let cid = contact(&db);
    let now = najwa_crypto::time::now() as i64;
    // Dedup: 92 days old goes; just past 90 days stays (mailbox may still hold it).
    db.mark_msg_id_seen(cid, &[33; 16]).unwrap();
    db.mark_msg_id_seen(cid, &[34; 16]).unwrap();
    db.mark_logical_msg_id_seen(cid, &[35; 16]).unwrap();
    let raw = raw_connection(&path, &key);
    for (table, column, id, age) in [
        ("msg_id_cache_transport", "msg_id", [33u8; 16], 92 * 86400),
        ("msg_id_cache_transport", "msg_id", [34; 16], 90 * 86400 + 60),
        ("msg_id_cache_logical", "logical_msg_id", [35; 16], 92 * 86400),
    ] {
        raw.execute(
            &format!("UPDATE {table} SET seen_at = ?1 WHERE {column} = ?2"),
            rusqlite::params![now - age, id.as_slice()],
        )
        .unwrap();
    }
    let skipped = |n: u32, expires_at: i64| SkippedKey {
        dh_pub: [36; 32],
        message_number: n,
        message_key: [37; 32],
        created_at: expires_at - 90 * 86400,
        expires_at,
    };
    db.save_skipped_key(cid, &skipped(1, now - 1)).unwrap();
    db.save_skipped_key(cid, &skipped(2, now + 3600)).unwrap();
    let intro = |ik: u8, expires_at: i64| NewPendingIntroduction {
        introducer_contact_id: cid,
        introduced_ik_pub: [ik; 32],
        introduced_display_name: "introduced".into(),
        introducer_ik_pub: [2; 32],
        payload_blob: vec![1],
        is_anonymous: false,
        created_at: now - 7200,
        expires_at,
    };
    let expired = db.save_pending_introduction(&intro(38, now - 1)).unwrap();
    db.save_pending_introduction(&intro(39, now + 3600)).unwrap();

    db.run_retention_cleanup().unwrap();

    assert!(!db.check_msg_id_seen(&[33; 16]).unwrap());
    assert!(db.check_msg_id_seen(&[34; 16]).unwrap());
    assert!(!db.check_logical_msg_id_seen(cid, &[35; 16]).unwrap());
    let keys = db.load_skipped_keys(cid).unwrap();
    assert_eq!(db.count_skipped_keys(cid).unwrap(), 1);
    assert_eq!(keys[0].message_number, 2);
    let pending = db.list_pending_introductions().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].introduced_ik_pub, [39; 32]);
    assert_eq!(
        db.get_pending_introduction(expired).unwrap().unwrap().status,
        IntroductionStatus::Expired
    );
}

fn raw_connection(path: &std::path::Path, key: &[u8; 32]) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    conn.pragma_update(None, "key", format!("x'{hex}'"))
        .unwrap();
    conn.pragma_update(None, "cipher_page_size", 4096).unwrap();
    conn.pragma_update(None, "kdf_iter", 256000).unwrap();
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA256")
        .unwrap();
    conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA256")
        .unwrap();
    conn
}

#[test]
fn blocked_checkpoint_does_not_report_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [25; 32];
    let db = SqliteStorage::open(&path, &key).unwrap();
    db.set_setting_raw("before", b"before").unwrap();
    let reader = raw_connection(&path, &key);
    reader
        .execute_batch("BEGIN; SELECT * FROM settings;")
        .unwrap();
    db.set_setting_raw("after", b"after").unwrap();
    let result = db.wal_checkpoint();
    let observer = raw_connection(&path, &key);
    observer.busy_timeout(std::time::Duration::ZERO).unwrap();
    let status: (i32, i32, i32) = observer
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    eprintln!("checkpoint returned {result:?}, actual checkpoint status {status:?}");
    assert!(
        result.is_err() || status.0 == 0,
        "checkpoint reported success while the WAL could not be checkpointed/truncated"
    );
}

#[test]
fn interrupted_first_schema_creation_recovers_on_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [26; 32];
    // The exact durable state after the first autocommitted schema statement,
    // before the remaining DDL and final schema-version insert run.
    {
        let conn = raw_connection(&path, &key);
        conn.execute_batch("CREATE TABLE db_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .unwrap();
    }
    SqliteStorage::open(&path, &key).unwrap();
}

#[test]
fn outbound_sequences_are_unique_across_database_connections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [27; 32];
    let first = SqliteStorage::open(&path, &key).unwrap();
    let cid = contact(&first);
    let second = SqliteStorage::open(&path, &key).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let child_barrier = barrier.clone();
    let worker = std::thread::spawn(move || {
        (0..1000)
            .map(|_| {
                child_barrier.wait();
                first.next_outbound_seq(cid).unwrap()
            })
            .collect::<Vec<_>>()
    });
    let mut values: Vec<u32> = (0..1000)
        .map(|_| {
            barrier.wait();
            second.next_outbound_seq(cid).unwrap()
        })
        .collect();
    values.extend(worker.join().unwrap());
    let expected = values.len();
    values.sort_unstable();
    values.dedup();
    assert_eq!(
        values.len(),
        expected,
        "distinct messages were assigned duplicate outbound sequence numbers"
    );
}

#[test]
fn decrypted_prekey_is_wiped_before_deallocation() {
    let db = SqliteStorage::open_in_memory(&[28; 32]).unwrap();
    db.save_prekey(&prekey()).unwrap();
    let loaded = db.get_prekey(&prekey().key_id).unwrap().unwrap();
    assert_eq!(loaded.private_key.len(), 32);
    assert!(loaded.private_key.capacity() >= 32);
    SECRET_FREED.store(false, Ordering::Relaxed);
    SECRET_WIPED.store(false, Ordering::Relaxed);
    SECRET_PTR.store(loaded.private_key.as_ptr() as usize, Ordering::Relaxed);
    drop(loaded);
    assert!(
        SECRET_FREED.load(Ordering::Relaxed),
        "observer did not see the deallocation"
    );
    assert!(
        SECRET_WIPED.load(Ordering::Relaxed),
        "decrypted prekey was freed with its secret bytes intact"
    );
    let cid = contact(&db);
    db.save_ratchet_state(cid, &ratchet()).unwrap();
    for field in 0..4 {
        let state = db.get_ratchet_state(cid).unwrap().unwrap();
        let bytes = [&state.dhs_private, &state.rk, &state.cks, &state.ckr][field]
            .as_ref()
            .unwrap();
        SECRET_FREED.store(false, Ordering::Relaxed);
        SECRET_WIPED.store(false, Ordering::Relaxed);
        SECRET_PTR.store(bytes.as_ptr() as usize, Ordering::Relaxed);
        drop(state);
        assert!(SECRET_FREED.load(Ordering::Relaxed));
        assert!(
            SECRET_WIPED.load(Ordering::Relaxed),
            "ratchet field {field} was not wiped"
        );
    }
    let row_key = Box::new(derive_row_key(&[42; 32], "prekeys", 1).unwrap());
    SECRET_FREED.store(false, Ordering::Relaxed);
    SECRET_WIPED.store(false, Ordering::Relaxed);
    SECRET_PTR.store(row_key.as_ptr() as usize, Ordering::Relaxed);
    drop(row_key);
    assert!(SECRET_FREED.load(Ordering::Relaxed));
    assert!(SECRET_WIPED.load(Ordering::Relaxed));
}

#[test]
fn header_check_uses_bounded_memory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("header-probe.db");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    MAX_ALLOCATION.set(0);
    OBSERVE_SIZE.set(true);
    let result = verify_wal_encryption(&path);
    OBSERVE_SIZE.set(false);
    result.unwrap();
    let largest = MAX_ALLOCATION.get();
    assert!(
        largest < 1024 * 1024,
        "a 16-byte header check allocated {largest} bytes"
    );
}

#[test]
fn late_initial_failure_rolls_back_all_writes() {
    let db = SqliteStorage::open_in_memory(&[29; 32]).unwrap();
    let cid = contact(&db);
    let before = ratchet();
    db.save_ratchet_state(cid, &before).unwrap();
    db.save_session_ad(cid, b"original AD").unwrap();
    db.save_prekey(&prekey()).unwrap();
    let skipped = SkippedKey {
        dh_pub: [30; 32],
        message_number: 0,
        message_key: [31; 32],
        created_at: 1,
        expires_at: i64::MAX,
    };
    db.save_skipped_key(cid, &skipped).unwrap();
    let mut after = before.clone();
    after.rk = Some(vec![32; 32]);
    let msg = message(cid);
    let transport = [33; 16];
    let logical = [34; 16];
    let result = db.commit_initial_received(
        cid,
        &after,
        &[],
        b"new AD",
        Some(prekey().key_id),
        Some(&msg),
        &transport,
        Some(&logical),
        None,
        Some(999),
    );
    assert!(result.is_err());
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().rk, before.rk);
    assert_eq!(db.get_session_ad(cid).unwrap().unwrap(), b"original AD");
    assert!(!db.get_prekey(&prekey().key_id).unwrap().unwrap().used);
    assert!(db.get_message_by_msg_id(&msg.msg_id).unwrap().is_none());
    assert!(!db.check_msg_id_seen(&transport).unwrap());
    assert!(!db.check_logical_msg_id_seen(cid, &logical).unwrap());
    assert_eq!(
        db.get_skipped_key(cid, &skipped.dh_pub, 0).unwrap(),
        Some(skipped.message_key)
    );
}

#[test]
fn late_send_failure_rolls_back_ratchet_and_message() {
    let db = SqliteStorage::open_in_memory(&[29; 32]).unwrap();
    let cid = contact(&db);
    let before = ratchet();
    db.save_ratchet_state(cid, &before).unwrap();
    let mut after = before.clone();
    after.rk = Some(vec![32; 32]);
    let msg = message(cid);
    let repair = OutboundRepairRecord {
        contact_id: 999,
        dh_pub: [13; 32],
        message_number: 0,
        msg_id: msg.msg_id,
        timestamp: 1,
        logical_seq: 1,
        content_type: 0,
        flags: 0,
        content: b"original plaintext".to_vec(),
        created_at: 1,
    };
    assert!(db
        .commit_sent(cid, &after, &msg, b"wire", None, Some(&repair))
        .is_err());
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().rk, before.rk);
    assert!(db.get_message_by_msg_id(&msg.msg_id).unwrap().is_none());
}

#[test]
fn sent_commit_succeeds_with_full_sync_despite_blocked_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let key = [35; 32];
    let db = SqliteStorage::open(&path, &key).unwrap();
    let cid = contact(&db);
    db.save_ratchet_state(cid, &ratchet()).unwrap();
    let reader = raw_connection(&path, &key);
    reader
        .execute_batch("BEGIN; SELECT * FROM contacts;")
        .unwrap();
    let observer = raw_connection(&path, &key);
    observer.busy_timeout(std::time::Duration::ZERO).unwrap();
    let before: (i32, i32, i32) = observer
        .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(
        before.1, before.2,
        "reader's snapshot must be fully checkpointed before the new send"
    );
    let result = db.commit_sent(cid, &ratchet(), &message(cid), b"wire", None, None);
    let after: (i32, i32, i32) = observer
        .query_row("PRAGMA wal_checkpoint(FULL)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    eprintln!("commit_sent returned {result:?}, checkpoint before={before:?}, after={after:?}");
    let id = result.unwrap();
    assert_ne!(after.0, 0, "reader must block the checkpoint in this test");
    assert!(db.get_message(id).unwrap().is_some());
    reader.execute_batch("ROLLBACK").unwrap();
    db.wal_checkpoint().unwrap();
    drop(observer);
    drop(reader);
    db.close().unwrap();
    let reopened = SqliteStorage::open(&path, &key).unwrap();
    assert!(reopened.get_message(id).unwrap().is_some());
}

#[test]
fn received_message_failure_preserves_ratchet_and_skipped_keys() {
    let db = SqliteStorage::open_in_memory(&[36; 32]).unwrap();
    let cid = contact(&db);
    let before = ratchet();
    db.save_ratchet_state(cid, &before).unwrap();
    let msg = message(cid);
    db.save_message(&msg).unwrap();
    let skipped = SkippedKey {
        dh_pub: [30; 32],
        message_number: 0,
        message_key: [31; 32],
        created_at: 1,
        expires_at: i64::MAX,
    };
    db.save_skipped_key(cid, &skipped).unwrap();
    let mut after = before.clone();
    after.rk = Some(vec![32; 32]);
    let transport = [37; 16];
    let logical = [38; 16];
    assert!(db
        .commit_received(
            cid,
            &after,
            &[],
            Some(&msg),
            &transport,
            Some(&logical),
            None
        )
        .is_err());
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().rk, before.rk);
    assert_eq!(
        db.get_skipped_key(cid, &skipped.dh_pub, 0).unwrap(),
        Some(skipped.message_key)
    );
    assert!(!db.check_msg_id_seen(&transport).unwrap());
    assert!(!db.check_logical_msg_id_seen(cid, &logical).unwrap());
}
