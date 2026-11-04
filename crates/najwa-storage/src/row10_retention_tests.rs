#[test]
fn row10_lock_snapshot_rolls_back_if_any_key_cannot_be_written() {
    let db = test_db();
    let cid = setup_contact(&db);
    let mut message = make_msg(cid, 1);
    message.disappear_timer = Some(30);
    let id = db.save_message(&message).unwrap();
    let now = najwa_crypto::time::now_ms();
    db.set_message_disappear_at(id, (now + 30_000) as u64)
        .unwrap();
    db.save_volatile_key(&message.msg_id, b"old wrapped key", None)
        .unwrap();
    db.conn()
        .execute_batch(
            "CREATE TRIGGER refuse_key BEFORE INSERT ON volatile_keys
        BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END;",
        )
        .unwrap();
    assert!(db
        .replace_volatile_keys(&[(message.msg_id, b"new wrapped key".to_vec())], now)
        .is_err());
    assert_eq!(
        db.get_volatile_key(&message.msg_id).unwrap().unwrap(),
        b"old wrapped key"
    );
}

#[test]
fn row10_unlock_takes_only_live_keys_and_drops_orphans() {
    let db = test_db();
    let cid = setup_contact(&db);
    let now = najwa_crypto::time::now_ms();
    for n in 1..=2 {
        let mut message = make_msg(cid, n);
        message.disappear_timer = Some(30);
        let id = db.save_message(&message).unwrap();
        db.set_message_disappear_at(id, if n == 1 { 1 } else { (now + 30_000) as u64 })
            .unwrap();
        db.save_volatile_key(&message.msg_id, &[n; 32], None)
            .unwrap();
    }
    db.save_volatile_key(&[99; 16], b"orphan", None).unwrap();
    let entries = db.take_live_volatile_keys(now).unwrap();
    assert_eq!(entries, vec![(make_msg(cid, 2).msg_id, vec![2; 32])]);
    assert!(db.get_all_volatile_keys().unwrap().is_empty());
}

#[test]
fn row10_fallback_deadlines_use_original_local_events_without_extension() {
    let db = test_db();
    let cid = setup_contact(&db);
    let now = najwa_crypto::time::now_ms();
    let sent_at = now / 1000 - 86_401;
    let mut sent = make_msg(cid, 1);
    sent.timestamp = sent_at;
    sent.disappear_timer = Some(30);
    let sent_id = db.save_message(&sent).unwrap();
    let mut received = make_msg(cid, 2);
    received.direction = MessageDirection::Received;
    received.received_at = Some(now / 1000 - 10);
    received.disappear_timer = Some(30);
    received.flags = 1;
    let received_id = db.save_message(&received).unwrap();
    assert_eq!(
        db.apply_fallback_disappear_timers((now - 86_400_000) as u64)
            .unwrap(),
        2
    );
    assert_eq!(
        db.get_message(sent_id).unwrap().unwrap().disappear_at,
        Some(sent_at * 1000 + 86_430_000)
    );
    assert_eq!(
        db.get_message(received_id).unwrap().unwrap().disappear_at,
        Some(received.received_at.unwrap() * 1000 + 30_000)
    );
    assert_eq!(
        db.apply_fallback_disappear_timers((now - 86_400_000) as u64)
            .unwrap(),
        0
    );
}
