fn row7_state(nr: u32) -> RatchetState {
    RatchetState {
        dhs_private: None,
        dhs_public: None,
        dhr: None,
        rk: None,
        cks: None,
        ckr: None,
        ns: 0,
        nr,
        pn: 0,
        prev_dhs_pub: None,
        established_at: 0,
        last_activity: 0,
    }
}

fn row7_sent(db: &SqliteStorage, cid: ContactId, id: u8, dh: u8, n: u32, flags: u8) -> MessageId {
    let mut message = make_msg(cid, id);
    message.flags = flags as i32;
    message.status = MessageStatus::Sent;
    let record = OutboundRepairRecord {
        contact_id: cid,
        dh_pub: [dh; 32],
        message_number: n,
        msg_id: message.msg_id,
        timestamp: 1234,
        logical_seq: n,
        content_type: 1,
        flags,
        content: message.content.clone(),
        created_at: 1234,
    };
    db.commit_sent(
        cid,
        &row7_state(0),
        &message,
        b"wire",
        Some((30, najwa_crypto::time::now_ms() as u64 + 120_000)),
        Some(&record),
    )
    .unwrap()
}

fn row7_confirm(
    db: &SqliteStorage,
    cid: ContactId,
    marker: u8,
    effect: DeliveryConfirmation,
) -> Result<Option<MessageId>> {
    db.commit_received_with_confirmation(
        cid,
        &row7_state(marker as u32),
        &[],
        None,
        &[marker; 16],
        None,
        None,
        Some(&effect),
    )
}

#[test]
fn row7_ack_ranges_are_bound_to_peer_chain_and_exact_completed_positions() {
    let db = test_db();
    let cid = setup_contact(&db);
    let other = db
        .create_contact(&NewContact {
            pseudonym: [31; 32],
            their_ik_pub: [52; 32],
            their_device_pub: [52; 32],
            our_pseudonym: [33; 32],
            display_name: None,
        })
        .unwrap();
    let ids = [
        row7_sent(&db, cid, 1, 50, 0, 0),
        row7_sent(&db, cid, 2, 50, 1, 0),
        row7_sent(&db, cid, 3, 50, 2, 0),
        row7_sent(&db, cid, 4, 51, 0, 0),
        row7_sent(&db, other, 5, 50, 0, 0),
    ];
    // Receipt of positions 0 and 2 must not acknowledge the hole at 1.
    row7_confirm(
        &db,
        cid,
        81,
        DeliveryConfirmation::Ack(vec![([50; 32], 0, 0), ([50; 32], 2, 2)]),
    )
    .unwrap();
    for (id, expected) in ids.into_iter().zip([
        MessageStatus::Delivered,
        MessageStatus::Sent,
        MessageStatus::Delivered,
        MessageStatus::Sent,
        MessageStatus::Sent,
    ]) {
        assert_eq!(db.get_message(id).unwrap().unwrap().status, expected);
    }
    let expiry = db
        .get_message(ids[0])
        .unwrap()
        .unwrap()
        .disappear_at
        .unwrap();
    assert!(expiry <= najwa_crypto::time::now_ms() + 30_000);
    row7_confirm(
        &db,
        cid,
        82,
        DeliveryConfirmation::Ack(vec![([50; 32], 0, u32::MAX)]),
    )
    .unwrap();
    assert_eq!(
        db.get_message(ids[0]).unwrap().unwrap().disappear_at,
        Some(expiry)
    );
    assert_eq!(
        db.get_message(ids[1]).unwrap().unwrap().status,
        MessageStatus::Delivered
    );
}

#[test]
fn row7_confirmation_failure_rolls_back_ratchet_status_and_dedup() {
    let db = test_db();
    let cid = setup_contact(&db);
    let id = row7_sent(&db, cid, 1, 50, 0, 4);
    db.conn().execute_batch("CREATE TRIGGER fail_confirmation BEFORE UPDATE OF status ON messages BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let effect = DeliveryConfirmation::Ack(vec![([50; 32], 0, 0)]);
    assert!(row7_confirm(&db, cid, 90, effect.clone()).is_err());
    assert_eq!(
        db.get_message(id).unwrap().unwrap().status,
        MessageStatus::Sent
    );
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().nr, 0);
    assert!(!db.check_msg_id_seen(&[90; 16]).unwrap());
    db.conn()
        .execute_batch("DROP TRIGGER fail_confirmation")
        .unwrap();
    row7_confirm(&db, cid, 90, effect).unwrap();
    assert_eq!(
        db.get_message(id).unwrap().unwrap().status,
        MessageStatus::Delivered
    );
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().nr, 90);
    // A duplicate must not restore the supplied stale state.
    db.commit_received_with_confirmation(
        cid,
        &row7_state(0),
        &[],
        None,
        &[90; 16],
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(db.get_ratchet_state(cid).unwrap().unwrap().nr, 90);
}

#[test]
fn row7_receipts_require_opt_in_and_sent_direction_and_never_extend_expiry() {
    let db = test_db();
    let cid = setup_contact(&db);
    let opted = row7_sent(&db, cid, 1, 50, 0, 4);
    let plain = row7_sent(&db, cid, 2, 50, 1, 0);
    let mut inbound = make_msg(cid, 3);
    inbound.flags = 4;
    inbound.direction = MessageDirection::Received;
    let received = db.save_message(&inbound).unwrap();
    for (marker, id) in [(91, opted), (92, plain), (93, received)] {
        let message = db.get_message(id).unwrap().unwrap();
        row7_confirm(
            &db,
            cid,
            marker,
            DeliveryConfirmation::ReadReceipt {
                msg_id: message.msg_id,
                timestamp: u64::MAX,
            },
        )
        .unwrap();
    }
    assert_eq!(
        db.get_message(opted).unwrap().unwrap().status,
        MessageStatus::Read
    );
    assert_eq!(
        db.get_message(plain).unwrap().unwrap().status,
        MessageStatus::Sent
    );
    assert_eq!(
        db.get_message(received).unwrap().unwrap().status,
        inbound.status
    );
    let msg = db.get_message(opted).unwrap().unwrap();
    row7_confirm(
        &db,
        cid,
        94,
        DeliveryConfirmation::Ack(vec![([50; 32], 0, 0)]),
    )
    .unwrap();
    row7_confirm(
        &db,
        cid,
        95,
        DeliveryConfirmation::ReadReceipt {
            msg_id: msg.msg_id,
            timestamp: 0,
        },
    )
    .unwrap();
    assert_eq!(
        db.get_message(opted).unwrap().unwrap().disappear_at,
        msg.disappear_at
    );
    assert_eq!(
        db.get_message(opted).unwrap().unwrap().status,
        MessageStatus::Read
    );
}

#[test]
fn row7_ack_positions_survive_repair_history_pruning() {
    let db = test_db();
    let cid = setup_contact(&db);
    let first = row7_sent(&db, cid, 1, 50, 0, 0);
    db.conn()
        .execute(
            "DELETE FROM outbound_repair_records WHERE contact_id=?1",
            params![cid],
        )
        .unwrap();
    row7_confirm(
        &db,
        cid,
        96,
        DeliveryConfirmation::Ack(vec![([50; 32], 0, 0)]),
    )
    .unwrap();
    assert_eq!(
        db.get_message(first).unwrap().unwrap().status,
        MessageStatus::Delivered
    );
}

#[test]
fn row7_ack_uses_transmitted_position_without_rewriting_repair_metadata() {
    let db = test_db();
    let cid = setup_contact(&db);
    let message = make_msg(cid, 1);
    let repair = OutboundRepairRecord {
        contact_id: cid,
        dh_pub: [50; 32],
        message_number: 99,
        msg_id: message.msg_id,
        timestamp: 1234,
        logical_seq: 1,
        content_type: 1,
        flags: 0,
        content: message.content.clone(),
        created_at: 1234,
    };
    let id = db
        .commit_sent_with_position(
            cid,
            &row7_state(0),
            &message,
            b"wire",
            None,
            Some(&repair),
            Some(([51; 32], 0)),
        )
        .unwrap();
    row7_confirm(
        &db,
        cid,
        97,
        DeliveryConfirmation::Ack(vec![([50; 32], 99, 99)]),
    )
    .unwrap();
    assert_eq!(
        db.get_message(id).unwrap().unwrap().status,
        MessageStatus::Pending
    );
    row7_confirm(
        &db,
        cid,
        98,
        DeliveryConfirmation::Ack(vec![([51; 32], 0, 0)]),
    )
    .unwrap();
    assert_eq!(
        db.get_message(id).unwrap().unwrap().status,
        MessageStatus::Delivered
    );
    assert_eq!(
        db.get_outbound_repair(cid, &[50; 32], 99).unwrap().unwrap(),
        repair
    );
}
