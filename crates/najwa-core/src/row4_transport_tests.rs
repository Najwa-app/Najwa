// Included in the existing core test module to use its mailbox/storage harness.
// Encryption, ratchet transitions, send and receive are the production code.
#[tokio::test]
async fn transport_clock_drives_send_receive_and_control_payloads() {
    use najwa_protocol::message::control::ControlMessage;
    use najwa_protocol::ratchet::init::{init_alice, init_bob};
    use najwa_transport::{config::TorConfig, tor::TorTransport};
    let alice_ik = Ed25519KeyPair::from_seed(&[81; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[82; 32]);
    let bob_spk = X25519KeyPair::from_seed([83; 32]);
    let a_state = init_alice(&[84; 32], bob_spk.public(), &[85; 32]).unwrap();
    let b_state = init_bob(&[84; 32], bob_spk);
    let transport = Arc::new(TorTransport::new(TorConfig::default()));
    let expected = najwa_crypto::time::now() + 3600;
    transport
        .clock()
        .synchronize_from_estimates(&[expected])
        .unwrap();
    let storage = MockStorage::new();
    storage.add_contact(contact_row(
        BOB_PSEUDO,
        ALICE_PSEUDO,
        bob_ik.public().to_bytes(),
        "Bob",
    ));
    storage.add_capability(ContactCapability {
        contact_id: 1,
        mailbox_id: 100,
        mailbox_onion: "bob.onion".into(),
        mailbox_fetch_cap: [86; 32],
        mailbox_deposit_cap: DCA,
        their_deposit_capability: Some(DCB),
        their_envelope_secret: Some(ESB),
    });
    let bob_fixture = build_bob(
        &[82; 32],
        [83; 32],
        [87; 32],
        [1; 4],
        [2; 4],
        alice_ik.public().to_bytes(),
    );
    let bob_transport = Arc::new(TorTransport::new(TorConfig::default()));
    bob_transport
        .clock()
        .synchronize_from_estimates(&[expected])
        .unwrap();
    let bob = MessagingService::with_transport(
        bob_ik,
        bob_fixture.storage,
        bob_fixture.mailbox_client,
        bob_transport.clone(),
    );
    let alice =
        MessagingService::with_transport(alice_ik, storage, MockMailbox::new(), transport.clone());
    alice.storage.save_ratchet_state(1, &a_state).await.unwrap();
    bob.storage.save_ratchet_state(1, &b_state).await.unwrap();
    alice
        .storage
        .save_session_ad(1, b"shared row4 AD")
        .await
        .unwrap();
    bob.storage
        .save_session_ad(1, b"shared row4 AD")
        .await
        .unwrap();

    let sent = alice
        .send_message(1, MessageContent::Text("clock corrected".into()))
        .await
        .unwrap();
    let stored = alice
        .storage
        .get_message_by_msg_id(&sent.msg_id)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.timestamp.abs_diff(expected) <= 5);
    let frames = alice.mailbox_client.take_deposited();
    assert_eq!(frames.len(), 1);
    let inner =
        najwa_protocol::message::envelope::envelope_decrypt(&ESB, &DCB, &frames[0].1).unwrap();
    // A receiver accidentally using system time rejects this as >5 minutes in
    // the future, even though sender and receiver share the corrected clock.
    let received = bob.process_message(&inner, None).await.unwrap().unwrap();
    assert_eq!(received.content, b"clock corrected");
    assert_eq!(received.timestamp, stored.timestamp);
    bob.mailbox_client.take_deposited();

    // With no correction at the receiver, a control payload from Alice must
    // fail timestamp validation. This catches a sender stamping controls with
    // the old system clock while stamping user messages correctly.
    bob_transport
        .clock()
        .synchronize_from_estimates(&[])
        .unwrap();
    alice
        .send_control_message(1, &ControlMessage::TypingIndicator)
        .await
        .unwrap();
    let control = alice.mailbox_client.take_deposited();
    assert_eq!(control.len(), 1);
    let inner =
        najwa_protocol::message::envelope::envelope_decrypt(&ESB, &DCB, &control[0].1).unwrap();
    assert!(matches!(
        bob.process_message(&inner, None).await,
        Err(MessagingError::TimestampOutOfRange)
    ));
}

#[tokio::test]
async fn corrected_message_clock_does_not_shift_local_retention_deadlines() {
    use najwa_protocol::ratchet::init::init_alice;
    use najwa_storage::prelude as sql;
    use najwa_transport::{config::TorConfig, tor::TorTransport};
    let db = sql::SqliteStorage::open_in_memory(&[91; 32]).unwrap();
    let ik = Ed25519KeyPair::from_seed(&[92; 32]);
    let peer = Ed25519KeyPair::from_seed(&[93; 32]);
    let cid = db
        .create_contact(&sql::NewContact {
            pseudonym: BOB_PSEUDO,
            their_ik_pub: peer.public().to_bytes(),
            their_device_pub: peer.public().to_bytes(),
            our_pseudonym: ALICE_PSEUDO,
            display_name: None,
        })
        .unwrap();
    let mid = db
        .save_mailbox(&sql::NewMailbox {
            onion_address: "bob.onion".into(),
            fetch_capability: vec![94; 32],
            deposit_capability: DCA.to_vec(),
            envelope_secret: ESA.to_vec(),
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
            priority: 1,
            created_at: 1,
        })
        .unwrap();
    db.save_contact_capability(&sql::NewContactMailboxCap {
        contact_id: cid,
        mailbox_id: mid,
        deposit_capability: DCA.to_vec(),
        fetch_capability: Some(vec![94; 32]),
        their_deposit_capability: Some(DCB.to_vec()),
        their_envelope_secret: Some(ESB.to_vec()),
        envelope_secret: Some(ESA.to_vec()),
        capability_type: 2,
        expires_at: None,
        registered_at: Some(1),
        created_at: 1,
    })
    .unwrap();
    let state = init_alice(
        &[95; 32],
        X25519KeyPair::from_seed([96; 32]).public(),
        &[97; 32],
    )
    .unwrap();
    CoreStorage::save_ratchet_state(&db, cid as u64, &state)
        .await
        .unwrap();
    CoreStorage::save_session_ad(&db, cid as u64, b"row4 AD")
        .await
        .unwrap();
    db.set_conversation_timer(cid, Some(30)).unwrap();
    let transport = Arc::new(TorTransport::new(TorConfig::default()));
    transport
        .clock()
        .synchronize_from_estimates(&[najwa_crypto::time::now() + 3600])
        .unwrap();
    let service = MessagingService::with_transport(ik, db, MockMailbox::new(), transport);
    let start = najwa_crypto::time::now_ms() as u64;
    let sent = service
        .send_message(cid as u64, MessageContent::Text("expires locally".into()))
        .await
        .unwrap();
    let stored = service
        .storage
        .get_message_by_msg_id(&sent.msg_id)
        .unwrap()
        .unwrap();
    assert!(stored.timestamp as u64 >= start / 1000 + 3599);
    let deadline = stored.disappear_at.unwrap();
    let delay = (crate::disappearing::SENDER_FALLBACK_SECS + 30) * 1000;
    assert!(
        (start + delay..=najwa_crypto::time::now_ms() as u64 + delay).contains(&(deadline as u64))
    );
}
