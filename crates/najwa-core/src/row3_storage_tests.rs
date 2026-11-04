// Included inside lib.rs's test module so the existing mailbox harness can be
// reused while the sender runs against real SQLCipher and the real core bridge.
#[tokio::test]
async fn sqlcipher_disappearing_repair_requires_live_key_and_unexpired_message() {
    use najwa_protocol::message::control::ControlMessage;
    use najwa_protocol::message::gap_repair::{EpochGap, GapRange};
    use najwa_protocol::ratchet::init::{init_alice, init_bob};
    use najwa_storage::prelude as sql;
    let alice_ik = Ed25519KeyPair::from_seed(&[71; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[72; 32]);
    let bob_spk = X25519KeyPair::from_seed([73; 32]);
    let a_state = init_alice(&[74; 32], bob_spk.public(), &[75; 32]).unwrap();
    let b_state = init_bob(&[74; 32], bob_spk);
    let db = sql::SqliteStorage::open_in_memory(&[76; 32]).unwrap();
    let cid = db
        .create_contact(&sql::NewContact {
            pseudonym: BOB_PSEUDO,
            their_ik_pub: bob_ik.public().to_bytes(),
            their_device_pub: bob_ik.public().to_bytes(),
            our_pseudonym: ALICE_PSEUDO,
            display_name: None,
        })
        .unwrap();
    let mid = db
        .save_mailbox(&sql::NewMailbox {
            onion_address: "test.onion".into(),
            fetch_capability: vec![77; 32],
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
        fetch_capability: Some(vec![77; 32]),
        their_deposit_capability: Some(DCB.to_vec()),
        their_envelope_secret: Some(ESB.to_vec()),
        envelope_secret: Some(ESA.to_vec()),
        capability_type: 2,
        expires_at: None,
        registered_at: Some(1),
        created_at: 1,
    })
    .unwrap();
    CoreStorage::save_ratchet_state(&db, cid as u64, &a_state)
        .await
        .unwrap();
    CoreStorage::save_session_ad(&db, cid as u64, b"row3 shared session AD")
        .await
        .unwrap();
    let bob = build_bob(
        &[72; 32],
        [73; 32],
        [78; 32],
        [1; 4],
        [2; 4],
        alice_ik.public().to_bytes(),
    );
    bob.storage.save_ratchet_state(1, &b_state).await.unwrap();
    bob.storage
        .save_session_ad(1, b"row3 shared session AD")
        .await
        .unwrap();
    let alice = MessagingService::new(alice_ik, db, MockMailbox::new());

    // Establish both directions through the real send/receive paths.
    alice
        .send_message(cid as u64, MessageContent::Text("bootstrap".into()))
        .await
        .unwrap();
    for (_, blob) in alice.mailbox_client.take_deposited() {
        let inner = najwa_protocol::message::envelope::envelope_decrypt(&ESB, &DCB, &blob).unwrap();
        bob.process_message(&inner, None).await.unwrap();
    }
    for (_, blob) in bob.mailbox_client.take_deposited() {
        let inner = najwa_protocol::message::envelope::envelope_decrypt(&ESA, &DCA, &blob).unwrap();
        alice.process_message(&inner, None).await.unwrap();
    }
    alice.storage.set_conversation_timer(cid, Some(30)).unwrap();
    for scenario in ["live", "key removed", "deadline passed", "deleted"] {
        // Each scenario is a fresh hour for the S08 §6.5 responder limit.
        alice.answered_gap_repairs.lock().unwrap().clear();
        let state = CoreStorage::get_ratchet_state(&alice.storage, cid as u64)
            .await
            .unwrap()
            .unwrap();
        let dh = state.dhs.public().to_bytes();
        let n = state.ns;
        let sent = alice
            .send_message(cid as u64, MessageContent::Text(scenario.into()))
            .await
            .unwrap();
        alice.mailbox_client.take_deposited(); // original user frame is lost
        let stored = alice
            .storage
            .get_message_by_msg_id(&sent.msg_id)
            .unwrap()
            .unwrap();
        let (repair, sealed) = alice
            .storage
            .get_outbound_repair_entry(cid, &dh, n)
            .unwrap()
            .unwrap();
        assert!(sealed);
        assert_eq!(repair.content, stored.content);
        assert!(!repair
            .content
            .windows(scenario.len())
            .any(|w| w == scenario.as_bytes()));
        match scenario {
            "key removed" => alice.volatile_cache.remove_key(&sent.msg_id),
            "deadline passed" => alice
                .storage
                .set_message_disappear_at(stored.id, 1)
                .unwrap(),
            "deleted" => alice.storage.delete_message(stored.id).unwrap(),
            _ => {}
        }
        bob.send_control_message(
            1,
            &ControlMessage::GapRepairRequest {
                epochs: vec![EpochGap {
                    dh_pub: dh,
                    ranges: vec![GapRange {
                        start_n: n,
                        end_n: n,
                    }],
                }],
            },
        )
        .await
        .unwrap();
        for (_, blob) in bob.mailbox_client.take_deposited() {
            let inner =
                najwa_protocol::message::envelope::envelope_decrypt(&ESA, &DCA, &blob).unwrap();
            alice.process_message(&inner, None).await.unwrap();
        }
        let replies = alice.mailbox_client.take_deposited();
        assert!(
            !replies.is_empty(),
            "repair request must receive a response: {scenario}"
        );
        for (_, blob) in replies {
            let inner =
                najwa_protocol::message::envelope::envelope_decrypt(&ESB, &DCB, &blob).unwrap();
            bob.process_message(&inner, None).await.unwrap();
        }
        let recovered = bob
            .storage
            .get_message_by_msg_id(&sent.msg_id)
            .await
            .unwrap();
        if scenario == "live" {
            assert_eq!(recovered.unwrap().content, scenario.as_bytes());
        } else {
            assert!(
                recovered.is_none(),
                "expired content was retransmitted: {scenario}"
            );
        }
    }
}
