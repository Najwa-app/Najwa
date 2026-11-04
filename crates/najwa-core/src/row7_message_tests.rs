// Row 7 regression tests: independent wire bodies over real crypto and SQLite.
#[tokio::test]
async fn durable_display_receipts_wait_for_view_and_retry_after_restart() {
    use najwa_protocol::message::envelope::envelope_decrypt;
    let (sender,receiver)=row7_pair().await;
    let sent=sender.send_message_with_flags(1,MessageContent::Text("read me".into()),4).await.unwrap();
    let frame=sender.mailbox_client.take_deposited().pop().unwrap();
    receiver.process_message(&envelope_decrypt(&ESA,&DCA,&frame.1).unwrap(),None).await.unwrap();
    for (_,ack) in receiver.mailbox_client.take_deposited() {
        sender.process_message(&envelope_decrypt(&ESB,&DCB,&ack).unwrap(),None).await.unwrap();
    }
    assert_eq!(sender.storage.get_message_by_msg_id(&sent.msg_id).await.unwrap().unwrap().status,MessageStatus::Delivered);
    // Receiving/fetching is not reading.
    receiver.enqueue_read_receipts().await.unwrap();
    assert!(receiver.storage.outgoing_frames().unwrap().is_empty());
    let received=receiver.storage.get_message_by_msg_id(&sent.msg_id).unwrap().unwrap();
    receiver.storage.mark_displayed_with_receipts(1,&[received.id]).unwrap();
    let displayed=receiver.storage.pending_read_receipts().unwrap()[0].timestamp;
    // Simulate expiry and shutdown before the worker prepares the receipt.
    receiver.storage.delete_message(received.id).unwrap();
    let restarted=MessagingService::new(Ed25519KeyPair::from_seed(&[171;32]),receiver.storage,MockMailbox::new());
    let (a,b)=tokio::join!(restarted.enqueue_read_receipts(),restarted.enqueue_read_receipts()); a.unwrap();b.unwrap();
    let queued=restarted.storage.outgoing_frames().unwrap();
    assert_eq!(queued.len(),1); assert!(!queued[0].requires_ack);
    assert!(restarted.mailbox_client.take_deposited().is_empty(),"display preparation must not use the network");
    // A failed delivery leaves the same ciphertext for automatic retry.
    restarted.storage.finish_outgoing(queued[0].id,false,0).unwrap();
    let restarted=MessagingService::new(Ed25519KeyPair::from_seed(&[171;32]),restarted.storage,MockMailbox::new());
    restarted.retry_outgoing().await.unwrap();
    let receipts=restarted.mailbox_client.take_deposited(); assert_eq!(receipts.len(),1);
    let raw=envelope_decrypt(&ESB,&DCB,&receipts[0].1).unwrap();
    assert_eq!(raw,queued[0].wire);
    sender.process_message(&raw,None).await.unwrap();
    let stored=sender.storage.get_message_by_msg_id(&sent.msg_id).await.unwrap().unwrap();
    assert_eq!(stored.status,MessageStatus::Read);
    assert!(displayed<=najwa_crypto::time::now());
    assert!(restarted.storage.outgoing_frames().unwrap().is_empty());
}

async fn row7_pair() -> (
    MessagingService<MockStorage, MockMailbox>,
    MessagingService<najwa_storage::database::SqliteStorage, MockMailbox>,
) {
    use najwa_protocol::ratchet::init::{init_alice, init_bob};
    use najwa_storage::prelude as sql;
    let receiver_key = Ed25519KeyPair::from_seed(&[171; 32]);
    let sender_key = Ed25519KeyPair::from_seed(&[172; 32]);
    let spk = X25519KeyPair::from_seed([173; 32]);
    let sending = init_alice(&[174; 32], spk.public(), &[175; 32]).unwrap();
    let receiving = init_bob(&[174; 32], spk);
    let sender = build_bob(
        &[172; 32],
        [176; 32],
        [177; 32],
        [1; 4],
        [2; 4],
        receiver_key.public().to_bytes(),
    );
    sender
        .storage
        .save_ratchet_state(1, &sending)
        .await
        .unwrap();
    sender.storage.save_session_ad(1, b"row7 AD").await.unwrap();
    let db = sql::SqliteStorage::open_in_memory(&[178; 32]).unwrap();
    let id = db
        .create_contact(&sql::NewContact {
            pseudonym: BOB_PSEUDO,
            their_ik_pub: sender_key.public().to_bytes(),
            their_device_pub: sender_key.public().to_bytes(),
            our_pseudonym: ALICE_PSEUDO,
            display_name: None,
        })
        .unwrap();
    assert_eq!(id, 1);
    let mailbox = db
        .save_mailbox(&sql::NewMailbox {
            onion_address: "a".repeat(56),
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
        contact_id: id,
        mailbox_id: mailbox,
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
    CoreStorage::save_ratchet_state(&db, 1, &receiving)
        .await
        .unwrap();
    CoreStorage::save_session_ad(&db, 1, b"row7 AD")
        .await
        .unwrap();
    (
        sender,
        MessagingService::new(receiver_key, db, MockMailbox::new()),
    )
}

async fn row7_frame(
    sender: &MessagingService<MockStorage, MockMailbox>,
    kind: u8,
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    use najwa_protocol::message::{MessageHeader, MessageType, WireMessage, WirePrefixMeta};
    let mut state = sender.storage.get_ratchet_state(1).await.unwrap().unwrap();
    let (header, encrypted_payload) = najwa_protocol::ratchet::encrypt::ratchet_encrypt(
        &mut state,
        plaintext,
        b"row7 AD",
        &WirePrefixMeta {
            version: 1,
            message_type: kind,
            x3dh_header: None,
        },
    )
    .unwrap();
    sender.storage.save_ratchet_state(1, &state).await.unwrap();
    let mut input = header.dh_pub.to_bytes().to_vec();
    input.extend_from_slice(&header.n.to_be_bytes());
    let id = najwa_crypto::hash::sha256(&input)[..16].try_into().unwrap();
    (
        WireMessage {
            version: 1,
            message_type: MessageType::try_from(kind).unwrap(),
            header: MessageHeader::Ratchet(header),
            x3dh_header: None,
            encrypted_payload,
        }
        .to_bytes(),
        id,
    )
}

fn row7_payload(kind: u8, flags: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = BOB_PSEUDO.to_vec();
    bytes.extend_from_slice(&[kind, flags]);
    bytes.extend_from_slice(&najwa_crypto::time::now().to_be_bytes());
    bytes.extend_from_slice(&[191; 16]);
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(&(content.len() as u32).to_be_bytes());
    bytes.extend_from_slice(content);
    bytes.resize(bytes.len().max(96), 0);
    bytes
}

#[tokio::test]
async fn row7_unknown_authenticated_frames_commit_and_deduplicate_without_response() {
    for (wire_type, payload) in [
        (0x7e, vec![99; 96]),
        (2, row7_payload(0x7e, 0, b"future")),
        (2, row7_payload(0x20, 0, &[0x7e])),
        (2, row7_payload(0x20, 0, &[0x25, 99])),
        (2, row7_payload(4, 0, &[99])),
    ] {
        let (sender, receiver) = row7_pair().await;
        let (raw, id) = row7_frame(&sender, wire_type, &payload).await;
        assert!(receiver
            .process_message(&raw, None)
            .await
            .unwrap()
            .is_none());
        let state = CoreStorage::get_ratchet_state(&receiver.storage, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.nr, 1);
        assert!(receiver.storage.check_msg_id_seen(&id).unwrap());
        assert!(receiver
            .storage
            .list_messages(1, 10, None)
            .unwrap()
            .is_empty());
        assert!(receiver
            .process_message(&raw, None)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            CoreStorage::get_ratchet_state(&receiver.storage, 1)
                .await
                .unwrap()
                .unwrap()
                .nr,
            1
        );
        assert!(receiver.mailbox_client.take_deposited().is_empty());
        assert!(receiver.epoch_quarantine.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn row7_malformed_file_bodies_commit_without_a_message_row() {
    for payload in [
        row7_payload(0x10, 0, &[1; 70]), // filename_len 257 fails S11 §2.2.1
        row7_payload(0x11, 0, &[2; 23]), // shorter than a FileChunk header
    ] {
        let (sender, receiver) = row7_pair().await;
        let (raw, id) = row7_frame(&sender, 2, &payload).await;
        assert!(receiver
            .process_message(&raw, None)
            .await
            .unwrap()
            .is_none());
        let state = CoreStorage::get_ratchet_state(&receiver.storage, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.nr, 1);
        assert!(receiver.storage.check_msg_id_seen(&id).unwrap());
        assert!(receiver
            .storage
            .list_messages(1, 10, None)
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn row7_future_outer_version_and_bad_aead_do_not_advance() {
    let (sender, receiver) = row7_pair().await;
    let (mut raw, id) = row7_frame(&sender, 0x7e, &[0; 96]).await;
    raw[0] = 99;
    assert!(receiver
        .process_message(&raw, None)
        .await
        .unwrap()
        .is_none());
    raw[0] = 1;
    *raw.last_mut().unwrap() ^= 1;
    assert!(receiver.process_message(&raw, None).await.is_err());
    assert_eq!(
        CoreStorage::get_ratchet_state(&receiver.storage, 1)
            .await
            .unwrap()
            .unwrap()
            .nr,
        0
    );
    assert!(!receiver.storage.check_msg_id_seen(&id).unwrap());
    assert!(receiver.mailbox_client.take_deposited().is_empty());
}

#[tokio::test]
async fn row7_read_receipt_updates_opted_in_sent_message_and_is_atomic() {
    use najwa_protocol::message::ack::{to_padded_plaintext, ReadReceiptContent};
    use najwa_storage::types::MessageStatus as SqlStatus;
    let (sender, receiver) = row7_pair().await;
    let msg_id = [180; 16];
    CoreStorage::save_message(
        &receiver.storage,
        &Message {
            id: 0,
            contact_id: 1,
            msg_id,
            direction: Direction::Sent,
            content_type: 1,
            flags: 4,
            content: b"read me".to_vec(),
            timestamp: najwa_crypto::time::now(),
            status: MessageStatus::Sent,
            ratchet_index: Some(0),
        },
    )
    .await
    .unwrap();
    let body = to_padded_plaintext(
        &ReadReceiptContent {
            msg_id,
            timestamp: 123,
        }
        .to_bytes(),
        96,
    )
    .unwrap();
    let (raw, id) = row7_frame(&sender, 0x11, &body).await;
    assert!(receiver
        .process_message(&raw, None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        receiver
            .storage
            .get_message_by_msg_id(&msg_id)
            .unwrap()
            .unwrap()
            .status,
        SqlStatus::Read
    );
    assert!(receiver.storage.check_msg_id_seen(&id).unwrap());
    assert!(receiver.mailbox_client.take_deposited().is_empty());
}

#[tokio::test]
async fn row7_reply_and_flags_survive_send_receive_storage() {
    use najwa_protocol::message::{envelope::envelope_decrypt, TextReplyContent};
    let (sender, receiver) = row7_pair().await;
    sender
        .send_message_with_flags(
            1,
            MessageContent::TextReply {
                text: "hello reply".into(),
                reply_to: [9; 16],
            },
            6,
        )
        .await
        .unwrap();
    let frames = sender.mailbox_client.take_deposited();
    let raw = envelope_decrypt(&ESA, &DCA, &frames[0].1).unwrap();
    let received = receiver.process_message(&raw, None).await.unwrap().unwrap();
    assert_eq!(received.content_type, 2);
    let content = TextReplyContent::from_bytes(&received.content).unwrap();
    assert_eq!(content.text, "hello reply");
    let stored = CoreStorage::get_message_by_msg_id(&receiver.storage, &received.msg_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.flags, 6);
    assert_eq!(stored.content_type, 2);
    let sql = receiver
        .storage
        .get_message_by_msg_id(&received.msg_id)
        .unwrap()
        .unwrap();
    assert_eq!(sql.reply_to_msg_id, Some(vec![9; 16]));
}

#[tokio::test]
async fn row7_identity_rotation_rejects_unsigned_body_without_changing_contact() {
    let (sender, receiver) = row7_pair().await;
    let old = receiver
        .storage
        .get_contact(1)
        .unwrap()
        .unwrap()
        .their_ik_pub;
    let mut body = vec![0x21];
    body.extend_from_slice(&old);
    body.extend_from_slice(&[0; 168]);
    let (raw, _) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &body)).await;
    assert!(receiver.process_message(&raw, None).await.is_err());
    assert_eq!(
        receiver
            .storage
            .get_contact(1)
            .unwrap()
            .unwrap()
            .their_ik_pub,
        old
    );
}

#[tokio::test]
async fn row7_normal_message_emits_registered_ack_and_marks_sender_delivered() {
    use najwa_protocol::message::{envelope::envelope_decrypt, MessageType, WireMessage};
    let (sender, receiver) = row7_pair().await;
    let sent = sender
        .send_message(1, MessageContent::Text("ack me".into()))
        .await
        .unwrap();
    let frame = sender.mailbox_client.take_deposited().pop().unwrap();
    let raw = envelope_decrypt(&ESA, &DCA, &frame.1).unwrap();
    receiver.process_message(&raw, None).await.unwrap();
    let acks = receiver.mailbox_client.take_deposited();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].1.len(), 256);
    let raw_ack = envelope_decrypt(&ESB, &DCB, &acks[0].1).unwrap();
    assert_eq!(
        WireMessage::from_bytes(&raw_ack).unwrap().message_type,
        MessageType::CumulativeAck
    );
    assert!(sender
        .process_message(&raw_ack, None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sender
            .storage
            .get_message_by_msg_id(&sent.msg_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MessageStatus::Delivered
    );
    assert!(
        sender.mailbox_client.take_deposited().is_empty(),
        "ACKs must not ping-pong"
    );
}

#[tokio::test]
async fn row7_mailbox_update_changes_route_without_deleting_contact_or_messages() {
    use najwa_protocol::contact::mailbox_key::MailboxEntry;
    use najwa_protocol::message::{control::ControlMessage, envelope::envelope_decrypt};
    let (sender, receiver) = row7_pair().await;
    let entry = MailboxEntry {
        onion_address: [b'z'; 56],
        deposit_capability: [41; 32],
        envelope_secret: [42; 32],
        mailbox_ik_pub: [43; 32],
        cert_signature: [44; 64],
        capability_type: 2,
    };
    let bytes = ControlMessage::MailboxUpdate {
        mailboxes: vec![entry],
    }
    .to_bytes();
    let (raw, _) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &bytes)).await;
    receiver.process_message(&raw, None).await.unwrap();
    assert!(receiver.storage.get_contact(1).unwrap().is_some());
    assert!(CoreStorage::get_ratchet_state(&receiver.storage, 1)
        .await
        .unwrap()
        .is_some());
    let caps = CoreStorage::get_contact_capabilities(&receiver.storage, 1)
        .await
        .unwrap();
    assert_eq!(caps[0].mailbox_onion, "z".repeat(56));
    assert_eq!(caps[0].their_deposit_capability, Some([41; 32]));
    let frames = receiver.mailbox_client.take_deposited();
    assert!(envelope_decrypt(&[42; 32], &[41; 32], &frames[0].1).is_ok());
}

#[tokio::test]
async fn row7_malformed_confirmations_do_not_consume_ratchet_or_dedup() {
    use najwa_protocol::message::ack::{to_padded_plaintext, ReadReceiptContent};
    let mut receipt = to_padded_plaintext(
        &ReadReceiptContent {
            msg_id: [1; 16],
            timestamp: 0,
        }
        .to_bytes(),
        96,
    )
    .unwrap();
    receipt[95] = 1;
    let mut inverted = vec![0x12, 1];
    inverted.extend_from_slice(&[7; 32]);
    inverted.extend_from_slice(&9u32.to_be_bytes());
    inverted.extend_from_slice(&3u32.to_be_bytes());
    for (kind, body) in [
        (0x11, receipt),
        (0x12, to_padded_plaintext(&inverted, 96).unwrap()),
    ] {
        let (sender, receiver) = row7_pair().await;
        let (raw, id) = row7_frame(&sender, kind, &body).await;
        assert!(receiver.process_message(&raw, None).await.is_err());
        assert_eq!(
            CoreStorage::get_ratchet_state(&receiver.storage, 1)
                .await
                .unwrap()
                .unwrap()
                .nr,
            0
        );
        assert!(!receiver.storage.check_msg_id_seen(&id).unwrap());
        assert!(receiver.mailbox_client.take_deposited().is_empty());
    }
}

#[tokio::test]
async fn row7_display_receipt_is_opt_in_and_uses_top_level_wire_format() {
    use najwa_protocol::message::{envelope::envelope_decrypt, MessageType, WireMessage};
    for flags in [0, 4] {
        let (sender, receiver) = row7_pair().await;
        let sent = sender
            .send_message_with_flags(1, MessageContent::Text("display".into()), flags)
            .await
            .unwrap();
        let frames = sender.mailbox_client.take_deposited();
        let raw = envelope_decrypt(&ESA, &DCA, &frames[0].1).unwrap();
        receiver.process_message(&raw, None).await.unwrap();
        let ack = receiver.mailbox_client.take_deposited();
        sender
            .process_message(&envelope_decrypt(&ESB, &DCB, &ack[0].1).unwrap(), None)
            .await
            .unwrap();
        receiver.send_read_receipt(1, sent.msg_id).await.unwrap();
        let receipts = receiver.mailbox_client.take_deposited();
        assert_eq!(receipts.len(), usize::from(flags != 0));
        if flags != 0 {
            let raw = envelope_decrypt(&ESB, &DCB, &receipts[0].1).unwrap();
            assert_eq!(
                WireMessage::from_bytes(&raw).unwrap().message_type,
                MessageType::ReadReceipt
            );
            sender.process_message(&raw, None).await.unwrap();
            assert_eq!(
                sender
                    .storage
                    .get_message_by_msg_id(&sent.msg_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MessageStatus::Read
            );
        }
    }
}

#[tokio::test]
async fn row7_unknown_initial_content_establishes_session_and_consumes_opk() {
    use najwa_protocol::message::{MessageHeader, MessageType, WireMessage, WirePrefixMeta};
    let receiver_key = Ed25519KeyPair::from_seed(&[171; 32]);
    let sender_key = Ed25519KeyPair::from_seed(&[172; 32]);
    let sender = build_bob(
        &[172; 32],
        [176; 32],
        [177; 32],
        [1; 4],
        [2; 4],
        receiver_key.public().to_bytes(),
    );
    let receiver = build_bob(
        &[171; 32],
        [176; 32],
        [177; 32],
        [1; 4],
        [2; 4],
        sender_key.public().to_bytes(),
    );
    receiver.storage.add_contact(contact_row(
        BOB_PSEUDO,
        ALICE_PSEUDO,
        sender_key.public().to_bytes(),
        "Sender",
    ));
    sender.mailbox_client.set_prekey_bundle(make_prekey_bundle(
        &receiver_key,
        &X25519KeyPair::from_seed([176; 32]),
        &X25519KeyPair::from_seed([177; 32]),
        [1; 4],
        [2; 4],
    ));
    let contact = sender.storage.get_contact(1).await.unwrap().unwrap();
    let (mut state, combined, initial) = sender.get_or_create_session(&contact).await.unwrap();
    assert!(initial);
    let (x3dh, ad) = combined.split_at(combined.len() - 64);
    let (header, encrypted_payload) = najwa_protocol::ratchet::encrypt::ratchet_encrypt(
        &mut state,
        &row7_payload(0x7e, 0, b"future"),
        ad,
        &WirePrefixMeta {
            version: 1,
            message_type: 1,
            x3dh_header: Some(x3dh),
        },
    )
    .unwrap();
    let mut id_input = header.dh_pub.to_bytes().to_vec();
    id_input.extend_from_slice(&header.n.to_be_bytes());
    let id: [u8; 16] = najwa_crypto::hash::sha256(&id_input)[..16]
        .try_into()
        .unwrap();
    let raw = WireMessage {
        version: 1,
        message_type: MessageType::Initial,
        header: MessageHeader::Ratchet(header),
        x3dh_header: Some(x3dh.to_vec()),
        encrypted_payload,
    }
    .to_bytes();
    assert!(receiver
        .process_message(&raw, None)
        .await
        .unwrap()
        .is_none());
    assert!(receiver.storage.check_msg_id_seen(&id).await.unwrap());
    assert_eq!(
        receiver
            .storage
            .get_ratchet_state(1)
            .await
            .unwrap()
            .unwrap()
            .nr,
        1
    );
    assert!(receiver
        .storage
        .get_opk_keypair(&[2; 4])
        .await
        .unwrap()
        .is_none());
    assert!(receiver.storage.messages.lock().unwrap().is_empty());
    assert!(receiver.mailbox_client.take_deposited().is_empty());
}

/// S05 §11.4: an introduction is stored only after its expiry and the
/// introducer's signature verify against the delivering contact's key.
#[tokio::test]
async fn row7_introductions_are_stored_only_after_expiry_and_signature_checks() {
    use najwa_protocol::contact::introduction::IntroductionPayload;
    let (sender, receiver) = row7_pair().await;
    let introducer = Ed25519KeyPair::from_seed(&[172; 32]);
    let body = |intro: &IntroductionPayload| {
        let mut control = vec![0x25];
        control.extend_from_slice(&intro.to_bytes());
        row7_payload(0x20, 0, &control)
    };

    // Names the contact as introducer, but another key signed it.
    let mut forged = IntroductionPayload::create(&introducer, &[0x42; 32], "Carol", &[], 7).unwrap();
    forged.introducer_signature = Ed25519KeyPair::from_seed(&[9; 32])
        .sign(&forged.signable_bytes())
        .to_bytes();
    // Correctly signed, but already expired.
    let mut expired = IntroductionPayload::create(&introducer, &[0x43; 32], "Dave", &[], 7).unwrap();
    expired.timestamp -= 200;
    expired.expires_at = expired.timestamp + 100;
    expired.introducer_signature = introducer.sign(&expired.signable_bytes()).to_bytes();
    for bad in [&forged, &expired] {
        let (raw, _) = row7_frame(&sender, 2, &body(bad)).await;
        assert!(matches!(
            receiver.process_message(&raw, None).await,
            Err(MessagingError::InvalidIntroduction(_))
        ));
    }
    assert_eq!(receiver.storage.count_pending_introductions().unwrap(), 0);

    let valid = IntroductionPayload::create(&introducer, &[0x44; 32], "Erin", &[], 7).unwrap();
    let (raw, _) = row7_frame(&sender, 2, &body(&valid)).await;
    receiver.process_message(&raw, None).await.unwrap();
    assert_eq!(receiver.storage.count_pending_introductions().unwrap(), 1);
}
