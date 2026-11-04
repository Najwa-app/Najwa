// Production send paths over in-process transport, with real envelope/ratchet crypto.
#[tokio::test]
async fn mutual_introduction_transmits_each_destinations_envelope_secret() {
    use najwa_protocol::message::{
        control::ControlMessage,
        envelope::{envelope_decrypt, envelope_encrypt},
        MessageHeader, Payload, WireMessage,
    };
    use najwa_protocol::ratchet::{
        decrypt::ratchet_decrypt,
        init::{init_alice, init_bob},
    };
    let ik = Ed25519KeyPair::from_seed(&[101; 32]);
    let introducer_pub = ik.public().clone();
    let storage = MockStorage::new();
    let service = MessagingService::new(ik, storage.clone(), MockMailbox::new());
    let mut receivers = Vec::new();
    for i in 1..=2u8 {
        let peer = Ed25519KeyPair::from_seed(&[101 + i; 32]);
        let mut contact = contact_row([i; 32], [10 + i; 32], peer.public().to_bytes(), "Peer");
        contact.id = i as u64;
        storage.add_contact(contact);
        storage.add_capability(ContactCapability {
            contact_id: i as u64,
            mailbox_id: i as i64,
            mailbox_onion: char::from(b'a' + i).to_string().repeat(56),
            mailbox_fetch_cap: [1; 32],
            mailbox_deposit_cap: [2; 32],
            // Same deposit token at two different servers, different secrets.
            their_deposit_capability: Some([3; 32]),
            their_envelope_secret: Some([20 + i; 32]),
        });
        let spk = X25519KeyPair::from_seed([30 + i; 32]);
        let sending = init_alice(&[40 + i; 32], spk.public(), &[50 + i; 32]).unwrap();
        receivers.push(init_bob(&[40 + i; 32], spk));
        storage
            .save_ratchet_state(i as u64, &sending)
            .await
            .unwrap();
        storage
            .save_session_ad(i as u64, b"row5 introduction AD")
            .await
            .unwrap();
    }
    // Refuse before sending either half if one contact lacks its D3 secret.
    storage.capabilities.lock().unwrap().get_mut(&2).unwrap()[0].their_envelope_secret = None;
    assert!(service.send_introduction(1, 2, false).await.is_err());
    assert!(service.mailbox_client.take_deposited().is_empty());
    assert_eq!(storage.get_ratchet_state(1).await.unwrap().unwrap().ns, 0);
    storage.capabilities.lock().unwrap().get_mut(&2).unwrap()[0].their_envelope_secret =
        Some([22; 32]);
    service.send_introduction(1, 2, false).await.unwrap();
    let deposits = service.mailbox_client.take_deposited();
    assert_eq!(deposits.len(), 2);
    for (index, ((onion, blob), receiver)) in deposits.iter().zip(&mut receivers).enumerate() {
        let recipient = index as u8 + 1;
        let introduced = 3 - recipient;
        assert_eq!(onion, &char::from(b'a' + recipient).to_string().repeat(56));
        let inner = envelope_decrypt(&[20 + recipient; 32], &[3; 32], blob).unwrap();
        let wire = WireMessage::from_bytes(&inner).unwrap();
        let MessageHeader::Ratchet(header) = &wire.header;
        let plaintext = ratchet_decrypt(
            receiver,
            header,
            &wire.encrypted_payload,
            b"row5 introduction AD",
            &wire.wire_prefix().unwrap(),
        )
        .unwrap();
        let payload = Payload::from_bytes(&plaintext).unwrap();
        let ControlMessage::Introduction(intro) =
            ControlMessage::from_bytes(&payload.content).unwrap()
        else {
            panic!("introduction payload")
        };
        intro.verify(&introducer_pub).unwrap();
        let target = &intro.introduced_mailboxes[0];
        assert_eq!(
            target.onion_address,
            char::from(b'a' + introduced).to_string().repeat(56)
        );
        assert_eq!(target.envelope_secret, [20 + introduced; 32]);
        let first_message = envelope_encrypt(
            &target.envelope_secret,
            &target.deposit_capability,
            b"hello",
        )
        .unwrap();
        assert_eq!(
            envelope_decrypt(&[20 + introduced; 32], &[3; 32], &first_message).unwrap(),
            b"hello"
        );
    }
}

#[tokio::test]
async fn accepted_sqlite_contact_sends_to_signed_remote_destination() {
    use najwa_protocol::contact::{accept::accept_contact, HandshakePayload};
    use najwa_protocol::message::envelope::envelope_decrypt;
    use najwa_protocol::ratchet::init::init_alice;
    use najwa_storage::prelude as sql;
    let db = sql::SqliteStorage::open_in_memory(&[110; 32]).unwrap();
    db.save_mailbox(&sql::NewMailbox {
        onion_address: "l".repeat(56),
        fetch_capability: vec![1; 32],
        deposit_capability: vec![2; 32],
        envelope_secret: vec![3; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
        priority: 0,
        created_at: 1,
    })
    .unwrap();
    let ik = Ed25519KeyPair::from_seed(&[111; 32]);
    let peer = Ed25519KeyPair::from_seed(&[112; 32]);
    let mut remote = MailboxConfig::new("r".repeat(56), [4; 32], [5; 32]);
    remote.envelope_secret = [6; 32];
    let mut handshake = HandshakePayload::create(&peer, &[remote], "Peer", 48).unwrap();
    handshake.mailboxes[0].onion_address = "unsigned-attacker".into();
    let id = accept_contact(&ik, &db, &handshake)
        .await
        .unwrap()
        .contact_id
        .0;
    let spk = X25519KeyPair::from_seed([113; 32]);
    let state = init_alice(&[114; 32], spk.public(), &[115; 32]).unwrap();
    CoreStorage::save_ratchet_state(&db, id, &state)
        .await
        .unwrap();
    CoreStorage::save_session_ad(&db, id, b"row5 accepted contact AD")
        .await
        .unwrap();
    let service = MessagingService::new(ik, db, MockMailbox::new());
    service
        .send_message(id, MessageContent::Text("hello remote".into()))
        .await
        .unwrap();
    let deposits = service.mailbox_client.take_deposited();
    assert_eq!(deposits.len(), 1);
    assert_eq!(deposits[0].0, "r".repeat(56));
    assert!(envelope_decrypt(&[6; 32], &[5; 32], &deposits[0].1).is_ok());
    assert!(envelope_decrypt(&[3; 32], &[2; 32], &deposits[0].1).is_err());
}
