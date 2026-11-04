// S11 §4.1 missing-part requests between two SQLCipher-backed services.
// Included inside lib.rs's test module to reuse its mailbox harness.
mod row11 {
    use super::*;
    use najwa_protocol::message::control::ControlMessage;
    use najwa_protocol::message::envelope::envelope_decrypt;
    use najwa_protocol::message::file_transfer::{
        FileChunkWire, FileMetadata, MAX_CHUNK_SIZE, NACK_MAX_ATTEMPTS, NACK_MIN_INTERVAL_SECS,
    };
    use najwa_storage::prelude as sql;

    type Party = MessagingService<sql::SqliteStorage, MockMailbox>;
    const SESSION: [u8; 16] = [0x5A; 16];

    /// A party whose contact 1 is the other side: `own` is its mailbox
    /// (deposit capability, envelope secret), `theirs` the peer's.
    async fn party(
        me: u8,
        peer: u8,
        (their_pseudonym, our_pseudonym): ([u8; 32], [u8; 32]),
        own: ([u8; 32], [u8; 32]),
        theirs: ([u8; 32], [u8; 32]),
        state: &RatchetState,
    ) -> Party {
        let db = sql::SqliteStorage::open_in_memory(&[me; 32]).unwrap();
        let peer_ik = Ed25519KeyPair::from_seed(&[peer; 32]).public().to_bytes();
        let cid = db
            .create_contact(&sql::NewContact {
                pseudonym: their_pseudonym,
                their_ik_pub: peer_ik,
                their_device_pub: peer_ik,
                our_pseudonym,
                display_name: None,
            })
            .unwrap();
        let mailbox = db
            .save_mailbox(&sql::NewMailbox {
                onion_address: "test.onion".into(),
                fetch_capability: vec![me; 32],
                deposit_capability: own.0.to_vec(),
                envelope_secret: own.1.to_vec(),
                cover_deposit_capability: None,
                cover_fetch_capability: None,
                cover_envelope_secret: None,
                priority: 1,
                created_at: 1,
            })
            .unwrap();
        db.save_contact_capability(&sql::NewContactMailboxCap {
            contact_id: cid,
            mailbox_id: mailbox,
            deposit_capability: own.0.to_vec(),
            fetch_capability: Some(vec![me; 32]),
            their_deposit_capability: Some(theirs.0.to_vec()),
            their_envelope_secret: Some(theirs.1.to_vec()),
            envelope_secret: Some(own.1.to_vec()),
            capability_type: 2,
            expires_at: None,
            registered_at: Some(1),
            created_at: 1,
        })
        .unwrap();
        CoreStorage::save_ratchet_state(&db, cid as u64, state).await.unwrap();
        CoreStorage::save_session_ad(&db, cid as u64, b"row11 session AD")
            .await
            .unwrap();
        MessagingService::new(Ed25519KeyPair::from_seed(&[me; 32]), db, MockMailbox::new())
    }

    /// Alice (the file's sender) and Bob with a session in both directions.
    async fn pair() -> (Party, Party) {
        use najwa_protocol::ratchet::init::{init_alice, init_bob};
        let spk = X25519KeyPair::from_seed([93; 32]);
        let a = init_alice(&[94; 32], spk.public(), &[95; 32]).unwrap();
        let b = init_bob(&[94; 32], spk);
        let alice = party(91, 92, (BOB_PSEUDO, ALICE_PSEUDO), (DCA, ESA), (DCB, ESB), &a).await;
        let bob = party(92, 91, (ALICE_PSEUDO, BOB_PSEUDO), (DCB, ESB), (DCA, ESA), &b).await;
        alice
            .send_message(1, MessageContent::Text("bootstrap".into()))
            .await
            .unwrap();
        to_bob(&alice, &bob, |_| true).await;
        to_alice(&bob, &alice).await;
        (alice, bob)
    }

    /// Deliver Alice's deposits to Bob, dropping those `keep` refuses.
    async fn to_bob(alice: &Party, bob: &Party, keep: impl Fn(usize) -> bool) {
        for (i, (_, blob)) in alice.mailbox_client.take_deposited().into_iter().enumerate() {
            if keep(i) {
                let inner = envelope_decrypt(&ESB, &DCB, &blob).unwrap();
                bob.process_message(&inner, None).await.unwrap();
            }
        }
    }

    async fn to_alice(bob: &Party, alice: &Party) {
        for (_, blob) in bob.mailbox_client.take_deposited() {
            let inner = envelope_decrypt(&ESA, &DCA, &blob).unwrap();
            alice.process_message(&inner, None).await.unwrap();
        }
    }

    /// Alice sends a three-part file; returns the file and each part's row id.
    async fn send_file(alice: &Party) -> (Vec<u8>, FileMetadata, Vec<i64>) {
        let data: Vec<u8> = (0..2 * MAX_CHUNK_SIZE + 100).map(|i| i as u8).collect();
        let meta = FileMetadata {
            session_id: SESSION,
            filename: "a.bin".into(),
            total_size: data.len() as u64,
            mime_type: "application/octet-stream".into(),
            chunk_count: 3,
            sha256_hash: najwa_crypto::hash::sha256(&data),
        };
        let raw = |content_type, bytes| MessageContent::Raw {
            content_type,
            bytes,
            reply_to: None,
        };
        alice.send_message(1, raw(0x10, meta.to_bytes())).await.unwrap();
        let mut parts = Vec::new();
        for (index, data) in data.chunks(MAX_CHUNK_SIZE).enumerate() {
            let body = FileChunkWire {
                session_id: SESSION,
                index: index as u32,
                data: data.to_vec(),
            };
            parts.push(alice.send_message(1, raw(0x11, body.to_bytes())).await.unwrap().id);
        }
        (data, meta, parts)
    }

    fn queued(p: &Party) -> usize {
        p.storage.outgoing_frames().unwrap().len()
    }

    /// Received metadata row of SESSION.
    fn received_metadata(bob: &Party) -> najwa_storage::types::Message {
        bob.storage
            .browser_messages(1)
            .unwrap()
            .into_iter()
            .find(|m| m.content_type == najwa_storage::types::ContentType::FileMetadata)
            .unwrap()
    }

    #[tokio::test]
    async fn lost_part_is_requested_after_the_quiet_period_and_resent_by_its_sender() {
        let (alice, bob) = pair().await;
        let (data, meta, parts) = send_file(&alice).await;
        let before = najwa_crypto::time::now();
        // Deposits: metadata, part 0, part 1, part 2. The mailbox loses part 1.
        to_bob(&alice, &bob, |i| i != 2).await;
        let after = najwa_crypto::time::now();
        to_alice(&bob, &alice).await;
        assert_eq!(bob.storage.attachment_progress(1, &SESSION, false).unwrap().0, 2);

        let idle = queued(&bob);
        bob.enqueue_file_nacks(before + NACK_MIN_INTERVAL_SECS - 1).await.unwrap();
        assert_eq!(queued(&bob), idle, "no request inside the quiet period");
        bob.enqueue_file_nacks(after + NACK_MIN_INTERVAL_SECS).await.unwrap();
        assert_eq!(queued(&bob), idle + 1, "one FileChunkNack");

        bob.retry_outgoing().await.unwrap();
        to_alice(&bob, &alice).await;
        let resent: Vec<_> = alice
            .storage
            .outgoing_frames()
            .unwrap()
            .into_iter()
            .filter_map(|f| f.message_id)
            .collect();
        assert_eq!(resent, [parts[1]], "only the stored part 1 is re-sent");

        alice.retry_outgoing().await.unwrap();
        to_bob(&alice, &bob, |_| true).await;
        let mut file = Vec::new();
        for index in 0..meta.chunk_count {
            let body = bob.storage.attachment_part(1, &SESSION, false, index).unwrap().unwrap();
            file.extend(FileChunkWire::from_bytes(&body).unwrap().data);
        }
        assert_eq!(file, data);
        assert_eq!(najwa_crypto::hash::sha256(&file), meta.sha256_hash);
        // Complete: the watch ends without another request or a failure.
        let idle = queued(&bob);
        bob.enqueue_file_nacks(after + 100 * NACK_MIN_INTERVAL_SECS).await.unwrap();
        assert_eq!(queued(&bob), idle);
        assert_eq!(received_metadata(&bob).retry_count, NACK_MAX_ATTEMPTS as i32 + 1);

        // The sender answers one NACK per file and contact per interval, and
        // ignores unknown files and another contact's files.
        to_alice(&bob, &alice).await;
        let idle = queued(&alice);
        for session in [SESSION, [0x77; 16]] {
            let nack = ControlMessage::FileChunkNack {
                session_id: session,
                missing_indices: vec![0, 1, 2],
            };
            bob.send_control_message(1, &nack).await.unwrap();
            to_alice(&bob, &alice).await;
        }
        let stranger = najwa_storage::messaging::InboundWork {
            id: 0,
            contact_id: 2,
            body: Vec::new(),
            cursor: 0,
        };
        alice.answer_file_nack(&stranger, SESSION, &[0, 1, 2]).await.unwrap();
        assert!(alice.storage.outgoing_file_part(2, &SESSION, 1).unwrap().is_none());
        assert_eq!(queued(&alice), idle, "no re-send for these requests");
        assert!(alice.storage.inbound_work().unwrap().is_empty());
    }

    #[tokio::test]
    async fn receiver_backs_off_and_fails_the_file_after_its_last_request() {
        let (alice, bob) = pair().await;
        send_file(&alice).await;
        to_bob(&alice, &bob, |i| i != 2).await;
        let mut at = najwa_crypto::time::now() + NACK_MIN_INTERVAL_SECS;
        let idle = queued(&bob);
        for attempt in 0..NACK_MAX_ATTEMPTS {
            bob.enqueue_file_nacks(at).await.unwrap();
            assert_eq!(queued(&bob), idle + attempt as usize + 1);
            assert_eq!(received_metadata(&bob).retry_count, attempt as i32 + 1);
            let wait = NACK_MIN_INTERVAL_SECS << (attempt + 1);
            bob.enqueue_file_nacks(at + wait - 1).await.unwrap();
            assert_eq!(queued(&bob), idle + attempt as usize + 1, "rate-limited per file");
            at += wait;
        }
        bob.enqueue_file_nacks(at).await.unwrap();
        bob.enqueue_file_nacks(at + 100 * NACK_MIN_INTERVAL_SECS).await.unwrap();
        assert_eq!(queued(&bob), idle + NACK_MAX_ATTEMPTS as usize, "attempts are bounded");
        assert_eq!(received_metadata(&bob).retry_count, NACK_MAX_ATTEMPTS as i32 + 1);
    }
}
