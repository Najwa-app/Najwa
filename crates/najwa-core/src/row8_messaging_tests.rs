mod row8 {
    use super::*;
    use najwa_protocol::message::{
        control::ControlMessage, envelope::envelope_decrypt, MessageHeader, MessageType,
        WireMessage,
    };
    use std::sync::atomic::Ordering::SeqCst;
    include!("row8_faults.rs");

    async fn ready() -> MessagingService<najwa_storage::database::SqliteStorage, MockMailbox> {
        let (sender, receiver) = row7_pair().await;
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"establish")).await;
        receiver.process_message(&raw, None).await.unwrap();
        receiver.mailbox_client.take_deposited();
        receiver
    }
    fn unwrap_wire(blob: &[u8]) -> Vec<u8> {
        envelope_decrypt(&ESB, &DCB, blob).unwrap()
    }

    #[tokio::test]
    async fn responsive_poll_stores_a_batch_before_waiting_for_delivery_ack_and_recovers_after_cancel() {
        let (sender,receiver)=row7_pair().await;
        let (initial,_)=row7_frame(&sender,2,&row7_payload(1,0,b"establish")).await;
        receiver.process_message(&initial,None).await.unwrap();
        let mut svc=MessagingService::new(Ed25519KeyPair::from_seed(&[171;32]),receiver.storage,Row8Mailbox::new());
        let slots=Arc::new(crate::cover::SlotSource::new(Arc::new(crate::cover::PendingQueues::new()),Arc::new(true.into())));
        slots.set_bypass(true);svc.set_slot_source(slots);
        let session=[27;16];let mut incoming=Vec::new();
        for index in 0..8 {
            let bytes=najwa_protocol::message::file_transfer::FileChunkWire {session_id:session,index,data:vec![7;1024]}.to_bytes();
            let mut payload=row7_payload(0x11,0,&bytes);
            payload[42..58].copy_from_slice(&(index+1).to_be_bytes().repeat(4));
            payload[58..62].copy_from_slice(&(index+1).to_be_bytes());
            let (raw,_)=row7_frame(&sender,2,&payload).await;
            let blob=najwa_protocol::message::envelope::envelope_encrypt(&ESA,&DCA,&raw).unwrap();
            incoming.push(MailboxMessage{id:format!("file-{index}"),size:blob.len() as u32,blob,deposited_at:1,cap_hint:None});
        }
        svc.mailbox_client.inner.inject_fetched(incoming.clone());
        svc.mailbox_client.pause_deposit.store(true,SeqCst);
        let svc=Arc::new(svc);let worker=svc.clone();
        let poll=tokio::spawn(async move{worker.poll_messages().await});
        tokio::time::timeout(std::time::Duration::from_secs(2),svc.mailbox_client.deposit_entered.notified()).await.unwrap();
        let stored=svc.storage.attachment_progress(1,&session,false).unwrap().0;
        poll.abort();let _=poll.await;
        assert_eq!(stored,8,"a network ACK blocked committing the rest of the batch");
        assert_eq!(svc.storage.outgoing_frames().unwrap().len(),1,"one durable cumulative ACK must cover this batch");
        // Simulate a lost mailbox acknowledgement and a new service instance.
        let svc=Arc::try_unwrap(svc).ok().unwrap();
        let mut restarted=MessagingService::new(Ed25519KeyPair::from_seed(&[171;32]),svc.storage,MockMailbox::new());
        let slots=Arc::new(crate::cover::SlotSource::new(Arc::new(crate::cover::PendingQueues::new()),Arc::new(true.into())));
        slots.set_bypass(true);restarted.set_slot_source(slots);
        restarted.mailbox_client.inject_fetched(incoming);
        restarted.poll_messages().await.unwrap();
        assert_eq!(restarted.storage.attachment_progress(1,&session,false).unwrap().0,8);
        assert_eq!(restarted.mailbox_client.acked_ids().len(),8);
        assert!(restarted.storage.outgoing_frames().unwrap().is_empty());
    }

    #[tokio::test]
    async fn responsive_file_circuits_separate_files_contacts_and_mailboxes_and_respect_live_mode() {
        let mut svc = ready().await;
        let slots=Arc::new(crate::cover::SlotSource::new(
            Arc::new(crate::cover::PendingQueues::new()), Arc::new(true.into()),
        ));
        slots.set_bypass(true);
        svc.set_slot_source(slots.clone());
        for (session,index) in [([8;16],0),([8;16],1),([9;16],0)] {
            let bytes=najwa_protocol::message::file_transfer::FileChunkWire {
                session_id:session,index,data:vec![7;1024],
            }.to_bytes();
            svc.enqueue_message(1,MessageContent::Raw{content_type:0x11,bytes,reply_to:None}).await.unwrap();
        }
        svc.enqueue_message(1,MessageContent::Text("ordinary chat".into())).await.unwrap();
        let frames=svc.storage.outgoing_frames().unwrap();
        let cap=CoreStorage::get_contact_capabilities(&svc.storage,1).await.unwrap().remove(0);
        let first=svc.responsive_file_isolation(&cap,frames[0].id).await.unwrap();
        assert_eq!(svc.responsive_file_isolation(&cap,frames[1].id).await,Some(first));
        assert_ne!(svc.responsive_file_isolation(&cap,frames[2].id).await,Some(first));
        assert_eq!(svc.responsive_file_isolation(&cap,frames[3].id).await,None);
        let mut other=cap.clone();other.contact_id+=1;
        assert_ne!(svc.responsive_file_isolation(&other,frames[0].id).await,Some(first));
        other=cap.clone();other.mailbox_onion.push('b');
        assert_ne!(svc.responsive_file_isolation(&other,frames[0].id).await,Some(first));
        other=cap.clone();other.their_deposit_capability=Some([99;32]);
        assert_ne!(svc.responsive_file_isolation(&other,frames[0].id).await,Some(first));
        slots.set_bypass(false);
        assert_eq!(svc.responsive_file_isolation(&cap,frames[0].id).await,None);
        slots.set_bypass(true);
        assert_eq!(svc.responsive_file_isolation(&cap,frames[0].id).await,Some(first));
        assert_eq!(svc.responsive_file_isolation(&cap,i64::MAX).await,None);
    }

    #[tokio::test]
    async fn deposited_control_is_not_reported_as_waiting_for_an_offline_recipient() {
        let svc = ready().await;
        svc.enqueue_timer_change(1, Some(30)).await.unwrap();
        let frame = svc.storage.outgoing_frames().unwrap().pop().unwrap();
        assert!(frame.requires_ack);
        assert_eq!(svc.storage.pending_deposit_count().unwrap(), 1);
        assert!(frame.deposited_at.is_none());
        svc.retry_outgoing().await.unwrap();
        let deposited = svc.storage.outgoing_frames().unwrap().pop().unwrap();
        assert_eq!(svc.storage.pending_deposit_count().unwrap(), 0);
        assert!(deposited.deposited_at.is_some());
        assert!(svc.storage.timer_change_pending(1).unwrap());
        // A failed retransmission must not undo an already successful deposit.
        svc.storage.finish_outgoing(frame.id, false, 0).unwrap();
        assert_eq!(svc.storage.pending_deposit_count().unwrap(), 0);
        assert_eq!(svc.storage.outgoing_frames().unwrap()[0].deposited_at, deposited.deposited_at);
    }

    #[tokio::test]
    async fn desktop_timer_exchange_survives_restart_and_waits_for_authenticated_ack() {
        let (peer, local) = row7_pair().await;
        let (initial, _) = row7_frame(&peer, 2, &row7_payload(1, 0, b"old history")).await;
        local.process_message(&initial, None).await.unwrap();
        local.mailbox_client.take_deposited();
        local.enqueue_timer_change(1, Some(30)).await.unwrap();
        let frame = local.storage.outgoing_frames().unwrap().pop().unwrap();
        assert!(local.mailbox_client.take_deposited().is_empty());
        assert!(local
            .enqueue_message(1, MessageContent::Text("too early".into()))
            .await
            .is_err());
        assert!(local.enqueue_timer_change(1, None).await.is_err());
        let restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            local.storage,
            MockMailbox::new(),
        );
        assert!(restarted.storage.timer_change_pending(1).unwrap());
        restarted.retry_outgoing().await.unwrap();
        let updates = restarted.mailbox_client.take_deposited();
        assert_eq!(updates.len(), 1);
        assert_eq!(unwrap_wire(&updates[0].1), frame.wire);
        assert!(
            restarted.storage.timer_change_pending(1).unwrap(),
            "deposit success is not peer acknowledgement"
        );
        peer.process_message(&unwrap_wire(&updates[0].1), None)
            .await
            .unwrap();
        assert_eq!(
            peer.storage.get_conversation_timer(1).await.unwrap(),
            Some(30)
        );
        let acks = peer.mailbox_client.take_deposited();
        assert!(!acks.is_empty());
        for (_, blob) in acks {
            let wire = envelope_decrypt(&ESA, &DCA, &blob).unwrap();
            restarted.process_message(&wire, None).await.unwrap();
        }
        assert!(!restarted.storage.timer_change_pending(1).unwrap());
        let message = restarted
            .enqueue_message(1, MessageContent::Text("timed content".into()))
            .await
            .unwrap();
        let stored = restarted.storage.get_message(message.id).unwrap().unwrap();
        assert_eq!(stored.disappear_timer, Some(30));
        assert_ne!(stored.content, b"timed content");
        assert!(
            matches!(crate::disappearing::open_sealed_content(restarted.volatile_cache(), &stored.msg_id, &stored.content).unwrap(), crate::disappearing::Opened::Plaintext(p) if p == b"timed content")
        );
        let old = restarted.storage.get_message(1).unwrap().unwrap();
        assert_eq!(old.disappear_timer, None);
        assert_eq!(old.content, b"old history");
    }

    #[tokio::test]
    async fn row8_outbox_enqueue_does_not_wait_for_network_and_survives_restart() {
        let mut svc = ready().await;
        // A running schedule with no grants makes any attempted deposit wait.
        svc.set_slot_source(Arc::new(crate::cover::SlotSource::new(
            Arc::new(crate::cover::PendingQueues::new()),
            Arc::new(true.into()),
        )));
        let queued = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            svc.enqueue_message(1, MessageContent::Text("queued while network busy".into())),
        )
        .await
        .expect("local queueing cannot wait for a cover slot")
        .unwrap();
        assert!(svc.mailbox_client.take_deposited().is_empty());
        let frame = svc.storage.outgoing_frames().unwrap().pop().unwrap();
        assert_eq!(frame.message_id, Some(queued.id));
        assert_eq!(
            svc.storage.get_message(queued.id).unwrap().unwrap().status,
            najwa_storage::types::MessageStatus::Pending
        );
        let restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            svc.storage,
            MockMailbox::new(),
        );
        restarted.retry_outgoing().await.unwrap();
        let deposited = restarted.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 1);
        assert_eq!(unwrap_wire(&deposited[0].1), frame.wire);
        assert_eq!(
            restarted
                .storage
                .get_message(queued.id)
                .unwrap()
                .unwrap()
                .status,
            najwa_storage::types::MessageStatus::Sent
        );
        assert!(restarted.storage.outgoing_frames().unwrap().is_empty());
    }

    #[tokio::test]
    async fn row8_outbox_enqueue_requires_existing_session_without_prekey_fetch() {
        // No bundle is available. Queueing must fail before attempting bootstrap,
        // leave the sending chain untouched and create no outgoing row.
        let svc = service_ready_to_send();
        assert!(matches!(
            svc.enqueue_message(1, MessageContent::Text("pending contact".into()))
                .await,
            Err(MessagingError::NoMatchingSession)
        ));
        assert!(svc.storage.get_ratchet_state(1).await.unwrap().is_none());
        assert!(svc.storage.outgoing_frames().await.unwrap().is_empty());
        assert!(svc.mailbox_client.take_deposited().is_empty());
    }
    fn repaired_item() -> najwa_protocol::message::gap_repair::RepairedItem {
        let content = b"message that should disappear".to_vec();
        let mut preimage = vec![1];
        preimage.extend_from_slice(&content);
        let hash = najwa_crypto::hash::sha256(&preimage);
        najwa_protocol::message::gap_repair::RepairedItem {
            original_dh_pub: [199; 32],
            original_n: 3,
            original_msg_id: najwa_protocol::message::id::generate_msg_id(
                &[199; 32],
                3,
                &hash,
                &BOB_PSEUDO,
            ),
            original_timestamp: najwa_crypto::time::now(),
            original_logical_seq: 3,
            original_content_type: 1,
            original_flags: 1,
            original_content: content,
        }
    }

    #[tokio::test]
    async fn row8_concurrent_user_and_control_sends_use_distinct_keys_and_nonces() {
        let receiver = ready().await;
        let store = Row8SqlStore::new(receiver.storage);
        store.pause.store(true, SeqCst);
        let svc = Arc::new(MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            store,
            MockMailbox::new(),
        ));
        let a = svc.clone();
        let first =
            tokio::spawn(
                async move { a.send_message(1, MessageContent::Text("one".into())).await },
            );
        svc.storage.entered.notified().await;
        let b = svc.clone();
        let second = tokio::spawn(async move {
            b.send_control_message(1, &ControlMessage::TypingIndicator)
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(
            svc.storage.reads.load(SeqCst),
            1,
            "second send must not read a stale chain snapshot"
        );
        svc.storage.release.notify_one();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        let deposited = svc.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 2);
        let frames: Vec<_> = deposited
            .iter()
            .map(|(_, b)| WireMessage::from_bytes(&unwrap_wire(b)).unwrap())
            .collect();
        let MessageHeader::Ratchet(a) = &frames[0].header;
        let MessageHeader::Ratchet(b) = &frames[1].header;
        assert_ne!((a.dh_pub.to_bytes(), a.n), (b.dh_pub.to_bytes(), b.n));
        assert_ne!(
            &frames[0].encrypted_payload[..24],
            &frames[1].encrypted_payload[..24]
        );
    }

    #[tokio::test]
    async fn row8_rejected_first_send_leaves_no_session_and_next_send_is_initial() {
        let svc = service_ready_to_send();
        assert!(svc
            .send_message(1, MessageContent::Text("x".repeat(2_000_000)))
            .await
            .is_err());
        assert!(svc.storage.get_ratchet_state(1).await.unwrap().is_none());
        assert!(svc.storage.get_session_ad(1).await.unwrap().is_none());
        svc.send_message(1, MessageContent::Text("first valid".into()))
            .await
            .unwrap();
        let caps = svc.storage.get_contact_capabilities(1).await.unwrap();
        let wire = envelope_decrypt(
            &caps[0].their_envelope_secret.unwrap(),
            &caps[0].their_deposit_capability.unwrap(),
            &svc.mailbox_client.last_deposit(),
        )
        .unwrap();
        assert_eq!(
            WireMessage::from_bytes(&wire).unwrap().message_type,
            MessageType::Initial
        );
    }

    #[tokio::test]
    async fn row8_repaired_disappearing_content_is_sealed_and_expires() {
        let (sender, receiver) = row7_pair().await;
        CoreStorage::set_conversation_timer(&receiver.storage, 1, Some(30))
            .await
            .unwrap();
        let item = repaired_item();
        let body = ControlMessage::GapRepairBundle {
            items: vec![item.clone(), item.clone()],
        }
        .to_bytes();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &body)).await;
        receiver.process_message(&raw, None).await.unwrap();
        let msg = receiver
            .storage
            .get_message_by_msg_id(&item.original_msg_id)
            .unwrap()
            .unwrap();
        assert_ne!(msg.content, item.original_content);
        assert_eq!(msg.disappear_timer, Some(30));
        assert!(msg.disappear_at.is_some());
        assert!(
            matches!(crate::disappearing::open_sealed_content(receiver.volatile_cache(),&msg.msg_id,&msg.content).unwrap(),crate::disappearing::Opened::Plaintext(p) if p==item.original_content)
        );
        receiver.volatile_cache().remove_key(&msg.msg_id);
        assert!(matches!(
            crate::disappearing::open_sealed_content(
                receiver.volatile_cache(),
                &msg.msg_id,
                &msg.content
            )
            .unwrap(),
            crate::disappearing::Opened::Expired
        ));
    }

    #[tokio::test]
    async fn row8_quarantine_failure_leaves_mailbox_copy_unacknowledged() {
        let (_, receiver) = row7_pair().await;
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            Row8SqlStore::new(receiver.storage),
            MockMailbox::new(),
        );
        svc.storage.fail_quarantine.store(true, SeqCst);
        assert!(matches!(
            svc.try_quarantine(b"frame").await,
            Err(MessagingError::StorageError(_))
        ));
        assert!(svc.epoch_quarantine.lock().unwrap().is_empty());
        assert!(svc
            .storage
            .inner
            .load_quarantined_frames()
            .unwrap()
            .is_empty());
        // An authenticated envelope with no matching session must not be ACKed
        // when the device cannot durably retain its inner frame.
        let alien = service_ready_to_send();
        alien
            .send_message(1, MessageContent::Text("alien".into()))
            .await
            .unwrap();
        let caps = alien.storage.get_contact_capabilities(1).await.unwrap();
        let mut wire = WireMessage::from_bytes(
            &envelope_decrypt(
                &caps[0].their_envelope_secret.unwrap(),
                &caps[0].their_deposit_capability.unwrap(),
                &alien.mailbox_client.last_deposit(),
            )
            .unwrap(),
        )
        .unwrap();
        wire.message_type = MessageType::Normal;
        wire.x3dh_header = None;
        let wrapped =
            najwa_protocol::message::envelope::envelope_encrypt(&ESA, &DCA, &wire.to_bytes())
                .unwrap();
        svc.mailbox_client.inject_fetched(vec![MailboxMessage {
            id: "uncommitted".into(),
            size: wrapped.len() as u32,
            blob: wrapped,
            deposited_at: 1,
            cap_hint: None,
        }]);
        svc.poll_messages().await.unwrap();
        assert!(svc.mailbox_client.acked_ids().is_empty());
    }

    #[tokio::test]
    async fn row8_quarantine_survives_transient_storage_error_and_recovers() {
        let (sender, receiver) = row7_pair().await;
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            Row8SqlStore::new(receiver.storage),
            MockMailbox::new(),
        );
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"recover me")).await;
        assert!(svc.try_quarantine(&raw).await.unwrap());
        assert!(svc.try_quarantine(&raw).await.unwrap());
        assert_eq!(svc.epoch_quarantine.lock().unwrap().len(), 1);
        svc.storage.fail_seen.store(true, SeqCst);
        assert!(svc.retry_quarantine().await.is_empty());
        assert_eq!(
            svc.storage.inner.load_quarantined_frames().unwrap().len(),
            1
        );
        assert_eq!(svc.epoch_quarantine.lock().unwrap().len(), 1);
        svc.storage.fail_seen.store(false, SeqCst);
        assert_eq!(svc.retry_quarantine().await.len(), 1);
        assert!(svc
            .storage
            .inner
            .load_quarantined_frames()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn row8_background_queue_errors_do_not_hide_a_committed_receive() {
        let (sender, receiver) = row7_pair().await;
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            Row8SqlStore::new(receiver.storage),
            MockMailbox::new(),
        );
        svc.storage.fail_maintenance.store(true, SeqCst);
        let (raw, header) =
            row7_frame(&sender, 2, &row7_payload(1, 0, b"visible after commit")).await;
        let blob = najwa_protocol::message::envelope::envelope_encrypt(&ESA, &DCA, &raw).unwrap();
        svc.mailbox_client.inject_fetched(vec![MailboxMessage {
            id: "committed".into(),
            size: blob.len() as u32,
            blob,
            deposited_at: 1,
            cap_hint: None,
        }]);
        let received = svc.poll_messages().await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].content, b"visible after commit");
        assert!(svc.storage.inner.check_msg_id_seen(&header).unwrap());
        assert_eq!(svc.mailbox_client.acked_ids(), vec!["committed"]);
    }

    #[tokio::test]
    async fn row8_failed_control_commit_is_retryable_without_ack_or_effects() {
        let (sender, receiver) = row7_pair().await;
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            Row8SqlStore::new(receiver.storage),
            MockMailbox::new(),
        );
        let item = repaired_item();
        let body = ControlMessage::GapRepairBundle {
            items: vec![item.clone()],
        }
        .to_bytes();
        let (raw, header) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &body)).await;
        svc.storage.fail_incoming.store(true, SeqCst);
        assert!(matches!(
            svc.process_message(&raw, None).await,
            Err(MessagingError::StorageError(_))
        ));
        assert!(!svc.storage.inner.check_msg_id_seen(&header).unwrap());
        assert!(svc
            .storage
            .inner
            .get_message_by_msg_id(&item.original_msg_id)
            .unwrap()
            .is_none());
        assert!(svc.mailbox_client.take_deposited().is_empty());
        svc.storage.fail_incoming.store(false, SeqCst);
        svc.process_message(&raw, None).await.unwrap();
        assert!(svc
            .storage
            .inner
            .get_message_by_msg_id(&item.original_msg_id)
            .unwrap()
            .is_some());
    }

    async fn pending_send() -> MessagingService<najwa_storage::database::SqliteStorage, MockMailbox>
    {
        let mut svc = ready().await;
        let slots = Arc::new(crate::cover::SlotSource::new(
            Arc::new(crate::cover::PendingQueues::new()),
            Arc::new(true.into()),
        ));
        svc.set_slot_source(slots);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            svc.send_message(1, MessageContent::Text("survive crash".into()))
        )
        .await
        .is_err());
        assert_eq!(svc.storage.outgoing_frames().unwrap().len(), 1);
        svc
    }
    #[tokio::test]
    async fn new_messages_deposit_while_an_older_attempt_is_stalled() {
        let service = ready().await;
        let service = Arc::new(MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            service.storage,
            Row8Mailbox::new(),
        ));
        let first = service
            .enqueue_message(1, MessageContent::Text("older blocked attempt".into()))
            .await
            .unwrap();
        let original_wire = service.storage.outgoing_frames().unwrap()[0].wire.clone();
        service.mailbox_client.pause_deposit.store(true, SeqCst);
        let worker = service.clone();
        let delivery = tokio::spawn(async move { worker.drive_outgoing().await });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            service.mailbox_client.deposit_entered.notified(),
        )
        .await
        .expect("the first network request must be in flight");

        let second = service
            .enqueue_message(1, MessageContent::Text("newly queued text".into()))
            .await
            .unwrap();
        let deposited = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if service.storage.get_message(second.id).unwrap().unwrap().status
                    == najwa_storage::types::MessageStatus::Sent
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        delivery.abort();
        let _ = delivery.await;
        assert!(deposited, "an older network attempt starved newly queued text");
        assert_eq!(service.storage.outgoing_frames().unwrap().len(), 1);
        assert_eq!(service.storage.outgoing_frames().unwrap()[0].wire, original_wire);
        assert_eq!(
            service.storage.get_message(first.id).unwrap().unwrap().status,
            najwa_storage::types::MessageStatus::Pending
        );
        // Cancelling a delivery pass releases its frame claim without advancing
        // the ratchet again or losing the exact bytes needed for a retry.
        service.drive_outgoing().await.unwrap();
        let deposits = service.mailbox_client.inner.take_deposited();
        assert_eq!(deposits.len(), 2);
        assert_eq!(unwrap_wire(&deposits[1].1), original_wire);
        assert!(service.storage.outgoing_frames().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bulk_retries_reserve_transport_capacity_for_foreground_chat() {
        let existing = ready().await;
        let service = Arc::new(MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]), existing.storage, Row8Mailbox::new(),
        ));
        for index in 0..12 {
            let bytes = najwa_protocol::message::file_transfer::FileChunkWire {
                session_id: [19; 16], index, data: vec![7; 65536],
            }.to_bytes();
            service.enqueue_message(1, MessageContent::Raw {
                content_type: 0x11, bytes, reply_to: None,
            }).await.unwrap();
        }
        service.mailbox_client.pause_bulk.store(true, SeqCst);
        let worker=service.clone();
        let driver=tokio::spawn(async move {worker.drive_outgoing().await});
        tokio::time::timeout(std::time::Duration::from_secs(2),async {
            while service.mailbox_client.bulk_entered.load(SeqCst)<4 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        let worker=service.clone();
        let poll_retry=tokio::spawn(async move {worker.retry_outgoing().await});
        let chat=tokio::time::timeout(std::time::Duration::from_millis(500),
            service.send_message(1,MessageContent::Text("chat during bulk transfer".into()))).await;
        let entered=service.mailbox_client.bulk_entered.load(SeqCst);
        driver.abort();poll_retry.abort();let _=driver.await;let _=poll_retry.await;
        assert!(chat.is_ok(),"background file requests monopolized the transport pool");
        assert!(chat.unwrap().is_ok());
        assert_eq!(entered,4,"send and poll retries must share one background budget");
        assert_eq!(service.storage.outgoing_frames().unwrap().len(),12);
        service.mailbox_client.pause_bulk.store(false,SeqCst);
        for _ in 0..4 {service.retry_outgoing().await.unwrap();}
        assert!(service.storage.outgoing_frames().unwrap().is_empty(),"cancellation lost retry capacity or durable frames");
    }

    #[tokio::test]
    async fn row8_restart_recovers_pending_wire_and_uses_retry_blob_column() {
        let svc = pending_send().await;
        let frame = svc.storage.outgoing_frames().unwrap().pop().unwrap();
        let mid = frame.message_id.unwrap();
        let msg = svc.storage.get_message(mid).unwrap().unwrap();
        assert_eq!(msg.status, najwa_storage::types::MessageStatus::Pending);
        assert_eq!(
            CoreStorage::get_message_blob(&svc.storage, mid)
                .await
                .unwrap(),
            Some(frame.wire.clone())
        );
        assert!(msg.encrypted_blob.is_none());
        let restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            svc.storage,
            MockMailbox::new(),
        );
        restarted.retry_outgoing().await.unwrap();
        assert_eq!(
            unwrap_wire(&restarted.mailbox_client.last_deposit()),
            frame.wire
        );
        assert!(restarted.storage.outgoing_frames().unwrap().is_empty());
        let msg = restarted.storage.get_message(mid).unwrap().unwrap();
        assert_eq!(msg.status, najwa_storage::types::MessageStatus::Sent);
        assert!(msg.retry_wire_blob.is_none());
    }
    #[tokio::test]
    async fn row8_retry_waits_for_cover_and_honors_blocking_during_wait() {
        let svc = pending_send().await;
        let queues = Arc::new(crate::cover::PendingQueues::new());
        let slots = Arc::new(crate::cover::SlotSource::new(
            queues.clone(),
            Arc::new(true.into()),
        ));
        let mut restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            svc.storage,
            MockMailbox::new(),
        );
        restarted.set_slot_source(slots.clone());
        let restarted = Arc::new(restarted);
        let worker = restarted.clone();
        let retry = tokio::spawn(async move { worker.retry_outgoing().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!queues.is_empty());
        assert!(restarted.mailbox_client.take_deposited().is_empty());
        restarted.block_contact(1).await.unwrap();
        slots.set_bypass(true);
        queues.wake_all();
        tokio::time::timeout(std::time::Duration::from_secs(2), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(restarted.mailbox_client.take_deposited().is_empty());
    }

    #[tokio::test]
    async fn row8_retry_does_not_deposit_a_message_that_expires_during_cover_wait() {
        let svc = pending_send().await;
        let mid = svc.storage.outgoing_frames().unwrap()[0]
            .message_id
            .unwrap();
        let queues = Arc::new(crate::cover::PendingQueues::new());
        let mut restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            svc.storage,
            MockMailbox::new(),
        );
        restarted.set_slot_source(Arc::new(crate::cover::SlotSource::new(
            queues.clone(),
            Arc::new(true.into()),
        )));
        let restarted = Arc::new(restarted);
        let worker = restarted.clone();
        let retry = tokio::spawn(async move { worker.retry_outgoing().await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!queues.is_empty());
        CoreStorage::set_message_disappearing(&restarted.storage, mid, 30, 1)
            .await
            .unwrap();
        queues.wake_all();
        retry.await.unwrap().unwrap();
        assert!(restarted.mailbox_client.take_deposited().is_empty());
    }
    #[tokio::test]
    async fn row8_failed_retry_preserves_work_beyond_five_attempts() {
        let svc = pending_send().await;
        let frame = svc.storage.outgoing_frames().unwrap().pop().unwrap();
        // Simulate four failed attempts, then retry a high-position frame.
        for _ in 0..4 {
            svc.storage.finish_outgoing(frame.id, false, 0).unwrap();
        }
        let mailbox = Row8Mailbox::new();
        mailbox.deposit_status.store(503, SeqCst);
        let restarted =
            MessagingService::new(Ed25519KeyPair::from_seed(&[171; 32]), svc.storage, mailbox);
        restarted.retry_outgoing().await.unwrap();
        let retained = restarted.storage.outgoing_frames().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].wire, frame.wire);
        let current = najwa_crypto::time::now();
        assert!(retained[0].next_attempt <= current + 80);
        let msg = restarted
            .storage
            .get_message(frame.message_id.unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(msg.retry_count, 5);
        assert_eq!(msg.status, najwa_storage::types::MessageStatus::Failed);
    }
    #[tokio::test]
    async fn row8_control_retry_is_identical_until_authenticated_ack() {
        let (sender, receiver) = row7_pair().await;
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"establish")).await;
        receiver.process_message(&raw, None).await.unwrap();
        receiver.mailbox_client.take_deposited();
        receiver
            .send_control_message(1, &ControlMessage::TypingIndicator)
            .await
            .unwrap();
        let frame = receiver.storage.outgoing_frames().unwrap().pop().unwrap();
        assert!(frame.requires_ack);
        assert_eq!(
            unwrap_wire(&receiver.mailbox_client.last_deposit()),
            frame.wire
        );
        receiver.storage.finish_outgoing(frame.id, true, 0).unwrap();
        receiver.retry_outgoing().await.unwrap();
        assert_eq!(
            unwrap_wire(&receiver.mailbox_client.last_deposit()),
            frame.wire
        );
        let ack = najwa_protocol::message::ack::CumulativeAck {
            ranges: vec![najwa_protocol::message::ack::AckRange {
                sender_dh_pub: frame.dh_pub,
                start_n: frame.n,
                end_n: frame.n,
            }],
        };
        let body = najwa_protocol::message::ack::to_padded_plaintext(&ack.to_bytes().unwrap(), 96)
            .unwrap();
        let (raw, _) = row7_frame(&sender, 0x12, &body).await;
        receiver.process_message(&raw, None).await.unwrap();
        assert!(receiver.storage.outgoing_frames().unwrap().is_empty());
    }
    #[tokio::test]
    async fn row8_duplicate_control_replays_ack_without_reapplying_effect() {
        let (sender, receiver) = row7_pair().await;
        let body = ControlMessage::DisappearTimer {
            duration_secs: 30,
            set_at: 1,
        }
        .to_bytes();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &body)).await;
        receiver.process_message(&raw, None).await.unwrap();
        receiver.mailbox_client.take_deposited();
        CoreStorage::set_conversation_timer_setting(&receiver.storage, 1, Some(60), 2, &[5; 32])
            .await
            .unwrap();
        receiver.process_message(&raw, None).await.unwrap();
        assert_eq!(
            CoreStorage::get_conversation_timer(&receiver.storage, 1)
                .await
                .unwrap(),
            Some(60)
        );
        assert_eq!(receiver.mailbox_client.take_deposited().len(), 1);
    }
    #[tokio::test]
    async fn row8_all_remote_targets_keep_their_own_coordinates() {
        let (_, receiver) = row7_pair().await;
        let entries: Vec<_> = (*b"abc")
            .into_iter()
            .map(|b| najwa_protocol::contact::mailbox_key::MailboxEntry {
                onion_address: [b; 56],
                deposit_capability: [b; 32],
                envelope_secret: [b + 1; 32],
                mailbox_ik_pub: [b + 2; 32],
                cert_signature: [b + 3; 64],
                capability_type: 2,
            })
            .collect();
        CoreStorage::update_remote_mailboxes(&receiver.storage, 1, &entries)
            .await
            .unwrap();
        let caps = CoreStorage::get_contact_capabilities(&receiver.storage, 1)
            .await
            .unwrap();
        assert_eq!(caps.len(), 3);
        for (cap, e) in caps.iter().zip(entries.iter()) {
            assert_eq!(
                cap.mailbox_onion,
                String::from_utf8(e.onion_address.to_vec()).unwrap()
            );
            assert_eq!(cap.their_deposit_capability, Some(e.deposit_capability));
            assert_eq!(cap.their_envelope_secret, Some(e.envelope_secret));
        }
        assert_eq!(
            caps[1].mailbox_id, 0,
            "remote-only onion must not borrow local mailbox health identity"
        );
    }
    #[tokio::test]
    async fn row8_inbound_limit_defers_the_51st_frame_without_consuming_state() {
        let (sender, receiver) = row7_pair().await;
        for i in 0u8..51 {
            let mut body = row7_payload(1, 0, format!("message {i}").as_bytes());
            body[42..58].fill(i);
            let (raw, header) = row7_frame(&sender, 2, &body).await;
            let result = receiver.process_message(&raw, None).await;
            if i < 50 {
                assert!(result.unwrap().is_some());
            } else {
                assert!(matches!(
                    result,
                    Err(MessagingError::RateLimitExceeded { .. })
                ));
                assert!(!receiver.storage.check_msg_id_seen(&header).unwrap());
                receiver.inbound_limiter.clear(1);
                assert!(receiver
                    .process_message(&raw, None)
                    .await
                    .unwrap()
                    .is_some());
            }
        }
    }
    #[tokio::test]
    async fn row8_temporary_deposit_failures_recover_without_manual_retry() {
        let receiver = ready().await;
        let mailbox = Row8Mailbox::new();
        mailbox.deposit_status.store(503, SeqCst);
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            receiver.storage,
            mailbox,
        );
        for index in 0..6 {
            svc.send_message(
                1,
                MessageContent::Text(format!("queued during outage {index}")),
            )
            .await
            .unwrap();
        }
        assert!(svc.storage.remote_mailbox_enabled(&"a".repeat(56)).unwrap());
        assert!(!CoreStorage::get_contact_capabilities(&svc.storage, 1)
            .await
            .unwrap()
            .is_empty());
        assert!(svc.storage.get_mailbox(1).unwrap().unwrap().enabled);
        let frames = svc.storage.outgoing_frames().unwrap();
        assert_eq!(frames.len(), 6);
        // Restart with the same durable store after the operator recovers.
        // No recipient process or explicit mailbox retry is involved.
        let restarted = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            svc.storage,
            MockMailbox::new(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !restarted.storage.outgoing_frames().unwrap().is_empty() {
                restarted.retry_outgoing().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        let deposited = restarted.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), frames.len());
        for frame in frames {
            assert!(deposited
                .iter()
                .any(|(_, blob)| unwrap_wire(blob) == frame.wire));
            assert_eq!(
                restarted
                    .storage
                    .get_message(frame.message_id.unwrap())
                    .unwrap()
                    .unwrap()
                    .status,
                najwa_storage::types::MessageStatus::Sent
            );
        }
        assert!(restarted.storage.retrying_mailboxes().unwrap().is_empty());
    }
    #[tokio::test]
    async fn row8_fetch_health_ignores_capability_errors_and_backs_off_on_server_errors() {
        let receiver = ready().await;
        let mailbox = Row8Mailbox::new();
        mailbox.fetch_status.store(410, SeqCst);
        let svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            receiver.storage,
            mailbox,
        );
        for _ in 0..6 {
            svc.poll_messages().await.unwrap();
        }
        assert_eq!(
            CoreStorage::get_mailbox_health(&svc.storage, 1)
                .await
                .unwrap()
                .unwrap()
                .consecutive_failures,
            0
        );
        svc.mailbox_client.fetch_status.store(503, SeqCst);
        let before = svc.mailbox_client.fetch_calls.load(SeqCst);
        for _ in 0..5 {
            svc.poll_messages().await.unwrap();
        }
        assert!(svc.storage.get_mailbox(1).unwrap().unwrap().enabled);
        assert_eq!(
            svc.mailbox_client.fetch_calls.load(SeqCst),
            before + 1,
            "cooldown must suppress repeated fetches to every queue on the same operator"
        );
        svc.mailbox_client.fetch_status.store(0, SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while svc.storage.get_mailbox(1).unwrap().unwrap().failure_count > 0 {
                svc.poll_messages().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert!(svc.storage.get_mailbox(1).unwrap().unwrap().enabled);
    }

    #[tokio::test]
    async fn row8_resend_request_reencrypts_history_preserving_logical_identity() {
        let (sender, receiver) = row7_pair().await;
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"establish")).await;
        receiver.process_message(&raw, None).await.unwrap();
        receiver
            .send_message(1, MessageContent::Text("history one".into()))
            .await
            .unwrap();
        receiver
            .send_message_with_flags(1, MessageContent::Text("history two".into()), 4)
            .await
            .unwrap();
        let original = receiver
            .storage
            .outbound_history(1, Some([0; 16]), 0, u64::MAX, 0)
            .unwrap();
        assert_eq!(original.len(), 2);
        // Sender-side UI can already show delivered while a peer asks for its
        // history again (e.g. after restoring an older local backup).
        receiver
            .storage
            .update_message_status(
                original[0].message.id,
                najwa_storage::types::MessageStatus::Delivered,
            )
            .unwrap();
        receiver.mailbox_client.take_deposited();
        let mut body = vec![0; 16];
        body.extend_from_slice(&0u64.to_be_bytes());
        let control = ControlMessage::ReSendRequest { mode: 1, body }.to_bytes();
        let mut payload = row7_payload(0x20, 0, &control);
        payload[42..58].fill(192);
        let (request, _) = row7_frame(&sender, 2, &payload).await;
        receiver.process_message(&request, None).await.unwrap();
        let deposits = receiver.mailbox_client.take_deposited();
        assert_eq!(deposits.len(), 3, "two history frames and the request ACK");
        let mut state = sender.storage.get_ratchet_state(1).await.unwrap().unwrap();
        let mut payloads = Vec::new();
        for (_, blob) in deposits {
            let wire = WireMessage::from_bytes(&unwrap_wire(&blob)).unwrap();
            if wire.message_type != MessageType::Normal {
                continue;
            }
            let MessageHeader::Ratchet(header) = &wire.header;
            let plain = najwa_protocol::ratchet::decrypt::ratchet_decrypt(
                &mut state,
                header,
                &wire.encrypted_payload,
                b"row7 AD",
                &wire.wire_prefix().unwrap(),
            )
            .unwrap();
            payloads.push(najwa_protocol::message::Payload::from_bytes(&plain).unwrap());
        }
        assert_eq!(payloads.len(), 2);
        for (p, h) in payloads.iter().zip(original.iter()) {
            assert_eq!(p.timestamp, h.message.timestamp as u64);
            assert_eq!(p.logical_seq, h.logical_seq);
            assert_eq!(p.flags, h.message.flags as u8);
            assert_eq!(p.content, h.message.content);
            assert_ne!(p.msg_id, h.message.msg_id);
            assert_eq!(
                najwa_protocol::message::id::generate_logical_msg_id(
                    &receiver.identity_key.public().to_bytes(),
                    &sender.identity_key.public().to_bytes(),
                    p.timestamp,
                    p.logical_seq,
                    p.content_type as u8,
                    &p.content
                ),
                h.logical_msg_id
            );
        }
        assert_eq!(
            receiver
                .storage
                .outbound_history(1, Some([0; 16]), 0, u64::MAX, 0)
                .unwrap()
                .len(),
            2,
            "replaying does not duplicate local history"
        );
        assert!(receiver.storage.inbound_work().unwrap().is_empty());
    }

    /// S08 §6.5: a responder answers one GapRepairRequest per contact per
    /// GAP_REPAIR_MIN_INTERVAL_SECS; a further request costs no re-encryption.
    #[tokio::test]
    async fn row8_gap_repair_requests_beyond_the_contact_bound_are_not_answered() {
        use najwa_protocol::message::gap_repair::{EpochGap, GapRange};
        let (sender, receiver) = row7_pair().await;
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"establish")).await;
        receiver.process_message(&raw, None).await.unwrap();
        let state = CoreStorage::get_ratchet_state(&receiver.storage, 1)
            .await
            .unwrap()
            .unwrap();
        let (dh_pub, n) = (state.dhs.public().to_bytes(), state.ns);
        receiver
            .send_message(1, MessageContent::Text("lost in transit".into()))
            .await
            .unwrap();
        receiver.mailbox_client.take_deposited();
        let request = ControlMessage::GapRepairRequest {
            epochs: vec![EpochGap {
                dh_pub,
                ranges: vec![GapRange { start_n: n, end_n: n }],
            }],
        }
        .to_bytes();
        let mut answers = Vec::new();
        for msg_id in [192, 193] {
            let mut payload = row7_payload(0x20, 0, &request);
            payload[42..58].fill(msg_id);
            let (frame, _) = row7_frame(&sender, 2, &payload).await;
            receiver.process_message(&frame, None).await.unwrap();
            answers.push(receiver.mailbox_client.take_deposited().len());
        }
        assert_eq!(answers, [2, 1], "a bundle and the ACK, then only the ACK");
        assert!(receiver.storage.inbound_work().unwrap().is_empty());
    }

    /// S08 §7.1: Delete seals a RevocationNotice that outlives the local
    /// delete, even for a blocked contact; the peer then wipes us too.
    #[tokio::test]
    async fn deleting_a_contact_revokes_the_conversation_on_the_peer_too() {
        use najwa_storage::prelude as sql;
        let (mock, local) = row7_pair().await;
        // The peer is the other side of row7_pair, also on SQLite.
        let db = sql::SqliteStorage::open_in_memory(&[179; 32]).unwrap();
        let local_ik = Ed25519KeyPair::from_seed(&[171; 32]).public().to_bytes();
        db.create_contact(&sql::NewContact {
            pseudonym: ALICE_PSEUDO,
            their_ik_pub: local_ik,
            their_device_pub: local_ik,
            our_pseudonym: BOB_PSEUDO,
            display_name: None,
        })
        .unwrap();
        let mailbox = db
            .save_mailbox(&sql::NewMailbox {
                onion_address: "b".repeat(56),
                fetch_capability: vec![78; 32],
                deposit_capability: DCB.to_vec(),
                envelope_secret: ESB.to_vec(),
                cover_deposit_capability: None,
                cover_fetch_capability: None,
                cover_envelope_secret: None,
                priority: 1,
                created_at: 1,
            })
            .unwrap();
        db.save_contact_capability(&sql::NewContactMailboxCap {
            contact_id: 1,
            mailbox_id: mailbox,
            deposit_capability: DCB.to_vec(),
            fetch_capability: Some(vec![78; 32]),
            their_deposit_capability: Some(DCA.to_vec()),
            their_envelope_secret: Some(ESA.to_vec()),
            envelope_secret: Some(ESB.to_vec()),
            capability_type: 2,
            expires_at: None,
            registered_at: Some(1),
            created_at: 1,
        })
        .unwrap();
        let sending = mock.storage.get_ratchet_state(1).await.unwrap().unwrap();
        CoreStorage::save_ratchet_state(&db, 1, &sending).await.unwrap();
        CoreStorage::save_session_ad(&db, 1, b"row7 AD").await.unwrap();
        let peer = MessagingService::new(Ed25519KeyPair::from_seed(&[172; 32]), db, MockMailbox::new());

        let sent = peer.send_message(1, MessageContent::Text("history".into())).await.unwrap();
        for (_, blob) in peer.mailbox_client.take_deposited() {
            local.process_message(&envelope_decrypt(&ESA, &DCA, &blob).unwrap(), None).await.unwrap();
        }
        local.mailbox_client.take_deposited();
        assert!(peer.storage.get_message_by_msg_id(&sent.msg_id).unwrap().is_some());
        local.storage.set_contact_blocked(1, true).unwrap();

        local.manage_local_contact(1, "delete", "").await.unwrap();
        assert!(local.storage.get_contact(1).unwrap().is_none());
        assert!(local.storage.outgoing_frames().unwrap().is_empty());
        assert!(local.mailbox_client.take_deposited().is_empty(), "delete never waits for the network");
        assert_eq!(local.storage.revocation_frames().unwrap().len(), 1);

        // A restart keeps the notice; the next delivery pass deposits it once.
        let local = MessagingService::new(Ed25519KeyPair::from_seed(&[171; 32]), local.storage, MockMailbox::new());
        local.retry_outgoing().await.unwrap();
        let deposited = local.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 1);
        assert!(local.storage.revocation_frames().unwrap().is_empty());
        let wire = unwrap_wire(&deposited[0].1);
        peer.process_message(&wire, None).await.unwrap();
        assert!(peer.storage.get_contact(1).unwrap().is_none());
        assert!(peer.storage.get_message_by_msg_id(&sent.msg_id).unwrap().is_none());
        assert!(CoreStorage::get_ratchet_state(&peer.storage, 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_a_contact_without_a_session_sends_nothing() {
        let (_, local) = row7_pair().await;
        CoreStorage::delete_ratchet_state(&local.storage, 1).await.unwrap();
        local.manage_local_contact(1, "delete", "").await.unwrap();
        assert!(local.storage.get_contact(1).unwrap().is_none());
        assert!(local.storage.revocation_frames().unwrap().is_empty());
        local.retry_outgoing().await.unwrap();
        assert!(local.mailbox_client.take_deposited().is_empty());
    }
}
