mod row10 {
    use super::*;
    use crate::disappearing::{
        open_sealed_content, DisappearingCleanupTask, DisappearingMessageManager, Opened,
    };

    #[tokio::test]
    async fn row10_normal_and_repaired_deadlines_respect_receipt_opt_in() {
        use najwa_protocol::message::{control::ControlMessage, gap_repair::RepairedItem};
        for repaired in [false, true] {
            for flags in [1, 5] {
                let (sender, receiver) = row7_pair().await;
                receiver
                    .storage
                    .set_conversation_timer(1, Some(30))
                    .unwrap();
                let before = najwa_crypto::time::now_ms();
                let (kind, body) = if repaired {
                    let content = b"secret".to_vec();
                    let mut preimage = vec![1];
                    preimage.extend_from_slice(&content);
                    let item = RepairedItem {
                        original_dh_pub: [199; 32],
                        original_n: 3,
                        original_msg_id: najwa_protocol::message::id::generate_msg_id(
                            &[199; 32],
                            3,
                            &najwa_crypto::hash::sha256(&preimage),
                            &BOB_PSEUDO,
                        ),
                        original_timestamp: najwa_crypto::time::now(),
                        original_logical_seq: 3,
                        original_content_type: 1,
                        original_flags: flags,
                        original_content: content,
                    };
                    (
                        0x20,
                        ControlMessage::GapRepairBundle { items: vec![item] }.to_bytes(),
                    )
                } else {
                    (1, b"secret".to_vec())
                };
                let (raw, _) = row7_frame(&sender, 2, &row7_payload(kind, flags, &body)).await;
                receiver.process_message(&raw, None).await.unwrap();
                let m = receiver
                    .storage
                    .list_messages(1, 10, None)
                    .unwrap()
                    .remove(0);
                let lifetime = if flags == 1 { 30_000 } else { 604_830_000 };
                let deadline = m.disappear_at.unwrap();
                assert!(deadline >= before + lifetime);
                assert!(deadline <= najwa_crypto::time::now_ms() + lifetime);
                assert!(
                    matches!(open_sealed_content(receiver.volatile_cache(), &m.msg_id, &m.content).unwrap(), Opened::Plaintext(p) if p == b"secret")
                );
            }
        }
    }

    #[tokio::test]
    async fn row10_sqlite_cleanup_erases_memory_and_persisted_keys() {
        let (sender, receiver) = row7_pair().await;
        receiver
            .storage
            .set_conversation_timer(1, Some(30))
            .unwrap();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 1, b"secret")).await;
        receiver.process_message(&raw, None).await.unwrap();
        let m = receiver
            .storage
            .list_messages(1, 10, None)
            .unwrap()
            .remove(0);
        let cache = receiver.volatile_cache().clone();
        let db = Arc::new(receiver.storage);
        db.set_message_disappear_at(m.id, 1).unwrap();
        db.save_volatile_key(&m.msg_id, &cache.persist_all(&[178; 32])[0].1, None)
            .unwrap();
        DisappearingCleanupTask::with_default_interval(
            Arc::new(DisappearingMessageManager::new(db.clone())),
            cache.clone(),
        )
        .run_once()
        .await
        .unwrap();
        assert!(db.get_message(m.id).unwrap().is_none());
        assert!(db.get_all_volatile_keys().unwrap().is_empty());
        assert!(matches!(
            open_sealed_content(&cache, &m.msg_id, &m.content).unwrap(),
            Opened::Expired
        ));
    }

    #[tokio::test]
    async fn row10_read_does_not_revive_or_extend_deadlines() {
        let (sender, receiver) = row7_pair().await;
        receiver
            .storage
            .set_conversation_timer(1, Some(30))
            .unwrap();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 5, b"secret")).await;
        receiver.process_message(&raw, None).await.unwrap();
        let db = &receiver.storage;
        let m = db.list_messages(1, 10, None).unwrap().remove(0);
        let earlier = najwa_crypto::time::now_ms() as u64 + 10_000;
        db.set_message_disappear_at(m.id, earlier).unwrap();
        assert_eq!(db.mark_messages_read(1).unwrap(), 1);
        assert_eq!(
            db.get_message(m.id).unwrap().unwrap().disappear_at,
            Some(earlier as i64)
        );
        assert_eq!(db.mark_messages_read(1).unwrap(), 0);
        db.set_message_disappear_at(m.id, 1).unwrap();
        assert_eq!(db.mark_messages_read(1).unwrap(), 0);
        assert_eq!(db.get_message(m.id).unwrap().unwrap().disappear_at, Some(1));
        assert!(db.list_messages(1, 10, None).unwrap().is_empty());
        assert!(db
            .list_messages(1, 10, Some((i64::MAX, i64::MAX)))
            .unwrap()
            .is_empty());

        // A never-read row that already expired is not marked or rescheduled.
        let (sender, receiver) = row7_pair().await;
        receiver
            .storage
            .set_conversation_timer(1, Some(30))
            .unwrap();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 5, b"unread")).await;
        receiver.process_message(&raw, None).await.unwrap();
        let m = receiver
            .storage
            .list_messages(1, 10, None)
            .unwrap()
            .remove(0);
        receiver.storage.set_message_disappear_at(m.id, 1).unwrap();
        assert_eq!(receiver.storage.mark_messages_read(1).unwrap(), 0);
        let m = receiver.storage.get_message(m.id).unwrap().unwrap();
        assert_eq!(m.disappear_at, Some(1));
        assert!(m.read_at.is_none());
    }

    #[tokio::test]
    async fn row10_invalid_timers_are_rejected_at_local_boundaries() {
        let (_, receiver) = row7_pair().await;
        let db = Arc::new(receiver.storage);
        let manager = DisappearingMessageManager::new(db.clone());
        manager.set_timer(1, Some(30), 100, &[1; 32]).await.unwrap();
        for timer in 1..30 {
            assert!(manager
                .set_timer(1, Some(timer), 101, &[1; 32])
                .await
                .is_err());
            assert!(manager
                .handle_timer_change(1, timer, 101, &[2; 32])
                .await
                .is_err());
            assert!(db.set_conversation_timer(1, Some(timer)).is_err());
            assert_eq!(manager.get_timer(1).await.unwrap(), Some(30));
        }
        manager.set_timer(1, Some(0), 102, &[1; 32]).await.unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), None);
    }

    // S12 §2.2: a received set_at past the S07 §7.1 future bound is ignored.
    // Accepted, 2^64 − 1 won every merge and made `previous + 1` overflow, so
    // the local user could never change the timer again.
    #[tokio::test]
    async fn row10_far_future_remote_set_at_cannot_pin_the_timer() {
        use najwa_protocol::message::control::ControlMessage;
        let (sender, receiver) = row7_pair().await;
        let body = ControlMessage::DisappearTimer {
            duration_secs: 30,
            set_at: u64::MAX,
        }
        .to_bytes();
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(0x20, 0, &body)).await;
        receiver.process_message(&raw, None).await.unwrap();
        receiver.mailbox_client.take_deposited();
        receiver.enqueue_timer_change(1, Some(60)).await.unwrap();
        let (secs, set_at, _) = receiver
            .storage
            .get_conversation_timer_setting(1)
            .unwrap()
            .unwrap();
        assert_eq!(secs, Some(60));
        assert!(set_at <= najwa_crypto::time::now());
        // The manager's receive path applies the same bound.
        let db = Arc::new(receiver.storage);
        let manager = DisappearingMessageManager::new(db.clone());
        manager
            .handle_timer_change(1, 300, u64::MAX, &[0; 32])
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), Some(60));
    }
}
