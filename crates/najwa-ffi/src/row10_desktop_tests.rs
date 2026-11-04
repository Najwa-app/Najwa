mod row10 {
    use super::*;
    use crate::state::AppState;
    use najwa_core::disappearing::{open_sealed_content, seal_content, Opened};

    fn setup() -> (tempfile::TempDir, AppState, Arc<SqliteStorage>, i64) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(dir.path().into()).unwrap();
        let db = crate::state::open_storage(dir.path(), &crate::state::test_key(23)).unwrap();
        let cid = db
            .create_contact(&najwa_storage::types::NewContact {
                pseudonym: [31; 32],
                their_ik_pub: [32; 32],
                their_device_pub: [32; 32],
                our_pseudonym: [33; 32],
                display_name: None,
            })
            .unwrap();
        state.db_key = Some(crate::state::test_key(23));
        state.identity = Some(najwa_identity::record::Identity {
            keypair: najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[24; 32]),
            created_at: 1,
            version: 1,
        });
        state.prepare_disappearing(&db, &[23; 32]).unwrap();
        state.storage = Some(db.clone());
        (dir, state, db, cid)
    }

    fn store(state: &AppState, db: &SqliteStorage, cid: i64, n: u8) -> (i64, Vec<u8>) {
        let sealed = seal_content(&state.disappearing_keys, &[n; 16], b"visible secret").unwrap();
        let id = state
            .runtime
            .block_on(najwa_core::storage::CoreStorage::save_message(
                db,
                &najwa_core::types::Message {
                    id: 0,
                    contact_id: cid as u64,
                    msg_id: [n; 16],
                    direction: najwa_core::types::Direction::Received,
                    content_type: 1,
                    flags: 5,
                    content: sealed.clone(),
                    timestamp: najwa_crypto::time::now(),
                    status: najwa_core::types::MessageStatus::Delivered,
                    ratchet_index: None,
                },
            ))
            .unwrap();
        db.set_message_disappear_pending(id, 30).unwrap();
        db.set_message_disappear_at(id, najwa_crypto::time::now_ms() as u64 + 604_830_000)
            .unwrap();
        (id, sealed)
    }

    #[test]
    fn desktop_prefetch_preserves_unread_state_and_timer_until_visible_ack() {
        let (_dir, mut state, db, cid) = setup();
        let (visible, _) = store(&state, &db, cid, 71);
        let (offscreen, _) = store(&state, &db, cid, 72);
        let before = db.get_message(visible).unwrap().unwrap();
        let prefetched =
            crate::disappearing::fetched_messages(&db, &state.disappearing_keys, cid).unwrap();
        assert_eq!(prefetched.len(), 2);
        assert!(prefetched.iter().all(|m| m.content == b"visible secret"));
        let after = db.get_message(visible).unwrap().unwrap();
        assert!(after.read_at.is_none());
        assert_eq!(after.disappear_at, before.disappear_at);

        db.mark_displayed_messages(cid, &[visible]).unwrap();
        let visible_row = db.get_message(visible).unwrap().unwrap();
        assert_eq!(visible_row.disappear_at, visible_row.read_at.map(|at| at + 30_000));
        assert!(db.get_message(offscreen).unwrap().unwrap().read_at.is_none());
        // Another background fetch must neither extend the started timer nor
        // mark the offscreen message as read.
        crate::disappearing::fetched_messages(&db, &state.disappearing_keys, cid).unwrap();
        assert_eq!(db.get_message(visible).unwrap().unwrap().disappear_at, visible_row.disappear_at);
        assert!(db.get_message(offscreen).unwrap().unwrap().read_at.is_none());
        state.clear_unlocked().unwrap();
    }

    #[test]
    fn row10_desktop_display_lock_and_offline_unlock_share_keys() {
        let _callbacks = crate::callback::tests::test_lock().lock().unwrap();
        let (_dir, mut state, db, cid) = setup();
        // Cancellation must finish without holding the global write lock.
        // try_read makes a regression fail deterministically instead of hang.
        struct Cancellation(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Cancellation {
            fn drop(&mut self) {
                self.0.store(
                    crate::state::state_cell().try_read().is_ok(),
                    Ordering::SeqCst,
                );
            }
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let previous = state.disappearing_cleanup.take().unwrap();
        previous.abort();
        let _ = state.runtime.block_on(previous);
        let guard = Cancellation(cancelled.clone());
        let (started, ready) = std::sync::mpsc::channel();
        state.disappearing_cleanup = Some(state.runtime.spawn(async move {
            let _guard = guard;
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        let (live, live_blob) = store(&state, &db, cid, 55);
        let (expired, expired_blob) = store(&state, &db, cid, 56);
        let client = Arc::new(HttpMailboxClient::new(Arc::new(Network {
            deposits: AtomicUsize::new(0),
        })));
        let handle = state.runtime.handle().clone();
        {
            let _entered = handle.enter();
            crate::install_connected_service(&mut state, client.clone()).unwrap();
        }
        {
            let service = state.service.lock().unwrap();
            assert!(matches!(
                open_sealed_content(
                    service.as_ref().unwrap().volatile_cache(),
                    &[55; 16],
                    &live_blob
                )
                .unwrap(),
                Opened::Plaintext(_)
            ));
        }
        *crate::state::state_cell().write().unwrap() = Some(state);
        crate::state::allow_operations();
        let contact = std::ffi::CString::new(cid.to_string()).unwrap();
        let ptr = crate::najwa_list_messages(contact.as_ptr());
        let json = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .unwrap()
            .to_owned();
        crate::najwa_free_string(ptr);
        let messages: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(messages.as_array().unwrap().len(), 2);
        assert!(messages
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["content"] == "visible secret"));
        let displayed = db.get_message(live).unwrap().unwrap();
        assert_eq!(
            displayed.disappear_at,
            displayed.read_at.map(|read| read + 30_000)
        );
        assert_eq!(crate::najwa_lock(), 0);
        assert!(cancelled.load(Ordering::SeqCst));
        assert_eq!(db.get_all_volatile_keys().unwrap().len(), 2);
        let mut state = crate::state::state_cell().write().unwrap().take().unwrap();
        assert!(state.disappearing_keys.is_empty());
        assert!(state.service.lock().unwrap().is_none());
        assert!(state.disappearing_cleanup.is_none());
        db.set_message_disappear_at(expired, 1).unwrap();
        // This is the unlock preparation called before storage is published or
        // a network service installed. It works with no connected service.
        state.prepare_disappearing(&db, &[23; 32]).unwrap();
        assert!(db.get_all_volatile_keys().unwrap().is_empty());
        assert!(db.get_message(expired).unwrap().is_none());
        assert!(matches!(
            open_sealed_content(&state.disappearing_keys, &[56; 16], &expired_blob).unwrap(),
            Opened::Expired
        ));
        let messages =
            crate::disappearing::displayed_messages(&db, &state.disappearing_keys, cid).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, b"visible secret");
        state.db_key = Some(crate::state::test_key(23));
        state.storage = Some(db.clone());
        state.clear_unlocked().unwrap();
        crate::state::allow_operations();
        crate::callback::unquiesce();
    }

    #[test]
    fn row10_desktop_periodic_cleanup_runs_without_transport() {
        let (_dir, mut state, db, cid) = setup();
        let (id, blob) = store(&state, &db, cid, 57);
        let initial = state.disappearing_cleanup.take().unwrap();
        initial.abort();
        let _ = state.runtime.block_on(initial);
        state.disappearing_cleanup = Some(crate::disappearing::start_cleanup(
            &state.runtime,
            &db,
            state.disappearing_keys.clone(),
            Duration::from_millis(10),
            crate::disappearing::RETENTION_INTERVAL,
        ));
        db.set_message_disappear_at(id, 1).unwrap();
        state.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while db.get_message(id).unwrap().is_some() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        });
        assert!(state.service.lock().unwrap().is_none());
        assert!(matches!(
            open_sealed_content(&state.disappearing_keys, &[57; 16], &blob).unwrap(),
            Opened::Expired
        ));
        state.clear_unlocked().unwrap();
    }

    #[test]
    fn retention_cleanup_runs_on_the_cleaner_only_while_unlocked() {
        let (_dir, mut state, db, cid) = setup();
        let initial = state.disappearing_cleanup.take().unwrap();
        initial.abort();
        let _ = state.runtime.block_on(initial);
        let expired_key = |n: u32| najwa_storage::types::SkippedKey {
            dh_pub: [41; 32],
            message_number: n,
            message_key: [42; 32],
            created_at: 1,
            expires_at: 2,
        };
        db.save_skipped_key(cid, &expired_key(1)).unwrap();
        db.save_pending_introduction(&najwa_storage::types::NewPendingIntroduction {
            introducer_contact_id: cid,
            introduced_ik_pub: [43; 32],
            introduced_display_name: "introduced".into(),
            introducer_ik_pub: [32; 32],
            payload_blob: vec![1],
            is_anonymous: false,
            created_at: 1,
            expires_at: 2,
        })
        .unwrap();
        db.mark_msg_id_seen(cid, &[44; 16]).unwrap();
        state.disappearing_cleanup = Some(crate::disappearing::start_cleanup(
            &state.runtime,
            &db,
            state.disappearing_keys.clone(),
            Duration::from_millis(10),
            Duration::from_millis(10),
        ));
        state.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while db.count_skipped_keys(cid).unwrap() != 0
                    || db.count_pending_introductions().unwrap() != 0
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("retention pass ran while unlocked");
        });
        assert!(db.check_msg_id_seen(&[44; 16]).unwrap(), "fresh dedup entry kept");
        // Lock stops the cleaner, so an expired key now waits for the next unlock.
        state.clear_unlocked().unwrap();
        db.save_skipped_key(cid, &expired_key(2)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(db.count_skipped_keys(cid).unwrap(), 1);
    }

    #[test]
    fn row10_display_only_starts_timers_for_the_rendered_page() {
        let (_dir, mut state, db, cid) = setup();
        // 201 live rows: only the newest 200 are rendered and marked read.
        let mut oldest = 0;
        for n in 1..=201 {
            let (id, _) = store(&state, &db, cid, n);
            if n == 1 {
                oldest = id;
            }
        }
        assert_eq!(
            crate::disappearing::displayed_messages(&db, &state.disappearing_keys, cid)
                .unwrap()
                .len(),
            200
        );
        assert!(db.get_message(oldest).unwrap().unwrap().read_at.is_none());
        state.clear_unlocked().unwrap();
    }

    #[test]
    fn row10_display_skips_missing_keys_and_expired_rows() {
        let (_dir, mut state, db, cid) = setup();
        let (missing, _) = store(&state, &db, cid, 60);
        let (expired, _) = store(&state, &db, cid, 61);
        state.disappearing_keys.remove_key(&[60; 16]);
        db.set_message_disappear_at(expired, 1).unwrap();
        assert!(
            crate::disappearing::displayed_messages(&db, &state.disappearing_keys, cid)
                .unwrap()
                .is_empty()
        );
        assert!(db.get_message(missing).unwrap().unwrap().read_at.is_none());
        assert!(db.get_message(expired).unwrap().unwrap().read_at.is_none());
        state.clear_unlocked().unwrap();
    }
}
