// #23: fetch-capability selection (S08 §6.1.1) and the locked fetch-only poll (S13 §8.3).
mod fetch_selection {
    use super::*;
    use crate::fetch_plan::{FetchPlan, DUMMY_CAPS_PER_MAILBOX, FETCH_CAPS_MAX, FETCH_CAPS_MIN};
    use std::collections::HashSet;

    /// A mailbox that keeps each queue's blobs until they are acknowledged and
    /// records every fetch.
    struct Queues {
        inner: MockMailbox,
        blobs: Mutex<HashMap<[u8; 32], Vec<MailboxMessage>>>,
        fetched: Mutex<Vec<[u8; 32]>>,
    }
    impl Queues {
        fn new() -> Self {
            Self { inner: MockMailbox::new(), blobs: Default::default(), fetched: Default::default() }
        }
        fn put(&self, cap: [u8; 32], id: &str, blob: Vec<u8>) {
            let message = MailboxMessage {
                id: id.into(), size: blob.len() as u32, blob, deposited_at: 1, cap_hint: None,
            };
            self.blobs.lock().unwrap().entry(cap).or_default().push(message);
        }
        fn take_fetched(&self) -> Vec<[u8; 32]> {
            std::mem::take(&mut *self.fetched.lock().unwrap())
        }
        fn stored(&self) -> usize {
            self.blobs.lock().unwrap().values().map(Vec::len).sum()
        }
    }
    #[async_trait]
    impl MailboxClient for Queues {
        async fn register_capability(&self, m: &MailboxConfig, s: &CapabilitySettings, p: Option<&PowSolution>) -> najwa_protocol::mailbox::error::Result<()> {
            self.inner.register_capability(m, s, p).await
        }
        async fn get_challenge(&self, m: &MailboxConfig, h: &[u8; 8]) -> najwa_protocol::mailbox::error::Result<PowChallenge> {
            self.inner.get_challenge(m, h).await
        }
        async fn deposit(&self, m: &MailboxConfig, c: &[u8; 32], b: &[u8], p: Option<&PowSolution>) -> najwa_protocol::mailbox::error::Result<DepositResult> {
            self.inner.deposit(m, c, b, p).await
        }
        async fn fetch(&self, _: &MailboxConfig, cap: &[u8; 32], _: Option<&str>, limit: u32) -> najwa_protocol::mailbox::error::Result<Vec<MailboxMessage>> {
            self.fetched.lock().unwrap().push(*cap);
            let blobs = self.blobs.lock().unwrap();
            Ok(blobs.get(cap).map(|q| q.iter().take(limit as usize).cloned().collect()).unwrap_or_default())
        }
        async fn upload_prekey_bundle(&self, m: &MailboxConfig, c: &[u8; 32], b: &PrekeyBundle) -> najwa_protocol::mailbox::error::Result<()> {
            self.inner.upload_prekey_bundle(m, c, b).await
        }
        async fn fetch_prekey_bundle(&self, m: &MailboxConfig, c: &[u8; 32], p: &[u8; 32]) -> najwa_protocol::mailbox::error::Result<PrekeyBundle> {
            self.inner.fetch_prekey_bundle(m, c, p).await
        }
        async fn get_status(&self, m: &MailboxConfig, c: &[u8; 32]) -> najwa_protocol::mailbox::error::Result<CapabilityStatus> {
            self.inner.get_status(m, c).await
        }
        async fn deactivate_capability(&self, m: &MailboxConfig, c: &[u8; 32]) -> najwa_protocol::mailbox::error::Result<()> {
            self.inner.deactivate_capability(m, c).await
        }
        async fn acknowledge(&self, m: &MailboxConfig, cap: &[u8; 32], ids: &[String]) -> najwa_protocol::mailbox::error::Result<()> {
            if let Some(queue) = self.blobs.lock().unwrap().get_mut(cap) {
                queue.retain(|message| !ids.contains(&message.id));
            }
            self.inner.acknowledge(m, cap, ids).await
        }
    }

    fn dummies() -> Vec<[u8; 32]> {
        (0..DUMMY_CAPS_PER_MAILBOX as u8).map(|n| [0x80 + n; 32]).collect()
    }

    /// The mailbox's own queue `[1; 32]` plus one registered queue per contact.
    fn queues_db(onion: &str, contacts: u8) -> najwa_storage::database::SqliteStorage {
        use najwa_storage::prelude as sql;
        let db = sql::SqliteStorage::open_in_memory(&[0x61; 32]).unwrap();
        let mailbox = db
            .save_mailbox(&sql::NewMailbox {
                onion_address: onion.into(), fetch_capability: vec![1; 32],
                deposit_capability: vec![2; 32], envelope_secret: vec![3; 32],
                cover_deposit_capability: None, cover_fetch_capability: None,
                cover_envelope_secret: None, priority: 1, created_at: 1,
            })
            .unwrap();
        for n in 0..contacts {
            let contact = db
                .create_contact(&sql::NewContact {
                    pseudonym: [10 + n; 32], their_ik_pub: [20 + n; 32],
                    their_device_pub: [20 + n; 32], our_pseudonym: [30 + n; 32],
                    display_name: None,
                })
                .unwrap();
            db.save_contact_capability(&sql::NewContactMailboxCap {
                contact_id: contact, mailbox_id: mailbox, deposit_capability: vec![40 + n; 32],
                fetch_capability: Some(vec![50 + n; 32]), their_deposit_capability: None,
                their_envelope_secret: None, envelope_secret: Some(vec![60 + n; 32]),
                capability_type: 2, expires_at: None, registered_at: Some(1), created_at: 1,
            })
            .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn poll_reads_four_to_ten_capabilities_whatever_the_contact_count() {
        let onion = "q".repeat(56);
        for contacts in [1u8, 3] {
            let mut svc = MessagingService::new(
                Ed25519KeyPair::from_seed(&[0x62; 32]),
                queues_db(&onion, contacts),
                Queues::new(),
            );
            let plan = Arc::new(FetchPlan::default());
            plan.replace(vec![(onion.clone(), Vec::new(), dummies())]);
            svc.set_fetch_plan(plan);
            let real: HashSet<[u8; 32]> =
                std::iter::once([1; 32]).chain((0..contacts).map(|n| [50 + n; 32])).collect();
            let mut seen = HashSet::new();
            for _ in 0..12 {
                svc.poll_messages().await.unwrap();
                let fetched: HashSet<_> = svc.mailbox_client.take_fetched().into_iter().collect();
                assert!(
                    (FETCH_CAPS_MIN..=FETCH_CAPS_MAX).contains(&fetched.len()),
                    "{contacts} contact(s): one poll read {} capabilities",
                    fetched.len()
                );
                assert!(fetched.iter().all(|cap| real.contains(cap) || dummies().contains(cap)));
                seen.extend(fetched);
            }
            assert!(real.is_subset(&seen), "every real queue is read over successive polls");
            assert_eq!(seen.len(), FETCH_CAPS_MAX, "real queues plus just enough dummies");
        }
    }

    #[tokio::test]
    async fn locked_polls_keep_the_selection_but_leave_blobs_for_unlock() {
        use najwa_protocol::message::envelope::envelope_encrypt;
        let (sender, receiver) = row7_pair().await;
        let onion = "a".repeat(56);
        // What the app snapshots just before lock: the fetch capabilities of
        // the own and per-contact queues (both [77; 32] in this fixture).
        let plan = Arc::new(FetchPlan::default());
        plan.replace(vec![(onion.clone(), vec![[77; 32], [77; 32]], dummies())]);
        let mut svc = MessagingService::new(
            Ed25519KeyPair::from_seed(&[171; 32]),
            receiver.storage,
            Queues::new(),
        );
        svc.set_fetch_plan(plan.clone());
        let (raw, _) = row7_frame(&sender, 2, &row7_payload(1, 0, b"waits for unlock")).await;
        svc.mailbox_client.put([77; 32], "real", envelope_encrypt(&ESA, &DCA, &raw).unwrap());
        svc.mailbox_client.put(dummies()[0], "cover", vec![9; 256]);

        let mut seen = HashSet::new();
        for _ in 0..6 {
            plan.poll_locked(&svc.mailbox_client).await;
            let fetched = svc.mailbox_client.take_fetched();
            assert!((FETCH_CAPS_MIN..=FETCH_CAPS_MAX).contains(&fetched.len()));
            seen.extend(fetched);
        }
        assert!(seen.contains(&[77; 32]) && seen.contains(&dummies()[0]));
        assert!(svc.mailbox_client.inner.acked_ids().is_empty(), "a locked poll acknowledges nothing");
        assert_eq!(svc.mailbox_client.stored(), 2, "blobs stay on the mailbox while locked");
        assert!(svc.storage.list_messages(1, 10, None).unwrap().is_empty(), "nothing processed while locked");

        let mut received = Vec::new();
        for _ in 0..3 {
            received.extend(svc.poll_messages().await.unwrap());
        }
        assert_eq!(bodies(&received), ["waits for unlock"]);
        let acked: HashSet<_> = svc.mailbox_client.inner.acked_ids().into_iter().collect();
        assert!(acked.contains("real") && acked.contains("cover"));
        assert_eq!(svc.mailbox_client.stored(), 0);
    }
}
