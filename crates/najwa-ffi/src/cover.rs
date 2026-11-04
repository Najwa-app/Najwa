//! Desktop cover lifetime is independent of unlocked identity/database state.
use crate::state::state_cell;
use najwa_core::cover::{
    AbsorptionPriority, CoverMailboxSnapshot, CoverTrafficConfig, CoverTrafficScheduler,
};
use najwa_core::fetch_plan::{active_dummies, FetchPlan, DUMMY_CAPS_PER_MAILBOX};
use najwa_protocol::mailbox::{
    http::HttpMailboxClient,
    types::{CapabilitySettings, MailboxConfig},
};
use najwa_storage::{database::SqliteStorage, types::Mailbox};
use std::{collections::HashMap, sync::Arc, time::Duration};

pub(crate) struct CoverRuntime {
    pub scheduler: CoverTrafficScheduler,
    pub client: Arc<HttpMailboxClient>,
    /// S08 §6.1.1 pools: onions and fetch capabilities only, so the receive
    /// worker keeps the same selection while locked (S13 §8.3).
    pub fetch_plan: Arc<FetchPlan>,
    snapshot: Vec<CoverMailboxSnapshot>,
    maintenance: Option<tokio::task::JoinHandle<()>>,
}

impl CoverRuntime {
    pub fn start(client: Arc<HttpMailboxClient>, config: CoverTrafficConfig) -> Self {
        let mut scheduler = CoverTrafficScheduler::new(config);
        scheduler.start(client.clone());
        Self {
            scheduler,
            client,
            fetch_plan: Default::default(),
            snapshot: Vec::new(),
            maintenance: Some(tokio::spawn(maintain())),
        }
    }

    pub fn refresh(&mut self, storage: &SqliteStorage) {
        match fetch_pools(storage) {
            Ok(pools) => self.fetch_plan.replace(pools),
            Err(error) => tracing::warn!(%error, "cannot refresh fetch plan"),
        }
        match cover_snapshot(storage) {
            Ok(snapshot) if snapshot != self.snapshot => {
                self.scheduler.replace_mailboxes(snapshot.clone());
                self.snapshot = snapshot;
            }
            Err(error) => tracing::warn!(%error, "cannot refresh cover mailboxes"),
            _ => {}
        }
    }
}

impl Drop for CoverRuntime {
    fn drop(&mut self) {
        if let Some(job) = self.maintenance.take() {
            job.abort();
        }
        self.scheduler.stop();
    }
}

fn coordinates(m: &Mailbox) -> Option<CoverMailboxSnapshot> {
    Some(CoverMailboxSnapshot {
        onion_address: m.onion_address.clone(),
        cover_deposit_capability: m.cover_deposit_capability.as_deref()?.try_into().ok()?,
        cover_fetch_capability: m.cover_fetch_capability.as_deref()?.try_into().ok()?,
        cover_envelope_secret: m.cover_envelope_secret.as_deref()?.try_into().ok()?,
        dummy_deposit_capabilities: Vec::new(),
    })
}

/// Real receive-queue fetch capabilities per enabled mailbox (S08 §6.1).
fn real_fetch_caps(storage: &SqliteStorage) -> Result<HashMap<i64, Vec<[u8; 32]>>, String> {
    let mut real: HashMap<i64, Vec<[u8; 32]>> = HashMap::new();
    for (id, queue) in najwa_core::bridge::receive_queues(storage)? {
        real.entry(id).or_default().push(queue.fetch_capability);
    }
    Ok(real)
}

/// Registered dummy `(fetch, deposit)` pairs of a mailbox, in pool order.
fn registered_dummies(storage: &SqliteStorage, mailbox: i64) -> Result<Vec<([u8; 32], [u8; 32])>, String> {
    Ok(storage
        .list_dummy_capabilities(mailbox)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|d| d.registered_at.is_some())
        .filter_map(|d| {
            Some((d.fetch_capability.as_slice().try_into().ok()?, d.deposit_capability.as_slice().try_into().ok()?))
        })
        .collect())
}

fn cover_snapshot(storage: &SqliteStorage) -> Result<Vec<CoverMailboxSnapshot>, String> {
    let real = real_fetch_caps(storage)?;
    let mut snapshot = Vec::new();
    for m in storage.list_mailboxes().map_err(|e| e.to_string())? {
        if !(m.enabled && m.failure_count < 5 && m.cover_registered_at.is_some()) {
            continue;
        }
        let Some(mut cover) = coordinates(&m) else { continue };
        // S10 §5.1: only dummies in the poll pool receive self-deposits.
        let active = active_dummies(real.get(&m.id).map_or(0, Vec::len));
        cover.dummy_deposit_capabilities =
            registered_dummies(storage, m.id)?.into_iter().take(active).map(|(_, deposit)| deposit).collect();
        snapshot.push(cover);
    }
    Ok(snapshot)
}

/// `(onion, real fetch capabilities, registered dummy fetch capabilities)` per
/// enabled mailbox, for the fetch plan that outlives the lock.
fn fetch_pools(storage: &SqliteStorage) -> Result<Vec<(String, Vec<[u8; 32]>, Vec<[u8; 32]>)>, String> {
    let mut real = real_fetch_caps(storage)?;
    let mut pools = Vec::new();
    for m in storage.list_mailboxes().map_err(|e| e.to_string())? {
        if m.enabled {
            let dummies = registered_dummies(storage, m.id)?.into_iter().map(|(fetch, _)| fetch).collect();
            pools.push((m.onion_address, real.remove(&m.id).unwrap_or_default(), dummies));
        }
    }
    Ok(pools)
}

#[derive(Clone)]
struct Registration {
    id: i64,
    cover: CoverMailboxSnapshot,
    /// A dummy pair `(row id, fetch, deposit)` registered instead of the cover
    /// pair, the same way (S08 §6.1.1, S10 §5.1).
    dummy: Option<(i64, [u8; 32], [u8; 32])>,
}
impl Registration {
    fn config(&self) -> MailboxConfig {
        let (fetch, deposit) = self.dummy.map_or(
            (self.cover.cover_fetch_capability, self.cover.cover_deposit_capability),
            |(_, fetch, deposit)| (fetch, deposit),
        );
        MailboxConfig {
            onion_address: self.cover.onion_address.clone(),
            fetch_capability: fetch,
            deposit_capability: deposit,
            envelope_secret: self.cover.cover_envelope_secret,
            cover_deposit_capability: Some(deposit),
            cover_fetch_capability: Some(fetch),
            cover_envelope_secret: Some(self.cover.cover_envelope_secret),
        }
    }
    fn matches(&self, storage: &SqliteStorage) -> bool {
        storage
            .get_mailbox(self.id)
            .ok()
            .flatten()
            .is_some_and(|m| {
                m.enabled && m.failure_count < 5 && coordinates(&m).as_ref() == Some(&self.cover)
            })
            && self.dummy.is_none_or(|(row, fetch, deposit)| {
                storage.list_dummy_capabilities(self.id).is_ok_and(|all| {
                    all.iter().any(|d| d.id == row && d.fetch_capability == fetch && d.deposit_capability == deposit)
                })
            })
    }
    fn stamp(&self, storage: &SqliteStorage) -> najwa_storage::error::Result<()> {
        let now = najwa_crypto::time::now() as i64;
        match self.dummy {
            Some((row, ..)) => storage.mark_dummy_capability_registered(row, now),
            None => storage.mark_cover_capabilities_registered(self.id, now),
        }
    }
}

fn next_registration(
    storage: &SqliteStorage,
    after: Option<i64>,
) -> najwa_storage::error::Result<Option<Registration>> {
    let mut mailboxes = storage.list_mailboxes()?;
    mailboxes.sort_by_key(|m| (after.is_some_and(|id| m.id <= id), m.id));
    for mut m in mailboxes {
        if !m.enabled || m.failure_count >= 5 {
            continue;
        }
        if coordinates(&m).is_none() {
            use najwa_crypto::random::random_bytes;
            storage.set_cover_capabilities(
                m.id,
                &random_bytes(),
                &random_bytes(),
                &random_bytes(),
            )?;
            m = storage.get_mailbox(m.id)?.expect("mailbox just updated");
        }
        let cover = coordinates(&m).expect("cover coordinates persisted");
        if m.cover_registered_at.is_none() {
            return Ok(Some(Registration { id: m.id, cover, dummy: None }));
        }
        // Then the dummy queues that pad this mailbox's polls (S08 §6.1.1).
        for _ in storage.list_dummy_capabilities(m.id)?.len()..DUMMY_CAPS_PER_MAILBOX {
            use najwa_crypto::random::random_bytes;
            storage.save_dummy_capability(m.id, &random_bytes(), &random_bytes())?;
        }
        let pending = storage
            .list_dummy_capabilities(m.id)?
            .into_iter()
            .filter(|d| d.registered_at.is_none())
            .find_map(|d| {
                Some((d.id, d.fetch_capability.as_slice().try_into().ok()?, d.deposit_capability.as_slice().try_into().ok()?))
            });
        if pending.is_some() {
            return Ok(Some(Registration { id: m.id, cover, dummy: pending }));
        }
    }
    Ok(None)
}

/// All database access is synchronous under the state lock. Only cover
/// coordinates survive awaits, so UI lock can close SQLCipher and zeroize keys.
async fn maintain() {
    let mut completed: Option<Registration> = None;
    let mut cursor = None;
    loop {
        let work = {
            let mut state = state_cell().write().unwrap();
            state.as_mut().and_then(|s| {
                let storage = s.storage.as_ref()?;
                let cover = s.cover.as_mut()?;
                if let Some(done) = completed.as_ref() {
                    if done.matches(storage) && done.stamp(storage).is_err() {
                        return None;
                    }
                    completed = None;
                }
                let next = match next_registration(storage, cursor) {
                    Ok(next) => next,
                    Err(error) => {
                        tracing::warn!(%error, "cover provisioning deferred");
                        None
                    }
                };
                cover.refresh(storage);
                next.map(|r| (r, cover.client.clone(), cover.scheduler.slot_source()))
            })
        };
        if let Some((registration, client, slots)) = work {
            cursor = Some(registration.id);
            let mailbox = registration.config();
            let result = tokio::time::timeout(Duration::from_secs(180), async {
                let pow = client.prepare_registration_pow(&mailbox).await?;
                loop {
                    let permit = slots
                        .await_slot(&mailbox.onion_address, AbsorptionPriority::Control, None)
                        .await;
                    // A health/configuration change during the wait cancels
                    // this registration and the permit supplies fallback cover.
                    let valid = state_cell()
                        .read()
                        .unwrap()
                        .as_ref()
                        .and_then(|s| s.storage.as_ref())
                        .is_none_or(|db| registration.matches(db));
                    if !valid {
                        return Err(
                            najwa_protocol::mailbox::error::MailboxError::CapabilityNotFound,
                        );
                    }
                    if permit.begin() {
                        break;
                    }
                }
                // Exact-pair registration is idempotent at the server, so a
                // lost local stamp is recovered by submitting the same pair.
                // A 409 instead means a different mapping and must fail.
                client
                    .register_cover_once(&mailbox, &CapabilitySettings::default(), pow)
                    .await
            })
            .await;
            if matches!(result, Ok(Ok(()))) {
                let mut state = state_cell().write().unwrap();
                if let Some(s) = state.as_mut() {
                    if s.storage
                        .as_ref()
                        .is_none_or(|db| registration.matches(db))
                    {
                        let stamped = s
                            .storage
                            .as_ref()
                            .is_some_and(|db| registration.stamp(db).is_ok());
                        // A registered dummy joins the pool at the next refresh.
                        if let Some(cover) = s.cover.as_mut().filter(|_| registration.dummy.is_none()) {
                            cover
                                .snapshot
                                .retain(|m| m.onion_address != registration.cover.onion_address);
                            cover.snapshot.push(registration.cover.clone());
                            cover.scheduler.replace_mailboxes(cover.snapshot.clone());
                        }
                        completed = if stamped { None } else { Some(registration) };
                    }
                }
            } else {
                tracing::warn!(mailbox = %registration.cover.onion_address, "cover registration deferred");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("row10_desktop_tests.rs");
    use najwa_protocol::mailbox::client::Transport;
    use najwa_transport::{
        circuit::{CircuitHandle, CircuitIsolation},
        error::TransportError,
        http::HttpResponse,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Network {
        deposits: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Transport for Network {
        async fn get_circuit(
            &self,
            isolation: CircuitIsolation,
        ) -> Result<CircuitHandle, TransportError> {
            Ok(CircuitHandle::new(isolation))
        }
        async fn post(
            &self,
            _: &CircuitHandle,
            url: &str,
            _: &[u8],
            _: &str,
        ) -> Result<HttpResponse, TransportError> {
            let body = if url.ends_with("/deposit") {
                self.deposits.fetch_add(1, Ordering::SeqCst);
                br#"{"accepted":true,"message_id":null}"#.to_vec()
            } else {
                br#"{"messages":[],"has_more":false}"#.to_vec()
            };
            Ok(HttpResponse {
                status: 200,
                headers: Default::default(),
                body,
            })
        }
        async fn get(&self, _: &CircuitHandle, _: &str) -> Result<HttpResponse, TransportError> {
            unreachable!()
        }
    }

    fn mailbox(db: &SqliteStorage, onion: &str) -> i64 {
        db.save_mailbox(&najwa_storage::types::NewMailbox::with_cover_caps(
            onion.into(),
            vec![11; 32],
            vec![12; 32],
            0,
            1,
        ))
        .unwrap()
    }

    #[test]
    fn row9_snapshot_excludes_unregistered_disabled_and_failed_mailboxes() {
        let db = SqliteStorage::open_in_memory(&[21; 32]).unwrap();
        let good = mailbox(&db, "good");
        let disabled = mailbox(&db, "disabled");
        let failed = mailbox(&db, "failed");
        mailbox(&db, "unregistered");
        for id in [good, disabled, failed] {
            db.mark_cover_capabilities_registered(id, 1).unwrap();
        }
        db.disable_mailbox(disabled).unwrap();
        for _ in 0..5 {
            db.update_mailbox_health(failed, false).unwrap();
        }
        let snapshot = cover_snapshot(&db).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].onion_address, "good");
        assert_ne!(snapshot[0].cover_fetch_capability, [11; 32]);
        assert_ne!(snapshot[0].cover_deposit_capability, [12; 32]);
    }

    #[test]
    fn row9_registration_preserves_coordinates_until_server_acceptance() {
        let db = SqliteStorage::open_in_memory(&[22; 32]).unwrap();
        let id = mailbox(&db, "register");
        let first = next_registration(&db, None).unwrap().unwrap();
        let retry = next_registration(&db, Some(first.id)).unwrap().unwrap();
        assert_eq!(first.cover, retry.cover);
        assert!(cover_snapshot(&db).unwrap().is_empty());
        db.mark_cover_capabilities_registered(id, 1).unwrap();
        assert!(next_registration(&db, None).unwrap().unwrap().dummy.is_some());
        assert_eq!(cover_snapshot(&db).unwrap(), vec![first.cover]);
    }

    #[test]
    fn dummy_queues_follow_the_cover_pair_and_fill_the_poll_pool() {
        let db = SqliteStorage::open_in_memory(&[26; 32]).unwrap();
        let id = mailbox(&db, "dummies");
        db.mark_cover_capabilities_registered(id, 1).unwrap();
        let mut registered = Vec::new();
        while let Some(next) = next_registration(&db, None).unwrap() {
            let (_, fetch, deposit) = next.dummy.expect("only dummies remain");
            assert!(next.matches(&db));
            let config = next.config();
            assert_eq!((config.fetch_capability, config.deposit_capability), (fetch, deposit));
            next.stamp(&db).unwrap();
            registered.push(fetch);
            assert!(registered.len() <= DUMMY_CAPS_PER_MAILBOX);
        }
        assert_eq!(registered.len(), DUMMY_CAPS_PER_MAILBOX);
        // The mailbox's own queue is its only real queue, so every dummy pads it.
        let pools = fetch_pools(&db).unwrap();
        assert_eq!(pools, vec![("dummies".to_string(), vec![[11; 32]], registered)]);
        let snapshot = cover_snapshot(&db).unwrap();
        assert_eq!(snapshot[0].dummy_deposit_capabilities.len(), DUMMY_CAPS_PER_MAILBOX);
    }

    #[test]
    fn row9_registration_rotates_past_failed_mailboxes() {
        let db = SqliteStorage::open_in_memory(&[25; 32]).unwrap();
        let first_id = mailbox(&db, "unreachable");
        let second_id = mailbox(&db, "healthy");
        assert_eq!(next_registration(&db, None).unwrap().unwrap().id, first_id);
        assert_eq!(
            next_registration(&db, Some(first_id)).unwrap().unwrap().id,
            second_id
        );
        assert_eq!(
            next_registration(&db, Some(second_id)).unwrap().unwrap().id,
            first_id
        );
    }

    #[test]
    fn row9_installed_cover_keeps_emitting_after_identity_and_storage_drop() {
        use najwa_core::cover::BurstMode;
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::state::AppState::new(dir.path().into()).unwrap();
        state.db_key = Some(crate::state::test_key(23));
        state.identity = Some(najwa_identity::record::Identity {
            keypair: najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[24; 32]),
            created_at: 1,
            version: 1,
        });
        let db = crate::state::open_storage(dir.path(), &crate::state::test_key(23)).unwrap();
        let id = mailbox(&db, "cover.onion");
        db.mark_cover_capabilities_registered(id, 1).unwrap();
        let cid = db
            .create_contact(&najwa_storage::types::NewContact {
                pseudonym: [31; 32],
                their_ik_pub: [32; 32],
                their_device_pub: [32; 32],
                our_pseudonym: [33; 32],
                display_name: None,
            })
            .unwrap();
        db.save_contact_capability(&najwa_storage::types::NewContactMailboxCap {
            contact_id: cid,
            mailbox_id: id,
            deposit_capability: vec![34; 32],
            fetch_capability: Some(vec![35; 32]),
            their_deposit_capability: Some(vec![36; 32]),
            their_envelope_secret: Some(vec![37; 32]),
            envelope_secret: Some(vec![38; 32]),
            capability_type: 2,
            expires_at: None,
            registered_at: Some(1),
            created_at: 1,
        })
        .unwrap();
        let peer_dh = najwa_crypto::keys::x25519::X25519KeyPair::from_seed([39; 32]);
        let ratchet =
            najwa_protocol::ratchet::init::init_alice(&[40; 32], peer_dh.public(), &[41; 32])
                .unwrap();
        state
            .runtime
            .block_on(najwa_core::storage::CoreStorage::save_ratchet_state(
                &*db, cid as u64, &ratchet,
            ))
            .unwrap();
        db.save_session_ad(cid, &[42; 64]).unwrap();
        drop(ratchet);
        drop(peer_dh);
        let weak_db = Arc::downgrade(&db);
        state.storage = Some(db);
        let network = Arc::new(Network {
            deposits: AtomicUsize::new(0),
        });
        let client = Arc::new(HttpMailboxClient::new(network.clone()));
        let handle = state.runtime.handle().clone();
        {
            let _entered = handle.enter();
            // Accelerate only the timer configuration; installation and lock
            // use exactly the production helpers.
            state.cover = Some(CoverRuntime::start(
                client.clone(),
                CoverTrafficConfig {
                    poll_interval: Duration::from_secs(86400),
                    deposit_interval: Duration::ZERO,
                    jitter_percent: 0,
                    burst_mode: BurstMode::PrivacyPriority,
                    ..Default::default()
                },
            ));
            crate::install_connected_service(&mut state, client).unwrap();
        }
        let weak_service = Arc::downgrade(state.service.lock().unwrap().as_ref().unwrap());
        handle.block_on(async {
            let service = weak_service.upgrade().unwrap();
            let send = service.send_message(
                cid as u64,
                najwa_core::types::MessageContent::Text("paced desktop message".into()),
            );
            tokio::pin!(send);
            assert!(tokio::time::timeout(Duration::from_millis(50), &mut send)
                .await
                .is_err());
            assert_eq!(network.deposits.load(Ordering::SeqCst), 0);
            assert_eq!(
                state
                    .cover
                    .as_ref()
                    .unwrap()
                    .scheduler
                    .pending_queues()
                    .len(),
                1
            );
            tokio::time::timeout(Duration::from_secs(3), &mut send)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(network.deposits.load(Ordering::SeqCst), 1);
        });
        state.clear_unlocked().unwrap();
        assert!(state.identity.is_none() && state.db_key.is_none());
        assert!(weak_db.upgrade().is_none() && weak_service.upgrade().is_none());
        assert!(state.cover.as_ref().unwrap().scheduler.is_running());
        let before = network.deposits.load(Ordering::SeqCst);
        handle.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while network.deposits.load(Ordering::SeqCst) == before {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
        });
    }
}
