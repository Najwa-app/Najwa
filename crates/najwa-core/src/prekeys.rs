//! Drive S06 maintenance from the production poll path, including S02 recovery.
use crate::{
    cover::AbsorptionPriority,
    error::{MessagingError, Result},
    service::MessagingService,
    storage::CoreStorage,
};
use async_trait::async_trait;
use najwa_protocol::{
    mailbox::{
        client::MailboxClient,
        types::{MailboxConfig, PrekeyBundle},
    },
    prekey::{manager::PrekeyPublisher, sqlite::SqlitePrekeyStorage, PrekeyManager},
};
use najwa_storage::prekey_lifecycle::prekey_scope_setting;

struct PacedPublisher<'a, S: CoreStorage, M: MailboxClient> {
    service: &'a MessagingService<S, M>,
    recovery: bool,
}
#[async_trait]
impl<S: CoreStorage, M: MailboxClient> PrekeyPublisher for PacedPublisher<'_, S, M> {
    async fn publish(
        &self,
        mailbox: &MailboxConfig,
        _deposit: &[u8; 32],
        bundle: &PrekeyBundle,
    ) -> najwa_protocol::mailbox::error::Result<()> {
        self.service.prekey_control_slot(mailbox).await;
        self.service
            .mailbox_client
            .publish_prekeys_once(mailbox, bundle, self.recovery)
            .await?;
        if let Some(db) = self.service.storage.prekey_database() {
            db.set_setting_raw(
                &prekey_scope_setting("dirty", &mailbox.fetch_capability),
                &[0],
            )
            .map_err(|e| {
                najwa_protocol::mailbox::error::MailboxError::DeserializationError(e.to_string())
            })?;
        }
        Ok(())
    }
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    pub(crate) async fn prekey_control_slot(&self, mailbox: &MailboxConfig) {
        if let Some(slots) = &self.slot_source {
            loop {
                let permit = slots
                    .await_slot(&mailbox.onion_address, AbsorptionPriority::Control, None)
                    .await;
                if permit.begin() {
                    break;
                }
            }
        }
    }

    pub(crate) fn require_prekey_recovery_complete(&self) -> Result<()> {
        let Some(db) = self.storage.prekey_database() else {
            return Ok(());
        };
        let generation = najwa_identity::prekey_recovery::generation(
            db.data_dir(),
            &self.identity_key.public().to_bytes(),
        )
        .map_err(|e| MessagingError::StorageError(e.to_string()))?;
        if let Some(generation) = generation {
            let complete = db
                .get_setting_raw("prekeys:complete")
                .map_err(|e| MessagingError::StorageError(e.to_string()))?;
            if complete.as_deref() != Some(generation.as_slice()) {
                return Err(MessagingError::StorageError(
                    "recovery prekey uploads pending".into(),
                ));
            }
        }
        Ok(())
    }

    /// Called before receiving Initials. Failed uploads remain pending across
    /// restart; successful maintenance is limited to once per hour per capability.
    pub async fn maintain_prekeys(&self) -> Result<()> {
        let Some(db) = self.storage.prekey_database() else {
            return Ok(());
        };
        let storage_error =
            |e: najwa_storage::error::StorageError| MessagingError::StorageError(e.to_string());
        let _maintenance = self.prekey_gate.lock().await;
        let generation = najwa_identity::prekey_recovery::generation(
            db.data_dir(),
            &self.identity_key.public().to_bytes(),
        )
        .map_err(|e| MessagingError::StorageError(e.to_string()))?;
        let recovering = if let Some(generation) = generation {
            // Retirement cannot overlap an Initial commit. Release this guard
            // before waiting for cover slots, so normal ratchet traffic can run.
            let _state = self.state_gate.lock().await;
            db.prepare_prekey_recovery(&generation)
                .map_err(storage_error)?;
            db.get_setting_raw("prekeys:complete")
                .map_err(storage_error)?
                .as_deref()
                != Some(generation.as_slice())
        } else {
            false
        };
        let mailboxes = self
            .storage
            .list_mailboxes_with_ids()
            .await
            .map_err(MessagingError::StorageError)?;
        let has_mailboxes = !mailboxes.is_empty();
        for (id, mailbox) in mailboxes {
            let ephemeral = self
                .storage
                .get_ephemeral_handshake_capability(id, &mailbox.fetch_capability)
                .await
                .map_err(MessagingError::StorageError)?;
            if let Some(cap) = ephemeral {
                if recovering {
                    // A type-1 capability authorizes only one Initial for its entire
                    // lifetime; recovery retires it rather than resetting its cache.
                    self.prekey_control_slot(&mailbox).await;
                    self.mailbox_client.deactivate_once(&mailbox).await?;
                    self.storage
                        .mark_ephemeral_handshake_cap_deactivated(cap.id)
                        .await
                        .map_err(MessagingError::StorageError)?;
                    continue;
                }
                if cap.accepted {
                    continue;
                }
            }
            let setting = prekey_scope_setting("last", &mailbox.fetch_capability);
            let now = najwa_crypto::time::now();
            let last = db.get_setting::<u64>(&setting).map_err(storage_error)?;
            let dirty = db
                .get_setting_raw(&prekey_scope_setting("dirty", &mailbox.fetch_capability))
                .map_err(storage_error)?
                .as_deref()
                == Some(&[1]);
            if !dirty && last.is_some_and(|last| now.saturating_sub(last) < 3600) {
                continue;
            }
            // Do not interpret a pending upload's fresh keys as remotely served.
            // First retry that exact pool; reconcile on the next maintenance run.
            if !recovering && !dirty && last.is_some() {
                self.prekey_control_slot(&mailbox).await;
                let status = self.mailbox_client.get_status_once(&mailbox).await?;
                if status.prekey_ids.len() != status.prekey_count as usize {
                    return Err(MessagingError::StorageError(
                        "incomplete server prekey inventory".into(),
                    ));
                }
                let _state = self.state_gate.lock().await;
                db.reconcile_prekey_inventory(
                    id,
                    &mailbox.fetch_capability,
                    &status.prekey_ids,
                    (now + najwa_protocol::prekey::SPK_GRACE_PERIOD_SECS) as i64,
                )
                .map_err(storage_error)?;
            }
            let storage = SqlitePrekeyStorage::new(db, id, mailbox.clone())
                .map_err(MessagingError::StorageError)?;
            let manager = PrekeyManager::new(
                // Shares the service's key instead of copying the seed (S01 §6.2).
                self.identity_key.clone(),
                storage,
                PacedPublisher {
                    service: self,
                    recovery: recovering,
                },
                mailbox,
            )
            .map_err(|e| MessagingError::StorageError(e.to_string()))?;
            manager
                .maintenance()
                .await
                .map_err(|e| MessagingError::StorageError(e.to_string()))?;
            db.set_setting(&setting, &now).map_err(storage_error)?;
        }
        if recovering && has_mailboxes {
            db.set_setting_raw("prekeys:complete", &generation.unwrap())
                .map_err(storage_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_protocol::mailbox::{client::Transport, http::HttpMailboxClient};
    use najwa_storage::{database::SqliteStorage, types::NewMailbox};
    use najwa_transport::{
        circuit::{CircuitHandle, CircuitIsolation},
        error::TransportError,
        http::HttpResponse,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    #[derive(Default)]
    struct UploadTransport {
        fail: AtomicBool,
        uploads: Mutex<Vec<serde_json::Value>>,
    }
    #[async_trait]
    impl Transport for UploadTransport {
        async fn get_circuit(
            &self,
            isolation: CircuitIsolation,
        ) -> std::result::Result<CircuitHandle, TransportError> {
            Ok(CircuitHandle::new(isolation))
        }
        async fn post(
            &self,
            _: &CircuitHandle,
            url: &str,
            body: &[u8],
            _: &str,
        ) -> std::result::Result<HttpResponse, TransportError> {
            assert!(url.ends_with("/v1/prekey/upload"));
            self.uploads
                .lock()
                .unwrap()
                .push(serde_json::from_slice(body).unwrap());
            Ok(HttpResponse {
                status: if self.fail.load(Ordering::SeqCst) {
                    503
                } else {
                    200
                },
                headers: Default::default(),
                body: b"{}".to_vec(),
            })
        }
        async fn get(
            &self,
            _: &CircuitHandle,
            _: &str,
        ) -> std::result::Result<HttpResponse, TransportError> {
            unreachable!()
        }
    }
    fn save_mailbox(db: &SqliteStorage, i: u8) -> i64 {
        db.save_mailbox(&NewMailbox::with_cover_caps(
            format!("mailbox{i}"),
            vec![i; 32],
            vec![i + 10; 32],
            1,
            1,
        ))
        .unwrap()
    }
    fn open_service(
        path: &std::path::Path,
        transport: Arc<UploadTransport>,
    ) -> MessagingService<SqliteStorage, HttpMailboxClient> {
        MessagingService::new(
            najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[29; 32]),
            SqliteStorage::open(path, &[9; 32]).unwrap(),
            HttpMailboxClient::new(transport),
        )
    }
    #[tokio::test]
    async fn recovery_failure_and_restart_preserve_gate_and_fresh_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("najwa.db");
        let transport = Arc::new(UploadTransport::default());
        let service = open_service(&path, transport.clone());
        let id = save_mailbox(&service.storage, 1);
        save_mailbox(&service.storage, 2);
        service.maintain_prekeys().await.unwrap();
        let old = service
            .storage
            .prekey_ids_for_mailbox(id, &[1; 32])
            .unwrap();
        assert_eq!(old.len(), 201);
        let before = transport.uploads.lock().unwrap().len();
        service.maintain_prekeys().await.unwrap();
        assert_eq!(
            transport.uploads.lock().unwrap().len(),
            before,
            "no upload on every poll"
        );
        let key: String = service
            .identity_key
            .public()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(dir.path().join(format!("prekey-recovery-{key}")), [42; 32]).unwrap();
        assert!(service.require_prekey_recovery_complete().is_err());
        transport.fail.store(true, Ordering::SeqCst);
        assert!(service.maintain_prekeys().await.is_err());
        assert!(service.require_prekey_recovery_complete().is_err());
        for id in &old {
            assert!(service.storage.get_prekey(id).unwrap().is_none());
        }
        let fresh = service
            .storage
            .prekey_ids_for_mailbox(id, &[1; 32])
            .unwrap();
        assert_eq!(fresh.len(), 201);
        assert!(fresh.iter().all(|id| !old.contains(id)));
        drop(service);
        let service = open_service(&path, transport.clone());
        assert!(service.require_prekey_recovery_complete().is_err());
        transport.fail.store(false, Ordering::SeqCst);
        service.maintain_prekeys().await.unwrap();
        service.require_prekey_recovery_complete().unwrap();
        assert_eq!(
            service
                .storage
                .prekey_ids_for_mailbox(id, &[1; 32])
                .unwrap(),
            fresh
        );
        {
            let uploads = transport.uploads.lock().unwrap();
            assert!(uploads.iter().all(|u| u["fetch_capability"].is_string()));
            assert_eq!(uploads.last().unwrap()["replace_opks"], true);
        }
        drop(service);
        open_service(&path, transport)
            .require_prekey_recovery_complete()
            .unwrap();
    }

    #[tokio::test]
    async fn replenishment_retry_preserves_pending_pool_and_inflight_private_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("najwa.db");
        let transport = Arc::new(UploadTransport::default());
        let service = open_service(&path, transport.clone());
        let id = save_mailbox(&service.storage, 1);
        service.maintain_prekeys().await.unwrap();
        let all = service
            .storage
            .prekey_ids_for_mailbox(id, &[1; 32])
            .unwrap();
        let opks: Vec<_> = all
            .into_iter()
            .filter(|id| {
                service.storage.get_prekey(id).unwrap().unwrap().key_type
                    == najwa_storage::types::PrekeyType::Opk
            })
            .collect();
        let available: Vec<_> = opks[..40]
            .iter()
            .map(|id| u32::from_be_bytes(*id))
            .collect();
        let grace = najwa_crypto::time::now() as i64 + 14 * 86400;
        // A malformed snapshot must leave the complete pool untouched.
        assert!(service
            .storage
            .reconcile_prekey_inventory(id, &[1; 32], &[available[0], available[0]], grace)
            .is_err());
        assert!(service
            .storage
            .get_prekey(&opks[100])
            .unwrap()
            .unwrap()
            .expires_at
            .is_none());
        service
            .storage
            .reconcile_prekey_inventory(id, &[1; 32], &available, grace)
            .unwrap();
        transport.fail.store(true, Ordering::SeqCst);
        assert!(service.maintain_prekeys().await.is_err());
        let pending = service
            .storage
            .prekey_ids_for_mailbox(id, &[1; 32])
            .unwrap();
        assert_eq!(pending.len(), 361); // 200 active + 160 served + SPK
        drop(service);
        let service = open_service(&path, transport.clone());
        transport.fail.store(false, Ordering::SeqCst);
        service.maintain_prekeys().await.unwrap(); // retry, with no status request
        assert_eq!(
            pending,
            service
                .storage
                .prekey_ids_for_mailbox(id, &[1; 32])
                .unwrap()
        );
        let served = service.storage.get_prekey(&opks[100]).unwrap().unwrap();
        assert_eq!(served.private_key.len(), 32);
        assert_eq!(served.expires_at, Some(grace));
        let uploads = transport.uploads.lock().unwrap();
        let published = uploads.last().unwrap()["bundle"]["one_time_prekeys"]
            .as_array()
            .unwrap();
        assert_eq!(published.len(), 200);
        assert!(published
            .iter()
            .all(|p| p["id"].as_u64().unwrap() != u32::from_be_bytes(opks[100]) as u64));
        assert!(
            service
                .storage
                .reconcile_prekey_inventory(id, &[1; 32], &[u32::from_be_bytes(opks[100])], grace)
                .is_err(),
            "a server cannot revive a retired key"
        );
    }

    #[tokio::test]
    async fn receiving_capabilities_on_one_mailbox_have_disjoint_prekeys() {
        use najwa_protocol::prekey::PrekeyStorage;
        let db = SqliteStorage::open_in_memory(&[6; 32]).unwrap();
        let id = save_mailbox(&db, 1);
        let transport = Arc::new(UploadTransport::default());
        for scope in [1, 2] {
            let mailbox = MailboxConfig::new("mailbox1".into(), [scope; 32], [scope + 10; 32]);
            let storage = SqlitePrekeyStorage::new(&db, id, mailbox.clone()).unwrap();
            let manager = PrekeyManager::new(
                najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[1; 32]),
                storage,
                HttpMailboxClient::new(transport.clone()),
                mailbox,
            )
            .unwrap();
            manager.maintenance().await.unwrap();
        }
        let a = db.prekey_ids_for_mailbox(id, &[1; 32]).unwrap();
        let b = db.prekey_ids_for_mailbox(id, &[2; 32]).unwrap();
        assert_eq!(a.len(), 201);
        assert_eq!(b.len(), 201);
        assert!(a.iter().all(|id| !b.contains(id)));
        let scope = SqlitePrekeyStorage::new(
            &db,
            id,
            MailboxConfig::new("mailbox1".into(), [1; 32], [11; 32]),
        )
        .unwrap();
        for id in b {
            assert!(scope.get_opk_by_id(&id).await.unwrap().is_none());
            assert!(scope.get_spk_by_id(&id).await.unwrap().is_none());
        }
    }
}
