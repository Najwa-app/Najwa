//! Prekey lifecycle manager (S06 §5).
//!
//! Manages generation, rotation, replenishment, upload, and cleanup
//! of signed prekeys (SPK) and one-time prekeys (OPK).

use async_trait::async_trait;
use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;
use najwa_crypto::random::random_bytes;
use najwa_crypto::time::now;
use najwa_crypto::types::PrekeyId;

use super::error::{PrekeyError, Result};
use super::types::{
    OneTimePrekey, PrekeyUploadBundle, SignedPrekey, DEFAULT_OPK_BATCH_SIZE, DEFAULT_OPK_THRESHOLD,
    DEFAULT_SPK_ROTATION_DAYS, SPK_GRACE_PERIOD_SECS,
};
use crate::mailbox::client::MailboxClient;
use crate::mailbox::types::MailboxConfig;

/// Narrow upload boundary lets the application pace prekey publication through
/// cover slots while standalone protocol users retain the mailbox implementation.
#[async_trait]
pub trait PrekeyPublisher: Send + Sync {
    async fn publish(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        bundle: &crate::mailbox::types::PrekeyBundle,
    ) -> crate::mailbox::error::Result<()>;
}
#[async_trait]
impl<M: MailboxClient> PrekeyPublisher for M {
    async fn publish(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        bundle: &crate::mailbox::types::PrekeyBundle,
    ) -> crate::mailbox::error::Result<()> {
        self.upload_prekey_bundle(mailbox, deposit_cap, bundle)
            .await
    }
}

// ---------------------------------------------------------------------------
// Storage trait (S06 §5.3)
// ---------------------------------------------------------------------------

/// Trait abstracting prekey storage operations.
///
/// Implementations live in the storage layer; this trait allows the protocol
/// crate to define lifecycle logic without depending on concrete storage.
#[async_trait]
pub trait PrekeyStorage: Send + Sync {
    /// Atomically persist a new SPK/OPKs and retire previous current SPKs.
    /// IDs must be insert-only: collisions must roll back the entire batch.
    async fn commit_bundle(
        &self,
        spk: Option<&SignedPrekey>,
        opks: &[OneTimePrekey],
        grace_end: u64,
    ) -> std::result::Result<(), String>;
    async fn list_unused_opks(&self) -> std::result::Result<Vec<StoredOpk>, String>;

    /// Save (insert or update) a signed prekey.
    async fn save_signed_prekey(&self, spk: &SignedPrekey) -> std::result::Result<(), String>;

    /// Get the current (non-expired) signed prekey.
    async fn get_current_spk(&self) -> std::result::Result<Option<StoredSpk>, String>;

    /// Get a signed prekey by ID.
    async fn get_spk_by_id(&self, id: &PrekeyId) -> std::result::Result<Option<StoredSpk>, String>;

    /// Mark a signed prekey as expiring (set `expires_at`).
    async fn expire_spk(&self, id: &PrekeyId, expires_at: u64) -> std::result::Result<(), String>;

    /// Delete signed prekeys whose `expires_at` is before the given timestamp.
    async fn delete_expired_spks(&self, before: u64) -> std::result::Result<u32, String>;

    /// Save a batch of one-time prekeys.
    async fn save_one_time_prekeys(
        &self,
        opks: &[OneTimePrekey],
    ) -> std::result::Result<(), String>;

    /// Count unused OPKs (optionally for a specific mailbox).
    async fn count_unused_opks(&self, mailbox_id: Option<i64>) -> std::result::Result<u32, String>;

    /// Mark an OPK as used.
    async fn mark_opk_used(&self, id: &PrekeyId) -> std::result::Result<(), String>;

    /// Get an unused OPK by ID (for X3DH responder).
    async fn get_opk_by_id(&self, id: &PrekeyId) -> std::result::Result<Option<StoredOpk>, String>;

    /// Delete used OPKs older than a given timestamp.
    async fn delete_used_opks(&self, before: u64) -> std::result::Result<u32, String>;

    /// List all mailbox configurations (for bundle upload).
    async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String>;
}

/// Stored signed prekey record. Private material is erased on drop.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct StoredSpk {
    pub id: PrekeyId,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    pub signature: [u8; 64],
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

/// Stored one-time prekey record.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct StoredOpk {
    pub id: PrekeyId,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
    pub created_at: u64,
    pub used: bool,
    pub mailbox_id: Option<i64>,
}

// ---------------------------------------------------------------------------
// PrekeyManager (S06 §5.2)
// ---------------------------------------------------------------------------

/// Manages the prekey lifecycle: generation, rotation, replenishment,
/// upload, and cleanup.
pub struct PrekeyManager<S: PrekeyStorage, M: PrekeyPublisher> {
    /// The real identity, retained locally; the derived key signs each mailbox bundle.
    identity_key: Ed25519KeyPair,
    signing_key: Ed25519KeyPair,
    mailbox: MailboxConfig,
    /// Storage backend.
    storage: S,
    /// Mailbox client for uploading bundles.
    mailbox_client: M,
}

impl<S: PrekeyStorage, M: PrekeyPublisher> PrekeyManager<S, M> {
    /// Create a new prekey manager.
    /// The storage backend must be scoped to this one mailbox.
    pub fn new(
        identity_key: Ed25519KeyPair,
        storage: S,
        mailbox_client: M,
        mailbox: MailboxConfig,
    ) -> Result<Self> {
        let seed = zeroize::Zeroizing::new(identity_key.private().to_bytes());
        let signing_key =
            crate::contact::mailbox_key::derive_mailbox_signing_key(&seed, &mailbox.onion_address)
                .map_err(|e| PrekeyError::KeyGenError(e.to_string()))?;
        Ok(Self {
            identity_key,
            signing_key,
            mailbox,
            storage,
            mailbox_client,
        })
    }

    // -----------------------------------------------------------------------
    // S06 §5.6 step 4 — Initial bundle generation
    // -----------------------------------------------------------------------

    /// Generate an initial prekey bundle when the scope has no SPK (S06 §5.6 step 4).
    ///
    /// 1. Generate a signed prekey (SPK)
    /// 2. Generate a batch of one-time prekeys (OPK)
    /// 3. Store both locally
    /// 4. Return the upload bundle
    pub async fn generate_initial_bundle(&self) -> Result<PrekeyUploadBundle> {
        let spk = self.generate_signed_prekey()?;
        let opks = self.generate_one_time_prekeys(DEFAULT_OPK_BATCH_SIZE)?;

        self.storage
            .commit_bundle(Some(&spk), &opks, now() + SPK_GRACE_PERIOD_SECS)
            .await
            .map_err(PrekeyError::StorageError)?;

        // Build upload bundle
        Ok(self.build_upload_bundle(&spk, &opks))
    }

    // -----------------------------------------------------------------------
    // S06 §5.4 — SPK rotation with grace period
    // -----------------------------------------------------------------------

    /// Rotate the signed prekey (S06 §5.4).
    ///
    /// 1. Generate a new SPK
    /// 2. Mark the old SPK as expiring (now + 14 days grace period)
    /// 3. Store new SPK
    /// 4. Upload new bundle to all mailboxes
    pub async fn rotate_signed_prekey(&self) -> Result<()> {
        let new_spk = self.generate_signed_prekey()?;
        self.storage
            .commit_bundle(Some(&new_spk), &[], now() + SPK_GRACE_PERIOD_SECS)
            .await
            .map_err(PrekeyError::StorageError)?;

        // Upload to all mailboxes
        self.upload_bundle_to_all_mailboxes().await?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // S06 §5.5 — OPK replenishment
    // -----------------------------------------------------------------------

    /// Replenish OPKs if the unused count is below the threshold (S06 §5.5).
    ///
    /// Returns the number of new OPKs generated (0 if no replenishment needed).
    pub async fn replenish_if_needed(&self, threshold: u32) -> Result<u32> {
        let current = self
            .storage
            .count_unused_opks(None)
            .await
            .map_err(PrekeyError::StorageError)?;

        if current < threshold {
            let needed = DEFAULT_OPK_BATCH_SIZE.saturating_sub(current);
            if needed == 0 {
                return Ok(0);
            }

            let new_opks = self.generate_one_time_prekeys(needed)?;
            self.storage
                .commit_bundle(None, &new_opks, now() + SPK_GRACE_PERIOD_SECS)
                .await
                .map_err(PrekeyError::StorageError)?;

            // Upload fresh bundle
            self.upload_bundle_to_all_mailboxes().await?;

            return Ok(needed);
        }
        Ok(0)
    }

    // -----------------------------------------------------------------------
    // S06 §2.3 step 10 — OPK consumption tracking
    // -----------------------------------------------------------------------

    /// Mark an OPK as used (called when processing an X3DH initial message).
    pub async fn mark_opk_used(&self, id: &PrekeyId) -> Result<()> {
        self.storage
            .mark_opk_used(id)
            .await
            .map_err(PrekeyError::StorageError)
    }

    /// Retrieve an OPK by ID (for X3DH responder).
    pub async fn get_opk(&self, id: &PrekeyId) -> Result<Option<StoredOpk>> {
        self.storage
            .get_opk_by_id(id)
            .await
            .map(|key| key.filter(|key| !key.used))
            .map_err(PrekeyError::StorageError)
    }

    /// Retrieve the current SPK (for handshake payload construction).
    pub async fn get_current_spk(&self) -> Result<Option<StoredSpk>> {
        self.storage
            .get_current_spk()
            .await
            .map_err(PrekeyError::StorageError)
    }

    /// Retrieve a SPK by ID (for X3DH responder, may be old but within grace).
    pub async fn get_spk(&self, id: &PrekeyId) -> Result<Option<StoredSpk>> {
        self.storage
            .get_spk_by_id(id)
            .await
            .map(|key| key.filter(|key| key.expires_at.is_none_or(|expires| expires > now())))
            .map_err(PrekeyError::StorageError)
    }

    // -----------------------------------------------------------------------
    // S06 §5.6 — Background maintenance
    // -----------------------------------------------------------------------

    /// Run background maintenance (S06 §5.6).
    ///
    /// 1. Delete expired SPKs past their grace period
    /// 2. Delete consumed OPKs older than 7 days
    /// 3. Check if SPK rotation is needed (≥ 7 days old, S06 §5.6)
    /// 4. Replenish OPKs if below threshold
    pub async fn maintenance(&self) -> Result<()> {
        // 1. Cleanup expired prekeys
        self.cleanup_expired_prekeys().await?;

        // 2. Check SPK rotation
        let spk = self
            .storage
            .get_current_spk()
            .await
            .map_err(PrekeyError::StorageError)?;
        if let Some(spk) = spk {
            // S06 §5.6: rotate every 7 days. Compare in seconds (not floored
            // whole days) so the first rotation fires at 7 days, not day 8.
            let age_secs = now().saturating_sub(spk.created_at);
            if age_secs >= DEFAULT_SPK_ROTATION_DAYS * 86400 {
                self.rotate_signed_prekey().await?;
            }
        } else {
            // No current SPK — generate one
            self.generate_initial_bundle().await?;
            self.upload_bundle_to_all_mailboxes().await?;
        }

        // 3. Replenish OPKs
        self.replenish_if_needed(DEFAULT_OPK_THRESHOLD).await?;
        // Also retry a previous failed upload even when the local pool is full.
        self.upload_bundle_to_all_mailboxes().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // S06 §5.6 step 3 — Expired prekey cleanup
    // -----------------------------------------------------------------------

    /// Delete SPKs whose grace period has passed and used OPKs older than 7 days.
    async fn cleanup_expired_prekeys(&self) -> Result<()> {
        let ts = now();

        // Delete SPKs past grace period
        self.storage
            .delete_expired_spks(ts)
            .await
            .map_err(PrekeyError::StorageError)?;

        // Delete used OPKs older than 7 days
        let seven_days_ago = ts.saturating_sub(7 * 24 * 3600);
        self.storage
            .delete_used_opks(seven_days_ago)
            .await
            .map_err(PrekeyError::StorageError)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // S06 §5.2 — Bundle upload to this receive queue
    // -----------------------------------------------------------------------

    /// Upload the current bundle to this manager's single mailbox scope.
    async fn upload_bundle_to_all_mailboxes(&self) -> Result<()> {
        let spk = self
            .storage
            .get_current_spk()
            .await
            .map_err(PrekeyError::StorageError)?
            .ok_or(PrekeyError::NoCurrentSpk)?;

        let upload_bundle = self.build_upload_bundle_from_stored(&spk).await?;
        self.mailbox_client
            .publish(
                &self.mailbox,
                &self.mailbox.deposit_capability,
                &upload_bundle.to_mailbox_bundle(),
            )
            .await
            .map_err(|e| PrekeyError::UploadError(e.to_string()))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Generate a new signed prekey (S06 §5.4).
    fn generate_signed_prekey(&self) -> Result<SignedPrekey> {
        let id: PrekeyId = random_bytes::<4>();
        let keypair = X25519KeyPair::generate(&mut rand::rngs::OsRng);
        let created_at = now();
        // S06 §4.2: sign "najwa/v1/spk/" || spk_pub || spk_id || spk_timestamp.
        let signature = self
            .signing_key
            .sign(&crate::x3dh::types::spk_signature_message(
                &keypair.public().to_bytes(),
                &id,
                created_at,
            ));

        Ok(SignedPrekey {
            id,
            keypair,
            signature,
            created_at,
            expires_at: None,
        })
    }

    /// Generate a batch of one-time prekeys (S06 §5.5).
    fn generate_one_time_prekeys(&self, count: u32) -> Result<Vec<OneTimePrekey>> {
        let mut rng = rand::rngs::OsRng;
        let ts = now();
        let mut ids = std::collections::HashSet::new();
        (0..count)
            .map(|_| {
                let id = loop {
                    let id = random_bytes::<4>();
                    if ids.insert(id) {
                        break id;
                    }
                };
                Ok(OneTimePrekey {
                    id,
                    keypair: X25519KeyPair::generate(&mut rng),
                    created_at: ts,
                    used: false,
                    mailbox_id: None,
                })
            })
            .collect()
    }

    /// Build an upload bundle from freshly generated keys.
    fn build_upload_bundle(
        &self,
        spk: &SignedPrekey,
        opks: &[OneTimePrekey],
    ) -> PrekeyUploadBundle {
        let opk_ids: Vec<u32> = opks.iter().map(|o| u32::from_be_bytes(o.id)).collect();
        let manifest = crate::x3dh::types::build_wire_manifest(
            &self.signing_key,
            &spk.id,
            &opk_ids,
            spk.created_at,
        );
        PrekeyUploadBundle {
            mailbox_ik_pub: self.signing_key.public().clone(),
            identity_key: self.identity_key.public().clone(),
            signed_prekey: spk.keypair.public().clone(),
            signed_prekey_id: spk.id,
            signed_prekey_signature: spk.signature.clone(),
            spk_timestamp: spk.created_at,
            one_time_prekeys: opks
                .iter()
                .map(|o| (o.keypair.public().clone(), o.id))
                .collect(),
            manifest: Some(manifest),
        }
    }

    /// Build an upload bundle from stored SPK data + current unused OPKs.
    async fn build_upload_bundle_from_stored(&self, spk: &StoredSpk) -> Result<PrekeyUploadBundle> {
        use najwa_crypto::keys::ed25519::Ed25519Signature;

        let sig = Ed25519Signature::from_bytes(&spk.signature)
            .map_err(|e| PrekeyError::SignatureError(e.to_string()))?;

        let opks = self
            .storage
            .list_unused_opks()
            .await
            .map_err(PrekeyError::StorageError)?;
        let ids: Vec<u32> = opks.iter().map(|o| u32::from_be_bytes(o.id)).collect();
        Ok(PrekeyUploadBundle {
            mailbox_ik_pub: self.signing_key.public().clone(),
            identity_key: self.identity_key.public().clone(),
            signed_prekey: najwa_crypto::keys::x25519::X25519Public::from_bytes(spk.public_key),
            signed_prekey_id: spk.id,
            signed_prekey_signature: sig,
            spk_timestamp: spk.created_at,
            one_time_prekeys: opks
                .iter()
                .map(|o| {
                    (
                        najwa_crypto::keys::x25519::X25519Public::from_bytes(o.public_key),
                        o.id,
                    )
                })
                .collect(),
            manifest: Some(crate::x3dh::types::build_wire_manifest(
                &self.signing_key,
                &spk.id,
                &ids,
                now(),
            )),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;
    use std::sync::Mutex;

    // -- Mock storage -------------------------------------------------------

    struct MockStorage {
        spks: Mutex<Vec<StoredSpk>>,
        opks: Mutex<Vec<StoredOpk>>,
        mailboxes: Mutex<Vec<MailboxConfig>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                spks: Mutex::new(Vec::new()),
                opks: Mutex::new(Vec::new()),
                mailboxes: Mutex::new(vec![MailboxConfig::new(
                    "test_mailbox".to_string(),
                    [0xAA; 32],
                    [0xBB; 32],
                )]),
            }
        }
    }

    #[async_trait]
    impl PrekeyStorage for MockStorage {
        async fn commit_bundle(
            &self,
            spk: Option<&SignedPrekey>,
            opks: &[OneTimePrekey],
            grace_end: u64,
        ) -> std::result::Result<(), String> {
            let mut stored_spks = self.spks.lock().unwrap();
            let mut stored_opks = self.opks.lock().unwrap();
            let mut ids: std::collections::HashSet<_> = stored_spks
                .iter()
                .map(|s| s.id)
                .chain(stored_opks.iter().map(|o| o.id))
                .collect();
            if spk.is_some_and(|s| !ids.insert(s.id)) || opks.iter().any(|o| !ids.insert(o.id)) {
                return Err("prekey ID collision".into());
            }
            if let Some(spk) = spk {
                for old in stored_spks.iter_mut().filter(|s| s.expires_at.is_none()) {
                    old.expires_at = Some(grace_end);
                }
                stored_spks.push(StoredSpk {
                    id: spk.id,
                    public_key: spk.keypair.public().to_bytes(),
                    private_key: spk.keypair.private().to_bytes(),
                    signature: spk.signature.to_bytes(),
                    created_at: spk.created_at,
                    expires_at: None,
                });
            }
            for opk in opks {
                stored_opks.push(StoredOpk {
                    id: opk.id,
                    public_key: opk.keypair.public().to_bytes(),
                    private_key: opk.keypair.private().to_bytes(),
                    created_at: opk.created_at,
                    used: false,
                    mailbox_id: opk.mailbox_id,
                });
            }
            Ok(())
        }
        async fn list_unused_opks(&self) -> std::result::Result<Vec<StoredOpk>, String> {
            Ok(self
                .opks
                .lock()
                .unwrap()
                .iter()
                .filter(|o| !o.used)
                .cloned()
                .collect())
        }

        async fn save_signed_prekey(&self, spk: &SignedPrekey) -> std::result::Result<(), String> {
            let mut spks = self.spks.lock().unwrap();
            // Remove existing with same ID
            spks.retain(|s| s.id != spk.id);
            spks.push(StoredSpk {
                id: spk.id,
                public_key: spk.keypair.public().to_bytes(),
                private_key: spk.keypair.private().to_bytes(),
                signature: spk.signature.to_bytes(),
                created_at: spk.created_at,
                expires_at: spk.expires_at,
            });
            Ok(())
        }

        async fn get_current_spk(&self) -> std::result::Result<Option<StoredSpk>, String> {
            let spks = self.spks.lock().unwrap();
            Ok(spks.iter().find(|s| s.expires_at.is_none()).cloned())
        }

        async fn get_spk_by_id(
            &self,
            id: &PrekeyId,
        ) -> std::result::Result<Option<StoredSpk>, String> {
            let spks = self.spks.lock().unwrap();
            Ok(spks.iter().find(|s| &s.id == id).cloned())
        }

        async fn expire_spk(
            &self,
            id: &PrekeyId,
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            let mut spks = self.spks.lock().unwrap();
            if let Some(spk) = spks.iter_mut().find(|s| &s.id == id) {
                spk.expires_at = Some(expires_at);
            }
            Ok(())
        }

        async fn delete_expired_spks(&self, before: u64) -> std::result::Result<u32, String> {
            let mut spks = self.spks.lock().unwrap();
            let before_len = spks.len();
            spks.retain(|s| match s.expires_at {
                Some(exp) => exp >= before,
                None => true,
            });
            Ok((before_len - spks.len()) as u32)
        }

        async fn save_one_time_prekeys(
            &self,
            opks: &[OneTimePrekey],
        ) -> std::result::Result<(), String> {
            let mut stored = self.opks.lock().unwrap();
            for opk in opks {
                stored.push(StoredOpk {
                    id: opk.id,
                    public_key: opk.keypair.public().to_bytes(),
                    private_key: opk.keypair.private().to_bytes(),
                    created_at: opk.created_at,
                    used: opk.used,
                    mailbox_id: opk.mailbox_id,
                });
            }
            Ok(())
        }

        async fn count_unused_opks(
            &self,
            _mailbox_id: Option<i64>,
        ) -> std::result::Result<u32, String> {
            let opks = self.opks.lock().unwrap();
            Ok(opks.iter().filter(|o| !o.used).count() as u32)
        }

        async fn mark_opk_used(&self, id: &PrekeyId) -> std::result::Result<(), String> {
            let mut opks = self.opks.lock().unwrap();
            if let Some(opk) = opks.iter_mut().find(|o| &o.id == id) {
                opk.used = true;
            }
            Ok(())
        }

        async fn get_opk_by_id(
            &self,
            id: &PrekeyId,
        ) -> std::result::Result<Option<StoredOpk>, String> {
            let opks = self.opks.lock().unwrap();
            Ok(opks.iter().find(|o| &o.id == id).cloned())
        }

        async fn delete_used_opks(&self, before: u64) -> std::result::Result<u32, String> {
            let mut opks = self.opks.lock().unwrap();
            let before_len = opks.len();
            opks.retain(|o| !(o.used && o.created_at < before));
            Ok((before_len - opks.len()) as u32)
        }

        async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String> {
            Ok(self.mailboxes.lock().unwrap().clone())
        }
    }

    // -- Mock mailbox client ------------------------------------------------

    struct MockMailboxClient {
        uploads: Mutex<Vec<(String, crate::mailbox::types::PrekeyBundle)>>,
        fail_next: std::sync::atomic::AtomicBool,
    }

    impl MockMailboxClient {
        fn new() -> Self {
            Self {
                uploads: Mutex::new(Vec::new()),
                fail_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn upload_count(&self) -> usize {
            self.uploads.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl MailboxClient for MockMailboxClient {
        async fn register_capability(
            &self,
            _mailbox: &MailboxConfig,
            _settings: &crate::mailbox::types::CapabilitySettings,
            _pow: Option<&crate::mailbox::types::PowSolution>,
        ) -> crate::mailbox::error::Result<()> {
            Ok(())
        }

        async fn get_challenge(
            &self,
            _mailbox: &MailboxConfig,
            _capability_hint: &[u8; 8],
        ) -> crate::mailbox::error::Result<crate::mailbox::types::PowChallenge> {
            Ok(crate::mailbox::types::PowChallenge {
                challenge: vec![0u8; 32],
                difficulty: 1,
                algorithm: "sha256-leading-zeros".to_string(),
                expires_at: u64::MAX,
            })
        }

        async fn deposit(
            &self,
            _mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            _blob: &[u8],
            _pow: Option<&crate::mailbox::types::PowSolution>,
        ) -> crate::mailbox::error::Result<crate::mailbox::types::DepositResult> {
            Ok(crate::mailbox::types::DepositResult {
                accepted: true,
                message_id: Some("test".to_string()),
            })
        }

        async fn fetch(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
            _since_id: Option<&str>,
            _limit: u32,
        ) -> crate::mailbox::error::Result<Vec<crate::mailbox::types::MailboxMessage>> {
            Ok(Vec::new())
        }

        async fn upload_prekey_bundle(
            &self,
            mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            bundle: &crate::mailbox::types::PrekeyBundle,
        ) -> crate::mailbox::error::Result<()> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(crate::mailbox::error::MailboxError::ServerError(503));
            }
            let mut uploads = self.uploads.lock().unwrap();
            uploads.push((mailbox.onion_address.clone(), bundle.clone()));
            Ok(())
        }

        async fn fetch_prekey_bundle(
            &self,
            _mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            _contact_pseudonym: &[u8; 32],
        ) -> crate::mailbox::error::Result<crate::mailbox::types::PrekeyBundle> {
            Ok(crate::mailbox::types::PrekeyBundle {
                identity_key: [0u8; 32],
                signed_prekey: [0u8; 32],
                signed_prekey_id: 0,
                signed_prekey_signature: vec![0u8; 64],
                signed_prekey_timestamp: 0,
                one_time_prekeys: Vec::new(),
                manifest: None,
            })
        }

        async fn get_status(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
        ) -> crate::mailbox::error::Result<crate::mailbox::types::CapabilityStatus> {
            Ok(crate::mailbox::types::CapabilityStatus {
                messages_stored: 0,
                quota_remaining: 1000,
                oldest_message_age: 0,
                prekey_count: 50,
                prekey_ids: (0..50).collect(),
            })
        }

        async fn deactivate_capability(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
        ) -> crate::mailbox::error::Result<()> {
            Ok(())
        }

        async fn acknowledge(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
            _message_ids: &[String],
        ) -> crate::mailbox::error::Result<()> {
            Ok(())
        }
    }

    // -- Helper -------------------------------------------------------------

    fn make_manager() -> PrekeyManager<MockStorage, MockMailboxClient> {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        PrekeyManager::new(
            ik,
            MockStorage::new(),
            MockMailboxClient::new(),
            MailboxConfig::new("test_mailbox".into(), [0xAA; 32], [0xBB; 32]),
        )
        .unwrap()
    }

    // -- Tests (S06 §5.6) Bundle generation ---------------------------------

    #[tokio::test]
    async fn initial_bundle_generates_spk_and_opks() {
        let mgr = make_manager();
        let bundle = mgr.generate_initial_bundle().await.unwrap();

        assert_eq!(bundle.signed_prekey_id.len(), 4);
        assert_eq!(
            bundle.one_time_prekeys.len(),
            DEFAULT_OPK_BATCH_SIZE as usize
        );

        // SPK stored
        let spk = mgr.storage.get_current_spk().await.unwrap();
        assert!(spk.is_some());
        let spk = spk.unwrap();
        assert!(spk.expires_at.is_none()); // current SPK, not expired

        // OPKs stored
        let opk_count = mgr.storage.count_unused_opks(None).await.unwrap();
        assert_eq!(opk_count, DEFAULT_OPK_BATCH_SIZE);
    }

    #[tokio::test]
    async fn bundle_spk_signature_is_valid() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mgr = PrekeyManager::new(
            ik,
            MockStorage::new(),
            MockMailboxClient::new(),
            MailboxConfig::new("test_mailbox".into(), [0xAA; 32], [0xBB; 32]),
        )
        .unwrap();
        let bundle = mgr.generate_initial_bundle().await.unwrap();

        // Verify SPK signature per S06 §4.2 (domain || spk_pub || spk_id || spk_ts).
        let ik_pub = mgr.signing_key.public();
        let msg = crate::x3dh::types::spk_signature_message(
            &bundle.signed_prekey.to_bytes(),
            &bundle.signed_prekey_id,
            bundle.spk_timestamp,
        );
        assert!(ik_pub.verify(&msg, &bundle.signed_prekey_signature).is_ok());
    }

    #[tokio::test]
    async fn bundle_opk_ids_are_unique() {
        let mgr = make_manager();
        let bundle = mgr.generate_initial_bundle().await.unwrap();

        let mut ids: Vec<PrekeyId> = bundle.one_time_prekeys.iter().map(|(_, id)| *id).collect();
        let before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), before, "OPK IDs should be unique");
    }

    #[tokio::test]
    async fn bundle_converts_to_mailbox_format() {
        let mgr = make_manager();
        let bundle = mgr.generate_initial_bundle().await.unwrap();
        let wire = bundle.to_mailbox_bundle();

        assert_eq!(wire.identity_key, mgr.signing_key.public().to_bytes());
        assert_eq!(wire.signed_prekey, bundle.signed_prekey.to_bytes());
        assert_eq!(wire.one_time_prekeys.len(), DEFAULT_OPK_BATCH_SIZE as usize);
    }

    // -- Tests (S06 §5.4) SPK rotation lifecycle ----------------------------

    #[tokio::test]
    async fn rotate_spk_creates_new_and_expires_old() {
        let mgr = make_manager();

        // Generate initial bundle
        mgr.generate_initial_bundle().await.unwrap();
        let old_spk = mgr.storage.get_current_spk().await.unwrap().unwrap();
        let old_id = old_spk.id;

        // Rotate
        mgr.rotate_signed_prekey().await.unwrap();

        // New current SPK exists and is different
        let new_spk = mgr.storage.get_current_spk().await.unwrap().unwrap();
        assert_ne!(new_spk.id, old_id);

        // Old SPK should have expires_at set
        let old = mgr.storage.get_spk_by_id(&old_id).await.unwrap().unwrap();
        assert!(old.expires_at.is_some());
        assert!(old.expires_at.unwrap() > now());
    }

    #[tokio::test]
    async fn rotate_uploads_to_mailboxes() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        mgr.rotate_signed_prekey().await.unwrap();

        assert!(mgr.mailbox_client.upload_count() > 0);
    }

    // -- Tests (S06 §5.5) OPK replenishment ---------------------------------

    #[tokio::test]
    async fn replenish_when_below_threshold() {
        let mgr = make_manager();

        // Start with no OPKs, need initial SPK for upload
        mgr.generate_initial_bundle().await.unwrap();

        // Mark all OPKs as used
        {
            let mut opks = mgr.storage.opks.lock().unwrap();
            for opk in opks.iter_mut() {
                opk.used = true;
            }
        }

        // Now count is 0, below threshold
        let generated = mgr
            .replenish_if_needed(DEFAULT_OPK_THRESHOLD)
            .await
            .unwrap();
        assert_eq!(generated, DEFAULT_OPK_BATCH_SIZE);

        let count = mgr.storage.count_unused_opks(None).await.unwrap();
        assert_eq!(count, DEFAULT_OPK_BATCH_SIZE);
    }

    #[tokio::test]
    async fn no_replenish_when_above_threshold() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        // All 100 OPKs are unused — above threshold
        let generated = mgr
            .replenish_if_needed(DEFAULT_OPK_THRESHOLD)
            .await
            .unwrap();
        assert_eq!(generated, 0);
    }

    // -- OPK consumption tracking (S06 §2.3) ---------------------------------

    #[tokio::test]
    async fn mark_opk_as_used() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        let first_opk_id = {
            let opks = mgr.storage.opks.lock().unwrap();
            opks[0].id
        };

        mgr.mark_opk_used(&first_opk_id).await.unwrap();

        assert!(mgr.get_opk(&first_opk_id).await.unwrap().is_none());
        assert!(
            mgr.storage
                .get_opk_by_id(&first_opk_id)
                .await
                .unwrap()
                .unwrap()
                .used
        );
    }

    // -- Maintenance (S06 §5.6) ----------------------------------------------

    #[tokio::test]
    async fn maintenance_with_current_spk_does_not_rotate() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        // SPK is fresh — maintenance should not rotate
        let spk_before = mgr.storage.get_current_spk().await.unwrap().unwrap();
        mgr.maintenance().await.unwrap();
        let spk_after = mgr.storage.get_current_spk().await.unwrap().unwrap();
        assert_eq!(spk_before.id, spk_after.id);
    }

    #[tokio::test]
    async fn maintenance_rotates_spk_at_7_days() {
        // S06 §5.6: rotation MUST fire at 7 days. The old floored `age_days > 7`
        // delayed the first rotation to day 8.
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();
        let old_id = mgr.storage.get_current_spk().await.unwrap().unwrap().id;

        // Backdate the current SPK to exactly the 7-day boundary.
        {
            let mut spks = mgr.storage.spks.lock().unwrap();
            for s in spks.iter_mut() {
                s.created_at = now().saturating_sub(DEFAULT_SPK_ROTATION_DAYS * 86400);
            }
        }

        mgr.maintenance().await.unwrap();

        let after = mgr.storage.get_current_spk().await.unwrap().unwrap();
        assert_ne!(
            after.id, old_id,
            "SPK must rotate at exactly 7 days (S06 §5.6)"
        );
    }

    // -- Expired prekey cleanup (S06 §5.6) -----------------------------------

    #[tokio::test]
    async fn cleanup_removes_expired_spks() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        // Manually set old SPK as expired in the past
        let old_id = mgr.storage.get_current_spk().await.unwrap().unwrap().id;
        mgr.storage.expire_spk(&old_id, 1000).await.unwrap(); // expired long ago

        // Generate a new current SPK
        let new_spk = mgr.generate_signed_prekey().unwrap();
        mgr.storage.save_signed_prekey(&new_spk).await.unwrap();

        // Cleanup should remove the expired one
        mgr.cleanup_expired_prekeys().await.unwrap();

        let removed = mgr.storage.get_spk_by_id(&old_id).await.unwrap();
        assert!(removed.is_none(), "expired SPK should have been deleted");
    }

    #[tokio::test]
    async fn cleanup_removes_used_opks() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();

        let first_id = {
            let opks = mgr.storage.opks.lock().unwrap();
            opks[0].id
        };

        // Mark as used and backdate
        {
            let mut opks = mgr.storage.opks.lock().unwrap();
            if let Some(o) = opks.iter_mut().find(|o| o.id == first_id) {
                o.used = true;
                o.created_at = 1000; // very old
            }
        }

        mgr.cleanup_expired_prekeys().await.unwrap();

        let opk = mgr.storage.get_opk_by_id(&first_id).await.unwrap();
        assert!(opk.is_none(), "used old OPK should have been deleted");
    }
    #[tokio::test]
    async fn replenishment_upload_contains_fresh_keys_and_manifest() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();
        for opk in mgr.storage.opks.lock().unwrap().iter_mut() {
            opk.used = true;
        }
        assert_eq!(mgr.replenish_if_needed(50).await.unwrap(), 200);
        let uploads = mgr.mailbox_client.uploads.lock().unwrap();
        let bundle = &uploads.last().unwrap().1;
        assert_eq!(bundle.one_time_prekeys.len(), 200);
        crate::x3dh::initiator::check_bundle_manifest(bundle, mgr.signing_key.public()).unwrap();
        assert_ne!(bundle.identity_key, mgr.identity_key.public().to_bytes());
    }

    #[tokio::test]
    async fn maintenance_retries_failed_upload_without_rotating_again() {
        let mgr = make_manager();
        mgr.generate_initial_bundle().await.unwrap();
        mgr.mailbox_client
            .fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(mgr.rotate_signed_prekey().await.is_err());
        let current = mgr.storage.get_current_spk().await.unwrap().unwrap().id;
        mgr.maintenance().await.unwrap();
        assert_eq!(
            mgr.storage.get_current_spk().await.unwrap().unwrap().id,
            current
        );
        assert!(mgr.mailbox_client.upload_count() > 0);
    }

    #[tokio::test]
    async fn sqlite_pools_are_independent_and_rotation_collision_rolls_back() {
        use super::super::sqlite::SqlitePrekeyStorage;
        use najwa_storage::{database::SqliteStorage, types::NewMailbox};
        let db = std::sync::Arc::new(SqliteStorage::open_in_memory(&[19; 32]).unwrap());
        let mut managers = Vec::new();
        for i in 1..=2u8 {
            let mailbox = MailboxConfig::new(format!("mailbox{i}"), [i; 32], [i + 10; 32]);
            let id = db
                .save_mailbox(&NewMailbox::with_cover_caps(
                    mailbox.onion_address.clone(),
                    mailbox.fetch_capability.to_vec(),
                    mailbox.deposit_capability.to_vec(),
                    1,
                    now() as i64,
                ))
                .unwrap();
            let storage = SqlitePrekeyStorage::new(&db, id, mailbox.clone()).unwrap();
            let mgr = PrekeyManager::new(
                Ed25519KeyPair::from_seed(&[3; 32]),
                storage,
                MockMailboxClient::new(),
                mailbox,
            )
            .unwrap();
            mgr.generate_initial_bundle().await.unwrap();
            managers.push(mgr);
        }
        let a = managers[0]
            .storage
            .get_current_spk()
            .await
            .unwrap()
            .unwrap();
        let b = managers[1]
            .storage
            .get_current_spk()
            .await
            .unwrap()
            .unwrap();
        assert_ne!(a.public_key, b.public_key);
        assert_ne!(
            managers[0].signing_key.public().to_bytes(),
            managers[1].signing_key.public().to_bytes()
        );
        assert_eq!(
            managers[0].storage.count_unused_opks(None).await.unwrap(),
            200
        );
        assert!(managers[0]
            .storage
            .get_spk_by_id(&b.id)
            .await
            .unwrap()
            .is_none());
        let mut collision = managers[0].generate_signed_prekey().unwrap();
        collision.id = b.id;
        assert!(managers[0]
            .storage
            .commit_bundle(Some(&collision), &[], now() + 100)
            .await
            .is_err());
        assert_eq!(
            managers[0]
                .storage
                .get_current_spk()
                .await
                .unwrap()
                .unwrap()
                .id,
            a.id
        );
        managers[0].rotate_signed_prekey().await.unwrap();
        assert!(managers[0]
            .storage
            .get_spk_by_id(&a.id)
            .await
            .unwrap()
            .unwrap()
            .expires_at
            .is_some());
        assert_eq!(
            managers[1]
                .storage
                .get_current_spk()
                .await
                .unwrap()
                .unwrap()
                .id,
            b.id
        );
    }
}
