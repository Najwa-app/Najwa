//! Production adapter. Each instance owns one mailbox's independent key pool.
use super::{OneTimePrekey, PrekeyStorage, SignedPrekey, StoredOpk, StoredSpk};
use crate::mailbox::types::MailboxConfig;
use async_trait::async_trait;
use najwa_storage::{
    database::SqliteStorage,
    types::{Prekey, PrekeyType},
};

type Result<T> = std::result::Result<T, String>;
pub struct SqlitePrekeyStorage<'a> {
    db: &'a SqliteStorage,
    mailbox_id: i64,
    mailbox: MailboxConfig,
}
impl<'a> SqlitePrekeyStorage<'a> {
    pub fn new(db: &'a SqliteStorage, mailbox_id: i64, mailbox: MailboxConfig) -> Result<Self> {
        let stored = db
            .get_mailbox(mailbox_id)
            .map_err(|e| e.to_string())?
            .ok_or("mailbox not found")?;
        if stored.onion_address != mailbox.onion_address {
            return Err("mailbox scope mismatch".into());
        }
        Ok(Self {
            db,
            mailbox_id,
            mailbox,
        })
    }
    fn get(&self, id: &[u8; 4], kind: PrekeyType) -> Result<Option<Prekey>> {
        Ok(self
            .db
            .get_prekey(id)
            .map_err(|e| e.to_string())?
            .filter(|p| {
                p.mailbox_id == Some(self.mailbox_id)
                    && p.key_type == kind
                    && self
                        .db
                        .prekey_in_scope(id, &self.mailbox.fetch_capability)
                        .unwrap_or(false)
            }))
    }
    fn keys(&self) -> Result<Vec<Prekey>> {
        self.db
            .prekey_ids_for_mailbox(self.mailbox_id, &self.mailbox.fetch_capability)
            .map_err(|e| e.to_string())?
            .iter()
            .filter_map(|id| self.db.get_prekey(id).transpose())
            .map(|p| p.map_err(|e| e.to_string()))
            .collect()
    }
}
fn spk_record(p: Prekey) -> Result<StoredSpk> {
    Ok(StoredSpk {
        id: p.key_id,
        public_key: p
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "bad public key")?,
        private_key: p
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| "bad private key")?,
        signature: p
            .signature
            .as_deref()
            .ok_or("missing signature")?
            .try_into()
            .map_err(|_| "bad signature")?,
        created_at: p.created_at as u64,
        expires_at: p.expires_at.map(|t| t as u64),
    })
}
fn opk_record(p: Prekey) -> Result<StoredOpk> {
    Ok(StoredOpk {
        id: p.key_id,
        public_key: p
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "bad public key")?,
        private_key: p
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| "bad private key")?,
        created_at: p.created_at as u64,
        used: p.used,
        mailbox_id: p.mailbox_id,
    })
}
fn spk_to_row(p: &SignedPrekey) -> Prekey {
    Prekey {
        key_id: p.id,
        key_type: PrekeyType::Spk,
        private_key: p.keypair.private().to_bytes().to_vec(),
        public_key: p.keypair.public().to_bytes().to_vec(),
        signature: Some(p.signature.to_bytes().to_vec()),
        created_at: p.created_at as i64,
        expires_at: p.expires_at.map(|t| t as i64),
        used: false,
        used_at: None,
        mailbox_id: None,
    }
}
fn opk_to_row(p: &OneTimePrekey) -> Prekey {
    Prekey {
        key_id: p.id,
        key_type: PrekeyType::Opk,
        private_key: p.keypair.private().to_bytes().to_vec(),
        public_key: p.keypair.public().to_bytes().to_vec(),
        signature: None,
        created_at: p.created_at as i64,
        expires_at: None,
        used: p.used,
        used_at: None,
        mailbox_id: None,
    }
}
#[async_trait]
impl PrekeyStorage for SqlitePrekeyStorage<'_> {
    async fn commit_bundle(
        &self,
        spk: Option<&SignedPrekey>,
        opks: &[OneTimePrekey],
        grace_end: u64,
    ) -> Result<()> {
        self.db
            .commit_prekey_batch(
                self.mailbox_id,
                &self.mailbox.fetch_capability,
                spk.map(spk_to_row).as_ref(),
                &opks.iter().map(opk_to_row).collect::<Vec<_>>(),
                grace_end as i64,
            )
            .map_err(|e| e.to_string())
    }
    async fn save_signed_prekey(&self, spk: &SignedPrekey) -> Result<()> {
        self.commit_bundle(
            Some(spk),
            &[],
            najwa_crypto::time::now() + super::SPK_GRACE_PERIOD_SECS,
        )
        .await
    }
    async fn get_current_spk(&self) -> Result<Option<StoredSpk>> {
        self.keys()?
            .into_iter()
            .find(|p| p.key_type == PrekeyType::Spk && !p.used && p.expires_at.is_none())
            .map(spk_record)
            .transpose()
    }
    async fn get_spk_by_id(&self, id: &[u8; 4]) -> Result<Option<StoredSpk>> {
        self.get(id, PrekeyType::Spk)?
            .filter(|p| {
                !p.used
                    && p.expires_at
                        .is_none_or(|t| t > najwa_crypto::time::now() as i64)
            })
            .map(spk_record)
            .transpose()
    }
    async fn expire_spk(&self, id: &[u8; 4], expires: u64) -> Result<()> {
        self.db
            .expire_mailbox_spk(
                self.mailbox_id,
                &self.mailbox.fetch_capability,
                id,
                expires as i64,
            )
            .map_err(|e| e.to_string())
    }
    async fn delete_expired_spks(&self, before: u64) -> Result<u32> {
        self.db
            .cleanup_mailbox_prekeys(
                self.mailbox_id,
                &self.mailbox.fetch_capability,
                PrekeyType::Spk,
                before as i64,
            )
            .map_err(|e| e.to_string())
    }
    async fn save_one_time_prekeys(&self, opks: &[OneTimePrekey]) -> Result<()> {
        self.commit_bundle(None, opks, 0).await
    }
    async fn list_unused_opks(&self) -> Result<Vec<StoredOpk>> {
        self.keys()?
            .into_iter()
            .filter(|p| p.key_type == PrekeyType::Opk && !p.used && p.expires_at.is_none())
            .map(opk_record)
            .collect()
    }
    async fn count_unused_opks(&self, _mailbox_id: Option<i64>) -> Result<u32> {
        Ok(self.list_unused_opks().await?.len() as u32)
    }
    async fn mark_opk_used(&self, id: &[u8; 4]) -> Result<()> {
        self.get(id, PrekeyType::Opk)?
            .ok_or("OPK outside mailbox scope")?;
        self.db.mark_opk_used(id).map_err(|e| e.to_string())
    }
    async fn get_opk_by_id(&self, id: &[u8; 4]) -> Result<Option<StoredOpk>> {
        self.get(id, PrekeyType::Opk)?
            .filter(|p| {
                !p.used
                    && p.expires_at
                        .is_none_or(|t| t > najwa_crypto::time::now() as i64)
            })
            .map(opk_record)
            .transpose()
    }
    async fn delete_used_opks(&self, before: u64) -> Result<u32> {
        self.db
            .cleanup_mailbox_prekeys(
                self.mailbox_id,
                &self.mailbox.fetch_capability,
                PrekeyType::Opk,
                before as i64,
            )
            .map_err(|e| e.to_string())
    }
    async fn list_mailboxes(&self) -> Result<Vec<MailboxConfig>> {
        Ok(vec![self.mailbox.clone()])
    }
}
