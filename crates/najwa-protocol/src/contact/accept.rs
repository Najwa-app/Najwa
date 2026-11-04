//! Contact acceptance with one atomic persistence boundary (S05 §8).

use super::error::{ContactError, HandshakeError};
use super::types::HandshakePayload;
use crate::pseudonym::types::ContactId;
use crate::pseudonym::{derive_pairwise_pseudonyms, Pseudonym};
use najwa_crypto::keys::{Ed25519KeyPair, Ed25519Public};
use najwa_crypto::random::random_bytes;
pub use najwa_storage::contact_establishment::LocalContactCapability;

#[derive(Debug, Clone)]
pub struct NewContact {
    pub their_pseudonym: [u8; 32],
    pub their_ik_pub: [u8; 32],
    pub our_pseudonym: [u8; 32],
    pub display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredMailbox {
    pub id: u64,
    pub onion_address: String,
    pub fetch_capability: [u8; 32],
}

/// Persistence boundary for contact acceptance. Implementations MUST commit the
/// contact, local credentials and all signed remote entries atomically, and
/// enforce identity uniqueness inside the same transaction. There is deliberately
/// no sequence of independently committing write methods or rollback fallback.
#[async_trait::async_trait]
pub trait ContactStore: Send + Sync {
    async fn get_contact_by_ik(&self, ik_pub: &[u8; 32]) -> Result<Option<ContactId>, String>;
    async fn list_mailboxes(&self) -> Result<Vec<StoredMailbox>, String>;
    async fn commit_contact(
        &self,
        contact: &NewContact,
        local_capabilities: &[LocalContactCapability],
        signed_payload: &HandshakePayload,
    ) -> Result<ContactId, ContactError>;
}

#[derive(Debug, Clone)]
pub struct AcceptResult {
    pub contact_id: ContactId,
    pub our_pseudonym: Pseudonym,
    pub their_pseudonym: Pseudonym,
}

/// Verify and prepare everything before the single atomic write. Local
/// capabilities are persisted as unregistered; network registration remains a
/// separate obligation. Remote coordinates always come from signed entries.
pub async fn accept_contact(
    my_ik: &Ed25519KeyPair,
    store: &dyn ContactStore,
    their_payload: &HandshakePayload,
) -> Result<AcceptResult, ContactError> {
    their_payload.verify()?;
    for entry in &their_payload.mailbox_entries {
        if !matches!(entry.capability_type, 0x01 | 0x02) {
            return Err(HandshakeError::InvalidFormat("unsupported capability type".into()).into());
        }
        std::str::from_utf8(&entry.onion_address).map_err(|_| {
            HandshakeError::InvalidFormat("invalid mailbox address encoding".into())
        })?;
    }
    if store
        .get_contact_by_ik(&their_payload.ik_pub)
        .await
        .map_err(ContactError::StorageError)?
        .is_some()
    {
        return Err(ContactError::AlreadyExists);
    }
    let their_ik = Ed25519Public::from_bytes(&their_payload.ik_pub)
        .map_err(|e| HandshakeError::CryptoError(e.to_string()))?;
    let (my_pseudo, their_pseudo) = derive_pairwise_pseudonyms(my_ik, &their_ik)?;
    let our_mailboxes = store
        .list_mailboxes()
        .await
        .map_err(ContactError::StorageError)?;
    if our_mailboxes.is_empty() {
        return Err(ContactError::StorageError(
            "no local mailbox available".into(),
        ));
    }
    let local_capabilities = our_mailboxes
        .iter()
        .map(|mailbox| {
            let mailbox_id = i64::try_from(mailbox.id)
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| ContactError::StorageError("invalid local mailbox id".into()))?;
            Ok(LocalContactCapability {
                mailbox_id,
                deposit_capability: random_bytes(),
                fetch_capability: random_bytes(),
                envelope_secret: random_bytes(),
            })
        })
        .collect::<Result<Vec<_>, ContactError>>()?;
    let contact_id = store
        .commit_contact(
            &NewContact {
                their_pseudonym: their_pseudo.0,
                their_ik_pub: their_payload.ik_pub,
                our_pseudonym: my_pseudo.0,
                display_name: Some(their_payload.display_name.clone()),
            },
            &local_capabilities,
            their_payload,
        )
        .await?;
    Ok(AcceptResult {
        contact_id,
        our_pseudonym: my_pseudo,
        their_pseudonym: their_pseudo,
    })
}

pub fn create_reciprocal_payload(
    my_ik: &Ed25519KeyPair,
    mailboxes: &[crate::mailbox::types::MailboxConfig],
    display_name: &str,
    validity_hours: u64,
) -> Result<HandshakePayload, HandshakeError> {
    HandshakePayload::create(my_ik, mailboxes, display_name, validity_hours)
}

#[async_trait::async_trait]
impl ContactStore for najwa_storage::database::SqliteStorage {
    async fn get_contact_by_ik(&self, ik_pub: &[u8; 32]) -> Result<Option<ContactId>, String> {
        Self::get_contact_by_ik(self, ik_pub)
            .map(|c| c.map(|c| ContactId(c.id as u64)))
            .map_err(|e| e.to_string())
    }
    async fn list_mailboxes(&self) -> Result<Vec<StoredMailbox>, String> {
        Self::list_mailboxes(self)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|m| m.enabled)
            .map(|m| {
                Ok(StoredMailbox {
                    id: m.id.try_into().map_err(|_| "invalid mailbox id")?,
                    onion_address: m.onion_address,
                    fetch_capability: m
                        .fetch_capability
                        .try_into()
                        .map_err(|_| "invalid fetch capability")?,
                })
            })
            .collect()
    }
    async fn commit_contact(
        &self,
        contact: &NewContact,
        local_capabilities: &[LocalContactCapability],
        signed_payload: &HandshakePayload,
    ) -> Result<ContactId, ContactError> {
        let targets = signed_payload
            .mailbox_entries
            .iter()
            .map(|entry| {
                Ok(najwa_storage::contact_establishment::ContactTarget {
                    onion: std::str::from_utf8(&entry.onion_address)
                        .map_err(|_| {
                            HandshakeError::InvalidFormat("invalid mailbox address encoding".into())
                        })?
                        .trim_end_matches('\0')
                        .to_string(),
                    deposit_capability: entry.deposit_capability,
                    envelope_secret: entry.envelope_secret,
                    mailbox_entry: entry.to_bytes().to_vec(),
                })
            })
            .collect::<Result<Vec<_>, ContactError>>()?;
        self.commit_contact_establishment(
            &najwa_storage::types::NewContact {
                pseudonym: contact.their_pseudonym,
                their_ik_pub: contact.their_ik_pub,
                their_device_pub: contact.their_ik_pub,
                our_pseudonym: contact.our_pseudonym,
                display_name: contact.display_name.clone(),
            },
            local_capabilities,
            &targets,
            &signed_payload.to_bytes(),
        )
        .map(|id| ContactId(id as u64))
        .map_err(|e| match e {
            najwa_storage::error::StorageError::AlreadyExists => ContactError::AlreadyExists,
            other => ContactError::StorageError(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::types::HANDSHAKE_VERSION;
    use najwa_crypto::keys::Ed25519KeyPair;
    use std::sync::Mutex;

    // Mock storage for testing
    struct MockStore {
        contacts: Mutex<Vec<NewContact>>,
        capabilities: Mutex<Vec<LocalContactCapability>>,
        remote_mailboxes: Mutex<Vec<crate::contact::mailbox_key::MailboxEntry>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                contacts: Mutex::new(Vec::new()),
                capabilities: Mutex::new(Vec::new()),
                remote_mailboxes: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl ContactStore for MockStore {
        async fn get_contact_by_ik(&self, ik_pub: &[u8; 32]) -> Result<Option<ContactId>, String> {
            let contacts = self.contacts.lock().unwrap();
            for (i, c) in contacts.iter().enumerate() {
                if &c.their_ik_pub == ik_pub {
                    return Ok(Some(ContactId(i as u64 + 1)));
                }
            }
            Ok(None)
        }

        async fn list_mailboxes(&self) -> Result<Vec<StoredMailbox>, String> {
            Ok(vec![StoredMailbox {
                id: 1,
                onion_address: "my_mailbox_onion".to_string(),
                fetch_capability: [0xCC; 32],
            }])
        }

        async fn commit_contact(
            &self,
            contact: &NewContact,
            local_capabilities: &[LocalContactCapability],
            signed_payload: &HandshakePayload,
        ) -> Result<ContactId, ContactError> {
            let mut contacts = self.contacts.lock().unwrap();
            if contacts
                .iter()
                .any(|c| c.their_ik_pub == contact.their_ik_pub)
            {
                return Err(ContactError::AlreadyExists);
            }
            let mut caps = self.capabilities.lock().unwrap();
            let mut remote = self.remote_mailboxes.lock().unwrap();
            contacts.push(contact.clone());
            caps.extend_from_slice(local_capabilities);
            remote.extend_from_slice(&signed_payload.mailbox_entries);
            Ok(ContactId(contacts.len() as u64))
        }
    }

    fn make_test_payload(ik: &Ed25519KeyPair) -> HandshakePayload {
        // Realistic created_at so the derived MailboxCertificate (created_at +
        // 180d, S05 §2.3) is not already expired when `accept_contact` checks it
        // against wall-clock `now()`.
        let now = najwa_crypto::time::now();
        HandshakePayload::create_with_time(
            ik,
            &[crate::mailbox::types::MailboxConfig::new(
                "their_mailbox".to_string(),
                [0; 32],
                [0; 32],
            )],
            "Bob",
            now,
            now + 86_400,
        )
    }

    #[tokio::test]
    async fn accept_contact_succeeds() {
        let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

        let bob_payload = make_test_payload(&bob_ik);
        let store = MockStore::new();

        let result = accept_contact(&alice_ik, &store, &bob_payload).await;
        assert!(result.is_ok());
        let accept = result.unwrap();
        assert_eq!(accept.contact_id, ContactId(1));

        // Verify contact was stored
        let contacts = store.contacts.lock().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].their_ik_pub, bob_ik.public().to_bytes());
        assert_eq!(contacts[0].display_name, Some("Bob".to_string()));
    }

    #[tokio::test]
    async fn accept_duplicate_contact_rejected() {
        let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

        let bob_payload = make_test_payload(&bob_ik);
        let store = MockStore::new();

        // First accept succeeds
        assert!(accept_contact(&alice_ik, &store, &bob_payload)
            .await
            .is_ok());
        // Second accept fails
        assert!(matches!(
            accept_contact(&alice_ik, &store, &bob_payload).await,
            Err(ContactError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn accept_stores_capabilities() {
        let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

        let bob_payload = make_test_payload(&bob_ik);
        let store = MockStore::new();

        accept_contact(&alice_ik, &store, &bob_payload)
            .await
            .unwrap();

        let caps = store.capabilities.lock().unwrap();
        assert_eq!(caps.len(), 1);
        assert_ne!(caps[0].deposit_capability, [0u8; 32]);
        assert_ne!(caps[0].envelope_secret, [0u8; 32]);
        let remote = store.remote_mailboxes.lock().unwrap();
        assert_eq!(remote.len(), 1);
        assert_eq!(
            remote[0].to_bytes(),
            bob_payload.mailbox_entries[0].to_bytes()
        );
    }

    #[tokio::test]
    async fn accept_derives_correct_pseudonyms() {
        let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

        let bob_payload = make_test_payload(&bob_ik);
        let store = MockStore::new();

        let result = accept_contact(&alice_ik, &store, &bob_payload)
            .await
            .unwrap();

        // Verify pseudonyms match what derive_pairwise_pseudonyms produces
        let (expected_my, expected_their) =
            derive_pairwise_pseudonyms(&alice_ik, bob_ik.public()).unwrap();
        assert_eq!(result.our_pseudonym, expected_my);
        assert_eq!(result.their_pseudonym, expected_their);
    }

    #[test]
    fn reciprocal_payload_is_valid() {
        let ik = Ed25519KeyPair::from_seed(&[0x10; 32]);

        let payload = create_reciprocal_payload(
            &ik,
            &[crate::mailbox::types::MailboxConfig::new(
                "my_mb".to_string(),
                [0; 32],
                [0; 32],
            )],
            "Alice",
            24,
        )
        .unwrap();

        assert_eq!(payload.version, HANDSHAKE_VERSION);
        assert!(payload.verify().is_ok());
    }
}
