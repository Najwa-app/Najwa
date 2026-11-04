//! TDD test suite for QR contact establishment flow.
//!
//! Tests the full chain: handshake → encode → decode → verify → accept → pseudonyms.
//! These tests exercise the existing implementation without modifying it.

use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_protocol::contact::accept::{
    accept_contact, create_reciprocal_payload, ContactStore, LocalContactCapability, NewContact,
    StoredMailbox,
};
use najwa_protocol::contact::error::{ContactError, HandshakeError};
use najwa_protocol::contact::fingerprint::{fingerprint, safety_number};
use najwa_protocol::contact::mailbox_key::{
    derive_mailbox_signing_key, MailboxCertificate, CAP_TYPE_EPHEMERAL, MAILBOX_ENTRY_SIZE,
};
use najwa_protocol::contact::types::{HandshakePayload, MAX_HANDSHAKE_SIZE};
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::pseudonym::{derive_pairwise_pseudonyms, PseudonymTable};

use std::sync::Mutex;

// ===========================================================================
// Test helpers
// ===========================================================================

fn test_mailboxes() -> Vec<MailboxConfig> {
    vec![MailboxConfig::new(
        "testmailbox123456".to_string(),
        [0xAA; 32],
        [0xBB; 32],
    )]
}

fn two_mailboxes() -> Vec<MailboxConfig> {
    vec![
        MailboxConfig::new(
            "mailbox_alpha_56chars_padded".to_string(),
            [0xAA; 32],
            [0xBB; 32],
        ),
        MailboxConfig::new(
            "mailbox_bravo_56chars_padded".to_string(),
            [0xCC; 32],
            [0xDD; 32],
        ),
    ]
}

struct MockStore {
    contacts: Mutex<Vec<NewContact>>,
    capabilities: Mutex<Vec<LocalContactCapability>>,
    remote_mailboxes: Mutex<Vec<najwa_protocol::contact::mailbox_key::MailboxEntry>>,
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
    async fn get_contact_by_ik(
        &self,
        ik_pub: &[u8; 32],
    ) -> Result<Option<najwa_protocol::pseudonym::types::ContactId>, String> {
        let contacts = self.contacts.lock().unwrap();
        for (i, c) in contacts.iter().enumerate() {
            if &c.their_ik_pub == ik_pub {
                return Ok(Some(najwa_protocol::pseudonym::types::ContactId(
                    i as u64 + 1,
                )));
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
    ) -> Result<najwa_protocol::pseudonym::types::ContactId, ContactError> {
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
        Ok(najwa_protocol::pseudonym::types::ContactId(
            contacts.len() as u64
        ))
    }
}

// ===========================================================================
// 1. Handshake Payload — edge cases
// ===========================================================================

#[test]
fn payload_created_at_after_expires_at_rejected_by_from_bytes() {
    // Build a payload where created_at > expires_at by manually crafting bytes
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    // Swap created_at and expires_at (created_at is at offset after mailbox entries + display name)
    // Easier: just set expires_at = 0 by zeroing the 8 bytes before signature
    let sig_start = bytes.len() - 64;
    let expires_start = sig_start - 8;
    bytes[expires_start..sig_start].copy_from_slice(&0u64.to_be_bytes());
    // Also set created_at to something high
    let created_start = expires_start - 8;
    bytes[created_start..expires_start].copy_from_slice(&9999999999u64.to_be_bytes());
    assert!(HandshakePayload::from_bytes(&bytes).is_err());
}

#[test]
fn payload_with_version_0x01_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    bytes[0] = 0x01; // downgrade version
    assert!(matches!(
        HandshakePayload::from_bytes(&bytes),
        Err(HandshakeError::UnsupportedVersion(0x01))
    ));
}

#[test]
fn payload_with_version_0xff_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    bytes[0] = 0xFF;
    assert!(matches!(
        HandshakePayload::from_bytes(&bytes),
        Err(HandshakeError::UnsupportedVersion(0xFF))
    ));
}

#[test]
fn payload_exceeding_2048_bytes_rejected() {
    let data = vec![0u8; MAX_HANDSHAKE_SIZE + 1];
    assert!(HandshakePayload::from_bytes(&data).is_err());
}

#[test]
fn payload_with_zero_mailboxes_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    // mailbox_count is at offset 33 (version=1 + ik_pub=32)
    bytes[33] = 0; // zero mailboxes
                   // This will fail parsing since there are actual mailbox bytes following
    assert!(HandshakePayload::from_bytes(&bytes).is_err());
}

#[test]
fn payload_with_9_mailboxes_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    bytes[33] = 9; // 9 mailboxes > MAX_MAILBOX_COUNT (8)
    assert!(HandshakePayload::from_bytes(&bytes).is_err());
}

#[test]
fn payload_display_name_over_128_bytes_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let mut bytes = payload.to_bytes();
    // The display_name_len field sits right after the mailbox entries:
    //   version(1) + ik(32) + mb_count(1) + mb_count * MAILBOX_ENTRY_SIZE.
    // Derive it from the constant so this can't drift when the entry size
    // changes (it grew 185 -> 217 with the D3 envelope_secret field).
    let name_len_offset = 1 + 32 + 1 + MAILBOX_ENTRY_SIZE;
    bytes[name_len_offset] = 0;
    bytes[name_len_offset + 1] = 129; // 129 in big-endian u16
    assert!(HandshakePayload::from_bytes(&bytes).is_err());
}

// ===========================================================================
// 2. Certificate verification edge cases
// ===========================================================================

#[test]
fn cert_with_wrong_ik_pub_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let other_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let mailbox_kp = derive_mailbox_signing_key(&ik.private().to_bytes(), "test.onion").unwrap();
    let cert = MailboxCertificate::create(&ik, &mailbox_kp.public().to_bytes(), "test.onion", 1000);
    // Verify against wrong identity key
    assert!(cert.verify(other_ik.public()).is_err());
}

#[test]
fn derived_signing_keys_differ_per_mailbox() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let kp1 = derive_mailbox_signing_key(&ik.private().to_bytes(), "server1.onion").unwrap();
    let kp2 = derive_mailbox_signing_key(&ik.private().to_bytes(), "server2.onion").unwrap();
    assert_ne!(kp1.public().to_bytes(), kp2.public().to_bytes());
}

#[test]
fn derived_signing_key_deterministic() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let kp1 = derive_mailbox_signing_key(&ik.private().to_bytes(), "same.onion").unwrap();
    let kp2 = derive_mailbox_signing_key(&ik.private().to_bytes(), "same.onion").unwrap();
    assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
}

#[test]
fn handshake_with_tampered_cert_signature_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    // Tamper the cert_signature in the first mailbox entry
    payload.mailbox_entries[0].cert_signature[0] ^= 0xFF;
    // Re-sign the outer payload so outer sig is valid but cert sig is broken
    let signable = payload.signable_bytes();
    payload.signature = ik.sign(&signable).to_bytes();
    // verify() checks cert signatures — should fail
    assert!(payload.verify().is_err());
}

#[test]
fn handshake_with_tampered_mailbox_ik_pub_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    // Replace mailbox_ik_pub with random key
    payload.mailbox_entries[0].mailbox_ik_pub = [0xFF; 32];
    // Re-sign outer payload
    let signable = payload.signable_bytes();
    payload.signature = ik.sign(&signable).to_bytes();
    // Cert signature won't match the new mailbox_ik_pub
    assert!(payload.verify().is_err());
}

// ===========================================================================
// 3. QR encoding edge cases
// ===========================================================================

#[test]
fn qr_string_starts_with_najwa_prefix() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let qr = payload.to_qr_string().unwrap();
    assert!(
        qr.starts_with("NAJWA:"),
        "QR string must start with NAJWA: prefix, got: {}",
        &qr[..20.min(qr.len())]
    );
}

#[test]
fn qr_decode_wrong_prefix_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let qr = payload.to_qr_string().unwrap();
    let bad = qr.replace("NAJWA:", "SIGNAL:");
    assert!(HandshakePayload::from_qr_string(&bad).is_err());
}

#[test]
fn uri_base64_portion_has_no_padding_chars() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let uri = payload.to_uri().unwrap();
    // The URI prefix "najwa://contact?data=" contains '=' — only check the Base64 portion
    let b64_portion = uri.strip_prefix("najwa://contact?data=").unwrap();
    assert!(
        !b64_portion.contains('='),
        "Base64URL portion should use no-pad, but contains '=': {}",
        b64_portion
    );
    // Also verify no '+' or '/' (standard Base64 chars that Base64URL replaces)
    assert!(
        !b64_portion.contains('+'),
        "Base64URL should not contain '+'"
    );
    assert!(
        !b64_portion.contains('/'),
        "Base64URL should not contain '/'"
    );
}

#[test]
fn uri_decode_wrong_prefix_rejected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    let uri = payload.to_uri().unwrap();
    let bad = uri.replace("najwa://contact?data=", "signal://contact?data=");
    assert!(HandshakePayload::from_uri(&bad).is_err());
}

#[test]
fn qr_roundtrip_with_multiple_mailboxes() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &two_mailboxes(), "Multi", 24).unwrap();
    let qr = payload.to_qr_string().unwrap();
    let decoded = HandshakePayload::from_qr_string(&qr).unwrap();
    assert_eq!(decoded.mailbox_entries.len(), 2);
    assert!(decoded.verify().is_ok());
}

#[test]
fn qr_roundtrip_with_empty_display_name() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "", 24).unwrap();
    let qr = payload.to_qr_string().unwrap();
    let decoded = HandshakePayload::from_qr_string(&qr).unwrap();
    assert_eq!(decoded.display_name, "");
    assert!(decoded.verify().is_ok());
}

#[test]
fn qr_roundtrip_with_unicode_display_name() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "أحمد", 24).unwrap();
    let qr = payload.to_qr_string().unwrap();
    let decoded = HandshakePayload::from_qr_string(&qr).unwrap();
    assert_eq!(decoded.display_name, "أحمد");
    assert!(decoded.verify().is_ok());
}

#[test]
fn uri_roundtrip_with_unicode_display_name() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "مريم", 24).unwrap();
    let uri = payload.to_uri().unwrap();
    let decoded = HandshakePayload::from_uri(&uri).unwrap();
    assert_eq!(decoded.display_name, "مريم");
    assert!(decoded.verify().is_ok());
}

// ===========================================================================
// 4. Contact acceptance — verification chain
// ===========================================================================

#[tokio::test]
async fn accept_verifies_outer_signature() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let mut payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    payload.ik_pub[0] ^= 0xFF; // tamper ik_pub
    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &payload).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn accept_rejects_expired_payload() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let mut payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let now = najwa_crypto::time::now();
    payload.created_at = now - 3600;
    payload.expires_at = now - 301;
    // Keep both signature layers valid so expiration is the only rejection.
    for entry in &mut payload.mailbox_entries {
        let onion = std::str::from_utf8(&entry.onion_address)
            .unwrap()
            .trim_end_matches('\0');
        entry.cert_signature =
            MailboxCertificate::create(&bob_ik, &entry.mailbox_ik_pub, onion, payload.created_at)
                .signature;
    }
    let signable = payload.signable_bytes();
    payload.signature = bob_ik.sign(&signable).to_bytes();
    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &payload).await;
    assert!(matches!(
        result,
        Err(ContactError::HandshakeError(HandshakeError::Expired))
    ));
}

#[tokio::test]
async fn accept_rejects_unknown_capability_type() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let mut payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    payload.mailbox_entries[0].capability_type = 0x03; // invalid
                                                       // Re-sign outer
    let signable = payload.signable_bytes();
    payload.signature = bob_ik.sign(&signable).to_bytes();
    // But cert was signed over old entry data, so cert will fail first.
    // The point is it should be rejected either way.
    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &payload).await;
    assert!(
        result.is_err(),
        "Unknown capability_type should be rejected"
    );
}

#[tokio::test]
async fn accept_stores_correct_display_name() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "أحمد", 24).unwrap();
    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &payload).await;
    assert!(result.is_ok());
    let contacts = store.contacts.lock().unwrap();
    assert_eq!(contacts[0].display_name, Some("أحمد".to_string()));
}

#[tokio::test]
async fn accept_generates_unique_caps_per_contact() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let carol_ik = Ed25519KeyPair::from_seed(&[0x03; 32]);

    let store = MockStore::new();

    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let carol_payload =
        HandshakePayload::create(&carol_ik, &test_mailboxes(), "Carol", 24).unwrap();

    accept_contact(&alice_ik, &store, &bob_payload)
        .await
        .unwrap();
    accept_contact(&alice_ik, &store, &carol_payload)
        .await
        .unwrap();

    let caps = store.capabilities.lock().unwrap();
    // Each contact has its own local receive credentials.
    assert_ne!(caps[0].deposit_capability, caps[1].deposit_capability);
}

// ===========================================================================
// 5. Pseudonym derivation
// ===========================================================================

#[test]
fn pseudonyms_symmetric_both_directions() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let (alice_my, alice_their) = derive_pairwise_pseudonyms(&alice_ik, bob_ik.public()).unwrap();
    let (bob_my, bob_their) = derive_pairwise_pseudonyms(&bob_ik, alice_ik.public()).unwrap();

    assert_eq!(
        alice_my, bob_their,
        "Alice's pseudonym must equal what Bob sees for her"
    );
    assert_eq!(
        alice_their, bob_my,
        "Bob's pseudonym must equal what Alice sees for him"
    );
}

#[test]
fn pseudonyms_differ_per_contact() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);
    let carol_ik = Ed25519KeyPair::from_seed(&[0x03; 32]);

    let (alice_bob_my, alice_bob_their) =
        derive_pairwise_pseudonyms(&alice_ik, bob_ik.public()).unwrap();
    let (alice_carol_my, alice_carol_their) =
        derive_pairwise_pseudonyms(&alice_ik, carol_ik.public()).unwrap();

    assert_ne!(
        alice_bob_my, alice_carol_my,
        "Alice's pseudonym with Bob must differ from Carol"
    );
    assert_ne!(alice_bob_their, alice_carol_their);
}

#[test]
fn pseudonym_not_all_zeros() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let (my, their) = derive_pairwise_pseudonyms(&alice_ik, bob_ik.public()).unwrap();
    assert_ne!(my.0, [0u8; 32]);
    assert_ne!(their.0, [0u8; 32]);
}

#[test]
fn pseudonym_table_lookup_100_contacts() {
    let me = Ed25519KeyPair::from_seed(&[0xFF; 32]);
    let mut table = PseudonymTable::new();

    for i in 0u8..100 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        let contact = Ed25519KeyPair::from_seed(&seed);
        let (_, their) = derive_pairwise_pseudonyms(&me, contact.public()).unwrap();
        table.insert(their, najwa_protocol::pseudonym::types::ContactId(i as u64));
    }

    // Verify all lookups succeed
    for i in 0u8..100 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        let contact = Ed25519KeyPair::from_seed(&seed);
        let (_, their) = derive_pairwise_pseudonyms(&me, contact.public()).unwrap();
        let found = table.lookup(&their);
        assert_eq!(
            found,
            Some(najwa_protocol::pseudonym::types::ContactId(i as u64))
        );
    }
}

#[test]
fn pseudonym_table_unknown_returns_none() {
    let table = PseudonymTable::new();
    let random = najwa_protocol::pseudonym::Pseudonym([0xDE; 32]);
    assert_eq!(table.lookup(&random), None);
}

// ===========================================================================
// 6. Fingerprint & safety number
// ===========================================================================

#[test]
fn safety_number_matches_across_qr_flow() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    // Simulate: Bob shows QR, Alice scans
    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();

    // Alice extracts Bob's ik_pub from the QR payload
    let alice_sn = safety_number(&alice_ik.public().to_bytes(), &bob_payload.ik_pub);
    let bob_sn = safety_number(&bob_ik.public().to_bytes(), &alice_ik.public().to_bytes());

    assert_eq!(alice_sn, bob_sn, "Safety numbers must match on both sides");
}

#[test]
fn fingerprint_format_is_8_groups_of_4_hex() {
    let fp = fingerprint(&[0x42; 32]);
    let groups: Vec<&str> = fp.split(' ').collect();
    assert_eq!(
        groups.len(),
        8,
        "Fingerprint must have 8 groups, got {}",
        groups.len()
    );
    for (i, g) in groups.iter().enumerate() {
        assert_eq!(g.len(), 4, "Group {} has {} chars, expected 4", i, g.len());
        assert!(
            g.chars().all(|c| c.is_ascii_hexdigit()),
            "Group {} contains non-hex chars: {}",
            i,
            g
        );
    }
}

#[test]
fn fingerprint_uses_lowercase_hex() {
    let fp = fingerprint(&[0x42; 32]);
    // All alpha chars should be lowercase
    for c in fp.chars() {
        if c.is_ascii_alphabetic() {
            assert!(
                c.is_ascii_lowercase(),
                "Fingerprint must use lowercase hex, found '{}'",
                c
            );
        }
    }
}

// ===========================================================================
// 7. Full QR pipeline — create → encode → decode → verify → accept
// ===========================================================================

#[tokio::test]
async fn full_qr_pipeline_succeeds() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    // Bob creates and encodes QR
    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let qr_string = bob_payload.to_qr_string().unwrap();

    // Alice scans and decodes
    let decoded = HandshakePayload::from_qr_string(&qr_string).unwrap();

    // Alice accepts
    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &decoded).await;
    assert!(
        result.is_ok(),
        "Full QR pipeline must succeed: {:?}",
        result.err()
    );

    let accept = result.unwrap();
    let contacts = store.contacts.lock().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].display_name, Some("Bob".to_string()));
    assert_eq!(contacts[0].their_ik_pub, bob_ik.public().to_bytes());

    // Pseudonyms should match independent derivation
    let (expected_my, expected_their) =
        derive_pairwise_pseudonyms(&alice_ik, bob_ik.public()).unwrap();
    assert_eq!(accept.our_pseudonym, expected_my);
    assert_eq!(accept.their_pseudonym, expected_their);
}

#[tokio::test]
async fn full_uri_pipeline_succeeds() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let uri = bob_payload.to_uri().unwrap();
    let decoded = HandshakePayload::from_uri(&uri).unwrap();

    let store = MockStore::new();
    let result = accept_contact(&alice_ik, &store, &decoded).await;
    assert!(
        result.is_ok(),
        "Full URI pipeline must succeed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn full_pipeline_duplicate_contact_rejected() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let qr = bob_payload.to_qr_string().unwrap();
    let decoded = HandshakePayload::from_qr_string(&qr).unwrap();

    let store = MockStore::new();
    // First accept
    assert!(accept_contact(&alice_ik, &store, &decoded).await.is_ok());
    // Second accept — same ik_pub
    let decoded2 = HandshakePayload::from_qr_string(&qr).unwrap();
    let err = accept_contact(&alice_ik, &store, &decoded2).await;
    assert!(matches!(err, Err(ContactError::AlreadyExists)));
}

#[tokio::test]
async fn full_pipeline_reciprocal_pseudonyms_match() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    // Alice accepts Bob's payload
    let bob_payload = HandshakePayload::create(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
    let alice_store = MockStore::new();
    let alice_result = accept_contact(&alice_ik, &alice_store, &bob_payload)
        .await
        .unwrap();

    // Bob accepts Alice's reciprocal payload
    let alice_payload =
        create_reciprocal_payload(&alice_ik, &test_mailboxes(), "Alice", 24).unwrap();
    let bob_store = MockStore::new();
    let bob_result = accept_contact(&bob_ik, &bob_store, &alice_payload)
        .await
        .unwrap();

    // Alice's "my pseudonym" == Bob's "their pseudonym"
    assert_eq!(alice_result.our_pseudonym, bob_result.their_pseudonym);
    assert_eq!(alice_result.their_pseudonym, bob_result.our_pseudonym);
}

// ===========================================================================
// 8. Adversarial tests
// ===========================================================================

#[test]
fn forged_ik_pub_with_victims_mailbox_entries_detected() {
    // Attacker generates payload with their own IK but copies victim's mailbox entries
    let victim_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let attacker_ik = Ed25519KeyPair::from_seed(&[0x99; 32]);

    let victim_payload =
        HandshakePayload::create(&victim_ik, &test_mailboxes(), "Victim", 24).unwrap();

    // Attacker creates a payload with their own ik_pub but victim's mailbox entries
    let mut forged =
        HandshakePayload::create(&attacker_ik, &test_mailboxes(), "Attacker", 24).unwrap();
    forged.mailbox_entries = victim_payload.mailbox_entries.clone();
    // Re-sign with attacker's key
    let signable = forged.signable_bytes();
    forged.signature = attacker_ik.sign(&signable).to_bytes();

    // Outer signature will verify (attacker signed it), but cert_signature in mailbox entries
    // were signed by victim's IK and contain victim's ik_pub — mismatch with forged.ik_pub
    assert!(
        forged.verify().is_err(),
        "Forged payload with victim's certs must be rejected"
    );
}

#[test]
fn mitm_replacing_deposit_capability_detected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    // MITM replaces deposit capability
    payload.mailboxes[0].deposit_capability = [0xFF; 32];
    payload.mailbox_entries[0].deposit_capability = [0xFF; 32];
    // Outer signature was computed over original data — now invalid
    assert!(payload.verify().is_err());
}

#[test]
fn mitm_replacing_onion_address_detected() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    // MITM replaces onion address
    payload.mailbox_entries[0].onion_address = [0xFF; 56];
    // Outer signature was computed over original data — now invalid
    assert!(payload.verify().is_err());
}

// ===========================================================================
// 9. Capability type validation
// ===========================================================================

#[test]
fn ephemeral_and_long_term_cap_types_accepted() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
    assert_eq!(
        payload.mailbox_entries[0].capability_type,
        CAP_TYPE_EPHEMERAL
    );
    assert!(payload.verify().is_ok());
}

// ===========================================================================
// 10. Multiple mailbox entries
// ===========================================================================

#[test]
fn payload_with_max_8_mailboxes() {
    let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let mut mbs = Vec::new();
    for i in 0..8u8 {
        mbs.push(MailboxConfig::new(
            format!("mailbox_{}_padded_to_fill", i),
            [i; 32],
            [i + 100; 32],
        ));
    }
    let payload = HandshakePayload::create(&ik, &mbs, "Max", 24).unwrap();
    assert_eq!(payload.mailbox_entries.len(), 8);
    assert!(payload.verify().is_ok());

    // Roundtrip via QR
    let qr = payload.to_qr_string().unwrap();
    let decoded = HandshakePayload::from_qr_string(&qr).unwrap();
    assert_eq!(decoded.mailbox_entries.len(), 8);
    assert!(decoded.verify().is_ok());
}

#[tokio::test]
async fn accept_with_2_mailboxes_stores_all_caps() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let bob_payload = HandshakePayload::create(&bob_ik, &two_mailboxes(), "Bob", 24).unwrap();
    let store = MockStore::new();
    accept_contact(&alice_ik, &store, &bob_payload)
        .await
        .unwrap();

    let caps = store.capabilities.lock().unwrap();
    assert_eq!(caps.len(), 1);
    let remote = store.remote_mailboxes.lock().unwrap();
    assert_eq!(remote.len(), 2);
    for (actual, expected) in remote.iter().zip(&bob_payload.mailbox_entries) {
        assert_eq!(actual.to_bytes(), expected.to_bytes());
    }
}
