//! Contact establishment, introduction, and rendezvous (S05).
//!
//! Provides:
//! - Handshake payload construction and verification (S05 §2, §4)
//! - QR code encoding (Base45 + zlib) (S05 §6)
//! - URI encoding (Base64URL) (S05 §7)
//! - Contact acceptance flow with pseudonym derivation (S05 §8)
//! - Per-contact capability generation (S05 §8 step 10)
//! - Reciprocal handshake for mutual add (S05 §8.2)
//! - Contact introduction payload (S05 §11)
//! - Rendezvous protocol via shared phrase (library code; no app path uses it)
//! - NFC/BLE proximity exchange trait (library code; no app path uses it)
//! - Printable QR card generation (S05 §6.3)

pub mod accept;
pub mod capability_lifecycle;
pub mod encode;
pub mod error;
pub mod fingerprint;
pub mod handshake;
pub mod introduction;
pub mod mailbox_key;
pub mod proximity;
pub mod qr_card;
pub mod rendezvous;
pub mod serialize;
pub mod types;

// Re-exports (S05 §8)
pub use accept::{
    accept_contact, create_reciprocal_payload, AcceptResult, ContactStore, NewContact,
};
pub use error::{ContactError, HandshakeError};
pub use types::{ContactMailboxCap, HandshakePayload, MailboxInfo, HANDSHAKE_VERSION};

// Re-exports (S05 §11)
pub use introduction::{
    IntroductionError, IntroductionPayload, DEFAULT_INTRODUCTION_VALIDITY_DAYS,
    INTRODUCTION_VERSION,
};
pub use proximity::{ProximityError, ProximityExchange};
pub use qr_card::{generate_printable_card, QrCardConfig};
pub use rendezvous::{
    assess_phrase, estimate_entropy, normalize_phrase, PhraseStrength, RendezvousError,
    RendezvousSession, MIN_ENTROPY_BITS, RENDEZVOUS_EXPIRY_SECS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudonym::derive_pairwise_pseudonyms;
    use najwa_crypto::keys::Ed25519KeyPair;

    fn test_mailboxes() -> Vec<crate::mailbox::types::MailboxConfig> {
        vec![crate::mailbox::types::MailboxConfig::new(
            "test_onion_addr_56chars".to_string(),
            [0xAA; 32],
            [0xBB; 32],
        )]
    }

    // -----------------------------------------------------------------------
    // S05 §2 — Handshake payload create + verify
    // -----------------------------------------------------------------------

    #[test]
    fn integration_create_verify_roundtrip() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();

        assert_eq!(payload.version, HANDSHAKE_VERSION);
        assert_eq!(payload.ik_pub, ik.public().to_bytes());
        assert_eq!(payload.display_name, "Alice");
        assert!(!payload.mailbox_entries.is_empty());
        assert!(payload.verify().is_ok());
    }

    #[test]
    fn integration_expired_payload_rejected() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create_with_time(
            &ik,
            &test_mailboxes(),
            "Alice",
            1000,
            1001, // expires immediately
        );
        assert!(matches!(
            payload.verify_at(2000),
            Err(HandshakeError::Expired)
        ));
    }

    #[test]
    fn integration_tampered_payload_rejected() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
        payload.display_name = "Evil".to_string(); // Tamper
        assert!(payload.verify().is_err());
    }

    // -----------------------------------------------------------------------
    // S05 §2.1 — Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn integration_bytes_roundtrip() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();

        let bytes = payload.to_bytes();
        let restored = HandshakePayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.display_name, payload.display_name);
        assert_eq!(restored.mailboxes.len(), payload.mailboxes.len());
        assert_eq!(
            restored.mailbox_entries.len(),
            payload.mailbox_entries.len()
        );
        assert_eq!(restored.signature, payload.signature);
        // Restored payload should also verify
        assert!(restored.verify().is_ok());
    }

    // -----------------------------------------------------------------------
    // S05 §6 — QR code encoding
    // -----------------------------------------------------------------------

    #[test]
    fn integration_qr_roundtrip() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();

        let qr = payload.to_qr_string().unwrap();
        assert!(qr.starts_with("NAJWA:"));

        let restored = HandshakePayload::from_qr_string(&qr).unwrap();
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.display_name, payload.display_name);
        assert!(restored.verify().is_ok());
    }

    // -----------------------------------------------------------------------
    // S05 §7 — URI encoding
    // -----------------------------------------------------------------------

    #[test]
    fn integration_uri_roundtrip() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();

        let uri = payload.to_uri().unwrap();
        assert!(uri.starts_with("najwa://contact?data="));

        let restored = HandshakePayload::from_uri(&uri).unwrap();
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.display_name, payload.display_name);
        assert!(restored.verify().is_ok());
    }

    // -----------------------------------------------------------------------
    // S05 §8 — Contact acceptance (async)
    // -----------------------------------------------------------------------

    // Note: async tests for accept_contact are in accept.rs with MockStore

    // -----------------------------------------------------------------------
    // S05 §8.2 — Reciprocal handshake
    // -----------------------------------------------------------------------

    #[test]
    fn integration_reciprocal_handshake_flow() {
        // Alice creates a payload, Bob accepts, Bob creates reciprocal payload
        let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

        // Alice's payload
        let alice_payload =
            HandshakePayload::create(&alice_ik, &test_mailboxes(), "Alice", 24).unwrap();
        assert!(alice_payload.verify().is_ok());

        // Bob creates reciprocal payload
        let bob_payload = create_reciprocal_payload(&bob_ik, &test_mailboxes(), "Bob", 24).unwrap();
        assert!(bob_payload.verify().is_ok());

        // Both can derive matching pseudonyms from each other's IK
        let alice_ik_pub =
            najwa_crypto::keys::Ed25519Public::from_bytes(&alice_payload.ik_pub).unwrap();
        let bob_ik_pub =
            najwa_crypto::keys::Ed25519Public::from_bytes(&bob_payload.ik_pub).unwrap();

        let (alice_my, alice_their) = derive_pairwise_pseudonyms(&alice_ik, &bob_ik_pub).unwrap();
        let (bob_my, bob_their) = derive_pairwise_pseudonyms(&bob_ik, &alice_ik_pub).unwrap();

        assert_eq!(alice_my, bob_their);
        assert_eq!(alice_their, bob_my);
    }

    // -----------------------------------------------------------------------
    // S05 §5 — Advertised capabilities
    // -----------------------------------------------------------------------

    // S05 §5: `create()` advertises the caller-provided deposit caps verbatim;
    // the caller mints a fresh invitation queue per invitation, not `create()`.
    // Assert faithful pass-through of distinct caps.
    #[test]
    fn integration_create_preserves_provided_caps() {
        use crate::mailbox::types::MailboxConfig;
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mbs = vec![
            MailboxConfig::new("mb1".to_string(), [1; 32], [0xAA; 32]),
            MailboxConfig::new("mb2".to_string(), [2; 32], [0xCC; 32]),
        ];

        let p = HandshakePayload::create(&ik, &mbs, "A", 24).unwrap();

        assert_ne!(
            p.mailboxes[0].deposit_capability,
            p.mailboxes[1].deposit_capability
        );
        assert_eq!(p.mailboxes[0].deposit_capability, [0xAA; 32]);
    }

    // -----------------------------------------------------------------------
    // End-to-end: create → encode → decode → verify
    // -----------------------------------------------------------------------

    #[test]
    fn integration_full_qr_pipeline() {
        let ik = Ed25519KeyPair::from_seed(&[0x42; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "FullTest", 48).unwrap();

        // Encode to QR
        let qr = payload.to_qr_string().unwrap();

        // Decode from QR
        let decoded = HandshakePayload::from_qr_string(&qr).unwrap();

        // Verify the decoded payload
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.display_name, "FullTest");
        assert_eq!(decoded.ik_pub, ik.public().to_bytes());
    }

    #[test]
    fn integration_full_uri_pipeline() {
        let ik = Ed25519KeyPair::from_seed(&[0x42; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "FullTest", 48).unwrap();

        // Encode to URI
        let uri = payload.to_uri().unwrap();

        // Decode from URI
        let decoded = HandshakePayload::from_uri(&uri).unwrap();

        // Verify the decoded payload
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded.display_name, "FullTest");
    }
}
