//! Message ID generation (S07 §6).

use najwa_crypto::kdf::{hkdf_sha256, info_strings};
use sha2::{Digest, Sha256};

/// Generate the transport message ID via HKDF (S07 §6.1).
///
/// ```text
/// msg_id = HKDF(
///     IKM  = ratchet_header.dh_pub(32) || message_number(4 BE) || content_hash(32),
///     salt = sender_pseudonym,
///     info = "najwa/v1/message-id",
///     length = 16
/// )
/// ```
///
/// `dh_pub` and `message_number` MUST be the values from the *actual* outgoing
/// ratchet header (peeked before `ratchet_encrypt` advances the chain), so two
/// byte-identical messages sent in the same second get distinct IDs — the ratchet
/// message number differs — instead of colliding and being dropped as a duplicate.
/// `content_hash = SHA256(content_type_byte || content_bytes)`.
pub fn generate_msg_id(
    dh_pub: &[u8; 32],
    message_number: u32,
    content_hash: &[u8; 32],
    sender_pseudonym: &[u8; 32],
) -> [u8; 16] {
    let mut ikm = Vec::with_capacity(32 + 4 + 32);
    ikm.extend_from_slice(dh_pub);
    ikm.extend_from_slice(&message_number.to_be_bytes());
    ikm.extend_from_slice(content_hash);

    let okm = hkdf_sha256(&ikm, sender_pseudonym, info_strings::MESSAGE_ID_INFO, 16)
        .expect("HKDF output length 16 is valid");

    let mut id = [0u8; 16];
    id.copy_from_slice(&okm);
    id
}

/// Generate the endpoint-invariant logical message ID (S07 §6.2).
///
/// ```text
/// logical_msg_id = SHA256(
///     sorted(IK_a_pub, IK_b_pub)(64) || 0x00 || // lex-min Ed25519 IK first
///     timestamp(8 BE)               || 0x00 || // Payload.timestamp
///     logical_seq(4 BE)             || 0x00 || // Payload.logical_seq
///     content_type(1)               || 0x00 || // Payload.content_type byte
///     content                            // Payload.content, byte-exact
/// )[0:16]
/// ```
///
/// Unlike the transport `msg_id` (§6.1, ratchet-derived), this is derived only
/// from the two identities + the logical content, so BOTH endpoints compute the
/// same value regardless of local `contact_id`, and it is STABLE across
/// session-repair / gap-repair re-encryption (the original `timestamp` and
/// `logical_seq` are reused byte-exact). It drives the `msg_id_cache_logical`
/// dedup (S03 §5.7) that gives at-most-once delivery across re-encryption.
pub fn generate_logical_msg_id(
    my_ik_pub: &[u8; 32],
    their_ik_pub: &[u8; 32],
    timestamp: u64,
    logical_seq: u32,
    content_type: u8,
    content: &[u8],
) -> [u8; 16] {
    // Lex-min IK first so both endpoints agree regardless of who is "us".
    let (a, b) = if my_ik_pub <= their_ik_pub {
        (my_ik_pub, their_ik_pub)
    } else {
        (their_ik_pub, my_ik_pub)
    };
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.update([0]);
    hasher.update(timestamp.to_be_bytes());
    hasher.update([0]);
    hasher.update(logical_seq.to_be_bytes());
    hasher.update([0]);
    hasher.update([content_type]);
    hasher.update([0]);
    hasher.update(content);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_id_deterministic() {
        let (dh, hash, pseudo) = ([0xAA; 32], [0xBB; 32], [0xCC; 32]);
        assert_eq!(
            generate_msg_id(&dh, 5, &hash, &pseudo),
            generate_msg_id(&dh, 5, &hash, &pseudo)
        );
    }

    #[test]
    fn distinct_message_numbers_never_collide() {
        // Same content + pseudonym at consecutive ratchet message numbers MUST
        // yield different IDs — this is the same-second collision fix (S07 §6.1).
        let (dh, hash, pseudo) = ([0xAA; 32], [0xBB; 32], [0xCC; 32]);
        assert_ne!(
            generate_msg_id(&dh, 10, &hash, &pseudo),
            generate_msg_id(&dh, 11, &hash, &pseudo)
        );
    }

    #[test]
    fn distinct_dh_pub_produce_different_ids() {
        let (hash, pseudo) = ([0xBB; 32], [0xCC; 32]);
        assert_ne!(
            generate_msg_id(&[0x01; 32], 0, &hash, &pseudo),
            generate_msg_id(&[0x02; 32], 0, &hash, &pseudo)
        );
    }

    #[test]
    fn distinct_pseudonyms_produce_different_ids() {
        let (dh, hash) = ([0xAA; 32], [0xBB; 32]);
        assert_ne!(
            generate_msg_id(&dh, 0, &hash, &[0x01; 32]),
            generate_msg_id(&dh, 0, &hash, &[0x02; 32])
        );
    }

    #[test]
    fn distinct_content_produce_different_ids() {
        let (dh, pseudo) = ([0xAA; 32], [0xCC; 32]);
        assert_ne!(
            generate_msg_id(&dh, 0, &[0x01; 32], &pseudo),
            generate_msg_id(&dh, 0, &[0x02; 32], &pseudo)
        );
    }

    #[test]
    fn msg_id_is_16_bytes() {
        assert_eq!(generate_msg_id(&[0; 32], 0, &[0; 32], &[0; 32]).len(), 16);
    }

    // S07 §6.2: both endpoints derive the same logical_msg_id regardless of who
    // is "us" (lex-min IK ordering).
    #[test]
    fn logical_msg_id_endpoint_invariant() {
        let (a, b) = ([0x11u8; 32], [0x22u8; 32]);
        assert_eq!(
            generate_logical_msg_id(&a, &b, 1000, 5, 0x01, b"hello"),
            generate_logical_msg_id(&b, &a, 1000, 5, 0x01, b"hello"),
        );
    }

    #[test]
    fn logical_msg_id_distinguishes_every_field() {
        let (a, b) = ([0x11u8; 32], [0x22u8; 32]);
        let base = generate_logical_msg_id(&a, &b, 1000, 5, 0x01, b"hi");
        assert_ne!(base, generate_logical_msg_id(&a, &b, 1001, 5, 0x01, b"hi")); // timestamp
        assert_ne!(base, generate_logical_msg_id(&a, &b, 1000, 6, 0x01, b"hi")); // logical_seq
        assert_ne!(base, generate_logical_msg_id(&a, &b, 1000, 5, 0x02, b"hi")); // content_type
        assert_ne!(base, generate_logical_msg_id(&a, &b, 1000, 5, 0x01, b"yo")); // content
        assert_eq!(base.len(), 16);
    }
}
