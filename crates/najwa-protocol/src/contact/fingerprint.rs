//! Fingerprint display and safety numbers (S05 §9).
//!
//! Provides human-readable fingerprint strings for identity key verification
//! and safety numbers for pairwise contact verification.

use najwa_crypto::hash::sha256;

/// Generate a human-readable fingerprint from an identity public key (S05 §9).
///
/// Format: SHA-256 of `ik_pub`, displayed as 8 groups of 4 hex characters
/// separated by spaces (64 hex chars total).
///
/// Example: `"a1b2 c3d4 e5f6 7890 1234 5678 9abc def0"`
pub fn fingerprint(ik_pub: &[u8; 32]) -> String {
    let hash = sha256(ik_pub);
    let hex = hex_encode(&hash[..16]); // First 16 bytes = 32 hex chars = 8×4 groups
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("????"))
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Generate a safety number for a pair of contacts (S05 §9).
///
/// Both parties independently compute the same safety number:
/// `SHA-256(sorted(ik_pub_a, ik_pub_b))` displayed as 8×4 hex groups.
///
/// The keys are sorted lexicographically before hashing so both
/// sides produce the same result regardless of who initiates.
pub fn safety_number(ik_pub_a: &[u8; 32], ik_pub_b: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(64);
    if ik_pub_a <= ik_pub_b {
        input.extend_from_slice(ik_pub_a);
        input.extend_from_slice(ik_pub_b);
    } else {
        input.extend_from_slice(ik_pub_b);
        input.extend_from_slice(ik_pub_a);
    }
    let hash = sha256(&input);
    let hex = hex_encode(&hash[..16]); // First 16 bytes = 32 hex chars = 8×4 groups
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("????"))
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[0x42; 32]);
        // Should be 8 groups of 4 hex chars separated by spaces
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 8);
        for g in &groups {
            assert_eq!(g.len(), 4);
            assert!(g.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn fingerprint_deterministic() {
        let fp1 = fingerprint(&[0x01; 32]);
        let fp2 = fingerprint(&[0x01; 32]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_different_keys_differ() {
        let fp1 = fingerprint(&[0x01; 32]);
        let fp2 = fingerprint(&[0x02; 32]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn safety_number_symmetric() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    #[test]
    fn safety_number_format() {
        let sn = safety_number(&[0x01; 32], &[0x02; 32]);
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 8);
    }

    #[test]
    fn safety_number_different_pairs_differ() {
        let sn1 = safety_number(&[0x01; 32], &[0x02; 32]);
        let sn2 = safety_number(&[0x01; 32], &[0x03; 32]);
        assert_ne!(sn1, sn2);
    }
}
