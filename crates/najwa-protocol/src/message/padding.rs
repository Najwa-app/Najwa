//! Bucket padding (S07 §5).
//!
//! Pads messages to fixed bucket sizes to prevent size-based traffic analysis.
//! The message path uses [`pad_payload`] (zero fill, S07 §5.2). [`pad_to_bucket`]
//! and [`unpad`] are a separate length-prefix scheme that no message path uses.

use najwa_crypto::random::fill_random;

use super::error::{MessageError, Result};

/// Padding bucket sizes in bytes — the **final deposited-blob** sizes an
/// observer sees (S07 §5.1). 11 sizes: the former 128-byte bucket is removed
/// because it cannot hold even the smallest fixed overhead (160).
pub const BUCKETS: &[usize] = &[
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144,
];

/// Pad plaintext to next bucket size using a length-prefix scheme.
///
/// Format: `[4-byte big-endian plaintext length] [plaintext] [random padding]`
///
/// Returns `ContentTooLarge` if the plaintext exceeds the largest bucket capacity.
///
/// NOTE: PKCS#7-style padding was considered but rejected because it encodes
/// the padding length in a single byte (`pad_len & 0xFF`), which silently
/// corrupts data when `pad_len > 256`. Length-prefix avoids this entirely.
pub fn pad_to_bucket(plaintext: &[u8]) -> Result<Vec<u8>> {
    // 4-byte length prefix + plaintext + at least 1 byte padding
    let needed = 4 + plaintext.len() + 1;
    let largest = *BUCKETS.last().unwrap();
    let target = match BUCKETS.iter().find(|&&size| size >= needed).copied() {
        Some(t) => t,
        None => {
            return Err(MessageError::ContentTooLarge {
                size: plaintext.len(),
                max: largest - 5,
            });
        }
    };

    let pad_len = target - 4 - plaintext.len();

    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    padded.extend_from_slice(plaintext);
    // Fill padding with random bytes (indistinguishable from ciphertext)
    let mut padding = vec![0u8; pad_len];
    fill_random(&mut padding);
    padded.extend_from_slice(&padding);
    Ok(padded)
}

/// Pad a 1:1 `Payload`'s serialized bytes with `0x00` zero-fill so the FINAL
/// DEPOSITED BLOB lands exactly on a §5.1 bucket (S07 §5.1.1 / §5.2).
///
/// `fixed_overhead` is everything the deposited blob carries besides the padded
/// plaintext: `ENVELOPE_OVERHEAD(40) + wire_prefix + AEAD nonce(24)+tag(16)`
/// (S07 §5.1.1) — **160** for `0x02 Standard`, **263/267** for `0x01 Initial`
/// (no OPK / with OPK). The padded-plaintext target is `bucket − fixed_overhead`,
/// so `deposited_blob = fixed_overhead + padded_plaintext` == a canonical bucket.
/// The always-on deposit envelope (S07 §3) guarantees that +40 is really present.
///
/// There is NO length indicator and NO random bytes: `Payload.content_length`
/// (§4) is the authoritative content delimiter, and [`super::types::Payload`]'s
/// `from_bytes` verifies the trailing padding is all `0x00` (§5.3) — the padding
/// is AEAD-authenticated, so this rejects a non-canonical pad. Buckets too small
/// to hold `fixed_overhead` are skipped (an Initial message can never land on the
/// 256 bucket: 263 > 256).
pub fn pad_payload(payload_bytes: &[u8], fixed_overhead: usize) -> Result<Vec<u8>> {
    // Smallest bucket whose padded-plaintext target (bucket − fixed_overhead)
    // still fits the payload. `checked_sub` drops buckets too small to hold the
    // overhead; BUCKETS is ascending, so the first fit is the smallest.
    let target = BUCKETS
        .iter()
        .filter_map(|&bucket| bucket.checked_sub(fixed_overhead))
        .find(|&t| t >= payload_bytes.len());
    let target = match target {
        Some(t) => t,
        None => {
            return Err(MessageError::ContentTooLarge {
                size: payload_bytes.len(),
                max: BUCKETS.last().unwrap().saturating_sub(fixed_overhead),
            });
        }
    };
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(payload_bytes);
    out.resize(target, 0x00); // §5.2: zero-fill, no length indicator
    Ok(out)
}

/// Remove padding by reading the length prefix (inverse of [`pad_to_bucket`]).
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < 5 {
        return Err(MessageError::EmptyMessage);
    }

    let content_len = u32::from_be_bytes(
        padded[0..4]
            .try_into()
            .map_err(|_| MessageError::InvalidPadding)?,
    ) as usize;

    if content_len > padded.len() - 4 {
        return Err(MessageError::InvalidPadding);
    }

    Ok(&padded[4..4 + content_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_empty_produces_smallest_bucket() {
        let padded = pad_to_bucket(&[]).unwrap();
        assert_eq!(padded.len(), 256); // 128 bucket removed (S07 §5.1)
    }

    #[test]
    fn pad_small_message_fits_256() {
        let msg = b"hello";
        let padded = pad_to_bucket(msg).unwrap();
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pad_produces_correct_bucket_sizes() {
        // Test each bucket boundary
        for &bucket in BUCKETS {
            // Payload that just fits: bucket - 4 (length prefix) - 1 (min padding)
            let max_payload = bucket - 5;
            let padded = pad_to_bucket(&vec![0xAA; max_payload]).unwrap();
            assert_eq!(
                padded.len(),
                bucket,
                "payload of {} bytes should fit in {} bucket",
                max_payload,
                bucket
            );
        }
    }

    #[test]
    fn pad_boundary_bumps_to_next_bucket() {
        // Payload that is exactly bucket - 4 (no room for 1 byte padding)
        let payload_size = 256 - 4;
        let padded = pad_to_bucket(&vec![0xBB; payload_size]).unwrap();
        assert_eq!(padded.len(), 512);
    }

    #[test]
    fn pad_payload_targets_deposited_blob_bucket() {
        // S07 §5.1.1: deposited_blob = fixed_overhead + padded_plaintext must
        // land on a §5.1 bucket. For 0x02 (fixed=160) a 100-byte payload can't
        // fit 256−160=96, so it targets 512−160=352 → deposited blob = 512.
        let payload = vec![0x7Au8; 100];
        let padded = pad_payload(&payload, 160).unwrap();
        assert_eq!(padded.len(), 512 - 160);
        assert_eq!(160 + padded.len(), 512, "deposited blob lands on a bucket");
        assert_eq!(&padded[..100], &payload[..]);
        assert!(
            padded[100..].iter().all(|&b| b == 0x00),
            "padding must be all 0x00 (§5.2)"
        );
    }

    #[test]
    fn pad_payload_smallest_bucket_when_it_fits() {
        // A payload that fits 256−160=96 lands the deposited blob on 256.
        let payload = vec![0x11u8; 96];
        let padded = pad_payload(&payload, 160).unwrap();
        assert_eq!(padded.len(), 96);
        assert_eq!(160 + padded.len(), 256);
    }

    #[test]
    fn pad_payload_initial_skips_256_bucket() {
        // 0x01 Initial fixed_overhead 263 > 256, so the 256 bucket is unusable
        // (S07 §5.1.1) — the smallest deposited blob is 512.
        let padded = pad_payload(&[0u8; 10], 263).unwrap();
        assert_eq!(263 + padded.len(), 512);
    }

    #[test]
    fn pad_payload_rejects_oversize() {
        // Largest 0x02 payload = 262144 − 160 = 261984.
        assert!(pad_payload(&vec![0u8; 261_984], 160).unwrap().len() == 261_984);
        assert!(pad_payload(&vec![0u8; 261_985], 160).is_err());
    }

    #[test]
    fn unpad_recovers_plaintext() {
        let msg = b"hello, world!";
        let padded = pad_to_bucket(msg).unwrap();
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn unpad_large_message() {
        let msg = vec![0x42u8; 10000];
        let padded = pad_to_bucket(&msg).unwrap();
        assert_eq!(padded.len(), 16384);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, &msg[..]);
    }

    #[test]
    fn unpad_rejects_too_short() {
        assert!(unpad(&[0, 0, 0, 1]).is_err()); // Only 4 bytes
        assert!(unpad(&[]).is_err());
    }

    #[test]
    fn unpad_rejects_invalid_length() {
        // Length prefix says 100 bytes but only 10 available
        let mut bad = vec![0u8; 20];
        bad[0..4].copy_from_slice(&100u32.to_be_bytes());
        assert!(unpad(&bad).is_err());
    }

    #[test]
    fn largest_bucket_accepts_max_payload() {
        // Payload that exactly fits largest bucket: 262144 - 4 (prefix) - 1 (min pad) = 262139
        let msg = vec![0xCC; 262_139];
        let padded = pad_to_bucket(&msg).unwrap();
        assert_eq!(padded.len(), 262_144);
    }

    #[test]
    fn oversized_message_rejected() {
        // Message larger than largest bucket capacity
        let msg = vec![0xCC; 262_140];
        assert!(pad_to_bucket(&msg).is_err());
    }
}
