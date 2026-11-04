//! AAD (Additional Authenticated Data) construction for identity encryption.
//!
//! See S02 §8.

use najwa_crypto::kdf::info_strings;

use crate::record::IdentityRecordStandard;

/// Build AAD for Standard Mode identity encryption (S02 §8).
///
/// Layout matches the record field order from S02 §7.1:
/// ```text
/// AAD_identity = magic(8) || version(1) || mode(1) || kdf_alg(1) || aead_alg(1) ||
///                argon2_memory(4,BE) || argon2_iterations(4,BE) || argon2_parallelism(1) ||
///                saltP(32) || ik_pub(32)
/// Total: 85 bytes
/// ```
///
/// **Note:** `reserved(3)` is included in the checksum but NOT in the AAD (S02 §7.3).
/// This allows future versions to use reserved bytes without breaking AAD compatibility.
pub fn build_aad_identity_standard(record: &IdentityRecordStandard) -> Vec<u8> {
    let mut aad = Vec::with_capacity(85);
    aad.extend_from_slice(&record.magic);
    aad.push(record.version);
    aad.push(record.mode);
    aad.push(record.kdf_alg);
    aad.push(record.aead_alg);
    aad.extend_from_slice(&record.argon2_memory.to_be_bytes());
    aad.extend_from_slice(&record.argon2_iterations.to_be_bytes());
    aad.push(record.argon2_parallelism);
    aad.extend_from_slice(&record.salt_p);
    aad.extend_from_slice(&record.ik_pub);
    aad
}

/// Build AAD for VK encryption (Hardware Mode).
///
/// Layout: `AAD_VK_ENCRYPT || mode || ik_pub`
pub fn build_aad_vk(mode: u8, ik_pub: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(55);
    aad.extend_from_slice(info_strings::AAD_VK_ENCRYPT);
    aad.push(mode);
    aad.extend_from_slice(ik_pub);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;

    #[test]
    fn aad_standard_deterministic() {
        let rec = IdentityRecordStandard {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_STANDARD,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            reserved: [0; 3],
            salt_p: [0x01; 32],
            nonce: [0; 24],
            ik_pub: [0x02; 32],
            enc_ik: [0; 48],
            checksum: [0; 32],
        };
        let aad1 = build_aad_identity_standard(&rec);
        let aad2 = build_aad_identity_standard(&rec);
        assert_eq!(aad1, aad2);
        // AAD starts with magic(8) per S02 §8.1, not the AAD_IK_ENCRYPT prefix
        assert_eq!(aad1.len(), 85);
        assert!(aad1.starts_with(&MAGIC));
    }

    #[test]
    fn aad_vk_contains_mode_and_pubkey() {
        let ik_pub = [0xAA; 32];
        let aad = build_aad_vk(MODE_HARDWARE, &ik_pub);
        assert!(aad.starts_with(info_strings::AAD_VK_ENCRYPT));
        assert!(aad.ends_with(&ik_pub));
    }
}
