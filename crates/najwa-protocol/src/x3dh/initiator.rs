//! X3DH initiator (Alice) side (S06 §2.2).

use najwa_crypto::kdf::hkdf_sha256;
use najwa_crypto::keys::conversion::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::keys::x25519::X25519KeyPair;
use zeroize::{Zeroize, Zeroizing};

use super::error::{Result, X3DHError};
use super::types::{PrekeyManifest, X3DHHeader, X3DHPrekeyBundle, X3DHResult};

/// Verify a fetched bundle's signed manifest and enforce the 3-DH acceptance
/// rule (S06 §2.2 steps 1a/1b). Call this after fetching a bundle and before
/// [`x3dh_initiate`], passing the responder's known per-mailbox signing key.
///
/// - No manifest → reject; there is no legacy downgrade exception.
/// - Manifest present → verify its signature against `mailbox_ik_pub`, bind it to
///   the served `spk_id`, and (Option A, strict fail-safe) reject if it commits
///   to OPKs (`opk_count > 0`) but the mailbox served none. On [`X3DHError::OpkWithheld`]
///   the caller MUST retry the fetch on a different mailbox; 3-DH is acceptable
///   only when the signed `opk_count == 0`.
pub fn check_bundle_manifest(
    bundle: &crate::mailbox::types::PrekeyBundle,
    mailbox_ik_pub: &Ed25519Public,
) -> Result<()> {
    let Some(m) = &bundle.manifest else {
        return Err(X3DHError::ManifestInvalid);
    };
    let sig_bytes: [u8; 64] = m
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| X3DHError::ManifestInvalid)?;
    let signature =
        Ed25519Signature::from_bytes(&sig_bytes).map_err(|_| X3DHError::ManifestInvalid)?;
    let manifest = PrekeyManifest {
        // The manifest is bound to the served SPK id (S06 §2.2 step 1a).
        spk_id: bundle.signed_prekey_id.to_be_bytes(),
        opk_id_set_hash: m.opk_id_set_hash,
        opk_count: m.opk_count,
        timestamp: m.timestamp,
        signature,
    };
    manifest
        .verify(mailbox_ik_pub)
        .map_err(|_| X3DHError::ManifestInvalid)?;
    if m.opk_ids.len() > 200
        || m.opk_ids.len() != m.opk_count as usize
        || m.opk_ids.windows(2).any(|ids| ids[0] >= ids[1])
        || super::types::opk_id_set_hash(&m.opk_ids) != m.opk_id_set_hash
        || bundle
            .one_time_prekeys
            .iter()
            .any(|opk| m.opk_ids.binary_search(&opk.id).is_err())
    {
        return Err(X3DHError::ManifestInvalid);
    }
    // S06 §2.2 step 1b: a signed commitment to OPKs with none served is a downgrade attempt.
    if manifest.opk_count > 0 && bundle.one_time_prekeys.is_empty() {
        return Err(X3DHError::OpkWithheld);
    }
    Ok(())
}

/// Perform the initiator side of X3DH (S06 §2.2).
///
/// # Steps
///
/// 1. Verify SPK signature (MUST succeed or hard-abort).
/// 2. Generate fresh ephemeral key pair.
/// 3. Convert identity keys Ed25519 → X25519 for DH.
/// 4. Compute 3 or 4 DH values.
/// 5. Derive shared secret via HKDF-SHA256.
/// 6. Build associated data and header.
///
/// # Security
///
/// - Ephemeral key is generated fresh for each call (S06 §2.2 step 2).
/// - All intermediate DH values are zeroized after SK derivation (S06 §2.2 step 7).
pub fn x3dh_initiate(
    our_identity: &Ed25519KeyPair,
    their_bundle: &X3DHPrekeyBundle,
) -> Result<X3DHResult> {
    if their_bundle.one_time_prekey.is_some() != their_bundle.one_time_prekey_id.is_some() {
        return Err(X3DHError::ManifestInvalid);
    }
    // 1. Verify signed prekey signature — hard abort on failure (S06 §2.2 step 1c)
    their_bundle
        .verify_spk_signature()
        .map_err(|_| X3DHError::InvalidSignature)?;

    // 2. Generate ephemeral key pair (fresh per initiation)
    let mut rng = rand::rngs::OsRng;
    let ephemeral = X25519KeyPair::generate(&mut rng);

    // 3. Convert identity keys to X25519 for DH
    let our_ik_x25519 = ed25519_priv_to_x25519(our_identity.private());
    let their_ik_x25519 = ed25519_pub_to_x25519(&their_bundle.identity_key)
        .map_err(|e| X3DHError::KeyConversionFailed(e.to_string()))?;

    // 4. Compute DH values
    //    DH1 = DH(IK_A, SPK_B)  — our identity × their signed prekey
    //    DH2 = DH(EK_A, IK_B)   — our ephemeral × their identity
    //    DH3 = DH(EK_A, SPK_B)  — our ephemeral × their signed prekey
    //    DH4 = DH(EK_A, OPK_B)  — our ephemeral × their one-time prekey [optional]
    let our_ik_x25519_kp = x25519_kp_from_private(our_ik_x25519);
    let dh1 = our_ik_x25519_kp.diffie_hellman(&their_bundle.signed_prekey)?;
    let dh2 = ephemeral.diffie_hellman(&their_ik_x25519)?;
    let dh3 = ephemeral.diffie_hellman(&their_bundle.signed_prekey)?;

    // 5. Concatenate DH outputs
    let mut dh_concat = Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(ref opk) = their_bundle.one_time_prekey {
        let dh4 = ephemeral.diffie_hellman(opk)?;
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // 6. Derive shared secret via HKDF-SHA256 (S06 §2.2)
    //    salt = 32 zero bytes; info = X3DH_INFO_PREFIX || X_IK_A_pub || X_IK_B_pub
    //    where A = initiator (us), B = responder (them), both converted to X25519.
    let info = super::x3dh_info(
        &our_ik_x25519_kp.public().to_bytes(),
        &their_ik_x25519.to_bytes(),
    );
    let sk_vec = Zeroizing::new(
        hkdf_sha256(&dh_concat, &[0u8; 32], &info, 32)
            .map_err(|e| X3DHError::KeyDerivationFailed(e.to_string()))?,
    );

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);

    // Zeroize intermediate DH concatenation
    dh_concat.zeroize();

    // 7. Build associated data: AD = Encode(IK_A) || Encode(IK_B)
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(&our_identity.public().to_bytes());
    associated_data.extend_from_slice(&their_bundle.identity_key.to_bytes());

    // 8. Build header
    let header = X3DHHeader {
        identity_key: our_identity.public().clone(),
        ephemeral_key: ephemeral.public().clone(),
        // Single-device: device_key == IK_pub (S06 §2.4, §7).
        device_key: our_identity.public().clone(),
        used_one_time_prekey_id: their_bundle.one_time_prekey_id,
        signed_prekey_id: their_bundle.signed_prekey_id,
    };

    Ok(X3DHResult {
        shared_secret,
        // S06 §3.2: retain EK_A's private so init_alice can use it as the first
        // sending-ratchet DH key (binding the ratchet to the authenticated X3DH).
        ephemeral_seed: ephemeral.private().to_bytes(),
        header,
        associated_data,
    })
}

/// Helper: construct an X25519KeyPair from a converted X25519Private.
///
/// We need the full key pair to call `diffie_hellman`, but the converted
/// private key doesn't come with its public half. We derive it.
fn x25519_kp_from_private(private: najwa_crypto::keys::x25519::X25519Private) -> X25519KeyPair {
    X25519KeyPair::from_seed(private.to_bytes())
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use crate::mailbox::types::{OneTimePrekey, PrekeyBundle};
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;

    /// Build a wire bundle whose manifest commits to `opk_ids`, optionally serving
    /// one OPK. `signed_prekey_id` is fixed at 7 (the manifest binds to it).
    fn bundle_with(mailbox_kp: &Ed25519KeyPair, opk_ids: &[u32], serve_opk: bool) -> PrekeyBundle {
        let spk_id: u32 = 7;
        let manifest = crate::x3dh::types::build_wire_manifest(
            mailbox_kp,
            &spk_id.to_be_bytes(),
            opk_ids,
            1000,
        );
        let one_time_prekeys = if serve_opk && !opk_ids.is_empty() {
            vec![OneTimePrekey {
                id: opk_ids[0],
                key: [9u8; 32],
            }]
        } else {
            vec![]
        };
        PrekeyBundle {
            identity_key: mailbox_kp.public().to_bytes(),
            signed_prekey: [1u8; 32],
            signed_prekey_id: spk_id,
            signed_prekey_signature: vec![0u8; 64],
            signed_prekey_timestamp: 1000,
            one_time_prekeys,
            manifest: Some(manifest),
        }
    }

    #[test]
    fn ok_when_opk_served() {
        let kp = Ed25519KeyPair::from_seed(&[1u8; 32]);
        check_bundle_manifest(&bundle_with(&kp, &[10, 20, 30], true), kp.public()).unwrap();
    }

    #[test]
    fn withheld_when_committed_but_none_served() {
        let kp = Ed25519KeyPair::from_seed(&[2u8; 32]);
        assert!(matches!(
            check_bundle_manifest(&bundle_with(&kp, &[10, 20, 30], false), kp.public()),
            Err(X3DHError::OpkWithheld)
        ));
    }

    #[test]
    fn signed_zero_authorizes_3dh() {
        // opk_count == 0 with no OPK served is the ONLY acceptable 3-DH fallback.
        let kp = Ed25519KeyPair::from_seed(&[3u8; 32]);
        check_bundle_manifest(&bundle_with(&kp, &[], false), kp.public()).unwrap();
    }

    #[test]
    fn tampered_count_rejected() {
        let kp = Ed25519KeyPair::from_seed(&[4u8; 32]);
        let mut b = bundle_with(&kp, &[10, 20], true);
        b.manifest.as_mut().unwrap().opk_count = 99; // signature no longer matches
        assert!(matches!(
            check_bundle_manifest(&b, kp.public()),
            Err(X3DHError::ManifestInvalid)
        ));
    }

    #[test]
    fn wrong_signing_key_rejected() {
        let kp = Ed25519KeyPair::from_seed(&[5u8; 32]);
        let other = Ed25519KeyPair::from_seed(&[6u8; 32]);
        assert!(matches!(
            check_bundle_manifest(&bundle_with(&kp, &[10], true), other.public()),
            Err(X3DHError::ManifestInvalid)
        ));
    }

    #[test]
    fn missing_manifest_is_rejected() {
        let kp = Ed25519KeyPair::from_seed(&[7u8; 32]);
        let mut b = bundle_with(&kp, &[10], true);
        b.manifest = None;
        assert!(matches!(
            check_bundle_manifest(&b, kp.public()),
            Err(X3DHError::ManifestInvalid)
        ));
        b.one_time_prekeys.clear();
        assert!(
            matches!(
                check_bundle_manifest(&b, kp.public()),
                Err(X3DHError::ManifestInvalid)
            ),
            "stripping both the manifest and OPK must not authorize 3-DH"
        );
    }

    #[test]
    fn survives_json_roundtrip() {
        // Mirrors upload -> mailbox stores opaque JSON -> fetch -> initiator verify.
        let kp = Ed25519KeyPair::from_seed(&[8u8; 32]);
        let b = bundle_with(&kp, &[10, 20, 30], true);
        let json = serde_json::to_string(&b).unwrap();
        let b2: PrekeyBundle = serde_json::from_str(&json).unwrap();
        check_bundle_manifest(&b2, kp.public()).unwrap();
    }
}
