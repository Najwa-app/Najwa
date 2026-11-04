//! X3DH responder (Bob) side (S06 §2.3).

use najwa_crypto::kdf::hkdf_sha256;
use najwa_crypto::keys::conversion::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;
use zeroize::{Zeroize, Zeroizing};

use super::error::{Result, X3DHError};
use super::types::{X3DHHeader, X3DHResult};

/// Perform the responder side of X3DH (S06 §2.3).
///
/// # Arguments
///
/// * `our_identity` – Responder's Ed25519 identity key pair (IK_B).
/// * `our_spk` – Responder's signed prekey pair (SPK_B, X25519).
/// * `our_opk` – Responder's one-time prekey pair (OPK_B) if one was used.
/// * `header` – The X3DH header received from the initiator.
///
/// # Security
///
/// - All intermediate DH values are zeroized after SK derivation (S06 §2.2 step 7).
/// - The caller MUST mark the OPK used in the receive commit (S06 §2.3 step 10).
pub fn x3dh_respond(
    our_identity: &Ed25519KeyPair,
    our_spk: &X25519KeyPair,
    our_opk: Option<&X25519KeyPair>,
    header: &X3DHHeader,
) -> Result<X3DHResult> {
    if our_opk.is_some() != header.used_one_time_prekey_id.is_some() {
        return Err(X3DHError::ManifestInvalid);
    }
    // 1. Convert identity keys to X25519
    let our_ik_x25519 = ed25519_priv_to_x25519(our_identity.private());
    let their_ik_x25519 = ed25519_pub_to_x25519(&header.identity_key)
        .map_err(|e| X3DHError::KeyConversionFailed(e.to_string()))?;

    // 2. Compute DH values (mirror of initiator)
    //    DH1 = DH(SPK_B, IK_A)   — our signed prekey × their identity
    //    DH2 = DH(IK_B, EK_A)    — our identity × their ephemeral
    //    DH3 = DH(SPK_B, EK_A)   — our signed prekey × their ephemeral
    //    DH4 = DH(OPK_B, EK_A)   — our one-time prekey × their ephemeral [optional]
    let dh1 = our_spk.diffie_hellman(&their_ik_x25519)?;
    let our_ik_x25519_kp = X25519KeyPair::from_seed(our_ik_x25519.to_bytes());
    let dh2 = our_ik_x25519_kp.diffie_hellman(&header.ephemeral_key)?;
    let dh3 = our_spk.diffie_hellman(&header.ephemeral_key)?;

    let mut dh_concat = Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = our_opk {
        let dh4 = opk.diffie_hellman(&header.ephemeral_key)?;
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // 3. Derive shared secret via HKDF-SHA256 (S06 §2.2)
    //    info = X3DH_INFO_PREFIX || X_IK_A_pub || X_IK_B_pub, where A = initiator
    //    (them), B = responder (us), both converted to X25519 — same order as the
    //    initiator so both derive the identical SK.
    let info = super::x3dh_info(
        &their_ik_x25519.to_bytes(),
        &our_ik_x25519_kp.public().to_bytes(),
    );
    let sk_vec = Zeroizing::new(hkdf_sha256(&dh_concat, &[0u8; 32], &info, 32)
        .map_err(|e| X3DHError::KeyDerivationFailed(e.to_string()))?);

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&sk_vec);

    // Zeroize intermediate DH concatenation
    dh_concat.zeroize();

    // 4. Build associated data: AD = Encode(IK_A) || Encode(IK_B)
    //    Note: order is initiator's IK first, then responder's IK.
    let mut associated_data = Vec::with_capacity(64);
    associated_data.extend_from_slice(&header.identity_key.to_bytes());
    associated_data.extend_from_slice(&our_identity.public().to_bytes());

    Ok(X3DHResult {
        shared_secret,
        // Initiator-only field (S06 §3.2): the responder keys its ratchet from
        // its own SPK via `init_bob`, never from EK_A, so this is unused here.
        ephemeral_seed: [0u8; 32],
        header: header.clone(),
        associated_data,
    })
}
