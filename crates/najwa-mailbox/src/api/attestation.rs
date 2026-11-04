//! Operator attestation endpoint (S16 §3.10).
//!
//! Returns a signed JSON with operator metadata. This allows clients
//! to verify the operator's identity and jurisdiction.

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::error::ApiError;
use crate::state::AppState;

/// Attestation response (S16 §3.10).
#[derive(Serialize)]
pub struct AttestationResponse {
    pub operator_id: String,
    pub jurisdiction: String,
    pub infrastructure_provider: String,
    pub onion_address: String,
    pub timestamp: i64,
    /// Ed25519 signature over [`attestation_digest`]. Base64-encoded (64
    /// bytes). Empty if operator key not configured. `operator_id` is NOT
    /// hashed in — the signature is verified under that very key, so binding
    /// it into the preimage would be redundant.
    pub signature: String,
}

/// Domain label of the attestation digest (S16 §3.10). `v2`: the unlabelled
/// v1 digest joined the text fields with no separators.
pub const ATTESTATION_LABEL: &[u8] = b"najwa-operator-attestation-v2";

/// S16 §3.10: `SHA256(label ‖ for each of onion_address, jurisdiction,
/// infrastructure_provider: len(8 BE) ‖ UTF-8 ‖ timestamp(8 BE))`. The length
/// prefixes fix the field boundaries, so `"ab" + "c"` and `"a" + "bc"` sign
/// differently. Verifiers (the onion probe) build the same bytes.
pub fn attestation_digest(
    onion_address: &str,
    jurisdiction: &str,
    infrastructure_provider: &str,
    timestamp: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTATION_LABEL);
    for field in [onion_address, jurisdiction, infrastructure_provider] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

/// GET /v1/attestation
///
/// Returns operator attestation signed with the server's Ed25519 key (S16 §3.10).
/// If no operator key is configured, returns unsigned attestation (empty signature).
pub async fn attestation(
    State(state): State<AppState>,
) -> Result<Json<AttestationResponse>, ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let cfg = &state.config.attestation;
    let onion = &state.config.server.onion_address;

    let signable = attestation_digest(onion, &cfg.jurisdiction, &cfg.infrastructure_provider, now);

    // Sign with the operator key resolved at startup (file wins over inline
    // seed); unsigned (empty) fields when none is configured.
    let (operator_id, signature) = match state.operator_signing_key() {
        Some(signing_key) => {
            use ed25519_dalek::{Signer, Verifier};
            let pub_key = signing_key.verifying_key();
            let sig = signing_key.sign(&signable);
            pub_key
                .verify(&signable, &sig)
                .expect("self-signed attestation verifies");
            (B64.encode(pub_key.as_bytes()), B64.encode(sig.to_bytes()))
        }
        None => (String::new(), String::new()),
    };

    Ok(Json(AttestationResponse {
        operator_id,
        jurisdiction: cfg.jurisdiction.clone(),
        infrastructure_provider: cfg.infrastructure_provider.clone(),
        onion_address: onion.clone(),
        timestamp: now,
        signature,
    }))
}

#[cfg(test)]
mod tests {
    use super::attestation_digest;

    /// The signed bytes must fix field boundaries: moving a character from one
    /// field to its neighbour changes the digest.
    #[test]
    fn digest_binds_field_boundaries() {
        let base = attestation_digest("onion", "ab", "c", 1);
        assert_ne!(base, attestation_digest("onion", "a", "bc", 1));
        assert_ne!(base, attestation_digest("onionab", "", "c", 1));
        assert_eq!(base, attestation_digest("onion", "ab", "c", 1));
    }
}
