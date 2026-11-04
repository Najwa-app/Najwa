//! Prekey endpoints: upload and fetch (S16 §3.6/§3.7).

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::api::capability::{decode_cap, make_pow_challenge, verify_solution, PowSolutionInput};
use crate::api::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// POST /v1/prekey/upload
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UploadRequest {
    pub deposit_capability: String,
    /// Owner proof (S16 §3.6): the queue's fetch capability. Required; parsed
    /// as optional so a missing proof gets the same 404 as a wrong one.
    #[serde(default)]
    pub fetch_capability: Option<String>,
    /// Owner recovery replacement: drop available OPKs not in this upload.
    #[serde(default)]
    pub replace_opks: bool,
    pub bundle: PrekeyBundleInput,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PrekeyBundleInput {
    #[serde(rename = "mailbox_ik_pub", alias = "identity_key")]
    pub identity_key: String, // base64(32 bytes) — mailbox_ik_pub
    pub signed_prekey: String, // base64(32 bytes)
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: String, // base64(64 bytes)
    /// S16 §3.6: SPK creation time; part of the SPK signature input (S06 §4.2).
    #[serde(default)]
    pub signed_prekey_timestamp: u64,
    #[serde(default)]
    pub one_time_prekeys: Vec<OtpkInput>,
    /// Opaque signed bundle manifest (S06 §2.2 1a). The mailbox cannot verify the
    /// client's signature — it stores + returns it verbatim so initiators can.
    #[serde(default)]
    pub manifest: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct OtpkInput {
    pub id: u32,
    pub key: String, // base64(32 bytes)
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub status: &'static str,
    pub prekeys_stored: u32,
}

pub async fn upload(
    State(state): State<AppState>,
    Json(req): Json<UploadRequest>,
) -> Result<Json<UploadResponse>, ApiError> {
    let deposit_cap = decode_cap(&req.deposit_capability)?;

    for (name, encoded, expected) in [
        ("identity_key", &req.bundle.identity_key, 32),
        ("signed_prekey", &req.bundle.signed_prekey, 32),
        (
            "signed_prekey_signature",
            &req.bundle.signed_prekey_signature,
            64,
        ),
    ] {
        if B64
            .decode(encoded)
            .map_or(true, |bytes| bytes.len() != expected)
        {
            return Err(ApiError::BadRequest(format!("invalid {name}")));
        }
    }

    // S16 §3.6 step 2: only the owner may upload. Check the fetch capability in
    // constant time before revealing any state: an unknown deposit capability
    // and a missing, malformed or wrong fetch capability get the same 404. Only
    // the owner can learn 410.
    let supplied = req
        .fetch_capability
        .as_deref()
        .and_then(|proof| decode_cap(proof).ok());
    let fetch_cap = match (state.db.lookup_deposit_cap_state(&deposit_cap)?, supplied) {
        (Some((fc, inactive, _)), Some(supplied))
            if supplied
                .iter()
                .zip(fc.iter())
                .fold(0u8, |diff, (a, b)| diff | (a ^ b))
                == 0 =>
        {
            if inactive {
                return Err(ApiError::Gone("capability has been deactivated".into()));
            }
            fc
        }
        _ => return Err(ApiError::NotFound("deposit capability not found".into())),
    };
    let replace = req.replace_opks;

    // Serialize the bundle (without OPKs — they go in their own table)
    let bundle_json = serde_json::to_string(&BundleJson {
        identity_key: req.bundle.identity_key.clone(),
        signed_prekey: req.bundle.signed_prekey.clone(),
        signed_prekey_id: req.bundle.signed_prekey_id,
        signed_prekey_signature: req.bundle.signed_prekey_signature.clone(),
        signed_prekey_timestamp: req.bundle.signed_prekey_timestamp,
        manifest: req.bundle.manifest.clone(),
    })
    .map_err(|e| ApiError::Internal(format!("json serialization failed: {e}")))?;

    // Decode OPKs
    let mut opks = Vec::with_capacity(req.bundle.one_time_prekeys.len());
    for otpk in &req.bundle.one_time_prekeys {
        let key_bytes = B64
            .decode(&otpk.key)
            .map_err(|_| ApiError::BadRequest("invalid base64 in OPK key".into()))?;
        if key_bytes.len() != 32 {
            return Err(ApiError::BadRequest("OPK key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        opks.push((otpk.id, arr));
    }

    // S06 §2.2 / S16 §3.6: a bundle that carries OPKs MUST carry the signed
    // manifest; without it the initiator cannot detect OPK withholding. A
    // bundle with no OPKs may omit it, and initiators then reject the bundle:
    // only a signed opk_count == 0 authorizes 3-DH (S06 §2.2 step 1b).
    if !req.bundle.one_time_prekeys.is_empty() && req.bundle.manifest.is_none() {
        return Err(ApiError::BadRequest(
            "signed manifest required when uploading one-time prekeys (S06 §2.2)".into(),
        ));
    }

    let now = chrono::Utc::now().timestamp();
    let upload = if replace {
        crate::db::Database::replace_prekey_bundle
    } else {
        crate::db::Database::upload_prekey_bundle
    };
    let total = upload(
        &state.db,
        &fetch_cap,
        &bundle_json,
        &opks,
        state.config.quotas.max_opks_per_capability,
        now,
    )
    .map_err(|error| match error {
        crate::db::PrekeyUploadError::Conflict => ApiError::BadRequest("prekey ID reused".into()),
        crate::db::PrekeyUploadError::Quota => ApiError::QuotaExceeded("OPK quota exceeded".into()),
        crate::db::PrekeyUploadError::Inactive => ApiError::Gone("capability is inactive".into()),
        crate::db::PrekeyUploadError::Database(error) => error.into(),
    })?;

    Ok(Json(UploadResponse {
        status: "ok",
        prekeys_stored: total,
    }))
}

/// Stored bundle JSON (without OPKs, which are in their own table).
#[derive(Serialize, Deserialize)]
struct BundleJson {
    #[serde(rename = "mailbox_ik_pub", alias = "identity_key")]
    identity_key: String,
    signed_prekey: String,
    signed_prekey_id: u32,
    signed_prekey_signature: String,
    #[serde(default)]
    signed_prekey_timestamp: u64,
    #[serde(default)]
    manifest: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// POST /v1/prekey/fetch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FetchPrekeyRequest {
    pub deposit_capability: String,
    /// PoW solution when a prior fetch was rate-limited (S16 §7.1/§7.2:
    /// prekey-fetch binding = deposit_cap, blob_hash = zeros).
    #[serde(default)]
    pub pow_solution: Option<PowSolutionInput>,
}

#[derive(Serialize)]
pub struct FetchPrekeyResponse {
    #[serde(rename = "mailbox_ik_pub")]
    pub identity_key: String,
    pub signed_prekey: String,
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: String,
    pub signed_prekey_timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_prekeys: Option<Vec<OtpkOutput>>,
    /// Opaque signed manifest (S06 §2.2 1a), returned verbatim from upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct OtpkOutput {
    pub id: u32,
    pub key: String,
}

pub async fn fetch_prekey(
    State(state): State<AppState>,
    Json(req): Json<FetchPrekeyRequest>,
) -> Result<Json<FetchPrekeyResponse>, ApiError> {
    let deposit_cap = decode_cap(&req.deposit_capability)?;

    // Look up fetch_cap from deposit_cap (S16 §3.7 step 1)
    let (fetch_cap, capability_type) = match state.db.lookup_deposit_cap_state(&deposit_cap)? {
        Some((fc, false, cap_type)) => (fc, cap_type),
        Some((_, true, _)) => {
            return Err(ApiError::Gone("capability has been deactivated".into()));
        }
        None => {
            return Err(ApiError::NotFound(
                "deposit capability not found or no bundle uploaded".into(),
            ));
        }
    };

    // §7.2 prekey-fetch: above the per-cap rate threshold, require a PoW solution
    // bound to deposit_cap (§7.1: blob_hash = zeros); issue a challenge otherwise.
    let rate = state.prekey_fetch_limiter.record(&deposit_cap);
    if rate > state.config.rate_limits.prekey_fetch_per_min {
        return Err(ApiError::TooManyRequests(
            "prekey fetch rate limit exceeded".into(),
        ));
    }
    if rate > state.config.pow.prekey_fetch_pow_threshold_per_min {
        match &req.pow_solution {
            Some(sol) => verify_solution(&state, sol, &deposit_cap, &[0u8; 32], 8)?,
            None => return make_pow_challenge(&state, 8, 20), // §7.2 floor 8–20 bits
        }
    }

    // Fetch bundle + consume one OPK (type-1 caps: idempotent, cached after first).
    let (bundle_json, consumed_opk) = state
        .db
        .fetch_prekey_bundle(&fetch_cap, capability_type)?
        .ok_or_else(|| {
            ApiError::NotFound("no prekey bundle uploaded for this capability".into())
        })?;

    let bundle: BundleJson = serde_json::from_str(&bundle_json)
        .map_err(|e| ApiError::Internal(format!("corrupt bundle json: {e}")))?;

    let opks = consumed_opk.map(|(id, key)| {
        vec![OtpkOutput {
            id,
            key: B64.encode(key),
        }]
    });

    Ok(Json(FetchPrekeyResponse {
        identity_key: bundle.identity_key,
        signed_prekey: bundle.signed_prekey,
        signed_prekey_id: bundle.signed_prekey_id,
        signed_prekey_signature: bundle.signed_prekey_signature,
        signed_prekey_timestamp: bundle.signed_prekey_timestamp,
        one_time_prekeys: opks,
        manifest: bundle.manifest,
    }))
}
