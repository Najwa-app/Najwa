//! Capability endpoints: register, deactivate, status (S16 §3.1, §3.9, §3.8).

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::api::error::{ApiError, PowChallengeResponse};
use crate::db::RegisterResult;
use crate::pow;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// POST /v1/capability/register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub fetch_capability: String,
    pub deposit_capability: String,
    /// S16 §3.1: 1 = ephemeral handshake (server clamps lifetime to <= 48h),
    /// 2 = long-term. Absent ⇒ long-term (backward compatible with older clients).
    pub capability_type: Option<u8>,
    /// S16 §3.1: absolute expiry (Unix seconds). Clamped server-side for type-1.
    pub expires_at: Option<i64>,
    pub pow_solution: Option<PowSolutionInput>,
    pub settings: Option<SettingsInput>,
}

#[derive(Deserialize)]
pub struct PowSolutionInput {
    pub challenge: String,
    pub nonce: u64,
    pub hash: String,
    /// S16 §7.1: solve-time Unix seconds, bound into the preimage and checked
    /// against the challenge's validity window.
    #[serde(default)]
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct SettingsInput {
    pub retention_days: Option<u32>,
    pub max_message_size: Option<usize>,
}

#[derive(Serialize)]
pub struct StatusOk {
    pub status: &'static str,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<StatusOk>, ApiError> {
    // S16 §13 step 2: a retiring server stops accepting NEW registrations
    // (existing capabilities keep working). Nothing in the API triggers
    // retirement — the operator sets `[server].retire_at` and restarts.
    if !state.is_accepting_registrations() {
        return Err(ApiError::ServiceUnavailable(
            "server is retiring; not accepting new registrations".into(),
        ));
    }

    // Decode capabilities
    let fetch_cap = decode_cap(&req.fetch_capability)?;
    let deposit_cap = decode_cap(&req.deposit_capability)?;

    // S16 §8: ceiling per fetch capability, counted before PoW like the other
    // limiters. It stops one pair being retried in a loop; registrations of
    // fresh pairs are priced by the always-on PoW below.
    if state.register_limiter.record(&fetch_cap) > state.config.rate_limits.register_per_min {
        return Err(ApiError::TooManyRequests(
            "registration rate limit exceeded".into(),
        ));
    }
    if state.config.pow.registration_always_requires_pow {
        let sol = match req.pow_solution.as_ref() {
            Some(s) => s,
            None => {
                // §7.2: registration floor 20–24 bits (adaptive by load).
                return make_pow_challenge(
                    &state,
                    state.config.pow.min_difficulty,
                    state.config.pow.max_difficulty,
                );
            }
        };
        // §7.1 registration binding: fetch_cap || deposit_cap (no blob).
        let mut cap_binding = Vec::with_capacity(64);
        cap_binding.extend_from_slice(&fetch_cap);
        cap_binding.extend_from_slice(&deposit_cap);
        verify_solution(
            &state,
            sol,
            &cap_binding,
            &[0u8; 32],
            state.config.pow.min_difficulty,
        )?;
    }

    // Build settings
    let settings = crate::db::models::CapabilitySettings {
        retention_days: req
            .settings
            .as_ref()
            .and_then(|s| s.retention_days)
            .unwrap_or(state.config.quotas.default_retention_days),
        max_message_size: req
            .settings
            .as_ref()
            .and_then(|s| s.max_message_size)
            .unwrap_or(state.config.quotas.max_blob_size_bytes),
    };

    let now = chrono::Utc::now().timestamp();
    // Default to long-term (type 2) when the client doesn't declare a type.
    let capability_type = req.capability_type.unwrap_or(2);
    if !matches!(capability_type, 1 | 2) {
        return Err(ApiError::BadRequest(
            "capability_type must be 1 or 2".into(),
        ));
    }
    if !(1..=90).contains(&settings.retention_days)
        || settings.max_message_size == 0
        || settings.max_message_size > state.config.quotas.max_blob_size_bytes
    {
        return Err(ApiError::BadRequest("invalid capability settings".into()));
    }
    let clamp_secs = state.config.capability_expiry.ephemeral_max_lifetime_hours as i64 * 3600;
    let result = state.db.register_capability(
        &fetch_cap,
        &deposit_cap,
        &settings,
        capability_type,
        req.expires_at,
        clamp_secs,
        now,
    )?;

    match result {
        RegisterResult::Created | RegisterResult::AlreadyExists => {
            Ok(Json(StatusOk { status: "ok" }))
        }
        RegisterResult::Conflict => Err(ApiError::Conflict("capability already registered".into())),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/capability/deactivate
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeactivateRequest {
    pub fetch_capability: String,
}

#[derive(Serialize)]
pub struct DeactivateResponse {
    pub status: &'static str,
    pub messages_deleted: u64,
}

pub async fn deactivate(
    State(state): State<AppState>,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<DeactivateResponse>, ApiError> {
    let fetch_cap = decode_cap(&req.fetch_capability)?;
    let messages_deleted = state
        .db
        .deactivate_capability(&fetch_cap)?
        .ok_or_else(|| ApiError::NotFound("capability not found or already deactivated".into()))?;

    Ok(Json(DeactivateResponse {
        status: "deactivated",
        messages_deleted,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/status
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct StatusRequest {
    pub fetch_capability: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub messages_stored: u64,
    pub quota_remaining: u64,
    pub oldest_message_age: u64,
    pub prekey_count: u32,
    /// Available OPKs, visible only to the fetch-capability owner.
    pub prekey_ids: Vec<u32>,
    pub current_retention_days: u32,
    /// S16 §3.7/§16: the OPK pool is at or below `[opk].low_alert_threshold` —
    /// set on the refuse-last-OPK boundary too (a drained pool is the point).
    pub opk_low: bool,
    /// S16 §6: signed batching-parameter attestation, present when
    /// `[attestation].publish_batching_attestation` is on and an operator key
    /// is configured (re-signed at most every 24 h).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batching_attestation: Option<crate::state::BatchingAttestation>,
    /// S16 §13: process-wide status, as in `/v1/health`.
    pub server_status: crate::api::health::ServerStatus,
    /// S16 §13: when a retiring server stops; present only when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retire_at: Option<i64>,
}

pub async fn status(
    State(state): State<AppState>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<StatusResponse>, ApiError> {
    let fetch_cap = decode_cap(&req.fetch_capability)?;

    let mut cap_status = state
        .db
        .capability_status(&fetch_cap)?
        .ok_or_else(|| ApiError::NotFound("capability not found".into()))?;

    // Override quota_remaining with actual config value
    let quota = if cap_status.capability_type == 1 {
        state.config.quotas.ephemeral_max_messages
    } else {
        state.config.quotas.max_messages_per_capability
    };
    cap_status.quota_remaining = quota.saturating_sub(cap_status.messages_stored);

    Ok(Json(StatusResponse {
        messages_stored: cap_status.messages_stored,
        quota_remaining: cap_status.quota_remaining,
        oldest_message_age: cap_status.oldest_message_age,
        prekey_count: cap_status.prekey_count,
        prekey_ids: cap_status.prekey_ids,
        current_retention_days: cap_status.retention_days,
        opk_low: cap_status.prekey_count <= state.config.opk.low_alert_threshold,
        batching_attestation: state.batching_attestation(),
        server_status: state.server_status(),
        retire_at: state.retire_at(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a base64-encoded 32-byte capability token.
pub fn decode_cap(b64: &str) -> Result<[u8; 32], ApiError> {
    let bytes = B64
        .decode(b64)
        .map_err(|_| ApiError::BadRequest("invalid base64 in capability".into()))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "capability must be exactly 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Verify a §7.1-bound PoW solution against a stored challenge. `cap_binding` is
/// the per-endpoint capability binding (`fetch_cap||deposit_cap` for register, or
/// `deposit_cap` for deposit/prekey/feed) and `blob_hash` is `SHA256(blob)` for
/// deposits (`zeros` otherwise). The solution is single-use (the challenge is
/// consumed), bound to this capability + blob, and its timestamp must fall within
/// the challenge's validity window.
pub fn verify_solution(
    state: &AppState,
    sol: &PowSolutionInput,
    cap_binding: &[u8],
    blob_hash: &[u8; 32],
    minimum_difficulty: u8,
) -> Result<(), ApiError> {
    let challenge_bytes = B64
        .decode(&sol.challenge)
        .map_err(|_| ApiError::BadRequest("invalid base64 in PoW challenge".into()))?;
    if challenge_bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "challenge must be exactly 32 bytes".into(),
        ));
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&challenge_bytes);

    let supplied = B64
        .decode(&sol.hash)
        .map_err(|_| ApiError::BadRequest("invalid base64 in PoW hash".into()))?;
    if supplied.len() != 32 {
        return Err(ApiError::BadRequest("hash must be exactly 32 bytes".into()));
    }
    let mut supplied_hash = [0u8; 32];
    supplied_hash.copy_from_slice(&supplied);

    let now = chrono::Utc::now().timestamp();
    let difficulty = state.challenges.consume(&challenge, now).ok_or_else(|| {
        ApiError::BadRequest("invalid, expired, or already used challenge".into())
    })?;

    // Challenges are shared across endpoints; a cheap prekey challenge must
    // never lower registration or ephemeral-deposit work requirements.
    if difficulty < minimum_difficulty {
        return Err(ApiError::BadRequest(
            "PoW challenge below required difficulty".into(),
        ));
    }

    // §7.1: the solve timestamp must fall within the challenge's validity window
    // (issued no earlier than `challenge_expiry_secs` ago, allowing small skew).
    let expiry = state.config.pow.challenge_expiry_secs as i64;
    let ts = sol.timestamp as i64;
    if ts > now + 60 || ts < now - expiry {
        return Err(ApiError::BadRequest(
            "PoW timestamp outside validity window".into(),
        ));
    }

    if !pow::verify_pow_bound(
        &challenge,
        cap_binding,
        sol.timestamp,
        blob_hash,
        sol.nonce,
        difficulty,
        &supplied_hash,
    ) {
        return Err(ApiError::BadRequest("PoW verification failed".into()));
    }

    Ok(())
}

/// Create a 429 RateLimited error with a fresh PoW challenge at the given
/// per-endpoint difficulty floor (S16 §7.2). `min_floor`/`max_floor` bound the
/// adaptive-by-load difficulty: registration 20–24, deposit type-2 8–24, deposit
/// type-1 16–24, prekey-fetch 8–20. Always returns `Err(RateLimited(..))`.
pub fn make_pow_challenge<T>(
    state: &AppState,
    min_floor: u8,
    max_floor: u8,
) -> Result<T, ApiError> {
    let challenge = pow::generate_challenge();
    let load = state.estimated_load_percent();
    let difficulty = pow::adaptive_difficulty(load, min_floor, max_floor);
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + state.config.pow.challenge_expiry_secs as i64;

    state.challenges.issue(challenge, difficulty, expires_at);

    Err(ApiError::RateLimited(PowChallengeResponse {
        challenge: B64.encode(challenge),
        difficulty,
        algorithm: "sha256-leading-zeros".into(),
        expires_at,
    }))
}
