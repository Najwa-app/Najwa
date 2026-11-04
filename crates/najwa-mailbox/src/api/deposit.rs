//! Deposit endpoint (S16 §3.3).

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::api::capability::{decode_cap, make_pow_challenge, verify_solution, PowSolutionInput};
use crate::api::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct DepositRequest {
    pub deposit_capability: String,
    pub blob: String, // base64-encoded encrypted message
    pub pow_solution: Option<PowSolutionInput>,
}

#[derive(Serialize)]
pub struct DepositResponse {
    pub accepted: bool,
    pub message_id: String,
}

pub async fn deposit(
    State(state): State<AppState>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, ApiError> {
    let deposit_cap = decode_cap(&req.deposit_capability)?;
    // S16 §12: never log capability tokens or message ids.
    tracing::debug!(blob_len = req.blob.len(), "deposit request received");

    // S16 §3.3 step 1 — shape validation FIRST. Decode + size-check the blob BEFORE
    // the capability lookup: these outcomes (400 malformed / 413 too large) are
    // capability-independent, so returning them here leaks nothing about lifecycle,
    // and doing them before the lookup stops oversized-blob probing from becoming a
    // capability oracle.
    let blob = B64
        .decode(&req.blob)
        .map_err(|_| ApiError::BadRequest("invalid base64 in blob".into()))?;
    if blob.is_empty() {
        return Err(ApiError::BadRequest("empty blob is not allowed".into()));
    }
    let checker = state.quota_checker();
    checker
        .check_blob_size(blob.len())
        .map_err(|e| ApiError::PayloadTooLarge(e.to_string()))?;

    // S16 §3.3 step 2 / §8 — rate ceiling (60/min per deposit_cap), counted for
    // EVERY well-formed capability BEFORE the lookup, so an unknown or dead
    // capability hits the same 429 as a live one.
    let rate = state.deposit_limiter.record(&deposit_cap);
    if rate > state.config.rate_limits.deposit_per_min_per_cap {
        return Err(ApiError::TooManyRequests(
            "deposit rate limit exceeded".into(),
        ));
    }

    // S16 §3.3 step 3 — look up the capability. A well-formed deposit to an
    // UNKNOWN, DEACTIVATED, or EXPIRED capability is SILENTLY DROPPED: return
    // `200 {accepted:true}` with a syntactically valid fake `message_id` and
    // store NOTHING. Returning 404/410 here is a capability-lifecycle oracle —
    // anyone holding a deposit cap could probe when the recipient deactivated or
    // rotated it — and is FORBIDDEN on the deposit path. The fake id is a keyed
    // hash of (deposit_cap, blob) laid out as msg-<uuidv4>, so it looks like a
    // real one and a repeated blob gets the same id, as live dedup gives. A dead
    // row keeps its stored type and limits, and an unknown capability is treated
    // as type 2, so PoW and 413 below answer exactly as for a live capability.
    let cap_state = state.db.lookup_deposit_cap_state(&deposit_cap)?;
    let capability_type = cap_state.map_or(2, |(_, _, cap_type)| cap_type);
    let blob_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&blob).into()
    };

    // §7.2 adaptive PoW: type-1 (ephemeral) caps ALWAYS require PoW (always-on
    // floor); type-2 only above the PoW threshold.
    let ephemeral_floor = state.config.pow.ephemeral_deposit_min_difficulty;
    // A configured floor of 0 means the operator disabled the ephemeral always-on
    // PoW outright, so type-1 falls back to the same rate-triggered rule as
    // type-2 rather than demanding a 0-bit challenge the client must round-trip
    // for nothing.
    let ephemeral_always_on = capability_type == 1 && ephemeral_floor > 0;
    if ephemeral_always_on || rate > state.config.pow.deposit_pow_threshold_per_min {
        // §7.2 deposit floor: type-1 caps `ephemeral_deposit_min_difficulty`
        // (16 by default), type-2 caps 8 — both adaptive by load up to the
        // operator's ceiling.
        let min_floor = if capability_type == 1 {
            ephemeral_floor
        } else {
            8
        };
        match &req.pow_solution {
            // §7.1 deposit binding: deposit_cap + SHA256(blob).
            Some(sol) => verify_solution(&state, sol, &deposit_cap, &blob_hash, min_floor)?,
            None => return make_pow_challenge(&state, min_floor, state.config.pow.max_difficulty),
        }
    }

    // Unknown capability: the type-2 size limit is `max_blob_size_bytes`, already
    // enforced in step 1, so drop here. Dead rows continue into the transaction,
    // which applies their registered `max_message_size` before dropping.
    let Some((fetch_cap, _, _)) = cap_state else {
        state.note_silent_drop();
        return Ok(Json(DepositResponse {
            accepted: true,
            message_id: state.discard_message_id(&deposit_cap, &blob_hash),
        }));
    };

    // S16 §3.3 steps 4–8 — size, dedup, quota + store, ATOMICALLY. Count, storage, dedup
    // and insert all run under one DB lock (closes the check-then-insert TOCTOU).
    // Type-1 caps get the reduced quota (S16 §9): `ephemeral_max_messages` /
    // `ephemeral_max_storage_mb` (default 100 msgs / 8 MiB) vs type-2
    // `max_messages_per_capability` / `max_storage_per_capability_mb`
    // (default 4096 msgs / 512 MiB).
    let (max_messages, max_storage_bytes) = if capability_type == 1 {
        (
            state.config.quotas.ephemeral_max_messages,
            state.config.quotas.ephemeral_max_storage_mb * 1024 * 1024,
        )
    } else {
        (checker.max_messages, checker.max_storage_bytes)
    };
    let now = chrono::Utc::now().timestamp();
    let outcome = state.db.deposit_message_checked(
        &fetch_cap,
        &deposit_cap,
        &blob,
        now,
        &state.config.batching,
        max_messages,
        max_storage_bytes,
    )?;
    let msg_id = match outcome {
        crate::db::DepositOutcome::Stored(id) => id,
        crate::db::DepositOutcome::Dropped => {
            state.note_silent_drop();
            state.discard_message_id(&deposit_cap, &blob_hash)
        }
        crate::db::DepositOutcome::BlobTooLarge => {
            return Err(ApiError::PayloadTooLarge(
                "capability message size exceeded".into(),
            ))
        }
        crate::db::DepositOutcome::MessageQuotaExceeded => {
            return Err(ApiError::QuotaExceeded("message quota exceeded".into()))
        }
        crate::db::DepositOutcome::StorageQuotaExceeded => {
            return Err(ApiError::QuotaExceeded("storage quota exceeded".into()))
        }
    };

    // S16 §12: no msg_id / capability tokens in logs.
    tracing::debug!(
        blob_bytes = blob.len(),
        "deposit: message stored (S16 §3.3)"
    );

    Ok(Json(DepositResponse {
        accepted: true,
        message_id: msg_id,
    }))
}
