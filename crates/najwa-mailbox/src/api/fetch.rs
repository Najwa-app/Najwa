//! Fetch endpoint (S16 §3.4). No fetch cursor (acknowledgement, S16 §3.5, is
//! the only one); no server-side noise.

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::api::capability::decode_cap;
use crate::api::error::ApiError;
use crate::db::CapabilityState;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct FetchRequest {
    pub fetch_capability: String,
    // NOTE: there is no fetch cursor (S16 §3.4). `release_at` can be randomized
    // (S16 §6), so a message deposited earlier can become visible AFTER a
    // monotonic cursor has passed it; any `since_id` filter would silently skip
    // late-released messages (ratchet desync). `/v1/acknowledge` is the ONLY
    // cursor. A `since_id` field in a request is ignored — serde drops unknown
    // fields.
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub messages: Vec<FetchedMessage>,
    pub has_more: bool,
}

#[derive(Serialize)]
pub struct FetchedMessage {
    pub id: String,
    pub blob: String, // base64
    pub deposited_at: i64,
    pub size: i64,
    /// `SHA256(deposit_capability)[0:8]` — base64-encoded (S16 §3.4, S07 §3.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_hint: Option<String>,
}

pub async fn fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    let fetch_cap = decode_cap(&req.fetch_capability)?;
    tracing::debug!("fetch request received"); // S16 §12: no capability tokens in logs

    // Distinguish 404 (not found) from 410 (deactivated) per S16 §3.4
    match state.db.capability_state(&fetch_cap)? {
        CapabilityState::Active => {
            tracing::trace!("fetch: capability active");
        }
        CapabilityState::Deactivated => {
            tracing::debug!("fetch: capability deactivated");
            return Err(ApiError::Gone("capability has been deactivated".into()));
        }
        CapabilityState::NotFound => {
            tracing::debug!("fetch: capability not found");
            return Err(ApiError::NotFound("fetch capability not found".into()));
        }
    }

    // Rate limit (fetch is read-only — no PoW, just enforce ceiling)
    let rate = state.fetch_limiter.record(&fetch_cap);
    if rate > state.config.rate_limits.fetch_per_min_per_cap {
        return Err(ApiError::TooManyRequests(
            "fetch rate limit exceeded".into(),
        ));
    }

    // S16 §3.4: max 100, default 50
    let limit = req.limit.unwrap_or(50).min(100);
    let now = chrono::Utc::now().timestamp();

    // Fetch one extra to determine has_more.
    // Only returns messages where release_at <= now (release timing, S16 §6).
    let rows = state.db.fetch_messages(&fetch_cap, limit + 1, now)?;

    let has_more = rows.len() as u32 > limit;
    let messages: Vec<FetchedMessage> = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| FetchedMessage {
            id: row.id,
            blob: B64.encode(&row.blob),
            deposited_at: row.deposited_at,
            size: row.size,
            cap_hint: row.cap_hint.map(|h| B64.encode(h)),
        })
        .collect();

    tracing::debug!(
        real_messages = messages.len(),
        has_more,
        "fetch: returning messages"
    );

    // NO server-side noise (S16 §3.4): the page holds only real stored blobs.
    // The server conceals nothing about response size. Clients add cover polls
    // on their own cover capabilities (S10 §4.2), and discard-by-envelope-
    // decryption-failure stays valid for any bytes a hostile operator injects.

    Ok(Json(FetchResponse { messages, has_more }))
}
