//! PoW challenge endpoint (S16 §3.2).

use axum::extract::State;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::pow;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub capability_hint: String, // base64(8 bytes) — first 8 bytes of a capability
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge: String, // base64(32 bytes)
    pub difficulty: u8,
    pub algorithm: &'static str,
    pub expires_at: i64,
}

pub async fn get_challenge(
    State(state): State<AppState>,
    Json(_req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let challenge = pow::generate_challenge();
    let load = state.estimated_load_percent();
    let difficulty = pow::adaptive_difficulty(
        load,
        state.config.pow.min_difficulty,
        state.config.pow.max_difficulty,
    );
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + state.config.pow.challenge_expiry_secs as i64;

    // In memory and capacity-bounded: no disk write per request (S16 §3.2).
    state.challenges.issue(challenge, difficulty, expires_at);

    Ok(Json(ChallengeResponse {
        challenge: B64.encode(challenge),
        difficulty,
        algorithm: "sha256-leading-zeros",
        expires_at,
    }))
}
