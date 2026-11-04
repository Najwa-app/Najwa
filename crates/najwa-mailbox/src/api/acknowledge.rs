//! Acknowledge endpoint — explicit message deletion (S16 §3.5).

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::capability::decode_cap;
use crate::api::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AcknowledgeRequest {
    pub fetch_capability: String,
    pub message_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct AcknowledgeResponse {
    pub status: &'static str,
    pub deleted: u32,
}

pub async fn acknowledge(
    State(state): State<AppState>,
    Json(req): Json<AcknowledgeRequest>,
) -> Result<Json<AcknowledgeResponse>, ApiError> {
    let fetch_cap = decode_cap(&req.fetch_capability)?;

    // S16 §12: never log capability tokens or message ids.
    tracing::debug!(
        count = req.message_ids.len(),
        "acknowledge request received"
    );

    if req.message_ids.is_empty() {
        return Err(ApiError::BadRequest("message_ids must not be empty".into()));
    }

    let deleted = state
        .db
        .acknowledge_messages(&fetch_cap, &req.message_ids)?;

    tracing::debug!(deleted, "acknowledge: messages deleted");

    Ok(Json(AcknowledgeResponse {
        status: "ok",
        deleted,
    }))
}
