//! Health check endpoint — internal monitoring only (S16 §3.11).

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::api::error::ApiError;
use crate::state::AppState;

/// Server operational status (S16 §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ServerStatus {
    /// Normal operation — accepting all requests.
    Active,
    /// Retiring — rejecting new capability registrations, serving existing.
    Retiring,
    /// Read-only — no new deposits or registrations, fetch/status only.
    ReadOnly,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub server_status: ServerStatus,
    pub uptime_secs: u64,
    pub capabilities_active: u64,
    pub messages_stored: u64,
    pub disk_usage_mb: u64,
    pub version: &'static str,
    /// If retiring, the Unix timestamp after which the server will shut down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retire_at: Option<i64>,
}

/// Global start time, set once at server boot.
static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Call once at server startup to record the boot time.
pub fn record_start_time() {
    START_TIME.get_or_init(std::time::Instant::now);
}

pub async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let uptime = START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0);

    let caps = state.db.active_capability_count()?;
    let msgs = state.db.total_message_count()?;

    // Estimate disk usage from database file size
    let disk_usage_mb = std::fs::metadata(&state.config.server.database_path)
        .map(|m| m.len() / (1024 * 1024))
        .unwrap_or(0);

    Ok(Json(HealthResponse {
        status: "healthy",
        server_status: state.server_status(),
        uptime_secs: uptime,
        capabilities_active: caps,
        messages_stored: msgs,
        disk_usage_mb,
        version: env!("CARGO_PKG_VERSION"),
        retire_at: state.retire_at(),
    }))
}
