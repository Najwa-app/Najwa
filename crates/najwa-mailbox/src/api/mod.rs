//! API layer — axum router and the ten S16 endpoints.
//!
//! Scope notes:
//! - There are no channel-feed (`/v1/feed/*`) routes or tables.
//! - There is no `/v1/capability/link`: S16 §1 lists the endpoints, and each
//!   fetch capability has exactly one deposit capability (S16 §2.1).

pub mod acknowledge;
pub mod attestation;
pub mod capability;
pub mod challenge;
pub mod deposit;
pub mod error;
pub mod fetch;
pub mod hardening;
pub mod health;
pub mod prekey;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::post;
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// S16 §12: cap request bodies at 1 MiB (axum's default is 2 MB). The largest
/// legitimate body is a deposit blob (≤256 KB base64-expanded) or a prekey bundle.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the full axum router with all `/v1/` endpoints.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Capability management
        .route("/v1/capability/register", post(capability::register))
        .route("/v1/capability/deactivate", post(capability::deactivate))
        // PoW challenge
        .route("/v1/challenge", post(challenge::get_challenge))
        // Message operations
        .route("/v1/deposit", post(deposit::deposit))
        .route("/v1/fetch", post(fetch::fetch))
        .route("/v1/acknowledge", post(acknowledge::acknowledge))
        // Prekey operations
        .route("/v1/prekey/upload", post(prekey::upload))
        .route("/v1/prekey/fetch", post(prekey::fetch_prekey))
        // Status
        .route("/v1/status", post(capability::status))
        // Operator attestation (S16 §3.10)
        .route(
            "/v1/attestation",
            post(attestation::attestation).get(attestation::attestation),
        )
        // S16 §12: bound request body size (before tracing so oversized bodies are
        // rejected early with 413).
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        // S16 §12: JSON limits the serde parser does not enforce (nesting,
        // array length, duplicate keys). Inside the deadline layer.
        .layer(middleware::from_fn(hardening::json_hardening))
        // S16 §14: fixed-deadline response scheduler — capability-lookup
        // timing equalisation. OUTERMOST so its window covers everything
        // below (JSON buffering included).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            hardening::fixed_deadline,
        ))
        // Request tracing — logs every HTTP request/response
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
