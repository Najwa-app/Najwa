//! API error types and JSON error responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Unified API error type returned by all handlers.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — malformed request.
    BadRequest(String),
    /// 404 — capability or resource not found.
    NotFound(String),
    /// 409 — capability already registered.
    Conflict(String),
    /// 410 — capability deactivated (S16 §3.9).
    Gone(String),
    /// 413 — blob too large.
    PayloadTooLarge(String),
    /// 429 — rate limited; PoW required.
    RateLimited(PowChallengeResponse),
    /// 429 — rate limited (no PoW challenge, e.g. fetch ceiling).
    TooManyRequests(String),
    /// 507 — quota exceeded.
    QuotaExceeded(String),
    /// 503 — server at capacity.
    ServiceUnavailable(String),
    /// 500 — internal server error.
    Internal(String),
}

/// PoW challenge returned with 429 responses.
#[derive(Debug, Clone, Serialize)]
pub struct PowChallengeResponse {
    pub challenge: String, // base64
    pub difficulty: u8,
    pub algorithm: String,
    pub expires_at: i64,
}

/// JSON body for error responses.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_challenge: Option<PowChallengeResponse>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, challenge) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg, None),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg, None),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg, None),
            ApiError::Gone(msg) => (StatusCode::GONE, msg, None),
            ApiError::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg, None),
            ApiError::RateLimited(challenge) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limited — PoW required".into(),
                Some(challenge),
            ),
            ApiError::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg, None),
            ApiError::QuotaExceeded(msg) => (StatusCode::INSUFFICIENT_STORAGE, msg, None),
            ApiError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg, None),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg, None),
        };

        let body = ErrorBody {
            error: message,
            pow_challenge: challenge,
        };

        (status, axum::Json(body)).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "database error");
        ApiError::Internal("internal server error".into())
    }
}
