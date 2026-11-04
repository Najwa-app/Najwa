use crate::{
    messaging,
    profile::{Failure, IdentityOperation, Owner},
};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// The default API body limit (S13 §19).
const BODY_LIMIT: usize = 32_768;

pub fn router(owner: Arc<Owner>) -> Router {
    Router::new()
        .route("/api/bootstrap", get(bootstrap))
        .route("/api/status", get(status))
        .route("/api/identity", post(identity))
        .route("/api/lock", post(lock))
        .route("/api/quit", post(quit))
        .route("/api/activity", post(activity))
        .route("/api/preferences", get(preferences).post(save_preferences))
        .route("/api/erase", post(erase))
        .route("/api/invoke", post(invoke))
        .route("/api/transfers",post(crate::transfer_http::operation))
        .route("/api/download/{ticket}",get(crate::transfer_http::download))
        .fallback(static_file)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .route(
            "/api/attachment",
            post(upload_attachment).layer(DefaultBodyLimit::max(8 * 1024 * 1024)),
        )
        .route("/api/transfer-part/{id}/{part}",post(crate::transfer_http::upload_part).layer(DefaultBodyLimit::max(1024*1024)))
        .layer(middleware::from_fn_with_state(owner.clone(), boundary))
        .with_state(owner)
}
async fn boundary(State(owner): State<Arc<Owner>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let api = request.uri().path().starts_with("/api/");
    let bootstrap = request.uri().path() == "/api/bootstrap";
    // The download handler validates an opaque, expiring file-only grant.
    // Native browser downloads cannot supply the JS API header. These grants
    // never unlock a profile and every streamed part checks the lock epoch.
    let download = request.uri().path().starts_with("/api/download/");
    let cookie_prefix = format!("{}=", owner.launch_cookie);
    let launch_cookie = value("cookie").is_some_and(|cookies| {
        cookies
            .split(';')
            .filter_map(|cookie| cookie.trim().strip_prefix(&cookie_prefix))
            .any(|cookie| owner.browser_access.accepts(cookie))
    });
    // On Linux and macOS the browser opens a file:// redirect page (launch.rs),
    // so loading the app page is a cross-site navigation. Allow only that page
    // load; it carries no credential and every API call stays same-origin.
    let launch_page = request.method() == "GET"
        && request.uri().path() == "/"
        && value("sec-fetch-mode") == Some("navigate")
        && value("sec-fetch-dest") == Some("document");
    let allowed = value("host") == Some(owner.host.as_str())
        && value("origin").is_none_or(|v| v == owner.origin)
        && value("sec-fetch-site").is_none_or(|v| matches!(v, "same-origin" | "none") || launch_page)
        && (!api
            || if bootstrap {
                token_matches(value("x-najwa-launch"), &owner.token) || launch_cookie
            } else if download {
                true
            } else {
                token_matches(value("x-najwa-session"), &owner.token)
            })
        && (request.method() != "POST"
            || value("content-type").is_some_and(|v| {
                if request.uri().path() == "/api/attachment" || request.uri().path().starts_with("/api/transfer-part/") {
                    v == "application/octet-stream"
                } else {
                    v == "application/json"
                }
            }));
    // Refusals carry the same security headers as every other response (S13 §19).
    let mut response = if allowed {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"error":{"code":"forbidden"}})),
        )
            .into_response()
    };
    let headers = response.headers_mut();
    for (key, value) in [
        ("cache-control", "no-store"), ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"), ("cross-origin-resource-policy", "same-origin"),
        ("cross-origin-opener-policy", "same-origin"), ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'"),
    ] { headers.insert(axum::http::HeaderName::from_static(key), axum::http::HeaderValue::from_static(value)); }
    response
}
/// The token is the API credential: compare in constant time.
fn token_matches(value: Option<&str>, token: &str) -> bool {
    value.is_some_and(|v| najwa_crypto::hash::constant_time_eq(v.as_bytes(), token.as_bytes()))
}
fn response(result: crate::profile::Result<Value>) -> Json<Value> {
    Json(match result {
        Ok(value) => json!({"ok":value}),
        Err(failure) => json!({"error":failure}),
    })
}
/// For replies that can carry recovery words or message text (S13 §17): the
/// JSON goes into a wiped buffer that is freed (wiped) once the HTTP library
/// has sent it, and the value's strings are wiped after serializing.
fn secret_response(result: crate::profile::Result<Value>) -> Response {
    let Json(mut value) = response(result);
    let body = najwa_ffi::hardening::to_json_zeroizing(&value);
    wipe_strings(&mut value);
    match body {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(Bytes::from_owner(body)),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(fields) => fields.values_mut().for_each(wipe_strings),
        _ => {}
    }
}
/// Reads a body that carries a passphrase or recovery words into one buffer
/// reserved at the body limit, so it never reallocates, and that is wiped on
/// drop on every path (S13 §17).
async fn secret_body(body: Body) -> Result<Zeroizing<Vec<u8>>, StatusCode> {
    use futures_util::StreamExt;
    let mut buffer = Zeroizing::new(Vec::with_capacity(BODY_LIMIT));
    let mut frames = body.into_data_stream();
    while let Some(frame) = frames.next().await {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if frame.len() > BODY_LIMIT - buffer.len() {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        buffer.extend_from_slice(&frame);
    }
    Ok(buffer)
}
async fn upload_attachment(
    State(owner): State<Arc<Owner>>,
    headers: axum::http::HeaderMap,
    bytes: Bytes,
) -> Json<Value> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let session = header("x-najwa-identity");
    let generation = header("x-najwa-generation").parse::<u64>();
    let contact = header("x-najwa-contact");
    let filename = STANDARD
        .decode(header("x-najwa-filename"))
        .ok()
        .and_then(|v| String::from_utf8(v).ok());
    let (Ok(generation), Some(filename)) = (generation, filename) else {
        return response(Err(Failure::new("invalid_request")));
    };
    response(
        tokio::task::spawn_blocking(move || {
            let input = zeroize::Zeroizing::new(bytes.to_vec());
            owner.validate(&session, generation, true)?;
            let result = owner
                .client
                .queue_file(&contact, &input, &filename)
                .map_err(|e| Failure::new(e.code));
            owner.validate(&session, generation, true)?;
            result.map(|_| Value::Null)
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
async fn bootstrap(State(owner): State<Arc<Owner>>) -> Response {
    let Ok((permission, max_age)) = owner.browser_access.cookie() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/api/bootstrap; Max-Age={max_age}",
        owner.launch_cookie, permission
    );
    (
        [(header::SET_COOKIE, cookie)],
        Json(json!({"token":owner.token,"session":owner.status().session})),
    )
        .into_response()
}
async fn quit(State(owner): State<Arc<Owner>>, Json(request): Json<SessionRequest>) -> Json<Value> {
    if owner.status().session != request.session {
        return response(Err(Failure::new("stale_operation")));
    }
    let epoch = owner.begin_lock();
    response(
        tokio::task::spawn_blocking(move || {
            owner.finish_lock(epoch)?;
            owner.shutdown.notify_one();
            Ok(Value::Null)
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
async fn status(State(owner): State<Arc<Owner>>) -> Json<Value> {
    response(Ok(json!(owner.status())))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRequest {
    session: String,
    generation: u64,
    operation: IdentityOperation,
}
async fn identity(State(owner): State<Arc<Owner>>, body: Body) -> Response {
    let body = match secret_body(body).await {
        Ok(body) => body,
        Err(status) => return status.into_response(),
    };
    // Wipe the request buffer right after parsing, including malformed credentials.
    let parsed = serde_json::from_slice::<IdentityRequest>(&body);
    drop(body);
    let Ok(request) = parsed else {
        return response(Err(Failure::new("invalid_request"))).into_response();
    };
    secret_response(
        tokio::task::spawn_blocking(move || {
            owner.identity(&request.session, request.generation, request.operation)
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    session: String,
    generation: u64,
}
async fn lock(State(owner): State<Arc<Owner>>, Json(request): Json<SessionRequest>) -> Json<Value> {
    if owner.status().session != request.session {
        return response(Err(Failure::new("stale_operation")));
    }
    // Lock is deliberately allowed while a prior operation advances generation.
    let epoch = owner.begin_lock();
    response(
        tokio::task::spawn_blocking(move || owner.finish_lock(epoch).map(|v| json!(v)))
            .await
            .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
async fn activity(
    State(owner): State<Arc<Owner>>,
    Json(request): Json<SessionRequest>,
) -> Json<Value> {
    response(
        owner
            .validate(&request.session, request.generation, true)
            .map(|_| {
                *owner.activity.lock().unwrap() = std::time::Instant::now();
                Value::Null
            }),
    )
}
async fn preferences(State(owner): State<Arc<Owner>>) -> Json<Value> {
    response(tokio::task::spawn_blocking(move || owner.preferences().map(|p| json!(p)))
        .await.unwrap_or_else(|_| Err(Failure::new("operation_failed"))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreferencesRequest {
    session: String,
    generation: u64,
    preferences: najwa_ffi::desktop::LocalPreferences,
}
async fn save_preferences(State(owner): State<Arc<Owner>>, Json(request): Json<PreferencesRequest>) -> Json<Value> {
    response(tokio::task::spawn_blocking(move || owner.save_preferences(&request.session, request.generation, request.preferences))
        .await.unwrap_or_else(|_| Err(Failure::new("operation_failed"))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseRequest {
    session: String,
    generation: u64,
    confirmed: bool,
    confirmation: String,
}
async fn erase(State(owner): State<Arc<Owner>>, Json(request): Json<EraseRequest>) -> Json<Value> {
    response(tokio::task::spawn_blocking(move || owner.erase(&request.session, request.generation, request.confirmed, &request.confirmation))
        .await.unwrap_or_else(|_| Err(Failure::new("operation_failed"))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvokeRequest {
    command: String,
    args: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagingArguments {
    request: MessagingRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessagingRequest {
    session: String,
    generation: u64,
    operation: messaging::Operation,
}
async fn invoke(
    State(owner): State<Arc<Owner>>,
    Json(request): Json<InvokeRequest>,
) -> Response {
    if request.command == "messaging_status" && request.args == json!({}) {
        let snapshot = owner.status();
        if snapshot.phase != "unlocked" {
            return response(Err(Failure::new("locked"))).into_response();
        }
        return response(
            tokio::task::spawn_blocking(move || {
                let mut network = serde_json::to_value(owner.client.status())
                    .map_err(|_| Failure::new("operation_failed"))?;
                owner.validate(&snapshot.session, snapshot.generation, true)?;
                network["enabled"] = json!(true);
                Ok(network)
            })
            .await
            .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
        )
        .into_response();
    }
    if request.command != "messaging_request" {
        return response(Err(Failure::new("invalid_request"))).into_response();
    }
    let Ok(arguments) = serde_json::from_value::<MessagingArguments>(request.args) else {
        return response(Err(Failure::new("invalid_request"))).into_response();
    };
    // Message history and previews are plaintext.
    secret_response(
        tokio::task::spawn_blocking(move || {
            let request = arguments.request;
            owner.validate(&request.session, request.generation, true)?;
            let result = messaging::execute(&owner.client, request.operation)
                .map_err(|e| Failure::new(e.code));
            owner.validate(&request.session, request.generation, true)?;
            result
        })
        .await
        .unwrap_or_else(|_| Err(Failure::new("operation_failed"))),
    )
}
async fn static_file(State(owner): State<Arc<Owner>>, request: Request) -> Response {
    if request.method() != "GET" {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = request.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if path.contains(['%', '\\', ':']) || path.split('/').any(|p| p == ".." || p.starts_with('.')) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mime = match path.rsplit('.').next() {
        Some("html") if path == "index.html" => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    match owner.assets.read(path).await {
        Some(bytes) => ([(header::CONTENT_TYPE, mime)], Body::from(bytes)).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S13 §17: a credential body is gathered from all its frames into one
    /// zeroizing buffer that never grew, and parses into zeroizing fields.
    #[test]
    fn credential_bodies_are_read_and_parsed_into_zeroizing_buffers() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let frames = [
            r#"{"session":"s","generation":1,"operation":{"kind":"change_password","current":"old "#,
            r#"passphrase","password":"new passphrase!","confirmation":"new passphrase!"}}"#,
        ];
        let body = Body::from_stream(futures_util::stream::iter(frames.map(Ok::<_, std::io::Error>)));
        let buffer: Zeroizing<Vec<u8>> = runtime.block_on(secret_body(body)).unwrap();
        assert_eq!(buffer.capacity(), BODY_LIMIT);
        let request: IdentityRequest = serde_json::from_slice(&buffer).unwrap();
        let IdentityOperation::ChangePassword { current, password, confirmation } = &request.operation
        else {
            panic!("wrong operation");
        };
        let fields: [&Zeroizing<String>; 3] = [current, password, confirmation];
        assert_eq!(fields.map(|f| f.as_str()), ["old passphrase", "new passphrase!", "new passphrase!"]);
        let large = Body::from(vec![b' '; BODY_LIMIT + 1]);
        assert_eq!(runtime.block_on(secret_body(large)).unwrap_err(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// S13 §19: the page and the API, served through the real router, carry
    /// the exact security headers.
    #[test]
    fn page_and_api_responses_carry_the_security_headers() {
        use tower::ServiceExt;
        const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'";
        let _owner = crate::profile::TEST_OWNER.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<!doctype html>").unwrap();
        let assets = crate::assets::Assets::resolve(Some(dir.path().into())).unwrap();
        let owner = Owner::open(&dir.path().join("profile"), assets, 1429).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        for (path, mime) in [("/", "text/html; charset=utf-8"), ("/api/status", "application/json")] {
            let request = axum::http::Request::builder()
                .uri(path)
                .header("host", &owner.host)
                .header("x-najwa-session", &owner.token)
                .body(Body::empty())
                .unwrap();
            let response = runtime.block_on(router(owner.clone()).oneshot(request)).unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let header = |name| response.headers().get(name).and_then(|v| v.to_str().ok());
            for (name, value) in [
                ("content-type", mime),
                ("content-security-policy", CSP),
                ("x-frame-options", "DENY"),
                ("cross-origin-opener-policy", "same-origin"),
                ("cross-origin-resource-policy", "same-origin"),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "no-referrer"),
                ("cache-control", "no-store"),
            ] {
                assert_eq!(header(name), Some(value), "{path}: {name}");
            }
            // The intent, directive by directive: no eval, no remote origin
            // (only keywords and data:/blob:), API calls same-origin only, no framing.
            let policy = header("content-security-policy").unwrap();
            assert!(!policy.contains("unsafe-eval"));
            let directives: Vec<Vec<&str>> =
                policy.split("; ").map(|d| d.split(' ').collect()).collect();
            for sources in &directives {
                assert!(sources[1..].iter().all(|s| s.starts_with('\'') || ["data:", "blob:"].contains(s)), "{sources:?}");
            }
            assert!(directives.contains(&vec!["connect-src", "'self'"]));
            assert!(directives.contains(&vec!["frame-ancestors", "'none'"]));
            assert!(directives.contains(&vec!["default-src", "'none'"]));
        }
        // A refused request (wrong Host) carries the same headers (S13 §19).
        let refused = axum::http::Request::builder()
            .uri("/api/status")
            .header("host", "attacker.example")
            .body(Body::empty())
            .unwrap();
        let response = runtime.block_on(router(owner.clone()).oneshot(refused)).unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get("content-security-policy").and_then(|v| v.to_str().ok()),
            Some(CSP)
        );
        assert_eq!(response.headers().get("x-frame-options").and_then(|v| v.to_str().ok()), Some("DENY"));
        drop(owner.client.prepare_wipe().unwrap());
    }

    #[test]
    fn token_check_rejects_a_wrong_token_of_any_length() {
        let token = "ab".repeat(32);
        assert!(super::token_matches(Some(&token), &token));
        assert!(!super::token_matches(Some(&format!("{}ac", &token[..62])), &token));
        assert!(!super::token_matches(Some(&token[..63]), &token));
        assert!(!super::token_matches(Some(""), &token));
        assert!(!super::token_matches(None, &token));
    }
}
