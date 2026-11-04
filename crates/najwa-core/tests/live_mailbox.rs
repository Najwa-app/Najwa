//! §9.2 Live mailbox integration tests.
//!
//! These tests run against a local mailbox server (no Tor, no PoW, no batching).
//!
//! Start the test server first:
//!   cd scripts/deployment
//!   docker compose -f docker-compose.test.yml up -d --build
//!
//! Then run (inside Docker):
//!   cargo test -p najwa-core --test live_mailbox -- --ignored --skip tor_sqlite --nocapture
//!
//! The separate `tor_sqlite` test requires TEST_MAILBOX_ONION pointing to an
//! onion service that forwards port 80 to this disposable test mailbox.
//!
//! Stop when done:
//!   docker compose -f docker-compose.test.yml down

/// Remote fetches can drain a pool even when no Initial ever reaches its owner.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn sqlite_replenishes_remote_depletion_and_retains_inflight_keys() {
    use najwa_core::service::MessagingService;
    use najwa_storage::{
        database::SqliteStorage, prekey_lifecycle::prekey_scope_setting, types::NewMailbox,
    };
    assert_server_up();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("najwa.db");
    let db = SqliteStorage::open(&path, &[34; 32]).unwrap();
    let mailbox = fresh_mailbox();
    let client = test_client();
    client
        .register_capability(&mailbox, &CapabilitySettings::default(), None)
        .await
        .unwrap();
    db.save_mailbox(&NewMailbox::with_cover_caps(
        mailbox.onion_address.clone(),
        mailbox.fetch_capability.to_vec(),
        mailbox.deposit_capability.to_vec(),
        1,
        1,
    ))
    .unwrap();
    let service = MessagingService::new(Ed25519KeyPair::from_seed(&[35; 32]), db, client.clone());
    service.maintain_prekeys().await.unwrap();
    let mut served = Vec::new();
    for _ in 0..160 {
        let bundle = client
            .fetch_prekey_bundle(&mailbox, &mailbox.deposit_capability, &random_bytes())
            .await
            .unwrap();
        served.push(bundle.one_time_prekeys[0].id);
    }
    assert_eq!(
        client.get_status_once(&mailbox).await.unwrap().prekey_count,
        40
    );
    let observer = SqliteStorage::open(&path, &[34; 32]).unwrap();
    observer
        .set_setting(
            &prekey_scope_setting("last", &mailbox.fetch_capability),
            &0u64,
        )
        .unwrap();
    service.maintain_prekeys().await.unwrap();
    let status = client.get_status_once(&mailbox).await.unwrap();
    assert_eq!(status.prekey_count, 200);
    assert_eq!(status.prekey_ids.len(), 200);
    assert!(served.iter().all(|id| !status.prekey_ids.contains(id)));
    for id in served {
        let key = observer.get_prekey(&id.to_be_bytes()).unwrap().unwrap();
        assert!(!key.used);
        assert_eq!(key.private_key.len(), 32);
        assert!(key.expires_at.unwrap() > najwa_crypto::time::now() as i64);
    }
}

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use najwa_core::cover::{CoverMailboxSnapshot, CoverTrafficConfig, CoverTrafficScheduler};
use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::random::random_bytes;
use najwa_protocol::mailbox::client::{MailboxClient, Transport};
use najwa_protocol::mailbox::http::HttpMailboxClient;
use najwa_protocol::mailbox::types::{
    CapabilitySettings, MailboxConfig, OneTimePrekey, PrekeyBundle, WireManifest,
};
use najwa_transport::circuit::{CircuitHandle, CircuitIsolation};
use najwa_transport::error::TransportError;
use najwa_transport::http::HttpResponse;

/// Server address — use env var to override (e.g. container name on Docker network).
/// Default: 127.0.0.1 for local development.
fn server_addr() -> String {
    std::env::var("TEST_MAILBOX_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string())
}
fn api_addr() -> String {
    format!("{}:8080", server_addr())
}
#[allow(dead_code)] // used by the --ignored live health test
fn health_addr() -> String {
    format!("{}:9090", server_addr())
}

// ---------------------------------------------------------------------------
// Direct HTTP transport — raw TCP to localhost, no Tor.
// ---------------------------------------------------------------------------

struct DirectHttpTransport;

impl DirectHttpTransport {
    fn raw_request(
        addr: &str,
        method: &str,
        path: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<HttpResponse, TransportError> {
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();

        let host = addr;
        let request = if let Some((body_bytes, content_type)) = body {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                method, path, host, content_type, body_bytes.len()
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                method, path, host
            )
        };

        stream
            .write_all(request.as_bytes())
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        if let Some((body_bytes, _)) = body {
            stream
                .write_all(body_bytes)
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        }
        stream
            .flush()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut response_bytes = Vec::new();
        stream
            .read_to_end(&mut response_bytes)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let response_str = String::from_utf8_lossy(&response_bytes);
        let (header_part, _body_part) = response_str
            .split_once("\r\n\r\n")
            .unwrap_or((&response_str, ""));

        let status_line = header_part.lines().next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Find body bytes by locating \r\n\r\n in raw bytes
        let body_vec = if let Some(pos) = response_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            response_bytes[pos + 4..].to_vec()
        } else {
            Vec::new()
        };

        Ok(HttpResponse {
            status,
            headers: HashMap::new(),
            body: body_vec,
        })
    }
}

#[async_trait::async_trait]
impl Transport for DirectHttpTransport {
    async fn get_circuit(
        &self,
        _isolation: CircuitIsolation,
    ) -> Result<CircuitHandle, TransportError> {
        Ok(CircuitHandle::new(CircuitIsolation::CoverTraffic(
            String::new(),
        )))
    }

    async fn post(
        &self,
        _circuit: &CircuitHandle,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<HttpResponse, TransportError> {
        let path = url.find("/v1/").map(|i| &url[i..]).unwrap_or("/");
        Self::raw_request(&api_addr(), "POST", path, Some((body, content_type)))
    }

    async fn get(
        &self,
        _circuit: &CircuitHandle,
        url: &str,
    ) -> Result<HttpResponse, TransportError> {
        let path = url.find("/v1/").map(|i| &url[i..]).unwrap_or("/");
        Self::raw_request(&api_addr(), "GET", path, None)
    }
}

fn test_client() -> HttpMailboxClient {
    HttpMailboxClient::new(Arc::new(DirectHttpTransport))
}

fn fresh_mailbox() -> MailboxConfig {
    MailboxConfig::new("test_local".to_string(), random_bytes(), random_bytes())
}

fn assert_server_up() {
    // Try the API port — health port (9090) binds to 127.0.0.1 inside the container
    // and is not reachable from other containers. Use a bogus POST to /v1/status
    // which should return 400 or 404 (but NOT connection refused).
    let result = DirectHttpTransport::raw_request(&api_addr(), "GET", "/v1/attestation", None);
    assert!(
        result.is_ok(),
        "Test mailbox server not running. Start it with:\n  \
         cd src/scripts/deployment && docker compose -f docker-compose.test.yml up -d --build\n  \
         Connection error: {:?}",
        result.err()
    );
}

fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(a >> 2) as usize] as char);
        encoded.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[(((b & 0x0F) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(c & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

fn register_ephemeral_raw(mailbox: &MailboxConfig, expires_at: i64) {
    let body = format!(
        "{{\"fetch_capability\":\"{}\",\"deposit_capability\":\"{}\",\"capability_type\":1,\"expires_at\":{},\"pow_solution\":null,\"settings\":{{\"retention_days\":1,\"max_message_size\":262144}}}}",
        base64_standard(&mailbox.fetch_capability),
        base64_standard(&mailbox.deposit_capability),
        expires_at
    );
    let response = DirectHttpTransport::raw_request(
        &api_addr(),
        "POST",
        "/v1/capability/register",
        Some((body.as_bytes(), "application/json")),
    )
    .expect("type-1 registration transport failed");
    assert!(
        (200..300).contains(&response.status),
        "type-1 registration rejected: status={} body={}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
}

// ===========================================================================
// Tests
// ===========================================================================

/// S05 §5: the exact capability advertised by a QR accepts a deposit, then
/// deactivation keyed by its FETCH cap makes the same deposit cap unusable.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn qr_ephemeral_cap_accepts_then_deactivation_rejects() {
    assert_server_up();
    let client = test_client();
    let mailbox = fresh_mailbox();
    let created_at = najwa_crypto::time::now();
    let expires_at = created_at as i64 + 900;
    register_ephemeral_raw(&mailbox, expires_at);

    let identity = Ed25519KeyPair::from_seed(&[0x55; 32]);
    let mut payload = najwa_protocol::contact::HandshakePayload::create(
        &identity,
        std::slice::from_ref(&mailbox),
        "E2E",
        1,
    )
    .unwrap();
    payload.expires_at = payload.created_at + 900;
    payload.signature = identity.sign(&payload.signable_bytes()).to_bytes();
    let qr = payload.to_qr_string().expect("QR encoding failed");
    let advertised =
        najwa_protocol::contact::HandshakePayload::from_qr_string(&qr).expect("QR decoding failed");
    assert_eq!(advertised.expires_at - advertised.created_at, 900);
    assert_eq!(advertised.mailbox_entries[0].capability_type, 0x01);
    assert_eq!(
        advertised.mailbox_entries[0].deposit_capability,
        mailbox.deposit_capability
    );

    let bundle = PrekeyBundle {
        identity_key: random_bytes(),
        signed_prekey: random_bytes(),
        signed_prekey_id: 77,
        signed_prekey_signature: vec![0x77; 64],
        signed_prekey_timestamp: created_at,
        // The server deliberately refuses the final OPK, so provide two and
        // prove type-1 idempotence on the first one it may safely consume.
        one_time_prekeys: vec![
            OneTimePrekey {
                id: 78,
                key: random_bytes(),
            },
            OneTimePrekey {
                id: 79,
                key: random_bytes(),
            },
        ],
        // OPK-carrying bundles MUST carry the signed manifest (S06 §2.2); the
        // server rejects an OPK upload without one.
        manifest: Some(WireManifest {
            opk_ids: vec![100, 101],
            opk_id_set_hash: random_bytes(),
            opk_count: 2,
            timestamp: created_at as u64,
            signature: vec![0x11; 64],
        }),
    };
    client
        .upload_prekey_bundle(&mailbox, &mailbox.deposit_capability, &bundle)
        .await
        .expect("ephemeral prekey upload failed");
    let fetched = client
        .fetch_prekey_bundle(
            &mailbox,
            &advertised.mailbox_entries[0].deposit_capability,
            &[0x11; 32],
        )
        .await
        .expect("QR-advertised capability could not fetch its prekey bundle");
    assert_eq!(fetched.signed_prekey_id, bundle.signed_prekey_id);
    assert_eq!(fetched.one_time_prekeys[0].id, 78);
    let fetched_again = client
        .fetch_prekey_bundle(
            &mailbox,
            &advertised.mailbox_entries[0].deposit_capability,
            &[0x11; 32],
        )
        .await
        .expect("repeat type-1 prekey fetch failed");
    assert_eq!(fetched_again.one_time_prekeys[0].id, 78);

    let first = client
        .deposit(
            &mailbox,
            &advertised.mailbox_entries[0].deposit_capability,
            b"valid-encrypted-placeholder",
            None,
        )
        .await
        .expect("QR-advertised capability rejected its first deposit");
    assert!(first.accepted);
    let stored = client
        .fetch(&mailbox, &mailbox.fetch_capability, None, 10)
        .await
        .expect("first type-1 deposit was not fetchable");
    assert!(
        stored
            .iter()
            .any(|message| message.blob == b"valid-encrypted-placeholder"),
        "first QR deposit was not present in the fetched page"
    );
    let stored_ids: Vec<String> = stored.iter().map(|message| message.id.clone()).collect();
    client
        .acknowledge(&mailbox, &mailbox.fetch_capability, &stored_ids)
        .await
        .expect("failed to acknowledge first type-1 deposit");

    client
        .deactivate_capability(&mailbox, &mailbox.fetch_capability)
        .await
        .expect("deactivation by ephemeral fetch capability failed");
    assert!(client
        .get_status(&mailbox, &mailbox.fetch_capability)
        .await
        .is_err());
    let opaque_drop = client
        .deposit(
            &mailbox,
            &advertised.mailbox_entries[0].deposit_capability,
            b"second-deposit-must-fail",
            None,
        )
        .await
        .expect("post-deactivation deposit must use the server's opaque success response");
    assert!(
        opaque_drop.accepted,
        "unknown/deactivated deposits use indistinguishable fake acceptance"
    );
}

/// Register → deposit → fetch → acknowledge roundtrip.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn mailbox_deposit_and_fetch_roundtrip() {
    assert_server_up();
    let client = test_client();
    let mailbox = fresh_mailbox();

    client
        .register_capability(&mailbox, &CapabilitySettings::default(), None)
        .await
        .expect("register_capability failed");

    let test_blob: Vec<u8> = (0..128).map(|i| i as u8).collect();
    let result = client
        .deposit(&mailbox, &mailbox.deposit_capability, &test_blob, None)
        .await
        .expect("deposit failed");
    assert!(result.accepted);
    assert!(result.message_id.is_some());

    // No batching delay — test config has batching disabled
    let messages = client
        .fetch(&mailbox, &mailbox.fetch_capability, None, 50)
        .await
        .expect("fetch failed");
    eprintln!("fetched {} messages", messages.len());
    for m in &messages {
        eprintln!("  msg id={} size={}", m.id, m.size);
    }
    assert!(
        !messages.is_empty(),
        "should have fetched the deposited message"
    );

    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    eprintln!("acknowledging {} messages: {:?}", ids.len(), ids);

    // Check acknowledge response
    let ack_result = client
        .acknowledge(&mailbox, &mailbox.fetch_capability, &ids)
        .await;
    eprintln!("acknowledge result: {:?}", ack_result);
    ack_result.expect("acknowledge failed");

    let after = client
        .fetch(&mailbox, &mailbox.fetch_capability, None, 50)
        .await
        .expect("fetch after ack failed");
    // The server never injects noise (docs/SPECS-VERSION.md),
    // but the client-side discard-by-id-prefix filter is kept as defense in
    // depth against a hostile/non-conforming operator.
    let real_after: Vec<_> = after.iter().filter(|m| m.id.starts_with("msg-")).collect();
    eprintln!(
        "messages after ack: {} total ({} real, {} noise)",
        after.len(),
        real_after.len(),
        after.len() - real_after.len()
    );
    assert!(
        real_after.is_empty(),
        "no real messages should remain after acknowledge"
    );
}

/// The production scheduler itself must place an envelope-wrapped cover blob
/// into a real mailbox. This catches the historical "task started but every
/// mailbox was skipped" failure mode that a lifecycle-only assertion cannot.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn cover_scheduler_deposit_reaches_live_mailbox() {
    assert_server_up();
    let client = Arc::new(test_client());
    let cover_fetch = random_bytes();
    let cover_deposit = random_bytes();
    let cover_secret = random_bytes();
    let mailbox = MailboxConfig {
        onion_address: "cover_live".into(),
        fetch_capability: cover_fetch,
        deposit_capability: cover_deposit,
        envelope_secret: cover_secret,
        cover_deposit_capability: Some(cover_deposit),
        cover_fetch_capability: Some(cover_fetch),
        cover_envelope_secret: Some(cover_secret),
    };
    client
        .register_capability(&mailbox, &CapabilitySettings::default(), None)
        .await
        .expect("cover capability registration failed");

    let config = CoverTrafficConfig {
        poll_interval: Duration::from_secs(1),
        deposit_interval: Duration::from_secs(1),
        jitter_percent: 0,
        ..CoverTrafficConfig::default()
    };
    let mut scheduler = CoverTrafficScheduler::new(config);
    scheduler.replace_mailboxes(vec![CoverMailboxSnapshot {
        onion_address: mailbox.onion_address.clone(),
        cover_deposit_capability: cover_deposit,
        cover_fetch_capability: cover_fetch,
        cover_envelope_secret: cover_secret,
        dummy_deposit_capabilities: Vec::new(),
    }]);
    scheduler.start(client.clone());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let deposited = loop {
        let messages = client
            .fetch(&mailbox, &cover_fetch, None, 50)
            .await
            .expect("cover fetch failed");
        if let Some(message) = messages.into_iter().find(|message| {
            najwa_protocol::message::envelope_decrypt(&cover_secret, &cover_deposit, &message.blob)
                .is_ok()
        }) {
            break message;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "scheduler emitted no cover deposit within 15 seconds"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    scheduler.stop();

    assert!(najwa_core::cover::config::COVER_DEPOSIT_SIZES.contains(&deposited.blob.len()));
    assert!(scheduler.snapshot().cover_deposits > 0);
}

/// S10 §6.2: a sender parked on a deposit slot must actually be released by the
/// running scheduler, and its own deposit must reach a real mailbox.
///
/// The destination here deliberately has **no cover snapshot** — the scheduler
/// holds cover capabilities for a different mailbox entirely. That is the case
/// the permit design exists for: were the scheduler depositing real content
/// itself, it would fail to resolve this destination, log "no longer eligible",
/// and drop the message. Granting a permit instead means a mailbox the cover
/// subsystem knows nothing about is still fully sendable.
///
/// Like the cover-emission test above, this asserts the *observable effect*.
/// The unit tests prove a grant wakes a waiter; only this proves the wired-up
/// scheduler task does it against a live server and that the bytes land.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn slot_paced_send_reaches_live_mailbox() {
    use najwa_core::cover::AbsorptionPriority;

    assert_server_up();
    let client = Arc::new(test_client());

    // Cover-only mailbox the scheduler knows about.
    let cover_cap = random_bytes();
    let cover_secret = random_bytes();
    let cover_mailbox = MailboxConfig {
        onion_address: "paced_cover".into(),
        fetch_capability: cover_cap,
        deposit_capability: cover_cap,
        envelope_secret: cover_secret,
        cover_deposit_capability: Some(cover_cap),
        cover_fetch_capability: Some(cover_cap),
        cover_envelope_secret: Some(cover_secret),
    };
    client
        .register_capability(&cover_mailbox, &CapabilitySettings::default(), None)
        .await
        .expect("cover capability registration failed");

    // Destination the send targets — unknown to the cover subsystem.
    let dest = fresh_mailbox();
    client
        .register_capability(&dest, &CapabilitySettings::default(), None)
        .await
        .expect("destination registration failed");

    let config = CoverTrafficConfig {
        poll_interval: Duration::from_secs(1),
        deposit_interval: Duration::from_secs(1),
        jitter_percent: 0,
        ..CoverTrafficConfig::default()
    };
    let mut scheduler = CoverTrafficScheduler::new(config);
    scheduler.replace_mailboxes(vec![CoverMailboxSnapshot {
        onion_address: cover_mailbox.onion_address.clone(),
        cover_deposit_capability: cover_cap,
        cover_fetch_capability: cover_cap,
        cover_envelope_secret: cover_secret,
        dummy_deposit_capabilities: Vec::new(),
    }]);
    // The production handle — the same one `messaging_service::get()` installs.
    let slots = scheduler.slot_source();
    scheduler.start(client.clone());

    // Park exactly as the send path does, then deposit on the granted slot.
    let grant = tokio::time::timeout(
        Duration::from_secs(15),
        slots.await_slot(&dest.onion_address, AbsorptionPriority::RealMessage, None),
    )
    .await
    .expect("scheduler granted no deposit slot within 15 seconds");
    assert!(
        grant.was_paced(),
        "expected a real slot grant, got {grant:?}"
    );

    let payload = b"slot-paced-send-marker".to_vec();
    let blob = najwa_protocol::message::envelope_encrypt(
        &dest.envelope_secret,
        &dest.deposit_capability,
        &payload,
    )
    .expect("envelope_encrypt failed");
    assert!(grant.begin(), "slot expired before deposit");
    client
        .deposit(&dest, &dest.deposit_capability, &blob, None)
        .await
        .expect("paced deposit failed");
    tokio::time::timeout(Duration::from_secs(5), async {
        while scheduler.snapshot().real_sends_absorbed == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("scheduler did not observe the consumed permit");
    scheduler.stop();

    let fetched = client
        .fetch(&dest, &dest.fetch_capability, None, 50)
        .await
        .expect("destination fetch failed");
    let found = fetched.iter().any(|message| {
        najwa_protocol::message::envelope_decrypt(
            &dest.envelope_secret,
            &dest.deposit_capability,
            &message.blob,
        )
        .map(|plain| plain == payload)
        .unwrap_or(false)
    });
    assert!(found, "slot-paced deposit never reached the mailbox");
    assert!(
        scheduler.snapshot().real_sends_absorbed > 0,
        "the grant was not counted as an absorbed slot"
    );
}

/// Upload a prekey bundle and fetch it back.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn mailbox_prekey_bundle_roundtrip() {
    assert_server_up();
    let client = test_client();
    let mailbox = fresh_mailbox();

    client
        .register_capability(&mailbox, &CapabilitySettings::default(), None)
        .await
        .expect("register_capability failed");

    let identity_key: [u8; 32] = random_bytes();
    let signed_prekey: [u8; 32] = random_bytes();
    let bundle = PrekeyBundle {
        identity_key,
        signed_prekey,
        signed_prekey_id: 42,
        signed_prekey_signature: vec![0x42; 64],
        signed_prekey_timestamp: 0,
        one_time_prekeys: vec![
            OneTimePrekey {
                id: 100,
                key: random_bytes(),
            },
            OneTimePrekey {
                id: 101,
                key: random_bytes(),
            },
        ],
        manifest: Some(WireManifest {
            opk_ids: vec![100, 101],
            opk_id_set_hash: random_bytes(),
            opk_count: 2,
            timestamp: 0,
            signature: vec![0x22; 64],
        }),
    };

    client
        .upload_prekey_bundle(&mailbox, &mailbox.deposit_capability, &bundle)
        .await
        .expect("upload_prekey_bundle failed");

    let fetched = client
        .fetch_prekey_bundle(&mailbox, &mailbox.deposit_capability, &[0u8; 32])
        .await
        .expect("fetch_prekey_bundle failed");

    assert_eq!(fetched.identity_key, identity_key);
    assert_eq!(fetched.signed_prekey, signed_prekey);
    assert_eq!(fetched.signed_prekey_id, 42);
}

/// 20 rapid deposits — all should succeed with test config (no PoW, high rate limits).
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn mailbox_rate_limiting() {
    assert_server_up();
    let client = test_client();
    let mailbox = fresh_mailbox();

    client
        .register_capability(&mailbox, &CapabilitySettings::default(), None)
        .await
        .expect("register_capability failed");

    let blob: Vec<u8> = vec![0xAB; 64];
    let mut success = 0u32;

    for i in 0..20 {
        match client
            .deposit(&mailbox, &mailbox.deposit_capability, &blob, None)
            .await
        {
            Ok(r) if r.accepted => success += 1,
            Ok(_) => eprintln!("deposit {} not accepted", i),
            Err(e) => eprintln!("deposit {} error: {}", i, e),
        }
    }

    assert_eq!(
        success, 20,
        "all 20 deposits should succeed with test config"
    );
}

/// Two independent encrypted databases, real HTTP mailbox, cold X3DH, ratchet
/// replies, process-style reopen, and idempotent polling after durable ACK.
#[tokio::test]
#[ignore = "requires local test mailbox (docker-compose.test.yml)"]
async fn sqlite_messaging_end_to_end_across_restart() {
    assert_server_up();
    exercise_sqlite_messaging([test_client(), test_client()], "a".repeat(56)).await;
}

/// Real embedded Arti clients, independent encrypted databases and onion routes.
#[tokio::test]
#[ignore = "requires live Tor and TEST_MAILBOX_ONION for a disposable mailbox"]
async fn tor_sqlite_messaging_end_to_end_across_restart() {
    use najwa_transport::{config::TorConfig, tor::TorTransport};
    let onion = std::env::var("TEST_MAILBOX_ONION").expect("TEST_MAILBOX_ONION is required");
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut transports = Vec::new();
    for dir in &dirs {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut tor = TorTransport::new(TorConfig {
            data_dir: dir.path().into(),
            ..Default::default()
        });
        tokio::time::timeout(Duration::from_secs(180), tor.bootstrap())
            .await
            .expect("Tor bootstrap deadline")
            .expect("Tor bootstrap failed");
        transports.push(Arc::new(tor));
    }
    exercise_sqlite_messaging(
        [
            HttpMailboxClient::new(transports[0].clone()),
            HttpMailboxClient::new(transports[1].clone()),
        ],
        onion.trim_end_matches(".onion").to_owned(),
    )
    .await;
    for tor in transports {
        Arc::try_unwrap(tor)
            .ok()
            .expect("transport still referenced")
            .shutdown()
            .await
            .unwrap();
    }
}

async fn exercise_sqlite_messaging(clients: [HttpMailboxClient; 2], onion: String) {
    use najwa_core::{service::MessagingService, storage::CoreStorage, types::MessageContent};
    use najwa_protocol::{contact::HandshakePayload, pseudonym::derive_pairwise_pseudonyms};
    use najwa_storage::{database::SqliteStorage, types::NewMailbox};
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let alice_key = Ed25519KeyPair::from_seed(&[81; 32]);
    let bob_key = Ed25519KeyPair::from_seed(&[82; 32]);
    let (ap, bp) = derive_pairwise_pseudonyms(&alice_key, bob_key.public()).unwrap();
    let mut mailboxes = Vec::new();
    let mut stores = Vec::new();
    for (i, dir) in dirs.iter().enumerate() {
        let db = SqliteStorage::open(&dir.path().join("najwa.db"), &[i as u8 + 1; 32]).unwrap();
        let mut mailbox = fresh_mailbox();
        mailbox.onion_address = onion.clone();
        mailbox.envelope_secret = random_bytes();
        clients[i]
            .register_capability(&mailbox, &CapabilitySettings::default(), None)
            .await
            .unwrap();
        db.save_mailbox(&NewMailbox {
            onion_address: mailbox.onion_address.clone(),
            fetch_capability: mailbox.fetch_capability.to_vec(),
            deposit_capability: mailbox.deposit_capability.to_vec(),
            envelope_secret: mailbox.envelope_secret.to_vec(),
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
            priority: 1,
            created_at: najwa_crypto::time::now() as i64,
        })
        .unwrap();
        mailboxes.push(mailbox);
        stores.push(db);
    }
    let alice_payload =
        HandshakePayload::create(&alice_key, &[mailboxes[0].clone()], "Alice", 24).unwrap();
    let bob_payload =
        HandshakePayload::create(&bob_key, &[mailboxes[1].clone()], "Bob", 24).unwrap();
    let alice_contact =
        CoreStorage::create_reciprocal_contact(&stores[0], &bob_payload, &ap.0, &bp.0)
            .await
            .unwrap();
    let bob_contact =
        CoreStorage::create_reciprocal_contact(&stores[1], &alice_payload, &bp.0, &ap.0)
            .await
            .unwrap();
    let bob_db = stores.pop().unwrap();
    let alice_db = stores.pop().unwrap();
    let alice = MessagingService::new(alice_key, alice_db, clients[0].clone());
    let bob = MessagingService::new(bob_key, bob_db, clients[1].clone());
    alice.load_pseudonym_table().await.unwrap();
    bob.load_pseudonym_table().await.unwrap();
    alice.maintain_prekeys().await.unwrap();
    bob.maintain_prekeys().await.unwrap();
    alice
        .send_message(
            alice_contact.id,
            MessageContent::Text("cold X3DH over live HTTP".into()),
        )
        .await
        .unwrap();
    let received = bob.poll_messages().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].content, b"cold X3DH over live HTTP");
    bob.send_message(bob_contact.id, MessageContent::Text("ratchet reply".into()))
        .await
        .unwrap();
    assert_eq!(
        alice.poll_messages().await.unwrap()[0].content,
        b"ratchet reply"
    );
    drop(bob);
    let bob = MessagingService::new(
        Ed25519KeyPair::from_seed(&[82; 32]),
        SqliteStorage::open(&dirs[1].path().join("najwa.db"), &[2; 32]).unwrap(),
        clients[1].clone(),
    );
    bob.load_pseudonym_table().await.unwrap();
    assert!(
        bob.poll_messages().await.unwrap().is_empty(),
        "durable ACK prevents redisplay"
    );
    alice
        .send_message(
            alice_contact.id,
            MessageContent::Text("after reopen".into()),
        )
        .await
        .unwrap();
    assert_eq!(
        bob.poll_messages().await.unwrap()[0].content,
        b"after reopen"
    );

    // Recovery on the same data directory replaces a full server pool, not an
    // append that exceeds quota. Unauthorized replacement must fail first.
    let old = clients[0]
        .fetch_prekey_bundle(&mailboxes[1], &mailboxes[1].deposit_capability, &ap.0)
        .await
        .unwrap();
    let mut unauthorized = mailboxes[1].clone();
    unauthorized.fetch_capability = [0; 32];
    assert!(matches!(
        clients[0]
            .publish_prekeys_once(&unauthorized, &old, true)
            .await,
        Err(najwa_protocol::mailbox::error::MailboxError::CapabilityNotFound)
    ));
    let public = Ed25519KeyPair::from_seed(&[82; 32]).public().to_bytes();
    let name: String = public.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(
        dirs[1].path().join(format!("prekey-recovery-{name}")),
        [99; 32],
    )
    .unwrap();
    bob.maintain_prekeys().await.unwrap();
    let fresh = clients[0]
        .fetch_prekey_bundle(&mailboxes[1], &mailboxes[1].deposit_capability, &ap.0)
        .await
        .unwrap();
    assert_ne!(fresh.signed_prekey_id, old.signed_prekey_id);
    assert!(fresh
        .one_time_prekeys
        .iter()
        .all(|k| !old.one_time_prekeys.iter().any(|o| o.id == k.id)));
}
