//! Endpoint-level tests over the real axum router (S16 §3).
//!
//! Complements the db-level stress tests: these drive HTTP semantics — PoW
//! challenge/verify on register, the §3.3 silent-drop on unknown deposit caps,
//! 404-vs-410 on the fetch path, quota/rate-limit responses, the refuse-last-
//! OPK rule, and the D11 reconciliation (a fetch response NEVER contains
//! server-injected noise).

use std::sync::Arc;

use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use najwa_mailbox::api;
use najwa_mailbox::config::Config;
use najwa_mailbox::db::Database;
use najwa_mailbox::pow::pow_hash;
use najwa_mailbox::state::AppState;
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;

/// Test server config: zero hold/jitter (immediate release), no PoW floors
/// except where a test opts in, relaxed rate limits except where a test
/// tightens them.
fn test_config(dir: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default_dev();
    cfg.server.database_path = dir.path().join("test.db");
    cfg.batching.min_hold_secs = 0;
    cfg.batching.max_hold_secs = 0;
    cfg.batching.jitter_secs = 0;
    cfg.quotas.ephemeral_max_messages = 100;
    cfg.quotas.ephemeral_max_storage_mb = 8;
    // Registration PoW stays ON (spec default) but at a solvable difficulty.
    cfg.pow.min_difficulty = 8;
    cfg.pow.max_difficulty = 8;
    cfg.pow.ephemeral_deposit_min_difficulty = 0;
    cfg.pow.deposit_pow_threshold_per_min = 999_999;
    cfg
}

fn server_for(cfg: Config) -> (TestServer, Arc<Database>) {
    let db = Arc::new(Database::open(&cfg).expect("open db"));
    let state = AppState::new(db.clone(), Arc::new(cfg)).expect("valid config");
    let router = api::router(state);
    (TestServer::new(router), db)
}

fn random_cap() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn b64cap(cap: &[u8; 32]) -> String {
    B64.encode(cap)
}

/// Find `nonce` such that `pow_hash(challenge, binding, ts, blob, nonce)` has
/// at least `difficulty` leading zero bits.
fn solve(challenge: &[u8; 32], binding: &[u8], difficulty: u8) -> (u64, [u8; 32]) {
    #[allow(clippy::cast_possible_truncation)]
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut nonce = 0u64;
    loop {
        let hash = pow_hash(challenge, binding, ts, &[0u8; 32], nonce);
        if leading_zero_bits(&hash) >= u32::from(difficulty) {
            return (nonce, hash);
        }
        nonce += 1;
        assert!(nonce < 5_000_000, "8-bit PoW must solve quickly");
    }
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    hash.iter()
        .take_while(|&&b| b == 0)
        .count() as u32 * 8
        + hash
            .iter()
            .find(|&&b| b != 0)
            .map_or(8, |b| b.leading_zeros())
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    pow_challenge: Option<PowChallengeBody>,
}

#[derive(Deserialize)]
struct PowChallengeBody {
    challenge: String,
    difficulty: u8,
}

#[derive(Deserialize)]
struct DepositResponse {
    accepted: bool,
    message_id: String,
}

#[derive(Deserialize)]
struct FetchResponse {
    messages: Vec<FetchedMessage>,
    has_more: bool,
}

#[derive(Deserialize)]
struct FetchedMessage {
    id: String,
    cap_hint: Option<String>,
}

#[tokio::test]
async fn register_without_pow_gets_challenge_then_solves() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    let body = json!({
        "fetch_capability": b64cap(&random_cap()),
        "deposit_capability": b64cap(&random_cap()),
    });

    // §7.2: registration ALWAYS requires PoW → 429 + challenge.
    let res = server.post("/v1/capability/register").json(&body).await;
    assert_eq!(res.status_code(), 429);
    let err: ErrorBody = res.json();
    let challenge = err.pow_challenge.expect("429 must carry a PoW challenge");
    assert_eq!(challenge.difficulty, 8);

    // Solve and re-submit (§7.1 register binding = fetch || deposit).
    let ch_bytes: [u8; 32] = B64.decode(&challenge.challenge).unwrap()[..32]
        .try_into()
        .unwrap();
    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    let mut binding = Vec::with_capacity(64);
    binding.extend_from_slice(&fetch_cap);
    binding.extend_from_slice(&deposit_cap);
    let (nonce, hash) = solve(&ch_bytes, &binding, challenge.difficulty);
    let body = json!({
        "fetch_capability": b64cap(&fetch_cap),
        "deposit_capability": b64cap(&deposit_cap),
        "pow_solution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": B64.encode(hash),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        },
    });
    let res = server.post("/v1/capability/register").json(&body).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());

    // The solved challenge is single-use: replaying it fails.
    let res = server.post("/v1/capability/register").json(&body).await;
    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn type1_register_clamps_expiry_even_when_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    // Registration PoW off for brevity — clamping is independent of it.
    cfg.pow.registration_always_requires_pow = false;
    let (server, db) = server_for(cfg);

    let fetch_cap = random_cap();
    let body = json!({
        "fetch_capability": b64cap(&fetch_cap),
        "deposit_capability": b64cap(&random_cap()),
        "capability_type": 1,
    });
    let res = server.post("/v1/capability/register").json(&body).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());

    let now = chrono::Utc::now().timestamp();
    let (cap_type, expires_at) = db
        .capability_type_and_expiry(&fetch_cap)
        .unwrap()
        .expect("row must exist");
    assert_eq!(cap_type, 1);
    let expires_at = expires_at.expect("type-1 must always have an expiry");
    // Clamped to <= created_at + 48 h (§3.1).
    assert!(expires_at <= now + 48 * 3600 + 5);
    assert!(expires_at > now);
}

#[tokio::test]
async fn deposit_to_unknown_cap_silently_drops() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, db) = server_for(cfg);

    let res = server
        .post("/v1/deposit")
        .json(&json!({
            "deposit_capability": b64cap(&random_cap()),
            "blob": B64.encode(b"dirty secret envelope"),
        }))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: DepositResponse = res.json();
    assert!(body.accepted);
    assert!(body.message_id.starts_with("msg-"), "fake id is shaped like a real one");
    // Nothing stored — the drop is silent (§3.3 step 3).
    assert_eq!(db.total_message_count().unwrap(), 0);
}

#[tokio::test]
async fn deposit_fetch_roundtrip_carries_cap_hint_and_never_noise() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    // 20 deposits. Under the retired noise mechanism a partially-filled page
    // had up to 3 random dummies appended; the D11-aligned fetch returns ONLY
    // real messages (docs/SPECS-VERSION.md).
    let mut ids = Vec::new();
    for i in 0..20 {
        let res = server
            .post("/v1/deposit")
            .json(&json!({
                "deposit_capability": b64cap(&deposit_cap),
                "blob": B64.encode(format!("envelope-{i}").as_bytes()),
            }))
            .await;
        assert_eq!(res.status_code(), 200);
        let body: DepositResponse = res.json();
        ids.push(body.message_id);
    }
    ids.sort();

    let res = server
        .post("/v1/fetch")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap), "limit": 100 }))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: FetchResponse = res.json();
    assert_eq!(body.messages.len(), 20, "exactly the real messages, no noise");
    assert!(!body.has_more);
    let mut got: Vec<String> = body.messages.iter().map(|m| m.id.clone()).collect();
    got.sort();
    assert_eq!(got, ids);
    for m in &body.messages {
        assert!(!m.id.starts_with("noise-"));
        // cap_hint = SHA256(deposit_cap)[0:8] (§3.4)
        assert_eq!(
            m.cap_hint.as_deref(),
            Some(B64.encode(sha256_prefix8(&deposit_cap)).as_str())
        );
    }

    // acknowledge deletes exactly the acked ids; unknown ids are idempotent.
    let res = server
        .post("/v1/acknowledge")
        .json(&json!({
            "fetch_capability": b64cap(&fetch_cap),
            "message_ids": [&ids[0], &ids[1], "msg-does-not-exist"],
        }))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<serde_json::Value>()["deleted"], 2);

    let res = server
        .post("/v1/fetch")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap), "limit": 100 }))
        .await;
    assert_eq!(res.json::<FetchResponse>().messages.len(), 18);
}

#[tokio::test]
async fn fetch_distinguishes_404_from_410() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    // Unknown capability → 404.
    let res = server
        .post("/v1/fetch")
        .json(&json!({ "fetch_capability": b64cap(&random_cap()) }))
        .await;
    assert_eq!(res.status_code(), 404);

    // Deactivated capability → 410 (and idempotent re-deactivation → 200/0, §3.9).
    let res = server
        .post("/v1/capability/deactivate")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(res.status_code(), 200);
    let res = server
        .post("/v1/fetch")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(res.status_code(), 410);
    let res = server
        .post("/v1/capability/deactivate")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(res.status_code(), 200);
    assert_eq!(res.json::<serde_json::Value>()["messages_deleted"], 0);
}

#[tokio::test]
async fn prekey_refuse_last_opk_and_type2_consumes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    let bundle = |opks: serde_json::Value| {
        json!({
            "deposit_capability": b64cap(&deposit_cap),
            "fetch_capability": b64cap(&fetch_cap),
            "bundle": {
                "identity_key": B64.encode([7u8; 32]),
                "signed_prekey": B64.encode([8u8; 32]),
                "signed_prekey_id": 42,
                "signed_prekey_signature": B64.encode([9u8; 64]),
                "manifest": {"opk_id_set_hash": B64.encode([3u8; 32]), "opk_count": 3, "timestamp": 0, "signature": B64.encode([4u8; 64])},
                "one_time_prekeys": opks,
            },
        })
    };

    // Exactly ONE OPK: the server MUST NOT serve the last OPK (§3.7) — the
    // bundle is served, no OPK, pool intact for a future 2+-OPK upload.
    let res = server
        .post("/v1/prekey/upload")
        .json(&bundle(json!([{ "id": 1, "key": B64.encode([1u8; 32]) }])))
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());

    let res = server
        .post("/v1/prekey/fetch")
        .json(&json!({ "deposit_capability": b64cap(&deposit_cap) }))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    assert!(body.get("one_time_prekeys").is_none_or(|v| v.is_null()));

    // Two OPKs: first fetch consumes one, second hits the refuse-last rule.
    let res = server
        .post("/v1/prekey/upload")
        .json(&bundle(json!([
            { "id": 2, "key": B64.encode([2u8; 32]) },
            { "id": 3, "key": B64.encode([3u8; 32]) },
        ])))
        .await;
    assert_eq!(res.status_code(), 200);

    let fetch = || async {
        server
            .post("/v1/prekey/fetch")
            .json(&json!({ "deposit_capability": b64cap(&deposit_cap) }))
            .await
    };
    // Pool = 3 → serve (§3.7: consume only while >1 remain, so the pool can
    // never drain to zero).
    let body: serde_json::Value = fetch().await.json();
    assert_eq!(body["one_time_prekeys"].as_array().unwrap().len(), 1);
    // Pool = 2 → still serves (2 > 1); the pool lands on exactly 1.
    let body: serde_json::Value = fetch().await.json();
    assert_eq!(body["one_time_prekeys"].as_array().unwrap().len(), 1);
    // Pool = 1 → refuse-last: no OPK served, and the final OPK is retained.
    let body: serde_json::Value = fetch().await.json();
    assert!(body.get("one_time_prekeys").is_none_or(|v| v.is_null()));
}

/// S16 §3.6: a deposit-capability holder (any contact or invitation holder)
/// cannot upload; only the owner's fetch capability authorizes it, and a
/// refusal looks exactly like an unknown deposit capability.
#[tokio::test]
async fn prekey_upload_requires_owner_fetch_capability() {
    let dir = tempfile::tempdir().unwrap();
    let (server, _db) = server_for(test_config(&dir));
    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    let upload = |deposit: &[u8; 32], fetch: Option<&[u8; 32]>| {
        let mut body = json!({
            "deposit_capability": b64cap(deposit),
            "replace_opks": true,
            "bundle": {
                "identity_key": B64.encode([7u8; 32]),
                "signed_prekey": B64.encode([8u8; 32]),
                "signed_prekey_id": 1,
                "signed_prekey_signature": B64.encode([9u8; 64]),
                "manifest": {"opk_count": 2},
                "one_time_prekeys": [
                    {"id": 1, "key": B64.encode([1u8; 32])},
                    {"id": 2, "key": B64.encode([2u8; 32])},
                ],
            },
        });
        if let Some(fetch) = fetch {
            body["fetch_capability"] = json!(b64cap(fetch));
        }
        let server = &server;
        async move {
            let res = server.post("/v1/prekey/upload").json(&body).await;
            (res.status_code(), res.text())
        }
    };

    let unknown = upload(&random_cap(), Some(&fetch_cap)).await;
    assert_eq!(unknown.0, 404);
    // (a) deposit capability alone, (b) wrong fetch capability: same as unknown.
    assert_eq!(upload(&deposit_cap, None).await, unknown);
    assert_eq!(upload(&deposit_cap, Some(&random_cap())).await, unknown);
    // (c) the owner's upload succeeds.
    let (status, text) = upload(&deposit_cap, Some(&fetch_cap)).await;
    assert_eq!(status, 200, "{text}");

    // Only the owner learns that the capability is deactivated.
    server
        .post("/v1/capability/deactivate")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(upload(&deposit_cap, Some(&random_cap())).await, unknown);
    assert_eq!(upload(&deposit_cap, Some(&fetch_cap)).await.0, 410);
}

#[tokio::test]
async fn fetch_rate_limit_returns_429() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.rate_limits.fetch_per_min_per_cap = 1;
    let (server, _db) = server_for(cfg);

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    let req = json!({ "fetch_capability": b64cap(&fetch_cap) });
    let res = server.post("/v1/fetch").json(&req).await;
    assert_eq!(res.status_code(), 200);
    let res = server.post("/v1/fetch").json(&req).await;
    assert_eq!(res.status_code(), 429);
}

// ---------------------------------------------------------------------------
// §3.3 deposit oracle: a holder of a deposit capability must get the same 429,
// 413 and PoW prompt from a dead (deactivated) or unknown capability as from a
// live one.
// ---------------------------------------------------------------------------

/// Register `(fetch, deposit)` with an explicit type and size limit (PoW off).
async fn register_typed(
    server: &TestServer,
    fetch_cap: &[u8; 32],
    deposit_cap: &[u8; 32],
    capability_type: u8,
    max_message_size: usize,
) {
    let res = server
        .post("/v1/capability/register")
        .json(&json!({
            "fetch_capability": b64cap(fetch_cap),
            "deposit_capability": b64cap(deposit_cap),
            "capability_type": capability_type,
            "settings": { "retention_days": 14, "max_message_size": max_message_size },
        }))
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
}

/// A live and a deactivated deposit capability of `capability_type`.
async fn live_and_dead(
    server: &TestServer,
    capability_type: u8,
    max_message_size: usize,
) -> ([u8; 32], [u8; 32]) {
    let live = random_cap();
    register_typed(server, &random_cap(), &live, capability_type, max_message_size).await;
    let (dead_fetch, dead) = (random_cap(), random_cap());
    register_typed(server, &dead_fetch, &dead, capability_type, max_message_size).await;
    let res = server
        .post("/v1/capability/deactivate")
        .json(&json!({ "fetch_capability": b64cap(&dead_fetch) }))
        .await;
    assert_eq!(res.status_code(), 200);
    (live, dead)
}

async fn deposit_raw(server: &TestServer, cap: &[u8; 32], blob: &[u8]) -> (u16, String) {
    let res = server
        .post("/v1/deposit")
        .json(&json!({ "deposit_capability": b64cap(cap), "blob": B64.encode(blob) }))
        .await;
    (res.status_code().as_u16(), res.text())
}

#[tokio::test]
async fn deposit_rate_limit_is_identical_for_live_dead_and_unknown_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.pow.registration_always_requires_pow = false;
    cfg.rate_limits.deposit_per_min_per_cap = 1;
    let (server, db) = server_for(cfg);
    let (live, dead) = live_and_dead(&server, 2, 262_144).await;

    let mut second = Vec::new();
    for cap in [live, dead, random_cap()] {
        assert_eq!(deposit_raw(&server, &cap, b"one").await.0, 200);
        second.push(deposit_raw(&server, &cap, b"two").await);
    }
    assert_eq!(second[0].0, 429, "{}", second[0].1);
    assert_eq!(second[1], second[0], "dead cap must 429 like a live one");
    assert_eq!(second[2], second[0], "unknown cap must 429 like a live one");
    assert_eq!(db.total_message_count().unwrap(), 1, "only the live deposit is stored");
}

#[tokio::test]
async fn deposit_too_large_is_identical_for_live_dead_and_unknown_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.pow.registration_always_requires_pow = false;
    cfg.quotas.max_blob_size_bytes = 64;
    let (server, db) = server_for(cfg);

    // Registered limit below the server maximum: the dead row still has its
    // settings, so it answers 413 exactly like the live queue.
    let (live, dead) = live_and_dead(&server, 1, 16).await;
    let live_res = deposit_raw(&server, &live, &[7u8; 32]).await;
    assert_eq!(live_res.0, 413, "{}", live_res.1);
    assert_eq!(deposit_raw(&server, &dead, &[7u8; 32]).await, live_res);

    // An unknown capability gets the type-2 limit (`max_blob_size_bytes`), the
    // same as a live queue registered with the default size.
    let (live2, dead2) = live_and_dead(&server, 2, 64).await;
    let live_res = deposit_raw(&server, &live2, &[7u8; 65]).await;
    assert_eq!(live_res.0, 413, "{}", live_res.1);
    assert_eq!(deposit_raw(&server, &dead2, &[7u8; 65]).await, live_res);
    assert_eq!(deposit_raw(&server, &random_cap(), &[7u8; 65]).await, live_res);
    assert_eq!(db.total_message_count().unwrap(), 0);
}

#[tokio::test]
async fn deposit_pow_prompt_is_identical_for_live_dead_and_unknown_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.pow.registration_always_requires_pow = false;
    // Type 1: always-on at 10 bits. Type 2: above 1/min at the 8-bit floor.
    cfg.pow.ephemeral_deposit_min_difficulty = 10;
    cfg.pow.deposit_pow_threshold_per_min = 1;
    let (server, _db) = server_for(cfg);

    // The challenge bytes and expiry differ per prompt; everything else must match.
    let prompt = |(status, text): (u16, String)| {
        let mut body: serde_json::Value = serde_json::from_str(&text).unwrap();
        let ch = body["pow_challenge"].as_object_mut().expect("429 carries a challenge");
        assert!(ch.remove("challenge").is_some() && ch.remove("expires_at").is_some());
        (status, body)
    };

    // Type 1: the first deposit already demands PoW, live or dead.
    let (live1, dead1) = live_and_dead(&server, 1, 262_144).await;
    let live_prompt = prompt(deposit_raw(&server, &live1, b"a").await);
    assert_eq!(live_prompt.0, 429);
    assert_eq!(live_prompt.1["pow_challenge"]["difficulty"], 10);
    assert_eq!(prompt(deposit_raw(&server, &dead1, b"a").await), live_prompt);

    // Type 2 (and unknown, treated as type 2): free once, then the 8-bit prompt.
    let (live2, dead2) = live_and_dead(&server, 2, 262_144).await;
    let mut prompts = Vec::new();
    for cap in [live2, dead2, random_cap()] {
        assert_eq!(deposit_raw(&server, &cap, b"a").await.0, 200);
        prompts.push(prompt(deposit_raw(&server, &cap, b"b").await));
    }
    assert_eq!(prompts[0].0, 429);
    assert_eq!(prompts[0].1["pow_challenge"]["difficulty"], 8);
    assert_eq!(prompts[1], prompts[0], "dead type-2 cap prompts like a live one");
    assert_eq!(prompts[2], prompts[0], "unknown cap prompts like a live type-2 one");
}

#[tokio::test]
async fn repeated_deposit_id_is_identical_for_live_dead_and_unknown_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.pow.registration_always_requires_pow = false;
    let (server, db) = server_for(cfg);
    let (live, dead) = live_and_dead(&server, 2, 262_144).await;

    let id = |(status, text): (u16, String)| {
        assert_eq!(status, 200, "{text}");
        let id = serde_json::from_str::<DepositResponse>(&text).unwrap().message_id;
        // Shaped exactly like a real id: msg-<UUIDv4>.
        let uuid = uuid::Uuid::parse_str(id.strip_prefix("msg-").unwrap()).unwrap();
        assert_eq!(uuid.get_version_num(), 4);
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
        id
    };
    for cap in [live, dead, random_cap()] {
        let first = id(deposit_raw(&server, &cap, b"same blob").await);
        assert_eq!(id(deposit_raw(&server, &cap, b"same blob").await), first);
        assert_ne!(id(deposit_raw(&server, &cap, b"other blob").await), first);
    }
    assert_eq!(db.total_message_count().unwrap(), 2, "two distinct live blobs");

    // A blob deposited while live keeps its id after deactivation, as live dedup.
    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_typed(&server, &fetch_cap, &deposit_cap, 2, 262_144).await;
    let before = id(deposit_raw(&server, &deposit_cap, b"pre").await);
    server
        .post("/v1/capability/deactivate")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(id(deposit_raw(&server, &deposit_cap, b"pre").await), before);
}

#[tokio::test]
async fn bloom_is_gone_and_attestation_serves() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    // S16 §3.12 is reserved: the capability-free queue-presence filter is removed.
    assert_eq!(server.get("/v1/bloom").await.status_code(), 404);

    // No operator key configured → unsigned attestation.
    let res = server.get("/v1/attestation").await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    assert_eq!(body["signature"], "");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn register_pair(server: &TestServer, fetch_cap: &[u8; 32], deposit_cap: &[u8; 32]) {
    let body = json!({
        "fetch_capability": b64cap(fetch_cap),
        "deposit_capability": b64cap(deposit_cap),
    });

    // Registration ALWAYS requires PoW (§7.2): first call → 429 + challenge,
    // then solve at the issued difficulty and re-submit (§7.1 register binding
    // = fetch_cap || deposit_cap).
    let res = server.post("/v1/capability/register").json(&body).await;
    assert_eq!(res.status_code(), 429, "{}", res.text());
    let err: ErrorBody = res.json();
    let challenge = err.pow_challenge.expect("429 must carry a PoW challenge");
    let ch_bytes: [u8; 32] = B64.decode(&challenge.challenge).unwrap()[..32]
        .try_into()
        .unwrap();
    let mut binding = Vec::with_capacity(64);
    binding.extend_from_slice(fetch_cap);
    binding.extend_from_slice(deposit_cap);
    let (nonce, hash) = solve(&ch_bytes, &binding, challenge.difficulty);

    let mut solved = body;
    solved["pow_solution"] = json!({
        "challenge": challenge.challenge,
        "nonce": nonce,
        "hash": B64.encode(hash),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });
    let res = server.post("/v1/capability/register").json(&solved).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
}

#[tokio::test]
async fn retire_at_in_config_retires_the_server_and_status_reports_it() {
    // §13: the operator sets `[server].retire_at` and restarts. Registration
    // then gets 503, existing queues keep working, and `/v1/status` reports
    // the status and the time.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    let (server, _db) = server_for(cfg.clone());
    let (fetch_cap, deposit_cap) = (random_cap(), random_cap());
    register_pair(&server, &fetch_cap, &deposit_cap).await;
    let status = |server: TestServer| async move {
        let res = server
            .post("/v1/status")
            .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        res.json::<serde_json::Value>()
    };
    let active = status(server).await;
    assert_eq!(active["server_status"], "Active");
    assert!(active.get("retire_at").is_none());

    let retire_at = chrono::Utc::now().timestamp() + 14 * 86_400;
    cfg.server.retire_at = Some(retire_at);
    let (server, _db) = server_for(cfg); // the restart, same database
    let res = server
        .post("/v1/capability/register")
        .json(&json!({
            "fetch_capability": b64cap(&random_cap()),
            "deposit_capability": b64cap(&random_cap()),
        }))
        .await;
    assert_eq!(res.status_code(), 503, "{}", res.text());
    assert_eq!(
        deposit_raw(&server, &deposit_cap, b"still served").await.0,
        200
    );
    let retiring = status(server).await;
    assert_eq!(retiring["server_status"], "Retiring");
    assert_eq!(retiring["retire_at"], retire_at);
}

#[tokio::test]
async fn register_per_min_caps_attempts_on_one_pair() {
    // §8: `register_per_min` counts per fetch capability before PoW, so past
    // the ceiling the server answers 429 without minting another challenge.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.rate_limits.register_per_min = 2;
    let (server, _db) = server_for(cfg);
    let body = json!({
        "fetch_capability": b64cap(&random_cap()),
        "deposit_capability": b64cap(&random_cap()),
    });
    let mut challenged = Vec::new();
    for _ in 0..3 {
        let res = server.post("/v1/capability/register").json(&body).await;
        assert_eq!(res.status_code(), 429, "{}", res.text());
        challenged.push(res.json::<ErrorBody>().pow_challenge.is_some());
    }
    assert_eq!(challenged, [true, true, false]);
    // Another pair has its own window.
    let other = json!({
        "fetch_capability": b64cap(&random_cap()),
        "deposit_capability": b64cap(&random_cap()),
    });
    let res = server.post("/v1/capability/register").json(&other).await;
    assert!(res.json::<ErrorBody>().pow_challenge.is_some());
}

#[tokio::test]
async fn status_reports_opk_low_below_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.opk.low_alert_threshold = 2;
    let db = Arc::new(Database::open(&cfg).unwrap());
    let state = AppState::new(db, Arc::new(cfg)).unwrap();
    let server = TestServer::new(api::router(state.clone()));

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    let status = || async {
        server
            .post("/v1/status")
            .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
            .await
            .json::<serde_json::Value>()
    };
    // Empty pool counts as low (nothing left to serve).
    assert_eq!(status().await["opk_low"], true);

    // Top up above the threshold (3 OPKs > threshold 2).
    let bundle = |n: u32| {
        json!({
            "deposit_capability": b64cap(&deposit_cap),
            "fetch_capability": b64cap(&fetch_cap),
            "bundle": {
                "identity_key": B64.encode([7u8; 32]),
                "signed_prekey": B64.encode([8u8; 32]),
                "signed_prekey_id": n,
                "signed_prekey_signature": B64.encode([9u8; 64]),
                "manifest": {"opk_id_set_hash": B64.encode([3u8; 32]), "opk_count": 3, "timestamp": 0, "signature": B64.encode([4u8; 64])},
                "one_time_prekeys": [
                    {"id": n, "key": B64.encode([n as u8; 32])},
                    {"id": n + 100, "key": B64.encode([(n + 100) as u8; 32])},
                    {"id": n + 200, "key": B64.encode([(n + 200) as u8; 32])},
                ],
            },
        })
    };
    let res = server.post("/v1/prekey/upload").json(&bundle(1)).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    assert_eq!(status().await["opk_low"], false); // 3 > 2

    // Drain to exactly 1: refuse-last serves while >1 remain, so the pool
    // lands on 1 and the flag flips low — never to zero.
    let fetch = json!({ "deposit_capability": b64cap(&deposit_cap) });
    server.post("/v1/prekey/fetch").json(&fetch).await; // 3 → 2 (served)
    server.post("/v1/prekey/fetch").json(&fetch).await; // 2 → 1 (served)
    let res = server.post("/v1/prekey/fetch").json(&fetch).await; // refused
    let body: serde_json::Value = res.json();
    assert!(body.get("one_time_prekeys").is_none_or(|v| v.is_null()));
    assert_eq!(status().await["opk_low"], true); // 1 <= 2
}

#[tokio::test]
async fn status_carries_batching_attestation_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir);
    cfg.batching.min_hold_secs = 30;
    cfg.batching.max_hold_secs = 300;
    cfg.batching.jitter_secs = 60;
    cfg.attestation.jurisdiction = "CH".into();
    cfg.attestation.operator_key_seed_hex = "11".repeat(32);
    cfg.attestation.publish_batching_attestation = true;
    let db = Arc::new(Database::open(&cfg).unwrap());
    let state = AppState::new(db, Arc::new(cfg.clone())).unwrap();
    let server = TestServer::new(api::router(state));

    let fetch_cap = random_cap();
    let deposit_cap = random_cap();
    register_pair(&server, &fetch_cap, &deposit_cap).await;

    let res = server
        .post("/v1/status")
        .json(&json!({ "fetch_capability": b64cap(&fetch_cap) }))
        .await;
    assert_eq!(res.status_code(), 200);
    let body: serde_json::Value = res.json();
    let att = body["batching_attestation"]
        .as_object()
        .expect("attestation present")
        .clone();
    assert_eq!(att["min_hold_secs"], 30);
    assert_eq!(att["max_hold_secs"], 300);
    assert_eq!(att["jitter_secs"], 60);
    let sig = att["signature"].as_str().unwrap().to_string();
    let signed_at = att["signed_at"].as_i64().unwrap();
    assert!(!sig.is_empty());

    // Verify the signature against the documented preimage.
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::Digest;
    let seed: [u8; 32] = std::array::from_fn(|_| 0x11);
    let vk = VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(&seed));
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"najwa-batching-attestation-v1");
    hasher.update(30u32.to_be_bytes());
    hasher.update(300u32.to_be_bytes());
    hasher.update(60u32.to_be_bytes());
    hasher.update(signed_at.to_be_bytes());
    let sig_bytes: [u8; 64] = B64.decode(&sig).unwrap()[..64].try_into().unwrap();
    let signature = Signature::from_slice(&sig_bytes).expect("64-byte signature");
    let ok = vk.verify(&hasher.finalize(), &signature);
    assert!(ok.is_ok(), "batching attestation signature must verify");
}

#[tokio::test]
async fn json_hardening_rejects_duplicate_keys_nesting_and_arrays() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    // Duplicate key (§12 reject-duplicate-keys).
    let res = server
        .post("/v1/fetch")
        .text(r#"{"fetch_capability":"AAAA","fetch_capability":"AAAA"}"#)
        .add_header("content-type", "application/json")
        .await;
    assert_eq!(res.status_code(), 400, "{}", res.text());

    // Nesting beyond 4.
    let res = server
        .post("/v1/fetch")
        .text(r#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#)
        .add_header("content-type", "application/json")
        .await;
    assert_eq!(res.status_code(), 400);

    // Array beyond 200.
    let long: Vec<&str> = vec!["\"x\""; 201];
    let body = format!("{{\"ids\":[{}]}}", long.join(","));
    let res = server
        .post("/v1/fetch")
        .text(&body)
        .add_header("content-type", "application/json")
        .await;
    assert_eq!(res.status_code(), 400);
}

#[tokio::test]
async fn responses_honor_the_fixed_deadline() {
    // §14: a fast MISS (unknown capability → immediate 404) is still held to
    // arrival + RESPONSE_DEADLINE_MS, so timing cannot oracle the lookup.
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir);
    let (server, _db) = server_for(cfg);

    let start = std::time::Instant::now();
    let res = server
        .post("/v1/fetch")
        .json(&json!({ "fetch_capability": b64cap(&random_cap()) }))
        .await;
    let elapsed = start.elapsed();
    assert_eq!(res.status_code(), 404);
    assert!(
        elapsed >= std::time::Duration::from_millis(95),
        "fast-path response must be held to the §14 deadline; took {elapsed:?}"
    );
}

fn sha256_prefix8(data: &[u8]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(data);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}
