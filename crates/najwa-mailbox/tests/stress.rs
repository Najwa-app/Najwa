//! Concurrency & volume stress tests for the mailbox `Database` layer.
//!
//! They target the structural properties surfaced by the robustness review:
//!   * the soft message quota is a NON-atomic check-then-insert (a real TOCTOU),
//!   * ack-as-cursor pagination (drift-fix #5) is correct across many pages,
//!   * dedup collapses concurrent duplicate deposits (race-safe under the lock),
//!   * the single global connection mutex keeps writes correct under load.
//!
//! All DB methods hold a `std::sync::Mutex<Connection>` for the duration of one
//! operation, so these run on a multi-thread runtime to get real contention.

use std::collections::HashSet;
use std::sync::Arc;

use najwa_mailbox::config::BatchingConfig;
use najwa_mailbox::db::models::CapabilitySettings;
use najwa_mailbox::db::Database;

const NOW: i64 = 1_700_000_000;

/// No hold, no jitter → `release_at == now`, so a fetch at `NOW` sees the deposit
/// immediately (keeps volume/pagination tests fast and deterministic).
fn immediate_batching() -> BatchingConfig {
    BatchingConfig {
        min_hold_secs: 0,
        max_hold_secs: 0,
        jitter_secs: 0,
    }
}

/// Exercise retry deduplication alongside an explicit hold window. Immediate
/// release also retains a bounded dedup window.
/// `message_count` counts rows regardless of `release_at`, so the batched hold
/// doesn't affect the assertion.
fn dedup_window() -> BatchingConfig {
    BatchingConfig {
        min_hold_secs: 0,
        max_hold_secs: 300,
        jitter_secs: 0,
    }
}

fn register(db: &Database, fetch_cap: &[u8; 32], deposit_cap: &[u8; 32]) {
    db.register_capability(
        fetch_cap,
        deposit_cap,
        &CapabilitySettings::default(),
        2,
        None,
        48 * 3600,
        NOW,
    )
    .expect("register_capability");
}

/// S16 §3.7 type-1 idempotency: repeat prekey fetches on an ephemeral (type-1)
/// capability return the SAME bundle + SAME consumed OPK byte-identically and
/// consume nothing more. Without the cache, each repeat would consume the NEXT
/// OPK (a different id/key), so byte-equality across fetches proves the cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn type1_prekey_fetch_is_idempotent() {
    let db = Database::open_in_memory().unwrap();
    let fetch_cap = [0x91u8; 32];
    let deposit_cap = [0x92u8; 32];
    db.register_capability(
        &fetch_cap,
        &deposit_cap,
        &CapabilitySettings::default(),
        1,
        None,
        48 * 3600,
        NOW,
    )
    .expect("register type-1");
    // 3 OPKs so a fetch can consume one under the refuse-last-OPK rule.
    let opks: Vec<(u32, [u8; 32])> = (0..3).map(|i| (i, [(i + 1) as u8; 32])).collect();
    db.upload_prekey_bundle(&fetch_cap, "{\"k\":1}", &opks, 200, NOW)
        .unwrap();

    let first = db
        .fetch_prekey_bundle(&fetch_cap, 1)
        .unwrap()
        .expect("bundle");
    let second = db
        .fetch_prekey_bundle(&fetch_cap, 1)
        .unwrap()
        .expect("bundle");
    let third = db
        .fetch_prekey_bundle(&fetch_cap, 1)
        .unwrap()
        .expect("bundle");

    assert!(first.1.is_some(), "first type-1 fetch consumes an OPK");
    assert_eq!(first, second, "type-1 repeat fetch is idempotent (cached)");
    assert_eq!(first, third, "still identical on the third fetch");
}

/// A type-2 capability is NOT idempotent — each fetch consumes the next OPK.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn type2_prekey_fetch_consumes_each_time() {
    let db = Database::open_in_memory().unwrap();
    let fetch_cap = [0x93u8; 32];
    let deposit_cap = [0x94u8; 32];
    db.register_capability(
        &fetch_cap,
        &deposit_cap,
        &CapabilitySettings::default(),
        2,
        None,
        48 * 3600,
        NOW,
    )
    .expect("register type-2");
    let opks: Vec<(u32, [u8; 32])> = (0..4).map(|i| (i, [(i + 1) as u8; 32])).collect();
    db.upload_prekey_bundle(&fetch_cap, "{\"k\":1}", &opks, 200, NOW)
        .unwrap();

    let first = db.fetch_prekey_bundle(&fetch_cap, 2).unwrap().unwrap();
    let second = db.fetch_prekey_bundle(&fetch_cap, 2).unwrap().unwrap();
    assert_ne!(first.1, second.1, "type-2 fetches consume distinct OPKs");
}

/// S16 §10 step 6 + FK cascade: an expired capability and ALL its child rows
/// (deposit_caps, messages) are removed by cleanup with foreign_keys=ON — the
/// parent DELETE would FK-violate without the child-first cascade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_cascades_expired_capability() {
    let db = Database::open_in_memory().unwrap();
    let fetch_cap = [0x77u8; 32];
    let deposit_cap = [0x88u8; 32];
    // Type-2 cap created in the past with expires_at already elapsed.
    db.register_capability(
        &fetch_cap,
        &deposit_cap,
        &CapabilitySettings::default(),
        2,
        Some(NOW - 1),
        48 * 3600,
        NOW - 100,
    )
    .expect("register");
    db.deposit_message(
        &fetch_cap,
        &deposit_cap,
        b"m",
        NOW - 50,
        &immediate_batching(),
    )
    .unwrap();
    assert_eq!(db.message_count(&fetch_cap).unwrap(), 1);

    let stats = db.cleanup(NOW, 14 * 86_400, 100).expect("cleanup");
    assert_eq!(
        stats.caps_deleted, 1,
        "expired capability deleted (S16 §10 step 6)"
    );
    assert_eq!(
        db.message_count(&fetch_cap).unwrap(),
        0,
        "messages cascaded"
    );
    assert!(
        db.lookup_deposit_cap_state(&deposit_cap).unwrap().is_none(),
        "deposit_cap cascaded — no orphan rows under foreign_keys=ON"
    );
}

/// Regression for the deposit quota TOCTOU. `deposit_message_checked` performs
/// the count/storage checks and the insert under ONE lock hold, so concurrent
/// depositors at the ceiling can no longer each observe room and all insert.
/// A `Barrier` forces maximal contention: all RACERS hit the atomic path at once
/// with the mailbox one slot short of full; exactly ONE must be admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_deposits_respect_quota_atomically() {
    const MAX: u64 = 1000;
    const RACERS: usize = 16;
    const UNLIMITED_STORAGE: u64 = 1 << 40; // isolate the message-count ceiling

    let db = Arc::new(Database::open_in_memory().unwrap());
    let fetch_cap = [0x11u8; 32];
    let deposit_cap = [0x22u8; 32];
    register(&db, &fetch_cap, &deposit_cap);

    // Pre-fill to exactly MAX-1 (999): exactly one more deposit is legal.
    let batching = immediate_batching();
    for i in 0..(MAX - 1) {
        db.deposit_message(
            &fetch_cap,
            &deposit_cap,
            format!("m{i}").as_bytes(),
            NOW,
            &batching,
        )
        .unwrap();
    }
    assert_eq!(db.message_count(&fetch_cap).unwrap(), MAX - 1);

    let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for i in 0..RACERS {
        let (db, batching, barrier) = (db.clone(), batching.clone(), barrier.clone());
        let (fc, dc) = (fetch_cap, deposit_cap);
        handles.push(tokio::spawn(async move {
            barrier.wait().await; // maximise the concurrent collision at the ceiling
            let blob = format!("race-{i}");
            matches!(
                db.deposit_message_checked(
                    &fc,
                    &dc,
                    blob.as_bytes(),
                    NOW,
                    &batching,
                    MAX,
                    UNLIMITED_STORAGE
                )
                .unwrap(),
                najwa_mailbox::db::DepositOutcome::Stored(_)
            )
        }));
    }
    let mut stored = 0usize;
    for h in handles {
        if h.await.unwrap() {
            stored += 1;
        }
    }

    let final_count = db.message_count(&fetch_cap).unwrap();
    // Atomic quota: exactly one racer fills the last slot; the rest are rejected.
    assert_eq!(stored, 1, "exactly one deposit fits under the ceiling");
    assert_eq!(
        final_count, MAX,
        "atomic quota holds the ceiling under concurrency — no overshoot"
    );
    eprintln!("[quota-atomic] {RACERS} racers at the ceiling → 1 stored, {} rejected, final={final_count}", RACERS - 1);
}

/// Ack-as-cursor (drift-fix #5 / D13): there is no `since_id`. To page past
/// `limit`, the client must `acknowledge` (delete) each batch so the next fetch
/// returns the next one. This drives 250 messages through a 50-per-page drain
/// and asserts every message is delivered exactly once — no skips, no repeats,
/// no infinite re-read of page one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ack_as_cursor_drains_all_messages_without_loss_or_repeat() {
    const TOTAL: usize = 250;
    const PAGE: u32 = 50;

    let db = Arc::new(Database::open_in_memory().unwrap());
    let fetch_cap = [0x33u8; 32];
    let deposit_cap = [0x44u8; 32];
    register(&db, &fetch_cap, &deposit_cap);

    let batching = immediate_batching();
    for i in 0..TOTAL {
        db.deposit_message(
            &fetch_cap,
            &deposit_cap,
            format!("msg-{i:04}").as_bytes(),
            NOW,
            &batching,
        )
        .unwrap();
    }

    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut pages = 0;
    loop {
        let batch = db.fetch_messages(&fetch_cap, PAGE, NOW).unwrap();
        if batch.is_empty() {
            break;
        }
        pages += 1;
        assert!(
            batch.len() <= PAGE as usize,
            "server must honour the page limit"
        );
        let ids: Vec<String> = batch.iter().map(|m| m.id.clone()).collect();
        for m in &batch {
            assert!(
                seen.insert(m.blob.clone()),
                "message delivered twice: {:?}",
                m.id
            );
        }
        // Acknowledge (delete) this page so the next fetch advances.
        let deleted = db.acknowledge_messages(&fetch_cap, &ids).unwrap();
        assert_eq!(
            deleted as usize,
            ids.len(),
            "every acked id must delete exactly one row"
        );
    }

    assert_eq!(
        seen.len(),
        TOTAL,
        "every deposited message must be delivered exactly once"
    );
    assert_eq!(
        db.message_count(&fetch_cap).unwrap(),
        0,
        "mailbox fully drained"
    );
    assert!(
        pages >= (TOTAL / PAGE as usize),
        "must have paged through the backlog"
    );
    eprintln!("[ack-cursor] drained {TOTAL} messages across {pages} pages, zero loss/dupes");
}

/// Dedup (drift-fix #7): the `(deposit_cap, blob_hash)` primary key + the
/// SELECT-then-INSERT under a single lock make deposit idempotent even under
/// concurrency. Many simultaneous deposits of the SAME blob collapse to one row,
/// and every caller gets the same `message_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_duplicate_deposits_collapse_to_one() {
    const DUPES: usize = 24;

    let db = Arc::new(Database::open_in_memory().unwrap());
    let fetch_cap = [0x55u8; 32];
    let deposit_cap = [0x66u8; 32];
    register(&db, &fetch_cap, &deposit_cap);

    let batching = dedup_window(); // dedup TTL = max_hold + jitter, so needs a non-zero hold
    let blob = b"identical-ciphertext-blob".to_vec();

    let barrier = Arc::new(tokio::sync::Barrier::new(DUPES));
    let mut handles = Vec::new();
    for _ in 0..DUPES {
        let (db, batching, barrier, blob) =
            (db.clone(), batching.clone(), barrier.clone(), blob.clone());
        let (fc, dc) = (fetch_cap, deposit_cap);
        handles.push(tokio::spawn(async move {
            barrier.wait().await; // maximise the concurrent collision
            db.deposit_message(&fc, &dc, &blob, NOW, &batching).unwrap()
        }));
    }
    let mut ids = HashSet::new();
    for h in handles {
        ids.insert(h.await.unwrap());
    }

    assert_eq!(
        db.message_count(&fetch_cap).unwrap(),
        1,
        "duplicate deposits must store exactly one row"
    );
    assert_eq!(
        ids.len(),
        1,
        "every duplicate deposit must return the same message_id"
    );
    eprintln!("[dedup] {DUPES} concurrent identical deposits → 1 stored row, 1 shared id");
}

/// Integrity under the single global connection mutex: concurrent deposits fanned
/// across many distinct capabilities must not lose writes or cross-contaminate.
/// Each cap ends with exactly its own messages, and no blob leaks between caps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_deposits_across_caps_stay_isolated_and_complete() {
    const CAPS: usize = 20;
    const PER_CAP: usize = 25;

    let db = Arc::new(Database::open_in_memory().unwrap());
    let caps: Vec<([u8; 32], [u8; 32])> = (0..CAPS)
        .map(|i| {
            let mut fc = [0u8; 32];
            let mut dc = [0u8; 32];
            fc[0] = 0x80 + i as u8;
            dc[0] = 0xC0 + i as u8;
            register(&db, &fc, &dc);
            (fc, dc)
        })
        .collect();

    let batching = immediate_batching();
    let mut handles = Vec::new();
    for (fc, dc) in caps.clone() {
        for j in 0..PER_CAP {
            let (db, batching) = (db.clone(), batching.clone());
            handles.push(tokio::spawn(async move {
                let blob = format!("cap{}-{j}", fc[0]);
                db.deposit_message(&fc, &dc, blob.as_bytes(), NOW, &batching)
                    .unwrap();
            }));
        }
    }
    for h in handles {
        h.await.unwrap();
    }

    let mut total = 0;
    for (fc, _dc) in &caps {
        assert_eq!(
            db.message_count(fc).unwrap(),
            PER_CAP as u64,
            "each capability must retain exactly its own {PER_CAP} messages"
        );
        // Every stored blob for this cap must belong to this cap (no cross-write).
        let rows = db.fetch_messages(fc, PER_CAP as u32 * 2, NOW).unwrap();
        for m in &rows {
            assert!(
                m.blob.starts_with(format!("cap{}-", fc[0]).as_bytes()),
                "blob leaked across capabilities"
            );
        }
        total += db.message_count(fc).unwrap();
    }
    assert_eq!(
        total,
        (CAPS * PER_CAP) as u64,
        "no writes lost under concurrent load"
    );
    eprintln!("[isolation] {CAPS} caps × {PER_CAP} concurrent deposits → all isolated & complete");
}
