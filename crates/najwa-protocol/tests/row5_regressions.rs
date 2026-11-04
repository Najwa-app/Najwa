//! Row 5 failures exercised at public boundaries, including real SQLite commits.
use najwa_crypto::keys::Ed25519KeyPair;
use najwa_protocol::contact::{
    accept::{accept_contact, ContactStore, LocalContactCapability, NewContact, StoredMailbox},
    generate_printable_card,
    introduction::{IntroductionMailbox, IntroductionPayload, INTRODUCTION_VERSION},
    rendezvous::{
        assess_phrase, estimate_entropy, generate_phrase, PhraseStrength, RendezvousError,
        RendezvousSession, MAX_PHRASE_BYTES, MIN_ENTROPY_BITS,
    },
    ContactError, HandshakePayload, MailboxInfo, QrCardConfig,
};
use najwa_protocol::directory::{
    DirectoryEntry, ServerStatus, SignedDirectory, DIRECTORY_MAX_AGE_SECS,
};
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::message::envelope::{envelope_decrypt, envelope_encrypt};
use najwa_protocol::pseudonym::types::ContactId;
use najwa_storage::{
    contact_establishment::ContactTarget, database::SqliteStorage, types::NewMailbox,
};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed(&[seed; 32])
}
fn mailbox(letter: char, token: u8, secret: u8) -> MailboxConfig {
    let mut m = MailboxConfig::new(
        letter.to_string().repeat(56),
        [token.wrapping_add(1); 32],
        [token; 32],
    );
    m.envelope_secret = [secret; 32];
    m
}
fn payload() -> HandshakePayload {
    HandshakePayload::create(&key(2), &[mailbox('a', 10, 20)], "Bob", 48).unwrap()
}
fn directory() -> SignedDirectory {
    SignedDirectory {
        version: 1,
        created_at: 1_000_000,
        signatures: vec![],
        servers: vec![DirectoryEntry {
            onion_address: "a".repeat(56),
            operator_id: "operator-a".into(),
            jurisdiction: "CH".into(),
            status: ServerStatus::Active,
            last_verified: 1_000_000,
        }],
    }
}
fn authorities() -> Vec<najwa_crypto::keys::Ed25519Public> {
    (1..=3).map(|n| key(n).public().clone()).collect()
}

#[test]
fn directory_requires_distinct_signatures() {
    let mut d = directory();
    let sig = d.sign(0, &key(1));
    d.signatures = vec![sig; 10];
    assert!(d.verify(&authorities()).is_err());
    d.signatures.push(d.sign(2, &key(3)));
    assert!(d.verify(&authorities()).is_ok());
}
#[test]
fn directory_requires_three_distinct_trusted_keys() {
    let mut d = directory();
    d.signatures = vec![d.sign(0, &key(1)), d.sign(1, &key(1))];
    let mut pubs = authorities();
    pubs[1] = pubs[0].clone();
    assert!(d.verify(&pubs).is_err());
    d.signatures[1] = d.sign(1, &key(2));
    let mut extra = authorities();
    extra.push(key(4).public().clone());
    assert!(d.verify(&extra).is_err());
    assert!(d.verify(&authorities()[..2]).is_err());
}
#[test]
fn invalid_signature_does_not_consume_the_signers_slot() {
    let mut d = directory();
    let mut bad = d.sign(0, &key(1));
    bad.signature[0] ^= 1;
    d.signatures = vec![bad, d.sign(0, &key(1)), d.sign(1, &key(2))];
    assert!(d.verify(&authorities()).is_ok());
}
#[test]
fn every_directory_metadata_field_is_authenticated() {
    let mut d = directory();
    d.signatures = vec![d.sign(0, &key(1)), d.sign(1, &key(2))];
    for field in 0..5 {
        let mut tampered = d.clone();
        match field {
            0 => tampered.servers[0].operator_id.push('x'),
            1 => tampered.servers[0].jurisdiction = "US".into(),
            2 => tampered.servers[0].onion_address = "b".repeat(56),
            3 => tampered.servers[0].status = ServerStatus::Removed,
            _ => tampered.servers[0].last_verified += 1,
        }
        assert!(tampered.verify(&authorities()).is_err(), "field {field}");
    }
}
#[test]
fn directory_metadata_has_unambiguous_length_framing() {
    let mut d = directory();
    d.servers[0].operator_id = "ab".into();
    d.servers[0].jurisdiction = "c".into();
    d.signatures = vec![d.sign(0, &key(1)), d.sign(1, &key(2))];
    d.servers[0].operator_id = "a".into();
    d.servers[0].jurisdiction = "bc".into();
    assert!(d.verify(&authorities()).is_err());
}
#[test]
fn future_directory_clock_skew_is_bounded_without_underflow() {
    let mut d = directory();
    assert!(!d.is_stale_at(d.created_at));
    assert!(!d.is_stale_at(d.created_at - 60));
    assert!(!d.is_stale_at(d.created_at - 300));
    assert!(d.is_stale_at(d.created_at - 301));
    assert!(!d.is_stale_at(d.created_at + DIRECTORY_MAX_AGE_SECS));
    assert!(d.is_stale_at(d.created_at + DIRECTORY_MAX_AGE_SECS + 1));
    d.created_at = u64::MAX;
    assert!(d.is_stale_at(0));
}

fn db() -> SqliteStorage {
    let db = SqliteStorage::open_in_memory(&[0x66; 32]).unwrap();
    db.save_mailbox(&NewMailbox {
        onion_address: "l".repeat(56),
        fetch_capability: vec![1; 32],
        deposit_capability: vec![2; 32],
        envelope_secret: vec![3; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
        priority: 0,
        created_at: 1,
    })
    .unwrap();
    db
}
fn targets(db: &SqliteStorage, id: ContactId) -> Vec<ContactTarget> {
    db.get_setting(&format!("contact_targets:{}", id.0))
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn serde_legacy_route_tampering_cannot_change_persisted_destination() {
    let mut json = serde_json::to_value(payload()).unwrap();
    json["mailboxes"][0]["onion_address"] = "attacker".into();
    let mut p: HandshakePayload = serde_json::from_value(json).unwrap();
    p.mailboxes[0].deposit_capability = [99; 32];
    p.mailboxes.push(MailboxInfo {
        onion_address: "extra".into(),
        deposit_capability: [88; 32],
    });
    let db = db();
    let accepted = accept_contact(&key(1), &db, &p).await.unwrap();
    let remote = targets(&db, accepted.contact_id);
    assert_eq!(remote.len(), 1);
    assert_eq!(remote[0].onion, "a".repeat(56));
    assert_eq!(remote[0].deposit_capability, [10; 32]);
    assert_eq!(remote[0].envelope_secret, [20; 32]);
}
#[tokio::test]
async fn missing_legacy_field_does_not_drop_remote_destinations() {
    let mut p = payload();
    p.mailboxes.clear();
    let db = db();
    let accepted = accept_contact(&key(1), &db, &p).await.unwrap();
    assert_eq!(targets(&db, accepted.contact_id)[0].onion, "a".repeat(56));
}
#[tokio::test]
async fn distinct_unknown_mailboxes_and_their_secrets_survive_acceptance() {
    let p = HandshakePayload::create(
        &key(2),
        &[mailbox('a', 10, 20), mailbox('b', 10, 21)],
        "Bob",
        48,
    )
    .unwrap();
    let decoded = HandshakePayload::from_bytes(&p.to_bytes()).unwrap();
    let db = db();
    let accepted = accept_contact(&key(1), &db, &decoded).await.unwrap();
    let remote = targets(&db, accepted.contact_id);
    assert_eq!(remote.len(), 2);
    assert_eq!(remote[0].onion, "a".repeat(56));
    assert_eq!(remote[1].onion, "b".repeat(56));
    for (target, entry) in remote.iter().zip(&decoded.mailbox_entries) {
        assert_eq!(target.mailbox_entry, entry.to_bytes());
        let encrypted = envelope_encrypt(
            &target.envelope_secret,
            &target.deposit_capability,
            b"Initial",
        )
        .unwrap();
        assert_eq!(
            envelope_decrypt(
                &entry.envelope_secret,
                &entry.deposit_capability,
                &encrypted
            )
            .unwrap(),
            b"Initial"
        );
    }
    let caps = db
        .get_contact_capabilities(accepted.contact_id.0 as i64)
        .unwrap();
    assert_eq!(caps.len(), 1);
    assert!(caps[0].mailbox_id > 0);
    assert!(caps[0].registered_at.is_none());
    assert!(caps[0].envelope_secret.is_some());
    assert_eq!(
        db.list_mailboxes().unwrap().len(),
        1,
        "remote servers are not local receive mailboxes"
    );
    assert_eq!(
        db.get_setting_raw(&format!("contact_handshake:{}", accepted.contact_id.0))
            .unwrap()
            .unwrap(),
        p.to_bytes()
    );
}
struct FaultStore {
    db: SqliteStorage,
    fail: AtomicBool,
}
#[async_trait::async_trait]
impl ContactStore for FaultStore {
    async fn get_contact_by_ik(&self, ik: &[u8; 32]) -> Result<Option<ContactId>, String> {
        ContactStore::get_contact_by_ik(&self.db, ik).await
    }
    async fn list_mailboxes(&self) -> Result<Vec<StoredMailbox>, String> {
        let mut local = ContactStore::list_mailboxes(&self.db).await?;
        if self.fail.load(Ordering::SeqCst) {
            local.push(StoredMailbox {
                id: 9999,
                onion_address: "nonexistent".into(),
                fetch_capability: [1; 32],
            });
        }
        Ok(local)
    }
    async fn commit_contact(
        &self,
        contact: &NewContact,
        local: &[LocalContactCapability],
        p: &HandshakePayload,
    ) -> Result<ContactId, ContactError> {
        ContactStore::commit_contact(&self.db, contact, local, p).await
    }
}
#[tokio::test]
async fn database_error_rolls_back_contact_settings_and_earlier_capability_writes() {
    let store = FaultStore {
        db: db(),
        fail: AtomicBool::new(true),
    };
    let p = payload();
    assert!(matches!(
        accept_contact(&key(1), &store, &p).await,
        Err(ContactError::StorageError(_))
    ));
    assert!(store.db.list_contacts().unwrap().is_empty());
    assert!(store.db.get_contact_capabilities(1).unwrap().is_empty());
    for prefix in ["contact_target", "contact_targets", "contact_handshake"] {
        assert!(store
            .db
            .get_setting_raw(&format!("{prefix}:1"))
            .unwrap()
            .is_none());
    }
    store.fail.store(false, Ordering::SeqCst);
    let accepted = accept_contact(&key(1), &store, &p).await.unwrap();
    assert_eq!(store.db.list_contacts().unwrap().len(), 1);
    assert_eq!(
        store
            .db
            .get_contact_capabilities(accepted.contact_id.0 as i64)
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn duplicate_accept_does_not_replace_existing_credentials() {
    let db = db();
    let p = payload();
    let accepted = accept_contact(&key(1), &db, &p).await.unwrap();
    let before = db
        .get_contact_capabilities(accepted.contact_id.0 as i64)
        .unwrap();
    assert!(matches!(
        accept_contact(&key(1), &db, &p).await,
        Err(ContactError::AlreadyExists)
    ));
    let after = db
        .get_contact_capabilities(accepted.contact_id.0 as i64)
        .unwrap();
    assert_eq!(after[0].deposit_capability, before[0].deposit_capability);
    assert_eq!(after[0].fetch_capability, before[0].fetch_capability);
}
#[tokio::test]
async fn absent_local_mailboxes_leave_no_contact() {
    let db = SqliteStorage::open_in_memory(&[55; 32]).unwrap();
    assert!(accept_contact(&key(1), &db, &payload()).await.is_err());
    assert!(db.list_contacts().unwrap().is_empty());
}

#[tokio::test]
async fn deleting_accepted_contact_removes_only_its_credential_settings() {
    let db = db();
    let first = accept_contact(&key(1), &db, &payload())
        .await
        .unwrap()
        .contact_id
        .0;
    let other = HandshakePayload::create(&key(3), &[mailbox('b', 30, 40)], "Carol", 48).unwrap();
    let second = accept_contact(&key(1), &db, &other)
        .await
        .unwrap()
        .contact_id
        .0;
    db.delete_contact(first as i64).unwrap();
    assert!(db.get_contact(first as i64).unwrap().is_none());
    assert!(db
        .get_contact_capabilities(first as i64)
        .unwrap()
        .is_empty());
    for prefix in ["contact_target", "contact_targets", "contact_handshake"] {
        assert!(db
            .get_setting_raw(&format!("{prefix}:{first}"))
            .unwrap()
            .is_none());
        assert!(db
            .get_setting_raw(&format!("{prefix}:{second}"))
            .unwrap()
            .is_some());
    }
    assert!(db.get_contact(second as i64).unwrap().is_some());
}

#[test]
fn malformed_unicode_qr_returns_errors_instead_of_panicking() {
    for body in ["😀😀", "éééé", "A😀B😀C", "00000é", "é000000"] {
        let outcome =
            std::panic::catch_unwind(|| HandshakePayload::from_qr_string(&format!("NAJWA:{body}")));
        assert!(outcome.unwrap().is_err());
    }
}
fn base45(data: &[u8]) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    let mut out = String::new();
    for chunk in data.chunks(2) {
        let mut value = if chunk.len() == 2 {
            chunk[0] as usize * 256 + chunk[1] as usize
        } else {
            chunk[0] as usize
        };
        for _ in 0..if chunk.len() == 2 { 3 } else { 2 } {
            out.push(CHARS[value % 45] as char);
            value /= 45;
        }
    }
    out
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}
fn bomb_qr() -> String {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&vec![0; 1024 * 1024]).unwrap();
    let body = base45(&z.finish().unwrap());
    format!(
        "NAJWA:{}{}",
        body,
        base45(&crc32(body.as_bytes()).to_be_bytes())
    )
}

// Track allocations on the current test thread only, after the test has built
// its attacker input. Large allocations would reproduce the old decoder bug.
struct TrackingAllocator;
std::thread_local! {
    static TRACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MAX_ALLOC: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn record_allocation(size: usize) {
    let _ = TRACK.try_with(|enabled| {
        if enabled.get() {
            let _ = MAX_ALLOC.try_with(|m| m.set(m.get().max(size)));
        }
    });
}
unsafe impl std::alloc::GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        record_allocation(layout.size());
        std::alloc::System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        record_allocation(size);
        std::alloc::System.realloc(ptr, layout, size)
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
fn measured_decode(f: impl FnOnce() -> bool) -> (bool, usize) {
    MAX_ALLOC.set(0);
    TRACK.set(true);
    let rejected = f();
    TRACK.set(false);
    (rejected, MAX_ALLOC.get())
}
#[test]
fn qr_bomb_is_rejected_before_allocating_the_expanded_payload() {
    let qr = bomb_qr();
    assert!(qr.len() < 2048);
    let (rejected, largest) = measured_decode(|| HandshakePayload::from_qr_string(&qr).is_err());
    assert!(rejected);
    assert!(largest < 128 * 1024, "decoder allocation {largest}");
}
#[test]
fn huge_encoded_inputs_are_rejected_before_decode_allocation() {
    let uri = format!("najwa://contact?data={}", "A".repeat(1_000_000));
    let qr = format!("NAJWA:{}", "0".repeat(1_000_000));
    for decode in [0, 1] {
        let (rejected, largest) = measured_decode(|| {
            if decode == 0 {
                HandshakePayload::from_uri(&uri).is_err()
            } else {
                HandshakePayload::from_qr_string(&qr).is_err()
            }
        });
        assert!(rejected);
        assert!(largest < 4096, "allocation {largest}");
    }
}
#[test]
fn maximum_valid_handshake_roundtrips_through_both_bounded_codecs() {
    let mailboxes: Vec<_> = (0..8)
        .map(|i| mailbox((b'a' + i) as char, i, i + 10))
        .collect();
    let p = HandshakePayload::create(&key(2), &mailboxes, &"x".repeat(128), 48).unwrap();
    assert_eq!(p.to_bytes().len(), 1980);
    HandshakePayload::from_qr_string(&p.to_qr_string().unwrap())
        .unwrap()
        .verify()
        .unwrap();
    HandshakePayload::from_uri(&p.to_uri().unwrap())
        .unwrap()
        .verify()
        .unwrap();
}
#[test]
fn handshake_constructor_rejects_invalid_structure_and_overflow() {
    let m = [mailbox('a', 10, 20)];
    for hours in [0, u64::MAX] {
        assert!(HandshakePayload::create(&key(2), &m, "Bob", hours).is_err());
    }
    for name in ["x".repeat(129), "é".repeat(65)] {
        assert!(HandshakePayload::create(&key(2), &m, &name, 1).is_err());
    }
    assert!(HandshakePayload::create(&key(2), &[], "Bob", 1).is_err());
    assert!(HandshakePayload::create(&key(2), &vec![m[0].clone(); 9], "Bob", 1).is_err());
}
#[tokio::test]
async fn signed_typed_invalid_handshakes_fail_every_acceptance_boundary() {
    for variant in 0..5 {
        let mut p = payload();
        match variant {
            0 => p.version = 255,
            1 => p.mailbox_entries.clear(),
            2 => p.mailbox_entries.resize(9, p.mailbox_entries[0].clone()),
            3 => p.display_name = "x".repeat(129),
            _ => p.expires_at = p.created_at,
        }
        p.signature = key(2).sign(&p.signable_bytes()).to_bytes();
        let p: HandshakePayload = serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap();
        assert!(p.verify().is_err());
        assert!(p.to_qr_string().is_err());
        assert!(p.to_uri().is_err());
        let db = db();
        assert!(accept_contact(&key(1), &db, &p).await.is_err());
        assert!(db.list_contacts().unwrap().is_empty());
    }
}
#[test]
fn handshake_rejects_unsigned_trailing_bytes() {
    let mut bytes = payload().to_bytes();
    bytes.push(0);
    assert!(HandshakePayload::from_bytes(&bytes).is_err());
}

#[test]
fn repeated_and_common_phrases_do_not_gain_strength_from_word_count() {
    for phrase in [
        "a a a a a a",
        "password password password password password password",
        "to be or not to be",
        "correct horse battery staple",
    ] {
        assert!(estimate_entropy(phrase) < MIN_ENTROPY_BITS, "{phrase}");
        assert_eq!(assess_phrase(phrase), PhraseStrength::Weak);
        assert!(matches!(
            RendezvousSession::from_phrase(phrase, &[mailbox('a', 10, 20)]),
            Err(RendezvousError::WeakPhrase { .. })
        ));
    }
}
#[test]
fn phrase_estimation_is_normalization_invariant_and_input_bounded() {
    assert_eq!(
        estimate_entropy("  A A\tA A A A "),
        estimate_entropy("a a a a a a")
    );
    let huge = "x".repeat(MAX_PHRASE_BYTES + 1);
    assert_eq!(assess_phrase(&huge), PhraseStrength::Weak);
    assert!(matches!(
        RendezvousSession::from_phrase(&huge, &[mailbox('a', 10, 20)]),
        Err(RendezvousError::PhraseTooLong)
    ));
}
#[test]
fn generated_rendezvous_phrases_are_distinct_and_pass_the_strength_gate() {
    let a = generate_phrase();
    let b = generate_phrase();
    assert_ne!(*a, *b);
    assert_eq!(a.split_whitespace().count(), 12);
    assert!(estimate_entropy(&a) >= MIN_ENTROPY_BITS);
    assert!(estimate_entropy(&b) >= MIN_ENTROPY_BITS);
}

fn introduction() -> IntroductionPayload {
    IntroductionPayload::create(
        &key(1),
        &key(2).public().to_bytes(),
        "Bob",
        &[IntroductionMailbox {
            onion_address: "a".repeat(56),
            deposit_capability: [10; 32],
            envelope_secret: [20; 32],
        }],
        7,
    )
    .unwrap()
}
#[test]
fn introduction_wire_roundtrip_enables_the_first_deposit_envelope() {
    let p = IntroductionPayload::from_bytes(&introduction().to_bytes()).unwrap();
    p.verify(key(1).public()).unwrap();
    assert_eq!(p.version, INTRODUCTION_VERSION);
    let m = &p.introduced_mailboxes[0];
    let envelope =
        envelope_encrypt(&m.envelope_secret, &m.deposit_capability, b"first Initial").unwrap();
    assert_eq!(
        envelope_decrypt(&[20; 32], &[10; 32], &envelope).unwrap(),
        b"first Initial"
    );
    assert!(envelope_decrypt(&[10; 32], &[10; 32], &envelope).is_err());
}
#[test]
fn introduction_authenticates_the_envelope_secret() {
    let mut p = introduction();
    p.introduced_mailboxes[0].envelope_secret[0] ^= 1;
    assert!(p.verify(key(1).public()).is_err());
}
#[test]
fn introduction_rejects_legacy_missing_secret_wire_and_trailing_bytes() {
    let mut bytes = introduction().to_bytes();
    bytes[0] = 1;
    assert!(IntroductionPayload::from_bytes(&bytes).is_err());
    bytes = introduction().to_bytes();
    bytes.push(0);
    assert!(IntroductionPayload::from_bytes(&bytes).is_err());
    bytes = introduction().to_bytes();
    bytes.truncate(bytes.len() - 32);
    assert!(IntroductionPayload::from_bytes(&bytes).is_err());
}
#[test]
fn printable_card_escapes_markup_and_preserves_unicode() {
    let svg = String::from_utf8(generate_printable_card(
        "NAJWA:TEST",
        &QrCardConfig {
            display_name: "أحمد & Bob </text><script>alert(1)</script>".into(),
            instruction: "A < B & C > D\0".into(),
            show_expiration: true,
        },
    ))
    .unwrap();
    assert!(svg.contains("أحمد &amp; Bob &lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(svg.contains("A &lt; B &amp; C &gt; D"));
    assert!(!svg.contains("<script>"));
    assert!(!svg.contains('\0'));
}
