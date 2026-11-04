//! Observe only registered, initialized byte ranges before allocator release.
//! No freed memory or uninitialized Vec capacity is read.
use super::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering::SeqCst};

struct InspectingAllocator;
const SLOTS: usize = 16;
// Named constant repeat operands preserve the crate's Rust 1.75 compatibility.
#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_POINTER: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_LENGTH: AtomicUsize = AtomicUsize::new(0);
static POINTERS: [AtomicPtr<u8>; SLOTS] = [EMPTY_POINTER; SLOTS];
static LENGTHS: [AtomicUsize; SLOTS] = [EMPTY_LENGTH; SLOTS];
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);
thread_local! { static OBSERVING: Cell<bool> = const { Cell::new(false) }; }

pub(super) fn observe(bytes: &[u8]) {
    if OBSERVING.with(Cell::get) && !bytes.is_empty() {
        let slot = POINTERS
            .iter()
            .position(|pointer| pointer.load(SeqCst).is_null())
            .unwrap();
        LENGTHS[slot].store(bytes.len(), SeqCst);
        POINTERS[slot].store(bytes.as_ptr().cast_mut(), SeqCst);
        REGISTERED.fetch_add(1, SeqCst);
    }
}

unsafe impl GlobalAlloc for InspectingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        for (slot, watched) in POINTERS.iter().enumerate() {
            if watched.load(SeqCst) == ptr {
                // Registered while the Vec owned and initialized precisely this range.
                let bytes = std::slice::from_raw_parts(ptr, LENGTHS[slot].load(SeqCst));
                DIRTY.fetch_or(bytes.iter().any(|byte| *byte != 0), SeqCst);
                watched.store(std::ptr::null_mut(), SeqCst);
                RELEASED.fetch_add(1, SeqCst);
            }
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: InspectingAllocator = InspectingAllocator;

fn checked(operation: impl FnOnce(), minimum_buffers: usize) {
    REGISTERED.store(0, SeqCst);
    RELEASED.store(0, SeqCst);
    DIRTY.store(false, SeqCst);
    OBSERVING.with(|active| active.set(true));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    OBSERVING.with(|active| active.set(false));
    assert!(REGISTERED.load(SeqCst) >= minimum_buffers);
    assert_eq!(REGISTERED.load(SeqCst), RELEASED.load(SeqCst));
    assert!(!DIRTY.load(SeqCst), "plaintext survived until deallocation");
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn backup_plaintext_is_wiped_on_success_error_and_unwind() {
    // One test owns the observer. Other test threads never register pointers.
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<Mnemonic>();
    let identity = Identity {
        keypair: Ed25519KeyPair::from_seed(&[7; 32]),
        created_at: 0,
        version: 3,
    };
    let (phrase, record) = create_recovery_record(&identity, 12).unwrap();
    checked(
        || {
            assert!(recover_from_recovery_record(&phrase, &record, "").is_err());
        },
        2,
    ); // valid decryption, then a later password-validation error
    let wrong_phrase = Mnemonic::from_entropy(&[3; 16]).unwrap().to_string();
    checked(
        || {
            assert!(recover_from_recovery_record(&wrong_phrase, &record, "password").is_err());
        },
        1,
    ); // authentication failure must still wipe recovery entropy
    let phrase24 = export_seed_phrase(&identity).unwrap();
    checked(
        || {
            assert!(recover_from_seed_phrase(&phrase24, "").is_err());
        },
        1,
    );
    // Build a valid encrypted-backup fixture using the accepted Argon2 floor.
    // The recovered heap seed must be wiped even when installing the identity
    // later fails password validation.
    let params = Argon2Params::ABSOLUTE_MIN;
    let salt = [3; 32];
    let nonce = [4; 24];
    let public = identity.keypair.public().to_bytes();
    let aad = [AAD_BACKUP_PREFIX, &[1], &public].concat();
    let key = argon2id(b"backup password", &salt, &params).unwrap();
    let encrypted = aead::encrypt(&key, &nonce, &[7; 32], &aad).unwrap();
    let mut record = Vec::from(BACKUP_MAGIC);
    record.extend_from_slice(&[1, BACKUP_KDF_ALG, BACKUP_AEAD_ALG, 0]);
    for parameter in [params.memory_kib, params.iterations, params.parallelism] {
        record.extend_from_slice(&parameter.to_be_bytes());
    }
    record.extend_from_slice(&salt);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&public);
    record.extend_from_slice(&encrypted);
    record.extend_from_slice(&sha256(&record));
    checked(
        || {
            assert!(restore_encrypted_backup(&record, "backup password", "").is_err());
        },
        1,
    );
    let backup = ContactBackup {
        version: 1,
        created_at: 0,
        contacts: vec![],
        mailboxes: vec![MailboxBackupEntry {
            onion_address: "synthetic.onion".into(),
            fetch_capability: vec![0x45; 32],
            deposit_capability: vec![0x46; 32],
        }],
    };
    checked(
        || {
            let blob = create_contact_backup(&[7; 32], &backup).unwrap();
            let restored = restore_contact_backup(&[7; 32], &blob).unwrap();
            assert_eq!(restored.mailboxes[0].fetch_capability, vec![0x45; 32]);
        },
        2,
    );
    let key = hkdf_sha256(&[7; 32], b"", info_strings::CONTACT_BACKUP_INFO, 32).unwrap();
    let nonce = [1; 24];
    let ciphertext = aead::encrypt(
        key.as_slice().try_into().unwrap(),
        &nonce,
        b"not JSON",
        b"contact-backup",
    )
    .unwrap();
    let blob = [nonce.as_slice(), &ciphertext].concat();
    checked(
        || {
            assert!(restore_contact_backup(&[7; 32], &blob).is_err());
        },
        1,
    );
    checked(
        || {
            let result = std::panic::catch_unwind(|| {
                let _plaintext = secret_vec(vec![0xAA; 32]);
                panic!("exercise unwinding of a live backup buffer");
            });
            assert!(result.is_err());
        },
        1,
    );
}
