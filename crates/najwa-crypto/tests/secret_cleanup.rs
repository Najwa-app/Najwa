//! Observe initialized synthetic secrets immediately before allocator release.
//! This deliberately never reads freed memory.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering::SeqCst};

use najwa_crypto::kdf::{argon2id, argon2id_variable, hkdf_extract, Argon2Params};

struct InspectingAllocator;
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static RELEASED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);
static BLOCK_RELEASES: AtomicUsize = AtomicUsize::new(0);
static DIRTY_BLOCKS: AtomicBool = AtomicBool::new(false);
const ARGON_BYTES: usize = 64 * 1024 * 1024;

unsafe impl GlobalAlloc for InspectingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr == WATCHED.load(SeqCst) {
            // The test registers only fully initialized, padding-free byte buffers.
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            DIRTY.store(bytes.iter().any(|b| *b != 0), SeqCst);
            RELEASED.store(true, SeqCst);
            WATCHED.store(std::ptr::null_mut(), SeqCst);
        }
        if layout.size() == ARGON_BYTES {
            // The only allocation of this size in this binary is the initialized
            // Argon2 block vector. Inspect every block, before System.dealloc.
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            DIRTY_BLOCKS.fetch_or(bytes.iter().any(|b| *b != 0), SeqCst);
            BLOCK_RELEASES.fetch_add(1, SeqCst);
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: InspectingAllocator = InspectingAllocator;

fn watch(ptr: *const u8) {
    RELEASED.store(false, SeqCst);
    DIRTY.store(false, SeqCst);
    WATCHED.store(ptr.cast_mut(), SeqCst);
}

fn assert_wiped() {
    assert!(RELEASED.load(SeqCst), "the watched buffer was not released");
    assert!(
        !DIRTY.load(SeqCst),
        "secret bytes survived until deallocation"
    );
}

#[test]
fn kdf_secrets_and_argon_workspace_are_wiped_on_drop_error_and_unwind() {
    // A single test owns the allocator observation slots; no ordering dependence.
    for unwind in [false, true] {
        let prk = Box::new(hkdf_extract(b"synthetic salt", b"synthetic key"));
        assert!(prk.iter().any(|b| *b != 0));
        watch(prk.as_ptr());
        let result = std::panic::catch_unwind(move || {
            let _prk = prk;
            if unwind {
                panic!("exercise PRK unwind cleanup");
            }
        });
        assert_eq!(result.is_err(), unwind);
        assert_wiped();
    }

    let key =
        Box::new(argon2id(b"synthetic password", &[5; 32], &Argon2Params::ABSOLUTE_MIN).unwrap());
    assert!(key.iter().any(|b| *b != 0));
    watch(key.as_ptr());
    drop(key);
    assert_wiped();

    let output = argon2id_variable(
        b"synthetic phrase",
        &[6; 32],
        &Argon2Params::ABSOLUTE_MIN,
        160,
    )
    .unwrap();
    assert!(output.iter().any(|b| *b != 0));
    watch(output.as_ptr());
    assert!(std::panic::catch_unwind(move || {
        let _output = output;
        panic!("exercise rendezvous-output unwind cleanup");
    })
    .is_err());
    assert_wiped();

    // Argon2 rejects this salt after allocating its guarded workspace.
    assert!(argon2id_variable(
        b"synthetic password",
        b"short",
        &Argon2Params::ABSOLUTE_MIN,
        160
    )
    .is_err());
    assert_eq!(BLOCK_RELEASES.load(SeqCst), 3);
    assert!(
        !DIRTY_BLOCKS.load(SeqCst),
        "Argon2 working memory was not wiped"
    );
}
