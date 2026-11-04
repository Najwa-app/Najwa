//! `GuardedMemory` zeroes its whole region before releasing it (S01 §6.2).
//! The allocator inspects the region just before release; it never reads freed memory.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use najwa_crypto::memory::GuardedMemory;

struct InspectingAllocator;
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for InspectingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == WATCHED.load(SeqCst) {
            // The region was fully initialized: zeroed on allocation, then written.
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            DIRTY.store(bytes.iter().any(|b| *b != 0), SeqCst);
            RELEASED.store(true, SeqCst);
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: InspectingAllocator = InspectingAllocator;

#[test]
fn guarded_region_is_locked_and_zeroed_before_release() {
    let secret = GuardedMemory::new([0xA5u8; 64]);
    // Windows grants a default working-set quota; one page always fits.
    #[cfg(windows)]
    assert!(secret.is_locked() && najwa_crypto::memory::unlocked_region_count() == 0);
    WATCHED.store(secret.as_ptr() as usize, SeqCst);
    drop(secret);
    assert!(RELEASED.load(SeqCst), "the region was not released");
    assert!(!DIRTY.load(SeqCst), "secret bytes survived until release");
}
