//! Every block reaches the inner allocator zeroed, including blocks freed by a
//! moving `realloc`. The inner allocator inspects blocks just before release;
//! freed memory is never read.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

use najwa_crypto::memory::ZeroizingAllocator;

struct Inspector;
static WATCHING: AtomicBool = AtomicBool::new(false);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for Inspector {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(SeqCst) {
            // ZeroizingAllocator has written every byte before this call.
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            DIRTY.fetch_or(bytes.iter().any(|b| *b != 0), SeqCst);
            RELEASED.fetch_add(1, SeqCst);
        }
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: ZeroizingAllocator<Inspector> = ZeroizingAllocator(Inspector);

#[test]
fn released_blocks_are_zeroed_including_moved_reallocations() {
    WATCHING.store(true, SeqCst);
    let mut text = String::from("synthetic passphrase");
    for _ in 0..12 {
        // Growth reallocates and releases the previous, filled block.
        text.push_str(" synthetic recovery words");
    }
    let block = vec![0xA5_u8; 64 * 1024].into_boxed_slice();
    assert!(text.len() > 256 && block[0] == 0xA5);
    drop(text);
    drop(block);
    WATCHING.store(false, SeqCst);

    assert!(RELEASED.load(SeqCst) >= 3, "growth and drops must release blocks");
    assert!(!DIRTY.load(SeqCst), "a block was released with non-zero bytes");
}
