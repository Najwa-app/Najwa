//! Secure memory utilities: zeroization, guarded memory, mlock.
//!
//! Provides:
//! - [`GuardedMemory<T>`] — value in its own locked pages, zeroed on drop
//! - [`mlock`] / [`munlock`] — safe wrappers for memory locking
//! - [`disable_core_dumps`] — prevent secret leakage via crash dumps
//! - [`zeroize_slice`] — explicit secure zeroing
//! - [`ZeroizingAllocator`] — global allocator that zeroes every block on release
//! - [`constant_time_eq`] — re-exported from [`crate::hash`]

use std::alloc::{GlobalAlloc, Layout};
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroize;

use crate::error::Result;
// CryptoError is used in platform submodules directly.

/// Securely zero a byte slice.
pub fn zeroize_slice(data: &mut [u8]) {
    data.zeroize();
}

/// Global allocator that zeroes every block before releasing it (S01 §6.1).
///
/// It covers copies of secrets that Najwa's own code cannot reach, such as
/// buffers inside the HTTP stack and the JSON parser. Applications install it
/// with `#[global_allocator]`. `realloc` always moves the block, so the old
/// copy is zeroed too.
pub struct ZeroizingAllocator<A = std::alloc::System>(pub A);

// SAFETY: every method forwards to the inner allocator with the caller's layout;
// blocks are only written (zeroed) while still owned, before they are released.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroizingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller owns `layout.size()` bytes at `ptr` until this release.
        // memset is fast even in debug builds (multi-hundred-MiB Argon2 blocks);
        // the fence and black_box keep the stores from being removed as dead
        // stores before the release.
        std::ptr::write_bytes(ptr, 0, layout.size());
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        std::hint::black_box(ptr);
        self.0.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the GlobalAlloc contract guarantees `new_size`, rounded up to
        // `layout.align()`, does not overflow.
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new = self.0.alloc(new_layout);
        if !new.is_null() {
            std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        new
    }
}

// ---------------------------------------------------------------------------
// mlock / munlock — platform-specific
// ---------------------------------------------------------------------------

/// Lock a memory region to prevent paging to disk (best effort).
///
/// Safe wrapper over the platform call (S01 §6.2). An empty slice is a no-op.
pub fn mlock(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    mlock_raw(data.as_ptr(), data.len())
}

/// Unlock a previously locked memory region.
pub fn munlock(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    munlock_raw(data.as_ptr(), data.len())
}

/// Low-level mlock: `mlock(2)` or `VirtualLock` (S01 §6.2).
pub fn mlock_raw(ptr: *const u8, len: usize) -> Result<()> {
    platform::mlock_impl(ptr, len)
}

/// Low-level munlock: `munlock(2)` or `VirtualUnlock` (S01 §6.2).
pub fn munlock_raw(ptr: *const u8, len: usize) -> Result<()> {
    platform::munlock_impl(ptr, len)
}

/// Raise this process's limit on locked memory, once, so SQLCipher's
/// `cipher_memory_security` and [`GuardedMemory`] can lock what they allocate
/// (S01 §6.2). Windows: a soft minimum working set of 64 MiB, which bounds
/// what `VirtualLock` may lock. Linux and macOS: the soft
/// `RLIMIT_MEMLOCK` raised to the hard limit. Best effort: a failure is logged
/// and memory that cannot be locked stays pageable.
pub fn ensure_lock_quota() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Err(error) = platform::lock_quota_impl() {
            tracing::warn!("locked-memory quota not raised: {error} (S01 §6.2)");
        }
    });
}

/// The Windows minimum working set requested by [`ensure_lock_quota`] (S01
/// §6.2). Measured: the storage unit tests lock every buffer at 64 MiB and log
/// about 6 000 refused locks at 32 MiB; the default quota is about 150 KB.
#[cfg(target_os = "windows")]
const LOCK_QUOTA: usize = 64 << 20;

/// Disable core dumps for this process (S01 §6.3).
///
/// On Linux: `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`.
/// On macOS: `RLIMIT_CORE = 0`.
/// On Windows: `SetErrorMode` to suppress the crash dialog. Crash dumps are
/// suppressed by [`exclude_from_error_reporting`], which the application calls.
pub fn disable_core_dumps() -> Result<()> {
    platform::disable_core_dumps_impl()
}

/// Exclude this executable from Windows Error Reporting, which writes crash
/// dumps (S01 §6.3). The exclusion is persistent and per user (HKCU), keyed by
/// the executable's file name, so only the shipped application calls it;
/// library callers and test binaries do not.
#[cfg(windows)]
pub fn exclude_from_error_reporting() -> Result<()> {
    platform::exclude_from_error_reporting_impl()
}

// ---------------------------------------------------------------------------
// GuardedMemory<T>
// ---------------------------------------------------------------------------

/// Live `GuardedMemory` regions the OS refused to lock (S01 §6.2).
static UNLOCKED_REGIONS: AtomicUsize = AtomicUsize::new(0);

/// Number of live [`GuardedMemory`] regions that could not be locked and are
/// pageable, for example because `RLIMIT_MEMLOCK` or the Windows working-set
/// quota is too small (S01 §6.2). Zero means every guarded secret is locked.
/// Applications may report it as a status.
pub fn unlocked_region_count() -> usize {
    UNLOCKED_REGIONS.load(Ordering::Relaxed)
}

/// A value in its own page-aligned allocation of whole pages, locked against
/// paging where the OS allows it, and zeroed before release (S01 §6.2).
///
/// No other value shares its pages, so locking or unlocking it never affects
/// anything else. If the lock fails the value stays usable in pageable memory
/// and [`unlocked_region_count`] counts it. `T` must hold its secret inline:
/// memory that `T` owns elsewhere (a `Vec`'s buffer) is not locked.
pub struct GuardedMemory<T> {
    ptr: NonNull<T>,
    layout: Layout,
    locked: bool,
}

// SAFETY: GuardedMemory uniquely owns its `T`, like `Box<T>`.
unsafe impl<T: Send> Send for GuardedMemory<T> {}
// SAFETY: shared access only hands out `&T`, like `Box<T>`.
unsafe impl<T: Sync> Sync for GuardedMemory<T> {}

impl<T> GuardedMemory<T> {
    /// Move `value` into a new region of its own and lock it (best effort).
    pub fn new(value: T) -> Self {
        let page = platform::page_size();
        assert!(std::mem::align_of::<T>() <= page, "alignment above page size");
        let size = std::mem::size_of::<T>().max(1).div_ceil(page) * page;
        let layout = Layout::from_size_align(size, page).expect("page-rounded layout");
        // SAFETY: `layout` has a non-zero size.
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let Some(ptr) = NonNull::new(raw.cast::<T>()) else {
            std::alloc::handle_alloc_error(layout)
        };
        // Lock before the secret is written, so it is never pageable.
        let locked = mlock_raw(raw, size).is_ok();
        if !locked {
            UNLOCKED_REGIONS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("secret memory could not be locked; it stays pageable (S01 §6.2)");
        }
        // SAFETY: `ptr` is valid for writes of `T` and aligned (page >= align).
        unsafe { ptr.as_ptr().write(value) };
        Self {
            ptr,
            layout,
            locked,
        }
    }

    /// Read-only access.
    pub fn read(&self) -> &T {
        self
    }

    /// Mutable access.
    pub fn write(&mut self) -> &mut T {
        self
    }

    /// Whether the OS locked the region against paging.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T> std::ops::Deref for GuardedMemory<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `ptr` holds an initialized `T` for the life of `self`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> std::ops::DerefMut for GuardedMemory<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` gives unique access.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for GuardedMemory<T> {
    fn drop(&mut self) {
        let raw = self.ptr.as_ptr().cast::<u8>();
        // SAFETY: `self` owns the initialized `T` and all `layout.size()` bytes
        // until the release below; the `T` is dropped exactly once.
        let region = unsafe {
            std::ptr::drop_in_place(self.ptr.as_ptr());
            std::slice::from_raw_parts_mut(raw.cast::<MaybeUninit<u8>>(), self.layout.size())
        };
        // Zero the whole region, then unlock and release it.
        region.zeroize();
        if self.locked {
            let _ = munlock_raw(raw, self.layout.size());
        } else {
            UNLOCKED_REGIONS.fetch_sub(1, Ordering::Relaxed);
        }
        // SAFETY: allocated in `new` with this exact layout.
        unsafe { std::alloc::dealloc(raw, self.layout) };
    }
}

impl<T> std::fmt::Debug for GuardedMemory<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedMemory")
            .field("inner", &"[REDACTED]")
            .field("locked", &self.locked)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Platform implementations
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use crate::error::{CryptoError, Result};

    pub fn page_size() -> usize {
        // SAFETY: GetSystemInfo only fills the struct it is given.
        let info = unsafe {
            let mut info = std::mem::zeroed();
            windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info);
            info
        };
        info.dwPageSize as usize
    }

    pub fn mlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: VirtualLock is safe for valid memory regions we own.
        let ret = unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut _, len) };
        if ret == 0 {
            Err(CryptoError::MlockFailed("VirtualLock failed".into()))
        } else {
            Ok(())
        }
    }

    pub fn munlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: VirtualUnlock is safe for valid memory regions previously locked with VirtualLock.
        let ret = unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut _, len) };
        if ret == 0 {
            Err(CryptoError::MunlockFailed("VirtualUnlock failed".into()))
        } else {
            Ok(())
        }
    }

    pub fn lock_quota_impl() -> Result<()> {
        use windows_sys::Win32::System::Memory::{
            GetProcessWorkingSetSizeEx, SetProcessWorkingSetSizeEx,
            QUOTA_LIMITS_HARDWS_MAX_DISABLE, QUOTA_LIMITS_HARDWS_MIN_DISABLE,
        };
        let quota = super::LOCK_QUOTA;
        // SAFETY: the pseudo-handle needs no closing; the outputs are locals.
        let (process, mut min, mut max, mut flags) =
            (unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() }, 0, 0, 0);
        if unsafe { GetProcessWorkingSetSizeEx(process, &mut min, &mut max, &mut flags) } == 0 {
            return Err(CryptoError::MlockFailed(format!(
                "GetProcessWorkingSetSizeEx: {}",
                std::io::Error::last_os_error()
            )));
        }
        if min >= quota {
            return Ok(());
        }
        // Soft limits: the minimum sets the VirtualLock quota without pinning
        // unlocked pages, and the maximum does not cap the working set.
        let soft = QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
        // SAFETY: changes only this process's working-set limits.
        if unsafe { SetProcessWorkingSetSizeEx(process, quota, max.max(quota), soft) } == 0 {
            return Err(CryptoError::MlockFailed(format!(
                "SetProcessWorkingSetSizeEx({quota}): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub fn disable_core_dumps_impl() -> Result<()> {
        // Suppress the crash dialog.
        // SAFETY: SetErrorMode is a safe Win32 call that only affects the process error mode.
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(
                windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS
                    | windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX,
            );
        }
        Ok(())
    }

    pub fn exclude_from_error_reporting_impl() -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        // S01 §6.3: exclude this executable from Windows Error Reporting, which
        // writes crash dumps. An in-process exception filter would not do: a
        // Rust abort (__fastfail) bypasses it. Per user (HKCU), keyed by the
        // executable's file name; needs no administrator rights.
        let exe: Vec<u16> = std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.encode_wide().chain([0]).collect())
            })
            .ok_or_else(|| {
                CryptoError::CoreDumpDisableFailed("executable name unavailable".into())
            })?;
        // SAFETY: `exe` is a NUL-terminated UTF-16 string that outlives the call.
        let hr = unsafe {
            windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication(exe.as_ptr(), 0)
        };
        if hr < 0 {
            return Err(CryptoError::CoreDumpDisableFailed(format!(
                "WerAddExcludedApplication failed: {hr:#x}"
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use crate::error::{CryptoError, Result};

    pub fn page_size() -> usize {
        // SAFETY: sysconf takes no pointers.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size).unwrap_or(4096)
    }

    pub fn mlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: ptr and len describe a valid, owned memory region allocated by Box/Vec.
        // libc::mlock only advises the kernel; it cannot corrupt memory.
        let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if ret != 0 {
            Err(CryptoError::MlockFailed(format!(
                "mlock errno={}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    pub fn munlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: ptr and len describe a region previously locked with mlock_impl.
        let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        if ret != 0 {
            Err(CryptoError::MunlockFailed(format!(
                "munlock errno={}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    pub fn lock_quota_impl() -> Result<()> {
        // ponytail: soft limit up to the hard one; raising the hard limit needs privilege.
        let failed = |call: &str| {
            CryptoError::MlockFailed(format!("{call}: {}", std::io::Error::last_os_error()))
        };
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit only writes the local `limit`.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
            return Err(failed("getrlimit(RLIMIT_MEMLOCK)"));
        }
        if limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            // SAFETY: setrlimit only reads the local `limit`.
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
                return Err(failed("setrlimit(RLIMIT_MEMLOCK)"));
            }
        }
        Ok(())
    }

    pub fn disable_core_dumps_impl() -> Result<()> {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) is a safe process-level operation with no
        // pointer arguments; it only prevents the kernel from generating core dumps.
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret != 0 {
            return Err(CryptoError::CoreDumpDisableFailed(
                "prctl(PR_SET_DUMPABLE) failed".into(),
            ));
        }
        // Also set RLIMIT_CORE to 0
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: rlim is a valid stack-allocated rlimit struct; setrlimit only
        // modifies process resource limits.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret != 0 {
            return Err(CryptoError::CoreDumpDisableFailed(
                "setrlimit(RLIMIT_CORE) failed".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::error::{CryptoError, Result};

    pub fn page_size() -> usize {
        // SAFETY: sysconf takes no pointers.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size).unwrap_or(4096)
    }

    pub fn mlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: ptr and len describe a valid, owned memory region allocated by Box/Vec.
        // libc::mlock only advises the kernel; it cannot corrupt memory.
        let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        if ret != 0 {
            Err(CryptoError::MlockFailed(format!(
                "mlock errno={}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    pub fn munlock_impl(ptr: *const u8, len: usize) -> Result<()> {
        // SAFETY: ptr and len describe a region previously locked with mlock_impl.
        let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        if ret != 0 {
            Err(CryptoError::MunlockFailed(format!(
                "munlock errno={}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    pub fn lock_quota_impl() -> Result<()> {
        // ponytail: soft limit up to the hard one; raising the hard limit needs privilege.
        let failed = |call: &str| {
            CryptoError::MlockFailed(format!("{call}: {}", std::io::Error::last_os_error()))
        };
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit only writes the local `limit`.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
            return Err(failed("getrlimit(RLIMIT_MEMLOCK)"));
        }
        if limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            // SAFETY: setrlimit only reads the local `limit`.
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
                return Err(failed("setrlimit(RLIMIT_MEMLOCK)"));
            }
        }
        Ok(())
    }

    pub fn disable_core_dumps_impl() -> Result<()> {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: rlim is a valid stack-allocated rlimit struct; setrlimit only
        // modifies process resource limits.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret != 0 {
            return Err(CryptoError::CoreDumpDisableFailed(
                "setrlimit(RLIMIT_CORE) failed".into(),
            ));
        }
        Ok(())
    }
}

// Fallback for other platforms (Android, iOS, etc.)
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod platform {
    use crate::error::{CryptoError, Result};

    pub fn page_size() -> usize {
        // ponytail: nothing is locked here, so the page size only affects padding.
        4096
    }

    pub fn mlock_impl(_ptr: *const u8, _len: usize) -> Result<()> {
        // Best effort: not available on this platform
        Err(CryptoError::MlockFailed(
            "mlock not supported on this platform".into(),
        ))
    }

    pub fn munlock_impl(_ptr: *const u8, _len: usize) -> Result<()> {
        Ok(())
    }

    pub fn lock_quota_impl() -> Result<()> {
        // Nothing is locked here (see mlock_impl), so there is no quota to raise.
        Ok(())
    }

    pub fn disable_core_dumps_impl() -> Result<()> {
        // Best effort: not available
        Err(CryptoError::CoreDumpDisableFailed(
            "core dump prevention not supported on this platform".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_slice_works() {
        let mut data = [0xFFu8; 32];
        zeroize_slice(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn guarded_memory_read_write() {
        let mut gm = GuardedMemory::new([0x42u8; 32]);
        assert_eq!(gm.read(), &[0x42u8; 32]);
        gm.write()[0] = 0x00;
        assert_eq!(gm.read()[0], 0x00);
    }

    // S01 §6.2: each region is whole pages of its own, so locking or unlocking
    // one never touches a page another value uses.
    #[test]
    fn guarded_regions_are_whole_pages_and_never_share_one() {
        let page = platform::page_size();
        let small = GuardedMemory::new([1u8; 32]);
        let large = GuardedMemory::new([2u8; 5000]);
        for (region, pages) in [(&small.layout, 1), (&large.layout, 5000usize.div_ceil(page))] {
            assert_eq!((region.size(), region.align()), (pages * page, page));
        }
        let (a, b) = (small.ptr.as_ptr() as usize, large.ptr.as_ptr() as usize);
        assert_eq!((a % page, b % page), (0, 0));
        assert!(a + small.layout.size() <= b || b + large.layout.size() <= a);
    }

    #[test]
    fn guarded_memory_debug_redacted() {
        let gm = GuardedMemory::new([0u8; 16]);
        let dbg = format!("{:?}", gm);
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("0"));
    }

    // S01 §6.2: the default Windows quota locks about 150 KB; after the raise a
    // region of several MiB locks.
    #[cfg(windows)]
    #[test]
    fn raised_lock_quota_locks_several_mebibytes() {
        ensure_lock_quota();
        let region = vec![1u8; 8 << 20];
        mlock(&region).unwrap();
        munlock(&region).unwrap();
    }

    #[test]
    fn mlock_empty_slice_ok() {
        assert!(mlock(&[]).is_ok());
        assert!(munlock(&[]).is_ok());
    }
}
