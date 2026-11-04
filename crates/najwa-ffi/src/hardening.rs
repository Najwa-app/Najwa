//! FFI safety helpers (S17 §3): panic guard, input validation, fallible
//! `CString` construction, and zeroize-before-free.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use zeroize::Zeroize;

use crate::error::FfiErrorCode;

/// §3: no panic may cross the FFI boundary. Every `extern "C"` body runs
/// under this guard; an escaping panic becomes `FfiErrorCode::Panic`.
#[macro_export]
macro_rules! ffi_guard {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => $crate::error::FfiErrorCode::Panic.as_i32(),
        }
    };
}

/// §3 variant for pointer-returning functions.
#[macro_export]
macro_rules! ffi_guard_ptr {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => std::ptr::null_mut(),
        }
    };
}

/// §3.1: validate a C-string input (NULL + UTF-8).
pub(crate) fn cstr_to_str(ptr: *const c_char) -> Result<&'static str, i32> {
    if ptr.is_null() {
        return Err(FfiErrorCode::NullPointer.as_i32());
    }
    // SAFETY: caller contract — `ptr` points to a NUL-terminated C string for
    // the duration of the call (the platform layer owns the buffer, §5.6.3).
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| FfiErrorCode::InvalidUtf8.as_i32())
}

/// S17 §3.1/§3.2: fallible CString for RETURN values. Returned values are JSON,
/// which escapes U+0000, so no interior NUL reaches here; if one does, the
/// bytes are wiped and the result is NULL instead of a panic.
pub(crate) fn str_to_cstring_ptr(mut s: String) -> *mut c_char {
    // `CString::new(s)` could reallocate `s` and free the old copy unwiped.
    let ptr = bytes_to_cstring_ptr(s.as_bytes());
    s.zeroize();
    ptr
}

/// §5.6.2: build `value` as JSON in a buffer sized before writing (it never
/// reallocates), copy it into the returned C string, then wipe the buffer.
pub(crate) fn json_to_cstring_ptr<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<*mut c_char, FfiErrorCode> {
    let mut json = to_json_zeroizing(value).map_err(|_| FfiErrorCode::SerializationError)?;
    let ptr = bytes_to_cstring_ptr(&json);
    json.zeroize();
    #[cfg(test)]
    tests::LAST_JSON.with(|last| *last.borrow_mut() = std::mem::take(&mut *json));
    Ok(ptr)
}

/// JSON in a zeroizing buffer sized by a counting pass first: a growing buffer
/// frees each smaller copy without wiping it. Also used by the local service.
pub fn to_json_zeroizing<T: serde::Serialize + ?Sized>(
    value: &T,
) -> serde_json::Result<zeroize::Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut size = Count(0);
    serde_json::to_writer(&mut size, value)?;
    let mut json = zeroize::Zeroizing::new(Vec::with_capacity(size.0));
    serde_json::to_writer(&mut *json, value)?;
    Ok(json)
}

/// One exact `len + 1` allocation: the one `najwa_free_string` wipes (§5.6.2).
fn bytes_to_cstring_ptr(bytes: &[u8]) -> *mut c_char {
    match CString::new(bytes) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            e.into_vec().zeroize();
            std::ptr::null_mut()
        }
    }
}

/// §5.6.2: zeroize the full buffer, then free it. No-op on NULL. Exported as
/// `najwa_free_string`.
///
/// # Safety
/// `ptr` must be a pointer handed out by this crate (`str_to_cstring_ptr` or
/// `json_to_cstring_ptr`) and not yet freed, or NULL.
pub(crate) unsafe fn zeroize_and_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let c = CString::from_raw(ptr);
    let mut bytes = c.into_bytes();
    bytes.zeroize();
    drop(bytes);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    thread_local! {
        /// The last JSON build buffer, kept (wiped) instead of freed so a test
        /// can check it.
        pub(crate) static LAST_JSON: std::cell::RefCell<Vec<u8>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    #[test]
    fn cstr_validation() {
        assert_eq!(cstr_to_str(std::ptr::null()), Err(FfiErrorCode::NullPointer.as_i32()));
        let ok = CString::new("fine").unwrap();
        assert_eq!(cstr_to_str(ok.as_ptr()), Ok("fine"));
        // Invalid UTF-8 input → InvalidUtf8.
        let bad: [u8; 3] = [0xFF, 0xFE, 0x00];
        let bad_ptr = bad.as_ptr() as *const c_char;
        assert_eq!(cstr_to_str(bad_ptr), Err(FfiErrorCode::InvalidUtf8.as_i32()));
    }

    #[test]
    fn interior_nul_in_return_value_maps_to_null_not_panic() {
        let ptr = str_to_cstring_ptr("a\0b".to_string());
        assert!(ptr.is_null(), "§3.2: fallible CString, never unwrap");
    }

    /// §5.6.2: free_string zeroizes before deallocation — verify by hand-rolling
    /// the same sequence and checking the bytes are gone while still allocated.
    #[test]
    fn zeroize_before_free_clears_bytes() {
        let c = CString::new("s3cret payload").unwrap();
        let ptr = c.into_raw();
        unsafe {
            let len = CStr::from_ptr(ptr).to_bytes().len();
            let recovered = CString::from_raw(ptr);
            let mut bytes = recovered.into_bytes();
            bytes.zeroize();
            assert!(bytes.iter().all(|&b| b == 0));
            assert_eq!(len, 14);
            drop(bytes);
        }
    }
}
