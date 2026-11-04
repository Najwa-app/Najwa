//! Atomic file write operations for identity records.
//!
//! Ensures crash-safe writes via write-to-temp + rename pattern.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::error::{IdentityError, Result};

/// Atomically and durably write `data` to `path` (S02 §12.2).
///
/// 1. Write to a **randomized** temporary file (S02 §12.2 — a predictable
///    `.tmp` name in a shared/attacker-writable dir invites a symlink/pre-create
///    race or a collision with a concurrent writer).
/// 2. `fsync` the temporary file.
/// 3. Replace `path` durably (see [`durable_replace`]).
///
/// `Ok` means the new contents survive a power cut, so a caller may then destroy
/// what the old contents needed (S02 §12.3 step 5). An error from step 3 can come
/// after the new file is already in place. A stray temp is removed on any failure.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    // S02 §12.2: randomized, unpredictable temp name.
    let rnd: [u8; 8] = najwa_crypto::random::random_bytes();
    let temp_path = path.with_extension(format!("tmp.{:016x}", u64::from_le_bytes(rnd)));

    // Write + fsync + durable replace; clean up the stray temp on any failure.
    let result = (|| -> Result<()> {
        let mut file = File::create(&temp_path)
            .map_err(|e| IdentityError::AtomicWriteFailed(format!("create temp: {e}")))?;
        file.write_all(data)
            .map_err(|e| IdentityError::AtomicWriteFailed(format!("write: {e}")))?;
        file.sync_all()
            .map_err(|e| IdentityError::AtomicWriteFailed(format!("sync: {e}")))?;
        drop(file);
        durable_replace(&temp_path, path)?;
        #[cfg(test)]
        if FAIL_DURABLE_REPLACE.with(|target| target.borrow().as_deref() == Some(path)) {
            return Err(IdentityError::AtomicWriteFailed(
                "sync: injected failure after replace".into(),
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Replace `target` with `temp`, returning only once the replacement is on disk.
///
/// ponytail: no `\\?\` long-path prefix; profile paths stay under `MAX_PATH`.
#[cfg(windows)]
fn durable_replace(temp: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide =
        |path: &Path| -> Vec<u16> { path.as_os_str().encode_wide().chain(Some(0)).collect() };
    let (from, to) = (wide(temp), wide(target));
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that outlive the call.
    let moved = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(IdentityError::AtomicWriteFailed(format!(
            "rename: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Replace `target` with `temp`, returning only once the replacement is on disk.
#[cfg(not(windows))]
fn durable_replace(temp: &Path, target: &Path) -> Result<()> {
    fs::rename(temp, target)
        .map_err(|e| IdentityError::AtomicWriteFailed(format!("rename: {e}")))?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match File::open(parent).and_then(|dir| dir.sync_all()) {
        // EINVAL: this file system cannot sync a directory; nothing more can be done.
        Err(e) if e.kind() != std::io::ErrorKind::InvalidInput => {
            Err(IdentityError::AtomicWriteFailed(format!("sync dir: {e}")))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: report a failed durable replace of this path after the new
    /// file is already in place, the case where the caller cannot tell which
    /// version a power cut would leave.
    static FAIL_DURABLE_REPLACE: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Make every later durable replace of `path` on this test thread fail (`None` stops it).
#[cfg(test)]
pub(crate) fn fail_durable_replace_for_test(path: Option<std::path::PathBuf>) {
    FAIL_DURABLE_REPLACE.with(|target| *target.borrow_mut() = path);
}

/// Read a file's contents, returning `None` if it doesn't exist.
pub fn read_record_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.dat");
        let data = b"hello atomic world";

        atomic_write(&path, data).unwrap();
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn atomic_write_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.dat");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, b"second");
    }

    #[test]
    fn atomic_write_randomized_temp_leaves_no_stray_files() {
        // S02 §12.2: after two successful writes the dir holds ONLY the target —
        // no fixed `.tmp` and no leftover randomized temp.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.dat");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "only the target remains, got {names:?}");
    }

    #[test]
    fn read_record_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.dat");
        assert!(read_record_file(&path).unwrap().is_none());
    }

    #[test]
    fn read_record_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.dat");
        fs::write(&path, b"data").unwrap();
        let data = read_record_file(&path).unwrap().unwrap();
        assert_eq!(data, b"data");
    }
}
