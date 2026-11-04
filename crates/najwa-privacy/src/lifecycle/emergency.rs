//! Local profile erasure (S13 §10). The caller must drain operations and close key owners
//! before `erase`; network cleanup may start only after `erase` succeeds.
use super::deletion::{overwrite_and_delete, secure_delete_directory, DeletionError};
use najwa_identity::{atomic::atomic_write, platform, record::IdentityRecordStandard};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const PENDING_FILE: &str = "wipe.pending";

fn checked_directory(directory: &Path) -> Result<PathBuf, DeletionError> {
    let directory = directory.canonicalize()?;
    if directory.parent().is_none() {
        return Err(std::io::Error::other("refusing a filesystem root").into());
    }
    Ok(directory)
}

fn read_record(path: &Path) -> Result<Vec<u8>, DeletionError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(193).read_to_end(&mut bytes)?;
    if bytes.len() > 192 {
        return Err(std::io::Error::other("oversized wipe record").into());
    }
    if !bytes.is_empty() {
        IdentityRecordStandard::from_bytes(&bytes)
            .map_err(|_| std::io::Error::other("invalid wipe record"))?;
    }
    Ok(bytes)
}

/// Persist the encrypted record needed to retry this profile's factor deletion.
/// This marker prohibits unlock/recreation until the entire local erase succeeds.
pub fn begin(directory: &Path) -> Result<(), DeletionError> {
    let directory = checked_directory(directory)?;
    let pending = directory.join(PENDING_FILE);
    if pending.try_exists()? {
        read_record(&pending)?;
        return Ok(());
    }
    let record = directory.join("identity.najwa");
    let bytes = if record.try_exists()? {
        read_record(&record)?
    } else {
        Vec::new()
    };
    atomic_write(&pending, &bytes)
        .map_err(|_| std::io::Error::other("cannot persist wipe intent"))?;
    Ok(())
}

fn erase_entry(path: &Path) -> Result<(), DeletionError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return overwrite_and_delete(path);
    }
    let mut failed = false;
    for entry in fs::read_dir(path)? {
        match entry {
            Ok(entry) => failed |= erase_entry(&entry.path()).is_err(),
            Err(_) => failed = true,
        }
    }
    if failed {
        return Err(std::io::Error::other("local wipe incomplete").into());
    }
    // The existing helper durably removes the now-empty directory.
    secure_delete_directory(path).map(|_| ())
}

/// Erase only the exclusively owned profile. Attempt every file even if factor
/// deletion or an earlier file fails. Preserve the marker on any failure.
/// `owner.lock` stays open to prevent another process reusing the profile midway.
pub fn erase(directory: &Path) -> Result<(), DeletionError> {
    let directory = checked_directory(directory)?;
    let pending = directory.join(PENDING_FILE);
    let bytes = read_record(&pending)?;
    let mut failed = false;
    if !bytes.is_empty() {
        let record = IdentityRecordStandard::from_bytes(&bytes)
            .map_err(|_| std::io::Error::other("invalid wipe record"))?;
        failed |= platform::delete_record_dkm(&record).is_err();
    }
    for entry in fs::read_dir(&directory)? {
        let Ok(entry) = entry else {
            failed = true;
            continue;
        };
        if entry.file_name() == "owner.lock" || entry.file_name() == PENDING_FILE {
            continue;
        }
        failed |= erase_entry(&entry.path()).is_err();
    }
    if failed {
        return Err(std::io::Error::other("local wipe incomplete").into());
    }
    // Keep retry metadata byte-identical if unlink fails. Its ciphertext is
    // already undecryptable because this record's factor has been deleted.
    fs::remove_file(&pending)?;
    #[cfg(unix)]
    fs::File::open(&directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_profile_erasure_preserves_lock_and_unrelated_backup() {
        let parent = tempfile::tempdir().unwrap();
        let profile = parent.path().join("profile");
        fs::create_dir(&profile).unwrap();
        fs::write(parent.path().join("exported-backup"), b"outside profile").unwrap();
        fs::write(profile.join("owner.lock"), []).unwrap();
        fs::write(profile.join("najwa.db"), b"encrypted database fixture").unwrap();
        fs::create_dir(profile.join("cache")).unwrap();
        fs::write(profile.join("cache/partial"), b"fixture").unwrap();
        begin(&profile).unwrap();
        erase(&profile).unwrap();
        assert_eq!(fs::read_dir(&profile).unwrap().count(), 1);
        assert!(profile.join("owner.lock").exists());
        assert_eq!(
            fs::read(parent.path().join("exported-backup")).unwrap(),
            b"outside profile"
        );
    }
    #[cfg(windows)]
    #[test]
    fn failed_file_is_retryable_and_does_not_skip_other_files() {
        use std::os::windows::fs::OpenOptionsExt;
        let profile = tempfile::tempdir().unwrap();
        fs::create_dir(profile.path().join("nested")).unwrap();
        fs::write(profile.path().join("nested/blocked"), b"fixture").unwrap();
        fs::write(profile.path().join("nested/other"), b"fixture").unwrap();
        fs::write(profile.path().join("other"), b"fixture").unwrap();
        begin(profile.path()).unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(profile.path().join("nested/blocked"))
            .unwrap();
        assert!(erase(profile.path()).is_err());
        assert!(profile.path().join(PENDING_FILE).exists());
        assert!(!profile.path().join("other").exists());
        assert!(!profile.path().join("nested/other").exists());
        drop(held);
        begin(profile.path()).unwrap();
        erase(profile.path()).unwrap();
        assert_eq!(fs::read_dir(profile.path()).unwrap().count(), 0);
    }
}
