//! DKM generations are addressed by the record's random password salt.
//! Preparing a replacement never overwrites the credential of a live record.
//! The legacy singleton remains readable unless the hardware feature requires
//! a record-scoped hardware key.

use super::*;
use crate::error::IdentityError;
use crate::record::IdentityRecordStandard;
use zeroize::Zeroizing;

pub(crate) fn record_key_id(record: &IdentityRecordStandard) -> String {
    record.salt_p.iter().map(|b| format!("{b:02x}")).collect()
}

fn name(record: &IdentityRecordStandard) -> String {
    format!("Najwa/DKM/record/{}", record_key_id(record))
}

fn file_path(record: &IdentityRecordStandard) -> Option<std::path::PathBuf> {
    headless_dkm_file().map(|mut path| {
        path.push(format!(".key.{}", record_key_id(record)));
        path.into()
    })
}

#[cfg(test)]
thread_local! {
    static KEYS: std::cell::RefCell<std::collections::BTreeMap<[u8; 32], Zeroizing<[u8; 32]>>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

#[cfg(test)]
pub(super) fn clear_mock_keys() {
    KEYS.with(|keys| keys.borrow_mut().clear());
}

/// Account deletion must also erase credentials left by an interrupted commit
/// or by preparation of a record that was never published.
pub(super) fn delete_all_record_dkms() -> Result<()> {
    #[cfg(test)]
    if MOCK_DKM_STORAGE.with(|m| m.borrow().is_some()) {
        clear_mock_keys();
        return Ok(());
    }
    if let Some(base) = headless_dkm_file() {
        let base = std::path::PathBuf::from(base);
        let parent = base
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let prefix = format!(
            "{}.key.",
            base.file_name()
                .ok_or_else(|| IdentityError::DkmError("invalid DKM path".into()))?
                .to_string_lossy()
        );
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(id) = name.to_string_lossy().strip_prefix(&prefix) {
                if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }
        return Ok(());
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    return imp::delete_record_dkms();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Ok(())
}

pub(crate) fn store_record_dkm(record: &IdentityRecordStandard, dkm: &[u8; 32]) -> Result<()> {
    #[cfg(test)]
    if MOCK_DKM_STORAGE.with(|m| m.borrow().is_some()) {
        KEYS.with(|keys| {
            keys.borrow_mut()
                .insert(record.salt_p, Zeroizing::new(*dkm))
        });
        return Ok(());
    }
    if let Some(path) = file_path(record) {
        // This explicit headless-test backend stores only synthetic secrets.
        let bytes = Zeroizing::new(dkm.to_vec());
        return crate::atomic::atomic_write(&path, &bytes);
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        let result = imp::store_named_dkm(&name(record), dkm);
        #[cfg(feature = "approved-software-fallback")]
        if result.is_err() && approved_software::approval_active() {
            return approved_software::store(record, dkm);
        }
        result
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Err(IdentityError::DkmError(
        "record-scoped DKM requires a supported desktop platform".into(),
    ))
}

fn retrieve_scoped(record: &IdentityRecordStandard) -> Result<[u8; 32]> {
    #[cfg(test)]
    if MOCK_DKM_STORAGE.with(|m| m.borrow().is_some()) {
        return KEYS
            .with(|keys| keys.borrow().get(&record.salt_p).map(|key| **key))
            .ok_or_else(|| IdentityError::DkmError("no record DKM stored".into()));
    }
    if let Some(path) = file_path(record) {
        let bytes = Zeroizing::new(std::fs::read(path)?);
        return bytes.as_slice().try_into().map_err(|_| {
            IdentityError::DkmError("record DKM must contain exactly 32 bytes".into())
        });
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    return imp::retrieve_named_dkm(&name(record));
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Err(IdentityError::DkmError(
        "record-scoped DKM requires a supported desktop platform".into(),
    ))
}

pub(crate) fn has_record_dkm(record: &IdentityRecordStandard) -> bool {
    #[cfg(feature = "approved-software-fallback")]
    if approved_software::record_uses_software_storage(record).unwrap_or(false) {
        return true;
    }
    retrieve_scoped(record).map(Zeroizing::new).is_ok()
}

/// Retrieve this record's DKM. Strict hardware builds reject legacy singleton
/// fallback; other builds retain compatibility with older records.
pub fn retrieve_record_dkm(record: &IdentityRecordStandard) -> Result<[u8; 32]> {
    #[cfg(feature = "approved-software-fallback")]
    {
        #[cfg(test)]
        let mocked = MOCK_DKM_STORAGE.with(|m| m.borrow().is_some());
        #[cfg(not(test))]
        let mocked = false;
        if !mocked {
            if let Some(dkm) = approved_software::retrieve(record)? {
                return Ok(dkm);
            }
        }
    }
    if hardware_keystore_required() {
        retrieve_scoped(record)
    } else {
        retrieve_scoped(record).or_else(|_| retrieve_dkm())
    }
}

/// Remove this record's credential. Other record generations remain usable.
/// A missing scoped key is harmless; legacy credentials are deleted by `delete_dkm`.
pub fn delete_record_dkm(record: &IdentityRecordStandard) -> Result<()> {
    #[cfg(test)]
    if MOCK_DKM_STORAGE.with(|m| m.borrow().is_some()) {
        KEYS.with(|keys| keys.borrow_mut().remove(&record.salt_p));
        return Ok(());
    }
    #[cfg(feature = "approved-software-fallback")]
    if approved_software::record_uses_software_storage(record)? {
        return approved_software::delete(record);
    }
    if let Some(path) = file_path(record) {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        };
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    return imp::delete_named_dkm(&name(record));
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Err(IdentityError::DkmError(
        "record-scoped DKM requires a supported desktop platform".into(),
    ))
}

#[cfg(all(
    test,
    any(
        all(target_os = "windows", feature = "windows-tpm"),
        all(target_os = "linux", feature = "linux-tpm"),
        all(target_os = "macos", feature = "macos-secure-enclave")
    )
))]
mod tpm_tests {
    use super::*;

    #[test]
    fn missing_scoped_key_does_not_fall_back_to_legacy_singleton() {
        set_dkm_storage_for_test(MockDkmStorage::new());
        let (record, _) = crate::creation::create_identity_from_seed(
            &[19; 32],
            "synthetic passphrase",
            Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
        )
        .unwrap();
        let key = Zeroizing::new(retrieve_record_dkm(&record).unwrap());
        store_dkm(&key).unwrap();
        delete_record_dkm(&record).unwrap();
        assert!(retrieve_dkm().is_ok(), "the legacy fixture exists");
        assert!(
            retrieve_record_dkm(&record).is_err(),
            "strict mode must not fall back"
        );
    }
}
