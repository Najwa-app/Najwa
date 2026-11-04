//! Explicitly approved OS-keystore device factors. Never a file-key fallback.
//!
//! A separate, versioned credential records approval for one identity generation.
//! Hardware records are never reinterpreted as software keys after a TPM failure.
use crate::{
    error::{IdentityError, Result},
    record::IdentityRecordStandard,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NJWAPR01";
const LENGTH: usize = 72;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE: &str = "com.najwa.identity";

thread_local! {
    static APPROVED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Scope explicit user approval to this synchronous identity operation. It cannot
/// leak into another worker thread or survive unwinding. Reading a previously
/// approved credential needs no new approval on every launch.
pub fn with_software_fallback_approval<T>(approved: bool, action: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            APPROVED.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(APPROVED.with(|value| value.replace(approved)));
    action()
}

pub(super) fn approval_active() -> bool {
    APPROVED.with(|value| value.get())
}

fn error(message: impl std::fmt::Display) -> IdentityError {
    IdentityError::DkmError(format!("approved system key storage: {message}"))
}

fn name(record: &IdentityRecordStandard) -> String {
    format!(
        "Najwa/DKM/record/approved-software/{}",
        super::scoped::record_key_id(record)
    )
}

fn binding(record: &IdentityRecordStandard) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"Najwa/approved-software/v1\0");
    digest.update(record.salt_p);
    digest.update(record.ik_pub);
    digest.finalize().into()
}

fn decode(record: &IdentityRecordStandard, blob: &[u8]) -> Result<[u8; 32]> {
    if blob.len() != LENGTH || &blob[..8] != MAGIC || blob[8..40] != binding(record) {
        return Err(error("invalid approval or identity binding"));
    }
    Ok(blob[40..].try_into().unwrap())
}

pub(super) fn store(record: &IdentityRecordStandard, dkm: &[u8; 32]) -> Result<()> {
    if !approval_active() {
        return Err(error("explicit user approval is required"));
    }
    let name = name(record);
    if backend::get(&name)?.is_some() {
        return Err(error("generation already exists"));
    }
    let mut blob = Zeroizing::new([0; LENGTH]);
    blob[..8].copy_from_slice(MAGIC);
    blob[8..40].copy_from_slice(&binding(record));
    blob[40..].copy_from_slice(dkm);
    backend::set(&name, &blob[..])
}

pub(super) fn retrieve(record: &IdentityRecordStandard) -> Result<Option<[u8; 32]>> {
    backend::get(&name(record))?
        .map(|blob| decode(record, &blob))
        .transpose()
}

pub fn record_uses_software_storage(record: &IdentityRecordStandard) -> Result<bool> {
    #[cfg(test)]
    if super::MOCK_DKM_STORAGE.with(|m| m.borrow().is_some()) {
        return Ok(false);
    }
    retrieve(record).map(|value| value.map(Zeroizing::new).is_some())
}

pub(super) fn delete(record: &IdentityRecordStandard) -> Result<()> {
    backend::remove(&name(record))
}

#[cfg(target_os = "windows")]
mod backend {
    use super::*;
    use windows_sys::Win32::{Foundation::ERROR_NOT_FOUND, Security::Credentials::*};
    pub(super) fn get(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut pointer: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: the terminated target and output pointer live across the call.
        if unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer) } == 0 {
            let e = std::io::Error::last_os_error();
            return if e.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                Ok(None)
            } else {
                Err(error(e))
            };
        }
        // SAFETY: successful CredReadW returns an owned allocation. Bound the copy,
        // wipe its secret before releasing it, and never expose an unchecked blob.
        unsafe {
            let credential = &*pointer;
            let result = if credential.CredentialBlobSize as usize == LENGTH {
                Ok(Some(Zeroizing::new(
                    std::slice::from_raw_parts(credential.CredentialBlob, LENGTH).to_vec(),
                )))
            } else {
                Err(error("invalid credential length"))
            };
            if credential.CredentialBlobSize > 0 {
                use zeroize::Zeroize;
                std::slice::from_raw_parts_mut(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
                .zeroize();
            }
            CredFree(pointer.cast());
            result
        }
    }
    pub(super) fn set(name: &str, blob: &[u8]) -> Result<()> {
        super::super::windows::write_credential(name, blob)
    }
    pub(super) fn remove(name: &str) -> Result<()> {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the target is a live terminated UTF-16 string.
        if unsafe { CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            Ok(())
        } else {
            Err(error(e))
        }
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    fn entry(name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, name).map_err(error)
    }
    pub(super) fn get(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match entry(name)?.get_secret() {
            Ok(data) => Ok(Some(Zeroizing::new(data))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(error(e)),
        }
    }
    pub(super) fn set(name: &str, blob: &[u8]) -> Result<()> {
        entry(name)?.set_secret(blob).map_err(error)
    }
    pub(super) fn remove(name: &str) -> Result<()> {
        match entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(error(e)),
        }
    }
}

#[cfg(target_os = "macos")]
mod backend {
    use super::*;
    use security_framework::passwords::*;
    pub(super) fn get(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match get_generic_password(SERVICE, name) {
            Ok(blob) => Ok(Some(Zeroizing::new(blob))),
            Err(e) if e.code() == -25300 => Ok(None),
            Err(e) => Err(error(e)),
        }
    }
    pub(super) fn set(name: &str, blob: &[u8]) -> Result<()> {
        set_generic_password(SERVICE, name, blob).map_err(error)
    }
    pub(super) fn remove(name: &str) -> Result<()> {
        match delete_generic_password(SERVICE, name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()),
            Err(e) => Err(error(e)),
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod backend {
    use super::*;
    pub(super) fn get(_: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(error("unsupported OS keystore"))
    }
    pub(super) fn set(_: &str, _: &[u8]) -> Result<()> {
        Err(error("unsupported OS keystore"))
    }
    pub(super) fn remove(_: &str) -> Result<()> {
        Err(error("unsupported OS keystore"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_envelope_is_bound_to_one_identity_generation() {
        let (record, _) = crate::creation::create_identity_from_seed(
            &[23; 32],
            "synthetic approval fixture",
            Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
        )
        .unwrap();
        assert!(store(&record, &[7; 32]).is_err());
        let mut blob = [0; LENGTH];
        blob[..8].copy_from_slice(MAGIC);
        blob[8..40].copy_from_slice(&binding(&record));
        blob[40..].fill(7);
        assert_eq!(decode(&record, &blob).unwrap(), [7; 32]);
        let mut other = record.clone();
        other.salt_p[0] ^= 1;
        assert!(decode(&other, &blob).is_err());
        other = record.clone();
        other.ik_pub[0] ^= 1;
        assert!(decode(&other, &blob).is_err());
        assert!(decode(&record, &[0; 32]).is_err());
    }
    #[test]
    #[ignore = "uses an isolated synthetic credential in the real OS keyring"]
    fn approved_software_real_os_roundtrip_binding_and_deletion() {
        let (record, _) = crate::creation::create_identity_from_seed(
            &[25; 32],
            "synthetic system storage",
            Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
        )
        .unwrap();
        struct Cleanup(IdentityRecordStandard);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete(&self.0);
            }
        }
        let _cleanup = Cleanup(record.clone());
        assert!(retrieve(&record).unwrap().is_none());
        assert!(store(&record, &[19; 32]).is_err());
        with_software_fallback_approval(true, || store(&record, &[19; 32])).unwrap();
        assert!(!approval_active());
        assert_eq!(retrieve(&record).unwrap().unwrap(), [19; 32]);
        assert!(with_software_fallback_approval(true, || store(&record, &[9; 32])).is_err());
        delete(&record).unwrap();
        assert!(retrieve(&record).unwrap().is_none());
    }
    #[test]
    fn approval_is_scoped_and_cannot_leak_to_another_thread_or_after_a_panic() {
        assert!(!approval_active());
        let result = std::panic::catch_unwind(|| {
            with_software_fallback_approval(true, || {
                assert!(approval_active());
                assert!(!std::thread::spawn(approval_active).join().unwrap());
                with_software_fallback_approval(false, || assert!(!approval_active()));
                assert!(approval_active());
                panic!("synthetic unwind");
            })
        });
        assert!(result.is_err());
        assert!(!approval_active());
    }
}
