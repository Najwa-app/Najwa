//! Windows DKM via Windows Credential Manager (CredWrite/CredRead/CredDelete).
//!
//! With `windows-tpm`, only a versioned TPM-wrapped device factor is stored here.
//! Builds without the feature retain the legacy 32-byte Credential Manager format.

use crate::error::{IdentityError, Result};

/// Credential target name used in Windows Credential Manager.
const CRED_TARGET: &str = "Najwa/DKM/v1";

pub(super) fn delete_record_dkms() -> Result<()> {
    #[cfg(feature = "windows-tpm")]
    super::windows_tpm::delete_orphans()?;
    use windows_sys::Win32::Security::Credentials::*;
    use zeroize::Zeroize;
    let filter: Vec<u16> = "Najwa/DKM/record/*".encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: filter is terminated; count/credentials are valid output pointers.
    if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) {
            return Ok(());
        }
        return Err(IdentityError::DkmError(format!(
            "CredEnumerateW failed: {error}"
        )));
    }
    let mut names = Vec::new();
    // SAFETY: successful enumeration supplies count valid credentials. Copy
    // names and wipe blobs while the allocation is alive, then free it once.
    unsafe {
        for pointer in std::slice::from_raw_parts(credentials, count as usize) {
            let credential = &**pointer;
            let mut length = 0;
            while *credential.TargetName.add(length) != 0 {
                length += 1;
            }
            names.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                credential.TargetName,
                length,
            )));
            if credential.CredentialBlobSize > 0 {
                std::slice::from_raw_parts_mut(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                )
                .zeroize();
            }
        }
        CredFree(credentials.cast());
    }
    for name in names {
        delete_named_dkm(&name)?;
    }
    Ok(())
}

pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    store_named_dkm(CRED_TARGET, dkm)
}

pub(super) fn store_named_dkm(name: &str, dkm: &[u8; 32]) -> Result<()> {
    #[cfg(feature = "windows-tpm")]
    {
        let pending = super::windows_tpm::wrap(name, dkm)?;
        write_credential(name, &pending.blob)?;
        pending.commit();
        Ok(())
    }
    #[cfg(not(feature = "windows-tpm"))]
    write_credential(name, dkm)
}

pub(super) fn write_credential(name: &str, blob: &[u8]) -> Result<()> {
    use std::ptr;
    use windows_sys::Win32::Security::Credentials::*;

    let target: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let username: Vec<u16> = "najwa-dkm"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_ptr() as *mut _,
        Comment: ptr::null_mut(),
        LastWritten: windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_ptr() as *mut _,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: ptr::null_mut(),
        TargetAlias: ptr::null_mut(),
        UserName: username.as_ptr() as *mut _,
    };

    // SAFETY: cred is a valid stack-allocated CREDENTIALW struct whose pointer fields
    // (TargetName, CredentialBlob, UserName) all point to live local variables above.
    let ret = unsafe { CredWriteW(&cred, 0) };
    if ret == 0 {
        Err(IdentityError::DkmError(format!(
            "CredWriteW failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    retrieve_named_dkm(CRED_TARGET)
}

pub(super) fn retrieve_named_dkm(name: &str) -> Result<[u8; 32]> {
    use windows_sys::Win32::Security::Credentials::*;

    let target: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pcred: *mut CREDENTIALW = std::ptr::null_mut();

    // SAFETY: target is a valid null-terminated UTF-16 string; pcred is an out-pointer
    // that CredReadW populates. We check the return value before dereferencing pcred.
    let ret = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) };
    if ret == 0 {
        return Err(IdentityError::DkmError(format!(
            "CredReadW failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: CredReadW succeeded (ret != 0), so pcred is a valid, non-null pointer
    // to a CREDENTIALW struct allocated by the Credential Manager.
    let cred = unsafe { &*pcred };
    // Finish reading the credential, including constructing errors, before freeing it.
    #[cfg(not(feature = "windows-tpm"))]
    let result = decode_blob(cred.CredentialBlobSize, || {
        let mut dkm = [0u8; 32];
        // SAFETY: decode_blob invokes this closure only for a 32-byte blob.
        unsafe { std::ptr::copy_nonoverlapping(cred.CredentialBlob, dkm.as_mut_ptr(), 32) };
        dkm
    });
    #[cfg(feature = "windows-tpm")]
    let result = copy_tpm_blob(cred.CredentialBlobSize, || {
        let mut blob = [0u8; super::windows_tpm::BLOB_LEN];
        // SAFETY: copy_tpm_blob invokes this only for the exact envelope size.
        unsafe {
            std::ptr::copy_nonoverlapping(cred.CredentialBlob, blob.as_mut_ptr(), blob.len())
        };
        blob
    });
    // SAFETY: CredReadW owns this allocation; erase its blob before releasing it.
    unsafe {
        if cred.CredentialBlobSize > 0 {
            use zeroize::Zeroize;
            std::slice::from_raw_parts_mut(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                .zeroize();
        }
        CredFree(pcred as *mut _);
    }
    #[cfg(feature = "windows-tpm")]
    return result.and_then(|blob| super::windows_tpm::unwrap(name, &blob));
    #[cfg(not(feature = "windows-tpm"))]
    result
}

#[cfg(any(not(feature = "windows-tpm"), test))]
fn decode_blob(size: u32, copy: impl FnOnce() -> [u8; 32]) -> Result<[u8; 32]> {
    if size != 32 {
        return Err(IdentityError::DkmError(format!(
            "DKM blob size mismatch: expected 32, got {size}"
        )));
    }
    Ok(copy())
}

#[cfg(feature = "windows-tpm")]
fn copy_tpm_blob(
    size: u32,
    copy: impl FnOnce() -> [u8; super::windows_tpm::BLOB_LEN],
) -> Result<[u8; super::windows_tpm::BLOB_LEN]> {
    if size as usize != super::windows_tpm::BLOB_LEN {
        return Err(IdentityError::DkmError(
            "TPM-wrapped device factor required; invalid credential length".into(),
        ));
    }
    Ok(copy())
}

pub fn delete_dkm() -> Result<()> {
    delete_named_dkm(CRED_TARGET)
}

pub(super) fn delete_named_dkm(name: &str) -> Result<()> {
    // Revoke the private key before removing its ciphertext. A hardware failure
    // must not be reported as successful key deletion.
    #[cfg(feature = "windows-tpm")]
    super::windows_tpm::delete(name)?;
    use windows_sys::Win32::Security::Credentials::*;

    let target: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: target is a valid null-terminated UTF-16 string pointing to a live local.
    let ret = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ret == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) {
            return Ok(());
        }
        Err(IdentityError::DkmError(format!(
            "CredDeleteW failed: {}",
            error
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_blob_is_rejected_without_reading_credential_memory() {
        for size in [0, 1, 31, 33, u32::MAX] {
            let error = decode_blob(size, || panic!("must not read a malformed blob")).unwrap_err();
            assert!(error.to_string().contains(&format!("got {size}")));
        }
        assert_eq!(decode_blob(32, || [7; 32]).unwrap(), [7; 32]);
    }

    #[cfg(feature = "windows-tpm")]
    #[test]
    fn tpm_backend_rejects_legacy_or_malformed_credential_before_copying() {
        for size in [0, 32, 263, 265, u32::MAX] {
            assert!(copy_tpm_blob(size, || panic!("must not copy malformed credential")).is_err());
        }
        assert!(super::super::headless_dkm_file().is_none());
    }

    #[cfg(feature = "windows-tpm")]
    #[test]
    #[ignore = "uses Credential Manager and uniquely named keys on a real Windows TPM"]
    fn hardware_credential_roundtrip_and_legacy_rejection() {
        let name = format!("Najwa/TPM-credential-test/{:032x}", rand::random::<u128>());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete_named_dkm(&self.0);
            }
        }
        let _cleanup = Cleanup(name.clone());
        let dkm = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
        write_credential(&name, &*dkm).unwrap();
        assert!(
            retrieve_named_dkm(&name).is_err(),
            "must reject a raw legacy device factor"
        );
        store_named_dkm(&name, &dkm).unwrap();
        assert_eq!(retrieve_named_dkm(&name).unwrap(), *dkm);
        assert!(store_named_dkm(&name, &[5; 32]).is_err());
        assert_eq!(retrieve_named_dkm(&name).unwrap(), *dkm);
        delete_named_dkm(&name).unwrap();
        assert!(retrieve_named_dkm(&name).is_err());
        delete_named_dkm(&name).unwrap();
    }
}
