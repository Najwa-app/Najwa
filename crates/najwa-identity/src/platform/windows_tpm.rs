//! Windows device-factor wrapping, separate from the S02 Hardware record format.
//!
//! Only the Platform Crypto Provider is permitted. The RSA private key is generated
//! there, never imported or exported. The existing passphrase + DKM construction
//! still protects the identity; this module does not implement Windows Hello.

use crate::error::{IdentityError, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::System::TpmBaseServices::*;
use windows_sys::Win32::{Foundation::*, Security::Cryptography::*};
use zeroize::Zeroizing;

const PREFIX: &str = "Najwa.DKM.v2.";
const MAGIC: &[u8; 8] = b"NJWTPM01";
const RSA_BITS: u32 = 2048;
const CIPHER_LEN: usize = RSA_BITS as usize / 8;
pub(super) const BLOB_LEN: usize = MAGIC.len() + CIPHER_LEN;

fn failure(operation: &str, status: i32) -> IdentityError {
    IdentityError::DkmError(format!(
        "Windows TPM {operation} failed (0x{:08x})",
        status as u32
    ))
}

fn check(operation: &str, status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(failure(operation, status))
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn key_name(credential: &str) -> String {
    let digest = Sha256::digest(credential.as_bytes());
    format!(
        "{PREFIX}{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this object owns the CNG handle and releases it exactly once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

fn property(handle: usize, name: windows_sys::core::PCWSTR) -> Result<u32> {
    let mut value = 0u32;
    let mut length = 0;
    // SAFETY: the caller holds a live handle; property identifiers are static UTF-16.
    check("read key policy", unsafe {
        NCryptGetProperty(
            handle,
            name,
            (&mut value as *mut u32).cast(),
            4,
            &mut length,
            0,
        )
    })?;
    if length != 4 {
        return Err(IdentityError::DkmError(
            "invalid Windows TPM policy length".into(),
        ));
    }
    Ok(value)
}

fn set_property(handle: usize, name: windows_sys::core::PCWSTR, value: u32) -> Result<()> {
    // SAFETY: all pointers remain valid for the synchronous CNG call.
    check("set key policy", unsafe {
        NCryptSetProperty(handle, name, (&value as *const u32).cast(), 4, 0)
    })
}

fn provider() -> Result<Handle> {
    require_tpm2()?;
    let mut handle = 0;
    // SAFETY: the output pointer is valid; provider identifier is static and terminated.
    check("open hardware provider", unsafe {
        NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0)
    })?;
    let provider = Handle(handle);
    let implementation = property(provider.0, NCRYPT_IMPL_TYPE_PROPERTY)?;
    if implementation & NCRYPT_IMPL_HARDWARE_FLAG == 0
        || implementation & NCRYPT_IMPL_SOFTWARE_FLAG != 0
    {
        return Err(IdentityError::DkmError(
            "Windows TPM hardware provider required".into(),
        ));
    }
    Ok(provider)
}

fn validate_device(info: &TPM_DEVICE_INFO) -> Result<()> {
    if info.structVersion != 1
        || info.tpmVersion != TPM_VERSION_20
        || !matches!(
            info.tpmInterfaceType,
            TPM_IFTYPE_HW | TPM_IFTYPE_SPB | TPM_IFTYPE_TRUSTZONE
        )
    {
        return Err(IdentityError::DkmError(
            "Windows TPM 2.0 hardware is required; software TPMs are not supported".into(),
        ));
    }
    Ok(())
}

fn require_tpm2() -> Result<()> {
    let mut info = TPM_DEVICE_INFO {
        structVersion: 0,
        tpmVersion: 0,
        tpmInterfaceType: 0,
        tpmImpRevision: 0,
    };
    // SAFETY: the output buffer has the SDK-defined size and lives across this read-only call.
    let status = unsafe {
        Tbsi_GetDeviceInfo(
            std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
            (&mut info as *mut TPM_DEVICE_INFO).cast(),
        )
    };
    check("read TPM 2.0 device information", status as i32)?;
    validate_device(&info)
}

fn verify_key(key: &Handle) -> Result<()> {
    if property(key.0, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0
        || property(key.0, NCRYPT_LENGTH_PROPERTY)? != RSA_BITS
    {
        return Err(IdentityError::DkmError(
            "Windows TPM key policy mismatch".into(),
        ));
    }
    // A PCP key may only be exported when generated as exportable or imported.
    // Refuse both. This property is a BOOLEAN, not a DWORD policy bitmask.
    let mut allowed = 0u32;
    let mut length = 0;
    // SAFETY: the key is live and the zero-initialized buffer accommodates both
    // BOOLEAN and DWORD encodings used by Windows provider versions.
    check("read export permission", unsafe {
        NCryptGetProperty(
            key.0,
            NCRYPT_PCP_EXPORT_ALLOWED_PROPERTY,
            (&mut allowed as *mut u32).cast(),
            4,
            &mut length,
            0,
        )
    })?;
    if !matches!(length, 1 | 4) || allowed != 0 {
        return Err(IdentityError::DkmError(
            "Windows TPM key must be non-exportable".into(),
        ));
    }
    Ok(())
}

fn open_key(provider: &Handle, credential: &str) -> Result<Handle> {
    let name = wide(&key_name(credential));
    let mut handle = 0;
    // SAFETY: provider and name live across the call, handle is a valid output.
    check("open device key", unsafe {
        NCryptOpenKey(
            provider.0,
            &mut handle,
            name.as_ptr(),
            0,
            NCRYPT_SILENT_FLAG,
        )
    })?;
    let key = Handle(handle);
    verify_key(&key)?;
    Ok(key)
}

/// A prepared key is rolled back unless its ciphertext is durably stored.
pub(super) struct PendingWrap {
    key: Handle,
    // Retain the provider until after the key is released.
    _provider: Handle,
    pub(super) blob: [u8; BLOB_LEN],
    committed: bool,
}

impl PendingWrap {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingWrap {
    fn drop(&mut self) {
        if !self.committed && self.key.0 != 0 {
            // SAFETY: the newly created key is owned here, never an existing key.
            if unsafe { NCryptDeleteKey(self.key.0, 0) } == 0 {
                self.key.0 = 0;
            }
            // If deletion fails, Handle still frees it. Account deletion enumerates
            // orphan keys after a crash or cleanup failure; no existing key is reused.
        }
    }
}

fn padding() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: core::ptr::null_mut(),
        cbLabel: 0,
    }
}

fn binding(credential: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Najwa/v2/TPM/DKM\0");
    hash.update(credential.as_bytes());
    hash.finalize().into()
}

pub(super) fn wrap(credential: &str, dkm: &[u8; 32]) -> Result<PendingWrap> {
    let provider = provider()?;
    let name = wide(&key_name(credential));
    let mut handle = 0;
    // SAFETY: pointers are live. No OVERWRITE or MACHINE flag: current-user key,
    // and an existing generation must never be replaced.
    check("create device key", unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut handle,
            NCRYPT_RSA_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    })?;
    let mut pending = PendingWrap {
        key: Handle(handle),
        _provider: provider,
        blob: [0; BLOB_LEN],
        committed: false,
    };
    set_property(handle, NCRYPT_LENGTH_PROPERTY, RSA_BITS)?;
    set_property(handle, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG)?;
    // Export is disabled by the PCP for generated keys. Verify after finalization
    // rather than assuming a provider's default or accepting an imported key.
    check("finalize device key", unsafe {
        NCryptFinalizeKey(handle, NCRYPT_SILENT_FLAG)
    })?;
    verify_key(&pending.key)?;
    // An empty OAEP label avoids TPM-specific string/length restrictions. Bind
    // the complete credential name inside the encrypted payload instead.
    let mut plaintext = Zeroizing::new([0u8; 64]);
    plaintext[..32].copy_from_slice(&binding(credential));
    plaintext[32..].copy_from_slice(dkm);
    let padding = padding();
    let mut written = 0;
    // SAFETY: fixed-size input/output and padding buffers are valid for this call.
    check("wrap device factor", unsafe {
        NCryptEncrypt(
            handle,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            (&padding as *const BCRYPT_OAEP_PADDING_INFO).cast(),
            pending.blob[MAGIC.len()..].as_mut_ptr(),
            CIPHER_LEN as u32,
            &mut written,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    })?;
    if written as usize != CIPHER_LEN {
        return Err(IdentityError::DkmError(
            "invalid Windows TPM ciphertext length".into(),
        ));
    }
    pending.blob[..MAGIC.len()].copy_from_slice(MAGIC);
    // Public-key encryption alone does not prove the TPM can decrypt this
    // scheme. Verify before publishing an identity that depends on the key.
    let recovered = Zeroizing::new(unwrap(credential, &pending.blob)?);
    if !najwa_crypto::hash::constant_time_eq(&*recovered, dkm) {
        return Err(IdentityError::DkmError(
            "Windows TPM wrapping verification failed".into(),
        ));
    }
    Ok(pending)
}

pub(super) fn unwrap(credential: &str, blob: &[u8]) -> Result<[u8; 32]> {
    if blob.len() != BLOB_LEN || &blob[..MAGIC.len()] != MAGIC {
        return Err(IdentityError::DkmError(
            "TPM-wrapped device factor required; legacy credentials cannot be used".into(),
        ));
    }
    let provider = provider()?;
    let key = open_key(&provider, credential)?;
    let padding = padding();
    // Use a modulus-size buffer: CNG providers may require it even though the
    // actual payload is 64 bytes. Always erase it, including on failed decryption.
    let mut plaintext = Zeroizing::new([0u8; CIPHER_LEN]);
    let mut written = 0;
    // SAFETY: validated ciphertext, live handle and bounded output/padding buffers.
    check("unwrap device factor", unsafe {
        NCryptDecrypt(
            key.0,
            blob[MAGIC.len()..].as_ptr(),
            CIPHER_LEN as u32,
            (&padding as *const BCRYPT_OAEP_PADDING_INFO).cast(),
            plaintext.as_mut_ptr(),
            plaintext.len() as u32,
            &mut written,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    })?;
    if written != 64 || plaintext[..32] != binding(credential) {
        return Err(IdentityError::DkmError(
            "invalid Windows TPM payload binding or length".into(),
        ));
    }
    Ok(plaintext[32..64].try_into().expect("fixed length"))
}

pub(super) fn delete(credential: &str) -> Result<()> {
    delete_key_name(&provider()?, &key_name(credential))
}

/// Statuses that prove the key no longer exists, so deletion counts as done
/// (S02 §17.6): the provider has no such key, or the key was made under a
/// storage parent this TPM no longer has (the TPM was cleared). Anything else,
/// including an absent, disabled or unprovisioned TPM, may leave a key that
/// works again later, so deletion keeps failing.
fn key_gone(status: i32) -> bool {
    matches!(
        status,
        NTE_BAD_KEYSET | NTE_NOT_FOUND | TPM_E_PCP_WRONG_PARENT | TPM_20_E_INTEGRITY
    )
}

fn delete_key_name(provider: &Handle, key_name: &str) -> Result<()> {
    let name = wide(key_name);
    let mut handle = 0;
    // SAFETY: provider/name are live and handle is a valid output pointer.
    let status = unsafe {
        NCryptOpenKey(
            provider.0,
            &mut handle,
            name.as_ptr(),
            0,
            NCRYPT_SILENT_FLAG,
        )
    };
    if key_gone(status) {
        return Ok(());
    }
    check("open key for deletion", status)?;
    let mut key = Handle(handle);
    // SAFETY: successful deletion frees the owned handle; clear it to avoid double free.
    match unsafe { NCryptDeleteKey(key.0, 0) } {
        0 => key.0 = 0,
        status if key_gone(status) => {}
        status => return Err(failure("delete device key", status)),
    }
    Ok(())
}

struct Buffer(*mut core::ffi::c_void);
impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this owns a buffer allocated by CNG enumeration.
            unsafe {
                NCryptFreeBuffer(self.0);
            }
        }
    }
}

/// Only called by the existing all-Najwa-account deletion operation. Removes
/// keys left between CNG finalization and Credential Manager commit as well.
pub(super) fn delete_orphans() -> Result<()> {
    let provider = provider()?;
    for name in key_names(&provider)? {
        delete_key_name(&provider, &name)?;
    }
    Ok(())
}

fn key_names(provider: &Handle) -> Result<Vec<String>> {
    let mut state = Buffer(core::ptr::null_mut());
    let mut names = Vec::new();
    loop {
        let mut key_name: *mut NCryptKeyName = core::ptr::null_mut();
        // SAFETY: output pointers are valid; CNG owns enumeration allocations.
        let status = unsafe {
            NCryptEnumKeys(
                provider.0,
                core::ptr::null(),
                &mut key_name,
                &mut state.0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status == NTE_NO_MORE_ITEMS {
            break;
        }
        check("enumerate device keys", status)?;
        let _allocation = Buffer(key_name.cast());
        // SAFETY: a successful enumeration provides a terminated UTF-16 name.
        let name = unsafe {
            let pointer = (*key_name).pszName;
            let mut length = 0;
            while *pointer.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(core::slice::from_raw_parts(pointer, length))
        };
        if name.strip_prefix(PREFIX).is_some_and(|suffix| {
            suffix.len() == 64 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        }) {
            names.push(name);
        }
    }
    // Finish enumeration before a caller mutates the provider's collection.
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tpm2_hardware_device_information_is_accepted() {
        let mut info = TPM_DEVICE_INFO {
            structVersion: 1,
            tpmVersion: TPM_VERSION_20,
            tpmInterfaceType: TPM_IFTYPE_HW,
            tpmImpRevision: 0,
        };
        for interface in [TPM_IFTYPE_HW, TPM_IFTYPE_SPB, TPM_IFTYPE_TRUSTZONE] {
            info.tpmInterfaceType = interface;
            assert!(validate_device(&info).is_ok());
        }
        for interface in [TPM_IFTYPE_UNKNOWN, TPM_IFTYPE_1, TPM_IFTYPE_EMULATOR, 99] {
            info.tpmInterfaceType = interface;
            assert!(validate_device(&info).is_err());
        }
        info.tpmInterfaceType = TPM_IFTYPE_HW;
        for version in [TPM_VERSION_UNKNOWN, TPM_VERSION_12, 99] {
            info.tpmVersion = version;
            assert!(validate_device(&info).is_err());
        }
        info.tpmVersion = TPM_VERSION_20;
        info.structVersion = 0;
        assert!(validate_device(&info).is_err());
    }

    // S02 §17.6 / S13 §10.4: a key that is provably gone counts as deleted so a
    // profile erase can finish; a key that may still exist keeps deletion failing.
    #[test]
    fn only_proof_of_absence_counts_as_deleted() {
        for gone in [
            NTE_BAD_KEYSET,
            NTE_NOT_FOUND,
            TPM_E_PCP_WRONG_PARENT,
            TPM_20_E_INTEGRITY,
        ] {
            assert!(key_gone(gone), "{:#010x}", gone as u32);
        }
        for maybe_present in [
            0,
            TBS_E_TPM_NOT_FOUND,
            NTE_DEVICE_NOT_FOUND,
            NTE_DEVICE_NOT_READY,
            TPM_E_PCP_DEVICE_NOT_READY,
            TPM_E_LOCKED_OUT,
            E_ACCESSDENIED,
        ] {
            assert!(!key_gone(maybe_present), "{:#010x}", maybe_present as u32);
        }
    }

    #[test]
    fn invalid_envelopes_are_rejected_before_hardware_access() {
        for blob in [
            vec![],
            vec![1; 32],
            vec![0; BLOB_LEN - 1],
            vec![0; BLOB_LEN],
            vec![0; BLOB_LEN + 1],
        ] {
            assert!(unwrap("invalid", &blob)
                .unwrap_err()
                .to_string()
                .contains("TPM-wrapped"));
        }
    }

    #[test]
    #[ignore = "creates and deletes uniquely named keys on a real Windows TPM"]
    fn hardware_wrap_tamper_export_rollback_and_delete() {
        let credential = format!("Najwa/TPM-test/{:032x}", rand::random::<u128>());
        let dkm = Zeroizing::new(rand::random::<[u8; 32]>());
        let pending = wrap(&credential, &dkm).expect("a working hardware TPM is required");
        let blob = pending.blob;
        assert_eq!(unwrap(&credential, &blob).unwrap(), *dkm);
        assert!(key_names(&pending._provider)
            .unwrap()
            .contains(&key_name(&credential)));
        let other_credential = format!("{credential}-other");
        let other = wrap(&other_credential, &[17; 32]).unwrap();
        assert!(
            unwrap(&other_credential, &blob).is_err(),
            "a different live key must reject this ciphertext"
        );
        drop(other);
        assert!(
            wrap(&credential, &[9; 32]).is_err(),
            "must not overwrite an existing key"
        );
        let mut tampered = blob;
        tampered[BLOB_LEN - 1] ^= 1;
        assert!(unwrap(&credential, &tampered).is_err());
        assert!(unwrap(&format!("{credential}-different"), &blob).is_err());
        let mut size = 0;
        // SAFETY: a live key and valid output-size pointer; no export buffer allocated.
        let export = unsafe {
            NCryptExportKey(
                pending.key.0,
                0,
                BCRYPT_RSAPRIVATE_BLOB,
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                &mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        assert_ne!(export, 0, "private key export must be refused");
        drop(pending); // Simulate failed credential commit, delete only this test key.
        assert!(unwrap(&credential, &blob).is_err());
        let pending = wrap(&credential, &dkm).unwrap();
        let blob = pending.blob;
        pending.commit();
        assert_eq!(unwrap(&credential, &blob).unwrap(), *dkm);
        delete(&credential).unwrap();
        assert!(unwrap(&credential, &blob).is_err());
        delete(&credential).unwrap();
    }

    #[test]
    #[ignore = "tests failed Credential Manager commit with a synthetic Windows TPM key"]
    fn hardware_failed_credential_commit_retires_prepared_key() {
        use windows_sys::Win32::Security::Credentials::CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
        let credential = format!(
            "Najwa/TPM-write-failure/{:032x}/{}",
            rand::random::<u128>(),
            "x".repeat(CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize)
        );
        let key_name = key_name(&credential);
        assert!(super::super::windows::store_named_dkm(&credential, &[31; 32]).is_err());
        assert!(
            !key_names(&provider().unwrap()).unwrap().contains(&key_name),
            "a failed credential write must remove the prepared TPM key"
        );
    }
}
