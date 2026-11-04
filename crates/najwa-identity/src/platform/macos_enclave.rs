//! Standard-mode device factor wrapped by a Secure Enclave P-256 key.
//! All key and ciphertext operations target the local data-protection keychain.

use crate::error::{IdentityError, Result};
use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    error::{CFError, CFErrorRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    key::SecKey,
};
use security_framework_sys::{
    access_control::kSecAccessControlPrivateKeyUsage,
    item::*,
    key::*,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// Security.framework exports these; security-framework-sys 2.x omits the bindings.
extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
}

const SERVICE: &str = "com.najwa.identity";
const KEY_LABEL: &str = "Najwa device factor";
const TAG_PREFIX: &[u8] = b"com.najwa.identity.enclave.v2.";
const MAGIC: &[u8; 8] = b"NJWMSE01";
const MAX_CIPHERTEXT: usize = 4096;
const NOT_FOUND: i32 = -25300;

#[cfg(test)]
thread_local! {
    static FAIL_CREDENTIAL_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn error(message: impl std::fmt::Display) -> IdentityError {
    IdentityError::DkmError(format!("macOS Secure Enclave: {message}"))
}

fn binding(name: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Najwa/v2/Secure-Enclave/DKM\0");
    hash.update(name.as_bytes());
    hash.finalize().into()
}

fn tag(name: &str) -> Vec<u8> {
    let mut tag = TAG_PREFIX.to_vec();
    tag.extend_from_slice(&Sha256::digest(name.as_bytes()));
    tag
}

type Attributes = Vec<(CFString, CFType)>;

// Callers pass only Apple's immutable, non-null Security.framework constants.
fn attribute(key: CFStringRef, value: impl TCFType) -> (CFString, CFType) {
    (
        unsafe { CFString::wrap_under_get_rule(key) },
        value.as_CFType(),
    )
}

fn text(value: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(value) }
}

fn dictionary(attributes: &[(CFString, CFType)]) -> CFDictionary {
    CFDictionary::from_CFType_pairs(attributes).into_untyped()
}

fn local_query(class: CFStringRef) -> Attributes {
    unsafe {
        vec![
            attribute(kSecClass, text(class)),
            attribute(kSecUseDataProtectionKeychain, CFBoolean::true_value()),
            attribute(kSecAttrSynchronizable, CFBoolean::false_value()),
            // No unsolicited biometric dialogs or UI fallback on background unlock.
            attribute(kSecUseAuthenticationUI, text(kSecUseAuthenticationUIFail)),
        ]
    }
}

fn key_query(name: Option<&str>) -> Attributes {
    let mut query = local_query(unsafe { kSecClassKey });
    unsafe {
        query.push(attribute(kSecAttrKeyClass, text(kSecAttrKeyClassPrivate)));
        query.push(attribute(
            kSecAttrKeyType,
            text(kSecAttrKeyTypeECSECPrimeRandom),
        ));
        if let Some(name) = name {
            query.push(attribute(
                kSecAttrApplicationTag,
                CFData::from_buffer(&tag(name)),
            ));
        } else {
            query.push(attribute(kSecAttrLabel, CFString::new(KEY_LABEL)));
        }
    }
    query
}

fn credential_query(name: &str) -> Attributes {
    let mut query = local_query(unsafe { kSecClassGenericPassword });
    unsafe {
        query.push(attribute(kSecAttrService, CFString::new(SERVICE)));
        query.push(attribute(kSecAttrAccount, CFString::new(name)));
    }
    query
}

fn search(query: &[(CFString, CFType)]) -> Result<Option<CFType>> {
    let query = dictionary(query);
    let mut raw: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
    let value = (!raw.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(raw) });
    match status {
        0 => value
            .map(Some)
            .ok_or_else(|| error("keychain returned no result")),
        NOT_FOUND => Ok(None),
        code => Err(error(format!("keychain search failed ({code})"))),
    }
}

fn field(attributes: &CFDictionary, key: CFStringRef) -> Option<CFType> {
    attributes
        .find(key.cast())
        .map(|value| unsafe { CFType::wrap_under_get_rule(*value) })
}

fn validate_key(key: &SecKey) -> Result<()> {
    let raw = unsafe { SecKeyCopyAttributes(key.as_concrete_TypeRef()) };
    if raw.is_null() {
        return Err(error("key attributes unavailable"));
    }
    let attributes = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    unsafe {
        let token = field(&attributes, kSecAttrTokenID).and_then(|v| v.downcast::<CFString>());
        let kind = field(&attributes, kSecAttrKeyType).and_then(|v| v.downcast::<CFString>());
        let class = field(&attributes, kSecAttrKeyClass).and_then(|v| v.downcast::<CFString>());
        let bits = field(&attributes, kSecAttrKeySizeInBits)
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|v| v.to_i64());
        if token != Some(text(kSecAttrTokenIDSecureEnclave))
            || kind != Some(text(kSecAttrKeyTypeECSECPrimeRandom))
            || class != Some(text(kSecAttrKeyClassPrivate))
            || bits != Some(256)
        {
            return Err(error("a Secure Enclave P-256 private key is required"));
        }
        if SecKeyIsAlgorithmSupported(
            key.as_concrete_TypeRef(),
            kSecKeyOperationTypeDecrypt,
            kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
        ) == 0
        {
            return Err(error("Secure Enclave ECIES decryption is unavailable"));
        }
    }
    Ok(())
}

fn keys(name: Option<&str>) -> Result<Vec<SecKey>> {
    let mut query = key_query(name);
    unsafe {
        query.push(attribute(kSecReturnRef, CFBoolean::true_value()));
        query.push(attribute(kSecMatchLimit, text(kSecMatchLimitAll)));
    }
    let Some(value) = search(&query)? else {
        return Ok(vec![]);
    };
    let array = value
        .downcast::<CFArray>()
        .ok_or_else(|| error("invalid key search result"))?;
    let mut keys = Vec::with_capacity(array.len() as usize);
    for reference in array.iter() {
        let value = unsafe { CFType::wrap_under_get_rule(*reference) };
        if !value.instance_of::<SecKey>() {
            return Err(error("invalid key reference"));
        }
        let key = unsafe { SecKey::wrap_under_get_rule(value.as_CFTypeRef().cast_mut().cast()) };
        validate_key(&key)?;
        keys.push(key);
    }
    Ok(keys)
}

fn load_key(name: &str) -> Result<SecKey> {
    let mut keys = keys(Some(name))?;
    if keys.len() != 1 {
        return Err(error("exactly one device key is required"));
    }
    Ok(keys.remove(0))
}

fn cf_failure(operation: &str, raw: CFErrorRef) -> IdentityError {
    if raw.is_null() {
        return error(format!("{operation} failed without an error result"));
    }
    let failure = unsafe { CFError::wrap_under_create_rule(raw) };
    error(format!("{operation} failed ({})", failure.code()))
}

fn generate_key(name: &str) -> Result<SecKey> {
    let control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage,
    )
    .map_err(error)?;
    let private = unsafe {
        dictionary(&[
            attribute(kSecAttrIsPermanent, CFBoolean::true_value()),
            attribute(kSecAttrApplicationTag, CFData::from_buffer(&tag(name))),
            attribute(kSecAttrLabel, CFString::new(KEY_LABEL)),
            attribute(kSecAttrAccessControl, control),
        ])
    };
    let attributes = unsafe {
        dictionary(&[
            attribute(kSecAttrKeyType, text(kSecAttrKeyTypeECSECPrimeRandom)),
            attribute(kSecAttrKeySizeInBits, CFNumber::from(256i32)),
            attribute(kSecAttrTokenID, text(kSecAttrTokenIDSecureEnclave)),
            attribute(kSecUseDataProtectionKeychain, CFBoolean::true_value()),
            attribute(kSecAttrSynchronizable, CFBoolean::false_value()),
            attribute(kSecAttrLabel, CFString::new(KEY_LABEL)),
            attribute(kSecPrivateKeyAttrs, private),
        ])
    };
    let mut failure = std::ptr::null_mut();
    let raw = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut failure) };
    let key = (!raw.is_null()).then(|| unsafe { SecKey::wrap_under_create_rule(raw) });
    if !failure.is_null() || key.is_none() {
        if let Some(key) = key {
            let _ = remove_key(&key);
        }
        return Err(cf_failure("key generation", failure));
    }
    Ok(key.expect("checked key"))
}

fn remove_key(key: &SecKey) -> Result<()> {
    let mut query = local_query(unsafe { kSecClassKey });
    query.push(attribute(unsafe { kSecValueRef }, key.clone()));
    let status = unsafe { SecItemDelete(dictionary(&query).as_concrete_TypeRef()) };
    match status {
        0 | NOT_FOUND => Ok(()),
        code => Err(error(format!("key deletion failed ({code})"))),
    }
}

struct PendingKey(Option<SecKey>);
impl Drop for PendingKey {
    fn drop(&mut self) {
        if let Some(key) = &self.0 {
            let _ = remove_key(key);
        }
    }
}

fn crypt(key: &SecKey, input: &[u8], encrypt: bool) -> Result<CFData> {
    let data = CFData::from_buffer(input);
    let mut failure = std::ptr::null_mut();
    let raw = unsafe {
        let algorithm = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
        if encrypt {
            SecKeyCreateEncryptedData(
                key.as_concrete_TypeRef(),
                algorithm,
                data.as_concrete_TypeRef(),
                &mut failure,
            )
        } else {
            SecKeyCreateDecryptedData(
                key.as_concrete_TypeRef(),
                algorithm,
                data.as_concrete_TypeRef(),
                &mut failure,
            )
        }
    };
    let output = (!raw.is_null()).then(|| unsafe { CFData::wrap_under_create_rule(raw) });
    if !failure.is_null() || output.is_none() {
        return Err(cf_failure("ECIES", failure));
    }
    Ok(output.expect("checked data"))
}

fn ciphertext(blob: &[u8]) -> Result<&[u8]> {
    if blob.len() <= MAGIC.len() || blob.len() > MAGIC.len() + MAX_CIPHERTEXT || &blob[..8] != MAGIC
    {
        return Err(error("bounded Secure Enclave ciphertext required"));
    }
    Ok(&blob[8..])
}

fn unwrap(key: &SecKey, name: &str, blob: &[u8]) -> Result<[u8; 32]> {
    let data = crypt(key, ciphertext(blob)?, false)?;
    let data = Zeroizing::new(data.to_vec());
    if data.len() != 64 || data[..32] != binding(name) {
        return Err(error("device factor binding or size mismatch"));
    }
    Ok(data[32..].try_into().expect("validated length"))
}

pub(super) fn store(name: &str, dkm: &[u8; 32]) -> Result<()> {
    // SecItemAdd below refuses an existing credential atomically. Never update it.
    let mut query = credential_query(name);
    query.push(attribute(
        unsafe { kSecReturnData },
        CFBoolean::true_value(),
    ));
    if search(&query)?.is_some() || !keys(Some(name))?.is_empty() {
        return Err(error("device factor generation already exists"));
    }
    let mut pending = PendingKey(Some(generate_key(name)?));
    let key = pending.0.as_ref().expect("pending key");
    validate_key(key)?;
    // Duplicate application tags can be generated by the OS. Require one key,
    // verify it is ours, and only ever clean up our exact key reference on failure.
    let loaded = load_key(name)?;
    if key.application_label().is_none() || key.application_label() != loaded.application_label() {
        return Err(error(
            "generated key does not match its persisted generation",
        ));
    }
    let public = key
        .public_key()
        .ok_or_else(|| error("public key unavailable"))?;
    let mut plaintext = Zeroizing::new([0u8; 64]);
    plaintext[..32].copy_from_slice(&binding(name));
    plaintext[32..].copy_from_slice(dkm);
    let encrypted = crypt(&public, &plaintext[..], true)?;
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(encrypted.bytes());
    let verified = Zeroizing::new(unwrap(&loaded, name, &blob)?);
    if !najwa_crypto::hash::constant_time_eq(&*verified, dkm) {
        return Err(error("device factor verification failed"));
    }
    let mut attributes = credential_query(name);
    // Authentication UI is a query parameter, not an item creation attribute.
    attributes.retain(|(key, _)| *key != text(unsafe { kSecUseAuthenticationUI }));
    unsafe {
        attributes.push(attribute(
            kSecAttrAccessible,
            text(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
        ));
        attributes.push(attribute(kSecValueData, CFData::from_buffer(&blob)));
    }
    #[cfg(test)]
    if FAIL_CREDENTIAL_WRITE.with(|fail| fail.replace(false)) {
        return Err(error("injected synthetic credential write failure"));
    }
    let status = unsafe {
        SecItemAdd(
            dictionary(&attributes).as_concrete_TypeRef(),
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(error(format!("credential creation failed ({status})")));
    }
    pending.0 = None;
    Ok(())
}

pub(super) fn retrieve(name: &str) -> Result<[u8; 32]> {
    let mut query = credential_query(name);
    query.push(attribute(
        unsafe { kSecReturnData },
        CFBoolean::true_value(),
    ));
    let value = search(&query)?.ok_or_else(|| error("device factor unavailable"))?;
    let blob = value
        .downcast::<CFData>()
        .ok_or_else(|| error("invalid credential type"))?;
    ciphertext(blob.bytes())?;
    unwrap(&load_key(name)?, name, blob.bytes())
}

pub(super) fn delete(name: &str) -> Result<()> {
    for key in keys(Some(name))? {
        remove_key(&key)?;
    }
    // If hardware deletion fails, preserve ciphertext for diagnosis/retry.
    let status =
        unsafe { SecItemDelete(dictionary(&credential_query(name)).as_concrete_TypeRef()) };
    match status {
        0 | NOT_FOUND => Ok(()),
        code => Err(error(format!("credential deletion failed ({code})"))),
    }
}

pub(super) fn delete_orphan_keys() -> Result<()> {
    for key in keys(None)? {
        let attributes = key.attributes();
        let tag = field(&attributes, unsafe { kSecAttrApplicationTag })
            .and_then(|v| v.downcast::<CFData>());
        if tag.is_some_and(|tag| {
            tag.bytes().starts_with(TAG_PREFIX) && tag.len() as usize == TAG_PREFIX.len() + 32
        }) {
            remove_key(&key)?;
        }
    }
    Ok(())
}

pub(super) fn delete_records() -> Result<()> {
    let mut query = local_query(unsafe { kSecClassGenericPassword });
    unsafe {
        query.push(attribute(kSecAttrService, CFString::new(SERVICE)));
        query.push(attribute(kSecReturnAttributes, CFBoolean::true_value()));
        query.push(attribute(kSecMatchLimit, text(kSecMatchLimitAll)));
    }
    if let Some(value) = search(&query)? {
        let array = value
            .downcast::<CFArray>()
            .ok_or_else(|| error("invalid credential search result"))?;
        for reference in array.iter() {
            let value = unsafe { CFType::wrap_under_get_rule(*reference) };
            let attributes = value
                .downcast::<CFDictionary>()
                .ok_or_else(|| error("invalid credential attributes"))?;
            let account = field(&attributes, unsafe { kSecAttrAccount })
                .and_then(|v| v.downcast::<CFString>());
            if let Some(account) = account {
                let name = account.to_string();
                if name.starts_with("Najwa/DKM/record/") {
                    delete(&name)?;
                }
            }
        }
    }
    // Crash-before-publication can leave a hardware key with no credential.
    delete_orphan_keys()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_legacy_and_oversized_ciphertexts_are_rejected() {
        for blob in [
            vec![],
            vec![0; 32],
            MAGIC.to_vec(),
            vec![0; MAX_CIPHERTEXT + 9],
        ] {
            assert!(ciphertext(&blob).is_err());
        }
        assert_ne!(tag("one"), tag("two"));
        assert_ne!(binding("one"), binding("two"));
    }

    #[test]
    fn software_private_key_is_rejected() {
        let attributes = unsafe {
            dictionary(&[
                attribute(kSecAttrKeyType, text(kSecAttrKeyTypeECSECPrimeRandom)),
                attribute(kSecAttrKeySizeInBits, CFNumber::from(256i32)),
            ])
        };
        let mut failure = std::ptr::null_mut();
        let raw = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut failure) };
        let key = (!raw.is_null()).then(|| unsafe { SecKey::wrap_under_create_rule(raw) });
        if !failure.is_null() {
            panic!("{}", cf_failure("synthetic software key", failure));
        }
        let key = key.expect("synthetic ephemeral software key");
        assert!(validate_key(&key).is_err());
    }

    #[test]
    #[ignore = "requires a signed macOS test process with Secure Enclave and keychain access"]
    fn hardware_enclave_lifecycle_binding_tamper_export_and_key_loss() {
        let name = format!("Najwa/Enclave-test/{:032x}", rand::random::<u128>());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete(&self.0);
            }
        }
        let _cleanup = Cleanup(name.clone());
        store(&name, &[42; 32]).unwrap();
        assert!(store(&name, &[43; 32]).is_err());
        assert_eq!(retrieve(&name).unwrap(), [42; 32]);
        let key = load_key(&name).unwrap();
        let mut failure = std::ptr::null_mut();
        let raw =
            unsafe { SecKeyCopyExternalRepresentation(key.as_concrete_TypeRef(), &mut failure) };
        let exported = (!raw.is_null()).then(|| unsafe { CFData::wrap_under_create_rule(raw) });
        if !failure.is_null() {
            drop(unsafe { CFError::wrap_under_create_rule(failure) });
        }
        assert!(
            exported.is_none(),
            "Secure Enclave private key must not be exportable"
        );
        let mut query = credential_query(&name);
        query.push(attribute(
            unsafe { kSecReturnData },
            CFBoolean::true_value(),
        ));
        let blob = search(&query)
            .unwrap()
            .unwrap()
            .downcast::<CFData>()
            .unwrap();
        assert!(unwrap(&key, "another generation", blob.bytes()).is_err());
        let mut tampered = blob.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(unwrap(&key, &name, &tampered).is_err());
        remove_key(&key).unwrap();
        assert!(retrieve(&name).is_err());
        delete(&name).unwrap();
        delete(&name).unwrap();
        FAIL_CREDENTIAL_WRITE.with(|fail| fail.set(true));
        assert!(store(&name, &[42; 32]).is_err());
        assert!(
            keys(Some(&name)).unwrap().is_empty(),
            "failed credential write must remove its new key"
        );
    }
}
