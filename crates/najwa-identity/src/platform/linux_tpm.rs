//! TPM2-sealed Standard-mode device factor. Production uses only /dev/tpmrm0.
//! Secret Service persists an encrypted TPM object, never a raw device secret.

use crate::error::{IdentityError, Result};
use sha2::{Digest as _, Sha256};
use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Digest, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters,
        RsaExponent, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf,
};
use zeroize::Zeroizing;

const SERVICE: &str = "com.najwa.identity";
const MAGIC: &[u8; 8] = b"NJWLTP01";
const MAX_BLOB: usize = 4096;

fn error(e: impl std::fmt::Display) -> IdentityError {
    IdentityError::DkmError(format!("Linux TPM: {e}"))
}

fn binding(name: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Najwa/v2/Linux-TPM/DKM\0");
    hash.update(name.as_bytes());
    hash.finalize().into()
}

fn device_transport() -> Result<TctiNameConf> {
    // Never consult TSS2_TCTI/TPM2TOOLS_TCTI or accept a network TCTI from a blob.
    "device:/dev/tpmrm0".parse().map_err(error)
}

// Only unit-test builds can select a simulator; release builds have no override.
#[cfg(test)]
thread_local! {
    static TEST_TRANSPORT: std::cell::RefCell<Option<TctiNameConf>> = const { std::cell::RefCell::new(None) };
}

fn transport() -> Result<TctiNameConf> {
    #[cfg(test)]
    if let Some(tcti) = TEST_TRANSPORT.with(|cell| cell.borrow().clone()) {
        return Ok(tcti);
    }
    device_transport()
}

fn sealed_template() -> Result<Public> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_user_with_auth(true)
                .with_sensitive_data_origin(false)
                .with_no_da(true)
                .build()
                .map_err(error)?,
        )
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(error)
}

fn validate_public(public: &Public) -> Result<()> {
    let template = sealed_template()?;
    match (public, &template) {
        (
            Public::KeyedHash {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique,
            },
            Public::KeyedHash {
                object_attributes: expected,
                parameters: expected_parameters,
                ..
            },
        ) if object_attributes == expected
            && parameters == expected_parameters
            && *name_hashing_algorithm == HashingAlgorithm::Sha256
            && auth_policy.is_empty()
            && unique.len() == 32 =>
        {
            Ok(())
        }
        _ => Err(error("sealed object must have the fixed TPM/parent policy")),
    }
}

struct Tpm {
    context: Context,
    parent: KeyHandle,
    session: AuthSession,
}

impl Tpm {
    fn new(transport: TctiNameConf) -> Result<Self> {
        let mut context = Context::new(transport).map_err(error)?;
        // Deterministic, TPM-generated owner-hierarchy storage root. No hierarchy
        // reset/ownership change and no persistent NV handle is allocated.
        let public = tss_esapi::utils::create_restricted_decryption_rsa_public(
            SymmetricDefinitionObject::AES_256_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .map_err(error)?;
        let parent = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
            })
            .map_err(error)?
            .key_handle;
        // Salt the HMAC session with the TPM root: DKM parameters are encrypted
        // on the TPM bus both when sealing and when returning unsealed data.
        let session = context
            .start_auth_session(
                Some(parent),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(error)?
            .ok_or_else(|| error("encrypted session unavailable"))?;
        Ok(Self {
            context,
            parent,
            session,
        })
    }

    fn protection(&mut self, decrypt: bool, encrypt: bool) -> Result<()> {
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(decrypt)
            .with_encrypt(encrypt)
            .build();
        self.context
            .tr_sess_set_attributes(self.session, attributes, mask)
            .map_err(error)
    }

    fn unseal(&mut self, name: &str, public: Public, private: Private) -> Result<[u8; 32]> {
        validate_public(&public)?;
        // Load carries an already encrypted private object; no plaintext DKM.
        let child = self
            .context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(self.parent, private, public)
            })
            .map_err(error)?;
        self.protection(false, true)?;
        let data = self
            .context
            .execute_with_session(Some(self.session), |ctx| ctx.unseal(child.into()))
            .map_err(error);
        // Flush even on an unseal failure. Context drop retries cleanup on errors.
        let cleanup = self.context.flush_context(child.into()).map_err(error);
        let data = data?;
        cleanup?;
        if data.len() != 64 || data[..32] != binding(name) {
            return Err(error("sealed device factor binding or size mismatch"));
        }
        Ok(data[32..64].try_into().expect("validated length"))
    }

    fn seal(&mut self, name: &str, dkm: &[u8; 32]) -> Result<Vec<u8>> {
        let mut data = Zeroizing::new([0u8; 64]);
        data[..32].copy_from_slice(&binding(name));
        data[32..].copy_from_slice(dkm);
        let sensitive = SensitiveData::try_from(data.as_slice()).map_err(error)?;
        let public = sealed_template()?;
        self.protection(true, true)?;
        let object = self
            .context
            .execute_with_session(Some(self.session), |ctx| {
                ctx.create(self.parent, public, None, Some(sensitive), None, None)
            })
            .map_err(error)?;
        let recovered = Zeroizing::new(self.unseal(
            name,
            object.out_public.clone(),
            object.out_private.clone(),
        )?);
        if !najwa_crypto::hash::constant_time_eq(&*recovered, dkm) {
            return Err(error("sealed device factor verification failed"));
        }
        encode(&object.out_public, &object.out_private)
    }
}

fn encode(public: &Public, private: &Private) -> Result<Vec<u8>> {
    let public = public.marshall().map_err(error)?;
    let private = private.value();
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&(public.len() as u16).to_be_bytes());
    blob.extend_from_slice(&(private.len() as u16).to_be_bytes());
    blob.extend_from_slice(&public);
    blob.extend_from_slice(private);
    if blob.len() > MAX_BLOB {
        return Err(error("sealed object too large"));
    }
    Ok(blob)
}

fn decode(blob: &[u8]) -> Result<(Public, Private)> {
    if !(12..=MAX_BLOB).contains(&blob.len()) || &blob[..8] != MAGIC {
        return Err(error("TPM-sealed device factor required"));
    }
    let public_len = u16::from_be_bytes(blob[8..10].try_into().expect("header")) as usize;
    let private_len = u16::from_be_bytes(blob[10..12].try_into().expect("header")) as usize;
    if public_len == 0 || private_len == 0 || 12 + public_len + private_len != blob.len() {
        return Err(error("invalid sealed object length"));
    }
    let public_bytes = &blob[12..12 + public_len];
    let public = Public::unmarshall(public_bytes).map_err(error)?;
    if public.marshall().map_err(error)? != public_bytes {
        return Err(error("noncanonical sealed public object"));
    }
    validate_public(&public)?;
    let private = Private::try_from(&blob[12 + public_len..]).map_err(error)?;
    Ok((public, private))
}

fn hex_blob(blob: &[u8]) -> String {
    blob.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_blob(hex: &str) -> Result<Vec<u8>> {
    if hex.len() > MAX_BLOB * 2 || !hex.len().is_multiple_of(2) {
        return Err(error("invalid sealed credential length"));
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).map_err(error)?;
            u8::from_str_radix(digits, 16).map_err(error)
        })
        .collect()
}

pub(super) fn store(name: &str, dkm: &[u8; 32]) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, name).map_err(error)?;
    match entry.get_password() {
        Err(keyring::Error::NoEntry) => {}
        Ok(_) => return Err(error("device factor generation already exists")),
        Err(e) => return Err(error(e)),
    }
    let mut tpm = Tpm::new(transport()?)?;
    let blob = tpm.seal(name, dkm)?;
    entry.set_password(&hex_blob(&blob)).map_err(error)
}

pub(super) fn retrieve(name: &str) -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(SERVICE, name).map_err(error)?;
    let hex = Zeroizing::new(entry.get_password().map_err(error)?);
    let (public, private) = decode(&parse_blob(&hex)?)?;
    Tpm::new(transport()?)?.unseal(name, public, private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_legacy_blobs_are_rejected_without_a_tpm() {
        for blob in [
            vec![],
            vec![0; 32],
            vec![0; 64],
            vec![0; MAX_BLOB + 1],
            MAGIC.to_vec(),
        ] {
            assert!(decode(&blob).is_err());
        }
        assert!(parse_blob(&"x".repeat(MAX_BLOB * 2 + 2)).is_err());
        assert!(parse_blob("€€").is_err());
        assert!(parse_blob("abc").is_err());
        assert!(matches!(
            device_transport().unwrap(),
            TctiNameConf::Device(_)
        ));
    }

    #[test]
    #[ignore = "requires an isolated TPM simulator on loopback ports 2321 and 2323"]
    fn simulator_roundtrip_restart_binding_tamper_and_device_loss() {
        let transport = || "swtpm:host=127.0.0.1,port=2321".parse().unwrap();
        let name = format!("Najwa/TPM-test/{:032x}", rand::random::<u128>());
        let dkm = Zeroizing::new(rand::random::<[u8; 32]>());
        let blob = Tpm::new(transport()).unwrap().seal(&name, &dkm).unwrap();
        let (public, private) = decode(&blob).unwrap();
        assert_eq!(
            Tpm::new(transport())
                .unwrap()
                .unseal(&name, public.clone(), private.clone())
                .unwrap(),
            *dkm
        );
        assert!(Tpm::new(transport())
            .unwrap()
            .unseal("different record", public, private)
            .is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let (public, private) = decode(&tampered).unwrap();
        assert!(Tpm::new(transport())
            .unwrap()
            .unseal(&name, public, private)
            .is_err());
        let (public, private) = decode(&blob).unwrap();
        let other = "swtpm:host=127.0.0.1,port=2323".parse().unwrap();
        assert!(
            Tpm::new(other)
                .unwrap()
                .unseal(&name, public, private)
                .is_err(),
            "another TPM must not unseal this object"
        );
    }

    #[test]
    #[ignore = "requires isolated loopback swtpm and a disposable Secret Service"]
    fn simulator_identity_and_credential_lifecycle() {
        use crate::{platform, record::IdentityRecordStandard, IdentityManager};
        struct TestScope;
        impl Drop for TestScope {
            fn drop(&mut self) {
                TEST_TRANSPORT.with(|cell| *cell.borrow_mut() = None);
                platform::set_dkm_storage_for_test(platform::MockDkmStorage::new());
            }
        }
        let _scope = TestScope;
        platform::MOCK_DKM_STORAGE.with(|cell| *cell.borrow_mut() = None);
        TEST_TRANSPORT.with(|cell| {
            *cell.borrow_mut() = Some("swtpm:host=127.0.0.1,port=2321".parse().unwrap())
        });
        let name = format!("Najwa/TPM-test/{:032x}", rand::random::<u128>());
        struct CredentialCleanup(String);
        impl Drop for CredentialCleanup {
            fn drop(&mut self) {
                let _ = platform::linux::delete_named_dkm(&self.0);
            }
        }
        let _credential = CredentialCleanup(name.clone());
        store(&name, &[42; 32]).unwrap();
        assert!(store(&name, &[43; 32]).is_err());
        assert_eq!(retrieve(&name).unwrap(), [42; 32]);
        let entry = keyring::Entry::new(SERVICE, &name).unwrap();
        let original = entry.get_password().unwrap();
        assert!(parse_blob(&original).unwrap().starts_with(MAGIC));
        entry.set_password(&"42".repeat(32)).unwrap();
        assert!(
            retrieve(&name).is_err(),
            "raw legacy credentials must be rejected"
        );
        entry.set_password(&original).unwrap();
        platform::linux::delete_named_dkm(&name).unwrap();
        assert!(retrieve(&name).is_err());
        platform::linux::delete_named_dkm(&name).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.najwa");
        struct RecordCleanup(std::path::PathBuf);
        impl Drop for RecordCleanup {
            fn drop(&mut self) {
                if let Ok(bytes) = std::fs::read(&self.0) {
                    if let Ok(record) = IdentityRecordStandard::from_bytes(&bytes) {
                        let _ = platform::delete_record_dkm(&record);
                    }
                }
            }
        }
        let _record = RecordCleanup(path.clone());
        let mut manager = IdentityManager::new(path.clone()).unwrap();
        manager.create("synthetic original passphrase").unwrap();
        let public = manager.identity().unwrap().keypair.public().to_bytes();
        let first = IdentityRecordStandard::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        drop(manager);
        let mut manager = IdentityManager::new(path.clone()).unwrap();
        assert!(manager.unlock("incorrect synthetic passphrase").is_err());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        manager.unlock("synthetic original passphrase").unwrap();
        assert_eq!(
            manager.identity().unwrap().keypair.public().to_bytes(),
            public
        );
        manager
            .change_password(
                "synthetic original passphrase",
                "synthetic replacement passphrase",
            )
            .unwrap();
        assert!(platform::retrieve_record_dkm(&first).is_err());
        drop(manager);
        assert_eq!(
            IdentityManager::unlock_once(&path, "synthetic replacement passphrase")
                .unwrap()
                .keypair
                .public()
                .to_bytes(),
            public
        );
        let current = IdentityRecordStandard::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        TEST_TRANSPORT.with(|cell| {
            *cell.borrow_mut() = Some("swtpm:host=127.0.0.1,port=2323".parse().unwrap())
        });
        assert!(IdentityManager::unlock_once(&path, "synthetic replacement passphrase").is_err());
        platform::delete_record_dkm(&current).unwrap();
        assert!(platform::retrieve_record_dkm(&current).is_err());
    }

    #[test]
    #[ignore = "requires a real /dev/tpmrm0 TPM2 device; creates only transient test objects"]
    fn hardware_roundtrip() {
        let name = format!("Najwa/TPM-test/{:032x}", rand::random::<u128>());
        let blob = Tpm::new(device_transport().unwrap())
            .unwrap()
            .seal(&name, &[19; 32])
            .unwrap();
        let (public, private) = decode(&blob).unwrap();
        assert_eq!(
            Tpm::new(device_transport().unwrap())
                .unwrap()
                .unseal(&name, public, private)
                .unwrap(),
            [19; 32]
        );
    }
}
