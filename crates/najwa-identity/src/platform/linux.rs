//! Linux DKM via Secret Service (`keyring` crate — GNOME Keyring / KWallet).

use crate::error::{IdentityError, Result};

const SERVICE: &str = "com.najwa.identity";
const USER: &str = "najwa-dkm-v1";

pub(super) fn delete_record_dkms() -> Result<()> {
    use dbus_secret_service::{EncryptionType, SecretService};
    let delete = || -> std::result::Result<(), dbus_secret_service::Error> {
        let service = SecretService::connect(EncryptionType::Dh)?;
        let items =
            service.search_items(std::collections::HashMap::from([("service", SERVICE)]))?;
        for item in items.unlocked.into_iter().chain(items.locked) {
            if item
                .get_attributes()?
                .get("username")
                .is_some_and(|name| name.starts_with("Najwa/DKM/record/"))
            {
                item.delete()?;
            }
        }
        Ok(())
    };
    delete().map_err(|e| IdentityError::DkmError(format!("keyring cleanup: {e}")))
}

pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    store_named_dkm(USER, dkm)
}

pub(super) fn store_named_dkm(name: &str, dkm: &[u8; 32]) -> Result<()> {
    #[cfg(feature = "linux-tpm")]
    return super::linux_tpm::store(name, dkm);
    #[cfg(not(feature = "linux-tpm"))]
    {
        let entry = keyring::Entry::new(SERVICE, name)
            .map_err(|e| IdentityError::DkmError(format!("keyring init: {e}")))?;
        // keyring stores strings; we hex-encode the 32 bytes
        let hex = zeroize::Zeroizing::new(hex_encode(dkm));
        entry
            .set_password(&hex)
            .map_err(|e| IdentityError::DkmError(format!("keyring store: {e}")))
    }
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    retrieve_named_dkm(USER)
}

pub(super) fn retrieve_named_dkm(name: &str) -> Result<[u8; 32]> {
    #[cfg(feature = "linux-tpm")]
    return super::linux_tpm::retrieve(name);
    #[cfg(not(feature = "linux-tpm"))]
    {
        let entry = keyring::Entry::new(SERVICE, name)
            .map_err(|e| IdentityError::DkmError(format!("keyring init: {e}")))?;
        let hex = zeroize::Zeroizing::new(
            entry
                .get_password()
                .map_err(|e| IdentityError::DkmError(format!("keyring retrieve: {e}")))?,
        );
        hex_decode_32(&hex)
    }
}

pub fn delete_dkm() -> Result<()> {
    delete_named_dkm(USER)
}

pub(super) fn delete_named_dkm(name: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE, name)
        .map_err(|e| IdentityError::DkmError(format!("keyring init: {e}")))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(IdentityError::DkmError(format!("keyring delete: {e}"))),
    }
}

#[cfg(not(feature = "linux-tpm"))]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(not(feature = "linux-tpm"))]
fn hex_decode_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(IdentityError::DkmError(format!(
            "DKM hex length mismatch: expected 64, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| IdentityError::DkmError("invalid hex".into()))?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| IdentityError::DkmError("invalid hex digit".into()))?;
    }
    Ok(out)
}
