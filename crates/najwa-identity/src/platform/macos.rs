//! macOS DKM via Keychain Services (`security-framework` crate).

#[cfg(not(feature = "macos-secure-enclave"))]
use crate::error::IdentityError;
use crate::error::Result;

#[cfg(not(feature = "macos-secure-enclave"))]
const SERVICE: &str = "com.najwa.identity";
const ACCOUNT: &str = "najwa-dkm-v1";

pub(super) fn delete_record_dkms() -> Result<()> {
    #[cfg(feature = "macos-secure-enclave")]
    return super::macos_enclave::delete_records();
    #[cfg(not(feature = "macos-secure-enclave"))]
    {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        let items = match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(items) => items,
            Err(e) if e.code() == -25300 => return Ok(()),
            Err(e) => {
                return Err(IdentityError::DkmError(format!(
                    "Keychain search failed: {e}"
                )))
            }
        };
        for item in items {
            if let Some(name) = item
                .simplify_dict()
                .and_then(|mut attributes| attributes.remove("acct"))
            {
                if name.starts_with("Najwa/DKM/record/") {
                    delete_named_dkm(&name)?;
                }
            }
        }
        Ok(())
    }
}

pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    store_named_dkm(ACCOUNT, dkm)
}

pub(super) fn store_named_dkm(name: &str, dkm: &[u8; 32]) -> Result<()> {
    #[cfg(feature = "macos-secure-enclave")]
    return super::macos_enclave::store(name, dkm);
    #[cfg(not(feature = "macos-secure-enclave"))]
    {
        use security_framework::passwords::set_generic_password;

        set_generic_password(SERVICE, name, dkm)
            .map_err(|e| IdentityError::DkmError(format!("Keychain store failed: {e}")))
    }
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    retrieve_named_dkm(ACCOUNT)
}

pub(super) fn retrieve_named_dkm(name: &str) -> Result<[u8; 32]> {
    #[cfg(feature = "macos-secure-enclave")]
    return super::macos_enclave::retrieve(name);
    #[cfg(not(feature = "macos-secure-enclave"))]
    {
        use security_framework::passwords::get_generic_password;

        let data = zeroize::Zeroizing::new(
            get_generic_password(SERVICE, name)
                .map_err(|e| IdentityError::DkmError(format!("Keychain retrieve failed: {e}")))?,
        );

        if data.len() != 32 {
            return Err(IdentityError::DkmError(format!(
                "DKM blob size mismatch: expected 32, got {}",
                data.len()
            )));
        }

        let mut dkm = [0u8; 32];
        dkm.copy_from_slice(&data);
        Ok(dkm)
    }
}

pub fn delete_dkm() -> Result<()> {
    delete_named_dkm(ACCOUNT)
}

pub(super) fn delete_named_dkm(name: &str) -> Result<()> {
    #[cfg(feature = "macos-secure-enclave")]
    return super::macos_enclave::delete(name);
    #[cfg(not(feature = "macos-secure-enclave"))]
    {
        use security_framework::passwords::delete_generic_password;

        match delete_generic_password(SERVICE, name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound
            Err(e) => Err(IdentityError::DkmError(format!(
                "Keychain delete failed: {e}"
            ))),
        }
    }
}
