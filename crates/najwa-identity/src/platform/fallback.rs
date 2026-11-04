//! Fallback DKM storage for unsupported platforms (Android, iOS, etc.).
//!
//! Returns errors for all operations. Mobile platforms will get proper
//! implementations in later phases via JNI (Android) or C FFI (iOS).

use crate::error::{IdentityError, Result};

pub fn store_dkm(_dkm: &[u8; 32]) -> Result<()> {
    Err(IdentityError::DkmError(
        "DKM storage not supported on this platform".into(),
    ))
}

pub fn retrieve_dkm() -> Result<[u8; 32]> {
    Err(IdentityError::DkmError(
        "DKM retrieval not supported on this platform".into(),
    ))
}

pub fn delete_dkm() -> Result<()> {
    Err(IdentityError::DkmError(
        "DKM deletion not supported on this platform".into(),
    ))
}
