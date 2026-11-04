//! Durable recovery obligation, shared by identity installation and messaging.
//! Identity records and the encrypted database belong in the same data directory.
use crate::{
    atomic::{atomic_write, read_record_file},
    error::{IdentityError, Result},
};
use std::path::{Path, PathBuf};

fn path(directory: &Path, identity: &[u8; 32]) -> PathBuf {
    let key: String = identity.iter().map(|b| format!("{b:02x}")).collect();
    directory.join(format!("prekey-recovery-{key}"))
}

/// Publish before installing recovered key material. On interruption this may
/// conservatively require rotation for the old record, never accept stale keys.
pub(crate) fn require(directory: &Path, identity: &[u8; 32]) -> Result<()> {
    atomic_write(
        &path(directory, identity),
        &najwa_crypto::random::random_bytes::<32>(),
    )
}

/// The marker remains after completion: SQLCipher records the completed generation.
/// Password changes and restarts therefore cannot erase an outstanding obligation.
pub fn generation(directory: &Path, identity: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    read_record_file(&path(directory, identity))?
        .map(|bytes| {
            bytes.try_into().map_err(|_| {
                IdentityError::AtomicWriteFailed("invalid prekey recovery generation".into())
            })
        })
        .transpose()
}
