//! Onion address pinning — trust-on-first-use.

use async_trait::async_trait;
use najwa_crypto::hash::sha256;
use najwa_crypto::time::now;
use serde::{Deserialize, Serialize};

use super::error::{MailboxError, Result};
use super::types::PinVerification;

/// A pinned onion address record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPin {
    /// The onion address (without `.onion` suffix).
    pub onion_address: String,
    /// Unix timestamp when this address was first seen.
    pub first_seen: u64,
    /// Unix timestamp when the pin was last verified.
    pub last_verified: u64,
    /// SHA-256 of the onion address bytes.
    pub pin_hash: [u8; 32],
}

/// Storage abstraction for onion address pins.
///
/// Implementations persist pins across sessions (e.g. via `najwa-storage`).
#[async_trait]
pub trait PinStore: Send + Sync {
    /// Retrieve a stored pin for the given onion address, if any.
    async fn get_onion_pin(&self, onion_address: &str) -> Result<Option<OnionPin>>;

    /// Persist a new or updated pin.
    async fn save_onion_pin(&self, pin: &OnionPin) -> Result<()>;
}

/// Verify the onion address pin.
///
/// - **First use**: creates and persists a new pin, returns `FirstUse`.
/// - **Pin matches**: updates `last_verified`, returns `Verified`.
/// - **Pin changed**: returns `Changed` with the original `first_seen`.
pub async fn verify_pin(store: &dyn PinStore, onion_address: &str) -> Result<PinVerification> {
    let current_hash = sha256(onion_address.as_bytes());

    match store.get_onion_pin(onion_address).await? {
        None => {
            // First connection — pin it
            let pin = OnionPin {
                onion_address: onion_address.to_string(),
                first_seen: now(),
                last_verified: now(),
                pin_hash: current_hash,
            };
            store.save_onion_pin(&pin).await?;
            Ok(PinVerification::FirstUse)
        }
        Some(existing) => {
            if existing.pin_hash == current_hash {
                // Pin matches — update last_verified
                let updated = OnionPin {
                    last_verified: now(),
                    ..existing
                };
                store.save_onion_pin(&updated).await?;
                Ok(PinVerification::Verified)
            } else {
                // Pin changed — possible MITM
                Ok(PinVerification::Changed {
                    first_seen: existing.first_seen,
                })
            }
        }
    }
}

/// Check a pin and return an error if it has changed.
///
/// Convenience wrapper around [`verify_pin`] that converts a `Changed`
/// result into `MailboxError::PinChanged`.
pub async fn require_pin_valid(
    store: &dyn PinStore,
    onion_address: &str,
) -> Result<PinVerification> {
    let result = verify_pin(store, onion_address).await?;
    if let PinVerification::Changed { first_seen } = &result {
        return Err(MailboxError::PinChanged {
            first_seen: *first_seen,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// In-memory pin store for testing.
    struct MemoryPinStore {
        pins: Mutex<HashMap<String, OnionPin>>,
    }

    impl MemoryPinStore {
        fn new() -> Self {
            Self {
                pins: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl PinStore for MemoryPinStore {
        async fn get_onion_pin(&self, onion_address: &str) -> Result<Option<OnionPin>> {
            Ok(self.pins.lock().await.get(onion_address).cloned())
        }

        async fn save_onion_pin(&self, pin: &OnionPin) -> Result<()> {
            self.pins
                .lock()
                .await
                .insert(pin.onion_address.clone(), pin.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn first_use_creates_pin() {
        let store = MemoryPinStore::new();
        let result = verify_pin(&store, "abc123def456").await.unwrap();
        assert_eq!(result, PinVerification::FirstUse);

        // Pin should now exist
        let pin = store.get_onion_pin("abc123def456").await.unwrap().unwrap();
        assert_eq!(pin.onion_address, "abc123def456");
        assert_eq!(pin.pin_hash, sha256(b"abc123def456"));
    }

    #[tokio::test]
    async fn second_use_verifies_pin() {
        let store = MemoryPinStore::new();

        // First use
        let r1 = verify_pin(&store, "abc123def456").await.unwrap();
        assert_eq!(r1, PinVerification::FirstUse);

        // Second use — should be verified
        let r2 = verify_pin(&store, "abc123def456").await.unwrap();
        assert_eq!(r2, PinVerification::Verified);
    }

    #[tokio::test]
    async fn changed_pin_detected() {
        let store = MemoryPinStore::new();

        // Pin an address
        let pin = OnionPin {
            onion_address: "abc123def456".to_string(),
            first_seen: 1000,
            last_verified: 1000,
            pin_hash: [0xFF; 32], // Wrong hash — simulates changed address
        };
        store.save_onion_pin(&pin).await.unwrap();

        // Verify should detect change
        let result = verify_pin(&store, "abc123def456").await.unwrap();
        assert_eq!(result, PinVerification::Changed { first_seen: 1000 });
    }

    #[tokio::test]
    async fn require_pin_valid_errors_on_change() {
        let store = MemoryPinStore::new();

        // Insert a pin with wrong hash
        let pin = OnionPin {
            onion_address: "abc123def456".to_string(),
            first_seen: 2000,
            last_verified: 2000,
            pin_hash: [0x00; 32],
        };
        store.save_onion_pin(&pin).await.unwrap();

        let result = require_pin_valid(&store, "abc123def456").await;
        assert!(matches!(
            result,
            Err(MailboxError::PinChanged { first_seen: 2000 })
        ));
    }

    #[tokio::test]
    async fn require_pin_valid_ok_on_first_use() {
        let store = MemoryPinStore::new();
        let result = require_pin_valid(&store, "newaddress").await.unwrap();
        assert_eq!(result, PinVerification::FirstUse);
    }
}
