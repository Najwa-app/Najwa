//! NFC/BLE proximity exchange stubs. Library code; no app path uses it.
//!
//! Provides trait definitions for proximity-based contact exchange.
//! Actual implementations require platform-specific native bridges:
//! - **Android:** NFC via `android.nfc` + BLE via `android.bluetooth.le`
//! - **iOS:** Core NFC + Core Bluetooth
//!
//! These are stubs — real implementations will be in the native bridge layer.

/// Errors during proximity exchange.
#[derive(Debug, thiserror::Error)]
pub enum ProximityError {
    /// NFC/BLE hardware not available.
    #[error("proximity hardware not available")]
    NotAvailable,

    /// Exchange timed out.
    #[error("proximity exchange timed out")]
    Timeout,

    /// Peer payload was invalid.
    #[error("invalid peer payload: {0}")]
    InvalidPayload(String),

    /// Platform-specific error.
    #[error("platform error: {0}")]
    PlatformError(String),
}

/// Trait for proximity-based contact exchange.
///
/// Implementations live in the native bridge layer (Android/iOS).
/// This trait defines the interface for the protocol crate.
#[async_trait::async_trait]
pub trait ProximityExchange: Send + Sync {
    /// Start advertising our handshake payload via NFC/BLE.
    async fn start_advertising(&self, payload_bytes: &[u8]) -> Result<(), ProximityError>;

    /// Start scanning for nearby handshake payloads.
    async fn start_scanning(&self) -> Result<(), ProximityError>;

    /// Stop advertising/scanning.
    async fn stop(&self);

    /// Wait for a peer's payload to be received.
    ///
    /// Returns the raw bytes of the peer's handshake payload.
    async fn receive_payload(&self) -> Result<Vec<u8>, ProximityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proximity_error_display() {
        let e = ProximityError::NotAvailable;
        assert_eq!(e.to_string(), "proximity hardware not available");
    }

    #[test]
    fn timeout_error_display() {
        let e = ProximityError::Timeout;
        assert_eq!(e.to_string(), "proximity exchange timed out");
    }
}
