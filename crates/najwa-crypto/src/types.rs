//! Cryptographic type aliases (S01 §3).
//!
//! Only protocol-level cryptographic types live here.
//! Database row IDs and storage types belong in `najwa-storage`.

/// Unix timestamp in seconds.
pub type Timestamp = u64;

/// Prekey identifier (4 bytes, S06 §4).
pub type PrekeyId = [u8; 4];

/// Message UUID (16 bytes / 128-bit, S07 §4).
pub type MsgUuid = [u8; 16];
