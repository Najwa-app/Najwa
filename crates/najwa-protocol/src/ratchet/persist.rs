//! Bincode serialization of ratchet state, used by test storage. The app
//! persists the state as table columns (S06 §3.10).

use super::error::{RatchetError, Result};
use super::state::RatchetState;

/// Serialize ratchet state with bincode. Test storage uses this; the app
/// persists the state as table columns (S06 §3.10).
///
/// Uses bincode for compact binary serialization.
/// The `skipped` HashMap is NOT included (marked `#[serde(skip)]`).
/// Skipped keys must be persisted separately via the `skipped_keys` SQL table.
pub fn serialize_state(state: &RatchetState) -> Result<Vec<u8>> {
    bincode::serialize(state).map_err(|_| RatchetError::CorruptedState)
}

/// Deserialize ratchet state produced by [`serialize_state`].
///
/// After deserialization, the `skipped` HashMap will be empty.
/// The caller must load skipped keys from the `skipped_keys` SQL table
/// and insert them into the returned state.
pub fn deserialize_state(data: &[u8]) -> Result<RatchetState> {
    use bincode::Options;
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(512)
        .reject_trailing_bytes().deserialize(data).map_err(|_| RatchetError::CorruptedState)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::init::init_bob;
    use najwa_crypto::keys::x25519::X25519KeyPair;

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();
        let spk = X25519KeyPair::generate(&mut rng);
        let sk = [0x42u8; 32];
        let state = init_bob(&sk, spk);

        let data = serialize_state(&state).unwrap();
        let restored = deserialize_state(&data).unwrap();

        assert_eq!(restored.rk, state.rk);
        assert_eq!(restored.ns, state.ns);
        assert_eq!(restored.nr, state.nr);
        assert_eq!(restored.pn, state.pn);
        assert!(restored.skipped.is_empty());
    }

    #[test]
    fn corrupted_data_rejected() {
        let result = deserialize_state(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }
}
