//! Key types and generation for Ed25519 and X25519.

pub mod conversion;
pub mod ed25519;
pub mod x25519;

pub use conversion::{ed25519_priv_to_x25519, ed25519_pub_to_x25519};
pub use ed25519::{Ed25519KeyPair, Ed25519Private, Ed25519Public, Ed25519Signature};
pub use x25519::{X25519KeyPair, X25519Private, X25519Public, X25519SharedSecret};
