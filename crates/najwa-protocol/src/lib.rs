//! Protocol logic for one-to-one Najwa conversations.
//!
//! Provides:
//! - Mailbox protocol client (S16)
//! - X3DH key agreement and prekey management (S06 §2, §5)
//! - Double Ratchet (S06 §3)
//! - Message format and encryption (S07)
//! - Pairwise pseudonyms (S01 §8)
//! - Contact establishment and safety numbers (S05)
//! - Contact introduction payloads (S05 §11)
//!
//! `contact::rendezvous`, `directory` and `pseudonym::group` are library code
//! that neither the app nor the receive path uses.

pub mod contact;
pub mod directory;
pub mod mailbox;
pub mod message;
pub mod prekey;
pub mod pseudonym;
pub mod ratchet;
pub mod x3dh;
