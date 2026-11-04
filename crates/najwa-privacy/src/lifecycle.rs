//! Account lifecycle: local profile erasure (`emergency`, S13 §10) and its
//! file-erasure helpers (`deletion`). The application does not use `autolock`,
//! `verification` or `deletion::delete_account`.

pub mod autolock;
pub mod deletion;
pub mod emergency;
pub mod verification;
