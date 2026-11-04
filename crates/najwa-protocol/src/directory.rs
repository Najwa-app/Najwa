//! Signed server directory primitives. No release component publishes or
//! fetches a directory; the app path does not use this module.
//!
//! The server directory is a list of known mailbox servers with their
//! onion addresses, operator attestations, and status. It is signed
//! by a 2-of-3 threshold of directory authorities to prevent any
//! single entity from controlling the server list.

use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::time::now;
use serde::{Deserialize, Serialize};

/// Number of directory authority keys required for a valid directory signature.
pub const DIRECTORY_THRESHOLD: usize = 2;

/// Total number of directory authority keys.
pub const DIRECTORY_AUTHORITY_COUNT: usize = 3;

/// Maximum age of a directory before it's considered stale (24 hours).
pub const DIRECTORY_MAX_AGE_SECS: u64 = 86_400;

/// A single server entry in the directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Onion address of the mailbox server.
    pub onion_address: String,
    /// Operator identifier (human-readable).
    pub operator_id: String,
    /// Jurisdiction / country code.
    pub jurisdiction: String,
    /// Server status.
    pub status: ServerStatus,
    /// Unix timestamp when this entry was last verified.
    pub last_verified: u64,
}

/// Server status in the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerStatus {
    /// Server is active and accepting registrations.
    Active,
    /// Server is retiring — no new registrations, still serving existing.
    Retiring,
    /// Server is read-only — no new deposits, fetch-only.
    ReadOnly,
    /// Server has been removed from the directory.
    Removed,
}

/// A signed server directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectory {
    /// Directory version (monotonically increasing).
    pub version: u64,
    /// Unix timestamp when this directory was created.
    pub created_at: u64,
    /// List of server entries.
    pub servers: Vec<DirectoryEntry>,
    /// Signatures from directory authorities (2-of-3 threshold).
    pub signatures: Vec<DirectorySignature>,
}

/// A single authority's signature over the directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySignature {
    /// Which authority key signed this (index 0-2).
    pub authority_index: u8,
    /// The authority's public key (32 bytes).
    pub authority_pub: [u8; 32],
    /// Ed25519 signature over the canonical directory bytes (64 bytes).
    pub signature: Vec<u8>,
}

impl SignedDirectory {
    /// Check if the directory has enough valid signatures (2-of-3 threshold).
    pub fn verify(&self, authority_keys: &[Ed25519Public]) -> Result<(), String> {
        if authority_keys.len() != DIRECTORY_AUTHORITY_COUNT {
            return Err(format!(
                "need {} authority keys, got {}",
                DIRECTORY_AUTHORITY_COUNT,
                authority_keys.len()
            ));
        }

        // The trust set itself must contain three independent identities.
        for (i, key) in authority_keys.iter().enumerate() {
            if authority_keys[..i]
                .iter()
                .any(|other| other.to_bytes() == key.to_bytes())
            {
                return Err("duplicate directory authority key".into());
            }
        }
        let canonical = self.canonical_bytes();
        let mut valid_count = 0usize;
        let mut counted = [false; DIRECTORY_AUTHORITY_COUNT];

        for dir_sig in &self.signatures {
            let idx = dir_sig.authority_index as usize;
            if idx >= authority_keys.len() || counted[idx] {
                continue;
            }
            if dir_sig.authority_pub != authority_keys[idx].to_bytes() {
                continue;
            }
            let sig_arr: [u8; 64] = match dir_sig.signature.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let sig = match Ed25519Signature::from_bytes(&sig_arr) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if authority_keys[idx].verify(&canonical, &sig).is_ok() {
                counted[idx] = true;
                valid_count += 1;
            }
        }

        if valid_count >= DIRECTORY_THRESHOLD {
            Ok(())
        } else {
            Err(format!(
                "insufficient valid signatures: {} < {}",
                valid_count, DIRECTORY_THRESHOLD
            ))
        }
    }

    /// Check if the directory is stale (older than DIRECTORY_MAX_AGE_SECS).
    pub fn is_stale(&self) -> bool {
        self.is_stale_at(now())
    }

    /// Reject old directories and timestamps beyond the allowed clock skew.
    pub fn is_stale_at(&self, timestamp: u64) -> bool {
        match timestamp.checked_sub(self.created_at) {
            Some(age) => age > DIRECTORY_MAX_AGE_SECS,
            None => {
                self.created_at - timestamp > najwa_crypto::time::TIMESTAMP_TOLERANCE_NORMAL_SECS
            }
        }
    }

    /// Consistency check: verify version is strictly greater than `known_version`.
    pub fn is_newer_than(&self, known_version: u64) -> bool {
        self.version > known_version
    }

    /// Get the canonical bytes for signing (everything except signatures).
    fn canonical_bytes(&self) -> Vec<u8> {
        // Version this representation: old signatures did not authenticate
        // operator/jurisdiction metadata. No legacy verification fallback.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"najwa/v2/server-directory/");
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf.extend_from_slice(&(self.servers.len() as u32).to_be_bytes());
        for server in &self.servers {
            let onion_bytes = server.onion_address.as_bytes();
            buf.extend_from_slice(&(onion_bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(onion_bytes);
            for metadata in [&server.operator_id, &server.jurisdiction] {
                buf.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
                buf.extend_from_slice(metadata.as_bytes());
            }
            buf.push(server.status as u8);
            buf.extend_from_slice(&server.last_verified.to_be_bytes());
        }
        buf
    }

    /// Sign this directory with an authority key. Returns the signature entry.
    pub fn sign(&self, authority_index: u8, authority_key: &Ed25519KeyPair) -> DirectorySignature {
        let canonical = self.canonical_bytes();
        let sig = authority_key.sign(&canonical);
        DirectorySignature {
            authority_index,
            authority_pub: authority_key.public().to_bytes(),
            signature: sig.to_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authorities() -> Vec<Ed25519KeyPair> {
        vec![
            Ed25519KeyPair::from_seed(&[0x01; 32]),
            Ed25519KeyPair::from_seed(&[0x02; 32]),
            Ed25519KeyPair::from_seed(&[0x03; 32]),
        ]
    }

    fn make_directory() -> SignedDirectory {
        SignedDirectory {
            version: 1,
            created_at: now(),
            servers: vec![DirectoryEntry {
                onion_address: "test.onion".into(),
                operator_id: "operator1".into(),
                jurisdiction: "CH".into(),
                status: ServerStatus::Active,
                last_verified: now(),
            }],
            signatures: Vec::new(),
        }
    }

    #[test]
    fn directory_2_of_3_threshold_passes() {
        let authorities = make_authorities();
        let mut dir = make_directory();

        // Sign with 2 of 3 authorities
        dir.signatures.push(dir.sign(0, &authorities[0]));
        dir.signatures.push(dir.sign(1, &authorities[1]));

        let pub_keys: Vec<Ed25519Public> = authorities.iter().map(|k| k.public().clone()).collect();
        assert!(dir.verify(&pub_keys).is_ok());
    }

    #[test]
    fn directory_1_of_3_threshold_fails() {
        let authorities = make_authorities();
        let mut dir = make_directory();

        // Only 1 signature — below threshold
        dir.signatures.push(dir.sign(0, &authorities[0]));

        let pub_keys: Vec<Ed25519Public> = authorities.iter().map(|k| k.public().clone()).collect();
        assert!(dir.verify(&pub_keys).is_err());
    }

    #[test]
    fn directory_version_check() {
        let dir = make_directory();
        assert!(dir.is_newer_than(0));
        assert!(!dir.is_newer_than(1));
        assert!(!dir.is_newer_than(2));
    }
}
