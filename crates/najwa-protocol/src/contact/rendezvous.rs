//! Rendezvous protocol for contact establishment via a shared phrase. Library
//! code only: no app or receive path calls it.
//!
//! Two users who share a secret phrase (exchanged out-of-band via voice,
//! paper, etc.) independently derive the same rendezvous point and exchange
//! handshake payloads.
//!
//! Flow:
//! 1. Both parties normalize the phrase and check entropy (≥60 bits)
//! 2. Argon2id (256 MiB) derives 160 bytes: rendezvous_id, deposit_cap, fetch_cap, envelope_secret, selector
//! 3. Both deposit their handshake payload to the same rendezvous mailbox
//! 4. Both poll for the counterparty's payload
//! 5. On receipt → mutual X3DH session initiation

use najwa_crypto::hash::sha256;
use najwa_crypto::kdf::{argon2id_variable, info_strings, Argon2Params};
use najwa_crypto::time::now;
use zeroize::Zeroizing;

use crate::mailbox::types::MailboxConfig;

/// Minimum estimated offline guessing work, in log2 guesses.
/// This is a model estimate, not a guarantee about an imported phrase's entropy.
pub const MIN_ENTROPY_BITS: u32 = 60;

/// Bound strength-estimation work before normalization or Argon2 allocation.
pub const MAX_PHRASE_BYTES: usize = 256;

/// Default rendezvous session expiration in seconds (24 hours).
pub const RENDEZVOUS_EXPIRY_SECS: u64 = 86400;

/// Errors during rendezvous operations.
#[derive(Debug, thiserror::Error)]
pub enum RendezvousError {
    #[error("rendezvous phrase exceeds {MAX_PHRASE_BYTES} bytes")]
    PhraseTooLong,
    /// Phrase is too weak (below minimum entropy).
    #[error("phrase too weak: {entropy_bits} bits < {}", MIN_ENTROPY_BITS)]
    WeakPhrase {
        /// Estimated entropy in bits.
        entropy_bits: u32,
    },

    /// No known mailboxes to use as rendezvous point.
    #[error("no known mailboxes for rendezvous")]
    NoMailboxes,

    /// Key derivation failed.
    #[error("key derivation error: {0}")]
    DerivationError(String),

    /// Mailbox operation failed.
    #[error("mailbox error: {0}")]
    MailboxError(String),
}

/// Argon2id parameters for rendezvous derivation.
/// 256 MiB memory, 4 iterations, 2 parallel lanes.
const RENDEZVOUS_ARGON2: Argon2Params = Argon2Params {
    memory_kib: 262144, // 256 MiB
    iterations: 4,
    parallelism: 2,
};

/// Total Argon2id output length: 160 bytes split into 5×32-byte components:
/// rendezvous_id, deposit_capability, fetch_capability,
/// envelope_secret, mailbox_selector.
const RENDEZVOUS_OUTPUT_LEN: usize = 160;

/// Rendezvous session derived from a shared phrase.
///
/// Both parties independently derive the same `rendezvous_id`,
/// `deposit_capability`, `fetch_capability`, and target mailbox
/// from the phrase alone via Argon2id with 256 MiB memory cost.
#[derive(Debug, Clone)]
pub struct RendezvousSession {
    /// Unique identifier for this rendezvous (32 bytes, Argon2id-derived).
    pub rendezvous_id: [u8; 32],
    /// Deposit capability for the rendezvous mailbox (32 bytes, Argon2id-derived).
    pub deposit_capability: [u8; 32],
    /// Fetch capability for the rendezvous mailbox (32 bytes, Argon2id-derived).
    pub fetch_capability: [u8; 32],
    /// Per-capability envelope secret for the rendezvous deposit capability
    /// (32 bytes, `output[96:128]`). Both parties derive it
    /// from the phrase; the deposited HandshakePayloads are envelope-encrypted
    /// under `HKDF(envelope_secret, "najwa/v1/deposit-envelope", "outer-key")`,
    /// so the mailbox server hosting the rendezvous CANNOT read the
    /// exchanged payloads. It MUST NEVER be sent to any server.
    pub envelope_secret: [u8; 32],
    /// Deterministically selected target mailbox.
    pub target_mailbox: MailboxConfig,
    /// Estimated entropy of the phrase in bits.
    pub phrase_entropy_bits: u32,
    /// Session creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Session expiration timestamp (Unix seconds).
    pub expires_at: u64,
}

impl RendezvousSession {
    /// Derive rendezvous parameters from a shared phrase.
    ///
    /// Both parties independently derive the same rendezvous_id,
    /// deposit_capability, fetch_capability, and target mailbox.
    ///
    /// **Derivation:**
    /// ```text
    /// salt = SHA256("najwa/v1/rendezvous-salt" || normalized)[0:32]
    /// output = Argon2id(normalized, salt, 262144 KiB, 4 iter, 2 parallel, 160 bytes)
    /// rendezvous_id      = output[0:32]
    /// deposit_capability  = output[32:64]
    /// fetch_capability    = output[64:96]
    /// envelope_secret     = output[96:128]  // NEVER sent to the server
    /// mailbox_selector    = output[128:160]
    /// ```
    ///
    /// # Errors
    ///
    /// - `WeakPhrase` if estimated entropy < 60 bits
    /// - `NoMailboxes` if `known_mailboxes` is empty
    /// - `DerivationError` if Argon2id fails
    pub fn from_phrase(
        phrase: &str,
        known_mailboxes: &[MailboxConfig],
    ) -> Result<Self, RendezvousError> {
        if known_mailboxes.is_empty() {
            return Err(RendezvousError::NoMailboxes);
        }
        if phrase.len() > MAX_PHRASE_BYTES {
            return Err(RendezvousError::PhraseTooLong);
        }

        // 1. Normalize phrase (lowercase, trim, collapse whitespace)
        let normalized = Zeroizing::new(normalize_phrase(phrase));

        // 2. Estimate entropy — minimum 60 bits to resist brute-force
        let entropy = estimate_entropy(&normalized);
        if entropy < MIN_ENTROPY_BITS {
            return Err(RendezvousError::WeakPhrase {
                entropy_bits: entropy,
            });
        }

        // 3. Derive salt: SHA256(RENDEZVOUS_SALT_PREFIX || normalized)[0:32]
        let mut salt_input = Zeroizing::new(Vec::with_capacity(
            info_strings::RENDEZVOUS_SALT_PREFIX.len() + normalized.len(),
        ));
        salt_input.extend_from_slice(info_strings::RENDEZVOUS_SALT_PREFIX);
        salt_input.extend_from_slice(normalized.as_bytes());
        let salt = sha256(&salt_input);

        // 4. Argon2id derivation: 256 MiB, 4 iterations, 2 parallel, 128-byte output
        let output = argon2id_variable(
            normalized.as_bytes(),
            &salt,
            &RENDEZVOUS_ARGON2,
            RENDEZVOUS_OUTPUT_LEN,
        )
        .map_err(|e| RendezvousError::DerivationError(e.to_string()))?;

        // 5. Split output: id(32) + deposit(32) + fetch(32) +
        //    envelope_secret(32) + mailbox_selector(32).
        let mut rendezvous_id = [0u8; 32];
        let mut deposit_cap = [0u8; 32];
        let mut fetch_cap = [0u8; 32];
        let mut envelope_secret = [0u8; 32];
        rendezvous_id.copy_from_slice(&output[0..32]);
        deposit_cap.copy_from_slice(&output[32..64]);
        fetch_cap.copy_from_slice(&output[64..96]);
        envelope_secret.copy_from_slice(&output[96..128]);

        // 6. Deterministic mailbox selection from mailbox_selector = output[128:160]
        //    (NOT the [96:128] envelope-secret region). Sort by onion
        //    address FIRST so both parties select the same mailbox regardless of
        //    their local list order; the index is mailbox_selector[0:8].
        let mut sorted = known_mailboxes.to_vec();
        sorted.sort_by(|a, b| a.onion_address.cmp(&b.onion_address));
        let mailbox_index = (u64::from_be_bytes(output[128..136].try_into().unwrap())
            % sorted.len() as u64) as usize;
        let target_mailbox = sorted[mailbox_index].clone();

        let ts = now();
        Ok(Self {
            rendezvous_id,
            deposit_capability: deposit_cap,
            fetch_capability: fetch_cap,
            envelope_secret,
            target_mailbox,
            phrase_entropy_bits: entropy,
            created_at: ts,
            expires_at: ts + RENDEZVOUS_EXPIRY_SECS,
        })
    }

    /// Check if this session has expired.
    pub fn is_expired(&self) -> bool {
        now() > self.expires_at
    }
}

/// Phrase strength assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseStrength {
    /// < 60 bits — too weak, reject.
    Weak,
    /// 60–63 estimated bits — acceptable.
    Moderate,
    /// At the estimator's 64-bit ceiling. Prefer generated phrases for actual
    /// randomness; this classification is not a 128-bit entropy guarantee.
    Strong,
}

/// Assess the strength of a rendezvous phrase.
pub fn assess_phrase(phrase: &str) -> PhraseStrength {
    if phrase.len() > MAX_PHRASE_BYTES {
        return PhraseStrength::Weak;
    }
    let entropy = estimate_entropy(&normalize_phrase(phrase));
    if entropy < MIN_ENTROPY_BITS {
        PhraseStrength::Weak
    } else if entropy < 64 {
        PhraseStrength::Moderate
    } else {
        PhraseStrength::Strong
    }
}

/// Normalize a phrase: lowercase, trim, collapse whitespace to single spaces.
pub fn normalize_phrase(phrase: &str) -> String {
    phrase
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Estimate the log2 offline guessing work using dictionary, repetition,
/// sequence and keyboard-pattern matching. This is a strength estimate, not
/// proof of Shannon entropy or of how an imported phrase was generated.
pub fn estimate_entropy(normalized_phrase: &str) -> u32 {
    if normalized_phrase.is_empty() || normalized_phrase.len() > MAX_PHRASE_BYTES {
        return 0;
    }
    let normalized = Zeroizing::new(normalize_phrase(normalized_phrase));
    // Word separators are predictable, not independent entropy. A phrase must
    // pass even when an attacker omits those separators from the search model.
    let compact = Zeroizing::new(normalized.split_whitespace().collect::<String>());
    let spaced = zxcvbn::zxcvbn(&normalized, &[]).guesses_log10();
    let compacted = zxcvbn::zxcvbn(&compact, &[]).guesses_log10();
    (spaced.min(compacted) * std::f64::consts::LOG2_10).floor() as u32
}

/// Generate a shareable phrase from 128 CSPRNG bits. Never derive this phrase
/// from identity recovery material. Import still applies the strength gate.
pub fn generate_phrase() -> Zeroizing<String> {
    loop {
        let entropy = Zeroizing::new(najwa_crypto::random::random_bytes::<16>());
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref()).expect("16-byte entropy");
        let phrase = Zeroizing::new(mnemonic.to_string());
        if estimate_entropy(&phrase) >= MIN_ENTROPY_BITS {
            return phrase;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mailboxes() -> Vec<MailboxConfig> {
        vec![
            MailboxConfig::new("mailbox1.onion".to_string(), [0xAA; 32], [0xBB; 32]),
            MailboxConfig::new("mailbox2.onion".to_string(), [0xCC; 32], [0xDD; 32]),
        ]
    }

    // -- Normalization --

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(
            normalize_phrase("  Purple Mountain  SUNSET  "),
            "purple mountain sunset"
        );
    }

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(
            normalize_phrase("one   two\tthree\nfour"),
            "one two three four"
        );
    }

    #[test]
    fn normalize_empty_phrase() {
        assert_eq!(normalize_phrase("  "), "");
    }

    // -- Entropy estimation --

    #[test]
    fn entropy_estimate_single_word() {
        assert!(estimate_entropy("hello") < MIN_ENTROPY_BITS);
    }

    #[test]
    fn entropy_estimate_four_words() {
        assert!(estimate_entropy("correct horse battery staple") < MIN_ENTROPY_BITS);
    }

    #[test]
    fn entropy_estimate_seven_words() {
        assert!(estimate_entropy("one two three four five six seven") < MIN_ENTROPY_BITS);
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(estimate_entropy(""), 0);
    }

    // -- Phrase strength --

    #[test]
    fn assess_weak_phrase() {
        // Familiar words are judged by the guessing model, not their count.
        assert_eq!(
            assess_phrase("correct horse battery staple"),
            PhraseStrength::Weak
        );
    }

    #[test]
    fn assess_moderate_phrase() {
        // Pattern-aware estimate at the admission boundary.
        assert_eq!(
            assess_phrase("correct horse battery staple plus"),
            PhraseStrength::Moderate
        );
    }

    #[test]
    fn assess_strong_phrase() {
        // The model reaches its ceiling on this longer input.
        assert_eq!(
            assess_phrase("one two three four five six seven eight nine"),
            PhraseStrength::Strong
        );
    }

    // -- Weak phrase rejection (< 60 bits) --

    #[test]
    fn weak_phrase_rejected() {
        let result = RendezvousSession::from_phrase("too short", &test_mailboxes());
        assert!(matches!(
            result,
            Err(RendezvousError::WeakPhrase { entropy_bits }) if entropy_bits < MIN_ENTROPY_BITS
        ));
    }

    #[test]
    fn four_word_phrase_rejected() {
        // Familiar words are judged by the guessing model, not their count.
        let result =
            RendezvousSession::from_phrase("correct horse battery staple", &test_mailboxes());
        assert!(matches!(
            result,
            Err(RendezvousError::WeakPhrase { entropy_bits }) if entropy_bits < MIN_ENTROPY_BITS
        ));
    }

    #[test]
    fn five_word_phrase_rejected() {
        // A predictable counting sequence is below the guessing-work threshold.
        let result = RendezvousSession::from_phrase("one two three four five", &test_mailboxes());
        assert!(matches!(
            result,
            Err(RendezvousError::WeakPhrase { entropy_bits }) if entropy_bits < MIN_ENTROPY_BITS
        ));
    }

    #[test]
    fn no_mailboxes_rejected() {
        let result = RendezvousSession::from_phrase("correct horse battery staple", &[]);
        assert!(matches!(result, Err(RendezvousError::NoMailboxes)));
    }

    // Use 7-word phrase (70 bits) for all derivation tests — above the 60-bit minimum.
    const TEST_PHRASE: &str = "purple mountain sunset golden river echo flame";
    const TEST_PHRASE_ALT: &str = "crystal forest midnight silver ocean breeze dawn";

    // -- Rendezvous derivation (both sides match) --

    #[test]
    fn both_sides_derive_same_rendezvous_id() {
        let mbs = test_mailboxes();

        let session_a = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        let session_b = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();

        assert_eq!(session_a.rendezvous_id, session_b.rendezvous_id);
        assert_eq!(session_a.deposit_capability, session_b.deposit_capability);
        assert_eq!(session_a.fetch_capability, session_b.fetch_capability);
        assert_eq!(
            session_a.target_mailbox.onion_address,
            session_b.target_mailbox.onion_address
        );
    }

    // Selection is order-independent — two parties holding the same
    // mailboxes in different local order MUST pick the same mailbox.
    #[test]
    fn mailbox_selection_is_order_independent() {
        let mbs_a = test_mailboxes();
        let mut mbs_b = test_mailboxes();
        mbs_b.reverse();

        let a = RendezvousSession::from_phrase(TEST_PHRASE, &mbs_a).unwrap();
        let b = RendezvousSession::from_phrase(TEST_PHRASE, &mbs_b).unwrap();

        assert_eq!(
            a.target_mailbox.onion_address,
            b.target_mailbox.onion_address
        );
    }

    #[test]
    fn normalization_makes_phrases_equivalent() {
        let mbs = test_mailboxes();

        let s1 =
            RendezvousSession::from_phrase("Purple Mountain Sunset Golden River Echo Flame", &mbs)
                .unwrap();
        let s2 = RendezvousSession::from_phrase(
            "  purple  mountain  sunset  golden  river  echo  flame  ",
            &mbs,
        )
        .unwrap();

        assert_eq!(s1.rendezvous_id, s2.rendezvous_id);
        assert_eq!(s1.deposit_capability, s2.deposit_capability);
        assert_eq!(s1.fetch_capability, s2.fetch_capability);
    }

    #[test]
    fn different_phrases_produce_different_ids() {
        let mbs = test_mailboxes();

        let s1 = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        let s2 = RendezvousSession::from_phrase(TEST_PHRASE_ALT, &mbs).unwrap();

        assert_ne!(s1.rendezvous_id, s2.rendezvous_id);
        assert_ne!(s1.deposit_capability, s2.deposit_capability);
    }

    #[test]
    fn session_has_24h_expiry() {
        let mbs = test_mailboxes();
        let session = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();

        assert_eq!(
            session.expires_at - session.created_at,
            RENDEZVOUS_EXPIRY_SECS
        );
        assert!(!session.is_expired());
    }

    #[test]
    fn session_entropy_tracked() {
        let mbs = test_mailboxes();
        let session = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        assert!(session.phrase_entropy_bits >= MIN_ENTROPY_BITS);
        assert!(session.phrase_entropy_bits <= 64); // estimator ceiling, not word-count entropy
    }

    #[test]
    fn deterministic_mailbox_selection() {
        let mbs = test_mailboxes();

        let s1 = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        let s2 = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        assert_eq!(
            s1.target_mailbox.onion_address,
            s2.target_mailbox.onion_address
        );
    }

    #[test]
    fn single_mailbox_always_selected() {
        let mbs = vec![MailboxConfig::new(
            "only.onion".to_string(),
            [0x11; 32],
            [0x22; 32],
        )];

        let session = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        assert_eq!(session.target_mailbox.onion_address, "only.onion");
    }

    #[test]
    fn fetch_capability_is_derived() {
        let mbs = test_mailboxes();
        let session = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        // fetch_capability must be non-zero and different from deposit
        assert_ne!(session.fetch_capability, [0u8; 32]);
        assert_ne!(session.fetch_capability, session.deposit_capability);
    }

    #[test]
    fn envelope_secret_is_derived_and_distinct() {
        // envelope_secret = output[96:128] — both sides derive the
        // same value (so deposits are envelope-encrypted), and it is distinct
        // from every other derived region.
        let mbs = test_mailboxes();
        let a = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        let b = RendezvousSession::from_phrase(TEST_PHRASE, &mbs).unwrap();
        assert_eq!(a.envelope_secret, b.envelope_secret);
        assert_ne!(a.envelope_secret, [0u8; 32]);
        assert_ne!(a.envelope_secret, a.rendezvous_id);
        assert_ne!(a.envelope_secret, a.deposit_capability);
        assert_ne!(a.envelope_secret, a.fetch_capability);
        // A different phrase yields a different envelope_secret.
        let c = RendezvousSession::from_phrase(TEST_PHRASE_ALT, &mbs).unwrap();
        assert_ne!(a.envelope_secret, c.envelope_secret);
    }
}
