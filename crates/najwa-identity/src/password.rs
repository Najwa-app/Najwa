//! Password normalization and validation.
//!
//! All passwords are normalized to Unicode NFC form before use
//! to prevent encoding-dependent key derivation differences.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{IdentityError, Result};

/// S02 §11.1 rule for every new passphrase (creation, change, recovery,
/// restore): 12 characters to 1024 bytes, and a zxcvbn estimate of at least
/// 2^40 guesses both as typed and with whitespace removed (an attacker can
/// omit word separators). Unlock never applies it, so an identity created
/// under an earlier rule still opens. Confirmation is the caller's concern.
pub fn validate_new_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < 12 {
        return Err(IdentityError::PasswordTooShort(12));
    }
    if passphrase.len() > 1024 {
        return Err(IdentityError::PasswordTooLong(1024));
    }
    let compact = Zeroizing::new(passphrase.split_whitespace().collect::<String>());
    let weakest = [zxcvbn::zxcvbn(passphrase, &[]), zxcvbn::zxcvbn(&compact, &[])]
        .into_iter()
        .min_by(|a, b| a.guesses_log10().total_cmp(&b.guesses_log10()))
        .unwrap();
    if weakest.guesses_log10() * std::f64::consts::LOG2_10 >= 40.0 {
        return Ok(());
    }
    Err(IdentityError::WeakPassphrase {
        hint: weakest.feedback().and_then(|f| f.warning()).map(|w| w.to_string()),
    })
}

/// Normalize a password to NFC form and return as UTF-8 bytes.
///
/// # Errors
///
/// Returns [`IdentityError::EmptyPassword`] if the password is empty.
pub fn normalize_password(password: &str) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(IdentityError::EmptyPassword);
    }
    let normalized: String = password.nfc().collect();
    Ok(normalized.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ascii() {
        let pw = normalize_password("hello123").unwrap();
        assert_eq!(pw, b"hello123");
    }

    #[test]
    fn normalize_empty_fails() {
        assert!(normalize_password("").is_err());
    }

    #[test]
    fn normalize_unicode_nfc() {
        // é can be represented as U+00E9 (precomposed) or U+0065 U+0301 (decomposed)
        let precomposed = "\u{00E9}";
        let decomposed = "\u{0065}\u{0301}";
        let a = normalize_password(precomposed).unwrap();
        let b = normalize_password(decomposed).unwrap();
        assert_eq!(a, b, "NFC normalization should produce identical bytes");
    }

    #[test]
    fn normalize_preserves_utf8() {
        let pw = normalize_password("пароль🔑").unwrap();
        assert_eq!(pw, "пароль🔑".as_bytes());
    }
}
