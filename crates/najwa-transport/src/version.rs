//! Version fingerprinting prevention (S04 §8).
//!
//! Ensures no client version information leaks in protocol messages
//! or HTTP headers. The update-check helpers below need an explicitly
//! configured onion endpoint; the desktop application configures none and
//! performs no network update check (S04 §8).

use serde::{Deserialize, Serialize};

/// Distribution channel of a build, used by the update-check helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DistributionChannel {
    /// Google Play / Apple App Store — updates via store.
    AppStore,
    /// F-Droid — updates via F-Droid.
    FDroid,
    /// Direct download / sideloaded — Tor-based update check.
    #[default]
    Direct,
}

/// Information about an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    /// Latest available version string.
    pub version: String,
    /// Whether this update is mandatory (security fix).
    pub mandatory: bool,
    /// Release notes URL (`.onion` address).
    pub release_notes_url: Option<String>,
}

/// Errors during update checking.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Transport error during update check.
    #[error("transport error: {0}")]
    TransportError(String),

    /// Failed to parse update response.
    #[error("parse error: {0}")]
    ParseError(String),
}

/// Update checker with distribution channel awareness. Not used by the
/// desktop application.
///
/// - AppStore/FDroid: updates handled by the store (no check needed)
/// - Direct: checks for updates via Tor to avoid version fingerprinting
pub struct UpdateChecker {
    /// The distribution channel of this build.
    distribution: DistributionChannel,
    update_url: Option<String>,
}

impl UpdateChecker {
    /// Create a new update checker for the given distribution channel.
    pub fn new(distribution: DistributionChannel) -> Self {
        Self {
            distribution,
            update_url: None,
        }
    }

    /// Configure the deployment's real update endpoint. There is no fabricated
    /// default service: direct builds without an endpoint remain unconfigured.
    pub fn with_update_url(
        distribution: DistributionChannel,
        url: String,
    ) -> Result<Self, UpdateError> {
        crate::http::validate_onion_url(&url)
            .map_err(|e| UpdateError::ParseError(e.to_string()))?;
        Ok(Self {
            distribution,
            update_url: Some(url),
        })
    }

    /// Get the distribution channel.
    pub fn distribution(&self) -> DistributionChannel {
        self.distribution
    }

    /// Check if an update check is needed for this distribution channel.
    ///
    /// Returns `false` for AppStore/FDroid (handled by the store),
    /// `true` for Direct builds with an explicitly configured onion endpoint.
    pub fn needs_update_check(&self) -> bool {
        matches!(self.distribution, DistributionChannel::Direct) && self.update_url.is_some()
    }

    /// Get the Tor-routed update check URL for direct builds.
    ///
    /// Returns `None` for AppStore/FDroid and unconfigured Direct builds.
    pub fn update_check_url(&self) -> Option<&str> {
        match self.distribution {
            DistributionChannel::Direct => self.update_url.as_deref(),
            _ => None,
        }
    }
}

/// Headers that MUST NOT be present in any protocol message (S04 §5.2, §8).
///
/// These are the headers that would leak version information.
/// The transport layer's header stripping (S04 §5.2) already prevents
/// these from being sent, but this list serves as documentation and
/// test verification.
pub const FORBIDDEN_HEADERS: &[&str] = &[
    "user-agent",
    "x-client-version",
    "x-app-version",
    "x-najwa-version",
    "server",
];

/// Verify that no version information leaks in a set of HTTP headers.
///
/// Returns a list of forbidden headers that were found.
pub fn check_headers_for_version_leak(headers: &[(String, String)]) -> Vec<String> {
    let mut leaks = Vec::new();
    for (key, _value) in headers {
        let lower = key.to_lowercase();
        if FORBIDDEN_HEADERS.contains(&lower.as_str()) {
            leaks.push(key.clone());
        }
    }
    leaks
}

/// Verify that no version information is present in a protocol message body.
///
/// Checks for common patterns that would leak the client version.
pub fn verify_no_version_in_body(body: &[u8]) -> bool {
    // Check for common version-leaking JSON patterns
    let body_str = String::from_utf8_lossy(body).to_lowercase();

    let leak_patterns = [
        "\"client_version\"",
        "\"app_version\"",
        "\"user_agent\"",
        "\"x-client-version\"",
    ];

    for pattern in &leak_patterns {
        if body_str.contains(pattern) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_distribution_is_direct() {
        assert_eq!(DistributionChannel::default(), DistributionChannel::Direct);
    }

    #[test]
    fn app_store_does_not_need_check() {
        let checker = UpdateChecker::new(DistributionChannel::AppStore);
        assert!(!checker.needs_update_check());
        assert!(checker.update_check_url().is_none());
    }

    #[test]
    fn fdroid_does_not_need_check() {
        let checker = UpdateChecker::new(DistributionChannel::FDroid);
        assert!(!checker.needs_update_check());
        assert!(checker.update_check_url().is_none());
    }

    #[test]
    fn direct_needs_tor_check() {
        let checker = UpdateChecker::with_update_url(
            DistributionChannel::Direct,
            format!("http://{}.onion/v1/latest", "a".repeat(56)),
        )
        .unwrap();
        assert!(checker.needs_update_check());
        let url = checker.update_check_url().unwrap();
        assert!(url.contains(".onion"));
    }

    #[test]
    fn no_version_leak_clean_headers() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), "example.onion".to_string()),
        ];
        let leaks = check_headers_for_version_leak(&headers);
        assert!(leaks.is_empty());
    }

    #[test]
    fn detects_user_agent_leak() {
        let headers = vec![
            ("User-Agent".to_string(), "Najwa/1.0".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let leaks = check_headers_for_version_leak(&headers);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0], "User-Agent");
    }

    #[test]
    fn detects_version_header_leak() {
        let headers = vec![("X-Client-Version".to_string(), "2.1.0".to_string())];
        let leaks = check_headers_for_version_leak(&headers);
        assert_eq!(leaks.len(), 1);
    }

    #[test]
    fn detects_multiple_leaks() {
        let headers = vec![
            ("User-Agent".to_string(), "Najwa/1.0".to_string()),
            ("X-Client-Version".to_string(), "1.0".to_string()),
            ("X-App-Version".to_string(), "1.0".to_string()),
        ];
        let leaks = check_headers_for_version_leak(&headers);
        assert_eq!(leaks.len(), 3);
    }

    #[test]
    fn no_version_in_clean_body() {
        let body = br#"{"message":"hello","timestamp":12345}"#;
        assert!(verify_no_version_in_body(body));
    }

    #[test]
    fn detects_version_in_body() {
        let body = br#"{"client_version":"1.0.0","data":"test"}"#;
        assert!(!verify_no_version_in_body(body));
    }

    #[test]
    fn forbidden_headers_list_is_complete() {
        assert!(FORBIDDEN_HEADERS.contains(&"user-agent"));
        assert!(FORBIDDEN_HEADERS.contains(&"x-client-version"));
        assert!(FORBIDDEN_HEADERS.contains(&"x-app-version"));
    }

    #[test]
    fn update_info_structure() {
        let info = UpdateInfo {
            version: "2.0.0".to_string(),
            mandatory: true,
            release_notes_url: Some("http://najwa.onion/notes".to_string()),
        };
        assert_eq!(info.version, "2.0.0");
        assert!(info.mandatory);
        assert!(info.release_notes_url.is_some());
    }

    #[test]
    fn distribution_channel_getter() {
        let checker = UpdateChecker::new(DistributionChannel::FDroid);
        assert_eq!(checker.distribution(), DistributionChannel::FDroid);
    }
}
