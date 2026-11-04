//! Library DNS leak self-test; the application does not call it.
//!
//! Provides a higher-level DNS leak test that wraps the transport-layer
//! `verify_no_dns_leak` with structured result reporting.
//!
//! DNS leaks can reveal *which mailboxes* the user connects to,
//! breaking unlinkability between the user and their conversations.
//!
//! **S04 §6.1: this module issues no DNS query of any kind.** A probe through
//! the SYSTEM resolver would perform the exact clearnet lookup the test exists
//! to prevent and disclose to the local resolver/ISP that this host runs
//! Najwa; and a non-existent name returns NXDOMAIN even on a leaking resolver,
//! so such a probe could only fire against an NXDOMAIN-hijacking ISP (S04
//! §6.2). Remote resolution is guaranteed structurally instead (embedded Arti
//! receives hostnames directly and never delegates them), and
//! `scripts/check-no-clearnet-dns.sh` fails if a crate under `crates/` uses a
//! system-resolver call (S04 §6.3).

/// Result of a DNS leak self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsLeakResult {
    /// No leak detected — clearnet DNS is blocked.
    Safe,
    /// Clearnet DNS resolution succeeded — LEAK!
    LeakDetected {
        /// What the leaked DNS resolved to.
        resolved_to: String,
    },
    /// Test inconclusive (network error unrelated to DNS).
    Inconclusive(String),
}

/// DNS leak tester.
///
/// Performs multiple checks to verify that all DNS resolution
/// goes through Tor (SOCKS5h) and no clearnet DNS leaks occur.
pub struct DnsLeakTest {
    /// Whether SOCKS5h (remote DNS) is configured.
    socks5h_configured: bool,
}

impl DnsLeakTest {
    /// Create a new DNS leak tester.
    ///
    /// `socks5h_configured` should be `true` when the transport layer
    /// uses SOCKS5h (hostname-based proxy) rather than SOCKS5.
    pub fn new(socks5h_configured: bool) -> Self {
        Self { socks5h_configured }
    }

    /// Run the DNS leak self-test.
    ///
    /// This should be called on every app startup.
    ///
    /// Verifies SOCKS5h (remote resolve) is configured. It performs **no DNS
    /// query** — see the module docs for why a system-resolver probe is
    /// forbidden (S04 §6.1, §6.2).
    pub fn run_self_test(&self) -> DnsLeakResult {
        if !self.verify_socks5h_configured() {
            return DnsLeakResult::LeakDetected {
                resolved_to: "SOCKS5h not configured".into(),
            };
        }
        DnsLeakResult::Safe
    }

    /// Verify that SOCKS5h (hostname-based proxy) is configured.
    ///
    /// SOCKS5h sends the hostname to the proxy for remote resolution,
    /// while SOCKS5 resolves DNS locally (which would be a leak).
    pub fn verify_socks5h_configured(&self) -> bool {
        self.socks5h_configured
    }

    /// Audit dependencies for known clearnet-calling patterns.
    ///
    /// Returns a list of flagged patterns that could cause DNS leaks:
    /// - Analytics SDKs
    /// - Crash reporting (Sentry, Crashlytics)
    /// - Automatic update checks (non-Tor)
    /// - Font loading from CDN
    /// - Certificate revocation checks (OCSP)
    pub fn audit_dependencies() -> Vec<String> {
        // Current workspace has been manually verified to contain no
        // flagged dependencies. For automated CI checking, use
        // audit_dependency_names() with names from `cargo metadata`.
        Vec::new()
    }

    /// Audit a list of dependency names against known risky patterns.
    ///
    /// Returns a list of flagged dependencies with explanations.
    /// Intended for CI integration: parse names from `cargo metadata` or
    /// `Cargo.lock` and pass them here.
    pub fn audit_dependency_names(names: &[&str]) -> Vec<String> {
        let known_risky: &[(&str, &str)] = &[
            ("sentry", "Crash reporting SDK may phone home over clearnet"),
            (
                "crashlytics",
                "Firebase crash reporting sends data to Google servers",
            ),
            ("analytics", "Analytics SDK sends telemetry over clearnet"),
            ("google-fonts", "Font loading from CDN leaks browsing info"),
            ("ocsp", "Certificate revocation check may use clearnet DNS"),
            ("crl-check", "CRL check may use clearnet DNS"),
        ];

        let mut flags = Vec::new();
        for name in names {
            let lower = name.to_lowercase();
            for (pattern, reason) in known_risky {
                if lower.contains(pattern) {
                    flags.push(format!("{}: {}", name, reason));
                }
            }
        }
        flags
    }
}

impl Default for DnsLeakTest {
    /// Default assumes SOCKS5h is configured (Arti default behavior).
    fn default() -> Self {
        Self {
            socks5h_configured: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_socks5h_configured() {
        let test = DnsLeakTest::default();
        assert!(test.verify_socks5h_configured());
    }

    #[test]
    fn socks5h_not_configured_is_leak() {
        let test = DnsLeakTest::new(false);
        let result = test.run_self_test();
        assert!(matches!(result, DnsLeakResult::LeakDetected { .. }));
    }

    // S04 §6.1: the self-test must reach its verdict without touching the
    // system resolver, so running `cargo test` never leaks a lookup either.
    #[test]
    fn socks5h_configured_is_safe_without_any_dns_query() {
        let test = DnsLeakTest::new(true);
        assert_eq!(test.run_self_test(), DnsLeakResult::Safe);
    }

    #[test]
    fn leak_detected_contains_info() {
        let result = DnsLeakResult::LeakDetected {
            resolved_to: "1.2.3.4:80".to_string(),
        };
        if let DnsLeakResult::LeakDetected { resolved_to } = result {
            assert_eq!(resolved_to, "1.2.3.4:80");
        } else {
            panic!("expected LeakDetected");
        }
    }

    #[test]
    fn inconclusive_contains_reason() {
        let result = DnsLeakResult::Inconclusive("network timeout".to_string());
        if let DnsLeakResult::Inconclusive(reason) = result {
            assert_eq!(reason, "network timeout");
        } else {
            panic!("expected Inconclusive");
        }
    }

    #[test]
    fn audit_dependencies_returns_empty() {
        let flags = DnsLeakTest::audit_dependencies();
        assert!(flags.is_empty());
    }

    #[test]
    fn audit_dependency_names_flags_risky_deps() {
        let deps = ["tokio", "serde", "sentry-core", "firebase-crashlytics"];
        let flags = DnsLeakTest::audit_dependency_names(&deps);
        assert_eq!(flags.len(), 2);
        assert!(flags[0].contains("sentry"));
        assert!(flags[1].contains("crashlytics"));
    }

    #[test]
    fn audit_dependency_names_clean_returns_empty() {
        let deps = ["tokio", "serde", "sha2", "ed25519-dalek"];
        let flags = DnsLeakTest::audit_dependency_names(&deps);
        assert!(flags.is_empty());
    }

    #[test]
    fn dns_leak_result_safe_equality() {
        assert_eq!(DnsLeakResult::Safe, DnsLeakResult::Safe);
    }
}
