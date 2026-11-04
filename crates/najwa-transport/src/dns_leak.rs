//! DNS leak prevention self-test (S04 §6).
//!
//! The startup hook (S04 §6.2) deliberately issues no runtime probe. S04 §6.1
//! forbids using the system resolver for any purpose, while the only way a
//! probe could detect a leak would be to submit the probe name to that
//! resolver. Doing so would create the disclosure this module prevents.
//!
//! Remote resolution is guaranteed structurally instead: this crate constructs
//! only embedded Arti clients. Arti receives destination hostnames directly and
//! never delegates them to the system resolver. Consequently there is no
//! runtime DNS-leak condition for the startup hook to test today.

use crate::circuit::CircuitIsolation;
use crate::error::{Result, TransportError};
use crate::tor::TorTransport;

/// Tor Project's support mirror, published at https://onion.torproject.org/.
const TOR_CHECK_ONION: &str =
    "http://rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad.onion/";

/// Startup hook for DNS-leak prevention.
///
/// This hook currently has no failing runtime condition: embedded Arti provides
/// remote hostname resolution by construction, and probing the system resolver
/// would violate S04 §6.1. It remains wired into bootstrap so a future genuine,
/// non-leaking check can use the existing fail-closed startup plumbing.
pub async fn verify_no_dns_leak(_transport: &TorTransport) -> Result<()> {
    tracing::info!("DNS leak prevention: embedded Arti provides remote resolution");
    Ok(())
}

/// Strict variant that also verifies Tor-routed `.onion` connectivity.
pub async fn verify_no_dns_leak_strict(transport: &TorTransport) -> Result<()> {
    if !transport.is_connected() {
        return Err(TransportError::NotBootstrapped);
    }
    verify_no_dns_leak(transport).await?;

    let circuit = transport.get_circuit(CircuitIsolation::OneShot).await?;
    let response = transport
        .get(&circuit, TOR_CHECK_ONION)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "DNS leak test (strict): .onion unreachable");
            TransportError::TorError(format!("Tor connectivity check failed: {e}"))
        })?;

    if !(200..400).contains(&response.status) {
        return Err(TransportError::TorError(
            "Tor connectivity endpoint returned an error".into(),
        ));
    }

    tracing::info!("DNS leak self-test (strict) passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn transport_sources_do_not_use_system_resolver_apis() {
        let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let forbidden = [
            ["lookup", "_host"].concat(),
            ["to_socket", "_addrs"].concat(),
        ];

        for entry in fs::read_dir(source_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }

            let source = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
            for api in &forbidden {
                assert!(
                    !source.contains(api),
                    "{} uses forbidden system-resolver API {api}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(test)]
#[test]
fn strict_connectivity_endpoint_is_accepted_by_the_actual_url_validator() {
    let parsed = crate::http::validate_onion_url(TOR_CHECK_ONION).unwrap();
    assert_eq!(parsed.port, 80);
    assert_eq!(parsed.host.len(), 62);
}
