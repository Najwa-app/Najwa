//! Development-only transport probe: real embedded Arti, no user identity.
//! Uses fresh random capabilities and an opaque random blob, then deactivates
//! the capability. This is not an end-to-end messenger or cover-traffic test.
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use najwa_crypto::keys::ed25519::{Ed25519Public, Ed25519Signature};
use najwa_protocol::mailbox::{
    client::MailboxClient,
    http::HttpMailboxClient,
    types::{CapabilitySettings, MailboxConfig},
};
use najwa_transport::{circuit::CircuitIsolation, config::TorConfig, tor::TorTransport};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};

type ProbeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Deserialize)]
struct Attestation {
    operator_id: String,
    jurisdiction: String,
    infrastructure_provider: String,
    onion_address: String,
    timestamp: i64,
    signature: String,
}

#[tokio::main]
async fn main() -> ProbeResult<()> {
    najwa_crypto::initialize()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: onion_mailbox_probe <v3-host.onion> <dedicated-tor-state-dir>".into());
    }
    let host = args[0].strip_suffix(".onion").unwrap_or(&args[0]);
    if host.len() != 56 || !host.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err("expected a v3 onion hostname".into());
    }
    let mut transport = TorTransport::new(TorConfig {
        data_dir: PathBuf::from(&args[1]),
        ..Default::default()
    });
    println!("Bootstrapping embedded Arti on the real Tor network...");
    tokio::time::timeout(Duration::from_secs(240), transport.bootstrap()).await??;
    let transport = Arc::new(transport);
    let circuit = transport
        .get_circuit(CircuitIsolation::ByMailbox(host.into()))
        .await?;
    let response = transport
        .get(&circuit, &format!("http://{host}.onion/v1/attestation"))
        .await?;
    if response.status != 200 {
        return Err(format!("attestation returned HTTP {}", response.status).into());
    }
    let attestation: Attestation = serde_json::from_slice(&response.body)?;
    if attestation.onion_address != host
        || attestation
            .timestamp
            .abs_diff(najwa_crypto::time::now_ms() / 1000)
            > 300
    {
        return Err("attestation hostname or freshness mismatch".into());
    }
    let public_bytes: [u8; 32] = BASE64
        .decode(&attestation.operator_id)?
        .try_into()
        .map_err(|_| "invalid operator key length")?;
    let signature_bytes: [u8; 64] = BASE64
        .decode(&attestation.signature)?
        .try_into()
        .map_err(|_| "invalid attestation signature length")?;
    // S16 §3.10: label, then each text field length-prefixed (u64 BE) so the
    // signature fixes field boundaries, then the timestamp.
    let mut hash = Sha256::new();
    hash.update(b"najwa-operator-attestation-v2");
    for field in [
        &attestation.onion_address,
        &attestation.jurisdiction,
        &attestation.infrastructure_provider,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(attestation.timestamp.to_be_bytes());
    Ed25519Public::from_bytes(&public_bytes)?.verify(
        &hash.finalize(),
        &Ed25519Signature::from_bytes(&signature_bytes)?,
    )?;
    println!("Onion reached; fresh operator signature verified (self-authentication only).");
    println!("Operator ID: {}", attestation.operator_id);
    println!(
        "Jurisdiction: {:?}; infrastructure provider: {:?}",
        attestation.jurisdiction, attestation.infrastructure_provider
    );
    let health = transport
        .get(&circuit, &format!("http://{host}.onion/v1/health"))
        .await?;
    if health.status != 404 {
        return Err("health endpoint unexpectedly reachable through the onion API".into());
    }

    let client = HttpMailboxClient::new(transport);
    let mailbox = MailboxConfig::new(
        host.into(),
        najwa_crypto::random::random_bytes(),
        najwa_crypto::random::random_bytes(),
    );
    client
        .register_capability(
            &mailbox,
            &CapabilitySettings {
                retention_days: 1,
                ..Default::default()
            },
            None,
        )
        .await?;
    println!("Fresh capability registered with proof-of-work.");
    let outcome =
        tokio::time::timeout(Duration::from_secs(600), roundtrip(&client, &mailbox)).await;
    // Cleanup even on a failed roundtrip; do not print capability tokens.
    let cleanup = client
        .deactivate_capability(&mailbox, &mailbox.fetch_capability)
        .await;
    if cleanup.is_err() {
        eprintln!("Capability cleanup failed; its development retention policy still applies.");
    }
    outcome??;
    cleanup?;
    println!("PASS: batched deposit/fetch/acknowledge and capability deactivation over Arti.");
    Ok(())
}

async fn roundtrip(client: &HttpMailboxClient, mailbox: &MailboxConfig) -> ProbeResult<()> {
    let blob: [u8; 1024] = najwa_crypto::random::random_bytes();
    let deposited = client
        .deposit(mailbox, &mailbox.deposit_capability, &blob, None)
        .await?;
    if !deposited.accepted || deposited.message_id.is_none() {
        return Err("deposit was not accepted".into());
    }
    println!("Opaque test blob deposited; waiting for the configured batching window...");
    loop {
        let messages = client
            .fetch(mailbox, &mailbox.fetch_capability, None, 10)
            .await?;
        if let Some(message) = messages
            .iter()
            .find(|m| Some(&m.id) == deposited.message_id.as_ref())
        {
            if message.blob != blob {
                return Err("fetched blob differs from deposited blob".into());
            }
            client
                .acknowledge(mailbox, &mailbox.fetch_capability, &[message.id.clone()])
                .await?;
            if !client
                .fetch(mailbox, &mailbox.fetch_capability, None, 10)
                .await?
                .is_empty()
            {
                return Err("acknowledged blob is still present".into());
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
