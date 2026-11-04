//! Arti (embedded Tor) integration.
//!
//! Wraps `arti-client` to provide bootstrapping, circuit-isolated connections,
//! and HTTP-over-Tor with full header stripping.

use crate::circuit::{CircuitHandle, CircuitIsolation};
use crate::clock::TorClockSync;
use crate::config::{TorConfig, TorMode};
use crate::error::{Result, TransportError};
use crate::http::{
    build_get_request, build_post_request, exchange, validate_onion_url, HttpResponse,
};

use arti_client::config::CfgPath;
use arti_client::{IsolationToken, StreamPrefs, TorClient, TorClientConfig};
use rusqlite::{Connection, OpenFlags};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tor_rtcompat::PreferredRuntime;

/// One isolation token, including the timestamps used to retire it.
struct CircuitEntry {
    token: IsolationToken,
    isolation: CircuitIsolation,
    created_at: Instant,
    last_used: Instant,
    in_flight: usize,
}

type CircuitRegistry = Mutex<HashMap<u64, CircuitEntry>>;

fn registry_lock(registry: &CircuitRegistry) -> MutexGuard<'_, HashMap<u64, CircuitEntry>> {
    registry.lock().unwrap_or_else(|e| e.into_inner())
}

/// Retire a failed or cancelled request's token. A synchronous lock makes this
/// cleanup run even when the requesting future is dropped during an await.
struct CircuitUse<'a> {
    registry: &'a CircuitRegistry,
    id: u64,
    succeeded: bool,
}

impl Drop for CircuitUse<'_> {
    fn drop(&mut self) {
        let mut entries = registry_lock(self.registry);
        if self.succeeded {
            if let Some(entry) = entries.get_mut(&self.id) {
                entry.in_flight = entry.in_flight.saturating_sub(1);
                entry.last_used = Instant::now();
            }
        } else {
            entries.remove(&self.id);
        }
    }
}

struct BootstrapGuard<'a> {
    state: &'a AtomicU8,
    progress: &'a AtomicU8,
    clock: &'a TorClockSync,
    completed: bool,
}

impl Drop for BootstrapGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.clock.synchronize_from_estimates(&[]).ok();
            self.state.store(STATE_DISCONNECTED, Ordering::SeqCst);
            self.progress.store(0, Ordering::SeqCst);
        }
    }
}

/// Transport state constants.
const STATE_DISCONNECTED: u8 = 0;
const STATE_CONNECTING: u8 = 1;
const STATE_CONNECTED: u8 = 2;

/// Tor transport backed by the Arti embedded client (S04 §10).
pub struct TorTransport {
    config: TorConfig,
    /// The Arti `TorClient`, set after bootstrap.
    client: RwLock<Option<TorClient<PreferredRuntime>>>,
    /// All token lifecycle changes happen under one lock.
    circuits: CircuitRegistry,
    /// Includes active one-shot streams after their handles have been consumed.
    requests: Semaphore,
    /// Connection state (0 = disconnected, 1 = connecting, 2 = connected).
    state: AtomicU8,
    /// Bootstrap progress 0-100.
    progress: AtomicU8,
    /// Clock offset derived from the latest validated Tor consensus.
    clock: TorClockSync,
}

impl TorTransport {
    /// Create a new `TorTransport` (not yet connected).
    pub fn new(config: TorConfig) -> Self {
        Self {
            requests: Semaphore::new(config.max_circuits as usize),
            config,
            client: RwLock::new(None),
            circuits: Mutex::new(HashMap::new()),
            state: AtomicU8::new(STATE_DISCONNECTED),
            progress: AtomicU8::new(0),
            clock: TorClockSync::new(),
        }
    }

    /// Bootstrap the Tor connection.
    ///
    /// This may take 30-60 seconds while downloading consensus and
    /// establishing circuits.
    pub async fn bootstrap(&mut self) -> Result<()> {
        // A second bootstrap starts from a completely disconnected instance.
        *self.client.write().await = None;
        registry_lock(&self.circuits).clear();
        self.clock.synchronize_from_estimates(&[]).ok();
        self.state.store(STATE_CONNECTING, Ordering::SeqCst);
        self.progress.store(5, Ordering::SeqCst);
        let mut guard = BootstrapGuard {
            state: &self.state,
            progress: &self.progress,
            clock: &self.clock,
            completed: false,
        };
        let arti_config = self.build_arti_config()?;
        self.progress.store(10, Ordering::SeqCst);
        let client = TorClient::create_bootstrapped(arti_config)
            .await
            .map_err(|e| TransportError::BootstrapFailed(e.to_string()))?;
        // A directory loaded from the cache (for example from an earlier direct
        // session) completes Arti's bootstrap with no network contact at all.
        // Connected means a channel to the first hop, a guard or the configured
        // bridge, finished its handshake (S04 §10.1).
        // ponytail: 250 ms status poll; a bootstrap_events() stream needs `futures`.
        while !client.bootstrap_status().ready_for_traffic() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // The consensus supplies an interval, not a measurement of "now".
        if let Some((start, end)) = self.extract_clock_estimates() {
            if let Err(error) = self.clock.synchronize_from_consensus(start, end) {
                tracing::warn!(%error, "Clock sync unavailable — using system time");
            }
        }
        crate::dns_leak::verify_no_dns_leak(self).await?;
        *self.client.write().await = Some(client);
        self.state.store(STATE_CONNECTED, Ordering::SeqCst);
        self.progress.store(100, Ordering::SeqCst);
        guard.completed = true;
        tracing::info!("Tor bootstrap complete");
        Ok(())
    }

    /// Current bootstrap progress (0-100).
    pub fn bootstrap_progress(&self) -> u8 {
        self.progress.load(Ordering::Relaxed)
    }

    /// Whether the transport is fully connected.
    pub fn is_connected(&self) -> bool {
        self.state.load(Ordering::SeqCst) == STATE_CONNECTED
    }

    /// Clock synchronized from the latest validated Tor consensus.
    pub fn clock(&self) -> &TorClockSync {
        &self.clock
    }

    /// Check if Tor can actually build circuits and reach the network.
    ///
    /// Performs a **real connection attempt** through Tor with a short
    /// timeout. This is only called as a fallback when Arti's
    /// `bootstrap_status().ready_for_traffic()` reports false, to confirm
    /// whether Tor has truly lost connectivity or is just reporting stale
    /// cached state.
    ///
    /// Uses a dummy .onion address that routes entirely through Tor
    /// rendezvous circuits — no exit relay is used. The .onion won't
    /// exist, but any circuit-level activity (even a failed lookup) proves
    /// Tor is functional.
    ///
    /// Timeout is 8 seconds to avoid dominating the single-threaded
    /// tokio runtime (which also processes tor_block_on tasks).
    pub async fn check_health(&self) -> bool {
        let client_guard = self.client.read().await;
        let client = match client_guard.as_ref() {
            Some(c) => c,
            None => return false,
        };

        // Quick check: if Arti itself says not ready, trust that immediately.
        if !client.bootstrap_status().ready_for_traffic() {
            return false;
        }

        // Arti says ready, but that can be stale. Do a real circuit probe.
        let prefs = StreamPrefs::new();
        // 8s timeout — short enough to not starve tor_block_on tasks on the
        // single-threaded runtime, long enough for a circuit attempt.
        let timeout = tokio::time::Duration::from_secs(8);

        // Dummy v3 .onion with valid checksum (all-zero pubkey, guaranteed
        // non-existent).  A rendezvous attempt tests guard/middle/intro
        // circuit building without ever using an exit relay.
        let probe_target = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion";
        match tokio::time::timeout(
            timeout,
            client.connect_with_prefs((probe_target, 80u16), &prefs),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                // Successfully opened a stream — Tor is definitely working
                true
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                // Errors that prove Tor IS working (circuits were built,
                // the failure is at the target/directory level):
                //   - "refused" = target refused connection
                //   - "exit policy" = exit won't connect to that port
                //   - "resolve" = DNS issue at exit (circuit still worked)
                //   - "reset" = connection reset by target
                //   - "not found" = onion service not found (circuits work)
                //   - "lookup" = HS directory lookup completed (circuits work)
                //   - "introduction" = HS intro point reached (circuits work)
                // Errors that mean Tor is broken:
                //   - "No running usable Relays" = no circuits possible
                //   - "Unable to build" = circuit build failure
                //   - timeout = can't reach relays
                if msg.contains("refused")
                    || msg.contains("exit policy")
                    || msg.contains("resolve")
                    || msg.contains("reset")
                    || msg.contains("not found")
                    || msg.contains("lookup")
                    || msg.contains("introduction")
                {
                    true
                } else {
                    tracing::warn!("tor health probe failed: {}", msg);
                    false
                }
            }
            Err(_) => {
                // Timeout — Tor can't build circuits
                tracing::warn!("tor health probe timed out (8s)");
                false
            }
        }
    }

    /// Gracefully shut down Tor.
    pub async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("shutting down Tor transport");

        // Drop the client to release Tor resources
        *self.client.write().await = None;
        registry_lock(&self.circuits).clear();
        self.clock.synchronize_from_estimates(&[]).ok();
        self.state.store(STATE_DISCONNECTED, Ordering::SeqCst);
        self.progress.store(0, Ordering::SeqCst);

        Ok(())
    }

    /// Obtain an isolated circuit handle.
    ///
    /// For reusable isolation types (ByMailbox, ByContact, FileTransfer,
    /// CoverTraffic), returns the existing entry unless it has been retired
    /// (S04 §4.3, §4.4).
    /// For `OneShot`, always creates a new token.
    pub async fn get_circuit(&self, isolation: CircuitIsolation) -> Result<CircuitHandle> {
        self.require_connected()?;

        if self.config.max_circuits == 0 || self.config.circuit_timeout_secs == 0 {
            return Err(TransportError::TorError(
                "circuit limits must be positive".into(),
            ));
        }
        let mut entries = registry_lock(&self.circuits);
        self.prune_circuits(&mut entries);
        if isolation.reuse_key().is_some() {
            if let Some((&id, entry)) = entries.iter_mut().find(|(_, e)| e.isolation == isolation) {
                entry.last_used = Instant::now();
                return Ok(CircuitHandle {
                    id,
                    isolation,
                    created_at: entry.created_at,
                });
            }
        }
        // Evict the least recently used idle token, never an active stream.
        if entries.len() >= self.config.max_circuits as usize {
            let victim = entries
                .iter()
                .filter(|(_, e)| e.in_flight == 0)
                .min_by_key(|(_, e)| e.last_used)
                .map(|(&id, _)| id);
            if let Some(id) = victim {
                entries.remove(&id);
            } else {
                return Err(TransportError::CircuitFailed(
                    "all circuits are busy".into(),
                ));
            }
        }
        let handle = CircuitHandle::new(isolation.clone());
        entries.insert(
            handle.id,
            CircuitEntry {
                token: IsolationToken::new(),
                isolation,
                created_at: handle.created_at,
                last_used: handle.created_at,
                in_flight: 0,
            },
        );
        Ok(handle)
    }

    /// Retire all handles in this category, including unused one-shot handles.
    pub async fn close_circuit(&self, isolation: &CircuitIsolation) -> Result<()> {
        registry_lock(&self.circuits).retain(|_, entry| &entry.isolation != isolation);
        Ok(())
    }

    /// HTTP POST over Tor (S04 §5, §10).
    pub async fn post(
        &self,
        circuit: &CircuitHandle,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<HttpResponse> {
        let parsed = validate_onion_url(url)?;
        let request = build_post_request(&parsed.authority, &parsed.path, body, content_type)?;
        self.send_request(circuit, &parsed.host, parsed.port, &request)
            .await
    }

    /// HTTP GET over Tor (S04 §5, §10).
    pub async fn get(&self, circuit: &CircuitHandle, url: &str) -> Result<HttpResponse> {
        let parsed = validate_onion_url(url)?;
        let request = build_get_request(&parsed.authority, &parsed.path)?;
        self.send_request(circuit, &parsed.host, parsed.port, &request)
            .await
    }

    /// Retire entries older than `MAX_AGE_SECS` or idle for
    /// `circuit_timeout_secs` (S04 §4.4).
    pub async fn cleanup_idle_circuits(&self) {
        self.prune_circuits(&mut registry_lock(&self.circuits));
    }

    fn prune_circuits(&self, entries: &mut HashMap<u64, CircuitEntry>) {
        entries.retain(|_, entry| {
            entry.created_at.elapsed().as_secs() < CircuitHandle::MAX_AGE_SECS
                && (entry.in_flight > 0
                    || entry.last_used.elapsed().as_secs()
                        < self.config.circuit_timeout_secs as u64)
        });
    }

    fn begin_request(&self, circuit: &CircuitHandle) -> Result<(IsolationToken, CircuitUse<'_>)> {
        let mut entries = registry_lock(&self.circuits);
        self.prune_circuits(&mut entries);
        let entry = entries
            .get_mut(&circuit.id)
            .filter(|entry| entry.isolation == circuit.isolation)
            .ok_or_else(|| {
                TransportError::CircuitFailed("circuit expired, consumed, or retired".into())
            })?;
        let token = entry.token;
        if matches!(entry.isolation, CircuitIsolation::OneShot) {
            // Consume before the first await: retries and concurrent reuse of
            // this handle cannot reuse its Tor isolation token.
            entries.remove(&circuit.id);
        } else {
            entry.in_flight += 1;
            entry.last_used = Instant::now();
        }
        Ok((
            token,
            CircuitUse {
                registry: &self.circuits,
                id: circuit.id,
                succeeded: false,
            },
        ))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Extract a clock estimate from Arti's validated consensus cache.
    ///
    /// Arti's stable API does not expose its live consensus. Its directory
    /// manager persists validated, usable consensuses as non-pending rows, so
    /// read the newest such row without mutating the cache.
    fn extract_clock_estimates(&self) -> Option<(u64, u64)> {
        let path = self.config.data_dir.join("cache").join("dir.sqlite3");
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = match Connection::open_with_flags(&path, flags) {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "could not open Tor consensus cache for clock sync"
                );
                return None;
            }
        };

        match extract_clock_estimates_from_connection(&connection) {
            Ok(estimates) => estimates,
            Err(error) => {
                tracing::warn!(%error, "could not read Tor consensus time");
                None
            }
        }
    }

    /// Validate routing settings without starting a process or using the network.
    pub fn validate_config(config: TorConfig) -> Result<()> {
        Self::new(config).build_arti_config().map(|_| ())
    }

    /// Build an `arti-client` config from our `TorConfig`.
    ///
    /// If `self.config.bridges` is non-empty, enables bridge mode and
    /// configures the specified bridges/pluggable transports in Arti.
    fn build_arti_config(&self) -> Result<TorClientConfig> {
        if !matches!(self.config.mode, TorMode::Embedded) {
            return Err(TransportError::TorError(
                "this build supports embedded Tor only; requested routing mode is unsupported"
                    .into(),
            ));
        }
        if self.config.max_circuits == 0
            || self.config.circuit_timeout_secs == 0
            || self.config.connect_timeout_secs == 0
            || self.config.request_timeout_secs == 0
        {
            return Err(TransportError::TorError(
                "transport limits and deadlines must be positive".into(),
            ));
        }
        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .cache_dir(CfgPath::new_literal(self.config.data_dir.join("cache")))
            .state_dir(CfgPath::new_literal(self.config.data_dir.join("state")));

        let mut protocols = std::collections::HashSet::new();
        for transport in &self.config.transports {
            let name = transport.bridge_type.protocol().ok_or_else(|| {
                TransportError::TorError("plain bridges do not use a PT executable".into())
            })?;
            if !protocols.insert(name) {
                return Err(TransportError::TorError(
                    "duplicate PT configuration".into(),
                ));
            }
            if !transport.executable.is_absolute() || !transport.executable.is_file() {
                return Err(TransportError::TorError(
                    "PT executable must be an existing absolute file path".into(),
                ));
            }
            let mut pt = arti_client::config::pt::TransportConfigBuilder::default();
            pt.protocols(vec![name.parse().map_err(|e| {
                TransportError::TorError(format!("PT protocol: {e}"))
            })?])
            .path(CfgPath::new_literal(transport.executable.clone()))
            .arguments(transport.arguments.clone())
            .run_on_startup(true);
            builder.bridges().transports().push(pt);
        }
        for bridge in &self.config.bridges {
            if bridge.address.trim().is_empty() || bridge.address.contains(['\r', '\n']) {
                return Err(TransportError::TorError(
                    "empty or multiline bridge configuration".into(),
                ));
            }
            let mut words: Vec<String> = bridge
                .address
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            if words.first().is_some_and(|s| s == "Bridge") {
                words.remove(0);
            }
            let protocol = bridge.bridge_type.protocol();
            if let Some(name) = protocol {
                if !protocols.contains(name) {
                    return Err(TransportError::TorError(format!(
                        "missing executable for {name}"
                    )));
                }
                if words
                    .first()
                    .is_some_and(|s| s.parse::<std::net::SocketAddr>().is_ok())
                {
                    words.insert(0, name.into());
                }
                if words.first().map(String::as_str) != Some(name) {
                    return Err(TransportError::TorError(
                        "bridge type does not match bridge line".into(),
                    ));
                }
            } else if !words
                .first()
                .is_some_and(|s| s.parse::<std::net::SocketAddr>().is_ok())
            {
                return Err(TransportError::TorError(
                    "plain bridge must start with an IP address and port".into(),
                ));
            }
            if let Some(fingerprint) = &bridge.fingerprint {
                if fingerprint.len() != 40 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(TransportError::TorError(
                        "invalid bridge fingerprint".into(),
                    ));
                }
                let index = if protocol.is_some() { 2 } else { 1 };
                if let Some(existing) = words
                    .get(index)
                    .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    if !existing.eq_ignore_ascii_case(fingerprint) {
                        return Err(TransportError::TorError(
                            "conflicting bridge fingerprints".into(),
                        ));
                    }
                } else if words.len() >= index {
                    words.insert(index, fingerprint.clone());
                }
            }
            builder.bridges().bridges().push(
                words
                    .join(" ")
                    .parse()
                    .map_err(|e| TransportError::TorError(format!("invalid bridge line: {e}")))?,
            );
        }
        builder
            .build()
            .map_err(|e| TransportError::TorError(format!("config build: {e}")))
    }

    /// Ensure we are connected before performing operations.
    fn require_connected(&self) -> Result<()> {
        if self.state.load(Ordering::SeqCst) != STATE_CONNECTED {
            return Err(TransportError::NotBootstrapped);
        }
        Ok(())
    }

    /// Send one request under a single deadline, without holding the client lock
    /// across network awaits. Shutdown is never blocked by a stalled peer.
    async fn send_request(
        &self,
        circuit: &CircuitHandle,
        host: &str,
        port: u16,
        request: &[u8],
    ) -> Result<HttpResponse> {
        self.require_connected()?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.request_timeout_secs as u64);
        let (token, mut usage) = self.begin_request(circuit)?;
        let result = tokio::time::timeout_at(deadline, async {
            let _permit = self
                .requests
                .acquire()
                .await
                .map_err(|_| TransportError::NotBootstrapped)?;
            let client = self
                .client
                .read()
                .await
                .clone()
                .ok_or(TransportError::NotBootstrapped)?;
            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(token);
            let stream = tokio::time::timeout(
                Duration::from_secs(self.config.connect_timeout_secs as u64),
                client.connect_with_prefs((host, port), &prefs),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|e| TransportError::CircuitFailed(e.to_string()))?;
            exchange(stream, request, deadline).await
        })
        .await
        .map_err(|_| TransportError::Timeout)?;
        usage.succeeded = result.is_ok();
        result
    }
}

/// Read the validity interval of the newest validated consensus. Neither
/// boundary is treated as the current time.
fn extract_clock_estimates_from_connection(
    connection: &Connection,
) -> rusqlite::Result<Option<(u64, u64)>> {
    use rusqlite::OptionalExtension;
    let row = connection
        .query_row(
            "SELECT unixepoch(valid_after), unixepoch(valid_until) FROM Consensuses \
         WHERE pending = 0 AND flavor = 'microdesc' ORDER BY valid_until DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(start, end)| match (start, end) {
        (Some(start), Some(end)) if start >= 0 && end > start => Some((start as u64, end as u64)),
        _ => None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_transport_is_disconnected() {
        let config = TorConfig::default();
        let transport = TorTransport::new(config);
        assert!(!transport.is_connected());
        assert_eq!(transport.bootstrap_progress(), 0);
        assert_eq!(transport.clock().offset(), 0);
    }

    #[test]
    fn extracts_latest_usable_consensus_clock_estimate() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE Consensuses (\
                    valid_after TEXT NOT NULL, \
                    valid_until TEXT NOT NULL, \
                    flavor TEXT NOT NULL, \
                    pending BOOLEAN NOT NULL\
                );\
                INSERT INTO Consensuses VALUES \
                    ('2026-08-11 10:00:00.0+00:00', '2026-08-11 13:00:00.0+00:00', 'microdesc', 0), \
                    ('2026-08-11 11:00:00.0+00:00', '2026-08-11 14:00:00.0+00:00', 'microdesc', 1), \
                    ('2026-08-11 13:00:00.0+00:00', '2026-08-11 16:00:00.0+00:00', 'ns', 0), \
                    ('2026-08-11 12:00:00.0+00:00', '2026-08-11 15:00:00.0+00:00', 'microdesc', 0);",
            )
            .unwrap();

        let estimates = extract_clock_estimates_from_connection(&connection).unwrap();
        assert_eq!(estimates, Some((1_786_449_600, 1_786_460_400)));
    }

    #[tokio::test]
    async fn get_circuit_requires_bootstrap() {
        let transport = TorTransport::new(TorConfig::default());
        let result = transport
            .get_circuit(CircuitIsolation::CoverTraffic("cover.onion".to_string()))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_requires_bootstrap() {
        let transport = TorTransport::new(TorConfig::default());
        let handle = CircuitHandle::new(CircuitIsolation::OneShot);
        let result = transport
            .post(
                &handle,
                "http://test.onion/api",
                b"data",
                "application/octet-stream",
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_requires_bootstrap() {
        let transport = TorTransport::new(TorConfig::default());
        let handle = CircuitHandle::new(CircuitIsolation::OneShot);
        let result = transport.get(&handle, "http://test.onion/api").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn post_rejects_clearnet() {
        let transport = TorTransport::new(TorConfig::default());
        let handle = CircuitHandle::new(CircuitIsolation::OneShot);
        let result = transport
            .post(
                &handle,
                "http://example.com/api",
                b"data",
                "application/octet-stream",
            )
            .await;
        assert!(matches!(result, Err(TransportError::NotOnionAddress)));
    }

    #[tokio::test]
    async fn get_rejects_clearnet() {
        let transport = TorTransport::new(TorConfig::default());
        let handle = CircuitHandle::new(CircuitIsolation::OneShot);
        let result = transport.get(&handle, "http://example.com/api").await;
        assert!(matches!(result, Err(TransportError::NotOnionAddress)));
    }

    #[tokio::test]
    async fn shutdown_clears_state() {
        let mut transport = TorTransport::new(TorConfig::default());
        transport.shutdown().await.unwrap();
        assert!(!transport.is_connected());
        assert_eq!(transport.bootstrap_progress(), 0);
    }
}

#[cfg(test)]
#[path = "tor_tests.rs"]
mod regression_tests;
