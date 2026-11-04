---
id: S04
title: Transport Layer
crates: [najwa-transport, najwa-protocol, najwa-ffi]
depends-on: [S01]
---

# S04 — Transport Layer

## Overview

Every network request Najwa makes goes through Tor to a mailbox onion service. The
native service embeds its own Tor client (Arti), so users install nothing else. The
browser UI never talks to the network: it talks to the native service on loopback,
and the native service talks to mailboxes.

This spec defines how the Tor client is configured and started, which Tor circuit
each kind of request uses, how HTTP requests are written and responses read, how
onion addresses are checked, how DNS leaks are ruled out, where network time comes
from, how bridges and pluggable transports work, and how failures are retried.

- **Onion only.** The transport accepts only `http://<56-character v3 label>.onion`
  URLs. Onion-service connections never use a Tor exit relay, and no hostname is
  ever handed to the operating system's resolver.
- **Circuit isolation.** Different kinds of work use different Tor circuits, so a
  relay or a mailbox operator cannot tie them together just because they share a
  circuit. Each prospective contact's prekey fetch has its own circuit, every
  deposit, real or cover, uses a fresh circuit, and cover polls to each mailbox
  have their own circuit. Isolation reduces some linkage between operations. It
  does not stop an observer who can watch both ends of the Tor network.
- **Bridges.** Where Tor is blocked, the user can paste plain, obfs4 or Snowflake
  bridge lines. obfs4 and Snowflake run through a bundled, checksum-pinned
  `lyrebird` helper. A broken bridge setup stops the connection. Najwa never falls
  back to direct Tor behind the user's back.
- **What "connected" means.** The Tor client bootstrapped and the messaging service
  is installed. It does not mean that prekeys are published, capabilities are
  registered or messages are delivered. Those are separate durable steps with their
  own retries ([S08](08-messaging-service.md)). An offline recipient is not a
  transport failure: the mailbox holds ciphertext until the recipient polls, within
  its retention policy ([S16](16-mailbox-server.md)).

The mailbox's own onion service is specified in [S16](16-mailbox-server.md) and
deployed per [Deployment](../server/deployment.md). When requests are sent (cover
traffic and delivery pacing) is specified in [S10](10-cover-traffic.md).

## 1. Scope

This specification defines:

- The Tor requirement and the absence of any clearnet path.
- Tor client configuration and bootstrap (embedded `arti-client`).
- Circuit isolation types, their assignment to mailbox operations, and rotation.
- Raw HTTP/1.1 request building and bounded response parsing over a Tor stream.
- `.onion` URL validation.
- DNS-leak prevention and its static enforcement.
- Network time derived from the Tor consensus.
- Version-leak prevention.
- Error types, retry and reconnect behavior.
- Bridges, pluggable transports and the bundled transport helper.

## 2. Tor Requirement

- All network communication of the messaging runtime MUST go through Tor to a v3
  onion service.
- There is no clearnet fallback. If Tor cannot bootstrap, or the saved bridge
  configuration is invalid, the client MUST report itself offline and send nothing.
- Only onion destinations are accepted (§5.4), so no request uses an exit relay.
- The client MUST use its embedded Arti client. External Tor daemons and SOCKS
  proxies are not supported (§3).
- The mailbox never learns the client's IP address.

The only connections the application makes outside Tor are the loopback HTTP
connection between the browser UI and the native service, and the connections a
pluggable transport makes to its own bridge infrastructure (§11.2, §13).

## 3. Configuration

```rust
struct TorConfig {
    mode: TorMode,                              // MUST be Embedded
    data_dir: PathBuf,                          // Tor state; the app uses <profile>/tor
    bridges: Vec<BridgeConfig>,                 // empty = direct Tor
    transports: Vec<PluggableTransportConfig>,  // one per pluggable-transport protocol in use
    max_circuits: u32,                          // default 8
    circuit_timeout_secs: u32,                  // default 60 — idle retirement (§4.4)
    connect_timeout_secs: u32,                  // default 60
    request_timeout_secs: u32,                  // default 120
}

enum TorMode {
    Embedded,                        // the only supported mode
    SystemSocks { addr: SocketAddr },// rejected
    Orbot,                           // rejected
}

struct BridgeConfig {
    bridge_type: BridgeType,
    address: String,                 // the bridge line (§11.1)
    fingerprint: Option<String>,     // optional 40-hex relay fingerprint
}

enum BridgeType { Plain, Obfs4, Meek, Snowflake }

struct PluggableTransportConfig {
    bridge_type: BridgeType,         // MUST NOT be Plain
    executable: PathBuf,             // absolute path to an existing file
    arguments: Vec<String>,          // process arguments; bridge options belong in the line
}
```

| Field | Default | Meaning |
|-------|---------|---------|
| `max_circuits` | 8 | Bound on registered isolation entries and on concurrent requests |
| `circuit_timeout_secs` | 60 | An entry idle this long with no request in flight is retired |
| `connect_timeout_secs` | 60 | Bound on opening one Tor stream |
| `request_timeout_secs` | 120 | Single deadline for one complete request (§10) |

Rules:

- A `mode` other than `Embedded` MUST be rejected when the Arti configuration is
  built (`TorError`).
- All four limits MUST be greater than zero. A zero limit MUST be rejected.
- `connect_timeout_secs` is 60 s because onion-service rendezvous routinely takes
  longer than 30 s. A shorter timeout produces spurious failures and synchronized
  retry storms.

### 3.1 Arti Configuration

The client builds an Arti `TorClientConfig` as follows:

1. `storage.cache_dir = data_dir/cache` and `storage.state_dir = data_dir/state`,
   both as literal paths.
2. For each `PluggableTransportConfig`:
   - The protocol name is `obfs4`, `meek` or `snowflake`. A `Plain` entry MUST be
     rejected.
   - A second entry for the same protocol MUST be rejected.
   - `executable` MUST be an absolute path to an existing file.
   - The entry is added to Arti's managed transports with that protocol, path and
     arguments, and `run_on_startup = true`.
3. Each bridge is normalized and added per §11.1.
4. The configuration is built. Any failure MUST abort with `TorError`.

`TorTransport::validate_config` performs these steps without starting Tor or
touching the network. The application calls it before saving bridge settings.

Arti is compiled without default features, with `tokio`, `onion-service-client`,
`rustls`, `bridge-client` and `pt-client` (§12).

## 4. Circuit Isolation

Each request carries an Arti `IsolationToken`. Arti never places streams with
different tokens on the same circuit. Streams with the same token may share one.

### 4.1 Isolation Types

```rust
enum CircuitIsolation {
    ByMailbox(String),      // mailbox onion label — one entry per mailbox
    ByContact([u8; 32]),    // prospective contact pseudonym — one entry per contact
    FileTransfer([u8; 32]), // Responsive file parts — one entry per file and destination (S10 §9)
    CoverTraffic(String),   // mailbox onion label — one cover entry per mailbox
    OneShot,                // single use; consumed by its first request
}
```

`CoverTraffic` carries the target mailbox onion: cover streams to different
mailboxes MUST NOT share a circuit. One shared cover circuit would let a
guard-position observer group the user's whole mailbox set.

### 4.1.1 Isolation Assignments (normative)

| Operation | Endpoint | Isolation | Attempts |
|-----------|----------|-----------|----------|
| Real mailbox fetch | `/v1/fetch` | `ByMailbox(onion)` | Up to 3 transport retries (§9.1.1) |
| Real acknowledge | `/v1/acknowledge` | `ByMailbox(onion)` | Up to 3 transport retries |
| Capability status | `/v1/status` | `ByMailbox(onion)` | One |
| Prekey publication | `/v1/prekey/upload` | `ByMailbox(onion)` | One |
| Capability deactivation | `/v1/capability/deactivate` | `ByMailbox(onion)` | One |
| PoW challenge | `/v1/challenge` | The isolation of the request it gates: `OneShot` for a deposit or registration, `ByContact(pseudonym)` for a prekey fetch | Up to 3 transport retries |
| Prekey fetch for a prospective contact | `/v1/prekey/fetch` | `ByContact(pseudonym)` | Up to 3 transport retries; one PoW retry |
| Capability registration (primary, per-contact, invitation, cover) | `/v1/capability/register` | `OneShot` | One |
| Real deposit: message, control, ACK, receipt; file part in Timing privacy | `/v1/deposit` | `OneShot` | One per attempt |
| File part in Responsive mode | `/v1/deposit` | `FileTransfer(key)` | One per attempt |
| Cover deposit | `/v1/deposit` | `OneShot` | One |
| Cover poll and its acknowledge | `/v1/fetch`, `/v1/acknowledge` | `CoverTraffic(onion)` | One |

Requirements:

- Every real deposit attempt MUST use a new `OneShot` circuit, including retries,
  PoW re-submissions and each target of a multi-mailbox delivery
  ([S08 §9](08-messaging-service.md)).
- Every cover deposit MUST also use a new `OneShot` circuit. If cover reused a
  circuit while real deposits built new ones, an observer at the user's guard
  could pick out real deposits by the circuit build. The cost is one onion-service
  circuit build per cover deposit. At the `High` cover level that is about 2 per
  minute in total, spread over the user's mailboxes, and about 8 per minute inside
  a boost window ([S10 §2.1, §8.1](10-cover-traffic.md)).
- Prekey fetches MUST use `ByContact`. With per-mailbox isolation, one mailbox could
  correlate a user's prekey fetches for several new contacts on one circuit.
- Cover polls and cover acknowledgements MUST use `CoverTraffic(onion)` for their
  own mailbox and MUST NOT use `ByMailbox`. They mirror real fetches, which reuse
  a `ByMailbox` circuit.
- A PoW challenge MUST use the isolation of the request it gates, and MUST NOT use
  `ByMailbox`. On the user's `ByMailbox` circuit, the challenge would let the
  mailbox link the gated deposit, registration or prekey fetch to the user's real
  fetches. Cover never solves PoW except for its registration, which is a
  registration and uses `OneShot`. The challenge for a Responsive file part
  uses `OneShot`, which links to nothing.
- Each capability registration MUST use its own `OneShot` circuit.
- `FileTransfer` MAY be used only for parts of one outgoing file in Responsive
  mode. Its key binds the file, the contact, the destination capability and the
  mailbox, so different files, contacts, capabilities or mailboxes never share an
  entry. The key derivation is in [S10 §9](10-cover-traffic.md). In Timing privacy
  mode file parts use `OneShot`.

### 4.2 Circuit Handle

```rust
struct CircuitHandle {
    id: u64,                    // process-unique, allocated from 1 upward
    isolation: CircuitIsolation,
    created_at: Instant,
}
```

A handle names one registry entry. A request on a handle whose entry has expired,
been consumed or been retired MUST fail with `CircuitFailed`.

### 4.3 Isolation Token Mapping

- Each registry entry holds its own fresh Arti `IsolationToken`. Tokens are not
  derived from the isolation value.
- `get_circuit` for `ByMailbox`, `ByContact`, `FileTransfer` or `CoverTraffic`
  returns the live entry whose `CircuitIsolation` value is equal (same variant and
  same payload). If there is none, it creates a new entry.
- Values of different variants never compare equal, so identical payloads under
  different variants never share a token.
- `OneShot` always creates a new entry. The entry is removed when its request
  begins, before any await, so neither a retry nor a concurrent caller can reuse
  its token.

### 4.4 Circuit Rotation

| Condition | Action |
|-----------|--------|
| Entry age ≥ 600 s (`CircuitHandle::MAX_AGE_SECS`) | Retire, even with a request in flight |
| No request in flight and idle ≥ `circuit_timeout_secs` | Retire |
| A request on the entry fails, times out or is cancelled | Retire immediately |
| Registry holds `max_circuits` entries and a new one is needed | Evict the least recently used entry with no request in flight; if every entry is busy, fail with `CircuitFailed("all circuits are busy")` |
| `close_circuit(isolation)` | Retire every entry with that isolation |
| Bootstrap or shutdown | Clear the registry |

```
CIRCUIT_MAX_AGE_SECS = 600

func get_circuit(isolation) → CircuitHandle:
    require state == CONNECTED                      // else NotBootstrapped
    prune(entries)                                  // age and idle rules above
    if isolation != OneShot:
        if entry with equal isolation exists:
            entry.last_used = now
            return handle(entry)
    if entries.len >= max_circuits:
        evict least-recently-used entry with in_flight == 0, or fail CircuitFailed
    insert new entry { token: IsolationToken::new(), isolation, created_at: now,
                       last_used: now, in_flight: 0 }
    return handle(new entry)
```

Pruning runs on every `get_circuit`, at the start of every request, and in
`cleanup_idle_circuits`. Retiring a token means the next request builds a new
circuit. Arti decides when the old circuit closes.

## 5. HTTP Over Tor

### 5.1 Request Building

Requests are written by hand as raw HTTP/1.1 bytes on an Arti `DataStream`. No HTTP
client library is used, so every header is under the client's control.

```
GET  {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n

POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: {content_type}\r\n
     Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}
```

(The POST header lines are shown wrapped; each ends with `\r\n`.)

- `authority` is the onion host, plus `:{port}` when the port is not 80.
- `authority` MUST be non-empty, `path` MUST start with `/`, and every byte of both
  MUST be in `0x21–0x7E`. Otherwise the request MUST be rejected
  (`HttpParseError`). This blocks header injection.
- `content_type` MUST be non-empty and every byte MUST be in `0x20–0x7E`.
- The mailbox client sends every mailbox call as `POST` with
  `Content-Type: application/json`.

### 5.2 Header Set

A request carries exactly the headers shown in §5.1: `Host`, `Connection` and, for
`POST`, `Content-Type` and `Content-Length`. In particular the client MUST NOT
send:

| Header | Reason |
|--------|--------|
| `User-Agent` | Fingerprints client software and version |
| `Accept-Language` | Reveals locale |
| `Accept-Encoding` | Fingerprints capabilities |
| `Referer` | Leaks navigation context |
| `Cookie` | Enables session tracking |
| `X-Forwarded-For` | Leaks addresses |
| Any version header (`X-Najwa-Version`, `X-Client-Version`, `X-App-Version`) | Fingerprints the release (§8) |

### 5.3 Response Parsing

The client reads exactly one final response and returns as soon as it is complete.
A framed response does not wait for the peer to close the stream.

| Constant | Value | Bounds |
|----------|-------|--------|
| `MAX_HEADER_BYTES` | 32,768 | Status lines and headers of all responses on the stream, shared |
| `MAX_BODY_BYTES` | 83,886,080 (80 MiB) | Response body; sized for a fetch of 200 base64-encoded 256 KiB blobs |
| `MAX_CHUNK_METADATA_BYTES` | 1,048,576 | Chunk-size lines and trailers |
| Informational responses | ≤ 8 before the final response | |

```rust
struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>, // lower-case names
    body: Vec<u8>,
}
```

Rules. Any violation MUST fail the request with `HttpParseError` or `Io`.

1. Every line MUST end with CRLF, MUST NOT contain a byte below `0x20` other than
   HTAB, MUST NOT contain `0x7F`, and MUST be valid UTF-8.
2. The status line MUST start with `HTTP/1.0` or `HTTP/1.1`, followed by a
   three-digit code in 100–599.
3. Header names MUST consist of RFC 9110 token characters. Names are lower-cased;
   values are trimmed of spaces and tabs. Repeated headers are joined with `, `.
   A repeated `Content-Length` or `Transfer-Encoding` MUST be rejected.
4. `Content-Length` MUST be ASCII digits only. A response with both
   `Content-Length` and `Transfer-Encoding` MUST be rejected.
   `Transfer-Encoding` MUST be `chunked` (case-insensitive) if present.
5. `101` MUST be rejected. Other `1xx` responses MUST NOT carry framing headers and
   are skipped.
6. `204` and `304` have no body. `Transfer-Encoding` on either, or a non-zero
   `Content-Length` on `204`, MUST be rejected.
7. Chunked bodies: each size line is hex digits, optionally followed by `;`
   extensions, which are ignored. Each chunk MUST be followed by CRLF. Trailer
   fields named `content-length`, `transfer-encoding` or `host` MUST be rejected.
8. With `Content-Length`, exactly that many bytes are read. With neither framing
   header, the body is read until the peer closes the stream.
9. A body larger than `MAX_BODY_BYTES` MUST be rejected under every framing.

### 5.4 URL Validation

```
func validate_onion_url(url) → OnionUrl | NotOnionAddress:
    reject unless url is ASCII, contains no byte ≤ 0x20 and no 0x7F, and contains no '#'
    rest = url with the exact prefix "http://" removed       // anything else, including https://, is rejected
    split rest at the first '/' or '?' into host_port and suffix
    path = suffix                 if suffix starts with '/'
           "/" + suffix           if suffix starts with '?'
           "/"                    if suffix is empty
    if host_port contains ':':
        split at the last ':' into host and port_text
        port_text MUST be one or more ASCII digits and parse as u16
    else:
        host = host_port; port = 80
    reject if port == 0
    host MUST end with ".onion"
    label = host without ".onion"
    label MUST be exactly 56 bytes, each in [a-z2-7]          // v3 onion; rejects 16-character labels, upper case, subdomains
    authority = host if port == 80 else host + ":" + port
    return { host, authority, port, path }
```

- Plain `http://` is required. Tor already encrypts and authenticates the
  connection to the onion service, so TLS adds nothing.
- Every `post` and `get` MUST validate its URL before any network operation.
- The client checks only the shape of the label. Arti checks the onion address
  checksum and version when it connects.
- The application also validates mailbox onion labels (56 characters of
  `[a-z2-7]`, optional `.onion` suffix) when the user enters them.

## 6. DNS Leak Prevention

### 6.1 Requirements

- The application MUST NOT resolve any hostname outside Tor. The system resolver
  MUST NOT be used for any purpose.
- Destination hostnames MUST be passed to Arti, which resolves onion addresses
  inside the Tor network.
- There MUST be no HTTP or HTTPS request to a clearnet server, and no NTP, OCSP,
  captive-portal check, analytics or crash reporting.
- Pluggable-transport helpers are separate programs and make their own connections
  to bridge infrastructure (§11.2, §13). This rule governs Najwa's own code.

### 6.2 Startup Hook

Bootstrap runs a DNS-leak startup hook before the transport reports itself
connected (§10.1). The hook MUST NOT issue a DNS query of any kind. If it fails,
bootstrap MUST abort and the transport MUST NOT become connected.

The hook has no failing condition in this release. Remote resolution is guaranteed
by construction: the transport creates only embedded Arti clients, and Arti
receives hostnames directly. A runtime probe of the system resolver is forbidden,
because it would itself disclose the probe name to the local resolver and ISP, and
a non-existent name returns NXDOMAIN even on a leaking resolver.

### 6.3 Static Enforcement

The no-system-resolver rule is enforced in source. The check MUST cover every
crate in the workspace and MUST run in continuous integration, because resolver
calls can appear in any crate. `scripts/check-no-clearnet-dns.sh` scans every Rust
source file under `crates/` and `apps/` (skipping `target/` and `node_modules/`),
runs in `.github/workflows/test.yml`, and fails on any of these patterns:

```
lookup_host | to_socket_addrs | ToSocketAddrs | getaddrinfo | trust_dns | hickory_resolver
```

A line may opt out with a trailing `dns-audit-allow` comment only where the name
appears as data (documentation, the script's own patterns, a test that scans for
the string), never to permit a call. `najwa-transport` also has a unit test that
fails if its own sources contain `lookup_host` or `to_socket_addrs`.

`TcpStream::connect` with a host name also resolves through the system, but cannot
be matched without false positives. Any new direct socket code MUST be reviewed
against §2.

## 7. Clock Synchronisation

### 7.1 Trusted Time Source

- The validity interval of the newest validated Tor consensus is the only network
  input for clock correction.
- Mailbox timestamps (`deposited_at`, HTTP `Date` headers) MUST NOT be used for
  clock correction. They are untrusted.
- NTP and other network time services MUST NOT be used (§6.1).
- When a messaging service holds a handle to its `TorTransport`, protocol
  timestamps are read from `TorClockSync::now()`. Without one, they are read from
  the system clock. Device-local retention timers always use the system clock.

### 7.2 TorClockSync

```rust
struct TorClockSync {
    offset: AtomicI64,   // seconds; corrected time = system time + offset
}
```

```
func synchronize_from_consensus(valid_after, valid_until) → Result<offset>:
    reject if valid_after >= valid_until
           or valid_until > i64::MAX
           or valid_until − valid_after > 86400
    system   = current system time (Unix seconds)
    estimate = clamp(system, valid_after, valid_until − 1)
    offset   = estimate − system
    store offset
    return offset

func now() → u64:
    return clamp(system time + offset, 0, u64::MAX)
```

A consensus attests an interval, not an instant. An already plausible system clock
(inside the interval) keeps offset 0. A clock outside the interval moves only to
the nearest valid boundary. The correction is therefore coarse.

Bootstrap reads the interval from Arti's directory cache
`data_dir/cache/dir.sqlite3`, opened read-only:

```sql
SELECT unixepoch(valid_after), unixepoch(valid_until) FROM Consensuses
 WHERE pending = 0 AND flavor = 'microdesc'
 ORDER BY valid_until DESC LIMIT 1
```

A row is used only if both values are present, `valid_after ≥ 0` and
`valid_until > valid_after`.

### 7.3 Skew Tolerances

Acceptance windows for timestamps are defined by the specs that consume them:
message timestamps in [S07](07-message-format.md), handshake timestamps in
[S05](05-contact-establishment.md). They compare against the protocol clock of §7.1.

### 7.5 Clock-Sync Failure Handling

- If the cache cannot be read, holds no usable row, or the interval is rejected,
  the client logs `Clock sync unavailable — using system time` and keeps offset 0.
- The offset is reset to 0 at the start of every bootstrap, after a failed
  bootstrap, and on shutdown. Clock sync is attempted again on every bootstrap.
- The client MUST NOT refuse to operate because clock sync failed.

## 8. Version-Leak Prevention

- No request may reveal the client version or build. The request builder (§5.1)
  emits only the headers listed in §5.2.
- Request bodies MUST NOT contain client version, application version or user
  agent fields.
- The application performs no network update check.

## 9. Error Handling

```rust
enum TransportError {
    NotBootstrapped,          // no connected client; also a closed request semaphore
    BootstrapFailed(String),  // Arti bootstrap failed
    CircuitFailed(String),    // stream open failed; stale handle; all circuits busy
    NotOnionAddress,          // §5.4
    DnsLeakDetected,          // reserved for the §6.2 hook
    Timeout,                  // connect or request deadline exceeded
    ConnectionRefused,
    ConnectionFailed(String),
    HttpError(String),
    HttpParseError(String),   // §5.1, §5.3
    TorError(String),         // configuration and Tor-subsystem errors
    Io(std::io::Error),
}
```

Bridge lines and transport options MUST NOT appear in error messages or logs.

### 9.1 Retry Strategy

| Situation | Behavior |
|-----------|----------|
| Any failed request | Its isolation entry is retired (§4.4), so the next attempt uses a new circuit |
| Transport error on fetch, acknowledge, PoW challenge or prekey fetch | Up to 3 retries with full-jitter backoff (§9.1.1) on the same isolation value (a `OneShot` challenge retries on a new `OneShot` circuit) |
| Transport error on a deposit, registration, status, prekey publication or deactivation | No transport-level retry. The caller owns the retry; outgoing frames stay in the durable outbox ([S08](08-messaging-service.md)) |
| HTTP 429 on a deposit or prekey fetch | Solve one PoW challenge ([S16 §7](16-mailbox-server.md)) and retry once; a second 429 is returned as `RateLimited` |
| Other HTTP error statuses | Mapped to mailbox errors; not retried at the transport level |
| Bootstrap failure | The connection is reported offline. While the profile is unlocked, the receive worker checks before each poll (exponential gaps, mean 3 s, [S08 §10.1](08-messaging-service.md)) and starts a new bootstrap if none is in progress |
| Saved bridge configuration invalid or helper unavailable | The connection is reported offline and Tor is not started. There is no fallback to direct Tor |
| Tor connectivity lost after bootstrap | Requests fail and are retried as above. Arti rebuilds circuits. The client is not re-bootstrapped |

#### 9.1.1 Full-Jitter Backoff (normative)

```
RETRY_BASE_MS = 1000
RETRY_CAP_MS  = 60000
MAX_RETRIES   = 3

sleep_n = uniform_integer(0, max(1, min(RETRY_CAP_MS, RETRY_BASE_MS × 2^n)))   // milliseconds
          // n = 0-based retry number; exponent capped at 20; CSPRNG, uniform
```

Deterministic backoff (1 s, 2 s, 4 s, …) is forbidden. After a mailbox hiccup,
every affected client would retry on the same schedule, producing synchronized
retry storms that load the server and cluster the affected clients in time.

#### 9.1.2 Randomized Poll Phase (normative)

Recurring schedules (the real mailbox poll loop of
[S08 §6.1](08-messaging-service.md)) MUST start from a per-client CSPRNG phase
offset drawn uniformly over the schedule's interval, generated at first run and
persisted. Client polls MUST NOT align on wall-clock boundaries or on application
launch or unlock times. Phase-aligned polling lets an observer group clients by
implementation and by install cohort.

## 10. TorTransport Implementation

```rust
struct TorTransport {
    config: TorConfig,
    client: RwLock<Option<TorClient<PreferredRuntime>>>,
    circuits: Mutex<HashMap<u64, CircuitEntry>>,   // handle id → entry (§4.3)
    requests: Semaphore,                           // max_circuits permits
    state: AtomicU8,                               // 0 disconnected, 1 connecting, 2 connected
    progress: AtomicU8,                            // 0–100
    clock: TorClockSync,
}

struct CircuitEntry {
    token: IsolationToken,
    isolation: CircuitIsolation,
    created_at: Instant,
    last_used: Instant,
    in_flight: usize,
}

impl TorTransport {
    fn new(config) -> Self
    fn validate_config(config) -> Result<()>                 // §3.1, no network
    async fn bootstrap(&mut self) -> Result<()>              // §10.1
    fn bootstrap_progress(&self) -> u8
    fn is_connected(&self) -> bool
    fn clock(&self) -> &TorClockSync
    async fn shutdown(&mut self) -> Result<()>
    async fn get_circuit(&self, isolation) -> Result<CircuitHandle>
    async fn close_circuit(&self, isolation: &CircuitIsolation) -> Result<()>
    async fn post(&self, circuit, url, body, content_type) -> Result<HttpResponse>
    async fn get(&self, circuit, url) -> Result<HttpResponse>
    async fn cleanup_idle_circuits(&self)
}
```

Request execution (`post` and `get`):

```
func send_request(handle, url, request_bytes):
    parsed = validate_onion_url(url)                         // before any network use
    require state == CONNECTED
    deadline = now + request_timeout_secs
    (token, usage) = begin_request(handle)                   // validates handle, consumes OneShot,
                                                             // otherwise in_flight += 1
    within deadline:
        acquire one of max_circuits request permits
        client = current Arti client                         // lock not held across network awaits
        stream = connect_with_prefs((parsed.host, parsed.port), isolation = token)
                 within connect_timeout_secs                 // Timeout / CircuitFailed
        write request_bytes; read one response (§5.3)
    deadline exceeded → Timeout
    on success: in_flight −= 1; last_used = now
    on failure or cancellation: retire the entry
```

The single deadline covers waiting for a permit, opening the stream, writing and
reading, so a stalled or slow-drip peer cannot extend a request. Shutdown is never
blocked by a stalled peer.

### 10.1 Bootstrap Procedure

```
async func bootstrap():
    client = None; clear circuit registry; clock offset = 0
    state = CONNECTING; progress = 5
    config = build_arti_config()                 // §3.1; fails closed
    progress = 10
    client = TorClient::create_bootstrapped(config).await   // BootstrapFailed on error
    wait until client.bootstrap_status().ready_for_traffic()
                                                 // a channel to the first hop finished
                                                 // its handshake; polled every 250 ms
    if newest consensus interval is readable:    // §7.2
        clock.synchronize_from_consensus(interval)   // failure only logged (§7.5)
    dns_leak_startup_hook()?                     // §6.2; failure aborts
    publish client
    state = CONNECTED; progress = 100
    // on any failure: state = DISCONNECTED, progress = 0, clock offset = 0
```

Arti's own bootstrap completes as soon as it has a usable directory, and a
directory loaded from the on-disk cache needs no network contact. A profile that
connected directly before bridges were configured keeps that cache, so without
the wait an unreachable bridge would report connected. The wait makes CONNECTED
mean that Tor reached its first hop: a guard, or with bridges (§11) a configured
bridge. Until then the transport stays CONNECTING.

Bootstrap has no deadline of its own; Arti governs it. In the application, the
native service bootstraps Tor after each unlock unless a Tor client from earlier
in the same process is still alive, in which case it reuses that client. A lock
keeps the Tor client alive for cover traffic ([S10 §11](10-cover-traffic.md)).

## 11. Bridge Support

For networks where direct Tor access is blocked:

| Bridge type | Transport | Accepted by the application |
|-------------|-----------|-----------------------------|
| Plain | Direct TCP to the bridge relay | Yes |
| obfs4 | Pluggable transport (bundled `lyrebird`) | Yes |
| Snowflake | Pluggable transport (bundled `lyrebird`) | Yes |
| meek | Pluggable transport | No (rejected as `invalid_bridges`) |

The transport crate normalizes each `BridgeConfig` before adding it to Arti:

```
func normalize_bridge(bridge) → String:
    reject if address is blank or contains CR or LF
    words = address split on whitespace; drop a leading "Bridge"
    if bridge_type has a protocol name P:
        reject unless a PluggableTransportConfig for P exists
        if words[0] parses as IP:port: insert P before it
        reject unless words[0] == P
    else (Plain):
        reject unless words[0] parses as IP:port
    if bridge.fingerprint is set:
        it MUST be 40 hex characters
        i = 2 if P exists else 1
        if words[i] is a 40-hex fingerprint: reject if it differs (case-insensitive)
        else insert the fingerprint at position i
    return words joined with single spaces   // then parsed by Arti; parse errors are rejected
```

### 11.1 Bridge Distribution

- Bridges are entered manually. The user chooses "Use bridges" in Settings and
  pastes bridge lines, for example from the Tor Project's bridge distribution.
  There are no built-in bridges and no automatic bridge retrieval.
- The native service validates the lines before saving:
  - at most 8 lines, at most 16,384 bytes in total, at most 4,096 bytes per line;
  - no CR, LF or NUL in a line; runs of whitespace collapse to one space;
  - an optional leading `Bridge ` is allowed;
  - the first word MUST be `obfs4`, `snowflake` or an `IP:port` socket address.
    Anything else, including `meek`, `webtunnel` and host names, is rejected.
- The native service then builds the complete Arti configuration (§3.1) with the
  bundled helper verified (§11.2). Any failure rejects the change and saves nothing.
- Bridge lines are stored in the encrypted profile database
  ([S03](03-encrypted-storage.md)) under the settings key
  `desktop:local-preferences`, as JSON
  `{"lockTimeoutSeconds": <u32>, "bridges": [<line>, …]}`. Unknown fields are
  rejected. A stored value that fails validation MUST be treated as an error,
  never as "no bridges".
- Bridge lines are never sent to mailbox servers and MUST NOT be logged.
- When a saved change alters the bridge list, the native service locks the
  profile, cancels in-flight operations and destroys the messaging runtime,
  including the Tor client and the cover scheduler. The new routing applies when
  the profile is next unlocked. A change that leaves the bridge list unchanged
  does not restart Tor.
- An empty bridge list means direct Tor.
- With bridges, Arti uses only the configured bridges as first hops and never
  falls back to direct directory fetches. While no bridge is reachable the
  connection stays `connecting`, even when a directory cached by an earlier
  direct session is present (§10.1).

### 11.2 Bundled Pluggable-Transport Helper

- The helper is `lyrebird` from the Tor Project's Tor expert bundle, version
  15.0.26, pinned in `tor-transports.json`. For each platform the manifest records
  the archive name and SHA-256, the member path and SHA-256 of the binary, and the
  license member and its SHA-256. It also records the signing-key fingerprint of
  the release.
- Pinned platforms: `windows-x86_64`, `linux-x86_64`, `macos-aarch64`,
  `macos-x86_64`.
- At build time, `scripts/fetch-tor-transports.py` downloads the archive, verifies
  its SHA-256, extracts only the two named members (regular files of at most
  32 MiB), verifies each member's SHA-256 and writes `lyrebird` (`lyrebird.exe` on
  Windows) and `LYREBIRD-LICENSES.txt` into a `transports/` directory next to the
  executable (`Contents/Resources/transports` in a macOS bundle). It never executes
  archive content.
- At run time, before building any configuration that uses obfs4 or Snowflake, the
  native service computes the SHA-256 of the packaged helper and compares it with
  the manifest entry for `{os}-{arch}`. A missing file, a missing platform entry or
  a mismatch MUST fail with `bridge_helper_unavailable`, and Tor is not started.
- The service adds one transport entry per protocol in use. Both point at the same
  helper, with no extra arguments. Arti launches the helper at startup.
- Plain bridges need no helper.
- The browser UI never chooses an executable path.

## 12. Rust Crate Dependencies

See [Dependencies](../security/dependencies.md) and
[Supply chain](../security/supply-chain.md) for the audited dependency set.

| Crate | Version | Purpose |
|-------|---------|---------|
| `arti-client` | 0.40.0 | Embedded Tor client; default features off; `tokio`, `onion-service-client`, `rustls`, `bridge-client`, `pt-client` |
| `tor-rtcompat` | 0.40.0 | Arti runtime on tokio |
| `rusqlite` | 0.38 | Reads Arti's consensus cache (§7.2); its `bundled-sqlcipher-vendored-openssl` feature unifies the SQLite library that Arti's directory manager also links |
| `tokio` | 1 | Async runtime, timeouts, semaphore |
| `async-trait`, `serde`, `thiserror`, `tracing` | workspace | Interfaces, configuration serialization, errors, logging |

## 13. Security Considerations

- **Scope of Tor.** Tor hides the client's network location from the mailbox and
  hides the destination from the local network. It does not protect against a
  malicious mailbox operator beyond what end-to-end encryption already provides,
  and it does not fix an expired capability, a full quota or lost peer history.
- **Traffic analysis.** Circuit isolation separates operations from the point of
  view of a single relay or mailbox. It does not stop an adversary who watches
  both the user's guard and the mailbox from correlating timing. Responsive
  delivery does not produce an activity-independent network trace.
  [S10](10-cover-traffic.md) states the cover-traffic limits.
- **Circuit construction is visible to the guard.** Every deposit, real or cover,
  builds a fresh onion-service circuit, so the circuit build does not separate
  real deposits from cover. Cover polls reuse one circuit per own mailbox, as
  real fetches do. An observer at the guard can still see deposits to mailboxes
  that cover never targets: cover goes only to the user's own mailboxes
  ([S10 §15](10-cover-traffic.md)).
- **PoW challenges.** `/v1/challenge` uses the isolation of the request it gates
  (§4.1.1), so the challenge links the gated request to nothing else the user
  sends. The gated request itself and its challenge go to the same mailbox at
  nearly the same time on separate `OneShot` circuits (one shared `ByContact`
  circuit for a prekey fetch), so the operator can still pair them by timing.
- **Responsive file circuits.** In Responsive mode, the parts of one file share a
  circuit, so the mailbox operator sees them as one stream of deposits. They are
  already linkable by size and timing. Timing privacy uses a fresh circuit per part.
- **Pluggable transports.** obfs4 connects directly to the bridge's IP address.
  Snowflake contacts a broker through a front domain and uses public STUN servers.
  The helper may resolve those names with the system resolver. This can reveal that
  a circumvention transport is in use. It does not reveal mailbox addresses.
- **Clock.** Correction from the consensus is coarse (§7.2). A badly wrong device
  clock still causes peers to reject timestamps.

## 14. Conformance Checklist

- Embedded Arti only; other modes, zero limits and invalid transport or bridge
  configuration rejected before Tor starts (§3, §3.1).
- No clearnet fallback; failed bootstrap or invalid saved bridges leave the client
  offline (§2, §9.1).
- Connected only after a channel to the first hop (guard or bridge) completed; a
  cached directory alone never counts (§10.1, §11).
- Circuit isolation types and the §4.1.1 assignments: `OneShot` for every real
  deposit attempt, every cover deposit and every registration, `ByContact` for
  prekey fetch, the gated request's isolation for a PoW challenge,
  `CoverTraffic(onion)` for cover polls and acknowledgements, `FileTransfer` only
  for Responsive file parts, `ByMailbox` otherwise.
- `OneShot` tokens consumed before the first await; failed requests retire their
  token (§4.3, §4.4).
- Rotation at 600 s age and `circuit_timeout_secs` idle; LRU eviction never evicts
  an active entry (§4.4).
- Raw HTTP/1.1 requests with only `Host`, `Connection`, `Content-Type` and
  `Content-Length`; request-field validation against injection (§5.1, §5.2).
- Bounded response parsing per §5.3, including framing conflicts, chunked bodies,
  trailers and size limits.
- Single request deadline covering permit wait, connect, write and read (§10).
- `.onion` v3 URL validation before any network use (§5.4).
- DNS-leak startup hook with no DNS query, failing closed (§6.2); source scan
  script and transport unit test for system-resolver APIs (§6.3).
- Consensus-interval clock correction with fallback to system time (§7.2, §7.5).
- Full-jitter CSPRNG backoff, 3 retries, 60 s cap (§9.1.1).
- Bridge validation, encrypted storage, no logging, runtime teardown on change
  (§11, §11.1).
- Pinned `lyrebird` helper verified by SHA-256 at build time and at run time (§11.2).
- Unit tests for URL validation, request building, response parsing, deadlines,
  token lifecycle, bridge configuration and clock sync.
