//! Tor configuration and bridge settings.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level Tor transport configuration (S04 §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// How to reach the Tor network.
    pub mode: TorMode,
    /// Directory for Tor state (consensus cache, keys, etc.).
    pub data_dir: PathBuf,
    /// Bridge lines for censored networks.
    pub bridges: Vec<BridgeConfig>,
    /// Executables managed by Arti for the configured bridge protocols.
    #[serde(default)]
    pub transports: Vec<PluggableTransportConfig>,
    /// Maximum number of concurrent circuits.
    pub max_circuits: u32,
    /// Per-circuit inactivity timeout in seconds.
    pub circuit_timeout_secs: u32,
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: u32,
    /// Deadline for the complete connect/write/read exchange.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u32,
}

fn default_request_timeout() -> u32 {
    120
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            mode: TorMode::Embedded,
            data_dir: PathBuf::from("tor_data"),
            bridges: Vec::new(),
            transports: Vec::new(),
            max_circuits: 8,
            circuit_timeout_secs: 60,
            connect_timeout_secs: 60,
            request_timeout_secs: default_request_timeout(),
        }
    }
}

/// How the application reaches the Tor network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TorMode {
    /// Embedded Arti client (default for desktop).
    Embedded,
    /// External SOCKS5 proxy (e.g. system Tor daemon).
    SystemSocks { addr: SocketAddr },
    /// Orbot integration (Android).
    Orbot,
}

/// A single bridge configuration line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Transport type used by this bridge.
    pub bridge_type: BridgeType,
    /// Bridge address (host:port or transport-specific).
    pub address: String,
    /// Optional relay fingerprint.
    pub fingerprint: Option<String>,
}

/// Pluggable transport / bridge types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeType {
    /// Direct bridge (no pluggable transport).
    Plain,
    /// obfs4 scramblesuit.
    Obfs4,
    /// Meek (domain-fronting).
    Meek,
    /// Snowflake (WebRTC).
    Snowflake,
}

/// A managed PT executable. Bridge-specific options (cert, url, front, etc.)
/// belong in the bridge line; process arguments belong here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluggableTransportConfig {
    pub bridge_type: BridgeType,
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
}

impl BridgeType {
    pub(crate) fn protocol(self) -> Option<&'static str> {
        match self {
            Self::Plain => None,
            Self::Obfs4 => Some("obfs4"),
            Self::Meek => Some("meek"),
            Self::Snowflake => Some("snowflake"),
        }
    }
}

/// VPN-mode Tor configuration for mobile platforms. Not used by the desktop
/// application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnModeTorConfig {
    /// Whether VPN mode is active.
    pub enabled: bool,
    /// Keep Tor connection warm between requests.
    pub keep_alive: bool,
    /// Enable cover traffic in VPN mode.
    pub cover_traffic: bool,
    /// Disable VPN mode below this battery percentage.
    pub battery_threshold: u8,
}

impl Default for VpnModeTorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keep_alive: false,
            cover_traffic: false,
            battery_threshold: 20,
        }
    }
}
