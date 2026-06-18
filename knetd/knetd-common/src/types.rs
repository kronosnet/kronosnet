//! Core type definitions shared between daemon and CLI.
//!
//! These types provide type-safe wrappers around primitive types and
//! include conversions to/from the knet-bindings types.

use serde::{Deserialize, Serialize};

/// A VPN instance name.
///
/// Each VPN instance is identified by a unique string name. The daemon can
/// manage multiple independent VPN instances simultaneously.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceName(pub String);

impl InstanceName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InstanceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A host identifier within a VPN instance.
///
/// Valid range: 0-65535 (KNET_MAX_HOST)
/// Each host in a knet VPN mesh has a unique ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostId(pub u16);

impl HostId {
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn to_u16(self) -> u16 {
        self.0
    }
}

// Conversion to/from knet-bindings types for API calls
impl From<HostId> for knet_bindings::knet_bindings::HostId {
    fn from(id: HostId) -> Self {
        knet_bindings::knet_bindings::HostId::new(id.0)
    }
}

impl From<knet_bindings::knet_bindings::HostId> for HostId {
    fn from(id: knet_bindings::knet_bindings::HostId) -> Self {
        Self(id.to_u16())
    }
}

/// A link identifier between hosts.
///
/// Valid range: 0-7 (KNET_MAX_LINK is 8)
/// Each pair of hosts can have up to 8 simultaneous links for redundancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkId(pub u8);

impl LinkId {
    /// Creates a new LinkId. Caller should validate that id < 8.
    pub fn new(id: u8) -> Self {
        Self(id)
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }
}

/// Information about a VPN instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub name: InstanceName,
    /// The local host ID for this VPN instance
    pub host_id: HostId,
    /// Whether the instance is currently running (handle created and forwarding enabled)
    pub running: bool,
    /// Crypto configuration (if enabled)
    #[serde(default)]
    pub crypto: Option<CryptoInfo>,
    /// Compression configuration (if enabled)
    #[serde(default)]
    pub compression: Option<CompressionInfo>,
}

/// Information about crypto configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInfo {
    pub model: String,
    pub cipher: String,
    pub hash: String,
}

/// Information about compression configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionInfo {
    pub model: String,
    pub threshold: u32,
    pub level: i32,
}

/// Information about a remote host in a VPN instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub host_id: HostId,
    /// Optional human-readable name for this host
    pub name: Option<String>,
    /// Whether this host is currently reachable via any link
    pub reachable: bool,
}

/// Information about a link to a remote host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    pub link_id: LinkId,
    /// Transport type (e.g., "udp", "loopback")
    pub transport: String,
    /// Local address:port (if configured)
    pub src_addr: Option<String>,
    /// Remote address:port (if configured, None for dynamic links)
    pub dst_addr: Option<String>,
    /// Whether the link is enabled for traffic
    pub enabled: bool,
    /// Whether the link is currently connected (receiving heartbeats)
    pub connected: bool,
}

/// Statistics for a link.
///
/// These counters are cumulative since the link was configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkStats {
    pub tx_data_packets: u64,
    pub rx_data_packets: u64,
    pub tx_data_bytes: u64,
    pub rx_data_bytes: u64,
    /// Minimum latency in microseconds
    pub latency_min: u32,
    /// Maximum latency in microseconds
    pub latency_max: u32,
    /// Average latency in microseconds
    pub latency_ave: u32,
    /// Number of times the link went down
    pub down_count: u32,
    /// Number of times the link came up
    pub up_count: u32,
}
