//! JSON-RPC 2.0 request and response message definitions.
//!
//! Each RPC method has a corresponding Request and Response struct.
//! These are serialized to/from JSON for communication between knetctl and knetd.

use serde::{Deserialize, Serialize};
use crate::{InstanceName, HostId, LinkId, InstanceInfo, HostInfo, LinkInfo, LinkStats, NozzleInfo};

fn default_true() -> bool { true }

/// Serde helper: encode `Vec<u8>` as a base64 string on the wire instead of
/// a JSON integer array.  A 1 KiB key as integers is ~5 KiB of JSON; as
/// base64 it is ~1.4 KiB and survives round-trips through any JSON parser.
mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64: {e}")))
    }
}

// ============================================================================
// Instance Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstanceRequest {
    pub name: InstanceName,
    pub host_id: HostId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstanceResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyInstanceRequest {
    pub name: InstanceName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyInstanceResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInstancesRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInstancesResponse {
    pub instances: Vec<InstanceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetForwardingRequest {
    pub instance: InstanceName,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetForwardingResponse {
    pub success: bool,
}

// ============================================================================
// Host Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddHostRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddHostResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveHostRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveHostResponse {
    pub success: bool,
}

// ============================================================================
// Host Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListHostsRequest {
    pub instance: InstanceName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListHostsResponse {
    pub hosts: Vec<HostInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHostStatusRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHostStatusResponse {
    pub host: HostInfo,
}

// ============================================================================
// Link Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLinkConfigRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
    pub link_id: LinkId,
    /// Transport type (e.g., "udp")
    pub transport: String,
    /// Local address:port (e.g., "10.0.0.1:5000")
    pub src_addr: String,
    /// Remote address:port (None for dynamic links)
    pub dst_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLinkConfigResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLinkEnableRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
    pub link_id: LinkId,
    pub enable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLinkEnableResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLinkStatusRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
    pub link_id: LinkId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLinkStatusResponse {
    pub link: LinkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLinkStatsRequest {
    pub instance: InstanceName,
    pub host_id: HostId,
    pub link_id: LinkId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLinkStatsResponse {
    pub stats: LinkStats,
}

// ============================================================================
// Crypto and Compression
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCryptoConfigRequest {
    pub instance: InstanceName,
    /// Crypto model (e.g., "openssl", "nss", "gcrypt", or "none" to disable)
    pub model: String,
    /// Cipher type (e.g., "aes256", "aes128", "aes192", or "none" to disable encryption)
    pub cipher: String,
    /// Hash type (e.g., "sha256", "sha512", "sha1", or "none" to disable hashing)
    pub hash: String,
    /// Private key bytes (must be at least 1024 bytes for knet), base64-encoded on the wire
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    /// Configuration slot number (0 or 1) - knet supports 2 concurrent configs
    #[serde(default)]
    pub config_num: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCryptoConfigResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseCryptoConfigRequest {
    pub instance: InstanceName,
    /// Configuration slot to activate for TX (0 or 1)
    pub config_num: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseCryptoConfigResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCompressionConfigRequest {
    pub instance: InstanceName,
    /// Compression model (e.g., "zlib", "lz4", "lz4hc", "lzo2", "lzma", "bzip2", "zstd", or "none" to disable)
    pub model: String,
    /// Threshold in bytes - packets smaller than this won't be compressed (0 = default 100 bytes)
    pub threshold: u32,
    /// Compression level (meaning varies by model, typically 1-9)
    pub level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCompressionConfigResponse {
    pub success: bool,
}

// ============================================================================
// Nozzle (tap device) Management
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNozzleRequest {
    pub instance: InstanceName,
    /// Desired tap device name; None lets the kernel assign one
    pub name: Option<String>,
    /// IP addresses to assign, as "IP/PREFIX" strings
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    /// MTU override; None keeps the default
    pub mtu: Option<i32>,
    /// Base MAC address ("XX:XX:XX:XX"); the daemon embeds the node ID in the last two bytes
    pub mac: Option<String>,
    /// Path to up/down scripts directory
    pub updown_path: Option<String>,
    /// Bring the device up automatically when forwarding is enabled
    #[serde(default = "default_true")]
    pub auto_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNozzleResponse {
    pub success: bool,
    /// Actual kernel device name that was assigned
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyNozzleRequest {
    pub instance: InstanceName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyNozzleResponse {
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNozzleStatusRequest {
    pub instance: InstanceName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNozzleStatusResponse {
    /// None if no nozzle device is attached to the instance
    pub nozzle: Option<NozzleInfo>,
}

// ============================================================================
// Event Subscription
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeEventsRequest {
    pub instance: InstanceName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeEventsResponse {
    /// Subscription ID for later polling
    pub subscription_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollEventsRequest {
    pub subscription_id: String,
    /// Maximum number of events to return (default 10)
    pub max_events: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollEventsResponse {
    pub events: Vec<crate::DaemonEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeEventsRequest {
    pub subscription_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeEventsResponse {
    pub success: bool,
}

// ============================================================================
// State dump
// ============================================================================

/// Request a snapshot of the daemon's current state as an opaque JSON value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpStateRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpStateResponse {
    /// Complete daemon state in the same JSON format as the knetd state file.
    pub state: serde_json::Value,
}

// ============================================================================
// Utility
// ============================================================================

/// Simple ping request to test daemon connectivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    pub pong: String,
}
