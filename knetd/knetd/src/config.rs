//! Configuration file loading and validation.
//!
//! The daemon configuration is loaded from a TOML file with optional
//! pre-configured VPN instances that can be auto-started on daemon launch.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),
}

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the Unix domain socket for RPC communication
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Log level (info, debug, trace, etc.)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable colored log output (default: false for plain text)
    #[serde(default = "default_colored_logs")]
    pub colored_logs: bool,

    /// Optional path to save daemon state for persistence across restarts
    #[serde(default)]
    pub state_file: Option<String>,

    /// Disable privileged mode even when running as root (default: false)
    /// When false (default), running as root will enable PRIVILEGED mode on knet handles
    #[serde(default = "default_disable_privileged")]
    pub disable_privileged: bool,

    /// Users allowed to connect to the RPC socket, in addition to root (UID 0)
    /// Each entry is either a username (resolved to UID at startup) or a numeric UID
    /// If empty, only root may connect
    #[serde(default)]
    pub allowed_users: Vec<String>,

    /// Pre-configured VPN instances to create on daemon startup
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
}

/// Configuration for a single VPN instance.
///
/// This configuration is node-agnostic - the same config file can be deployed
/// to all nodes in the cluster. Each node identifies itself via the KNETD_NODE_ID
/// environment variable or command-line argument, and only configures the hosts
/// and links relevant to itself.
///
/// Two modes are supported:
/// 1. Manual mode: Define nodes and links explicitly
/// 2. Full-mesh mode: Set full_mesh=true and define nodes with link addresses;
///    the daemon automatically creates bidirectional links between all nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Unique name for this instance
    pub name: String,

    /// Whether to automatically start this instance on daemon launch
    #[serde(default)]
    pub auto_start: bool,

    /// Enable full-mesh mode: automatically create bidirectional links between all nodes
    /// When enabled, nodes must have link_addresses defined, and the links field is ignored
    #[serde(default)]
    pub full_mesh: bool,

    /// All hosts/nodes in this VPN cluster
    /// Each daemon will identify which one is "me" and add the others as remote hosts
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,

    /// All links in the cluster, defined bidirectionally (manual mode only)
    /// Each daemon will only configure links where it is the source
    /// Ignored if full_mesh is enabled
    #[serde(default)]
    pub links: Vec<LinkConfig>,

    /// Nozzle (tap device) configuration (optional)
    /// If specified, a tap device will be created and attached to this instance
    #[serde(default)]
    pub nozzle: Option<NozzleConfig>,

    /// Cryptographic configuration (optional)
    /// If specified, encryption will be enabled on this instance
    #[serde(default)]
    pub crypto: Option<CryptoConfig>,

    /// Compression configuration (optional)
    /// If specified, compression will be enabled on this instance
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
}

/// Configuration for a nozzle (tap) device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NozzleConfig {
    /// Device name (e.g., "knet0")
    /// If not specified, kernel assigns a name
    pub name: Option<String>,

    /// IP addresses to assign to the device
    /// Format: ["192.168.1.1/24", "10.0.0.1/16"]
    #[serde(default)]
    pub ip_addresses: Vec<String>,

    /// MTU for the tap device (optional)
    pub mtu: Option<i32>,

    /// MAC address for the tap device (optional)
    /// Format: "00:11:22:33:44:55"
    pub mac: Option<String>,

    /// Path to up/down scripts directory (optional)
    pub updown_path: Option<String>,

    /// Automatically bring the device up after creation
    #[serde(default = "default_true")]
    pub auto_up: bool,
}

/// Configuration for cryptography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Crypto model (e.g., "openssl", "nss", "gcrypt")
    pub model: String,

    /// Cipher type (e.g., "aes256", "aes128", "aes192")
    pub cipher: String,

    /// Hash type (e.g., "sha256", "sha512", "sha1")
    pub hash: String,

    /// Path to the key file containing at least 1024 bytes
    pub key_file: String,

    /// Configuration slot number (0 or 1) - knet supports 2 concurrent configs for key rotation
    #[serde(default)]
    pub config_num: u8,
}

/// Configuration for compression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Compression model (e.g., "zlib", "lz4", "lz4hc", "lzo2", "lzma", "bzip2", "zstd")
    pub model: String,

    /// Threshold in bytes - packets smaller than this won't be compressed
    /// Set to 0 for default (100 bytes)
    #[serde(default)]
    pub threshold: u32,

    /// Compression level (meaning varies by model, typically 1-9)
    #[serde(default = "default_compression_level")]
    pub level: i32,
}

fn default_true() -> bool {
    true
}

fn default_compression_level() -> i32 {
    1
}

/// Configuration for a node in the VPN cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Host ID for this node (0-65535)
    pub host_id: u16,

    /// Human-readable name for this node
    pub name: String,

    /// Link addresses for full-mesh mode (optional)
    /// Each entry is a "address:port" string for a different link
    /// The link_id is the index in this array (0-7)
    /// Example: ["192.168.1.1:5000", "10.0.0.1:5000"] creates link 0 and link 1
    #[serde(default)]
    pub link_addresses: Vec<String>,
}

/// Configuration for a link between two nodes.
///
/// Links are unidirectional from the perspective of configuration.
/// For bidirectional connectivity, define two links (one in each direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkConfig {
    /// Source node host ID (the node that initiates this link)
    pub from_host: u16,

    /// Destination node host ID (the remote node)
    pub to_host: u16,

    /// Link ID (0-7, up to 8 links per host pair)
    pub link_id: u8,

    /// Transport type (e.g., "udp", "sctp")
    #[serde(default = "default_transport")]
    pub transport: String,

    /// Local address:port on the source node
    pub src_addr: String,

    /// Remote address:port on the destination node
    pub dst_addr: Option<String>,

    /// Whether to automatically enable this link after configuration
    #[serde(default)]
    pub auto_enable: bool,
}

fn default_transport() -> String {
    "udp".to_string()
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            log_level: default_log_level(),
            colored_logs: default_colored_logs(),
            state_file: None,
            disable_privileged: default_disable_privileged(),
            allowed_users: Vec::new(),
            instances: Vec::new(),
        }
    }
}

// Default configuration values
fn default_socket_path() -> String {
    "/run/knetd/knetd.sock".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_colored_logs() -> bool {
    false
}

fn default_disable_privileged() -> bool {
    false
}

/// Load configuration from a TOML file.
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_config(path: impl AsRef<Path>) -> Result<DaemonConfig, ConfigError> {
    let contents = fs::read_to_string(path)?;
    let config = toml::from_str(&contents)?;
    Ok(config)
}
