//! VPN instance management.
//!
//! Each VPN instance wraps a knet::Handle and manages its lifecycle,
//! including logging, host tracking, and proper cleanup.

use anyhow::{Context, Result};
use knet_bindings::knet_bindings as knet;
use nozzle_bindings::nozzle_bindings as nozzle;
use knetd_common::{DaemonEvent, HostId, InstanceName, LinkId, NozzleInfo};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex as StdMutex, OnceLock};
use std::thread;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use chrono::Utc;

/// Entry in the event registry for routing C callbacks to event channels.
type EventRegistryEntry = (InstanceName, broadcast::Sender<DaemonEvent>);
type EventRegistryMap = HashMap<usize, EventRegistryEntry>;

/// Global registry mapping knet handle pointers to (instance_name, event_sender).
///
/// This allows C callbacks to find the event channel to send to.
/// We use the handle's pointer address as a unique key.
static EVENT_REGISTRY: OnceLock<StdMutex<EventRegistryMap>> = OnceLock::new();

fn get_event_registry() -> &'static StdMutex<EventRegistryMap> {
    EVENT_REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Wrapper for nozzle::Handle pointer that can be sent between threads.
///
/// SAFETY: The actual nozzle operations are protected by mutex in the daemon state,
/// ensuring serialized access. We only ever access the handle from one thread at a time.
struct SendNozzleHandle(*mut nozzle::Handle);
unsafe impl Send for SendNozzleHandle {}

/// Global registry mapping instance names to nozzle handle raw pointers.
///
/// Nozzle handles are not Send (contain raw pointers), so we store them as SendNozzleHandle.
/// SAFETY: All access to nozzle handles happens from tokio runtime threads via the
/// mutex-protected VpnInstance, ensuring single-threaded access.
/// IMPORTANT: nozzle_close() destroys the device, so we must keep handles alive!
static NOZZLE_REGISTRY: OnceLock<StdMutex<HashMap<String, SendNozzleHandle>>> = OnceLock::new();

fn get_nozzle_registry() -> &'static StdMutex<HashMap<String, SendNozzleHandle>> {
    NOZZLE_REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Callback for link status changes from knet.
fn link_status_change_callback(
    private_data: u64,
    host_id: knet::HostId,
    link_id: u8,
    connected: bool,
    remote: bool,
    external: bool,
) {
    let handle_ptr = private_data as usize;
    let registry = get_event_registry().lock().unwrap();

    if let Some((instance_name, sender)) = registry.get(&handle_ptr) {
        let event = DaemonEvent::LinkStatusChange {
            instance: instance_name.clone(),
            host_id: HostId::from(host_id),
            link_id: LinkId::new(link_id),
            connected,
            remote,
            external,
            timestamp: Utc::now(),
        };

        // Ignore send errors (no subscribers is OK)
        let _ = sender.send(event);
    }
}

/// Callback for host status changes from knet.
fn host_status_change_callback(
    private_data: u64,
    host_id: knet::HostId,
    reachable: bool,
    remote: bool,
    external: bool,
) {
    let handle_ptr = private_data as usize;
    let registry = get_event_registry().lock().unwrap();

    if let Some((instance_name, sender)) = registry.get(&handle_ptr) {
        let event = DaemonEvent::HostStatusChange {
            instance: instance_name.clone(),
            host_id: HostId::from(host_id),
            reachable,
            remote,
            external,
            timestamp: Utc::now(),
        };

        let _ = sender.send(event);
    }
}

/// Callback for socket notifications (datafd errors) from knet.
///
/// This is called when knet detects an error or EOF on a datafd.
/// For tap devices, this typically means the device was closed or has an error.
fn sock_notify_callback(
    private_data: u64,
    datafd: i32,
    channel: i8,
    txrx: knet::TxRx,
    res: std::io::Result<()>,
) {
    let handle_ptr = private_data as usize;
    let registry = get_event_registry().lock().unwrap();

    if let Some((instance_name, _sender)) = registry.get(&handle_ptr) {
        let dir = match txrx {
            knet::TxRx::Tx => "TX",
            knet::TxRx::Rx => "RX",
        };

        match res {
            Ok(()) => {
                // EOF (0 bytes read/written)
                warn!("[{}] Socket notification: EOF on datafd {} channel {} ({})",
                      instance_name.as_str(), datafd, channel, dir);
            }
            Err(e) => {
                // Error on read/write
                error!("[{}] Socket notification: Error on datafd {} channel {} ({}): {}",
                       instance_name.as_str(), datafd, channel, dir, e);
            }
        }
    }
}

/// A VPN instance wrapping a libknet handle.
///
/// This structure manages the complete lifecycle of a knet VPN instance,
/// including initialization, logging, and proper cleanup.
pub struct VpnInstance {
    /// Instance name
    pub name: InstanceName,

    /// Local host ID for this instance
    pub host_id: HostId,

    /// Underlying knet handle
    handle: knet::Handle,

    /// Log message sender (kept alive to prevent channel close)
    /// When this is dropped, the logging thread will exit
    _log_sender: Sender<knet::LogMsg>,

    /// Tracked remote hosts in this instance
    hosts: HashMap<HostId, HostMetadata>,

    /// Whether data forwarding is enabled
    forwarding_enabled: bool,

    /// Data file descriptors registered with knet
    data_fds: Vec<i32>,

    /// Event broadcaster for async notifications
    event_tx: broadcast::Sender<DaemonEvent>,

    /// Nozzle (tap device) metadata; None if no tap device is attached.
    nozzle_meta: Option<NozzleMetadata>,

    /// Current crypto configuration (for state persistence)
    crypto_config: Option<CryptoMetadata>,

    /// Current compression configuration (for state persistence)
    compression_config: Option<CompressionMetadata>,
}

/// Metadata stored for a nozzle device after creation.
#[derive(Debug, Clone)]
struct NozzleMetadata {
    device_name: String,
    /// Original "IP/PREFIX" strings as supplied by the caller (before node-ID embedding)
    ip_addresses: Vec<String>,
    mtu: Option<i32>,
    mac: Option<String>,
    updown_path: Option<String>,
    auto_up: bool,
    /// The knet datafd assigned when the nozzle FD was registered; needed for removal.
    datafd: i32,
}

/// Metadata for crypto configuration.
#[derive(Debug, Clone)]
struct CryptoMetadata {
    model: String,
    cipher: String,
    hash: String,
    key_file: String,
    config_num: u8,
}

/// Metadata for compression configuration.
#[derive(Debug, Clone)]
struct CompressionMetadata {
    model: String,
    threshold: u32,
    level: i32,
}

/// Metadata for a remote host.
#[derive(Debug, Clone)]
struct HostMetadata {
    /// Optional human-readable name
    name: Option<String>,

    /// Links configured for this host
    links: HashMap<u8, LinkMetadata>,
}

/// Metadata for a link.
#[derive(Debug, Clone)]
struct LinkMetadata {
    /// Whether the link is enabled
    enabled: bool,
}

impl VpnInstance {
    /// Create a new VPN instance.
    ///
    /// This initializes a knet handle with the given host ID and sets up
    /// logging infrastructure.
    ///
    /// # Arguments
    /// * `name` - Unique name for this instance
    /// * `host_id` - Local host ID (0-65535)
    /// * `privileged` - Whether to enable privileged mode (allows certain operations when running as root)
    ///
    /// # Returns
    /// A new VpnInstance ready for configuration
    pub fn new(name: InstanceName, host_id: HostId, privileged: bool, log_level: &str) -> Result<Self> {
        info!("Creating VPN instance '{}' with host_id {}", name.as_str(), host_id.to_u16());

        // Create logging channel
        let (log_sender, log_receiver) = channel::<knet::LogMsg>();

        // Spawn logging thread
        let instance_name = name.clone();
        let log_thread = thread::spawn(move || {
            logging_thread(instance_name, log_receiver);
        });

        // Parse log level to match daemon's level
        let knet_log_level = match log_level.to_lowercase().as_str() {
            "trace" => knet::LogLevel::Trace,
            "debug" => knet::LogLevel::Debug,
            "info" => knet::LogLevel::Info,
            "warn" => knet::LogLevel::Warn,
            "error" => knet::LogLevel::Err,
            _ => knet::LogLevel::Info, // Default to Info
        };

        // Create knet handle with appropriate flags
        let knet_host_id = knet::HostId::from(host_id);
        let flags = if privileged {
            knet::HandleFlags::PRIVILEGED
        } else {
            knet::HandleFlags::NONE
        };

        let handle = knet::handle_new(
            &knet_host_id,
            Some(log_sender.clone()),
            knet_log_level,
            flags,
        )?;

        if privileged {
            info!("Created knet handle for instance '{}' with PRIVILEGED mode", name.as_str());
        } else {
            debug!("Created knet handle for instance '{}'", name.as_str());
        }

        // Create event broadcaster (capacity of 100 events)
        let (event_tx, _event_rx) = broadcast::channel(100);

        // Register event callbacks with knet.
        // Use handle.knet_handle (the underlying C pointer value, a stable u64) as
        // the registry key — this value is unchanged by Rust struct moves, so Drop
        // can remove the entry by self.handle.knet_handle even after the move into Self.
        let handle_ptr = handle.knet_handle as usize;

        // Register in global registry
        {
            let mut registry = get_event_registry().lock().unwrap();
            registry.insert(handle_ptr, (name.clone(), event_tx.clone()));
        }

        // Enable link status change notifications
        knet::link_enable_status_change_notify(&handle, handle_ptr as u64, Some(link_status_change_callback))?;

        // Enable host status change notifications
        knet::host_enable_status_change_notify(&handle, handle_ptr as u64, Some(host_status_change_callback))?;

        // Enable socket notification for datafd error handling
        // This is REQUIRED before adding any datafds
        knet::handle_enable_sock_notify(&handle, handle_ptr as u64, Some(sock_notify_callback))?;

        // Detach the logging thread - it will run until the channel closes
        // (when _log_sender is dropped)
        drop(log_thread);

        Ok(Self {
            name,
            host_id,
            handle,
            _log_sender: log_sender,
            hosts: HashMap::new(),
            forwarding_enabled: false,
            data_fds: Vec::new(),
            event_tx,
            nozzle_meta: None,
            crypto_config: None,
            compression_config: None,
        })
    }

    /// Get the local host ID.
    pub fn host_id(&self) -> HostId {
        self.host_id
    }

    /// Check if data forwarding is enabled.
    pub fn is_forwarding(&self) -> bool {
        self.forwarding_enabled
    }

    /// Enable or disable data forwarding.
    ///
    /// This must be called to start passing traffic through the VPN.
    /// If a nozzle device is attached, it will also be brought up/down.
    pub fn set_forwarding(&mut self, enabled: bool) -> Result<()> {
        info!("Setting forwarding to {} for instance '{}'", enabled, self.name.as_str());

        // Set knet forwarding
        knet::handle_setfwd(&self.handle, enabled)?;
        self.forwarding_enabled = enabled;

        // If we have a nozzle device, bring it up/down in sync
        if let Some(ref meta) = self.nozzle_meta {
            let devname = &meta.device_name;
            let registry = get_nozzle_registry().lock().unwrap();
            if let Some(handle_wrapper) = registry.get(devname) {
                // SAFETY: We control all access to this pointer and ensure it's valid
                let nozzle_handle = unsafe { &*handle_wrapper.0 };
                if enabled {
                    info!("Bringing nozzle device '{}' up", devname);
                    if let Err(e) = nozzle::set_up(nozzle_handle) {
                        error!("Failed to bring nozzle '{}' up: {}", devname, e);
                        // Don't fail the whole operation, knet forwarding is still enabled
                    }
                } else {
                    info!("Bringing nozzle device '{}' down", devname);
                    if let Err(e) = nozzle::set_down(nozzle_handle) {
                        error!("Failed to bring nozzle '{}' down: {}", devname, e);
                    }
                }
            } else {
                warn!("Nozzle '{}' not found in registry", devname);
            }
        }

        Ok(())
    }

    /// Create and configure a nozzle (tap) device for this instance.
    ///
    /// # Arguments
    /// * `devname` - Desired device name (or empty for kernel-assigned)
    /// * `ip_addresses` - IP addresses to assign (format: "192.168.1.1/24")
    /// * `mtu` - Optional MTU
    /// * `mac` - Optional MAC address
    /// * `updown_path` - Optional path to up/down scripts
    /// * `auto_up` - Whether to bring the device up automatically (if forwarding is enabled)
    ///
    /// # Note
    /// The device is brought up only if auto_up=true AND forwarding is already enabled.
    /// Otherwise, it will be brought up when `set_forwarding(true)` is called.
    /// This ensures the nozzle state stays in sync with knet forwarding state.
    /// Reparse nozzle IP address to embed node ID.
    ///
    /// For IPv4: Masks the base IP with the prefix and ORs in the node ID.
    /// For IPv6: Appends node ID as hex after the :: notation.
    ///
    /// This matches Corosync's behavior in totemknet.c.
    fn reparse_nozzle_ip(&self, base_ip: &str, prefix: &str) -> Result<String> {
        use std::net::Ipv4Addr;

        let prefix_bits: u32 = prefix.parse()
            .with_context(|| format!("Invalid prefix '{}'", prefix))?;

        // Check if IPv6 (contains ::)
        if base_ip.contains("::") {
            // IPv6: append node ID as hex after ::
            if !(8..=64).contains(&prefix_bits) {
                anyhow::bail!("IPv6 nozzle prefix must be >= 8 and <= 64 (got {})", prefix_bits);
            }

            let colon_pos = base_ip.find("::").unwrap();
            let node_id = self.host_id.to_u16();
            Ok(format!("{}::{:x}", &base_ip[..colon_pos], node_id))
        } else {
            // IPv4: mask and OR with node ID
            if !(8..=30).contains(&prefix_bits) {
                anyhow::bail!("IPv4 nozzle prefix must be >= 8 and <= 30 (got {})", prefix_bits);
            }

            let base_addr: Ipv4Addr = base_ip.parse()
                .with_context(|| format!("Failed to parse IPv4 address '{}'", base_ip))?;

            let node_id = self.host_id.to_u16() as u32;
            let nodeid_mask = (1u32 << (32 - prefix_bits)) - 1;
            let addr_mask = !nodeid_mask;
            let masked_nodeid = node_id & nodeid_mask;

            let mut addr_bits = u32::from(base_addr);
            addr_bits &= addr_mask;
            addr_bits |= masked_nodeid;

            let result_addr = Ipv4Addr::from(addr_bits);
            Ok(result_addr.to_string())
        }
    }

    pub fn create_nozzle(
        &mut self,
        devname: Option<&str>,
        ip_addresses: &[String],
        mtu: Option<i32>,
        mac: Option<&str>,
        updown_path: Option<&str>,
        auto_up: bool,
    ) -> Result<String> {
        if self.nozzle_meta.is_some() {
            anyhow::bail!("Nozzle device already exists for instance '{}'", self.name.as_str());
        }

        let mut name = devname.unwrap_or("").to_string();
        let path = updown_path.unwrap_or("");

        // Validate updown_path before use: libnozzle executes scripts found there,
        // so an unprivileged allowed_user could escalate to root by pointing this at
        // a directory they control.
        if !path.is_empty() {
            use std::os::unix::fs::PermissionsExt;
            let p = std::path::Path::new(path);
            if !p.is_absolute() {
                anyhow::bail!("updown_path '{}' must be an absolute path", path);
            }
            if p.components().any(|c| c == std::path::Component::ParentDir) {
                anyhow::bail!("updown_path '{}' must not contain '..' components", path);
            }
            let meta = std::fs::metadata(p)
                .with_context(|| format!("updown_path '{}' is not accessible", path))?;
            if !meta.is_dir() {
                anyhow::bail!("updown_path '{}' must be a directory", path);
            }
            if meta.permissions().mode() & 0o002 != 0 {
                anyhow::bail!("updown_path '{}' must not be world-writable", path);
            }
        }

        info!("Creating nozzle device for instance '{}' (requested name: '{}')",
              self.name.as_str(), if name.is_empty() { "<auto>" } else { &name });

        // Open nozzle device
        let handle = nozzle::open(&mut name, path)?;
        let actual_name = name.clone();

        info!("Created nozzle device '{}' for instance '{}'", actual_name, self.name.as_str());

        // Set MTU if specified
        if let Some(mtu_val) = mtu {
            info!("Setting MTU to {} for nozzle '{}'", mtu_val, actual_name);
            nozzle::set_mtu(&handle, mtu_val)?;
        }

        // Set MAC with node ID embedded in last 2 bytes
        // This ensures each node has a unique MAC on the nozzle network
        if let Some(mac_addr) = mac {
            // Take first 12 chars (6 hex bytes without colons) and add node ID in last 2 bytes
            // Format: XX:XX:XX:XX:HH:HH where HH:HH = node_id (high byte, low byte)
            let base_mac = if mac_addr.len() >= 11 {
                &mac_addr[..11]
            } else {
                error!("Invalid base MAC address '{}', using default", mac_addr);
                "fe:54:00:00"
            };

            let node_id = self.host_id.to_u16();
            let unique_mac = format!("{}:{:02x}:{:02x}",
                base_mac,
                (node_id >> 8) & 0xff,
                node_id & 0xff
            );

            info!("Setting MAC to {} for nozzle '{}' (node ID {} embedded)",
                  unique_mac, actual_name, node_id);
            nozzle::set_mac(&handle, &unique_mac)?;
        }

        // Add IP addresses with node ID embedded
        // This ensures each node has a unique IP on the nozzle network
        for ip_addr in ip_addresses {
            // Parse IP/prefix
            let parts: Vec<&str> = ip_addr.split('/').collect();
            if parts.len() != 2 {
                error!("Invalid IP address format '{}', expected 'IP/PREFIX'", ip_addr);
                continue;
            }
            let base_ip = parts[0];
            let prefix = parts[1];

            let unique_ip = self.reparse_nozzle_ip(base_ip, prefix)?;

            info!("Adding IP address {}/{} to nozzle '{}' (node ID {} embedded)",
                  unique_ip, prefix, actual_name, self.host_id.to_u16());
            nozzle::add_ip(&handle, &unique_ip, prefix)?;
        }

        // Get the file descriptor and register it with knet
        let fd = nozzle::get_fd(&handle)?;
        info!("Nozzle '{}' FD: {}, registering with knet", actual_name, fd);
        let (datafd, channel) = knet::handle_add_datafd(&self.handle, fd, 0, knet::DataFdFlags::NONE)?;
        info!("Registered nozzle FD {} with knet (datafd={}, channel={})", fd, datafd, channel);
        self.data_fds.push(datafd);

        // Bring the device up if requested AND forwarding is already enabled.
        // On failure, roll back the knet datafd registration before returning so
        // that knet's rx/tx threads don't poll a stale (soon-to-be-closed) fd.
        if auto_up && self.forwarding_enabled {
            info!("Bringing nozzle '{}' up (forwarding already enabled)", actual_name);
            if let Err(e) = nozzle::set_up(&handle) {
                let _ = knet::handle_remove_datafd(&self.handle, datafd);
                self.data_fds.retain(|&f| f != datafd);
                return Err(e.into());
            }
        } else if auto_up {
            info!("Nozzle '{}' created but left down (forwarding not enabled yet)", actual_name);
        }

        // Store the handle in global registry as a raw pointer
        // (MUST NOT close it - that destroys the device!)
        // SAFETY: We box the handle and leak it intentionally. It will be cleaned up in Drop.
        {
            let handle_ptr = Box::into_raw(Box::new(handle));
            let mut registry = get_nozzle_registry().lock().unwrap();
            registry.insert(actual_name.clone(), SendNozzleHandle(handle_ptr));
        }

        self.nozzle_meta = Some(NozzleMetadata {
            device_name: actual_name.clone(),
            ip_addresses: ip_addresses.to_vec(),
            mtu,
            mac: mac.map(|s| s.to_string()),
            updown_path: updown_path.map(|s| s.to_string()),
            auto_up,
            datafd,
        });

        Ok(actual_name)
    }

    /// Remove the nozzle (tap) device from this instance.
    ///
    /// Closes the tap device, removes its FD from knet, and clears all nozzle state.
    /// The instance itself remains running; only the tap interface is destroyed.
    pub fn destroy_nozzle(&mut self) -> Result<()> {
        let meta = self.nozzle_meta.take()
            .ok_or_else(|| anyhow::anyhow!("No nozzle device attached to instance '{}'", self.name.as_str()))?;

        info!("Destroying nozzle device '{}' for instance '{}'", meta.device_name, self.name.as_str());

        // Remove the datafd from knet first (before closing the nozzle FD)
        if let Err(e) = knet::handle_remove_datafd(&self.handle, meta.datafd) {
            error!("Failed to remove nozzle datafd {}: {}", meta.datafd, e);
        }
        self.data_fds.retain(|&fd| fd != meta.datafd);

        // Close the nozzle device (this destroys the tap interface)
        let mut registry = get_nozzle_registry().lock().unwrap();
        if let Some(handle_wrapper) = registry.remove(&meta.device_name) {
            // SAFETY: We're taking ownership back from the raw pointer.
            // We call nozzle::close() explicitly, then forget the Box to prevent
            // Handle::drop() from calling nozzle_close a second time (double-free).
            let handle = unsafe { Box::from_raw(handle_wrapper.0) };
            let close_result = nozzle::close(handle.as_ref());
            std::mem::forget(handle);
            close_result.with_context(|| format!("Failed to close nozzle device '{}'", meta.device_name))?;
        } else {
            warn!("Nozzle '{}' not found in registry during destroy", meta.device_name);
        }

        info!("Nozzle device '{}' destroyed", meta.device_name);
        Ok(())
    }

    /// Return status information about the attached nozzle device, if any.
    pub fn nozzle_info(&self) -> Option<NozzleInfo> {
        self.nozzle_meta.as_ref().map(|meta| NozzleInfo {
            device_name: meta.device_name.clone(),
            ip_addresses: meta.ip_addresses.clone(),
            mtu: meta.mtu,
            mac: meta.mac.clone(),
            updown_path: meta.updown_path.clone(),
            auto_up: meta.auto_up,
            is_up: self.forwarding_enabled,
        })
    }

    /// Add a remote host to this VPN instance.
    ///
    /// # Arguments
    /// * `host_id` - Remote host ID
    /// * `name` - Optional human-readable name
    pub fn add_host(&mut self, host_id: HostId, name: Option<String>) -> Result<()> {
        info!("Adding host {} to instance '{}'", host_id.to_u16(), self.name.as_str());

        let knet_host_id = knet::HostId::from(host_id);
        knet::host_add(&self.handle, &knet_host_id)?;

        // Set name if provided
        if let Some(ref host_name) = name {
            knet::host_set_name(&self.handle, &knet_host_id, host_name)?;
        }

        // Track metadata
        self.hosts.insert(host_id, HostMetadata {
            name,
            links: HashMap::new(),
        });

        Ok(())
    }

    /// Remove a remote host from this VPN instance.
    pub fn remove_host(&mut self, host_id: HostId) -> Result<()> {
        info!("Removing host {} from instance '{}'", host_id.to_u16(), self.name.as_str());

        // Clear all links for this host first
        if let Some(metadata) = self.hosts.get(&host_id) {
            let link_ids: Vec<u8> = metadata.links.keys().copied().collect();
            for link_id in link_ids {
                self.clear_link(host_id, link_id)?;
            }
        }

        // Remove the host
        let knet_host_id = knet::HostId::from(host_id);
        knet::host_remove(&self.handle, &knet_host_id)?;

        // Remove from tracking
        self.hosts.remove(&host_id);

        Ok(())
    }

    /// Get list of all remote hosts.
    pub fn list_hosts(&self) -> Vec<HostId> {
        self.hosts.keys().copied().collect()
    }

    /// Get host metadata.
    pub fn get_host_name(&self, host_id: HostId) -> Option<&str> {
        self.hosts.get(&host_id)
            .and_then(|m| m.name.as_deref())
    }

    /// Return the link IDs configured for a host.
    pub fn list_host_links(&self, host_id: HostId) -> Vec<u8> {
        self.hosts
            .get(&host_id)
            .map(|h| h.links.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Return the configuration for one link as (transport, src_addr, dst_addr, enabled).
    ///
    /// Returns None if the host or link is not tracked, or if knet cannot
    /// return the config (which would indicate an internal inconsistency).
    pub fn get_link_config(
        &self,
        host_id: HostId,
        link_id: u8,
    ) -> Option<(String, String, Option<String>, bool)> {
        let host = self.hosts.get(&host_id)?;
        let link_meta = host.links.get(&link_id)?;
        let knet_host_id = knet::HostId::from(host_id);
        let (transport, src_addr, dst_addr, _flags) =
            knet::link_get_config(&self.handle, &knet_host_id, link_id).ok()?;
        let src = src_addr?.to_string();
        Some((
            transport.to_string(),
            src,
            dst_addr.map(|a| a.to_string()),
            link_meta.enabled,
        ))
    }

    /// Track a link configuration.
    pub fn track_link(&mut self, host_id: HostId, link_id: u8, enabled: bool) -> Result<()> {
        let host = self.hosts.get_mut(&host_id)
            .ok_or_else(|| anyhow::anyhow!("Host {} not found", host_id.to_u16()))?;

        host.links.insert(link_id, LinkMetadata { enabled });
        Ok(())
    }

    /// Clear a link configuration.
    fn clear_link(&mut self, host_id: HostId, link_id: u8) -> Result<()> {
        debug!("Clearing link {} for host {} in instance '{}'",
               link_id, host_id.to_u16(), self.name.as_str());

        let knet_host_id = knet::HostId::from(host_id);

        // Disable if enabled
        if let Some(host) = self.hosts.get(&host_id)
            && let Some(link) = host.links.get(&link_id)
            && link.enabled {
            knet::link_set_enable(&self.handle, &knet_host_id, link_id, false)?;
        }

        // Clear configuration
        knet::link_clear_config(&self.handle, &knet_host_id, link_id)?;

        // Remove from tracking
        if let Some(host) = self.hosts.get_mut(&host_id) {
            host.links.remove(&link_id);
        }

        Ok(())
    }

    /// Configure a link to a remote host.
    ///
    /// # Arguments
    /// * `host_id` - Remote host ID
    /// * `link_id` - Link ID (0-7)
    /// * `transport` - Transport name (e.g., "udp", "sctp")
    /// * `src_addr` - Local address:port
    /// * `dst_addr` - Remote address:port (None for dynamic links)
    pub fn set_link_config(
        &mut self,
        host_id: HostId,
        link_id: u8,
        transport: &str,
        src_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<()> {
        info!(
            "Configuring link {} for host {} in instance '{}': {} -> {:?}",
            link_id,
            host_id.to_u16(),
            self.name.as_str(),
            src_addr,
            dst_addr
        );

        // Parse addresses
        let src_sockaddr: std::net::SocketAddr = src_addr.parse()?;
        let dst_sockaddr: Option<std::net::SocketAddr> = dst_addr
            .map(|addr| addr.parse())
            .transpose()?;

        // Parse transport type (convert to uppercase for knet API)
        let transport_id = knet::TransportId::from_string(transport.to_uppercase());

        // Configure the link
        let knet_host_id = knet::HostId::from(host_id);
        knet::link_set_config(
            &self.handle,
            &knet_host_id,
            link_id,
            transport_id,
            &src_sockaddr,
            dst_sockaddr.as_ref(),
            knet::LinkFlags::NONE,
        )?;

        // Track the link configuration
        self.track_link(host_id, link_id, false)?;

        Ok(())
    }

    /// Enable or disable a link.
    ///
    /// The link must be configured first via set_link_config.
    pub fn set_link_enable(&mut self, host_id: HostId, link_id: u8, enable: bool) -> Result<()> {
        info!(
            "{} link {} for host {} in instance '{}'",
            if enable { "Enabling" } else { "Disabling" },
            link_id,
            host_id.to_u16(),
            self.name.as_str()
        );

        let knet_host_id = knet::HostId::from(host_id);
        knet::link_set_enable(&self.handle, &knet_host_id, link_id, enable)?;

        // Update tracking
        if let Some(host) = self.hosts.get_mut(&host_id)
            && let Some(link) = host.links.get_mut(&link_id) {
            link.enabled = enable;
        }

        Ok(())
    }

    /// Get status of a specific link.
    pub fn get_link_status(&self, host_id: HostId, link_id: u8) -> Result<knet::LinkStatus> {
        let knet_host_id = knet::HostId::from(host_id);
        Ok(knet::link_get_status(&self.handle, &knet_host_id, link_id)?)
    }

    /// Configure cryptographic settings for this VPN instance.
    ///
    /// # Arguments
    /// * `model` - Crypto model ("openssl", "nss", "gcrypt", or "none")
    /// * `cipher` - Cipher type (e.g., "aes256", "aes128", or "none")
    /// * `hash` - Hash type (e.g., "sha256", "sha512", or "none")
    /// * `key` - Private key (must be at least 1024 bytes)
    /// * `config_num` - Configuration slot (0 or 1)
    ///
    /// knet supports 2 concurrent crypto configurations for runtime key rotation.
    pub fn set_crypto_config(
        &mut self,
        model: &str,
        cipher: &str,
        hash: &str,
        key: &[u8],
        config_num: u8,
    ) -> Result<()> {
        self.set_crypto_config_with_file(model, cipher, hash, key, config_num, None)
    }

    /// Configure cryptographic settings with optional key file tracking.
    ///
    /// This is a helper that allows tracking the key file path
    /// for state persistence when crypto is configured from a file.
    pub(crate) fn set_crypto_config_with_file(
        &mut self,
        model: &str,
        cipher: &str,
        hash: &str,
        key: &[u8],
        config_num: u8,
        key_file: Option<String>,
    ) -> Result<()> {
        info!(
            "Configuring crypto for instance '{}': model={}, cipher={}, hash={}, config_num={}",
            self.name.as_str(),
            model,
            cipher,
            hash,
            config_num
        );

        // Validate config_num (knet requires 1 or 2; 0 is not valid)
        if !(1..=2).contains(&config_num) {
            return Err(anyhow::anyhow!("config_num must be 1 or 2"));
        }

        // Validate key length (knet requires at least KNET_MIN_KEY_LEN = 1024 bytes)
        if key.len() < 1024 {
            return Err(anyhow::anyhow!(
                "Key must be at least 1024 bytes (got {})",
                key.len()
            ));
        }

        let crypto_config = knet::CryptoConfig {
            crypto_model: model.to_string(),
            crypto_cipher_type: cipher.to_string(),
            crypto_hash_type: hash.to_string(),
            private_key: key,
        };

        knet::handle_crypto_set_config(&self.handle, &crypto_config, config_num)?;

        self.crypto_config = Some(CryptoMetadata {
            model: model.to_string(),
            cipher: cipher.to_string(),
            hash: hash.to_string(),
            key_file: key_file.unwrap_or_default(),
            config_num,
        });

        info!(
            "Crypto configured successfully for instance '{}'",
            self.name.as_str()
        );

        Ok(())
    }

    /// Activate a specific crypto configuration for transmission.
    ///
    /// # Arguments
    /// * `config_num` - Configuration slot to use for TX (0 or 1)
    ///
    /// After setting up crypto configs with set_crypto_config, use this to
    /// specify which one to use for outgoing packets.
    pub fn use_crypto_config(&self, config_num: u8) -> Result<()> {
        info!(
            "Activating crypto config {} for instance '{}'",
            config_num,
            self.name.as_str()
        );

        if !(1..=2).contains(&config_num) {
            return Err(anyhow::anyhow!("config_num must be 1 or 2"));
        }

        knet::handle_crypto_use_config(&self.handle, config_num)?;

        info!(
            "Crypto config {} activated for instance '{}'",
            config_num,
            self.name.as_str()
        );

        Ok(())
    }

    /// Configure packet compression for this VPN instance.
    ///
    /// # Arguments
    /// * `model` - Compression model (e.g., "zlib", "lz4", "lzo2", "lzma", "bzip2", "zstd", or "none")
    /// * `threshold` - Packets smaller than this (in bytes) won't be compressed (0 = default 100)
    /// * `level` - Compression level (meaning varies by model, typically 1-9)
    ///
    /// Compression reduces bandwidth but adds CPU overhead. The threshold prevents
    /// compressing small packets where the overhead exceeds the benefit.
    pub fn set_compression(
        &mut self,
        model: &str,
        threshold: u32,
        level: i32,
    ) -> Result<()> {
        info!(
            "Configuring compression for instance '{}': model={}, threshold={}, level={}",
            self.name.as_str(),
            model,
            threshold,
            level
        );

        let compress_config = knet::CompressConfig {
            compress_model: model.to_string(),
            compress_threshold: threshold,
            compress_level: level,
        };

        knet::handle_compress(&self.handle, &compress_config)?;

        // Store metadata for state persistence
        self.compression_config = Some(CompressionMetadata {
            model: model.to_string(),
            threshold,
            level,
        });

        info!(
            "Compression configured successfully for instance '{}'",
            self.name.as_str()
        );

        Ok(())
    }

    /// Get the current crypto configuration (if any).
    pub fn crypto_config(&self) -> Option<(&str, &str, &str, &str, u8)> {
        self.crypto_config.as_ref().map(|c| {
            (c.model.as_str(), c.cipher.as_str(), c.hash.as_str(), c.key_file.as_str(), c.config_num)
        })
    }

    /// Get the current compression configuration (if any).
    pub fn compression_config(&self) -> Option<(&str, u32, i32)> {
        self.compression_config.as_ref().map(|c| {
            (c.model.as_str(), c.threshold, c.level)
        })
    }

    /// Subscribe to events from this VPN instance.
    ///
    /// Returns a receiver that will get all events (link/host status changes, etc.)
    pub fn subscribe_events(&self) -> broadcast::Receiver<DaemonEvent> {
        self.event_tx.subscribe()
    }
}

impl Drop for VpnInstance {
    /// Cleanup the VPN instance following the critical cleanup sequence.
    ///
    /// This must be done in the correct order to avoid crashes and memory leaks:
    /// 1. Stop forwarding
    /// 2. Remove data FDs
    /// 3. Disable all links
    /// 4. Clear all link configs
    /// 5. Remove all hosts
    /// 6. Free the handle
    fn drop(&mut self) {
        info!("Cleaning up VPN instance '{}'", self.name.as_str());

        // Unregister from event registry using the same stable key used in new().
        let handle_ptr = self.handle.knet_handle as usize;
        {
            let mut registry = get_event_registry().lock().unwrap();
            registry.remove(&handle_ptr);
        }

        // 0. Close nozzle device (if any)
        if let Some(ref meta) = self.nozzle_meta {
            let devname = &meta.device_name;
            info!("Closing nozzle device '{}' for instance '{}'", devname, self.name.as_str());
            let mut registry = get_nozzle_registry().lock().unwrap();
            if let Some(handle_wrapper) = registry.remove(devname) {
                // SAFETY: We're taking ownership back from the raw pointer.
                // Forget the Box after explicit close to prevent Handle::drop()
                // from calling nozzle_close a second time (double-free).
                let handle = unsafe { Box::from_raw(handle_wrapper.0) };
                if let Err(e) = nozzle::close(handle.as_ref()) {
                    error!("Failed to close nozzle device '{}': {}", devname, e);
                }
                std::mem::forget(handle);
            } else {
                warn!("Nozzle '{}' not found in registry during cleanup", devname);
            }
        }

        // 1. Stop forwarding
        if self.forwarding_enabled
            && let Err(e) = knet::handle_setfwd(&self.handle, false) {
            error!("Failed to stop forwarding: {}", e);
        }

        // 2. Remove data FDs
        for fd in self.data_fds.drain(..) {
            if let Err(e) = knet::handle_remove_datafd(&self.handle, fd) {
                error!("Failed to remove datafd {}: {}", fd, e);
            }
        }

        // 3 & 4. Disable and clear all links
        let hosts: Vec<HostId> = self.hosts.keys().copied().collect();
        for host_id in &hosts {
            if let Some(host) = self.hosts.get(host_id) {
                let links: Vec<u8> = host.links.keys().copied().collect();
                for link_id in links {
                    if let Err(e) = self.clear_link(*host_id, link_id) {
                        error!("Failed to clear link {} for host {}: {}",
                               link_id, host_id.to_u16(), e);
                    }
                }
            }
        }

        // 5. Remove all hosts
        for host_id in hosts {
            let knet_host_id = knet::HostId::from(host_id);
            if let Err(e) = knet::host_remove(&self.handle, &knet_host_id) {
                error!("Failed to remove host {}: {}", host_id.to_u16(), e);
            }
        }

        // 6. Free the handle (done automatically by knet::Handle's Drop)
        debug!("Freeing knet handle for instance '{}'", self.name.as_str());

        // Note: We don't explicitly join the logging thread here because:
        // 1. The thread is blocked on receiver.recv() waiting for log messages
        // 2. The sender is dropped when the Handle drops (which happens automatically)
        // 3. Joining here would cause a deadlock - we'd wait for the thread,
        //    but the thread is waiting for the handle to drop
        // 4. The thread will exit cleanly on its own when the channel closes
        //
        // The logging thread is detached and will clean itself up.

        info!("VPN instance '{}' cleaned up", self.name.as_str());
    }
}

/// Logging thread for a VPN instance.
///
/// This runs in a separate OS thread and drains log messages from the
/// knet library, forwarding them to the tracing infrastructure.
fn logging_thread(instance_name: InstanceName, receiver: std::sync::mpsc::Receiver<knet::LogMsg>) {
    debug!("Starting logging thread for instance '{}'", instance_name.as_str());

    for msg in receiver {
        // Get subsystem name
        let subsystem = knet::log_get_subsystem_name(msg.subsystem as u8)
            .unwrap_or_else(|_| "unknown".to_string());

        // Map knet log levels to tracing levels
        match msg.level {
            knet::LogLevel::Err => {
                error!("[{}] {}: {}", instance_name.as_str(), subsystem, msg.msg);
            }
            knet::LogLevel::Warn => {
                warn!("[{}] {}: {}", instance_name.as_str(), subsystem, msg.msg);
            }
            knet::LogLevel::Info => {
                info!("[{}] {}: {}", instance_name.as_str(), subsystem, msg.msg);
            }
            knet::LogLevel::Debug | knet::LogLevel::Trace => {
                debug!("[{}] {}: {}", instance_name.as_str(), subsystem, msg.msg);
            }
        }
    }

    debug!("Logging thread finished for instance '{}'", instance_name.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_creation() {
        let name = InstanceName::new("test");
        let host_id = HostId::new(1);

        let instance = VpnInstance::new(name.clone(), host_id, false, "info");
        assert!(instance.is_ok());

        let instance = instance.unwrap();
        assert_eq!(instance.name, name);
        assert_eq!(instance.host_id, host_id);
        assert!(!instance.is_forwarding());
    }

    #[test]
    fn test_host_tracking() {
        let name = InstanceName::new("test");
        let mut instance = VpnInstance::new(name, HostId::new(1), false, "info").unwrap();

        // Add host
        let result = instance.add_host(HostId::new(2), Some("node2".to_string()));
        assert!(result.is_ok());

        // Check list
        let hosts = instance.list_hosts();
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains(&HostId::new(2)));

        // Check name
        assert_eq!(instance.get_host_name(HostId::new(2)), Some("node2"));
    }
}
