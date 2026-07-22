//! Main daemon runtime and state management.
//!
//! The daemon runs a tokio async runtime that:
//! - Listens for RPC requests on a Unix socket
//! - Manages VPN instance lifecycle
//! - Handles graceful shutdown on SIGINT/SIGTERM

use crate::config::{DaemonConfig, InstanceConfig};
use crate::rpc_server::RpcServer;
use crate::vpn_instance::VpnInstance;
use anyhow::{Context, Result};
use knetd_common::{DaemonEvent, HostId, InstanceName};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

/// Event subscription tracking.
pub struct EventSubscription {
    pub receiver: broadcast::Receiver<DaemonEvent>,
    pub instance_name: InstanceName,
}

/// Shared daemon state containing all VPN instances.
pub struct State {
    /// Active VPN instances indexed by name
    pub instances: HashMap<InstanceName, VpnInstance>,

    /// Event subscriptions indexed by subscription ID
    pub subscriptions: HashMap<String, EventSubscription>,

    /// Whether to use privileged mode for new instances
    pub use_privileged: bool,

    /// Log level for knet instances (should match daemon log level)
    pub log_level: String,
}

/// Shared daemon state wrapped for async access.
pub type DaemonState = Arc<Mutex<State>>;

/// Configure a newly created VPN instance with hosts, links, crypto, compression, and nozzle.
///
/// This function:
/// 1. Adds all remote hosts from the instance config
/// 2. Configures links (either full-mesh or manual mode)
/// 3. Configures crypto if specified (reads key from file)
/// 4. Configures compression if specified
/// 5. Creates and configures a nozzle device if specified
/// 6. Enables forwarding to bring the instance up
///
/// # Parameters
/// * `instance` - The VPN instance to configure
/// * `instance_config` - Configuration for this instance
/// * `my_node` - Configuration for this local node
fn configure_instance(
    instance: &mut VpnInstance,
    instance_config: &InstanceConfig,
    my_node: &crate::config::NodeConfig,
) -> Result<()> {
    // Add all other nodes as remote hosts
    for node_config in &instance_config.nodes {
        if node_config.host_id == my_node.host_id {
            continue; // Skip ourselves
        }
        let remote_host_id = HostId::new(node_config.host_id);
        if let Err(e) = instance.add_host(remote_host_id, Some(node_config.name.clone())) {
            error!("Failed to add host {} ({}) to instance '{}': {}",
                   node_config.host_id, node_config.name, instance_config.name, e);
        }
    }

    // Configure links based on mode
    if instance_config.full_mesh {
        // Full-mesh mode: create bidirectional links to all other nodes
        info!("Configuring full-mesh links for instance '{}'", instance_config.name);

        if my_node.link_addresses.is_empty() {
            error!("Node {} has no link_addresses defined for full-mesh mode", my_node.host_id);
        } else {
            for remote_node in &instance_config.nodes {
                if remote_node.host_id == my_node.host_id {
                    continue; // Skip ourselves
                }

                if remote_node.link_addresses.is_empty() {
                    error!("Remote node {} has no link_addresses defined", remote_node.host_id);
                    continue;
                }

                // Create links for each address pair (up to min of both address lists)
                let max_links = std::cmp::min(my_node.link_addresses.len(), remote_node.link_addresses.len());
                for link_id in 0..max_links {
                    let link_id = link_id as u8;
                    let src_addr = &my_node.link_addresses[link_id as usize];
                    let dst_addr = &remote_node.link_addresses[link_id as usize];
                    let to_host = HostId::new(remote_node.host_id);

                    info!("Configuring full-mesh link {} from {} to {} ({})",
                          link_id, my_node.host_id, remote_node.host_id, "udp");

                    if let Err(e) = instance.set_link_config(
                        to_host,
                        link_id,
                        "udp",
                        src_addr,
                        Some(dst_addr),
                    ) {
                        error!("Failed to configure link {} to host {}: {}",
                               link_id, remote_node.host_id, e);
                        continue;
                    }

                    // Auto-enable in full-mesh mode
                    if let Err(e) = instance.set_link_enable(to_host, link_id, true) {
                        error!("Failed to enable link {} to host {}: {}",
                               link_id, remote_node.host_id, e);
                    }
                }
            }
        }
    } else {
        // Manual mode: configure links where we are the source
        for link_config in &instance_config.links {
            if link_config.from_host != my_node.host_id {
                continue; // Not our link
            }

            let to_host = HostId::new(link_config.to_host);
            info!("Configuring link {} from {} to {} ({})",
                  link_config.link_id, link_config.from_host, link_config.to_host,
                  link_config.transport);

            if let Err(e) = instance.set_link_config(
                to_host,
                link_config.link_id,
                &link_config.transport,
                &link_config.src_addr,
                link_config.dst_addr.as_deref(),
            ) {
                error!("Failed to configure link {} to host {}: {}",
                       link_config.link_id, link_config.to_host, e);
                continue;
            }

            if link_config.auto_enable
                && let Err(e) = instance.set_link_enable(to_host, link_config.link_id, true) {
                error!("Failed to enable link {} to host {}: {}",
                       link_config.link_id, link_config.to_host, e);
            }
        }
    }

    // Configure crypto if specified
    if let Some(ref crypto_config) = instance_config.crypto {
        info!("Configuring crypto for instance '{}': model={}, cipher={}, hash={}",
              instance_config.name, crypto_config.model, crypto_config.cipher, crypto_config.hash);

        let key = std::fs::read(&crypto_config.key_file)
            .map_err(|e| anyhow::anyhow!("Failed to read crypto key file '{}': {}", crypto_config.key_file, e))?;

        if key.len() < 1024 {
            return Err(anyhow::anyhow!(
                "Crypto key file '{}' is too small ({} bytes, need at least 1024)",
                crypto_config.key_file, key.len()
            ));
        }

        instance.set_crypto_config_with_file(
            &crypto_config.model,
            &crypto_config.cipher,
            &crypto_config.hash,
            &key,
            crypto_config.config_num,
            Some(crypto_config.key_file.clone()),
        ).map_err(|e| anyhow::anyhow!("Failed to configure crypto for instance '{}': {}", instance_config.name, e))?;

        instance.use_crypto_config(crypto_config.config_num)
            .map_err(|e| anyhow::anyhow!("Failed to activate crypto config {} for instance '{}': {}",
                crypto_config.config_num, instance_config.name, e))?;

        info!("Crypto enabled for instance '{}'", instance_config.name);
    }

    // Configure compression if specified
    if let Some(ref compress_config) = instance_config.compression {
        info!("Configuring compression for instance '{}': model={}, threshold={}, level={}",
              instance_config.name, compress_config.model, compress_config.threshold, compress_config.level);

        if let Err(e) = instance.set_compression(
            &compress_config.model,
            compress_config.threshold,
            compress_config.level,
        ) {
            error!("Failed to configure compression for instance '{}': {}", instance_config.name, e);
        } else {
            info!("Compression enabled for instance '{}'", instance_config.name);
        }
    }

    // Create nozzle device if configured
    if let Some(ref nozzle_config) = instance_config.nozzle {
        info!("Creating nozzle device for instance '{}'", instance_config.name);

        let devname = instance.create_nozzle(
            nozzle_config.name.as_deref(),
            &nozzle_config.ip_addresses,
            nozzle_config.mtu,
            nozzle_config.mac.as_deref(),
            nozzle_config.updown_path.as_deref(),
            nozzle_config.auto_up,
        ).map_err(|e| anyhow::anyhow!("Failed to create nozzle device for instance '{}': {}", instance_config.name, e))?;

        info!("Created nozzle device '{}' for instance '{}'", devname, instance_config.name);
    }

    // Enable forwarding (brings nozzle up too if configured)
    instance.set_forwarding(true)
        .map_err(|e| anyhow::anyhow!("Failed to enable forwarding for instance '{}': {}", instance_config.name, e))?;

    Ok(())
}

/// Look up the numeric UID for a username using getpwnam_r(3).
fn lookup_uid(username: &str) -> Option<u32> {
    use std::ffi::CString;

    let c_name = CString::new(username).ok()?;
    // Use a 4 KiB stack buffer; fall back gracefully if it is too small.
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };

    let ret = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pw,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if ret == 0 && !result.is_null() {
        Some(unsafe { (*result).pw_uid })
    } else {
        None
    }
}

/// Resolve `allowed_users` from the config into a deduplicated list of UIDs.
///
/// Root (UID 0) is always prepended so it can never be locked out.
/// Each entry is interpreted as a numeric UID if it parses as `u32`,
/// otherwise as a username that is looked up via the system password database.
fn resolve_allowed_uids(allowed_users: &[String]) -> Vec<u32> {
    let mut uids: Vec<u32> = vec![0]; // root is always allowed

    for entry in allowed_users {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(uid) = entry.parse::<u32>() {
            uids.push(uid);
        } else {
            match lookup_uid(entry) {
                Some(uid) => {
                    info!("Resolved allowed_user '{}' to UID {}", entry, uid);
                    uids.push(uid);
                }
                None => {
                    warn!("Could not resolve allowed_user '{}' to a UID — entry ignored", entry);
                }
            }
        }
    }

    uids.sort_unstable();
    uids.dedup();
    uids
}

/// Run the daemon main loop.
///
/// This function:
/// 1. Initializes daemon state
/// 2. Starts the RPC server on the configured Unix socket
/// 3. Waits for either:
///    - A fatal error from the RPC server
///    - Ctrl+C (SIGINT) for graceful shutdown
/// 4. Performs cleanup and exits
///
/// # Parameters
/// * `config` - Daemon configuration (may define multiple nodes and links)
/// * `local_node_id` - This node's host ID (filters config to relevant parts)
pub async fn run(
    config: DaemonConfig,
    local_node_id: Option<u16>,
) -> Result<()> {
    // Determine whether to use privileged mode based on:
    // 1. If daemon is running as root (UID 0)
    // 2. Unless disabled via config
    let is_root = unsafe { libc::getuid() } == 0;
    let use_privileged = is_root && !config.disable_privileged;

    if is_root {
        if use_privileged {
            info!("Running as root - PRIVILEGED mode will be used for new instances");
        } else {
            info!("Running as root but PRIVILEGED mode disabled via config");
        }
    } else {
        info!("Not running as root - PRIVILEGED mode will not be used");
    }

    // Load persisted state if configured
    let mut instances = if let Some(ref state_file) = config.state_file {
        match crate::state::load_state(state_file) {
            Ok(persisted_state) => {
                info!("Loaded persisted state from {}", state_file);
                match crate::state::restore_instances(persisted_state, use_privileged, &config.log_level) {
                    Ok(instances) => instances,
                    Err(e) => {
                        error!("Failed to restore instances: {}", e);
                        error!("Starting with empty state");
                        HashMap::new()
                    }
                }
            }
            Err(e) => {
                error!("Failed to load state from {}: {}", state_file, e);
                error!("Starting with empty state");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // Auto-start instances from config
    for instance_config in &config.instances {
        if !instance_config.auto_start {
            continue;
        }

        info!("Auto-starting instance '{}' from config", instance_config.name);

        // Determine this node's identity from the config
        let my_node = if let Some(node_id) = local_node_id {
            // Local node ID specified - find matching node in config
            instance_config.nodes.iter()
                .find(|n| n.host_id == node_id)
                .ok_or_else(|| {
                    error!("Local node ID {} not found in instance '{}' nodes list",
                           node_id, instance_config.name);
                    anyhow::anyhow!("Local node ID {} not defined in config", node_id)
                })?
        } else {
            // No local node ID - config must have exactly one node (backward compatibility)
            if instance_config.nodes.len() == 1 {
                &instance_config.nodes[0]
            } else if instance_config.nodes.is_empty() {
                error!("Instance '{}' has no nodes defined and no local node ID specified",
                       instance_config.name);
                continue;
            } else {
                error!("Instance '{}' has {} nodes but no local node ID specified (use --node-id or KNETD_NODE_ID)",
                       instance_config.name, instance_config.nodes.len());
                continue;
            }
        };

        let name = InstanceName::new(instance_config.name.clone());
        let host_id = HostId::new(my_node.host_id);

        info!("Starting instance '{}' as node {} ({})",
              instance_config.name, my_node.host_id, my_node.name);

        // Skip if already exists from persisted state
        if instances.contains_key(&name) {
            info!("Instance '{}' already exists from persisted state", instance_config.name);
            continue;
        }

        match VpnInstance::new(name.clone(), host_id, use_privileged, &config.log_level) {
            Ok(mut instance) => {
                if let Err(e) = configure_instance(&mut instance, instance_config, my_node) {
                    error!("Failed to configure instance '{}': {}", instance_config.name, e);
                } else {
                    instances.insert(name, instance);
                }
            }
            Err(e) => {
                error!("Failed to create instance '{}': {}", instance_config.name, e);
            }
        }
    }

    let state: DaemonState = Arc::new(Mutex::new(State {
        instances,
        subscriptions: HashMap::new(),
        use_privileged,
        log_level: config.log_level.clone(),
    }));

    info!("Starting RPC server on {}", config.socket_path);

    let allowed_uids = resolve_allowed_uids(&config.allowed_users);
    let rpc_server = RpcServer::new(config.socket_path.clone(), state.clone(), allowed_uids);
    let _server = rpc_server.start().await?;

    info!("Daemon ready, waiting for signals...");

    // Wait for SIGINT or SIGTERM using tokio's signal infrastructure.
    // This is integrated with tokio's I/O driver and works correctly even
    // when blocking tasks (spawn_blocking) are running concurrently.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    warn!("SIGINT handler error: {}", e);
                }
                info!("Received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
            .context("Failed to listen for ctrl-c")?;
        info!("Received Ctrl-C, shutting down");
    }

    // RPC server will be dropped automatically, which triggers cleanup
    info!("Received shutdown signal, cleaning up...");

    // Save state before shutdown
    if let Some(ref state_file) = config.state_file {
        info!("Saving daemon state before shutdown");
        let state = state.lock().await;
        info!("Got state lock for saving");
        if let Err(e) = crate::state::save_state(state_file, &state.instances) {
            error!("Failed to save state: {}", e);
        }
        info!("State save complete");
    }

    info!("Daemon shutdown complete");

    // Note: We don't explicitly cleanup VPN instances here because:
    // 1. VpnInstance::drop() can block for several seconds waiting for threads
    // 2. We're about to exit anyway, so the OS will reclaim resources
    // 3. The state was already saved above
    //
    // Force exit because jsonrpc-ipc-server background threads don't stop cleanly
    std::process::exit(0);
}
