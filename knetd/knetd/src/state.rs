//! State persistence and restoration.
//!
//! This module handles saving and loading daemon state to/from JSON files,
//! allowing VPN instances to survive daemon restarts.

use crate::vpn_instance::VpnInstance;
use anyhow::{Context, Result};
use knetd_common::{HostId, InstanceName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

/// Serializable state for a VPN instance.
///
/// This captures the essential configuration needed to recreate
/// an instance after daemon restart. Runtime state (like actual
/// link connectivity) is not persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceState {
    pub name: String,
    pub host_id: u16,
    pub forwarding_enabled: bool,
    pub hosts: Vec<HostState>,
    #[serde(default)]
    pub nozzle: Option<NozzleState>,
    #[serde(default)]
    pub crypto: Option<CryptoState>,
    #[serde(default)]
    pub compression: Option<CompressionState>,
}

/// Serializable state for a remote host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostState {
    pub host_id: u16,
    pub name: Option<String>,
    #[serde(default)]
    pub links: Vec<LinkState>,
}

/// Serializable configuration for one link to a remote host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkState {
    pub link_id: u8,
    pub transport: String,
    pub src_addr: String,
    #[serde(default)]
    pub dst_addr: Option<String>,
    pub enabled: bool,
}

/// Serializable nozzle (tap device) configuration state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NozzleState {
    pub device_name: String,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub mtu: Option<i32>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub updown_path: Option<String>,
    pub auto_up: bool,
}

/// Serializable crypto configuration state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoState {
    pub model: String,
    pub cipher: String,
    pub hash: String,
    pub key_file: String,
    pub config_num: u8,
}

/// Serializable compression configuration state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionState {
    pub model: String,
    pub threshold: u32,
    pub level: i32,
}

/// Complete daemon state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub version: u32,
    pub instances: Vec<InstanceState>,
}

impl DaemonState {
    const CURRENT_VERSION: u32 = 1;

    /// Create a new empty daemon state.
    pub fn new() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            instances: Vec::new(),
        }
    }
}

/// Collect current daemon state into a serialisable snapshot.
///
/// Extracted so both `save_state()` and the `state.dump` RPC handler can
/// share the same serialisation logic without duplicating the instance loop.
pub fn collect_state(instances: &HashMap<InstanceName, VpnInstance>) -> DaemonState {
    let instance_states: Vec<InstanceState> = instances
        .iter()
        .map(|(name, instance)| {
            let hosts: Vec<HostState> = instance
                .list_hosts()
                .into_iter()
                .map(|host_id| {
                    let links = instance
                        .list_host_links(host_id)
                        .into_iter()
                        .filter_map(|link_id| {
                            let (transport, src_addr, dst_addr, enabled) =
                                instance.get_link_config(host_id, link_id)?;
                            Some(LinkState { link_id, transport, src_addr, dst_addr, enabled })
                        })
                        .collect();
                    HostState {
                        host_id: host_id.to_u16(),
                        name: instance.get_host_name(host_id).map(String::from),
                        links,
                    }
                })
                .collect();

            let crypto = instance.crypto_config().map(|(model, cipher, hash, key_file, config_num)| {
                CryptoState {
                    model: model.to_string(),
                    cipher: cipher.to_string(),
                    hash: hash.to_string(),
                    key_file: key_file.to_string(),
                    config_num,
                }
            });

            let compression = instance.compression_config().map(|(model, threshold, level)| {
                CompressionState {
                    model: model.to_string(),
                    threshold,
                    level,
                }
            });

            let nozzle = instance.nozzle_info().map(|n| NozzleState {
                device_name: n.device_name,
                ip_addresses: n.ip_addresses,
                mtu: n.mtu,
                mac: n.mac,
                updown_path: n.updown_path,
                auto_up: n.auto_up,
            });

            InstanceState {
                name: name.as_str().to_string(),
                host_id: instance.host_id().to_u16(),
                forwarding_enabled: instance.is_forwarding(),
                hosts,
                nozzle,
                crypto,
                compression,
            }
        })
        .collect();

    DaemonState {
        version: DaemonState::CURRENT_VERSION,
        instances: instance_states,
    }
}

/// Save daemon state to a JSON file.
///
/// # Arguments
/// * `path` - Path to the state file
/// * `instances` - Map of active VPN instances
///
/// # Errors
/// Returns an error if serialization or file write fails.
pub fn save_state(
    path: impl AsRef<Path>,
    instances: &HashMap<InstanceName, VpnInstance>,
) -> Result<()> {
    let path = path.as_ref();
    info!("Saving daemon state to {:?}", path);

    let state = collect_state(instances);

    // Serialize to JSON with pretty printing
    let json = serde_json::to_string_pretty(&state)
        .context("Failed to serialize state")?;

    // Write to temporary file first, then rename (atomic on POSIX)
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, json)
        .with_context(|| format!("Failed to write state to {:?}", temp_path))?;

    fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename state file to {:?}", path))?;

    info!("Saved state with {} instances", state.instances.len());
    Ok(())
}

/// Load daemon state from a JSON file.
///
/// # Arguments
/// * `path` - Path to the state file
///
/// # Returns
/// The loaded state, or an empty state if the file doesn't exist
///
/// # Errors
/// Returns an error if the file exists but cannot be read or parsed
pub fn load_state(path: impl AsRef<Path>) -> Result<DaemonState> {
    let path = path.as_ref();

    // If file doesn't exist, return empty state
    if !path.exists() {
        info!("No state file found at {:?}, starting fresh", path);
        return Ok(DaemonState::new());
    }

    info!("Loading daemon state from {:?}", path);

    let json = fs::read_to_string(path)
        .with_context(|| format!("Failed to read state file {:?}", path))?;

    let state: DaemonState = serde_json::from_str(&json)
        .context("Failed to parse state file")?;

    // Check version compatibility
    if state.version != DaemonState::CURRENT_VERSION {
        warn!(
            "State file version {} does not match current version {}",
            state.version,
            DaemonState::CURRENT_VERSION
        );
        warn!("State file may not be fully compatible");
    }

    info!("Loaded state with {} instances", state.instances.len());
    Ok(state)
}

/// Restore VPN instances from persisted state.
///
/// This recreates the VPN instances and restores crypto and compression
/// settings. Link configurations are NOT restored and must be reapplied.
///
/// # Arguments
/// * `state` - The loaded daemon state
/// * `use_privileged` - Whether to create instances with privileged mode
/// * `log_level` - Log level to use for knet instances
///
/// # Returns
/// A map of recreated VPN instances
pub fn restore_instances(state: DaemonState, use_privileged: bool, log_level: &str) -> Result<HashMap<InstanceName, VpnInstance>> {
    let mut instances = HashMap::new();

    for instance_state in state.instances {
        info!("Restoring instance '{}'", instance_state.name);

        // Create the instance
        let name = InstanceName::new(instance_state.name.clone());
        let host_id = HostId::new(instance_state.host_id);

        let mut instance = VpnInstance::new(name.clone(), host_id, use_privileged, log_level)
            .with_context(|| format!("Failed to create instance '{}'", instance_state.name))?;

        // Restore hosts and their links
        for host_state in instance_state.hosts {
            let host_id = HostId::new(host_state.host_id);
            if let Err(e) = instance.add_host(host_id, host_state.name.clone()) {
                error!(
                    "Failed to restore host {} for instance '{}': {}",
                    host_state.host_id, instance_state.name, e
                );
                continue;
            }

            for link_state in host_state.links {
                if let Err(e) = instance.set_link_config(
                    host_id,
                    link_state.link_id,
                    &link_state.transport,
                    &link_state.src_addr,
                    link_state.dst_addr.as_deref(),
                ) {
                    error!(
                        "Failed to restore link {} for host {} in instance '{}': {}",
                        link_state.link_id, host_state.host_id, instance_state.name, e
                    );
                    continue;
                }
                if link_state.enabled
                    && let Err(e) = instance.set_link_enable(host_id, link_state.link_id, true) {
                    error!(
                        "Failed to enable link {} for host {} in instance '{}': {}",
                        link_state.link_id, host_state.host_id, instance_state.name, e
                    );
                }
            }
        }

        // Restore crypto configuration if present
        if let Some(crypto_state) = instance_state.crypto {
            info!("Restoring crypto config for instance '{}'", instance_state.name);

            match std::fs::read(&crypto_state.key_file) {
                Ok(key) => {
                    if key.len() < 1024 {
                        error!("Crypto key file '{}' is too small ({} bytes, need at least 1024)",
                               crypto_state.key_file, key.len());
                    } else {
                        // Use the internal method to restore crypto with key_file tracking
                        if let Err(e) = instance.set_crypto_config_with_file(
                            &crypto_state.model,
                            &crypto_state.cipher,
                            &crypto_state.hash,
                            &key,
                            crypto_state.config_num,
                            Some(crypto_state.key_file.clone()),
                        ) {
                            error!("Failed to restore crypto config for instance '{}': {}", instance_state.name, e);
                        } else {
                            // Activate the crypto config
                            if let Err(e) = instance.use_crypto_config(crypto_state.config_num) {
                                error!("Failed to activate crypto config {} for instance '{}': {}",
                                       crypto_state.config_num, instance_state.name, e);
                            } else {
                                info!("Crypto config restored for instance '{}'", instance_state.name);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read crypto key file '{}' for instance '{}': {}",
                           crypto_state.key_file, instance_state.name, e);
                }
            }
        }

        // Restore compression configuration if present
        if let Some(comp_state) = instance_state.compression {
            info!("Restoring compression config for instance '{}'", instance_state.name);

            if let Err(e) = instance.set_compression(
                &comp_state.model,
                comp_state.threshold,
                comp_state.level,
            ) {
                error!("Failed to restore compression config for instance '{}': {}", instance_state.name, e);
            } else {
                info!("Compression config restored for instance '{}'", instance_state.name);
            }
        }

        // Restore nozzle device if one was attached
        if let Some(nozzle_state) = instance_state.nozzle {
            info!("Restoring nozzle device '{}' for instance '{}'",
                  nozzle_state.device_name, instance_state.name);
            match instance.create_nozzle(
                Some(&nozzle_state.device_name),
                &nozzle_state.ip_addresses,
                nozzle_state.mtu,
                nozzle_state.mac.as_deref(),
                nozzle_state.updown_path.as_deref(),
                nozzle_state.auto_up,
            ) {
                Ok(dev) => info!("Restored nozzle device '{}' for instance '{}'",
                                 dev, instance_state.name),
                Err(e) => error!("Failed to restore nozzle device for instance '{}': {}",
                                 instance_state.name, e),
            }
        }

        // Restore forwarding state
        if instance_state.forwarding_enabled
            && let Err(e) = instance.set_forwarding(true) {
            error!(
                "Failed to enable forwarding for instance '{}': {}",
                instance_state.name, e
            );
        }

        instances.insert(name, instance);
    }

    info!("Restored {} instances", instances.len());
    Ok(instances)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_empty_state() {
        let temp_dir = TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let instances = HashMap::new();
        save_state(&state_path, &instances).unwrap();

        let loaded = load_state(&state_path).unwrap();
        assert_eq!(loaded.version, DaemonState::CURRENT_VERSION);
        assert_eq!(loaded.instances.len(), 0);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let state_path = temp_dir.path().join("nonexistent.json");

        let state = load_state(&state_path).unwrap();
        assert_eq!(state.instances.len(), 0);
    }

    #[test]
    fn test_state_serialization() {
        let state = DaemonState {
            version: 1,
            instances: vec![InstanceState {
                name: "test".to_string(),
                host_id: 1,
                forwarding_enabled: false,
                hosts: vec![HostState {
                    host_id: 2,
                    name: Some("node2".to_string()),
                }],
                crypto: Some(CryptoState {
                    model: "openssl".to_string(),
                    cipher: "aes256".to_string(),
                    hash: "sha256".to_string(),
                    key_file: "/etc/knetd/test.key".to_string(),
                    config_num: 0,
                }),
                compression: Some(CompressionState {
                    model: "lz4".to_string(),
                    threshold: 100,
                    level: 1,
                }),
            }],
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: DaemonState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.instances.len(), 1);
        assert_eq!(deserialized.instances[0].name, "test");
        assert_eq!(deserialized.instances[0].hosts.len(), 1);
        assert!(deserialized.instances[0].crypto.is_some());
        assert!(deserialized.instances[0].compression.is_some());
    }
}
