//! JSON-RPC 2.0 server implementation over Unix domain sockets.
//!
//! The RPC server accepts connections from knetctl and dispatches
//! method calls to the appropriate handlers.

use crate::daemon::{DaemonState, EventSubscription};
use crate::vpn_instance::VpnInstance;
use anyhow::Result;
use jsonrpc_core::{IoHandler, Params, Value, Error as RpcError, ErrorCode};
use jsonrpc_ipc_server::{Server, ServerBuilder};
use knetd_common::*;
use std::path::Path;
use tokio::sync::broadcast;
use tracing::info;
use uuid::Uuid;

/// RPC server that listens on a Unix domain socket.
pub struct RpcServer {
    socket_path: String,
    state: DaemonState,
}

impl RpcServer {
    pub fn new(socket_path: String, state: DaemonState) -> Self {
        Self { socket_path, state }
    }

    /// Start the RPC server.
    ///
    /// This method:
    /// 1. Registers all RPC method handlers
    /// 2. Removes any existing socket file at the configured path
    /// 3. Binds to the Unix socket
    /// 4. Returns the Server handle which must be kept alive
    ///
    /// The server will continue running as long as the returned Server is alive.
    pub async fn start(self) -> Result<Server> {
        let mut io = IoHandler::new();

        // Register RPC methods
        // Each method is an async closure that receives JSON-RPC params
        // and returns a JSON-RPC result

        // Simple ping method for testing connectivity
        io.add_method("ping", move |_params: Params| async move {
            let response = serde_json::json!({
                "pong": "knetd v0.1.0"
            });
            Ok(response)
        });

        // Instance management methods
        let state = self.state.clone();
        io.add_method("instance.create", move |params: Params| {
            let state = state.clone();
            async move {
                handle_instance_create(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("instance.destroy", move |params: Params| {
            let state = state.clone();
            async move {
                handle_instance_destroy(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("instance.list", move |params: Params| {
            let state = state.clone();
            async move {
                handle_instance_list(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("instance.set_forwarding", move |params: Params| {
            let state = state.clone();
            async move {
                handle_instance_set_forwarding(state, params).await
            }
        });

        // Host management methods
        let state = self.state.clone();
        io.add_method("host.add", move |params: Params| {
            let state = state.clone();
            async move {
                handle_host_add(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("host.remove", move |params: Params| {
            let state = state.clone();
            async move {
                handle_host_remove(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("host.list", move |params: Params| {
            let state = state.clone();
            async move {
                handle_host_list(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("host.status", move |params: Params| {
            let state = state.clone();
            async move {
                handle_host_status(state, params).await
            }
        });

        // Link management methods
        let state = self.state.clone();
        io.add_method("link.set_config", move |params: Params| {
            let state = state.clone();
            async move {
                handle_link_set_config(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("link.enable", move |params: Params| {
            let state = state.clone();
            async move {
                handle_link_enable(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("link.get_status", move |params: Params| {
            let state = state.clone();
            async move {
                handle_link_get_status(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("link.get_stats", move |params: Params| {
            let state = state.clone();
            async move {
                handle_link_get_stats(state, params).await
            }
        });

        // Event subscription methods
        let state = self.state.clone();
        io.add_method("events.subscribe", move |params: Params| {
            let state = state.clone();
            async move {
                handle_events_subscribe(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("events.poll", move |params: Params| {
            let state = state.clone();
            async move {
                handle_events_poll(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("events.unsubscribe", move |params: Params| {
            let state = state.clone();
            async move {
                handle_events_unsubscribe(state, params).await
            }
        });

        // Crypto configuration methods
        let state = self.state.clone();
        io.add_method("crypto.set_config", move |params: Params| {
            let state = state.clone();
            async move {
                handle_crypto_set_config(state, params).await
            }
        });

        let state = self.state.clone();
        io.add_method("crypto.use_config", move |params: Params| {
            let state = state.clone();
            async move {
                handle_crypto_use_config(state, params).await
            }
        });

        // Compression configuration methods
        let state = self.state.clone();
        io.add_method("compress.set_config", move |params: Params| {
            let state = state.clone();
            async move {
                handle_compress_set_config(state, params).await
            }
        });

        // Ensure parent directory exists
        if let Some(parent) = Path::new(&self.socket_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow::anyhow!(
                        "Failed to create socket directory '{}': {}. \
                         Try using a socket path in a writable directory (e.g., /tmp/knetd.sock)",
                        parent.display(), e
                    ))?;
            }
        }

        // Remove stale socket file if it exists
        if Path::new(&self.socket_path).exists() {
            info!("Removing existing socket at {}", self.socket_path);
            std::fs::remove_file(&self.socket_path)?;
        }

        // Bind to Unix socket
        info!("Binding to socket {}", self.socket_path);
        let server = ServerBuilder::new(io)
            .start(&self.socket_path)?;

        info!("RPC server listening on {}", self.socket_path);

        // Return the server handle - caller must keep it alive
        // The server runs in background threads managed by jsonrpc-ipc-server
        Ok(server)
    }
}

// ============================================================================
// RPC Handler Functions
// ============================================================================

/// Handle instance.create RPC call.
async fn handle_instance_create(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: CreateInstanceRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Creating instance '{}' with host_id {}",
          req.name.as_str(), req.host_id.to_u16());

    // Get privileged flag from state before creating instance
    let use_privileged = {
        let state = state.lock().await;
        state.use_privileged
    };

    // Get log level from state
    let log_level = {
        let state = state.lock().await;
        state.log_level.clone()
    };

    // Create the VPN instance
    let instance = VpnInstance::new(req.name.clone(), req.host_id, use_privileged, &log_level)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to create instance: {}", e),
            data: None,
        })?;

    // Add to state
    let mut state = state.lock().await;

    if state.instances.contains_key(&req.name) {
        return Err(RpcError {
            code: ErrorCode::ServerError(-32001),
            message: format!("Instance '{}' already exists", req.name.as_str()),
            data: None,
        });
    }

    state.instances.insert(req.name, instance);

    let response = CreateInstanceResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle instance.destroy RPC call.
async fn handle_instance_destroy(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: DestroyInstanceRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Destroying instance '{}'", req.name.as_str());

    // Remove from state (Drop will handle cleanup)
    let mut state = state.lock().await;

    if state.instances.remove(&req.name).is_none() {
        return Err(RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.name.as_str()),
            data: None,
        });
    }

    let response = DestroyInstanceResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle instance.list RPC call.
async fn handle_instance_list(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let _req: ListInstancesRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Listing instances");

    let state = state.lock().await;

    let instances: Vec<InstanceInfo> = state.instances.iter()
        .map(|(name, instance)| {
            // Get crypto info if configured
            let crypto = instance.crypto_config().map(|(model, cipher, hash, _key_file, _config_num)| {
                knetd_common::CryptoInfo {
                    model: model.to_string(),
                    cipher: cipher.to_string(),
                    hash: hash.to_string(),
                }
            });

            // Get compression info if configured
            let compression = instance.compression_config().map(|(model, threshold, level)| {
                knetd_common::CompressionInfo {
                    model: model.to_string(),
                    threshold,
                    level,
                }
            });

            InstanceInfo {
                name: name.clone(),
                host_id: instance.host_id(),
                running: instance.is_forwarding(),
                crypto,
                compression,
            }
        })
        .collect();

    let response = ListInstancesResponse { instances };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle instance.set_forwarding RPC call.
///
/// Enables or disables data forwarding on a VPN instance. When disabled, no traffic flows.
async fn handle_instance_set_forwarding(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SetForwardingRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Setting forwarding for instance '{}' to {}", req.instance.as_str(), req.enabled);

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.set_forwarding(req.enabled)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to set forwarding: {}", e),
            data: None,
        })?;

    let response = SetForwardingResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

// ============================================================================
// Host Management
// ============================================================================

/// Handle host.add RPC call.
async fn handle_host_add(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: AddHostRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Adding host {} to instance '{}'",
          req.host_id.to_u16(), req.instance.as_str());

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.add_host(req.host_id, req.name)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to add host: {}", e),
            data: None,
        })?;

    let response = AddHostResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle host.remove RPC call.
async fn handle_host_remove(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: RemoveHostRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Removing host {} from instance '{}'",
          req.host_id.to_u16(), req.instance.as_str());

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.remove_host(req.host_id)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to remove host: {}", e),
            data: None,
        })?;

    let response = RemoveHostResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle host.list RPC call.
async fn handle_host_list(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: ListHostsRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Listing hosts in instance '{}'", req.instance.as_str());

    let state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    let hosts: Vec<HostInfo> = instance.list_hosts().iter()
        .map(|&host_id| {
            // TODO: Query knet for actual reachability status
            HostInfo {
                host_id,
                name: instance.get_host_name(host_id).map(|s| s.to_string()),
                reachable: false,
            }
        })
        .collect();

    let response = ListHostsResponse { hosts };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle host.status RPC call.
async fn handle_host_status(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: GetHostStatusRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Getting status for host {} in instance '{}'",
          req.host_id.to_u16(), req.instance.as_str());

    let state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    // Check if host exists
    if !instance.list_hosts().contains(&req.host_id) {
        return Err(RpcError {
            code: ErrorCode::ServerError(-32003),
            message: format!("Host {} not found in instance '{}'",
                           req.host_id.to_u16(), req.instance.as_str()),
            data: None,
        });
    }

    // TODO: Query knet API for actual reachability status
    let host = HostInfo {
        host_id: req.host_id,
        name: instance.get_host_name(req.host_id).map(|s| s.to_string()),
        reachable: false,
    };

    let response = GetHostStatusResponse { host };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle link.set_config RPC call.
async fn handle_link_set_config(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SetLinkConfigRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Configuring link {} for host {} in instance '{}'",
        req.link_id.to_u8(),
        req.host_id.to_u16(),
        req.instance.as_str()
    );

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.set_link_config(
        req.host_id,
        req.link_id.to_u8(),
        &req.transport,
        &req.src_addr,
        req.dst_addr.as_deref(),
    )
    .map_err(|e| RpcError {
        code: ErrorCode::InternalError,
        message: format!("Failed to configure link: {}", e),
        data: None,
    })?;

    let response = SetLinkConfigResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle link.enable RPC call.
async fn handle_link_enable(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SetLinkEnableRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: {} link {} for host {} in instance '{}'",
        if req.enable { "Enabling" } else { "Disabling" },
        req.link_id.to_u8(),
        req.host_id.to_u16(),
        req.instance.as_str()
    );

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.set_link_enable(req.host_id, req.link_id.to_u8(), req.enable)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to enable/disable link: {}", e),
            data: None,
        })?;

    let response = SetLinkEnableResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle link.get_status RPC call.
async fn handle_link_get_status(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: GetLinkStatusRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Getting status for link {} of host {} in instance '{}'",
        req.link_id.to_u8(),
        req.host_id.to_u16(),
        req.instance.as_str()
    );

    let state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    let link_status = instance.get_link_status(req.host_id, req.link_id.to_u8())
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to get link status: {}", e),
            data: None,
        })?;

    // Convert knet LinkStatus to our LinkInfo
    // Note: knet doesn't return transport type in status, so we use "unknown"
    let link = LinkInfo {
        link_id: req.link_id,
        transport: "unknown".to_string(),
        src_addr: Some(format!("{}:{}", link_status.src_ipaddr, link_status.src_port)),
        dst_addr: Some(format!("{}:{}", link_status.dst_ipaddr, link_status.dst_port)),
        enabled: link_status.enabled,
        connected: link_status.connected,
    };

    let response = GetLinkStatusResponse { link };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle link.get_stats RPC call.
async fn handle_link_get_stats(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: GetLinkStatsRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Getting stats for link {} of host {} in instance '{}'",
        req.link_id.to_u8(),
        req.host_id.to_u16(),
        req.instance.as_str()
    );

    let state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    let link_status = instance.get_link_status(req.host_id, req.link_id.to_u8())
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to get link stats: {}", e),
            data: None,
        })?;

    // Convert knet LinkStatus stats to our LinkStats
    let stats = LinkStats {
        tx_data_packets: link_status.stats.tx_data_packets,
        rx_data_packets: link_status.stats.rx_data_packets,
        tx_data_bytes: link_status.stats.tx_data_bytes,
        rx_data_bytes: link_status.stats.rx_data_bytes,
        latency_min: link_status.stats.latency_min,
        latency_max: link_status.stats.latency_max,
        latency_ave: link_status.stats.latency_ave,
        down_count: link_status.stats.down_count,
        up_count: link_status.stats.up_count,
    };

    let response = GetLinkStatsResponse { stats };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle events.subscribe RPC call.
async fn handle_events_subscribe(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SubscribeEventsRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Subscribing to events for instance '{}'", req.instance.as_str());

    let mut state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32002),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    // Create subscription
    let subscription_id = Uuid::new_v4().to_string();
    let receiver = instance.subscribe_events();

    state.subscriptions.insert(
        subscription_id.clone(),
        EventSubscription {
            receiver,
        },
    );

    let response = SubscribeEventsResponse { subscription_id };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle events.poll RPC call.
async fn handle_events_poll(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: PollEventsRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    let mut state = state.lock().await;

    let subscription = state.subscriptions.get_mut(&req.subscription_id)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32004),
            message: format!("Subscription '{}' not found", req.subscription_id),
            data: None,
        })?;

    // Collect available events (non-blocking)
    let max_events = req.max_events.unwrap_or(10);
    let mut events = Vec::new();

    for _ in 0..max_events {
        match subscription.receiver.try_recv() {
            Ok(event) => events.push(event),
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(_)) => {
                // Some events were missed, continue
                continue;
            }
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }

    let response = PollEventsResponse { events };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle events.unsubscribe RPC call.
async fn handle_events_unsubscribe(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: UnsubscribeEventsRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!("RPC: Unsubscribing from events: {}", req.subscription_id);

    let mut state = state.lock().await;

    let success = state.subscriptions.remove(&req.subscription_id).is_some();

    let response = UnsubscribeEventsResponse { success };
    Ok(serde_json::to_value(response).unwrap())
}

// ============================================================================
// Crypto Configuration Handlers
// ============================================================================

/// Handle crypto.set_config RPC call.
async fn handle_crypto_set_config(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SetCryptoConfigRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Setting crypto config for instance '{}': model={}, cipher={}, hash={}, config_num={}",
        req.instance.as_str(),
        req.model,
        req.cipher,
        req.hash,
        req.config_num
    );

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32001),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.set_crypto_config(
        &req.model,
        &req.cipher,
        &req.hash,
        &req.key,
        req.config_num,
    )
    .map_err(|e| RpcError {
        code: ErrorCode::InternalError,
        message: format!("Failed to set crypto config: {}", e),
        data: None,
    })?;

    let response = SetCryptoConfigResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

/// Handle crypto.use_config RPC call.
async fn handle_crypto_use_config(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: UseCryptoConfigRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Activating crypto config {} for instance '{}'",
        req.config_num,
        req.instance.as_str()
    );

    let state = state.lock().await;

    let instance = state.instances.get(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32001),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.use_crypto_config(req.config_num)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to activate crypto config: {}", e),
            data: None,
        })?;

    let response = UseCryptoConfigResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}

// ============================================================================
// Compression Configuration Handlers
// ============================================================================

/// Handle compress.set_config RPC call.
async fn handle_compress_set_config(state: DaemonState, params: Params) -> Result<Value, RpcError> {
    let req: SetCompressionConfigRequest = params.parse()
        .map_err(|e| RpcError {
            code: ErrorCode::InvalidParams,
            message: format!("Invalid parameters: {}", e),
            data: None,
        })?;

    info!(
        "RPC: Setting compression config for instance '{}': model={}, threshold={}, level={}",
        req.instance.as_str(),
        req.model,
        req.threshold,
        req.level
    );

    let mut state = state.lock().await;

    let instance = state.instances.get_mut(&req.instance)
        .ok_or_else(|| RpcError {
            code: ErrorCode::ServerError(-32001),
            message: format!("Instance '{}' not found", req.instance.as_str()),
            data: None,
        })?;

    instance.set_compression(&req.model, req.threshold, req.level)
        .map_err(|e| RpcError {
            code: ErrorCode::InternalError,
            message: format!("Failed to set compression config: {}", e),
            data: None,
        })?;

    let response = SetCompressionConfigResponse { success: true };
    Ok(serde_json::to_value(response).unwrap())
}
