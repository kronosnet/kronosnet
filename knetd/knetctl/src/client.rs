//! JSON-RPC client for communicating with knetd daemon.

use anyhow::Result;
use jsonrpc_core_client::transports::ipc;
use jsonrpc_core_client::{RpcChannel, TypedClient};
use serde_json::Value;

/// RPC client that communicates with knetd over a Unix socket.
pub struct RpcClient {
    client: TypedClient,
}

impl RpcClient {
    /// Create a new RPC client connected to the daemon.
    ///
    /// # Arguments
    /// * `socket_path` - Path to the Unix domain socket (e.g., "/run/knetd/knetd.sock")
    ///
    /// # Errors
    /// Returns an error if the connection fails (daemon not running, socket doesn't exist, etc.)
    pub async fn new(socket_path: &str) -> Result<Self> {
        let channel: RpcChannel = ipc::connect(socket_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {:?}", socket_path, e))?;
        let client = channel.into();
        Ok(Self { client })
    }

    /// Call a JSON-RPC method on the daemon.
    ///
    /// # Arguments
    /// * `method` - The RPC method name (e.g., "ping", "instance.create")
    /// * `params` - JSON parameters for the method call
    ///
    /// # Returns
    /// The JSON-RPC result value
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // JSON-RPC expects params as a single value, not wrapped in tuple
        let response: Value = self.client
            .call_method(method, "", params)
            .await
            .map_err(|e| anyhow::anyhow!("RPC call failed: {:?}", e))?;
        Ok(response)
    }
}
