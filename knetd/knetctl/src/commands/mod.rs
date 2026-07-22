//! Command implementations for knetctl.
//!
//! Each module here corresponds to a subcommand category
//! (instance, host, link, crypto, etc.)

pub mod instance;
pub mod host;
pub mod link;
pub mod events;
pub mod topology;
pub mod crypto;
pub mod compress;
pub mod nozzle;
pub mod state;

use crate::client::RpcClient;
use anyhow::Result;
use serde_json::json;

/// Simple ping command to test daemon connectivity.
///
/// This is useful for verifying the daemon is running and responding.
pub async fn ping(client: &RpcClient) -> Result<()> {
    let response = client.call("ping", json!({})).await?;
    println!("{}", response);
    Ok(())
}
