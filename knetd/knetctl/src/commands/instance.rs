//! Instance management commands.
//!
//! Commands for creating, destroying, and listing VPN instances.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;

/// Instance subcommands.
#[derive(Subcommand)]
pub enum InstanceCommands {
    /// Create a new VPN instance
    #[command(override_usage = "knetctl instance create -n|--name <NAME> -H|--host-id <HOST_ID>")]
    Create {
        /// Name for the new instance
        #[arg(short = 'n', long)]
        name: String,

        /// Local host ID for this instance (0-65535)
        #[arg(short = 'H', long)]
        host_id: u16,
    },

    /// Destroy an existing VPN instance
    #[command(override_usage = "knetctl instance destroy -n|--name <NAME>")]
    Destroy {
        /// Name of the instance to destroy
        #[arg(short = 'n', long)]
        name: String,
    },

    /// List all VPN instances
    List,

    /// Start data forwarding (enable traffic flow)
    #[command(override_usage = "knetctl instance start -n|--name <NAME>")]
    Start {
        /// Name of the instance to start
        #[arg(short = 'n', long)]
        name: String,
    },

    /// Stop data forwarding (disable traffic flow)
    #[command(override_usage = "knetctl instance stop -n|--name <NAME>")]
    Stop {
        /// Name of the instance to stop
        #[arg(short = 'n', long)]
        name: String,
    },
}

/// Handle instance commands.
pub async fn handle_command(client: &RpcClient, cmd: InstanceCommands) -> Result<()> {
    match cmd {
        InstanceCommands::Create { name, host_id } => {
            let req = CreateInstanceRequest {
                name: InstanceName::new(name.clone()),
                host_id: HostId::new(host_id),
            };

            let response = client.call("instance.create", serde_json::to_value(req)?).await?;
            let resp: CreateInstanceResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Created instance '{}'", name);
            } else {
                println!("✗ Failed to create instance '{}'", name);
            }
        }

        InstanceCommands::Destroy { name } => {
            let req = DestroyInstanceRequest {
                name: InstanceName::new(name.clone()),
            };

            let response = client.call("instance.destroy", serde_json::to_value(req)?).await?;
            let resp: DestroyInstanceResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Destroyed instance '{}'", name);
            } else {
                println!("✗ Failed to destroy instance '{}'", name);
            }
        }

        InstanceCommands::List => {
            let req = ListInstancesRequest {};

            let response = client.call("instance.list", serde_json::to_value(req)?).await?;
            let resp: ListInstancesResponse = serde_json::from_value(response)?;

            if resp.instances.is_empty() {
                println!("No instances configured");
            } else {
                println!("VPN Instances:");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                for instance in &resp.instances {
                    let status = if instance.running { "RUNNING" } else { "STOPPED" };
                    println!("  {} (host_id: {}) - {}",
                             instance.name.as_str(),
                             instance.host_id.to_u16(),
                             status);
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Total: {}", resp.instances.len());
            }
        }

        InstanceCommands::Start { name } => {
            let req = SetForwardingRequest {
                instance: InstanceName::new(name.clone()),
                enabled: true,
            };

            let response = client.call("instance.set_forwarding", serde_json::to_value(req)?).await?;
            let resp: SetForwardingResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Started instance '{}' (data forwarding enabled)", name);
            } else {
                println!("✗ Failed to start instance '{}'", name);
            }
        }

        InstanceCommands::Stop { name } => {
            let req = SetForwardingRequest {
                instance: InstanceName::new(name.clone()),
                enabled: false,
            };

            let response = client.call("instance.set_forwarding", serde_json::to_value(req)?).await?;
            let resp: SetForwardingResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Stopped instance '{}' (data forwarding disabled)", name);
            } else {
                println!("✗ Failed to stop instance '{}'", name);
            }
        }
    }
    Ok(())
}
