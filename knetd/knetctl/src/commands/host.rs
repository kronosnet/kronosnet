//! Host management commands.
//!
//! Commands for adding, removing, and listing remote hosts in VPN instances.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;

/// Host subcommands.
#[derive(Subcommand)]
pub enum HostCommands {
    /// Add a remote host to a VPN instance
    #[command(override_usage = "knetctl host add -i|--instance <INSTANCE> -H|--host-id <HOST_ID> [-n|--name <NAME>]")]
    Add {
        /// Name of the VPN instance
        #[arg(short = 'i', long)]
        instance: String,

        /// Host ID to add (0-65535)
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Optional human-readable name for this host
        #[arg(short = 'n', long)]
        name: Option<String>,
    },

    /// Remove a remote host from a VPN instance
    #[command(override_usage = "knetctl host remove -i|--instance <INSTANCE> -H|--host-id <HOST_ID>")]
    Remove {
        /// Name of the VPN instance
        #[arg(short = 'i', long)]
        instance: String,

        /// Host ID to remove
        #[arg(short = 'H', long)]
        host_id: u16,
    },

    /// List all remote hosts in a VPN instance
    #[command(override_usage = "knetctl host list -i|--instance <INSTANCE>")]
    List {
        /// Name of the VPN instance
        #[arg(short = 'i', long)]
        instance: String,
    },

    /// Get status of a specific remote host
    #[command(override_usage = "knetctl host status -i|--instance <INSTANCE> -H|--host-id <HOST_ID>")]
    Status {
        /// Name of the VPN instance
        #[arg(short = 'i', long)]
        instance: String,

        /// Host ID to query
        #[arg(short = 'H', long)]
        host_id: u16,
    },
}

/// Handle host commands.
pub async fn handle_command(client: &RpcClient, cmd: HostCommands) -> Result<()> {
    match cmd {
        HostCommands::Add { instance, host_id, name } => {
            let req = AddHostRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                name,
            };

            let response = client.call("host.add", serde_json::to_value(req)?).await?;
            let resp: AddHostResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Added host {} to instance '{}'", host_id, instance);
            } else {
                println!("✗ Failed to add host {} to instance '{}'", host_id, instance);
            }
        }

        HostCommands::Remove { instance, host_id } => {
            let req = RemoveHostRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
            };

            let response = client.call("host.remove", serde_json::to_value(req)?).await?;
            let resp: RemoveHostResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Removed host {} from instance '{}'", host_id, instance);
            } else {
                println!("✗ Failed to remove host {} from instance '{}'", host_id, instance);
            }
        }

        HostCommands::List { instance } => {
            let req = ListHostsRequest {
                instance: InstanceName::new(instance.clone()),
            };

            let response = client.call("host.list", serde_json::to_value(req)?).await?;
            let resp: ListHostsResponse = serde_json::from_value(response)?;

            if resp.hosts.is_empty() {
                println!("No hosts configured in instance '{}'", instance);
            } else {
                println!("Remote Hosts in '{}':", instance);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                for host in &resp.hosts {
                    let name_str = host.name.as_deref().unwrap_or("<unnamed>");
                    let status = if host.reachable { "REACHABLE" } else { "UNREACHABLE" };
                    println!("  Host {} ({}) - {}",
                             host.host_id.to_u16(),
                             name_str,
                             status);
                }
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!("Total: {}", resp.hosts.len());
            }
        }

        HostCommands::Status { instance, host_id } => {
            let req = GetHostStatusRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
            };

            let response = client.call("host.status", serde_json::to_value(req)?).await?;
            let resp: GetHostStatusResponse = serde_json::from_value(response)?;

            let name_str = resp.host.name.as_deref().unwrap_or("<unnamed>");
            let status = if resp.host.reachable { "REACHABLE" } else { "UNREACHABLE" };

            println!("Host {} in instance '{}':", host_id, instance);
            println!("  Name:   {}", name_str);
            println!("  Status: {}", status);
        }
    }
    Ok(())
}
