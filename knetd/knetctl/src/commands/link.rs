//! Link management commands.
//!
//! Commands for configuring, enabling, and monitoring links between hosts.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;

/// Link subcommands.
#[derive(Subcommand)]
pub enum LinkCommands {
    /// Configure a link to a remote host
    #[command(override_usage = "knetctl link config -i|--instance <INSTANCE> -H|--host-id <HOST_ID> -l|--link-id <LINK_ID> -t|--transport <TRANSPORT> -s|--src-addr <SRC_ADDR> [-d|--dst-addr <DST_ADDR>]")]
    Config {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Remote host ID
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Link ID (0-7)
        #[arg(short = 'l', long)]
        link_id: u8,

        /// Transport type (udp, sctp, loopback)
        #[arg(short = 't', long, default_value = "udp")]
        transport: String,

        /// Local address:port (e.g., 10.0.0.1:5000)
        #[arg(short = 's', long)]
        src_addr: String,

        /// Remote address:port (omit for dynamic links)
        #[arg(short = 'd', long)]
        dst_addr: Option<String>,
    },

    /// Enable a link
    #[command(override_usage = "knetctl link enable -i|--instance <INSTANCE> -H|--host-id <HOST_ID> -l|--link-id <LINK_ID>")]
    Enable {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Remote host ID
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Link ID (0-7)
        #[arg(short = 'l', long)]
        link_id: u8,
    },

    /// Disable a link
    #[command(override_usage = "knetctl link disable -i|--instance <INSTANCE> -H|--host-id <HOST_ID> -l|--link-id <LINK_ID>")]
    Disable {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Remote host ID
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Link ID (0-7)
        #[arg(short = 'l', long)]
        link_id: u8,
    },

    /// Get link status
    #[command(override_usage = "knetctl link status -i|--instance <INSTANCE> -H|--host-id <HOST_ID> -l|--link-id <LINK_ID>")]
    Status {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Remote host ID
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Link ID (0-7)
        #[arg(short = 'l', long)]
        link_id: u8,
    },

    /// Get link statistics
    #[command(override_usage = "knetctl link stats -i|--instance <INSTANCE> -H|--host-id <HOST_ID> -l|--link-id <LINK_ID>")]
    Stats {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Remote host ID
        #[arg(short = 'H', long)]
        host_id: u16,

        /// Link ID (0-7)
        #[arg(short = 'l', long)]
        link_id: u8,
    },
}

/// Handle link commands.
pub async fn handle_command(client: &RpcClient, cmd: LinkCommands) -> Result<()> {
    match cmd {
        LinkCommands::Config {
            instance,
            host_id,
            link_id,
            transport,
            src_addr,
            dst_addr,
        } => {
            let req = SetLinkConfigRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                link_id: LinkId::new(link_id),
                transport,
                src_addr: src_addr.clone(),
                dst_addr,
            };

            let response = client.call("link.set_config", serde_json::to_value(req)?).await?;
            let resp: SetLinkConfigResponse = serde_json::from_value(response)?;

            if resp.success {
                println!(
                    "✓ Configured link {} for host {} in instance '{}'",
                    link_id, host_id, instance
                );
                println!("  Source: {}", src_addr);
            } else {
                println!("✗ Failed to configure link");
            }
        }

        LinkCommands::Enable {
            instance,
            host_id,
            link_id,
        } => {
            let req = SetLinkEnableRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                link_id: LinkId::new(link_id),
                enable: true,
            };

            let response = client.call("link.enable", serde_json::to_value(req)?).await?;
            let resp: SetLinkEnableResponse = serde_json::from_value(response)?;

            if resp.success {
                println!(
                    "✓ Enabled link {} for host {} in instance '{}'",
                    link_id, host_id, instance
                );
            } else {
                println!("✗ Failed to enable link");
            }
        }

        LinkCommands::Disable {
            instance,
            host_id,
            link_id,
        } => {
            let req = SetLinkEnableRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                link_id: LinkId::new(link_id),
                enable: false,
            };

            let response = client.call("link.enable", serde_json::to_value(req)?).await?;
            let resp: SetLinkEnableResponse = serde_json::from_value(response)?;

            if resp.success {
                println!(
                    "✓ Disabled link {} for host {} in instance '{}'",
                    link_id, host_id, instance
                );
            } else {
                println!("✗ Failed to disable link");
            }
        }

        LinkCommands::Status {
            instance,
            host_id,
            link_id,
        } => {
            let req = GetLinkStatusRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                link_id: LinkId::new(link_id),
            };

            let response = client.call("link.get_status", serde_json::to_value(req)?).await?;
            let resp: GetLinkStatusResponse = serde_json::from_value(response)?;

            println!(
                "Link {} for host {} in instance '{}':",
                link_id, host_id, instance
            );
            println!("  Transport:  {}", resp.link.transport);
            println!(
                "  Source:     {}",
                resp.link.src_addr.as_deref().unwrap_or("N/A")
            );
            println!(
                "  Dest:       {}",
                resp.link.dst_addr.as_deref().unwrap_or("dynamic")
            );
            println!(
                "  Enabled:    {}",
                if resp.link.enabled { "yes" } else { "no" }
            );
            println!(
                "  Connected:  {}",
                if resp.link.connected { "yes" } else { "no" }
            );
        }

        LinkCommands::Stats {
            instance,
            host_id,
            link_id,
        } => {
            let req = GetLinkStatsRequest {
                instance: InstanceName::new(instance.clone()),
                host_id: HostId::new(host_id),
                link_id: LinkId::new(link_id),
            };

            let response = client.call("link.get_stats", serde_json::to_value(req)?).await?;
            let resp: GetLinkStatsResponse = serde_json::from_value(response)?;

            println!(
                "Statistics for link {} to host {} in instance '{}':",
                link_id, host_id, instance
            );
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  TX Packets:  {}", resp.stats.tx_data_packets);
            println!("  RX Packets:  {}", resp.stats.rx_data_packets);
            println!("  TX Bytes:    {}", resp.stats.tx_data_bytes);
            println!("  RX Bytes:    {}", resp.stats.rx_data_bytes);
            println!();
            println!("  Latency (µs):");
            println!("    Min:       {}", resp.stats.latency_min);
            println!("    Max:       {}", resp.stats.latency_max);
            println!("    Average:   {}", resp.stats.latency_ave);
            println!();
            println!("  Link Changes:");
            println!("    Up count:  {}", resp.stats.up_count);
            println!("    Down count:{}", resp.stats.down_count);
        }
    }
    Ok(())
}
