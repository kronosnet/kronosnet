//! Nozzle (tap device) management commands.
//!
//! Commands for creating, destroying, and querying the tap (ethernet)
//! interface attached to a VPN instance.

use crate::client::RpcClient;
use anyhow::Result;
use clap::{ArgAction, Subcommand};
use knetd_common::*;

/// Nozzle subcommands.
#[derive(Subcommand)]
pub enum NozzleCommands {
    /// Create a tap (ethernet) device for a VPN instance
    #[command(override_usage = "knetctl nozzle create -i|--instance <INSTANCE> [-n|--name <NAME>] [-a|--ip-address <IP/PREFIX>]... [--mtu <MTU>] [--mac <MAC>] [--updown-path <PATH>] [--no-auto-up]")]
    Create {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Desired tap device name (e.g. knet0); kernel assigns one if omitted
        #[arg(short = 'n', long)]
        name: Option<String>,

        /// IP address to assign to the device, in IP/PREFIX format (may be repeated)
        ///
        /// The daemon embeds the local node ID into the host portion of each address
        /// so that all nodes derive unique addresses from the same base.
        /// Example: -a 10.1.0.0/24  -a fd00::/64
        #[arg(short = 'a', long = "ip-address", value_name = "IP/PREFIX", action = ArgAction::Append)]
        ip_addresses: Vec<String>,

        /// MTU for the tap device (default: inherits from knet)
        #[arg(long)]
        mtu: Option<i32>,

        /// Base MAC address (first 4 bytes, e.g. fe:54:00:00).
        /// The daemon appends the node ID as the last two bytes to ensure uniqueness.
        #[arg(long)]
        mac: Option<String>,

        /// Directory containing nozzle up/down scripts (pre-up.d, up.d, etc.)
        #[arg(long)]
        updown_path: Option<String>,

        /// Do not bring the device up automatically when forwarding is enabled
        #[arg(long)]
        no_auto_up: bool,
    },

    /// Remove the tap device from a VPN instance
    #[command(override_usage = "knetctl nozzle destroy -i|--instance <INSTANCE>")]
    Destroy {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,
    },

    /// Show tap device status for a VPN instance
    #[command(override_usage = "knetctl nozzle status -i|--instance <INSTANCE>")]
    Status {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,
    },
}

/// Execute a nozzle command.
pub async fn handle_command(client: &RpcClient, cmd: NozzleCommands) -> Result<()> {
    match cmd {
        NozzleCommands::Create {
            instance,
            name,
            ip_addresses,
            mtu,
            mac,
            updown_path,
            no_auto_up,
        } => {
            let request = CreateNozzleRequest {
                instance: InstanceName::new(&instance),
                name,
                ip_addresses: ip_addresses.clone(),
                mtu,
                mac: mac.clone(),
                updown_path: updown_path.clone(),
                auto_up: !no_auto_up,
            };

            let response = client.call("nozzle.create", serde_json::to_value(request)?).await?;
            let resp: CreateNozzleResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("Created tap device '{}' for instance '{}'", resp.device_name, instance);
                if !ip_addresses.is_empty() {
                    println!("  IP addresses (base): {}", ip_addresses.join(", "));
                }
                if let Some(m) = mtu {
                    println!("  MTU: {}", m);
                }
                if let Some(ref mac_addr) = mac {
                    println!("  Base MAC: {}", mac_addr);
                }
                if let Some(ref path) = updown_path {
                    println!("  Up/down scripts: {}", path);
                }
                println!("  Auto-up: {}", !no_auto_up);
            } else {
                println!("Failed to create nozzle device");
            }
        }

        NozzleCommands::Destroy { instance } => {
            let request = DestroyNozzleRequest {
                instance: InstanceName::new(&instance),
            };

            let response = client.call("nozzle.destroy", serde_json::to_value(request)?).await?;
            let resp: DestroyNozzleResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("Tap device removed from instance '{}'", instance);
            } else {
                println!("Failed to remove nozzle device");
            }
        }

        NozzleCommands::Status { instance } => {
            let request = GetNozzleStatusRequest {
                instance: InstanceName::new(&instance),
            };

            let response = client.call("nozzle.status", serde_json::to_value(request)?).await?;
            let resp: GetNozzleStatusResponse = serde_json::from_value(response)?;

            match resp.nozzle {
                None => println!("No tap device attached to instance '{}'", instance),
                Some(info) => {
                    println!("Tap device for instance '{}':", instance);
                    println!("  Device:   {}", info.device_name);
                    println!("  State:    {}", if info.is_up { "up" } else { "down" });
                    println!("  Auto-up:  {}", info.auto_up);
                    if info.ip_addresses.is_empty() {
                        println!("  IPs:      (none)");
                    } else {
                        println!("  IPs (base): {}", info.ip_addresses.join(", "));
                    }
                    match info.mtu {
                        Some(m) => println!("  MTU:      {}", m),
                        None    => println!("  MTU:      (default)"),
                    }
                    match info.mac {
                        Some(ref m) => println!("  Base MAC: {}", m),
                        None        => println!("  Base MAC: (auto)"),
                    }
                    match info.updown_path {
                        Some(ref p) => println!("  Scripts:  {}", p),
                        None        => println!("  Scripts:  (none)"),
                    }
                }
            }
        }
    }

    Ok(())
}
