//! knetctl - Command-line control utility for knetd daemon
//!
//! This CLI connects to the knetd daemon via a Unix domain socket
//! and sends JSON-RPC 2.0 commands to manage VPN instances.

mod client;
mod commands;
mod visualize;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Main CLI argument parser
#[derive(Parser)]
#[command(name = "knetctl")]
#[command(about = "Control utility for knetd daemon", long_about = None)]
struct Cli {
    /// Path to the daemon's Unix socket
    #[arg(short = 's', long, default_value = "/run/knetd/knetd.sock")]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

/// Top-level command categories
#[derive(Subcommand)]
enum Commands {
    /// Test connectivity to the daemon
    Ping,

    /// Manage VPN instances
    #[command(subcommand)]
    Instance(commands::instance::InstanceCommands),

    /// Manage remote hosts in VPN instances
    #[command(subcommand)]
    Host(commands::host::HostCommands),

    /// Manage links between hosts
    #[command(subcommand)]
    Link(commands::link::LinkCommands),

    /// Watch events from VPN instances
    #[command(subcommand)]
    Events(commands::events::EventCommands),

    /// Visualize network topology
    #[command(subcommand)]
    Topology(commands::topology::TopologyCommands),

    /// Configure encryption and authentication
    #[command(subcommand)]
    Crypto(commands::crypto::CryptoCommands),

    /// Configure packet compression
    #[command(subcommand)]
    Compress(commands::compress::CompressCommands),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Connect to daemon
    let client = client::RpcClient::new(&cli.socket).await?;

    match cli.command {
        Commands::Ping => {
            commands::ping(&client).await?;
        }
        Commands::Instance(cmd) => {
            commands::instance::handle_command(&client, cmd).await?;
        }
        Commands::Host(cmd) => {
            commands::host::handle_command(&client, cmd).await?;
        }
        Commands::Link(cmd) => {
            commands::link::handle_command(&client, cmd).await?;
        }
        Commands::Events(cmd) => {
            commands::events::handle_command(&client, cmd).await?;
        }
        Commands::Crypto(cmd) => {
            commands::crypto::execute(cmd, &client).await?;
        }
        Commands::Compress(cmd) => {
            commands::compress::execute(cmd, &client).await?;
        }
        Commands::Topology(cmd) => {
            commands::topology::handle_command(&client, cmd).await?;
        }
    }

    Ok(())
}
