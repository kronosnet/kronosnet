//! knetctl - Command-line control utility for knetd daemon
//!
//! This CLI connects to the knetd daemon via a Unix domain socket
//! and sends JSON-RPC 2.0 commands to manage VPN instances.

mod client;
mod commands;
mod visualize;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::path::PathBuf;

/// Main CLI argument parser
#[derive(Parser)]
#[command(name = "knetctl")]
#[command(about = "Control utility for knetd daemon", long_about = None)]
struct Cli {
    /// Path to the daemon's Unix socket
    #[arg(short = 's', long, default_value = "/run/knetd/knetd.sock")]
    socket: String,

    /// Start an interactive shell for entering multiple commands
    #[arg(short = 'i', long)]
    interactive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Parser used inside the interactive shell — same commands, no global flags.
#[derive(Parser)]
#[command(name = "knetctl", about = "Type 'help' for commands, 'exit' to quit")]
struct ShellCommand {
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

    /// Manage the tap (nozzle) device attached to a VPN instance
    #[command(subcommand)]
    Nozzle(commands::nozzle::NozzleCommands),

    /// Manage daemon state snapshots
    #[command(subcommand)]
    State(commands::state::StateCommands),
}

async fn dispatch(client: &client::RpcClient, command: Commands) -> Result<()> {
    match command {
        Commands::Ping => commands::ping(client).await?,
        Commands::Instance(cmd) => commands::instance::handle_command(client, cmd).await?,
        Commands::Host(cmd) => commands::host::handle_command(client, cmd).await?,
        Commands::Link(cmd) => commands::link::handle_command(client, cmd).await?,
        Commands::Events(cmd) => commands::events::handle_command(client, cmd).await?,
        Commands::Crypto(cmd) => commands::crypto::execute(cmd, client).await?,
        Commands::Compress(cmd) => commands::compress::execute(cmd, client).await?,
        Commands::Topology(cmd) => commands::topology::handle_command(client, cmd).await?,
        Commands::Nozzle(cmd) => commands::nozzle::handle_command(client, cmd).await?,
        Commands::State(cmd) => commands::state::execute(cmd, client).await?,
    }
    Ok(())
}

async fn interactive_shell(client: &client::RpcClient) -> Result<()> {
    let mut rl = DefaultEditor::new()?;

    let history_path: Option<PathBuf> = std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".knetctl_history"));

    if let Some(ref path) = history_path {
        let _ = rl.load_history(path);
    }

    println!("knetctl interactive shell. Type 'help' for commands, 'exit' to quit.");

    loop {
        let readline = rl.readline("knetctl> ");
        match readline {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);

                match line.as_str() {
                    "exit" | "quit" => break,
                    "help" | "?" => {
                        ShellCommand::command().print_help()?;
                        println!();
                        continue;
                    }
                    _ => {}
                }

                let tokens = match shlex::split(&line) {
                    Some(t) => t,
                    None => {
                        eprintln!("Error: invalid quoting in command");
                        continue;
                    }
                };

                // Prepend a dummy argv[0] as clap expects the binary name first.
                let args: Vec<String> = std::iter::once("knetctl".to_string())
                    .chain(tokens)
                    .collect();

                match ShellCommand::try_parse_from(&args) {
                    Ok(shell_cmd) => {
                        if let Err(e) = dispatch(client, shell_cmd.command).await {
                            eprintln!("Error: {e}");
                        }
                    }
                    Err(e) => {
                        // clap prints help/version to stdout and errors to stderr.
                        let _ = e.print();
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C clears the current input; continue the loop.
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D exits the shell.
                break;
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Readline error: {e}"));
            }
        }
    }

    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.interactive {
        let client = client::RpcClient::new(&cli.socket).await?;
        interactive_shell(&client).await?;
    } else if let Some(command) = cli.command {
        let client = client::RpcClient::new(&cli.socket).await?;
        dispatch(&client, command).await?;
    } else {
        Cli::command().print_help()?;
        println!();
        std::process::exit(1);
    }

    Ok(())
}
