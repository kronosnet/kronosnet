//! knetd - Kronosnet VPN Daemon
//!
//! A daemon for managing libknet VPN instances via a JSON-RPC 2.0 interface.
//! The daemon listens on a Unix domain socket for commands from knetctl.

mod config;
mod daemon;
mod rpc_server;
mod state;
mod vpn_instance;

use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use std::io;

/// knetd - Kronosnet VPN Daemon
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Local node ID (overrides KNETD_NODE_ID environment variable)
    /// Required when config file defines multiple nodes
    #[arg(short = 'n', long)]
    node_id: Option<u16>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Determine local node ID from:
    // 1. Command-line argument (--node-id)
    // 2. KNETD_NODE_ID environment variable
    // 3. None (valid only for backward-compatible single-node configs)
    let local_node_id = args.node_id
        .or_else(|| std::env::var("KNETD_NODE_ID").ok().and_then(|s| s.parse().ok()));

    // Load config from:
    // 1. Command-line argument (--config)
    // 2. KNETD_CONFIG environment variable
    // 3. /etc/knetd/knetd.toml (system-wide)
    // 4. ./knetd.toml (current directory)
    // 5. Built-in defaults
    let config = if let Some(config_path) = args.config.or_else(|| std::env::var("KNETD_CONFIG").ok()) {
        // Explicit config path - fail if it can't be loaded
        match config::load_config(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Error: Failed to load config file '{}': {}", config_path, e);
                std::process::exit(1);
            }
        }
    } else {
        // Try default paths, ignore "not found" errors but fail on parse errors
        match config::load_config("/etc/knetd/knetd.toml") {
            Ok(cfg) => cfg,
            Err(config::ConfigError::ReadError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // System config not found, try local config
                match config::load_config("knetd.toml") {
                    Ok(cfg) => cfg,
                    Err(config::ConfigError::ReadError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        // No config files found, use defaults
                        config::DaemonConfig::default()
                    }
                    Err(e) => {
                        eprintln!("Error: Failed to parse config file 'knetd.toml': {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: Failed to load config file '/etc/knetd/knetd.toml': {}", e);
                std::process::exit(1);
            }
        }
    };

    // Parse log level from config
    let log_level = match config.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    // Initialize logging with configured level and color settings
    // Use line-buffered writer to ensure clean output without cursor positioning
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_ansi(config.colored_logs)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_line_number(false)
        .with_file(false)
        .with_writer(move || io::LineWriter::new(io::stderr()))
        .init();

    info!("Starting knetd daemon");
    if config.colored_logs {
        info!("Colored logging enabled");
    }

    info!("Loaded configuration: socket_path={}", config.socket_path);

    // Create tokio runtime manually so we can block on it properly
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        daemon::run(config, local_node_id).await
    });

    // Explicitly shutdown runtime with timeout
    info!("Shutting down tokio runtime...");
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));

    result
}
