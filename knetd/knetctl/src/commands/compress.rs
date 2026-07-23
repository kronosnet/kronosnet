//! Compression configuration commands.
//!
//! Commands for configuring packet compression on VPN instances.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;

/// Compress subcommands.
#[derive(Subcommand)]
pub enum CompressCommands {
    /// List compression models available in this build
    List,

    /// Configure packet compression
    #[command(override_usage = "knetctl compress set-config -i|--instance <INSTANCE> -m|--model <MODEL> [-t|--threshold <THRESHOLD>] [-l|--level <LEVEL>]")]
    SetConfig {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Compression model (zlib, lz4, lz4hc, lzo2, lzma, bzip2, zstd, or none to disable)
        #[arg(short = 'm', long)]
        model: String,

        /// Threshold in bytes - packets smaller than this won't be compressed
        /// (0 = default 100 bytes, 1 = compress everything)
        #[arg(short = 't', long, default_value = "0")]
        threshold: u32,

        /// Compression level (meaning varies by model, typically 1-9)
        /// zlib: 0-9 (0=none, 9=max)
        /// lz4: 1-9 (1=max compression, 9=fastest)
        /// lz4hc: 1-16 (1=min, 16=max)
        /// lzma: 0-9
        /// bzip2: 1-9
        /// lzo2: 1 (selects algorithm)
        /// zstd: 1-22
        #[arg(short = 'l', long, default_value = "6")]
        level: i32,
    },
}

/// Execute a compress command.
pub async fn execute(cmd: CompressCommands, client: &RpcClient) -> Result<()> {
    match cmd {
        CompressCommands::List => {
            let request = GetCompressOptionsRequest {};
            let response = client.call("compress.get_options", serde_json::to_value(request)?).await?;
            let resp: GetCompressOptionsResponse = serde_json::from_value(response)?;

            if resp.models.is_empty() {
                println!("Available compression models: (none)");
            } else {
                let names: Vec<&str> = resp.models.iter().map(|m| m.name.as_str()).collect();
                println!("Available compression models: {}", names.join(", "));
            }
        }

        CompressCommands::SetConfig {
            instance,
            model,
            threshold,
            level,
        } => {
            let request = SetCompressionConfigRequest {
                instance: InstanceName::new(&instance),
                model: model.clone(),
                threshold,
                level,
            };

            let response = client.call("compress.set_config", serde_json::to_value(request)?).await?;
            let resp: SetCompressionConfigResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Compression configuration set successfully for instance '{}'", instance);
                println!("  Model: {}", model);
                println!("  Threshold: {} bytes", threshold);
                println!("  Level: {}", level);
            } else {
                println!("✗ Failed to set compression configuration");
            }
        }
    }

    Ok(())
}
