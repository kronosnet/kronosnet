//! Crypto configuration commands.
//!
//! Commands for configuring encryption and authentication on VPN instances.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;
use std::fs;
use std::path::PathBuf;

/// Crypto subcommands.
#[derive(Subcommand)]
pub enum CryptoCommands {
    /// Configure cryptographic settings
    #[command(override_usage = "knetctl crypto set-config -i|--instance <INSTANCE> -m|--model <MODEL> -c|--cipher <CIPHER> -H|--hash <HASH> -k|--key-file <KEY_FILE> [-n|--config-num <CONFIG_NUM>]")]
    SetConfig {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Crypto model (openssl, nss, gcrypt, or none to disable)
        #[arg(short = 'm', long, default_value = "openssl")]
        model: String,

        /// Cipher type (e.g., aes256, aes128, aes192, or none)
        #[arg(short = 'c', long, default_value = "aes256")]
        cipher: String,

        /// Hash type (e.g., sha256, sha512, sha1, or none)
        #[arg(short = 'H', long, default_value = "sha256")]
        hash: String,

        /// Path to key file (must be at least 1024 bytes)
        #[arg(short = 'k', long)]
        key_file: PathBuf,

        /// Configuration slot (1 or 2) - knet supports 2 concurrent configs for key rotation
        #[arg(short = 'n', long, default_value = "1")]
        config_num: u8,
    },

    /// List crypto libraries, ciphers, and hashes available in this build
    List,

    /// Activate a crypto configuration for transmission
    #[command(override_usage = "knetctl crypto use-config -i|--instance <INSTANCE> -n|--config-num <CONFIG_NUM>")]
    UseConfig {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Configuration slot to activate (0 or 1)
        #[arg(short = 'n', long)]
        config_num: u8,
    },
}

/// Execute a crypto command.
pub async fn execute(cmd: CryptoCommands, client: &RpcClient) -> Result<()> {
    match cmd {
        CryptoCommands::List => {
            let request = GetCryptoOptionsRequest {};
            let response = client.call("crypto.get_options", serde_json::to_value(request)?).await?;
            let resp: GetCryptoOptionsResponse = serde_json::from_value(response)?;

            println!("Available crypto options:");
            if resp.models.is_empty() {
                println!("  Models:  (none)");
            } else {
                let names: Vec<&str> = resp.models.iter().map(|m| m.name.as_str()).collect();
                println!("  Models:  {}", names.join(", "));
            }
            if resp.ciphers.is_empty() {
                println!("  Ciphers: (none)");
            } else {
                let descs: Vec<String> = resp.ciphers.iter()
                    .map(|c| format!("{} ({}, {}-bit)", c.name, c.mode, c.key_bits))
                    .collect();
                println!("  Ciphers: {}", descs.join(", "));
            }
            if resp.hashes.is_empty() {
                println!("  Hashes:  (none)");
            } else {
                let descs: Vec<String> = resp.hashes.iter()
                    .map(|h| format!("{} ({}-bit)", h.name, h.hash_bits))
                    .collect();
                println!("  Hashes:  {}", descs.join(", "));
            }
        }

        CryptoCommands::SetConfig {
            instance,
            model,
            cipher,
            hash,
            key_file,
            config_num,
        } => {
            // Read key from file
            let key = fs::read(&key_file)?;

            if key.len() < 1024 {
                return Err(anyhow::anyhow!(
                    "Key file must be at least 1024 bytes (got {} bytes)",
                    key.len()
                ));
            }

            let request = SetCryptoConfigRequest {
                instance: InstanceName::new(&instance),
                model: model.clone(),
                cipher: cipher.clone(),
                hash: hash.clone(),
                key,
                config_num,
            };

            let response = client.call("crypto.set_config", serde_json::to_value(request)?).await?;
            let resp: SetCryptoConfigResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Crypto configuration set successfully for instance '{}'", instance);
                println!("  Model: {}", model);
                println!("  Cipher: {}", cipher);
                println!("  Hash: {}", hash);
                println!("  Config slot: {}", config_num);
            } else {
                println!("✗ Failed to set crypto configuration");
            }
        }

        CryptoCommands::UseConfig {
            instance,
            config_num,
        } => {
            let request = UseCryptoConfigRequest {
                instance: InstanceName::new(&instance),
                config_num,
            };

            let response = client.call("crypto.use_config", serde_json::to_value(request)?).await?;
            let resp: UseCryptoConfigResponse = serde_json::from_value(response)?;

            if resp.success {
                println!("✓ Activated crypto config {} for instance '{}'", config_num, instance);
            } else {
                println!("✗ Failed to activate crypto configuration");
            }
        }
    }

    Ok(())
}
