//! `state` subcommands for knetctl.

use crate::client::RpcClient;
use anyhow::{Context, Result};
use clap::Subcommand;
use knetd_common::*;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum StateCommands {
    /// Dump current daemon state as JSON
    Save {
        /// Write to this file instead of stdout
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

pub async fn execute(cmd: StateCommands, client: &RpcClient) -> Result<()> {
    match cmd {
        StateCommands::Save { output } => {
            let request = DumpStateRequest {};
            let response = client.call("state.dump", serde_json::to_value(request)?).await?;
            let resp: DumpStateResponse = serde_json::from_value(response)?;
            let json = serde_json::to_string_pretty(&resp.state)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &json)
                        .with_context(|| format!("Failed to write {}", path.display()))?;
                    println!("State saved to {}", path.display());
                }
                None => println!("{}", json),
            }
        }
    }
    Ok(())
}
