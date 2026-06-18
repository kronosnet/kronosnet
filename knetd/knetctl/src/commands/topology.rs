//! Network topology visualization commands.
//!
//! Commands for displaying and exporting VPN network topology in various formats.

use crate::client::RpcClient;
use crate::visualize::Topology;
use anyhow::Result;
use clap::Subcommand;
use std::fs;

/// Topology subcommands.
#[derive(Clone, Subcommand)]
pub enum TopologyCommands {
    /// Display network topology as ASCII-art
    #[command(override_usage = "knetctl topology show -i|--instance <INSTANCE> [-C|--no-color]")]
    Show {
        /// Instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Disable color output
        #[arg(short = 'C', long)]
        no_color: bool,
    },

    /// Export network topology
    #[command(override_usage = "knetctl topology export -i|--instance <INSTANCE> -f|--format <FORMAT> -o|--output <OUTPUT>")]
    Export {
        /// Instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Export format (dot, svg)
        #[arg(short = 'f', long, default_value = "dot")]
        format: ExportFormat,

        /// Output file path
        #[arg(short = 'o', long)]
        output: String,
    },
}

/// Export format for topology visualization.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExportFormat {
    /// DOT format (GraphViz)
    Dot,
    /// SVG format (rendered with GraphViz)
    Svg,
}

/// Handle topology commands with real daemon data.
pub async fn handle_command(client: &RpcClient, cmd: TopologyCommands) -> Result<()> {
    match cmd {
        TopologyCommands::Show { instance, no_color } => {
            let topology = fetch_topology(client, &instance).await?;
            let ascii = topology.render_ascii(!no_color);
            println!("{}", ascii);
        }

        TopologyCommands::Export { instance, format, output } => {
            let topology = fetch_topology(client, &instance).await?;

            let content = match format {
                ExportFormat::Dot => {
                    println!("Generating DOT format...");
                    topology.export_dot()
                }
                ExportFormat::Svg => {
                    println!("Generating SVG format (requires GraphViz)...");
                    match topology.export_svg() {
                        Ok(svg) => svg,
                        Err(e) => {
                            eprintln!("Error generating SVG: {}", e);
                            eprintln!("Falling back to DOT format...");
                            topology.export_dot()
                        }
                    }
                }
            };

            fs::write(&output, content)?;
            println!("✓ Exported to {}", output);

            match format {
                ExportFormat::Dot => {
                    println!("\nTo render the DOT file:");
                    println!("  dot -Tpng {} -o {}.png", output, instance);
                    println!("  dot -Tsvg {} -o {}.svg", output, instance);
                }
                ExportFormat::Svg => {
                    println!("\nYou can now edit the SVG in Inkscape:");
                    println!("  inkscape {}", output);
                }
            }
        }
    }

    Ok(())
}

/// Fetch topology data from the daemon.
async fn fetch_topology(client: &RpcClient, instance_name: &str) -> Result<Topology> {
    use knetd_common::{
        InstanceName, LinkId,
        ListInstancesRequest, ListInstancesResponse,
        ListHostsRequest, ListHostsResponse,
        GetLinkStatusRequest, GetLinkStatusResponse,
    };
    use std::collections::HashMap;

    // Get instance info
    let list_req = ListInstancesRequest {};
    let response = client.call("instance.list", serde_json::to_value(list_req)?).await?;
    let list_resp: ListInstancesResponse = serde_json::from_value(response)?;

    let instance = list_resp.instances.iter()
        .find(|i| i.name.as_str() == instance_name)
        .ok_or_else(|| anyhow::anyhow!("Instance '{}' not found", instance_name))?
        .clone();

    // Get list of hosts
    let host_req = ListHostsRequest {
        instance: InstanceName::new(instance_name),
    };
    let response = client.call("host.list", serde_json::to_value(host_req)?).await?;
    let host_resp: ListHostsResponse = serde_json::from_value(response)?;

    // Get links for each host (query all 8 possible link IDs)
    let mut links_map = HashMap::new();
    for host in &host_resp.hosts {
        let mut host_links = Vec::new();

        // Try all 8 possible link IDs (0-7)
        for link_id in 0..8 {
            let link_req = GetLinkStatusRequest {
                instance: InstanceName::new(instance_name),
                host_id: host.host_id,
                link_id: LinkId::new(link_id),
            };

            match client.call("link.get_status", serde_json::to_value(link_req)?).await {
                Ok(response) => {
                    if let Ok(link_resp) = serde_json::from_value::<GetLinkStatusResponse>(response) {
                        host_links.push(link_resp.link);
                    }
                }
                Err(_) => {
                    // Link not configured, skip
                }
            }
        }

        if !host_links.is_empty() {
            links_map.insert(host.host_id, host_links);
        }
    }

    Ok(Topology::from_instance(&instance, host_resp.hosts, links_map))
}

