//! Network topology visualization.
//!
//! This module provides ASCII-art and export capabilities for visualizing
//! VPN network topology, including nodes, links, and their status.

use colored::*;
use knetd_common::{HostId, LinkId, InstanceInfo, HostInfo, LinkInfo};
use std::collections::HashMap;

/// A node in the network topology.
#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub host_id: HostId,
    pub name: Option<String>,
    pub reachable: bool,
    pub is_local: bool,
}

/// A link between two nodes.
#[derive(Debug, Clone)]
pub struct TopologyLink {
    pub src_host: HostId,
    pub dst_host: HostId,
    pub link_id: LinkId,
    pub transport: String,
    pub enabled: bool,
    pub connected: bool,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
}

/// Network topology representation.
#[derive(Debug)]
pub struct Topology {
    pub instance_name: String,
    pub nodes: Vec<TopologyNode>,
    pub links: Vec<TopologyLink>,
    pub crypto: Option<(String, String, String)>,  // (model, cipher, hash)
    pub compression: Option<(String, u32, i32)>,    // (model, threshold, level)
}

impl Topology {
    /// Create a topology from instance and host information.
    pub fn from_instance(
        instance: &InstanceInfo,
        hosts: Vec<HostInfo>,
        links: HashMap<HostId, Vec<LinkInfo>>,
    ) -> Self {
        // Add local node
        let mut nodes = vec![TopologyNode {
            host_id: instance.host_id,
            name: Some(format!("local ({})", instance.host_id.to_u16())),
            reachable: true,
            is_local: true,
        }];

        // Add remote nodes
        for host in hosts {
            nodes.push(TopologyNode {
                host_id: host.host_id,
                name: host.name,
                reachable: host.reachable,
                is_local: false,
            });
        }

        // Convert link info to topology links
        let topology_links: Vec<TopologyLink> = links
            .into_iter()
            .flat_map(|(host_id, host_links)| {
                host_links.into_iter().map(move |link| TopologyLink {
                    src_host: instance.host_id,
                    dst_host: host_id,
                    link_id: LinkId::new(link.link_id.to_u8()),
                    transport: link.transport,
                    enabled: link.enabled,
                    connected: link.connected,
                    src_addr: link.src_addr,
                    dst_addr: link.dst_addr,
                })
            })
            .collect();

        // Extract crypto and compression info
        let crypto = instance.crypto.as_ref().map(|c| {
            (c.model.clone(), c.cipher.clone(), c.hash.clone())
        });

        let compression = instance.compression.as_ref().map(|c| {
            (c.model.clone(), c.threshold, c.level)
        });

        Self {
            instance_name: instance.name.to_string(),
            nodes,
            links: topology_links,
            crypto,
            compression,
        }
    }

    /// Render the topology as ASCII-art.
    ///
    /// This creates a visual representation using box-drawing characters
    /// and color coding (if supported by the terminal).
    pub fn render_ascii(&self, use_color: bool) -> String {
        let mut output = String::new();

        // Header
        output.push_str(
            "╔══════════════════════════════════════════════════════════╗\n"
        );
        output.push_str(&format!(
            "║  VPN Instance: {:41} ║\n",
            self.instance_name
        ));

        // Show crypto status
        if let Some((model, cipher, hash)) = &self.crypto {
            output.push_str(&format!(
                "║  Crypto: {}/{}/{:28}     ║\n",
                model, cipher, hash
            ));
        } else {
            output.push_str(
                "║  Crypto: disabled                                        ║\n"
            );
        }

        // Show compression status
        if let Some((model, threshold, level)) = &self.compression {
            output.push_str(&format!(
                "║  Compression: {} (threshold: {}B, level: {:9})    ║\n",
                model, threshold, level
            ));
        } else {
            output.push_str(
                "║  Compression: disabled                                   ║\n"
            );
        }

        output.push_str(
            "╚══════════════════════════════════════════════════════════╝\n\n"
        );

        // Local node
        let local_node = self
            .nodes
            .iter()
            .find(|n| n.is_local)
            .expect("Local node must exist");

        output.push_str(&self.render_node(local_node, use_color));
        output.push('\n');

        // Links and remote nodes
        let remote_nodes: Vec<_> = self.nodes.iter().filter(|n| !n.is_local).collect();

        if remote_nodes.is_empty() {
            output.push_str("  (No remote hosts configured)\n");
        } else {
            for (idx, remote_node) in remote_nodes.iter().enumerate() {
                // Find links to this remote node
                let node_links: Vec<_> = self
                    .links
                    .iter()
                    .filter(|l| l.dst_host == remote_node.host_id)
                    .collect();

                // Draw connection lines
                if node_links.is_empty() {
                    output.push_str("  ║ (no links)\n");
                } else {
                    for (link_idx, link) in node_links.iter().enumerate() {
                        let is_last_link = link_idx == node_links.len() - 1;
                        let connector = if is_last_link { "└" } else { "├" };

                        output.push_str(&format!(
                            "  ║\n  {}─── {} {}\n",
                            connector,
                            self.render_link_status(link, use_color),
                            self.render_link_label(link)
                        ));
                    }
                }

                // Draw remote node
                let connector = if idx < remote_nodes.len() - 1 {
                    "║"
                } else {
                    " "
                };
                output.push_str(&format!("  {}\n", connector));
                output.push_str(&self.render_node(remote_node, use_color));
                output.push_str(&format!("\n  {}\n", connector));
            }
        }

        // Legend
        output.push_str("\nLegend:\n");
        if use_color {
            output.push_str(&format!(
                "  {} enabled & connected  {} enabled & disconnected  {} disabled\n",
                "━━━".green().bold(),
                "╌╌╌".yellow().bold(),
                "···".red()
            ));
        } else {
            output.push_str("  ━━━ enabled & connected  ╌╌╌ enabled & disconnected  ··· disabled\n");
        }
        output.push_str(&format!(
            "  {} local node  {} remote node (reachable)  {} remote node (unreachable)\n",
            "⬢", "◯", "◌"
        ));

        output
    }

    /// Render a single node.
    fn render_node(&self, node: &TopologyNode, use_color: bool) -> String {
        let symbol = if node.is_local { "⬢" } else if node.reachable { "◯" } else { "◌" };

        let name = node
            .name
            .as_ref()
            .map(|n| format!(" ({})", n))
            .unwrap_or_default();

        let node_str = format!(
            "  {} Host {} {}",
            symbol,
            node.host_id.to_u16(),
            name
        );

        if use_color {
            if node.is_local {
                node_str.bright_cyan().bold().to_string()
            } else if node.reachable {
                node_str.green().to_string()
            } else {
                node_str.red().to_string()
            }
        } else {
            node_str
        }
    }

    /// Render link status symbol.
    fn render_link_status(&self, link: &TopologyLink, use_color: bool) -> String {
        let symbol = if link.enabled && link.connected {
            "━━━"
        } else if link.enabled {
            "╌╌╌"
        } else {
            "···"
        };

        if use_color {
            if link.enabled && link.connected {
                symbol.green().bold().to_string()
            } else if link.enabled {
                symbol.yellow().bold().to_string()
            } else {
                symbol.red().to_string()
            }
        } else {
            symbol.to_string()
        }
    }

    /// Render link label with details.
    fn render_link_label(&self, link: &TopologyLink) -> String {
        let status = if link.enabled && link.connected {
            "UP"
        } else if link.enabled {
            "DOWN"
        } else {
            "DISABLED"
        };

        let addrs = if let (Some(src), Some(dst)) = (&link.src_addr, &link.dst_addr) {
            format!(" {}→{}", src, dst)
        } else {
            String::new()
        };

        format!(
            "Link {} ({}) [{}]{}",
            link.link_id.to_u8(),
            link.transport,
            status,
            addrs
        )
    }

    /// Export topology to DOT format (GraphViz).
    ///
    /// This format can be rendered with GraphViz tools:
    /// - `dot -Tpng topology.dot -o topology.png`
    /// - `dot -Tsvg topology.dot -o topology.svg`
    pub fn export_dot(&self) -> String {
        let mut dot = String::new();

        // Header
        dot.push_str("digraph kronosnet_vpn {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=rounded];\n");
        dot.push_str("  edge [fontsize=10];\n\n");

        // Title with crypto/compression info
        let mut label = format!("VPN Instance: {}", self.instance_name);

        if let Some((model, cipher, hash)) = &self.crypto {
            label.push_str(&format!("\\nCrypto: {}/{}/{}", model, cipher, hash));
        } else {
            label.push_str("\\nCrypto: disabled");
        }

        if let Some((model, threshold, level)) = &self.compression {
            label.push_str(&format!("\\nCompression: {} (threshold: {}B, level: {})", model, threshold, level));
        } else {
            label.push_str("\\nCompression: disabled");
        }

        dot.push_str(&format!(
            "  labelloc=\"t\";\n  label=\"{}\";\n\n",
            label
        ));

        // Nodes
        for node in &self.nodes {
            let name = node
                .name
                .as_ref()
                .map(|n| format!("\\n{}", n))
                .unwrap_or_default();

            let color = if node.is_local {
                "lightblue"
            } else if node.reachable {
                "lightgreen"
            } else {
                "lightcoral"
            };

            let style = if node.is_local { "filled,bold" } else { "filled" };

            dot.push_str(&format!(
                "  host_{} [label=\"Host {}{}\" fillcolor=\"{}\" style=\"{}\"];\n",
                node.host_id.to_u16(),
                node.host_id.to_u16(),
                name,
                color,
                style
            ));
        }

        dot.push('\n');

        // Links
        for link in &self.links {
            let style = if link.enabled && link.connected {
                "solid"
            } else if link.enabled {
                "dashed"
            } else {
                "dotted"
            };

            let color = if link.enabled && link.connected {
                "green"
            } else if link.enabled {
                "orange"
            } else {
                "red"
            };

            let label = format!(
                "L{} ({}){}",
                link.link_id.to_u8(),
                link.transport,
                if link.enabled && link.connected {
                    ""
                } else if link.enabled {
                    "\\nDOWN"
                } else {
                    "\\nDISABLED"
                }
            );

            dot.push_str(&format!(
                "  host_{} -> host_{} [label=\"{}\" style=\"{}\" color=\"{}\"];\n",
                link.src_host.to_u16(),
                link.dst_host.to_u16(),
                label,
                style,
                color
            ));
        }

        // Legend
        dot.push_str("\n  // Legend\n");
        dot.push_str("  subgraph cluster_legend {\n");
        dot.push_str("    label=\"Legend\";\n");
        dot.push_str("    style=filled;\n");
        dot.push_str("    color=lightgrey;\n");
        dot.push_str("    legend_local [label=\"Local Node\" fillcolor=\"lightblue\" style=\"filled\"];\n");
        dot.push_str("    legend_remote [label=\"Remote Node\" fillcolor=\"lightgreen\" style=\"filled\"];\n");
        dot.push_str("    legend_unreachable [label=\"Unreachable\" fillcolor=\"lightcoral\" style=\"filled\"];\n");
        dot.push_str("    legend_local -> legend_remote [label=\"Link UP\" color=\"green\"];\n");
        dot.push_str("    legend_remote -> legend_unreachable [label=\"Link DOWN\" color=\"orange\" style=\"dashed\"];\n");
        dot.push_str("  }\n");

        dot.push_str("}\n");
        dot
    }

    /// Export topology to SVG format.
    ///
    /// This uses the DOT format and attempts to render it with GraphViz.
    /// Falls back to including the DOT source in the SVG if GraphViz is not available.
    pub fn export_svg(&self) -> Result<String, String> {
        use std::process::{Command, Stdio};
        use std::io::Write;

        let dot_source = self.export_dot();

        // Try to use GraphViz 'dot' command
        let mut child = Command::new("dot")
            .arg("-Tsvg")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn 'dot' command: {}. Is GraphViz installed?", e))?;

        // Write DOT source to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(dot_source.as_bytes())
                .map_err(|e| format!("Failed to write to dot stdin: {}", e))?;
        }

        // Read SVG output
        let output = child.wait_with_output()
            .map_err(|e| format!("Failed to wait for dot command: {}", e))?;

        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| format!("Invalid UTF-8 in SVG output: {}", e))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("GraphViz 'dot' command failed: {}", stderr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use knetd_common::InstanceName;

    #[test]
    fn test_empty_topology() {
        let instance = InstanceInfo {
            name: InstanceName::new("test"),
            host_id: HostId::new(1),
            running: true,
            crypto: None,
            compression: None,
        };

        let topology = Topology::from_instance(&instance, vec![], HashMap::new());

        assert_eq!(topology.nodes.len(), 1);
        assert_eq!(topology.links.len(), 0);
        assert_eq!(topology.instance_name, "test");
    }

    #[test]
    fn test_ascii_rendering() {
        let instance = InstanceInfo {
            name: InstanceName::new("test"),
            host_id: HostId::new(1),
            running: true,
            crypto: None,
            compression: None,
        };

        let topology = Topology::from_instance(&instance, vec![], HashMap::new());
        let ascii = topology.render_ascii(false);

        assert!(ascii.contains("VPN Instance: test"));
        assert!(ascii.contains("Host 1"));
        assert!(ascii.contains("Legend"));
        assert!(ascii.contains("Crypto: disabled"));
        assert!(ascii.contains("Compression: disabled"));
    }

    #[test]
    fn test_dot_export() {
        let instance = InstanceInfo {
            name: InstanceName::new("test"),
            host_id: HostId::new(1),
            running: true,
            crypto: None,
            compression: None,
        };

        let topology = Topology::from_instance(&instance, vec![], HashMap::new());
        let dot = topology.export_dot();

        assert!(dot.contains("digraph kronosnet_vpn"));
        assert!(dot.contains("VPN Instance: test"));
        assert!(dot.contains("host_1"));
    }
}
