# Network Topology Visualization

The knetctl CLI provides comprehensive network topology visualization capabilities to help understand and document VPN mesh networks.

## Features

### ASCII-Art Display

Display network topology directly in your terminal with box-drawing characters, color-coded link states, and real-time status information.

```bash
knetctl topology show -i mynetwork
```

**Output Example:**
```
╔══════════════════════════════════════════════════════════╗
║  VPN Instance: mynetwork                                 ║
╚══════════════════════════════════════════════════════════╝

  ⬢ Host 1  (local (1))
  ║
  ├─── ━━━ Link 0 (udp) [UP] 10.0.0.1:5000→10.0.0.2:5000
  ║
  └─── ╌╌╌ Link 1 (udp) [DOWN] 192.168.1.1:5001→192.168.1.2:5001
  ║
  ◯ Host 2  (node2)
  ║
  ║
  └─── ━━━ Link 0 (udp) [UP] 10.0.0.1:5002→10.0.0.3:5000
  ║
  ◯ Host 3  (node3)
```

**Legend:**
- `⬢` - Local node (this host)
- `◯` - Remote node (reachable)
- `◌` - Remote node (unreachable)
- `━━━` - Link enabled & connected (green in color terminals)
- `╌╌╌` - Link enabled & disconnected (yellow in color terminals)
- `···` - Link disabled (red in color terminals)

### Color Support

By default, the visualization uses terminal colors if supported. To disable colors:

```bash
knetctl topology show -i mynetwork --no-color
```

## Export Formats

### DOT Format (GraphViz)

Export topology to DOT format for rendering with GraphViz tools:

```bash
knetctl topology export -i mynetwork -f dot -o topology.dot
```

The DOT file can be rendered to various image formats:

```bash
# PNG image
dot -Tpng topology.dot -o topology.png

# SVG image
dot -Tsvg topology.dot -o topology.svg

# PDF document
dot -Tpdf topology.dot -o topology.pdf

# PostScript
dot -Tps topology.dot -o topology.ps
```

**DOT File Features:**
- Directed graph with labeled nodes and edges
- Color-coded nodes (local/remote/unreachable)
- Link status indicators (solid/dashed/dotted)
- Built-in legend
- Left-to-right layout for readability

### SVG Format (Inkscape-ready)

Export directly to SVG for visual editing in Inkscape or other vector graphics tools:

```bash
knetctl topology export -i mynetwork -f svg -o topology.svg
```

This format is ideal for:
- Creating documentation diagrams
- Annotating network topology
- Publishing in presentations or reports
- Further customization in Inkscape

**Note:** SVG export requires GraphViz (`dot` command) to be installed. If not available, the tool will fall back to DOT format.

## Visualization Elements

### Node Representation

Each node shows:
- **Host ID**: Unique identifier (0-65535)
- **Name**: Human-readable name (if configured)
- **Status**: 
  - Local node (light blue background)
  - Remote reachable (green background)
  - Remote unreachable (red background)

### Link Representation

Each link displays:
- **Link ID**: 0-7 (up to 8 links per host pair)
- **Transport**: udp, loopback, etc.
- **Status**: UP, DOWN, DISABLED
- **Addresses**: Source and destination IP:port
- **Visual Style**:
  - Solid line: Link is up and passing traffic
  - Dashed line: Link is enabled but down
  - Dotted line: Link is disabled

### Multi-Link Support

libknet supports up to 8 simultaneous links between any pair of hosts for redundancy. The visualization shows all configured links with their individual status.

## Use Cases

### Network Troubleshooting

Quickly identify problematic links:

```bash
knetctl topology show -i prod | grep "╌╌╌"  # Find disconnected links
knetctl topology show -i prod | grep "···"  # Find disabled links
```

### Documentation

Generate network diagrams for documentation:

```bash
# Export to SVG
knetctl topology export -i prod -f svg -o prod-topology.svg

# Edit in Inkscape to add annotations
inkscape prod-topology.svg

# Or render to PNG for embedding in documents
dot -Tpng -Gdpi=300 prod-topology.dot -o prod-topology-hires.png
```

### Monitoring Scripts

Include topology snapshots in monitoring reports:

```bash
#!/bin/bash
# Daily network topology report
DATE=$(date +%Y-%m-%d)
knetctl topology show -i prod --no-color > "/var/log/knet/topology-$DATE.txt"
knetctl topology export -i prod -f dot -o "/var/log/knet/topology-$DATE.dot"
```

### Capacity Planning

Visualize current utilization to plan for expansion:

```bash
# Export current topology
knetctl topology export -i prod -f svg -o current-topology.svg

# Use as baseline for capacity planning presentations
```

## GraphViz Integration

The DOT format output is compatible with the full GraphViz suite of tools:

- **dot**: Hierarchical layouts (default)
- **neato**: Spring model layouts
- **fdp**: Force-directed placement
- **sfdp**: Scalable force-directed placement (for large networks)
- **twopi**: Radial layout
- **circo**: Circular layout

Example with alternative layout:

```bash
knetctl topology export -i mynetwork -f dot -o topology.dot
neato -Tsvg topology.dot -o topology-neato.svg
```

## Inkscape Tips

After exporting to SVG, you can enhance the diagram in Inkscape:

1. **Add annotations**: Use text tool to add notes about specific links or nodes
2. **Highlight paths**: Add colored overlays to show primary/backup paths
3. **Add statistics**: Insert text boxes with bandwidth, latency, or utilization data
4. **Create legends**: Extend the auto-generated legend with custom symbols
5. **Export variants**: Create multiple versions for different audiences

## Future Enhancements

Planned visualization features:

- **Statistics overlay**: Show bandwidth, latency, error rates on links
- **Historical view**: Animate link status changes over time
- **Interactive mode**: Click on nodes/links for detailed information
- **Diff mode**: Compare two topologies to visualize changes
- **Custom layouts**: Specify node positions for consistent diagrams
- **Cluster grouping**: Group nodes by location or function
- **Performance heatmap**: Color-code based on utilization or latency

## Requirements

- **Rust crates**:
  - `colored` - Terminal color support (included)
  - Standard library only for ASCII rendering

- **External tools** (optional):
  - GraphViz (`dot`, `neato`, etc.) - For SVG export and rendering
  - Inkscape - For SVG editing

Install GraphViz on various platforms:

```bash
# Debian/Ubuntu
sudo apt install graphviz

# Fedora/RHEL
sudo dnf install graphviz

# macOS
brew install graphviz

# Windows (with Chocolatey)
choco install graphviz
```

## Examples

### Simple Two-Node Network

```bash
knetctl topology show -i simple
```

Shows a basic VPN with local node and one remote peer, ideal for testing.

### Multi-Site Mesh

```bash
knetctl topology export -i prod -f svg -o mesh.svg
```

Exports a complex mesh network with multiple sites and redundant links.

### High-Availability Pair

Visualize an HA pair with multiple link types:

```bash
knetctl topology show -i ha-cluster --no-color > ha-status.txt
```

### Documentation Set

Generate a complete documentation set:

```bash
#!/bin/bash
INSTANCE="prod"
OUTDIR="docs/network-topology"

mkdir -p "$OUTDIR"

# Text version
knetctl topology show -i "$INSTANCE" --no-color > "$OUTDIR/topology.txt"

# DOT source
knetctl topology export -i "$INSTANCE" -f dot -o "$OUTDIR/topology.dot"

# High-res PNG
dot -Tpng -Gdpi=300 "$OUTDIR/topology.dot" -o "$OUTDIR/topology.png"

# Editable SVG
knetctl topology export -i "$INSTANCE" -f svg -o "$OUTDIR/topology.svg"

# PDF for printing
dot -Tpdf "$OUTDIR/topology.dot" -o "$OUTDIR/topology.pdf"

echo "Topology documentation generated in $OUTDIR/"
ls -lh "$OUTDIR/"
```

## Troubleshooting

### No color in terminal

If colors don't appear:
- Ensure your terminal supports ANSI colors
- Try setting `TERM=xterm-256color`
- Use `--no-color` flag for plain output

### GraphViz not found

If SVG export fails:
```
Error: Failed to spawn 'dot' command: No such file or directory
```

Install GraphViz (see Requirements section) or use DOT export instead.

### Large networks render slowly

For networks with many nodes:
- Use DOT export and render offline
- Try `sfdp` layout engine for better scalability
- Consider filtering to show only active links

## See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) - How to extend visualization features
- [CODE_TOUR.md](CODE_TOUR.md) - Implementation details
- [README.md](README.md) - General knetd documentation
- GraphViz documentation: https://graphviz.org/documentation/
- Inkscape documentation: https://inkscape.org/learn/
