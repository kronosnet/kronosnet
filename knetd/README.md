# knetd - Kronosnet VPN Daemon

A Rust daemon and CLI utility for managing libknet VPN instances.

## Project Structure

This is a Cargo workspace containing three crates:

- **knetd**: The daemon that manages VPN instances using libknet
- **knetctl**: Command-line utility to control the daemon
- **knetd-common**: Shared types and RPC message definitions

## Building

```bash
cargo build
cargo build --release
```

## Running

### Start the daemon:

```bash
./target/debug/knetd
```

By default, the daemon listens on `/run/knetd/knetd.sock`. You can configure this with a TOML file.

### Use the CLI:

```bash
# Test connectivity
./target/debug/knetctl ping

# Instance management (short options: -n name, -H host-id)
./target/debug/knetctl instance create -n mynet -H 1
./target/debug/knetctl instance list
./target/debug/knetctl instance start -n mynet   # Enable data forwarding (required for traffic!)
./target/debug/knetctl instance stop -n mynet    # Disable data forwarding
./target/debug/knetctl instance destroy -n mynet

# Host management (short options: -i instance, -H host-id, -n name)
./target/debug/knetctl host add -i mynet -H 2 -n node2
./target/debug/knetctl host add -i mynet -H 3 -n node3
./target/debug/knetctl host list -i mynet
./target/debug/knetctl host status -i mynet -H 2
./target/debug/knetctl host remove -i mynet -H 3

# Link configuration (short options: -i instance, -H host-id, -l link-id, -t transport, -s src, -d dst)
./target/debug/knetctl link config -i mynet -H 2 -l 0 -t udp -s 10.0.0.1:5000 -d 10.0.0.2:5000
./target/debug/knetctl link enable -i mynet -H 2 -l 0
./target/debug/knetctl link status -i mynet -H 2 -l 0
./target/debug/knetctl link stats -i mynet -H 2 -l 0
./target/debug/knetctl link disable -i mynet -H 2 -l 0

# Event notifications (short options: -i instance, -p poll-interval-ms)
./target/debug/knetctl events watch -i mynet
# Real-time output:
# [1] 08:16:17 Link 0 to host 2 is DOWN mynet
# [2] 08:16:20 Link 0 to host 2 is UP mynet

# Crypto configuration (short options: -i instance, -m model, -c cipher, -H hash, -k key-file, -n config-num)
dd if=/dev/urandom of=/tmp/vpn.key bs=1024 count=1  # Generate key
./target/debug/knetctl crypto set-config -i mynet -m openssl -c aes256 -H sha256 -k /tmp/vpn.key
./target/debug/knetctl crypto use-config -i mynet -n 0

# Compression configuration (short options: -i instance, -m model, -t threshold, -l level)
./target/debug/knetctl compress set-config -i mynet -m zlib -t 100 -l 6
./target/debug/knetctl compress set-config -i mynet -m lz4 -l 9  # Fast compression
./target/debug/knetctl compress set-config -i mynet -m none     # Disable

# Visualize network topology (short options: -i instance, -f format, -o output, -C no-color)
./target/debug/knetctl topology show -i demo-network
./target/debug/knetctl topology show -i demo-network -C  # no color
./target/debug/knetctl topology export -i demo-network -f dot -o topology.dot
./target/debug/knetctl topology export -i demo-network -f svg -o topology.svg
```

## Configuration

See `knetd/knetd.toml.example` for an example configuration file.
See `knetd/knetd-fullmesh.toml.example` for a full-mesh configuration example (Corosync-style).

### Node-Agnostic Configuration

The config file is designed to be **node-agnostic** - the same file can be deployed to all nodes in a cluster. Each node identifies itself via:
1. `--node-id <N>` command-line argument, or
2. `KNETD_NODE_ID=<N>` environment variable

Two configuration modes are supported:

#### Manual Mode (Default)

The config file defines:
- **All nodes** in the cluster (via `[[instances.nodes]]` sections)
- **All links** between all nodes (via `[[instances.links]]` sections with `from_host` and `to_host`)

When knetd starts, it:
- Identifies which node is "me" based on the node ID
- Creates instances with the local node's host_id
- Adds all other nodes as remote hosts
- Only configures links where `from_host` matches the local node ID

#### Full-Mesh Mode (Corosync-style)

Set `full_mesh = true` in the instance configuration. In this mode:
- Each node defines its link addresses in the `link_addresses` array
- The daemon **automatically creates bidirectional links** between all nodes
- Perfect for high-availability clusters that need full mesh connectivity
- All links are UDP and auto-enabled

**Example full-mesh config**:
```toml
[[instances]]
name = "ha-cluster"
full_mesh = true

[[instances.nodes]]
host_id = 1
name = "node1"
link_addresses = ["192.168.1.1:5405", "10.0.0.1:5405"]

[[instances.nodes]]
host_id = 2
name = "node2"
link_addresses = ["192.168.1.2:5405", "10.0.0.2:5405"]

[[instances.nodes]]
host_id = 3
name = "node3"
link_addresses = ["192.168.1.3:5405", "10.0.0.3:5405"]
```

This automatically creates 2 redundant links between each pair of nodes (6 links total per node in a 3-node cluster).

**Example**: Same config file on all three nodes
```bash
# On node 1 (alice)
knetd --node-id 1 --config /etc/knetd/knetd.toml

# On node 2 (bob)
knetd --node-id 2 --config /etc/knetd/knetd.toml

# On node 3 (charlie)
knetd --node-id 3 --config /etc/knetd/knetd.toml
```

See `example-script.sh` for a complete demonstration.

### Config File Locations

The daemon looks for configuration files in this order:
1. Path specified via `--config` command-line argument
2. Path specified via `KNETD_CONFIG` environment variable
3. `/etc/knetd/knetd.toml`
4. `./knetd.toml`
5. Built-in defaults

**Config Validation**: If a config file is explicitly specified (via `--config` or `KNETD_CONFIG`) but is malformed, the daemon will refuse to start with a clear error message. For default paths, only "file not found" errors are ignored - parse errors always cause the daemon to exit.

### Nozzle (Tap Device) Support

Each instance can optionally create a tap device (via libnozzle) for sending and receiving traffic. **Requires root privileges**.

**IMPORTANT**: To ensure unique MAC and IP addresses across all nodes in a cluster, the configured MAC and IP addresses are treated as **base addresses**. The daemon automatically embeds the **node ID** into both:
- **MAC address**: Last 2 bytes are replaced with the node ID
- **IP address**: Node ID is masked and ORed into the host bits

This allows the same config file to be deployed to all nodes. See [NOZZLE_UNIQUE_ADDRESSING.md](NOZZLE_UNIQUE_ADDRESSING.md) for details.

```toml
[[instances]]
name = "vpn1"
auto_start = true

[instances.nozzle]
name = "knet0"                          # Device name
ip_addresses = ["192.168.100.0/24"]     # Base IP (becomes .1, .2, .3 per node)
mtu = 1400                              # Optional MTU
mac = "fe:54:00:00:00:00"               # Base MAC (last 2 bytes replaced with node ID)
updown_path = "/etc/knetd/updown.d"     # Optional up/down scripts
auto_up = true                          # Bring device up automatically
```

When configured, the daemon will:
1. Create the tap device with the specified name
2. Embed node ID into MAC address (last 2 bytes) and IP address (host bits)
3. Configure unique IP addresses, MTU, and MAC per node
4. Register the device's file descriptor with knet for **bidirectional data forwarding**
4. Enable socket notifications for error handling
5. If `auto_start = true`: **automatically enable forwarding and bring nozzle up**
6. Otherwise, bring the device up **in sync with `knet_handle_setfwd()`**:
   - Device is brought **up** when `instance start` is called
   - Device is brought **down** when `instance stop` is called
   - This ensures nozzle state matches knet forwarding state
7. Automatically clean up the device when the instance is destroyed

**Data Flow**:
- Application → tap device (write) → knet reads → encrypts → sends to remote nodes
- Remote nodes → knet receives → decrypts → tap device (knet writes) → application reads

The tap device acts as a virtual network interface. Applications can send/receive IP packets through it just like a physical interface (e.g., `ping 192.168.100.2` from the remote node).

**Important**: The nozzle device state is synchronized with knet forwarding:

**With `auto_start = true`** (automatic):
```bash
# 1. Start daemon - forwarding automatically enabled, nozzle already UP!
knetd --config myconfig.toml --node-id 1

# 2. Traffic flows immediately
ping 192.168.100.2  # Works!

# 3. Can manually stop if needed
knetctl instance stop -n vpn1
```

**With `auto_start = false`** (manual):
```bash
# 1. Create instance (with nozzle configured in TOML)
knetd --config myconfig.toml --node-id 1

# 2. Start forwarding (this brings nozzle UP and enables knet forwarding)
knetctl instance start -n vpn1

# 3. Now traffic can flow through the tap device
ping 192.168.100.2  # Works!

# 4. Stop forwarding (this brings nozzle DOWN and disables knet forwarding)
knetctl instance stop -n vpn1
```

**Note**: The `sock_notify` callback handles errors/EOF on the tap device FD, allowing graceful handling of device failures.

## Current Status

**Phase 1 (MVP) - COMPLETE:**
- ✅ Workspace structure
- ✅ knetd-common with shared types
- ✅ Basic daemon with tokio runtime
- ✅ TOML config loading
- ✅ JSON-RPC server over Unix socket
- ✅ Basic CLI with clap
- ✅ Ping command working
- ✅ Comprehensive code documentation

**Phase 2 (Instance Lifecycle) - COMPLETE:**
- ✅ VpnInstance struct wrapping knet::Handle
- ✅ Logging thread per instance
- ✅ Proper cleanup sequence (Drop implementation)
- ✅ instance.create/destroy/list RPC methods
- ✅ CLI commands for instance management
- ✅ State tracking with Arc<Mutex<State>>
- ✅ End-to-end testing

**Phase 3 (Host Management) - COMPLETE:**
- ✅ Add/remove remote hosts in VPN instances
- ✅ Host metadata tracking (names, links)
- ✅ host.add/remove/list/status RPC methods
- ✅ CLI commands for host management
- ✅ Proper cleanup on host removal
- ✅ Error handling and validation

**Phase 4 (Link Configuration) - COMPLETE:**
- ✅ Configure UDP/loopback links between hosts
- ✅ Enable/disable links dynamically
- ✅ link.set_config/enable/get_status/get_stats RPC methods
- ✅ CLI commands for link management
- ✅ Multi-link support (up to 8 links per host pair)
- ✅ Link statistics (packets, bytes, latency)

**Phase 5 (Event Notifications) - COMPLETE:**
- ✅ Real-time link and host status change events
- ✅ Async event broadcasting via tokio channels
- ✅ knet callback integration (link/host status)
- ✅ events.subscribe/poll/unsubscribe RPC methods
- ✅ CLI event watching (knetctl events watch)
- ✅ Multi-client subscription support

**Phase 6 (Crypto and Compression) - COMPLETE:**
- ✅ Crypto configuration (OpenSSL, NSS, gcrypt backends)
- ✅ Multiple cipher support (AES128/192/256, etc.)
- ✅ Multiple hash support (SHA1/256/384/512, etc.)
- ✅ Dual crypto config slots for key rotation
- ✅ Compression support (zlib, lz4, zstd, lzo2, lzma, bzip2)
- ✅ Configurable compression thresholds and levels
- ✅ crypto.set_config/use_config RPC methods
- ✅ compress.set_config RPC method
- ✅ CLI commands for crypto and compression

**Phase 8 (Visualization) - COMPLETE:**
- ✅ ASCII-art topology display with box-drawing characters
- ✅ Color-coded link status (green/yellow/red)
- ✅ DOT format export (GraphViz compatible)
- ✅ SVG export for Inkscape
- ✅ Multi-link visualization
- ✅ Legend and status indicators

**Phase 7 (State Persistence) - COMPLETE:**
- ✅ JSON state serialization with atomic writes
- ✅ State loading on daemon startup
- ✅ Graceful shutdown with state save (SIGINT/SIGTERM)
- ✅ Config file support (KNETD_CONFIG environment variable)
- ✅ Signal handling with dedicated thread
- ✅ Multi-instance state management

**Phase 9 (Nozzle Integration) - COMPLETE:**
- ✅ Tap device creation via libnozzle
- ✅ IP address configuration
- ✅ MTU and MAC address configuration
- ✅ Automatic registration with knet data FD
- ✅ Auto-up support
- ✅ Proper cleanup on instance destruction

**Phase 10 (Production Hardening) - COMPLETE:**
- ✅ Systemd service files (single and template)
- ✅ Security hardening in service definitions
- ✅ Man pages (knetd.8, knetctl.1, knetd.conf.5)
- ✅ Installation documentation
- ✅ Packaging guidelines (RPM, DEB)

## Architecture

The daemon uses:
- **Tokio** async runtime for control plane
- **JSON-RPC 2.0** over Unix sockets for IPC
- **libknet Rust bindings** for VPN functionality
- **Broadcast channels** for event streaming (future)

The CLI uses:
- **Clap v4** for argument parsing
- **JSON-RPC client** to communicate with daemon
- **Tabled** for pretty output (future)

## Visualization

The CLI includes powerful network topology visualization:

- **ASCII-art**: Display topology in terminal with color-coded status
- **DOT export**: GraphViz-compatible format for high-quality diagrams
- **SVG export**: Vector graphics for Inkscape or documentation

See [VISUALIZATION.md](VISUALIZATION.md) for detailed documentation and examples.

**Quick Example:**

```bash
# Display topology in terminal
./target/debug/knetctl topology show -i mynetwork

# Export to SVG for documentation
./target/debug/knetctl topology export -i mynetwork -f svg -o network.svg

# Render with GraphViz
dot -Tpng topology.dot -o network.png
```

## Documentation

### User Documentation
- [README.md](README.md) - This file, general overview
- [INSTALLATION.md](INSTALLATION.md) - **Installation and deployment guide**
- [NODE_AGNOSTIC_CONFIG.md](NODE_AGNOSTIC_CONFIG.md) - **Node-agnostic configuration guide** (deploy same config to all nodes)
- [NOZZLE_UNIQUE_ADDRESSING.md](NOZZLE_UNIQUE_ADDRESSING.md) - **Automatic MAC/IP uniqueness for nozzle devices**
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Quick reference for all CLI commands and short options
- [VISUALIZATION.md](VISUALIZATION.md) - Topology visualization guide

### System Administration
- [systemd/README.md](systemd/README.md) - Systemd integration and service management
- man/knetd.8 - Daemon manual page (view with `man 8 knetd`)
- man/knetctl.1 - CLI manual page (view with `man 1 knetctl`)
- man/knetd.conf.5 - Configuration manual page (view with `man 5 knetd.conf`)

### Developer Documentation
- [CONTRIBUTING.md](CONTRIBUTING.md) - Developer guide and how to contribute
- [CODE_TOUR.md](CODE_TOUR.md) - Architectural deep-dive
- [PACKAGING.md](PACKAGING.md) - Distribution packaging guidelines

## License

LGPL-2.1+

This project is part of the kronosnet suite.
