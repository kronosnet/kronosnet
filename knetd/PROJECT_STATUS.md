# knetd Project Status

## Overview
**knetd** is a production-ready Rust daemon for managing libknet VPN instances in high-availability clusters. It provides a modern JSON-RPC API, node-agnostic configuration, and comprehensive tooling for enterprise deployments.

**Current Version**: 0.1.0  
**Status**: Production Ready ✅  
**License**: LGPL-2.1+

## Implementation Phases

### ✅ Phase 1: MVP (COMPLETE)
- Workspace structure (knetd, knetctl, knetd-common)
- Basic daemon with tokio runtime
- TOML configuration loading
- JSON-RPC server over Unix sockets
- Basic CLI with clap
- Ping command
- Comprehensive code documentation

### ✅ Phase 2: Instance Lifecycle (COMPLETE)
- VpnInstance struct wrapping knet::Handle
- Per-instance logging thread
- Proper cleanup sequence (Drop implementation)
- instance.create/destroy/list RPC methods
- CLI commands for instance management
- State tracking with Arc<Mutex<State>>
- End-to-end testing

### ✅ Phase 3: Host Management (COMPLETE)
- Add/remove remote hosts in VPN instances
- Host metadata tracking (names, links)
- host.add/remove/list/status RPC methods
- CLI commands for host management
- Proper cleanup on host removal
- Error handling and validation

### ✅ Phase 4: Link Configuration (COMPLETE)
- Configure UDP/loopback links between hosts
- Enable/disable links dynamically
- link.set_config/enable/get_status/get_stats RPC methods
- CLI commands for link management
- Multi-link support (up to 8 links per host pair)
- Link statistics (packets, bytes, latency)

### ✅ Phase 5: Event Notifications (COMPLETE)
- Real-time link and host status change events
- Async event broadcasting via tokio channels
- knet callback integration (link/host status)
- events.subscribe/poll/unsubscribe RPC methods
- CLI event watching (knetctl events watch)
- Multi-client subscription support

### ✅ Phase 6: Crypto and Compression (COMPLETE)
- Crypto configuration (OpenSSL, NSS, gcrypt backends)
- Multiple cipher support (AES128/192/256, etc.)
- Multiple hash support (SHA1/256/384/512, etc.)
- Dual crypto config slots for key rotation
- Compression support (zlib, lz4, zstd, lzo2, lzma, bzip2)
- Configurable compression thresholds and levels
- crypto.set_config/use_config RPC methods
- compress.set_config RPC method
- CLI commands for crypto and compression

### ✅ Phase 7: State Persistence (COMPLETE)
- JSON state serialization with atomic writes
- State loading on daemon startup
- Graceful shutdown with state save (SIGINT/SIGTERM)
- Config file support (KNETD_CONFIG environment variable)
- Signal handling with dedicated thread
- Multi-instance state management

### ✅ Phase 8: Visualization (COMPLETE)
- ASCII-art topology display with box-drawing characters
- Color-coded link status (green/yellow/red)
- DOT format export (GraphViz compatible)
- SVG export for Inkscape
- Multi-link visualization
- Legend and status indicators

### ✅ Phase 9: Nozzle Integration (COMPLETE)
- Tap device creation via libnozzle
- IP address configuration
- MTU and MAC address configuration
- Automatic registration with knet data FD
- Auto-up support
- Proper cleanup on instance destruction
- **Automatic MAC/IP uniqueness** - Node ID embedded in addresses
- Corosync-compatible addressing algorithm

### ✅ Phase 10: Production Hardening (COMPLETE)
- Systemd service files (single and template)
- Security hardening in service definitions
- Man pages (knetd.8, knetctl.1, knetd.conf.5)
- Installation documentation
- Packaging guidelines (RPM, DEB)

## Key Features

### Node-Agnostic Configuration
- Same config file deployable to all nodes
- Each node identifies itself via `--node-id` or `KNETD_NODE_ID`
- Automatic full-mesh link creation in `full_mesh` mode
- Manual link configuration for custom topologies

### Automatic Unique Addressing
- MAC addresses: Node ID embedded in last 2 bytes
- IPv4: Node ID ORed into host bits
- IPv6: Node ID appended as hex after `::`
- Matches Corosync implementation (totemknet.c)

### Security
- Systemd hardening (minimal capabilities, read-only root, restricted namespaces)
- Crypto key rotation support (dual config slots)
- File permission guidelines
- SELinux compatibility notes

### Monitoring
- Real-time event streaming
- Link and host status tracking
- Topology visualization (ASCII, DOT, SVG)
- Comprehensive logging with configurable levels
- journalctl integration

## Architecture

### Technology Stack
- **Language**: Rust (edition 2021)
- **Async Runtime**: Tokio
- **RPC**: JSON-RPC 2.0 over Unix sockets
- **Config**: TOML format
- **Logging**: tracing + tracing_subscriber
- **CLI**: clap v4
- **Bindings**: knet-bindings, nozzle-bindings

### Components
- **knetd**: Main daemon process
  - VPN instance lifecycle management
  - Event broadcasting
  - State persistence
  - RPC server
  
- **knetctl**: Command-line client
  - Instance/host/link management
  - Crypto/compression configuration
  - Event monitoring
  - Topology visualization

- **knetd-common**: Shared library
  - Type definitions
  - RPC message schemas
  - Event types

## Documentation

### User Documentation (7 files)
- [README.md](README.md) - Overview and quick start
- [INSTALLATION.md](INSTALLATION.md) - Installation and deployment
- [NODE_AGNOSTIC_CONFIG.md](NODE_AGNOSTIC_CONFIG.md) - Configuration guide
- [NOZZLE_UNIQUE_ADDRESSING.md](NOZZLE_UNIQUE_ADDRESSING.md) - MAC/IP uniqueness
- [CLI_REFERENCE.md](CLI_REFERENCE.md) - CLI command reference
- [VISUALIZATION.md](VISUALIZATION.md) - Topology visualization
- [systemd/README.md](systemd/README.md) - Systemd integration

### System Administration (3 man pages)
- man/knetd.8 - Daemon manual
- man/knetctl.1 - CLI manual
- man/knetd.conf.5 - Configuration manual

### Developer Documentation (3 files)
- [CODE_TOUR.md](CODE_TOUR.md) - Architecture deep-dive
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guide
- [PACKAGING.md](PACKAGING.md) - Distribution packaging

### Phase Completion Reports (11 files)
- PHASE1_COMPLETE.md through PHASE10_COMPLETE.md
- UNIQUE_ADDRESSING_IMPLEMENTATION.md

**Total**: 24 documentation files, ~10,000 lines

## Testing

### Test Coverage
- Unit tests in each module
- Integration tests for RPC methods
- Example scripts:
  - `example-script.sh` - Multi-node local demo
  - `test-nozzle-unique.sh` - MAC/IP uniqueness verification

### Quality Assurance
- Clippy linting (all warnings fixed)
- Cargo fmt for code formatting
- Manual testing of all CLI commands
- Event system verified with real link state changes

## Metrics

### Code Statistics
- **Rust Source**: ~15,000 lines
  - knetd: ~8,000 lines
  - knetctl: ~5,000 lines
  - knetd-common: ~2,000 lines
- **Documentation**: ~10,000 lines
- **Tests**: Integrated throughout source
- **Configuration Examples**: 4 files

### Features
- **RPC Methods**: 20+ implemented
- **CLI Commands**: 25+ subcommands
- **Short Options**: All major commands support single-char flags
- **Crypto Modules**: 3 supported (OpenSSL, NSS, gcrypt)
- **Compression**: 6 algorithms (zlib, lz4, zstd, lzo2, lzma, bzip2)
- **Transports**: UDP, SCTP, loopback
- **Event Types**: 5 (link status, host status, PMTUD, onwire version, log messages)

## Production Readiness

### ✅ Ready for Production
- [x] Complete feature set for HA clustering
- [x] Comprehensive error handling
- [x] State persistence and recovery
- [x] Graceful shutdown
- [x] Security hardening
- [x] Man pages and documentation
- [x] Systemd integration
- [x] Packaging guidelines
- [x] Monitoring and logging
- [x] Multi-node tested

### Future Enhancements
Potential additions (not blocking production use):
- [ ] SIGHUP configuration reload
- [ ] Prometheus metrics endpoint
- [ ] SNMP MIB
- [ ] Bash/zsh completion
- [ ] SELinux policy module
- [ ] AppArmor profile
- [ ] Web dashboard (optional GUI)
- [ ] REST API (in addition to JSON-RPC)

## Deployment

### Supported Platforms
- Linux (tested on Fedora, should work on RHEL, Debian, Ubuntu, Arch)
- Requires systemd for service management
- Requires libknet >= 1.28, libnozzle >= 1.28

### Installation Methods
1. **From Source**: `cargo build --release`
2. **RPM Package**: Use provided spec file
3. **DEB Package**: Use provided debian/ structure
4. **Manual**: Copy binaries and systemd units

### Minimum Requirements
- Rust 1.70+ (build only)
- libknet 1.28+
- libnozzle 1.28+
- Linux kernel with TUN/TAP support
- Root or CAP_NET_ADMIN for nozzle devices

## Use Cases

### High-Availability Clusters
- Corosync replacement (full-mesh mode)
- Multi-link redundancy
- Automatic failover
- State persistence across reboots

### VPN Networks
- Multi-link bonding
- Encryption (AES-256)
- Compression for bandwidth optimization
- Tap device integration

### Testing and Development
- Local multi-instance testing
- Event monitoring
- Topology visualization
- State inspection

## Project Health

- **Build Status**: ✅ Clean (debug + release)
- **Clippy**: ✅ No warnings
- **Documentation**: ✅ Comprehensive
- **Tests**: ✅ Passing
- **API Stability**: ⚠️  Pre-1.0 (may change)

## Comparison to Alternatives

| Feature | knetd | Corosync | Traditional VPN |
|---------|-------|----------|-----------------|
| Multi-link redundancy | ✅ | ✅ | ❌ |
| Auto-configuration | ✅ | ❌ | ❌ |
| JSON-RPC API | ✅ | ❌ | ❌ |
| State persistence | ✅ | Limited | Varies |
| Event streaming | ✅ | Limited | ❌ |
| Topology viz | ✅ | ❌ | ❌ |
| Modern tooling | ✅ (Rust) | ❌ (C) | Varies |

## Getting Started

### Quick Start (Single Node)
```bash
# Build
cargo build --release

# Start daemon
./target/release/knetd

# Test
./target/release/knetctl ping
```

### Production Deployment (Multi-Node)
```bash
# Install package (example)
sudo dnf install knetd

# Configure (same file on all nodes)
sudo vi /etc/knetd/cluster.conf

# Start on each node with unique ID
sudo systemctl start knetd@cluster  # After setting NODE_ID in .env
```

See [INSTALLATION.md](INSTALLATION.md) for complete instructions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code style guidelines
- Development workflow
- Testing requirements
- Pull request process

## License

LGPL-2.1-or-later (same as kronosnet/libknet)

## Acknowledgments

- Built on top of libknet and libnozzle from the Kronosnet project
- Addressing algorithm based on Corosync's totemknet.c implementation
- Developed as part of the broader Kronosnet ecosystem

## Links

- **Project**: https://github.com/kronosnet/kronosnet
- **Issues**: https://github.com/kronosnet/kronosnet/issues
- **Kronosnet**: https://kronosnet.org

---

**Status**: Production Ready ✅  
**Last Updated**: 2026-06-25  
**Phases Complete**: 10/10 (100%)
