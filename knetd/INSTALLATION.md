# Installation Guide

This document covers installation and deployment of knetd in production environments.

## Prerequisites

### Build Dependencies
- Rust 1.70+ (cargo, rustc)
- libknet development files
- libnozzle development files
- pkg-config

**Fedora/RHEL/CentOS**:
```bash
sudo dnf install rust cargo libknet-devel libnozzle-devel pkg-config
```

**Debian/Ubuntu**:
```bash
sudo apt install rustc cargo libknet-dev libnozzle-dev pkg-config
```

### Runtime Dependencies
- libknet (with desired crypto/compression modules)
- libnozzle
- systemd (for service integration)

## Building from Source

### Standard Build
```bash
# Clone repository
git clone https://github.com/kronosnet/kronosnet.git
cd kronosnet/knetd

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls -lh target/release/knetd target/release/knetctl
```

### Build Options
```bash
# Debug build (with debug symbols)
cargo build

# Build with all warnings
cargo build --release -- -D warnings

# Run tests
cargo test

# Check for clippy lints
cargo clippy --all-targets
```

## Installation

### Manual Installation

```bash
# Install binaries
sudo install -m 755 target/release/knetd /usr/sbin/
sudo install -m 755 target/release/knetctl /usr/bin/

# Install systemd service files
sudo install -m 644 systemd/knetd.service /etc/systemd/system/
sudo install -m 644 systemd/knetd@.service /etc/systemd/system/
sudo systemctl daemon-reload

# Install man pages
sudo install -m 644 man/knetd.8 /usr/share/man/man8/
sudo install -m 644 man/knetctl.1 /usr/share/man/man1/
sudo install -m 644 man/knetd.conf.5 /usr/share/man/man5/
sudo mandb

# Create directories
sudo mkdir -p /etc/knetd
sudo mkdir -p /var/lib/knetd
sudo mkdir -p /run/knetd

# Install example config
sudo install -m 644 knetd/knetd.toml.example /etc/knetd/knetd.conf
```

### Using a Package Manager

Package maintainers should create distribution-specific packages (RPM, DEB) that install:
- Binaries to `/usr/sbin/knetd` and `/usr/bin/knetctl`
- Systemd units to `/usr/lib/systemd/system/`
- Man pages to `/usr/share/man/`
- Example configs to `/usr/share/doc/knetd/examples/`
- Documentation to `/usr/share/doc/knetd/`

See [PACKAGING.md](PACKAGING.md) for packaging guidelines.

## Configuration

### Single Node Setup

1. **Edit configuration**:
```bash
sudo vi /etc/knetd/knetd.conf
```

Minimal config:
```toml
socket_path = "/run/knetd/knetd.sock"
log_level = "info"
state_file = "/var/lib/knetd/state.json"

[[instances]]
name = "vpn1"
auto_start = true
```

2. **Start the daemon**:
```bash
sudo systemctl start knetd
sudo systemctl enable knetd
```

3. **Verify**:
```bash
sudo systemctl status knetd
knetctl ping
```

### Multi-Node Cluster Setup

1. **Create node-agnostic configuration** (same file on all nodes):
```bash
sudo vi /etc/knetd/cluster.conf
```

```toml
socket_path = "/run/knetd/knetd.sock"
log_level = "info"
state_file = "/var/lib/knetd/state.json"

[[instances]]
name = "ha-cluster"
auto_start = true
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

[instances.nozzle]
name = "knet0"
ip_addresses = ["192.168.100.0/24"]
mac = "fe:54:00:00"
mtu = 1400
auto_up = true
```

2. **Deploy to all nodes**:
```bash
# Copy config to all nodes
for node in node1 node2 node3; do
    scp /etc/knetd/cluster.conf root@${node}:/etc/knetd/
done
```

3. **Create environment files on each node**:
```bash
# On node1
echo "NODE_ID=1" | sudo tee /etc/knetd/cluster.env

# On node2
echo "NODE_ID=2" | sudo tee /etc/knetd/cluster.env

# On node3
echo "NODE_ID=3" | sudo tee /etc/knetd/cluster.env
```

4. **Start services on all nodes**:
```bash
sudo systemctl start knetd@cluster
sudo systemctl enable knetd@cluster
```

5. **Verify cluster**:
```bash
# On any node
knetctl instance list
knetctl host list -i ha-cluster
knetctl events watch -i ha-cluster
```

## Security Considerations

### Filesystem Permissions
```bash
# Config files should be root-readable only (may contain keys)
sudo chmod 600 /etc/knetd/*.conf

# State directory
sudo chown root:root /var/lib/knetd
sudo chmod 700 /var/lib/knetd

# Socket directory (if clients need access)
sudo chmod 755 /run/knetd
```

### SELinux
If using SELinux, you may need custom policies for:
- Creating tap devices
- Binding to knet ports
- Writing to state files

Example policy module (pseudo-code):
```
allow knetd_t self:capability { net_admin net_raw sys_admin };
allow knetd_t knetd_var_lib_t:dir { create write };
allow knetd_t knetd_var_run_t:sock_file { create write };
```

### Firewall Rules
Open ports for knet traffic:
```bash
# For UDP transport on port 5405 (example)
sudo firewall-cmd --add-port=5405/udp --permanent
sudo firewall-cmd --reload

# Or for a range
sudo firewall-cmd --add-port=5405-5410/udp --permanent
```

## Troubleshooting

### Daemon Won't Start
```bash
# Check logs
sudo journalctl -u knetd -n 100

# Test config
sudo /usr/sbin/knetd --config /etc/knetd/knetd.conf --help

# Check permissions
ls -l /etc/knetd/knetd.conf
ls -ld /var/lib/knetd /run/knetd
```

### Nozzle Devices Fail to Create
```bash
# Check capabilities
sudo systemctl show knetd | grep Capabilities

# Test manually
sudo ip tuntap add mode tap knet-test
sudo ip tuntap del mode tap knet-test

# Check kernel modules
lsmod | grep tun
```

### Links Won't Come Up
```bash
# Check firewall
sudo iptables -L -n | grep 5405

# Test UDP connectivity
# On node1:
nc -u -l 5405

# On node2:
echo "test" | nc -u node1 5405

# Watch events
knetctl events watch -i <instance>
```

## Upgrading

### Binary Upgrade
```bash
# Build new version
cd kronosnet/knetd
git pull
cargo build --release

# Stop daemon
sudo systemctl stop knetd

# Backup old binary
sudo cp /usr/sbin/knetd /usr/sbin/knetd.backup

# Install new binary
sudo install -m 755 target/release/knetd /usr/sbin/

# Restart
sudo systemctl start knetd
sudo systemctl status knetd
```

### Rolling Upgrade (Multi-Node)
```bash
# Upgrade one node at a time
for node in node1 node2 node3; do
    echo "Upgrading ${node}..."
    ssh root@${node} systemctl stop knetd
    scp target/release/knetd root@${node}:/usr/sbin/
    ssh root@${node} systemctl start knetd
    sleep 10
done
```

## Monitoring

### Systemd Status
```bash
sudo systemctl status knetd
sudo systemctl is-active knetd
```

### Logs
```bash
# Real-time logs
sudo journalctl -u knetd -f

# Logs since last boot
sudo journalctl -u knetd -b

# With priority (errors only)
sudo journalctl -u knetd -p err
```

### Health Checks
```bash
# Test daemon connectivity
knetctl ping

# List instances
knetctl instance list

# Check specific instance
knetctl host list -i <instance>
knetctl topology show -i <instance>
```

### Metrics
Future versions may support:
- Prometheus metrics endpoint
- SNMP traps
- Graphite/StatsD integration

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop knetd
sudo systemctl disable knetd

# Remove binaries
sudo rm /usr/sbin/knetd
sudo rm /usr/bin/knetctl

# Remove systemd units
sudo rm /etc/systemd/system/knetd.service
sudo rm /etc/systemd/system/knetd@.service
sudo systemctl daemon-reload

# Remove man pages
sudo rm /usr/share/man/man8/knetd.8
sudo rm /usr/share/man/man1/knetctl.1
sudo rm /usr/share/man/man5/knetd.conf.5
sudo mandb

# Remove config and data (CAUTION: destroys state)
sudo rm -rf /etc/knetd
sudo rm -rf /var/lib/knetd
sudo rm -rf /run/knetd
```

## See Also
- [README.md](README.md) - General documentation
- [NODE_AGNOSTIC_CONFIG.md](NODE_AGNOSTIC_CONFIG.md) - Configuration guide
- [PACKAGING.md](PACKAGING.md) - Packaging guidelines
- systemd/README.md - Systemd integration details
