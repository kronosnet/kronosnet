# Systemd Integration

This directory contains systemd service files for knetd.

## Service Files

### knetd.service
Standard single-instance service that uses `/etc/knetd/knetd.conf`.

**Installation**:
```bash
sudo cp systemd/knetd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable knetd
sudo systemctl start knetd
```

**Usage**:
```bash
# Start/stop/restart
sudo systemctl start knetd
sudo systemctl stop knetd
sudo systemctl restart knetd

# Enable on boot
sudo systemctl enable knetd

# Check status
sudo systemctl status knetd

# View logs
sudo journalctl -u knetd -f
```

### knetd@.service
Template service for running multiple instances or node-specific configurations.

**Installation**:
```bash
sudo cp systemd/knetd@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**Per-Node Configuration**:

Each node needs a configuration file `/etc/knetd/<instance>.conf` and an environment file `/etc/knetd/<instance>.env`:

```bash
# On node 1
echo "NODE_ID=1" | sudo tee /etc/knetd/cluster.env
sudo systemctl enable knetd@cluster
sudo systemctl start knetd@cluster

# On node 2
echo "NODE_ID=2" | sudo tee /etc/knetd/cluster.env
sudo systemctl enable knetd@cluster
sudo systemctl start knetd@cluster
```

**Multiple Instances**:
```bash
# Different VPN networks on same host
sudo cp /etc/knetd/knetd.conf /etc/knetd/vpn1.conf
sudo cp /etc/knetd/knetd.conf /etc/knetd/vpn2.conf

# Edit configs, then:
sudo systemctl enable knetd@vpn1
sudo systemctl enable knetd@vpn2
sudo systemctl start knetd@vpn1
sudo systemctl start knetd@vpn2
```

## Security Hardening

Both service files include systemd security features:

- **Capabilities**: Only `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_ADMIN` (required for nozzle)
- **Filesystem**: Read-only root, writable only in `/var/lib/knetd`, `/run/knetd`, `/var/log/knetd`
- **Namespaces**: Restricted to prevent privilege escalation
- **Address Families**: Only `AF_UNIX`, `AF_INET`, `AF_INET6`
- **Resource Limits**: 65536 file descriptors, unlimited memory locking

## Directory Structure

The service files create:
- `/etc/knetd/` - Configuration files
- `/var/lib/knetd/` - Persistent state
- `/run/knetd/` - Runtime files (Unix sockets)
- `/var/log/knetd/` - Log files (if file logging is enabled)

## Reload Configuration

To reload the daemon's configuration without restarting:
```bash
sudo systemctl reload knetd
```

This sends SIGHUP to the daemon (future feature - not yet implemented).

## Troubleshooting

**View logs**:
```bash
# Real-time logs
sudo journalctl -u knetd -f

# Last 100 lines
sudo journalctl -u knetd -n 100

# Since boot
sudo journalctl -u knetd -b

# For template instances
sudo journalctl -u knetd@cluster -f
```

**Check service status**:
```bash
sudo systemctl status knetd
sudo systemd-analyze security knetd
```

**Socket permissions**:
If clients can't connect to the Unix socket, check permissions:
```bash
ls -l /run/knetd/knetd.sock
```

The socket should be accessible to the `knetd` group or world-readable depending on your configuration.

## Notes

- The daemon requires root or appropriate capabilities to create nozzle (tap) devices
- State persistence is handled via `/var/lib/knetd/state.json` (configure via `state_file` in config)
- The Unix socket is created in `/run/knetd/knetd.sock` by default
