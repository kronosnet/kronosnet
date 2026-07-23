# knetctl CLI Quick Reference

## Short Option Summary

All knetctl commands support short-form options for faster typing. Use `knetctl <command> --help` to see all available options.

### Common Options

| Short | Long | Description |
|-------|------|-------------|
| `-s` | `--socket` | Path to daemon's Unix socket |
| `-i` | `--instance` | VPN instance name |
| `-H` | `--host-id` | Host ID (0-65535) |
| `-l` | `--link-id` | Link ID (0-7) |
| `-h` | `--help` | Show help message |

### Instance Management

```bash
# Create instance
knetctl instance create -n <name> -H <host-id>

# Start/stop data forwarding (REQUIRED for traffic to flow!)
knetctl instance start -n <name>
knetctl instance stop -n <name>

# List instances
knetctl instance list

# Destroy instance
knetctl instance destroy -n <name>
```

**Options:**
- `-n, --name` - Instance name
- `-H, --host-id` - Local host ID

**Important**: After creating an instance and configuring links, you must run `instance start` to enable data forwarding. Without this, no traffic will pass through the VPN.

### Host Management

```bash
# Add host
knetctl host add -i <instance> -H <host-id> [-n <name>]

# Remove host
knetctl host remove -i <instance> -H <host-id>

# List hosts
knetctl host list -i <instance>

# Get host status
knetctl host status -i <instance> -H <host-id>
```

**Options:**
- `-i, --instance` - Instance name
- `-H, --host-id` - Host ID
- `-n, --name` - Optional host name

### Link Configuration

```bash
# Configure link
knetctl link config -i <instance> -H <host-id> -l <link-id> \
    -t <transport> -s <src-addr> [-d <dst-addr>]

# Enable/disable link
knetctl link enable -i <instance> -H <host-id> -l <link-id>
knetctl link disable -i <instance> -H <host-id> -l <link-id>

# Get link status
knetctl link status -i <instance> -H <host-id> -l <link-id>

# Get link statistics
knetctl link stats -i <instance> -H <host-id> -l <link-id>
```

**Options:**
- `-i, --instance` - Instance name
- `-H, --host-id` - Host ID
- `-l, --link-id` - Link ID (0-7)
- `-t, --transport` - Transport type (udp, loopback)
- `-s, --src-addr` - Local address:port
- `-d, --dst-addr` - Remote address:port (optional for dynamic links)

### Event Monitoring

```bash
# Watch events (real-time)
knetctl events watch -i <instance>

# Watch with custom poll interval
knetctl events watch -i <instance> -p <milliseconds>
```

**Options:**
- `-i, --instance` - Instance name
- `-p, --poll-interval` - Poll interval in milliseconds (default: 500)

### Crypto Configuration

```bash
# List available crypto models, ciphers, and hashes (reflects what's compiled in)
knetctl crypto list

# Set crypto configuration
knetctl crypto set-config -i <instance> -m <model> \
    -c <cipher> -H <hash> -k <key-file> [-n <config-num>]

# Use crypto configuration
knetctl crypto use-config -i <instance> -n <config-num>
```

**Options (set-config / use-config):**
- `-i, --instance` - Instance name
- `-m, --model` - Crypto model (openssl, nss, gcrypt, or none)
- `-c, --cipher` - Cipher type (aes256, aes128, aes192, or none)
- `-H, --hash` - Hash type (sha256, sha512, sha1, or none)
- `-k, --key-file` - Path to key file (min 1024 bytes)
- `-n, --config-num` - Configuration slot (1 or 2)

### Compression Configuration

```bash
# List available compression models (reflects what's compiled in)
knetctl compress list

# Set compression
knetctl compress set-config -i <instance> -m <model> \
    [-t <threshold>] [-l <level>]

# Disable compression
knetctl compress set-config -i <instance> -m none
```

**Options (set-config):**
- `-i, --instance` - Instance name
- `-m, --model` - Compression model (zlib, lz4, lz4hc, lzo2, lzma, bzip2, zstd, none)
- `-t, --threshold` - Compression threshold in bytes (default: 100; use 1 to compress everything)
- `-l, --level` - Compression level (model-dependent, default: 6)

### Nozzle (Tap Device) Management

```bash
# Create a tap device for an instance
knetctl nozzle create -i <instance> [-n <dev-name>] [-a <ip/prefix>]... [--mtu <mtu>] [--mac <mac>] [--updown-path <path>] [--no-auto-up]

# Destroy the tap device
knetctl nozzle destroy -i <instance>

# Show tap device status
knetctl nozzle status -i <instance>
```

**Options:**
- `-i, --instance` - Instance name
- `-n, --name` - Desired tap device name (e.g. knet0); kernel assigns one if omitted
- `-a, --ip-address` - IP address in IP/PREFIX format to assign (repeatable); the daemon embeds the node ID into the host portion for uniqueness
- `--mtu` - MTU for the tap device (default: inherits from knet)
- `--mac` - Base MAC address (first 4 bytes, e.g. fe:54:00:00); daemon appends node ID as last two bytes
- `--updown-path` - Directory containing nozzle up/down scripts (pre-up.d, up.d, down.d, post-down.d)
- `--no-auto-up` - Do not bring the device up automatically when forwarding is enabled

### State Management

```bash
# Dump current daemon state as JSON to stdout
knetctl state save

# Save state to a file
knetctl state save -o <file>
```

**Options:**
- `-o, --output` - Write to this file instead of stdout

### Topology Visualization

```bash
# Show ASCII topology
knetctl topology show -i <instance> [-C]

# Export topology
knetctl topology export -i <instance> -f <format> -o <output>
```

**Options:**
- `-i, --instance` - Instance name
- `-C, --no-color` - Disable color output
- `-f, --format` - Export format (dot, svg)
- `-o, --output` - Output file path

## Examples

### Quick Setup

```bash
# Start daemon (in another terminal)
knetd

# Create VPN with 3 nodes
knetctl instance create -n cluster -H 1
knetctl host add -i cluster -H 2 -n web
knetctl host add -i cluster -H 3 -n db

# Configure links
knetctl link config -i cluster -H 2 -l 0 -t udp -s 10.0.0.1:5000 -d 10.0.0.2:5000
knetctl link enable -i cluster -H 2 -l 0

# Enable crypto
dd if=/dev/urandom of=/tmp/key bs=1024 count=1
knetctl crypto set-config -i cluster -m openssl -c aes256 -H sha256 -k /tmp/key
knetctl crypto use-config -i cluster -n 0

# Start data forwarding (IMPORTANT: required for traffic to flow!)
knetctl instance start -n cluster

# View topology
knetctl topology show -i cluster
```

### Troubleshooting

```bash
# Check daemon connectivity
knetctl ping

# List all instances
knetctl instance list

# Check specific link status
knetctl link status -i mynet -H 2 -l 0

# Get link statistics
knetctl link stats -i mynet -H 2 -l 0

# Watch for events
knetctl events watch -i mynet
```

## Tips

1. **Tab Completion**: Short options are faster to type and easier to remember
2. **Help is Always Available**: Add `--help` or `-h` to any command
3. **Socket Path**: Use `-s` to connect to a non-default daemon socket
4. **Combine Short Options**: Some shells allow combining: `-iH` instead of `-i -H` (not supported by clap)

## See Also

- `README.md` - Full documentation and examples
- `VISUALIZATION.md` - Detailed topology visualization guide
- `knetctl --help` - Interactive help for all commands
