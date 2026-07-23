# knetctl CLI Short Options Reference

This document lists all short options available in knetctl for faster command-line usage.

## Global Options

| Short | Long       | Description                          |
|-------|------------|--------------------------------------|
| `-s`  | `--socket` | Path to daemon's Unix socket         |
| `-h`  | `--help`   | Print help information               |

## Instance Commands

### `instance create`
```bash
knetctl instance create -n <NAME> -H <HOST_ID>
```
| Short | Long        | Description                        |
|-------|-------------|------------------------------------|
| `-n`  | `--name`    | Name for the new instance          |
| `-H`  | `--host-id` | Local host ID (0-65535)            |

### `instance destroy`
```bash
knetctl instance destroy -n <NAME>
```
| Short | Long     | Description                        |
|-------|----------|------------------------------------|
| `-n`  | `--name` | Name of instance to destroy        |

### `instance list`
```bash
knetctl instance list
```
No options required.

## Host Commands

### `host add`
```bash
knetctl host add -i <INSTANCE> -H <HOST_ID> [-n <NAME>]
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Host ID to add (0-65535)           |
| `-n`  | `--name`     | Optional human-readable name       |

### `host remove`
```bash
knetctl host remove -i <INSTANCE> -H <HOST_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Host ID to remove                  |

### `host list`
```bash
knetctl host list -i <INSTANCE>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |

### `host status`
```bash
knetctl host status -i <INSTANCE> -H <HOST_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Host ID to query                   |

## Link Commands

### `link config`
```bash
knetctl link config -i <INSTANCE> -H <HOST_ID> -l <LINK_ID> -t <TRANSPORT> -s <SRC> [-d <DST>]
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Remote host ID                     |
| `-l`  | `--link-id`  | Link ID (0-7)                      |
| `-t`  | `--transport`| Transport type (udp, loopback)     |
| `-s`  | `--src-addr` | Local address:port                 |
| `-d`  | `--dst-addr` | Remote address:port (optional)     |

### `link enable`
```bash
knetctl link enable -i <INSTANCE> -H <HOST_ID> -l <LINK_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Remote host ID                     |
| `-l`  | `--link-id`  | Link ID (0-7)                      |

### `link disable`
```bash
knetctl link disable -i <INSTANCE> -H <HOST_ID> -l <LINK_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Remote host ID                     |
| `-l`  | `--link-id`  | Link ID (0-7)                      |

### `link status`
```bash
knetctl link status -i <INSTANCE> -H <HOST_ID> -l <LINK_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Remote host ID                     |
| `-l`  | `--link-id`  | Link ID (0-7)                      |

### `link stats`
```bash
knetctl link stats -i <INSTANCE> -H <HOST_ID> -l <LINK_ID>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |
| `-H`  | `--host-id`  | Remote host ID                     |
| `-l`  | `--link-id`  | Link ID (0-7)                      |

## Event Commands

### `events watch`
```bash
knetctl events watch -i <INSTANCE> [-p <POLL_INTERVAL>]
```
| Short | Long              | Description                              |
|-------|-------------------|------------------------------------------|
| `-i`  | `--instance`      | VPN instance name                        |
| `-p`  | `--poll-interval` | Poll interval in milliseconds (default: 500) |

## Crypto Commands

### `crypto list`
```bash
knetctl crypto list
```
No options required. Prints available models, ciphers, and hashes compiled into libknet.

### `crypto set-config`
```bash
knetctl crypto set-config -i <INSTANCE> -m <MODEL> -c <CIPHER> -H <HASH> -k <KEY_FILE> [-n <CONFIG_NUM>]
```
| Short | Long           | Description                                |
|-------|----------------|--------------------------------------------|
| `-i`  | `--instance`   | VPN instance name                          |
| `-m`  | `--model`      | Crypto model (openssl, nss, gcrypt, none); default: openssl |
| `-c`  | `--cipher`     | Cipher type (aes256, aes128, aes192, none); default: aes256 |
| `-H`  | `--hash`       | Hash type (sha256, sha512, sha1, none); default: sha256 |
| `-k`  | `--key-file`   | Path to key file (must be at least 1024 bytes) |
| `-n`  | `--config-num` | Configuration slot (1 or 2); default: 1   |

### `crypto use-config`
```bash
knetctl crypto use-config -i <INSTANCE> -n <CONFIG_NUM>
```
| Short | Long           | Description                                |
|-------|----------------|--------------------------------------------|
| `-i`  | `--instance`   | VPN instance name                          |
| `-n`  | `--config-num` | Configuration slot to activate (1 or 2)   |

## Compress Commands

### `compress list`
```bash
knetctl compress list
```
No options required. Prints compression models compiled into libknet.

### `compress set-config`
```bash
knetctl compress set-config -i <INSTANCE> -m <MODEL> [-t <THRESHOLD>] [-l <LEVEL>]
```
| Short | Long          | Description                                               |
|-------|---------------|-----------------------------------------------------------|
| `-i`  | `--instance`  | VPN instance name                                         |
| `-m`  | `--model`     | Compression model (zlib, lz4, lz4hc, lzo2, lzma, bzip2, zstd, none) |
| `-t`  | `--threshold` | Threshold in bytes; packets smaller won't be compressed (default: 100, 1 = compress everything) |
| `-l`  | `--level`     | Compression level (model-dependent; default: 6)           |

## Nozzle Commands

### `nozzle create`
```bash
knetctl nozzle create -i <INSTANCE> [-n <NAME>] [-a <IP/PREFIX>]... [--mtu <MTU>] [--mac <MAC>] [--updown-path <PATH>] [--no-auto-up]
```
| Short | Long             | Description                                                |
|-------|------------------|------------------------------------------------------------|
| `-i`  | `--instance`     | VPN instance name                                          |
| `-n`  | `--name`         | Desired tap device name (kernel assigns one if omitted)    |
| `-a`  | `--ip-address`   | IP address in IP/PREFIX format (may be repeated)           |
| (none)| `--mtu`          | MTU for the tap device (default: inherits from knet)       |
| (none)| `--mac`          | Base MAC address (first 4 bytes, e.g. fe:54:00:00)         |
| (none)| `--updown-path`  | Directory containing nozzle up/down scripts                |
| (none)| `--no-auto-up`   | Do not bring device up automatically when forwarding starts |

### `nozzle destroy`
```bash
knetctl nozzle destroy -i <INSTANCE>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |

### `nozzle status`
```bash
knetctl nozzle status -i <INSTANCE>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | VPN instance name                  |

## State Commands

### `state save`
```bash
knetctl state save [-o <OUTPUT>]
```
| Short | Long       | Description                                        |
|-------|------------|----------------------------------------------------|
| `-o`  | `--output` | Write JSON state to this file instead of stdout    |

## Topology Commands

### `topology show`
```bash
knetctl topology show -i <INSTANCE> [-C]
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | Instance name                      |
| `-C`  | `--no-color` | Disable color output               |

### `topology export`
```bash
knetctl topology export -i <INSTANCE> -f <FORMAT> -o <OUTPUT>
```
| Short | Long         | Description                        |
|-------|--------------|------------------------------------|
| `-i`  | `--instance` | Instance name                      |
| `-f`  | `--format`   | Export format (dot, svg)           |
| `-o`  | `--output`   | Output file path                   |

## Examples

### Complete VPN Setup
```bash
# Create instance
knetctl instance create -n prod -H 1

# Add remote hosts
knetctl host add -i prod -H 10 -n "node10"
knetctl host add -i prod -H 11 -n "node11"

# Configure links
knetctl link config -i prod -H 10 -l 0 -t udp -s 10.0.0.1:5000 -d 10.0.0.10:5000
knetctl link config -i prod -H 11 -l 0 -t udp -s 10.0.0.1:5001 -d 10.0.0.11:5000

# Enable links
knetctl link enable -i prod -H 10 -l 0
knetctl link enable -i prod -H 11 -l 0

# Check link status
knetctl link status -i prod -H 10 -l 0
knetctl link stats -i prod -H 10 -l 0
```

### Multi-Link Redundancy
```bash
# Add primary link
knetctl link config -i prod -H 10 -l 0 -t udp -s 10.0.0.1:5000 -d 10.0.0.10:5000
knetctl link enable -i prod -H 10 -l 0

# Add backup link on different network
knetctl link config -i prod -H 10 -l 1 -t udp -s 192.168.1.1:5001 -d 192.168.1.10:5000
knetctl link enable -i prod -H 10 -l 1

# Both links now active for redundancy
```

### Quick Instance and Host Setup
```bash
# Create instance with short options
knetctl instance create -n prod -H 1

# Add hosts with short options
knetctl host add -i prod -H 10 -n "node10"
knetctl host add -i prod -H 11 -n "node11"

# List hosts
knetctl host list -i prod

# Check host status
knetctl host status -i prod -H 10
```

### Topology Visualization
```bash
# Show topology without colors
knetctl topology show -i prod -C

# Export to DOT format
knetctl topology export -i prod -f dot -o network.dot

# Export to SVG
knetctl topology export -i prod -f svg -o network.svg
```

## Design Notes

### Short Option Conventions

- **`-i`**: instance (most commonly used option)
- **`-n`**: name (for both instance names and host names)
- **`-H`**: host-id (uppercase to avoid conflict with `-h` for help)
- **`-l`**: link-id
- **`-t`**: transport type
- **`-s`**: source address (or socket for global option)
- **`-d`**: destination address
- **`-C`**: no-color (uppercase to avoid common conflicts)
- **`-f`**: format
- **`-o`**: output

### Why `-H` for host-id?

We use uppercase `-H` instead of lowercase `-h` because:
- `-h` is universally reserved for `--help` in CLI tools
- Uppercase is visually distinct and emphasizes "Host ID"
- Consistent with conventions in networking tools (e.g., `ssh -H`)

### Adding New Commands

When adding new commands, follow these conventions:
- `-i` for instance name (consistent across all commands)
- `-l` for link-id
- Use uppercase for less common options to avoid conflicts
- Always provide both short and long forms for discoverability
- Long-form-only options (`--option`) are acceptable for infrequently used flags
