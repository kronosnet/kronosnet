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

### Future Commands

When adding new commands (crypto, compression, events), follow these conventions:
- `-i` for instance name (consistent across all commands)
- `-l` for link-id
- `-c` for crypto/compression config
- Use uppercase for less common options to avoid conflicts
- Always provide both short and long forms for discoverability
