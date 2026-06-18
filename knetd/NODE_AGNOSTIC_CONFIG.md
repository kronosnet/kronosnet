# Node-Agnostic Configuration

## Overview

As of this update, knetd supports **node-agnostic configuration files**. This means the same configuration file can be deployed to all nodes in a cluster, with each node automatically filtering the configuration to use only the parts relevant to itself.

## Key Concepts

### Node Identification

Each daemon instance identifies itself using one of:
1. `--node-id <N>` command-line argument (highest priority)
2. `KNETD_NODE_ID=<N>` environment variable

The node ID must match a `host_id` defined in the config's `[[instances.nodes]]` section.

### Configuration Structure

The config file defines the **entire cluster topology**:

```toml
[[instances]]
name = "my-cluster"
auto_start = true

# All nodes in the cluster
[[instances.nodes]]
host_id = 1
name = "alice"

[[instances.nodes]]
host_id = 2
name = "bob"

[[instances.nodes]]
host_id = 3
name = "charlie"

# All links (unidirectional) between all nodes
[[instances.links]]
from_host = 1
to_host = 2
link_id = 0
transport = "udp"
src_addr = "10.0.1.1:5000"
dst_addr = "10.0.1.2:5000"
auto_enable = true

[[instances.links]]
from_host = 2
to_host = 1
link_id = 0
transport = "udp"
src_addr = "10.0.1.2:5000"
dst_addr = "10.0.1.1:5000"
auto_enable = true
```

### Startup Behavior

When knetd starts with `--node-id 1`:
1. Finds the node with `host_id = 1` in `[[instances.nodes]]`
2. Creates VPN instance with that node's `host_id`
3. Adds **all other nodes** as remote hosts
4. Configures **only links where `from_host = 1`**
5. Ignores all other links (they belong to other nodes)

When knetd starts with `--node-id 2`:
1. Finds the node with `host_id = 2`
2. Creates VPN instance with that node's `host_id`
3. Adds alice and charlie as remote hosts
4. Configures **only links where `from_host = 2`**

## Benefits

1. **Single source of truth**: One config file defines the entire cluster topology
2. **No per-node customization**: Deploy identical files to all nodes
3. **Easier management**: Update cluster topology in one place
4. **Configuration management friendly**: Works well with Ansible, Salt, Puppet, etc.

## Example Deployment

### Config File (`/etc/knetd/knetd.toml`)
Deploy this identical file to all three nodes:

```toml
socket_path = "/var/run/knetd.sock"

[[instances]]
name = "prod-cluster"
auto_start = true

[[instances.nodes]]
host_id = 1
name = "web1"

[[instances.nodes]]
host_id = 2
name = "web2"

[[instances.nodes]]
host_id = 3
name = "db1"

# Bidirectional links between all nodes
[[instances.links]]
from_host = 1
to_host = 2
link_id = 0
transport = "udp"
src_addr = "192.168.1.1:5000"
dst_addr = "192.168.1.2:5000"
auto_enable = true

[[instances.links]]
from_host = 2
to_host = 1
link_id = 0
transport = "udp"
src_addr = "192.168.1.2:5000"
dst_addr = "192.168.1.1:5000"
auto_enable = true

# ... more links ...
```

### Systemd Service Override

On each node, create `/etc/systemd/system/knetd.service.d/override.conf`:

**web1 (192.168.1.1)**:
```ini
[Service]
Environment="KNETD_NODE_ID=1"
```

**web2 (192.168.1.2)**:
```ini
[Service]
Environment="KNETD_NODE_ID=2"
```

**db1 (192.168.1.3)**:
```ini
[Service]
Environment="KNETD_NODE_ID=3"
```

Or pass via command-line:
```ini
[Service]
ExecStart=/usr/bin/knetd --node-id 1
```

## Backward Compatibility

### Single-Node Configs (Old Style)

The old config style still works when there's exactly **one node** defined:

```toml
[[instances]]
name = "old-style"
host_id = 1  # Still supported for backward compatibility
auto_start = true

[[instances.nodes]]
host_id = 1
name = "only-node"
```

If `--node-id` is not specified and there's only one node, knetd will use that node.

### Migration from Old Style

Old config:
```toml
[[instances]]
name = "mynet"
host_id = 1
auto_start = true

[[instances.hosts]]  # Old field
host_id = 2
name = "node2"

[[instances.links]]  # Old field (implicit from_host)
host_id = 2
link_id = 0
transport = "udp"
src_addr = "10.0.0.1:5000"
dst_addr = "10.0.0.2:5000"
```

New config (node-agnostic):
```toml
[[instances]]
name = "mynet"
auto_start = true

[[instances.nodes]]  # Define ALL nodes
host_id = 1
name = "node1"

[[instances.nodes]]
host_id = 2
name = "node2"

[[instances.links]]  # Explicit from_host/to_host
from_host = 1
to_host = 2
link_id = 0
transport = "udp"
src_addr = "10.0.0.1:5000"
dst_addr = "10.0.0.2:5000"

[[instances.links]]  # Reverse link (bidirectional)
from_host = 2
to_host = 1
link_id = 0
transport = "udp"
src_addr = "10.0.0.2:5000"
dst_addr = "10.0.0.1:5000"
```

Then start with `--node-id 1` on node1 and `--node-id 2` on node2.

## Error Handling

### Missing Node ID with Multiple Nodes

If the config has multiple nodes but no node ID is specified:
```
ERROR Instance 'mynet' has 3 nodes but no local node ID specified (use --node-id or KNETD_NODE_ID)
```

The daemon still starts but won't auto-start that instance.

### Invalid Node ID

If `--node-id 99` is specified but no node with `host_id = 99` exists:
```
ERROR Local node ID 99 not found in instance 'mynet' nodes list
```

The instance is skipped during auto-start.

## Full-Mesh Mode

For high-availability clusters (like Corosync) that need full mesh connectivity, knetd supports a simplified **full-mesh mode**.

### How It Works

Set `full_mesh = true` in your instance configuration and define `link_addresses` for each node. The daemon automatically creates bidirectional links between all nodes.

### Example Configuration

```toml
[[instances]]
name = "ha-cluster"
auto_start = true
full_mesh = true  # Enable automatic full-mesh

[[instances.nodes]]
host_id = 1
name = "node1"
link_addresses = [
    "192.168.1.1:5405",   # Link 0: primary network
    "10.0.0.1:5405",      # Link 1: secondary network
]

[[instances.nodes]]
host_id = 2
name = "node2"
link_addresses = [
    "192.168.1.2:5405",
    "10.0.0.2:5405",
]

[[instances.nodes]]
host_id = 3
name = "node3"
link_addresses = [
    "192.168.1.3:5405",
    "10.0.0.3:5405",
]
```

### What Gets Created

On **node1** (--node-id 1):
- Link 0 to node2: `192.168.1.1:5405 → 192.168.1.2:5405`
- Link 1 to node2: `10.0.0.1:5405 → 10.0.0.2:5405`
- Link 0 to node3: `192.168.1.1:5405 → 192.168.1.3:5405`
- Link 1 to node3: `10.0.0.1:5405 → 10.0.0.3:5405`

On **node2** (--node-id 2):
- Link 0 to node1: `192.168.1.2:5405 → 192.168.1.1:5405`
- Link 1 to node1: `10.0.0.2:5405 → 10.0.0.1:5405`
- Link 0 to node3: `192.168.1.2:5405 → 192.168.1.3:5405`
- Link 1 to node3: `10.0.0.2:5405 → 10.0.0.3:5405`

And so on. Result: full bidirectional mesh with redundant links.

### Full-Mesh Mode Rules

- `link_addresses[0]` becomes link 0, `link_addresses[1]` becomes link 1, etc.
- Maximum 8 links per node pair (indices 0-7)
- If nodes have different numbers of link addresses, only the minimum is used
- All links are UDP transport
- All links are automatically enabled
- The `links` field in the config is **ignored** in full-mesh mode

### Benefits Over Manual Mode

**Manual mode** (3 nodes, 2 links each):
```toml
# 12 link definitions required (2 links × 3 pairs × 2 directions)
[[instances.links]]
from_host = 1
to_host = 2
link_id = 0
# ... 11 more ...
```

**Full-mesh mode** (same topology):
```toml
# Just define addresses for each node
[[instances.nodes]]
link_addresses = ["addr1", "addr2"]
```

Much simpler for HA clusters!

## See Also

- `knetd.toml.example` - Manual mode example with 3-node cluster
- `knetd-fullmesh.toml.example` - Full-mesh mode example (Corosync-style)
- `example-script.sh` - Demonstration script
- `README.md` - Main documentation
