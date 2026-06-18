# Nozzle Unique Addressing

## Overview

When using nozzle (tap) devices with knetd in a multi-node cluster, each node must have a unique MAC address and IP address on the nozzle network. To avoid manual configuration of different addresses for each node, knetd automatically embeds the **node ID** into both the MAC address and IP address.

This approach matches Corosync's implementation in `totemknet.c` and allows the same configuration file to be deployed to all nodes in a cluster.

## How It Works

### MAC Address Uniqueness

The configured MAC address is treated as a **base MAC** with only the first 4 bytes (8 hex digits). The **last 2 bytes** are automatically replaced with the node ID:

**Format**: `XX:XX:XX:XX:HH:HH`

Where:
- `XX:XX:XX:XX` = First 4 bytes from the configured base MAC
- `HH:HH` = Node ID encoded as 2 bytes (high byte, low byte)

**Example**:

```toml
[instances.nozzle]
mac = "fe:54:00:00"  # Base MAC (first 4 bytes)
```

**Result for each node**:
- Node 1: `fe:54:00:00:00:01`
- Node 2: `fe:54:00:00:00:02`
- Node 3: `fe:54:00:00:00:03`
- Node 256: `fe:54:00:00:01:00`

### IP Address Uniqueness

The configured IP address is treated as a **base IP** that gets masked and combined with the node ID.

#### IPv4

For IPv4 addresses, the algorithm:
1. Parses the base IP and prefix
2. Creates a node ID mask: `nodeid_mask = 0xFFFFFFFF & ((1 << (32 - prefix_bits)) - 1)`
3. Creates an address mask: `addr_mask = 0xFFFFFFFF ^ nodeid_mask`
4. Masks the base IP: `base_ip & addr_mask`
5. Masks the node ID: `node_id & nodeid_mask`
6. Combines them: `(base_ip & addr_mask) | (node_id & nodeid_mask)`

**Prefix Constraints**: Must be between 8 and 30 (inclusive)

**Example**:

```toml
[instances.nozzle]
ip_addresses = ["192.168.100.0/24"]
```

With prefix `/24`, the last 8 bits are available for the node ID:
- Node 1: `192.168.100.1/24`
- Node 2: `192.168.100.2/24`
- Node 3: `192.168.100.3/24`
- Node 254: `192.168.100.254/24`

**Example with /16**:

```toml
[instances.nozzle]
ip_addresses = ["10.0.0.0/16"]
```

With prefix `/16`, the last 16 bits are available:
- Node 1: `10.0.0.1/16`
- Node 256: `10.0.1.0/16`
- Node 257: `10.0.1.1/16`
- Node 65535: `10.0.255.255/16`

#### IPv6

For IPv6 addresses using `::` notation, the node ID is simply appended as hexadecimal after the `::`.

**Prefix Constraints**: Must be between 8 and 64 (inclusive)

**Example**:

```toml
[instances.nozzle]
ip_addresses = ["fd00::/64"]
```

**Result for each node**:
- Node 1: `fd00::1/64`
- Node 2: `fd00::2/64`
- Node 255: `fd00::ff/64`
- Node 256: `fd00::100/64`

## Configuration Example

### Single Configuration File for All Nodes

```toml
socket_path = "/var/run/knetd.sock"
log_level = "info"

[[instances]]
name = "ha-cluster"
auto_start = true
full_mesh = true

[[instances.nodes]]
host_id = 1
name = "node1"
link_addresses = ["192.168.1.1:5405"]

[[instances.nodes]]
host_id = 2
name = "node2"
link_addresses = ["192.168.1.2:5405"]

[[instances.nodes]]
host_id = 3
name = "node3"
link_addresses = ["192.168.1.3:5405"]

# Nozzle configuration - SAME on all nodes
[instances.nozzle]
name = "knet0"
ip_addresses = ["10.0.0.0/24"]      # Base IP - will become 10.0.0.1, 10.0.0.2, 10.0.0.3
mtu = 1400
mac = "fe:54:00:00"                  # Base MAC - will become fe:54:00:00:00:01, etc.
auto_up = true
```

### Deploy and Run

Deploy the **same** config file to all three nodes:

```bash
# On node 1
knetd --config /etc/knetd/knetd.toml --node-id 1

# On node 2
knetd --config /etc/knetd/knetd.toml --node-id 2

# On node 3
knetd --config /etc/knetd/knetd.toml --node-id 3
```

Each node will:
- Create nozzle device `knet0`
- Assign unique MAC based on node ID
- Assign unique IP based on node ID
- Connect to other nodes via knet links

## Verification

After starting the daemon, check the logs for the actual assigned addresses:

```bash
# Check assigned MAC
grep "Setting MAC" /var/log/knetd.log

# Check assigned IP
grep "Adding IP address" /var/log/knetd.log
```

Or use system tools:

```bash
# Check MAC address
ip link show knet0

# Check IP address
ip addr show knet0
```

## Testing

A test script is provided to verify unique addressing with multiple local instances:

```bash
cd knetd
./test-nozzle-unique.sh
```

This script:
1. Starts 3 daemon instances locally (nodes 1, 2, 3)
2. Each creates a nozzle device with embedded node ID
3. Verifies MAC and IP uniqueness in logs
4. Cleans up automatically

**Note**: Requires root privileges to actually create nozzle devices. Without root, it still verifies the calculation logic in logs.

## Implementation Details

The implementation is in `knetd/src/vpn_instance.rs`:

- **`reparse_nozzle_ip()`**: Implements IP address masking and node ID embedding
- **`create_nozzle()`**: Implements MAC address formatting with node ID

This matches the logic in Corosync's `exec/totemknet.c`:
- `reparse_nozzle_ip_address()` - IP address handling
- `setup_nozzle()` - MAC address handling with node ID insertion

## Limitations

### Node ID Range

- **Maximum node ID**: 65535 (2 bytes)
- For MAC addresses, all node IDs are valid
- For IP addresses, the usable range depends on the prefix:
  - `/30` (IPv4): Only 2 host bits → nodes 1-3 usable (0 and 255 typically reserved)
  - `/24` (IPv4): 256 addresses → nodes 1-254 usable
  - `/16` (IPv4): 65536 addresses → all node IDs fit

### Reserved Addresses

The algorithm does NOT automatically exclude:
- Network address (all host bits = 0)
- Broadcast address (all host bits = 1 for IPv4)

**Best practice**: Avoid using node ID 0 and avoid using node IDs near the broadcast address.

For example, with `/24`:
- Don't use node ID 0 (would be network address `192.168.100.0`)
- Don't use node ID 255 (would be broadcast `192.168.100.255`)
- Use node IDs 1-254

## Rationale

This design:
1. **Simplifies deployment**: Same config file on all nodes
2. **Prevents conflicts**: Automatic uniqueness guaranteed
3. **Matches Corosync**: Compatible with existing HA clustering patterns
4. **Supports large clusters**: Up to 65535 nodes (16-bit node IDs)

## See Also

- [NODE_AGNOSTIC_CONFIG.md](NODE_AGNOSTIC_CONFIG.md) - Node-agnostic configuration guide
- [README.md](README.md) - General knetd documentation
- Corosync source: `exec/totemknet.c` - Original implementation reference
