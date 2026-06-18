# Code Tour: knetd Architecture

This document provides a guided tour through the knetd codebase for developers.

## Project Structure

```
knetd/
├── Cargo.toml                 # Workspace definition
├── README.md                  # User documentation
├── CONTRIBUTING.md            # Developer guide
├── CODE_TOUR.md              # This file
│
├── knetd-common/             # Shared types library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs            # Re-exports all modules
│       ├── types.rs          # HostId, LinkId, InstanceName wrappers
│       ├── rpc.rs            # RPC request/response messages
│       └── events.rs         # Event types for notifications
│
├── knetd/                    # Daemon binary
│   ├── Cargo.toml
│   ├── knetd.toml.example   # Example configuration
│   └── src/
│       ├── main.rs           # Entry point
│       ├── daemon.rs         # Main runtime loop
│       ├── rpc_server.rs     # JSON-RPC server
│       └── config.rs         # TOML config loading
│
└── knetctl/                  # CLI binary
    ├── Cargo.toml
    └── src/
        ├── main.rs           # Entry point, arg parsing
        ├── client.rs         # JSON-RPC client
        └── commands/         # Command implementations
            ├── mod.rs
            └── instance.rs   # Instance commands
```

## Data Flow

### Daemon Startup
```
main.rs
  ├─> Load config from TOML file
  ├─> Initialize tracing (logging)
  └─> daemon::run(config)
        ├─> Create shared state (Arc<Mutex<...>>)
        ├─> Start RPC server
        └─> Wait for shutdown signal or error
```

### RPC Request Flow
```
knetctl                         Unix Socket                knetd
  │                                  │                       │
  ├─> Parse CLI args                 │                       │
  ├─> Connect to socket ─────────────┼───────────────────────>
  ├─> Send JSON-RPC request ─────────┼───────────────────────>
  │                                  │                       ├─> Parse request
  │                                  │                       ├─> Dispatch to handler
  │                                  │                       ├─> Execute operation
  │                                  │                       └─> Return response
  <──────── Receive response ────────┼───────────────────────┤
  └─> Pretty-print output            │                       │
```

### Future: Event Streaming
```
knetd                                                     knetctl
  │                                                          │
  ├─> libknet callback (C thread)                           │
  │     └─> Send to broadcast channel                       │
  │                                                          │
  <── Client subscribes via RPC "events.subscribe" ─────────┤
  │                                                          │
  ├─> Broadcast events to all subscribers ──────────────────>
  │     (LinkStatusChange, HostStatusChange, etc.)          │
```

## Key Types

### knetd-common Types

```rust
// Type-safe wrappers
pub struct InstanceName(String);    // VPN instance name
pub struct HostId(u16);             // Host ID (0-65535)
pub struct LinkId(u8);              // Link ID (0-7)

// Info structures
pub struct InstanceInfo {
    name: InstanceName,
    host_id: HostId,
    running: bool,
}

pub struct HostInfo {
    host_id: HostId,
    name: Option<String>,
    reachable: bool,
}

pub struct LinkInfo {
    link_id: LinkId,
    transport: String,
    src_addr: Option<String>,
    dst_addr: Option<String>,
    enabled: bool,
    connected: bool,
}

// Events
pub enum DaemonEvent {
    LinkStatusChange { instance, host_id, link_id, connected, ... },
    HostStatusChange { instance, host_id, reachable, ... },
    PmtudNotify { instance, mtu, ... },
    // ...
}
```

### Future: VPN Instance State

```rust
// Will be added in Phase 2
struct VpnInstance {
    name: InstanceName,
    host_id: HostId,
    handle: knet::Handle,           // libknet handle
    hosts: HashMap<HostId, HostMetadata>,
    event_tx: broadcast::Sender<DaemonEvent>,
    log_thread: JoinHandle<()>,
}

struct HostMetadata {
    name: Option<String>,
    links: HashMap<LinkId, LinkConfig>,
}

struct LinkConfig {
    transport: TransportId,
    src_addr: SocketAddr,
    dst_addr: Option<SocketAddr>,
    enabled: bool,
}
```

## RPC Protocol

### Message Format

All RPC messages follow JSON-RPC 2.0 format:

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "instance.create",
  "params": {
    "name": "mynet",
    "host_id": 1
  },
  "id": 1
}
```

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true
  },
  "id": 1
}
```

**Error Response:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "VPN instance 'mynet' not found"
  },
  "id": 1
}
```

### Registered Methods (Current)

- `ping` - Test connectivity

### Planned Methods (Future Phases)

**Instance Management:**
- `instance.create(name, host_id)` → `{success: bool}`
- `instance.destroy(name)` → `{success: bool}`
- `instance.list()` → `{instances: [InstanceInfo]}`

**Host Management:**
- `host.add(instance, host_id, name?)` → `{success: bool}`
- `host.remove(instance, host_id)` → `{success: bool}`
- `host.list(instance)` → `{hosts: [HostInfo]}`
- `host.get_status(instance, host_id)` → `{host: HostInfo}`

**Link Management:**
- `link.set_config(instance, host_id, link_id, ...)` → `{success: bool}`
- `link.enable(instance, host_id, link_id, enable)` → `{success: bool}`
- `link.get_status(instance, host_id, link_id)` → `{link: LinkInfo}`
- `link.get_stats(instance, host_id, link_id)` → `{stats: LinkStats}`

**Crypto/Compression:**
- `crypto.set_config(instance, model, cipher, hash, key)` → `{success: bool}`
- `compression.set_config(instance, model, threshold, level)` → `{success: bool}`

**Event Subscription:**
- `events.subscribe(instance?)` → Stream of DaemonEvent
- `events.unsubscribe()` → `{success: bool}`

## Threading Model

### Current (Phase 1)
```
Main Thread (tokio)
  ├─> RPC server (background threads via jsonrpc-ipc-server)
  └─> Signal handling (Ctrl+C)
```

### Future (Phase 2+)
```
Main Thread (tokio)
  ├─> RPC server (background threads)
  ├─> Event broadcaster task
  └─> Signal handling

Per-VPN Instance:
  ├─> Logging thread (OS thread, reads mpsc from libknet)
  └─> libknet internal threads (rx, tx, heartbeat, pmtud, etc.)
```

## Important Patterns

### 1. Cleanup Sequence

**CRITICAL**: When destroying a VPN instance, follow this exact order:

```rust
// 1. Stop forwarding
knet::handle_setfwd(handle, false)?;

// 2. Remove data file descriptors
knet::handle_remove_datafd(handle, datafd)?;

// 3. Disable all links
for (host_id, link_id) in links {
    knet::link_set_enable(handle, &host_id, link_id, false)?;
}

// 4. Clear link configurations
for (host_id, link_id) in links {
    knet::link_clear_config(handle, &host_id, link_id)?;
}

// 5. Remove all hosts
for host_id in hosts {
    knet::host_remove(handle, &host_id)?;
}

// 6. Free the handle
knet::handle_free(handle)?;
```

This order prevents crashes and memory leaks.

### 2. Logging Thread Pattern

libknet logging is async via a channel:

```rust
use std::sync::mpsc::channel;

let (log_sender, log_receiver) = channel::<knet::LogMsg>();

// Spawn thread to drain log messages
spawn(move || {
    for msg in &log_receiver {
        tracing::info!("[{}] {}: {}",
            msg.subsystem, msg.level, msg.msg);
    }
});

// Create handle with logging channel
let handle = knet::handle_new(
    &host_id,
    Some(log_sender),
    knet::LogLevel::Debug,
    knet::HandleFlags::NONE
)?;
```

### 3. Callback Bridge Pattern

Bridge C callbacks to Rust async:

```rust
// Context stored in callback private_data
struct CallbackContext {
    event_tx: broadcast::Sender<DaemonEvent>,
}

// Store as raw pointer for C FFI
let ctx = Box::new(CallbackContext { event_tx });
let private_data = Box::into_raw(ctx) as u64;

// Register callback
knet::link_enable_status_change_notify(
    handle,
    private_data,
    Some(link_callback)
)?;

// Callback runs on C thread
fn link_callback(private_data: u64, host_id: HostId,
                 link_id: u8, connected: bool, ...) {
    // SAFETY: private_data is valid for lifetime of handle
    let ctx = unsafe { &*(private_data as *const CallbackContext) };

    // Non-blocking send to tokio channel
    let _ = ctx.event_tx.try_send(DaemonEvent::LinkStatusChange {
        // ...
    });
}

// Don't forget to free on cleanup!
unsafe { Box::from_raw(private_data as *mut CallbackContext) };
```

## Configuration File Format

```toml
# knetd.toml example
[daemon]
socket_path = "/run/knetd/knetd.sock"
log_level = "info"
state_file = "/var/lib/knetd/state.json"

# Pre-configured instances (optional)
[[instances]]
name = "prod"
host_id = 1
auto_start = true

  [[instances.hosts]]
  host_id = 2
  name = "node2"

  [[instances.links]]
  host_id = 2
  link_id = 0
  transport = "udp"
  src_addr = "10.0.0.1:5000"
  dst_addr = "10.0.0.2:5000"
  auto_enable = true
```

## Dependencies

### knetd
- `tokio` - Async runtime
- `jsonrpc-core`, `jsonrpc-ipc-server` - RPC server
- `serde`, `serde_json` - Serialization
- `toml` - Config parsing
- `tracing`, `tracing-subscriber` - Logging
- `thiserror` - Error types
- `knet-bindings` - libknet Rust API

### knetctl
- `clap` - CLI argument parsing
- `jsonrpc-core-client` - RPC client
- `tokio` - Async runtime
- `serde_json` - Serialization
- `anyhow` - Error handling
- `tabled` - Pretty table output (future)

## Next Steps for Developers

1. **Read the implementation plan**: `.claude/plans/gleaming-wondering-robin.md`
2. **Study the reference implementation**: `../libknet/bindings/rust/tests/src/bin/knet-test.rs`
3. **Start with Phase 2**: Implement VPN instance lifecycle
4. **Follow the patterns**: Use the cleanup sequence, logging thread, callback bridge

## Debugging Tips

### Enable Debug Logging
```bash
RUST_LOG=debug ./target/debug/knetd
```

### Test RPC Manually
```bash
# Using netcat
echo '{"jsonrpc":"2.0","method":"ping","params":{},"id":1}' | \
  nc -U /run/knetd/knetd.sock
```

### Check Socket Permissions
```bash
ls -l /run/knetd/knetd.sock
# Should be writable by your user
```

### Verify libknet Plugins
The daemon uses libknet's crypto/compression plugins. Make sure they're in the library path:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## Common Issues

**Socket already in use:**
```
Error: Failed to bind: Address already in use
```
Solution: Remove stale socket: `rm /run/knetd/knetd.sock`

**Can't connect to daemon:**
```
Error: Failed to connect to /run/knetd/knetd.sock: No such file or directory
```
Solution: Start the daemon first

**libknet not found:**
```
error while loading shared libraries: libknet.so.2
```
Solution: Install libknet or set `LD_LIBRARY_PATH`
