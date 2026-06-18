# Contributing to knetd

Thank you for your interest in contributing to knetd!

## Architecture Overview

The knetd project is organized as a Cargo workspace with three crates:

### knetd-common
Shared types and message definitions used by both daemon and CLI.

**Key files:**
- `src/types.rs` - Type-safe wrappers (HostId, LinkId, etc.) with conversions to/from knet-bindings
- `src/rpc.rs` - JSON-RPC request/response message definitions
- `src/events.rs` - Event types for async notifications

### knetd (daemon)
The daemon process that manages libknet VPN instances.

**Key files:**
- `src/main.rs` - Entry point, config loading, logging setup
- `src/daemon.rs` - Main runtime loop, state management
- `src/rpc_server.rs` - JSON-RPC server over Unix sockets
- `src/config.rs` - TOML configuration parsing

**Architecture:**
- Uses tokio async runtime for I/O
- JSON-RPC 2.0 over Unix domain sockets for IPC
- Each VPN instance wraps one knet::Handle from knet-bindings
- Callbacks from libknet (C threads) bridged to tokio via channels

### knetctl (CLI)
Command-line utility to control the daemon.

**Key files:**
- `src/main.rs` - Entry point, argument parsing with clap
- `src/client.rs` - JSON-RPC client
- `src/commands/` - Command implementations (instance, host, link, etc.)

## Development Workflow

### Building
```bash
cd knetd
cargo build
```

### Running Tests
```bash
cargo test
```

### Running the Daemon
```bash
# From the repository root
cd knetd
./target/debug/knetd

# Or with a config file
./target/debug/knetd --config my-config.toml
```

### Using the CLI
```bash
./target/debug/knetctl ping
./target/debug/knetctl instance list
```

## Adding a New RPC Method

To add a new RPC method (e.g., "host.add"):

1. **Add message types** in `knetd-common/src/rpc.rs`:
   ```rust
   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct AddHostRequest {
       pub instance: InstanceName,
       pub host_id: HostId,
       pub name: Option<String>,
   }

   #[derive(Debug, Clone, Serialize, Deserialize)]
   pub struct AddHostResponse {
       pub success: bool,
   }
   ```

2. **Register the method** in `knetd/src/rpc_server.rs`:
   ```rust
   let state = self.state.clone();
   io.add_method("host.add", move |params: Params| {
       let state = state.clone();
       async move {
           // Parse params
           let req: AddHostRequest = params.parse()?;

           // Call implementation
           let result = add_host_impl(&state, req).await?;

           // Return response
           Ok(serde_json::to_value(result)?)
       }
   });
   ```

3. **Add CLI command** in `knetctl/src/commands/host.rs`:
   ```rust
   #[derive(Subcommand)]
   pub enum HostCommands {
       Add {
           #[arg(long)]
           instance: String,
           host_id: u16,
           #[arg(long)]
           name: Option<String>,
       },
   }
   ```

4. **Wire up the CLI** to call the RPC method:
   ```rust
   HostCommands::Add { instance, host_id, name } => {
       let req = AddHostRequest { ... };
       let response = client.call("host.add", serde_json::to_value(req)?).await?;
       println!("Success: {}", response["success"]);
   }
   ```

## Code Style

- Use `rustfmt` for formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy`
- Add doc comments (`///` for items, `//!` for modules) to public APIs
- Add regular comments (`//`) to explain non-obvious logic
- Keep functions focused and under 50 lines when possible
- Use descriptive variable names

## Key Patterns

### Cleanup Sequence for VPN Instances

When destroying a VPN instance, **follow this exact order** (from knet-test.rs):

```rust
1. knet::handle_setfwd(false)       // Stop forwarding
2. knet::handle_remove_datafd()     // Remove data FDs
3. knet::link_set_enable(false)     // Disable all links
4. knet::link_clear_config()        // Clear link configs
5. knet::host_remove()              // Remove all hosts
6. knet::handle_free()              // Free the handle
```

This sequence is critical to avoid memory leaks and crashes.

### Callback Bridge Pattern

libknet callbacks run on C-managed threads. Bridge them to tokio:

```rust
// Store event channel in callback private_data
struct CallbackContext {
    event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
}

let ctx = Box::new(CallbackContext { event_tx });
let private_data = Box::into_raw(ctx) as u64;

// In callback (C thread):
fn link_notify_fn(private_data: u64, ...) {
    let ctx = unsafe { &*(private_data as *const CallbackContext) };
    let _ = ctx.event_tx.try_send(DaemonEvent::LinkStatusChange { ... });
}

// Don't forget to free on cleanup!
unsafe { Box::from_raw(private_data as *mut CallbackContext) };
```

### Error Handling

- Use `thiserror` for daemon errors (structured error types)
- Use `anyhow` for CLI errors (convenience)
- Map JSON-RPC errors with proper error codes
- Always include context in error messages

## Testing

### Unit Tests
Place tests in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_id_conversion() {
        let id = HostId::new(42);
        assert_eq!(id.to_u16(), 42);
    }
}
```

### Integration Tests
Place in `tests/` directory. Example:

```rust
// tests/integration_test.rs
#[tokio::test]
async fn test_daemon_startup() {
    // Start daemon
    // Send RPC request
    // Verify response
}
```

## Reference Documentation

Key files to reference when implementing features:

- `/home/christine/dev/kronosnet/libknet/bindings/rust/src/knet_bindings.rs` - Complete API
- `/home/christine/dev/kronosnet/libknet/bindings/rust/tests/src/bin/knet-test.rs` - Usage examples
- `/home/christine/dev/kronosnet/CLAUDE.md` - Project overview
- `/home/christine/.claude/plans/gleaming-wondering-robin.md` - Implementation plan

## Commit Messages

Follow the kronosnet style:

```
component: Brief description

Longer explanation if needed. Reference issues/PRs if applicable.

Signed-off-by: Your Name <your.email@example.com>
```

Example:
```
knetd: Add host management RPC methods

Implements host.add, host.remove, and host.list RPC methods
with proper error handling and state tracking.

Signed-off-by: John Doe <john@example.com>
```

## Getting Help

- Check the implementation plan: `.claude/plans/gleaming-wondering-robin.md`
- Read the knet-bindings test: `../libknet/bindings/rust/tests/src/bin/knet-test.rs`
- Look at existing code for similar patterns
- Ask questions in issues/PRs

## License

All contributions are licensed under LGPL-2.1+ to match the kronosnet project.
