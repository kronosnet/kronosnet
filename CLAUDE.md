# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kronosnet is an advanced VPN library for High Availability applications, consisting of two main libraries:

- **libknet**: Core networking library providing multi-link, fault-tolerant network communication with crypto/compression support
- **libnozzle**: Commodity library for managing tap (ethernet) interfaces

The project uses a dlopen model for crypto and compression modules to save runtime resources and provide flexibility.

## Build System

This project uses GNU Autotools (autoconf/automake).

### Initial Setup
```bash
./autogen.sh
./configure [options]
make
```

### Common Configure Options
- `--disable-crypto-{nss,openssl,gcrypt}` - Disable specific crypto modules
- `--disable-compress-{zlib,lz4,lzo2,lzma,bzip2,zstd}` - Disable specific compression modules
- `--disable-libnozzle` - Disable libnozzle library
- `--enable-debug` - Enable debug build (disables optimization)
- `--enable-rust-bindings` - Enable Rust bindings
- `--enable-wireshark-dissector` - Enable Wireshark dissector plugin
- `--with-sanitizers=asan,ubsan,tsan` - Enable sanitizers for development

### Testing
```bash
# Run all tests
make check

# Run specific test categories
make check-memcheck        # Valgrind memory leak detection
make check-helgrind        # Valgrind thread analysis
make check-annocheck-libs  # Binary hardening verification
make check-covscan         # Coverity static analysis

# Run individual tests
cd libknet/tests
./api_knet_handle_new_test
```

Note: Functional tests (`fun_*`) can be disabled with `--disable-functional-tests` for slow architectures.

### Installing Tests
Use `--enable-install-tests` and `--with-testdir=/path` to install the test suite.

## Architecture

### libknet Core Components

**Threading Model** - libknet uses multiple specialized threads:
- `threads_rx.c` - Receives packets from the network
- `threads_tx.c` - Transmits packets to the network  
- `threads_heartbeat.c` - Manages ping/pong keepalives between nodes
- `threads_pmtud.c` - Path MTU Discovery
- `threads_dsthandler.c` - Handles packet forwarding decisions

**Transport Layer** - Pluggable transport backends:
- `transport_udp.c` - UDP transport (default)
- `transport_loopback.c` - Loopback for testing
- Transport operations defined in `transport_common.h`

**Crypto Modules** - Dynamically loaded via dlopen:
- `crypto_nss.c` - Mozilla NSS
- `crypto_openssl.c` - OpenSSL/LibreSSL
- `crypto_gcrypt.c` - libgcrypt
- See `crypto_model.h` for the plugin interface

**Compression Modules** - Dynamically loaded via dlopen:
- `compress_zlib.c`, `compress_lz4.c`, `compress_lzo2.c`, `compress_lzma.c`, `compress_bzip2.c`, `compress_zstd.c`
- See `compress_model.h` for the plugin interface

**On-Wire Protocol**:
- `onwire.c` / `onwire_v1.c` - Protocol version handling
- Supports protocol versioning with upgrade notifications
- Current API version: 2

**Access Control**:
- `links_acl.c` / `links_acl_ip.c` / `links_acl_loopback.c` - ACL implementation for controlling which nodes can connect

**Key Data Structures** (see `internals.h`):
- `knet_handle` - Main library handle
- `knet_host` - Per-node state including defragmentation buffers
- `knet_link` - Per-link state (up to 8 links between two hosts)
- Packet defragmentation uses `knet_host_defrag_buf` structures

### libnozzle

A simple library for managing tap devices, used by projects like Corosync. Key features:
- Cross-platform tap device creation (Linux, BSD, Solaris)
- Up/down script execution (pre-up.d, up.d, down.d, post-down.d)
- IP address and MAC address management

## Code Style

Follow the guidelines in `STYLE_GUIDE.md`:

- **C Standard**: C99 minimum
- **Indentation**: TABS (not spaces)
- **Naming**: 
  - Public API: `knet_*` or `nozzle_*` prefix
  - Public macros/enums: `KNET_*` or `NOZZLE_*` (uppercase)
  - Internal non-thread-safe functions: single underscore prefix (`_function_name`) - callers must provide locking
  - Variables and functions: `snake_case`
- **Line length**: Prefer 120 characters maximum
- **Braces**: Opening brace on same line for control flow, next line for functions
- **Always use braces** for if/for/while statements

### API Changes
Any modification to an internal or external API MUST be accompanied by new or updated tests.

## Platform-Specific Notes

**FreeBSD**:
- Requires `kern.ipc.maxsockbuf=18388608` in `/etc/sysctl.conf`
- Requires `if_tap.ko` kernel module for libnozzle

**Solaris/Illumos**:
- GNU tools must be in PATH first: `export PATH=/usr/gnu/bin:$PATH`
- Tune socket buffers: `ipadm set-prop -p max_buf=8388608 udp`

## Rust Bindings

Rust bindings are included in the source tree. While published to crates.io, the published versions are outdated (4+ years old) and do not reflect recent updates to the knet codebase:
- https://crates.io/crates/knet-bindings (outdated)
- https://crates.io/crates/nozzle-bindings (outdated)

For current bindings, build from source with `--enable-rust-bindings` (requires cargo, rustc, rustdoc, bindgen, clippy-driver).

## Development Workflow

1. Changes should maintain backward compatibility within major versions (1.x can talk to 1.x+n)
2. No onwire compatibility guarantee between major versions
3. Test suite must pass before merging
4. Binary hardening is enforced (annocheck) unless `--disable-hardening` is used
5. Valgrind testing is available but not required for all changes

## Important Files

- `libknet/libknet.h` - Public API definitions and constants
- `libknet/internals.h` - Internal data structures
- `libnozzle/libnozzle.h` - Nozzle public API
- `configure.ac` - Autoconf configuration
- `NOTES_TO_PACKAGE_MAINTAINERS` - Important packaging information
