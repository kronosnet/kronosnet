# Packaging Guidelines

Guidelines for creating distribution packages (RPM, DEB, etc.) for knetd.

## Package Structure

### Binary Package: knetd

**Binaries**:
- `/usr/sbin/knetd` - Main daemon
- `/usr/bin/knetctl` - CLI utility

**Systemd Units**:
- `/usr/lib/systemd/system/knetd.service` - Single instance service
- `/usr/lib/systemd/system/knetd@.service` - Template service for multiple instances

**Man Pages**:
- `/usr/share/man/man8/knetd.8.gz` - Daemon manual
- `/usr/share/man/man1/knetctl.1.gz` - CLI manual
- `/usr/share/man/man5/knetd.conf.5.gz` - Configuration manual

**Documentation**:
- `/usr/share/doc/knetd/README.md`
- `/usr/share/doc/knetd/INSTALLATION.md`
- `/usr/share/doc/knetd/NODE_AGNOSTIC_CONFIG.md`
- `/usr/share/doc/knetd/NOZZLE_UNIQUE_ADDRESSING.md`
- `/usr/share/doc/knetd/CLI_REFERENCE.md`
- `/usr/share/doc/knetd/CODE_TOUR.md`
- `/usr/share/doc/knetd/VISUALIZATION.md`
- `/usr/share/doc/knetd/LICENSE` (LGPL-2.1+)

**Example Configurations**:
- `/usr/share/doc/knetd/examples/knetd.toml.example`
- `/usr/share/doc/knetd/examples/knetd-fullmesh.toml.example`
- `/usr/share/doc/knetd/examples/knetd-nozzle-example.toml`

**Directories** (created on install):
- `/etc/knetd/` - Configuration directory
- `/var/lib/knetd/` - State persistence
- `/run/knetd/` - Runtime files (sockets)

## Dependencies

### Build Dependencies
- rust >= 1.70 or cargo
- libknet-devel >= 1.28
- libnozzle-devel >= 1.28
- pkg-config

### Runtime Dependencies
- libknet >= 1.28
- libnozzle >= 1.28
- systemd (for service management)

### Optional Runtime Dependencies
For crypto support (at least one):
- openssl-libs or nss or libgcrypt

For compression support (optional):
- zlib, lz4-libs, lzo, xz-libs, bzip2-libs, libzstd

## RPM Spec Example

```spec
Name:           knetd
Version:        0.1.0
Release:        1%{?dist}
Summary:        Kronosnet VPN daemon

License:        LGPL-2.1-or-later
URL:            https://github.com/kronosnet/kronosnet
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust-packaging
BuildRequires:  cargo
BuildRequires:  libknet-devel >= 1.28
BuildRequires:  libnozzle-devel >= 1.28
BuildRequires:  pkg-config
BuildRequires:  systemd-rpm-macros

Requires:       libknet >= 1.28
Requires:       libnozzle >= 1.28
Requires:       systemd

%description
knetd is a daemon for managing libknet VPN instances for high-availability
clustering. It provides multi-link fault-tolerant networking with encryption
and compression support.

%prep
%autosetup

%build
cargo build --release

%install
# Binaries
install -D -m 755 target/release/knetd %{buildroot}%{_sbindir}/knetd
install -D -m 755 target/release/knetctl %{buildroot}%{_bindir}/knetctl

# Systemd units
install -D -m 644 systemd/knetd.service %{buildroot}%{_unitdir}/knetd.service
install -D -m 644 systemd/knetd@.service %{buildroot}%{_unitdir}/knetd@.service

# Man pages
install -D -m 644 man/knetd.8 %{buildroot}%{_mandir}/man8/knetd.8
install -D -m 644 man/knetctl.1 %{buildroot}%{_mandir}/man1/knetctl.1
install -D -m 644 man/knetd.conf.5 %{buildroot}%{_mandir}/man5/knetd.conf.5

# Documentation
mkdir -p %{buildroot}%{_docdir}/%{name}
cp README.md INSTALLATION.md NODE_AGNOSTIC_CONFIG.md \\
   NOZZLE_UNIQUE_ADDRESSING.md CLI_REFERENCE.md CODE_TOUR.md \\
   VISUALIZATION.md %{buildroot}%{_docdir}/%{name}/

# Examples
mkdir -p %{buildroot}%{_docdir}/%{name}/examples
cp knetd/*.toml.example %{buildroot}%{_docdir}/%{name}/examples/

# Directories
mkdir -p %{buildroot}%{_sysconfdir}/knetd
mkdir -p %{buildroot}%{_sharedstatedir}/knetd
mkdir -p %{buildroot}%{_rundir}/knetd

%post
%systemd_post knetd.service

%preun
%systemd_preun knetd.service

%postun
%systemd_postun_with_restart knetd.service

%files
%license LICENSE
%doc %{_docdir}/%{name}/
%{_sbindir}/knetd
%{_bindir}/knetctl
%{_unitdir}/knetd.service
%{_unitdir}/knetd@.service
%{_mandir}/man8/knetd.8*
%{_mandir}/man1/knetctl.1*
%{_mandir}/man5/knetd.conf.5*
%dir %{_sysconfdir}/knetd
%dir %{_sharedstatedir}/knetd
%dir %{_rundir}/knetd

%changelog
* Wed Jun 25 2026 Kronosnet Team
- Initial package
```

## Debian Package Example

**debian/control**:
```
Source: knetd
Section: net
Priority: optional
Maintainer: Kronosnet Team <kronosnet@example.com>
Build-Depends: debhelper-compat (= 13),
               cargo,
               rustc (>= 1.70),
               libknet-dev (>= 1.28),
               libnozzle-dev (>= 1.28),
               pkg-config
Standards-Version: 4.6.0
Homepage: https://github.com/kronosnet/kronosnet

Package: knetd
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends},
         libknet1 (>= 1.28),
         libnozzle1 (>= 1.28),
         systemd
Description: Kronosnet VPN daemon
 knetd is a daemon for managing libknet VPN instances for high-availability
 clustering. It provides multi-link fault-tolerant networking with encryption
 and compression support.
```

**debian/rules**:
```makefile
#!/usr/bin/make -f

%:
\tdh $@

override_dh_auto_build:
\tcargo build --release

override_dh_auto_install:
\tinstall -D -m 755 target/release/knetd debian/knetd/usr/sbin/knetd
\tinstall -D -m 755 target/release/knetctl debian/knetd/usr/bin/knetctl
\tinstall -D -m 644 systemd/knetd.service debian/knetd/lib/systemd/system/knetd.service
\tinstall -D -m 644 systemd/knetd@.service debian/knetd/lib/systemd/system/knetd@.service
\t# Man pages, docs, etc.
```

## File Permissions

- Binaries: `0755 root:root`
- Systemd units: `0644 root:root`
- Man pages: `0644 root:root`
- Config directory: `0755 root:root`
- Config files (if installed): `0600 root:root` (may contain keys)
- State directory: `0700 root:root`
- Run directory: `0755 root:root`

## Configuration Defaults

### Default Paths
Packages should use system paths, not temporary paths:

```toml
socket_path = "/run/knetd/knetd.sock"
log_level = "info"
colored_logs = false
state_file = "/var/lib/knetd/state.json"
```

### Don't Install Default Config
Do NOT install a default `/etc/knetd/knetd.conf` - let users create their own
from examples. This prevents:
- Overwriting user configurations on upgrade
- Starting unwanted VPN instances automatically

## Post-Install Scripts

### RPM
```bash
%post
%systemd_post knetd.service

%preun
%systemd_preun knetd.service

%postun
%systemd_postun_with_restart knetd.service
```

### DEB
```bash
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    deb-systemd-helper enable knetd.service || true
    deb-systemd-invoke restart knetd.service || true
fi
```

## Distribution-Specific Notes

### Fedora/RHEL/CentOS
- Use `%{_sbindir}` for daemon
- Use `%{_bindir}` for CLI
- Use `%{_unitdir}` for systemd units
- Requires `rust-packaging` and `cargo`

### Debian/Ubuntu
- Use `/usr/sbin` for daemon
- Use `/usr/bin` for CLI
- Use `/lib/systemd/system` for units
- May need `cargo` from testing/backports

### Arch Linux
- PKGBUILD with `cargo build --release`
- Install to `/usr/bin` (no /usr/sbin on Arch)
- Use `systemd` package for units

## Testing Packages

### RPM
```bash
# Build
rpmbuild -ba knetd.spec

# Install
sudo rpm -ivh knetd-0.1.0-1.fc39.x86_64.rpm

# Test
sudo systemctl start knetd
knetctl ping

# Verify files
rpm -ql knetd
rpm -V knetd
```

### DEB
```bash
# Build
dpkg-buildpackage -b

# Install
sudo dpkg -i knetd_0.1.0_amd64.deb

# Test
sudo systemctl start knetd
knetctl ping

# Verify
dpkg -L knetd
```

## Cargo.toml Metadata

For packaging, include metadata in `Cargo.toml`:

```toml
[package]
name = "knetd"
version = "0.1.0"
authors = ["Kronosnet Team"]
edition = "2021"
license = "LGPL-2.1-or-later"
description = "Kronosnet VPN daemon for high-availability clustering"
homepage = "https://github.com/kronosnet/kronosnet"
repository = "https://github.com/kronosnet/kronosnet"
```

## Security Hardening

Packages should leverage systemd security features by default (already in service files):
- Capabilities: Only NET_ADMIN, NET_RAW, SYS_ADMIN
- Read-only root filesystem
- Private /tmp
- Restricted namespaces and address families

## Changelog Format

### RPM
```
* Wed Jun 25 2026 Kronosnet Team <kronosnet@example.com> - 0.1.0-1
- Initial release
- Full-mesh auto-configuration support
- Nozzle unique addressing
```

### DEB
```
knetd (0.1.0-1) unstable; urgency=low

  * Initial release
  * Full-mesh auto-configuration support
  * Nozzle unique addressing

 -- Kronosnet Team <kronosnet@example.com>  Wed, 25 Jun 2026 12:00:00 +0000
```

## Additional Notes

- Keep package names consistent: `knetd` (not `rust-knetd` or `kronosnet-daemon`)
- Separate `-devel` or `-dev` package is not needed (no C libraries exposed)
- Consider providing bash completion scripts in future versions
- SELinux policies should be in a separate `-selinux` subpackage if needed
