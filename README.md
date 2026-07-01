# Kronosnet

> Copyright (C) 2010-2026 Red Hat, Inc. All rights reserved.
>
> Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
>
> This software licensed under GPL-2.0+

## Upstream Resources

- **Website**: https://kronosnet.org/
- **GitHub**: https://github.com/kronosnet/kronosnet/
- **CI/CD**: https://ci.kronosnet.org/
- **Project Board**: https://projects.clusterlabs.org/project/board/86/
- **Documentation**: https://drive.google.com/drive/folders/0B_zxAPgZTkM_TklfYzN6a2FYUFE?resourcekey=0-Cfr5D94rZ8LVbeMPGjxbdg&usp=sharing
- **IRC**: #kronosnet on Libera.Chat

### Mailing Lists

- [Users](https://lists.kronosnet.org/mailman3/postorius/lists/users.lists.kronosnet.org/)
- [Developers](https://lists.kronosnet.org/mailman3/postorius/lists/devel.lists.kronosnet.org/)
- [Commits and CI Notifications](https://lists.kronosnet.org/mailman3/postorius/lists/commits.lists.kronosnet.org/)

## Architecture

Please refer to the [Google Drive Presentations](https://drive.google.com/drive/folders/0B_zxAPgZTkM_TklfYzN6a2FYUFE?resourcekey=0-Cfr5D94rZ8LVbeMPGjxbdg&usp=sharing) directory for diagrams and fancy schemas.

## Dependencies

Kronosnet has few obligatory dependencies, though it is strongly recommended that you build it with at least one crypto library enabled.

It does, however, require **libqb** for both the `doxygen2man` tool (for creating the API man pages) and headers for list manipulation. You can get these from installing libqb from source or the `libqb-devel` package. Your distro might provide `doxygen2man` as its own package.

## Platform-Specific Notes

### Running on FreeBSD

Knet requires big socket buffers. Add the following to `/etc/sysctl.conf`:

```
kern.ipc.maxsockbuf=18388608
net.local.dgram.maxdgram=131072
```

**Note**: Knet will fail to run without these settings.

**libnozzle** requires `if_tap.ko` loaded in the kernel.

**Important**: Avoid using `ifconfig_DEFAULT` in `/etc/rc.conf` to use DHCP for all interfaces, as the dhclient will interfere with libnozzle interface management, causing errors on operations such as `ifconfig tap down`.

### Building on Solaris / Illumos

Tested on **SunOS 5.11 (OpenIndiana)**

**Note**: gcc-14 and clang-20 are minimum supported versions

#### Install Dependencies

```bash
pkg install autoconf automake libtool pkg-config \
    gcc-14 gnu-binutils gnu-coreutils gnu-make check \
    system/mozilla-nss system/library/mozilla-nss \
    system/library/mozilla-nss/header-nss doxygen \
    header-tun tun
```

#### Optional Packages

```bash
pkg install developer/clang-20
```

#### Build Instructions

GNU tools must be preferred:

```bash
export PATH=/usr/gnu/bin:$PATH
./autogen.sh && ./configure
make all -j && make check -j
```

### Running on Solaris / Illumos

#### Tune Socket Buffers

Tune socket buffers for the protocol you intend to use:

```bash
ipadm set-prop -p max_buf=8388608 udp
```

#### Enable Large Datagram Support

For `KNET_DATAFD_FLAG_RX_RETURN_INFO` support (datagrams >64KB), add to `/etc/system` and reboot:

```
set strmsgsz=131072
```

This increases the TL (loopback transport) TIDU size for Unix domain sockets.

## Rust Bindings

Rust bindings for libknet and libnozzle are part of this source tree, but are included here mainly to keep all of the kronosnet APIs in one place and to ensure that everything is kept up-to-date and properly tested in our CI system.

The correct place to get the Rust crates for libknet and libnozzle is still **crates.io** as it would be for other crates. These will be updated when we issue a new release of knet.

- https://crates.io/crates/knet-bindings
- https://crates.io/crates/nozzle-bindings

Of course, if you want to try any new features in the APIs that may have not yet been released then you can try these sources, but please keep in touch with us via email or IRC if you do so.
