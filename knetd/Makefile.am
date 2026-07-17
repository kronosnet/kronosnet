#
# Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= \
			  Cargo.toml \
			  Cargo.lock \
			  knetd/Cargo.toml \
			  knetd/src \
			  knetctl/Cargo.toml \
			  knetctl/src \
			  knetd-common/Cargo.toml \
			  knetd-common/src \
			  knetd/knetd.toml.example \
			  knetd-multi-instance.toml.example \
			  man \
			  systemd \
			  tests/test_knetd.sh

if BUILD_KNETD

# Example config files
exampledir		= $(docdir)/examples
example_DATA		= \
			  knetd/knetd.toml.example \
			  knetd-multi-instance.toml.example

# systemd service files
# TODO: Add systemd detection to configure.ac and install these conditionally
# systemdsystemunit_DATA	= \
#			  systemd/knetd.service \
#			  systemd/knetd@.service

# Build targets
all-local: build-knetd-rust

build-knetd-rust:
	cd $(srcdir) && \
	RUSTFLAGS="-L $(abs_top_builddir)/libknet/.libs -L $(abs_top_builddir)/libnozzle/.libs" \
	$(CARGO) build $(RUST_FLAGS)

install-exec-local:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) $(srcdir)/target/$(RUST_TARGET_DIR)/knetd$(EXEEXT) $(DESTDIR)$(bindir)/knetd$(EXEEXT)
	$(INSTALL_PROGRAM) $(srcdir)/target/$(RUST_TARGET_DIR)/knetctl$(EXEEXT) $(DESTDIR)$(bindir)/knetctl$(EXEEXT)

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/knetd$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/knetctl$(EXEEXT)

clean-local:
	-$(CARGO) clean --manifest-path=$(srcdir)/Cargo.toml

check-local:
	KNETD_BIN="$(srcdir)/target/$(RUST_TARGET_DIR)/knetd" \
	KNETCTL_BIN="$(srcdir)/target/$(RUST_TARGET_DIR)/knetctl" \
	$(SHELL) $(srcdir)/tests/test_knetd.sh

endif
