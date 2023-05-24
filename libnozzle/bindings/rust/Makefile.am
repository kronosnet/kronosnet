#
# Copyright (C) 2021-2023 Red Hat, Inc.  All rights reserved.
#
# Author: Christine Caulfield <ccaulfie@redhat.com>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk
include $(top_srcdir)/build-aux/rust.mk

# required for make check
localver		= $(libnozzlerustver)

SUBDIRS			= . tests

EXTRA_DIST		= \
			  $(RUST_COMMON) \
			  $(RUST_SHIP_SRCS) \
			  README

RUST_SHIP_SRCS		= \
			  src/nozzle_bindings.rs \
			  src/lib.rs \
			  src/sys/mod.rs

RUST_BUILT_SRCS		= \
			  src/sys/libnozzle.rs

src/sys/libnozzle.rs: cargo-tree-prep ../../libnozzle.h
	$(top_srcdir)/build-aux/rust-regen.sh $(top_srcdir)/libnozzle/libnozzle.h $@ NOZZLE

all-local: target/$(RUST_TARGET_DIR)/nozzle_bindings.rlib

clean-local: cargo-clean
