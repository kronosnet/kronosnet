#
# Copyright (C) 2021 Red Hat, Inc.  All rights reserved.
#
# Author: Christine Caulfield <ccaulfie@redhat.com>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk
include $(top_srcdir)/build-aux/rust.mk

# required for make check
localver		= $(libknetrustver)

SUBDIRS			= . tests

EXTRA_DIST		= \
			  $(RUST_COMMON) \
			  $(RUST_SHIP_SRCS) \
			  README

RUST_SHIP_SRCS		= \
			  src/knet_bindings.rs \
			  src/lib.rs \
			  src/sys/mod.rs

RUST_BUILT_SRCS		= \
			  src/sys/libknet.rs

src/sys/libknet.rs: ../../libknet.h
	$(top_srcdir)/build-aux/rust-regen.sh $^ $@ KNET

all-local: cargo-tree-prep target/$(RUST_TARGET_DIR)/knet_bindings.rlib

clean-local: cargo-clean
