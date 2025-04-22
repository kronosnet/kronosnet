#
# Copyright (C) 2021-2025 Red Hat, Inc.  All rights reserved.
#
# Author: Christine Caulfield <ccaulfie@redhat.com>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk
include $(top_srcdir)/build-aux/rust.mk

EXTRA_DIST		= \
			  $(RUST_COMMON) \
			  $(RUST_SHIP_SRCS)

RUST_SHIP_SRCS		= src/bin/set_plugin_path.c \
			  src/bin/knet-test.rs

check_SCRIPTS		= target/$(RUST_TARGET_DIR)/knet-test

noinst_SCRIPTS		= $(check_SCRIPTS)

if INSTALL_TESTS
testsuitedir		= $(TESTDIR)
testsuite_SCRIPTS	= $(check_SCRIPTS)
endif

AM_TESTS_ENVIRONMENT=LD_LIBRARY_PATH="$(abs_top_builddir)/libknet/.libs"

TESTS			= $(check_SCRIPTS)

clean-local: cargo-clean
