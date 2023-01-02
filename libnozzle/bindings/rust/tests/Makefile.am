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

EXTRA_DIST		= \
			  $(RUST_COMMON) \
			  $(RUST_SHIP_SRCS)

RUST_SHIP_SRCS		= src/bin/nozzle-test.rs

check_SCRIPTS		= target/$(RUST_TARGET_DIR)/nozzle-test

noinst_SCRIPTS		= $(check_SCRIPTS)

if INSTALL_TESTS
testsuitedir		= $(TESTDIR)
testsuite_SCRIPTS	= $(check_SCRIPTS)
endif

AM_TESTS_ENVIRONMENT=LD_LIBRARY_PATH="$(abs_top_builddir)/libnozzle/.libs"

TESTS			= $(check_SCRIPTS)

clean-local: cargo-clean
