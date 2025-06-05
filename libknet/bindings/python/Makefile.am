#
# Copyright (C) 2025 Red Hat, Inc.  All rights reserved.
#
# Author: Jules <jules@google.com> (Google AI Agent)
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES = Makefile.in

# Get CFLAGS and LIBS from python3-config or pkg-config (already handled in configure.ac)
AM_CFLAGS = $(PYTHON_CFLAGS) -I$(top_srcdir)/libknet
AM_LDFLAGS = $(PYTHON_LIBS)

# Define the Python extension module
# The library will be named _knet.so
# It will be built from _knet.c (which doesn't exist yet)
pkglib_LTLIBRARIES = _knet.la
_knet_la_SOURCES = _knet.c
_knet_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
_knet_la_CFLAGS = $(AM_CFLAGS)

# Ensure the .so file is installed in a way that Python can find it,
# typically within the package's directory structure or a site-packages directory.
# For now, we'll install it into pkglibdir, which might need adjustment later
# depending on the overall Python package structure.
# pkglibdir = $(libdir)/kronosnet/python (adjust as necessary)

# To make it discoverable by python, we might need a setup.py or similar,
# or ensure it's installed in a standard Python module path.
# This Makefile.am is just for building the .so.

# Files to be cleaned
CLEANFILES = *.lo *.la .libs/* _knet.so

# Tests
# Tell make where to find the tests and that they are python scripts
# The path is relative to this Makefile.am
TESTS = tests/test_knet.py

# Set up the environment for running the tests
# We need to ensure that the compiled Python extension (_knet.so) is findable.
# It's typically in .libs after compilation by libtool, or in the current directory.
AM_TESTS_ENVIRONMENT = \
	LD_PRELOAD="$(top_builddir)/libknet/.libs/libknet.so" \
	PYTHONPATH="$(abs_builddir)/.libs:$(abs_builddir):$(PYTHONPATH)" \
	srcdir="$(abs_srcdir)" \
	PYTHON="$(PYTHON3)" # Ensure python3 is used

# test_knet.py needs to be executable and have the correct shebang.
# We list test files as EXTRA_DIST to ensure they are included in source distributions.
EXTRA_DIST = tests/__init__.py tests/test_knet.py
