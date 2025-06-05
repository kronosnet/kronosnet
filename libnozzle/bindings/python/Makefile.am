#
# Copyright (C) 2025 Red Hat, Inc.  All rights reserved.
#
# Author: Jules <jules@google.com> (Google AI Agent)
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES = Makefile.in

# Get CFLAGS and LIBS from python3-config or pkg-config (already handled in configure.ac)
AM_CFLAGS = $(PYTHON_CFLAGS) -I$(top_srcdir)/libnozzle
AM_LDFLAGS = $(PYTHON_LIBS)

# Define the Python extension module
# The library will be named _nozzle.so
# It will be built from _nozzle.c (which doesn't exist yet)
pkglib_LTLIBRARIES = _nozzle.la
_nozzle_la_SOURCES = _nozzle.c
_nozzle_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
_nozzle_la_CFLAGS = $(AM_CFLAGS)

# Ensure the .so file is installed in a way that Python can find it,
# typically within the package's directory structure or a site-packages directory.
# For now, we'll install it into pkglibdir, which might need adjustment later
# depending on the overall Python package structure.
# pkglibdir = $(libdir)/kronosnet/python (adjust as necessary)

# To make it discoverable by python, we might need a setup.py or similar,
# or ensure it's installed in a standard Python module path.
# This Makefile.am is just for building the .so.

# Files to be cleaned
CLEANFILES = *.lo *.la .libs/* _nozzle.so

# Tests
# Tell make where to find the tests and that they are python scripts
# The path is relative to this Makefile.am
TESTS = tests/test_nozzle.py

# Set up the environment for running the tests
# We need to ensure that the compiled Python extension (_nozzle.so) is findable.
# It's typically in .libs after compilation by libtool, or in the current directory.
# The $(top_builddir) variable points to the root of the build directory.
# The $(abs_top_builddir) gives an absolute path.
# The $(builddir) is the current directory where Makefile runs.
# The $(abs_builddir) is its absolute path.
# Our _nozzle.so will be in $(abs_builddir)/.libs or $(abs_builddir) after linking.
# The test script itself is in $(srcdir)/tests/test_nozzle.py
# We also need access to the source directory for the test script itself.
AM_TESTS_ENVIRONMENT = \
	LD_PRELOAD="$(top_builddir)/libnozzle/.libs/libnozzle.so" \
	PYTHONPATH="$(abs_builddir)/.libs:$(abs_builddir):$(PYTHONPATH)" \
	srcdir="$(abs_srcdir)" \
	PYTHON="$(PYTHON3)" # Ensure python3 is used if system python is older

# test_nozzle.py needs to be executable and have the correct shebang.
# We list it as a source to ensure it's part of the distribution.
EXTRA_DIST = tests/__init__.py tests/test_nozzle.py
