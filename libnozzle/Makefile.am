#
# Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk


SYMFILE			= libnozzle_exported_syms

EXTRA_DIST		= $(SYMFILE) tap_updown_bad tap_updown_good api-test-coverage

sources			= libnozzle.c

libversion		= 1:0:0

AM_CFLAGS		+= $(PTHREAD_CFLAGS)
LIBS			= $(PTHREAD_LIBS)

if BUILD_LIBNOZZLE

include_HEADERS		= libnozzle.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libnozzle.pc

lib_LTLIBRARIES		= libnozzle.la

libnozzle_la_SOURCES	= $(sources)

EXTRA_libnozzle_la_DEPENDENCIES	= $(SYMFILE)

libnozzle_la_LDFLAGS	= $(AM_LDFLAGS) \
			  -Wl,-version-script,$(srcdir)/$(SYMFILE) \
			  -version-info $(libversion)

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check_PROGRAMS		= nozzle_test

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libnozzle/api-test-coverage
	$(top_srcdir)/libnozzle/api-test-coverage $(top_srcdir) $(top_builddir)

nozzle_test_SOURCES	= $(sources)

nozzle_test_CPPFLAGS	= -DTEST \
			  -DABSBUILDDIR=\"$(abs_builddir)\"

endif
