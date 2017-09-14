#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk


SYMFILE			= libtap_exported_syms

EXTRA_DIST		= $(SYMFILE) tap_updown_bad tap_updown_good api-test-coverage

sources			= libtap.c

libversion		= 1:0:0

# override global LIBS that pulls in lots of craft we don't need here
LIBS			= $(pthread_LIBS)

if BUILD_LIBTAP

include_HEADERS		= libtap.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= $(sources)

EXTRA_libtap_la_DEPENDENCIES	= $(SYMFILE)

libtap_la_LDFLAGS	= -Wl,-version-script,$(srcdir)/$(SYMFILE) \
			  --export-dynamic \
			  -version-number $(libversion)

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check_PROGRAMS		= tap_test

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libtap/api-test-coverage
	$(top_srcdir)/libtap/api-test-coverage $(top_srcdir) $(top_builddir)

tap_test_SOURCES	= $(sources)

tap_test_CPPFLAGS	= -DTEST \
			  -DABSBUILDDIR=\"$(abs_builddir)\"

endif
