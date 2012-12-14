#
# Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

EXTRA_DIST		= libtap_exported_sym tap_updown_bad tap_updown_good

include $(top_srcdir)/build-aux/check.mk

sources			= libtap.c

libversion		= 0:0:0

# override global LIBS that pulls in lots of craft we don't need here
LIBS			= -lpthread

include_HEADERS		= libtap.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= $(sources)

libtap_la_LDFLAGS	= -Wl,-version-script,$(srcdir)/libtap_exported_sym \
			  --export-dynamic \
			  -version-number $(libversion)

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check_PROGRAMS		= tap_test

tap_test_SOURCES	= $(sources)

tap_test_CPPFLAGS	= -DTEST \
			  -DABSBUILDDIR=\"$(abs_builddir)\"
