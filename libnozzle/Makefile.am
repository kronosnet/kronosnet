#
# Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

SYMFILE			= libnozzle_exported_syms

EXTRA_DIST		= $(SYMFILE)

if BUILD_LIBNOZZLE

SUBDIRS			= . tests bindings

sources			= libnozzle.c \
			  internals.c

include_HEADERS		= libnozzle.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libnozzle.pc

noinst_HEADERS		= \
			  internals.h

lib_LTLIBRARIES		= libnozzle.la

libnozzle_la_SOURCES	= $(sources)

libnozzle_la_CFLAGS	= $(AM_CFLAGS) $(PTHREAD_CFLAGS) $(libnl_CFLAGS) $(libnlroute_CFLAGS)

EXTRA_libnozzle_la_DEPENDENCIES	= $(SYMFILE)

libnozzle_la_LDFLAGS	= $(AM_LDFLAGS) \
			  -Wl,-version-script,$(srcdir)/$(SYMFILE) \
			  -version-info $(libnozzleversion)

libnozzle_la_LIBADD	= $(PTHREAD_LIBS) $(libnl_LIBS) $(libnlroute_LIBS)

check-local: check-annocheck-libs

endif
