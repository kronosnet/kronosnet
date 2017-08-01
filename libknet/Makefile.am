#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

SYMFILE			= libknet_exported_syms

EXTRA_DIST		= $(SYMFILE)

SUBDIRS			= . tests

libversion		= 0:0:0

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

sources			= \
			  common.c \
			  compat.c \
			  crypto.c \
			  handle.c \
			  host.c \
			  link.c \
			  logging.c \
			  netutils.c \
			  nsscrypto.c \
			  threads_common.c \
			  threads_dsthandler.c \
			  threads_heartbeat.c \
			  threads_pmtud.c \
			  threads_rx.c \
			  threads_tx.c \
			  transport_udp.c \
			  transport_sctp.c \
			  transport_loopback.c \
			  transport_common.c

include_HEADERS		= libknet.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libknet.pc

noinst_HEADERS		= \
			  common.h \
			  compat.h \
			  crypto.h \
			  host.h \
			  internals.h \
			  link.h \
			  logging.h \
			  netutils.h \
			  nsscrypto.h \
			  onwire.h \
			  threads_common.h \
			  threads_dsthandler.h \
			  threads_heartbeat.h \
			  threads_pmtud.h \
			  threads_rx.h \
			  threads_tx.h \
			  transports.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)

libknet_la_CFLAGS	= $(nss_CFLAGS)

EXTRA_libknet_la_DEPENDENCIES	= $(SYMFILE)

libknet_la_LDFLAGS	= -Wl,--version-script=$(srcdir)/$(SYMFILE) \
			  --export-dynamic \
			  -version-number $(libversion)

libknet_la_LIBADD	= $(nss_LIBS) -lrt -lpthread -lm
