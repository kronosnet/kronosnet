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

SUBDIRS			= . tests

libversion		= 0:0:0

sources			= \
			  common.c \
			  crypto.c \
			  handle.c \
			  host.c \
			  listener.c \
			  link.c \
			  logging.c \
			  nsscrypto.c \
			  threads_dsthandler.c \
			  threads_heartbeat.c \
			  threads_pmtud.c \
			  threads_send_recv.c

include_HEADERS		= libknet.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libknet.pc

noinst_HEADERS		= \
			  common.h \
			  crypto.h \
			  host.h \
			  internals.h \
			  link.h \
			  listener.h \
			  logging.h \
			  nsscrypto.h \
			  onwire.h \
			  threads_common.h \
			  threads_dsthandler.h \
			  threads_heartbeat.h \
			  threads_pmtud.h \
			  threads_send_recv.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)

libknet_la_LIBS		= -version-info $(libversion)
libknet_la_CFLAGS	= $(nss_CFLAGS)
libknet_la_LIBADD	= $(nss_LIBS) -lrt -lpthread -lm
