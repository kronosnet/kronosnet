#
# Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

LIBS			= -lpthread \
			  -version-info $(libversion)

libversion		= 0:0:0

sources			= \
			  common.c \
			  handle.c \
			  host.c \
			  listener.c \
			  crypto.c \
			  nsscrypto.c

include_HEADERS		= libknet.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libknet.pc

noinst_HEADERS		= libknet-private.h \
			  crypto.h \
			  nsscrypto.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)

libknet_la_CFLAGS	= $(nss_CFLAGS)
libknet_la_LIBADD	= $(nss_LIBS) -lrt
