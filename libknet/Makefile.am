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

libversion		= 1:0:0

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

sources			= \
			  common.c \
			  compat.c \
			  compress.c \
			  compress_zlib.c \
			  compress_lz4.c \
			  compress_lzo2.c \
			  compress_lzma.c \
			  compress_bzip2.c \
			  crypto.c \
			  crypto_nss.c \
			  crypto_openssl.c \
			  handle.c \
			  host.c \
			  links.c \
			  logging.c \
			  netutils.c \
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
			  compress.h \
			  compress_zlib.h \
			  compress_lz4.h \
			  compress_lzo2.h \
			  compress_lzma.h \
			  compress_bzip2.h \
			  crypto.h \
			  crypto_nss.h \
			  crypto_openssl.h \
			  host.h \
			  internals.h \
			  links.h \
			  logging.h \
			  netutils.h \
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

libknet_la_CFLAGS	= $(nss_CFLAGS) $(openssl_CFLAGS) \
			  $(zlib_CFLAGS) $(liblz4_CFLAGS) $(lzo2_CFLAGS) $(liblzma_CFLAGS) $(bzip2_CFLAGS)

EXTRA_libknet_la_DEPENDENCIES	= $(SYMFILE)

libknet_la_LDFLAGS	= -Wl,--version-script=$(srcdir)/$(SYMFILE) \
			  --export-dynamic \
			  -version-number $(libversion)

libknet_la_LIBADD	= $(dl_LIBS) $(pthread_LIBS) $(rt_LIBS) $(m_LIBS) $(openssl_LIBS)
