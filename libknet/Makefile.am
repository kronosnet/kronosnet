#
# Copyright (C) 2010-2019 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

SYMFILE			= libknet_exported_syms

EXTRA_DIST		= $(SYMFILE)

SUBDIRS			= . tests

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libversion		= 3:0:2

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

sources			= \
			  common.c \
			  compat.c \
			  compress.c \
			  crypto.c \
			  handle.c \
			  host.c \
			  links.c \
			  links_acl.c \
			  links_acl_ip.c \
			  links_acl_loopback.c \
			  logging.c \
			  netutils.c \
			  onwire.c \
			  threads_common.c \
			  threads_dsthandler.c \
			  threads_heartbeat.c \
			  threads_pmtud.c \
			  threads_rx.c \
			  threads_tx.c \
			  transports.c \
			  transport_common.c \
			  transport_loopback.c \
			  transport_udp.c \
			  transport_sctp.c

include_HEADERS		= libknet.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libknet.pc

noinst_HEADERS		= \
			  common.h \
			  compat.h \
			  compress.h \
			  compress_model.h \
			  crypto.h \
			  crypto_model.h \
			  host.h \
			  internals.h \
			  links.h \
			  links_acl.h \
			  links_acl_ip.h \
			  links_acl_loopback.h \
			  logging.h \
			  netutils.h \
			  onwire.h \
			  threads_common.h \
			  threads_dsthandler.h \
			  threads_heartbeat.h \
			  threads_pmtud.h \
			  threads_rx.h \
			  threads_tx.h \
			  transports.h \
			  transport_common.h \
			  transport_loopback.h \
			  transport_udp.h \
			  transport_sctp.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)

libknet_la_CFLAGS	= $(AM_CFLAGS) $(PTHREAD_CFLAGS)

EXTRA_libknet_la_DEPENDENCIES	= $(SYMFILE)

libknet_la_LDFLAGS	= $(AM_LDFLAGS) \
			  -Wl,--version-script=$(srcdir)/$(SYMFILE) \
			  -Wl,-rpath=$(pkglibdir) \
			  -version-info $(libversion)

libknet_la_LIBADD	= $(PTHREAD_LIBS) $(dl_LIBS) $(rt_LIBS) $(m_LIBS)

# Prepare empty value for appending
pkglib_LTLIBRARIES	=

# MODULE_LDFLAGS would mean a target-specific variable for Automake
MODULELDFLAGS		= $(AM_LDFLAGS) -module -avoid-version -export-dynamic

if BUILD_COMPRESS_ZSTD
pkglib_LTLIBRARIES	+= compress_zstd.la
compress_zstd_la_LDFLAGS = $(MODULELDFLAGS)
compress_zstd_la_CFLAGS	= $(AM_CFLAGS) $(libzstd_CFLAGS)
compress_zstd_la_LIBADD	= $(libzstd_LIBS)
endif

if BUILD_COMPRESS_ZLIB
pkglib_LTLIBRARIES	+= compress_zlib.la
compress_zlib_la_LDFLAGS = $(MODULELDFLAGS)
compress_zlib_la_CFLAGS	= $(AM_CFLAGS) $(zlib_CFLAGS)
compress_zlib_la_LIBADD	= $(zlib_LIBS)
endif

if BUILD_COMPRESS_LZ4
pkglib_LTLIBRARIES	+= compress_lz4.la compress_lz4hc.la
compress_lz4_la_LDFLAGS	= $(MODULELDFLAGS)
compress_lz4_la_CFLAGS	= $(AM_CFLAGS) $(liblz4_CFLAGS)
compress_lz4_la_LIBADD	= $(liblz4_LIBS)
compress_lz4hc_la_LDFLAGS = $(MODULELDFLAGS)
compress_lz4hc_la_CFLAGS = $(AM_CFLAGS) $(liblz4_CFLAGS)
compress_lz4hc_la_LIBADD = $(liblz4_LIBS)
endif

if BUILD_COMPRESS_LZO2
pkglib_LTLIBRARIES	+= compress_lzo2.la
compress_lzo2_la_LDFLAGS = $(MODULELDFLAGS)
compress_lzo2_la_CFLAGS	= $(AM_CFLAGS) $(lzo2_CFLAGS)
compress_lzo2_la_LIBADD	= $(lzo2_LIBS)
endif

if BUILD_COMPRESS_LZMA
pkglib_LTLIBRARIES	+= compress_lzma.la
compress_lzma_la_LDFLAGS = $(MODULELDFLAGS)
compress_lzma_la_CFLAGS	= $(AM_CFLAGS) $(liblzma_CFLAGS)
compress_lzma_la_LIBADD	= $(liblzma_LIBS)
endif

if BUILD_COMPRESS_BZIP2
pkglib_LTLIBRARIES	+= compress_bzip2.la
compress_bzip2_la_LDFLAGS = $(MODULELDFLAGS)
compress_bzip2_la_CFLAGS = $(AM_CFLAGS) $(bzip2_CFLAGS)
compress_bzip2_la_LIBADD = $(bzip2_LIBS)
endif

if BUILD_CRYPTO_NSS
pkglib_LTLIBRARIES	+= crypto_nss.la
crypto_nss_la_LDFLAGS	= $(MODULELDFLAGS)
crypto_nss_la_CFLAGS	= $(AM_CFLAGS) $(nss_CFLAGS)
crypto_nss_la_LIBADD	= $(nss_LIBS)
endif

if BUILD_CRYPTO_OPENSSL
pkglib_LTLIBRARIES	+= crypto_openssl.la
crypto_openssl_la_LDFLAGS = $(MODULELDFLAGS)
crypto_openssl_la_CFLAGS = $(AM_CFLAGS) $(openssl_CFLAGS)
crypto_openssl_la_LIBADD = $(openssl_LIBS)
endif
