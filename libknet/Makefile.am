#
# Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
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

SUBDIRS			= . tests man

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
			  compress_lz4.h \
			  compress_lz4_remap.h \
			  compress_lzma.h \
			  compress_lzma_remap.h \
			  compress_lzo2.h \
			  compress_lzo2_remap.h \
			  compress_zlib.h \
			  compress_zlib_remap.h \
			  crypto.h \
			  crypto_nss.h \
			  crypto_nss_remap.h \
			  crypto_openssl.h \
			  crypto_openssl_remap.h \
			  host.h \
			  internals.h \
			  links.h \
			  logging.h \
			  netutils.h \
			  onwire.h \
			  remap.h \
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

libknet_la_CFLAGS	= $(PTHREAD_CFLAGS) \
			  $(nss_CFLAGS) $(openssl_CFLAGS) \
			  $(zlib_CFLAGS) $(liblz4_CFLAGS) $(lzo2_CFLAGS) $(liblzma_CFLAGS)

EXTRA_libknet_la_DEPENDENCIES	= $(SYMFILE)

libknet_la_LDFLAGS	= -Wl,--version-script=$(srcdir)/$(SYMFILE) \
			  --export-dynamic \
			  -Wl,-rpath=$(pkglibdir) \
			  -version-number $(libversion)

libknet_la_LIBADD	= $(PTHREAD_LIBS) $(dl_LIBS) $(rt_LIBS) $(m_LIBS)

# Prepare empty value for appending
pkglib_LTLIBRARIES	=

if BUILDCOMPBZIP2
pkglib_LTLIBRARIES	+= compress_bzip2.la
compress_bzip2_la_LDFLAGS = -module -avoid-version
compress_bzip2_la_CFLAGS = $(bzip2_CFLAGS)
compress_bzip2_la_LIBADD = $(bzip2_LIBS)
endif

noinst_PROGRAMS		= crypto_canary compress_canary
crypto_canary_SOURCES	= crypto_canary.c
crypto_canary_CFLAGS	= $(nss_CFLAGS) $(openssl_CFLAGS)
crypto_canary_LDADD	= $(nss_LIBS)   $(openssl_LIBS)
compress_canary_SOURCES	= compress_canary.c
compress_canary_CFLAGS	= $(zlib_CFLAGS) $(liblz4_CFLAGS) $(lzo2_CFLAGS) $(liblzma_CFLAGS)
compress_canary_LDADD	= $(zlib_LIBS)   $(liblz4_LIBS)   $(lzo2_LIBS)   $(liblzma_LIBS)

dist_man_MANS		= man

update-man-pages: doxyfile.stamp

doxyfile.stamp: Doxyfile
if MANPAGEUPDATES
	$(DOXYGEN) Doxyfile
	$(DOXY2MAN) -o $(abs_srcdir)/man -s 3 --short-pkg @PACKAGE_NAME@ --pkg "Kronosnet Programmer's Manual" $(builddir)/xml/libknet_8h.xml
else
	@echo this system does not have doxy2man or doxygen installed. Unable to update man pages automatically.
endif
	touch doxyfile.stamp

clean-local:
	rm -rf doxyfile.stamp xml
