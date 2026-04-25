#
# Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES		= Makefile.in

include $(top_srcdir)/build-aux/check.mk

noinst_HEADERS			= packet-kronosnet.h

wsdissectorlibdir		= $(wireshark_INSTALL_PREFIX)/$(wireshark_PLUGINDIR)/epan

wsdissectorlib_LTLIBRARIES	= kronosnet.la

# override global LIBS that pulls in lots of craft we don't need here
LIBS				=

kronosnet_la_SOURCES		= \
				  packet-kronosnet.c \
				  ../handle.c \
				  ../compress.c \
				  ../crypto.c \
				  ../lib_config.c \
				  ../common.c \
				  ../logging.c \
				  ../threads_common.c
kronosnet_la_CFLAGS		= $(wireshark_CFLAGS) -DPLUGINPATH="\"$(pkglibdir)\"" -DWIRESHARK_BUILD=1
kronosnet_la_LDFLAGS		= -module -avoid-version -export-dynamic
kronosnet_la_LIBADD		= $(wireshark_LIBS)
