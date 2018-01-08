#
# Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

noinst_PROGRAMS		= nss_hash

nss_hash_SOURCES	= main.c

nss_hash_CFLAGS		= $(nss_CFLAGS)

nss_hash_LDFLAGS	= $(nss_LIBS)
