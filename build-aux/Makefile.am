#
# Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST	= check.mk gitlog-to-changelog git-version-gen \
		  knet_valgrind_helgrind.supp knet_valgrind_memcheck.supp \
		  release.mk update-copyright.sh

# Avoid Automake warnings about overriding these user variables.
# Programs in this directory are used during the build only.
AUTOMAKE_OPTIONS = -Wno-gnu
EXEEXT=$(BUILD_EXEEXT)
CC=$(CC_FOR_BUILD)
CFLAGS=$(CFLAGS_FOR_BUILD)
CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
LDFLAGS=$(LDFLAGS_FOR_BUILD)

noinst_PROGRAMS	= doxyxml

doxyxml_SOURCES = doxyxml.c
doxyxml_CFLAGS = $(AM_CFLAGS) $(libqb_BUILD_CFLAGS) $(libxml_BUILD_CFLAGS)
doxyxml_LDADD = $(libqb_BUILD_LIBS) $(libxml_BUILD_LIBS)
