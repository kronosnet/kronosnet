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

noinst_PROGRAMS	= doxyxml

doxyxml_SOURCES = doxyxml.c
doxyxml_CFLAGS = $(libqb_CFLAGS) $(libxml_CFLAGS)
doxyxml_LDADD = $(libqb_LIBS) $(libxml_LIBS)
