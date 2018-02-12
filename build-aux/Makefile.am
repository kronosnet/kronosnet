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

EXEEXT=$(BUILD_EXEEXT)

noinst_PROGRAMS	= doxyxml

$(doxyxml_OBJECTS) : CC=$(CC_FOR_BUILD)
$(doxyxml_OBJECTS) : CFLAGS=$(CFLAGS_FOR_BUILD)
$(doxyxml_OBJECTS) : CPPFLAGS=$(CPPFLAGS_FOR_BUILD)

doxyxml_SOURCES = doxyxml.c
doxyxml_CFLAGS = $(AM_CFLAGS) $(libqb_BUILD_CFLAGS) $(libxml_BUILD_CFLAGS)
doxyxml_LDADD = $(libqb_BUILD_LIBS) $(libxml_BUILD_LIBS)
doxyxml_LINK = $(CC_FOR_BUILD) $(doxyxml_CFLAGS) $(CFLAGS_FOR_BUILD) $(AM_LDFLAGS) $(LDFLAGS_FOR_BUILD) -o $@
