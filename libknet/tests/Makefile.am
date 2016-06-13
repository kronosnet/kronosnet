#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

AM_CPPFLAGS		= -I$(top_srcdir)/libknet
LDADD			= $(top_builddir)/libknet/libknet.la

noinst_HEADERS		= \
			  test-common.h

check_PROGRAMS		= timediff_test

noinst_PROGRAMS		= \
			  pckt_test \
			  ping_test \
			  khandle_test \
			  $(check_PROGRAMS)

TESTS			= $(check_PROGRAMS)

ping_test_SOURCES	= ping_test.c

khandle_test_SOURCES	= khandle_test.c

pckt_test_SOURCES	= pckt_test.c

timediff_test_SOURCES	= timediff_test.c
