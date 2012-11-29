#
# Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --track-fds=yes --leak-check=full
HELGRIND = valgrind -v --tool=helgrind

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check-helgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(HELGRIND)" check

noinst_PROGRAMS = \
		  ping_test \
		  khandle_test \
		  lookup_bench \
		  $(check_PROGRAMS)

check_PROGRAMS = \
		  netutils_test \
		  timediff_test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS		= -DTEST \
			  -I$(srcdir)/../libtap/ \
			  -I$(srcdir)/../libknet/ \
			  -I$(srcdir)/../kronosnetd/

AM_LDFLAGS		= \
			  $(top_builddir)/libtap/libtap.la \
			  $(top_builddir)/libknet/libknet.la 

ping_test_SOURCES	= ping_test.c

khandle_test_SOURCES	= khandle_test.c

lookup_bench_SOURCES	= lookup_bench.c \
			  $(srcdir)/../kronosnetd/netutils.c

netutils_test_SOURCES	= netutils_test.c \
			  $(srcdir)/../kronosnetd/netutils.c

timediff_test_SOURCES	= timediff_test.c
