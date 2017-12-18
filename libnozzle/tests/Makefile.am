#
# Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= tap_updown_bad tap_updown_good api-test-coverage

if BUILD_LIBNOZZLE

check_PROGRAMS		= nozzle_test

TESTS			= $(check_PROGRAMS)

noinst_PROGRAMS		= $(check_PROGRAMS)

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libnozzle/tests/api-test-coverage
	$(top_srcdir)/libnozzle/tests/api-test-coverage $(top_srcdir) $(top_builddir)

nozzle_test_SOURCES	= nozzle_test.c \
			  ../internals.c

nozzle_test_CPPFLAGS	= -I$(top_srcdir)/libnozzle \
			  -DABSBUILDDIR=\"$(abs_builddir)\"

nozzle_test_CFLAGS	= $(PTHREAD_CFLAGS)

nozzle_test_LDFLAGS	= $(top_builddir)/libnozzle/libnozzle.la \
			  $(PTHREAD_LIBS)

endif
