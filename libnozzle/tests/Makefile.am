#
# Copyright (C) 2017-2018 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= \
			  tap_updown_bad \
			  tap_updown_good \
			  api-test-coverage

noinst_HEADERS		= \
			  test-common.h

if BUILD_LIBNOZZLE

check_PROGRAMS		= \
			  api_nozzle_open_test \
			  api_nozzle_close_test \
			  api_nozzle_set_up_test \
			  api_nozzle_set_down_test \
			  api_nozzle_get_mtu_test \
			  api_nozzle_set_mtu_test \
			  api_nozzle_get_mac_test \
			  api_nozzle_set_mac_test \
			  api_nozzle_get_handle_by_name_test \
			  api_nozzle_get_name_by_handle_test \
			  api_nozzle_get_fd_test \
			  nozzle_test

noinst_PROGRAMS		= $(check_PROGRAMS)

noinst_SCRIPTS		= \
			  api-test-coverage

TESTS			= $(check_PROGRAMS)

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libnozzle/tests/api-test-coverage
	$(top_srcdir)/libnozzle/tests/api-test-coverage $(top_srcdir) $(top_builddir)

AM_CPPFLAGS		= -I$(top_srcdir)/libnozzle -DABSBUILDDIR=\"$(abs_builddir)\"
AM_CFLAGS		+= $(PTHREAD_CFLAGS) $(libnl_CFLAGS)
LIBS			+= $(top_builddir)/libnozzle/libnozzle.la $(PTHREAD_LIBS) $(libnl_LIBS)

api_nozzle_open_test_SOURCES = api_nozzle_open.c \
			       test-common.c

api_nozzle_close_test_SOURCES = api_nozzle_close.c \
				test-common.c

api_nozzle_set_up_test_SOURCES = api_nozzle_set_up.c \
				 test-common.c \
				 ../internals.c

api_nozzle_set_down_test_SOURCES = api_nozzle_set_down.c \
				   test-common.c \
				   ../internals.c

api_nozzle_get_mtu_test_SOURCES = api_nozzle_get_mtu.c \
				  test-common.c

api_nozzle_set_mtu_test_SOURCES = api_nozzle_set_mtu.c \
				  test-common.c \
				  ../internals.c

api_nozzle_get_mac_test_SOURCES = api_nozzle_get_mac.c \
				  test-common.c

api_nozzle_set_mac_test_SOURCES = api_nozzle_set_mac.c \
				  test-common.c

api_nozzle_get_handle_by_name_test_SOURCES = api_nozzle_get_handle_by_name.c \
					     test-common.c

api_nozzle_get_name_by_handle_test_SOURCES = api_nozzle_get_name_by_handle.c \
					     test-common.c

api_nozzle_get_fd_test_SOURCES = api_nozzle_get_fd.c \
				 test-common.c

nozzle_test_SOURCES	= nozzle_test.c \
			  test-common.c \
			  ../internals.c

endif
