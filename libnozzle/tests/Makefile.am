#
# Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= \
			  nozzle_run_updown_exit_true \
			  nozzle_run_updown_exit_false \
			  api-test-coverage

noinst_HEADERS		= \
			  test-common.h

if BUILD_LIBNOZZLE

api_checks		= \
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
			  api_nozzle_run_updown_test \
			  api_nozzle_add_ip_test \
			  api_nozzle_del_ip_test \
			  api_nozzle_get_ips_test

int_checks		= \
			  int_execute_bin_sh_command_test

fun_checks		=

benchmarks		=

check_PROGRAMS		= \
			  $(api_checks) \
			  $(int_checks) \
			  $(fun_checks)

noinst_PROGRAMS		= \
			  $(benchmarks) \
			  $(check_PROGRAMS)

noinst_SCRIPTS		= \
			  api-test-coverage

TESTS			= $(check_PROGRAMS)

if INSTALL_TESTS
testsuitedir		= $(TESTDIR)
testsuite_PROGRAMS	= $(noinst_PROGRAMS)
endif

check-local: check-api-test-coverage check-annocheck-bins

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libnozzle/tests/api-test-coverage
	$(top_srcdir)/libnozzle/tests/api-test-coverage $(top_srcdir) $(top_builddir)

AM_CPPFLAGS		= -I$(top_srcdir)/libnozzle -DABSBUILDDIR=\"$(abs_builddir)\" -DABSSRCDIR=\"$(abs_srcdir)\"
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

api_nozzle_run_updown_test_SOURCES = api_nozzle_run_updown.c \
				     test-common.c \
				     ../internals.c

api_nozzle_add_ip_test_SOURCES = api_nozzle_add_ip.c \
				 test-common.c \
				 ../internals.c

api_nozzle_del_ip_test_SOURCES = api_nozzle_del_ip.c \
				 test-common.c \
				 ../internals.c

api_nozzle_get_ips_test_SOURCES = api_nozzle_get_ips.c \
				  test-common.c

int_execute_bin_sh_command_test_SOURCES = int_execute_bin_sh_command.c \
					  test-common.c \
					  ../internals.c
endif
