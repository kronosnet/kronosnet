#
# Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk
include $(top_srcdir)/libknet/tests/api-check.mk

EXTRA_DIST		= \
			  api-test-coverage \
			  api-check.mk

AM_CPPFLAGS		= -I$(top_srcdir)/libknet
AM_CFLAGS		+= $(PTHREAD_CFLAGS) $(libqb_CFLAGS) $(zlib_CFLAGS)
LIBS			= $(top_builddir)/libknet/libknet.la \
			  $(PTHREAD_LIBS) $(dl_LIBS) $(zlib_LIBS)

noinst_HEADERS		= \
			  test-common.h

# the order of those tests is NOT random.
# some functions can only be tested properly after some dependents
# API have been validated upfront.

check_PROGRAMS		= \
			  $(api_checks) \
			  $(int_checks)

if RUN_FUN_TESTS
check_PROGRAMS		+= $(fun_checks)
endif

int_checks		= \
			  int_links_acl_ip_test \
			  int_timediff_test

fun_checks		= \
			  fun_config_crypto_test \
			  fun_onwire_upgrade_test \
			  fun_acl_check_test

# checks below need to be executed manually
# or with a specific environment

long_run_checks		= \
			  fun_pmtud_crypto_test

benchmarks		= \
			  knet_bench_test

noinst_PROGRAMS		= \
			  api_knet_handle_new_limit_test \
			  pckt_test \
			  $(benchmarks) \
			  $(long_run_checks) \
			  $(api_checks) \
			  $(int_checks) \
			  $(fun_checks)

noinst_SCRIPTS		= \
			  api-test-coverage

TESTS			= $(check_PROGRAMS)

if INSTALL_TESTS
testsuitedir		= $(TESTDIR)
testsuite_PROGRAMS	= $(noinst_PROGRAMS)
endif

check-local: check-api-test-coverage check-annocheck-bins

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libknet/tests/api-test-coverage
	$(top_srcdir)/libknet/tests/api-test-coverage $(top_srcdir) $(top_builddir)

pckt_test_SOURCES	= pckt_test.c

int_links_acl_ip_test_SOURCES = int_links_acl_ip.c \
				../common.c \
				../compat.c \
				../logging.c \
				../netutils.c \
				../threads_common.c \
				../onwire.c \
				../transports.c \
				../transport_common.c \
				../transport_loopback.c \
				../transport_sctp.c \
				../transport_udp.c \
				../links_acl.c \
				../links_acl_ip.c \
				../links_acl_loopback.c \
				../lib_config.c

int_timediff_test_SOURCES = int_timediff.c

knet_bench_test_SOURCES	= knet_bench.c \
			  test-common.c \
			  ../common.c \
			  ../logging.c \
			  ../compat.c \
			  ../transport_common.c \
			  ../threads_common.c \
			  ../onwire.c \
			  ../lib_config.c

fun_pmtud_crypto_test_SOURCES = fun_pmtud_crypto.c \
				test-common.c \
				../onwire.c \
				../logging.c \
				../threads_common.c \
				../lib_config.c

fun_config_crypto_test_SOURCES = fun_config_crypto.c \
				 test-common.c

fun_onwire_upgrade_test_SOURCES = fun_onwire_upgrade.c \
				  test-common.c

fun_acl_check_test_SOURCES = fun_acl_check.c \
			     test-common.c
