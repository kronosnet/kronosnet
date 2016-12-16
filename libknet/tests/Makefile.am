#
# Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk
include $(top_srcdir)/libknet/tests/api-check.mk

EXTRA_DIST		= \
			  api-test-coverage \
			  api-check.mk

AM_CPPFLAGS		= -I$(top_srcdir)/libknet \
			  -I$(top_srcdir)/common

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

LDADD			= $(top_builddir)/libknet/libknet.la

noinst_HEADERS		= \
			  test-common.h

# the order of those tests is NOT random.
# some functions can only be tested properly after some dependents
# API have been validated upfront.

check_PROGRAMS		= \
			  $(api_checks) \
			  $(int_checks) \
			  $(fun_checks)

int_checks		= \
			  int_timediff_test \
			  int_crypto_test

fun_checks		=

benchmarks		= \
			  crypto_bench_test \
			  knet_bench_test

noinst_PROGRAMS		= \
			  pckt_test \
			  ping_test \
			  $(benchmarks) \
			  $(check_PROGRAMS)

noinst_SCRIPTS		= \
			  api-test-coverage

TESTS			= $(check_PROGRAMS)

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libknet/tests/api-test-coverage
	$(top_srcdir)/libknet/tests/api-test-coverage $(top_srcdir) $(top_builddir)

ping_test_SOURCES	= ping_test.c

pckt_test_SOURCES	= pckt_test.c

int_timediff_test_SOURCES = int_timediff.c

int_crypto_test_SOURCES = int_crypto.c \
			  ../crypto.c \
			  ../nsscrypto.c \
			  ../logging.c \
			  test-common.c

int_crypto_test_CFLAGS	= $(nss_CFLAGS)

int_crypto_test_LDFLAGS = $(nss_LIBS)

crypto_bench_test_SOURCES = crypto_bench.c \
			    ../crypto.c \
			    ../nsscrypto.c \
			    ../logging.c \
			    test-common.c

crypto_bench_test_CFLAGS  = $(nss_CFLAGS)

crypto_bench_test_LDFLAGS = $(nss_LIBS)

knet_bench_test_SOURCES	= knet_bench.c \
			  ../../common/netutils.c \
			  test-common.c
