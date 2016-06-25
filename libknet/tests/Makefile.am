#
# Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= api-test-coverage

AM_CPPFLAGS		= -I$(top_srcdir)/libknet \
			  -I$(top_srcdir)/common

LDADD			= $(top_builddir)/libknet/libknet.la

noinst_HEADERS		= \
			  test-common.h

# the order of those tests is NOT random.
# some functions can only be tested properly after some dependents
# API have been validated upfront.

check_PROGRAMS		= \
			  api_knet_handle_new \
			  api_knet_handle_free \
			  api_knet_host_add \
			  api_knet_host_remove \
			  api_knet_host_set_name \
			  api_knet_host_get_name_by_host_id \
			  api_knet_host_get_id_by_host_name \
			  api_knet_host_get_host_list \
			  api_knet_host_set_policy \
			  api_knet_host_get_policy \
			  api_knet_log_get_subsystem_name \
			  api_knet_log_get_subsystem_id \
			  api_knet_log_get_loglevel_name \
			  api_knet_log_get_loglevel_id \
			  timediff_test

noinst_PROGRAMS		= \
			  pckt_test \
			  ping_test \
			  $(check_PROGRAMS)

noinst_SCRIPTS		= \
			  api-test-coverage

TESTS			= $(check_PROGRAMS)

check-local: check-api-test-coverage

check-api-test-coverage:
	chmod u+x $(top_srcdir)/libknet/tests/api-test-coverage
	$(top_srcdir)/libknet/tests/api-test-coverage $(top_srcdir)

api_knet_handle_new_SOURCES = api_knet_handle_new.c \
			      test-common.c

api_knet_handle_free_SOURCES = api_knet_handle_free.c \
			       test-common.c

api_knet_host_add_SOURCES = api_knet_host_add.c \
			    test-common.c

api_knet_host_remove_SOURCES = api_knet_host_remove.c \
			       ../../common/netutils.c \
			       test-common.c

api_knet_host_set_name_SOURCES = api_knet_host_set_name.c \
				 test-common.c

api_knet_host_get_name_by_host_id_SOURCES = api_knet_host_get_name_by_host_id.c \
					    test-common.c

api_knet_host_get_id_by_host_name_SOURCES = api_knet_host_get_id_by_host_name.c \
					    test-common.c

api_knet_host_get_host_list_SOURCES = api_knet_host_get_host_list.c \
				      test-common.c

api_knet_host_set_policy_SOURCES = api_knet_host_set_policy.c \
				   test-common.c

api_knet_host_get_policy_SOURCES = api_knet_host_get_policy.c \
				   test-common.c

api_knet_log_get_subsystem_name_SOURCES = api_knet_log_get_subsystem_name.c \
					  test-common.c

api_knet_log_get_subsystem_id_SOURCES = api_knet_log_get_subsystem_id.c \
					test-common.c

api_knet_log_get_loglevel_name_SOURCES = api_knet_log_get_loglevel_name.c \
					 test-common.c

api_knet_log_get_loglevel_id_SOURCES = api_knet_log_get_loglevel_id.c \
				       test-common.c

ping_test_SOURCES	= ping_test.c

pckt_test_SOURCES	= pckt_test.c

timediff_test_SOURCES	= timediff_test.c
