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
			  api_knet_handle_new_test \
			  api_knet_handle_free_test \
			  api_knet_host_add_test \
			  api_knet_host_remove_test \
			  api_knet_host_set_name_test \
			  api_knet_host_get_name_by_host_id_test \
			  api_knet_host_get_id_by_host_name_test \
			  api_knet_host_get_host_list_test \
			  api_knet_host_set_policy_test \
			  api_knet_host_get_policy_test \
			  api_knet_log_get_subsystem_name_test \
			  api_knet_log_get_subsystem_id_test \
			  api_knet_log_get_loglevel_name_test \
			  api_knet_log_get_loglevel_id_test \
			  api_knet_log_set_loglevel_test \
			  api_knet_log_get_loglevel_test \
			  api_knet_link_set_config_test \
			  api_knet_link_get_config_test \
			  api_knet_link_set_ping_timers_test \
			  api_knet_link_get_ping_timers_test \
			  api_knet_link_set_pong_count_test \
			  api_knet_link_get_pong_count_test \
			  api_knet_link_set_priority_test \
			  api_knet_link_get_priority_test \
			  api_knet_link_set_enable_test \
			  api_knet_link_get_enable_test \
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
	$(top_srcdir)/libknet/tests/api-test-coverage $(top_srcdir) $(top_builddir)

api_knet_handle_new_test_SOURCES = api_knet_handle_new.c \
				   test-common.c

api_knet_handle_free_test_SOURCES = api_knet_handle_free.c \
				    test-common.c

api_knet_host_add_test_SOURCES = api_knet_host_add.c \
				 test-common.c

api_knet_host_remove_test_SOURCES = api_knet_host_remove.c \
				    ../../common/netutils.c \
				    test-common.c

api_knet_host_set_name_test_SOURCES = api_knet_host_set_name.c \
				      test-common.c

api_knet_host_get_name_by_host_id_test_SOURCES = api_knet_host_get_name_by_host_id.c \
						 test-common.c

api_knet_host_get_id_by_host_name_test_SOURCES = api_knet_host_get_id_by_host_name.c \
						 test-common.c

api_knet_host_get_host_list_test_SOURCES = api_knet_host_get_host_list.c \
					   test-common.c

api_knet_host_set_policy_test_SOURCES = api_knet_host_set_policy.c \
					test-common.c

api_knet_host_get_policy_test_SOURCES = api_knet_host_get_policy.c \
					test-common.c

api_knet_log_get_subsystem_name_test_SOURCES = api_knet_log_get_subsystem_name.c \
					       test-common.c

api_knet_log_get_subsystem_id_test_SOURCES = api_knet_log_get_subsystem_id.c \
					     test-common.c

api_knet_log_get_loglevel_name_test_SOURCES = api_knet_log_get_loglevel_name.c \
					      test-common.c

api_knet_log_get_loglevel_id_test_SOURCES = api_knet_log_get_loglevel_id.c \
					    test-common.c

api_knet_log_set_loglevel_test_SOURCES = api_knet_log_set_loglevel.c \
					 test-common.c

api_knet_log_get_loglevel_test_SOURCES = api_knet_log_get_loglevel.c \
					 test-common.c

api_knet_link_set_config_test_SOURCES = api_knet_link_set_config.c \
					../../common/netutils.c \
					test-common.c

api_knet_link_get_config_test_SOURCES = api_knet_link_get_config.c \
					../../common/netutils.c \
					test-common.c

api_knet_link_set_ping_timers_test_SOURCES = api_knet_link_set_ping_timers.c \
					     ../../common/netutils.c \
					     test-common.c

api_knet_link_get_ping_timers_test_SOURCES = api_knet_link_get_ping_timers.c \
					     ../../common/netutils.c \
					     test-common.c

api_knet_link_set_pong_count_test_SOURCES = api_knet_link_set_pong_count.c \
					    ../../common/netutils.c \
					    test-common.c

api_knet_link_get_pong_count_test_SOURCES = api_knet_link_get_pong_count.c \
					    ../../common/netutils.c \
					    test-common.c

api_knet_link_set_priority_test_SOURCES = api_knet_link_set_priority.c \
					  ../../common/netutils.c \
					  test-common.c

api_knet_link_get_priority_test_SOURCES = api_knet_link_get_priority.c \
					  ../../common/netutils.c \
					  test-common.c

api_knet_link_set_enable_test_SOURCES = api_knet_link_set_enable.c \
					../../common/netutils.c \
					test-common.c

api_knet_link_get_enable_test_SOURCES = api_knet_link_get_enable.c \
					../../common/netutils.c \
					test-common.c

ping_test_SOURCES	= ping_test.c

pckt_test_SOURCES	= pckt_test.c

timediff_test_SOURCES	= timediff_test.c