#
# Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

api_checks		= \
			  api_knet_handle_new_test \
			  api_knet_handle_free_test \
			  api_knet_handle_compress_test \
			  api_knet_handle_crypto_test \
			  api_knet_handle_setfwd_test \
			  api_knet_handle_enable_access_lists_test \
			  api_knet_handle_enable_filter_test \
			  api_knet_handle_enable_sock_notify_test \
			  api_knet_handle_add_datafd_test \
			  api_knet_handle_remove_datafd_test \
			  api_knet_handle_get_channel_test \
			  api_knet_handle_get_datafd_test \
			  api_knet_handle_get_stats_test \
			  api_knet_get_crypto_list_test \
			  api_knet_get_compress_list_test \
			  api_knet_handle_clear_stats_test \
			  api_knet_get_transport_list_test \
			  api_knet_get_transport_name_by_id_test \
			  api_knet_get_transport_id_by_name_test \
			  api_knet_handle_set_transport_reconnect_interval_test \
			  api_knet_handle_get_transport_reconnect_interval_test \
			  api_knet_recv_test \
			  api_knet_send_test \
			  api_knet_send_crypto_test \
			  api_knet_send_compress_test \
			  api_knet_send_sync_test \
			  api_knet_send_loopback_test \
			  api_knet_handle_pmtud_setfreq_test \
			  api_knet_handle_pmtud_getfreq_test \
			  api_knet_handle_enable_pmtud_notify_test \
			  api_knet_handle_pmtud_get_test \
			  api_knet_handle_pmtud_set_test \
			  api_knet_host_add_test \
			  api_knet_host_remove_test \
			  api_knet_host_set_name_test \
			  api_knet_host_get_name_by_host_id_test \
			  api_knet_host_get_id_by_host_name_test \
			  api_knet_host_get_host_list_test \
			  api_knet_host_set_policy_test \
			  api_knet_host_get_policy_test \
			  api_knet_host_get_status_test \
			  api_knet_host_enable_status_change_notify_test \
			  api_knet_log_get_subsystem_name_test \
			  api_knet_log_get_subsystem_id_test \
			  api_knet_log_get_loglevel_name_test \
			  api_knet_log_get_loglevel_id_test \
			  api_knet_log_set_loglevel_test \
			  api_knet_log_get_loglevel_test \
			  api_knet_strtoaddr_test \
			  api_knet_addrtostr_test \
			  api_knet_link_set_config_test \
			  api_knet_link_clear_config_test \
			  api_knet_link_get_config_test \
			  api_knet_link_set_ping_timers_test \
			  api_knet_link_get_ping_timers_test \
			  api_knet_link_set_pong_count_test \
			  api_knet_link_get_pong_count_test \
			  api_knet_link_set_priority_test \
			  api_knet_link_get_priority_test \
			  api_knet_link_set_enable_test \
			  api_knet_link_get_enable_test \
			  api_knet_link_get_link_list_test \
			  api_knet_link_get_status_test \
			  api_knet_link_add_acl_test \
			  api_knet_link_insert_acl_test \
			  api_knet_link_rm_acl_test \
			  api_knet_link_clear_acl_test \
			  api_knet_handle_crypto_set_config_test \
			  api_knet_handle_crypto_use_config_test \
			  api_knet_handle_crypto_rx_clear_traffic_test

api_knet_handle_new_test_SOURCES = api_knet_handle_new.c \
				   test-common.c

api_knet_handle_free_test_SOURCES = api_knet_handle_free.c \
				    test-common.c

api_knet_handle_new_limit_test_SOURCES = api_knet_handle_new_limit.c \
					 test-common.c

api_knet_handle_compress_test_SOURCES = api_knet_handle_compress.c \
					test-common.c

api_knet_handle_crypto_test_SOURCES = api_knet_handle_crypto.c \
				      test-common.c

api_knet_handle_setfwd_test_SOURCES = api_knet_handle_setfwd.c \
				      test-common.c

api_knet_handle_enable_access_lists_test_SOURCES = api_knet_handle_enable_access_lists.c \
						   test-common.c

api_knet_handle_enable_filter_test_SOURCES = api_knet_handle_enable_filter.c \
					     test-common.c

api_knet_handle_enable_sock_notify_test_SOURCES = api_knet_handle_enable_sock_notify.c \
						  test-common.c

api_knet_handle_add_datafd_test_SOURCES = api_knet_handle_add_datafd.c \
					  test-common.c

api_knet_handle_remove_datafd_test_SOURCES = api_knet_handle_remove_datafd.c \
					     test-common.c

api_knet_handle_get_channel_test_SOURCES = api_knet_handle_get_channel.c \
					   test-common.c

api_knet_handle_get_datafd_test_SOURCES = api_knet_handle_get_datafd.c \
					  test-common.c

api_knet_handle_get_stats_test_SOURCES = api_knet_handle_get_stats.c \
					 test-common.c

api_knet_get_crypto_list_test_SOURCES = api_knet_get_crypto_list.c \
					test-common.c

api_knet_get_compress_list_test_SOURCES = api_knet_get_compress_list.c \
					  test-common.c

api_knet_handle_clear_stats_test_SOURCES = api_knet_handle_clear_stats.c \
					  test-common.c

api_knet_get_transport_list_test_SOURCES = api_knet_get_transport_list.c \
					   test-common.c

api_knet_get_transport_name_by_id_test_SOURCES = api_knet_get_transport_name_by_id.c \
						 test-common.c

api_knet_get_transport_id_by_name_test_SOURCES = api_knet_get_transport_id_by_name.c \
						 test-common.c

api_knet_handle_set_transport_reconnect_interval_test_SOURCES = api_knet_handle_set_transport_reconnect_interval.c \
								test-common.c

api_knet_handle_get_transport_reconnect_interval_test_SOURCES = api_knet_handle_get_transport_reconnect_interval.c \
								test-common.c

api_knet_recv_test_SOURCES = api_knet_recv.c \
			     test-common.c

api_knet_send_test_SOURCES = api_knet_send.c \
			     test-common.c

api_knet_send_compress_test_SOURCES = api_knet_send_compress.c \
				      test-common.c

api_knet_send_crypto_test_SOURCES = api_knet_send_crypto.c \
				    test-common.c

api_knet_send_loopback_test_SOURCES = api_knet_send_loopback.c \
			     test-common.c

api_knet_send_sync_test_SOURCES = api_knet_send_sync.c \
				  test-common.c

api_knet_handle_pmtud_setfreq_test_SOURCES = api_knet_handle_pmtud_setfreq.c \
					     test-common.c

api_knet_handle_pmtud_getfreq_test_SOURCES = api_knet_handle_pmtud_getfreq.c \
					     test-common.c

api_knet_handle_enable_pmtud_notify_test_SOURCES = api_knet_handle_enable_pmtud_notify.c \
						   test-common.c

api_knet_handle_pmtud_get_test_SOURCES = api_knet_handle_pmtud_get.c \
					 test-common.c

api_knet_handle_pmtud_set_test_SOURCES = api_knet_handle_pmtud_set.c \
					 test-common.c

api_knet_host_add_test_SOURCES = api_knet_host_add.c \
				 test-common.c

api_knet_host_remove_test_SOURCES = api_knet_host_remove.c \
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

api_knet_host_get_status_test_SOURCES = api_knet_host_get_status.c \
					test-common.c

api_knet_host_enable_status_change_notify_test_SOURCES = api_knet_host_enable_status_change_notify.c \
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

api_knet_strtoaddr_test_SOURCES = api_knet_strtoaddr.c

api_knet_addrtostr_test_SOURCES = api_knet_addrtostr.c

api_knet_link_set_config_test_SOURCES = api_knet_link_set_config.c \
					test-common.c

api_knet_link_clear_config_test_SOURCES = api_knet_link_clear_config.c \
					  test-common.c

api_knet_link_get_config_test_SOURCES = api_knet_link_get_config.c \
					test-common.c

api_knet_link_set_ping_timers_test_SOURCES = api_knet_link_set_ping_timers.c \
					     test-common.c

api_knet_link_get_ping_timers_test_SOURCES = api_knet_link_get_ping_timers.c \
					     test-common.c

api_knet_link_set_pong_count_test_SOURCES = api_knet_link_set_pong_count.c \
					    test-common.c

api_knet_link_get_pong_count_test_SOURCES = api_knet_link_get_pong_count.c \
					    test-common.c

api_knet_link_set_priority_test_SOURCES = api_knet_link_set_priority.c \
					  test-common.c

api_knet_link_get_priority_test_SOURCES = api_knet_link_get_priority.c \
					  test-common.c

api_knet_link_set_enable_test_SOURCES = api_knet_link_set_enable.c \
					test-common.c

api_knet_link_get_enable_test_SOURCES = api_knet_link_get_enable.c \
					test-common.c

api_knet_link_get_link_list_test_SOURCES = api_knet_link_get_link_list.c \
					   test-common.c

api_knet_link_get_status_test_SOURCES = api_knet_link_get_status.c \
					test-common.c

api_knet_link_add_acl_test_SOURCES = api_knet_link_add_acl.c \
				     test-common.c

api_knet_link_insert_acl_test_SOURCES = api_knet_link_insert_acl.c \
					test-common.c

api_knet_link_rm_acl_test_SOURCES = api_knet_link_rm_acl.c \
				    test-common.c

api_knet_link_clear_acl_test_SOURCES = api_knet_link_clear_acl.c \
				       test-common.c

api_knet_handle_crypto_set_config_test_SOURCES = api_knet_handle_crypto_set_config.c \
						 test-common.c

api_knet_handle_crypto_use_config_test_SOURCES = api_knet_handle_crypto_use_config.c \
						 test-common.c

api_knet_handle_crypto_rx_clear_traffic_test_SOURCES = api_knet_handle_crypto_rx_clear_traffic.c \
						       test-common.c
