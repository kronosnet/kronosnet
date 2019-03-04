#
# Copyright (C) 2017-2018 Red Hat, Inc.  All rights reserved.
#
# Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
#          Federico Simoncelli <fsimon@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST	= \
		  kronosnetd.8 knet-keygen.8 \
		  api-to-man-page-coverage

# Avoid Automake warnings about overriding these user variables.
# Programs in this directory are used during the build only.
AUTOMAKE_OPTIONS = -Wno-gnu
EXEEXT=$(BUILD_EXEEXT)
CC=$(CC_FOR_BUILD)
CFLAGS=$(CFLAGS_FOR_BUILD)
CPPFLAGS=$(CPPFLAGS_FOR_BUILD)
LDFLAGS=$(LDFLAGS_FOR_BUILD)

if BUILD_MAN

if BUILD_KRONOSNETD
man8_MANS	= kronosnetd.8 knet-keygen.8
endif

noinst_PROGRAMS	= doxyxml

doxyxml_SOURCES = doxyxml.c
doxyxml_CFLAGS = $(AM_CFLAGS) $(libqb_BUILD_CFLAGS) $(libxml_BUILD_CFLAGS)
doxyxml_LDADD = $(libqb_BUILD_LIBS) $(libxml_BUILD_LIBS)

knet_man3_MANS = \
		knet_addrtostr.3 \
		knet_handle_add_datafd.3 \
		knet_handle_clear_stats.3 \
		knet_handle_compress.3 \
		knet_handle_crypto.3 \
		knet_handle_enable_filter.3 \
		knet_handle_enable_pmtud_notify.3 \
		knet_handle_enable_sock_notify.3 \
		knet_handle_free.3 \
		knet_handle_get_channel.3 \
		knet_get_compress_list.3 \
		knet_get_crypto_list.3 \
		knet_handle_get_datafd.3 \
		knet_handle_get_stats.3 \
		knet_get_transport_id_by_name.3 \
		knet_get_transport_list.3 \
		knet_get_transport_name_by_id.3 \
		knet_handle_get_transport_reconnect_interval.3 \
		knet_handle_new.3 \
		knet_handle_pmtud_get.3 \
		knet_handle_pmtud_getfreq.3 \
		knet_handle_pmtud_setfreq.3 \
		knet_handle_remove_datafd.3 \
		knet_handle_setfwd.3 \
		knet_handle_set_transport_reconnect_interval.3 \
		knet_host_add.3 \
		knet_host_enable_status_change_notify.3 \
		knet_host_get_host_list.3 \
		knet_host_get_id_by_host_name.3 \
		knet_host_get_name_by_host_id.3 \
		knet_host_get_policy.3 \
		knet_host_get_status.3 \
		knet_host_remove.3 \
		knet_host_set_name.3 \
		knet_host_set_policy.3 \
		knet_link_clear_config.3 \
		knet_link_get_config.3 \
		knet_link_get_enable.3 \
		knet_link_get_link_list.3 \
		knet_link_get_ping_timers.3 \
		knet_link_get_pong_count.3 \
		knet_link_get_priority.3 \
		knet_link_get_status.3 \
		knet_link_set_config.3 \
		knet_link_set_enable.3 \
		knet_link_set_ping_timers.3 \
		knet_link_set_pong_count.3 \
		knet_link_set_priority.3 \
		knet_log_get_loglevel.3 \
		knet_log_get_loglevel_id.3 \
		knet_log_get_loglevel_name.3 \
		knet_log_get_subsystem_id.3 \
		knet_log_get_subsystem_name.3 \
		knet_log_set_loglevel.3 \
		knet_recv.3 \
		knet_send.3 \
		knet_send_sync.3 \
		knet_strtoaddr.3 \
		knet_handle_set_threads_timer_res.3 \
		knet_handle_get_threads_timer_res.3 \
		knet_link_enable_status_change_notify.3 \
		knet_handle_enable_access_lists.3 \
		knet_link_add_acl.3 \
		knet_link_insert_acl.3 \
		knet_link_rm_acl.3 \
		knet_link_clear_acl.3

if BUILD_LIBNOZZLE
nozzle_man3_MANS = \
		nozzle_add_ip.3 \
		nozzle_close.3 \
		nozzle_del_ip.3 \
		nozzle_get_fd.3 \
		nozzle_get_handle_by_name.3 \
		nozzle_get_ips.3 \
		nozzle_get_mac.3 \
		nozzle_get_mtu.3 \
		nozzle_get_name_by_handle.3 \
		nozzle_open.3 \
		nozzle_reset_mac.3 \
		nozzle_reset_mtu.3 \
		nozzle_run_updown.3 \
		nozzle_set_down.3 \
		nozzle_set_mac.3 \
		nozzle_set_mtu.3 \
		nozzle_set_up.3
endif

man3_MANS = $(knet_man3_MANS) $(nozzle_man3_MANS)

$(MANS): doxyfile-knet.stamp doxyfile-nozzle.stamp

doxyfile-knet.stamp: $(builddir)/doxyxml Doxyfile-knet $(top_srcdir)/libknet/libknet.h
	$(DOXYGEN) Doxyfile-knet
	$(builddir)/doxyxml -m -P -o $(builddir) -s 3 -p @PACKAGE_NAME@ -H "Kronosnet Programmer's Manual" \
		$$($(UTC_DATE_AT)$(SOURCE_EPOCH) +"-D %F -Y %Y") -d $(builddir)/xml-knet/ libknet_8h.xml
	touch doxyfile-knet.stamp

doxyfile-nozzle.stamp: $(builddir)/doxyxml Doxyfile-nozzle $(top_srcdir)/libnozzle/libnozzle.h
if BUILD_LIBNOZZLE
	$(DOXYGEN) Doxyfile-nozzle
	$(builddir)/doxyxml -m -P -o $(builddir) -s 3 -p @PACKAGE_NAME@ -H "Kronosnet Programmer's Manual" \
		$$($(UTC_DATE_AT)$(SOURCE_EPOCH) +"-D %F -Y %Y") -d $(builddir)/xml-nozzle/ libnozzle_8h.xml
endif

noinst_SCRIPTS	= api-to-man-page-coverage

check-local: check-api-to-man-page-coverage-libknet check-api-to-man-page-coverage-libnozzle

check-api-to-man-page-coverage-libnozzle:
if BUILD_LIBNOZZLE
	$(srcdir)/api-to-man-page-coverage $(top_srcdir) nozzle
endif

check-api-to-man-page-coverage-libknet:
	$(srcdir)/api-to-man-page-coverage $(top_srcdir) knet

endif

clean-local:
	rm -rf doxyfile*.stamp xml* *.3
