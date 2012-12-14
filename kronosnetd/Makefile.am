#
# Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in kronostnetd.logrotate

EXTRA_DIST		= kronosnetd.logrotate.in

include $(top_srcdir)/build-aux/check.mk

noinst_HEADERS		= \
			  cfg.h \
			  etherfilter.h \
			  logging.h \
			  netutils.h \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h 

sbin_PROGRAMS		= kronosnetd \
			  knet-keygen

check_PROGRAMS		= netutils_test

noinst_PROGRAMS		= $(check_PROGRAMS)

TESTS			= $(check_PROGRAMS)

kronosnetd_SOURCES	= \
			  cfg.c \
			  etherfilter.c \
			  main.c \
			  logging.c \
			  netutils.c \
			  vty.c \
			  vty_auth.c \
			  vty_cli.c \
			  vty_cli_cmds.c \
			  vty_utils.c

kronosnetd_CPPFLAGS	= \
			  -I$(top_srcdir)/libtap \
			  -I$(top_srcdir)/libknet

kronosnetd_CFLAGS	= $(libqb_CFLAGS)

kronosnetd_LDADD	= \
			  $(top_builddir)/libknet/libknet.la \
			  $(top_builddir)/libtap/libtap.la \
			  $(libqb_LIBS)

knet_keygen_SOURCES	= keygen.c

knet_keygen_CPPFLAGS	= -I$(top_srcdir)/libknet

dist_man_MANS		= kronosnetd.8 knet-keygen.8

netutils_test_SOURCES	= netutils_test.c \
			  netutils.c

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d
	$(INSTALL) -d -m 0755 $(DESTDIR)/$(sysconfdir)/logrotate.d
	$(INSTALL) -m 644 kronosnetd.logrotate $(DESTDIR)/$(sysconfdir)/logrotate.d/kronosnetd
	


uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;
	rm -f $(DESTDIR)/$(sysconfdir)/logrotate.d/kronosnetd
	rmdir $(DESTDIR)/$(sysconfdir)/logrotate.d || :;
