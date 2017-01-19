#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in kronostnetd.logrotate

include $(top_srcdir)/build-aux/check.mk

EXTRA_DIST		= kronosnetd.logrotate.in kronosnetd.8 knet-keygen.8

noinst_HEADERS		= \
			  cfg.h \
			  etherfilter.h \
			  logging.h \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h 

kronosnetd_SOURCES	= \
			  cfg.c \
			  etherfilter.c \
			  main.c \
			  logging.c \
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

if BUILD_KRONOSNETD

sbin_PROGRAMS		= kronosnetd \
			  knet-keygen

dist_man_MANS		= kronosnetd.8 knet-keygen.8

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d
	$(INSTALL) -d -m 0755 $(DESTDIR)/$(sysconfdir)/logrotate.d
	$(INSTALL) -m 644 kronosnetd.logrotate $(DESTDIR)/$(sysconfdir)/logrotate.d/kronosnetd
	$(INSTALL) -d -m 0755 $(DESTDIR)/$(sysconfdir)/pam.d
	if [ -a $(sysconfdir)/pam.d/password-auth ]; then \
		cd $(DESTDIR)/$(sysconfdir)/pam.d && \
			rm -f kronosnetd && \
			$(LN_S) password-auth kronosnetd; \
	else \
		cd $(DESTDIR)/$(sysconfdir)/pam.d && \
			rm -f kronosnetd && \
			$(LN_S) passwd kronosnetd; \
	fi

uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;
	rm -f $(DESTDIR)/$(sysconfdir)/logrotate.d/kronosnetd
	rmdir $(DESTDIR)/$(sysconfdir)/logrotate.d || :;
	rm -f $(DESTDIR)/$(sysconfdir)/pam.d/kronosnetd || :;
	rmdir $(DESTDIR)/$(sysconfdir)/pam.d || :;

endif
