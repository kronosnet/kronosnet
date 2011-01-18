MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~ \
			  autoscan.log configure.scan

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SUBDIRS			= libtap libknet tests

if BUILD_DOCS
SUBDIRS			+= docs
endif

AM_CFLAGS		= -I$(srcdir)/libtap -I$(srcdir)/libknet

dist_doc_DATA		= \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence \
			  README \
			  TODO

noinst_HEADERS		= \
			  cfg.h \
			  netutils.h \
			  utils.h \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  cfg.c \
			  main.c \
			  netutils.c \
			  utils.c \
			  vty.c \
			  vty_auth.c \
			  vty_cli.c \
			  vty_cli_cmds.c \
			  vty_utils.c

kronosnetd_LDADD	= \
			  $(top_builddir)/libknet/libknet.a \
			  $(top_builddir)/libtap/libtap.la

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d

uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/post-down.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/pre-up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/up.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;

maintainer-clean-local:
	rm -rf m4
