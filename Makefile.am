MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SUBDIRS			= tests

if BUILD_DOCS
SUBDIRS			+= docs
endif

dist_doc_DATA		= \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence \
			  README \
			  TODO

noinst_HEADERS		= \
			  cfg.h \
			  knet.h \
			  knethandle.h \
			  netutils.h \
			  ring.h \
			  utils.h \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  cfg.c \
			  knet.c \
			  main.c \
			  netutils.c \
			  ring.c \
			  utils.c \
			  vty.c \
			  vty_auth.c \
			  vty_cli.c \
			  vty_cli_cmds.c \
			  vty_utils.c

install-exec-local:
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)

uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;

maintainer-clean-local:
	rm -rf m4
