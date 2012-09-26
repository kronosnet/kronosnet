MAINTAINERCLEANFILES	= Makefile.in

noinst_HEADERS		= \
			  cfg.h \
			  logging.h \
			  netutils.h \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h 

sbin_PROGRAMS		= kronosnetd \
			  knet-keygen

kronosnetd_SOURCES	= \
			  cfg.c \
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

kronosnetd_CFLAGS	= $(LIBQB_CFLAGS)

kronosnetd_LDADD	= \
			  $(top_builddir)/libknet/libknet.la \
			  $(top_builddir)/libtap/libtap.la \
			  $(LIBQB_LIBS)

knet_keygen_SOURCES	= keygen.c

install-exec-local:
	$(INSTALL) -d -m 0700 $(DESTDIR)/$(DEFAULT_CONFIG_DIR)
	$(INSTALL) -d $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d

uninstall-local:
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR)/cryptokeys.d || :;
	rmdir $(DESTDIR)/$(DEFAULT_CONFIG_DIR) || :;
