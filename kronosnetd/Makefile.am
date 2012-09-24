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

sbin_PROGRAMS		= kronosnetd

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
