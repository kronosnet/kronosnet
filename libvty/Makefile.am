MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		= \
			  -I$(top_srcdir)/libtap \
			  -I$(top_srcdir)/libknet

noinst_HEADERS		= \
			  vty.h \
			  vty_auth.h \
			  vty_cli.h \
			  vty_cli_cmds.h \
			  vty_utils.h

noinst_LIBRARIES	= libvty.a

libvty_a_SOURCES	= \
			  vty.c \
			  vty_auth.c \
			  vty_cli.c \
			  vty_cli_cmds.c \
			  vty_utils.c
