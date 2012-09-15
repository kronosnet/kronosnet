MAINTAINERCLEANFILES	= Makefile.in

noinst_HEADERS		= \
			  cfg.h \
			  utils.h

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  cfg.c \
			  main.c \
			  utils.c

kronosnetd_CPPFLAGS	= \
			  -I$(top_srcdir)/libtap \
			  -I$(top_srcdir)/libknet \
			  -I$(top_srcdir)/libvty

kronosnetd_LDADD	= \
			  $(top_builddir)/libvty/libvty.a \
			  $(top_builddir)/libknet/libknet.a \
			  $(top_builddir)/libtap/libtap.la
