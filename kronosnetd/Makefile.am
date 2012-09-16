MAINTAINERCLEANFILES	= Makefile.in

noinst_HEADERS		= \
			  cfg.h \
			  logging.h

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  cfg.c \
			  main.c \
			  logging.c

kronosnetd_CPPFLAGS	= \
			  -I$(top_srcdir)/libtap \
			  -I$(top_srcdir)/libknet \
			  -I$(top_srcdir)/libvty

kronosnetd_CFLAGS	= $(LIBQB_CFLAGS)

kronosnetd_LDADD	= \
			  $(top_builddir)/libvty/libvty.a \
			  $(top_builddir)/libknet/libknet.a \
			  $(top_builddir)/libtap/libtap.la \
			  $(LIBQB_LIBS)
