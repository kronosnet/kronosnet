MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~ \
			  autoscan.log configure.scan

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SUBDIRS			= libtap libknet libvty tests

if BUILD_DOCS
SUBDIRS			+= docs
endif

AM_CFLAGS		= \
			  -I$(top_srcdir)/libtap \
			  -I$(top_srcdir)/libknet \
			  -I$(top_srcdir)/libvty

dist_doc_DATA		= \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence \
			  README \
			  TODO

noinst_HEADERS		= \
			  cfg.h \
			  utils.h

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  cfg.c \
			  main.c \
			  utils.c

kronosnetd_LDADD	= \
			  $(top_builddir)/libvty/libvty.a \
			  $(top_builddir)/libknet/libknet.a \
			  $(top_builddir)/libtap/libtap.la

maintainer-clean-local:
	rm -rf m4
