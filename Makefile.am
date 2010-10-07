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
			  README.licence

noinst_HEADERS		=

sbin_PROGRAMS		= kronosnetd

kronosnetd_SOURCES	= \
			  main.c \
			  utils.c

maintainer-clean-local:
	rm -rf m4
