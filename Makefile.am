MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~ \
			  autoscan.log configure.scan

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SUBDIRS			= init libtap libknet kronosnetd tests

EXTRA_DIST		= debian kronosnetd.spec

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

maintainer-clean-local:
	rm -rf m4
