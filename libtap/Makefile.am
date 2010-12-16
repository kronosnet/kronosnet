MAINTAINERCLEANFILES	= Makefile.in

LIBS			= -lpthread \
			  -version-info $(libversion)

name			= libtap
sources			= $(name).c

libversion		= 0:0:0

include_HEADERS		= $(name).h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= $(name).pc

lib_LTLIBRARIES		= libtap.la

noinst_LTLIBRARIES	= libtap_test.la

libtap_test_la_SOURCES	= $(sources)

libtap_test_la_CPPFLAGS	= -DTEST

libtap_la_SOURCES	= $(sources)
