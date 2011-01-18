MAINTAINERCLEANFILES	= Makefile.in

sources			= libtap.c

libversion		= 0:0:0

AM_CFLAGS		= -fPIC

# override global LIBS that pulls in lots of craft we don't need here
LIBS			= -lpthread

include_HEADERS		= libtap.h

noinst_HEADERS		= libtap-private.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= $(sources)

libtap_la_LDFLAGS	= -Wl,-version-script,libtap_exported_sym \
			  --export-dynamic \
			  -version-info $(libversion)

noinst_LTLIBRARIES	= libtap_test.la

libtap_test_la_SOURCES	= $(sources)

libtap_test_la_CPPFLAGS	= -DTEST
