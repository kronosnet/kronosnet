MAINTAINERCLEANFILES	= Makefile.in

# clear global linking list
LIBS			=

libversion		= 0:0:0

include_HEADERS		= libtap.h

pkgconfigdir		= $(libdir)/pkgconfig

pkgconfig_DATA		= libtap.pc

lib_LTLIBRARIES		= libtap.la

libtap_la_SOURCES	= libtap.c

libtap_la_LDFLAGS	= -lpthread \
			  -version-info $(libversion)
