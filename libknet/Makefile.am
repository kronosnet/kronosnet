MAINTAINERCLEANFILES	= Makefile.in

LIBS			= -lpthread \
			  -version-info $(libversion)

sources			= ring.c

libversion		= 0:0:0

include_HEADERS		= ring.h

noinst_HEADERS		= knethandle.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)
