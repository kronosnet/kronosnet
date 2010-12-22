MAINTAINERCLEANFILES	= Makefile.in

LIBS			= -lpthread \
			  -version-info $(libversion)

libversion		= 0:0:0

sources			= \
			  ring.c \
			  host.c \
			  listener.c

include_HEADERS		= libknet.h
noinst_HEADERS		= libknet-private.h

noinst_LIBRARIES	= libknet.a
#lib_LTLIBRARIES	= libknet.la

libknet_a_SOURCES	= $(sources)
#libknet_la_SOURCES	= $(sources)
