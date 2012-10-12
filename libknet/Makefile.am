MAINTAINERCLEANFILES	= Makefile.in

LIBS			= -lpthread \
			  -version-info $(libversion)

libversion		= 0:0:0

sources			= \
			  common.c \
			  handle.c \
			  host.c \
			  listener.c \
			  crypto.c \
			  nsscrypto.c \
			  etherfilter.c

include_HEADERS		= libknet.h
noinst_HEADERS		= libknet-private.h \
			  crypto.h \
			  nsscrypto.h

lib_LTLIBRARIES		= libknet.la

libknet_la_SOURCES	= $(sources)

libknet_la_CFLAGS	= $(nss_CFLAGS)
libknet_la_LIBADD	= $(nss_LIBS)
