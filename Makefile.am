MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

noinst_HEADERS		= \
			  conf.h logging.h \
			  tun.h

sbin_PROGRAMS		= clusternetd

clusternetd_SOURCES	= main.c \
			  conf.c logging.c \
			  tun.c

clusternetd_CPPFLAGS	=

clusternetd_CFLAGS	= -fPIC \
			  $(logt_CFLAGS)

clusternetd_LDFLAGS	= $(logt_LIBS)

clusternetd_LDADD	= 

maintainer-clean-local:
	rm -rf m4
