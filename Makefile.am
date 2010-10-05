MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

SUBDIRS			= docs

dist_doc_DATA		= example.conf \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence

noinst_HEADERS		= \
			  conf.h logging.h \
			  knet.h nodes.h \
			  utils.h controlt.h \
			  controlt_comm.h \
			  netsocket.h

sbin_PROGRAMS		= kronosnetd knet_tool

kronosnetd_SOURCES	= main.c \
			  conf.c logging.c \
			  knet.c nodes.c \
			  utils.c controlt.c \
			  controlt_comm.c \
			  netsocket.c

kronosnetd_CPPFLAGS	=

kronosnetd_CFLAGS	= -fPIC \
			  $(confdb_CFLAGS) \
			  $(logsys_CFLAGS)

kronosnetd_LDFLAGS	= \
			  $(confdb_LIBS) \
			  $(logsys_LIBS) \
			  -lpthread

kronosnetd_LDADD	=

knet_tool_SOURCES	= knet_tool.c \
			  utils.c \
			  controlt_comm.c

knet_tool_CFLAGS	= -fPIC

knet_tool_LDFLAGS	=

knet_tool_LDADD		=

maintainer-clean-local:
	rm -rf m4
