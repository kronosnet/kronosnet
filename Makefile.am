MAINTAINERCLEANFILES	= Makefile.in aclocal.m4 configure depcomp \
			  config.guess config.sub missing install-sh \
			  ltmain.sh compile config.h.in config.h.in~

AUTOMAKE_OPTIONS	= foreign

ACLOCAL_AMFLAGS		= -I m4

dist_doc_DATA		= example.conf \
			  COPYING.applications \
			  COPYING.libraries \
			  COPYRIGHT \
			  README.licence

noinst_HEADERS		= \
			  conf.h logging.h \
			  cnet.h nodes.h \
			  utils.h controlt.h \
			  controlt_comm.h

sbin_PROGRAMS		= clusternetd cnet_tool

clusternetd_SOURCES	= main.c \
			  conf.c logging.c \
			  cnet.c nodes.c \
			  utils.c controlt.c \
			  controlt_comm.c

clusternetd_CPPFLAGS	=

clusternetd_CFLAGS	= -fPIC \
			  $(confdb_CFLAGS) \
			  $(logt_CFLAGS)

clusternetd_LDFLAGS	= \
			  $(confdb_LIBS) \
			  $(logt_LIBS) \
			  -lpthread

clusternetd_LDADD	= 

cnet_tool_SOURCES	= cnet_tool.c \
			  utils.c \
			  controlt_comm.c

cnet_tool_CFLAGS	= -fPIC

cnet_tool_LDFLAGS	=

cnet_tool_LDADD		=

maintainer-clean-local:
	rm -rf m4
