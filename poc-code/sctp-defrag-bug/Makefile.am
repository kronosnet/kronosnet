#
# Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

AM_CPPFLAGS		= -I$(top_srcdir)/libknet

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

noinst_PROGRAMS		= client server

noinst_HEADERS		= common.h

server_SOURCES		= server.c \
			  common.c

client_SOURCES		= client.c \
			  common.c
