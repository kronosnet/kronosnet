#
# Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

noinst_HEADERS		= netutils.h

check_PROGRAMS		= netutils_test

noinst_PROGRAMS		= $(check_PROGRAMS)

TESTS			= $(check_PROGRAMS)

netutils_test_SOURCES	= netutils_test.c \
			  netutils.c
