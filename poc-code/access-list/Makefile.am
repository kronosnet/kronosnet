#
# Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

# override global LIBS that pulls in lots of craft we don't need here
LIBS			=

EXTRA_DIST		= test_ipcheck.txt

noinst_PROGRAMS		= test_ipcheck

noinst_HEADERS		= ipcheck.h

test_ipcheck_SOURCES	= ipcheck.c test_ipcheck.c
