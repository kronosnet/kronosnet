#
# Copyright (C) 2021-2025 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
#

MAINTAINERCLEANFILES	= Makefile.in

include $(top_srcdir)/build-aux/check.mk

SUBDIRS			= .

if BUILD_RUST_BINDINGS
SUBDIRS			+= rust
endif
