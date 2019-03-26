#
# Copyright (C) 2012-2019 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+, LGPL-2.0+
#

VALGRIND = $(VALGRIND_EXEC) -q --error-exitcode=127 --gen-suppressions=all

MEMCHECK = $(VALGRIND) --track-fds=yes --leak-check=full --alignment=16 --suppressions=$(abs_top_srcdir)/build-aux/knet_valgrind_memcheck.supp
HELGRIND = $(VALGRIND) --tool=helgrind --suppressions=$(abs_top_srcdir)/build-aux/knet_valgrind_helgrind.supp

check-memcheck: $(check_PROGRAMS)
if HAS_VALGRIND
	export KNETMEMCHECK=yes && \
		$(MAKE) check LOG_COMPILE="libtool --mode=execute $(MEMCHECK)"
else
	@echo valgrind not available on this platform
endif

check-helgrind: $(check_PROGRAMS)
if HAS_VALGRIND
	export KNETHELGRIND=yes && \
		$(MAKE) check LOG_COMPILE="libtool --mode=execute $(HELGRIND)"
else
	@echo valgrind not available on this platform
endif
