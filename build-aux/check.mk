#
# Copyright (C) 2012-2020 Red Hat, Inc.  All rights reserved.
#
# Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
#
# This software licensed under GPL-2.0+
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

check-covscan:
if HAS_COVBUILD
	rm -rf $(abs_top_builddir)/cov*
	$(MAKE) -C $(abs_top_builddir) clean
	$(COVBUILD_EXEC) --dir=$(abs_top_builddir)/cov $(MAKE) -C $(abs_top_builddir)
if HAS_COVANALYZE
	$(COVANALYZE_EXEC) --dir=$(abs_top_builddir)/cov --wait-for-license $(covoptions)
if HAS_COVFORMATERRORS
	$(COVFORMATERRORS_EXEC) --dir=$(abs_top_builddir)/cov --emacs-style > $(abs_top_builddir)/cov.output.txt
	$(COVFORMATERRORS_EXEC) --dir=$(abs_top_builddir)/cov --html-output $(abs_top_builddir)/cov.html
endif
else
	@echo directory $(abs_top_builddir)/cov ready to be uploaded to https://scan.coverity.com
endif
else
	@echo cov-build not available on this platform
endif
