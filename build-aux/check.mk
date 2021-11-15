#
# Copyright (C) 2012-2021 Red Hat, Inc.  All rights reserved.
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
	if [ -z "$(covoptions)" ]; then \
		COVOPTS="--all --disable STACK_USE --disable-parse-warnings";\
	else \
		COVOPTS="$(covoptions)";\
	fi; \
	$(COVANALYZE_EXEC) --dir=$(abs_top_builddir)/cov --wait-for-license $$COVOPTS
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

check-annocheck-libs:
if HAS_ANNOCHECK
	@echo Running annocheck libs test
	if ! $(ANNOCHECK_EXEC) --skip-lto --quiet .libs/*.so; then \
		$(ANNOCHECK_EXEC) --skip-lto --verbose .libs/*.so; \
		echo annocheck libs test: FAILED; \
		exit 1; \
	else \
		echo annocheck libs test: PASS; \
	fi
else
	@echo Annocheck build or binary not available
endif

# we cannot check run-path because CI builds with specific prefix/user_prefix
# and the only binaries affected are the test suite.

check-annocheck-bins:
if HAS_ANNOCHECK
	@echo Running annocheck binaries test
	if ! $(ANNOCHECK_EXEC) --skip-run-path --skip-lto --quiet .libs/*; then \
		$(ANNOCHECK_EXEC) --skip-run-path --skip-lto --verbose .libs/*; \
		echo annocheck binaries test: FAILED; \
		exit 1; \
	else \
		echo annocheck binaries test: PASS; \
	fi
else
	@echo Annocheck build or binary not available
endif
