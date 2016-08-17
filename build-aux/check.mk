VALGRIND = valgrind -q --error-exitcode=127

MEMCHECK = $(VALGRIND) --track-fds=yes --leak-check=full --suppressions=$(abs_top_srcdir)/build-aux/knet_valgrind_memcheck.supp
HELGRIND = $(VALGRIND) --tool=helgrind --suppressions=$(abs_top_srcdir)/build-aux/knet_valgrind_helgrind.supp

check-memcheck: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(MEMCHECK)"

check-helgrind: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(HELGRIND)"
