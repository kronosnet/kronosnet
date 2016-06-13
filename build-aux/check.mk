VALGRIND = valgrind -q --error-exitcode=127

MEMCHECK = $(VALGRIND) --track-fds=yes --leak-check=full
HELGRIND = $(VALGRIND) --tool=helgrind

check-memcheck: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(MEMCHECK)"

check-helgrind: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(HELGRIND)"
