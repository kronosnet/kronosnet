VALGRIND = valgrind -q --error-exitcode=127 --track-fds=yes --leak-check=full
HELGRIND = valgrind -v --tool=helgrind

check-valgrind: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(VALGRIND)"

check-helgrind: $(check_PROGRAMS)
	$(MAKE) check LOG_COMPILE="libtool --mode=execute $(HELGRIND)"
