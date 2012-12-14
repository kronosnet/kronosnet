VALGRIND = valgrind -q --error-exitcode=127 --track-fds=yes --leak-check=full
HELGRIND = valgrind -v --tool=helgrind

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check-helgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(HELGRIND)" check
