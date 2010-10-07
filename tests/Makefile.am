MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --leak-check=full

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check_PROGRAMS =

TESTS = $(check_PROGRAMS)
