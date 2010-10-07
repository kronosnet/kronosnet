MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --leak-check=full

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check_PROGRAMS = knet_test

TESTS = $(check_PROGRAMS)

knet_test_SOURCES	= \
			  knet_test.c \
			  ../knet.c
