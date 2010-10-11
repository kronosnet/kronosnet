MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --leak-check=full

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

noinst_PROGRAMS = \
		  ping_test \
		  $(check_PROGRAMS)

check_PROGRAMS = \
		  knet_test \
		  ring_test

TESTS = $(check_PROGRAMS)

knet_test_SOURCES	= \
			  knet_test.c \
			  ../knet.c \
			  ../utils.c

knet_test_CFLAGS	= -DTEST

ring_test_SOURCES	= \
			  ring_test.c \
			  ../ring.c \
			  ../utils.c

ping_test_SOURCES	= \
			  ping_test.c \
			  ../ring.c \
			  ../utils.c
