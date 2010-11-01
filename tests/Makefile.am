MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --leak-check=full

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

noinst_PROGRAMS = \
		  ping_test \
		  khandle_test \
		  $(check_PROGRAMS)

check_PROGRAMS = \
		  vty_test \
		  knet_test \
		  netutils_test

TESTS = $(check_PROGRAMS)

AM_CFLAGS		= -DTEST

knet_test_SOURCES	= \
			  knet_test.c \
			  ../knet.c \
			  ../utils.c

ping_test_SOURCES	= \
			  ping_test.c \
			  ../ring.c \
			  ../utils.c

khandle_test_SOURCES	= \
			  khandle_test.c \
			  ../ring.c \
			  ../utils.c

vty_test_SOURCES	= \
			  vty_test.c \
			  ../vty.c \
			  ../vty_auth.c \
			  ../vty_cli.c \
			  ../vty_cli_cmds.c \
			  ../vty_utils.c \
			  ../netutils.c \
			  ../utils.c

netutils_test_SOURCES	= \
			  netutils_test.c \
			  ../netutils.c \
			  ../utils.c
