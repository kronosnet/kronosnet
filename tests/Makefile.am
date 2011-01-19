MAINTAINERCLEANFILES	= Makefile.in

VALGRIND = valgrind -q --error-exitcode=127 --track-fds=yes --leak-check=full
HELGRIND = valgrind -v --tool=helgrind

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check-helgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(HELGRIND)" check

noinst_PROGRAMS = \
		  ping_test \
		  khandle_test \
		  lookup_bench \
		  $(check_PROGRAMS)

check_PROGRAMS = \
		  vty_test \
		  netutils_test \
		  listener_test \
		  utils_test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS		= -DTEST \
			  -I$(srcdir)/../ \
			  -I$(srcdir)/../libtap/ \
			  -I$(srcdir)/../libknet/

AM_LDFLAGS		= \
			  $(top_builddir)/libtap/libtap_test.la \
			  $(top_builddir)/libknet/libknet.a

ping_test_SOURCES	= \
			  ping_test.c \
			  ../netutils.c \
			  ../utils.c

khandle_test_SOURCES	= \
			  khandle_test.c \
			  ../netutils.c \
			  ../utils.c

lookup_bench_SOURCES	= \
			  lookup_bench.c \
			  ../netutils.c \
			  ../utils.c

listener_test_SOURCES	= \
			  listener_test.c \
			  ../netutils.c \
			  ../utils.c

vty_test_SOURCES	= \
			  vty_test.c \
			  ../cfg.c \
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

utils_test_SOURCES	= \
			  utils_test.c \
			  ../utils.c
