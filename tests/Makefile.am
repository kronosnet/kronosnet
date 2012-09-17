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
		  netutils_test \
		  listener_test \
		  timediff_test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS		= -DTEST \
			  -I$(srcdir)/../libtap/ \
			  -I$(srcdir)/../libknet/ \
			  -I$(srcdir)/../kronosnetd/

AM_LDFLAGS		= \
			  $(top_builddir)/libtap/libtap.la \
			  $(top_builddir)/libknet/libknet.a 

ping_test_SOURCES	= ping_test.c

khandle_test_SOURCES	= khandle_test.c

lookup_bench_SOURCES	= lookup_bench.c \
			  $(srcdir)/../kronosnetd/netutils.c

listener_test_SOURCES	= listener_test.c

netutils_test_SOURCES	= netutils_test.c \
			  $(srcdir)/../kronosnetd/netutils.c

timediff_test_SOURCES	= timediff_test.c
