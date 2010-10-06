VALGRIND = valgrind -q --error-exitcode=127 --leak-check=full

check-valgrind: $(check_PROGRAMS)
	$(MAKE) TESTS_ENVIRONMENT="$(VALGRIND)" check

check_PROGRAMS = check_packet
TESTS = $(check_PROGRAMS)

check_packet_SOURCES = \
	check_packet.c \
	../packet.c

