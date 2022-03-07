/*
 * Copyright (C) 2019-2022 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include "internals.h"
#include "links_acl.h"
#include "links_acl_ip.h"

#include "test-common.h"

static struct acl_match_entry *match_entry_v4;
static struct acl_match_entry *match_entry_v6;

/* This is a test program .. remember! */
#define BUFLEN 1024

static int get_ipaddress(const char *buf, struct sockaddr_storage *addr)
{
	struct addrinfo *info;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;

	if (getaddrinfo(buf, NULL, &hints, &info)) {
		return -1;
	}

	memmove(addr, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);
	return 0;
}

static int read_2ip(const char *buf, const char *delim, struct sockaddr_storage *addr, struct sockaddr_storage *addr2)
{
	char tmpbuf[BUFLEN];
	char *deli;

	deli = strstr(buf, delim);
	if (!deli) {
		return -1;
	}

	strncpy(tmpbuf, buf, deli-buf);
	tmpbuf[deli-buf] = '\0';

	if (get_ipaddress(tmpbuf, addr)) {
		return -1;
	}

	if (get_ipaddress(deli+1, addr2)) {
		return -1;
	}

	return 0;
}

/*
 * be aware that ordering is important
 * so we can test all the rules with few
 * ipcheck_validate calls
 */

static const char *rules[100] = {
	/*
	 * ipv4
	 */
	"RA192.168.0.3",		/* reject address */
	"AA192.168.0.1",		/* accept address */
	"RR192.168.0.10-192.168.0.20",	/* reject range */
	"AR192.168.0.0-192.168.0.255",	/* accept range */
	"RM192.168.2.0/255.255.255.0",	/* reject mask */
	"AM192.168.2.0/255.255.254.0",	/* accept mask */
	/*
	 * ipv6
	 */
	"RA3ffe::3",
	"AA3ffe::1",
	"RR3ffe::10-3ffe::20",
	"AR3ffe::0-3ffe::ff",
	"RM3ffe:1::0/ffff:ffff:ffff:ffff:ffff:ffff:ffff:0",
	"AM3ffe:1::0/ffff:ffff:ffff:ffff::0"
};

static int _ipcheck_addip(void *fd_tracker_match_entry_head,
			  struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
			  check_type_t type, check_acceptreject_t acceptreject)
{
	return ipcheck_addip(fd_tracker_match_entry_head, -1, ss1, ss2, type, acceptreject);
}

static int default_rules(int load)
{
	int ret;
	check_type_t type;
	check_acceptreject_t acceptreject;
	struct sockaddr_storage addr1;
	struct sockaddr_storage addr2;
	int i = 0;
	int (*loadfn)(void *fd_tracker_match_entry_head, struct sockaddr_storage *ss1, struct sockaddr_storage *ss2, check_type_t type, check_acceptreject_t acceptreject);

	if (load) {
		loadfn = _ipcheck_addip;
	} else {
		loadfn = ipcheck_rmip;
	}

	while (rules[i] != NULL) {
		printf("Parsing rule: %s\n", rules[i]);
		memset(&addr1, 0, sizeof(struct sockaddr_storage));
		memset(&addr2, 0, sizeof(struct sockaddr_storage));
		/*
		 * First char is A (accept) or R (Reject)
		 */
		switch(rules[i][0] & 0x5F) {
			case 'A':
				acceptreject = CHECK_ACCEPT;
				break;
			case 'R':
				acceptreject = CHECK_REJECT;
				break;
			default:
				fprintf(stderr, "Unknown record type on line %d: %s\n", i, rules[i]);
				goto next_record;
		}

		/*
		 * Second char is the filter type:
		 * A Address
		 * M Mask
		 * R Range
		 */
		switch(rules[i][1] & 0x5F) {
			case 'A':
				type = CHECK_TYPE_ADDRESS;
				ret = get_ipaddress(rules[i]+2, &addr1);
				break;
			case 'M':
				type = CHECK_TYPE_MASK;
				ret = read_2ip(rules[i]+2, "/", &addr1, &addr2);
				break;
			case 'R':
				type = CHECK_TYPE_RANGE;
				ret = read_2ip(rules[i]+2, "-", &addr1, &addr2);
				break;
			default:
				fprintf(stderr, "Unknown filter type on line %d: %s\n", i, rules[i]);
				goto next_record;
				break;
		}

		if (ret) {
			fprintf(stderr, "Failed to parse address on line %d: %s\n", i, rules[i]);
			return -1;
		} else {
			if (addr1.ss_family == AF_INET) {
				if (loadfn(&match_entry_v4, &addr1, &addr2, type, acceptreject) < 0) {
					fprintf(stderr, "Failed to add/rm address on line %d: %s (errno: %s)\n", i, rules[i], strerror(errno));
					return -1;
				}
			} else {
				if (loadfn(&match_entry_v6, &addr1, &addr2, type, acceptreject) < 0) {
					fprintf(stderr, "Failed to add/rm address on line %d: %s (errno: %s)\n", i, rules[i], strerror(errno));
					return -1;
				}
			}
		}

	next_record:
		i++;
	}

	return 0;
}

static const char *tests[100] = {
	/*
	 * ipv4
	 */
	"R192.168.0.3",		/* reject address */
	"A192.168.0.1",		/* accept address */
	"R192.168.0.11",	/* reject range */
	"A192.168.0.8",		/* accept range */
	"R192.168.2.1",		/* reject mask */
	"A192.168.3.1",		/* accept mask */
	/*
	 * ipv6
	 */
	"R3ffe::3",
	"A3ffe::1",
	"R3ffe::11",
	"A3ffe::8",
	"R3ffe:1::1",
	"A3ffe:1::1:1"
};

static const char *after_insert_tests[100] = {
	/*
	 * ipv4
	 */
	"R192.168.0.3",		/* reject address */
	"A192.168.0.1",		/* accept address */
	"R192.168.0.11",	/* reject range */
	"A192.168.0.8",		/* accept range */
	"A192.168.2.1",		/* reject mask */
	"A192.168.3.1",		/* accept mask */
	/*
	 * ipv6
	 */
	"R3ffe::3",
	"A3ffe::1",
	"R3ffe::11",
	"A3ffe::8",
	"A3ffe:1::1",
	"A3ffe:1::1:1"
};

int test(void)
{
	int i = 0;
	int expected;
	struct sockaddr_storage saddr;
	struct acl_match_entry *match_entry;

	/*
	 * default tests
	 */
	while (tests[i] != NULL) {
		/*
		 * First char is A (accept) or R (Reject)
		 */
		switch(tests[i][0] & 0x5F) {
			case 'A':
				expected = 1;
				break;
			case 'R':
				expected = 0;
				break;
			default:
				fprintf(stderr, "Unknown record type on line %d: %s\n", i, tests[i]);
				return FAIL;
				break;
		}

		if (get_ipaddress(tests[i]+1, &saddr)) {
				fprintf(stderr, "Cannot parse address %s\n", tests[i]+1);
				return FAIL;
		}

		if (saddr.ss_family == AF_INET) {
			match_entry = match_entry_v4;
		} else {
			match_entry = match_entry_v6;
		}

		if (ipcheck_validate(&match_entry, &saddr) != expected) {
			fprintf(stderr, "Failed to check access list for ip: %s\n", tests[i]);
			return FAIL;
		}
		i++;
	}

	/*
	 * insert tests
	 */

	if (get_ipaddress("192.168.2.1", &saddr)) {
		fprintf(stderr, "Cannot parse address 192.168.2.1\n");
		return FAIL;
	}

	if (ipcheck_addip(&match_entry_v4, 3, &saddr, &saddr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) {
		fprintf(stderr, "Unable to insert address in position 3 192.168.2.1\n");
		return FAIL;
	}

	if (get_ipaddress("3ffe:1::1", &saddr)) {
		fprintf(stderr, "Cannot parse address 3ffe:1::1\n");
		return FAIL;
	}

	if (ipcheck_addip(&match_entry_v6, 3, &saddr, &saddr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) {
		fprintf(stderr, "Unable to insert address in position 3 3ffe:1::1\n");
		return FAIL;
	}

	while (after_insert_tests[i] != NULL) {
		/*
		 * First char is A (accept) or R (Reject)
		 */
		switch(after_insert_tests[i][0] & 0x5F) {
			case 'A':
				expected = 1;
				break;
			case 'R':
				expected = 0;
				break;
			default:
				fprintf(stderr, "Unknown record type on line %d: %s\n", i, after_insert_tests[i]);
				return FAIL;
				break;
		}

		if (get_ipaddress(after_insert_tests[i]+1, &saddr)) {
				fprintf(stderr, "Cannot parse address %s\n", after_insert_tests[i]+1);
				return FAIL;
		}

		if (saddr.ss_family == AF_INET) {
			match_entry = match_entry_v4;
		} else {
			match_entry = match_entry_v6;
		}

		if (ipcheck_validate(&match_entry, &saddr) != expected) {
			fprintf(stderr, "Failed to check access list for ip: %s\n", after_insert_tests[i]);
			return FAIL;
		}
		i++;
	}
	return PASS;
}

int main(int argc, char *argv[])
{
	struct sockaddr_storage saddr;
	struct acl_match_entry *match_entry;
	int ret = PASS;
	int i;

	if (default_rules(1) < 0) {
		return -1;
	}

	if (argc > 1) {
		/*
		 * run manual check against default access lists
		 */
		for (i=1; i<argc; i++) {
			if (get_ipaddress(argv[i], &saddr)) {
				fprintf(stderr, "Cannot parse address %s\n", argv[i]);
				ret = FAIL;
				goto out;
			} else {
				if (saddr.ss_family == AF_INET) {
					match_entry = match_entry_v4;
				} else {
					match_entry = match_entry_v6;
				}
				if (ipcheck_validate(&match_entry, &saddr)) {
					printf("%s is VALID\n", argv[i]);
					ret = PASS;
				} else {
					printf("%s is not allowed\n", argv[i]);
					ret = FAIL;
				}
			}
		}
	} else {
		/*
		 * run automatic tests
		 */
		ret = test();
	}

	/*
	 * test memory leaks with ipcheck_rmip
	 */
	if (default_rules(0) < 0) {
		return FAIL;
	}

	/*
	 * test memory leaks with ipcheck_rmall
	 */
	if (default_rules(1) < 0) {
		return FAIL;
	}
out:
	ipcheck_rmall(&match_entry_v4);
	ipcheck_rmall(&match_entry_v6);

	return ret;
}
