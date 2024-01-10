/*
 * Copyright (C) 2018-2024 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#ifndef __NOZZLE_TEST_COMMON_H__
#define __NOZZLE_TEST_COMMON_H__

#include "internals.h"
#include "libnozzle.h"

/*
 * error codes from automake test-driver
 */

#define PASS	0
#define SKIP	77
#define ERROR	99
#define FAIL	-1

/*
 * common facilities
 */

#define IPBUFSIZE 1024

void need_root(void);
void need_tun(void);
int test_iface(char *name, size_t size, const char *updownpath);
int is_if_in_system(char *name);
int get_random_byte(void);
void make_local_ips(char *testipv4_1, char *testipv4_2, char *testipv6_1, char *testipv6_2);

#endif
