/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "test-common.h"

static int test_multi_eth(void)
{
	char device_name1[IFNAMSIZ];
	char device_name2[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle1 = NULL;
	nozzle_t nozzle2 = NULL;

	printf("Testing multiple nozzle interface instances\n");

	memset(device_name1, 0, size);
	memset(device_name2, 0, size);

	printf("Creating first nozzle interface\n");
	FAIL_ON_NULL(nozzle1, nozzle_open(device_name1, size, NULL));

	FAIL_ON_ZERO(is_if_in_system(device_name1) > 0, "Unable to find interface on the system");

	printf("Creating second nozzle interface\n");
	FAIL_ON_NULL(nozzle2, nozzle_open(device_name2, size, NULL));

	FAIL_ON_ZERO(is_if_in_system(device_name2) > 0, "Unable to find interface on the system");

	if (nozzle1) {
		nozzle_close(nozzle1);
		nozzle1 = NULL;
	}

	if (nozzle2) {
		nozzle_close(nozzle2);
		nozzle2 = NULL;
	}
#ifndef KNET_SOLARIS
	printf("Testing error conditions\n");

	printf("Open same device twice\n");

	memset(device_name1, 0, size);

	printf("Creating first nozzle interface\n");
	FAIL_ON_NULL(nozzle1, nozzle_open(device_name1, size, NULL));

	FAIL_ON_ZERO(is_if_in_system(device_name1) > 0, "Unable to find interface on the system");

	printf("Testing duplicate interface creation\n");
	FAIL_ON_NOT_NULL(nozzle2, nozzle_open(device_name1, size, NULL), EBUSY);
#endif
out_clean:
	if (nozzle1) {
		nozzle_close(nozzle1);
	}

	if (nozzle2) {
		nozzle_close(nozzle2);
	}

	return err;
}

static int test(void)
{
	char device_name[2*IFNAMSIZ];
	char fakepath[PATH_MAX];
	size_t size = IFNAMSIZ;
	int err = 0;
#ifndef KNET_SOLARIS
	uint8_t randombyte = get_random_byte();
#endif

	memset(device_name, 0, sizeof(device_name));

	printf("Creating random nozzle interface:\n");
	FAIL_ON_ERR_ONLY(test_iface(device_name, size, NULL), "Unable to create random interface");

#ifdef KNET_LINUX
	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	FAIL_ON_ERR_ONLY(test_iface(device_name, size, NULL), "Unable to create kronostest interface");
#endif
#if KNET_BSD
	printf("Creating tap%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "tap%u", randombyte);
	FAIL_ON_ERR_ONLY(test_iface(device_name, size, NULL), "Unable to create tap interface");

	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	FAIL_ON_ZERO(test_iface(device_name, size, NULL), "BSD should not accept kronostest interface");
#endif

	printf("Testing ERROR conditions\n");

	printf("Testing dev == NULL\n");
	FAIL_ON_NOT_ERR_ONLY(test_iface(NULL, size, NULL), EINVAL, "Something is wrong in nozzle_open sanity checks");

	printf("Testing size < IFNAMSIZ\n");
	FAIL_ON_NOT_ERR_ONLY(test_iface(device_name, 1, NULL), EINVAL, "Something is wrong in nozzle_open sanity checks");

	printf("Testing device_name size > IFNAMSIZ\n");
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	FAIL_ON_NOT_ERR_ONLY(test_iface(device_name, IFNAMSIZ, NULL), E2BIG, "Something is wrong in nozzle_open sanity checks");

	printf("Testing updown path != abs\n");
	memset(device_name, 0, IFNAMSIZ);
	FAIL_ON_NOT_ERR_ONLY(test_iface(device_name, IFNAMSIZ, "foo"), EINVAL, "Something is wrong in nozzle_open sanity checks");

	memset(fakepath, 0, PATH_MAX);
	memset(fakepath, '/', PATH_MAX - 2);

	printf("Testing updown path > PATH_MAX\n");
	memset(device_name, 0, IFNAMSIZ);
	FAIL_ON_NOT_ERR_ONLY(test_iface(device_name, IFNAMSIZ, fakepath), E2BIG, "Something is wrong in nozzle_open sanity checks");

out_clean:
	return err;
}

int main(void)
{
	need_root();
	need_tun();

	if (test() < 0)
		return FAIL;

	if (test_multi_eth() < 0)
		return FAIL;

	return PASS;
}
