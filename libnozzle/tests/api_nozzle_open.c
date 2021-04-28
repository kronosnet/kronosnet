/*
 * Copyright (C) 2018-2021 Red Hat, Inc.  All rights reserved.
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

	nozzle1 = nozzle_open(device_name1, size, NULL);
	if (!nozzle1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	nozzle2 = nozzle_open(device_name2, size, NULL);
	if (!nozzle2) {
		printf("Unable to init %s\n", device_name2);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name2) > 0) {
		printf("Found interface %s on the system\n", device_name2);
	} else {
		printf("Unable to find interface %s on the system\n", device_name2);
	}

	if (nozzle1) {
		nozzle_close(nozzle1);
	}

	if (nozzle2) {
		nozzle_close(nozzle2);
	}

	printf("Testing error conditions\n");

	printf("Open same device twice\n");

	memset(device_name1, 0, size);

	nozzle1 = nozzle_open(device_name1, size, NULL);
	if (!nozzle1) {
		printf("Unable to init %s\n", device_name1);
		err = -1;
		goto out_clean;
	}

	if (is_if_in_system(device_name1) > 0) {
		printf("Found interface %s on the system\n", device_name1);
	} else {
		printf("Unable to find interface %s on the system\n", device_name1);
	}

	nozzle2 = nozzle_open(device_name1, size, NULL);
	if (nozzle2) {
		printf("We were able to init 2 interfaces with the same name!\n");
		err = -1;
		goto out_clean;
	}

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
	uint8_t randombyte = get_random_byte();

	memset(device_name, 0, sizeof(device_name));

	printf("Creating random nozzle interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("Unable to create random interface\n");
		return -1;
	}

#ifdef KNET_LINUX
	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create kronostest%u interface\n", randombyte);
		return -1;
	}
#endif
#ifdef KNET_BSD
	printf("Creating tap%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "tap%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create tap%u interface\n", randombyte);
		return -1;
	}

	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) == 0) {
		printf("BSD should not accept kronostest%u interface\n", randombyte);
		return -1;
	}
#endif

	printf("Testing ERROR conditions\n");

	printf("Testing dev == NULL\n");
	errno=0;
	if ((test_iface(NULL, size, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing size < IFNAMSIZ\n");
	errno=0;
	if ((test_iface(device_name, 1, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing device_name size > IFNAMSIZ\n");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ, NULL) >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing updown path != abs\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, "foo")  >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	memset(fakepath, 0, PATH_MAX);
	memset(fakepath, '/', PATH_MAX - 2);

	printf("Testing updown path > PATH_MAX\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, fakepath)  >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	return 0;
}

int main(void)
{
	need_root();

	if (test() < 0)
		return FAIL;

	if (test_multi_eth() < 0)
		return FAIL;

	return PASS;
}
