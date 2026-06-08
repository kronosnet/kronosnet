/*
 * Copyright (C) 2018-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>

#include "test-common.h"

static int test(void)
{
	char verifycmd[1024];
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;
	char *error_string = NULL;

	printf("Testing interface up/down\n");

	memset(device_name, 0, size);

	printf("Creating nozzle interface\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Put the interface up\n");
	FAIL_ON_ERR(nozzle_set_up(nozzle));

	printf("Verifying interface is UP\n");
	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#if defined(KNET_BSD) || defined(KNET_SOLARIS)
		 "ifconfig %s | grep -q UP", nozzle->name);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("*** FAIL on line %d. Unable to verify inteface UP\n", __LINE__);
		err = -1;
		goto out_clean;
	}

	printf("Test ERROR conditions\n");

	printf("Try to UP the same interface twice\n");
	FAIL_ON_ERR(nozzle_set_up(nozzle));

	printf("Pass NULL to nozzle set_up\n");
	FAIL_ON_SUCCESS(nozzle_set_up(NULL), EINVAL);

out_clean:
	if (nozzle) {
		nozzle_set_down(nozzle);
		nozzle_close(nozzle);
	}

	return err;
}

int main(void)
{
	need_root();
	need_tun();

	if (test() < 0)
		return FAIL;

	return PASS;
}
