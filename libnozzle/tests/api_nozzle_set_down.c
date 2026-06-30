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

#include "test-common.h"

static int test(void)
{
	char verifycmd[1024];
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;
	char *error_string = NULL;

	printf("Testing interface down\n");

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
#ifdef KNET_BSD
	         "ifconfig %s | sed -e 's/LOWER_UP/GROT/' | grep -q UP", nozzle->name);
#endif
#ifdef KNET_SOLARIS
                 "exit 0"); // No way to check this
#endif

        FAIL_ON_CMD(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify interface UP");

	printf("Put the interface down\n");
	FAIL_ON_ERR(nozzle_set_down(nozzle));

	printf("Verifying interface is DOWN\n");
	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#ifdef KNET_BSD
	         "ifconfig %s | sed -e 's/LOWER_UP/GROT/' | grep -q UP", nozzle->name);
#endif
#ifdef KNET_SOLARIS
                 "exit 1"); // No way to check this
#endif
	FAIL_ON_CMD_SUCCESS(err, execute_bin_sh_command(verifycmd, &error_string), error_string, "Unable to verify interface DOWN");

	printf("Try to DOWN the same interface twice\n");
	FAIL_ON_ERR(nozzle_set_down(nozzle));

	printf("Pass NULL to nozzle set_down\n");
	FAIL_ON_SUCCESS(nozzle_set_down(NULL), EINVAL);

out_clean:
	if (nozzle) {
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
