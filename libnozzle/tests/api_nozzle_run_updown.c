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
#include <sys/stat.h>
#include <sys/types.h>

#include "test-common.h"

static int test(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle = NULL;
	char *error_string = NULL;
	char *tmpdir = NULL;
	char tmpdirsrc[PATH_MAX*2];
	char tmpstr[PATH_MAX*2];
	char srcfile[PATH_MAX];
	char dstfile[PATH_MAX];
	char current_dir[PATH_MAX];

	/*
	 * create a tmp dir for storing up/down scripts.
	 * we cannot create symlinks src dir
	 */
	FAIL_ON_NULL(tmpdir, getcwd(current_dir, sizeof(current_dir)));
	snprintf(tmpdirsrc, sizeof(tmpdirsrc)-1, "%s/nozzle_test_XXXXXX", current_dir);

	FAIL_ON_NULL(tmpdir, mkdtemp(tmpdirsrc));

	printf("Created temporary test dir: %s\n", tmpdir);

	printf("Populating test dir...\n");

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/pre-up.d", tmpdir);
	FAIL_ON_ERR_ONLY(mkdir(tmpstr, 0700), "Unable to create pre-up.d");

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/up.d", tmpdir);
	FAIL_ON_ERR_ONLY(mkdir(tmpstr, 0700), "Unable to create up.d");

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/down.d", tmpdir);
	FAIL_ON_ERR_ONLY(mkdir(tmpstr, 0700), "Unable to create down.d");

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/post-down.d", tmpdir);
	FAIL_ON_ERR_ONLY(mkdir(tmpstr, 0700), "Unable to create post-down.d");

	printf("Testing error conditions\n");

	printf("Init nozzle device with no path\n");

	memset(device_name, 0, size);
	printf("Creating nozzle interface without updown path\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, NULL));

	printf("Testing run_updown without updown path\n");
	FAIL_ON_SUCCESS(nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string), EINVAL);

	nozzle_close(nozzle);
	nozzle = NULL;

	printf("Init nozzle device with path\n");

	memset(device_name, 0, size);
	printf("Creating nozzle interface with updown path\n");
	FAIL_ON_NULL(nozzle, nozzle_open(device_name, size, tmpdir));

	printf("Testing invalid nozzle handle\n");
	FAIL_ON_SUCCESS(nozzle_run_updown(NULL, NOZZLE_POSTDOWN, &error_string), EINVAL);

	printf("Testing invalid action\n");
	FAIL_ON_SUCCESS(nozzle_run_updown(nozzle, NOZZLE_POSTDOWN + 1, &error_string), EINVAL);

	printf("Testing NULL error string pointer\n");
	FAIL_ON_SUCCESS(nozzle_run_updown(nozzle, NOZZLE_POSTDOWN + 1, NULL), EINVAL);

	printf("Testing interface pre-up/up/down/post-down (no scripts installed)\n");

	FAIL_ON_ZERO(err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string), "nozzle_run_updown failed to detect lack of script in pre-up.d");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_ZERO(err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string), "nozzle_run_updown failed to detect lack of script in up.d");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_ZERO(err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string), "nozzle_run_updown failed to detect lack of script in down.d");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_ZERO(err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string), "nozzle_run_updown failed to detect lack of script in post-down.d");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	printf("Populating test dir with fail scripts\n");

	snprintf(srcfile, sizeof(srcfile) - 1, "%s/nozzle_run_updown_exit_false", ABSSRCDIR);

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/pre-up.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/up.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/down.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/post-down.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	printf("Testing interface pre-up/up/down/post-down (FAIL scripts installed)\n");

	FAIL_ON_NONZERO(nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string) != -2, "nozzle_run_updown failed to detect script failure in pre-up.d (expected -2)");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_NONZERO(nozzle_run_updown(nozzle, NOZZLE_UP, &error_string) != -2, "nozzle_run_updown failed to detect script failure in up.d (expected -2)");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_NONZERO(nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string) != -2, "nozzle_run_updown failed to detect script failure in down.d (expected -2)");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	FAIL_ON_NONZERO(nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string) != -2, "nozzle_run_updown failed to detect script failure in post-down.d (expected -2)");
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}
	err = 0;

	printf("Populating test dir with true scripts\n");

	snprintf(srcfile, sizeof(srcfile) - 1, "%s/nozzle_run_updown_exit_true", ABSSRCDIR);

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/pre-up.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(unlink(dstfile), "unable to remove old symlink");
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/up.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(unlink(dstfile), "unable to remove old symlink");
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/down.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(unlink(dstfile), "unable to remove old symlink");
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/post-down.d/%s", tmpdir, device_name);
	FAIL_ON_ERR_ONLY(unlink(dstfile), "unable to remove old symlink");
	FAIL_ON_ERR_ONLY(link(srcfile, dstfile), "unable to create symlink");

	printf("Testing interface pre-up/up/down/post-down (TRUE scripts installed)\n");

	printf("Testing pre-up with true script\n");
	FAIL_ON_ERR(nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string));
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	printf("Testing up with true script\n");
	FAIL_ON_ERR(nozzle_run_updown(nozzle, NOZZLE_UP, &error_string));
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	printf("Testing down with true script\n");
	FAIL_ON_ERR(nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string));
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

	printf("Testing post-down with true script\n");
	FAIL_ON_ERR(nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string));
	if (error_string) {
		free(error_string);
		error_string = NULL;
	}

out_clean:
	if (tmpdir) {
		snprintf(tmpstr, sizeof(tmpstr) - 1, "rm -rf %s", tmpdir);
		printf("Removing temporary dir: %s\n", tmpstr);
		if (execute_bin_sh_command(tmpstr, &error_string)) {
			if (error_string) {
				printf("Error removing directory: %s\n", error_string);
			}
		}
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}
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
