/*
 * Copyright (C) 2018-2023 Red Hat, Inc.  All rights reserved.
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
	if (getcwd(current_dir, sizeof(current_dir)) == NULL) {
		printf("Unable to get current working directory: %s\n", strerror(errno));
		return -1;
	}
	snprintf(tmpdirsrc, sizeof(tmpdirsrc)-1, "%s/nozzle_test_XXXXXX", current_dir);

	tmpdir = mkdtemp(tmpdirsrc);
	if (!tmpdir) {
		printf("Unable to create temporary directory %s for testing: %s\n", tmpdirsrc, strerror(errno));
		return -1;
	}

	printf("Created temporary test dir: %s\n", tmpdir);

	printf("Populating test dir...\n");

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/pre-up.d", tmpdir);
	if (mkdir(tmpstr, 0700) < 0) {
		printf("Unable to create %s/pre-up.d: %s", tmpdir, strerror(errno));
		err = -1;
		goto out_clean;
	}

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/up.d", tmpdir);
	if (mkdir(tmpstr, 0700) < 0) {
		printf("Unable to create %s/up.d: %s", tmpdir, strerror(errno));
		err = -1;
		goto out_clean;
	}

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/down.d", tmpdir);
	if (mkdir(tmpstr, 0700) < 0) {
		printf("Unable to create %s/down.d: %s", tmpdir, strerror(errno));
		err = -1;
		goto out_clean;
	}

	snprintf(tmpstr, sizeof(tmpstr) - 1, "%s/post-down.d", tmpdir);
	if (mkdir(tmpstr, 0700) < 0) {
		printf("Unable to create %s/post-down.d: %s", tmpdir, strerror(errno));
		err = -1;
		goto out_clean;
	}

	printf("Testing error conditions\n");

	printf("Init nozzle device with no path\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		err = -1;
		goto out_clean;
	}

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_run_updown sanity check failed\n");
		err = -1;
		goto out_clean;
	}

	nozzle_close(nozzle);

	printf("Init nozzle device with path\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, tmpdir);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		err = -1;
		goto out_clean;
	}

	printf("Testing invalid nozzle handle\n");

	err = nozzle_run_updown(NULL, NOZZLE_POSTDOWN, &error_string);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_run_updown sanity check failed\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing invalid action\n");

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN + 1, &error_string);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_run_updown sanity check failed\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing invalid error string\n");

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN + 1, NULL);
	if ((!err) || (errno != EINVAL)) {
		printf("nozzle_run_updown sanity check failed\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing interface pre-up/up/down/post-down (no scripts installed)\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (!err) {
		printf("nozzle_run_updown failed to detect lack of script in pre-up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (!err) {
		printf("nozzle_run_updown failed to detect lack of script in up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (!err) {
		printf("nozzle_run_updown failed to detect lack of script in down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (!err) {
		printf("nozzle_run_updown failed to detect lack of script in post-down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	printf("Populating test dir with fail scripts\n");

	snprintf(srcfile, sizeof(srcfile) - 1, "%s/nozzle_run_updown_exit_false", ABSSRCDIR);

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/pre-up.d/%s", tmpdir, device_name);
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/up.d/%s", tmpdir, device_name);
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/down.d/%s", tmpdir, device_name);
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/post-down.d/%s", tmpdir, device_name);
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing interface pre-up/up/down/post-down (FAIL scripts installed)\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err != -2) {
		printf("nozzle_run_updown failed to detect script failure in pre-up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err != -2) {
		printf("nozzle_run_updown failed to detect script failure in up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err != -2) {
		printf("nozzle_run_updown failed to detect script failure in down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err != -2) {
		printf("nozzle_run_updown failed to detect script failure in post-down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	printf("Populating test dir with true scripts\n");

	snprintf(srcfile, sizeof(srcfile) - 1, "%s/nozzle_run_updown_exit_true", ABSSRCDIR);

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/pre-up.d/%s", tmpdir, device_name);
	if (unlink(dstfile) < 0) {
		printf("unable to remove old symlink\n");
		err = -1;
		goto out_clean;
	}
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/up.d/%s", tmpdir, device_name);
	if (unlink(dstfile) < 0) {
		printf("unable to remove old symlink\n");
		err = -1;
		goto out_clean;
	}
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/down.d/%s", tmpdir, device_name);
	if (unlink(dstfile) < 0) {
		printf("unable to remove old symlink\n");
		err = -1;
		goto out_clean;
	}
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	snprintf(dstfile, sizeof(dstfile) - 1, "%s/post-down.d/%s", tmpdir, device_name);
	if (unlink(dstfile) < 0) {
		printf("unable to remove old symlink\n");
		err = -1;
		goto out_clean;
	}
	if (link(srcfile, dstfile) < 0) {
		printf("unable to create symlink\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing interface pre-up/up/down/post-down (TRUE scripts installed)\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err) {
		printf("nozzle_run_updown failed to execute true script in pre-up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err) {
		printf("nozzle_run_updown failed to execute true script in up.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown failed to execite true script in down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}

	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown failed to execute true script in post-down.d\n");
		err = -1;
		goto out_clean;
	} else {
		if (error_string) {
			free(error_string);
			error_string = NULL;
		}
	}


out_clean:
	if (tmpdir) {
		snprintf(tmpstr, sizeof(tmpstr) - 1, "rm -rf %s", tmpdir);
		printf("Removing temporary dir: %s\n", tmpstr);
		if (execute_bin_sh_command(tmpstr, &error_string)) {
			printf("Error removing directory: %s\n", error_string);
		}
		if (error_string) {
			free(error_string);
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
