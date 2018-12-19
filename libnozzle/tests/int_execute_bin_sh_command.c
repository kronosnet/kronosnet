/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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
	int err = 0;
	char *error_string = NULL;

	printf("Testing execute_bin_sh_command\n");

	printf("command true\n");

	err = execute_bin_sh_command("true", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to execute true ?!?!\n");
		goto out_clean;
	}

	printf("command false\n");

	err = execute_bin_sh_command("false", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute false successfully?!?!\n");
		err = -1;
		goto out_clean;
	}

	printf("command that outputs to stdout (enforcing redirect)\n");

	err = execute_bin_sh_command("grep -h 2>&1", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	}

	printf("command that outputs to stderr\n");
	err = execute_bin_sh_command("grep -h", &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Can we really execute grep -h successfully?!?\n");
		err = -1;
		goto out_clean;
	}

	printf("Testing ERROR conditions\n");

	printf("empty command\n");
	err = execute_bin_sh_command(NULL, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if ((!err) || (errno != EINVAL)) {
		printf("execute_bin_sh_command returned incorrect error or incorrect errno!\n");
		err = -1;
		goto out_clean;
	}

	printf("empty error\n");
	err = execute_bin_sh_command("true", NULL);
	if ((!err) || (errno != EINVAL)) {
		printf("execute_bin_sh_command returned incorrect error or incorrect errno!\n");
		err = -1;
		goto out_clean;
	}

	err = 0;

out_clean:

	return err;
}

int main(void)
{
	need_root();

	if (test() < 0)
		return FAIL;

	return PASS;
}
