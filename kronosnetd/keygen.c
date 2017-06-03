/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libknet.h>

static char *output_file = NULL;
static ssize_t keylen = KNET_MAX_KEY_LEN;

static void print_usage(void)
{
	printf("\nUsage:\n\n");
	printf("knet-keygen -o <output_file> [-s <size>]\n\n");
};

#define OPTION_STRING "ho:s:"

static int read_arguments(int argc, char **argv)
{
	int cont = 1;
	int optchar;

	while (cont) {
		optchar = getopt(argc, argv, OPTION_STRING);

		switch (optchar) {

		case 'o':
			output_file = strdup(optarg);
			if (!output_file) {
				fprintf(stderr, "Error: Unable to allocate memory\n");
				return -1;
			}
			if (strlen(output_file) > PATH_MAX) {
				fprintf(stderr, "Seriously? WTF\n");
				return -1;
			}
			break;

		case 's':
			keylen = atoi(optarg);
			if ((keylen < KNET_MIN_KEY_LEN) || (keylen > KNET_MAX_KEY_LEN)) {
				fprintf(stderr, "Error: Key size should be a value between %d and %d (default) included\n",
					KNET_MIN_KEY_LEN, KNET_MAX_KEY_LEN);
				return -1;
			}
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;

		case EOF:
			cont = 0;
			break;

		default:
			fprintf(stderr, "Error: unknown option: %c\n", optchar);
			print_usage();
			return -1;
			break;

		}
	}
	if (!output_file) {
		fprintf(stderr, "Error: no output file specified\n");
		print_usage();
		return -1;
	}
	return 0;
}

int main (int argc, char *argv[])
{
	int ret = 0;
	int fd = -1;
	ssize_t res;
	ssize_t bytes_read = 0;
	char *keybuf = NULL;

	printf (PACKAGE " key generator.\n");

	if (read_arguments(argc, argv) < 0) {
		goto exit_error;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "Error: Authorization key must be generated as root user.\n");
		goto exit_error;
	}

	fd = open ("/dev/random", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: Unable to open /dev/random\n");
		goto exit_error;
	}

	keybuf = malloc(keylen);
	if (!keybuf) {
		fprintf(stderr, "Error: Unable to allocate memory for key\n");
		goto exit_error;
	}

	printf("Gathering %zd bytes for key from /dev/random.\n", keylen);
	printf("This process might take a long time due the amount on entropy required\n");
	printf("Press keys on your keyboard, perform any kind of disk I/O and/or network to generate entropy faster.\n");

keep_reading:
	res = read(fd, &keybuf[bytes_read], keylen - bytes_read);
	if (res == -1) {
		fprintf(stderr, "Error: Unable to read from /dev/random.\n");
		goto exit_error;
	}
	bytes_read += res;
	if (bytes_read != keylen) {
		printf("bytes read = %zd, missing = %zd.\n", bytes_read, keylen - bytes_read);
		goto keep_reading;
	}
	close (fd);
	fd = -1;

	fd = open (output_file, O_CREAT|O_WRONLY, 600);
	if (fd == -1) {
		fprintf(stderr, "Error: Could not create %s\n", output_file);
		goto exit_error;
	}

	/*
	 * Make sure file is owned by root and mode 0400
	 */
	if (fchown(fd, 0, 0)) {
		fprintf(stderr, "Error: Could not set uid 0 (root) and gid 0 (root) on keyfile %s\n", output_file);
		goto exit_error;
	}
	if (fchmod(fd, 0400)) {
		fprintf(stderr, "Error: Could not set read-only permissions on keyfile %s\n", output_file);
		goto exit_error;
	}

	printf("Writing private key to %s\n", output_file);

	if (write(fd, keybuf, keylen) != keylen) {
		fprintf(stderr, "Error: Could not write key to file %s\n", output_file);
		goto exit_error;
	}

	printf("Done.\n");
	printf("Please copy this file in " DEFAULT_CONFIG_DIR "/cryptokeys.d/<knet_interface_name>\n");
	printf("on all nodes participating in the same kronosnet instance\n");

exit_clean:
	if (output_file)
		free(output_file);
	if (keybuf)
		free(keybuf);
	if (fd > -1)
		close(fd);

	return ret;

exit_error:
	ret = -1;
	goto exit_clean;
}
