/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "libknet.h"
#include "test-common.h"

static int _read_pipe(int fd, char **file, size_t *length)
{
	char buf[4096];
	int n;
	int done = 0;

	*file = NULL;
	*length = 0;

	memset(buf, 0, sizeof(buf));

	while (!done) {

		n = read(fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;

			if (*file)
				free(*file);

			return n;
		}

		if (n == 0 && (!*length))
			return 0;

		if (n == 0)
			done = 1;

		if (*file)
			*file = realloc(*file, (*length) + n + done);
		else
			*file = malloc(n + done);

		if (!*file)
			return -1;

		memcpy((*file) + (*length), buf, n);
		*length += (done + n);
	}

	/* Null terminator */
	(*file)[(*length) - 1] = 0;

	return 0;
}

int execute_shell(const char *command, char **error_string)
{
	pid_t pid;
	int status, err = 0;
	int fd[2];
	size_t size = 0;

	if ((command == NULL) || (!error_string)) {
		errno = EINVAL;
		return FAIL;
	}

	*error_string = NULL;

	err = pipe(fd);
	if (err)
		goto out_clean;

	pid = fork();
	if (pid < 0) {
		err = pid;
		goto out_clean;
	}

	if (pid) { /* parent */

		close(fd[1]);
		err = _read_pipe(fd[0], error_string, &size);
		if (err)
			goto out_clean0;

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			err = -1;
			goto out_clean0;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			err = WEXITSTATUS(status);
			goto out_clean0;
		}
		goto out_clean0;
	} else { /* child */
		close(0);
		close(1);
		close(2);

		close(fd[0]);
		dup2(fd[1], 1);
		dup2(fd[1], 2);
		close(fd[1]);

		execlp("/bin/sh", "/bin/sh", "-c", command, NULL);
		exit(FAIL);
	}

out_clean:
	close(fd[1]);
out_clean0:
	close(fd[0]);

	return err;
}

int need_root(void)
{
	if (geteuid() != 0) {
		printf("This test requires root privileges\n");
		exit(SKIP);
	}

	return PASS;
}

int setup_logpipes(int *logfds)
{
	if (pipe2(logfds, O_CLOEXEC | O_NONBLOCK) < 0) {
		printf("Unable to setup logging pipe\n");
		exit(FAIL);
	}

	return PASS;
}

void close_logpipes(int *logfds)
{
	close(logfds[0]);
	logfds[0] = 0;
	close(logfds[1]);
	logfds[1] = 0;
}

void flush_logs(int logfd, struct _IO_FILE *std)
{
	struct knet_log_msg msg;
	size_t bytes_read;
	int len;

next:
	len = 0;
	bytes_read = 0;
	memset(&msg, 0, sizeof(struct knet_log_msg));

	while (bytes_read < sizeof(struct knet_log_msg)) {
		len = read(logfd, &msg + bytes_read,
			   sizeof(struct knet_log_msg) - bytes_read);
		if (len <= 0) {
			return;
		}
		bytes_read += len;
	}

	if (len > 0) {
		fprintf(std, "knet logs: [%s] %s: %s\n",
			knet_log_get_loglevel_name(msg.msglevel),
			knet_log_get_subsystem_name(msg.subsystem),
			msg.msg);
		goto next;
	}
}
