#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

int do_read(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == -1 && errno == EINTR)
			continue;
		if ((rv == 0) || (rv == -1))
			return -1;
		off += rv;
	}
	return 0;
}

int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0)
		return rv;
	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

int str_explode(char *src, char **dest, int *pos)
{
	char c;
	int status;
	int dest_pos;

	status = 0;
	dest_pos = 0;

	if (*dest == NULL) {
		*dest = strdup(src);
		if (*dest == NULL) {
			return -2;
		}
	}

	while (status != 2) {
		c = src[*pos];

		switch (status) {
		case 0:
			if (c == '\0') {
				free(*dest);
				*dest = NULL;
				return -1;
			} else if (!(c == ' ' || c == '\t')) {
				status = 1;
			} else {
				(*pos)++;
			}
		break;
		case 1:
			if (c == '\0') {
				(*dest)[dest_pos++] = '\0';
				status = 2;
			} else if (c == ' ' || c == '\t') {
				(*dest)[dest_pos++] = '\0';
				(*pos)++;
				status = 2;
			} else {
				(*dest)[dest_pos++] = c;
				(*pos)++;
			}
		break;
		}
	}

	return 0;
}
