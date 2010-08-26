#include "config.h"

#include <unistd.h>
#include <errno.h>

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
