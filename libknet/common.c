#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "libknet-private.h"

int _fdset_cloexec(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= FD_CLOEXEC;

	if (fcntl(fd, F_SETFD, fdflags) < 0)
		return -1;

	return 0;
}

int _fdset_nonblock(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFD, fdflags) < 0)
		return -1;

	return 0;
}

int _dst_cache_update(knet_handle_t knet_h, uint16_t node_id)
{
	int write_retry = 0;

try_again:
	if (write(knet_h->pipefd[1], &node_id, sizeof(node_id)) != sizeof(node_id)) {
		if ((write_retry < 10) && ((errno = EAGAIN) || (errno = EWOULDBLOCK))) {
			write_retry++;
			goto try_again;
		} else {
			return -1;
		}
	}
	return 0;
}

