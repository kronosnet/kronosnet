#include "config.h"

#include <unistd.h>
#include <fcntl.h>

#include "utils.h"

int utils_debug = 0;
int utils_syslog = 1;

int knet_fdset_cloexec(int fd)
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
