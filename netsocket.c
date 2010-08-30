#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "netsocket.h"
#include "logging.h"
#include "utils.h"

int setup_net_listener(void)
{
	struct sockaddr_in6 addr;
	int rv, s, value;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		logt_print(LOG_INFO, "Unable to open netsocket error: %s\n",
				     strerror(errno));
		return s;
	}

	value = fcntl(s, F_GETFD, 0);
	if (value < 0) {
		logt_print(LOG_INFO, "Unable to get close-on-exec flag from netsocket error: %s\n",
				     strerror(errno));
		close(s);
		return value;
	}
	value |= FD_CLOEXEC;
	rv = fcntl(s, F_SETFD, value);
	if (rv < 0) {
		logt_print(LOG_INFO, "Unable to set close-on-exec flag from netsocket error: %s\n",
					strerror(errno));
		close(s);
		return rv;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = ntohs(DEFAULT_PORT);
	memcpy(&addr.sin6_addr, &in6addr_any, sizeof(struct in6_addr));

	rv = bind(s, (struct sockaddr *) &addr, sizeof(addr));
	if (rv < 0) {
		logt_print(LOG_INFO, "Unable to bind to netsocket error: %s\n",
				     strerror(errno));
		close(s);
		return rv;
	}

	return s;
}
