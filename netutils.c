#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "netutils.h"
#include "utils.h"

int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(host, port, &hints, &result);

	if (ret == 0) {
		memmove(sa, result->ai_addr,
			(salen < result->ai_addrlen) ? salen : result->ai_addrlen);
	}

	freeaddrinfo(result);

	return ret;
}
