#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "netutils.h"
#include "utils.h"

#define ADDRTOSTR_HOST_LEN 256
#define ADDRTOSTR_PORT_LEN 24

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

int addrtostr(const struct sockaddr *sa, socklen_t salen, char *buf[2])
{
	int ret;

	buf[0] = malloc(ADDRTOSTR_HOST_LEN + ADDRTOSTR_PORT_LEN);
	buf[1] = buf[0] + ADDRTOSTR_HOST_LEN;

	ret = getnameinfo(sa, salen, buf[0], ADDRTOSTR_HOST_LEN,
				buf[1], ADDRTOSTR_PORT_LEN,
				NI_NUMERICHOST | NI_NUMERICSERV);

	if (ret != 0) {
		buf[0] = '\0';
		buf[1] = '\0';
	} else {
		buf[0][ADDRTOSTR_HOST_LEN - 1] = '\0';
		buf[1][ADDRTOSTR_PORT_LEN - 1] = '\0';
	}

	return ret;
}

void addrtostr_free(char *str[2])
{
	if (str[0] != NULL)
		free(str[0]);
}
