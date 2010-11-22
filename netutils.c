#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "netutils.h"
#include "utils.h"

#define ADDRTOSTR_HOST_LEN 256
#define ADDRTOSTR_PORT_LEN 24

static int is_v4_mapped(struct sockaddr *sa, socklen_t salen)
{
	char map[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) sa;
	return memcmp(&addr6->sin6_addr, map, 12);
}

int cmpaddr(struct sockaddr *sa1, socklen_t salen1,
	    struct sockaddr *sa2, socklen_t salen2)
{
	int sa1_offset = 0, sa2_offset = 0;
	struct sockaddr_in6 *sa1_addr6 = (struct sockaddr_in6 *)sa1;
	struct sockaddr_in6 *sa2_addr6 = (struct sockaddr_in6 *)sa2;
	struct sockaddr_in *sa1_addr = (struct sockaddr_in *)sa1;
	struct sockaddr_in *sa2_addr = (struct sockaddr_in *)sa2;
	char *addr1, *addr2;

	if (sa1->sa_family == sa2->sa_family)
		return memcmp(sa1, sa2, salen1);

	if (sa1->sa_family == AF_INET6) {
		if (is_v4_mapped(sa1, salen1))
			return 1;

		addr1 = (char *)&sa1_addr6->sin6_addr;
		sa1_offset = 12;
	} else
		addr1 = (char *)&sa1_addr->sin_addr;

	if (sa2->sa_family == AF_INET6) {
		if (is_v4_mapped(sa2, salen2))
			return 1;

		addr2 = (char *)&sa2_addr6->sin6_addr;  
		sa2_offset = 12;
	} else
		addr2 = (char *)&sa2_addr->sin_addr; 

	return memcmp(addr1+sa1_offset, addr2+sa2_offset, 4);
}

int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	ret = getaddrinfo(host, port, &hints, &result);

	if (ret != 0) {
		errno = EINVAL;
		return -1;
	}

	memmove(sa, result->ai_addr,
		(salen < result->ai_addrlen) ? salen : result->ai_addrlen);

	freeaddrinfo(result);

	return ret;
}

int addrtostr(const struct sockaddr *sa, socklen_t salen, char *buf[2])
{
	int ret;

	buf[0] = malloc(ADDRTOSTR_HOST_LEN + ADDRTOSTR_PORT_LEN);

	if (buf[0] == NULL)
		return -1;

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
