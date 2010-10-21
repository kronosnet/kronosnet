#include "config.h"

#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "netutils.h"
#include "utils.h"

#define STRTOADDR_BUFSIZE 48

int strtoaddr(char *str, struct sockaddr *sa, socklen_t salen)
{
	int ret;
	char *addr_p, *port_p;
	char addr_s[STRTOADDR_BUFSIZE];

	/* casting to specific structures */
	struct sockaddr_in *sin4_dst = (struct sockaddr_in *) sa;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *) sa;

	for (addr_p = str; isspace(*addr_p); addr_p++) {
		if (*addr_p == '\0') return -1; /* empty string */
	}

	if (*addr_p == '[') { /* format: [ipv6]:port */
		addr_p++;

		if ((port_p = strstr(addr_p, "]:")) == NULL)
			return -1;

		memset(addr_s, 0, STRTOADDR_BUFSIZE);
		strncpy(addr_s, addr_p, port_p - addr_p);

		ret = inet_pton(AF_INET6, addr_s, &sin6_dst->sin6_addr.s6_addr);

		if (ret != 1)
			return -1;

		port_p += 2;

		sin6_dst->sin6_family = AF_INET6;
		sin6_dst->sin6_port = htons(atoi(port_p));
	} else {
		ret = inet_pton(AF_INET6, addr_p, &sin6_dst->sin6_addr.s6_addr);

		if (ret == 1) { /* format: ipv6 */
			sin6_dst->sin6_family = AF_INET6;
			sin6_dst->sin6_port = 0;
			return 0;
		}

		port_p = strrchr(addr_p, ':');

		if (port_p != NULL) { /* format: ipv4:port */
			memset(addr_s, 0, STRTOADDR_BUFSIZE);
			strncpy(addr_s, addr_p, port_p - addr_p);

			ret = inet_pton(AF_INET, addr_s, &sin4_dst->sin_addr.s_addr);

			if (ret != 1)
				return -1;

			port_p += 1;

			sin4_dst->sin_family = AF_INET;
			sin4_dst->sin_port = htons(atoi(port_p));

			return 0;
		}

		ret = inet_pton(AF_INET, addr_p, &sin4_dst->sin_addr.s_addr);

		if (ret != 1)
			return -1;

		sin4_dst->sin_family = AF_INET;
		sin4_dst->sin_port = 0;
	}

	return 0;
}
