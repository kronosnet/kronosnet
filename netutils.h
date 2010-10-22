#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <sys/socket.h>

int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen);

#endif
