#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <sys/socket.h>

int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen);
int addrtostr(const struct sockaddr *sa, socklen_t salen, char *str[2]);
void addrtostr_free(char *str[2]);

#endif
