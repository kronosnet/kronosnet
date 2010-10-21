#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <sys/socket.h>

int strtoaddr(char *str, struct sockaddr *sa, socklen_t salen);

#endif
