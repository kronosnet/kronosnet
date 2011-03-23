#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "netutils.h"

static void check_ipv4(void)
{
	int err;
	char *buf[2];
	struct sockaddr_in addr, addrck;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	memset(&addrck, 0, sizeof(struct sockaddr_in));

	printf("Checking strtoaddr on 192.168.0.1:50000\n");

	addrck.sin_family = AF_INET;
	addrck.sin_addr.s_addr = htonl(0xc0a80001); /* 192.168.0.1 */
	addrck.sin_port = htons(50000);

	err = strtoaddr("192.168.0.1", "50000",
			(struct sockaddr *) &addr, sizeof(struct sockaddr_in));

	if (err != 0) {
		printf("Unable to convert 192.168.0.1:50000\n");
		exit(EXIT_FAILURE);
	}

	if (memcmp(&addr, &addrck, sizeof(struct sockaddr_in)) != 0) {
		errno = EINVAL;
		printf("Check on 192.168.0.1:50000 failed\n");
		exit(EXIT_FAILURE);
	}

	printf("Checking addrtostr on 192.168.0.1:50000\n");

	err = addrtostr((struct sockaddr *) &addrck,
					sizeof(struct sockaddr_in), buf);

	if (err != 0) {
		printf("Unable to convert 192.168.0.1:50000\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(buf[0], "192.168.0.1") != 0) {
		errno = EINVAL;
		printf("Wrong address conversion: %s\n", buf[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(buf[1], "50000") != 0) {
		errno = EINVAL;
		printf("Wrong port conversion: %s\n", buf[1]);
		exit(EXIT_FAILURE);
	}

	addrtostr_free(buf);
}

static void check_ipv6(void)
{
	int err;
	char *buf[2];
	struct sockaddr_in6 addr, addrck;

	memset(&addr, 0, sizeof(struct sockaddr_in6));
	memset(&addrck, 0, sizeof(struct sockaddr_in6));

	printf("Checking strtoaddr on [fd00::1]:50000\n");

	addrck.sin6_family = AF_INET6;
	addrck.sin6_addr.s6_addr16[0] = htons(0xfd00); /* fd00::1 */
	addrck.sin6_addr.s6_addr16[7] = htons(0x0001);
	addrck.sin6_port = htons(50000);

	err = strtoaddr("fd00::1", "50000",
			(struct sockaddr *) &addr, sizeof(struct sockaddr_in6));

	if (err != 0) {
		printf("Unable to convert [fd00::1]:50000\n");
		exit(EXIT_FAILURE);
	}

	if (memcmp(&addr, &addrck, sizeof(struct sockaddr_in6)) != 0) {
		errno = EINVAL;
		printf("Check on 192.168.0.1:50000 failed\n");
		exit(EXIT_FAILURE);
	}

	printf("Checking addrtostr on [fd00::1]:50000\n");

	err = addrtostr((struct sockaddr *) &addrck,
					sizeof(struct sockaddr_in6), buf);

	if (err != 0) {
		printf("Unable to convert 192.168.0.1:50000\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(buf[0], "fd00::1") != 0) {
		errno = EINVAL;
		printf("Wrong address conversion: %s\n", buf[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(buf[1], "50000") != 0) {
		errno = EINVAL;
		printf("Wrong port conversion: %s\n", buf[1]);
		exit(EXIT_FAILURE);
	}

	addrtostr_free(buf);
}

static void check_resolve(void)
{
	int err;
	struct sockaddr_in addr;

	printf("Checking host resolution\n");
	err = strtoaddr("localhost", "50000",
			(struct sockaddr *) &addr, sizeof(struct sockaddr_in));

	if (err == 0) {
		errno = EINVAL;
		printf("Host resolution should not be enabled\n");
		exit(EXIT_FAILURE);
	}

	printf("Checking port resolution\n");
	err = strtoaddr("127.0.0.1", "ssh",
			(struct sockaddr *) &addr, sizeof(struct sockaddr_in));

	if (err == 0) {
		errno = EINVAL;
		printf("Port resolution should not be enabled\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	int err;
	char *buf[2];
	struct sockaddr_storage address;

	if (argc == 1) { /* automated tests */
		check_ipv4();
		check_ipv6();
		check_resolve();
		exit(EXIT_SUCCESS);
	} else if (argc != 3) {
		printf("usage: %s [host] [port]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	err = strtoaddr(argv[1], argv[2], (struct sockaddr *) &address,
					sizeof(struct sockaddr_storage));

	if (err != 0) {
		printf("Unable to convert strings to sockaddr\n");
		exit(EXIT_FAILURE);
	}

	err = addrtostr((struct sockaddr *) &address,
			sizeof(struct sockaddr_storage), buf);

	if (err != 0) {
		printf("Unable to convert sockaddr to strings\n");
		exit(EXIT_FAILURE);
	}

	printf("host: %s port: %s\n", buf[0], buf[1]);
	addrtostr_free(buf);

	return 0;
}
