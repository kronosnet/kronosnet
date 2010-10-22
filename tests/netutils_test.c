#include "config.h"

#include <stdlib.h>
#include <unistd.h>

#include "netutils.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int err;
	char *buf[2];
	struct sockaddr_storage address;

	if (argc != 3) {
		printf("usage: %s [host] [port]\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	err = strtoaddr(argv[1], argv[2], (struct sockaddr *) &address,
					sizeof(struct sockaddr_storage));

	if (err != 0) {
		log_error("Unable to convert strings to sockaddr");
		exit(EXIT_FAILURE);
	}

	err = addrtostr((struct sockaddr *) &address,
			sizeof(struct sockaddr_storage), buf);

	if (err != 0) {
		log_error("Unable to convert sockaddr to strings");
		exit(EXIT_FAILURE);
	}

	printf("host: %s port: %s\n", buf[0], buf[1]);
	addrtostr_free(buf);

	return 0;
}
