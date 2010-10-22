#include "config.h"

#include <unistd.h>

#include "netutils.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int ret;
	struct sockaddr_storage address;

	memset(&address, 0, sizeof(struct sockaddr_storage));
	ret = strtoaddr(argv[1], argv[2], (struct sockaddr *) &address, sizeof(struct sockaddr_storage));

	if (ret == 0) {
		write(1, &address, sizeof(struct sockaddr_storage));
	}

	return 0;
}
