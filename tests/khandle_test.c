#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

#define HOST_LIST_SIZE 8192
#define HOST_LIST_LOOP 64

static int host_loop(knet_handle_t knet_h, struct knet_host *host, struct knet_host_search *search)
{
	host->active = 1;
	search->param1++;
	return KNET_HOST_FOREACH_NEXT;
}

int main(int argc, char *argv[])
{
	int sock, i, j;
	knet_handle_t knet_h;
	struct knet_host_search search;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0) {
		log_error("Unable to create new socket");
		exit(EXIT_FAILURE);
	}

	knet_h = knet_handle_new(sock);

	for (i = 0; i < HOST_LIST_SIZE; i++)
		knet_host_add(knet_h, i);

	search.param1 = 0;

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		for (j = 0; j < HOST_LIST_LOOP; j++) {
			knet_host_foreach(knet_h, host_loop, &search);
		}
		knet_host_remove(knet_h, i);
	}

	printf("Loop count: %u times\n", (unsigned int) search.param1);

	if (knet_handle_free(knet_h) != 0) {
		log_error("Unable to free knet_handle");
		exit(EXIT_FAILURE);
	}

	return 0;
}
