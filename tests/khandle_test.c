#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

int my_action(struct knet_host *host, void *data);

int my_action(struct knet_host *host, void *data)
{
	host->active = 1;
	return 0;
}

#define HOST_LIST_SIZE 8192
#define HOST_LIST_LOOP 64

struct knet_host *host_list[HOST_LIST_SIZE];

int main(int argc, char *argv[])
{
	int i, j;
	knet_handle_t knet_h;

	knet_h = knet_handle_new();

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		host_list[i] = malloc(sizeof(struct knet_host));
		knet_host_add(knet_h, host_list[i]);
	}

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		for (j = 0; j < HOST_LIST_LOOP; j++)
			knet_host_foreach(knet_h, my_action, NULL);
		knet_host_remove(knet_h, host_list[i]);
	}

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		free(host_list[i]);
	}

	return 0;
}
