#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

#define HOST_LIST_SIZE 8192
#define HOST_LIST_LOOP 64

struct knet_host *host_list[HOST_LIST_SIZE];

static int host_loop(knet_handle_t knet_h, size_t *loopnum)
{
	struct knet_host *kh;

	knet_host_acquire(knet_h, &kh, 1);

	while (kh != NULL) {
		kh->active = 1;
		kh = kh->next;
		(*loopnum)++;
	}

	knet_host_release(knet_h);

	return 0;
}

int main(int argc, char *argv[])
{
	int i, j;
	size_t loopnum;
	knet_handle_t knet_h;
	

	knet_h = knet_handle_new();

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		host_list[i] = malloc(sizeof(struct knet_host));
		knet_host_add(knet_h, host_list[i]);
	}

	loopnum = 0;

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		for (j = 0; j < HOST_LIST_LOOP; j++) {
			host_loop(knet_h, &loopnum);
		}
		knet_host_remove(knet_h, host_list[i]);
	}

	for (i = 0; i < HOST_LIST_SIZE; i++) {
		free(host_list[i]);
		host_list[i] = NULL;
	}

	printf("loop count: %zu times\n", loopnum);

	return 0;
}
