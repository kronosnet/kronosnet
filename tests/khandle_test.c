#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

static int my_action(struct knet_host *host, void *data)
{
	host->active = 1;
	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	knet_handle_t knet_h;
	struct knet_host *host;

	knet_h = knet_handle_new();

	for (i = 0; i < 1024; i++) {
		host = malloc(sizeof(struct knet_host));
		knet_host_add(knet_h, host);
	}

	for (i = 0; i < 4096 * 1024; i++) {
		knet_host_foreach(knet_h, my_action, NULL);
	}

	return 0;
}
