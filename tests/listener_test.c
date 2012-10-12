#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "libknet-private.h"

#define KNET_TEST_PORT 50000

static knet_handle_t knet_h;
struct knet_listener *listener;

static void test_add_listener(void)
{
	struct sockaddr_in *address;

	listener = malloc(sizeof(struct knet_listener));

	if (listener == NULL) {
		printf("Unable to create listener\n");
		exit(EXIT_FAILURE);
	}

	memset(listener, 0, sizeof(struct knet_listener));

	address = (struct sockaddr_in *) &listener->address;

	address->sin_family = AF_INET;
	address->sin_port = htons(KNET_TEST_PORT);
	address->sin_addr.s_addr = INADDR_ANY;

	if (knet_listener_add(knet_h, listener) != 0) {
		printf("Unable to add listener\n");
		exit(EXIT_FAILURE);
	}
}

static void test_add_host(void)
{
	struct knet_host *host;

	if (knet_host_add(knet_h, 1) != 0) {
		printf("Unable to add host to knet_handle\n");
		exit(EXIT_FAILURE);
	}

	knet_host_get(knet_h, 1, &host);

	host->link[0].sock = listener->sock;
	host->link[0].configured = 1;

	knet_host_release(knet_h, &host);
}

int main(int argc, char *argv[])
{
	int err, sock;
	struct epoll_event ev;
	struct knet_handle_cfg knet_handle_cfg;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0) {
		printf("Unable to create new socket\n");
		exit(EXIT_FAILURE);
	}

	memset(&knet_handle_cfg, 0, sizeof(struct knet_handle_cfg));
	knet_handle_cfg.fd = sock;
	knet_handle_cfg.node_id = 1;

	if ((knet_h = knet_handle_new(&knet_handle_cfg)) == NULL) {
		printf("Unable to create new knet_handle_t\n");
		exit(EXIT_FAILURE);
	}

	printf("Adding listener to handle\n");
	test_add_listener();

	memset(&ev, 0, sizeof(struct epoll_event));

	/* don't try this at home :) */
	err = epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, listener->sock, &ev);

	if (err != -1) {
		printf("Listener file descriptor not found in epollfd\n");
		exit(EXIT_FAILURE);
	}

	printf("Listener file descriptor was added to epollfd\n");

	printf("Adding host to handle\n");
	test_add_host();

	err = knet_listener_remove(knet_h, listener);

	if (err != -EBUSY) {
		printf("Listener socket should be in use\n");
		exit(EXIT_FAILURE);
	}

	printf("Unable to remove listener with active links\n");

	printf("Removing host from handle\n");
	err = knet_host_remove(knet_h, 1);

	if (err != 0) {
		printf("Unable to remove host from knet_handle\n");
		exit(EXIT_FAILURE);
	}

	printf("Removing listener\n");
	err = knet_listener_remove(knet_h, listener);

	if (err != 0) {
		printf("Unable to remove listener from knet_handle\n");
		exit(EXIT_FAILURE);
	}

	/* don't try this at home :) */
	err = epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, listener->sock, &ev);

	if (err != -1) {
		printf("Listener file was present in epollfd\n");
		exit(EXIT_FAILURE);
	}

	printf("Listener file descriptor was removed from epollfd\n");

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
