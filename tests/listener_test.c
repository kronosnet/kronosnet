#include "config.h"

#include <stdlib.h>
#include <sys/epoll.h>

#include "knethandle.h"
#include "utils.h"

#define KNET_TEST_PORT 50000

static knet_handle_t knet_h;
struct knet_listener *listener;
struct knet_host *host;

static void test_add_listener(void)
{
	struct sockaddr_in *address;

	listener = malloc(sizeof(struct knet_listener));

	if (listener == NULL) {
		log_error("Unable to create listener");
		exit(EXIT_FAILURE);
	}

	memset(listener, 0, sizeof(struct knet_listener));

	address = (struct sockaddr_in *) &listener->address;

	address->sin_family = AF_INET;
	address->sin_port = htons(KNET_TEST_PORT);
	address->sin_addr.s_addr = INADDR_ANY;

	if (knet_listener_add(knet_h, listener) != 0) {
		log_error("Unable to add listener");
		exit(EXIT_FAILURE);
	}
}

static void test_add_host(void)
{
	host = malloc(sizeof(struct knet_host));

	if (host == NULL) {
		log_error("Unable to allocate new knet_host");
		exit(EXIT_FAILURE);
	}

	memset(host, 0, sizeof(struct knet_host));

	host->link = malloc(sizeof(struct knet_link));

	if (host->link == NULL) {
		log_error("Unable to allocate new knet_link");
		exit(EXIT_FAILURE);
	}

	memset(host->link, 0, sizeof(struct knet_link));
	host->link->sock = listener->sock;

	if (knet_host_add(knet_h, host) != 0) {
		log_error("Unable to add host to knet_handle");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	int err;
	struct epoll_event ev;

	if ((knet_h = knet_handle_new()) == NULL) {
		log_error("Unable to create new knet_handle_t");
		exit(EXIT_FAILURE);
	}

	log_info("Adding listener to handle");
	test_add_listener();

	memset(&ev, 0, sizeof(struct epoll_event));

	/* don't try this at home :) */
	log_info("Checking listener file descriptor");
	err = epoll_ctl(knet_h->epollfd, EPOLL_CTL_ADD, listener->sock, &ev);

	if (err != -1) {
		log_error("Listener file descriptor not found in epollfd");
		exit(EXIT_FAILURE);
	}

	log_info("Adding host to handle");
	test_add_host();

	log_info("Removing listener (with active links)");
	err = knet_listener_remove(knet_h, listener);

	if (err != -EBUSY) {
		log_error("Listener socket should be in use");
		exit(EXIT_FAILURE);
	}

	log_info("Removing host from handle");
	err = knet_host_remove(knet_h, host);

	if (err != 0) {
		log_error("Unable to remove host from knet_handle");
		exit(EXIT_FAILURE);
	}

	log_info("Removing listener");
	err = knet_listener_remove(knet_h, listener);

	if (err != 0) {
		log_error("Unable to remove listener from knet_handle");
		exit(EXIT_FAILURE);
	}

	log_info("Checking listener file descriptor");
	err = epoll_ctl(knet_h->epollfd, EPOLL_CTL_DEL, listener->sock, &ev);

	if (err != -1) {
		log_error("Listener file was present in epollfd");
		exit(EXIT_FAILURE);
	}

	return 0;
}
