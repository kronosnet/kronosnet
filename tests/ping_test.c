#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

struct knet_host *host_head = NULL;

static in_port_t tok_inport(char *str)
{
	int value = atoi(str);

	if ((value < 0) || (value > UINT16_MAX))
		return 0;

	return (in_port_t) value;
}

static int tok_inaddrport(char *str, struct sockaddr_in *addr)
{
	char *strhost, *strport, *tmp = NULL;

	strhost = strtok_r(str, ":", &tmp);
	strport = strtok_r(NULL, ":", &tmp);

	if (strport == NULL)
		addr->sin_port = htons(KNET_RING_DEFPORT);
	else
		addr->sin_port = htons(tok_inport(strport));

	return inet_aton(strhost, &addr->sin_addr);
}

static void wait_data_loop(int sockfd, time_t timeout)
{
	int err;
	fd_set rfds;
	struct timeval tv;
	ssize_t len;
	struct knet_frame recv_frame;

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	while ((tv.tv_sec > 0) || (tv.tv_usec > 0)) {
		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		err = select(sockfd + 1, &rfds, NULL, NULL, &tv);

		if (err == -1) {
			log_error("Unable to wait for ping messages");
			exit(EXIT_FAILURE);
		} else if (!FD_ISSET(sockfd, &rfds)) {
			continue;
		}

		len = knet_dispatch(sockfd, &recv_frame, sizeof(struct knet_frame));

		if ((len > 0) && (recv_frame.type == KNET_FRAME_PONG)) {
			log_info("Pong received!");
		}
	}
}

static void print_usage(char *name)
{
	printf("usage: %s <localip>[:<port>] <remoteip>[:port] [...]\n", name);
	printf("example: %s 0.0.0.0 192.168.0.2\n", name);
}

static int start_server(char *addrstring)
{
	int err, sockfd;
	struct sockaddr_in address;

	address.sin_family = AF_INET;
	err = tok_inaddrport(addrstring, &address);

	if (err < 0) {
		log_error("Unable to convert ip address: %s", addrstring);
		exit(EXIT_FAILURE);
	}

	sockfd = knet_bind((struct sockaddr *) &address, sizeof(struct sockaddr_in));

	if (sockfd < 0) {
		log_error("Unable to bind knet");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

static void create_hosts(int sockfd, int hostnum, char *hoststring[])
{
	int err, i;
	struct knet_host *host;

	for (i = 0; i < hostnum; i++) {
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

		host->link->sock = sockfd;
		host->link->address.ss_family = AF_INET;

		err = tok_inaddrport(hoststring[i], (struct sockaddr_in *) &host->link->address);

		if (err < 0) {
			log_error("Unable to convert ip address: %s", hoststring[i]);
			exit(EXIT_FAILURE);
		}

		host->next = host_head;
		host_head = host;
	}
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct knet_frame send_frame;

	if (argc < 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	sockfd = start_server(argv[1]);
	create_hosts(sockfd, argc - 2, &argv[2]);

	send_frame.magic = htonl(KNET_FRAME_MAGIC);
	send_frame.version = KNET_FRAME_VERSION;
	send_frame.type = KNET_FRAME_PING;

	while (1) {
		log_info("Sending pings");

		knet_send(host_head, &send_frame, sizeof(struct knet_frame));
		wait_data_loop(sockfd, 5); /* wait data for 5 seconds */
	}

	/* FIXME: allocated hosts should be free'd */

	return 0;
}
