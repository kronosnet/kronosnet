#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <arpa/inet.h>

#include "ring.h"
#include "utils.h"

static in_port_t tok_inport(char *str)
{
	int value = atoi(str);

	if ((value < 0) || (value > UINT16_MAX))
		return 0;

	return (in_port_t) value;
}

static int tok_inaddrport(char *str, struct sockaddr_in *addr)
{
	char *strhost, *strport, *tmp;

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

		err =
		    recv(sockfd, &recv_frame, sizeof(recv_frame),
			 MSG_DONTWAIT);

		if (err != sizeof(recv_frame)) {
			if (errno == 0)
				errno = EBADMSG;
			log_error("Received ping was too short");
		} else {
			log_info("Ping successfully received!");
		}
	}
}

static void print_usage(char *name)
{
	printf("usage: %s <port> <remoteip>[:port] [...]\n", name);
}

int main(int argc, char *argv[])
{
	int err, i;
	struct knet_ring ring;
	struct knet_host *host;
	struct knet_frame send_frame;
	struct sockaddr_in *addrtmp;

	if (argc < 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	addrtmp = (struct sockaddr_in *) &ring.address;

	addrtmp->sin_family = AF_INET;
	addrtmp->sin_addr.s_addr = htonl(INADDR_ANY);
	addrtmp->sin_port = htons(tok_inport(argv[1]));

	err = knet_ring_start(&ring);

	if (err < 0) {
		log_error("Unable to prepare server");
		exit(EXIT_FAILURE);
	}

	ring.host = NULL;

	for (i = 2; i < argc; i++) {
		host = malloc(sizeof(struct knet_host));

		if (host == NULL) {
			log_error("Unable to allocate new knet_host");
			exit(EXIT_FAILURE);
		}

		memset(host, 0, sizeof(struct knet_host));

		/* push new host to the front */
		host->next = ring.host;
		ring.host = host;

		addrtmp = (struct sockaddr_in *) &ring.host->address;
		addrtmp->sin_family = AF_INET;

		err = tok_inaddrport(argv[i], addrtmp);

		if (err < 0) {
			log_error("Unable to convert ip address: %s", argv[i]);
			exit(EXIT_FAILURE);
		}
	}

	send_frame.magic = KNET_FRAME_MAGIC;
	send_frame.version = KNET_FRAME_VERSION;
	send_frame.type = KNET_FRAME_PING;

	while (1) {
		log_info("Sending ping");

		err = knet_ring_send(&ring, &send_frame, sizeof(send_frame));

		if (err != sizeof(struct knet_frame)) {
			log_error("Unable to send ping");
			exit(EXIT_FAILURE);
		}

		wait_data_loop(ring.sockfd, 5); /* wait data for 5 seconds */
	}

	/* FIXME: allocated hosts should be free'd */

	log_info("Closing sockets");
	knet_ring_stop(&ring);

	return 0;
}
