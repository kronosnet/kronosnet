#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>

#include "ring.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int err, sockfd;
	struct sockaddr_in loopback;
	struct knet_host *host;
	struct knet_frame send_frame, recv_frame;

	loopback.sin_family = AF_INET;
	loopback.sin_addr.s_addr = htonl(INADDR_ANY);
	loopback.sin_port = htons(KNET_RING_DEFPORT);

	log_info("Opening ring socket");
	sockfd = knet_bind((struct sockaddr *) &loopback, sizeof(struct sockaddr_in));

	if (sockfd < 0) {
		log_error("Unable to open ring socket");
		exit(EXIT_FAILURE);
	}

	log_info("Allocating new knet_host");
	host = malloc(sizeof(struct knet_host));

	if (host == NULL) {
		log_error("Unable to allocate ring");
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

	loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	memmove(&host->link->address, &loopback, sizeof(struct sockaddr_in));

	memset(&recv_frame, 0, sizeof(struct knet_frame));
	memset(&send_frame, 0, sizeof(struct knet_frame));

	send_frame.magic = KNET_FRAME_MAGIC;
	send_frame.version = KNET_FRAME_VERSION;
	send_frame.type = KNET_FRAME_PING;

	log_info("Writing to socket");
	knet_send(host, &send_frame, sizeof(struct knet_frame));

	log_info("Waiting for delivery");
	usleep(100000); /* wait 0.1 seconds */

	log_info("Reading data from socket");
	err = recv(host->link->sock,
			&recv_frame, sizeof(struct knet_frame), MSG_DONTWAIT);

	if (err != sizeof(struct knet_frame)) {
		log_error("Unable to read from ring socket");
		exit(EXIT_FAILURE);
	}

	log_info("Comparing sent data and received data");
	if (memcmp(&send_frame, &recv_frame, sizeof(struct knet_frame)) != 0) {
		errno = EINVAL;
		log_error("Received message mismatch");
		exit(EXIT_FAILURE);
	}

	log_info("Closing sockets");
	close(sockfd);

	free(host);
	host = NULL;

	return 0;
}
