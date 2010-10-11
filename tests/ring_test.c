#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>

#include "ring.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int err;
	struct sockaddr_in *addrtmp;
	struct knet_ring ring;
	struct knet_frame send_frame, recv_frame;

	addrtmp = (struct sockaddr_in *) &ring.address;

	addrtmp->sin_family = AF_INET;
	addrtmp->sin_addr.s_addr = htonl(INADDR_ANY);
	addrtmp->sin_port = htons(KNET_RING_DEFPORT);

	log_info("Opening ring socket");
	err = knet_ring_start(&ring);

	if (err < 0) {
		log_error("Unable to open ring socket");
		exit(EXIT_FAILURE);
	}

	log_info("Allocating new knet_host");
	ring.host = malloc(sizeof(struct knet_host));

	if (ring.host == NULL) {
		log_error("Unable to allocate ring");
		exit(EXIT_FAILURE);
	}

	memset(ring.host, 0, sizeof(struct knet_host));

	addrtmp = (struct sockaddr_in *) &ring.host->address;

	addrtmp->sin_family = AF_INET;
	addrtmp->sin_port = htons(KNET_RING_DEFPORT);
	addrtmp->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	memset(&recv_frame, 0, sizeof(struct knet_frame));
	memset(&send_frame, 0, sizeof(struct knet_frame));

	send_frame.magic = KNET_FRAME_MAGIC;
	send_frame.version = KNET_FRAME_VERSION;
	send_frame.type = KNET_FRAME_PING;

	log_info("Writing to socket");
	err = knet_ring_send(&ring, &send_frame, sizeof(struct knet_frame));

	if (err != sizeof(struct knet_frame)) {
		log_error("Unable to write to ring socket");
		exit(EXIT_FAILURE);
	}

	log_info("Waiting for delivery");
	usleep(100000); /* wait 0.1 seconds */

	log_info("Reading data from socket");
	err = recv(ring.sockfd,
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
	knet_ring_stop(&ring);

	free(ring.host);
	ring.host = NULL;

	return 0;
}
