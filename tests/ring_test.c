#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>

#include "ring.h"
#include "utils.h"

int main(void)
{
	int srv_sockfd, err;
	struct sockaddr_in *ring_in, srv_sa;
	struct knet_ring *test_ring;
	struct knet_frame *send_frame, *recv_frame;

	srv_sa.sin_family = AF_INET;
	srv_sa.sin_port = htons(KNET_RING_DEFPORT );
	srv_sa.sin_addr.s_addr = htonl(INADDR_ANY);

	log_info("Opening ring socket");
	srv_sockfd = knet_ring_listen(
			(struct sockaddr *) &srv_sa, sizeof(srv_sa));

	if (srv_sockfd < 0) {
		log_error("Unable to open ring socket");
		exit(-1);
	}

	log_info("Allocating new ring");
	test_ring = alloca(sizeof(struct knet_ring));

	if (test_ring == 0) {
		log_error("Unable to allocate ring");
		exit(-1);
	}

	knet_ring_init(test_ring, AF_INET);

	ring_in = (struct sockaddr_in *) &test_ring->info;

	ring_in->sin_port = htons(KNET_RING_DEFPORT);
	ring_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	log_info("Allocating new send/recv knet frames");
	send_frame = alloca(sizeof(struct knet_frame));
	recv_frame = alloca(sizeof(struct knet_frame));

	if ((send_frame == 0) || (recv_frame == 0)) {
		log_error("Unable to allocate knet frames");
		exit(-1);
	}

	memset(recv_frame, 0, sizeof(struct knet_frame));
	memset(send_frame, 0, sizeof(struct knet_frame));

	send_frame->magic = KNET_FRAME_MAGIC;
	send_frame->version = KNET_FRAME_VERSION;
	send_frame->type = KNET_FRAME_PING;

	log_info("Writing to socket");
	err = knet_ring_send(test_ring, send_frame, sizeof(struct knet_frame));

	if (err != sizeof(struct knet_frame)) {
		log_error("Unable to write to ring socket");
		exit(-1);
	}

	log_info("Waiting for delivery");
	usleep(100000); /* wait 0.1 seconds */

	log_info("Reading data from socket");
	err = recv(srv_sockfd,
			recv_frame, sizeof(struct knet_frame), MSG_DONTWAIT);

	if (err != sizeof(struct knet_frame)) {
		log_error("Unable to read from ring socket");
		exit(-1);
	}

	log_info("Comparing sent data and received data");
	if (memcmp(send_frame, recv_frame, sizeof(struct knet_frame)) != 0) {
		errno = EINVAL;
		log_error("Received message mismatch");
		exit(-1);
	}

	log_info("Closing sockets");
	close(srv_sockfd);
	knet_ring_free(test_ring);

	return 0;
}
