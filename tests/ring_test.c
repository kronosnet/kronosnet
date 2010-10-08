#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>

#include "ring.h"
#include "utils.h"

/*
static int wait_data(int sock, time_t sec)
{
	int err;
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	err = select(sock + 1, &rfds, NULL, NULL, &tv);

	if (err == -1) {
		log_error("Unable to wait for data");
		exit(-1);
	} else if (FD_ISSET(sock, &rfds)) {
		return 0;
	}

	errno = ENODATA;
	return -1;
}
*/
int main(void)
{
	int sock_srv, err;
	struct knet_ring *test_ring;
	struct knet_frame *send_frame, *recv_frame;
	struct sockaddr_in *ring_in, ring_listen;

	ring_listen.sin_family = AF_INET;
	ring_listen.sin_port = htons(KNET_RING_DEFPORT);
	ring_listen.sin_addr.s_addr = htonl(INADDR_ANY);

	log_info("Opening ring socket");
	sock_srv = knet_ring_listen(
			(struct sockaddr *) &ring_listen, sizeof(ring_listen));

	if (sock_srv < 0) {
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

	log_info("Reading data from socket");
	err = recvfrom(sock_srv, recv_frame,
			sizeof(struct knet_frame), MSG_DONTWAIT, 0, 0);

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
	close(sock_srv);
	knet_ring_free(test_ring);

	return 0;
}
