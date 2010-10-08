#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>

#include "ring.h"
#include "utils.h"


static char test_msg[] = "HelloWorld01234567890";


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

	return -1;
}

int main(void)
{
	int sock_srv, sock_cli, err;
	char recv_buff[64];
	struct knet_ring *test_ring;
	struct sockaddr_in *ring_in, ring_listen;

	ring_listen.sin_family = AF_INET;
	ring_listen.sin_port = htons(KNET_RING_DEFPORT);
	ring_listen.sin_addr.s_addr = INADDR_ANY;

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

	memset(test_ring, 0, sizeof(struct knet_ring));
	ring_in = (struct sockaddr_in *) &test_ring->info;

	ring_in->sin_family = AF_INET;
	ring_in->sin_port = htons(KNET_RING_DEFPORT);
	ring_in->sin_addr.s_addr = htonl(INADDR_LOOPBACK); /*localhost */

	log_info("Connecting ring socket");
	sock_cli = knet_ring_connect(test_ring);

	if (sock_cli < 0) {
		log_error("Unable to connect ring socket");
		exit(-1);
	}

	log_info("Writing to socket");
	err = write(sock_cli, test_msg, sizeof(test_msg));

	if (err != sizeof(test_msg)) {
		log_error("Unable to write to ring socket");
		exit(-1);
	}

	log_info("Waiting data from socket");
	err = wait_data(sock_srv, 5); /* 5 seconds timeout */

	if (err != 0) {
		log_error("Unable to deliver data over ring socket");
		exit(-1);
	}

	log_info("Reading data from socket");
	err = read(sock_srv, recv_buff, sizeof(recv_buff));

	if (err != sizeof(test_msg)) {
		log_error("Unable to read from ring socket");
		exit(-1);
	}

	log_info("Comparing sent data and received data");
	if (memcmp(test_msg, recv_buff, sizeof(test_msg)) != 0) {
		errno = EINVAL;
		log_error("Received message mismatch");
		exit(-1);
	}

	log_info("Closing sockets");
	close(sock_srv);
	knet_ring_disconnect(test_ring);

	return 0;
}
