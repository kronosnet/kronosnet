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
		log_error("unable to wait for data");
		exit(-1);
	} else if (FD_ISSET(sock, &rfds)) {
		return 0;
	}

	return -1;
}

int main(void)
{
	int sock_srv, sock_cli, err;
	char recv_buf[64];
	struct knet_ring *test_ring;

	sock_srv = knet_ring_listen(KNET_RING_DEFPORT);

	if (sock_srv < 0) {
		log_error("unable to open ring socket");
		exit(-1);
	}

	test_ring = alloca(sizeof(struct knet_ring));

	test_ring->info.sa_family = AF_INET;
	test_ring->info.in.sin_port = htons(KNET_RING_DEFPORT);
	test_ring->info.in.sin_addr.s_addr = 0x0100007f; /*localhost */

	sock_cli = knet_ring_connect(test_ring);

	if (sock_cli < 0) {
		log_error("unable to connect ring socket");
		exit(-1);
	}

	err = write(sock_cli, test_msg, sizeof(test_msg));

	if (err != sizeof(test_msg)) {
		log_error("unable to write to ring socket");
		exit(-1);
	}

	err = wait_data(sock_srv, 5); /* 5 seconds timeout */

	if (err != 0) {
		log_error("unable to deliver data over ring socket");
		exit(-1);
	}

	err = read(sock_srv, recv_buf, sizeof(recv_buf));

	if (err != sizeof(test_msg)) {
		log_error("unable to read from ring socket");
		exit(-1);
	}

	if (memcmp(test_msg, recv_buf, sizeof(test_msg)) != 0) {
		errno = EINVAL;
		log_error("received message mismatch");
		exit(-1);
	}

	close(sock_srv);
	knet_ring_disconnect(test_ring);

	return 0;
}
