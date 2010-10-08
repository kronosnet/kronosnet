#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "ring.h"
#include "utils.h"


int knet_ring_listen(const struct sockaddr *addr_info, const size_t addr_len)
{
	int err, sock, value;

	sock = socket(addr_info->sa_family, SOCK_DGRAM, 0);

	if (sock < 0) {
		log_error("Unable to open netsocket error");
		return sock;
	}

	value = KNET_RING_RCVBUFF;
	err = setsockopt(sock,
			SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0) {
		log_error("Unable to set receive buffer");
	}

	value = fcntl(sock, F_GETFD, 0);

	if (value < 0) {
		log_error("Unable to get close-on-exec flag");
		goto exit_fail;
	}

	value |= FD_CLOEXEC;
	err = fcntl(sock, F_SETFD, value);

	if (err < 0) {
		log_error("Unable to set close-on-exec flag");
		goto exit_fail;
	}

	err = bind(sock, (struct sockaddr *) addr_info, addr_len);

	if (err < 0) {
		log_error("Unable to bind to ring socket");
		goto exit_fail;
	}

	return sock;

exit_fail:
	close(sock);
	return -1;
}

int knet_ring_connect(struct knet_ring *ring)
{
	ring->sock = socket(ring->info.ss_family, SOCK_DGRAM, 0);

	if (ring->sock < 0) {
		log_error("Unable create ring socket");
		return ring->sock;
	}

	if (connect(ring->sock, (struct sockaddr *) &ring->info,
						sizeof(ring->info)) != 0) {
		log_error("Unable to connect ring socket");
		goto exit_fail;
	}

	return ring->sock;

exit_fail:
	close(ring->sock);
	ring->sock = -1;

	return ring->sock;
}

void knet_ring_disconnect(struct knet_ring *ring)
{
	if (ring->sock > 0) {
		close(ring->sock);
		ring->sock = -1;
	}
}
