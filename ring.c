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
	int err, sockfd, value;

	sockfd = socket(addr_info->sa_family, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		log_error("Unable to open netsocket error");
		return sockfd;
	}

	value = KNET_RING_RCVBUFF;
	err = setsockopt(sockfd,
			SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0) {
		log_error("Unable to set receive buffer");
	}

	value = fcntl(sockfd, F_GETFD, 0);

	if (value < 0) {
		log_error("Unable to get close-on-exec flag");
		goto exit_fail;
	}

	value |= FD_CLOEXEC;
	err = fcntl(sockfd, F_SETFD, value);

	if (err < 0) {
		log_error("Unable to set close-on-exec flag");
		goto exit_fail;
	}

	err = bind(sockfd, (struct sockaddr *) addr_info, addr_len);

	if (err < 0) {
		log_error("Unable to bind to ring socket");
		goto exit_fail;
	}

	return sockfd;

exit_fail:
	close(sockfd);
	return -1;
}

int knet_ring_connect(struct knet_ring *ring)
{
	ring->sockfd = socket(ring->info.ss_family, SOCK_DGRAM, 0);

	if (ring->sockfd < 0) {
		log_error("Unable create ring socket");
		return ring->sockfd;
	}

	if (connect(ring->sockfd, (struct sockaddr *) &ring->info,
						sizeof(ring->info)) != 0) {
		log_error("Unable to connect ring socket");
		goto exit_fail;
	}

	return ring->sockfd;

exit_fail:
	close(ring->sockfd);
	ring->sockfd = -1;

	return ring->sockfd;
}

void knet_ring_disconnect(struct knet_ring *ring)
{
	if (ring->sockfd > 0) {
		close(ring->sockfd);
		ring->sockfd = -1;
	}
}
