#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "ring.h"
#include "utils.h"

int knet_ring_start(struct knet_ring *ring)
{
	int err, value;

	ring->sockfd = socket(ring->address.ss_family, SOCK_DGRAM, 0);

	if (ring->sockfd < 0) {
		log_error("Unable to open netsocket error");
		return ring->sockfd;
	}

	value = KNET_RING_RCVBUFF;
	err = setsockopt(ring->sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0)
		log_error("Unable to set receive buffer");

	value = fcntl(ring->sockfd, F_GETFD, 0);

	if (value < 0) {
		log_error("Unable to get close-on-exec flag");
		goto exit_fail;
	}

	value |= FD_CLOEXEC;
	err = fcntl(ring->sockfd, F_SETFD, value);

	if (err < 0) {
		log_error("Unable to set close-on-exec flag");
		goto exit_fail;
	}

	err = bind(ring->sockfd, (struct sockaddr *) &ring->address, sizeof(ring->address));

	if (err < 0) {
		log_error("Unable to bind to ring socket");
		goto exit_fail;
	}

	return ring->sockfd;

exit_fail:
	knet_ring_stop(ring);
	return -1;
}

void knet_ring_stop(struct knet_ring *ring)
{
	if (ring->sockfd < 0)
		return;

	close(ring->sockfd);
	ring->sockfd = -1;
}

inline ssize_t knet_ring_send(struct knet_ring *ring, struct knet_frame *frame, size_t len)
{
	ssize_t err, retval;
	struct knet_host *host;

	retval = len;

	for (host = ring->host; host != NULL; host = host->next) {
		err = sendto(ring->sockfd, frame, len, 0,
			(struct sockaddr *) &host->address, sizeof(struct sockaddr_storage));

		if (err != len)
			retval = err;
	}

	return retval;
}
