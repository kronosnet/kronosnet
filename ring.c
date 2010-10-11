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
	err = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

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

inline ssize_t knet_ring_send(int sockfd, struct knet_ring *ring, struct knet_frame *frame, size_t len)
{
	return sendto(sockfd, frame, len, MSG_DONTWAIT,
		(struct sockaddr *) &ring->info, sizeof(ring->info));
}
