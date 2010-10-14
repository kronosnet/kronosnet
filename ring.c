#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>

#include "ring.h"
#include "utils.h"

int knet_bind(struct sockaddr *address, socklen_t addrlen)
{
	int sockfd, err, value;

	sockfd = socket(address->sa_family, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		log_error("Unable to open netsocket error");
		return sockfd;
	}

	value = KNET_RING_RCVBUFF;
	err = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0)
		log_error("Unable to set receive buffer");

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

	err = bind(sockfd, address, addrlen);

	if (err < 0) {
		log_error("Unable to bind to ring socket");
		goto exit_fail;
	}

	return sockfd;

exit_fail:
	close(sockfd);
	return -1;
}

ssize_t knet_dispatch(int sockfd, struct knet_frame *frame, size_t len)
{
	ssize_t ret;
	struct sockaddr_storage address;
	socklen_t addrlen;

	addrlen = sizeof(struct sockaddr_storage);

	ret = recvfrom(sockfd, frame,
		len, MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (ret <= 0)
		return ret;

	if (ret < sizeof(struct knet_frame)) {
		errno = EBADMSG;
		return -1;
	}

	if (frame->magic != KNET_FRAME_MAGIC) {
		errno = EBADMSG;
		return -1;
	}

	if (frame->version != KNET_FRAME_VERSION) { /* TODO: versioning */
		errno = EBADMSG;
		return -1;
	}

	switch (frame->type) {
	case KNET_FRAME_DATA:
		return ret;
	case KNET_FRAME_PING:
		frame->type = KNET_FRAME_PONG;
		sendto(sockfd, frame, ret, MSG_DONTWAIT, (struct sockaddr *) &address, addrlen);
		return 0;
	case KNET_FRAME_PONG:
		/* TODO: find the link and mark enabled */
		return ret;
	}

	errno = EBADMSG;
	return -1;
}

void knet_send(struct knet_host *host, struct knet_frame *frame, size_t len)
{
	ssize_t err;
	struct knet_host *khp;
	struct knet_link *klp;

	for (khp = host; khp != NULL; khp = khp->next) {
		if (frame->type == KNET_FRAME_DATA) {
			/* TODO: packet inspection, might continue */
		}

		for (klp = khp->link; klp != NULL; klp = klp->next) {
			if ((frame->type == KNET_FRAME_DATA) && (!klp->enabled))
				continue;

			err = sendto(klp->sock, frame, len, MSG_DONTWAIT,
				(struct sockaddr *) &klp->address, sizeof(struct sockaddr_storage));

			if ((frame->type == KNET_FRAME_DATA) && (!khp->active) && (err == len))
				break;
		}
	}
}
