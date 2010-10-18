#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "ring.h"
#include "utils.h"

#define KNET_MAX_EVENTS 8

struct __knet_handle {
	int sock[2];
	int epollfd;
	struct knet_host *host_head;
	pthread_t control_thread;
	pthread_rwlock_t host_rwlock;
};

static void *knet_control_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h;
	struct epoll_event events[KNET_MAX_EVENTS];

	knet_h = (knet_handle_t) data;

	while(1) {
		nev = epoll_wait(knet_h->epollfd, events, KNET_MAX_EVENTS, 500);

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == knet_h->sock[0]) {
				/* TODO: read data, inspect and deliver */
			}
			else {
				/* TODO: read frame, porcess or dispatch */
			}
		}
	}

	return NULL;
}

knet_handle_t knet_handle_new(void)
{
	knet_handle_t knet_h;
	struct epoll_event ev;

	knet_h = malloc(sizeof(struct __knet_handle));

	if (knet_h == NULL)
		return NULL;

	memset(knet_h, 0, sizeof(struct __knet_handle));

	if (pthread_rwlock_init(&knet_h->host_rwlock, NULL) != 0)
		goto exit_fail1;

	if (socketpair(AF_UNIX, SOCK_STREAM, IPPROTO_IP, knet_h->sock) != 0)
		goto exit_fail2;

	knet_h->epollfd = epoll_create1(FD_CLOEXEC);

	if (knet_h->epollfd < 0)
		goto exit_fail3;

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sock[0];

	if (epoll_ctl(knet_h->epollfd, EPOLL_CTL_ADD, knet_h->sock[0], &ev) != 0)
               goto exit_fail4;

	if (pthread_create(&knet_h->control_thread,
			0, knet_control_thread, (void *) knet_h) != 0)
		goto exit_fail4;

	return knet_h;

exit_fail4:
	close(knet_h->epollfd);

exit_fail3:
	close(knet_h->sock[0]);
	close(knet_h->sock[1]);

exit_fail2:
	pthread_rwlock_destroy(&knet_h->host_rwlock);

exit_fail1:
	free(knet_h);
	return NULL;
}

int knet_handle_getfd(knet_handle_t knet_h)
{
	return knet_h->sock[1];
}

int knet_host_add(knet_handle_t knet_h, struct knet_host *host)
{
	struct knet_link *lp;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;

	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0)
		return -1;

	for (lp = host->link; lp != NULL; lp = lp->next) {
		ev.data.fd = lp->sock;
		ev.data.ptr = lp;
		/* TODO: check for errors? */
		epoll_ctl(knet_h->epollfd, EPOLL_CTL_ADD, lp->sock, &ev);
	}

	/* pushing new host to the front */
	host->next = knet_h->host_head;
	knet_h->host_head = host;

	pthread_rwlock_unlock(&knet_h->host_rwlock);
	return 0;
}

int knet_host_remove(knet_handle_t knet_h, struct knet_host *host)
{
	struct knet_host *hp;
	struct knet_link *lp;

	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0)
		return -1;

	/* TODO: use a doubly-linked list? */
	if (host == knet_h->host_head) {
		knet_h->host_head = host->next;
	} else {
		for (hp = knet_h->host_head; hp != NULL; hp = hp->next) {
			if (host == hp->next) {
				hp->next = hp->next->next;
				break;
			}
		}
	}

	/* NOTE: kernel versions before 2.6.9 required a non-NULL pointer
	 * TODO: check for EPOLL_CTL_DEL errors? */
	for (lp = host->link; lp != NULL; lp = lp->next)
		epoll_ctl(knet_h->epollfd, EPOLL_CTL_DEL, lp->sock, 0);

	pthread_rwlock_unlock(&knet_h->host_rwlock);
	return 0;
}

int knet_host_foreach(knet_handle_t knet_h, int (*action)(struct knet_host *, void *), void *data)
{
	struct knet_host *i;

	if (pthread_rwlock_rdlock(&knet_h->host_rwlock) != 0)
		return -1;

	for (i = knet_h->host_head; i != NULL; i = i->next) {
		if (action && action(i, data) != 0)
			break;
	}

	pthread_rwlock_unlock(&knet_h->host_rwlock);
	return 0;
}

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

	if (ntohl(frame->magic) != KNET_FRAME_MAGIC) {
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
