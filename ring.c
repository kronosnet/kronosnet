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
#define KNET_PING_TIMERES 5000
#define KNET_BUFSIZE 2048

struct __knet_handle {
	int sock[2];
	int epollfd;
	struct knet_host *host_head;
	struct knet_frame *buff;
	pthread_t control_thread;
	pthread_rwlock_t host_rwlock;
};

static void *knet_control_thread(void *data);
static void knet_send_data(knet_handle_t knet_h);
static void knet_recv_frame(knet_handle_t knet_h, struct knet_link *link);

knet_handle_t knet_handle_new(void)
{
	knet_handle_t knet_h;
	struct epoll_event ev;

	if ((knet_h = malloc(sizeof(struct __knet_handle))) == NULL)
		return NULL;

	memset(knet_h, 0, sizeof(struct __knet_handle));

	if ((knet_h->buff = malloc(KNET_BUFSIZE)) == NULL)
		goto exit_fail1;

	memset(knet_h->buff, 0, KNET_BUFSIZE);

	if (pthread_rwlock_init(&knet_h->host_rwlock, NULL) != 0)
		goto exit_fail2;

	if (socketpair(AF_UNIX, SOCK_STREAM, IPPROTO_IP, knet_h->sock) != 0)
		goto exit_fail3;

	knet_h->epollfd = epoll_create(0);

	if (knet_h->epollfd < 0)
		goto exit_fail4;

	if (knet_fdset_cloexec(knet_h->epollfd) != 0)
		goto exit_fail5;

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events	= EPOLLIN;
	ev.data.ptr	= knet_h;

	if (epoll_ctl(knet_h->epollfd,
				EPOLL_CTL_ADD, knet_h->sock[0], &ev) != 0)
		goto exit_fail5;

	if (pthread_create(&knet_h->control_thread, 0,
				knet_control_thread, (void *) knet_h) != 0)
		goto exit_fail5;

	return knet_h;

exit_fail5:
	close(knet_h->epollfd);

exit_fail4:
	close(knet_h->sock[0]);
	close(knet_h->sock[1]);

exit_fail3:
	pthread_rwlock_destroy(&knet_h->host_rwlock);

exit_fail2:
	free(knet_h->buff);

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
		ev.data.ptr = lp;
		/* TODO: check for errors? */
		epoll_ctl(knet_h->epollfd, EPOLL_CTL_ADD, lp->sock, &ev);
	}

	/* pushing new host to the front */
	host->next		= knet_h->host_head;
	knet_h->host_head	= host;

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

int knet_host_foreach(knet_handle_t knet_h,
			int (*action)(struct knet_host *, void *), void *data)
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
	err = setsockopt(sockfd,
			SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (err != 0)
		log_error("Unable to set receive buffer");

	err = knet_fdset_cloexec(sockfd);

	if (err != 0) {
		log_error("Unable to get close-on-exec flag");
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

static void *knet_control_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h;
	struct epoll_event events[KNET_MAX_EVENTS];

	knet_h = (knet_handle_t) data;

	while (1) {
		nev = epoll_wait(knet_h->epollfd,
				events, KNET_MAX_EVENTS, KNET_PING_TIMERES);

		for (i = 0; i < nev; i++) {
			if (events[i].data.ptr == knet_h) {
				knet_send_data(knet_h);
			} else {
				knet_recv_frame(knet_h, events[i].data.ptr);
			}
		}
	}

	return NULL;
}

static void knet_send_data(knet_handle_t knet_h)
{
	ssize_t len, snt;
	struct knet_host *i;
	struct knet_link *j;

	len = read(knet_h->sock[0], knet_h->buff + 1,
				KNET_BUFSIZE - sizeof(struct knet_frame));

	if (len == 0) {
		/* TODO: disconnection, should never happen! */
		close(knet_h->sock[0]); /* FIXME: from here is downhill :) */
		return;
	}

	len += sizeof(struct knet_frame);

	knet_h->buff->magic	= htonl(KNET_FRAME_MAGIC);
	knet_h->buff->version 	= KNET_FRAME_VERSION;
	knet_h->buff->type	= KNET_FRAME_DATA;

	/* TODO: packet inspection */

	if (pthread_rwlock_rdlock(&knet_h->host_rwlock) != 0)
		return;

	for (i = knet_h->host_head; i != NULL; i = i->next) {
		for (j = i->link; j != NULL; j = j->next) {
			snt = sendto(j->sock, knet_h->buff, len, MSG_DONTWAIT,
					(struct sockaddr *) &j->address,
					sizeof(struct sockaddr_storage));
			if ((i->active == 0) && (snt == len))
				break;
		}
	}

	pthread_rwlock_unlock(&knet_h->host_rwlock);
}

static void knet_recv_frame(knet_handle_t knet_h, struct knet_link *hlnk)
{
	ssize_t len;
	struct sockaddr_storage address;
	socklen_t addrlen;

	len = recvfrom(hlnk->sock, knet_h->buff, KNET_BUFSIZE,
		MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (len < sizeof(struct knet_frame))
		return;

	if (ntohl(knet_h->buff->magic) != KNET_FRAME_MAGIC)
		return;

	if (knet_h->buff->version != KNET_FRAME_VERSION)
		return;

	switch (knet_h->buff->type) {
	case KNET_FRAME_DATA:
		write(knet_h->sock[0],
			knet_h->buff + 1, len - sizeof(struct knet_frame));
		break;
	case KNET_FRAME_PING:
		/* TODO: reply using KNET_FRAME_PONG */
		break;
	case KNET_FRAME_PONG:
		/* TODO: find the link and mark enabled */
		break;
	}
}

