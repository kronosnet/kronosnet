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
#define KNET_PING_TIMERES 200
#define KNET_BUFSIZE 2048

struct __knet_handle {
	int sock[2];
	int epollfd;
	struct knet_host *host_head;
	struct knet_listener *listener_head;
	struct knet_frame *buff;
	pthread_t control_thread;
	pthread_rwlock_t host_rwlock;
};

static void *knet_control_thread(void *data);

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

	knet_h->epollfd = epoll_create(KNET_MAX_EVENTS);

	if (knet_h->epollfd < 0)
		goto exit_fail4;

	if (knet_fdset_cloexec(knet_h->epollfd) != 0)
		goto exit_fail5;

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sock[0];

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

int knet_host_acquire(knet_handle_t knet_h, struct knet_host **head, int writelock)
{
	int ret;

	if (writelock != 0)
		ret = pthread_rwlock_wrlock(&knet_h->host_rwlock);
	else
		ret = pthread_rwlock_rdlock(&knet_h->host_rwlock);

	*head = (ret == 0) ? knet_h->host_head : NULL;

	return ret;
}

int knet_host_release(knet_handle_t knet_h)
{
	return pthread_rwlock_unlock(&knet_h->host_rwlock);
}

int knet_handle_getfd(knet_handle_t knet_h)
{
	return knet_h->sock[1];
}

int knet_host_add(knet_handle_t knet_h, struct knet_host *host)
{
	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0)
		return -1;

	/* pushing new host to the front */
	host->next		= knet_h->host_head;
	knet_h->host_head	= host;

	pthread_rwlock_unlock(&knet_h->host_rwlock);
	return 0;
}

int knet_host_remove(knet_handle_t knet_h, struct knet_host *host)
{
	struct knet_host *hp;

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

	pthread_rwlock_unlock(&knet_h->host_rwlock);
	return 0;
}

int knet_listener_add(knet_handle_t knet_h, struct knet_listener *listener)
{
	int value;
	struct epoll_event ev;

	listener->sock = socket(listener->address.ss_family, SOCK_DGRAM, 0);

	if (listener->sock < 0)
		return listener->sock;

	value = KNET_RING_RCVBUFF;
	setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (knet_fdset_cloexec(listener->sock) != 0)
		goto exit_fail1;

	if (bind(listener->sock, (struct sockaddr *) &listener->address,
					sizeof(struct sockaddr_storage)) != 0)
		goto exit_fail1;

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = listener->sock;

	if (epoll_ctl(knet_h->epollfd, EPOLL_CTL_ADD, listener->sock, &ev) != 0)
		goto exit_fail1;

	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0)
		goto exit_fail2;

	/* pushing new host to the front */
	listener->next		= knet_h->listener_head;
	knet_h->listener_head	= listener;

	pthread_rwlock_unlock(&knet_h->host_rwlock);

	return 0;

 exit_fail2:
	epoll_ctl(knet_h->epollfd, EPOLL_CTL_DEL, listener->sock, &ev);

 exit_fail1:
	close(listener->sock);
	return -1;
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

	knet_h->buff->magic = htonl(KNET_FRAME_MAGIC);
	knet_h->buff->version = KNET_FRAME_VERSION;
	knet_h->buff->type = KNET_FRAME_DATA;

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

static void knet_recv_frame(knet_handle_t knet_h, int sockfd)
{
	ssize_t len;
	struct sockaddr_storage address;
	socklen_t addrlen;
	struct knet_host *i;
	struct knet_link *j, *link_src;

	if (pthread_rwlock_rdlock(&knet_h->host_rwlock) != 0)
		return;

	len = recvfrom(sockfd, knet_h->buff, KNET_BUFSIZE,
		MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (len < sizeof(struct knet_frame))
		goto exit_unlock;

	if (ntohl(knet_h->buff->magic) != KNET_FRAME_MAGIC)
		goto exit_unlock;

	if (knet_h->buff->version != KNET_FRAME_VERSION)
		goto exit_unlock;

	/* searching host/link, TODO: improve lookup */
	link_src = NULL;

	for (i = knet_h->host_head; i != NULL; i = i->next) {
		for (j = i->link; j != NULL; j = j->next) {
			if (memcmp(&address, &j->address, addrlen) == 0) {
				link_src = j;
				break;
			}
		}
	}

	if (link_src == NULL) /* host/link not found */
		goto exit_unlock;

	switch (knet_h->buff->type) {
	case KNET_FRAME_DATA:
		write(knet_h->sock[0],
			knet_h->buff + 1, len - sizeof(struct knet_frame));
		break;
	case KNET_FRAME_PING:
		knet_h->buff->type = KNET_FRAME_PONG;
		sendto(j->sock, knet_h->buff, sizeof(struct knet_frame),
				MSG_DONTWAIT, (struct sockaddr *) &j->address,
				sizeof(struct sockaddr_storage));
		break;
	case KNET_FRAME_PONG:
		j->enabled = 1; /* TODO: might need write lock */
		clock_gettime(CLOCK_MONOTONIC, &j->pong_last);
		break;
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->host_rwlock);
}

static void knet_tsdiff(struct timespec *start, struct timespec *end, suseconds_t *diff)
{
	*diff = (end->tv_sec - start->tv_sec) * 1000000; /* micro-seconds */
	*diff += (end->tv_nsec - start->tv_nsec) / 1000; /* micro-seconds */
}

static void knet_heartbeat_check_each(knet_handle_t knet_h, struct knet_link *j)
{
	struct timespec clock_now;
	suseconds_t diff_ping, diff_pong;

	if (clock_gettime(CLOCK_MONOTONIC, &clock_now) != 0)
		return;

	knet_tsdiff(&j->ping_last, &clock_now, &diff_ping);

	if (diff_ping >= j->ping_interval) {
		printf("diff_ping: %lu\n", diff_ping);

		knet_h->buff->type = KNET_FRAME_PING;

		sendto(j->sock, knet_h->buff, sizeof(struct knet_frame),
			MSG_DONTWAIT, (struct sockaddr *) &j->address,
			sizeof(struct sockaddr_storage));

		clock_gettime(CLOCK_MONOTONIC, &j->ping_last);
		/* TODO: send ping */
	}

	if (j->enabled == 1) {
		knet_tsdiff(&j->pong_last, &clock_now, &diff_pong);

		if (diff_pong >= j->pong_timeout) {
			printf("diff_pong: %lu\n", diff_pong);
			j->enabled = 0; /* TODO: might need write lock */
		}
	}
}

static void knet_heartbeat_check(knet_handle_t knet_h)
{
	struct knet_host *i;
	struct knet_link *j;

	if (pthread_rwlock_rdlock(&knet_h->host_rwlock) != 0)
		return;

	for (i = knet_h->host_head; i != NULL; i = i->next) {
		for (j = i->link; j != NULL; j = j->next)
			knet_heartbeat_check_each(knet_h, j);
	}

	pthread_rwlock_unlock(&knet_h->host_rwlock);
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
			if (events[i].data.fd == knet_h->sock[0]) {
				knet_send_data(knet_h);
			} else {
				knet_recv_frame(knet_h, events[i].data.fd);
			}
		}

		knet_heartbeat_check(knet_h);
	}

	return NULL;
}
