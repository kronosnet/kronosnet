#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "utils.h"
#include "libknet-private.h"

int knet_listener_acquire(knet_handle_t knet_h, struct knet_listener **head, int writelock)
{
	int ret;

	if (writelock != 0)
		ret = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	else
		ret = pthread_rwlock_rdlock(&knet_h->list_rwlock);

	if (head)
		*head = (ret == 0) ? knet_h->listener_head : NULL;

	return ret;
}

int knet_listener_release(knet_handle_t knet_h)
{
	return pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0)
		goto exit_fail2;

	/* pushing new host to the front */
	listener->next		= knet_h->listener_head;
	knet_h->listener_head	= listener;

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;

 exit_fail2:
	epoll_ctl(knet_h->epollfd, EPOLL_CTL_DEL, listener->sock, &ev);

 exit_fail1:
	close(listener->sock);
	return -1;
}

int knet_listener_remove(knet_handle_t knet_h, struct knet_listener *listener)
{
	int i, ret;
	struct epoll_event ev; /* kernel < 2.6.9 bug (see epoll_ctl man) */
	struct knet_host *host;
	struct knet_listener *l;

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0)
		return -EINVAL;

	ret = 0;

	/* checking if listener is in use */
	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (i = 0; i < KNET_MAX_LINK; i++) {
			if (host->link[i].ready != 1) continue;

			if (host->link[i].sock == listener->sock) {
				ret = -EBUSY;
				goto exit_fail1;
			}
		}
	}

	/* TODO: use a doubly-linked list? */
	if (listener == knet_h->listener_head) {
		knet_h->listener_head = knet_h->listener_head->next;
	} else {
		for (l = knet_h->listener_head; l != NULL; l = l->next) {
			if (listener == l->next) {
				l->next = l->next->next;
				break;
			}
		}
	}

	epoll_ctl(knet_h->epollfd, EPOLL_CTL_DEL, listener->sock, &ev);
	close(listener->sock);

 exit_fail1:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

	if (ret < 0) errno = -ret;
	return ret;
}
