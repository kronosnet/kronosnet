#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <string.h>

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
	int save_errno = 0;

	listener->sock = socket(listener->address.ss_family, SOCK_DGRAM, 0);

	if (listener->sock < 0)
		return listener->sock;

	value = KNET_RING_RCVBUFF;
	setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value));

	if (_fdset_cloexec(listener->sock) != 0) {
		save_errno = errno;
		goto exit_fail1;
	}

	if (bind(listener->sock, (struct sockaddr *) &listener->address,
					sizeof(struct sockaddr_storage)) != 0) {
		save_errno = errno;
		goto exit_fail1;
	}

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = listener->sock;

	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, listener->sock, &ev) != 0) {
		save_errno = errno;
		goto exit_fail1;
	}

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0) {
		save_errno = errno;
		goto exit_fail2;
	}

	/* pushing new host to the front */
	listener->next		= knet_h->listener_head;
	knet_h->listener_head	= listener;

	pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;

 exit_fail2:
	epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, listener->sock, &ev);

 exit_fail1:
	close(listener->sock);
	errno = save_errno;
	return -1;
}

int knet_listener_remove(knet_handle_t knet_h, struct knet_listener *listener)
{
	int link_idx, ret;
	struct epoll_event ev; /* kernel < 2.6.9 bug (see epoll_ctl man) */
	struct knet_host *host;
	struct knet_listener *tmp_listener;

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0)
		return -EINVAL;

	ret = 0;

	/* checking if listener is in use */
	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (host->link[link_idx].configured != 1)
				continue;

			if (host->link[link_idx].sock == listener->sock) {
				ret = -EBUSY;
				goto exit_fail1;
			}
		}
	}

	/* TODO: use a doubly-linked list? */
	if (listener == knet_h->listener_head) {
		knet_h->listener_head = knet_h->listener_head->next;
	} else {
		for (tmp_listener = knet_h->listener_head; tmp_listener != NULL; tmp_listener = tmp_listener->next) {
			if (listener == tmp_listener->next) {
				tmp_listener->next = tmp_listener->next->next;
				break;
			}
		}
	}

	epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, listener->sock, &ev);
	close(listener->sock);

 exit_fail1:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

	if (ret < 0)
		errno = -ret;
	return ret;
}
