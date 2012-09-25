#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "libknet-private.h"
#include "nsscrypto.h"

#define KNET_MAX_EVENTS 8
#define KNET_PING_TIMERES 200000

static void *_handle_tap_to_links_thread(void *data);
static void *_handle_recv_from_links_thread(void *data);
static void *_handle_heartbt_thread(void *data);

knet_handle_t knet_handle_new(const struct knet_handle_cfg *knet_handle_cfg)
{
	knet_handle_t knet_h;
	struct epoll_event ev;

	/*
	 * validate incoming config request
	 */
	if (knet_handle_cfg == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (knet_handle_cfg->fd <= 0) {
		errno = EINVAL;
		return NULL;
	}

	if ((knet_h = malloc(sizeof(struct knet_handle))) == NULL)
		return NULL;

	memset(knet_h, 0, sizeof(struct knet_handle));

	if (crypto_init(knet_h, knet_handle_cfg) < 0)
		goto exit_fail1;

	if ((knet_h->tap_to_links_buf = malloc(KNET_DATABUFSIZE))== NULL)
		goto exit_fail2;

	memset(knet_h->tap_to_links_buf, 0, KNET_DATABUFSIZE);

	if ((knet_h->recv_from_links_buf = malloc(KNET_DATABUFSIZE))== NULL)
		goto exit_fail3;

	memset(knet_h->recv_from_links_buf, 0, KNET_DATABUFSIZE);

	if ((knet_h->pingbuf = malloc(KNET_PINGBUFSIZE))== NULL)
		goto exit_fail4;

	memset(knet_h->pingbuf, 0, KNET_PINGBUFSIZE);

	if (pthread_rwlock_init(&knet_h->list_rwlock, NULL) != 0)
		goto exit_fail5;

	knet_h->sockfd = knet_handle_cfg->fd;
	knet_h->tap_to_links_epollfd = epoll_create(KNET_MAX_EVENTS);
	knet_h->recv_from_links_epollfd = epoll_create(KNET_MAX_EVENTS);
	knet_h->node_id = knet_handle_cfg->node_id;

	if ((knet_h->tap_to_links_epollfd < 0) ||
	    (knet_h->recv_from_links_epollfd < 0))
		goto exit_fail6;

	if ((_fdset_cloexec(knet_h->tap_to_links_epollfd) != 0) ||
	    (_fdset_cloexec(knet_h->recv_from_links_epollfd != 0)))
		goto exit_fail6;

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = knet_h->sockfd;

	if (epoll_ctl(knet_h->tap_to_links_epollfd,
				EPOLL_CTL_ADD, knet_h->sockfd, &ev) != 0)
		goto exit_fail6;

	if (pthread_create(&knet_h->tap_to_links_thread, 0,
				_handle_tap_to_links_thread, (void *) knet_h) != 0)
		goto exit_fail6;

	if (pthread_create(&knet_h->recv_from_links_thread, 0,
				_handle_recv_from_links_thread, (void *) knet_h) != 0)
		goto exit_fail7;

	if (pthread_create(&knet_h->heartbt_thread, 0,
				_handle_heartbt_thread, (void *) knet_h) != 0)
		goto exit_fail8;

	return knet_h;

exit_fail8:
	pthread_cancel(knet_h->recv_from_links_thread);

exit_fail7:
	pthread_cancel(knet_h->tap_to_links_thread);

exit_fail6:
	if (knet_h->tap_to_links_epollfd >= 0)
		close(knet_h->tap_to_links_epollfd);
	if (knet_h->recv_from_links_epollfd >= 0)
		close(knet_h->recv_from_links_epollfd);

	pthread_rwlock_destroy(&knet_h->list_rwlock);

exit_fail5:
	free(knet_h->pingbuf);

exit_fail4:
	free(knet_h->recv_from_links_buf);

exit_fail3:
	free(knet_h->tap_to_links_buf);

exit_fail2:
	crypto_fini(knet_h);

exit_fail1:
	free(knet_h);
	return NULL;
}

int knet_handle_free(knet_handle_t knet_h)
{
	void *retval;

	if ((knet_h->host_head != NULL) || (knet_h->listener_head != NULL))
		goto exit_busy;

	pthread_cancel(knet_h->heartbt_thread);
	pthread_join(knet_h->heartbt_thread, &retval);

	if (retval != PTHREAD_CANCELED)
		goto exit_busy;

	pthread_cancel(knet_h->tap_to_links_thread);
	pthread_join(knet_h->tap_to_links_thread, &retval);
	if (retval != PTHREAD_CANCELED)
		goto exit_busy;

	pthread_cancel(knet_h->recv_from_links_thread);
	pthread_join(knet_h->recv_from_links_thread, &retval);

	if (retval != PTHREAD_CANCELED)
		goto exit_busy;

	close(knet_h->tap_to_links_epollfd);
	close(knet_h->recv_from_links_epollfd);

	pthread_rwlock_destroy(&knet_h->list_rwlock);

	free(knet_h->tap_to_links_buf);
	free(knet_h->recv_from_links_buf);
	free(knet_h->pingbuf);

	crypto_fini(knet_h);

	free(knet_h);

	return 0;

 exit_busy:
	errno = EBUSY;
	return -EBUSY;
}

void knet_handle_setfwd(knet_handle_t knet_h, int enabled)
{
	knet_h->enabled = (enabled == 1) ? 1 : 0;
}

void knet_link_timeout(struct knet_link *lnk,
				time_t interval, time_t timeout, int precision)
{
	lnk->ping_interval = interval * 1000; /* microseconds */
	lnk->pong_timeout = timeout * 1000; /* microseconds */
	lnk->latency_fix = precision;
	lnk->latency_exp = precision - \
				((lnk->ping_interval * precision) / 8000000);
}

static void _handle_tap_to_links(knet_handle_t knet_h)
{
	int j;
	ssize_t len, snt, outlen;
	struct knet_host *i;

	len = read(knet_h->sockfd, knet_h->tap_to_links_buf->kf_data,
					KNET_DATABUFSIZE - KNET_FRAME_SIZE);

	if (len == 0) {
		/* TODO: disconnection, should never happen! */
		return;
	}

	len += KNET_FRAME_SIZE;

	if (knet_h->enabled != 1) /* data forward is disabled */
		return;

	/* TODO: packet inspection */

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0)
		return;

	if (crypto_encrypt_and_sign(knet_h->crypto_instance,
				    (const unsigned char *)knet_h->tap_to_links_buf,
				    len,
				    knet_h->tap_to_links_buf_crypt,
				    &outlen) < 0)
		return;

	for (i = knet_h->host_head; i != NULL; i = i->next) {
		for (j = 0; j < KNET_MAX_LINK; j++) {
			if (i->link[j].enabled != 1) /* link is disabled */
				continue;

			snt = sendto(i->link[j].sock,
					knet_h->tap_to_links_buf_crypt, outlen, MSG_DONTWAIT,
					(struct sockaddr *) &i->link[j].address,
					sizeof(struct sockaddr_storage));

			if ((i->active == 0) && (snt == len))
				break;
		}
	}

	pthread_rwlock_unlock(&knet_h->list_rwlock);
}

static void _handle_recv_from_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t len, outlen;
	struct sockaddr_storage address;
	socklen_t addrlen;
	struct knet_host *src_host;
	struct knet_link *src_link;
	unsigned long long latency_last;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0)
		return;

	addrlen = sizeof(struct sockaddr_storage);
	len = recvfrom(sockfd, knet_h->recv_from_links_buf, KNET_DATABUFSIZE,
		MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (crypto_authenticate_and_decrypt(knet_h->crypto_instance,
					    (unsigned char *)knet_h->recv_from_links_buf,
					    &len) < 0)
		goto exit_unlock;

	if (len < (KNET_FRAME_SIZE + 1))
		goto exit_unlock;

	if (ntohl(knet_h->recv_from_links_buf->kf_magic) != KNET_FRAME_MAGIC)
		goto exit_unlock;

	if (knet_h->recv_from_links_buf->kf_version != KNET_FRAME_VERSION)
		goto exit_unlock;

	src_host = NULL;
	src_link = NULL;

	if ((knet_h->recv_from_links_buf->kf_type & KNET_FRAME_PMSK) != 0) {
		knet_h->recv_from_links_buf->kf_node = ntohs(knet_h->recv_from_links_buf->kf_node);
		src_host = knet_h->host_index[knet_h->recv_from_links_buf->kf_node];

		if (src_host == NULL)	/* host not found */
			goto exit_unlock;

		src_link = src_host->link +
				(knet_h->recv_from_links_buf->kf_link % KNET_MAX_LINK);
	}

	switch (knet_h->recv_from_links_buf->kf_type) {
	case KNET_FRAME_DATA:
		if (knet_h->enabled != 1) /* data forward is disabled */
			break;

		write(knet_h->sockfd,
			knet_h->recv_from_links_buf->kf_data, len - KNET_FRAME_SIZE);

		break;
	case KNET_FRAME_PING:
		knet_h->recv_from_links_buf->kf_type = KNET_FRAME_PONG;
		knet_h->recv_from_links_buf->kf_node = htons(knet_h->node_id);

		if (crypto_encrypt_and_sign(knet_h->crypto_instance,
					    (const unsigned char *)knet_h->recv_from_links_buf,
					    len,
					    knet_h->recv_from_links_buf_crypt,
					    &outlen) < 0)
			break;
					    

		sendto(src_link->sock, knet_h->recv_from_links_buf_crypt, outlen, MSG_DONTWAIT,
				(struct sockaddr *) &src_link->address,
				sizeof(struct sockaddr_storage));

		break;
	case KNET_FRAME_PONG:
		clock_gettime(CLOCK_MONOTONIC, &src_link->pong_last);

		timespec_diff(knet_h->recv_from_links_buf->kf_time,
				src_link->pong_last, &latency_last);

		src_link->latency =
			((src_link->latency * src_link->latency_exp) +
			((latency_last / 1000llu) *
				(src_link->latency_fix - src_link->latency_exp))) /
					src_link->latency_fix;

		if (src_link->latency < src_link->pong_timeout)
			src_link->enabled = 1;

		break;
	default:
		goto exit_unlock;
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
}

static void _handle_check_each(knet_handle_t knet_h, struct knet_link *dst_link)
{
	int len;
	ssize_t outlen;
	struct timespec clock_now, pong_last;
	unsigned long long diff_ping;

	/* caching last pong to avoid race conditions */
	pong_last = dst_link->pong_last;

	if (clock_gettime(CLOCK_MONOTONIC, &clock_now) != 0)
		return;

	timespec_diff(dst_link->ping_last, clock_now, &diff_ping);

	if (diff_ping >= (dst_link->ping_interval * 1000llu)) {
		knet_h->pingbuf->kf_time = clock_now;
		knet_h->pingbuf->kf_link = dst_link->link_id;

		if (crypto_encrypt_and_sign(knet_h->crypto_instance,
					    (const unsigned char *)knet_h->pingbuf,
					    KNET_PINGBUFSIZE,
					    knet_h->pingbuf_crypt,
					    &outlen) < 0)
		return;

		len = sendto(dst_link->sock, knet_h->pingbuf_crypt, outlen,
			MSG_DONTWAIT, (struct sockaddr *) &dst_link->address,
			sizeof(struct sockaddr_storage));

		if (len == outlen)
			dst_link->ping_last = clock_now;
	}

	if (dst_link->enabled == 1) {
		timespec_diff(pong_last, clock_now, &diff_ping);

		if (diff_ping >= (dst_link->pong_timeout * 1000llu))
			dst_link->enabled = 0; /* TODO: might need write lock */
	}
}

static void *_handle_heartbt_thread(void *data)
{
	int j;
	knet_handle_t knet_h;
	struct knet_host *i;

	knet_h = (knet_handle_t) data;

	/* preparing ping buffer */
	knet_h->pingbuf->kf_magic = htonl(KNET_FRAME_MAGIC);
	knet_h->pingbuf->kf_version = KNET_FRAME_VERSION;
	knet_h->pingbuf->kf_type = KNET_FRAME_PING;
	knet_h->pingbuf->kf_node = htons(knet_h->node_id);

	while (1) {
		usleep(KNET_PING_TIMERES);

		if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0)
			continue;

		for (i = knet_h->host_head; i != NULL; i = i->next) {
			for (j = 0; j < KNET_MAX_LINK; j++) {
				if (i->link[j].ready != 1) continue;
				_handle_check_each(knet_h, &i->link[j]);
			}
		}

		pthread_rwlock_unlock(&knet_h->list_rwlock);
	}

	return NULL;
}

static void *_handle_tap_to_links_thread(void *data)
{
	knet_handle_t knet_h;
	struct epoll_event events[KNET_MAX_EVENTS];

	knet_h = (knet_handle_t) data;

	/* preparing data buffer */
	knet_h->tap_to_links_buf->kf_magic = htonl(KNET_FRAME_MAGIC);
	knet_h->tap_to_links_buf->kf_version = KNET_FRAME_VERSION;
	knet_h->tap_to_links_buf->kf_type = KNET_FRAME_DATA;

	while (1) {
		if (epoll_wait(knet_h->tap_to_links_epollfd, events, KNET_MAX_EVENTS, -1) >= 1)
			_handle_tap_to_links(knet_h);
	}

	return NULL;

}

static void *_handle_recv_from_links_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h;
	struct epoll_event events[KNET_MAX_EVENTS];

	knet_h = (knet_handle_t) data;

	/* preparing data buffer */
	knet_h->recv_from_links_buf->kf_magic = htonl(KNET_FRAME_MAGIC);
	knet_h->recv_from_links_buf->kf_version = KNET_FRAME_VERSION;

	while (1) {
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			_handle_recv_from_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;
}
