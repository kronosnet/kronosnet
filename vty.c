#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "utils.h"
#include "vty.h"

STATIC pthread_mutex_t knet_vty_mutex = PTHREAD_MUTEX_INITIALIZER;

STATIC int vty_max_connections = KNET_VTY_DEFAULT_MAX_CONN;
STATIC int vty_current_connections = 0;

STATIC int daemon_quit = 0;

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigpipe_handler(int sig)
{
	return;
}

/*
 * mainloop is not thread safe as there should only be one
 */
int knet_vty_main_loop(const char *configfile, const char *ip_addr,
		       const unsigned short port)
{
	int vty_listener_fd;
	int vty_accept_fd;
	struct sockaddr incoming_sa;
	socklen_t salen;
	fd_set rfds;
	int se_result = 0;
	struct timeval tv;
	int err = 0;

	signal(SIGTERM, sigterm_handler);
	signal(SIGPIPE, sigpipe_handler);

	// read and process config file here

	vty_listener_fd = knet_vty_init_listener(ip_addr, port);
	if (vty_listener_fd < 0) {
		log_error("Unable to setup vty listener");
		return -1;
	}

	while (se_result >= 0 && !daemon_quit) {
		FD_ZERO (&rfds);
		FD_SET (vty_listener_fd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((vty_listener_fd + 1), &rfds, 0, 0, &tv);

		if ((se_result == -1) && (daemon_quit)) {
			log_info("Got a SIGTERM, goodbye");
			goto out;
		}

		if (se_result == -1) {
			err = se_result;
			log_error("Unable to select on vty listener socket!");
			goto out;
		}

		if ((se_result == 0) || (!FD_ISSET(vty_listener_fd, &rfds)))
			continue;

		vty_accept_fd = accept(vty_listener_fd, &incoming_sa, &salen);
		if (vty_accept_fd < 0) {
			log_error("Unable to accept connection to vty");
			continue;
		}

		// check for ip address access list here against incoming_sa

		pthread_mutex_lock(&knet_vty_mutex);
		if (vty_current_connections == vty_max_connections) {
			errno = ECONNREFUSED;
			log_error("Too many connections to VTY");
			close(vty_accept_fd);
			pthread_mutex_unlock(&knet_vty_mutex);
			continue;
		}

		// start vty thread here
		// vty_current_connections++; should be incremented once
		// the thread is started and operating

		pthread_mutex_unlock(&knet_vty_mutex);
	}

out:
	knet_vty_close_listener(vty_listener_fd);

	// reverse running config to close/release resources;

	return err;
}

void knet_vty_set_max_connections(const int max_connections)
{
	pthread_mutex_lock(&knet_vty_mutex);
	vty_max_connections = max_connections;
	pthread_mutex_unlock(&knet_vty_mutex);
}

int knet_vty_init_listener(const char *ip_addr, const unsigned short port)
{
	int sockfd = -1, sockopt = 1;
	int socktype = SOCK_STREAM;
	int af_family = AF_INET6;
	int salen = 0, err = 0;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	pthread_mutex_lock(&knet_vty_mutex);

	/* handle sigpipe if we decide to use KEEPALIVE */

	/*
	 * I REALLY HATE MYSELF FOR WRITING THIS PIECE OF CRAP
	 * but it gets the job done
	 */

	if ((ip_addr) &&
	    (strlen(ip_addr)) &&
	    (!strchr(ip_addr, ':'))) {
		af_family = AF_INET;
	}

	sockfd = socket(af_family, socktype, 0);
	if ((sockfd < 0) &&
	    (errno == EAFNOSUPPORT) &&
	    (af_family = AF_INET6)) {
		af_family = AF_INET;
		sockfd = socket(af_family, socktype, 0);
	}
	if (sockfd < 0) {
		err = sockfd;
		goto out_clean;
	}

	err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&sockopt, sizeof(sockopt));
	if (err)
		goto out_clean;

	if (knet_fdset_cloexec(sockfd) < 0) {
		err = -1;
		goto out_clean;
	}

	if (af_family == AF_INET) {
		salen = sizeof(struct sockaddr_in);
		memset(&sin, 0, salen);
		sin.sin_family = af_family;
		sin.sin_port = htons(port);
		if ((!ip_addr) || (!strlen(ip_addr)))
			sin.sin_addr.s_addr = htonl(INADDR_ANY);
		else
			if (inet_pton(af_family, ip_addr, &sin.sin_addr) <= 0) {
				err = -1;
				goto out_clean;
			}
		sin.sin_port = htons(port);
		err = bind(sockfd, (struct sockaddr *)&sin, salen);
	} else {
		salen = sizeof(struct sockaddr_in6);
		memset(&sin6, 0, salen);
		sin6.sin6_family = af_family;
		sin6.sin6_port = htons(port);
		if ((!ip_addr) || (!strlen(ip_addr)))
			memcpy(&sin6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
		else
			if (inet_pton(af_family, ip_addr, &sin6.sin6_addr) <= 0) {
				err = -1;
				goto out_clean;
			}
		err = bind(sockfd, (struct sockaddr *)&sin6, salen);
	}

	if (err)
		goto out_clean;

	err = listen(sockfd, 0);
	if (err)
		goto out_clean;

	pthread_mutex_unlock(&knet_vty_mutex);

	return sockfd;

out_clean:
	if (sockfd >= 0)
		close(sockfd);

	pthread_mutex_unlock(&knet_vty_mutex);

	return err;
}

void knet_vty_close_listener(int listener_fd)
{
	pthread_mutex_lock(&knet_vty_mutex);

	if (listener_fd <= 0)
		goto out_clean;

	close(listener_fd);
	listener_fd = 0;

out_clean:

	pthread_mutex_unlock(&knet_vty_mutex);

	return;
}
