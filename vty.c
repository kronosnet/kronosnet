#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "utils.h"
#include "netutils.h"
#include "vty.h"
#include "vty_auth.h"
#include "vty_utils.h"

STATIC pthread_mutex_t knet_vty_mutex = PTHREAD_MUTEX_INITIALIZER;

STATIC int vty_max_connections = KNET_VTY_DEFAULT_MAX_CONN;
STATIC int vty_current_connections = 0;

STATIC struct knet_vty knet_vtys[KNET_VTY_TOTAL_MAX_CONN];

STATIC int daemon_quit = 0;

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigpipe_handler(int sig)
{
	return;
}

static void *vty_accept_thread(void *arg)
{
	struct knet_vty *vty = (struct knet_vty *)&knet_vtys[*(int *)arg];
	char *src_ip[2];
	const char *ip = "unknown";
	int err;

	src_ip[0] = NULL;

	knet_vty_print_banner(vty);
	if (vty->got_epipe)
		goto out_clean;

	err = addrtostr((struct sockaddr *)&vty->src_sa,
			vty->src_sa_len,
			src_ip);

	if (!err)
		ip = src_ip[0];

	if ((knet_vty_auth_user(vty, NULL) < 0) && (!vty->got_epipe)) {
		log_info("User failed to authenticate (ip: %s)", ip);
		goto out_clean;
	}
	if (vty->got_epipe)
		goto out_clean;

	log_info("User %s connected from %s", vty->username, ip);
	knet_vty_write(vty, "Welcome %s (%s) on vty(%d)\n", vty->username, ip, vty->conn_num);
	if (vty->got_epipe)
		goto out_clean;

	if (knet_vty_set_iacs(vty) < 0) {
		knet_vty_write(vty, "Unable to set telnet session preferences");
		goto out_clean;
	}
	if (vty->got_epipe)
		goto out_clean;

out_clean:
	if (src_ip[0])
		addrtostr_free(src_ip);

	pthread_mutex_lock(&knet_vty_mutex);
	vty->active = 0;
	close(vty->vty_sock);
	vty_current_connections--;
	pthread_mutex_unlock(&knet_vty_mutex);

	return NULL;
}

/*
 * mainloop is not thread safe as there should only be one
 */
int knet_vty_main_loop(const char *configfile, const char *ip_addr,
		       const char *port)
{
	int vty_listener_fd;
	int vty_accept_fd;
	struct sockaddr_storage incoming_sa;
	socklen_t salen;
	fd_set rfds;
	int se_result = 0;
	struct timeval tv;
	int err = 0;
	int conn_index, found;
	char portbuf[8];
	char ipbuf[4];

	signal(SIGTERM, sigterm_handler);
	signal(SIGPIPE, sigpipe_handler);

	// read and process config file here

	if (!ip_addr) {
		memset(&ipbuf, 0, sizeof(ipbuf));
		snprintf(ipbuf, sizeof(ipbuf), "::");
		ip_addr = ipbuf;
	}
	if (!port) {
		memset(&portbuf, 0, sizeof(portbuf));
		snprintf(portbuf, sizeof(portbuf), "%d", KNET_VTY_DEFAULT_PORT);
		port = portbuf;
	}

	vty_listener_fd = knet_vty_init_listener(ip_addr, port);
	if (vty_listener_fd < 0) {
		log_error("Unable to setup vty listener");
		return -1;
	}

	memset(&knet_vtys, 0, sizeof(knet_vtys));

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

		memset(&incoming_sa, 0, sizeof(struct sockaddr_storage));
		salen = sizeof(struct sockaddr_storage);

		vty_accept_fd = accept(vty_listener_fd, (struct sockaddr *)&incoming_sa, &salen);
		if (vty_accept_fd < 0) {
			log_error("Unable to accept connection to vty");
			continue;
		}

		// check for ip address access list here against incoming_sa

		pthread_mutex_lock(&knet_vty_mutex);

		found = 0;
		for(conn_index = 0; conn_index <= vty_max_connections; conn_index++) {
			if (knet_vtys[conn_index].active == 0) {
				found = 1;
				break;
			}
		}

		if ((vty_current_connections == vty_max_connections) || (!found)) {
			errno = ECONNREFUSED;
			log_error("Too many connections to VTY or no available slots");
			close(vty_accept_fd);
			pthread_mutex_unlock(&knet_vty_mutex);
			continue;
		}

		vty_current_connections++;

		memset(&knet_vtys[conn_index], 0,
		       sizeof(struct knet_vty));

		knet_vtys[conn_index].vty_sock = vty_accept_fd;
		knet_vtys[conn_index].conn_num = conn_index;
		memcpy(&knet_vtys[conn_index].src_sa, &incoming_sa, salen);
		knet_vtys[conn_index].src_sa_len = salen;
		knet_vtys[conn_index].active = 1;

		err = pthread_create(&knet_vtys[conn_index].vty_thread,
				     NULL, vty_accept_thread,
				     (void *)&conn_index);
		if (err < 0) {
			log_error("Unable to spawn vty thread");
			memset(&knet_vtys[conn_index], 0,
			       sizeof(struct knet_vty));
			vty_current_connections--;
		}

		pthread_mutex_unlock(&knet_vty_mutex);
	}

out:
	knet_vty_close_listener(vty_listener_fd);

	// reverse running config to close/release resources;

	return err;
}

int knet_vty_set_max_connections(const int max_connections)
{
	int err = 0;

	pthread_mutex_lock(&knet_vty_mutex);
	if ((max_connections > KNET_VTY_TOTAL_MAX_CONN) ||
	    (max_connections < 1)) {
		errno = EINVAL;
		err = -1;
	} else {
		vty_max_connections = max_connections;
	}
	pthread_mutex_unlock(&knet_vty_mutex);
	return err;
}

int knet_vty_init_listener(const char *ip_addr, const char *port)
{
	int sockfd = -1, sockopt = 1;
	int socktype = SOCK_STREAM;
	int err = 0;
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(struct sockaddr_storage));

	if (strtoaddr(ip_addr, port, (struct sockaddr *)&ss, sizeof(struct sockaddr_storage)) != 0)
		return -1;

	pthread_mutex_lock(&knet_vty_mutex);

	/* handle sigpipe if we decide to use KEEPALIVE */

	sockfd = socket(ss.ss_family, socktype, 0);
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

	err = bind(sockfd, (struct sockaddr *)&ss, sizeof(struct sockaddr_storage));
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
