/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "cfg.h"
#include "logging.h"
#include "netutils.h"
#include "vty.h"
#include "vty_auth.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

static int vty_max_connections = KNET_VTY_DEFAULT_MAX_CONN;
static int vty_current_connections = 0;
static int daemon_quit = 0;

pthread_mutex_t knet_vty_mutex = PTHREAD_MUTEX_INITIALIZER;
int knet_vty_config = -1;
struct knet_vty knet_vtys[KNET_VTY_TOTAL_MAX_CONN];
struct knet_vty_global_conf vty_global_conf;
pthread_t logging_thread;

static int _fdset_cloexec(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= FD_CLOEXEC;

	if (fcntl(fd, F_SETFD, fdflags) < 0)
		return -1;

	return 0;
}

static int _fdset_nonblock(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFL, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, fdflags) < 0)
		return -1;

	return 0;
}

static void *_handle_logging_thread(void *data)
{
	int logfd;
	int se_result = 0;
	fd_set rfds;
	struct timeval tv;

	memcpy(&logfd, data, sizeof(int));

	while (se_result >= 0 && !daemon_quit){
		FD_ZERO (&rfds);
		FD_SET (logfd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select(FD_SETSIZE, &rfds, 0, 0, &tv);

		if (se_result == -1)
			goto out;

		if (se_result == 0)
			continue;

		if (FD_ISSET(logfd, &rfds))  {
			struct knet_log_msg msg;
			size_t bytes_read = 0;
			size_t len;

			while (bytes_read < sizeof(struct knet_log_msg)) {
				len = read(logfd, &msg + bytes_read,
					   sizeof(struct knet_log_msg) - bytes_read);
				if (len <= 0) {
					break;
				}
				bytes_read += len;
			}

			if (bytes_read != sizeof(struct knet_log_msg))
				continue;

			switch(msg.msglevel) {
				case KNET_LOG_WARN:
					log_warn("(%s) %s", knet_get_subsystem_name(msg.subsystem), msg.msg);
					break;
				case KNET_LOG_INFO:
					log_info("(%s) %s", knet_get_subsystem_name(msg.subsystem), msg.msg);
					break;
				case KNET_LOG_DEBUG:
					log_kdebug("(%s) %s", knet_get_subsystem_name(msg.subsystem), msg.msg);
					break;
				case KNET_LOG_ERR:
				default:
					log_error("(%s) %s", knet_get_subsystem_name(msg.subsystem), msg.msg);
			}
		}
	}

out:
	return NULL;
}

static int knet_vty_init_listener(const char *ip_addr, const char *port)
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

	if (ss.ss_family == AF_INET6) {
		err = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				 (void *)&sockopt, sizeof(sockopt));
		if (err)
			goto out_clean;
	}

	err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&sockopt, sizeof(sockopt));
	if (err)
		goto out_clean;

	if (_fdset_cloexec(sockfd)) {
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

static void knet_vty_close_listener(int listener_fd)
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

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigpipe_handler(int sig)
{
	return;
}

static void knet_vty_close(struct knet_vty *vty)
{
	if (knet_vty_config == vty->conn_num)
		knet_vty_config = -1;

	knet_vty_free_history(vty);
	vty->active = 0;
	close(vty->vty_sock);
	vty_current_connections--;
}

static void *vty_accept_thread(void *arg)
{
	struct knet_vty *vty = (struct knet_vty *)&knet_vtys[*(int *)arg];
	char *src_ip[2];
	int err;

	knet_vty_print_banner(vty);
	if (vty->got_epipe)
		goto out_clean;

	src_ip[0] = NULL;
	err = addrtostr((struct sockaddr *)&vty->src_sa,
			vty->src_sa_len,
			src_ip);

	if (!err) {
		strncpy(vty->ip, src_ip[0], sizeof(vty->ip));
	} else {
		strcpy(vty->ip, "unknown");
	}

	if (src_ip[0])
		addrtostr_free(src_ip);

	if ((knet_vty_auth_user(vty, NULL) < 0) && (!vty->got_epipe)) {
		log_info("User failed to authenticate (ip: %s)", vty->ip);
		goto out_clean;
	}
	if (vty->got_epipe)
		goto out_clean;

	log_info("User %s connected from %s", vty->username, vty->ip);
	knet_vty_write(vty, "Welcome %s (%s) on vty(%d)\n\n", vty->username, vty->ip, vty->conn_num);
	if (vty->got_epipe)
		goto out_clean;

	if (knet_vty_set_iacs(vty) < 0) {
		knet_vty_write(vty, "Unable to set telnet session preferences");
		goto out_clean;
	}
	if (vty->got_epipe)
		goto out_clean;

	knet_vty_cli_bind(vty);

out_clean:
	pthread_mutex_lock(&knet_vty_mutex);
	knet_vty_close(vty);
	pthread_mutex_unlock(&knet_vty_mutex);

	return NULL;
}

/*
 * mainloop is not thread safe as there should only be one
 */
int knet_vty_main_loop(int debug)
{
	int logfd[2];
	int vty_listener6_fd;
	int vty_listener4_fd;
	int vty_listener_fd;
	int vty_accept_fd;
	struct sockaddr_storage incoming_sa;
	socklen_t salen;
	fd_set rfds;
	int se_result = 0;
	struct timeval tv;
	int err = 0;
	int conn_index, found;

	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);
	signal(SIGPIPE, sigpipe_handler);

	if (pipe(logfd)) {
		log_error("Unable to create logging pipe");
		return -1;
	}

	if ((_fdset_cloexec(logfd[0])) ||
	    (_fdset_nonblock(logfd[0])) ||
	    (_fdset_cloexec(logfd[1])) ||
	    (_fdset_nonblock(logfd[1]))) {
		log_error("Unable to set FD_CLOEXEX / O_NONBLOCK on logfd pipe");
		return -1;
	}

	err = pthread_create(&logging_thread,
			     NULL, _handle_logging_thread,
			     (void *)&logfd[0]);
	if (err) {
		log_error("Unable to create logging thread");
		return -1;
	}

	memset(&knet_vtys, 0, sizeof(knet_vtys));
	memset(&vty_global_conf, 0, sizeof(struct knet_vty_global_conf));
	vty_global_conf.idle_timeout = KNET_VTY_CLI_TIMEOUT;

	for(conn_index = 0; conn_index < KNET_VTY_TOTAL_MAX_CONN; conn_index++) {
		knet_vtys[conn_index].logfd = logfd[1];
		knet_vtys[conn_index].vty_global_conf = &vty_global_conf;
		if (debug) {
			knet_vtys[conn_index].loglevel = KNET_LOG_DEBUG;
		} else {
			knet_vtys[conn_index].loglevel = KNET_LOG_INFO;
		}
	}

	if (knet_read_conf() < 0) {
		log_error("Unable to read config file %s", knet_cfg_head.conffile);
		return -1;
	}

	vty_listener6_fd = knet_vty_init_listener(knet_cfg_head.vty_ipv6,
						  knet_cfg_head.vty_port);
	if (vty_listener6_fd < 0) {
		log_error("Unable to setup vty listener for ipv6");
		return -1;
	}

	vty_listener4_fd = knet_vty_init_listener(knet_cfg_head.vty_ipv4,
						  knet_cfg_head.vty_port);

	if (vty_listener4_fd < 0) {
		log_error("Unable to setup vty listener for ipv4");
		goto out;
	}

	while (se_result >= 0 && !daemon_quit) {
		FD_ZERO (&rfds);
		FD_SET (vty_listener6_fd, &rfds);
		FD_SET (vty_listener4_fd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select(FD_SETSIZE, &rfds, 0, 0, &tv);

		if ((se_result == -1) && (daemon_quit)) {
			log_info("Got a SIGTERM, requesting CLI threads to exit");	
			for(conn_index = 0; conn_index < KNET_VTY_TOTAL_MAX_CONN; conn_index++) {
				if (knet_vtys[conn_index].active) {
					knet_vty_write(&knet_vtys[conn_index], "%s%sServer is going down..%s%s",
						telnet_newline, telnet_newline, telnet_newline, telnet_newline);
					knet_vty_close(&knet_vtys[conn_index]);
					knet_vtys[conn_index].got_epipe = 1;
				}
			}
			sleep(2); /* give time to all vty to exit */
			knet_close_down();
			log_info("Have a nice day! Goodbye");
			goto out;
		}

		if (se_result == -1) {
			err = se_result;
			log_error("Unable to select on vty listener socket!");
			goto out;
		}

		if (se_result == 0) {
			pthread_mutex_lock(&knet_vty_mutex);
			for(conn_index = 0; conn_index < KNET_VTY_TOTAL_MAX_CONN; conn_index++) {
				if ((knet_vtys[conn_index].active) &&
				    (knet_vtys[conn_index].idle_timeout)) {
					knet_vtys[conn_index].idle++;
					if (knet_vtys[conn_index].idle > knet_vtys[conn_index].idle_timeout) {
						knet_vty_close(&knet_vtys[conn_index]);
						knet_vtys[conn_index].got_epipe = 1;
					}
				}
			}
			pthread_mutex_unlock(&knet_vty_mutex);
			continue;
		}

		if (FD_ISSET(vty_listener6_fd, &rfds)) {
			vty_listener_fd = vty_listener6_fd;
		} else if (FD_ISSET(vty_listener4_fd, &rfds)) {
			vty_listener_fd = vty_listener4_fd;
		} else {
			continue;
		}

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
		knet_vtys[conn_index].logfd = logfd[1];
		knet_vtys[conn_index].vty_global_conf = &vty_global_conf;
		knet_vtys[conn_index].idle_timeout = vty_global_conf.idle_timeout;
		if (debug) {
			knet_vtys[conn_index].loglevel = KNET_LOG_DEBUG;
		} else {
			knet_vtys[conn_index].loglevel = KNET_LOG_INFO;
		}

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
	pthread_cancel(logging_thread);
	knet_vty_close_listener(vty_listener6_fd);
	knet_vty_close_listener(vty_listener4_fd);
	close(logfd[0]);
	close(logfd[1]);

	return err;
}

/*
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
*/
