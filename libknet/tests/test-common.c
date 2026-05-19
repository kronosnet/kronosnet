
/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/select.h>
#include <poll.h>

#include "libknet.h"
#include "internals.h"
#include "test-common.h"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_init = 0;
static pthread_mutex_t log_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t log_thread;
static int log_thread_init = 0;
static int log_fds[2];
struct log_thread_data {
	int logfd;
	FILE *std;
};
static struct log_thread_data data;
static char plugin_path[PATH_MAX];
static struct timeval log_start_time;
static int log_start_time_init = 0;

/* Log filter state for runtime pattern matching */
static pthread_mutex_t log_filter_mutex = PTHREAD_MUTEX_INITIALIZER;
static log_filter_fn log_filter_callback = NULL;
static int log_filter_logfd = -1;
static void *log_filter_private_data = NULL;
static int log_pattern_found = 0;

int is_memcheck(void)
{
	char *val;

	val = getenv("KNETMEMCHECK");

	if (val) {
		if (!strncmp(val, "yes", 3)) {
			return 1;
		}
	}

	return 0;
}

int is_helgrind(void)
{
	char *val;

	val = getenv("KNETHELGRIND");

	if (val) {
		if (!strncmp(val, "yes", 3)) {
			return 1;
		}
	}

	return 0;
}

static int adjust_timeout_for_valgrind(int seconds, int logfd)
{
	if (is_memcheck() || is_helgrind()) {
		int adjusted = seconds * 16;
		log_test(logfd, "Running under valgrind, adjusting timeout from %d to %d seconds",
			 seconds, adjusted);
		return adjusted;
	}
	return seconds;
}

static int setup_logpipes(int *logfds)
{
	if (pipe2(logfds, O_CLOEXEC | O_NONBLOCK) < 0) {
		printf("Unable to setup logging pipe\n");
		exit(FAIL);
	}

	if (!log_start_time_init) {
		gettimeofday(&log_start_time, NULL);
		log_start_time_init = 1;
	}

	// coverity[ORDER_REVERSAL:SUPPRESS] - it's a test, get over it
	return PASS;
}

static void close_logpipes(int *logfds)
{
	close(logfds[0]);
	logfds[0] = 0;
	close(logfds[1]);
	logfds[1] = 0;
}

static void flush_logs(int logfd, FILE *std)
{
	struct knet_log_msg msg;
	int len;
	struct timeval now, elapsed;
	long elapsed_sec, elapsed_usec;
	char log_line[1024];

	while (1) {
		len = read(logfd, &msg, sizeof(msg));
		if (len != sizeof(msg)) {
			/*
			 * clear errno to avoid incorrect propagation
			 */
			errno = 0;
			return;
		}

		msg.msg[sizeof(msg.msg) - 1] = 0;

		gettimeofday(&now, NULL);
		timersub(&now, &log_start_time, &elapsed);
		elapsed_sec = elapsed.tv_sec;
		elapsed_usec = elapsed.tv_usec / 1000; /* convert to milliseconds */

		if (msg.subsystem == (KNET_SUB_UNKNOWN - 1) && msg.msglevel == 0) {
			snprintf(log_line, sizeof(log_line),
				 "[%6ld.%03ld] [testsuite]: %.*s",
				 elapsed_sec, elapsed_usec,
				 KNET_MAX_LOG_MSG_SIZE, msg.msg);
		} else {
			snprintf(log_line, sizeof(log_line),
				 "[%6ld.%03ld] [%s] %s: %.*s",
				 elapsed_sec, elapsed_usec,
				 knet_log_get_loglevel_name(msg.msglevel),
				 knet_log_get_subsystem_name(msg.subsystem),
				 KNET_MAX_LOG_MSG_SIZE, msg.msg);
		}

		fprintf(std, "%s\n", log_line);

		/* Check log filter if installed */
		pthread_mutex_lock(&log_filter_mutex);
		if (log_filter_callback != NULL) {
			if (log_filter_callback(log_filter_logfd, log_line, log_filter_private_data)) {
				log_pattern_found = 1;
			}
		}
		pthread_mutex_unlock(&log_filter_mutex);
	}
}

static void *_logthread(void *args)
{
	while (1) {
		int num;
		struct timeval tv = { 60, 0 };
		fd_set rfds;

		FD_ZERO(&rfds);
		FD_SET(data.logfd, &rfds);

		num = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
		if (num < 0) {
			fprintf(data.std, "Unable select over logfd!\nHALTING LOGTHREAD!\n");
			return NULL;
		}
		if (num == 0) {
			fprintf(data.std, "[knet]: No logs in the last 60 seconds\n");
			continue;
		}
		if (FD_ISSET(data.logfd, &rfds)) {
			flush_logs(data.logfd, data.std);
		}
	}
}

static int start_logthread(int logfd, FILE *std)
{
	int savederrno = 0;

	savederrno = pthread_mutex_lock(&log_thread_mutex);
	if (savederrno) {
		printf("Unable to get log_thread mutex lock\n");
		return -1;
	}

	if (!log_thread_init) {
		data.logfd = logfd;
		data.std = std;

		savederrno = pthread_create(&log_thread, 0, _logthread, NULL);
		if (savederrno) {
			printf("Unable to start logging thread: %s\n", strerror(savederrno));
			pthread_mutex_unlock(&log_thread_mutex);
			return -1;
		}
		log_thread_init = 1;
	}

	pthread_mutex_unlock(&log_thread_mutex);
	return 0;
}

static int stop_logthread(void)
{
	int savederrno = 0;
	void *retval;

	savederrno = pthread_mutex_lock(&log_thread_mutex);
	if (savederrno) {
		printf("Unable to get log_thread mutex lock\n");
		return -1;
	}

	if (log_thread_init) {
		pthread_cancel(log_thread);
		pthread_join(log_thread, &retval);
		log_thread_init = 0;
	}

	pthread_mutex_unlock(&log_thread_mutex);
	return 0;
}

void stop_logging(void)
{
	int savederrno = 0;

	savederrno = pthread_mutex_lock(&log_mutex);
	if (savederrno) {
		printf("Unable to get log_mutex lock\n");
		return;
	}

	if (log_init) {
		stop_logthread();
		flush_logs(log_fds[0], stdout);
		close_logpipes(log_fds);
		log_start_time_init = 0;
		log_init = 0;
	}

	pthread_mutex_unlock(&log_mutex);
}

int start_logging(FILE *std)
{
	int savederrno = 0;

	savederrno = pthread_mutex_lock(&log_mutex);
	if (savederrno) {
		printf("Unable to get log_mutex lock\n");
		return -1;
	}

	if (!log_init) {
		setup_logpipes(log_fds);

		if (atexit(&stop_logging) != 0) {
			printf("Unable to register atexit handler to stop logging: %s\n",
			       strerror(errno));
			exit(FAIL);
		}

		if (start_logthread(log_fds[0], std) < 0) {
			exit(FAIL);
		}

		log_init = 1;
	}

	pthread_mutex_unlock(&log_mutex);

	// coverity[MISSING_LOCK:SUPPRESS] - log_fds[1] is set while holding lock and doesn't change after init
	return log_fds[1];
}

static int dir_filter(const struct dirent *dname)
{
	if ( (strcmp(dname->d_name + strlen(dname->d_name)-3, ".so") == 0) &&
	    ((strncmp(dname->d_name,"crypto", 6) == 0) ||
	     (strncmp(dname->d_name,"compress", 8) == 0))) {
		return 1;
	}
	return 0;
}

/* Make sure the proposed plugin path has at least 1 of each plugin available
   - just as a sanity check really */
static int contains_plugins(char *path)
{
	struct dirent **namelist;
	int n,i;
	size_t j;
	struct knet_compress_info compress_list[256];
	struct knet_crypto_info crypto_list[256];
	size_t num_compress, num_crypto;
	size_t compress_found = 0;
	size_t crypto_found = 0;

	if (knet_get_compress_list(compress_list, &num_compress) == -1) {
		return 0;
	}
	if (knet_get_crypto_list(crypto_list, &num_crypto) == -1) {
		return 0;
	}

	// coverity[UNINIT:SUPPRESS] - it's supposed to be...
	n = scandir(path, &namelist, dir_filter, alphasort);
	if (n == -1) {
		return 0;
	}

	/* Look for plugins in the list */
	for (i=0; i<n; i++) {
		for (j=0; j<num_crypto; j++) {
			if (strlen(namelist[i]->d_name) >= 7 &&
			    strncmp(crypto_list[j].name, namelist[i]->d_name+7,
				    strlen(crypto_list[j].name)) == 0) {
				crypto_found++;
			}
		}
		for (j=0; j<num_compress; j++) {
			if (strlen(namelist[i]->d_name) >= 9 &&
			    strncmp(compress_list[j].name, namelist[i]->d_name+9,
				    strlen(compress_list[j].name)) == 0) {
				compress_found++;
			}
		}
		free(namelist[i]);
	}
	free(namelist);
	/* If at least one plugin was found (or none were built) */
	if ((crypto_found || num_crypto == 0) &&
	    (compress_found || num_compress == 0)) {
		return 1;
	} else {
		return 0;
	}
}


/* libtool sets LD_LIBRARY_PATH to the build tree when running test in-tree */
char *find_plugins_path(int logfd)
{
	char *ld_libs_env = getenv("LD_LIBRARY_PATH");
	if (ld_libs_env) {
		char *ld_libs = strdup(ld_libs_env);
		char *str = strtok(ld_libs, ":");
		while (str) {
			if (contains_plugins(str)) {
				strncpy(plugin_path, str, sizeof(plugin_path)-1);
				free(ld_libs);
				log_test(logfd, "Using plugins from %.200s", plugin_path);
				return plugin_path;
			}
			str = strtok(NULL, ":");
		}
		free(ld_libs);
	}
	return NULL;
}


knet_handle_t _ts_knet_handle_start(int logfd, uint8_t log_level, knet_handle_t knet_h_array[])
{
	knet_handle_t knet_h = knet_handle_new_ex(1, logfd, log_level, 0);
	char *plugins_path;

	if (knet_h) {
		log_test(logfd, "knet_handle_new at %p", knet_h);
		plugins_path = find_plugins_path(logfd);
		/* Use plugins from the build tree */
		if (plugins_path) {
			knet_h->plugin_path = plugins_path;
		}
		knet_h_array[1] = knet_h;
		return knet_h;
	} else {
		log_test(logfd, "knet_handle_new failed: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}
}

int _ts_knet_handle_reconnect_links(knet_handle_t knet_h, int logfd)
{
	size_t i, j;
	knet_node_id_t host_ids[KNET_MAX_HOST];
	uint8_t link_ids[KNET_MAX_LINK];
	size_t host_ids_entries = 0, link_ids_entries = 0;
	unsigned int enabled;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries) < 0) {
		log_test(logfd, "knet_host_get_host_list failed: %s", strerror(errno));
		return -1;
	}

	for (i = 0; i < host_ids_entries; i++) {
		if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
			log_test(logfd, "knet_link_get_link_list failed: %s", strerror(errno));
			return -1;
		}
		for (j = 0; j < link_ids_entries; j++) {
			if (knet_link_get_enable(knet_h, host_ids[i], link_ids[j], &enabled)) {
				log_test(logfd, "knet_link_get_enable failed: %s", strerror(errno));
				return -1;
			}
			if (!enabled) {
				if (knet_link_set_enable(knet_h, host_ids[i], j, 1)) {
					log_test(logfd, "knet_link_set_enable failed: %s", strerror(errno));
					return -1;
				}
			}
		}
	}

	return 0;
}

int _ts_knet_handle_disconnect_links(knet_handle_t knet_h, int logfd)
{
	size_t i, j;
	knet_node_id_t host_ids[KNET_MAX_HOST];
	uint8_t link_ids[KNET_MAX_LINK];
	size_t host_ids_entries = 0, link_ids_entries = 0;
	unsigned int enabled;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries) < 0) {
		log_test(logfd, "knet_host_get_host_list failed: %s", strerror(errno));
		return -1;
	}

	for (i = 0; i < host_ids_entries; i++) {
		if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
			log_test(logfd, "knet_link_get_link_list failed: %s", strerror(errno));
			return -1;
		}
		for (j = 0; j < link_ids_entries; j++) {
			if (knet_link_get_enable(knet_h, host_ids[i], link_ids[j], &enabled)) {
				log_test(logfd, "knet_link_get_enable failed: %s", strerror(errno));
				return -1;
			}
			if (enabled) {
				if (knet_link_set_enable(knet_h, host_ids[i], j, 0)) {
					log_test(logfd, "knet_link_set_enable failed: %s", strerror(errno));
					return -1;
				}
			}
		}
	}

	return 0;
}

static int _make_local_sockaddr(struct sockaddr_storage *lo, int offset, int family, int logfd)
{
	in_port_t port;
	char portstr[32];

	if (offset < 0) {
		/*
		 * api_knet_link_set_config needs to access the API directly, but
		 * it does not send any traffic, so it´s safe to ask the kernel
		 * for a random port.
		 */
		port = 0;
	} else {
		/* Use the pid if we can. but makes sure its in a sensible range */
		port = (getpid() + offset) % (TEST_PORT_MAX - TEST_PORT_BASE) + TEST_PORT_BASE;
	}
	sprintf(portstr, "%u", port);
	memset(lo, 0, sizeof(struct sockaddr_storage));
	log_test(logfd, "Using port %u", port);

	if (family == AF_INET6) {
		return knet_strtoaddr("::1", portstr, lo, sizeof(struct sockaddr_storage));
	}
	return knet_strtoaddr("127.0.0.1", portstr, lo, sizeof(struct sockaddr_storage));
}

int make_local_sockaddr(struct sockaddr_storage *lo, int offset, int logfd)
{
	return _make_local_sockaddr(lo, offset, AF_INET, logfd);
}

int make_local_sockaddr6(struct sockaddr_storage *lo, int offset, int logfd)
{
	return _make_local_sockaddr(lo, offset, AF_INET6, logfd);
}

int _ts_knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			  uint8_t transport, uint64_t flags, int family, int dynamic,
			  struct sockaddr_storage *lo, int logfd)
{
	int err = 0, savederrno = 0;
	uint32_t port;
	char portstr[32];

	for (port = TEST_PORT_MIN; port < TEST_PORT_MAX; port++) {
		sprintf(portstr, "%u", port);
		memset(lo, 0, sizeof(struct sockaddr_storage));
		if (family == AF_INET6) {
			err = knet_strtoaddr("::1", portstr, lo, sizeof(struct sockaddr_storage));
		} else {
			err = knet_strtoaddr("127.0.0.1", portstr, lo, sizeof(struct sockaddr_storage));
		}
		if (err < 0) {
			log_test(logfd, "Unable to convert loopback to sockaddr: %s", strerror(errno));
			goto out;
		}
		errno = 0;
		if (dynamic) {
			err = knet_link_set_config(knet_h, host_id, link_id, transport, lo, NULL, flags);
		} else {
			err = knet_link_set_config(knet_h, host_id, link_id, transport, lo, lo, flags);
		}
		savederrno = errno;
		if ((err < 0)  && (savederrno != EADDRINUSE)) {
			log_test(logfd, "Unable to configure link: %s", strerror(savederrno));
			goto out;
		}
		if (!err) {
			log_test(logfd, "Using port %u", port);
			goto out;
		}
	}

	if (err) {
		log_test(logfd, "No more ports available");
	}
out:
	errno = savederrno;
	return err;
}

void test_sleep(int logfd, int seconds)
{
	seconds = adjust_timeout_for_valgrind(seconds, logfd);
	log_test(logfd, "Sleeping for %d second%s", seconds, seconds == 1 ? "" : "s");
	sleep(seconds);
}

int wait_for_packet(knet_handle_t knet_h, int seconds, int datafd, int logfd)
{
	fd_set rfds;
	struct timeval tv;
	int err = 0, i = 0;

	seconds = adjust_timeout_for_valgrind(seconds, logfd);

try_again:
	FD_ZERO(&rfds);
	FD_SET(datafd, &rfds);

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	err = select(datafd+1, &rfds, NULL, NULL, &tv);
	/*
	 * on slow arches the first call to select can return 0.
	 * pick an arbitrary 10 times loop (multiplied by waiting seconds)
	 * before failing.
	 */
	if ((!err) && (i < seconds)) {
		i++;
		goto try_again;
	}
	if ((err > 0) && (FD_ISSET(datafd, &rfds))) {
		return 0;
	}

	errno = ETIMEDOUT;
	return -1;
}

/*
 * functional tests helpers
 */

void _ts_knet_handle_start_nodes(knet_handle_t knet_h[], uint8_t numnodes, int logfd, uint8_t log_level)
{
	uint8_t i;
	char *plugins_path = find_plugins_path(logfd);

	for (i = 1; i <= numnodes; i++) {
		knet_h[i] = knet_handle_new_ex(i, logfd, log_level, 0);
		if (!knet_h[i]) {
			log_test(logfd, "failed to create handle: %s", strerror(errno));
			break;
		} else {
			log_test(logfd, "knet_h[%u] at %p", i, knet_h[i]);
		}
		/* Use plugins from the build tree */
		if (plugins_path) {
			knet_h[i]->plugin_path = plugins_path;
		}
	}

	if (i < numnodes) {
		_ts_knet_handle_stop_everything(knet_h, i, logfd);
		exit(FAIL);
	}

	return;
}

void _ts_knet_handle_join_nodes(knet_handle_t knet_h[], uint8_t numnodes, uint8_t numlinks, int family, uint8_t transport, int logfd)
{
	uint8_t i, x, j, tmp_peer;
	struct sockaddr_storage lo;

	/*
	 * Phase 1: Add all peers and allocate ports with temporary configurations
	 * This binds ports without races - ports stay bound throughout
	 */
	log_test(logfd, "Phase 1: Adding peers and allocating ports for %u nodes with %u links each", numnodes, numlinks);

	for (i = 1; i <= numnodes; i++) {
		/* Add all peer nodes first */
		for (j = 1; j <= numnodes; j++) {
			if (j == i) {
				continue;
			}

			log_test(logfd, "host %u adding host: %u", i, j);

			if (knet_host_add(knet_h[i], j) < 0) {
				log_test(logfd, "Unable to add host: %s", strerror(errno));
				_ts_knet_handle_stop_everything(knet_h, numnodes, logfd);
				exit(FAIL);
			}
		}

		/* Configure links with temporary dst (use first peer as temporary dst) */
		tmp_peer = (i == 1) ? 2 : 1;
		for (x = 0; x < numlinks; x++) {
			/*
			 * Use _ts_knet_link_set_config to find available port
			 * Configure to temporary peer to bind the src port
			 * Port stays bound - we'll update dst in Phase 2
			 */
			if (_ts_knet_link_set_config(knet_h[i], tmp_peer, x, transport, 0, family, 0, &lo, logfd) < 0) {
				log_test(logfd, "Unable to allocate port for node %u link %u: %s", i, x, strerror(errno));
				_ts_knet_handle_stop_everything(knet_h, numnodes, logfd);
				exit(FAIL);
			}

			/*
			 * Hack: Clear the configured flag to allow reconfiguration to actual peer
			 * Port/socket stays bound, but API will allow reconfiguring to different host_id
			 */
			pthread_rwlock_wrlock(&knet_h[i]->global_rwlock);
			knet_h[i]->host_index[tmp_peer]->link[x].configured = 0;
			pthread_rwlock_unlock(&knet_h[i]->global_rwlock);
		}
	}

	/*
	 * Phase 2: Update link configurations with correct dst addresses
	 * All ports are now allocated and bound, just update destinations
	 */
	log_test(logfd, "Phase 2: Updating link destinations");

	for (i = 1; i <= numnodes; i++) {
		tmp_peer = (i == 1) ? 2 : 1;
		for (j = 1; j <= numnodes; j++) {
			if (j == i) {
				continue;
			}

			for (x = 0; x < numlinks; x++) {
				uint8_t tmp_peer_j = (j == 1) ? 2 : 1;
				struct sockaddr_storage src, dst;

				/*
				 * Copy addresses from link structures to local vars
				 * - src: node i's link x src_addr (bound in Phase 1)
				 * - dst: node j's link x src_addr (bound in Phase 1)
				 * Local copies required - passing pointers directly causes internal state issues
				 */
				memcpy(&src, &knet_h[i]->host_index[tmp_peer]->link[x].src_addr, sizeof(struct sockaddr_storage));
				memcpy(&dst, &knet_h[j]->host_index[tmp_peer_j]->link[x].src_addr, sizeof(struct sockaddr_storage));

				/*
				 * Update link configuration with correct dst
				 * Second call to knet_link_set_config updates the existing link
				 */
				if (knet_link_set_config(knet_h[i], j, x, transport, &src, &dst, 0) < 0) {
					log_test(logfd, "Unable to configure link: %s", strerror(errno));
					_ts_knet_handle_stop_everything(knet_h, numnodes, logfd);
					exit(FAIL);
				}

				if (knet_link_set_enable(knet_h[i], j, x, 1) < 0) {
					log_test(logfd, "unable to enable link: %s", strerror(errno));
					_ts_knet_handle_stop_everything(knet_h, numnodes, logfd);
					exit(FAIL);
				}
			}
		}
	}

	for (i = 1; i <= numnodes; i++) {
		wait_for_nodes_state(knet_h[i], numnodes, 1, TEST_TIMEOUT_LONG, logfd);
	}

	return;
}


static int target=0;

static int state_wait_pipe[2] = {0,0};
static int host_wait_pipe[2] = {0,0};
static int callback_logfd = -1;

static int count_nodes(knet_handle_t knet_h)
{
	int nodes = 0;
	int i;

	for (i=0; i< KNET_MAX_HOST; i++) {
		if (knet_h->host_index[i] && knet_h->host_index[i]->status.reachable == 1) {
			nodes++;
		}
	}
	return nodes;
}

static void nodes_notify_callback(void *private_data,
				  knet_node_id_t host_id,
				  uint8_t reachable, uint8_t remote, uint8_t external)
{
	knet_handle_t knet_h = (knet_handle_t) private_data;
	int nodes;
	int res;

	nodes = count_nodes(knet_h);

	if (nodes == target) {
		res = write(state_wait_pipe[1], ".", 1);
		if (res != 1) {
			log_test(callback_logfd, "***FAILed to signal wait_for_nodes_state: %s", strerror(errno));
		}
	}
}

/* Called atexit() */
static void finish_state_pipes()
{
	if (state_wait_pipe[0] != 0) {
		close(state_wait_pipe[0]);
		close(state_wait_pipe[1]);
		state_wait_pipe[0] = 0;
	}
	if (host_wait_pipe[0] != 0) {
		close(host_wait_pipe[0]);
		close(host_wait_pipe[1]);
		host_wait_pipe[0] = 0;
	}
}

static void host_notify_callback(void *private_data,
				 knet_node_id_t host_id,
				 uint8_t reachable, uint8_t remote, uint8_t external)
{
	knet_handle_t knet_h = (knet_handle_t) private_data;
	int res;

	if (knet_h->host_index[host_id]->status.reachable == 1) {
		res = write(host_wait_pipe[1], ".", 1);
		if (res != 1) {
			log_test(callback_logfd, "***FAILed to signal wait_for_host: %s", strerror(errno));
		}
	}
}

int wait_for_reply(int seconds, int pipefd, int logfd)
{
	int res;
	struct pollfd pfds;
	char tmpbuf[32];

	seconds = adjust_timeout_for_valgrind(seconds, logfd);

	pfds.fd = pipefd;
	pfds.events = POLLIN | POLLERR | POLLHUP;
	pfds.revents = 0;

	res = poll(&pfds, 1, seconds*1000);
	if (res == 1) {
		if (pfds.revents & POLLIN) {
			res = read(pipefd, tmpbuf, sizeof(tmpbuf));
			if (res > 0) {
				return 0;
			}
		} else {
			log_test(logfd, "Error on pipe poll revent = 0x%x", pfds.revents);
			errno = EIO;
		}
	}
	if (res == 0) {
		errno = ETIMEDOUT;
		return -1;
	}

	return -1;
}

/* Wait for a cluster of 'numnodes' to come up/go down */
int wait_for_nodes_state(knet_handle_t knet_h, size_t numnodes,
			 uint8_t state, uint32_t seconds,
			 int logfd)
{
	int res, savederrno = 0;

	callback_logfd = logfd;

	if (state_wait_pipe[0] == 0) {
		res = pipe(state_wait_pipe);
		if (res == -1) {
			savederrno = errno;
			log_test(logfd, "Error creating host reply pipe: %s", strerror(errno));
			errno = savederrno;
			return -1;
		}
		if (atexit(finish_state_pipes)) {
			log_test(logfd, "Unable to register atexit handler to close pipes: %s",
			       strerror(errno));
			exit(FAIL);
		}

	}

	if (state) {
		target = numnodes-1; /* exclude us */
	} else {
		target = 0; /* Wait for all to go down */
	}

	/* Set this before checking existing status or there's a race condition */
	knet_host_enable_status_change_notify(knet_h,
					      (void *)(long)knet_h,
					      nodes_notify_callback);

	/* Check we haven't already got all the nodes in the correct state */
	if (count_nodes(knet_h) == target) {
		log_test(logfd, "target already reached");
		knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);
		return 0;
	}

	res = wait_for_reply(seconds, state_wait_pipe[0], logfd);
	if (res == -1) {
		savederrno = errno;
		log_test(logfd, "Error waiting for nodes status reply: %s", strerror(errno));
	}

	knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);
	errno = savederrno;
	return res;
}

/* Wait for a single node to come up */
int wait_for_host(knet_handle_t knet_h, uint16_t host_id, int seconds, int logfd)
{
	int res = 0;
	int savederrno = 0;

	callback_logfd = logfd;

	if (host_wait_pipe[0] == 0) {
		res = pipe(host_wait_pipe);
		if (res == -1) {
			savederrno = errno;
			log_test(logfd, "Error creating host reply pipe: %s", strerror(errno));
			errno = savederrno;
			return -1;
		}
		if (atexit(finish_state_pipes)) {
			log_test(logfd, "Unable to register atexit handler to close pipes: %s",
			       strerror(errno));
			exit(FAIL);
		}

	}

	/* Set this before checking existing status or there's a race condition */
	knet_host_enable_status_change_notify(knet_h,
					      (void *)(long)knet_h,
					      host_notify_callback);

	/* Check it's not already reachable */
	if (knet_h->host_index[host_id]->status.reachable == 1) {
		knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);
		return 0;
	}

	res = wait_for_reply(seconds, host_wait_pipe[0], logfd);
	if (res == -1) {
		savederrno = errno;
		log_test(logfd, "Error waiting for host status reply: %s", strerror(errno));
	}

	knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);

	/* Still wait for it to settle */
	test_sleep(logfd, 1);
	errno = savederrno;
	return res;
}

/* Shutdown all nodes and links attached to an array of knet handles.
 * Mostly stolen from corosync code (that I wrote, before anyone complains about licences)
 */
void _ts_knet_handle_stop_everything(knet_handle_t knet_h[], uint8_t numnodes, int logfd)
{
	int res = 0;
	int h;
	size_t i,j;
	static knet_node_id_t nodes[KNET_MAX_HOST]; /* static to save stack */
	uint8_t links[KNET_MAX_LINK];
	size_t num_nodes;
	size_t num_links;

	for (h=1; h<numnodes+1; h++) {
		if (!knet_h[h]) {
			continue;
		}

		res = knet_handle_setfwd(knet_h[h], 0);
		if (res) {
			log_test(logfd, "knet_handle_setfwd failed: %s", strerror(errno));
		}

		res = knet_host_get_host_list(knet_h[h], nodes, &num_nodes);
		if (res) {
			log_test(logfd, "Cannot get knet node list for shutdown: %s", strerror(errno));
			continue;
		}

		/* Tidily shut down all nodes & links. */
		for (i=0; i<num_nodes; i++) {

			res = knet_link_get_link_list(knet_h[h], nodes[i], links, &num_links);
			if (res) {
				log_test(logfd, "Cannot get knet link list for node %u: %s", nodes[i], strerror(errno));
				goto finalise_error;
			}
			for (j=0; j<num_links; j++) {
				res = knet_link_set_enable(knet_h[h], nodes[i], links[j], 0);
				if (res) {
					log_test(logfd, "knet_link_set_enable(node %u, link %d) failed: %s", nodes[i], links[j], strerror(errno));
				}
				res = knet_link_clear_config(knet_h[h], nodes[i], links[j]);
				if (res) {
					log_test(logfd, "knet_link_clear_config(node %u, link %d) failed: %s", nodes[i], links[j], strerror(errno));
				}
			}
			res = knet_host_remove(knet_h[h], nodes[i]);
			if (res) {
				log_test(logfd, "knet_host_remove(node %u) failed: %s", nodes[i], strerror(errno));
			}
		}

	finalise_error:
		res = knet_handle_free(knet_h[h]);
		if (res) {
			log_test(logfd, "knet_handle_free failed: %s", strerror(errno));
		}
	}
}

/*
 * Packet injector: Create a packet and inject it into a link's socket
 *
 * This allows testing RX validation without network-level packet manipulation.
 * The caller provides a seq_num to avoid packet deduplication in the RX thread.
 *
 * Returns 0 on success, -1 on error
 */
int inject_packet(knet_handle_t knet_h,
		  uint8_t packet_type,
		  knet_node_id_t src_host_id,
		  uint8_t actual_link_id,
		  uint8_t claimed_link_id,
		  uint8_t frag_num,
		  uint8_t frag_seq,
		  seq_num_t seq_num,
		  const char *payload,
		  size_t payload_len)
{
	struct knet_header *packet;
	size_t packet_len;
	struct knet_host *src_host;
	struct knet_link *src_link;
	ssize_t sent;
	socklen_t addrlen;
	struct timespec timestamp;

	/* Determine packet size based on type */
	switch (packet_type) {
	case KNET_HEADER_TYPE_DATA:
		packet_len = KNET_HEADER_DATA_SIZE + payload_len;
		break;
	case KNET_HEADER_TYPE_PING:
		packet_len = KNET_HEADER_PING_SIZE;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	packet = malloc(packet_len);
	if (!packet) {
		return -1;
	}

	memset(packet, 0, packet_len);

	/* Fill in common packet header */
	packet->kh_version = 0;
	packet->kh_type = packet_type;
	packet->kh_node = htons(src_host_id);

	/* Fill in type-specific payload */
	switch (packet_type) {
	case KNET_HEADER_TYPE_DATA:
		packet->khp_data_seq_num = htons(seq_num);
		packet->khp_data_compress = 0;
		packet->khp_data_bcast = 0;
		packet->khp_data_channel = 0;
		packet->khp_data_frag_num = frag_num;
		packet->khp_data_frag_seq = frag_seq;

		/* Copy payload */
		if (payload && payload_len > 0) {
			memcpy(packet->khp_data_userdata, payload, payload_len);
		}
		break;
	case KNET_HEADER_TYPE_PING:
		packet->khp_ping_link = claimed_link_id;
		clock_gettime(CLOCK_MONOTONIC, &timestamp);
		memmove(&packet->khp_ping_time[0], &timestamp, sizeof(struct timespec));
		packet->khp_ping_seq_num = htons(seq_num);
		packet->khp_ping_timed = 1;
		break;
	}

	/* Get the source host and link to determine where to inject */
	src_host = knet_h->host_index[src_host_id];
	if (!src_host) {
		free(packet);
		return -1;
	}

	src_link = &src_host->link[actual_link_id];

	/* Check if link is properly configured */
	if (src_link->outsock < 0) {
		free(packet);
		return -1;
	}

	/* Determine address length based on address family */
	switch (src_link->dst_addr.ss_family) {
	case AF_INET:
		addrlen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		addrlen = sizeof(struct sockaddr_in6);
		break;
	default:
		free(packet);
		return -1;
	}

	/* Inject the packet by sending to ourselves (loopback) */
	sent = sendto(src_link->outsock, packet, packet_len, MSG_DONTWAIT | MSG_NOSIGNAL,
		      (struct sockaddr *)&src_link->dst_addr,
		      addrlen);

	free(packet);

	if (sent != (ssize_t)packet_len) {
		return -1;
	}

	return 0;
}

/*
 * Install a runtime log filter callback
 * Thread-safe via mutex protection
 */
void install_log_filter(int logfd, log_filter_fn filter_fn, void *private_data)
{
	pthread_mutex_lock(&log_filter_mutex);
	log_filter_callback = filter_fn;
	log_filter_logfd = logfd;
	log_filter_private_data = private_data;
	log_pattern_found = 0; /* Reset flag when installing new filter */
	pthread_mutex_unlock(&log_filter_mutex);
}

/*
 * Check if log filter found a pattern match
 * Returns current value and resets the flag
 */
int check_log_pattern_found(void)
{
	int found;

	pthread_mutex_lock(&log_filter_mutex);
	found = log_pattern_found;
	log_pattern_found = 0; /* Reset after reading */
	pthread_mutex_unlock(&log_filter_mutex);

	return found;
}
