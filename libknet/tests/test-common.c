
/*
 * Copyright (C) 2016-2021 Red Hat, Inc.  All rights reserved.
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
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/select.h>
#include <poll.h>

#include "libknet.h"
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

static int _read_pipe(int fd, char **file, size_t *length)
{
	char buf[4096];
	int n;
	int done = 0;

	*file = NULL;
	*length = 0;

	memset(buf, 0, sizeof(buf));

	while (!done) {

		n = read(fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;

			if (*file)
				free(*file);

			return n;
		}

		if (n == 0 && (!*length))
			return 0;

		if (n == 0)
			done = 1;

		if (*file)
			*file = realloc(*file, (*length) + n + done);
		else
			*file = malloc(n + done);

		if (!*file)
			return -1;

		memmove((*file) + (*length), buf, n);
		*length += (done + n);
	}

	/* Null terminator */
	(*file)[(*length) - 1] = 0;

	return 0;
}

int execute_shell(const char *command, char **error_string)
{
	pid_t pid;
	int status, err = 0;
	int fd[2];
	size_t size = 0;

	if ((command == NULL) || (!error_string)) {
		errno = EINVAL;
		return FAIL;
	}

	*error_string = NULL;

	err = pipe(fd);
	if (err)
		goto out_clean;

	pid = fork();
	if (pid < 0) {
		err = pid;
		goto out_clean;
	}

	if (pid) { /* parent */

		close(fd[1]);
		err = _read_pipe(fd[0], error_string, &size);
		if (err)
			goto out_clean0;

		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			err = -1;
			goto out_clean0;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			err = WEXITSTATUS(status);
			goto out_clean0;
		}
		goto out_clean0;
	} else { /* child */
		close(0);
		close(1);
		close(2);

		close(fd[0]);
		dup2(fd[1], 1);
		dup2(fd[1], 2);
		close(fd[1]);

		execlp("/bin/sh", "/bin/sh", "-c", command, NULL);
		exit(FAIL);
	}

out_clean:
	close(fd[1]);
out_clean0:
	close(fd[0]);

	return err;
}

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

void set_scheduler(int policy)
{
	struct sched_param sched_param;
	int err;

	err = sched_get_priority_max(policy);
	if (err < 0) {
		printf("Could not get maximum scheduler priority\n");
		exit(FAIL);
	}
	sched_param.sched_priority = err;
	err = sched_setscheduler(0, policy, &sched_param);
	if (err < 0) {
		printf("Could not set priority\n");
		exit(FAIL);
	}
	return;
}

int setup_logpipes(int *logfds)
{
	if (pipe2(logfds, O_CLOEXEC | O_NONBLOCK) < 0) {
		printf("Unable to setup logging pipe\n");
		exit(FAIL);
	}

	return PASS;
}

void close_logpipes(int *logfds)
{
	close(logfds[0]);
	logfds[0] = 0;
	close(logfds[1]);
	logfds[1] = 0;
}

void flush_logs(int logfd, FILE *std)
{
	struct knet_log_msg msg;
	int len;

	while (1) {
		len = read(logfd, &msg, sizeof(msg));
		if (len != sizeof(msg)) {
			/*
			 * clear errno to avoid incorrect propagation
			 */
			errno = 0;
			return;
		}

		if (!msg.knet_h) {
			/*
			 * this is harsh but this function is void
			 * and it is used also inside log_thread.
			 * this is the easiest to get out with an error
			 */
			fprintf(std, "NO HANDLE INFO IN LOG MSG!!\n");
			abort();
		}

		msg.msg[sizeof(msg.msg) - 1] = 0;

		fprintf(std, "[knet: %p]: [%s] %s: %.*s\n",
			msg.knet_h,
			knet_log_get_loglevel_name(msg.msglevel),
			knet_log_get_subsystem_name(msg.subsystem),
			KNET_MAX_LOG_MSG_SIZE, msg.msg);
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

int start_logthread(int logfd, FILE *std)
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

int stop_logthread(void)
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

static void stop_logging(void)
{
	stop_logthread();
	flush_logs(log_fds[0], stdout);
	close_logpipes(log_fds);
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
char *find_plugins_path(void)
{
	char *ld_libs_env = getenv("LD_LIBRARY_PATH");
	if (ld_libs_env) {
		char *ld_libs = strdup(ld_libs_env);
		char *str = strtok(ld_libs, ":");
		while (str) {
			if (contains_plugins(str)) {
				strncpy(plugin_path, str, sizeof(plugin_path)-1);
				free(ld_libs);
				printf("Using plugins from %s\n", plugin_path);
				return plugin_path;
			}
			str = strtok(NULL, ":");
		}
		free(ld_libs);
	}
	return NULL;
}


knet_handle_t knet_handle_start(int logfds[2], uint8_t log_level)
{
	knet_handle_t knet_h = knet_handle_new(1, logfds[1], log_level, 0);
	char *plugins_path;

	if (knet_h) {
		printf("knet_handle_new at %p\n", knet_h);
		plugins_path = find_plugins_path();
		/* Use plugins from the build tree */
		if (plugins_path) {
			knet_h->plugin_path = plugins_path;
		}
		return knet_h;
	} else {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
}

int knet_handle_reconnect_links(knet_handle_t knet_h)
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
		printf("knet_host_get_host_list failed: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < host_ids_entries; i++) {
		if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
			printf("knet_link_get_link_list failed: %s\n", strerror(errno));
			return -1;
		}
		for (j = 0; j < link_ids_entries; j++) {
			if (knet_link_get_enable(knet_h, host_ids[i], link_ids[j], &enabled)) {
				printf("knet_link_get_enable failed: %s\n", strerror(errno));
				return -1;
			}
			if (!enabled) {
				if (knet_link_set_enable(knet_h, host_ids[i], j, 1)) {
					printf("knet_link_set_enable failed: %s\n", strerror(errno));
					return -1;
				}
			}
		}
	}

	return 0;
}

int knet_handle_disconnect_links(knet_handle_t knet_h)
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
		printf("knet_host_get_host_list failed: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < host_ids_entries; i++) {
		if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
			printf("knet_link_get_link_list failed: %s\n", strerror(errno));
			return -1;
		}
		for (j = 0; j < link_ids_entries; j++) {
			if (knet_link_get_enable(knet_h, host_ids[i], link_ids[j], &enabled)) {
				printf("knet_link_get_enable failed: %s\n", strerror(errno));
				return -1;
			}
			if (enabled) {
				if (knet_link_set_enable(knet_h, host_ids[i], j, 0)) {
					printf("knet_link_set_enable failed: %s\n", strerror(errno));
					return -1;
				}
			}
		}
	}

	return 0;
}

int knet_handle_stop(knet_handle_t knet_h)
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

	if (knet_handle_setfwd(knet_h, 0) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		return -1;
	}

	if (knet_host_get_host_list(knet_h, host_ids, &host_ids_entries) < 0) {
		printf("knet_host_get_host_list failed: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < host_ids_entries; i++) {
		if (knet_link_get_link_list(knet_h, host_ids[i], link_ids, &link_ids_entries)) {
			printf("knet_link_get_link_list failed: %s\n", strerror(errno));
			return -1;
		}
		for (j = 0; j < link_ids_entries; j++) {
			if (knet_link_get_enable(knet_h, host_ids[i], link_ids[j], &enabled)) {
				printf("knet_link_get_enable failed: %s\n", strerror(errno));
				return -1;
			}
			if (enabled) {
				if (knet_link_set_enable(knet_h, host_ids[i], j, 0)) {
					printf("knet_link_set_enable failed: %s\n", strerror(errno));
					return -1;
				}
			}
			printf("clearing config for: %p host: %u link: %zu\n", knet_h, host_ids[i], j);
			knet_link_clear_config(knet_h, host_ids[i], j);
		}
		if (knet_host_remove(knet_h, host_ids[i]) < 0) {
			printf("knet_host_remove failed: %s\n", strerror(errno));
			return -1;
		}
	}

	if (knet_handle_free(knet_h)) {
		printf("knet_handle_free failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int _make_local_sockaddr(struct sockaddr_storage *lo, int offset, int family)
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
		port = (getpid() + offset) % (65536-1024) + 1024;
	}
	sprintf(portstr, "%u", port);
	memset(lo, 0, sizeof(struct sockaddr_storage));
	printf("Using port %u\n", port);

	if (family == AF_INET6) {
		return knet_strtoaddr("::1", portstr, lo, sizeof(struct sockaddr_storage));
	}
	return knet_strtoaddr("127.0.0.1", portstr, lo, sizeof(struct sockaddr_storage));
}

int make_local_sockaddr(struct sockaddr_storage *lo, int offset)
{
	return _make_local_sockaddr(lo, offset, AF_INET);
}

int make_local_sockaddr6(struct sockaddr_storage *lo, int offset)
{
	return _make_local_sockaddr(lo, offset, AF_INET6);
}

int _knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			  uint8_t transport, uint64_t flags, int family, int dynamic,
			  struct sockaddr_storage *lo)
{
	int err = 0, savederrno = 0;
	uint32_t port;
	char portstr[32];

	for (port = 1025; port < 65536; port++) {
		sprintf(portstr, "%u", port);
		memset(lo, 0, sizeof(struct sockaddr_storage));
		if (family == AF_INET6) {
			err = knet_strtoaddr("::1", portstr, lo, sizeof(struct sockaddr_storage));
		} else {
			err = knet_strtoaddr("127.0.0.1", portstr, lo, sizeof(struct sockaddr_storage));
		}
		if (err < 0) {
			printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
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
			printf("Unable to configure link: %s\n", strerror(savederrno));
			goto out;
		}
		if (!err) {
			printf("Using port %u\n", port);
			goto out;
		}
	}

	if (err) {
		printf("No more ports available\n");
	}
out:
	errno = savederrno;
	return err;
}

void test_sleep(knet_handle_t knet_h, int seconds)
{
	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting sleep timers\n");
		seconds = seconds * 16;
	}
	sleep(seconds);
}


int wait_for_packet(knet_handle_t knet_h, int seconds, int datafd, int logfd, FILE *std)
{
	fd_set rfds;
	struct timeval tv;
	int err = 0, i = 0;

	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting wait_for_packet timeout\n");
		seconds = seconds * 16;
	}

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
		flush_logs(logfd, std);
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

void knet_handle_start_nodes(knet_handle_t knet_h[], uint8_t numnodes, int logfds[2], uint8_t log_level)
{
	uint8_t i;
	char *plugins_path = find_plugins_path();

	for (i = 1; i <= numnodes; i++) {
		knet_h[i] = knet_handle_new(i, logfds[1], log_level, 0);
		if (!knet_h[i]) {
			printf("failed to create handle: %s\n", strerror(errno));
			break;
		} else {
			printf("knet_h[%u] at %p\n", i, knet_h[i]);
		}
		/* Use plugins from the build tree */
		if (plugins_path) {
			knet_h[i]->plugin_path = plugins_path;
		}
	}

	if (i < numnodes) {
		knet_handle_stop_nodes(knet_h, i);
		exit(FAIL);
	}

	return;
}

void knet_handle_stop_nodes(knet_handle_t knet_h[], uint8_t numnodes)
{
	uint8_t i;

	for (i = 1; i <= numnodes; i++) {
		if (knet_h[i]) {
			printf("stopping handle %u at %p\n", i, knet_h[i]);
			knet_handle_stop(knet_h[i]);
		}
	}

	return;
}

void knet_handle_join_nodes(knet_handle_t knet_h[], uint8_t numnodes, uint8_t numlinks, int family, uint8_t transport)
{
	uint8_t i, x, j;
	struct sockaddr_storage src, dst;
	int offset = 0;
	int res;

	for (i = 1; i <= numnodes; i++) {
		for (j = 1; j <= numnodes; j++) {
			/*
			 * don´t connect to itself
			 */
			if (j == i) {
				continue;
			}

			printf("host %u adding host: %u\n", i, j);

			if (knet_host_add(knet_h[i], j) < 0) {
				printf("Unable to add host: %s\n", strerror(errno));
				knet_handle_stop_nodes(knet_h, numnodes);
				exit(FAIL);
			}

			for (x = 0; x < numlinks; x++) {
				res = -1;
				offset = 0;
				while (i + x + offset++ < 65535 && res != 0) {
					if (_make_local_sockaddr(&src, i + x + offset, family) < 0) {
						printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
						knet_handle_stop_nodes(knet_h, numnodes);
						exit(FAIL);
					}

					if (_make_local_sockaddr(&dst, j + x + offset, family) < 0) {
						printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
						knet_handle_stop_nodes(knet_h, numnodes);
						exit(FAIL);
					}

					res = knet_link_set_config(knet_h[i], j, x, transport, &src, &dst, 0);
				}
				printf("joining node %u with node %u via link %u src offset: %u dst offset: %u\n", i, j, x, i+x, j+x);
				if (knet_link_set_enable(knet_h[i], j, x, 1) < 0) {
					printf("unable to enable link: %s\n", strerror(errno));
					knet_handle_stop_nodes(knet_h, numnodes);
					exit(FAIL);
				}
			}
		}
	}

	for (i = 1; i <= numnodes; i++) {
		wait_for_nodes_state(knet_h[i], numnodes, 1, 600, knet_h[1]->logfd, stdout);
	}
	return;
}


static int target=0;

static int state_wait_pipe[2] = {0,0};
static int host_wait_pipe[2] = {0,0};

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
			printf("***FAILed to signal wait_for_nodes_state: %s\n", strerror(errno));
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
			printf("***FAILed to signal wait_for_host: %s\n", strerror(errno));
		}
	}
}

static int wait_for_reply(int seconds, int pipefd)
{
	int res;
	struct pollfd pfds;
	char tmpbuf[32];

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
			printf("Error on pipe poll revent = 0x%x\n", pfds.revents);
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
			 uint8_t state, uint32_t timeout,
			 int logfd, FILE *std)
{
	int res, savederrno = 0;

	if (state_wait_pipe[0] == 0) {
		res = pipe(state_wait_pipe);
		if (res == -1) {
			savederrno = errno;
			printf("Error creating host reply pipe: %s\n", strerror(errno));
			errno = savederrno;
			return -1;
		}
		if (atexit(finish_state_pipes)) {
			printf("Unable to register atexit handler to close pipes: %s\n",
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
		fprintf(stderr, "target already reached\n");
		knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);
		flush_logs(logfd, std);
		return 0;
	}

	res = wait_for_reply(timeout, state_wait_pipe[0]);
	if (res == -1) {
		savederrno = errno;
		printf("Error waiting for nodes status reply: %s\n", strerror(errno));
	}

	knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);
	flush_logs(logfd, std);
	errno = savederrno;
	return res;
}

/* Wait for a single node to come up */
int wait_for_host(knet_handle_t knet_h, uint16_t host_id, int seconds, int logfd, FILE *std)
{
	int res = 0;
	int savederrno = 0;

	if (is_memcheck() || is_helgrind()) {
		printf("Test suite is running under valgrind, adjusting wait_for_host timeout\n");
		seconds = seconds * 16;
	}

	if (host_wait_pipe[0] == 0) {
		res = pipe(host_wait_pipe);
		if (res == -1) {
			savederrno = errno;
			printf("Error creating host reply pipe: %s\n", strerror(errno));
			errno = savederrno;
			return -1;
		}
		if (atexit(finish_state_pipes)) {
			printf("Unable to register atexit handler to close pipes: %s\n",
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
		flush_logs(logfd, std);
		return 0;
	}

	res = wait_for_reply(seconds, host_wait_pipe[0]);
	if (res == -1) {
		savederrno = errno;
		printf("Error waiting for host status reply: %s\n", strerror(errno));
	}

	knet_host_enable_status_change_notify(knet_h, (void *)(long)0, NULL);

	/* Still wait for it to settle */
	flush_logs(logfd, std);
	test_sleep(knet_h, 1);
	errno = savederrno;
	return res;
}
