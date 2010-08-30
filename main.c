#include "config.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"
#include "controlt.h"
#include "netsocket.h"
#include "utils.h"
#include "cnet.h"

#define LOCKFILE_NAME RUNDIR PACKAGE ".pid"

#define OPTION_STRING "hdfVc:"

int daemonize = 1;
int debug = 0;
int daemon_quit = 0;
char *conffile = NULL;
int statistics = 0;
int rerouting = 0;
int net_sock;
int eth_fd;
char localnet[16]; /* match IFNAMSIZ from linux/if.h */
static pthread_t eth_thread;
struct node *mainconf;

static void print_usage(void)
{
	printf("Usage:\n\n");
	printf(PACKAGE " [options]\n\n");
	printf("Options:\n\n");
	printf("  -c <file> Use config file (default "CONFFILE")\n");
	printf("  -f        Do not fork in background\n");
	printf("  -d        Enable debugging output\n");
	printf("  -h        This help\n");
	printf("  -V        Print program version information\n");
	return;
}

static void read_arguments(int argc, char **argv)
{
	int cont = 1;
	int optchar;

	while (cont) {
		optchar = getopt(argc, argv, OPTION_STRING);

		switch (optchar) {

		case 'c':
			conffile = strdup(optarg);
			break;

		case 'd':
			debug = 1;
			break;

		case 'f':
			daemonize = 0;
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;

		case 'V':
			printf(PACKAGE " " PACKAGE_VERSION " (built " __DATE__
			       " " __TIME__ ")\n");
			exit(EXIT_SUCCESS);
			break;

		case EOF:
			cont = 0;
			break;

		default:
			fprintf(stderr, "unknown option: %c\n", optchar);
			print_usage();
			exit(EXIT_FAILURE);
			break;

		}
	}
}

static void set_oom_adj(int val)
{
	FILE *fp;

	fp = fopen("/proc/self/oom_adj", "w");
	if (!fp)
		return;

	fprintf(fp, "%i", val);
	fclose(fp);
}

static void set_scheduler(void)
{
	struct sched_param sched_param;
	int err;

	err = sched_get_priority_max(SCHED_RR);
	if (err != -1) {
		sched_param.sched_priority = err;
		err = sched_setscheduler(0, SCHED_RR, &sched_param);
		if (err == -1)
			logt_print(LOG_WARNING,
				   "could not set SCHED_RR priority %d err %d",
				   sched_param.sched_priority, errno);
	} else {
		logt_print(LOG_WARNING,
			   "could not get maximum scheduler priority err %d",
			   errno);
	}
}

static void remove_lockfile(void)
{
	unlink(LOCKFILE_NAME);
}

static int create_lockfile(const char *lockfile)
{
	int fd, value;
	size_t bufferlen;
	ssize_t write_out;
	struct flock lock;
	char buffer[50];

	if ((fd = open(lockfile, O_CREAT | O_WRONLY,
		       (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) < 0) {
		fprintf(stderr, "Cannot open lockfile [%s], error was [%s]\n",
			lockfile, strerror(errno));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

retry_fcntl:

	if (fcntl(fd, F_SETLK, &lock) < 0) {
		switch (errno) {
		case EINTR:
			goto retry_fcntl;
			break;
		case EACCES:
		case EAGAIN:
			fprintf(stderr, "Cannot lock lockfile [%s], error was [%s]\n",
				lockfile, strerror(errno));
			break;
		default:
			fprintf(stderr, "process is already running\n");
		}

		goto fail_close;
	}

	if (ftruncate(fd, 0) < 0) {
		fprintf(stderr, "Cannot truncate pidfile [%s], error was [%s]\n",
			lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer)-1, "%u\n", getpid());

	bufferlen = strlen(buffer);
	write_out = write(fd, buffer, bufferlen);

	if ((write_out < 0) || (write_out == 0 && errno)) {
		fprintf(stderr, "Cannot write pid to pidfile [%s], error was [%s]\n",
			lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	if ((write_out == 0) || (write_out < bufferlen)) {
		fprintf(stderr, "Cannot write pid to pidfile [%s], shortwrite of"
				"[%zu] bytes, expected [%zu]\n",
				lockfile, write_out, bufferlen);

		goto fail_close_unlink;
	}

	if ((value = fcntl(fd, F_GETFD, 0)) < 0) {
		fprintf(stderr, "Cannot get close-on-exec flag from pidfile [%s], "
				"error was [%s]\n", lockfile, strerror(errno));

		goto fail_close_unlink;
	}
	value |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, value) < 0) {
		fprintf(stderr, "Cannot set close-on-exec flag from pidfile [%s], "
				"error was [%s]\n", lockfile, strerror(errno));

		goto fail_close_unlink;
	}

	return 0;

fail_close_unlink:
	if (unlink(lockfile))
		fprintf(stderr, "Unable to unlink %s\n", lockfile);

fail_close:
	if (close(fd))
		fprintf(stderr, "Unable to close %s file descriptor\n", lockfile);
	return -1;
}

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigpipe_handler(int sig)
{
	return;
}

static void *eth_to_cnet_thread(void *arg)
{
	fd_set rfds;
	int se_result;
	char read_buf[131072];
	ssize_t read_len = 0;
	struct timeval tv;

	do {
		FD_ZERO (&rfds);
		FD_SET (eth_fd, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((eth_fd + 1), &rfds, 0, 0, &tv);
		if (se_result == -1) {
			logt_print(LOG_CRIT, "Unable to select in eth thread: %s\n", strerror(errno));
			daemon_quit = 1;
		}

		if (se_result == 0)
			continue;

		if (FD_ISSET(eth_fd, &rfds)) {
			read_len = read(eth_fd, read_buf, sizeof(read_buf));
			if (read_len > 0) {
				logt_print(LOG_DEBUG, "Read %zu\n", read_len);
				dispatch_buf(mainconf, read_buf, read_len);
			} else if (read_len < 0) {
				logt_print(LOG_INFO, "Error reading from localnet error: %s\n", strerror(errno));
			} else
				logt_print(LOG_DEBUG, "Read 0?\n");
		}
	} while (se_result >= 0 && !daemon_quit);

	return NULL;
}

//static void *cnet_to_eth_thread(void *arg)
//{

	/* strip and process our internal header here */

	/* and write starting from read_buf+sizeof(our header) */
//	rv = do_write(eth_fd, read_buf, read_len);
//	close(net_fd);

//}

static void loop(void) {
	int net_sock_new, se_result;
	fd_set rfds;
	struct timeval tv;

	do {
		connect_to_nodes(mainconf);

		FD_ZERO (&rfds);
		FD_SET (net_sock, &rfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		se_result = select((net_sock + 1), &rfds, 0, 0, &tv);

		if (daemon_quit)
			goto out;

		if (se_result == -1) {
			logt_print(LOG_CRIT, "Unable to select: %s\n", strerror(errno));
			goto out;
		}

		if (se_result == 0)
			continue;

		if (FD_ISSET(net_sock, &rfds)) {

			net_sock_new = accept(net_sock, NULL, NULL);
			if (net_sock_new < 0) {
				logt_print(LOG_INFO, "Error accepting connections on netsocket error: %s\n", strerror(errno));
				continue;
			}

			/* XXXXXX: need to add net_fd to the right node entry */
			/* create a thread that we can signal to reload the fd entries for read */
		} 
out:
		if (se_result <0 || daemon_quit)
			logt_print(LOG_DEBUG, "End of mail loop\n");
	} while (se_result >= 0 && !daemon_quit);
}

int main(int argc, char **argv)
{
	confdb_handle_t confdb_handle = 0;
	int rv, eth_thread_started = 1;

	if (create_lockfile(LOCKFILE_NAME) < 0)
		exit(EXIT_FAILURE);

	atexit(remove_lockfile);

	read_arguments(argc, argv);

	if (!conffile)
		conffile = strdup(CONFFILE);

	confdb_handle = readconf(conffile);
	if (confdb_handle == 0)
		exit(EXIT_FAILURE);

	if (configure_logging(confdb_handle, 0) < 0) {
		fprintf(stderr, "Unable to initialize logging subsystem\n");
		exit(EXIT_FAILURE);
	}
	logt_print(LOG_INFO, PACKAGE " version " VERSION "\n");
	logt_exit();

	if (daemonize) {
		if (daemon(0, 0) < 0) {
			perror("Unable to daemonize");
			exit(EXIT_FAILURE);
		}
	}

	logt_reinit();

	signal(SIGTERM, sigterm_handler);
	signal(SIGPIPE, sigpipe_handler);

	parse_global_config(confdb_handle);
	mainconf = parse_nodes_config(confdb_handle);

	if (statistics)
		logt_print(LOG_DEBUG, "statistics collector enabled\n");
	if (rerouting)
		logt_print(LOG_DEBUG, "rerouting engine enabled\n");

	logt_print(LOG_DEBUG, "Adjust OOM to -16\n");
	set_oom_adj(-16);

	logt_print(LOG_DEBUG, "Set RR scheduler\n");
	set_scheduler();

	/* do stuff here, should we */
	logt_print(LOG_DEBUG, "Starting daemon control thread\n");
	if (start_control_thread() < 0)
		goto out;

	logt_print(LOG_DEBUG, "Initializing local ethernet\n");
	strncpy(localnet, "clusternet", 16);
	eth_fd = cnet_open(localnet, 16);
	if (eth_fd < 0) {
		logt_print(LOG_INFO, "Unable to inizialize local tap device: %s\n",
			   strerror(errno));
		goto out;
	}

	logt_print(LOG_DEBUG, "Initializing local ethernet delivery thread\n");
	rv = pthread_create(&eth_thread, NULL, eth_to_cnet_thread, NULL);
	if (rv < 0) {
		eth_thread_started = 0;
		logt_print(LOG_INFO, "Unable to inizialize local RX thread. error: %s\n",
			   strerror(errno));
		goto out;
	}

	logt_print(LOG_DEBUG, "Starting network socket listener\n");
	net_sock = setup_net_listener();
	if (net_sock < 0)
		goto out;

	logt_print(LOG_DEBUG, "Entering main loop\n");
	loop();

out:
	disconnect_from_nodes(mainconf);

	if (eth_thread_started > 0)
		pthread_cancel(eth_thread);

	if (eth_fd >= 0)
		close(eth_fd);

	if (net_sock >= 0)
		close(net_sock);

	stop_control_thread();

	free_nodes_config(mainconf);

	free(conffile);

	freeconf(confdb_handle);

	close_logging();

	return 0;
}
