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
#include <pthread.h>

#include "conf.h"
#include "logging.h"

#define LOCKFILE_NAME RUNDIR PACKAGE ".pid"

#define OPTION_STRING "hdfVc:"

int daemonize = 1;
int debug = 0;
int daemon_quit = 0;
char *conffile = NULL;
int statistics = 0;
int rerouting = 0;

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

int main(int argc, char **argv)
{
	confdb_handle_t confdb_handle = 0;

	if (create_lockfile(LOCKFILE_NAME) < 0)
		exit(EXIT_FAILURE);

	atexit(remove_lockfile);

	read_arguments(argc, argv);

	if (!conffile)
		conffile = strdup(CONFFILE);

	confdb_handle = readconf(conffile);
	if (confdb_handle == 0)
		exit(EXIT_FAILURE);

	parse_global_config(confdb_handle);

	if (daemonize) {
		if (daemon(0, 0) < 0) {
			perror("Unable to daemonize");
			exit(EXIT_FAILURE);
		}
	}

	if (configure_logging(confdb_handle, 0) < 0) {
		fprintf(stderr, "Unable to initialize logging subsystem\n");
		return -1;
	}

	signal(SIGTERM, sigterm_handler);

	logt_print(LOG_INFO, PACKAGE " version " VERSION "\n");
	if (statistics)
		logt_print(LOG_INFO, "statistics collector enabled\n");
	if (rerouting)
		logt_print(LOG_INFO, "rerouting engine enabled\n");

	logt_print(LOG_DEBUG, "Adjust OOM to -16\n");
	set_oom_adj(-16);

	logt_print(LOG_DEBUG, "Set RR scheduler\n");
	set_scheduler();

	free(conffile);

	freeconf(confdb_handle);

	close_logging();

	return 0;
}
