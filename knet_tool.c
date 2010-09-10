#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/un.h>
#include <limits.h>

#include "utils.h"
#include "controlt.h"
#include "controlt_comm.h"

#define OPTION_STRING "hdVc:"

int debug = 0;
char *command = NULL;

static void print_usage(void)
{
	printf("Usage:\n\n");
	printf("knet_tool [options]\n\n");
	printf("Options:\n\n");
	printf("  -c <command> Execute command\n");
	printf("  -d           Enable debugging output\n");
	printf("  -h           This help\n");
	printf("  -V           Print program version information\n");
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
			command = strdup(optarg);
			break;

		case 'd':
			debug = 1;
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

static int do_connect(void)
{
	struct sockaddr_un addr;
	int s, rv, value;

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		fprintf(stderr, "Unable to open socket %s error: %s\n",
				KRONOSNETD_SOCKNAME, strerror(errno));
		return s;
	}

	value = fcntl(s, F_GETFD, 0);
	if (value < 0) {
		fprintf(stderr, "Unable to  get close-on-exec flag from socket %s error: %s\n",
				KRONOSNETD_SOCKNAME, strerror(errno));
		close(s);
		return value;
	}
	value |= FD_CLOEXEC;
	rv = fcntl(s, F_SETFD, value);
	if (rv < 0) {
		fprintf(stderr, "Unable to set close-on-exec flag from socket %s error: %s\n",
				KRONOSNETD_SOCKNAME, strerror(errno));
		close(s);
		return rv;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, KRONOSNETD_SOCKNAME, strlen(KRONOSNETD_SOCKNAME));

	rv = connect(s, (struct sockaddr *) &addr, sizeof(addr));
	if (rv < 0) {
		fprintf(stderr, "Unable to connect to socket %s error: %s\n",
				KRONOSNETD_SOCKNAME, strerror(errno));
		close(s);
		s = rv;
	}

	return s;
}

static int send_quit(int fd)
{
	struct ctrl_header h;
	int rv;

	init_header(&h, KNETD_CMD_QUIT, 0);

	rv = do_write(fd, &h, sizeof(h));
	close(fd);

	return rv;
}

static int get_status(int fd)
{
	struct ctrl_header h, *hs;
	int rv;
	char status[PATH_MAX];

	init_header(&h, KNETD_CMD_STATUS, 0);

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out;

	memset(status, 0, PATH_MAX);

	do_read(fd, status, PATH_MAX);

	hs = (struct ctrl_header *)status;
	rv = hs->data;
	if (rv < 0)
		goto out;

	printf("%s\n", (char *)status + sizeof(struct ctrl_header));
out:
	close(fd); 

	return rv;
}

int main(int argc, char **argv)
{
	int out = 0,fd;

	read_arguments(argc, argv);

	if (!command)
		command = strdup("status");

	fd = do_connect();
	if (fd < 0)
		return -1;

	if (!strncmp(command, "quit", strlen("quit")))
		out = send_quit(fd);

	if (!strncmp(command, "status", strlen("status")))
		out = get_status(fd);

	if (command)
		free(command);

	return out;
}
