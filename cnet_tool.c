#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "controlt.h"

#define OPTION_STRING "hdVc:"

int debug = 0;
char *command = NULL;

static void print_usage(void)
{
	printf("Usage:\n\n");
	printf("cnet_tool [options]\n\n");
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

int main(int argc, char **argv)
{
	read_arguments(argc, argv);

	if (!command)
		command = strdup("status");

	return 0;
}
