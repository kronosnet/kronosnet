#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "conf.h"

static confdb_callbacks_t callbacks = {};

int parse_global_config(confdb_handle_t handle)
{
	return 0;
}

confdb_handle_t readconf(const char *conffile)
{
	confdb_handle_t handle = 0;

	if (setenv("COROSYNC_DEFAULT_CONFIG_IFACE", "corosync_parser", 1)) {
		fprintf(stderr, "Unable to set COROSYNC_DEFAULT_CONFIG_IFACE reason [%s]\n", strerror(errno));
		return 0;
	}
	if (setenv("COROSYNC_MAIN_CONFIG_FILE", conffile, 1)) {
		fprintf(stderr, "Unable to set COROSYNC_MAIN_CONFIG_FILE reason [%s]\n", strerror(errno));
		return 0;
	}

	if (confdb_initialize(&handle, &callbacks) != CS_OK) {
		fprintf(stderr, "Error reading config file\n");
		return 0;
	}

	return handle;
}

void freeconf(confdb_handle_t handle)
{
	confdb_finalize(handle);
	return;
}
