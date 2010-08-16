#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "conf.h"

static confdb_callbacks_t callbacks = {};

extern int statistics;
extern int rerouting;

int parse_global_config(confdb_handle_t handle)
{
	int res;
	hdb_handle_t global_handle;
	char key_name[PATH_MAX];
	size_t key_name_len;
	char key_value[PATH_MAX];
	size_t key_value_len;

	res = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK)
		return -1;

	res = confdb_object_find(handle, OBJECT_PARENT_HANDLE, "global", strlen("global"), &global_handle);
	if (res != CS_OK)
		return 0;

	confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);

	res = confdb_key_iter_start(handle, global_handle);
	if (res != CS_OK)
		return -1;

	while ( (res = confdb_key_iter(handle, global_handle, key_name, &key_name_len,
					key_value, &key_value_len)) == CS_OK) {
		key_name[key_name_len] = '\0';
		key_value[key_value_len] = '\0';

		if (!strncmp(key_name, "statistics",  strlen("statistics"))) {
			statistics = 1;
		} else if (!strncmp(key_name, "rerouting",  strlen("rerouting"))) {
			rerouting = 1;
		}
	}

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
