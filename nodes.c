#include "config.h"

#include <stdio.h>
#include <limits.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"

static int parse_node(confdb_handle_t handle, hdb_handle_t nodes_handle)
{
	

	return 0;
}

int parse_nodes_config(confdb_handle_t handle)
{
	int res, err = 0;
	hdb_handle_t nodes_handle;
	char obj_name[PATH_MAX];
	size_t obj_name_len;
/*
	char key_name[PATH_MAX];
	size_t key_name_len;
	char key_value[PATH_MAX];
	size_t key_value_len;
*/
	res = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK) {
		logt_print(LOG_INFO, "Unable to access objdb parent\n");
		return -1;
	}

	res = confdb_object_iter_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK) {
		logt_print(LOG_INFO, "Unable to iterate through nodes config objects?\n");
		confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);
		return -1;
	}

	while ( (res = confdb_object_iter(handle, OBJECT_PARENT_HANDLE, &nodes_handle, obj_name, &obj_name_len) == CS_OK) ) {
		obj_name[obj_name_len] = '\0';

		if (!strncmp(obj_name, "node", strlen("node")))
			if (parse_node(handle, nodes_handle)) {
				err = -1;
				goto out;
			}
	}

out:
	confdb_object_iter_destroy(handle, OBJECT_PARENT_HANDLE);
	confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);

	return err;
}
