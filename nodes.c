#include "config.h"

#include <stdio.h>
#include <limits.h>
#include <string.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"

static int convert_ip(struct node *new, char* iptemp)
{
	char *tmp1 = iptemp, *tmp2 = iptemp;
	char tempip[256];
	int i;

	/* Clear out white space and tabs */
	for (i = strlen (iptemp) - 1; i > -1; i--) {
		if (iptemp[i] == '\t' || iptemp[i] == ' ') {
			iptemp[i] = '\0';
		} else {
			break;
		}
	}

	/* convert tabs in spaces */
	for (i = 0; i <= strlen (iptemp); i++) {
		if (iptemp[i] == '\t') {
			iptemp[i] = ' ';
		}
	}

	while (tmp1) {
		memset(tempip, 0, sizeof(tempip));

		tmp2 = strchr(tmp1, ' ');
		if (tmp2) {
			strncpy(tempip, tmp1, tmp2 - tmp1);
			tmp1 = tmp2 + 1;
			if (!strlen(tempip))
				continue;
		} else {
			if (tmp1) {
				strcpy(tempip, tmp1);
				tmp1 = tmp2;
			} else {
				break;
			}
		}

		logt_print(LOG_DEBUG, "tempip: %s\n", tempip);
	}

	return 0;
}

static struct node *parse_node(confdb_handle_t handle, hdb_handle_t node_handle)
{
	int res;
	char key_name[PATH_MAX];
	size_t key_name_len;
	char key_value[PATH_MAX];
	size_t key_value_len;
	char *iptemp = NULL;
	struct node *new;

	new = malloc(sizeof(struct node));
	if (!new) {
		logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
		goto out;
	}
	memset(new, 0, sizeof(struct node));
	new->nodeid = -1;

	res = confdb_key_iter_start(handle, node_handle);
	if (res != CS_OK) {
		logt_print(LOG_INFO, "Unable to iterate through node config keys?\n");
		goto out;
	}

	while ( (res = confdb_key_iter(handle, node_handle, key_name, &key_name_len,
					key_value, &key_value_len)) == CS_OK) {
		key_name[key_name_len] = '\0';
		key_value[key_value_len] = '\0';

		if (!strncmp(key_name, "nodename", strlen("nodename"))) {
			if (strlen(key_value)) {
				new->nodename = strdup(key_value);
				if (!new->nodename) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "preup", strlen("preup"))) {
			if (strlen(key_value)) {
				new->preup = strdup(key_value);
				if (!new->preup) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "up", strlen("up"))) {
			if (strlen(key_value)) { 
				new->up = strdup(key_value);
				if (!new->up) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "down", strlen("down"))) {
			if (strlen(key_value)) {
				new->down = strdup(key_value);
				if (!new->down) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "postdown", strlen("postdown"))) {
			if (strlen(key_value)) {
				new->postdown = strdup(key_value);
				if (!new->postdown) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "ip", strlen("ip"))) {
			if (strlen(key_value)) {
				iptemp = strdup(key_value);
				if (!iptemp) {
					logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "nodeid", strlen("nodeid"))) {
			if (strlen(key_value)) {
				new->nodeid = atoi(key_value);
			}
		}

	}

	/* add sanity checks here */
	if (new->nodename == NULL) {
		logt_print(LOG_INFO, "No nodename specified\n");
		goto out;
	}
	if (new->nodeid < 0) {
		logt_print(LOG_INFO, "No nodeid or invalid nodeid specified\n");
		goto out;
	}

	if (!iptemp) {
		iptemp = strdup(new->nodename);
		if (!iptemp) {
			logt_print(LOG_INFO, "Unable to allocate memory for node structures\n");
			goto out;
		}
	}

	/* go to string2ip converter */
	if (convert_ip(new, iptemp) < 0)
		goto out;

	if (iptemp)
		free(iptemp);

	return new;

out:
	if (iptemp)
		free(iptemp);

	if (new)
		free(new);
	return NULL;
}

struct node *parse_nodes_config(confdb_handle_t handle)
{
	int res;
	hdb_handle_t nodes_handle;
	char obj_name[PATH_MAX];
	size_t obj_name_len;
	struct node *head = NULL;
	struct node *new = NULL;

	res = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK) {
		logt_print(LOG_INFO, "Unable to access objdb parent\n");
		return NULL;
	}

	res = confdb_object_iter_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK) {
		logt_print(LOG_INFO, "Unable to iterate through nodes config objects?\n");
		confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);
		return NULL;
	}

	while ( (res = confdb_object_iter(handle, OBJECT_PARENT_HANDLE, &nodes_handle, obj_name, &obj_name_len) == CS_OK) ) {
		obj_name[obj_name_len] = '\0';

		if (!strncmp(obj_name, "node", strlen("node"))) {
			new = parse_node(handle, nodes_handle);
			if (!new) {
				if (head)
					free_nodes_config(head);
				goto out;
			}

			if (!head)
				head = new;
			else
				head->tail->next = new;

			head->tail = new;
		}
	}

out:
	confdb_object_iter_destroy(handle, OBJECT_PARENT_HANDLE);
	confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);

	return head;
}

static void free_nodes_conn(struct conn *conn)
{
	if (!conn)
		return;

	free(conn);
	return;
}

void free_nodes_config(struct node *head)
{
	struct node *next;

	while (head) {
		next = head->next;
		free_nodes_conn(head->conn);
		if (head->nodename)
			free(head->nodename);
		if (head->preup)
			free(head->preup);
		if (head->up)
			free(head->up);
		if (head->down)
			free(head->down);
		if (head->postdown)
			free(head->postdown);
		free(head);
		head = next;
	}

	return;
}
