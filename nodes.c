#include "config.h"

#include <stdio.h>
#include <limits.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"

/*
static void print_conn_ainfo(struct addrinfo *ainfo)
{
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_storage *ss = (struct sockaddr_storage *)ainfo->ai_addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)ainfo->ai_addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ainfo->ai_addr;
	void *saddr;

	if (ss->ss_family == AF_INET6)
		saddr = &sin6->sin6_addr;
	else
		saddr = &sin->sin_addr;

	inet_ntop(ainfo->ai_family, (void *)saddr, buf, sizeof(buf));

	logt_print(LOG_DEBUG, "print_conn_ainfo: %s\n", buf);
}
*/

/*
 * this is delicate
 * return -1 if getaddrinfo fails as it might not be completely fatal
 * -2 for other fatal errors.
 */

static int add_ip(struct node *node, const char* curip, int seq_num)
{
	struct addrinfo *ainfo;
	struct addrinfo ahints;
	struct conn *conn;
	int ret;

	memset(&ahints, 0, sizeof(ahints));
	ahints.ai_socktype = 0;
	ahints.ai_protocol = 0;
	ahints.ai_family = AF_UNSPEC;

	ret = getaddrinfo(curip, NULL, &ahints, &ainfo);
	if (ret < 0) {
		logt_print(LOG_INFO, "Unable to get addrinfo for [%s]: %s\n", curip, gai_strerror(ret));
		return -1;
	}

	while (ainfo) {
		conn = malloc(sizeof(struct conn));
		if (!conn) {
			logt_print(LOG_INFO, "Unable to allocate memory for connection data\n");
			return -2;
		}

		memset(conn, 0, sizeof(struct conn));
		conn->ainfo=ainfo;
		conn->seq_num=seq_num;

		if (!node->conn)
			node->conn = conn;
		else
			node->conn->tail->next = conn;

		node->conn->tail = conn;

		ainfo = ainfo->ai_next;
	}

	return 0;
}

static int convert_ip(struct node *node, char* iptemp)
{
	char *tmp1 = iptemp, *tmp2 = iptemp;
	char curip[256];
	int i, seq_num;

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

	seq_num = 0;
	while (tmp1) {
		memset(curip, 0, sizeof(curip));

		tmp2 = strchr(tmp1, ' ');
		if (tmp2) {
			strncpy(curip, tmp1, tmp2 - tmp1);
			tmp1 = tmp2 + 1;
			if (!strlen(curip))
				continue;
		} else {
			if (tmp1) {
				strcpy(curip, tmp1);
				tmp1 = tmp2;
			} else {
				break;
			}
		}

		if (add_ip(node, curip, seq_num) < -1) 
			return -1;

		seq_num++;
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
	struct conn *next;
	int seq_num = 0, next_seq = -1;

	while(conn) {
		next = conn->next;

		if ((seq_num != next_seq) && (conn->ainfo))
			freeaddrinfo(conn->ainfo);

		seq_num = conn->seq_num;
		if (next) 
			next_seq = next->seq_num;

		free(conn);
		conn = next;
	}
	return;
}

void free_nodes_config(struct node *head)
{
	struct node *next;

	while (head) {
		next = head->next;
		if (head->conn)
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
