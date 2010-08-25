#ifndef __NODES_H__
#define __NODES_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "conf.h"


struct conn_info {
	int fd;
	// latency;
	int status;
};

struct conn {
	struct conn *next;
	struct conn *tail;
	struct conn_info *in;
	struct conn_info *out;
	struct sockaddr_storage *ip_addr;
};

struct node {
	struct node *next;
	struct node *tail;
	struct conn *conn;
	char *nodename;
	char *preup;
	char *up;
	char *down;
	char *postdown;
	int nodeid;
};

struct node *parse_nodes_config(confdb_handle_t handle);
void free_nodes_config(struct node *head);

#endif
