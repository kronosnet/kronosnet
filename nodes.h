#ifndef __NODES_H__
#define __NODES_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "conf.h"

struct conn {
	struct conn *next;
	struct conn *tail;
	struct addrinfo *ainfo;
	int seq_num;
	int fd;
	int status;
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
