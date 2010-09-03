#ifndef __NODES_H__
#define __NODES_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "conf.h"

struct conn {
	struct conn *next;
	struct conn *tail;
	struct addrinfo *ainfo;
	int serial_num;
	int fd;
	int status;
	int local;
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
	int af_family;
/* size of nodeid and seq_num _MUST_ match the ones in netsocket.h */
	uint32_t nodeid;
	uint32_t seq_num;
};

struct node *parse_nodes_config(confdb_handle_t handle);
void free_nodes_config(struct node *head);
void connect_to_nodes(struct node *head);
void disconnect_from_nodes(struct node *head);

#endif
