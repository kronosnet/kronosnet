#ifndef __NODES_H__
#define __NODES_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "conf.h"
#include "netsocket.h"

#define CBUFFER_SIZE	4096

#define NODE_STATUS_OFFLINE 0
#define NODE_STATUS_ONLINE 1

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
	char *netdevname;
	char *net_ips;
	int mtu;
	int af_family;
/* size of nodeid _MUST_ match the ones in netsocket.h */
	uint32_t nodeid;
	seq_num_t seq_num;
	char circular_buffer[CBUFFER_SIZE];
	int start;
	int end;
	int status;
};

struct node *parse_nodes_config(confdb_handle_t handle);
void free_nodes_config(struct node *head);
void connect_to_nodes(struct node *head);
void disconnect_from_nodes(struct node *head);
int should_deliver(struct node *node, seq_num_t seq_num);
void has_been_delivered(struct node *node, seq_num_t seq_num);
extern int process_local_node_config_preup(struct node *mainconf, char *netdevname);
extern int process_local_node_config_postup(struct node *mainconf, const char *netdevname);

#endif
