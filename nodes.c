#include "config.h"

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "conf.h"
#include "logging.h"
#include "nodes.h"
#include "utils.h"
#include "netsocket.h"

extern int our_nodeid;

static void print_conn_ainfo(struct sockaddr *in)
{
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_storage *ss = (struct sockaddr_storage *)in;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	void *saddr;

	if (ss->ss_family == AF_INET6)
		saddr = &sin6->sin6_addr;
	else
		saddr = &sin->sin_addr;

	inet_ntop(ss->ss_family, (void *)saddr, buf, sizeof(buf));

	logt_print(LOG_DEBUG, "print_conn_ainfo: %s\n", buf);
}

static int ipaddr_equal(struct sockaddr *addr1, struct sockaddr *addr2)
{
	int addrlen = 0;

	if (addr1->sa_family != addr2->sa_family)
		return 0;

	if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *addr_in1 = (struct sockaddr_in *)addr1;
		struct sockaddr_in *addr_in2 = (struct sockaddr_in *)addr2;

		addrlen = sizeof(struct in_addr);
		if (memcmp((const void *)&addr_in1->sin_addr, (const void *)&addr_in2->sin_addr, addrlen) == 0)
			return 1;
	}

	if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in61 = (struct sockaddr_in6 *)addr1;
		struct sockaddr_in6 *addr_in62 = (struct sockaddr_in6 *)addr2;

		addrlen = sizeof(struct in6_addr);
		if (memcmp((const void *)&addr_in61->sin6_addr, (const void *)&addr_in62->sin6_addr, addrlen) == 0)
			return 1;

	}

	return 0;
}

/*
 * return 1 if the ip is local to the node
 * XXX: optimize to avoid N calls to getifaddrs
 */
static int is_local_ip(struct sockaddr *addr)
{
	struct ifaddrs *ifap = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if (getifaddrs(&ifap) < 0) {
		logt_print(LOG_INFO, "Unable to get list of interfaces! Error: %s:\n", strerror(errno));
		return 1;
	}

	ifa = ifap;

	while (ifa) {
		if (ipaddr_equal(ifa->ifa_addr, addr) > 0) {
			found = 1;
			break;
		}

		ifa = ifa->ifa_next;
	}

	freeifaddrs(ifap);

	return found;
}

/*
 * this is delicate
 * return -1 if getaddrinfo fails as it might not be completely fatal
 * -2 for other fatal errors.
 */

static int add_ip(struct node *node, const char* curip, int serial_num)
{
	struct addrinfo *ainfo;
	struct addrinfo ahints;
	struct conn *conn;
	int ret;

	memset(&ahints, 0, sizeof(ahints));
	ahints.ai_socktype = SOCK_DGRAM;
	ahints.ai_protocol = IPPROTO_UDP;
	ahints.ai_family = node->af_family;

	ret = getaddrinfo(curip, NULL, &ahints, &ainfo);
	if (ret < 0) {
		logt_print(LOG_INFO, "Unable to get addrinfo for [%s]: %s\n", curip, gai_strerror(ret));
		return -1;
	}

	while (ainfo) {
		//print_conn_ainfo(ainfo->ai_addr);
		conn = malloc(sizeof(struct conn));
		if (!conn) {
			logt_print(LOG_INFO, "Unable to allocate memory for connection data\n");
			return -2;
		}

		memset(conn, 0, sizeof(struct conn));
		conn->ainfo=ainfo;
		conn->serial_num=serial_num;
		conn->local = is_local_ip(ainfo->ai_addr);

		if (conn->local)
			our_nodeid = node->nodeid;

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
	int i, serial_num;

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

	serial_num = 0;
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

		if (add_ip(node, curip, serial_num) < -1) 
			return -1;

		serial_num++;
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
	new->seq_num = 0;

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
		} else if (!strncmp(key_name, "inet", strlen("inet"))) {
			if (strlen(key_value)) {
				new->af_family = AF_INET;
				if (!strncmp(key_value, "ipv4", strlen("ipv4")))
					new->af_family = AF_INET;
				if (!strncmp(key_value, "ipv6", strlen("ipv6"))) 
					new->af_family = AF_INET6;
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
		} else if (!strncmp(key_name, "nodeips", strlen("nodeips"))) {
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
	int serial_num = 0, next_seq = -1;

	while(conn) {
		next = conn->next;

		if ((serial_num != next_seq) && (conn->ainfo))
			freeaddrinfo(conn->ainfo);

		serial_num = conn->serial_num;
		if (next) 
			next_seq = next->serial_num;

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

void connect_to_nodes(struct node *next)
{
	while (next) {
		struct conn *conn;

		conn = next->conn;
		while (conn) {
			if ((!conn->fd) && (!conn->local)) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)conn->ainfo->ai_addr;
				struct sockaddr_in *sin = (struct sockaddr_in *)conn->ainfo->ai_addr;

				if (conn->ainfo->ai_family == AF_INET6)
					sin6->sin6_port = ntohs(DEFAULT_PORT);
				else
					sin->sin_port = ntohs(DEFAULT_PORT);

				conn->fd = socket(conn->ainfo->ai_family, conn->ainfo->ai_socktype, conn->ainfo->ai_protocol);

				if (conn->fd < 0) {
					logt_print(LOG_DEBUG, "Unable to open socket for. Error: %s\n", strerror(errno));
					print_conn_ainfo(conn->ainfo->ai_addr);
					conn->fd = 0;
					goto next_conn;
				}

				if (connect(conn->fd, conn->ainfo->ai_addr, conn->ainfo->ai_addrlen) < 0) {
					logt_print(LOG_DEBUG, "Unable to connect! Error: %s\n", strerror(errno));
					close(conn->fd);
					conn->fd = 0;
				}
				logt_print(LOG_DEBUG, "node: %s fd: %d\n", next->nodename, conn->fd);

			}
next_conn:
			conn = conn->next;
		}
		next = next->next;
	}

	return;
}

void disconnect_from_nodes(struct node *next)
{
	while (next) {
		struct conn *conn;
		conn = next->conn;
		while (conn) {
			if (conn->fd) {
				close(conn->fd);
				conn->fd = 0;
			}
			conn = conn->next;
		}
		next = next->next;
	}
	return;
}

/*** CHUNK OF CRAP ***/
/*
if (cnet_h->seq_num != peer->seq_num + 1)
	logt_print(LOG_INFO, "Got %u, expected %u from node %s\n", cnet_h->seq_num, peer->seq_num + 1, peer->nodename);

if ((cnet_h->seq_num == 0) && (peer->seq_num == SEQ_MAX)) {
	logt_print(LOG_DEBUG, "Rolling over node: %s[%u]\n", peer->nodename, peer->nodeid);
	rollover = 1;
}

if (cnet_h->seq_num > peer->seq_num + (SEQ_MAX / 2)) {
	logt_print(LOG_DEBUG, "This doesn't look right\n");
	break;
}

if (cnet_h->seq_num == 1) {
	logt_print(LOG_DEBUG, "Restarting sequence\n");
	peer->seq_num = 0;
}

if ((cnet_h->seq_num > peer->seq_num) || (rollover > 0)) {
	logt_print(LOG_DEBUG, "Act pkct from node %s[%u]: %u\n", peer->nodename, peer->nodeid, cnet_h->seq_num);
...
} else
	logt_print(LOG_DEBUG, "Discarding duplicated package from node %s[%u]: %u\n", peer->nodename, peer->nodeid, cnet_h->seq_num);
*/

static void clear_ring_buffer(struct node *node, seq_num_t seq_num)
{
	uint32_t new_offset = (seq_num + 1) % CBUFFER_SIZE;
	uint32_t idx_offset = (node->seq_num + 1) % CBUFFER_SIZE;

	if (idx_offset == new_offset)
		return;

	logt_print(LOG_DEBUG, "clearing from %u to %u\n", idx_offset, new_offset);

	while (idx_offset != new_offset) {
		node->circular_buffer[idx_offset] = 0;
		idx_offset = (idx_offset + 1) % CBUFFER_SIZE;
	}

	return;
}

/*
 * check if a packet has been seen before
 * if not, return 1 and deliver
 * if yes, then return 0 and drop
 */
int should_deliver(struct node *node, seq_num_t seq_num)
{
	int rollover = 0;

	logt_print(LOG_DEBUG, "should_deliver for: %s[%u]: %u\n", node->nodename, node->seq_num, seq_num);
	logt_print(LOG_DEBUG, "modulo: %u %u\n", seq_num % CBUFFER_SIZE, node->seq_num % CBUFFER_SIZE);

	/*
	 * rollover definition:
	 * new_seq < old_seq - SEQ_MAX ?
	 */

	if (seq_num < (node->seq_num - (SEQ_MAX / 2))) {
		logt_print(LOG_INFO, "Doing a rollover?\n");
		rollover = 1;
	}

	if ((seq_num > node->seq_num) || (rollover > 0))
		clear_ring_buffer(node, seq_num);

	if (node->circular_buffer[seq_num % CBUFFER_SIZE] == 1) {
		logt_print(LOG_DEBUG, "Packet has been seen before\n");
		return 0;
	}

	return 1;
}

/*
 * update ring buffer _after_ a packet has been written
 * to make sure it's been delivered
 */
void has_been_delivered(struct node *node, seq_num_t seq_num)
{
	node->circular_buffer[seq_num % CBUFFER_SIZE] = 1;
	node->seq_num = seq_num;
	return;
}
