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
#include <linux/if.h>

#include "conf.h"
#include "knet.h"
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

	log_printf(LOGSYS_LEVEL_DEBUG, "print_conn_ainfo: %s\n", buf);
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
		log_printf(LOGSYS_LEVEL_INFO, "Unable to get list of interfaces! Error: %s:\n", strerror(errno));
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
		log_printf(LOGSYS_LEVEL_INFO, "Unable to get addrinfo for [%s]: %s\n", curip, gai_strerror(ret));
		return -1;
	}

	while (ainfo) {
		//print_conn_ainfo(ainfo->ai_addr);
		conn = malloc(sizeof(struct conn));
		if (!conn) {
			log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for connection data\n");
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
	char *curip;
	int i;
	int res;
	int serial_num;

	serial_num = 0;
	curip = NULL;
	i = 0;

	while ((res = str_explode(iptemp, &curip, &i)) == 0) {
		if (add_ip(node, curip, serial_num) < -1) 
			return -1;

		serial_num++;
	}

	if (res == -2) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
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
		log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
		goto out;
	}
	memset(new, 0, sizeof(struct node));
	new->nodeid = -1;
	new->seq_num = 0;

	res = confdb_key_iter_start(handle, node_handle);
	if (res != CS_OK) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to iterate through node config keys?\n");
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
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
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
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "up", strlen("up"))) {
			if (strlen(key_value)) { 
				new->up = strdup(key_value);
				if (!new->up) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "down", strlen("down"))) {
			if (strlen(key_value)) {
				new->down = strdup(key_value);
				if (!new->down) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "postdown", strlen("postdown"))) {
			if (strlen(key_value)) {
				new->postdown = strdup(key_value);
				if (!new->postdown) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "nodeips", strlen("nodeips"))) {
			if (strlen(key_value)) {
				iptemp = strdup(key_value);
				if (!iptemp) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "nodeid", strlen("nodeid"))) {
			if (strlen(key_value)) {
				new->nodeid = atoi(key_value);
			}
		} else if (!strncmp(key_name, "netdevname", strlen("netdevname"))) {
			if (strlen(key_value)) {
				if (strlen(key_value) > IFNAMSIZ) {
					log_printf(LOGSYS_LEVEL_INFO, "Network device name (netdevname) option too long\n");
					goto out;
				}

				new->netdevname = strdup(key_value);
				if (!new->netdevname) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "knet_ips", strlen("knet_ips"))) {
			if (strlen(key_value)) {
				new->net_ips = strdup(key_value);
				if (!new->net_ips) {
					log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
					goto out;
				}
			}
		} else if (!strncmp(key_name, "knet_mtu", strlen("knet_mtu"))) {
			if (strlen(key_value)) {
				new->mtu = atoi(key_value);
			}
		}

	}

	/* add sanity checks here */
	if (new->nodename == NULL) {
		log_printf(LOGSYS_LEVEL_INFO, "No nodename specified\n");
		goto out;
	}
	if (new->nodeid < 0) {
		log_printf(LOGSYS_LEVEL_INFO, "No nodeid or invalid nodeid specified\n");
		goto out;
	}

	if (!iptemp) {
		iptemp = strdup(new->nodename);
		if (!iptemp) {
			log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for node structures\n");
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
		log_printf(LOGSYS_LEVEL_INFO, "Unable to access objdb parent\n");
		return NULL;
	}

	res = confdb_object_iter_start(handle, OBJECT_PARENT_HANDLE);
	if (res != CS_OK) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to iterate through nodes config objects?\n");
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

static struct node *find_local_node(struct node *mainconf)
{
	struct node *local_node;

	for (local_node = mainconf; local_node != NULL && !local_node->conn->local; local_node = local_node->next) ;

	if (local_node == NULL) {
		log_printf(LOGSYS_LEVEL_INFO, "Unable to find local node\n");
		return NULL;
	}

	return local_node;
}

int process_local_node_config_preup(struct node *mainconf, char *netdevname)
{
	struct node *local_node;

	if ((local_node = find_local_node(mainconf)) == NULL) {
		return -1;
	}

	if (local_node->netdevname != NULL)
		strcpy(netdevname, local_node->netdevname);

	return 0;
}

int process_local_node_config_postup(struct node *mainconf, const char *netdevname)
{
	struct node *local_node;
	char *net_ip;
	int pos;
	int res;

	if ((local_node = find_local_node(mainconf)) == NULL) {
		return -1;
	}

	if (local_node->net_ips != NULL) {
		net_ip = NULL;
		pos = 0;

		if (knet_up(netdevname, local_node->mtu) != 0) {
			return -1;
		}

		while ((res = str_explode(local_node->net_ips, &net_ip, &pos)) == 0) {
			if (knet_add_ip(netdevname, net_ip) != 0)
				return -1;
		}

		if (res == -2) {
			log_printf(LOGSYS_LEVEL_INFO, "Unable to allocate memory for ips\n");
			return -1;
		}
	}

	return 0;
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
		if (head->netdevname)
			free(head->netdevname);
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
					log_printf(LOGSYS_LEVEL_DEBUG, "Unable to open socket for. Error: %s\n", strerror(errno));
					print_conn_ainfo(conn->ainfo->ai_addr);
					conn->fd = 0;
					goto next_conn;
				}

				if (connect(conn->fd, conn->ainfo->ai_addr, conn->ainfo->ai_addrlen) < 0) {
					log_printf(LOGSYS_LEVEL_DEBUG, "Unable to connect! Error: %s\n", strerror(errno));
					close(conn->fd);
					conn->fd = 0;
				}
				log_printf(LOGSYS_LEVEL_DEBUG, "node: %s fd: %d\n", next->nodename, conn->fd);

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
if (knet_h->seq_num != peer->seq_num + 1)
	log_printf(LOGSYS_LEVEL_INFO, "Got %u, expected %u from node %s\n", knet_h->seq_num, peer->seq_num + 1, peer->nodename);

if ((knet_h->seq_num == 0) && (peer->seq_num == SEQ_MAX)) {
	log_printf(LOGSYS_LEVEL_DEBUG, "Rolling over node: %s[%u]\n", peer->nodename, peer->nodeid);
	rollover = 1;
}

if (knet_h->seq_num > peer->seq_num + (SEQ_MAX / 2)) {
	log_printf(LOGSYS_LEVEL_DEBUG, "This doesn't look right\n");
	break;
}

if (knet_h->seq_num == 1) {
	log_printf(LOGSYS_LEVEL_DEBUG, "Restarting sequence\n");
	peer->seq_num = 0;
}

if ((knet_h->seq_num > peer->seq_num) || (rollover > 0)) {
	log_printf(LOGSYS_LEVEL_DEBUG, "Act pkct from node %s[%u]: %u\n", peer->nodename, peer->nodeid, knet_h->seq_num);
...
} else
	log_printf(LOGSYS_LEVEL_DEBUG, "Discarding duplicated package from node %s[%u]: %u\n", peer->nodename, peer->nodeid, knet_h->seq_num);

improved rollover check? :
	if ((node->seq_num > (SEQ_MAX / 2)) && (seq_num < node->seq_num - (SEQ_MAX / 2)))

*/

static void clear_ring_buffer(struct node *node, seq_num_t seq_num)
{
	seq_num_t seq_count;
	size_t clr_bgn, clr_end;

	if (seq_num < node->seq_num) 
		seq_count = (SEQ_MAX - node->seq_num) + seq_num;
	else
		seq_count = seq_num - node->seq_num;

	/* let's keep 4 bytes unused to avoid overwrites in one shot
 	 * 1 bytes should be enough
 	 */
	if (seq_count > (CBUFFER_SIZE - 4)) {
		/* better options for this case would be dropping the connection
		 * or to increase the buffer size
		 * FIXME: we also hit this part when a node is restarted
		 */
		log_printf(LOGSYS_LEVEL_INFO, "WARNING: circular buffer not big enough!\n");
		memset(node->circular_buffer, 0, CBUFFER_SIZE);
		goto exit_clean;
	}

	if (seq_count > 1) {
		log_printf(LOGSYS_LEVEL_INFO, "clearing offset for %s: %u -> %u = %u\n",
			node->nodename, node->seq_num, seq_num, seq_count);
	}

	clr_bgn = (node->seq_num + 1) % CBUFFER_SIZE;
	clr_end = (seq_num + 1) % CBUFFER_SIZE;

	if (clr_bgn > clr_end) {
		memset(node->circular_buffer + clr_bgn, 0, CBUFFER_SIZE - clr_bgn);
		memset(node->circular_buffer, 0, clr_end);
	}
	else {
		memset(node->circular_buffer + clr_bgn, 0, clr_end - clr_bgn);
	}

exit_clean:

	node->seq_num = seq_num;

	return;
}

/* checks if a seq num is newer than the last seen */
static int is_seq_new(struct node *node, seq_num_t seq_num)
{
	seq_num_t seq_lim;

	seq_lim = (node->seq_num + (SEQ_MAX / 2)) % SEQ_MAX;

	if (seq_lim < node->seq_num) {
		if (seq_num > node->seq_num || seq_num < seq_lim)
			return 1;
	}
	else {
		if (seq_num > node->seq_num && seq_num < seq_lim)
			return 1;
	}

	return 0;
}

/*
 * check if a packet has been seen before
 * if not, return 1 and deliver
 * if yes, then return 0 and drop
 */
int should_deliver(struct node *node, seq_num_t seq_num)
{
	if (is_seq_new(node, seq_num))
		clear_ring_buffer(node, seq_num);
	
	/* we should check if the distance between seq_num and
	 * node->seq_num is higher than CBUFFER_SIZE
	 * if the packet is too old we can't continue
	 */

	if (node->circular_buffer[seq_num % CBUFFER_SIZE] != 0)
		return 0;

	return 1;
}

/*
 * update ring buffer _after_ a packet has been written
 * to make sure it's been delivered
 */
void has_been_delivered(struct node *node, seq_num_t seq_num)
{
	node->circular_buffer[seq_num % CBUFFER_SIZE] = 1;
	return;
}
