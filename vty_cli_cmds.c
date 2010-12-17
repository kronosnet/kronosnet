#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "cfg.h"
#include "utils.h"
#include "libtap.h"
#include "netutils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

#define KNET_VTY_MAX_MATCHES	64
#define KNET_VTY_MATCH_HELP	0
#define KNET_VTY_MATCH_EXEC	1
#define KNET_VTY_MATCH_EXPAND	2

#define CMDS_PARAM_NOMORE	0
#define CMDS_PARAM_KNET		1
#define CMDS_PARAM_IP		2
#define CMDS_PARAM_IP_PREFIX	3
#define CMDS_PARAM_IP_PORT	4
#define CMDS_PARAM_BOOL		5
#define CMDS_PARAM_INT		6
#define CMDS_PARAM_NODEID	7
#define CMDS_PARAM_NAME		8
#define CMDS_PARAM_MTU		9

/*
 * CLI helper functions - menu/node stuff starts below
 */


/*
 * return 0 if we find a command in vty->line and cmd/len/no are set
 * return -1 if we cannot find a command. no can be trusted. cmd/len would be empty
 */

static int get_command(struct knet_vty *vty, char **cmd, int *cmdlen, int *cmdoffset, int *no)
{
	int start = 0, idx;

	for (idx = 0; idx < vty->line_idx; idx++) {
		if (vty->line[idx] != ' ')
			break;
	}

	if (!strncmp(&vty->line[idx], "no ", 3)) {
		*no = 1;
		idx = idx + 3;

		for (idx = idx; idx < vty->line_idx; idx++) {
			if (vty->line[idx] != ' ')
				break;
		}
	} else {
		*no = 0;
	}

	start = idx;
	if (start == vty->line_idx)
		return -1;

	*cmd = &vty->line[start];
	*cmdoffset = start;

	for (idx = start; idx < vty->line_idx; idx++) {
		if (vty->line[idx] == ' ')
			break;
	}

	*cmdlen = idx - start;

	return 0;
}

/*
 * still not sure why I need to count backwards...
 */
static void get_n_word_from_end(struct knet_vty *vty, int n,
					char **word, int *wlen, int *woffset)
{
	int widx;
	int idx, end, start;

	start = end = vty->line_idx;

	for (widx = 0; widx < n; widx++) {
		for (idx = start - 1; idx > 0; idx--) {
			if (vty->line[idx] != ' ')
				break;
		}
		end = idx;
		for (idx = end; idx > 0; idx--) {
			if (vty->line[idx-1] == ' ')
				break;
		}
		start = idx;
	}

	*wlen = (end - start) + 1;
	*word = &vty->line[start];
	*woffset = start;
}

static int expected_params(const vty_param_t *params)
{
	int idx = 0;

	while(params[idx].param != CMDS_PARAM_NOMORE)
		idx++;

	return idx;
}

static int count_words(struct knet_vty *vty,
			 int offset)
{
	int idx, widx = 0;
	int status = 0;

	for (idx = offset; idx < vty->line_idx; idx++) {
		if (vty->line[idx] == ' ') {
			status = 0;
			continue;
		}
		if ((vty->line[idx] != ' ') && (!status)) {
			widx++;
			status = 1;
			continue;
		}
	}
	return widx;
}

static int param_to_int(const char *param, int paramlen)
{
	char buf[KNET_VTY_MAX_LINE];

	memset(buf, 0, sizeof(buf));
	memcpy(buf, param, paramlen);
	return atoi(buf);
}

static int param_to_str(char *buf, int bufsize, const char *param, int paramlen)
{
	if (bufsize < paramlen)
		return -1;

	memset(buf, 0, bufsize);
	memcpy(buf, param, paramlen);
	return paramlen;
}

static const vty_node_cmds_t *get_cmds(struct knet_vty *vty, char **cmd, int *cmdlen, int *cmdoffset)
{
	int no;
	const vty_node_cmds_t *cmds =  knet_vty_nodes[vty->node].cmds;

	get_command(vty, cmd, cmdlen, cmdoffset, &no);

	if (no)
		cmds = knet_vty_nodes[vty->node].no_cmds;

	return cmds;
}

static int check_param(struct knet_vty *vty, const int paramtype, char *param, int paramlen)
{
	int err = 0;
	char buf[KNET_VTY_MAX_LINE];
	int tmp;

	memset(buf, 0, sizeof(buf));

	switch(paramtype) {
		case CMDS_PARAM_NOMORE:
			break;
		case CMDS_PARAM_KNET:
			if (paramlen >= IFNAMSIZ) {
				knet_vty_write(vty, "interface name too long%s", telnet_newline);
				err = -1;
			}
			break;
		case CMDS_PARAM_IP:
			break;
		case CMDS_PARAM_IP_PREFIX:
			break;
		case CMDS_PARAM_IP_PORT:
			tmp = param_to_int(param, paramlen);
			if ((tmp < 0) || (tmp > 65279)) {
				knet_vty_write(vty, "port number must be a value between 0 and 65279%s", telnet_newline);
				err = -1;
			}
			break;
		case CMDS_PARAM_BOOL:
			break;
		case CMDS_PARAM_INT:
			break;
		case CMDS_PARAM_NODEID:
			tmp = param_to_int(param, paramlen);
			if ((tmp < 0) || (tmp > 255)) {
				knet_vty_write(vty, "node id must be a value between 0 and 255%s", telnet_newline);
				err = -1;
			}
			break;
		case CMDS_PARAM_NAME:
			if (paramlen >= KNET_MAX_HOST_LEN) {
				knet_vty_write(vty, "name cannot exceed %d char in len%s", KNET_MAX_HOST_LEN - 1, telnet_newline);
			}
			break;
		case CMDS_PARAM_MTU:
			tmp = param_to_int(param, paramlen);
			if ((tmp < 576) || (tmp > 65536)) {
				knet_vty_write(vty, "mtu should be a value between 576 and 65536 (note: max value depends on the media)%s", telnet_newline);
				err = -1;
			}
			break;
		default:
			knet_vty_write(vty, "CLI ERROR: unknown parameter type%s", telnet_newline);
			err = -1;
			break;
	}
	return err;
}

static void describe_param(struct knet_vty *vty, const int paramtype)
{
	switch(paramtype) {
		case CMDS_PARAM_NOMORE:
			knet_vty_write(vty, "no more parameters%s", telnet_newline);
			break;
		case CMDS_PARAM_KNET:
			knet_vty_write(vty, "KNET_IFACE_NAME - interface name (max %d chars) eg: kronosnet0%s", IFNAMSIZ, telnet_newline);
			break;
		case CMDS_PARAM_IP:
			knet_vty_write(vty, "IP address - ipv4 or ipv6 address to add/remove%s", telnet_newline);
			break;
		case CMDS_PARAM_IP_PREFIX:
			knet_vty_write(vty, "IP prefix len (eg. 24, 64)%s", telnet_newline);
			break;
		case CMDS_PARAM_IP_PORT:
			knet_vty_write(vty, "base port (eg: %d) %s", KNET_RING_DEFPORT, telnet_newline);
		case CMDS_PARAM_BOOL:
			break;
		case CMDS_PARAM_INT:
			break;
		case CMDS_PARAM_NODEID:
			knet_vty_write(vty, "NODEID - unique identifier for this interface in this kronos network (value between 0 and 255)%s", telnet_newline);
			break;
		case CMDS_PARAM_NAME:
			knet_vty_write(vty, "NAME - unique name identifier for this entity (max %d chars)%s", KNET_MAX_HOST_LEN - 1, telnet_newline);
			break;
		case CMDS_PARAM_MTU:
			knet_vty_write(vty, "MTU - a value between 576 and 65536 (note: max value depends on the media)%s", telnet_newline);
			break;
		default: /* this should never happen */
			knet_vty_write(vty, "CLI ERROR: unknown parameter type%s", telnet_newline);
			break;
	}
}

static void print_help(struct knet_vty *vty, const vty_node_cmds_t *cmds, int idx)
{
	if ((idx < 0) || (cmds == NULL) || (cmds[idx].cmd == NULL))
		return;

	if (cmds[idx].help != NULL) {
		knet_vty_write(vty, "%s\t%s%s",
			cmds[idx].cmd,
			cmds[idx].help,
			telnet_newline);
	} else {
		knet_vty_write(vty, "%s\tNo help available for this command%s",
			cmds[idx].cmd,
			telnet_newline);
	}
}

static int get_param(struct knet_vty *vty, int wanted_paranum,
			      char **param, int *paramlen, int *paramoffset)
{
	int eparams, tparams;
	const vty_param_t *params = (const vty_param_t *)vty->param;
	int paramstart = vty->paramoffset;

	eparams = expected_params(params);
	tparams = count_words(vty, paramstart);

	if (tparams > eparams)
		return -1;

	if (wanted_paranum == -1) {
		get_n_word_from_end(vty, 1, param, paramlen, paramoffset);
		return tparams;
	}

	if (tparams < wanted_paranum)
		return -1;

	get_n_word_from_end(vty, (tparams - wanted_paranum) + 1, param, paramlen, paramoffset);
	return tparams - wanted_paranum;
}


static int match_command(struct knet_vty *vty, const vty_node_cmds_t *cmds,
			 char *cmd, int cmdlen, int cmdoffset, int mode)
{
	int idx = 0, found = -1, paramoffset = 0, paramlen = 0, last_param = 0;
	char *param = NULL;
	int paramstart = cmdlen + cmdoffset;
	int matches[KNET_VTY_MAX_MATCHES];

	memset(&matches, -1, sizeof(matches));

	while ((cmds[idx].cmd != NULL) && (idx < KNET_VTY_MAX_MATCHES)) {
		if (!strncmp(cmds[idx].cmd, cmd, cmdlen)) {
			found++;
			matches[found] = idx;
		}
		idx++;
	}

	if (idx >= KNET_VTY_MAX_MATCHES) {
		knet_vty_write(vty, "Too many matches for this command%s", telnet_newline);
		return -1;
	}

	if (found < 0) {
		knet_vty_write(vty, "There is no such command%s", telnet_newline);
		return -1;
	}

	switch(mode) {
		case KNET_VTY_MATCH_HELP:
			if (found == 0) {
				if ((cmdoffset <= vty->cursor_pos) && (vty->cursor_pos <= paramstart)) {
					print_help(vty, cmds, matches[0]);
					break;
				}
				if (cmds[matches[0]].params != NULL) {
					vty->param = (void *)cmds[matches[0]].params;
					vty->paramoffset = paramstart;
					last_param = get_param(vty, -1, &param, &paramlen, &paramoffset);

					if ((paramoffset <= vty->cursor_pos) && (vty->cursor_pos <= (paramoffset + paramlen)))
						last_param--;

					if (last_param >= CMDS_PARAM_NOMORE) {
						describe_param(vty, cmds[matches[0]].params[last_param].param);
						if (paramoffset > 0)
							check_param(vty, cmds[matches[0]].params[last_param].param, param, paramlen);
					}
					break;
				}
			}
			if (found >= 0) {
				idx = 0;
				while (matches[idx] >= 0) {
					print_help(vty, cmds, matches[idx]);
					idx++;
				}
			}
			break;
		case KNET_VTY_MATCH_EXEC:
			if (found == 0) {
				int exec = 0;
				if (cmds[matches[0]].params != NULL) {
					int eparams, tparams;

					eparams = expected_params(cmds[matches[0]].params);
					tparams = count_words(vty, paramstart);

					if (eparams != tparams) {
						exec = -1;
						idx = 0;

						knet_vty_write(vty, "Parameter required for this command:%s", telnet_newline);

						while(cmds[matches[0]].params[idx].param != CMDS_PARAM_NOMORE) {
							describe_param(vty, cmds[matches[0]].params[idx].param);
							idx++;
						}
						break;
					}

					idx = 0;
					vty->param = (void *)cmds[matches[0]].params;
					vty->paramoffset = paramstart;
					while(cmds[matches[0]].params[idx].param != CMDS_PARAM_NOMORE) {
						get_param(vty, idx + 1, &param, &paramlen, &paramoffset);
						if (check_param(vty, cmds[matches[0]].params[idx].param,
								param, paramlen) < 0) {
							exec = -1;
							if (vty->filemode)
								return -1;
						}

						idx++;
					}
				}
				if (!exec) {
					if (cmds[matches[0]].params != NULL) {
						vty->param = (void *)cmds[matches[0]].params;
						vty->paramoffset = paramstart;
					}
					if (cmds[matches[0]].func != NULL) {
						return cmds[matches[0]].func(vty);
					} else { /* this will eventually disappear */
						knet_vty_write(vty, "no fn associated to this command%s", telnet_newline);
					}
				}
			}
			if (found > 0) {
				knet_vty_write(vty, "Ambiguous command.%s", telnet_newline);
			}
			break;
		case KNET_VTY_MATCH_EXPAND:
			if (found == 0) {
				int cmdreallen;

				if (vty->cursor_pos > cmdoffset+cmdlen) /* complete param? */
					break;

				cmdreallen = strlen(cmds[matches[0]].cmd);
				memset(vty->line + cmdoffset, 0, cmdlen);
				memcpy(vty->line + cmdoffset, cmds[matches[0]].cmd, cmdreallen);
				vty->line[cmdreallen + cmdoffset] = ' ';
				vty->line_idx = cmdreallen + cmdoffset + 1;
				vty->cursor_pos = cmdreallen + cmdoffset + 1;
			}
			if (found > 0) { /* add completion to string base root */
				int count = 0;
				idx = 0;
				while (matches[idx] >= 0) {
					knet_vty_write(vty, "%s\t\t", cmds[matches[idx]].cmd);
					idx++;
					count++;
					if (count == 4) {
						knet_vty_write(vty, "%s",telnet_newline);
						count = 0;
					}
				}
				knet_vty_write(vty, "%s",telnet_newline);
			}
			break;
		default: /* this should never really happen */
			log_info("Unknown match mode");
			break;
	}
	return found;
}

/* forward declarations */

/* common to almost all nodes */
static int knet_cmd_logout(struct knet_vty *vty);
static int knet_cmd_who(struct knet_vty *vty);
static int knet_cmd_exit_node(struct knet_vty *vty);
static int knet_cmd_help(struct knet_vty *vty);

/* root node */
static int knet_cmd_config(struct knet_vty *vty);

/* config node */
static int knet_cmd_interface(struct knet_vty *vty);
static int knet_cmd_no_interface(struct knet_vty *vty);
static int knet_cmd_show_conf(struct knet_vty *vty);
static int knet_cmd_write_conf(struct knet_vty *vty);

/* interface node */
static int knet_cmd_mtu(struct knet_vty *vty);
static int knet_cmd_no_mtu(struct knet_vty *vty);
static int knet_cmd_ip(struct knet_vty *vty);
static int knet_cmd_no_ip(struct knet_vty *vty);
static int knet_cmd_baseport(struct knet_vty *vty);
static int knet_cmd_peer(struct knet_vty *vty);
static int knet_cmd_no_peer(struct knet_vty *vty);
static int knet_cmd_start(struct knet_vty *vty);
static int knet_cmd_stop(struct knet_vty *vty);

/* peer node */
static int knet_cmd_link(struct knet_vty *vty);
static int knet_cmd_no_link(struct knet_vty *vty);

/* root node description */
vty_node_cmds_t root_cmds[] = {
	{ "configure", "enter configuration mode", NULL, knet_cmd_config },
	{ "exit", "exit from CLI", NULL, knet_cmd_logout },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ NULL, NULL, NULL, NULL },
};

/* config node description */
vty_param_t no_int_params[] = {
	{ CMDS_PARAM_KNET },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t no_config_cmds[] = {
	{ "interface", "destroy kronosnet interface", no_int_params, knet_cmd_no_interface },
	{ NULL, NULL, NULL, NULL },
};

vty_param_t int_params[] = {
	{ CMDS_PARAM_KNET },
	{ CMDS_PARAM_NODEID },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t config_cmds[] = {
	{ "exit", "exit configuration mode", NULL, knet_cmd_exit_node },
	{ "interface", "configure kronosnet interface", int_params, knet_cmd_interface },
	{ "show", "show running config", NULL, knet_cmd_show_conf },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ "write", "write current config to file", NULL, knet_cmd_write_conf },
	{ NULL, NULL, NULL, NULL },
};

/* interface node description */

vty_param_t ip_params[] = {
	{ CMDS_PARAM_IP },
	{ CMDS_PARAM_IP_PREFIX },
	{ CMDS_PARAM_NOMORE },
};

vty_param_t peer_params[] = {
	{ CMDS_PARAM_NAME },
	{ CMDS_PARAM_NODEID },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t no_interface_cmds[] = {
	{ "ip", "remove ip address", ip_params, knet_cmd_no_ip },
	{ "mtu", "revert to default MTU", NULL, knet_cmd_no_mtu },
	{ "peer", "remove peer from this interface", peer_params, knet_cmd_no_peer },
	{ NULL, NULL, NULL, NULL },
};

vty_param_t mtu_params[] = {
	{ CMDS_PARAM_MTU },
	{ CMDS_PARAM_NOMORE },
};

vty_param_t baseport_params[] = {
	{ CMDS_PARAM_IP_PORT },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t interface_cmds[] = {
	{ "baseport", "set base listening port for this interface", baseport_params, knet_cmd_baseport },
	{ "exit", "exit configuration mode", NULL, knet_cmd_exit_node },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "ip", "add ip address", ip_params, knet_cmd_ip },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "mtu", "set mtu", mtu_params, knet_cmd_mtu },
	{ "no", "revert command", NULL, NULL },
	{ "peer", "add peer endpoint", peer_params, knet_cmd_peer },
	{ "show", "show running config", NULL, knet_cmd_show_conf },
	{ "start", "start forwarding engine", NULL, knet_cmd_start },
	{ "stop", "stop forwarding engine", NULL, knet_cmd_stop },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ "write", "write current config to file", NULL, knet_cmd_write_conf },
	{ NULL, NULL, NULL, NULL },
};

/* peer node description */

vty_param_t link_params[] = {
	{ CMDS_PARAM_IP },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t no_peer_cmds[] = {
	{ "link", "remove peer endpoint", link_params, knet_cmd_no_link},
	{ NULL, NULL, NULL, NULL },
};

vty_node_cmds_t peer_cmds[] = {
	{ "exit", "exit configuration mode", NULL, knet_cmd_exit_node },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "link", "add peer endpoint", link_params, knet_cmd_link },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL },
	{ "show", "show running config", NULL, knet_cmd_show_conf },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ "write", "write current config to file", NULL, knet_cmd_write_conf },
	{ NULL, NULL, NULL, NULL },
};

/* link node description */

vty_node_cmds_t link_cmds[] = {
	{ "exit", "exit configuration mode", NULL, knet_cmd_exit_node },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL },
	{ "show", "show running config", NULL, knet_cmd_show_conf },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ "write", "write current config to file", NULL, knet_cmd_write_conf },
	{ NULL, NULL, NULL, NULL },
};

/* nodes */
vty_nodes_t knet_vty_nodes[] = {
	{ NODE_ROOT, "knet", root_cmds, NULL },
	{ NODE_CONFIG, "config", config_cmds, no_config_cmds },
	{ NODE_INTERFACE, "iface", interface_cmds, no_interface_cmds },
	{ NODE_PEER, "peer", peer_cmds, no_peer_cmds },
	{ NODE_LINK, "link", link_cmds, NULL },
	{ -1, NULL, NULL },
};

/* command execution */

/* links */

static int knet_cmd_no_link(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_host *host = (struct knet_host *)vty->host;
	int j, paramlen = 0, paramoffset = 0, found = 0;
	char *param = NULL;
	char ipaddr[KNET_MAX_HOST_LEN], port[6];

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, KNET_MAX_HOST_LEN, param, paramlen);

	memset(port, 0, sizeof(port));
	snprintf(port, 6, "%d", knet_iface->cfg_ring.base_port + knet_iface->cfg_eth.node_id);

	for (j = 0; j < KNET_MAX_LINK; j++) {
		if (!strcmp(host->link[j].ipaddr, ipaddr)
					&& !strcmp(host->link[j].port, port)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		knet_vty_write(vty, "Error: unable to find link%s", telnet_newline);
		return -1;
	}

	host->link[j].ready = 0;

	return 0;
}

static int knet_cmd_link(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_host *host = (struct knet_host *)vty->host;
	struct knet_link *klink = NULL;
	int j, paramlen = 0, paramoffset = 0, err = 0, found = 0;
	char *param = NULL;
	char ipaddr[KNET_MAX_HOST_LEN], port[6];

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, KNET_MAX_HOST_LEN, param, paramlen);

	memset(port, 0, sizeof(port));
	snprintf(port, 6, "%d", knet_iface->cfg_ring.base_port + knet_iface->cfg_eth.node_id);

	for (j = 0; j < KNET_MAX_LINK; j++) {
		if ((klink == NULL) && (host->link[j].ready == 0)) {
			klink = &host->link[j];
		}
		if (!strcmp(host->link[j].ipaddr, ipaddr)
					&& !strcmp(host->link[j].port, port)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (!klink) {
			knet_vty_write(vty, "Error: all links are in use!%s", telnet_newline);
			return -1;
		}

		memset(klink, 0, sizeof(struct knet_link));

		memcpy(klink->ipaddr, ipaddr, strlen(ipaddr));
		memcpy(klink->port, port, strlen(port));

		if (strtoaddr(klink->ipaddr, klink->port, (struct sockaddr *)&klink->address, sizeof(klink->address)) != 0) {
			knet_vty_write(vty, "Error: unable to convert ip addr to sockaddr!%s", telnet_newline);
			err = -1;
			goto out_clean;
		}

		klink->sock = host->listener->sock;

		knet_link_timeout(klink, 1000, 5000, 2048);

		klink->ready = 1;
	}

	vty->link = (void *)klink;
	vty->node = NODE_LINK;

out_clean:
	if (err < 0) {
		if (klink)
			free(klink);

	}
	return err;
}

static int knet_find_host(struct knet_vty *vty, struct knet_host **host,
					const char *nodename, const int requested_node_id)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_host *head = NULL;
	int err = 0;

	*host = NULL;
	if (knet_host_acquire(knet_iface->cfg_ring.knet_h, &head)) {
		knet_vty_write(vty, "Error: unable to acquire lock on peer list!%s", telnet_newline);
		return -1;
	}

	while (head != NULL) {
		if (!strcmp(head->name, nodename)) {
			if (head->node_id == requested_node_id) {
				*host = head;
				err = 1;
				goto out_clean;
			} else {
				knet_vty_write(vty, "Error: requested peer exists with another nodeid%s", telnet_newline);
				err = -1;
				goto out_clean;
			}
		} else {
			if (head->node_id == requested_node_id) {
				knet_vty_write(vty, "Error: requested peer nodeid already exists%s", telnet_newline);
				err = -1;
				goto out_clean;
			}
		}
		head = head->next;
	}

out_clean:
	while (knet_host_release(knet_iface->cfg_ring.knet_h, &head) != 0) {
		knet_vty_write(vty, "Error: unable to release lock on peer list!%s", telnet_newline);
		sleep(1);
	}

	return err;
}

static int knet_cmd_no_peer(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	int paramlen = 0, paramoffset = 0, requested_node_id = 0, err = 0;
	char *param = NULL;
	struct knet_host *host = NULL;
	char nodename[KNET_MAX_HOST_LEN];

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(nodename, sizeof(nodename), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	requested_node_id = param_to_int(param, paramlen);

	if (requested_node_id == knet_iface->cfg_eth.node_id) {
		knet_vty_write(vty, "Error: remote peer id cannot be the same as local id%s", telnet_newline);
		return -1;
	}

	err = knet_find_host(vty, &host, nodename, requested_node_id);
	if (err < 0)
		goto out_clean;

	if (err == 0) {
		knet_vty_write(vty, "Error: peer not found in list%s", telnet_newline);
		goto out_clean;
	}
	if (host->listener) {
		if (knet_listener_remove(knet_iface->cfg_ring.knet_h, host->listener) == -EBUSY) {
			knet_vty_write(vty, "Error: unable to remove listener from current peer%s", telnet_newline);
			err = -1;
			goto out_clean;
		}
	}

	if (knet_host_remove(knet_iface->cfg_ring.knet_h, requested_node_id) < 0) {
		knet_vty_write(vty, "Error: unable to remove peer from current config%s", telnet_newline);
		err = -1;
		goto out_clean;
	}

out_clean:
	return err;
}

static int knet_cmd_peer(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	int paramlen = 0, paramoffset = 0, requested_node_id = 0, err = 0;
	char *param = NULL;
	struct knet_host *host, *temp = NULL;
	struct knet_listener *listener = NULL;
	char nodename[KNET_MAX_HOST_LEN];

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(nodename, sizeof(nodename), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	requested_node_id = param_to_int(param, paramlen);

	if (requested_node_id == knet_iface->cfg_eth.node_id) {
		knet_vty_write(vty, "Error: remote peer id cannot be the same as local id%s", telnet_newline);
		return -1;
	}

	err = knet_find_host(vty, &host, nodename, requested_node_id);
	if (err < 0)
		goto out_clean;

	if (err == 0) {
		if (knet_host_add(knet_iface->cfg_ring.knet_h, requested_node_id) < 0) {
			knet_vty_write(vty, "Error: unable to allocate memory for host struct!%s", telnet_newline);
			err = -1;
			goto out_clean;
		}
		knet_host_get(knet_iface->cfg_ring.knet_h, requested_node_id, &temp);
		host = temp;
		knet_host_release(knet_iface->cfg_ring.knet_h, &temp);
		memcpy(host->name, nodename, strlen(nodename));

		listener = malloc(sizeof(struct knet_listener));
		if (!listener) {
			knet_vty_write(vty, "Error: unable to allocate memory for listener struct!%s", telnet_newline);
			err = -1;
			goto out_clean;
		}
		memset(listener, 0, sizeof(struct knet_listener));
		snprintf(listener->ipaddr, KNET_MAX_HOST_LEN, "::");
		snprintf(listener->port, 6, "%d", knet_iface->cfg_ring.base_port + requested_node_id);
		if (strtoaddr(listener->ipaddr, listener->port, (struct sockaddr *)&listener->address, sizeof(listener->address)) != 0) {
			knet_vty_write(vty, "Error: unable to convert ip addr to sockaddr!%s", telnet_newline);
			err = -1;
			goto out_clean;
		}
		if (knet_listener_add(knet_iface->cfg_ring.knet_h, listener) != 0) {
			knet_vty_write(vty, "Error: unable to start listener!%s", telnet_newline);
			err = -1;
			goto out_clean;
		}
		host->listener = listener;
	}

	vty->host = (void *)host;
	vty->node = NODE_PEER;

out_clean:
	if (err < 0) {
		if (listener)
			free(listener);
		if (host)
			knet_host_remove(knet_iface->cfg_ring.knet_h, host->node_id);
	}

	return err;
}

static int active_listeners(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_host *head = NULL;
	int listeners = 0;

	if (knet_host_acquire(knet_iface->cfg_ring.knet_h, &head)) {
		knet_vty_write(vty, "Error: unable to acquire lock on peer list!%s", telnet_newline);
		return -1;
	}

	while (head != NULL) {
		if (head->listener)
			listeners++;
		head = head->next;
	}

	while (knet_host_release(knet_iface->cfg_ring.knet_h, &head) != 0) {
		knet_vty_write(vty, "Error: unable to release lock on peer list!%s", telnet_newline);
		sleep(1);
	}

	return listeners;
}

static int knet_cmd_baseport(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	int paramlen = 0, paramoffset = 0, err = 0;
	char *param = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);

	/* need to check if baseport is in use by other interfaces */
	err = active_listeners(vty);
	if (!err) {
		knet_iface->cfg_ring.base_port = param_to_int(param, paramlen);
	}
	if (err > 0) {
		knet_vty_write(vty, "Error: cannot switch baseport when listeners are active%s", telnet_newline);
		err = -1;
	}

	return err;
}

static int knet_cmd_no_ip(struct knet_vty *vty)
{
	int paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char ipaddr[KNET_MAX_HOST_LEN], prefix[4];
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, sizeof(ipaddr), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	param_to_str(prefix, sizeof(prefix), param, paramlen);

	if (knet_tap_del_ip(knet_iface->cfg_eth.knet_tap, ipaddr, prefix) < 0) {
		knet_vty_write(vty, "Error: Unable to del ip addr %s/%s on device %s%s",
				ipaddr, prefix, knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);
		return -1;
	}

	return 0;
}

static int knet_cmd_ip(struct knet_vty *vty)
{
	int paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char ipaddr[512], prefix[4];
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, sizeof(ipaddr), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	param_to_str(prefix, sizeof(prefix), param, paramlen);

	if (knet_tap_add_ip(knet_iface->cfg_eth.knet_tap, ipaddr, prefix) < 0) {
		knet_vty_write(vty, "Error: Unable to set ip addr %s/%s on device %s%s",
				ipaddr, prefix, knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);
	}

	return 0;
}

static int knet_cmd_no_mtu(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	if (knet_tap_reset_mtu(knet_iface->cfg_eth.knet_tap) < 0) {
		knet_vty_write(vty, "Error: Unable to set default mtu on device %s%s",
				knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);
				return -1;
	}

	return 0;
}

static int knet_cmd_mtu(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	int paramlen = 0, paramoffset = 0, expected_mtu = 0;
	char *param = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	expected_mtu = param_to_int(param, paramlen);

	if (knet_tap_set_mtu(knet_iface->cfg_eth.knet_tap, expected_mtu) < 0) {
		knet_vty_write(vty, "Error: Unable to set requested mtu %d on device %s%s",
				expected_mtu, knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);
				return -1;
	}

	return 0;
}

static int knet_cmd_stop(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	if (knet_tap_set_down(knet_iface->cfg_eth.knet_tap) < 0)
		knet_vty_write(vty, "Error: Unable to set interface %s down!%s", knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);

	knet_handle_setfwd(knet_iface->cfg_ring.knet_h, 0);

	knet_iface->active = 0;

	return 0;
}

static int knet_cmd_start(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	knet_handle_setfwd(knet_iface->cfg_ring.knet_h, 1);

	if (knet_tap_set_up(knet_iface->cfg_eth.knet_tap) < 0) {
		knet_vty_write(vty, "Error: Unable to set interface %s up!%s", knet_tap_get_name(knet_iface->cfg_eth.knet_tap), telnet_newline);
		knet_handle_setfwd(knet_iface->cfg_ring.knet_h, 0);
		return -1;
	}

	knet_iface->active = 1;

	return 0;
}

static int knet_cmd_no_interface(struct knet_vty *vty)
{
	int err = 0, paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char device[IFNAMSIZ];
	struct knet_cfg *knet_iface = NULL;
	struct knet_host *host;
	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(device, IFNAMSIZ, param, paramlen);

	knet_iface = knet_get_iface(device, 0);
	if (!knet_iface) {
		knet_vty_write(vty, "Error: Unable to find requested interface%s", telnet_newline);
		return -1;
	}

	vty->iface = (void *)knet_iface;

/* FIXME
	while (knet_iface->cfg_eth.knet_ip != NULL) {
		knet_tap_del_ip(knet_iface->cfg_eth.knet_tap,
			    knet_iface->cfg_eth.knet_ip->ipaddr,
			    knet_iface->cfg_eth.knet_ip->prefix);
		knet_destroy_ip(knet_iface, knet_iface->cfg_eth.knet_ip);
	}
*/

	while (1) {
		struct knet_host *head;
		int i;

		while (knet_host_acquire(knet_iface->cfg_ring.knet_h, &head) != 0) {
			log_error("CLI ERROR: unable to acquire peer lock.. will retry in 1 sec"); 
			sleep (1);
		}

		if (head == NULL)
			break;

		host = head;

		while (knet_host_release(knet_iface->cfg_ring.knet_h, &head) != 0) {
			log_error("CLI ERROR: unable to release peer lock.. will retry in 1 sec");
			sleep (1);
		}

		for (i = 0; i < KNET_MAX_LINK; i++)
			host->link[i].ready = 0;

		knet_listener_remove(knet_iface->cfg_ring.knet_h, host->listener);

		while (knet_host_remove(knet_iface->cfg_ring.knet_h, host->node_id) != 0) {
			log_error("CLI ERROR: unable to release peer.. will retry in 1 sec");
			sleep (1);
		}
	}

	knet_cmd_stop(vty);

	if (knet_iface->cfg_ring.knet_h)
		knet_handle_free(knet_iface->cfg_ring.knet_h);

	if (knet_iface->cfg_eth.knet_tap)
		knet_tap_close(knet_iface->cfg_eth.knet_tap);

	if (knet_iface)
		knet_destroy_iface(knet_iface);

	return err;
}

static int knet_cmd_interface(struct knet_vty *vty)
{
	int err = 0, paramlen = 0, paramoffset = 0, found = 0, requested_id;
	char *param = NULL, *cur_mac = NULL;
	char device[IFNAMSIZ];
	char mac[18];
	int maclen;
	struct knet_cfg *knet_iface = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(device, IFNAMSIZ, param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	requested_id = param_to_int(param, paramlen);

	knet_iface = knet_get_iface(device, 1);
	if (!knet_iface) {
		knet_vty_write(vty, "Error: Unable to allocate memory for config structures%s",
				telnet_newline);
		return -1;
	}

	if (knet_iface->cfg_eth.knet_tap) {
		found = 1;
		goto knet_tap_found;
	}

	if (!knet_iface->cfg_eth.knet_tap)
		knet_iface->cfg_eth.knet_tap = knet_tap_open(device, IFNAMSIZ);

	if ((!knet_iface->cfg_eth.knet_tap) && (errno = EBUSY)) {
		knet_vty_write(vty, "Error: interface %s seems to exist in the system%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}

	if (!knet_iface->cfg_eth.knet_tap) {
		knet_vty_write(vty, "Error: Unable to create %s system tap device%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}
knet_tap_found:

	if (knet_iface->cfg_ring.knet_h)
		goto knet_found;

	/* FIXME */
	knet_iface->cfg_ring.knet_h = knet_handle_new(knet_tap_get_fd(knet_iface->cfg_eth.knet_tap));
	//knet_iface->cfg_ring.knet_h = knet_handle_new(knet_tap_get_fd(knet_iface->cfg_eth.knet_tap), requested_id);
	if (!knet_iface->cfg_ring.knet_h) {
		knet_vty_write(vty, "Error: Unable to create ring handle for device %s%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}

knet_found:
	if (found) {
		if (requested_id == knet_iface->cfg_eth.node_id)
			goto out_found;

		knet_vty_write(vty, "Error: no interface %s with nodeid %d found%s",
				device, requested_id, telnet_newline);
		goto out_clean;

	} else {
		knet_iface->cfg_eth.node_id = requested_id;
	}

	if (knet_tap_get_mac(knet_iface->cfg_eth.knet_tap, &cur_mac) < 0) {
		knet_vty_write(vty, "Error: Unable to get mac address on device %s%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}
	memset(&mac, 0, sizeof(mac));
	maclen = strrchr(cur_mac, ':') - cur_mac + 1;
	memcpy(mac, cur_mac, maclen);
	snprintf(mac + maclen, sizeof(mac) - maclen, "%x", knet_iface->cfg_eth.node_id);
	free(cur_mac);
	if (knet_tap_set_mac(knet_iface->cfg_eth.knet_tap, mac) < 0) {
		knet_vty_write(vty, "Error: Unable to set mac address %s on device %s%s",
				mac, device, telnet_newline); 
		err = -1;
		goto out_clean;
	}

out_found:

	vty->node = NODE_INTERFACE;
	vty->iface = (void *)knet_iface;

out_clean:
	if (err) {
		if (knet_iface->cfg_ring.knet_h)
			knet_handle_free(knet_iface->cfg_ring.knet_h);

		if (knet_iface->cfg_eth.knet_tap)
			knet_tap_close(knet_iface->cfg_eth.knet_tap);
 
		knet_destroy_iface(knet_iface);
	}
	return err;
}

static int knet_cmd_exit_node(struct knet_vty *vty)
{
	knet_vty_exit_node(vty);
	return 0;
}

static int knet_cmd_print_conf(struct knet_vty *vty)
{
	int i;
	struct knet_cfg *knet_iface = knet_cfg_head.knet_cfg;
	struct knet_host *host = NULL;
	const char *nl = telnet_newline;

	if (vty->filemode)
		nl = file_newline;

	knet_vty_write(vty, "configure%s", nl);

	while (knet_iface != NULL) {
		knet_vty_write(vty, " interface %s %d%s", knet_tap_get_name(knet_iface->cfg_eth.knet_tap), knet_iface->cfg_eth.node_id, nl);

		knet_vty_write(vty, "  mtu %d%s", knet_tap_get_mtu(knet_iface->cfg_eth.knet_tap), nl);

/* FIXME
		while (knet_ip != NULL) {
			knet_vty_write(vty, "  ip %s %s%s", knet_ip->ipaddr, knet_ip->prefix, nl);
			knet_ip = knet_ip->next;
		}
*/

		knet_vty_write(vty, "  baseport %d%s", knet_iface->cfg_ring.base_port, nl);

		while (knet_host_acquire(knet_iface->cfg_ring.knet_h, &host)) {
			log_error("CLI ERROR: waiting for peer lock");
			sleep(1);
		}

		while (host != NULL) {
			knet_vty_write(vty, "  peer %s %d%s", host->name, host->node_id, nl);
			for (i = 0; i < KNET_MAX_LINK; i++) {
				if (host->link[i].ready == 1) {
					knet_vty_write(vty, "   link %s%s", host->link[i].ipaddr, nl);
					/* print link properties */
					knet_vty_write(vty, "    exit%s", nl);
				}
			}
			knet_vty_write(vty, "   exit%s", nl);
			host = host->next;
		}

		while (knet_host_release(knet_iface->cfg_ring.knet_h, &host) != 0) {
			log_error("CLI ERROR: unable to release peer lock.. will retry in 1 sec");
			sleep(1);
		}

		if (knet_iface->active)
			knet_vty_write(vty, "  start%s", nl);

		knet_vty_write(vty, "  exit%s", nl);
		knet_iface = knet_iface->next;
	}

	knet_vty_write(vty, " exit%sexit%s", nl, nl);

	return 0;
}

static int knet_cmd_show_conf(struct knet_vty *vty)
{
	return knet_cmd_print_conf(vty);
}

static int knet_cmd_write_conf(struct knet_vty *vty)
{
	int fd = 1, vty_sock, err = 0, backup = 1;
	char tempfile[PATH_MAX];

	memset(tempfile, 0, sizeof(tempfile));

	snprintf(tempfile, sizeof(tempfile), "%s.sav", knet_cfg_head.conffile);
	err = rename(knet_cfg_head.conffile, tempfile);
	if ((err < 0) && (errno != ENOENT)) {
		knet_vty_write(vty, "Unable to create backup config file %s %s", tempfile, telnet_newline);
		return -1;
	}
	if ((err < 0) && (errno == ENOENT))
		backup = 0;

	fd = open(knet_cfg_head.conffile,
		  O_RDWR | O_CREAT | O_EXCL | O_TRUNC,
		  S_IRUSR | S_IWUSR);
	if (fd < 0) {
		knet_vty_write(vty, "Error unable to open file%s", telnet_newline);
		return -1;
	}

	vty_sock = vty->vty_sock;
	vty->vty_sock = fd;
	vty->filemode = 1;
	knet_cmd_print_conf(vty);
	vty->vty_sock = vty_sock;
	vty->filemode = 0;

	close(fd);

	knet_vty_write(vty, "Configuration saved to %s%s", knet_cfg_head.conffile, telnet_newline);
	if (backup)
		knet_vty_write(vty, "Old configuration file has been stored in %s%s",
				tempfile, telnet_newline);

	return err;
}

static int knet_cmd_config(struct knet_vty *vty)
{
	int err = 0;

	if (!vty->user_can_enable) {
		knet_vty_write(vty, "Error: user %s does not have enough privileges to perform config operations%s", vty->username, telnet_newline);
		return -1;
	}

	pthread_mutex_lock(&knet_vty_mutex);
	if (knet_vty_config >= 0) {
		knet_vty_write(vty, "Error: configuration is currently locked by user %s on vty(%d). Try again later%s", vty->username, knet_vty_config, telnet_newline);
		err = -1;
		goto out_clean;
	}
	vty->node = NODE_CONFIG;
	knet_vty_config = vty->conn_num;
out_clean:
	pthread_mutex_unlock(&knet_vty_mutex);
	return err;
}

static int knet_cmd_logout(struct knet_vty *vty)
{
	vty->got_epipe = 1;
	return 0;
}

static int knet_cmd_who(struct knet_vty *vty)
{
	int conn_index;

	pthread_mutex_lock(&knet_vty_mutex);

	for(conn_index = 0; conn_index < KNET_VTY_TOTAL_MAX_CONN; conn_index++) {
		if (knet_vtys[conn_index].active) {
			knet_vty_write(vty, "User %s connected on vty(%d) from %s%s",
				knet_vtys[conn_index].username,
				knet_vtys[conn_index].conn_num,
				knet_vtys[conn_index].ip,
				telnet_newline);
		}
	}

	pthread_mutex_unlock(&knet_vty_mutex);

	return 0;
}

static int knet_cmd_help(struct knet_vty *vty)
{
	knet_vty_write(vty, PACKAGE " VTY provides advanced help feature.%s%s"
			    "When you need help, anytime at the command line please press '?'.%s%s"
			    "If nothing matches, the help list will be empty and you must backup%s"
			    " until entering a '?' shows the available options.%s",
			    telnet_newline, telnet_newline, telnet_newline, telnet_newline, 
			    telnet_newline, telnet_newline);
	return 0;
}

/* exported API to vty_cli.c */

int knet_vty_execute_cmd(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;
	int cmdoffset = 0;

	if (knet_vty_is_line_empty(vty))
		return 0;

	cmds = get_cmds(vty, &cmd, &cmdlen, &cmdoffset);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return 0;
	}

	return match_command(vty, cmds, cmd, cmdlen, cmdoffset, KNET_VTY_MATCH_EXEC);
}

int knet_read_conf(void)
{
	int err = 0, len = 0, line = 0;
	struct knet_vty *vty = &knet_vtys[0];
	FILE *file = NULL;

	file = fopen(knet_cfg_head.conffile, "r");

	if ((file == NULL) && (errno != ENOENT)) {
		log_error("Unable to open config file for reading %s", knet_cfg_head.conffile);
		return -1;
	}

	if ((file == NULL) && (errno == ENOENT)) {
		log_info("Configuration file %s not found, starting with default empty config", knet_cfg_head.conffile);
		return 0;
	}

	vty->vty_sock = 1;
	vty->user_can_enable = 1;
	vty->filemode = 1;

	while(fgets(vty->line, sizeof(vty->line), file) != NULL) {
		line++;
		len = strlen(vty->line) - 1;
		memset(&vty->line[len], 0, 1);
		vty->line_idx = len;
		err = knet_vty_execute_cmd(vty);
		if (err != 0)  {
			log_error("line[%d]: %s", line, vty->line);
			break;
		}
	}

	fclose(file);

	memset(vty, 0, sizeof(vty));

	return err;
}

void knet_vty_help(struct knet_vty *vty)
{
	int idx = 0;
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;
	int cmdoffset = 0;

	cmds = get_cmds(vty, &cmd, &cmdlen, &cmdoffset);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	if (knet_vty_is_line_empty(vty) || cmd == NULL) {
		while (cmds[idx].cmd != NULL) {
			print_help(vty, cmds, idx);
			idx++;
		}
		return;
	}

	match_command(vty, cmds, cmd, cmdlen, cmdoffset, KNET_VTY_MATCH_HELP);
}

void knet_vty_tab_completion(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;
	int cmdoffset = 0;

	if (knet_vty_is_line_empty(vty))
		return;

	knet_vty_write(vty, "%s", telnet_newline);

	cmds = get_cmds(vty, &cmd, &cmdlen, &cmdoffset);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	match_command(vty, cmds, cmd, cmdlen, cmdoffset, KNET_VTY_MATCH_EXPAND);

	knet_vty_prompt(vty);
	knet_vty_write(vty, "%s", vty->line);
}
