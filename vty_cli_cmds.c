#include "config.h"

#include "cfg.h"
#include "utils.h"
#include "knet.h"
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
#define CMDS_PARAM_BOOL		4
#define CMDS_PARAM_INT		5
#define CMDS_PARAM_NODEID	6
#define CMDS_PARAM_STR		7
#define CMDS_PARAM_MTU		8

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
		case CMDS_PARAM_STR:
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
			knet_vty_write(vty, "IP address - ipv4 or ipv6 address to add to this interface%s", telnet_newline);
			break;
		case CMDS_PARAM_IP_PREFIX:
			knet_vty_write(vty, "IP prefix len (eg. 24, 64)%s", telnet_newline);
			break;
		case CMDS_PARAM_BOOL:
			break;
		case CMDS_PARAM_INT:
			break;
		case CMDS_PARAM_NODEID:
			knet_vty_write(vty, "NODEID - unique identifier for this interface in this kronos network (value between 0 and 255)%s", telnet_newline);
			break;
		case CMDS_PARAM_STR:
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


/*
 * -1 command not found or error
 *  0 exact command found
 *  > 0 number of commands (-1)
 */
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
					while(cmds[matches[0]].params[idx].param != CMDS_PARAM_NOMORE) {
						vty->param = (void *)cmds[matches[0]].params;
						vty->paramoffset = paramstart;
						get_param(vty, idx + 1, &param, &paramlen, &paramoffset);
						if (check_param(vty, cmds[matches[0]].params[idx].param, param, paramlen) < 0)
							exec = -1;

						idx++;
					}
				}
				if (!exec) {
					if (cmds[matches[0]].params != NULL) {
						vty->param = (void *)cmds[matches[0]].params;
						vty->paramoffset = paramstart;
					}
					if (cmds[matches[0]].func != NULL) {
						cmds[matches[0]].func(vty);
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

/* interface node */
static int knet_cmd_mtu(struct knet_vty *vty);
static int knet_cmd_no_mtu(struct knet_vty *vty);
static int knet_cmd_ip(struct knet_vty *vty);
static int knet_cmd_no_ip(struct knet_vty *vty);

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
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ NULL, NULL, NULL, NULL },
};

/* interface node description */

vty_param_t ip_params[] = {
	{ CMDS_PARAM_IP },
	{ CMDS_PARAM_IP_PREFIX },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t no_interface_cmds[] = {
	{ "ip", "remove ip address", ip_params, knet_cmd_no_ip },
	{ "mtu", "revert to default MTU", NULL, knet_cmd_no_mtu },
	{ NULL, NULL, NULL, NULL },
};

vty_param_t mtu_params[] = {
	{ CMDS_PARAM_MTU },
	{ CMDS_PARAM_NOMORE },
};

vty_node_cmds_t interface_cmds[] = {
	{ "exit", "exit configuration mode", NULL, knet_cmd_exit_node },
	{ "help", "display basic help", NULL, knet_cmd_help },
	{ "ip", "add ip address", ip_params, knet_cmd_ip },
	{ "logout", "exit from CLI", NULL, knet_cmd_logout },
	{ "mtu", "set mtu", mtu_params, knet_cmd_mtu },
	{ "no", "revert command", NULL, NULL },
	{ "who", "display users connected to CLI", NULL, knet_cmd_who },
	{ NULL, NULL, NULL, NULL },
};

/* nodes */
vty_nodes_t knet_vty_nodes[] = {
	{ NODE_ROOT, "knet", root_cmds, NULL },
	{ NODE_CONFIG, "config", config_cmds, no_config_cmds },
	{ NODE_INTERFACE, "iface", interface_cmds, no_interface_cmds },
	{ -1, NULL, NULL },
};


/* command execution */

static int knet_cmd_no_ip(struct knet_vty *vty)
{
	int paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char ipaddr[512], prefix[4];
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_cfg_ip *knet_ip = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, sizeof(ipaddr), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	param_to_str(prefix, sizeof(prefix), param, paramlen);

	knet_ip = knet_get_ip(knet_iface, ipaddr, prefix, 0);
	if (!knet_ip) {
		knet_vty_write(vty, "Error: Unable to locate ip addr config entry%s", telnet_newline);
		return -1;
	}

	if (knet_del_ip(knet_iface->knet_eth, ipaddr, prefix) < 0) {
		knet_vty_write(vty, "Error: Unable to del ip addr %s/%s on device %s%s",
				ipaddr, prefix, knet_iface->cfg_eth.name, telnet_newline);
		return -1;
	}

	knet_destroy_ip(knet_iface, knet_ip);

	return 0;
}

static int knet_cmd_ip(struct knet_vty *vty)
{
	int paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char ipaddr[512], prefix[4];
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	struct knet_cfg_ip *knet_ip = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(ipaddr, sizeof(ipaddr), param, paramlen);

	get_param(vty, 2, &param, &paramlen, &paramoffset);
	param_to_str(prefix, sizeof(prefix), param, paramlen);

	knet_ip = knet_get_ip(knet_iface, ipaddr, prefix, 1);
	if (!knet_ip) {
		knet_vty_write(vty, "Error: Unable to create ip addr config entry%s", telnet_newline);
		return -1;
	}

	if (knet_ip->active)
		return 0;

	if (knet_add_ip(knet_iface->knet_eth, ipaddr, prefix) < 0) {
		knet_vty_write(vty, "Error: Unable to set ip addr %s/%s on device %s%s",
				ipaddr, prefix, knet_iface->cfg_eth.name, telnet_newline);
		knet_destroy_ip(knet_iface, knet_ip);
	}

	knet_ip->active = 1;

	return 0;
}

static int knet_cmd_no_mtu(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;

	if (knet_set_mtu(knet_iface->knet_eth, knet_iface->cfg_eth.default_mtu) < 0) {
		knet_vty_write(vty, "Error: Unable to set default mtu %d on device %s%s",
				 knet_iface->cfg_eth.default_mtu, knet_iface->cfg_eth.name, telnet_newline);
				return -1;
	}

	knet_iface->cfg_eth.mtu = knet_iface->cfg_eth.default_mtu;

	return 0;
}

static int knet_cmd_mtu(struct knet_vty *vty)
{
	struct knet_cfg *knet_iface = (struct knet_cfg *)vty->iface;
	int paramlen = 0, paramoffset = 0, expected_mtu = 0;
	char *param = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	expected_mtu = param_to_int(param, paramlen);

	if (knet_set_mtu(knet_iface->knet_eth, expected_mtu) < 0) {
		knet_vty_write(vty, "Error: Unable to set requested mtu %d on device %s%s",
				expected_mtu, knet_iface->cfg_eth.name, telnet_newline);
				return -1;
	}

	knet_iface->cfg_eth.mtu = expected_mtu;

	return 0;
}

static int knet_cmd_no_interface(struct knet_vty *vty)
{
	int err = 0, paramlen = 0, paramoffset = 0;
	char *param = NULL;
	char device[IFNAMSIZ];
	struct knet_cfg *knet_iface = NULL;

	get_param(vty, 1, &param, &paramlen, &paramoffset);
	param_to_str(device, IFNAMSIZ, param, paramlen);

	knet_iface = knet_get_iface(device, 0);
	if (!knet_iface) {
		knet_vty_write(vty, "Error: Unable to find requested interface%s", telnet_newline);
		return -1;
	}

	while (knet_iface->cfg_eth.knet_ip != NULL) {
		knet_del_ip(knet_iface->knet_eth,
			    knet_iface->cfg_eth.knet_ip->ipaddr,
			    knet_iface->cfg_eth.knet_ip->prefix);
		knet_destroy_ip(knet_iface, knet_iface->cfg_eth.knet_ip);
	}

	if (knet_iface->knet_eth)
		knet_close(knet_iface->knet_eth);

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

	knet_iface = knet_get_iface(device, 1);
	if (!knet_iface) {
		knet_vty_write(vty, "Error: Unable to allocate memory for config structures%s",
				telnet_newline);
		return -1;
	}

	if (knet_iface->knet_eth) {
		found = 1;
		goto knet_found;
	}

	if (!knet_iface->knet_eth)
		knet_iface->knet_eth = knet_open(device, IFNAMSIZ);

	if ((!knet_iface->knet_eth) && (errno = EBUSY)) {
		knet_vty_write(vty, "Error: interface %s seems to exist in the system%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}

	if (!knet_iface->knet_eth) {
		knet_vty_write(vty, "Error: Unable to create %s system tap device%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}

knet_found:
	get_param(vty, 2, &param, &paramlen, &paramoffset);
	requested_id = param_to_int(param, paramlen);
	if (found) {
		if (requested_id == knet_iface->cfg_eth.node_id)
			goto out_found;

		knet_vty_write(vty, "Error: no interface %s with nodeid %d found%s",
				device, requested_id, telnet_newline);
		goto out_clean;

	} else {
		knet_iface->cfg_eth.node_id = requested_id;
	}

	if (knet_get_mac(knet_iface->knet_eth, &cur_mac) < 0) {
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
	if (knet_set_mac(knet_iface->knet_eth, mac) < 0) {
		knet_vty_write(vty, "Error: Unable to set mac address %s on device %s%s",
				mac, device, telnet_newline); 
		err = -1;
		goto out_clean;
	}

	knet_iface->cfg_eth.default_mtu = knet_get_mtu(knet_iface->knet_eth);
	if (knet_iface->cfg_eth.default_mtu < 0) {
		knet_vty_write(vty, "Error: Unable to get current MTU on device %s%s",
				device, telnet_newline);
		err = -1;
		goto out_clean;
	}
	knet_iface->cfg_eth.mtu = knet_iface->cfg_eth.default_mtu;

out_found:

	vty->node = NODE_INTERFACE;
	vty->iface = (void *)knet_iface;

out_clean:
	if (err) {
		if (knet_iface->knet_eth)
			knet_close(knet_iface->knet_eth);
 
		knet_destroy_iface(knet_iface);
	}
	return err;
}

static int knet_cmd_exit_node(struct knet_vty *vty)
{
	knet_vty_exit_node(vty);
	return 0;
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

void knet_vty_execute_cmd(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;
	int cmdoffset = 0;

	if (knet_vty_is_line_empty(vty))
		return;

	cmds = get_cmds(vty, &cmd, &cmdlen, &cmdoffset);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	match_command(vty, cmds, cmd, cmdlen, cmdoffset, KNET_VTY_MATCH_EXEC);
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
