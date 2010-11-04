#include <config.h>

#include "utils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

/* forward declarations */

static int knet_cmd_config(struct knet_vty *vty);
static int knet_cmd_exit_node(struct knet_vty *vty);
static int knet_cmd_help(struct knet_vty *vty);
static int knet_cmd_interface(struct knet_vty *vty);
static int knet_cmd_no_interface(struct knet_vty *vty);
static int knet_cmd_logout(struct knet_vty *vty);
static int knet_cmd_who(struct knet_vty *vty);

vty_node_cmds_t root_cmds[] = {
	{ "configure", "enter configuration mode", NULL, NULL, knet_cmd_config },
	{ "exit", "exit from CLI", NULL, NULL, knet_cmd_logout },
	{ "help", "display basic help", NULL, NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, NULL, knet_cmd_logout },
	{ "who", "display users connected to CLI", NULL, NULL, knet_cmd_who },
	{ NULL, NULL, NULL, NULL, NULL },
};

vty_node_opts_t interface_opts[] = {
	{ "name", "interface name (eg. kronosnet0)", NULL, 0 },
	{ NULL, NULL, NULL, 0 },

};

vty_node_cmds_t no_config_cmds[] = {
	{ "interface", "destroy kronosnet interface", NULL, interface_opts, knet_cmd_no_interface },
	{ NULL, NULL, NULL, NULL, NULL },
};

vty_node_cmds_t config_cmds[] = {
	{ "exit", "exit configuration mode", NULL, NULL, knet_cmd_exit_node },
	{ "interface", "configure kronosnet interface", NULL, interface_opts, knet_cmd_interface },
	{ "help", "display basic help", NULL, NULL, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, NULL, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL, NULL },
	{ "who", "display users connected to CLI", NULL, NULL, knet_cmd_who },
	{ NULL, NULL, NULL, NULL, NULL },
};

vty_nodes_t knet_vty_nodes[] = {
	{ NODE_ROOT, "knet", root_cmds, NULL },
	{ NODE_CONFIG, "config", config_cmds, no_config_cmds },
	{ NODE_INTERFACE, "iface", NULL, NULL },
	{ -1, NULL, NULL },
};

static int knet_cmd_no_interface(struct knet_vty *vty)
{
	int err = 0;
	return err;
}

static int knet_cmd_interface(struct knet_vty *vty)
{
	int err = 0;

	vty->node = NODE_INTERFACE;

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
	knet_vty_help(vty);
	return 0;
}

static int get_first_word(struct knet_vty *vty, char **cmd, int *len)
{
	int start = 0, idx;

	for (idx = 0; idx < vty->line_idx; idx++) {
		if (vty->line[idx] != ' ')
			break;
	}
	start = idx;
	if (start == vty->line_idx)
		return -1;

	*cmd = &vty->line[start];

	for (idx = start; idx < vty->line_idx; idx++) {
		if (vty->line[idx] == ' ')
			break;
	}

	*len = idx - start;

	return 0;
}

/*
 * note to self: need to change the return codes based on matches
 */
static int find_command(struct knet_vty *vty)
{
	char *cmd;
	int cmdlen, len, idx, found, ret;

	if (knet_vty_nodes[vty->node].cmds == NULL) {
		knet_vty_write(vty,
			"CLI error. no commands defined for this node%s", telnet_newline);
		return -1;
	}

	if (get_first_word(vty, &cmd, &len) < 0) {
		knet_vty_write(vty,
			"CLI error. Unable to determine command%s", telnet_newline);
		return -1;
	}

	idx = 0;
	found = 0;
	while (knet_vty_nodes[vty->node].cmds[idx].cmd != NULL) {
		cmdlen = strlen(knet_vty_nodes[vty->node].cmds[idx].cmd);
		ret = strncmp(knet_vty_nodes[vty->node].cmds[idx].cmd, cmd, len);
		if ((ret == 0) && (cmdlen == len)) {
			return idx;
		}
/*
		if (ret >= 0) {
			knet_vty_write(vty, "maybe multiple matches\n\r");
			found++;
		}
		if (ret < 0) {
			knet_vty_write(vty, "command(%s) does not match(%s)\n\r",
					cmd, knet_vty_nodes[vty->node].cmds[idx].cmd);
		}
*/
		idx++;
	}

	knet_vty_write(vty, "command (%s) not found%s", cmd, telnet_newline);

	return -1;
}

void knet_vty_execute_cmd(struct knet_vty *vty)
{
	void *func;
	int cmdidx;
	func = NULL;

	cmdidx = find_command(vty);
	if (cmdidx < 0)
		return;

	if (knet_vty_nodes[vty->node].cmds[cmdidx].func != NULL) {
		knet_vty_nodes[vty->node].cmds[cmdidx].func(vty);
	} else { /* this will eventually disappear */
		knet_vty_write(vty, "no fn associated to this command%s", telnet_newline);
	}
	return;
}

void knet_vty_help(struct knet_vty *vty)
{
	int idx = 0;

	if (knet_vty_nodes[vty->node].cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	while (knet_vty_nodes[vty->node].cmds[idx].cmd != NULL) {
		if (knet_vty_nodes[vty->node].cmds[idx].help != NULL) {
			knet_vty_write(vty, "%s\t%s%s",
				knet_vty_nodes[vty->node].cmds[idx].cmd,
				knet_vty_nodes[vty->node].cmds[idx].help,
				telnet_newline);
		} else {
			knet_vty_write(vty, "%s\tNo help available for this command%s",
				knet_vty_nodes[vty->node].cmds[idx].cmd,
				telnet_newline);
		}
		idx++;
	}
}

void knet_vty_exit_node(struct knet_vty *vty)
{
	switch(vty->node) {
		case NODE_INTERFACE:
			vty->node = NODE_CONFIG;
			break;
		case NODE_CONFIG:
			pthread_mutex_lock(&knet_vty_mutex);
			knet_vty_config = -1;
			pthread_mutex_unlock(&knet_vty_mutex);
			vty->node = NODE_ROOT;
			break;
		case NODE_ROOT:
			vty->got_epipe = 1;
			break;
		default:
			knet_vty_write(vty, "No idea where to go..%s", telnet_newline);
			break;
	}
}
