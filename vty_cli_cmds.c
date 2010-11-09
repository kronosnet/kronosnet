#include <config.h>

#include "utils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

#define KNET_VTY_MAX_MATCHES	64
#define KNET_VTY_MATCH_HELP	0
#define KNET_VTY_MATCH_EXEC	1
#define KNET_VTY_MATCH_EXPAND	2

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
	{ "NAME", "interface name (eg. kronosnet0)", NULL, 0, NULL },
	{ NULL, NULL, NULL, 0, NULL },
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
	knet_vty_write(vty, PACKAGE " VTY provides advanced help feature.%s%s"
			    "When you need help, anytime at the command line please press '?'.%s%s"
			    "If nothing matches, the help list will be empty and you must backup%s"
			    " until entering a '?' shows the available options.%s",
			    telnet_newline, telnet_newline, telnet_newline, telnet_newline, 
			    telnet_newline, telnet_newline);
	return 0;
}

static void knet_vty_print_help(struct knet_vty *vty, const vty_node_cmds_t *cmds, int idx)
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

/*
 * return 0 if we find a command in vty->line and cmd/len/no are set
 * return -1 if we cannot find a command. no can be trusted. cmd/len would be empty
 */

static int get_command(struct knet_vty *vty, char **cmd, int *len, int *no)
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

	for (idx = start; idx < vty->line_idx; idx++) {
		if (vty->line[idx] == ' ')
			break;
	}

	*len = idx - start;

	return 0;
}

static const vty_node_cmds_t *get_cmds(struct knet_vty *vty, char **cmd, int *len)
{
	int no;
	const vty_node_cmds_t *cmds =  knet_vty_nodes[vty->node].cmds;

	get_command(vty, cmd, len, &no);

	if (no)
		cmds = knet_vty_nodes[vty->node].no_cmds;

	return cmds;
}

/*
 * -1 command not found or error
 *  0 exact command found
 *  > 0 number of commands (-1)
 */
static int match_command(struct knet_vty *vty, const vty_node_cmds_t *cmds,
			 char *cmd, int len, int mode)
{
	int idx = 0, found = -1;
	int matches[KNET_VTY_MAX_MATCHES];

	memset(&matches, -1, sizeof(matches));

	while ((cmds[idx].cmd != NULL) && (idx < KNET_VTY_MAX_MATCHES)) {
		if (!strncmp(cmds[idx].cmd, cmd, len)) {
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
				if (cmds[matches[0]].opts != NULL) {
					//parse_opts(vty, cmd+len, cmds[matches[0]].opts);
					knet_vty_write(vty, "help for options not implemented%s", telnet_newline);
				} else {
					knet_vty_write(vty, "No options available%s", telnet_newline);
				}
			}
			if (found > 0) {
				idx = 0;
				while (matches[idx] >= 0) {
					knet_vty_print_help(vty, cmds, matches[idx]);
					idx++;
				}
			}
			break;
		case KNET_VTY_MATCH_EXEC:
			if (found == 0) {
				if (cmds[matches[0]].func != NULL) {
					cmds[matches[0]].func(vty);
				} else { /* this will eventually disappear */
					knet_vty_write(vty, "no fn associated to this command%s", telnet_newline);
				}
			}
			if (found > 0) {
				knet_vty_write(vty, "Ambiguous command.%s", telnet_newline);
			}
			break;
		default:
			log_info("Unknown match mode");
			break;
	}
	return found;
}

void knet_vty_execute_cmd(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int len = 0;

	if (knet_vty_is_line_empty(vty))
		return;

	cmds = get_cmds(vty, &cmd, &len);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	match_command(vty, cmds, cmd, len, KNET_VTY_MATCH_EXEC);
}

void knet_vty_help(struct knet_vty *vty)
{
	int idx = 0;
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int len = 0;

	cmds = get_cmds(vty, &cmd, &len);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	if (knet_vty_is_line_empty(vty) || cmd == NULL) {
		while (cmds[idx].cmd != NULL) {
			knet_vty_print_help(vty, cmds, idx);
			idx++;
		}
		return;
	}

	match_command(vty, cmds, cmd, len, KNET_VTY_MATCH_HELP);
}

void knet_vty_tab_completion(struct knet_vty *vty)
{
	if (knet_vty_is_line_empty(vty))
		return;

	/* here we need to do cmd/opt matching */
}
