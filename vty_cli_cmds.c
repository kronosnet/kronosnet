#include "config.h"

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

#define CMDS_PARAM_NO		0
#define CMDS_PARAM_KNET		1
#define CMDS_PARAM_IP		2
#define CMDS_PARAM_BOOL		3
#define CMDS_PARAM_INT		4
#define CMDS_PARAM_SHORT	5
#define CMDS_PARAM_STR		6

/* forward declarations */

static int knet_cmd_config(struct knet_vty *vty);
static int knet_cmd_exit_node(struct knet_vty *vty);
static int knet_cmd_help(struct knet_vty *vty);
static int knet_cmd_interface(struct knet_vty *vty);
static int knet_cmd_no_interface(struct knet_vty *vty);
static int knet_cmd_logout(struct knet_vty *vty);
static int knet_cmd_who(struct knet_vty *vty);

vty_node_cmds_t root_cmds[] = {
	{ "configure", "enter configuration mode", NULL, NULL, CMDS_PARAM_NO, knet_cmd_config },
	{ "exit", "exit from CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_logout },
	{ "help", "display basic help", NULL, NULL, CMDS_PARAM_NO, knet_cmd_help },
	{ "login", "exit from CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_logout },
	{ "logout", "exit from CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_logout },
	{ "who", "display users connected to CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_who },
	{ NULL, NULL, NULL, NULL, CMDS_PARAM_NO, NULL },
};

vty_node_opts_t interface_opts[] = {
	{ "NAME", "interface name (eg. kronosnet0)", NULL, 0, NULL },
	{ NULL, NULL, NULL, 0, NULL },
};

vty_node_cmds_t no_config_cmds[] = {
	{ "interface", "destroy kronosnet interface", NULL, NULL, CMDS_PARAM_KNET, knet_cmd_no_interface },
	{ NULL, NULL, NULL, NULL, CMDS_PARAM_NO, NULL },
};

vty_node_cmds_t config_cmds[] = {
	{ "exit", "exit configuration mode", NULL, NULL, CMDS_PARAM_NO, knet_cmd_exit_node },
	{ "interface", "configure kronosnet interface", NULL, NULL, CMDS_PARAM_KNET, knet_cmd_interface },
	{ "help", "display basic help", NULL, NULL, CMDS_PARAM_NO, knet_cmd_help },
	{ "logout", "exit from CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_logout },
	{ "no", "revert command", NULL, NULL, CMDS_PARAM_NO, NULL },
	{ "who", "display users connected to CLI", NULL, NULL, CMDS_PARAM_NO, knet_cmd_who },
	{ NULL, NULL, NULL, NULL, CMDS_PARAM_NO, NULL },
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

static int knet_vty_get_n_word_from_end(struct knet_vty *vty, int n, char **word, int *wlen)
{
	int widx;
	int idx, end, start;

	for (widx = 0; widx < n; widx++) {
		for (idx = vty->line_idx - 1; idx > 0; idx--) {
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

static int get_command(struct knet_vty *vty, char **cmd, int *cmdlen, int *no)
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

	*cmdlen = idx - start;

	return 0;
}

static const vty_node_cmds_t *get_cmds(struct knet_vty *vty, char **cmd, int *cmdlen)
{
	int no;
	const vty_node_cmds_t *cmds =  knet_vty_nodes[vty->node].cmds;

	get_command(vty, cmd, cmdlen, &no);

	if (no)
		cmds = knet_vty_nodes[vty->node].no_cmds;

	return cmds;
}

static int check_param(struct knet_vty *vty, const int paramtype, char *param, int paramlen)
{
	int err = 0;

	switch(paramtype) {
		case CMDS_PARAM_KNET:
			if (paramlen >= IFNAMSIZ) {
				knet_vty_write(vty, "interface name too long%s", telnet_newline);
				err = -1;
			}
			break;
		case CMDS_PARAM_IP:
			break;
		case CMDS_PARAM_BOOL:
			break;
		case CMDS_PARAM_INT:
			break;
		case CMDS_PARAM_SHORT:
			break;
		case CMDS_PARAM_STR:
			break;
		default: /* this should never happen */
			knet_vty_write(vty, "CLI ERRROR: unknown parameter type%s", telnet_newline);
			err = -1;
			break;
	}
	return err;
}

static void describe_param(struct knet_vty *vty, const int paramtype)
{
	switch(paramtype) {
		case CMDS_PARAM_KNET:
			knet_vty_write(vty, "KNET_IFACE_NAME - interface name (max %d chars) eg: kronosnet0%s", IFNAMSIZ, telnet_newline);
			break;
		case CMDS_PARAM_IP:
			break;
		case CMDS_PARAM_BOOL:
			break;
		case CMDS_PARAM_INT:
			break;
		case CMDS_PARAM_SHORT:
			break;
		case CMDS_PARAM_STR:
			break;
		default: /* this should never happen */
			knet_vty_write(vty, "CLI ERRROR: unknown parameter type%s", telnet_newline);
			break;
	}
}

/*
 * -1 command not found or error
 *  0 exact command found
 *  > 0 number of commands (-1)
 */
static int match_command(struct knet_vty *vty, const vty_node_cmds_t *cmds,
			 char *cmd, int cmdlen, int mode)
{
	int idx = 0, found = -1, wlen;
	char *word;
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
				if (cmds[matches[0]].param != CMDS_PARAM_NO) {
					knet_vty_get_n_word_from_end(vty, 1, &word, &wlen);
					if (strncmp(word, cmd, wlen)) {
						check_param(vty, cmds[matches[0]].param, word, wlen);
					} else {
						describe_param(vty, cmds[matches[0]].param);
					}
					break;
				}
			}
			if (found >= 0) {
				idx = 0;
				while (matches[idx] >= 0) {
					knet_vty_print_help(vty, cmds, matches[idx]);
					idx++;
				}
			}
			break;
		case KNET_VTY_MATCH_EXEC:
			if (found == 0) {
				int exec = 0;
				if (cmds[matches[0]].param != CMDS_PARAM_NO) {
					knet_vty_get_n_word_from_end(vty, 1, &word, &wlen);
					if (strncmp(word, cmd, wlen)) {
						exec = check_param(vty, cmds[matches[0]].param, word, wlen);
					} else {
						exec = -1;
						describe_param(vty, cmds[matches[0]].param);
						knet_vty_write(vty, "Parameter required for this command%s", telnet_newline);
					}
				}
				if (!exec) {
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
				int do_complete = 1;
				if (vty->cursor_pos > cmdlen)
					break;

				if (cmds[matches[0]].param != CMDS_PARAM_NO) {
					knet_vty_get_n_word_from_end(vty, 1, &word, &wlen);
					if (strncmp(word, cmd, wlen)) {
						do_complete=0;
					}
				}

				if (do_complete) {
					int cmdreallen = strlen(cmds[matches[0]].cmd);
					memset(vty->line, 0, sizeof(vty->line));
					memcpy(vty->line, cmds[matches[0]].cmd, cmdreallen);
					vty->line[cmdreallen] = ' ';
					vty->line_idx = cmdreallen + 1;
					vty->cursor_pos = cmdreallen + 1;
				}
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

void knet_vty_execute_cmd(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;

	if (knet_vty_is_line_empty(vty))
		return;

	cmds = get_cmds(vty, &cmd, &cmdlen);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	match_command(vty, cmds, cmd, cmdlen, KNET_VTY_MATCH_EXEC);
}

void knet_vty_help(struct knet_vty *vty)
{
	int idx = 0;
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;

	cmds = get_cmds(vty, &cmd, &cmdlen);

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

	match_command(vty, cmds, cmd, cmdlen, KNET_VTY_MATCH_HELP);
}

void knet_vty_tab_completion(struct knet_vty *vty)
{
	const vty_node_cmds_t *cmds = NULL;
	char *cmd = NULL;
	int cmdlen = 0;

	if (knet_vty_is_line_empty(vty))
		return;

	knet_vty_write(vty, "%s", telnet_newline);

	cmds = get_cmds(vty, &cmd, &cmdlen);

	/* this will eventually disappear. keep it as safeguard for now */
	if (cmds == NULL) {
		knet_vty_write(vty, "No commands associated to this node%s", telnet_newline);
		return;
	}

	match_command(vty, cmds, cmd, cmdlen, KNET_VTY_MATCH_EXPAND);

	knet_vty_prompt(vty);
	knet_vty_write(vty, "%s", vty->line);
}
