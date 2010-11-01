#include <config.h>

#include "utils.h"
#include "vty.h"
#include "vty_cli.h"
#include "vty_cli_cmds.h"
#include "vty_utils.h"

/* forward declarations */

static int knet_cmd_who(struct knet_vty *vty);
static int knet_cmd_help(struct knet_vty *vty);

enum vty_nodes {
	ROOT = 0,
	CONFIG,
};

vty_node_cmds_t root_cmds[] = {
	{ "who", "Display users connected to CLI", NULL, NULL, knet_cmd_who },
	{ "help", "Display basic help", NULL, NULL, knet_cmd_help },
	{ "show", "Show several information", NULL, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL },
};

vty_nodes_t knet_vty_nodes[] = {
	{ ROOT, "knet", root_cmds },
	{ CONFIG, "config", NULL },
	{ -1, NULL, NULL },
};

static int knet_cmd_who(struct knet_vty *vty)
{
	int conn_index;

	pthread_mutex_lock(&knet_vty_mutex);

	for(conn_index = 0; conn_index < KNET_VTY_TOTAL_MAX_CONN; conn_index++) {
		if (knet_vtys[conn_index].active) {
			knet_vty_write(vty, " User: %s on vty(%d) from %s%s",
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

static char *get_first_word(struct knet_vty *vty)
{
	int start = 0, idx;

	for (idx = 0; idx < vty->line_idx; idx++) {
		if (vty->line[idx] != ' ')
			break;
	}
	start = idx;
	if (start == vty->line_idx)
		return NULL;

	for (idx = start; idx < vty->line_idx; idx++) {
		if (vty->line[idx] == ' ')
			break;
	}
	vty->line[idx] = 0;

	return &vty->line[start];
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

	cmd = get_first_word(vty);
	len = strlen(cmd);

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

void knet_vty_help(struct knet_vty *vty)
{
	int idx = 0;

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
