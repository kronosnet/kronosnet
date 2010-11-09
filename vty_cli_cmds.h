#ifndef __VTY_CLI_CMDS_H__
#define __VTY_CLI_CMDS_H__

#include "vty.h"

typedef struct {
	const char	*option;
	const char	*help;
	const char	*requires;
	const int	optional;
	const void	*next_opts;
} vty_node_opts_t;

typedef struct {
	const char		*cmd;
	const char		*help;
	const char		*requires;
	const vty_node_opts_t	*opts;
	int (*func) (struct knet_vty *vty);
} vty_node_cmds_t;

typedef struct {
	const int		node_num;
	const char		*prompt;
	const vty_node_cmds_t	*cmds;
	const vty_node_cmds_t	*no_cmds;
} vty_nodes_t;

enum vty_nodes {
	NODE_ROOT = 0,
	NODE_CONFIG,
	NODE_INTERFACE,
};

void knet_vty_execute_cmd(struct knet_vty *vty);
void knet_vty_help(struct knet_vty *vty);
void knet_vty_tab_completion(struct knet_vty *vty);

extern vty_nodes_t knet_vty_nodes[];

#endif
