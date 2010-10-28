#ifndef __VTY_H__
#define __VTY_H__

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#define KNET_VTY_DEFAULT_PORT		50000

#define KNET_VTY_DEFAULT_MAX_CONN	4
#define KNET_VTY_TOTAL_MAX_CONN		16
#define KNET_VTY_CLI_TIMEOUT		60

#define KNET_VTY_MAX_LINE		512

#define KNET_VTY_MAX_HIST		50

struct knet_vty {
	pthread_t		vty_thread;	/* thread struct for this vty */
	struct sockaddr_storage	src_sa;		/* source IP */
	socklen_t		src_sa_len;	/* sa len */
	char			username[64];	/* username */
	char			line[KNET_VTY_MAX_LINE]; /* input line */
	char			*history[KNET_VTY_MAX_HIST]; /* history */
	int			history_idx;	/* index to history */
	int			history_pos;	/* position in the history */
	int			insert_mode;	/* add or insert */
	int			line_idx;	/* index on the input line */
	int			cursor_pos;	/* position of the cursor in the line */
	int			escape;		/* escape status */
	int			escape_code;	/* escape code buffer */
	int			user_can_enable;/* user is in group kronosnetadm */
	int			vty_sock;	/* tcp socket for this vty */
	int			conn_num;	/* vty number */
	int			active;		/* vty is active */
	int			got_epipe;	/* vty_sock has been closed */
	int			idle;		/* idle time */
	int			disable_idle;	/* disable automatic logout */
};

int knet_vty_main_loop(const char *configfile, const char *ip_addr,
		       const char *port);

int knet_vty_init_listener(const char *address, const char *port);
void knet_vty_close_listener(int listener_fd);

int knet_vty_set_max_connections(const int max_connections);

#endif
