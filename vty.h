#ifndef __VTY_H__
#define __VTY_H__

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#define KNET_VTY_DEFAULT_PORT		50000

#define KNET_VTY_DEFAULT_MAX_CONN	4
#define KNET_VTY_TOTAL_MAX_CONN		16

struct knet_vty {
	pthread_t		vty_thread;
	struct sockaddr_storage	src_sa;
	socklen_t		src_sa_len;
	char			username[64];
	int			user_can_enable;
	int			vty_sock;
	int			conn_num;
	int			active;
	int			got_epipe;
};

int knet_vty_main_loop(const char *configfile, const char *ip_addr,
		       const char *port);

int knet_vty_init_listener(const char *address, const char *port);
void knet_vty_close_listener(int listener_fd);

int knet_vty_set_max_connections(const int max_connections);

#endif
