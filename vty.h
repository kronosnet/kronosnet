#ifndef __VTY_H__
#define __VTY_H__

#define KNET_VTY_DEFAULT_PORT	50000

int knet_vty_init_listener(const char *address, unsigned short port);
void knet_vty_close_listener(int listener_fd);

#endif
