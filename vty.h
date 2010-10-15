#ifndef __VTY_H__
#define __VTY_H__

#define KNET_VTY_DEFAULT_PORT	50000

int knet_vty_init_listener(const char *address, unsigned short port);

#endif
