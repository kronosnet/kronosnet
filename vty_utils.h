#ifndef __VTY_UTILS_H__
#define __VTY_UTILS_H__

#define VTY_MAX_BUFFER_SIZE	4096

int knet_vty_write(int vty_sock, const char *format, ...)
		   __attribute__ ((__format__ (__printf__, 2, 3)));

int knet_vty_read(int vty_sock, unsigned char *buf, size_t bufsize);

int knet_vty_set_echo(int vty_sock, int on);

void knet_vty_print_banner(int vty_sock);

#endif
