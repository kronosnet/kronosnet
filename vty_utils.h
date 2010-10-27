#ifndef __VTY_UTILS_H__
#define __VTY_UTILS_H__

#include "vty.h"

#define VTY_MAX_BUFFER_SIZE	4096

int knet_vty_write(struct knet_vty *vty, const char *format, ...)
		   __attribute__ ((__format__ (__printf__, 2, 3)));

int knet_vty_read(struct knet_vty *vty, unsigned char *buf, size_t bufsize);

int knet_vty_set_echo(struct knet_vty *vty, int on);

void knet_vty_print_banner(struct knet_vty *vty);

int knet_vty_set_iacs(struct knet_vty *vty);

#endif
