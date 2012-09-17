#ifndef __VTY_AUTH_H__
#define __VTY_AUTH_H__

#include "vty.h"

#define AUTH_MAX_RETRY 3

int knet_vty_auth_user(struct knet_vty *vty, const char *user);

#endif
