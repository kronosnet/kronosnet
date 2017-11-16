/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LIBNOZZLE_H__
#define __LIBNOZZLE_H__

#include <sys/types.h>
#include <net/if.h>

/**
 *
 * @file libnozzle.h
 * @brief tap interfaces management API include file
 * @copyright Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * nozzle is a commodity library to manage tap (ethernet) interfaces
 */

typedef struct nozzle_iface *nozzle_t;

nozzle_t nozzle_open(char *dev, size_t dev_size, const char *updownpath);
int nozzle_close(nozzle_t tap);

nozzle_t nozzle_find(char *dev, size_t dev_size);

int nozzle_get_fd(const nozzle_t tap);

const char *nozzle_get_name(const nozzle_t tap);

int nozzle_get_mtu(const nozzle_t tap);
int nozzle_set_mtu(nozzle_t tap, const int mtu);
int nozzle_reset_mtu(nozzle_t tap);

int nozzle_get_mac(const nozzle_t tap, char **ether_addr);
int nozzle_set_mac(nozzle_t tap, const char *ether_addr);
int nozzle_reset_mac(nozzle_t tap);

int nozzle_set_up(nozzle_t tap, char **error_preup, char **error_up);
int nozzle_set_down(nozzle_t tap, char **error_down, char **error_postdown);

int nozzle_add_ip(nozzle_t tap, const char *ip_addr, const char *prefix, char **error_string);
int nozzle_del_ip(nozzle_t tap, const char *ip_addr, const char *prefix, char **error_string);
int nozzle_get_ips(const nozzle_t tap, char **ip_addr_list, int *entries);

#endif
