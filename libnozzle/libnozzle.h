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
 * @copyright Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * nozzle is a commodity library to manage tap (ethernet) interfaces
 */

typedef struct nozzle_iface *nozzle_t;

/**
 * nozzle_open
 * @brief create a new tap device on the system.
 *
 * devname - pointer to device name of at least size IFNAMSIZ.
 *           if the dev strlen is 0, then the system will assign a name automatically.
 *           if a string is specified, the system will try to create a device with
 *           the specified name.
 *           NOTE: on FreeBSD the tap device names can only be tapX where X is a
 *           number from 0 to 255. On Linux such limitation does not apply.
 *           The name must be unique to the system. If an interface with the same
 *           name is already configured on the system, an error will be returned.
 *
 * devname_size - length of the buffer provided in dev (has to be at least IFNAMSIZ).
 *
 * updownpath - nozzle supports the typical filesystem structure to execute
 *              actions for: down.d  post-down.d  pre-up.d  up.d
 *              in the form of:
 *              updownpath/<action>/<interface_name>
 *              updownpath specifies where to find those directories on the
 *              filesystem and it must be an absolute path.
 *
 * @return
 * nozzle_open returns
 * a pointer to a nozzle struct on success
 * NULL on error and errno is set.
 */

nozzle_t nozzle_open(char *devname, size_t devname_size, const char *updownpath);

/**
 * nozzle_close
 * @brief deconfigure and destroy a nozzle device
 *
 * nozzle - pointer to the nozzle struct to destroy
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_close(nozzle_t nozzle);


#define NOZZLE_PREUP    0
#define NOZZLE_UP       1
#define NOZZLE_DOWN     2
#define NOZZLE_POSTDOWN 3

/**
 * nozzle_run_updown
 * @brief execute updown commands associated with a nozzle device. It is
 *        the application responsibility to call helper scripts
 *        before or after creating/destroying interfaces or IP addresses.
 *
 * nozzle - pointer to the nozzle struct
 *
 * action - pre-up.d / up.d / down.d / post-down.d (see defines above)
 *
 * exec_string - pointers to string to record executing action stdout/stderr.
 *               The string is malloc'ed, the caller needs to free the buffer.
 *               If the script generates no output this string might be NULL.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_run_updown(const nozzle_t nozzle, uint8_t action, char **exec_string);

/**
 * nozzle_set_up
 * @brief equivalent of ifconfig up
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_set_up(nozzle_t nozzle);

/**
 * nozzle_set_down
 * @brief equivalent of ifconfig down
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_set_down(nozzle_t nozzle);

/**
 * nozzle_add_ip
 * @brief equivalent of ip addr or ifconfig <ipaddress/prefix>
 *
 * nozzle - pointer to the nozzle struct
 *
 * ipaddr - string containing either an IPv4 or an IPv6 address.
 *           Please note that Linux will automatically remove any IPv6 addresses from an interface
 *           with MTU < 1280. libnozzle will cache those IPs and re-instate them when MTU is > 1280.
 *           MTU must be set via nozzle_set_mtu for IPv6 to be re-instated.
 *
 * prefix - 24, 64 or any valid network prefix for the requested address.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_add_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix);

/**
 * nozzle_del_ip
 * @brief equivalent of ip addr del or ifconfig del <ipaddress/prefix>
 *
 * nozzle - pointer to the nozzle struct
 *
 * ipaddr - string containing either an IPv4 or an IPv6 address.
 *
 * prefix - 24, 64 or any valid network prefix for the requested address.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_del_ip(nozzle_t nozzle, const char *ipaddr, const char *prefix);

/**
 * nozzle_get_ips
 * @brief retrive the list of all configured ips for a given interface
 *
 * TODO: change to use a ipaddr_list struct!
 *
 * nozzle - pointer to the nozzle struct
 *
 * ipaddr_list - list of strings containing either an IPv4 or an IPv6 address and their prefixes.
 *
 * entries - entries recorded.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * ipaddr_list is a malloc'ed buffer that the user needs to parse and free after use. ipaddr_list can
 * be NULL if entries is 0.
 *
 */

int nozzle_get_ips(const nozzle_t nozzle, char **ipaddr_list, int *entries);

/**
 * nozzle_get_mtu
 * @brief retrive mtu on a given nozzle interface
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * MTU on success
 * -1 on error and errno is set.
 */

int nozzle_get_mtu(const nozzle_t nozzle);

/**
 * nozzle_set_mtu
 * @brief set mtu on a given nozzle interface
 *
 * nozzle - pointer to the nozzle struct
 *
 * mtu - new MTU value
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_set_mtu(nozzle_t nozzle, const int mtu);

/**
 * nozzle_reset_mtu
 * @brief reset mtu on a given nozzle interface to the system default
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 */

int nozzle_reset_mtu(nozzle_t nozzle);

/**
 * nozzle_get_mac
 * @brief retrive mac address on a given nozzle interface
 *
 * nozzle - pointer to the nozzle struct
 *
 * ether_addr - pointers to string containing the current mac address.
 *              The string is malloc'ed, the caller needs to free this buffer.
 * @return
 * 0 on success.
 * -1 on error and errno is set.
 */

int nozzle_get_mac(const nozzle_t nozzle, char **ether_addr);

/**
 * nozzle_set_mac
 * @brief set mac address on a given nozzle interface
 *
 * nozzle - pointer to the nozzle struct
 *
 * ether_addr - pointers to string containing the new mac address.
 *
 * @return
 * 0 on success.
 * -1 on error and errno is set.
 */

int nozzle_set_mac(nozzle_t nozzle, const char *ether_addr);

/**
 * nozzle_reset_mac
 * @brief reset mac address on a given nozzle interface to system default
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * 0 on success.
 * -1 on error and errno is set.
 */

int nozzle_reset_mac(nozzle_t nozzle);

/**
 * nozzle_get_handle_by_name
 * @brief find a nozzle handle by device name
 *
 * devname - string containing the name of the interface
 *
 * @return
 * handle on success.
 * NULL on error and errno is set.
 */

nozzle_t nozzle_get_handle_by_name(const char *devname);

/**
 * nozzle_get_name_by_handle
 * @brief retrive nozzle interface name by handle
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * pointer to the interface name
 * NULL on error and errno is set.
 */

const char *nozzle_get_name_by_handle(const nozzle_t nozzle);

/**
 * nozzle_get_fd
 * @brief
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * fd associated to a given nozzle on success.
 * -1 on error and errno is set.
 */

int nozzle_get_fd(const nozzle_t nozzle);

#endif
