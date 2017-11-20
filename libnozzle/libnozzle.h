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
 * error_down - pointers to string to record errors from executing down.d
 *              when configured. The string is malloc'ed, the caller needs to free those
 *              buffers.
 *
 * error_postdown - pointers to string to record errors from executing post-down.d
 *                  when configured. The string is malloc'ed, the caller needs to free
 *                  those buffers.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * error_down / error_postdown are set to NULL if execution of external scripts
 * is sucessful
 * error_down / error_postdown will contain strings recording the execution error.
 */

int nozzle_close(nozzle_t nozzle, char **error_down, char **error_postdown);

/**
 * nozzle_set_up
 * @brief equivalent of ifconfig up, executes pre-up.d up.d if configured
 *
 * nozzle - pointer to the nozzle struct
 *
 * error_preup - pointer to string pointer to record errors from executing pre-up.d
 *               when configured. The string is malloc'ed, the caller needs to free that
 *               buffer.
 *
 * error_up - pointer to string pointer to record errors from executing up.d
 *            when configured. The string is malloc'ed, the caller needs to free that
 *            buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * error_preup / error_up are set to NULL if execution of external scripts
 * is sucessful
 * error_preup / error_up will contain strings recording the execution error.
 */

int nozzle_set_up(nozzle_t nozzle, char **error_preup, char **error_up);

/**
 * nozzle_set_down
 * @brief equivalent of ifconfig down, executes down.d post-down.d
 *
 * nozzle - pointer to the nozzle struct
 *
 * error_down - pointer to a string pointer to record errors from executing down.d
 *              when configured. The string is malloc'ed, the caller needs to free that
 *              buffer.
 *
 * error_postdown - pointer to a string pointer to record errors from executing post-down.d
 *                  when configured. The string is malloc'ed, the caller needs to free
 *                  that buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * error_down / error_postdown are set to NULL if execution of external scripts
 * is sucessful
 * error_down / error_postdown will contain strings recording the execution error.
 */

int nozzle_set_down(nozzle_t nozzle, char **error_down, char **error_postdown);

/**
 * nozzle_add_ip
 * @brief equivalent of ip addr or ifconfig <ipaddress/prefix>
 *
 * nozzle - pointer to the nozzle struct
 *
 * ip_addr - string containing either an IPv4 or an IPv6 address.
 *           Please note that Linux will automatically remove any IPv6 addresses from an interface
 *           with MTU < 1280. libnozzle will cache those IPs and re-instate them when MTU is > 1280.
 *           MTU must be set via nozzle_set_mtu for IPv6 to be re-instated.
 *
 * prefix - 24, 64 or any valid network prefix for the requested address.
 *
 * error_string - pointers to string to record errors from ipaddr2 (Linux) or ifconfig (BSD).
 *                The string is malloc'ed, the caller needs to free this buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 *  error_string is set to NULL on success
 *  error_string will contain a string recording the execution error.
 */

int nozzle_add_ip(nozzle_t nozzle, const char *ip_addr, const char *prefix, char **error_string);

/**
 * nozzle_del_ip
 * @brief equivalent of ip addr del or ifconfig del <ipaddress/prefix>
 *
 * nozzle - pointer to the nozzle struct
 *
 * ip_addr - string containing either an IPv4 or an IPv6 address.
 *
 * prefix - 24, 64 or any valid network prefix for the requested address.
 *
 * error_string - pointers to string to record errors from ipaddr2 (Linux) or ifconfig (BSD).
 *                The string is malloc'ed, the caller needs to free this buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 *  error_string is set to NULL on success
 *  error_string will contain a string recording the execution error.
 */

int nozzle_del_ip(nozzle_t nozzle, const char *ip_addr, const char *prefix, char **error_string);

/**
 * nozzle_get_ips
 * @brief retrive the list of all configured ips for a given interface
 *
 * TODO: change to use a ip_addr_list struct!
 *
 * nozzle - pointer to the nozzle struct
 *
 * ip_addr_list - list of strings containing either an IPv4 or an IPv6 address and their prefixes.
 *
 * entries - entries recorded.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * ip_addr_list is a malloc'ed buffer that the user needs to parse and free after use. ip_addr_list can
 * be NULL if entries is 0.
 *
 */

int nozzle_get_ips(const nozzle_t nozzle, char **ip_addr_list, int *entries);

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
 * error_string - pointer to string to record errors from ipaddr2 (Linux) or ifconfig (BSD)
 *                when re-instanting IPv6 address if MTU is becoming again > 1280.
 *                The string is malloc'ed, the caller needs to free this buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * error_string is set to NULL on success
 * error_string will contain a string recording the execution error.
 */

int nozzle_set_mtu(nozzle_t nozzle, const int mtu, char **error_string);

/**
 * nozzle_reset_mtu
 * @brief reset mtu on a given nozzle interface to the system default
 *
 * nozzle - pointer to the nozzle struct
 *
 * error_string - pointer to string to record errors from ipaddr2 (Linux) or ifconfig (BSD)
 *                when re-instanting IPv6 address if MTU is becoming again > 1280.
 *                The string is malloc'ed, the caller needs to free this buffer.
 *
 * @return
 * 0 on success
 * -1 on error and errno is set.
 * error_string is set to NULL on success
 * error_string will contain a string recording the execution error.
 */

int nozzle_reset_mtu(nozzle_t nozzle, char **error_string);

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
 * @brief fine a nozzle handle by device name
 *
 * devname - string containing the name of the interface
 *
 * @return
 * handle on success.
 * NULL on error and errno is set.
 */

nozzle_t nozzle_get_handle_by_name(char *devname);

/**
 * nozzle_get_name_by_handle
 * @brief fine a nozzle handle by device name
 *
 * nozzle - pointer to the nozzle struct
 *
 * @return
 * pointer to the interface name
 * NULL on error and errno is set.
 */

const char *nozzle_get_name_by_handle(const nozzle_t nozzle);

int nozzle_get_fd(const nozzle_t nozzle);

#endif
