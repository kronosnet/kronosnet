/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>

#include "test-common.h"

char testipv4_1[IPBUFSIZE];
char testipv4_2[IPBUFSIZE];
char testipv6_1[IPBUFSIZE];
char testipv6_2[IPBUFSIZE];

static int check_knet_up_down(void)
{
	char verifycmd[1024];
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	int err=0;
	nozzle_t nozzle;
	char *error_string = NULL;

	printf("Testing interface up/down\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to set interface up\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", nozzle->name);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err < 0) {
		printf("Unable to verify inteface UP\n");
		err = -1;
		goto out_clean;
	}

	printf("Put the interface down\n");

	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q UP", nozzle->name);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q UP", nozzle->name);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify inteface DOWN\n");
		err = -1;
		goto out_clean;
	}

	nozzle_close(nozzle);

	printf("Testing interface pre-up/up/down/post-down (exec errors)\n");

	memset(device_name, 0, size);
	nozzle = nozzle_open(device_name, size, ABSBUILDDIR "/nozzle_updown_bad");
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_PREUP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("preup output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to put the interface up\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_UP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("up output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	printf("Put the interface down\n");

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_DOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("down output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_POSTDOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("postdown output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	nozzle_close(nozzle);

	printf("Testing interface pre-up/up/down/post-down\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, ABSBUILDDIR "/nozzle_updown_good");
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Put the interface up\n");

	err = nozzle_run_updown(nozzle, NOZZLE_PREUP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_PREUP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("preup output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_up(nozzle);
	if (err < 0) {
		printf("Unable to put the interface up\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_UP, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_UP error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("up output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	printf("Put the interface down\n");

	err = nozzle_run_updown(nozzle, NOZZLE_DOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_DOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("down output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	err = nozzle_set_down(nozzle);
	if (err < 0) {
		printf("Unable to put the interface down\n");
		err = -1;
		goto out_clean;
	}
	err = nozzle_run_updown(nozzle, NOZZLE_POSTDOWN, &error_string);
	if (err) {
		printf("nozzle_run_updown NOZZLE_POSTDOWN error: %s\n", strerror(errno));
	}
	if (error_string) {
		printf("postdown output: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}

	nozzle_close(nozzle);

	printf("Test ERROR conditions\n");

	printf("Pass NULL to nozzle set_up\n");
	err = 0;
	errno = 0;
	if ((nozzle_set_up(NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_up sanity checks\n");
		err = -1;
		goto out_clean;
	}

	printf("Pass NULL to nozzle set_down\n");
	errno = 0;
	if ((nozzle_set_down(NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_set_down sanity checks\n");
		err = -1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

static int check_knet_set_del_ip(void)
{
	char device_name[IFNAMSIZ];
	size_t size = IFNAMSIZ;
	char verifycmd[2048];
	int err = 0;
	nozzle_t nozzle;
	struct nozzle_ip *ip_list = NULL, *ip_list_tmp = NULL;
	int ip_list_entries = 0;
	char *error_string = NULL;

	printf("Testing interface add/remove ip\n");

	memset(device_name, 0, size);

	nozzle = nozzle_open(device_name, size, NULL);
	if (!nozzle) {
		printf("Unable to init %s\n", device_name);
		return -1;
	}

	printf("Adding ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/24\n", testipv4_2);

	err = nozzle_add_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding duplicate ip: %s/24\n", testipv4_1);

	err = nozzle_add_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to find IP address in libnozzle db\n");
		err=-1;
		goto out_clean;
	}

	printf("Checking ip: %s/24\n", testipv4_1);

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Get ip list from libnozzle:\n");

	if (nozzle_get_ips(nozzle, &ip_list) < 0) {
		printf("Not enough mem?\n");
		err=-1;
		goto out_clean;
	}

	ip_list_tmp = ip_list;
	ip_list_entries = 0;

	while(ip_list_tmp) {
		ip_list_entries++;
		printf("Found IP %s %s in libnozzle db\n", ip_list_tmp->ipaddr, ip_list_tmp->prefix);
		ip_list_tmp = ip_list_tmp->next;
	}

	if (ip_list_entries != 2) {
		printf("Didn't get enough ip back from libnozzle?\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_1);

	err = nozzle_del_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/24\n", testipv4_2);

	err = nozzle_del_ip(nozzle, testipv4_2, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting again ip: %s/24\n", testipv4_1);

	err = nozzle_del_ip(nozzle, testipv4_1, "24");
	if (err < 0) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/24", nozzle->name, testipv4_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv4_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Adding ip: %s/64\n", testipv6_1);

	err = nozzle_add_ip(nozzle, testipv6_1, "64");
	if (err < 0) {
		printf("Unable to assign IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

	printf("Deleting ip: %s/64\n", testipv6_1);

	err = nozzle_del_ip(nozzle, testipv6_1, "64");
	if (err) {
		printf("Unable to delete IP address\n");
		err=-1;
		goto out_clean;
	}

	memset(verifycmd, 0, sizeof(verifycmd));
	snprintf(verifycmd, sizeof(verifycmd)-1,
#ifdef KNET_LINUX
		 "ip addr show dev %s | grep -q %s/64", nozzle->name, testipv6_1);
#endif
#ifdef KNET_BSD
		 "ifconfig %s | grep -q %s", nozzle->name, testipv6_1);
#endif
	err = execute_bin_sh_command(verifycmd, &error_string);
	if (error_string) {
		printf("Error string: %s\n", error_string);
		free(error_string);
		error_string = NULL;
	}
	if (!err) {
		printf("Unable to verify IP address\n");
		err=-1;
		goto out_clean;
	}

out_clean:
	nozzle_close(nozzle);

	return err;
}

int main(void)
{
	need_root();

	make_local_ips(testipv4_1, testipv4_2, testipv6_1, testipv6_2);

	if (check_knet_up_down() < 0)
		return -1;

	if (check_knet_set_del_ip() < 0)
		return -1;

	return 0;
}
