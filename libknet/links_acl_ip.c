/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "logging.h"
#include "transports.h"
#include "links_acl.h"
#include "links_acl_ip.h"

struct ip_acl_match_entry {
	check_type_t type;
	check_acceptreject_t acceptreject;
	struct sockaddr_storage addr1; /* Actual IP address, mask top or low IP */
	struct sockaddr_storage addr2; /* high IP address or address bitmask */
	struct ip_acl_match_entry *next;
};

/*
 * s6_addr32 is not defined in BSD userland, only kernel.
 * definition is the same as linux and it works fine for
 * what we need.
 */
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

/*
 * IPv4 See if the address we have matches the current match entry
 */

static int ip_matches_v4(struct sockaddr_storage *checkip, struct ip_acl_match_entry *match_entry)
{
	struct sockaddr_in *ip_to_check;
	struct sockaddr_in *match1;
	struct sockaddr_in *match2;

	ip_to_check = (struct sockaddr_in *)checkip;
	match1 = (struct sockaddr_in *)&match_entry->addr1;
	match2 = (struct sockaddr_in *)&match_entry->addr2;

	switch(match_entry->type) {
	case CHECK_TYPE_ADDRESS:
		if (ip_to_check->sin_addr.s_addr == match1->sin_addr.s_addr)
			return 1;
		break;
	case CHECK_TYPE_MASK:
		if ((ip_to_check->sin_addr.s_addr & match2->sin_addr.s_addr) ==
		    match1->sin_addr.s_addr)
			return 1;
		break;
	case CHECK_TYPE_RANGE:
		if ((ntohl(ip_to_check->sin_addr.s_addr) >= ntohl(match1->sin_addr.s_addr)) &&
		    (ntohl(ip_to_check->sin_addr.s_addr) <= ntohl(match2->sin_addr.s_addr)))
			return 1;
		break;

	}
	return 0;
}

/*
 * Compare two IPv6 addresses
 */

static int ip6addr_cmp(struct in6_addr *a, struct in6_addr *b)
{
	uint64_t a_high, a_low;
	uint64_t b_high, b_low;

	a_high = ((uint64_t)htonl(a->s6_addr32[0]) << 32) | (uint64_t)htonl(a->s6_addr32[1]);
	a_low  = ((uint64_t)htonl(a->s6_addr32[2]) << 32) | (uint64_t)htonl(a->s6_addr32[3]);

	b_high = ((uint64_t)htonl(b->s6_addr32[0]) << 32) | (uint64_t)htonl(b->s6_addr32[1]);
	b_low  = ((uint64_t)htonl(b->s6_addr32[2]) << 32) | (uint64_t)htonl(b->s6_addr32[3]);

	if (a_high > b_high)
		return 1;
	if (a_high < b_high)
		return -1;

	if (a_low > b_low)
		return 1;
	if (a_low < b_low)
		return -1;

	return 0;
}

/*
 * IPv6 See if the address we have matches the current match entry
 */

static int ip_matches_v6(struct sockaddr_storage *checkip, struct ip_acl_match_entry *match_entry)
{
	struct sockaddr_in6 *ip_to_check;
	struct sockaddr_in6 *match1;
	struct sockaddr_in6 *match2;
	int i;

	ip_to_check = (struct sockaddr_in6 *)checkip;
	match1 = (struct sockaddr_in6 *)&match_entry->addr1;
	match2 = (struct sockaddr_in6 *)&match_entry->addr2;

	switch(match_entry->type) {
	case CHECK_TYPE_ADDRESS:
		if (!memcmp(ip_to_check->sin6_addr.s6_addr32, match1->sin6_addr.s6_addr32, sizeof(struct in6_addr)))
			return 1;
		break;

	case CHECK_TYPE_MASK:
		/*
		 * Note that this little loop will quit early if there is a non-match so the
		 * comparison might look backwards compared to the IPv4 one
		 */
		for (i=sizeof(struct in6_addr)/4-1; i>=0; i--) {
			if ((ip_to_check->sin6_addr.s6_addr32[i] & match2->sin6_addr.s6_addr32[i]) !=
			    match1->sin6_addr.s6_addr32[i])
				return 0;
		}
		return 1;
	case CHECK_TYPE_RANGE:
		if ((ip6addr_cmp(&ip_to_check->sin6_addr, &match1->sin6_addr) >= 0) &&
		    (ip6addr_cmp(&ip_to_check->sin6_addr, &match2->sin6_addr) <= 0))
			return 1;
		break;
	}
	return 0;
}


int ipcheck_validate(void *fd_tracker_match_entry_head, struct sockaddr_storage *checkip)
{
	struct ip_acl_match_entry **match_entry_head = (struct ip_acl_match_entry **)fd_tracker_match_entry_head;
	struct ip_acl_match_entry *match_entry = *match_entry_head;
	int (*match_fn)(struct sockaddr_storage *checkip, struct ip_acl_match_entry *match_entry);

	if (checkip->ss_family == AF_INET){
		match_fn = ip_matches_v4;
	} else {
		match_fn = ip_matches_v6;
	}

	while (match_entry) {
		if (match_fn(checkip, match_entry)) {
			if (match_entry->acceptreject == CHECK_ACCEPT)
				return 1;
			else
				return 0;
		}
		match_entry = match_entry->next;
	}
	return 0; /* Default reject */
}

/*
 * Routines to manuipulate access lists
 */

void ipcheck_rmall(void *fd_tracker_match_entry_head)
{
	struct ip_acl_match_entry **match_entry_head = (struct ip_acl_match_entry **)fd_tracker_match_entry_head;
	struct ip_acl_match_entry *next_match_entry;
	struct ip_acl_match_entry *match_entry = *match_entry_head;

	while (match_entry) {
		next_match_entry = match_entry->next;
		free(match_entry);
		match_entry = next_match_entry;
	}
	*match_entry_head = NULL;
}

static struct ip_acl_match_entry *ipcheck_findmatch(struct ip_acl_match_entry **match_entry_head,
						 struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
						 check_type_t type, check_acceptreject_t acceptreject)
{
	struct ip_acl_match_entry *match_entry = *match_entry_head;

	while (match_entry) {
		if ((!memcmp(&match_entry->addr1, ss1, sizeof(struct sockaddr_storage))) &&
		    (!memcmp(&match_entry->addr2, ss2, sizeof(struct sockaddr_storage))) &&
		    (match_entry->type == type) &&
		    (match_entry->acceptreject == acceptreject)) {
			return match_entry;
		}
		match_entry = match_entry->next;
	}

	return NULL;
}

int ipcheck_rmip(void *fd_tracker_match_entry_head,
		 struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		 check_type_t type, check_acceptreject_t acceptreject)
{
	struct ip_acl_match_entry **match_entry_head = (struct ip_acl_match_entry **)fd_tracker_match_entry_head;
	struct ip_acl_match_entry *next_match_entry = NULL;
	struct ip_acl_match_entry *rm_match_entry;
	struct ip_acl_match_entry *match_entry = *match_entry_head;

	rm_match_entry = ipcheck_findmatch(match_entry_head, ss1, ss2, type, acceptreject);
	if (!rm_match_entry) {
		errno = ENOENT;
		return -1;
	}

	while (match_entry) {
		next_match_entry = match_entry->next;
		/*
		 * we are removing the list head, be careful
		 */
		if (rm_match_entry == match_entry) {
			*match_entry_head = next_match_entry;
			free(match_entry);
			break;
		}
		/*
		 * the next one is the one we need to remove
		 */
		if (rm_match_entry == next_match_entry) {
			match_entry->next = next_match_entry->next;
			free(next_match_entry);
			break;
		}
		match_entry = next_match_entry;
	}

	return 0;
}

int ipcheck_addip(void *fd_tracker_match_entry_head, int index,
		  struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		  check_type_t type, check_acceptreject_t acceptreject)
{
	struct ip_acl_match_entry **match_entry_head = (struct ip_acl_match_entry **)fd_tracker_match_entry_head;
	struct ip_acl_match_entry *new_match_entry;
	struct ip_acl_match_entry *match_entry = *match_entry_head;
	int i = 0;

	if (ipcheck_findmatch(match_entry_head, ss1, ss2, type, acceptreject) != NULL) {
		errno = EEXIST;
		return -1;
	}

	new_match_entry = malloc(sizeof(struct ip_acl_match_entry));
	if (!new_match_entry) {
		return -1;
	}

	memmove(&new_match_entry->addr1, ss1, sizeof(struct sockaddr_storage));
	memmove(&new_match_entry->addr2, ss2, sizeof(struct sockaddr_storage));
	new_match_entry->type = type;
	new_match_entry->acceptreject = acceptreject;
	new_match_entry->next = NULL;

	if (match_entry) {
		/*
		 * special case for index 0, since we need to update
		 * the head of the list
		 */
		if (index == 0) {
			*match_entry_head = new_match_entry;
			new_match_entry->next = match_entry;
		} else {
			/*
			 * find the end of the list or stop at "index"
			 */
			while ((match_entry->next) || (i < index)) {
				match_entry = match_entry->next;
				i++;
			}
			/*
			 * insert if there are more entries in the list
			 */
			if (match_entry->next) {
				new_match_entry->next = match_entry->next;
			}
			/*
			 * add if we are at the end
			 */
			match_entry->next = new_match_entry;
		}
	} else {
		/*
		 * first entry in the list
		 */
		*match_entry_head = new_match_entry;
	}

	return 0;
}
