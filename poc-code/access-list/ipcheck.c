#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include "ipcheck.h"

struct ip_match_entry {
	ipcheck_type_t type;
	ipcheck_acceptreject_t acceptreject;
	struct sockaddr_storage addr1; /* Actual IP address, mask top or low IP */
	struct sockaddr_storage addr2; /* high IP address or address bitmask */
	struct ip_match_entry *next;
};


/* Lists of things to match against. These are dummy structs to provide a quick list head */
static struct ip_match_entry match_entry_head_v4;
static struct ip_match_entry match_entry_head_v6;

/*
 * IPv4 See if the address we have matches the current match entry
 *
 */
static int ip_matches_v4(struct sockaddr_storage *checkip, struct ip_match_entry *match_entry)
{
	struct sockaddr_in *ip_to_check;
	struct sockaddr_in *match1;
	struct sockaddr_in *match2;

	ip_to_check = (struct sockaddr_in *)checkip;
	match1 = (struct sockaddr_in *)&match_entry->addr1;
	match2 = (struct sockaddr_in *)&match_entry->addr2;

	switch(match_entry->type) {
	case IPCHECK_TYPE_ADDRESS:
		if (ip_to_check->sin_addr.s_addr == match1->sin_addr.s_addr)
			return 1;
		break;
	case IPCHECK_TYPE_MASK:
		if ((ip_to_check->sin_addr.s_addr & match2->sin_addr.s_addr) ==
		    match1->sin_addr.s_addr)
			return 1;
		break;
	case IPCHECK_TYPE_RANGE:
		if ((ntohl(ip_to_check->sin_addr.s_addr) >= ntohl(match1->sin_addr.s_addr)) &&
		    (ntohl(ip_to_check->sin_addr.s_addr) <= ntohl(match2->sin_addr.s_addr)))
			return 1;
		break;

	}
	return 0;
}

/* Compare two IPv6 addresses */
static int ip6addr_cmp(struct in6_addr *a, struct in6_addr *b)
{
	uint64_t a_high, a_low;
	uint64_t b_high, b_low;

	/* Not sure why '&' doesn't work below, so I used '+' instead which is effectively
	   the same thing because the bottom 32bits are always zero and the value unsigned */
	a_high = ((uint64_t)htonl(a->s6_addr32[0]) << 32) + (uint64_t)htonl(a->s6_addr32[1]);
	a_low  = ((uint64_t)htonl(a->s6_addr32[2]) << 32) + (uint64_t)htonl(a->s6_addr32[3]);

	b_high = ((uint64_t)htonl(b->s6_addr32[0]) << 32) + (uint64_t)htonl(b->s6_addr32[1]);
	b_low  = ((uint64_t)htonl(b->s6_addr32[2]) << 32) + (uint64_t)htonl(b->s6_addr32[3]);

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
 *
 */
static int ip_matches_v6(struct sockaddr_storage *checkip, struct ip_match_entry *match_entry)
{
	struct sockaddr_in6 *ip_to_check;
	struct sockaddr_in6 *match1;
	struct sockaddr_in6 *match2;
	int i;

	ip_to_check = (struct sockaddr_in6 *)checkip;
	match1 = (struct sockaddr_in6 *)&match_entry->addr1;
	match2 = (struct sockaddr_in6 *)&match_entry->addr2;

	switch(match_entry->type) {
	case IPCHECK_TYPE_ADDRESS:
		if (!memcmp(ip_to_check->sin6_addr.s6_addr32, match1->sin6_addr.s6_addr32, sizeof(struct in6_addr)))
			return 1;
		break;

	case IPCHECK_TYPE_MASK:
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
	case IPCHECK_TYPE_RANGE:
		if ((ip6addr_cmp(&ip_to_check->sin6_addr, &match1->sin6_addr) >= 0) &&
		    (ip6addr_cmp(&ip_to_check->sin6_addr, &match2->sin6_addr) <= 0))
			return 1;
		break;
	}
	return 0;
}


/*
 * YOU ARE HERE
 */
int ipcheck_validate(struct sockaddr_storage *checkip)
{
	struct ip_match_entry *match_entry;
	int (*match_fn)(struct sockaddr_storage *checkip, struct ip_match_entry *match_entry);

	if (checkip->ss_family == AF_INET){
		match_entry = match_entry_head_v4.next;
		match_fn = ip_matches_v4;
	} else {
		match_entry = match_entry_head_v6.next;
		match_fn = ip_matches_v6;
	}
	while (match_entry) {
		if (match_fn(checkip, match_entry)) {
			if (match_entry->acceptreject == IPCHECK_ACCEPT)
				return 1;
			else
				return 0;
		}
		match_entry = match_entry->next;
	}
	return 0; /* Default reject */
}

/*
 * Routines to manuipulate the lists
 */

void ipcheck_clear(void)
{
	struct ip_match_entry *match_entry;
	struct ip_match_entry *next_match_entry;

	match_entry = match_entry_head_v4.next;
	while (match_entry) {
		next_match_entry = match_entry->next;
		free(match_entry);
		match_entry = next_match_entry;
	}

	match_entry = match_entry_head_v6.next;
	while (match_entry) {
		next_match_entry = match_entry->next;
		free(match_entry);
		match_entry = next_match_entry;
	}
}

int ipcheck_addip(struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
		  ipcheck_type_t type, ipcheck_acceptreject_t acceptreject)
{
	struct ip_match_entry *match_entry;
	struct ip_match_entry *new_match_entry;

	if (type == IPCHECK_TYPE_RANGE &&
	    (ip1->ss_family != ip2->ss_family))
		return -1;

	if (ip1->ss_family == AF_INET){
		match_entry = &match_entry_head_v4;
	} else {
		match_entry = &match_entry_head_v6;
	}


	new_match_entry = malloc(sizeof(struct ip_match_entry));
	if (!new_match_entry)
		return -1;

	memmove(&new_match_entry->addr1, ip1, sizeof(struct sockaddr_storage));
	memmove(&new_match_entry->addr2, ip2, sizeof(struct sockaddr_storage));
	new_match_entry->type = type;
	new_match_entry->acceptreject = acceptreject;
	new_match_entry->next = NULL;

	/* Find the end of the list */
	/* is this OK, or should we use a doubly-linked list or bulk-load API call? */
	while (match_entry->next) {
		match_entry = match_entry->next;
	}
	match_entry->next = new_match_entry;

	return 0;
}
