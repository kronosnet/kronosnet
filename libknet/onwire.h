/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __ONWIRE_H__
#define __ONWIRE_H__

/*
 * data structures to define network packets.
 * Start from knet_header at the bottom
 */

#include <stdint.h>

#if 0

/*
 * for future protocol extension (re-switching table calculation)
 */

struct knet_hinfo_link {
	uint8_t			khl_link_id;
	uint8_t			khl_link_dynamic;
	uint8_t			khl_link_priority;
	uint64_t		khl_link_latency;
	char			khl_link_dst_ipaddr[KNET_MAX_HOST_LEN];
	char			khl_link_dst_port[KNET_MAX_PORT_LEN];
} __attribute__((packed));

struct knet_hinfo_link_table {
	uint16_t		khlt_node_id;
	uint8_t			khlt_local; /* we have this node connected locally */
	struct knet_hinfo_link	khlt_link[KNET_MAX_LINK]; /* info we send about each link in the node */
} __attribute__((packed));

struct link_table {
	uint16_t	khdt_host_entries;
	uint8_t		khdt_host_maps[0]; /* array of knet_hinfo_link_table[khdt_host_entries] */
} __attribute__((packed));
#endif

#define KNET_HOSTINFO_LINK_STATUS_DOWN 0
#define KNET_HOSTINFO_LINK_STATUS_UP   1

struct knet_hostinfo_payload_link_status {
	uint8_t		khip_link_status_link_id;	/* link id */
	uint8_t		khip_link_status_status;	/* up/down status */
} __attribute__((packed));

/*
 * union to reference possible individual payloads
 */

union knet_hostinfo_payload {
	struct knet_hostinfo_payload_link_status knet_hostinfo_payload_link_status;
} __attribute__((packed));

/*
 * due to the nature of knet_hostinfo, we are currently
 * sending those data as part of knet_header_payload_data.khp_data_userdata
 * and avoid a union that increses knet_header_payload_data size
 * unnecessarely.
 * This might change later on depending on how we implement
 * host info exchange
 */

#define KNET_HOSTINFO_TYPE_LINK_UP_DOWN 0
#define KNET_HOSTINFO_TYPE_LINK_TABLE   1 // NOT IMPLEMENTED

#define KNET_HOSTINFO_UCAST 0	/* send info to a specific host */
#define KNET_HOSTINFO_BCAST 1	/* send info to all known / connected hosts */

struct knet_hostinfo {
	uint8_t				khi_type;	/* type of hostinfo we are sending */
	uint8_t				khi_bcast;	/* hostinfo destination bcast/ucast */
	uint16_t			khi_dst_node_id;/* used only if in ucast mode */
	union knet_hostinfo_payload	khi_payload;
} __attribute__((packed));

#define KNET_HOSTINFO_ALL_SIZE sizeof(struct knet_hostinfo)
#define KNET_HOSTINFO_SIZE (KNET_HOSTINFO_ALL_SIZE - sizeof(union knet_hostinfo_payload))
#define KNET_HOSTINFO_LINK_STATUS_SIZE (KNET_HOSTINFO_SIZE + sizeof(struct knet_hostinfo_payload_link_status))

#define khip_link_status_status khi_payload.knet_hostinfo_payload_link_status.khip_link_status_status
#define khip_link_status_link_id khi_payload.knet_hostinfo_payload_link_status.khip_link_status_link_id

/*
 * typedef uint64_t seq_num_t;
 * #define SEQ_MAX UINT64_MAX
 */
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

struct knet_header_payload_data {
	seq_num_t	khp_data_seq_num;	/* pckt seq number used to deduplicate pkcts */
	uint8_t		khp_data_userdata[0];	/* pointer to the real user data */
} __attribute__((packed));

struct knet_header_payload_ping {
	uint8_t		khp_ping_link;		/* source link id */
	uint32_t	khp_ping_time[4];	/* ping timestamp */
}  __attribute__((packed));

/* taken from tracepath6 */
#define KNET_PMTUD_SIZE_V4 65535
#define KNET_PMTUD_SIZE_V6 128000
#define KNET_PMTUD_OVERHEAD_V4 28
#define KNET_PMTUD_OVERHEAD_V6 48
#define KNET_PMTUD_MIN_MTU_V4 576
#define KNET_PMTUD_MIN_MTU_V6 1280

struct knet_header_payload_pmtud {
	uint8_t		khp_pmtud_link;		/* source link id */
	uint16_t	khp_pmtud_size;		/* size of the current packet */
	uint8_t		khp_pmtud_data[0];	/* pointer to empty/random data/fill buffer */
} __attribute__((packed));

/*
 * union to reference possible individual payloads
 */

union knet_header_payload {
	struct knet_header_payload_data		khp_data;  /* pure data packet struct */
	struct knet_header_payload_ping		khp_ping;  /* heartbeat packet struct */
	struct knet_header_payload_pmtud 	khp_pmtud; /* Path MTU discovery packet struct */
} __attribute__((packed));

/*
 * starting point
 */

#define KNET_HEADER_VERSION          0x01 /* we currently support only one version */

#define KNET_HEADER_TYPE_DATA        0x00 /* pure data packet */
#define KNET_HEADER_TYPE_HOST_INFO   0x01 /* host status information pckt */

#define KNET_HEADER_TYPE_PMSK        0x80 /* packet mask */
#define KNET_HEADER_TYPE_PING        0x81 /* heartbeat */
#define KNET_HEADER_TYPE_PONG        0x82 /* reply to heartbeat */
#define KNET_HEADER_TYPE_PMTUD       0x83 /* Used to determine Path MTU */
#define KNET_HEADER_TYPE_PMTUD_REPLY 0x84 /* reply from remote host */

struct knet_header {
	uint8_t				kh_version; /* pckt format/version */
	uint8_t				kh_type;    /* from above defines. Tells what kind of pckt it is */
	uint16_t			kh_node;    /* host id of the source host for this pckt */
	union knet_header_payload	kh_payload; /* union of potential data struct based on kh_type */
} __attribute__((packed));

/*
 * commodoty defines to hide structure nesting
 * (needs review and cleanup)
 */

#define khp_data_seq_num  kh_payload.khp_data.khp_data_seq_num
#define khp_data_userdata kh_payload.khp_data.khp_data_userdata

#define khp_ping_link     kh_payload.khp_ping.khp_ping_link
#define khp_ping_time     kh_payload.khp_ping.khp_ping_time

#define khp_pmtud_link    kh_payload.khp_pmtud.khp_pmtud_link
#define khp_pmtud_size    kh_payload.khp_pmtud.khp_pmtud_size
#define khp_pmtud_data    kh_payload.khp_pmtud.khp_pmtud_data

/*
 * extra defines to avoid mingling with sizeof() too much
 */

#define KNET_HEADER_ALL_SIZE sizeof(struct knet_header)
#define KNET_HEADER_SIZE (KNET_HEADER_ALL_SIZE - sizeof(union knet_header_payload))
#define KNET_HEADER_PING_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_ping))
#define KNET_HEADER_PMTUD_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_pmtud))
#define KNET_HEADER_DATA_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_data))

#endif
