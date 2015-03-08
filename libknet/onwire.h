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
#endif

union knet_hinfo_dtype {
	struct {
		uint8_t		khdt_link_id;
		uint8_t		khdt_link_status;
	} link_up_down;
#if 0
	struct {
		uint16_t	khdt_host_entries;
		uint8_t		khdt_host_maps[0]; /* array of knet_hinfo_link_table[khdt_host_entries] */
	} link_table __attribute__((packed));
#endif
} __attribute__((packed));

struct knet_hinfo_data {			/* this is sent in kf_data */
	uint8_t			khd_type;	/* link_up_down / link_table */
	uint8_t			khd_bcast;	/* bcast/ucast */
	uint16_t		khd_dst_node_id;/* used only if in ucast mode */
	union knet_hinfo_dtype  khd_dype;
} __attribute__((packed));

/*
 * typedef uint64_t seq_num_t;
 * #define SEQ_MAX UINT64_MAX
 */
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

struct knet_header_payload_data {
	seq_num_t	kfd_seq_num;
	uint8_t		kfd_data[0];
} __attribute__((packed));

struct knet_header_payload_ping {
	uint8_t		khp_ping_link;		/* source link id */
	uint32_t	khp_ping_time[4];	/* ping timestamp */
}  __attribute__((packed));

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

#define KNET_FRAME_VERSION          0x01 /* we currently support only one version */

#define KNET_FRAME_TYPE_DATA        0x00 /* pure data packet */
#define KNET_FRAME_TYPE_HOST_INFO   0x01 /* host status information pckt */

#define KNET_FRAME_TYPE_PMSK        0x80 /* packet mask */
#define KNET_FRAME_TYPE_PING        0x81 /* heartbeat */
#define KNET_FRAME_TYPE_PONG        0x82 /* reply to heartbeat */
#define KNET_FRAME_TYPE_PMTUD       0x83 /* Used to determine Path MTU */
#define KNET_FRAME_TYPE_PMTUD_REPLY 0x84 /* reply from remote host */

struct knet_header {
	uint8_t				kh_version; /* pckt format/version */
	uint8_t				kh_type;    /* from above defines. Tells what kind of pckt it is */
	uint16_t			kh_node;    /* host id of the source host for this pckt */
	union knet_header_payload	kh_payload; /* union of potential data struct based on kh_type */
} __attribute__((packed));

#define kf_seq_num kh_payload.khp_data.kfd_seq_num
#define kf_data    kh_payload.khp_data.kfd_data

#define kf_link    kh_payload.khp_ping.khp_ping_link
#define kf_time    kh_payload.khp_ping.khp_ping_time

#define kf_plink   kh_payload.khp_pmtud.khp_pmtud_link
#define kf_psize   kh_payload.khp_pmtud.khp_pmtud_size
#define kf_pdata   kh_payload.khp_pmtud.khp_pmtud_data

#define KNET_PING_SIZE sizeof(struct knet_header)
#define KNET_FRAME_SIZE (sizeof(struct knet_header) - sizeof(union knet_header_payload))
#define KNET_FRAME_DATA_SIZE KNET_FRAME_SIZE + sizeof(struct knet_header_payload_data)

/* taken from tracepath6 */
#define KNET_PMTUD_SIZE_V4 65535
#define KNET_PMTUD_SIZE_V6 128000
#define KNET_PMTUD_OVERHEAD_V4 28
#define KNET_PMTUD_OVERHEAD_V6 48
#define KNET_PMTUD_MIN_MTU_V4 576
#define KNET_PMTUD_MIN_MTU_V6 1280

#define KNET_HOST_INFO_LINK_UP_DOWN 0
#define KNET_HOST_INFO_LINK_TABLE   1

#endif
