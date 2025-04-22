/*
 * Copyright (C) 2012-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_ONWIRE_H__
#define __KNET_ONWIRE_H__

/*
 * data structures to define network packets.
 * Start from knet_header at the bottom
 */

#include <stdint.h>

#include "libknet.h"

/*
 * typedef uint64_t seq_num_t;
 * #define SEQ_MAX UINT64_MAX
 */
typedef uint16_t seq_num_t;
#define SEQ_MAX UINT16_MAX

struct knet_header_payload_data {
	seq_num_t	khp_data_seq_num;	/* pckt seq number used to deduplicate pkcts */
	uint8_t		khp_data_compress;	/* identify if user data are compressed */
	uint8_t		khp_data_pad1;		/* make sure to have space in the header to grow features */
	uint8_t		khp_data_bcast;		/* data destination bcast/ucast */
	uint8_t		khp_data_frag_num;	/* number of fragments of this pckt. 1 is not fragmented */
	uint8_t		khp_data_frag_seq;	/* as above, indicates the frag sequence number */
	int8_t		khp_data_channel;	/* transport channel data for localsock <-> knet <-> localsock mapping */
	uint8_t		khp_data_userdata[0];	/* pointer to the real user data */
} __attribute__((packed));

struct knet_header_payload_ping {
	uint8_t		khp_ping_link;		/* source link id */
	uint32_t	khp_ping_time[4];	/* ping timestamp */
	seq_num_t	khp_ping_seq_num;	/* transport host seq_num */
	uint8_t		khp_ping_timed;		/* timed pinged (1) or forced by seq_num (0) */
}  __attribute__((packed));

/* taken from tracepath6 */
#define KNET_PMTUD_SIZE_V4 65535
#define KNET_PMTUD_SIZE_V6 KNET_PMTUD_SIZE_V4

/*
 * IPv4/IPv6 header size
 */
#define KNET_PMTUD_OVERHEAD_V4 20
#define KNET_PMTUD_OVERHEAD_V6 40

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

#define KNET_HEADER_TYPE_PMSK        0x80 /* packet mask */
#define KNET_HEADER_TYPE_PING        0x81 /* heartbeat */
#define KNET_HEADER_TYPE_PONG        0x82 /* reply to heartbeat */
#define KNET_HEADER_TYPE_PMTUD       0x83 /* Used to determine Path MTU */
#define KNET_HEADER_TYPE_PMTUD_REPLY 0x84 /* reply from remote host */

struct knet_header {
	uint8_t				kh_version; /* pckt format/version */
	uint8_t				kh_type;    /* from above defines. Tells what kind of pckt it is */
	knet_node_id_t			kh_node;    /* host id of the source host for this pckt */
	uint8_t				kh_pad1;    /* make sure to have space in the header to grow features */
	uint8_t				kh_pad2;
	union knet_header_payload	kh_payload; /* union of potential data struct based on kh_type */
} __attribute__((packed));

/*
 * commodoty defines to hide structure nesting
 * (needs review and cleanup)
 */

#define khp_data_seq_num  kh_payload.khp_data.khp_data_seq_num
#define khp_data_frag_num kh_payload.khp_data.khp_data_frag_num
#define khp_data_frag_seq kh_payload.khp_data.khp_data_frag_seq
#define khp_data_userdata kh_payload.khp_data.khp_data_userdata
#define khp_data_bcast    kh_payload.khp_data.khp_data_bcast
#define khp_data_channel  kh_payload.khp_data.khp_data_channel
#define khp_data_compress kh_payload.khp_data.khp_data_compress

#define khp_ping_link     kh_payload.khp_ping.khp_ping_link
#define khp_ping_time     kh_payload.khp_ping.khp_ping_time
#define khp_ping_seq_num  kh_payload.khp_ping.khp_ping_seq_num
#define khp_ping_timed    kh_payload.khp_ping.khp_ping_timed

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

size_t calc_data_outlen(knet_handle_t knet_h, size_t inlen);
size_t calc_max_data_outlen(knet_handle_t knet_h, size_t inlen);
size_t calc_min_mtu(knet_handle_t knet_h);

#endif
