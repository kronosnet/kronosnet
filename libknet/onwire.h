/*
 * Copyright (C) 2012-2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_ONWIRE_H__
#define __KNET_ONWIRE_H__

#include <stdint.h>

#include "libknet.h"

/*
 * data structures to define network packets.
 * Start from knet_header at the bottom
 */

/*
 * Plan is to support MAX_VER with MIN_VER = MAX_VER - 1
 * but for the sake of not rewriting the world later on,
 * let´s make sure we can support a random range of protocol
 * versions
 */

#define KNET_HEADER_ONWIRE_MAX_VER   0x01 /* max onwire protocol supported by this build */
#define KNET_HEADER_ONWIRE_MIN_VER   0x01 /* min onwire protocol supported by this build */

/*
 * Packet types
 *
 * adding new DATA types requires the packet to contain
 * data_seq_num and frag_num/frag_seq in the current data types.
 *
 * Changing those data types requires major surgery to thread_tx/thread_rx
 * and defrag buffer allocation in knet_host_add.
 *
 * Also please be aware that frags buffer allocation size is not constant
 * so you cannot assume each frag is 64K+.
 * (see handle.c)
 */

#define KNET_HEADER_TYPE_DATA        0x00 /* pure data packet */

#define KNET_HEADER_TYPE_PING        0x81 /* heartbeat */
#define KNET_HEADER_TYPE_PONG        0x82 /* reply to heartbeat */
#define KNET_HEADER_TYPE_PMTUD       0x83 /* Used to determine Path MTU */
#define KNET_HEADER_TYPE_PMTUD_REPLY 0x84 /* reply from remote host */

/*
 * KNET_HEADER_TYPE_DATA
 */

typedef uint16_t seq_num_t;			/* data sequence number required to deduplicate pckts */
#define SEQ_MAX UINT16_MAX

struct knet_header_payload_data_v1 {
	seq_num_t	khp_data_seq_num;	/* pckt seq number used to deduplicate pckts */
	uint8_t		khp_data_compress;	/* identify if user data are compressed */
	uint8_t		khp_data_pad1;		/* make sure to have space in the header to grow features */
	uint8_t		khp_data_bcast;		/* data destination bcast/ucast */
	uint8_t		khp_data_frag_num;	/* number of fragments of this pckt. 1 is not fragmented */
	uint8_t		khp_data_frag_seq;	/* as above, indicates the frag sequence number */
	int8_t		khp_data_channel;	/* transport channel data for localsock <-> knet <-> localsock mapping */
	uint8_t		khp_data_userdata[0];	/* pointer to the real user data */
} __attribute__((packed));

#define khp_data_v1_seq_num  kh_payload.khp_data_v1.khp_data_seq_num
#define khp_data_v1_frag_num kh_payload.khp_data_v1.khp_data_frag_num
#define khp_data_v1_frag_seq kh_payload.khp_data_v1.khp_data_frag_seq
#define khp_data_v1_userdata kh_payload.khp_data_v1.khp_data_userdata
#define khp_data_v1_bcast    kh_payload.khp_data_v1.khp_data_bcast
#define khp_data_v1_channel  kh_payload.khp_data_v1.khp_data_channel
#define khp_data_v1_compress kh_payload.khp_data_v1.khp_data_compress

/*
 * KNET_HEADER_TYPE_PING / KNET_HEADER_TYPE_PONG
 */

struct knet_header_payload_ping_v1 {
	uint8_t		khp_ping_link;		/* changing khp_ping_link requires changes to thread_rx.c
						   KNET_LINK_DYNIP code handling */
	uint32_t	khp_ping_time[4];	/* ping timestamp */
	seq_num_t	khp_ping_seq_num;	/* transport host seq_num */
	uint8_t		khp_ping_timed;		/* timed pinged (1) or forced by seq_num (0) */
}  __attribute__((packed));

#define khp_ping_v1_link     kh_payload.khp_ping_v1.khp_ping_link
#define khp_ping_v1_time     kh_payload.khp_ping_v1.khp_ping_time
#define khp_ping_v1_seq_num  kh_payload.khp_ping_v1.khp_ping_seq_num
#define khp_ping_v1_timed    kh_payload.khp_ping_v1.khp_ping_timed

/*
 * KNET_HEADER_TYPE_PMTUD / KNET_HEADER_TYPE_PMTUD_REPLY
 */

/*
 * taken from tracepath6
 */
#define KNET_PMTUD_SIZE_V4 65535
#define KNET_PMTUD_SIZE_V6 KNET_PMTUD_SIZE_V4

/*
 * IPv4/IPv6 header size
 */
#define KNET_PMTUD_OVERHEAD_V4 20
#define KNET_PMTUD_OVERHEAD_V6 40

#define KNET_PMTUD_MIN_MTU_V4 576
#define KNET_PMTUD_MIN_MTU_V6 1280

struct knet_header_payload_pmtud_v1 {
	uint8_t		khp_pmtud_link;		/* link_id */
	uint16_t	khp_pmtud_size;		/* size of the current packet */
	uint8_t		khp_pmtud_data[0];	/* pointer to empty/random data/fill buffer */
} __attribute__((packed));

#define khp_pmtud_v1_link    kh_payload.khp_pmtud_v1.khp_pmtud_link
#define khp_pmtud_v1_size    kh_payload.khp_pmtud_v1.khp_pmtud_size
#define khp_pmtud_v1_data    kh_payload.khp_pmtud_v1.khp_pmtud_data

/*
 * PMTUd related functions
 */

size_t calc_data_outlen(knet_handle_t knet_h, size_t inlen);
size_t calc_max_data_outlen(knet_handle_t knet_h, size_t inlen);
size_t calc_min_mtu(knet_handle_t knet_h);

/*
 * union to reference possible individual payloads
 */

union knet_header_payload {
	struct knet_header_payload_data_v1	khp_data_v1;     /* pure data packet struct */
	struct knet_header_payload_ping_v1	khp_ping_v1;  /* heartbeat packet struct */
	struct knet_header_payload_pmtud_v1 	khp_pmtud_v1; /* Path MTU discovery packet struct */
} __attribute__((packed));

/*
 * this header CANNOT change or onwire compat will break!
 */

struct knet_header {
	uint8_t				kh_version; /* this pckt format/version */
	uint8_t				kh_type;    /* from above defines. Tells what kind of pckt it is */
	knet_node_id_t			kh_node;    /* host id of the source host for this pckt */
	uint8_t				kh_max_ver; /* max version of the protocol supported by this node */
	uint8_t				kh_pad1;    /* make sure to have space in the header to grow features */
	union knet_header_payload	kh_payload; /* union of potential data struct based on kh_type */
} __attribute__((packed));

/*
 * extra defines to avoid mingling with sizeof() too much
 */

#define KNET_HEADER_ALL_SIZE sizeof(struct knet_header)
#define KNET_HEADER_SIZE (KNET_HEADER_ALL_SIZE - sizeof(union knet_header_payload))
#define KNET_HEADER_PING_V1_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_ping_v1))
#define KNET_HEADER_PMTUD_V1_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_pmtud_v1))
#define KNET_HEADER_DATA_V1_SIZE (KNET_HEADER_SIZE + sizeof(struct knet_header_payload_data_v1))

#endif
