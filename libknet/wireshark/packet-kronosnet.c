/*
 * Copyright (C) 2026 Red Hat, Inc.  All rights reserved.
 *
 * Routines for the Kronosnet (kronosnet) protocol used by corosync
 * corosync packets are NOT decoded by this dissector
 *
 * Authors: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <wsutil/file_util.h>

#include "../libknet.h"
#include "../crypto.h"
#include "../compress.h"
#include "packet-kronosnet.h"

void proto_register_kronosnet(void);
void proto_reg_handoff_kronosnet(void);

WS_DLL_PUBLIC_DEF const char plugin_version[] = "1.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

#define PROTO_TAG_KRONOSNET      "Kronosnet"    /*!< Definition of kronosnet Protocol */
/*
 * NOTE this is actually the corosync port number, but it's where
 * knet packets are most likely to be found
 */
#define PORT 5405           /* Not IANA registered */

/**
 * @addtogroup messageids kronosnet Message ID:s
 * Message ID:s of the kronosnet protocol
 */
/**@{*/
#define KRONOSNET_HEADER_TYPE_DATA        0x00 /* !< Message ID definition: pure data packet */
#define KRONOSNET_HEADER_TYPE_PING        0x81 /* !< Message ID definition: heartbeat */
#define KRONOSNET_HEADER_TYPE_PONG        0x82 /* !< Message ID definition: reply to heartbeat */
#define KRONOSNET_HEADER_TYPE_PMTUD       0x83 /* !< Message ID definition: Used to determine Path MTU */
#define KRONOSNET_HEADER_TYPE_PMTUD_REPLY 0x84 /* !< Message ID definition: reply from remote host */

/**
 * @addtogroup protocols Protocol Variables
 * Protocol variables.
 */
/**@{*/
static int proto_kronosnet;
static dissector_handle_t kronosnet_handle;
static dissector_handle_t corosync_totemknet_handle;
static int hf_kronosnet_packet_type;
static int ett_kronosnet;
static int ett_kronosnet_data;
static int ett_kronosnet_ping;
static int ett_kronosnet_pmtu;
static reassembly_table kronosnet_reassembly_table;

// Pref fields for decryption & extra debug
static const char *kronosnet_private_key_file;
static const char *kronosnet_crypto_cipher;
static const char *kronosnet_crypto_hash;
static const char *private_key;
static bool kronosnet_extra_debug;

// Things for keying into libknet
static int crypto_initialised = 0;
static knet_handle_t knet_h;

// Header fields
static int hf_kh_version; /* this pckt format/version */
static int hf_kh_type;    /* from above defines. Tells what kind of pckt it is */
static int hf_kh_node;    /* host id of the source host for this pckt */
static int hf_kh_max_ver; /* max version of the protocol supported by this node */
static int hf_kh_pad1;    /* make sure to have space in the header to grow features */

static int hf_khp_data_seq_num;
static int hf_khp_data_compress;
static int hf_khp_data_pad1;
static int hf_khp_data_bcast;
static int hf_khp_data_frag_num;
static int hf_khp_data_frag_seq;
static int hf_khp_data_channel;
static int hf_khp_data_checksum;
static int hf_khp_data_userdata;
static int hf_khp_ping_link;
static int hf_khp_ping_time1;
static int hf_khp_ping_time2;
static int hf_khp_ping_time3;
static int hf_khp_ping_time4;
static int hf_khp_ping_seq_num;
static int hf_khp_ping_timed;
static int hf_khp_pmtud_link;
static int hf_khp_pmtud_size;
// Stuff for defragmenting
static int hf_kronosnet_fragments;
static int hf_kronosnet_fragment;
static int hf_kronosnet_fragment_overlap;
static int hf_kronosnet_fragment_overlap_conflicts;
static int hf_kronosnet_fragment_multiple_tails;
static int hf_kronosnet_fragment_too_long_fragment;
static int hf_kronosnet_fragment_error;
static int hf_kronosnet_fragment_count;
static int hf_kronosnet_reassembled_in;
static int hf_kronosnet_reassembled_length;
static int ett_kronosnet_fragment;
static int ett_kronosnet_fragments;
/**@}*/

static const fragment_items kronosnet_frag_items = {
    /* Fragment subtrees */
    &ett_kronosnet_fragment,
    &ett_kronosnet_fragments,
    /* Fragment fields */
    &hf_kronosnet_fragments,
    &hf_kronosnet_fragment,
    &hf_kronosnet_fragment_overlap,
    &hf_kronosnet_fragment_overlap_conflicts,
    &hf_kronosnet_fragment_multiple_tails,
    &hf_kronosnet_fragment_too_long_fragment,
    &hf_kronosnet_fragment_error,
    &hf_kronosnet_fragment_count,
    /* Reassembled in field */
    &hf_kronosnet_reassembled_in,
    /* Reassembled length field */
    &hf_kronosnet_reassembled_length,
    /* Reassembled_data - not used */
    NULL,
    /* Tag */
    "Kronsnet fragments"
};

/**
 * @addtogroup headerfields Dissector Header Fields
 * Header fields of the kronosnet datagram
 */
/* *@{*/


static const value_string knet_packet_type_names[] = {
    { KRONOSNET_HEADER_TYPE_DATA,        "Data"        },
    { KRONOSNET_HEADER_TYPE_PING,        "Ping"        },
    { KRONOSNET_HEADER_TYPE_PONG,        "Ping Reply"  },
    { KRONOSNET_HEADER_TYPE_PMTUD,       "PMTU Check"  },
    { KRONOSNET_HEADER_TYPE_PMTUD_REPLY, "PMTU Reply"  },
    { 0,                    NULL                  }
};


// Dissect DATA packet with defragmentation and decompression
static int dissect_data_v1(proto_tree *pt, tvbuff_t *tvb, int offset,
                           knet_handle_t knet_h, packet_info *pinfo)
{
    proto_tree *data_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_data, NULL, "Data");
    int compress_type = 0;
    int seq_num;
    int frag_num;
    int frag_seq;

    proto_tree_add_item(data_tree, hf_khp_data_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    seq_num = tvb_get_ntohs(tvb, offset);
    offset += 2;
    proto_tree_add_item(data_tree, hf_khp_data_compress, tvb, offset, 1, ENC_BIG_ENDIAN);
    compress_type = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_pad1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_bcast, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_frag_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    frag_num = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_frag_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
    frag_seq = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (kronosnet_extra_debug) {
        proto_tree_add_item(data_tree, hf_khp_data_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    int save_fragmented = pinfo->fragmented;
    tvbuff_t *next_tvb = NULL;

    // Need to collect the frags
    if (frag_num > 1) {
        pinfo->fragmented = true;
        fragment_head *frag_msg = NULL;

        frag_msg = fragment_add_seq_check(&kronosnet_reassembly_table,
                                          tvb, offset, pinfo,
                                          seq_num, NULL, /* ID for fragments belonging together */
                                          frag_seq-1, /* fragment sequence number */
                                          tvb_captured_length_remaining(tvb, offset), /* fragment length - to the end */
                                          (frag_seq != frag_num)); /* More fragments? */

        tvbuff_t *new_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                     "Reassembled Message", frag_msg, &kronosnet_frag_items,
                                                     NULL, pt);

        if (frag_num == frag_seq) {
            col_append_str(pinfo->cinfo, COL_INFO,
                           " (Message Reassembled)");
        } else { /* Not last packet of reassembled Short Message */
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " (Message fragment %u)", frag_seq);
        }

        if (new_tvb) { /* take it all */
            next_tvb = new_tvb;
            offset = 0;
        } else { /* make a new subset */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            offset = 0;
        }
    }
    else { /* Not fragmented */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        offset = 0;
    }
    pinfo->fragmented = save_fragmented;

    // Decompress?
    if (((frag_num > 1 && frag_seq == frag_num) ||
         (frag_seq == 0)) &&
        compress_type) {
        int len = tvb_captured_length_remaining(next_tvb, offset);

        unsigned char *newbuf = (unsigned char*)wmem_alloc(pinfo->pool, KNET_DATABUFSIZE_COMPRESS);
        ssize_t outlen = KNET_DATABUFSIZE_COMPRESS;

        int err = decompress(knet_h, compress_type,
                             tvb_memdup(pinfo->pool, next_tvb, offset, -1), len,
                             newbuf, &outlen);
        if (err == 0) {
            next_tvb = tvb_new_child_real_data(tvb, newbuf, outlen, outlen);
            add_new_data_source(pinfo, next_tvb, "Decompressed Data");
            proto_tree_add_item(data_tree, hf_khp_data_userdata, next_tvb, 0, outlen, ENC_NA);
            offset = 0;
        } else {
            ws_warning("Kronosnet: decompress (type %d) failed: %d", compress_type, errno);
            // Return still-compressed(?) data
        }
    }

    // Try and decode corosync packets if the dissector is available
    if (corosync_totemknet_handle) {
        return call_dissector(corosync_totemknet_handle, next_tvb, pinfo, data_tree);
    } else {
        return offset;
    }
}

static int dissect_ping_v1(proto_tree *pt, tvbuff_t *tvb, int offset, char *name)
{
    proto_tree *ping_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_ping, NULL, name);

    proto_tree_add_item(ping_tree, hf_khp_ping_link, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ping_tree, hf_khp_ping_time1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ping_tree, hf_khp_ping_timed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static int dissect_pmtud_v1(proto_tree *pt, tvbuff_t *tvb, int offset, char *name)
{
    proto_tree *pmtu_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_pmtu, NULL, name);

    proto_tree_add_item(pmtu_tree, hf_khp_pmtud_link, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pmtu_tree, hf_khp_pmtud_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int read_key_file(packet_info *pinfo)
{
    FILE *fp;
    long fsize = 0;
    char *buf = NULL;

    fp = ws_fopen(kronosnet_private_key_file, "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        if (fsize == -1L) {
            fclose(fp);
            return -1;
        }
        fseek(fp, 0, SEEK_SET);

        buf = (char*)wmem_alloc(pinfo->pool, fsize + 1);
        if (fread(buf, 1, fsize, fp) != (size_t)fsize) {
            fclose(fp);
            return -1;
        }
        fclose(fp);
    }
    private_key = buf;
    return fsize;
}

/**
 * dissect_kronosnet is the dissector which is called
 * by Wireshark when kronosnet UDP packets are captured.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_kronosnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb = NULL;

    /* Only decrypt if we have ALL of the information we need */
    if (kronosnet_private_key_file[0] &&
        kronosnet_crypto_cipher[0] &&
        kronosnet_crypto_hash[0]) {
        if (!crypto_initialised) {
            // Conect to Knet
            knet_h = knet_handle_new(1, 2, KNET_LOG_DEBUG);
            if (!knet_h) {
                ws_warning("Kronsnet: Failed to get knet_handle");
                return 0;
            }
            // Init openssl
            struct knet_handle_crypto_cfg ccfg;
            strcpy(ccfg.crypto_model, "openssl");
            strcpy(ccfg.crypto_hash_type, kronosnet_crypto_hash);
            strcpy(ccfg.crypto_cipher_type, kronosnet_crypto_cipher);
            ccfg.private_key_len = read_key_file(pinfo);
            if (ccfg.private_key_len > 0) {
                memcpy(ccfg.private_key, private_key, ccfg.private_key_len);
                if (knet_handle_crypto_set_config(knet_h, &ccfg, 1 != 0)) {
                    ws_warning("Kronsnet: Failed to init crypto");
                    return 0;
                }
                if (knet_handle_crypto_use_config(knet_h, 1) != 0) {
                    ws_warning("Kronsnet: Failed to 'use' crypto");
                    return 0;
                }
            } else {
                ws_warning("Kronsnet: Failed to read private key");
                return 0;
            }
            if (compress_init(knet_h) != 0) {
                ws_warning("Kronsnet: Failed to init compression");
                return 0;
            }
            crypto_initialised = 1;
        }
        // decrypt packet and reset tvb etc
        int len = tvb_captured_length_remaining(tvb, 0);
        unsigned char *newbuf = (unsigned char*)wmem_alloc(pinfo->pool, len);
        ssize_t outlen = len;
        int res = crypto_authenticate_and_decrypt(knet_h,
                                                  tvb_memdup(pinfo->pool, tvb, 0, -1), len,
                                                  newbuf, &outlen);
        if (res) {
            ws_warning("Kronsnet: Failed to decrypt packet: %d", res);
            return 0;
        } else {
            next_tvb = tvb_new_child_real_data(tvb, newbuf, outlen, outlen);
            add_new_data_source(pinfo, next_tvb, "Decrypted Data");
        }
    }

    if (next_tvb == NULL) {
        return 0;
    }

    int offset = 0;
    int type = 0;
    int version = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRONOSNET");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    // Might need to change this to allow us to encapsulate corosync (if that ever happens)
    proto_item *ti = proto_tree_add_item(tree, proto_kronosnet, next_tvb, 0, -1, ENC_NA);

    proto_tree *kronosnet_tree = proto_item_add_subtree(ti, ett_kronosnet);
    proto_tree_add_item(kronosnet_tree, hf_kronosnet_packet_type, next_tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(kronosnet_tree, hf_kh_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    version = tvb_get_uint8(next_tvb, offset);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_type, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_uint8(next_tvb, offset);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_node, next_tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kronosnet_tree, hf_kh_max_ver, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_pad1, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (version == 1) {
        switch (type) {
            case KRONOSNET_HEADER_TYPE_DATA:
                offset = dissect_data_v1(kronosnet_tree, next_tvb, offset, knet_h, pinfo);
                break;
            case KRONOSNET_HEADER_TYPE_PING:
                offset = dissect_ping_v1(kronosnet_tree, next_tvb, offset, "Ping");
                break;
            case KRONOSNET_HEADER_TYPE_PONG:
                offset = dissect_ping_v1(kronosnet_tree, next_tvb, offset, "Pong");
                break;
            case KRONOSNET_HEADER_TYPE_PMTUD:
                offset = dissect_pmtud_v1(kronosnet_tree, next_tvb, offset, "pMTUd");
                break;
            case KRONOSNET_HEADER_TYPE_PMTUD_REPLY:
                offset = dissect_pmtud_v1(kronosnet_tree, next_tvb, offset, "pMTUd Reply");
                break;
        }
    }

    return tvb_captured_length(next_tvb);
}
/**
 * proto_register_kronosnet registers our kronosnet protocol,
 * headerfield- and subtree-array to Wireshark.
 *
 */
void
proto_register_kronosnet(void)
{
    module_t *kronosnet_module;

    static hf_register_info hf[] = {
        // First entry is needed but not sure what it does
        { &hf_kronosnet_packet_type,
          { "Kronosnet Packet Type", "kronosnet.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_version,
          { "kronosnet version", "kronosnet.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_type,
          { "Kronosnet packet type", "kronosnet.type",
            FT_UINT8, BASE_DEC,
            VALS(knet_packet_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_kh_node,
          { "Kronosnet node id", "kronosnet.nodeid",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_max_ver,
          { "kronosnet max version", "kronosnet.max_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_pad1,
          { "Kronosnet pad1", "kronosnet.pad1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_seq_num,
          { "Kronosnet data seq_num", "kronosnet.data.seq_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_compress,
          { "Kronosnet data compress", "kronosnet.data.compress",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_pad1,
          { "Kronosnet data pad1", "kronosnet.data.pad1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_bcast,
          { "Kronosnet data bcast", "kronosnet.data.bcast",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_frag_num,
          { "Kronosnet data frag_num", "kronosnet.data.frag_num",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_frag_seq,
          { "Kronosnet data frag_seq", "kronosnet.data.frag_seq",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_channel,
          { "Kronosnet data channel", "kronosnet.data.channel",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_checksum,
          { "Kronosnet data checksum", "kronosnet.data.checksum",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_userdata,
          { "Kronosnet data data", "kronosnet.data.userdata",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_link,
          { "Kronosnet ping/pong link", "kronosnet.pingpong.link",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time1,
          { "Kronosnet ping/pong time1", "kronosnet.pingpong.time1",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time2,
          { "Kronosnet ping/pong time2", "kronosnet.pingpong.time2",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time3,
          { "Kronosnet ping/pong time3", "kronosnet.pingpong.time3",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time4,
          { "Kronosnet ping/pong time4", "kronosnet.pingpong.time4",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_seq_num,
          { "Kronosnet ping/pong seq_num", "kronosnet.pingpong.seq_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_timed,
          { "Kronosnet ping/pong timed", "kronosnet.pingpong.timed",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_pmtud_link,
          { "Kronosnet pMTU link", "kronosnet.pmtu.link",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_pmtud_size,
          { "Kronosnet pMTU size", "kronosnet.pmtu.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_kronosnet_fragments,
         {"Message fragments", "kronosnet.fragments",
          FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment,
         {"Message fragment", "kronosnet.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_overlap,
         {"Message fragment overlap", "kronosnet.fragment.overlap",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_overlap_conflicts,
         {"Message fragment overlapping with conflicting data",
          "kronosnet.fragment.overlap.conflicts",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_multiple_tails,
         {"Message has multiple tail fragments",
          "kronosnet.fragment.multiple_tails",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_too_long_fragment,
         {"Message fragment too long", "kronosnet.fragment.too_long_fragment",
          FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_error,
         {"Message defragmentation error", "kronosnet.fragment.error",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_fragment_count,
         {"Message fragment count", "kronosnet.fragment.count",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_reassembled_in,
         {"Reassembled in", "kronosnet.reassembled.in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_kronosnet_reassembled_length,
         {"Reassembled length", "kronosnet.reassembled.length",
          FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        }
    };
    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_kronosnet,
        &ett_kronosnet_data,
        &ett_kronosnet_ping,
        &ett_kronosnet_pmtu,
        &ett_kronosnet_fragment,
        &ett_kronosnet_fragments
    };


    /* Register protocols */
    proto_kronosnet = proto_register_protocol ("kronosnet Protocol", "KRONOSNET", "kronosnet");
    proto_register_field_array(proto_kronosnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    kronosnet_handle = register_dissector_with_description(
        "kronosnet",
        "Kronosnet protocol",
        dissect_kronosnet,
        proto_kronosnet);

    /* Prefs to get encryption parameters */
    kronosnet_module = prefs_register_protocol(proto_kronosnet, NULL);
    prefs_register_filename_preference(kronosnet_module, "private_key_file", "Private key filename",
                                     "File containting key used to encryption",
                                       &kronosnet_private_key_file, false);
    prefs_register_string_preference(kronosnet_module, "crypto_cipher", "Crypto Cipher",
                                     "encrpytion cipher",
                                     &kronosnet_crypto_cipher);
    prefs_register_string_preference(kronosnet_module, "crypto_hash", "Crypto Hash",
                                     "HMAC authentication type",
                                     &kronosnet_crypto_hash);
    /* Pref for decoding EXTRA_DEBUG packets */
    prefs_register_bool_preference(kronosnet_module, "extra_debug", "Decode Extra Debug packets",
                                   "Decode 'Extra Debug' packets (This is a Knet build config option)",
                                   &kronosnet_extra_debug);


    /* Register reassembly table */
    reassembly_table_register(&kronosnet_reassembly_table,
                              &addresses_reassembly_table_functions);
}

/**
 * proto_reg_handoff_kronosnet registers our kronosnet dissectors to Wireshark
 *
 */
void
proto_reg_handoff_kronosnet(void)
{
    dissector_add_uint_with_preference("udp.port", PORT, kronosnet_handle);

    // This can fail and it's fine.
    corosync_totemknet_handle = find_dissector_add_dependency("corosync_totemknet", proto_kronosnet);
}


WS_DLL_PUBLIC_DEF void plugin_register(void)
{
    static proto_plugin plug_kronosnet;

    plug_kronosnet.register_protoinfo = proto_register_kronosnet;
    plug_kronosnet.register_handoff = proto_reg_handoff_kronosnet;
    proto_register_plugin(&plug_kronosnet);
}


/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
