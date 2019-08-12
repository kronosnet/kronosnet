/*
 * Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "internals.h"
#include "logging.h"
#include "common.h"
#include "transport_udp.h"
#include "transport_sctp.h"

/*
 * unencrypted packet looks like:
 *
 * | ip | protocol  | knet_header | unencrypted data                                  |
 * | onwire_len                                                                       |
 * | proto_overhead |
 *                  | data_len                                                        |
 *                                | app MTU                                           |
 *
 * encrypted packet looks like (not to scale):
 *
 * | ip | protocol  | salt | crypto(knet_header | data)      | crypto_data_pad | hash |
 * | onwire_len                                                                       |
 * | proto_overhead |
 *                  | data_len                                                        |
 *                                              | app MTU    |
 *
 * knet_h->sec_block_size is >= 0 if encryption will pad the data
 * knet_h->sec_salt_size is >= 0 if encryption is enabled
 * knet_h->sec_hash_size is >= 0 if signing is enabled
 */

/*
 * this function takes in the data that we would like to send
 * and tells us the outgoing onwire data size with crypto and
 * all the headers adjustment.
 * calling thread needs to account for protocol overhead.
 */

size_t calc_data_outlen(knet_handle_t knet_h, size_t inlen)
{
	size_t outlen = inlen, pad_len = 0;

	if (knet_h->sec_block_size) {
		/*
		 * if the crypto mechanism requires padding, calculate the padding
		 * and add it back to outlen because that's what the crypto layer
		 * would do.
		 */
		pad_len = knet_h->sec_block_size - (outlen % knet_h->sec_block_size);

		outlen = outlen + pad_len;
	}

	return outlen + knet_h->sec_salt_size + knet_h->sec_hash_size;
}

/*
 * this function takes in the data that we would like to send
 * and tells us what is the real maximum data we can send
 * accounting for headers and crypto
 * calling thread needs to account for protocol overhead.
 */

size_t calc_max_data_outlen(knet_handle_t knet_h, size_t inlen)
{
	size_t outlen = inlen, pad_len = 0;

	if (knet_h->sec_block_size) {
		/*
		 * drop both salt and hash, that leaves only the crypto data and padding
		 * we need to calculate the padding based on the real encrypted data
		 * that includes the knet_header.
		 */
		outlen = outlen - (knet_h->sec_salt_size + knet_h->sec_hash_size);

		/*
		 * if the crypto mechanism requires padding, calculate the padding
		 * and remove it, to align the data.
		 * NOTE: we need to remove pad_len + 1 because, based on testing,
		 * if we send data that are already aligned to block_size, the
		 * crypto implementations will add another block_size!
		 * so we want to make sure that our data won't add an unnecessary
		 * block_size that we need to remove later.
		 */
		pad_len = outlen % knet_h->sec_block_size;

		outlen = outlen - (pad_len + 1);

		/*
		 * add both hash and salt size back, similar to padding above,
		 * the crypto layer will add them to the outlen
		 */
		outlen = outlen + (knet_h->sec_salt_size + knet_h->sec_hash_size);
	}

	/*
	 * drop KNET_HEADER_ALL_SIZE to provide a clean application MTU
	 * and various crypto headers
	 */
	outlen = outlen - (KNET_HEADER_ALL_SIZE + knet_h->sec_salt_size + knet_h->sec_hash_size);

	return outlen;
}

/*
 * set the lowest possible value as failsafe for all links.
 * KNET_PMTUD_MIN_MTU_V4 < KNET_PMTUD_MIN_MTU_V6
 * KNET_PMTUD_OVERHEAD_V6 > KNET_PMTUD_OVERHEAD_V4
 * KNET_PMTUD_SCTP_OVERHEAD > KNET_PMTUD_UDP_OVERHEAD
 */

size_t calc_min_mtu(knet_handle_t knet_h)
{
	return calc_max_data_outlen(knet_h, KNET_PMTUD_MIN_MTU_V4 - (KNET_PMTUD_OVERHEAD_V6 + KNET_PMTUD_SCTP_OVERHEAD));
}
