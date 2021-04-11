/*
 * Copyright (C) 2019-2021 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
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

int knet_handle_enable_onwire_ver_notify(knet_handle_t knet_h,
					 void *onwire_ver_notify_fn_private_data,
					 void (*onwire_ver_notify_fn) (
						void *private_data,
						uint8_t onwire_min_ver,
						uint8_t onwire_max_ver,
						uint8_t onwire_ver))
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->onwire_ver_notify_fn_private_data = onwire_ver_notify_fn_private_data;
	knet_h->onwire_ver_notify_fn = onwire_ver_notify_fn;
	if (knet_h->onwire_ver_notify_fn) {
		log_debug(knet_h, KNET_SUB_HANDLE, "onwire_ver_notify_fn enabled");
		/*
		 * generate an artificial call to notify the app of what´s curently
		 * happening
		 */
		knet_h->onwire_ver_notify_fn(knet_h->onwire_ver_notify_fn_private_data,
					     knet_h->onwire_min_ver,
					     knet_h->onwire_max_ver,
					     knet_h->onwire_ver);
	} else {
		log_debug(knet_h, KNET_SUB_HANDLE, "onwire_ver_notify_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}

int knet_handle_get_onwire_ver(knet_handle_t knet_h,
			       knet_node_id_t host_id,
			       uint8_t *onwire_min_ver,
			       uint8_t *onwire_max_ver,
			       uint8_t *onwire_ver)
{
	int err = 0, savederrno = 0;
	struct knet_host *host;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!onwire_min_ver) {
		errno = EINVAL;
		return -1;
	}

	if (!onwire_max_ver) {
		errno = EINVAL;
		return -1;
	}

	if (!onwire_ver) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * we need a write lock here so that gathering host onwire info
	 * is not racy (updated by thread_rx) and we can save a mutex_lock
	 * to gather local node info.
	 */
	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (host_id == knet_h->host_id) {
		*onwire_min_ver = knet_h->onwire_min_ver;
		*onwire_max_ver = knet_h->onwire_max_ver;
		*onwire_ver = knet_h->onwire_ver;
	} else {
		host = knet_h->host_index[host_id];
		if (!host) {
			err = -1;
			savederrno = EINVAL;
			log_err(knet_h, KNET_SUB_HANDLE, "Unable to find host %u: %s", host_id, strerror(savederrno));
			goto out_unlock;
		}
		*onwire_min_ver = 0;
		*onwire_max_ver = host->onwire_max_ver;
		*onwire_ver = host->onwire_ver;
	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_handle_set_onwire_ver(knet_handle_t knet_h,
			       uint8_t onwire_ver)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if ((onwire_ver) &&
	    ((onwire_ver < knet_h->onwire_min_ver) ||
	     (onwire_ver > knet_h->onwire_max_ver))) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->onwire_force_ver = onwire_ver;

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	return 0;
}
