/*
 * Copyright (C) 2017-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "internals.h"
#include "compress.h"
#include "compress_model.h"
#include "logging.h"
#include "threads_common.h"
#include "common.h"

/*
 * internal module switch data
 */

/*
 * DO NOT CHANGE MODEL_ID HERE OR ONWIRE COMPATIBILITY
 * WILL BREAK!
 *
 * Always add new items before the last NULL.
 */

static compress_model_t compress_modules_cmds[] = {
	{ "none" , 0, 0, 0, NULL },
	{ "zlib" , 1, WITH_COMPRESS_ZLIB , 0, NULL },
	{ "lz4"  , 2, WITH_COMPRESS_LZ4  , 0, NULL },
	{ "lz4hc", 3, WITH_COMPRESS_LZ4  , 0, NULL },
	{ "lzo2" , 4, WITH_COMPRESS_LZO2 , 0, NULL },
	{ "lzma" , 5, WITH_COMPRESS_LZMA , 0, NULL },
	{ "bzip2", 6, WITH_COMPRESS_BZIP2, 0, NULL },
	{ "zstd" , 7, WITH_COMPRESS_ZSTD, 0, NULL },
	{ NULL, 255, 0, 0, NULL }
};

static int max_model = 0;
static struct timespec last_load_failure;

static int compress_get_model(const char *model)
{
	int idx = 0;

	while (compress_modules_cmds[idx].model_name != NULL) {
		if (!strcmp(compress_modules_cmds[idx].model_name, model)) {
			return compress_modules_cmds[idx].model_id;
		}
		idx++;
	}
	return -1;
}

static int compress_get_max_model(void)
{
	int idx = 0;
	while (compress_modules_cmds[idx].model_name != NULL) {
		idx++;
	}
	return idx - 1;
}

static int compress_is_valid_model(int compress_model)
{
	int idx = 0;

	while (compress_modules_cmds[idx].model_name != NULL) {
		if ((compress_model == compress_modules_cmds[idx].model_id) &&
		    (compress_modules_cmds[idx].built_in == 1)) {
			return 0;
		}
		idx++;
	}
	return -1;
}

static int val_level(
	knet_handle_t knet_h,
	int compress_model,
	int compress_level)
{
	if (compress_modules_cmds[compress_model].ops->val_level != NULL) {
		return compress_modules_cmds[compress_model].ops->val_level(knet_h, compress_level);
	}
	return 0;
}

/*
 * compress_check_lib_is_init needs to be invoked in a locked context!
 */
static int compress_check_lib_is_init(knet_handle_t knet_h, int cmp_model)
{
	/*
	 * lack of a .is_init function means that the module does not require
	 * init per handle so we use a fake reference in the compress_int_data
	 * to identify that we already increased the libref for this handle
	 */
	if (compress_modules_cmds[cmp_model].loaded == 1) {
		if (compress_modules_cmds[cmp_model].ops->is_init == NULL) {
			if (knet_h->compress_int_data[cmp_model] != NULL) {
				return 1;
			}
		} else {
			if (compress_modules_cmds[cmp_model].ops->is_init(knet_h, cmp_model) == 1) {
				return 1;
			}
		}
	}

	return 0;
}

/*
 * compress_load_lib should _always_ be invoked in write lock context
 */
static int compress_load_lib(knet_handle_t knet_h, int cmp_model, int rate_limit)
{
	struct timespec clock_now;
	unsigned long long timediff;

	/*
	 * checking again for paranoia and because
	 * compress_check_lib_is_init is usually invoked in read context
	 * and we need to switch from read to write locking in between.
	 * another thread might have init the library in the meantime
	 */
	if (compress_check_lib_is_init(knet_h, cmp_model)) {
		return 0;
	}

	/*
	 * due to the fact that decompress can load libraries
	 * on demand, depending on the compress model selected
	 * on other nodes, it is possible for an attacker
	 * to send crafted packets to attempt to load libraries
	 * at random in a DoS fashion.
	 * If there is an error loading a library, then we want
	 * to rate_limit a retry to reload the library every X
	 * seconds to avoid a lock DoS that could greatly slow
	 * down libknet.
	 */
	if (rate_limit) {
		if ((last_load_failure.tv_sec != 0) ||
		    (last_load_failure.tv_nsec != 0)) {
			clock_gettime(CLOCK_MONOTONIC, &clock_now);
			timespec_diff(last_load_failure, clock_now, &timediff);
			if (timediff < 10000000000) {
				errno = EAGAIN;
				return -1;
			}
		}
	}

	if (compress_modules_cmds[cmp_model].loaded == 0) {
		compress_modules_cmds[cmp_model].ops = load_module (knet_h, "compress", compress_modules_cmds[cmp_model].model_name);
		if (!compress_modules_cmds[cmp_model].ops) {
			clock_gettime(CLOCK_MONOTONIC, &last_load_failure);
			return -1;
		}
		if (compress_modules_cmds[cmp_model].ops->abi_ver != KNET_COMPRESS_MODEL_ABI) {
			log_err(knet_h, KNET_SUB_COMPRESS,
				"ABI mismatch loading module %s. knet ver: %d, module ver: %d",
				compress_modules_cmds[cmp_model].model_name, KNET_COMPRESS_MODEL_ABI,
				compress_modules_cmds[cmp_model].ops->abi_ver);
			errno = EINVAL;
			return -1;
		}
		compress_modules_cmds[cmp_model].loaded = 1;
	}

	if (compress_modules_cmds[cmp_model].ops->init != NULL) {
		if (compress_modules_cmds[cmp_model].ops->init(knet_h, cmp_model) < 0) {
			return -1;
		}
	} else {
		knet_h->compress_int_data[cmp_model] = (void *)&"1";
	}

	return 0;
}

static int compress_lib_test(knet_handle_t knet_h)
{
	int savederrno = 0;
	unsigned char src[KNET_DATABUFSIZE];
	unsigned char dst[KNET_DATABUFSIZE_COMPRESS];
	ssize_t dst_comp_len = KNET_DATABUFSIZE_COMPRESS, dst_decomp_len = KNET_DATABUFSIZE;
	unsigned int i;
	int request_level;

	memset(src, 0, KNET_DATABUFSIZE);
	memset(dst, 0, KNET_DATABUFSIZE_COMPRESS);

	/*
	 * NOTE: we cannot use compress and decompress API calls due to locking
	 * so we need to call directly into the modules
	 */

	if (compress_modules_cmds[knet_h->compress_model].ops->compress(knet_h, src, KNET_DATABUFSIZE, dst, &dst_comp_len) < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_COMPRESS, "Unable to compress test buffer. Please check your compression settings: %s", strerror(savederrno));
		errno = savederrno;
		return -1;
	} else if ((long unsigned int)dst_comp_len >= KNET_DATABUFSIZE) {
		/*
		 * compress not effective, try again using default compression level when available
		 */
		request_level = knet_h->compress_level;
		log_warn(knet_h, KNET_SUB_COMPRESS, "Requested compression level (%d) did not generate any compressed data (source: %zu destination: %zu)",
				request_level, sizeof(src), dst_comp_len);

		if ((!compress_modules_cmds[knet_h->compress_model].ops->get_default_level()) ||
				((knet_h->compress_level = compress_modules_cmds[knet_h->compress_model].ops->get_default_level()) == KNET_COMPRESS_UNKNOWN_DEFAULT)) {
                        log_err(knet_h, KNET_SUB_COMPRESS, "compression %s does not provide a default value",
					compress_modules_cmds[knet_h->compress_model].model_name);
			return -1;
                } else {
			memset(src, 0, KNET_DATABUFSIZE);
			memset(dst, 0, KNET_DATABUFSIZE_COMPRESS);
			dst_comp_len = KNET_DATABUFSIZE_COMPRESS;
			if (compress_modules_cmds[knet_h->compress_model].ops->compress(knet_h, src, KNET_DATABUFSIZE, dst, &dst_comp_len) < 0) {
                                savederrno = errno;
                                log_err(knet_h, KNET_SUB_COMPRESS, "Unable to compress with default compression level: %s", strerror(savederrno));
				errno = savederrno;
				return -1;
			}
			log_warn(knet_h, KNET_SUB_COMPRESS, "Requested compression level (%d) did not work, switching to default (%d)",
					request_level, knet_h->compress_level);
		}
	}

	if (compress_modules_cmds[knet_h->compress_model].ops->decompress(knet_h, dst, dst_comp_len, src, &dst_decomp_len) < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_COMPRESS, "Unable to decompress test buffer. Please check your compression settings: %s", strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	for (i = 0; i < KNET_DATABUFSIZE; i++) {
		if (src[i] != 0) {
			log_err(knet_h, KNET_SUB_COMPRESS, "Decompressed buffer contains incorrect data");
			errno = EINVAL;
			return -1;
		}
	}

	return 0;
}

int compress_init(
	knet_handle_t knet_h)
{
	max_model = compress_get_max_model();
	if (max_model > KNET_MAX_COMPRESS_METHODS) {
		log_err(knet_h, KNET_SUB_COMPRESS, "Too many compress methods defined in compress.c.");
		errno = EINVAL;
		return -1;
	}

	memset(&last_load_failure, 0, sizeof(struct timespec));

	return 0;
}

int compress_cfg(
	knet_handle_t knet_h,
	struct knet_handle_compress_cfg *knet_handle_compress_cfg)
{
	int savederrno = 0, err = 0;
	int cmp_model;

	cmp_model = compress_get_model(knet_handle_compress_cfg->compress_model);
	if (cmp_model < 0) {
		log_err(knet_h, KNET_SUB_COMPRESS, "compress model %s not supported", knet_handle_compress_cfg->compress_model);
		errno = EINVAL;
		return -1;
	}

	log_debug(knet_h, KNET_SUB_COMPRESS,
		  "Initizializing compress module [%s/%d/%u]",
		  knet_handle_compress_cfg->compress_model, knet_handle_compress_cfg->compress_level, knet_handle_compress_cfg->compress_threshold);

	if (cmp_model > 0) {
		if (compress_modules_cmds[cmp_model].built_in == 0) {
			log_err(knet_h, KNET_SUB_COMPRESS, "compress model %s support has not been built in. Please contact your vendor or fix the build", knet_handle_compress_cfg->compress_model);
			errno = EINVAL;
			return -1;
		}

		if (knet_handle_compress_cfg->compress_threshold > KNET_MAX_PACKET_SIZE) {
			log_err(knet_h, KNET_SUB_COMPRESS, "compress threshold cannot be higher than KNET_MAX_PACKET_SIZE (%d).",
				 KNET_MAX_PACKET_SIZE);
			errno = EINVAL;
			return -1;
		}

		if (knet_handle_compress_cfg->compress_threshold == 0) {
			knet_h->compress_threshold = KNET_COMPRESS_THRESHOLD;
			log_debug(knet_h, KNET_SUB_COMPRESS, "resetting compression threshold to default (%d)", KNET_COMPRESS_THRESHOLD);
		} else {
			knet_h->compress_threshold = knet_handle_compress_cfg->compress_threshold;
		}

		savederrno = pthread_rwlock_rdlock(&shlib_rwlock);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_COMPRESS, "Unable to get read lock: %s",
				strerror(savederrno));
			errno = savederrno;
			return -1;
		}

		if (!compress_check_lib_is_init(knet_h, cmp_model)) {
			/*
			 * need to switch to write lock, load the lib, and return with a write lock
			 * this is not racy because compress_load_lib is written idempotent.
			 */
			pthread_rwlock_unlock(&shlib_rwlock);
			savederrno = pthread_rwlock_wrlock(&shlib_rwlock);
			if (savederrno) {
				log_err(knet_h, KNET_SUB_COMPRESS, "Unable to get write lock: %s",
					strerror(savederrno));
				errno = savederrno;
				return -1;
			}

			if (compress_load_lib(knet_h, cmp_model, 0) < 0) {
				savederrno = errno;
				log_err(knet_h, KNET_SUB_COMPRESS, "Unable to load library: %s",
					strerror(savederrno));
				err = -1;
				goto out_unlock;
			}
		}

		if (val_level(knet_h, cmp_model, knet_handle_compress_cfg->compress_level) < 0) {
			log_err(knet_h, KNET_SUB_COMPRESS, "compress level %d not supported for model %s",
				knet_handle_compress_cfg->compress_level, knet_handle_compress_cfg->compress_model);
			savederrno = EINVAL;
			err = -1;
			goto out_unlock;
		}

		knet_h->compress_model = cmp_model;
		knet_h->compress_level = knet_handle_compress_cfg->compress_level;

		if (compress_lib_test(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			goto out_unlock;
		}

out_unlock:
		pthread_rwlock_unlock(&shlib_rwlock);
	}

	if (err) {
		knet_h->compress_model = 0;
		knet_h->compress_level = 0;
	}

	errno = savederrno;
	return err;
}

void compress_fini(
	knet_handle_t knet_h,
	int all)
{
	int savederrno = 0;
	int idx = 0;

	savederrno = pthread_rwlock_wrlock(&shlib_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_COMPRESS, "Unable to get write lock: %s",
			strerror(savederrno));
		return;
	}

	while (compress_modules_cmds[idx].model_name != NULL) {
		if ((idx < KNET_MAX_COMPRESS_METHODS) && /* check idx first so we don't read bad data */
		    (compress_modules_cmds[idx].built_in == 1) &&
		    (compress_modules_cmds[idx].loaded == 1) &&
		    (compress_modules_cmds[idx].model_id > 0) &&
		    (knet_h->compress_int_data[idx] != NULL)) {
			if ((all) || (compress_modules_cmds[idx].model_id == knet_h->compress_model)) {
				if (compress_modules_cmds[idx].ops->fini != NULL) {
					compress_modules_cmds[idx].ops->fini(knet_h, idx);
				} else {
					knet_h->compress_int_data[idx] = NULL;
				}
			}
		}
		idx++;
	}

	pthread_rwlock_unlock(&shlib_rwlock);
	return;
}

/*
 * compress does not require compress_check_lib_is_init
 * because it's protected by compress_cfg
 */
int compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return compress_modules_cmds[knet_h->compress_model].ops->compress(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

int decompress(
	knet_handle_t knet_h,
	int compress_model,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int savederrno = 0, err = 0;

	if (compress_model > max_model) {
		log_err(knet_h,  KNET_SUB_COMPRESS, "Received packet with unknown compress model %d", compress_model);
		errno = EINVAL;
		return -1;
	}

	if (compress_is_valid_model(compress_model) < 0) {
		log_err(knet_h,  KNET_SUB_COMPRESS, "Received packet compressed with %s but support is not built in this version of libknet. Please contact your distribution vendor or fix the build.", compress_modules_cmds[compress_model].model_name);
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&shlib_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_COMPRESS, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!compress_check_lib_is_init(knet_h, compress_model)) {
		/*
		 * need to switch to write lock, load the lib, and return with a write lock
		 * this is not racy because compress_load_lib is written idempotent.
		 */
		pthread_rwlock_unlock(&shlib_rwlock);
		savederrno = pthread_rwlock_wrlock(&shlib_rwlock);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_COMPRESS, "Unable to get write lock: %s",
				strerror(savederrno));
			errno = savederrno;
			return -1;
		}

		if (compress_load_lib(knet_h, compress_model, 1) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_COMPRESS, "Unable to load library: %s",
				strerror(savederrno));
			goto out_unlock;
		}
	}

	err = compress_modules_cmds[compress_model].ops->decompress(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
	savederrno = errno;

out_unlock:
	pthread_rwlock_unlock(&shlib_rwlock);

	errno = savederrno;
	return err;
}

int knet_get_compress_list(struct knet_compress_info *compress_list, size_t *compress_list_entries)
{
	int err = 0;
	int idx = 0;
	int outidx = 0;

	if (!compress_list_entries) {
		errno = EINVAL;
		return -1;
	}

	while (compress_modules_cmds[idx].model_name != NULL) {
		if (compress_modules_cmds[idx].built_in) {
			if (compress_list) {
				compress_list[outidx].name = compress_modules_cmds[idx].model_name;
			}
			outidx++;
		}
		idx++;
	}
	*compress_list_entries = outidx;

	if (!err)
		errno = 0;
	return err;
}
