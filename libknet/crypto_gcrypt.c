/*
 * Copyright (C) 2017-2020 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>

/*
 * make sure NOT to use deprecated API
 */
#define GCRYPTO_NO_DEPRECATED 1

#define NEED_LIBGCRYPT_VERSION "1.8.0"

#include <gcrypt.h>

#include "logging.h"
#include "crypto_model.h"

/*
 * crypto definitions and conversion tables
 */

#define SALT_SIZE 16

/*
 * gcrypt rejects private key len > crypto max keylen. openssl/nss automatically trim the key.
 * we need to store a crypto key len and a hash keylen separately
 * and crypto key len is trimmed automatically at gcrypt_init time.
 */

struct gcryptcrypto_instance {
	void *private_key;
	size_t crypt_private_key_len;
	size_t hash_private_key_len;
	int crypto_cipher_type;
	int crypto_hash_type;
};

static int gcrypt_is_init = 0;

/*
 * crypt/decrypt functions
 */

static int encrypt_gcrypt(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct gcryptcrypto_instance *instance = crypto_instance->model_instance;
	gcry_error_t	 gerr;
	gcry_cipher_hd_t handle = NULL;
	int		 err = 0;
	int		 i;
	unsigned char	 *salt = buf_out;
	size_t		 output_len = 0, pad_len = 0;
	unsigned char	 inbuf[KNET_DATABUFSIZE_CRYPT];
	unsigned char	 *data = buf_out + SALT_SIZE;

	gerr = gcry_cipher_open(&handle, instance->crypto_cipher_type, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to allocate gcrypt cipher context: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_cipher_setkey(handle, instance->private_key, instance->crypt_private_key_len);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to load private key: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gcry_randomize(salt, SALT_SIZE, GCRY_VERY_STRONG_RANDOM);

	gerr = gcry_cipher_setiv(handle, salt, SALT_SIZE);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to load init vector: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	/*
	 * libgcrypt requires an input buffer that is
	 * already aligned to block size.
	 * The easiest way is to build the data in
	 * a dedicated buffer
	 */
	output_len = 0;
	for (i=0; i<iovcnt; i++) {
		memcpy(inbuf + output_len, iov[i].iov_base, iov[i].iov_len);
		output_len = output_len + iov[i].iov_len;
	}

	/*
	 * init the pad buffer (PKCS# standard)
	 * https://en.m.wikipedia.org/wiki/Padding_(cryptography)
	 */

	pad_len = (crypto_instance->sec_block_size - (output_len % crypto_instance->sec_block_size));

	memset(inbuf + output_len, pad_len, pad_len);

	output_len = output_len + pad_len;

	/*
	 * some ciphers methods require _final to be called
	 * before the last call to _encrypt, for example when
	 * encrypting big chunks of data split in multiple buffers.
	 * knet only has one buffer, so we can safely call _final here.
	 * adding a comment as the code looks backwards compared to other
	 * cipher implementations that do final _after_ encrypting the last block
	 */
	gcry_cipher_final(handle);

	gerr = gcry_cipher_encrypt(handle,
				   data, output_len,
				   inbuf, output_len);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to encrypt data: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	*buf_out_len = output_len + SALT_SIZE;

out_err:
	if (handle) {
		gcry_cipher_close(handle);
	}
	return err;
}

static int decrypt_gcrypt(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len,
	uint8_t log_level)
{
	struct gcryptcrypto_instance *instance = crypto_instance->model_instance;
	gcry_error_t	 gerr;
	gcry_cipher_hd_t handle = NULL;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = 0;

	if (datalen <= 0) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "Packet is too short");
		err = -1;
		goto out_err;
	}

	gerr = gcry_cipher_open(&handle, instance->crypto_cipher_type, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to allocate gcrypt cipher context: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_cipher_setkey(handle, instance->private_key, instance->crypt_private_key_len);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to load private key: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_cipher_setiv(handle, salt, SALT_SIZE);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to load init vector: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_cipher_decrypt(handle,
				   buf_out, KNET_DATABUFSIZE_CRYPT,
				   data, datalen);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to decrypt data: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	/*
	 * drop the padding size based on PCKS standards
	 * (see also crypt above)
	 */
	*buf_out_len = datalen - buf_out[datalen - 1];

out_err:
	if (handle) {
		gcry_cipher_close(handle);
	}
	return err;
}

/*
 * hash/hmac/digest functions
 */

static int calculate_gcrypt_hash(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash,
	uint8_t log_level)
{
	struct gcryptcrypto_instance *instance = crypto_instance->model_instance;
	gcry_error_t gerr;
	gcry_mac_hd_t handle = NULL;
	int err = 0;
	size_t outlen = crypto_instance->sec_hash_size;

	gerr = gcry_mac_open(&handle, instance->crypto_hash_type, GCRY_MAC_FLAG_SECURE, 0);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to allocate gcrypt hmac context: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_mac_setkey(handle, instance->private_key, instance->hash_private_key_len);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to set gcrypt hmac key: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_mac_write(handle, buf, buf_len);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to calculate gcrypt hmac: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

	gerr = gcry_mac_read(handle, hash, &outlen);
	if (gerr) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
			"Unable to retrive gcrypt hmac: %s/%s",
			gcry_strsource(gerr), gcry_strerror(gerr));
		err = -1;
		goto out_err;
	}

out_err:
	if (handle) {
		gcry_mac_close(handle);
	}

	return err;
}

/*
 * exported API
 */

static int gcryptcrypto_encrypt_and_signv (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct gcryptcrypto_instance *instance = crypto_instance->model_instance;
	int i;

	if (instance->crypto_cipher_type) {
		if (encrypt_gcrypt(knet_h, crypto_instance, iov_in, iovcnt_in, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		*buf_out_len = 0;
		for (i=0; i<iovcnt_in; i++) {
			memmove(buf_out + *buf_out_len, iov_in[i].iov_base, iov_in[i].iov_len);
			*buf_out_len = *buf_out_len + iov_in[i].iov_len;
		}
	}

	if (instance->crypto_hash_type) {
		if (calculate_gcrypt_hash(knet_h, crypto_instance, buf_out, *buf_out_len, buf_out + *buf_out_len, KNET_LOG_ERR) < 0) {
			return -1;
		}
		*buf_out_len = *buf_out_len + crypto_instance->sec_hash_size;
	}

	return 0;
}

static int gcryptcrypto_encrypt_and_sign (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct iovec iov_in;

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (unsigned char *)buf_in;
	iov_in.iov_len = buf_in_len;

	return gcryptcrypto_encrypt_and_signv(knet_h, crypto_instance, &iov_in, 1, buf_out, buf_out_len);
}

static int gcryptcrypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len,
	uint8_t log_level)
{
	struct gcryptcrypto_instance *instance = crypto_instance->model_instance;
	ssize_t temp_len = buf_in_len;

	if (instance->crypto_hash_type) {
		unsigned char tmp_hash[crypto_instance->sec_hash_size];
		ssize_t temp_buf_len = buf_in_len - crypto_instance->sec_hash_size;

		if ((temp_buf_len <= 0) || (temp_buf_len > KNET_MAX_PACKET_SIZE)) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "Incorrect packet size.");
			return -1;
		}

		if (calculate_gcrypt_hash(knet_h, crypto_instance, buf_in, temp_buf_len, tmp_hash, log_level) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf_in + temp_buf_len, crypto_instance->sec_hash_size) != 0) {
			if (log_level == KNET_LOG_DEBUG) {
				log_debug(knet_h, KNET_SUB_GCRYPTCRYPTO, "Digest does not match");
			} else {
				log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "Digest does not match");
			}
			return -1;
		}

		temp_len = temp_len - crypto_instance->sec_hash_size;
		*buf_out_len = temp_len;
	}
	if (instance->crypto_cipher_type) {
		if (decrypt_gcrypt(knet_h, crypto_instance, buf_in, temp_len, buf_out, buf_out_len, log_level) < 0) {
			return -1;
		}
	} else {
		memmove(buf_out, buf_in, temp_len);
		*buf_out_len = temp_len;
	}

	return 0;
}

static void gcryptcrypto_fini(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance)
{
	struct gcryptcrypto_instance *gcryptcrypto_instance = crypto_instance->model_instance;

	if (gcryptcrypto_instance) {
		if (gcryptcrypto_instance->private_key) {
			free(gcryptcrypto_instance->private_key);
			gcryptcrypto_instance->private_key = NULL;
		}
		free(gcryptcrypto_instance);
		crypto_instance->model_instance = NULL;
	}

	return;
}

static int gcryptcrypto_init(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	struct gcryptcrypto_instance *gcryptcrypto_instance = NULL;
	gcry_error_t gerr;
	int savederrno;
	/*
	 * gcrypt name to ID mapping requires HMAC_ in the name.
	 * so for example to use SHA1, the name should be HMAC_SHA1
	 * that makes it not compatible with nss/openssl naming.
	 * make sure to add HMAC_ transparently so that changing crypto config
	 * can be done transparently.
	 */
	char remap_hash_type[sizeof(knet_handle_crypto_cfg->crypto_hash_type) + strlen("HMAC_") + 1];

	log_debug(knet_h, KNET_SUB_GCRYPTCRYPTO,
		  "Initizializing gcrypt crypto module [%s/%s]",
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	if (!gcrypt_is_init) {
		if (!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"libgcrypt is too old (need %s, have %s)",
				NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
			errno = EINVAL;
			return -1;
		}

		gerr = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
		if (gerr) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"Unable to suppress sec mem warnings: %s/%s",
				gcry_strsource(gerr), gcry_strerror(gerr));
			errno = EINVAL;
			return -1;
		}

		gerr = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
		if (gerr) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"Unable to init sec mem: %s/%s",
				gcry_strsource(gerr), gcry_strerror(gerr));
			errno = ENOMEM;
			return -1;
		}

		gerr = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
		if (gerr) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"Unable to restore sec mem warnings: %s/%s",
				gcry_strsource(gerr), gcry_strerror(gerr));
			errno = EINVAL;
			return -1;
		}

		gerr = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
		if (gerr) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"Unable to notify gcrypt that init is completed: %s/%s",
				gcry_strsource(gerr), gcry_strerror(gerr));
			errno = EINVAL;
			return -1;
		}

		if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO,
				"gcrypt could not initialize properly");
			errno = EINVAL;
			return -1;
		}

		gcrypt_is_init = 1;
	}

	crypto_instance->model_instance = malloc(sizeof(struct gcryptcrypto_instance));
	if (!crypto_instance->model_instance) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "Unable to allocate memory for gcrypt model instance");
		errno = ENOMEM;
		return -1;
	}

	gcryptcrypto_instance = crypto_instance->model_instance;

	memset(gcryptcrypto_instance, 0, sizeof(struct gcryptcrypto_instance));

	gcryptcrypto_instance->private_key = malloc(knet_handle_crypto_cfg->private_key_len);
	if (!gcryptcrypto_instance->private_key) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "Unable to allocate memory for gcrypt private key");
		savederrno = ENOMEM;
		goto out_err;
	}
	memmove(gcryptcrypto_instance->private_key, knet_handle_crypto_cfg->private_key, knet_handle_crypto_cfg->private_key_len);

	if (strcmp(knet_handle_crypto_cfg->crypto_cipher_type, "none") == 0) {
		gcryptcrypto_instance->crypto_cipher_type = 0;
	} else {
		gcryptcrypto_instance->crypto_cipher_type = gcry_cipher_map_name(knet_handle_crypto_cfg->crypto_cipher_type);
		if (!gcryptcrypto_instance->crypto_cipher_type) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "unknown crypto cipher type requested");
			savederrno = EINVAL;
			goto out_err;
		}
		if (gcry_cipher_test_algo(gcryptcrypto_instance->crypto_cipher_type)) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "requested crypto cipher type not available for use");
			savederrno = EINVAL;
			goto out_err;
		}
		if (gcry_cipher_get_algo_keylen(gcryptcrypto_instance->crypto_cipher_type) < knet_handle_crypto_cfg->private_key_len) {
			log_warn(knet_h, KNET_SUB_GCRYPTCRYPTO, "requested crypto cipher key len (%u) too big (max: %zu)",
				 knet_handle_crypto_cfg->private_key_len, gcry_cipher_get_algo_keylen(gcryptcrypto_instance->crypto_cipher_type));
			gcryptcrypto_instance->crypt_private_key_len = gcry_cipher_get_algo_keylen(gcryptcrypto_instance->crypto_cipher_type);
		} else {
			gcryptcrypto_instance->crypt_private_key_len = knet_handle_crypto_cfg->private_key_len;
		}

	}

	if (strcmp(knet_handle_crypto_cfg->crypto_hash_type, "none") == 0) {
		gcryptcrypto_instance->crypto_hash_type = 0;
	} else {
		if (!strncasecmp(knet_handle_crypto_cfg->crypto_hash_type, "HMAC_", strlen("HMAC_"))) {
			strncpy(remap_hash_type, knet_handle_crypto_cfg->crypto_hash_type, sizeof(remap_hash_type) - 1);
		} else {
			snprintf(remap_hash_type, sizeof(remap_hash_type) - 1, "%s%s", "HMAC_", knet_handle_crypto_cfg->crypto_hash_type);
		}
		gcryptcrypto_instance->crypto_hash_type = gcry_mac_map_name(remap_hash_type);
		if (!gcryptcrypto_instance->crypto_hash_type) {
			savederrno = EINVAL;
			goto out_err;
		}
		if (gcry_mac_test_algo(gcryptcrypto_instance->crypto_hash_type)) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "requested crypto hash type not available for use");
			savederrno = EINVAL;
			goto out_err;
		}
		gcryptcrypto_instance->hash_private_key_len = knet_handle_crypto_cfg->private_key_len;
	}

	if ((gcryptcrypto_instance->crypto_cipher_type) &&
	    (!gcryptcrypto_instance->crypto_hash_type)) {
		log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "crypto communication requires hash specified");
		savederrno = EINVAL;
		goto out_err;
	}

	if (gcryptcrypto_instance->crypto_hash_type) {
		crypto_instance->sec_hash_size = gcry_mac_get_algo_maclen(gcryptcrypto_instance->crypto_hash_type);
		if (!crypto_instance->sec_hash_size) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "unable to gather hash digest size");
			savederrno = EINVAL;
			goto out_err;
		}
	}

	if (gcryptcrypto_instance->crypto_cipher_type) {
		size_t block_size;

		block_size = gcry_cipher_get_algo_blklen(gcryptcrypto_instance->crypto_cipher_type);
		if (!block_size) {
			log_err(knet_h, KNET_SUB_GCRYPTCRYPTO, "unable to gather cipher blocksize");
			savederrno = EINVAL;
			goto out_err;
		}

		crypto_instance->sec_salt_size = SALT_SIZE;
		crypto_instance->sec_block_size = block_size;
	}

	return 0;

out_err:
	gcryptcrypto_fini(knet_h, crypto_instance);

	errno = savederrno;
	return -1;
}

crypto_ops_t crypto_model = {
	KNET_CRYPTO_MODEL_ABI,
	gcryptcrypto_init,
	gcryptcrypto_fini,
	gcryptcrypto_encrypt_and_sign,
	gcryptcrypto_encrypt_and_signv,
	gcryptcrypto_authenticate_and_decrypt
};
