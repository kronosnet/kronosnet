/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <nss.h>
#include <pk11pub.h>
#include <pkcs11.h>
#include <prerror.h>
#include <blapit.h>
#include <hasht.h>

#include "crypto.h"
#include "nsscrypto.h"
#include "logging.h"

/*
 * crypto definitions and conversion tables
 */

#define SALT_SIZE 16

/*
 * This are defined in new NSS. For older one, we will define our own
 */
#ifndef AES_256_KEY_LENGTH
#define AES_256_KEY_LENGTH 32
#endif

#ifndef AES_192_KEY_LENGTH
#define AES_192_KEY_LENGTH 24
#endif

#ifndef AES_128_KEY_LENGTH
#define AES_128_KEY_LENGTH 16
#endif

enum crypto_crypt_t {
	CRYPTO_CIPHER_TYPE_NONE = 0,
	CRYPTO_CIPHER_TYPE_AES256 = 1,
	CRYPTO_CIPHER_TYPE_AES192 = 2,
	CRYPTO_CIPHER_TYPE_AES128 = 3,
	CRYPTO_CIPHER_TYPE_3DES = 4
};

CK_MECHANISM_TYPE cipher_to_nss[] = {
	0,				/* CRYPTO_CIPHER_TYPE_NONE */
	CKM_AES_CBC_PAD,		/* CRYPTO_CIPHER_TYPE_AES256 */
	CKM_AES_CBC_PAD,		/* CRYPTO_CIPHER_TYPE_AES192 */
	CKM_AES_CBC_PAD,		/* CRYPTO_CIPHER_TYPE_AES128 */
	CKM_DES3_CBC_PAD 		/* CRYPTO_CIPHER_TYPE_3DES */
};

size_t cipher_key_len[] = {
	0,				/* CRYPTO_CIPHER_TYPE_NONE */
	AES_256_KEY_LENGTH,		/* CRYPTO_CIPHER_TYPE_AES256 */
	AES_192_KEY_LENGTH,		/* CRYPTO_CIPHER_TYPE_AES192 */
	AES_128_KEY_LENGTH,		/* CRYPTO_CIPHER_TYPE_AES128 */
	24				/* CRYPTO_CIPHER_TYPE_3DES */
};

size_t cypher_block_len[] = {
	0,				/* CRYPTO_CIPHER_TYPE_NONE */
	AES_BLOCK_SIZE,			/* CRYPTO_CIPHER_TYPE_AES256 */
	AES_BLOCK_SIZE,			/* CRYPTO_CIPHER_TYPE_AES192 */
	AES_BLOCK_SIZE,			/* CRYPTO_CIPHER_TYPE_AES128 */
	0				/* CRYPTO_CIPHER_TYPE_3DES */
};

/*
 * hash definitions and conversion tables
 */

enum crypto_hash_t {
	CRYPTO_HASH_TYPE_NONE	= 0,
	CRYPTO_HASH_TYPE_MD5	= 1,
	CRYPTO_HASH_TYPE_SHA1	= 2,
	CRYPTO_HASH_TYPE_SHA256	= 3,
	CRYPTO_HASH_TYPE_SHA384	= 4,
	CRYPTO_HASH_TYPE_SHA512	= 5
};

CK_MECHANISM_TYPE hash_to_nss[] = {
	 0,				/* CRYPTO_HASH_TYPE_NONE */
	CKM_MD5_HMAC,			/* CRYPTO_HASH_TYPE_MD5 */
	CKM_SHA_1_HMAC,			/* CRYPTO_HASH_TYPE_SHA1 */
	CKM_SHA256_HMAC,		/* CRYPTO_HASH_TYPE_SHA256 */
	CKM_SHA384_HMAC,		/* CRYPTO_HASH_TYPE_SHA384 */
	CKM_SHA512_HMAC			/* CRYPTO_HASH_TYPE_SHA512 */
};

size_t hash_len[] = {
	 0,				/* CRYPTO_HASH_TYPE_NONE */
	MD5_LENGTH,			/* CRYPTO_HASH_TYPE_MD5 */
	SHA1_LENGTH,			/* CRYPTO_HASH_TYPE_SHA1 */
	SHA256_LENGTH,			/* CRYPTO_HASH_TYPE_SHA256 */
	SHA384_LENGTH,			/* CRYPTO_HASH_TYPE_SHA384 */
	SHA512_LENGTH			/* CRYPTO_HASH_TYPE_SHA512 */
};

size_t hash_block_len[] = {
	 0,				/* CRYPTO_HASH_TYPE_NONE */
	MD5_BLOCK_LENGTH,		/* CRYPTO_HASH_TYPE_MD5 */
	SHA1_BLOCK_LENGTH,		/* CRYPTO_HASH_TYPE_SHA1 */
	SHA256_BLOCK_LENGTH,		/* CRYPTO_HASH_TYPE_SHA256 */
	SHA384_BLOCK_LENGTH,		/* CRYPTO_HASH_TYPE_SHA384 */
	SHA512_BLOCK_LENGTH		/* CRYPTO_HASH_TYPE_SHA512 */
};

struct nsscrypto_instance {
	PK11SymKey   *nss_sym_key;
	PK11SymKey   *nss_sym_key_sign;

	unsigned char *private_key;

	unsigned int private_key_len;

	int crypto_cipher_type;

	int crypto_hash_type;
};

/*
 * crypt/decrypt functions
 */

static int string_to_crypto_cipher_type(const char* crypto_cipher_type)
{
	if (strcmp(crypto_cipher_type, "none") == 0) {
		return CRYPTO_CIPHER_TYPE_NONE;
	} else if (strcmp(crypto_cipher_type, "aes256") == 0) {
		return CRYPTO_CIPHER_TYPE_AES256;
	} else if (strcmp(crypto_cipher_type, "aes192") == 0) {
		return CRYPTO_CIPHER_TYPE_AES192;
	} else if (strcmp(crypto_cipher_type, "aes128") == 0) {
		return CRYPTO_CIPHER_TYPE_AES128;
	} else if (strcmp(crypto_cipher_type, "3des") == 0) {
		return CRYPTO_CIPHER_TYPE_3DES;
	}
	return -1;
}

static int init_nss_crypto(knet_handle_t knet_h)
{
	PK11SlotInfo*	crypt_slot = NULL;
	SECItem		crypt_param;
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (!cipher_to_nss[instance->crypto_cipher_type]) {
		return 0;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = instance->private_key;
	crypt_param.len = cipher_key_len[instance->crypto_cipher_type];

	crypt_slot = PK11_GetBestSlot(cipher_to_nss[instance->crypto_cipher_type], NULL);
	if (crypt_slot == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to find security slot (err %d)",
			   PR_GetError());
		return -1;
	}

	instance->nss_sym_key = PK11_ImportSymKey(crypt_slot,
						  cipher_to_nss[instance->crypto_cipher_type],
						  PK11_OriginUnwrap, CKA_ENCRYPT|CKA_DECRYPT,
						  &crypt_param, NULL);
	if (instance->nss_sym_key == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to import key into NSS (err %d)",
			   PR_GetError());
		return -1;
	}

	PK11_FreeSlot(crypt_slot);

	return 0;
}

static int encrypt_nss(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	PK11Context*	crypt_context = NULL;
	SECItem		crypt_param;
	SECItem		*nss_sec_param = NULL;
	int		tmp1_outlen = 0;
	unsigned int	tmp2_outlen = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = -1;

	if (PK11_GenerateRandom (salt, SALT_SIZE) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to generate a random number %d",
			   PR_GetError());
		goto out;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = salt;
	crypt_param.len = SALT_SIZE;

	nss_sec_param = PK11_ParamFromIV (cipher_to_nss[instance->crypto_cipher_type],
					  &crypt_param);
	if (nss_sec_param == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to set up PKCS11 param (err %d)",
			   PR_GetError());
		goto out;
	}

	/*
	 * Create cipher context for encryption
	 */
	crypt_context = PK11_CreateContextBySymKey (cipher_to_nss[instance->crypto_cipher_type],
						    CKA_ENCRYPT,
						    instance->nss_sym_key,
						    nss_sec_param);
	if (!crypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (encrypt) crypt_type=%d (err %d)",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_CipherOp(crypt_context, data,
			  &tmp1_outlen,
			  KNET_DATABUFSIZE_CRYPT,
			  (unsigned char *)buf_in, buf_in_len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp failed (encrypt) crypt_type=%d (err %d)",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(crypt_context, data + tmp1_outlen,
			     &tmp2_outlen, KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal failed (encrypt) crypt_type=%d (err %d)",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError());
		goto out;

	}

	*buf_out_len = tmp1_outlen + tmp2_outlen + SALT_SIZE;

	err = 0;

out:
	if (crypt_context) {
		PK11_DestroyContext(crypt_context, PR_TRUE);
	}
	if (nss_sec_param) {
		SECITEM_FreeItem(nss_sec_param, PR_TRUE);
	}
	return err;
}

static int decrypt_nss (
	knet_handle_t knet_h,
	unsigned char *buf,
	ssize_t *buf_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	PK11Context*	decrypt_context = NULL;
	SECItem		decrypt_param;
	int		tmp1_outlen = 0;
	unsigned int	tmp2_outlen = 0;
	unsigned char	*salt = buf;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = *buf_len - SALT_SIZE;
	unsigned char	outbuf[KNET_DATABUFSIZE_CRYPT];
	int		outbuf_len;
	int		err = -1;

	/* Create cipher context for decryption */
	decrypt_param.type = siBuffer;
	decrypt_param.data = salt;
	decrypt_param.len = SALT_SIZE;

	decrypt_context = PK11_CreateContextBySymKey(cipher_to_nss[instance->crypto_cipher_type],
						     CKA_DECRYPT,
						     instance->nss_sym_key, &decrypt_param);
	if (!decrypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext (decrypt) failed (err %d)",
			   PR_GetError());
		goto out;
	}

	if (PK11_CipherOp(decrypt_context, outbuf, &tmp1_outlen,
			  sizeof(outbuf), data, datalen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp (decrypt) failed (err %d)",
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(decrypt_context, outbuf + tmp1_outlen, &tmp2_outlen,
			     sizeof(outbuf) - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal (decrypt) failed (err %d)",
			   PR_GetError()); 
		goto out;
	}

	outbuf_len = tmp1_outlen + tmp2_outlen;

	memset(buf, 0, *buf_len);
	memcpy(buf, outbuf, outbuf_len);

	*buf_len = outbuf_len;

	err = 0;

out:
	if (decrypt_context) {
		PK11_DestroyContext(decrypt_context, PR_TRUE);
	}

	return err;
}


/*
 * hash/hmac/digest functions
 */

static int string_to_crypto_hash_type(const char* crypto_hash_type)
{
	if (strcmp(crypto_hash_type, "none") == 0) {
		return CRYPTO_HASH_TYPE_NONE;
	} else if (strcmp(crypto_hash_type, "md5") == 0) {
		return CRYPTO_HASH_TYPE_MD5;
	} else if (strcmp(crypto_hash_type, "sha1") == 0) {
		return CRYPTO_HASH_TYPE_SHA1;
	} else if (strcmp(crypto_hash_type, "sha256") == 0) {
		return CRYPTO_HASH_TYPE_SHA256;
	} else if (strcmp(crypto_hash_type, "sha384") == 0) {
		return CRYPTO_HASH_TYPE_SHA384;
	} else if (strcmp(crypto_hash_type, "sha512") == 0) {
		return CRYPTO_HASH_TYPE_SHA512;
	}

	return -1;
}

static int init_nss_hash(knet_handle_t knet_h)
{
	PK11SlotInfo*	hash_slot = NULL;
	SECItem		hash_param;
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (!hash_to_nss[instance->crypto_hash_type]) {
		return 0;
	}

	hash_param.type = siBuffer;
	hash_param.data = instance->private_key;
	hash_param.len = instance->private_key_len;

	hash_slot = PK11_GetBestSlot(hash_to_nss[instance->crypto_hash_type], NULL);
	if (hash_slot == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to find security slot (err %d)",
			   PR_GetError());
		return -1;
	}

	instance->nss_sym_key_sign = PK11_ImportSymKey(hash_slot,
						       hash_to_nss[instance->crypto_hash_type],
						       PK11_OriginUnwrap, CKA_SIGN,
						       &hash_param, NULL);
	if (instance->nss_sym_key_sign == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to import key into NSS (err %d)",
			   PR_GetError());
		return -1;
	}

	PK11_FreeSlot(hash_slot);

	return 0;
}

static int calculate_nss_hash(
	knet_handle_t knet_h,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	PK11Context*	hash_context = NULL;
	SECItem		hash_param;
	unsigned int	hash_tmp_outlen = 0;
	unsigned char	hash_block[hash_block_len[instance->crypto_hash_type]];
	int		err = -1;

	/* Now do the digest */
	hash_param.type = siBuffer;
	hash_param.data = 0;
	hash_param.len = 0;

	hash_context = PK11_CreateContextBySymKey(hash_to_nss[instance->crypto_hash_type],
						 CKA_SIGN,
						 instance->nss_sym_key_sign,
						 &hash_param);

	if (!hash_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestBegin(hash_context) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestBegin failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestOp(hash_context,
			  buf,
			  buf_len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestOp failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(hash_context,
			     hash_block,
			     &hash_tmp_outlen,
			     hash_block_len[instance->crypto_hash_type]) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinale failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	memcpy(hash, hash_block, hash_len[instance->crypto_hash_type]);
	err = 0;

out:
	if (hash_context) {
		PK11_DestroyContext(hash_context, PR_TRUE);
	}

	return err;
}

/*
 * global/glue nss functions
 */

static int init_nss_db(knet_handle_t knet_h)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if ((!cipher_to_nss[instance->crypto_cipher_type]) &&
	    (!hash_to_nss[instance->crypto_hash_type])) {
		return 0;
	}

	if (NSS_NoDB_Init(".") != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB initialization failed (err %d)",
			   PR_GetError());
		return -1;
	}

	return 0;
}

static int init_nss(knet_handle_t knet_h)
{
	if (init_nss_db(knet_h) < 0) {
		return -1;
	}

	if (init_nss_crypto(knet_h) < 0) {
		return -1;
	}

	if (init_nss_hash(knet_h) < 0) {
		return -1;
	}

	return 0;
}

/*
 * exported API
 */

int nsscrypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (encrypt_nss(knet_h, buf_in, buf_in_len, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		memcpy(buf_out, buf_in, buf_in_len);
		*buf_out_len = buf_in_len;
	}

	if (hash_to_nss[instance->crypto_hash_type]) {
		if (calculate_nss_hash(knet_h, buf_out, *buf_out_len, buf_out + *buf_out_len) < 0) {
			return -1;
		}
		*buf_out_len = *buf_out_len + hash_len[instance->crypto_hash_type];
	}

	return 0;
}

int nsscrypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	unsigned char *buf,
	ssize_t *buf_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (hash_to_nss[instance->crypto_hash_type]) {
		unsigned char	tmp_hash[hash_len[instance->crypto_hash_type]];

		if (calculate_nss_hash(knet_h, buf, *buf_len - hash_len[instance->crypto_hash_type], tmp_hash) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf + (*buf_len - hash_len[instance->crypto_hash_type]), hash_len[instance->crypto_hash_type]) != 0) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "Digest does not match");
			return -1;
		}

		*buf_len = *buf_len - hash_len[instance->crypto_hash_type];
	}

	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (decrypt_nss(knet_h, buf, buf_len) < 0) {
			return -1;
		}
	}

	return 0;
}

int nsscrypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	struct nsscrypto_instance *nsscrypto_instance = NULL;

	log_debug(knet_h, KNET_SUB_NSSCRYPTO,
		  "Initizializing nss crypto module [%s/%s]",
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance->model_instance = malloc(sizeof(struct nsscrypto_instance));
	if (!knet_h->crypto_instance->model_instance) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to allocate memory for nss model instance");
		return -1;
	}

	nsscrypto_instance = knet_h->crypto_instance->model_instance;

	memset(nsscrypto_instance, 0, sizeof(struct nsscrypto_instance));

	if (!knet_handle_crypto_cfg->crypto_cipher_type) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "no crypto cipher type specified");
		goto out_err;
	}

	nsscrypto_instance->crypto_cipher_type = string_to_crypto_cipher_type(knet_handle_crypto_cfg->crypto_cipher_type);
	if (nsscrypto_instance->crypto_cipher_type < 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unknown crypto cipher type requested");
		goto out_err;
	}

	if (!knet_handle_crypto_cfg->crypto_hash_type) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "no crypto hash type specified");
		goto out_err;
	}

	nsscrypto_instance->crypto_hash_type = string_to_crypto_hash_type(knet_handle_crypto_cfg->crypto_hash_type);
	if (nsscrypto_instance->crypto_hash_type < 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unknown crypto hash type requested");
		goto out_err;
	}

	nsscrypto_instance->private_key = knet_handle_crypto_cfg->private_key;
	nsscrypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	if ((nsscrypto_instance->crypto_cipher_type > 0) &&
	    (nsscrypto_instance->crypto_hash_type == 0)) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "crypto communication requires hash specified");
		goto out_err;
	}

	if ((nsscrypto_instance->crypto_cipher_type > 0) ||
	    (nsscrypto_instance->crypto_hash_type > 0)) {
		if ((!nsscrypto_instance->private_key) ||
		    (nsscrypto_instance->private_key_len < KNET_MIN_KEY_LEN) ||
		    (nsscrypto_instance->private_key_len > KNET_MAX_KEY_LEN)) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "crypto private key parameters are incorrect");
			goto out_err;
		}
	}

	nsscrypto_instance->private_key = knet_handle_crypto_cfg->private_key;
	nsscrypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	if (init_nss(knet_h) < 0) {
		goto out_err;
	}

	knet_h->sec_header_size = 0;

	if (nsscrypto_instance->crypto_hash_type > 0) {
		knet_h->sec_header_size += hash_len[nsscrypto_instance->crypto_hash_type];
		knet_h->sec_hash_size = hash_len[nsscrypto_instance->crypto_hash_type];
	}

	if (nsscrypto_instance->crypto_cipher_type > 0) {
		int block_size;

		if (cypher_block_len[nsscrypto_instance->crypto_cipher_type]) {
			block_size = cypher_block_len[nsscrypto_instance->crypto_cipher_type];
		} else {
			block_size = PK11_GetBlockSize(nsscrypto_instance->crypto_cipher_type, NULL);
			if (block_size < 0) {
				goto out_err;
			}
		}

		knet_h->sec_header_size += (block_size * 2);
		knet_h->sec_header_size += SALT_SIZE;
		knet_h->sec_salt_size = SALT_SIZE;
		knet_h->sec_block_size = block_size;
	}

	return 0;

out_err:
	nsscrypto_fini(knet_h);
	return -1;
}

void nsscrypto_fini(
	knet_handle_t knet_h)
{
	struct nsscrypto_instance *nsscrypto_instance = knet_h->crypto_instance->model_instance;

	if (nsscrypto_instance) {
		if (nsscrypto_instance->nss_sym_key) {
			PK11_FreeSymKey(nsscrypto_instance->nss_sym_key);
			nsscrypto_instance->nss_sym_key = NULL;
		}
		if (nsscrypto_instance->nss_sym_key_sign) {
			PK11_FreeSymKey(nsscrypto_instance->nss_sym_key_sign);
			nsscrypto_instance->nss_sym_key_sign = NULL;
		}
		free(nsscrypto_instance);
		knet_h->crypto_instance->model_instance = NULL;
		knet_h->sec_header_size = 0;
	}

	return;
}
