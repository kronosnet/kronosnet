/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#ifdef BUILDCRYPTONSS
#include <nss.h>
#include <nspr.h>
#include <pk11pub.h>
#include <pkcs11.h>
#include <prerror.h>
#include <blapit.h>
#include <hasht.h>
#include <pthread.h>
#include <stdlib.h>
#include <secerr.h>

#include "crypto.h"
#include "crypto_nss.h"
#include "logging.h"

static pthread_mutex_t nssdbinit_mutex = PTHREAD_MUTEX_INITIALIZER;
static int nssdbinit_done = 0;

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

enum sym_key_type {
	SYM_KEY_TYPE_CRYPT,
	SYM_KEY_TYPE_HASH
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

static PK11SymKey *import_symmetric_key(knet_handle_t knet_h, enum sym_key_type key_type)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	SECItem key_item;
	PK11SlotInfo *slot;
	PK11SymKey *res_key;
	CK_MECHANISM_TYPE cipher;
	CK_ATTRIBUTE_TYPE operation;
	CK_MECHANISM_TYPE wrap_mechanism;
	int wrap_key_len;
	PK11SymKey *wrap_key;
	PK11Context *wrap_key_crypt_context;
	SECItem tmp_sec_item;
	SECItem wrapped_key;
	int wrapped_key_len;
	unsigned char wrapped_key_data[KNET_MAX_KEY_LEN];

	memset(&key_item, 0, sizeof(key_item));
	slot = NULL;
	wrap_key = NULL;
	res_key = NULL;
	wrap_key_crypt_context = NULL;

	key_item.type = siBuffer;
	key_item.data = instance->private_key;

	switch (key_type) {
		case SYM_KEY_TYPE_CRYPT:
			key_item.len = cipher_key_len[instance->crypto_cipher_type];
			cipher = cipher_to_nss[instance->crypto_cipher_type];
			operation = CKA_ENCRYPT|CKA_DECRYPT;
			break;
		case SYM_KEY_TYPE_HASH:
			key_item.len = instance->private_key_len;
			cipher = hash_to_nss[instance->crypto_hash_type];
			operation = CKA_SIGN;
			break;
		default:
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "Import symmetric key failed. Unknown keyimport request");
			goto exit_res_key;
			break;
	}

	slot = PK11_GetBestSlot(cipher, NULL);
	if (slot == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to find security slot (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	/*
	 * Without FIPS it would be possible to just use
	 * 	res_key = PK11_ImportSymKey(slot, cipher, PK11_OriginUnwrap, operation, &key_item, NULL);
	 * with FIPS NSS Level 2 certification has to be "workarounded" (so it becomes Level 1) by using
	 * following method:
	 * 1. Generate wrap key
	 * 2. Encrypt authkey with wrap key
	 * 3. Unwrap encrypted authkey using wrap key
	 */

	/*
	 * Generate wrapping key
	 */
	wrap_mechanism = PK11_GetBestWrapMechanism(slot);
	wrap_key_len = PK11_GetBestKeyLength(slot, wrap_mechanism);
	wrap_key = PK11_KeyGen(slot, wrap_mechanism, NULL, wrap_key_len, NULL);
	if (wrap_key == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to generate wrapping key (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	/*
	 * Encrypt authkey with wrapping key
	 */

	/*
	 * Initialization of IV is not needed because PK11_GetBestWrapMechanism should return ECB mode
	 */
	memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));
	wrap_key_crypt_context = PK11_CreateContextBySymKey(wrap_mechanism, CKA_ENCRYPT,
							    wrap_key, &tmp_sec_item);
	if (wrap_key_crypt_context == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to create encrypt context (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	wrapped_key_len = (int)sizeof(wrapped_key_data);

	if (PK11_CipherOp(wrap_key_crypt_context, wrapped_key_data, &wrapped_key_len,
			  sizeof(wrapped_key_data), key_item.data, key_item.len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to encrypt authkey (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	if (PK11_Finalize(wrap_key_crypt_context) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to finalize encryption of authkey (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	/*
	 * Finally unwrap sym key
	 */
	memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));
	wrapped_key.data = wrapped_key_data;
	wrapped_key.len = wrapped_key_len;

	res_key = PK11_UnwrapSymKey(wrap_key, wrap_mechanism, &tmp_sec_item, &wrapped_key,
				    cipher, operation, key_item.len);
	if (res_key == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to import key into NSS (%d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));

		if (PR_GetError() == SEC_ERROR_BAD_DATA) {
			/*
			 * Maximum key length for FIPS enabled softtoken is limited to
			 * MAX_KEY_LEN (pkcs11i.h - 256) and checked in NSC_UnwrapKey. Returned
			 * error is CKR_TEMPLATE_INCONSISTENT which is mapped to SEC_ERROR_BAD_DATA.
			 */
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "Secret key is probably too long. "
				"Try reduce it to 256 bytes");
		}
		goto exit_res_key;
	}

exit_res_key:
	if (wrap_key_crypt_context != NULL) {
		PK11_DestroyContext(wrap_key_crypt_context, PR_TRUE);
	}

	if (wrap_key != NULL) {
		PK11_FreeSymKey(wrap_key);
	}

	if (slot != NULL) {
		PK11_FreeSlot(slot);
	}

	return (res_key);
}

static int init_nss_crypto(knet_handle_t knet_h)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (!cipher_to_nss[instance->crypto_cipher_type]) {
		return 0;
	}

	instance->nss_sym_key = import_symmetric_key(knet_h, SYM_KEY_TYPE_CRYPT);
	if (instance->nss_sym_key == NULL) {
		return -1;
	}

	return 0;
}

static int encrypt_nss(
	knet_handle_t knet_h,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	PK11Context*	crypt_context = NULL;
	SECItem		crypt_param;
	SECItem		*nss_sec_param = NULL;
	int		tmp_outlen = 0, tmp1_outlen = 0;
	unsigned int	tmp2_outlen = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = -1;
	int		i;

	if (PK11_GenerateRandom (salt, SALT_SIZE) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to generate a random number (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = salt;
	crypt_param.len = SALT_SIZE;

	nss_sec_param = PK11_ParamFromIV(cipher_to_nss[instance->crypto_cipher_type],
					 &crypt_param);
	if (nss_sec_param == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to set up PKCS11 param (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	/*
	 * Create cipher context for encryption
	 */
	crypt_context = PK11_CreateContextBySymKey(cipher_to_nss[instance->crypto_cipher_type],
						   CKA_ENCRYPT,
						   instance->nss_sym_key,
						   nss_sec_param);
	if (!crypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (encrypt) crypt_type=%d (err %d): %s",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	for (i=0; i<iovcnt; i++) {
		if (PK11_CipherOp(crypt_context, data,
				  &tmp_outlen,
				  KNET_DATABUFSIZE_CRYPT,
				  (unsigned char *)iov[i].iov_base, iov[i].iov_len) != SECSuccess) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp failed (encrypt) crypt_type=%d (err %d): %s",
				(int)cipher_to_nss[instance->crypto_cipher_type],
				PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
			goto out;
		}
		tmp1_outlen = tmp1_outlen + tmp_outlen;
	}

	if (PK11_DigestFinal(crypt_context, data + tmp1_outlen,
			     &tmp2_outlen, KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal failed (encrypt) crypt_type=%d (err %d): %s",
			(int)cipher_to_nss[instance->crypto_cipher_type],
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
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
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	PK11Context*	decrypt_context = NULL;
	SECItem		decrypt_param;
	int		tmp1_outlen = 0;
	unsigned int	tmp2_outlen = 0;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = -1;

	/* Create cipher context for decryption */
	decrypt_param.type = siBuffer;
	decrypt_param.data = salt;
	decrypt_param.len = SALT_SIZE;

	decrypt_context = PK11_CreateContextBySymKey(cipher_to_nss[instance->crypto_cipher_type],
						     CKA_DECRYPT,
						     instance->nss_sym_key, &decrypt_param);
	if (!decrypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext (decrypt) failed (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if (PK11_CipherOp(decrypt_context, buf_out, &tmp1_outlen,
			  KNET_DATABUFSIZE_CRYPT, data, datalen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp (decrypt) failed (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if (PK11_DigestFinal(decrypt_context, buf_out + tmp1_outlen, &tmp2_outlen,
			     KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal (decrypt) failed (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	*buf_out_len = tmp1_outlen + tmp2_outlen;

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
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;

	if (!hash_to_nss[instance->crypto_hash_type]) {
		return 0;
	}

	instance->nss_sym_key_sign = import_symmetric_key(knet_h, SYM_KEY_TYPE_HASH);
	if (instance->nss_sym_key_sign == NULL) {
		return -1;
	}

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
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if (PK11_DigestBegin(hash_context) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestBegin failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if (PK11_DigestOp(hash_context, buf, buf_len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestOp failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if (PK11_DigestFinal(hash_context, hash,
			     &hash_tmp_outlen, hash_len[instance->crypto_hash_type]) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinale failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

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

static void nss_atexit_handler(void)
{
	NSS_Shutdown();
	PL_ArenaFinish();
	PR_Cleanup();
}

static int init_nss_db(knet_handle_t knet_h)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	int err = 0;

	if ((!cipher_to_nss[instance->crypto_cipher_type]) &&
	    (!hash_to_nss[instance->crypto_hash_type])) {
		return 0;
	}

	err = pthread_mutex_lock(&nssdbinit_mutex);
	if (err) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB unable to get mutex lock (%d)", err);
		return -1;
	}

	if (nssdbinit_done) {
		err = 0;
		goto out_unlock;
	}

	PR_Init(PR_USER_THREAD, PR_PRIORITY_URGENT, 0);

	if (NSS_NoDB_Init(".") != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB initialization failed (err %d): %s",
			PR_GetError(), PR_ErrorToString(PR_GetError(), PR_LANGUAGE_I_DEFAULT));
		err = -1;
		goto out_unlock;
	}

	if (atexit(&nss_atexit_handler) != 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB unable to register atexit handler");
		err = -1;
		goto out_unlock;
	}

	nssdbinit_done = 1;

out_unlock:
	pthread_mutex_unlock(&nssdbinit_mutex);
	return err;
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
	struct iovec iov_in;

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (unsigned char *)buf_in;
	iov_in.iov_len = buf_in_len;

	return nsscrypto_encrypt_and_signv(knet_h, &iov_in, 1, buf_out, buf_out_len);
}

int nsscrypto_encrypt_and_signv (
	knet_handle_t knet_h,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	int i;

	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (encrypt_nss(knet_h, iov_in, iovcnt_in, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		*buf_out_len = 0;
		for (i=0; i<iovcnt_in; i++) {
			memmove(buf_out + *buf_out_len, iov_in[i].iov_base, iov_in[i].iov_len);
			*buf_out_len = *buf_out_len + iov_in[i].iov_len;
		}
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
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct nsscrypto_instance *instance = knet_h->crypto_instance->model_instance;
	ssize_t temp_len = buf_in_len;

	if (hash_to_nss[instance->crypto_hash_type]) {
		unsigned char tmp_hash[hash_len[instance->crypto_hash_type]];
		ssize_t temp_buf_len = buf_in_len - hash_len[instance->crypto_hash_type];

		if ((temp_buf_len < 0) || (temp_buf_len > KNET_MAX_PACKET_SIZE)) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "Incorrect packet size.");
			return -1;
		}

		if (calculate_nss_hash(knet_h, buf_in, temp_buf_len, tmp_hash) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf_in + temp_buf_len, hash_len[instance->crypto_hash_type]) != 0) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "Digest does not match");
			return -1;
		}

		temp_len = temp_len - hash_len[instance->crypto_hash_type];
		*buf_out_len = temp_len;
	}

	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (decrypt_nss(knet_h, buf_in, temp_len, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		memmove(buf_out, buf_in, temp_len);
		*buf_out_len = temp_len;
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

	nsscrypto_instance->crypto_cipher_type = string_to_crypto_cipher_type(knet_handle_crypto_cfg->crypto_cipher_type);
	if (nsscrypto_instance->crypto_cipher_type < 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unknown crypto cipher type requested");
		goto out_err;
	}

	nsscrypto_instance->crypto_hash_type = string_to_crypto_hash_type(knet_handle_crypto_cfg->crypto_hash_type);
	if (nsscrypto_instance->crypto_hash_type < 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unknown crypto hash type requested");
		goto out_err;
	}

	if ((nsscrypto_instance->crypto_cipher_type > 0) &&
	    (nsscrypto_instance->crypto_hash_type == 0)) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "crypto communication requires hash specified");
		goto out_err;
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
#endif
