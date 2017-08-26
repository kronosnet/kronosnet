/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#ifdef BUILDCRYPTONSS
#include <nss.h>
#include <nspr.h>
#include <pk11pub.h>
#include <pkcs11.h>
#include <prerror.h>
#include <blapit.h>
#include <hasht.h>
#include <pthread.h>
#include <secerr.h>

#include "crypto.h"
#include "crypto_nss.h"
#include "logging.h"

/*
 * global vars for dlopen
 */
static void *nss_lib;

/*
 * symbols remapping
 */
/*
 * nss3
 */
CK_MECHANISM_TYPE (*_int_PK11_GetBestWrapMechanism)(PK11SlotInfo *slot);
PK11SlotInfo *(*_int_PK11_GetBestSlot)(CK_MECHANISM_TYPE type, void *wincx);
int (*_int_PK11_GetBestKeyLength)(PK11SlotInfo *slot, CK_MECHANISM_TYPE type);
SECStatus (*_int_PK11_DigestFinal)(PK11Context *context, unsigned char *data,
				   unsigned int *outLen, unsigned int length);
void (*_int_SECITEM_FreeItem)(SECItem *zap, PRBool freeit);
SECStatus (*_int_NSS_NoDB_Init)(const char *configdir);
SECStatus (*_int_NSS_Shutdown)(void);
SECStatus (*_int_PK11_DigestBegin)(PK11Context *cx);
SECStatus (*_int_PK11_DigestOp)(PK11Context *context, const unsigned char *in, unsigned len);
void (*_int_PK11_DestroyContext)(PK11Context *context, PRBool freeit);
SECStatus (*_int_PK11_Finalize)(PK11Context *context);
SECStatus (*_int_PK11_CipherOp)(PK11Context *context, unsigned char *out, int *outlen,
				int maxout, const unsigned char *in, int inlen);
PK11SymKey *(*_int_PK11_UnwrapSymKey)(PK11SymKey *key,
				      CK_MECHANISM_TYPE wraptype, SECItem *param, SECItem *wrapppedKey,
				      CK_MECHANISM_TYPE target, CK_ATTRIBUTE_TYPE operation, int keySize);
void (*_int_PK11_FreeSymKey)(PK11SymKey *key);
PK11Context *(*_int_PK11_CreateContextBySymKey)(CK_MECHANISM_TYPE type,
						CK_ATTRIBUTE_TYPE operation,
						PK11SymKey *symKey, SECItem *param);
SECStatus (*_int_PK11_GenerateRandom)(unsigned char *data, int len);
SECItem *(*_int_PK11_ParamFromIV)(CK_MECHANISM_TYPE type, SECItem *iv);
void (*_int_PK11_FreeSlot)(PK11SlotInfo *slot);
int (*_int_PK11_GetBlockSize)(CK_MECHANISM_TYPE type, SECItem *params);
PK11SymKey *(*_int_PK11_KeyGen)(PK11SlotInfo *slot, CK_MECHANISM_TYPE type,
				SECItem *param, int keySize, void *wincx);

/*
 * nspr4
 */
PRStatus (*_int_PR_Cleanup)(void);
const char * (*_int_PR_ErrorToString)(PRErrorCode code, PRLanguageCode language);
void (*_int_PR_Init)(PRThreadType type, PRThreadPriority priority, PRUintn maxPTDs);
PRErrorCode (*_int_PR_GetError)(void);

/*
 * plds4
 */
void (*_int_PL_ArenaFinish)(void);

static int nsscrypto_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

	/*
	 * nss3
	 */

	_int_PK11_GetBestWrapMechanism = dlsym(nss_lib, "PK11_GetBestWrapMechanism");
	if (!_int_PK11_GetBestWrapMechanism) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_GetBestWrapMechanism: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_GetBestSlot = dlsym(nss_lib, "PK11_GetBestSlot");
	if (!_int_PK11_GetBestSlot) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_GetBestSlot: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_GetBestKeyLength = dlsym(nss_lib, "PK11_GetBestKeyLength");
	if (!_int_PK11_GetBestKeyLength) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_GetBestKeyLength: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_DigestFinal = dlsym(nss_lib, "PK11_DigestFinal");
	if (!_int_PK11_DigestFinal) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_DigestFinal: %s", error);
		err = -1;
		goto out;
	}

	_int_SECITEM_FreeItem = dlsym(nss_lib, "SECITEM_FreeItem");
	if (!_int_SECITEM_FreeItem) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map SECITEM_FreeItem: %s", error);
		err = -1;
		goto out;
	}

	_int_NSS_NoDB_Init = dlsym(nss_lib, "NSS_NoDB_Init");
	if (!_int_NSS_NoDB_Init) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map NSS_NoDB_Init: %s", error);
		err = -1;
		goto out;
	}

	_int_NSS_Shutdown = dlsym(nss_lib, "NSS_Shutdown");
	if (!_int_NSS_Shutdown) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map NSS_Shutdown: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_DigestBegin = dlsym(nss_lib, "PK11_DigestBegin");
	if (!_int_PK11_DigestBegin) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_DigestBegin: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_DigestOp = dlsym(nss_lib, "PK11_DigestOp");
	if (!_int_PK11_DigestOp) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_DigestOp: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_DestroyContext = dlsym(nss_lib, "PK11_DestroyContext");
	if (!_int_PK11_DestroyContext) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_DestroyContext: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_Finalize = dlsym(nss_lib, "PK11_Finalize");
	if (!_int_PK11_Finalize) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_Finalize: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_CipherOp = dlsym(nss_lib, "PK11_CipherOp");
	if (!_int_PK11_CipherOp) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_CipherOp: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_UnwrapSymKey = dlsym(nss_lib, "PK11_UnwrapSymKey");
	if (!_int_PK11_UnwrapSymKey) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_UnwrapSymKey: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_FreeSymKey = dlsym(nss_lib, "PK11_FreeSymKey");
	if (!_int_PK11_FreeSymKey) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_FreeSymKey: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_CreateContextBySymKey = dlsym(nss_lib, "PK11_CreateContextBySymKey");
	if (!_int_PK11_CreateContextBySymKey) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_CreateContextBySymKey: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_GenerateRandom = dlsym(nss_lib, "PK11_GenerateRandom");
	if (!_int_PK11_GenerateRandom) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_GenerateRandom: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_ParamFromIV = dlsym(nss_lib, "PK11_ParamFromIV");
	if (!_int_PK11_ParamFromIV) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_ParamFromIV: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_FreeSlot = dlsym(nss_lib, "PK11_FreeSlot");
	if (!_int_PK11_FreeSlot) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_FreeSlot: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_GetBlockSize = dlsym(nss_lib, "PK11_GetBlockSize");
	if (!_int_PK11_GetBlockSize) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_GetBlockSize: %s", error);
		err = -1;
		goto out;
	}

	_int_PK11_KeyGen = dlsym(nss_lib, "PK11_KeyGen");
	if (!_int_PK11_KeyGen) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PK11_KeyGen: %s", error);
		err = -1;
		goto out;
	}

	/*
	 * nspr4
	 */

	_int_PR_Cleanup = dlsym(nss_lib, "PR_Cleanup");
	if (!_int_PR_Cleanup) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PR_Cleanup: %s", error);
		err = -1;
		goto out;
	}

	_int_PR_ErrorToString = dlsym(nss_lib, "PR_ErrorToString");
	if (!_int_PR_ErrorToString) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PR_ErrorToString: %s", error);
		err = -1;
		goto out;
	}

	_int_PR_Init = dlsym(nss_lib, "PR_Init");
	if (!_int_PR_Init) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PR_Init: %s", error);
		err = -1;
		goto out;
	}

	_int_PR_GetError = dlsym(nss_lib, "PR_GetError");
	if (!_int_PR_GetError) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PR_GetError: %s", error);
		err = -1;
		goto out;
	}

	/*
	 * plds4
	 */

	_int_PL_ArenaFinish = dlsym(nss_lib, "PL_ArenaFinish");
	if (!_int_PL_ArenaFinish) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to map PL_ArenaFinish: %s", error);
		err = -1;
		goto out;
	}


out:
	if (err) {
		_int_PK11_GetBestWrapMechanism = NULL;
		_int_PK11_GetBestSlot = NULL;
		_int_PK11_GetBestKeyLength = NULL;
		_int_PK11_DigestFinal = NULL;
		_int_SECITEM_FreeItem = NULL;
		_int_NSS_NoDB_Init = NULL;
		_int_NSS_Shutdown = NULL;
		_int_PK11_DigestBegin = NULL;
		_int_PK11_DigestOp = NULL;
		_int_PK11_DestroyContext = NULL;
		_int_PK11_Finalize = NULL;
		_int_PK11_CipherOp = NULL;
		_int_PK11_UnwrapSymKey = NULL;
		_int_PK11_FreeSymKey = NULL;
		_int_PK11_CreateContextBySymKey = NULL;
		_int_PK11_GenerateRandom = NULL;
		_int_PK11_ParamFromIV = NULL;
		_int_PK11_FreeSlot = NULL;
		_int_PK11_GetBlockSize = NULL;
		_int_PK11_KeyGen = NULL;

		_int_PR_Cleanup = NULL;
		_int_PR_ErrorToString = NULL;
		_int_PR_Init = NULL;
		_int_PR_GetError = NULL;

		_int_PL_ArenaFinish = NULL;
	}
	return err;
}

static void nss_atexit_handler(void)
{
	(*_int_NSS_Shutdown)();
	(*_int_PL_ArenaFinish)();
	(*_int_PR_Cleanup)();
}

static int init_nss_db(knet_handle_t knet_h)
{
	(*_int_PR_Init)(PR_USER_THREAD, PR_PRIORITY_URGENT, 0);

	if ((*_int_NSS_NoDB_Init)(".") != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB initialization failed (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		return -1;
	}

	if (atexit(&nss_atexit_handler) != 0) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "NSS DB unable to register atexit handler");
		return -1;
	}

	return 0;
}

void nsscrypto_unload_lib(
	knet_handle_t knet_h)
{
	log_warn(knet_h, KNET_SUB_NSSCRYPTO, "libnss cannot be unloaded at runtime! Please restart your application");
	return;
}

int nsscrypto_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;
	char *error = NULL;

	if (!nss_lib) {
		/*
		 * clear any pending error
		 */
		nss_lib = dlopen("libnss3.so", RTLD_LAZY | RTLD_GLOBAL | RTLD_NODELETE);
		error = dlerror();
		if (error != NULL) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "unable to dlopen libnss3.so: %s", error);
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}

		if (nsscrypto_remap_symbols(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			goto out;
		}

		if (init_nss_db(knet_h) < 0) {
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}
	}

out:
	if (err) {
		nsscrypto_unload_lib(knet_h);
	}
	errno = savederrno;
	return err;
}

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

	slot = (*_int_PK11_GetBestSlot)(cipher, NULL);
	if (slot == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to find security slot (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
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
	wrap_mechanism = (*_int_PK11_GetBestWrapMechanism)(slot);
	wrap_key_len = (*_int_PK11_GetBestKeyLength)(slot, wrap_mechanism);
	wrap_key = (*_int_PK11_KeyGen)(slot, wrap_mechanism, NULL, wrap_key_len, NULL);
	if (wrap_key == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to generate wrapping key (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	/*
	 * Encrypt authkey with wrapping key
	 */

	/*
	 * Initialization of IV is not needed because PK11_GetBestWrapMechanism should return ECB mode
	 */
	memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));
	wrap_key_crypt_context = (*_int_PK11_CreateContextBySymKey)(wrap_mechanism, CKA_ENCRYPT,
								    wrap_key, &tmp_sec_item);
	if (wrap_key_crypt_context == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to create encrypt context (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	wrapped_key_len = (int)sizeof(wrapped_key_data);

	if ((*_int_PK11_CipherOp)(wrap_key_crypt_context, wrapped_key_data, &wrapped_key_len,
				  sizeof(wrapped_key_data), key_item.data, key_item.len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to encrypt authkey (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	if ((*_int_PK11_Finalize)(wrap_key_crypt_context) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Unable to finalize encryption of authkey (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto exit_res_key;
	}

	/*
	 * Finally unwrap sym key
	 */
	memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));
	wrapped_key.data = wrapped_key_data;
	wrapped_key.len = wrapped_key_len;

	res_key = (*_int_PK11_UnwrapSymKey)(wrap_key, wrap_mechanism, &tmp_sec_item, &wrapped_key,
					    cipher, operation, key_item.len);
	if (res_key == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to import key into NSS (%d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));

		if ((*_int_PR_GetError)() == SEC_ERROR_BAD_DATA) {
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
		(*_int_PK11_DestroyContext)(wrap_key_crypt_context, PR_TRUE);
	}

	if (wrap_key != NULL) {
		(*_int_PK11_FreeSymKey)(wrap_key);
	}

	if (slot != NULL) {
		(*_int_PK11_FreeSlot)(slot);
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

	if ((*_int_PK11_GenerateRandom)(salt, SALT_SIZE) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to generate a random number (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = salt;
	crypt_param.len = SALT_SIZE;

	nss_sec_param = (*_int_PK11_ParamFromIV)(cipher_to_nss[instance->crypto_cipher_type],
						 &crypt_param);
	if (nss_sec_param == NULL) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "Failure to set up PKCS11 param (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	/*
	 * Create cipher context for encryption
	 */
	crypt_context = (*_int_PK11_CreateContextBySymKey)(cipher_to_nss[instance->crypto_cipher_type],
							   CKA_ENCRYPT,
							   instance->nss_sym_key,
							   nss_sec_param);
	if (!crypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (encrypt) crypt_type=%d (err %d): %s",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   (*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	for (i=0; i<iovcnt; i++) {
		if ((*_int_PK11_CipherOp)(crypt_context, data,
					  &tmp_outlen,
					  KNET_DATABUFSIZE_CRYPT,
					  (unsigned char *)iov[i].iov_base,
					  iov[i].iov_len) != SECSuccess) {
			log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp failed (encrypt) crypt_type=%d (err %d): %s",
				(int)cipher_to_nss[instance->crypto_cipher_type],
				(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
			goto out;
		}
		tmp1_outlen = tmp1_outlen + tmp_outlen;
	}

	if ((*_int_PK11_DigestFinal)(crypt_context, data + tmp1_outlen,
				     &tmp2_outlen, KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal failed (encrypt) crypt_type=%d (err %d): %s",
			(int)cipher_to_nss[instance->crypto_cipher_type],
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;

	}

	*buf_out_len = tmp1_outlen + tmp2_outlen + SALT_SIZE;

	err = 0;

out:
	if (crypt_context) {
		(*_int_PK11_DestroyContext)(crypt_context, PR_TRUE);
	}
	if (nss_sec_param) {
		(*_int_SECITEM_FreeItem)(nss_sec_param, PR_TRUE);
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

	decrypt_context = (*_int_PK11_CreateContextBySymKey)(cipher_to_nss[instance->crypto_cipher_type],
							     CKA_DECRYPT,
							     instance->nss_sym_key, &decrypt_param);
	if (!decrypt_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext (decrypt) failed (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if ((*_int_PK11_CipherOp)(decrypt_context, buf_out, &tmp1_outlen,
				  KNET_DATABUFSIZE_CRYPT, data, datalen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CipherOp (decrypt) failed (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if ((*_int_PK11_DigestFinal)(decrypt_context, buf_out + tmp1_outlen, &tmp2_outlen,
				     KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinal (decrypt) failed (err %d): %s",
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	*buf_out_len = tmp1_outlen + tmp2_outlen;

	err = 0;

out:
	if (decrypt_context) {
		(*_int_PK11_DestroyContext)(decrypt_context, PR_TRUE);
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

	hash_context = (*_int_PK11_CreateContextBySymKey)(hash_to_nss[instance->crypto_hash_type],
							  CKA_SIGN,
							  instance->nss_sym_key_sign,
							  &hash_param);

	if (!hash_context) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_CreateContext failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if ((*_int_PK11_DigestBegin)(hash_context) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestBegin failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if ((*_int_PK11_DigestOp)(hash_context, buf, buf_len) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestOp failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	if ((*_int_PK11_DigestFinal)(hash_context, hash,
				     &hash_tmp_outlen, hash_len[instance->crypto_hash_type]) != SECSuccess) {
		log_err(knet_h, KNET_SUB_NSSCRYPTO, "PK11_DigestFinale failed (hash) hash_type=%d (err %d): %s",
			(int)hash_to_nss[instance->crypto_hash_type],
			(*_int_PR_GetError)(), (*_int_PR_ErrorToString)((*_int_PR_GetError)(), PR_LANGUAGE_I_DEFAULT));
		goto out;
	}

	err = 0;

out:
	if (hash_context) {
		(*_int_PK11_DestroyContext)(hash_context, PR_TRUE);
	}

	return err;
}

/*
 * global/glue nss functions
 */

static int init_nss(knet_handle_t knet_h)
{
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
			block_size = (*_int_PK11_GetBlockSize)(nsscrypto_instance->crypto_cipher_type, NULL);
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
			(*_int_PK11_FreeSymKey)(nsscrypto_instance->nss_sym_key);
			nsscrypto_instance->nss_sym_key = NULL;
		}
		if (nsscrypto_instance->nss_sym_key_sign) {
			(*_int_PK11_FreeSymKey)(nsscrypto_instance->nss_sym_key_sign);
			nsscrypto_instance->nss_sym_key_sign = NULL;
		}
		free(nsscrypto_instance);
		knet_h->crypto_instance->model_instance = NULL;
		knet_h->sec_header_size = 0;
	}

	return;
}
#endif
