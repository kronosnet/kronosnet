#include "config.h"

#include <nss.h>
#include <pk11pub.h>
#include <pkcs11.h>
#include <prerror.h>
#include <blapit.h>
#include <hasht.h>

#include "nsscrypto.h"
#include "libknet-private.h"

#ifdef CRYPTO_DEBUG
#define log_printf(format, args...) fprintf(stderr, format "\n", ##args);
#else
#define log_printf(format, args...);
#endif

/*
 * crypto definitions and conversion tables
 */

#define SALT_SIZE 16
#define KNET_DATABUFSIZE_CRYPT KNET_DATABUFSIZE * 2

enum crypto_crypt_t {
	CRYPTO_CIPHER_TYPE_NONE = 0,
	CRYPTO_CIPHER_TYPE_AES256 = 1
};

CK_MECHANISM_TYPE cipher_to_nss[] = {
	0,				/* CRYPTO_CIPHER_TYPE_NONE */
	CKM_AES_CBC_PAD			/* CRYPTO_CIPHER_TYPE_AES256 */
};

size_t cipher_key_len[] = {
	 0,				/* CRYPTO_CIPHER_TYPE_NONE */
	32,				/* CRYPTO_CIPHER_TYPE_AES256 */
};

size_t cypher_block_len[] = {
	 0,				/* CRYPTO_CIPHER_TYPE_NONE */
	AES_BLOCK_SIZE			/* CRYPTO_CIPHER_TYPE_AES256 */
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

struct crypto_instance {
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
	}
	return -1;
}

static int init_nss_crypto(struct crypto_instance *instance)
{
	PK11SlotInfo*	crypt_slot = NULL;
	SECItem		crypt_param;

	if (!cipher_to_nss[instance->crypto_cipher_type]) {
		return 0;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = instance->private_key;
	crypt_param.len = cipher_key_len[instance->crypto_cipher_type];

	crypt_slot = PK11_GetBestSlot(cipher_to_nss[instance->crypto_cipher_type], NULL);
	if (crypt_slot == NULL) {
		log_printf("Unable to find security slot (err %d)",
			   PR_GetError());
		return -1;
	}

	instance->nss_sym_key = PK11_ImportSymKey(crypt_slot,
						  cipher_to_nss[instance->crypto_cipher_type],
						  PK11_OriginUnwrap, CKA_ENCRYPT|CKA_DECRYPT,
						  &crypt_param, NULL);
	if (instance->nss_sym_key == NULL) {
		log_printf("Failure to import key into NSS (err %d)",
			   PR_GetError());
		return -1;
	}

	PK11_FreeSlot(crypt_slot);

	return 0;
}

static int encrypt_nss(
	struct crypto_instance *instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	PK11Context*	crypt_context = NULL;
	SECItem		crypt_param;
	SECItem		*nss_sec_param = NULL;
	int		tmp1_outlen = 0;
	unsigned int	tmp2_outlen = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = -1;

	if (PK11_GenerateRandom (salt, SALT_SIZE) != SECSuccess) {
		log_printf("Failure to generate a random number %d",
			   PR_GetError());
		goto out;
	}

	crypt_param.type = siBuffer;
	crypt_param.data = salt;
	crypt_param.len = SALT_SIZE;

	nss_sec_param = PK11_ParamFromIV (cipher_to_nss[instance->crypto_cipher_type],
					  &crypt_param);
	if (nss_sec_param == NULL) {
		log_printf("Failure to set up PKCS11 param (err %d)",
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
		log_printf("PK11_CreateContext failed (encrypt) crypt_type=%d (err %d)",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_CipherOp(crypt_context, data,
			  &tmp1_outlen,
			  KNET_DATABUFSIZE_CRYPT,
			  (unsigned char *)buf_in, buf_in_len) != SECSuccess) {
		log_printf("PK11_CipherOp failed (encrypt) crypt_type=%d (err %d)",
			   (int)cipher_to_nss[instance->crypto_cipher_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(crypt_context, data + tmp1_outlen,
			     &tmp2_outlen, KNET_DATABUFSIZE_CRYPT - tmp1_outlen) != SECSuccess) {
		log_printf("PK11_DigestFinal failed (encrypt) crypt_type=%d (err %d)",
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
	struct crypto_instance *instance,
	unsigned char *buf,
	ssize_t *buf_len)
{
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
		log_printf("PK11_CreateContext (decrypt) failed (err %d)",
			   PR_GetError());
		goto out;
	}

	if (PK11_CipherOp(decrypt_context, outbuf, &tmp1_outlen,
			  sizeof(outbuf), data, datalen) != SECSuccess) {
		log_printf("PK11_CipherOp (decrypt) failed (err %d)",
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(decrypt_context, outbuf + tmp1_outlen, &tmp2_outlen,
			     sizeof(outbuf) - tmp1_outlen) != SECSuccess) {
		log_printf("PK11_DigestFinal (decrypt) failed (err %d)",
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

static int init_nss_hash(struct crypto_instance *instance)
{
	PK11SlotInfo*	hash_slot = NULL;
	SECItem		hash_param;

	if (!hash_to_nss[instance->crypto_hash_type]) {
		return 0;
	}

	hash_param.type = siBuffer;
	hash_param.data = 0;
	hash_param.len = 0;

	hash_slot = PK11_GetBestSlot(hash_to_nss[instance->crypto_hash_type], NULL);
	if (hash_slot == NULL) {
		log_printf("Unable to find security slot (err %d)",
			   PR_GetError());
		return -1;
	}

	instance->nss_sym_key_sign = PK11_ImportSymKey(hash_slot,
						       hash_to_nss[instance->crypto_hash_type],
						       PK11_OriginUnwrap, CKA_SIGN,
						       &hash_param, NULL);
	if (instance->nss_sym_key_sign == NULL) {
		log_printf("Failure to import key into NSS (err %d)",
			   PR_GetError());
		return -1;
	}

	PK11_FreeSlot(hash_slot);

	return 0;
}

static int calculate_nss_hash(
	struct crypto_instance *instance,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash)
{
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
		log_printf("PK11_CreateContext failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestBegin(hash_context) != SECSuccess) {
		log_printf("PK11_DigestBegin failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestOp(hash_context,
			  buf,
			  buf_len) != SECSuccess) {
		log_printf("PK11_DigestOp failed (hash) hash_type=%d (err %d)",
			   (int)hash_to_nss[instance->crypto_hash_type],
			   PR_GetError());
		goto out;
	}

	if (PK11_DigestFinal(hash_context,
			     hash_block,
			     &hash_tmp_outlen,
			     hash_block_len[instance->crypto_hash_type]) != SECSuccess) {
		log_printf("PK11_DigestFinale failed (hash) hash_type=%d (err %d)",
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

static int init_nss_db(struct crypto_instance *instance)
{
	if ((!cipher_to_nss[instance->crypto_cipher_type]) &&
	    (!hash_to_nss[instance->crypto_hash_type])) {
		return 0;
	}

	if (NSS_NoDB_Init(".") != SECSuccess) {
		log_printf("NSS DB initialization failed (err %d)",
			   PR_GetError());
		return -1;
	}

	return 0;
}

static int init_nss(struct crypto_instance *instance)
{
	if (init_nss_db(instance) < 0) {
		return -1;
	}

	if (init_nss_crypto(instance) < 0) {
		return -1;
	}

	if (init_nss_hash(instance) < 0) {
		return -1;
	}

	return 0;
}

/*
 * exported API
 */

int crypto_encrypt_and_sign (
	struct crypto_instance *instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (encrypt_nss(instance, buf_in, buf_in_len, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		memcpy(buf_out, buf_in, buf_in_len);
		*buf_out_len = buf_in_len;
	}

	if (hash_to_nss[instance->crypto_hash_type]) {
		if (calculate_nss_hash(instance, buf_out, *buf_out_len, buf_out + *buf_out_len) < 0) {
			return -1;
		}
		*buf_out_len = *buf_out_len + hash_len[instance->crypto_hash_type];
	}

	return 0;
}

int crypto_authenticate_and_decrypt (struct crypto_instance *instance,
	unsigned char *buf,
	ssize_t *buf_len)
{
	if (hash_to_nss[instance->crypto_hash_type]) {
		unsigned char	tmp_hash[hash_len[instance->crypto_hash_type]];

		if (calculate_nss_hash(instance, buf, *buf_len - hash_len[instance->crypto_hash_type], tmp_hash) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf + (*buf_len - hash_len[instance->crypto_hash_type]), hash_len[instance->crypto_hash_type]) != 0) {
			log_printf("Digest does not match");
			return -1;
		}

		*buf_len = *buf_len - hash_len[instance->crypto_hash_type];
	}

	if (cipher_to_nss[instance->crypto_cipher_type]) {
		if (decrypt_nss(instance, buf, buf_len) < 0) {
			return -1;
		}
	}

	return 0;
}

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	log_printf("Initizializing nss crypto module [%s/%s]",
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance = malloc(sizeof(struct crypto_instance));
	if (!knet_h->crypto_instance) {
		return -1;
	}

	memset(knet_h->crypto_instance, 0, sizeof(struct crypto_instance));

	if (!knet_handle_crypto_cfg->crypto_cipher_type) {
		goto out_err;
	}

	knet_h->crypto_instance->crypto_cipher_type = string_to_crypto_cipher_type(knet_handle_crypto_cfg->crypto_cipher_type);
	if (knet_h->crypto_instance->crypto_cipher_type < 0) {
		goto out_err;
	}

	if (!knet_handle_crypto_cfg->crypto_hash_type) {
		goto out_err;
	}

	knet_h->crypto_instance->crypto_hash_type = string_to_crypto_hash_type(knet_handle_crypto_cfg->crypto_hash_type);
	if (knet_h->crypto_instance->crypto_hash_type < 0) {
		goto out_err;
	}

	knet_h->crypto_instance->private_key = knet_handle_crypto_cfg->private_key;
	knet_h->crypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	if ((knet_h->crypto_instance->crypto_cipher_type > 0) ||
	    (knet_h->crypto_instance->crypto_hash_type > 0)) {
		if ((!knet_h->crypto_instance->private_key) ||
		    (knet_h->crypto_instance->private_key_len < KNET_MIN_KEY_LEN) ||
		    (knet_h->crypto_instance->private_key_len > KNET_MAX_KEY_LEN)) {
			goto out_err;
		}
	}

	knet_h->tap_to_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->tap_to_links_buf_crypt)
		goto out_err;

	knet_h->pingbuf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->pingbuf_crypt)
		goto out_err;

	knet_h->recv_from_links_buf_crypt = malloc(KNET_DATABUFSIZE_CRYPT);
	if (!knet_h->recv_from_links_buf_crypt)
		goto out_err;

	knet_h->crypto_instance->private_key = knet_handle_crypto_cfg->private_key;
	knet_h->crypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	if (init_nss(knet_h->crypto_instance) < 0) {
		goto out_err;
	}

	return 0;

out_err:
	crypto_fini(knet_h);
	return -1;
}

void crypto_fini(
	knet_handle_t knet_h)
{
	if (knet_h->crypto_instance) {
		if (knet_h->crypto_instance->nss_sym_key)
			PK11_FreeSymKey(knet_h->crypto_instance->nss_sym_key);
		if (knet_h->crypto_instance->nss_sym_key_sign) 
			PK11_FreeSymKey(knet_h->crypto_instance->nss_sym_key_sign);
		if (knet_h->pingbuf_crypt)
			free(knet_h->pingbuf_crypt);
		if (knet_h->tap_to_links_buf_crypt)
			free(knet_h->tap_to_links_buf_crypt);
		if (knet_h->recv_from_links_buf_crypt)
			free(knet_h->recv_from_links_buf_crypt);
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	return;
}
