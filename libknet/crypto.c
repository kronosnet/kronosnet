#include "config.h"

#include <stdlib.h>

#include "crypto.h"
#include "nsscrypto.h"
#include "libknet-private.h"

#ifdef CRYPTO_DEBUG
#define log_printf(format, args...) fprintf(stderr, format "\n", ##args);
#else
#define log_printf(format, args...);
#endif

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
	return nsscrypto_encrypt_and_sign(instance->model_instance,
					  buf_in, buf_in_len, buf_out, buf_out_len);
}

int crypto_authenticate_and_decrypt (struct crypto_instance *instance,
	unsigned char *buf,
	ssize_t *buf_len)
{
	return nsscrypto_authenticate_and_decrypt(instance->model_instance, buf, buf_len);
}

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	log_printf("Initizializing crypto module [%s/%s/%s]",
		  knet_handle_crypto_cfg->crypto_model,
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance = malloc(sizeof(struct crypto_instance));

	if (!knet_h->crypto_instance) {
		log_printf("no memory from crypto");
		return -1;
	}

	/* do the model switch here */
	if (nsscrypto_init(knet_h, knet_handle_crypto_cfg)) {
		free(knet_h->crypto_instance);
		return -1;
	}

	return nsscrypto_init(knet_h, knet_handle_crypto_cfg);
}

void crypto_fini(
	knet_handle_t knet_h)
{
	if (knet_h->crypto_instance) {
		nsscrypto_fini(knet_h);
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	return;
}
