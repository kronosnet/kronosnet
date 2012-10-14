#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "nsscrypto.h"
#include "libknet.h"

#ifdef CRYPTO_DEBUG
#include <stdio.h>
#define log_printf(format, args...) fprintf(stderr, format "\n", ##args);
#else
#define log_printf(format, args...);
#endif

/*
 * internal module switch data
 */

crypto_model_t modules_cmds[] = {
	{ "nss", nsscrypto_init, nsscrypto_fini, nsscrypto_encrypt_and_sign, nsscrypto_authenticate_and_decrypt },
	{ NULL, NULL, NULL, NULL, NULL },
};

static int get_model(const char *model)
{
	int idx = 0;

	while (modules_cmds[idx].model_name != NULL) {
		if (!strcmp(modules_cmds[idx].model_name, model))
			return idx;
		idx++;
	}
	return -1;
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
	return modules_cmds[instance->model].crypt(instance->model_instance,
					  buf_in, buf_in_len, buf_out, buf_out_len);
}

int crypto_authenticate_and_decrypt (struct crypto_instance *instance,
	unsigned char *buf,
	ssize_t *buf_len)
{
	return modules_cmds[instance->model].decrypt(instance->model_instance, buf, buf_len);
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

	knet_h->crypto_instance->model = get_model(knet_handle_crypto_cfg->crypto_model);
	if (knet_h->crypto_instance->model < 0) {
		log_printf("model %s not supported", knet_handle_crypto_cfg->crypto_model);
		goto out_err;
	}

	if (modules_cmds[knet_h->crypto_instance->model].init(knet_h, knet_handle_crypto_cfg))
		goto out_err;

	return 0;

out_err:
	free(knet_h->crypto_instance);
	knet_h->crypto_instance = NULL;
	return -1;
}

void crypto_fini(
	knet_handle_t knet_h)
{
	if (knet_h->crypto_instance) {
		modules_cmds[knet_h->crypto_instance->model].fini(knet_h);
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	return;
}
