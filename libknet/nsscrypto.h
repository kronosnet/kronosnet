#ifndef NSSCRYPTO_H_DEFINED
#define NSSCRYPTO_H_DEFINED

#include <sys/types.h>
#include "libknet.h"

struct nsscrypto_instance;

int nsscrypto_authenticate_and_decrypt (
	void *model_instance,
	unsigned char *buf,
	ssize_t *buf_len);

int nsscrypto_encrypt_and_sign (
	void *model_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out, 
	ssize_t *buf_out_len);

int nsscrypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

void nsscrypto_fini(
	knet_handle_t knet_h);

#endif /* NSSCRYPTO_H_DEFINED */
