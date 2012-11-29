/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef NSSCRYPTO_H_DEFINED
#define NSSCRYPTO_H_DEFINED

#include <sys/types.h>
#include "libknet.h"

struct nsscrypto_instance;

int nsscrypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	unsigned char *buf,
	ssize_t *buf_len);

int nsscrypto_encrypt_and_sign (
	knet_handle_t knet_h,
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
