/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPRESS_MODEL_H__
#define __KNET_COMPRESS_MODEL_H__

#include "internals.h"

/* This separate typedef can be removed again when the load_lib field disappears */
typedef struct compress_model_t compress_model_t;

struct compress_model_t {
	const char	*model_name;
	uint8_t		model_id;    /* sequencial unique identifier */
	uint8_t		built_in;    /* set at configure/build time to 1 if available */

	/*
	 * shared lib load functions
	 *
	 * both are called in shlib_rwlock write context and should
	 * update the loaded status below.
	 */
	int (*load_lib)		(knet_handle_t knet_h, compress_model_t *self);

	/*
	 * library is loaded
	 */
	uint8_t		loaded;

	/*
	 * runtime bits
	 */

	/*
	 * some libs need special init and handling of buffers etc.
	 * is_init is called in shlib_rwlock read only context to see if
	 * the module has been initialized within this knet_handle.
	 * Providing is_init is optional. A module that does not export
	 * an is_init and if the associated shared library is already loaded
	 * is treated as "does not require init".
	 */
	int (*is_init)  (knet_handle_t knet_h, int method_idx);

	/*
	 * init is called when the library requires special init handling,
	 * such as memory allocation and such.
	 * init is invoked in shlib_rwlock write only context when
	 * the module exports this function.
	 * It is optional to provide an init function if the module
	 * does not require any init.
	 */
	int (*init)     (knet_handle_t knet_h, int method_idx);

	/*
	 * fini is invoked only on knet_handle_free in a write only context.
	 * It is optional to provide this function if the module
	 * does not require any finalization
	 */
	void (*fini)    (knet_handle_t knet_h, int method_idx);

	/*
	 * runtime config validation and compress/decompress
	 */

	/*
	 * required functions
	 *
	 * val_level is called upon compress configuration changes
	 * to make sure that the requested compress_level is valid
	 * within the context of a given module.
	 */
	int (*val_level)(knet_handle_t knet_h,
			 int compress_level);

	/*
	 * hopefully those 2 don't require any explanation....
	 */
	int (*compress)	(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
	int (*decompress)(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
};

#endif
