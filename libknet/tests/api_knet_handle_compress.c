/*
 * Copyright (C) 2017-2023 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknet.h"

#include "internals.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int res;
	struct knet_handle_compress_cfg knet_handle_compress_cfg;

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	setup_logpipes(logfds);

	printf("Test knet_handle_compress incorrect knet_h\n");
	if ((!knet_handle_compress(NULL, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_compress with invalid cfg\n");
	FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, NULL), EINVAL);

	printf("Test knet_handle_compress with un-initialized cfg\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, &knet_handle_compress_cfg), EINVAL);

	printf("Test knet_handle_compress with none compress model (disable compress)\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "none", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	FAIL_ON_ERR(knet_handle_compress(knet_h1, &knet_handle_compress_cfg));

#if WITH_COMPRESS_BZIP2 > 0
	printf("Test knet_handle_compress with bzip2 (no default) with negative level (-3)\n");
        memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
        strncpy(knet_handle_compress_cfg.compress_model, "bzip2", sizeof(knet_handle_compress_cfg.compress_model) - 1);
        knet_handle_compress_cfg.compress_level = -3;

        FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, &knet_handle_compress_cfg), EINVAL);
#endif
	printf("Test knet_handle_compress with zlib compress and not effective compression level (0)\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 0;
	FAIL_ON_ERR(knet_handle_compress(knet_h1, &knet_handle_compress_cfg));

	printf("Test knet_handle_compress with zlib compress and negative level (-2)\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = -2;
	FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, &knet_handle_compress_cfg), EINVAL);

	printf("Test knet_handle_compress with zlib compress and excessive compress level\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 10;
	FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, &knet_handle_compress_cfg), EINVAL);


	printf("Test knet_handle_compress with zlib compress and excessive compress threshold\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = KNET_MAX_PACKET_SIZE +1;
	FAIL_ON_SUCCESS(knet_handle_compress(knet_h1, &knet_handle_compress_cfg), EINVAL);

	printf("Test knet_handle_compress with zlib compress model normal compress level and threshold\n");
	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;
	FAIL_ON_ERR(knet_handle_compress(knet_h1, &knet_handle_compress_cfg));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	struct knet_compress_info compress_list[16];
	size_t compress_list_entries;
	size_t i;

	memset(compress_list, 0, sizeof(compress_list));

	if (knet_get_compress_list(compress_list, &compress_list_entries) < 0) {
		printf("knet_get_compress_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (compress_list_entries == 0) {
		printf("no compression modules detected. Skipping\n");
		return SKIP;
	}

	for (i=0; i < compress_list_entries; i++) {
		if (!strcmp(compress_list[i].name, "zlib")) {
			test();
			return PASS;
		}
	}

	printf("WARNING: zlib support not builtin the library. Unable to test/verify internal compress API calls\n");
	return SKIP;
}
