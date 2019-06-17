/*
 * Copyright (C) 2017-2019 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_handle_compress_cfg knet_handle_compress_cfg;

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));

	printf("Test knet_handle_compress incorrect knet_h\n");

	if ((!knet_handle_compress(NULL, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with invalid cfg\n");

	if ((!knet_handle_compress(knet_h, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid cfg or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with un-initialized cfg\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));

	if ((!knet_handle_compress(knet_h, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid un-initialized cfg\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with none compress model (disable compress)\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "none", sizeof(knet_handle_compress_cfg.compress_model) - 1);

	if (knet_handle_compress(knet_h, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress did not accept none compress mode cfg\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with zlib compress and not effective compression level (0)\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 0;

	if((knet_handle_compress(knet_h, &knet_handle_compress_cfg)) || (errno == EINVAL)) {
		printf("knet_handle_compress failed to compress with default compression level\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with zlib compress and negative level (-2)\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = -2;

	if ((!knet_handle_compress(knet_h, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid (-2) compress level for zlib\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with zlib compress and excessive compress level\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 10;

	if ((!knet_handle_compress(knet_h, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid (10) compress level for zlib\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with zlib compress and excessive compress threshold\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = KNET_MAX_PACKET_SIZE +1;

	if ((!knet_handle_compress(knet_h, &knet_handle_compress_cfg)) || (errno != EINVAL)) {
		printf("knet_handle_compress accepted invalid compress threshold\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_compress with zlib compress model normal compress level and threshold\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress did not accept zlib compress mode with compress level 1 cfg\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
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
