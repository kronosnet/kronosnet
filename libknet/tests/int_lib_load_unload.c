#include "config.h"

#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>

#include "libknet.h"
#include "test-common.h"

char *orig[256];
int orig_idx = 0;

char *cur[256];
int cur_idx = 0;

int use_cur = 0;

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	if (strlen(info->dlpi_name) > 0) {
		if (use_cur) {
			cur[cur_idx] = strdup(info->dlpi_name);
			cur_idx++;
		} else {
			orig[orig_idx] = strdup(info->dlpi_name);
			orig_idx++;
		}
	}

	return 0;
}

static void free_loop(void)
{
	int i;

	if (use_cur) {
		for (i = 0; i < cur_idx; i++) {
			free(cur[i]);
			cur[i] = NULL;
		}
		cur_idx = 0;
	} else {
		for (i = 0; i < orig_idx; i++) {
			free(orig[i]);
			orig[i] = NULL;
		}
		orig_idx = 0;
	}
}

#if defined(BUILDCRYPTONSS) || defined(BUILDCOMPZLIB)
static int dump_all = 0;
static int find_lib(const char *libname)
{
	int i;

	for (i = 0; i < cur_idx; i++) {
		if (dump_all) {
			printf("BLA: %s\n", cur[i]);
		}
		if (strstr(cur[i], libname) != NULL) {
			return 1;
		}
	}
	return 0;
}
#endif

static void test(void)
{
	int logfds[2];
	knet_handle_t knet_h1, knet_h2;
#ifdef BUILDCRYPTONSS
	struct knet_handle_crypto_cfg knet_handle_crypto_cfg;
#endif
#ifdef BUILDCOMPZLIB
	struct knet_handle_compress_cfg knet_handle_compress_cfg;
#endif
	int do_close = 0;

	use_cur = 0;
	dl_iterate_phdr(callback, NULL);
	use_cur = 1;

	setup_logpipes(logfds);

	knet_h1 = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);
	if (!knet_h1) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

#ifdef BUILDCRYPTONSS
	printf("Testing loading nss crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libnss")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing unloading nss crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libnss")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: nss support not builtin the library. Unable to test/verify internal crypto load/unload code\n");
#endif

#ifdef BUILDCRYPTOOPENSSL
	printf("Testing loading openssl crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "openssl", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libcrypto")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing unloading openssl crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libcrypto")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: openssl support not builtin the library. Unable to test/verify internal crypto load/unload code\n");
#endif

#ifdef BUILDCOMPZLIB
	printf("Testing loading compress library\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libz")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing unloading compress library\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "none", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libz")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: zlib support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif

	knet_h2 = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);
	if (!knet_h2) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

#ifdef BUILDCRYPTONSS
	printf("Testing multiple handles loading nss crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libnss")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libnss")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libnss")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: nss support not builtin the library. Unable to test/verify internal crypto load/unload code\n");
#endif

#ifdef BUILDCRYPTOOPENSSL
	printf("Testing multiple handles loading openssl crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "openssl", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libcrypto")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libcrypto")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libcrypto")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: openssl support not builtin the library. Unable to test/verify internal crypto load/unload code\n");
#endif

#ifdef BUILDCOMPZLIB
	printf("Testing multiple handles loading compress library\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	if (knet_handle_compress(knet_h2, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libz")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading compress library\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "none", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libz")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	if (knet_handle_compress(knet_h2, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libz")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: zlib support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif

#ifdef BUILDCRYPTONSS
#ifdef BUILDCRYPTOOPENSSL
	printf("Testing multiple handles loading different crypto libraries\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "openssl", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libnss")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (!find_lib("libcrypto")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading crypto library\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "none", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "none", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "none", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libnss")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libcrypto")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

#else
	printf("WARNING: openssl support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif
#else
	printf("WARNING: nss support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif

#ifdef BUILDCRYPTONSS
#ifdef BUILDCRYPTOOPENSSL
	printf("Testing multiple handles loading different crypto libraries (part 2)\n");

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "nss", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h1, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	memset(&knet_handle_crypto_cfg, 0, sizeof(struct knet_handle_crypto_cfg));
	strncpy(knet_handle_crypto_cfg.crypto_model, "openssl", sizeof(knet_handle_crypto_cfg.crypto_model) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_cipher_type, "aes128", sizeof(knet_handle_crypto_cfg.crypto_cipher_type) - 1);
	strncpy(knet_handle_crypto_cfg.crypto_hash_type, "sha1", sizeof(knet_handle_crypto_cfg.crypto_hash_type) - 1);
	knet_handle_crypto_cfg.private_key_len = 2000;

	if (knet_handle_crypto(knet_h2, &knet_handle_crypto_cfg)) {
		printf("knet_handle_crypto failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libnss")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (!find_lib("libcrypto")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading crypto library by closing handles\n");

	knet_handle_free(knet_h1);
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libnss")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	knet_handle_free(knet_h2);
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libcrypto")) {
		printf("library doesn't appear to be unloaded\n");
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: openssl support not builtin the library. Unable to test/verify internal compress load/unload code\n");
	do_close = 1;
#endif
#else
	printf("WARNING: nss support not builtin the library. Unable to test/verify internal compress load/unload code\n");
	do_close = 1;
#endif

	knet_h1 = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);
	if (!knet_h1) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	knet_h2 = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);
	if (!knet_h2) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);


#ifdef BUILDCOMPZLIB
#ifdef BUILDCOMPBZIP2
	printf("Testing multiple handles loading different compress libraries\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "bzip2", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h2, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libz")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (!find_lib("libbz2")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading compress library\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "none", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libz")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	if (knet_handle_compress(knet_h2, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libbz2")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: bzip2 support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif
#else
	printf("WARNING: zlib support not builtin the library. Unable to test/verify internal compress load/unload code\n");
#endif

#ifdef BUILDCOMPZLIB
#ifdef BUILDCOMPBZIP2
	printf("Testing multiple handles loading different compress libraries (part 2)\n");

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "zlib", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h1, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, "bzip2", sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 1;
	knet_handle_compress_cfg.compress_threshold = 64;

	if (knet_handle_compress(knet_h2, &knet_handle_compress_cfg) != 0) {
		printf("knet_handle_compress failed with correct config: %s\n", strerror(errno));
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (!find_lib("libz")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (!find_lib("libbz2")) {
		printf("library doesn't appear to be loaded\n");
		knet_handle_free(knet_h1);
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	printf("Testing multiple handles unloading compress library by closing handles\n");

	knet_handle_free(knet_h1);
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libz")) {
		printf("library doesn't appear to be unloaded\n");
		knet_handle_free(knet_h2);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();

	knet_handle_free(knet_h2);
	flush_logs(logfds[0], stdout);

	dl_iterate_phdr(callback, NULL);

	if (find_lib("libbz2")) {
		printf("library doesn't appear to be unloaded\n");
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	free_loop();
#else
	printf("WARNING: bzip2 support not builtin the library. Unable to test/verify internal compress load/unload code\n");
	do_close = 1;
#endif
#else
	printf("WARNING: zlib support not builtin the library. Unable to test/verify internal compress load/unload code\n");
	do_close = 1;
#endif

	if (do_close) {
		knet_handle_free(knet_h2);
		knet_handle_free(knet_h1);
	}
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
	use_cur = 0;
	free_loop();
}

int main(int argc, char *argv[])
{
	need_root();

	test();

	return PASS;
}
