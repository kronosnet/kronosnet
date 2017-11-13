#include "remap.h"

#ifdef BUILDCRYPTOOPENSSL10
REMAP_PROTO(void,OPENSSL_add_all_algorithms_noconf,(void))
#endif
#ifdef BUILDCRYPTOOPENSSL11
REMAP_PROTO(int,OPENSSL_init_crypto,
            (uint64_t opts, const OPENSSL_INIT_SETTINGS *settings))
#endif

#ifdef BUILDCRYPTOOPENSSL10
REMAP_PROTO(void,ERR_load_crypto_strings,(void))
#endif
REMAP_PROTO(unsigned long,ERR_get_error,(void))
REMAP_PROTO(void,ERR_error_string_n,
            (unsigned long e, char *buf, size_t len))

REMAP_PROTO(void,RAND_seed,(const void *buf, int num))
REMAP_PROTO(int,RAND_bytes,(unsigned char *buf, int num))

REMAP_PROTO(const EVP_MD *,EVP_get_digestbyname,(const char *name))
REMAP_PROTO(int,EVP_MD_size,(const EVP_MD *md))
REMAP_PROTO(unsigned char *,HMAC,
            (const EVP_MD *evp_md, const void *key, int key_len,
             const unsigned char *d, size_t n, unsigned char *md,
             unsigned int *md_len))

REMAP_PROTO(const EVP_CIPHER *,EVP_get_cipherbyname,(const char *name))
REMAP_PROTO(int,EVP_CIPHER_block_size,(const EVP_CIPHER *cipher))

#ifdef BUILDCRYPTOOPENSSL10
REMAP_PROTO(void,EVP_CIPHER_CTX_init,(EVP_CIPHER_CTX *a))
REMAP_PROTO(int,EVP_CIPHER_CTX_cleanup,(EVP_CIPHER_CTX *a))
#endif
#ifdef BUILDCRYPTOOPENSSL11
REMAP_PROTO(EVP_CIPHER_CTX *,EVP_CIPHER_CTX_new,(void))
REMAP_PROTO(void,EVP_CIPHER_CTX_free,(EVP_CIPHER_CTX *c))
#endif

REMAP_PROTO(int,EVP_EncryptInit_ex,
            (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
             ENGINE *impl, const unsigned char *key,
             const unsigned char *iv))
REMAP_PROTO(int,EVP_EncryptUpdate,
            (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
             const unsigned char *in, int inl))
REMAP_PROTO(int,EVP_EncryptFinal_ex,
            (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl))

REMAP_PROTO(int,EVP_DecryptInit_ex,
            (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
             ENGINE *impl, const unsigned char *key,
             const unsigned char *iv))
REMAP_PROTO(int,EVP_DecryptUpdate,
            (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
             const unsigned char *in, int inl))
REMAP_PROTO(int,EVP_DecryptFinal_ex,
            (EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl))
