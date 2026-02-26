#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H
#include <stdint.h>
#include <stddef.h>

extern int tls_verbose;

uint8_t *do_https_get(const char *host, int port, const char *path, size_t *out_len);

/* Crypto primitives (for tests) */
typedef struct { uint64_t st[25]; uint8_t buf[136]; size_t buf_len; } shake256_ctx;
void shake256_init(shake256_ctx *ctx);
void shake256_update(shake256_ctx *ctx, const uint8_t *data, size_t len);
void shake256_final(shake256_ctx *ctx, uint8_t *out, size_t out_len);

int ed25519_verify(const uint8_t pubkey[32], const uint8_t *msg, size_t msg_len, const uint8_t sig[64]);
void x448_scalar_mult(const uint8_t scalar[56], const uint8_t u_in[56], uint8_t u_out[56]);
int x448_shared_secret(const uint8_t priv[56], const uint8_t peer[56], uint8_t out[56]);
int ed448_verify(const uint8_t pubkey[57], const uint8_t *msg, size_t msg_len, const uint8_t sig[114]);

#endif
