/*
 * tls_crypto.h — Internal crypto primitives for testing and benchmarking.
 * Not part of the public API (use tls_client.h for that).
 */
#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Digest / key lengths */
#define SHA1_DIGEST_LEN   20
#define SHA256_DIGEST_LEN 32
#define SHA384_DIGEST_LEN 48

#define X25519_KEY_LEN 32
#define X448_KEY_LEN   56

/* Hash contexts */
typedef struct { uint32_t h[8]; uint8_t buf[64]; size_t buf_len; uint64_t total; } sha256_ctx;
typedef struct { uint32_t h[5]; uint8_t buf[64]; size_t buf_len; uint64_t total; } sha1_ctx;
typedef struct { uint64_t h[8]; uint8_t buf[128]; size_t buf_len; uint64_t total; } sha512_ctx;
typedef sha512_ctx sha384_ctx;

typedef struct { uint64_t st[25]; uint8_t buf[136]; size_t buf_len; } shake256_ctx;
typedef struct {
    uint64_t st[25];
    uint8_t buf[168];
    size_t buf_len;
    int finalized;
    size_t squeeze_pos;
} shake128_ctx;

/* Hash algorithm abstraction */
typedef void (*hash_fn_t)(const uint8_t*, size_t, uint8_t*);
typedef struct {
    void (*init)(void*);
    void (*update)(void*, const uint8_t*, size_t);
    void (*final_fn)(void*, uint8_t*);
    hash_fn_t hash;
    size_t digest_len, block_size;
} hash_alg;

extern const hash_alg SHA256_ALG;
extern const hash_alg SHA384_ALG;

/* SHA family */
void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20]);
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]);
void sha384_hash(const uint8_t *data, size_t len, uint8_t out[48]);
void sha512_hash(const uint8_t *data, size_t len, uint8_t out[64]);

/* SHA-3 / SHAKE */
void shake256_init(shake256_ctx *ctx);
void shake256_final(shake256_ctx *ctx, uint8_t *out, size_t out_len);
void sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);
void shake128_init(shake128_ctx *ctx);
void shake128_update(shake128_ctx *ctx, const uint8_t *data, size_t len);
void shake128_finalize(shake128_ctx *ctx);
void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t out_len);

/* HMAC / HKDF */
void hmac(const hash_alg *alg, const uint8_t *key, size_t klen,
          const uint8_t *msg, size_t mlen, uint8_t *out);
void hkdf_extract_u(const hash_alg *alg, const uint8_t *salt, size_t slen,
                     const uint8_t *ikm, size_t ilen, uint8_t *out);
void hkdf_expand_u(const hash_alg *alg, const uint8_t *prk,
                    const uint8_t *info, size_t ilen, uint8_t *out, size_t olen);

/* AES-GCM */
void aes_gcm_encrypt_impl(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[16]);
int aes_gcm_decrypt_impl(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct, size_t ct_len,
                          uint8_t *pt, const uint8_t tag[16]);

/* AES-CBC */
void aes_cbc_encrypt(const uint8_t *key, size_t key_len,
                     const uint8_t iv[16], const uint8_t *pt, size_t pt_len,
                     uint8_t *ct);

/* ChaCha20 / Poly1305 */
void chacha20_encrypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                      const uint8_t *in, size_t len, uint8_t *out);
void poly1305_mac(const uint8_t key[32], const uint8_t *msg,
                  size_t msg_len, uint8_t tag[16]);
void chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t *ct, uint8_t tag[16]);
int chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               uint8_t *pt, const uint8_t tag[16]);

/* X25519 / Ed25519 */
void x25519_scalar_mult(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);
int x25519_shared_secret(const uint8_t priv[32], const uint8_t pub[32], uint8_t out[32]);
int ed25519_verify(const uint8_t pubkey[32], const uint8_t *msg, size_t msg_len,
                   const uint8_t sig[64]);

/* X448 / Ed448 */
void x448_scalar_mult(const uint8_t scalar[56], const uint8_t point[56], uint8_t out[56]);
int x448_shared_secret(const uint8_t priv[56], const uint8_t pub[56], uint8_t out[56]);
int ed448_verify(const uint8_t pubkey[57], const uint8_t *msg, size_t msg_len,
                 const uint8_t sig[114]);

/* ML-KEM-768 */
void mlkem768_keygen(uint8_t ek[1184], uint8_t dk[2400]);
void mlkem768_encaps(const uint8_t ek[1184], uint8_t ct[1088], uint8_t ss[32]);
void mlkem768_decaps(const uint8_t dk[2400], const uint8_t ct[1088], uint8_t ss[32]);

#endif
