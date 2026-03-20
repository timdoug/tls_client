/*
 * tls_bench.c — Benchmarks for tls_client crypto primitives.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tls_crypto.h"

/* Detect hardware acceleration (must match tls_client.c logic) */
#if defined(__aarch64__) && (defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES))
#define USE_ARM64_CRYPTO 1
#else
#define USE_ARM64_CRYPTO 0
#endif

#if defined(__x86_64__) && defined(__AES__) && defined(__PCLMUL__)
#define USE_X86_AES 1
#else
#define USE_X86_AES 0
#endif

int main(void) {
    printf("Benchmarks");
#if USE_ARM64_CRYPTO
    printf(" (ARM64 crypto extensions enabled)");
#elif USE_X86_AES
    printf(" (x86-64: AES-NI PCLMULQDQ)");
#else
    printf(" (portable C)");
#endif
    printf(":\n");

    #define BENCH_BYTES (4 * 1024 * 1024)
    uint8_t *buf = malloc(BENCH_BYTES);
    uint8_t *out = malloc(BENCH_BYTES + 16);
    if(!buf || !out) { printf("  malloc failed\n"); return 1; }
    memset(buf, 0xAB, BENCH_BYTES);

    uint8_t key32[32] = {0}, nonce12[12] = {0}, tag[32], iv16[16] = {0};
    struct timespec t0, t1;
    double elapsed, mbs;

    /* SHA-256 */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    { sha256_ctx c; sha256_init(&c); sha256_update(&c, buf, BENCH_BYTES); sha256_final(&c, tag); }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    mbs = ((double)BENCH_BYTES / (1024.0 * 1024.0)) / elapsed;
    printf("  SHA-256           %8.1f MB/s\n", mbs);

    /* AES-128-GCM encrypt */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    aes_gcm_encrypt_impl(key32, 16, nonce12, NULL, 0, buf, BENCH_BYTES, out, tag);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    mbs = ((double)BENCH_BYTES / (1024.0 * 1024.0)) / elapsed;
    printf("  AES-128-GCM       %8.1f MB/s\n", mbs);

    /* AES-256-GCM encrypt */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    aes_gcm_encrypt_impl(key32, 32, nonce12, NULL, 0, buf, BENCH_BYTES, out, tag);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    mbs = ((double)BENCH_BYTES / (1024.0 * 1024.0)) / elapsed;
    printf("  AES-256-GCM       %8.1f MB/s\n", mbs);

    /* AES-128-CBC encrypt */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    aes_cbc_encrypt(key32, 16, iv16, buf, BENCH_BYTES, out);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    mbs = ((double)BENCH_BYTES / (1024.0 * 1024.0)) / elapsed;
    printf("  AES-128-CBC       %8.1f MB/s\n", mbs);

    /* ChaCha20-Poly1305 encrypt */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    chacha20_poly1305_encrypt(key32, nonce12, NULL, 0, buf, BENCH_BYTES, out, tag);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    mbs = ((double)BENCH_BYTES / (1024.0 * 1024.0)) / elapsed;
    printf("  ChaCha20-Poly1305 %8.1f MB/s\n", mbs);

    free(buf); free(out);
    return 0;
}
