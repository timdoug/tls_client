/*
 * tls_client.c — TLS 1.2/1.3 HTTPS client library from scratch in C.
 * Implements: SHA-1, SHA-256, SHA-384, SHA-512, SHAKE256, HMAC, HKDF,
 *             AES-128/256-GCM, AES-128/256-CBC, ChaCha20-Poly1305,
 *             ECDHE-P256/P384, X25519, X448, Ed25519, Ed448, TLS 1.2/1.3
 * No external crypto libraries.
 *
 * Certificate verification: SHA-256/384/512, ECDSA-P256/P384,
 *   RSA PKCS#1 v1.5, RSA-PSS, Ed25519, Ed448, X.509 chain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include "tls_client.h"

int tls_verbose = 0;

/* ---- Detect limb width: 64-bit on 64-bit platforms, 32-bit otherwise ---- */
#if !defined(USE_64BIT_LIMBS)
#if defined(__LP64__) || defined(_LP64) || defined(_WIN64) || \
    defined(__x86_64__) || defined(__aarch64__) || defined(__ppc64__) || \
    defined(__s390x__) || defined(__mips64) || \
    (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ >= 8)
#define USE_64BIT_LIMBS 1
#else
#define USE_64BIT_LIMBS 0
#endif
#endif

#if USE_64BIT_LIMBS
typedef uint64_t limb_t;
#define LIMB_BITS  64
#define LIMB_BYTES 8
#define FP384_N    6
#define FP256_N    4
#define FP25519_N  4
#define FP448_N    7
#define BN_MAX_LIMBS 130
#else
typedef uint32_t limb_t;
#define LIMB_BITS  32
#define LIMB_BYTES 4
#define FP384_N    12
#define FP256_N    8
#define FP25519_N  8
#define FP448_N    14
#define BN_MAX_LIMBS 260
#endif

/* 64×64→128 multiply */
#if defined(__SIZEOF_INT128__)
static inline void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    __extension__ unsigned __int128 p = (unsigned __int128)a * b;
    *lo = (uint64_t)p;
    *hi = (uint64_t)(p >> 64);
}
#else
/* Portable fallback via 32-bit half-products (C11 compliant) */
static inline void mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;
    uint64_t mid = p1 + (p0 >> 32);
    uint64_t carry = (mid < p1);
    mid += p2;
    carry += (mid < p2);
    *lo = (mid << 32) | (uint32_t)p0;
    *hi = p3 + (mid >> 32) + (carry << 32);
}
#endif

static inline uint64_t addcarry64(uint64_t a, uint64_t b, uint64_t *sum) {
    *sum = a + b;
    return (*sum < a) ? 1 : 0;
}

/* 64-bit helpers: used by 64-bit limb path and by Poly1305's 64-bit fp25519_mul */
#if USE_64BIT_LIMBS
/* Multiply-accumulate: (hi:lo) = a*b + addend + carry_in */
static inline void mac64(uint64_t a, uint64_t b, uint64_t addend, uint64_t carry_in,
                         uint64_t *hi, uint64_t *lo) {
    uint64_t ph, pl;
    mul64(a, b, &ph, &pl);
    uint64_t s = pl + addend;
    uint64_t c = (s < pl);
    *lo = s + carry_in;
    c += (*lo < s);
    *hi = ph + c;
}

/* Add with carry: sum = a + b + carry_in, returns carry out */
static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t *sum) {
    uint64_t s = a + b;
    uint64_t c = (s < a);
    *sum = s + carry_in;
    c += (*sum < s);
    return c;
}

/* Subtract with borrow: diff = a - b - borrow_in, returns borrow out */
static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t *diff) {
    uint64_t d = a - b;
    uint64_t c = (a < b);
    *diff = d - borrow_in;
    c += (d < borrow_in);
    return c;
}
#endif

/* ---- Generic limb-width helpers (aliases on 64-bit, native on 32-bit) ---- */
#if USE_64BIT_LIMBS
#define mac_limb mac64
#define adc_limb adc64
#define sbb_limb sbb64
#else
static inline void mac_limb(uint32_t a, uint32_t b, uint32_t addend, uint32_t carry_in,
                             uint32_t *hi, uint32_t *lo) {
    uint64_t p = (uint64_t)a * b + addend + carry_in;
    *lo = (uint32_t)p; *hi = (uint32_t)(p >> 32);
}
static inline uint32_t adc_limb(uint32_t a, uint32_t b, uint32_t carry_in, uint32_t *sum) {
    uint64_t s = (uint64_t)a + b + carry_in;
    *sum = (uint32_t)s; return (uint32_t)(s >> 32);
}
static inline uint32_t sbb_limb(uint32_t a, uint32_t b, uint32_t borrow_in, uint32_t *diff) {
    uint32_t d = a - b, c = (a < b);
    *diff = d - borrow_in; c += (d < borrow_in);
    return c;
}
#endif

#define PUT16(b,v) do{(b)[0]=(uint8_t)((v)>>8);(b)[1]=(uint8_t)(v);}while(0)
#define GET16(b) ((uint16_t)(((uint16_t)(b)[0]<<8)|(b)[1]))
#define GET24(b) (((uint32_t)(b)[0]<<16)|((uint32_t)(b)[1]<<8)|(b)[2])

static inline void put_be64(uint8_t buf[8], uint64_t val) {
    for(int i=7;i>=0;i--) { buf[i]=(uint8_t)(val&0xFF); val>>=8; }
}

/* TLS record types */
#define TLS_RT_CCS      0x14
#define TLS_RT_ALERT     0x15
#define TLS_RT_HANDSHAKE 0x16
#define TLS_RT_APPDATA   0x17

/* TLS versions */
#define TLS_VERSION_10   0x0301
#define TLS_VERSION_12   0x0303
#define TLS_VERSION_13   0x0304

/* Crypto sizes */
#define SHA256_DIGEST_LEN  32
#define SHA384_DIGEST_LEN  48
#define AES128_KEY_LEN     16
#define AES256_KEY_LEN     32
#define AES_GCM_NONCE_LEN  12
#define AES_GCM_TAG_LEN    16

/* EC sizes */
#define P256_POINT_LEN    65
#define P384_POINT_LEN    97
#define P256_SCALAR_LEN   32
#define P384_SCALAR_LEN   48

/* Named groups */
#define TLS_GROUP_X25519    0x001D
#define TLS_GROUP_X448      0x001E
#define TLS_GROUP_SECP256R1 0x0017
#define TLS_GROUP_SECP384R1 0x0018

/* X25519 / X448 / ChaCha20-Poly1305 sizes */
#define X25519_KEY_LEN            32
#define X25519_A24                121665
#define X448_KEY_LEN              56
#define X448_A24                  39081
#define CHACHA20_POLY1305_TAG_LEN 16
#define ED25519_SIG_LEN           64
#define ED448_SIG_LEN             114

/* TLS plaintext / AES-CBC sizes */
#define TLS_MAX_PLAINTEXT 16384
#define AES_BLOCK_SIZE    16

/* TLS 1.3 cipher suites */
#define TLS_AES_128_GCM_SHA256        0x1301
#define TLS_AES_256_GCM_SHA384        0x1302
#define TLS_CHACHA20_POLY1305_SHA256  0x1303

/* TLS 1.2 cipher suites */
#define TLS_ECDHE_ECDSA_CHACHA_POLY   0xCCA9
#define TLS_ECDHE_RSA_CHACHA_POLY     0xCCA8
#define TLS_ECDHE_ECDSA_AES128_GCM   0xC02B
#define TLS_ECDHE_RSA_AES128_GCM     0xC02F
#define TLS_ECDHE_ECDSA_AES256_GCM   0xC02C
#define TLS_ECDHE_RSA_AES256_GCM     0xC030
#define TLS_RSA_AES256_GCM           0x009D
#define TLS_RSA_AES128_GCM           0x009C
#define TLS_ECDHE_RSA_AES256_CBC     0xC014
#define TLS_ECDHE_RSA_AES128_CBC     0xC013
#define TLS_ECDHE_ECDSA_AES256_CBC   0xC00A
#define TLS_ECDHE_ECDSA_AES128_CBC   0xC009
#define TLS_RSA_AES256_CBC           0x0035
#define TLS_RSA_AES128_CBC           0x002F

/* Signature algorithms (RFC 8446 §4.2.3) */
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIG_ECDSA_SECP384R1_SHA384 0x0503
#define TLS_SIG_RSA_PKCS1_SHA256       0x0401
#define TLS_SIG_RSA_PKCS1_SHA384       0x0501
#define TLS_SIG_RSA_PSS_SHA256         0x0804
#define TLS_SIG_RSA_PSS_SHA384         0x0805
#define TLS_SIG_ED25519                0x0807
#define TLS_SIG_ED448                  0x0808

/* Buffer sizes */
#define CH_BUF_SIZE   2048
#define REC_BUF_SIZE  32768
#define HS_BUF_SIZE   65536
#define REQ_BUF_SIZE  512

/* Socket read timeouts (seconds) */
#define TLS_READ_TIMEOUT_S   10
#define AIA_READ_TIMEOUT_S   5
#define CRL_READ_TIMEOUT_S   10

static void __attribute__((noreturn)) die(const char *msg) { fprintf(stderr, "FATAL: %s\n", msg); exit(1); }

static void random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) die("open urandom");
    size_t d = 0;
    while(d < len) {
        ssize_t n = read(fd, buf+d, len-d);
        if(n<=0) die("read urandom");
        d+=(size_t)n;
    }
    close(fd);
}

static int read_exact(int fd, uint8_t *buf, size_t len) {
    size_t d = 0;
    while(d < len) { ssize_t n = read(fd, buf+d, len-d); if(n<=0) return -1; d+=(size_t)n; }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t d = 0;
    while(d < len) { ssize_t n = write(fd, buf+d, len-d); if(n<=0) return -1; d+=(size_t)n; }
    return 0;
}

/* Constant-time helpers */
static void secure_zero(void *p, size_t len) {
    volatile uint8_t *v = p;
    while(len--) *v++ = 0;
}

static int ct_memeq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = a, *y = b;
    volatile uint8_t diff = 0;
    for(size_t i = 0; i < len; i++) diff |= x[i] ^ y[i];
    /* Constant-time: map 0 -> 1, nonzero -> 0 without branching */
    return (int)(1 & ((uint32_t)(diff - 1) >> 8));
}

/* ================================================================
 * SHA-256
 * ================================================================ */
static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct { uint32_t h[8]; uint8_t buf[64]; size_t buf_len; uint64_t total; } sha256_ctx;

#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define SIG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define SIG1(x) (RR(x,17)^RR(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t blk[64]) {
    uint32_t w[64], a,b,c,d,e,f,g,h;
    for(size_t i=0;i<16;i++)
        w[i]=((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)
            |((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    for(int i=16;i<64;i++)
        w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];
    e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
    for(int i=0;i<64;i++) {
        uint32_t t1=h+EP1(e)+CH(e,f,g)+sha256_k[i]+w[i], t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;
    ctx->h[4]+=e;ctx->h[5]+=f;ctx->h[6]+=g;ctx->h[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->h[0]=0x6a09e667;ctx->h[1]=0xbb67ae85;ctx->h[2]=0x3c6ef372;ctx->h[3]=0xa54ff53a;
    ctx->h[4]=0x510e527f;ctx->h[5]=0x9b05688c;ctx->h[6]=0x1f83d9ab;ctx->h[7]=0x5be0cd19;
    ctx->buf_len=0; ctx->total=0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total += len;
    while(len > 0) {
        size_t space = 64 - ctx->buf_len, chunk = len < space ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk; data += chunk; len -= chunk;
        if(ctx->buf_len == 64) { sha256_transform(ctx, ctx->buf); ctx->buf_len = 0; }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->total * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while(ctx->buf_len != 56) sha256_update(ctx, &pad, 1);
    uint8_t lb[8]; put_be64(lb, bits);
    sha256_update(ctx, lb, 8);
    for(size_t i=0;i<8;i++) {
        out[4*i]=(uint8_t)(ctx->h[i]>>24); out[4*i+1]=(uint8_t)(ctx->h[i]>>16);
        out[4*i+2]=(uint8_t)(ctx->h[i]>>8); out[4*i+3]=(uint8_t)ctx->h[i];
    }
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ================================================================
 * SHA-1 (needed for HMAC-SHA-1 MAC in TLS 1.2 AES-CBC-SHA cipher suites)
 * ================================================================ */
#define SHA1_DIGEST_LEN 20

typedef struct { uint32_t h[5]; uint8_t buf[64]; size_t buf_len; uint64_t total; } sha1_ctx;

static void sha1_transform(sha1_ctx *ctx, const uint8_t blk[64]) {
    uint32_t w[80];
    for(size_t i=0;i<16;i++)
        w[i]=((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)
            |((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    for(int i=16;i<80;i++){
        uint32_t t=w[i-3]^w[i-8]^w[i-14]^w[i-16];
        w[i]=(t<<1)|(t>>31);
    }
    uint32_t a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4];
    for(int i=0;i<80;i++){
        uint32_t f,k;
        if(i<20)      {f=(b&c)|((~b)&d);k=0x5A827999;}
        else if(i<40) {f=b^c^d;k=0x6ED9EBA1;}
        else if(i<60) {f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
        else          {f=b^c^d;k=0xCA62C1D6;}
        uint32_t tmp=((a<<5)|(a>>27))+f+e+k+w[i];
        e=d;d=c;c=(b<<30)|(b>>2);b=a;a=tmp;
    }
    ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;ctx->h[4]+=e;
}

static void sha1_init(sha1_ctx *ctx) {
    ctx->h[0]=0x67452301; ctx->h[1]=0xEFCDAB89; ctx->h[2]=0x98BADCFE;
    ctx->h[3]=0x10325476; ctx->h[4]=0xC3D2E1F0;
    ctx->buf_len=0;ctx->total=0;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total+=len;
    while(len>0){
        size_t space=64-ctx->buf_len, chunk=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,chunk);
        ctx->buf_len+=chunk;data+=chunk;len-=chunk;
        if(ctx->buf_len==64){sha1_transform(ctx,ctx->buf);ctx->buf_len=0;}
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t out[20]) {
    uint64_t bits=ctx->total*8;
    uint8_t pad=0x80;
    sha1_update(ctx,&pad,1);
    pad=0;
    while(ctx->buf_len!=56) sha1_update(ctx,&pad,1);
    uint8_t lb[8]; put_be64(lb, bits);
    sha1_update(ctx,lb,8);
    for(size_t i=0;i<5;i++){
        out[4*i]=(uint8_t)(ctx->h[i]>>24); out[4*i+1]=(uint8_t)(ctx->h[i]>>16);
        out[4*i+2]=(uint8_t)(ctx->h[i]>>8); out[4*i+3]=(uint8_t)ctx->h[i];
    }
}

static void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx c; sha1_init(&c); sha1_update(&c,data,len); sha1_final(&c,out);
}

/* ================================================================
 * SHA-512 / SHA-384 (64-bit words, 128-byte blocks, 80 rounds)
 * SHA-384 is SHA-512 with different IVs and output truncated to 48 bytes.
 * ================================================================ */
static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

typedef struct { uint64_t h[8]; uint8_t buf[128]; size_t buf_len; uint64_t total; } sha512_ctx;
typedef sha512_ctx sha384_ctx; /* SHA-384 uses same internal state */

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define S512_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define S512_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S512_EP0(x) (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define S512_EP1(x) (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define S512_SIG0(x) (ROTR64(x,1)^ROTR64(x,8)^((x)>>7))
#define S512_SIG1(x) (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))

static void sha512_transform(sha512_ctx *ctx, const uint8_t blk[128]) {
    uint64_t w[80],a,b,c,d,e,f,g,h;
    for(int i=0;i<16;i++){w[i]=0;for(int j=0;j<8;j++)w[i]=(w[i]<<8)|blk[8*i+j];}
    for(int i=16;i<80;i++) w[i]=S512_SIG1(w[i-2])+w[i-7]+S512_SIG0(w[i-15])+w[i-16];
    a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];
    e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
    for(int i=0;i<80;i++){
        uint64_t t1=h+S512_EP1(e)+S512_CH(e,f,g)+sha512_k[i]+w[i];
        uint64_t t2=S512_EP0(a)+S512_MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->h[0]+=a;ctx->h[1]+=b;ctx->h[2]+=c;ctx->h[3]+=d;
    ctx->h[4]+=e;ctx->h[5]+=f;ctx->h[6]+=g;ctx->h[7]+=h;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total+=len;
    while(len>0){
        size_t space=128-ctx->buf_len, chunk=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,chunk);
        ctx->buf_len+=chunk; data+=chunk; len-=chunk;
        if(ctx->buf_len==128){sha512_transform(ctx,ctx->buf);ctx->buf_len=0;}
    }
}
#define sha384_update sha512_update

/* SHA-512: full 64-byte output */
static void sha512_init(sha512_ctx *ctx) {
    ctx->h[0]=0x6a09e667f3bcc908ULL;ctx->h[1]=0xbb67ae8584caa73bULL;
    ctx->h[2]=0x3c6ef372fe94f82bULL;ctx->h[3]=0xa54ff53a5f1d36f1ULL;
    ctx->h[4]=0x510e527fade682d1ULL;ctx->h[5]=0x9b05688c2b3e6c1fULL;
    ctx->h[6]=0x1f83d9abfb41bd6bULL;ctx->h[7]=0x5be0cd19137e2179ULL;
    ctx->buf_len=0; ctx->total=0;
}

static void sha512_final(sha512_ctx *ctx, uint8_t out[64]) {
    uint64_t bits=ctx->total*8;
    uint8_t pad=0x80;
    sha512_update(ctx,&pad,1);
    pad=0;
    while(ctx->buf_len!=112) sha512_update(ctx,&pad,1);
    uint8_t lb[16]={0}; put_be64(lb+8, bits);
    sha512_update(ctx,lb,16);
    for(int i=0;i<8;i++)for(int j=0;j<8;j++) out[i*8+j]=(ctx->h[i]>>(56-8*j))&0xFF;
}

static void sha512_hash(const uint8_t *data, size_t len, uint8_t out[64]) {
    sha512_ctx c; sha512_init(&c); sha512_update(&c,data,len); sha512_final(&c,out);
}

/* SHA-384: different IVs, output truncated to 48 bytes */
static void sha384_init(sha384_ctx *ctx) {
    ctx->h[0]=0xcbbb9d5dc1059ed8ULL;ctx->h[1]=0x629a292a367cd507ULL;
    ctx->h[2]=0x9159015a3070dd17ULL;ctx->h[3]=0x152fecd8f70e5939ULL;
    ctx->h[4]=0x67332667ffc00b31ULL;ctx->h[5]=0x8eb44a8768581511ULL;
    ctx->h[6]=0xdb0c2e0d64f98fa7ULL;ctx->h[7]=0x47b5481dbefa4fa4ULL;
    ctx->buf_len=0; ctx->total=0;
}

static void sha384_final(sha384_ctx *ctx, uint8_t out[48]) {
    uint64_t bits=ctx->total*8;
    uint8_t pad=0x80;
    sha384_update(ctx,&pad,1);
    pad=0;
    while(ctx->buf_len!=112) sha384_update(ctx,&pad,1);
    uint8_t lb[16]={0}; put_be64(lb+8, bits);
    sha384_update(ctx,lb,16);
    for(int i=0;i<6;i++)for(int j=0;j<8;j++) out[i*8+j]=(ctx->h[i]>>(56-8*j))&0xFF;
}

static void sha384_hash(const uint8_t *data, size_t len, uint8_t out[48]) {
    sha384_ctx c; sha384_init(&c); sha384_update(&c,data,len); sha384_final(&c,out);
}

/* ================================================================
 * SHAKE256 (Keccak-based XOF, FIPS 202)
 * Used by Ed448 signature verification.
 * ================================================================ */
static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,0x8000000080008000ULL,
    0x000000000000808BULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008AULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
    0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800AULL,0x800000008000000AULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static void keccak_f1600(uint64_t st[25]) {
    for(int round=0;round<24;round++){
        /* theta */
        uint64_t c[5],d[5];
        for(int x=0;x<5;x++) c[x]=st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20];
        for(int x=0;x<5;x++){
            d[x]=c[(x+4)%5]^((c[(x+1)%5]<<1)|(c[(x+1)%5]>>63));
            for(int y=0;y<25;y+=5) st[y+x]^=d[x];
        }
        /* rho + pi */
        uint64_t tmp=st[1];
        static const int pi[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
        static const int rho[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
        for(int i=0;i<24;i++){
            uint64_t r=st[pi[i]];
            st[pi[i]]=(tmp<<rho[i])|(tmp>>(64-rho[i]));
            tmp=r;
        }
        /* chi */
        for(int y=0;y<25;y+=5){
            uint64_t t0=st[y],t1=st[y+1],t2=st[y+2],t3=st[y+3],t4=st[y+4];
            st[y]  =t0^((~t1)&t2);
            st[y+1]=t1^((~t2)&t3);
            st[y+2]=t2^((~t3)&t4);
            st[y+3]=t3^((~t4)&t0);
            st[y+4]=t4^((~t0)&t1);
        }
        /* iota */
        st[0]^=keccak_rc[round];
    }
}

#define SHAKE256_RATE 136 /* 1600 - 2*256 = 1088 bits = 136 bytes */
typedef struct { uint64_t st[25]; uint8_t buf[136]; size_t buf_len; } shake256_ctx;

static void shake256_init(shake256_ctx *ctx) {
    memset(ctx,0,sizeof(*ctx));
}

static void shake256_update(shake256_ctx *ctx, const uint8_t *data, size_t len) {
    while(len>0){
        size_t space=SHAKE256_RATE-ctx->buf_len;
        size_t chunk=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,chunk);
        ctx->buf_len+=chunk; data+=chunk; len-=chunk;
        if(ctx->buf_len==SHAKE256_RATE){
            for(int i=0;i<SHAKE256_RATE/8;i++){
                uint64_t w=0;
                for(int j=0;j<8;j++) w|=(uint64_t)ctx->buf[8*i+j]<<(8*j);
                ctx->st[i]^=w;
            }
            keccak_f1600(ctx->st);
            ctx->buf_len=0;
        }
    }
}

static void shake256_final(shake256_ctx *ctx, uint8_t *out, size_t out_len) {
    /* Pad: SHAKE domain separation 0x1F, then pad10*1 */
    memset(ctx->buf+ctx->buf_len,0,SHAKE256_RATE-ctx->buf_len);
    ctx->buf[ctx->buf_len]|=0x1F;
    ctx->buf[SHAKE256_RATE-1]|=0x80;
    for(int i=0;i<SHAKE256_RATE/8;i++){
        uint64_t w=0;
        for(int j=0;j<8;j++) w|=(uint64_t)ctx->buf[8*i+j]<<(8*j);
        ctx->st[i]^=w;
    }
    keccak_f1600(ctx->st);
    /* Squeeze */
    size_t squeezed=0;
    while(squeezed<out_len){
        size_t avail=SHAKE256_RATE;
        if(avail>out_len-squeezed) avail=out_len-squeezed;
        for(size_t i=0;i<avail;i++)
            out[squeezed+i]=(uint8_t)(ctx->st[i/8]>>(8*(i%8)));
        squeezed+=avail;
        if(squeezed<out_len) keccak_f1600(ctx->st);
    }
}

/* Hash algorithm abstraction for unified HMAC/HKDF/PRF */
typedef void (*hash_fn_t)(const uint8_t*, size_t, uint8_t*);
typedef struct {
    void (*init)(void*);
    void (*update)(void*, const uint8_t*, size_t);
    void (*final_fn)(void*, uint8_t*);
    hash_fn_t hash;
    size_t digest_len, block_size;
} hash_alg;

static void sha1_init_v(void *ctx){sha1_init((sha1_ctx*)ctx);}
static void sha1_update_v(void *ctx,const uint8_t *d,size_t l){sha1_update((sha1_ctx*)ctx,d,l);}
static void sha1_final_v(void *ctx,uint8_t *o){sha1_final((sha1_ctx*)ctx,o);}
static void sha256_init_v(void *ctx){sha256_init((sha256_ctx*)ctx);}
static void sha256_update_v(void *ctx,const uint8_t *d,size_t l){
    sha256_update((sha256_ctx*)ctx,d,l);
}
static void sha256_final_v(void *ctx,uint8_t *o){sha256_final((sha256_ctx*)ctx,o);}
static void sha384_init_v(void *ctx){sha384_init((sha384_ctx*)ctx);}
static void sha384_update_v(void *ctx,const uint8_t *d,size_t l){
    sha384_update((sha384_ctx*)ctx,d,l);
}
static void sha384_final_v(void *ctx,uint8_t *o){sha384_final((sha384_ctx*)ctx,o);}

static const hash_alg SHA1_ALG={
    sha1_init_v,sha1_update_v,sha1_final_v,sha1_hash,SHA1_DIGEST_LEN,64};
static const hash_alg SHA256_ALG={
    sha256_init_v,sha256_update_v,sha256_final_v,sha256_hash,SHA256_DIGEST_LEN,64};
static const hash_alg SHA384_ALG={
    sha384_init_v,sha384_update_v,sha384_final_v,sha384_hash,SHA384_DIGEST_LEN,128};

static void hmac(const hash_alg *alg, const uint8_t *key, size_t klen,
                  const uint8_t *msg, size_t mlen, uint8_t *out) {
    uint8_t k[128]={0};
    if(klen>alg->block_size) alg->hash(key,klen,k); else memcpy(k,key,klen);
    uint8_t ip[128], op[128];
    for(size_t i=0;i<alg->block_size;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}
    union{sha256_ctx s2;sha384_ctx s3;}u;
    alg->init(&u); alg->update(&u,ip,alg->block_size); alg->update(&u,msg,mlen);
    uint8_t inner[48]; alg->final_fn(&u,inner);
    alg->init(&u); alg->update(&u,op,alg->block_size); alg->update(&u,inner,alg->digest_len);
    alg->final_fn(&u,out);
}

static void hkdf_extract_u(const hash_alg *alg, const uint8_t *salt, size_t slen,
                             const uint8_t *ikm, size_t ilen, uint8_t *out) {
    if(slen==0){const uint8_t z[48]={0}; hmac(alg,z,alg->digest_len,ikm,ilen,out);}
    else hmac(alg,salt,slen,ikm,ilen,out);
}

static void hkdf_expand_u(const hash_alg *alg, const uint8_t *prk,
                            const uint8_t *info, size_t ilen, uint8_t *out, size_t olen) {
    uint8_t t[48]; size_t tl=0, done=0; uint8_t ctr=1;
    while(done<olen){
        union{sha256_ctx s2;sha384_ctx s3;}u;
        uint8_t ik[128]={0},ok[128]={0};
        memcpy(ik,prk,alg->digest_len);
        for(size_t i=0;i<alg->block_size;i++){
            ik[i]^=0x36; ok[i]=((i<alg->digest_len)?prk[i]:0)^0x5c;
        }
        alg->init(&u); alg->update(&u,ik,alg->block_size);
        if(tl>0) alg->update(&u,t,tl);
        alg->update(&u,info,ilen);
        alg->update(&u,&ctr,1);
        uint8_t inner[48]; alg->final_fn(&u,inner);
        union{sha256_ctx s2;sha384_ctx s3;}u2;
        alg->init(&u2); alg->update(&u2,ok,alg->block_size); alg->update(&u2,inner,alg->digest_len);
        alg->final_fn(&u2,t); tl=alg->digest_len;
        size_t use=olen-done; if(use>alg->digest_len) use=alg->digest_len;
        memcpy(out+done,t,use); done+=use; ctr++;
    }
}

static void hkdf_expand_label_u(const hash_alg *alg, const uint8_t *secret, const char *label,
                                  const uint8_t *ctx, size_t clen, uint8_t *out, size_t olen) {
    uint8_t info[256]; size_t p=0;
    size_t label_len=strlen(label);
    if(2+1+6+label_len+1+clen>sizeof(info)) die("hkdf_expand_label: info overflow");
    info[p++]=(olen>>8)&0xFF; info[p++]=olen&0xFF;
    size_t ll=6+label_len;
    info[p++]=ll&0xFF;
    memcpy(info+p,"tls13 ",6); p+=6;
    memcpy(info+p,label,label_len); p+=label_len;
    info[p++]=clen&0xFF;
    if(clen>0){memcpy(info+p,ctx,clen);p+=clen;}
    hkdf_expand_u(alg,secret,info,p,out,olen);
}

static void tls12_prf_u(const hash_alg *alg, const uint8_t *secret, size_t secret_len,
                          const char *label, const uint8_t *seed, size_t seed_len,
                          uint8_t *out, size_t out_len) {
    uint8_t lseed[256];
    size_t label_len=strlen(label);
    size_t ls_len=label_len+seed_len;
    if(ls_len>sizeof(lseed)) die("tls12_prf: label+seed overflow");
    memcpy(lseed,label,label_len);
    memcpy(lseed+label_len,seed,seed_len);
    uint8_t a[48];
    hmac(alg,secret,secret_len,lseed,ls_len,a);
    size_t done=0;
    while(done<out_len){
        uint8_t buf[48+256];
        memcpy(buf,a,alg->digest_len);
        memcpy(buf+alg->digest_len,lseed,ls_len);
        uint8_t hmac_out[48];
        hmac(alg,secret,secret_len,buf,alg->digest_len+ls_len,hmac_out);
        size_t use=out_len-done; if(use>alg->digest_len) use=alg->digest_len;
        memcpy(out+done,hmac_out,use); done+=use;
        hmac(alg,secret,secret_len,a,alg->digest_len,a);
    }
}

/* ================================================================
 * AES (128/256)
 * ================================================================ */
static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t aes_rcon[10]={1,2,4,8,16,32,64,128,27,54};

/* Constant-time S-box lookup: scans entire table to avoid cache timing leaks */
static uint8_t ct_sbox(uint8_t idx) {
    uint8_t result=0;
    for(unsigned i=0;i<256;i++){
        /* 0xFF when i==idx, 0x00 otherwise, no branches */
        uint8_t mask=(uint8_t)(((uint32_t)((uint8_t)i^idx)-1)>>8);
        result|=aes_sbox[i]&mask;
    }
    return result;
}

static void aes128_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk,key,16);
    for(size_t i=0;i<10;i++) {
        const uint8_t *p=rk+16*i; uint8_t *n=rk+16*(i+1);
        uint8_t t[4]={ct_sbox(p[13]),ct_sbox(p[14]),ct_sbox(p[15]),ct_sbox(p[12])};
        t[0]^=aes_rcon[i];
        for(int j=0;j<4;j++){
            n[j]=p[j]^t[j]; n[4+j]=p[4+j]^n[j];
            n[8+j]=p[8+j]^n[4+j]; n[12+j]=p[12+j]^n[8+j];
        }
    }
}

static void aes256_expand(const uint8_t key[32], uint8_t rk[240]) {
    memcpy(rk,key,32);
    for(size_t i=0;i<7;i++){
        const uint8_t *prev=rk+32*i;
        uint8_t *next=rk+32*i+32;
        /* First 16 bytes: RotWord+SubWord+Rcon on last 4 bytes of prev 32 */
        uint8_t t[4]={ct_sbox(prev[29]),ct_sbox(prev[30]),ct_sbox(prev[31]),ct_sbox(prev[28])};
        t[0]^=aes_rcon[i];
        for(int j=0;j<4;j++) next[j]=prev[j]^t[j];
        for(int j=4;j<16;j++) next[j]=prev[j]^next[j-4];
        if(i==6) break; /* only need 15 round keys = 240 bytes, stop after 7th block of 16 */
        /* Second 16 bytes: SubWord on 4th word of current 16 */
        const uint8_t s[4]={ct_sbox(next[12]),ct_sbox(next[13]),
                            ct_sbox(next[14]),ct_sbox(next[15])};
        for(int j=0;j<4;j++) next[16+j]=prev[16+j]^s[j];
        for(int j=20;j<32;j++) next[j]=prev[j]^next[j-4];
    }
}

static uint8_t xt(uint8_t x){return (uint8_t)((x<<1)^((x>>7)*0x1b));}

static void aes_encrypt(const uint8_t *rk, int nr, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16);
    for(int i=0;i<16;i++) s[i]^=rk[i];
    for(int r=1;r<=nr;r++) {
        for(int i=0;i<16;i++) s[i]=ct_sbox(s[i]);
        uint8_t t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if(r<nr) {
            for(size_t c=0;c<4;c++){
                uint8_t *col=s+4*c, a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                col[0]=xt(a0)^xt(a1)^a1^a2^a3; col[1]=a0^xt(a1)^xt(a2)^a2^a3;
                col[2]=a0^a1^xt(a2)^xt(a3)^a3; col[3]=xt(a0)^a0^a1^a2^xt(a3);
            }
        }
        for(int i=0;i<16;i++) s[i]^=rk[16*r+i];
    }
    memcpy(out,s,16);
}

/* ================================================================
 * AES-GCM (128/256)
 * ================================================================ */
static void gf128_mul(uint8_t r[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16],z[16]; memcpy(v,y,16); memset(z,0,16);
    for(int i=0;i<128;i++){
        uint8_t mask = -((x[i/8]>>(7-(i%8)))&1); /* 0x00 or 0xFF */
        for(int j=0;j<16;j++) z[j]^=v[j]&mask;
        uint8_t lsb_mask=-(v[15]&1); /* 0x00 or 0xFF */
        for(int j=15;j>0;j--) v[j]=(uint8_t)((v[j]>>1)|(v[j-1]<<7));
        v[0]>>=1; v[0]^=0xe1&lsb_mask;
    }
    memcpy(r,z,16);
}

static void ghash(const uint8_t h[16], const uint8_t *aad, size_t al,
                   const uint8_t *ct, size_t cl, uint8_t out[16]) {
    uint8_t x[16]={0}, blk[16];
    size_t i;
    for(i=0;i+16<=al;i+=16){for(size_t j=0;j<16;j++)x[j]^=aad[i+j];gf128_mul(x,x,h);}
    if(i<al){
        memset(blk,0,16); memcpy(blk,aad+i,al-i);
        for(int j=0;j<16;j++){x[j]^=blk[j];} gf128_mul(x,x,h);
    }
    for(i=0;i+16<=cl;i+=16){for(size_t j=0;j<16;j++)x[j]^=ct[i+j];gf128_mul(x,x,h);}
    if(i<cl){
        memset(blk,0,16); memcpy(blk,ct+i,cl-i);
        for(int j=0;j<16;j++){x[j]^=blk[j];} gf128_mul(x,x,h);
    }
    memset(blk,0,16);
    uint64_t ab=al*8, cb=cl*8;
    for(int j=0;j<8;j++){blk[7-j]=(ab>>(8*j))&0xFF;blk[15-j]=(cb>>(8*j))&0xFF;}
    for(int j=0;j<16;j++){x[j]^=blk[j];} gf128_mul(x,x,h);
    memcpy(out,x,16);
}

static void inc32(uint8_t ctr[16]){for(int i=15;i>=12;i--)if(++ctr[i])break;}

static void aes_gcm_encrypt_impl(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                                   const uint8_t *aad, size_t al,
                                   const uint8_t *pt, size_t pl,
                                   uint8_t *ct_out, uint8_t tag[16]) {
    uint8_t rk[240]; int nr;
    if(key_len==AES256_KEY_LEN){aes256_expand(key,rk);nr=14;}
    else{aes128_expand(key,rk);nr=10;}
    uint8_t hh[16]={0}; aes_encrypt(rk,nr,hh,hh);
    uint8_t ctr[16]; memcpy(ctr,nonce,12); ctr[12]=ctr[13]=ctr[14]=0; ctr[15]=2;
    for(size_t i=0;i<pl;i+=16){
        uint8_t ks[16]; aes_encrypt(rk,nr,ctr,ks); inc32(ctr);
        size_t n=pl-i; if(n>16)n=16;
        for(size_t j=0;j<n;j++) ct_out[i+j]=pt[i+j]^ks[j];
    }
    ghash(hh,aad,al,ct_out,pl,tag);
    uint8_t j0[16]; memcpy(j0,nonce,12); j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t ej0[16]; aes_encrypt(rk,nr,j0,ej0);
    for(int i=0;i<16;i++) tag[i]^=ej0[i];
}

static int aes_gcm_decrypt_impl(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                                  const uint8_t *aad, size_t al,
                                  const uint8_t *ct, size_t cl,
                                  uint8_t *pt, const uint8_t exp_tag[16]) {
    uint8_t rk[240]; int nr;
    if(key_len==AES256_KEY_LEN){aes256_expand(key,rk);nr=14;}
    else{aes128_expand(key,rk);nr=10;}
    uint8_t hh[16]={0}; aes_encrypt(rk,nr,hh,hh);
    uint8_t tag[16];
    ghash(hh,aad,al,ct,cl,tag);
    uint8_t j0[16]; memcpy(j0,nonce,12); j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t ej0[16]; aes_encrypt(rk,nr,j0,ej0);
    for(int i=0;i<16;i++) tag[i]^=ej0[i];
    if(!ct_memeq(tag,exp_tag,16)) return -1;
    uint8_t ctr[16]; memcpy(ctr,nonce,12); ctr[12]=ctr[13]=ctr[14]=0; ctr[15]=2;
    for(size_t i=0;i<cl;i+=16){
        uint8_t ks[16]; aes_encrypt(rk,nr,ctr,ks); inc32(ctr);
        size_t n=cl-i; if(n>16)n=16;
        for(size_t j=0;j<n;j++) pt[i+j]=ct[i+j]^ks[j];
    }
    return 0;
}

/* ================================================================
 * AES Inverse Cipher (for CBC decrypt)
 * ================================================================ */
static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t ct_inv_sbox(uint8_t idx) {
    uint8_t result=0;
    for(unsigned i=0;i<256;i++){
        uint8_t mask=(uint8_t)(((uint32_t)((uint8_t)i^idx)-1)>>8);
        result|=aes_inv_sbox[i]&mask;
    }
    return result;
}

static uint8_t xtm(uint8_t x, uint8_t m) {
    /* Multiply x by m in GF(2^8) — used for InvMixColumns */
    uint8_t r=0;
    for(int i=0;i<8;i++){
        if(m&1) r^=x;
        uint8_t hi=x&0x80;
        x=(uint8_t)((x<<1)^(hi?0x1b:0));
        m>>=1;
    }
    return r;
}

static void aes_decrypt(const uint8_t *rk, int nr, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16);
    for(int i=0;i<16;i++) s[i]^=rk[16*nr+i];
    for(int r=nr-1;r>=0;r--){
        /* InvShiftRows */
        uint8_t t;
        t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
        t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
        t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t;
        /* InvSubBytes */
        for(int i=0;i<16;i++) s[i]=ct_inv_sbox(s[i]);
        /* AddRoundKey */
        for(int i=0;i<16;i++) s[i]^=rk[16*r+i];
        /* InvMixColumns (skip for round 0) */
        if(r>0){
            for(size_t c=0;c<4;c++){
                uint8_t *col=s+4*c, a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                col[0]=xtm(a0,0x0e)^xtm(a1,0x0b)^xtm(a2,0x0d)^xtm(a3,0x09);
                col[1]=xtm(a0,0x09)^xtm(a1,0x0e)^xtm(a2,0x0b)^xtm(a3,0x0d);
                col[2]=xtm(a0,0x0d)^xtm(a1,0x09)^xtm(a2,0x0e)^xtm(a3,0x0b);
                col[3]=xtm(a0,0x0b)^xtm(a1,0x0d)^xtm(a2,0x09)^xtm(a3,0x0e);
            }
        }
    }
    memcpy(out,s,16);
}

/* ================================================================
 * AES-CBC Encrypt / Decrypt
 * ================================================================ */
static void aes_cbc_encrypt(const uint8_t *key, size_t key_len,
                              const uint8_t iv[16], const uint8_t *pt, size_t len,
                              uint8_t *ct) {
    uint8_t rk[240]; int nr;
    if(key_len==AES256_KEY_LEN){aes256_expand(key,rk);nr=14;}
    else{aes128_expand(key,rk);nr=10;}
    uint8_t prev[16]; memcpy(prev,iv,16);
    for(size_t i=0;i<len;i+=16){
        uint8_t blk[16];
        for(size_t j=0;j<16;j++) blk[j]=pt[i+j]^prev[j];
        aes_encrypt(rk,nr,blk,ct+i);
        memcpy(prev,ct+i,16);
    }
}

static void aes_cbc_decrypt(const uint8_t *key, size_t key_len,
                              const uint8_t iv[16], const uint8_t *ct, size_t len,
                              uint8_t *pt) {
    uint8_t rk[240]; int nr;
    if(key_len==AES256_KEY_LEN){aes256_expand(key,rk);nr=14;}
    else{aes128_expand(key,rk);nr=10;}
    uint8_t prev[16]; memcpy(prev,iv,16);
    for(size_t i=0;i<len;i+=16){
        uint8_t blk[16];
        aes_decrypt(rk,nr,ct+i,blk);
        for(size_t j=0;j<16;j++) pt[i+j]=blk[j]^prev[j];
        memcpy(prev,ct+i,16);
    }
}

/* ================================================================
 * ChaCha20 Stream Cipher (RFC 8439)
 * ================================================================ */
static uint32_t rotl32(uint32_t x, int n){return (x<<n)|(x>>(32-n));}

#define QR(a,b,c,d) \
    (a)+=(b);(d)^=(a);(d)=rotl32((d),16); \
    (c)+=(d);(b)^=(c);(b)=rotl32((b),12); \
    (a)+=(b);(d)^=(a);(d)=rotl32((d),8);  \
    (c)+=(d);(b)^=(c);(b)=rotl32((b),7);

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
    uint32_t counter, uint8_t out[64]) {
    uint32_t s[16];
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for(size_t i=0;i<8;i++)
        s[4+i]=(uint32_t)key[4*i]|((uint32_t)key[4*i+1]<<8)
              |((uint32_t)key[4*i+2]<<16)|((uint32_t)key[4*i+3]<<24);
    s[12]=counter;
    for(size_t i=0;i<3;i++)
        s[13+i]=(uint32_t)nonce[4*i]|((uint32_t)nonce[4*i+1]<<8)
               |((uint32_t)nonce[4*i+2]<<16)|((uint32_t)nonce[4*i+3]<<24);
    uint32_t w[16]; memcpy(w,s,64);
    for(int i=0;i<10;i++){
        QR(w[0],w[4],w[8],w[12])  QR(w[1],w[5],w[9],w[13])
        QR(w[2],w[6],w[10],w[14]) QR(w[3],w[7],w[11],w[15])
        QR(w[0],w[5],w[10],w[15]) QR(w[1],w[6],w[11],w[12])
        QR(w[2],w[7],w[8],w[13])  QR(w[3],w[4],w[9],w[14])
    }
    for(int i=0;i<16;i++) w[i]+=s[i];
    for(size_t i=0;i<16;i++){
        out[4*i]=(uint8_t)w[i]; out[4*i+1]=(uint8_t)(w[i]>>8);
        out[4*i+2]=(uint8_t)(w[i]>>16); out[4*i+3]=(uint8_t)(w[i]>>24);
    }
}

static void chacha20_encrypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                              const uint8_t *in, size_t len, uint8_t *out) {
    for(size_t off=0;off<len;off+=64){
        uint8_t ks[64];
        chacha20_block(key,nonce,counter++,ks);
        size_t n=len-off; if(n>64) n=64;
        for(size_t j=0;j<n;j++) out[off+j]=in[off+j]^ks[j];
    }
}

/* ================================================================
 * Poly1305 MAC (RFC 8439)
 * Prime: p = 2^130 - 5.  Accumulator in 3 x 64-bit words (44/44/42-bit limbs).
 * ================================================================ */
static void poly1305_mac(const uint8_t key[32], const uint8_t *msg,
    size_t msg_len, uint8_t tag[16]) {
    /* Clamp r */
    uint64_t r0=0,r1=0;
    for(int i=0;i<8;i++) r0|=(uint64_t)key[i]<<(8*i);
    for(int i=0;i<8;i++) r1|=(uint64_t)key[8+i]<<(8*i);
    r0&=0x0FFFFFFC0FFFFFFF; r1&=0x0FFFFFFC0FFFFFFC;
    /* r as 3 limbs of 44/44/42 bits for schoolbook multiply */
    uint64_t rr0 = r0 & 0xFFFFFFFFFFF;
    uint64_t rr1 = ((r0>>44)|(r1<<20)) & 0xFFFFFFFFFFF;
    uint64_t rr2 = (r1>>24) & 0x3FFFFFFFFFF;

    uint64_t h0=0,h1=0,h2=0;
    /* Precompute 20*r limbs for modular reduction (2^130 ≡ 5 mod p, ×4 for limb alignment) */
    uint64_t s1=20*rr1, s2=20*rr2;

    for(size_t i=0;i<msg_len;i+=16){
        /* Read up to 16 bytes of message block */
        uint8_t blk[17]={0};
        size_t n=msg_len-i; if(n>16) n=16;
        memcpy(blk,msg+i,n);
        blk[n]=1; /* pad byte */
        /* Parse block as little-endian 130-bit number */
        uint64_t t0=0,t1=0,t2=0;
        for(int j=0;j<8&&j<(int)(n+1);j++) t0|=(uint64_t)blk[j]<<(8*j);
        for(int j=0;j<8&&(j+8)<(int)(n+1);j++) t1|=(uint64_t)blk[8+j]<<(8*j);
        if(n>=16) t2=(uint64_t)blk[16];
        /* Split into 44-bit limbs */
        uint64_t b0 = t0 & 0xFFFFFFFFFFF;
        uint64_t b1 = ((t0>>44)|(t1<<20)) & 0xFFFFFFFFFFF;
        uint64_t b2 = ((t1>>24)|(t2<<40)) & 0x3FFFFFFFFFF;

        h0+=b0; h1+=b1; h2+=b2;

        /* h = h * r mod p using 44-bit limbs */
        uint64_t d0_hi, d0_lo, d1_hi, d1_lo, d2_hi, d2_lo;
        /* d0 = h0*rr0 + h1*s2 + h2*s1 */
        mul64(h0, rr0, &d0_hi, &d0_lo);
        { uint64_t ph, pl;
          mul64(h1, s2, &ph, &pl);
          d0_hi += ph + addcarry64(d0_lo, pl, &d0_lo);
          mul64(h2, s1, &ph, &pl);
          d0_hi += ph + addcarry64(d0_lo, pl, &d0_lo);
        }
        /* d1 = h0*rr1 + h1*rr0 + h2*s2 */
        mul64(h0, rr1, &d1_hi, &d1_lo);
        { uint64_t ph, pl;
          mul64(h1, rr0, &ph, &pl);
          d1_hi += ph + addcarry64(d1_lo, pl, &d1_lo);
          mul64(h2, s2, &ph, &pl);
          d1_hi += ph + addcarry64(d1_lo, pl, &d1_lo);
        }
        /* d2 = h0*rr2 + h1*rr1 + h2*rr0 */
        mul64(h0, rr2, &d2_hi, &d2_lo);
        { uint64_t ph, pl;
          mul64(h1, rr1, &ph, &pl);
          d2_hi += ph + addcarry64(d2_lo, pl, &d2_lo);
          mul64(h2, rr0, &ph, &pl);
          d2_hi += ph + addcarry64(d2_lo, pl, &d2_lo);
        }

        /* Partial reduction / carry propagation */
        uint64_t c0=(d0_lo >> 44) | (d0_hi << 20); h0=d0_lo & 0xFFFFFFFFFFF;
        d1_hi += addcarry64(d1_lo, c0, &d1_lo);
        uint64_t c1=(d1_lo >> 44) | (d1_hi << 20); h1=d1_lo & 0xFFFFFFFFFFF;
        d2_hi += addcarry64(d2_lo, c1, &d2_lo);
        uint64_t c2=(d2_lo >> 42) | (d2_hi << 22); h2=d2_lo & 0x3FFFFFFFFFF;
        h0+=c2*5;
        uint64_t c3=h0>>44; h0&=0xFFFFFFFFFFF;
        h1+=c3;
    }
    /* Final reduction */
    uint64_t c4=h1>>44; h1&=0xFFFFFFFFFFF;
    h2+=c4;
    uint64_t c5=h2>>42; h2&=0x3FFFFFFFFFF;
    h0+=c5*5;
    uint64_t c6=h0>>44; h0&=0xFFFFFFFFFFF;
    h1+=c6;

    /* Compute h - p; keep if h >= p */
    uint64_t g0=h0+5; uint64_t cg=g0>>44; g0&=0xFFFFFFFFFFF;
    uint64_t g1=h1+cg; cg=g1>>44; g1&=0xFFFFFFFFFFF;
    uint64_t g2=h2+cg-(1ULL<<42);
    uint64_t mask2=-(g2>>63); /* if g2 < 0 (underflow), mask=0xFFF..., keep h; else keep g */
    h0=(h0&mask2)|(g0&~mask2);
    h1=(h1&mask2)|(g1&~mask2);
    h2=(h2&mask2)|(g2&~mask2);

    /* Convert back to 128-bit number */
    uint64_t lo=h0|(h1<<44);
    uint64_t hi=(h1>>20)|(h2<<24);

    /* Add s (second half of key) */
    uint64_t s_lo=0,s_hi=0;
    for(int i=0;i<8;i++) s_lo|=(uint64_t)key[16+i]<<(8*i);
    for(int i=0;i<8;i++) s_hi|=(uint64_t)key[24+i]<<(8*i);
    uint64_t carry_s=addcarry64(lo, s_lo, &lo);
    hi=hi+s_hi+carry_s;

    /* Output little-endian */
    for(int i=0;i<8;i++){tag[i]=(lo>>(8*i))&0xFF; tag[8+i]=(hi>>(8*i))&0xFF;}
}

/* ================================================================
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 * ================================================================ */
static void chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                        const uint8_t *aad, size_t al,
                                        const uint8_t *pt, size_t pl,
                                        uint8_t *ct, uint8_t tag[16]) {
    /* 1. Generate Poly1305 one-time key */
    uint8_t poly_key[64];
    chacha20_block(key,nonce,0,poly_key);
    /* 2. Encrypt plaintext with counter starting at 1 */
    chacha20_encrypt(key,nonce,1,pt,pl,ct);
    /* 3. Construct MAC input and compute tag */
    size_t apad=(16-(al%16))%16;
    size_t cpad=(16-(pl%16))%16;
    size_t mac_len=al+apad+pl+cpad+16;
    uint8_t *mac_data=malloc(mac_len);
    if(!mac_data) die("malloc failed");
    size_t mp=0;
    memcpy(mac_data+mp,aad,al); mp+=al;
    memset(mac_data+mp,0,apad); mp+=apad;
    memcpy(mac_data+mp,ct,pl); mp+=pl;
    memset(mac_data+mp,0,cpad); mp+=cpad;
    for(int i=0;i<8;i++) mac_data[mp++]=(al>>(8*i))&0xFF;
    for(int i=0;i<8;i++) mac_data[mp++]=(pl>>(8*i))&0xFF;
    poly1305_mac(poly_key,mac_data,mac_len,tag);
    free(mac_data);
    secure_zero(poly_key,sizeof(poly_key));
}

static int chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                       const uint8_t *aad, size_t al,
                                       const uint8_t *ct, size_t cl,
                                       uint8_t *pt, const uint8_t exp_tag[16]) {
    /* 1. Generate Poly1305 one-time key */
    uint8_t poly_key[64];
    chacha20_block(key,nonce,0,poly_key);
    /* 2. Verify tag first */
    size_t apad=(16-(al%16))%16;
    size_t cpad=(16-(cl%16))%16;
    size_t mac_len=al+apad+cl+cpad+16;
    uint8_t *mac_data=malloc(mac_len);
    if(!mac_data) die("malloc failed");
    size_t mp=0;
    memcpy(mac_data+mp,aad,al); mp+=al;
    memset(mac_data+mp,0,apad); mp+=apad;
    memcpy(mac_data+mp,ct,cl); mp+=cl;
    memset(mac_data+mp,0,cpad); mp+=cpad;
    for(int i=0;i<8;i++) mac_data[mp++]=(al>>(8*i))&0xFF;
    for(int i=0;i<8;i++) mac_data[mp++]=(cl>>(8*i))&0xFF;
    uint8_t tag[16];
    poly1305_mac(poly_key,mac_data,mac_len,tag);
    free(mac_data);
    secure_zero(poly_key,sizeof(poly_key));
    if(!ct_memeq(tag,exp_tag,16)) return -1;
    /* 3. Decrypt */
    chacha20_encrypt(key,nonce,1,ct,cl,pt);
    return 0;
}

/* ================================================================
 * Big-Number Arithmetic (for RSA and ECDSA mod-n operations)
 * ================================================================ */
typedef struct { limb_t v[BN_MAX_LIMBS]; int len; } bignum;

static void bn_zero(bignum *r) { memset(r,0,sizeof(*r)); }

static int bn_is_zero(const bignum *a) {
    for(int i=0;i<a->len;i++) if(a->v[i]) return 0;
    return 1;
}

static void bn_from_bytes(bignum *r, const uint8_t *buf, size_t blen) {
    bn_zero(r);
    r->len=(int)((blen+LIMB_BYTES-1)/LIMB_BYTES);
    if(r->len>BN_MAX_LIMBS) r->len=BN_MAX_LIMBS;
    for(size_t i=0;i<blen&&(int)(i/LIMB_BYTES)<BN_MAX_LIMBS;i++)
        r->v[i/LIMB_BYTES]|=(limb_t)buf[blen-1-i]<<(8*(i%LIMB_BYTES));
}

static void bn_to_bytes(const bignum *a, uint8_t *buf, size_t blen) {
    memset(buf,0,blen);
    for(size_t i=0;i<blen&&(int)(i/LIMB_BYTES)<BN_MAX_LIMBS;i++)
        buf[blen-1-i]=(uint8_t)((a->v[i/LIMB_BYTES]>>(8*(i%LIMB_BYTES)))&0xFF);
}

static int bn_cmp(const bignum *a, const bignum *b) {
    int ml=a->len>b->len?a->len:b->len;
    for(int i=ml-1;i>=0;i--){
        limb_t av=i<a->len?a->v[i]:0, bv=i<b->len?b->v[i]:0;
        if(av>bv) return 1;
        if(av<bv) return -1;
    }
    return 0;
}

static void bn_sub(bignum *r, const bignum *a, const bignum *b) {
    int ml=a->len>b->len?a->len:b->len;
    limb_t borrow=0;
    for(int i=0;i<ml;i++){
        limb_t av=i<a->len?a->v[i]:0;
        limb_t bv=i<b->len?b->v[i]:0;
        borrow=sbb_limb(av, bv, borrow, &r->v[i]);
    }
    r->len=ml;
    while(r->len>0&&r->v[r->len-1]==0) r->len--;
}

static void bn_mul(bignum *r, const bignum *a, const bignum *b) {
    bignum t; bn_zero(&t);
    t.len=a->len+b->len;
    if(t.len>BN_MAX_LIMBS) t.len=BN_MAX_LIMBS;
    for(int i=0;i<a->len;i++){
        limb_t carry=0;
        for(int j=0;j<b->len&&i+j<BN_MAX_LIMBS;j++){
            mac_limb(a->v[i], b->v[j], t.v[i+j], carry, &carry, &t.v[i+j]);
        }
        if(i+b->len<BN_MAX_LIMBS) t.v[i+b->len]=carry;
    }
    while(t.len>0&&t.v[t.len-1]==0) t.len--;
    *r=t;
}

static int bn_bits(const bignum *a) {
    if(a->len==0) return 0;
    int bits=(a->len-1)*LIMB_BITS;
    limb_t top=a->v[a->len-1];
    while(top){bits++;top>>=1;}
    return bits;
}

static void bn_shl1(bignum *a) {
    limb_t carry=0;
    for(int i=0;i<a->len;i++){
        limb_t nc=a->v[i]>>(LIMB_BITS-1);
        a->v[i]=(a->v[i]<<1)|carry;
        carry=nc;
    }
    if(carry&&a->len<BN_MAX_LIMBS) a->v[a->len++]=carry;
}

static void bn_mod(bignum *r, const bignum *a, const bignum *m) {
    bignum rem; bn_zero(&rem);
    int abits=bn_bits(a);
    for(int i=abits-1;i>=0;i--){
        bn_shl1(&rem);
        if((a->v[i/LIMB_BITS]>>(i%LIMB_BITS))&1){rem.v[0]|=1;if(rem.len==0)rem.len=1;}
        if(bn_cmp(&rem,m)>=0) bn_sub(&rem,&rem,m);
    }
    *r=rem;
}

static void bn_modmul(bignum *r, const bignum *a, const bignum *b, const bignum *m) {
    bignum t; bn_mul(&t,a,b); bn_mod(r,&t,m);
}

/* Constant-time conditional copy: dst = src if bit==1, unchanged if bit==0 */
static void bn_cmov(bignum *dst, const bignum *src, int bit) {
    limb_t mask = -(limb_t)(bit&1); /* 0 or 0xFFFF... */
    int max_len = dst->len > src->len ? dst->len : src->len;
    for(int i=0;i<max_len;i++)
        dst->v[i] = (dst->v[i] & ~mask) | (src->v[i] & mask);
    dst->len = (dst->len & (int)~mask) | (src->len & (int)mask);
}
typedef struct {
    limb_t m_inv;     /* -m^(-1) mod 2^LIMB_BITS */
    int n;            /* number of limbs in m */
    bignum rr;        /* R^2 mod m, for converting to Montgomery form */
} bn_mont_ctx;

static void bn_mont_init(bn_mont_ctx *ctx, const bignum *m) {
    ctx->n = m->len;
    /* Compute m_inv = -m[0]^(-1) mod 2^LIMB_BITS via Newton's method */
    limb_t m0 = m->v[0];
    limb_t x = 1;
#if USE_64BIT_LIMBS
    for(int i = 0; i < 6; i++) /* 1->2->4->8->16->32->64 bits */
#else
    for(int i = 0; i < 5; i++) /* 1->2->4->8->16->32 bits */
#endif
        x = x * (2 - m0 * x);
    ctx->m_inv = -x; /* negate: m_inv * m[0] ≡ -1 (mod 2^LIMB_BITS) */
    /* Compute R mod m where R = 2^(n*LIMB_BITS) */
    bignum R; bn_zero(&R);
    R.v[ctx->n] = 1; R.len = ctx->n + 1;
    bignum R_mod_m; bn_mod(&R_mod_m, &R, m);
    /* Compute R^2 mod m */
    bn_modmul(&ctx->rr, &R_mod_m, &R_mod_m, m);
}

static void bn_mont_mul(bignum *r, const bignum *a, const bignum *b,
                        const bignum *m, const bn_mont_ctx *ctx) {
    int n = ctx->n;
    limb_t t[BN_MAX_LIMBS + 2];
    memset(t, 0, ((size_t)n + 2) * sizeof(limb_t));
    for(int i = 0; i < n; i++) {
        limb_t ai = (i < a->len) ? a->v[i] : 0;
        /* t += a[i] * b */
        limb_t carry = 0;
        for(int j = 0; j < n; j++) {
            mac_limb(ai, (j < b->len) ? b->v[j] : 0, t[j], carry, &carry, &t[j]);
        }
        limb_t sc = adc_limb(t[n], carry, 0, &t[n]);
        t[n + 1] = sc;
        /* u = t[0] * m_inv mod 2^LIMB_BITS */
        limb_t u = t[0] * ctx->m_inv;
        /* t += u * m, cancels bottom limb */
        carry = 0;
        for(int j = 0; j < n; j++) {
            mac_limb(u, m->v[j], t[j], carry, &carry, &t[j]);
        }
        sc = adc_limb(t[n], carry, 0, &t[n]);
        t[n + 1] += sc;
        /* shift right LIMB_BITS (drop zeroed bottom limb) */
        for(int j = 0; j <= n; j++) t[j] = t[j + 1];
        t[n + 1] = 0;
    }
    bignum result; bn_zero(&result);
    for(int i = 0; i <= n; i++) result.v[i] = t[i];
    result.len = n + 1;
    while(result.len > 0 && result.v[result.len - 1] == 0) result.len--;
    if(bn_cmp(&result, m) >= 0) bn_sub(r, &result, m);
    else *r = result;
}

static void bn_modexp(bignum *r, const bignum *base, const bignum *exp, const bignum *m) {
    bn_mont_ctx ctx; bn_mont_init(&ctx, m);
    bignum base_red; bn_mod(&base_red, base, m);
    /* Convert base to Montgomery form: bm = base * R mod m */
    bignum bm; bn_mont_mul(&bm, &base_red, &ctx.rr, m, &ctx);
    /* Build table: table[0] = R mod m (Montgomery 1), table[i] = base^i * R mod m */
    bignum table[16];
    bignum one; bn_zero(&one); one.v[0] = 1; one.len = 1;
    bn_mont_mul(&table[0], &one, &ctx.rr, m, &ctx);
    table[1] = bm;
    for(int i = 2; i < 16; i++)
        bn_mont_mul(&table[i], &table[i - 1], &bm, m, &ctx);
    bignum result = table[0];
    /* Process exponent MSB to LSB in 4-bit windows, fixed count to avoid leaking length */
    int total_windows = m->len * (LIMB_BITS / 4); /* m->len * LIMB_BITS / 4 */
    for(int w = total_windows - 1; w >= 0; w--) {
        /* Square 4 times */
        for(int s = 0; s < 4; s++)
            bn_mont_mul(&result, &result, &result, m, &ctx);
        /* Extract 4-bit window (always aligned to nibble, never spans limbs) */
        int bit_pos = w * 4;
        int window = (bit_pos / LIMB_BITS < exp->len)
            ? (int)((exp->v[bit_pos / LIMB_BITS] >> (bit_pos % LIMB_BITS)) & 0xF) : 0;
        /* Constant-time table lookup */
        bignum sel = table[0];
        for(int i = 1; i < 16; i++)
            bn_cmov(&sel, &table[i], i == window);
        bn_mont_mul(&result, &result, &sel, m, &ctx);
    }
    /* Convert out of Montgomery form */
    bn_mont_mul(r, &result, &one, m, &ctx);
}

/* ================================================================
 * P-384 Field Arithmetic (mod p, p = 2^384 - 2^128 - 2^96 + 2^32 - 1)
 * ================================================================ */
typedef struct { limb_t v[FP384_N]; } fp384;

#if USE_64BIT_LIMBS
static const fp384 P384_P = {{
    0x00000000FFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
}};
static const fp384 FP384_ZERO = {{0,0,0,0,0,0}};
static const fp384 FP384_ONE  = {{1,0,0,0,0,0}};
#else
static const fp384 P384_P = {{
    0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};
static const fp384 FP384_ZERO = {{0,0,0,0,0,0,0,0,0,0,0,0}};
static const fp384 FP384_ONE  = {{1,0,0,0,0,0,0,0,0,0,0,0}};
#endif

static int fp384_cmp(const fp384 *a, const fp384 *b) {
    for(int i=FP384_N-1;i>=0;i--) {
        if(a->v[i]>b->v[i]) return 1;
        if(a->v[i]<b->v[i]) return -1;
    }
    return 0;
}

static limb_t fp384_add_raw(fp384 *r, const fp384 *a, const fp384 *b) {
    limb_t c=0;
    for(int i=0;i<FP384_N;i++){c=adc_limb(a->v[i],b->v[i],c,&r->v[i]);}
    return c;
}

static limb_t fp384_sub_raw(fp384 *r, const fp384 *a, const fp384 *b) {
    limb_t borrow=0;
    for(int i=0;i<FP384_N;i++){
        borrow=sbb_limb(a->v[i],b->v[i],borrow,&r->v[i]);
    }
    return borrow;
}

/* Constant-time conditional selection: r = mask ? t : r (per-limb) */
#define FP_CSEL(r, t, mask, N) do { \
    for(int _i=0;_i<(N);_i++) \
        (r)->v[_i]=((r)->v[_i]&~(mask))|((t)->v[_i]&(mask)); \
} while(0)

static void fp384_add(fp384 *r, const fp384 *a, const fp384 *b) {
    limb_t carry=fp384_add_raw(r,a,b);
    fp384 t; limb_t borrow=fp384_sub_raw(&t,r,&P384_P);
    /* Use subtracted result if carry, or if no borrow (r >= P) */
    limb_t mask=-(limb_t)(carry|(1-borrow));
    FP_CSEL(r, &t, mask, FP384_N);
}

static void fp384_sub(fp384 *r, const fp384 *a, const fp384 *b) {
    limb_t borrow=fp384_sub_raw(r,a,b);
    fp384 t; fp384_add_raw(&t,r,&P384_P);
    limb_t mask=-(limb_t)borrow;
    FP_CSEL(r, &t, mask, FP384_N);
}

#if USE_64BIT_LIMBS
static void fp384_mul(fp384 *r, const fp384 *a, const fp384 *b) {
    /* Schoolbook 6x6 -> 12 limbs */
    uint64_t w[12]; memset(w,0,sizeof(w));
    for(int i=0;i<6;i++){
        uint64_t carry=0;
        for(int j=0;j<6;j++){
            mac64(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+6]=carry;
    }
    /* Algebraic reduction: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
     * Split into hi=w[6..11], lo=w[0..5]
     * result = lo + hi + (hi<<128) + (hi<<96) - (hi<<32) mod p
     * Uses 10-limb (640-bit) accumulator for intermediate result */
    uint64_t acc[10]; memset(acc,0,sizeof(acc));
    uint64_t c;
    /* +lo */
    for(int i=0;i<6;i++) acc[i]=w[i];
    /* +hi */
    c=0; for(int i=0;i<6;i++){c=adc64(acc[i],w[i+6],c,&acc[i]);}
    for(int i=6;i<10;i++){c=adc64(acc[i],0,c,&acc[i]);}
    /* +hi<<128 (shift by 2 limbs) */
    c=0; for(int i=0;i<6;i++){c=adc64(acc[i+2],w[i+6],c,&acc[i+2]);}
    for(int i=8;i<10;i++){c=adc64(acc[i],0,c,&acc[i]);}
    /* +hi<<96 (shift by 1 limb + 32 bits) */
    { uint64_t sh[10]={0};
      for(int i=0;i<6;i++){sh[i+1]|=w[i+6]<<32; sh[i+2]|=w[i+6]>>32;}
      c=0; for(int i=0;i<10;i++){c=adc64(acc[i],sh[i],c,&acc[i]);}
    }
    /* -hi<<32 */
    { uint64_t sh[10]={0};
      sh[0]=w[6]<<32;
      for(int i=1;i<6;i++) sh[i]=(w[i+6]<<32)|(w[i+5]>>32);
      sh[6]=w[11]>>32;
      uint64_t borrow=0;
      for(int i=0;i<10;i++){
          borrow=sbb64(acc[i],sh[i],borrow,&acc[i]);
      }
    }
    /* Second pass: reduce acc[6..9] * K + acc[0..5] */
    { const uint64_t hi2[6]={acc[6],acc[7],acc[8],acc[9],0,0}; uint64_t lo2[6];
      memcpy(lo2,acc,48);
      memset(acc,0,sizeof(acc));
      for(int i=0;i<6;i++) acc[i]=lo2[i];
      c=0; for(int i=0;i<6;i++){c=adc64(acc[i],hi2[i],c,&acc[i]);}
      for(int i=6;i<10;i++){c=adc64(acc[i],0,c,&acc[i]);}
      c=0; for(int i=0;i<4;i++){c=adc64(acc[i+2],hi2[i],c,&acc[i+2]);}
      for(int i=6;i<10;i++){c=adc64(acc[i],0,c,&acc[i]);}
      { uint64_t sh[10]={0};
        for(int i=0;i<4;i++){sh[i+1]|=hi2[i]<<32; sh[i+2]|=hi2[i]>>32;}
        c=0; for(int i=0;i<10;i++){c=adc64(acc[i],sh[i],c,&acc[i]);}
      }
      { uint64_t sh[10]={0};
        sh[0]=hi2[0]<<32;
        for(int i=1;i<4;i++) sh[i]=(hi2[i]<<32)|(hi2[i-1]>>32);
        sh[4]=hi2[3]>>32;
        uint64_t borrow=0;
        for(int i=0;i<10;i++){
          borrow=sbb64(acc[i],sh[i],borrow,&acc[i]);
      }
      }
    }
    /* Final: constant-time conditional subtraction of p (at most 4 times) */
    memcpy(r,acc,48);
    for(int pass=0;pass<4;pass++){
        fp384 t; limb_t borrow=fp384_sub_raw(&t,r,&P384_P);
        limb_t mask=-(limb_t)(1-borrow);
        FP_CSEL(r, &t, mask, FP384_N);
    }
}
#else /* 32-bit limbs: 12×12 schoolbook, limb-aligned shifts */
static void fp384_mul(fp384 *r, const fp384 *a, const fp384 *b) {
    /* Schoolbook 12x12 -> 24 limbs (32-bit) */
    uint32_t w[24]; memset(w,0,sizeof(w));
    for(int i=0;i<12;i++){
        uint32_t carry=0;
        for(int j=0;j<12;j++){
            mac_limb(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+12]=carry;
    }
    /* Reduction: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
     * hi = w[12..23] (12 limbs), lo = w[0..11]
     * result = lo + hi + (hi<<128) + (hi<<96) - (hi<<32) mod p
     * All shifts are limb-aligned (32-bit boundaries). */
    uint32_t acc[20]; memset(acc,0,sizeof(acc));
    uint32_t c;
    /* +lo */
    for(int i=0;i<12;i++) acc[i]=w[i];
    /* +hi (at position 0) */
    c=0; for(int i=0;i<12;i++){c=adc_limb(acc[i],w[i+12],c,&acc[i]);}
    for(int i=12;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
    /* +hi<<128 (shift by 4 limbs) */
    c=0; for(int i=0;i<12;i++){c=adc_limb(acc[i+4],w[i+12],c,&acc[i+4]);}
    for(int i=16;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
    /* +hi<<96 (shift by 3 limbs) */
    c=0; for(int i=0;i<12;i++){c=adc_limb(acc[i+3],w[i+12],c,&acc[i+3]);}
    for(int i=15;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
    /* -hi<<32 (shift by 1 limb) */
    { uint32_t borrow=0;
      for(int i=0;i<12;i++){borrow=sbb_limb(acc[i+1],w[i+12],borrow,&acc[i+1]);}
      for(int i=13;i<20;i++){borrow=sbb_limb(acc[i],0,borrow,&acc[i]);}
    }
    /* Second pass: reduce acc[12..19] */
    { uint32_t hi2[12]; memset(hi2,0,sizeof(hi2));
      for(int i=0;i<8;i++) hi2[i]=acc[12+i];
      uint32_t lo2[12]; memcpy(lo2,acc,48);
      memset(acc,0,sizeof(acc));
      for(int i=0;i<12;i++) acc[i]=lo2[i];
      c=0; for(int i=0;i<12;i++){c=adc_limb(acc[i],hi2[i],c,&acc[i]);}
      for(int i=12;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
      c=0; for(int i=0;i<8;i++){c=adc_limb(acc[i+4],hi2[i],c,&acc[i+4]);}
      for(int i=12;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
      c=0; for(int i=0;i<8;i++){c=adc_limb(acc[i+3],hi2[i],c,&acc[i+3]);}
      for(int i=11;i<20;i++){c=adc_limb(acc[i],0,c,&acc[i]);}
      { uint32_t borrow=0;
        for(int i=0;i<8;i++){borrow=sbb_limb(acc[i+1],hi2[i],borrow,&acc[i+1]);}
        for(int i=9;i<20;i++){borrow=sbb_limb(acc[i],0,borrow,&acc[i]);}
      }
    }
    /* Final: constant-time conditional subtraction of p (at most 4 times) */
    memcpy(r,acc,48);
    for(int pass=0;pass<4;pass++){
        fp384 t; limb_t borrow=fp384_sub_raw(&t,r,&P384_P);
        limb_t mask=-(limb_t)(1-borrow);
        FP_CSEL(r, &t, mask, FP384_N);
    }
}
#endif

static void fp384_sqr(fp384 *r, const fp384 *a){fp384_mul(r,a,a);}

static void fp384_inv(fp384 *r, const fp384 *a) {
#if USE_64BIT_LIMBS
    static const fp384 pm2={{
        0x00000000FFFFFFFD,0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF
    }};
#else
    static const fp384 pm2={{
        0xFFFFFFFD, 0x00000000, 0x00000000, 0xFFFFFFFF,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }};
#endif
    fp384 result=FP384_ONE, base=*a;
    for(int i=0;i<384;i++){
        if((pm2.v[i/LIMB_BITS]>>(i%LIMB_BITS))&1) fp384_mul(&result,&result,&base);
        fp384_sqr(&base,&base);
    }
    *r=result;
}

static void fp384_from_bytes(fp384 *r, const uint8_t b[48]) {
    for(int i=0;i<FP384_N;i++) {
        r->v[i]=0;
        for(int j=0;j<LIMB_BYTES;j++)
            r->v[i]|=(limb_t)b[47-(i*LIMB_BYTES+j)]<<(8*j);
    }
}
static void fp384_to_bytes(uint8_t b[48], const fp384 *a) {
    for(int i=0;i<FP384_N;i++)
        for(int j=0;j<LIMB_BYTES;j++)
            b[47-(i*LIMB_BYTES+j)]=(uint8_t)((a->v[i]>>(8*j))&0xFF);
}

/* ================================================================
 * P-384 Elliptic Curve  (y^2 = x^3 - 3x + b)
 * ================================================================ */
typedef struct { fp384 x,y,z; } ec384;

#if USE_64BIT_LIMBS
static const fp384 P384_B ={{
    0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A,
    0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4}};
static const fp384 P384_GX={{
    0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38,
    0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537}};
static const fp384 P384_GY={{
    0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0,
    0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F}};
#else
static const fp384 P384_B ={{
    0xD3EC2AEF, 0x2A85C8ED, 0x8A2ED19D, 0xC656398D,
    0x5013875A, 0x0314088F, 0xFE814112, 0x181D9C6E,
    0xE3F82D19, 0x988E056B, 0xE23EE7E4, 0xB3312FA7}};
static const fp384 P384_GX={{
    0x72760AB7, 0x3A545E38, 0xBF55296C, 0x5502F25D,
    0x82542A38, 0x59F741E0, 0x8BA79B98, 0x6E1D3B62,
    0xF320AD74, 0x8EB1C71E, 0xBE8B0537, 0xAA87CA22}};
static const fp384 P384_GY={{
    0x90EA0E5F, 0x7A431D7C, 0x1D7E819D, 0x0A60B1CE,
    0xB5F0B8C0, 0xE9DA3113, 0x289A147C, 0xF8F41DBD,
    0x9292DC29, 0x5D9E98BF, 0x96262C6F, 0x3617DE4A}};
#endif

static const uint8_t P384_ORDER[48] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,
    0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
    0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
};

/* Check if affine point (x,y) is on curve: y^2 = x^3 - 3x + b */
static int ec384_on_curve(const fp384 *x, const fp384 *y) {
    fp384 y2, x3, t, three={{0}}; three.v[0]=3;
    fp384_sqr(&y2, y);
    fp384_sqr(&t, x); fp384_mul(&x3, &t, x);
    fp384_mul(&t, x, &three);
    fp384_sub(&x3, &x3, &t);
    fp384_add(&x3, &x3, &P384_B);
    return fp384_cmp(&y2, &x3) == 0;
}

static int ec384_is_inf(const ec384 *p){return fp384_cmp(&p->z,&FP384_ZERO)==0;}

static void ec384_set_inf(ec384 *p){p->x=FP384_ONE;p->y=FP384_ONE;p->z=FP384_ZERO;}

/* Point doubling in Jacobian coords with a=-3.
 * No infinity branch: when z=0, z3=2*y*z=0 naturally. */
static void ec384_double(ec384 *r, const ec384 *p) {
    fp384 z2,z4,m,s,x3,y3,z3,t1,t2,y2;
    fp384_sqr(&z2,&p->z);
    fp384_sqr(&z4,&z2);
    /* m = 3*(x - z^2)*(x + z^2) since a=-3 */
    fp384_sub(&t1,&p->x,&z2);
    fp384_add(&t2,&p->x,&z2);
    fp384_mul(&m,&t1,&t2);
    fp384 m3; fp384_add(&m3,&m,&m); fp384_add(&m3,&m3,&m); /* m3 = 3*m */
    /* s = 4*x*y^2 */
    fp384_sqr(&y2,&p->y);
    fp384_mul(&s,&p->x,&y2);
    fp384_add(&s,&s,&s); fp384_add(&s,&s,&s); /* s = 4*x*y^2 */
    /* x3 = m3^2 - 2*s */
    fp384_sqr(&x3,&m3);
    fp384 s2; fp384_add(&s2,&s,&s);
    fp384_sub(&x3,&x3,&s2);
    /* y3 = m3*(s - x3) - 8*y^4 */
    fp384_sub(&t1,&s,&x3);
    fp384_mul(&y3,&m3,&t1);
    fp384 y4; fp384_sqr(&y4,&y2);
    fp384_add(&y4,&y4,&y4); fp384_add(&y4,&y4,&y4); fp384_add(&y4,&y4,&y4); /* 8*y^4 */
    fp384_sub(&y3,&y3,&y4);
    /* z3 = 2*y*z */
    fp384_mul(&z3,&p->y,&p->z);
    fp384_add(&z3,&z3,&z3);
    r->x=x3; r->y=y3; r->z=z3;
}

/* Point addition (Jacobian). No branches — designed for Montgomery ladder
 * where R0/R1 are never both infinity or equal after first iteration.
 * When h=0 or z=0, the formula naturally produces z3=0. */
static void ec384_add(ec384 *r, const ec384 *p, const ec384 *q) {
    fp384 z1s,z2s,u1,u2,z1c,z2c,s1,s2,h,rr,h2,h3,u1h2;
    fp384_sqr(&z1s,&p->z); fp384_sqr(&z2s,&q->z);
    fp384_mul(&u1,&p->x,&z2s); fp384_mul(&u2,&q->x,&z1s);
    fp384_mul(&z1c,&z1s,&p->z); fp384_mul(&z2c,&z2s,&q->z);
    fp384_mul(&s1,&p->y,&z2c); fp384_mul(&s2,&q->y,&z1c);
    fp384_sub(&h,&u2,&u1); fp384_sub(&rr,&s2,&s1);
    fp384_sqr(&h2,&h); fp384_mul(&h3,&h2,&h); fp384_mul(&u1h2,&u1,&h2);
    fp384 x3,y3,z3,t;
    fp384_sqr(&x3,&rr); fp384_sub(&x3,&x3,&h3);
    fp384 u1h2_2; fp384_add(&u1h2_2,&u1h2,&u1h2);
    fp384_sub(&x3,&x3,&u1h2_2);
    fp384_sub(&t,&u1h2,&x3); fp384_mul(&y3,&rr,&t);
    fp384 s1h3; fp384_mul(&s1h3,&s1,&h3); fp384_sub(&y3,&y3,&s1h3);
    fp384_mul(&z3,&p->z,&q->z); fp384_mul(&z3,&z3,&h);
    r->x=x3;r->y=y3;r->z=z3;
}

/* Convert Jacobian -> Affine */
static void ec384_to_affine(fp384 *ax, fp384 *ay, const ec384 *p) {
    fp384 zi,zi2,zi3;
    fp384_inv(&zi,&p->z);
    fp384_sqr(&zi2,&zi); fp384_mul(&zi3,&zi2,&zi);
    fp384_mul(ax,&p->x,&zi2); fp384_mul(ay,&p->y,&zi3);
}

/* Constant-time conditional swap of two EC points */
static void ec384_cswap(ec384 *a, ec384 *b, limb_t bit) {
    limb_t mask = -(limb_t)bit;
    for(int i=0;i<FP384_N;i++){
        limb_t d;
        d=mask&(a->x.v[i]^b->x.v[i]); a->x.v[i]^=d; b->x.v[i]^=d;
        d=mask&(a->y.v[i]^b->y.v[i]); a->y.v[i]^=d; b->y.v[i]^=d;
        d=mask&(a->z.v[i]^b->z.v[i]); a->z.v[i]^=d; b->z.v[i]^=d;
    }
}

/* Montgomery ladder scalar multiplication (constant-time).
 * Caller must ensure top bit of scalar is set.
 * Initializes R0=P, R1=2P and iterates from bit 382 down,
 * so add/double never see infinity inputs. */
static void ec384_scalar_mul(ec384 *r, const ec384 *p, const uint8_t scalar[48]) {
    ec384 R0, R1;
    R0 = *p;
    ec384_double(&R1, p);
    for(int i=382;i>=0;i--){
        int byte_idx=47-(i/8);
        int bit_pos=i%8;
        limb_t bit=(scalar[byte_idx]>>bit_pos)&1;
        ec384_cswap(&R0,&R1,bit);
        ec384_add(&R1,&R0,&R1);
        ec384_double(&R0,&R0);
        ec384_cswap(&R0,&R1,bit);
    }
    *r=R0;
}

/* ECDHE P-384: generate keypair, compute shared secret */
static void ecdhe_p384_keygen(uint8_t priv[P384_SCALAR_LEN], uint8_t pub[P384_POINT_LEN]) {
    random_bytes(priv,P384_SCALAR_LEN);
    /* Reduce scalar mod n to ensure it's in valid range [1, n-1] */
    bignum k, n384;
    bn_from_bytes(&k,priv,P384_SCALAR_LEN);
    bn_from_bytes(&n384,P384_ORDER,48);
    bn_mod(&k,&k,&n384);
    if(bn_is_zero(&k)) { k.v[0]=1; k.len=1; } /* avoid zero scalar */
    bn_to_bytes(&k,priv,P384_SCALAR_LEN);
    priv[0] |= 0x80; /* Set top bit so Montgomery ladder never hits infinity */
    ec384 G; G.x=P384_GX; G.y=P384_GY; G.z=FP384_ONE;
    ec384 Q; ec384_scalar_mul(&Q,&G,priv);
    fp384 ax,ay; ec384_to_affine(&ax,&ay,&Q);
    pub[0]=0x04;
    fp384_to_bytes(pub+1,&ax);
    fp384_to_bytes(pub+49,&ay);
    /* Verify the point is on the curve */
    if(!ec384_on_curve(&ax,&ay)) {
        fprintf(stderr,"BUG: generated point NOT on curve!\n");
        /* Also test that G is on the curve */
        if(!ec384_on_curve(&P384_GX,&P384_GY)) fprintf(stderr,"  G is NOT on curve either!\n");
        else fprintf(stderr,"  G IS on curve (field math OK, EC ops buggy)\n");
    } else {
        if(tls_verbose) fprintf(stderr,"  Point verified on curve\n");
    }
}

static void ecdhe_p384_shared_secret(const uint8_t priv[P384_SCALAR_LEN],
    const uint8_t peer_pub[P384_POINT_LEN], uint8_t secret[P384_SCALAR_LEN]) {
    fp384 px,py;
    fp384_from_bytes(&px,peer_pub+1);
    fp384_from_bytes(&py,peer_pub+49);
    if(!ec384_on_curve(&px,&py)) die("peer public key not on curve");
    ec384 P; P.x=px; P.y=py; P.z=FP384_ONE;
    ec384 S; ec384_scalar_mul(&S,&P,priv);
    fp384 sx,sy; ec384_to_affine(&sx,&sy,&S);
    fp384_to_bytes(secret,&sx);
}
/* ================================================================
 * P-256 Field Arithmetic (mod p, p = 2^256 - 2^224 + 2^192 + 2^96 - 1)
 * Constant-time fixed-width 4x64-bit limbs, modeled on fp384.
 * ================================================================ */
typedef struct { limb_t v[FP256_N]; } fp256;

#if USE_64BIT_LIMBS
static const fp256 P256_P = {{
    0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF,
    0x0000000000000000, 0xFFFFFFFF00000001
}};
static const fp256 FP256_ZERO = {{0,0,0,0}};
static const fp256 FP256_ONE  = {{1,0,0,0}};
static const fp256 P256_B = {{
    0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7
}};
static const fp256 P256_GX = {{
    0xF4A13945D898C296, 0x77037D812DEB33A0,
    0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247
}};
static const fp256 P256_GY = {{
    0xCBB6406837BF51F5, 0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B
}};
#else
static const fp256 P256_P = {{
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
    0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
}};
static const fp256 FP256_ZERO = {{0,0,0,0,0,0,0,0}};
static const fp256 FP256_ONE  = {{1,0,0,0,0,0,0,0}};
static const fp256 P256_B = {{
    0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
    0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
}};
static const fp256 P256_GX = {{
    0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
    0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2
}};
static const fp256 P256_GY = {{
    0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
    0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
}};
#endif

static const uint8_t P256_ORDER[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
    0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
};

static int fp256_cmp(const fp256 *a, const fp256 *b) {
    for(int i=FP256_N-1;i>=0;i--) {
        if(a->v[i]>b->v[i]) return 1;
        if(a->v[i]<b->v[i]) return -1;
    }
    return 0;
}

static int fp256_is_zero(const fp256 *a) {
    limb_t z=0; for(int i=0;i<FP256_N;i++) z|=a->v[i]; return z==0;
}

static limb_t fp256_add_raw(fp256 *r, const fp256 *a, const fp256 *b) {
    limb_t c=0;
    for(int i=0;i<FP256_N;i++){c=adc_limb(a->v[i],b->v[i],c,&r->v[i]);}
    return c;
}

static limb_t fp256_sub_raw(fp256 *r, const fp256 *a, const fp256 *b) {
    limb_t borrow=0;
    for(int i=0;i<FP256_N;i++){
        borrow=sbb_limb(a->v[i],b->v[i],borrow,&r->v[i]);
    }
    return borrow;
}

static void fp256_add(fp256 *r, const fp256 *a, const fp256 *b) {
    limb_t carry=fp256_add_raw(r,a,b);
    fp256 t; limb_t borrow=fp256_sub_raw(&t,r,&P256_P);
    limb_t mask=-(limb_t)(carry|(1-borrow));
    FP_CSEL(r, &t, mask, FP256_N);
}

static void fp256_sub(fp256 *r, const fp256 *a, const fp256 *b) {
    limb_t borrow=fp256_sub_raw(r,a,b);
    fp256 t; fp256_add_raw(&t,r,&P256_P);
    limb_t mask=-(limb_t)borrow;
    FP_CSEL(r, &t, mask, FP256_N);
}

#if USE_64BIT_LIMBS
static void fp256_mul(fp256 *r, const fp256 *a, const fp256 *b) {
    /* Schoolbook 4x4 -> 8 limbs */
    uint64_t w[8]; memset(w,0,sizeof(w));
    for(int i=0;i<4;i++){
        uint64_t carry=0;
        for(int j=0;j<4;j++){
            mac64(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+4]=carry;
    }
    /* NIST FIPS 186-4 D.2.3 fast reduction for P-256.
     * Extract 16 x 32-bit words from 512-bit product, then form
     * intermediate 256-bit values and accumulate.
     * Each si = (A7,A6,...,A0) big-endian 32-bit words.
     * Limb mapping: v[k] = (A_{2k+1} << 32) | A_{2k} */
    uint32_t c[16];
    for(size_t i=0;i<8;i++){c[2*i]=(uint32_t)w[i];c[2*i+1]=(uint32_t)(w[i]>>32);}
    #define W(hi,lo) ((uint64_t)(lo)|((uint64_t)(hi)<<32))
    /* s1 = (c7,c6,c5,c4,c3,c2,c1,c0) */
    fp256 s1={{w[0],w[1],w[2],w[3]}};
    /* s2 = (c15,c14,c13,c12,c11,0,0,0) */
    fp256 s2={{0, W(c[11],0), W(c[13],c[12]), W(c[15],c[14])}};
    /* s3 = (0,c15,c14,c13,c12,0,0,0) */
    fp256 s3={{0, W(c[12],0), W(c[14],c[13]), W(0,c[15])}};
    /* s4 = (c15,c14,0,0,0,c10,c9,c8) */
    fp256 s4={{W(c[9],c[8]), W(0,c[10]), 0, W(c[15],c[14])}};
    /* s5 = (c8,c13,c15,c14,c13,c11,c10,c9) */
    fp256 s5={{W(c[10],c[9]), W(c[13],c[11]), W(c[15],c[14]), W(c[8],c[13])}};
    /* s6 = (c10,c8,0,0,0,c13,c12,c11) */
    fp256 s6={{W(c[12],c[11]), W(0,c[13]), 0, W(c[10],c[8])}};
    /* s7 = (c11,c9,0,0,c15,c14,c13,c12) */
    fp256 s7={{W(c[13],c[12]), W(c[15],c[14]), 0, W(c[11],c[9])}};
    /* s8 = (c12,0,c10,c9,c8,c15,c14,c13) */
    fp256 s8={{W(c[14],c[13]), W(c[8],c[15]), W(c[10],c[9]), W(c[12],0)}};
    /* s9 = (c13,0,c11,c10,c9,0,c15,c14) */
    fp256 s9={{W(c[15],c[14]), W(c[9],0), W(c[11],c[10]), W(c[13],0)}};
    #undef W
    /* Accumulate: T = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 */
    fp256 T;
    T=s1;
    fp256_add(&T,&T,&s2); fp256_add(&T,&T,&s2);
    fp256_add(&T,&T,&s3); fp256_add(&T,&T,&s3);
    fp256_add(&T,&T,&s4);
    fp256_add(&T,&T,&s5);
    fp256_sub(&T,&T,&s6);
    fp256_sub(&T,&T,&s7);
    fp256_sub(&T,&T,&s8);
    fp256_sub(&T,&T,&s9);
    *r=T;
}
#else /* 32-bit limbs: 8×8 schoolbook, limbs are the 32-bit words directly */
static void fp256_mul(fp256 *r, const fp256 *a, const fp256 *b) {
    /* Schoolbook 8x8 -> 16 limbs (32-bit) */
    uint32_t w[16]; memset(w,0,sizeof(w));
    for(int i=0;i<8;i++){
        uint32_t carry=0;
        for(int j=0;j<8;j++){
            mac_limb(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+8]=carry;
    }
    /* NIST FIPS 186-4 D.2.3 fast reduction for P-256.
     * c[0..15] = w[0..15] — limbs ARE the 32-bit words.
     * s1..s9 constructed directly from limbs. */
    uint32_t *c = w;
    /* s1 = (c7,c6,c5,c4,c3,c2,c1,c0) */
    fp256 s1={{c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7]}};
    /* s2 = (c15,c14,c13,c12,c11,0,0,0) */
    fp256 s2={{0,0,0,c[11],c[12],c[13],c[14],c[15]}};
    /* s3 = (0,c15,c14,c13,c12,0,0,0) */
    fp256 s3={{0,0,0,c[12],c[13],c[14],c[15],0}};
    /* s4 = (c15,c14,0,0,0,c10,c9,c8) */
    fp256 s4={{c[8],c[9],c[10],0,0,0,c[14],c[15]}};
    /* s5 = (c8,c13,c15,c14,c13,c11,c10,c9) */
    fp256 s5={{c[9],c[10],c[11],c[13],c[14],c[15],c[13],c[8]}};
    /* s6 = (c10,c8,0,0,0,c13,c12,c11) */
    fp256 s6={{c[11],c[12],c[13],0,0,0,c[8],c[10]}};
    /* s7 = (c11,c9,0,0,c15,c14,c13,c12) */
    fp256 s7={{c[12],c[13],c[14],c[15],0,0,c[9],c[11]}};
    /* s8 = (c12,0,c10,c9,c8,c15,c14,c13) */
    fp256 s8={{c[13],c[14],c[15],c[8],c[9],c[10],0,c[12]}};
    /* s9 = (c13,0,c11,c10,c9,0,c15,c14) */
    fp256 s9={{c[14],c[15],0,c[9],c[10],c[11],0,c[13]}};
    /* Accumulate: T = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9 */
    fp256 T;
    T=s1;
    fp256_add(&T,&T,&s2); fp256_add(&T,&T,&s2);
    fp256_add(&T,&T,&s3); fp256_add(&T,&T,&s3);
    fp256_add(&T,&T,&s4);
    fp256_add(&T,&T,&s5);
    fp256_sub(&T,&T,&s6);
    fp256_sub(&T,&T,&s7);
    fp256_sub(&T,&T,&s8);
    fp256_sub(&T,&T,&s9);
    *r=T;
}
#endif

static void fp256_sqr(fp256 *r, const fp256 *a){fp256_mul(r,a,a);}

static void fp256_inv(fp256 *r, const fp256 *a) {
    /* Fermat's little theorem: a^(p-2) mod p */
#if USE_64BIT_LIMBS
    static const fp256 pm2={{
        0xFFFFFFFFFFFFFFFD, 0x00000000FFFFFFFF,
        0x0000000000000000, 0xFFFFFFFF00000001
    }};
#else
    static const fp256 pm2={{
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
    }};
#endif
    fp256 result=FP256_ONE, base=*a;
    for(int i=0;i<256;i++){
        if((pm2.v[i/LIMB_BITS]>>(i%LIMB_BITS))&1) fp256_mul(&result,&result,&base);
        fp256_sqr(&base,&base);
    }
    *r=result;
}

static void fp256_from_bytes(fp256 *r, const uint8_t b[32]) {
    for(int i=0;i<FP256_N;i++) {
        r->v[i]=0;
        for(int j=0;j<LIMB_BYTES;j++)
            r->v[i]|=(limb_t)b[31-(i*LIMB_BYTES+j)]<<(8*j);
    }
}
static void fp256_to_bytes(uint8_t b[32], const fp256 *a) {
    for(int i=0;i<FP256_N;i++)
        for(int j=0;j<LIMB_BYTES;j++)
            b[31-(i*LIMB_BYTES+j)]=(uint8_t)((a->v[i]>>(8*j))&0xFF);
}

/* ================================================================
 * P-256 Elliptic Curve  (y^2 = x^3 - 3x + b)
 * Constant-time fixed-width, no branches on point coordinates.
 * ================================================================ */
typedef struct { fp256 x,y,z; } ec256;

static int ec256_is_inf(const ec256 *p){return fp256_is_zero(&p->z);}
static void ec256_set_inf(ec256 *p){p->x=FP256_ONE;p->y=FP256_ONE;p->z=FP256_ZERO;}

static int ec256_on_curve(const fp256 *x, const fp256 *y) {
    fp256 y2, x3, t, three={{0}}; three.v[0]=3;
    fp256_sqr(&y2, y);
    fp256_sqr(&t, x); fp256_mul(&x3, &t, x);
    fp256_mul(&t, x, &three);
    fp256_sub(&x3, &x3, &t);
    fp256_add(&x3, &x3, &P256_B);
    return fp256_cmp(&y2, &x3) == 0;
}

/* Point doubling in Jacobian coords with a=-3.
 * No infinity branch: when z=0, z3=2*y*z=0 naturally. */
static void ec256_double(ec256 *r, const ec256 *pt) {
    fp256 z2,m,y2,s,x3,y3,z3,t1,t2,y4,s2;
    fp256_sqr(&z2,&pt->z);
    /* m = 3*(x-z2)*(x+z2) */
    fp256_sub(&t1,&pt->x,&z2);
    fp256_add(&t2,&pt->x,&z2);
    fp256_mul(&m,&t1,&t2);
    fp256 m3; fp256_add(&m3,&m,&m); fp256_add(&m3,&m3,&m);
    /* s = 4*x*y^2 */
    fp256_sqr(&y2,&pt->y);
    fp256_mul(&s,&pt->x,&y2);
    fp256_add(&s,&s,&s); fp256_add(&s,&s,&s);
    /* x3 = m3^2 - 2s */
    fp256_sqr(&x3,&m3);
    fp256_add(&s2,&s,&s);
    fp256_sub(&x3,&x3,&s2);
    /* y3 = m3*(s-x3) - 8*y^4 */
    fp256_sub(&t1,&s,&x3);
    fp256_mul(&y3,&m3,&t1);
    fp256_sqr(&y4,&y2);
    fp256_add(&y4,&y4,&y4); fp256_add(&y4,&y4,&y4); fp256_add(&y4,&y4,&y4);
    fp256_sub(&y3,&y3,&y4);
    /* z3 = 2*y*z */
    fp256_mul(&z3,&pt->y,&pt->z);
    fp256_add(&z3,&z3,&z3);
    r->x=x3; r->y=y3; r->z=z3;
}

/* Point addition (Jacobian). No branches — designed for Montgomery ladder
 * where R0/R1 are never both infinity or equal after first iteration.
 * When h=0 or z=0, the formula naturally produces z3=0. */
static void ec256_add(ec256 *r, const ec256 *p, const ec256 *q) {
    fp256 z1s,z2s,u1,u2,z1c,z2c,s1,s2,h,rr,h2,h3,u1h2;
    fp256_sqr(&z1s,&p->z); fp256_sqr(&z2s,&q->z);
    fp256_mul(&u1,&p->x,&z2s); fp256_mul(&u2,&q->x,&z1s);
    fp256_mul(&z1c,&z1s,&p->z); fp256_mul(&z2c,&z2s,&q->z);
    fp256_mul(&s1,&p->y,&z2c); fp256_mul(&s2,&q->y,&z1c);
    fp256_sub(&h,&u2,&u1); fp256_sub(&rr,&s2,&s1);
    fp256_sqr(&h2,&h); fp256_mul(&h3,&h2,&h); fp256_mul(&u1h2,&u1,&h2);
    fp256 x3,y3,z3,t;
    fp256_sqr(&x3,&rr); fp256_sub(&x3,&x3,&h3);
    fp256 u1h2_2; fp256_add(&u1h2_2,&u1h2,&u1h2);
    fp256_sub(&x3,&x3,&u1h2_2);
    fp256_sub(&t,&u1h2,&x3); fp256_mul(&y3,&rr,&t);
    fp256 s1h3; fp256_mul(&s1h3,&s1,&h3); fp256_sub(&y3,&y3,&s1h3);
    fp256_mul(&z3,&p->z,&q->z); fp256_mul(&z3,&z3,&h);
    r->x=x3;r->y=y3;r->z=z3;
}

static void ec256_to_affine(fp256 *ax, fp256 *ay, const ec256 *p) {
    fp256 zi,zi2,zi3;
    fp256_inv(&zi,&p->z);
    fp256_sqr(&zi2,&zi); fp256_mul(&zi3,&zi2,&zi);
    fp256_mul(ax,&p->x,&zi2); fp256_mul(ay,&p->y,&zi3);
}

static void ec256_cswap(ec256 *a, ec256 *b, limb_t bit) {
    limb_t mask = -(limb_t)bit;
    for(int i=0;i<FP256_N;i++){
        limb_t d;
        d=mask&(a->x.v[i]^b->x.v[i]); a->x.v[i]^=d; b->x.v[i]^=d;
        d=mask&(a->y.v[i]^b->y.v[i]); a->y.v[i]^=d; b->y.v[i]^=d;
        d=mask&(a->z.v[i]^b->z.v[i]); a->z.v[i]^=d; b->z.v[i]^=d;
    }
}

/* Montgomery ladder scalar multiplication (constant-time).
 * Caller must ensure top bit of scalar is set.
 * Initializes R0=P, R1=2P and iterates from bit 254 down,
 * so add/double never see infinity inputs. */
static void ec256_scalar_mul(ec256 *r, const ec256 *p, const uint8_t scalar[32]) {
    ec256 R0, R1;
    R0 = *p;
    ec256_double(&R1, p);
    for(int i=254;i>=0;i--){
        int byte_idx=31-(i/8);
        int bit_pos=i%8;
        limb_t bit=(scalar[byte_idx]>>bit_pos)&1;
        ec256_cswap(&R0,&R1,bit);
        ec256_add(&R1,&R0,&R1);
        ec256_double(&R0,&R0);
        ec256_cswap(&R0,&R1,bit);
    }
    *r=R0;
}

/* Variable-time scalar multiplication for ECDSA verification (public data).
 * Uses double-and-add; handles arbitrary scalars including those with top bit 0. */
static void ec256_scalar_mul_vartime(ec256 *r, const ec256 *p, const uint8_t scalar[32]) {
    ec256_set_inf(r);
    int started=0;
    for(int i=0;i<256;i++){
        int byte_idx=i/8, bit_pos=7-(i%8);
        int bit=(scalar[byte_idx]>>bit_pos)&1;
        if(started){
            ec256_double(r,r);
            if(bit) ec256_add(r,r,p);
        } else if(bit){
            *r=*p; started=1;
        }
    }
}

/* ECDHE P-256 keygen */
static void ecdhe_p256_keygen(uint8_t priv[P256_SCALAR_LEN], uint8_t pub[P256_POINT_LEN]) {
    random_bytes(priv,P256_SCALAR_LEN);
    /* Reduce scalar mod n to ensure it's in valid range [1, n-1] */
    bignum k256, n256;
    bn_from_bytes(&k256,priv,P256_SCALAR_LEN);
    bn_from_bytes(&n256,P256_ORDER,32);
    bn_mod(&k256,&k256,&n256);
    if(bn_is_zero(&k256)) { k256.v[0]=1; k256.len=1; }
    bn_to_bytes(&k256,priv,P256_SCALAR_LEN);
    priv[0]|=0x80;
    ec256 G; G.x=P256_GX; G.y=P256_GY; G.z=FP256_ONE;
    ec256 Q; ec256_scalar_mul(&Q,&G,priv);
    fp256 ax,ay; ec256_to_affine(&ax,&ay,&Q);
    pub[0]=0x04;
    fp256_to_bytes(pub+1,&ax);
    fp256_to_bytes(pub+33,&ay);
    if(!ec256_on_curve(&ax,&ay)) fprintf(stderr,"BUG: P-256 point NOT on curve!\n");
    else if(tls_verbose) fprintf(stderr,"  P-256 point verified on curve\n");
}

static void ecdhe_p256_shared_secret(const uint8_t priv[P256_SCALAR_LEN],
    const uint8_t peer_pub[P256_POINT_LEN], uint8_t secret[P256_SCALAR_LEN]) {
    fp256 px,py;
    fp256_from_bytes(&px,peer_pub+1);
    fp256_from_bytes(&py,peer_pub+33);
    if(!ec256_on_curve(&px,&py)) die("P-256 peer key not on curve");
    ec256 P; P.x=px; P.y=py; P.z=FP256_ONE;
    ec256 S; ec256_scalar_mul(&S,&P,priv);
    fp256 sx,sy; ec256_to_affine(&sx,&sy,&S);
    fp256_to_bytes(secret,&sx);
}

/* ================================================================
 * Curve25519 / X25519 Key Exchange
 * Field: GF(2^255 - 19), 4×64-bit limbs (little-endian)
 * ================================================================ */
typedef struct { limb_t v[FP25519_N]; } fp25519;

#if USE_64BIT_LIMBS
static const fp25519 FP25519_ZERO = {{0,0,0,0}};
static const fp25519 FP25519_P = {{
    0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF
}};
#else
static const fp25519 FP25519_ZERO = {{0,0,0,0,0,0,0,0}};
static const fp25519 FP25519_P = {{
    0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF
}};
#endif

static limb_t fp25519_add_raw(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    limb_t c=0;
    for(int i=0;i<FP25519_N;i++){c=adc_limb(a->v[i],b->v[i],c,&r->v[i]);}
    return c;
}

static limb_t fp25519_sub_raw(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    limb_t borrow=0;
    for(int i=0;i<FP25519_N;i++){
        borrow=sbb_limb(a->v[i],b->v[i],borrow,&r->v[i]);
    }
    return borrow;
}

static void fp25519_add(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    limb_t carry=fp25519_add_raw(r,a,b);
    fp25519 t; limb_t borrow=fp25519_sub_raw(&t,r,&FP25519_P);
    limb_t mask=-(limb_t)(carry|(1-borrow));
    FP_CSEL(r, &t, mask, FP25519_N);
}

static void fp25519_sub(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    limb_t borrow=fp25519_sub_raw(r,a,b);
    fp25519 t; fp25519_add_raw(&t,r,&FP25519_P);
    limb_t mask=-(limb_t)borrow;
    FP_CSEL(r, &t, mask, FP25519_N);
}

#if USE_64BIT_LIMBS
static void fp25519_mul(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    /* Schoolbook 4×4 → 8 limbs, reduce via 2^256 ≡ 38 (mod p) */
    uint64_t w[8]; memset(w,0,sizeof(w));
    for(int i=0;i<4;i++){
        uint64_t carry=0;
        for(int j=0;j<4;j++){
            mac64(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+4]=carry;
    }
    /* Reduce: result = w[0..3] + w[4..7] * 38 */
    uint64_t c_hi=0, c_lo=0;
    for(int i=0;i<4;i++){
        uint64_t ph, pl;
        mul64(w[i+4], 38, &ph, &pl);
        c_hi += ph;
        c_hi += addcarry64(c_lo, pl, &c_lo);
        c_hi += addcarry64(c_lo, w[i], &c_lo);
        w[i] = c_lo;
        c_lo = c_hi;
        c_hi = 0;
    }
    /* Carry could be up to ~38, fold once more */
    uint64_t fold = c_lo * 38;
    uint64_t ac = addcarry64(w[0], fold, &w[0]);
    for(int i=1;i<4&&ac;i++){ac=addcarry64(w[i], ac, &w[i]);}
    fp25519 res={{w[0],w[1],w[2],w[3]}};
    /* Conditional subtraction of p */
    fp25519 t; limb_t borrow=fp25519_sub_raw(&t,&res,&FP25519_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(&res, &t, mask, FP25519_N);
    *r=res;
}
#else /* 32-bit limbs: 8×8 schoolbook, native uint64_t for double-width */
static void fp25519_mul(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    /* Schoolbook 8×8 → 16 limbs (32-bit), reduce via 2^256 ≡ 38 (mod p) */
    uint32_t w[16]; memset(w,0,sizeof(w));
    for(int i=0;i<8;i++){
        uint32_t carry=0;
        for(int j=0;j<8;j++){
            mac_limb(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+8]=carry;
    }
    /* Reduce: result = w[0..7] + w[8..15] * 38 */
    uint64_t carry=0;
    for(int i=0;i<8;i++){
        uint64_t s = (uint64_t)w[i] + (uint64_t)w[i+8] * 38 + carry;
        w[i] = (uint32_t)s;
        carry = s >> 32;
    }
    /* Carry could be up to ~38, fold once more */
    uint64_t fold = carry * 38;
    carry = 0;
    for(int i=0;i<8;i++){
        uint64_t s = (uint64_t)w[i] + fold + carry;
        w[i] = (uint32_t)s;
        carry = s >> 32;
        fold = 0;
    }
    fp25519 res={{w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7]}};
    /* Conditional subtraction of p */
    fp25519 t; limb_t borrow=fp25519_sub_raw(&t,&res,&FP25519_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(&res, &t, mask, FP25519_N);
    *r=res;
}
#endif

static void fp25519_sqr(fp25519 *r, const fp25519 *a){fp25519_mul(r,a,a);}

static void fp25519_inv(fp25519 *r, const fp25519 *a) {
    /* Fermat: a^(p-2) mod p, p-2 = 2^255 - 21 */
#if USE_64BIT_LIMBS
    static const fp25519 pm2={{
        0xFFFFFFFFFFFFFFEB, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF
    }};
#else
    static const fp25519 pm2={{
        0xFFFFFFEB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF
    }};
#endif
    fp25519 result={{0}}; result.v[0]=1;
    fp25519 base=*a;
    for(int i=0;i<255;i++){
        if((pm2.v[i/LIMB_BITS]>>(i%LIMB_BITS))&1) fp25519_mul(&result,&result,&base);
        fp25519_sqr(&base,&base);
    }
    *r=result;
}

#if USE_64BIT_LIMBS
static void fp25519_mul_a24(fp25519 *r, const fp25519 *a) {
    /* Multiply by a24 = (486662-2)/4 = 121665 per RFC 7748 */
    uint64_t c_hi=0, c_lo=0;
    for(int i=0;i<4;i++){
        uint64_t ph, pl;
        mul64(a->v[i], X25519_A24, &ph, &pl);
        c_hi += ph;
        c_hi += addcarry64(c_lo, pl, &c_lo);
        r->v[i] = c_lo;
        c_lo = c_hi;
        c_hi = 0;
    }
    /* Reduce carry: carry * 38 */
    uint64_t hi=c_lo;
    uint64_t fold=hi*38;
    uint64_t ac=addcarry64(r->v[0], fold, &r->v[0]);
    for(int i=1;i<4&&ac;i++){ac=addcarry64(r->v[i], ac, &r->v[i]);}
    /* Conditional subtraction */
    fp25519 t; limb_t borrow=fp25519_sub_raw(&t,r,&FP25519_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(r, &t, mask, FP25519_N);
}
#else /* 32-bit: native uint64_t multiplication */
static void fp25519_mul_a24(fp25519 *r, const fp25519 *a) {
    uint64_t carry=0;
    for(int i=0;i<8;i++){
        uint64_t s = (uint64_t)a->v[i] * X25519_A24 + carry;
        r->v[i] = (uint32_t)s;
        carry = s >> 32;
    }
    /* Reduce carry: carry * 38 */
    uint64_t fold = carry * 38;
    carry = 0;
    for(int i=0;i<8;i++){
        uint64_t s = (uint64_t)r->v[i] + fold + carry;
        r->v[i] = (uint32_t)s;
        carry = s >> 32;
        fold = 0;
    }
    /* Conditional subtraction */
    fp25519 t; limb_t borrow=fp25519_sub_raw(&t,r,&FP25519_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(r, &t, mask, FP25519_N);
}
#endif

static void fp25519_cswap(fp25519 *a, fp25519 *b, limb_t bit) {
    limb_t mask=-(limb_t)bit;
    for(int i=0;i<FP25519_N;i++){
        limb_t d=mask&(a->v[i]^b->v[i]);
        a->v[i]^=d; b->v[i]^=d;
    }
}

/* Load 32 bytes little-endian into fp25519 */
static void fp25519_from_le(fp25519 *r, const uint8_t b[32]) {
    for(int i=0;i<FP25519_N;i++) {
        r->v[i]=0;
        for(int j=0;j<LIMB_BYTES;j++)
            r->v[i]|=(limb_t)b[i*LIMB_BYTES+j]<<(8*j);
    }
}

/* Store fp25519 as 32 bytes little-endian. Fully reduces first. */
static void fp25519_to_le(uint8_t b[32], const fp25519 *a) {
    fp25519 t=*a;
    /* Ensure fully reduced: subtract p if >= p (up to 2 times) */
    for(int pass=0;pass<2;pass++){
        fp25519 s; limb_t borrow=fp25519_sub_raw(&s,&t,&FP25519_P);
        limb_t mask=-(limb_t)(1-borrow);
        FP_CSEL(&t, &s, mask, FP25519_N);
    }
    for(int i=0;i<FP25519_N;i++)
        for(int j=0;j<LIMB_BYTES;j++)
            b[i*LIMB_BYTES+j]=(uint8_t)((t.v[i]>>(8*j))&0xFF);
}

/* X25519 Montgomery ladder (RFC 7748 §5) — x-coordinate only */
static void x25519_scalar_mult(const uint8_t scalar[32],
    const uint8_t u_in[32], uint8_t u_out[32]) {
    fp25519 u; fp25519_from_le(&u,u_in);
    /* Clamp scalar */
    uint8_t s[32]; memcpy(s,scalar,32);
    s[0]&=248; s[31]&=127; s[31]|=64;
    /* Montgomery ladder */
    fp25519 x_2={{0}}, z_2=FP25519_ZERO; x_2.v[0]=1;
    fp25519 x_3=u, z_3={{0}}; z_3.v[0]=1;
    limb_t swap=0;
    for(int t=254;t>=0;t--){
        limb_t kt=(s[t/8]>>(t%8))&1;
        swap^=kt;
        fp25519_cswap(&x_2,&x_3,swap);
        fp25519_cswap(&z_2,&z_3,swap);
        swap=kt;

        fp25519 A,B,C,D,AA,BB,E,DA,CB;
        fp25519_add(&A,&x_2,&z_2);
        fp25519_sqr(&AA,&A);
        fp25519_sub(&B,&x_2,&z_2);
        fp25519_sqr(&BB,&B);
        fp25519_sub(&E,&AA,&BB);
        fp25519_add(&C,&x_3,&z_3);
        fp25519_sub(&D,&x_3,&z_3);
        fp25519_mul(&DA,&D,&A);
        fp25519_mul(&CB,&C,&B);

        fp25519 sum,diff;
        fp25519_add(&sum,&DA,&CB);
        fp25519_sqr(&x_3,&sum);
        fp25519_sub(&diff,&DA,&CB);
        fp25519_sqr(&z_3,&diff);
        fp25519_mul(&z_3,&z_3,&u);

        fp25519_mul(&x_2,&AA,&BB);
        fp25519 a24e;
        fp25519_mul_a24(&a24e,&E);
        fp25519 t2; fp25519_add(&t2,&AA,&a24e);
        fp25519_mul(&z_2,&E,&t2);
    }
    fp25519_cswap(&x_2,&x_3,swap);
    fp25519_cswap(&z_2,&z_3,swap);
    /* Result = x_2 / z_2 */
    fp25519 inv_z; fp25519_inv(&inv_z,&z_2);
    fp25519 result; fp25519_mul(&result,&x_2,&inv_z);
    fp25519_to_le(u_out,&result);
}

static void x25519_keygen(uint8_t priv[X25519_KEY_LEN], uint8_t pub[X25519_KEY_LEN]) {
    random_bytes(priv,X25519_KEY_LEN);
    /* Basepoint u=9 */
    uint8_t basepoint[32]={9};
    x25519_scalar_mult(priv,basepoint,pub);
}

static int x25519_shared_secret(const uint8_t priv[X25519_KEY_LEN],
    const uint8_t peer[X25519_KEY_LEN], uint8_t out[X25519_KEY_LEN]) {
    x25519_scalar_mult(priv,peer,out);
    /* Check for all-zeros result (low-order point) */
    uint8_t z=0; for(int i=0;i<32;i++) z|=out[i];
    return z!=0 ? 0 : -1;
}

/* ================================================================
 * Ed25519 Signature Verification (RFC 8032 §5.1)
 * Edwards curve: -x² + y² = 1 + d·x²·y² over GF(2^255-19)
 * ================================================================ */

/* d = -121665/121666 mod p */
/* Group order L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t ED25519_L[32] = {
    0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
};
/* Basepoint B (compressed): y-coordinate little-endian, high bit = sign of x */
static const uint8_t ED25519_B_COMPRESSED[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

/* d = -121665/121666 mod p */
#if USE_64BIT_LIMBS
static const fp25519 ED25519_D = {{
    0x75EB4DCA135978A3ULL, 0x00700A4D4141D8ABULL,
    0x8CC740797779E898ULL, 0x52036CEE2B6FFE73ULL
}};
/* 2*d */
static const fp25519 ED25519_2D = {{
    0xEBD69B9426B2F159ULL, 0x00E0149A8283B156ULL,
    0x198E80F2EEF3D130ULL, 0x2406D9DC56DFFCE7ULL
}};
/* sqrt(-1) mod p */
static const fp25519 ED25519_SQRTM1 = {{
    0xC4EE1B274A0EA0B0ULL, 0x2F431806AD2FE478ULL,
    0x2B4D00993DFBD7A7ULL, 0x2B8324804FC1DF0BULL
}};
#else
static const fp25519 ED25519_D = {{
    0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D,
    0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE
}};
static const fp25519 ED25519_2D = {{
    0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A,
    0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC
}};
static const fp25519 ED25519_SQRTM1 = {{
    0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806,
    0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480
}};
#endif

typedef struct { fp25519 x,y,z,t; } ed25519_pt;

/* a^((p-5)/8) — used for square roots on GF(p), p = 2^255-19 ≡ 5 (mod 8) */
static void fp25519_pow2523(fp25519 *r, const fp25519 *a) {
    /* (p-5)/8 = 2^252 - 3, binary: 250 ones, 0, 1 */
    /* Bit-scan from LSB, same approach as fp25519_inv */
#if USE_64BIT_LIMBS
    static const fp25519 exp={{
        0xFFFFFFFFFFFFFFFD, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF
    }};
#else
    static const fp25519 exp={{
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0FFFFFFF
    }};
#endif
    fp25519 result={{0}}; result.v[0]=1;
    fp25519 base=*a;
    for(int i=0;i<252;i++){
        if((exp.v[i/LIMB_BITS]>>(i%LIMB_BITS))&1)
            fp25519_mul(&result,&result,&base);
        fp25519_sqr(&base,&base);
    }
    *r=result;
}

/* Decompress 32-byte Ed25519 point → extended coordinates */
static int ed25519_decompress(ed25519_pt *p, const uint8_t enc[32]) {
    uint8_t tmp[32]; memcpy(tmp,enc,32);
    int sign = tmp[31]>>7;
    tmp[31]&=0x7F;
    fp25519_from_le(&p->y,tmp);

    /* u = y²-1, v = d·y²+1 */
    fp25519 y2,u,v,one;
    one=FP25519_ZERO; one.v[0]=1;
    fp25519_sqr(&y2,&p->y);
    fp25519_sub(&u,&y2,&one);
    fp25519_mul(&v,&y2,&ED25519_D);
    fp25519_add(&v,&v,&one);

    /* x = u·v³·(u·v⁷)^((p-5)/8) */
    fp25519 v3,uv3,uv7;
    fp25519_sqr(&v3,&v); fp25519_mul(&v3,&v3,&v);         /* v³ */
    fp25519_mul(&uv3,&u,&v3);                              /* u·v³ */
    fp25519_sqr(&uv7,&v3); fp25519_mul(&uv7,&uv7,&v);     /* v⁷ */
    fp25519_mul(&uv7,&u,&uv7);                              /* u·v⁷ */
    fp25519 beta;
    fp25519_pow2523(&beta,&uv7);
    fp25519_mul(&p->x,&uv3,&beta);

    /* Check: v·x² == u? */
    fp25519 vx2,check;
    fp25519_sqr(&vx2,&p->x); fp25519_mul(&vx2,&vx2,&v);
    fp25519_sub(&check,&vx2,&u);
    uint8_t c1[32]; fp25519_to_le(c1,&check);
    int is_zero=1; for(int i=0;i<32;i++) if(c1[i]) {is_zero=0;break;}
    if(!is_zero){
        /* Try v·x² == -u */
        fp25519_add(&check,&vx2,&u);
        fp25519_to_le(c1,&check);
        is_zero=1; for(int i=0;i<32;i++) if(c1[i]) {is_zero=0;break;}
        if(!is_zero) return -1; /* not on curve */
        fp25519_mul(&p->x,&p->x,&ED25519_SQRTM1);
    }

    /* Adjust sign */
    uint8_t xb[32]; fp25519_to_le(xb,&p->x);
    if((xb[0]&1)!=sign){
        fp25519_sub(&p->x,&FP25519_ZERO,&p->x); /* negate */
    }

    /* Check x != 0 when sign bit is set */
    fp25519_to_le(xb,&p->x);
    is_zero=1; for(int i=0;i<32;i++) if(xb[i]) {is_zero=0;break;}
    if(is_zero && sign) return -1;

    /* z=1, t=x*y */
    p->z=FP25519_ZERO; p->z.v[0]=1;
    fp25519_mul(&p->t,&p->x,&p->y);
    return 0;
}

/* Compress extended coordinates → 32 bytes */
static void ed25519_compress(uint8_t out[32], const ed25519_pt *p) {
    fp25519 zinv,x,y;
    fp25519_inv(&zinv,&p->z);
    fp25519_mul(&x,&p->x,&zinv);
    fp25519_mul(&y,&p->y,&zinv);
    fp25519_to_le(out,&y);
    uint8_t xb[32]; fp25519_to_le(xb,&x);
    out[31]|=(xb[0]&1)<<7;
}

/* Extended coordinates addition (unified formula) */
static void ed25519_add(ed25519_pt *r, const ed25519_pt *p, const ed25519_pt *q) {
    fp25519 a,b,c,d,e,f,g,h;
    fp25519_sub(&a,&p->y,&p->x);
    fp25519_sub(&b,&q->y,&q->x);
    fp25519_mul(&a,&a,&b);
    fp25519_add(&b,&p->y,&p->x);
    fp25519_add(&c,&q->y,&q->x);
    fp25519_mul(&b,&b,&c);
    fp25519_mul(&c,&p->t,&q->t);
    fp25519_mul(&c,&c,&ED25519_2D);
    fp25519_mul(&d,&p->z,&q->z);
    fp25519_add(&d,&d,&d);
    fp25519_sub(&e,&b,&a);
    fp25519_sub(&f,&d,&c);
    fp25519_add(&g,&d,&c);
    fp25519_add(&h,&b,&a);
    fp25519_mul(&r->x,&e,&f);
    fp25519_mul(&r->y,&g,&h);
    fp25519_mul(&r->t,&e,&h);
    fp25519_mul(&r->z,&f,&g);
}

/* Point doubling: a=-1 twisted Edwards extended coordinates
   A=X², B=Y², C=2Z², D=-A, E=(X+Y)²-A-B, G=D+B, F=G-C, H=D-B */
static void ed25519_double(ed25519_pt *r, const ed25519_pt *p) {
    fp25519 a,b,c,dd,e,f,g,h;
    fp25519_sqr(&a,&p->x);
    fp25519_sqr(&b,&p->y);
    fp25519_sqr(&c,&p->z); fp25519_add(&c,&c,&c);
    fp25519_sub(&dd,&FP25519_ZERO,&a);
    fp25519_add(&e,&p->x,&p->y);
    fp25519_sqr(&e,&e); fp25519_sub(&e,&e,&a); fp25519_sub(&e,&e,&b);
    fp25519_add(&g,&dd,&b);
    fp25519_sub(&f,&g,&c);
    fp25519_sub(&h,&dd,&b);
    fp25519_mul(&r->x,&e,&f);
    fp25519_mul(&r->y,&g,&h);
    fp25519_mul(&r->t,&e,&h);
    fp25519_mul(&r->z,&f,&g);
}

/* Identity point */
static void ed25519_identity(ed25519_pt *p) {
    memset(p,0,sizeof(*p));
    p->y.v[0]=1; p->z.v[0]=1; /* (0,1,1,0) */
}

/* Variable-time double scalar multiplication: [s]B + [k]A (Strauss/Shamir) */
static void ed25519_double_scalar_mul_vartime(ed25519_pt *r,
    const uint8_t s[32], const ed25519_pt *B,
    const uint8_t k[32], const ed25519_pt *A) {
    /* Precompute A+B */
    ed25519_pt AB;
    ed25519_add(&AB,A,B);

    ed25519_identity(r);
    for(int i=255;i>=0;i--){
        ed25519_double(r,r);
        int sb=(s[i/8]>>(i%8))&1;
        int kb=(k[i/8]>>(i%8))&1;
        if(sb && kb) ed25519_add(r,r,&AB);
        else if(sb) ed25519_add(r,r,B);
        else if(kb) ed25519_add(r,r,A);
    }
}

/* Reduce 64-byte (512-bit) value mod L (TweetNaCl approach).
   L = 2^252 + 27742317777372353535851937790883648493 */
static void ed25519_reduce_l(uint8_t out[32], const uint8_t in[64]) {
    static const int64_t L[32] = {
        0xED,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,
        0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
    };
    int64_t x[64];
    int i,j;
    int64_t carry;
    for(i=0;i<64;i++) x[i]=(int64_t)in[i];
    /* Reduce high bytes: subtract 16*x[i] copies of L (compensates for L[31]=0x10) */
    for(i=63;i>=32;i--){
        carry=0;
        for(j=i-32;j<i-12;j++){
            x[j]+=carry-16*x[i]*L[j-(i-32)];
            carry=(x[j]+128)>>8;
            x[j]-=carry*256;
        }
        x[j]+=carry;
        x[i]=0;
    }
    /* Final reduction: handle x[31]'s high nibble (above 2^252 boundary) */
    carry=0;
    for(j=0;j<32;j++){
        x[j]+=carry-(x[31]>>4)*L[j];
        carry=x[j]>>8;
        x[j]&=255;
    }
    for(j=0;j<32;j++) x[j]-=carry*L[j];
    for(i=0;i<32;i++){
        x[i+1]+=x[i]>>8;
        out[i]=(uint8_t)(x[i]&255);
    }
}

/* Ed25519 verify (RFC 8032 §5.1.7, cofactorless) */
static int ed25519_verify(const uint8_t pubkey[32], const uint8_t *msg, size_t msg_len,
                          const uint8_t sig[64]) {
    ed25519_pt A;
    if(ed25519_decompress(&A,pubkey)<0) return 0;
    ed25519_pt R;
    if(ed25519_decompress(&R,sig)<0) return 0;

    /* Check s < L (local copy so static analyzers can track bounds) */
    uint8_t s_scalar[32];
    memcpy(s_scalar,sig+32,32);
    for(int i=31;i>=0;i--){
        if(s_scalar[i]<ED25519_L[i]) break;
        if(s_scalar[i]>ED25519_L[i]) return 0;
    }

    /* k = SHA-512(R || A || msg) mod L */
    uint8_t h[64];
    {
        sha512_ctx ctx; sha512_init(&ctx);
        sha512_update(&ctx,sig,32);
        sha512_update(&ctx,pubkey,32);
        sha512_update(&ctx,msg,msg_len);
        sha512_final(&ctx,h);
    }
    uint8_t k[32];
    ed25519_reduce_l(k,h);

    ed25519_pt B;
    if(ed25519_decompress(&B,ED25519_B_COMPRESSED)<0) return 0;

    /* [s]B - [k]A */
    ed25519_pt neg_A;
    fp25519_sub(&neg_A.x,&FP25519_ZERO,&A.x);
    neg_A.y=A.y; neg_A.z=A.z;
    fp25519_sub(&neg_A.t,&FP25519_ZERO,&A.t);

    ed25519_pt result;
    ed25519_double_scalar_mul_vartime(&result,s_scalar,&B,k,&neg_A);

    uint8_t result_enc[32];
    ed25519_compress(result_enc,&result);
    return ct_memeq(result_enc,sig,32);
}

/* ================================================================
 * fp448 Field Arithmetic — GF(2^448 - 2^224 - 1) "Goldilocks"
 * Used by X448 key exchange and Ed448 signatures.
 * ================================================================ */
typedef struct { limb_t v[FP448_N]; } fp448;

#if USE_64BIT_LIMBS
static const fp448 FP448_ZERO = {{0,0,0,0,0,0,0}};
static const fp448 FP448_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
#else
static const fp448 FP448_ZERO = {{0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
static const fp448 FP448_P = {{
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFEFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};
#endif

static limb_t fp448_add_raw(fp448 *r, const fp448 *a, const fp448 *b) {
    limb_t c=0;
    for(int i=0;i<FP448_N;i++){c=adc_limb(a->v[i],b->v[i],c,&r->v[i]);}
    return c;
}

static limb_t fp448_sub_raw(fp448 *r, const fp448 *a, const fp448 *b) {
    limb_t borrow=0;
    for(int i=0;i<FP448_N;i++){borrow=sbb_limb(a->v[i],b->v[i],borrow,&r->v[i]);}
    return borrow;
}

static void fp448_add(fp448 *r, const fp448 *a, const fp448 *b) {
    limb_t carry=fp448_add_raw(r,a,b);
    fp448 t; limb_t borrow=fp448_sub_raw(&t,r,&FP448_P);
    limb_t mask=-(limb_t)(carry|(1-borrow));
    FP_CSEL(r, &t, mask, FP448_N);
}

static void fp448_sub(fp448 *r, const fp448 *a, const fp448 *b) {
    limb_t borrow=fp448_sub_raw(r,a,b);
    fp448 t; fp448_add_raw(&t,r,&FP448_P);
    limb_t mask=-(limb_t)borrow;
    FP_CSEL(r, &t, mask, FP448_N);
}

#if USE_64BIT_LIMBS
static void fp448_mul(fp448 *r, const fp448 *a, const fp448 *b) {
    /* Schoolbook 7×7 → 14 limbs, then reduce via 2^448 ≡ 2^224 + 1.
       Convert to 32-bit limbs for reduction where 224/32=7 aligns cleanly. */
    uint64_t w[14]; memset(w,0,sizeof(w));
    for(int i=0;i<7;i++){
        uint64_t carry=0;
        for(int j=0;j<7;j++){
            mac64(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+7]=carry;
    }
    /* Split 14 x 64-bit limbs into 28 x 32-bit limbs */
    uint32_t t[28];
    for(int i=0;i<14;i++){
        t[2*i]=(uint32_t)w[i]; t[2*i+1]=(uint32_t)(w[i]>>32);
    }
    /* Reduce mod p using 32-bit limbs: acc = t[0..13] + t[14..27]*(2^224+1) */
    uint64_t acc[21]; memset(acc,0,sizeof(acc));
    for(int i=0;i<14;i++) acc[i]=t[i];
    for(int i=0;i<14;i++) acc[i]+=(uint64_t)t[i+14];     /* +1 part */
    for(int i=0;i<14;i++) acc[i+7]+=(uint64_t)t[i+14];   /* +2^224 part */
    /* Fold positions 14..20 back: 2^448 ≡ 2^224+1 */
    for(int i=14;i<=20;i++){
        acc[i-14]+=acc[i]; acc[i-14+7]+=acc[i]; acc[i]=0;
    }
    /* Carry propagation */
    for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
    /* Fold acc[14] */
    if(acc[14]){
        uint64_t top=acc[14]; acc[14]=0;
        acc[0]+=top; acc[7]+=top;
        for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
        if(acc[14]){ top=acc[14]; acc[14]=0; acc[0]+=top; acc[7]+=top;
            for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
        }
    }
    /* Convert back to 7 x 64-bit limbs */
    fp448 res;
    for(int i=0;i<7;i++) res.v[i]=(uint64_t)acc[2*i]|((uint64_t)acc[2*i+1]<<32);
    fp448 tmp; limb_t borrow=fp448_sub_raw(&tmp,&res,&FP448_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(&res, &tmp, mask, FP448_N);
    *r=res;
}
#else /* 32-bit */
static void fp448_mul(fp448 *r, const fp448 *a, const fp448 *b) {
    uint32_t w[28]; memset(w,0,sizeof(w));
    for(int i=0;i<14;i++){
        uint32_t carry=0;
        for(int j=0;j<14;j++){
            mac_limb(a->v[i], b->v[j], w[i+j], carry, &carry, &w[i+j]);
        }
        w[i+14]=carry;
    }
    /* Reduce: 2^448 ≡ 2^224 + 1. 224/32=7 limbs, clean alignment. */
    uint64_t acc[21]; memset(acc,0,sizeof(acc));
    for(int i=0;i<14;i++) acc[i]=w[i];
    for(int i=0;i<14;i++) acc[i]+=(uint64_t)w[i+14];     /* +1 part */
    for(int i=0;i<14;i++) acc[i+7]+=(uint64_t)w[i+14];   /* +2^224 part */
    /* Fold positions 14..20 back */
    for(int i=14;i<=20;i++){
        acc[i-14]+=acc[i]; acc[i-14+7]+=acc[i]; acc[i]=0;
    }
    for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
    if(acc[14]){
        uint64_t top=acc[14]; acc[14]=0;
        acc[0]+=top; acc[7]+=top;
        for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
        if(acc[14]){ top=acc[14]; acc[14]=0; acc[0]+=top; acc[7]+=top;
            for(int i=0;i<14;i++){ acc[i+1]+=acc[i]>>32; acc[i]&=0xFFFFFFFF; }
        }
    }
    fp448 res;
    for(int i=0;i<14;i++) res.v[i]=(uint32_t)acc[i];
    fp448 t; limb_t borrow=fp448_sub_raw(&t,&res,&FP448_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(&res, &t, mask, FP448_N);
    *r=res;
}
#endif

static void fp448_sqr(fp448 *r, const fp448 *a) { fp448_mul(r,a,a); }

static void fp448_inv(fp448 *r, const fp448 *a) {
    /* Fermat: a^(p-2), p-2 = 2^448 - 2^224 - 3.
       Binary of p-2 (MSB first): 223 ones, 0, 222 ones, 0, 1.
       Use addition chain to build a^(2^k-1) for needed k values. */
    int i;
    fp448 pow2,pow4,pow6,pow8,pow14,pow16,pow30,pow32,pow64,pow128,pow192,pow222;

    /* a^(2^2-1) = a^3 */
    fp448_sqr(&pow2,a); fp448_mul(&pow2,&pow2,a);
    /* a^(2^4-1) */
    pow4=pow2; for(i=0;i<2;i++) fp448_sqr(&pow4,&pow4);
    fp448_mul(&pow4,&pow4,&pow2);
    /* a^(2^6-1) */
    pow6=pow4; for(i=0;i<2;i++) fp448_sqr(&pow6,&pow6);
    fp448_mul(&pow6,&pow6,&pow2);
    /* a^(2^8-1) */
    pow8=pow4; for(i=0;i<4;i++) fp448_sqr(&pow8,&pow8);
    fp448_mul(&pow8,&pow8,&pow4);
    /* a^(2^14-1) */
    pow14=pow8; for(i=0;i<6;i++) fp448_sqr(&pow14,&pow14);
    fp448_mul(&pow14,&pow14,&pow6);
    /* a^(2^16-1) */
    pow16=pow8; for(i=0;i<8;i++) fp448_sqr(&pow16,&pow16);
    fp448_mul(&pow16,&pow16,&pow8);
    /* a^(2^30-1) */
    pow30=pow16; for(i=0;i<14;i++) fp448_sqr(&pow30,&pow30);
    fp448_mul(&pow30,&pow30,&pow14);
    /* a^(2^32-1) */
    pow32=pow16; for(i=0;i<16;i++) fp448_sqr(&pow32,&pow32);
    fp448_mul(&pow32,&pow32,&pow16);
    /* a^(2^64-1) */
    pow64=pow32; for(i=0;i<32;i++) fp448_sqr(&pow64,&pow64);
    fp448_mul(&pow64,&pow64,&pow32);
    /* a^(2^128-1) */
    pow128=pow64; for(i=0;i<64;i++) fp448_sqr(&pow128,&pow128);
    fp448_mul(&pow128,&pow128,&pow64);
    /* a^(2^192-1) */
    pow192=pow128; for(i=0;i<64;i++) fp448_sqr(&pow192,&pow192);
    fp448_mul(&pow192,&pow192,&pow64);
    /* a^(2^222-1) */
    pow222=pow192; for(i=0;i<30;i++) fp448_sqr(&pow222,&pow222);
    fp448_mul(&pow222,&pow222,&pow30);

    /* Now compute a^(p-2) using the bit pattern 223 ones, 0, 222 ones, 0, 1:
       pow223 = pow222^2 * a = a^(2^223-1) */
    fp448 result;
    fp448_sqr(&result,&pow222); fp448_mul(&result,&result,a);
    /* bit 224 = 0: square only → a^(2^224-2) */
    fp448_sqr(&result,&result);
    /* 222 ones: square 222 times then multiply by pow222 */
    for(i=0;i<222;i++) fp448_sqr(&result,&result);
    fp448_mul(&result,&result,&pow222);
    /* bit 1 = 0: square only */
    fp448_sqr(&result,&result);
    /* bit 0 = 1: square and multiply by a */
    fp448_sqr(&result,&result);
    fp448_mul(&result,&result,a);
    *r=result;
}

#if USE_64BIT_LIMBS
static void fp448_mul_a24(fp448 *r, const fp448 *a) {
    /* Multiply by a24 = 39081 */
    uint64_t c_hi=0, c_lo=0;
    for(int i=0;i<7;i++){
        uint64_t ph, pl;
        mul64(a->v[i], (uint64_t)X448_A24, &ph, &pl);
        c_hi += ph;
        c_hi += addcarry64(c_lo, pl, &c_lo);
        r->v[i] = c_lo;
        c_lo = c_hi;
        c_hi = 0;
    }
    /* Reduce carry: carry * (2^224 + 1) */
    uint64_t top = c_lo;
    uint64_t carry;
    carry = adc64(r->v[0], top, 0, &r->v[0]);
    for(int i=1;i<3&&carry;i++) carry=adc64(r->v[i], 0, carry, &r->v[i]);
    carry = adc64(r->v[3], top<<32, carry, &r->v[3]);
    carry = adc64(r->v[4], top>>32, carry, &r->v[4]);
    for(int i=5;i<7&&carry;i++) carry=adc64(r->v[i], 0, carry, &r->v[i]);
    /* Conditional subtraction */
    fp448 t; limb_t borrow=fp448_sub_raw(&t,r,&FP448_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(r, &t, mask, FP448_N);
}
#else
static void fp448_mul_a24(fp448 *r, const fp448 *a) {
    uint64_t carry=0;
    for(int i=0;i<14;i++){
        uint64_t s = (uint64_t)a->v[i] * X448_A24 + carry;
        r->v[i] = (uint32_t)s;
        carry = s >> 32;
    }
    /* Reduce carry: carry * (2^224 + 1). 224/32 = 7 limbs offset. */
    uint32_t top = (uint32_t)carry;
    uint64_t c;
    c = (uint64_t)r->v[0] + top; r->v[0]=(uint32_t)c; c>>=32;
    for(int i=1;i<7&&c;i++){uint64_t s=(uint64_t)r->v[i]+c;r->v[i]=(uint32_t)s;c=s>>32;}
    c = (uint64_t)r->v[7] + top + c; r->v[7]=(uint32_t)c; c>>=32;
    for(int i=8;i<14&&c;i++){uint64_t s=(uint64_t)r->v[i]+c;r->v[i]=(uint32_t)s;c=s>>32;}
    fp448 t; limb_t borrow=fp448_sub_raw(&t,r,&FP448_P);
    limb_t mask=-(limb_t)(1-borrow);
    FP_CSEL(r, &t, mask, FP448_N);
}
#endif

static void fp448_cswap(fp448 *a, fp448 *b, limb_t bit) {
    limb_t mask=-(limb_t)bit;
    for(int i=0;i<FP448_N;i++){
        limb_t d=mask&(a->v[i]^b->v[i]);
        a->v[i]^=d; b->v[i]^=d;
    }
}

static void fp448_from_le(fp448 *r, const uint8_t b[56]) {
    for(int i=0;i<FP448_N;i++){
        r->v[i]=0;
        for(int j=0;j<LIMB_BYTES;j++)
            r->v[i]|=(limb_t)b[i*LIMB_BYTES+j]<<(8*j);
    }
}

static void fp448_to_le(uint8_t b[56], const fp448 *a) {
    fp448 t=*a;
    for(int pass=0;pass<2;pass++){
        fp448 s; limb_t borrow=fp448_sub_raw(&s,&t,&FP448_P);
        limb_t mask=-(limb_t)(1-borrow);
        FP_CSEL(&t, &s, mask, FP448_N);
    }
    for(int i=0;i<FP448_N;i++)
        for(int j=0;j<LIMB_BYTES;j++)
            b[i*LIMB_BYTES+j]=(uint8_t)((t.v[i]>>(8*j))&0xFF);
}

/* X448 Montgomery ladder (RFC 7748 §5) — u-coordinate only */
static void x448_scalar_mult(const uint8_t scalar[56],
    const uint8_t u_in[56], uint8_t u_out[56]) {
    fp448 u; fp448_from_le(&u,u_in);
    uint8_t s[56]; memcpy(s,scalar,56);
    /* Clamp */
    s[0]&=252; s[55]|=128;
    /* Montgomery ladder */
    fp448 x_2=FP448_ZERO, z_2=FP448_ZERO; x_2.v[0]=1;
    fp448 x_3=u, z_3=FP448_ZERO; z_3.v[0]=1;
    limb_t swap=0;
    for(int t=447;t>=0;t--){
        limb_t kt=(s[t/8]>>(t%8))&1;
        swap^=kt;
        fp448_cswap(&x_2,&x_3,swap);
        fp448_cswap(&z_2,&z_3,swap);
        swap=kt;

        fp448 A,B,C,D,AA,BB,E,DA,CB;
        fp448_add(&A,&x_2,&z_2);
        fp448_sqr(&AA,&A);
        fp448_sub(&B,&x_2,&z_2);
        fp448_sqr(&BB,&B);
        fp448_sub(&E,&AA,&BB);
        fp448_add(&C,&x_3,&z_3);
        fp448_sub(&D,&x_3,&z_3);
        fp448_mul(&DA,&D,&A);
        fp448_mul(&CB,&C,&B);

        fp448 sum,diff;
        fp448_add(&sum,&DA,&CB);
        fp448_sqr(&x_3,&sum);
        fp448_sub(&diff,&DA,&CB);
        fp448_sqr(&z_3,&diff);
        fp448_mul(&z_3,&z_3,&u);

        fp448_mul(&x_2,&AA,&BB);
        fp448 a24e;
        fp448_mul_a24(&a24e,&E);
        fp448 t2; fp448_add(&t2,&AA,&a24e);
        fp448_mul(&z_2,&E,&t2);
    }
    fp448_cswap(&x_2,&x_3,swap);
    fp448_cswap(&z_2,&z_3,swap);
    fp448 inv_z; fp448_inv(&inv_z,&z_2);
    fp448 result; fp448_mul(&result,&x_2,&inv_z);
    fp448_to_le(u_out,&result);
}

static void x448_keygen(uint8_t priv[X448_KEY_LEN], uint8_t pub[X448_KEY_LEN]) {
    random_bytes(priv,X448_KEY_LEN);
    uint8_t basepoint[56]={5}; /* u=5 */
    x448_scalar_mult(priv,basepoint,pub);
}

static int x448_shared_secret(const uint8_t priv[X448_KEY_LEN],
    const uint8_t peer[X448_KEY_LEN], uint8_t out[X448_KEY_LEN]) {
    x448_scalar_mult(priv,peer,out);
    uint8_t z=0; for(int i=0;i<56;i++) z|=out[i];
    return z!=0 ? 0 : -1;
}

/* ================================================================
 * Ed448-Goldilocks Signature Verification (RFC 8032 §5.2)
 * Edwards curve: x² + y² = 1 - 39081·x²·y² over GF(2^448-2^224-1)
 * ================================================================ */

/* d = -39081 mod p */
#if USE_64BIT_LIMBS
static const fp448 ED448_D = {{
    0xFFFFFFFFFFFF6756ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
#else
static const fp448 ED448_D = {{
    0xFFFF6756, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFEFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
}};
#endif

/* Group order L for Ed448:
   L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
   (a 446-bit prime) */
static const uint8_t ED448_L[57] = {
    0xF3,0x44,0x58,0xAB,0x92,0xC2,0x78,0x23,0x55,0x8F,0xC5,0x8D,0x72,0xC2,0x6C,0x21,
    0x90,0x36,0xD6,0xAE,0x49,0xDB,0x4E,0xC4,0xE9,0x23,0xCA,0x7C,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F,0x00
};

/* Basepoint B (compressed, 57 bytes) — y-coordinate LE, sign bit in byte 56 */
static const uint8_t ED448_B_COMPRESSED[57] = {
    0x14,0xFA,0x30,0xF2,0x5B,0x79,0x08,0x98,0xAD,0xC8,0xD7,0x4E,0x2C,0x13,0xBD,0xFD,
    0xC4,0x39,0x7C,0xE6,0x1C,0xFF,0xD3,0x3A,0xD7,0xC2,0xA0,0x05,0x1E,0x9C,0x78,0x87,
    0x40,0x98,0xA3,0x6C,0x73,0x73,0xEA,0x4B,0x62,0xC7,0xC9,0x56,0x37,0x20,0x76,0x88,
    0x24,0xBC,0xB6,0x6E,0x71,0x46,0x3F,0x69,0x00
};

typedef struct { fp448 x,y,z,t; } ed448_pt;

static void ed448_identity(ed448_pt *p) {
    memset(p,0,sizeof(*p));
    p->y.v[0]=1; p->z.v[0]=1;
}

/* Decompress 57-byte Ed448 point → extended coordinates */
static int ed448_decompress(ed448_pt *p, const uint8_t enc[57]) {
    uint8_t tmp[56]; memcpy(tmp,enc,56);
    int sign = (enc[56]&0x80)>>7;
    /* The y-coordinate is in bytes 0..55, the sign of x is in the high bit of byte 56.
       But byte 56 should have its low 7 bits all zero (y is 448 bits = 56 bytes). */
    fp448_from_le(&p->y,tmp);

    /* x² = (y²-1)/(d·y²-1) from curve equation x²+y²=1+d·x²·y² */
    fp448 y2,u,v,one;
    one=FP448_ZERO; one.v[0]=1;
    fp448_sqr(&y2,&p->y);
    fp448_sub(&u,&y2,&one);
    fp448_mul(&v,&y2,&ED448_D);
    fp448_sub(&v,&v,&one);

    /* sqrt(u/v) = (u/v)^((p+1)/4), (p+1)/4 = 2^222·(2^224-1) */
    fp448 v_inv, uv;
    fp448_inv(&v_inv,&v);
    fp448_mul(&uv,&u,&v_inv);

    /* Compute uv^(2^224-1) via addition chain, then square 222 times */
    fp448 a2, a4, a8, a16, a32, a64, a96, a128, a224;
    fp448_sqr(&a2,&uv); fp448_mul(&a2,&a2,&uv);
    a4=a2; for(int i=0;i<2;i++) fp448_sqr(&a4,&a4); fp448_mul(&a4,&a4,&a2);
    a8=a4; for(int i=0;i<4;i++) fp448_sqr(&a8,&a8); fp448_mul(&a8,&a8,&a4);
    a16=a8; for(int i=0;i<8;i++) fp448_sqr(&a16,&a16); fp448_mul(&a16,&a16,&a8);
    a32=a16; for(int i=0;i<16;i++) fp448_sqr(&a32,&a32); fp448_mul(&a32,&a32,&a16);
    a64=a32; for(int i=0;i<32;i++) fp448_sqr(&a64,&a64); fp448_mul(&a64,&a64,&a32);
    a128=a64; for(int i=0;i<64;i++) fp448_sqr(&a128,&a128); fp448_mul(&a128,&a128,&a64);
    a96=a64; for(int i=0;i<32;i++) fp448_sqr(&a96,&a96); fp448_mul(&a96,&a96,&a32);
    a224=a128; for(int i=0;i<96;i++) fp448_sqr(&a224,&a224); fp448_mul(&a224,&a224,&a96);
    fp448 sq = a224;
    for(int i=0;i<222;i++) fp448_sqr(&sq,&sq);
    p->x = sq;

    /* Verify: x² == u/v */
    fp448 x2_check;
    fp448_sqr(&x2_check,&p->x);
    fp448_sub(&x2_check,&x2_check,&uv);
    uint8_t chk[56]; fp448_to_le(chk,&x2_check);
    int is_zero=1; for(int i=0;i<56;i++) if(chk[i]) {is_zero=0;break;}
    if(!is_zero) return -1;

    /* Adjust sign */
    uint8_t xb[56]; fp448_to_le(xb,&p->x);
    if((xb[0]&1)!=sign){
        fp448_sub(&p->x,&FP448_ZERO,&p->x);
    }

    /* z=1, t=x*y */
    p->z=FP448_ZERO; p->z.v[0]=1;
    fp448_mul(&p->t,&p->x,&p->y);
    return 0;
}

static void ed448_compress(uint8_t out[57], const ed448_pt *p) {
    fp448 zinv,x,y;
    fp448_inv(&zinv,&p->z);
    fp448_mul(&x,&p->x,&zinv);
    fp448_mul(&y,&p->y,&zinv);
    fp448_to_le(out,&y);
    uint8_t xb[56]; fp448_to_le(xb,&x);
    out[56]=(xb[0]&1)<<7;
}

/* Extended coordinates addition for a=1 twisted Edwards: x²+y²=1+d·x²·y²
   A=X1·X2, B=Y1·Y2, C=T1·d·T2, D=Z1·Z2,
   E=(X1+Y1)·(X2+Y2)-A-B, F=D-C, G=D+C, H=B-A */
static void ed448_add(ed448_pt *r, const ed448_pt *p, const ed448_pt *q) {
    fp448 a,b,c,d,e,f,g,h;
    fp448_mul(&a,&p->x,&q->x);
    fp448_mul(&b,&p->y,&q->y);
    fp448_mul(&c,&p->t,&q->t);
    fp448_mul(&c,&c,&ED448_D);
    fp448_mul(&d,&p->z,&q->z);
    fp448_add(&e,&p->x,&p->y);
    fp448_add(&f,&q->x,&q->y);
    fp448_mul(&e,&e,&f);
    fp448_sub(&e,&e,&a);
    fp448_sub(&e,&e,&b);
    fp448_sub(&f,&d,&c);
    fp448_add(&g,&d,&c);
    fp448_sub(&h,&b,&a);
    fp448_mul(&r->x,&e,&f);
    fp448_mul(&r->y,&g,&h);
    fp448_mul(&r->t,&e,&h);
    fp448_mul(&r->z,&f,&g);
}

/* Point doubling: a=1 twisted Edwards extended coordinates
   A=X², B=Y², C=2Z², D=A, E=(X+Y)²-A-B, G=D+B, F=G-C, H=D-B */
static void ed448_double(ed448_pt *r, const ed448_pt *p) {
    fp448 a,b,c,d,e,f,g,h;
    fp448_sqr(&a,&p->x);
    fp448_sqr(&b,&p->y);
    fp448_sqr(&c,&p->z); fp448_add(&c,&c,&c);
    d=a;
    fp448_add(&e,&p->x,&p->y);
    fp448_sqr(&e,&e);
    fp448_sub(&e,&e,&a);
    fp448_sub(&e,&e,&b);
    fp448_add(&g,&d,&b);
    fp448_sub(&f,&g,&c);
    fp448_sub(&h,&d,&b);
    fp448_mul(&r->x,&e,&f);
    fp448_mul(&r->y,&g,&h);
    fp448_mul(&r->t,&e,&h);
    fp448_mul(&r->z,&f,&g);
}

static void ed448_double_scalar_mul_vartime(ed448_pt *r,
    const uint8_t *s, int s_bits,
    const ed448_pt *B,
    const uint8_t *k, int k_bits,
    const ed448_pt *A) {
    ed448_pt AB;
    ed448_add(&AB,A,B);
    ed448_identity(r);
    int max_bits = s_bits > k_bits ? s_bits : k_bits;
    for(int i=max_bits-1;i>=0;i--){
        ed448_double(r,r);
        int sb = (i < s_bits) ? (s[i/8]>>(i%8))&1 : 0;
        int kb = (i < k_bits) ? (k[i/8]>>(i%8))&1 : 0;
        if(sb && kb) ed448_add(r,r,&AB);
        else if(sb) ed448_add(r,r,B);
        else if(kb) ed448_add(r,r,A);
    }
}

/* Reduce 114-byte little-endian SHAKE256 output mod L for Ed448.
   Uses iterative reduction: 2^446 ≡ c (mod L) where c = 2^446 - L (224 bits). */
static void ed448_reduce_l(uint8_t out[57], const uint8_t in[114]) {
    /* c = 2^446 - L, 28 bytes little-endian */
    static const uint8_t C[28] = {
        0x0D,0xBB,0xA7,0x54,0x6D,0x3D,0x87,0xDC,
        0xAA,0x70,0x3A,0x72,0x8D,0x3D,0x93,0xDE,
        0x6F,0xC9,0x29,0x51,0xB6,0x24,0xB1,0x3B,
        0x16,0xDC,0x35,0x83
    };
    /* 16-bit limbs in uint64_t; split at bit 446 (limb 27, bit 14) */
    uint64_t x[72];
    int i,j;
    for(i=0;i<57;i++) x[i]=((uint64_t)in[2*i]) | ((uint64_t)in[2*i+1]<<8);
    for(i=57;i<72;i++) x[i]=0;

    uint64_t cl[14];
    for(i=0;i<14;i++) cl[i]=((uint64_t)C[2*i]) | ((uint64_t)C[2*i+1]<<8);

    /* 3 iterations: extract x_hi = x >> 446, replace x with x_lo + x_hi * c */
    for(int iter=0;iter<3;iter++){
        int hi_limbs = (iter==0) ? 30 : (iter==1) ? 16 : 4;
        uint64_t hi[32];
        for(i=0;i<32;i++) hi[i]=0;
        for(i=0;i<hi_limbs;i++){
            uint64_t lo_part = (i+27 < 72) ? x[i+27] : 0;
            uint64_t hi_part = (i+28 < 72) ? x[i+28] : 0;
            hi[i] = (lo_part >> 14) | ((hi_part & 0x3FFF) << 2);
        }

        x[27] &= 0x3FFF;
        for(i=28;i<72;i++) x[i]=0;

        for(i=0;i<hi_limbs;i++){
            if(hi[i]==0) continue;
            uint64_t carry=0;
            for(j=0;j<14;j++){
                uint64_t v = x[i+j] + hi[i]*cl[j] + carry;
                x[i+j] = v & 0xFFFF;
                carry = v >> 16;
            }
            for(j=i+14; carry && j<72; j++){
                uint64_t v = x[j] + carry;
                x[j] = v & 0xFFFF;
                carry = v >> 16;
            }
        }
    }

    /* Conditional subtract of L */
    uint64_t ll[28];
    for(i=0;i<28;i++) ll[i]=((uint64_t)ED448_L[2*i]) | ((uint64_t)ED448_L[2*i+1]<<8);
    ll[27] &= 0x3FFF;

    uint64_t borrow=0;
    uint64_t b[28];
    for(i=0;i<28;i++){
        uint64_t v = x[i] - ll[i] - borrow;
        b[i] = v & 0xFFFF;
        borrow = (v >> 63) & 1;
    }
    if(!borrow){
        for(i=0;i<28;i++) x[i]=b[i];
    }

    for(i=0;i<28;i++){
        out[2*i]   = (uint8_t)(x[i] & 0xFF);
        out[2*i+1] = (uint8_t)((x[i]>>8) & 0xFF);
    }
    out[56]=0;
}

/* Ed448 verify (RFC 8032 §5.2.7, cofactorless) */
static int ed448_verify(const uint8_t pubkey[57], const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[114]) {
    ed448_pt A;
    if(ed448_decompress(&A,pubkey)<0) return 0;
    ed448_pt R;
    if(ed448_decompress(&R,sig)<0) return 0;

    /* Check s < L */
    const uint8_t *s_bytes=sig+57;
    for(int i=56;i>=0;i--){
        if(s_bytes[i]<ED448_L[i]) break;
        if(s_bytes[i]>ED448_L[i]) return 0;
    }

    /* k = SHAKE256(dom4(0,0) || R || A || msg, 114) mod L */
    uint8_t h[114];
    {
        shake256_ctx ctx; shake256_init(&ctx);
        static const uint8_t dom4[10] = {'S','i','g','E','d','4','4','8',0x00,0x00};
        shake256_update(&ctx,dom4,10);
        shake256_update(&ctx,sig,57);
        shake256_update(&ctx,pubkey,57);
        shake256_update(&ctx,msg,msg_len);
        shake256_final(&ctx,h,114);
    }
    uint8_t k[57];
    ed448_reduce_l(k,h);

    ed448_pt B;
    if(ed448_decompress(&B,ED448_B_COMPRESSED)<0) return 0;

    /* [s]B - [k]A */
    ed448_pt neg_A;
    fp448_sub(&neg_A.x,&FP448_ZERO,&A.x);
    neg_A.y=A.y; neg_A.z=A.z;
    fp448_sub(&neg_A.t,&FP448_ZERO,&A.t);

    ed448_pt result;
    ed448_double_scalar_mul_vartime(&result,s_bytes,446,&B,k,446,&neg_A);

    uint8_t result_enc[57], R_enc[57];
    ed448_compress(result_enc,&result);
    memcpy(R_enc,sig,57);
    return ct_memeq(result_enc,R_enc,57);
}

/* ================================================================
 * Base64 / PEM Decoder
 * ================================================================ */
static int b64val(uint8_t c) {
    if(c>='A'&&c<='Z') return c-'A';
    if(c>='a'&&c<='z') return c-'a'+26;
    if(c>='0'&&c<='9') return c-'0'+52;
    if(c=='+') return 62;
    if(c=='/') return 63;
    return -1;
}

static size_t pem_to_der(const char *pem, size_t pem_len, uint8_t *der) {
    const char *begin = strstr(pem, "-----BEGIN ");
    if(!begin) return 0;
    begin = memchr(begin, '\n', pem_len-(size_t)(begin-pem));
    if(!begin) return 0;
    begin++;
    const char *end = strstr(begin, "-----END ");
    if(!end) return 0;
    size_t out = 0;
    uint32_t acc = 0; int bits = 0;
    for(const char *p = begin; p < end; p++) {
        int v = b64val((uint8_t)*p);
        if(v < 0) continue;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if(bits >= 8) { bits -= 8; der[out++] = (acc >> bits) & 0xFF; }
    }
    return out;
}

/* ================================================================
 * ASN.1/DER Parser Helpers
 * ================================================================ */
/* Read tag + length, return pointer to value. NULL on error. */
static const uint8_t *der_read_tl(const uint8_t *p, const uint8_t *end,
                                    uint8_t *tag, size_t *len) {
    if(p >= end) return NULL;
    *tag = *p++;
    if(p >= end) return NULL;
    if(*p < 0x80) {
        *len = *p++;
    } else {
        int nb = *p++ & 0x7F;
        /* nb==0: reject BER indefinite length */
        if(nb == 0 || nb > 3 || p + nb > end) return NULL;
        *len = 0;
        for(int i = 0; i < nb; i++) *len = (*len << 8) | *p++;
    }
    if(p + *len > end) return NULL;
    return p;
}

/* Skip one TLV element, return pointer past it */
static const uint8_t *der_skip(const uint8_t *p, const uint8_t *end) {
    uint8_t tag; size_t len;
    const uint8_t *val = der_read_tl(p, end, &tag, &len);
    if(!val) return NULL;
    return val + len;
}

/* Read TLV expecting a specific tag. Returns pointer to value, or NULL on mismatch. */
static const uint8_t *der_expect(const uint8_t *p, const uint8_t *end,
                                  uint8_t expected_tag, size_t *len) {
    uint8_t tag;
    const uint8_t *val=der_read_tl(p, end, &tag, len);
    if(!val || tag!=expected_tag) return NULL;
    return val;
}

static int oid_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    return alen == blen && memcmp(a, b, alen) == 0;
}

/* Parse UTCTime (tag 0x17: YYMMDDHHMMSSZ) or GeneralizedTime (tag 0x18: YYYYMMDDHHMMSSZ) */
static time_t der_parse_time(const uint8_t *p, const uint8_t *end) {
    uint8_t tag; size_t len;
    const uint8_t *val=der_read_tl(p,end,&tag,&len);
    if(!val) return 0;
    const char *s=(const char *)val;
    struct tm t={0};
    if(tag==0x17){ /* UTCTime */
        int yy=(s[0]-'0')*10+(s[1]-'0');
        t.tm_year=yy>=50?yy:yy+100;
        s+=2;
    } else if(tag==0x18){ /* GeneralizedTime */
        t.tm_year=(s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0')-1900;
        s+=4;
    } else return 0;
    t.tm_mon=(s[0]-'0')*10+(s[1]-'0')-1;
    t.tm_mday=(s[2]-'0')*10+(s[3]-'0');
    t.tm_hour=(s[4]-'0')*10+(s[5]-'0');
    t.tm_min=(s[6]-'0')*10+(s[7]-'0');
    t.tm_sec=(s[8]-'0')*10+(s[9]-'0');
    return timegm(&t);
}


/* HelloRetryRequest sentinel random (RFC 8446 §4.1.3) */
static const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

/* ================================================================
 * ECDSA Signature Verification
 * ================================================================ */
/* Variable-time scalar mul (safe for public verification inputs) */
static void ec384_scalar_mul_vartime(ec384 *r, const ec384 *p, const uint8_t scalar[48]) {
    ec384_set_inf(r);
    int started=0;
    for(int i=0;i<384;i++){
        int byte_idx=i/8, bit_pos=7-(i%8);
        int bit=(scalar[byte_idx]>>bit_pos)&1;
        if(started){
            ec384_double(r,r);
            if(bit) ec384_add(r,r,p);
        } else if(bit){
            *r=*p; started=1;
        }
    }
}

static int ecdsa_p384_verify(const uint8_t *hash, size_t hash_len,
                              const uint8_t *sig_der, size_t sig_len,
                              const uint8_t *pubkey, size_t pk_len) {
    if(pk_len!=P384_POINT_LEN||pubkey[0]!=0x04) return 0;

    /* Parse DER signature → (r, s) */
    const uint8_t *p=sig_der, *end=sig_der+sig_len;
    size_t len;
    p=der_expect(p,end,0x30,&len);
    if(!p) return 0;
    end=p+len;

    const uint8_t *rval=der_expect(p,end,0x02,&len);
    if(!rval) return 0;
    const uint8_t *rp=rval; size_t rlen=len;
    if(rlen>0&&rp[0]==0){rp++;rlen--;}
    p=rval+len;

    const uint8_t *sval=der_expect(p,end,0x02,&len);
    if(!sval) return 0;
    const uint8_t *sp=sval; size_t slen=len;
    if(slen>0&&sp[0]==0){sp++;slen--;}

    bignum r_bn, s_bn, n, hash_bn, w, u1, u2;
    bn_from_bytes(&r_bn,rp,rlen);
    bn_from_bytes(&s_bn,sp,slen);
    bn_from_bytes(&n,P384_ORDER,48);

    /* SEC 1 §4.1.4: verify r,s ∈ [1, n-1] */
    if(bn_is_zero(&r_bn) || bn_cmp(&r_bn,&n)>=0) return 0;
    if(bn_is_zero(&s_bn) || bn_cmp(&s_bn,&n)>=0) return 0;

    bn_from_bytes(&hash_bn,hash,hash_len>48?48:hash_len);

    /* w = s^(-1) mod n via Fermat: s^(n-2) mod n */
    bignum nm2;
    bn_from_bytes(&nm2,P384_ORDER,48);
    bignum two; bn_zero(&two); two.v[0]=2; two.len=1;
    bn_sub(&nm2,&nm2,&two);
    bn_modexp(&w,&s_bn,&nm2,&n);

    /* u1 = hash * w mod n, u2 = r * w mod n */
    bn_modmul(&u1,&hash_bn,&w,&n);
    bn_modmul(&u2,&r_bn,&w,&n);

    uint8_t u1_bytes[48], u2_bytes[48];
    bn_to_bytes(&u1,u1_bytes,48);
    bn_to_bytes(&u2,u2_bytes,48);

    /* R = u1*G + u2*Q */
    ec384 G; G.x=P384_GX; G.y=P384_GY; G.z=FP384_ONE;
    ec384 Q;
    fp384 qx,qy;
    fp384_from_bytes(&qx,pubkey+1);
    fp384_from_bytes(&qy,pubkey+49);
    Q.x=qx; Q.y=qy; Q.z=FP384_ONE;

    ec384 R1,R2,R;
    ec384_scalar_mul_vartime(&R1,&G,u1_bytes);
    ec384_scalar_mul_vartime(&R2,&Q,u2_bytes);
    ec384_add(&R,&R1,&R2);
    if(ec384_is_inf(&R)) return 0;

    fp384 rx,ry;
    ec384_to_affine(&rx,&ry,&R);
    uint8_t rx_bytes[48];
    fp384_to_bytes(rx_bytes,&rx);
    bignum rx_bn;
    bn_from_bytes(&rx_bn,rx_bytes,48);
    bn_mod(&rx_bn,&rx_bn,&n);
    return bn_cmp(&rx_bn,&r_bn)==0;
}

/* ECDSA-P256 signature verification */
static int ecdsa_p256_verify(const uint8_t *hash, size_t hash_len,
                              const uint8_t *sig_der, size_t sig_len,
                              const uint8_t *pubkey, size_t pk_len) {
    if(pk_len!=P256_POINT_LEN||pubkey[0]!=0x04) return 0;

    /* Parse DER signature → (r, s) */
    const uint8_t *p=sig_der, *end=sig_der+sig_len;
    size_t len;
    p=der_expect(p,end,0x30,&len);
    if(!p) return 0;
    end=p+len;

    const uint8_t *rval=der_expect(p,end,0x02,&len);
    if(!rval) return 0;
    const uint8_t *rp=rval; size_t rlen=len;
    if(rlen>0&&rp[0]==0){rp++;rlen--;}
    p=rval+len;

    const uint8_t *sval=der_expect(p,end,0x02,&len);
    if(!sval) return 0;
    const uint8_t *sp=sval; size_t slen=len;
    if(slen>0&&sp[0]==0){sp++;slen--;}

    /* Bignum arithmetic on group order n (public data, variable-time OK) */
    bignum r_bn, s_bn, n, hash_bn, w, u1, u2;
    bn_from_bytes(&r_bn,rp,rlen);
    bn_from_bytes(&s_bn,sp,slen);
    bn_from_bytes(&n,P256_ORDER,32);

    /* SEC 1 §4.1.4: verify r,s ∈ [1, n-1] */
    if(bn_is_zero(&r_bn) || bn_cmp(&r_bn,&n)>=0) return 0;
    if(bn_is_zero(&s_bn) || bn_cmp(&s_bn,&n)>=0) return 0;

    bn_from_bytes(&hash_bn,hash,hash_len>32?32:hash_len);

    /* w = s^(-1) mod n via Fermat: s^(n-2) mod n */
    bignum nm2;
    bn_from_bytes(&nm2,P256_ORDER,32);
    bignum two; bn_zero(&two); two.v[0]=2; two.len=1;
    bn_sub(&nm2,&nm2,&two);
    bn_modexp(&w,&s_bn,&nm2,&n);

    /* u1 = hash * w mod n, u2 = r * w mod n */
    bn_modmul(&u1,&hash_bn,&w,&n);
    bn_modmul(&u2,&r_bn,&w,&n);

    uint8_t u1_bytes[32], u2_bytes[32];
    bn_to_bytes(&u1,u1_bytes,32);
    bn_to_bytes(&u2,u2_bytes,32);

    /* R = u1*G + u2*Q using fp256-based EC */
    ec256 G;
    G.x=P256_GX; G.y=P256_GY; G.z=FP256_ONE;

    fp256 qx,qy;
    fp256_from_bytes(&qx,pubkey+1);
    fp256_from_bytes(&qy,pubkey+33);
    ec256 Q; Q.x=qx; Q.y=qy; Q.z=FP256_ONE;

    ec256 R1; ec256_scalar_mul_vartime(&R1,&G,u1_bytes);
    ec256 R2; ec256_scalar_mul_vartime(&R2,&Q,u2_bytes);
    ec256 R;
    if(ec256_is_inf(&R1)) R=R2;
    else if(ec256_is_inf(&R2)) R=R1;
    else ec256_add(&R,&R1,&R2);
    if(ec256_is_inf(&R)) return 0;

    fp256 rx_fp,ry_fp;
    ec256_to_affine(&rx_fp,&ry_fp,&R);
    /* Convert fp256 result to bignum for mod-n comparison */
    uint8_t rx_bytes[32];
    fp256_to_bytes(rx_bytes,&rx_fp);
    bignum rx;
    bn_from_bytes(&rx,rx_bytes,32);
    bn_mod(&rx,&rx,&n);
    return bn_cmp(&rx,&r_bn)==0;
}

/* ================================================================
 * RSA PKCS#1 v1.5 Signature Verification (unified)
 * ================================================================ */
static const uint8_t DI_SHA256[]={
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};
static const uint8_t DI_SHA384[]={
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30
};
static const uint8_t DI_SHA512[]={
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
    0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40
};

static int rsa_pkcs1_verify(const uint8_t *hash, size_t hash_len,
                             const uint8_t *di, size_t di_len,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *modulus, size_t mod_len,
                             const uint8_t *exponent, size_t exp_len) {
    bignum s_bn, n_bn, e_bn, m_bn;
    bn_from_bytes(&s_bn,sig,sig_len);
    bn_from_bytes(&n_bn,modulus,mod_len);
    bn_from_bytes(&e_bn,exponent,exp_len);

    /* Validate RSA public exponent: e >= 3, e is odd */
    if(bn_is_zero(&e_bn) || e_bn.len<1 || e_bn.v[0]<3 || !(e_bn.v[0]&1)) return 0;

    bn_modexp(&m_bn,&s_bn,&e_bn,&n_bn);

    uint8_t m[512];
    if(mod_len>sizeof(m)) return 0;
    bn_to_bytes(&m_bn,m,mod_len);

    if(mod_len < 2+8+1+di_len+hash_len) return 0;
    uint8_t expected[512];
    expected[0]=0x00; expected[1]=0x01;
    size_t pad_len=mod_len-3-di_len-hash_len;
    memset(expected+2,0xFF,pad_len);
    expected[2+pad_len]=0x00;
    memcpy(expected+3+pad_len,di,di_len);
    memcpy(expected+3+pad_len+di_len,hash,hash_len);
    return ct_memeq(m,expected,mod_len);
}

/* ================================================================
 * RSA-PSS Signature Verification (unified)
 * ================================================================ */

static int rsa_pss_verify(const uint8_t *hash, size_t hash_len,
                           hash_fn_t hash_fn,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *modulus, size_t mod_len,
                           const uint8_t *exponent, size_t exp_len) {
    bignum s_bn, n_bn, e_bn, m_bn;
    bn_from_bytes(&s_bn,sig,sig_len);
    bn_from_bytes(&n_bn,modulus,mod_len);
    bn_from_bytes(&e_bn,exponent,exp_len);

    /* Validate RSA public exponent: e >= 3, e is odd */
    if(bn_is_zero(&e_bn) || e_bn.len<1 || e_bn.v[0]<3 || !(e_bn.v[0]&1)) return 0;

    bn_modexp(&m_bn,&s_bn,&e_bn,&n_bn);

    uint8_t em[512];
    if(mod_len>sizeof(em)) return 0;
    bn_to_bytes(&m_bn,em,mod_len);

    size_t em_len=mod_len;
    if(em[em_len-1]!=0xBC) return 0;

    size_t salt_len=hash_len;
    /* RFC 8017 §9.1.2: emLen must be at least hLen + sLen + 2 */
    if(em_len < hash_len + salt_len + 2) return 0;
    size_t db_len=em_len-hash_len-1;
    const uint8_t *masked_db=em;
    const uint8_t *h=em+db_len;

    /* MGF1: dbMask = MGF1(H, db_len) */
    uint8_t db_mask[512];
    size_t done=0;
    uint32_t counter=0;
    while(done<db_len){
        uint8_t cb[52]; /* max: 48 + 4 */
        memcpy(cb,h,hash_len);
        cb[hash_len]=(uint8_t)((counter>>24)&0xFF);
        cb[hash_len+1]=(uint8_t)((counter>>16)&0xFF);
        cb[hash_len+2]=(uint8_t)((counter>>8)&0xFF);
        cb[hash_len+3]=counter&0xFF;
        uint8_t md[48];
        hash_fn(cb,hash_len+4,md);
        size_t use=db_len-done; if(use>hash_len) use=hash_len;
        memcpy(db_mask+done,md,use);
        done+=use; counter++;
    }

    uint8_t db[512] = {0}; /* zero-init silences false-positive uninitialized-read warning */
    for(size_t i=0;i<db_len;i++) db[i]=masked_db[i]^db_mask[i];
    db[0]&=0x7F;

    size_t pad_len=db_len-salt_len-1;
    uint8_t pad_ok=0;
    for(size_t i=0;i<pad_len;i++) pad_ok|=db[i];
    pad_ok|=db[pad_len]^0x01;
    const uint8_t *salt=db+pad_len+1;

    uint8_t mp[8+48+48]; /* max: 8 + 48 + 48 */
    memset(mp,0,8);
    memcpy(mp+8,hash,hash_len);
    memcpy(mp+8+hash_len,salt,salt_len);

    uint8_t hp[48];
    hash_fn(mp,8+hash_len+salt_len,hp);
    int pad_valid = (pad_ok == 0);
    return ct_memeq(hp,h,hash_len) & pad_valid;
}

/* ================================================================
 * RSA PKCS#1 v1.5 Type 2 Encryption (for RSA key transport)
 * ================================================================ */
static int rsa_encrypt(const uint8_t *pt, size_t pt_len,
                        const uint8_t *modulus, size_t mod_len,
                        const uint8_t *exponent, size_t exp_len,
                        uint8_t *ct) {
    if(mod_len < pt_len+11) return -1; /* need at least 8 bytes padding + 3 overhead */
    uint8_t em[512];
    if(mod_len>sizeof(em)) return -1;
    em[0]=0x00; em[1]=0x02;
    size_t pad_len=mod_len-pt_len-3;
    /* Fill padding with random non-zero bytes */
    random_bytes(em+2,pad_len);
    for(size_t i=0;i<pad_len;i++){
        while(em[2+i]==0) random_bytes(em+2+i,1);
    }
    em[2+pad_len]=0x00;
    memcpy(em+3+pad_len,pt,pt_len);

    bignum msg_bn, n_bn, e_bn, ct_bn;
    bn_from_bytes(&msg_bn,em,mod_len);
    bn_from_bytes(&n_bn,modulus,mod_len);
    bn_from_bytes(&e_bn,exponent,exp_len);
    bn_modexp(&ct_bn,&msg_bn,&e_bn,&n_bn);
    bn_to_bytes(&ct_bn,ct,mod_len);
    return 0;
}

/* OID constants */
static const uint8_t OID_ECDSA_SHA384[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03};
static const uint8_t OID_ECDSA_SHA256[] = {0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02};
static const uint8_t OID_SHA256_RSA[]   = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B};
static const uint8_t OID_SHA384_RSA[]   = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C};
static const uint8_t OID_SHA512_RSA[]   = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D};
static const uint8_t OID_EC_PUBKEY[]    = {0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01};
static const uint8_t OID_RSA_ENC[]      = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01};
static const uint8_t OID_SAN[]          = {0x55,0x1D,0x11};
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55,0x1D,0x13};
static const uint8_t OID_KEY_USAGE[]    = {0x55,0x1D,0x0F};
static const uint8_t OID_EXT_KEY_USAGE[]= {0x55,0x1D,0x25};
static const uint8_t OID_SERVER_AUTH[]  = {0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01};
static const uint8_t OID_AIA[]         = {0x2B,0x06,0x01,0x05,0x05,0x07,0x01,0x01};
static const uint8_t OID_CA_ISSUERS[]  = {0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02};
static const uint8_t OID_NAME_CONSTRAINTS[]   = {0x55,0x1D,0x1E};
static const uint8_t OID_POLICY_CONSTRAINTS[] = {0x55,0x1D,0x24};
static const uint8_t OID_SCT_LIST[] = {0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x04,0x02};
static const uint8_t OID_CRL_DIST_POINTS[] = {0x55,0x1D,0x1F};
static const uint8_t OID_ED25519[]  = {0x2B,0x65,0x70}; /* 1.3.101.112 */
static const uint8_t OID_ED448[]    = {0x2B,0x65,0x71}; /* 1.3.101.113 */

#include "ct_log_table.inc"

/* ================================================================
 * X.509 Certificate Parser
 * ================================================================ */
typedef struct {
    const uint8_t *tbs; size_t tbs_len;           /* raw TBS for hashing */
    const uint8_t *sig_alg; size_t sig_alg_len;   /* signature algorithm OID */
    const uint8_t *sig; size_t sig_len;            /* signature bytes */
    const uint8_t *issuer; size_t issuer_len;      /* raw DER of issuer Name */
    const uint8_t *subject; size_t subject_len;    /* raw DER of subject Name */
    const uint8_t *pubkey; size_t pubkey_len;      /* EC: 04||x||y */
    const uint8_t *rsa_n; size_t rsa_n_len;        /* RSA modulus */
    const uint8_t *rsa_e; size_t rsa_e_len;        /* RSA exponent */
    const uint8_t *san; size_t san_len;            /* SAN extension value */
    const uint8_t *aia_url; size_t aia_url_len;    /* caIssuers HTTP URL */
    const uint8_t *name_constraints; size_t name_constraints_len;
    time_t not_before, not_after;                  /* validity period */
    int key_type;                                   /* 1=EC, 2=RSA */
    int is_ca;                                      /* basicConstraints CA flag */
    int path_len;                                   /* pathLenConstraint (-1 = unlimited) */
    int has_key_usage;                              /* whether keyUsage extension was present */
    int has_eku;                                    /* whether EKU extension was present */
    int eku_server_auth;                            /* EKU contains serverAuth */
    int version;                                    /* 0=v1, 1=v2, 2=v3 */
    uint16_t key_usage;                             /* keyUsage bit flags (0 = not present) */
    const uint8_t *sct_list; size_t sct_list_len;   /* SCT list extension value */
    const uint8_t *spki; size_t spki_len;            /* raw DER SubjectPublicKeyInfo */
    const uint8_t *serial; size_t serial_len;        /* raw DER INTEGER (tag+len+value) */
    const uint8_t *crl_dp_url; size_t crl_dp_url_len; /* first HTTP CRL distribution point */
} x509_cert;

static int parse_x509_extensions(x509_cert *cert, const uint8_t *tp, const uint8_t *tbs_end) {
    uint8_t tag; size_t len;
    if(tp>=tbs_end||*tp!=0xA3) return 0;
    const uint8_t *ext_outer=der_read_tl(tp,tbs_end,&tag,&len);
    if(!ext_outer) return 0;
    const uint8_t *exts_val=der_expect(ext_outer,ext_outer+len,0x30,&len);
    if(!exts_val) return 0;
    const uint8_t *ep=exts_val, *exts_end=exts_val+len;
    #define MAX_EXT_OIDS 20
    struct { const uint8_t *oid; size_t len; } seen_oids[MAX_EXT_OIDS];
    int seen_count=0;
    while(ep<exts_end){
        const uint8_t *ext_seq=der_expect(ep,exts_end,0x30,&len);
        if(!ext_seq) break;
        const uint8_t *ext_end2=ext_seq+len;
        ep=ext_end2;
        const uint8_t *eoid=der_expect(ext_seq,ext_end2,0x06,&len);
        if(!eoid) continue;
        /* RFC 5280 §4.2: each extension OID must be unique */
        for(int si=0;si<seen_count;si++){
            if(seen_oids[si].len==len && memcmp(seen_oids[si].oid,eoid,len)==0)
                return -1;
        }
        if(seen_count<MAX_EXT_OIDS){
            seen_oids[seen_count].oid=eoid;
            seen_oids[seen_count].len=len;
            seen_count++;
        }
        if(oid_eq(eoid,len,OID_SAN,sizeof(OID_SAN))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){cert->san=oct;cert->san_len=len;}
        } else if(oid_eq(eoid,len,OID_BASIC_CONSTRAINTS,sizeof(OID_BASIC_CONSTRAINTS))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){
                const uint8_t *oct_end=oct+len;
                const uint8_t *sq=der_read_tl(oct,oct_end,&tag,&len);
                if(sq&&tag==0x30){
                    const uint8_t *sq_end=sq+len;
                    const uint8_t *bp=sq;
                    if(bp<sq_end&&*bp==0x01){
                        const uint8_t *bv=der_read_tl(bp,sq_end,&tag,&len);
                        if(bv&&tag==0x01&&len==1&&bv[0]!=0)
                            cert->is_ca=1;
                        if(bv) bp=bv+len;
                    }
                    if(bp<sq_end&&*bp==0x02){
                        const uint8_t *pv=der_read_tl(bp,sq_end,&tag,&len);
                        if(pv&&tag==0x02&&len>=1){
                            int pl=0;
                            for(size_t j=0;j<len;j++) pl=(pl<<8)|pv[j];
                            cert->path_len=pl;
                        }
                    }
                }
            }
        } else if(oid_eq(eoid,len,OID_KEY_USAGE,sizeof(OID_KEY_USAGE))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){
                const uint8_t *bs=der_read_tl(oct,oct+len,&tag,&len);
                if(bs&&tag==0x03&&len>=2){
                    cert->has_key_usage=1;
                    cert->key_usage=bs[1];
                    if(len>=3) cert->key_usage|=((uint16_t)bs[2]<<8);
                }
            }
        } else if(oid_eq(eoid,len,OID_EXT_KEY_USAGE,sizeof(OID_EXT_KEY_USAGE))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){
                const uint8_t *sq=der_read_tl(oct,oct+len,&tag,&len);
                if(sq&&tag==0x30){
                    const uint8_t *sq_end=sq+len;
                    cert->has_eku=1;
                    while(sq<sq_end){
                        const uint8_t *eo=der_read_tl(sq,sq_end,&tag,&len);
                        if(!eo||tag!=0x06) break;
                        if(oid_eq(eo,len,OID_SERVER_AUTH,sizeof(OID_SERVER_AUTH)))
                            cert->eku_server_auth=1;
                        sq=eo+len;
                    }
                }
            }
        } else if(oid_eq(eoid,len,OID_AIA,sizeof(OID_AIA))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){
                const uint8_t *sq=der_read_tl(oct,oct+len,&tag,&len);
                if(sq&&tag==0x30){
                    const uint8_t *sq_end=sq+len;
                    while(sq<sq_end){
                        const uint8_t *ad=der_read_tl(sq,sq_end,&tag,&len);
                        if(!ad||tag!=0x30) break;
                        const uint8_t *ad_end=ad+len;
                        sq=ad_end;
                        const uint8_t *moid=der_read_tl(ad,ad_end,&tag,&len);
                        if(!moid||tag!=0x06) continue;
                        if(!oid_eq(moid,len,OID_CA_ISSUERS,sizeof(OID_CA_ISSUERS)))
                            continue;
                        const uint8_t *loc=moid+len;
                        if(loc<ad_end&&*loc==0x86){
                            const uint8_t *url=der_read_tl(loc,ad_end,&tag,&len);
                            if(url&&tag==0x86&&len>7&&
                               memcmp(url,"http://",7)==0){
                                cert->aia_url=url;
                                cert->aia_url_len=len;
                            }
                        }
                    }
                }
            }
        } else if(oid_eq(eoid,len,OID_NAME_CONSTRAINTS,sizeof(OID_NAME_CONSTRAINTS))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){cert->name_constraints=oct;cert->name_constraints_len=len;}
        } else if(oid_eq(eoid,len,OID_POLICY_CONSTRAINTS,sizeof(OID_POLICY_CONSTRAINTS))){
            /* Recognized to avoid critical-extension rejection; not enforced */
            (void)0;
        } else if(oid_eq(eoid,len,OID_SCT_LIST,sizeof(OID_SCT_LIST))){
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){cert->sct_list=oct;cert->sct_list_len=len;}
        } else if(oid_eq(eoid,len,OID_CRL_DIST_POINTS,sizeof(OID_CRL_DIST_POINTS))){
            /* CRL Distribution Points: SEQUENCE OF DistributionPoint
             * DistributionPoint ::= SEQUENCE { distributionPoint [0] { fullName [0] GeneralNames } }
             * GeneralName ::= uniformResourceIdentifier [6] IA5String */
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01) rest=der_skip(rest,ext_end2);
            const uint8_t *oct=der_read_tl(rest,ext_end2,&tag,&len);
            if(oct&&tag==0x04){
                /* OCTET STRING wraps SEQUENCE OF DistributionPoint */
                const uint8_t *sq=der_expect(oct,oct+len,0x30,&len);
                if(sq){
                    const uint8_t *sq_end=sq+len;
                    while(sq<sq_end&&!cert->crl_dp_url){
                        /* DistributionPoint SEQUENCE */
                        const uint8_t *dp=der_read_tl(sq,sq_end,&tag,&len);
                        if(!dp||tag!=0x30) break;
                        const uint8_t *dp_end=dp+len;
                        sq=dp_end;
                        /* distributionPoint [0] EXPLICIT */
                        if(dp<dp_end&&*dp==0xA0){
                            const uint8_t *dpn=der_read_tl(dp,dp_end,&tag,&len);
                            if(dpn&&tag==0xA0){
                                const uint8_t *dpn_end=dpn+len;
                                /* fullName [0] EXPLICIT -> GeneralNames */
                                if(dpn<dpn_end&&*dpn==0xA0){
                                    const uint8_t *fn=der_read_tl(dpn,dpn_end,&tag,&len);
                                    if(fn&&tag==0xA0){
                                        const uint8_t *fn_end=fn+len;
                                        /* Find uniformResourceIdentifier [6] */
                                        const uint8_t *gn=fn;
                                        while(gn<fn_end){
                                            const uint8_t *gv=der_read_tl(gn,fn_end,&tag,&len);
                                            if(!gv) break;
                                            if(tag==0x86&&len>7&&
                                               memcmp(gv,"http://",7)==0){
                                                cert->crl_dp_url=gv;
                                                cert->crl_dp_url_len=len;
                                                break;
                                            }
                                            gn=gv+len;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            /* RFC 5280 §4.2: reject unrecognized critical extensions */
            const uint8_t *rest=eoid+len;
            if(rest<ext_end2&&*rest==0x01){
                const uint8_t *cv=der_read_tl(rest,ext_end2,&tag,&len);
                if(cv&&tag==0x01&&len==1&&cv[0]!=0)
                    return -1;
            }
        }
    }
    return 0;
}

static int x509_parse(x509_cert *cert, const uint8_t *der, size_t der_len) {
    memset(cert,0,sizeof(*cert));
    cert->path_len=-1; /* unlimited by default */
    const uint8_t *p=der, *end=der+der_len;
    uint8_t tag; size_t len;

    /* Certificate SEQUENCE */
    p=der_expect(p,end,0x30,&len);
    if(!p) return -1;
    const uint8_t *cert_end=p+len;

    /* TBSCertificate — save raw bytes including tag+length */
    const uint8_t *tbs_start=p;
    const uint8_t *tbs_val=der_expect(p,cert_end,0x30,&len);
    if(!tbs_val) return -1;
    cert->tbs=tbs_start;
    cert->tbs_len=(size_t)((tbs_val+len)-tbs_start);
    const uint8_t *tbs_end=tbs_val+len;
    const uint8_t *tp=tbs_val;

    /* [0] version — default v1 (0) if absent */
    if(tp<tbs_end&&*tp==0xA0){
        const uint8_t *v_outer=der_read_tl(tp,tbs_end,&tag,&len);
        if(!v_outer) return -1;
        const uint8_t *v_end=v_outer+len;
        const uint8_t *vp=der_read_tl(v_outer,v_end,&tag,&len);
        if(vp&&tag==0x02&&len==1) cert->version=vp[0];
        tp=v_end;
    }
    /* serialNumber */
    cert->serial=tp;
    tp=der_skip(tp,tbs_end); if(!tp) return -1;
    cert->serial_len=(size_t)(tp-cert->serial);
    /* signature AlgorithmIdentifier */
    tp=der_skip(tp,tbs_end); if(!tp) return -1;

    /* issuer Name */
    const uint8_t *issuer_start=tp;
    tp=der_skip(tp,tbs_end); if(!tp) return -1;
    cert->issuer=issuer_start;
    cert->issuer_len=(size_t)(tp-issuer_start);

    /* validity */
    {
        const uint8_t *vld=der_expect(tp,tbs_end,0x30,&len);
        if(!vld) return -1;
        const uint8_t *vld_end=vld+len;
        cert->not_before=der_parse_time(vld,vld_end);
        const uint8_t *after_nb=der_skip(vld,vld_end);
        cert->not_after=der_parse_time(after_nb,vld_end);
        tp=vld_end;
    }

    /* subject Name */
    const uint8_t *subj_start=tp;
    tp=der_skip(tp,tbs_end); if(!tp) return -1;
    cert->subject=subj_start;
    cert->subject_len=(size_t)(tp-subj_start);

    /* SubjectPublicKeyInfo */
    const uint8_t *spki_start=tp;
    const uint8_t *spki_val=der_expect(tp,tbs_end,0x30,&len);
    if(!spki_val) return -1;
    const uint8_t *spki_end=spki_val+len;
    tp=spki_end;
    cert->spki=spki_start;
    cert->spki_len=(size_t)(spki_end-spki_start);

    /* AlgorithmIdentifier inside SPKI */
    const uint8_t *alg_val=der_expect(spki_val,spki_end,0x30,&len);
    if(!alg_val) return -1;
    const uint8_t *alg_end=alg_val+len;

    const uint8_t *pk_oid=der_expect(alg_val,alg_end,0x06,&len);
    if(!pk_oid) return -1;
    int is_ec=oid_eq(pk_oid,len,OID_EC_PUBKEY,sizeof(OID_EC_PUBKEY));
    int is_rsa=oid_eq(pk_oid,len,OID_RSA_ENC,sizeof(OID_RSA_ENC));
    int is_ed25519=oid_eq(pk_oid,len,OID_ED25519,sizeof(OID_ED25519));
    int is_ed448=oid_eq(pk_oid,len,OID_ED448,sizeof(OID_ED448));

    /* BIT STRING with public key follows AlgorithmIdentifier */
    const uint8_t *bs_val=der_read_tl(alg_end,spki_end,&tag,&len);
    if(!bs_val||tag!=0x03||len<2) return -1;

    if(is_ed25519){
        cert->key_type=3;
        cert->pubkey=bs_val+1; /* skip unused-bits byte */
        cert->pubkey_len=len-1;
    } else if(is_ed448){
        cert->key_type=3;
        cert->pubkey=bs_val+1;
        cert->pubkey_len=len-1;
    } else if(is_ec){
        cert->key_type=1;
        cert->pubkey=bs_val+1; /* skip unused-bits byte */
        cert->pubkey_len=len-1;
    } else if(is_rsa){
        cert->key_type=2;
        const uint8_t *rsa_p=bs_val+1, *rsa_end2=bs_val+len;
        const uint8_t *rsa_seq=der_expect(rsa_p,rsa_end2,0x30,&len);
        if(!rsa_seq) return -1;
        const uint8_t *rsa_seq_end=rsa_seq+len;
        /* INTEGER n */
        const uint8_t *nv=der_expect(rsa_seq,rsa_seq_end,0x02,&len);
        if(!nv) return -1;
        cert->rsa_n=nv; cert->rsa_n_len=len;
        if(cert->rsa_n_len>0&&cert->rsa_n[0]==0){cert->rsa_n++;cert->rsa_n_len--;}
        /* INTEGER e */
        const uint8_t *ev=der_expect(nv+len,rsa_seq_end,0x02,&len);
        if(!ev) return -1;
        cert->rsa_e=ev; cert->rsa_e_len=len;
        if(cert->rsa_e_len>0&&cert->rsa_e[0]==0){cert->rsa_e++;cert->rsa_e_len--;}
    }

    /* Extensions [3] */
    if(parse_x509_extensions(cert,tp,tbs_end)<0) return -1;

    /* signatureAlgorithm (after TBS) */
    p=cert->tbs+cert->tbs_len;
    const uint8_t *sa_seq=der_expect(p,cert_end,0x30,&len);
    if(!sa_seq) return -1;
    const uint8_t *sa_end=sa_seq+len;
    const uint8_t *sa_oid=der_expect(sa_seq,sa_end,0x06,&len);
    if(!sa_oid) return -1;
    cert->sig_alg=sa_oid; cert->sig_alg_len=len;

    /* signatureValue BIT STRING */
    p=sa_end;
    const uint8_t *sv=der_read_tl(p,cert_end,&tag,&len);
    if(!sv||tag!=0x03||len<2) return -1;
    cert->sig=sv+1; cert->sig_len=len-1;
    return 0;
}

/* ================================================================
 * Hostname Verification (SAN + CN fallback)
 * ================================================================ */
static int dns_name_eq(const uint8_t *a, size_t alen, const char *b, size_t blen) {
    if(alen!=blen) return 0;
    for(size_t i=0;i<alen;i++){
        uint8_t ca=a[i], cb=(uint8_t)b[i];
        if(ca>='A'&&ca<='Z') ca+=32;
        if(cb>='A'&&cb<='Z') cb+=32;
        if(ca!=cb) return 0;
    }
    return 1;
}

static int wildcard_match(const uint8_t *pat, size_t plen, const char *hostname) {
    /* pattern must be *.something.tld (at least 2 dots in pattern) */
    if(plen<4||pat[0]!='*'||pat[1]!='.') return 0;
    int dots=0;
    for(size_t i=0;i<plen;i++) if(pat[i]=='.') dots++;
    if(dots<2) return 0;
    const char *dot=strchr(hostname,'.');
    if(!dot) return 0;
    return dns_name_eq(pat+2,plen-2,dot+1,strlen(dot+1));
}

static int verify_hostname(const x509_cert *cert, const char *hostname) {
    size_t hn_len=strlen(hostname);
    uint8_t tag; size_t len;

    if(cert->san&&cert->san_len>0){
        const uint8_t *p=cert->san, *end=cert->san+cert->san_len;
        int has_dns_name=0;
        p=der_read_tl(p,end,&tag,&len);
        if(p&&tag==0x30){
            end=p+len;
            while(p<end){
                const uint8_t *val=der_read_tl(p,end,&tag,&len);
                if(!val) break;
                if(tag==0x82){ /* dNSName */
                    has_dns_name=1;
                    if(dns_name_eq(val,len,hostname,hn_len)) return 1;
                    if(wildcard_match(val,len,hostname)) return 1;
                }
                p=val+len;
            }
        }
        /* RFC 6125 §6.4.4: if SAN has dNSName entries, don't fall back to CN */
        if(has_dns_name) return 0;
    }
    /* CN fallback */
    static const uint8_t OID_CN[]={0x55,0x04,0x03};
    const uint8_t *p=cert->subject, *end=cert->subject+cert->subject_len;
    p=der_expect(p,end,0x30,&len);
    if(!p) return 0;
    end=p+len;
    while(p<end){
        const uint8_t *set_val=der_expect(p,end,0x31,&len);
        if(!set_val) break;
        p=set_val+len;
        const uint8_t *seq_val=der_expect(set_val,set_val+len,0x30,&len);
        if(!seq_val) continue;
        const uint8_t *seq_end=seq_val+len;
        const uint8_t *ov=der_expect(seq_val,seq_end,0x06,&len);
        if(!ov) continue;
        if(oid_eq(ov,len,OID_CN,sizeof(OID_CN))){
            const uint8_t *cv=der_read_tl(ov+len,seq_end,&tag,&len);
            if(cv&&dns_name_eq(cv,len,hostname,hn_len)) return 1;
        }
    }
    return 0;
}

/* ================================================================
 * Trust Store Loader
 * ================================================================ */
#define MAX_TRUST_CERTS 200

typedef struct {
    uint8_t subject[512]; size_t subject_len;
    int key_type;
    uint8_t pubkey[128]; size_t pubkey_len;   /* EC point */
    uint8_t rsa_n[520]; size_t rsa_n_len;     /* RSA modulus */
    uint8_t rsa_e[16]; size_t rsa_e_len;      /* RSA exponent */
    uint8_t spki_hash[32];                    /* SHA-256 of DER SPKI, for CT issuer_key_hash */
} trust_cert;

static trust_cert trust_store[MAX_TRUST_CERTS];
static int trust_store_count=0;

static void load_trust_store(const char *dir) {
    DIR *d=opendir(dir);
    if(!d){fprintf(stderr,"Warning: cannot open %s\n",dir);return;}
    const struct dirent *ent;
    uint8_t der_buf[4096];
    char pem_buf[8192];
    while((ent=readdir(d))!=NULL&&trust_store_count<MAX_TRUST_CERTS){
        size_t nl=strlen(ent->d_name);
        if(nl<4||strcmp(ent->d_name+nl-4,".crt")!=0) continue;
        char path[PATH_MAX];
        if(snprintf(path,sizeof(path),"%s/%s",dir,ent->d_name)>=(int)sizeof(path)) continue;
        FILE *f=fopen(path,"r");
        if(!f) continue;
        size_t pem_len=fread(pem_buf,1,sizeof(pem_buf)-1,f);
        fclose(f);
        pem_buf[pem_len]=0;
        size_t der_len=pem_to_der(pem_buf,pem_len,der_buf);
        if(der_len==0||der_len>sizeof(der_buf)) continue;
        x509_cert cert;
        if(x509_parse(&cert,der_buf,der_len)!=0) continue;
        trust_cert *tc=&trust_store[trust_store_count];
        memset(tc,0,sizeof(*tc));
        if(cert.subject_len>sizeof(tc->subject)) continue;
        memcpy(tc->subject,cert.subject,cert.subject_len);
        tc->subject_len=cert.subject_len;
        tc->key_type=cert.key_type;
        if((cert.key_type==1||cert.key_type==3)&&cert.pubkey_len<=sizeof(tc->pubkey)){
            memcpy(tc->pubkey,cert.pubkey,cert.pubkey_len);
            tc->pubkey_len=cert.pubkey_len;
        } else if(cert.key_type==2){
            if(cert.rsa_n_len<=sizeof(tc->rsa_n)){
                memcpy(tc->rsa_n,cert.rsa_n,cert.rsa_n_len);
                tc->rsa_n_len=cert.rsa_n_len;
            }
            if(cert.rsa_e_len<=sizeof(tc->rsa_e)){
                memcpy(tc->rsa_e,cert.rsa_e,cert.rsa_e_len);
                tc->rsa_e_len=cert.rsa_e_len;
            }
        }
        if(cert.spki && cert.spki_len > 0)
            sha256_hash(cert.spki, cert.spki_len, tc->spki_hash);
        trust_store_count++;
    }
    closedir(d);
    if(tls_verbose) fprintf(stderr,"Loaded %d trust store certificates\n",trust_store_count);
}

/* Unified signature verification dispatch */
static int verify_signature(const uint8_t *tbs, size_t tbs_len,
                             const uint8_t *sig_alg, size_t sig_alg_len,
                             const uint8_t *sig, size_t sig_len,
                             int key_type,
                             const uint8_t *pubkey, size_t pubkey_len,
                             const uint8_t *rsa_n, size_t rsa_n_len,
                             const uint8_t *rsa_e, size_t rsa_e_len) {
    /* For ECDSA the OID specifies only the hash; the curve is determined
       by the signing key, not the algorithm identifier. */
    if(oid_eq(sig_alg,sig_alg_len,OID_ECDSA_SHA384,sizeof(OID_ECDSA_SHA384))){
        if(key_type!=1) return 0;
        uint8_t h[48]; sha384_hash(tbs,tbs_len,h);
        if(pubkey_len==P256_POINT_LEN)
            return ecdsa_p256_verify(h,SHA384_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
        if(pubkey_len==P384_POINT_LEN)
            return ecdsa_p384_verify(h,SHA384_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
        return 0;
    }
    if(oid_eq(sig_alg,sig_alg_len,OID_ECDSA_SHA256,sizeof(OID_ECDSA_SHA256))){
        if(key_type!=1) return 0;
        uint8_t h[32]; sha256_hash(tbs,tbs_len,h);
        if(pubkey_len==P256_POINT_LEN)
            return ecdsa_p256_verify(h,SHA256_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
        if(pubkey_len==P384_POINT_LEN)
            return ecdsa_p384_verify(h,SHA256_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
        return 0;
    }
    if(oid_eq(sig_alg,sig_alg_len,OID_SHA256_RSA,sizeof(OID_SHA256_RSA))){
        if(key_type!=2) return 0;
        uint8_t h[32]; sha256_hash(tbs,tbs_len,h);
        return rsa_pkcs1_verify(h,SHA256_DIGEST_LEN,DI_SHA256,sizeof(DI_SHA256),
            sig,sig_len,rsa_n,rsa_n_len,rsa_e,rsa_e_len);
    }
    if(oid_eq(sig_alg,sig_alg_len,OID_SHA384_RSA,sizeof(OID_SHA384_RSA))){
        if(key_type!=2) return 0;
        uint8_t h[48]; sha384_hash(tbs,tbs_len,h);
        return rsa_pkcs1_verify(h,SHA384_DIGEST_LEN,DI_SHA384,sizeof(DI_SHA384),
            sig,sig_len,rsa_n,rsa_n_len,rsa_e,rsa_e_len);
    }
    if(oid_eq(sig_alg,sig_alg_len,OID_SHA512_RSA,sizeof(OID_SHA512_RSA))){
        if(key_type!=2) return 0;
        uint8_t h[64]; sha512_hash(tbs,tbs_len,h);
        return rsa_pkcs1_verify(h,64,DI_SHA512,sizeof(DI_SHA512),
            sig,sig_len,rsa_n,rsa_n_len,rsa_e,rsa_e_len);
    }
    /* Ed25519: pure signature, no separate hash */
    if(oid_eq(sig_alg,sig_alg_len,OID_ED25519,sizeof(OID_ED25519))){
        if(key_type!=3||pubkey_len!=32||sig_len!=ED25519_SIG_LEN) return 0;
        return ed25519_verify(pubkey,tbs,tbs_len,sig);
    }
    /* Ed448: pure signature, no separate hash */
    if(oid_eq(sig_alg,sig_alg_len,OID_ED448,sizeof(OID_ED448))){
        if(key_type!=3||pubkey_len!=57||sig_len!=ED448_SIG_LEN) return 0;
        return ed448_verify(pubkey,tbs,tbs_len,sig);
    }
    return 0;
}

/* Validate leaf certificate: hostname, EKU, keyUsage */
static int validate_leaf_cert(const x509_cert *leaf, const char *hostname) {
    if(!verify_hostname(leaf,hostname)){
        fprintf(stderr,"Hostname verification failed for %s\n",hostname);
        return -1;
    }
    if(tls_verbose) fprintf(stderr,"    Hostname verified: %s\n",hostname);
    if(leaf->has_eku && !leaf->eku_server_auth){
        fprintf(stderr,"Leaf certificate EKU does not include serverAuth\n");
        return -1;
    }
    if(leaf->has_key_usage && !(leaf->key_usage & 0x80)){
        fprintf(stderr,"Leaf certificate keyUsage missing digitalSignature\n");
        return -1;
    }
    return 0;
}

/* ================================================================
 * HTTP Fetcher (shared by AIA and CRL)
 * ================================================================ */
static int http_fetch(const uint8_t *url, size_t url_len, int timeout_s,
                      uint8_t **out, size_t *out_len) {
    /* Parse URL: skip "http://" prefix, extract host and path */
    if(url_len<=7) return -1;
    const uint8_t *hp=url+7;
    size_t hp_len=url_len-7;
    /* Find path separator */
    size_t host_len=hp_len;
    const uint8_t *path=(const uint8_t *)"/";
    size_t path_len=1;
    for(size_t i=0;i<hp_len;i++){
        if(hp[i]=='/'){
            host_len=i;
            path=hp+i;
            path_len=hp_len-i;
            break;
        }
    }
    if(host_len==0||host_len>=256) return -1;
    char host[256];
    memcpy(host,hp,host_len);
    host[host_len]='\0';

    /* Connect to HTTP server */
    struct addrinfo hints={0}, *res;
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,"80",&hints,&res)!=0) return -1;
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(fd<0){ freeaddrinfo(res); return -1; }
    struct timeval tv={timeout_s,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    if(connect(fd,res->ai_addr,res->ai_addrlen)<0){
        freeaddrinfo(res); close(fd); return -1;
    }
    freeaddrinfo(res);

    /* Send HTTP/1.0 GET request */
    char req[512];
    int rlen=snprintf(req,sizeof(req),
        "GET %.*s HTTP/1.0\r\nHost: %s\r\n\r\n",
        (int)path_len,path,host);
    if(rlen<0||rlen>=(int)sizeof(req)){ close(fd); return -1; }
    if(write_all(fd,(const uint8_t *)req,(size_t)rlen)<0){ close(fd); return -1; }

    /* Read entire response into dynamic buffer */
    size_t total=0, cap=4096;
    uint8_t *buf=malloc(cap);
    if(!buf){ close(fd); return -1; }
    for(;;){
        if(total==cap){
            cap*=2;
            uint8_t *nb=realloc(buf,cap);
            if(!nb){ free(buf); close(fd); return -1; }
            buf=nb;
        }
        ssize_t n=read(fd,buf+total,cap-total);
        if(n<=0) break;
        total+=(size_t)n;
    }
    close(fd);
    if(total==0){ free(buf); return -1; }

    /* Skip HTTP headers: find \r\n\r\n */
    size_t hdr_end=0;
    for(size_t i=0;i+3<total;i++){
        if(buf[i]=='\r'&&buf[i+1]=='\n'&&
           buf[i+2]=='\r'&&buf[i+3]=='\n'){
            hdr_end=i+4;
            break;
        }
    }
    if(!hdr_end){ free(buf); return -1; }
    size_t body_len=total-hdr_end;
    if(body_len==0){ free(buf); return -1; }

    /* Shift body to start of buffer so caller owns a single allocation */
    memmove(buf,buf+hdr_end,body_len);
    *out=buf;
    *out_len=body_len;
    return 0;
}

static int http_fetch_der(const uint8_t *url, size_t url_len,
                           uint8_t **out, size_t *out_len) {
    return http_fetch(url,url_len,AIA_READ_TIMEOUT_S,out,out_len);
}

/* DNS name constraint matching per RFC 5280 §4.2.1.10:
 * Constraint "example.com" matches "example.com" exactly and any subdomain
 * like "foo.example.com". Comparison is case-insensitive. */
static int dns_name_matches_constraint(const char *name, size_t name_len,
                                        const uint8_t *constraint, size_t cons_len) {
    if(cons_len==0) return 0;
    /* Leading dot in constraint means subdomain-only (strip it for matching) */
    if(constraint[0]=='.'){constraint++;cons_len--;}
    if(cons_len==0) return 0;
    /* Exact match */
    if(name_len==cons_len){
        for(size_t i=0;i<name_len;i++){
            uint8_t a=(uint8_t)name[i], b=constraint[i];
            if(a>='A'&&a<='Z') a+=32;
            if(b>='A'&&b<='Z') b+=32;
            if(a!=b) return 0;
        }
        return 1;
    }
    /* Subdomain match: name must end with ".constraint" */
    if(name_len>cons_len+1&&name[name_len-cons_len-1]=='.'){
        const char *suffix=name+(name_len-cons_len);
        for(size_t i=0;i<cons_len;i++){
            uint8_t a=(uint8_t)suffix[i], b=constraint[i];
            if(a>='A'&&a<='Z') a+=32;
            if(b>='A'&&b<='Z') b+=32;
            if(a!=b) return 0;
        }
        return 1;
    }
    return 0;
}

static int check_name_constraints(const x509_cert *ca, const x509_cert *leaf,
                                   const char *hostname) {
    if(!ca->name_constraints||ca->name_constraints_len==0) return 0;
    uint8_t tag; size_t len;
    const uint8_t *p=ca->name_constraints;
    const uint8_t *nc_end=p+ca->name_constraints_len;

    /* NameConstraints ::= SEQUENCE { permittedSubtrees [0], excludedSubtrees [1] } */
    const uint8_t *seq=der_expect(p,nc_end,0x30,&len);
    if(!seq) return -1;
    const uint8_t *seq_end=seq+len;
    const uint8_t *sp=seq;

    /* Collect permitted and excluded dNSName constraints */
    #define MAX_NC_NAMES 16
    struct { const uint8_t *name; size_t len; } permitted[MAX_NC_NAMES], excluded[MAX_NC_NAMES];
    int n_permitted=0, n_excluded=0;

    while(sp<seq_end){
        const uint8_t *sub=der_read_tl(sp,seq_end,&tag,&len);
        if(!sub) break;
        const uint8_t *sub_end=sub+len;
        sp=sub_end;
        int is_permitted=(tag==0xA0);
        int is_excluded=(tag==0xA1);
        if(!is_permitted&&!is_excluded) continue;
        /* Parse GeneralSubtrees: SEQUENCE OF GeneralSubtree */
        const uint8_t *gp=sub;
        while(gp<sub_end){
            const uint8_t *gs=der_read_tl(gp,sub_end,&tag,&len);
            if(!gs||tag!=0x30) break;
            const uint8_t *gs_end=gs+len;
            gp=gs_end;
            /* GeneralSubtree.base is a GeneralName; dNSName = tag 0x82 */
            const uint8_t *base=der_read_tl(gs,gs_end,&tag,&len);
            if(!base) continue;
            if(tag==0x82){ /* dNSName */
                if(is_permitted&&n_permitted<MAX_NC_NAMES){
                    permitted[n_permitted].name=base;
                    permitted[n_permitted].len=len;
                    n_permitted++;
                } else if(is_excluded&&n_excluded<MAX_NC_NAMES){
                    excluded[n_excluded].name=base;
                    excluded[n_excluded].len=len;
                    n_excluded++;
                }
            }
        }
    }
    #undef MAX_NC_NAMES

    /* If no DNS name constraints at all, nothing to enforce */
    if(n_permitted==0&&n_excluded==0) return 0;

    /* Check a single DNS name against the collected constraints.
     * Returns 0 on success, -1 on violation. */
    #define CHECK_NAME(name_str, name_len) do { \
        for(int _e=0;_e<n_excluded;_e++){ \
            if(dns_name_matches_constraint(name_str,name_len, \
                                            excluded[_e].name,excluded[_e].len)) \
                return -1; \
        } \
        if(n_permitted>0){ \
            int _ok=0; \
            for(int _p=0;_p<n_permitted;_p++){ \
                if(dns_name_matches_constraint(name_str,name_len, \
                                                permitted[_p].name,permitted[_p].len)){ \
                    _ok=1; break; \
                } \
            } \
            if(!_ok) return -1; \
        } \
    } while(0)

    /* Check leaf SAN dNSName entries */
    if(leaf->san&&leaf->san_len>0){
        const uint8_t *lp=leaf->san;
        const uint8_t *lend=lp+leaf->san_len;
        lp=der_read_tl(lp,lend,&tag,&len);
        if(lp&&tag==0x30){
            lend=lp+len;
            while(lp<lend){
                const uint8_t *val=der_read_tl(lp,lend,&tag,&len);
                if(!val) break;
                if(tag==0x82&&len>0){ /* dNSName */
                    char nbuf[256];
                    size_t nlen=len<sizeof(nbuf)?len:sizeof(nbuf)-1;
                    memcpy(nbuf,val,nlen); nbuf[nlen]='\0';
                    CHECK_NAME(nbuf,nlen);
                }
                lp=val+len;
            }
        }
    }

    /* Also check the hostname (covers CN fallback case) */
    CHECK_NAME(hostname, strlen(hostname));

    #undef CHECK_NAME
    return 0;
}

/* ================================================================
 * Certificate Transparency (RFC 6962) — SCT Verification
 * ================================================================ */

static const ct_log_entry *ct_find_log(const uint8_t log_id[32]) {
    for(int i=0;i<CT_LOG_COUNT;i++)
        if(memcmp(ct_logs[i].log_id,log_id,32)==0) return &ct_logs[i];
    return NULL;
}

/* DER length encoding helpers */
static size_t der_length_size(size_t len) {
    if(len<0x80) return 1;
    if(len<0x100) return 2;
    if(len<0x10000) return 3;
    return 4;
}

static size_t der_write_length(uint8_t *out, size_t len) {
    if(len<0x80){ out[0]=(uint8_t)len; return 1; }
    if(len<0x100){ out[0]=0x81; out[1]=(uint8_t)len; return 2; }
    if(len<0x10000){ out[0]=0x82; out[1]=(uint8_t)(len>>8); out[2]=(uint8_t)len; return 3; }
    out[0]=0x83; out[1]=(uint8_t)(len>>16); out[2]=(uint8_t)(len>>8); out[3]=(uint8_t)len; return 4;
}

/* Reconstruct the precertificate TBSCertificate by removing the SCT list extension.
   CT logs sign a version of TBS *without* the SCT extension (entry_type=1 precert). */
static int ct_reconstruct_precert_tbs(const uint8_t *tbs, size_t tbs_len,
                                       uint8_t *out, size_t out_size, size_t *out_len) {
    uint8_t tag; size_t len;

    /* tbs points to the TBS SEQUENCE value start (after outer tag+len) —
       but we actually receive the full TBS with its SEQUENCE wrapper.
       Parse the outer SEQUENCE. */
    const uint8_t *tbs_end = tbs + tbs_len;
    const uint8_t *val = der_read_tl(tbs, tbs_end, &tag, &len);
    if(!val || tag != 0x30) return -1;
    const uint8_t *seq_end = val + len;

    /* Walk through TBS fields to find the [3] extensions wrapper */
    const uint8_t *tp = val;

    /* version [0] EXPLICIT */
    if(tp < seq_end && *tp == 0xA0) { tp = der_skip(tp, seq_end); if(!tp) return -1; }
    /* serialNumber */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* signature AlgorithmIdentifier */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* issuer Name */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* validity */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* subject Name */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* subjectPublicKeyInfo */
    tp = der_skip(tp, seq_end); if(!tp) return -1;
    /* optional issuerUniqueID [1], subjectUniqueID [2] */
    while(tp < seq_end && (*tp == 0x81 || *tp == 0x82))
        { tp = der_skip(tp, seq_end); if(!tp) return -1; }

    /* Now tp should point to [3] EXPLICIT extensions */
    if(tp >= seq_end || *tp != 0xA3) return -1;

    const uint8_t *a3_start = tp;
    const uint8_t *a3_val = der_read_tl(tp, seq_end, &tag, &len);
    if(!a3_val || tag != 0xA3) return -1;

    /* extensions SEQUENCE */
    const uint8_t *exts_val = der_expect(a3_val, a3_val + len, 0x30, &len);
    if(!exts_val) return -1;
    const uint8_t *exts_end = exts_val + len;

    /* Find the SCT extension and record its byte range */
    const uint8_t *sct_ext_start = NULL;
    const uint8_t *sct_ext_end_ptr = NULL;
    const uint8_t *ep = exts_val;
    while(ep < exts_end) {
        const uint8_t *ext_start = ep;
        const uint8_t *ext_val = der_expect(ep, exts_end, 0x30, &len);
        if(!ext_val) return -1;
        const uint8_t *ext_end2 = ext_val + len;
        /* Read OID */
        size_t oid_len;
        const uint8_t *eoid = der_expect(ext_val, ext_end2, 0x06, &oid_len);
        if(eoid && oid_eq(eoid, oid_len, OID_SCT_LIST, sizeof(OID_SCT_LIST))) {
            sct_ext_start = ext_start;
            sct_ext_end_ptr = ext_end2;
        }
        ep = ext_end2;
    }

    if(!sct_ext_start) return -1; /* no SCT extension found */

    size_t sct_ext_len = (size_t)(sct_ext_end_ptr - sct_ext_start);

    /* Compute new lengths */
    size_t old_exts_content_len = (size_t)(exts_end - exts_val);
    size_t new_exts_content_len = old_exts_content_len - sct_ext_len;
    size_t new_exts_seq_len = 1 + der_length_size(new_exts_content_len) + new_exts_content_len;
    size_t new_a3_content_len = new_exts_seq_len;

    /* Content before [3] wrapper */
    size_t prefix_len = (size_t)(a3_start - val);
    size_t new_tbs_content_len = prefix_len + 1 + der_length_size(new_a3_content_len) + new_a3_content_len;

    size_t total = 1 + der_length_size(new_tbs_content_len) + new_tbs_content_len;
    if(total > out_size) return -1;

    uint8_t *wp = out;

    /* TBS SEQUENCE tag + new length */
    *wp++ = 0x30;
    wp += der_write_length(wp, new_tbs_content_len);

    /* Copy everything before [3] */
    memcpy(wp, val, prefix_len);
    wp += prefix_len;

    /* [3] EXPLICIT tag + new length */
    *wp++ = 0xA3;
    wp += der_write_length(wp, new_a3_content_len);

    /* Extensions SEQUENCE tag + new length */
    *wp++ = 0x30;
    wp += der_write_length(wp, new_exts_content_len);

    /* Copy extensions content, skipping the SCT extension */
    size_t before_sct = (size_t)(sct_ext_start - exts_val);
    if(before_sct > 0) { memcpy(wp, exts_val, before_sct); wp += before_sct; }
    size_t after_sct = (size_t)(exts_end - sct_ext_end_ptr);
    if(after_sct > 0) { memcpy(wp, sct_ext_end_ptr, after_sct); wp += after_sct; }

    *out_len = (size_t)(wp - out);
    return 0;
}

/* Verify a single SCT against a precertificate TBS */
static int ct_verify_sct(const uint8_t *precert_tbs, size_t precert_tbs_len,
                          const uint8_t *issuer_key_hash,
                          const uint8_t *sct, size_t sct_len) {
    if(sct_len < 47) return 0; /* minimum: 1+32+8+2+1+1+2 = 47 */
    const uint8_t *sp = sct;
    const uint8_t *sct_end = sct + sct_len;

    uint8_t version = *sp++;
    if(version != 0) return 0; /* only v1 */

    const uint8_t *log_id = sp; sp += 32;
    const uint8_t *timestamp = sp; sp += 8;

    /* extensions */
    if(sp + 2 > sct_end) return 0;
    uint16_t ext_len = (uint16_t)((sp[0]<<8)|sp[1]); sp += 2;
    const uint8_t *ext_data = sp;
    if(sp + ext_len > sct_end) return 0;
    sp += ext_len;

    /* hash_alg + sig_alg */
    if(sp + 2 > sct_end) return 0;
    uint8_t hash_alg = *sp++;
    uint8_t sig_alg = *sp++;
    if(hash_alg != 4 || sig_alg != 3) return 0; /* SHA-256 + ECDSA only */

    /* signature */
    if(sp + 2 > sct_end) return 0;
    uint16_t sig_len2 = (uint16_t)((sp[0]<<8)|sp[1]); sp += 2;
    if(sp + sig_len2 > sct_end) return 0;
    const uint8_t *sig = sp;

    /* Look up log */
    const ct_log_entry *log = ct_find_log(log_id);
    if(!log) return 0;

    /* Build signed data: version(1) + sig_type(1) + timestamp(8) +
       entry_type(2) + issuer_key_hash(32) + tbs_len(3) + tbs + ext_len(2) + ext */
    size_t signed_data_len = 1 + 1 + 8 + 2 + 32 + 3 + precert_tbs_len + 2 + ext_len;
    uint8_t *signed_data = malloc(signed_data_len);
    if(!signed_data) return 0;

    uint8_t *wp = signed_data;
    *wp++ = 0x00; /* version v1 */
    *wp++ = 0x00; /* signature_type = certificate_timestamp */
    memcpy(wp, timestamp, 8); wp += 8;
    *wp++ = 0x00; *wp++ = 0x01; /* entry_type = precert_entry */
    memcpy(wp, issuer_key_hash, 32); wp += 32;
    /* tbs_length is 3 bytes (uint24) */
    *wp++ = (uint8_t)(precert_tbs_len >> 16);
    *wp++ = (uint8_t)(precert_tbs_len >> 8);
    *wp++ = (uint8_t)(precert_tbs_len);
    memcpy(wp, precert_tbs, precert_tbs_len); wp += precert_tbs_len;
    *wp++ = (uint8_t)(ext_len >> 8);
    *wp++ = (uint8_t)(ext_len);
    if(ext_len > 0) { memcpy(wp, ext_data, ext_len); }

    uint8_t hash[32];
    sha256_hash(signed_data, signed_data_len, hash);
    free(signed_data);

    return ecdsa_p256_verify(hash, 32, sig, sig_len2, log->pubkey, 65);
}

/* Verify all embedded SCTs in a leaf certificate.
   Chrome/Apple policy: <=180 day cert needs 2 SCTs from >=2 distinct operators,
   >180 day cert needs 3 SCTs from >=2 distinct operators. */
static int ct_verify_scts(const x509_cert *leaf, const uint8_t *issuer_key_hash) {
    if(!leaf->sct_list || leaf->sct_list_len < 2) {
        fprintf(stderr, "No embedded SCTs in leaf certificate\n");
        return -1;
    }

    /* The extension value is an OCTET STRING wrapping a TLS-encoded SCT list.
       sct_list/sct_list_len point to the OCTET STRING contents (the outer
       OCTET STRING was already stripped by the extension parser). Inside is
       another opaque<1..2^16-1> (the TLS SCT list encoding). */
    const uint8_t *p = leaf->sct_list;
    const uint8_t *end = p + leaf->sct_list_len;

    /* Inner OCTET STRING wrapping (some certs have double OCTET STRING) */
    uint8_t tag; size_t ilen;
    const uint8_t *inner = der_read_tl(p, end, &tag, &ilen);
    if(inner && tag == 0x04 && inner + ilen <= end) {
        p = inner;
        end = inner + ilen;
    }

    /* TLS-encoded SignedCertificateTimestampList: 2-byte total length */
    if(end - p < 2) {
        fprintf(stderr, "SCT list too short\n");
        return -1;
    }
    uint16_t list_len = (uint16_t)((p[0]<<8)|p[1]); p += 2;
    if(p + list_len > end) list_len = (uint16_t)(end - p);

    const uint8_t *list_end = p + list_len;

    /* Reconstruct precert TBS (remove SCT extension) */
    uint8_t *precert_tbs = malloc(leaf->tbs_len + 16);
    if(!precert_tbs) return -1;
    size_t precert_tbs_len = 0;

    /* tbs/tbs_len in x509_cert includes the full TBS SEQUENCE tag+length+value,
       so we can pass it directly to the reconstruction function. */
    if(ct_reconstruct_precert_tbs(leaf->tbs, leaf->tbs_len,
                                   precert_tbs, leaf->tbs_len + 16, &precert_tbs_len) < 0) {
        free(precert_tbs);
        fprintf(stderr, "Failed to reconstruct precert TBS\n");
        return -1;
    }

    /* Parse individual SCTs and verify — track total count + distinct operators */
    uint8_t verified_ops[10]; /* distinct operator IDs seen, up to 10 */
    int distinct_ops = 0;
    int total_scts = 0;

    while(p + 2 <= list_end) {
        uint16_t sct_len = (uint16_t)((p[0]<<8)|p[1]); p += 2;
        if(p + sct_len > list_end) break;

        if(ct_verify_sct(precert_tbs, precert_tbs_len, issuer_key_hash, p, sct_len)) {
            total_scts++;
            /* Look up the log to get operator_id */
            const uint8_t *this_id = p + 1; /* skip version byte to get log_id */
            const ct_log_entry *log = ct_find_log(this_id);
            if(log) {
                int dup = 0;
                for(int k = 0; k < distinct_ops; k++) {
                    if(verified_ops[k] == log->operator_id) { dup = 1; break; }
                }
                if(!dup && distinct_ops < 10) {
                    verified_ops[distinct_ops] = log->operator_id;
                    distinct_ops++;
                }
            }
        }
        p += sct_len;
    }

    free(precert_tbs);

    /* Chrome/Apple policy: require more SCTs for longer-lived certs,
       and always require SCTs from at least 2 distinct operators */
    int lifetime_days = (int)((leaf->not_after - leaf->not_before) / 86400);
    int required = (lifetime_days <= 180) ? 2 : 3;

    if(tls_verbose) fprintf(stderr,"    CT: %d valid SCT(s) from %d distinct operator(s) (%d SCTs required, 2 operators required)\n",
                       total_scts, distinct_ops, required);

    if(total_scts < required) {
        fprintf(stderr, "CT: only %d valid SCT(s), need at least %d\n", total_scts, required);
        return -1;
    }
    if(distinct_ops < 2) {
        fprintf(stderr, "CT: SCTs from only %d operator(s), need at least 2 distinct\n", distinct_ops);
        return -1;
    }

    return 0;
}

/* ================================================================
 * CRL (Certificate Revocation List) Check
 * ================================================================ */
static int crl_check(const x509_cert *cert, const x509_cert *issuer) {
    if(!cert->crl_dp_url){
        if(tls_verbose) fprintf(stderr,"    CRL: no distribution point URL\n");
        return 0; /* soft-fail */
    }

    /* Extract cache filename from URL: skip "http://", flatten path with '_' */
    char cache_path[PATH_MAX];
    int have_cache_path=0;
    {
        const uint8_t *url=cert->crl_dp_url;
        size_t url_len=cert->crl_dp_url_len;
        /* Skip past "http://" or "https://" */
        size_t start=0;
        if(url_len>7&&memcmp(url,"http://",7)==0) start=7;
        else if(url_len>8&&memcmp(url,"https://",8)==0) start=8;
        if(start<url_len){
            size_t remain=url_len-start;
            if(remain>sizeof(cache_path)-6) remain=sizeof(cache_path)-6;
            memcpy(cache_path,"crls/",5);
            for(size_t i=0;i<remain;i++)
                cache_path[5+i]=(url[start+i]=='/')?'_':(char)url[start+i];
            cache_path[5+remain]='\0';
            have_cache_path=1;
        }
    }

    uint8_t *crl_der=NULL; size_t crl_len=0;
    int from_cache=0;

    /* Try loading from disk cache */
    if(have_cache_path){
        FILE *cf=fopen(cache_path,"rb");
        if(cf){
            fseek(cf,0,SEEK_END);
            long fsz=ftell(cf);
            fseek(cf,0,SEEK_SET);
            if(fsz>0){
                crl_der=malloc((size_t)fsz);
                if(crl_der){
                    crl_len=fread(crl_der,1,(size_t)fsz,cf);
                    if(crl_len==0){ free(crl_der); crl_der=NULL; }
                }
            }
            fclose(cf);
            if(crl_der){
                /* Check freshness: quick partial parse for nextUpdate */
                int fresh=0;
                size_t tlen;
                const uint8_t *cp=der_expect(crl_der,crl_der+crl_len,0x30,&tlen);
                if(cp){
                    const uint8_t *tp=der_expect(cp,cp+tlen,0x30,&tlen);
                    if(tp){
                        const uint8_t *tp_end=tp+tlen;
                        if(tp<tp_end&&*tp==0x02) tp=der_skip(tp,tp_end);
                        if(tp) tp=der_skip(tp,tp_end); /* signature AlgId */
                        if(tp) tp=der_skip(tp,tp_end); /* issuer Name */
                        if(tp) tp=der_skip(tp,tp_end); /* thisUpdate */
                        if(tp&&tp<tp_end&&(*tp==0x17||*tp==0x18)){
                            time_t nu=der_parse_time(tp,tp_end);
                            if(nu>0&&time(NULL)<=nu) fresh=1;
                        }
                    }
                }
                if(fresh){
                    if(tls_verbose) fprintf(stderr,"    CRL: using cached %s\n",cache_path);
                    from_cache=1;
                } else {
                    if(tls_verbose) fprintf(stderr,"    CRL: cached %s expired, re-fetching\n",cache_path);
                    free(crl_der);
                    crl_der=NULL;
                    crl_len=0;
                }
            }
        }
    }

    if(!from_cache){
        if(tls_verbose) fprintf(stderr,"    CRL: fetching %.*s\n",
               (int)cert->crl_dp_url_len,cert->crl_dp_url);
        if(http_fetch(cert->crl_dp_url,cert->crl_dp_url_len,
                      CRL_READ_TIMEOUT_S,&crl_der,&crl_len)<0){
            if(tls_verbose) fprintf(stderr,"    CRL: fetch failed (soft-fail)\n");
            return 0;
        }
        /* Write to disk cache (best-effort) */
        if(have_cache_path&&crl_len>0){
            if(mkdir("crls",0755)<0&&errno!=EEXIST){
                /* ignore mkdir failure */
            } else {
                FILE *wf=fopen(cache_path,"wb");
                if(wf){
                    fwrite(crl_der,1,crl_len,wf);
                    fclose(wf);
                    if(tls_verbose) fprintf(stderr,"    CRL: cached to %s\n",cache_path);
                }
            }
        }
    }

    /* Parse CRL DER:
     * CertificateList ::= SEQUENCE { tbsCertList, sigAlg, sig }
     * TBSCertList ::= SEQUENCE { version?, sigAlg, issuer, thisUpdate,
     *                             nextUpdate?, revokedCertificates?, extensions? } */
    int ret=0;
    uint8_t tag; size_t len;
    const uint8_t *p=der_expect(crl_der,crl_der+crl_len,0x30,&len);
    if(!p){
        if(tls_verbose) fprintf(stderr,"    CRL: parse error (soft-fail)\n");
        goto done;
    }
    const uint8_t *crl_end=p+len;

    /* TBSCertList */
    const uint8_t *tbs_start=p;
    const uint8_t *tbs=der_expect(p,crl_end,0x30,&len);
    if(!tbs){
        if(tls_verbose) fprintf(stderr,"    CRL: parse error (soft-fail)\n");
        goto done;
    }
    const uint8_t *tbs_end_ptr=tbs+len;
    size_t tbs_full_len=(size_t)(tbs_end_ptr-tbs_start);
    p=tbs_end_ptr;

    /* signatureAlgorithm */
    const uint8_t *crl_sig_alg_start=p;
    const uint8_t *sa=der_read_tl(p,crl_end,&tag,&len);
    if(!sa||tag!=0x30){
        if(tls_verbose) fprintf(stderr,"    CRL: parse error (soft-fail)\n");
        goto done;
    }
    /* Extract the OID from the AlgorithmIdentifier SEQUENCE */
    const uint8_t *sa_oid=der_expect(sa,sa+len,0x06,&len);
    size_t crl_sig_alg_len=0;
    const uint8_t *crl_sig_alg=NULL;
    if(sa_oid){ crl_sig_alg=sa_oid; crl_sig_alg_len=len; }
    p=der_skip(crl_sig_alg_start,crl_end);
    if(!p){
        if(tls_verbose) fprintf(stderr,"    CRL: parse error (soft-fail)\n");
        goto done;
    }

    /* signatureValue BIT STRING */
    const uint8_t *sig_bits=der_expect(p,crl_end,0x03,&len);
    if(!sig_bits||len<2||sig_bits[0]!=0){
        if(tls_verbose) fprintf(stderr,"    CRL: parse error (soft-fail)\n");
        goto done;
    }
    const uint8_t *crl_sig=sig_bits+1;
    size_t crl_sig_len=len-1;

    /* Verify CRL signature against issuer's public key */
    if(crl_sig_alg){
        if(!verify_signature(tbs_start,tbs_full_len,
                              crl_sig_alg,crl_sig_alg_len,
                              crl_sig,crl_sig_len,
                              issuer->key_type,
                              issuer->pubkey,issuer->pubkey_len,
                              issuer->rsa_n,issuer->rsa_n_len,
                              issuer->rsa_e,issuer->rsa_e_len)){
            if(tls_verbose) fprintf(stderr,"    CRL: signature verification failed (soft-fail)\n");
            goto done;
        }
        if(tls_verbose) fprintf(stderr,"    CRL: signature verified\n");
    }

    /* Parse TBSCertList fields */
    const uint8_t *tp=tbs;
    /* version (optional INTEGER) */
    if(tp<tbs_end_ptr&&*tp==0x02) tp=der_skip(tp,tbs_end_ptr);
    /* signature AlgorithmIdentifier */
    if(!tp) goto done;
    tp=der_skip(tp,tbs_end_ptr);
    /* issuer Name */
    if(!tp) goto done;
    tp=der_skip(tp,tbs_end_ptr);
    /* thisUpdate */
    if(!tp) goto done;
    time_t this_update=der_parse_time(tp,tbs_end_ptr);
    tp=der_skip(tp,tbs_end_ptr);
    if(!tp) goto done;

    /* nextUpdate is OPTIONAL per RFC 5280 §5.1.2.5; if absent, the next
     * element is revokedCertificates (a SEQUENCE, tag 0x30).  We distinguish
     * by checking for a Time tag (UTCTime 0x17 or GeneralizedTime 0x18). */
    time_t next_update=0;
    if(tp<tbs_end_ptr&&(*tp==0x17||*tp==0x18)){
        next_update=der_parse_time(tp,tbs_end_ptr);
        tp=der_skip(tp,tbs_end_ptr);
        if(!tp) goto done;
    }

    /* Check validity */
    time_t now=time(NULL);
    if(this_update>0&&now<this_update){
        if(tls_verbose) fprintf(stderr,"    CRL: not yet valid (soft-fail)\n");
        goto done;
    }
    if(next_update>0&&now>next_update){
        if(tls_verbose) fprintf(stderr,"    CRL: expired (soft-fail)\n");
        goto done;
    }

    /* revokedCertificates is OPTIONAL per RFC 5280 §5.1.2.6; a conforming
     * CA may omit it when there are no revoked certificates. */
    if(tp>=tbs_end_ptr||*tp!=0x30){
        if(tls_verbose) fprintf(stderr,"    CRL: no revoked certificates — not revoked\n");
        goto done;
    }
    const uint8_t *revoked=der_expect(tp,tbs_end_ptr,0x30,&len);
    if(!revoked){
        if(tls_verbose) fprintf(stderr,"    CRL: not revoked\n");
        goto done;
    }
    const uint8_t *revoked_end=revoked+len;

    /* Extract cert serial value bytes (skip tag+length) */
    uint8_t stag; size_t slen;
    const uint8_t *cert_serial_val=der_read_tl(cert->serial,cert->serial+cert->serial_len,&stag,&slen);
    if(!cert_serial_val||stag!=0x02) goto done;

    /* Walk revokedCertificates entries */
    const uint8_t *rp=revoked;
    while(rp<revoked_end){
        const uint8_t *entry=der_read_tl(rp,revoked_end,&tag,&len);
        if(!entry||tag!=0x30) break;
        const uint8_t *entry_end=entry+len;
        rp=entry_end;
        /* userCertificate INTEGER */
        const uint8_t *rev_serial=der_read_tl(entry,entry_end,&tag,&len);
        if(!rev_serial||tag!=0x02) continue;
        /* Compare serial value bytes */
        if(len==slen&&memcmp(rev_serial,cert_serial_val,slen)==0){
            fprintf(stderr,"CRL: certificate serial number is REVOKED\n");
            ret=-1;
            goto done;
        }
    }

    if(tls_verbose) fprintf(stderr,"    CRL: certificate not revoked\n");
done:
    free(crl_der);
    return ret;
}

/* ================================================================
 * Certificate Chain Validation
 * ================================================================ */
static int verify_cert_chain(const uint8_t *cert_msg, size_t cert_msg_len,
                              const char *hostname, int is_tls13) {
    const uint8_t *p=cert_msg;
    const uint8_t *msg_end=cert_msg+cert_msg_len;
    if(is_tls13) {
        if(p>=msg_end) return -1;
        uint8_t ctx_len=*p++;
        if(p+ctx_len>msg_end) return -1;
        p+=ctx_len;
    }
    if(p+3>msg_end) return -1;
    uint32_t list_len=GET24(p); p+=3;
    const uint8_t *end=p+list_len;
    if(end>msg_end) end=msg_end;

    #define MAX_CHAIN 5
    const uint8_t *chain_der[MAX_CHAIN];
    size_t chain_len[MAX_CHAIN];
    int chain_count=0;
    uint8_t *aia_alloc=NULL; /* dynamically fetched AIA cert, freed on exit */

    while(p+3<=end&&chain_count<MAX_CHAIN){
        uint32_t cl=GET24(p); p+=3;
        if(p+cl>end) break;
        chain_der[chain_count]=p;
        chain_len[chain_count]=cl;
        chain_count++;
        p+=cl;
        if(is_tls13) {
            if(p+2>end) break;
            uint16_t el=GET16(p); p+=2;
            if(p+el>end) break;
            p+=el;
        }
    }
    if(chain_count==0){fprintf(stderr,"No certificates in chain\n");return -1;}

    x509_cert certs[MAX_CHAIN];
    memset(certs, 0, sizeof(certs));
    for(int i=0;i<chain_count;i++){
        if(x509_parse(&certs[i],chain_der[i],chain_len[i])!=0){
            fprintf(stderr,"Failed to parse certificate %d\n",i);
            return -1;
        }
    }

    /* Reject RSA keys smaller than 2048 bits */
    for(int i=0;i<chain_count;i++){
        if(certs[i].key_type==2 && certs[i].rsa_n_len<256){
            fprintf(stderr,"Certificate %d has RSA key < 2048 bits\n",i);
            return -1;
        }
    }

    /* Validate leaf certificate */
    if(validate_leaf_cert(&certs[0],hostname)<0) return -1;

    /* Check validity period for all chain certs */
    time_t now=time(NULL);
    for(int i=0;i<chain_count;i++){
        if(now<certs[i].not_before){
            fprintf(stderr,"Certificate %d is not yet valid\n",i);
            return -1;
        }
        if(now>certs[i].not_after){
            fprintf(stderr,"Certificate %d has expired\n",i);
            return -1;
        }
    }
    if(tls_verbose) fprintf(stderr,"    Validity periods OK\n");

    /* Walk chain from leaf upward: at each cert, try trust store first,
     * then find issuer among remaining chain certs. Handles out-of-order
     * chains and cross-signed certs. */
    int ret=-1;
    #define MAX_AIA_FETCHES 1
    int aia_fetches=0;
    for(int i=0;i<chain_count;i++){
        /* Try trust store for this cert */
        for(int j=0;j<trust_store_count;j++){
            if(certs[i].issuer_len!=trust_store[j].subject_len) continue;
            if(memcmp(certs[i].issuer,trust_store[j].subject,certs[i].issuer_len)!=0) continue;
            if(tls_verbose) fprintf(stderr,"    Verifying cert %d against trust store...\n",i);
            if(verify_signature(certs[i].tbs,certs[i].tbs_len,
                                 certs[i].sig_alg,certs[i].sig_alg_len,
                                 certs[i].sig,certs[i].sig_len,
                                 trust_store[j].key_type,
                                 trust_store[j].pubkey,trust_store[j].pubkey_len,
                                 trust_store[j].rsa_n,trust_store[j].rsa_n_len,
                                 trust_store[j].rsa_e,trust_store[j].rsa_e_len)){
                if(tls_verbose) fprintf(stderr,"    Certificate %d root signature verified\n",i);
                if(tls_verbose) fprintf(stderr,"    Certificate chain verified successfully!\n");
                /* CT verification — skip for directly-trusted certs (e.g. self-signed
                   in trust store); CT is a public WebPKI mechanism only */
                if(i > 0) {
                    uint8_t ikh[32];
                    sha256_hash(certs[1].spki, certs[1].spki_len, ikh);
                    if(certs[0].sct_list) {
                        if(ct_verify_scts(&certs[0], ikh) < 0) goto out;
                    } else {
                        fprintf(stderr, "No embedded SCTs in leaf certificate\n");
                        goto out;
                    }
                }
                /* CRL revocation check for leaf certificate */
                {
                    x509_cert leaf_issuer;
                    memset(&leaf_issuer,0,sizeof(leaf_issuer));
                    if(i==0){
                        leaf_issuer.key_type=trust_store[j].key_type;
                        leaf_issuer.pubkey=trust_store[j].pubkey;
                        leaf_issuer.pubkey_len=trust_store[j].pubkey_len;
                        leaf_issuer.rsa_n=trust_store[j].rsa_n;
                        leaf_issuer.rsa_n_len=trust_store[j].rsa_n_len;
                        leaf_issuer.rsa_e=trust_store[j].rsa_e;
                        leaf_issuer.rsa_e_len=trust_store[j].rsa_e_len;
                    } else {
                        leaf_issuer=certs[1];
                    }
                    if(crl_check(&certs[0],&leaf_issuer)<0) goto out;
                }
                ret=0;
                goto out;
            }
        }
        /* Find issuer among remaining chain certs (handles out-of-order chains) */
        int found=-1;
        for(int j=i+1;j<chain_count;j++){
            if(certs[i].issuer_len==certs[j].subject_len&&
               memcmp(certs[i].issuer,certs[j].subject,certs[i].issuer_len)==0){
                found=j;
                break;
            }
        }
        if(found<0&&certs[i].aia_url&&chain_count<MAX_CHAIN&&aia_fetches<MAX_AIA_FETCHES){
            if(tls_verbose) fprintf(stderr,"    AIA: fetching issuer for cert %d from %.*s\n",
                   i,(int)certs[i].aia_url_len,certs[i].aia_url);
            uint8_t *fetched=NULL; size_t fetched_len=0;
            if(http_fetch_der(certs[i].aia_url,certs[i].aia_url_len,
                              &fetched,&fetched_len)==0){
                x509_cert fc;
                if(x509_parse(&fc,fetched,fetched_len)==0){
                    time_t now2=time(NULL);
                    if(now2>=fc.not_before&&now2<=fc.not_after&&
                       !(fc.key_type==2&&fc.rsa_n_len<256)){
                        chain_der[chain_count]=fetched;
                        chain_len[chain_count]=fetched_len;
                        certs[chain_count]=fc;
                        chain_count++;
                        aia_fetches++;
                        aia_alloc=fetched;
                        fetched=NULL;
                        if(tls_verbose) fprintf(stderr,"    AIA: fetched intermediate certificate\n");
                        /* Retry issuer search with the new cert */
                        for(int j=i+1;j<chain_count;j++){
                            if(certs[i].issuer_len==certs[j].subject_len&&
                               memcmp(certs[i].issuer,certs[j].subject,
                                      certs[i].issuer_len)==0){
                                found=j;
                                break;
                            }
                        }
                    }
                }
                free(fetched);
            }
        }
        if(found<0){
            fprintf(stderr,"No issuer found for cert %d\n",i);
            goto out;
        }
        /* Detect cycle: issuer must not be the same cert */
        if(certs[i].tbs==certs[found].tbs){
            fprintf(stderr,"Certificate chain cycle detected at cert %d\n",i);
            goto out;
        }
        /* Swap found cert to position i+1 if needed */
        if(found!=i+1){
            x509_cert tmp=certs[i+1]; certs[i+1]=certs[found]; certs[found]=tmp;
        }
        if(tls_verbose) fprintf(stderr,"    Verifying cert %d signature...\n",i);
        if(!verify_signature(certs[i].tbs,certs[i].tbs_len,
                              certs[i].sig_alg,certs[i].sig_alg_len,
                              certs[i].sig,certs[i].sig_len,
                              certs[i+1].key_type,
                              certs[i+1].pubkey,certs[i+1].pubkey_len,
                              certs[i+1].rsa_n,certs[i+1].rsa_n_len,
                              certs[i+1].rsa_e,certs[i+1].rsa_e_len)){
            fprintf(stderr,"Signature verification failed for cert %d\n",i);
            goto out;
        }
        if(tls_verbose) fprintf(stderr,"    Certificate %d signature verified\n",i);
        /* Intermediate must be v3 (only v3 has extensions) */
        if(certs[i+1].version!=2){
            fprintf(stderr,"Certificate %d is not v3, cannot be CA\n",i+1);
            goto out;
        }
        /* Intermediate cert must have CA:TRUE basicConstraints */
        if(!certs[i+1].is_ca){
            fprintf(stderr,"Certificate %d used as CA but lacks basicConstraints CA:TRUE\n",i+1);
            goto out;
        }
        /* Enforce pathLenConstraint: i certs below this CA (0=leaf only) */
        if(certs[i+1].path_len>=0 && i>certs[i+1].path_len){
            fprintf(stderr,"Certificate %d exceeds pathLenConstraint %d\n",i+1,certs[i+1].path_len);
            goto out;
        }
        /* Intermediate: if keyUsage present, must include keyCertSign (bit 5) */
        if(certs[i+1].has_key_usage && !(certs[i+1].key_usage & 0x04)){
            fprintf(stderr,"CA certificate %d keyUsage missing keyCertSign\n",i+1);
            goto out;
        }
        /* Check name constraints on the leaf against each CA in the chain */
        if(certs[i+1].name_constraints){
            if(check_name_constraints(&certs[i+1],&certs[0],hostname)<0){
                fprintf(stderr,"Name constraints violated at cert %d\n",i+1);
                goto out;
            }
        }
    }
    fprintf(stderr,"No matching root CA found in trust store\n");
out:
    free(aia_alloc);
    return ret;
}

/* ================================================================
 * TLS 1.3 (RFC 8446)
 * ================================================================ */

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints={0}, *res;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    char ps[8]; snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host,ps,&hints,&res)!=0) die("getaddrinfo");
    int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(fd<0) die("socket");
    if(connect(fd,res->ai_addr,res->ai_addrlen)<0) die("connect");
    freeaddrinfo(res);
    /* Prevents hanging when a server silently drops our ClientHello */
    struct timeval tv={TLS_READ_TIMEOUT_S,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    return fd;
}

/* Send a TLS record (header + body in a single write to avoid TCP fragmentation
   issues with middleboxes that can't reassemble split TLS record headers) */
static void tls_send_record(int fd, uint8_t type, const uint8_t *data, size_t len) {
    uint8_t *buf = malloc(5+len);
    if(!buf) die("malloc failed");
    buf[0]=type; buf[1]=(TLS_VERSION_12>>8); buf[2]=(TLS_VERSION_12&0xFF);
    PUT16(buf+3,(uint16_t)len);
    memcpy(buf+5,data,len);
    write_all(fd,buf,5+len);
    free(buf);
}

/* Read a TLS record. Returns content type, or -1 on error. */
static int tls_read_record(int fd, uint8_t *out, size_t *out_len) {
    uint8_t hdr[5];
    if(read_exact(fd,hdr,5)<0) return -1;
    uint16_t len=GET16(hdr+3);
    /* RFC 5246 §6.2.3: max 2^14+2048 for TLS 1.2; RFC 8446 §5.2: max 2^14+256 for TLS 1.3.
       Enforce the stricter TLS 1.3 limit (16640). TLS 1.2 CBC records with compression
       could exceed this but compression is not supported, so 16640 is safe for both. */
    if(len>16384+256) die("record too large");
    if(read_exact(fd,out,len)<0) return -1;
    *out_len=len;
    return hdr[0];
}

/* ================================================================
 * TLS 1.3 Session Resumption (PSK-DHE)
 * ================================================================ */
struct tls_session {
    uint8_t *ticket;            /* opaque ticket blob */
    size_t ticket_len;
    uint32_t ticket_lifetime;   /* seconds */
    uint32_t ticket_age_add;    /* obfuscation value */
    uint8_t psk[48];            /* HKDF-Expand-Label(res_master, "resumption", nonce) */
    size_t psk_len;             /* 32 (SHA-256) or 48 (SHA-384) */
    uint16_t cipher_suite;      /* must match on resumption */
    uint64_t timestamp;         /* time() when ticket was received */
};

void tls_session_free(tls_session *s) {
    if(s) { secure_zero(s->psk, sizeof(s->psk)); free(s->ticket); free(s); }
}

/* Build ClientHello for TLS 1.2/1.3.
   only_group: 0 = emit all key shares (initial CH),
               specific group = emit only that group's key share (after HRR)
   session_id: NULL = generate new (initial CH), non-NULL = reuse (HRR per RFC 8446 §4.1.2) */
static size_t build_client_hello(uint8_t *buf, const uint8_t p256_pub[P256_POINT_LEN],
                                  const uint8_t p384_pub[P384_POINT_LEN],
                                  const uint8_t x25519_pub[X25519_KEY_LEN],
                                  const uint8_t x448_pub[X448_KEY_LEN],
                                  const char *host,
                                  uint8_t client_random[32],
                                  const uint8_t *session_id,
                                  uint16_t only_group,
                                  const tls_session *sess) {
    size_t p=0;
    /* Handshake header - fill length later */
    buf[p++]=0x01; /* ClientHello */
    buf[p++]=0; buf[p++]=0; buf[p++]=0; /* length placeholder */

    /* Legacy version TLS 1.2 */
    buf[p++]=(TLS_VERSION_12>>8); buf[p++]=(TLS_VERSION_12&0xFF);

    /* Random: generate fresh for initial CH, reuse for HRR (RFC 8446 §4.1.2) */
    if(only_group) {
        memcpy(buf+p,client_random,32);
    } else {
        random_bytes(buf+p,32);
        memcpy(client_random,buf+p,32);
    }
    p+=32;

    /* Session ID: generate fresh for initial CH, reuse for HRR (RFC 8446 §4.1.2) */
    buf[p++]=32;
    if(session_id)
        memcpy(buf+p,session_id,32);
    else
        random_bytes(buf+p,32);
    p+=32;

    /* Cipher suites: TLS 1.3 + TLS 1.2 GCM + ChaCha20-Poly1305 + CBC + SCSV */
    buf[p++]=0x00; buf[p++]=0x24; /* 36 bytes = 18 suites */
    PUT16(buf+p, TLS_AES_128_GCM_SHA256); p+=2;
    PUT16(buf+p, TLS_AES_256_GCM_SHA384); p+=2;
    PUT16(buf+p, TLS_CHACHA20_POLY1305_SHA256); p+=2;
    PUT16(buf+p, TLS_ECDHE_ECDSA_CHACHA_POLY); p+=2;
    PUT16(buf+p, TLS_ECDHE_RSA_CHACHA_POLY); p+=2;
    PUT16(buf+p, TLS_ECDHE_ECDSA_AES128_GCM); p+=2;
    PUT16(buf+p, TLS_ECDHE_RSA_AES128_GCM); p+=2;
    PUT16(buf+p, TLS_ECDHE_ECDSA_AES256_GCM); p+=2;
    PUT16(buf+p, TLS_ECDHE_RSA_AES256_GCM); p+=2;
    PUT16(buf+p, TLS_RSA_AES256_GCM); p+=2;
    PUT16(buf+p, TLS_RSA_AES128_GCM); p+=2;
    PUT16(buf+p, TLS_ECDHE_RSA_AES256_CBC); p+=2;
    PUT16(buf+p, TLS_ECDHE_RSA_AES128_CBC); p+=2;
    PUT16(buf+p, TLS_ECDHE_ECDSA_AES256_CBC); p+=2;
    PUT16(buf+p, TLS_ECDHE_ECDSA_AES128_CBC); p+=2;
    PUT16(buf+p, TLS_RSA_AES256_CBC); p+=2;
    PUT16(buf+p, TLS_RSA_AES128_CBC); p+=2;
    PUT16(buf+p, 0x00FF); p+=2; /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746) */

    /* Compression */
    buf[p++]=0x01; buf[p++]=0x00;

    /* Extensions - length placeholder */
    size_t ext_len_pos=p; p+=2;

    /* SNI */
    {
        size_t hl=strlen(host);
        buf[p++]=0x00;buf[p++]=0x00; /* extension type */
        size_t el=hl+5;
        PUT16(buf+p,(uint16_t)el);p+=2;
        PUT16(buf+p,(uint16_t)(hl+3));p+=2;
        buf[p++]=0x00;
        PUT16(buf+p,(uint16_t)hl);p+=2;
        memcpy(buf+p,host,hl);p+=hl;
    }

    /* ec_point_formats (needed for TLS 1.2 ECDHE) */
    buf[p++]=0x00;buf[p++]=0x0b; /* extension type 11 */
    buf[p++]=0x00;buf[p++]=0x02; /* ext len */
    buf[p++]=0x01;               /* list len */
    buf[p++]=0x00;               /* uncompressed */

    /* supported_groups */
    buf[p++]=0x00;buf[p++]=0x0a;
    buf[p++]=0x00;buf[p++]=0x0a; /* ext len = 4 groups * 2 + 2 */
    buf[p++]=0x00;buf[p++]=0x08; /* list len = 4 groups * 2 bytes */
    buf[p++]=(TLS_GROUP_X25519>>8);buf[p++]=(TLS_GROUP_X25519&0xFF); /* x25519 (preferred) */
    buf[p++]=(TLS_GROUP_X448>>8);buf[p++]=(TLS_GROUP_X448&0xFF); /* x448 */
    buf[p++]=(TLS_GROUP_SECP256R1>>8);buf[p++]=(TLS_GROUP_SECP256R1&0xFF); /* secp256r1 */
    buf[p++]=(TLS_GROUP_SECP384R1>>8);buf[p++]=(TLS_GROUP_SECP384R1&0xFF); /* secp384r1 */

    /* signature_algorithms */
    buf[p++]=0x00;buf[p++]=0x0d;
    buf[p++]=0x00;buf[p++]=0x12; /* ext len = 8 algos * 2 + 2 */
    buf[p++]=0x00;buf[p++]=0x10; /* list len = 8 algos * 2 bytes */
    PUT16(buf+p, TLS_SIG_ECDSA_SECP384R1_SHA384); p+=2;
    PUT16(buf+p, TLS_SIG_ECDSA_SECP256R1_SHA256); p+=2;
    PUT16(buf+p, TLS_SIG_ED25519); p+=2;
    PUT16(buf+p, TLS_SIG_ED448); p+=2;
    PUT16(buf+p, TLS_SIG_RSA_PSS_SHA384); p+=2;
    PUT16(buf+p, TLS_SIG_RSA_PSS_SHA256); p+=2;
    PUT16(buf+p, TLS_SIG_RSA_PKCS1_SHA384); p+=2;
    PUT16(buf+p, TLS_SIG_RSA_PKCS1_SHA256); p+=2;

    /* key_share */
    buf[p++]=0x00;buf[p++]=0x33;
    if(only_group==TLS_GROUP_SECP256R1) {
        PUT16(buf+p,(uint16_t)(P256_POINT_LEN+4+2));p+=2;
        PUT16(buf+p,(uint16_t)(P256_POINT_LEN+4));p+=2;
        buf[p++]=(TLS_GROUP_SECP256R1>>8);buf[p++]=(TLS_GROUP_SECP256R1&0xFF);
        PUT16(buf+p,P256_POINT_LEN);p+=2;
        memcpy(buf+p,p256_pub,P256_POINT_LEN);p+=P256_POINT_LEN;
    } else if(only_group==TLS_GROUP_SECP384R1) {
        PUT16(buf+p,(uint16_t)(P384_POINT_LEN+4+2));p+=2;
        PUT16(buf+p,(uint16_t)(P384_POINT_LEN+4));p+=2;
        buf[p++]=(TLS_GROUP_SECP384R1>>8);buf[p++]=(TLS_GROUP_SECP384R1&0xFF);
        PUT16(buf+p,P384_POINT_LEN);p+=2;
        memcpy(buf+p,p384_pub,P384_POINT_LEN);p+=P384_POINT_LEN;
    } else if(only_group==TLS_GROUP_X25519) {
        PUT16(buf+p,(uint16_t)(X25519_KEY_LEN+4+2));p+=2;
        PUT16(buf+p,(uint16_t)(X25519_KEY_LEN+4));p+=2;
        buf[p++]=(TLS_GROUP_X25519>>8);buf[p++]=(TLS_GROUP_X25519&0xFF);
        PUT16(buf+p,X25519_KEY_LEN);p+=2;
        memcpy(buf+p,x25519_pub,X25519_KEY_LEN);p+=X25519_KEY_LEN;
    } else if(only_group==TLS_GROUP_X448) {
        PUT16(buf+p,(uint16_t)(X448_KEY_LEN+4+2));p+=2;
        PUT16(buf+p,(uint16_t)(X448_KEY_LEN+4));p+=2;
        buf[p++]=(TLS_GROUP_X448>>8);buf[p++]=(TLS_GROUP_X448&0xFF);
        PUT16(buf+p,X448_KEY_LEN);p+=2;
        memcpy(buf+p,x448_pub,X448_KEY_LEN);p+=X448_KEY_LEN;
    } else {
        /* Emit X25519 first (most preferred), then X448, P-256, P-384 */
        uint16_t shares_len=X25519_KEY_LEN+4+X448_KEY_LEN+4+P256_POINT_LEN+4+P384_POINT_LEN+4;
        PUT16(buf+p,(uint16_t)(shares_len+2));p+=2;
        PUT16(buf+p,shares_len);p+=2;
        buf[p++]=(TLS_GROUP_X25519>>8);buf[p++]=(TLS_GROUP_X25519&0xFF);
        PUT16(buf+p,X25519_KEY_LEN);p+=2;
        memcpy(buf+p,x25519_pub,X25519_KEY_LEN);p+=X25519_KEY_LEN;
        buf[p++]=(TLS_GROUP_X448>>8);buf[p++]=(TLS_GROUP_X448&0xFF);
        PUT16(buf+p,X448_KEY_LEN);p+=2;
        memcpy(buf+p,x448_pub,X448_KEY_LEN);p+=X448_KEY_LEN;
        buf[p++]=(TLS_GROUP_SECP256R1>>8);buf[p++]=(TLS_GROUP_SECP256R1&0xFF);
        PUT16(buf+p,P256_POINT_LEN);p+=2;
        memcpy(buf+p,p256_pub,P256_POINT_LEN);p+=P256_POINT_LEN;
        buf[p++]=(TLS_GROUP_SECP384R1>>8);buf[p++]=(TLS_GROUP_SECP384R1&0xFF);
        PUT16(buf+p,P384_POINT_LEN);p+=2;
        memcpy(buf+p,p384_pub,P384_POINT_LEN);p+=P384_POINT_LEN;
    }

    /* supported_versions (TLS 1.3 preferred, TLS 1.2 fallback) */
    buf[p++]=0x00;buf[p++]=0x2b;
    buf[p++]=0x00;buf[p++]=0x05; /* ext len */
    buf[p++]=0x04;               /* list len */
    buf[p++]=(TLS_VERSION_13>>8);buf[p++]=(TLS_VERSION_13&0xFF); /* TLS 1.3 */
    buf[p++]=(TLS_VERSION_12>>8);buf[p++]=(TLS_VERSION_12&0xFF); /* TLS 1.2 */

    /* ALPN (application_layer_protocol_negotiation) — offer http/1.1 */
    buf[p++]=0x00;buf[p++]=0x10; /* extension type 16 */
    buf[p++]=0x00;buf[p++]=0x0b; /* ext len = 11 */
    buf[p++]=0x00;buf[p++]=0x09; /* protocol list len = 9 */
    buf[p++]=0x08;               /* protocol name len = 8 */
    memcpy(buf+p,"http/1.1",8);p+=8;

    /* psk_key_exchange_modes extension (0x002d): always advertise psk_dhe_ke (0x01)
       so servers know we support resumption and will send NewSessionTicket */
    buf[p++]=0x00;buf[p++]=0x2d;
    buf[p++]=0x00;buf[p++]=0x02;
    buf[p++]=0x01;buf[p++]=0x01;

    /* pre_shared_key extension — MUST be final extension */
    if(sess && sess->ticket && sess->ticket_len>0) {
        /* Determine hash length for binder */
        size_t hash_len=sess->psk_len; /* 32 or 48 */
        const hash_alg *psk_alg=(hash_len==48)?&SHA384_ALG:&SHA256_ALG;

        /* pre_shared_key extension (0x0029) — MUST be last */
        /* Compute obfuscated_ticket_age */
        uint64_t now=(uint64_t)time(NULL);
        uint32_t age_ms=(uint32_t)((now-sess->timestamp)*1000);
        uint32_t obf_age=(age_ms+sess->ticket_age_add);

        /* Extension layout:
           type(2) + ext_len(2) +
           identities_len(2) + [ identity_len(2) + identity(ticket_len) + obf_age(4) ] +
           binders_len(2) + [ binder_len(1) + binder(hash_len) ]
        */
        size_t identities_inner=2+sess->ticket_len+4;
        size_t binders_inner=1+hash_len;
        size_t ext_data_len=2+identities_inner+2+binders_inner;

        buf[p++]=0x00;buf[p++]=0x29; /* extension type */
        PUT16(buf+p,(uint16_t)ext_data_len);p+=2;
        /* identities */
        PUT16(buf+p,(uint16_t)identities_inner);p+=2;
        PUT16(buf+p,(uint16_t)sess->ticket_len);p+=2;
        memcpy(buf+p,sess->ticket,sess->ticket_len);p+=sess->ticket_len;
        buf[p++]=(obf_age>>24)&0xFF;buf[p++]=(obf_age>>16)&0xFF;
        buf[p++]=(obf_age>>8)&0xFF;buf[p++]=obf_age&0xFF;
        /* Save position: partial ClientHello for binder ends here (after identities) */
        size_t truncated_ch_len=p;
        /* binders — placeholder first */
        PUT16(buf+p,(uint16_t)binders_inner);p+=2;
        buf[p++]=(uint8_t)hash_len;
        memset(buf+p,0,hash_len); /* placeholder binder */
        size_t binder_val_pos=p;
        p+=hash_len;

        /* Fill in extension and handshake lengths before computing binder */
        PUT16(buf+ext_len_pos,(uint16_t)(p-ext_len_pos-2));
        uint32_t body_len=(uint32_t)(p-4);
        buf[1]=(body_len>>16)&0xFF;buf[2]=(body_len>>8)&0xFF;buf[3]=body_len&0xFF;

        /* Compute binder (RFC 8446 §4.2.11.2):
           1. early_secret = HKDF-Extract(zero, PSK)
           2. binder_key = HKDF-Expand-Label(early_secret, "res binder", hash(""))
           3. finished_key = HKDF-Expand-Label(binder_key, "finished", "")
           4. partial_hash = Hash(ClientHello up to and including identities, not binders)
           5. binder = HMAC(finished_key, partial_hash)
        */
        uint8_t early_secret[SHA384_DIGEST_LEN];
        { const uint8_t z[SHA384_DIGEST_LEN]={0};
          hkdf_extract_u(psk_alg,z,psk_alg->digest_len,sess->psk,sess->psk_len,early_secret); }

        uint8_t binder_key[SHA384_DIGEST_LEN];
        { uint8_t empty_hash[SHA384_DIGEST_LEN];
          psk_alg->hash(NULL,0,empty_hash);
          hkdf_expand_label_u(psk_alg,early_secret,"res binder",
              empty_hash,psk_alg->digest_len,binder_key,psk_alg->digest_len); }

        uint8_t finished_key[SHA384_DIGEST_LEN];
        hkdf_expand_label_u(psk_alg,binder_key,"finished",NULL,0,
            finished_key,psk_alg->digest_len);

        /* Hash the partial ClientHello: everything up to and including identities,
           but not the binders list (RFC 8446 §4.2.11.2). Length fields are already
           set as if the full binders were present. */
        uint8_t partial_hash[SHA384_DIGEST_LEN];
        psk_alg->hash(buf,truncated_ch_len,partial_hash);

        /* binder = HMAC(finished_key, partial_hash) */
        uint8_t binder[SHA384_DIGEST_LEN];
        hmac(psk_alg,finished_key,psk_alg->digest_len,
             partial_hash,psk_alg->digest_len,binder);
        memcpy(buf+binder_val_pos,binder,hash_len);

        secure_zero(early_secret,sizeof(early_secret));
        secure_zero(binder_key,sizeof(binder_key));
        secure_zero(finished_key,sizeof(finished_key));

        return p;
    }

    /* Fill in lengths */
    PUT16(buf+ext_len_pos,(uint16_t)(p-ext_len_pos-2));
    uint32_t body_len=(uint32_t)(p-4);
    buf[1]=(body_len>>16)&0xFF;buf[2]=(body_len>>8)&0xFF;buf[3]=body_len&0xFF;
    return p;
}

/* Parse ServerHello, extract server_random and determine negotiated version.
   Returns negotiated version (TLS_VERSION_12 for TLS 1.2, TLS_VERSION_13 for TLS 1.3).
   For TLS 1.3: fills server_pub/pub_len from key_share.
   For TLS 1.2: *pub_len is set to 0. */
static uint16_t parse_server_hello(const uint8_t *msg, size_t len,
                                    uint8_t *server_pub, size_t *pub_len,
                                    uint8_t server_random[32],
                                    uint16_t *cipher_suite_out,
                                    int *psk_accepted) {
    const uint8_t *end=msg+len;
    if(len<4) die("ServerHello too short");
    if(msg[0]!=0x02) die("not ServerHello");
    uint32_t sh_len=GET24(msg+1);
    if(4+sh_len>len) die("ServerHello length exceeds record");
    const uint8_t *sh_end=msg+4+sh_len;
    const uint8_t *b=msg+4;
    /* version */
    if(b+2>sh_end) die("ServerHello truncated at version");
    b+=2;
    /* random - save it */
    if(b+32>sh_end) die("ServerHello truncated at random");
    memcpy(server_random,b,32);
    b+=32;
    /* session id */
    if(b+1>sh_end) die("ServerHello truncated at session_id len");
    uint8_t sid_len=*b++;
    if(b+sid_len>sh_end) die("ServerHello session_id exceeds message");
    b+=sid_len;
    /* cipher suite */
    if(b+2>sh_end) die("ServerHello truncated at cipher suite");
    uint16_t cs=GET16(b); b+=2;
    *cipher_suite_out=cs;
    if(cs!=TLS_AES_128_GCM_SHA256 && cs!=TLS_AES_256_GCM_SHA384 &&
       cs!=TLS_CHACHA20_POLY1305_SHA256 &&
       cs!=TLS_ECDHE_ECDSA_CHACHA_POLY && cs!=TLS_ECDHE_RSA_CHACHA_POLY &&
       cs!=TLS_ECDHE_ECDSA_AES128_GCM && cs!=TLS_ECDHE_RSA_AES128_GCM &&
       cs!=TLS_ECDHE_ECDSA_AES256_GCM && cs!=TLS_ECDHE_RSA_AES256_GCM &&
       cs!=TLS_RSA_AES256_GCM && cs!=TLS_RSA_AES128_GCM &&
       cs!=TLS_RSA_AES256_CBC && cs!=TLS_RSA_AES128_CBC &&
       cs!=TLS_ECDHE_RSA_AES256_CBC && cs!=TLS_ECDHE_RSA_AES128_CBC &&
       cs!=TLS_ECDHE_ECDSA_AES256_CBC && cs!=TLS_ECDHE_ECDSA_AES128_CBC) {
        fprintf(stderr,"cipher suite 0x%04x\n",cs);
        die("unexpected cipher suite");
    }
    /* compression */
    if(b+1>sh_end) die("ServerHello truncated at compression");
    b++;
    /* extensions (may not be present for TLS 1.2 minimal hello) */
    uint16_t version=TLS_VERSION_12; /* default TLS 1.2 */
    *pub_len=0;
    if(psk_accepted) *psk_accepted=0;
    if(b+2<=sh_end) {
        uint16_t ext_total=GET16(b); b+=2;
        const uint8_t *ext_end=b+ext_total;
        if(ext_end>sh_end) ext_end=sh_end;
        while(b+4<=ext_end) {
            uint16_t etype=GET16(b); b+=2;
            uint16_t elen=GET16(b); b+=2;
            if(b+elen>ext_end) break;
            if(etype==0x0033 && elen>=4) { /* key_share */
                uint16_t group=GET16(b);
                uint16_t klen=GET16(b+2);
                if(group==TLS_GROUP_X25519 && klen==X25519_KEY_LEN && elen>=4+X25519_KEY_LEN) {
                    memcpy(server_pub,b+4,X25519_KEY_LEN);
                    *pub_len=X25519_KEY_LEN;
                } else if(group==TLS_GROUP_X448 && klen==X448_KEY_LEN && elen>=4+X448_KEY_LEN) {
                    memcpy(server_pub,b+4,X448_KEY_LEN);
                    *pub_len=X448_KEY_LEN;
                } else if(group==TLS_GROUP_SECP256R1 && klen==P256_POINT_LEN
                          && elen>=4+P256_POINT_LEN) {
                    memcpy(server_pub,b+4,P256_POINT_LEN);
                    *pub_len=P256_POINT_LEN;
                } else if(group==TLS_GROUP_SECP384R1 && klen==P384_POINT_LEN
                          && elen>=4+P384_POINT_LEN) {
                    memcpy(server_pub,b+4,P384_POINT_LEN);
                    *pub_len=P384_POINT_LEN;
                }
            } else if(etype==0x002b && elen>=2) { /* supported_versions */
                uint16_t ver=GET16(b);
                if(ver==TLS_VERSION_13) version=TLS_VERSION_13;
            } else if(etype==0x0029 && elen>=2 && psk_accepted) { /* pre_shared_key */
                uint16_t selected=GET16(b);
                if(selected==0) *psk_accepted=1;
            }
            b+=elen;
        }
    }
    (void)end;
    /* Note: pub_len==0 with version TLS_VERSION_13 is valid for HelloRetryRequest */
    return version;
}

/* ================================================================
 * TLS cipher mode classification
 * ================================================================ */
typedef enum { CIPHER_GCM, CIPHER_CBC, CIPHER_CHACHA } cipher_mode_t;

static cipher_mode_t cipher_mode_of(uint16_t cs) {
    switch(cs) {
    case TLS_ECDHE_RSA_AES256_CBC: case TLS_ECDHE_RSA_AES128_CBC:
    case TLS_RSA_AES256_CBC: case TLS_RSA_AES128_CBC:
    case TLS_ECDHE_ECDSA_AES256_CBC: case TLS_ECDHE_ECDSA_AES128_CBC:
        return CIPHER_CBC;
    case TLS_ECDHE_ECDSA_CHACHA_POLY: case TLS_ECDHE_RSA_CHACHA_POLY:
    case TLS_CHACHA20_POLY1305_SHA256:
        return CIPHER_CHACHA;
    default:
        return CIPHER_GCM;
    }
}

/* Construct TLS 1.3 per-record nonce: IV XOR sequence number */
static void make_nonce(uint8_t nonce[AES_GCM_NONCE_LEN],
    const uint8_t iv[AES_GCM_NONCE_LEN], uint64_t seq) {
    memcpy(nonce,iv,AES_GCM_NONCE_LEN);
    for(int i=0;i<8;i++) nonce[11-i]^=(seq>>(8*i))&0xFF;
}

/* Decrypt a TLS 1.3 encrypted record.
   Returns inner content type, plaintext in pt, pt_len set. */
static int decrypt_record(const uint8_t *rec, size_t rec_len,
                           const uint8_t *key, const uint8_t iv[AES_GCM_NONCE_LEN],
                           uint64_t seq, uint8_t *pt, size_t *pt_len,
                           cipher_mode_t mode, size_t key_len) {
    if(seq==UINT64_MAX) die("sequence number overflow");
    if(rec_len<16+1) die("encrypted record too short");
    size_t ct_len=rec_len-16; /* both GCM and ChaCha20-Poly1305 use 16-byte tags */
    const uint8_t *tag=rec+ct_len;

    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce,iv,seq);

    /* AAD = record header */
    uint8_t aad[5]={TLS_RT_APPDATA,(TLS_VERSION_12>>8),(TLS_VERSION_12&0xFF),0,0};
    PUT16(aad+3,(uint16_t)rec_len);

    int r;
    if(mode==CIPHER_CHACHA)
        r=chacha20_poly1305_decrypt(key,nonce,aad,5,rec,ct_len,pt,tag);
    else
        r=aes_gcm_decrypt_impl(key,key_len,nonce,aad,5,rec,ct_len,pt,tag);
    if(r<0) die("AEAD decrypt failed");

    /* Find inner content type (last non-zero byte) */
    size_t i=ct_len;
    while(i>0 && pt[i-1]==0) i--;
    if(i==0) die("no content type in record");
    uint8_t inner_type=pt[i-1];
    *pt_len=i-1;
    if(*pt_len>TLS_MAX_PLAINTEXT) die("decrypted record exceeds maximum plaintext size");
    return inner_type;
}

/* Encrypt and send a TLS 1.3 record */
static void encrypt_and_send(int fd, uint8_t inner_type,
                              const uint8_t *data, size_t len,
                              const uint8_t *key, const uint8_t iv[AES_GCM_NONCE_LEN],
                              uint64_t seq, cipher_mode_t mode, size_t key_len) {
    if(seq==UINT64_MAX) die("sequence number overflow");
    /* Build inner plaintext: data + content_type */
    if(len>TLS_MAX_PLAINTEXT) die("TLS 1.3 record too large to encrypt");
    uint8_t *inner = malloc(len+1);
    if(!inner) die("malloc failed");
    memcpy(inner,data,len);
    inner[len]=inner_type;

    uint8_t nonce[AES_GCM_NONCE_LEN];
    make_nonce(nonce,iv,seq);

    size_t ct_len=len+1;
    uint8_t *ct=malloc(ct_len+16);
    if(!ct) die("malloc failed");
    uint8_t tag[16];

    uint8_t aad[5]={TLS_RT_APPDATA,(TLS_VERSION_12>>8),(TLS_VERSION_12&0xFF),0,0};
    PUT16(aad+3,(uint16_t)(ct_len+16));

    if(mode==CIPHER_CHACHA)
        chacha20_poly1305_encrypt(key,nonce,aad,5,inner,ct_len,ct,tag);
    else
        aes_gcm_encrypt_impl(key,key_len,nonce,aad,5,inner,ct_len,ct,tag);
    memcpy(ct+ct_len,tag,16);

    tls_send_record(fd,TLS_RT_APPDATA,ct,ct_len+16);
    free(inner); free(ct);
}

/* Build TLS 1.2 AAD / MAC header: seq(8) || type(1) || version(2) || len(2) */
static void build_tls12_aad(uint8_t aad[13], uint64_t seq,
                             uint8_t content_type, uint16_t len) {
    put_be64(aad, seq);
    aad[8]=content_type;
    aad[9]=(uint8_t)(TLS_VERSION_12>>8);
    aad[10]=(uint8_t)(TLS_VERSION_12&0xFF);
    PUT16(aad+11, len);
}

/* ================================================================
 * TLS 1.2 GCM Record Encrypt / Decrypt
 * Nonce: write_iv(4) || explicit_nonce(8, = seq_num big-endian)
 * AAD: seq_num(8) || content_type(1) || 0x0303(2) || plaintext_length(2)
 * Record body: [explicit_nonce(8)][ciphertext][tag(16)]
 * ================================================================ */
static void tls12_encrypt_and_send(int fd, uint8_t content_type,
                                     const uint8_t *data, size_t len,
                                     const uint8_t *write_key,
                                     const uint8_t write_iv[4],
                                     uint64_t seq, size_t key_len) {
    if(seq==UINT64_MAX) die("sequence number overflow");
    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, write_iv, 4);
    put_be64(nonce+4, seq);

    uint8_t aad[13];
    build_tls12_aad(aad, seq, content_type, (uint16_t)len);

    if(len>TLS_MAX_PLAINTEXT) die("TLS 1.2 record too large to encrypt");
    uint8_t *ct=malloc(len);
    if(!ct) die("malloc failed");
    uint8_t tag[AES_GCM_TAG_LEN];
    aes_gcm_encrypt_impl(write_key,key_len,nonce,aad,13,data,len,ct,tag);

    size_t rec_len=8+len+AES_GCM_TAG_LEN;
    uint8_t *rec=malloc(rec_len);
    if(!rec) die("malloc failed");
    memcpy(rec, nonce+4, 8);
    memcpy(rec+8, ct, len);
    memcpy(rec+8+len, tag, AES_GCM_TAG_LEN);

    tls_send_record(fd, content_type, rec, rec_len);
    free(ct);
    free(rec);
}

static int tls12_decrypt_record(const uint8_t *rec, size_t rec_len,
                                  uint8_t content_type,
                                  const uint8_t *read_key,
                                  const uint8_t read_iv[4],
                                  uint64_t seq,
                                  uint8_t *pt, size_t *pt_len, size_t key_len) {
    if(seq==UINT64_MAX) return -1;
    if(rec_len < 8+AES_GCM_TAG_LEN) return -1;

    uint8_t nonce[AES_GCM_NONCE_LEN];
    memcpy(nonce, read_iv, 4);
    memcpy(nonce+4, rec, 8);

    size_t ct_len = rec_len - 8 - AES_GCM_TAG_LEN;
    const uint8_t *ct = rec + 8;
    const uint8_t *tag = rec + 8 + ct_len;

    uint8_t aad[13];
    build_tls12_aad(aad, seq, content_type, (uint16_t)ct_len);

    int r=aes_gcm_decrypt_impl(read_key,key_len,nonce,aad,13,ct,ct_len,pt,tag);
    if(r<0) return -1;
    *pt_len=ct_len;
    return 0;
}

/* ================================================================
 * TLS 1.2 CBC Record Encrypt / Decrypt (MAC-then-encrypt, RFC 5246 §6.2.3.2)
 * Record body: [IV(16)][ciphertext]
 * Plaintext before encryption: [data][MAC][padding][padding_length]
 * ================================================================ */
static void tls12_encrypt_and_send_cbc(int fd, uint8_t content_type,
                                         const uint8_t *data, size_t len,
                                         const uint8_t *write_key, size_t key_len,
                                         const uint8_t *mac_key, size_t mac_key_len,
                                         const hash_alg *mac_alg, uint64_t seq) {
    /* Compute MAC: HMAC(mac_key, seq||type||version||length||data) */
    size_t mac_len=mac_alg->digest_len;
    uint8_t mac_input_hdr[13];
    build_tls12_aad(mac_input_hdr, seq, content_type, (uint16_t)len);

    /* HMAC with incremental update for header+data */
    uint8_t mac_out[48];
    {
        uint8_t k[128]={0};
        if(mac_key_len>mac_alg->block_size) mac_alg->hash(mac_key,mac_key_len,k);
        else memcpy(k,mac_key,mac_key_len);
        uint8_t ip[128],op[128];
        for(size_t i=0;i<mac_alg->block_size;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}
        union{sha1_ctx s1;sha256_ctx s2;sha384_ctx s3;}u;
        mac_alg->init(&u); mac_alg->update(&u,ip,mac_alg->block_size);
        mac_alg->update(&u,mac_input_hdr,13);
        mac_alg->update(&u,data,len);
        uint8_t inner[48]; mac_alg->final_fn(&u,inner);
        mac_alg->init(&u); mac_alg->update(&u,op,mac_alg->block_size);
        mac_alg->update(&u,inner,mac_alg->digest_len);
        mac_alg->final_fn(&u,mac_out);
    }

    /* Build plaintext: data || MAC || padding || padding_length */
    size_t unpadded=len+mac_len;
    uint8_t pad_len=(uint8_t)(AES_BLOCK_SIZE-1-(unpadded%AES_BLOCK_SIZE));
    size_t padded_len=unpadded+pad_len+1;
    uint8_t *plain=malloc(padded_len);
    if(!plain) die("malloc failed");
    memcpy(plain,data,len);
    memcpy(plain+len,mac_out,mac_len);
    memset(plain+unpadded,pad_len,pad_len+1);

    /* Generate random IV and encrypt */
    uint8_t iv[AES_BLOCK_SIZE];
    random_bytes(iv,AES_BLOCK_SIZE);
    uint8_t *ct_body=malloc(padded_len);
    if(!ct_body) die("malloc failed");
    aes_cbc_encrypt(write_key,key_len,iv,plain,padded_len,ct_body);
    free(plain);

    /* Send record: [IV][ciphertext] */
    size_t rec_len=AES_BLOCK_SIZE+padded_len;
    uint8_t *rec=malloc(rec_len);
    if(!rec) die("malloc failed");
    memcpy(rec,iv,AES_BLOCK_SIZE);
    memcpy(rec+AES_BLOCK_SIZE,ct_body,padded_len);
    tls_send_record(fd,content_type,rec,rec_len);
    free(ct_body);
    free(rec);
}

static int tls12_decrypt_record_cbc(const uint8_t *rec, size_t rec_len,
                                      uint8_t content_type,
                                      const uint8_t *read_key, size_t key_len,
                                      const uint8_t *mac_key, size_t mac_key_len,
                                      const hash_alg *mac_alg, uint64_t seq,
                                      uint8_t *pt, size_t *pt_len) {
    if(rec_len<2*AES_BLOCK_SIZE) return -1; /* need at least IV + one block */
    const uint8_t *iv=rec;
    const uint8_t *ct=rec+AES_BLOCK_SIZE;
    size_t ct_len=rec_len-AES_BLOCK_SIZE;
    if(ct_len%AES_BLOCK_SIZE!=0) return -1;

    /* Decrypt */
    uint8_t *plain=malloc(ct_len);
    if(!plain) die("malloc failed");
    aes_cbc_decrypt(read_key,key_len,iv,ct,ct_len,plain);

    /* Check and strip padding — constant-time: no early returns before MAC check */
    uint8_t pad_val=plain[ct_len-1];
    uint8_t pad_ok=0;
    /* Flag invalid padding length, and clamp loop to prevent buffer underflow */
    pad_ok |= (uint8_t)((pad_val >= ct_len) ? 0xFF : 0);
    size_t check_len = (pad_val < ct_len) ? (size_t)(pad_val+1) : 0;
    for(size_t i=0;i<check_len;i++)
        pad_ok|=plain[ct_len-1-i]^pad_val;

    size_t mac_len=mac_alg->digest_len;
    /* If pad_val+1+mac_len > ct_len, set error flag but don't return early.
       Use a safe content_len that won't underflow regardless. */
    uint8_t len_ok = (pad_val+1+mac_len <= ct_len) ? 1 : 0;
    pad_ok |= (uint8_t)(len_ok ? 0 : 0xFF);
    /* Use safe content_len: if invalid, use 0 to avoid underflow; MAC will fail anyway */
    size_t content_len = len_ok ? ct_len-pad_val-1-mac_len : 0;

    /* Extract MAC and compute expected MAC */
    const uint8_t *received_mac=plain+content_len;

    uint8_t mac_input_hdr[13];
    build_tls12_aad(mac_input_hdr, seq, content_type, (uint16_t)content_len);

    uint8_t expected_mac[48];
    {
        uint8_t k[128]={0};
        if(mac_key_len>mac_alg->block_size) mac_alg->hash(mac_key,mac_key_len,k);
        else memcpy(k,mac_key,mac_key_len);
        uint8_t ip[128],op[128];
        for(size_t i=0;i<mac_alg->block_size;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}
        union{sha1_ctx s1;sha256_ctx s2;sha384_ctx s3;}u;
        mac_alg->init(&u); mac_alg->update(&u,ip,mac_alg->block_size);
        mac_alg->update(&u,mac_input_hdr,13);
        mac_alg->update(&u,plain,content_len);
        uint8_t inner[48]; mac_alg->final_fn(&u,inner);
        mac_alg->init(&u); mac_alg->update(&u,op,mac_alg->block_size);
        mac_alg->update(&u,inner,mac_alg->digest_len);
        mac_alg->final_fn(&u,expected_mac);
    }

    int mac_ok=ct_memeq(expected_mac,received_mac,mac_len);
    if(!mac_ok||pad_ok!=0){free(plain);return -1;}

    memcpy(pt,plain,content_len);
    *pt_len=content_len;
    free(plain);
    return 0;
}

/* ================================================================
 * TLS 1.2 ChaCha20-Poly1305 Record Encrypt / Decrypt
 * Nonce: implicit IV(12) XOR padded seq (same as TLS 1.3)
 * AAD: seq(8) || type(1) || version(2) || plaintext_len(2)
 * Record body: ciphertext || tag(16), NO explicit nonce prefix
 * ================================================================ */
static void tls12_encrypt_and_send_chacha(int fd, uint8_t content_type,
                                            const uint8_t *data, size_t len,
                                            const uint8_t *write_key,
                                            const uint8_t write_iv[12],
                                            uint64_t seq) {
    if(seq==UINT64_MAX) die("sequence number overflow");
    uint8_t nonce[12];
    make_nonce(nonce,write_iv,seq);

    uint8_t aad[13];
    build_tls12_aad(aad, seq, content_type, (uint16_t)len);

    if(len>TLS_MAX_PLAINTEXT) die("TLS 1.2 ChaCha record too large");
    uint8_t *ct=malloc(len);
    if(!ct) die("malloc failed");
    uint8_t tag[CHACHA20_POLY1305_TAG_LEN];
    chacha20_poly1305_encrypt(write_key,nonce,aad,13,data,len,ct,tag);

    size_t rec_len=len+CHACHA20_POLY1305_TAG_LEN;
    uint8_t *rec=malloc(rec_len);
    if(!rec) die("malloc failed");
    memcpy(rec,ct,len);
    memcpy(rec+len,tag,CHACHA20_POLY1305_TAG_LEN);
    tls_send_record(fd,content_type,rec,rec_len);
    free(ct); free(rec);
}

static int tls12_decrypt_record_chacha(const uint8_t *rec, size_t rec_len,
                                         uint8_t content_type,
                                         const uint8_t *read_key,
                                         const uint8_t read_iv[12],
                                         uint64_t seq,
                                         uint8_t *pt, size_t *pt_len) {
    if(seq==UINT64_MAX) return -1;
    if(rec_len<CHACHA20_POLY1305_TAG_LEN) return -1;
    size_t ct_len=rec_len-CHACHA20_POLY1305_TAG_LEN;
    const uint8_t *tag=rec+ct_len;

    uint8_t nonce[12];
    make_nonce(nonce,read_iv,seq);

    uint8_t aad[13];
    build_tls12_aad(aad, seq, content_type, (uint16_t)ct_len);

    int r=chacha20_poly1305_decrypt(read_key,nonce,aad,13,rec,ct_len,pt,tag);
    if(r<0) return -1;
    *pt_len=ct_len;
    return 0;
}

/* ================================================================
 * TLS 1.2 cipher dispatch helpers
 * ================================================================ */
static void tls12_send_encrypted(int fd, uint8_t ct, const uint8_t *pt, size_t len,
                                 cipher_mode_t mode,
                                 const uint8_t *wk, size_t key_len,
                                 const uint8_t *mk, size_t mk_len,
                                 const hash_alg *mac_alg,
                                 const uint8_t *wiv, uint64_t seq) {
    if(mode==CIPHER_CBC)
        tls12_encrypt_and_send_cbc(fd,ct,pt,len,wk,key_len,mk,mk_len,mac_alg,seq);
    else if(mode==CIPHER_CHACHA)
        tls12_encrypt_and_send_chacha(fd,ct,pt,len,wk,wiv,seq);
    else
        tls12_encrypt_and_send(fd,ct,pt,len,wk,wiv,seq,key_len);
}

static int tls12_recv_decrypt(const uint8_t *rec, size_t rec_len, uint8_t ct,
                              cipher_mode_t mode,
                              const uint8_t *rk, size_t key_len,
                              const uint8_t *mk, size_t mk_len,
                              const hash_alg *mac_alg,
                              const uint8_t *riv, uint64_t seq,
                              uint8_t *pt, size_t *pt_len) {
    if(mode==CIPHER_CBC)
        return tls12_decrypt_record_cbc(rec,rec_len,ct,rk,key_len,mk,mk_len,mac_alg,seq,pt,pt_len);
    else if(mode==CIPHER_CHACHA)
        return tls12_decrypt_record_chacha(rec,rec_len,ct,rk,riv,seq,pt,pt_len);
    else
        return tls12_decrypt_record(rec,rec_len,ct,rk,riv,seq,pt,pt_len,key_len);
}

/* ================================================================
 * Unified signature verification dispatch
 * ================================================================ */
static int verify_sig_algo(uint16_t algo, const uint8_t *data, size_t data_len,
                           const uint8_t *sig, size_t sig_len,
                           const x509_cert *leaf) {
    /* In TLS 1.2 the SignatureAndHashAlgorithm field encodes hash and
       signature type independently (RFC 5246 §7.4.1.4.1).  For ECDSA the
       curve is determined by the certificate key, not the algorithm ID.
       We therefore pick the hash from the algorithm and the ECDSA curve
       from the leaf key. */
    if(algo==TLS_SIG_ECDSA_SECP256R1_SHA256 ||
       algo==TLS_SIG_ECDSA_SECP384R1_SHA384) {
        if(leaf->key_type!=1) return 0;
        int use_384_hash = (algo==TLS_SIG_ECDSA_SECP384R1_SHA384);
        if(use_384_hash) {
            uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(data,data_len,h);
            if(leaf->pubkey_len==P256_POINT_LEN)
                return ecdsa_p256_verify(h,SHA384_DIGEST_LEN,sig,sig_len,leaf->pubkey,leaf->pubkey_len);
            if(leaf->pubkey_len==P384_POINT_LEN)
                return ecdsa_p384_verify(h,SHA384_DIGEST_LEN,sig,sig_len,leaf->pubkey,leaf->pubkey_len);
        } else {
            uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(data,data_len,h);
            if(leaf->pubkey_len==P256_POINT_LEN)
                return ecdsa_p256_verify(h,SHA256_DIGEST_LEN,sig,sig_len,leaf->pubkey,leaf->pubkey_len);
            if(leaf->pubkey_len==P384_POINT_LEN)
                return ecdsa_p384_verify(h,SHA256_DIGEST_LEN,sig,sig_len,leaf->pubkey,leaf->pubkey_len);
        }
    } else if(algo==TLS_SIG_RSA_PKCS1_SHA256) {
        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(data,data_len,h);
        if(leaf->key_type==2)
            return rsa_pkcs1_verify(h,SHA256_DIGEST_LEN,DI_SHA256,sizeof(DI_SHA256),
                sig,sig_len,leaf->rsa_n,leaf->rsa_n_len,leaf->rsa_e,leaf->rsa_e_len);
    } else if(algo==TLS_SIG_RSA_PSS_SHA256) {
        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(data,data_len,h);
        if(leaf->key_type==2)
            return rsa_pss_verify(h,SHA256_DIGEST_LEN,sha256_hash,
                sig,sig_len,leaf->rsa_n,leaf->rsa_n_len,leaf->rsa_e,leaf->rsa_e_len);
    } else if(algo==TLS_SIG_RSA_PSS_SHA384) {
        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(data,data_len,h);
        if(leaf->key_type==2)
            return rsa_pss_verify(h,SHA384_DIGEST_LEN,sha384_hash,
                sig,sig_len,leaf->rsa_n,leaf->rsa_n_len,leaf->rsa_e,leaf->rsa_e_len);
    } else if(algo==TLS_SIG_RSA_PKCS1_SHA384) {
        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(data,data_len,h);
        if(leaf->key_type==2)
            return rsa_pkcs1_verify(h,SHA384_DIGEST_LEN,DI_SHA384,sizeof(DI_SHA384),
                sig,sig_len,leaf->rsa_n,leaf->rsa_n_len,leaf->rsa_e,leaf->rsa_e_len);
    } else if(algo==TLS_SIG_ED25519) {
        /* Ed25519 is a pure signature scheme — pass raw content, no pre-hash */
        if(leaf->key_type!=3||leaf->pubkey_len!=32) return 0;
        return ed25519_verify(leaf->pubkey,data,data_len,sig);
    } else if(algo==TLS_SIG_ED448) {
        if(leaf->key_type!=3||leaf->pubkey_len!=57) return 0;
        return ed448_verify(leaf->pubkey,data,data_len,sig);
    }
    return 0;
}

/* ================================================================
 * Connection context for TLS handshake dispatch
 * ================================================================ */
typedef struct {
    int fd;
    const char *host, *path;
    uint8_t client_random[32], server_random[32];
    uint8_t p256_priv[P256_SCALAR_LEN], p256_pub[P256_POINT_LEN];
    uint8_t p384_priv[P384_SCALAR_LEN], p384_pub[P384_POINT_LEN];
    uint8_t x25519_priv[X25519_KEY_LEN], x25519_pub[X25519_KEY_LEN];
    uint8_t x448_priv[X448_KEY_LEN], x448_pub[X448_KEY_LEN];
    uint8_t server_pub[P384_POINT_LEN]; size_t server_pub_len;
    uint16_t cipher_suite;
    sha256_ctx transcript;
    sha384_ctx transcript384;
    size_t sh_leftover;
    uint8_t sh_leftover_data[REC_BUF_SIZE];
} tls_conn;

/* ================================================================
 * TLS 1.2 Key Derivation
 * ================================================================ */
typedef struct {
    uint8_t c_wk[32], s_wk[32];
    uint8_t c_wiv[16], s_wiv[16];
    uint8_t c_mk[20], s_mk[20];
    uint8_t master[48];
    size_t key_len, mac_key_len, iv_len;
    int is_aes256, prf_is_sha384;
    const hash_alg *alg, *mac_alg;
} tls12_keys;

static void tls12_derive_keys(tls12_keys *k, uint16_t cipher_suite,
                              cipher_mode_t mode,
                              const uint8_t *shared, size_t shared_len,
                              const uint8_t client_random[32],
                              const uint8_t server_random[32]) {
    k->is_aes256 = (cipher_suite==TLS_ECDHE_ECDSA_AES256_GCM
                 || cipher_suite==TLS_ECDHE_RSA_AES256_GCM
                 || cipher_suite==TLS_RSA_AES256_GCM
                 || cipher_suite==TLS_ECDHE_RSA_AES256_CBC
                 || cipher_suite==TLS_RSA_AES256_CBC
                 || cipher_suite==TLS_ECDHE_ECDSA_AES256_CBC);
    k->prf_is_sha384 = (cipher_suite==TLS_ECDHE_ECDSA_AES256_GCM
                      || cipher_suite==TLS_ECDHE_RSA_AES256_GCM
                      || cipher_suite==TLS_RSA_AES256_GCM);
    k->alg = k->prf_is_sha384 ? &SHA384_ALG : &SHA256_ALG;
    if(mode==CIPHER_CHACHA) k->key_len=32;
    else k->key_len = k->is_aes256 ? AES256_KEY_LEN : AES128_KEY_LEN;
    k->mac_key_len = (mode==CIPHER_CBC) ? SHA1_DIGEST_LEN : 0;
    if(mode==CIPHER_CBC) k->iv_len=AES_BLOCK_SIZE;
    else if(mode==CIPHER_CHACHA) k->iv_len=12;
    else k->iv_len=4;
    k->mac_alg = (mode==CIPHER_CBC) ? &SHA1_ALG : NULL;

    uint8_t pms_seed[64];
    memcpy(pms_seed, client_random, 32);
    memcpy(pms_seed+32, server_random, 32);
    tls12_prf_u(k->alg, shared, shared_len, "master secret", pms_seed, 64, k->master, 48);

    uint8_t ke_seed[64];
    memcpy(ke_seed, server_random, 32);
    memcpy(ke_seed+32, client_random, 32);

    size_t kb_len = k->mac_key_len*2 + k->key_len*2 + k->iv_len*2;
    uint8_t key_block[136];
    tls12_prf_u(k->alg, k->master, 48, "key expansion", ke_seed, 64, key_block, kb_len);

    memset(k->c_mk,0,sizeof(k->c_mk)); memset(k->s_mk,0,sizeof(k->s_mk));
    memset(k->c_wiv,0,sizeof(k->c_wiv)); memset(k->s_wiv,0,sizeof(k->s_wiv));
    size_t off=0;
    memcpy(k->c_mk, key_block+off, k->mac_key_len); off+=k->mac_key_len;
    memcpy(k->s_mk, key_block+off, k->mac_key_len); off+=k->mac_key_len;
    memcpy(k->c_wk, key_block+off, k->key_len); off+=k->key_len;
    memcpy(k->s_wk, key_block+off, k->key_len); off+=k->key_len;
    memcpy(k->c_wiv, key_block+off, k->iv_len); off+=k->iv_len;
    memcpy(k->s_wiv, key_block+off, k->iv_len);

    secure_zero(pms_seed,sizeof(pms_seed));
    secure_zero(ke_seed,sizeof(ke_seed));
    secure_zero(key_block,sizeof(key_block));
}

/* ================================================================
 * TLS 1.2 Handshake Helpers
 * ================================================================ */
typedef struct {
    uint8_t *cert_msg;       /* heap-allocated, caller frees */
    size_t cert_msg_len;
    uint8_t ske_pubkey[P384_POINT_LEN];
    uint16_t ske_curve;
} tls12_server_params;

/* Phase 1: Read Certificate, ServerKeyExchange, ServerHelloDone */
static void tls12_read_server_msgs(int fd, sha256_ctx *transcript,
                                    sha384_ctx *transcript384,
                                    const uint8_t *leftover, size_t leftover_len,
                                    int is_rsa_kex,
                                    const uint8_t client_random[32],
                                    const uint8_t server_random[32],
                                    const char *host,
                                    tls12_server_params *out) {
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    uint8_t hs12_buf[HS_BUF_SIZE]; size_t hs12_len=0;
    int got_server_done=0;

    if(leftover_len>0 && leftover_len<=sizeof(hs12_buf)) {
        memcpy(hs12_buf, leftover, leftover_len);
        hs12_len=leftover_len;
    }

    while(!got_server_done) {
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype!=TLS_RT_HANDSHAKE) die("expected handshake record in TLS 1.2");

        if(hs12_len+rec_len>sizeof(hs12_buf)) die("TLS 1.2 handshake buffer overflow");
        memcpy(hs12_buf+hs12_len, rec, rec_len);
        hs12_len+=rec_len;

        size_t pos=0;
        while(pos+4<=hs12_len) {
            uint8_t mtype=hs12_buf[pos];
            uint32_t mlen=GET24(hs12_buf+pos+1);
            if(pos+4+mlen>hs12_len) break;
            size_t msg_total=4+mlen;

            sha256_update(transcript, hs12_buf+pos, msg_total);
            sha384_update(transcript384, hs12_buf+pos, msg_total);

            switch(mtype) {
                case 11: /* Certificate */
                    if(tls_verbose) fprintf(stderr,"  Certificate (%u bytes)\n",(unsigned)mlen);
                    free(out->cert_msg);
                    out->cert_msg=malloc(mlen);
                    if(!out->cert_msg) die("malloc failed");
                    memcpy(out->cert_msg, hs12_buf+pos+4, mlen);
                    out->cert_msg_len=mlen;
                    break;
                case 12: { /* ServerKeyExchange */
                    if(is_rsa_kex)
                        die("unexpected ServerKeyExchange for RSA key transport");
                    if(tls_verbose) fprintf(stderr,"  ServerKeyExchange (%u bytes)\n",(unsigned)mlen);
                    if(mlen<8) die("ServerKeyExchange too short");
                    const uint8_t *ske=hs12_buf+pos+4;
                    if(ske[0]!=0x03) die("expected named_curve type in SKE");
                    out->ske_curve=GET16(ske+1);
                    uint8_t pk_len=ske[3];
                    if(out->ske_curve==TLS_GROUP_X25519) {
                        if(pk_len!=X25519_KEY_LEN)
                            die("expected 32-byte X25519 key");
                    } else if(out->ske_curve==TLS_GROUP_X448) {
                        if(pk_len!=X448_KEY_LEN)
                            die("expected 56-byte X448 key");
                    } else if(out->ske_curve==TLS_GROUP_SECP256R1) {
                        if(pk_len!=P256_POINT_LEN)
                            die("expected uncompressed P-256 point");
                    } else if(out->ske_curve==TLS_GROUP_SECP384R1) {
                        if(pk_len!=P384_POINT_LEN)
                            die("expected uncompressed P-384 point");
                    } else die("unsupported curve in SKE");
                    if(4+(uint32_t)pk_len>mlen) die("SKE pubkey truncated");
                    memcpy(out->ske_pubkey, ske+4, pk_len);

                    size_t params_len=4+pk_len;
                    if(params_len+4>mlen)
                        die("SKE signature header truncated");
                    const uint8_t *sig_ptr=ske+params_len;
                    uint16_t sig_algo=GET16(sig_ptr); sig_ptr+=2;
                    uint16_t sig_len_val=GET16(sig_ptr); sig_ptr+=2;
                    if(params_len+4+sig_len_val>mlen)
                        die("SKE signature truncated");

                    if(sig_algo!=TLS_SIG_ECDSA_SECP256R1_SHA256 &&
                       sig_algo!=TLS_SIG_ECDSA_SECP384R1_SHA384 &&
                       sig_algo!=TLS_SIG_RSA_PSS_SHA256 &&
                       sig_algo!=TLS_SIG_RSA_PSS_SHA384 &&
                       sig_algo!=TLS_SIG_RSA_PKCS1_SHA256 &&
                       sig_algo!=TLS_SIG_RSA_PKCS1_SHA384 &&
                       sig_algo!=TLS_SIG_ED25519 &&
                       sig_algo!=TLS_SIG_ED448)
                        die("SKE signature algorithm not in offered list");

                    uint8_t signed_data[256];
                    memcpy(signed_data, client_random, 32);
                    memcpy(signed_data+32, server_random, 32);
                    memcpy(signed_data+64, ske, params_len);
                    size_t signed_len=64+params_len;

                    if(!out->cert_msg)
                        die("Certificate must precede ServerKeyExchange");
                    if(out->cert_msg_len<6)
                        die("Certificate message too short");
                    const uint8_t *cp=out->cert_msg;
                    uint32_t list_len12=GET24(cp); cp+=3;
                    if(3+list_len12>out->cert_msg_len)
                        die("Certificate list length exceeds message");
                    if(list_len12<3) die("Certificate list too short");
                    uint32_t first_cert_len=GET24(cp); cp+=3;
                    if(6+first_cert_len>out->cert_msg_len)
                        die("First certificate exceeds message");
                    x509_cert leaf;
                    if(x509_parse(&leaf,cp,first_cert_len)!=0)
                        die("Failed to parse leaf cert");

                    int sig_ok=verify_sig_algo(sig_algo,signed_data,
                        signed_len,sig_ptr,sig_len_val,&leaf);
                    if(!sig_ok)
                        die("ServerKeyExchange signature verification failed");
                    if(tls_verbose) fprintf(stderr,"    SKE signature verified (algo=0x%04x)\n",
                           sig_algo);
                    break;
                }
                case 14: /* ServerHelloDone */
                    if(tls_verbose) fprintf(stderr,"  ServerHelloDone\n");
                    got_server_done=1;
                    break;
                default:
                    if(tls_verbose) fprintf(stderr,"  TLS 1.2 handshake msg type %d (%u bytes)\n",
                           mtype,(unsigned)mlen);
                    break;
            }
            pos+=msg_total;
        }
        if(pos>0 && pos<hs12_len) {
            memmove(hs12_buf, hs12_buf+pos, hs12_len-pos);
            hs12_len-=pos;
        } else if(pos==hs12_len) {
            hs12_len=0;
        }
    }

    if(out->cert_msg) {
        if(tls_verbose) fprintf(stderr,"  Validating certificate chain...\n");
        if(verify_cert_chain(out->cert_msg,out->cert_msg_len,host,0)<0)
            die("Certificate verification failed");
    }
}

/* Phase 2: Send ClientKeyExchange, compute shared secret, derive keys */
static void tls12_do_key_exchange(int fd, sha256_ctx *transcript,
                                   sha384_ctx *transcript384,
                                   const tls12_server_params *srv,
                                   uint16_t cipher_suite, cipher_mode_t mode,
                                   int is_rsa_kex,
                                   uint8_t p256_priv[P256_SCALAR_LEN],
                                   const uint8_t p256_pub[P256_POINT_LEN],
                                   uint8_t p384_priv[P384_SCALAR_LEN],
                                   const uint8_t p384_pub[P384_POINT_LEN],
                                   uint8_t x25519_priv[X25519_KEY_LEN],
                                   const uint8_t x25519_pub[X25519_KEY_LEN],
                                   uint8_t x448_priv[X448_KEY_LEN],
                                   const uint8_t x448_pub[X448_KEY_LEN],
                                   const uint8_t client_random[32],
                                   const uint8_t server_random[32],
                                   tls12_keys *tk) {
    uint8_t ss12[X448_KEY_LEN]; size_t ss12_len; /* X448_KEY_LEN=56 is largest */
    if(is_rsa_kex) {
        if(!srv->cert_msg) die("No certificate for RSA key exchange");
        if(srv->cert_msg_len<6) die("Certificate message too short");
        const uint8_t *cp2=srv->cert_msg;
        uint32_t ll2=GET24(cp2); cp2+=3;
        if(3+ll2>srv->cert_msg_len) die("cert list length");
        if(ll2<3) die("cert list too short");
        uint32_t cl2=GET24(cp2); cp2+=3;
        if(6+cl2>srv->cert_msg_len) die("first cert exceeds message");
        x509_cert leaf;
        if(x509_parse(&leaf,cp2,cl2)!=0)
            die("Failed to parse leaf cert for RSA kex");
        if(leaf.key_type!=2) die("RSA key transport requires RSA cert");

        uint8_t pms[48];
        pms[0]=0x03; pms[1]=0x03;
        random_bytes(pms+2,46);

        uint8_t encrypted_pms[512];
        if(rsa_encrypt(pms,48,leaf.rsa_n,leaf.rsa_n_len,
                       leaf.rsa_e,leaf.rsa_e_len,encrypted_pms)<0)
            die("RSA encrypt failed");

        size_t enc_len=leaf.rsa_n_len;
        uint8_t cke[4+2+512];
        uint32_t cke_body_len=(uint32_t)(2+enc_len);
        cke[0]=0x10;
        cke[1]=(cke_body_len>>16)&0xFF;
        cke[2]=(cke_body_len>>8)&0xFF;
        cke[3]=cke_body_len&0xFF;
        PUT16(cke+4,(uint16_t)enc_len);
        memcpy(cke+6,encrypted_pms,enc_len);
        size_t cke_total=4+2+enc_len;
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,cke_total);
        sha256_update(transcript, cke, cke_total);
        sha384_update(transcript384, cke, cke_total);

        memcpy(ss12,pms,48);
        ss12_len=48;
        secure_zero(pms,sizeof(pms));
        if(tls_verbose) fprintf(stderr,"Sent ClientKeyExchange (RSA encrypted PMS, %zu bytes)\n",
               enc_len);
    } else if(srv->ske_curve==TLS_GROUP_X25519) {
        uint8_t cke[5+X25519_KEY_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0;
        cke[3]=X25519_KEY_LEN+1; cke[4]=X25519_KEY_LEN;
        memcpy(cke+5, x25519_pub, X25519_KEY_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(transcript, cke, sizeof(cke));
        sha384_update(transcript384, cke, sizeof(cke));
        if(x25519_shared_secret(x25519_priv, srv->ske_pubkey, ss12)<0)
            die("X25519 shared secret is zero");
        ss12_len=X25519_KEY_LEN;
        if(tls_verbose) fprintf(stderr,"Sent ClientKeyExchange\n"
               "Computed ECDHE shared secret (X25519)\n");
    } else if(srv->ske_curve==TLS_GROUP_X448) {
        uint8_t cke[5+X448_KEY_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0;
        cke[3]=X448_KEY_LEN+1; cke[4]=X448_KEY_LEN;
        memcpy(cke+5, x448_pub, X448_KEY_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(transcript, cke, sizeof(cke));
        sha384_update(transcript384, cke, sizeof(cke));
        if(x448_shared_secret(x448_priv, srv->ske_pubkey, ss12)<0)
            die("X448 shared secret is zero");
        ss12_len=X448_KEY_LEN;
        if(tls_verbose) fprintf(stderr,"Sent ClientKeyExchange\n"
               "Computed ECDHE shared secret (X448)\n");
    } else if(srv->ske_curve==TLS_GROUP_SECP256R1) {
        uint8_t cke[5+P256_POINT_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0;
        cke[3]=P256_POINT_LEN+1; cke[4]=P256_POINT_LEN;
        memcpy(cke+5, p256_pub, P256_POINT_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(transcript, cke, sizeof(cke));
        sha384_update(transcript384, cke, sizeof(cke));
        ecdhe_p256_shared_secret(p256_priv, srv->ske_pubkey, ss12);
        ss12_len=P256_SCALAR_LEN;
        if(tls_verbose) fprintf(stderr,"Sent ClientKeyExchange\n"
               "Computed ECDHE shared secret (P-256)\n");
    } else {
        uint8_t cke[5+P384_POINT_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0;
        cke[3]=P384_POINT_LEN+1; cke[4]=P384_POINT_LEN;
        memcpy(cke+5, p384_pub, P384_POINT_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(transcript, cke, sizeof(cke));
        sha384_update(transcript384, cke, sizeof(cke));
        ecdhe_p384_shared_secret(p384_priv, srv->ske_pubkey, ss12);
        ss12_len=P384_SCALAR_LEN;
        if(tls_verbose) fprintf(stderr,"Sent ClientKeyExchange\n"
               "Computed ECDHE shared secret (P-384)\n");
    }
    secure_zero(p256_priv,P256_SCALAR_LEN);
    secure_zero(p384_priv,P384_SCALAR_LEN);
    secure_zero(x25519_priv,X25519_KEY_LEN);
    secure_zero(x448_priv,X448_KEY_LEN);

    tls12_derive_keys(tk, cipher_suite, mode, ss12, ss12_len,
                      client_random, server_random);
    secure_zero(ss12,sizeof(ss12));
    if(tls_verbose) fprintf(stderr,"Derived TLS 1.2 traffic keys\n");
}

/* Phase 3: Exchange CCS and Finished messages */
static void tls12_exchange_finished(int fd, cipher_mode_t mode,
                                     const tls12_keys *tk,
                                     sha256_ctx *transcript,
                                     sha384_ctx *transcript384) {
    /* Send ChangeCipherSpec */
    { uint8_t ccs=1; tls_send_record(fd,TLS_RT_CCS,&ccs,1); }
    if(tls_verbose) fprintf(stderr,"Sent ChangeCipherSpec\n");

    /* Send Finished (encrypted) */
    {
        uint8_t th12[SHA384_DIGEST_LEN];
        size_t th12_len;
        if(tk->prf_is_sha384) {
            sha384_ctx tc384=*transcript384; sha384_final(&tc384,th12);
            th12_len=SHA384_DIGEST_LEN;
        } else {
            sha256_ctx tc=*transcript; sha256_final(&tc,th12);
            th12_len=SHA256_DIGEST_LEN;
        }

        uint8_t verify_data[12];
        tls12_prf_u(tk->alg, tk->master, 48, "client finished",
                    th12, th12_len, verify_data, 12);

        uint8_t fin_msg[16];
        fin_msg[0]=0x14;
        fin_msg[1]=0; fin_msg[2]=0; fin_msg[3]=12;
        memcpy(fin_msg+4, verify_data, 12);

        tls12_send_encrypted(fd,TLS_RT_HANDSHAKE,fin_msg,16,
            mode,tk->c_wk,tk->key_len,tk->c_mk,tk->mac_key_len,
            tk->mac_alg,tk->c_wiv,0);
        sha256_update(transcript, fin_msg, 16);
        sha384_update(transcript384, fin_msg, 16);
        if(tls_verbose) fprintf(stderr,"Sent Finished (encrypted)\n");
    }

    /* Receive ChangeCipherSpec */
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype!=TLS_RT_CCS) die("expected ChangeCipherSpec from server");
    if(tls_verbose) fprintf(stderr,"Received ChangeCipherSpec\n");

    /* Receive server Finished (encrypted) */
    rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype!=TLS_RT_HANDSHAKE) die("expected Finished from server");
    {
        uint8_t pt12[256]; size_t pt12_len;
        int dec_ok=tls12_recv_decrypt(rec,rec_len,TLS_RT_HANDSHAKE,
            mode,tk->s_wk,tk->key_len,tk->s_mk,tk->mac_key_len,
            tk->mac_alg,tk->s_wiv,0,pt12,&pt12_len);
        if(dec_ok<0) die("Failed to decrypt server Finished");
        if(pt12[0]!=0x14) die("expected Finished message type");
        if(pt12_len<4||GET24(pt12+1)!=12)
            die("Server Finished length mismatch");

        uint8_t th12_sf[SHA384_DIGEST_LEN];
        size_t th12_sf_len;
        if(tk->prf_is_sha384) {
            sha384_ctx tc384=*transcript384; sha384_final(&tc384,th12_sf);
            th12_sf_len=SHA384_DIGEST_LEN;
        } else {
            sha256_ctx tc=*transcript; sha256_final(&tc,th12_sf);
            th12_sf_len=SHA256_DIGEST_LEN;
        }
        uint8_t expected[12];
        tls12_prf_u(tk->alg, tk->master, 48, "server finished",
                    th12_sf, th12_sf_len, expected, 12);
        if(!ct_memeq(expected, pt12+4, 12))
            die("Server Finished verify failed!");
        if(tls_verbose) fprintf(stderr,"Server Finished VERIFIED\n");
    }
}

/* ---- HTTP response output: strips headers and decodes chunked TE ---- */
static struct {
    int state;       /* 0=headers 1=body 2=chunk_size 3=chunk_data 4=chunk_crlf 5=done */
    int chunked;
    int hex_done;
    size_t chunk_rem;
    uint8_t hdr[16384];
    size_t hdr_len;
    uint8_t *body;      /* accumulated body */
    size_t body_len;    /* current length */
    size_t body_cap;    /* allocated capacity */
} ho;

static void http_output_init(void) { memset(&ho,0,sizeof(ho)); }

static void ho_append(const uint8_t *data, size_t len) {
    if(ho.body_len + len > ho.body_cap) {
        size_t new_cap = ho.body_cap ? ho.body_cap * 2 : 4096;
        while(new_cap < ho.body_len + len) new_cap *= 2;
        ho.body = realloc(ho.body, new_cap);
        if(!ho.body) die("realloc");
        ho.body_cap = new_cap;
    }
    memcpy(ho.body + ho.body_len, data, len);
    ho.body_len += len;
}

static void http_output(const uint8_t *d, size_t len) {
    size_t i=0;
    while(i<len) {
        switch(ho.state) {
        case 0: /* accumulate headers until \r\n\r\n */
            while(i<len) {
                if(ho.hdr_len<sizeof(ho.hdr)-1)
                    ho.hdr[ho.hdr_len++]=d[i];
                i++;
                if(ho.hdr_len>=4 &&
                   ho.hdr[ho.hdr_len-4]=='\r' && ho.hdr[ho.hdr_len-3]=='\n' &&
                   ho.hdr[ho.hdr_len-2]=='\r' && ho.hdr[ho.hdr_len-1]=='\n') {
                    if(tls_verbose) fwrite(ho.hdr,1,ho.hdr_len,stderr);
                    ho.hdr[ho.hdr_len]='\0';
                    /* scan for Transfer-Encoding: chunked */
                    for(const char *p=(char*)ho.hdr; *p; ) {
                        const char *te="transfer-encoding:";
                        const char *a=p, *b=te;
                        while(*b && *a!='\n') {
                            char ca=*a, cb=*b;
                            if(ca>='A'&&ca<='Z') ca+=32;
                            if(ca!=cb) break;
                            a++; b++;
                        }
                        if(!*b) {
                            while(*a==' ') a++;
                            const char *ck="chunked";
                            const char *x=a, *y=ck;
                            while(*y && *x!='\r' && *x!='\n') {
                                char cx=*x;
                                if(cx>='A'&&cx<='Z') cx+=32;
                                if(cx!=*y) break;
                                x++; y++;
                            }
                            if(!*y) ho.chunked=1;
                        }
                        while(*p && *p!='\n') p++;
                        if(*p) p++;
                    }
                    ho.state=ho.chunked?2:1;
                    break;
                }
            }
            break;
        case 1: /* non-chunked body */
            ho_append(d+i, len-i);
            i=len;
            break;
        case 2: /* chunk size line */
            while(i<len) {
                uint8_t c=d[i++];
                if(c=='\n') {
                    ho.state=ho.chunk_rem==0?5:3;
                    ho.hex_done=0;
                    break;
                }
                if(c=='\r'||ho.hex_done) continue;
                int v;
                if(c>='0'&&c<='9') v=c-'0';
                else if(c>='a'&&c<='f') v=10+c-'a';
                else if(c>='A'&&c<='F') v=10+c-'A';
                else { ho.hex_done=1; continue; }
                ho.chunk_rem=ho.chunk_rem*16+(size_t)v;
            }
            break;
        case 3: { /* chunk data */
            size_t avail=len-i;
            size_t n=avail<ho.chunk_rem?avail:ho.chunk_rem;
            ho_append(d+i, n);
            i+=n;
            ho.chunk_rem-=n;
            if(ho.chunk_rem==0) ho.state=4;
            break;
        }
        case 4: /* CRLF after chunk */
            if(d[i]=='\n') { ho.state=2; ho.chunk_rem=0; }
            i++;
            break;
        default: return;
        }
    }
}

/* Phase 4: Application data transfer */
static void tls12_transfer_appdata(int fd, const char *path, const char *host,
                                    cipher_mode_t mode, const tls12_keys *tk) {
    uint64_t c12_seq=1;
    {
        char req[REQ_BUF_SIZE];
        int rlen=snprintf(req,sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "Connection: close\r\nUser-Agent: tls_client/0.1\r\n\r\n",
            path,host);
        tls12_send_encrypted(fd,TLS_RT_APPDATA,(uint8_t*)req,(size_t)rlen,
            mode,tk->c_wk,tk->key_len,tk->c_mk,tk->mac_key_len,
            tk->mac_alg,tk->c_wiv,c12_seq++);
        if(tls_verbose) fprintf(stderr,"Sent HTTP GET %s\n\n",path);
    }

    uint64_t s12_seq=1;
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    if(tls_verbose) fprintf(stderr,"=== HTTP Response ===\n");
    http_output_init();
    for(;;) {
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype<0) break;
        if(rtype==TLS_RT_APPDATA) {
            uint8_t pt12[REC_BUF_SIZE]; size_t pt12_len;
            int dec_ok2=tls12_recv_decrypt(rec,rec_len,TLS_RT_APPDATA,
                mode,tk->s_wk,tk->key_len,tk->s_mk,tk->mac_key_len,
                tk->mac_alg,tk->s_wiv,s12_seq++,pt12,&pt12_len);
            if(dec_ok2<0) {
                fprintf(stderr,"Decrypt failed at seq %llu\n",
                        (unsigned long long)(s12_seq-1));
                break;
            }
            http_output(pt12,pt12_len);
        } else if(rtype==TLS_RT_ALERT) {
            if(rec_len>=2 && rec[0]==1 && rec[1]==0) break;
            break;
        } else {
            break;
        }
    }
    { const uint8_t alert[2]={1,0};
      tls12_send_encrypted(fd,TLS_RT_ALERT,alert,2,
          mode,tk->c_wk,tk->key_len,tk->c_mk,tk->mac_key_len,
          tk->mac_alg,tk->c_wiv,c12_seq++); }
    if(tls_verbose) fprintf(stderr,"\n=== Done ===\n");
}

/* ================================================================
 * TLS 1.2 Handshake
 * ================================================================ */
static void tls12_handshake(const tls_conn *conn) {
    int fd = conn->fd;
    const char *host = conn->host;
    uint16_t cipher_suite = conn->cipher_suite;
    uint8_t client_random[32], server_random[32];
    memcpy(client_random, conn->client_random, 32);
    memcpy(server_random, conn->server_random, 32);
    uint8_t p256_priv[P256_SCALAR_LEN], p256_pub[P256_POINT_LEN];
    memcpy(p256_priv, conn->p256_priv, P256_SCALAR_LEN);
    memcpy(p256_pub, conn->p256_pub, P256_POINT_LEN);
    uint8_t p384_priv[P384_SCALAR_LEN], p384_pub[P384_POINT_LEN];
    memcpy(p384_priv, conn->p384_priv, P384_SCALAR_LEN);
    memcpy(p384_pub, conn->p384_pub, P384_POINT_LEN);
    uint8_t x25519_priv[X25519_KEY_LEN], x25519_pub[X25519_KEY_LEN];
    memcpy(x25519_priv, conn->x25519_priv, X25519_KEY_LEN);
    memcpy(x25519_pub, conn->x25519_pub, X25519_KEY_LEN);
    uint8_t x448_priv[X448_KEY_LEN], x448_pub[X448_KEY_LEN];
    memcpy(x448_priv, conn->x448_priv, X448_KEY_LEN);
    memcpy(x448_pub, conn->x448_pub, X448_KEY_LEN);
    sha256_ctx transcript = conn->transcript;
    sha384_ctx transcript384 = conn->transcript384;

    int is_rsa_kex = (cipher_suite==TLS_RSA_AES256_GCM
                   || cipher_suite==TLS_RSA_AES128_GCM
                   || cipher_suite==TLS_RSA_AES256_CBC
                   || cipher_suite==TLS_RSA_AES128_CBC);
    cipher_mode_t mode = cipher_mode_of(cipher_suite);
    if(tls_verbose) fprintf(stderr,"Negotiated TLS 1.2 (cipher suite 0x%04x%s%s%s)\n",cipher_suite,
           is_rsa_kex?" RSA-kex":"", mode==CIPHER_CBC?" CBC":"",
           mode==CIPHER_CHACHA?" ChaCha20":"");

    /* Phase 1: Read Certificate, ServerKeyExchange, ServerHelloDone */
    tls12_server_params srv;
    memset(&srv,0,sizeof(srv));
    tls12_read_server_msgs(fd, &transcript, &transcript384,
        conn->sh_leftover_data, conn->sh_leftover,
        is_rsa_kex, client_random, server_random, host, &srv);

    /* Phase 2: Key exchange and derivation */
    tls12_keys tk;
    tls12_do_key_exchange(fd, &transcript, &transcript384, &srv,
        cipher_suite, mode, is_rsa_kex,
        p256_priv, p256_pub, p384_priv, p384_pub,
        x25519_priv, x25519_pub, x448_priv, x448_pub,
        client_random, server_random, &tk);

    /* Phase 3: Exchange CCS and Finished */
    tls12_exchange_finished(fd, mode, &tk, &transcript, &transcript384);

    /* Phase 4: Application data */
    tls12_transfer_appdata(fd, conn->path, host, mode, &tk);

    free(srv.cert_msg);
    secure_zero(&tk,sizeof(tk));
    close(fd);
}

/* ================================================================
 * TLS 1.3 Transcript Hash Helper
 * ================================================================ */
static void tls13_transcript_hash(int is_aes256,
                                  const sha256_ctx *t256,
                                  const sha384_ctx *t384,
                                  uint8_t *out) {
    if(is_aes256) {
        sha384_ctx tc=*t384; sha384_final(&tc,out);
    } else {
        sha256_ctx tc=*t256; sha256_final(&tc,out);
    }
}

/* ================================================================
 * TLS 1.3 Handshake Helpers
 * ================================================================ */
typedef struct {
    int fd;
    const char *host, *path;
    int is_aes256;
    cipher_mode_t mode;
    const hash_alg *alg;
    size_t hash_len, kl;
    sha256_ctx transcript;
    sha384_ctx transcript384;
    /* Handshake secrets and keys */
    uint8_t hs_secret[SHA384_DIGEST_LEN];
    uint8_t s_hs_key[AES256_KEY_LEN], s_hs_iv[AES_GCM_NONCE_LEN];
    uint8_t c_hs_key[AES256_KEY_LEN], c_hs_iv[AES_GCM_NONCE_LEN];
    uint8_t s_hs_traffic[SHA384_DIGEST_LEN], c_hs_traffic[SHA384_DIGEST_LEN];
    /* Encrypted handshake outputs */
    uint8_t *cert_msg;
    size_t cert_msg_len;
    int got_cert_request;
    /* Application keys */
    uint8_t s_ap_key[AES256_KEY_LEN], s_ap_iv[AES_GCM_NONCE_LEN];
    uint8_t c_ap_key[AES256_KEY_LEN], c_ap_iv[AES_GCM_NONCE_LEN];
    uint8_t s_ap_traffic[SHA384_DIGEST_LEN], c_ap_traffic[SHA384_DIGEST_LEN];
    /* PSK resumption state */
    int psk_mode;
    uint8_t master_secret[SHA384_DIGEST_LEN];
    uint8_t res_master[SHA384_DIGEST_LEN];
    tls_session **out_session;
} tls13_hs_state;

/* Phase 1: Derive handshake traffic keys from shared secret */
static void tls13_derive_hs_keys(tls13_hs_state *st,
                                  const uint8_t *shared, size_t shared_len,
                                  const uint8_t *psk, size_t psk_len) {
    const hash_alg *alg=st->alg;
    uint8_t early_secret[SHA384_DIGEST_LEN];
    if(psk && psk_len>0) {
        const uint8_t z[SHA384_DIGEST_LEN]={0};
        hkdf_extract_u(alg,z,alg->digest_len,psk,psk_len,early_secret);
    } else {
        const uint8_t z[SHA384_DIGEST_LEN]={0};
        hkdf_extract_u(alg,z,alg->digest_len,z,alg->digest_len,early_secret);
    }
    uint8_t derived1[SHA384_DIGEST_LEN];
    { uint8_t empty_hash[SHA384_DIGEST_LEN]; alg->hash(NULL,0,empty_hash);
      hkdf_expand_label_u(alg,early_secret,"derived",empty_hash,
          alg->digest_len,derived1,alg->digest_len); }
    hkdf_extract_u(alg,derived1,alg->digest_len,
                   shared,shared_len,st->hs_secret);

    uint8_t th1[SHA384_DIGEST_LEN];
    tls13_transcript_hash(st->is_aes256,&st->transcript,&st->transcript384,th1);

    hkdf_expand_label_u(alg,st->hs_secret,"s hs traffic",th1,
        alg->digest_len,st->s_hs_traffic,alg->digest_len);
    hkdf_expand_label_u(alg,st->hs_secret,"c hs traffic",th1,
        alg->digest_len,st->c_hs_traffic,alg->digest_len);

    hkdf_expand_label_u(alg,st->s_hs_traffic,"key",NULL,0,st->s_hs_key,st->kl);
    hkdf_expand_label_u(alg,st->s_hs_traffic,"iv",
                        NULL,0,st->s_hs_iv,AES_GCM_NONCE_LEN);
    hkdf_expand_label_u(alg,st->c_hs_traffic,"key",NULL,0,st->c_hs_key,st->kl);
    hkdf_expand_label_u(alg,st->c_hs_traffic,"iv",
                        NULL,0,st->c_hs_iv,AES_GCM_NONCE_LEN);
    if(tls_verbose) fprintf(stderr,"Derived handshake traffic keys\n");

    secure_zero(early_secret,sizeof(early_secret));
    secure_zero(derived1,sizeof(derived1));
}

/* Phase 2: Process encrypted handshake messages until server Finished */
static void tls13_process_encrypted_hs(tls13_hs_state *st) {
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    uint64_t s_hs_seq=0;
    uint8_t hs_buf[HS_BUF_SIZE]; size_t hs_buf_len=0;

    /* May get a ChangeCipherSpec first (compat) */
    rtype=tls_read_record(st->fd,rec,&rec_len);
    if(rtype==TLS_RT_CCS)
        rtype=tls_read_record(st->fd,rec,&rec_len);

    int got_finished=0, got_cert_verify=st->psk_mode; /* PSK mode: no cert verify needed */
    while(!got_finished) {
        if(rtype!=TLS_RT_APPDATA) die("expected encrypted record");
        uint8_t pt[REC_BUF_SIZE]; size_t pt_len;
        int inner=decrypt_record(rec,rec_len,st->s_hs_key,st->s_hs_iv,
            s_hs_seq++,pt,&pt_len,st->mode,st->kl);
        if(inner!=TLS_RT_HANDSHAKE)
            die("expected handshake inside encrypted record");

        if(hs_buf_len+pt_len>sizeof(hs_buf))
            die("TLS 1.3 handshake buffer overflow");
        memcpy(hs_buf+hs_buf_len,pt,pt_len);
        hs_buf_len+=pt_len;

        size_t pos=0;
        while(pos+4<=hs_buf_len) {
            uint8_t mtype=hs_buf[pos];
            uint32_t mlen=GET24(hs_buf+pos+1);
            if(pos+4+mlen>hs_buf_len) break;
            size_t msg_total=4+mlen;

            switch(mtype) {
                case 8: /* EncryptedExtensions */
                    if(tls_verbose) fprintf(stderr,"  EncryptedExtensions (%u bytes)\n",
                           (unsigned)mlen);
                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    break;
                case 11: /* Certificate */
                    if(tls_verbose) fprintf(stderr,"  Certificate (%u bytes)\n",(unsigned)mlen);
                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    free(st->cert_msg);
                    st->cert_msg=malloc(mlen);
                    if(!st->cert_msg) die("malloc failed");
                    memcpy(st->cert_msg,hs_buf+pos+4,mlen);
                    st->cert_msg_len=mlen;
                    break;
                case 13: /* CertificateRequest */
                    if(tls_verbose) fprintf(stderr,"  CertificateRequest (%u bytes)\n",
                           (unsigned)mlen);
                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    st->got_cert_request=1;
                    break;
                case 15: { /* CertificateVerify */
                    if(tls_verbose) fprintf(stderr,"  CertificateVerify (%u bytes)\n",
                           (unsigned)mlen);
                    if(st->cert_msg){
                        if(tls_verbose) fprintf(stderr,"  Validating certificate chain...\n");
                        if(verify_cert_chain(st->cert_msg,st->cert_msg_len,
                                             st->host,1)<0)
                            die("Certificate verification failed");
                    }
                    if(mlen<4) die("CertificateVerify too short");
                    const uint8_t *cv=hs_buf+pos+4;
                    uint16_t cv_algo=GET16(cv);
                    uint16_t cv_sig_len=GET16(cv+2);
                    if(4+(uint32_t)cv_sig_len>mlen)
                        die("CertificateVerify sig length mismatch");
                    const uint8_t *cv_sig=cv+4;

                    if(cv_algo!=TLS_SIG_ECDSA_SECP256R1_SHA256 &&
                       cv_algo!=TLS_SIG_ECDSA_SECP384R1_SHA384 &&
                       cv_algo!=TLS_SIG_RSA_PSS_SHA256 &&
                       cv_algo!=TLS_SIG_RSA_PSS_SHA384 &&
                       cv_algo!=TLS_SIG_ED25519 &&
                       cv_algo!=TLS_SIG_ED448)
                        die("CertificateVerify uses sig algo not in offered list");

                    uint8_t th_cv[SHA384_DIGEST_LEN];
                    tls13_transcript_hash(st->is_aes256,&st->transcript,
                                          &st->transcript384,th_cv);

                    size_t cv_content_len=64+33+1+st->hash_len;
                    uint8_t cv_content[64+33+1+SHA384_DIGEST_LEN];
                    memset(cv_content,0x20,64);
                    memcpy(cv_content+64,
                           "TLS 1.3, server CertificateVerify",33);
                    cv_content[97]=0x00;
                    memcpy(cv_content+98,th_cv,st->hash_len);

                    if(!st->cert_msg)
                        die("No certificate for CertificateVerify");
                    const uint8_t *cp2=st->cert_msg;
                    uint8_t ctx_len2=*cp2++; cp2+=ctx_len2;
                    cp2+=3;
                    uint32_t leaf_len=GET24(cp2); cp2+=3;
                    x509_cert leaf;
                    if(x509_parse(&leaf,cp2,leaf_len)!=0)
                        die("Failed to parse leaf cert for CV");

                    int cv_ok=verify_sig_algo(cv_algo,cv_content,
                        cv_content_len,cv_sig,cv_sig_len,&leaf);
                    if(!cv_ok)
                        die("CertificateVerify signature verification failed");
                    if(tls_verbose) fprintf(stderr,"  CertificateVerify VERIFIED (algo=0x%04x)\n",
                           cv_algo);
                    got_cert_verify=1;

                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    break;
                }
                case 20: { /* Finished */
                    if(!got_cert_verify)
                        die("Server Finished without CertificateVerify");
                    if(mlen!=st->hash_len)
                        die("Server Finished length mismatch");
                    if(tls_verbose) fprintf(stderr,"  Server Finished\n");
                    uint8_t fin_key[SHA384_DIGEST_LEN];
                    hkdf_expand_label_u(st->alg,st->s_hs_traffic,"finished",
                        NULL,0,fin_key,st->alg->digest_len);
                    uint8_t th_before_fin[SHA384_DIGEST_LEN];
                    tls13_transcript_hash(st->is_aes256,&st->transcript,
                        &st->transcript384,th_before_fin);
                    uint8_t expected[SHA384_DIGEST_LEN];
                    hmac(st->alg,fin_key,st->alg->digest_len,
                         th_before_fin,st->alg->digest_len,expected);
                    if(!ct_memeq(expected,hs_buf+pos+4,st->hash_len))
                        die("Server Finished verify failed!");
                    if(tls_verbose) fprintf(stderr,"  Server Finished VERIFIED\n");
                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    got_finished=1;
                    break;
                }
                default:
                    if(tls_verbose) fprintf(stderr,"  Unknown handshake msg type %d\n",mtype);
                    if(st->is_aes256)
                        sha384_update(&st->transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&st->transcript,hs_buf+pos,msg_total);
                    break;
            }
            pos+=msg_total;
        }
        if(pos>0 && pos<hs_buf_len) {
            memmove(hs_buf,hs_buf+pos,hs_buf_len-pos);
            hs_buf_len-=pos;
        } else if(pos==hs_buf_len) {
            hs_buf_len=0;
        }

        if(!got_finished)
            rtype=tls_read_record(st->fd,rec,&rec_len);
    }
}

/* Phase 3: Derive application traffic keys from master secret */
static void tls13_derive_app_keys(tls13_hs_state *st) {
    const hash_alg *alg=st->alg;
    uint8_t th_sf[SHA384_DIGEST_LEN];
    tls13_transcript_hash(st->is_aes256,&st->transcript,
                          &st->transcript384,th_sf);

    uint8_t derived2[SHA384_DIGEST_LEN];
    { uint8_t empty_hash[SHA384_DIGEST_LEN]; alg->hash(NULL,0,empty_hash);
      hkdf_expand_label_u(alg,st->hs_secret,"derived",empty_hash,
          alg->digest_len,derived2,alg->digest_len); }
    uint8_t master_secret[SHA384_DIGEST_LEN];
    { const uint8_t z[SHA384_DIGEST_LEN]={0};
      hkdf_extract_u(alg,derived2,alg->digest_len,
                     z,alg->digest_len,master_secret); }

    hkdf_expand_label_u(alg,master_secret,"s ap traffic",th_sf,
        alg->digest_len,st->s_ap_traffic,alg->digest_len);
    hkdf_expand_label_u(alg,master_secret,"c ap traffic",th_sf,
        alg->digest_len,st->c_ap_traffic,alg->digest_len);

    hkdf_expand_label_u(alg,st->s_ap_traffic,"key",
                        NULL,0,st->s_ap_key,st->kl);
    hkdf_expand_label_u(alg,st->s_ap_traffic,"iv",
                        NULL,0,st->s_ap_iv,AES_GCM_NONCE_LEN);
    hkdf_expand_label_u(alg,st->c_ap_traffic,"key",
                        NULL,0,st->c_ap_key,st->kl);
    hkdf_expand_label_u(alg,st->c_ap_traffic,"iv",
                        NULL,0,st->c_ap_iv,AES_GCM_NONCE_LEN);
    if(tls_verbose) fprintf(stderr,"Derived application traffic keys\n");

    /* Keep master_secret for resumption_master_secret derivation after client Finished */
    memcpy(st->master_secret, master_secret, alg->digest_len);

    secure_zero(derived2,sizeof(derived2));
    secure_zero(master_secret,sizeof(master_secret));
}

/* Phase 4: Send CCS, optional empty cert, and client Finished */
static void tls13_send_client_finished(tls13_hs_state *st) {
    /* Send client ChangeCipherSpec (compat) */
    { uint8_t ccs=1; tls_send_record(st->fd,TLS_RT_CCS,&ccs,1); }

    uint64_t c_hs_seq=0;

    /* If server requested client cert, send empty Certificate */
    if(st->got_cert_request) {
        uint8_t cert_msg[8];
        cert_msg[0]=0x0b;
        cert_msg[1]=0; cert_msg[2]=0; cert_msg[3]=4;
        cert_msg[4]=0;
        cert_msg[5]=0; cert_msg[6]=0; cert_msg[7]=0;
        encrypt_and_send(st->fd,TLS_RT_HANDSHAKE,cert_msg,8,
            st->c_hs_key,st->c_hs_iv,c_hs_seq++,st->mode,st->kl);
        if(st->is_aes256) sha384_update(&st->transcript384,cert_msg,8);
        else sha256_update(&st->transcript,cert_msg,8);
        if(tls_verbose) fprintf(stderr,"Sent empty client Certificate\n");
    }

    /* Send client Finished */
    {
        uint8_t th_for_fin[SHA384_DIGEST_LEN];
        tls13_transcript_hash(st->is_aes256,&st->transcript,
                              &st->transcript384,th_for_fin);
        uint8_t fin_key[SHA384_DIGEST_LEN];
        hkdf_expand_label_u(st->alg,st->c_hs_traffic,"finished",
                            NULL,0,fin_key,st->alg->digest_len);
        uint8_t verify[SHA384_DIGEST_LEN];
        hmac(st->alg,fin_key,st->alg->digest_len,
             th_for_fin,st->alg->digest_len,verify);
        uint8_t fin_msg[52]; fin_msg[0]=0x14;
        fin_msg[1]=0; fin_msg[2]=0; fin_msg[3]=(uint8_t)st->hash_len;
        memcpy(fin_msg+4,verify,st->hash_len);
        encrypt_and_send(st->fd,TLS_RT_HANDSHAKE,fin_msg,4+st->hash_len,
            st->c_hs_key,st->c_hs_iv,c_hs_seq++,st->mode,st->kl);
        /* Update transcript with client Finished for res_master derivation */
        if(st->is_aes256) sha384_update(&st->transcript384,fin_msg,4+st->hash_len);
        else sha256_update(&st->transcript,fin_msg,4+st->hash_len);
    }
    if(tls_verbose) fprintf(stderr,"Sent client Finished\n");

    /* Derive resumption_master_secret from master_secret + transcript after client Finished */
    {
        uint8_t th_after_cf[SHA384_DIGEST_LEN];
        tls13_transcript_hash(st->is_aes256,&st->transcript,&st->transcript384,th_after_cf);
        hkdf_expand_label_u(st->alg,st->master_secret,"res master",th_after_cf,
            st->alg->digest_len,st->res_master,st->alg->digest_len);
        secure_zero(st->master_secret,sizeof(st->master_secret));
    }
}

/* Phase 5: Send HTTP GET, receive response with KeyUpdate support */
static void tls13_transfer_appdata(tls13_hs_state *st) {
    uint64_t c_ap_seq=0;
    {
        char req[REQ_BUF_SIZE];
        int rlen=snprintf(req,sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "Connection: close\r\nUser-Agent: tls_client/0.1\r\n\r\n",
            st->path,st->host);
        encrypt_and_send(st->fd,TLS_RT_APPDATA,(uint8_t*)req,(size_t)rlen,
            st->c_ap_key,st->c_ap_iv,c_ap_seq++,st->mode,st->kl);
        if(tls_verbose) fprintf(stderr,"Sent HTTP GET %s\n\n",st->path);
    }

    uint64_t s_ap_seq=0;
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    if(tls_verbose) fprintf(stderr,"=== HTTP Response ===\n");
    http_output_init();
    for(;;) {
        rtype=tls_read_record(st->fd,rec,&rec_len);
        if(rtype<0) break;
        if(rtype==TLS_RT_APPDATA) {
            uint8_t pt[REC_BUF_SIZE]; size_t pt_len;
            int inner=decrypt_record(rec,rec_len,st->s_ap_key,st->s_ap_iv,
                s_ap_seq++,pt,&pt_len,st->mode,st->kl);
            if(inner==TLS_RT_APPDATA) {
                http_output(pt,pt_len);
            } else if(inner==TLS_RT_ALERT) {
                if(pt_len>=2 && pt[0]==1 && pt[1]==0) break;
                printf("\n[TLS Alert: %d %d]\n",pt[0],pt_len>1?pt[1]:-1);
                break;
            } else if(inner==TLS_RT_HANDSHAKE) {
                /* Parse handshake messages inside app data records */
                size_t hpos=0;
                while(hpos+4<=pt_len) {
                    uint8_t hmtype=pt[hpos];
                    uint32_t hmlen=GET24(pt+hpos+1);
                    if(hpos+4+hmlen>pt_len) break;
                    if(hmtype==4 && st->out_session) {
                        /* NewSessionTicket (type 4) */
                        const uint8_t *tp=pt+hpos+4;
                        if(hmlen<13) { hpos+=4+hmlen; continue; }
                        uint32_t lifetime=(uint32_t)tp[0]<<24|(uint32_t)tp[1]<<16|
                                          (uint32_t)tp[2]<<8|tp[3];
                        uint32_t age_add=(uint32_t)tp[4]<<24|(uint32_t)tp[5]<<16|
                                         (uint32_t)tp[6]<<8|tp[7];
                        uint8_t nonce_len=tp[8];
                        if(9u+nonce_len+2>hmlen) { hpos+=4+hmlen; continue; }
                        const uint8_t *nonce=tp+9;
                        uint16_t tkt_len=GET16(tp+9+nonce_len);
                        if(9u+nonce_len+2+tkt_len>hmlen) { hpos+=4+hmlen; continue; }
                        const uint8_t *tkt_data=tp+9+nonce_len+2;
                        /* Derive PSK from res_master + ticket_nonce */
                        tls_session *sess=calloc(1,sizeof(tls_session));
                        if(!sess) die("malloc failed");
                        sess->ticket=malloc(tkt_len);
                        if(!sess->ticket) die("malloc failed");
                        memcpy(sess->ticket,tkt_data,tkt_len);
                        sess->ticket_len=tkt_len;
                        sess->ticket_lifetime=lifetime;
                        sess->ticket_age_add=age_add;
                        sess->cipher_suite=st->is_aes256 ?
                            TLS_AES_256_GCM_SHA384 : TLS_AES_128_GCM_SHA256;
                        if(st->mode==CIPHER_CHACHA)
                            sess->cipher_suite=TLS_CHACHA20_POLY1305_SHA256;
                        sess->psk_len=st->alg->digest_len;
                        hkdf_expand_label_u(st->alg,st->res_master,"resumption",
                            nonce,nonce_len,sess->psk,sess->psk_len);
                        sess->timestamp=(uint64_t)time(NULL);
                        /* Free previous session if any, store new one */
                        if(*st->out_session) tls_session_free(*st->out_session);
                        *st->out_session=sess;
                        if(tls_verbose) fprintf(stderr,"Received NewSessionTicket (lifetime=%u, ticket_len=%u)\n",
                            lifetime,(unsigned)tkt_len);
                    } else if(hmtype==24 && hmlen==1) {
                        /* KeyUpdate — handle inline */
                        uint8_t request_update=pt[hpos+4];
                        {
                            uint8_t new_s[SHA384_DIGEST_LEN];
                            hkdf_expand_label_u(st->alg,st->s_ap_traffic,
                                "traffic upd",NULL,0,new_s,st->alg->digest_len);
                            memcpy(st->s_ap_traffic,new_s,st->alg->digest_len);
                            hkdf_expand_label_u(st->alg,st->s_ap_traffic,"key",
                                NULL,0,st->s_ap_key,st->kl);
                            hkdf_expand_label_u(st->alg,st->s_ap_traffic,"iv",
                                NULL,0,st->s_ap_iv,AES_GCM_NONCE_LEN);
                        }
                        s_ap_seq=0;
                        if(request_update==1) {
                            const uint8_t ku_msg[5]={24,0,0,1,0};
                            encrypt_and_send(st->fd,TLS_RT_HANDSHAKE,ku_msg,5,
                                st->c_ap_key,st->c_ap_iv,c_ap_seq++,
                                st->mode,st->kl);
                            {
                                uint8_t new_c[SHA384_DIGEST_LEN];
                                hkdf_expand_label_u(st->alg,st->c_ap_traffic,
                                    "traffic upd",NULL,0,new_c,
                                    st->alg->digest_len);
                                memcpy(st->c_ap_traffic,new_c,
                                       st->alg->digest_len);
                                hkdf_expand_label_u(st->alg,st->c_ap_traffic,
                                    "key",NULL,0,st->c_ap_key,st->kl);
                                hkdf_expand_label_u(st->alg,st->c_ap_traffic,
                                    "iv",NULL,0,st->c_ap_iv,AES_GCM_NONCE_LEN);
                            }
                            c_ap_seq=0;
                        }
                    }
                    hpos+=4+hmlen;
                }
            }
        } else {
            break;
        }
    }
    { const uint8_t alert[2]={1,0};
      encrypt_and_send(st->fd,TLS_RT_ALERT,alert,2,st->c_ap_key,st->c_ap_iv,
          c_ap_seq,st->mode,st->kl); }
    if(tls_verbose) fprintf(stderr,"\n=== Done ===\n");
}

/* ================================================================
 * TLS 1.3 Handshake
 * ================================================================ */
static void tls13_handshake(const tls_conn *conn, int psk_accepted,
                            const uint8_t *psk, size_t psk_len,
                            tls_session **out_session) {
    tls13_hs_state st;
    memset(&st,0,sizeof(st));
    st.fd = conn->fd;
    st.host = conn->host;
    st.path = conn->path;
    st.psk_mode = psk_accepted;
    st.out_session = out_session;
    uint16_t cipher_suite = conn->cipher_suite;
    st.is_aes256 = (cipher_suite == TLS_AES_256_GCM_SHA384);
    st.mode = cipher_mode_of(cipher_suite);
    st.alg = st.is_aes256 ? &SHA384_ALG : &SHA256_ALG;
    st.hash_len = st.alg->digest_len;
    st.kl = st.is_aes256 ? AES256_KEY_LEN :
            (st.mode==CIPHER_CHACHA ? 32 : AES128_KEY_LEN);
    st.transcript = conn->transcript;
    st.transcript384 = conn->transcript384;

    uint8_t server_pub[P384_POINT_LEN];
    size_t server_pub_len = conn->server_pub_len;
    memcpy(server_pub, conn->server_pub, server_pub_len);
    uint8_t p256_priv[P256_SCALAR_LEN], p384_priv[P384_SCALAR_LEN];
    memcpy(p256_priv, conn->p256_priv, P256_SCALAR_LEN);
    memcpy(p384_priv, conn->p384_priv, P384_SCALAR_LEN);
    uint8_t x25519_priv[X25519_KEY_LEN];
    memcpy(x25519_priv, conn->x25519_priv, X25519_KEY_LEN);
    uint8_t x448_priv[X448_KEY_LEN];
    memcpy(x448_priv, conn->x448_priv, X448_KEY_LEN);

    uint16_t selected_group;
    if(server_pub_len==X25519_KEY_LEN) selected_group=TLS_GROUP_X25519;
    else if(server_pub_len==X448_KEY_LEN) selected_group=TLS_GROUP_X448;
    else if(server_pub_len==P256_POINT_LEN) selected_group=TLS_GROUP_SECP256R1;
    else selected_group=TLS_GROUP_SECP384R1;
    if(tls_verbose) fprintf(stderr,"Received ServerHello (TLS 1.3, cipher=0x%04x, group=0x%04x)\n",
        cipher_suite,selected_group);

    /* Compute shared secret */
    uint8_t shared[X448_KEY_LEN]; size_t shared_len; /* X448_KEY_LEN=56 is largest */
    if(selected_group==TLS_GROUP_X25519) {
        if(x25519_shared_secret(x25519_priv,server_pub,shared)<0)
            die("X25519 shared secret is zero");
        shared_len=X25519_KEY_LEN;
    } else if(selected_group==TLS_GROUP_X448) {
        if(x448_shared_secret(x448_priv,server_pub,shared)<0)
            die("X448 shared secret is zero");
        shared_len=X448_KEY_LEN;
    } else if(selected_group==TLS_GROUP_SECP256R1) {
        uint8_t ss[P256_SCALAR_LEN];
        ecdhe_p256_shared_secret(p256_priv,server_pub,ss);
        memcpy(shared,ss,P256_SCALAR_LEN);
        shared_len=P256_SCALAR_LEN;
        secure_zero(ss,sizeof(ss));
    } else {
        ecdhe_p384_shared_secret(p384_priv,server_pub,shared);
        shared_len=P384_SCALAR_LEN;
    }
    secure_zero(p256_priv,sizeof(p256_priv));
    secure_zero(p384_priv,sizeof(p384_priv));
    secure_zero(x25519_priv,sizeof(x25519_priv));
    secure_zero(x448_priv,sizeof(x448_priv));
    if(tls_verbose) fprintf(stderr,"Computed ECDHE shared secret (%zu bytes)\n",shared_len);

    /* Phase 1: Derive handshake keys */
    tls13_derive_hs_keys(&st, shared, shared_len, psk, psk_len);
    secure_zero(shared,sizeof(shared));

    /* Phase 2: Process encrypted handshake messages */
    tls13_process_encrypted_hs(&st);

    /* Phase 3: Derive application keys */
    tls13_derive_app_keys(&st);

    /* Phase 4: Send client Finished */
    tls13_send_client_finished(&st);

    /* Phase 5: Application data transfer */
    tls13_transfer_appdata(&st);

    int fd=st.fd;
    free(st.cert_msg);
    secure_zero(&st,sizeof(st));
    close(fd);
}

/* ================================================================
 * HelloRetryRequest Handling (RFC 8446 §4.1.4)
 * ================================================================ */
static void handle_hello_retry(int fd, uint8_t *rec, size_t *rec_len,
                               uint16_t *cipher_suite,
                               const uint8_t client_random[32],
                               const uint8_t *session_id,
                               const uint8_t p256_pub[P256_POINT_LEN],
                               const uint8_t p384_pub[P384_POINT_LEN],
                               const uint8_t x25519_pub[X25519_KEY_LEN],
                               const uint8_t x448_pub[X448_KEY_LEN],
                               const char *host,
                               uint8_t *server_pub, size_t *server_pub_len,
                               uint8_t server_random[32],
                               uint16_t *version,
                               sha256_ctx *transcript,
                               sha384_ctx *transcript384,
                               size_t *sh_leftover) {
    uint32_t sh_msg_len=4+GET24(rec+1);
    if(tls_verbose) fprintf(stderr,"Received HelloRetryRequest (cipher=0x%04x)\n",*cipher_suite);

    /* Parse HRR extensions to find selected group */
    uint16_t hrr_group=0;
    {
        const uint8_t *b=rec+4;
        b+=2; b+=32;
        uint8_t sid_len=*b++; b+=sid_len;
        b+=2; b++;
        if(b+2<=rec+sh_msg_len) {
            uint16_t ext_total=GET16(b); b+=2;
            const uint8_t *ext_end=b+ext_total;
            if(ext_end>rec+sh_msg_len) ext_end=rec+sh_msg_len;
            while(b+4<=ext_end) {
                uint16_t etype=GET16(b); b+=2;
                uint16_t elen=GET16(b); b+=2;
                if(b+elen>ext_end) break;
                if(etype==0x0033 && elen==2)
                    hrr_group=GET16(b);
                b+=elen;
            }
        }
    }
    if(hrr_group!=TLS_GROUP_X25519 && hrr_group!=TLS_GROUP_X448
       && hrr_group!=TLS_GROUP_SECP256R1 && hrr_group!=TLS_GROUP_SECP384R1)
        die("HRR selected unsupported group");
    if(tls_verbose) fprintf(stderr,"  HRR selected group 0x%04x\n",hrr_group);

    int hrr_aes256 = (*cipher_suite == TLS_AES_256_GCM_SHA384);

    /* Transcript replacement per RFC 8446 §4.4.1 */
    if(hrr_aes256) {
        uint8_t ch1_hash[SHA384_DIGEST_LEN];
        sha384_ctx tc=*transcript384; sha384_final(&tc,ch1_hash);
        sha384_init(transcript384);
        uint8_t synth[4+SHA384_DIGEST_LEN]={0xFE,0x00,0x00,SHA384_DIGEST_LEN};
        memcpy(synth+4,ch1_hash,SHA384_DIGEST_LEN);
        sha384_update(transcript384,synth,sizeof(synth));
        sha384_update(transcript384,rec,sh_msg_len);
    } else {
        uint8_t ch1_hash[SHA256_DIGEST_LEN];
        sha256_ctx tc=*transcript; sha256_final(&tc,ch1_hash);
        sha256_init(transcript);
        uint8_t synth[4+SHA256_DIGEST_LEN]={0xFE,0x00,0x00,SHA256_DIGEST_LEN};
        memcpy(synth+4,ch1_hash,SHA256_DIGEST_LEN);
        sha256_update(transcript,synth,sizeof(synth));
        sha256_update(transcript,rec,sh_msg_len);
    }

    /* Build and send new ClientHello with only the requested group.
       Reuse client_random and session_id per RFC 8446 §4.1.2. */
    uint8_t ch[CH_BUF_SIZE];
    uint8_t cr_copy[32]; memcpy(cr_copy, client_random, 32);
    size_t ch_len=build_client_hello(ch,p256_pub,p384_pub,x25519_pub,x448_pub,host,
        cr_copy,session_id,hrr_group,NULL);
    if(hrr_aes256)
        sha384_update(transcript384,ch,ch_len);
    else
        sha256_update(transcript,ch,ch_len);

    tls_send_record(fd,TLS_RT_HANDSHAKE,ch,ch_len);
    if(tls_verbose) fprintf(stderr,"Sent new ClientHello with group 0x%04x (%zu bytes)\n",hrr_group,ch_len);

    /* Read real ServerHello (skip CCS if present) */
    int rtype=tls_read_record(fd,rec,rec_len);
    if(rtype==TLS_RT_CCS)
        rtype=tls_read_record(fd,rec,rec_len);
    if(rtype==TLS_RT_ALERT && *rec_len>=2) {
        fprintf(stderr,"Alert: level=%d desc=%d\n",rec[0],rec[1]);
        die("server sent alert after HRR");
    }
    if(rtype!=TLS_RT_HANDSHAKE) die("expected handshake record after HRR");
    if(rec[0]!=0x02) die("expected ServerHello after HRR");
    *version=parse_server_hello(rec,*rec_len,server_pub,
        server_pub_len,server_random,cipher_suite,NULL);
    if(*version!=TLS_VERSION_13) die("expected TLS 1.3 after HRR");
    if(*server_pub_len==0) die("no key_share in real ServerHello after HRR");
    sh_msg_len=4+GET24(rec+1);
    if(hrr_aes256)
        sha384_update(transcript384,rec,sh_msg_len);
    else
        sha256_update(transcript,rec,sh_msg_len);
    *sh_leftover=*rec_len>sh_msg_len ? *rec_len-sh_msg_len : 0;
    if(tls_verbose) fprintf(stderr,"Received real ServerHello after HRR (cipher=0x%04x)\n",*cipher_suite);
}

/* Main TLS handshake + HTTP GET with optional session resumption */
uint8_t *do_https_get_session(const char *host, int port, const char *path,
                               size_t *out_len, tls_session **session) {
    load_trust_store("trust_store");

    /* Check if we have a valid session for PSK resumption */
    tls_session *sess = (session && *session) ? *session : NULL;
    if(sess) {
        /* Check ticket lifetime */
        uint64_t now=(uint64_t)time(NULL);
        if(now - sess->timestamp > sess->ticket_lifetime) {
            if(tls_verbose) fprintf(stderr,"Session ticket expired, doing full handshake\n");
            tls_session_free(sess);
            if(session) *session=NULL;
            sess=NULL;
        }
    }
    if(sess && tls_verbose)
        fprintf(stderr,"Attempting PSK resumption (ticket_len=%zu)\n",sess->ticket_len);

    int fd=tcp_connect(host,port);
    if(tls_verbose) fprintf(stderr,"Connected to %s:%d\n",host,port);

    /* Generate ECDHE keypairs for all groups */
    uint8_t p384_priv[P384_SCALAR_LEN], p384_pub[P384_POINT_LEN];
    ecdhe_p384_keygen(p384_priv,p384_pub);
    uint8_t p256_priv[P256_SCALAR_LEN], p256_pub[P256_POINT_LEN];
    ecdhe_p256_keygen(p256_priv,p256_pub);
    uint8_t x25519_priv[X25519_KEY_LEN], x25519_pub_key[X25519_KEY_LEN];
    x25519_keygen(x25519_priv,x25519_pub_key);
    uint8_t x448_priv[X448_KEY_LEN], x448_pub_key[X448_KEY_LEN];
    x448_keygen(x448_priv,x448_pub_key);
    if(tls_verbose) fprintf(stderr,"Generated ECDHE keypairs (X25519 + X448 + P-256 + P-384)\n");

    /* Build & send ClientHello */
    uint8_t ch[CH_BUF_SIZE];
    uint8_t client_random[32];
    size_t ch_len=build_client_hello(ch,p256_pub,p384_pub,x25519_pub_key,x448_pub_key,host,client_random,NULL,0,sess);
    /* Save session_id from ClientHello for HRR reuse (RFC 8446 §4.1.2) */
    const uint8_t *saved_session_id=ch+6+32+1; /* past: type(1)+len(3)+version(2)+random(32)+sid_len(1) */
    /* For the record layer, first ClientHello uses version 0x0301.
       Send header+body in one write to avoid middlebox issues with TCP fragmentation. */
    {
        uint8_t ch_rec[5+CH_BUF_SIZE];
        ch_rec[0]=TLS_RT_HANDSHAKE; ch_rec[1]=(TLS_VERSION_10>>8); ch_rec[2]=(TLS_VERSION_10&0xFF);
        PUT16(ch_rec+3,(uint16_t)ch_len);
        memcpy(ch_rec+5,ch,ch_len);
        write_all(fd,ch_rec,5+ch_len);
    }

    /* Start transcript */
    sha256_ctx transcript;
    sha256_init(&transcript);
    sha384_ctx transcript384;
    sha384_init(&transcript384);
    sha256_update(&transcript,ch,ch_len);
    sha384_update(&transcript384,ch,ch_len);
    if(tls_verbose) fprintf(stderr,"Sent ClientHello (%zu bytes)\n",ch_len);

    /* Read ServerHello */
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype==TLS_RT_ALERT && rec_len>=2) {
        fprintf(stderr,"Alert: level=%d desc=%d\n",rec[0],rec[1]);
        die("server sent alert");
    }
    if(rtype!=TLS_RT_HANDSHAKE) die("expected handshake record");
    if(rec_len<4||rec[0]!=0x02) die("expected ServerHello");
    uint8_t server_pub[P384_POINT_LEN]; size_t server_pub_len=0;
    uint8_t server_random[32];
    uint16_t cipher_suite;
    int psk_accepted=0;
    uint16_t version=parse_server_hello(rec,rec_len,server_pub,
        &server_pub_len,server_random,&cipher_suite,&psk_accepted);
    uint32_t sh_msg_len=4+GET24(rec+1);
    sha256_update(&transcript,rec,sh_msg_len);
    sha384_update(&transcript384,rec,sh_msg_len);
    size_t sh_leftover=rec_len>sh_msg_len ? rec_len-sh_msg_len : 0;

    /* If we offered PSK but server didn't accept, fall back to full handshake */
    if(sess && !psk_accepted) {
        if(tls_verbose) fprintf(stderr,"Server did not accept PSK, falling back to full handshake\n");
        tls_session_free(sess);
        if(session) *session=NULL;
        sess=NULL;
    }
    if(psk_accepted && tls_verbose)
        fprintf(stderr,"Server accepted PSK resumption\n");

    /* HelloRetryRequest handling */
    if(memcmp(server_random,HRR_RANDOM,32)==0) {
        handle_hello_retry(fd,rec,&rec_len,&cipher_suite,client_random,
            saved_session_id,p256_pub,p384_pub,x25519_pub_key,x448_pub_key,host,server_pub,&server_pub_len,
            server_random,&version,&transcript,&transcript384,&sh_leftover);
        sh_msg_len=4+GET24(rec+1); /* rec now holds real ServerHello */
    }

    /* RFC 8446 §4.1.3: detect MITM downgrade from TLS 1.3 to 1.2/1.1 */
    if(version!=TLS_VERSION_13) {
        static const uint8_t DG12[8]={0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x01};
        static const uint8_t DG11[8]={0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x00};
        if(memcmp(server_random+24,DG12,8)==0 || memcmp(server_random+24,DG11,8)==0)
            die("TLS downgrade attack detected (server_random sentinel)");
    }

    /* Verify TLS 1.3 ServerHello has key_share */
    if(version==TLS_VERSION_13 && server_pub_len==0) die("TLS 1.3 but no key_share in ServerHello");

    /* Pack connection context and dispatch */
    tls_conn conn;
    conn.fd = fd;
    conn.host = host;
    conn.path = path;
    memcpy(conn.client_random, client_random, 32);
    memcpy(conn.server_random, server_random, 32);
    memcpy(conn.p256_priv, p256_priv, P256_SCALAR_LEN);
    memcpy(conn.p256_pub, p256_pub, P256_POINT_LEN);
    memcpy(conn.p384_priv, p384_priv, P384_SCALAR_LEN);
    memcpy(conn.p384_pub, p384_pub, P384_POINT_LEN);
    memcpy(conn.x25519_priv, x25519_priv, X25519_KEY_LEN);
    memcpy(conn.x25519_pub, x25519_pub_key, X25519_KEY_LEN);
    memcpy(conn.x448_priv, x448_priv, X448_KEY_LEN);
    memcpy(conn.x448_pub, x448_pub_key, X448_KEY_LEN);
    memcpy(conn.server_pub, server_pub, server_pub_len);
    conn.server_pub_len = server_pub_len;
    conn.cipher_suite = cipher_suite;
    conn.transcript = transcript;
    conn.transcript384 = transcript384;
    conn.sh_leftover = sh_leftover;
    if(sh_leftover > 0) {
        memcpy(conn.sh_leftover_data, rec + sh_msg_len, sh_leftover);
    }

    /* Clear local secret material */
    secure_zero(p256_priv, sizeof(p256_priv));
    secure_zero(p384_priv, sizeof(p384_priv));
    secure_zero(x25519_priv, sizeof(x25519_priv));
    secure_zero(x448_priv, sizeof(x448_priv));

    /* Copy PSK data and free old session before handshake, since
       tls13_transfer_appdata may replace *session with a new ticket */
    uint8_t psk_copy[48]; size_t psk_copy_len=0;
    if(sess) {
        psk_copy_len=sess->psk_len;
        memcpy(psk_copy,sess->psk,psk_copy_len);
        tls_session_free(sess);
        if(session) *session=NULL;
        sess=NULL;
    }

    if(version == TLS_VERSION_12) {
        tls12_handshake(&conn);
    } else {
        tls13_handshake(&conn, psk_accepted,
                        psk_copy_len ? psk_copy : NULL,
                        psk_copy_len,
                        session);
    }
    secure_zero(psk_copy,sizeof(psk_copy));

    /* Clear connection context secrets */
    secure_zero(&conn, sizeof(conn));

    *out_len = ho.body_len;
    return ho.body;
}

uint8_t *do_https_get(const char *host, int port, const char *path, size_t *out_len) {
    return do_https_get_session(host, port, path, out_len, NULL);
}

/* ================================================================
 * Built-in self-tests (compiled only with -DTLS_TEST)
 * RFC/NIST known-answer tests for every crypto primitive.
 * ================================================================ */
#ifdef TLS_TEST
#include <stdio.h>

static int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for(size_t i=0;i<bin_len;i++){
        unsigned hi,lo;
        if(sscanf(hex+2*i,"%1x%1x",&hi,&lo)!=2) return -1;
        bin[i]=(uint8_t)((hi<<4)|lo);
    }
    return 0;
}

#define T(name,ok) do{ if(ok){pass++;printf("  %-28s PASS\n",name);} \
    else{fail++;printf("  %-28s FAIL\n",name);} }while(0)

int main(void) {
    int pass=0,fail=0;

    /* ---- Ed25519 RFC 8032 §7.1 Test Vector 1: empty message ---- */
    {
        uint8_t sk[32],pk[32],sig[64];
        hex2bin("9d61b19deffd5a60ba844af492ec2cc4"
                "4449c5697b326919703bac031cae7f60",sk,32);
        hex2bin("d75a980182b10ab7d54bfed3c964073a"
                "0ee172f3daa62325af021a68f707511a",pk,32);
        hex2bin("e5564300c360ac729086e2cc806e828a"
                "84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b",sig,64);
        T("Ed25519 (empty msg)",ed25519_verify(pk,(const uint8_t*)"",0,sig));
    }
    /* ---- Ed25519 RFC 8032 §7.1 Test Vector 2: 1-byte message (0x72) ---- */
    {
        uint8_t pk[32],sig[64];
        hex2bin("3d4017c3e843895a92b70aa74d1b7ebc"
                "9c982ccf2ec4968cc0cd55f12af4660c",pk,32);
        hex2bin("92a009a9f0d4cab8720e820b5f642540"
                "a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c"
                "387b2eaeb4302aeeb00d291612bb0c00",sig,64);
        const uint8_t msg[1]={0x72};
        T("Ed25519 (1-byte msg)",ed25519_verify(pk,msg,1,sig));
    }

    /* ---- X448 RFC 7748 §6.2: Alice and Bob DH ---- */
    {
        uint8_t alice_priv[56],alice_pub[56],bob_priv[56],bob_pub[56],shared[56],expected_shared[56];
        hex2bin("9a8f4925d1519f5775cf46971028b71b"
                "44c869ef7f811f2e980069a5b4b6ff84"
                "c06991f5ecc68a4f9c8c8e40c0b55607"
                "3ebf96a2a94e5340",alice_priv,56);
        hex2bin("07f32d8adc627f9789eaffb9dfd11fb6"
                "b0297fc419bfd414e16127f1e1cfd847"
                "bb6915ea4c0a20ed07dc3a1994685770"
                "45867de21a4e4c18",alice_pub,56);
        hex2bin("1c306a7ac2a0e2e0990b294470cba339"
                "e6453772b075811d8fad0d1d6927c120"
                "bb5ee8972b0d3e21374c9c921b09d1b0"
                "366f10106a0f6a54",bob_priv,56);
        hex2bin("1854a97a9c7f7cc2e5bb27297b8018b6"
                "3655fae71e230c989331d79d4912f475"
                "89c0d8ec320665c7f937fde0dcc9d7d4"
                "3294cdf11f8855d5",bob_pub,56);
        hex2bin("556634e295417314cc1fa25fcd60735a"
                "4044bc7fbda74964eb5fd76d9ac0242e"
                "0cf958b4841cfb7f1d2f6a6dafe4d26e"
                "a16cbc0456048db3",expected_shared,56);

        uint8_t computed_pub[56];
        uint8_t basepoint[56]={5};
        x448_scalar_mult(alice_priv,basepoint,computed_pub);
        x448_shared_secret(alice_priv,bob_pub,shared);
        T("X448 DH (RFC 7748)",memcmp(computed_pub,alice_pub,56)==0 &&
                               memcmp(shared,expected_shared,56)==0);
    }

    /* ---- Ed448 RFC 8032 §7.4 Test Vector 1: empty message ---- */
    {
        uint8_t pk[57],sig[114];
        hex2bin("5fd7449b59b461fd2ce787ec616ad46a"
                "1da1342485a70e1f8a0ea75d80e96778"
                "edf124769b46c7061bd6783df1e50f6c"
                "d1fa1abeafe8256180",pk,57);
        hex2bin("533a37f6bbe457251f023c0d88f976ae"
                "2dfb504a843e34d2074fd823d41a591f"
                "2b233f034f628281f2fd7a22ddd47d78"
                "28c59bd0a21bfd39"
                "80ff0d2028d4b18a9df63e006c5d1c2d"
                "345b925d8dc00b4104852db99ac5c7cd"
                "da8530a113a0f4dbb61149f05a736326"
                "8c71d95808ff2e652600",sig,114);
        T("Ed448 (empty msg)",ed448_verify(pk,(const uint8_t*)"",0,sig));
    }

    /* ---- SHAKE256 sanity check ---- */
    {
        uint8_t out[32],expected[32];
        shake256_ctx c; shake256_init(&c); shake256_final(&c,out,32);
        hex2bin("46b9dd2b0ba88d13233b3feb743eeb24"
                "3fcd52ea62b81b82b50c27646ed5762f",expected,32);
        T("SHAKE256 (empty)",memcmp(out,expected,32)==0);
    }

    /* ---- SHA-1 FIPS 180-4: "abc" ---- */
    {
        uint8_t out[20],expected[20];
        sha1_hash((const uint8_t*)"abc",3,out);
        hex2bin("a9993e364706816aba3e25717850c26c9cd0d89d",expected,20);
        T("SHA-1 (\"abc\")",memcmp(out,expected,20)==0);
    }

    /* ---- SHA-256 FIPS 180-4: "abc" ---- */
    {
        uint8_t out[32],expected[32];
        sha256_hash((const uint8_t*)"abc",3,out);
        hex2bin("ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad",expected,32);
        T("SHA-256 (\"abc\")",memcmp(out,expected,32)==0);
    }

    /* ---- SHA-256 FIPS 180-4: 2-block message ---- */
    {
        uint8_t out[32],expected[32];
        const char *msg="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256_hash((const uint8_t*)msg,56,out);
        hex2bin("248d6a61d20638b8e5c026930c3e6039"
                "a33ce45964ff2167f6ecedd419db06c1",expected,32);
        T("SHA-256 (2-block)",memcmp(out,expected,32)==0);
    }

    /* ---- SHA-384 FIPS 180-4: "abc" ---- */
    {
        uint8_t out[48],expected[48];
        sha384_hash((const uint8_t*)"abc",3,out);
        hex2bin("cb00753f45a35e8bb5a03d699ac65007"
                "272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7",expected,48);
        T("SHA-384 (\"abc\")",memcmp(out,expected,48)==0);
    }

    /* ---- SHA-512 FIPS 180-4: "abc" ---- */
    {
        uint8_t out[64],expected[64];
        sha512_hash((const uint8_t*)"abc",3,out);
        hex2bin("ddaf35a193617abacc417349ae204131"
                "12e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd"
                "454d4423643ce80e2a9ac94fa54ca49f",expected,64);
        T("SHA-512 (\"abc\")",memcmp(out,expected,64)==0);
    }

    /* ---- HMAC-SHA256 RFC 4231 Test Case 2 ---- */
    {
        uint8_t out[32],expected[32];
        hmac(&SHA256_ALG,(const uint8_t*)"Jefe",4,
             (const uint8_t*)"what do ya want for nothing?",28,out);
        hex2bin("5bdcc146bf60754e6a042426089575c7"
                "5a003f089d2739839dec58b964ec3843",expected,32);
        T("HMAC-SHA256 (RFC 4231)",memcmp(out,expected,32)==0);
    }

    /* ---- HMAC-SHA384 RFC 4231 Test Case 2 ---- */
    {
        uint8_t out[48],expected[48];
        hmac(&SHA384_ALG,(const uint8_t*)"Jefe",4,
             (const uint8_t*)"what do ya want for nothing?",28,out);
        hex2bin("af45d2e376484031617f78d2b58a6b1b"
                "9c7ef464f5a01b47e42ec3736322445e"
                "8e2240ca5e69e2c78b3239ecfab21649",expected,48);
        T("HMAC-SHA384 (RFC 4231)",memcmp(out,expected,48)==0);
    }

    /* ---- HKDF-SHA256 RFC 5869 Test Case 1 ---- */
    {
        uint8_t ikm[22],salt[13],info[10],prk[32],okm[42];
        uint8_t exp_prk[32],exp_okm[42];
        hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",ikm,22);
        hex2bin("000102030405060708090a0b0c",salt,13);
        hex2bin("f0f1f2f3f4f5f6f7f8f9",info,10);
        hex2bin("077709362c2e32df0ddc3f0dc47bba63"
                "90b6c73bb50f9c3122ec844ad7c2b3e5",exp_prk,32);
        hex2bin("3cb25f25faacd57a90434f64d0362f2a"
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865",exp_okm,42);
        hkdf_extract_u(&SHA256_ALG,salt,13,ikm,22,prk);
        hkdf_expand_u(&SHA256_ALG,prk,info,10,okm,42);
        T("HKDF-SHA256 (RFC 5869)",memcmp(prk,exp_prk,32)==0 &&
                                   memcmp(okm,exp_okm,42)==0);
    }

    /* ---- AES-128-GCM NIST SP 800-38D Test Case 4 ---- */
    {
        uint8_t key[16],nonce[12],pt[60],aad[20],ct[60],tag[16];
        uint8_t exp_ct[60],exp_tag[16];
        hex2bin("feffe9928665731c6d6a8f9467308308",key,16);
        hex2bin("cafebabefacedbaddecaf888",nonce,12);
        hex2bin("d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",pt,60);
        hex2bin("feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",aad,20);
        hex2bin("42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091",exp_ct,60);
        hex2bin("5bc94fbc3221a5db94fae95ae7121a47",exp_tag,16);
        aes_gcm_encrypt_impl(key,16,nonce,aad,20,pt,60,ct,tag);
        T("AES-128-GCM (NIST TC4)",memcmp(ct,exp_ct,60)==0 &&
                                   memcmp(tag,exp_tag,16)==0);
    }

    /* ---- AES-256-GCM NIST SP 800-38D Test Case 16 ---- */
    {
        uint8_t key[32],nonce[12],pt[60],aad[20],ct[60],tag[16];
        uint8_t exp_ct[60],exp_tag[16];
        hex2bin("feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308",key,32);
        hex2bin("cafebabefacedbaddecaf888",nonce,12);
        hex2bin("d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39",pt,60);
        hex2bin("feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",aad,20);
        hex2bin("522dc1f099567d07f47f37a32a84427d"
                "643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838"
                "c5f61e6393ba7a0abcc9f662",exp_ct,60);
        hex2bin("76fc6ece0f4e1768cddf8853bb2d551b",exp_tag,16);
        aes_gcm_encrypt_impl(key,32,nonce,aad,20,pt,60,ct,tag);
        T("AES-256-GCM (NIST TC16)",memcmp(ct,exp_ct,60)==0 &&
                                    memcmp(tag,exp_tag,16)==0);
    }

    /* ---- ChaCha20 RFC 8439 §2.4.2: Sunscreen ---- */
    {
        uint8_t key[32],nonce[12],pt[114],ct[114],exp_ct[114];
        hex2bin("000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f",key,32);
        hex2bin("000000000000004a00000000",nonce,12);
        hex2bin("4c616469657320616e642047656e746c"
                "656d656e206f662074686520636c6173"
                "73206f66202739393a20496620492063"
                "6f756c64206f6666657220796f75206f"
                "6e6c79206f6e652074697020666f7220"
                "746865206675747572652c2073756e73"
                "637265656e20776f756c642062652069"
                "742e",pt,114);
        hex2bin("6e2e359a2568f98041ba0728dd0d6981"
                "e97e7aec1d4360c20a27afccfd9fae0b"
                "f91b65c5524733ab8f593dabcd62b357"
                "1639d624e65152ab8f530c359f0861d8"
                "07ca0dbf500d6a6156a38e088a22b65e"
                "52bc514d16ccf806818ce91ab7793736"
                "5af90bbf74a35be6b40b8eedf2785e42"
                "874d",exp_ct,114);
        chacha20_encrypt(key,nonce,1,pt,114,ct);
        T("ChaCha20 (RFC 8439)",memcmp(ct,exp_ct,114)==0);
    }

    /* ---- Poly1305 RFC 8439 §2.5.2 ---- */
    {
        uint8_t key[32],msg[34],tag[16],exp_tag[16];
        hex2bin("85d6be7857556d337f4452fe42d506a8"
                "0103808afb0db2fd4abff6af4149f51b",key,32);
        hex2bin("43727970746f6772617068696320466f"
                "72756d205265736561726368204772"
                "6f7570",msg,34);
        hex2bin("a8061dc1305136c6c22b8baf0c0127a9",exp_tag,16);
        poly1305_mac(key,msg,34,tag);
        T("Poly1305 (RFC 8439)",memcmp(tag,exp_tag,16)==0);
    }

    /* ---- ChaCha20-Poly1305 RFC 8439 §2.8.2 ---- */
    {
        uint8_t key[32],nonce[12],aad[12],pt[114],ct[114],tag[16];
        uint8_t exp_ct[114],exp_tag[16];
        hex2bin("808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f",key,32);
        hex2bin("070000004041424344454647",nonce,12);
        hex2bin("50515253c0c1c2c3c4c5c6c7",aad,12);
        hex2bin("4c616469657320616e642047656e746c"
                "656d656e206f662074686520636c6173"
                "73206f66202739393a20496620492063"
                "6f756c64206f6666657220796f75206f"
                "6e6c79206f6e652074697020666f7220"
                "746865206675747572652c2073756e73"
                "637265656e20776f756c642062652069"
                "742e",pt,114);
        hex2bin("d31a8d34648e60db7b86afbc53ef7ec2"
                "a4aded51296e08fea9e2b5a736ee62d6"
                "3dbea45e8ca9671282fafb69da92728b"
                "1a71de0a9e060b2905d6a5b67ecd3b36"
                "92ddbd7f2d778b8c9803aee328091b58"
                "fab324e4fad675945585808b4831d7bc"
                "3ff4def08e4b7a9de576d26586cec64b"
                "6116",exp_ct,114);
        hex2bin("1ae10b594f09e26a7e902ecbd0600691",exp_tag,16);
        chacha20_poly1305_encrypt(key,nonce,aad,12,pt,114,ct,tag);
        T("ChaCha20-Poly1305 (8439)",memcmp(ct,exp_ct,114)==0 &&
                                     memcmp(tag,exp_tag,16)==0);
    }

    /* ---- X25519 RFC 7748 §6.1: Alice and Bob DH ---- */
    {
        uint8_t alice_priv[32],alice_pub[32],bob_priv[32],bob_pub[32];
        uint8_t shared[32],expected_shared[32],expected_pub[32];
        hex2bin("77076d0a7318a57d3c16c17251b26645"
                "df4c2f87ebc0992ab177fba51db92c2a",alice_priv,32);
        hex2bin("8520f0098930a754748b7ddcb43ef75a"
                "0dbf3a0d26381af4eba4a98eaa9b4e6a",expected_pub,32);
        hex2bin("5dab087e624a8a4b79e17f8b83800ee6"
                "6f3bb1292618b6fd1c2f8b27ff88e0eb",bob_priv,32);
        hex2bin("de9edb7d7b7dc1b4d35b61c2ece43537"
                "3f8343c85b78674dadfc7e146f882b4f",bob_pub,32);
        hex2bin("4a5d9d5ba4ce2de1728e3bf480350f25"
                "e07e21c947d19e3376f09b3c1e161742",expected_shared,32);

        uint8_t basepoint[32]={9};
        x25519_scalar_mult(alice_priv,basepoint,alice_pub);
        x25519_shared_secret(alice_priv,bob_pub,shared);
        T("X25519 DH (RFC 7748)",memcmp(alice_pub,expected_pub,32)==0 &&
                                 memcmp(shared,expected_shared,32)==0);
    }

    /* ---- AES-128-CBC NIST SP 800-38A §F.2.1 ---- */
    {
        uint8_t key[16],iv[16],pt[64],ct[64],exp_ct[64];
        hex2bin("2b7e151628aed2a6abf7158809cf4f3c",key,16);
        hex2bin("000102030405060708090a0b0c0d0e0f",iv,16);
        hex2bin("6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710",pt,64);
        hex2bin("7649abac8119b246cee98e9b12e9197d"
                "5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e22229516"
                "3ff1caa1681fac09120eca307586e1a7",exp_ct,64);
        aes_cbc_encrypt(key,16,iv,pt,64,ct);
        T("AES-128-CBC (NIST)",memcmp(ct,exp_ct,64)==0);
    }

    /* ---- AES-256-CBC NIST SP 800-38A §F.2.5 ---- */
    {
        uint8_t key[32],iv[16],pt[64],ct[64],exp_ct[64];
        hex2bin("603deb1015ca71be2b73aef0857d7781"
                "1f352c073b6108d72d9810a30914dff4",key,32);
        hex2bin("000102030405060708090a0b0c0d0e0f",iv,16);
        hex2bin("6bc1bee22e409f96e93d7e117393172a"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "f69f2445df4f9b17ad2b417be66c3710",pt,64);
        hex2bin("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                "9cfc4e967edb808d679f777bc6702c7d"
                "39f23369a9d9bacfa530e26304231461"
                "b2eb05e2c39be9fcda6c19078c6a9d1b",exp_ct,64);
        aes_cbc_encrypt(key,32,iv,pt,64,ct);
        T("AES-256-CBC (NIST)",memcmp(ct,exp_ct,64)==0);
    }

    /* ---- Negative tests ---- */
    printf("\n");

    /* ---- Ed25519: corrupted signature must fail ---- */
    {
        uint8_t pk[32],sig[64];
        hex2bin("d75a980182b10ab7d54bfed3c964073a"
                "0ee172f3daa62325af021a68f707511a",pk,32);
        hex2bin("e5564300c360ac729086e2cc806e828a"
                "84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b",sig,64);
        sig[0]^=0x01;
        T("Ed25519 reject bad sig",!ed25519_verify(pk,(const uint8_t*)"",0,sig));
    }

    /* ---- Ed448: corrupted signature must fail ---- */
    {
        uint8_t pk[57],sig[114];
        hex2bin("5fd7449b59b461fd2ce787ec616ad46a"
                "1da1342485a70e1f8a0ea75d80e96778"
                "edf124769b46c7061bd6783df1e50f6c"
                "d1fa1abeafe8256180",pk,57);
        hex2bin("533a37f6bbe457251f023c0d88f976ae"
                "2dfb504a843e34d2074fd823d41a591f"
                "2b233f034f628281f2fd7a22ddd47d78"
                "28c59bd0a21bfd39"
                "80ff0d2028d4b18a9df63e006c5d1c2d"
                "345b925d8dc00b4104852db99ac5c7cd"
                "da8530a113a0f4dbb61149f05a736326"
                "8c71d95808ff2e652600",sig,114);
        sig[0]^=0x01;
        T("Ed448 reject bad sig",!ed448_verify(pk,(const uint8_t*)"",0,sig));
    }

    /* ---- AES-128-GCM: corrupted tag must fail ---- */
    {
        uint8_t key[16],nonce[12],ct[60],aad[20],pt[60],tag[16];
        hex2bin("feffe9928665731c6d6a8f9467308308",key,16);
        hex2bin("cafebabefacedbaddecaf888",nonce,12);
        hex2bin("42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091",ct,60);
        hex2bin("feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2",aad,20);
        hex2bin("5bc94fbc3221a5db94fae95ae7121a47",tag,16);
        tag[0]^=0x01;
        T("AES-GCM reject bad tag",aes_gcm_decrypt_impl(key,16,nonce,aad,20,ct,60,pt,tag)==-1);
    }

    /* ---- ChaCha20-Poly1305: corrupted tag must fail ---- */
    {
        uint8_t key[32],nonce[12],aad[12],ct[114],pt[114],tag[16];
        hex2bin("808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f",key,32);
        hex2bin("070000004041424344454647",nonce,12);
        hex2bin("50515253c0c1c2c3c4c5c6c7",aad,12);
        hex2bin("d31a8d34648e60db7b86afbc53ef7ec2"
                "a4aded51296e08fea9e2b5a736ee62d6"
                "3dbea45e8ca9671282fafb69da92728b"
                "1a71de0a9e060b2905d6a5b67ecd3b36"
                "92ddbd7f2d778b8c9803aee328091b58"
                "fab324e4fad675945585808b4831d7bc"
                "3ff4def08e4b7a9de576d26586cec64b"
                "6116",ct,114);
        hex2bin("1ae10b594f09e26a7e902ecbd0600691",tag,16);
        tag[0]^=0x01;
        T("CC20-P1305 reject bad tag",chacha20_poly1305_decrypt(key,nonce,aad,12,ct,114,pt,tag)==-1);
    }

    /* ---- X25519: all-zero public key must fail ---- */
    {
        uint8_t priv[32],zero_pub[32]={0},out[32];
        hex2bin("77076d0a7318a57d3c16c17251b26645"
                "df4c2f87ebc0992ab177fba51db92c2a",priv,32);
        T("X25519 reject low-order",x25519_shared_secret(priv,zero_pub,out)==-1);
    }

    /* ---- X448: all-zero public key must fail ---- */
    {
        uint8_t priv[56],zero_pub[56]={0},out[56];
        hex2bin("9a8f4925d1519f5775cf46971028b71b"
                "44c869ef7f811f2e980069a5b4b6ff84"
                "c06991f5ecc68a4f9c8c8e40c0b55607"
                "3ebf96a2a94e5340",priv,56);
        T("X448 reject low-order",x448_shared_secret(priv,zero_pub,out)==-1);
    }

    printf("Self-tests: %d passed, %d failed\n",pass,fail);
    return fail>0 ? 1 : 0;
}
#endif /* TLS_TEST */
