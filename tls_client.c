/*
 * tls_client.c — TLS 1.2/1.3 HTTPS client from scratch in C.
 * Implements: SHA-256, SHA-384, HMAC, HKDF, AES-128/256-GCM, ChaCha20-Poly1305,
 *             ECDHE-P256/P384, X25519, TLS 1.2/1.3
 * No external crypto libraries.
 *
 * Compile:  cc -O2 -o tls_client tls_client.c
 * Run:      ./tls_client
 *
 * Certificate verification: SHA-384, ECDSA-P384, RSA PKCS#1 v1.5, X.509 chain.
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

typedef unsigned __int128 uint128_t;

#define PUT16(b,v) do{(b)[0]=(uint8_t)((v)>>8);(b)[1]=(uint8_t)(v);}while(0)
#define GET16(b) (((uint16_t)(b)[0]<<8)|(b)[1])
#define GET24(b) (((uint32_t)(b)[0]<<16)|((uint32_t)(b)[1]<<8)|(b)[2])

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
#define TLS_GROUP_SECP256R1 0x0017
#define TLS_GROUP_SECP384R1 0x0018

/* X25519 / ChaCha20-Poly1305 sizes */
#define X25519_KEY_LEN            32
#define CHACHA20_POLY1305_TAG_LEN 16

/* Buffer sizes */
#define CH_BUF_SIZE   1024
#define REC_BUF_SIZE  32768
#define HS_BUF_SIZE   65536
#define REQ_BUF_SIZE  512

static void die(const char *msg) { fprintf(stderr, "FATAL: %s\n", msg); exit(1); }

static void random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) die("open urandom");
    size_t d = 0;
    while (d < len) { ssize_t n = read(fd, buf+d, len-d); if (n<=0) die("read urandom"); d+=n; }
    close(fd);
}

static int read_exact(int fd, uint8_t *buf, size_t len) {
    size_t d = 0;
    while (d < len) { ssize_t n = read(fd, buf+d, len-d); if (n<=0) return -1; d+=n; }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t d = 0;
    while (d < len) { ssize_t n = write(fd, buf+d, len-d); if (n<=0) return -1; d+=n; }
    return 0;
}

/* Constant-time helpers */
static void secure_zero(void *p, size_t len) {
    volatile uint8_t *v = p;
    while (len--) *v++ = 0;
}

static int ct_memeq(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = a, *y = b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= x[i] ^ y[i];
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
    for (int i=0;i<16;i++)
        w[i]=((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)
            |((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    for (int i=16;i<64;i++)
        w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    a=ctx->h[0];b=ctx->h[1];c=ctx->h[2];d=ctx->h[3];
    e=ctx->h[4];f=ctx->h[5];g=ctx->h[6];h=ctx->h[7];
    for (int i=0;i<64;i++) {
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
    while (len > 0) {
        size_t space = 64 - ctx->buf_len, chunk = len < space ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk; data += chunk; len -= chunk;
        if (ctx->buf_len == 64) { sha256_transform(ctx, ctx->buf); ctx->buf_len = 0; }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t bits = ctx->total * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->buf_len != 56) sha256_update(ctx, &pad, 1);
    uint8_t lb[8]; for (int i=7;i>=0;i--) { lb[i]=bits&0xFF; bits>>=8; }
    sha256_update(ctx, lb, 8);
    for (int i=0;i<8;i++) {
        out[4*i]=(ctx->h[i]>>24)&0xFF; out[4*i+1]=(ctx->h[i]>>16)&0xFF;
        out[4*i+2]=(ctx->h[i]>>8)&0xFF; out[4*i+3]=ctx->h[i]&0xFF;
    }
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ================================================================
 * SHA-1 (needed for HMAC-SHA-1 in TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
 * ================================================================ */
#define SHA1_DIGEST_LEN 20

typedef struct { uint32_t h[5]; uint8_t buf[64]; size_t buf_len; uint64_t total; } sha1_ctx;

static void sha1_transform(sha1_ctx *ctx, const uint8_t blk[64]) {
    uint32_t w[80];
    for(int i=0;i<16;i++)
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
    uint8_t lb[8]; for(int i=7;i>=0;i--){lb[i]=bits&0xFF;bits>>=8;}
    sha1_update(ctx,lb,8);
    for(int i=0;i<5;i++){
        out[4*i]=(ctx->h[i]>>24)&0xFF; out[4*i+1]=(ctx->h[i]>>16)&0xFF;
        out[4*i+2]=(ctx->h[i]>>8)&0xFF; out[4*i+3]=ctx->h[i]&0xFF;
    }
}

static void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx c; sha1_init(&c); sha1_update(&c,data,len); sha1_final(&c,out);
}

/* ================================================================
 * AES-128
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
    for (int i=0;i<10;i++) {
        uint8_t *p=rk+16*i, *n=rk+16*(i+1);
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
    for(int i=0;i<7;i++){
        uint8_t *prev=rk+32*i;
        uint8_t *next=prev+32;
        /* First 16 bytes: RotWord+SubWord+Rcon on last 4 bytes of prev 32 */
        uint8_t t[4]={ct_sbox(prev[29]),ct_sbox(prev[30]),ct_sbox(prev[31]),ct_sbox(prev[28])};
        t[0]^=aes_rcon[i];
        for(int j=0;j<4;j++) next[j]=prev[j]^t[j];
        for(int j=4;j<16;j++) next[j]=prev[j]^next[j-4];
        if(i==6) break; /* only need 15 round keys = 240 bytes, stop after 7th block of 16 */
        /* Second 16 bytes: SubWord on 4th word of current 16 */
        uint8_t s[4]={ct_sbox(next[12]),ct_sbox(next[13]),ct_sbox(next[14]),ct_sbox(next[15])};
        for(int j=0;j<4;j++) next[16+j]=prev[16+j]^s[j];
        for(int j=20;j<32;j++) next[j]=prev[j]^next[j-4];
    }
}

static uint8_t xt(uint8_t x){return (x<<1)^((x>>7)*0x1b);}

static void aes_encrypt(const uint8_t *rk, int nr, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16);
    for(int i=0;i<16;i++) s[i]^=rk[i];
    for (int r=1;r<=nr;r++) {
        for(int i=0;i<16;i++) s[i]=ct_sbox(s[i]);
        uint8_t t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if(r<nr) {
            for(int c=0;c<4;c++){
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
 * AES-128-GCM
 * ================================================================ */
static void gf128_mul(uint8_t r[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16],z[16]; memcpy(v,y,16); memset(z,0,16);
    for(int i=0;i<128;i++){
        uint8_t mask = -((x[i/8]>>(7-(i%8)))&1); /* 0x00 or 0xFF */
        for(int j=0;j<16;j++) z[j]^=v[j]&mask;
        uint8_t lsb_mask=-(v[15]&1); /* 0x00 or 0xFF */
        for(int j=15;j>0;j--) v[j]=(v[j]>>1)|(v[j-1]<<7);
        v[0]>>=1; v[0]^=0xe1&lsb_mask;
    }
    memcpy(r,z,16);
}

static void ghash(const uint8_t h[16], const uint8_t *aad, size_t al,
                   const uint8_t *ct, size_t cl, uint8_t out[16]) {
    uint8_t x[16]={0}, blk[16];
    size_t i;
    for(i=0;i+16<=al;i+=16){for(int j=0;j<16;j++)x[j]^=aad[i+j];gf128_mul(x,x,h);}
    if(i<al){
        memset(blk,0,16); memcpy(blk,aad+i,al-i);
        for(int j=0;j<16;j++) x[j]^=blk[j]; gf128_mul(x,x,h);
    }
    for(i=0;i+16<=cl;i+=16){for(int j=0;j<16;j++)x[j]^=ct[i+j];gf128_mul(x,x,h);}
    if(i<cl){
        memset(blk,0,16); memcpy(blk,ct+i,cl-i);
        for(int j=0;j<16;j++) x[j]^=blk[j]; gf128_mul(x,x,h);
    }
    memset(blk,0,16);
    uint64_t ab=al*8, cb=cl*8;
    for(int j=0;j<8;j++){blk[7-j]=(ab>>(8*j))&0xFF;blk[15-j]=(cb>>(8*j))&0xFF;}
    for(int j=0;j<16;j++)x[j]^=blk[j]; gf128_mul(x,x,h);
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
        x=(x<<1)^(hi?0x1b:0);
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
            for(int c=0;c<4;c++){
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
        for(int j=0;j<16;j++) blk[j]=pt[i+j]^prev[j];
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
        for(int j=0;j<16;j++) pt[i+j]=blk[j]^prev[j];
        memcpy(prev,ct+i,16);
    }
}

/* ================================================================
 * P-384 Field Arithmetic (mod p, p = 2^384 - 2^128 - 2^96 + 2^32 - 1)
 * ================================================================ */
typedef struct { uint64_t v[6]; } fp384;

static const fp384 P384_P = {{
    0x00000000FFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
}};
static const fp384 FP384_ZERO = {{0,0,0,0,0,0}};
static const fp384 FP384_ONE  = {{1,0,0,0,0,0}};

static int fp384_cmp(const fp384 *a, const fp384 *b) {
    for(int i=5;i>=0;i--){if(a->v[i]>b->v[i])return 1;if(a->v[i]<b->v[i])return -1;}return 0;
}

static uint64_t fp384_add_raw(fp384 *r, const fp384 *a, const fp384 *b) {
    uint128_t c=0;
    for(int i=0;i<6;i++){c+=(uint128_t)a->v[i]+b->v[i];r->v[i]=(uint64_t)c;c>>=64;}
    return (uint64_t)c;
}

static uint64_t fp384_sub_raw(fp384 *r, const fp384 *a, const fp384 *b) {
    __int128 borrow=0;
    for(int i=0;i<6;i++){
        borrow=(__int128)a->v[i]-b->v[i]+borrow;
        r->v[i]=(uint64_t)borrow; borrow>>=64;
    }
    return (borrow<0)?1:0;
}

static void fp384_add(fp384 *r, const fp384 *a, const fp384 *b) {
    uint64_t carry=fp384_add_raw(r,a,b);
    fp384 t; uint64_t borrow=fp384_sub_raw(&t,r,&P384_P);
    /* Use subtracted result if carry, or if no borrow (r >= P) */
    uint64_t mask=-(uint64_t)(carry|(1-borrow));
    for(int i=0;i<6;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp384_sub(fp384 *r, const fp384 *a, const fp384 *b) {
    uint64_t borrow=fp384_sub_raw(r,a,b);
    fp384 t; fp384_add_raw(&t,r,&P384_P);
    uint64_t mask=-(uint64_t)borrow;
    for(int i=0;i<6;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp384_mul(fp384 *r, const fp384 *a, const fp384 *b) {
    /* Schoolbook 6x6 -> 12 limbs */
    uint64_t w[12]; memset(w,0,sizeof(w));
    for(int i=0;i<6;i++){
        uint64_t carry=0;
        for(int j=0;j<6;j++){
            uint128_t p=(uint128_t)a->v[i]*b->v[j]+w[i+j]+carry;
            w[i+j]=(uint64_t)p; carry=(uint64_t)(p>>64);
        }
        w[i+6]=carry;
    }
    /* Algebraic reduction: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
     * Split into hi=w[6..11], lo=w[0..5]
     * result = lo + hi + (hi<<128) + (hi<<96) - (hi<<32) mod p
     * Uses 10-limb (640-bit) accumulator for intermediate result */
    uint64_t acc[10]; memset(acc,0,sizeof(acc));
    uint128_t c;
    /* +lo */
    for(int i=0;i<6;i++) acc[i]=w[i];
    /* +hi */
    c=0; for(int i=0;i<6;i++){c+=(uint128_t)acc[i]+w[i+6];acc[i]=(uint64_t)c;c>>=64;}
    for(int i=6;i<10;i++){c+=(uint128_t)acc[i];acc[i]=(uint64_t)c;c>>=64;}
    /* +hi<<128 (shift by 2 limbs) */
    c=0; for(int i=0;i<6;i++){c+=(uint128_t)acc[i+2]+w[i+6];acc[i+2]=(uint64_t)c;c>>=64;}
    for(int i=8;i<10;i++){c+=(uint128_t)acc[i];acc[i]=(uint64_t)c;c>>=64;}
    /* +hi<<96 (shift by 1 limb + 32 bits) */
    { uint64_t sh[10]={0};
      for(int i=0;i<6;i++){sh[i+1]|=w[i+6]<<32; if(i+2<10) sh[i+2]|=w[i+6]>>32;}
      c=0; for(int i=0;i<10;i++){c+=(uint128_t)acc[i]+sh[i];acc[i]=(uint64_t)c;c>>=64;}
    }
    /* -hi<<32 */
    { uint64_t sh[10]={0};
      sh[0]=w[6]<<32;
      for(int i=1;i<6;i++) sh[i]=(w[i+6]<<32)|(w[i+5]>>32);
      sh[6]=w[11]>>32;
      __int128 borrow=0;
      for(int i=0;i<10;i++){
          borrow=(__int128)acc[i]-sh[i]+borrow;
          acc[i]=(uint64_t)borrow; borrow>>=64;
      }
    }
    /* Second pass: reduce acc[6..9] * K + acc[0..5] */
    { uint64_t hi2[6]={acc[6],acc[7],acc[8],acc[9],0,0}, lo2[6];
      memcpy(lo2,acc,48);
      memset(acc,0,sizeof(acc));
      for(int i=0;i<6;i++) acc[i]=lo2[i];
      c=0; for(int i=0;i<6;i++){c+=(uint128_t)acc[i]+hi2[i];acc[i]=(uint64_t)c;c>>=64;}
      for(int i=6;i<10;i++){c+=(uint128_t)acc[i];acc[i]=(uint64_t)c;c>>=64;}
      c=0; for(int i=0;i<4;i++){c+=(uint128_t)acc[i+2]+hi2[i];acc[i+2]=(uint64_t)c;c>>=64;}
      for(int i=6;i<10;i++){c+=(uint128_t)acc[i];acc[i]=(uint64_t)c;c>>=64;}
      { uint64_t sh[10]={0};
        for(int i=0;i<4;i++){sh[i+1]|=hi2[i]<<32; if(i+2<10) sh[i+2]|=hi2[i]>>32;}
        c=0; for(int i=0;i<10;i++){c+=(uint128_t)acc[i]+sh[i];acc[i]=(uint64_t)c;c>>=64;}
      }
      { uint64_t sh[10]={0};
        sh[0]=hi2[0]<<32;
        for(int i=1;i<4;i++) sh[i]=(hi2[i]<<32)|(hi2[i-1]>>32);
        sh[4]=hi2[3]>>32;
        __int128 borrow=0;
        for(int i=0;i<10;i++){
          borrow=(__int128)acc[i]-sh[i]+borrow;
          acc[i]=(uint64_t)borrow; borrow>>=64;
      }
      }
    }
    /* Final: constant-time conditional subtraction of p (at most 4 times) */
    memcpy(r,acc,48);
    for(int pass=0;pass<4;pass++){
        fp384 t; uint64_t borrow=fp384_sub_raw(&t,r,&P384_P);
        uint64_t mask=-(uint64_t)(1-borrow); /* all 1s if no borrow (r>=P) */
        for(int i=0;i<6;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
    }
}

static void fp384_sqr(fp384 *r, const fp384 *a){fp384_mul(r,a,a);}

static void fp384_inv(fp384 *r, const fp384 *a) {
    static const fp384 pm2={{
        0x00000000FFFFFFFD,0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF
    }};
    fp384 result=FP384_ONE, base=*a;
    for(int i=0;i<384;i++){
        if((pm2.v[i/64]>>(i%64))&1) fp384_mul(&result,&result,&base);
        fp384_sqr(&base,&base);
    }
    *r=result;
}

static void fp384_from_bytes(fp384 *r, const uint8_t b[48]) {
    for(int i=0;i<6;i++){r->v[i]=0;for(int j=0;j<8;j++)r->v[i]|=(uint64_t)b[47-(i*8+j)]<<(8*j);}
}
static void fp384_to_bytes(uint8_t b[48], const fp384 *a) {
    for(int i=0;i<6;i++)for(int j=0;j<8;j++)b[47-(i*8+j)]=(a->v[i]>>(8*j))&0xFF;
}

/* ================================================================
 * P-384 Elliptic Curve  (y^2 = x^3 - 3x + b)
 * ================================================================ */
typedef struct { fp384 x,y,z; } ec384;

static const fp384 P384_B ={{
    0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A,
    0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4}};
static const fp384 P384_GX={{
    0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38,
    0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537}};
static const fp384 P384_GY={{
    0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0,
    0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F}};

/* Check if affine point (x,y) is on curve: y^2 = x^3 - 3x + b */
static int ec384_on_curve(const fp384 *x, const fp384 *y) {
    fp384 y2, x3, t, three={{3,0,0,0,0,0}};
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
static void ec384_cswap(ec384 *a, ec384 *b, uint64_t bit) {
    uint64_t mask = -(uint64_t)bit;
    for(int i=0;i<6;i++){
        uint64_t d;
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
        uint64_t bit=(scalar[byte_idx]>>bit_pos)&1;
        ec384_cswap(&R0,&R1,bit);
        ec384_add(&R1,&R0,&R1);
        ec384_double(&R0,&R0);
        ec384_cswap(&R0,&R1,bit);
    }
    *r=R0;
}

/* ECDHE: generate keypair, compute shared secret */
static void ecdhe_keygen(uint8_t priv[P384_SCALAR_LEN], uint8_t pub[P384_POINT_LEN]) {
    random_bytes(priv,P384_SCALAR_LEN);
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
        printf("  Point verified on curve\n");
    }
}

static void ecdhe_shared_secret(const uint8_t priv[P384_SCALAR_LEN],
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
 * Base64 / PEM Decoder
 * ================================================================ */
static int b64val(uint8_t c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return c-'a'+26;
    if (c>='0'&&c<='9') return c-'0'+52;
    if (c=='+') return 62;
    if (c=='/') return 63;
    return -1;
}

static size_t pem_to_der(const char *pem, size_t pem_len, uint8_t *der) {
    const char *begin = strstr(pem, "-----BEGIN ");
    if (!begin) return 0;
    begin = memchr(begin, '\n', pem_len-(begin-pem));
    if (!begin) return 0;
    begin++;
    const char *end = strstr(begin, "-----END ");
    if (!end) return 0;
    size_t out = 0;
    uint32_t acc = 0; int bits = 0;
    for (const char *p = begin; p < end; p++) {
        int v = b64val((uint8_t)*p);
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; der[out++] = (acc >> bits) & 0xFF; }
    }
    return out;
}

/* ================================================================
 * ASN.1/DER Parser Helpers
 * ================================================================ */
/* Read tag + length, return pointer to value. NULL on error. */
static const uint8_t *der_read_tl(const uint8_t *p, const uint8_t *end,
                                    uint8_t *tag, size_t *len) {
    if (p >= end) return NULL;
    *tag = *p++;
    if (p >= end) return NULL;
    if (*p < 0x80) {
        *len = *p++;
    } else {
        int nb = *p++ & 0x7F;
        /* nb==0: reject BER indefinite length */
        if (nb == 0 || nb > 3 || p + nb > end) return NULL;
        *len = 0;
        for (int i = 0; i < nb; i++) *len = (*len << 8) | *p++;
    }
    if (p + *len > end) return NULL;
    return p;
}

/* Skip one TLV element, return pointer past it */
static const uint8_t *der_skip(const uint8_t *p, const uint8_t *end) {
    uint8_t tag; size_t len;
    const uint8_t *val = der_read_tl(p, end, &tag, &len);
    if (!val) return NULL;
    return val + len;
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

/* ================================================================
 * SHA-384 (SHA-512 truncated, different IVs, 64-bit words, 80 rounds)
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

typedef struct { uint64_t h[8]; uint8_t buf[128]; size_t buf_len; uint64_t total; } sha384_ctx;

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define S512_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define S512_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S512_EP0(x) (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define S512_EP1(x) (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define S512_SIG0(x) (ROTR64(x,1)^ROTR64(x,8)^((x)>>7))
#define S512_SIG1(x) (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))

static void sha384_transform(sha384_ctx *ctx, const uint8_t blk[128]) {
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

static void sha384_init(sha384_ctx *ctx) {
    ctx->h[0]=0xcbbb9d5dc1059ed8ULL;ctx->h[1]=0x629a292a367cd507ULL;
    ctx->h[2]=0x9159015a3070dd17ULL;ctx->h[3]=0x152fecd8f70e5939ULL;
    ctx->h[4]=0x67332667ffc00b31ULL;ctx->h[5]=0x8eb44a8768581511ULL;
    ctx->h[6]=0xdb0c2e0d64f98fa7ULL;ctx->h[7]=0x47b5481dbefa4fa4ULL;
    ctx->buf_len=0; ctx->total=0;
}

static void sha384_update(sha384_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total+=len;
    while(len>0){
        size_t space=128-ctx->buf_len, chunk=len<space?len:space;
        memcpy(ctx->buf+ctx->buf_len,data,chunk);
        ctx->buf_len+=chunk; data+=chunk; len-=chunk;
        if(ctx->buf_len==128){sha384_transform(ctx,ctx->buf);ctx->buf_len=0;}
    }
}

static void sha384_final(sha384_ctx *ctx, uint8_t out[48]) {
    uint64_t bits=ctx->total*8;
    uint8_t pad=0x80;
    sha384_update(ctx,&pad,1);
    pad=0;
    while(ctx->buf_len!=112) sha384_update(ctx,&pad,1);
    uint8_t lb[16]={0};
    for(int i=15;i>=8;i--){lb[i]=bits&0xFF;bits>>=8;}
    sha384_update(ctx,lb,16);
    for(int i=0;i<6;i++)for(int j=0;j<8;j++) out[i*8+j]=(ctx->h[i]>>(56-8*j))&0xFF;
}

static void sha384_hash(const uint8_t *data, size_t len, uint8_t out[48]) {
    sha384_ctx c; sha384_init(&c); sha384_update(&c,data,len); sha384_final(&c,out);
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
    if(slen==0){uint8_t z[48]={0}; hmac(alg,z,alg->digest_len,ikm,ilen,out);}
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

/* SHA-512: same algorithm as SHA-384, different IVs, full 64-byte output */
typedef sha384_ctx sha512_ctx;
#define sha512_transform sha384_transform
#define sha512_update sha384_update

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
    uint8_t lb[16]={0};
    for(int i=15;i>=8;i--){lb[i]=bits&0xFF;bits>>=8;}
    sha512_update(ctx,lb,16);
    for(int i=0;i<8;i++)for(int j=0;j<8;j++) out[i*8+j]=(ctx->h[i]>>(56-8*j))&0xFF;
}

static void sha512_hash(const uint8_t *data, size_t len, uint8_t out[64]) {
    sha512_ctx c; sha512_init(&c); sha512_update(&c,data,len); sha512_final(&c,out);
}

/* OID constants */
/* ================================================================
 * Big-Number Arithmetic (for RSA and ECDSA mod-n operations)
 * ================================================================ */
#define BN_MAX_LIMBS 130  /* must hold product of two RSA-4096 numbers (128 limbs) */

typedef struct { uint64_t v[BN_MAX_LIMBS]; int len; } bignum;

static void bn_zero(bignum *r) { memset(r,0,sizeof(*r)); }

static void bn_from_bytes(bignum *r, const uint8_t *buf, size_t blen) {
    bn_zero(r);
    r->len=(int)((blen+7)/8);
    if(r->len>BN_MAX_LIMBS) r->len=BN_MAX_LIMBS;
    for(size_t i=0;i<blen&&(int)(i/8)<BN_MAX_LIMBS;i++)
        r->v[i/8]|=(uint64_t)buf[blen-1-i]<<(8*(i%8));
}

static void bn_to_bytes(const bignum *a, uint8_t *buf, size_t blen) {
    memset(buf,0,blen);
    for(size_t i=0;i<blen&&(int)(i/8)<BN_MAX_LIMBS;i++)
        buf[blen-1-i]=(a->v[i/8]>>(8*(i%8)))&0xFF;
}

static int bn_cmp(const bignum *a, const bignum *b) {
    int ml=a->len>b->len?a->len:b->len;
    for(int i=ml-1;i>=0;i--){
        uint64_t av=i<a->len?a->v[i]:0, bv=i<b->len?b->v[i]:0;
        if(av>bv)return 1; if(av<bv)return -1;
    }
    return 0;
}

static void bn_sub(bignum *r, const bignum *a, const bignum *b) {
    int ml=a->len>b->len?a->len:b->len;
    __int128 borrow=0;
    for(int i=0;i<ml;i++){
        borrow=(__int128)(i<a->len?a->v[i]:0)-(i<b->len?b->v[i]:0)+borrow;
        r->v[i]=(uint64_t)borrow; borrow>>=64;
    }
    r->len=ml;
    while(r->len>0&&r->v[r->len-1]==0) r->len--;
}

static void bn_mul(bignum *r, const bignum *a, const bignum *b) {
    bignum t; bn_zero(&t);
    t.len=a->len+b->len;
    if(t.len>BN_MAX_LIMBS) t.len=BN_MAX_LIMBS;
    for(int i=0;i<a->len;i++){
        uint64_t carry=0;
        for(int j=0;j<b->len&&i+j<BN_MAX_LIMBS;j++){
            uint128_t p=(uint128_t)a->v[i]*b->v[j]+t.v[i+j]+carry;
            t.v[i+j]=(uint64_t)p; carry=(uint64_t)(p>>64);
        }
        if(i+b->len<BN_MAX_LIMBS) t.v[i+b->len]=carry;
    }
    while(t.len>0&&t.v[t.len-1]==0) t.len--;
    *r=t;
}

static int bn_bits(const bignum *a) {
    if(a->len==0) return 0;
    int bits=(a->len-1)*64;
    uint64_t top=a->v[a->len-1];
    while(top){bits++;top>>=1;}
    return bits;
}

static void bn_shl1(bignum *a) {
    uint64_t carry=0;
    for(int i=0;i<a->len;i++){
        uint64_t nc=a->v[i]>>63;
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
        if((a->v[i/64]>>(i%64))&1){rem.v[0]|=1;if(rem.len==0)rem.len=1;}
        if(bn_cmp(&rem,m)>=0) bn_sub(&rem,&rem,m);
    }
    *r=rem;
}

static void bn_modmul(bignum *r, const bignum *a, const bignum *b, const bignum *m) {
    bignum t; bn_mul(&t,a,b); bn_mod(r,&t,m);
}

/* Constant-time conditional copy: dst = src if bit==1, unchanged if bit==0 */
static void bn_cmov(bignum *dst, const bignum *src, int bit) {
    uint64_t mask = -(uint64_t)(bit&1); /* 0 or 0xFFFF... */
    int max_len = dst->len > src->len ? dst->len : src->len;
    for(int i=0;i<max_len;i++)
        dst->v[i] = (dst->v[i] & ~mask) | (src->v[i] & mask);
    dst->len = (dst->len & (int)~mask) | (src->len & (int)mask);
}

static void bn_modexp(bignum *r, const bignum *base, const bignum *exp, const bignum *m) {
    bignum result; bn_zero(&result); result.v[0]=1; result.len=1;
    bignum b; bn_mod(&b,base,m);
    /* Use fixed bit count based on modulus size to avoid leaking exponent length */
    int total_bits = m->len * 64;
    for(int i=0;i<total_bits;i++){
        /* Always multiply, conditionally keep result */
        bignum tmp;
        bn_modmul(&tmp,&result,&b,m);
        int bit = (i < exp->len*64) ? (int)((exp->v[i/64]>>(i%64))&1) : 0;
        bn_cmov(&result,&tmp,bit);
        if(i<total_bits-1) bn_modmul(&b,&b,&b,m);
    }
    *r=result;
}

/* ================================================================
 * P-256 Field Arithmetic (mod p, p = 2^256 - 2^224 + 2^192 + 2^96 - 1)
 * Constant-time fixed-width 4x64-bit limbs, modeled on fp384.
 * ================================================================ */
typedef struct { uint64_t v[4]; } fp256;

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

static int fp256_cmp(const fp256 *a, const fp256 *b) {
    for(int i=3;i>=0;i--){if(a->v[i]>b->v[i])return 1;if(a->v[i]<b->v[i])return -1;}return 0;
}

static int fp256_is_zero(const fp256 *a) {
    return (a->v[0]|a->v[1]|a->v[2]|a->v[3])==0;
}

static uint64_t fp256_add_raw(fp256 *r, const fp256 *a, const fp256 *b) {
    uint128_t c=0;
    for(int i=0;i<4;i++){c+=(uint128_t)a->v[i]+b->v[i];r->v[i]=(uint64_t)c;c>>=64;}
    return (uint64_t)c;
}

static uint64_t fp256_sub_raw(fp256 *r, const fp256 *a, const fp256 *b) {
    __int128 borrow=0;
    for(int i=0;i<4;i++){
        borrow=(__int128)a->v[i]-b->v[i]+borrow;
        r->v[i]=(uint64_t)borrow; borrow>>=64;
    }
    return (borrow<0)?1:0;
}

static void fp256_add(fp256 *r, const fp256 *a, const fp256 *b) {
    uint64_t carry=fp256_add_raw(r,a,b);
    fp256 t; uint64_t borrow=fp256_sub_raw(&t,r,&P256_P);
    uint64_t mask=-(uint64_t)(carry|(1-borrow));
    for(int i=0;i<4;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp256_sub(fp256 *r, const fp256 *a, const fp256 *b) {
    uint64_t borrow=fp256_sub_raw(r,a,b);
    fp256 t; fp256_add_raw(&t,r,&P256_P);
    uint64_t mask=-(uint64_t)borrow;
    for(int i=0;i<4;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp256_mul(fp256 *r, const fp256 *a, const fp256 *b) {
    /* Schoolbook 4x4 -> 8 limbs */
    uint64_t w[8]; memset(w,0,sizeof(w));
    for(int i=0;i<4;i++){
        uint64_t carry=0;
        for(int j=0;j<4;j++){
            uint128_t p=(uint128_t)a->v[i]*b->v[j]+w[i+j]+carry;
            w[i+j]=(uint64_t)p; carry=(uint64_t)(p>>64);
        }
        w[i+4]=carry;
    }
    /* NIST FIPS 186-4 D.2.3 fast reduction for P-256.
     * Extract 16 x 32-bit words from 512-bit product, then form
     * intermediate 256-bit values and accumulate.
     * Each si = (A7,A6,...,A0) big-endian 32-bit words.
     * Limb mapping: v[k] = (A_{2k+1} << 32) | A_{2k} */
    uint32_t c[16];
    for(int i=0;i<8;i++){c[2*i]=(uint32_t)w[i];c[2*i+1]=(uint32_t)(w[i]>>32);}
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

static void fp256_sqr(fp256 *r, const fp256 *a){fp256_mul(r,a,a);}

static void fp256_inv(fp256 *r, const fp256 *a) {
    /* Fermat's little theorem: a^(p-2) mod p */
    static const fp256 pm2={{
        0xFFFFFFFFFFFFFFFD, 0x00000000FFFFFFFF,
        0x0000000000000000, 0xFFFFFFFF00000001
    }};
    fp256 result=FP256_ONE, base=*a;
    for(int i=0;i<256;i++){
        if((pm2.v[i/64]>>(i%64))&1) fp256_mul(&result,&result,&base);
        fp256_sqr(&base,&base);
    }
    *r=result;
}

static void fp256_from_bytes(fp256 *r, const uint8_t b[32]) {
    for(int i=0;i<4;i++){r->v[i]=0;for(int j=0;j<8;j++)r->v[i]|=(uint64_t)b[31-(i*8+j)]<<(8*j);}
}
static void fp256_to_bytes(uint8_t b[32], const fp256 *a) {
    for(int i=0;i<4;i++)for(int j=0;j<8;j++)b[31-(i*8+j)]=(a->v[i]>>(8*j))&0xFF;
}

/* ================================================================
 * P-256 Elliptic Curve  (y^2 = x^3 - 3x + b)
 * Constant-time fixed-width, no branches on point coordinates.
 * ================================================================ */
typedef struct { fp256 x,y,z; } ec256;

static int ec256_is_inf(const ec256 *p){return fp256_is_zero(&p->z);}
static void ec256_set_inf(ec256 *p){p->x=FP256_ONE;p->y=FP256_ONE;p->z=FP256_ZERO;}

static int ec256_on_curve(const fp256 *x, const fp256 *y) {
    fp256 y2, x3, t, three={{3,0,0,0}};
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

static void ec256_cswap(ec256 *a, ec256 *b, uint64_t bit) {
    uint64_t mask = -(uint64_t)bit;
    for(int i=0;i<4;i++){
        uint64_t d;
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
        uint64_t bit=(scalar[byte_idx]>>bit_pos)&1;
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
    priv[0]|=0x80;
    ec256 G; G.x=P256_GX; G.y=P256_GY; G.z=FP256_ONE;
    ec256 Q; ec256_scalar_mul(&Q,&G,priv);
    fp256 ax,ay; ec256_to_affine(&ax,&ay,&Q);
    pub[0]=0x04;
    fp256_to_bytes(pub+1,&ax);
    fp256_to_bytes(pub+33,&ay);
    if(!ec256_on_curve(&ax,&ay)) fprintf(stderr,"BUG: P-256 point NOT on curve!\n");
    else printf("  P-256 point verified on curve\n");
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
typedef struct { uint64_t v[4]; } fp25519;

static const fp25519 FP25519_ZERO = {{0,0,0,0}};

/* p = 2^255 - 19 */
static const fp25519 FP25519_P = {{
    0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF
}};

static uint64_t fp25519_add_raw(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    uint128_t c=0;
    for(int i=0;i<4;i++){c+=(uint128_t)a->v[i]+b->v[i];r->v[i]=(uint64_t)c;c>>=64;}
    return (uint64_t)c;
}

static uint64_t fp25519_sub_raw(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    __int128 borrow=0;
    for(int i=0;i<4;i++){
        borrow=(__int128)a->v[i]-b->v[i]+borrow;
        r->v[i]=(uint64_t)borrow; borrow>>=64;
    }
    return (borrow<0)?1:0;
}

static void fp25519_add(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    uint64_t carry=fp25519_add_raw(r,a,b);
    fp25519 t; uint64_t borrow=fp25519_sub_raw(&t,r,&FP25519_P);
    uint64_t mask=-(uint64_t)(carry|(1-borrow));
    for(int i=0;i<4;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp25519_sub(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    uint64_t borrow=fp25519_sub_raw(r,a,b);
    fp25519 t; fp25519_add_raw(&t,r,&FP25519_P);
    uint64_t mask=-(uint64_t)borrow;
    for(int i=0;i<4;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp25519_mul(fp25519 *r, const fp25519 *a, const fp25519 *b) {
    /* Schoolbook 4×4 → 8 limbs, reduce via 2^256 ≡ 38 (mod p) */
    uint64_t w[8]; memset(w,0,sizeof(w));
    for(int i=0;i<4;i++){
        uint64_t carry=0;
        for(int j=0;j<4;j++){
            uint128_t p=(uint128_t)a->v[i]*b->v[j]+w[i+j]+carry;
            w[i+j]=(uint64_t)p; carry=(uint64_t)(p>>64);
        }
        w[i+4]=carry;
    }
    /* Reduce: result = w[0..3] + w[4..7] * 38 */
    uint128_t c=0;
    for(int i=0;i<4;i++){
        c+=(uint128_t)w[i]+(uint128_t)w[i+4]*38;
        w[i]=(uint64_t)c; c>>=64;
    }
    /* Carry could be up to ~38, fold once more */
    c*=38;
    c+=(uint128_t)w[0]; w[0]=(uint64_t)c; c>>=64;
    for(int i=1;i<4&&c;i++){c+=(uint128_t)w[i]; w[i]=(uint64_t)c; c>>=64;}
    fp25519 res={{w[0],w[1],w[2],w[3]}};
    /* Conditional subtraction of p */
    fp25519 t; uint64_t borrow=fp25519_sub_raw(&t,&res,&FP25519_P);
    uint64_t mask=-(uint64_t)(1-borrow);
    for(int i=0;i<4;i++) res.v[i]=(res.v[i]&~mask)|(t.v[i]&mask);
    *r=res;
}

static void fp25519_sqr(fp25519 *r, const fp25519 *a){fp25519_mul(r,a,a);}

static void fp25519_inv(fp25519 *r, const fp25519 *a) {
    /* Fermat: a^(p-2) mod p, p-2 = 2^255 - 21 */
    static const fp25519 pm2={{
        0xFFFFFFFFFFFFFFEB, 0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF
    }};
    fp25519 result={{1,0,0,0}}, base=*a;
    for(int i=0;i<255;i++){
        if((pm2.v[i/64]>>(i%64))&1) fp25519_mul(&result,&result,&base);
        fp25519_sqr(&base,&base);
    }
    *r=result;
}

static void fp25519_mul_a24(fp25519 *r, const fp25519 *a) {
    /* Multiply by a24 = (486662-2)/4 = 121665 per RFC 7748 */
    uint128_t c=0;
    for(int i=0;i<4;i++){
        c+=(uint128_t)a->v[i]*121665; r->v[i]=(uint64_t)c; c>>=64;
    }
    /* Reduce carry: carry * 38 */
    uint64_t hi=(uint64_t)c;
    c=(uint128_t)r->v[0]+hi*38; r->v[0]=(uint64_t)c; c>>=64;
    for(int i=1;i<4&&c;i++){c+=(uint128_t)r->v[i]; r->v[i]=(uint64_t)c; c>>=64;}
    /* Conditional subtraction */
    fp25519 t; uint64_t borrow=fp25519_sub_raw(&t,r,&FP25519_P);
    uint64_t mask=-(uint64_t)(1-borrow);
    for(int i=0;i<4;i++) r->v[i]=(r->v[i]&~mask)|(t.v[i]&mask);
}

static void fp25519_cswap(fp25519 *a, fp25519 *b, uint64_t bit) {
    uint64_t mask=-(uint64_t)bit;
    for(int i=0;i<4;i++){
        uint64_t d=mask&(a->v[i]^b->v[i]);
        a->v[i]^=d; b->v[i]^=d;
    }
}

/* Load 32 bytes little-endian into fp25519 */
static void fp25519_from_le(fp25519 *r, const uint8_t b[32]) {
    for(int i=0;i<4;i++){r->v[i]=0;for(int j=0;j<8;j++)r->v[i]|=(uint64_t)b[i*8+j]<<(8*j);}
}

/* Store fp25519 as 32 bytes little-endian. Fully reduces first. */
static void fp25519_to_le(uint8_t b[32], const fp25519 *a) {
    fp25519 t=*a;
    /* Ensure fully reduced: subtract p if >= p (up to 2 times) */
    for(int pass=0;pass<2;pass++){
        fp25519 s; uint64_t borrow=fp25519_sub_raw(&s,&t,&FP25519_P);
        uint64_t mask=-(uint64_t)(1-borrow);
        for(int i=0;i<4;i++) t.v[i]=(t.v[i]&~mask)|(s.v[i]&mask);
    }
    for(int i=0;i<4;i++)for(int j=0;j<8;j++)b[i*8+j]=(t.v[i]>>(8*j))&0xFF;
}

/* X25519 Montgomery ladder (RFC 7748 §5) — x-coordinate only */
static void x25519_scalar_mult(const uint8_t scalar[32],
    const uint8_t u_in[32], uint8_t u_out[32]) {
    fp25519 u; fp25519_from_le(&u,u_in);
    /* Clamp scalar */
    uint8_t s[32]; memcpy(s,scalar,32);
    s[0]&=248; s[31]&=127; s[31]|=64;
    /* Montgomery ladder */
    fp25519 x_2={{1,0,0,0}}, z_2=FP25519_ZERO;
    fp25519 x_3=u, z_3={{1,0,0,0}};
    uint64_t swap=0;
    for(int t=254;t>=0;t--){
        uint64_t kt=(s[t/8]>>(t%8))&1;
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
 * ChaCha20 Stream Cipher (RFC 8439)
 * ================================================================ */
static uint32_t rotl32(uint32_t x, int n){return (x<<n)|(x>>(32-n));}

#define QR(a,b,c,d) \
    a+=b;d^=a;d=rotl32(d,16); \
    c+=d;b^=c;b=rotl32(b,12); \
    a+=b;d^=a;d=rotl32(d,8);  \
    c+=d;b^=c;b=rotl32(b,7);

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
    uint32_t counter, uint8_t out[64]) {
    uint32_t s[16];
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for(int i=0;i<8;i++)
        s[4+i]=(uint32_t)key[4*i]|((uint32_t)key[4*i+1]<<8)
              |((uint32_t)key[4*i+2]<<16)|((uint32_t)key[4*i+3]<<24);
    s[12]=counter;
    for(int i=0;i<3;i++)
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
    for(int i=0;i<16;i++){
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
 * Prime: p = 2^130 - 5.  Accumulator in 3×64-bit limbs.
 * ================================================================ */
static void poly1305_mac(const uint8_t key[32], const uint8_t *msg,
    size_t msg_len, uint8_t tag[16]) {
    /* Clamp r */
    uint64_t r0=0,r1=0;
    for(int i=0;i<8;i++) r0|=(uint64_t)key[i]<<(8*i);
    for(int i=0;i<8;i++) r1|=(uint64_t)key[8+i]<<(8*i);
    r0&=0x0FFFFFFC0FFFFFFF; r1&=0x0FFFFFFC0FFFFFFC;
    /* r as 3 limbs of 44/44/42 bits for schoolbook multiply with __uint128_t */
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
        uint128_t d0=(uint128_t)h0*rr0 + (uint128_t)h1*s2 + (uint128_t)h2*s1;
        uint128_t d1=(uint128_t)h0*rr1 + (uint128_t)h1*rr0 + (uint128_t)h2*s2;
        uint128_t d2=(uint128_t)h0*rr2 + (uint128_t)h1*rr1 + (uint128_t)h2*rr0;

        /* Partial reduction / carry propagation */
        uint64_t c0=(uint64_t)(d0>>44); h0=(uint64_t)d0 & 0xFFFFFFFFFFF;
        d1+=c0;
        uint64_t c1=(uint64_t)(d1>>44); h1=(uint64_t)d1 & 0xFFFFFFFFFFF;
        d2+=c1;
        uint64_t c2=(uint64_t)(d2>>42); h2=(uint64_t)d2 & 0x3FFFFFFFFFF;
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
    uint128_t sum=(uint128_t)lo+s_lo;
    lo=(uint64_t)sum;
    sum=(uint128_t)hi+s_hi+(uint64_t)(sum>>64);
    hi=(uint64_t)sum;

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

/* HelloRetryRequest sentinel random (RFC 8446 §4.1.3) */
static const uint8_t HRR_RANDOM[32] = {
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C
};

/* P-256 curve order n (big-endian) */
static const uint8_t P256_ORDER[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
    0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
};

/* P-384 curve order n (big-endian) */
static const uint8_t P384_ORDER[48] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,
    0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
    0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
};

/* ================================================================
 * ECDSA-P384 Signature Verification
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
    uint8_t tag; size_t len;
    p=der_read_tl(p,end,&tag,&len);
    if(!p||tag!=0x30) return 0;
    end=p+len;

    const uint8_t *rval=der_read_tl(p,end,&tag,&len);
    if(!rval||tag!=0x02) return 0;
    const uint8_t *rp=rval; size_t rlen=len;
    if(rlen>0&&rp[0]==0){rp++;rlen--;}
    p=rval+len;

    const uint8_t *sval=der_read_tl(p,end,&tag,&len);
    if(!sval||tag!=0x02) return 0;
    const uint8_t *sp=sval; size_t slen=len;
    if(slen>0&&sp[0]==0){sp++;slen--;}

    bignum r_bn, s_bn, n, hash_bn, w, u1, u2;
    bn_from_bytes(&r_bn,rp,rlen);
    bn_from_bytes(&s_bn,sp,slen);
    bn_from_bytes(&n,P384_ORDER,48);
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

/* ECDSA-P256 signature verification using bignum EC ops */
static int ecdsa_p256_verify(const uint8_t *hash, size_t hash_len,
                              const uint8_t *sig_der, size_t sig_len,
                              const uint8_t *pubkey, size_t pk_len) {
    if(pk_len!=P256_POINT_LEN||pubkey[0]!=0x04) return 0;

    /* Parse DER signature → (r, s) */
    const uint8_t *p=sig_der, *end=sig_der+sig_len;
    uint8_t tag; size_t len;
    p=der_read_tl(p,end,&tag,&len);
    if(!p||tag!=0x30) return 0;
    end=p+len;

    const uint8_t *rval=der_read_tl(p,end,&tag,&len);
    if(!rval||tag!=0x02) return 0;
    const uint8_t *rp=rval; size_t rlen=len;
    if(rlen>0&&rp[0]==0){rp++;rlen--;}
    p=rval+len;

    const uint8_t *sval=der_read_tl(p,end,&tag,&len);
    if(!sval||tag!=0x02) return 0;
    const uint8_t *sp=sval; size_t slen=len;
    if(slen>0&&sp[0]==0){sp++;slen--;}

    /* Bignum arithmetic on group order n (public data, variable-time OK) */
    bignum r_bn, s_bn, n, hash_bn, w, u1, u2;
    bn_from_bytes(&r_bn,rp,rlen);
    bn_from_bytes(&s_bn,sp,slen);
    bn_from_bytes(&n,P256_ORDER,32);
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
    bn_modexp(&m_bn,&s_bn,&e_bn,&n_bn);

    uint8_t em[512];
    if(mod_len>sizeof(em)) return 0;
    bn_to_bytes(&m_bn,em,mod_len);

    size_t em_len=mod_len;
    if(em[em_len-1]!=0xBC) return 0;

    size_t salt_len=hash_len;
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
        cb[hash_len]=(counter>>24)&0xFF;
        cb[hash_len+1]=(counter>>16)&0xFF;
        cb[hash_len+2]=(counter>>8)&0xFF;
        cb[hash_len+3]=counter&0xFF;
        uint8_t md[48];
        hash_fn(cb,hash_len+4,md);
        size_t use=db_len-done; if(use>hash_len) use=hash_len;
        memcpy(db_mask+done,md,use);
        done+=use; counter++;
    }

    uint8_t db[512];
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
    return ct_memeq(hp,h,hash_len) & (pad_ok == 0);
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

/* ================================================================
 * X.509 Certificate Parser
 * ================================================================ */
typedef struct {
    const uint8_t *tbs; size_t tbs_len;           /* raw TBS for hashing */
    const uint8_t *sig_alg; size_t sig_alg_len;   /* signature algorithm OID */
    const uint8_t *sig; size_t sig_len;            /* signature bytes */
    const uint8_t *issuer; size_t issuer_len;      /* raw DER of issuer Name */
    const uint8_t *subject; size_t subject_len;    /* raw DER of subject Name */
    int key_type;                                   /* 1=EC, 2=RSA */
    const uint8_t *pubkey; size_t pubkey_len;      /* EC: 04||x||y */
    const uint8_t *rsa_n; size_t rsa_n_len;        /* RSA modulus */
    const uint8_t *rsa_e; size_t rsa_e_len;        /* RSA exponent */
    const uint8_t *san; size_t san_len;            /* SAN extension value */
    time_t not_before, not_after;                  /* validity period */
    int is_ca;                                      /* basicConstraints CA flag */
    int path_len;                                   /* pathLenConstraint (-1 = unlimited) */
    uint16_t key_usage;                             /* keyUsage bit flags (0 = not present) */
    int has_key_usage;                              /* whether keyUsage extension was present */
    int has_eku;                                    /* whether EKU extension was present */
    int eku_server_auth;                            /* EKU contains serverAuth */
    int version;                                    /* 0=v1, 1=v2, 2=v3 */
} x509_cert;

static int parse_x509_extensions(x509_cert *cert, const uint8_t *tp, const uint8_t *tbs_end) {
    uint8_t tag; size_t len;
    if(tp>=tbs_end||*tp!=0xA3) return 0;
    const uint8_t *ext_outer=der_read_tl(tp,tbs_end,&tag,&len);
    if(!ext_outer) return 0;
    const uint8_t *exts_val=der_read_tl(ext_outer,ext_outer+len,&tag,&len);
    if(!exts_val||tag!=0x30) return 0;
    const uint8_t *ep=exts_val, *exts_end=exts_val+len;
    #define MAX_EXT_OIDS 20
    struct { const uint8_t *oid; size_t len; } seen_oids[MAX_EXT_OIDS];
    int seen_count=0;
    while(ep<exts_end){
        const uint8_t *ext_seq=der_read_tl(ep,exts_end,&tag,&len);
        if(!ext_seq||tag!=0x30) break;
        const uint8_t *ext_end2=ext_seq+len;
        ep=ext_end2;
        const uint8_t *eoid=der_read_tl(ext_seq,ext_end2,&tag,&len);
        if(!eoid||tag!=0x06) continue;
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
                        bp=bv+len;
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
    p=der_read_tl(p,end,&tag,&len);
    if(!p||tag!=0x30) return -1;
    const uint8_t *cert_end=p+len;

    /* TBSCertificate — save raw bytes including tag+length */
    const uint8_t *tbs_start=p;
    const uint8_t *tbs_val=der_read_tl(p,cert_end,&tag,&len);
    if(!tbs_val||tag!=0x30) return -1;
    cert->tbs=tbs_start;
    cert->tbs_len=(tbs_val+len)-tbs_start;
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
    tp=der_skip(tp,tbs_end); if(!tp) return -1;
    /* signature AlgorithmIdentifier */
    tp=der_skip(tp,tbs_end); if(!tp) return -1;

    /* issuer Name */
    const uint8_t *issuer_start=tp;
    tp=der_skip(tp,tbs_end); if(!tp) return -1;
    cert->issuer=issuer_start;
    cert->issuer_len=tp-issuer_start;

    /* validity */
    {
        const uint8_t *vld=der_read_tl(tp,tbs_end,&tag,&len);
        if(!vld||tag!=0x30) return -1;
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
    cert->subject_len=tp-subj_start;

    /* SubjectPublicKeyInfo */
    const uint8_t *spki_val=der_read_tl(tp,tbs_end,&tag,&len);
    if(!spki_val||tag!=0x30) return -1;
    const uint8_t *spki_end=spki_val+len;
    tp=spki_end;

    /* AlgorithmIdentifier inside SPKI */
    const uint8_t *alg_val=der_read_tl(spki_val,spki_end,&tag,&len);
    if(!alg_val||tag!=0x30) return -1;
    const uint8_t *alg_end=alg_val+len;

    const uint8_t *pk_oid=der_read_tl(alg_val,alg_end,&tag,&len);
    if(!pk_oid||tag!=0x06) return -1;
    int is_ec=oid_eq(pk_oid,len,OID_EC_PUBKEY,sizeof(OID_EC_PUBKEY));
    int is_rsa=oid_eq(pk_oid,len,OID_RSA_ENC,sizeof(OID_RSA_ENC));

    /* BIT STRING with public key follows AlgorithmIdentifier */
    const uint8_t *bs_val=der_read_tl(alg_end,spki_end,&tag,&len);
    if(!bs_val||tag!=0x03||len<2) return -1;

    if(is_ec){
        cert->key_type=1;
        cert->pubkey=bs_val+1; /* skip unused-bits byte */
        cert->pubkey_len=len-1;
    } else if(is_rsa){
        cert->key_type=2;
        const uint8_t *rsa_p=bs_val+1, *rsa_end2=bs_val+len;
        const uint8_t *rsa_seq=der_read_tl(rsa_p,rsa_end2,&tag,&len);
        if(!rsa_seq||tag!=0x30) return -1;
        const uint8_t *rsa_seq_end=rsa_seq+len;
        /* INTEGER n */
        const uint8_t *nv=der_read_tl(rsa_seq,rsa_seq_end,&tag,&len);
        if(!nv||tag!=0x02) return -1;
        cert->rsa_n=nv; cert->rsa_n_len=len;
        if(cert->rsa_n_len>0&&cert->rsa_n[0]==0){cert->rsa_n++;cert->rsa_n_len--;}
        /* INTEGER e */
        const uint8_t *ev=der_read_tl(nv+len,rsa_seq_end,&tag,&len);
        if(!ev||tag!=0x02) return -1;
        cert->rsa_e=ev; cert->rsa_e_len=len;
        if(cert->rsa_e_len>0&&cert->rsa_e[0]==0){cert->rsa_e++;cert->rsa_e_len--;}
    }

    /* Extensions [3] */
    if(parse_x509_extensions(cert,tp,tbs_end)<0) return -1;

    /* signatureAlgorithm (after TBS) */
    p=cert->tbs+cert->tbs_len;
    const uint8_t *sa_seq=der_read_tl(p,cert_end,&tag,&len);
    if(!sa_seq||tag!=0x30) return -1;
    const uint8_t *sa_end=sa_seq+len;
    const uint8_t *sa_oid=der_read_tl(sa_seq,sa_end,&tag,&len);
    if(!sa_oid||tag!=0x06) return -1;
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
        p=der_read_tl(p,end,&tag,&len);
        if(p&&tag==0x30){
            end=p+len;
            while(p<end){
                const uint8_t *val=der_read_tl(p,end,&tag,&len);
                if(!val) break;
                if(tag==0x82){ /* dNSName */
                    if(dns_name_eq(val,len,hostname,hn_len)) return 1;
                    if(wildcard_match(val,len,hostname)) return 1;
                }
                p=val+len;
            }
        }
        return 0;
    }
    /* CN fallback */
    static const uint8_t OID_CN[]={0x55,0x04,0x03};
    const uint8_t *p=cert->subject, *end=cert->subject+cert->subject_len;
    p=der_read_tl(p,end,&tag,&len);
    if(!p||tag!=0x30) return 0;
    end=p+len;
    while(p<end){
        const uint8_t *set_val=der_read_tl(p,end,&tag,&len);
        if(!set_val||tag!=0x31) break;
        p=set_val+len;
        const uint8_t *seq_val=der_read_tl(set_val,set_val+len,&tag,&len);
        if(!seq_val||tag!=0x30) continue;
        const uint8_t *seq_end=seq_val+len;
        const uint8_t *ov=der_read_tl(seq_val,seq_end,&tag,&len);
        if(!ov||tag!=0x06) continue;
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
} trust_cert;

static trust_cert trust_store[MAX_TRUST_CERTS];
static int trust_store_count=0;

static void load_trust_store(const char *dir) {
    DIR *d=opendir(dir);
    if(!d){fprintf(stderr,"Warning: cannot open %s\n",dir);return;}
    struct dirent *ent;
    uint8_t der_buf[4096];
    char pem_buf[8192];
    while((ent=readdir(d))!=NULL&&trust_store_count<MAX_TRUST_CERTS){
        size_t nl=strlen(ent->d_name);
        if(nl<4||strcmp(ent->d_name+nl-4,".crt")!=0) continue;
        char path[512];
        snprintf(path,sizeof(path),"%s/%s",dir,ent->d_name);
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
        if(cert.key_type==1&&cert.pubkey_len<=sizeof(tc->pubkey)){
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
        trust_store_count++;
    }
    closedir(d);
    printf("Loaded %d trust store certificates\n",trust_store_count);
}

/* Unified signature verification dispatch */
static int verify_signature(const uint8_t *tbs, size_t tbs_len,
                             const uint8_t *sig_alg, size_t sig_alg_len,
                             const uint8_t *sig, size_t sig_len,
                             int key_type,
                             const uint8_t *pubkey, size_t pubkey_len,
                             const uint8_t *rsa_n, size_t rsa_n_len,
                             const uint8_t *rsa_e, size_t rsa_e_len) {
    if(oid_eq(sig_alg,sig_alg_len,OID_ECDSA_SHA384,sizeof(OID_ECDSA_SHA384))){
        if(key_type!=1) return 0;
        uint8_t h[48]; sha384_hash(tbs,tbs_len,h);
        if(pubkey_len==P384_POINT_LEN)
            return ecdsa_p384_verify(h,SHA384_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
        if(pubkey_len==P256_POINT_LEN)
            return ecdsa_p256_verify(h,SHA384_DIGEST_LEN,sig,sig_len,pubkey,pubkey_len);
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
    return 0;
}

/* Validate leaf certificate: hostname, EKU, keyUsage */
static int validate_leaf_cert(const x509_cert *leaf, const char *hostname) {
    if(!verify_hostname(leaf,hostname)){
        fprintf(stderr,"Hostname verification failed for %s\n",hostname);
        return -1;
    }
    printf("    Hostname verified: %s\n",hostname);
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

    #define MAX_CHAIN 4
    const uint8_t *chain_der[MAX_CHAIN];
    size_t chain_len[MAX_CHAIN];
    int chain_count=0;

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
    printf("    Validity periods OK\n");

    /* Walk chain from leaf upward: at each cert, try trust store first,
     * then find issuer among remaining chain certs. Handles out-of-order
     * chains and cross-signed certs. */
    for(int i=0;i<chain_count;i++){
        /* Try trust store for this cert */
        for(int j=0;j<trust_store_count;j++){
            if(certs[i].issuer_len!=trust_store[j].subject_len) continue;
            if(memcmp(certs[i].issuer,trust_store[j].subject,certs[i].issuer_len)!=0) continue;
            printf("    Verifying cert %d against trust store...\n",i);
            if(verify_signature(certs[i].tbs,certs[i].tbs_len,
                                 certs[i].sig_alg,certs[i].sig_alg_len,
                                 certs[i].sig,certs[i].sig_len,
                                 trust_store[j].key_type,
                                 trust_store[j].pubkey,trust_store[j].pubkey_len,
                                 trust_store[j].rsa_n,trust_store[j].rsa_n_len,
                                 trust_store[j].rsa_e,trust_store[j].rsa_e_len)){
                printf("    Certificate %d root signature verified\n",i);
                printf("    Certificate chain verified successfully!\n");
                return 0;
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
        if(found<0){
            fprintf(stderr,"No issuer found for cert %d\n",i);
            return -1;
        }
        /* Detect cycle: issuer must not be the same cert */
        if(certs[i].tbs==certs[found].tbs){
            fprintf(stderr,"Certificate chain cycle detected at cert %d\n",i);
            return -1;
        }
        /* Swap found cert to position i+1 if needed */
        if(found!=i+1){
            x509_cert tmp=certs[i+1]; certs[i+1]=certs[found]; certs[found]=tmp;
        }
        printf("    Verifying cert %d signature...\n",i);
        if(!verify_signature(certs[i].tbs,certs[i].tbs_len,
                              certs[i].sig_alg,certs[i].sig_alg_len,
                              certs[i].sig,certs[i].sig_len,
                              certs[i+1].key_type,
                              certs[i+1].pubkey,certs[i+1].pubkey_len,
                              certs[i+1].rsa_n,certs[i+1].rsa_n_len,
                              certs[i+1].rsa_e,certs[i+1].rsa_e_len)){
            fprintf(stderr,"Signature verification failed for cert %d\n",i);
            return -1;
        }
        printf("    Certificate %d signature verified\n",i);
        /* Intermediate must be v3 (only v3 has extensions) */
        if(certs[i+1].version!=2){
            fprintf(stderr,"Certificate %d is not v3, cannot be CA\n",i+1);
            return -1;
        }
        /* Intermediate cert must have CA:TRUE basicConstraints */
        if(!certs[i+1].is_ca){
            fprintf(stderr,"Certificate %d used as CA but lacks basicConstraints CA:TRUE\n",i+1);
            return -1;
        }
        /* Enforce pathLenConstraint: i certs below this CA (0=leaf only) */
        if(certs[i+1].path_len>=0 && i>certs[i+1].path_len){
            fprintf(stderr,"Certificate %d exceeds pathLenConstraint %d\n",i+1,certs[i+1].path_len);
            return -1;
        }
        /* Intermediate: if keyUsage present, must include keyCertSign (bit 5) */
        if(certs[i+1].has_key_usage && !(certs[i+1].key_usage & 0x04)){
            fprintf(stderr,"CA certificate %d keyUsage missing keyCertSign\n",i+1);
            return -1;
        }
    }
    fprintf(stderr,"No matching root CA found in trust store\n");
    return -1;
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

/* Read a TLS record. Returns content type. */
static int tls_read_record(int fd, uint8_t *out, size_t *out_len) {
    uint8_t hdr[5];
    if(read_exact(fd,hdr,5)<0) return -1;
    uint16_t len=GET16(hdr+3);
    /* RFC 8446 §5.1: max 2^14+256 for TLS 1.3, RFC 5246 §6.2.3: 2^14+2048 for TLS 1.2 */
    if(len>16384+2048) die("record too large");
    if(read_exact(fd,out,len)<0) return -1;
    *out_len=len;
    return hdr[0];
}

/* Build ClientHello for TLS 1.2/1.3.
   only_group: 0 = emit all key shares (initial CH),
               specific group = emit only that group's key share (after HRR) */
static size_t build_client_hello(uint8_t *buf, const uint8_t p256_pub[P256_POINT_LEN],
                                  const uint8_t p384_pub[P384_POINT_LEN],
                                  const uint8_t x25519_pub[X25519_KEY_LEN],
                                  const char *host,
                                  uint8_t client_random[32], uint16_t only_group) {
    size_t p=0;
    /* Handshake header - fill length later */
    buf[p++]=0x01; /* ClientHello */
    buf[p++]=0; buf[p++]=0; buf[p++]=0; /* length placeholder */

    /* Legacy version TLS 1.2 */
    buf[p++]=(TLS_VERSION_12>>8); buf[p++]=(TLS_VERSION_12&0xFF);

    /* Random */
    random_bytes(buf+p,32);
    memcpy(client_random,buf+p,32);
    p+=32;

    /* Session ID (32 bytes for compat) */
    buf[p++]=32;
    random_bytes(buf+p,32); p+=32;

    /* Cipher suites: TLS 1.3 + TLS 1.2 GCM + ChaCha20-Poly1305 + CBC + SCSV */
    buf[p++]=0x00; buf[p++]=0x24; /* 36 bytes = 18 suites */
    buf[p++]=0x13; buf[p++]=0x01; /* TLS_AES_128_GCM_SHA256 */
    buf[p++]=0x13; buf[p++]=0x02; /* TLS_AES_256_GCM_SHA384 */
    buf[p++]=0x13; buf[p++]=0x03; /* TLS_CHACHA20_POLY1305_SHA256 */
    buf[p++]=0xCC; buf[p++]=0xA9; /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    buf[p++]=0xCC; buf[p++]=0xA8; /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    buf[p++]=0xC0; buf[p++]=0x2B; /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    buf[p++]=0xC0; buf[p++]=0x2F; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    buf[p++]=0xC0; buf[p++]=0x2C; /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    buf[p++]=0xC0; buf[p++]=0x30; /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    buf[p++]=0x00; buf[p++]=0x9D; /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    buf[p++]=0x00; buf[p++]=0x9C; /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    buf[p++]=0xC0; buf[p++]=0x14; /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    buf[p++]=0xC0; buf[p++]=0x13; /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    buf[p++]=0xC0; buf[p++]=0x0A; /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    buf[p++]=0xC0; buf[p++]=0x09; /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    buf[p++]=0x00; buf[p++]=0x35; /* TLS_RSA_WITH_AES_256_CBC_SHA */
    buf[p++]=0x00; buf[p++]=0x2F; /* TLS_RSA_WITH_AES_128_CBC_SHA */
    buf[p++]=0x00; buf[p++]=0xFF; /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746) */

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
    buf[p++]=0x00;buf[p++]=0x08; /* ext len */
    buf[p++]=0x00;buf[p++]=0x06; /* list len = 3 groups * 2 bytes */
    buf[p++]=(TLS_GROUP_X25519>>8);buf[p++]=(TLS_GROUP_X25519&0xFF); /* x25519 (preferred) */
    buf[p++]=(TLS_GROUP_SECP256R1>>8);buf[p++]=(TLS_GROUP_SECP256R1&0xFF); /* secp256r1 */
    buf[p++]=(TLS_GROUP_SECP384R1>>8);buf[p++]=(TLS_GROUP_SECP384R1&0xFF); /* secp384r1 */

    /* signature_algorithms */
    buf[p++]=0x00;buf[p++]=0x0d;
    buf[p++]=0x00;buf[p++]=0x0e; /* ext len */
    buf[p++]=0x00;buf[p++]=0x0c; /* list len */
    buf[p++]=0x05;buf[p++]=0x03; /* ecdsa_secp384r1_sha384 */
    buf[p++]=0x04;buf[p++]=0x03; /* ecdsa_secp256r1_sha256 */
    buf[p++]=0x08;buf[p++]=0x05; /* rsa_pss_rsae_sha384 */
    buf[p++]=0x08;buf[p++]=0x04; /* rsa_pss_rsae_sha256 */
    buf[p++]=0x05;buf[p++]=0x01; /* rsa_pkcs1_sha384 */
    buf[p++]=0x04;buf[p++]=0x01; /* rsa_pkcs1_sha256 */

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
    } else {
        /* Emit X25519 first (most preferred), then P-256, then P-384 */
        uint16_t shares_len=X25519_KEY_LEN+4+P256_POINT_LEN+4+P384_POINT_LEN+4;
        PUT16(buf+p,(uint16_t)(shares_len+2));p+=2;
        PUT16(buf+p,shares_len);p+=2;
        buf[p++]=(TLS_GROUP_X25519>>8);buf[p++]=(TLS_GROUP_X25519&0xFF);
        PUT16(buf+p,X25519_KEY_LEN);p+=2;
        memcpy(buf+p,x25519_pub,X25519_KEY_LEN);p+=X25519_KEY_LEN;
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

    /* Fill in lengths */
    PUT16(buf+ext_len_pos,(uint16_t)(p-ext_len_pos-2));
    uint32_t body_len=p-4;
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
                                    uint16_t *cipher_suite_out) {
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
    if(cs!=0x1301 && cs!=0x1302 && cs!=0x1303 &&
       cs!=0xCCA9 && cs!=0xCCA8 &&
       cs!=0xC02B && cs!=0xC02F && cs!=0xC02C && cs!=0xC030 &&
       cs!=0x009D && cs!=0x009C && cs!=0x0035 && cs!=0x002F &&
       cs!=0xC014 && cs!=0xC013 && cs!=0xC00A && cs!=0xC009) {
        fprintf(stderr,"cipher suite 0x%04x\n",cs);
        die("unexpected cipher suite");
    }
    /* compression */
    if(b+1>sh_end) die("ServerHello truncated at compression");
    b++;
    /* extensions (may not be present for TLS 1.2 minimal hello) */
    uint16_t version=TLS_VERSION_12; /* default TLS 1.2 */
    *pub_len=0;
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
            }
            b+=elen;
        }
    }
    (void)end;
    /* Note: pub_len==0 with version TLS_VERSION_13 is valid for HelloRetryRequest */
    return version;
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
                           int is_aes256, int is_chacha) {
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
    if(is_chacha)
        r=chacha20_poly1305_decrypt(key,nonce,aad,5,rec,ct_len,pt,tag);
    else {
        size_t kl=is_aes256?AES256_KEY_LEN:AES128_KEY_LEN;
        r=aes_gcm_decrypt_impl(key,kl,nonce,aad,5,rec,ct_len,pt,tag);
    }
    if(r<0) die("AEAD decrypt failed");

    /* Find inner content type (last non-zero byte) */
    size_t i=ct_len;
    while(i>0 && pt[i-1]==0) i--;
    if(i==0) die("no content type in record");
    uint8_t inner_type=pt[i-1];
    *pt_len=i-1;
    if(*pt_len>16384) die("decrypted record exceeds maximum plaintext size");
    return inner_type;
}

/* Encrypt and send a TLS 1.3 record */
static void encrypt_and_send(int fd, uint8_t inner_type,
                              const uint8_t *data, size_t len,
                              const uint8_t *key, const uint8_t iv[AES_GCM_NONCE_LEN],
                              uint64_t seq, int is_aes256, int is_chacha) {
    if(seq==UINT64_MAX) die("sequence number overflow");
    /* Build inner plaintext: data + content_type */
    if(len>16384) die("TLS 1.3 record too large to encrypt");
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

    if(is_chacha)
        chacha20_poly1305_encrypt(key,nonce,aad,5,inner,ct_len,ct,tag);
    else
        aes_gcm_encrypt_impl(key,is_aes256?AES256_KEY_LEN:AES128_KEY_LEN,
            nonce,aad,5,inner,ct_len,ct,tag);
    memcpy(ct+ct_len,tag,16);

    tls_send_record(fd,TLS_RT_APPDATA,ct,ct_len+16);
    free(inner); free(ct);
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
    for(int i=7;i>=0;i--) nonce[4+(7-i)]=(seq>>(8*i))&0xFF;

    uint8_t aad[13];
    for(int i=7;i>=0;i--) aad[7-i]=(seq>>(8*i))&0xFF;
    aad[8]=content_type;
    aad[9]=(TLS_VERSION_12>>8); aad[10]=(TLS_VERSION_12&0xFF);
    PUT16(aad+11,(uint16_t)len);

    if(len>16384) die("TLS 1.2 record too large to encrypt");
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
    for(int i=7;i>=0;i--) aad[7-i]=(seq>>(8*i))&0xFF;
    aad[8]=content_type;
    aad[9]=(TLS_VERSION_12>>8); aad[10]=(TLS_VERSION_12&0xFF);
    PUT16(aad+11,(uint16_t)ct_len);

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
    for(int i=7;i>=0;i--) mac_input_hdr[7-i]=(seq>>(8*i))&0xFF;
    mac_input_hdr[8]=content_type;
    mac_input_hdr[9]=(TLS_VERSION_12>>8); mac_input_hdr[10]=(TLS_VERSION_12&0xFF);
    PUT16(mac_input_hdr+11,(uint16_t)len);

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
    uint8_t pad_len=(uint8_t)(16-1-(unpadded%16)); /* 0..15 */
    size_t padded_len=unpadded+pad_len+1;
    uint8_t *plain=malloc(padded_len);
    if(!plain) die("malloc failed");
    memcpy(plain,data,len);
    memcpy(plain+len,mac_out,mac_len);
    memset(plain+unpadded,pad_len,pad_len+1);

    /* Generate random IV and encrypt */
    uint8_t iv[16];
    random_bytes(iv,16);
    uint8_t *ct_body=malloc(padded_len);
    if(!ct_body) die("malloc failed");
    aes_cbc_encrypt(write_key,key_len,iv,plain,padded_len,ct_body);
    free(plain);

    /* Send record: [IV][ciphertext] */
    size_t rec_len=16+padded_len;
    uint8_t *rec=malloc(rec_len);
    if(!rec) die("malloc failed");
    memcpy(rec,iv,16);
    memcpy(rec+16,ct_body,padded_len);
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
    if(rec_len<32) return -1; /* need at least IV(16) + one block(16) */
    const uint8_t *iv=rec;
    const uint8_t *ct=rec+16;
    size_t ct_len=rec_len-16;
    if(ct_len%16!=0) return -1;

    /* Decrypt */
    uint8_t *plain=malloc(ct_len);
    if(!plain) die("malloc failed");
    aes_cbc_decrypt(read_key,key_len,iv,ct,ct_len,plain);

    /* Check and strip padding (constant-time) */
    uint8_t pad_val=plain[ct_len-1];
    if(pad_val>=ct_len){free(plain);return -1;}
    uint8_t pad_ok=0;
    for(size_t i=0;i<(size_t)(pad_val+1);i++)
        pad_ok|=plain[ct_len-1-i]^pad_val;

    size_t mac_len=mac_alg->digest_len;
    size_t content_len=ct_len-pad_val-1-mac_len;
    /* Avoid underflow: if padding+mac exceeds plaintext, reject */
    if(pad_val+1+mac_len>ct_len){free(plain);return -1;}

    /* Extract MAC and compute expected MAC */
    const uint8_t *received_mac=plain+content_len;

    uint8_t mac_input_hdr[13];
    for(int i=7;i>=0;i--) mac_input_hdr[7-i]=(seq>>(8*i))&0xFF;
    mac_input_hdr[8]=content_type;
    mac_input_hdr[9]=(TLS_VERSION_12>>8); mac_input_hdr[10]=(TLS_VERSION_12&0xFF);
    PUT16(mac_input_hdr+11,(uint16_t)content_len);

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
    memcpy(nonce,write_iv,12);
    for(int i=0;i<8;i++) nonce[11-i]^=(seq>>(8*i))&0xFF;

    uint8_t aad[13];
    for(int i=7;i>=0;i--) aad[7-i]=(seq>>(8*i))&0xFF;
    aad[8]=content_type;
    aad[9]=(TLS_VERSION_12>>8); aad[10]=(TLS_VERSION_12&0xFF);
    PUT16(aad+11,(uint16_t)len);

    if(len>16384) die("TLS 1.2 ChaCha record too large");
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
    memcpy(nonce,read_iv,12);
    for(int i=0;i<8;i++) nonce[11-i]^=(seq>>(8*i))&0xFF;

    uint8_t aad[13];
    for(int i=7;i>=0;i--) aad[7-i]=(seq>>(8*i))&0xFF;
    aad[8]=content_type;
    aad[9]=(TLS_VERSION_12>>8); aad[10]=(TLS_VERSION_12&0xFF);
    PUT16(aad+11,(uint16_t)ct_len);

    int r=chacha20_poly1305_decrypt(read_key,nonce,aad,13,rec,ct_len,pt,tag);
    if(r<0) return -1;
    *pt_len=ct_len;
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
    uint8_t server_pub[P384_POINT_LEN]; size_t server_pub_len;
    uint16_t cipher_suite;
    sha256_ctx transcript;
    sha384_ctx transcript384;
    size_t sh_leftover;
    uint8_t sh_leftover_data[REC_BUF_SIZE];
} tls_conn;

/* ================================================================
 * TLS 1.2 Handshake
 * ================================================================ */
static void tls12_handshake(tls_conn *conn) {
    int fd = conn->fd;
    const char *host = conn->host;
    const char *path = conn->path;
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
    sha256_ctx transcript = conn->transcript;
    sha384_ctx transcript384 = conn->transcript384;

    uint8_t x25519_priv[X25519_KEY_LEN], x25519_pub[X25519_KEY_LEN];
    memcpy(x25519_priv, conn->x25519_priv, X25519_KEY_LEN);
    memcpy(x25519_pub, conn->x25519_pub, X25519_KEY_LEN);

    int is_rsa_kex = (cipher_suite==0x009D || cipher_suite==0x009C
                   || cipher_suite==0x0035 || cipher_suite==0x002F);
    int is_cbc = (cipher_suite==0xC014 || cipher_suite==0xC013
               || cipher_suite==0x0035 || cipher_suite==0x002F
               || cipher_suite==0xC00A || cipher_suite==0xC009);
    int is_chacha = (cipher_suite==0xCCA8 || cipher_suite==0xCCA9);
    printf("Negotiated TLS 1.2 (cipher suite 0x%04x%s%s%s)\n",cipher_suite,
           is_rsa_kex?" RSA-kex":"", is_cbc?" CBC":"", is_chacha?" ChaCha20":"");

    /* Read plaintext handshake messages */
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    uint8_t hs12_buf[HS_BUF_SIZE]; size_t hs12_len=0;
    int got_server_done=0;
    uint8_t *cert12_msg=NULL; size_t cert12_msg_len=0;
    uint8_t ske_pubkey[P384_POINT_LEN];
    uint16_t ske_curve=0;

    /* Carry leftover handshake data from ServerHello record */
    if(conn->sh_leftover>0 && conn->sh_leftover<=sizeof(hs12_buf)) {
        memcpy(hs12_buf, conn->sh_leftover_data, conn->sh_leftover);
        hs12_len=conn->sh_leftover;
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

            sha256_update(&transcript, hs12_buf+pos, msg_total);
            sha384_update(&transcript384, hs12_buf+pos, msg_total);

            switch(mtype) {
                case 11: /* Certificate */
                    printf("  Certificate (%u bytes)\n",(unsigned)mlen);
                    cert12_msg=malloc(mlen);
                    if(!cert12_msg) die("malloc failed");
                    memcpy(cert12_msg, hs12_buf+pos+4, mlen);
                    cert12_msg_len=mlen;
                    break;
                case 12: { /* ServerKeyExchange (not sent for RSA key transport) */
                    if(is_rsa_kex) die("unexpected ServerKeyExchange for RSA key transport");
                    printf("  ServerKeyExchange (%u bytes)\n",(unsigned)mlen);
                    if(mlen<8) die("ServerKeyExchange too short");
                    const uint8_t *ske=hs12_buf+pos+4;
                    if(ske[0]!=0x03) die("expected named_curve type in SKE");
                    ske_curve=GET16(ske+1);
                    uint8_t pk_len=ske[3];
                    if(ske_curve==TLS_GROUP_X25519) {
                        if(pk_len!=X25519_KEY_LEN) die("expected 32-byte X25519 key");
                    } else if(ske_curve==TLS_GROUP_SECP256R1) {
                        if(pk_len!=P256_POINT_LEN) die("expected uncompressed P-256 point");
                    } else if(ske_curve==TLS_GROUP_SECP384R1) {
                        if(pk_len!=P384_POINT_LEN) die("expected uncompressed P-384 point");
                    } else die("unsupported curve in SKE");
                    if(4+pk_len>mlen) die("SKE pubkey truncated");
                    memcpy(ske_pubkey, ske+4, pk_len);

                    size_t params_len=4+pk_len;
                    if(params_len+4>mlen) die("SKE signature header truncated");
                    const uint8_t *sig_ptr=ske+params_len;
                    uint16_t sig_algo=GET16(sig_ptr); sig_ptr+=2;
                    uint16_t sig_len_val=GET16(sig_ptr); sig_ptr+=2;
                    if(params_len+4+sig_len_val>mlen) die("SKE signature truncated");

                    /* Validate sig algo against offered signature_algorithms */
                    if(sig_algo!=0x0403 && sig_algo!=0x0503 &&
                       sig_algo!=0x0804 && sig_algo!=0x0805 &&
                       sig_algo!=0x0401 && sig_algo!=0x0501)
                        die("SKE signature algorithm not in offered list");

                    /* Signed data: client_random || server_random || params */
                    uint8_t signed_data[256];
                    memcpy(signed_data, client_random, 32);
                    memcpy(signed_data+32, server_random, 32);
                    memcpy(signed_data+64, ske, params_len);
                    size_t signed_len=64+params_len;

                    /* Parse leaf cert for verification */
                    if(!cert12_msg) die("Certificate must precede ServerKeyExchange");
                    if(cert12_msg_len<6) die("Certificate message too short");
                    const uint8_t *cp=cert12_msg;
                    uint32_t list_len12=GET24(cp); cp+=3;
                    if(3+list_len12>cert12_msg_len) die("Certificate list length exceeds message");
                    if(list_len12<3) die("Certificate list too short");
                    uint32_t first_cert_len=GET24(cp); cp+=3;
                    if(6+first_cert_len>cert12_msg_len) die("First certificate exceeds message");
                    x509_cert leaf;
                    if(x509_parse(&leaf,cp,first_cert_len)!=0) die("Failed to parse leaf cert");

                    int sig_ok=0;
                    if(sig_algo==0x0403) { /* ecdsa + sha256 */
                        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(signed_data,signed_len,h);
                        if(leaf.key_type==1 && leaf.pubkey_len==P256_POINT_LEN)
                            sig_ok=ecdsa_p256_verify(h,SHA256_DIGEST_LEN,
                                sig_ptr,sig_len_val,leaf.pubkey,leaf.pubkey_len);
                        else if(leaf.key_type==1 && leaf.pubkey_len==P384_POINT_LEN)
                            sig_ok=ecdsa_p384_verify(h,SHA384_DIGEST_LEN,
                                sig_ptr,sig_len_val,leaf.pubkey,leaf.pubkey_len);
                    } else if(sig_algo==0x0503) { /* ecdsa + sha384 */
                        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(signed_data,signed_len,h);
                        if(leaf.key_type==1 && leaf.pubkey_len==P256_POINT_LEN)
                            sig_ok=ecdsa_p256_verify(h,SHA384_DIGEST_LEN,
                                sig_ptr,sig_len_val,leaf.pubkey,leaf.pubkey_len);
                        else if(leaf.key_type==1 && leaf.pubkey_len==P384_POINT_LEN)
                            sig_ok=ecdsa_p384_verify(h,SHA384_DIGEST_LEN,
                                sig_ptr,sig_len_val,leaf.pubkey,leaf.pubkey_len);
                    } else if(sig_algo==0x0401) { /* rsa_pkcs1_sha256 */
                        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(signed_data,signed_len,h);
                        if(leaf.key_type==2)
                            sig_ok=rsa_pkcs1_verify(h,SHA256_DIGEST_LEN,
                                DI_SHA256,sizeof(DI_SHA256),sig_ptr,sig_len_val,
                                leaf.rsa_n,leaf.rsa_n_len,leaf.rsa_e,leaf.rsa_e_len);
                    } else if(sig_algo==0x0804) { /* rsa_pss_rsae_sha256 */
                        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(signed_data,signed_len,h);
                        if(leaf.key_type==2)
                            sig_ok=rsa_pss_verify(h,SHA256_DIGEST_LEN,sha256_hash,
                                sig_ptr,sig_len_val,leaf.rsa_n,leaf.rsa_n_len,
                                leaf.rsa_e,leaf.rsa_e_len);
                    } else if(sig_algo==0x0805) { /* rsa_pss_rsae_sha384 */
                        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(signed_data,signed_len,h);
                        if(leaf.key_type==2)
                            sig_ok=rsa_pss_verify(h,SHA384_DIGEST_LEN,sha384_hash,
                                sig_ptr,sig_len_val,leaf.rsa_n,leaf.rsa_n_len,
                                leaf.rsa_e,leaf.rsa_e_len);
                    } else if(sig_algo==0x0501) { /* rsa_pkcs1_sha384 */
                        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(signed_data,signed_len,h);
                        if(leaf.key_type==2)
                            sig_ok=rsa_pkcs1_verify(h,SHA384_DIGEST_LEN,
                                DI_SHA384,sizeof(DI_SHA384),sig_ptr,sig_len_val,
                                leaf.rsa_n,leaf.rsa_n_len,leaf.rsa_e,leaf.rsa_e_len);
                    }
                    if(!sig_ok) die("ServerKeyExchange signature verification failed");
                    printf("    SKE signature verified (algo=0x%04x)\n",sig_algo);
                    break;
                }
                case 14: /* ServerHelloDone */
                    printf("  ServerHelloDone\n");
                    got_server_done=1;
                    break;
                default:
                    printf("  TLS 1.2 handshake msg type %d (%u bytes)\n",mtype,(unsigned)mlen);
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

    /* Validate certificate chain */
    if(cert12_msg) {
        printf("  Validating certificate chain...\n");
        if(verify_cert_chain(cert12_msg,cert12_msg_len,host,0)<0)
            die("Certificate verification failed");
    }

    /* Send ClientKeyExchange */
    uint8_t ss12[P384_SCALAR_LEN]; size_t ss12_len;
    if(is_rsa_kex) {
        /* RSA key transport: encrypt PMS with server's RSA public key */
        if(!cert12_msg) die("No certificate for RSA key exchange");
        if(cert12_msg_len<6) die("Certificate message too short");
        const uint8_t *cp2=cert12_msg;
        uint32_t ll2=GET24(cp2); cp2+=3;
        if(3+ll2>cert12_msg_len) die("cert list length");
        if(ll2<3) die("cert list too short");
        uint32_t cl2=GET24(cp2); cp2+=3;
        if(6+cl2>cert12_msg_len) die("first cert exceeds message");
        x509_cert leaf;
        if(x509_parse(&leaf,cp2,cl2)!=0) die("Failed to parse leaf cert for RSA kex");
        if(leaf.key_type!=2) die("RSA key transport requires RSA cert");

        uint8_t pms[48];
        pms[0]=0x03; pms[1]=0x03; /* TLS 1.2 version */
        random_bytes(pms+2,46);

        uint8_t encrypted_pms[512];
        if(rsa_encrypt(pms,48,leaf.rsa_n,leaf.rsa_n_len,leaf.rsa_e,leaf.rsa_e_len,encrypted_pms)<0)
            die("RSA encrypt failed");

        size_t enc_len=leaf.rsa_n_len;
        uint8_t cke[4+2+512];
        uint32_t cke_body_len=2+enc_len;
        cke[0]=0x10;
        cke[1]=(cke_body_len>>16)&0xFF; cke[2]=(cke_body_len>>8)&0xFF; cke[3]=cke_body_len&0xFF;
        PUT16(cke+4,(uint16_t)enc_len);
        memcpy(cke+6,encrypted_pms,enc_len);
        size_t cke_total=4+2+enc_len;
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,cke_total);
        sha256_update(&transcript, cke, cke_total);
        sha384_update(&transcript384, cke, cke_total);

        memcpy(ss12,pms,48);
        ss12_len=48;
        secure_zero(pms,sizeof(pms));
        printf("Sent ClientKeyExchange (RSA encrypted PMS, %zu bytes)\n",enc_len);
    } else if(ske_curve==TLS_GROUP_X25519) {
        uint8_t cke[5+X25519_KEY_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0; cke[3]=X25519_KEY_LEN+1; cke[4]=X25519_KEY_LEN;
        memcpy(cke+5, x25519_pub, X25519_KEY_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(&transcript, cke, sizeof(cke));
        sha384_update(&transcript384, cke, sizeof(cke));
        if(x25519_shared_secret(x25519_priv, ske_pubkey, ss12)<0)
            die("X25519 shared secret is zero");
        ss12_len=X25519_KEY_LEN;
        printf("Sent ClientKeyExchange\nComputed ECDHE shared secret (X25519)\n");
    } else if(ske_curve==TLS_GROUP_SECP256R1) {
        uint8_t cke[5+P256_POINT_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0; cke[3]=P256_POINT_LEN+1; cke[4]=P256_POINT_LEN;
        memcpy(cke+5, p256_pub, P256_POINT_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(&transcript, cke, sizeof(cke));
        sha384_update(&transcript384, cke, sizeof(cke));
        ecdhe_p256_shared_secret(p256_priv, ske_pubkey, ss12);
        ss12_len=P256_SCALAR_LEN;
        printf("Sent ClientKeyExchange\nComputed ECDHE shared secret (P-256)\n");
    } else {
        uint8_t cke[5+P384_POINT_LEN];
        cke[0]=0x10; cke[1]=0; cke[2]=0; cke[3]=P384_POINT_LEN+1; cke[4]=P384_POINT_LEN;
        memcpy(cke+5, p384_pub, P384_POINT_LEN);
        tls_send_record(fd,TLS_RT_HANDSHAKE,cke,sizeof(cke));
        sha256_update(&transcript, cke, sizeof(cke));
        sha384_update(&transcript384, cke, sizeof(cke));
        ecdhe_shared_secret(p384_priv, ske_pubkey, ss12);
        ss12_len=P384_SCALAR_LEN;
        printf("Sent ClientKeyExchange\nComputed ECDHE shared secret (P-384)\n");
    }
    secure_zero(p256_priv,sizeof(p256_priv));
    secure_zero(p384_priv,sizeof(p384_priv));
    secure_zero(x25519_priv,sizeof(x25519_priv));

    /* TLS 1.2 key derivation */
    int is_aes256 = (cipher_suite==0xC02C || cipher_suite==0xC030
                  || cipher_suite==0x009D || cipher_suite==0xC014
                  || cipher_suite==0x0035 || cipher_suite==0xC00A);
    /* PRF hash: 0x009D (GCM-SHA384) uses SHA-384, ChaCha20 suites use SHA-256 */
    int prf_is_sha384 = (cipher_suite==0xC02C || cipher_suite==0xC030 || cipher_suite==0x009D);
    const hash_alg *alg = prf_is_sha384 ? &SHA384_ALG : &SHA256_ALG;
    size_t key_len;
    if(is_chacha) key_len=32;
    else key_len = is_aes256 ? AES256_KEY_LEN : AES128_KEY_LEN;
    size_t mac_key_len = is_cbc ? SHA1_DIGEST_LEN : 0;
    size_t iv_len;
    if(is_cbc) iv_len=16;
    else if(is_chacha) iv_len=12;
    else iv_len=4; /* GCM implicit nonce */
    const hash_alg *mac_alg = is_cbc ? &SHA1_ALG : NULL;

    uint8_t pms_seed[64];
    memcpy(pms_seed, client_random, 32);
    memcpy(pms_seed+32, server_random, 32);

    uint8_t tls12_master[48];
    tls12_prf_u(alg, ss12, ss12_len, "master secret", pms_seed, 64, tls12_master, 48);

    uint8_t ke_seed[64];
    memcpy(ke_seed, server_random, 32);
    memcpy(ke_seed+32, client_random, 32);

    size_t kb_len = mac_key_len*2 + key_len*2 + iv_len*2;
    uint8_t key_block[136]; /* max: 20*2 + 32*2 + 16*2 = 136 */
    tls12_prf_u(alg, tls12_master, 48, "key expansion", ke_seed, 64, key_block, kb_len);

    uint8_t c_mk[20]={0}, s_mk[20]={0}; /* MAC keys (CBC only) */
    uint8_t c_wk[32], s_wk[32], c_wiv[16]={0}, s_wiv[16]={0};
    size_t off=0;
    memcpy(c_mk, key_block+off, mac_key_len); off+=mac_key_len;
    memcpy(s_mk, key_block+off, mac_key_len); off+=mac_key_len;
    memcpy(c_wk, key_block+off, key_len); off+=key_len;
    memcpy(s_wk, key_block+off, key_len); off+=key_len;
    memcpy(c_wiv, key_block+off, iv_len); off+=iv_len;
    memcpy(s_wiv, key_block+off, iv_len);
    printf("Derived TLS 1.2 traffic keys\n");

    /* Send ChangeCipherSpec */
    { uint8_t ccs=1; tls_send_record(fd,TLS_RT_CCS,&ccs,1); }
    printf("Sent ChangeCipherSpec\n");

    /* Send Finished (encrypted) */
    {
        uint8_t th12[SHA384_DIGEST_LEN];
        size_t th12_len;
        if(prf_is_sha384) {
            sha384_ctx tc384=transcript384; sha384_final(&tc384,th12);
            th12_len=SHA384_DIGEST_LEN;
        } else {
            sha256_ctx tc=transcript; sha256_final(&tc,th12);
            th12_len=SHA256_DIGEST_LEN;
        }

        uint8_t verify_data[12];
        tls12_prf_u(alg, tls12_master, 48, "client finished", th12, th12_len, verify_data, 12);

        uint8_t fin_msg[16];
        fin_msg[0]=0x14;
        fin_msg[1]=0; fin_msg[2]=0; fin_msg[3]=12;
        memcpy(fin_msg+4, verify_data, 12);

        if(is_cbc)
            tls12_encrypt_and_send_cbc(fd, TLS_RT_HANDSHAKE, fin_msg, 16,
                c_wk, key_len, c_mk, mac_key_len, mac_alg, 0);
        else if(is_chacha)
            tls12_encrypt_and_send_chacha(fd, TLS_RT_HANDSHAKE, fin_msg, 16, c_wk, c_wiv, 0);
        else
            tls12_encrypt_and_send(fd, TLS_RT_HANDSHAKE, fin_msg, 16, c_wk, c_wiv, 0, key_len);
        sha256_update(&transcript, fin_msg, 16);
        sha384_update(&transcript384, fin_msg, 16);
        printf("Sent Finished (encrypted)\n");
    }

    /* Receive ChangeCipherSpec */
    rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype!=TLS_RT_CCS) die("expected ChangeCipherSpec from server");
    printf("Received ChangeCipherSpec\n");

    /* Receive server Finished (encrypted) */
    rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype!=TLS_RT_HANDSHAKE) die("expected Finished from server");
    {
        uint8_t pt12[256]; size_t pt12_len;
        int dec_ok;
        if(is_cbc)
            dec_ok=tls12_decrypt_record_cbc(rec, rec_len, TLS_RT_HANDSHAKE,
                s_wk, key_len, s_mk, mac_key_len, mac_alg, 0, pt12, &pt12_len);
        else if(is_chacha)
            dec_ok=tls12_decrypt_record_chacha(rec, rec_len,
                TLS_RT_HANDSHAKE, s_wk, s_wiv, 0, pt12, &pt12_len);
        else
            dec_ok=tls12_decrypt_record(rec, rec_len, TLS_RT_HANDSHAKE,
                s_wk, s_wiv, 0, pt12, &pt12_len, key_len);
        if(dec_ok<0) die("Failed to decrypt server Finished");
        if(pt12[0]!=0x14) die("expected Finished message type");
        if(pt12_len<4||GET24(pt12+1)!=12) die("Server Finished length mismatch");

        uint8_t th12_sf[SHA384_DIGEST_LEN];
        size_t th12_sf_len;
        if(prf_is_sha384) {
            sha384_ctx tc384=transcript384; sha384_final(&tc384,th12_sf);
            th12_sf_len=SHA384_DIGEST_LEN;
        } else {
            sha256_ctx tc=transcript; sha256_final(&tc,th12_sf);
            th12_sf_len=SHA256_DIGEST_LEN;
        }
        uint8_t expected[12];
        tls12_prf_u(alg, tls12_master, 48, "server finished", th12_sf, th12_sf_len, expected, 12);
        if(!ct_memeq(expected, pt12+4, 12)) die("Server Finished verify failed!");
        printf("Server Finished VERIFIED\n");
    }

    /* Send HTTP GET */
    uint64_t c12_seq=1;
    {
        char req[REQ_BUF_SIZE];
        int rlen=snprintf(req,sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: tls_client/0.1\r\n\r\n",
            path,host);
        if(is_cbc)
            tls12_encrypt_and_send_cbc(fd,TLS_RT_APPDATA,(uint8_t*)req,rlen,
                c_wk,key_len,c_mk,mac_key_len,mac_alg,c12_seq++);
        else if(is_chacha)
            tls12_encrypt_and_send_chacha(fd,TLS_RT_APPDATA,
                (uint8_t*)req,rlen,c_wk,c_wiv,c12_seq++);
        else
            tls12_encrypt_and_send(fd,TLS_RT_APPDATA,(uint8_t*)req,rlen,
                c_wk,c_wiv,c12_seq++,key_len);
        printf("Sent HTTP GET %s\n\n",path);
    }

    /* Receive HTTP response */
    uint64_t s12_seq=1;
    printf("=== HTTP Response ===\n");
    for(;;) {
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype<0) break;
        if(rtype==TLS_RT_APPDATA) {
            uint8_t pt12[REC_BUF_SIZE]; size_t pt12_len;
            int dec_ok2;
            if(is_cbc)
                dec_ok2=tls12_decrypt_record_cbc(rec,rec_len,TLS_RT_APPDATA,
                    s_wk,key_len,s_mk,mac_key_len,mac_alg,s12_seq++,pt12,&pt12_len);
            else if(is_chacha)
                dec_ok2=tls12_decrypt_record_chacha(rec,rec_len,TLS_RT_APPDATA,
                    s_wk,s_wiv,s12_seq++,pt12,&pt12_len);
            else
                dec_ok2=tls12_decrypt_record(rec,rec_len,TLS_RT_APPDATA,
                    s_wk,s_wiv,s12_seq++,pt12,&pt12_len,key_len);
            if(dec_ok2<0) {
                fprintf(stderr,"Decrypt failed at seq %llu\n",(unsigned long long)(s12_seq-1));
                break;
            }
            fwrite(pt12,1,pt12_len,stdout);
        } else if(rtype==TLS_RT_ALERT) {
            if(rec_len>=2 && rec[0]==1 && rec[1]==0) break;
            break;
        } else {
            break;
        }
    }
    /* Send close_notify */
    if(is_cbc)
    {   uint8_t alert[2]={1,0};
        if(is_cbc)
            tls12_encrypt_and_send_cbc(fd,TLS_RT_ALERT,alert,2,
                c_wk,key_len,c_mk,mac_key_len,mac_alg,c12_seq++);
        else if(is_chacha)
            tls12_encrypt_and_send_chacha(fd,TLS_RT_ALERT,alert,2,
                c_wk,c_wiv,c12_seq++);
        else
            tls12_encrypt_and_send(fd,TLS_RT_ALERT,alert,2,
                c_wk,c_wiv,c12_seq++,key_len);
    }
    printf("\n=== Done ===\n");

    free(cert12_msg);
    secure_zero(ss12,sizeof(ss12));
    secure_zero(pms_seed,sizeof(pms_seed));
    secure_zero(ke_seed,sizeof(ke_seed));
    secure_zero(tls12_master,sizeof(tls12_master));
    secure_zero(key_block,sizeof(key_block));
    secure_zero(c_wk,sizeof(c_wk)); secure_zero(s_wk,sizeof(s_wk));
    secure_zero(c_wiv,sizeof(c_wiv)); secure_zero(s_wiv,sizeof(s_wiv));
    secure_zero(c_mk,sizeof(c_mk)); secure_zero(s_mk,sizeof(s_mk));
    secure_zero(p384_priv,sizeof(p384_priv));
    secure_zero(p256_priv,sizeof(p256_priv));
    secure_zero(x25519_priv,sizeof(x25519_priv));
    close(fd);
}

/* ================================================================
 * TLS 1.3 Handshake
 * ================================================================ */
static void tls13_handshake(tls_conn *conn) {
    int fd = conn->fd;
    const char *host = conn->host;
    const char *path = conn->path;
    uint16_t cipher_suite = conn->cipher_suite;
    uint8_t server_pub[P384_POINT_LEN];
    size_t server_pub_len = conn->server_pub_len;
    memcpy(server_pub, conn->server_pub, server_pub_len);
    uint8_t p256_priv[P256_SCALAR_LEN], p384_priv[P384_SCALAR_LEN];
    memcpy(p256_priv, conn->p256_priv, P256_SCALAR_LEN);
    memcpy(p384_priv, conn->p384_priv, P384_SCALAR_LEN);
    uint8_t x25519_priv[X25519_KEY_LEN];
    memcpy(x25519_priv, conn->x25519_priv, X25519_KEY_LEN);
    sha256_ctx transcript = conn->transcript;
    sha384_ctx transcript384 = conn->transcript384;

    int is_aes256 = (cipher_suite == 0x1302);
    int is_chacha = (cipher_suite == 0x1303);
    const hash_alg *alg = is_aes256 ? &SHA384_ALG : &SHA256_ALG;
    size_t hash_len = alg->digest_len;

    uint16_t selected_group;
    if(server_pub_len==X25519_KEY_LEN) selected_group=TLS_GROUP_X25519;
    else if(server_pub_len==P256_POINT_LEN) selected_group=TLS_GROUP_SECP256R1;
    else selected_group=TLS_GROUP_SECP384R1;
    printf("Received ServerHello (TLS 1.3, cipher=0x%04x, group=0x%04x)\n",
        cipher_suite,selected_group);

    /* Compute shared secret based on negotiated group */
    uint8_t shared[P384_SCALAR_LEN]; size_t shared_len;
    if(selected_group==TLS_GROUP_X25519) {
        if(x25519_shared_secret(x25519_priv,server_pub,shared)<0)
            die("X25519 shared secret is zero");
        shared_len=X25519_KEY_LEN;
    } else if(selected_group==TLS_GROUP_SECP256R1) {
        uint8_t ss[P256_SCALAR_LEN];
        ecdhe_p256_shared_secret(p256_priv,server_pub,ss);
        memcpy(shared,ss,P256_SCALAR_LEN);
        shared_len=P256_SCALAR_LEN;
        secure_zero(ss,sizeof(ss));
    } else {
        ecdhe_shared_secret(p384_priv,server_pub,shared);
        shared_len=P384_SCALAR_LEN;
    }
    secure_zero(p256_priv,sizeof(p256_priv));
    secure_zero(p384_priv,sizeof(p384_priv));
    secure_zero(x25519_priv,sizeof(x25519_priv));
    printf("Computed ECDHE shared secret (%zu bytes)\n",shared_len);

    /* Derive handshake keys */
    uint8_t early_secret[SHA384_DIGEST_LEN];
    { uint8_t z[SHA384_DIGEST_LEN]={0};
      hkdf_extract_u(alg,z,alg->digest_len,z,alg->digest_len,early_secret); }
    uint8_t derived1[SHA384_DIGEST_LEN];
    { uint8_t empty_hash[SHA384_DIGEST_LEN]; alg->hash(NULL,0,empty_hash);
      hkdf_expand_label_u(alg,early_secret,"derived",empty_hash,
          alg->digest_len,derived1,alg->digest_len); }
    uint8_t hs_secret[SHA384_DIGEST_LEN];
    hkdf_extract_u(alg,derived1,alg->digest_len,shared,shared_len,hs_secret);

    uint8_t th1[SHA384_DIGEST_LEN];
    if(is_aes256) {
        sha384_ctx tc=transcript384; sha384_final(&tc,th1);
    } else {
        sha256_ctx tc=transcript; sha256_final(&tc,th1);
    }

    uint8_t s_hs_traffic[SHA384_DIGEST_LEN], c_hs_traffic[SHA384_DIGEST_LEN];
    hkdf_expand_label_u(alg,hs_secret,"s hs traffic",th1,
        alg->digest_len,s_hs_traffic,alg->digest_len);
    hkdf_expand_label_u(alg,hs_secret,"c hs traffic",th1,
        alg->digest_len,c_hs_traffic,alg->digest_len);

    size_t kl = is_aes256 ? AES256_KEY_LEN : (is_chacha ? 32 : AES128_KEY_LEN);
    uint8_t s_hs_key[AES256_KEY_LEN], s_hs_iv[AES_GCM_NONCE_LEN];
    uint8_t c_hs_key[AES256_KEY_LEN], c_hs_iv[AES_GCM_NONCE_LEN];
    hkdf_expand_label_u(alg,s_hs_traffic,"key",NULL,0,s_hs_key,kl);
    hkdf_expand_label_u(alg,s_hs_traffic,"iv",NULL,0,s_hs_iv,AES_GCM_NONCE_LEN);
    hkdf_expand_label_u(alg,c_hs_traffic,"key",NULL,0,c_hs_key,kl);
    hkdf_expand_label_u(alg,c_hs_traffic,"iv",NULL,0,c_hs_iv,AES_GCM_NONCE_LEN);
    printf("Derived handshake traffic keys\n");

    /* Read encrypted handshake messages */
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype;
    uint64_t s_hs_seq=0;
    uint8_t hs_buf[HS_BUF_SIZE]; size_t hs_buf_len=0;

    /* May get a ChangeCipherSpec first (compat) */
    rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype==TLS_RT_CCS) { /* CCS, skip it */
        rtype=tls_read_record(fd,rec,&rec_len);
    }

    /* Process encrypted records until we get Finished */
    int got_finished=0, got_cert_verify=0, got_cert_request=0;
    uint8_t *saved_cert_msg=NULL; size_t saved_cert_msg_len=0;
    while(!got_finished) {
        if(rtype!=TLS_RT_APPDATA) die("expected encrypted record");
        uint8_t pt[REC_BUF_SIZE]; size_t pt_len;
        int inner=decrypt_record(rec,rec_len,s_hs_key,s_hs_iv,
            s_hs_seq++,pt,&pt_len,is_aes256,is_chacha);
        if(inner!=TLS_RT_HANDSHAKE) die("expected handshake inside encrypted record");

        /* Append to handshake buffer */
        if(hs_buf_len+pt_len>sizeof(hs_buf)) die("TLS 1.3 handshake buffer overflow");
        memcpy(hs_buf+hs_buf_len,pt,pt_len);
        hs_buf_len+=pt_len;

        /* Process complete handshake messages from buffer */
        size_t pos=0;
        while(pos+4<=hs_buf_len) {
            uint8_t mtype=hs_buf[pos];
            uint32_t mlen=GET24(hs_buf+pos+1);
            if(pos+4+mlen>hs_buf_len) break; /* incomplete */
            size_t msg_total=4+mlen;

            switch(mtype) {
                case 8: /* EncryptedExtensions */
                    printf("  EncryptedExtensions (%u bytes)\n",(unsigned)mlen);
                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    break;
                case 11: /* Certificate */
                    printf("  Certificate (%u bytes)\n",(unsigned)mlen);
                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    saved_cert_msg=malloc(mlen);
                    if(!saved_cert_msg) die("malloc failed");
                    memcpy(saved_cert_msg,hs_buf+pos+4,mlen);
                    saved_cert_msg_len=mlen;
                    break;
                case 13: /* CertificateRequest */
                    printf("  CertificateRequest (%u bytes)\n",(unsigned)mlen);
                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    got_cert_request=1;
                    break;
                case 15: { /* CertificateVerify */
                    printf("  CertificateVerify (%u bytes)\n",(unsigned)mlen);

                    /* Validate cert chain first */
                    if(saved_cert_msg){
                        printf("  Validating certificate chain...\n");
                        if(verify_cert_chain(saved_cert_msg,saved_cert_msg_len,host,1)<0)
                            die("Certificate verification failed");
                    }

                    /* Verify CertificateVerify signature (RFC 8446 §4.4.3) */
                    if(mlen<4) die("CertificateVerify too short");
                    const uint8_t *cv=hs_buf+pos+4;
                    uint16_t cv_algo=GET16(cv);
                    uint16_t cv_sig_len=GET16(cv+2);
                    if(4+cv_sig_len>mlen) die("CertificateVerify sig length mismatch");
                    const uint8_t *cv_sig=cv+4;

                    /* RFC 8446 §4.4.3: sig algos for CertificateVerify */
                    if(cv_algo!=0x0403 && cv_algo!=0x0503 &&
                       cv_algo!=0x0804 && cv_algo!=0x0805)
                        die("CertificateVerify uses sig algo not in offered list");

                    /* Transcript hash up to (but not including) CertificateVerify */
                    uint8_t th_cv[SHA384_DIGEST_LEN];
                    if(is_aes256) {
                        sha384_ctx tc=transcript384; sha384_final(&tc,th_cv);
                    } else {
                        sha256_ctx tc=transcript; sha256_final(&tc,th_cv);
                    }

                    /* Content to verify: 64 spaces || context string || 0x00 || transcript hash */
                    size_t cv_content_len = 64 + 33 + 1 + hash_len;
                    uint8_t cv_content[64+33+1+SHA384_DIGEST_LEN];
                    memset(cv_content,0x20,64);
                    memcpy(cv_content+64,"TLS 1.3, server CertificateVerify",33);
                    cv_content[97]=0x00;
                    memcpy(cv_content+98,th_cv,hash_len);

                    /* Parse leaf cert public key */
                    if(!saved_cert_msg) die("No certificate for CertificateVerify");
                    const uint8_t *cp2=saved_cert_msg;
                    uint8_t ctx_len2=*cp2++; cp2+=ctx_len2;
                    cp2+=3; /* skip list length */
                    uint32_t leaf_len=GET24(cp2); cp2+=3;
                    x509_cert leaf;
                    if(x509_parse(&leaf,cp2,leaf_len)!=0) die("Failed to parse leaf cert for CV");

                    int cv_ok=0;
                    if(cv_algo==0x0403){ /* ecdsa_secp256r1_sha256 */
                        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(cv_content,cv_content_len,h);
                        if(leaf.key_type==1 && leaf.pubkey_len==P256_POINT_LEN)
                            cv_ok=ecdsa_p256_verify(h,SHA256_DIGEST_LEN,
                                cv_sig,cv_sig_len,leaf.pubkey,leaf.pubkey_len);
                    } else if(cv_algo==0x0503){ /* ecdsa_secp384r1_sha384 */
                        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(cv_content,cv_content_len,h);
                        if(leaf.key_type==1 && leaf.pubkey_len==P384_POINT_LEN)
                            cv_ok=ecdsa_p384_verify(h,SHA384_DIGEST_LEN,
                                cv_sig,cv_sig_len,leaf.pubkey,leaf.pubkey_len);
                    } else if(cv_algo==0x0804){ /* rsa_pss_rsae_sha256 */
                        uint8_t h[SHA256_DIGEST_LEN]; sha256_hash(cv_content,cv_content_len,h);
                        if(leaf.key_type==2)
                            cv_ok=rsa_pss_verify(h,SHA256_DIGEST_LEN,sha256_hash,
                                cv_sig,cv_sig_len,leaf.rsa_n,leaf.rsa_n_len,
                                leaf.rsa_e,leaf.rsa_e_len);
                    } else if(cv_algo==0x0805){ /* rsa_pss_rsae_sha384 */
                        uint8_t h[SHA384_DIGEST_LEN]; sha384_hash(cv_content,cv_content_len,h);
                        if(leaf.key_type==2)
                            cv_ok=rsa_pss_verify(h,SHA384_DIGEST_LEN,sha384_hash,
                                cv_sig,cv_sig_len,leaf.rsa_n,leaf.rsa_n_len,
                                leaf.rsa_e,leaf.rsa_e_len);
                    }
                    if(!cv_ok) die("CertificateVerify signature verification failed");
                    printf("  CertificateVerify VERIFIED (algo=0x%04x)\n",cv_algo);
                    got_cert_verify=1;

                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    break;
                }
                case 20: { /* Finished */
                    if(!got_cert_verify) die("Server Finished without CertificateVerify");
                    if(mlen!=hash_len) die("Server Finished length mismatch");
                    printf("  Server Finished\n");
                    /* Verify server finished */
                    uint8_t fin_key[SHA384_DIGEST_LEN];
                    hkdf_expand_label_u(alg,s_hs_traffic,"finished",NULL,0,fin_key,alg->digest_len);
                    uint8_t th_before_fin[SHA384_DIGEST_LEN];
                    if(is_aes256) {
                        sha384_ctx tc=transcript384; sha384_final(&tc,th_before_fin);
                    } else {
                        sha256_ctx tc=transcript; sha256_final(&tc,th_before_fin);
                    }
                    uint8_t expected[SHA384_DIGEST_LEN];
                    hmac(alg,fin_key,alg->digest_len,th_before_fin,alg->digest_len,expected);
                    if(!ct_memeq(expected,hs_buf+pos+4,hash_len))
                        die("Server Finished verify failed!");
                    printf("  Server Finished VERIFIED\n");
                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    got_finished=1;
                    break;
                }
                default:
                    printf("  Unknown handshake msg type %d\n",mtype);
                    if(is_aes256) sha384_update(&transcript384,hs_buf+pos,msg_total);
                    else sha256_update(&transcript,hs_buf+pos,msg_total);
                    break;
            }
            pos+=msg_total;
        }
        /* Shift remaining data */
        if(pos>0 && pos<hs_buf_len) {
            memmove(hs_buf,hs_buf+pos,hs_buf_len-pos);
            hs_buf_len-=pos;
        } else if(pos==hs_buf_len) {
            hs_buf_len=0;
        }

        if(!got_finished)
            rtype=tls_read_record(fd,rec,&rec_len);
    }

    /* Derive application keys */
    uint8_t th_sf[SHA384_DIGEST_LEN];
    if(is_aes256) {
        sha384_ctx tc=transcript384; sha384_final(&tc,th_sf);
    } else {
        sha256_ctx tc=transcript; sha256_final(&tc,th_sf);
    }

    uint8_t derived2[SHA384_DIGEST_LEN];
    { uint8_t empty_hash[SHA384_DIGEST_LEN]; alg->hash(NULL,0,empty_hash);
      hkdf_expand_label_u(alg,hs_secret,"derived",empty_hash,
          alg->digest_len,derived2,alg->digest_len); }
    uint8_t master_secret[SHA384_DIGEST_LEN];
    { uint8_t z[SHA384_DIGEST_LEN]={0};
      hkdf_extract_u(alg,derived2,alg->digest_len,z,alg->digest_len,master_secret); }

    uint8_t s_ap_traffic[SHA384_DIGEST_LEN], c_ap_traffic[SHA384_DIGEST_LEN];
    hkdf_expand_label_u(alg,master_secret,"s ap traffic",th_sf,
        alg->digest_len,s_ap_traffic,alg->digest_len);
    hkdf_expand_label_u(alg,master_secret,"c ap traffic",th_sf,
        alg->digest_len,c_ap_traffic,alg->digest_len);

    uint8_t s_ap_key[AES256_KEY_LEN], s_ap_iv[AES_GCM_NONCE_LEN];
    uint8_t c_ap_key[AES256_KEY_LEN], c_ap_iv[AES_GCM_NONCE_LEN];
    hkdf_expand_label_u(alg,s_ap_traffic,"key",NULL,0,s_ap_key,kl);
    hkdf_expand_label_u(alg,s_ap_traffic,"iv",NULL,0,s_ap_iv,AES_GCM_NONCE_LEN);
    hkdf_expand_label_u(alg,c_ap_traffic,"key",NULL,0,c_ap_key,kl);
    hkdf_expand_label_u(alg,c_ap_traffic,"iv",NULL,0,c_ap_iv,AES_GCM_NONCE_LEN);
    printf("Derived application traffic keys\n");

    /* Send client ChangeCipherSpec (compat) */
    { uint8_t ccs=1; tls_send_record(fd,TLS_RT_CCS,&ccs,1); }

    uint64_t c_hs_seq=0;

    /* If server requested client cert, send empty Certificate (RFC 8446 §4.4.2) */
    if(got_cert_request) {
        /* Empty Certificate: context_len(1)=0, cert_list_len(3)=0 */
        uint8_t cert_msg[8];
        cert_msg[0]=0x0b; /* Certificate */
        cert_msg[1]=0; cert_msg[2]=0; cert_msg[3]=4; /* length = 4 */
        cert_msg[4]=0; /* certificate_request_context length = 0 */
        cert_msg[5]=0; cert_msg[6]=0; cert_msg[7]=0; /* certificate_list length = 0 */
        encrypt_and_send(fd,TLS_RT_HANDSHAKE,cert_msg,8,
            c_hs_key,c_hs_iv,c_hs_seq++,is_aes256,is_chacha);
        if(is_aes256) sha384_update(&transcript384,cert_msg,8);
        else sha256_update(&transcript,cert_msg,8);
        printf("Sent empty client Certificate\n");
    }

    /* Send client Finished */
    {
        /* Transcript hash includes client Certificate if sent */
        uint8_t th_for_fin[SHA384_DIGEST_LEN];
        if(is_aes256) {
            sha384_ctx tc=transcript384; sha384_final(&tc,th_for_fin);
        } else {
            sha256_ctx tc=transcript; sha256_final(&tc,th_for_fin);
        }
        uint8_t fin_key[SHA384_DIGEST_LEN];
        hkdf_expand_label_u(alg,c_hs_traffic,"finished",NULL,0,fin_key,alg->digest_len);
        uint8_t verify[SHA384_DIGEST_LEN];
        hmac(alg,fin_key,alg->digest_len,th_for_fin,alg->digest_len,verify);
        uint8_t fin_msg[52]; fin_msg[0]=0x14;
        fin_msg[1]=0; fin_msg[2]=0; fin_msg[3]=(uint8_t)hash_len;
        memcpy(fin_msg+4,verify,hash_len);
        encrypt_and_send(fd,TLS_RT_HANDSHAKE,fin_msg,4+hash_len,
            c_hs_key,c_hs_iv,c_hs_seq++,is_aes256,is_chacha);
    }
    printf("Sent client Finished\n");

    /* Send HTTP GET (encrypted with application keys) */
    uint64_t c_ap_seq=0;
    {
        char req[REQ_BUF_SIZE];
        int rlen=snprintf(req,sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: tls_client/0.1\r\n\r\n",
            path,host);
        encrypt_and_send(fd,TLS_RT_APPDATA,(uint8_t*)req,rlen,
            c_ap_key,c_ap_iv,c_ap_seq++,is_aes256,is_chacha);
        printf("Sent HTTP GET %s\n\n",path);
    }

    /* Receive HTTP response */
    uint64_t s_ap_seq=0;
    printf("=== HTTP Response ===\n");
    for(;;) {
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype<0) break;
        if(rtype==TLS_RT_APPDATA) {
            uint8_t pt[REC_BUF_SIZE]; size_t pt_len;
            int inner=decrypt_record(rec,rec_len,s_ap_key,s_ap_iv,
                s_ap_seq++,pt,&pt_len,is_aes256,is_chacha);
            if(inner==TLS_RT_APPDATA) { /* application data */
                fwrite(pt,1,pt_len,stdout);
            } else if(inner==TLS_RT_ALERT) { /* alert */
                if(pt_len>=2 && pt[0]==1 && pt[1]==0) break; /* close_notify */
                printf("\n[TLS Alert: %d %d]\n",pt[0],pt_len>1?pt[1]:-1);
                break;
            } else if(inner==TLS_RT_HANDSHAKE) {
                /* Post-handshake message */
                if(pt_len>=5 && pt[0]==24 && GET24(pt+1)==1) {
                    /* KeyUpdate (type 24, length 1) */
                    uint8_t request_update=pt[4];
                    /* Derive new server traffic secret */
                    {
                        uint8_t new_s[SHA384_DIGEST_LEN];
                        hkdf_expand_label_u(alg,s_ap_traffic,"traffic upd",
                            NULL,0,new_s,alg->digest_len);
                        memcpy(s_ap_traffic,new_s,alg->digest_len);
                        hkdf_expand_label_u(alg,s_ap_traffic,"key",NULL,0,s_ap_key,kl);
                        hkdf_expand_label_u(alg,s_ap_traffic,"iv",
                            NULL,0,s_ap_iv,AES_GCM_NONCE_LEN);
                    }
                    s_ap_seq=0;
                    if(request_update==1) {
                        /* Send KeyUpdate(update_not_requested) with current client keys */
                        uint8_t ku_msg[5]={24,0,0,1,0};
                        encrypt_and_send(fd,TLS_RT_HANDSHAKE,ku_msg,5,
                            c_ap_key,c_ap_iv,c_ap_seq++,is_aes256,is_chacha);
                        /* Derive new client traffic secret */
                        {
                            uint8_t new_c[SHA384_DIGEST_LEN];
                            hkdf_expand_label_u(alg,c_ap_traffic,"traffic upd",
                                NULL,0,new_c,alg->digest_len);
                            memcpy(c_ap_traffic,new_c,alg->digest_len);
                            hkdf_expand_label_u(alg,c_ap_traffic,"key",NULL,0,c_ap_key,kl);
                            hkdf_expand_label_u(alg,c_ap_traffic,"iv",
                                NULL,0,c_ap_iv,AES_GCM_NONCE_LEN);
                        }
                        c_ap_seq=0;
                    }
                }
                /* else: NewSessionTicket or other post-handshake, skip */
            }
        } else if(rtype==TLS_RT_ALERT) {
            break;
        } else {
            break;
        }
    }
    /* Send close_notify */
    { uint8_t alert[2]={1,0};
      encrypt_and_send(fd,TLS_RT_ALERT,alert,2,c_ap_key,c_ap_iv,
          c_ap_seq,is_aes256,is_chacha); }
    printf("\n=== Done ===\n");
    free(saved_cert_msg);
    secure_zero(p384_priv,sizeof(p384_priv));
    secure_zero(p256_priv,sizeof(p256_priv));
    secure_zero(x25519_priv,sizeof(x25519_priv));
    secure_zero(shared,sizeof(shared));
    secure_zero(early_secret,sizeof(early_secret));
    secure_zero(derived1,sizeof(derived1));
    secure_zero(hs_secret,sizeof(hs_secret));
    secure_zero(s_hs_traffic,sizeof(s_hs_traffic));
    secure_zero(c_hs_traffic,sizeof(c_hs_traffic));
    secure_zero(s_hs_key,sizeof(s_hs_key)); secure_zero(s_hs_iv,sizeof(s_hs_iv));
    secure_zero(c_hs_key,sizeof(c_hs_key)); secure_zero(c_hs_iv,sizeof(c_hs_iv));
    secure_zero(derived2,sizeof(derived2));
    secure_zero(master_secret,sizeof(master_secret));
    secure_zero(s_ap_key,sizeof(s_ap_key)); secure_zero(s_ap_iv,sizeof(s_ap_iv));
    secure_zero(c_ap_key,sizeof(c_ap_key)); secure_zero(c_ap_iv,sizeof(c_ap_iv));
    close(fd);
}

/* Main TLS handshake + HTTP GET */
static void do_https_get(const char *host, int port, const char *path) {
    load_trust_store("trust_store");

    int fd=tcp_connect(host,port);
    printf("Connected to %s:%d\n",host,port);

    /* Generate ECDHE keypairs for all groups */
    uint8_t p384_priv[P384_SCALAR_LEN], p384_pub[P384_POINT_LEN];
    ecdhe_keygen(p384_priv,p384_pub);
    uint8_t p256_priv[P256_SCALAR_LEN], p256_pub[P256_POINT_LEN];
    ecdhe_p256_keygen(p256_priv,p256_pub);
    uint8_t x25519_priv[X25519_KEY_LEN], x25519_pub_key[X25519_KEY_LEN];
    x25519_keygen(x25519_priv,x25519_pub_key);
    printf("Generated ECDHE keypairs (X25519 + P-256 + P-384)\n");

    /* Build & send ClientHello */
    uint8_t ch[CH_BUF_SIZE];
    uint8_t client_random[32];
    size_t ch_len=build_client_hello(ch,p256_pub,p384_pub,x25519_pub_key,host,client_random,0);
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
    printf("Sent ClientHello (%zu bytes)\n",ch_len);

    /* Read ServerHello */
    uint8_t rec[REC_BUF_SIZE]; size_t rec_len;
    int rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype==TLS_RT_ALERT && rec_len>=2) {
        fprintf(stderr,"Alert: level=%d desc=%d\n",rec[0],rec[1]);
        die("server sent alert");
    }
    if(rtype!=TLS_RT_HANDSHAKE) die("expected handshake record");
    if(rec[0]!=0x02) die("expected ServerHello");
    uint8_t server_pub[P384_POINT_LEN]; size_t server_pub_len=0;
    uint8_t server_random[32];
    uint16_t cipher_suite;
    uint16_t version=parse_server_hello(rec,rec_len,server_pub,
        &server_pub_len,server_random,&cipher_suite);
    uint32_t sh_msg_len=4+GET24(rec+1);
    sha256_update(&transcript,rec,sh_msg_len);
    sha384_update(&transcript384,rec,sh_msg_len);
    size_t sh_leftover=rec_len>sh_msg_len ? rec_len-sh_msg_len : 0;

    /* ================================================================
     * HelloRetryRequest Handling (RFC 8446 §4.1.4)
     * ================================================================ */
    if(memcmp(server_random,HRR_RANDOM,32)==0) {
        printf("Received HelloRetryRequest (cipher=0x%04x)\n",cipher_suite);
        /* Parse HRR extensions to find selected group */
        uint16_t hrr_group=0;
        {
            const uint8_t *b=rec+4; /* skip handshake header */
            b+=2; /* version */
            b+=32; /* random */
            uint8_t sid_len=*b++; b+=sid_len; /* session id */
            b+=2; /* cipher suite */
            b++; /* compression */
            if(b+2<=rec+sh_msg_len) {
                uint16_t ext_total=GET16(b); b+=2;
                const uint8_t *ext_end=b+ext_total;
                if(ext_end>rec+sh_msg_len) ext_end=rec+sh_msg_len;
                while(b+4<=ext_end) {
                    uint16_t etype=GET16(b); b+=2;
                    uint16_t elen=GET16(b); b+=2;
                    if(b+elen>ext_end) break;
                    if(etype==0x0033 && elen==2) { /* key_share with just selected group */
                        hrr_group=GET16(b);
                    }
                    b+=elen;
                }
            }
        }
        if(hrr_group!=TLS_GROUP_X25519 && hrr_group!=TLS_GROUP_SECP256R1
           && hrr_group!=TLS_GROUP_SECP384R1)
            die("HRR selected unsupported group");
        printf("  HRR selected group 0x%04x\n",hrr_group);

        int hrr_aes256 = (cipher_suite == 0x1302);

        /* Transcript replacement per RFC 8446 §4.4.1:
           Hash(CH1) → synthetic message_hash, then add HRR */
        if(hrr_aes256) {
            uint8_t ch1_hash[SHA384_DIGEST_LEN];
            sha384_ctx tc=transcript384; sha384_final(&tc,ch1_hash);
            sha384_init(&transcript384);
            uint8_t synth[4+SHA384_DIGEST_LEN]={0xFE,0x00,0x00,SHA384_DIGEST_LEN};
            memcpy(synth+4,ch1_hash,SHA384_DIGEST_LEN);
            sha384_update(&transcript384,synth,sizeof(synth));
            sha384_update(&transcript384,rec,sh_msg_len);
        } else {
            uint8_t ch1_hash[SHA256_DIGEST_LEN];
            sha256_ctx tc=transcript; sha256_final(&tc,ch1_hash);
            sha256_init(&transcript);
            uint8_t synth[4+SHA256_DIGEST_LEN]={0xFE,0x00,0x00,SHA256_DIGEST_LEN};
            memcpy(synth+4,ch1_hash,SHA256_DIGEST_LEN);
            sha256_update(&transcript,synth,sizeof(synth));
            sha256_update(&transcript,rec,sh_msg_len);
        }

        /* Build new ClientHello with only the requested group */
        ch_len=build_client_hello(ch,p256_pub,p384_pub,x25519_pub_key,host,client_random,hrr_group);
        if(hrr_aes256)
            sha384_update(&transcript384,ch,ch_len);
        else
            sha256_update(&transcript,ch,ch_len);

        /* Send new ClientHello */
        tls_send_record(fd,TLS_RT_HANDSHAKE,ch,ch_len);
        printf("Sent new ClientHello with group 0x%04x (%zu bytes)\n",hrr_group,ch_len);

        /* Read real ServerHello (skip CCS if present) */
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype==TLS_RT_CCS) { /* ChangeCipherSpec, skip */
            rtype=tls_read_record(fd,rec,&rec_len);
        }
        if(rtype==TLS_RT_ALERT && rec_len>=2) {
            fprintf(stderr,"Alert: level=%d desc=%d\n",rec[0],rec[1]);
            die("server sent alert after HRR");
        }
        if(rtype!=TLS_RT_HANDSHAKE) die("expected handshake record after HRR");
        if(rec[0]!=0x02) die("expected ServerHello after HRR");
        version=parse_server_hello(rec,rec_len,server_pub,
            &server_pub_len,server_random,&cipher_suite);
        if(version!=TLS_VERSION_13) die("expected TLS 1.3 after HRR");
        if(server_pub_len==0) die("no key_share in real ServerHello after HRR");
        sh_msg_len=4+GET24(rec+1);
        if(hrr_aes256)
            sha384_update(&transcript384,rec,sh_msg_len);
        else
            sha256_update(&transcript,rec,sh_msg_len);
        sh_leftover=rec_len>sh_msg_len ? rec_len-sh_msg_len : 0;
        printf("Received real ServerHello after HRR (cipher=0x%04x)\n",cipher_suite);
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

    if(version == TLS_VERSION_12) {
        tls12_handshake(&conn);
    } else {
        tls13_handshake(&conn);
    }

    /* Clear connection context secrets */
    secure_zero(&conn, sizeof(conn));
}


int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s https://host[:port]/path\n", argv[0]); return 1; }
    const char *url = argv[1];
    if (strncmp(url, "https://", 8) != 0) die("URL must start with https://");
    const char *hoststart = url + 8;
    const char *slash = strchr(hoststart, '/');
    const char *path = slash ? slash : "/";
    char host[256];
    int port = 443;
    size_t hostlen = slash ? (size_t)(slash - hoststart) : strlen(hoststart);
    if (hostlen >= sizeof(host)) die("hostname too long");
    memcpy(host, hoststart, hostlen);
    host[hostlen] = '\0';
    /* check for :port */
    char *colon = strchr(host, ':');
    if (colon) { port = atoi(colon + 1); *colon = '\0'; }
    printf("TLS 1.2/1.3 HTTPS Client — from scratch in C\n");
    printf("Ciphers: AES-GCM, ChaCha20-Poly1305 | Key Exchange: X25519, P-256, P-384\n\n");
    do_https_get(host, port, path);
    return 0;
}
