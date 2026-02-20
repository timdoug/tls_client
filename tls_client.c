/*
 * tls_client.c — TLS 1.3 HTTPS client from scratch in C.
 * Implements: SHA-256, HMAC, HKDF, AES-128-GCM, ECDHE-P384, TLS 1.3
 * No external crypto libraries.
 *
 * Compile:  cc -O2 -o tls_client tls_client.c
 * Run:      ./tls_client
 *
 * NOTE: Certificate verification is NOT implemented — educational demo only.
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

typedef unsigned __int128 uint128_t;

#define PUT16(b,v) do{(b)[0]=(uint8_t)((v)>>8);(b)[1]=(uint8_t)(v);}while(0)
#define GET16(b) (((uint16_t)(b)[0]<<8)|(b)[1])
#define GET24(b) (((uint32_t)(b)[0]<<16)|((uint32_t)(b)[1]<<8)|(b)[2])

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
    for (int i=0;i<16;i++) w[i]=((uint32_t)blk[4*i]<<24)|((uint32_t)blk[4*i+1]<<16)|((uint32_t)blk[4*i+2]<<8)|blk[4*i+3];
    for (int i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
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
    for (int i=0;i<8;i++) { out[4*i]=(ctx->h[i]>>24)&0xFF; out[4*i+1]=(ctx->h[i]>>16)&0xFF; out[4*i+2]=(ctx->h[i]>>8)&0xFF; out[4*i+3]=ctx->h[i]&0xFF; }
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ================================================================
 * HMAC-SHA256
 * ================================================================ */
static void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    uint8_t k[64]={0};
    if (klen>64) sha256_hash(key,klen,k); else memcpy(k,key,klen);
    uint8_t ip[64], op[64];
    for (int i=0;i<64;i++) { ip[i]=k[i]^0x36; op[i]=k[i]^0x5c; }
    sha256_ctx c; sha256_init(&c); sha256_update(&c,ip,64); sha256_update(&c,msg,mlen);
    uint8_t inner[32]; sha256_final(&c,inner);
    sha256_init(&c); sha256_update(&c,op,64); sha256_update(&c,inner,32); sha256_final(&c,out);
}

/* ================================================================
 * HKDF + TLS 1.3 label helpers
 * ================================================================ */
static void hkdf_extract(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen, uint8_t out[32]) {
    if (slen == 0) { uint8_t z[32]={0}; hmac_sha256(z,32,ikm,ilen,out); }
    else hmac_sha256(salt,slen,ikm,ilen,out);
}

static void hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t ilen, uint8_t *out, size_t olen) {
    uint8_t t[32]; size_t tl=0, done=0; uint8_t ctr=1;
    while (done < olen) {
        sha256_ctx c; sha256_init(&c);
        uint8_t ik[64]={0}, ok[64]={0}; memcpy(ik,prk,32);
        for(int i=0;i<64;i++){ik[i]^=0x36;ok[i]=((i<32)?prk[i]:0)^0x5c;}
        sha256_update(&c,ik,64);
        if (tl>0) sha256_update(&c,t,tl);
        sha256_update(&c,info,ilen);
        sha256_update(&c,&ctr,1);
        uint8_t inner[32]; sha256_final(&c,inner);
        sha256_ctx c2; sha256_init(&c2); sha256_update(&c2,ok,64); sha256_update(&c2,inner,32);
        sha256_final(&c2,t); tl=32;
        size_t use = olen-done; if(use>32) use=32;
        memcpy(out+done,t,use); done+=use; ctr++;
    }
}

static void hkdf_expand_label(const uint8_t secret[32], const char *label,
                               const uint8_t *ctx, size_t clen, uint8_t *out, size_t olen) {
    uint8_t info[256]; size_t p=0;
    info[p++]=(olen>>8)&0xFF; info[p++]=olen&0xFF;
    size_t ll=6+strlen(label);
    info[p++]=ll&0xFF;
    memcpy(info+p,"tls13 ",6); p+=6;
    memcpy(info+p,label,strlen(label)); p+=strlen(label);
    info[p++]=clen&0xFF;
    if(clen>0){memcpy(info+p,ctx,clen);p+=clen;}
    hkdf_expand(secret,info,p,out,olen);
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

static void aes128_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk,key,16);
    for (int i=0;i<10;i++) {
        uint8_t *p=rk+16*i, *n=rk+16*(i+1);
        uint8_t t[4]={aes_sbox[p[13]],aes_sbox[p[14]],aes_sbox[p[15]],aes_sbox[p[12]]};
        t[0]^=aes_rcon[i];
        for(int j=0;j<4;j++){n[j]=p[j]^t[j];n[4+j]=p[4+j]^n[j];n[8+j]=p[8+j]^n[4+j];n[12+j]=p[12+j]^n[8+j];}
    }
}

static uint8_t xt(uint8_t x){return (x<<1)^((x>>7)*0x1b);}

static void aes128_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16);
    for(int i=0;i<16;i++) s[i]^=rk[i];
    for (int r=1;r<=10;r++) {
        for(int i=0;i<16;i++) s[i]=aes_sbox[s[i]];
        uint8_t t;
        t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
        t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
        t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
        if(r<10) {
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
        if(x[i/8]&(0x80>>(i%8))) for(int j=0;j<16;j++) z[j]^=v[j];
        uint8_t lsb=v[15]&1;
        for(int j=15;j>0;j--) v[j]=(v[j]>>1)|(v[j-1]<<7);
        v[0]>>=1; if(lsb) v[0]^=0xe1;
    }
    memcpy(r,z,16);
}

static void ghash(const uint8_t h[16], const uint8_t *aad, size_t al,
                   const uint8_t *ct, size_t cl, uint8_t out[16]) {
    uint8_t x[16]={0}, blk[16];
    size_t i;
    for(i=0;i+16<=al;i+=16){for(int j=0;j<16;j++)x[j]^=aad[i+j];gf128_mul(x,x,h);}
    if(i<al){memset(blk,0,16);memcpy(blk,aad+i,al-i);for(int j=0;j<16;j++)x[j]^=blk[j];gf128_mul(x,x,h);}
    for(i=0;i+16<=cl;i+=16){for(int j=0;j<16;j++)x[j]^=ct[i+j];gf128_mul(x,x,h);}
    if(i<cl){memset(blk,0,16);memcpy(blk,ct+i,cl-i);for(int j=0;j<16;j++)x[j]^=blk[j];gf128_mul(x,x,h);}
    memset(blk,0,16);
    uint64_t ab=al*8, cb=cl*8;
    for(int j=0;j<8;j++){blk[7-j]=(ab>>(8*j))&0xFF;blk[15-j]=(cb>>(8*j))&0xFF;}
    for(int j=0;j<16;j++)x[j]^=blk[j]; gf128_mul(x,x,h);
    memcpy(out,x,16);
}

static void inc32(uint8_t ctr[16]){for(int i=15;i>=12;i--)if(++ctr[i])break;}

static void aes_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                              const uint8_t *aad, size_t al,
                              const uint8_t *pt, size_t pl,
                              uint8_t *ct_out, uint8_t tag[16]) {
    uint8_t rk[176]; aes128_expand(key,rk);
    uint8_t hh[16]={0}; aes128_encrypt(rk,hh,hh);
    uint8_t ctr[16]; memcpy(ctr,nonce,12); ctr[12]=ctr[13]=ctr[14]=0; ctr[15]=2;
    for(size_t i=0;i<pl;i+=16){
        uint8_t ks[16]; aes128_encrypt(rk,ctr,ks); inc32(ctr);
        size_t n=pl-i; if(n>16)n=16;
        for(size_t j=0;j<n;j++) ct_out[i+j]=pt[i+j]^ks[j];
    }
    ghash(hh,aad,al,ct_out,pl,tag);
    uint8_t j0[16]; memcpy(j0,nonce,12); j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t ej0[16]; aes128_encrypt(rk,j0,ej0);
    for(int i=0;i<16;i++) tag[i]^=ej0[i];
}

static int aes_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                            const uint8_t *aad, size_t al,
                            const uint8_t *ct, size_t cl,
                            uint8_t *pt, const uint8_t exp_tag[16]) {
    uint8_t rk[176]; aes128_expand(key,rk);
    uint8_t hh[16]={0}; aes128_encrypt(rk,hh,hh);
    uint8_t tag[16];
    ghash(hh,aad,al,ct,cl,tag);
    uint8_t j0[16]; memcpy(j0,nonce,12); j0[12]=j0[13]=j0[14]=0; j0[15]=1;
    uint8_t ej0[16]; aes128_encrypt(rk,j0,ej0);
    for(int i=0;i<16;i++) tag[i]^=ej0[i];
    if(memcmp(tag,exp_tag,16)!=0) return -1;
    uint8_t ctr[16]; memcpy(ctr,nonce,12); ctr[12]=ctr[13]=ctr[14]=0; ctr[15]=2;
    for(size_t i=0;i<cl;i+=16){
        uint8_t ks[16]; aes128_encrypt(rk,ctr,ks); inc32(ctr);
        size_t n=cl-i; if(n>16)n=16;
        for(size_t j=0;j<n;j++) pt[i+j]=ct[i+j]^ks[j];
    }
    return 0;
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
    for(int i=0;i<6;i++){borrow=(__int128)a->v[i]-b->v[i]+borrow;r->v[i]=(uint64_t)borrow;borrow>>=64;}
    return (borrow<0)?1:0;
}

static void fp384_add(fp384 *r, const fp384 *a, const fp384 *b) {
    uint64_t c=fp384_add_raw(r,a,b);
    if(c||fp384_cmp(r,&P384_P)>=0) fp384_sub_raw(r,r,&P384_P);
}

static void fp384_sub(fp384 *r, const fp384 *a, const fp384 *b) {
    if(fp384_sub_raw(r,a,b)) fp384_add_raw(r,r,&P384_P);
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
      for(int i=0;i<10;i++){borrow=(__int128)acc[i]-sh[i]+borrow;acc[i]=(uint64_t)borrow;borrow>>=64;}
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
        for(int i=0;i<10;i++){borrow=(__int128)acc[i]-sh[i]+borrow;acc[i]=(uint64_t)borrow;borrow>>=64;}
      }
    }
    /* Final: subtract p while result >= p */
    memcpy(r,acc,48);
    while(fp384_cmp(r,&P384_P)>=0) fp384_sub_raw(r,r,&P384_P);
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

static const fp384 P384_B ={{0x2A85C8EDD3EC2AEF,0xC656398D8A2ED19D,0x0314088F5013875A,0x181D9C6EFE814112,0x988E056BE3F82D19,0xB3312FA7E23EE7E4}};
static const fp384 P384_GX={{0x3A545E3872760AB7,0x5502F25DBF55296C,0x59F741E082542A38,0x6E1D3B628BA79B98,0x8EB1C71EF320AD74,0xAA87CA22BE8B0537}};
static const fp384 P384_GY={{0x7A431D7C90EA0E5F,0x0A60B1CE1D7E819D,0xE9DA3113B5F0B8C0,0xF8F41DBD289A147C,0x5D9E98BF9292DC29,0x3617DE4A96262C6F}};

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

/* Point doubling in Jacobian coords with a=-3 */
static void ec384_double(ec384 *r, const ec384 *p) {
    if(ec384_is_inf(p)){ec384_set_inf(r);return;}
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

/* Point addition (Jacobian) */
static void ec384_add(ec384 *r, const ec384 *p, const ec384 *q) {
    if(ec384_is_inf(p)){*r=*q;return;}
    if(ec384_is_inf(q)){*r=*p;return;}
    fp384 z1s,z2s,u1,u2,z1c,z2c,s1,s2,h,rr,h2,h3,u1h2;
    fp384_sqr(&z1s,&p->z); fp384_sqr(&z2s,&q->z);
    fp384_mul(&u1,&p->x,&z2s); fp384_mul(&u2,&q->x,&z1s);
    fp384_mul(&z1c,&z1s,&p->z); fp384_mul(&z2c,&z2s,&q->z);
    fp384_mul(&s1,&p->y,&z2c); fp384_mul(&s2,&q->y,&z1c);
    fp384_sub(&h,&u2,&u1); fp384_sub(&rr,&s2,&s1);
    if(fp384_cmp(&h,&FP384_ZERO)==0){
        if(fp384_cmp(&rr,&FP384_ZERO)==0){ec384_double(r,p);return;}
        ec384_set_inf(r);return;
    }
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

/* Scalar multiplication: double-and-add, MSB first */
static void ec384_scalar_mul(ec384 *r, const ec384 *p, const uint8_t scalar[48]) {
    ec384_set_inf(r);
    int started=0;
    for(int i=0;i<384;i++){
        int bit_idx=383-i;
        int byte_idx=47-(bit_idx/8);
        int bit_pos=bit_idx%8;
        int bit=(scalar[byte_idx]>>bit_pos)&1;
        if(started) ec384_double(r,r);
        if(bit){
            if(!started){*r=*p;started=1;}
            else ec384_add(r,r,p);
        }
    }
    if(!started) ec384_set_inf(r);
}

/* ECDHE: generate keypair, compute shared secret */
static void ecdhe_keygen(uint8_t priv[48], uint8_t pub[97]) {
    random_bytes(priv,48);
    /* Ensure scalar < n (it almost certainly is for random 384-bit) */
    priv[0] &= 0xFF; /* no-op, just for clarity */
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

static void ecdhe_shared_secret(const uint8_t priv[48], const uint8_t peer_pub[97], uint8_t secret[48]) {
    fp384 px,py;
    fp384_from_bytes(&px,peer_pub+1);
    fp384_from_bytes(&py,peer_pub+49);
    ec384 P; P.x=px; P.y=py; P.z=FP384_ONE;
    ec384 S; ec384_scalar_mul(&S,&P,priv);
    fp384 sx,sy; ec384_to_affine(&sx,&sy,&S);
    fp384_to_bytes(secret,&sx);
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

/* Send a TLS record */
static void tls_send_record(int fd, uint8_t type, const uint8_t *data, size_t len) {
    uint8_t hdr[5]; hdr[0]=type; hdr[1]=0x03; hdr[2]=0x03; PUT16(hdr+3,(uint16_t)len);
    write_all(fd,hdr,5);
    write_all(fd,data,len);
}

/* Read a TLS record. Returns content type. */
static int tls_read_record(int fd, uint8_t *out, size_t *out_len) {
    uint8_t hdr[5];
    if(read_exact(fd,hdr,5)<0) return -1;
    uint16_t len=GET16(hdr+3);
    if(len>16384+256) die("record too large");
    if(read_exact(fd,out,len)<0) return -1;
    *out_len=len;
    return hdr[0];
}

/* Build ClientHello for TLS 1.3 with secp384r1 */
static size_t build_client_hello(uint8_t *buf, const uint8_t pub[97], const char *host) {
    size_t p=0;
    /* Handshake header - fill length later */
    buf[p++]=0x01; /* ClientHello */
    buf[p++]=0; buf[p++]=0; buf[p++]=0; /* length placeholder */

    /* Legacy version TLS 1.2 */
    buf[p++]=0x03; buf[p++]=0x03;

    /* Random */
    random_bytes(buf+p,32); p+=32;

    /* Session ID (32 bytes for compat) */
    buf[p++]=32;
    random_bytes(buf+p,32); p+=32;

    /* Cipher suites */
    buf[p++]=0x00; buf[p++]=0x02; /* 2 bytes */
    buf[p++]=0x13; buf[p++]=0x01; /* TLS_AES_128_GCM_SHA256 */

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

    /* supported_groups */
    buf[p++]=0x00;buf[p++]=0x0a;
    buf[p++]=0x00;buf[p++]=0x04; /* ext len */
    buf[p++]=0x00;buf[p++]=0x02; /* list len */
    buf[p++]=0x00;buf[p++]=0x18; /* secp384r1 */

    /* signature_algorithms */
    buf[p++]=0x00;buf[p++]=0x0d;
    buf[p++]=0x00;buf[p++]=0x08; /* ext len */
    buf[p++]=0x00;buf[p++]=0x06; /* list len */
    buf[p++]=0x05;buf[p++]=0x03; /* ecdsa_secp384r1_sha384 */
    buf[p++]=0x04;buf[p++]=0x03; /* ecdsa_secp256r1_sha256 */
    buf[p++]=0x08;buf[p++]=0x04; /* rsa_pss_rsae_sha256 */

    /* key_share */
    buf[p++]=0x00;buf[p++]=0x33;
    PUT16(buf+p,(uint16_t)(97+4+2));p+=2; /* ext data len */
    PUT16(buf+p,(uint16_t)(97+4));p+=2;   /* client shares len */
    buf[p++]=0x00;buf[p++]=0x18;           /* secp384r1 */
    PUT16(buf+p,97);p+=2;                  /* key exchange len */
    memcpy(buf+p,pub,97);p+=97;

    /* supported_versions */
    buf[p++]=0x00;buf[p++]=0x2b;
    buf[p++]=0x00;buf[p++]=0x03; /* ext len */
    buf[p++]=0x02;               /* list len */
    buf[p++]=0x03;buf[p++]=0x04; /* TLS 1.3 */

    /* Fill in lengths */
    PUT16(buf+ext_len_pos,(uint16_t)(p-ext_len_pos-2));
    uint32_t body_len=p-4;
    buf[1]=(body_len>>16)&0xFF;buf[2]=(body_len>>8)&0xFF;buf[3]=body_len&0xFF;
    return p;
}

/* Parse ServerHello, extract key_share public key */
static int parse_server_hello(const uint8_t *msg, size_t len __attribute__((unused)), uint8_t server_pub[97]) {
    if(msg[0]!=0x02) die("not ServerHello");
    const uint8_t *b=msg+4;
    /* version */ b+=2;
    /* random */ b+=32;
    /* session id */
    uint8_t sid_len=*b++; b+=sid_len;
    /* cipher suite */
    uint16_t cs=GET16(b); b+=2;
    if(cs!=0x1301) { fprintf(stderr,"cipher suite 0x%04x\n",cs); die("unexpected cipher suite"); }
    /* compression */ b++;
    /* extensions */
    uint16_t ext_total=GET16(b); b+=2;
    const uint8_t *ext_end=b+ext_total;
    int found_key=0;
    while(b<ext_end) {
        uint16_t etype=GET16(b); b+=2;
        uint16_t elen=GET16(b); b+=2;
        if(etype==0x0033) { /* key_share */
            uint16_t group=GET16(b);
            uint16_t klen=GET16(b+2);
            if(group==0x0018 && klen==97) {
                memcpy(server_pub,b+4,97);
                found_key=1;
            }
        } else if(etype==0x002b) { /* supported_versions */
            uint16_t ver=GET16(b);
            if(ver!=0x0304) die("not TLS 1.3");
        }
        b+=elen;
    }
    if(!found_key) die("no key_share in ServerHello");
    return 0;
}

/* Decrypt a TLS 1.3 encrypted record.
   Returns inner content type, plaintext in pt, pt_len set. */
static int decrypt_record(const uint8_t *rec, size_t rec_len,
                           const uint8_t key[16], const uint8_t iv[12],
                           uint64_t seq, uint8_t *pt, size_t *pt_len) {
    if(rec_len<17) die("encrypted record too short");
    size_t ct_len=rec_len-16;
    const uint8_t *tag=rec+ct_len;

    /* Construct nonce */
    uint8_t nonce[12]; memcpy(nonce,iv,12);
    for(int i=0;i<8;i++) nonce[11-i]^=(seq>>(8*i))&0xFF;

    /* AAD = record header */
    uint8_t aad[5]={0x17,0x03,0x03,0,0};
    PUT16(aad+3,(uint16_t)rec_len);

    if(aes_gcm_decrypt(key,nonce,aad,5,rec,ct_len,pt,tag)<0) die("AEAD decrypt failed");

    /* Find inner content type (last non-zero byte) */
    size_t i=ct_len;
    while(i>0 && pt[i-1]==0) i--;
    if(i==0) die("no content type in record");
    uint8_t inner_type=pt[i-1];
    *pt_len=i-1;
    return inner_type;
}

/* Encrypt and send a TLS 1.3 record */
static void encrypt_and_send(int fd, uint8_t inner_type,
                              const uint8_t *data, size_t len,
                              const uint8_t key[16], const uint8_t iv[12],
                              uint64_t seq) {
    /* Build inner plaintext: data + content_type */
    uint8_t *inner = malloc(len+1);
    memcpy(inner,data,len);
    inner[len]=inner_type;

    uint8_t nonce[12]; memcpy(nonce,iv,12);
    for(int i=0;i<8;i++) nonce[11-i]^=(seq>>(8*i))&0xFF;

    size_t ct_len=len+1;
    uint8_t *ct=malloc(ct_len+16);
    uint8_t tag[16];

    uint8_t aad[5]={0x17,0x03,0x03,0,0};
    PUT16(aad+3,(uint16_t)(ct_len+16));

    aes_gcm_encrypt(key,nonce,aad,5,inner,ct_len,ct,tag);
    memcpy(ct+ct_len,tag,16);

    tls_send_record(fd,0x17,ct,ct_len+16);
    free(inner); free(ct);
}

/* Main TLS 1.3 handshake + HTTP GET */
static void do_https_get(const char *host, int port, const char *path) {
    int fd=tcp_connect(host,port);
    printf("Connected to %s:%d\n",host,port);

    /* Generate ECDHE keypair */
    uint8_t priv[48], pub[97];
    ecdhe_keygen(priv,pub);
    printf("Generated ECDHE-P384 keypair\n");

    /* Build & send ClientHello */
    uint8_t ch[1024];
    size_t ch_len=build_client_hello(ch,pub,host);
    /* For the record layer, first ClientHello uses version 0x0301 */
    uint8_t ch_hdr[5]={0x16,0x03,0x01,0,0};
    PUT16(ch_hdr+3,(uint16_t)ch_len);
    write_all(fd,ch_hdr,5);
    write_all(fd,ch,ch_len);

    /* Start transcript */
    sha256_ctx transcript;
    sha256_init(&transcript);
    sha256_update(&transcript,ch,ch_len);
    printf("Sent ClientHello (%zu bytes)\n",ch_len);

    /* Read ServerHello */
    uint8_t rec[32768]; size_t rec_len;
    int rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype==0x15 && rec_len>=2) { fprintf(stderr,"Alert: level=%d desc=%d\n",rec[0],rec[1]); die("server sent alert"); }
    if(rtype!=0x16) die("expected handshake record");
    if(rec[0]!=0x02) die("expected ServerHello");
    uint8_t server_pub[97];
    parse_server_hello(rec,rec_len,server_pub);
    sha256_update(&transcript,rec,rec_len);
    printf("Received ServerHello\n");

    /* Compute shared secret */
    uint8_t shared[48];
    ecdhe_shared_secret(priv,server_pub,shared);
    printf("Computed ECDHE shared secret\n");

    /* Derive handshake keys */
    uint8_t early_secret[32];
    { uint8_t z[32]={0}; hkdf_extract(z,32,z,32,early_secret); }
    uint8_t derived1[32];
    { uint8_t empty_hash[32]; sha256_hash(NULL,0,empty_hash);
      hkdf_expand_label(early_secret,"derived",empty_hash,32,derived1,32); }
    uint8_t hs_secret[32];
    hkdf_extract(derived1,32,shared,48,hs_secret);

    uint8_t th1[32]; { sha256_ctx tc=transcript; sha256_final(&tc,th1); }

    uint8_t s_hs_traffic[32], c_hs_traffic[32];
    hkdf_expand_label(hs_secret,"s hs traffic",th1,32,s_hs_traffic,32);
    hkdf_expand_label(hs_secret,"c hs traffic",th1,32,c_hs_traffic,32);

    uint8_t s_hs_key[16], s_hs_iv[12], c_hs_key[16], c_hs_iv[12];
    hkdf_expand_label(s_hs_traffic,"key",NULL,0,s_hs_key,16);
    hkdf_expand_label(s_hs_traffic,"iv",NULL,0,s_hs_iv,12);
    hkdf_expand_label(c_hs_traffic,"key",NULL,0,c_hs_key,16);
    hkdf_expand_label(c_hs_traffic,"iv",NULL,0,c_hs_iv,12);
    printf("Derived handshake traffic keys\n");

    /* Read encrypted handshake messages */
    uint64_t s_hs_seq=0;
    uint8_t hs_buf[65536]; size_t hs_buf_len=0;

    /* May get a ChangeCipherSpec first (compat) */
    rtype=tls_read_record(fd,rec,&rec_len);
    if(rtype==0x14) { /* CCS, skip it */
        rtype=tls_read_record(fd,rec,&rec_len);
    }

    /* Process encrypted records until we get Finished */
    int got_finished=0;
    while(!got_finished) {
        if(rtype!=0x17) die("expected encrypted record");
        uint8_t pt[32768]; size_t pt_len;
        int inner=decrypt_record(rec,rec_len,s_hs_key,s_hs_iv,s_hs_seq++,pt,&pt_len);
        if(inner!=0x16) die("expected handshake inside encrypted record");

        /* Append to handshake buffer */
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
                    sha256_update(&transcript,hs_buf+pos,msg_total);
                    break;
                case 11: /* Certificate */
                    printf("  Certificate (%u bytes)\n",(unsigned)mlen);
                    sha256_update(&transcript,hs_buf+pos,msg_total);
                    break;
                case 15: /* CertificateVerify */
                    printf("  CertificateVerify (%u bytes)\n",(unsigned)mlen);
                    sha256_update(&transcript,hs_buf+pos,msg_total);
                    /* NOTE: Not verifying the certificate signature */
                    break;
                case 20: { /* Finished */
                    printf("  Server Finished\n");
                    /* Verify server finished */
                    uint8_t fin_key[32];
                    hkdf_expand_label(s_hs_traffic,"finished",NULL,0,fin_key,32);
                    uint8_t th_before_fin[32];
                    { sha256_ctx tc=transcript; sha256_final(&tc,th_before_fin); }
                    uint8_t expected[32];
                    hmac_sha256(fin_key,32,th_before_fin,32,expected);
                    if(memcmp(expected,hs_buf+pos+4,32)!=0) die("Server Finished verify failed!");
                    printf("  Server Finished VERIFIED\n");
                    sha256_update(&transcript,hs_buf+pos,msg_total);
                    got_finished=1;
                    break;
                }
                default:
                    printf("  Unknown handshake msg type %d\n",mtype);
                    sha256_update(&transcript,hs_buf+pos,msg_total);
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
    uint8_t th_sf[32]; { sha256_ctx tc=transcript; sha256_final(&tc,th_sf); }

    uint8_t derived2[32];
    { uint8_t empty_hash[32]; sha256_hash(NULL,0,empty_hash);
      hkdf_expand_label(hs_secret,"derived",empty_hash,32,derived2,32); }
    uint8_t master_secret[32];
    { uint8_t z[32]={0}; hkdf_extract(derived2,32,z,32,master_secret); }

    uint8_t s_ap_traffic[32], c_ap_traffic[32];
    hkdf_expand_label(master_secret,"s ap traffic",th_sf,32,s_ap_traffic,32);
    hkdf_expand_label(master_secret,"c ap traffic",th_sf,32,c_ap_traffic,32);

    uint8_t s_ap_key[16], s_ap_iv[12], c_ap_key[16], c_ap_iv[12];
    hkdf_expand_label(s_ap_traffic,"key",NULL,0,s_ap_key,16);
    hkdf_expand_label(s_ap_traffic,"iv",NULL,0,s_ap_iv,12);
    hkdf_expand_label(c_ap_traffic,"key",NULL,0,c_ap_key,16);
    hkdf_expand_label(c_ap_traffic,"iv",NULL,0,c_ap_iv,12);
    printf("Derived application traffic keys\n");

    /* Send client ChangeCipherSpec (compat) */
    { uint8_t ccs=1; tls_send_record(fd,0x14,&ccs,1); }

    /* Send client Finished */
    {
        uint8_t fin_key[32];
        hkdf_expand_label(c_hs_traffic,"finished",NULL,0,fin_key,32);
        uint8_t verify[32];
        hmac_sha256(fin_key,32,th_sf,32,verify);
        uint8_t fin_msg[36]; fin_msg[0]=0x14;
        fin_msg[1]=0; fin_msg[2]=0; fin_msg[3]=32;
        memcpy(fin_msg+4,verify,32);
        encrypt_and_send(fd,0x16,fin_msg,36,c_hs_key,c_hs_iv,0);
    }
    printf("Sent client Finished\n");

    /* Send HTTP GET (encrypted with application keys) */
    {
        char req[512];
        int rlen=snprintf(req,sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: tls_client/0.1\r\n\r\n",
            path,host);
        encrypt_and_send(fd,0x17,(uint8_t*)req,rlen,c_ap_key,c_ap_iv,0);
        printf("Sent HTTP GET %s\n\n",path);
    }

    /* Receive HTTP response */
    uint64_t s_ap_seq=0;
    printf("=== HTTP Response ===\n");
    for(;;) {
        rtype=tls_read_record(fd,rec,&rec_len);
        if(rtype<0) break;
        if(rtype==0x17) {
            uint8_t pt[32768]; size_t pt_len;
            int inner=decrypt_record(rec,rec_len,s_ap_key,s_ap_iv,s_ap_seq++,pt,&pt_len);
            if(inner==0x17) { /* application data */
                fwrite(pt,1,pt_len,stdout);
            } else if(inner==0x15) { /* alert */
                if(pt_len>=2 && pt[0]==1 && pt[1]==0) break; /* close_notify */
                printf("\n[TLS Alert: %d %d]\n",pt[0],pt_len>1?pt[1]:-1);
                break;
            } else if(inner==0x16) {
                /* NewSessionTicket or other post-handshake, skip */
            }
        } else if(rtype==0x15) {
            break;
        } else {
            break;
        }
    }
    printf("\n=== Done ===\n");
    close(fd);
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
    printf("TLS 1.3 HTTPS Client — from scratch in C\n");
    printf("Cipher: TLS_AES_128_GCM_SHA256, Key Exchange: ECDHE-secp384r1\n\n");
    do_https_get(host, port, path);
    return 0;
}
