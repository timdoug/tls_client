/* tls_test.c — Self-tests for tls_client crypto primitives */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "tls_client.h"

static int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for(size_t i=0;i<bin_len;i++){
        unsigned hi,lo;
        if(sscanf(hex+2*i,"%1x%1x",&hi,&lo)!=2) return -1;
        bin[i]=(uint8_t)((hi<<4)|lo);
    }
    return 0;
}

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
        int ok=ed25519_verify(pk,(const uint8_t*)"",0,sig);
        if(ok){pass++;printf("  Ed25519 test 1 (empty msg): PASS\n");}
        else{fail++;printf("  Ed25519 test 1 (empty msg): FAIL\n");}
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
        int ok=ed25519_verify(pk,msg,1,sig);
        if(ok){pass++;printf("  Ed25519 test 2 (1-byte):    PASS\n");}
        else{fail++;printf("  Ed25519 test 2 (1-byte):    FAIL\n");}
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

        /* Verify Alice's public key = scalar_mult(alice_priv, basepoint) */
        uint8_t computed_pub[56];
        uint8_t basepoint[56]={5};
        x448_scalar_mult(alice_priv,basepoint,computed_pub);
        int pub_ok = memcmp(computed_pub,alice_pub,56)==0;

        /* Verify shared secret = scalar_mult(alice_priv, bob_pub) */
        x448_shared_secret(alice_priv,bob_pub,shared);
        int shared_ok = memcmp(shared,expected_shared,56)==0;

        if(pub_ok&&shared_ok){pass++;printf("  X448 DH test (RFC 7748):    PASS\n");}
        else{fail++;printf("  X448 DH test (RFC 7748):    FAIL (pub=%d shared=%d)\n",pub_ok,shared_ok);}
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
        int ok=ed448_verify(pk,(const uint8_t*)"",0,sig);
        if(ok){pass++;printf("  Ed448 test 1 (empty msg):   PASS\n");}
        else{fail++;printf("  Ed448 test 1 (empty msg):   FAIL\n");}
    }

    /* ---- SHAKE256 sanity check ---- */
    {
        /* SHAKE256("", 32) = 46b9dd2b0ba88d13233b3feb743eeb24
                              3fcd52ea62b81b82b50c27646ed5762f */
        uint8_t out[32],expected[32];
        shake256_ctx c; shake256_init(&c); shake256_final(&c,out,32);
        hex2bin("46b9dd2b0ba88d13233b3feb743eeb24"
                "3fcd52ea62b81b82b50c27646ed5762f",expected,32);
        if(memcmp(out,expected,32)==0){pass++;printf("  SHAKE256 sanity check:      PASS\n");}
        else{fail++;printf("  SHAKE256 sanity check:      FAIL\n");}
    }

    printf("Self-tests: %d passed, %d failed\n",pass,fail);
    return fail>0 ? 1 : 0;
}
