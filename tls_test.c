/*
 * tls_test.c — Unit tests for tls_client crypto primitives.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_crypto.h"

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

    /* ---- SHA3-256: empty message (NIST) ---- */
    {
        uint8_t out[32], exp[32];
        sha3_256((const uint8_t*)"",0,out);
        hex2bin("a7ffc6f8bf1ed76651c14756a061d662"
                "f580ff4de43b49fa82d80a4b80f8434a",exp,32);
        T("SHA3-256 empty",memcmp(out,exp,32)==0);
    }

    /* ---- SHA3-512: empty message (NIST) ---- */
    {
        uint8_t out[64], exp[64];
        sha3_512((const uint8_t*)"",0,out);
        hex2bin("a69f73cca23a9ac5c8b567dc185a756e"
                "97c982164fe25859e0d1dcc1475c80a6"
                "15b2123af1f5f94c11e3e9402c3ac558"
                "f500199d95b6d3e301758586281dcd26",exp,64);
        T("SHA3-512 empty",memcmp(out,exp,64)==0);
    }

    /* ---- SHAKE128: empty input, 32 bytes (NIST) ---- */
    {
        uint8_t out[32], exp[32];
        shake128_ctx ctx;
        shake128_init(&ctx);
        shake128_update(&ctx,(const uint8_t*)"",0);
        shake128_finalize(&ctx);
        shake128_squeeze(&ctx,out,32);
        hex2bin("7f9c2ba4e88f827d616045507605853e"
                "d73b8093f6efbc88eb1a6eacfa66ef26",exp,32);
        T("SHAKE128 empty 32B",memcmp(out,exp,32)==0);
    }

    /* ---- ML-KEM768 round-trip: keygen → encaps → decaps ---- */
    {
        uint8_t ek[1184], dk[2400], ct[1088], ss_enc[32], ss_dec[32];
        mlkem768_keygen(ek, dk);
        mlkem768_encaps(ek, ct, ss_enc);
        mlkem768_decaps(dk, ct, ss_dec);
        T("ML-KEM768 round-trip",memcmp(ss_enc,ss_dec,32)==0);
    }

    /* ---- ML-KEM768 implicit rejection: corrupt ct → different ss ---- */
    {
        uint8_t ek[1184], dk[2400], ct[1088], ss_enc[32], ss_dec[32];
        mlkem768_keygen(ek, dk);
        mlkem768_encaps(ek, ct, ss_enc);
        ct[0] ^= 0x01; /* corrupt ciphertext */
        mlkem768_decaps(dk, ct, ss_dec);
        T("ML-KEM768 implicit reject",memcmp(ss_enc,ss_dec,32)!=0);
    }

    printf("Self-tests: %d passed, %d failed\n",pass,fail);
    return fail>0 ? 1 : 0;
}
