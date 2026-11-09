/* main.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* CRACEN Cryptomaster test for the nRF54L15 DK.
 *
 * Every algorithm the port offloads is run on the hardware (devId =
 * WOLFSSL_CRACEN_DEVID) and in software (INVALID_DEVID) over the same inputs,
 * with lengths that exercise partial blocks and streaming splits, and the
 * results compared. Then wolfcrypt_test() runs with WC_USE_DEVID so its own
 * known-answer tests go through the device too. */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_cryptocb.h>
#include <wolfcrypt/test/test.h>

#include <stdio.h>
#include <string.h>

#include "board.h"

#define HW_DEVID  WOLFSSL_CRACEN_DEVID
#define SW_DEVID  INVALID_DEVID

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static int gFails = 0;

#define CHECK(cond, ...)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            gFails++;                                             \
            printf("  FAIL line %d: ", __LINE__);                 \
            printf(__VA_ARGS__);                                  \
            printf("\n");                                         \
        }                                                         \
    } while (0)

static byte gMsg[4096];
static byte gKey[32];
static byte gIv[16];

/* deterministic filler */
static void fill(byte* p, word32 n, word32 seed)
{
    word32 x = seed * 2654435761UL + 12345UL;
    word32 i;
    for (i = 0; i < n; i++) {
        x = x * 1103515245UL + 12345UL;
        p[i] = (byte)(x >> 16);
    }
}

static const word32 gChunks[] =
    { 1, 3, 7, 16, 63, 64, 65, 100, 128, 129, 5, 256, 2, 15, 17, 31 };
#define N_CHUNKS ((word32)(sizeof(gChunks) / sizeof(gChunks[0])))

static void hexdump(const char* tag, const byte* p, word32 n)
{
    word32 i;
    printf("  %s:", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Hash --------------------------------------------------------------------*/

static int hash_stream(enum wc_HashType type, int devId, const byte* msg,
    word32 len, word32 ci, byte* out)
{
    wc_HashAlg h;
    word32 off = 0;
    int ret;

    ret = wc_HashInit_ex(&h, type, NULL, devId);
    while (ret == 0 && off < len) {
        word32 c = gChunks[ci++ % N_CHUNKS];
        if (c > len - off)
            c = len - off;
        ret = wc_HashUpdate(&h, type, msg + off, c);
        off += c;
    }
    if (ret == 0)
        ret = wc_HashFinal(&h, type, out);
    wc_HashFree(&h, type);
    return ret;
}

static void test_hash(const char* name, enum wc_HashType type)
{
    int    digestSz = wc_HashGetDigestSize(type);
    int    before = gFails;
    int    cases = 0;
    word32 len;

    for (len = 0; len <= 700; len = (len < 140) ? len + 1 : len + 29) {
        byte hw[WC_MAX_DIGEST_SIZE];
        byte sw[WC_MAX_DIGEST_SIZE];
        int r1 = hash_stream(type, HW_DEVID, gMsg, len, len, hw);
        int r2 = hash_stream(type, SW_DEVID, gMsg, len, len * 7, sw);
        CHECK(r1 == 0 && r2 == 0, "%s len %u: hw %d sw %d", name, len, r1, r2);
        if (r1 == 0 && r2 == 0) {
            CHECK(memcmp(hw, sw, digestSz) == 0, "%s len %u digest mismatch",
                name, len);
            if (memcmp(hw, sw, digestSz) != 0) {
                hexdump("hw", hw, digestSz);
                hexdump("sw", sw, digestSz);
            }
        }
        cases++;
    }
    printf("%-8s streaming vs software, %d lengths: %s\n", name, cases,
        gFails == before ? "ok" : "FAIL");
}

static void test_hash_copy(void)
{
    wc_Sha256 a;
    wc_Sha256 b;
    byte d1[WC_SHA256_DIGEST_SIZE];
    byte d2[WC_SHA256_DIGEST_SIZE];
    byte sw[WC_SHA256_DIGEST_SIZE];
    int  before = gFails;
    int  ret;

    ret = wc_InitSha256_ex(&a, NULL, HW_DEVID);
    if (ret == 0)
        ret = wc_Sha256Update(&a, gMsg, 100);
    if (ret == 0)
        ret = wc_Sha256Copy(&a, &b);
    if (ret == 0)
        ret = wc_Sha256Update(&a, gMsg + 100, 77);
    if (ret == 0)
        ret = wc_Sha256Update(&b, gMsg + 100, 77);
    if (ret == 0)
        ret = wc_Sha256Final(&a, d1);
    if (ret == 0)
        ret = wc_Sha256Final(&b, d2);
    /* reuse after final */
    if (ret == 0)
        ret = wc_Sha256Update(&a, gMsg, 177);
    if (ret == 0)
        ret = wc_Sha256GetHash(&a, d1);
    wc_Sha256Free(&a);
    wc_Sha256Free(&b);
    CHECK(ret == 0, "sha256 copy sequence ret %d", ret);
    if (ret == 0) {
        ret = hash_stream(WC_HASH_TYPE_SHA256, SW_DEVID, gMsg, 177, 0, sw);
        CHECK(ret == 0 && memcmp(d1, sw, sizeof(sw)) == 0, "sha256 reuse/GetHash");
        CHECK(memcmp(d2, sw, sizeof(sw)) == 0, "sha256 copy");
    }
    printf("%-8s copy, GetHash and reuse: %s\n", "SHA-256",
        gFails == before ? "ok" : "FAIL");
}

static void test_hash_kat(void)
{
    static const byte abc[] = { 'a', 'b', 'c' };
    static const byte expect[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    byte out[WC_SHA256_DIGEST_SIZE];
    int  before = gFails;
    int  ret = hash_stream(WC_HASH_TYPE_SHA256, HW_DEVID, abc, 3, 0, out);

    CHECK(ret == 0 && memcmp(out, expect, sizeof(out)) == 0,
        "SHA-256(\"abc\") ret %d", ret);
    if (ret == 0 && memcmp(out, expect, sizeof(out)) != 0)
        hexdump("hw", out, sizeof(out));
    printf("%-8s known answer: %s\n", "SHA-256",
        gFails == before ? "ok" : "FAIL");
}

/* HMAC: software HMAC over hardware hashes -------------------------------*/

static int hmac_stream(int type, int devId, const byte* key, word32 keySz,
    const byte* msg, word32 len, word32 ci, byte* out)
{
    Hmac   hmac;
    word32 off = 0;
    int    ret;

    ret = wc_HmacInit(&hmac, NULL, devId);
    if (ret == 0)
        ret = wc_HmacSetKey(&hmac, type, key, keySz);
    while (ret == 0 && off < len) {
        word32 c = gChunks[ci++ % N_CHUNKS];
        if (c > len - off)
            c = len - off;
        ret = wc_HmacUpdate(&hmac, msg + off, c);
        off += c;
    }
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, out);
    wc_HmacFree(&hmac);
    return ret;
}

static void test_hmac(const char* name, int type)
{
    static const word32 keySizes[] = { 16, 32, 64, 65, 130 };
    int    digestSz = wc_HmacSizeByType(type);
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 len;

    for (k = 0; k < sizeof(keySizes) / sizeof(keySizes[0]); k++) {
        for (len = 0; len <= 300; len += 37) {
            byte hw[WC_MAX_DIGEST_SIZE];
            byte sw[WC_MAX_DIGEST_SIZE];
            int r1 = hmac_stream(type, HW_DEVID, gMsg + 1000, keySizes[k],
                gMsg, len, len, hw);
            int r2 = hmac_stream(type, SW_DEVID, gMsg + 1000, keySizes[k],
                gMsg, len, len * 3, sw);
            CHECK(r1 == 0 && r2 == 0, "%s key %u len %u: hw %d sw %d", name,
                keySizes[k], len, r1, r2);
            if (r1 == 0 && r2 == 0) {
                CHECK(memcmp(hw, sw, digestSz) == 0,
                    "%s key %u len %u mismatch", name, keySizes[k], len);
            }
            cases++;
        }
    }
    printf("%-8s HMAC vs software, %d cases: %s\n", name, cases,
        gFails == before ? "ok" : "FAIL");
}

/* AES ---------------------------------------------------------------------*/

#ifdef HAVE_AES_ECB
static void test_aes_ecb(void)
{
    static const word32 keySizes[] = { 16, 24, 32 };
    static const word32 lens[] = { 16, 32, 48, 256, 1024, 4096 };
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 l;

    for (k = 0; k < 3; k++) {
        for (l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
            byte hw[4096];
            byte sw[4096];
            byte back[4096];
            Aes  aes;
            int  ret;

            ret = wc_AesInit(&aes, NULL, HW_DEVID);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], NULL, AES_ENCRYPTION);
            if (ret == 0)
                ret = wc_AesEcbEncrypt(&aes, hw, gMsg, lens[l]);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], NULL, AES_DECRYPTION);
            if (ret == 0)
                ret = wc_AesEcbDecrypt(&aes, back, hw, lens[l]);
            wc_AesFree(&aes);
            CHECK(ret == 0, "ecb hw key %u len %u ret %d", keySizes[k], lens[l], ret);

            if (ret == 0)
                ret = wc_AesInit(&aes, NULL, SW_DEVID);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], NULL, AES_ENCRYPTION);
            if (ret == 0)
                ret = wc_AesEcbEncrypt(&aes, sw, gMsg, lens[l]);
            wc_AesFree(&aes);
            CHECK(ret == 0, "ecb sw key %u len %u ret %d", keySizes[k], lens[l], ret);
            if (ret == 0) {
                CHECK(memcmp(hw, sw, lens[l]) == 0, "ecb key %u len %u enc mismatch",
                    keySizes[k], lens[l]);
                CHECK(memcmp(back, gMsg, lens[l]) == 0, "ecb key %u len %u dec mismatch",
                    keySizes[k], lens[l]);
            }
            cases++;
        }
    }
    printf("%-8s ECB vs software, %d cases: %s\n", "AES",  cases,
        gFails == before ? "ok" : "FAIL");
}
#endif

#ifdef HAVE_AES_CBC
/* CBC in two calls (chaining carried in Aes.reg) against one software call */
static void test_aes_cbc(void)
{
    static const word32 keySizes[] = { 16, 24, 32 };
    static const word32 lens[] = { 16, 32, 64, 240, 1024, 4096 };
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 l;

    for (k = 0; k < 3; k++) {
        for (l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
            byte   hw[4096];
            byte   sw[4096];
            byte   back[4096];
            word32 first = (lens[l] / 2) & ~15UL;
            Aes    aes;
            int    ret;

            ret = wc_AesInit(&aes, NULL, HW_DEVID);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], gIv, AES_ENCRYPTION);
            if (ret == 0 && first > 0)
                ret = wc_AesCbcEncrypt(&aes, hw, gMsg, first);
            if (ret == 0)
                ret = wc_AesCbcEncrypt(&aes, hw + first, gMsg + first, lens[l] - first);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], gIv, AES_DECRYPTION);
            if (ret == 0 && first > 0)
                ret = wc_AesCbcDecrypt(&aes, back, hw, first);
            if (ret == 0)
                ret = wc_AesCbcDecrypt(&aes, back + first, hw + first, lens[l] - first);
            wc_AesFree(&aes);
            CHECK(ret == 0, "cbc hw key %u len %u ret %d", keySizes[k], lens[l], ret);

            if (ret == 0)
                ret = wc_AesInit(&aes, NULL, SW_DEVID);
            if (ret == 0)
                ret = wc_AesSetKey(&aes, gKey, keySizes[k], gIv, AES_ENCRYPTION);
            if (ret == 0)
                ret = wc_AesCbcEncrypt(&aes, sw, gMsg, lens[l]);
            wc_AesFree(&aes);
            CHECK(ret == 0, "cbc sw key %u len %u ret %d", keySizes[k], lens[l], ret);
            if (ret == 0) {
                CHECK(memcmp(hw, sw, lens[l]) == 0, "cbc key %u len %u enc mismatch",
                    keySizes[k], lens[l]);
                CHECK(memcmp(back, gMsg, lens[l]) == 0, "cbc key %u len %u dec mismatch",
                    keySizes[k], lens[l]);
            }
            cases++;
        }
    }
    printf("%-8s CBC chained vs software, %d cases: %s\n", "AES", cases,
        gFails == before ? "ok" : "FAIL");
}
#endif

#ifdef WOLFSSL_AES_COUNTER
static int ctr_stream(int devId, word32 keySz, const byte* in, word32 len,
    word32 ci, byte* out)
{
    Aes    aes;
    word32 off = 0;
    int    ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0)
        ret = wc_AesSetKeyDirect(&aes, gKey, keySz, gIv, AES_ENCRYPTION);
    while (ret == 0 && off < len) {
        word32 c = gChunks[ci++ % N_CHUNKS];
        if (c > len - off)
            c = len - off;
        ret = wc_AesCtrEncrypt(&aes, out + off, in + off, c);
        off += c;
    }
    wc_AesFree(&aes);
    return ret;
}

static void test_aes_ctr(void)
{
    static const word32 keySizes[] = { 16, 24, 32 };
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 len;

    for (k = 0; k < 3; k++) {
        for (len = 0; len <= 300; len = (len < 70) ? len + 1 : len + 23) {
            byte hw[512];
            byte sw[512];
            byte back[512];
            int r1 = ctr_stream(HW_DEVID, keySizes[k], gMsg, len, len, hw);
            int r2 = ctr_stream(SW_DEVID, keySizes[k], gMsg, len, 0, sw);
            int r3 = ctr_stream(HW_DEVID, keySizes[k], hw, len, len + 5, back);
            CHECK(r1 == 0 && r2 == 0 && r3 == 0, "ctr key %u len %u: %d %d %d",
                keySizes[k], len, r1, r2, r3);
            if (r1 == 0 && r2 == 0 && r3 == 0) {
                CHECK(memcmp(hw, sw, len) == 0, "ctr key %u len %u enc mismatch",
                    keySizes[k], len);
                CHECK(memcmp(back, gMsg, len) == 0, "ctr key %u len %u roundtrip",
                    keySizes[k], len);
            }
            cases++;
        }
    }
    printf("%-8s CTR streaming vs software, %d cases: %s\n", "AES", cases,
        gFails == before ? "ok" : "FAIL");
}
#endif

#ifdef HAVE_AESGCM
static int gcm_run(int devId, word32 keySz, int enc, const byte* in,
    word32 len, const byte* aad, word32 aadSz, byte* out, byte* tag,
    word32 tagSz)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, gKey, keySz);
    if (ret == 0) {
        if (enc) {
            ret = wc_AesGcmEncrypt(&aes, out, in, len, gIv, GCM_NONCE_MID_SZ,
                tag, tagSz, aad, aadSz);
        }
        else {
            ret = wc_AesGcmDecrypt(&aes, out, in, len, gIv, GCM_NONCE_MID_SZ,
                tag, tagSz, aad, aadSz);
        }
    }
    wc_AesFree(&aes);
    return ret;
}

static void test_aes_gcm(void)
{
    static const word32 keySizes[] = { 16, 32 };
    static const word32 aadSizes[] = { 0, 5, 16, 20, 48 };
    static const word32 lens[] = { 0, 1, 15, 16, 17, 31, 32, 64, 100, 1000 };
    static const word32 tagSizes[] = { 16, 12, 13 };
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 a;
    word32 l;
    word32 t;

    for (k = 0; k < 2; k++) {
        for (a = 0; a < sizeof(aadSizes) / sizeof(aadSizes[0]); a++) {
            for (l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
                for (t = 0; t < sizeof(tagSizes) / sizeof(tagSizes[0]); t++) {
                    byte hw[1024];
                    byte sw[1024];
                    byte back[1024];
                    byte hwTag[16];
                    byte swTag[16];
                    int  r1, r2, r3;

                    r1 = gcm_run(HW_DEVID, keySizes[k], 1, gMsg, lens[l],
                        gMsg + 2000, aadSizes[a], hw, hwTag, tagSizes[t]);
                    r2 = gcm_run(SW_DEVID, keySizes[k], 1, gMsg, lens[l],
                        gMsg + 2000, aadSizes[a], sw, swTag, tagSizes[t]);
                    CHECK(r1 == 0 && r2 == 0, "gcm enc key %u aad %u len %u tag %u: %d %d",
                        keySizes[k], aadSizes[a], lens[l], tagSizes[t], r1, r2);
                    if (r1 == 0 && r2 == 0) {
                        CHECK(memcmp(hw, sw, lens[l]) == 0,
                            "gcm key %u aad %u len %u ciphertext", keySizes[k],
                            aadSizes[a], lens[l]);
                        CHECK(memcmp(hwTag, swTag, tagSizes[t]) == 0,
                            "gcm key %u aad %u len %u tag %u", keySizes[k],
                            aadSizes[a], lens[l], tagSizes[t]);
                        if (memcmp(hwTag, swTag, tagSizes[t]) != 0) {
                            hexdump("hw tag", hwTag, tagSizes[t]);
                            hexdump("sw tag", swTag, tagSizes[t]);
                        }
                        /* decrypt and verify on hardware */
                        r3 = gcm_run(HW_DEVID, keySizes[k], 0, sw, lens[l],
                            gMsg + 2000, aadSizes[a], back, swTag, tagSizes[t]);
                        CHECK(r3 == 0 && memcmp(back, gMsg, lens[l]) == 0,
                            "gcm dec key %u aad %u len %u: %d", keySizes[k],
                            aadSizes[a], lens[l], r3);
                        /* tampered tag must be rejected */
                        swTag[0] ^= 0x80;
                        r3 = gcm_run(HW_DEVID, keySizes[k], 0, sw, lens[l],
                            gMsg + 2000, aadSizes[a], back, swTag, tagSizes[t]);
                        CHECK(r3 == AES_GCM_AUTH_E,
                            "gcm tampered tag accepted (ret %d)", r3);
                    }
                    cases++;
                }
            }
        }
    }
    printf("%-8s GCM vs software, %d cases: %s\n", "AES", cases,
        gFails == before ? "ok" : "FAIL");
}
#endif

#ifdef WOLFSSL_CMAC
static int cmac_stream(int devId, word32 keySz, const byte* in, word32 len,
    word32 ci, byte* out)
{
    Cmac   cmac;
    word32 off = 0;
    word32 outSz = WC_AES_BLOCK_SIZE;
    int    ret;

    ret = wc_InitCmac_ex(&cmac, gKey, keySz, WC_CMAC_AES, NULL, NULL, devId);
    while (ret == 0 && off < len) {
        word32 c = gChunks[ci++ % N_CHUNKS];
        if (c > len - off)
            c = len - off;
        ret = wc_CmacUpdate(&cmac, in + off, c);
        off += c;
    }
    if (ret == 0)
        ret = wc_CmacFinal(&cmac, out, &outSz);
    return ret;
}

static void test_aes_cmac(void)
{
    static const word32 keySizes[] = { 16, 24, 32 };
    int    before = gFails;
    int    cases = 0;
    word32 k;
    word32 len;

    for (k = 0; k < 3; k++) {
        for (len = 0; len <= 300; len = (len < 70) ? len + 1 : len + 19) {
            byte hw[WC_AES_BLOCK_SIZE];
            byte sw[WC_AES_BLOCK_SIZE];
            int r1 = cmac_stream(HW_DEVID, keySizes[k], gMsg, len, len, hw);
            int r2 = cmac_stream(SW_DEVID, keySizes[k], gMsg, len, 0, sw);
            CHECK(r1 == 0 && r2 == 0, "cmac key %u len %u: %d %d", keySizes[k],
                len, r1, r2);
            if (r1 == 0 && r2 == 0) {
                CHECK(memcmp(hw, sw, sizeof(hw)) == 0, "cmac key %u len %u mismatch",
                    keySizes[k], len);
                if (memcmp(hw, sw, sizeof(hw)) != 0) {
                    hexdump("hw", hw, sizeof(hw));
                    hexdump("sw", sw, sizeof(sw));
                }
            }
            cases++;
        }
    }
    printf("%-8s CMAC streaming vs software, %d cases: %s\n", "AES", cases,
        gFails == before ? "ok" : "FAIL");
}
#endif

/* RNG ---------------------------------------------------------------------*/

#define TRNG_SAMPLE_SZ 65536UL
static byte gRnd[TRNG_SAMPLE_SZ];

static int all_zero(const byte* p, word32 n)
{
    word32 i;
    byte   acc = 0;
    for (i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

/* Cheap sanity statistics on raw conditioned output. These catch a stuck,
 * biased or repeating source; they are not a certification test. Bounds are
 * far from the expectation of a uniform source, so a healthy TRNG never trips
 * them. */
static void trng_sanity(const byte* p, word32 n)
{
    static word32 hist[256];
    word32 ones = 0;
    word32 run = 0;
    word32 maxRun = 0;
    word32 repeats = 0;
    word32 i;
    int    prev = -1;
    double expect = (double)n / 256.0;
    double chi = 0.0;
    double entropy = 0.0;
    long   onesPermille;
    int    before = gFails;

    memset(hist, 0, sizeof(hist));
    for (i = 0; i < n; i++) {
        int k;
        hist[p[i]]++;
        for (k = 7; k >= 0; k--) {
            int bit = (p[i] >> k) & 1;
            ones += (word32)bit;
            if (bit == prev) {
                run++;
            }
            else {
                run = 1;
                prev = bit;
            }
            if (run > maxRun)
                maxRun = run;
        }
        if (i >= 16 && (i & 15) == 0 && memcmp(p + i, p + i - 16, 16) == 0)
            repeats++;
    }
    for (i = 0; i < 256; i++) {
        double d = (double)hist[i] - expect;
        chi += d * d / expect;
        if (hist[i] > 0) {
            double pr = (double)hist[i] / (double)n;
            /* log2 via natural log to keep libm use minimal */
            entropy -= pr * (__builtin_log(pr) / 0.69314718055994530942);
        }
    }
    onesPermille = (long)(((unsigned long long)ones * 1000ULL) / ((unsigned long long)n * 8ULL));

    printf("  %lu bytes: ones %ld/1000, byte chi-square %ld (255 dof), "
           "longest run %lu, entropy %ld mbit/byte, repeated blocks %lu\n",
           (unsigned long)n, onesPermille, (long)chi, (unsigned long)maxRun,
           (long)(entropy * 1000.0), (unsigned long)repeats);

    CHECK(onesPermille >= 496 && onesPermille <= 504, "bit bias");
    CHECK(chi > 150.0 && chi < 400.0, "byte distribution");
    CHECK(maxRun <= 48, "long run of identical bits");
    CHECK(entropy >= 7.95, "low byte entropy");
    CHECK(repeats == 0, "repeated 16-byte blocks");
    (void)before;
}

static void test_rng(void)
{
    WC_RNG rng;
    wc_CracenTrngStats st;
    byte   a[64];
    byte   b[64];
    byte   small[16];
    int    before = gFails;
    int    ret;
    word32 off;
    uint32_t t0, t1;

    /* raw TRNG: throughput and statistics over a 64 KB sample */
    t0 = board_cycles();
    for (off = 0, ret = 0; ret == 0 && off < TRNG_SAMPLE_SZ; off += 1024)
        ret = wc_CracenTrngRead(gRnd + off, 1024);
    t1 = board_cycles();
    CHECK(ret == 0, "TRNG read ret %d", ret);
    if (ret == 0) {
        unsigned long cyc = (unsigned long)(t1 - t0);
        unsigned long hz  = (unsigned long)board_clock_hz();
        if (cyc > 0) {
            printf("  TRNG %lu bytes in %lu cycles: %lu kB/s\n",
                (unsigned long)TRNG_SAMPLE_SZ, cyc,
                (unsigned long)(((unsigned long long)TRNG_SAMPLE_SZ * hz) /
                                ((unsigned long long)cyc * 1000ULL)));
        }
        trng_sanity(gRnd, TRNG_SAMPLE_SZ);
    }

    /* odd sizes and a restart after power-down */
    ret = wc_CracenTrngRead(small, 1);
    if (ret == 0)
        ret = wc_CracenTrngRead(small + 1, 3);
    if (ret == 0)
        ret = wc_CracenTrngRead(small + 4, 12);
    CHECK(ret == 0 && !all_zero(small, sizeof(small)), "TRNG odd sizes %d", ret);
    wc_CracenTrngOff();
    memset(small, 0, sizeof(small));
    ret = wc_CracenTrngRead(small, sizeof(small));
    CHECK(ret == 0 && !all_zero(small, sizeof(small)),
        "TRNG restart after power-down %d", ret);

    /* Hash-DRBG seeded from the TRNG through wc_GenerateSeed() */
    ret = wc_InitRng_ex(&rng, NULL, HW_DEVID);
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, a, sizeof(a));
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, b, sizeof(b));
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(&rng, small, 1);
    wc_FreeRng(&rng);
    CHECK(ret == 0, "Hash-DRBG ret %d", ret);
    CHECK(!all_zero(a, sizeof(a)) && memcmp(a, b, sizeof(a)) != 0,
        "DRBG output degenerate");

    if (wc_CracenTrngGetStats(&st) == 0) {
        printf("  TRNG starts %lu, error recoveries %lu, alarms: repetition %lu,"
               " proportion %lu, AIS31 preliminary %lu, AIS31 %lu, "
               "last status 0x%03lx, bytes %lu\n",
               (unsigned long)st.starts, (unsigned long)st.errors,
               (unsigned long)st.repFail, (unsigned long)st.propFail,
               (unsigned long)st.ais31Prelim, (unsigned long)st.ais31Alarm,
               (unsigned long)st.lastStatus, (unsigned long)st.bytes);
        CHECK(st.errors == 0, "TRNG needed %lu error recoveries",
            (unsigned long)st.errors);
    }
    printf("%-8s TRNG sanity and Hash-DRBG: %s\n", "RNG",
        gFails == before ? "ok" : "FAIL");
}

#ifndef CRACEN_TRNG_DUMP
    #define CRACEN_TRNG_DUMP 0
#endif
#if CRACEN_TRNG_DUMP > 0
/* Raw output as hex between markers, for ent/dieharder on the host. */
static void trng_dump(void)
{
    word32 left = CRACEN_TRNG_DUMP;
    byte   buf[64];

    printf("---BEGIN TRNG---\n");
    while (left > 0) {
        word32 n = (left > sizeof(buf)) ? (word32)sizeof(buf) : left;
        word32 i;
        if (wc_CracenTrngRead(buf, n) != 0) {
            printf("read error\n");
            break;
        }
        for (i = 0; i < n; i++)
            printf("%02x", buf[i]);
        printf("\n");
        left -= n;
    }
    printf("---END TRNG---\n");
}
#endif

/* Timing ------------------------------------------------------------------*/

static void time_sha256(int devId, const char* label)
{
    wc_Sha256 sha;
    byte      d[WC_SHA256_DIGEST_SIZE];
    uint32_t  t0, t1;

    if (wc_InitSha256_ex(&sha, NULL, devId) != 0)
        return;
    t0 = board_cycles();
    wc_Sha256Update(&sha, gMsg, sizeof(gMsg));
    wc_Sha256Final(&sha, d);
    t1 = board_cycles();
    wc_Sha256Free(&sha);
    printf("  SHA-256  %u bytes %s: %lu cycles\n", (unsigned)sizeof(gMsg),
        label, (unsigned long)(t1 - t0));
}

#ifdef HAVE_AES_CBC
static void time_aes_cbc(int devId, const char* label)
{
    static byte out[4096];
    Aes      aes;
    uint32_t t0, t1;

    if (wc_AesInit(&aes, NULL, devId) != 0)
        return;
    if (wc_AesSetKey(&aes, gKey, 16, gIv, AES_ENCRYPTION) == 0) {
        t0 = board_cycles();
        wc_AesCbcEncrypt(&aes, out, gMsg, sizeof(gMsg));
        t1 = board_cycles();
        printf("  AES-CBC  %u bytes %s: %lu cycles\n", (unsigned)sizeof(gMsg),
            label, (unsigned long)(t1 - t0));
    }
    wc_AesFree(&aes);
}
#endif

#ifdef HAVE_AESGCM
static void time_aes_gcm(int devId, const char* label)
{
    static byte out[4096];
    byte     tag[16];
    Aes      aes;
    uint32_t t0, t1;

    if (wc_AesInit(&aes, NULL, devId) != 0)
        return;
    if (wc_AesGcmSetKey(&aes, gKey, 16) == 0) {
        t0 = board_cycles();
        wc_AesGcmEncrypt(&aes, out, gMsg, sizeof(gMsg), gIv, GCM_NONCE_MID_SZ,
            tag, sizeof(tag), NULL, 0);
        t1 = board_cycles();
        printf("  AES-GCM  %u bytes %s: %lu cycles\n", (unsigned)sizeof(gMsg),
            label, (unsigned long)(t1 - t0));
    }
    wc_AesFree(&aes);
}
#endif

static void timing(void)
{
    printf("Timing at %lu Hz:\n", (unsigned long)board_clock_hz());
    time_sha256(HW_DEVID, "hw");
    time_sha256(SW_DEVID, "sw");
#ifdef HAVE_AES_CBC
    time_aes_cbc(HW_DEVID, "hw");
    time_aes_cbc(SW_DEVID, "sw");
#endif
#ifdef HAVE_AESGCM
    time_aes_gcm(HW_DEVID, "hw");
    time_aes_gcm(SW_DEVID, "sw");
#endif
}

/* -------------------------------------------------------------------------*/

int main(void)
{
    wc_CracenHwInfo hw;
    func_args args;
    int ret;

    board_init();
    printf("\n\nwolfCrypt CRACEN test, nRF54L15\n");

    fill(gMsg, sizeof(gMsg), 1);
    fill(gKey, sizeof(gKey), 2);
    fill(gIv,  sizeof(gIv),  3);

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
        return ret;
    }
    ret = wc_CracenInit();
    if (ret != 0) {
        printf("wc_CracenInit failed %d\n", ret);
        return ret;
    }
    if (wc_CracenGetInfo(&hw) == 0) {
        printf("CRACEN engines 0x%08lx, AES modes 0x%08lx, AES ctr size 0x%08lx, "
               "hash cfg 0x%08lx, RNG cfg 0x%08lx\n",
               (unsigned long)hw.engines, (unsigned long)hw.aesModes,
               (unsigned long)hw.aesCtrSz, (unsigned long)hw.hashCfg,
               (unsigned long)hw.rngCfg);
    }

    test_rng();
    test_hash_kat();
#ifndef NO_SHA
    test_hash("SHA-1", WC_HASH_TYPE_SHA);
#endif
#ifdef WOLFSSL_SHA224
    test_hash("SHA-224", WC_HASH_TYPE_SHA224);
#endif
    test_hash("SHA-256", WC_HASH_TYPE_SHA256);
#ifdef WOLFSSL_SHA384
    test_hash("SHA-384", WC_HASH_TYPE_SHA384);
#endif
#ifdef WOLFSSL_SHA512
    test_hash("SHA-512", WC_HASH_TYPE_SHA512);
#endif
    test_hash_copy();
    test_hmac("SHA-256", WC_SHA256);
#ifdef WOLFSSL_SHA384
    test_hmac("SHA-384", WC_SHA384);
#endif
#ifdef HAVE_AES_ECB
    test_aes_ecb();
#endif
#ifdef HAVE_AES_CBC
    test_aes_cbc();
#endif
#ifdef WOLFSSL_AES_COUNTER
    test_aes_ctr();
#endif
#ifdef HAVE_AESGCM
    test_aes_gcm();
#endif
#ifdef WOLFSSL_CMAC
    test_aes_cmac();
#endif
    timing();

    printf("\nwolfcrypt_test() with devId 0x%x:\n", HW_DEVID);
    memset(&args, 0, sizeof(args));
    wolfcrypt_test(&args);
    printf("wolfcrypt_test() return code %d\n", args.return_code);
    if (args.return_code != 0)
        gFails++;

    wc_CracenCleanup();
    wolfCrypt_Cleanup();

    if (gFails == 0)
        printf("\nALL TESTS PASSED\n");
    else
        printf("\nFAILED: %d\n", gFails);

#if CRACEN_TRNG_DUMP > 0
    trng_dump();
#endif

#ifndef WOLFSSL_CRACEN_HOST_TEST
    for (;;) {
    }
#endif
    return gFails == 0 ? 0 : 1;
}
