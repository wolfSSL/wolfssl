/* test_asn.c
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

#include <tests/unit.h>

#include <tests/api/api.h>
#include <tests/api/test_asn.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_DILITHIUM
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && defined(HAVE_ED25519)
static int test_SetAsymKeyDer_once(byte* privKey, word32 privKeySz, byte* pubKey,
    word32 pubKeySz, byte* trueDer, word32 trueDerSz)
{
    EXPECT_DECLS;

    byte* calcDer = NULL;
    word32 calcDerSz = 0;

    ExpectIntEQ(calcDerSz = SetAsymKeyDer(privKey, privKeySz, pubKey, pubKeySz,
        NULL, 0, ED25519k), trueDerSz);
    ExpectNotNull(calcDer = (byte*)XMALLOC(calcDerSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(calcDerSz = SetAsymKeyDer(privKey, privKeySz, pubKey, pubKeySz,
        calcDer, calcDerSz, ED25519k), trueDerSz);
    ExpectIntEQ(XMEMCMP(calcDer, trueDer, trueDerSz), 0);
    XFREE(calcDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && HAVE_ED25519 */

int test_SetAsymKeyDer(void)
{
    EXPECT_DECLS;

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && defined(HAVE_ED25519)
    /* We can't access the keyEd25519Oid variable, so declare it instead */
    byte algId[] = {43, 101, 112};
    /* RFC 5958: version is v1 (0) for private only, v2 (1) when public key
     * bundled. Conditions 1-5 are private only, 6-8 include pub key and
     * mutate version[0] = 0x1 before building trueDer. */
    byte version[] = {0x0};
    byte keyPat = 0xcc;

    byte* privKey = NULL;
    word32 privKeySz = 0;
    byte* pubKey = NULL;
    word32 pubKeySz = 0;
    byte trueDer[310]; /* The largest size is 310 bytes on Condition 8 */
    word32 trueDerSz = 0;

    /*
     * Condition 1:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 46             (1 to 127)
     */
    privKeySz = 32;
    pubKeySz = 0;
    trueDerSz = 48;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = trueDerSz - 2;
    /* VER */
    trueDer[2]  = ASN_INTEGER;
    trueDer[3]  = sizeof(version);
    trueDer[4]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[5]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[6]  = sizeof(algId) + 2;
    trueDer[7]  = ASN_OBJECT_ID;
    trueDer[8]  = sizeof(algId);
    trueDer[9]  = algId[0];
    trueDer[10] = algId[1];
    trueDer[11] = algId[2];
    /* PKEY */
    trueDer[12] = ASN_OCTET_STRING;
    trueDer[13] = privKeySz + 2;
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz;
    privKey     = &trueDer[16];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[16] to trueDer[47] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 2:
     *     PKEY data = 129          (128 to 255)
     *     PKEY_CURVEKEY data = 127 (0 to 127)
     *     PUBKEY data = 0          (Empty)
     *     SEQ data = 142           (128 to 255)
     */
    privKeySz = 127;
    pubKeySz = 0;
    trueDerSz = 145;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = 0x81;
    trueDer[15] = privKeySz + 2;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = privKeySz;
    privKey     = &trueDer[18];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[18] to trueDer[144] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 3:
     *     PKEY data = 131     (128 to 255)
     *     PKEY_CURVEKEY = 128 (128 to 255)
     *     PUBKEY data = 0     (Empty)
     *     SEQ data =144       (128 to 255)
     */
    privKeySz = 128;
    pubKeySz = 0;
    trueDerSz = 147;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = 0x81;
    trueDer[15] = privKeySz + 3;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = 0x81;
    trueDer[18] = privKeySz;
    privKey     = &trueDer[19];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[19] to trueDer[146] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 4:
     *     PKEY data = 258           (256 to 65535)
     *     PKEY_CURVEPKEY data = 255 (128 to 255)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 272            (256 to 65536)
     */
    privKeySz = 255;
    pubKeySz = 0;
    trueDerSz = 276;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = 0x82;
    trueDer[16] = ((privKeySz + 3) >> 8) & 0xff;
    trueDer[17] = (privKeySz + 3) & 0xff;
    trueDer[18] = ASN_OCTET_STRING;
    trueDer[19] = 0x81;
    trueDer[20] = privKeySz;
    privKey     = &trueDer[21];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[21] to trueDer[275] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 5:
     *     PKEY data = 260           (256 to 65535)
     *     PKEY_CURVEPKEY data = 256 (256 to 65535)
     *     PUBKEY data = 0           (Empty)
     *     SEQ data = 274            (256 to 65535)
     */
    privKeySz = 256;
    pubKeySz = 0;
    trueDerSz = 278;

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = 0x82;
    trueDer[16] = ((privKeySz + 4) >> 8) & 0xff;
    trueDer[17] = (privKeySz + 4) & 0xff;
    trueDer[18] = ASN_OCTET_STRING;
    trueDer[19] = 0x82;
    trueDer[20] = (privKeySz >> 8) & 0xff;
    trueDer[21] = privKeySz & 0xff;
    privKey     = &trueDer[22];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[22] to trueDer[277] */
    /* PUBKEY */
    pubKey = NULL; /* Empty */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 6:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 32          (1 to 127)
     *     SEQ data = 80             (1 to 127)
     */
    privKeySz = 32;
    pubKeySz = 32;
    trueDerSz = 82;
    version[0] = 0x1; /* publicKey present (v2) */

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = trueDerSz - 2;
    /* VER */
    trueDer[2]  = ASN_INTEGER;
    trueDer[3]  = sizeof(version);
    trueDer[4]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[5]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[6]  = sizeof(algId) + 2;
    trueDer[7]  = ASN_OBJECT_ID;
    trueDer[8]  = sizeof(algId);
    trueDer[9]  = algId[0];
    trueDer[10] = algId[1];
    trueDer[11] = algId[2];
    /* PKEY */
    trueDer[12] = ASN_OCTET_STRING;
    trueDer[13] = privKeySz + 2;
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz;
    privKey     = &trueDer[16];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[16] to trueDer[47] */
    /* PUBKEY */
    trueDer[48] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[49] = pubKeySz;
    pubKey      = &trueDer[50];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[50] to trueDer[81] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 7:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 128         (128 to 255)
     *     SEQ data = 180            (128 to 255)
     */
    privKeySz = 32;
    pubKeySz = 128;
    trueDerSz = 180;
    version[0] = 0x1; /* publicKey present (v2) */

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x81;
    trueDer[2]  = trueDerSz - 3;
    /* VER */
    trueDer[3]  = ASN_INTEGER;
    trueDer[4]  = sizeof(version);
    trueDer[5]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[6]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[7]  = sizeof(algId) + 2;
    trueDer[8]  = ASN_OBJECT_ID;
    trueDer[9]  = sizeof(algId);
    trueDer[10] = algId[0];
    trueDer[11] = algId[1];
    trueDer[12] = algId[2];
    /* PKEY */
    trueDer[13] = ASN_OCTET_STRING;
    trueDer[14] = privKeySz + 2;
    trueDer[15] = ASN_OCTET_STRING;
    trueDer[16] = privKeySz;
    privKey     = &trueDer[17];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[17] to trueDer[48] */
    /* PUBKEY */
    trueDer[49] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[50] = 0x81;
    trueDer[51] = pubKeySz;
    pubKey      = &trueDer[52];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[52] to trueDer[179] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));

    /*
     * Condition 8:
     *     PKEY data = 34            (1 to 127)
     *     PKEY_CURVEPKEY data = 32  (1 to 127)
     *     PUBKEY data = 256         (256 to 65535)
     *     SEQ data = 306            (256 to 65535)
     */
    privKeySz = 32;
    pubKeySz = 256;
    trueDerSz = 310;
    version[0] = 0x1; /* publicKey present (v2) */

    /* SEQ */
    trueDer[0]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[1]  = 0x82;
    trueDer[2]  = ((trueDerSz - 4) >> 8) & 0xff;
    trueDer[3]  = (trueDerSz - 4) & 0xff;
    /* VER */
    trueDer[4]  = ASN_INTEGER;
    trueDer[5]  = sizeof(version);
    trueDer[6]  = version[0];
    /* PKEYALGO_SEQ */
    trueDer[7]  = ASN_SEQUENCE | ASN_CONSTRUCTED;
    trueDer[8]  = sizeof(algId) + 2;
    trueDer[9]  = ASN_OBJECT_ID;
    trueDer[10] = sizeof(algId);
    trueDer[11] = algId[0];
    trueDer[12] = algId[1];
    trueDer[13] = algId[2];
    /* PKEY */
    trueDer[14] = ASN_OCTET_STRING;
    trueDer[15] = privKeySz + 2;
    trueDer[16] = ASN_OCTET_STRING;
    trueDer[17] = privKeySz;
    privKey     = &trueDer[18];
    XMEMSET(privKey, keyPat, privKeySz); /* trueDer[18] to trueDer[49] */
    /* PUBKEY */
    trueDer[50] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    trueDer[51] = 0x82;
    trueDer[52] = (pubKeySz >> 8) & 0xff;
    trueDer[53] = pubKeySz & 0xff;
    pubKey      = &trueDer[54];
    XMEMSET(pubKey, keyPat, pubKeySz); /* trueDer[54] to trueDer[309] */

    EXPECT_TEST(test_SetAsymKeyDer_once(privKey, privKeySz, pubKey, pubKeySz,
        trueDer, trueDerSz));
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && HAVE_ED25519 */

    return EXPECT_RESULT();

}

/* RFC 5958 leniency: parser must accept all four variants:
 *   {v=0,v=1} x {publicKey absent, present}. */
int test_DecodeAsymKey_lenient_versions(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(WOLFSSL_KEY_GEN)
    ed25519_key key;
    ed25519_key parsed;
    WC_RNG rng;
    byte bundled[256];   /* v=1 + publicKey */
    byte privOnly[256];  /* v=0, no publicKey */
    byte tmp[256];
    int  bundledSz = 0;
    int  privOnlySz = 0;
    word32 idx;

    XMEMSET(&key,    0, sizeof(key));
    XMEMSET(&parsed, 0, sizeof(parsed));
    XMEMSET(&rng,    0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    ExpectIntGT(bundledSz = wc_Ed25519KeyToDer(&key, bundled,
        (word32)sizeof(bundled)), 0);
    ExpectIntGT(privOnlySz = wc_Ed25519PrivateKeyToDer(&key, privOnly,
        (word32)sizeof(privOnly)), 0);

    if (EXPECT_SUCCESS() &&
        ((bundledSz  > 0) && ((size_t)bundledSz  <= sizeof(bundled)) &&
         (privOnlySz > 0) && ((size_t)privOnlySz <= sizeof(privOnly)))) {

        /* v=1 + publicKey */
        XMEMCPY(tmp, bundled, (size_t)bundledSz);
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntEQ(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)bundledSz), 0);
        wc_ed25519_free(&parsed);

        /* v=0 + publicKey: patch version byte, [1] publicKey field present. */
        XMEMCPY(tmp, bundled, (size_t)bundledSz);
        ExpectIntGT(test_pkcs8_patch_version_byte(tmp, (word32)bundledSz, 0),
            0);
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntEQ(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)bundledSz), 0);
        wc_ed25519_free(&parsed);

        /* v=0, no publicKey */
        XMEMCPY(tmp, privOnly, (size_t)privOnlySz);
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntEQ(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)privOnlySz), 0);
        wc_ed25519_free(&parsed);

        /* v=1, no publicKey */
        XMEMCPY(tmp, privOnly, (size_t)privOnlySz);
        ExpectIntGT(test_pkcs8_patch_version_byte(tmp, (word32)privOnlySz, 1),
            0);
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntEQ(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)privOnlySz), 0);
        wc_ed25519_free(&parsed);
    }

    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

int test_DecodeAsymKey_negative(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(WOLFSSL_KEY_GEN)
    ed25519_key key;
    ed25519_key parsed;
    WC_RNG rng;
    byte good[256];
    byte tmp[256];
    int  goodSz = 0;
    word32 idx;

    XMEMSET(&key,    0, sizeof(key));
    XMEMSET(&parsed, 0, sizeof(parsed));
    XMEMSET(&rng,    0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    ExpectIntGT(goodSz = wc_Ed25519KeyToDer(&key, good,
        (word32)sizeof(good)), 0);

    if (EXPECT_SUCCESS() &&
        (goodSz > 0 && (size_t)goodSz <= sizeof(good))) {

        /* Truncated buffer */
        XMEMCPY(tmp, good, (size_t)goodSz);
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntLT(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)(goodSz - 1)), 0);
        wc_ed25519_free(&parsed);

        /* Outer length too big. Patch low-order length byte (long form: bump
         * the last byte of the multi-byte length encoding). */
        XMEMCPY(tmp, good, (size_t)goodSz);
        if ((good[1] & 0x80) == 0) {
            tmp[1] = (byte)(good[1] + 1);
        }
        else {
            word32 nBytes = (word32)(good[1] & 0x7F);
            tmp[1 + nBytes] = (byte)(good[1 + nBytes] + 1);
        }
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntLT(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)goodSz), 0);
        wc_ed25519_free(&parsed);

        /* Outer tag not SEQUENCE */
        XMEMCPY(tmp, good, (size_t)goodSz);
        tmp[0] = 0x02;
        XMEMSET(&parsed, 0, sizeof(parsed));
        ExpectIntEQ(wc_ed25519_init(&parsed), 0);
        idx = 0;
        ExpectIntLT(wc_Ed25519PrivateKeyDecode(tmp, &idx, &parsed,
            (word32)goodSz), 0);
        wc_ed25519_free(&parsed);
    }

    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#ifndef NO_ASN
static int test_GetSetShortInt_once(word32 val, byte* valDer, word32 valDerSz)
{
    EXPECT_DECLS;

#ifndef NO_PWDBASED
#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS8) || \
     defined(HAVE_PKCS12)

    byte outDer[MAX_SHORT_SZ];
    word32 outDerSz = 0;
    word32 inOutIdx = 0;
    word32 maxIdx = MAX_SHORT_SZ;
    int value;

    ExpectIntLE(2 + valDerSz, MAX_SHORT_SZ);
    ExpectIntEQ(outDerSz = SetShortInt(outDer, &inOutIdx, val, maxIdx),
        2 + valDerSz);
    ExpectIntEQ(outDer[0], ASN_INTEGER);
    ExpectIntEQ(outDer[1], valDerSz);
    ExpectIntEQ(XMEMCMP(outDer + 2, valDer, valDerSz), 0);
    if (val < 0x80000000) {
        /* GetShortInt only supports positive values. */
        inOutIdx = 0;
        ExpectIntEQ(val, GetShortInt(outDer, &inOutIdx, &value, maxIdx));
    }

#endif /* !WOLFSSL_ASN_TEMPLATE || HAVE_PKCS8 || HAVE_PKCS12 */
#endif /* !NO_PWDBASED */

    (void)val;
    (void)valDer;
    (void)valDerSz;

    return EXPECT_RESULT();
}
#endif

int test_GetSetShortInt(void)
{
    EXPECT_DECLS;

#ifndef NO_ASN
    byte valDer[MAX_SHORT_SZ] = {0};

    /* Corner tests for input size */
    {
        /* Input 1 byte min */
        valDer[0] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x00, valDer, 1));

        /* Input 1 byte max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xff, valDer, 2));

        /* Input 2 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x0100, valDer, 2));

        /* Input 2 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffff, valDer, 3));

        /* Input 3 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x010000, valDer, 3));

        /* Input 3 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffffff, valDer, 4));

        /* Input 4 bytes min */
        valDer[0] = 0x01;
        valDer[1] = 0x00;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x01000000, valDer, 4));

        /* Input 4 bytes max */
        valDer[0] = 0x00;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        valDer[4] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0xffffffff, valDer, 5));
    }

    /* Corner tests for output size */
    {
        /* Skip "Output 1 byte min" because of same as "Input 1 byte min" */

        /* Output 1 byte max */
        valDer[0] = 0x7f;
        EXPECT_TEST(test_GetSetShortInt_once(0x7f, valDer, 1));

        /* Output 2 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        EXPECT_TEST(test_GetSetShortInt_once(0x80, valDer, 2));

        /* Output 2 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fff, valDer, 2));

        /* Output 3 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x8000, valDer, 3));

        /* Output 3 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fffff, valDer, 3));

        /* Output 4 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x800000, valDer, 4));

        /* Output 4 bytes max */
        valDer[0] = 0x7f;
        valDer[1] = 0xff;
        valDer[2] = 0xff;
        valDer[3] = 0xff;
        EXPECT_TEST(test_GetSetShortInt_once(0x7fffffff, valDer, 4));

        /* Output 5 bytes min */
        valDer[0] = 0x00;
        valDer[1] = 0x80;
        valDer[2] = 0x00;
        valDer[3] = 0x00;
        valDer[4] = 0x00;
        EXPECT_TEST(test_GetSetShortInt_once(0x80000000, valDer, 5));

        /* Skip "Output 5 bytes max" because of same as "Input 4 bytes max" */
    }

    /* Extra tests */
    {
        valDer[0] = 0x01;
        EXPECT_TEST(test_GetSetShortInt_once(0x01, valDer, 1));
    }

#if !defined(NO_PWDBASED) || defined(WOLFSSL_ASN_EXTRA)
    /* Negative INTEGER values. */
    {
        word32 idx = 0;
        int value;

        valDer[0] = ASN_INTEGER;
        valDer[1] = 1;
        valDer[2] = 0x80;
        ExpectIntEQ(GetShortInt(valDer, &idx, &value, 3),
                WC_NO_ERR_TRACE(ASN_EXPECT_0_E));

        idx = 0;
        valDer[0] = ASN_INTEGER;
        valDer[1] = 4;
        valDer[2] = 0xFF;
        valDer[3] = 0xFF;
        valDer[4] = 0xFF;
        valDer[5] = 0xFF;
        ExpectIntEQ(GetShortInt(valDer, &idx, &value, 6),
                WC_NO_ERR_TRACE(ASN_EXPECT_0_E));
    }

    #if (!defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    /* zero length value. should return ASN_PARSE_E */
    {
        word32 idx = 0;
        int value = 0;
        valDer[0] = ASN_INTEGER;
        valDer[1] = 0x00;
        ExpectIntEQ(GetShortInt(valDer, &idx, &value, 2),
                WC_NO_ERR_TRACE(ASN_PARSE_E));
    }
    #endif /* */
#endif /* !NO_PWDBASED || WOLFSSL_ASN_EXTRA */
#endif

    return EXPECT_RESULT();
}


int test_wc_IndexSequenceOf(void)
{
    EXPECT_DECLS;

#ifndef NO_ASN
    const byte int_seq[] = {
        0x30, 0x0A,
        0x02, 0x01, 0x0A,
        0x02, 0x02, 0x00, 0xF0,
        0x02, 0x01, 0x7F,
    };
    const byte bad_seq[] = {
        0xA0, 0x01, 0x01,
    };
    const byte empty_seq[] = {
        0x30, 0x00,
    };

    const byte * element;
    word32 elementSz;

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 0U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[2]);
    ExpectIntEQ(elementSz, 3);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 1U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[5]);
    ExpectIntEQ(elementSz, 4);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 2U, &element, &elementSz), 0);
    ExpectPtrEq(element, &int_seq[9]);
    ExpectIntEQ(elementSz, 3);

    ExpectIntEQ(wc_IndexSequenceOf(int_seq, sizeof(int_seq), 3U, &element, &elementSz), WC_NO_ERR_TRACE(BAD_INDEX_E));

    ExpectIntEQ(wc_IndexSequenceOf(bad_seq, sizeof(bad_seq), 0U, &element, &elementSz), WC_NO_ERR_TRACE(ASN_PARSE_E));

    ExpectIntEQ(wc_IndexSequenceOf(empty_seq, sizeof(empty_seq), 0U, &element, &elementSz), WC_NO_ERR_TRACE(BAD_INDEX_E));
#endif

    return EXPECT_RESULT();
}

int test_wolfssl_local_MatchBaseName(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
    /*
     * Tests for DNS type (ASN_DNS_TYPE = 0x02)
     */

    /* Positive tests - should match */
    /* Exact match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, "domain.com", 10), 1);
    /* Case insensitive match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "DOMAIN.COM", 10, "domain.com", 10), 1);
    /* Subdomain match (RFC 5280: adding labels to the left) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "sub.domain.com", 14, "domain.com", 10), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.b.domain.com", 14, "domain.com", 10), 1);
    /* Leading dot constraint with subdomain (not RFC 5280 compliant for DNS,
     * but kept for backwards compatibility) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "sub.domain.com", 14, ".domain.com", 11), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.b.domain.com", 14, ".domain.com", 11), 1);
    /* Trailing-dot normalization: absolute DNS form is equivalent. */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com.", (int)XSTRLEN("domain.com."),
                "domain.com", (int)XSTRLEN("domain.com")), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", (int)XSTRLEN("domain.com"),
                "domain.com.", (int)XSTRLEN("domain.com.")), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com.", (int)XSTRLEN("domain.com."),
                "domain.com.", (int)XSTRLEN("domain.com.")), 1);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "sub.domain.com.", (int)XSTRLEN("sub.domain.com."),
                ".domain.com.", (int)XSTRLEN(".domain.com.")), 1);

    /* Negative tests - should NOT match */
    /* Bug #3: fakedomain.com should NOT match domain.com (no dot boundary) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "fakedomain.com", 14, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "notdomain.com", 13, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "xexample.com", 12, "example.com", 11), 0);
    /* Bug #3: fakedomain.com should NOT match .domain.com */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "fakedomain.com", 14, ".domain.com", 11), 0);
    /* domain.com should NOT match .domain.com (leading dot requires subdomain) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, ".domain.com", 11), 0);
    /* Different domain */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "other.com", 9, "domain.com", 10), 0);
    /* Name starting with dot */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                ".domain.com", 11, "domain.com", 10), 0);
    /* More than one trailing dot leaves an empty label after normalization. */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com..", (int)XSTRLEN("domain.com.."),
                "domain.com", (int)XSTRLEN("domain.com")), 0);

    /*
     * Tests for email type (ASN_RFC822_TYPE = 0x01)
     */

    /* Positive tests - should match */
    /* Exact email match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "user@domain.com", 15), 1);
    /* Email with domain constraint (leading dot) - subdomain present */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@sub.domain.com", 19, ".domain.com", 11), 1);
    /* Email with domain constraint (no leading dot) - exact domain */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "domain.com", 10), 1);

    /* Negative tests - should NOT match */
    /* user@domain.com should NOT match .domain.com (subdomain required) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, ".domain.com", 11), 0);
    /* user@sub.domain.com should NOT match domain.com (exact domain only) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@sub.domain.com", 19, "domain.com", 10), 0);
    /* @ at start is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "@domain.com", 11, ".domain.com", 11), 0);
    /* @ at end is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@", 5, ".domain.com", 11), 0);
    /* double @ is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@@domain.com", 16, ".domain.com", 11), 0);
    /* multiple @ is invalid */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain@extra.com", 21, ".domain.com", 11), 0);
    /* No @ in email name */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "userdomain.com", 14, ".domain.com", 11), 0);
    /* Email domain doesn't match constraint */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@other.com", 14, ".domain.com", 11), 0);
    /* Email suffix without dot boundary (fakedomain) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@fakedomain.com", 19, ".domain.com", 11), 0);
    /* Base constraint with invalid @ position */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "@domain.com", 11), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE,
                "user@domain.com", 15, "user@", 5), 0);

    /*
     * Tests for directory type (ASN_DIR_TYPE = 0x04)
     */

    /* Positive tests - should match */
    /* Exact match */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=test", 7, "CN=test", 7), 1);
    /* Prefix match (name longer than base) */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=test,O=org", 13, "CN=test", 7), 1);

    /* Negative tests - should NOT match */
    /* Different content */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=other", 8, "CN=test", 7), 0);
    /* Case sensitive for directory */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=TEST", 7, "CN=test", 7), 0);

    /*
     * Edge cases and error handling
     */

    /* NULL pointers */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                NULL, 10, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, NULL, 10), 0);
    /* Empty/zero size */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "", 0, "domain.com", 10), 0);
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "domain.com", 10, "", 0), 0);
    /* Invalid type */
    ExpectIntEQ(wolfssl_local_MatchBaseName(0xFF,
                "domain.com", 10, "domain.com", 10), 0);
    /* Name starting with dot */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                ".", 1, ".", 1), 0);
    /* Name shorter than base */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DNS_TYPE,
                "a.com", 5, "domain.com", 10), 0);

#endif /* !NO_CERTS && !NO_ASN && !IGNORE_NAME_CONSTRAINTS */

    return EXPECT_RESULT();
}

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
/* Convenience wrappers so the cases below read as (name, base) pairs and the
 * string lengths can't drift out of sync with the literals. */
static int dnsWildPermitted(const char* name, const char* base)
{
    return wolfssl_local_MatchDnsConstraintWildcard(name, (int)XSTRLEN(name),
        base, (int)XSTRLEN(base), 1);
}
static int dnsWildExcluded(const char* name, const char* base)
{
    return wolfssl_local_MatchDnsConstraintWildcard(name, (int)XSTRLEN(name),
        base, (int)XSTRLEN(base), 0);
}
static int uriNC(const char* uri, const char* base)
{
    return wolfssl_local_MatchUriNameConstraint(uri, (int)XSTRLEN(uri), base,
        (int)XSTRLEN(base));
}
#endif

/*
 * Tests label-aware matching of a wildcard DNS SAN against a name-constraint
 * subtree. The permitted variant must prove containment (every expansion of
 * the wildcard stays inside the subtree); the excluded variant must detect
 * intersection (some expansion falls inside the subtree). A '*' never crosses
 * a label boundary, so the comparison is by label from the right.
 */
int test_wolfssl_local_MatchDnsConstraintWildcard(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
    /*
     * PERMITTED subtree -- containment. Accept only when EVERY expansion of
     * the wildcard is inside the base subtree.
     */

    /* Wildcard is an extra label to the left of the base: always contained. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "example.com"),  1);
    ExpectIntEQ(dnsWildPermitted("*.sub.example.com", "example.com"),  1);
    ExpectIntEQ(dnsWildPermitted("foo*.example.com",  "example.com"),  1);
    ExpectIntEQ(dnsWildPermitted("a*b.example.com",   "example.com"),  1);
    /* Case-insensitive on the literal tail labels. */
    ExpectIntEQ(dnsWildPermitted("*.EXAMPLE.CoM",      "example.com"),  1);
    /* Single-label base; the matched tail "com" is literal. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "com"),          1);
    /* Leading-dot base requires at least one label before it -- the wildcard
     * label satisfies that. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     ".example.com"), 1);
    ExpectIntEQ(dnsWildPermitted("*.sub.example.com", ".example.com"), 1);
    /* Trailing-dot normalization: absolute DNS form is equivalent. */
    ExpectIntEQ(dnsWildPermitted("*.example.com.",    "example.com"),  1);
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "example.com."), 1);
    ExpectIntEQ(dnsWildPermitted("*.example.com.",    "example.com."), 1);
    ExpectIntEQ(dnsWildPermitted("*.example.com.",    ".example.com."), 1);

    /* Wildcard lands on a label that must equal the base: NOT provably
     * contained, because the label can expand to something else. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "foo.example.com"), 0);
    ExpectIntEQ(dnsWildPermitted("*.example.com.",    "foo.example.com"), 0);
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "foo.example.com."), 0);
    ExpectIntEQ(dnsWildPermitted("ex*.com",           "example.com"),     0);
    ExpectIntEQ(dnsWildPermitted("foo.exa*ple.com",   "example.com"),     0);
    /* Tail labels do not match the base at all. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     "example.org"),     0);
    ExpectIntEQ(dnsWildPermitted("*.evil.com",        "example.com"),     0);
    /* Leading-dot base, but wildcard would have to equal an interior base
     * label. */
    ExpectIntEQ(dnsWildPermitted("*.example.com",     ".sub.example.com"), 0);
    /* A bare '*' cannot be proven inside any multi-label-or-single subtree. */
    ExpectIntEQ(dnsWildPermitted("*",                 "com"),             0);

    /*
     * EXCLUDED subtree -- intersection. Reject when SOME expansion of the
     * wildcard falls inside the base subtree. A wildcard label is
     * conservatively treated as able to match any single base label.
     */

    ExpectIntEQ(dnsWildExcluded("*.example.com",      "foo.example.com"), 1);
    ExpectIntEQ(dnsWildExcluded("*.example.com.",     "foo.example.com"), 1);
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "foo.example.com."), 1);
    ExpectIntEQ(dnsWildExcluded("*.example.com.",     "foo.example.com."), 1);
    /* Wildcard adds a label on top of the excluded subtree. */
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "example.com"),     1);
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "com"),             1);
    ExpectIntEQ(dnsWildExcluded("*.example.com",      ".example.com"),    1);
    /* Wildcard in a non-left label still intersects. */
    ExpectIntEQ(dnsWildExcluded("foo.*.example.com",  "bar.example.com"), 1);
    /* Partial-label wildcard: conservatively excluded even though "ex*"
     * cannot actually expand to "foo" (over-rejection, safe). */
    ExpectIntEQ(dnsWildExcluded("ex*.example.com",    "foo.example.com"), 1);
    /* A bare '*' can expand to the apex label of a single-label subtree. */
    ExpectIntEQ(dnsWildExcluded("*",                  "com"),             1);

    /* No intersection: literal tail labels differ from the base. */
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "foo.other.com"),   0);
    ExpectIntEQ(dnsWildExcluded("*.other.com",        "example.com"),     0);
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "example.org"),     0);
    /* Leading-dot excluded base needs a label before it; the wildcard SAN has
     * no room for one, so no expansion reaches the proper subtree. */
    ExpectIntEQ(dnsWildExcluded("*.example.com",      ".foo.example.com"), 0);
    /* Same arity: '*' can expand to the apex label of the base, so the
     * wildcard intersects (*.com can be example.com, which is excluded). */
    ExpectIntEQ(dnsWildExcluded("*.com",              "example.com"),     1);
    /* But a base with MORE labels than the name cannot be reached. */
    ExpectIntEQ(dnsWildExcluded("*.com",              "a.example.com"),   0);

    /*
     * Error / degenerate inputs (both flags reject).
     */
    ExpectIntEQ(wolfssl_local_MatchDnsConstraintWildcard(NULL, 5,
                "com", 3, 1), 0);
    ExpectIntEQ(wolfssl_local_MatchDnsConstraintWildcard("*.com", 5,
                NULL, 3, 1), 0);
    ExpectIntEQ(wolfssl_local_MatchDnsConstraintWildcard("*.com", 0,
                "com", 3, 1), 0);
    ExpectIntEQ(wolfssl_local_MatchDnsConstraintWildcard("*.com", 5,
                "com", 0, 1), 0);
    /* Name beginning with a dot is invalid. */
    ExpectIntEQ(dnsWildPermitted(".x.com",            "com"),             0);
    ExpectIntEQ(dnsWildExcluded(".x.com",             "com"),             0);
    /* Base that is only dots collapses to nothing. */
    ExpectIntEQ(dnsWildExcluded("*.example.com",      "."),               0);
    ExpectIntEQ(dnsWildExcluded("*.example.com",      ".."),              0);
    /* SAN has an empty interior label ("*..com"), but only the right-most
     * "com" label overlaps the base "com" -- the empty label sits outside the
     * compared suffix, and '*' can expand to any label, so the matcher
     * conservatively reports intersection. */
    ExpectIntEQ(dnsWildExcluded("*..com",             "com"),             1);

#endif /* !NO_CERTS && !NO_ASN && !IGNORE_NAME_CONSTRAINTS */

    return EXPECT_RESULT();
}

/*
 * Tests URI name-constraint matching (RFC 5280 4.2.1.10): the constraint
 * applies to the host portion of the URI. A constraint that does NOT begin
 * with a dot is an exact host match; one that begins with a dot matches any
 * host with one or more additional leading labels (the bare host is excluded).
 */
int test_wolfssl_local_MatchUriNameConstraint(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
    /*
     * Exact host match (no leading dot in the constraint).
     */
    ExpectIntEQ(uriNC("https://host.com/path",        "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com",             "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com:8443/x",      "host.com"), 1);
    ExpectIntEQ(uriNC("ftp://user@host.com/x",        "host.com"), 1);
    ExpectIntEQ(uriNC("https://HOST.COM",             "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com?q=1",         "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com#frag",        "host.com"), 1);

    /* The bug this fix closes: an exact-host constraint must NOT subtree-match
     * a sub-host. */
    ExpectIntEQ(uriNC("https://www.host.com/",        "host.com"), 0);
    ExpectIntEQ(uriNC("https://a.b.host.com",         "host.com"), 0);
    /* Suffix that does not respect a label boundary. */
    ExpectIntEQ(uriNC("https://xhost.com",            "host.com"), 0);
    /* host.com is a prefix of the URI host but not the whole host. */
    ExpectIntEQ(uriNC("https://host.com.evil.com",    "host.com"), 0);
    ExpectIntEQ(uriNC("https://other.com",            "host.com"), 0);

    /*
     * Leading-dot constraint: proper subtree of hosts (apex excluded).
     */
    ExpectIntEQ(uriNC("https://www.host.com/",        ".host.com"), 1);
    ExpectIntEQ(uriNC("https://a.b.host.com",         ".host.com"), 1);
    ExpectIntEQ(uriNC("https://www.host.com:443",     ".host.com"), 1);
    /* The bare host is NOT in the leading-dot subtree. */
    ExpectIntEQ(uriNC("https://host.com",             ".host.com"), 0);
    ExpectIntEQ(uriNC("https://evilhost.com",         ".host.com"), 0);

    /*
     * IPv6 literal host extraction ([..]) then exact match.
     */
    ExpectIntEQ(uriNC("https://[2001:db8::1]:443/x",  "2001:db8::1"), 1);
    ExpectIntEQ(uriNC("https://[2001:db8::1]",        "2001:db8::2"), 0);

    /*
     * Malformed / degenerate URIs and inputs (reject).
     */
    ExpectIntEQ(uriNC("no-scheme-host.com",           "host.com"), 0);
    ExpectIntEQ(uriNC("https://",                     "host.com"), 0);
    /* double literal to abide source-check thinking it's a c++ comment */
    ExpectIntEQ(uriNC("https://" "/path",             "host.com"), 0);
    ExpectIntEQ(wolfssl_local_MatchUriNameConstraint(NULL, 10,
                "host.com", 8), 0);
    ExpectIntEQ(wolfssl_local_MatchUriNameConstraint("https://host.com", 16,
                NULL, 8), 0);
    ExpectIntEQ(wolfssl_local_MatchUriNameConstraint("https://host.com", 0,
                "host.com", 8), 0);
    ExpectIntEQ(wolfssl_local_MatchUriNameConstraint("https://host.com", 16,
                "host.com", 0), 0);

#endif /* !NO_CERTS && !NO_ASN && !IGNORE_NAME_CONSTRAINTS */

    return EXPECT_RESULT();
}

/*
 * Testing wc_DecodeRsaPssParams with known DER byte arrays.
 * Exercises both WOLFSSL_ASN_TEMPLATE and non-template paths.
 */
int test_wc_DecodeRsaPssParams(void)
{
    EXPECT_DECLS;
#if defined(WC_RSA_PSS) && !defined(NO_RSA) && !defined(NO_ASN)
    enum wc_HashType hash;
    int mgf;
    int saltLen;

    /* SHA-256 / MGF1-SHA-256 / saltLen=32 */
    static const byte pssParamsSha256[] = {
        0x30, 0x34,
          0xA0, 0x0F,
            0x30, 0x0D,
              0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                          0x04, 0x02, 0x01,
              0x05, 0x00,
          0xA1, 0x1C,
            0x30, 0x1A,
              0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                          0x01, 0x01, 0x08,
              0x30, 0x0D,
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                            0x04, 0x02, 0x01,
                0x05, 0x00,
          0xA2, 0x03,
            0x02, 0x01, 0x20,
    };

    /* Hash-only: SHA-256 hash, defaults for MGF and salt */
    static const byte pssParamsHashOnly[] = {
        0x30, 0x11,
          0xA0, 0x0F,
            0x30, 0x0D,
              0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                          0x04, 0x02, 0x01,
              0x05, 0x00,
    };

    /* Salt-only: default hash/mgf, saltLen=48 */
    static const byte pssParamsSaltOnly[] = {
        0x30, 0x05,
          0xA2, 0x03,
            0x02, 0x01, 0x30,
    };

    /* NULL tag (05 00) means all defaults */
    static const byte pssParamsNull[] = { 0x05, 0x00 };

    /* Empty SEQUENCE means all non-default fields omitted => defaults */
    static const byte pssParamsEmptySeq[] = { 0x30, 0x00 };

    /* --- Test 1: sz=0 => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams((const byte*)"", 0,
        &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

    /* --- Test 2: NULL tag => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsNull,
        (word32)sizeof(pssParamsNull), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

    /* --- Test 3: Empty SEQUENCE => all defaults --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsEmptySeq,
        (word32)sizeof(pssParamsEmptySeq), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);

#ifndef NO_SHA256
    /* --- Test 4: SHA-256 / MGF1-SHA-256 / salt=32 --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsSha256,
        (word32)sizeof(pssParamsSha256), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA256);
    ExpectIntEQ(mgf, WC_MGF1SHA256);
    ExpectIntEQ(saltLen, 32);

    /* --- Test 5: Hash only => SHA-256, default MGF/salt --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsHashOnly,
        (word32)sizeof(pssParamsHashOnly), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA256);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 20);
#endif

    /* --- Test 6: Salt only => default hash/MGF, salt=48 --- */
    hash = WC_HASH_TYPE_NONE;
    mgf = 0;
    saltLen = 0;
    ExpectIntEQ(wc_DecodeRsaPssParams(pssParamsSaltOnly,
        (word32)sizeof(pssParamsSaltOnly), &hash, &mgf, &saltLen), 0);
    ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
    ExpectIntEQ(mgf, WC_MGF1SHA1);
    ExpectIntEQ(saltLen, 48);

    /* --- Test 7: NULL pointer -> BAD_FUNC_ARG --- */
    ExpectIntEQ(wc_DecodeRsaPssParams(NULL, 10, &hash, &mgf, &saltLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- Test 8: Bad leading tag => ASN_PARSE_E --- */
    {
        static const byte badTag[] = { 0x01, 0x00 };
        ExpectIntEQ(wc_DecodeRsaPssParams(badTag, (word32)sizeof(badTag),
            &hash, &mgf, &saltLen), WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* --- Test 9: trailerField = 1 (trailerFieldBC) => valid in all modes --- */
    /* SEQUENCE { [3] CONSTRUCTED { INTEGER 1 } } = 30 05 a3 03 02 01 01 */
    {
        static const byte trailerValid[] = {
            0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x01
        };
        hash    = WC_HASH_TYPE_NONE;
        mgf     = 0;
        saltLen = 0;
        ExpectIntEQ(wc_DecodeRsaPssParams(trailerValid,
            (word32)sizeof(trailerValid), &hash, &mgf, &saltLen), 0);
        ExpectIntEQ((int)hash, (int)WC_HASH_TYPE_SHA);
        ExpectIntEQ(mgf, WC_MGF1SHA1);
        ExpectIntEQ(saltLen, 20);
    }

#ifndef WOLFSSL_NO_ASN_STRICT
    /* --- Test 10: trailerField = 2 => ASN_PARSE_E (strict mode) --- */
    /* RFC 8017 A.2.3: trailerField SHALL be trailerFieldBC(1). */
    /* SEQUENCE { [3] CONSTRUCTED { INTEGER 2 } } = 30 05 a3 03 02 01 02 */
    {
        static const byte trailerTwo[] = {
            0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x02
        };
        ExpectIntEQ(wc_DecodeRsaPssParams(trailerTwo,
            (word32)sizeof(trailerTwo), &hash, &mgf, &saltLen),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* --- Test 11: trailerField = 0 => ASN_PARSE_E (strict mode) --- */
    /* SEQUENCE { [3] CONSTRUCTED { INTEGER 0 } } = 30 05 a3 03 02 01 00 */
    {
        static const byte trailerZero[] = {
            0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x00
        };
        ExpectIntEQ(wc_DecodeRsaPssParams(trailerZero,
            (word32)sizeof(trailerZero), &hash, &mgf, &saltLen),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    /* --- Test 12: trailerField = 256 (multi-byte INTEGER) => ASN_PARSE_E ---
     * Exercises the 2-byte integer branch in GetInteger16Bit (non-template)
     * and the len==2 case of ASN_DATA_TYPE_WORD16 (template path).
     * SEQUENCE { [3] CONSTRUCTED { INTEGER 256 } } = 30 06 a3 04 02 02 01 00
     */
    {
        static const byte trailerMultiByte[] = {
            0x30, 0x06, 0xa3, 0x04, 0x02, 0x02, 0x01, 0x00
        };
        ExpectIntEQ(wc_DecodeRsaPssParams(trailerMultiByte,
            (word32)sizeof(trailerMultiByte), &hash, &mgf, &saltLen),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
    }
#endif /* !WOLFSSL_NO_ASN_STRICT */

#endif /* WC_RSA_PSS && !NO_RSA && !NO_ASN */
    return EXPECT_RESULT();
}

/* Test that DecodeAltNames rejects a SAN entry whose length exceeds the
 * remaining SEQUENCE length (integer underflow on the length tracker). */
int test_DecodeAltNames_length_underflow(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(NO_ASN)
    /* Self-signed DER certificate with a well-formed SAN extension.
     * Byte at offset 418 is the SAN SEQUENCE length (0x06).  The negative
     * test below copies this cert and shrinks that byte to 0x03 so the
     * DNS entry length exceeds the SEQUENCE bounds. */
    static const unsigned char good_san_cert[] = {
        0x30, 0x82, 0x02, 0xf9, 0x30, 0x82, 0x01, 0xe1, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x02, 0x10, 0x21, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0f, 0x31, 0x0d,
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x61, 0x61, 0x31,
        0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x32, 0x30, 0x37, 0x31,
        0x37, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x34, 0x30, 0x32,
        0x31, 0x34, 0x30, 0x36, 0x32, 0x36, 0x35, 0x33, 0x5a, 0x30, 0x0f, 0x31,
        0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x61, 0x61,
        0x61, 0x61, 0x30, 0x82, 0x01, 0x20, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
        0x0d, 0x00, 0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa8,
        0x8a, 0x5e, 0x26, 0x23, 0x1b, 0x31, 0xd3, 0x37, 0x1a, 0x70, 0xb2, 0xec,
        0x3f, 0x74, 0xd4, 0xb4, 0x44, 0xe3, 0x7a, 0xa5, 0xc0, 0xf5, 0xaa, 0x97,
        0x26, 0x9a, 0x04, 0xff, 0xda, 0xbe, 0xe5, 0x09, 0x03, 0x98, 0x3d, 0xb5,
        0xbf, 0x01, 0x2c, 0x9a, 0x0a, 0x3a, 0xfb, 0xbc, 0x3c, 0xe7, 0xbe, 0x83,
        0x5c, 0xb3, 0x70, 0xe8, 0x5c, 0xe3, 0xd1, 0x83, 0xc3, 0x94, 0x08, 0xcd,
        0x1a, 0x87, 0xe5, 0xe0, 0x5b, 0x9c, 0x5c, 0x6e, 0xb0, 0x7d, 0xe2, 0x58,
        0x6c, 0xc3, 0xb5, 0xc8, 0x9d, 0x11, 0xf1, 0x5d, 0x96, 0x0d, 0x66, 0x1e,
        0x56, 0x7f, 0x8f, 0x59, 0xa7, 0xa5, 0xe1, 0xc5, 0xe7, 0x81, 0x4c, 0x09,
        0x9d, 0x5e, 0x96, 0xf0, 0x9a, 0xc2, 0x8b, 0x70, 0xd5, 0xab, 0x79, 0x58,
        0x5d, 0xb7, 0x58, 0xaa, 0xfd, 0x75, 0x52, 0xaa, 0x4b, 0xa7, 0x25, 0x68,
        0x76, 0x59, 0x00, 0xee, 0x78, 0x2b, 0x91, 0xc6, 0x59, 0x91, 0x99, 0x38,
        0x3e, 0xa1, 0x76, 0xc3, 0xf5, 0x23, 0x6b, 0xe6, 0x07, 0xea, 0x63, 0x1c,
        0x97, 0x49, 0xef, 0xa0, 0xfe, 0xfd, 0x13, 0xc9, 0xa9, 0x9f, 0xc2, 0x0b,
        0xe6, 0x87, 0x92, 0x5b, 0xcc, 0xf5, 0x42, 0x95, 0x4a, 0xa4, 0x6d, 0x64,
        0xba, 0x7d, 0xce, 0xcb, 0x04, 0xd0, 0xf8, 0xe7, 0xe3, 0xda, 0x75, 0x60,
        0xd3, 0x8b, 0x6a, 0x64, 0xfc, 0x78, 0x56, 0x21, 0x69, 0x5a, 0xe8, 0xa7,
        0x8f, 0xfb, 0x8f, 0x82, 0xe3, 0xae, 0x36, 0xa2, 0x93, 0x66, 0x92, 0xcb,
        0x82, 0xa3, 0xbe, 0x84, 0x00, 0x86, 0xdc, 0x7e, 0x6d, 0x53, 0x77, 0x84,
        0x17, 0xb9, 0x55, 0x43, 0x0d, 0xf1, 0x16, 0x1f, 0xd5, 0x43, 0x75, 0x99,
        0x66, 0x19, 0x52, 0xd0, 0xac, 0x5f, 0x74, 0xad, 0xb2, 0x90, 0x15, 0x50,
        0x04, 0x74, 0x43, 0xdf, 0x6c, 0x35, 0xd0, 0xfd, 0x32, 0x37, 0xb3, 0x8d,
        0xf5, 0xe5, 0x09, 0x02, 0x01, 0x03, 0xa3, 0x61, 0x30, 0x5f, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
        /* SAN extension: correct SEQUENCE length 0x06 */
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x82,
        0x04, 0x61, 0x2a, 0x62, 0x2a, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
        0x04, 0x16, 0x04, 0x14, 0x92, 0x6a, 0x1e, 0x52, 0x3a, 0x1a, 0x57, 0x9f,
        0xc9, 0x82, 0x9a, 0xce, 0xc8, 0xc0, 0xa9, 0x51, 0x9d, 0x2f, 0xc7, 0x72,
        0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
        0x14, 0x6b, 0xf9, 0xa4, 0x2d, 0xa5, 0xe9, 0x39, 0x89, 0xa8, 0x24, 0x58,
        0x79, 0x87, 0x11, 0xfc, 0x6f, 0x07, 0x91, 0xef, 0xa6, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
        0x03, 0x82, 0x01, 0x01, 0x00, 0x3f, 0xd5, 0x37, 0x2f, 0xc7, 0xf8, 0x8b,
        0x39, 0x1c, 0xe3, 0xdf, 0x77, 0xee, 0xc6, 0x4b, 0x5f, 0x84, 0xcf, 0xfa,
        0x33, 0x2c, 0xb2, 0xb5, 0x4b, 0x09, 0xee, 0x56, 0xc0, 0xf2, 0xf0, 0xeb,
        0xad, 0x1c, 0x02, 0xef, 0xae, 0x09, 0x53, 0xc0, 0x06, 0xad, 0x4e, 0xfd,
        0x3e, 0x8c, 0x13, 0xb3, 0xbf, 0x80, 0x05, 0x36, 0xb5, 0x3f, 0x2b, 0xc7,
        0x60, 0x53, 0x14, 0xbf, 0x33, 0x63, 0x47, 0xc3, 0xc6, 0x28, 0xda, 0x10,
        0x12, 0xe2, 0xc4, 0xeb, 0xc5, 0x64, 0x66, 0xc0, 0xcc, 0x6b, 0x84, 0xda,
        0x0c, 0xe9, 0xf6, 0xe3, 0xf8, 0x8e, 0x3d, 0x95, 0x5f, 0xba, 0x9f, 0xe1,
        0xc7, 0xed, 0x6e, 0x97, 0xcc, 0xbd, 0x7d, 0xe5, 0x4e, 0xab, 0xbc, 0x1b,
        0xf1, 0x3a, 0x09, 0x33, 0x09, 0xe1, 0xcc, 0xec, 0x21, 0x16, 0x8e, 0xb1,
        0x74, 0x9e, 0xc8, 0x13, 0x7c, 0xdf, 0x07, 0xaa, 0xeb, 0x70, 0xd7, 0x91,
        0x5c, 0xc4, 0xef, 0x83, 0x88, 0xc3, 0xe4, 0x97, 0xfa, 0xe4, 0xdf, 0xd7,
        0x0d, 0xff, 0xba, 0x78, 0x22, 0xfc, 0x3f, 0xdc, 0xd8, 0x02, 0x8d, 0x93,
        0x57, 0xf9, 0x9e, 0x39, 0x3a, 0x77, 0x00, 0xd9, 0x19, 0xaa, 0x68, 0xa1,
        0xe6, 0x9e, 0x13, 0xeb, 0x37, 0x16, 0xf5, 0x77, 0xa4, 0x0b, 0x40, 0x04,
        0xd3, 0xa5, 0x49, 0x78, 0x35, 0xfa, 0x3b, 0xf6, 0x02, 0xab, 0x85, 0xee,
        0xcb, 0x9b, 0x62, 0xda, 0x05, 0x00, 0x22, 0x2f, 0xf8, 0xbd, 0x0b, 0xe5,
        0x2c, 0xb2, 0x53, 0x78, 0x0a, 0xcb, 0x69, 0xc0, 0xb6, 0x9f, 0x96, 0xff,
        0x58, 0x22, 0x70, 0x9c, 0x01, 0x2e, 0x56, 0x60, 0x5d, 0x37, 0xe3, 0x40,
        0x25, 0xc9, 0x90, 0xc8, 0x0f, 0x41, 0x68, 0xb4, 0xfd, 0x10, 0xe2, 0x09,
        0x99, 0x08, 0x5d, 0x7b, 0xc9, 0xe3, 0x29, 0xd4, 0x5a, 0xcf, 0xc9, 0x34,
        0x55, 0xa1, 0x40, 0x44, 0xd6, 0x88, 0x16, 0xbb, 0xdd
    };

    /* Offset of the SAN SEQUENCE length byte inside good_san_cert. */
    #define SAN_SEQ_LEN_OFFSET 418

    DecodedCert cert;
    unsigned char bad_san_cert[sizeof(good_san_cert)];

    /* Control: the original cert with correct SAN SEQUENCE length should
     * parse successfully (signature won't verify, but NO_VERIFY skips that). */
    wc_InitDecodedCert(&cert, good_san_cert, (word32)sizeof(good_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    wc_FreeDecodedCert(&cert);

    /* Build a malformed variant: shrink the SAN SEQUENCE length from 6 to 3
     * so the DNS entry length (4) exceeds the SEQUENCE bounds.  Without a
     * bounds check DecodeAltNames would underflow the length tracker. */
    XMEMCPY(bad_san_cert, good_san_cert, sizeof(good_san_cert));
    bad_san_cert[SAN_SEQ_LEN_OFFSET] = 0x03;

    wc_InitDecodedCert(&cert, bad_san_cert, (word32)sizeof(bad_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    wc_FreeDecodedCert(&cert);

    /* NUL in dNSName SAN must be rejected per RFC 5280 4.2.1.6. */
    XMEMCPY(bad_san_cert, good_san_cert, sizeof(good_san_cert));
    bad_san_cert[SAN_SEQ_LEN_OFFSET + 5] = 0x00;

    wc_InitDecodedCert(&cert, bad_san_cert, (word32)sizeof(bad_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
    wc_FreeDecodedCert(&cert);

#endif /* !NO_CERTS && !NO_RSA && !NO_ASN */
    return EXPECT_RESULT();
}

/* A certificate must not carry two certificatePolicies extensions
 * (non-repeatable per RFC 5280 4.2). DecodeCertExtensions calls
 * DecodeExtensionType once per extension; with strict ASN.1 (the default) a
 * second certificatePolicies extension must be rejected (ASN_OBJECT_ID_E)
 * rather than silently overwriting the first - which happened in
 * WOLFSSL_CERT_EXT builds without WOLFSSL_SEP before the duplicate guard was
 * extended to cover them. */
int test_DecodeCertExtensions_dup_certpol(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(WOLFSSL_NO_ASN_STRICT) && !defined(NO_CERTS) && !defined(NO_ASN)
    /* Minimal certificatePolicies extnValue: SEQUENCE OF PolicyInformation
     * with one policyIdentifier OID 1.2.3.4 (encoded 2A 03 04). */
    static const byte policy[] = {
        0x30, 0x07,                         /* certificatePolicies SEQUENCE */
            0x30, 0x05,                     /* PolicyInformation SEQUENCE */
                0x06, 0x03, 0x2A, 0x03, 0x04 /* policyIdentifier OID 1.2.3.4 */
    };
    DecodedCert cert;
    int isUnknown = 0;

    /* DecodeExtensionType only needs an initialized DecodedCert for its
     * bit-fields and policy storage; the source buffer is never parsed here,
     * so any non-NULL pointer/size suffices. */
    wc_InitDecodedCert(&cert, policy, (word32)sizeof(policy), NULL);

    /* First certificatePolicies extension: accepted. */
    ExpectIntEQ(DecodeExtensionType(policy, (word32)sizeof(policy),
        CERT_POLICY_OID, 0, &cert, &isUnknown), 0);
    /* Duplicate certificatePolicies extension: rejected as non-repeatable. */
    ExpectIntEQ(DecodeExtensionType(policy, (word32)sizeof(policy),
        CERT_POLICY_OID, 0, &cert, &isUnknown),
        WC_NO_ERR_TRACE(ASN_OBJECT_ID_E));

    wc_FreeDecodedCert(&cert);
#endif
    return EXPECT_RESULT();
}

int test_ParseCert_SM3wSM2_short_pubkey(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(NO_SKID) && \
    defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    /* Malformed cert: the SubjectPublicKeyInfo is an id-ecPublicKey key on the
     * sm2p256v1 curve with only a 4-byte public key body, whole SPKI is 30
     * bytes with no subjectKeyIdentifier extension and SKID derived from the
     * key. */
    static const byte sm2ShortKeyCert[] = {
        0x30, 0x81, 0xa7,
          0x30, 0x56,
            0xa0, 0x03, 0x02, 0x01, 0x02,
            0x02, 0x01, 0x01,
            0x30, 0x0a, 0x06, 0x08,
              0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75,
            0x30, 0x00,
            0x30, 0x1e,
              0x17, 0x0d, 0x32, 0x35, 0x31, 0x31, 0x31, 0x33,
              0x32, 0x30, 0x34, 0x31, 0x32, 0x31, 0x5a,
              0x17, 0x0d, 0x32, 0x38, 0x30, 0x38, 0x30, 0x39,
              0x32, 0x30, 0x34, 0x31, 0x32, 0x31, 0x5a,
            0x30, 0x00,
            0x30, 0x1c,
              0x30, 0x13,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
              0x03, 0x05, 0x00, 0x04, 0x11, 0x22, 0x33,
          0x30, 0x0a, 0x06, 0x08,
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75,
          0x03, 0x41, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DecodedCert cert;

    wc_InitDecodedCert(&cert, sm2ShortKeyCert, (word32)sizeof(sm2ShortKeyCert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL),
        WC_NO_ERR_TRACE(BUFFER_E));
    wc_FreeDecodedCert(&cert);
#endif
    return EXPECT_RESULT();
}

int test_SerialNumber0_RootCA(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(WOLFSSL_NO_PEM) && defined(WOLFSSL_PEM_TO_DER)
    /* Test that root CA certificates with serial number 0 are accepted,
     * while non-root certificates with serial 0 are rejected (issue #8615) */

#if !defined(WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_PYTHON) && \
    !defined(WOLFSSL_ASN_ALLOW_0_SERIAL) && \
    !defined(WOLFSSL_TEST_APPLE_NATIVE_CERT_VALIDATION)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    const char* rootSerial0File = "./certs/test-serial0/root_serial0.pem";
    const char* selfSignedNonCASerial0File =
        "./certs/test-serial0/selfsigned_nonca_serial0.pem";

    /* Test 1: Root CA with serial 0 should load successfully */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, rootSerial0File, NULL),
                WOLFSSL_SUCCESS);

#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    {
        const char* eeSerial0File = "./certs/test-serial0/ee_serial0.pem";
        const char* eeNormalFile = "./certs/test-serial0/ee_normal.pem";

        /* Test 2: End-entity cert with serial 0 should be rejected during
         * verify */
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, eeSerial0File,
                    WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_PARSE_E));

        /* Test 3: Normal end-entity cert signed by root CA with serial 0
         * should verify successfully */
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, eeNormalFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
#endif

    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    /* Test 4: Self-signed non-CA certificate with serial 0 should be rejected */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntNE(wolfSSL_CertManagerLoadCA(cm, selfSignedNonCASerial0File, NULL),
                WOLFSSL_SUCCESS);

    if (cm != NULL) {
        wolfSSL_CertManagerFree(cm);
        cm = NULL;
    }

    /* Test 5: Intermediate CA (CA:TRUE but issuer != subject) with serial 0
     * must be rejected when loaded as CA_TYPE. Exercises the selfSigned
     * half of the ParseCertRelative exemption predicate. */
    {
        const char* intermediateSerial0File =
            "./certs/test-serial0/intermediate_serial0.pem";
        ExpectNotNull(cm = wolfSSL_CertManagerNew());
        ExpectIntNE(wolfSSL_CertManagerLoadCA(cm, intermediateSerial0File,
                    NULL), WOLFSSL_SUCCESS);
        if (cm != NULL) {
            wolfSSL_CertManagerFree(cm);
            cm = NULL;
        }
    }
#endif /* !WOLFSSL_NO_ASN_STRICT && !WOLFSSL_PYTHON &&
          !WOLFSSL_ASN_ALLOW_0_SERIAL &&
          !WOLFSSL_TEST_APPLE_NATIVE_CERT_VALIDATION */
#endif /* !NO_CERTS && !NO_FILESYSTEM && !NO_RSA && !WOLFSSL_NO_PEM */

    return EXPECT_RESULT();
}

int test_wc_DecodeObjectId(void)
{
    EXPECT_DECLS;

#if !defined(NO_ASN) && \
    (defined(HAVE_OID_DECODING) || defined(WOLFSSL_ASN_PRINT))
    {
        /* OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
         * DER encoding: 2a 86 48 86 f7 0d 01 01 0b
         * First byte 0x2a = 42 => arc0 = 42/40 = 1, arc1 = 42%40 = 2
         * Remaining arcs: 840, 113549, 1, 1, 11
         */
        static const byte oid_sha256rsa[] = {
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
        };
        word16 out[MAX_OID_SZ];
        word32 outSz;

        /* Test 1: Normal decode */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz), 0);
        ExpectIntEQ((int)outSz, 7);
        ExpectIntEQ(out[0], 1);
        ExpectIntEQ(out[1], 2);
        ExpectIntEQ(out[2], 840);
        ExpectIntEQ(out[3], (word16)113549); /* truncated to word16 */
        ExpectIntEQ(out[4], 1);
        ExpectIntEQ(out[5], 1);
        ExpectIntEQ(out[6], 11);

        /* Test 2: NULL args */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(NULL, sizeof(oid_sha256rsa), out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 3 (Bug 1): outSz=1 must return BUFFER_E, not OOB write.
         * The first OID byte decodes into two arcs, so outSz must be >= 2. */
        outSz = 1;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 4: outSz=0 must also return BUFFER_E */
        outSz = 0;
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 5: outSz=2 is enough for a single-byte OID (two arcs) */
        {
            static const byte oid_one_byte[] = { 0x2a }; /* 1.2 */
            outSz = 2;
            ExpectIntEQ(DecodeObjectId(oid_one_byte, sizeof(oid_one_byte),
                                       out, &outSz), 0);
            ExpectIntEQ((int)outSz, 2);
            ExpectIntEQ(out[0], 1);
            ExpectIntEQ(out[1], 2);
        }

        /* Test 6: Buffer too small for later arcs */
        outSz = 3; /* only room for 3 arcs, but OID has 7 */
        ExpectIntEQ(DecodeObjectId(oid_sha256rsa, sizeof(oid_sha256rsa),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
#endif /* !NO_ASN && (HAVE_OID_DECODING || WOLFSSL_ASN_PRINT) */

    return EXPECT_RESULT();
}

#if defined(HAVE_PKCS8) && !defined(NO_ASN) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_PUBLIC_ASN)) && \
    (defined(HAVE_ED25519) || \
     (defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
      defined(WOLFSSL_KEY_GEN)) || \
     (defined(HAVE_DILITHIUM) && \
      !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
      !defined(WOLFSSL_DILITHIUM_NO_ASN1)))
/* Run ToTraditional_ex() on a copy of der and assert the algId, returned
 * length, and the inner OCTET STRING tag/length at the start of the
 * (in-place rewritten) buffer. */
static int test_ToTraditional_ex_once(const byte* der, word32 derSz,
    word32 expectAlgId, word32 expectPrivKeySz)
{
    EXPECT_DECLS;
    byte* copy = NULL;
    word32 algId = 0;
    int    ret;

    copy = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(copy);
    if (copy != NULL) {
        XMEMCPY(copy, der, derSz);
        ret = ToTraditional_ex(copy, derSz, &algId);
        ExpectIntGT(ret, 0);
        ExpectIntEQ(algId, expectAlgId);
        if (ret > 0) {
            /* wolfSSL writes nested OCTET STRING, but accept raw bytes
             * too per RFC 5958. */
            if (copy[0] == ASN_OCTET_STRING) {
                if (expectPrivKeySz < 0x80) {
                    ExpectIntEQ(copy[1], (byte)expectPrivKeySz);
                }
                else if (expectPrivKeySz < 0x100) {
                    ExpectIntEQ(copy[1], 0x81);
                    ExpectIntEQ(copy[2], (byte)expectPrivKeySz);
                }
                else {
                    ExpectIntEQ(copy[1], 0x82);
                    ExpectIntEQ(((word32)copy[2] << 8) | copy[3],
                        expectPrivKeySz);
                }
            }
            else {
                ExpectIntEQ(ret, (int)expectPrivKeySz);
            }
        }
    }
    XFREE(copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#endif

/* Hand crafted PKCS#8 v0 and v1 Ed25519 buffers to test parser directly. */
int test_ToTraditional_ex_handcrafted(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS8) && defined(HAVE_ED25519) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_PUBLIC_ASN))
    /* Ed25519 algorithm OID body (1.3.101.112). */
    static const byte algId[] = { 43, 101, 112 };
    const word32 privKeySz = ED25519_KEY_SIZE;
    const word32 pubKeySz  = ED25519_PUB_KEY_SIZE;
    byte der[128];
    word32 sz;
    word32 outerLenIdx;
    /* Filler bytes for the dummy private/public key bodies */
    const byte keyPat = 0xCC;
    const byte pubPat = 0xDD;

    /* v0: SEQ { INTEGER 0, SEQ { OID }, OCTET STRING { OCTET STRING priv } } */
    sz = 0;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    outerLenIdx = sz;
    der[sz++] = 0;  /* outer length, filled in below */
    der[sz++] = ASN_INTEGER;
    der[sz++] = 1;
    der[sz++] = 0x00;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    der[sz++] = (byte)(sizeof(algId) + 2);
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(algId);
    XMEMCPY(der + sz, algId, sizeof(algId)); sz += sizeof(algId);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)(privKeySz + 2);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)privKeySz;
    XMEMSET(der + sz, keyPat, privKeySz); sz += privKeySz;
    der[outerLenIdx] = (byte)(sz - outerLenIdx - 1);

    EXPECT_TEST(test_ToTraditional_ex_once(der, sz, ED25519k, privKeySz));

    /* v1: same plus [1] publicKey trailer. */
    sz = 0;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    outerLenIdx = sz;
    der[sz++] = 0;
    der[sz++] = ASN_INTEGER;
    der[sz++] = 1;
    der[sz++] = 0x01;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    der[sz++] = (byte)(sizeof(algId) + 2);
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(algId);
    XMEMCPY(der + sz, algId, sizeof(algId)); sz += sizeof(algId);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)(privKeySz + 2);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)privKeySz;
    XMEMSET(der + sz, keyPat, privKeySz); sz += privKeySz;
    /* [1] publicKey trailer */
    der[sz++] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
    der[sz++] = (byte)pubKeySz;
    XMEMSET(der + sz, pubPat, pubKeySz); sz += pubKeySz;
    der[outerLenIdx] = (byte)(sz - outerLenIdx - 1);

    EXPECT_TEST(test_ToTraditional_ex_once(der, sz, ED25519k, privKeySz));

    /* v1 without publicKey: should still accept per RFC 5958. */
    sz = 0;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    outerLenIdx = sz;
    der[sz++] = 0;
    der[sz++] = ASN_INTEGER;
    der[sz++] = 1;
    der[sz++] = 0x01;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    der[sz++] = (byte)(sizeof(algId) + 2);
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(algId);
    XMEMCPY(der + sz, algId, sizeof(algId)); sz += sizeof(algId);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)(privKeySz + 2);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)privKeySz;
    XMEMSET(der + sz, keyPat, privKeySz); sz += privKeySz;
    der[outerLenIdx] = (byte)(sz - outerLenIdx - 1);

    EXPECT_TEST(test_ToTraditional_ex_once(der, sz, ED25519k, privKeySz));
#endif /* HAVE_PKCS8 && HAVE_ED25519 */
    return EXPECT_RESULT();
}

/* Encoder/parser round trip: ToTraditional_ex() must accept both forms created
 * by SetAsymKeyDer() (v0 with PrivateKeyToDer, v1 with KeyToDer). */
int test_ToTraditional_ex_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS8) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_PUBLIC_ASN))

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    defined(WOLFSSL_KEY_GEN)
    {
        ed25519_key key;
        WC_RNG rng;
        byte der[256];
        int  derSz = 0;

        XMEMSET(&key, 0, sizeof(key));
        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

        if (EXPECT_SUCCESS()) {
            ExpectIntGT(derSz = wc_Ed25519KeyToDer(&key, der, sizeof(der)), 0);
            EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz, ED25519k,
                ED25519_KEY_SIZE));

            derSz = wc_Ed25519PrivateKeyToDer(&key, der, sizeof(der));
            ExpectIntGT(derSz, 0);
            EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz, ED25519k,
                ED25519_KEY_SIZE));
        }

        wc_ed25519_free(&key);
        wc_FreeRng(&rng);
    }
#endif /* HAVE_ED25519 */

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    defined(WOLFSSL_KEY_GEN)
    {
        ed448_key key;
        WC_RNG rng;
        byte der[256];
        int  derSz = 0;

        XMEMSET(&key, 0, sizeof(key));
        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ed448_init(&key), 0);
        ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

        if (EXPECT_SUCCESS()) {
            ExpectIntGT(derSz = wc_Ed448KeyToDer(&key, der, sizeof(der)), 0);
            EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz, ED448k,
                ED448_KEY_SIZE));

            derSz = wc_Ed448PrivateKeyToDer(&key, der, sizeof(der));
            ExpectIntGT(derSz, 0);
            EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz, ED448k,
                ED448_KEY_SIZE));
        }

        wc_ed448_free(&key);
        wc_FreeRng(&rng);
    }
#endif /* HAVE_ED448 */

#if defined(HAVE_DILITHIUM) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_ASN1) && \
    (!defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_65) || \
     !defined(WOLFSSL_NO_ML_DSA_87))
    {
        static const struct {
            int   wcLevel;
            word32 oidSum;
            word32 privKeySz;
        } variants[] = {
        #ifndef WOLFSSL_NO_ML_DSA_44
            { WC_ML_DSA_44, ML_DSA_LEVEL2k, ML_DSA_LEVEL2_KEY_SIZE },
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_65
            { WC_ML_DSA_65, ML_DSA_LEVEL3k, ML_DSA_LEVEL3_KEY_SIZE },
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_87
            { WC_ML_DSA_87, ML_DSA_LEVEL5k, ML_DSA_LEVEL5_KEY_SIZE },
        #endif
        };

        const word32 derMaxSz = DILITHIUM_MAX_BOTH_KEY_DER_SIZE;
        byte* der = NULL;
        WC_RNG rng;
        size_t i;
        int derSz;

        XMEMSET(&rng, 0, sizeof(rng));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectNotNull(der = (byte*)XMALLOC(derMaxSz, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));

        for (i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
            dilithium_key key;

            XMEMSET(&key, 0, sizeof(key));
            ExpectIntEQ(wc_dilithium_init(&key), 0);
            ExpectIntEQ(wc_dilithium_set_level(&key, variants[i].wcLevel), 0);
            ExpectIntEQ(wc_dilithium_make_key(&key, &rng), 0);

            if (EXPECT_SUCCESS()) {
                ExpectIntGT(derSz = wc_Dilithium_KeyToDer(&key, der, derMaxSz),
                    0);
                EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz,
                    variants[i].oidSum, variants[i].privKeySz));

                derSz = wc_Dilithium_PrivateKeyToDer(&key, der, derMaxSz);
                ExpectIntGT(derSz, 0);
                EXPECT_TEST(test_ToTraditional_ex_once(der, (word32)derSz,
                    variants[i].oidSum, variants[i].privKeySz));
            }

            wc_dilithium_free(&key);
        }

        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
    }
#endif /* HAVE_DILITHIUM */

#endif /* HAVE_PKCS8 */
    return EXPECT_RESULT();
}

/* Trailing garbage that is neither [0] attributes nor [1] publicKey must
 * still be rejected. */
int test_ToTraditional_ex_negative(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS8) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_KEY_EXPORT) && defined(WOLFSSL_KEY_GEN) && \
    defined(WOLFSSL_ASN_TEMPLATE) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_PUBLIC_ASN))
    ed25519_key key;
    WC_RNG rng;
    byte der[256];
    byte copy[256];
    int  derSz = 0;
    word32 algId;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    ExpectIntGT(derSz = wc_Ed25519PrivateKeyToDer(&key, der, sizeof(der)), 0);

    if (EXPECT_SUCCESS() && (derSz > 0) &&
        ((size_t)derSz + 1 <= sizeof(copy))) {
        /* Append one byte of trailing data, grow outer SEQ length to cover.
         * Ed25519 PKCS#8 outer SEQ is under 128 bytes, expect DER short form
         * so the negative path is always exercised. */
        XMEMCPY(copy, der, (size_t)derSz);
        ExpectTrue(copy[1] < 0x80);
        if (EXPECT_SUCCESS() && copy[1] < 0x80) {
            copy[1] = (byte)(copy[1] + 1);
            copy[derSz] = 0x05;
            algId = 0;
            ExpectIntLT(ToTraditional_ex(copy, (word32)(derSz + 1), &algId), 0);
        }
    }

    /* publicKey trailer is permitted only when version == v1 */
    if (EXPECT_SUCCESS() && (derSz > 0) &&
        ((size_t)derSz + 2 + ED25519_PUB_KEY_SIZE <= sizeof(copy))) {
        word32 trailerSz = 2 + ED25519_PUB_KEY_SIZE;
        XMEMCPY(copy, der, (size_t)derSz);
        ExpectTrue(copy[1] < (byte)(0x80 - trailerSz));
        if (EXPECT_SUCCESS() && copy[1] < (byte)(0x80 - trailerSz)) {
            copy[1] = (byte)(copy[1] + trailerSz);
            copy[derSz] = ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY;
            copy[derSz + 1] = ED25519_PUB_KEY_SIZE;
            XMEMSET(copy + derSz + 2, 0xDD, ED25519_PUB_KEY_SIZE);
            algId = 0;
            ExpectIntLT(ToTraditional_ex(copy,
                (word32)(derSz + (int)trailerSz), &algId), 0);
        }
    }

    /* v1 buffer (with publicKey) plus extra trailing garbage. */
    ExpectIntGT(derSz = wc_Ed25519KeyToDer(&key, der, sizeof(der)), 0);
    if (EXPECT_SUCCESS() && (derSz > 0) &&
        ((size_t)derSz + 1 <= sizeof(copy))) {
        XMEMCPY(copy, der, (size_t)derSz);
        ExpectTrue(copy[1] < 0x80);
        if (EXPECT_SUCCESS() && copy[1] < 0x80) {
            copy[1] = (byte)(copy[1] + 1);
            copy[derSz] = 0x05;
            algId = 0;
            ExpectIntLT(ToTraditional_ex(copy, (word32)(derSz + 1), &algId), 0);
        }
    }

    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

/* ML-DSA AlgorithmIdentifier has no parameters per FIPS 204. Verify
 * ToTraditional_ex() rejects a PKCS#8 whose algoSeq carries trailing NULL
 * or OBJECT_ID parameters. Template parser only (legacy is lenient). */
int test_ToTraditional_ex_mldsa_bad_params(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PKCS8) && defined(HAVE_DILITHIUM) && \
    defined(WOLFSSL_ASN_TEMPLATE) && \
    (defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_PUBLIC_ASN))
    /* ML-DSA-65 OID body: 2.16.840.1.101.3.4.3.18 */
    static const byte mldsaOid[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                     0x04, 0x03, 0x12 };
    /* Single-arc OID body, used only to occupy the OBJECT_ID slot. */
    static const byte extraOid[] = { 0x01 };
    byte der[64];
    byte copy[64];
    word32 sz;
    word32 outerLenIdx;
    word32 algId;
    const word32 privKeySz = 4;
    const byte   privBody  = 0xAA;

    /* Bad case, algoSeq = { OID, NULL } */
    sz = 0;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    outerLenIdx = sz;
    der[sz++] = 0;  /* outer length, filled in below */
    der[sz++] = ASN_INTEGER;
    der[sz++] = 1;
    der[sz++] = 0x00;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    der[sz++] = (byte)(sizeof(mldsaOid) + 2 + 2);
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(mldsaOid);
    XMEMCPY(der + sz, mldsaOid, sizeof(mldsaOid)); sz += sizeof(mldsaOid);
    /* Disallowed, NULL parameter after the ML-DSA OID. */
    der[sz++] = ASN_TAG_NULL;
    der[sz++] = 0;
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)(privKeySz + 2);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)privKeySz;
    XMEMSET(der + sz, privBody, privKeySz); sz += privKeySz;
    der[outerLenIdx] = (byte)(sz - outerLenIdx - 1);

    XMEMCPY(copy, der, sz);
    algId = 0;
    ExpectIntLT(ToTraditional_ex(copy, sz, &algId), 0);

    /* Bad case, algoSeq = { OID, OBJECT_ID } */
    sz = 0;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    outerLenIdx = sz;
    der[sz++] = 0;
    der[sz++] = ASN_INTEGER;
    der[sz++] = 1;
    der[sz++] = 0x00;
    der[sz++] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    der[sz++] = (byte)(sizeof(mldsaOid) + 2 + sizeof(extraOid) + 2);
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(mldsaOid);
    XMEMCPY(der + sz, mldsaOid, sizeof(mldsaOid)); sz += sizeof(mldsaOid);
    /* Disallowed, OBJECT_ID parameter after the ML-DSA OID. */
    der[sz++] = ASN_OBJECT_ID;
    der[sz++] = (byte)sizeof(extraOid);
    XMEMCPY(der + sz, extraOid, sizeof(extraOid)); sz += sizeof(extraOid);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)(privKeySz + 2);
    der[sz++] = ASN_OCTET_STRING;
    der[sz++] = (byte)privKeySz;
    XMEMSET(der + sz, privBody, privKeySz); sz += privKeySz;
    der[outerLenIdx] = (byte)(sz - outerLenIdx - 1);

    XMEMCPY(copy, der, sz);
    algId = 0;
    ExpectIntLT(ToTraditional_ex(copy, sz, &algId), 0);
#endif
    return EXPECT_RESULT();
}
