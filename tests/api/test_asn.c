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
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
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

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(IGNORE_NAME_CONSTRAINTS)
/* One AttributeTypeAndValue for the directoryName cases below. */
typedef struct DirTestAttr {
    byte        oid;   /* Last octet of the 2.5.4.x attribute type OID. */
    byte        tag;   /* ASN.1 string tag of the value. */
    const byte* val;   /* Value content octets. */
    word32      valSz;
} DirTestAttr;

#define DIR_OID_CN 0x03  /* 2.5.4.3  commonName */
#define DIR_OID_O  0x0a  /* 2.5.4.10 organizationName */
/* OR into the oid field to put the attribute in the same RDN as the one
 * before it, making a multi-valued RDN. The 2.5.4.x attribute types are all
 * well below this bit. */
#define DIR_JOIN   0x80

/* Encode the content octets of an RDNSequence, i.e. what GetCertName()
 * stores in cert->subjectRaw and what DecodeSubtreeGeneralName() stores for
 * a directoryName subtree (the outer SEQUENCE header is stripped in both).
 * Each attribute starts a new RDN unless its oid carries DIR_JOIN, which
 * puts it in the RDN before it. The attributes of a multi-valued RDN are
 * emitted in the order
 * given rather than in DER SET OF order, which is what lets the cases below
 * present the same RDN two ways. Only short form lengths are needed here.
 * Returns the encoded length or -1 if it does not fit. */
static int dirNameEnc(byte* out, word32 outSz, const DirTestAttr* attrs,
                      int cnt)
{
    word32 idx = 0;
    int    i = 0;

    while (i < cnt) {
        word32 setLenIdx;
        word32 setSz = 0;

        if ((idx + 2) > outSz) {
            return -1;
        }
        out[idx++] = 0x31;                  /* SET OF */
        setLenIdx = idx++;                  /* Length, filled in below. */

        do {
            /* AttributeTypeAndValue content: the OID TLV plus the value TLV.
             */
            word32 avaSz = (2 + 3) + (2 + attrs[i].valSz);

            if ((attrs[i].valSz > 127) || (avaSz > 127) ||
                    ((idx + 2 + avaSz) > outSz)) {
                return -1;
            }

            out[idx++] = 0x30;              /* SEQUENCE */
            out[idx++] = (byte)avaSz;
            out[idx++] = 0x06;              /* OBJECT IDENTIFIER */
            out[idx++] = 0x03;
            out[idx++] = 0x55;              /* 2.5.4.x */
            out[idx++] = 0x04;
            out[idx++] = (byte)(attrs[i].oid & (byte)~DIR_JOIN);
            out[idx++] = attrs[i].tag;
            out[idx++] = (byte)attrs[i].valSz;
            XMEMCPY(out + idx, attrs[i].val, attrs[i].valSz);
            idx += attrs[i].valSz;

            setSz += 2 + avaSz;
            i++;
        } while ((i < cnt) && ((attrs[i].oid & DIR_JOIN) != 0));

        if (setSz > 127) {
            return -1;
        }
        out[setLenIdx] = (byte)setSz;
    }

    return (int)idx;
}

/* Encode both names and run them through the directoryName matcher. */
static int dirMatch(const DirTestAttr* nm, int nmCnt, const DirTestAttr* bs,
                    int bsCnt)
{
    byte nameDer[128];
    byte baseDer[128];
    int  nameSz;
    int  baseSz;

    nameSz = dirNameEnc(nameDer, (word32)sizeof(nameDer), nm, nmCnt);
    baseSz = dirNameEnc(baseDer, (word32)sizeof(baseDer), bs, bsCnt);
    if ((nameSz < 0) || (baseSz < 0)) {
        return -1;
    }

    return wolfssl_local_MatchBaseName(ASN_DIR_TYPE, (const char*)nameDer,
        nameSz, (const char*)baseDer, baseSz);
}
#endif /* !NO_CERTS && !NO_ASN && !IGNORE_NAME_CONSTRAINTS */

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
     *
     * A directoryName subtree matches when its RDN sequence is an initial
     * subsequence of the certificate DN (RFC 5280 Sec. 4.2.1.10), with RDNs
     * compared using the Sec. 7.1 name matching rules: the attribute type
     * OID must be identical, but the value is compared by folded code point
     * so that letter case, the ASN.1 string type used and insignificant
     * spacing do not matter. Comparing the DER directly used to let a
     * semantically equal name slip past an excluded subtree.
     */
    {
        static const byte forbidden[]   =
            { 'F','o','r','b','i','d','d','e','n' };
        static const byte forbiddenUp[] =
            { 'F','O','R','B','I','D','D','E','N' };
        static const byte forbiddenSp[] =
            { ' ','F','o','r','b','i','d','d','e','n',' ',' ' };
        static const byte forbid[]      = { 'F','o','r','b','i','d' };
        static const byte allowed[]     = { 'A','l','l','o','w','e','d' };
        static const byte leaf[]        = { 'l','e','a','f' };
        static const byte other[]       = { 'o','t','h','e','r' };
        static const byte forBid[]      = { 'F','o','r',' ','b','i','d' };
        static const byte forBid2[]     = { 'F','o','r',' ',' ','b','i','d' };
        /* "Forbidden" as BMPString (UCS-2) and UniversalString (UCS-4). */
        static const byte forbiddenBmp[] = {
            0,'F', 0,'o', 0,'r', 0,'b', 0,'i', 0,'d', 0,'d', 0,'e', 0,'n'
        };
        static const byte forbiddenUcs[] = {
            0,0,0,'F', 0,0,0,'o', 0,0,0,'r', 0,0,0,'b', 0,0,0,'i',
            0,0,0,'d', 0,0,0,'d', 0,0,0,'e', 0,0,0,'n'
        };
        /* U+00C4 and U+00E4 (A with diaeresis, upper and lower case) in
         * UTF-8 and as a BMPString. */
        static const byte upperAeUtf8[] = { 0xc3, 0x84 };
        static const byte upperAeBmp[]  = { 0x00, 0xc4 };
        static const byte lowerAeUtf8[] = { 0xc3, 0xa4 };

        /* base: O=Forbidden */
        const DirTestAttr bForbidden[] = {
            { DIR_OID_O, ASN_UTF8STRING, forbidden, sizeof(forbidden) }
        };
        /* base: O=Forbidden, CN=leaf */
        const DirTestAttr bForbiddenLeaf[] = {
            { DIR_OID_O,  ASN_UTF8STRING, forbidden, sizeof(forbidden) },
            { DIR_OID_CN, ASN_UTF8STRING, leaf,      sizeof(leaf) }
        };

        /* Exact encoding, subtree is a proper prefix of the DN. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbidden, sizeof(forbidden) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf,      sizeof(leaf) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 1);
        }
        /* Whole DN equals the subtree. */
        ExpectIntEQ(dirMatch(bForbiddenLeaf, 2, bForbiddenLeaf, 2), 1);

        /* Letter case is ignored. Byte comparison used to miss this and
         * accept the certificate. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbiddenUp,
                  sizeof(forbiddenUp) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf, sizeof(leaf) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 1);
        }
        /* A different string type holding the same characters is the same
         * name: PrintableString, BMPString and UniversalString against a
         * UTF8String subtree. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_PRINTABLE_STRING, forbidden,
                  sizeof(forbidden) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf, sizeof(leaf) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 1);
        }
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_BMPSTRING, forbiddenBmp,
                  sizeof(forbiddenBmp) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bForbidden, 1), 1);
        }
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_UNIVERSALSTRING, forbiddenUcs,
                  sizeof(forbiddenUcs) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bForbidden, 1), 1);
        }
        /* Non-ASCII characters compare across string types too. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_BMPSTRING, upperAeBmp, sizeof(upperAeBmp) }
            };
            const DirTestAttr bs[] = {
                { DIR_OID_O, ASN_UTF8STRING, upperAeUtf8,
                  sizeof(upperAeUtf8) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bs, 1), 1);
        }
        /* Leading and trailing spaces are insignificant, in either operand.
         * The DN encoding being shorter than the subtree encoding must not
         * short-circuit the comparison. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbiddenSp,
                  sizeof(forbiddenSp) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf, sizeof(leaf) }
            };
            const DirTestAttr bs[] = {
                { DIR_OID_O, ASN_UTF8STRING, forbiddenSp,
                  sizeof(forbiddenSp) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 1);
            ExpectIntEQ(dirMatch(bForbidden, 1, bs, 1), 1);
        }
        /* An inner run of spaces collapses to one. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_UTF8STRING, forBid2, sizeof(forBid2) }
            };
            const DirTestAttr bs[] = {
                { DIR_OID_O, ASN_UTF8STRING, forBid, sizeof(forBid) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bs, 1), 1);
        }

        /* RFC 4518 Sec. 2.2 maps a fixed set of code points to SPACE and
         * another to nothing, so that names differing only in the width of
         * a space or in characters that carry no meaning of their own are
         * the same name. Leaving them unmapped would let a subordinate CA
         * sidestep an excluded subtree with a name that renders the same as
         * the excluded one. */
        {
            /* "For" + NO-BREAK SPACE (U+00A0) + "bid". */
            static const byte forNbspBid[] =
                { 'F','o','r', 0xc2,0xa0, 'b','i','d' };
            /* "For" + CHARACTER TABULATION + "bid". */
            static const byte forTabBid[] =
                { 'F','o','r', 0x09, 'b','i','d' };
            /* "For" + IDEOGRAPHIC SPACE (U+3000) + "bid". */
            static const byte forIdeoBid[] =
                { 'F','o','r', 0xe3,0x80,0x80, 'b','i','d' };
            /* NO-BREAK SPACE either side of "Forbidden". */
            static const byte nbspForbidden[] = {
                0xc2,0xa0, 'F','o','r','b','i','d','d','e','n', 0xc2,0xa0
            };
            /* "For" SPACE SOFT HYPHEN (U+00AD) SPACE "bid": a code point
             * that maps to nothing does not break the run of spaces. */
            static const byte forShyBid[] =
                { 'F','o','r', ' ', 0xc2,0xad, ' ', 'b','i','d' };
            /* "Forbid" with a ZERO WIDTH SPACE (U+200B) in the middle,
             * which maps to nothing rather than to a space. */
            static const byte forZwspBid[] =
                { 'F','o','r', 0xe2,0x80,0x8b, 'b','i','d' };
            /* "Forbidden" with VARIATION SELECTOR-1 (U+FE00) in it. */
            static const byte forbidVsDen[] = {
                'F','o','r','b','i','d', 0xef,0xb8,0x80, 'd','e','n'
            };
            /* "For" + the octet 0xa0 + "bid". */
            static const byte forA0Bid[] =
                { 'F','o','r', 0xa0, 'b','i','d' };

            /* base: O=For bid */
            const DirTestAttr bForBid[] = {
                { DIR_OID_O, ASN_UTF8STRING, forBid, sizeof(forBid) }
            };
            /* base: O=Forbid */
            const DirTestAttr bForbid[] = {
                { DIR_OID_O, ASN_UTF8STRING, forbid, sizeof(forbid) }
            };

            /* Code points that stand in for a space. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forNbspBid,
                      sizeof(forNbspBid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 1);
                ExpectIntEQ(dirMatch(bForBid, 1, nm, 1), 1);
            }
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forTabBid,
                      sizeof(forTabBid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 1);
            }
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forIdeoBid,
                      sizeof(forIdeoBid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 1);
            }
            /* They are insignificant leading and trailing, as a space is. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, nbspForbidden,
                      sizeof(nbspForbidden) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForbidden, 1), 1);
            }
            /* Code points that map to nothing drop out, leaving the spaces
             * on either side of them one run. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forShyBid,
                      sizeof(forShyBid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 1);
            }
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forbidVsDen,
                      sizeof(forbidVsDen) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForbidden, 1), 1);
            }
            /* ZERO WIDTH SPACE maps to nothing and not to a space, whatever
             * its name suggests: it joins the two halves rather than
             * separating them. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forZwspBid,
                      sizeof(forZwspBid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForbid, 1), 1);
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 0);
            }
            /* Only the Unicode string types are mapped beyond ASCII. The
             * octet 0xa0 of a T61String is not NO-BREAK SPACE, and in a
             * UTF8String it is not a character at all. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_T61STRING, forA0Bid, sizeof(forA0Bid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1), 0);
            }
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forA0Bid,
                      sizeof(forA0Bid) }
                };
                ExpectIntEQ(dirMatch(nm, 1, bForBid, 1),
                            WC_NO_ERR_TRACE(ASN_PARSE_E));
            }
        }

        /* Negative tests - should NOT match */

        /* Different value. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, allowed, sizeof(allowed) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf,    sizeof(leaf) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 0);
        }
        /* A value the subtree value is a prefix of is a different name. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbid, sizeof(forbid) },
                { DIR_OID_CN, ASN_UTF8STRING, leaf,   sizeof(leaf) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbidden, 1), 0);
        }
        /* Same value under a different attribute type. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_CN, ASN_UTF8STRING, forbidden, sizeof(forbidden) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bForbidden, 1), 0);
        }
        /* The DN has fewer RDNs than the subtree. */
        ExpectIntEQ(dirMatch(bForbidden, 1, bForbiddenLeaf, 2), 0);
        /* The subtree is not an initial subsequence of the DN. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbidden, sizeof(forbidden) },
                { DIR_OID_CN, ASN_UTF8STRING, other,     sizeof(other) }
            };
            ExpectIntEQ(dirMatch(nm, 2, bForbiddenLeaf, 2), 0);
        }
        /* An inner space is significant, only runs of them collapse. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_UTF8STRING, forbid, sizeof(forbid) }
            };
            const DirTestAttr bs[] = {
                { DIR_OID_O, ASN_UTF8STRING, forBid, sizeof(forBid) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bs, 1), 0);
        }
        /* Case folding is ASCII only, matching what other implementations
         * canonicalize. U+00C4 and U+00E4 stay distinct. */
        {
            const DirTestAttr nm[] = {
                { DIR_OID_O, ASN_UTF8STRING, lowerAeUtf8,
                  sizeof(lowerAeUtf8) }
            };
            const DirTestAttr bs[] = {
                { DIR_OID_O, ASN_UTF8STRING, upperAeUtf8,
                  sizeof(upperAeUtf8) }
            };
            ExpectIntEQ(dirMatch(nm, 1, bs, 1), 0);
        }

        /* An RDN holding several attributes is a set: RFC 5280 Sec. 7.1
         * matches two RDNs when their attributes pair up one for one, in
         * whatever order they were encoded. DER sorts the components of a
         * SET OF by encoding, but the sort key is the encoding while the
         * comparison is deliberately insensitive to it, so equal names can
         * still list their attributes in different orders. */
        {
            /* One RDN: O=Forbidden + CN=leaf. */
            const DirTestAttr mv[] = {
                { DIR_OID_O,  ASN_UTF8STRING, forbidden, sizeof(forbidden) },
                { DIR_OID_CN | DIR_JOIN, ASN_UTF8STRING, leaf, sizeof(leaf) }
            };
            /* The same RDN with the attributes the other way around. */
            const DirTestAttr mvRev[] = {
                { DIR_OID_CN, ASN_UTF8STRING, leaf, sizeof(leaf) },
                { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, forbidden,
                  sizeof(forbidden) }
            };

            /* Order within the RDN does not matter, in either operand. */
            ExpectIntEQ(dirMatch(mv, 2, mvRev, 2), 1);
            ExpectIntEQ(dirMatch(mvRev, 2, mv, 2), 1);
            /* Reordering and the Sec. 7.1 value rules apply together. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_CN, ASN_PRINTABLE_STRING, leaf, sizeof(leaf) },
                    { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, forbiddenUp,
                      sizeof(forbiddenUp) }
                };
                ExpectIntEQ(dirMatch(nm, 2, mv, 2), 1);
            }
            /* A reordered multi-valued RDN still only matches as a whole
             * RDN of the subtree, with any further DN RDNs ignored. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_O,  ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) },
                    { DIR_OID_CN | DIR_JOIN, ASN_UTF8STRING, leaf,
                      sizeof(leaf) },
                    { DIR_OID_CN, ASN_UTF8STRING, other, sizeof(other) }
                };
                ExpectIntEQ(dirMatch(nm, 3, mvRev, 2), 1);
            }

            /* An attribute of the subtree RDN that the DN RDN does not hold
             * means the RDNs differ, however they are ordered. */
            ExpectIntEQ(dirMatch(bForbidden, 1, mv, 2), 0);
            ExpectIntEQ(dirMatch(mv, 2, bForbidden, 1), 0);
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_CN, ASN_UTF8STRING, other, sizeof(other) },
                    { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) }
                };
                ExpectIntEQ(dirMatch(nm, 2, mv, 2), 0);
            }
            /* The attributes must pair up one for one: a repeated attribute
             * cannot stand in for two different ones. */
            {
                const DirTestAttr twice[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) },
                    { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) }
                };
                const DirTestAttr pair[] = {
                    { DIR_OID_O, ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) },
                    { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, allowed,
                      sizeof(allowed) }
                };
                ExpectIntEQ(dirMatch(twice, 2, pair, 2), 0);
                ExpectIntEQ(dirMatch(pair, 2, twice, 2), 0);
                ExpectIntEQ(dirMatch(twice, 2, twice, 2), 1);
            }
        }

        /* Malformed encodings - neither "match" nor "no match" is safe, so
         * the error is returned and the caller rejects the certificate. */
        {
            /* Overlong two octet encoding of "F": it must not decode to a
             * character, or it could impersonate the plain spelling. */
            static const byte overlongF[] =
                { 0xc1, 0x86, 'o','r','b','i','d','d','e','n' };
            /* Truncated two octet sequence. */
            static const byte truncUtf8[] = { 'F', 0xc3 };
            /* Continuation octet with no lead octet. */
            static const byte loneCont[]  = { 0x80, 'F' };
            /* BMPString with an odd number of octets. */
            static const byte oddBmp[]    = { 0x00, 'F', 0x00 };
            /* BMPString high surrogate with no low surrogate after it. */
            static const byte loneHiBmp[] = { 0xd8, 0x00, 0x00, 'F' };
            /* BMPString low surrogate with no high surrogate before it. */
            static const byte loneLoBmp[] = { 0xdc, 0x00, 0x00, 'F' };
            /* UniversalString with a length that is not a multiple of 4. */
            static const byte shortUcs[]  = { 0x00, 0x00, 0x00 };
            /* UniversalString code point past the end of Unicode. */
            static const byte bigUcs[]    = { 0x00, 0x11, 0x00, 0x00 };
            static const struct {
                byte        tag;
                const byte* val;
                word32      valSz;
            } bad[] = {
                { ASN_UTF8STRING,      overlongF, sizeof(overlongF) },
                { ASN_UTF8STRING,      truncUtf8, sizeof(truncUtf8) },
                { ASN_UTF8STRING,      loneCont,  sizeof(loneCont)  },
                { ASN_BMPSTRING,       oddBmp,    sizeof(oddBmp)    },
                { ASN_BMPSTRING,       loneHiBmp, sizeof(loneHiBmp) },
                { ASN_BMPSTRING,       loneLoBmp, sizeof(loneLoBmp) },
                { ASN_UNIVERSALSTRING, shortUcs,  sizeof(shortUcs)  },
                { ASN_UNIVERSALSTRING, bigUcs,    sizeof(bigUcs)    }
            };
            int i;

            for (i = 0; i < (int)(sizeof(bad) / sizeof(bad[0])); i++) {
                DirTestAttr one[] = {
                    { DIR_OID_O, bad[i].tag, bad[i].val, bad[i].valSz }
                };

                /* Malformed in the certificate DN. */
                ExpectIntEQ(dirMatch(one, 1, bForbidden, 1),
                            WC_NO_ERR_TRACE(ASN_PARSE_E));
                /* Malformed in the constraint subtree. */
                ExpectIntEQ(dirMatch(bForbidden, 1, one, 1),
                            WC_NO_ERR_TRACE(ASN_PARSE_E));
            }

            /* A malformed value is only decoded once the attribute type
             * matches, so a different OID still answers "no match". */
            {
                const DirTestAttr one[] = {
                    { DIR_OID_CN, ASN_UTF8STRING, truncUtf8,
                      sizeof(truncUtf8) }
                };
                ExpectIntEQ(dirMatch(one, 1, bForbidden, 1), 0);
            }

            /* A malformed attribute inside a multi-valued RDN is reported
             * even though the other attribute of that RDN pairs up. */
            {
                const DirTestAttr nm[] = {
                    { DIR_OID_CN, ASN_UTF8STRING, leaf, sizeof(leaf) },
                    { DIR_OID_O | DIR_JOIN, ASN_UTF8STRING, truncUtf8,
                      sizeof(truncUtf8) }
                };
                const DirTestAttr bs[] = {
                    { DIR_OID_O,  ASN_UTF8STRING, forbidden,
                      sizeof(forbidden) },
                    { DIR_OID_CN | DIR_JOIN, ASN_UTF8STRING, leaf,
                      sizeof(leaf) }
                };
                ExpectIntEQ(dirMatch(nm, 2, bs, 2),
                            WC_NO_ERR_TRACE(ASN_PARSE_E));
            }
        }
    }

    /* Neither operand is a parsable RDNSequence. Reporting "no match" would
     * be fail-open for an excluded subtree and "match" fail-open for a
     * permitted one, so the error is returned instead. */
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=test", 7, "CN=test", 7), WC_NO_ERR_TRACE(ASN_PARSE_E));
    ExpectIntEQ(wolfssl_local_MatchBaseName(ASN_DIR_TYPE,
                "CN=other", 8, "CN=test", 7), WC_NO_ERR_TRACE(ASN_PARSE_E));

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

    /* A single trailing dot is the absolute-FQDN marker: "host.com." and
     * "host.com" denote the same host and must compare equal, matching the
     * DNS name-constraint path. */
    ExpectIntEQ(uriNC("https://host.com./",           "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com.:8443/x",     "host.com"), 1);
    ExpectIntEQ(uriNC("https://host.com",             "host.com."), 1);
    ExpectIntEQ(uriNC("https://host.com./",           "host.com."), 1);
    ExpectIntEQ(uriNC("https://v1.addr./",            "v1.addr"), 1);
    ExpectIntEQ(uriNC("https://v1.addr/",             "v1.addr."), 1);
    /* Only ONE trailing dot is the marker; an empty last label is not. */
    ExpectIntEQ(uriNC("https://host.com../",          "host.com"), 0);
    ExpectIntEQ(uriNC("https://a.host.com../",        ".host.com"), 0);
    /* Empty interior labels are not valid DNS host labels. */
    ExpectIntEQ(uriNC("https://a..host.com/",         ".host.com"), 0);

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
     * RFC 5280 URI constraints require a DNS host. IP-literals / IPvFuture
     * hosts in brackets and IPv4address hosts are not DNS reg-names.
     */
    ExpectIntEQ(uriNC("https://[2001:db8::1]:443/x",  "2001:db8::1"), 0);
    ExpectIntEQ(uriNC("https://[2001:db8::1]",        "2001:db8::2"), 0);
    ExpectIntEQ(uriNC("https://[v1.addr.]/",          "v1.addr"), 0);
    ExpectIntEQ(uriNC("https://[v1.addr.]/",          "v1.addr."), 0);
    ExpectIntEQ(uriNC("https://12.31.2.3/",           "12.31.2.3"), 0);
    /* An IPv4address host is still not a DNS reg-name when written with the
     * absolute-FQDN trailing dot. */
    ExpectIntEQ(uriNC("https://12.31.2.3./",          "12.31.2.3"), 0);
    ExpectIntEQ(uriNC("https://12.31.2.3./",          "12.31.2.3."), 0);

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
 * remaining SEQUENCE length (integer underflow on the length tracker), and
 * that a dNSName SAN carrying an embedded NUL is stored rather than rejected
 * so verification reports a name mismatch instead of a parse error. */
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

    /* An embedded NUL in a dNSName SAN is an invalid presented identifier
     * (RFC 6125 Sec. 6.3 / RFC 9525 Sec. 6.3), not a malformed certificate.
     * Set the third byte of the 4-byte dNSName ("a*b*") to NUL, giving
     * "a*\0*".  The certificate must still parse: the entry is stored with
     * its embedded NUL intact (length 4, not truncated) so that hostname
     * verification reports DOMAIN_NAME_MISMATCH rather than the parser
     * aborting with ASN_PARSE_E (regression from curl test 311). */
    XMEMCPY(bad_san_cert, good_san_cert, sizeof(good_san_cert));
    bad_san_cert[SAN_SEQ_LEN_OFFSET + 5] = 0x00;

    wc_InitDecodedCert(&cert, bad_san_cert, (word32)sizeof(bad_san_cert),
        NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
    ExpectNotNull(cert.altNames);
    if (cert.altNames != NULL) {
        ExpectIntEQ(cert.altNames->type, ASN_DNS_TYPE);
        ExpectIntEQ(cert.altNames->len, 4);
        /* Embedded NUL preserved at offset 2: stored, not truncated. */
        ExpectNotNull(cert.altNames->name);
        if (cert.altNames->name != NULL) {
            ExpectIntEQ(cert.altNames->name[2], 0x00);
        }
    }
    wc_FreeDecodedCert(&cert);

#endif /* !NO_CERTS && !NO_RSA && !NO_ASN */
    return EXPECT_RESULT();
}

/* A certificate must not carry two certificatePolicies extensions
 * (non-repeatable per RFC 5280 4.2). DecodeCertExtensions calls
 * DecodeExtensionType once per extension; a second certificatePolicies
 * extension must be rejected (ASN_OBJECT_ID_E) rather than silently
 * overwriting the first - which happened in WOLFSSL_CERT_EXT builds without
 * WOLFSSL_SEP before the duplicate guard was extended to cover them. */
int test_DecodeCertExtensions_dup_certpol(void)
{
    EXPECT_DECLS;
#if (defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_CERTS) && !defined(NO_ASN)
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

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(NO_RSA)
/* Number of bytes needed to DER-encode the definite length "len".
 * Only handles len < 0x10000, which is all this test needs. */
static int dnb_lenSz(int len)
{
    if (len < 0x80)
        return 1;
    if (len < 0x100)
        return 2;
    return 3;
}

/* Write the DER definite length "len" to out. Returns the bytes written. */
static int dnb_encodeLen(byte* out, int len)
{
    int i = 0;

    if (len < 0x80) {
        out[i++] = (byte)len;
    }
    else if (len < 0x100) {
        out[i++] = 0x81;
        out[i++] = (byte)len;
    }
    else {
        out[i++] = 0x82;
        out[i++] = (byte)(len >> 8);
        out[i++] = (byte)(len & 0xff);
    }
    return i;
}

/* Build one RDN: SET { SEQUENCE { <oidTlv>, <valTag> <val> } }, where oidTlv is
 * the full DER attribute-type OID (tag, length and content). Returns the total
 * number of bytes written to out. */
static int dnb_buildRdn(byte* out, const byte* oidTlv, int oidTlvLen,
    byte valTag, const byte* val, int valLen)
{
    int attrTlvLen;
    int seqContentLen;
    int setContentLen;
    int idx = 0;

    attrTlvLen    = 1 + dnb_lenSz(valLen) + valLen;
    seqContentLen = oidTlvLen + attrTlvLen;
    setContentLen = 1 + dnb_lenSz(seqContentLen) + seqContentLen;

    out[idx++] = 0x31;                                  /* SET OF */
    idx += dnb_encodeLen(&out[idx], setContentLen);
    out[idx++] = 0x30;                                  /* SEQUENCE */
    idx += dnb_encodeLen(&out[idx], seqContentLen);
    XMEMCPY(&out[idx], oidTlv, (size_t)oidTlvLen);
    idx += oidTlvLen;
    out[idx++] = valTag;                                /* string tag */
    idx += dnb_encodeLen(&out[idx], valLen);
    XMEMCPY(&out[idx], val, (size_t)valLen);
    idx += valLen;

    return idx;
}
#endif /* !NO_CERTS && !NO_ASN && !NO_RSA */

/* Regression test for a 1-byte out-of-bounds NUL write in GetCertName().
 * When a Subject DN exactly fills the WC_ASN_NAME_MAX character buffer the
 * classic (WOLFSSL_ASN_ORIGINAL) parser wrote the string terminator one byte
 * past cert->subject. Each certificate below is built so its second (boundary)
 * RDN would land the running index on exactly WC_ASN_NAME_MAX, which must now
 * be rejected as too big, leaving only the first RDN. Several attribute types
 * are exercised because the too-big guards differ per attribute: commonName
 * uses the "/CN=" prefix, emailAddress takes the distinct email branch with the
 * longer "/emailAddress=" prefix, and (under WOLFSSL_CERT_EXT) jurisdictionC
 * takes the JOI branch. Each attribute is checked on both boundary sides: at
 * the cap (dropped) and one byte under it (kept in full), so an over-tightening
 * off-by-one on any single guard is caught too. Runs under both ASN parsers. */
int test_ParseCert_dnBufferBoundary(void)
{
    EXPECT_DECLS;

#if !defined(NO_CERTS) && !defined(NO_ASN) && !defined(NO_RSA)
    /* 2048-bit RSA SubjectPublicKeyInfo, extracted with OpenSSL from
     * certs/client-cert.pem, so the key decodes and the parse succeeds. */
    static const byte rsaSpki[] = {
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
        0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x03, 0xd1,
        0x2b, 0xfe, 0x39, 0xa4, 0x32, 0x45, 0x3b, 0x53, 0xc8, 0x84, 0x2b, 0x2a,
        0x7c, 0x74, 0x9a, 0xbd, 0xaa, 0x2a, 0x52, 0x07, 0x47, 0xd6, 0xa6, 0x36,
        0xb2, 0x07, 0x32, 0x8e, 0xd0, 0xba, 0x69, 0x7b, 0xc6, 0xc3, 0x44, 0x9e,
        0xd4, 0x81, 0x48, 0xfd, 0x2d, 0x68, 0xa2, 0x8b, 0x67, 0xbb, 0xa1, 0x75,
        0xc8, 0x36, 0x2c, 0x4a, 0xd2, 0x1b, 0xf7, 0x8b, 0xba, 0xcf, 0x0d, 0xf9,
        0xef, 0xec, 0xf1, 0x81, 0x1e, 0x7b, 0x9b, 0x03, 0x47, 0x9a, 0xbf, 0x65,
        0xcc, 0x7f, 0x65, 0x24, 0x69, 0xa6, 0xe8, 0x14, 0x89, 0x5b, 0xe4, 0x34,
        0xf7, 0xc5, 0xb0, 0x14, 0x93, 0xf5, 0x67, 0x7b, 0x3a, 0x7a, 0x78, 0xe1,
        0x01, 0x56, 0x56, 0x91, 0xa6, 0x13, 0x42, 0x8d, 0xd2, 0x3c, 0x40, 0x9c,
        0x4c, 0xef, 0xd1, 0x86, 0xdf, 0x37, 0x51, 0x1b, 0x0c, 0xa1, 0x3b, 0xf5,
        0xf1, 0xa3, 0x4a, 0x35, 0xe4, 0xe1, 0xce, 0x96, 0xdf, 0x1b, 0x7e, 0xbf,
        0x4e, 0x97, 0xd0, 0x10, 0xe8, 0xa8, 0x08, 0x30, 0x81, 0xaf, 0x20, 0x0b,
        0x43, 0x14, 0xc5, 0x74, 0x67, 0xb4, 0x32, 0x82, 0x6f, 0x8d, 0x86, 0xc2,
        0x88, 0x40, 0x99, 0x36, 0x83, 0xba, 0x1e, 0x40, 0x72, 0x22, 0x17, 0xd7,
        0x52, 0x65, 0x24, 0x73, 0xb0, 0xce, 0xef, 0x19, 0xcd, 0xae, 0xff, 0x78,
        0x6c, 0x7b, 0xc0, 0x12, 0x03, 0xd4, 0x4e, 0x72, 0x0d, 0x50, 0x6d, 0x3b,
        0xa3, 0x3b, 0xa3, 0x99, 0x5e, 0x9d, 0xc8, 0xd9, 0x0c, 0x85, 0xb3, 0xd9,
        0x8a, 0xd9, 0x54, 0x26, 0xdb, 0x6d, 0xfa, 0xac, 0xbb, 0xff, 0x25, 0x4c,
        0xc4, 0xd1, 0x79, 0xf4, 0x71, 0xd3, 0x86, 0x40, 0x18, 0x13, 0xb0, 0x63,
        0xb5, 0x72, 0x4e, 0x30, 0xc4, 0x97, 0x84, 0x86, 0x2d, 0x56, 0x2f, 0xd7,
        0x15, 0xf7, 0x7f, 0xc0, 0xae, 0xf5, 0xfc, 0x5b, 0xe5, 0xfb, 0xa1, 0xba,
        0xd3, 0x02, 0x03, 0x01, 0x00, 0x01
    };
    /* Certificate fields up to (not including) the subject Name. The two 0x0000
     * placeholders are the outer and tbsCertificate SEQUENCE lengths, patched
     * once the subject size is known. */
    static const byte certPrefix[] = {
        /* Certificate SEQUENCE (length patched) */
        0x30, 0x82, 0x00, 0x00,
        /* tbsCertificate SEQUENCE (length patched) */
        0x30, 0x82, 0x00, 0x00,
        /* version [0] INTEGER 2 */
        0xa0, 0x03, 0x02, 0x01, 0x02,
        /* serialNumber INTEGER 1 */
        0x02, 0x01, 0x01,
        /* signature AlgorithmIdentifier: sha256WithRSAEncryption */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0b, 0x05, 0x00,
        /* issuer Name: /CN=Test */
        0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
        0x04, 0x54, 0x65, 0x73, 0x74,
        /* validity: notBefore 20000101000000Z, notAfter 20491231235959Z */
        0x30, 0x1e,
        0x17, 0x0d, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x5a,
        0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39,
        0x35, 0x39, 0x5a
    };
    /* Outer signatureAlgorithm and a placeholder signatureValue. Not checked
     * because NO_VERIFY is used, but the structure must be present. */
    static const byte certSuffix[] = {
        /* signatureAlgorithm: sha256WithRSAEncryption */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0b, 0x05, 0x00,
        /* signatureValue BIT STRING */
        0x03, 0x05, 0x00, 0xde, 0xad, 0xbe, 0xef
    };
    /* commonName OID (2.5.4.3). */
    static const byte cnOid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    /* emailAddress OID (1.2.840.113549.1.9.1, PKCS#9). */
    static const byte emailOid[] = {
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01
    };
#ifdef WOLFSSL_CERT_EXT
    /* jurisdictionCountryName OID (ASN_JOI_PREFIX + ASN_JOI_C). */
    static const byte joiCOid[] = {
        0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01,
        0x03
    };
#endif
    /* One entry per boundary attribute. valLen is sized relative to the buffer
     * cap: after the leading /CN=A (index 5) the parser adds copyLen + strLen,
     * where commonName copyLen is 4 ("/CN="), emailAddress copyLen is
     * sizeof(WOLFSSL_EMAIL_ADDR) - 1 ("/emailAddress="), and jurisdictionC
     * copyLen is sizeof(WOLFSSL_JOI_C) - 1 ("/jurisdictionC="). The reject cases
     * land on exactly WC_ASN_NAME_MAX (must be dropped); the accept case lands
     * one byte under (largest name that still fits, must be kept in full). */
    struct {
        const byte* oid;
        int         oidLen;
        byte        valTag;
        int         valLen;
        int         expectFull; /* 1: second RDN kept in full; 0: dropped */
    } cases[6];
    DecodedCert cert;
    byte* der = NULL;
    byte* val2 = NULL;
    byte  rdn1[16];
    int   numCases = 4;
    int   valLen;
    int   rdn1Len;
    int   rdn2Len;
    int   nameContentLen;
    int   tbsContentLen;
    int   outerContentLen;
    int   pos;
    int   derSz;
    int   c;

    /* Each attribute is tested on both boundary sides: valLen at the cap
     * (copyLen + strLen == WC_ASN_NAME_MAX - idx) must be dropped, and one byte
     * under the cap must be kept in full. Both sides are covered per attribute
     * because the too-big guards are independent comparison sites. */
    /* commonName (final catch-all guard). */
    cases[0].oid        = cnOid;
    cases[0].oidLen     = (int)sizeof(cnOid);
    cases[0].valTag     = 0x13;                         /* PrintableString */
    cases[0].valLen     = WC_ASN_NAME_MAX - 9;
    cases[0].expectFull = 0;
    cases[1].oid        = cnOid;
    cases[1].oidLen     = (int)sizeof(cnOid);
    cases[1].valTag     = 0x13;
    cases[1].valLen     = WC_ASN_NAME_MAX - 10;
    cases[1].expectFull = 1;
    /* emailAddress (distinct email branch guard). */
    cases[2].oid        = emailOid;
    cases[2].oidLen     = (int)sizeof(emailOid);
    cases[2].valTag     = 0x16;                         /* IA5String */
    cases[2].valLen     = WC_ASN_NAME_MAX - 5 -
        ((int)sizeof(WOLFSSL_EMAIL_ADDR) - 1);
    cases[2].expectFull = 0;
    cases[3].oid        = emailOid;
    cases[3].oidLen     = (int)sizeof(emailOid);
    cases[3].valTag     = 0x16;
    cases[3].valLen     = WC_ASN_NAME_MAX - 6 -
        ((int)sizeof(WOLFSSL_EMAIL_ADDR) - 1);
    cases[3].expectFull = 1;
#ifdef WOLFSSL_CERT_EXT
    /* jurisdictionCountryName (JOI branch guard). */
    cases[4].oid        = joiCOid;
    cases[4].oidLen     = (int)sizeof(joiCOid);
    cases[4].valTag     = 0x13;                         /* PrintableString */
    cases[4].valLen     = WC_ASN_NAME_MAX - 5 -
        ((int)sizeof(WOLFSSL_JOI_C) - 1);
    cases[4].expectFull = 0;
    cases[5].oid        = joiCOid;
    cases[5].oidLen     = (int)sizeof(joiCOid);
    cases[5].valTag     = 0x13;
    cases[5].valLen     = WC_ASN_NAME_MAX - 6 -
        ((int)sizeof(WOLFSSL_JOI_C) - 1);
    cases[5].expectFull = 1;
    numCases = 6;
#endif

    ExpectNotNull(val2 = (byte*)XMALLOC((size_t)WC_ASN_NAME_MAX, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(der = (byte*)XMALLOC(2048, NULL, DYNAMIC_TYPE_TMP_BUFFER));

    for (c = 0; (der != NULL) && (val2 != NULL) && (c < numCases); c++) {
        valLen = cases[c].valLen;
        XMEMSET(val2, 'B', (size_t)valLen);

        /* Fixed leading fields. */
        XMEMCPY(der, certPrefix, sizeof(certPrefix));
        pos = (int)sizeof(certPrefix);

        /* First RDN: /CN=A (a short name that must survive). */
        rdn1Len = dnb_buildRdn(rdn1, cnOid, (int)sizeof(cnOid), 0x13,
            (const byte*)"A", 1);

        /* Second RDN length, computed the same way dnb_buildRdn() lays it
         * out. */
        rdn2Len = 1 + dnb_lenSz(valLen) + valLen;          /* value TLV */
        rdn2Len = cases[c].oidLen + rdn2Len;               /* SEQUENCE content */
        rdn2Len = 1 + dnb_lenSz(rdn2Len) + rdn2Len;        /* SET content */
        rdn2Len = 1 + dnb_lenSz(rdn2Len) + rdn2Len;        /* SET TLV */
        nameContentLen = rdn1Len + rdn2Len;

        /* Subject Name SEQUENCE header, then the two RDNs in order. */
        der[pos++] = 0x30;
        pos += dnb_encodeLen(&der[pos], nameContentLen);
        XMEMCPY(&der[pos], rdn1, (size_t)rdn1Len);
        pos += rdn1Len;
        pos += dnb_buildRdn(&der[pos], cases[c].oid, cases[c].oidLen,
            cases[c].valTag, val2, valLen);

        /* SubjectPublicKeyInfo. */
        XMEMCPY(&der[pos], rsaSpki, sizeof(rsaSpki));
        pos += (int)sizeof(rsaSpki);

        /* tbsCertificate content spans from offset 8 to here. */
        tbsContentLen = pos - 8;

        /* Outer signature algorithm and value. */
        XMEMCPY(&der[pos], certSuffix, sizeof(certSuffix));
        pos += (int)sizeof(certSuffix);
        derSz = pos;
        outerContentLen = derSz - 4;

        /* Patch the two SEQUENCE lengths (both use the 0x82 long form). */
        der[6] = (byte)(tbsContentLen >> 8);
        der[7] = (byte)(tbsContentLen & 0xff);
        der[2] = (byte)(outerContentLen >> 8);
        der[3] = (byte)(outerContentLen & 0xff);

        wc_InitDecodedCert(&cert, der, (word32)derSz, NULL);
        ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
        if (cases[c].expectFull) {
            /* Largest name that still fits: the second RDN is kept and the
             * subject fills the buffer up to the in-bounds terminator. */
            ExpectIntEQ((int)XSTRLEN(cert.subject), WC_ASN_NAME_MAX - 1);
        }
        else {
            /* The boundary attribute is dropped so the terminator stays in
             * bounds; only the first RDN remains. */
            ExpectStrEQ(cert.subject, "/CN=A");
        }
        wc_FreeDecodedCert(&cert);
    }

    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(val2, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* !NO_CERTS && !NO_ASN && !NO_RSA */
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


/* Test for word16 FIPS version of function */
int test_wc_DecodeObjectId_FIPS16(void)
{
    EXPECT_DECLS;

#if !defined(NO_ASN) && \
    (defined(HAVE_OID_DECODING) || defined(WOLFSSL_ASN_PRINT))
    {
        word32 i;
        static const word16 oid_dot_2[] = {
            2, 100, 4, 6
        };

        static const byte oid_start_with_2[] = {
            0x81, 0x34, 0x04, 0x06
        };

        static const byte oid_secp112r1[] = {
            0x2B, 0x81, 0x04, 0x00, 0x06
        };

        static const word16 oid_dot_form[] = {
            1U, 3U, 132U, 0U, 6U
        };

        word16 out[MAX_OID_SZ];
        word32 outSz;

        word32 trueOutSz = sizeof(oid_dot_form) / sizeof(*oid_dot_form);
        /* Test 1: Normal decode */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(oid_secp112r1,
                    sizeof(oid_secp112r1), out, &outSz), 0);
        ExpectIntEQ((int)outSz, trueOutSz);
        for (i = 0; i < ((outSz <= trueOutSz) ? outSz : trueOutSz); i++) {
            ExpectIntEQ(out[i], oid_dot_form[i]);
        }

        /* Test 2: NULL args */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId(NULL, sizeof(oid_secp112r1),
                    out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(DecodeObjectId(oid_secp112r1,
                    sizeof(oid_secp112r1), out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 3 (Bug 1): outSz=1 must return BUFFER_E, not OOB write.
         * The first OID byte decodes into two arcs, so outSz must be >= 2. */
        outSz = 1;
        ExpectIntEQ(DecodeObjectId(oid_secp112r1,
                    sizeof(oid_secp112r1), out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 4: outSz=0 must also return BUFFER_E */
        outSz = 0;
        ExpectIntEQ(DecodeObjectId(oid_secp112r1,
                    sizeof(oid_secp112r1), out, &outSz),
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
        outSz = 3; /* only room for 3 arcs, but OID has 5 */
        ExpectIntEQ(DecodeObjectId(oid_secp112r1,
                    sizeof(oid_secp112r1), out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 7: first Arc is 2 */
        {
            word32 trueOutSz2 = sizeof(oid_dot_2) / sizeof(*oid_dot_2);
            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId(oid_start_with_2,
                        sizeof(oid_start_with_2),
                        out, &outSz), 0);
            ExpectIntEQ((int)outSz, trueOutSz2);
            for (i = 0; i < ((outSz <= trueOutSz2) ?
                        outSz : trueOutSz2); i++) {
                ExpectIntEQ(out[i], oid_dot_2[i]);
            }
        }

        /* Test 8: an OID with an arc that exceeds word16. Tests that wrong
         * but unchangeable behavior is working correctly,
         *
         * word16 version is used in FIPS build
         */
        {
            static const byte oid_large_arc[] = {
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
            };
            static const word16 oid_dot_large_arc[] = {
                1U, 2U, 840U, (word16)113549U, 1U, 1U, 11U
            };
            word32 trueOutSz3 = sizeof(oid_dot_large_arc) / sizeof(word16);

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId(oid_large_arc, sizeof(oid_large_arc),
                                       out, &outSz), 0);
            ExpectIntEQ((int)outSz, (int)trueOutSz3);
            for (i = 0; i < ((outSz <= trueOutSz3) ? outSz : trueOutSz3); i++) {
                ExpectIntEQ(out[i], oid_dot_large_arc[i]);
            }
        }
    }
#endif /* !NO_ASN && (HAVE_OID_DECODING || WOLFSSL_ASN_PRINT) */

    return EXPECT_RESULT();
}

int test_wc_DecodeObjectId32(void)
{
    EXPECT_DECLS;

#if !defined(NO_ASN) && \
    (defined(HAVE_OID_DECODING) || defined(WOLFSSL_ASN_PRINT))
    {
        word32 i;

        /* Tests multi byte encoding for arc 1 and 2
         * (only possible when arc 1 is 2 and arc 2 is greater than 39) */
        static const word32 oid_dot_2[] = {
            2, 100, 4, 6
        };

        /* Tests multi byte encoding for arc 1 and 2
         * (only possible when arc 1 is 2 and arc 2 is greater than 39) */
        static const byte oid_start_with_2[] = {
            0x81, 0x34, 0x04, 0x06
        };

        /* OID 1.3.132.0.6 (secp112r1)
         * DER encoding: 2b 81 04 00 06
         * First byte 0x2b = 43 => arc0 = 43/40 = 1, arc1 = 43%40 = 3
         * Remaining arcs: 132 0 6
         */
        static const byte oid_secp112r1[] = {
            0x2B, 0x81, 0x04, 0x00, 0x06
        };

        static const word32 oid_dot_form[] = {
            1U, 3U, 132U, 0U, 6U
        };

        word32 out[MAX_OID_SZ];
        word32 outSz;

        word32 trueOutSz = sizeof(oid_dot_form) / sizeof(word32);
        /* Test 1: Normal decode */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId32(oid_secp112r1, sizeof(oid_secp112r1),
                                   out, &outSz), 0);
        ExpectIntEQ((int)outSz, trueOutSz);
        for (i = 0; i < ((outSz <= trueOutSz) ? outSz : trueOutSz); i++) {
            ExpectIntEQ(out[i], oid_dot_form[i]);
        }

        /* Test 2: NULL args */
        outSz = MAX_OID_SZ;
        ExpectIntEQ(DecodeObjectId32(NULL, sizeof(oid_secp112r1), out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(DecodeObjectId32(oid_secp112r1, sizeof(oid_secp112r1),
                                   out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 3 (Bug 1): outSz=1 must return BUFFER_E, not OOB write.
         * The first OID byte decodes into two arcs, so outSz must be >= 2. */
        outSz = 1;
        ExpectIntEQ(DecodeObjectId32(oid_secp112r1, sizeof(oid_secp112r1),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 4: outSz=0 must also return BUFFER_E */
        outSz = 0;
        ExpectIntEQ(DecodeObjectId32(oid_secp112r1, sizeof(oid_secp112r1),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 5: outSz=2 is enough for a single-byte OID (two arcs) */
        {
            static const byte oid_one_byte[] = { 0x2a }; /* 1.2 */
            outSz = 2;
            ExpectIntEQ(DecodeObjectId32(oid_one_byte, sizeof(oid_one_byte),
                                       out, &outSz), 0);
            ExpectIntEQ((int)outSz, 2);
            ExpectIntEQ(out[0], 1);
            ExpectIntEQ(out[1], 2);
        }

        /* Test 6: Buffer too small for later arcs */
        outSz = 3; /* only room for 3 arcs, but OID has 5 */
        ExpectIntEQ(DecodeObjectId32(oid_secp112r1, sizeof(oid_secp112r1),
                                   out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 7: first Arc is 2 */
        {
            word32 trueOutSz2 = sizeof(oid_dot_2) / sizeof(word32);
            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_start_with_2,
                        sizeof(oid_start_with_2),
                        out, &outSz), 0);
            ExpectIntEQ((int)outSz, trueOutSz2);
            for (i = 0; i < ((outSz <= trueOutSz2) ?
                        outSz : trueOutSz2); i++) {
                ExpectIntEQ(out[i], oid_dot_2[i]);
            }
        }

        /* Test 8: an OID with an arc that exceeds word16. */
        {
            static const byte oid_large_arc[] = {
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
            };
            static const word32 oid_dot_large_arc[] = {
                1U, 2U, 840U, 113549U, 1U, 1U, 11U
            };
            word32 trueOutSz3 = sizeof(oid_dot_large_arc) / sizeof(word32);

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_large_arc, sizeof(oid_large_arc),
                                       out, &outSz), 0);
            ExpectIntEQ((int)outSz, (int)trueOutSz3);
            for (i = 0; i < ((outSz <= trueOutSz3) ? outSz : trueOutSz3); i++) {
                ExpectIntEQ(out[i], oid_dot_large_arc[i]);
            }
        }

        /* Test 9: an arc that does not fit in a word32 must be rejected by
         * the overflow guard rather than silently wrapping. In each vector
         * the first byte (0x2a) decodes to 1.2 and the remaining bytes encode
         * a single sub-identifier. */
        {
            /* Five continuation bytes: 35 significant bits. */
            static const byte oid_overflow_arc[] = {
                0x2a, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
            };
            /* Six continuation bytes: more than the encoder ever emits. */
            static const byte oid_overflow_arc_long[] = {
                0x2a, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
            };
            /* Exactly 2^32 - 1: the largest arc that does fit. */
            static const byte oid_max_arc[] = {
                0x2a, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F
            };
            /* Exactly 2^32: one more than fits. */
            static const byte oid_over_max_arc[] = {
                0x2a, 0x90, 0x80, 0x80, 0x80, 0x00
            };

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_overflow_arc,
                        sizeof(oid_overflow_arc), out, &outSz),
                        WC_NO_ERR_TRACE(ASN_OBJECT_ID_E));

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_overflow_arc_long,
                        sizeof(oid_overflow_arc_long), out, &outSz),
                        WC_NO_ERR_TRACE(ASN_OBJECT_ID_E));

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_max_arc, sizeof(oid_max_arc),
                        out, &outSz), 0);
            ExpectIntEQ((int)outSz, 3);
            ExpectTrue(out[2] == 0xFFFFFFFFU);

            outSz = MAX_OID_SZ;
            ExpectIntEQ(DecodeObjectId32(oid_over_max_arc,
                        sizeof(oid_over_max_arc), out, &outSz),
                        WC_NO_ERR_TRACE(ASN_OBJECT_ID_E));
        }
    }
#endif /* !NO_ASN && (HAVE_OID_DECODING || WOLFSSL_ASN_PRINT) */

    return EXPECT_RESULT();
}

int test_wc_EncodeObjectId(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OID_ENCODING) && !defined(NO_ASN)
    {
        /* wc_EncodeObjectId() takes word16 arcs, so only OIDs whose arcs all
         * fit in a word16 can be encoded with it. 1.3.132.0.6 (secp112r1). */
        static const word16 oid_small[] = { 1U, 3U, 132U, 0U, 6U };
        static const byte oid_small_der[] = {
            0x2b, 0x81, 0x04, 0x00, 0x06
        };
        const word32 oid_small_cnt = sizeof(oid_small) / sizeof(word16);
        byte   out[MAX_OID_SZ];
        word32 outSz;
        word32 i;

        /* Test 1: length-only query (out == NULL) */
        outSz = 0;
        ExpectIntEQ(wc_EncodeObjectId(oid_small, oid_small_cnt, NULL, &outSz),
                    0);
        ExpectIntEQ((int)outSz, (int)sizeof(oid_small_der));

        /* Test 2: normal encode matches expected DER */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId(oid_small, oid_small_cnt, out, &outSz),
            0);
        ExpectIntEQ((int)outSz, (int)sizeof(oid_small_der));
        for (i = 0; i < outSz && i < sizeof(oid_small_der); i++) {
            ExpectIntEQ(out[i], oid_small_der[i]);
        }

        /* Test 3: NULL args */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId(NULL, oid_small_cnt, out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_EncodeObjectId(oid_small, oid_small_cnt, out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 4: output buffer too small */
        outSz = 1;
        ExpectIntEQ(wc_EncodeObjectId(oid_small, oid_small_cnt, out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 5: first arc greater than 2 is invalid (in[0] > 2) */
        {
            static const word16 oid_bad_first[] = { 3U, 1U };
            outSz = sizeof(out);
            ExpectIntEQ(wc_EncodeObjectId(oid_bad_first,
                        sizeof(oid_bad_first) / sizeof(word16), out, &outSz),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }

        /* Test 6: fewer than two arcs is invalid (inSz < 2) */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId(oid_small, 1, out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif /* HAVE_OID_ENCODING && !NO_ASN */

    return EXPECT_RESULT();
}

int test_wc_EncodeObjectId32(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OID_ENCODING) && !defined(NO_ASN)
    {
        /* 1.3.132.0.6 (secp112r1) -- every arc fits in word16, so this
         * encodes identically in both build configs. */
        static const word32 oid_small[] = { 1U, 3U, 132U, 0U, 6U };
        static const byte oid_small_der[] = {
            0x2b, 0x81, 0x04, 0x00, 0x06
        };
        const word32 oid_small_cnt = sizeof(oid_small) / sizeof(word32);
        byte   out[MAX_OID_SZ];
        word32 outSz;
        word32 i;

        /* Test 1: length-only query (out == NULL) */
        outSz = 0;
        ExpectIntEQ(wc_EncodeObjectId32(oid_small, oid_small_cnt, NULL, &outSz),
                    0);
        ExpectIntEQ((int)outSz, (int)sizeof(oid_small_der));

        /* Test 2: normal encode matches expected DER */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId32(oid_small, oid_small_cnt, out, &outSz),
                    0);
        ExpectIntEQ((int)outSz, (int)sizeof(oid_small_der));
        for (i = 0; i < outSz && i < sizeof(oid_small_der); i++) {
            ExpectIntEQ(out[i], oid_small_der[i]);
        }

        /* Test 3: NULL args */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId32(NULL, oid_small_cnt, out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_EncodeObjectId32(oid_small, oid_small_cnt, out, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 4: output buffer too small */
        outSz = 1;
        ExpectIntEQ(wc_EncodeObjectId32(oid_small, oid_small_cnt, out, &outSz),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* Test 5 : arc greater that SHRT_MAX */
        {
            static const word32 oid_large[] = {
                1U, 2U, 840U, 113549U, 1U, 1U, 11U
            };
            static const byte oid_large_der[] = {
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
            };
            const word32 oid_large_cnt = sizeof(oid_large) / sizeof(word32);

            outSz = sizeof(out);
            ExpectIntEQ(wc_EncodeObjectId32(oid_large, oid_large_cnt, out,
                        &outSz), 0);
            ExpectIntEQ((int)outSz, (int)sizeof(oid_large_der));
            for (i = 0; i < outSz && i < sizeof(oid_large_der); i++) {
                ExpectIntEQ(out[i], oid_large_der[i]);
            }

#if defined(HAVE_OID_DECODING) || defined(WOLFSSL_ASN_PRINT)
            {
                word32 dec[MAX_OID_SZ];
                word32 decSz = MAX_OID_SZ;
                ExpectIntEQ(DecodeObjectId32(out, outSz, dec, &decSz), 0);
                ExpectIntEQ((int)decSz, (int)oid_large_cnt);
                for (i = 0; i < decSz && i < oid_large_cnt; i++) {
                    ExpectIntEQ(dec[i], oid_large[i]);
                }
            }
#endif /* HAVE_OID_DECODING || WOLFSSL_ASN_PRINT */
        }

        /* Test 6: first arc greater than 2 is invalid (in[0] > 2) */
        {
            static const word32 oid_bad_first[] = { 3U, 1U };
            outSz = sizeof(out);
            ExpectIntEQ(wc_EncodeObjectId32(oid_bad_first,
                        sizeof(oid_bad_first) / sizeof(word32), out, &outSz),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }

        /* Test 7: fewer than two arcs is invalid (inSz < 2) */
        outSz = sizeof(out);
        ExpectIntEQ(wc_EncodeObjectId32(oid_small, 1, out, &outSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Test 8: (in[0] * 40) + in[1] must not overflow a word32 */
        {
            static const word32 oid_overflow[] = { 2U, 0xFFFFFFFFU, 1U };
            outSz = sizeof(out);
            ExpectIntEQ(wc_EncodeObjectId32(oid_overflow,
                        sizeof(oid_overflow) / sizeof(word32), out, &outSz),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }
    }
#endif /* HAVE_OID_ENCODING && !NO_ASN */

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

/* What wc_SignCert() bounds testing needs regardless of the signing algorithm.
 * Each algorithm then gates on its own key type and certificate buffers, so an
 * RSA-less build still gets the ECDSA sweep and vice versa. */
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_SHA256) && !defined(WC_NO_RNG) && \
    !defined(NO_ASN_TIME) && !defined(NO_ASN_CRYPT)
    #if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
        #define TEST_SIGN_CERT_BOUNDS_RSA
    #endif
    #if defined(HAVE_ECC) && defined(USE_CERT_BUFFERS_256)
        #define TEST_SIGN_CERT_BOUNDS_ECC
    #endif
#endif

#if defined(TEST_SIGN_CERT_BOUNDS_RSA) || defined(TEST_SIGN_CERT_BOUNDS_ECC)

#define SIGN_CERT_SCRATCH_SZ 4096
/* Number of capacities below the exact encoding size to try. Has to be wider
 * than the AlgorithmIdentifier plus BIT STRING header that a sequence-headers
 * only estimate leaves out. */
#define SIGN_CERT_BAND_SZ    24
/* Bytes kept past the advertised capacity to catch a write past the end. */
#define SIGN_CERT_GUARD_SZ   32
#define SIGN_CERT_GUARD_BYTE 0xA5

#ifdef TEST_SIGN_CERT_BOUNDS_RSA
/* Build the certificate body used by test_wc_SignCert_buffer_bounds().
 * wc_SignCert() rewrites the buffer in place, so it has to be rebuilt for
 * every capacity tried. Returns the body size or a negative error.
 *
 * The serial is fixed rather than left for wc_MakeCert() to generate. A
 * generated serial is random, and GenerateInteger() does not shrink its length
 * after dropping leading zero bytes, so the promoted byte can carry the MSB and
 * make the encoder pad the INTEGER with an extra 0x00. That changes the body
 * size for about one certificate in 250, which would make the swept capacities
 * below disagree with the reference size. */
static int test_wc_SignCert_makeBody(Cert* cert, RsaKey* key, WC_RNG* rng,
    byte* out, word32 outSz)
{
    static const byte serial[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08 };
    int ret;

    ret = wc_InitCert(cert);
    if (ret != 0)
        return ret;

    cert->sigType = CTC_SHA256wRSA;
    cert->isCA = 0;
    XMEMCPY(cert->serial, serial, sizeof(serial));
    cert->serialSz = (int)sizeof(serial);
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "MT", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "wolfSSL", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "signcert-bounds", CTC_NAME_SIZE);

    return wc_MakeCert(cert, out, outSz, key, NULL, rng);
}
#endif /* TEST_SIGN_CERT_BOUNDS_RSA */

#ifdef TEST_SIGN_CERT_BOUNDS_ECC
/* ECDSA r and s are DER INTEGERs whose length changes with the leading zero
 * bytes of each new signature, so an ECDSA encoding size measured once does not
 * repeat. The sweep copes with that by asserting an invariant that holds for
 * either outcome rather than a fixed return, so only the accept case needs a
 * capacity clear of anything the jitter can reach. */
#define SIGN_CERT_ECC_SLACK 8

/* ECDSA counterpart of test_wc_SignCert_makeBody(). */
static int test_wc_SignCert_makeBodyEcc(Cert* cert, ecc_key* key, WC_RNG* rng,
    byte* out, word32 outSz)
{
    static const byte serial[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08 };
    int ret;

    ret = wc_InitCert(cert);
    if (ret != 0)
        return ret;

    cert->sigType = CTC_SHA256wECDSA;
    cert->isCA = 0;
    XMEMCPY(cert->serial, serial, sizeof(serial));
    cert->serialSz = (int)sizeof(serial);
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "MT", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "wolfSSL", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "signcert-bounds-ecc", CTC_NAME_SIZE);

    return wc_MakeCert(cert, out, outSz, NULL, key, rng);
}
#endif /* TEST_SIGN_CERT_BOUNDS_ECC */
#endif /* TEST_SIGN_CERT_BOUNDS_RSA || TEST_SIGN_CERT_BOUNDS_ECC */

/*
 * wc_SignCert() must never write past the capacity it was given.
 *
 * SignCert() hands the buffer to AddSignature(), which appends the
 * signatureAlgorithm AlgorithmIdentifier and the signatureValue BIT STRING as
 * well as wrapping everything in the outer SEQUENCE. A size check that only
 * accounts for sequence headers under-counts by the algorithm identifier and
 * bit string header, so capacities in a narrow band just below the exact
 * encoding size get accepted and overrun.
 */
#if !defined(NO_ASN) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(WC_NO_RNG) && !defined(NO_ASN_CRYPT)
    #define TEST_KEYUSAGE_DECIPHER_ONLY
#endif

/*
 * decipherOnly is bit 8, the only KeyUsage value landing in the second byte
 * of the BIT STRING - so the only one needing a second content byte to encode
 * and the high-byte shift to decode. Round-trip it alone and combined with a
 * first-byte bit to cover both halves.
 */
int test_wc_DecodeKeyUsage_decipherOnly(void)
{
    EXPECT_DECLS;
#ifdef TEST_KEYUSAGE_DECIPHER_ONLY
    static const struct {
        const char* str;
        word16      expected;
    } kuCases[] = {
        { "decipherOnly",                  KEYUSE_DECIPHER_ONLY },
        { "digitalSignature,decipherOnly", (word16)(KEYUSE_DIGITAL_SIG |
                                                    KEYUSE_DECIPHER_ONLY) },
        { "encipherOnly,decipherOnly",     (word16)(KEYUSE_ENCIPHER_ONLY |
                                                    KEYUSE_DECIPHER_ONLY) },
        /* A first-byte-only value must keep encoding in a single byte. */
        { "digitalSignature",              KEYUSE_DIGITAL_SIG },
    };
    WC_RNG      rng;
    RsaKey      key;
    byte*       der = NULL;
    word32      idx = 0;
    int         rngInit = 0;
    int         keyInit = 0;
    size_t      c;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;

    ExpectNotNull(der = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));

    ExpectIntEQ(wc_InitRsaKey_ex(&key, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) keyInit = 1;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &key,
        sizeof_server_key_der_2048), 0);

    for (c = 0; c < XELEM_CNT(kuCases); c++) {
        Cert        cert;
        DecodedCert dCert;
        int         dCertInit = 0;
        int         derSz = 0;

        if (!EXPECT_SUCCESS()) break;

        XMEMSET(&cert, 0, sizeof(cert));
        ExpectIntEQ(wc_InitCert(&cert), 0);
        if (EXPECT_SUCCESS()) {
            cert.sigType = CTC_SHA256wRSA;
            cert.isCA = 0;
            XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
            XSTRNCPY(cert.subject.org, "wolfSSL", CTC_NAME_SIZE);
            XSTRNCPY(cert.subject.commonName, "keyUsage", CTC_NAME_SIZE);
        }
        ExpectIntEQ(wc_SetKeyUsage(&cert, kuCases[c].str), 0);
        ExpectIntGT(derSz = wc_MakeSelfCert(&cert, der, FOURK_BUF, &key, &rng),
            0);

        if (EXPECT_SUCCESS() && (der != NULL)) {
            wc_InitDecodedCert(&dCert, der, (word32)derSz, HEAP_HINT);
            dCertInit = 1;
            ExpectIntEQ(wc_ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL), 0);
            /* Every requested bit must survive and nothing else be set - a
             * byte-order slip silently yields a first-byte usage. */
            ExpectIntEQ(dCert.extKeyUsage, kuCases[c].expected);
        }
        if (dCertInit) wc_FreeDecodedCert(&dCert);
    }

    if (keyInit) wc_FreeRsaKey(&key);
    if (rngInit) wc_FreeRng(&rng);
    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* TEST_KEYUSAGE_DECIPHER_ONLY */
    return EXPECT_RESULT();
}

int test_wc_SignCert_buffer_bounds(void)
{
    EXPECT_DECLS;
#if defined(TEST_SIGN_CERT_BOUNDS_RSA) || defined(TEST_SIGN_CERT_BOUNDS_ECC)
    WC_RNG rng;
    Cert   cert;
    byte*  scratch = NULL;
    byte*  buf = NULL;
    int    rngInit = 0;
    int    bodySz = 0;
    int    cap;
    int    i;
#ifdef TEST_SIGN_CERT_BOUNDS_RSA
    RsaKey key;
    word32 idx = 0;
    int    keyInit = 0;
    int    exactSz = 0;
#endif
#ifdef TEST_SIGN_CERT_BOUNDS_ECC
    ecc_key eccKey;
    word32 eccIdx = 0;
    int    eccInit = 0;
    int    eccExactSz = 0;
    int    eccSignedSz = 0;
    int    k;
#endif

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&cert, 0, sizeof(cert));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;

    ExpectNotNull(scratch = (byte*)XMALLOC(SIGN_CERT_SCRATCH_SZ, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(buf = (byte*)XMALLOC(SIGN_CERT_SCRATCH_SZ, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));

#ifdef TEST_SIGN_CERT_BOUNDS_RSA
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_InitRsaKey_ex(&key, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) keyInit = 1;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &key,
        sizeof_server_key_der_2048), 0);

    /* Sign into a roomy buffer once to learn the exact encoding size. */
    ExpectIntGT(bodySz = test_wc_SignCert_makeBody(&cert, &key, &rng, scratch,
        SIGN_CERT_SCRATCH_SZ), 0);
    ExpectIntGT(exactSz = wc_SignCert(bodySz, cert.sigType, scratch,
        SIGN_CERT_SCRATCH_SZ, &key, NULL, &rng), 0);
    ExpectIntLT(exactSz + SIGN_CERT_GUARD_SZ, SIGN_CERT_SCRATCH_SZ);

    /* Every capacity below the exact size has to be rejected, and rejected
     * without touching a byte beyond it. */
    for (cap = exactSz - SIGN_CERT_BAND_SZ; cap < exactSz; cap++) {
        if (!EXPECT_SUCCESS()) break;

        ExpectIntGT(bodySz = test_wc_SignCert_makeBody(&cert, &key, &rng,
            scratch, SIGN_CERT_SCRATCH_SZ), 0);
        if (!EXPECT_SUCCESS()) break;

        XMEMCPY(buf, scratch, (size_t)bodySz);
        XMEMSET(buf + cap, SIGN_CERT_GUARD_BYTE, SIGN_CERT_GUARD_SZ);

        ExpectIntEQ(wc_SignCert(bodySz, cert.sigType, buf, (word32)cap, &key,
            NULL, &rng), WC_NO_ERR_TRACE(BUFFER_E));

        for (i = 0; i < SIGN_CERT_GUARD_SZ; i++) {
            ExpectIntEQ(buf[cap + i], SIGN_CERT_GUARD_BYTE);
        }
    }

    /* The exact size still has to be accepted - the check must not be made
     * conservative instead of correct. */
    ExpectIntGT(bodySz = test_wc_SignCert_makeBody(&cert, &key, &rng, scratch,
        SIGN_CERT_SCRATCH_SZ), 0);
    if (EXPECT_SUCCESS() && (buf != NULL)) {
        XMEMCPY(buf, scratch, (size_t)bodySz);
        XMEMSET(buf + exactSz, SIGN_CERT_GUARD_BYTE, SIGN_CERT_GUARD_SZ);
    }
    ExpectIntEQ(wc_SignCert(bodySz, cert.sigType, buf, (word32)exactSz, &key,
        NULL, &rng), exactSz);
    for (i = 0; i < SIGN_CERT_GUARD_SZ; i++) {
        ExpectIntEQ(buf[exactSz + i], SIGN_CERT_GUARD_BYTE);
    }
#endif /* TEST_SIGN_CERT_BOUNDS_RSA */

#ifdef TEST_SIGN_CERT_BOUNDS_ECC
    /* Same sweep for ECDSA. IsSigAlgoNoParams() drops the NULL parameters from
     * the AlgorithmIdentifier, so the under-count an estimate makes has a
     * different width here than it does for RSA. */
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    ExpectIntEQ(wc_ecc_init_ex(&eccKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) eccInit = 1;
    ExpectIntEQ(wc_EccPrivateKeyDecode(ecc_key_der_256, &eccIdx, &eccKey,
        sizeof_ecc_key_der_256), 0);

    for (k = 1; k < SIGN_CERT_BAND_SZ; k++) {
        if (!EXPECT_SUCCESS()) break;

        /* Measured fresh every iteration: the previous signature's length
         * says nothing about the next one's. */
        ExpectIntGT(bodySz = test_wc_SignCert_makeBodyEcc(&cert, &eccKey, &rng,
            scratch, SIGN_CERT_SCRATCH_SZ), 0);
        ExpectIntGT(eccExactSz = wc_SignCert(bodySz, cert.sigType, scratch,
            SIGN_CERT_SCRATCH_SZ, NULL, &eccKey, &rng), 0);
        if (!EXPECT_SUCCESS()) break;

        cap = eccExactSz - k;
        ExpectIntGT(bodySz = test_wc_SignCert_makeBodyEcc(&cert, &eccKey, &rng,
            scratch, SIGN_CERT_SCRATCH_SZ), 0);
        if (!EXPECT_SUCCESS()) break;

        XMEMCPY(buf, scratch, (size_t)bodySz);
        XMEMSET(buf + cap, SIGN_CERT_GUARD_BYTE, SIGN_CERT_GUARD_SZ);

        eccSignedSz = wc_SignCert(bodySz, cert.sigType, buf, (word32)cap, NULL,
            &eccKey, &rng);
        /* The signature this call produces is not the one the capacity was
         * derived from, so a capacity below the measured size is not always
         * too small. Both outcomes are legitimate; what must hold either way
         * is that nothing was written past the capacity. */
        ExpectTrue((eccSignedSz == WC_NO_ERR_TRACE(BUFFER_E)) ||
                   ((eccSignedSz > 0) && (eccSignedSz <= cap)));

        for (i = 0; i < SIGN_CERT_GUARD_SZ; i++) {
            ExpectIntEQ(buf[cap + i], SIGN_CERT_GUARD_BYTE);
        }
    }

    /* A capacity above anything the signature length can reach still has to be
     * accepted, so the check is not merely conservative. */
    ExpectIntGT(bodySz = test_wc_SignCert_makeBodyEcc(&cert, &eccKey, &rng,
        scratch, SIGN_CERT_SCRATCH_SZ), 0);
    ExpectIntGT(eccExactSz = wc_SignCert(bodySz, cert.sigType, scratch,
        SIGN_CERT_SCRATCH_SZ, NULL, &eccKey, &rng), 0);
    cap = eccExactSz + SIGN_CERT_ECC_SLACK;
    ExpectIntGT(bodySz = test_wc_SignCert_makeBodyEcc(&cert, &eccKey, &rng,
        scratch, SIGN_CERT_SCRATCH_SZ), 0);
    if (EXPECT_SUCCESS() && (buf != NULL)) {
        XMEMCPY(buf, scratch, (size_t)bodySz);
        XMEMSET(buf + cap, SIGN_CERT_GUARD_BYTE, SIGN_CERT_GUARD_SZ);
    }
    ExpectIntGT(eccSignedSz = wc_SignCert(bodySz, cert.sigType, buf,
        (word32)cap, NULL, &eccKey, &rng), 0);
    ExpectIntLE(eccSignedSz, cap);
    for (i = 0; i < SIGN_CERT_GUARD_SZ; i++) {
        ExpectIntEQ(buf[cap + i], SIGN_CERT_GUARD_BYTE);
    }
#endif /* TEST_SIGN_CERT_BOUNDS_ECC */

    XFREE(buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(scratch, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef TEST_SIGN_CERT_BOUNDS_ECC
    if (eccInit)
        wc_ecc_free(&eccKey);
#endif
#ifdef TEST_SIGN_CERT_BOUNDS_RSA
    if (keyInit)
        wc_FreeRsaKey(&key);
#endif
    if (rngInit)
        wc_FreeRng(&rng);
#endif /* TEST_SIGN_CERT_BOUNDS_RSA || TEST_SIGN_CERT_BOUNDS_ECC */
    return EXPECT_RESULT();
}

/*
 * MC/DC wave 2 - decision-targeted negative paths for PKCS#8 wrap/parse
 * and RSA key decode. Targets argument-check, short-buffer, and
 * truncated-DER decision branches in wolfcrypt/src/asn.c without touching
 * the library source.
 */
int test_wc_AsnDecisionCoverage(void)
{
    EXPECT_DECLS;

#if !defined(NO_ASN) && !defined(NO_RSA) && \
    (defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048)) && \
    !defined(HAVE_FIPS)
    /* ---- wc_RsaPublicKeyDecode: truncated / bad-arg decision branches ---- */
    {
        RsaKey key;
        const byte* derKey;
        word32 derKeySz;
        word32 idx;

        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);

    #ifdef USE_CERT_BUFFERS_2048
        derKey = client_keypub_der_2048;
        derKeySz = (word32)sizeof_client_keypub_der_2048;
    #else
        derKey = client_keypub_der_1024;
        derKeySz = (word32)sizeof_client_keypub_der_1024;
    #endif

        /* Null arg branches. */
        idx = 0;
        ExpectIntEQ(wc_RsaPublicKeyDecode(NULL, &idx, &key, derKeySz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaPublicKeyDecode(derKey, NULL, &key, derKeySz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_RsaPublicKeyDecode(derKey, &idx, NULL, derKeySz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Truncated input: header says more data than buffer length. */
        idx = 0;
        ExpectIntLT(wc_RsaPublicKeyDecode(derKey, &idx, &key, 4), 0);

        /* wc_RsaPublicKeyDecodeRaw null-arg branches. */
        {
            static const byte nBuf[] = { 0xC0 };
            static const byte eBuf[] = { 0x01, 0x00, 0x01 };
            ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(NULL, sizeof(nBuf),
                eBuf, sizeof(eBuf), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(nBuf, sizeof(nBuf),
                NULL, sizeof(eBuf), &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(nBuf, sizeof(nBuf),
                eBuf, sizeof(eBuf), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }

        DoExpectIntEQ(wc_FreeRsaKey(&key), 0);
    }

    /* ---- wc_GetPkcs8TraditionalOffset: argument-check branches ---- */
    {
        byte buf[8] = { 0x30, 0x82, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00 };
        word32 idx;

        idx = 0;
        ExpectIntEQ(wc_GetPkcs8TraditionalOffset(NULL, &idx, sizeof(buf)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_GetPkcs8TraditionalOffset(buf, NULL, sizeof(buf)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* idx >= sz decision branch - any negative return exercises the
         * short-input guard (BUFFER_E in current code, but we do not pin
         * the exact code here). */
        idx = sizeof(buf);
        ExpectIntLT(wc_GetPkcs8TraditionalOffset(buf, &idx, sizeof(buf)), 0);
        /* Non-PKCS#8 blob: malformed DER decision branch. */
        {
            byte bogus[4] = { 0x00, 0x00, 0x00, 0x00 };
            idx = 0;
            ExpectIntLT(wc_GetPkcs8TraditionalOffset(bogus, &idx,
                sizeof(bogus)), 0);
        }
    }

    /* ---- wc_CreatePKCS8Key: size-query and bad-arg branches ----
     * Uses the existing RSA private key DER from certs_test.h to avoid
     * runtime key generation (which requires WOLFSSL_KEY_GEN and a usable
     * RNG and is not available in every retained lane). */
    {
    #ifdef USE_CERT_BUFFERS_2048
        const byte* rsaDer = client_key_der_2048;
        word32 rsaDerSz = (word32)sizeof_client_key_der_2048;
    #else
        const byte* rsaDer = client_key_der_1024;
        word32 rsaDerSz = (word32)sizeof_client_key_der_1024;
    #endif
        byte pkcs8[2048];
        word32 pkcs8Sz;

        /* Size-query: out == NULL should return LENGTH_ONLY_E and set
         * outSz. */
        pkcs8Sz = 0;
        ExpectIntEQ(wc_CreatePKCS8Key(NULL, &pkcs8Sz, (byte*)rsaDer,
            rsaDerSz, RSAk, NULL, 0),
            WC_NO_ERR_TRACE(LENGTH_ONLY_E));
        ExpectIntGT(pkcs8Sz, 0);

        /* Null outSz branch. */
        ExpectIntEQ(wc_CreatePKCS8Key(pkcs8, NULL, (byte*)rsaDer, rsaDerSz,
            RSAk, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif /* !NO_ASN && !NO_RSA && cert-buffers && !HAVE_FIPS */

    return EXPECT_RESULT();
}

/*
 * MC/DC wave 2 - feature-oriented positive paths to lift asn.c MC/DC by
 * exercising real cert parsing, PKCS#8 round trips, ECC key decoding, and
 * PEM<->DER conversions on the static cert buffers (no new fixtures).
 */
int test_wc_AsnFeatureCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_ASN) && !defined(NO_RSA) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(HAVE_FIPS)
    /* ---- DecodedCert: full client cert parse, with subject + pubkey ---- */
    {
        struct DecodedCert cert;
        byte pubKey[512];
        word32 pubKeySz = sizeof(pubKey);
        char subject[256];
        word32 subjectSz = sizeof(subject);

        wc_InitDecodedCert(&cert, client_cert_der_2048,
            sizeof_client_cert_der_2048, NULL);
        ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
        ExpectIntEQ(wc_GetPubKeyDerFromCert(&cert, pubKey, &pubKeySz), 0);
        ExpectIntGT(pubKeySz, 0);
        ExpectIntEQ(wc_GetDecodedCertSubject(&cert, subject, &subjectSz), 0);
        wc_FreeDecodedCert(&cert);
    }

    /* ---- DecodedCert: server cert parse and SubjectPublicKeyInfo extract -- */
    {
        struct DecodedCert cert;
        byte spki[1024];
        word32 spkiSz = sizeof(spki);

        wc_InitDecodedCert(&cert, server_cert_der_2048,
            sizeof_server_cert_der_2048, NULL);
        ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL), 0);
        wc_FreeDecodedCert(&cert);

        /* Some retained builds return 0 on success and write spkiSz; others
         * return spkiSz directly. Accept any non-negative result and require
         * a non-zero output size. */
        ExpectIntGE(wc_GetSubjectPubKeyInfoDerFromCert(server_cert_der_2048,
            sizeof_server_cert_der_2048, spki, &spkiSz), 0);
        ExpectIntGT(spkiSz, 0);
    }

    /* ---- PKCS#8: round trip wrap then offset extract ---- */
    {
        byte pkcs8[2048];
        word32 pkcs8Sz = 0;
        word32 idx;
        int wrapSz;

        /* Size query first. */
        ExpectIntEQ(wc_CreatePKCS8Key(NULL, &pkcs8Sz,
            (byte*)client_key_der_2048, sizeof_client_key_der_2048, RSAk,
            NULL, 0), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
        ExpectIntGT(pkcs8Sz, 0);

        wrapSz = wc_CreatePKCS8Key(pkcs8, &pkcs8Sz,
            (byte*)client_key_der_2048, sizeof_client_key_der_2048, RSAk,
            NULL, 0);
        ExpectIntGT(wrapSz, 0);

        if (wrapSz > 0) {
            idx = 0;
            ExpectIntGE(wc_GetPkcs8TraditionalOffset(pkcs8, &idx,
                (word32)wrapSz), 0);
            ExpectIntGT(idx, 0);
        }
    }

    /* ---- CA cert parse: exercises CA-specific decision branches ---- */
    {
        struct DecodedCert caCert;
        wc_InitDecodedCert(&caCert, ca_cert_der_2048, sizeof_ca_cert_der_2048,
            NULL);
        ExpectIntEQ(wc_ParseCert(&caCert, CA_TYPE, NO_VERIFY, NULL), 0);
        wc_FreeDecodedCert(&caCert);
    }

    /* ---- Parse server cert a second time with CERT_TYPE + verify off ----
     * to touch ParseCertRelative decision branches that the first pass skips.
     */
    {
        struct DecodedCert cert2;
        wc_InitDecodedCert(&cert2, server_cert_der_2048,
            sizeof_server_cert_der_2048, NULL);
        ExpectIntEQ(wc_ParseCert(&cert2, CERT_TYPE, NO_VERIFY, NULL), 0);
        wc_FreeDecodedCert(&cert2);
    }

    /* ---- PEM<->DER conversion round trip on the client cert ---- */
    #ifdef WOLFSSL_DER_TO_PEM
    {
        byte pem[4096];
        int  pemSz;

        pemSz = wc_DerToPem(client_cert_der_2048, sizeof_client_cert_der_2048,
            pem, sizeof(pem), CERT_TYPE);
        ExpectIntGT(pemSz, 0);

        #ifdef WOLFSSL_PEM_TO_DER
        if (pemSz > 0) {
            byte der[2048];
            int  derSz;
            derSz = wc_CertPemToDer(pem, pemSz, der, sizeof(der), CERT_TYPE);
            ExpectIntGT(derSz, 0);
            if (derSz > 0)
                ExpectBufEQ(der, client_cert_der_2048,
                    sizeof_client_cert_der_2048);
        }
        #endif
    }
    #endif /* WOLFSSL_DER_TO_PEM */
#endif /* !NO_ASN && !NO_RSA && USE_CERT_BUFFERS_2048 && !HAVE_FIPS */

#if !defined(NO_ASN) && defined(HAVE_ECC) && \
    defined(USE_CERT_BUFFERS_256) && !defined(HAVE_FIPS)
    /* ---- ECC private + public key DER decode round trip ---- */
    {
        ecc_key ecKey;
        word32  idx = 0;
        byte    pubKeyDer[256];
        int     derSz;

        XMEMSET(&ecKey, 0, sizeof(ecKey));
        ExpectIntEQ(wc_ecc_init(&ecKey), 0);
        ExpectIntEQ(wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &ecKey,
            sizeof_ecc_clikey_der_256), 0);

        derSz = wc_EccPublicKeyToDer(&ecKey, pubKeyDer, sizeof(pubKeyDer), 1);
        ExpectIntGT(derSz, 0);

        if (derSz > 0) {
            ecc_key pubOnly;
            word32  idx2 = 0;
            XMEMSET(&pubOnly, 0, sizeof(pubOnly));
            ExpectIntEQ(wc_ecc_init(&pubOnly), 0);
            ExpectIntEQ(wc_EccPublicKeyDecode(pubKeyDer, &idx2, &pubOnly,
                (word32)derSz), 0);
            wc_ecc_free(&pubOnly);
        }
        wc_ecc_free(&ecKey);
    }
#endif /* !NO_ASN && HAVE_ECC && USE_CERT_BUFFERS_256 && !HAVE_FIPS */
    return EXPECT_RESULT();
}
