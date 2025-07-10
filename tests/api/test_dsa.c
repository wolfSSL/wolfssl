/* test_dsa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_dsa.h>

/*
 * Testing wc_InitDsaKey()
 */
int test_wc_InitDsaKey(void)
{
    EXPECT_DECLS;
#ifndef NO_DSA
    DsaKey key;

    XMEMSET(&key, 0, sizeof(DsaKey));

    ExpectIntEQ(wc_InitDsaKey(&key), 0);

    /* Pass in bad args. */
    ExpectIntEQ(wc_InitDsaKey(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();

} /* END test_wc_InitDsaKey */

/*
 * Testing wc_DsaSign() and wc_DsaVerify()
 */
int test_wc_DsaSignVerify(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA)
    DsaKey key;
    WC_RNG rng;
    wc_Sha sha;
    byte   signature[DSA_SIG_SIZE];
    byte   hash[WC_SHA_DIGEST_SIZE];
    word32 idx = 0;
    word32 bytes;
    int    answer = 0;
#ifdef USE_CERT_BUFFERS_1024
    byte   tmp[ONEK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    byte   tmp[TWOK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    byte   tmp[TWOK_BUF];
    XFILE  fp = XBADFILE;

    XMEMSET(tmp, 0, sizeof(tmp));
    ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb")) != XBADFILE);
    ExpectTrue((bytes = (word32)XFREAD(tmp, 1, sizeof(tmp), fp)) > 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif /* END USE_CERT_BUFFERS_1024 */

    ExpectIntEQ(wc_InitSha(&sha), 0);
    ExpectIntEQ(wc_ShaUpdate(&sha, tmp, bytes), 0);
    ExpectIntEQ(wc_ShaFinal(&sha, hash), 0);
    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, &key, bytes), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Sign. */
    ExpectIntEQ(wc_DsaSign(hash, signature, &key, &rng), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_DsaSign(NULL, signature, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaSign(hash, NULL, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaSign(hash, signature, NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaSign(hash, signature, &key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Verify. */
    ExpectIntEQ(wc_DsaVerify(hash, signature, &key, &answer), 0);
    ExpectIntEQ(answer, 1);
    /* Pass in bad args. */
    ExpectIntEQ(wc_DsaVerify(NULL, signature, &key, &answer), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaVerify(hash, NULL, &key, &answer), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaVerify(hash, signature, NULL, &answer), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaVerify(hash, signature, &key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if !defined(HAVE_FIPS) && defined(WOLFSSL_PUBLIC_MP)
    /* hard set q to 0 and test fail case */
    mp_free(&key.q);
    ExpectIntEQ(mp_init(&key.q), 0);
    ExpectIntEQ(wc_DsaSign(hash, signature, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    mp_set(&key.q, 1);
    ExpectIntEQ(wc_DsaSign(hash, signature, &key, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    DoExpectIntEQ(wc_FreeRng(&rng),0);
    wc_FreeDsaKey(&key);
    wc_ShaFree(&sha);
#endif
    return EXPECT_RESULT();
} /* END test_wc_DsaSign */

/*
 * Testing wc_DsaPrivateKeyDecode() and wc_DsaPublicKeyDecode()
 */
int test_wc_DsaPublicPrivateKeyDecode(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA)
    DsaKey key;
    word32 bytes = 0;
    word32 idx  = 0;
    int    ret = 0;
#ifdef USE_CERT_BUFFERS_1024
    byte   tmp[ONEK_BUF];

    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    byte   tmp[TWOK_BUF];

    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    byte   tmp[TWOK_BUF];
    XFILE  fp = XBADFILE;

    XMEMSET(tmp, 0, sizeof(tmp));
    ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb")) != XBADFILE);
    ExpectTrue((bytes = (word32) XFREAD(tmp, 1, sizeof(tmp), fp)) > 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif /* END USE_CERT_BUFFERS_1024 */

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, &key, bytes), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_DsaPrivateKeyDecode(NULL, &idx, &key, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, NULL, &key, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, NULL, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntLT(ret = wc_DsaPrivateKeyDecode(tmp, &idx, &key, bytes), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(ASN_PARSE_E)) || (ret == WC_NO_ERR_TRACE(BUFFER_E)));
    wc_FreeDsaKey(&key);

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    idx = 0; /* Reset */
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, &idx, &key, bytes), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_DsaPublicKeyDecode(NULL, &idx, &key, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, NULL, &key, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaPublicKeyDecode(tmp, &idx, NULL, bytes), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntLT(ret = wc_DsaPublicKeyDecode(tmp, &idx, &key, bytes), 0);
    ExpectTrue((ret == WC_NO_ERR_TRACE(ASN_PARSE_E)) || (ret == WC_NO_ERR_TRACE(BUFFER_E)));
    wc_FreeDsaKey(&key);
#endif /* !NO_DSA */
    return EXPECT_RESULT();

} /* END test_wc_DsaPublicPrivateKeyDecode */

/*
 * Testing wc_MakeDsaKey() and wc_MakeDsaParameters()
 */
int test_wc_MakeDsaKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && defined(WOLFSSL_KEY_GEN)
    DsaKey genKey;
    WC_RNG rng;

    XMEMSET(&genKey, 0, sizeof(genKey));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitDsaKey(&genKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_MakeDsaParameters(&rng, ONEK_BUF, &genKey), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_MakeDsaParameters(NULL, ONEK_BUF, &genKey), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeDsaParameters(&rng, ONEK_BUF, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeDsaParameters(&rng, ONEK_BUF + 1, &genKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_MakeDsaKey(&rng, &genKey), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_MakeDsaKey(NULL, &genKey), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeDsaKey(&rng, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_FreeDsaKey(&genKey);
#endif
    return EXPECT_RESULT();
} /* END test_wc_MakeDsaKey */

/*
 * Testing wc_DsaKeyToDer()
 */
int test_wc_DsaKeyToDer(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && defined(WOLFSSL_KEY_GEN)
    DsaKey key;
    word32 bytes;
    word32 idx = 0;
#ifdef USE_CERT_BUFFERS_1024
    byte   tmp[ONEK_BUF];
    byte   der[ONEK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(der, 0, sizeof(der));
    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    byte   tmp[TWOK_BUF];
    byte   der[TWOK_BUF];

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(der, 0, sizeof(der));
    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    byte   tmp[TWOK_BUF];
    byte   der[TWOK_BUF];
    XFILE fp = XBADFILE;

    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMSET(der, 0, sizeof(der));
    ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb")) != XBADFILE);
    ExpectTrue((bytes = (word32) XFREAD(tmp, 1, sizeof(tmp), fp)) > 0);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif /* END USE_CERT_BUFFERS_1024 */

    XMEMSET(&key, 0, sizeof(DsaKey));

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaPrivateKeyDecode(tmp, &idx, &key, bytes), 0);
    ExpectIntGE(wc_DsaKeyToDer(&key, der, bytes), 0);
    ExpectIntEQ(XMEMCMP(der, tmp, bytes), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_DsaKeyToDer(NULL, der, FOURK_BUF), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaKeyToDer(&key, NULL, FOURK_BUF), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_FreeDsaKey(&key);
#endif /* !NO_DSA && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();

} /* END test_wc_DsaKeyToDer */

/*
 *  Testing wc_DsaKeyToPublicDer()
 *  (indirectly testing setDsaPublicKey())
 */
int test_wc_DsaKeyToPublicDer(void)
{
    EXPECT_DECLS;
#ifndef HAVE_SELFTEST
#if !defined(NO_DSA) && defined(WOLFSSL_KEY_GEN)
    DsaKey key;
    WC_RNG rng;
    byte*  der = NULL;
    word32 sz = 0;
    word32 idx = 0;

    XMEMSET(&key, 0, sizeof(DsaKey));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectNotNull(der = (byte*)XMALLOC(ONEK_BUF, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_MakeDsaParameters(&rng, ONEK_BUF, &key), 0);
    ExpectIntEQ(wc_MakeDsaKey(&rng, &key), 0);

    ExpectIntGE(sz = (word32)wc_DsaKeyToPublicDer(&key, der, ONEK_BUF), 0);
    wc_FreeDsaKey(&key);

    idx = 0;
    ExpectIntEQ(wc_DsaPublicKeyDecode(der, &idx, &key, sz), 0);

    /* Test without the SubjectPublicKeyInfo header */
    ExpectIntGE(sz = (word32)wc_SetDsaPublicKey(der, &key, ONEK_BUF, 0), 0);
    wc_FreeDsaKey(&key);
    idx = 0;
    ExpectIntEQ(wc_DsaPublicKeyDecode(der, &idx, &key, sz), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_DsaKeyToPublicDer(NULL, der, FOURK_BUF), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DsaKeyToPublicDer(&key, NULL, FOURK_BUF), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_FreeDsaKey(&key);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* !NO_DSA && WOLFSSL_KEY_GEN */
#endif /* !HAVE_SELFTEST */
    return EXPECT_RESULT();

} /* END test_wc_DsaKeyToPublicDer */

/*
 * Testing wc_DsaImportParamsRaw()
 */
int test_wc_DsaImportParamsRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA)
    DsaKey key;
    /* [mod = L=1024, N=160], from CAVP KeyPair */
    const char* p = "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d"
                    "4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c"
                    "5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b6"
                    "52236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c71"
                    "47123188f8dc551054ee162b634d60f097f719076640e209"
                    "80a0093113a8bd73";
    const char* q = "96c5390a8b612c0e422bb2b0ea194a3ec935a281";
    const char* g = "06b7861abbd35cc89e79c52f68d20875389b127361ca66822"
                    "138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37e"
                    "b23b94074d3c3d300042bdf15762812b6333ef7b07ceba786"
                    "07610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c"
                    "61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc0"
                    "76341a7e7d9";
    /* invalid p and q parameters */
    const char* invalidP = "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d";
    const char* invalidQ = "96c5390a";

    XMEMSET(&key, 0, sizeof(DsaKey));

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaImportParamsRaw(&key, p, q, g), 0);

    /* test bad args */
    /* null key struct */
    ExpectIntEQ(wc_DsaImportParamsRaw(NULL, p, q, g), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null param pointers */
    ExpectIntEQ(wc_DsaImportParamsRaw(&key, NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* illegal p length */
    ExpectIntEQ(wc_DsaImportParamsRaw(&key, invalidP, q, g), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* illegal q length */
    ExpectIntEQ(wc_DsaImportParamsRaw(&key, p, invalidQ, g), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();

} /* END test_wc_DsaImportParamsRaw */

/*
 * Testing wc_DsaImportParamsRawCheck()
 */
int test_wc_DsaImportParamsRawCheck(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
    DsaKey key;
    int    trusted = 0;
    /* [mod = L=1024, N=160], from CAVP KeyPair */
    const char* p = "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d"
                    "4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c"
                    "5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b6"
                    "52236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c71"
                    "47123188f8dc551054ee162b634d60f097f719076640e209"
                    "80a0093113a8bd73";
    const char* q = "96c5390a8b612c0e422bb2b0ea194a3ec935a281";
    const char* g = "06b7861abbd35cc89e79c52f68d20875389b127361ca66822"
                    "138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37e"
                    "b23b94074d3c3d300042bdf15762812b6333ef7b07ceba786"
                    "07610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c"
                    "61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc0"
                    "76341a7e7d9";
    /* invalid p and q parameters */
    const char* invalidP = "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d";
    const char* invalidQ = "96c5390a";

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_DsaImportParamsRawCheck(&key, p, q, g, trusted, NULL), 0);

    /* test bad args */
    /* null key struct */
    ExpectIntEQ(wc_DsaImportParamsRawCheck(NULL, p, q, g, trusted, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null param pointers */
    ExpectIntEQ(wc_DsaImportParamsRawCheck(&key, NULL, NULL, NULL, trusted,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* illegal p length */
    ExpectIntEQ(wc_DsaImportParamsRawCheck(&key, invalidP, q, g, trusted, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* illegal q length */
    ExpectIntEQ(wc_DsaImportParamsRawCheck(&key, p, invalidQ, g, trusted, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_DsaImportParamsRawCheck */

/*
 * Testing wc_DsaExportParamsRaw()
 */
int test_wc_DsaExportParamsRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA)
    DsaKey key;
    /* [mod = L=1024, N=160], from CAVP KeyPair */
    const char* p = "d38311e2cd388c3ed698e82fdf88eb92b5a9a483dc88005d"
                    "4b725ef341eabb47cf8a7a8a41e792a156b7ce97206c4f9c"
                    "5ce6fc5ae7912102b6b502e59050b5b21ce263dddb2044b6"
                    "52236f4d42ab4b5d6aa73189cef1ace778d7845a5c1c1c71"
                    "47123188f8dc551054ee162b634d60f097f719076640e209"
                    "80a0093113a8bd73";
    const char* q = "96c5390a8b612c0e422bb2b0ea194a3ec935a281";
    const char* g = "06b7861abbd35cc89e79c52f68d20875389b127361ca66822"
                    "138ce4991d2b862259d6b4548a6495b195aa0e0b6137ca37e"
                    "b23b94074d3c3d300042bdf15762812b6333ef7b07ceba786"
                    "07610fcc9ee68491dbc1e34cd12615474e52b18bc934fb00c"
                    "61d39e7da8902291c4434a4e2224c3f4fd9f93cd6f4f17fc0"
                    "76341a7e7d9";
    const char* pCompare = "\xd3\x83\x11\xe2\xcd\x38\x8c\x3e\xd6\x98\xe8\x2f"
                           "\xdf\x88\xeb\x92\xb5\xa9\xa4\x83\xdc\x88\x00\x5d"
                           "\x4b\x72\x5e\xf3\x41\xea\xbb\x47\xcf\x8a\x7a\x8a"
                           "\x41\xe7\x92\xa1\x56\xb7\xce\x97\x20\x6c\x4f\x9c"
                           "\x5c\xe6\xfc\x5a\xe7\x91\x21\x02\xb6\xb5\x02\xe5"
                           "\x90\x50\xb5\xb2\x1c\xe2\x63\xdd\xdb\x20\x44\xb6"
                           "\x52\x23\x6f\x4d\x42\xab\x4b\x5d\x6a\xa7\x31\x89"
                           "\xce\xf1\xac\xe7\x78\xd7\x84\x5a\x5c\x1c\x1c\x71"
                           "\x47\x12\x31\x88\xf8\xdc\x55\x10\x54\xee\x16\x2b"
                           "\x63\x4d\x60\xf0\x97\xf7\x19\x07\x66\x40\xe2\x09"
                           "\x80\xa0\x09\x31\x13\xa8\xbd\x73";
    const char* qCompare = "\x96\xc5\x39\x0a\x8b\x61\x2c\x0e\x42\x2b\xb2\xb0"
                           "\xea\x19\x4a\x3e\xc9\x35\xa2\x81";
    const char* gCompare = "\x06\xb7\x86\x1a\xbb\xd3\x5c\xc8\x9e\x79\xc5\x2f"
                           "\x68\xd2\x08\x75\x38\x9b\x12\x73\x61\xca\x66\x82"
                           "\x21\x38\xce\x49\x91\xd2\xb8\x62\x25\x9d\x6b\x45"
                           "\x48\xa6\x49\x5b\x19\x5a\xa0\xe0\xb6\x13\x7c\xa3"
                           "\x7e\xb2\x3b\x94\x07\x4d\x3c\x3d\x30\x00\x42\xbd"
                           "\xf1\x57\x62\x81\x2b\x63\x33\xef\x7b\x07\xce\xba"
                           "\x78\x60\x76\x10\xfc\xc9\xee\x68\x49\x1d\xbc\x1e"
                           "\x34\xcd\x12\x61\x54\x74\xe5\x2b\x18\xbc\x93\x4f"
                           "\xb0\x0c\x61\xd3\x9e\x7d\xa8\x90\x22\x91\xc4\x43"
                           "\x4a\x4e\x22\x24\xc3\xf4\xfd\x9f\x93\xcd\x6f\x4f"
                           "\x17\xfc\x07\x63\x41\xa7\xe7\xd9";
    byte pOut[MAX_DSA_PARAM_SIZE];
    byte qOut[MAX_DSA_PARAM_SIZE];
    byte gOut[MAX_DSA_PARAM_SIZE];
    word32 pOutSz;
    word32 qOutSz;
    word32 gOutSz;

    XMEMSET(&key, 0, sizeof(DsaKey));

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    /* first test using imported raw parameters, for expected */
    ExpectIntEQ(wc_DsaImportParamsRaw(&key, p, q, g), 0);
    pOutSz = sizeof(pOut);
    qOutSz = sizeof(qOut);
    gOutSz = sizeof(gOut);
    ExpectIntEQ(wc_DsaExportParamsRaw(&key, pOut, &pOutSz, qOut, &qOutSz, gOut,
        &gOutSz), 0);
    /* validate exported parameters are correct */
    ExpectIntEQ(XMEMCMP(pOut, pCompare, pOutSz), 0);
    ExpectIntEQ(XMEMCMP(qOut, qCompare, qOutSz), 0);
    ExpectIntEQ(XMEMCMP(gOut, gCompare, gOutSz), 0);

    /* test bad args */
    /* null key struct */
    ExpectIntEQ(wc_DsaExportParamsRaw(NULL, pOut, &pOutSz, qOut, &qOutSz, gOut,
        &gOutSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null output pointers */
    ExpectIntEQ(wc_DsaExportParamsRaw(&key, NULL, &pOutSz, NULL, &qOutSz, NULL,
        &gOutSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    /* null output size pointers */
    ExpectIntEQ( wc_DsaExportParamsRaw(&key, pOut, NULL, qOut, NULL, gOut,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* p output buffer size too small */
    pOutSz = 1;
    ExpectIntEQ(wc_DsaExportParamsRaw(&key, pOut, &pOutSz, qOut, &qOutSz, gOut,
        &gOutSz), WC_NO_ERR_TRACE(BUFFER_E));
    pOutSz = sizeof(pOut);
    /* q output buffer size too small */
    qOutSz = 1;
    ExpectIntEQ(wc_DsaExportParamsRaw(&key, pOut, &pOutSz, qOut, &qOutSz, gOut,
        &gOutSz), WC_NO_ERR_TRACE(BUFFER_E));
    qOutSz = sizeof(qOut);
    /* g output buffer size too small */
    gOutSz = 1;
    ExpectIntEQ(wc_DsaExportParamsRaw(&key, pOut, &pOutSz, qOut, &qOutSz, gOut,
        &gOutSz), WC_NO_ERR_TRACE(BUFFER_E));

    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_DsaExportParamsRaw */

/*
 * Testing wc_DsaExportKeyRaw()
 */
int test_wc_DsaExportKeyRaw(void)
{
    EXPECT_DECLS;
#if !defined(NO_DSA) && defined(WOLFSSL_KEY_GEN)
    DsaKey key;
    WC_RNG rng;
    byte xOut[MAX_DSA_PARAM_SIZE];
    byte yOut[MAX_DSA_PARAM_SIZE];
    word32 xOutSz, yOutSz;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitDsaKey(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_MakeDsaParameters(&rng, 1024, &key), 0);
    ExpectIntEQ(wc_MakeDsaKey(&rng, &key), 0);

    /* try successful export */
    xOutSz = sizeof(xOut);
    yOutSz = sizeof(yOut);
    ExpectIntEQ(wc_DsaExportKeyRaw(&key, xOut, &xOutSz, yOut, &yOutSz), 0);

    /* test bad args */
    /* null key struct */
    ExpectIntEQ(wc_DsaExportKeyRaw(NULL, xOut, &xOutSz, yOut, &yOutSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* null output pointers */
    ExpectIntEQ(wc_DsaExportKeyRaw(&key, NULL, &xOutSz, NULL, &yOutSz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    /* null output size pointers */
    ExpectIntEQ(wc_DsaExportKeyRaw(&key, xOut, NULL, yOut, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* x output buffer size too small */
    xOutSz = 1;
    ExpectIntEQ(wc_DsaExportKeyRaw(&key, xOut, &xOutSz, yOut, &yOutSz),
        WC_NO_ERR_TRACE(BUFFER_E));
    xOutSz = sizeof(xOut);
    /* y output buffer size too small */
    yOutSz = 1;
    ExpectIntEQ(wc_DsaExportKeyRaw(&key, xOut, &xOutSz, yOut, &yOutSz),
        WC_NO_ERR_TRACE(BUFFER_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_FreeDsaKey(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_DsaExportParamsRaw */

