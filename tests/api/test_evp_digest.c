/* test_evp_digest.c
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

#include <wolfssl/openssl/evp.h>
#include <tests/api/api.h>
#include <tests/api/test_evp_digest.h>

int test_wolfSSL_EVP_shake128(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA3) && \
                                            defined(WOLFSSL_SHAKE128)
    const EVP_MD* md = NULL;

    ExpectNotNull(md = EVP_shake128());
    ExpectIntEQ(XSTRNCMP(md, "SHAKE128", XSTRLEN("SHAKE128")), 0);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_shake256(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SHA3) && \
                                            defined(WOLFSSL_SHAKE256)
    const EVP_MD* md = NULL;

    ExpectNotNull(md = EVP_shake256());
    ExpectIntEQ(XSTRNCMP(md, "SHAKE256", XSTRLEN("SHAKE256")), 0);
#endif

    return EXPECT_RESULT();
}

/*
 *  Testing EVP digest API with SM3
 */
int test_wolfSSL_EVP_sm3(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SM3)
    EXPECT_DECLS;
    const EVP_MD* md = NULL;
    EVP_MD_CTX* mdCtx = NULL;
    byte data[WC_SM3_BLOCK_SIZE * 4];
    byte hash[WC_SM3_DIGEST_SIZE];
    byte calcHash[WC_SM3_DIGEST_SIZE];
    byte expHash[WC_SM3_DIGEST_SIZE] = {
        0x38, 0x48, 0x15, 0xa7, 0x0e, 0xae, 0x0b, 0x27,
        0x5c, 0xde, 0x9d, 0xa5, 0xd1, 0xa4, 0x30, 0xa1,
        0xca, 0xd4, 0x54, 0x58, 0x44, 0xa2, 0x96, 0x1b,
        0xd7, 0x14, 0x80, 0x3f, 0x80, 0x1a, 0x07, 0xb6
    };
    word32 chunk;
    word32 i;
    unsigned int sz;
    int ret;

    XMEMSET(data, 0, sizeof(data));

    md = EVP_sm3();
    ExpectTrue(md != NULL);
    ExpectIntEQ(XSTRNCMP(md, "SM3", XSTRLEN("SM3")), 0);
    mdCtx = EVP_MD_CTX_new();
    ExpectTrue(mdCtx != NULL);

    /* Invalid Parameters */
    ExpectIntEQ(EVP_DigestInit(NULL, md), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestInit(mdCtx, md), WOLFSSL_SUCCESS);

    ExpectIntEQ(EVP_DigestUpdate(NULL, NULL, 1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, NULL, 1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestUpdate(NULL, data, 1),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE - 2),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_BLOCK_SIZE * 2),
        WOLFSSL_SUCCESS);
    /* Ensure too many bytes for lengths. */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, WC_SM3_PAD_SIZE),
        WOLFSSL_SUCCESS);

    /* Invalid Parameters */
    ExpectIntEQ(EVP_DigestFinal(NULL, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(mdCtx, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(NULL, hash, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(NULL, hash, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(EVP_DigestFinal(mdCtx, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    /* Valid Parameters */
    ExpectIntEQ(EVP_DigestFinal(mdCtx, hash, NULL), WOLFSSL_SUCCESS);
    ExpectBufEQ(hash, expHash, WC_SM3_DIGEST_SIZE);

    /* Chunk tests. */
    ExpectIntEQ(EVP_DigestUpdate(mdCtx, data, sizeof(data)), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(mdCtx, calcHash, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, WC_SM3_DIGEST_SIZE);
    for (chunk = 1; chunk <= WC_SM3_BLOCK_SIZE + 1; chunk++) {
        for (i = 0; i + chunk <= (word32)sizeof(data); i += chunk) {
            ExpectIntEQ(EVP_DigestUpdate(mdCtx, data + i, chunk),
                WOLFSSL_SUCCESS);
        }
        if (i < (word32)sizeof(data)) {
            ExpectIntEQ(EVP_DigestUpdate(mdCtx, data + i,
                (word32)sizeof(data) - i), WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(EVP_DigestFinal(mdCtx, hash, NULL), WOLFSSL_SUCCESS);
        ExpectBufEQ(hash, calcHash, WC_SM3_DIGEST_SIZE);
    }

    /* Not testing when the low 32-bit length overflows. */

    ret = EVP_MD_CTX_cleanup(mdCtx);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    wolfSSL_EVP_MD_CTX_free(mdCtx);

    res = EXPECT_RESULT();
#endif
    return res;
}  /* END test_EVP_sm3 */

int test_EVP_blake2(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && (defined(HAVE_BLAKE2) || defined(HAVE_BLAKE2S))
    const EVP_MD* md = NULL;
    (void)md;

#if defined(HAVE_BLAKE2)
    ExpectNotNull(md = EVP_blake2b512());
    ExpectIntEQ(XSTRNCMP(md, "BLAKE2b512", XSTRLEN("BLAKE2b512")), 0);
#endif

#if defined(HAVE_BLAKE2S)
    ExpectNotNull(md = EVP_blake2s256());
    ExpectIntEQ(XSTRNCMP(md, "BLAKE2s256", XSTRLEN("BLAKE2s256")), 0);
#endif
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_md4(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD4) && defined(OPENSSL_ALL)
    ExpectNotNull(wolfSSL_EVP_md4());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_ripemd160(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_STUB) && defined(OPENSSL_ALL)
    ExpectNull(wolfSSL_EVP_ripemd160());
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_get_digestbynid(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#ifndef NO_MD5
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_md5));
#endif
#ifndef NO_SHA
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_sha1));
#endif
#ifndef NO_SHA256
    ExpectNotNull(wolfSSL_EVP_get_digestbynid(NID_sha256));
#endif
    ExpectNull(wolfSSL_EVP_get_digestbynid(0));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_Digest(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_SHA256) && !defined(NO_PWDBASED)
    const char* in = "abc";
    int   inLen = (int)XSTRLEN(in);
    byte  out[WC_SHA256_DIGEST_SIZE];
    unsigned int outLen;
    const char* expOut =
        "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
        "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
        "\x15\xAD";

    ExpectIntEQ(wolfSSL_EVP_Digest((unsigned char*)in, inLen, out, &outLen,
        "SHA256", NULL), 1);
    ExpectIntEQ(outLen, WC_SHA256_DIGEST_SIZE);
    ExpectIntEQ(XMEMCMP(out, expOut, WC_SHA256_DIGEST_SIZE), 0);
#endif /* OPEN_EXTRA && ! NO_SHA256 */
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_Digest_all(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    const char* digests[] = {
#ifndef NO_MD5
        "MD5",
#endif
#ifndef NO_SHA
        "SHA",
#endif
#ifdef WOLFSSL_SHA224
        "SHA224",
#endif
#ifndef NO_SHA256
        "SHA256",
#endif
#ifdef WOLFSSL_SHA384
        "SHA384",
#endif
#ifdef WOLFSSL_SHA512
        "SHA512",
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224)
        "SHA512-224",
#endif
#if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256)
        "SHA512-256",
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
        "SHA3-224",
#endif
#ifndef WOLFSSL_NOSHA3_256
        "SHA3-256",
#endif
        "SHA3-384",
#ifndef WOLFSSL_NOSHA3_512
        "SHA3-512",
#endif
#endif /* WOLFSSL_SHA3 */
        NULL
    };
    const char** d;
    const unsigned char in[] = "abc";
    int   inLen = XSTR_SIZEOF(in);
    byte  out[WC_MAX_DIGEST_SIZE];
    unsigned int outLen;

    for (d = digests; *d != NULL; d++) {
        ExpectIntEQ(EVP_Digest(in, inLen, out, &outLen, *d, NULL), 1);
        ExpectIntGT(outLen, 0);
        ExpectIntEQ(EVP_MD_size(*d), outLen);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_DigestFinal_ex(void)
{
    EXPECT_DECLS;
#if !defined(NO_SHA256) && defined(OPENSSL_ALL)
    WOLFSSL_EVP_MD_CTX mdCtx;
    unsigned int       s = 0;
    unsigned char      md[WC_SHA256_DIGEST_SIZE];
    unsigned char      md2[WC_SHA256_DIGEST_SIZE];

    /* Bad Case */
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md, &s), 0);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#else
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md, &s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

#endif

    /* Good Case */
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, EVP_sha256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_DigestFinal_ex(&mdCtx, md2, &s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_DigestFinalXOF(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256) && defined(OPENSSL_ALL)
    WOLFSSL_EVP_MD_CTX mdCtx;
    unsigned char      shake[256];
    unsigned char      zeros[10];
    unsigned char      data[] = "Test data";
    unsigned int sz;

    XMEMSET(zeros, 0, sizeof(zeros));
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_MD_flags(EVP_shake256()), EVP_MD_FLAG_XOF);
    ExpectIntEQ(EVP_MD_flags(EVP_sha3_256()), 0);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    XMEMSET(shake, 0, sizeof(shake));
    ExpectIntEQ(EVP_DigestFinalXOF(&mdCtx, shake, 10), WOLFSSL_SUCCESS);

    /* make sure was only size of 10 */
    ExpectIntEQ(XMEMCMP(&shake[11], zeros, 10), 0);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake256()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(&mdCtx, shake, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, 32);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);

    #if defined(WOLFSSL_SHAKE128)
    wolfSSL_EVP_MD_CTX_init(&mdCtx);
    ExpectIntEQ(EVP_DigestInit(&mdCtx, EVP_shake128()), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestUpdate(&mdCtx, data, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_DigestFinal(&mdCtx, shake, &sz), WOLFSSL_SUCCESS);
    ExpectIntEQ(sz, 16);
    ExpectIntEQ(EVP_MD_CTX_cleanup(&mdCtx), WOLFSSL_SUCCESS);
    #endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_EVP_MD_nid(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
#ifndef NO_MD5
    ExpectIntEQ(EVP_MD_nid(EVP_md5()), NID_md5);
#endif
#ifndef NO_SHA
    ExpectIntEQ(EVP_MD_nid(EVP_sha1()), NID_sha1);
#endif
#ifndef NO_SHA256
    ExpectIntEQ(EVP_MD_nid(EVP_sha256()), NID_sha256);
#endif
    ExpectIntEQ(EVP_MD_nid(NULL), NID_undef);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA)
static void list_md_fn(const EVP_MD* m, const char* from,
                       const char* to, void* arg)
{
    const char* mn;
    BIO *bio;

    (void) from;
    (void) to;
    (void) arg;
    (void) mn;
    (void) bio;

    if (!m) {
        /* alias */
        AssertNull(m);
        AssertNotNull(to);
    }
    else {
        AssertNotNull(m);
        AssertNull(to);
    }

    AssertNotNull(from);

#if !defined(NO_FILESYSTEM) && defined(DEBUG_WOLFSSL_VERBOSE)
    mn = EVP_get_digestbyname(from);
    /* print to stderr */
    AssertNotNull(arg);

    bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, arg, BIO_NOCLOSE);
    BIO_printf(bio, "Use %s message digest algorithm\n", mn);
    BIO_free(bio);
#endif
}
#endif

int test_EVP_MD_do_all(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    EVP_MD_do_all(NULL, stderr);

    EVP_MD_do_all(list_md_fn, stderr);

    res = TEST_SUCCESS;
#endif

    return res;
}

int test_wolfSSL_EVP_MD_size(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    WOLFSSL_EVP_MD_CTX mdCtx;

#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA3-224"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA3_224_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA3_224_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif
#ifndef WOLFSSL_NOSHA3_256
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA3-256"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA3_256_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA3_256_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA3-384"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA3_384_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA3_384_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#ifndef WOLFSSL_NOSHA3_512
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA3-512"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA3_512_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA3_512_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif
#endif /* WOLFSSL_SHA3 */

#ifndef NO_SHA256
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA256"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA256_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA256_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA256_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA256_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#endif

#ifndef NO_MD5
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "MD5"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_MD5_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_MD5_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_MD5_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_MD5_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#endif

#ifdef WOLFSSL_SHA224
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA224"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA224_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA224_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA224_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA224_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#endif

#ifdef WOLFSSL_SHA384
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA384"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA384_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA384_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA384_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA384_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#endif

#ifdef WOLFSSL_SHA512
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA512"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA512_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA512_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA512_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA512_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

#endif

#ifndef NO_SHA
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);

    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, "SHA1"), 1);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_block_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)),
        WC_SHA_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_size(&mdCtx), WC_SHA_DIGEST_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), WC_SHA_BLOCK_SIZE);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif
    /* error case */
    wolfSSL_EVP_MD_CTX_init(&mdCtx);

    ExpectIntEQ(wolfSSL_EVP_DigestInit(&mdCtx, ""), 0);
    ExpectIntEQ(wolfSSL_EVP_MD_size(wolfSSL_EVP_MD_CTX_md(&mdCtx)), 0);
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_block_size(&mdCtx), 0);
    /* Cleanup is valid on uninit'ed struct */
    ExpectIntEQ(wolfSSL_EVP_MD_CTX_cleanup(&mdCtx), 1);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

