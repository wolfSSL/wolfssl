/* test_ed448.c
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

#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ed448.h>


/*
 * Testing wc_ed448_make_key().
 */
int test_wc_ed448_make_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448)
    ed448_key     key;
    WC_RNG        rng;
    unsigned char pubkey[ED448_PUB_KEY_SIZE];

    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_ed448_make_public(&key, pubkey, sizeof(pubkey)),
        WC_NO_ERR_TRACE(ECC_PRIV_KEY_E));
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_make_key(NULL, ED448_KEY_SIZE, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE - 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE + 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_make_key */


/*
 * Testing wc_ed448_init()
 */
int test_wc_ed448_init(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448)
    ed448_key key;

    XMEMSET(&key, 0, sizeof(ed448_key));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_init */

/*
 * Test wc_ed448_sign_msg() and wc_ed448_verify_msg()
 */
int test_wc_ed448_sign_msg(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN)
    ed448_key key;
    WC_RNG    rng;
    byte      msg[] = "Everybody gets Friday off.\n";
    byte      sig[ED448_SIG_SIZE];
    word32    msglen = sizeof(msg);
    word32    siglen = sizeof(sig);
    word32    badSigLen = sizeof(sig) - 1;
#ifdef HAVE_ED448_VERIFY
    int       verify_ok = 0; /*1 = Verify success.*/
#endif

    /* Initialize stack variables. */
    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(sig, 0, siglen);

    /* Initialize key. */
    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, sig, &siglen, &key, NULL, 0), 0);
    ExpectIntEQ(siglen, ED448_SIG_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_sign_msg(NULL, msglen, sig, &siglen, &key, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, NULL, &siglen, &key, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, sig, NULL, &key, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, sig, &siglen, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, sig, &badSigLen, &key, NULL, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(badSigLen, ED448_SIG_SIZE);
    badSigLen--;

#ifdef HAVE_ED448_VERIFY
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen, msg, msglen, &verify_ok, &key,
        NULL, 0), 0);
    ExpectIntEQ(verify_ok, 1);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen - 1, msg, msglen, &verify_ok,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen + 1, msg, msglen, &verify_ok,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(NULL, siglen, msg, msglen, &verify_ok,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen, NULL, msglen, &verify_ok,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen, msg, msglen, NULL,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen, msg, msglen, &verify_ok,
        NULL, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg(sig, badSigLen, msg, msglen, &verify_ok,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* Verify. */

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_sign_msg */

/*
 * Testing wc_ed448_import_public()
 */
int test_wc_ed448_import_public(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    ed448_key  pubKey;
    WC_RNG     rng;
    const byte in[] =
                    "Ed448PublicKeyUnitTest.................................\n";
    word32     inlen = sizeof(in);

    XMEMSET(&pubKey, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&pubKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &pubKey), 0);

    ExpectIntEQ(wc_ed448_import_public_ex(in, inlen, &pubKey, 1), 0);
    ExpectIntEQ(XMEMCMP(in, pubKey.p, inlen), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_import_public(NULL, inlen, &pubKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_public(in, inlen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_public(in, inlen - 1, &pubKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&pubKey);
#endif
    return EXPECT_RESULT();
} /* END wc_ed448_import_public */

/*
 * Testing wc_ed448_import_private_key()
 */
int test_wc_ed448_import_private_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    ed448_key  key;
    WC_RNG     rng;
    const byte privKey[] =
        "Ed448PrivateKeyUnitTest................................\n";
    const byte pubKey[] =
        "Ed448PublicKeyUnitTest.................................\n";
    word32     privKeySz = sizeof(privKey);
    word32     pubKeySz = sizeof(pubKey);
#ifdef HAVE_ED448_KEY_EXPORT
    byte       bothKeys[sizeof(privKey) + sizeof(pubKey)];
    word32     bothKeysSz = sizeof(bothKeys);
#endif

    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_ed448_import_private_key_ex(privKey, privKeySz, pubKey,
        pubKeySz, &key, 1), 0);
    ExpectIntEQ(XMEMCMP(pubKey, key.p, privKeySz), 0);
    ExpectIntEQ(XMEMCMP(privKey, key.k, pubKeySz), 0);

#ifdef HAVE_ED448_KEY_EXPORT
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private(&key, bothKeys, &bothKeysSz), 0);
    PRIVATE_KEY_LOCK();
    ExpectIntEQ(wc_ed448_import_private_key_ex(bothKeys, bothKeysSz, NULL, 0,
        &key, 1), 0);
    ExpectIntEQ(XMEMCMP(pubKey, key.p, privKeySz), 0);
    ExpectIntEQ(XMEMCMP(privKey, key.k, pubKeySz), 0);
#endif

    /* Test bad args. */
    ExpectIntEQ(wc_ed448_import_private_key(NULL, privKeySz, pubKey, pubKeySz,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_private_key(privKey, privKeySz, NULL, pubKeySz,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_private_key(privKey, privKeySz, pubKey,
        pubKeySz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_private_key(privKey, privKeySz - 1, pubKey,
        pubKeySz, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_private_key(privKey, privKeySz, pubKey,
        pubKeySz - 1, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_import_private_key(privKey, privKeySz, NULL, 0, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_import_private_key */

/*
 * Testing wc_ed448_export_public() and wc_ed448_export_private_only()
 */
int test_wc_ed448_export(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
    ed448_key key;
    WC_RNG    rng;
    byte      priv[ED448_PRV_KEY_SIZE];
    byte      pub[ED448_PUB_KEY_SIZE];
    word32    privSz = sizeof(priv);
    word32    pubSz = sizeof(pub);

    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_ed448_export_public(&key, pub, &pubSz), 0);
    ExpectIntEQ(pubSz, ED448_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(key.p, pub, pubSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_export_public(NULL, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_public(&key, NULL, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_public(&key, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private_only(&key, priv, &privSz), 0);
    ExpectIntEQ(privSz, ED448_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(key.k, priv, privSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_export_private_only(NULL, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private_only(&key, NULL, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private_only(&key, priv, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_export */

/*
 *  Testing wc_ed448_size()
 */
int test_wc_ed448_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448)
    ed448_key key;
    WC_RNG    rng;

    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_ed448_size(&key), ED448_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_sig_size(&key), ED448_SIG_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_sig_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_pub_size(&key), ED448_PUB_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_pub_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_priv_size(&key), ED448_PRV_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_priv_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_size */

/*
 * Testing wc_ed448_export_private() and wc_ed448_export_key()
 */
int test_wc_ed448_exportKey(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
    ed448_key key;
    WC_RNG    rng;
    byte      priv[ED448_PRV_KEY_SIZE];
    byte      pub[ED448_PUB_KEY_SIZE];
    byte      privOnly[ED448_PRV_KEY_SIZE];
    word32    privSz      = sizeof(priv);
    word32    pubSz       = sizeof(pub);
    word32    privOnlySz  = sizeof(privOnly);

    XMEMSET(&key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private(&key, privOnly, &privOnlySz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_export_private(NULL, privOnly, &privOnlySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private(&key, NULL, &privOnlySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private(&key, privOnly, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_export_key(&key, priv, &privSz, pub, &pubSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed448_export_key(NULL, priv, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_key(&key, NULL, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_key(&key, priv, NULL, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_key(&key, priv, &privSz, NULL, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_key(&key, priv, &privSz, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    /* Cross check output. */
    ExpectIntEQ(XMEMCMP(priv, privOnly, privSz), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_exportKey */

/*
 * Testing wc_Ed448PublicKeyToDer
 */
int test_wc_Ed448PublicKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    ed448_key key;
    byte      derBuf[1024];

    XMEMSET(&key, 0, sizeof(ed448_key));

    /* Test bad args */
    ExpectIntEQ(wc_Ed448PublicKeyToDer(NULL, NULL, 0, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_Ed448PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    wc_ed448_free(&key);

    /*  Test good args */
    if (EXPECT_SUCCESS()) {
        WC_RNG rng;

        XMEMSET(&rng, 0, sizeof(WC_RNG));

        ExpectIntEQ(wc_ed448_init(&key), 0);
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);
        /* length only */
        ExpectIntGT(wc_Ed448PublicKeyToDer(&key, NULL, 0, 0), 0);
        ExpectIntGT(wc_Ed448PublicKeyToDer(&key, NULL, 0, 1), 0);
        ExpectIntGT(wc_Ed448PublicKeyToDer(&key, derBuf,
                    (word32)sizeof(derBuf), 1), 0);

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
        wc_ed448_free(&key);
    }
#endif
    return EXPECT_RESULT();
} /* END testing wc_Ed448PublicKeyToDer */

/*
 * Testing wc_Ed448KeyToDer
 */
int test_wc_Ed448KeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    byte      output[ONEK_BUF];
    ed448_key ed448Key;
    WC_RNG    rng;
    word32    inLen;

    XMEMSET(&ed448Key, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&ed448Key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed448Key), 0);
    inLen = (word32)sizeof(output);

    /* Bad Cases */
    ExpectIntEQ(wc_Ed448KeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed448KeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed448KeyToDer(&ed448Key, output, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good Cases */
    /* length only */
    ExpectIntGT(wc_Ed448KeyToDer(&ed448Key, NULL, 0), 0);
    ExpectIntGT(wc_Ed448KeyToDer(&ed448Key, output, inLen), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&ed448Key);
#endif
    return EXPECT_RESULT();
} /* End test_wc_Ed448KeyToDer */

/*
 * Testing wc_Ed448PrivateKeyToDer
 */
int test_wc_Ed448PrivateKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    byte      output[ONEK_BUF];
    ed448_key ed448PrivKey;
    WC_RNG    rng;
    word32    inLen;

    XMEMSET(&ed448PrivKey, 0, sizeof(ed448_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed448_init(&ed448PrivKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed448PrivKey),
        0);
    inLen = (word32)sizeof(output);

    /* Bad Cases */
    ExpectIntEQ(wc_Ed448PrivateKeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed448PrivateKeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed448PrivateKeyToDer(&ed448PrivKey, output, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good cases */
    /* length only */
    ExpectIntGT(wc_Ed448PrivateKeyToDer(&ed448PrivKey, NULL, 0), 0);
    ExpectIntGT(wc_Ed448PrivateKeyToDer(&ed448PrivKey, output, inLen), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&ed448PrivKey);
#endif
    return EXPECT_RESULT();
} /* End test_wc_Ed448PrivateKeyToDer */

