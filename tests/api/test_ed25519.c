/* test_ed25519.c
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

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ed25519.h>

/*
 * Testing wc_ed25519_make_key().
 */
int test_wc_ed25519_make_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY)
    ed25519_key   key;
    WC_RNG        rng;
    unsigned char pubkey[ED25519_PUB_KEY_SIZE+1];
    int           pubkey_sz = ED25519_PUB_KEY_SIZE;

    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectIntEQ(wc_ed25519_make_public(&key, pubkey, (word32)pubkey_sz),
        WC_NO_ERR_TRACE(ECC_PRIV_KEY_E));
    ExpectIntEQ(wc_ed25519_make_public(&key, pubkey+1, (word32)pubkey_sz),
        WC_NO_ERR_TRACE(ECC_PRIV_KEY_E));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_make_key(NULL, ED25519_KEY_SIZE, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE - 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE + 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_make_key */

/*
 * Testing wc_ed25519_init()
 */
int test_wc_ed25519_init(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519)
    ed25519_key key;

    XMEMSET(&key, 0, sizeof(ed25519_key));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_init */

/*
 * Test wc_ed25519_sign_msg() and wc_ed25519_verify_msg()
 */
int test_wc_ed25519_sign_msg(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    WC_RNG      rng;
    ed25519_key key;
    byte        msg[] = "Everybody gets Friday off.\n";
    byte        sig[ED25519_SIG_SIZE+1];
    word32      msglen = sizeof(msg);
    word32      siglen = ED25519_SIG_SIZE;
    word32      badSigLen = ED25519_SIG_SIZE - 1;
#ifdef HAVE_ED25519_VERIFY
    int         verify_ok = 0; /*1 = Verify success.*/
#endif

    /* Initialize stack variables. */
    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(sig, 0, sizeof(sig));

    /* Initialize key. */
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, sig, &siglen, &key), 0);
    ExpectIntEQ(siglen, ED25519_SIG_SIZE);
    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, sig+1, &siglen, &key), 0);
    ExpectIntEQ(siglen, ED25519_SIG_SIZE);

    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_sign_msg(NULL, msglen, sig, &siglen, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, NULL, &siglen, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, sig, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, sig, &siglen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, msglen, sig, &badSigLen, &key),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(badSigLen, ED25519_SIG_SIZE);
    badSigLen--;

#ifdef HAVE_ED25519_VERIFY
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen, msg, msglen, &verify_ok,
        &key), 0);
    ExpectIntEQ(verify_ok, 1);

    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen - 1, msg, msglen,
        &verify_ok, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen + 1, msg, msglen,
        &verify_ok, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(NULL, siglen, msg, msglen, &verify_ok,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen, NULL, msglen, &verify_ok,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen, msg, msglen, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, siglen, msg, msglen, &verify_ok,
        NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig+1, badSigLen, msg, msglen, &verify_ok,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* Verify. */

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();

} /* END test_wc_ed25519_sign_msg */

/*
 * Testing wc_ed25519_import_public()
 */
int test_wc_ed25519_import_public(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_key pubKey;
    WC_RNG      rng;
    const byte  in[] = "Ed25519PublicKeyUnitTest......\n";
    word32      inlen = sizeof(in);

    XMEMSET(&pubKey, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&pubKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef HAVE_ED25519_MAKE_KEY
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &pubKey), 0);
#endif

    ExpectIntEQ(wc_ed25519_import_public_ex(in, inlen, &pubKey, 1), 0);
    ExpectIntEQ(XMEMCMP(in, pubKey.p, inlen), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_import_public(NULL, inlen, &pubKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_public(in, inlen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_public(in, inlen - 1, &pubKey),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&pubKey);
#endif
    return EXPECT_RESULT();
} /* END wc_ed25519_import_public */

/*
 * Testing wc_ed25519_import_private_key()
 */
int test_wc_ed25519_import_private_key(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_key key;
    WC_RNG      rng;
    const byte  privKey[] = "Ed25519PrivateKeyUnitTest.....\n";
    const byte  pubKey[] = "Ed25519PublicKeyUnitTest......\n";
    word32      privKeySz = sizeof(privKey);
    word32      pubKeySz = sizeof(pubKey);
#ifdef HAVE_ED25519_KEY_EXPORT
    byte        bothKeys[sizeof(privKey) + sizeof(pubKey)];
    word32      bothKeysSz = sizeof(bothKeys);
#endif

    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef HAVE_ED25519_MAKE_KEY
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
#endif

    ExpectIntEQ(wc_ed25519_import_private_key_ex(privKey, privKeySz, pubKey,
        pubKeySz, &key, 1), 0);
    ExpectIntEQ(XMEMCMP(pubKey, key.p, privKeySz), 0);
    ExpectIntEQ(XMEMCMP(privKey, key.k, pubKeySz), 0);

#ifdef HAVE_ED25519_KEY_EXPORT
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed25519_export_private(&key, bothKeys, &bothKeysSz), 0);
    PRIVATE_KEY_LOCK();
    ExpectIntEQ(wc_ed25519_import_private_key_ex(bothKeys, bothKeysSz, NULL, 0,
        &key, 1), 0);
    ExpectIntEQ(XMEMCMP(pubKey, key.p, privKeySz), 0);
    ExpectIntEQ(XMEMCMP(privKey, key.k, pubKeySz), 0);
#endif

    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_import_private_key(NULL, privKeySz, pubKey, pubKeySz,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_private_key(privKey, privKeySz, NULL,
        pubKeySz, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_private_key(privKey, privKeySz, pubKey,
        pubKeySz, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_private_key(privKey, privKeySz - 1, pubKey,
        pubKeySz, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_private_key(privKey, privKeySz, pubKey,
        pubKeySz - 1, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_import_private_key(privKey, privKeySz, NULL, 0,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_import_private_key */

/*
 * Testing wc_ed25519_export_public() and wc_ed25519_export_private_only()
 */
int test_wc_ed25519_export(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    ed25519_key key;
    WC_RNG      rng;
    byte        priv[ED25519_PRV_KEY_SIZE];
    byte        pub[ED25519_PUB_KEY_SIZE];
    word32      privSz = sizeof(priv);
    word32      pubSz = sizeof(pub);
#ifndef HAVE_ED25519_MAKE_KEY
    const byte  privKey[] = {
        0xf8, 0x55, 0xb7, 0xb6, 0x49, 0x3f, 0x99, 0x9c,
        0x88, 0xe3, 0xc5, 0x42, 0x6a, 0xa4, 0x47, 0x4a,
        0xe4, 0x95, 0xda, 0xdb, 0xbf, 0xf8, 0xa7, 0x42,
        0x9d, 0x0e, 0xe7, 0xd0, 0x57, 0x8f, 0x16, 0x69
    };
    const byte  pubKey[] = {
        0x42, 0x3b, 0x7a, 0xf9, 0x82, 0xcf, 0xf9, 0xdf,
        0x19, 0xdd, 0xf3, 0xf0, 0x32, 0x29, 0x6d, 0xfa,
        0xfd, 0x76, 0x4f, 0x68, 0xc2, 0xc2, 0xe0, 0x6c,
        0x47, 0xae, 0xc2, 0x55, 0x68, 0xac, 0x0d, 0x4d
    };
#endif

    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef HAVE_ED25519_MAKE_KEY
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
#else
    ExpectIntEQ(wc_ed25519_import_private_key_ex(privKey, sizeof(privKey),
        pubKey, sizeof(pubKey), &key, 1), 0);
#endif

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed25519_export_public(&key, pub, &pubSz), 0);
    ExpectIntEQ(pubSz, ED25519_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(key.p, pub, pubSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_export_public(NULL, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_public(&key, NULL, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_public(&key, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed25519_export_private_only(&key, priv, &privSz), 0);
    ExpectIntEQ(privSz, ED25519_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(key.k, priv, privSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_export_private_only(NULL, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private_only(&key, NULL, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private_only(&key, priv, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_export */

/*
 *  Testing wc_ed25519_size()
 */
int test_wc_ed25519_size(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519)
    ed25519_key key;
    WC_RNG      rng;
#ifndef HAVE_ED25519_MAKE_KEY
    const byte  privKey[] = {
        0xf8, 0x55, 0xb7, 0xb6, 0x49, 0x3f, 0x99, 0x9c,
        0x88, 0xe3, 0xc5, 0x42, 0x6a, 0xa4, 0x47, 0x4a,
        0xe4, 0x95, 0xda, 0xdb, 0xbf, 0xf8, 0xa7, 0x42,
        0x9d, 0x0e, 0xe7, 0xd0, 0x57, 0x8f, 0x16, 0x69
    };
    const byte  pubKey[] = {
        0x42, 0x3b, 0x7a, 0xf9, 0x82, 0xcf, 0xf9, 0xdf,
        0x19, 0xdd, 0xf3, 0xf0, 0x32, 0x29, 0x6d, 0xfa,
        0xfd, 0x76, 0x4f, 0x68, 0xc2, 0xc2, 0xe0, 0x6c,
        0x47, 0xae, 0xc2, 0x55, 0x68, 0xac, 0x0d, 0x4d
    };
#endif

    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef HAVE_ED25519_MAKE_KEY
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
#else
    ExpectIntEQ(wc_ed25519_import_private_key_ex(privKey, sizeof(privKey),
        pubKey, sizeof(pubKey), &key, 1), 0);
#endif

    ExpectIntEQ(wc_ed25519_size(&key), ED25519_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed25519_sig_size(&key), ED25519_SIG_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_sig_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed25519_pub_size(&key), ED25519_PUB_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_pub_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed25519_priv_size(&key), ED25519_PRV_KEY_SIZE);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_priv_size(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_size */

/*
 * Testing wc_ed25519_export_private() and wc_ed25519_export_key()
 */
int test_wc_ed25519_exportKey(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    WC_RNG      rng;
    ed25519_key key;
    byte        priv[ED25519_PRV_KEY_SIZE];
    byte        pub[ED25519_PUB_KEY_SIZE];
    byte        privOnly[ED25519_PRV_KEY_SIZE];
    word32      privSz      = sizeof(priv);
    word32      pubSz       = sizeof(pub);
    word32      privOnlySz  = sizeof(privOnly);
#ifndef HAVE_ED25519_MAKE_KEY
    const byte  privKey[] = {
        0xf8, 0x55, 0xb7, 0xb6, 0x49, 0x3f, 0x99, 0x9c,
        0x88, 0xe3, 0xc5, 0x42, 0x6a, 0xa4, 0x47, 0x4a,
        0xe4, 0x95, 0xda, 0xdb, 0xbf, 0xf8, 0xa7, 0x42,
        0x9d, 0x0e, 0xe7, 0xd0, 0x57, 0x8f, 0x16, 0x69
    };
    const byte  pubKey[] = {
        0x42, 0x3b, 0x7a, 0xf9, 0x82, 0xcf, 0xf9, 0xdf,
        0x19, 0xdd, 0xf3, 0xf0, 0x32, 0x29, 0x6d, 0xfa,
        0xfd, 0x76, 0x4f, 0x68, 0xc2, 0xc2, 0xe0, 0x6c,
        0x47, 0xae, 0xc2, 0x55, 0x68, 0xac, 0x0d, 0x4d
    };
#endif

    XMEMSET(&key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
#ifdef HAVE_ED25519_MAKE_KEY
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
#else
    ExpectIntEQ(wc_ed25519_import_private_key_ex(privKey, sizeof(privKey),
        pubKey, sizeof(pubKey), &key, 1), 0);
#endif

    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed25519_export_private(&key, privOnly, &privOnlySz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_export_private(NULL, privOnly, &privOnlySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private(&key, NULL, &privOnlySz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private(&key, privOnly, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed25519_export_key(&key, priv, &privSz, pub, &pubSz), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_ed25519_export_key(NULL, priv, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_key(&key, NULL, &privSz, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_key(&key, priv, NULL, pub, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_key(&key, priv, &privSz, NULL, &pubSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_key(&key, priv, &privSz, pub, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();

    /* Cross check output. */
    ExpectIntEQ(XMEMCMP(priv, privOnly, privSz), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_exportKey */

/*
 * Testing wc_Ed25519PublicKeyToDer
 */
int test_wc_Ed25519PublicKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    ed25519_key key;
    byte        derBuf[1024];

    XMEMSET(&key, 0, sizeof(ed25519_key));

    /* Test bad args */
    ExpectIntEQ(wc_Ed25519PublicKeyToDer(NULL, NULL, 0, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_Ed25519PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    wc_ed25519_free(&key);

    /*  Test good args */
    if (EXPECT_SUCCESS()) {
        WC_RNG rng;

        XMEMSET(&rng, 0, sizeof(WC_RNG));

        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
        /* length only */
        ExpectIntGT(wc_Ed25519PublicKeyToDer(&key, NULL, 0, 0), 0);
        ExpectIntGT(wc_Ed25519PublicKeyToDer(&key, NULL, 0, 1), 0);
        ExpectIntGT(wc_Ed25519PublicKeyToDer(&key, derBuf,
                    (word32)sizeof(derBuf), 1), 0);

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
        wc_ed25519_free(&key);
    }
#endif
    return EXPECT_RESULT();
} /* END testing wc_Ed25519PublicKeyToDer */

/*
 * Testing wc_Ed25519KeyToDer
 */
int test_wc_Ed25519KeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    byte        output[ONEK_BUF];
    ed25519_key ed25519Key;
    WC_RNG      rng;
    word32      inLen;

    XMEMSET(&ed25519Key, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&ed25519Key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed25519Key), 0);
    inLen = (word32)sizeof(output);

    /* Bad Cases */
    ExpectIntEQ(wc_Ed25519KeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed25519KeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed25519KeyToDer(&ed25519Key, output, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good Cases */
    /* length only */
    ExpectIntGT(wc_Ed25519KeyToDer(&ed25519Key, NULL, 0), 0);
    ExpectIntGT(wc_Ed25519KeyToDer(&ed25519Key, NULL, inLen), 0);
    ExpectIntGT(wc_Ed25519KeyToDer(&ed25519Key, output, inLen), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&ed25519Key);
#endif
    return EXPECT_RESULT();
} /* End test_wc_Ed25519KeyToDer*/

/*
 * Testing wc_Ed25519PrivateKeyToDer
 */
int test_wc_Ed25519PrivateKeyToDer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
    byte        output[ONEK_BUF];
    ed25519_key ed25519PrivKey;
    WC_RNG      rng;
    word32      inLen;

    XMEMSET(&ed25519PrivKey, 0, sizeof(ed25519_key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&ed25519PrivKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed25519PrivKey),
        0);
    inLen = (word32)sizeof(output);

    /* Bad Cases */
    ExpectIntEQ(wc_Ed25519PrivateKeyToDer(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed25519PrivateKeyToDer(NULL, output, inLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Ed25519PrivateKeyToDer(&ed25519PrivKey, output, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Good Cases */
    /* length only */
    ExpectIntGT(wc_Ed25519PrivateKeyToDer(&ed25519PrivKey, NULL, 0), 0);
    ExpectIntGT(wc_Ed25519PrivateKeyToDer(&ed25519PrivKey, output, inLen), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&ed25519PrivKey);
#endif
    return EXPECT_RESULT();
} /* End test_wc_Ed25519PrivateKeyToDer*/

