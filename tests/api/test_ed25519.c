/* test_ed25519.c
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
 * Test that wc_ed25519_sign_msg() rejects a public-key-only key object.
 * A key with pubKeySet=1 but privKeySet=0 must not silently sign.
 */
int test_wc_ed25519_sign_msg_pubonly_fails(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(HAVE_ED25519_KEY_EXPORT)
    ed25519_key fullKey;
    ed25519_key pubOnlyKey;
    WC_RNG      rng;
    byte        pubBuf[ED25519_PUB_KEY_SIZE];
    word32      pubSz = sizeof(pubBuf);
    byte        msg[] = "test message for pubonly check";
    byte        sig[ED25519_SIG_SIZE];
    word32      sigLen = sizeof(sig);

    XMEMSET(&fullKey, 0, sizeof(fullKey));
    XMEMSET(&pubOnlyKey, 0, sizeof(pubOnlyKey));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_ed25519_init(&fullKey), 0);
    ExpectIntEQ(wc_ed25519_init(&pubOnlyKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Generate a real key pair and export its public key. */
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &fullKey), 0);
    ExpectIntEQ(wc_ed25519_export_public(&fullKey, pubBuf, &pubSz), 0);

    /* Import only the public key into a fresh key object. */
    ExpectIntEQ(wc_ed25519_import_public(pubBuf, pubSz, &pubOnlyKey), 0);

    /* Signing with a public-key-only object must fail. */
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen,
        &pubOnlyKey), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&pubOnlyKey);
    wc_ed25519_free(&fullKey);
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_sign_msg_pubonly_fails */

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

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
    /* Reject export when private key not set. */
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed25519_export_private_only(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();
#endif /* !HAVE_FIPS || FIPS_VERSION3_GE(7,0,0) */

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

#ifdef HAVE_ED25519_KEY_IMPORT
    /* Public-only key: re-init and import just the public part; private
     * exports must still fail with privKeySet == 0. */
    wc_ed25519_free(&key);
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_import_public(pub, pubSz, &key), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed25519_export_private_only(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_export_private(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();
#endif /* !HAVE_FIPS || FIPS_VERSION3_GE(7,0,0) */

#endif

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
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ed25519_key));

    /* Test bad args */
    ExpectIntEQ(wc_Ed25519PublicKeyToDer(NULL, NULL, 0, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
    if (EXPECT_SUCCESS()) {
        int ret = wc_Ed25519PublicKeyToDer(&key, derBuf, 0, 0);
        ExpectTrue((ret == WC_NO_ERR_TRACE(BUFFER_E)) ||
                   (ret == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    }
#else
    ExpectIntEQ(wc_Ed25519PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(PUBLIC_KEY_E));
#endif
    wc_ed25519_free(&key);

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    ExpectIntEQ(wc_Ed25519PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);

    /*  Test good args */
    if (EXPECT_SUCCESS()) {
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

/*
 * RFC 5958: version=v2 (1) when pub key is bundled, v1 (0) for private only. */
int test_wc_Ed25519KeyToDer_oneasymkey_version(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(WOLFSSL_KEY_GEN)
    ed25519_key key;
    ed25519_key key2;
    WC_RNG rng;
    byte ref[256];   /* reference DER (bundled, then private only) */
    byte rt[256];    /* re-export target for memcmp */
    int  refSz = 0;
    int  rtSz = 0;
    word32 idx;

    XMEMSET(&key,  0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng,  0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_init(&key2), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    /* Bundled (v=1) */
    ExpectIntGT(refSz = wc_Ed25519KeyToDer(&key, ref, (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 1);
    idx = 0;
    ExpectIntEQ(wc_Ed25519PrivateKeyDecode(ref, &idx, &key2, (word32)refSz),
        0);
    ExpectIntEQ(rtSz = wc_Ed25519KeyToDer(&key2, rt, (word32)sizeof(rt)),
        refSz);
    ExpectIntEQ(XMEMCMP(ref, rt, (size_t)refSz), 0);

    /* Priv-only (v=0) */
    ExpectIntGT(refSz = wc_Ed25519PrivateKeyToDer(&key, ref,
        (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 0);

    wc_ed25519_free(&key);
    wc_ed25519_free(&key2);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

/* Ed25519 identity and small-order public keys must be rejected. When
 * the public key is the identity point (or any small-order point), any
 * signature of the form (R = [S]B, S) verifies for arbitrary messages
 * because h*A is the neutral element. Gated on FIPS_VERSION3_GE(7,0,0)
 * because older FIPS-certified modules do not have this check in their
 * frozen copy of ed25519.c and would fail this test. */
int test_wc_ed25519_reject_small_order_keys(void)
{
    EXPECT_DECLS;
#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && \
    defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    /* Each entry holds an encoded small-order Ed25519 public key. The
     * sign-bit variants of each y-coordinate are listed explicitly so
     * the test catches both possible encodings of each y. */
    static const byte small_order_keys[][ED25519_PUB_KEY_SIZE] = {
        /* identity (y = 1) */
        {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        /* identity with x-sign bit set */
        {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80},
        /* order 2: y = p - 1 */
        {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        /* order 2: y = p - 1 with x-sign bit set */
        {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
        /* non-canonical y = p (decodes to y = 0) */
        {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        /* non-canonical y = p with x-sign bit set */
        {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
        /* non-canonical y = p + 1 (decodes to y = 1) */
        {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        /* non-canonical y = p + 1 with x-sign bit set */
        {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
        /* order 4: y = 0 */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        /* order 4 with x-sign bit set */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80},
        /* order 8 */
        {0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,
         0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
         0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,
         0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05},
        /* order 8 with x-sign bit set */
        {0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,
         0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
         0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,
         0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x85},
        /* order 8 (other y) */
        {0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,
         0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
         0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,
         0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a},
        /* order 8 (other y) with x-sign bit set */
        {0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,
         0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
         0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,
         0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0xfa},
    };
#ifndef NO_ED25519_VERIFY
    /* Forged signature: R = B (base point), S = 1.
     * With public key A = identity, S*B - h*A = B = R for any message. */
    static const byte forged_sig[ED25519_SIG_SIZE] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
#endif
    ed25519_key key;
    word32 i;
    word32 num_keys = (word32)(sizeof(small_order_keys) / ED25519_PUB_KEY_SIZE);

    /* (1) Untrusted wc_ed25519_import_public must reject every small-order
     * encoding (it runs wc_ed25519_check_key as part of the import). */
    for (i = 0; i < num_keys; i++) {
        int rc;
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        rc = wc_ed25519_import_public(small_order_keys[i],
            ED25519_PUB_KEY_SIZE, &key);
        if (rc != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            fprintf(stderr, "small_order_keys[%u]: import_public returned %d, "
                "expected PUBLIC_KEY_E\n", (unsigned)i, rc);
        }
        ExpectIntEQ(rc, WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_ed25519_free(&key);
    }

    /* (2) wc_ed25519_check_key called directly must also reject. Guards
     * against a refactor that moves the small-order check out of
     * check_key and into the import path: (1) would still pass, but the
     * documented check_key contract would silently regress. */
    for (i = 0; i < num_keys; i++) {
        int rc;
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        /* trusted = 1 bypasses the import-time check_key call so the
         * direct check_key below is what's under test. */
        ExpectIntEQ(wc_ed25519_import_public_ex(small_order_keys[i],
            ED25519_PUB_KEY_SIZE, &key, 1), 0);
        rc = wc_ed25519_check_key(&key);
        if (rc != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            fprintf(stderr, "small_order_keys[%u]: check_key returned %d, "
                "expected PUBLIC_KEY_E\n", (unsigned)i, rc);
        }
        ExpectIntEQ(rc, WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_ed25519_free(&key);
    }

#ifndef NO_ED25519_VERIFY
    /* (3) Even a "trusted" import (which bypasses wc_ed25519_check_key)
     * must not let wc_ed25519_verify_msg accept a forged signature against
     * an identity public key. Test both the canonical encoding (y = 1,
     * small_order_keys[0]) and the non-canonical encoding (y = p + 1,
     * small_order_keys[6]) so the verify-side check is exercised against
     * the canonical-form bypass route, not just the byte-for-byte
     * identity. The forged sig (R = B, S = 1) verifies for an identity
     * public key only - other small-order points would reject it on the
     * math alone, so they aren't useful here. */
    {
        static const word32 identity_indices[] = { 0, 6 };
        const char* msg = "forged message";
        word32 j;

        for (j = 0;
             j < sizeof(identity_indices)/sizeof(identity_indices[0]);
             j++) {
            word32 idx = identity_indices[j];
            int verify_result = 1;
            int rc;

            XMEMSET(&key, 0, sizeof(key));
            ExpectIntEQ(wc_ed25519_init(&key), 0);
            ExpectIntEQ(wc_ed25519_import_public_ex(small_order_keys[idx],
                ED25519_PUB_KEY_SIZE, &key, 1), 0);
            rc = wc_ed25519_verify_msg(forged_sig, sizeof(forged_sig),
                (const byte*)msg, (word32)XSTRLEN(msg), &verify_result, &key);
            if (rc != WC_NO_ERR_TRACE(BAD_FUNC_ARG) || verify_result != 0) {
                fprintf(stderr, "verify_msg with identity-equiv "
                    "small_order_keys[%u]: rc=%d verify_result=%d "
                    "(expected BAD_FUNC_ARG and 0)\n",
                    (unsigned)idx, rc, verify_result);
            }
            ExpectIntEQ(rc, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(verify_result, 0);
            wc_ed25519_free(&key);
        }
    }
#endif
#endif
    return EXPECT_RESULT();
}

/*
 * Test wc_ed25519_verify_msg() in non-blocking mode.
 * Uses RFC 8032 test vectors 1-3 (1-, 1-, and 2-byte messages).
 * Each verify is driven in a do/while loop until it returns 0 (done)
 * or a real error, mirroring how an embedded application would yield
 * between steps.  A corrupted signature is also checked for rejection.
 */
int test_wc_ed25519_verify_msg_nonblock(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    defined(WC_ED25519_NONBLOCK)
    /* RFC 8032 test vectors 1-3 */
    static const byte pKey1[] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
        0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
        0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };
    static const byte pKey2[] = {
        0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,
        0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,
        0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c
    };
    static const byte pKey3[] = {
        0xfc,0x51,0xcd,0x8e,0x62,0x18,0xa1,0xa3,
        0x8d,0xa4,0x7e,0xd0,0x02,0x30,0xf0,0x58,
        0x08,0x16,0xed,0x13,0xba,0x33,0x03,0xac,
        0x5d,0xeb,0x91,0x15,0x48,0x90,0x80,0x25
    };
    static const byte sig1[] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
        0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
        0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
        0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
        0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };
    static const byte sig2[] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,
        0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,
        0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,
        0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,
        0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
    };
    static const byte sig3[] = {
        0x62,0x91,0xd6,0x57,0xde,0xec,0x24,0x02,
        0x48,0x27,0xe6,0x9c,0x3a,0xbe,0x01,0xa3,
        0x0c,0xe5,0x48,0xa2,0x84,0x74,0x3a,0x44,
        0x5e,0x36,0x80,0xd7,0xdb,0x5a,0xc3,0xac,
        0x18,0xff,0x9b,0x53,0x8d,0x16,0xf2,0x90,
        0xae,0x67,0xf7,0x60,0x98,0x4d,0xc6,0x59,
        0x4a,0x7c,0x15,0xe9,0x71,0x6e,0xd2,0x8d,
        0xc0,0x27,0xbe,0xce,0xea,0x1e,0xc4,0x0a
    };
    static const byte msg1[] = { 0x00 }; /* Workaround since C-lang doesn't allow zero length array */
    static const byte msg2[] = { 0x72 };
    static const byte msg3[] = { 0xAF, 0x82 };

    static const byte*  pKeys[] = { pKey1,       pKey2,       pKey3       };
    static const byte*  sigs[]  = { sig1,        sig2,        sig3        };
    static const byte*  msgs[]  = { msg1,        msg2,        msg3        };
    static const word32 msgSz[] = { 0,    sizeof(msg2), sizeof(msg3)      };

    ed25519_key      key;
    ed25519_nb_ctx_t nb_ctx;
    byte             bad_sig[ED25519_SIG_SIZE];
    byte             bad_msg[2];
    int              verify;
    int              ret;
    int              i;

    XMEMSET(&key,    0, sizeof(key));
    XMEMSET(&nb_ctx, 0, sizeof(nb_ctx));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_set_nonblock(&key, &nb_ctx), 0);

    for (i = 0; i < 3; i++) {
        ExpectIntEQ(wc_ed25519_import_public(pKeys[i], ED25519_KEY_SIZE, &key),
                    0);

        /* non-blocking verify good signature */
        verify = 0;
        do {
            ret = wc_ed25519_verify_msg(sigs[i], ED25519_SIG_SIZE,
                                        msgs[i], msgSz[i], &verify, &key);
        } while (ret == MP_WOULDBLOCK);
        ExpectIntEQ(ret, 0);
        ExpectIntEQ(verify, 1);

        /* verify corrupted last byte of signature - must fail */
        XMEMCPY(bad_sig, sigs[i], ED25519_SIG_SIZE);
        bad_sig[ED25519_SIG_SIZE - 1] = bad_sig[ED25519_SIG_SIZE - 1] + 1;
        verify = 0;
        do {
            ret = wc_ed25519_verify_msg(bad_sig, ED25519_SIG_SIZE,
                                        msgs[i], msgSz[i], &verify, &key);
        } while (ret == MP_WOULDBLOCK);
        ExpectIntNE(ret, 0);
        ExpectIntEQ(verify, 0);

        /* verify corrupted first byte of signature - must fail */
        XMEMCPY(bad_sig, sigs[i], ED25519_SIG_SIZE);
        bad_sig[0] = bad_sig[0] + 1;
        verify = 0;
        do {
            ret = wc_ed25519_verify_msg(bad_sig, ED25519_SIG_SIZE,
                                        msgs[i], msgSz[i], &verify, &key);
        } while (ret == MP_WOULDBLOCK);
        ExpectIntNE(ret, 0);
        ExpectIntEQ(verify, 0);
    }

    /* tampered message with valid signature must fail (pKey3/sig3 still loaded) */
    XMEMCPY(bad_msg, msg3, sizeof(msg3));
    bad_msg[0] ^= 0x01;
    verify = 0;
    do {
        ret = wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE,
                                    bad_msg, sizeof(msg3), &verify, &key);
    } while (ret == MP_WOULDBLOCK);
    ExpectIntNE(ret, 0);
    ExpectIntEQ(verify, 0);

    /* bad args */
    ExpectIntEQ(wc_ed25519_verify_msg(NULL, ED25519_SIG_SIZE,
        msg3, sizeof(msg3), &verify, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE,
        NULL, sizeof(msg3), &verify, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE,
        msg3, sizeof(msg3), NULL, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE,
        msg3, sizeof(msg3), &verify, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE - 1,
        msg3, sizeof(msg3), &verify, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE + 1,
        msg3, sizeof(msg3), &verify, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* verify falls back to blocking after disabling non-block mode */
    wc_ed25519_set_nonblock(&key, NULL);
    verify = 0;
    ExpectIntEQ(wc_ed25519_verify_msg(sig3, ED25519_SIG_SIZE,
        msg3, sizeof(msg3), &verify, &key), 0);
    ExpectIntEQ(verify, 1);

    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
}

/*
 * Test wc_ed25519_make_key() in non-blocking mode.
 * Drives the keygen loop until completion, verifies the key pair by sign +
 * verify, checks bad-args, and confirms blocking fallback after disabling
 * non-block mode.
 */
int test_wc_ed25519_make_key_nonblock(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY) && \
    defined(WC_ED25519_NONBLOCK) && defined(HAVE_ED25519_SIGN) && \
    defined(HAVE_ED25519_VERIFY)
    ed25519_key      key;
    ed25519_nb_ctx_t nb_ctx;
    WC_RNG           rng;
    int              ret;

    XMEMSET(&key,    0, sizeof(key));
    XMEMSET(&nb_ctx, 0, sizeof(nb_ctx));
    XMEMSET(&rng,    0, sizeof(rng));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_set_nonblock(&key, &nb_ctx), 0);

    /* non-blocking key generation */
    do {
        ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
    } while (ret == MP_WOULDBLOCK);
    ExpectIntEQ(ret, 0);
    ExpectIntEQ(key.privKeySet, 1);
    ExpectIntEQ(key.pubKeySet,  1);

    /* verify generated key pair by sign + verify */
    if (EXPECT_SUCCESS()) {
        byte   sig[ED25519_SIG_SIZE];
        word32 sigLen = sizeof(sig);
        byte   msg[]  = "nonblock keygen test";
        int    verified = 0;

        wc_ed25519_set_nonblock(&key, NULL);
        ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, &key),
            0);
        ExpectIntEQ(wc_ed25519_verify_msg(sig, sigLen, msg, sizeof(msg),
            &verified, &key), 0);
        ExpectIntEQ(verified, 1);
    }

    /* bad args */
    ExpectIntEQ(wc_ed25519_set_nonblock(&key, &nb_ctx), 0);
    ExpectIntEQ(wc_ed25519_make_key(NULL, ED25519_KEY_SIZE, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE - 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* blocking fallback after disabling non-block mode */
    wc_ed25519_set_nonblock(&key, NULL);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    ExpectIntEQ(key.privKeySet, 1);
    ExpectIntEQ(key.pubKeySet,  1);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
}

/*
 * Test wc_ed25519_sign_msg() in non-blocking mode.
 * Uses a blocking-generated key pair, then drives the sign loop until
 * completion and verifies the resulting signature.
 * Also checks bad-args and blocking fallback after disabling non-block mode.
 */
int test_wc_ed25519_sign_msg_nonblock(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN) && \
    defined(HAVE_ED25519_VERIFY) && defined(WC_ED25519_NONBLOCK)
    ed25519_key      key;
    ed25519_nb_ctx_t nb_ctx;
    WC_RNG           rng;
    byte             sig[ED25519_SIG_SIZE];
    word32           sigLen;
    byte             msg[] = "nonblock sign test message";
    int              verified;
    int              ret;

    XMEMSET(&key,    0, sizeof(key));
    XMEMSET(&nb_ctx, 0, sizeof(nb_ctx));
    XMEMSET(&rng,    0, sizeof(rng));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* generate key pair in blocking mode */
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    /* non-blocking sign */
    ExpectIntEQ(wc_ed25519_set_nonblock(&key, &nb_ctx), 0);
    sigLen = sizeof(sig);
    do {
        ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, &key);
    } while (ret == MP_WOULDBLOCK);
    ExpectIntEQ(ret, 0);
    ExpectIntEQ(sigLen, ED25519_SIG_SIZE);

    /* verify the signature produced by non-blocking sign */
    wc_ed25519_set_nonblock(&key, NULL);
    verified = 0;
    ExpectIntEQ(wc_ed25519_verify_msg(sig, sigLen, msg, sizeof(msg),
        &verified, &key), 0);
    ExpectIntEQ(verified, 1);

    /* corrupted signature must fail */
    sig[ED25519_SIG_SIZE - 1]++;
    verified = 0;
    ExpectIntNE(wc_ed25519_verify_msg(sig, sigLen, msg, sizeof(msg),
        &verified, &key), 0);
    ExpectIntEQ(verified, 0);
    sig[ED25519_SIG_SIZE - 1]--;

    /* bad args */
    ExpectIntEQ(wc_ed25519_set_nonblock(&key, &nb_ctx), 0);
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519_sign_msg(NULL, sizeof(msg), sig, &sigLen, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), NULL, &sigLen, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* blocking fallback after disabling non-block mode */
    wc_ed25519_set_nonblock(&key, NULL);
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, &key), 0);
    ExpectIntEQ(sigLen, ED25519_SIG_SIZE);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
}

