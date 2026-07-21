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
    defined(HAVE_ED25519_MAKE_KEY) && \
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
    defined(HAVE_ED25519_MAKE_KEY) && \
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
    defined(HAVE_ED25519_MAKE_KEY) && \
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
    defined(HAVE_ED25519_KEY_IMPORT) && defined(HAVE_ED25519_MAKE_KEY) && \
    defined(WOLFSSL_KEY_GEN)
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
 * MC/DC wave 1 - decision-targeted negative/edge paths for wolfcrypt/src/
 * ed25519.c that the existing API tests above do not drive. Split into
 * several smaller functions (rather than one large one), matching the
 * lesson learned on the ecc.c MC/DC wave (a single large function tripped
 * a stack-corrupting crash under -fcoverage-mcdc + -O0).
 */

/*
 * Testing the Ed25519ctx/Ed25519ph sign+verify variants and the shared
 * context==NULL-with-nonzero-contextLen / Ed25519ph length checks in
 * wc_ed25519_sign_msg_ex and wc_ed25519_verify_msg_ex (called both via
 * the ctx/ph wrappers and directly with type as an argument).
 */
int test_wc_ed25519_sign_verify_ctx_ph(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN) && \
    defined(HAVE_ED25519_VERIFY)
    WC_RNG      rng;
    ed25519_key key;
    byte        msg[] = "context-and-prehash coverage message";
    byte        hash[64]; /* WC_SHA512_DIGEST_SIZE */
    byte        ctx[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte        sig[ED25519_SIG_SIZE];
    word32      sigLen;
    int         verify_ok;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(hash, 0x42, sizeof(hash));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    /* Ed25519ctx round trip: type==Ed25519ctx true side, real context. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519ctx_sign_msg(msg, sizeof(msg), sig, &sigLen, &key,
        ctx, sizeof(ctx)), 0);
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519ctx_verify_msg(sig, sigLen, msg, sizeof(msg),
        &verify_ok, &key, ctx, sizeof(ctx)), 0);
    ExpectIntEQ(verify_ok, 1);

    /* Ed25519ph round trip via hash and via full message, type==Ed25519ph
     * true side, WC_SHA512_DIGEST_SIZE length check false side (equal). */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519ph_sign_hash(hash, sizeof(hash), sig, &sigLen,
        &key, ctx, sizeof(ctx)), 0);
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519ph_verify_hash(sig, sigLen, hash, sizeof(hash),
        &verify_ok, &key, ctx, sizeof(ctx)), 0);
    ExpectIntEQ(verify_ok, 1);

    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519ph_sign_msg(msg, sizeof(msg), sig, &sigLen, &key,
        ctx, sizeof(ctx)), 0);
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519ph_verify_msg(sig, sigLen, msg, sizeof(msg),
        &verify_ok, &key, ctx, sizeof(ctx)), 0);
    ExpectIntEQ(verify_ok, 1);

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)
    /* Ed25519ph length check true side: wrong-size "hash" input. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519_sign_msg_ex(hash, sizeof(hash) - 1, sig, &sigLen,
        &key, (byte)Ed25519ph, ctx, sizeof(ctx)),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519_verify_msg_ex(sig, sizeof(sig), hash,
        sizeof(hash) - 1, &verify_ok, &key, (byte)Ed25519ph, ctx,
        sizeof(ctx)), WC_NO_ERR_TRACE(BAD_LENGTH_E));
#endif

    /* context==NULL && contextLen!=0 compound: TRUE side, direct low-level
     * calls (the ctx/ph wrappers above always pass a real, non-NULL
     * context, so this operand's TRUE side needs the _ex entry point). */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed25519_sign_msg_ex(msg, sizeof(msg), sig, &sigLen, &key,
        (byte)Ed25519, NULL, 5), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519_verify_msg_ex(sig, sizeof(sig), msg, sizeof(msg),
        &verify_ok, &key, (byte)Ed25519, NULL, 5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_sign_verify_ctx_ph */

/*
 * Testing wc_ed25519_verify_msg_init/_update/_final directly: NULL/size
 * argument checks, the non-canonical-S high-bits rejection, and the
 * S >= order boundary loop (both the "greater" and "equal" halves).
 */
int test_wc_ed25519_verify_streaming(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN) && \
    defined(HAVE_ED25519_VERIFY) && defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    WC_RNG      rng;
    ed25519_key key;
    byte        msg[] = "streaming verify coverage message";
    byte        sig[ED25519_SIG_SIZE];
    word32      sigLen = sizeof(sig);
    int         verify_ok;
    /* ed25519 order in little endian (mirrors the file-static table). */
    static const byte order[] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    byte badSig[ED25519_SIG_SIZE];
    byte ctx[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(WC_RNG));

    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    ExpectIntEQ(wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigLen, &key), 0);

    /* Valid streaming round trip, message split across two update calls. */
    ExpectIntEQ(wc_ed25519_verify_msg_init(sig, sigLen, &key, (byte)Ed25519,
        NULL, 0), 0);
    ExpectIntEQ(wc_ed25519_verify_msg_update(msg, 10, &key), 0);
    ExpectIntEQ(wc_ed25519_verify_msg_update(msg + 10, sizeof(msg) - 10,
        &key), 0);
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519_verify_msg_final(sig, sigLen, &verify_ok, &key),
        0);
    ExpectIntEQ(verify_ok, 1);

    /* init: NULL args. */
    ExpectIntEQ(wc_ed25519_verify_msg_init(NULL, sigLen, &key, (byte)Ed25519,
        NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)
    ExpectIntEQ(wc_ed25519_verify_msg_init(sig, sigLen, NULL, (byte)Ed25519,
        NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    /* init: sigLen wrong. */
    ExpectIntEQ(wc_ed25519_verify_msg_init(sig, sigLen - 1, &key,
        (byte)Ed25519, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* init: non-canonical S (top 3 bits of sig[63] set). */
    XMEMCPY(badSig, sig, sizeof(badSig));
    badSig[ED25519_SIG_SIZE - 1] |= 0xE0;
    ExpectIntEQ(wc_ed25519_verify_msg_init(badSig, sizeof(badSig), &key,
        (byte)Ed25519, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* update: NULL msgSegment, then NULL key (independent operand). */
    ExpectIntEQ(wc_ed25519_verify_msg_update(NULL, 4, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)
    ExpectIntEQ(wc_ed25519_verify_msg_update(msg, 4, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* init: context==NULL/contextLen!=0 compound, explicit both-sides
     * pairing within this function (type left as plain Ed25519 so the
     * context is never actually consumed by the hash math either way,
     * isolating the argument-check decision itself). */
    ExpectIntEQ(wc_ed25519_verify_msg_init(sig, sigLen, &key, (byte)Ed25519,
        NULL, 5), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg_init(sig, sigLen, &key, (byte)Ed25519,
        ctx, sizeof(ctx)), 0);
    ExpectIntEQ(wc_ed25519_verify_msg_update(msg, sizeof(msg), &key), 0);
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519_verify_msg_final(sig, sigLen, &verify_ok, &key),
        0);
    ExpectIntEQ(verify_ok, 1);

    /* final: NULL args. */
    verify_ok = 0;
    ExpectIntEQ(wc_ed25519_verify_msg_final(NULL, sigLen, &verify_ok, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_verify_msg_final(sig, sigLen, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GT(6,0,0)
    ExpectIntEQ(wc_ed25519_verify_msg_final(sig, sigLen, &verify_ok, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    /* final: sigLen wrong. */
    ExpectIntEQ(wc_ed25519_verify_msg_final(sig, sigLen - 1, &verify_ok,
        &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* S order-boundary loop lives in ed25519_verify_msg_final_with_sha
     * (NOT init -- init only checks the top-3-bits non-canonical form),
     * and runs before ed25519_hash_final() touches the sha state, so it
     * can be reached by calling wc_ed25519_verify_msg_final() directly on
     * a freshly-init'd key without a prior init/update pair.
     *
     * S == order exactly: the "not larger, not smaller, loop runs off the
     * end" (i == -1) equal-all-bytes rejection. */
    XMEMCPY(badSig, sig, sizeof(badSig));
    XMEMCPY(badSig + (ED25519_SIG_SIZE / 2), order, sizeof(order));
    verify_ok = 1;
    ExpectIntEQ(wc_ed25519_verify_msg_final(badSig, sizeof(badSig),
        &verify_ok, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* S > order: bump the top byte by one so the "bigger than order"
     * branch of the boundary loop fires on the first (highest) byte. */
    XMEMCPY(badSig, sig, sizeof(badSig));
    XMEMCPY(badSig + (ED25519_SIG_SIZE / 2), order, sizeof(order));
    badSig[ED25519_SIG_SIZE - 1] = (byte)(order[sizeof(order) - 1] + 1);
    verify_ok = 1;
    ExpectIntEQ(wc_ed25519_verify_msg_final(badSig, sizeof(badSig),
        &verify_ok, &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* Legitimate structural pass-through (order/small-order/on-curve all
     * OK) but a mismatching R half: reaches the real ConstantCompare
     * rejection (GAPS: under WOLFSSL_CHECK_VER_FAULTS, the "ret==0"
     * operand of the redundant post-verify compound needs its FALSE side,
     * i.e. the primary comparison already having failed). */
    XMEMCPY(badSig, sig, sizeof(badSig));
    badSig[0] ^= 0xFF;
    ExpectIntEQ(wc_ed25519_verify_msg_init(badSig, sizeof(badSig), &key,
        (byte)Ed25519, NULL, 0), 0);
    ExpectIntEQ(wc_ed25519_verify_msg_update(msg, sizeof(msg), &key), 0);
    verify_ok = 1;
    ExpectIntEQ(wc_ed25519_verify_msg_final(badSig, sizeof(badSig),
        &verify_ok, &key), WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntEQ(verify_ok, 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_verify_streaming */

/*
 * Testing wc_ed25519_check_key edge cases: NULL key, pubKeySet==0,
 * privKeySet-mismatch, and the no-private-key Y-range boundary decision
 * (key->p[31]&0x7f==0x7f, the byte-loop, and the p[0]<0xed compound).
 */
int test_wc_ed25519_check_key_edgecases(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(HAVE_ED25519_KEY_EXPORT)
    WC_RNG      rng;
    ed25519_key key;
    byte        pub[ED25519_PUB_KEY_SIZE];
    word32      pubSz = sizeof(pub);

    XMEMSET(&rng, 0, sizeof(WC_RNG));

    /* key == NULL. */
    ExpectIntEQ(wc_ed25519_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* pubKeySet == 0. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
    wc_ed25519_free(&key);

    /* privKeySet==1 path, public key mutated after generation so the
     * make-and-compare mismatches. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);
    key.p[0] ^= 0xFF;
    ExpectIntEQ(wc_ed25519_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);

    /* No private key: Y-range boundary, "order or higher" (deterministic
     * reject: top byte 0x7f, all mid bytes 0xff, low byte 0xff so the
     * post-loop p[0]<0xed check is false -> stays PUBLIC_KEY_E without
     * reaching ge_frombytes_negate_vartime). */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    XMEMSET(pub, 0xff, sizeof(pub));
    pub[ED25519_PUB_KEY_SIZE - 1] = 0x7f;
    XMEMCPY(key.p, pub, sizeof(pub));
    key.pubKeySet = 1;
    ExpectIntEQ(wc_ed25519_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
    wc_ed25519_free(&key);

    /* No private key, Y-range boundary loop breaks early (a middle byte
     * is not 0xff): first operand's false side, second never evaluated,
     * ret reset to 0 by the break -- lands in ge_frombytes_negate_vartime
     * on an arbitrary (not necessarily on-curve) point, so only the
     * decision shape is asserted here, not a specific final verdict. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    XMEMSET(pub, 0xff, sizeof(pub));
    pub[ED25519_PUB_KEY_SIZE - 1] = 0x7f;
    pub[15] = 0x01;
    XMEMCPY(key.p, pub, sizeof(pub));
    key.pubKeySet = 1;
    ExpectTrue((wc_ed25519_check_key(&key) == 0) ||
        (wc_ed25519_check_key(&key) == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    wc_ed25519_free(&key);

    /* No private key, Y-range boundary "order or higher" false side (the
     * pass-through p[0]<0xed case, distinct from the p-1 small-order
     * table entry at p[0]==0xec): again only the decision shape is
     * asserted, not a specific final verdict. */
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    XMEMSET(pub, 0xff, sizeof(pub));
    pub[ED25519_PUB_KEY_SIZE - 1] = 0x7f;
    pub[0] = 0xeb;
    XMEMCPY(key.p, pub, sizeof(pub));
    key.pubKeySet = 1;
    ExpectTrue((wc_ed25519_check_key(&key) == 0) ||
        (wc_ed25519_check_key(&key) == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    wc_ed25519_free(&key);

    (void)pubSz;
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_check_key_edgecases */

/*
 * Testing wc_ed25519_import_public_ex's three input-shape branches
 * (compressed-prefix, plain-length, else BAD_FUNC_ARG) and
 * wc_ed25519_import_private_key_ex's pub==NULL argument-derivation
 * compound.
 */
int test_wc_ed25519_import_variants(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_key key;
    byte        compressed[ED25519_PUB_KEY_SIZE + 1];

    XMEMSET(compressed, 0, sizeof(compressed));
    compressed[0] = 0x40;
    XMEMSET(compressed + 1, 7, ED25519_PUB_KEY_SIZE);

    /* compressed-prefix branch: in[0]==0x40 && inLen==PUB_KEY_SIZE+1. */
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_import_public_ex(compressed, sizeof(compressed),
        &key, 1), 0);
    ExpectIntEQ(XMEMCMP(key.p, compressed + 1, ED25519_PUB_KEY_SIZE), 0);
    wc_ed25519_free(&key);

    /* wrong length, not matching any of the three recognized shapes. */
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_import_public_ex(compressed, ED25519_PUB_KEY_SIZE
        - 1, &key, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_ed25519_free(&key);

    /* GAPS: in[0]==0x40 compound's second operand FALSE side (right
     * prefix byte, wrong length) -- falls through to the plain
     * inLen==PUB_KEY_SIZE branch since compressed[0]==0x40 is itself a
     * valid arbitrary key byte there. */
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_import_public_ex(compressed, ED25519_PUB_KEY_SIZE,
        &key, 1), 0);
    ExpectIntEQ(XMEMCMP(key.p, compressed, ED25519_PUB_KEY_SIZE), 0);
    wc_ed25519_free(&key);

    /* GAPS: in[0]==0x04 compound's second operand FALSE side (right
     * prefix byte, inLen not > 2*PUB_KEY_SIZE) -- same fallthrough. */
    compressed[0] = 0x04;
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_ed25519_import_public_ex(compressed, ED25519_PUB_KEY_SIZE,
        &key, 1), 0);
    ExpectIntEQ(XMEMCMP(key.p, compressed, ED25519_PUB_KEY_SIZE), 0);
    wc_ed25519_free(&key);

    /* wc_ed25519_import_private_only argument checks (GAPS: entirely
     * untested elsewhere). */
    {
        ed25519_key privKey;
        byte        privOnly[ED25519_KEY_SIZE];

        XMEMSET(privOnly, 5, sizeof(privOnly));

        ExpectIntEQ(wc_ed25519_import_private_only(NULL, sizeof(privOnly),
            &key), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ed25519_init(&privKey), 0);
        ExpectIntEQ(wc_ed25519_import_private_only(privOnly,
            sizeof(privOnly), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ed25519_import_private_only(privOnly,
            sizeof(privOnly) - 1, &privKey), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ed25519_import_private_only(privOnly,
            sizeof(privOnly), &privKey), 0);
        ExpectIntEQ(XMEMCMP(privKey.k, privOnly, sizeof(privOnly)), 0);
        wc_ed25519_free(&privKey);
    }

#if defined(HAVE_ED25519_KEY_EXPORT) && defined(HAVE_ED25519_MAKE_KEY)
    /* wc_ed25519_import_private_key_ex: pub==NULL branch. */
    {
        WC_RNG      rng;
        ed25519_key fullKey;
        byte        priv[ED25519_PRV_KEY_SIZE];
        word32      privSz = sizeof(priv);

        XMEMSET(&rng, 0, sizeof(WC_RNG));
        ExpectIntEQ(wc_ed25519_init(&fullKey), 0);
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &fullKey),
            0);
        PRIVATE_KEY_UNLOCK();
        ExpectIntEQ(wc_ed25519_export_private(&fullKey, priv, &privSz), 0);
        PRIVATE_KEY_LOCK();

        /* pub==NULL && pubSz!=0: BAD_FUNC_ARG. */
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_ed25519_import_private_key_ex(priv, privSz, NULL, 4,
            &key, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_ed25519_free(&key);

        /* pub==NULL && privSz!=PRV_KEY_SIZE: BAD_FUNC_ARG. */
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_ed25519_import_private_key_ex(priv, ED25519_KEY_SIZE,
            NULL, 0, &key, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_ed25519_free(&key);

        /* pub==NULL, privSz==PRV_KEY_SIZE: derive pub from priv+32. */
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_ed25519_import_private_key_ex(priv, privSz, NULL, 0,
            &key, 1), 0);
        ExpectIntEQ(XMEMCMP(key.p, priv + ED25519_KEY_SIZE,
            ED25519_PUB_KEY_SIZE), 0);
        wc_ed25519_free(&key);

        /* pub!=NULL but pubSz < PUB_KEY_SIZE: BAD_FUNC_ARG. */
        ExpectIntEQ(wc_ed25519_init(&key), 0);
        ExpectIntEQ(wc_ed25519_import_private_key_ex(priv, ED25519_KEY_SIZE,
            priv + ED25519_KEY_SIZE, ED25519_PUB_KEY_SIZE - 1, &key, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        wc_ed25519_free(&key);

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
        wc_ed25519_free(&fullKey);
    }
#endif /* HAVE_ED25519_KEY_EXPORT */
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_import_variants */

/*
 * Testing wc_ed25519_make_public's own argument-check compound (GAPS:
 * exercised elsewhere only indirectly, through wc_ed25519_make_key, which
 * never passes it a bad pubKey/pubKeySz).
 */
int test_wc_ed25519_make_public_argchecks(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_MAKE_KEY)
    WC_RNG        rng;
    ed25519_key   key;
    unsigned char pubKey[ED25519_PUB_KEY_SIZE];

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_ed25519_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key), 0);

    /* key==NULL||pubKey==NULL||pubKeySz!=SIZE compound, each operand's
     * TRUE side individually. */
    ExpectIntEQ(wc_ed25519_make_public(NULL, pubKey, sizeof(pubKey)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_public(&key, NULL, sizeof(pubKey)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed25519_make_public(&key, pubKey, sizeof(pubKey) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* all-false: valid call, also completes the (ret==0 && !privKeySet)
     * compound's first operand's FALSE side (ret already BAD_FUNC_ARG from
     * the pubKey==NULL case above never reaches key->privKeySet). */
    ExpectIntEQ(wc_ed25519_make_public(&key, pubKey, sizeof(pubKey)), 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed25519_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed25519_make_public_argchecks */

