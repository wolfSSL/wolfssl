/* test_ossl_ecx.c
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

#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ec25519.h>
#include <wolfssl/openssl/ed25519.h>
#include <wolfssl/openssl/ec448.h>
#include <wolfssl/openssl/ed448.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_ecx.h>

/*******************************************************************************
 * ECX OpenSSL compatibility API Testing
 ******************************************************************************/

#ifdef OPENSSL_EXTRA
int test_EC25519(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE25519) && defined(WOLFSSL_KEY_GEN)
    byte         priv[CURVE25519_KEYSIZE];
    unsigned int privSz = CURVE25519_KEYSIZE;
    byte         pub[CURVE25519_KEYSIZE];
    unsigned int pubSz = CURVE25519_KEYSIZE;
    byte         priv2[CURVE25519_KEYSIZE];
    unsigned int priv2Sz = CURVE25519_KEYSIZE;
    byte         pub2[CURVE25519_KEYSIZE];
    unsigned int pub2Sz = CURVE25519_KEYSIZE;
    byte         shared[CURVE25519_KEYSIZE];
    unsigned int sharedSz = CURVE25519_KEYSIZE;
    byte         shared2[CURVE25519_KEYSIZE];
    unsigned int shared2Sz = CURVE25519_KEYSIZE;

    /* Bad parameter testing of key generation. */
    ExpectIntEQ(wolfSSL_EC25519_generate_key(NULL,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(NULL, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(NULL, &privSz,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv,    NULL,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv, &privSz,  pub,   NULL), 0);
    /*   Bad length */
    privSz = 1;
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv, &privSz, pub, &pubSz), 0);
    privSz = CURVE25519_KEYSIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv, &privSz, pub, &pubSz), 0);
    pubSz = CURVE25519_KEYSIZE;

    /* Good case of generating key. */
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv, &privSz, pub, &pubSz), 1);
    ExpectIntEQ(wolfSSL_EC25519_generate_key(priv2, &priv2Sz, pub2, &pub2Sz),
        1);
    ExpectIntEQ(privSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(pubSz, CURVE25519_KEYSIZE);

    /* Bad parameter testing of shared key. */
    ExpectIntEQ(wolfSSL_EC25519_shared_key(  NULL,      NULL, NULL, privSz,
        NULL,  pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(  NULL, &sharedSz, NULL, privSz,
        NULL, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(  NULL, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, NULL, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
        NULL, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(  NULL, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared,      NULL, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, NULL, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
        NULL, pubSz), 0);
    /*   Bad length. */
    sharedSz = 1;
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    sharedSz = CURVE25519_KEYSIZE;
    privSz = 1;
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    privSz = CURVE25519_KEYSIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    pubSz = CURVE25519_KEYSIZE;

    /* Good case of shared key. */
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared, &sharedSz, priv, privSz,
        pub2, pub2Sz), 1);
    ExpectIntEQ(wolfSSL_EC25519_shared_key(shared2, &shared2Sz, priv2, priv2Sz,
        pub, pubSz), 1);
    ExpectIntEQ(sharedSz, CURVE25519_KEYSIZE);
    ExpectIntEQ(shared2Sz, CURVE25519_KEYSIZE);
    ExpectIntEQ(XMEMCMP(shared, shared2, sharedSz), 0);
#endif /* HAVE_CURVE25519 && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();
}

int test_ED25519(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT) && \
    defined(WOLFSSL_KEY_GEN)
    byte         priv[ED25519_PRV_KEY_SIZE];
    unsigned int privSz = (unsigned int)sizeof(priv);
    byte         pub[ED25519_PUB_KEY_SIZE];
    unsigned int pubSz = (unsigned int)sizeof(pub);
#if defined(HAVE_ED25519_SIGN) && defined(HAVE_ED25519_KEY_IMPORT)
    const char*  msg = TEST_STRING;
    unsigned int msglen = (unsigned int)TEST_STRING_SZ;
    byte         sig[ED25519_SIG_SIZE];
    unsigned int sigSz = (unsigned int)sizeof(sig);
#endif /* HAVE_ED25519_SIGN && HAVE_ED25519_KEY_IMPORT */

    /* Bad parameter testing of key generation. */
    ExpectIntEQ(wolfSSL_ED25519_generate_key(NULL,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(NULL, &privSz, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(NULL,    NULL,  pub,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(NULL,    NULL, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(NULL, &privSz,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv,    NULL,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv, &privSz,  pub,   NULL), 0);
    /*   Bad length. */
    privSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv, &privSz, pub, &pubSz), 0);
    privSz = ED25519_PRV_KEY_SIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv, &privSz, pub, &pubSz), 0);
    pubSz = ED25519_PUB_KEY_SIZE;

    /* Good case of generating key. */
    ExpectIntEQ(wolfSSL_ED25519_generate_key(priv, &privSz, pub, &pubSz),
        1);
    ExpectIntEQ(privSz, ED25519_PRV_KEY_SIZE);
    ExpectIntEQ(pubSz, ED25519_PUB_KEY_SIZE);

#if defined(HAVE_ED25519_SIGN) && defined(HAVE_ED25519_KEY_IMPORT)
    /* Bad parameter testing of signing. */
    ExpectIntEQ(wolfSSL_ED25519_sign(      NULL, msglen, NULL, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, NULL, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign(      NULL, msglen, priv, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign(      NULL, msglen, NULL, privSz, sig,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign(      NULL, msglen, NULL, privSz, NULL,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign(      NULL, msglen, priv, privSz,  sig,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, NULL, privSz,  sig,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, priv, privSz,  NULL,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, priv, privSz,  sig,
          NULL), 0);
    /*   Bad length. */
    privSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 0);
    privSz = ED25519_PRV_KEY_SIZE;
    sigSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 0);
    sigSz = ED25519_SIG_SIZE;

    /* Good case of signing. */
    ExpectIntEQ(wolfSSL_ED25519_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 1);
    ExpectIntEQ(sigSz, ED25519_SIG_SIZE);

#ifdef HAVE_ED25519_VERIFY
    /* Bad parameter testing of verification. */
    ExpectIntEQ(wolfSSL_ED25519_verify(      NULL, msglen, NULL, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, NULL, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify(      NULL, msglen,  pub, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify(      NULL, msglen, NULL, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify(      NULL, msglen,  pub, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, NULL, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen,  pub, pubSz, NULL,
        sigSz), 0);
    /*   Bad length. */
    pubSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
    pubSz = ED25519_PUB_KEY_SIZE;
    sigSz = 1;
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
    sigSz = ED25519_SIG_SIZE;

    /* Good case of verification. */
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 1);
    /* Bad signature. */
    if (EXPECT_SUCCESS()) {
        sig[1] ^= 0x80;
    }
    ExpectIntEQ(wolfSSL_ED25519_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN && HAVE_ED25519_KEY_IMPORT */
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_EXPORT && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();
}

int test_EC448(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CURVE448) && defined(WOLFSSL_KEY_GEN)
    byte         priv[CURVE448_KEY_SIZE];
    unsigned int privSz = CURVE448_KEY_SIZE;
    byte         pub[CURVE448_KEY_SIZE];
    unsigned int pubSz = CURVE448_KEY_SIZE;
    byte         priv2[CURVE448_KEY_SIZE];
    unsigned int priv2Sz = CURVE448_KEY_SIZE;
    byte         pub2[CURVE448_KEY_SIZE];
    unsigned int pub2Sz = CURVE448_KEY_SIZE;
    byte         shared[CURVE448_KEY_SIZE];
    unsigned int sharedSz = CURVE448_KEY_SIZE;
    byte         shared2[CURVE448_KEY_SIZE];
    unsigned int shared2Sz = CURVE448_KEY_SIZE;

    /* Bad parameter testing of key generation. */
    ExpectIntEQ(wolfSSL_EC448_generate_key(NULL,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_EC448_generate_key(NULL, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_generate_key(NULL, &privSz,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv,    NULL,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv, &privSz,  pub,   NULL), 0);
    /*   Bad length. */
    privSz = 1;
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv, &privSz, pub, &pubSz), 0);
    privSz = CURVE448_KEY_SIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv, &privSz, pub, &pubSz), 0);
    pubSz = CURVE448_KEY_SIZE;

    /* Good case of generating key. */
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv, &privSz, pub, &pubSz), 1);
    ExpectIntEQ(wolfSSL_EC448_generate_key(priv2, &priv2Sz, pub2, &pub2Sz), 1);
    ExpectIntEQ(privSz, CURVE448_KEY_SIZE);
    ExpectIntEQ(pubSz, CURVE448_KEY_SIZE);

    /* Bad parameter testing of shared key. */
    ExpectIntEQ(wolfSSL_EC448_shared_key(  NULL,      NULL, NULL, privSz,
        NULL,  pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(  NULL, &sharedSz, NULL, privSz,
        NULL, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(  NULL, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, NULL, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
        NULL, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(  NULL, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared,      NULL, priv, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, NULL, privSz,
         pub, pubSz), 0);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
        NULL, pubSz), 0);
    /*   Bad length. */
    sharedSz = 1;
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    sharedSz = CURVE448_KEY_SIZE;
    privSz = 1;
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    privSz = CURVE448_KEY_SIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
         pub, pubSz), 0);
    pubSz = CURVE448_KEY_SIZE;

    /* Good case of shared key. */
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared, &sharedSz, priv, privSz,
        pub2, pub2Sz), 1);
    ExpectIntEQ(wolfSSL_EC448_shared_key(shared2, &shared2Sz, priv2, priv2Sz,
        pub, pubSz), 1);
    ExpectIntEQ(sharedSz, CURVE448_KEY_SIZE);
    ExpectIntEQ(shared2Sz, CURVE448_KEY_SIZE);
    ExpectIntEQ(XMEMCMP(shared, shared2, sharedSz), 0);
#endif /* HAVE_CURVE448 && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();
}

int test_ED448(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    defined(WOLFSSL_KEY_GEN)
    byte         priv[ED448_PRV_KEY_SIZE];
    unsigned int privSz = (unsigned int)sizeof(priv);
    byte         pub[ED448_PUB_KEY_SIZE];
    unsigned int pubSz = (unsigned int)sizeof(pub);
#if defined(HAVE_ED448_SIGN) && defined(HAVE_ED448_KEY_IMPORT)
    const char*  msg = TEST_STRING;
    unsigned int msglen = (unsigned int)TEST_STRING_SZ;
    byte         sig[ED448_SIG_SIZE];
    unsigned int sigSz = (unsigned int)sizeof(sig);
#endif /* HAVE_ED448_SIGN && HAVE_ED448_KEY_IMPORT */

    /* Bad parameter testing of key generation. */
    ExpectIntEQ(wolfSSL_ED448_generate_key(NULL,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv,    NULL, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(NULL, &privSz, NULL,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(NULL,    NULL,  pub,   NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(NULL,    NULL, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(NULL, &privSz,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv,    NULL,  pub, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv, &privSz, NULL, &pubSz), 0);
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv, &privSz,  pub,   NULL), 0);
    /*   Bad length. */
    privSz = 1;
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv, &privSz, pub, &pubSz), 0);
    privSz = ED448_PRV_KEY_SIZE;
    pubSz = 1;
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv, &privSz, pub, &pubSz), 0);
    pubSz = ED448_PUB_KEY_SIZE;

    /* Good case of generating key. */
    ExpectIntEQ(wolfSSL_ED448_generate_key(priv, &privSz, pub, &pubSz), 1);
    ExpectIntEQ(privSz, ED448_PRV_KEY_SIZE);
    ExpectIntEQ(pubSz, ED448_PUB_KEY_SIZE);

#if defined(HAVE_ED448_SIGN) && defined(HAVE_ED448_KEY_IMPORT)
    /* Bad parameter testing of signing. */
    ExpectIntEQ(wolfSSL_ED448_sign(      NULL, msglen, NULL, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, NULL, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_sign(      NULL, msglen, priv, privSz, NULL,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_sign(      NULL, msglen, NULL, privSz, sig,
          NULL), 0);
    ExpectIntEQ(wolfSSL_ED448_sign(      NULL, msglen, NULL, privSz, NULL,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_sign(      NULL, msglen, priv, privSz,  sig,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, NULL, privSz,  sig,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, priv, privSz,  NULL,
        &sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, priv, privSz,  sig,
          NULL), 0);
    /*   Bad length. */
    privSz = 1;
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 0);
    privSz = ED448_PRV_KEY_SIZE;
    sigSz = 1;
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 0);
    sigSz = ED448_SIG_SIZE;

    /* Good case of signing. */
    ExpectIntEQ(wolfSSL_ED448_sign((byte*)msg, msglen, priv, privSz, sig,
        &sigSz), 1);
    ExpectIntEQ(sigSz, ED448_SIG_SIZE);

#ifdef HAVE_ED448_VERIFY
   /* Bad parameter testing of verification. */
    ExpectIntEQ(wolfSSL_ED448_verify(      NULL, msglen, NULL, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, NULL, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify(      NULL, msglen,  pub, pubSz, NULL,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify(      NULL, msglen, NULL, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify(      NULL, msglen,  pub, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, NULL, pubSz,  sig,
        sigSz), 0);
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen,  pub, pubSz, NULL,
        sigSz), 0);
    /*   Bad length. */
    pubSz = 1;
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
    pubSz = ED448_PUB_KEY_SIZE;
    sigSz = 1;
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
    sigSz = ED448_SIG_SIZE;

    /* Good case of verification. */
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 1);
    /* Bad signature. */
    if (EXPECT_SUCCESS()) {
        sig[1] ^= 0x80;
    }
    ExpectIntEQ(wolfSSL_ED448_verify((byte*)msg, msglen, pub, pubSz, sig,
        sigSz), 0);
#endif /* HAVE_ED448_VERIFY */
#endif /* HAVE_ED448_SIGN && HAVE_ED448_KEY_IMPORT */
#endif /* HAVE_ED448 && HAVE_ED448_KEY_EXPORT && WOLFSSL_KEY_GEN */
    return EXPECT_RESULT();
}
#endif /* OPENSSL_EXTRA */

