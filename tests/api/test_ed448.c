/* test_ed448.c
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

    /* MC/DC: wc_ed448_make_public()'s (key == NULL || pubKey == NULL ||
     * pubKeySz != ED448_PUB_KEY_SIZE) arg check. The call above (valid key,
     * valid pubkey, correct size) is the all-FALSE baseline; each call
     * below flips exactly one operand TRUE while holding the other two at
     * their baseline (FALSE) value, closing all three operands'
     * independence pairs. They also give the (ret == 0) FALSE side of the
     * (ret == 0) && (!key->privKeySet) check immediately below it. */
    ExpectIntEQ(wc_ed448_make_public(NULL, pubkey, sizeof(pubkey)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_make_public(&key, NULL, sizeof(pubkey)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_make_public(&key, pubkey, sizeof(pubkey) - 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

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
 * RFC 8032 requires the Ed448 signature scalar S to be canonical (S < L).
 * Because L times the base point is the identity, a malleated signature with
 * S' = S + L recomputes the same R, so the S-range check is the only guard
 * against it. Confirm a signature with S >= L (including the malleability case
 * S + L) is rejected with BAD_FUNC_ARG, while an in-range but wrong S fails
 * verification with SIG_VERIFY_E.
 */
int test_wc_ed448_verify_sig_S_range(void)
{
    EXPECT_DECLS;
    /* The S-range rejection may be absent in the frozen ed448.c of older
     * FIPS-certified modules, so restrict to non-FIPS or FIPS v7 and later. */
#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && \
    defined(HAVE_ED448) && defined(HAVE_ED448_SIGN) && \
    defined(HAVE_ED448_VERIFY)
    ed448_key key;
    WC_RNG    rng;
    byte      msg[] = "Everybody gets Friday off.\n";
    byte      sig[ED448_SIG_SIZE];
    byte      badSig[ED448_SIG_SIZE];
    word32    msglen = sizeof(msg);
    word32    siglen = sizeof(sig);
    int       verify_ok = 0;
    int       i;
    int       carry;
    int       sum;
    /* Ed448 group order L, little-endian, 57 bytes. */
    static const byte order[] = {
        0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
        0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
        0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
        0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
        0x00
    };

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(sig, 0, sizeof(sig));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    /* Produce a valid signature and confirm it verifies. */
    ExpectIntEQ(wc_ed448_sign_msg(msg, msglen, sig, &siglen, &key, NULL, 0), 0);
    ExpectIntEQ(siglen, ED448_SIG_SIZE);
    ExpectIntEQ(wc_ed448_verify_msg(sig, siglen, msg, msglen, &verify_ok, &key,
        NULL, 0), 0);
    ExpectIntEQ(verify_ok, 1);

    /* Malleability: S' = S + L. The same R is recomputed, so only the S-range
     * check can reject it. */
    XMEMCPY(badSig, sig, ED448_SIG_SIZE);
    carry = 0;
    for (i = 0; i < (int)sizeof(order); i++) {
        sum = (int)badSig[ED448_SIG_SIZE / 2 + i] + (int)order[i] + carry;
        badSig[ED448_SIG_SIZE / 2 + i] = (byte)(sum & 0xff);
        carry = sum >> 8;
    }
    verify_ok = 1;
    ExpectIntEQ(wc_ed448_verify_msg(badSig, ED448_SIG_SIZE, msg, msglen,
        &verify_ok, &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* S exactly equal to L. */
    XMEMCPY(badSig, sig, ED448_SIG_SIZE);
    XMEMCPY(badSig + ED448_SIG_SIZE / 2, order, sizeof(order));
    verify_ok = 1;
    ExpectIntEQ(wc_ed448_verify_msg(badSig, ED448_SIG_SIZE, msg, msglen,
        &verify_ok, &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* S greater than L in a high byte. */
    XMEMCPY(badSig, sig, ED448_SIG_SIZE);
    XMEMCPY(badSig + ED448_SIG_SIZE / 2, order, sizeof(order));
    badSig[ED448_SIG_SIZE / 2 + 55] = 0x40;
    verify_ok = 1;
    ExpectIntEQ(wc_ed448_verify_msg(badSig, ED448_SIG_SIZE, msg, msglen,
        &verify_ok, &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* S greater than L in a low byte. */
    XMEMCPY(badSig, sig, ED448_SIG_SIZE);
    XMEMCPY(badSig + ED448_SIG_SIZE / 2, order, sizeof(order));
    badSig[ED448_SIG_SIZE / 2 + 0] = 0xf4;
    verify_ok = 1;
    ExpectIntEQ(wc_ed448_verify_msg(badSig, ED448_SIG_SIZE, msg, msglen,
        &verify_ok, &key, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(verify_ok, 0);

    /* S below L: passes the range check, fails verification instead. */
    XMEMCPY(badSig, sig, ED448_SIG_SIZE);
    XMEMCPY(badSig + ED448_SIG_SIZE / 2, order, sizeof(order));
    badSig[ED448_SIG_SIZE / 2 + 0] = 0xf2;
    verify_ok = 1;
    ExpectIntEQ(wc_ed448_verify_msg(badSig, ED448_SIG_SIZE, msg, msglen,
        &verify_ok, &key, NULL, 0), WC_NO_ERR_TRACE(SIG_VERIFY_E));
    ExpectIntEQ(verify_ok, 0);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_verify_sig_S_range */

/*
 * Test that wc_ed448_sign_msg() rejects a public-key-only key object.
 * A key with pubKeySet=1 but privKeySet=0 must not silently sign.
 */
int test_wc_ed448_sign_msg_pubonly_fails(void)
{
    EXPECT_DECLS;
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
#if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN) && \
    defined(HAVE_ED448_KEY_IMPORT) && defined(HAVE_ED448_KEY_EXPORT)
    ed448_key fullKey;
    ed448_key pubOnlyKey;
    WC_RNG    rng;
    byte      pubBuf[ED448_PUB_KEY_SIZE];
    word32    pubSz = sizeof(pubBuf);
    byte      msg[] = "test message for pubonly check";
    byte      sig[ED448_SIG_SIZE];
    word32    sigLen = sizeof(sig);

    XMEMSET(&fullKey, 0, sizeof(fullKey));
    XMEMSET(&pubOnlyKey, 0, sizeof(pubOnlyKey));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_ed448_init(&fullKey), 0);
    ExpectIntEQ(wc_ed448_init(&pubOnlyKey), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Generate a real key pair and export its public key. */
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &fullKey), 0);
    ExpectIntEQ(wc_ed448_export_public(&fullKey, pubBuf, &pubSz), 0);

    /* Import only the public key into a fresh key object. */
    ExpectIntEQ(wc_ed448_import_public(pubBuf, pubSz, &pubOnlyKey), 0);

    /* Signing with a public-key-only object must fail. */
    ExpectIntEQ(wc_ed448_sign_msg(msg, sizeof(msg), sig, &sigLen,
        &pubOnlyKey, NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&pubOnlyKey);
    wc_ed448_free(&fullKey);
#endif
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_sign_msg_pubonly_fails */

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

    /* MC/DC: wc_ed448_import_public_ex()'s tri-state length check
     * (inLen != PUB_KEY_SIZE && inLen != PUB_KEY_SIZE+1 &&
     *  inLen != 2*PUB_KEY_SIZE+1) -- close the third operand's FALSE side
     * (inLen == 115) by falling through with a 115-byte input below, which
     * also exercises the compressed-prefix (in[0] == 0x40 &&
     * inLen > PUB_KEY_SIZE) and uncompressed-prefix (in[0] == 0x04 &&
     * inLen > 2*PUB_KEY_SIZE) branches that no other test reaches. */
    {
        byte compressed[ED448_PUB_KEY_SIZE + 1];
        byte uncompressed[2 * ED448_PUB_KEY_SIZE + 1];

        /* in[0] == 0x40, inLen (58) > PUB_KEY_SIZE (57): compressed-prefix
         * branch TRUE side. */
        compressed[0] = 0x40;
        XMEMCPY(compressed + 1, in, ED448_PUB_KEY_SIZE);
        ExpectIntEQ(wc_ed448_import_public_ex(compressed,
            (word32)sizeof(compressed), &pubKey, 1), 0);

        /* in[0] == 0x40, inLen (57) == PUB_KEY_SIZE: compressed-prefix
         * branch's length operand FALSE side -- falls through to the
         * "inLen == PUB_KEY_SIZE" plain-copy branch instead. */
        ExpectIntEQ(wc_ed448_import_public_ex(compressed,
            ED448_PUB_KEY_SIZE, &pubKey, 1), 0);

        /* in[0] == 0x04, inLen (115 == 2*PUB_KEY_SIZE+1) > 2*PUB_KEY_SIZE:
         * uncompressed-prefix branch TRUE side, and the tri-state length
         * OR's third operand FALSE side (with the first two held TRUE).
         * ge448_compress_key() does not validate that (x, y) is on the
         * curve, so arbitrary x/y bytes exercise the branch safely under
         * a trusted import. */
        uncompressed[0] = 0x04;
        XMEMSET(uncompressed + 1, 0x24, ED448_PUB_KEY_SIZE);       /* x */
        XMEMCPY(uncompressed + 1 + ED448_PUB_KEY_SIZE, in,
            ED448_PUB_KEY_SIZE);                                   /* y */
        ExpectIntEQ(wc_ed448_import_public_ex(uncompressed,
            (word32)sizeof(uncompressed), &pubKey, 1), 0);

        /* in[0] == 0x04, inLen (57) == PUB_KEY_SIZE: uncompressed-prefix
         * branch's length operand FALSE side -- also falls through to the
         * plain-copy branch (the leading 0x04 becomes part of the
         * "compressed" key bytes copied verbatim). */
        ExpectIntEQ(wc_ed448_import_public_ex(uncompressed,
            ED448_PUB_KEY_SIZE, &pubKey, 1), 0);
    }

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

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
    /* Reject export when private key not set. */
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private_only(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();
#endif /* !HAVE_FIPS || FIPS_VERSION3_GE(7,0,0) */

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

    /* MC/DC: the (ret == 0) && (*outLen < <size>) BUFFER_E checks in
     * wc_ed448_export_public(), wc_ed448_export_private_only() and
     * wc_ed448_export_private(). Each pair holds the size operand at a
     * fixed too-small value across a NULL-key call (ret == 0 FALSE) and a
     * valid-key call (ret == 0 TRUE), closing both operands. */
    {
        word32 tinyPubLen = ED448_PUB_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_public(NULL, pub, &tinyPubLen),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        tinyPubLen = ED448_PUB_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_public(&key, pub, &tinyPubLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ(tinyPubLen, ED448_PUB_KEY_SIZE);
    }

    PRIVATE_KEY_UNLOCK();
    {
        word32 tinyPrivLen = ED448_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_private_only(NULL, priv, &tinyPrivLen),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        tinyPrivLen = ED448_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_private_only(&key, priv, &tinyPrivLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ(tinyPrivLen, ED448_KEY_SIZE);
    }
    {
        word32 tinyBothLen = ED448_PRV_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_private(NULL, priv, &tinyBothLen),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        tinyBothLen = ED448_PRV_KEY_SIZE - 1;
        ExpectIntEQ(wc_ed448_export_private(&key, priv, &tinyBothLen),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ(tinyBothLen, ED448_PRV_KEY_SIZE);
    }
    PRIVATE_KEY_LOCK();

#ifdef HAVE_ED448_KEY_IMPORT
    /* Public-only key: re-init and import just the public part; private
     * exports must still fail with privKeySet == 0. */
    wc_ed448_free(&key);
    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_ed448_import_public(pub, pubSz, &key), 0);

#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private_only(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_export_private(&key, priv, &privSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    PRIVATE_KEY_LOCK();
#endif /* !HAVE_FIPS || FIPS_VERSION3_GE(7,0,0) */

#endif

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
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(&key, 0, sizeof(ed448_key));

    /* Test bad args */
    ExpectIntEQ(wc_Ed448PublicKeyToDer(NULL, NULL, 0, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ed448_init(&key), 0);
#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(7,0,0)
    if (EXPECT_SUCCESS()) {
        int ret = wc_Ed448PublicKeyToDer(&key, derBuf, 0, 0);
        ExpectTrue((ret == WC_NO_ERR_TRACE(BUFFER_E)) ||
                   (ret == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    }
#else
    ExpectIntEQ(wc_Ed448PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(PUBLIC_KEY_E));
#endif
    wc_ed448_free(&key);

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);
    ExpectIntEQ(wc_Ed448PublicKeyToDer(&key, derBuf, 0, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);

    /*  Test good args */
    if (EXPECT_SUCCESS()) {
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

/*
 * RFC 5958: version=v2 (1) when pub key is bundled, v1 (0) for private only. */
int test_wc_Ed448KeyToDer_oneasymkey_version(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT) && \
    defined(HAVE_ED448_KEY_IMPORT) && defined(WOLFSSL_KEY_GEN)
    ed448_key key;
    ed448_key key2;
    WC_RNG rng;
    byte ref[512];   /* reference DER (bundled, then private only) */
    byte rt[512];    /* re-export target for memcmp */
    int  refSz = 0;
    int  rtSz = 0;
    word32 idx;

    XMEMSET(&key,  0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng,  0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_ed448_init(&key2), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    /* Bundled (v=1) */
    ExpectIntGT(refSz = wc_Ed448KeyToDer(&key, ref, (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 1);
    idx = 0;
    ExpectIntEQ(wc_Ed448PrivateKeyDecode(ref, &idx, &key2, (word32)refSz), 0);
    ExpectIntEQ(rtSz = wc_Ed448KeyToDer(&key2, rt, (word32)sizeof(rt)), refSz);
    ExpectIntEQ(XMEMCMP(ref, rt, (size_t)refSz), 0);

    /* Private only (v=0) */
    ExpectIntGT(refSz = wc_Ed448PrivateKeyToDer(&key, ref,
        (word32)sizeof(ref)), 0);
    ExpectIntEQ(test_pkcs8_get_version_byte(ref, (word32)refSz), 0);

    wc_ed448_free(&key);
    wc_ed448_free(&key2);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

/* Ed448 identity and small-order public keys must be rejected.
 * Edwards448 has cofactor 4, so the small-order subgroup contains the
 * identity, an order-2 point, and two order-4 points. With any of these
 * as the public key, h*A is the neutral element and forged signatures
 * verify for arbitrary messages. Gated on FIPS_VERSION3_GE(7,0,0)
 * because older FIPS-certified modules do not have this check in their
 * frozen copy of ed448.c. */
int test_wc_ed448_reject_small_order_keys(void)
{
    EXPECT_DECLS;
#if (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0)) && \
    defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    /* Two regressions are guarded here. Both sign-bit variants of each
     * y are listed so weakening the "clear all of byte 56" mask in
     * ed448_is_small_order() would be caught. The non-canonical rows
     * (y = p, y = p + 1) guard against dropping the canonical-form
     * coverage: fe448_from_bytes reads bytes 0-55 modulo p with no
     * canonical-form check, so y = p decodes to 0 and y = p + 1
     * decodes to 1, both of which are small order. */
    static const byte small_order_keys[][ED448_PUB_KEY_SIZE] = {
        /* identity (y = 1), sign 0 */
        {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00},
        /* identity (y = 1), sign bit set */
        {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x80},
        /* order 4: y = 0, x-sign 0 */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00},
        /* order 4: y = 0, x-sign 1 */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x80},
        /* order 2: y = p - 1, x = 0, sign 0 */
        {0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x00},
        /* order 2: y = p - 1, sign bit set */
        {0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x80},
        /* non-canonical y = p (decodes to y = 0), sign 0 */
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x00},
        /* non-canonical y = p, sign bit set */
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x80},
        /* non-canonical y = p + 1 (decodes to y = 1), sign 0 */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x00},
        /* non-canonical y = p + 1, sign bit set */
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0x80},
    };
#ifndef NO_ED448_VERIFY
    /* Arbitrary signature bytes: S = 1 (must be below the Ed448 group
     * order or wc_ed448_verify_msg() returns BAD_FUNC_ARG before the
     * small-order check has a chance to fire). The R bytes do not need
     * to encode a valid curve point for this test - the small-order
     * defence in ed448_verify_msg_final_with_sha() rejects the public
     * key before the R/S verification math runs. */
    static const byte forged_sig[ED448_SIG_SIZE] = {
        /* R: 57 bytes of arbitrary data (last byte 0 to satisfy the
         * spec-mandated zero of byte 56 bits 0-6; sign bit doesn't
         * matter here). */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,
        /* S = 1 */
        0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00
    };
#endif
    ed448_key key;
    word32 i;
    word32 num_keys = (word32)(sizeof(small_order_keys) / ED448_PUB_KEY_SIZE);

    /* (1) Untrusted wc_ed448_import_public must reject every small-order
     * encoding (it runs wc_ed448_check_key as part of the import). */
    for (i = 0; i < num_keys; i++) {
        int rc;
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_ed448_init(&key), 0);
        rc = wc_ed448_import_public(small_order_keys[i],
            ED448_PUB_KEY_SIZE, &key);
        if (rc != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            fprintf(stderr, "small_order_keys[%u]: import_public returned %d, "
                "expected PUBLIC_KEY_E\n", (unsigned)i, rc);
        }
        ExpectIntEQ(rc, WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_ed448_free(&key);
    }

    /* (2) wc_ed448_check_key called directly must also reject. Guards
     * against a refactor that moves the small-order check out of
     * check_key and into the import path: (1) would still pass, but the
     * documented check_key contract would silently regress. */
    for (i = 0; i < num_keys; i++) {
        int rc;
        XMEMSET(&key, 0, sizeof(key));
        ExpectIntEQ(wc_ed448_init(&key), 0);
        /* trusted = 1 bypasses the import-time check_key call so the
         * direct check_key below is what's under test. */
        ExpectIntEQ(wc_ed448_import_public_ex(small_order_keys[i],
            ED448_PUB_KEY_SIZE, &key, 1), 0);
        rc = wc_ed448_check_key(&key);
        if (rc != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
            fprintf(stderr, "small_order_keys[%u]: check_key returned %d, "
                "expected PUBLIC_KEY_E\n", (unsigned)i, rc);
        }
        ExpectIntEQ(rc, WC_NO_ERR_TRACE(PUBLIC_KEY_E));
        wc_ed448_free(&key);
    }

#ifndef NO_ED448_VERIFY
    /* (3) Even a "trusted" import (which bypasses wc_ed448_check_key)
     * must not let wc_ed448_verify_msg accept a forged signature against
     * an identity public key. Test both the canonical encoding (y = 1,
     * small_order_keys[0]) and the non-canonical encoding (y = p + 1,
     * small_order_keys[8]) so the verify-side check is exercised against
     * the canonical-form bypass route, not just the byte-for-byte
     * identity. */
    {
        static const word32 identity_indices[] = { 0, 8 };
        const char* msg = "forged message";
        word32 j;

        for (j = 0;
             j < sizeof(identity_indices)/sizeof(identity_indices[0]);
             j++) {
            word32 idx = identity_indices[j];
            int verify_result = 1;
            int rc;

            XMEMSET(&key, 0, sizeof(key));
            ExpectIntEQ(wc_ed448_init(&key), 0);
            ExpectIntEQ(wc_ed448_import_public_ex(small_order_keys[idx],
                ED448_PUB_KEY_SIZE, &key, 1), 0);
            rc = wc_ed448_verify_msg(forged_sig, sizeof(forged_sig),
                (const byte*)msg, (word32)XSTRLEN(msg), &verify_result,
                &key, NULL, 0);
            if (rc != WC_NO_ERR_TRACE(BAD_FUNC_ARG) || verify_result != 0) {
                fprintf(stderr, "verify_msg with identity-equiv "
                    "small_order_keys[%u]: rc=%d verify_result=%d "
                    "(expected BAD_FUNC_ARG and 0)\n",
                    (unsigned)idx, rc, verify_result);
            }
            ExpectIntEQ(rc, WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(verify_result, 0);
            wc_ed448_free(&key);
        }
    }
#endif
#endif
    return EXPECT_RESULT();
}

/*
 * MC/DC decision coverage for wolfcrypt/src/ed448.c decisions the pre-existing
 * ed448 API tests never drive: the sign/verify (context == NULL && contextLen
 * != 0) compound and its "context != NULL" hash-update branches, the explicit
 * wc_ed448_sign_msg_ex/verify_msg_ex type path, and the Ed448ph (prehash)
 * sign/verify branches including the (type == Ed448ph && inLen !=
 * ED448_PREHASH_SIZE) length check.
 */
int test_wc_Ed448DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN) && defined(HAVE_ED448_VERIFY)
    ed448_key key;
    ed448_key key2;
    WC_RNG    rng;
    byte      msg[]     = "ed448 decision coverage message";
    byte      ctx[]     = "ed448-context";
    byte      sig[ED448_SIG_SIZE];
    byte      hash[ED448_PREHASH_SIZE];
    byte      badhash[ED448_PREHASH_SIZE - 1];
    word32    sigLen = sizeof(sig);
    word32    msgLen = sizeof(msg);
    byte      ctxLen = (byte)(sizeof(ctx) - 1);
    int       verify = 0;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(sig, 0, sizeof(sig));
    XMEMSET(hash, 0x5a, sizeof(hash));
    XMEMSET(badhash, 0x5a, sizeof(badhash));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    /* MC/DC: the (ret == 0) && (context != NULL) hash-update guards in
     * wc_ed448_sign_msg_ex() (both the nonce and the R/S hash phases share
     * the same `ret` chain). A freshly-initialized key (pubKeySet == 0)
     * with a non-NULL context makes the (ret == 0) operand FALSE while
     * holding "context != NULL" at the same TRUE value used by the
     * successful sign-with-context call below, closing that operand's
     * independence pair without needing to force an internal hash
     * failure. */
    ExpectIntEQ(wc_ed448_init(&key2), 0);
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg(msg, msgLen, sig, &sigLen, &key2, ctx,
        ctxLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    wc_ed448_free(&key2);

    /* Sign/verify with a non-NULL context: exercises the "context != NULL"
     * side of the (context == NULL && contextLen != 0) compound plus the
     * "context != NULL" hash-update branches in both sign and verify. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg(msg, msgLen, sig, &sigLen, &key, ctx, ctxLen),
        0);
    ExpectIntEQ(wc_ed448_verify_msg(sig, sigLen, msg, msgLen, &verify, &key,
        ctx, ctxLen), 0);
    ExpectIntEQ(verify, 1);

    /* context == NULL && contextLen != 0: compound TRUE -> BAD_FUNC_ARG, in
     * both the sign and verify sanity checks. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg(msg, msgLen, sig, &sigLen, &key, NULL, 5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    verify = 0;
    ExpectIntEQ(wc_ed448_verify_msg(sig, sizeof(sig), msg, msgLen, &verify,
        &key, NULL, 5), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Explicit wc_ed448_sign_msg_ex/verify_msg_ex with type == Ed448. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg_ex(msg, msgLen, sig, &sigLen, &key,
        (byte)Ed448, ctx, ctxLen), 0);
    verify = 0;
    ExpectIntEQ(wc_ed448_verify_msg_ex(sig, sigLen, msg, msgLen, &verify, &key,
        (byte)Ed448, ctx, ctxLen), 0);
    ExpectIntEQ(verify, 1);

    /* Ed448ph: type == Ed448ph path through sign_msg_ex (prehash then sign)
     * and the matching verify, without and with a context. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448ph_sign_msg(msg, msgLen, sig, &sigLen, &key, NULL, 0),
        0);
    verify = 0;
    ExpectIntEQ(wc_ed448ph_verify_msg(sig, sigLen, msg, msgLen, &verify, &key,
        NULL, 0), 0);
    ExpectIntEQ(verify, 1);

    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448ph_sign_msg(msg, msgLen, sig, &sigLen, &key, ctx,
        ctxLen), 0);
    verify = 0;
    ExpectIntEQ(wc_ed448ph_verify_msg(sig, sigLen, msg, msgLen, &verify, &key,
        ctx, ctxLen), 0);
    ExpectIntEQ(verify, 1);

    /* Ed448ph prehash sign/verify with a correctly sized hash. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448ph_sign_hash(hash, sizeof(hash), sig, &sigLen, &key,
        NULL, 0), 0);
    verify = 0;
    ExpectIntEQ(wc_ed448ph_verify_hash(sig, sigLen, hash, sizeof(hash), &verify,
        &key, NULL, 0), 0);
    ExpectIntEQ(verify, 1);

    /* type == Ed448ph && inLen != ED448_PREHASH_SIZE -> BAD_LENGTH_E
     * (sign_hash forwards hashLen as inLen with type Ed448ph). */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448ph_sign_hash(badhash, sizeof(badhash), sig, &sigLen,
        &key, NULL, 0), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* MC/DC: wc_ed448_verify_msg_ex()'s (type == Ed448ph &&
     * msgLen != ED448_PREHASH_SIZE) check, verify side. Paired with the
     * regular (non-ph) verify calls above (type == Ed448ph FALSE, msgLen
     * != PREHASH_SIZE TRUE) for the type operand, and with the
     * correctly-sized Ed448ph verify_hash call above (type == Ed448ph
     * TRUE, msgLen != PREHASH_SIZE FALSE) for the length operand. */
    ExpectIntEQ(wc_ed448ph_verify_hash(sig, sigLen, badhash, sizeof(badhash),
        &verify, &key, NULL, 0), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Ed448DecisionCoverage */

/*
 * Feature coverage for the ed448 streaming verify API
 * (wc_ed448_verify_msg_init/update/final): positive multi-chunk verification
 * (loop true-sides) without and with a context, plus the update NULL-segment
 * and init/final NULL argument guards. Guarded identically to the streaming
 * verify code under test so it auto-skips where the feature is compiled out.
 */
int test_wc_Ed448FeatureCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN) && \
    defined(HAVE_ED448_VERIFY) && defined(WOLFSSL_ED448_STREAMING_VERIFY)
    ed448_key key;
    WC_RNG    rng;
    byte      msg[]  = "streaming multi-chunk ed448 verify message body";
    byte      ctx[]  = "stream-ctx";
    byte      sig[ED448_SIG_SIZE];
    word32    sigLen = sizeof(sig);
    word32    msgLen = sizeof(msg);
    byte      ctxLen = (byte)(sizeof(ctx) - 1);
    int       verify = 0;
    word32    off;
    word32    chunk = 7;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(sig, 0, sizeof(sig));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);

    /* Sign the whole message (no context), then verify it through the
     * streaming init/update(x N)/final API a few bytes at a time. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg(msg, msgLen, sig, &sigLen, &key, NULL, 0), 0);
    ExpectIntEQ(wc_ed448_verify_msg_init(sig, sigLen, &key, (byte)Ed448, NULL,
        0), 0);
    for (off = 0; off < msgLen; off += chunk) {
        word32 n = (msgLen - off < chunk) ? (msgLen - off) : chunk;
        ExpectIntEQ(wc_ed448_verify_msg_update(msg + off, n, &key), 0);
    }
    ExpectIntEQ(wc_ed448_verify_msg_final(sig, sigLen, &verify, &key), 0);
    ExpectIntEQ(verify, 1);

    /* Same, but with a non-NULL context supplied at init. */
    sigLen = sizeof(sig);
    ExpectIntEQ(wc_ed448_sign_msg(msg, msgLen, sig, &sigLen, &key, ctx, ctxLen),
        0);
    ExpectIntEQ(wc_ed448_verify_msg_init(sig, sigLen, &key, (byte)Ed448, ctx,
        ctxLen), 0);
    for (off = 0; off < msgLen; off += chunk) {
        word32 n = (msgLen - off < chunk) ? (msgLen - off) : chunk;
        ExpectIntEQ(wc_ed448_verify_msg_update(msg + off, n, &key), 0);
    }
    verify = 0;
    ExpectIntEQ(wc_ed448_verify_msg_final(sig, sigLen, &verify, &key), 0);
    ExpectIntEQ(verify, 1);

    /* Negative decisions in the streaming path: init NULL sig, update NULL
     * segment (ed448_verify_msg_update_with_sha's msgSegment == NULL guard),
     * final NULL res. */
    ExpectIntEQ(wc_ed448_verify_msg_init(NULL, sigLen, &key, (byte)Ed448, NULL,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg_init(sig, sigLen, &key, (byte)Ed448, NULL,
        0), 0);
    ExpectIntEQ(wc_ed448_verify_msg_update(NULL, msgLen, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg_update(msg, msgLen, &key), 0);
    /* MC/DC: ed448_verify_msg_final_with_sha()'s sig == NULL operand
     * (reachable only through the streaming final() API, since
     * wc_ed448_verify_msg_ex() always calls the init step -- which itself
     * rejects a NULL sig -- before ever reaching the final step). */
    ExpectIntEQ(wc_ed448_verify_msg_final(NULL, sigLen, &verify, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ed448_verify_msg_final(sig, sigLen, NULL, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_Ed448FeatureCoverage */

/*
 * MC/DC decision coverage for wolfcrypt/src/ed448.c's
 * wc_ed448_import_private_only(): the (priv == NULL || key == NULL) arg
 * check, the (ret == 0 && privSz != ED448_KEY_SIZE) length check, the
 * (ret == 0 && key->pubKeySet) validate-against-public-key branch, and the
 * (ret != 0 && key != NULL) error-cleanup guard. No existing test called
 * this function at all before this addition.
 */
int test_wc_ed448_import_private_only(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT) && \
    defined(HAVE_ED448_KEY_EXPORT)
    ed448_key key;
    ed448_key key2;
    WC_RNG    rng;
    byte      priv[ED448_KEY_SIZE];
    byte      privOnly[ED448_KEY_SIZE];
    word32    privOnlySz = sizeof(privOnly);

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(priv, 0x11, sizeof(priv));

    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_ed448_init(&key2), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);
    PRIVATE_KEY_UNLOCK();
    ExpectIntEQ(wc_ed448_export_private_only(&key, privOnly, &privOnlySz), 0);
    PRIVATE_KEY_LOCK();

    /* Baseline: key2 has neither key set. Valid priv + correct size ->
     * success. Gives (ret == 0) TRUE with (privSz != SIZE) FALSE, and
     * (key->pubKeySet) FALSE with (ret == 0) TRUE. */
    ExpectIntEQ(wc_ed448_import_private_only(priv, ED448_KEY_SIZE, &key2), 0);

    /* (ret == 0) && (privSz != ED448_KEY_SIZE): TRUE side, holding the
     * arg-NULL operands FALSE (priv/key both valid). */
    ExpectIntEQ(wc_ed448_import_private_only(priv, ED448_KEY_SIZE - 1, &key2),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* priv == NULL, with the same too-small privSz held constant across
     * the pair: (ret == 0) FALSE here (short-circuited by the arg check)
     * vs TRUE above -> closes the (ret == 0) operand of the privSz check.
     * Also priv == NULL with key != NULL (held valid across this call and
     * the baseline) closes the arg-check OR's priv-operand. */
    ExpectIntEQ(wc_ed448_import_private_only(NULL, ED448_KEY_SIZE - 1, &key2),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* key == NULL, with priv held valid/non-NULL across this call and the
     * baseline: closes the arg-check OR's key-operand. Also gives
     * (ret != 0) && (key == NULL) for the error-cleanup guard below, which
     * must not dereference key. */
    ExpectIntEQ(wc_ed448_import_private_only(priv, ED448_KEY_SIZE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* (ret == 0) && key->pubKeySet: TRUE side. `key` already has
     * pubKeySet == 1 from wc_ed448_make_key() above; re-importing its own
     * exported private key recomputes a matching public key, so
     * wc_ed448_check_key() succeeds and ret stays 0. */
    ExpectIntEQ(wc_ed448_import_private_only(privOnly, ED448_KEY_SIZE, &key),
        0);

    /* (ret == 0) FALSE with key->pubKeySet held TRUE (same `key`, still
     * pubKeySet == 1): a bad privSz trips the length check first, so the
     * pubKeySet branch is never reached with ret == 0 -- closes that
     * operand's independence pair. This call's (ret != 0) && (key != NULL)
     * also closes the error-cleanup guard's independence pairs alongside
     * the baseline (ret == 0) and key == NULL (above) calls. */
    ExpectIntEQ(wc_ed448_import_private_only(priv, ED448_KEY_SIZE - 1, &key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
    wc_ed448_free(&key2);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_import_private_only */

/*
 * MC/DC decision coverage for wolfcrypt/src/ed448.c's wc_ed448_check_key():
 * the (ret == 0 && !key->pubKeySet) "have a public key" gate, the
 * (ret == 0) operand of the (ret == 0 && ed448_is_small_order(...)) defence
 * (the is_small_order VALUE operand's independence is already shown by
 * test_wc_ed448_reject_small_order_keys()), the (ret == 0 &&
 * XMEMCMP(...) != 0) recomputed-vs-stored public key mismatch check in the
 * have-private-key branch, and the deep Y-range check's final byte compare.
 */
int test_wc_ed448_check_key_decisions(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    ed448_key key;
    ed448_key freshKey;
    WC_RNG    rng;
    byte      near_p[ED448_PUB_KEY_SIZE];
    int       rc;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&freshKey, 0, sizeof(freshKey));
    XMEMSET(&rng, 0, sizeof(rng));

    /* key == NULL: (ret == 0) FALSE side (short-circuited before any key
     * dereference). */
    ExpectIntEQ(wc_ed448_check_key(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Freshly-initialized key: key != NULL (ret == 0 TRUE) but pubKeySet
     * == 0 -> PUBLIC_KEY_E. Closes the pubKeySet operand's TRUE side and,
     * paired against the NULL call above, the (ret == 0) operand of this
     * same decision. Also gives the (ret == 0) FALSE side of the
     * small-order check below it (ret is already PUBLIC_KEY_E by the time
     * that line runs, so it short-circuits without touching key->p). */
    ExpectIntEQ(wc_ed448_init(&freshKey), 0);
    ExpectIntEQ(wc_ed448_check_key(&freshKey), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
    wc_ed448_free(&freshKey);

    /* Real key pair: pubKeySet == 1 (closes the pubKeySet operand's FALSE
     * side), not small order, private key matches public key -> success.
     * Gives the (ret == 0) TRUE side of the small-order check (paired
     * against the fresh-key call above) and the FALSE side of the
     * recomputed-public-key-mismatch compare below. */
    ExpectIntEQ(wc_ed448_init(&key), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ed448_make_key(&rng, ED448_KEY_SIZE, &key), 0);
    ExpectIntEQ(wc_ed448_check_key(&key), 0);

    /* Tamper with the stored public key while keeping the private key:
     * wc_ed448_make_public() recomputes the real public key from key->k,
     * which will now differ from the corrupted key->p -> XMEMCMP(...) != 0
     * TRUE -> PUBLIC_KEY_E. Closes the mismatch operand's TRUE side. */
    key.p[0] = (byte)(key.p[0] ^ 0xff);
    ExpectIntEQ(wc_ed448_check_key(&key), WC_NO_ERR_TRACE(PUBLIC_KEY_E));
    /* Restore so wc_ed448_free()'s zeroize-check doesn't care either way.*/
    key.p[0] = (byte)(key.p[0] ^ 0xff);

    /* Deep Y-range check: a Y value that is not one of
     * ed448_is_small_order()'s tabulated points but still forces both
     * range-check loops all the way down to the final byte compare (every
     * byte except p[0] matches the encoded field prime p). Only reachable
     * via a trusted import, which skips wc_ed448_check_key() at import
     * time so the crafted (curve-invalid) point can be handed to a
     * *direct* wc_ed448_check_key() call below -- same technique as
     * test_wc_ed448_reject_small_order_keys(). Whatever the later
     * curve-decode step decides is fine; the range-check decision itself
     * is what's targeted here. */
    XMEMSET(near_p, 0xff, sizeof(near_p));
    near_p[28] = 0xfe;
    near_p[0]  = 0x00;
    ExpectIntEQ(wc_ed448_init(&freshKey), 0);
    ExpectIntEQ(wc_ed448_import_public_ex(near_p, ED448_PUB_KEY_SIZE,
        &freshKey, 1), 0);
    rc = wc_ed448_check_key(&freshKey);
    ExpectTrue((rc == 0) || (rc == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    wc_ed448_free(&freshKey);

    /* Same construction but with an extra byte (p[1]) perturbed so the
     * second range-check loop exits early with ret == 0 before the final
     * byte compare runs -- closes that compare's PUBLIC_KEY_E
     * guard operand's FALSE side. */
    near_p[1] = 0x00;
    ExpectIntEQ(wc_ed448_init(&freshKey), 0);
    ExpectIntEQ(wc_ed448_import_public_ex(near_p, ED448_PUB_KEY_SIZE,
        &freshKey, 1), 0);
    rc = wc_ed448_check_key(&freshKey);
    ExpectTrue((rc == 0) || (rc == WC_NO_ERR_TRACE(PUBLIC_KEY_E)));
    wc_ed448_free(&freshKey);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_ed448_free(&key);
#endif
    return EXPECT_RESULT();
} /* END test_wc_ed448_check_key_decisions */

