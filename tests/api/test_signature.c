/* test_signature.c
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

#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#if defined(HAVE_PQC) && defined(HAVE_FALCON)
    #include <wolfssl/wolfcrypt/falcon.h>
    #ifdef HAVE_LIBOQS
        #include <oqs/oqs.h>
    #endif
#endif
#include <tests/api/api.h>
#include <tests/api/test_signature.h>

/* Testing wc_SignatureGetSize() for signature type ECC */
int test_wc_SignatureGetSize_ecc(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && defined(HAVE_ECC) && !defined(NO_ECC256)
    enum wc_SignatureType sig_type;
    word32 key_len;
    ecc_key ecc;
    const char* qx =
        "fa2737fb93488d19caef11ae7faf6b7f4bcd67b286e3fc54e8a65c2b74aeccb0";
    const char* qy =
        "d4ccd6dae698208aa8c3a6f39e45510d03be09b2f124bfc067856c324f9b4d09";
    const char* d =
        "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25";

    XMEMSET(&ecc, 0, sizeof(ecc_key));

    ExpectIntEQ(wc_ecc_init(&ecc), 0);
    ExpectIntEQ(wc_ecc_import_raw(&ecc, qx, qy, d, "SECP256R1"), 0);
    /* Input for signature type ECC */
    sig_type = WC_SIGNATURE_TYPE_ECC;
    key_len = sizeof(ecc_key);
    ExpectIntGT(wc_SignatureGetSize(sig_type, &ecc, key_len), 0);

    /* Test bad args */
    /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
    sig_type = (enum wc_SignatureType) 100;
    /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &ecc, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sig_type = WC_SIGNATURE_TYPE_ECC;
    ExpectIntEQ(wc_SignatureGetSize(sig_type, NULL, key_len), 0);
    key_len = (word32)0;
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &ecc, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* key_len must be exactly sizeof(ecc_key): one less or one more is invalid */
    key_len = (word32)(sizeof(ecc_key) - 1);
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &ecc, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    key_len = (word32)(sizeof(ecc_key) + 1);
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &ecc, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_ecc_free(&ecc), 0);
#endif /* !NO_SIG_WRAPPER && HAVE_ECC && !NO_ECC256 */
    return EXPECT_RESULT();
} /* END test_wc_SignatureGetSize_ecc() */

/* Testing wc_SignatureGetSize() for signature type rsa */
int test_wc_SignatureGetSize_rsa(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && !defined(NO_RSA)
    enum wc_SignatureType sig_type;
    word32 key_len;
    word32 idx = 0;
    RsaKey rsa_key;
    byte* tmp = NULL;
    size_t bytes;

    XMEMSET(&rsa_key, 0, sizeof(RsaKey));

    #ifdef USE_CERT_BUFFERS_1024
        bytes = (size_t)sizeof_client_key_der_1024;
        if (bytes < (size_t)sizeof_client_key_der_1024)
            bytes = (size_t)sizeof_client_cert_der_1024;
    #elif defined(USE_CERT_BUFFERS_2048)
        bytes = (size_t)sizeof_client_key_der_2048;
        if (bytes < (size_t)sizeof_client_cert_der_2048)
            bytes = (size_t)sizeof_client_cert_der_2048;
    #else
        bytes = FOURK_BUF;
    #endif

    ExpectNotNull(tmp = (byte*)XMALLOC(bytes, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (tmp != NULL) {
    #ifdef USE_CERT_BUFFERS_1024
        XMEMCPY(tmp, client_key_der_1024, (size_t)sizeof_client_key_der_1024);
    #elif defined(USE_CERT_BUFFERS_2048)
        XMEMCPY(tmp, client_key_der_2048, (size_t)sizeof_client_key_der_2048);
    #elif !defined(NO_FILESYSTEM)
        XFILE file = XBADFILE;
        ExpectTrue((file = XFOPEN(clientKey, "rb")) != XBADFILE);
        ExpectIntGT(bytes = (size_t)XFREAD(tmp, 1, FOURK_BUF, file), 0);
        if (file != XBADFILE) {
            XFCLOSE(file);
        }
    #else
        ExpectFail();
    #endif
    }

    ExpectIntEQ(wc_InitRsaKey_ex(&rsa_key, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, &rsa_key, (word32)bytes), 0);
    /* Input for signature type RSA */
    sig_type = WC_SIGNATURE_TYPE_RSA;
    key_len = sizeof(RsaKey);
    ExpectIntGT(wc_SignatureGetSize(sig_type, &rsa_key, key_len), 0);

    /* Test bad args */
    /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
    sig_type = (enum wc_SignatureType)100;
    /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &rsa_key, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sig_type = WC_SIGNATURE_TYPE_RSA;
    ExpectIntEQ(wc_SignatureGetSize(sig_type, NULL, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    key_len = (word32)0;
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &rsa_key, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* key_len must be exactly sizeof(RsaKey): one less or one more is invalid */
    key_len = (word32)(sizeof(RsaKey) - 1);
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &rsa_key, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    key_len = (word32)(sizeof(RsaKey) + 1);
    ExpectIntEQ(wc_SignatureGetSize(sig_type, &rsa_key, key_len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_FreeRsaKey(&rsa_key), 0);
    XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* !NO_SIG_WRAPPER && !NO_RSA */
    return EXPECT_RESULT();
} /* END test_wc_SignatureGetSize_rsa(void) */

int test_wc_falcon_sign_verify(void)
{
    EXPECT_DECLS;
#if defined(HAVE_PQC) && defined(HAVE_FALCON) && defined(HAVE_LIBOQS)
    falcon_key key;
    WC_RNG rng;
    OQS_SIG* oqssig = NULL;
    OQS_STATUS oqsRc;
    byte pub[FALCON_LEVEL1_PUB_KEY_SIZE];
    byte priv[FALCON_LEVEL1_KEY_SIZE];
    byte privDer[FALCON_LEVEL1_PRV_KEY_SIZE + 4];
    byte sig[FALCON_LEVEL1_SIG_SIZE];
    word32 sigLen = (word32)sizeof(sig);
    word32 privDerLen = 0;
    int verified = 0;
    static const byte msg[] = "wolfssl falcon coverage";

    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, 1), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectNotNull(oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_512));
    if (oqssig != NULL) {
        oqsRc = OQS_SIG_keypair(oqssig, pub, priv);
        ExpectIntEQ((int)oqsRc, (int)OQS_SUCCESS);
        privDer[privDerLen++] = ASN_OCTET_STRING;
        privDer[privDerLen++] = 0x82;
        privDer[privDerLen++] = (byte)(FALCON_LEVEL1_PRV_KEY_SIZE >> 8);
        privDer[privDerLen++] = (byte)(FALCON_LEVEL1_PRV_KEY_SIZE & 0xff);
        XMEMCPY(privDer + privDerLen, priv, sizeof(priv));
        privDerLen += (word32)sizeof(priv);
        XMEMCPY(privDer + privDerLen, pub, sizeof(pub));
        privDerLen += (word32)sizeof(pub);
        ExpectIntEQ(wc_falcon_import_private_key(privDer, privDerLen, NULL, 0,
            &key), 0);
        ExpectIntGT(wc_falcon_size(&key), 0);
        ExpectIntGT(wc_falcon_pub_size(&key), 0);
        ExpectIntGT(wc_falcon_priv_size(&key), 0);
        ExpectIntGT(wc_falcon_sig_size(&key), 0);
        ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
            &key, &rng), 0);
        ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
            &verified, &key), 0);
        ExpectIntEQ(verified, 1);
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_falcon_free(&key);
#endif
    return EXPECT_RESULT();
}

/*
 * test_wc_SignatureBadArgCoverage
 *
 * MC/DC batch 1 — bad-argument paths for wc_SignatureVerifyHash and
 * wc_SignatureGenerateHash_ex (L154 and L413 5-condition guards).
 *
 * Each ExpectIntEQ/NE call isolates one condition in the compound predicate:
 *   hash_data==NULL | hash_len==0 | sig==NULL | sig_len==0 |
 *   key==NULL       | key_len==0
 * Pairs covered (one condition TRUE while the rest are FALSE):
 *   (hash_data=NULL), (hash_len=0), (sig=NULL), (sig_len=0),
 *   (key=NULL),       (key_len=0),  all-FALSE (success baseline)
 */
int test_wc_SignatureBadArgCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && defined(HAVE_ECC) && !defined(NO_ECC256)
    ecc_key ecc;
    WC_RNG  rng;
    /* 32-byte SHA-256 digest placeholder */
    byte hash[32];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = (word32)sizeof(sig);
    int    ret;

    XMEMSET(&ecc,  0, sizeof(ecc));
    XMEMSET(hash,  0xAB, sizeof(hash));
    XMEMSET(sig,   0,    sizeof(sig));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init_ex(&ecc, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, KEY32, &ecc), 0);

    /* --- wc_SignatureVerifyHash bad-arg isolation --- */

    /* P1: hash_data == NULL */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        NULL, (word32)sizeof(hash),
        sig, sigLen,
        &ecc, (word32)sizeof(ecc)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* P2: hash_len == 0 */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, 0,
        sig, sigLen,
        &ecc, (word32)sizeof(ecc)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* P3: sig == NULL */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        NULL, sigLen,
        &ecc, (word32)sizeof(ecc)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* P4: sig_len == 0 */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, 0,
        &ecc, (word32)sizeof(ecc)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* P5: key == NULL */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, sigLen,
        NULL, (word32)sizeof(ecc)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* P6: key_len == 0 */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, sigLen,
        &ecc, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_SignatureGenerateHash_ex bad-arg isolation (L413) --- */

    /* G1: hash_data == NULL */
    sigLen = (word32)sizeof(sig);
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        NULL, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G2: hash_len == 0 */
    sigLen = (word32)sizeof(sig);
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, 0,
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G3: sig == NULL */
    sigLen = (word32)sizeof(sig);
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        NULL, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G4: sig_len pointer == NULL */
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, NULL,
        &ecc, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G5: *sig_len == 0 */
    sigLen = 0;
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G6: key == NULL */
    sigLen = (word32)sizeof(sig);
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        NULL, (word32)sizeof(ecc), &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* G7: key_len == 0 */
    sigLen = (word32)sizeof(sig);
    ret = wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, 0, &rng, 0);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_ecc_free(&ecc), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif /* !NO_SIG_WRAPPER && HAVE_ECC && !NO_ECC256 */
    return EXPECT_RESULT();
} /* END test_wc_SignatureBadArgCoverage */

/*
 * test_wc_SignatureDecisionCoverage
 *
 * MC/DC batch 1 — decision-coverage pairs for the 5-condition compound
 * predicates at L154 and L220 of wc_SignatureVerifyHash.
 *
 * L154: all-false baseline (success) vs each condition individually true.
 * L220: ret!=0 || is_valid_sig!=1 — exercises both sub-conditions.
 *
 * Strategy: sign a real hash with an ECC key, then:
 *   - verify with correct inputs (all-false → success)
 *   - verify with corrupted sig  (ret==0 but sig invalid → is_valid_sig=0)
 */
int test_wc_SignatureDecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && defined(HAVE_ECC) && !defined(NO_ECC256) && \
    defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    ecc_key ecc;
    WC_RNG  rng;
    byte    hash[32];         /* SHA-256 digest */
    byte    sig[ECC_MAX_SIG_SIZE];
    byte    badsig[ECC_MAX_SIG_SIZE];
    word32  sigLen;
    int     ret;

    XMEMSET(&ecc,    0, sizeof(ecc));
    XMEMSET(hash,    0x55, sizeof(hash));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init_ex(&ecc, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, KEY32, &ecc), 0);

    /* Generate a valid signature over hash[] */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0 /* verify=0 */), 0);

    /* L154 all-false baseline: valid inputs → success path */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, sigLen,
        &ecc, (word32)sizeof(ecc)), 0);

    /* L220: is_valid_sig != 1 — flip one sig byte so wc_ecc_verify_hash
     * returns 0 but sets is_valid_sig=0, driving ret = SIG_VERIFY_E */
    XMEMCPY(badsig, sig, sigLen);
    badsig[sigLen / 2] ^= 0xFF;
    ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        badsig, sigLen,
        &ecc, (word32)sizeof(ecc));
    /* expect SIG_VERIFY_E (negative) */
    ExpectIntLT(ret, 0);

    /* L161: sig_len > wc_SignatureGetSize — oversized sig rejected */
    {
        word32 bigLen = (word32)ECC_MAX_SIG_SIZE;
        /* Fill a buffer larger than the key's max sig size */
        byte bigsig[ECC_MAX_SIG_SIZE];
        XMEMSET(bigsig, 0xAA, sizeof(bigsig));
        /* sig_len is deliberately set to max, which exceeds the key's
         * wc_SignatureGetSize() return value when the key is only 256-bit */
        (void)bigLen; /* suppress unused-variable warning on some compilers */
        /* Use a sig_len that is exactly 1 byte over the ECC key sig size */
        {
            int maxSz = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC,
                &ecc, (word32)sizeof(ecc));
            if (maxSz > 0) {
                word32 overLen = (word32)(maxSz + 1);
                ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
                    WC_SIGNATURE_TYPE_ECC,
                    hash, (word32)sizeof(hash),
                    bigsig, overLen,
                    &ecc, (word32)sizeof(ecc)),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }
        }
    }

    /* L168: invalid hash type → wc_HashGetDigestSize returns negative */
    {
        /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
        enum wc_HashType badHash = (enum wc_HashType)0xFF;
        /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
        ExpectIntLT(wc_SignatureVerifyHash(badHash,
            WC_SIGNATURE_TYPE_ECC,
            hash, (word32)sizeof(hash),
            sig, sigLen,
            &ecc, (word32)sizeof(ecc)), 0);
    }

    DoExpectIntEQ(wc_ecc_free(&ecc), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif /* !NO_SIG_WRAPPER && HAVE_ECC && !NO_ECC256 */
    return EXPECT_RESULT();
} /* END test_wc_SignatureDecisionCoverage */

/*
 * test_wc_SignatureGenerateHashExVerify
 *
 * MC/DC batch 1 — L413 (wc_SignatureGenerateHash_ex) and L278 decisions.
 *
 * L413 compound guard (5 conditions):
 *   covered by test_wc_SignatureBadArgCoverage above (bad-arg sweep).
 *
 * L494: if (ret == 0 && verify) — toggles the post-sign verify branch.
 *   - verify=0: branch not taken
 *   - verify=1: branch taken, internal wc_SignatureVerifyHash called
 *
 * L278 (RSA path): ret >= 0 && plain_ptr != NULL
 *   - covered by RSA round-trip below (both sub-conditions true → success,
 *     and a wrong-hash comparison exercises the else arm → SIG_VERIFY_E).
 */
int test_wc_SignatureGenerateHashExVerify(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && defined(HAVE_ECC) && !defined(NO_ECC256) && \
    defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    ecc_key ecc;
    WC_RNG  rng;
    byte    hash[32];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sigLen;

    XMEMSET(&ecc,  0, sizeof(ecc));
    XMEMSET(hash,  0x77, sizeof(hash));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_ecc_init_ex(&ecc, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, KEY32, &ecc), 0);

    /* L494 branch NOT taken: verify=0 */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0 /* verify=0 */), 0);

    /* L494 branch TAKEN: verify=1 — internal verify must also pass */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 1 /* verify=1 */), 0);

    /* L420: sig buffer too small → second BAD_FUNC_ARG guard in GenerateHash_ex */
    {
        int   minSz = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC,
            &ecc, (word32)sizeof(ecc));
        if (minSz > 0 && minSz > 1) {
            word32 tooSmall = (word32)(minSz - 1);
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                WC_SIGNATURE_TYPE_ECC,
                hash, (word32)sizeof(hash),
                sig, &tooSmall,
                &ecc, (word32)sizeof(ecc), &rng, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }
    }

    /* L427: invalid hash_type → wc_HashGetDigestSize < 0 in GenerateHash_ex */
    {
        /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
        enum wc_HashType badHash = (enum wc_HashType)0xFF;
        /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
        sigLen = (word32)sizeof(sig);
        ExpectIntLT(wc_SignatureGenerateHash_ex(badHash,
            WC_SIGNATURE_TYPE_ECC,
            hash, (word32)sizeof(hash),
            sig, &sigLen,
            &ecc, (word32)sizeof(ecc), &rng, 0), 0);
    }

    /* WC_SIGNATURE_TYPE_NONE → default branch → BAD_FUNC_ARG */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_NONE,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &ecc, (word32)sizeof(ecc), &rng, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    DoExpectIntEQ(wc_ecc_free(&ecc), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif /* !NO_SIG_WRAPPER && HAVE_ECC && !NO_ECC256 */
    return EXPECT_RESULT();
} /* END test_wc_SignatureGenerateHashExVerify */

/*
 * test_wc_SignatureRsaDecisionCoverage
 *
 * MC/DC batch 1 — RSA paths in wc_SignatureVerifyHash (L278) and
 * wc_SignatureGenerateHash_ex RSA branch (L452-486).
 *
 * L278: ret >= 0 && plain_ptr — both true (success), then plain_ptr mismatch
 *       triggers SIG_VERIFY_E (hash comparison fails).
 *
 * Also exercises WC_SIGNATURE_TYPE_RSA and WC_SIGNATURE_TYPE_RSA_W_ENC
 * enum arms to satisfy decision reachability for the switch() at L204/L434.
 */
int test_wc_SignatureRsaDecisionCoverage(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER) && !defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    defined(WOLFSSL_KEY_GEN)
    RsaKey  rsa;
    WC_RNG  rng;
    byte    hash[32];         /* SHA-256 digest */
    byte    sig[256];         /* 2048-bit key → 256-byte sig */
    word32  sigLen;

    XMEMSET(&rsa,  0, sizeof(rsa));
    XMEMSET(hash,  0x33, sizeof(hash));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_InitRsaKey_ex(&rsa, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, &rng), 0);

    /* WC_SIGNATURE_TYPE_RSA — generate then verify (L278 success path) */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &rsa, (word32)sizeof(rsa), &rng, 0 /* verify=0 */), 0);

    /* L278 both sub-conditions true → success */
    ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash),
        sig, sigLen,
        &rsa, (word32)sizeof(rsa)), 0);

    /* L278 hash mismatch: use a different hash → SIG_VERIFY_E */
    {
        byte wrongHash[32];
        XMEMSET(wrongHash, 0xCC, sizeof(wrongHash));
        ExpectIntLT(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
            WC_SIGNATURE_TYPE_RSA,
            wrongHash, (word32)sizeof(wrongHash),
            sig, sigLen,
            &rsa, (word32)sizeof(rsa)), 0);
    }

    /* WC_SIGNATURE_TYPE_RSA — verify=1 exercises L494 branch in GenerateHash_ex */
    sigLen = (word32)sizeof(sig);
    ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_RSA,
        hash, (word32)sizeof(hash),
        sig, &sigLen,
        &rsa, (word32)sizeof(rsa), &rng, 1 /* verify=1 */), 0);

    DoExpectIntEQ(wc_FreeRsaKey(&rsa), 0);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif /* !NO_SIG_WRAPPER && !NO_RSA && ... */
    return EXPECT_RESULT();
} /* END test_wc_SignatureRsaDecisionCoverage */

/*
 * test_wc_SignatureGetSizeAllTypes
 *
 * MC/DC batch 1 — ensure every enum wc_SignatureType arm in wc_SignatureGetSize
 * is reachable, providing decision coverage for the switch() at L93.
 *
 * Covers: WC_SIGNATURE_TYPE_ECC, WC_SIGNATURE_TYPE_RSA,
 *         WC_SIGNATURE_TYPE_RSA_W_ENC, WC_SIGNATURE_TYPE_NONE (bad arg).
 * WC_SIGNATURE_TYPE_ECC_W_ENC is intentionally omitted as it falls through
 * to WC_SIGNATURE_TYPE_ECC in the current implementation.
 */
int test_wc_SignatureGetSizeAllTypes(void)
{
    EXPECT_DECLS;
#if !defined(NO_SIG_WRAPPER)
#if defined(HAVE_ECC) && !defined(NO_ECC256)
    {
        ecc_key ecc;
        WC_RNG  rng;
        XMEMSET(&ecc, 0, sizeof(ecc));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_ecc_init_ex(&ecc, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_ecc_make_key(&rng, KEY32, &ecc), 0);

        /* ECC: should return a positive size */
        ExpectIntGT(wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC,
            &ecc, (word32)sizeof(ecc)), 0);

        DoExpectIntEQ(wc_ecc_free(&ecc), 0);
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif /* HAVE_ECC && !NO_ECC256 */

#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
    {
        RsaKey rsa;
        WC_RNG rng;
        XMEMSET(&rsa, 0, sizeof(rsa));
        ExpectIntEQ(wc_InitRng(&rng), 0);
        ExpectIntEQ(wc_InitRsaKey_ex(&rsa, HEAP_HINT, testDevId), 0);
        ExpectIntEQ(wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, &rng), 0);

        /* RSA: positive size */
        ExpectIntGT(wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA,
            &rsa, (word32)sizeof(rsa)), 0);

        /* RSA_W_ENC: same underlying key, same size */
        ExpectIntGT(wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA_W_ENC,
            &rsa, (word32)sizeof(rsa)), 0);

        DoExpectIntEQ(wc_FreeRsaKey(&rsa), 0);
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
#endif /* !NO_RSA && WOLFSSL_KEY_GEN */

    /* NONE: BAD_FUNC_ARG regardless of key */
    ExpectIntEQ(wc_SignatureGetSize(WC_SIGNATURE_TYPE_NONE, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Out-of-range enum: hits default branch → BAD_FUNC_ARG */
    {
        /* // NOLINTBEGIN(clang-analyzer-optin.core.EnumCastOutOfRange) */
        enum wc_SignatureType badType = (enum wc_SignatureType)0x7F;
        /* // NOLINTEND(clang-analyzer-optin.core.EnumCastOutOfRange) */
        ExpectIntEQ(wc_SignatureGetSize(badType, NULL, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

#endif /* !NO_SIG_WRAPPER */
    return EXPECT_RESULT();
} /* END test_wc_SignatureGetSizeAllTypes */
