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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef HAVE_FALCON
    #include <wolfssl/wolfcrypt/falcon.h>
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
#if defined(HAVE_FALCON) && defined(HAVE_LIBOQS)
    falcon_key key;
    WC_RNG rng;
    byte sig[FALCON_LEVEL1_SIG_SIZE];
    word32 sigLen = (word32)sizeof(sig);
    word32 idx = 0;
    int verified = 0;
    static const byte msg[] = "wolfssl falcon coverage";

    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, 1), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Use the embedded benchmark key rather than generating one with a
     * direct OQS_SIG_keypair() call: that call draws from liboqs'
     * randombytes callback, which wolfSSL points at its default liboqs RNG.
     * Any earlier wolfCrypt_Init/Cleanup cycle in this suite leaves that RNG
     * freed (wolfSSL_liboqsClose() does not reset liboqs_init, so re-Init
     * never re-creates it) and the callback then abort()s. The wolfSSL API
     * paths below hand OUR rng to liboqs instead, so they do not depend on
     * that state. */
    ExpectIntEQ(wc_Falcon_PrivateKeyDecode(bench_falcon_level1_key, &idx,
        &key, (word32)sizeof_bench_falcon_level1_key), 0);

    ExpectIntGT(wc_falcon_size(&key), 0);
    ExpectIntGT(wc_falcon_pub_size(&key), 0);
    ExpectIntGT(wc_falcon_priv_size(&key), 0);
    ExpectIntGT(wc_falcon_sig_size(&key), 0);
    ExpectIntEQ(wc_falcon_sign_msg(msg, (word32)sizeof(msg), sig, &sigLen,
        &key, &rng), 0);
    ExpectIntEQ(wc_falcon_verify_msg(sig, sigLen, msg, (word32)sizeof(msg),
        &verified, &key), 0);
    ExpectIntEQ(verified, 1);

    DoExpectIntEQ(wc_FreeRng(&rng), 0);
    wc_falcon_free(&key);
#endif
    return EXPECT_RESULT();
}

/* Decision coverage for the wc_Signature{Verify,Generate}{,Hash,_ex}()
 * dispatch wrapper: argument-check independence pairs, sig_type switch
 * dispatch (including the sig_type-NONE/default arm and unsupported-type
 * arms), hash-type/size validation, and the RSA_W_ENC-specific ASN.1
 * decode-length checks. */
int test_wc_SignatureDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifndef NO_SIG_WRAPPER
#ifdef HAVE_ECC
    {
        ecc_key ecc;
        enum wc_SignatureType sig_type = WC_SIGNATURE_TYPE_ECC;
        word32 key_len = (word32)sizeof(ecc_key);
        int eccSigMax = 0;
        /* Non-zero: wc_ecc_sign_hash() rejects an all-0's digest with
         * ECC_BAD_ARG_E (unless WC_ALLOW_ECC_ZERO_HASH), and this buffer
         * is used both for arg-check calls (content irrelevant) and for
         * a genuine sign at the end of this block. */
        byte hash[WC_SHA256_DIGEST_SIZE];
        word32 hash_len = (word32)sizeof(hash);
        byte sig[128] = {0};
        word32 sig_len;
        const char* qx =
            "fa2737fb93488d19caef11ae7faf6b7f4bcd67b286e3fc54e8a65c2b74aeccb0";
        const char* qy =
            "d4ccd6dae698208aa8c3a6f39e45510d03be09b2f124bfc067856c324f9b4d09";
        const char* d =
            "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25";

        XMEMSET(&ecc, 0, sizeof(ecc));
        XMEMSET(hash, 0x11, sizeof(hash));
        ExpectIntEQ(wc_ecc_init(&ecc), 0);
        ExpectIntEQ(wc_ecc_import_raw(&ecc, qx, qy, d, "SECP256R1"), 0);
        ExpectIntGT(eccSigMax = wc_SignatureGetSize(sig_type, &ecc, key_len),
            0);
        sig_len = (word32)eccSigMax;

        /* wc_SignatureVerifyHash(): argument-check independence pairs.
         * Each call flips exactly one operand of the arg-check OR-chain
         * while holding the others at a valid value. */
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            NULL, hash_len, sig, sig_len, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, 0, sig, sig_len, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, hash_len, NULL, sig_len, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, hash_len, sig, 0, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, hash_len, sig, sig_len, NULL, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, hash_len, sig, sig_len, &ecc, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* sig_len greater than wc_SignatureGetSize() allows */
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, hash_len, sig, (word32)(eccSigMax + 100000), &ecc,
            key_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Invalid/unsupported hash type: wc_HashGetDigestSize() < 0 */
        ExpectIntEQ(wc_SignatureVerifyHash((enum wc_HashType)999, sig_type,
            hash, hash_len, sig, sig_len, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* hash_len mismatch on the non-RSA_W_ENC path -> BAD_LENGTH_E */
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
            hash, (word32)(hash_len - 1), sig, sig_len, &ecc, key_len),
            WC_NO_ERR_TRACE(BAD_LENGTH_E));

        /* wc_SignatureVerify(): same argument-check independence pairs at
         * the data (pre-hash) level, plus a genuine sign/verify-mismatch
         * (SIG_VERIFY_E) and the weak-hash rejection. */
        {
            byte data[16];
            word32 data_len = (word32)sizeof(data);
            WC_RNG rng;

            XMEMSET(data, 0x5A, sizeof(data));
            ExpectIntEQ(wc_InitRng(&rng), 0);

            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                NULL, data_len, sig, sig_len, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, 0, sig, sig_len, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, NULL, sig_len, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, sig, 0, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, sig, sig_len, NULL, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, sig, sig_len, &ecc, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            /* sig_len too large for the key/sig_type */
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, sig, (word32)(eccSigMax + 100000), &ecc,
                key_len), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            /* Invalid hash type */
            ExpectIntEQ(wc_SignatureVerify((enum wc_HashType)999, sig_type,
                data, data_len, sig, sig_len, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifndef NO_SHA
            /* Hash weaker than WC_SIG_MIN_HASH_TYPE (default SHA-256)
             * rejected by wc_SignatureCheckHashStrength() */
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA, sig_type,
                data, data_len, sig, sig_len, &ecc, key_len),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

            /* Real signature that fails verification: SIG_VERIFY_E */
            {
                byte realSig[128] = {0};
                word32 realSigLen = (word32)sizeof(realSig);

                ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
                    sig_type, data, data_len, realSig, &realSigLen, &ecc,
                    key_len, &rng), 0);
                realSig[0] = (byte)(realSig[0] ^ 0xFF);
                ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
                    data, data_len, realSig, realSigLen, &ecc, key_len),
                    WC_NO_ERR_TRACE(SIG_VERIFY_E));
            }

            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }

        /* wc_SignatureGenerateHash_ex(): argument checks (mirrors the
         * VerifyHash pairs above, plus the sig / sig_len pointer split),
         * the sig_type switch default arm (reachable here, unlike in
         * VerifyHash, because the size guard is '*sig_len < GetSize()'
         * rather than 'sig_len > GetSize()': a positive *sig_len is never
         * less than GetSize()'s negative BAD_FUNC_ARG for an invalid
         * sig_type), and the verify-flag independence pair. */
        {
            byte genSig[128] = {0};
            word32 genSigLen = (word32)eccSigMax;
            WC_RNG rng;

            ExpectIntEQ(wc_InitRng(&rng), 0);

            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, NULL, hash_len, genSig, &genSigLen, &ecc, key_len,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, 0, genSig, &genSigLen, &ecc, key_len,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, hash_len, NULL, &genSigLen, &ecc, key_len,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, hash_len, genSig, NULL, &ecc, key_len,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            {
                word32 zeroLen = 0;
                ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                    sig_type, hash, hash_len, genSig, &zeroLen, &ecc,
                    key_len, &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, hash_len, genSig, &genSigLen, NULL, key_len,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, hash_len, genSig, &genSigLen, &ecc, 0,
                &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            /* *sig_len too small for key/sig_type */
            {
                word32 tinyLen = 1;
                ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                    sig_type, hash, hash_len, genSig, &tinyLen, &ecc,
                    key_len, &rng, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }

            /* Invalid hash type */
            {
                word32 lenCopy = (word32)eccSigMax;
                ExpectIntEQ(wc_SignatureGenerateHash_ex(
                    (enum wc_HashType)999, sig_type, hash, hash_len, genSig,
                    &lenCopy, &ecc, key_len, &rng, 1),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }

            /* sig_type NONE reaches the switch() default arm (see comment
             * above); asserts a genuinely different decision than the
             * arg-check/size-check BAD_FUNC_ARG returns above. */
            {
                word32 lenCopy = (word32)eccSigMax;
                ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                    WC_SIGNATURE_TYPE_NONE, hash, hash_len, genSig, &lenCopy,
                    &ecc, key_len, &rng, 1),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }

            /* verify == 0: skip the internal round-trip verify even though
             * ret == 0 (independence pair on the verify operand; the ret
             * operand is exercised by the BAD_FUNC_ARG cases above, all
             * called with verify == 1). */
            genSigLen = (word32)eccSigMax;
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, hash_len, genSig, &genSigLen, &ecc, key_len,
                &rng, 0), 0);

            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }

        /* wc_SignatureGenerate(): mirrors the argument checks above at the
         * data (pre-hash) level. */
        {
            byte data[16];
            word32 data_len = (word32)sizeof(data);
            byte genSig[128] = {0};
            word32 genSigLen = (word32)eccSigMax;
            WC_RNG rng;

            XMEMSET(data, 0xA5, sizeof(data));
            ExpectIntEQ(wc_InitRng(&rng), 0);

            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                NULL, data_len, genSig, &genSigLen, &ecc, key_len, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                data, 0, genSig, &genSigLen, &ecc, key_len, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, NULL, &genSigLen, &ecc, key_len, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, genSig, NULL, &ecc, key_len, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            {
                word32 zeroLen = 0;
                ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
                    sig_type, data, data_len, genSig, &zeroLen, &ecc,
                    key_len, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }
            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, genSig, &genSigLen, NULL, key_len, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
                data, data_len, genSig, &genSigLen, &ecc, 0, &rng),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

            /* *sig_len too small */
            {
                word32 tinyLen = 1;
                ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
                    sig_type, data, data_len, genSig, &tinyLen, &ecc,
                    key_len, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }

            /* Invalid hash type */
            {
                word32 lenCopy = (word32)eccSigMax;
                ExpectIntEQ(wc_SignatureGenerate((enum wc_HashType)999,
                    sig_type, data, data_len, genSig, &lenCopy, &ecc,
                    key_len, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }

#ifndef NO_SHA
            /* Weak hash rejected before any hashing/signing occurs */
            {
                word32 lenCopy = (word32)eccSigMax;
                ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA, sig_type,
                    data, data_len, genSig, &lenCopy, &ecc, key_len, &rng),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            }
#endif

            DoExpectIntEQ(wc_FreeRng(&rng), 0);
        }

        DoExpectIntEQ(wc_ecc_free(&ecc), 0);
    }
#endif /* HAVE_ECC */

#ifndef NO_RSA
    {
        RsaKey rsa_key;
        word32 idx = 0;
        byte* tmp = NULL;
        size_t bytes;
        word32 key_len = (word32)sizeof(RsaKey);
        int rsaSigMax = 0;
        byte hashGarbage[32];
        byte sigBuf[1] = {0};

        XMEMSET(&rsa_key, 0, sizeof(RsaKey));
        XMEMSET(hashGarbage, 0xEE, sizeof(hashGarbage));

    #ifdef USE_CERT_BUFFERS_1024
        bytes = (size_t)sizeof_client_key_der_1024;
    #elif defined(USE_CERT_BUFFERS_2048)
        bytes = (size_t)sizeof_client_key_der_2048;
    #else
        bytes = FOURK_BUF;
    #endif

        ExpectNotNull(tmp = (byte*)XMALLOC(bytes, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (tmp != NULL) {
        #ifdef USE_CERT_BUFFERS_1024
            XMEMCPY(tmp, client_key_der_1024,
                (size_t)sizeof_client_key_der_1024);
        #elif defined(USE_CERT_BUFFERS_2048)
            XMEMCPY(tmp, client_key_der_2048,
                (size_t)sizeof_client_key_der_2048);
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
        ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, &rsa_key,
            (word32)bytes), 0);
        ExpectIntGT(rsaSigMax = wc_SignatureGetSize(
            WC_SIGNATURE_TYPE_RSA_W_ENC, &rsa_key, key_len), 0);

        /* Non-DER hash_data for RSA_W_ENC: GetSequence() fails to find the
         * leading SEQUENCE tag -> ASN_PARSE_E */
        ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256,
            WC_SIGNATURE_TYPE_RSA_W_ENC, hashGarbage,
            (word32)sizeof(hashGarbage), sigBuf, (word32)sizeof(sigBuf),
            &rsa_key, key_len), WC_NO_ERR_TRACE(ASN_PARSE_E));

#if !defined(NO_ASN) && !defined(NO_SHA)
        /* Well-formed DigestInfo (built for a SHA-256-sized digest) but
         * decoded/verified as SHA-1: the decoded OCTET STRING length (32)
         * mismatches wc_HashGetDigestSize(WC_HASH_TYPE_SHA) (20) ->
         * BAD_LENGTH_E */
        {
            byte digest[WC_SHA256_DIGEST_SIZE] = {0};
            byte encoded[MAX_DER_DIGEST_SZ] = {0};
            int oid = 0;
            word32 encLen = 0;

            XMEMSET(digest, 0x11, sizeof(digest));
            ExpectIntGE(oid = wc_HashGetOID(WC_HASH_TYPE_SHA256), 0);
            ExpectIntGT((int)(encLen = wc_EncodeSignature(encoded, digest,
                (word32)sizeof(digest), oid)), 0);

            ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA,
                WC_SIGNATURE_TYPE_RSA_W_ENC, encoded, encLen, sigBuf,
                (word32)sizeof(sigBuf), &rsa_key, key_len),
                WC_NO_ERR_TRACE(BAD_LENGTH_E));
        }
#endif /* !NO_ASN && !NO_SHA */

        DoExpectIntEQ(wc_FreeRsaKey(&rsa_key), 0);
        XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* !NO_RSA */
#endif /* !NO_SIG_WRAPPER */
    return EXPECT_RESULT();
} /* END test_wc_SignatureDecisionCoverage() */

/* Feature/positive-path coverage for wc_Signature{Verify,Generate}{,Hash,_ex}():
 * full sign+verify round trips for each supported sig_type (ECC, RSA,
 * RSA_W_ENC), and the verify-flag "true" independence pair (the "false"
 * pair is exercised in test_wc_SignatureDecisionCoverage()). */
int test_wc_SignatureFeatureCoverage(void)
{
    EXPECT_DECLS;
#ifndef NO_SIG_WRAPPER
#ifdef HAVE_ECC
    {
        ecc_key ecc;
        WC_RNG rng;
        enum wc_SignatureType sig_type = WC_SIGNATURE_TYPE_ECC;
        word32 key_len = (word32)sizeof(ecc_key);
        byte data[32];
        word32 data_len = (word32)sizeof(data);
        byte sig[128] = {0};
        word32 sig_len;
        const char* qx =
            "fa2737fb93488d19caef11ae7faf6b7f4bcd67b286e3fc54e8a65c2b74aeccb0";
        const char* qy =
            "d4ccd6dae698208aa8c3a6f39e45510d03be09b2f124bfc067856c324f9b4d09";
        const char* d =
            "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25";

        XMEMSET(&ecc, 0, sizeof(ecc));
        XMEMSET(data, 0x42, sizeof(data));

        ExpectIntEQ(wc_ecc_init(&ecc), 0);
        ExpectIntEQ(wc_ecc_import_raw(&ecc, qx, qy, d, "SECP256R1"), 0);
        ExpectIntEQ(wc_InitRng(&rng), 0);

        /* wc_SignatureGetSize(): positive path for ECC */
        ExpectIntGT(wc_SignatureGetSize(sig_type, &ecc, key_len), 0);

        /* Full generate+verify round trip via the data-level API (default
         * verify == 1): exercises the "ret == 0 && verify" true branch,
         * where the internal wc_SignatureVerifyHash() round-trip call
         * itself succeeds. */
        sig_len = (word32)sizeof(sig);
        ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256, sig_type,
            data, data_len, sig, &sig_len, &ecc, key_len, &rng), 0);
        ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256, sig_type,
            data, data_len, sig, sig_len, &ecc, key_len), 0);

        /* Hash-level round trip, independently confirming the sig that
         * wc_SignatureGenerateHash_ex() produced with verify == 0 (see
         * test_wc_SignatureDecisionCoverage()) is a valid signature. */
        {
            byte hash[WC_SHA256_DIGEST_SIZE] = {0};
            byte sig2[128] = {0};
            word32 sig2_len = (word32)sizeof(sig2);

            ExpectIntEQ(wc_Hash(WC_HASH_TYPE_SHA256, data, data_len, hash,
                (word32)sizeof(hash)), 0);
            ExpectIntEQ(wc_SignatureGenerateHash_ex(WC_HASH_TYPE_SHA256,
                sig_type, hash, (word32)sizeof(hash), sig2, &sig2_len, &ecc,
                key_len, &rng, 0), 0);
            ExpectIntEQ(wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, sig_type,
                hash, (word32)sizeof(hash), sig2, sig2_len, &ecc, key_len),
                0);
        }

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
        DoExpectIntEQ(wc_ecc_free(&ecc), 0);
    }
#endif /* HAVE_ECC */

#ifndef NO_RSA
    {
        RsaKey rsa_key;
        WC_RNG rng;
        word32 idx = 0;
        byte* tmp = NULL;
        size_t bytes;
        word32 key_len = (word32)sizeof(RsaKey);
        byte data[32];
        word32 data_len = (word32)sizeof(data);
        byte sig[512] = {0};
        word32 sig_len;

        XMEMSET(&rsa_key, 0, sizeof(RsaKey));
        XMEMSET(data, 0x24, sizeof(data));

    #ifdef USE_CERT_BUFFERS_1024
        bytes = (size_t)sizeof_client_key_der_1024;
    #elif defined(USE_CERT_BUFFERS_2048)
        bytes = (size_t)sizeof_client_key_der_2048;
    #else
        bytes = FOURK_BUF;
    #endif

        ExpectNotNull(tmp = (byte*)XMALLOC(bytes, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER));
        if (tmp != NULL) {
        #ifdef USE_CERT_BUFFERS_1024
            XMEMCPY(tmp, client_key_der_1024,
                (size_t)sizeof_client_key_der_1024);
        #elif defined(USE_CERT_BUFFERS_2048)
            XMEMCPY(tmp, client_key_der_2048,
                (size_t)sizeof_client_key_der_2048);
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
        ExpectIntEQ(wc_RsaPrivateKeyDecode(tmp, &idx, &rsa_key,
            (word32)bytes), 0);
        ExpectIntEQ(wc_InitRng(&rng), 0);

        /* wc_SignatureGetSize(): positive path for RSA */
        ExpectIntGT(wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA, &rsa_key,
            key_len), 0);

        /* Plain RSA (PKCS#1 v1.5, no DigestInfo wrapper) round trip */
        sig_len = (word32)sizeof(sig);
        ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
            WC_SIGNATURE_TYPE_RSA, data, data_len, sig, &sig_len, &rsa_key,
            key_len, &rng), 0);
        ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256,
            WC_SIGNATURE_TYPE_RSA, data, data_len, sig, sig_len, &rsa_key,
            key_len), 0);

#ifndef NO_ASN
        /* RSA_W_ENC round trip: true branch of
         * "hash_enc_len += MAX_DER_DIGEST_ASN_SZ", wc_SignatureDerEncode()'s
         * success path, and the RSA_W_ENC ASN.1 decode success path in
         * wc_SignatureVerifyHash() (complementing the ASN_PARSE_E/
         * BAD_LENGTH_E failure paths in test_wc_SignatureDecisionCoverage()).
         */
        {
            byte sigEnc[512] = {0};
            word32 sigEncLen = (word32)sizeof(sigEnc);

            ExpectIntEQ(wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
                WC_SIGNATURE_TYPE_RSA_W_ENC, data, data_len, sigEnc,
                &sigEncLen, &rsa_key, key_len, &rng), 0);
            ExpectIntEQ(wc_SignatureVerify(WC_HASH_TYPE_SHA256,
                WC_SIGNATURE_TYPE_RSA_W_ENC, data, data_len, sigEnc,
                sigEncLen, &rsa_key, key_len), 0);
        }
#endif /* !NO_ASN */

        DoExpectIntEQ(wc_FreeRng(&rng), 0);
        DoExpectIntEQ(wc_FreeRsaKey(&rsa_key), 0);
        XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* !NO_RSA */
#endif /* !NO_SIG_WRAPPER */
    return EXPECT_RESULT();
} /* END test_wc_SignatureFeatureCoverage() */
