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
#ifdef HAVE_FALCON
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
#if defined(HAVE_FALCON) && defined(HAVE_LIBOQS)
    falcon_key key;
    WC_RNG rng;
    OQS_SIG* oqssig = NULL;
    OQS_STATUS oqs_status;
    byte pub[FALCON_LEVEL1_PUB_KEY_SIZE];
    byte priv[FALCON_LEVEL1_KEY_SIZE];
    byte sig[FALCON_LEVEL1_SIG_SIZE];
    word32 sigLen = (word32)sizeof(sig);
    int verified = 0;
    static const byte msg[] = "wolfssl falcon coverage";

    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(wc_falcon_init(&key), 0);
    ExpectIntEQ(wc_falcon_set_level(&key, 1), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    ExpectNotNull(oqssig = OQS_SIG_new(OQS_SIG_alg_falcon_512));
    if (oqssig != NULL) {
        /* Keep the call out of ExpectIntEQ: the macro casts its arguments to
         * int, and casting a function call returning the OQS_STATUS enum
         * trips -Werror=bad-function-cast; casting a variable does not. */
        oqs_status = OQS_SIG_keypair(oqssig, pub, priv);
        ExpectIntEQ((int)oqs_status, (int)OQS_SUCCESS);
        ExpectIntEQ(wc_falcon_import_private_key(priv, (word32)sizeof(priv), pub,
            (word32)sizeof(pub), &key), 0);
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
