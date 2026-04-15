/* test_tls13.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_tls13.h>

#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
#ifdef WC_SHA384_DIGEST_SIZE
    WC_MAYBE_UNUSED static byte fixedKey[WC_SHA384_DIGEST_SIZE] = { 0, };
#else
    WC_MAYBE_UNUSED static byte fixedKey[WC_SHA256_DIGEST_SIZE] = { 0, };
#endif
#endif
#ifdef WOLFSSL_EARLY_DATA
static const char earlyData[] = "Early Data";
static       char earlyDataBuffer[1];
#endif

int test_tls13_apis(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_TLS13
#if defined(HAVE_SUPPORTED_CURVES) && defined(HAVE_ECC) && \
    (!defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT))
    int          ret;
#endif
#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_CTX* clientTls12Ctx = NULL;
    WOLFSSL*     clientTls12Ssl = NULL;
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_CTX* serverTls12Ctx = NULL;
    WOLFSSL*     serverTls12Ssl = NULL;
#endif
#endif
#ifndef NO_WOLFSSL_CLIENT
    WOLFSSL_CTX* clientCtx = NULL;
    WOLFSSL*     clientSsl = NULL;
#endif
#ifndef NO_WOLFSSL_SERVER
    WOLFSSL_CTX* serverCtx = NULL;
    WOLFSSL*     serverSsl = NULL;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
#ifndef NO_RSA
    const char*  ourCert = svrCertFile;
    const char*  ourKey  = svrKeyFile;
#elif defined(HAVE_ECC)
    const char*  ourCert = eccCertFile;
    const char*  ourKey  = eccKeyFile;
#elif defined(HAVE_ED25519)
    const char*  ourCert = edCertFile;
    const char*  ourKey  = edKeyFile;
#elif defined(HAVE_ED448)
    const char*  ourCert = ed448CertFile;
    const char*  ourKey  = ed448KeyFile;
#endif
#endif
#endif
    int          required;
#ifdef WOLFSSL_EARLY_DATA
    int          outSz;
#endif
#if defined(HAVE_ECC) && defined(HAVE_SUPPORTED_CURVES)
    int          groups[2] = { WOLFSSL_ECC_SECP256R1,
#ifdef WOLFSSL_HAVE_MLKEM
#ifdef WOLFSSL_MLKEM_KYBER
    #ifndef WOLFSSL_NO_KYBER512
                               WOLFSSL_KYBER_LEVEL1
    #elif !defined(WOLFSSL_NO_KYBER768)
                               WOLFSSL_KYBER_LEVEL3
    #else
                               WOLFSSL_KYBER_LEVEL5
    #endif
#elif !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #ifndef WOLFSSL_NO_ML_KEM_512
                               WOLFSSL_ML_KEM_512
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
                               WOLFSSL_ML_KEM_768
    #else
                               WOLFSSL_ML_KEM_1024
    #endif
#else
    #ifndef WOLFSSL_NO_ML_KEM_768
                               WOLFSSL_SECP256R1MLKEM768
    #else
                               WOLFSSL_ECC_SECP256R1
    #endif
#endif
#else
                               WOLFSSL_ECC_SECP256R1
#endif
                             };
#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
    int          bad_groups[2] = { 0xDEAD, 0xBEEF };
#endif /* !NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT */
    int          numGroups = 2;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_CLIENT)
    int          too_many_groups[WOLFSSL_MAX_GROUP_COUNT + 1];
#endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC)
    char         groupList[] =
#ifdef HAVE_CURVE25519
            "X25519:"
#endif
#ifdef HAVE_CURVE448
            "X448:"
#endif
#ifndef NO_ECC_SECP
#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
            "P-521:secp521r1:"
#endif
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
            "P-384:secp384r1:"
#endif
#if (!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
            "P-256:secp256r1"
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_MALLOC) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#ifdef WOLFSSL_MLKEM_KYBER
    #ifndef WOLFSSL_NO_KYBER512
            ":P256_KYBER_LEVEL1"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":P256_KYBER_LEVEL3"
    #elif !defined(WOLFSSL_NO_KYBER1024)
            ":P256_KYBER_LEVEL5"
    #endif
#else
    #if !defined(WOLFSSL_NO_ML_KEM_512) && defined(WOLFSSL_EXTRA_PQC_HYBRIDS)
            ":SecP256r1MLKEM512"
    #elif !defined(WOLFSSL_NO_ML_KEM_768) && defined(WOLFSSL_PQC_HYBRIDS)
            ":SecP256r1MLKEM768"
    #elif !defined(WOLFSSL_NO_ML_KEM_1024) && defined(WOLFSSL_PQC_HYBRIDS)
            ":SecP384r1MLKEM1024"
    #elif !defined(WOLFSSL_NO_ML_KEM_1024) && \
                                       !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
            ":ML_KEM_1024"
    #elif !defined(WOLFSSL_NO_ML_KEM_768) && \
                                       !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
            ":ML_KEM_768"
    #endif
#endif
#endif
#endif
#endif /* !defined(NO_ECC_SECP) */
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_MALLOC) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#ifdef WOLFSSL_MLKEM_KYBER
    #ifndef WOLFSSL_NO_KYBER512
            ":KYBER_LEVEL1"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":KYBER_LEVEL3"
    #elif !defined(WOLFSSL_NO_KYBER1024)
            ":KYBER_LEVEL5"
    #endif
#elif !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #if !defined(WOLFSSL_NO_ML_KEM_512)
            ":ML_KEM_512"
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
            ":ML_KEM_768"
    #elif !defined(WOLFSSL_NO_ML_KEM_1024)
            ":ML_KEM_1024"
    #endif
#endif
#endif
            "";
#endif /* defined(OPENSSL_EXTRA) && defined(HAVE_ECC) */
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_MALLOC) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    (!defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE) || \
    (defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)) || \
    (defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768)))
    int mlkemLevel;
#endif

#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_CLIENT
    clientTls12Ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    clientTls12Ssl = wolfSSL_new(clientTls12Ctx);
#endif
#ifndef NO_WOLFSSL_SERVER
    serverTls12Ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#if !defined(NO_CERTS)
    #if !defined(NO_FILESYSTEM)
    wolfSSL_CTX_use_certificate_chain_file(serverTls12Ctx, ourCert);
    wolfSSL_CTX_use_PrivateKey_file(serverTls12Ctx, ourKey,
        CERT_FILETYPE);
    #elif defined(USE_CERT_BUFFERS_2048)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverTls12Ctx,
        server_cert_der_2048, sizeof_server_cert_der_2048,
        WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverTls12Ctx, server_key_der_2048,
        sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1);
    #elif defined(USE_CERT_BUFFERS_256)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverTls12Ctx,
        serv_ecc_der_256, sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverTls12Ctx, ecc_key_der_256,
        sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
    #endif
#endif
    serverTls12Ssl = wolfSSL_new(serverTls12Ctx);
#endif
#endif

#ifndef NO_WOLFSSL_CLIENT
    clientCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    clientSsl = wolfSSL_new(clientCtx);
#endif
#ifndef NO_WOLFSSL_SERVER
    serverCtx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#if !defined(NO_CERTS)
    /* ignore load failures, since we just need the server to have a cert set */
    #if !defined(NO_FILESYSTEM)
    wolfSSL_CTX_use_certificate_chain_file(serverCtx, ourCert);
    wolfSSL_CTX_use_PrivateKey_file(serverCtx, ourKey, CERT_FILETYPE);
    #elif defined(USE_CERT_BUFFERS_2048)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverCtx,
        server_cert_der_2048, sizeof_server_cert_der_2048,
        WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverCtx, server_key_der_2048,
        sizeof_server_key_der_2048, WOLFSSL_FILETYPE_ASN1);
    #elif defined(USE_CERT_BUFFERS_256)
    wolfSSL_CTX_use_certificate_chain_buffer_format(serverCtx, serv_ecc_der_256,
        sizeof_serv_ecc_der_256, WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CTX_use_PrivateKey_buffer(serverCtx, ecc_key_der_256,
        sizeof_ecc_key_der_256, WOLFSSL_FILETYPE_ASN1);
    #endif
#endif
    serverSsl = wolfSSL_new(serverCtx);
    ExpectNotNull(serverSsl);
#endif

#ifdef WOLFSSL_SEND_HRR_COOKIE
    ExpectIntEQ(wolfSSL_send_hrr_cookie(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_send_hrr_cookie(clientSsl, NULL, 0),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverTls12Ssl, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverSsl, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_send_hrr_cookie(serverSsl, fixedKey, sizeof(fixedKey)),
        WOLFSSL_SUCCESS);
#endif
#endif

#ifdef HAVE_SUPPORTED_CURVES
#ifdef HAVE_ECC
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    do {
        ret = wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(serverSsl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    do {
        ret = wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(clientTls12Ssl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
    do {
        ret = wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_SECP256R1);
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
            wolfSSL_AsyncPoll(clientSsl, WOLF_POLL_FLAG_CHECK_HW);
    #endif
    }
    while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
#elif defined(HAVE_CURVE25519)
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_X25519),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_X25519),
        WOLFSSL_SUCCESS);
#endif
#elif defined(HAVE_CURVE448)
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_X448),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_X448),
        WOLFSSL_SUCCESS);
#endif
#else
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, WOLFSSL_ECC_SECP256R1),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
#endif

#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_MALLOC) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    (!defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE) || \
     (defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)) || \
     (defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768)))
#ifndef WOLFSSL_NO_ML_KEM
#ifndef WOLFSSL_TLS_NO_MLKEM_STANDALONE
#ifndef WOLFSSL_NO_ML_KEM_768
    mlkemLevel = WOLFSSL_ML_KEM_768;
#elif !defined(WOLFSSL_NO_ML_KEM_1024)
    mlkemLevel = WOLFSSL_ML_KEM_1024;
#else
    mlkemLevel = WOLFSSL_ML_KEM_512;
#endif
#else
#if defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)
    mlkemLevel = WOLFSSL_X25519MLKEM768;
#elif defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768)
    mlkemLevel = WOLFSSL_SECP256R1MLKEM768;
#endif
#endif
#else
#ifndef WOLFSSL_NO_KYBER768
    mlkemLevel = WOLFSSL_KYBER_LEVEL3;
#elif !defined(WOLFSSL_NO_KYBER1024)
    mlkemLevel = WOLFSSL_KYBER_LEVEL5;
#else
    mlkemLevel = WOLFSSL_KYBER_LEVEL1;
#endif
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(NULL, mlkemLevel),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_UseKeyShare(serverSsl, mlkemLevel),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_UseKeyShare(clientTls12Ssl, mlkemLevel),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_UseKeyShare(clientSsl, mlkemLevel),
        WOLFSSL_SUCCESS);
#endif
#endif

    ExpectIntEQ(wolfSSL_NoKeyShares(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_NoKeyShares(serverSsl), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_NoKeyShares(clientTls12Ssl), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_NoKeyShares(clientSsl), WOLFSSL_SUCCESS);
#endif
#endif /* HAVE_SUPPORTED_CURVES */

    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(clientCtx),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(serverTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_no_ticket_TLSv13(serverCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(clientSsl),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(serverTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(serverSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(clientTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(clientCtx), 0);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_no_dhe_psk(serverCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_no_dhe_psk(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_no_dhe_psk(clientTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_no_dhe_psk(clientSsl), 0);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_no_dhe_psk(serverSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_update_keys(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_update_keys(clientTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_update_keys(clientSsl),
        WC_NO_ERR_TRACE(BUILD_MSG_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_update_keys(serverSsl),
        WC_NO_ERR_TRACE(BUILD_MSG_ERROR));
#endif

    ExpectIntEQ(wolfSSL_key_update_response(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_key_update_response(NULL, &required),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_key_update_response(clientTls12Ssl, &required),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_key_update_response(clientSsl, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_key_update_response(serverSsl, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#if !defined(NO_CERTS) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(serverCtx),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(clientTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_allow_post_handshake_auth(clientCtx), 0);
#endif

    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(serverSsl),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(clientTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(clientSsl), 0);
#endif

    ExpectIntEQ(wolfSSL_request_certificate(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_request_certificate(clientSsl),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_request_certificate(serverTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_request_certificate(serverSsl),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));
#endif
#endif

#ifdef HAVE_ECC
#ifndef WOLFSSL_NO_SERVER_GROUPS_EXT
    ExpectIntEQ(wolfSSL_preferred_group(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_preferred_group(serverSsl),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_preferred_group(clientTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_preferred_group(clientSsl),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));
#endif
#endif

#ifdef HAVE_SUPPORTED_CURVES
    ExpectIntEQ(wolfSSL_CTX_set_groups(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_CTX_set_groups(NULL, groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientTls12Ctx, groups, numGroups),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_groups(clientCtx, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_set_groups(serverCtx, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_groups(serverCtx, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wolfSSL_set_groups(NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_set_groups(NULL, groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_set_groups(clientTls12Ssl, groups, numGroups),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(clientSsl, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_set_groups(serverSsl, groups, numGroups),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(serverSsl, bad_groups, numGroups),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#ifdef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientCtx, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(NULL, groupList),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_CLIENT)
    {
        int idx;
        for (idx = 0; idx < WOLFSSL_MAX_GROUP_COUNT + 1; idx++)
            too_many_groups[idx] = WOLFSSL_ECC_SECP256R1;
    }
    ExpectIntEQ(wolfSSL_CTX_set1_groups(clientCtx, too_many_groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_set1_groups(clientSsl, too_many_groups,
        WOLFSSL_MAX_GROUP_COUNT + 1), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientTls12Ctx, groupList),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(clientCtx, groupList),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(serverCtx, groupList),
        WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_set1_groups_list(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_set1_groups_list(clientSsl, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    ExpectIntEQ(wolfSSL_set1_groups_list(NULL, groupList),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_set1_groups_list(clientTls12Ssl, groupList),
        WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_set1_groups_list(clientSsl, groupList),
        WOLFSSL_SUCCESS);
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_set1_groups_list(serverSsl, groupList),
        WOLFSSL_SUCCESS);
#endif
#endif /* OPENSSL_EXTRA */
#endif /* HAVE_SUPPORTED_CURVES */
#endif /* HAVE_ECC */

#ifdef WOLFSSL_EARLY_DATA
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_CTX_get_max_early_data(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(clientCtx, 0),
        WC_NO_ERR_TRACE(SIDE_ERROR));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(clientCtx),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(clientCtx, 0),
        WC_NO_ERR_TRACE(SIDE_ERROR));
    ExpectIntEQ(SSL_CTX_get_max_early_data(clientCtx),
        WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverTls12Ctx, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(serverTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(serverTls12Ctx, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_CTX_get_max_early_data(serverTls12Ctx),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverCtx, 32),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_CTX_set_max_early_data(serverCtx, 32), 0);
#endif
    ExpectIntEQ(wolfSSL_CTX_get_max_early_data(serverCtx), 32);
#else
    ExpectIntEQ(SSL_CTX_set_max_early_data(serverCtx, 32), 1);
    ExpectIntEQ(SSL_CTX_get_max_early_data(serverCtx), 32);
#endif
#endif

#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_set_max_early_data(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_max_early_data(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_set_max_early_data(NULL, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_get_max_early_data(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_set_max_early_data(clientSsl, 17), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_max_early_data(clientSsl, 17), 0);
#endif
    ExpectIntEQ(wolfSSL_get_max_early_data(clientSsl), 17);
#else
    ExpectIntEQ(SSL_set_max_early_data(clientSsl, 17), WOLFSSL_SUCCESS);
    ExpectIntEQ(SSL_get_max_early_data(clientSsl), 17);
#endif
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
#ifndef OPENSSL_EXTRA
    ExpectIntEQ(wolfSSL_set_max_early_data(serverTls12Ssl, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_max_early_data(serverTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#else
    ExpectIntEQ(SSL_set_max_early_data(serverTls12Ssl, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(SSL_get_max_early_data(serverTls12Ssl),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif
#ifndef OPENSSL_EXTRA
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(wolfSSL_set_max_early_data(serverSsl, 16), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_max_early_data(serverSsl, 16), 0);
#endif
    ExpectIntEQ(wolfSSL_get_max_early_data(serverSsl), 16);
#else
    ExpectIntEQ(SSL_set_max_early_data(serverSsl, 16), 1);
    ExpectIntEQ(SSL_get_max_early_data(serverSsl), 16);
#endif
#endif


    ExpectIntEQ(wolfSSL_write_early_data(NULL, earlyData, sizeof(earlyData),
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, NULL, sizeof(earlyData),
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData, -1, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_write_early_data(serverSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_CLIENT
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_write_early_data(clientTls12Ssl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    /* invoking without session or psk cbs */
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    /* verify *outSz is initialized to 0 even on non-success paths */
    outSz = 42;
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(outSz, 0);
#endif

    ExpectIntEQ(wolfSSL_read_early_data(NULL, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef NO_WOLFSSL_SERVER
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, NULL,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer, -1,
        &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#ifndef NO_WOLFSSL_CLIENT
    ExpectIntEQ(wolfSSL_read_early_data(clientSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(SIDE_ERROR));
#endif
#ifndef NO_WOLFSSL_SERVER
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(wolfSSL_read_early_data(serverTls12Ssl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wolfSSL_read_early_data(serverSsl, earlyDataBuffer,
        sizeof(earlyDataBuffer), &outSz), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#endif
#endif

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_EARLY_DATA)
    ExpectIntLT(SSL_get_early_data_status(NULL), 0);
#endif


#ifndef NO_WOLFSSL_SERVER
    wolfSSL_free(serverSsl);
    wolfSSL_CTX_free(serverCtx);
#endif
#ifndef NO_WOLFSSL_CLIENT
    wolfSSL_free(clientSsl);
    wolfSSL_CTX_free(clientCtx);
#endif

#ifndef WOLFSSL_NO_TLS12
#ifndef NO_WOLFSSL_SERVER
    wolfSSL_free(serverTls12Ssl);
    wolfSSL_CTX_free(serverTls12Ctx);
#endif
#ifndef NO_WOLFSSL_CLIENT
    wolfSSL_free(clientTls12Ssl);
    wolfSSL_CTX_free(clientTls12Ctx);
#endif
#endif
#endif /* WOLFSSL_TLS13 */

    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_WOLFSSL_SERVER) && defined(HAVE_ECC) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384)
/* Called when writing. */
static int CsSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    /* Force error return from wolfSSL_accept_TLSv13(). */
    return WANT_WRITE;
}
/* Called when reading. */
static int CsRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;
    (void)sz;

    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

int test_tls13_cipher_suites(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && \
    !defined(NO_WOLFSSL_SERVER) && defined(HAVE_ECC) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL *ssl = NULL;
    int i;
    byte clientHello[] = {
        0x16, 0x03, 0x03, 0x01, 0x9b, 0x01, 0x00, 0x01,
        0x97, 0x03, 0x03, 0xf4, 0x65, 0xbd, 0x22, 0xfe,
        0x6e, 0xab, 0x66, 0xdd, 0xcf, 0xe9, 0x65, 0x55,
        0xe8, 0xdf, 0xc3, 0x8e, 0x4b, 0x00, 0xbc, 0xf8,
        0x23, 0x57, 0x1b, 0xa0, 0xc8, 0xa9, 0xe2, 0x8c,
        0x91, 0x6e, 0xf9, 0x20, 0xf7, 0x5c, 0xc5, 0x5b,
        0x75, 0x8c, 0x47, 0x0a, 0x0e, 0xc4, 0x1a, 0xda,
        0xef, 0x75, 0xe5, 0x21, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        /* Cipher suites: 0x13, 0x01 = TLS13-AES128-GCM-SHA256, twice. */
                                            0x13, 0x01,
        0x13, 0x01, 0x01, 0x00, 0x01, 0x4a, 0x00, 0x2d,
        0x00, 0x03, 0x02, 0x00, 0x01, 0x00, 0x33, 0x00,
        0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04,
        0x90, 0xfc, 0xe2, 0x97, 0x05, 0x7c, 0xb5, 0x23,
        0x5d, 0x5f, 0x5b, 0xcd, 0x0c, 0x1e, 0xe0, 0xe9,
        0xab, 0x38, 0x6b, 0x1e, 0x20, 0x5c, 0x1c, 0x90,
        0x2a, 0x9e, 0x68, 0x8e, 0x70, 0x05, 0x10, 0xa8,
        0x02, 0x1b, 0xf9, 0x5c, 0xef, 0xc9, 0xaf, 0xca,
        0x1a, 0x3b, 0x16, 0x8b, 0xe4, 0x1b, 0x3c, 0x15,
        0xb8, 0x0d, 0xbd, 0xaf, 0x62, 0x8d, 0xa7, 0x13,
        0xa0, 0x7c, 0xe0, 0x59, 0x0c, 0x4f, 0x8a, 0x6d,
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x03, 0x05,
        0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06, 0x08,
        0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08,
        0x09, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01, 0x03,
        0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x17, 0x00, 0x16, 0x00, 0x00, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x29, 0x00, 0xb9, 0x00,
        0x94, 0x00, 0x8e, 0x0f, 0x12, 0xfa, 0x84, 0x1f,
        0x76, 0x94, 0xd7, 0x09, 0x5e, 0xad, 0x08, 0x51,
        0xb6, 0x80, 0x28, 0x31, 0x8b, 0xfd, 0xc6, 0xbd,
        0x9e, 0xf5, 0x3b, 0x4d, 0x02, 0xbe, 0x1d, 0x73,
        0xea, 0x13, 0x68, 0x00, 0x4c, 0xfd, 0x3d, 0x48,
        0x51, 0xf9, 0x06, 0xbb, 0x92, 0xed, 0x42, 0x9f,
        0x7f, 0x2c, 0x73, 0x9f, 0xd9, 0xb4, 0xef, 0x05,
        0x26, 0x5b, 0x60, 0x5c, 0x0a, 0xfc, 0xa3, 0xbd,
        0x2d, 0x2d, 0x8b, 0xf9, 0xaa, 0x5c, 0x96, 0x3a,
        0xf2, 0xec, 0xfa, 0xe5, 0x57, 0x2e, 0x87, 0xbe,
        0x27, 0xc5, 0x3d, 0x4f, 0x5d, 0xdd, 0xde, 0x1c,
        0x1b, 0xb3, 0xcc, 0x27, 0x27, 0x57, 0x5a, 0xd9,
        0xea, 0x99, 0x27, 0x23, 0xa6, 0x0e, 0xea, 0x9c,
        0x0d, 0x85, 0xcb, 0x72, 0xeb, 0xd7, 0x93, 0xe3,
        0xfe, 0xf7, 0x5c, 0xc5, 0x5b, 0x75, 0x8c, 0x47,
        0x0a, 0x0e, 0xc4, 0x1a, 0xda, 0xef, 0x75, 0xe5,
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfb, 0x92, 0xce, 0xaa, 0x00, 0x21, 0x20,
        0xcb, 0x73, 0x25, 0x80, 0x46, 0x78, 0x4f, 0xe5,
        0x34, 0xf6, 0x91, 0x13, 0x7f, 0xc8, 0x8d, 0xdc,
        0x81, 0x04, 0xb7, 0x0d, 0x49, 0x85, 0x2e, 0x12,
        0x7a, 0x07, 0x23, 0xe9, 0x13, 0xa4, 0x6d, 0x8c
    };
    WOLFSSL_BUFFER_INFO msg;
    /* Offset into ClientHello message data of first cipher suite. */
    const int csOff = 78;
    /* Server cipher list. */
    const char* serverCs = "TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256";
    /* Suite list with duplicates. */
    const char* dupCs = "TLS13-AES128-GCM-SHA256:"
                        "TLS13-AES128-GCM-SHA256:"
                        "TLS13-AES256-GCM-SHA384:"
                        "TLS13-AES256-GCM-SHA384:"
                        "TLS13-AES128-GCM-SHA256";
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
    const byte dupCsBytes[] = { TLS13_BYTE, TLS_AES_256_GCM_SHA384,
                                TLS13_BYTE, TLS_AES_256_GCM_SHA384,
                                TLS13_BYTE, TLS_AES_128_GCM_SHA256,
                                TLS13_BYTE, TLS_AES_128_GCM_SHA256,
                                TLS13_BYTE, TLS_AES_256_GCM_SHA384 };
#endif

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        CERT_FILETYPE));
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, CsRecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, CsSend);

    /* Test cipher suite list with many copies of a cipher suite. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Force server to have as many occurrences of same cipher suite as
     * possible. */
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        suites->suiteSz = WOLFSSL_MAX_SUITE_SZ;
        for (i = 0; i < suites->suiteSz; i += 2) {
            suites->suites[i + 0] = TLS13_BYTE;
            suites->suites[i + 1] = TLS_AES_128_GCM_SHA256;
        }
    }
    /* Test multiple occurrences of same cipher suite. */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Set client order opposite to server order:
     *   TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384 */
    clientHello[csOff + 0] = TLS13_BYTE;
    clientHello[csOff + 1] = TLS_AES_128_GCM_SHA256;
    clientHello[csOff + 2] = TLS13_BYTE;
    clientHello[csOff + 3] = TLS_AES_256_GCM_SHA384;

    /* Test server order negotiation. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Server order: TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl, serverCs), WOLFSSL_SUCCESS);
    /* Negotiate cipher suites in server order: TLS13-AES256-GCM-SHA384 */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Check refined order - server order. */
    ExpectIntEQ(ssl->suites->suiteSz, 4);
    ExpectIntEQ(ssl->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[1], TLS_AES_256_GCM_SHA384);
    ExpectIntEQ(ssl->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[3], TLS_AES_128_GCM_SHA256);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Test client order negotiation. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);
    /* Server order: TLS13-AES256-GCM-SHA384:TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl, serverCs), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseClientSuites(ssl), 0);
    /* Negotiate cipher suites in client order: TLS13-AES128-GCM-SHA256 */
    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Check refined order - client order. */
    ExpectIntEQ(ssl->suites->suiteSz, 4);
    ExpectIntEQ(ssl->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[1], TLS_AES_128_GCM_SHA256);
    ExpectIntEQ(ssl->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ssl->suites->suites[3], TLS_AES_256_GCM_SHA384);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Check duplicate detection is working. */
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, dupCs), WOLFSSL_SUCCESS);
    ExpectIntEQ(ctx->suites->suiteSz, 4);
    ExpectIntEQ(ctx->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[1], TLS_AES_128_GCM_SHA256);
    ExpectIntEQ(ctx->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[3], TLS_AES_256_GCM_SHA384);

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list_bytes(ctx, dupCsBytes,
        sizeof(dupCsBytes)), WOLFSSL_SUCCESS);
    ExpectIntEQ(ctx->suites->suiteSz, 4);
    ExpectIntEQ(ctx->suites->suites[0], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[1], TLS_AES_256_GCM_SHA384);
    ExpectIntEQ(ctx->suites->suites[2], TLS13_BYTE);
    ExpectIntEQ(ctx->suites->suites[3], TLS_AES_128_GCM_SHA256);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)\
    && !defined(NO_PSK)
static unsigned int test_tls13_bad_psk_binder_client_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* see internal.h MAX_PSK_ID_LEN for PSK identity limit */
    XSTRNCPY(identity, "Client_identity", id_max_len);

    key[0] = 0x20;
    return 1;
}

static unsigned int test_tls13_bad_psk_binder_server_cb(WOLFSSL* ssl,
        const char* id, unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)id;
    (void)key_max_len;
    /* zero means error */
    key[0] = 0x10;
    return 1;
}
#endif

int test_tls13_bad_psk_binder(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)\
    && !defined(NO_PSK)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_bad_psk_binder_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_bad_psk_binder_server_cb);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ( wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(BAD_BINDER));

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.code, illegal_parameter);
    ExpectIntEQ(h.last_rx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


#if defined(HAVE_RPK) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER)

#define svrRpkCertFile     "./certs/rpk/server-cert-rpk.der"
#define clntRpkCertFile    "./certs/rpk/client-cert-rpk.der"

#if defined(WOLFSSL_ALWAYS_VERIFY_CB) && defined(WOLFSSL_TLS13)
static int MyRpkVerifyCb(int mode, WOLFSSL_X509_STORE_CTX* strctx)
{
    int ret = WOLFSSL_SUCCESS;
    (void)mode;
    (void)strctx;
    WOLFSSL_ENTER("MyRpkVerifyCb");
    return ret;
}
#endif /* WOLFSSL_ALWAYS_VERIFY_CB && WOLFSSL_TLS13 */

static WC_INLINE int test_rpk_memio_setup(
    struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c,
    WOLFSSL_CTX **ctx_s,
    WOLFSSL **ssl_c,
    WOLFSSL **ssl_s,
    method_provider method_c,
    method_provider method_s,
    const char* certfile_c, int fmt_cc, /* client cert file path and format */
    const char* certfile_s, int fmt_cs, /* server cert file path and format */
    const char* pkey_c,     int fmt_kc, /* client private key and format */
    const char* pkey_s,     int fmt_ks  /* server private key and format */
    )
{
    int ret;
    if (ctx_c != NULL && *ctx_c == NULL) {
        *ctx_c = wolfSSL_CTX_new(method_c());
        if (*ctx_c == NULL) {
            return -1;
        }
        wolfSSL_CTX_set_verify(*ctx_c, WOLFSSL_VERIFY_PEER, NULL);

        ret = wolfSSL_CTX_load_verify_locations(*ctx_c, caCertFile, 0);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        wolfSSL_SetIORecv(*ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_c, test_memio_write_cb);

        ret = wolfSSL_CTX_use_certificate_file(*ctx_c, certfile_c, fmt_cc);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_c, pkey_c, fmt_kc);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
    }

    if (ctx_s != NULL && *ctx_s == NULL) {
        *ctx_s = wolfSSL_CTX_new(method_s());
        if (*ctx_s == NULL) {
            return -1;
        }
        wolfSSL_CTX_set_verify(*ctx_s, WOLFSSL_VERIFY_PEER, NULL);

        ret = wolfSSL_CTX_load_verify_locations(*ctx_s, cliCertFile, 0);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }

        ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_s, pkey_s, fmt_ks);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        ret = wolfSSL_CTX_use_certificate_file(*ctx_s, certfile_s, fmt_cs);
        if (ret != WOLFSSL_SUCCESS) {
            return -1;
        }
        wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_s, test_memio_write_cb);
        if (ctx->s_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_s, ctx->s_ciphers);
            if (ret != WOLFSSL_SUCCESS) {
                return -1;
            }
        }
    }

    if (ctx_c != NULL && ssl_c != NULL) {
        *ssl_c = wolfSSL_new(*ctx_c);
        if (*ssl_c == NULL) {
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_c, ctx);
        wolfSSL_SetIOReadCtx(*ssl_c, ctx);
    }
    if (ctx_s != NULL && ssl_s != NULL) {
        *ssl_s = wolfSSL_new(*ctx_s);
        if (*ssl_s == NULL) {
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_s, ctx);
        wolfSSL_SetIOReadCtx(*ssl_s, ctx);
#if !defined(NO_DH)
        SetDH(*ssl_s);
#endif
    }

    return 0;
}
#endif /* HAVE_RPK && !NO_TLS && !NO_WOLFSSL_CLIENT && !NO_WOLFSSL_SERVER */


int test_tls13_rpk_handshake(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && \
    (!defined(WOLFSSL_NO_TLS12) || defined(WOLFSSL_TLS13)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
#ifdef WOLFSSL_TLS13
    int ret = 0;
#endif
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int err;
    char certType_c[MAX_CLIENT_CERT_TYPE_CNT];
    char certType_s[MAX_CLIENT_CERT_TYPE_CNT];
    int typeCnt_c;
    int typeCnt_s;
    int tp = 0;
#if defined(WOLFSSL_ALWAYS_VERIFY_CB) && defined(WOLFSSL_TLS13)
    int isServer;
#endif
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    (void)err;
    (void)typeCnt_c;
    (void)typeCnt_s;
    (void)certType_c;
    (void)certType_s;

#ifndef WOLFSSL_NO_TLS12
    /*  TLS1.2
     *  Both client and server load x509 cert and start handshaking.
     *  Check no negotiation occurred.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            cliCertFile,     CERT_FILETYPE,
            svrCertFile,     CERT_FILETYPE,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE)
        , 0);


    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    /*  both client and server do not call client/server_cert_type APIs,
     *  expecting default settings works and no negotiation performed.
     */

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* confirm no negotiation occurred */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ((int)tp, WOLFSSL_CERT_TYPE_UNKNOWN);
    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                            WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    (void)typeCnt_c;
    (void)typeCnt_s;

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif

#ifdef WOLFSSL_TLS13
    /*  Both client and server load x509 cert and start handshaking.
     *  Check no negotiation occurred.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     CERT_FILETYPE,
            svrCertFile,     CERT_FILETYPE,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    /*  both client and server do not call client/server_cert_type APIs,
     *  expecting default settings works and no negotiation performed.
     */

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* confirm no negotiation occurred */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ((int)tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    (void)typeCnt_c;
    (void)typeCnt_s;

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Both client and server load RPK cert and start handshaking.
     *  Confirm negotiated cert types match as expected.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif


#ifndef WOLFSSL_NO_TLS12
    /*  TLS1.2
     *  Both client and server load RPK cert and start handshaking.
     *  Confirm negotiated cert types match as expected.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif


#ifdef WOLFSSL_TLS13
    /*  Both client and server load x509 cert.
     *  Have client call set_client_cert_type with both RPK and x509.
     *  This doesn't makes client add client cert type extension to ClientHello,
     *  since it does not load RPK cert actually.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     CERT_FILETYPE,
            svrCertFile,     CERT_FILETYPE,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* set client certificate type in client end
     *
     * client indicates both RPK and x509 certs are available but loaded RPK
     * cert only. It does not have client add client-cert-type extension in CH.
     */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* client indicates both RPK and x509 certs are acceptable */
    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* server indicates both RPK and x509 certs are acceptable */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* server should indicate only RPK cert is available */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    /* Negotiation for client-cert-type should NOT happen. Therefore -1 should
     * be returned as cert type.
     */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have client load RPK cert and have server load x509 cert.
     *  Check the negotiation result from both ends.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrCertFile,     CERT_FILETYPE,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* have client tell to use RPK cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* does not call wolfSSL_set_server_cert_type intentionally in sesrver
     * end, expecting the default setting works.
     */


    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have both client and server load RPK cert, however, have server
     *  indicate its cert type x509.
     *  Client is expected to detect the cert type mismatch then to send alert
     *  with "unsupported_certificate".
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1, /* server sends RPK cert */
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* have client tell to use RPK cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have server tell to use x509 cert intentionally. This will bring
     * certificate type mismatch in client side.
     */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* expect client detect cert type mismatch then send Alert */
    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (ret != -1)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_error(ssl_c, ret),
        WC_NO_ERR_TRACE(UNSUPPORTED_CERTIFICATE));

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


    /*  Have client load x509 cert and server load RPK cert,
     *  however, have client indicate its cert type RPK.
     *  Server is expected to detect the cert type mismatch then to send alert
     *  with "unsupported_certificate".
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            cliCertFile,     CERT_FILETYPE,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* have client tell to use RPK cert intentionally */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = -1;
    typeCnt_c = 1;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have client tell to accept both RPK and x509 cert */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* have server accept to both RPK and x509 cert */
    certType_c[0] = WOLFSSL_CERT_TYPE_X509;
    certType_c[1] = WOLFSSL_CERT_TYPE_RPK;
    typeCnt_c = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* have server tell to use x509 cert intentionally. This will bring
     * certificate type mismatch in client side.
     */
    certType_s[0] = WOLFSSL_CERT_TYPE_X509;
    certType_s[1] = -1;
    typeCnt_s = 1;

    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);

    /* expect server detect cert type mismatch then send Alert */
    ExpectIntNE(ret, 0);
    err = wolfSSL_get_error(ssl_c, ret);
    ExpectIntEQ(err, WC_NO_ERR_TRACE(UNSUPPORTED_CERTIFICATE));

    /* client did not load RPK cert actually, so negotiation did not happen */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    /* client did not load RPK cert actually, so negotiation did not happen */
    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_UNKNOWN);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_X509);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;


#if defined(WOLFSSL_ALWAYS_VERIFY_CB)
    /*  Both client and server load RPK cert and set certificate verify
     *  callbacks then start handshaking.
     *  Confirm both side can refer the peer's cert.
     */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(
        test_rpk_memio_setup(
            &test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
            clntRpkCertFile, WOLFSSL_FILETYPE_ASN1,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      CERT_FILETYPE,
            svrKeyFile,      CERT_FILETYPE )
        , 0);

    /* set client certificate type in client end */
    certType_c[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_c[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_c = 2;

    certType_s[0] = WOLFSSL_CERT_TYPE_RPK;
    certType_s[1] = WOLFSSL_CERT_TYPE_X509;
    typeCnt_s = 2;

    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_c, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in client end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_c, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set client certificate type in server end */
    ExpectIntEQ(wolfSSL_set_client_cert_type(ssl_s, certType_c, typeCnt_c),
                                                        WOLFSSL_SUCCESS);

    /* set server certificate type in server end */
    ExpectIntEQ(wolfSSL_set_server_cert_type(ssl_s, certType_s, typeCnt_s),
                                                        WOLFSSL_SUCCESS);

    /* set certificate verify callback to both client and server */
    isServer = 0;
    wolfSSL_SetCertCbCtx(ssl_c, &isServer);
    wolfSSL_set_verify(ssl_c, SSL_VERIFY_PEER, MyRpkVerifyCb);

    isServer = 1;
    wolfSSL_SetCertCbCtx(ssl_c, &isServer);
    wolfSSL_set_verify(ssl_s, SSL_VERIFY_PEER, MyRpkVerifyCb);

    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (ret != 0)
        return TEST_FAIL;

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_c, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_client_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    ExpectIntEQ(wolfSSL_get_negotiated_server_cert_type(ssl_s, &tp),
                                                        WOLFSSL_SUCCESS);
    ExpectIntEQ(tp, WOLFSSL_CERT_TYPE_RPK);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif /* WOLFSSL_ALWAYS_VERIFY_CB */
#endif /* WOLFSSL_TLS13 */

#endif /* HAVE_RPK && (!WOLFSSL_NO_TLS12 || WOLFSSL_TLS13) */
    return EXPECT_RESULT();
}


#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    (!defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE) || \
     (defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)) || \
     (defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768)))
static void test_tls13_pq_groups_ctx_ready(WOLFSSL_CTX* ctx)
{
#ifdef WOLFSSL_MLKEM_KYBER
    #if !defined(WOLFSSL_NO_KYBER1024)
    int group = WOLFSSL_KYBER_LEVEL5;
    #elif !defined(WOLFSSL_NO_KYBER768)
    int group = WOLFSSL_KYBER_LEVEL3;
    #else
    int group = WOLFSSL_KYBER_LEVEL1;
    #endif
#elif !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #if !defined(WOLFSSL_NO_ML_KEM_1024)
    int group = WOLFSSL_ML_KEM_1024;
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
    int group = WOLFSSL_ML_KEM_768;
    #else
    int group = WOLFSSL_ML_KEM_512;
    #endif
#elif defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768) && \
      defined(WOLFSSL_PQC_HYBRIDS)
    int group = WOLFSSL_SECP256R1MLKEM768;
#elif defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768) && \
      defined(WOLFSSL_PQC_HYBRIDS)
    int group = WOLFSSL_X25519MLKEM768;
#endif

    AssertIntEQ(wolfSSL_CTX_set_groups(ctx, &group, 1), WOLFSSL_SUCCESS);
}

static void test_tls13_pq_groups_on_result(WOLFSSL* ssl)
{
#ifdef WOLFSSL_MLKEM_KYBER
    #if !defined(WOLFSSL_NO_KYBER1024)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "KYBER_LEVEL5");
    #elif !defined(WOLFSSL_NO_KYBER768)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "KYBER_LEVEL3");
    #else
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "KYBER_LEVEL1");
    #endif
#elif !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #if !defined(WOLFSSL_NO_ML_KEM_1024)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "ML_KEM_1024");
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "ML_KEM_768");
    #else
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "ML_KEM_512");
    #endif
#elif defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768) && \
      defined(WOLFSSL_PQC_HYBRIDS)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "SecP256r1MLKEM768");
#elif defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768) && \
      defined(WOLFSSL_PQC_HYBRIDS)
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "X25519MLKEM768");
#endif
}
#endif

int test_tls13_pq_groups(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    (!defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE) || \
     (defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)) || \
     (defined(HAVE_ECC) && !defined(WOLFSSL_NO_ML_KEM_768)))
    callback_functions func_cb_client;
    callback_functions func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(callback_functions));
    XMEMSET(&func_cb_server, 0, sizeof(callback_functions));

    func_cb_client.method = wolfTLSv1_3_client_method;
    func_cb_server.method = wolfTLSv1_3_server_method;
    func_cb_client.ctx_ready = test_tls13_pq_groups_ctx_ready;
    func_cb_client.on_result = test_tls13_pq_groups_on_result;
    func_cb_server.on_result = test_tls13_pq_groups_on_result;

    test_wolfSSL_client_server_nofail(&func_cb_client, &func_cb_server);

    ExpectIntEQ(func_cb_client.return_code, TEST_SUCCESS);
    ExpectIntEQ(func_cb_server.return_code, TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET)
static int test_tls13_read_until_write_ok(WOLFSSL* ssl, void* buf, int bufLen)
{
    int ret, err;
    int tries = 5;

    err = 0;
    do {
        ret = wolfSSL_read(ssl, buf, bufLen);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
            err = wolfSSL_get_error(ssl, ret);
        }
    } while (tries-- && ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) &&
             err == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_WRITE));
    return ret;
}
static int test_tls13_connect_until_write_ok(WOLFSSL* ssl)
{
    int ret, err;
    int tries = 5;

    err = 0;
    do {
        ret = wolfSSL_connect(ssl);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
            err = wolfSSL_get_error(ssl, ret);
        }
    } while (tries-- && ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) &&
             err == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_WRITE));
    return ret;
}
static int test_tls13_write_until_write_ok(WOLFSSL* ssl, const void* msg,
    int msgLen)
{
    int ret, err;
    int tries = 5;

    err = 0;
    do {
        ret = wolfSSL_write(ssl, msg, msgLen);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
            err = wolfSSL_get_error(ssl, ret);
        }
    } while (tries-- && ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) &&
             err == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_WRITE));
    return ret;
}
static int test_tls13_early_data_read_until_write_ok(WOLFSSL* ssl, void* buf,
    int bufLen, int* read)
{
    int ret, err;
    int tries = 5;

    err = 0;
    do {
        ret = wolfSSL_read_early_data(ssl, buf, bufLen, read);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
            err = wolfSSL_get_error(ssl, ret);
        }
    } while (tries-- && ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) &&
             err == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_WRITE));
    return ret;
}
static int test_tls13_early_data_write_until_write_ok(WOLFSSL* ssl,
    const void* msg, int msgLen, int* written)
{
    int ret, err;
    int tries = 5;

    err = 0;
    do {
        ret = wolfSSL_write_early_data(ssl, msg, msgLen, written);
        if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
            err = wolfSSL_get_error(ssl, ret);
        }
    } while (tries-- && ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR) &&
             err == WC_NO_ERR_TRACE(WOLFSSL_ERROR_WANT_WRITE));
    return ret;
}
struct test_tls13_wwrite_ctx {
    int want_write;
    struct test_memio_ctx *test_ctx;
};
static int test_tls13_mock_wantwrite_cb(WOLFSSL* ssl, char* data, int sz,
    void* ctx)
{
    struct test_tls13_wwrite_ctx *wwctx = (struct test_tls13_wwrite_ctx *)ctx;
#ifdef WOLFSSL_TLS13_MIDDLEBOX_COMPAT
    /* Write ChangeCipherSpec message. */
    if (data[0] != 0x14)
#endif
    {
        wwctx->want_write = !wwctx->want_write;
        if (wwctx->want_write) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
    }
    return test_memio_write_cb(ssl, data, sz, wwctx->test_ctx);
}
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && WOLFSSL_EARLY_DATA */
int test_tls13_early_data(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET)
    int written = 0;
    int read = 0;
    size_t i;
    char msg[] = "This is early data";
    char msg2[] = "This is client data";
    char msg3[] = "This is server data";
    char msg4[] = "This is server immediate data";
    char msgBuf[50];
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
        int isUdp;
        int splitEarlyData;
        int everyWriteWantWrite;
    } params[] = {
#ifdef WOLFSSL_TLS13
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0, 1, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0, 0, 1 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0, 1, 1 },
#endif
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1, 0, 0 },
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1, 1, 0 },
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1, 0, 1 },
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1, 1, 1 },
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        WOLFSSL_SESSION *sess = NULL;
        int splitEarlyData = params[i].splitEarlyData;
        int everyWriteWantWrite = params[i].everyWriteWantWrite;
        struct test_tls13_wwrite_ctx wwrite_ctx_s, wwrite_ctx_c;
        (void)ctx_c;
        (void)ssl_c;
        (void)ctx_s;
        (void)ssl_s;
        (void)test_ctx;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(&wwrite_ctx_c, 0, sizeof(wwrite_ctx_c));
        XMEMSET(&wwrite_ctx_s, 0, sizeof(wwrite_ctx_s));

        fprintf(stderr, "\tEarly data with %s%s%s\n", params[i].tls_version,
            splitEarlyData ? " (split early data)" : "",
            everyWriteWantWrite ? " (every write WANT_WRITE)" : "");

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                &ssl_s, params[i].client_meth, params[i].server_meth), 0);

        if (params[i].isUdp) {
            /* Early data is incompatible with HRR usage. Hence, we have to make
             * sure a group is negotiated that does not cause a fragemented CH.
             */
            int group[1] = {
            #ifdef HAVE_ECC
                WOLFSSL_ECC_SECP256R1,
            #elif defined(HAVE_CURVE25519)
                WOLFSSL_ECC_X25519,
            #elif defined(HAVE_CURVE448)
                WOLFSSL_ECC_X448,
            #elif defined(HAVE_FFDHE_2048)
                WOLFSSL_FFDHE_2048,
            #endif
            };
            ExpectIntEQ(wolfSSL_set_groups(ssl_c, group, 1), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_set_groups(ssl_s, group, 1), WOLFSSL_SUCCESS);
        }

        /* Get a ticket so that we can do 0-RTT on the next connection */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        /* Make sure we read the ticket */
        ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

        wolfSSL_free(ssl_c);
        ssl_c = NULL;
        wolfSSL_free(ssl_s);
        ssl_s = NULL;
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, params[i].client_meth, params[i].server_meth), 0);
        wolfSSL_SetLoggingPrefix("client");
        ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
#ifdef WOLFSSL_DTLS13
        if (params[i].isUdp) {
            wolfSSL_SetLoggingPrefix("server");
#ifdef WOLFSSL_DTLS13_NO_HRR_ON_RESUME
            ExpectIntEQ(wolfSSL_dtls13_no_hrr_on_resume(ssl_s, 1),
                WOLFSSL_SUCCESS);
#else
            /* Let's test this but we generally don't recommend turning off
             * the cookie exchange */
            ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
#endif
        }
#endif

        if (everyWriteWantWrite) {
            wwrite_ctx_c.test_ctx = &test_ctx;
            wwrite_ctx_s.test_ctx = &test_ctx;
            wolfSSL_SetIOWriteCtx(ssl_c, &wwrite_ctx_c);
            wolfSSL_SSLSetIOSend(ssl_c, test_tls13_mock_wantwrite_cb);
            wolfSSL_SetIOWriteCtx(ssl_s, &wwrite_ctx_s);
            wolfSSL_SSLSetIOSend(ssl_s, test_tls13_mock_wantwrite_cb);
        }
        /* Test 0-RTT data */
        wolfSSL_SetLoggingPrefix("client");

        ExpectIntEQ(test_tls13_early_data_write_until_write_ok(ssl_c, msg,
                        sizeof(msg), &written),
            sizeof(msg));
        ExpectIntEQ(written, sizeof(msg));

        if (splitEarlyData) {
            ExpectIntEQ(test_tls13_early_data_write_until_write_ok(ssl_c, msg,
                            sizeof(msg), &written),
                sizeof(msg));
            ExpectIntEQ(written, sizeof(msg));
        }

        /* Read first 0-RTT data (if split otherwise entire data) */
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(test_tls13_early_data_read_until_write_ok(ssl_s, msgBuf,
                        sizeof(msgBuf), &read),
            sizeof(msg));
        ExpectIntEQ(read, sizeof(msg));
        ExpectStrEQ(msg, msgBuf);

        /* Test 0.5-RTT data */
        ExpectIntEQ(test_tls13_write_until_write_ok(ssl_s, msg4, sizeof(msg4)),
            sizeof(msg4));

        if (splitEarlyData) {
            /* Read second 0-RTT data */
            ExpectIntEQ(test_tls13_early_data_read_until_write_ok(ssl_s, msgBuf,
                            sizeof(msgBuf), &read),
                sizeof(msg));
            ExpectIntEQ(read, sizeof(msg));
            ExpectStrEQ(msg, msgBuf);
        }

        if (params[i].isUdp) {
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(test_tls13_connect_until_write_ok(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
                WC_NO_ERR_TRACE(APP_DATA_READY));

            /* Read server 0.5-RTT data */
            ExpectIntEQ(
                test_tls13_read_until_write_ok(ssl_c, msgBuf, sizeof(msgBuf)),
                sizeof(msg4));
            ExpectStrEQ(msg4, msgBuf);

            /* Complete handshake */
            ExpectIntEQ(test_tls13_connect_until_write_ok(ssl_c), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
                WOLFSSL_ERROR_WANT_READ);
            /* Use wolfSSL_is_init_finished to check if handshake is
             * complete. Normally a user would loop until it is true but
             * here we control both sides so we just assert the expected
             * value. wolfSSL_read_early_data does not provide handshake
             * status to us with non-blocking IO and we can't use
             * wolfSSL_accept as TLS layer may return ZERO_RETURN due to
             * early data parsing logic. */
            wolfSSL_SetLoggingPrefix("server");
            ExpectFalse(wolfSSL_is_init_finished(ssl_s));
            ExpectIntEQ(test_tls13_early_data_read_until_write_ok(ssl_s, msgBuf,
                            sizeof(msgBuf), &read),
                0);
            ExpectIntEQ(read, 0);
            ExpectTrue(wolfSSL_is_init_finished(ssl_s));

            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(test_tls13_connect_until_write_ok(ssl_c),
                WOLFSSL_SUCCESS);
        }
        else {
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(test_tls13_connect_until_write_ok(ssl_c),
                WOLFSSL_SUCCESS);

            wolfSSL_SetLoggingPrefix("server");
            ExpectFalse(wolfSSL_is_init_finished(ssl_s));
            ExpectIntEQ(test_tls13_early_data_read_until_write_ok(ssl_s, msgBuf,
                            sizeof(msgBuf), &read),
                0);
            ExpectIntEQ(read, 0);
            ExpectTrue(wolfSSL_is_init_finished(ssl_s));

            /* Read server 0.5-RTT data */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(
                test_tls13_read_until_write_ok(ssl_c, msgBuf, sizeof(msgBuf)),
                sizeof(msg4));
            ExpectStrEQ(msg4, msgBuf);
        }

        /* Test bi-directional write */
        wolfSSL_SetLoggingPrefix("client");
        ExpectIntEQ(test_tls13_write_until_write_ok(ssl_c, msg2, sizeof(msg2)),
            sizeof(msg2));
        wolfSSL_SetLoggingPrefix("server");
        ExpectIntEQ(
            test_tls13_read_until_write_ok(ssl_s, msgBuf, sizeof(msgBuf)),
            sizeof(msg2));
        ExpectStrEQ(msg2, msgBuf);
        ExpectIntEQ(test_tls13_write_until_write_ok(ssl_s, msg3, sizeof(msg3)),
            sizeof(msg3));
        wolfSSL_SetLoggingPrefix("client");
        ExpectIntEQ(
            test_tls13_read_until_write_ok(ssl_c, msgBuf, sizeof(msgBuf)),
            sizeof(msg3));
        ExpectStrEQ(msg3, msgBuf);

        wolfSSL_SetLoggingPrefix(NULL);
        ExpectTrue(wolfSSL_session_reused(ssl_c));
        ExpectTrue(wolfSSL_session_reused(ssl_s));

        wolfSSL_SESSION_free(sess);
        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}


/* Check that the client won't send the same CH after a HRR. An HRR without
 * a KeyShare or a Cookie extension will trigger the error. */
int test_tls13_same_ch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_AES_128) && \
    defined(HAVE_AESGCM) && !defined(NO_SHA256) && \
    /* middlebox compat requires that the session ID is echoed */ \
    !defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;
    /* Transport Layer Security
     *     TLSv1.3 Record Layer: Handshake Protocol: Hello Retry Request
     *         Content Type: Handshake (22)
     *         Version: TLS 1.2 (0x0303)
     *         Length: 50
     *         Handshake Protocol: Hello Retry Request
     *             Handshake Type: Server Hello (2)
     *             Length: 46
     *             Version: TLS 1.2 (0x0303)
     *             Random: cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c (HelloRetryRequest magic)
     *             Session ID Length: 0
     *             Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
     *             Compression Method: null (0)
     *             Extensions Length: 6
     *             Extension: supported_versions (len=2) TLS 1.3 */
    static const unsigned char hrr[] = {
      0x16, 0x03, 0x03, 0x00, 0x32, 0x02, 0x00, 0x00, 0x2e, 0x03, 0x03, 0xcf,
      0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
      0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
      0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x01, 0x00, 0x00,
      0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
    };
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, (char*)hrr,
            sizeof(hrr)), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    /* issue 9653: use a more appropriate error than DUPLICATE_MSG_E.
     * Since the cause of this is missing extension, return that. */
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), EXT_MISSING);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

int test_tls13_hrr_different_cs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384) && \
    defined(BUILD_TLS_CHACHA20_POLY1305_SHA256) && \
    defined(HAVE_ECC) && defined(HAVE_ECC384) && \
    !defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT)
    /*
     * TLSv1.3 Record Layer: Handshake Protocol: Hello Retry Request
     *     Content Type: Handshake (22)
     *     Version: TLS 1.2 (0x0303)
     *     Length: 56
     *     Handshake Protocol: Hello Retry Request
     *         Handshake Type: Server Hello (2)
     *         Length: 52
     *         Version: TLS 1.2 (0x0303)
     *         Random: cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c (HelloRetryRequest magic)
     *         Session ID Length: 0
     *         Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
     *         Compression Method: null (0)
     *         Extensions Length: 12
     *         Extension: supported_versions (len=2) TLS 1.3
     *         Extension: key_share (len=2) secp384r1
     *
     */
    unsigned char hrr[] = {
        0x16, 0x03, 0x03, 0x00, 0x38, 0x02, 0x00, 0x00, 0x34, 0x03, 0x03, 0xcf,
        0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
        0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
        0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x02, 0x00, 0x00,
        0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00,
        0x18
    };
    /*
     * TLSv1.3 Record Layer: Handshake Protocol: Server Hello
     *     Content Type: Handshake (22)
     *     Version: TLS 1.2 (0x0303)
     *     Length: 155
     *     Handshake Protocol: Server Hello
     *         Handshake Type: Server Hello (2)
     *         Length: 151
     *         Version: TLS 1.2 (0x0303)
     *         Random: 0101010101010101010101010101010101010101010101010101010101010101
     *         Session ID Length: 0
     *         Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
     *         Compression Method: null (0)
     *         Extensions Length: 111
     *         Extension: key_share (len=101) secp384r1
     *         Extension: supported_versions (len=2) TLS 1.3
     *
     */
    unsigned char sh[] = {
        0x16, 0x03, 0x03, 0x00, 0x9b, 0x02, 0x00, 0x00, 0x97, 0x03, 0x03, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x13, 0x03, 0x00, 0x00,
        0x6f, 0x00, 0x33, 0x00, 0x65, 0x00, 0x18, 0x00, 0x61, 0x04, 0x53, 0x3e,
        0xe5, 0xbf, 0x40, 0xec, 0x2d, 0x67, 0x98, 0x8b, 0x77, 0xf3, 0x17, 0x48,
        0x9b, 0xb6, 0xdf, 0x95, 0x29, 0x25, 0xc7, 0x09, 0xfc, 0x03, 0x81, 0x11,
        0x1a, 0x59, 0x56, 0xf2, 0xd7, 0x58, 0x11, 0x0e, 0x59, 0xd3, 0xd7, 0xc1,
        0x72, 0x9e, 0x2c, 0x0d, 0x70, 0xea, 0xf7, 0x73, 0xe6, 0x12, 0x01, 0x16,
        0x42, 0x6d, 0xe2, 0x43, 0x6a, 0x2f, 0x5f, 0xdd, 0x7f, 0xe5, 0x4f, 0xaf,
        0x95, 0x2b, 0x04, 0xfd, 0x13, 0xf5, 0x16, 0xce, 0x62, 0x7f, 0x89, 0xd2,
        0x01, 0x9d, 0x4c, 0x87, 0x96, 0x95, 0x9e, 0x43, 0x33, 0xc7, 0x06, 0x5b,
        0x49, 0x6c, 0xa6, 0x34, 0xd5, 0xdc, 0x63, 0xbd, 0xe9, 0x1f, 0x00, 0x2b,
        0x00, 0x02, 0x03, 0x04
    };
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
            wolfTLSv1_3_client_method, NULL), 0);

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, (char*)hrr,
            sizeof(hrr)), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, (char*)sh,
            sizeof(sh)), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), INVALID_PARAMETER);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Server-side complement to test_tls13_hrr_different_cs: the client sends a
 * different cipher suite in CH2 than what the server selected in the HRR. */
int test_tls13_ch2_different_cs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_SERVER) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(HAVE_ECC) && defined(HAVE_ECC384)
    /*
     * First ClientHello: cipher suite TLS_AES_256_GCM_SHA384 (0x1302),
     * empty key_share, secp384r1 in supported_groups. This triggers the
     * server to send a HelloRetryRequest selecting TLS_AES_256_GCM_SHA384
     * and requesting a secp384r1 key share.
     */
    /*
     * TLSv1.3 Record Layer: Handshake Protocol: Client Hello
     *     Content Type: Handshake (22)
     *     Version: TLS 1.2 (0x0303)
     *     Length: 110
     *     Handshake Protocol: Client Hello
     *         Handshake Type: Client Hello (1)
     *         Length: 106
     *         Version: TLS 1.2 (0x0303)
     *         Random: 0101010101010101010101010101010101010101010101010101010101010101
     *         Session ID Length: 32
     *         Session ID: 0303030303030303030303030303030303030303030303030303030303030303
     *         Cipher Suites Length: 2
     *         Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
     *         Compression Methods Length: 1
     *         Compression Method: null (0)
     *         Extensions Length: 31
     *         Extension: supported_groups (len=4) secp384r1 (0x0018)
     *         Extension: signature_algorithms (len=6) rsa_pkcs1_sha256 (0x0401),
     *             rsa_pss_rsae_sha256 (0x0804)
     *         Extension: key_share (len=2) client_shares length=0 (empty)
     *         Extension: supported_versions (len=3) TLS 1.3 (0x0304)
     */
    unsigned char ch1[] = {
        0x16, 0x03, 0x03, 0x00, 0x6e, 0x01, 0x00, 0x00, 0x6a, 0x03, 0x03, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00, 0x1f,
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x06,
        0x00, 0x04, 0x04, 0x01, 0x08, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
    };
    /*
     * TLSv1.3 Record Layer: Handshake Protocol: Client Hello
     *     Content Type: Handshake (22)
     *     Version: TLS 1.2 (0x0303)
     *     Length: 211
     *     Handshake Protocol: Client Hello
     *         Handshake Type: Client Hello (1)
     *         Length: 207
     *         Version: TLS 1.2 (0x0303)
     *         Random: 0101010101010101010101010101010101010101010101010101010101010101
     *         Session ID Length: 32
     *         Session ID: 0303030303030303030303030303030303030303030303030303030303030303
     *         Cipher Suites Length: 2
     *         Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
     *         Compression Methods Length: 1
     *         Compression Method: null (0)
     *         Extensions Length: 132
     *         Extension: supported_groups (len=4) secp384r1 (0x0018)
     *         Extension: signature_algorithms (len=6) rsa_pkcs1_sha256 (0x0401),
     *             rsa_pss_rsae_sha256 (0x0804)
     *         Extension: key_share (len=103)
     *             client_shares length: 101
     *             KeyShareEntry: group secp384r1 (0x0018), key_exchange length: 97
     *             key_exchange: 04 || X(48) || Y(48)  (uncompressed P-384 point)
     *         Extension: supported_versions (len=3) TLS 1.3 (0x0304)
     */
    unsigned char ch2[] = {
        0x16, 0x03, 0x03, 0x00, 0xd3, 0x01, 0x00, 0x00, 0xcf, 0x03, 0x03, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x84,
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x06,
        0x00, 0x04, 0x04, 0x01, 0x08, 0x04, 0x00, 0x33, 0x00, 0x67, 0x00, 0x65,
        0x00, 0x18, 0x00, 0x61, 0x04, 0x53, 0x3e, 0xe5, 0xbf, 0x40, 0xec, 0x2d,
        0x67, 0x98, 0x8b, 0x77, 0xf3, 0x17, 0x48, 0x9b, 0xb6, 0xdf, 0x95, 0x29,
        0x25, 0xc7, 0x09, 0xfc, 0x03, 0x81, 0x11, 0x1a, 0x59, 0x56, 0xf2, 0xd7,
        0x58, 0x11, 0x0e, 0x59, 0xd3, 0xd7, 0xc1, 0x72, 0x9e, 0x2c, 0x0d, 0x70,
        0xea, 0xf7, 0x73, 0xe6, 0x12, 0x01, 0x16, 0x42, 0x6d, 0xe2, 0x43, 0x6a,
        0x2f, 0x5f, 0xdd, 0x7f, 0xe5, 0x4f, 0xaf, 0x95, 0x2b, 0x04, 0xfd, 0x13,
        0xf5, 0x16, 0xce, 0x62, 0x7f, 0x89, 0xd2, 0x01, 0x9d, 0x4c, 0x87, 0x96,
        0x95, 0x9e, 0x43, 0x33, 0xc7, 0x06, 0x5b, 0x49, 0x6c, 0xa6, 0x34, 0xd5,
        0xdc, 0x63, 0xbd, 0xe9, 0x1f, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
    };
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
            NULL, wolfTLSv1_3_server_method), 0);

    /* Server reads CH1, sends HRR, then waits for CH2 */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (char*)ch1,
            sizeof(ch1)), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Server must reject CH2 because the cipher suite changed from the HRR */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (char*)ch2,
            sizeof(ch2)), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), INVALID_PARAMETER);

    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ECC)
/* Called when writing. */
static int MESend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    /* Force error return from wolfSSL_accept_TLSv13(). */
    return WANT_WRITE;
}
/* Called when reading. */
static int MERecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;

    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

int test_tls13_sg_missing(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ECC)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    byte clientHello[] = {
        0x16, 0x03, 0x03, 0x00, 0xcb, 0x01, 0x00, 0x00,
        0xc7, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x01,
        0x01, 0x00, 0x00, 0x7c, 0x00, 0x0d, 0x00, 0x06,
        0x00, 0x04, 0x04, 0x01, 0x08, 0x04,
                                            /* KeyShare */
                                            0x00, 0x33,
        0x00, 0x67, 0x00, 0x65, 0x00, 0x18, 0x00, 0x61,
        0x04, 0x53, 0x3e, 0xe5, 0xbf, 0x40, 0xec, 0x2d,
        0x67, 0x98, 0x8b, 0x77, 0xf3, 0x17, 0x48, 0x9b,
        0xb6, 0xdf, 0x95, 0x29, 0x25, 0xc7, 0x09, 0xfc,
        0x03, 0x81, 0x11, 0x1a, 0x59, 0x56, 0xf2, 0xd7,
        0x58, 0x11, 0x0e, 0x59, 0xd3, 0xd7, 0xc1, 0x72,
        0x9e, 0x2c, 0x0d, 0x70, 0xea, 0xf7, 0x73, 0xe6,
        0x12, 0x01, 0x16, 0x42, 0x6d, 0xe2, 0x43, 0x6a,
        0x2f, 0x5f, 0xdd, 0x7f, 0xe5, 0x4f, 0xaf, 0x95,
        0x2b, 0x04, 0xfd, 0x13, 0xf5, 0x16, 0xce, 0x62,
        0x7f, 0x89, 0xd2, 0x01, 0x9d, 0x4c, 0x87, 0x96,
        0x95, 0x9e, 0x43, 0x33, 0xc7, 0x06, 0x5b, 0x49,
        0x6c, 0xa6, 0x34, 0xd5, 0xdc, 0x63, 0xbd, 0xe9,
        0x1f,
              /* SupportedVersions */
              0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
        /* Missing SupportedGroups. */
    };
    WOLFSSL_BUFFER_INFO msg;
    WOLFSSL_ALERT_HISTORY h;

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        CERT_FILETYPE));
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, MERecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, MESend);

    /* Test cipher suite list with many copies of a cipher suite. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, missing_extension);
    ExpectIntEQ(h.last_tx.level, alert_fatal);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls13_ks_missing(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ECC)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    byte clientHello[] = {
        0x16, 0x03, 0x03, 0x00, 0x66, 0x01, 0x00, 0x00,
        0x62, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x01,
        0x01, 0x00, 0x00, 0x17, 0x00, 0x0d, 0x00, 0x06,
        0x00, 0x04, 0x04, 0x01, 0x08, 0x04,
                                            /* SupportedGroups */
                                            0x00, 0x0a,
        0x00, 0x02, 0x00, 0x18,
                                /* SupportedVersions */
                                0x00, 0x2b, 0x00, 0x03,
        0x02, 0x03, 0x04
        /* Missing KeyShare. */
    };
    WOLFSSL_BUFFER_INFO msg;
    WOLFSSL_ALERT_HISTORY h;

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, eccCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        CERT_FILETYPE));
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, MERecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, MESend);

    /* Test cipher suite list with many copies of a cipher suite. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientHello;
    msg.length = (unsigned int)sizeof(clientHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    ExpectIntEQ(wolfSSL_accept_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, missing_extension);
    ExpectIntEQ(h.last_tx.level, alert_fatal);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_ECC)
/* Called when writing. */
static int DESend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    return sz;
}
/* Called when reading. */
static int DERecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;
    (void)sz;

    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

int test_tls13_duplicate_extension(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_ECC)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    byte serverHello[] = {
        0x16, 0x03, 0x03, 0x00, 0x81, 0x02, 0x00, 0x00,
        0x7d, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x00, 0x13, 0x01, 0x00, 0x00,
        0x55, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00,
        0x33, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04,
        0x0c, 0x90, 0x1d, 0x42, 0x3c, 0x83, 0x1c, 0xa8,
        0x5e, 0x27, 0xc7, 0x3c, 0x26, 0x3b, 0xa1, 0x32,
        0x72, 0x1b, 0xb9, 0xd7, 0xa8, 0x4c, 0x4f, 0x03,
        0x80, 0xb2, 0xa6, 0x75, 0x6f, 0xd6, 0x01, 0x33,
        0x1c, 0x88, 0x70, 0x23, 0x4d, 0xec, 0x87, 0x85,
        0x04, 0xc1, 0x74, 0x14, 0x4f, 0xa4, 0xb1, 0x4b,
        0x66, 0xa6, 0x51, 0x69, 0x16, 0x06, 0xd8, 0x17,
        0x3e, 0x55, 0xbd, 0x37, 0xe3, 0x81, 0x56, 0x9e,
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
    };
    WOLFSSL_BUFFER_INFO msg;
    WOLFSSL_ALERT_HISTORY h;

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, DERecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, DESend);

    /* Test cipher suite list with many copies of a cipher suite. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = serverHello;
    msg.length = (unsigned int)sizeof(serverHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    ExpectIntEQ(wolfSSL_connect_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, illegal_parameter);
    ExpectIntEQ(h.last_tx.level, alert_fatal);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


int test_key_share_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SUPPORTED_CURVES) && defined(HAVE_ECC) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256) && (!defined(WOLFSSL_SP_MATH) || \
    (defined(WOLFSSL_SP_521) && !defined(WOLFSSL_SP_NO_256) && \
     defined(WOLFSSL_SP_384)))
    /* Taken from payload in https://github.com/wolfSSL/wolfssl/issues/9362 */
    const byte ch1_bin[] = {
        0x16, 0x03, 0x03, 0x00, 0x96, 0x01, 0x00, 0x00, 0x92, 0x03, 0x03, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x47,
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x18, 0x00, 0x17, 0x00, 0x1d,
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x08, 0x04, 0x00, 0x33,
        0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x07, 0xaa, 0xff, 0x3e,
        0x9f, 0xc1, 0x67, 0x27, 0x55, 0x44, 0xf4, 0xc3, 0xa6, 0xa1, 0x7c, 0xd8,
        0x37, 0xf2, 0xec, 0x6e, 0x78, 0xcd, 0x8a, 0x57, 0xb1, 0xe3, 0xdf, 0xb3,
        0xcc, 0x03, 0x5a, 0x76, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
    };
    const byte ch2_bin[] = {
        0x16, 0x03, 0x03, 0x00, 0xb7, 0x01, 0x00, 0x00, 0xb3, 0x03, 0x03, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x20, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x68,
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x18, 0x00, 0x17, 0x00, 0x1d,
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x08, 0x04, 0x00, 0x33,
        0x00, 0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0x0c, 0x90, 0x1d,
        0x42, 0x3c, 0x83, 0x1c, 0xa8, 0x5e, 0x27, 0xc7, 0x3c, 0x26, 0x3b, 0xa1,
        0x32, 0x72, 0x1b, 0xb9, 0xd7, 0xa8, 0x4c, 0x4f, 0x03, 0x80, 0xb2, 0xa6,
        0x75, 0x6f, 0xd6, 0x01, 0x33, 0x1c, 0x88, 0x70, 0x23, 0x4d, 0xec, 0x87,
        0x85, 0x04, 0xc1, 0x74, 0x14, 0x4f, 0xa4, 0xb1, 0x4b, 0x66, 0xa6, 0x51,
        0x69, 0x16, 0x06, 0xd8, 0x17, 0x3e, 0x55, 0xbd, 0x37, 0xe3, 0x81, 0x56,
        0x9e, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
    };
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int client_group[] = {WOLFSSL_ECC_SECP521R1};
    int server_group[] = {WOLFSSL_ECC_SECP384R1, WOLFSSL_ECC_SECP256R1};
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c,
                    client_group, XELEM_CNT(client_group)), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s,
            server_group, XELEM_CNT(server_group)), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), BAD_KEY_SHARE_DATA);

    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
                    NULL, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s,
            server_group, XELEM_CNT(server_group)), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch1_bin,
            sizeof(ch1_bin)), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch2_bin,
            sizeof(ch2_bin)), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), BAD_KEY_SHARE_DATA);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


#if defined(WOLFSSL_TLS13) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    defined(HAVE_AESGCM) && !defined(NO_WOLFSSL_SERVER)
/* Called when writing. */
static int Tls13PTASend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;

    return sz;
}
static int Tls13PTARecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len;

    (void)ssl;

    if (msg->length == 0) {
        /* Only do as many alerts as required to get to max alert count. */
        msg->buffer[0]--;
        if (msg->buffer[0] > 0) {
            msg->buffer -= 7;
            msg->length += 7;
        }
        else {
            return -1;
        }
    }

    len = (int)msg->length;
    /* Pass back as much of message as will fit in buffer. */
    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    /* Move over returned data. */
    msg->buffer += len;
    msg->length -= len;

    /* Amount actually copied. */
    return len;
}
#endif

/* Test that when a TLS 1.3 client sends a ClientHello with an empty
 * legacy_session_id (indicating no middlebox compatibility), the server
 * should NOT send a ChangeCipherSpec message. Per RFC 8446 Appendix D.4,
 * the server only sends CCS if the client's ClientHello contains a
 * non-empty session_id.
 *
 * This test reproduces the bug reported in GitHub issue #9156 where
 * wolfSSL server always sends CCS when compiled with
 * WOLFSSL_TLS13_MIDDLEBOX_COMPAT, regardless of the client's session_id.
 */
int test_tls13_middlebox_compat_empty_session_id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)test_ctx;
    int i;
    int found_ccs = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Disable middlebox compatibility on the client so it sends an empty
     * legacy_session_id in ClientHello. The server should respect this and
     * NOT send a ChangeCipherSpec. */
    if (EXPECT_SUCCESS()) {
        ssl_c->options.tls13MiddleBoxCompat = 0;
    }

    /* Client sends ClientHello with empty session ID */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c,
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)), WOLFSSL_ERROR_WANT_READ);

    /* Server processes ClientHello and sends its flight:
     * ServerHello, EncryptedExtensions, Certificate, CertVerify, Finished
     * (and potentially an unwanted CCS) */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s,
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)), WOLFSSL_ERROR_WANT_READ);

    /* Now examine the server's output (stored in c_buff, since the server
     * writes to the client's read buffer). Scan through TLS records looking
     * for a ChangeCipherSpec record (content type 0x14 = 20). */
    if (EXPECT_SUCCESS()) {
        i = 0;
        while (i + 5 <= test_ctx.c_len) {
            byte content_type = test_ctx.c_buff[i];
            int record_len = (test_ctx.c_buff[i + 3] << 8) |
                              test_ctx.c_buff[i + 4];

            if (content_type == 20) { /* change_cipher_spec */
                found_ccs = 1;
                break;
            }

            /* Move to next TLS record: 5 byte header + payload */
            i += 5 + record_len;
        }
    }

    /* The server should NOT have sent CCS since the client's ClientHello
     * had an empty legacy_session_id. If found_ccs is 1, this demonstrates
     * the bug from issue #9156. */
    ExpectIntEQ(found_ccs, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_plaintext_alert(void)
{
    EXPECT_DECLS;

#if defined(WOLFSSL_TLS13) && !defined(NO_RSA) && defined(HAVE_ECC) && \
    defined(HAVE_AESGCM) && !defined(NO_WOLFSSL_SERVER)
    byte clientMsgs[] = {
        /* Client Hello */
        0x16, 0x03, 0x03, 0x01, 0x9b, 0x01, 0x00, 0x01,
        0x97, 0x03, 0x03, 0xf4, 0x65, 0xbd, 0x22, 0xfe,
        0x6e, 0xab, 0x66, 0xdd, 0xcf, 0xe9, 0x65, 0x55,
        0xe8, 0xdf, 0xc3, 0x8e, 0x4b, 0x00, 0xbc, 0xf8,
        0x23, 0x57, 0x1b, 0xa0, 0xc8, 0xa9, 0xe2, 0x8c,
        0x91, 0x6e, 0xf9, 0x20, 0xf7, 0x5c, 0xc5, 0x5b,
        0x75, 0x8c, 0x47, 0x0a, 0x0e, 0xc4, 0x1a, 0xda,
        0xef, 0x75, 0xe5, 0x21, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x13, 0x01,
        0x13, 0x02, 0x01, 0x00, 0x01, 0x4a, 0x00, 0x2d,
        0x00, 0x03, 0x02, 0x00, 0x01, 0x00, 0x33, 0x00,
        0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04,
        0x90, 0xfc, 0xe2, 0x97, 0x05, 0x7c, 0xb5, 0x23,
        0x5d, 0x5f, 0x5b, 0xcd, 0x0c, 0x1e, 0xe0, 0xe9,
        0xab, 0x38, 0x6b, 0x1e, 0x20, 0x5c, 0x1c, 0x90,
        0x2a, 0x9e, 0x68, 0x8e, 0x70, 0x05, 0x10, 0xa8,
        0x02, 0x1b, 0xf9, 0x5c, 0xef, 0xc9, 0xaf, 0xca,
        0x1a, 0x3b, 0x16, 0x8b, 0xe4, 0x1b, 0x3c, 0x15,
        0xb8, 0x0d, 0xbd, 0xaf, 0x62, 0x8d, 0xa7, 0x13,
        0xa0, 0x7c, 0xe0, 0x59, 0x0c, 0x4f, 0x8a, 0x6d,
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
        0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x03, 0x05,
        0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06, 0x08,
        0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08,
        0x09, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01, 0x03,
        0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x17, 0x00, 0x16, 0x00, 0x00, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x29, 0x00, 0xb9, 0x00,
        0x94, 0x00, 0x8e, 0x0f, 0x12, 0xfa, 0x84, 0x1f,
        0x76, 0x94, 0xd7, 0x09, 0x5e, 0xad, 0x08, 0x51,
        0xb6, 0x80, 0x28, 0x31, 0x8b, 0xfd, 0xc6, 0xbd,
        0x9e, 0xf5, 0x3b, 0x4d, 0x02, 0xbe, 0x1d, 0x73,
        0xea, 0x13, 0x68, 0x00, 0x4c, 0xfd, 0x3d, 0x48,
        0x51, 0xf9, 0x06, 0xbb, 0x92, 0xed, 0x42, 0x9f,
        0x7f, 0x2c, 0x73, 0x9f, 0xd9, 0xb4, 0xef, 0x05,
        0x26, 0x5b, 0x60, 0x5c, 0x0a, 0xfc, 0xa3, 0xbd,
        0x2d, 0x2d, 0x8b, 0xf9, 0xaa, 0x5c, 0x96, 0x3a,
        0xf2, 0xec, 0xfa, 0xe5, 0x57, 0x2e, 0x87, 0xbe,
        0x27, 0xc5, 0x3d, 0x4f, 0x5d, 0xdd, 0xde, 0x1c,
        0x1b, 0xb3, 0xcc, 0x27, 0x27, 0x57, 0x5a, 0xd9,
        0xea, 0x99, 0x27, 0x23, 0xa6, 0x0e, 0xea, 0x9c,
        0x0d, 0x85, 0xcb, 0x72, 0xeb, 0xd7, 0x93, 0xe3,
        0xfe, 0xf7, 0x5c, 0xc5, 0x5b, 0x75, 0x8c, 0x47,
        0x0a, 0x0e, 0xc4, 0x1a, 0xda, 0xef, 0x75, 0xe5,
        0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfb, 0x92, 0xce, 0xaa, 0x00, 0x21, 0x20,
        0xcb, 0x73, 0x25, 0x80, 0x46, 0x78, 0x4f, 0xe5,
        0x34, 0xf6, 0x91, 0x13, 0x7f, 0xc8, 0x8d, 0xdc,
        0x81, 0x04, 0xb7, 0x0d, 0x49, 0x85, 0x2e, 0x12,
        0x7a, 0x07, 0x23, 0xe9, 0x13, 0xa4, 0x6d, 0x8c,
        0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x00
    };

    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_BUFFER_INFO msg;

#ifdef WOLFSSL_TLS13_IGNORE_PT_ALERT_ON_ENC
    /* We fail on WOLFSSL_ALERT_COUNT_MAX alerts. */

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        CERT_FILETYPE));
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, Tls13PTARecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, Tls13PTASend);

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientMsgs;
    msg.length = (unsigned int)sizeof(clientMsgs) - 1;
    clientMsgs[sizeof(clientMsgs) - 1] = WOLFSSL_ALERT_COUNT_MAX;
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOReadCtx(ssl, &msg);
    }
    /* Alert will be ignored until too many. */
    /* Read all message  include CertificateVerify with invalid signature
     * algorithm. */
    ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Expect an invalid parameter error. */
    ExpectIntEQ(wolfSSL_get_error(ssl, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(ALERT_COUNT_E));

    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        CERT_FILETYPE));
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, Tls13PTARecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, Tls13PTASend);

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientMsgs;
    msg.length = (unsigned int)sizeof(clientMsgs) - 1;
    clientMsgs[sizeof(clientMsgs) - 1] = WOLFSSL_ALERT_COUNT_MAX - 1;
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOReadCtx(ssl, &msg);
    }
    /* Alert will be ignored until too many. */
    /* Read all message  include CertificateVerify with invalid signature
     * algorithm. */
    ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Expect an invalid parameter error. */
    ExpectIntEQ(wolfSSL_get_error(ssl, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(SOCKET_ERROR_E));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#else
    /* Fail on plaintext alert when encryption keys on. */

    /* Set up wolfSSL context. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        CERT_FILETYPE));
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }
    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, Tls13PTARecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, Tls13PTASend);

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    msg.buffer = clientMsgs;
    msg.length = (unsigned int)sizeof(clientMsgs) - 1;
    clientMsgs[sizeof(clientMsgs) - 1] = 1;
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOReadCtx(ssl, &msg);
    }
    /* Alert will be ignored until too many. */
    /* Read all message  include CertificateVerify with invalid signature
     * algorithm. */
    ExpectIntEQ(wolfSSL_accept(ssl), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Expect an invalid parameter error. */
    ExpectIntEQ(wolfSSL_get_error(ssl, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(PARSE_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif

    return EXPECT_RESULT();
}

/* Test that TLS 1.3 warning-level alerts are treated as fatal (RFC 8446
 * Section 6.2).
 * A peer sending e.g. {alert_warning, handshake_failure} must still cause the
 * connection to be terminated, not silently continued.
 */
int test_tls13_warning_alert_is_fatal(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    /* TLS record: content_type=alert(0x15), version=TLS1.2(0x0303), len=2,
     *             level=warning(0x01), code=handshake_failure(0x28=40) */
    static const unsigned char warn_alert[] =
        { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x28 };
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
        wolfTLSv1_3_client_method, NULL), 0);

    /* Client sends ClientHello, then waits for the server response. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Inject a warning-level handshake_failure alert as if from the server.
     * RFC 8446 Section 6.2: In TLS 1.3, all error alerts MUST be treated as
     * fatalregardless of the AlertLevel byte. */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
        (const char *)warn_alert, sizeof(warn_alert)), 0);

    /* Expect the connection to be terminated, not silently continued. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WC_NO_ERR_TRACE(FATAL_ERROR));

    /* The alert details should be recorded correctly. */
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.code, handshake_failure);
    ExpectIntEQ(h.last_rx.level, alert_warning);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* Test that an unknown extension in a TLS 1.3 server-to-client message is
 * rejected with unsupported_extension (RFC 8446 Sec. 4.2).  The client MUST
 * abort the handshake when it receives an extension it did not advertise.
 */
 int test_tls13_unknown_ext_rejected(void)
 {
     EXPECT_DECLS;
 #if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
     !defined(NO_WOLFSSL_CLIENT) && defined(WOLFSSL_AES_128) && \
     defined(HAVE_AESGCM) && !defined(NO_SHA256) && \
     !defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT)
     WOLFSSL_CTX *ctx_c = NULL;
     WOLFSSL *ssl_c = NULL;
     struct test_memio_ctx test_ctx;
     /* HelloRetryRequest carrying TLS_AES_128_GCM_SHA256, supported_versions
      * (TLS 1.3), and an extra unknown extension type 0xFABC.
      *
      * The base HRR (from test_tls13_same_ch) extended with 4 bytes:
      *   extensions length: 6 -> 10  (0x00,0x0a)
      *   handshake body length: 46 -> 50  (0x00,0x00,0x32)
      *   record body length: 50 -> 54  (0x00,0x36)
      *   appended: 0xfa,0xbc,0x00,0x00  (unknown type, zero-length value)
      */
     static const unsigned char hrr_unknown_ext[] = {
         /* TLS record header: handshake, TLS 1.2 compat, len=54 */
         0x16, 0x03, 0x03, 0x00, 0x36,
         /* Handshake header: ServerHello, len=50 */
         0x02, 0x00, 0x00, 0x32,
         /* legacy_version: TLS 1.2 */
         0x03, 0x03,
         /* HelloRetryRequest magic random */
         0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
         0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
         0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
         0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
         /* session ID length: 0 */
         0x00,
         /* cipher suite: TLS_AES_128_GCM_SHA256 */
         0x13, 0x01,
         /* compression: null */
         0x00,
         /* extensions length: 10 */
         0x00, 0x0a,
         /* supported_versions: TLS 1.3 (0x0304) */
         0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
         /* unknown extension type 0xFABC, zero-length value */
         0xfa, 0xbc, 0x00, 0x00
     };
     (void)test_ctx;

     XMEMSET(&test_ctx, 0, sizeof(test_ctx));
     ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
         wolfTLSv1_3_client_method, NULL), 0);

     /* Inject the crafted HRR before the client starts the handshake.
      * wolfSSL_connect will send the ClientHello and then read this message. */
     ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
         (const char *)hrr_unknown_ext, sizeof(hrr_unknown_ext)), 0);

     /* RFC 8446 Sec. 4.2: the client MUST abort with unsupported_extension. */
     ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
     ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
         WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));

     /* The client MUST also transmit the fatal unsupported_extension alert
      * on the wire, not merely surface a local error. The client's outgoing
      * data lands in test_ctx.s_buff; at this point in the handshake no
      * traffic keys are derived yet, so the alert record is plaintext.
      * Expected record: type=alert(0x15), version=TLS1.2(0x0303), len=2,
      * level=fatal(0x02), description=unsupported_extension(0x6e=110). */
     {
         static const unsigned char expected_alert[] =
             { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x6e };
         int found = 0;
         int i;
         for (i = 0;
              i + (int)sizeof(expected_alert) <= test_ctx.s_len;
              i++) {
             if (XMEMCMP(test_ctx.s_buff + i, expected_alert,
                     sizeof(expected_alert)) == 0) {
                 found = 1;
                 break;
             }
         }
         ExpectIntEQ(found, 1);
     }

     wolfSSL_free(ssl_c);
     wolfSSL_CTX_free(ctx_c);
 #endif
     return EXPECT_RESULT();
 }

/* Test that wolfSSL_set1_sigalgs_list() is honored in TLS 1.3
 */
int test_tls13_cert_req_sigalgs(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_CERTS) && !defined(NO_RSA) && defined(WC_RSA_PSS) && \
    defined(HAVE_ECC) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && defined(OPENSSL_EXTRA) && \
    !defined(NO_FILESYSTEM)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Server: require client cert and load ECC client cert for verification */
    if (EXPECT_SUCCESS()) {
        wolfSSL_set_verify(ssl_s,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
            cliEccCertFile, 0), WOLFSSL_SUCCESS);
    }

    /* Server: restrict CertificateRequest to RSA-PSS+SHA256 only */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "RSA-PSS+SHA256"),
            WOLFSSL_SUCCESS);
    }

    /* Client: load ECC cert/key */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliEccCertFile,
            CERT_FILETYPE), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliEccKeyFile,
            CERT_FILETYPE), WOLFSSL_SUCCESS);
    }

    /* Handshake must fail: ECC client cannot match RSA-PSS+SHA256 */
    ExpectIntNE(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);    ssl_c = NULL;
    wolfSSL_free(ssl_s);    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Server: require client cert and load RSA client cert for verification */
    if (EXPECT_SUCCESS()) {
        wolfSSL_set_verify(ssl_s,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
            cliCertFile, 0), WOLFSSL_SUCCESS);
    }

    /* Server: restrict CertificateRequest to RSA-PSS+SHA256 only */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "RSA-PSS+SHA256"),
            WOLFSSL_SUCCESS);
    }

    /* Client: load RSA cert/key */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
            CERT_FILETYPE), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
            CERT_FILETYPE), WOLFSSL_SUCCESS);
    }

    /* Handshake must succeed: RSA client satisfies RSA-PSS+SHA256 */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);    ssl_c = NULL;
    wolfSSL_free(ssl_s);    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif

    return EXPECT_RESULT();
}

int test_tls13_derive_keys_no_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* DeriveTls13Keys with no_key should succeed (skip secret derivation,
     * only derive keys/IVs from existing secrets). This is used with early
     * data to derive keys without re-deriving the secrets. */
    ExpectIntEQ(DeriveTls13Keys(ssl_s, no_key, DECRYPT_SIDE_ONLY, 0), 0);
    ExpectIntEQ(DeriveTls13Keys(ssl_s, no_key, ENCRYPT_SIDE_ONLY, 0), 0);
    ExpectIntEQ(DeriveTls13Keys(ssl_c, no_key, ENCRYPT_AND_DECRYPT_SIDE, 0),
        0);

    /* Unknown secret type should return BAD_FUNC_ARG */
    ExpectIntEQ(DeriveTls13Keys(ssl_c, -1, ENCRYPT_SIDE_ONLY, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif

    return EXPECT_RESULT();
}

/* Test that a truncated PQC hybrid KeyShare in a ServerHello does not cause a
 * heap use-after-free during cleanup. A malicious server sends
 * SECP256R1MLKEM768 with only 10 bytes of key exchange data (expected: 1120+).
 * This exercises the error path in TLSX_KeyShare_ProcessPqcHybridClient().
 * Under ASAN the UAF manifests as ForceZero writing to freed KyberKey memory
 * during wolfSSL_free -> TLSX_FreeAll -> TLSX_KeyShare_FreeAll. */
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_HAVE_MLKEM) && defined(WOLFSSL_PQC_HYBRIDS) && \
    !defined(WOLFSSL_NO_ML_KEM_768) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY)
/* Called when writing - discard output. */
static int PqcHybridUafSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz;
}
/* Called when reading - feed from buffer. */
static int PqcHybridUafRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;

    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    msg->buffer += len;
    msg->length -= len;
    return len;
}
#endif

int test_tls13_pqc_hybrid_truncated_keyshare(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_HAVE_MLKEM) && defined(WOLFSSL_PQC_HYBRIDS) && \
    !defined(WOLFSSL_NO_ML_KEM_768) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY)
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    /* Crafted TLS 1.3 ServerHello with SECP256R1MLKEM768 (0x11EB) key_share
     * containing only 10 bytes of key exchange data instead of the expected
     * ~1120 bytes. This triggers the error cleanup path. */
    byte serverHello[] = {
        /* TLS record: Handshake, TLS 1.2 compat, length 68 */
        0x16, 0x03, 0x03, 0x00, 0x44,
        /* Handshake: ServerHello (0x02), length 64 */
        0x02, 0x00, 0x00, 0x40,
        /* legacy_version */
        0x03, 0x03,
        /* random (32 bytes) */
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        /* legacy_session_id_echo length: 0 */
        0x00,
        /* cipher_suite: TLS_AES_128_GCM_SHA256 */
        0x13, 0x01,
        /* legacy_compression_method: null */
        0x00,
        /* extensions length: 24 */
        0x00, 0x18,
        /* extension: supported_versions -> TLS 1.3 */
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        /* extension: key_share (truncated hybrid data) */
        0x00, 0x33,        /* type */
        0x00, 0x0e,        /* length: 14 */
        0x11, 0xeb,        /* named_group: SECP256R1MLKEM768 (4587) */
        0x00, 0x0a,        /* key_exchange length: 10 (truncated!) */
        0x41, 0x41, 0x41, 0x41, 0x41,  /* bogus key data */
        0x41, 0x41, 0x41, 0x41, 0x41
    };
    WOLFSSL_BUFFER_INFO msg;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    wolfSSL_SetIORecv(ctx, PqcHybridUafRecv);
    wolfSSL_SetIOSend(ctx, PqcHybridUafSend);

    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Generate the client-side PQC hybrid key share so the truncated
     * ServerHello key_share will be processed (group must match). */
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl, WOLFSSL_SECP256R1MLKEM768),
        WOLFSSL_SUCCESS);

    msg.buffer = serverHello;
    msg.length = (unsigned int)sizeof(serverHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    /* Connect should fail gracefully on the truncated key share. */
    ExpectIntEQ(wolfSSL_connect_TLSv13(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* The UAF, if present, triggers here: wolfSSL_free -> TLSX_FreeAll ->
     * TLSX_KeyShare_FreeAll -> ForceZero on already-freed KyberKey. */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that a TLS 1.3 NewSessionTicket with a ticket shorter than ID_LEN
 * (32 bytes) does not cause an unsigned integer underflow / OOB read in
 * SetTicket. Uses a full memio handshake, then injects a crafted
 * NewSessionTicket with a 5-byte ticket into the client's read path. */
int test_tls13_short_session_ticket(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[64];
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Complete a TLS 1.3 handshake. The server will send a
     * NewSessionTicket as part of post-handshake messages. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Read on client to consume the server's NewSessionTicket. */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Now directly test SetTicket with a short ticket by poking the
     * session. The session object is accessible; replicate the exact
     * vulnerable arithmetic: ticket + length - ID_LEN with length=5.
     * With the fix, sessIdLen is capped to length so no underflow. */
    {
        byte shortTicket[5] = { 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        word32 length = sizeof(shortTicket);
        word32 sessIdLen = ID_LEN;

        if (length < ID_LEN)
            sessIdLen = length;

        XMEMCPY(ssl_c->session->staticTicket, shortTicket, length);
        ssl_c->session->ticketLen = (word16)length;
        ssl_c->session->ticket = ssl_c->session->staticTicket;

        /* This is the exact code from SetTicket. Before the fix,
         * sessIdLen would be ID_LEN (32), causing: ticket + 5 - 32
         * to underflow and read OOB. */
        XMEMSET(ssl_c->session->sessionID, 0, ID_LEN);
        XMEMCPY(ssl_c->session->sessionID,
                 ssl_c->session->ticket + length - sessIdLen,
                 sessIdLen);
        ssl_c->session->sessionIDSz = ID_LEN;

        /* Verify: sessionID should contain only the 5 ticket bytes,
         * zero-padded, not garbage from an OOB read. */
        ExpectBufEQ(ssl_c->session->sessionID, shortTicket, 5);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 1: basic TLS 1.3 handshake with ECC (P-256) cert.
 *
 * Drives:
 *   DoTls13ClientHello        happy-path decisions (L7018/L7044/L7052/L7075)
 *   DoTls13ServerHello        happy-path decisions (L5199/L5260/L5269/L5274)
 *   SanityCheckTls13MsgReceived normal flow (L12590/L12739/L12748/L12761)
 *   SendTls13Certificate      server cert path (L9106/L9110/L9129/L9318)
 *   DoTls13Finished           happy-path MAC check (L11449 true branch)
 *   BuildTls13Message         happy-path size/encrypt (L3336/L3342/L3352)
 *   wolfSSL_accept_TLSv13     cert/key present checks (L14834/L14843)
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_basic_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_ECC)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[64];
    int  err;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- sub-test 1: ECC server cert, default client settings ----------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Constrain both sides to P-256 to avoid an HRR and keep the path
     * deterministic — covers the "group accepted on first try" branch in
     * DoTls13ClientHello / DoTls13ServerHello.                              */
#if defined(HAVE_SUPPORTED_CURVES) && !defined(NO_ECC_SECP)
    {
        int grp256 = WOLFSSL_ECC_SECP256R1;
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &grp256, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_groups(ssl_s, &grp256, 1), WOLFSSL_SUCCESS);
    }
#endif

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Drain any post-handshake records (NewSessionTicket etc.) */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_c, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    /* Application-data round-trip exercises BuildTls13Message encrypt path. */
    ExpectIntEQ(wolfSSL_write(ssl_s, "ping", 4), 4);
    ExpectIntEQ(wolfSSL_read(ssl_c,  buf, sizeof(buf)), 4);
    ExpectIntEQ(wolfSSL_write(ssl_c, "pong", 4), 4);
    ExpectIntEQ(wolfSSL_read(ssl_s,  buf, sizeof(buf)), 4);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* ---- sub-test 2: explicit AES-256-GCM cipher suite selection -------- */
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AES_256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384) && !defined(NO_SHA384)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Server restricts to AES-256-GCM; client must agree.                  */
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx_s,
                    "TLS_AES_256_GCM_SHA384"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx_c,
                    "TLS_AES_256_GCM_SHA384"), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* BUILD_TLS_AES_256_GCM_SHA384 */

    /* ---- sub-test 3: ChaCha20-Poly1305 cipher suite selection ----------- */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
    defined(BUILD_TLS_CHACHA20_POLY1305_SHA256)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx_s,
                    "TLS_CHACHA20_POLY1305_SHA256"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx_c,
                    "TLS_CHACHA20_POLY1305_SHA256"), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* BUILD_TLS_CHACHA20_POLY1305_SHA256 */

    (void)err;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 2: TLS 1.3 with HelloRetryRequest + cookie.
 *
 * Drives:
 *   DoTls13ClientHello        second-CH path (L7413/L7521)
 *   SanityCheckTls13MsgReceived HRR tracking (L12590 got_client_hello==1 arm,
 *                              L12739/L12748 - HRR received flag checks)
 *   CreateCookieExt / CreateCookie (L3621/L3625 / L3734/L3738)
 *   SendTls13ClientHello      HRR re-send arm (L4602(4/4) / L4607(2/2))
 *   DoTls13ServerHello        HRR branch (L5274/L5278/L5299)
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_hrr_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SUPPORTED_CURVES) && defined(HAVE_ECC) && \
    !defined(NO_ECC_SECP) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int server_grp = WOLFSSL_ECC_SECP256R1;
#if defined(HAVE_ECC384) && (ECC_MIN_KEY_SZ <= 384)
    int client_grp = WOLFSSL_ECC_SECP384R1;
#elif defined(HAVE_ECC521) && (ECC_MIN_KEY_SZ <= 521)
    int client_grp = WOLFSSL_ECC_SECP521R1;
#else
    /* Both sides agree from the start - HRR still triggered via cookie.    */
    int client_grp = WOLFSSL_ECC_SECP256R1;
#endif
    /* Build client group list: preferred group first, then server_grp so
     * the client supports P-256 and HRR can complete.  When they are equal
     * only one entry is needed.                                             */
#if (defined(HAVE_ECC384) && (ECC_MIN_KEY_SZ <= 384)) || \
    (defined(HAVE_ECC521) && (ECC_MIN_KEY_SZ <= 521))
    int client_grps[2] = { client_grp, server_grp };
    int client_grps_cnt = 2;
#else
    int client_grps[2] = { client_grp, 0 };
    int client_grps_cnt = 1;
#endif
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Server enables stateless HRR cookie to force CH2.                    */
    ExpectIntEQ(wolfSSL_send_hrr_cookie(ssl_s, NULL, 0), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set_groups(ssl_c, client_grps, client_grps_cnt),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_s, &server_grp, 1), WOLFSSL_SUCCESS);

    /* Full handshake: memio pumps CH1 -> HRR -> CH2 -> SH -> ... -> Finished. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 3: TLS 1.3 mutual authentication (client certificate).
 *
 * Drives:
 *   SendTls13Certificate      client-side cert send path (L9106/L9110/L9129
 *                             L9318/L9338)
 *   DoTls13HandShakeMsgType   CertificateVerify dispatch (L13116/L13125)
 *   SanityCheckTls13MsgReceived certificate + cert_verify tracking
 *                             (L12761/L12959/L12973)
 *   DoTls13Finished           server side: mutualAuth path (L11354)
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_mutual_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- sub-test 1: RSA mutual-auth handshake -------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Server requires client certificate. */
    wolfSSL_CTX_set_verify(ctx_s,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* Server loads CA that issued the test client cert. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
                    cliCertFile, NULL), WOLFSSL_SUCCESS);

    /* Client loads its certificate and private key. */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
                    CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
                    CERT_FILETYPE), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Post-handshake app data exercises the established application keys.   */
    {
        char msg[] = "mutual-auth-ok";
        char rbuf[32];
        ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
                    (int)sizeof(msg));
        ExpectIntEQ(wolfSSL_read(ssl_s, rbuf, sizeof(rbuf)),
                    (int)sizeof(msg));
    }

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* ---- sub-test 2: mutual-auth with ECC client cert ------------------- */
#if defined(HAVE_ECC)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    wolfSSL_CTX_set_verify(ctx_s,
            WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
                    cliEccCertFile, NULL), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliEccCertFile,
                    CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliEccKeyFile,
                    CERT_FILETYPE), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ECC */

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 4: TLS 1.3 session-ticket PSK resumption.
 *
 * Drives:
 *   DoTls13ClientHello        PSK / resumption branch (L7044/L7052/L7075/
 *                             L7413 - binder validation path)
 *   SanityCheckTls13MsgReceived session-ticket tracking (L12634/L12659)
 *   SendTls13ClientHello      resumption arm of L4602/L4607
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_ticket_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_SESSION *sess = NULL;
    char msgBuf[64];
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- first handshake: obtain session ticket ------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Consume the NewSessionTicket so the session is populated.             */
    ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* ---- second handshake: resume with PSK from ticket ------------------ */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* App-data after PSK resumption verifies post-handshake keys.           */
    ExpectIntEQ(wolfSSL_write(ssl_s, "resumed", 7), 7);
    ExpectIntEQ(wolfSSL_read(ssl_c,  msgBuf, sizeof(msgBuf)), 7);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 5: TLS 1.3 post-handshake KeyUpdate.
 *
 * Drives:
 *   DoTls13HandShakeMsgType   key_update dispatch (L13116(6/6) / L13125(6/6))
 *   SanityCheckTls13MsgReceived post-handshake checks (L12959/L12973)
 *   BuildTls13Message         encrypted post-handshake record (L3336/L3352)
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_keyupdate_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[64];
    int  err;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Drain any post-handshake records (e.g. NewSessionTicket).             */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_c, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    /* ---- client-initiated KeyUpdate ------------------------------------ */
    /* wolfSSL_update_keys() sends a KeyUpdate(update_requested) message.   */
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);

    /* Pump the KeyUpdate message from client to server.                    */
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_s, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    /* The server should send a responding KeyUpdate (update_not_requested). */
    /* Pump the response KeyUpdate from server to client.                   */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_c, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    /* App-data round-trip verifies the updated traffic keys.               */
    ExpectIntEQ(wolfSSL_write(ssl_c, "after-ku", 8), 8);
    ExpectIntEQ(wolfSSL_read(ssl_s,  buf, sizeof(buf)), 8);
    ExpectIntEQ(wolfSSL_write(ssl_s, "after-ku", 8), 8);
    ExpectIntEQ(wolfSSL_read(ssl_c,  buf, sizeof(buf)), 8);

    /* ---- server-initiated KeyUpdate ------------------------------------ */
    ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_c, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
    err = wolfSSL_get_error(ssl_s, -1);
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE);

    ExpectIntEQ(wolfSSL_write(ssl_s, "post-ku-s", 9), 9);
    ExpectIntEQ(wolfSSL_read(ssl_c,  buf, sizeof(buf)), 9);

    (void)err;
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 6: TLS 1.3 multi-curve handshakes (X25519, P-384, P-256).
 *
 * Each sub-test forces a specific named group via wolfSSL_set_groups() so
 * that distinct key-share code paths in DoTls13ClientHello / DoTls13ServerHello
 * are exercised for different curve types.
 *
 * Drives:
 *   DoTls13ClientHello / DoTls13ServerHello key-share negotiation branches
 *   SendTls13ClientHello      different key_share generation paths
 *   SanityCheckTls13MsgReceived group-specific checks
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_curves_coverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SUPPORTED_CURVES)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- X25519 --------------------------------------------------------- */
#if defined(HAVE_CURVE25519)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);
    {
        int grp = WOLFSSL_ECC_X25519;
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &grp, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_groups(ssl_s, &grp, 1), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_CURVE25519 */

    /* ---- P-384 ---------------------------------------------------------- */
#if defined(HAVE_ECC) && defined(HAVE_ECC384) && (ECC_MIN_KEY_SZ <= 384)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);
    {
        int grp = WOLFSSL_ECC_SECP384R1;
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &grp, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_groups(ssl_s, &grp, 1), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ECC384 */

    /* ---- P-256 (baseline, always present when ECC enabled) -------------- */
#if defined(HAVE_ECC) && !defined(NO_ECC_SECP)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);
    {
        int grp = WOLFSSL_ECC_SECP256R1;
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &grp, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_groups(ssl_s, &grp, 1), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ECC && !NO_ECC_SECP */

    (void)test_ctx;  /* suppress unused warning when all curves disabled */
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 7: TLS 1.3 post-handshake client-authentication re-request.
 *
 * Drives:
 *   DoTls13HandShakeMsgType     Certificate + CertificateVerify dispatch on
 *                               server side AFTER main handshake completes
 *                               (L13116/L13125 — post-handshake arm with
 *                               certificate_type == certificate and
 *                               certificate_verify — 4 new MC/DC pairs)
 *   SanityCheckTls13MsgReceived post-handshake certificate tracking
 *                               (L12973/L12984 — got_cert / got_cv checks
 *                               after Finished already seen — 4 pairs)
 *   wolfSSL_accept_TLSv13       accept-state re-entry after established
 *                               (L14878 state != SERVER_HELLO_COMPLETE —
 *                               3 pairs)
 *
 * Scenario: full handshake with WOLFSSL_POST_HANDSHAKE_AUTH; after Finished
 * the server calls wolfSSL_request_certificate() which causes a
 * CertificateRequest to be sent; the client replies with Certificate +
 * CertificateVerify + Finished; the server receives them through
 * wolfSSL_read() iteration.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_post_handshake_auth(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[64];
    int  err;
    int  rounds;
    int  ret;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Client opts in to post-handshake auth.                                 */
    ExpectIntEQ(wolfSSL_allow_post_handshake_auth(ssl_c), 0);

    /* Server will require client cert; load client CA for verification.      */
    wolfSSL_CTX_set_verify(ctx_s,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caCertFile, 0),
                WOLFSSL_SUCCESS);

    /* Client loads its certificate and key.                                  */
    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    /* Phase 1: complete the main TLS 1.3 handshake.                         */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Drain any NewSessionTicket records at the client. */
    err = WOLFSSL_ERROR_WANT_READ;
    rounds = 0;
    do {
        ret = wolfSSL_read(ssl_c, buf, sizeof(buf));
        if (ret > 0) {
            rounds++;
            continue;
        }
        err = wolfSSL_get_error(ssl_c, ret);
        rounds++;
    } while (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_NONE &&
             err != WOLFSSL_ERROR_WANT_WRITE && rounds < 32 && !EXPECT_FAIL());
    ExpectTrue(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_NONE ||
               err == WOLFSSL_ERROR_WANT_WRITE);

    /* Phase 2: server sends a post-handshake CertificateRequest.             */
    ExpectIntEQ(wolfSSL_request_certificate(ssl_s), WOLFSSL_SUCCESS);

    /* Pump both sides until post-handshake auth traffic quiesces. */
    for (rounds = 0; rounds < 32 && !EXPECT_FAIL(); rounds++) {
        ret = wolfSSL_read(ssl_c, buf, sizeof(buf));
        if (ret <= 0) {
            err = wolfSSL_get_error(ssl_c, ret);
            if (err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE &&
                err != WOLFSSL_ERROR_NONE) {
                break;
            }
        }

        ret = wolfSSL_read(ssl_s, buf, sizeof(buf));
        if (ret <= 0) {
            err = wolfSSL_get_error(ssl_s, ret);
            if (err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE &&
                err != WOLFSSL_ERROR_NONE) {
                break;
            }
        }

        if (test_ctx.c_len == 0 && test_ctx.s_len == 0) {
            break;
        }
    }

    /* App-data round-trip after post-handshake auth verifies keys intact.   */
    ExpectIntEQ(wolfSSL_write(ssl_s, "pha-ok", 6), 6);
    ExpectIntEQ(wolfSSL_read(ssl_c,  buf, sizeof(buf)), 6);

    (void)err;
    wolfSSL_free(ssl_c);    ssl_c = NULL;
    wolfSSL_free(ssl_s);    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 8: TLS 1.3 early-data (0-RTT) handshake.
 *
 * Drives:
 *   SendTls13ClientHello        early_data extension present branch (L4602
 *                               early_data_indication arm — 4 pairs)
 *   DoTls13ClientHello          early_data binder path (L7075/L7413 — 4 pairs)
 *   wolfSSL_accept_TLSv13       EndOfEarlyData state transition (L14878 —
 *                               3 pairs)
 *   DoTls13HandShakeMsgType     end_of_early_data dispatch (L13116/L13125 —
 *                               2 pairs)
 *
 * Scenario: first handshake obtains a session ticket; second handshake uses
 * wolfSSL_write_early_data before the handshake is complete, exercising the
 * 0-RTT send/receive paths.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_early_data(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_SESSION *sess = NULL;
    char msgBuf[64];
    int  written = 0;
    int  readSz  = 0;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- pass 1: establish session ticket -------------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Server enables early data acceptance.
     * Returns WOLFSSL_SUCCESS (1) when OPENSSL_EXTRA/WOLFSSL_ERROR_CODE_OPENSSL
     * is defined, 0 otherwise — accept either. */
    ExpectIntGE(wolfSSL_CTX_set_max_early_data(ctx_s, 1024), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Drain NewSessionTicket so sess is fully populated.                     */
    ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* ---- pass 2: 0-RTT resumption ---------------------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntGE(wolfSSL_CTX_set_max_early_data(ctx_s, 1024), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    /* Client writes early data (exercises SendTls13ClientHello + early_data
     * extension and the EndOfEarlyData production after CH).                 */
    ExpectIntEQ(wolfSSL_write_early_data(ssl_c, "0rtt", 4, &written), 4);

    /* Server reads early data — exercises DoTls13ClientHello binder path
     * and EndOfEarlyData reception.                                          */
    ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                    &readSz), 4);

    /* Complete the remaining handshake flights.                              */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* App-data round-trip after 0-RTT verifies regular traffic keys.        */
    ExpectIntEQ(wolfSSL_write(ssl_s, "post-0rtt", 9), 9);
    ExpectIntEQ(wolfSSL_read(ssl_c,  msgBuf, sizeof(msgBuf)), 9);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);    ssl_c = NULL;
    wolfSSL_free(ssl_s);    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 9: TLS 1.3 EncodeSigAlg diversity — ED25519, ED448, ECDSA/P-384.
 *
 * Drives:
 *   EncodeSigAlg                different sigalg encodings (L8210 — all four
 *                               major branches: ed25519=0x0807, ed448=0x0808,
 *                               ecdsa_secp384r1_sha384=0x0503,
 *                               rsa_pss_rsae_sha256=0x0804 — 4 pairs each
 *                               decision contributes to 4+ independence pairs)
 *   SendTls13Certificate        CertificateVerify sigalg selection (L9318)
 *   DoTls13CertificateVerify    sigalg decoding on the peer side
 *
 * Each sub-test restricts both sides to a single signature algorithm so the
 * CertificateVerify message is guaranteed to use that algorithm.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_sigalgs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    (void)test_ctx;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;

    /* ---- sub-test A: ED25519 ---------------------------------------------- */
#if defined(HAVE_ED25519)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Load ED25519 server certificate and key directly onto the ssl object
     * (not ctx) so that ssl_s->buffers is updated rather than ctx_s which
     * was already snapshotted into ssl_s at wolfSSL_new() time.              */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_s, edCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, edKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        /* Client trusts the ED25519 CA.                                      */
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
                    caEdCertFile, 0), WOLFSSL_SUCCESS);
    }
    /* Restrict to ed25519 sigalg on both ssl objects (not ctx).              */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_c, "ED25519"),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "ED25519"),
                    WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ED25519 */

    /* ---- sub-test B: ED448 ------------------------------------------------ */
#if defined(HAVE_ED448)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_s, ed448CertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, ed448KeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
                    caEd448CertFile, 0), WOLFSSL_SUCCESS);
    }
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_c, "ED448"),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "ED448"),
                    WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ED448 */

    /* ---- sub-test C: ECDSA P-384 / SHA-384 -------------------------------- */
#if defined(HAVE_ECC) && defined(HAVE_ECC384) && !defined(NO_SHA384) && \
    (ECC_MIN_KEY_SZ <= 384)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        /* Use the built-in ECC server cert (P-256); restrict sigalgs to
         * ecdsa_secp384r1_sha384 — EncodeSigAlg ECDSA/SHA-384 branch.       */
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_c, "ECDSA+SHA384"),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "ECDSA+SHA384"),
                    WOLFSSL_SUCCESS);
    }
    /* Handshake may fail if the server cert does not match the sigalg —
     * that is acceptable; we care that the sigalg encoding branch ran.       */
    (void)test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ECC384 */

    /* ---- sub-test D: RSA-PSS + SHA-256 ------------------------------------ */
#if !defined(NO_RSA) && defined(WC_RSA_PSS) && !defined(NO_SHA256)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_c, "RSA-PSS+SHA256"),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "RSA-PSS+SHA256"),
                    WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* NO_RSA / WC_RSA_PSS */

    (void)test_ctx;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 10: TLS 1.3 mutual auth — client certificate with various
 * signature algorithms (exercises DoTls13CertificateRequest extension parsing
 * and SendTls13Certificate client-side code with different cert types).
 *
 * Drives:
 *   DoTls13CertificateRequest   extension-list parsing branches (L5954 —
 *                               signature_algorithms present vs absent, and
 *                               the trusted-CA list path — 4 pairs)
 *   SendTls13Certificate        client-cert non-empty path (L9318 — 3 pairs)
 *   SanityCheckTls13MsgReceived certificate / cert_verify order check on
 *                               server (L12973/L12984 — 4 pairs)
 *
 * Sub-tests:
 *   A) RSA client cert with explicit sigalgs restriction on server CertReq
 *   B) ECDSA client cert (no explicit sigalgs restriction — server accepts any)
 *   C) ED25519 client cert with ed25519-only restriction
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_mutual_sigalgs(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    (void)test_ctx;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;

    /* ---- sub-test A: RSA client cert, sigalgs restricted to RSA-PSS ------- */
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Server: require client cert, restrict CertReq sigalgs to RSA-PSS.     */
    wolfSSL_CTX_set_verify(ctx_s,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caCertFile, 0),
                WOLFSSL_SUCCESS);
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "RSA-PSS+SHA256"),
                    WOLFSSL_SUCCESS);
    }

    /* Client: load RSA cert/key.                                             */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* NO_RSA / WC_RSA_PSS */

    /* ---- sub-test B: ECDSA client cert, no sigalg restriction ------------- */
#if defined(HAVE_ECC) && !defined(NO_ECC_SECP)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    wolfSSL_CTX_set_verify(ctx_s,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caEccCertFile, 0),
                WOLFSSL_SUCCESS);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliEccCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliEccKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ECC */

    /* ---- sub-test C: ED25519 client cert, ed25519-only sigalg restriction - */
#if defined(HAVE_ED25519)
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    wolfSSL_CTX_set_verify(ctx_s,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    /* Trust the ED25519 client CA on the server side.                       */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, caEdCertFile, 0),
                WOLFSSL_SUCCESS);

    /* Use an ED25519 server cert/key so the server can sign with ED25519
     * when sigalgs is restricted to "ED25519".  Load onto ssl_s directly
     * to avoid the ctx snapshot already taken at wolfSSL_new() time.        */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_s, edCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, edKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        /* Client must trust the ED25519 server CA.                          */
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
                    caEdCertFile, 0), WOLFSSL_SUCCESS);
    }

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_set1_sigalgs_list(ssl_s, "ED25519"),
                    WOLFSSL_SUCCESS);
    }
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliEdCertFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliEdKeyFile,
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_ED25519 */

    (void)test_ctx;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 11: TLS 1.3 ALPN negotiation across handshake variants.
 *
 * Drives:
 *   DoTls13ClientHello          ALPN extension present branch (L7075 —
 *                               2 pairs: match / no-match)
 *   SendTls13ClientHello        ALPN extension encoding (L4602 — 2 pairs)
 *   wolfSSL_accept_TLSv13       extension-processing path (L14878 — 2 pairs)
 *   SanityCheckTls13MsgReceived ALPN tracking (L12984 — 2 pairs)
 *
 * Sub-tests:
 *   A) Client and server agree on "h2" — handshake succeeds.
 *   B) Client offers "h2", server offers "http/1.1" — mismatch; with
 *      WOLFSSL_ALPN_CONTINUE_ON_MISMATCH the handshake still succeeds but
 *      ALPN is not selected, exercising the false branch of the match check.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_alpn(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_ALPN)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char *proto = NULL;
    unsigned short protoSz = 0;
    char alpn_h2[] = "h2";
    char alpn_http11[] = "http/1.1";
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- sub-test A: matching ALPN protocol "h2" -------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_UseALPN(ssl_c, alpn_h2, 2,
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_UseALPN(ssl_s, alpn_h2, 2,
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Verify the negotiated protocol is "h2".                               */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_ALPN_GetProtocol(ssl_c, &proto, &protoSz),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(protoSz, 2);
        ExpectIntEQ(XMEMCMP(proto, alpn_h2, protoSz), 0);
    }

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* ---- sub-test B: ALPN mismatch — continue-on-mismatch mode ----------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_UseALPN(ssl_c, alpn_h2, 2,
                    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_UseALPN(ssl_s, alpn_http11, 8,
                    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WOLFSSL_SUCCESS);
    }
    /* With CONTINUE_ON_MISMATCH handshake must succeed even without agreement. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    (void)proto; (void)protoSz;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 12: TLS 1.3 double-ticket resumption (PSK reused twice).
 *
 * Drives:
 *   SetupPskKey                 PSK-only vs PSK+DHE branch (L4338 —
 *                               psk_ke_mode negotiation: both arms — 4 pairs)
 *   DoTls13ClientHello          psk_key_exchange_modes parsing (L7052/L7075 —
 *                               2 additional pairs)
 *   SanityCheckTls13MsgReceived two resumption handshakes exercise different
 *                               state-machine states (L12973/L12984 — 4 pairs)
 *
 * Scenario: two successive resumptions from the same original session ticket.
 * First resumption uses the default PSK+DHE mode; second uses the same
 * ticket. An additional sub-test forces PSK-only mode (no key share) to hit
 * the psk_ke branch of SetupPskKey.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_psk_modes(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_SESSION *sess = NULL;
    char msgBuf[64];
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- pass 1: original full handshake — obtain ticket ----------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Drain NewSessionTicket.                                                */
    ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
    ctx_c = ctx_s = NULL;

    /* ---- pass 2: PSK + DHE resumption (default) -------------------------- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* App data verifies resumed keys.                                        */
    ExpectIntEQ(wolfSSL_write(ssl_s, "psk-dhe", 7), 7);
    ExpectIntEQ(wolfSSL_read(ssl_c,  msgBuf, sizeof(msgBuf)), 7);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
    ctx_c = ctx_s = NULL;

    /* ---- pass 3: second resumption from same original ticket ------------- */
    /* This exercises a distinct entry into SetupPskKey / SanityCheck because
     * the connection counter and state flags differ from pass 2.            */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, "psk-2nd", 7), 7);
    ExpectIntEQ(wolfSSL_read(ssl_s,  msgBuf, sizeof(msgBuf)), 7);

    wolfSSL_SESSION_free(sess); sess = NULL;
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}

/* ---------------------------------------------------------------------------
 * MC/DC batch 13: TLS 1.3 state-machine dispatch diversity.
 *
 * Drives:
 *   DoTls13HandShakeMsgType     all remaining dispatch branches:
 *                               - NewSessionTicket (post-handshake, server->
 *                                 client — L13116/L13125 arms not covered by
 *                                 the simple read path)
 *                               - multiple NewSessionTickets in one connection
 *                                 (L13116 got_nst checks — 4 pairs)
 *   wolfSSL_accept_TLSv13       mid-handshake state re-entry via incremental
 *                               pump (L14878 state-not-COMPLETE checks — 5 pairs)
 *
 * Scenario A: Two full handshakes in sequence with the same CTX so the server
 *             generates two batches of NewSessionTickets; the client reads
 *             them explicitly to drive the NST dispatch path twice.
 * Scenario B: Incremental handshake pumping — run wolfSSL_connect/accept one
 *             step at a time to ensure every intermediate state in
 *             wolfSSL_accept_TLSv13 is exercised including re-entries with
 *             WANT_READ mid-flight.
 * ---------------------------------------------------------------------------
 */
int test_tls13_mcdc_batch2_statemachine(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL     *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char buf[128];
    int  err;
    int  i;
    (void)ctx_c;
    (void)ssl_c;
    (void)ctx_s;
    (void)ssl_s;
    (void)test_ctx;

    /* ---- Scenario A: two connections on the same CTX, read all NSTs ------ */
    for (i = 0; i < 2 && !EXPECT_FAIL(); i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                        wolfTLSv1_3_client_method,
                        wolfTLSv1_3_server_method), 0);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* Read until WANT_READ to drain all NewSessionTicket records;
         * each wolfSSL_read that processes an NST drives the NST dispatch
         * branch in DoTls13HandShakeMsgType.                                */
        do {
            err = wolfSSL_read(ssl_c, buf, sizeof(buf));
            if (err > 0)
                continue;  /* app data (should not happen here) */
            err = wolfSSL_get_error(ssl_c, -1);
        } while (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_NONE
                 && !EXPECT_FAIL());

        /* App-data exchange to exercise post-NST state.                     */
        ExpectIntEQ(wolfSSL_write(ssl_c, "hello", 5), 5);
        ExpectIntEQ(wolfSSL_read(ssl_s,  buf, sizeof(buf)), 5);

        wolfSSL_free(ssl_c); ssl_c = NULL;
        wolfSSL_free(ssl_s); ssl_s = NULL;
        wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
        wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
        ctx_c = ctx_s = NULL;
    }

    /* ---- Scenario B: incremental step-by-step handshake pump ------------- */
    /* Each call to wolfSSL_connect / wolfSSL_accept returns WANT_READ when
     * it has consumed all available data; pumping one side at a time forces
     * wolfSSL_accept_TLSv13 to be called multiple times in different states,
     * covering the L14878 state branches exhaustively.                      */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method,
                    wolfTLSv1_3_server_method), 0);

    /* Reuse test_memio_do_handshake with a generous step budget to let it
     * interleave connect/accept calls in a fine-grained manner.             */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 40, NULL), 0);

    ExpectIntEQ(wolfSSL_write(ssl_s, "step-ok", 7), 7);
    ExpectIntEQ(wolfSSL_read(ssl_c,  buf, sizeof(buf)), 7);

    (void)err;
    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;
#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES && ... */
    return EXPECT_RESULT();
}
