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

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK)
int test_tls13_cert_with_extern_psk_apis(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_CTX_set_cert_with_extern_psk(NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(NULL, 0), WOLFSSL_FAILURE);

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    ExpectNotNull(ctx);
    ssl = wolfSSL_new(ctx);
    ExpectNotNull(ssl);

    if (EXPECT_SUCCESS()) {
        /* Any non-zero value enables cert_with_extern_psk. */
        ExpectIntEQ(wolfSSL_CTX_set_cert_with_extern_psk(ctx, -1),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_set_cert_with_extern_psk(ctx, 2),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl, -1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl, 2), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_set_cert_with_extern_psk(ctx, 1),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl, 0), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl, 1), WOLFSSL_SUCCESS);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
}
#else
int test_tls13_cert_with_extern_psk_apis(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
/* 32-byte external PSK (SHA-256 digest size) used by cwep test callbacks. */
static const unsigned char test_tls13_cwep_psk[32] = {
    0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A,
    0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A,
    0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A,
    0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A
};

static unsigned int test_tls13_cwep_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    if (id_max_len == 0 || key_max_len < sizeof(test_tls13_cwep_psk))
        return 0;
    XSTRNCPY(identity, "cwep_client", id_max_len);
    XMEMCPY(key, test_tls13_cwep_psk, sizeof(test_tls13_cwep_psk));
    return (unsigned int)sizeof(test_tls13_cwep_psk);
}

static unsigned int test_tls13_cwep_server_cb(WOLFSSL* ssl, const char* id,
    unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    if (key_max_len < sizeof(test_tls13_cwep_psk) || id == NULL)
        return 0;
    if (XSTRCMP(id, "cwep_client") != 0)
        return 0;
    XMEMCPY(key, test_tls13_cwep_psk, sizeof(test_tls13_cwep_psk));
    return (unsigned int)sizeof(test_tls13_cwep_psk);
}
#endif

int test_tls13_cert_with_extern_psk_handshake(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char appMsg[] = "cert_with_extern_psk test";
    char readBuf[sizeof(appMsg)];
    int readSz;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
#if defined(HAVE_ECC)
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, eccCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, eccKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_load_verify_locations(ctx_c, caEccCertFile,
        NULL) == WOLFSSL_SUCCESS);
#elif !defined(NO_RSA)
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, svrCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, svrKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_load_verify_locations(ctx_c, caCertFile,
        NULL) == WOLFSSL_SUCCESS);
#endif
#endif
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_cwep_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_cwep_server_cb);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_c, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_s, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_c->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_s->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_c->msgsReceived.got_certificate, 1);
    ExpectIntEQ(ssl_c->msgsReceived.got_certificate_verify, 1);

    /* Verify application data exchange works with the derived keys. */
    ExpectIntEQ(wolfSSL_write(ssl_c, appMsg, (int)XSTRLEN(appMsg)),
        (int)XSTRLEN(appMsg));
    readSz = wolfSSL_read(ssl_s, readBuf, sizeof(readBuf));
    ExpectIntEQ(readSz, (int)XSTRLEN(appMsg));
    ExpectIntEQ(XMEMCMP(readBuf, appMsg, (size_t)readSz), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_cert_with_extern_psk_requires_key_share(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
#if defined(HAVE_ECC)
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, eccCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, eccKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#elif !defined(NO_RSA)
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, svrCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, svrKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#endif
#endif
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_cwep_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_cwep_server_cb);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_c, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_s, 1), WOLFSSL_SUCCESS);
    /* Omit key_share in CH1 to force the server to send an HRR. */
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    /* CH1: client -> server (no key_share). */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* HRR: server reads CH1, sends HRR requesting a key_share group. */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(ssl_s->options.serverState,
        SERVER_HELLO_RETRY_REQUEST_COMPLETE);

    /* Complete the handshake: client sends CH2 (with key_share), server
     * responds with SH + cert + cert-verify + Finished, client finishes. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);

    /* Verify that cert_with_extern_psk was negotiated end-to-end. */
    ExpectIntEQ(ssl_c->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_s->options.pskNegotiated, 1);
    ExpectIntEQ(ssl_c->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_s->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_c->msgsReceived.got_certificate, 1);
    ExpectIntEQ(ssl_c->msgsReceived.got_certificate_verify, 1);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_cert_with_extern_psk_rejects_resumption(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_SESSION_TICKET) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (defined(HAVE_ECC) || !defined(NO_RSA))
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    byte readBuf[16];

    /* Step 1: plain TLS 1.3 handshake to obtain a session ticket.  The same
     * server CTX is reused below so the ticket encryption key matches. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
#if defined(HAVE_ECC)
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx_s, eccCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx_s, eccKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#else
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Drain the NewSessionTicket post-handshake message. */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    /* Step 2: attempt to resume while also offering cert_with_extern_psk.
     * RFC 8773bis Sect. 5.1 requires all PSKs offered alongside
     * cert_with_extern_psk to be external PSKs.  The client MUST therefore
     * suppress the resumption ticket identity from the pre_shared_key
     * extension.  The handshake succeeds as a cert_with_extern_psk handshake
     * using only the external PSK. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_cwep_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_cwep_server_cb);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_c, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    /* Handshake succeeds; the client correctly omits the resumption ticket. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    /* Verify we got a cert_with_extern_psk handshake, not a resumption. */
    ExpectIntEQ(ssl_c->options.certWithExternPsk, 1);
    ExpectIntEQ(ssl_s->options.certWithExternPsk, 1);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
/* Locate the extensions block of a TLS 1.3 ServerHello record.  On success,
 * writes the offset of the 2-byte extensions_length field into *ext_len_off
 * and returns 0.  Returns -1 on malformed input.  Only the plaintext SH
 * record (type 0x16, handshake subtype 0x02) is supported. */
static int test_cwep_sh_find_ext_block(const byte* sh, int sh_len,
    int* ext_len_off)
{
    int idx;
    int sid_len;

    /* 5 byte record hdr + 4 byte handshake hdr + 2 byte legacy_version
     * + 32 byte random + 1 byte legacy_session_id length. */
    if (sh_len < 5 + 4 + 2 + 32 + 1)
        return -1;
    if (sh[0] != 0x16 || sh[5] != 0x02)
        return -1;
    idx = 5 + 4 + 2 + 32;
    sid_len = sh[idx];
    idx += 1 + sid_len + 2 + 1; /* skip sid + cipher_suite + compression */
    if (idx + 2 > sh_len)
        return -1;
    *ext_len_off = idx;
    return 0;
}

/* Apply a delta to the record, handshake and extensions length fields of a
 * TLS 1.3 SH record.  Negative values shrink the message. */
static void test_cwep_sh_adjust_lengths(byte* sh, int ext_len_off, int delta)
{
    int v;

    v = (int)(((word32)sh[3] << 8) | sh[4]) + delta;
    sh[3] = (byte)(v >> 8);
    sh[4] = (byte)v;
    v = (int)(((word32)sh[6] << 16) | ((word32)sh[7] << 8) | sh[8]) + delta;
    sh[6] = (byte)(v >> 16);
    sh[7] = (byte)(v >> 8);
    sh[8] = (byte)v;
    v = (int)(((word32)sh[ext_len_off] << 8) | sh[ext_len_off + 1]) + delta;
    sh[ext_len_off] = (byte)(v >> 8);
    sh[ext_len_off + 1] = (byte)v;
}

/* Remove the first extension of the given type from a TLS 1.3 SH record.
 * Returns the new record length, or -1 if the extension was not present. */
static int test_cwep_sh_strip_extension(byte* sh, int sh_len, word16 ext_type)
{
    int ext_len_off;
    int ext_base, ext_end;
    int p;
    word16 ext_total;

    if (test_cwep_sh_find_ext_block(sh, sh_len, &ext_len_off) != 0)
        return -1;
    ext_total = (word16)(((word16)sh[ext_len_off] << 8) | sh[ext_len_off + 1]);
    ext_base = ext_len_off + 2;
    ext_end = ext_base + ext_total;
    if (ext_end > sh_len)
        return -1;

    p = ext_base;
    while (p + 4 <= ext_end) {
        word16 t = (word16)(((word16)sh[p] << 8) | sh[p + 1]);
        word16 l = (word16)(((word16)sh[p + 2] << 8) | sh[p + 3]);
        int entry = 4 + (int)l;
        if (p + entry > ext_end)
            return -1;
        if (t == ext_type) {
            XMEMMOVE(sh + p, sh + p + entry,
                (size_t)(sh_len - p - entry));
            test_cwep_sh_adjust_lengths(sh, ext_len_off, -entry);
            return sh_len - entry;
        }
        p += entry;
    }
    return -1;
}

#if defined(HAVE_SESSION_TICKET)
/* Append a zero-length extension of the given type to a TLS 1.3 SH record.
 * The SH body must be the tail of the record, which is the normal case. */
static int test_cwep_sh_append_empty_extension(byte* sh, int sh_len,
    int sh_cap, word16 ext_type)
{
    int ext_len_off;
    int ext_base, ext_end;
    word16 ext_total;

    if (test_cwep_sh_find_ext_block(sh, sh_len, &ext_len_off) != 0)
        return -1;
    ext_total = (word16)(((word16)sh[ext_len_off] << 8) | sh[ext_len_off + 1]);
    ext_base = ext_len_off + 2;
    ext_end = ext_base + ext_total;
    if (ext_end != sh_len)
        return -1;
    if (sh_len + 4 > sh_cap)
        return -1;

    sh[sh_len + 0] = (byte)(ext_type >> 8);
    sh[sh_len + 1] = (byte)ext_type;
    sh[sh_len + 2] = 0;
    sh[sh_len + 3] = 0;
    test_cwep_sh_adjust_lengths(sh, ext_len_off, 4);
    return sh_len + 4;
}
#endif /* HAVE_SESSION_TICKET */
#endif

int test_tls13_cert_with_extern_psk_sh_missing_key_share(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (defined(HAVE_ECC) || !defined(NO_RSA))
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte sh_buf[4096];
    const char* sh_bytes = NULL;
    int sh_sz = 0;
    int new_sz;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
#if defined(HAVE_ECC)
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, eccCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, eccKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#else
    ExpectTrue(wolfSSL_use_certificate_file(ssl_s, svrCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_use_PrivateKey_file(ssl_s, svrKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#endif
    wolfSSL_set_psk_client_callback(ssl_c, test_tls13_cwep_client_cb);
    wolfSSL_set_psk_server_callback(ssl_s, test_tls13_cwep_server_cb);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_c, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl_s, 1), WOLFSSL_SUCCESS);

    /* Drive the client to emit the ClientHello, then let the server produce
     * its flight. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* The first "message" recorded by memio may contain several concatenated
     * records (SH + CCS + first encrypted handshake record).  Slice the
     * plaintext SH record out using its own length field. */
    ExpectIntEQ(test_memio_get_message(&test_ctx, 1, &sh_bytes, &sh_sz, 0), 0);
    if (sh_sz >= 5 && (byte)sh_bytes[0] == 0x16) {
        int rec_body = ((int)(byte)sh_bytes[3] << 8) | (byte)sh_bytes[4];
        sh_sz = 5 + rec_body;
    }
    ExpectTrue(sh_sz > 0 && sh_sz <= (int)sizeof(sh_buf));
    if (sh_sz > 0 && sh_sz <= (int)sizeof(sh_buf)) {
        XMEMCPY(sh_buf, sh_bytes, (size_t)sh_sz);
        /* Strip the key_share extension from the SH so the resulting SH
         * confirms cert_with_extern_psk without negotiating (EC)DHE. */
        new_sz = test_cwep_sh_strip_extension(sh_buf, sh_sz, 0x0033);
        ExpectIntGT(new_sz, 0);
    }
    else {
        new_sz = -1;
    }

    /* Throw away the entire server flight and feed only the tampered SH. */
    test_memio_clear_buffer(&test_ctx, 1);
    if (new_sz > 0) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
            (const char*)sh_buf, new_sz), 0);
    }

    /* Client must reject the SH with EXT_MISSING. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        EXT_MISSING);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_cert_with_extern_psk_sh_confirms_resumption(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && defined(HAVE_SESSION_TICKET) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (defined(HAVE_ECC) || !defined(NO_RSA))
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    struct test_memio_ctx test_ctx;
    byte sh_buf[4096];
    const char* sh_bytes = NULL;
    byte drain[16];
    int sh_sz = 0;
    int new_sz;

    /* Phase 1: plain handshake so the client gets a session ticket.  The
     * server CTX is reused below to keep the ticket encryption key. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
#if defined(HAVE_ECC)
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx_s, eccCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx_s, eccKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#else
    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        CERT_FILETYPE) == WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Drain the NewSessionTicket post-handshake message. */
    ExpectIntEQ(wolfSSL_read(ssl_c, drain, sizeof(drain)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    /* Phase 2: client resumes WITHOUT cert_with_extern_psk.  The server
     * performs a normal resumption.  We then tamper the SH to inject an
     * unsolicited cert_with_extern_psk extension.  The client must reject
     * it because it never offered the extension. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_NONE, NULL);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

    /* Run client CH then server flight. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntEQ(test_memio_get_message(&test_ctx, 1, &sh_bytes, &sh_sz, 0), 0);
    if (sh_sz >= 5 && (byte)sh_bytes[0] == 0x16) {
        int rec_body = ((int)(byte)sh_bytes[3] << 8) | (byte)sh_bytes[4];
        sh_sz = 5 + rec_body;
    }
    ExpectTrue(sh_sz > 0 && sh_sz <= (int)sizeof(sh_buf));
    if (sh_sz > 0 && sh_sz <= (int)sizeof(sh_buf)) {
        XMEMCPY(sh_buf, sh_bytes, (size_t)sh_sz);
        /* Append an unsolicited cert_with_extern_psk (0x0021) extension.
         * The client never offered this extension, so it must be rejected. */
        new_sz = test_cwep_sh_append_empty_extension(sh_buf, sh_sz,
            (int)sizeof(sh_buf), 0x0021);
        ExpectIntGT(new_sz, 0);
    }
    else {
        new_sz = -1;
    }

    test_memio_clear_buffer(&test_ctx, 1);
    if (new_sz > 0) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 1,
            (const char*)sh_buf, new_sz), 0);
    }

    /* Client must reject the unsolicited extension. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
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
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        WOLFSSL_SESSION *sess = NULL;
        int splitEarlyData = params[i].splitEarlyData;
        int everyWriteWantWrite = params[i].everyWriteWantWrite;
        struct test_tls13_wwrite_ctx wwrite_ctx_s, wwrite_ctx_c;

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


#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_EARLY_DATA) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TICKET_HAVE_ID) && \
    !defined(NO_SESSION_CACHE) && defined(HAVE_EXT_CACHE)
/* Single-slot external session cache keyed by altSessionID, used by
 * test_tls13_early_data_0rtt_replay to assert the 0-RTT anti-replay
 * fix clears both caches. */
static struct {
    byte id[ID_LEN];
    byte has_entry;
    WOLFSSL_SESSION* sess;
    int new_calls;
    int get_calls;
    int rem_calls;
} test_tls13_0rtt_replay_cache;

static void test_tls13_0rtt_replay_cache_reset(void)
{
    /* wolfSSL_SESSION_free is NULL-safe, so unconditionally drop any
     * stored session without touching has_entry first. */
    wolfSSL_SESSION_free(test_tls13_0rtt_replay_cache.sess);
    XMEMSET(&test_tls13_0rtt_replay_cache, 0,
            sizeof(test_tls13_0rtt_replay_cache));
}

/* Stateful-ticket sessions always have haveAltSessionID set, so key the
 * cache on altSessionID directly (wolfSSL_SESSION_get_id is only
 * declared under the OpenSSL compatibility layer). */
static int test_tls13_0rtt_replay_new_cb(WOLFSSL* ssl, WOLFSSL_SESSION* s)
{
    (void)ssl;
    test_tls13_0rtt_replay_cache.new_calls++;
    if (s == NULL || !s->haveAltSessionID)
        return 0;
    wolfSSL_SESSION_free(test_tls13_0rtt_replay_cache.sess);
    XMEMCPY(test_tls13_0rtt_replay_cache.id, s->altSessionID, ID_LEN);
    test_tls13_0rtt_replay_cache.sess = s;
    test_tls13_0rtt_replay_cache.has_entry = 1;
    return 1; /* retain the reference; freed in the rem callback */
}

static WOLFSSL_SESSION* test_tls13_0rtt_replay_get_cb(WOLFSSL* ssl,
        const byte* id, int idLen, int* ref)
{
    (void)ssl;
    test_tls13_0rtt_replay_cache.get_calls++;
    *ref = 1; /* keep ownership; wolfSSL duplicates from us */
    if (!test_tls13_0rtt_replay_cache.has_entry || idLen != ID_LEN)
        return NULL;
    if (XMEMCMP(test_tls13_0rtt_replay_cache.id, id, ID_LEN) != 0)
        return NULL;
    return test_tls13_0rtt_replay_cache.sess;
}

static void test_tls13_0rtt_replay_rem_cb(WOLFSSL_CTX* ctx,
        WOLFSSL_SESSION* s)
{
    const byte* id;
    (void)ctx;
    if (!test_tls13_0rtt_replay_cache.has_entry || s == NULL)
        return;
    /* Internal-cache-evicted sessions have haveAltSessionID cleared
     * (that field sits before the DupSession copy offset), so fall
     * back to sessionID when altSessionID is not set. Both carry the
     * ID_LEN lookup key. */
    if (s->haveAltSessionID)
        id = s->altSessionID;
    else if (s->sessionIDSz == ID_LEN)
        id = s->sessionID;
    else
        return;
    if (XMEMCMP(test_tls13_0rtt_replay_cache.id, id, ID_LEN) != 0)
        return;
    wolfSSL_SESSION_free(test_tls13_0rtt_replay_cache.sess);
    test_tls13_0rtt_replay_cache.sess = NULL;
    test_tls13_0rtt_replay_cache.has_entry = 0;
    test_tls13_0rtt_replay_cache.rem_calls++;
}

/* RFC 8446 section 8 anti-replay: a 0-RTT-eligible session must be
 * evicted from both the internal and external caches on resumption so
 * the same ClientHello cannot replay early data. */
int test_tls13_early_data_0rtt_replay(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    char buf[64];
    int round;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_tls13_0rtt_replay_cache_reset();

    /* Step 1: full handshake populates both caches. */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method),
                0);
    /* Stateful tickets + 0-RTT enabled. */
    ExpectTrue(wolfSSL_set_options(ssl_s, WOLFSSL_OP_NO_TICKET) != 0);
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_ERROR_CODE_OPENSSL)
    ExpectIntEQ(wolfSSL_set_max_early_data(ssl_s, 128), WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_set_max_early_data(ssl_s, 128), 0);
#endif
    wolfSSL_CTX_sess_set_new_cb(ctx_s, test_tls13_0rtt_replay_new_cb);
    wolfSSL_CTX_sess_set_get_cb(ctx_s, test_tls13_0rtt_replay_get_cb);
    wolfSSL_CTX_sess_set_remove_cb(ctx_s, test_tls13_0rtt_replay_rem_cb);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Let the client consume NewSessionTicket. */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    ExpectIntEQ(wolfSSL_SessionIsSetup(sess), 1);
    /* Stateful (ID-only) ticket on the client side. */
    ExpectIntEQ(sess->ticketLen, ID_LEN);
    ExpectIntEQ((int)sess->maxEarlyDataSz, 128);
    /* External cache saw the add. */
    ExpectIntGT(test_tls13_0rtt_replay_cache.new_calls, 0);
    ExpectIntEQ(test_tls13_0rtt_replay_cache.has_entry, 1);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;

    /* Resume the same session twice, offering 0-RTT each time. */
    for (round = 0; round < 2 && !EXPECT_FAIL(); round++) {
        const char earlyMsg[] = "early-data-0rtt";
        int written = 0;
        int earlyRead = 0;
        char earlyBuf[sizeof(earlyMsg)];

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(earlyBuf, 0, sizeof(earlyBuf));
        /* Reuse the CTXs so both caches survive (test_memio_setup
         * leaves *ctx alone when non-NULL). */
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                        &ssl_s, wolfTLSv1_3_client_method,
                        wolfTLSv1_3_server_method), 0);
        ExpectTrue(wolfSSL_set_options(ssl_s, WOLFSSL_OP_NO_TICKET) != 0);
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_ERROR_CODE_OPENSSL)
        ExpectIntEQ(wolfSSL_set_max_early_data(ssl_s, 128),
                    WOLFSSL_SUCCESS);
#else
        ExpectIntEQ(wolfSSL_set_max_early_data(ssl_s, 128), 0);
#endif
        ExpectIntEQ(wolfSSL_SessionIsSetup(sess), 1);
        ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);

        ExpectIntEQ(test_tls13_early_data_write_until_write_ok(ssl_c,
                        earlyMsg, (int)sizeof(earlyMsg), &written),
                    sizeof(earlyMsg));
        ExpectIntEQ(written, sizeof(earlyMsg));

        (void)test_tls13_early_data_read_until_write_ok(ssl_s, earlyBuf,
                sizeof(earlyBuf), &earlyRead);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        if (round == 0) {
            ExpectTrue(wolfSSL_session_reused(ssl_s));
            ExpectIntEQ(earlyRead, sizeof(earlyMsg));
            ExpectStrEQ(earlyMsg, earlyBuf);
            /* Fix fired exactly once to evict the cached entry. */
            ExpectIntEQ(test_tls13_0rtt_replay_cache.rem_calls, 1);
        }
        else {
            ExpectFalse(wolfSSL_session_reused(ssl_s));
            ExpectIntEQ(earlyRead, 0);
            /* No additional eviction in the replay round. */
            ExpectIntEQ(test_tls13_0rtt_replay_cache.rem_calls, 1);
        }

        wolfSSL_free(ssl_c); ssl_c = NULL;
        wolfSSL_free(ssl_s); ssl_s = NULL;
    }

    wolfSSL_SESSION_free(sess);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    test_tls13_0rtt_replay_cache_reset();
    return EXPECT_RESULT();
}
#else
int test_tls13_early_data_0rtt_replay(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif


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
    unsigned char hrr[] = {
      0x16, 0x03, 0x03, 0x00, 0x32, 0x02, 0x00, 0x00, 0x2e, 0x03, 0x03, 0xcf,
      0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
      0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
      0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x01, 0x00, 0x00,
      0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
    };

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


#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
static int DupEchSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;

    return sz;
}
static int DupEchRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    WOLFSSL_BUFFER_INFO* msg = (WOLFSSL_BUFFER_INFO*)ctx;
    int len = (int)msg->length;

    (void)ssl;
    (void)sz;

    if (len > sz)
        len = sz;
    XMEMCPY(buf, msg->buffer, len);
    msg->buffer += len;
    msg->length -= len;

    return len;
}
#endif

/* Test detection of duplicate ECH extension (type 0xfe0d) in ClientHello.
 * ECH has a semaphore mapping in TLSX_ToSemaphore() and needs to be included
 * in the duplicate-detection gate in TLSX_Parse(). RFC 8446 section 4.2
 * requires rejecting messages with duplicate extensions.
 */
int test_tls13_duplicate_ech_extension(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
    /* TLS 1.3 ClientHello with two ECH extensions (type 0xfe0d).
     * Extensions block contains: supported_versions + ECH + ECH (dup). */
    const unsigned char clientHelloDupEch[] = {
        0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00,
        0x3c, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x00, 0x00, 0x02, 0x13, 0x01,
        0x01, 0x00, 0x00, 0x11, 0x00, 0x2b, 0x00, 0x03,
        0x02, 0x03, 0x04, 0xfe, 0x0d, 0x00, 0x01, 0x00,
        0xfe, 0x0d, 0x00, 0x01, 0x00
    };
    WOLFSSL_BUFFER_INFO msg;
    const char* testCertFile;
    const char* testKeyFile;
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL     *ssl = NULL;

#ifndef NO_RSA
    testCertFile = svrCertFile;
    testKeyFile = svrKeyFile;
#elif defined(HAVE_ECC)
    testCertFile = eccCertFile;
    testKeyFile = eccKeyFile;
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));

    ExpectTrue(wolfSSL_CTX_use_certificate_file(ctx, testCertFile,
        CERT_FILETYPE));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, testKeyFile,
        CERT_FILETYPE));

    /* Read from 'msg'. */
    wolfSSL_SetIORecv(ctx, DupEchRecv);
    /* No where to send to - dummy sender. */
    wolfSSL_SetIOSend(ctx, DupEchSend);

    ssl = wolfSSL_new(ctx);
    ExpectNotNull(ssl);

    msg.buffer = (unsigned char*)clientHelloDupEch;
    msg.length = (unsigned int)sizeof(clientHelloDupEch);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    ExpectIntNE(wolfSSL_accept(ssl), WOLFSSL_SUCCESS);
    /* Can return duplicate ext error or socket error if the peer closed
     * down while sending alert. */
    if (wolfSSL_get_error(ssl, 0) != WC_NO_ERR_TRACE(SOCKET_ERROR_E)) {
        ExpectIntEQ(wolfSSL_get_error(ssl, 0),
            WC_NO_ERR_TRACE(DUPLICATE_TLS_EXT_E));
    }

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
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;

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
int test_tls13_empty_record_limit(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    int recSz = 0;
    /* Send exactly WOLFSSL_MAX_EMPTY_RECORDS to pin the boundary check.
     * The Nth record increments the counter to N, and `N >= N` triggers
     * the error. Sending one more would let a `>=` -> `>` mutation survive
     * (the extra record would still trip the mutated check). */
    int numRecs = WOLFSSL_MAX_EMPTY_RECORDS;
    byte rec[128]; /* buffer for one encrypted record */
    byte *allRecs = NULL;
    int i;
    char buf[64];

    /* Test 1: Exceeding the empty record limit returns an error. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    if (EXPECT_SUCCESS()) {
        /* Consume any post-handshake messages (e.g. NewSessionTicket). */
        wolfSSL_read(ssl_c, buf, sizeof(buf));
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);

        /* Get the size of an encrypted zero-length app data record. */
        recSz = BuildTls13Message(ssl_c, NULL, 0, NULL, 0,
                                  application_data, 0, 1, 0);
        ExpectIntGT(recSz, 0);
        ExpectIntLE(recSz, (int)sizeof(rec));
    }

    /* Build all empty records into one contiguous buffer. */
    if (EXPECT_SUCCESS()) {
        allRecs = (byte*)XMALLOC((size_t)(recSz * numRecs), NULL,
                                 DYNAMIC_TYPE_TMP_BUFFER);
        ExpectNotNull(allRecs);
    }

    for (i = 0; i < numRecs && EXPECT_SUCCESS(); i++) {
        XMEMSET(rec, 0, sizeof(rec));
        ExpectIntEQ(BuildTls13Message(ssl_c, rec, (int)sizeof(rec), rec +
                        RECORD_HEADER_SZ, 0, application_data, 0, 0, 0),
                    recSz);
        XMEMCPY(allRecs + i * recSz, rec, (size_t)recSz);
    }

    /* Inject all records as a single message. */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                        (const char*)allRecs, recSz * numRecs), 0);
    }

    /* The server's wolfSSL_read should fail with EMPTY_RECORD_LIMIT_E. */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)),
                    WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                    WC_NO_ERR_TRACE(EMPTY_RECORD_LIMIT_E));
    }

    XFREE(allRecs, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    allRecs = NULL;
    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

    /* Test 2: Counter resets on non-empty record.
     * Send (limit - 1) empty records, then 1 non-empty, then (limit - 1)
     * more empty records. Should succeed without hitting the limit. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    if (EXPECT_SUCCESS()) {
        wolfSSL_read(ssl_c, buf, sizeof(buf));
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);

        recSz = BuildTls13Message(ssl_c, NULL, 0, NULL, 0,
                                  application_data, 0, 1, 0);
        ExpectIntGT(recSz, 0);
    }

    if (EXPECT_SUCCESS()) {
        int emptyBefore = WOLFSSL_MAX_EMPTY_RECORDS - 1;
        int emptyAfter = WOLFSSL_MAX_EMPTY_RECORDS - 1;
        int dataRecSz = 0;
        byte dataRec[128];
        byte payload[1] = { 'a' };
        int totalSz = 0;

        if (EXPECT_SUCCESS()) {
            dataRecSz = BuildTls13Message(ssl_c, NULL, 0, NULL, 1,
                                          application_data, 0, 1, 0);
            ExpectIntGT(dataRecSz, 0);
        }

        if (EXPECT_SUCCESS()) {
            totalSz = recSz * (emptyBefore + emptyAfter) + dataRecSz;
            allRecs = (byte*)XMALLOC((size_t)totalSz, NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
            ExpectNotNull(allRecs);
        }

        /* Build (limit - 1) empty records */
        for (i = 0; i < emptyBefore && EXPECT_SUCCESS(); i++) {
            XMEMSET(rec, 0, sizeof(rec));
            ExpectIntEQ(BuildTls13Message(ssl_c, rec, (int)sizeof(rec),
                            rec + RECORD_HEADER_SZ, 0, application_data,
                            0, 0, 0), recSz);
            XMEMCPY(allRecs + i * recSz, rec, (size_t)recSz);
        }

        /* Build 1 non-empty record */
        if (EXPECT_SUCCESS()) {
            XMEMSET(dataRec, 0, sizeof(dataRec));
            XMEMCPY(dataRec + RECORD_HEADER_SZ, payload, sizeof(payload));
            ExpectIntEQ(BuildTls13Message(ssl_c, dataRec, (int)sizeof(dataRec),
                            dataRec + RECORD_HEADER_SZ, 1, application_data,
                            0, 0, 0), dataRecSz);
            XMEMCPY(allRecs + emptyBefore * recSz, dataRec,
                     (size_t)dataRecSz);
        }

        /* Build (limit - 1) more empty records */
        for (i = 0; i < emptyAfter && EXPECT_SUCCESS(); i++) {
            XMEMSET(rec, 0, sizeof(rec));
            ExpectIntEQ(BuildTls13Message(ssl_c, rec, (int)sizeof(rec),
                            rec + RECORD_HEADER_SZ, 0, application_data,
                            0, 0, 0), recSz);
            XMEMCPY(allRecs + emptyBefore * recSz + dataRecSz + i * recSz,
                     rec, (size_t)recSz);
        }

        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                            (const char*)allRecs, totalSz), 0);
        }
    }

    /* wolfSSL_read should return the 1-byte payload. The counter resets
     * on the non-empty record so neither batch of (limit - 1) empties
     * triggers the error. */
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), 1);
        ExpectIntEQ(buf[0], 'a');
    }

    XFREE(allRecs, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_tls13_short_session_ticket(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    char buf[64];

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


/* Test that a corrupted TLS 1.3 Finished verify_data is properly rejected
 * with VERIFY_FINISHED_ERROR. We run the handshake step-by-step and corrupt
 * the server's client_write_MAC_secret before it processes the client's
 * Finished, causing the HMAC comparison to fail.
 */
int test_tls13_corrupted_finished(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    /* Step 1: Client sends ClientHello */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 2: Server processes CH, sends SH + EE + Cert + CV + Finished */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 3: Client processes server flight, verifies server Finished,
     * sends client Finished */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

    /* Corrupt the server's client_write_MAC_secret so that when it computes
     * the expected Finished HMAC, the result won't match the client's actual
     * Finished message. */
    if (EXPECT_SUCCESS()) {
        XMEMSET(ssl_s->keys.client_write_MAC_secret, 0xFF,
            sizeof(ssl_s->keys.client_write_MAC_secret));
    }

    /* Step 4: Server processes client Finished - should fail */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(VERIFY_FINISHED_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* Test the TLS 1.3 peerAuthGood fail-safe checks on both sides.
 * The client branch queues a real server flight before forcing
 * FIRST_REPLY_SECOND on a live handshake object, and the server branch clears
 * peerAuthGood just before processing the client's Finished.
 */
int test_tls13_peerauth_failsafe(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        /* Queue ClientHello and server flight. */
        ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);

        ssl_c->options.peerAuthGood = 0;
        ssl_c->options.sendVerify = 0;
        ssl_c->options.connectState = FIRST_REPLY_SECOND;
        ret = wolfSSL_connect(ssl_c);
        ExpectIntEQ(ret, WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(ssl_c->options.connectState, FIRST_REPLY_SECOND);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ctx_c = NULL;
    ctx_s = NULL;
    ssl_c = NULL;
    ssl_s = NULL;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

        ssl_s->options.peerAuthGood = 0;
        ret = wolfSSL_accept(ssl_s);
        ExpectIntEQ(ret, WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(ssl_s->options.peerAuthGood, 0);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/* Test that a corrupted HRR cookie HMAC is rejected with HRR_COOKIE_ERROR. */
int test_tls13_hrr_bad_cookie(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_SEND_HRR_COOKIE) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_send_hrr_cookie(ssl_s, NULL, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    /* Step 1: Client sends CH1 (no key shares) */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 2: Server sends HRR with cookie */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Step 3: Client processes HRR, sends CH2 with cookie */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    /* Corrupt the server-side cookie secret after HRR so CH2's cookie no longer
     * verifies in TlsCheckCookie(). */
    if (EXPECT_SUCCESS()) {
        ExpectNotNull(ssl_s->buffers.tls13CookieSecret.buffer);
        ExpectIntGT(ssl_s->buffers.tls13CookieSecret.length, 0);
        ssl_s->buffers.tls13CookieSecret.buffer[
            ssl_s->buffers.tls13CookieSecret.length - 1] ^= 0xFF;
    }

    /* Step 4: Server processes corrupted CH2 - should fail */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(HRR_COOKIE_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that a TLS 1.3 encrypted record whose inner content type resolves to
 * zero is rejected in removeMsgInnerPadding() with PARSE_ERROR and an
 * unexpected_message alert. */
int test_tls13_zero_inner_content_type(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    byte record[64];
    byte dummy = 0;
    char readBuf[8];
    int recordSz;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&h, 0, sizeof(h));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_no_ticket_TLSv13(ssl_s), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(test_ctx.s_len, 0);

        recordSz = BuildTls13Message(ssl_c, record, (int)sizeof(record), &dummy,
            0, no_type, 0, 0, 0);
        ExpectIntGT(recordSz, 0);
        ExpectIntEQ(wolfSSL_inject(ssl_s, record, recordSz), WOLFSSL_SUCCESS);
    }

    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, (int)sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WC_NO_ERR_TRACE(PARSE_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_s, &h), WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_tx.code, unexpected_message);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test that a TLS 1.3-capable client rejects downgrade sentinels in a
 * downgraded ServerHello random for both TLS 1.2 and TLS 1.1-or-lower. */
int test_tls13_downgrade_sentinel(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;
    int randomOff = 11 + 24;
    static const byte downgradeTls12[8] = {
        0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
    };
#ifndef NO_OLD_TLS
    static const byte downgradeTls11[8] = {
        0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00
    };
#endif

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&h, 0, sizeof(h));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLS_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS()) {
        ExpectIntGT(test_ctx.c_len, randomOff + (int)sizeof(downgradeTls12));
        XMEMCPY(test_ctx.c_buff + randomOff, downgradeTls12,
            sizeof(downgradeTls12));
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(VERSION_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectTrue(h.last_tx.code == illegal_parameter ||
        h.last_tx.code == wolfssl_alert_protocol_version);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

#ifndef NO_OLD_TLS
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&h, 0, sizeof(h));
    ctx_c = NULL;
    ctx_s = NULL;
    ssl_c = NULL;
    ssl_s = NULL;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLS_client_method, wolfTLSv1_1_server_method), 0);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS()) {
        ExpectIntGT(test_ctx.c_len, randomOff + (int)sizeof(downgradeTls11));
        XMEMCPY(test_ctx.c_buff + randomOff, downgradeTls11,
            sizeof(downgradeTls11));
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(VERSION_ERROR));
    ExpectIntEQ(wolfSSL_get_alert_history(ssl_c, &h), WOLFSSL_SUCCESS);
    ExpectTrue(h.last_tx.code == illegal_parameter ||
        h.last_tx.code == wolfssl_alert_protocol_version);
    ExpectIntEQ(h.last_tx.level, alert_fatal);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
#endif
    return EXPECT_RESULT();
}

/* Test that a TLS 1.3 client rejects ServerHello cipher suites that are not
 * TLS 1.3 suites or were not offered by the client. */
int test_tls13_serverhello_bad_cipher_suites(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_AES_256_GCM_SHA384)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx12_c = NULL;
    WOLFSSL_CTX *ctx12_s = NULL;
    WOLFSSL *ssl12_c = NULL;
    WOLFSSL *ssl12_s = NULL;
    struct test_memio_ctx test_ctx12;
    int suiteOff;
    byte tls12Suite0 = 0;
    byte tls12Suite = 0;

    XMEMSET(&test_ctx12, 0, sizeof(test_ctx12));
    ExpectIntEQ(test_memio_setup(&test_ctx12, &ctx12_c, &ctx12_s, &ssl12_c,
        &ssl12_s, wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl12_c, ssl12_s, 10, NULL), 0);
    if (EXPECT_SUCCESS()) {
        tls12Suite0 = ssl12_c->options.cipherSuite0;
        tls12Suite = ssl12_c->options.cipherSuite;
        ExpectIntNE(tls12Suite0, TLS13_BYTE);
    }
    wolfSSL_free(ssl12_c);
    wolfSSL_CTX_free(ctx12_c);
    wolfSSL_free(ssl12_s);
    wolfSSL_CTX_free(ctx12_s);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    suiteOff = 44 + (byte)test_ctx.c_buff[43];
    if (EXPECT_SUCCESS()) {
        ExpectIntGT(test_ctx.c_len, suiteOff + 1);
        ExpectNotNull(ssl_c->suites);
        ssl_c->suites->suiteSz = 2;
        ssl_c->suites->suites[0] = tls12Suite0;
        ssl_c->suites->suites[1] = tls12Suite;
        test_ctx.c_buff[suiteOff + 0] = tls12Suite0;
        test_ctx.c_buff[suiteOff + 1] = tls12Suite;
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(INVALID_PARAMETER));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ctx_c = NULL;
    ctx_s = NULL;
    ssl_c = NULL;
    ssl_s = NULL;
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);

    suiteOff = 44 + (byte)test_ctx.c_buff[43];
    if (EXPECT_SUCCESS()) {
        ExpectIntGT(test_ctx.c_len, suiteOff + 1);
        test_ctx.c_buff[suiteOff + 0] = TLS13_BYTE;
        test_ctx.c_buff[suiteOff + 1] = TLS_AES_256_GCM_SHA384;
    }

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WC_NO_ERR_TRACE(INVALID_PARAMETER));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
