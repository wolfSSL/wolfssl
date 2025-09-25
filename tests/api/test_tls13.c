/* test_tls13.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_tls13.h>

#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
#ifdef WC_SHA384_DIGEST_SIZE
    static byte fixedKey[WC_SHA384_DIGEST_SIZE] = { 0, };
#else
    static byte fixedKey[WC_SHA256_DIGEST_SIZE] = { 0, };
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
#else
    #ifndef WOLFSSL_NO_ML_KEM_512
                               WOLFSSL_ML_KEM_512
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
                               WOLFSSL_ML_KEM_768
    #else
                               WOLFSSL_ML_KEM_1024
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
    #else
            ":P256_KYBER_LEVEL5"
    #endif
#else
    #ifndef WOLFSSL_NO_KYBER512
            ":SecP256r1MLKEM512"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":SecP384r1MLKEM768"
    #else
            ":SecP521r1MLKEM1024"
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
    #else
            ":KYBER_LEVEL5"
    #endif
#else
    #ifndef WOLFSSL_NO_KYBER512
            ":ML_KEM_512"
    #elif !defined(WOLFSSL_NO_KYBER768)
            ":ML_KEM_768"
    #else
            ":ML_KEM_1024"
    #endif
#endif
#endif
            "";
#endif /* defined(OPENSSL_EXTRA) && defined(HAVE_ECC) */
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_MLKEM_NO_MALLOC) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
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
        WOLFSSL_FILETYPE_PEM);
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
    wolfSSL_CTX_use_PrivateKey_file(serverCtx, ourKey, WOLFSSL_FILETYPE_PEM);
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
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
#ifndef WOLFSSL_NO_ML_KEM
#ifndef WOLFSSL_NO_ML_KEM_768
    mlkemLevel = WOLFSSL_ML_KEM_768;
#elif !defined(WOLFSSL_NO_ML_KEM_1024)
    mlkemLevel = WOLFSSL_ML_KEM_1024;
#else
    mlkemLevel = WOLFSSL_ML_KEM_512;
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
    ExpectIntEQ(wolfSSL_write_early_data(clientSsl, earlyData,
        sizeof(earlyData), &outSz), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
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
        WOLFSSL_FILETYPE_PEM));
    ExpectTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, eccKeyFile,
        WOLFSSL_FILETYPE_PEM));
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


#if defined(HAVE_RPK) && !defined(NO_TLS)

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
#endif /* HAVE_RPK && !NO_TLS */


int test_tls13_rpk_handshake(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && (!defined(WOLFSSL_NO_TLS12) || defined(WOLFSSL_TLS13))
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
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM)
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
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            svrCertFile,     WOLFSSL_FILETYPE_PEM,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliCertFile,     WOLFSSL_FILETYPE_PEM,
            svrRpkCertFile,  WOLFSSL_FILETYPE_ASN1,
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
            cliKeyFile,      WOLFSSL_FILETYPE_PEM,
            svrKeyFile,      WOLFSSL_FILETYPE_PEM )
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
    defined(WOLFSSL_HAVE_MLKEM)
static void test_tls13_pq_groups_ctx_ready(WOLFSSL_CTX* ctx)
{
#ifdef WOLFSSL_MLKEM_KYBER
    int group = WOLFSSL_KYBER_LEVEL5;
#else
    int group = WOLFSSL_ML_KEM_1024;
#endif
    AssertIntEQ(wolfSSL_CTX_set_groups(ctx, &group, 1), WOLFSSL_SUCCESS);
}

static void test_tls13_pq_groups_on_result(WOLFSSL* ssl)
{
#ifdef WOLFSSL_MLKEM_KYBER
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "KYBER_LEVEL5");
#else
    AssertStrEQ(wolfSSL_get_curve_name(ssl), "ML_KEM_1024");
#endif
}
#endif

int test_tls13_pq_groups(void)
{
    EXPECT_DECLS;
#if defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_HAVE_MLKEM)
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

int test_tls13_early_data(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET)
    int written = 0;
    int read = 0;
    size_t i;
    int splitEarlyData;
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
    } params[] = {
#ifdef WOLFSSL_TLS13
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
                "TLS 1.3", 0 },
#endif
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method,
                "DTLS 1.3", 1 },
#endif
    };

    for (i = 0; i < sizeof(params)/sizeof(*params) && !EXPECT_FAIL(); i++) {
        for (splitEarlyData = 0; splitEarlyData < 2; splitEarlyData++) {
            struct test_memio_ctx test_ctx;
            WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
            WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
            WOLFSSL_SESSION *sess = NULL;

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));

            fprintf(stderr, "\tEarly data with %s\n", params[i].tls_version);

            ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
                    &ssl_s, params[i].client_meth, params[i].server_meth), 0);

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

            /* Test 0-RTT data */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write_early_data(ssl_c, msg, sizeof(msg),
                    &written), sizeof(msg));
            ExpectIntEQ(written, sizeof(msg));

            if (splitEarlyData) {
                ExpectIntEQ(wolfSSL_write_early_data(ssl_c, msg, sizeof(msg),
                        &written), sizeof(msg));
                ExpectIntEQ(written, sizeof(msg));
            }

            /* Read first 0-RTT data (if split otherwise entire data) */
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf, sizeof(msgBuf),
                    &read), sizeof(msg));
            ExpectIntEQ(read, sizeof(msg));
            ExpectStrEQ(msg, msgBuf);

            /* Test 0.5-RTT data */
            ExpectIntEQ(wolfSSL_write(ssl_s, msg4, sizeof(msg4)), sizeof(msg4));

            if (splitEarlyData) {
                /* Read second 0-RTT data */
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf,
                    sizeof(msgBuf), &read), sizeof(msg));
                ExpectIntEQ(read, sizeof(msg));
                ExpectStrEQ(msg, msgBuf);
            }

            if (params[i].isUdp) {
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
                ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
                    WC_NO_ERR_TRACE(APP_DATA_READY));

                /* Read server 0.5-RTT data */
                ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)),
                    sizeof(msg4));
                ExpectStrEQ(msg4, msgBuf);

                /* Complete handshake */
                ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
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
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf,
                    sizeof(msgBuf), &read), 0);
                ExpectIntEQ(read, 0);
                ExpectTrue(wolfSSL_is_init_finished(ssl_s));

                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
            }
            else {
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);

                wolfSSL_SetLoggingPrefix("server");
                ExpectFalse(wolfSSL_is_init_finished(ssl_s));
                ExpectIntEQ(wolfSSL_read_early_data(ssl_s, msgBuf,
                    sizeof(msgBuf), &read), 0);
                ExpectIntEQ(read, 0);
                ExpectTrue(wolfSSL_is_init_finished(ssl_s));

                /* Read server 0.5-RTT data */
                wolfSSL_SetLoggingPrefix("client");
                ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)),
                    sizeof(msg4));
                ExpectStrEQ(msg4, msgBuf);
            }

            /* Test bi-directional write */
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_write(ssl_c, msg2, sizeof(msg2)), sizeof(msg2));
            wolfSSL_SetLoggingPrefix("server");
            ExpectIntEQ(wolfSSL_read(ssl_s, msgBuf, sizeof(msgBuf)),
                sizeof(msg2));
            ExpectStrEQ(msg2, msgBuf);
            ExpectIntEQ(wolfSSL_write(ssl_s, msg3, sizeof(msg3)), sizeof(msg3));
            wolfSSL_SetLoggingPrefix("client");
            ExpectIntEQ(wolfSSL_read(ssl_c, msgBuf, sizeof(msgBuf)),
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
    }
#endif
    return EXPECT_RESULT();
}

