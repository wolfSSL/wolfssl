/* test_certman.c
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
#include <wolfssl/ocsp.h>
#include <tests/api/api.h>
#include <tests/api/test_certman.h>
#include <tests/utils.h>

int test_wolfSSL_CertManagerAPI(void)
{
    EXPECT_DECLS;
#ifndef NO_CERTS
    WOLFSSL_CERT_MANAGER* cm = NULL;
    unsigned char c = 0;

    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));

    wolfSSL_CertManagerFree(NULL);
    ExpectIntEQ(wolfSSL_CertManager_up_ref(NULL), 0);
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifdef WOLFSSL_TRUST_PEER_CERT
    ExpectIntEQ(wolfSSL_CertManagerUnload_trust_peers(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer_ex(NULL, &c, 1,
        WOLFSSL_FILETYPE_ASN1, 0, 0), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

#if !defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(NULL, NULL, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, NULL, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(NULL, &c, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(NULL, NULL, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(NULL, &c, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, NULL, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, &c, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, &c, 1, -1),
        WC_NO_ERR_TRACE(WOLFSSL_BAD_FILETYPE));
#endif

#if !defined(NO_FILESYSTEM)
    {
    #ifdef WOLFSSL_PEM_TO_DER
        const char* ca_cert = "./certs/ca-cert.pem";
    #if !defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)
        const char* ca_cert_der = "./certs/ca-cert.der";
    #endif
    #else
        const char* ca_cert = "./certs/ca-cert.der";
    #endif
        const char* ca_path = "./certs";

    #if !defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)
        ExpectIntEQ(wolfSSL_CertManagerVerify(NULL, NULL, -1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, NULL, WOLFSSL_FILETYPE_ASN1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_CertManagerVerify(NULL, ca_cert,
            WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, ca_cert, -1),
            WC_NO_ERR_TRACE(WOLFSSL_BAD_FILETYPE));
#ifdef WOLFSSL_PEM_TO_DER
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, ca_cert_der,
            WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER));
#endif
        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, "no-file",
            WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(WOLFSSL_BAD_FILE));
    #endif

        ExpectIntEQ(wolfSSL_CertManagerLoadCA(NULL, NULL, NULL),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_CertManagerLoadCA(NULL, ca_cert, NULL),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_CertManagerLoadCA(NULL, NULL, ca_path),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
        ExpectIntEQ(wolfSSL_CertManagerLoadCA(NULL, ca_cert, ca_path),
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    }
#endif

#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, 0), 1);
#elif !defined(HAVE_CRL)
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, 0),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif

    ExpectIntEQ(wolfSSL_CertManagerDisableCRL(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerDisableCRL(cm), 1);
#ifdef HAVE_CRL
    /* Test APIs when CRL is disabled. */
#ifdef HAVE_CRL_IO
    ExpectIntEQ(wolfSSL_CertManagerSetCRL_IOCb(cm, NULL), 1);
#endif
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, server_cert_der_2048,
        sizeof_server_cert_der_2048), 1);
    ExpectIntEQ(wolfSSL_CertManagerFreeCRL(cm), 1);
#endif

    /* OCSP */
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSP(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSP(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPStapling(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPStapling(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPMustStaple(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPMustStaple(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPStapling(cm),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPMustStaple(cm),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPMustStaple(cm),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif

#ifdef HAVE_OCSP
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(NULL, NULL, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, NULL, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(NULL, &c, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(NULL, &c, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, &c, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CertManagerCheckOCSPResponse(NULL, NULL, 0,
        NULL, NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSPResponse(cm, NULL, 1,
        NULL, NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSPResponse(NULL, &c, 1,
        NULL, NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(NULL, ""),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(cm, NULL), 1);

    ExpectIntEQ(wolfSSL_CertManagerSetOCSP_Cb(NULL, NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerSetOCSP_Cb(cm, NULL, NULL, NULL), 1);

    ExpectIntEQ(wolfSSL_CertManagerDisableOCSP(cm), 1);
    /* Test APIs when OCSP is disabled. */
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSPResponse(cm, &c, 1,
        NULL, NULL, NULL, NULL), 1);
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, &c, 1), 1);

#endif

    ExpectIntEQ(wolfSSL_CertManager_up_ref(cm), 1);
    if (EXPECT_SUCCESS()) {
        wolfSSL_CertManagerFree(cm);
    }
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));

#ifdef HAVE_OCSP
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSP(cm, WOLFSSL_OCSP_URL_OVERRIDE |
         WOLFSSL_OCSP_CHECKALL), 1);
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPStapling(cm), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPStapling(cm), 1);
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPStapling(cm), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPStapling(cm), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSPMustStaple(cm), 1);
    ExpectIntEQ(wolfSSL_CertManagerDisableOCSPMustStaple(cm), 1);
#endif

    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(cm, ""), 1);
    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(cm, ""), 1);
#endif

#ifdef WOLFSSL_TRUST_PEER_CERT
    ExpectIntEQ(wolfSSL_CertManagerUnload_trust_peers(cm), 1);
#endif
    wolfSSL_CertManagerFree(cm);
#endif
    return EXPECT_RESULT();
}

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS)
static int test_cm_load_ca_buffer(const byte* cert_buf, size_t cert_sz,
    int file_type)
{
    int ret;
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        fprintf(stderr, "test_cm_load_ca failed\n");
        return -1;
    }

    ret = wolfSSL_CertManagerLoadCABuffer(cm, cert_buf, (sword32)cert_sz,
                                          file_type);

    wolfSSL_CertManagerFree(cm);

    return ret;
}

static int test_cm_load_ca_file(const char* ca_cert_file)
{
    int ret = 0;
    byte* cert_buf = NULL;
    size_t cert_sz = 0;
#if defined(WOLFSSL_PEM_TO_DER)
    DerBuffer* pDer = NULL;
#endif

    ret = load_file(ca_cert_file, &cert_buf, &cert_sz);
    if (ret == 0) {
        /* normal test */
        ret = test_cm_load_ca_buffer(cert_buf, cert_sz, CERT_FILETYPE);

        if (ret == WOLFSSL_SUCCESS) {
            /* test including null terminator in length */
            byte* tmp = (byte*)realloc(cert_buf, cert_sz+1);
            if (tmp == NULL) {
                ret = MEMORY_E;
            }
            else {
                cert_buf = tmp;
                cert_buf[cert_sz] = '\0';
                ret = test_cm_load_ca_buffer(cert_buf, cert_sz+1,
                        CERT_FILETYPE);
            }

        }

    #if defined(WOLFSSL_PEM_TO_DER)
        if (ret == WOLFSSL_SUCCESS) {
            /* test loading DER */
            ret = wc_PemToDer(cert_buf, (sword32)cert_sz, CA_TYPE, &pDer,
                    NULL, NULL, NULL);
            if (ret == 0 && pDer != NULL) {
                ret = test_cm_load_ca_buffer(pDer->buffer, pDer->length,
                    WOLFSSL_FILETYPE_ASN1);

                wc_FreeDer(&pDer);
            }
        }
    #endif

    }
    free(cert_buf);

    return ret;
}

static int test_cm_load_ca_buffer_ex(const byte* cert_buf, size_t cert_sz,
                                     int file_type, word32 flags)
{
    int ret;
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        fprintf(stderr, "test_cm_load_ca failed\n");
        return -1;
    }

    ret = wolfSSL_CertManagerLoadCABuffer_ex(cm, cert_buf, (sword32)cert_sz,
                                             file_type, 0, flags);

    wolfSSL_CertManagerFree(cm);

    return ret;
}

static int test_cm_load_ca_file_ex(const char* ca_cert_file, word32 flags)
{
    int ret = 0;
    byte* cert_buf = NULL;
    size_t cert_sz = 0;
#if defined(WOLFSSL_PEM_TO_DER)
    DerBuffer* pDer = NULL;
#endif

    ret = load_file(ca_cert_file, &cert_buf, &cert_sz);
    if (ret == 0) {
        /* normal test */
        ret = test_cm_load_ca_buffer_ex(cert_buf, cert_sz,
                                        CERT_FILETYPE, flags);

        if (ret == WOLFSSL_SUCCESS) {
            /* test including null terminator in length */
            byte* tmp = (byte*)realloc(cert_buf, cert_sz+1);
            if (tmp == NULL) {
                ret = MEMORY_E;
            }
            else {
                cert_buf = tmp;
                cert_buf[cert_sz] = '\0';
                ret = test_cm_load_ca_buffer_ex(cert_buf, cert_sz+1,
                        CERT_FILETYPE, flags);
            }

        }

    #if defined(WOLFSSL_PEM_TO_DER)
        if (ret == WOLFSSL_SUCCESS) {
            /* test loading DER */
            ret = wc_PemToDer(cert_buf, (sword32)cert_sz, CA_TYPE, &pDer,
                              NULL, NULL, NULL);
            if (ret == 0 && pDer != NULL) {
                ret = test_cm_load_ca_buffer_ex(pDer->buffer, pDer->length,
                    WOLFSSL_FILETYPE_ASN1, flags);

                wc_FreeDer(&pDer);
            }
        }
    #endif

    }
    free(cert_buf);

    return ret;
}

#endif /* !NO_FILESYSTEM && !NO_CERTS */

int test_wolfSSL_CertManagerLoadCABuffer(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS)
#if defined(WOLFSSL_PEM_TO_DER)
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* ca_expired_cert = "./certs/test/expired/expired-ca.pem";
#else
    const char* ca_cert = "./certs/ca-cert.der";
    const char* ca_expired_cert = "./certs/test/expired/expired-ca.der";
#endif
    int ret;

    ExpectIntLE(ret = test_cm_load_ca_file(ca_cert), 1);
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_RSA)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif

    ExpectIntLE(ret = test_cm_load_ca_file(ca_expired_cert), 1);
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_RSA)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
#elif !(WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS && \
        WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) && !defined(NO_ASN_TIME)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_AFTER_DATE_E));
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerLoadCABuffer_ex(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS)
#if defined(WOLFSSL_PEM_TO_DER)
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* ca_expired_cert = "./certs/test/expired/expired-ca.pem";
#else
    const char* ca_cert = "./certs/ca-cert.der";
    const char* ca_expired_cert = "./certs/test/expired/expired-ca.der";
#endif
    int ret;

    ExpectIntLE(ret = test_cm_load_ca_file_ex(ca_cert, WOLFSSL_LOAD_FLAG_NONE),
        1);
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_RSA)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif

    ExpectIntLE(ret = test_cm_load_ca_file_ex(ca_expired_cert,
        WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY), 1);
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
#elif defined(NO_RSA)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E));
#elif !(WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS && \
        WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) && !defined(NO_ASN_TIME) && \
      defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(ASN_AFTER_DATE_E));
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif

#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerLoadCABufferType(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    !defined(NO_RSA) && !defined(NO_SHA256) && \
    !defined(WOLFSSL_TEST_APPLE_NATIVE_CERT_VALIDATION)
#if defined(WOLFSSL_PEM_TO_DER)
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* int1_cert = "./certs/intermediate/ca-int-cert.pem";
    const char* int2_cert = "./certs/intermediate/ca-int2-cert.pem";
    const char* client_cert = "./certs/intermediate/client-int-cert.pem";
#else
    const char* ca_cert = "./certs/ca-cert.der";
    const char* int1_cert = "./certs/intermediate/ca-int-cert.der";
    const char* int2_cert = "./certs/intermediate/ca-int2-cert.der";
    const char* client_cert = "./certs/intermediate/client-int-cert.der";
#endif
    byte* ca_cert_buf = NULL;
    byte* int1_cert_buf = NULL;
    byte* int2_cert_buf = NULL;
    byte* client_cert_buf = NULL;
    size_t ca_cert_sz = 0;
    size_t int1_cert_sz = 0;
    size_t int2_cert_sz = 0;
    size_t client_cert_sz = 0;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(load_file(ca_cert, &ca_cert_buf, &ca_cert_sz), 0);
    ExpectIntEQ(load_file(int1_cert, &int1_cert_buf, &int1_cert_sz), 0);
    ExpectIntEQ(load_file(int2_cert, &int2_cert_buf, &int2_cert_sz), 0);
    ExpectIntEQ(load_file(client_cert, &client_cert_buf, &client_cert_sz), 0);

    ExpectIntNE(wolfSSL_CertManagerLoadCABufferType(cm, ca_cert_buf,
        (sword32)ca_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, 0), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerLoadCABufferType(cm, ca_cert_buf,
        (sword32)ca_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, 5), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, ca_cert_buf,
        (sword32)ca_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_USER_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, int1_cert_buf,
        (sword32)int1_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, int2_cert_buf,
        (sword32)int2_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, client_cert_buf,
        (sword32)client_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);

    /* Intermediate certs have been unloaded, but CA cert is still
       loaded.  Expect first level intermediate to verify, rest to fail. */
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, int1_cert_buf,
        (sword32)int1_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_TEMP_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, int2_cert_buf,
        (sword32)int2_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_CHAIN_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectIntEQ(wolfSSL_CertManagerLoadCABufferType(cm, client_cert_buf,
        (sword32)client_cert_sz, CERT_FILETYPE, 0,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_USER_INTER),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_CHAIN_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_TEMP_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_CertManagerUnloadTypeCerts(cm, WOLFSSL_USER_CA),
        WOLFSSL_SUCCESS);
#if (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
    defined(OPENSSL_EXTRA)
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, int1_cert_buf,
        int1_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, int2_cert_buf,
        int2_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(cm, client_cert_buf,
        client_cert_sz, CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif

    if (cm)
        wolfSSL_CertManagerFree(cm);
    if (ca_cert_buf)
        free(ca_cert_buf);
    if (int1_cert_buf)
        free(int1_cert_buf);
    if (int2_cert_buf)
        free(int2_cert_buf);
    if (client_cert_buf)
        free(client_cert_buf);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerGetCerts(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
     defined(WOLFSSL_SIGNER_DER_CERT)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_STACK* sk = NULL;
    X509* x509 = NULL;
    X509* cert1 = NULL;
    FILE* file1 = NULL;
#ifdef DEBUG_WOLFSSL_VERBOSE
    WOLFSSL_BIO* bio = NULL;
#endif
    int i = 0;
    int ret = 0;
    const byte* der = NULL;
    int derSz = 0;

    ExpectNotNull(file1 = fopen("./certs/ca-cert.pem", "rb"));

    ExpectNotNull(cert1 = wolfSSL_PEM_read_X509(file1, NULL, NULL, NULL));
    if (file1 != NULL) {
        fclose(file1);
    }

    ExpectNull(sk = wolfSSL_CertManagerGetCerts(NULL));
    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));
    ExpectNull(sk = wolfSSL_CertManagerGetCerts(cm));

    ExpectNotNull(der = wolfSSL_X509_get_der(cert1, &derSz));
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    /* Check that ASN_SELF_SIGNED_E is returned for a self-signed cert for QT
     * and full OpenSSL compatibility */
    ExpectIntEQ(ret = wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E));
#else
    ExpectIntEQ(ret = wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
#endif

    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CertManagerLoadCA(cm,
                "./certs/ca-cert.pem", NULL));

    ExpectNotNull(sk = wolfSSL_CertManagerGetCerts(cm));

    for (i = 0; EXPECT_SUCCESS() && i < sk_X509_num(sk); i++) {
        ExpectNotNull(x509 = sk_X509_value(sk, i));
        ExpectIntEQ(0, wolfSSL_X509_cmp(x509, cert1));

#ifdef DEBUG_WOLFSSL_VERBOSE
        bio = BIO_new(wolfSSL_BIO_s_file());
        if (bio != NULL) {
            BIO_set_fp(bio, stderr, BIO_NOCLOSE);
            X509_print(bio, x509);
            BIO_free(bio);
        }
#endif /* DEBUG_WOLFSSL_VERBOSE */
    }
    wolfSSL_X509_free(cert1);
    sk_X509_pop_free(sk, NULL);
    wolfSSL_CertManagerFree(cm);
#endif /* defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
          !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
          defined(WOLFSSL_SIGNER_DER_CERT) */

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerSetVerify(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    WOLFSSL_CERT_MANAGER* cm = NULL;
    int tmp = myVerifyAction;
#ifdef WOLFSSL_PEM_TO_DER
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* expiredCert = "./certs/test/expired/expired-cert.pem";
#else
    const char* ca_cert = "./certs/ca-cert.der";
    const char* expiredCert = "./certs/test/expired/expired-cert.der";
#endif

    wolfSSL_CertManagerSetVerify(NULL, NULL);
    wolfSSL_CertManagerSetVerify(NULL, myVerify);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());

    wolfSSL_CertManagerSetVerify(cm, myVerify);

#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, ca_cert, NULL), -1);
#else
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, ca_cert, NULL),
                WOLFSSL_SUCCESS);
#endif
    /* Use the test CB that always accepts certs */
    myVerifyAction = VERIFY_OVERRIDE_ERROR;

    ExpectIntEQ(wolfSSL_CertManagerVerify(cm, expiredCert,
        CERT_FILETYPE), WOLFSSL_SUCCESS);

#ifdef WOLFSSL_ALWAYS_VERIFY_CB
    {
        const char* verifyCert = "./certs/server-cert.der";
        /* Use the test CB that always fails certs */
        myVerifyAction = VERIFY_FORCE_FAIL;

        ExpectIntEQ(wolfSSL_CertManagerVerify(cm, verifyCert,
            WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(VERIFY_CERT_ERROR));
    }
#endif

    wolfSSL_CertManagerFree(cm);
    myVerifyAction = tmp;
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerNameConstraint(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_ALT_NAMES) && \
    !defined(NO_SHA256)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_EVP_PKEY *priv = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    const char* ca_cert = "./certs/test/cert-ext-nc.der";
    const char* server_cert = "./certs/test/server-goodcn.pem";
    int i = 0;
    static const byte extNameConsOid[] = {85, 29, 30};

    RsaKey  key;
    WC_RNG  rng;
    byte    *der = NULL;
    int     derSz = 0;
    word32  idx = 0;
    byte    *pt;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;

    wc_InitRng(&rng);

    /* load in CA private key for signing */
    ExpectIntEQ(wc_InitRsaKey_ex(&key, HEAP_HINT, testDevId), 0);
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &key,
                sizeof_server_key_der_2048), 0);

    /* get ca certificate then alter it */
    ExpectNotNull(der =
            (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull(pt = (byte*)wolfSSL_X509_get_tbs(x509, &derSz));
    if (EXPECT_SUCCESS() && (der != NULL)) {
        XMEMCPY(der, pt, (size_t)derSz);

        /* find the name constraint extension and alter it */
        pt = der;
        for (i = 0; i < derSz - 3; i++) {
            if (XMEMCMP(pt, extNameConsOid, 3) == 0) {
                pt += 3;
                break;
            }
            pt++;
        }
        ExpectIntNE(i, derSz - 3); /* did not find OID if this case is hit */

        /* go to the length value and set it to 0 */
        while (i < derSz && *pt != 0x81) {
            pt++;
            i++;
        }
        ExpectIntNE(i, derSz); /* did not place to alter */
        pt++;
        *pt = 0x00;
    }

    /* resign the altered certificate */
    ExpectIntGT((derSz = wc_SignCert(derSz, CTC_SHA256wRSA, der,
                             FOURK_BUF, &key, NULL, &rng)), 0);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_PARSE_E));
    wolfSSL_CertManagerFree(cm);

    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_X509_free(x509);
    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);

    /* add email alt name to satisfy constraint */
    pt = (byte*)server_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                (const unsigned char**)&pt, sizeof_server_key_der_2048));

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(ca, &derSz)));
    DEBUG_WRITE_DER(der, derSz, "ca.der");

    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* Good cert test with proper alt email name */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                    (byte*)"support@info.wolfssl.com", 24, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "wolfssl@info.wolfssl.com", ASN_RFC822_TYPE);

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;


    /* Cert with bad alt name list */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                    (byte*)"support@info.wolfssl.com", 24, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);

    wolfSSL_X509_add_altname(x509, "wolfssl@info.com", ASN_RFC822_TYPE);
    wolfSSL_X509_add_altname(x509, "wolfssl@info.wolfssl.com", ASN_RFC822_TYPE);

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));

    wolfSSL_CertManagerFree(cm);
    wolfSSL_X509_free(x509);
    wolfSSL_X509_free(ca);
    wolfSSL_EVP_PKEY_free(priv);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerNameConstraint2(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_ALT_NAMES)
    const char* ca_cert  = "./certs/test/cert-ext-ndir.der";
    const char* ca_cert2 = "./certs/test/cert-ext-ndir-exc.der";
    const char* server_cert = "./certs/server-cert.pem";
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;

    const unsigned char *der = NULL;
    const unsigned char *pt;
    WOLFSSL_EVP_PKEY *priv = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    int   derSz = 0;

    /* C=US*/
    char altName[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53
    };

    /* C=ID */
    char altNameFail[] = {
        0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x44
    };

    /* C=US ST=California*/
    char altNameExc[] = {
        0x30, 0x22,
        0x31, 0x0B,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
        0x31, 0x13,
        0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A,
        0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61
    };
    /* load in CA private key for signing */
    pt = ca_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pt,
                                                sizeof_ca_key_der_2048));

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull((der = wolfSSL_X509_get_der(ca, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* Test no name case. */
    ExpectIntEQ(wolfSSL_X509_add_altname_ex(x509, NULL, 0, ASN_DIR_TYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_altname(x509, "", ASN_DIR_TYPE),
        WOLFSSL_SUCCESS);
    /* IP not supported unless WOLFSSL_IP_ALT_NAME is enabled. */
#ifdef WOLFSSL_IP_ALT_NAME
    ExpectIntEQ(wolfSSL_X509_add_altname(x509, "127.0.0.1", ASN_IP_TYPE),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(wolfSSL_X509_add_altname(x509, "127.0.0.1", ASN_IP_TYPE),
        WOLFSSL_FAILURE);
#endif

    /* add in matching DIR alt name and resign */
    wolfSSL_X509_add_altname_ex(x509, altName, sizeof(altName), ASN_DIR_TYPE);
#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif

    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check verify fail */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);

    /* add in miss matching DIR alt name and resign */
    wolfSSL_X509_add_altname_ex(x509, altNameFail, sizeof(altNameFail),
            ASN_DIR_TYPE);

#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
#ifndef WOLFSSL_NO_ASN_STRICT
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
#else
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
#endif

    /* check that it still fails if one bad altname and one good altname is in
     * the certificate */
    wolfSSL_X509_free(x509);
    x509 = NULL;
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    wolfSSL_X509_add_altname_ex(x509, altName, sizeof(altName), ASN_DIR_TYPE);
    wolfSSL_X509_add_altname_ex(x509, altNameFail, sizeof(altNameFail),
            ASN_DIR_TYPE);

#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
#ifndef WOLFSSL_NO_ASN_STRICT
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
#else
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
#endif

    /* check it fails with switching position of bad altname */
    wolfSSL_X509_free(x509);
    x509 = NULL;
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    wolfSSL_X509_add_altname_ex(x509, altNameFail, sizeof(altNameFail),
            ASN_DIR_TYPE);
    wolfSSL_X509_add_altname_ex(x509, altName, sizeof(altName), ASN_DIR_TYPE);

#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
#ifndef WOLFSSL_NO_ASN_STRICT
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
#else
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
#endif
    wolfSSL_CertManagerFree(cm);

    wolfSSL_X509_free(x509);
    x509 = NULL;
    wolfSSL_X509_free(ca);
    ca = NULL;

    /* now test with excluded name constraint */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert2,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull((der = wolfSSL_X509_get_der(ca, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    wolfSSL_X509_add_altname_ex(x509, altNameExc, sizeof(altNameExc),
            ASN_DIR_TYPE);
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);

#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_NOSHA3_256)
    wolfSSL_X509_sign(x509, priv, EVP_sha3_256());
#else
    wolfSSL_X509_sign(x509, priv, EVP_sha256());
#endif
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));
#ifndef WOLFSSL_NO_ASN_STRICT
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
#else
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
#endif
    wolfSSL_CertManagerFree(cm);
    wolfSSL_X509_free(x509);
    wolfSSL_X509_free(ca);
    wolfSSL_EVP_PKEY_free(priv);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerNameConstraint3(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_ALT_NAMES) && \
    !defined(NO_SHA256)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_EVP_PKEY *priv = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    const char* ca_cert = "./certs/test/cert-ext-mnc.der";
    const char* server_cert = "./certs/test/server-goodcn.pem";

    byte    *der = NULL;
    int     derSz = 0;
    byte    *pt;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;

    pt = (byte*)server_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                (const unsigned char**)&pt, sizeof_server_key_der_2048));

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(ca, &derSz)));
    DEBUG_WRITE_DER(der, derSz, "ca.der");

    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* check satisfying .wolfssl.com constraint passes */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                    (byte*)"support@info.wolfssl.com", 24, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "wolfssl@info.wolfssl.com", ASN_RFC822_TYPE);

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-1st-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check satisfying .random.com constraint passes */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                    (byte*)"support@info.example.com", 24, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "wolfssl@info.example.com", ASN_RFC822_TYPE);

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-2nd-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check fail case when neither constraint is matched */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                     (byte*)"support@info.com", 16, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);

    wolfSSL_X509_add_altname(x509, "wolfssl@info.com", ASN_RFC822_TYPE);

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));

    wolfSSL_CertManagerFree(cm);
    wolfSSL_X509_free(x509);
    wolfSSL_X509_free(ca);
    wolfSSL_EVP_PKEY_free(priv);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerNameConstraint4(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_ALT_NAMES) && \
    !defined(NO_SHA256)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_EVP_PKEY *priv = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    const char* ca_cert = "./certs/test/cert-ext-ncdns.der";
    const char* server_cert = "./certs/test/server-goodcn.pem";

    byte    *der = NULL;
    int     derSz;
    byte    *pt;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;

    pt = (byte*)server_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                (const unsigned char**)&pt, sizeof_server_key_der_2048));

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(ca, &derSz)));
    DEBUG_WRITE_DER(der, derSz, "ca.der");

    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* check satisfying wolfssl.com constraint passes */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "www.wolfssl.com", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-1st-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check satisfying example.com constraint passes */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"example.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "www.example.com", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-2nd-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check satisfying wolfssl.com constraint passes with list of DNS's */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "www.wolfssl.com", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "www.info.wolfssl.com", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "extra.wolfssl.com", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-multiple-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check fail when one DNS in the list is bad */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "www.wolfssl.com", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "www.nomatch.com", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "www.info.wolfssl.com", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-multiple-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* check fail case when neither constraint is matched */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"common", 6, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);

    wolfSSL_X509_add_altname(x509, "www.random.com", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));

    wolfSSL_CertManagerFree(cm);
    wolfSSL_X509_free(x509);
    wolfSSL_X509_free(ca);
    wolfSSL_EVP_PKEY_free(priv);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerNameConstraint5(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_RSA) && \
    defined(OPENSSL_EXTRA) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_ALT_NAMES) && \
    !defined(NO_SHA256)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    WOLFSSL_EVP_PKEY *priv = NULL;
    WOLFSSL_X509_NAME* name = NULL;
    const char* ca_cert = "./certs/test/cert-ext-ncmixed.der";
    const char* server_cert = "./certs/test/server-goodcn.pem";

    byte    *der = NULL;
    int     derSz;
    byte    *pt;
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;

    pt = (byte*)server_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                (const unsigned char**)&pt, sizeof_server_key_der_2048));

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(ca_cert,
                WOLFSSL_FILETYPE_ASN1));
    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(ca, &derSz)));
    DEBUG_WRITE_DER(der, derSz, "ca.der");

    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* check satisfying wolfssl.com constraint passes */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"example", 7, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "good.example", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "facts@into.wolfssl.com", ASN_RFC822_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* fail with DNS check because of common name */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "example", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "facts@wolfssl.com", ASN_RFC822_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-cn-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* fail on permitted DNS name constraint */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "www.example", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "www.wolfssl", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "info@wolfssl.com", ASN_RFC822_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-1st-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* fail on permitted email name constraint */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;

    wolfSSL_X509_add_altname(x509, "example", ASN_DNS_TYPE);
    wolfSSL_X509_add_altname(x509, "info@wolfssl.com", ASN_RFC822_TYPE);
    wolfSSL_X509_add_altname(x509, "info@example.com", ASN_RFC822_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "bad-2nd-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(ASN_NAME_INVALID_E));
    wolfSSL_X509_free(x509);
    x509 = NULL;

    /* success with empty email name */
    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(server_cert,
                WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);
    name = NULL;

    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name), WOLFSSL_SUCCESS);
    X509_NAME_free(name);

    wolfSSL_X509_add_altname(x509, "example", ASN_DNS_TYPE);
    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    DEBUG_WRITE_CERT_X509(x509, "good-missing-constraint-cert.pem");

    ExpectNotNull((der = (byte*)wolfSSL_X509_get_der(x509, &derSz)));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(x509);

    wolfSSL_CertManagerFree(cm);
    wolfSSL_X509_free(ca);
    wolfSSL_EVP_PKEY_free(priv);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerCRL(void)
{
    EXPECT_DECLS;
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && defined(HAVE_CRL) && \
    !defined(NO_RSA)
    const char* ca_cert = "./certs/ca-cert.pem";
    const char* crl1     = "./certs/crl/crl.pem";
    const char* crl2     = "./certs/crl/crl2.pem";
#ifdef WC_RSA_PSS
    const char* crl_rsapss = "./certs/crl/crl_rsapss.pem";
    const char* ca_rsapss  = "./certs/rsapss/ca-rsapss.pem";
#endif
    /* ./certs/crl/crl.der */
    const unsigned char crl_buff[] = {
        0x30, 0x82, 0x02, 0x04, 0x30, 0x81, 0xED, 0x02,
        0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
        0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
        0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55,
        0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74,
        0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F,
        0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30,
        0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08,
        0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74, 0x68,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
        0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73, 0x75,
        0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18, 0x30,
        0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F,
        0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66,
        0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
        0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48,
        0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x10,
        0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D,
        0x17, 0x0D, 0x32, 0x34, 0x30, 0x31, 0x30, 0x39,
        0x30, 0x30, 0x33, 0x34, 0x33, 0x30, 0x5A, 0x17,
        0x0D, 0x32, 0x36, 0x31, 0x30, 0x30, 0x35, 0x30,
        0x30, 0x33, 0x34, 0x33, 0x30, 0x5A, 0x30, 0x14,
        0x30, 0x12, 0x02, 0x01, 0x02, 0x17, 0x0D, 0x32,
        0x34, 0x30, 0x31, 0x30, 0x39, 0x30, 0x30, 0x33,
        0x34, 0x33, 0x30, 0x5A, 0xA0, 0x0E, 0x30, 0x0C,
        0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x14, 0x04,
        0x03, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
        0xB3, 0x6F, 0xED, 0x72, 0xD2, 0x73, 0x6A, 0x77,
        0xBF, 0x3A, 0x55, 0xBC, 0x54, 0x18, 0x6A, 0x71,
        0xBC, 0x6A, 0xCC, 0xCD, 0x5D, 0x90, 0xF5, 0x64,
        0x8D, 0x1B, 0xF0, 0xE0, 0x48, 0x7B, 0xF2, 0x7B,
        0x06, 0x86, 0x53, 0x63, 0x9B, 0xD8, 0x24, 0x15,
        0x10, 0xB1, 0x19, 0x96, 0x9B, 0xD2, 0x75, 0xA8,
        0x25, 0xA2, 0x35, 0xA9, 0x14, 0xD6, 0xD5, 0x5E,
        0x53, 0xE3, 0x34, 0x9D, 0xF2, 0x8B, 0x07, 0x19,
        0x9B, 0x1F, 0xF1, 0x02, 0x0F, 0x04, 0x46, 0xE8,
        0xB8, 0xB6, 0xF2, 0x8D, 0xC7, 0xC0, 0x15, 0x3E,
        0x3E, 0x8E, 0x96, 0x73, 0x15, 0x1E, 0x62, 0xF6,
        0x4E, 0x2A, 0xF7, 0xAA, 0xA0, 0x91, 0x80, 0x12,
        0x7F, 0x81, 0x0C, 0x65, 0xCC, 0x38, 0xBE, 0x58,
        0x6C, 0x14, 0xA5, 0x21, 0xA1, 0x8D, 0xF7, 0x8A,
        0xB9, 0x24, 0xF4, 0x2D, 0xCA, 0xC0, 0x67, 0x43,
        0x0B, 0xC8, 0x1C, 0xB4, 0x7D, 0x12, 0x7F, 0xA2,
        0x1B, 0x19, 0x0E, 0x94, 0xCF, 0x7B, 0x9F, 0x75,
        0xA0, 0x08, 0x9A, 0x67, 0x3F, 0x87, 0x89, 0x3E,
        0xF8, 0x58, 0xA5, 0x8A, 0x1B, 0x2D, 0xDA, 0x9B,
        0xD0, 0x1B, 0x18, 0x92, 0xC3, 0xD2, 0x6A, 0xD7,
        0x1C, 0xFC, 0x45, 0x69, 0x77, 0xC3, 0x57, 0x65,
        0x75, 0x99, 0x9E, 0x47, 0x2A, 0x20, 0x25, 0xEF,
        0x90, 0xF2, 0x5F, 0x3B, 0x7D, 0x9C, 0x7D, 0x00,
        0xEA, 0x92, 0x54, 0xEB, 0x0B, 0xE7, 0x17, 0xAF,
        0x24, 0x1A, 0xF9, 0x7C, 0x83, 0x50, 0x68, 0x1D,
        0xDC, 0x5B, 0x60, 0x12, 0xA7, 0x52, 0x78, 0xD9,
        0xA9, 0xB0, 0x1F, 0x59, 0x48, 0x36, 0xC7, 0xA6,
        0x97, 0x34, 0xC7, 0x87, 0x3F, 0xAE, 0xFD, 0xA9,
        0x56, 0x5D, 0x48, 0xCC, 0x89, 0x7A, 0x79, 0x60,
        0x8F, 0x9B, 0x2B, 0x63, 0x3C, 0xB3, 0x04, 0x1D,
        0x5F, 0xF7, 0x20, 0xD2, 0xFD, 0xF2, 0x51, 0xB1,
        0x96, 0x93, 0x13, 0x5B, 0xAB, 0x74, 0x82, 0x8B
    };

    WOLFSSL_CERT_MANAGER* cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());

    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECKALL), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECK), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm,
        WOLFSSL_CRL_CHECK | WOLFSSL_CRL_CHECKALL), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, 16), 1);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECKALL), 1);

    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(NULL, NULL, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, NULL, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(NULL, server_cert_der_2048, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(NULL, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(NULL, server_cert_der_2048, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, server_cert_der_2048, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, server_cert_der_2048,
        sizeof_server_cert_der_2048), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));

    ExpectIntEQ(wolfSSL_CertManagerSetCRL_Cb(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerSetCRL_Cb(cm, NULL), 1);
#ifdef HAVE_CRL_IO
    ExpectIntEQ(wolfSSL_CertManagerSetCRL_IOCb(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerSetCRL_IOCb(cm, NULL), 1);
#endif

#ifndef NO_FILESYSTEM
    ExpectIntEQ(wolfSSL_CertManagerLoadCRL(NULL, NULL, WOLFSSL_FILETYPE_ASN1,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRL(cm, NULL, WOLFSSL_FILETYPE_ASN1,
        0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* -1 seen as !WOLFSSL_FILETYPE_PEM */
    ExpectIntEQ(wolfSSL_CertManagerLoadCRL(cm, "./certs/crl", -1, 0), 1);

    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(NULL, NULL,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, NULL, WOLFSSL_FILETYPE_ASN1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* -1 seen as !WOLFSSL_FILETYPE_PEM */
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, "./certs/crl/crl.pem", -1),
        WC_NO_ERR_TRACE(ASN_PARSE_E));
#endif

    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(NULL, NULL, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(cm, NULL, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(NULL, crl_buff, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(NULL, NULL, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(NULL, crl_buff, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(cm, NULL, 1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(cm, crl_buff, -1,
        WOLFSSL_FILETYPE_ASN1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wolfSSL_CertManagerFreeCRL(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    DoExpectIntEQ(wolfSSL_CertManagerFreeCRL(cm), 1);

    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCA(cm, ca_cert, NULL));
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCRL(cm, crl1, WOLFSSL_FILETYPE_PEM, 0));
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCRL(cm, crl2, WOLFSSL_FILETYPE_PEM, 0));
    wolfSSL_CertManagerFreeCRL(cm);

#ifndef WOLFSSL_CRL_ALLOW_MISSING_CDP
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCRL(cm, crl1, WOLFSSL_FILETYPE_PEM, 0));
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCA(cm, ca_cert, NULL));
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, server_cert_der_2048,
        sizeof_server_cert_der_2048), WC_NO_ERR_TRACE(CRL_MISSING));
    ExpectIntEQ(wolfSSL_CertManagerVerifyBuffer(cm, server_cert_der_2048,
        sizeof_server_cert_der_2048, WOLFSSL_FILETYPE_ASN1),
        WC_NO_ERR_TRACE(CRL_MISSING));
#endif /* !WOLFSSL_CRL_ALLOW_MISSING_CDP */

    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(cm, crl_buff, sizeof(crl_buff),
        WOLFSSL_FILETYPE_ASN1), 1);

#if !defined(NO_FILESYSTEM) && defined(WC_RSA_PSS)
    /* loading should fail without the CA set */
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, crl_rsapss,
        WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E));

    /* now successfully load the RSA-PSS crl once loading in it's CA */
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCA(cm, ca_rsapss, NULL));
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLFile(cm, crl_rsapss,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
#endif

    wolfSSL_CertManagerFree(cm);
#endif

    return EXPECT_RESULT();
}

int test_wolfSSL_CRL_static_revoked_list(void)
{
    EXPECT_DECLS;
#if defined(CRL_STATIC_REVOKED_LIST) && defined(HAVE_CRL) && \
    !defined(NO_RSA) && !defined(NO_CERTS)
    /* CRL signed by certs/ca-cert.pem that revokes serials 05, 02, 01 in that
     * (unsorted) wire order. The unsorted order exposes a binary search bug in
     * FindRevokedSerial when CRL_STATIC_REVOKED_LIST is enabled: the revoked
     * cert array is never sorted after parsing, so binary search misses entries
     * that are out of order.
     *
     * Generated with Python cryptography library:
     *   builder.add_revoked_certificate(serial=5)
     *   builder.add_revoked_certificate(serial=2)
     *   builder.add_revoked_certificate(serial=1)
     *   crl = builder.sign(ca_key, hashes.SHA256())
     */
    static const unsigned char crl_multi_revoked[] = {
        0x30, 0x82, 0x02, 0x1D, 0x30, 0x82, 0x01, 0x05,
        0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        0x05, 0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30,
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E,
        0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11,
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C,
        0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74,
        0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x0B, 0x0C, 0x0A, 0x43, 0x6F, 0x6E, 0x73,
        0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
        0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C,
        0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D,
        0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
        0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
        0x17, 0x0D, 0x33, 0x36, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30,
        0x3C, 0x30, 0x12, 0x02, 0x01, 0x05, 0x17, 0x0D,
        0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x12, 0x02,
        0x01, 0x02, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x32,
        0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5A, 0x30, 0x12, 0x02, 0x01, 0x01, 0x17, 0x0D,
        0x32, 0x33, 0x30, 0x33, 0x30, 0x31, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x0D, 0x06,
        0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01,
        0x00, 0x15, 0x9F, 0xC1, 0x9E, 0x17, 0xB3, 0x5A,
        0xF1, 0x48, 0xA5, 0x87, 0x2A, 0x84, 0xD1, 0x93,
        0x8D, 0x19, 0x24, 0xCB, 0xC5, 0x32, 0x56, 0x10,
        0x6C, 0x4D, 0xF5, 0xD1, 0x9A, 0xC0, 0x1A, 0x8B,
        0x1C, 0x84, 0x6B, 0x4B, 0x20, 0xA7, 0xA4, 0x2C,
        0x11, 0x5C, 0x23, 0xBD, 0x0C, 0xB1, 0x33, 0xBE,
        0x38, 0x1B, 0xCB, 0xDB, 0x8E, 0xD4, 0x0F, 0x62,
        0x0D, 0xB5, 0x18, 0x21, 0x28, 0x0B, 0x77, 0xB9,
        0xB4, 0xA8, 0xE9, 0xA0, 0x25, 0x00, 0x83, 0xED,
        0x64, 0x49, 0x8E, 0x52, 0xD9, 0x8D, 0xAF, 0xC2,
        0x16, 0x3E, 0xD3, 0x93, 0x09, 0xB9, 0x18, 0xBB,
        0x6C, 0x41, 0xDF, 0x59, 0x59, 0x53, 0x8C, 0x64,
        0x8B, 0xD1, 0x9D, 0xBB, 0x92, 0x8F, 0xB2, 0x26,
        0x27, 0x78, 0x41, 0xFB, 0xF8, 0xB1, 0x2F, 0x8F,
        0xA1, 0x85, 0xB6, 0xC7, 0x8E, 0x42, 0x72, 0xEF,
        0xF4, 0x3F, 0xC4, 0xAF, 0x40, 0x95, 0xCA, 0x94,
        0xE5, 0x88, 0x89, 0x18, 0x32, 0x54, 0xC3, 0xC4,
        0xBE, 0x7E, 0x48, 0x1B, 0x3D, 0xB3, 0x6C, 0x11,
        0x54, 0x6F, 0x9E, 0xFE, 0x09, 0x5B, 0x72, 0x3F,
        0xD7, 0xA0, 0x02, 0xFF, 0x43, 0x01, 0xFE, 0x23,
        0xF8, 0x72, 0xCD, 0xA9, 0x76, 0x36, 0x31, 0x78,
        0x21, 0xCB, 0x0E, 0xC2, 0x25, 0x8D, 0x0B, 0x4C,
        0x2C, 0xAA, 0x6A, 0x80, 0x6E, 0xE2, 0x1E, 0xAC,
        0x70, 0x5D, 0x4A, 0xAA, 0x56, 0x17, 0xF0, 0x2D,
        0xA2, 0x2A, 0x4E, 0x2B, 0xC8, 0xC9, 0x87, 0x8E,
        0x07, 0xEB, 0xD8, 0x36, 0x42, 0x39, 0xA0, 0xA4,
        0xF6, 0x34, 0xC2, 0x5F, 0xE1, 0x21, 0x07, 0x50,
        0x4B, 0x37, 0x15, 0x7D, 0xF9, 0x18, 0x54, 0x13,
        0xC0, 0x1D, 0x0A, 0x27, 0x3A, 0x63, 0xD2, 0xC3,
        0xD5, 0x57, 0x5E, 0x67, 0x56, 0x65, 0x9E, 0x2E,
        0x4D, 0xB4, 0x96, 0x54, 0x7A, 0x3D, 0xFD, 0xF9,
        0xCF, 0xCD, 0x10, 0x65, 0x05, 0x97, 0x53, 0x72,
        0x12
    };
    WOLFSSL_CERT_MANAGER* cm = NULL;

    /* Set up CertManager with the CA and CRL checking enabled */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, "./certs/ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);

    /* Load the CRL that revokes serials {05, 02, 01} in unsorted wire order */
    ExpectIntEQ(wolfSSL_CertManagerLoadCRLBuffer(cm, crl_multi_revoked,
        sizeof(crl_multi_revoked), WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);

    /* server-cert.pem has serial 01, which is in the CRL but at the last
     * position in the unsorted array. Binary search on unsorted data misses
     * it, so this assertion fails before the bug fix. */
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, server_cert_der_2048,
        sizeof_server_cert_der_2048), WC_NO_ERR_TRACE(CRL_CERT_REVOKED));

    wolfSSL_CertManagerFree(cm);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CRL_duplicate_extensions(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_CERTS) && \
    defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(WOLFSSL_NO_ASN_STRICT) && \
    (defined(WC_ASN_RUNTIME_DATE_CHECK_CONTROL) || defined(NO_ASN_TIME_CHECK))
    const unsigned char crl_duplicate_akd[] =
        "-----BEGIN X509 CRL-----\n"
        "MIICCDCB8QIBATANBgkqhkiG9w0BAQsFADB5MQswCQYDVQQGEwJVUzETMBEGA1UE\n"
        "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEGA1UECgwK\n"
        "TXkgQ29tcGFueTETMBEGA1UEAwwKTXkgUm9vdCBDQTETMBEGA1UECwwKTXkgUm9v\n"
        "dCBDQRcNMjQwOTAxMDAwMDAwWhcNMjUxMjAxMDAwMDAwWqBEMEIwHwYDVR0jBBgw\n"
        "FoAU72ng99Ud5pns3G3Q9+K5XGRxgzUwHwYDVR0jBBgwFoAU72ng99Ud5pns3G3Q\n"
        "9+K5XGRxgzUwDQYJKoZIhvcNAQELBQADggEBAIFVw4jrS4taSXR/9gPzqGrqFeHr\n"
        "IXCnFtHJTLxqa8vUOAqSwqysvNpepVKioMVoGrLjFMjANjWQqTEiMROAnLfJ/+L8\n"
        "FHZkV/mZwOKAXMhIC9MrJzifxBICwmvD028qnwQm09EP8z4ICZptD6wPdRTDzduc\n"
        "KBuAX+zn8pNrJgyrheRKpPgno9KsbCzK4D/RIt1sTK2M3vVOtY+vpsN70QYUXvQ4\n"
        "r2RZac3omlT43x5lddPxIlcouQpwWcVvr/K+Va770MRrjn88PBrJmvsEw/QYVBXp\n"
        "Gxv2b78HFDacba80sMIm8ltRdqUCa5qIc6OATsz7izCQXEbkTEeESrcK1MA=\n"
        "-----END X509 CRL-----\n";

    WOLFSSL_CERT_MANAGER* cm = NULL;
    int ret;

    (void)wc_AsnSetSkipDateCheck(1);

    cm = wolfSSL_CertManagerNew();
    ExpectNotNull(cm);

    /* Test loading CRL with duplicate extensions */
    WOLFSSL_MSG("Testing CRL with duplicate Authority Key Identifier "
                "extensions");
    ret = wolfSSL_CertManagerLoadCRLBuffer(cm, crl_duplicate_akd,
                                           sizeof(crl_duplicate_akd),
                                           WOLFSSL_FILETYPE_PEM);
    ExpectIntEQ(ret, ASN_PARSE_E);

    wolfSSL_CertManagerFree(cm);

    (void)wc_AsnSetSkipDateCheck(0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CertManagerCheckOCSPResponse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && !defined(NO_RSA) && !defined(NO_SHA)
/* Need one of these for wolfSSL_OCSP_REQUEST_new. */
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_APACHE_HTTPD) || \
    defined(HAVE_LIGHTY)
    WOLFSSL_CERT_MANAGER* cm = NULL;
    /* Raw OCSP response bytes captured using the following setup:
     * - Run responder with
     *      openssl ocsp -port 9999 -ndays 9999
     *      -index certs/ocsp/index-intermediate1-ca-issued-certs.txt
     *      -rsigner certs/ocsp/ocsp-responder-cert.pem
     *      -rkey certs/ocsp/ocsp-responder-key.pem
     *      -CA certs/ocsp/intermediate1-ca-cert.pem
     * - Run client with
     *      openssl ocsp -host 127.0.0.1:9999 -respout resp.out
     *      -issuer certs/ocsp/intermediate1-ca-cert.pem
     *      -cert certs/ocsp/server1-cert.pem
     *      -CAfile certs/ocsp/root-ca-cert.pem -noverify
     * - Select the response packet in Wireshark, and export it using
     *   "File->Export Packet Dissection->As "C" Arrays".  Select "Selected
     *   packets only".  After importing into the editor, remove the initial
     *   ~148 bytes of header, ending with the Content-Length and the \r\n\r\n.
     */
    static const byte response[] = {
        0x30, 0x82, 0x07, 0x40, /* ....0..@ */
        0x0a, 0x01, 0x00, 0xa0, 0x82, 0x07, 0x39, 0x30, /* ......90 */
        0x82, 0x07, 0x35, 0x06, 0x09, 0x2b, 0x06, 0x01, /* ..5..+.. */
        0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, /* ...0.... */
        0x07, 0x26, 0x30, 0x82, 0x07, 0x22, 0x30, 0x82, /* .&0.."0. */
        0x01, 0x40, 0xa1, 0x81, 0xa1, 0x30, 0x81, 0x9e, /* .@...0.. */
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, /* 1.0...U. */
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, /* ...US1.0 */
        0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, /* ...U.... */
        0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, /* Washingt */
        0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, /* on1.0... */
        0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, /* U....Sea */
        0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, /* ttle1.0. */
        0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, /* ..U....w */
        0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, /* olfSSL1. */
        0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, /* 0...U... */
        0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, /* .Enginee */
        0x72, 0x69, 0x6e, 0x67, 0x31, 0x1f, 0x30, 0x1d, /* ring1.0. */
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x77, /* ..U....w */
        0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x4f, /* olfSSL O */
        0x43, 0x53, 0x50, 0x20, 0x52, 0x65, 0x73, 0x70, /* CSP Resp */
        0x6f, 0x6e, 0x64, 0x65, 0x72, 0x31, 0x1f, 0x30, /* onder1.0 */
        0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, /* ...*.H.. */
        0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, /* ......in */
        0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, /* fo@wolfs */
        0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x18, 0x0f, /* sl.com.. */
        0x32, 0x30, 0x32, 0x34, 0x31, 0x32, 0x32, 0x30, /* 20241220 */
        0x31, 0x37, 0x30, 0x37, 0x30, 0x34, 0x5a, 0x30, /* 170704Z0 */
        0x64, 0x30, 0x62, 0x30, 0x3a, 0x30, 0x09, 0x06, /* d0b0:0.. */
        0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, /* .+...... */
        0x04, 0x14, 0x71, 0x4d, 0x82, 0x23, 0x40, 0x59, /* ..qM.#@Y */
        0xc0, 0x96, 0xa1, 0x37, 0x43, 0xfa, 0x31, 0xdb, /* ...7C.1. */
        0xba, 0xb1, 0x43, 0x18, 0xda, 0x04, 0x04, 0x14, /* ..C..... */
        0x83, 0xc6, 0x3a, 0x89, 0x2c, 0x81, 0xf4, 0x02, /* ..:.,... */
        0xd7, 0x9d, 0x4c, 0xe2, 0x2a, 0xc0, 0x71, 0x82, /* ..L.*.q. */
        0x64, 0x44, 0xda, 0x0e, 0x02, 0x01, 0x05, 0x80, /* dD...... */
        0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x31, /* ...20241 */
        0x32, 0x32, 0x30, 0x31, 0x37, 0x30, 0x37, 0x30, /* 22017070 */
        0x34, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, /* 4Z....20 */
        0x35, 0x32, 0x30, 0x35, 0x30, 0x36, 0x31, 0x37, /* 52050617 */
        0x30, 0x37, 0x30, 0x34, 0x5a, 0xa1, 0x23, 0x30, /* 0704Z.#0 */
        0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, /* !0...+.. */
        0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, /* ...0.... */
        0x04, 0x10, 0x12, 0x7c, 0x27, 0xbd, 0x22, 0x28, /* ...|'."( */
        0x5e, 0x62, 0x81, 0xed, 0x6d, 0x2c, 0x2d, 0x59, /* ^b..m,-Y */
        0x42, 0xd7, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, /* B.0...*. */
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, /* H....... */
        0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6c, 0xce, /* ......l. */
        0xa8, 0xe8, 0xfe, 0xaf, 0x33, 0xe2, 0xce, 0x4e, /* ....3..N */
        0x63, 0x8d, 0x61, 0x16, 0x0f, 0x70, 0xb2, 0x0c, /* c.a..p.. */
        0x9a, 0xe3, 0x01, 0xd5, 0xca, 0xe5, 0x9b, 0x70, /* .......p */
        0x81, 0x6f, 0x94, 0x09, 0xe8, 0x88, 0x98, 0x1a, /* .o...... */
        0x67, 0xa0, 0xc2, 0xe7, 0x8f, 0x9b, 0x5f, 0x13, /* g....._. */
        0x17, 0x8d, 0x93, 0x8c, 0x31, 0x61, 0x7d, 0x72, /* ....1a}r */
        0x34, 0xbd, 0x21, 0x48, 0xca, 0xb2, 0xc9, 0xae, /* 4.!H.... */
        0x28, 0x5f, 0x97, 0x19, 0xcb, 0xdf, 0xed, 0xd4, /* (_...... */
        0x6e, 0x89, 0x30, 0x89, 0x11, 0xd1, 0x05, 0x08, /* n.0..... */
        0x81, 0xe9, 0xa7, 0xba, 0xf7, 0x16, 0x0c, 0xbe, /* ........ */
        0x48, 0x2e, 0xc0, 0x05, 0xac, 0x90, 0xc2, 0x35, /* H......5 */
        0xce, 0x6c, 0x94, 0x5d, 0x2b, 0xad, 0x4f, 0x19, /* .l.]+.O. */
        0xea, 0x7b, 0xd9, 0x4f, 0x49, 0x20, 0x8d, 0x98, /* .{.OI .. */
        0xa9, 0xe4, 0x53, 0x6d, 0xca, 0x34, 0xdb, 0x4a, /* ..Sm.4.J */
        0x28, 0xb3, 0x33, 0xfb, 0xfd, 0xcc, 0x4b, 0xfa, /* (.3...K. */
        0xdb, 0x70, 0xe1, 0x96, 0xc8, 0xd4, 0xf1, 0x85, /* .p...... */
        0x99, 0xaf, 0x06, 0xeb, 0xfd, 0x96, 0x21, 0x86, /* ......!. */
        0x81, 0xee, 0xcf, 0xd2, 0xf4, 0x83, 0xc9, 0x1d, /* ........ */
        0x8f, 0x42, 0xd1, 0xc1, 0xbc, 0x50, 0x0a, 0xfb, /* .B...P.. */
        0x95, 0x39, 0x4c, 0x36, 0xa8, 0xfe, 0x2b, 0x8e, /* .9L6..+. */
        0xc5, 0xb5, 0xe0, 0xab, 0xdb, 0xc0, 0xbf, 0x1d, /* ........ */
        0x35, 0x4d, 0xc0, 0x52, 0xfb, 0x08, 0x04, 0x4c, /* 5M.R...L */
        0x98, 0xf0, 0xb5, 0x5b, 0xff, 0x99, 0x74, 0xce, /* ...[..t. */
        0xb7, 0xc9, 0xe3, 0xe5, 0x70, 0x2e, 0xd3, 0x1d, /* ....p... */
        0x46, 0x38, 0xf9, 0x51, 0x17, 0x73, 0xd1, 0x08, /* F8.Q.s.. */
        0x8d, 0x3d, 0x12, 0x47, 0xd0, 0x66, 0x77, 0xaf, /* .=.G.fw. */
        0xfd, 0x4c, 0x75, 0x1f, 0xe9, 0x6c, 0xf4, 0x5a, /* .Lu..l.Z */
        0xde, 0xec, 0x37, 0xc7, 0xc4, 0x0a, 0xbe, 0x91, /* ..7..... */
        0xbc, 0x05, 0x08, 0x86, 0x47, 0x30, 0x2a, 0xc6, /* ....G0*. */
        0x85, 0x4b, 0x55, 0x6c, 0xef, 0xdf, 0x2d, 0x5a, /* .KUl..-Z */
        0xf7, 0x5b, 0xb5, 0xba, 0xed, 0x38, 0xb0, 0xcb, /* .[...8.. */
        0xeb, 0x7e, 0x84, 0x3a, 0x69, 0x2c, 0xa0, 0x82, /* .~.:i,.. */
        0x04, 0xc6, 0x30, 0x82, 0x04, 0xc2, 0x30, 0x82, /* ..0...0. */
        0x04, 0xbe, 0x30, 0x82, 0x03, 0xa6, 0xa0, 0x03, /* ..0..... */
        0x02, 0x01, 0x02, 0x02, 0x01, 0x04, 0x30, 0x0d, /* ......0. */
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, /* ..*.H... */
        0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x97, /* .....0.. */
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, /* 1.0...U. */
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, /* ...US1.0 */
        0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, /* ...U.... */
        0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, /* Washingt */
        0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, /* on1.0... */
        0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, /* U....Sea */
        0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, /* ttle1.0. */
        0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, /* ..U....w */
        0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, /* olfSSL1. */
        0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, /* 0...U... */
        0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, /* .Enginee */
        0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, /* ring1.0. */
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, /* ..U....w */
        0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x72, /* olfSSL r */
        0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x1f, /* oot CA1. */
        0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, /* 0...*.H. */
        0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, /* .......i */
        0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, 0x66, /* nfo@wolf */
        0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, /* ssl.com0 */
        0x1e, 0x17, 0x0d, 0x32, 0x34, 0x31, 0x32, 0x31, /* ...24121 */
        0x38, 0x32, 0x31, 0x32, 0x35, 0x33, 0x31, 0x5a, /* 8212531Z */
        0x17, 0x0d, 0x32, 0x37, 0x30, 0x39, 0x31, 0x34, /* ..270914 */
        0x32, 0x31, 0x32, 0x35, 0x33, 0x31, 0x5a, 0x30, /* 212531Z0 */
        0x81, 0x9e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, /* ..1.0... */
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, /* U....US1 */
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, /* .0...U.. */
        0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, /* ..Washin */
        0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, /* gton1.0. */
        0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, /* ..U....S */
        0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, /* eattle1. */
        0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, /* 0...U... */
        0x07, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, /* .wolfSSL */
        0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, /* 1.0...U. */
        0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, /* ...Engin */
        0x65, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x1f, /* eering1. */
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, /* 0...U... */
        0x16, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, /* .wolfSSL */
        0x20, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x65, /*  OCSP Re */
        0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x31, /* sponder1 */
        0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, /* .0...*.H */
        0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, /* ........ */
        0x69, 0x6e, 0x66, 0x6f, 0x40, 0x77, 0x6f, 0x6c, /* info@wol */
        0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, /* fssl.com */
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, /* 0.."0... */
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, /* *.H..... */
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, /* ........ */
        0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, /* 0....... */
        0x00, 0xb8, 0xba, 0x23, 0xb4, 0xf6, 0xc3, 0x7b, /* ...#...{ */
        0x14, 0xc3, 0xa4, 0xf5, 0x1d, 0x61, 0xa1, 0xf5, /* .....a.. */
        0x1e, 0x63, 0xb9, 0x85, 0x23, 0x34, 0x50, 0x6d, /* .c..#4Pm */
        0xf8, 0x7c, 0xa2, 0x8a, 0x04, 0x8b, 0xd5, 0x75, /* .|.....u */
        0x5c, 0x2d, 0xf7, 0x63, 0x88, 0xd1, 0x07, 0x7a, /* \-.c...z */
        0xea, 0x0b, 0x45, 0x35, 0x2b, 0xeb, 0x1f, 0xb1, /* ..E5+... */
        0x22, 0xb4, 0x94, 0x41, 0x38, 0xe2, 0x9d, 0x74, /* "..A8..t */
        0xd6, 0x8b, 0x30, 0x22, 0x10, 0x51, 0xc5, 0xdb, /* ..0".Q.. */
        0xca, 0x3f, 0x46, 0x2b, 0xfe, 0xe5, 0x5a, 0x3f, /* .?F+..Z? */
        0x41, 0x74, 0x67, 0x75, 0x95, 0xa9, 0x94, 0xd5, /* Atgu.... */
        0xc3, 0xee, 0x42, 0xf8, 0x8d, 0xeb, 0x92, 0x95, /* ..B..... */
        0xe1, 0xd9, 0x65, 0xb7, 0x43, 0xc4, 0x18, 0xde, /* ..e.C... */
        0x16, 0x80, 0x90, 0xce, 0x24, 0x35, 0x21, 0xc4, /* ....$5!. */
        0x55, 0xac, 0x5a, 0x51, 0xe0, 0x2e, 0x2d, 0xb3, /* U.ZQ..-. */
        0x0a, 0x5a, 0x4f, 0x4a, 0x73, 0x31, 0x50, 0xee, /* .ZOJs1P. */
        0x4a, 0x16, 0xbd, 0x39, 0x8b, 0xad, 0x05, 0x48, /* J..9...H */
        0x87, 0xb1, 0x99, 0xe2, 0x10, 0xa7, 0x06, 0x72, /* .......r */
        0x67, 0xca, 0x5c, 0xd1, 0x97, 0xbd, 0xc8, 0xf1, /* g.\..... */
        0x76, 0xf8, 0xe0, 0x4a, 0xec, 0xbc, 0x93, 0xf4, /* v..J.... */
        0x66, 0x4c, 0x28, 0x71, 0xd1, 0xd8, 0x66, 0x03, /* fL(q..f. */
        0xb4, 0x90, 0x30, 0xbb, 0x17, 0xb0, 0xfe, 0x97, /* ..0..... */
        0xf5, 0x1e, 0xe8, 0xc7, 0x5d, 0x9b, 0x8b, 0x11, /* ....]... */
        0x19, 0x12, 0x3c, 0xab, 0x82, 0x71, 0x78, 0xff, /* ..<..qx. */
        0xae, 0x3f, 0x32, 0xb2, 0x08, 0x71, 0xb2, 0x1b, /* .?2..q.. */
        0x8c, 0x27, 0xac, 0x11, 0xb8, 0xd8, 0x43, 0x49, /* .'....CI */
        0xcf, 0xb0, 0x70, 0xb1, 0xf0, 0x8c, 0xae, 0xda, /* ..p..... */
        0x24, 0x87, 0x17, 0x3b, 0xd8, 0x04, 0x65, 0x6c, /* $..;..el */
        0x00, 0x76, 0x50, 0xef, 0x15, 0x08, 0xd7, 0xb4, /* .vP..... */
        0x73, 0x68, 0x26, 0x14, 0x87, 0x95, 0xc3, 0x5f, /* sh&...._ */
        0x6e, 0x61, 0xb8, 0x87, 0x84, 0xfa, 0x80, 0x1a, /* na...... */
        0x0a, 0x8b, 0x98, 0xf3, 0xe3, 0xff, 0x4e, 0x44, /* ......ND */
        0x1c, 0x65, 0x74, 0x7c, 0x71, 0x54, 0x65, 0xe5, /* .et|qTe. */
        0x39, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, /* 9....... */
        0x01, 0x0a, 0x30, 0x82, 0x01, 0x06, 0x30, 0x09, /* ..0...0. */
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, /* ..U....0 */
        0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, /* .0...U.. */
        0x04, 0x16, 0x04, 0x14, 0x32, 0x67, 0xe1, 0xb1, /* ....2g.. */
        0x79, 0xd2, 0x81, 0xfc, 0x9f, 0x23, 0x0c, 0x70, /* y....#.p */
        0x40, 0x50, 0xb5, 0x46, 0x56, 0xb8, 0x30, 0x36, /* @P.FV.06 */
        0x30, 0x81, 0xc4, 0x06, 0x03, 0x55, 0x1d, 0x23, /* 0....U.# */
        0x04, 0x81, 0xbc, 0x30, 0x81, 0xb9, 0x80, 0x14, /* ...0.... */
        0x73, 0xb0, 0x1c, 0xa4, 0x2f, 0x82, 0xcb, 0xcf, /* s.../... */
        0x47, 0xa5, 0x38, 0xd7, 0xb0, 0x04, 0x82, 0x3a, /* G.8....: */
        0x7e, 0x72, 0x15, 0x21, 0xa1, 0x81, 0x9d, 0xa4, /* ~r.!.... */
        0x81, 0x9a, 0x30, 0x81, 0x97, 0x31, 0x0b, 0x30, /* ..0..1.0 */
        0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, /* ...U.... */
        0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, /* US1.0... */
        0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, /* U....Was */
        0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, /* hington1 */
        0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, /* .0...U.. */
        0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, /* ..Seattl */
        0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, /* e1.0...U */
        0x04, 0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66, /* ....wolf */
        0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, /* SSL1.0.. */
        0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, /* .U....En */
        0x67, 0x69, 0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e, /* gineerin */
        0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, /* g1.0...U */
        0x04, 0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, /* ....wolf */
        0x53, 0x53, 0x4c, 0x20, 0x72, 0x6f, 0x6f, 0x74, /* SSL root */
        0x20, 0x43, 0x41, 0x31, 0x1f, 0x30, 0x1d, 0x06, /*  CA1.0.. */
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, /* .*.H.... */
        0x09, 0x01, 0x16, 0x10, 0x69, 0x6e, 0x66, 0x6f, /* ....info */
        0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, /* @wolfssl */
        0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x01, 0x63, 0x30, /* .com..c0 */
        0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, /* ...U.%.. */
        0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, /* 0...+... */
        0x05, 0x07, 0x03, 0x09, 0x30, 0x0d, 0x06, 0x09, /* ....0... */
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, /* *.H..... */
        0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, /* ........ */
        0x4d, 0xa2, 0xd8, 0x55, 0xe0, 0x2b, 0xf4, 0xad, /* M..U.+.. */
        0x65, 0xe2, 0x92, 0x35, 0xcb, 0x60, 0xa0, 0xa2, /* e..5.`.. */
        0x6b, 0xa6, 0x88, 0xc1, 0x86, 0x58, 0x57, 0x37, /* k....XW7 */
        0xbd, 0x2e, 0x28, 0x6e, 0x1c, 0x56, 0x2a, 0x35, /* ..(n.V*5 */
        0xde, 0xff, 0x3e, 0x8e, 0x3d, 0x47, 0x21, 0x1a, /* ..>.=G!. */
        0xe9, 0xd3, 0xc6, 0xb4, 0xe2, 0xcb, 0x3e, 0xc6, /* ......>. */
        0xaf, 0x9b, 0xef, 0x23, 0x88, 0x56, 0x95, 0x73, /* ...#.V.s */
        0x2e, 0xb3, 0xed, 0xc5, 0x11, 0x4b, 0x69, 0xf7, /* .....Ki. */
        0x13, 0x3a, 0x05, 0xe1, 0xaf, 0xba, 0xc9, 0x59, /* .:.....Y */
        0xfd, 0xe2, 0xa0, 0x81, 0xa0, 0x4c, 0x0c, 0x2c, /* .....L., */
        0xcb, 0x57, 0xad, 0x96, 0x3a, 0x8c, 0x32, 0xa6, /* .W..:.2. */
        0x4a, 0xf8, 0x72, 0xb8, 0xec, 0xb3, 0x26, 0x69, /* J.r...&i */
        0xd6, 0x6a, 0x4c, 0x4c, 0x78, 0x18, 0x3c, 0xca, /* .jLLx.<. */
        0x19, 0xf1, 0xb5, 0x8e, 0x23, 0x81, 0x5b, 0x27, /* ....#.[' */
        0x90, 0xe0, 0x5c, 0x2b, 0x17, 0x4d, 0x78, 0x99, /* ..\+.Mx. */
        0x6b, 0x25, 0xbd, 0x2f, 0xae, 0x1b, 0xaa, 0xce, /* k%./.... */
        0x84, 0xb9, 0x44, 0x21, 0x46, 0xc0, 0x34, 0x6b, /* ..D!F.4k */
        0x5b, 0xb9, 0x1b, 0xca, 0x5c, 0x60, 0xf1, 0xef, /* [...\`.. */
        0xe6, 0x66, 0xbc, 0x84, 0x63, 0x56, 0x50, 0x7d, /* .f..cVP} */
        0xbb, 0x2c, 0x2f, 0x7b, 0x47, 0xb4, 0xfd, 0x58, /* .,/{G..X */
        0x77, 0x87, 0xee, 0x27, 0x20, 0x96, 0x72, 0x8e, /* w..' .r. */
        0x4c, 0x7e, 0x4f, 0x93, 0xeb, 0x5f, 0x8f, 0x9c, /* L~O.._.. */
        0x1e, 0x59, 0x7a, 0x96, 0xaa, 0x53, 0x77, 0x22, /* .Yz..Sw" */
        0x41, 0xd8, 0xd3, 0xf9, 0x89, 0x8f, 0xe8, 0x9d, /* A....... */
        0x65, 0xbd, 0x0c, 0x71, 0x3c, 0xbb, 0xa3, 0x07, /* e..q<... */
        0xbf, 0xfb, 0xa8, 0xd1, 0x18, 0x0a, 0xb4, 0xc4, /* ........ */
        0xf7, 0x83, 0xb3, 0x86, 0x2b, 0xf0, 0x5b, 0x05, /* ....+.[. */
        0x28, 0xc1, 0x01, 0x31, 0x73, 0x5c, 0x2b, 0xbd, /* (..1s\+. */
        0x60, 0x97, 0xa3, 0x36, 0x82, 0x96, 0xd7, 0x83, /* `..6.... */
        0xdf, 0x75, 0xee, 0x29, 0x42, 0x97, 0x86, 0x41, /* .u.)B..A */
        0x55, 0xb9, 0x70, 0x87, 0xd5, 0x02, 0x85, 0x13, /* U.p..... */
        0x41, 0xf8, 0x25, 0x05, 0xab, 0x6a, 0xaa, 0x57  /* A.%..j.W */
    };
    OcspEntry entry[1];
    CertStatus status[1];
    OcspRequest* request = NULL;
#ifndef NO_FILESYSTEM
    const char* ca_cert = "./certs/ca-cert.pem";
#endif

    byte serial[] = {0x05};
    byte issuerHash[] = {
        0x71, 0x4d, 0x82, 0x23, 0x40, 0x59, 0xc0, 0x96,
        0xa1, 0x37, 0x43, 0xfa, 0x31, 0xdb, 0xba, 0xb1,
        0x43, 0x18, 0xda, 0x04
    };
    byte issuerKeyHash[] = {
        0x83, 0xc6, 0x3a, 0x89, 0x2c, 0x81, 0xf4, 0x02,
        0xd7, 0x9d, 0x4c, 0xe2, 0x2a, 0xc0, 0x71, 0x82,
        0x64, 0x44, 0xda, 0x0e
    };


    XMEMSET(entry, 0, sizeof(OcspEntry));
    XMEMSET(status, 0, sizeof(CertStatus));

    ExpectNotNull(request = wolfSSL_OCSP_REQUEST_new());
    ExpectNotNull(request->serial = (byte*)XMALLOC(sizeof(serial), NULL,
                                                   DYNAMIC_TYPE_OCSP_REQUEST));

    if ((request != NULL) && (request->serial != NULL)) {
        request->serialSz = sizeof(serial);
        XMEMCPY(request->serial, serial, sizeof(serial));
        XMEMCPY(request->issuerHash, issuerHash, sizeof(issuerHash));
        XMEMCPY(request->issuerKeyHash, issuerKeyHash, sizeof(issuerKeyHash));
    }

    ExpectNotNull(cm = wolfSSL_CertManagerNew_ex(NULL));
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSP(cm, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);

    /* Response should be valid. */
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSPResponse(cm, (byte *)response,
        sizeof(response), NULL, status, entry, request), WOLFSSL_SUCCESS);

    /* Flip a byte in the request serial number, response should be invalid
     * now. */
    if ((request != NULL) && (request->serial != NULL))
        request->serial[0] ^= request->serial[0];
    ExpectIntNE(wolfSSL_CertManagerCheckOCSPResponse(cm, (byte *)response,
        sizeof(response), NULL, status, entry, request), WOLFSSL_SUCCESS);

#ifndef NO_FILESYSTEM
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, server_cert_der_2048,
        sizeof(server_cert_der_2048)), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    ExpectIntEQ(WOLFSSL_SUCCESS,
        wolfSSL_CertManagerLoadCA(cm, ca_cert, NULL));
    ExpectIntEQ(wolfSSL_CertManagerCheckOCSP(cm, server_cert_der_2048,
        sizeof(server_cert_der_2048)), 1);
#endif

    wolfSSL_OCSP_REQUEST_free(request);
    wolfSSL_CertManagerFree(cm);
#endif /* OPENSSL_ALL || WOLFSSL_NGINX ||  WOLFSSL_HAPROXY ||
        * WOLFSSL_APACHE_HTTPD || HAVE_LIGHTY */
#endif /* HAVE_OCSP */
    return EXPECT_RESULT();
}

#ifdef HAVE_CERT_CHAIN_VALIDATION
#ifndef WOLFSSL_TEST_APPLE_NATIVE_CERT_VALIDATION
#ifdef WOLFSSL_PEM_TO_DER
#ifndef NO_SHA256
static int load_ca_into_cm(WOLFSSL_CERT_MANAGER* cm, char* certA)
{
    int ret;

    if ((ret = wolfSSL_CertManagerLoadCA(cm, certA, 0)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "loading cert %s failed\n", certA);
        fprintf(stderr, "Error: (%d): %s\n", ret,
            wolfSSL_ERR_reason_error_string((word32)ret));
        return -1;
    }

    return 0;
}

static int verify_cert_with_cm(WOLFSSL_CERT_MANAGER* cm, char* certA)
{
    int ret;
    if ((ret = wolfSSL_CertManagerVerify(cm, certA, CERT_FILETYPE))
                                                         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "could not verify the cert: %s\n", certA);
        fprintf(stderr, "Error: (%d): %s\n", ret,
            wolfSSL_ERR_reason_error_string((word32)ret));
        return -1;
    }
    else {
        fprintf(stderr, "successfully verified: %s\n", certA);
    }

    return 0;
}
#define LOAD_ONE_CA(a, b, c, d)                         \
                    do {                                \
                        (a) = load_ca_into_cm(c, d);    \
                        if ((a) != 0)                   \
                            return (b);                 \
                        else                            \
                            (b)--;                      \
                    } while(0)

#define VERIFY_ONE_CERT(a, b, c, d)                     \
                    do {                                \
                        (a) = verify_cert_with_cm(c, d);\
                        if ((a) != 0)                   \
                            return (b);                 \
                        else                            \
                            (b)--;                      \
                    } while(0)

static int test_chainG(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain G is a valid chain per RFC 5280 section 4.2.1.9 */
    char chainGArr[9][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainG-ICA7-pathlen100.pem",
                             "certs/test-pathlen/chainG-ICA6-pathlen10.pem",
                             "certs/test-pathlen/chainG-ICA5-pathlen20.pem",
                             "certs/test-pathlen/chainG-ICA4-pathlen5.pem",
                             "certs/test-pathlen/chainG-ICA3-pathlen99.pem",
                             "certs/test-pathlen/chainG-ICA2-pathlen1.pem",
                             "certs/test-pathlen/chainG-ICA1-pathlen0.pem",
                             "certs/test-pathlen/chainG-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainGArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[4]); /* if failure, i = -5 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[5]); /* if failure, i = -6 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[6]); /* if failure, i = -7 here */
    LOAD_ONE_CA(ret, i, cm, chainGArr[7]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[1]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[2]); /* if failure, i = -10 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[3]); /* if failure, i = -11 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[4]); /* if failure, i = -12 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[5]); /* if failure, i = -13 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[6]); /* if failure, i = -14 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[7]); /* if failure, i = -15 here */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[8]); /* if failure, i = -16 here */

    /* test validating the entity twice, should have no effect on pathLen since
     * entity/leaf cert */
    VERIFY_ONE_CERT(ret, i, cm, chainGArr[8]); /* if failure, i = -17 here */

    return ret;
}

static int test_chainH(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain H is NOT a valid chain per RFC5280 section 4.2.1.9:
     * ICA4-pathlen of 2 signing ICA3-pathlen of 2 (reduce max path len to 2)
     * ICA3-pathlen of 2 signing ICA2-pathlen of 2 (reduce max path len to 1)
     * ICA2-pathlen of 2 signing ICA1-pathlen of 0 (reduce max path len to 0)
     * ICA1-pathlen of 0 signing entity (pathlen is already 0, ERROR)
     * Test should successfully verify ICA4, ICA3, ICA2 and then fail on ICA1
     */
    char chainHArr[6][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainH-ICA4-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA3-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA2-pathlen2.pem",
                             "certs/test-pathlen/chainH-ICA1-pathlen0.pem",
                             "certs/test-pathlen/chainH-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainHArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainHArr[4]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[1]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[2]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[3]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[4]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainHArr[5]); /* if failure, i = -10 here */

    return ret;
}

static int test_chainI(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain I is a valid chain per RFC5280 section 4.2.1.9:
     * ICA3-pathlen of 2 signing ICA2 without a pathlen (reduce maxPathLen to 2)
     * ICA2-no_pathlen signing ICA1-no_pathlen (reduce maxPathLen to 1)
     * ICA1-no_pathlen signing entity (reduce maxPathLen to 0)
     * Test should successfully verify ICA4, ICA3, ICA2 and then fail on ICA1
     */
    char chainIArr[5][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainI-ICA3-pathlen2.pem",
                             "certs/test-pathlen/chainI-ICA2-no_pathlen.pem",
                             "certs/test-pathlen/chainI-ICA1-no_pathlen.pem",
                             "certs/test-pathlen/chainI-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainIArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainIArr[3]); /* if failure, i = -4 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[1]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[2]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[3]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainIArr[4]); /* if failure, i = -8 here */

    return ret;
}

static int test_chainJ(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;
    int i = -1;
    /* Chain J is NOT a valid chain per RFC5280 section 4.2.1.9:
     * ICA4-pathlen of 2 signing ICA3 without a pathlen (reduce maxPathLen to 2)
     * ICA3-pathlen of 2 signing ICA2 without a pathlen (reduce maxPathLen to 1)
     * ICA2-no_pathlen signing ICA1-no_pathlen (reduce maxPathLen to 0)
     * ICA1-no_pathlen signing entity (ERROR, pathlen zero and non-leaf cert)
     */
    char chainJArr[6][50] = {"certs/ca-cert.pem",
                             "certs/test-pathlen/chainJ-ICA4-pathlen2.pem",
                             "certs/test-pathlen/chainJ-ICA3-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-ICA2-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-ICA1-no_pathlen.pem",
                             "certs/test-pathlen/chainJ-entity.pem"};

    LOAD_ONE_CA(ret, i, cm, chainJArr[0]); /* if failure, i = -1 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[1]); /* if failure, i = -2 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[2]); /* if failure, i = -3 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[3]); /* if failure, i = -4 here */
    LOAD_ONE_CA(ret, i, cm, chainJArr[4]); /* if failure, i = -5 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[1]); /* if failure, i = -6 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[2]); /* if failure, i = -7 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[3]); /* if failure, i = -8 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[4]); /* if failure, i = -9 here */
    VERIFY_ONE_CERT(ret, i, cm, chainJArr[5]); /* if failure, i = -10 here */

    return ret;
}
#endif
#endif
#endif
#endif

int test_various_pathlen_chains(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_PEM_TO_DER) && defined(HAVE_CERT_CHAIN_VALIDATION) && \
    !defined(WOLFSSL_TEST_APPLE_NATIVE_CERT_VALIDATION)
#ifndef NO_SHA256
    WOLFSSL_CERT_MANAGER* cm = NULL;

    /* Test chain G (large chain with varying pathLens) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(test_chainG(cm), -1);
#else
    ExpectIntEQ(test_chainG(cm), 0);
#endif /* NO_WOLFSSL_CLIENT && NO_WOLFSSL_SERVER */
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    /* end test chain G */

    /* Test chain H (5 chain with same pathLens) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntLT(test_chainH(cm), 0);
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    /* end test chain H */

    /* Test chain I (only first ICA has pathLen set and it's set to 2,
     * followed by 2 ICA's, should pass) */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
#if defined(NO_WOLFSSL_CLIENT) && defined(NO_WOLFSSL_SERVER)
    ExpectIntEQ(test_chainI(cm), -1);
#else
    ExpectIntEQ(test_chainI(cm), 0);
#endif /* NO_WOLFSSL_CLIENT && NO_WOLFSSL_SERVER */
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    /* Test chain J (Again only first ICA has pathLen set and it's set to 2,
     * this time followed by 3 ICA's, should fail */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntLT(test_chainJ(cm), 0);
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
    cm = NULL;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerUnloadCAs(cm), WOLFSSL_SUCCESS);
    wolfSSL_CertManagerFree(cm);
#endif
#endif
    return EXPECT_RESULT();
}
