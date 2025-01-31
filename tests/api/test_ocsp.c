/* ocsp.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <tests/api/test_ocsp.h>
#include <tests/api/test_ocsp_test_blobs.h>
#include <tests/unit.h>
#include <wolfssl/internal.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/ssl.h>

#if defined(HAVE_OCSP)
struct ocsp_cb_ctx {
    byte* response;
    int responseSz;
};

struct test_conf {
    unsigned char* resp;
    int respSz;
    unsigned char* ca0;
    int ca0Sz;
    unsigned char* ca1;
    int ca1Sz;
    unsigned char* targetCert;
    int targetCertSz;
};

static int ocsp_cb(void* ctx, const char* url, int urlSz, unsigned char* req,
    int reqSz, unsigned char** respBuf)
{
    struct ocsp_cb_ctx* cb_ctx = (struct ocsp_cb_ctx*)ctx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;

    *respBuf = cb_ctx->response;
    return cb_ctx->responseSz;
}

static int test_ocsp_response_with_cm(struct test_conf* c)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    struct ocsp_cb_ctx cb_ctx;
    int ret;

    cm = wolfSSL_CertManagerNew();
    ExpectPtrNE(cm, NULL);
    ret = wolfSSL_CertManagerEnableOCSP(cm,
        WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    ret = wolfSSL_CertManagerSetOCSPOverrideURL(cm, "http://foo.com");
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    cb_ctx.response = (byte*)c->resp;
    cb_ctx.responseSz = c->respSz;
    ret = wolfSSL_CertManagerSetOCSP_Cb(cm, ocsp_cb, NULL, (void*)&cb_ctx);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* add ca in cm */
    if (c->ca0 != NULL) {
        ret = wolfSSL_CertManagerLoadCABuffer(cm, c->ca0, c->ca0Sz,
            WOLFSSL_FILETYPE_ASN1);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    }
    if (c->ca1 != NULL) {
        ret = wolfSSL_CertManagerLoadCABuffer(cm, c->ca1, c->ca1Sz,
            WOLFSSL_FILETYPE_ASN1);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    }
    /* check cert */
    ret = wolfSSL_CertManagerCheckOCSP(cm, c->targetCert, c->targetCertSz);
    wolfSSL_CertManagerFree(cm);
    return ret;
}

int test_ocsp_response_parsing(void)
{
    struct test_conf conf;
    int ret;
    EXPECT_DECLS;
    conf.resp = (unsigned char*)resp;
    conf.respSz = sizeof(resp);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ret = test_ocsp_response_with_cm(&conf);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);

    conf.resp = (unsigned char*)resp_multi;
    conf.respSz = sizeof(resp_multi);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ret = test_ocsp_response_with_cm(&conf);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);

    conf.resp = (unsigned char*)resp_bad_noauth;
    conf.respSz = sizeof(resp_bad_noauth);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = ca_cert_pem;
    conf.ca1Sz = sizeof(ca_cert_pem);
    conf.targetCert = server_cert_pem;
    conf.targetCertSz = sizeof(server_cert_pem);
    ret = test_ocsp_response_with_cm(&conf);
#ifndef WOLFSSL_NO_OCSP_ISSUER_CHECK
    ExpectIntNE(ret, WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
    return EXPECT_SUCCESS();
}
#else  /* HAVE_OCSP */
int test_ocsp_response_parsing(void) { return TEST_SKIPPED; }
#endif /* HAVE_OCSP */

#if defined(HAVE_OCSP) && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA))
static int test_ocsp_create_x509store(WOLFSSL_X509_STORE** store,
    unsigned char* ca, int caSz)
{
    EXPECT_DECLS;
    WOLFSSL_X509* cert = NULL;
    int ret;

    *store = wolfSSL_X509_STORE_new();
    ExpectPtrNE(*store, NULL);
    cert = wolfSSL_X509_d2i(&cert, ca, caSz);
    ExpectPtrNE(cert, NULL);
    ret = wolfSSL_X509_STORE_add_cert(*store, cert);
    wolfSSL_X509_free(cert);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

static int test_create_stack_of_x509(WOLF_STACK_OF(WOLFSSL_X509) * *certs,
    unsigned char* der, int derSz)
{
    EXPECT_DECLS;
    WOLFSSL_X509* cert = NULL;
    int ret;

    *certs = wolfSSL_sk_X509_new_null();
    ExpectPtrNE(*certs, NULL);
    cert = wolfSSL_X509_d2i(&cert, der, derSz);
    ExpectPtrNE(cert, NULL);
    ret = wolfSSL_sk_X509_push(*certs, cert);
    ExpectIntEQ(ret, 1);
    return EXPECT_RESULT();
}

int test_ocsp_basic_verify(void)
{
    EXPECT_DECLS;
    WOLF_STACK_OF(WOLFSSL_X509) * certs;
    OcspResponse* response = NULL;
    WOLFSSL_X509_STORE* store;
    const unsigned char* ptr;
    DecodedCert cert;
    int ret;

    wc_InitDecodedCert(&cert, ocsp_responder_cert_pem,
        sizeof(ocsp_responder_cert_pem), NULL);
    ret = wc_ParseCert(&cert, CERT_TYPE, 0, NULL);
    ExpectIntEQ(ret, 0);

    /* just decoding */
    ptr = (const unsigned char*)resp;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp));
    ExpectPtrNE(response, NULL);
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_NAME);
    ExpectBufEQ(response->responderId.nameHash, cert.subjectHash,
        OCSP_DIGEST_SIZE);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* responder Id by key hash */
    ptr = (const unsigned char*)resp_rid_bykey;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_rid_bykey));
    ExpectPtrNE(response, NULL);
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_KEY);
    ExpectBufEQ(response->responderId.keyHash, cert.subjectKeyHash,
        OCSP_DIGEST_SIZE);
    wc_FreeDecodedCert(&cert);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding with no embedded certificates */
    ptr = (const unsigned char*)resp_nocert;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert));
    ExpectPtrNE(response, NULL);
    ExpectIntEQ(response->responseStatus, 0);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding an invalid response */
    ptr = (const unsigned char*)resp_bad;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_bad));
    ExpectPtrEq(response, NULL);

    ptr = (const unsigned char*)resp;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp));
    ExpectPtrNE(response, NULL);
    /* no verify signer certificate */
    ret = wolfSSL_OCSP_basic_verify(response, NULL, NULL, OCSP_NOVERIFY);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* verify that the signature is checked */
    response->sig[0] ^= 0xff;
    ret = wolfSSL_OCSP_basic_verify(response, NULL, NULL, OCSP_NOVERIFY);
    ExpectIntEQ(ret, WOLFSSL_FAILURE);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* populate a store with root-ca-cert */
    ret = test_ocsp_create_x509store(&store, root_ca_cert_pem,
        sizeof(root_ca_cert_pem));
    ExpectIntEQ(ret, TEST_SUCCESS);

    /* populate a WOLF_STACK_OF(WOLFSSL_X509) with responder certificate */
    ret = test_create_stack_of_x509(&certs, ocsp_responder_cert_pem,
        sizeof(ocsp_responder_cert_pem));
    ExpectIntEQ(ret, TEST_SUCCESS);

    /* cert not embedded, cert in certs, validated using store */
    ptr = (const unsigned char*)resp_nocert;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert));
    ExpectPtrNE(response, NULL);
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, 0);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* cert embedded, verified using store */
    ptr = (const unsigned char*)resp;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp));
    ExpectPtrNE(response, NULL);
    ret = wolfSSL_OCSP_basic_verify(response, NULL, store, 0);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* make invalid signature */
    response->sig[0] ^= 0xff;
    ret = wolfSSL_OCSP_basic_verify(response, NULL, store, 0);
    ExpectIntEQ(ret, WOLFSSL_FAILURE);
    response->sig[0] ^= 0xff;

    /* cert embedded and in certs, no store needed bc OCSP_TRUSTOTHER */
    ret = wolfSSL_OCSP_basic_verify(response, certs, NULL, OCSP_TRUSTOTHER);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* this should also pass */
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_NOINTERN);
    ;
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* this should not */
    ret = wolfSSL_OCSP_basic_verify(response, NULL, store, OCSP_NOINTERN);
    ;
    ExpectIntNE(ret, WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* cert not embedded, not certs */
    ptr = (const unsigned char*)resp_nocert;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert));
    ExpectPtrNE(response, NULL);
    ret = wolfSSL_OCSP_basic_verify(response, NULL, store, 0);
    ExpectIntNE(ret, WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    wolfSSL_sk_X509_pop_free(certs, wolfSSL_X509_free);
    wolfSSL_X509_STORE_free(store);

    ret = test_ocsp_create_x509store(&store, root_ca_cert_pem,
        sizeof(root_ca_cert_pem));
    ExpectIntEQ(ret, TEST_SUCCESS);
    ret = test_create_stack_of_x509(&certs, root_ca_cert_pem,
        sizeof(root_ca_cert_pem));
    ExpectIntEQ(ret, TEST_SUCCESS);

    /* multiple responses in a ocsp response */
    ptr = (const unsigned char*)resp_multi;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_multi));
    ExpectPtrNE(response, NULL);
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, 0);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* cert in certs, cert verified on store, not authorized to verify all
     * responses */
    ptr = (const unsigned char*)resp_bad_noauth;
    response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_bad_noauth));
    ExpectPtrNE(response, NULL);
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, 0);
#ifndef WOLFSSL_NO_OCSP_ISSUER_CHECK
    ExpectIntEQ(ret, WOLFSSL_FAILURE);
#else
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#endif
    /* should pass with OCSP_NOCHECKS ...*/
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_NOCHECKS);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    /* or with OSCP_TRUSTOTHER */
    ret = wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_TRUSTOTHER);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    wolfSSL_sk_X509_pop_free(certs, wolfSSL_X509_free);
    wolfSSL_X509_STORE_free(store);

    return EXPECT_RESULT();
}
#else
int test_ocsp_basic_verify(void) { return TEST_SKIPPED; }
#endif /* HAVE_OCSP  && (OPENSSL_ALL || OPENSSL_EXTRA) */

#if defined(HAVE_OCSP) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&     \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA))

struct _test_ocsp_status_callback_ctx {
    byte* ocsp_resp;
    int ocsp_resp_sz;
    int invoked;
};

static int test_ocsp_status_callback_cb(WOLFSSL* ssl, void* ctx)
{
    struct _test_ocsp_status_callback_ctx* _ctx =
        (struct _test_ocsp_status_callback_ctx*)ctx;
    byte* allocated;

    _ctx->invoked++;
    allocated = (byte*)XMALLOC(_ctx->ocsp_resp_sz, NULL, 0);
    if (allocated == NULL)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    XMEMCPY(allocated, _ctx->ocsp_resp, _ctx->ocsp_resp_sz);
    SSL_set_tlsext_status_ocsp_resp(ssl, allocated, _ctx->ocsp_resp_sz);
    return SSL_TLSEXT_ERR_OK;
}

static int test_ocsp_status_callback_cb_noack(WOLFSSL* ssl, void* ctx)
{
    struct _test_ocsp_status_callback_ctx* _ctx =
        (struct _test_ocsp_status_callback_ctx*)ctx;
    (void)ssl;

    _ctx->invoked++;
    return SSL_TLSEXT_ERR_NOACK;
}

static int test_ocsp_status_callback_cb_err(WOLFSSL* ssl, void* ctx)
{
    struct _test_ocsp_status_callback_ctx* _ctx =
        (struct _test_ocsp_status_callback_ctx*)ctx;
    (void)ssl;

    _ctx->invoked++;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int test_ocsp_status_callback_test_setup(
    struct _test_ocsp_status_callback_ctx* cb_ctx,
    struct test_ssl_memio_ctx* test_ctx, method_provider cm, method_provider sm)
{
    int ret;

    cb_ctx->invoked = 0;
    XMEMSET(test_ctx, 0, sizeof(*test_ctx));
    test_ctx->c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx->s_cb.certPemFile = "./certs/ocsp/server1-cert.pem";
    test_ctx->s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx->c_cb.method = cm;
    test_ctx->s_cb.method = sm;
    ret = test_ssl_memio_setup(test_ctx);
    wolfSSL_set_verify(test_ctx->c_ssl, WOLFSSL_VERIFY_DEFAULT, NULL);
    return ret;
}

static int test_ocsp_status_callback(void)
{
    struct test_params {
        method_provider c_method;
        method_provider s_method;
    };

    const char* responseFile = "./certs/ocsp/test-leaf-response.der";
    struct _test_ocsp_status_callback_ctx cb_ctx;
    struct test_ssl_memio_ctx test_ctx;
    int enable_client_ocsp;
    int enable_must_staple;
    XFILE f = XBADFILE;
    byte data[4096];
    unsigned int i;
    EXPECT_DECLS;

    struct test_params params[] = {
        {wolfTLSv1_2_client_method, wolfTLSv1_2_server_method},
#if defined(WOLFSSL_TLS13)
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method},
#endif
#if defined(WOLFSSL_DTLS)
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method},
#endif
#if defined(WOLFSSL_DTLS13)
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method},
#endif
    };

    XMEMSET(&cb_ctx, 0, sizeof(cb_ctx));
    f = XFOPEN(responseFile, "rb");
    if (f == XBADFILE)
        return -1;
    cb_ctx.ocsp_resp_sz = (word32)XFREAD(data, 1, 4096, f);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    cb_ctx.ocsp_resp = data;

    for (i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        for (enable_client_ocsp = 0; enable_client_ocsp <= 1;
            enable_client_ocsp++) {
            ExpectIntEQ(test_ocsp_status_callback_test_setup(&cb_ctx, &test_ctx,
                            params[i].c_method, params[i].s_method),
                TEST_SUCCESS);
            ExpectIntEQ(SSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                            test_ocsp_status_callback_cb),
                SSL_SUCCESS);
            ExpectIntEQ(
                SSL_CTX_set_tlsext_status_arg(test_ctx.s_ctx, (void*)&cb_ctx),
                SSL_SUCCESS);
            if (enable_client_ocsp) {
                ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                                WOLFSSL_CSR_OCSP, 0),
                    WOLFSSL_SUCCESS);
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
                    WOLFSSL_SUCCESS);
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(test_ctx.c_ctx),
                    WOLFSSL_SUCCESS);
            }
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(cb_ctx.invoked, enable_client_ocsp ? 1 : 0);
            test_ssl_memio_cleanup(&test_ctx);
            if (!EXPECT_SUCCESS())
                return EXPECT_RESULT();
        }
    }
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    /* test client sending both OCSPv1 and OCSPv2/MultiOCSP */
    /* StatusCb only supports OCSPv1 */
    ExpectIntEQ(test_ocsp_status_callback_test_setup(&cb_ctx, &test_ctx,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method),
        TEST_SUCCESS);
    ExpectIntEQ(SSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                    test_ocsp_status_callback_cb),
        SSL_SUCCESS);
    ExpectIntEQ(SSL_CTX_set_tlsext_status_arg(test_ctx.s_ctx, (void*)&cb_ctx),
        SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(test_ctx.c_ctx),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(
        wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl, WOLFSSL_CSR2_OCSP_MULTI, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_set_verify(test_ctx.c_ssl, WOLFSSL_VERIFY_DEFAULT, NULL);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(cb_ctx.invoked, 1);
    test_ssl_memio_cleanup(&test_ctx);

    if (!EXPECT_SUCCESS())
        return EXPECT_RESULT();
#endif /* defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) */
    /* test cb returning NO_ACK, not acking the OCSP */
    for (i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        for (enable_must_staple = 0; enable_must_staple <= 1;
            enable_must_staple++) {
            ExpectIntEQ(test_ocsp_status_callback_test_setup(&cb_ctx, &test_ctx,
                            params[i].c_method, params[i].s_method),
                TEST_SUCCESS);
            ExpectIntEQ(SSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                            test_ocsp_status_callback_cb_noack),
                SSL_SUCCESS);
            ExpectIntEQ(
                SSL_CTX_set_tlsext_status_arg(test_ctx.s_ctx, (void*)&cb_ctx),
                SSL_SUCCESS);
            ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(
                wolfSSL_UseOCSPStapling(test_ctx.c_ssl, WOLFSSL_CSR_OCSP, 0),
                WOLFSSL_SUCCESS);
            if (enable_must_staple)
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(test_ctx.c_ctx),
                    WOLFSSL_SUCCESS);
            wolfSSL_set_verify(test_ctx.c_ssl, WOLFSSL_VERIFY_DEFAULT, NULL);
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                enable_must_staple ? TEST_FAIL : TEST_SUCCESS);
            ExpectIntEQ(cb_ctx.invoked, 1);
            test_ssl_memio_cleanup(&test_ctx);
            if (!EXPECT_SUCCESS())
                return EXPECT_RESULT();
        }
    }

    /* test cb returning err aborting handshake */
    for (i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        for (enable_client_ocsp = 0; enable_client_ocsp <= 1;
            enable_client_ocsp++) {
            ExpectIntEQ(test_ocsp_status_callback_test_setup(&cb_ctx, &test_ctx,
                            params[i].c_method, params[i].s_method),
                TEST_SUCCESS);
            ExpectIntEQ(SSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                            test_ocsp_status_callback_cb_err),
                SSL_SUCCESS);
            ExpectIntEQ(
                SSL_CTX_set_tlsext_status_arg(test_ctx.s_ctx, (void*)&cb_ctx),
                SSL_SUCCESS);
            if (enable_client_ocsp)
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
                    WOLFSSL_SUCCESS);
            ExpectIntEQ(
                wolfSSL_UseOCSPStapling(test_ctx.c_ssl, WOLFSSL_CSR_OCSP, 0),
                WOLFSSL_SUCCESS);
            wolfSSL_set_verify(test_ctx.c_ssl, WOLFSSL_VERIFY_DEFAULT, NULL);
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                enable_client_ocsp ? TEST_FAIL : TEST_SUCCESS);
            ExpectIntEQ(cb_ctx.invoked, enable_client_ocsp ? 1 : 0);
            test_ssl_memio_cleanup(&test_ctx);
            if (!EXPECT_SUCCESS())
                return EXPECT_RESULT();
        }
    }

    return EXPECT_RESULT();
}

#else
int test_ocsp_status_callback(void) { return TEST_SKIPPED; }
#endif /* defined(HAVE_OCSP) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)  \
    && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12)                                                    \
    && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) */
