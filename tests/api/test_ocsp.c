/* test_ocsp.c
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

#include <tests/api/test_ocsp.h>
#include <tests/api/test_ocsp_test_blobs.h>
#include <wolfssl/internal.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/ssl.h>

#if defined(HAVE_OCSP) && !defined(NO_SHA) && !defined(NO_RSA)
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

static int test_ocsp_response_with_cm(struct test_conf* c, int expectedRet)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    struct ocsp_cb_ctx cb_ctx;

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerEnableOCSP(cm,
                    WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerSetOCSPOverrideURL(cm, "http://foo.com"),
        WOLFSSL_SUCCESS);
    cb_ctx.response = (byte*)c->resp;
    cb_ctx.responseSz = c->respSz;
    ExpectIntEQ(
        wolfSSL_CertManagerSetOCSP_Cb(cm, ocsp_cb, NULL, (void*)&cb_ctx),
        WOLFSSL_SUCCESS);
    /* add ca in cm */
    if (c->ca0 != NULL) {
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, c->ca0, c->ca0Sz,
                        WOLFSSL_FILETYPE_ASN1),
            WOLFSSL_SUCCESS);
    }
    if (c->ca1 != NULL) {
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, c->ca1, c->ca1Sz,
                        WOLFSSL_FILETYPE_ASN1),
            WOLFSSL_SUCCESS);
    }
    /* check cert */
    ExpectIntEQ(
        wolfSSL_CertManagerCheckOCSP(cm, c->targetCert, c->targetCertSz),
        expectedRet);
    if (cm != NULL)
        wolfSSL_CertManagerFree(cm);
    return EXPECT_RESULT();
}

int test_ocsp_response_parsing(void)
{
    EXPECT_DECLS;
    struct test_conf conf;
    int  expectedRet;

    conf.resp = (unsigned char*)resp;
    conf.respSz = sizeof(resp);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, WOLFSSL_SUCCESS),
        TEST_SUCCESS);

    conf.resp = (unsigned char*)resp_multi;
    conf.respSz = sizeof(resp_multi);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, WOLFSSL_SUCCESS),
        TEST_SUCCESS);

    conf.resp = (unsigned char*)resp_bad_noauth;
    conf.respSz = sizeof(resp_bad_noauth);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = ca_cert_pem;
    conf.ca1Sz = sizeof(ca_cert_pem);
    conf.targetCert = server_cert_pem;
    conf.targetCertSz = sizeof(server_cert_pem);
    expectedRet = OCSP_LOOKUP_FAIL;
#ifdef WOLFSSL_NO_OCSP_ISSUER_CHECK
    expectedRet = WOLFSSL_SUCCESS;
#endif
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, expectedRet), TEST_SUCCESS);

    /* Test response with unusable internal cert but that can be verified in CM
     */
    conf.resp = (unsigned char*)resp_bad_embedded_cert;
    conf.respSz = sizeof(resp_bad_embedded_cert);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, WOLFSSL_SUCCESS),
        TEST_SUCCESS);
    return EXPECT_SUCCESS();
}
#else  /* HAVE_OCSP && !NO_SHA */
int test_ocsp_response_parsing(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && !NO_SHA */

#if defined(HAVE_OCSP) && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(NO_RSA)
static int test_ocsp_create_x509store(WOLFSSL_X509_STORE** store,
    unsigned char* ca, int caSz)
{
    EXPECT_DECLS;
    WOLFSSL_X509* cert = NULL;

    ExpectNotNull(*store = wolfSSL_X509_STORE_new());
    ExpectNotNull(cert = wolfSSL_X509_d2i(&cert, ca, caSz));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(*store, cert), WOLFSSL_SUCCESS);
    wolfSSL_X509_free(cert);
    return EXPECT_RESULT();
}

static int test_create_stack_of_x509(WOLF_STACK_OF(WOLFSSL_X509) * *certs,
    unsigned char* der, int derSz)
{
    EXPECT_DECLS;
    WOLFSSL_X509* cert = NULL;

    ExpectNotNull(*certs = wolfSSL_sk_X509_new_null());
    ExpectNotNull(cert = wolfSSL_X509_d2i(&cert, der, derSz));
    ExpectIntEQ(wolfSSL_sk_X509_push(*certs, cert), 1);
    return EXPECT_RESULT();
}

int test_ocsp_basic_verify(void)
{
    EXPECT_DECLS;
    WOLF_STACK_OF(WOLFSSL_X509)* certs = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    const unsigned char* ptr = NULL;
    OcspResponse* response = NULL;
    DecodedCert cert;
    int expectedRet;

    wc_InitDecodedCert(&cert, ocsp_responder_cert_pem,
        sizeof(ocsp_responder_cert_pem), NULL);
    ExpectIntEQ(wc_ParseCert(&cert, CERT_TYPE, 0, NULL), 0);

    /* just decoding */
    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp)));
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_NAME);
    ExpectBufEQ(response->responderId.nameHash, cert.subjectHash,
        OCSP_DIGEST_SIZE);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* responder Id by key hash */
    ptr = (const unsigned char*)resp_rid_bykey;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
                      sizeof(resp_rid_bykey)));
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_KEY);
    ExpectBufEQ(response->responderId.keyHash, cert.subjectKeyHash,
        OCSP_RESPONDER_ID_KEY_SZ);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding with no embedded certificates */
    ptr = (const unsigned char*)resp_nocert;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert)));
    ExpectIntEQ(response->responseStatus, 0);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding an invalid response */
    ptr = (const unsigned char*)resp_bad;
    ExpectNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_bad)));

    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp)));
    /* no verify signer certificate */
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, NULL, OCSP_NOVERIFY),
        WOLFSSL_SUCCESS);
    /* verify that the signature is checked */
    if (EXPECT_SUCCESS()) {
        response->sig[0] ^= 0xff;
    }
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, NULL, OCSP_NOVERIFY),
        WOLFSSL_FAILURE);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* populate a store with root-ca-cert */
    ExpectIntEQ(test_ocsp_create_x509store(&store, root_ca_cert_pem,
                    sizeof(root_ca_cert_pem)),
        TEST_SUCCESS);

    /* populate a WOLF_STACK_OF(WOLFSSL_X509) with responder certificate */
    ExpectIntEQ(test_create_stack_of_x509(&certs, ocsp_responder_cert_pem,
                    sizeof(ocsp_responder_cert_pem)),
        TEST_SUCCESS);

    /* cert not embedded, cert in certs, validated using store */
    ptr = (const unsigned char*)resp_nocert;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert)));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* cert embedded, verified using store */
    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp)));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, store, 0),
        WOLFSSL_SUCCESS);
    /* make invalid signature */
    if (EXPECT_SUCCESS()) {
        response->sig[0] ^= 0xff;
    }
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, store, 0),
        WOLFSSL_FAILURE);
    if (EXPECT_SUCCESS()) {
        response->sig[0] ^= 0xff;
    }

    /* cert embedded and in certs, no store needed bc OCSP_TRUSTOTHER */
    ExpectIntEQ(
        wolfSSL_OCSP_basic_verify(response, certs, NULL, OCSP_TRUSTOTHER),
        WOLFSSL_SUCCESS);
    /* this should also pass */
    ExpectIntEQ(
        wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_NOINTERN),
        WOLFSSL_SUCCESS);
    /* this should not */
    ExpectIntNE(wolfSSL_OCSP_basic_verify(response, NULL, store, OCSP_NOINTERN),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* cert not embedded, not certs */
    ptr = (const unsigned char*)resp_nocert;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert)));
    ExpectIntNE(wolfSSL_OCSP_basic_verify(response, NULL, store, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    wolfSSL_sk_X509_pop_free(certs, wolfSSL_X509_free);
    certs = NULL;
    wolfSSL_X509_STORE_free(store);
    store = NULL;

    ExpectIntEQ(test_ocsp_create_x509store(&store, root_ca_cert_pem,
                    sizeof(root_ca_cert_pem)),
        TEST_SUCCESS);
    ExpectIntEQ(test_create_stack_of_x509(&certs, root_ca_cert_pem,
                    sizeof(root_ca_cert_pem)),
        TEST_SUCCESS);

    /* multiple responses in a ocsp response */
    ptr = (const unsigned char*)resp_multi;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_multi)));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* cert in certs, cert verified on store, not authorized to verify all
     * responses */
    ptr = (const unsigned char*)resp_bad_noauth;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
                      sizeof(resp_bad_noauth)));

    expectedRet = WOLFSSL_FAILURE;
#ifdef WOLFSSL_NO_OCSP_ISSUER_CHECK
    expectedRet = WOLFSSL_SUCCESS;
#endif
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        expectedRet);
    /* should pass with OCSP_NOCHECKS ...*/
    ExpectIntEQ(
        wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_NOCHECKS),
        WOLFSSL_SUCCESS);
    /* or with OSCP_TRUSTOTHER */
    ExpectIntEQ(
        wolfSSL_OCSP_basic_verify(response, certs, store, OCSP_TRUSTOTHER),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);

    wc_FreeDecodedCert(&cert);
    wolfSSL_sk_X509_pop_free(certs, wolfSSL_X509_free);
    wolfSSL_X509_STORE_free(store);
    return EXPECT_RESULT();
}
#else
int test_ocsp_basic_verify(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP  && (OPENSSL_ALL || OPENSSL_EXTRA) */

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) &&     \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  \
    defined(OPENSSL_ALL)

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

int test_ocsp_status_callback(void)
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
int test_ocsp_status_callback(void)
{
    return TEST_SKIPPED;
}
#endif /* defined(HAVE_OCSP) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)  \
        && defined(HAVE_CERTIFICATE_STATUS_REQUEST) &&                         \
        !defined(WOLFSSL_NO_TLS12)                                             \
        && defined(OPENSSL_ALL) */

#if !defined(NO_SHA) && defined(OPENSSL_ALL) && defined(HAVE_OCSP) &&          \
    !defined(WOLFSSL_SM3) && !defined(WOLFSSL_SM2) && !defined(NO_RSA)
int test_ocsp_certid_enc_dec(void)
{
    EXPECT_DECLS;
    WOLFSSL_OCSP_CERTID* certIdDec = NULL;
    WOLFSSL_OCSP_CERTID* certId = NULL;
    WOLFSSL_X509* subject = NULL;
    WOLFSSL_X509* issuer = NULL;
    unsigned char* temp = NULL;
    unsigned char* der2 = NULL;
    unsigned char* der = NULL;
    int derSz = 0, derSz1 = 0;

    /* Load test certificates */
    ExpectNotNull(
        subject = wolfSSL_X509_load_certificate_file(
            "./certs/ocsp/intermediate1-ca-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(issuer = wolfSSL_X509_load_certificate_file(
                      "./certs/ocsp/root-ca-cert.pem", WOLFSSL_FILETYPE_PEM));

    /* Create CERTID from certificates */
    ExpectNotNull(certId = wolfSSL_OCSP_cert_to_id(NULL, subject, issuer));

    /* get len */
    ExpectIntGT(derSz = wolfSSL_i2d_OCSP_CERTID(certId, NULL), 0);

    /* encode it */
    ExpectIntGT(derSz1 = wolfSSL_i2d_OCSP_CERTID(certId, &der), 0);
    ExpectIntEQ(derSz, derSz1);

    if (EXPECT_SUCCESS())
        temp = der2 = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_OPENSSL);
    ExpectNotNull(der2);
    /* encode without allocation */
    ExpectIntGT(derSz1 = wolfSSL_i2d_OCSP_CERTID(certId, &der2), 0);
    ExpectIntEQ(derSz, derSz1);
    ExpectPtrEq(der2, temp + derSz);
    ExpectBufEQ(der, temp, derSz);
    XFREE(temp, NULL, DYNAMIC_TYPE_OPENSSL);

    /* save original */
    temp = der;
    /* decode it */
    ExpectNotNull(certIdDec = wolfSSL_d2i_OCSP_CERTID(NULL,
                      (const unsigned char**)&der, derSz));
    /* check ptr is advanced */
    ExpectPtrEq(der, temp + derSz);
    der = der2;
    XFREE(temp, NULL, DYNAMIC_TYPE_OPENSSL);

    /* compare */
    ExpectIntEQ(wolfSSL_OCSP_id_cmp(certId, certIdDec), 0);

    wolfSSL_OCSP_CERTID_free(certId);
    wolfSSL_OCSP_CERTID_free(certIdDec);
    wolfSSL_X509_free(subject);
    wolfSSL_X509_free(issuer);
    return EXPECT_SUCCESS();
}
#else /* !NO_SHA && OPENSSL_ALL && HAVE_OCSP && !WOLFSSL_SM3 && !WOLFSSL_SM2 */
int test_ocsp_certid_enc_dec(void)
{
    return TEST_SKIPPED;
}
#endif
