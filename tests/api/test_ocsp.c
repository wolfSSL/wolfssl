/* test_ocsp.c
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
#include <tests/utils.h>

#include <tests/api/test_ocsp.h>
#include <tests/api/test_ocsp_test_blobs.h>
#include <wolfssl/internal.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/asn.h>

/* Upper bound of the loops that also run each lookup as a would-block retry. */
#ifdef WOLFSSL_NONBLOCK_OCSP
    #define TEST_OCSP_NONBLOCK_MAX 1
#else
    #define TEST_OCSP_NONBLOCK_MAX 0
#endif

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

struct wolfio_http_test_ctx {
    const char* data;
    int dataSz;
    int offset;
    int maxChunk;
    int finalRet;
};

static int wolfio_http_test_io_cb(char* buf, int sz, void* ctx)
{
    struct wolfio_http_test_ctx* ioCtx = (struct wolfio_http_test_ctx*)ctx;
    int copySz;

    if (ioCtx == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ioCtx->offset >= ioCtx->dataSz)
        return ioCtx->finalRet;

    copySz = ioCtx->dataSz - ioCtx->offset;
    if (copySz > sz)
        copySz = sz;
    if (ioCtx->maxChunk > 0 && copySz > ioCtx->maxChunk)
        copySz = ioCtx->maxChunk;
    if (copySz <= 0)
        return WOLFSSL_FATAL_ERROR;

    XMEMCPY(buf, ioCtx->data + ioCtx->offset, (size_t)copySz);
    ioCtx->offset += copySz;
    return copySz;
}

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
    char urlName[80];
    char urlPath[80];
    word16 urlPort = 0;
    byte reqBuf[256];
    byte httpBuf[128];
    byte* httpResp = NULL;
    static const char* ocspAppStrList[] = {
        "application/ocsp-response",
        NULL
    };
    struct wolfio_http_test_ctx ioCtx;
    static const char validHttpResp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "abc";
    static const char headerEarlyEndResp[] =
        "HTTP/1.1 200 OK\r\n"
        "\r\n";

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

    /* Test response with CERT_UNKNOWN status */
    conf.resp = (unsigned char*)resp_cert_unknown;
    conf.respSz = sizeof(resp_cert_unknown);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, OCSP_CERT_UNKNOWN),
        TEST_SUCCESS);

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

    /* Truncated and empty responses should be rejected during decode. */
    conf.resp = (unsigned char*)resp;
    conf.respSz = sizeof(resp) - 1;
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, OCSP_LOOKUP_FAIL),
        TEST_SUCCESS);

    conf.resp = (unsigned char*)resp;
    conf.respSz = 0;
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, OCSP_LOOKUP_FAIL),
        TEST_SUCCESS);

    /* wolfio helpers used by OCSP/CRL lookup should reject malformed inputs
     * and accept a compact valid HTTP response. */
    XMEMSET(urlName, 0, sizeof(urlName));
    XMEMSET(urlPath, 0, sizeof(urlPath));
    ExpectIntEQ(wolfIO_DecodeUrl(NULL, 0, urlName, urlPath, &urlPort), -1);
    ExpectIntEQ(urlName[0], 0);
    ExpectIntEQ(urlPath[0], 0);
    ExpectIntEQ(urlPort, 0);
    ExpectIntEQ(wolfIO_DecodeUrl("http://example.com:abc/", 23,
        urlName, urlPath, &urlPort), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfIO_DecodeUrl("http://example.com/ocsp",
        (int)XSTRLEN("http://example.com/ocsp"), urlName, urlPath, &urlPort),
        0);
    ExpectBufEQ(urlName, "example.com", (int)sizeof("example.com"));
    ExpectBufEQ(urlPath, "/ocsp", (int)sizeof("/ocsp"));
    ExpectIntEQ(urlPort, 80);

    ExpectIntEQ(wolfIO_HttpBuildRequest("POST", "example.com", "/ocsp", 5, 3,
        "application/ocsp-request", reqBuf, 8), 0);
    ExpectIntGT(wolfIO_HttpBuildRequest("POST", "example.com", "/ocsp", 5, 3,
        "application/ocsp-request", reqBuf, (int)sizeof(reqBuf)), 0);

    XMEMSET(&ioCtx, 0, sizeof(ioCtx));
    ioCtx.data = validHttpResp;
    ioCtx.dataSz = (int)sizeof(validHttpResp) - 1;
    ioCtx.maxChunk = 7;
    ioCtx.finalRet = WOLFSSL_FATAL_ERROR;
    ExpectIntEQ(wolfIO_HttpProcessResponseGenericIO(wolfio_http_test_io_cb,
        &ioCtx, ocspAppStrList, &httpResp, httpBuf, (int)sizeof(httpBuf),
        DYNAMIC_TYPE_OCSP, NULL), 3);
    ExpectNotNull(httpResp);
    if (httpResp != NULL) {
        ExpectBufEQ(httpResp, "abc", 3);
        XFREE(httpResp, NULL, DYNAMIC_TYPE_OCSP);
        httpResp = NULL;
    }

    XMEMSET(&ioCtx, 0, sizeof(ioCtx));
    ioCtx.finalRet = WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ);
    ExpectIntEQ(wolfIO_HttpProcessResponseGenericIO(wolfio_http_test_io_cb,
        &ioCtx, ocspAppStrList, &httpResp, httpBuf, (int)sizeof(httpBuf),
        DYNAMIC_TYPE_OCSP, NULL), OCSP_WANT_READ);

    XMEMSET(&ioCtx, 0, sizeof(ioCtx));
    ioCtx.finalRet = WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_TIMEOUT);
    ExpectIntEQ(wolfIO_HttpProcessResponseGenericIO(wolfio_http_test_io_cb,
        &ioCtx, ocspAppStrList, &httpResp, httpBuf, (int)sizeof(httpBuf),
        DYNAMIC_TYPE_OCSP, NULL), HTTP_TIMEOUT);

    XMEMSET(&ioCtx, 0, sizeof(ioCtx));
    ioCtx.data = validHttpResp;
    ioCtx.dataSz = (int)sizeof(validHttpResp) - 3;
    ioCtx.finalRet = WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_TIMEOUT);
    ExpectIntEQ(wolfIO_HttpProcessResponseGenericIO(wolfio_http_test_io_cb,
        &ioCtx, ocspAppStrList, &httpResp, httpBuf, (int)sizeof(httpBuf),
        DYNAMIC_TYPE_OCSP, NULL), HTTP_TIMEOUT);

    XMEMSET(&ioCtx, 0, sizeof(ioCtx));
    ioCtx.data = headerEarlyEndResp;
    ioCtx.dataSz = (int)sizeof(headerEarlyEndResp) - 1;
    ioCtx.maxChunk = 9;
    ioCtx.finalRet = WOLFSSL_FATAL_ERROR;
    ExpectIntEQ(wolfIO_HttpProcessResponseGenericIO(wolfio_http_test_io_cb,
        &ioCtx, ocspAppStrList, &httpResp, httpBuf, (int)sizeof(httpBuf),
        DYNAMIC_TYPE_OCSP, NULL), HTTP_HEADER_ERR);
    return EXPECT_SUCCESS();
}
#else  /* HAVE_OCSP && !NO_SHA */
int test_ocsp_response_parsing(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && !NO_SHA */

int test_http_connect_blocking_mode(void)
{
#if (defined(HAVE_OCSP) || (defined(HAVE_CRL) && defined(HAVE_CRL_IO))) && \
    defined(HAVE_HTTP_CLIENT) && defined(HAVE_SOCKADDR) && \
    !defined(NO_ASN_TIME) && !defined(WOLFSSL_LWIP) && \
    !defined(WOLFSSL_NO_SOCK) && defined(SO_RCVTIMEO) && \
    defined(SO_SNDTIMEO) && (defined(__unix__) || defined(__APPLE__))
    EXPECT_DECLS;
    SOCKET_T listener = SOCKET_INVALID;
    SOCKET_T client = SOCKET_INVALID;
    SOCKADDR_IN addr;
    XSOCKLENT addrSz = (XSOCKLENT)sizeof(addr);
    int ret;
    int flags;

    listener = (SOCKET_T)socket(AF_INET, SOCK_STREAM, 0);
    ExpectTrue(listener != SOCKET_INVALID);
    if (listener != SOCKET_INVALID) {
        XMEMSET(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ret = XSOCKET_BIND(listener, (SOCKADDR*)&addr, sizeof(addr));
        ExpectIntEQ(ret, 0);
        if (ret == 0) {
            ret = XSOCKET_LISTEN(listener, 1);
            ExpectIntEQ(ret, 0);
        }
        if (ret == 0) {
            ret = getsockname(listener, (SOCKADDR*)&addr, &addrSz);
            ExpectIntEQ(ret, 0);
        }
        if (ret == 0) {
            ExpectIntEQ(wolfIO_TcpConnect(&client, "127.0.0.1",
                ntohs(addr.sin_port), 1), 0);
            if (client != SOCKET_INVALID) {
                flags = fcntl(client, F_GETFL, 0);
                ExpectTrue(flags >= 0);
                if (flags >= 0)
                    ExpectIntEQ(flags & O_NONBLOCK, 0);
            }
        }
    }
    if (client != SOCKET_INVALID)
        CloseSocket(client);
    if (listener != SOCKET_INVALID)
        CloseSocket(listener);
    return EXPECT_SUCCESS();
#else
    return TEST_SKIPPED;
#endif
}

#if defined(HAVE_OCSP) && !defined(NO_SHA) && !defined(NO_RSA) && \
    !defined(WOLFSSL_NO_OCSP_ISSUER_CHECK)
int test_ocsp_ancestor_responder_rejected(void)
{
    EXPECT_DECLS;
    struct test_conf conf;

    conf.resp = (unsigned char*)resp_server1_cert_ancestor_responder;
    conf.respSz = sizeof(resp_server1_cert_ancestor_responder);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = intermediate1_ca_cert_pem;
    conf.ca1Sz = sizeof(intermediate1_ca_cert_pem);
    conf.targetCert = server1_cert_pem;
    conf.targetCertSz = sizeof(server1_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, OCSP_LOOKUP_FAIL),
        TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_ocsp_ancestor_responder_rejected(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && !defined(NO_SHA) && !defined(NO_RSA)
/* The responder certificate embedded in an OCSP response must have its own
 * signature verified against the CA it claims issued it (RFC 6960 4.2.2.2:
 * the delegation certificate and the certificate being checked must be signed
 * by the same key). resp_forged_responder_cert carries a responder
 * certificate that names the legitimate root CA as its issuer and repeats
 * that CA's key identifier, so the signer lookup resolves to the real root
 * CA, but it was signed by the imposter root CA's key. Matching names and key
 * identifiers only select a candidate issuer; they do not authenticate one.
 * Nothing else about the response is wrong, so accepting it would mean the
 * responder certificate's signature was never checked. */
int test_ocsp_forged_responder_cert_rejected(void)
{
    EXPECT_DECLS;
    struct test_conf conf;

    conf.resp = (unsigned char*)resp_forged_responder_cert;
    conf.respSz = sizeof(resp_forged_responder_cert);
    conf.ca0 = root_ca_cert_pem;
    conf.ca0Sz = sizeof(root_ca_cert_pem);
    conf.ca1 = NULL;
    conf.ca1Sz = 0;
    conf.targetCert = intermediate1_ca_cert_pem;
    conf.targetCertSz = sizeof(intermediate1_ca_cert_pem);
    ExpectIntEQ(test_ocsp_response_with_cm(&conf, OCSP_LOOKUP_FAIL),
        TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_ocsp_forged_responder_cert_rejected(void)
{
    return TEST_SKIPPED;
}
#endif

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
    ExpectPtrEq(ptr, (const unsigned char*)resp + sizeof(resp));
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_NAME);
    ExpectBufEQ(response->responderId.nameHash, cert.subjectHash,
        OCSP_DIGEST_SIZE);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* responder Id by key hash */
    ptr = (const unsigned char*)resp_rid_bykey;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
                      sizeof(resp_rid_bykey)));
    ExpectPtrEq(ptr, (const unsigned char*)resp_rid_bykey +
        sizeof(resp_rid_bykey));
    ExpectIntEQ(response->responseStatus, 0);
    ExpectIntEQ(response->responderIdType, OCSP_RESPONDER_ID_KEY);
    ExpectBufEQ(response->responderId.keyHash, cert.subjectKeyHash,
        OCSP_RESPONDER_ID_KEY_SZ);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding with no embedded certificates */
    ptr = (const unsigned char*)resp_nocert;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_nocert)));
    ExpectPtrEq(ptr, (const unsigned char*)resp_nocert + sizeof(resp_nocert));
    ExpectIntEQ(response->responseStatus, 0);
    wolfSSL_OCSP_RESPONSE_free(response);

    /* decoding an invalid response */
    ptr = (const unsigned char*)resp_bad;
    ExpectNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp_bad)));

    /* reuse failure must clear caller pointer */
    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(&response, &ptr, sizeof(resp)));
    ptr = (const unsigned char*)resp_bad;
    ExpectNull(
        wolfSSL_d2i_OCSP_RESPONSE(&response, &ptr, sizeof(resp_bad)));
    ExpectNull(response);

    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp)));
    ExpectPtrEq(ptr, (const unsigned char*)resp + sizeof(resp));
    /* no verify signer certificate */
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, NULL, OCSP_NOVERIFY),
        WOLFSSL_SUCCESS);
    /* verify that the signature is checked */
    if (EXPECT_SUCCESS()) {
        ((byte *)(wc_ptr_t)response->sig)[0] ^= 0xff;
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
    ExpectPtrEq(ptr, (const unsigned char*)resp_nocert + sizeof(resp_nocert));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* cert embedded, verified using store */
    ptr = (const unsigned char*)resp;
    ExpectNotNull(
        response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr, sizeof(resp)));
    ExpectPtrEq(ptr, (const unsigned char*)resp + sizeof(resp));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, store, 0),
        WOLFSSL_SUCCESS);
    /* make invalid signature */
    if (EXPECT_SUCCESS()) {
        ((byte *)(wc_ptr_t)response->sig)[0] ^= 0xff;
    }
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, NULL, store, 0),
        WOLFSSL_FAILURE);
    if (EXPECT_SUCCESS()) {
        ((byte *)(wc_ptr_t)response->sig)[0] ^= 0xff;
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
    ExpectPtrEq(ptr, (const unsigned char*)resp_nocert + sizeof(resp_nocert));
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
    ExpectPtrEq(ptr, (const unsigned char*)resp_multi + sizeof(resp_multi));
    ExpectIntEQ(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_OCSP_RESPONSE_free(response);
    response = NULL;

    /* cert in certs, cert verified on store, not authorized to verify all
     * responses */
    ptr = (const unsigned char*)resp_bad_noauth;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
                      sizeof(resp_bad_noauth)));
    ExpectPtrEq(ptr, (const unsigned char*)resp_bad_noauth +
        sizeof(resp_bad_noauth));

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

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(HAVE_OCSP) && \
    !defined(NO_RSA) && !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
/* The OCSP nonce configured on a context is drawn once, so reusing it would
 * put the same value in the clear in every ClientHello from that context - a
 * stable identifier for the process - and would stop binding one OCSP
 * response to one handshake. Each connection must draw its own. */
int test_ocsp_ctx_stapling_nonce_per_connection(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    byte ctxNonce[MAX_OCSP_NONCE_SZ];
    byte nonce[2][MAX_OCSP_NONCE_SZ];
    TLSX* ext = NULL;
    CertificateStatusRequest* csr = NULL;
    int i;

    XMEMSET(ctxNonce, 0, sizeof(ctxNonce));
    XMEMSET(nonce, 0, sizeof(nonce));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_CTX_UseOCSPStapling(ctx_c, WOLFSSL_CSR_OCSP,
        WOLFSSL_CSR_OCSP_USE_NONCE), WOLFSSL_SUCCESS);

    /* The nonce the context holds. */
    ExpectNotNull(ext = TLSX_Find(ctx_c == NULL ? NULL : ctx_c->extensions,
        TLSX_STATUS_REQUEST));
    if (ext != NULL) {
        csr = (CertificateStatusRequest*)ext->data;
        ExpectNotNull(csr);
        if (csr != NULL) {
            ExpectIntEQ(csr->request.ocsp[0].nonceSz, MAX_OCSP_NONCE_SZ);
            XMEMCPY(ctxNonce, csr->request.ocsp[0].nonce, MAX_OCSP_NONCE_SZ);
        }
    }

    for (i = 0; i < 2; i++) {
        if (i > 0) {
            ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
            wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
            wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
        }
        /* Only the ClientHello is needed; there is no server to answer. */
        ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);

        ext = TLSX_Find(ssl_c == NULL ? NULL : ssl_c->extensions,
            TLSX_STATUS_REQUEST);
        ExpectNotNull(ext);
        if (ext != NULL) {
            csr = (CertificateStatusRequest*)ext->data;
            ExpectNotNull(csr);
            if (csr != NULL) {
                ExpectIntEQ(csr->request.ocsp[0].nonceSz, MAX_OCSP_NONCE_SZ);
                XMEMCPY(nonce[i], csr->request.ocsp[0].nonce,
                    MAX_OCSP_NONCE_SZ);
            }
        }
        wolfSSL_free(ssl_c);
        ssl_c = NULL;
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);
    }

    ExpectIntNE(XMEMCMP(nonce[0], nonce[1], MAX_OCSP_NONCE_SZ), 0);
    ExpectIntNE(XMEMCMP(nonce[0], ctxNonce, MAX_OCSP_NONCE_SZ), 0);
    ExpectIntNE(XMEMCMP(nonce[1], ctxNonce, MAX_OCSP_NONCE_SZ), 0);

    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#else
int test_ocsp_ctx_stapling_nonce_per_connection(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST && HAVE_OCSP */

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && defined(HAVE_OCSP) && \
    !defined(NO_RSA) && !defined(NO_FILESYSTEM) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
/* Same for status_request_v2, which differs in that the context holds a list:
 * the connection level list replaces the context one on the wire, so every
 * item has to be copied and every item needs its own fresh nonce. */
int test_ocsp_ctx_stapling_v2_nonce_per_connection(void)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    byte ctxNonce[2][MAX_OCSP_NONCE_SZ];
    byte nonce[2][2][MAX_OCSP_NONCE_SZ];
    byte ctxTypes[2];
    TLSX* ext = NULL;
    CertificateStatusRequestItemV2* csr2 = NULL;
    int ctxItems = 0;
    int i;
    int j;

    XMEMSET(ctxNonce, 0, sizeof(ctxNonce));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(ctxTypes, 0, sizeof(ctxTypes));

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* Two items of different status types, so the copy has to preserve both
     * the list length and each item's type. */
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStaplingV2(ctx_c, WOLFSSL_CSR2_OCSP_MULTI,
        WOLFSSL_CSR2_OCSP_USE_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_UseOCSPStaplingV2(ctx_c, WOLFSSL_CSR2_OCSP,
        WOLFSSL_CSR2_OCSP_USE_NONCE), WOLFSSL_SUCCESS);

    /* What the context holds. */
    ExpectNotNull(ext = TLSX_Find(ctx_c == NULL ? NULL : ctx_c->extensions,
        TLSX_STATUS_REQUEST_V2));
    if (ext != NULL) {
        for (csr2 = (CertificateStatusRequestItemV2*)ext->data;
                (csr2 != NULL) && (ctxItems < 2); csr2 = csr2->next) {
            ExpectIntEQ(csr2->request.ocsp[0].nonceSz, MAX_OCSP_NONCE_SZ);
            XMEMCPY(ctxNonce[ctxItems], csr2->request.ocsp[0].nonce,
                MAX_OCSP_NONCE_SZ);
            ctxTypes[ctxItems] = csr2->status_type;
            ctxItems++;
        }
    }
    ExpectIntEQ(ctxItems, 2);

    for (i = 0; i < 2; i++) {
        int items = 0;

        if (i > 0) {
            ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
            wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
            wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
        }
        /* Only the ClientHello is needed; there is no server to answer. */
        ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);

        ext = TLSX_Find(ssl_c == NULL ? NULL : ssl_c->extensions,
            TLSX_STATUS_REQUEST_V2);
        ExpectNotNull(ext);
        if (ext != NULL) {
            for (csr2 = (CertificateStatusRequestItemV2*)ext->data;
                    (csr2 != NULL) && (items < 2); csr2 = csr2->next) {
                ExpectIntEQ(csr2->request.ocsp[0].nonceSz, MAX_OCSP_NONCE_SZ);
                XMEMCPY(nonce[i][items], csr2->request.ocsp[0].nonce,
                    MAX_OCSP_NONCE_SZ);
                /* Every item of the context list is copied, in order. */
                ExpectIntEQ(csr2->status_type, ctxTypes[items]);
                items++;
            }
        }
        /* Both items, not just the head. */
        ExpectIntEQ(items, 2);

        wolfSSL_free(ssl_c);
        ssl_c = NULL;
        test_memio_clear_buffer(&test_ctx, 0);
        test_memio_clear_buffer(&test_ctx, 1);
    }

    for (i = 0; i < 2; i++) {
        /* Fresh on each connection, and not the context's. */
        ExpectIntNE(XMEMCMP(nonce[0][i], nonce[1][i], MAX_OCSP_NONCE_SZ), 0);
        for (j = 0; j < 2; j++) {
            ExpectIntNE(XMEMCMP(nonce[j][i], ctxNonce[i], MAX_OCSP_NONCE_SZ),
                0);
        }
    }

    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#else
int test_ocsp_ctx_stapling_v2_nonce_per_connection(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 && HAVE_OCSP */

#if defined(HAVE_OCSP) && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(NO_RSA)
/* Decoding into an existing OCSP_RESPONSE releases the buffer the previous
 * encoding was parsed from. Every reference into it (response, cert, sig,
 * sigParams, nonce) has to go with it: the new encoding only sets the ones it
 * carries, so a leftover reference is read from freed memory - a later
 * OCSP_check_nonce() verdict, for instance, would come from the old buffer. */
int test_ocsp_d2i_reuse_clears_refs(void)
{
    EXPECT_DECLS;
    const unsigned char* ptr = NULL;
    OcspResponse* response = NULL;

    /* resp carries an embedded responder certificate. */
    ptr = (const unsigned char*)resp;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
        sizeof(resp)));
    ExpectNotNull(response == NULL ? NULL : response->cert);
    ExpectIntGT(response == NULL ? 0 : (int)response->certSz, 0);

    /* resp_nocert does not, so nothing sets cert again. */
    ptr = (const unsigned char*)resp_nocert;
    ExpectNotNull(wolfSSL_d2i_OCSP_RESPONSE(&response, &ptr,
        sizeof(resp_nocert)));
    if (EXPECT_SUCCESS()) {
        ExpectNull(response->cert);
        ExpectIntEQ((int)response->certSz, 0);
        ExpectNull(response->nonce);
        ExpectIntEQ(response->nonceSz, 0);
        ExpectNull(response->sigParams);
        ExpectIntEQ((int)response->sigParamsSz, 0);
        /* What the new encoding does set must point into the new buffer. */
        ExpectNotNull(response->response);
        ExpectTrue((response->response >= response->source) &&
            (response->response < response->source + response->maxIdx));
        ExpectNotNull(response->sig);
        ExpectTrue((response->sig >= response->source) &&
            (response->sig < response->source + response->maxIdx));
    }

    wolfSSL_OCSP_RESPONSE_free(response);
    return EXPECT_RESULT();
}
#else
int test_ocsp_d2i_reuse_clears_refs(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP  && (OPENSSL_ALL || OPENSSL_EXTRA) */

#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) && \
    defined(HAVE_OCSP) && \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && !defined(NO_RSA)
static long ocsp_reuse_live = 0;

static void* ocsp_reuse_malloc(size_t size)
{
    void* p = malloc(size);
    if (p != NULL)
        ocsp_reuse_live++;
    return p;
}

static void ocsp_reuse_free(void* ptr)
{
    if (ptr != NULL)
        ocsp_reuse_live--;
    free(ptr);
}

static void* ocsp_reuse_realloc(void* ptr, size_t size)
{
    void* p = realloc(ptr, size);
    if ((p != NULL) && (ptr == NULL))
        ocsp_reuse_live++;
    return p;
}

/* Decoding into an existing OCSP_RESPONSE has to release the whole
 * SingleResponse chain the previous decode built. FreeOcspEntry() on its own
 * frees the head entry's CertStatus chain and nothing else, so every
 * SingleResponse after the first used to be leaked on each reuse - an OCSP
 * poller that refreshes into one object grows without bound. */
int test_ocsp_d2i_reuse_frees_single_chain(void)
{
    EXPECT_DECLS;
    wolfSSL_Malloc_cb prevM = NULL;
    wolfSSL_Free_cb prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;
    const unsigned char* ptr = NULL;
    OcspResponse* response = NULL;
    OcspEntry* s = NULL;
    long afterFirst = 0;
    int singles = 0;
    int i;

    ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(ocsp_reuse_malloc, ocsp_reuse_free,
        ocsp_reuse_realloc), 0);

    /* resp_multi carries more than one SingleResponse. */
    ptr = (const unsigned char*)resp_multi;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
        sizeof(resp_multi)));
    if (response != NULL) {
        for (s = response->single; s != NULL; s = s->next)
            singles++;
    }
    ExpectIntGT(singles, 1);
    afterFirst = ocsp_reuse_live;

    /* Each reuse must end up holding exactly what the first decode held. */
    for (i = 0; EXPECT_SUCCESS() && (i < 4); i++) {
        ptr = (const unsigned char*)resp_multi;
        ExpectNotNull(wolfSSL_d2i_OCSP_RESPONSE(&response, &ptr,
            sizeof(resp_multi)));
        ExpectIntEQ((int)(ocsp_reuse_live - afterFirst), 0);
    }

    wolfSSL_OCSP_RESPONSE_free(response);
    (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    return EXPECT_RESULT();
}
#else
int test_ocsp_d2i_reuse_frees_single_chain(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(NO_RSA) && !defined(WOLFSSL_NO_OCSP_ISSUER_CHECK)
/* Verify that OCSP responder authorization is bound to BOTH halves of the
 * CertID (issuerNameHash AND issuerKeyHash). The forged response in
 * resp_certid_keyhash_mismatch was signed by the legitimate ocsp-responder
 * (so the response signature itself verifies) but its CertID pairs the
 * legitimate root CA's name hash with the imposter root CA's key hash. With
 * a name-only authorization check the response would be incorrectly
 * accepted; the CertID-bound check must reject it. */
int test_ocsp_responder_keyhash_binding(void)
{
    EXPECT_DECLS;
    WOLF_STACK_OF(WOLFSSL_X509)* certs = NULL;
    WOLFSSL_X509_STORE* store = NULL;
    const unsigned char* ptr = NULL;
    OcspResponse* response = NULL;

    ExpectIntEQ(test_ocsp_create_x509store(&store, root_ca_cert_pem,
                    sizeof(root_ca_cert_pem)),
        TEST_SUCCESS);
    ExpectIntEQ(test_create_stack_of_x509(&certs, ocsp_responder_cert_pem,
                    sizeof(ocsp_responder_cert_pem)),
        TEST_SUCCESS);

    ptr = (const unsigned char*)resp_certid_keyhash_mismatch;
    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
                      sizeof(resp_certid_keyhash_mismatch)));
    ExpectIntNE(wolfSSL_OCSP_basic_verify(response, certs, store, 0),
        WOLFSSL_SUCCESS);

    wolfSSL_OCSP_RESPONSE_free(response);
    wolfSSL_sk_X509_pop_free(certs, wolfSSL_X509_free);
    wolfSSL_X509_STORE_free(store);
    return EXPECT_RESULT();
}
#else
int test_ocsp_responder_keyhash_binding(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) &&     \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  \
    defined(OPENSSL_ALL) && !defined(WOLFSSL_SMALL_CERT_VERIFY)

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

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) &&        \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  \
    defined(OPENSSL_ALL) && !defined(WOLFSSL_SMALL_CERT_VERIFY) &&             \
    defined(HAVE_SECURE_RENEGOTIATION)
/* A CertificateStatus sent during a renegotiation goes out encrypted. The
 * length handed to the record layer then has to be the handshake body alone,
 * with none of the cipher expansion slack the send buffer carries. */
int test_ocsp_status_request_scr(void)
{
    EXPECT_DECLS;
    const char* responseFile = "./certs/ocsp/test-leaf-response.der";
    struct _test_ocsp_status_callback_ctx cb_ctx;
    struct test_ssl_memio_ctx test_ctx;
    XFILE f = XBADFILE;
    byte data[4096];
    char readBuf[16];

    XMEMSET(&cb_ctx, 0, sizeof(cb_ctx));
    /* Zeroed here, not just in the setup helper: the Expect macros below stop
     * running once one fails, and the cleanup at the end is unconditional. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectTrue((f = XFOPEN(responseFile, "rb")) != XBADFILE);
    if (f != XBADFILE) {
        cb_ctx.ocsp_resp_sz = (int)XFREAD(data, 1, sizeof(data), f);
        XFCLOSE(f);
    }
    cb_ctx.ocsp_resp = data;
    ExpectIntGT(cb_ctx.ocsp_resp_sz, 0);

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
    ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(test_ctx.c_ssl),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(test_ctx.s_ssl),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(cb_ctx.invoked, 1);

    /* Renegotiate. The second CertificateStatus is the encrypted one. */
    ExpectIntEQ(wolfSSL_Rehandshake(test_ctx.c_ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, -1),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(test_ctx.s_ssl, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.s_ssl, -1),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL), TEST_SUCCESS);
    ExpectIntEQ(cb_ctx.invoked, 2);

    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}
#else
int test_ocsp_status_request_scr(void)
{
    return TEST_SKIPPED;
}
#endif

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
int test_ocsp_certid_dup(void)
{
    EXPECT_DECLS;
    WOLFSSL_OCSP_CERTID* certId = NULL;
    WOLFSSL_OCSP_CERTID* certIdDup = NULL;
    WOLFSSL_X509* subject = NULL;
    WOLFSSL_X509* issuer = NULL;

    /* Load test certificates */
    ExpectNotNull(
        subject = wolfSSL_X509_load_certificate_file(
            "./certs/ocsp/intermediate1-ca-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(issuer = wolfSSL_X509_load_certificate_file(
                      "./certs/ocsp/root-ca-cert.pem", WOLFSSL_FILETYPE_PEM));

    /* Create CERTID from certificates */
    ExpectNotNull(certId = wolfSSL_OCSP_cert_to_id(NULL, subject, issuer));

    /* Dup */
    ExpectNotNull(certIdDup = wolfSSL_OCSP_CERTID_dup(certId));

    /* Verify the dup compares equal */
    ExpectIntEQ(wolfSSL_OCSP_id_cmp(certId, certIdDup), 0);

    /* Verify status is a distinct allocation (deep copy) */
    ExpectPtrNE(certId->status, certIdDup->status);

    /* Freeing both must not double-free (ASAN will catch it) */
    wolfSSL_OCSP_CERTID_free(certId);
    wolfSSL_OCSP_CERTID_free(certIdDup);

    wolfSSL_X509_free(subject);
    wolfSSL_X509_free(issuer);
    return EXPECT_SUCCESS();
}

#else /* !NO_SHA && OPENSSL_ALL && HAVE_OCSP && !WOLFSSL_SM3 && !WOLFSSL_SM2 */
int test_ocsp_certid_enc_dec(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_certid_dup(void)
{
    return TEST_SKIPPED;
}
#endif

int test_ocsp_resp_find_status_serial_prefix(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA) && !defined(NO_SHA)
    OcspResponse response;
    OcspEntry    single;
    CertStatus   responseStatus;
    OcspEntry    requestedId;
    CertStatus   requestedStatus;
    int          status;
    WOLFSSL_ASN1_TIME* thisupd = NULL;
    WOLFSSL_ASN1_TIME* nextupd = NULL;

    XMEMSET(&response, 0, sizeof(response));
    XMEMSET(&single, 0, sizeof(single));
    XMEMSET(&responseStatus, 0, sizeof(responseStatus));
    XMEMSET(&requestedId, 0, sizeof(requestedId));
    XMEMSET(&requestedStatus, 0, sizeof(requestedStatus));

    single.status   = &responseStatus;
    requestedId.status = &requestedStatus;
    response.single  = &single;

    /* Matching issuer name and key hashes on both sides. */
    XMEMSET(single.issuerHash, 0x41, OCSP_DIGEST_SIZE);
    XMEMSET(single.issuerKeyHash, 0x42, OCSP_DIGEST_SIZE);
    XMEMCPY(requestedId.issuerHash, single.issuerHash, OCSP_DIGEST_SIZE);
    XMEMCPY(requestedId.issuerKeyHash, single.issuerKeyHash, OCSP_DIGEST_SIZE);

    /* Response carries a CERT_GOOD status for serial 01:02 (2 bytes). */
    responseStatus.serial[0] = 0x01;
    responseStatus.serial[1] = 0x02;
    responseStatus.serialSz  = 2;
    responseStatus.status    = CERT_GOOD;

    /* Sanity check: an exact serial match must be found and report CERT_GOOD. */
    requestedStatus.serial[0] = 0x01;
    requestedStatus.serial[1] = 0x02;
    requestedStatus.serialSz  = 2;
    status = -1;
    ExpectIntEQ(wolfSSL_OCSP_resp_find_status(&response, &requestedId, &status,
                    NULL, NULL, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(status, CERT_GOOD);

    /* No update times parsed: both must come back NULL. */
    ExpectIntEQ(wolfSSL_OCSP_resp_find_status(&response, &requestedId, &status,
                    NULL, NULL, &thisupd, &nextupd), WOLFSSL_SUCCESS);
    ExpectNull(thisupd);
    ExpectNull(nextupd);
#ifdef WOLFSSL_OCSP_PARSE_STATUS
    /* thisUpdate present, nextUpdate absent. */
    responseStatus.thisDateParsed.length = 15;
    nextupd = &responseStatus.nextDateParsed;
    ExpectIntEQ(wolfSSL_OCSP_resp_find_status(&response, &requestedId, &status,
                    NULL, NULL, &thisupd, &nextupd), WOLFSSL_SUCCESS);
    ExpectPtrEq(thisupd, &responseStatus.thisDateParsed);
    ExpectNull(nextupd);
#endif

    /* Request serial 01:02:03 (3 bytes) shares the 01:02 prefix of the
     * response serial.
     * The lookup must not bind the good response to this longer and
     * differing serial. */
    requestedStatus.serial[0] = 0x01;
    requestedStatus.serial[1] = 0x02;
    requestedStatus.serial[2] = 0x03;
    requestedStatus.serialSz  = 3;
    status = -1;
    ExpectIntEQ(wolfSSL_OCSP_resp_find_status(&response, &requestedId, &status,
                    NULL, NULL, NULL, NULL), WOLFSSL_FAILURE);
#endif
    return EXPECT_RESULT();
}

/* The test responses carry thisUpdate only. */
int test_ocsp_resp_times(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA) && !defined(NO_SHA) && \
    !defined(NO_RSA)
    const unsigned char* ptr = (const unsigned char*)resp;
    OcspResponse* response = NULL;
    WOLFSSL_OCSP_BASICRESP* bs = NULL;
    WOLFSSL_OCSP_SINGLERESP* single = NULL;
    WOLFSSL_ASN1_TIME* thisupd = NULL;
    WOLFSSL_ASN1_TIME* nextupd = NULL;
    int reason = -1;

    ExpectNotNull(response = wolfSSL_d2i_OCSP_RESPONSE(NULL, &ptr,
        sizeof(resp)));
    ExpectNotNull(bs = wolfSSL_OCSP_response_get1_basic(response));
    ExpectNotNull(single = wolfSSL_OCSP_resp_get0(bs, 0));
    ExpectIntEQ(wolfSSL_OCSP_single_get0_status(single, &reason, NULL,
        &thisupd, &nextupd), CERT_GOOD);
#ifdef WOLFSSL_OCSP_PARSE_STATUS
    ExpectNotNull(thisupd);
    if (thisupd != NULL) {
        ExpectIntEQ(thisupd->type, ASN_GENERALIZED_TIME);
        ExpectIntGT(thisupd->length, 0);
    }
#else
    ExpectNull(thisupd);
#endif
    ExpectNull(nextupd);

    wolfSSL_OCSP_BASICRESP_free(bs);
    wolfSSL_OCSP_RESPONSE_free(response);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_OCSP) && defined(WOLFSSL_CERT_SETUP_CB) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA) && \
    (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && \
    defined(SESSION_CERTS)

static struct {
    size_t chainLen;
    byte failStaple:2;
} test_ocsp_tls_cert_cb_opts;
/* --- certificate-selection callback ----------------------------------- */
static int test_ocsp_tls_cert_cb_cert_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    switch (test_ocsp_tls_cert_cb_opts.chainLen) {
        case 1:
            if (wolfSSL_use_certificate_file(ssl,
                    "./certs/ocsp/server1-cert.pem", WOLFSSL_FILETYPE_PEM)
                    != WOLFSSL_SUCCESS)
                return 0;
            break;
        case 2: {
            /* We need to limit the buffer to only the leaf and int certs */
            byte* buf = NULL;
            size_t bufLen = 0;
            byte* lastCert = NULL;
            byte loaded = 0;

            if (wc_FileLoad("./certs/ocsp/server1-cert.pem", &buf, &bufLen,
                    NULL) != 0)
                return 0;
            /* Find the last cert */
            lastCert = (byte*)XSTRNSTR((char*)buf,
                    "-----BEGIN CERTIFICATE-----", (unsigned int)bufLen);
            if (lastCert != NULL) {
                lastCert = (byte*)XSTRNSTR((char*)lastCert + 1,
                        "-----BEGIN CERTIFICATE-----",
                        (unsigned int)(bufLen - (lastCert - buf)));
            }
            if (lastCert != NULL) {
                lastCert = (byte*)XSTRNSTR((char*)lastCert + 1,
                        "-----BEGIN CERTIFICATE-----",
                        (unsigned int)(bufLen - (lastCert - buf)));
            }
            if (lastCert != NULL) {
                if (wolfSSL_use_certificate_chain_buffer(ssl, buf, lastCert - buf)
                        == WOLFSSL_SUCCESS)
                    loaded = 1;
            }
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (!loaded)
                return 0;
            break;
        }
        case 3:
            if (wolfSSL_use_certificate_chain_file(ssl,
                    "./certs/ocsp/server1-cert.pem")
                    != WOLFSSL_SUCCESS)
                return 0;
            break;
    }
    if (wolfSSL_use_PrivateKey_file(ssl,
            "./certs/ocsp/server1-key.pem",  WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS)
        return 0;
    return 1;  /* success */
}

static int test_ocsp_tls_cert_cb_status_cb(WOLFSSL* ssl, void* ioCtx)
{
    byte* leaf_resp = NULL;
    byte* int_resp = NULL;
    byte* root_resp = NULL;
    int ret = WOLFSSL_OCSP_STATUS_CB_ALERT_FATAL;
    (void)ioCtx;
    leaf_resp = (byte*)XMALLOC(sizeof(resp_server1_cert), NULL, 0);
    int_resp = (byte*)XMALLOC(sizeof(resp_intermediate1_cert), NULL, 0);
    root_resp = (byte*)XMALLOC(sizeof(resp_root_ca_cert), NULL, 0);
    if (leaf_resp != NULL && int_resp != NULL && root_resp != NULL) {
        XMEMCPY(leaf_resp, resp_server1_cert, sizeof(resp_server1_cert));
        XMEMCPY(int_resp, resp_intermediate1_cert, sizeof(resp_intermediate1_cert));
        XMEMCPY(root_resp, resp_root_ca_cert, sizeof(resp_root_ca_cert));
        /* 320 is inside the signature so flipping bits should cause errors */
        switch (test_ocsp_tls_cert_cb_opts.failStaple) {
            case 1:
                leaf_resp[320] = ~leaf_resp[320];
                break;
            case 2:
                int_resp[320] = ~int_resp[320];
                break;
            case 3:
                root_resp[320] = ~root_resp[320];
                break;
        }
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, leaf_resp,
                sizeof(resp_server1_cert), 0) == WOLFSSL_SUCCESS)
            leaf_resp = NULL;
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, int_resp,
                sizeof(resp_intermediate1_cert), 1) == WOLFSSL_SUCCESS)
            int_resp = NULL;
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, root_resp,
                sizeof(resp_root_ca_cert), 2) == WOLFSSL_SUCCESS)
            root_resp = NULL;
        /* If all responses loaded then return OK */
        if (leaf_resp == NULL && int_resp == NULL && root_resp == NULL)
            ret = WOLFSSL_OCSP_STATUS_CB_OK;
    }
    XFREE(leaf_resp, NULL, 0);
    XFREE(int_resp, NULL, 0);
    XFREE(root_resp, NULL, 0);
    return ret;
}

static int test_ocsp_tls_cert_cb_verify_cb(int preverify,
        WOLFSSL_X509_STORE_CTX* store)
{
    int ret = 1;
    int err = wolfSSL_X509_STORE_CTX_get_error(store);
    int idx = wolfSSL_X509_STORE_CTX_get_error_depth(store);

    if (err == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E) ||
            err == WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E)
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
            || err == WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            || err == WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
#endif
            ) {
        WOLFSSL_BUFFER_INFO* bInfo = &store->certs[idx];
        WOLFSSL_CERT_MANAGER* cm = NULL;
        DecodedCert cert;
        byte certInit = 0;

        ret = 1;
        cm = wolfSSL_CertManagerNew();
        if (cm == NULL)
            ret = 0;
        if (ret == 1 &&
            wolfSSL_CertManagerLoadCA(cm, "./certs/ocsp/root-ca-cert.pem", NULL)
                != WOLFSSL_SUCCESS)
            ret = 0;
        /* If verifying leaf cert then we need to load the intermediate CA */
        if (ret == 1 && idx == 0 &&
            wolfSSL_CertManagerLoadCA(cm, "./certs/ocsp/intermediate1-ca-cert.pem", NULL)
                != WOLFSSL_SUCCESS)
            ret = 0;

        /* Verify cert with CA */
        if (ret == 1) {
            wc_InitDecodedCert(&cert, bInfo->buffer, bInfo->length, NULL);
            certInit = 1;
        }
        if (ret == 1 && wc_ParseCert(&cert, CERT_TYPE, VERIFY, cm) != 0)
            ret = 0;

        if (certInit)
            wc_FreeDecodedCert(&cert);
        wolfSSL_CertManagerFree(cm);
    }
    (void)preverify;
    return ret;
}

static int test_ocsp_tls_cert_cb_ocsp_verify_cb(WOLFSSL* ssl, int err,
        byte* staple, word32 stapleSz, word32 idx, void* arg)
{
    (void)ssl;
    (void)arg;
    if (err != 0) {
        WOLFSSL_CERT_MANAGER* cm = NULL;
        DecodedCert cert;
        byte certInit = 0;
        WOLFSSL_OCSP* ocsp = NULL;
        WOLFSSL_X509_CHAIN* peerCerts;

        cm = wolfSSL_CertManagerNew();
        if (cm == NULL)
            goto cleanup;
        if (wolfSSL_CertManagerLoadCA(cm, "./certs/ocsp/root-ca-cert.pem", NULL)
                != WOLFSSL_SUCCESS)
            goto cleanup;
        /* If verifying leaf cert then we need to load the intermediate CA */
        if (idx == 0 && wolfSSL_CertManagerLoadCA(cm,
                "./certs/ocsp/intermediate1-ca-cert.pem", NULL)
                != WOLFSSL_SUCCESS)
            goto cleanup;

        peerCerts = wolfSSL_get_peer_chain(ssl);
        if (peerCerts == NULL || wolfSSL_get_chain_count(peerCerts) <= (int)idx
                || wolfSSL_get_chain_length(peerCerts, (int)idx) == 0)
            goto cleanup;

        /* Verify cert with CA */
        wc_InitDecodedCert(&cert, wolfSSL_get_chain_cert(peerCerts, idx),
                wolfSSL_get_chain_length(peerCerts, idx), NULL);
        certInit = 1;
        if (wc_ParseCert(&cert, CERT_TYPE, VERIFY, cm) != 0)
            goto cleanup;
        if ((ocsp = wc_NewOCSP(cm)) == NULL)
            goto cleanup;
        if (wc_CheckCertOcspResponse(ocsp, &cert, staple, stapleSz, NULL) != 0)
            goto cleanup;

        err = 0;
cleanup:
        wc_FreeOCSP(ocsp);
        if (certInit)
            wc_FreeDecodedCert(&cert);
        wolfSSL_CertManagerFree(cm);
    }
    return err;
}

static int test_ocsp_tls_cert_cb_ctx_ready(WOLFSSL_CTX* ctx)
{
    /* server: dynamic cert */
    wolfSSL_CTX_set_cert_cb(ctx, test_ocsp_tls_cert_cb_cert_cb, NULL);
    return TEST_SUCCESS;
}

/* --- very small OCSP-status callback ---------------------------------- */
/* no status callback path - context struct not needed */

/* --- the actual test case --------------------------------------------- */
int test_ocsp_tls_cert_cb(void)
{
    EXPECT_DECLS;
    size_t i, j, chainLen;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
        byte useV2:1;
        byte useV2multi:1;
        byte maxFail:2;
    } params[] = {
#if !defined(WOLFSSL_NO_TLS12)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 0, 0, 1 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 1, 0, 1 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 1, 1, 1 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 0, 0, 1 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 1, 0, 1 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2", 1, 1, 3 },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 0, 0, 1 },
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 1, 0, 1 },
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 1, 1, 1 },
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 0, 0, 1 },
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 1, 0, 1 },
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2", 1, 1, 3 },
#endif
#endif
#ifdef WOLFSSL_TLS13
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3", 0, 0, 3 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, "TLSv1_3", 0, 0, 1 },
#ifdef WOLFSSL_DTLS13
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3", 0, 0, 3 },
        { wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, "DTLSv1_3", 0, 0, 1 },
#endif
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        printf("\nTesting %s\n", params[i].tls_version);
        for (chainLen = 1; chainLen <= 3 && !EXPECT_FAIL(); chainLen++) {
            printf("\tWith chain length %zu\n", chainLen);
            /* 0   - all staples valid
             * 1-3 - break the corresponding staple */
            for (j = 0; j <= params[i].maxFail && j <= chainLen && !EXPECT_FAIL(); j++) {
                struct test_ssl_memio_ctx test_ctx;
                byte skip = 0;

                test_ocsp_tls_cert_cb_opts.failStaple = j;
                printf("\t%s (%zu)", j ? "with failing staple" : "correct staple", j);

                XMEMSET(&test_ctx, 0, sizeof(test_ctx));
                test_ctx.c_cb.caPemFile  = "";
                /* Do NOT preload any cert/key into the server context: leave empty strings
                   so that ctx setup code skips loading them entirely and the only cert
                   comes from the per-connection callback below. */
                test_ctx.s_cb.certPemFile = "";  /* nothing pre-loaded */
                test_ctx.s_cb.keyPemFile  = "";

                test_ctx.c_cb.method = params[i].client_meth;
                test_ctx.s_cb.method = params[i].server_meth;

                test_ocsp_tls_cert_cb_opts.chainLen = chainLen;

                test_ctx.s_cb.ctx_ready = test_ocsp_tls_cert_cb_ctx_ready;

                ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);

                /* Unload the certificate that test helpers may have put into the server
                   SSL object - we want the server to *not* have any certificate at the
                   moment it parses ClientHello so that the early OCSP code path fails. */
                ExpectIntEQ(wolfSSL_UnloadCertsKeys(test_ctx.s_ssl), WOLFSSL_SUCCESS);

                /* turn on OCSP stapling on the server side */
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.s_ctx), WOLFSSL_SUCCESS);
                ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                        test_ocsp_tls_cert_cb_status_cb), WOLFSSL_SUCCESS);

                /* client: request stapling */
                wolfSSL_set_verify(test_ctx.c_ssl, WOLFSSL_VERIFY_DEFAULT,
                        test_ocsp_tls_cert_cb_verify_cb);
                wolfSSL_CTX_set_ocsp_status_verify_cb(test_ctx.c_ctx,
                        test_ocsp_tls_cert_cb_ocsp_verify_cb, NULL);

                /* Set the ssl object as the cert callback context as there is
                 * no way to get ssl from the store without OPENSSL_EXTRA */
                wolfSSL_SetCertCbCtx(test_ctx.c_ssl, test_ctx.c_ssl);
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx), WOLFSSL_SUCCESS);
                ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(test_ctx.c_ctx), WOLFSSL_SUCCESS);
                if (params[i].useV2) {
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                    printf("\twith V2 %s\n", params[i].useV2multi ? "multi" : "single");
                    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                            params[i].useV2multi ?
                                    WOLFSSL_CSR2_OCSP_MULTI : WOLFSSL_CSR2_OCSP,
                                    WOLFSSL_CSR2_OCSP_USE_NONCE),
                            WOLFSSL_SUCCESS);
    #else
                    skip = 1;
    #endif
                }
                else {
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                    printf("\twith V1\n");
                    ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                            WOLFSSL_CSR_OCSP, 0),
                            WOLFSSL_SUCCESS);
    #else
                    skip = 1;
    #endif
                }

                if (!skip) {
                    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                            j == 0 ? TEST_SUCCESS : TEST_FAIL);
                    if (j != 0) {
                        WOLFSSL_ALERT_HISTORY h;
                        XMEMSET(&h, 0, sizeof(h));
                        ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
                                WOLFSSL_SUCCESS);
                        ExpectIntEQ(h.last_rx.level, alert_fatal);
                        ExpectIntEQ(h.last_rx.code, bad_certificate_status_response);
                    }
                }
                else {
                    /* coverity[deadcode] - skip is only set for some build configs */
                    printf("\tskipping test case\n");
                }

                test_ssl_memio_cleanup(&test_ctx);
            }
        }
    }

    return EXPECT_RESULT();
}

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12)
/* Stapling for a 3-cert chain. The intermediate and root staples are the
 * normal single-SingleResponse CERT_GOOD responses, but the leaf (idx 0)
 * staple is resp_server1_revoked_good_first: one validly-signed
 * BasicOCSPResponse that bundles a benign CERT_GOOD single FIRST and the
 * server1 leaf cert's CERT_REVOKED single SECOND. */
static int test_ocsp_revoked_multi_single_status_cb(WOLFSSL* ssl, void* ioCtx)
{
    byte* leaf_resp = NULL;
    byte* int_resp = NULL;
    byte* root_resp = NULL;
    int ret = WOLFSSL_OCSP_STATUS_CB_ALERT_FATAL;
    (void)ioCtx;
    leaf_resp = (byte*)XMALLOC(sizeof(resp_server1_revoked_good_first), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    int_resp = (byte*)XMALLOC(sizeof(resp_intermediate1_cert), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    root_resp = (byte*)XMALLOC(sizeof(resp_root_ca_cert), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (leaf_resp != NULL && int_resp != NULL && root_resp != NULL) {
        XMEMCPY(leaf_resp, resp_server1_revoked_good_first,
                sizeof(resp_server1_revoked_good_first));
        XMEMCPY(int_resp, resp_intermediate1_cert,
                sizeof(resp_intermediate1_cert));
        XMEMCPY(root_resp, resp_root_ca_cert, sizeof(resp_root_ca_cert));
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, leaf_resp,
                sizeof(resp_server1_revoked_good_first), 0) == WOLFSSL_SUCCESS)
            leaf_resp = NULL;
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, int_resp,
                sizeof(resp_intermediate1_cert), 1) == WOLFSSL_SUCCESS)
            int_resp = NULL;
        if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, root_resp,
                sizeof(resp_root_ca_cert), 2) == WOLFSSL_SUCCESS)
            root_resp = NULL;
        if (leaf_resp == NULL && int_resp == NULL && root_resp == NULL)
            ret = WOLFSSL_OCSP_STATUS_CB_OK;
    }
    XFREE(leaf_resp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(int_resp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(root_resp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/*
 * status_request_v2 OCSP-multi must reject a stapled leaf response
 * whose MATCHING SingleResponse is CERT_REVOKED, even when an unrelated
 * CERT_GOOD SingleResponse appears first in the same BasicOCSPResponse.
 */
int test_ocsp_status_request_v2_multi_revoked_single(void)
{
    EXPECT_DECLS;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* tls_version;
    } params[] = {
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, "TLSv1_2" },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, "DTLSv1_2" },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;
        WOLFSSL_ALERT_HISTORY h;

        printf("\nTesting %s\n", params[i].tls_version);

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_cb.caPemFile = "";
        /* Server cert/key come only from the per-connection cert callback. */
        test_ctx.s_cb.certPemFile = "";
        test_ctx.s_cb.keyPemFile = "";
        test_ctx.c_cb.method = params[i].client_meth;
        test_ctx.s_cb.method = params[i].server_meth;

        /* Full server1 -> intermediate1 -> root chain so the leaf staple is at
         * idx 0. */
        test_ocsp_tls_cert_cb_opts.chainLen = 3;
        test_ocsp_tls_cert_cb_opts.failStaple = 0;
        test_ctx.s_cb.ctx_ready = test_ocsp_tls_cert_cb_ctx_ready;

        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_UnloadCertsKeys(test_ctx.s_ssl), WOLFSSL_SUCCESS);

        /* server: enable stapling and supply the multi-single leaf */
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.s_ctx),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(test_ctx.s_ctx,
                test_ocsp_revoked_multi_single_status_cb), WOLFSSL_SUCCESS);

        /* client: verify chain via callback, request status_request_v2 multi.
         * Deliberately no ocsp_status_verify_cb: exercise DoCertificateStatus
         * in isolation. */
        wolfSSL_set_verify(test_ctx.c_ssl, WOLFSSL_VERIFY_DEFAULT,
                test_ocsp_tls_cert_cb_verify_cb);
        wolfSSL_SetCertCbCtx(test_ctx.c_ssl, test_ctx.c_ssl);
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(test_ctx.c_ctx),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                WOLFSSL_CSR2_OCSP_MULTI, WOLFSSL_CSR2_OCSP_USE_NONCE),
                WOLFSSL_SUCCESS);

        /* Revoked leaf must abort the handshake. */
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_FAIL);
        XMEMSET(&h, 0, sizeof(h));
        ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
                WOLFSSL_SUCCESS);
        ExpectIntEQ(h.last_rx.level, alert_fatal);
        ExpectIntEQ(h.last_rx.code, bad_certificate_status_response);

        test_ssl_memio_cleanup(&test_ctx);
    }
    return EXPECT_RESULT();
}
#else
int test_ocsp_status_request_v2_multi_revoked_single(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 && !WOLFSSL_NO_TLS12 */

#else  /* feature guards */
int test_ocsp_tls_cert_cb(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_status_request_v2_multi_revoked_single(void)
{
    return TEST_SKIPPED;
}
#endif

/*
 * Test: OCSP returns CERT_UNKNOWN for the leaf cert, CRL says cert is valid.
 * Expects the TLS handshake to succeed via CRL fallback.
 *
 * Uses:
 *  - server-cert.pem (serial 0x01, issued by ca-cert.pem)
 *  - resp_server_cert_unknown: OCSP response with CERT_UNKNOWN for serial 0x01
 *  - crl/crl.pem: CRL from ca-cert.pem, only revokes serial 0x02
 */
#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA) && \
    !defined(NO_SHA)

static int test_ocsp_unknown_crl_fallback_ocsp_io_cb(void* ioCtx,
    const char* url, int urlSz, unsigned char* request, int requestSz,
    unsigned char** response)
{
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;

    /* Return the pre-built CERT_UNKNOWN response for server-cert.pem */
    *response = (unsigned char*)ioCtx;
    return (int)sizeof(resp_server_cert_unknown);
}

static int test_ocsp_unknown_crl_fallback_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    /* Enable OCSP on client with URL override so no real network is needed */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx,
                    WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    /* Set the OCSP I/O callback to return our CERT_UNKNOWN response blob */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                    test_ocsp_unknown_crl_fallback_ocsp_io_cb, NULL,
                    (void*)resp_server_cert_unknown),
        WOLFSSL_SUCCESS);

    /* Enable CRL checking (already loaded via crlPemFile in the framework) */

    return EXPECT_RESULT();
}

int test_ocsp_cert_unknown_crl_fallback(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Server setup: use standard server cert issued by ca-cert.pem */
    test_ctx.s_cb.certPemFile = "./certs/server-cert.pem";
    test_ctx.s_cb.keyPemFile  = "./certs/server-key.pem";

    /* Client setup: CA cert, CRL file, and custom ctx_ready for OCSP */
    test_ctx.c_cb.caPemFile   = "./certs/ca-cert.pem";
    test_ctx.c_cb.crlPemFile  = "./certs/crl/crl.pem";
    test_ctx.c_cb.ctx_ready   = test_ocsp_unknown_crl_fallback_ctx_ready;

    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);

    /* The OCSP response returns CERT_UNKNOWN for the server cert.
     * CRL (crl.pem) does NOT revoke serial 0x01 (only 0x02 is revoked).
     * If OCSP CERT_UNKNOWN correctly falls back to CRL, the handshake
     * should succeed.
     */
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);

    test_ssl_memio_cleanup(&test_ctx);
    return EXPECT_RESULT();
}

#else
int test_ocsp_cert_unknown_crl_fallback(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && */
       /* !NO_RSA && !NO_SHA */

/*
 * Test: OCSP returns CERT_UNKNOWN for a non-leaf (intermediate) cert,
 * CRL says the cert is valid. With both OCSP_CHECKALL and CRL_CHECKALL
 * enabled, the CRL fallback for non-leaf certs should kick in.
 *
 * Chain: server1 (serial 0x05) -> intermediate1 (serial 0x01) -> root-ca
 *
 * OCSP responses:
 *  - intermediate1: resp_cert_unknown (CERT_UNKNOWN)
 *  - server1:       resp_server1_cert (CERT_GOOD)
 *
 * CRL files (empty = no revocations):
 *  - root-ca-crl.pem:          covers intermediate1 (serial 0x01 not revoked)
 *  - intermediate1-ca-crl.pem: covers server1 (serial 0x05 not revoked)
 */
#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA) && \
    !defined(NO_SHA)

static int test_ocsp_unknown_nonleaf_call_count;

static int test_ocsp_unknown_nonleaf_ocsp_io_cb(void* ioCtx,
    const char* url, int urlSz, unsigned char* request, int requestSz,
    unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;

    test_ocsp_unknown_nonleaf_call_count++;

    if (test_ocsp_unknown_nonleaf_call_count == 1) {
        /* First OCSP lookup: non-leaf cert (intermediate1).
         * Return CERT_UNKNOWN. */
        *response = (unsigned char*)resp_cert_unknown;
        return (int)sizeof(resp_cert_unknown);
    }
    else {
        /* Second OCSP lookup: leaf cert (server1).
         * Return CERT_GOOD. */
        *response = (unsigned char*)resp_server1_cert;
        return (int)sizeof(resp_server1_cert);
    }
}

static int test_ocsp_unknown_nonleaf_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    /* Need VERIFY_PEER so chain certs get added to the CM. Without it
     * (e.g. OPENSSL_COMPATIBLE_DEFAULTS sets VERIFY_NONE), the intermediate
     * CA won't be registered and the leaf cert's issuerKeyHash stays zero,
     * causing the OCSP CertID comparison to fail. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Enable OCSP with CHECKALL so non-leaf certs are also OCSP-checked */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
                    WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    /* Set the OCSP I/O callback to return our test responses */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                    test_ocsp_unknown_nonleaf_ocsp_io_cb, NULL, NULL),
        WOLFSSL_SUCCESS);

    /* Load CRL from root-ca (covers intermediate1, serial 0x01 not revoked).
     * The leaf cert (server1) gets CERT_GOOD from OCSP so doesn't need CRL. */
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                    "./certs/ocsp/root-ca-crl.pem", WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_cert_unknown_crl_fallback_nonleaf(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_unknown_nonleaf_call_count = 0;

    /* Server: server1-chain-noroot.pem contains server1 + intermediate1
     * (no root-ca, since the client already trusts root-ca) */
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile  = "./certs/ocsp/server1-key.pem";

    /* Client: trust root-ca, enable OCSP+CRL in ctx_ready */
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_unknown_nonleaf_ctx_ready;

    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);

    /* OCSP returns CERT_UNKNOWN for intermediate1 (non-leaf).
     * CRL (root-ca-crl.pem) has no revocations, so intermediate1 is valid.
     * If the non-leaf OCSP->CRL fallback works, the handshake should succeed.
     */
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);

    test_ssl_memio_cleanup(&test_ctx);
    return EXPECT_RESULT();
}

#else
int test_ocsp_cert_unknown_crl_fallback_nonleaf(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES */

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)

/* The default memio chain (certs/server-cert.pem under certs/ca-cert.pem)
 * carries no AIA extension, so no cert in it advertises an OCSP responder
 * and no override URL is configured. */

static int test_ocsp_no_url_checkall_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    /* CHECKALL selects scope only, so it must not fail a chain that
     * advertises no responder. */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_no_url_fail_closed_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
                    WOLFSSL_OCSP_FAIL_IF_NOT_SUPPORTED),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_no_url_policy(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* WOLFSSL_OCSP_CHECKALL on its own soft-fails a cert that advertises no
     * responder, as it has since the flag was introduced. Regression test:
     * failing closed here breaks any chain whose CA publishes no OCSP URI,
     * which is common on the public web. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.ctx_ready = test_ocsp_no_url_checkall_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    test_ssl_memio_cleanup(&test_ctx);

    /* Opting in with WOLFSSL_OCSP_FAIL_IF_NOT_SUPPORTED refuses the same
     * chain with OCSP_NEED_URL. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.ctx_ready = test_ocsp_no_url_fail_closed_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(OCSP_NEED_URL));
    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}

#else
int test_ocsp_no_url_policy(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES */

/* A server that acks status_request and then sends no CertificateStatus must
 * fail a must-staple client whatever the CRL or OCSP fallbacks return. */
#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_SHA)

static struct {
    int useCrl;
    int useOcsp;
    int anon;
} test_ocsp_must_staple_opts;

static int test_ocsp_must_staple_noack_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl;
    (void)arg;
    return WOLFSSL_OCSP_STATUS_CB_NOACK;
}

static int test_ocsp_must_staple_srv_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(ctx,
            test_ocsp_must_staple_noack_cb), WOLFSSL_SUCCESS);
#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    if (test_ocsp_must_staple_opts.anon) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        ExpectIntEQ(wolfSSL_CTX_allow_anon_cipher(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "ADH-AES128-SHA"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_SetTmpDH_file(ctx, "./certs/dh2048.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
#endif

    return EXPECT_RESULT();
}

static int test_ocsp_must_staple_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;

    *response = (unsigned char*)resp_server1_cert;
    return (int)sizeof(resp_server1_cert);
}

static int test_ocsp_must_staple_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    /* Peer verification alone already refuses an anonymous server. */
    wolfSSL_CTX_set_verify(ctx, test_ocsp_must_staple_opts.anon ?
        WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(ctx), WOLFSSL_SUCCESS);
    if (test_ocsp_must_staple_opts.useOcsp) {
        ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
                WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ocsp_must_staple_io_cb,
                NULL, NULL), WOLFSSL_SUCCESS);
    }
#ifdef HAVE_CRL
    if (test_ocsp_must_staple_opts.useCrl) {
        ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK),
            WOLFSSL_SUCCESS);
        /* Issued by ca-cert and does not revoke server-cert, so the check
         * comes back clean. */
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/crl/crl.pem",
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
#endif
#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    if (test_ocsp_must_staple_opts.anon) {
        ExpectIntEQ(wolfSSL_CTX_allow_anon_cipher(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "ADH-AES128-SHA"),
            WOLFSSL_SUCCESS);
    }
#endif

    return EXPECT_RESULT();
}

int test_ocsp_must_staple_acked_no_status(void)
{
    EXPECT_DECLS;
    size_t i;
    struct {
        const char* desc;
        const char* caFile;
        const char* certFile;
        const char* keyFile;
        int useCrl;
        int useOcsp;
        int anon;
    } params[] = {
        { "no fallback configured", "./certs/ca-cert.pem",
          "./certs/server-cert.pem", "./certs/server-key.pem", 0, 0, 0 },
#ifdef HAVE_CRL
        { "clean CRL loaded", "./certs/ca-cert.pem",
          "./certs/server-cert.pem", "./certs/server-key.pem", 1, 0, 0 },
#endif
        { "OCSP responder answers good", "./certs/ocsp/root-ca-cert.pem",
          "./certs/ocsp/server1-chain-noroot.pem",
          "./certs/ocsp/server1-key.pem", 0, 1, 0 },
#if defined(BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA) && !defined(NO_DH)
        /* No certificate to staple for, which an anonymous suite does not
         * turn into a waiver. */
        { "anonymous cipher suite", "./certs/ca-cert.pem",
          "./certs/server-cert.pem", "./certs/server-key.pem", 0, 0, 1 },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;

        XMEMSET(&test_ocsp_must_staple_opts, 0,
            sizeof(test_ocsp_must_staple_opts));
        test_ocsp_must_staple_opts.useCrl = params[i].useCrl;
        test_ocsp_must_staple_opts.useOcsp = params[i].useOcsp;
        test_ocsp_must_staple_opts.anon = params[i].anon;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_cb.method = wolfTLSv1_2_client_method;
        test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        test_ctx.s_cb.certPemFile = params[i].certFile;
        test_ctx.s_cb.keyPemFile = params[i].keyFile;
        test_ctx.s_cb.ctx_ready = test_ocsp_must_staple_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = params[i].caFile;
        test_ctx.c_cb.ctx_ready = test_ocsp_must_staple_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        /* Unrequested, so the anonymous server has nothing to acknowledge. */
        if (!params[i].anon) {
            ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                WOLFSSL_CSR_OCSP, 0), WOLFSSL_SUCCESS);
        }

        /* The staple the client demanded never arrived. */
        ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
            TEST_SUCCESS);
        if (params[i].anon) {
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN));
        }
        if (EXPECT_FAIL())
            fprintf(stderr, "case: %s\n", params[i].desc);

        test_ssl_memio_cleanup(&test_ctx);
    }

    return EXPECT_RESULT();
}

#else
int test_ocsp_must_staple_acked_no_status(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CERTIFICATE_STATUS_REQUEST && */
       /* HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && !WOLFSSL_NO_TLS12 && */
       /* !NO_RSA && !NO_SHA */

#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
/* Status callback test_ocsp_srv_ctx_ready() installs. */
static WC_MAYBE_UNUSED tlsextStatusCb test_ocsp_srv_status_cb;

/* Staples a copy of der as the response at index idx. */
static WC_MAYBE_UNUSED int test_ocsp_set_staple(WOLFSSL* ssl, const byte* der,
    int sz, word32 idx)
{
    byte* staple;

    staple = (byte*)XMALLOC((size_t)sz, NULL, 0);
    if (staple == NULL)
        return WOLFSSL_OCSP_STATUS_CB_ALERT_FATAL;
    XMEMCPY(staple, der, (size_t)sz);
    if (wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, staple, sz, idx) !=
            WOLFSSL_SUCCESS) {
        XFREE(staple, NULL, 0);
        return WOLFSSL_OCSP_STATUS_CB_ALERT_FATAL;
    }

    return WOLFSSL_OCSP_STATUS_CB_OK;
}

static WC_MAYBE_UNUSED int test_ocsp_srv_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectNotNull(test_ocsp_srv_status_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(ctx,
            test_ocsp_srv_status_cb), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_CRL) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    !defined(NO_RSA) && !defined(NO_SHA)

static const char* test_ocsp_checkall_staple_crl_file;
static int test_ocsp_checkall_staple_crl_pin_fail;
static int test_ocsp_checkall_staple_crl_cb_calls;

/* Passes preverify through, or rejects the intermediate as a failed pin
 * would. */
static int test_ocsp_checkall_staple_crl_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    if (store->error_depth != 1)
        return preverify;
    test_ocsp_checkall_staple_crl_cb_calls++;
    if (test_ocsp_checkall_staple_crl_pin_fail)
        return 0;
    return preverify;
}

/* Staples both chain entries, so every certificate's status comes from OCSP. */
static int test_ocsp_checkall_staple_crl_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    if (test_ocsp_set_staple(ssl, resp_server1_cert,
            (int)sizeof(resp_server1_cert), 0) != WOLFSSL_OCSP_STATUS_CB_OK)
        return WOLFSSL_OCSP_STATUS_CB_ALERT_FATAL;
    return test_ocsp_set_staple(ssl, resp_intermediate1_cert,
        (int)sizeof(resp_intermediate1_cert), 1);
}

static int test_ocsp_checkall_staple_crl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER,
        test_ocsp_checkall_staple_crl_verify_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    if (test_ocsp_checkall_staple_crl_file != NULL) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                test_ocsp_checkall_staple_crl_file, WOLFSSL_FILETYPE_PEM),
            WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

static int test_ocsp_checkall_staple_crl_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_checkall_staple_crl_run(struct test_ssl_memio_ctx* ctx)
{
    EXPECT_DECLS;

    ctx->c_cb.method = wolfTLSv1_3_client_method;
    ctx->s_cb.method = wolfTLSv1_3_server_method;
    ctx->s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    ctx->s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ocsp_srv_status_cb = test_ocsp_checkall_staple_crl_status_cb;
    ctx->s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    ctx->c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    ctx->c_cb.ctx_ready = test_ocsp_checkall_staple_crl_ctx_ready;
    ctx->c_cb.ssl_ready = test_ocsp_checkall_staple_crl_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(ctx), TEST_SUCCESS);

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

int test_ocsp_checkall_staple_crl_missing(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* Every chain entry carries a staple, so a CRL store holding nothing for
     * the intermediate's issuer must not reject it. */
    test_ocsp_checkall_staple_crl_file = NULL;
    test_ocsp_checkall_staple_crl_pin_fail = 0;
    test_ocsp_checkall_staple_crl_cb_calls = 0;
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_ocsp_checkall_staple_crl_run(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    test_ssl_memio_cleanup(&test_ctx);

    /* The staple answers for the missing CRL, but not for a verify callback
     * that rejects the intermediate on other grounds. */
    test_ocsp_checkall_staple_crl_pin_fail = 1;
    test_ocsp_checkall_staple_crl_cb_calls = 0;
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_ocsp_checkall_staple_crl_run(&test_ctx), TEST_SUCCESS);
#ifdef WOLFSSL_VERIFY_CB_ALL_CERTS
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(VERIFY_CERT_ERROR));
    ExpectIntEQ(test_ocsp_checkall_staple_crl_cb_calls, 2);
#else
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(test_ocsp_checkall_staple_crl_cb_calls, 1);
#endif
    test_ssl_memio_cleanup(&test_ctx);
    test_ocsp_checkall_staple_crl_pin_fail = 0;

    /* A CRL that does revoke the intermediate still rejects it, staple or no
     * staple. */
    test_ocsp_checkall_staple_crl_file = "./certs/ocsp/root-ca-crl-revoked.pem";
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_ocsp_checkall_staple_crl_run(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    test_ssl_memio_cleanup(&test_ctx);
    test_ocsp_checkall_staple_crl_file = NULL;

    return EXPECT_RESULT();
}

static int test_ocsp_staple_crl_no_checkall_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_staple_crl_no_checkall(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* Without OCSP chain checking no staple verdict can ever replace the
     * chain CRL verdict, so holding that verdict back would discard it. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ocsp_srv_status_cb = test_ocsp_checkall_staple_crl_status_cb;
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_no_checkall_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_checkall_staple_crl_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_MISSING));
    test_ssl_memio_cleanup(&test_ctx);

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#if defined(HAVE_OCSP_RESPONDER) && defined(WOLFSSL_ASN_TEMPLATE) && \
    !defined(NO_FILESYSTEM)
static byte* test_ocsp_ca_above_resp[2];
static word32 test_ocsp_ca_above_resp_sz[2];
static int test_ocsp_ca_above_own_crl;
static int test_ocsp_ca_above_root_crl;

/* Signs a good OCSP response for a certificate with its issuer's key. */
static int test_ocsp_ca_above_make_resp(WOLFSSL_CERT_MANAGER* cm,
    const char* certFile, const char* issuerFile, const char* keyFile,
    byte** out, word32* outSz)
{
    EXPECT_DECLS;
    byte* cert = NULL;
    byte* issuer = NULL;
    byte* key = NULL;
    size_t certSz = 0;
    size_t issuerSz = 0;
    size_t keySz = 0;
    DecodedCert dCert;
    DecodedCert dIssuer;
    OcspRequest* req = NULL;
    OcspResponder* responder = NULL;
    byte reqBuf[1024];
    int reqSz = 0;
    char subject[WC_ASN_NAME_MAX];
    word32 subjectSz = sizeof(subject);
    byte serial[EXTERNAL_SERIAL_SIZE];
    word32 serialSz = sizeof(serial);

    XMEMSET(&dCert, 0, sizeof(dCert));
    XMEMSET(&dIssuer, 0, sizeof(dIssuer));
    ExpectIntEQ(load_file(certFile, &cert, &certSz), 0);
    ExpectIntEQ(load_file(issuerFile, &issuer, &issuerSz), 0);
    ExpectIntEQ(load_file(keyFile, &key, &keySz), 0);
    wc_InitDecodedCert(&dCert, cert, (word32)certSz, NULL);
    wc_InitDecodedCert(&dIssuer, issuer, (word32)issuerSz, NULL);
    ExpectIntEQ(wc_ParseCert(&dIssuer, CERT_TYPE, 0, NULL), 0);
    ExpectIntEQ(wc_ParseCert(&dCert, CERT_TYPE, 0, cm), 0);

    ExpectNotNull(req = wc_OcspRequest_new(NULL));
    ExpectIntEQ(wc_InitOcspRequest(req, &dCert, 0, NULL), 0);
    ExpectIntGT(reqSz = wc_EncodeOcspRequest(req, reqBuf, sizeof(reqBuf)), 0);

    ExpectNotNull(responder = wc_OcspResponder_new(NULL, 0));
    ExpectIntEQ(wc_OcspResponder_AddSigner(responder, issuer, (word32)issuerSz,
        key, (word32)keySz, NULL, 0), 0);
    ExpectIntEQ(wc_GetDecodedCertSubject(&dIssuer, subject, &subjectSz), 0);
    ExpectIntEQ(wc_GetDecodedCertSerial(&dCert, serial, &serialSz), 0);
    ExpectIntEQ(wc_OcspResponder_SetCertStatus(responder, subject, subjectSz,
        serial, serialSz, CERT_GOOD, 0, WC_CRL_REASON_UNSPECIFIED, 3600), 0);
    ExpectIntEQ(wc_OcspResponder_WriteResponse(responder, reqBuf,
        (word32)reqSz, NULL, outSz), 0);
    ExpectNotNull(*out = (byte*)XMALLOC(*outSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_OcspResponder_WriteResponse(responder, reqBuf,
        (word32)reqSz, *out, outSz), 0);

    wc_OcspResponder_free(responder);
    wc_OcspRequest_free(req);
    wc_FreeDecodedCert(&dCert);
    wc_FreeDecodedCert(&dIssuer);
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(issuer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}

static int test_ocsp_ca_above_status_cb(WOLFSSL* ssl, void* arg)
{
    int i;
    int ret = WOLFSSL_OCSP_STATUS_CB_OK;

    (void)arg;
    for (i = 0; i < 2 && ret == WOLFSSL_OCSP_STATUS_CB_OK; i++) {
        ret = test_ocsp_set_staple(ssl, test_ocsp_ca_above_resp[i],
            (int)test_ocsp_ca_above_resp_sz[i], (word32)i);
    }

    return ret;
}

static int test_ocsp_ca_above_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    /* The server sends server-int and ca-int2, the client holds ca-int. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL), WOLFSSL_SUCCESS);
    if (test_ocsp_ca_above_own_crl) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/crl/ca-int.pem",
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
    if (test_ocsp_ca_above_root_crl) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/crl/crl.pem",
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

/* The staples cover the sent chain, but not the CA above it. */
int test_ocsp_checkall_staple_crl_ca_above(void)
{
    EXPECT_DECLS;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    size_t i;
    static const struct {
        const char* desc;
        int ownCrl;
        int rootCrl;
        int expect;
    } params[] = {
        { "CRLs for the top certificate and the CA above it", 1, 1, 0 },
        { "no CRL for the CA above", 1, 0, WC_NO_ERR_TRACE(CRL_MISSING) },
        { "no CRL for the top certificate or the CA above", 0, 0,
          WC_NO_ERR_TRACE(CRL_MISSING) },
        { "no CRL for the top certificate only", 0, 1, 0 },
    };

    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, "./certs/ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm,
        "./certs/intermediate/ca-int-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm,
        "./certs/intermediate/ca-int2-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_ocsp_ca_above_make_resp(cm,
        "./certs/intermediate/server-int-cert.der",
        "./certs/intermediate/ca-int2-cert.der",
        "./certs/intermediate/ca-int2-key.der",
        &test_ocsp_ca_above_resp[0], &test_ocsp_ca_above_resp_sz[0]),
        TEST_SUCCESS);
    ExpectIntEQ(test_ocsp_ca_above_make_resp(cm,
        "./certs/intermediate/ca-int2-cert.der",
        "./certs/intermediate/ca-int-cert.der",
        "./certs/intermediate/ca-int-key.der",
        &test_ocsp_ca_above_resp[1], &test_ocsp_ca_above_resp_sz[1]),
        TEST_SUCCESS);
    wolfSSL_CertManagerFree(cm);

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;

        test_ocsp_ca_above_own_crl = params[i].ownCrl;
        test_ocsp_ca_above_root_crl = params[i].rootCrl;
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_cb.method = wolfTLSv1_3_client_method;
        test_ctx.s_cb.method = wolfTLSv1_3_server_method;
        test_ctx.s_cb.certPemFile =
            "./certs/intermediate/server-chain-short.pem";
        test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_ca_above_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_ca_above_ctx_ready;
        test_ctx.c_cb.ssl_ready = test_ocsp_checkall_staple_crl_ssl_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        if (params[i].expect == 0) {
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
        }
        else {
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                params[i].expect);
        }
        if (EXPECT_FAIL())
            fprintf(stderr, "case: %s\n", params[i].desc);
        test_ssl_memio_cleanup(&test_ctx);
    }

    for (i = 0; i < 2; i++) {
        XFREE(test_ocsp_ca_above_resp[i], NULL, DYNAMIC_TYPE_TMP_BUFFER);
        test_ocsp_ca_above_resp[i] = NULL;
    }

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}
#else
int test_ocsp_checkall_staple_crl_ca_above(void)
{
    return TEST_SKIPPED;
}
#endif

#else
int test_ocsp_checkall_staple_crl_missing(void)
{
    return TEST_SKIPPED;
}

int test_ocsp_staple_crl_no_checkall(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_checkall_staple_crl_ca_above(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && WOLFSSL_TLS13 && */
       /* HAVE_CERTIFICATE_STATUS_REQUEST && */
       /* HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && */
       /* !WOLFSSL_CRL_ALLOW_MISSING_CDP && !NO_RSA && !NO_SHA */

/* The test certificates name no CRL distribution point, so these cases cannot
 * run where a missing one skips the check. */
#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    !defined(NO_RSA) && !defined(NO_SHA)

static int test_ocsp_no_url_crl_fallback_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, 0), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_no_url_crl_fallback(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* server-revoked-cert.pem carries no extensions, so it advertises no OCSP
     * responder; crl.pem revokes its serial. Enabling OCSP alongside CRL must
     * not suppress the CRL check. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.s_cb.certPemFile = "./certs/server-revoked-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-revoked-key.pem";
    test_ctx.c_cb.crlPemFile = "./certs/crl/crl.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_no_url_crl_fallback_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}

static int test_ocsp_no_url_crl_fallback_nonleaf_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    /* Issued by the root, revokes ca-int (serial 1000). The chain is walked
     * root-most first, so no other CRL is reached. */
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                    "./certs/crl/extra-crls/ca-int-cert-revoked.pem",
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_no_url_crl_fallback_nonleaf(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* Same fall-through for a chain cert: no cert in certs/intermediate has
     * an AIA extension, and the revoked one is the intermediate ca-int
     * rather than the leaf. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.s_cb.certPemFile = "./certs/intermediate/server-chain.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
    test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_no_url_crl_fallback_nonleaf_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}

static int test_ocsp_no_url_crl_not_loaded_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_no_url_crl_not_loaded(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* Reaching the CRL for a certificate that names no responder also reaches
     * deployments holding no CRL for the issuer, which now fail closed. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.s_cb.certPemFile = "./certs/server-revoked-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-revoked-key.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_no_url_crl_not_loaded_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_MISSING));
    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}

#else
int test_ocsp_no_url_crl_fallback(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_no_url_crl_fallback_nonleaf(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_no_url_crl_not_loaded(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && */
       /* !WOLFSSL_CRL_ALLOW_MISSING_CDP && !NO_RSA && !NO_SHA */

#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_RSA) && !defined(NO_SHA)

/* As above, but OCSP is enabled too. The leaf names no responder, so the OCSP
 * result is the soft-fail 0 and must not stand in for the skipped CRL check. */
static int test_ocsp_acked_no_leaf_staple_crl_ocsp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, 0), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_acked_no_leaf_staple_crl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_acked_no_leaf_staple_crl_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* Must-staple, CRL only: the CRL verdict must not answer for the staple. */
static int test_ocsp_acked_no_leaf_staple_must_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(ctx), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_acked_no_leaf_staple_srv_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* Which extension the leaf CRL cases below request: 0 is status_request,
 * 1 status_request_v2 ocsp and 2 status_request_v2 ocsp_multi. */
static int test_ocsp_acked_no_leaf_staple_policy_csr;
/* 0 disables OCSP, 1 enables it for a leaf that names no responder, 2 has
 * the responder answer unknown and 3 does too with CRL checking off. */
static int test_ocsp_acked_no_leaf_staple_policy_ocsp;

static int test_ocsp_acked_no_leaf_staple_policy_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    if (test_ocsp_acked_no_leaf_staple_policy_ocsp != 3) {
        ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK),
            WOLFSSL_SUCCESS);
    }
    if (test_ocsp_acked_no_leaf_staple_policy_ocsp == 1) {
        ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, 0), WOLFSSL_SUCCESS);
    }
    else if (test_ocsp_acked_no_leaf_staple_policy_ocsp >= 2) {
        ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
            WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
            test_ocsp_unknown_crl_fallback_ocsp_io_cb, NULL,
            (void*)resp_server_cert_unknown), WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

static int test_ocsp_acked_no_leaf_staple_policy_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

    if (test_ocsp_acked_no_leaf_staple_policy_csr == 0) {
        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
            WOLFSSL_SUCCESS);
    }
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    else {
        ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(ssl,
            test_ocsp_acked_no_leaf_staple_policy_csr == 1 ? WOLFSSL_CSR2_OCSP :
            WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
    }
#endif

    return EXPECT_RESULT();
}

/* When OCSP gives no answer the whole CRL verdict decides, as it does without
 * stapling: a missing CRL fails and a clean one settles an unknown answer. */
static int test_ocsp_acked_no_leaf_staple_policy(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    static const struct {
        int ocsp;
        const char* crl;
        int expect;
    } cases[] = {
        { 0, NULL, WC_NO_ERR_TRACE(CRL_MISSING) },
        { 1, NULL, WC_NO_ERR_TRACE(CRL_MISSING) },
        { 2, NULL, WC_NO_ERR_TRACE(CRL_MISSING) },
        { 2, "./certs/crl/crl.pem", 0 },
        { 3, NULL, WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN) },
    };
    int csr;
    size_t i;

    for (csr = 0; csr < 3 && !EXPECT_FAIL(); csr++) {
#ifndef HAVE_CERTIFICATE_STATUS_REQUEST_V2
        if (csr > 0)
            break;
#endif
        for (i = 0; i < XELEM_CNT(cases) && !EXPECT_FAIL(); i++) {
            test_ocsp_acked_no_leaf_staple_policy_csr = csr;
            test_ocsp_acked_no_leaf_staple_policy_ocsp = cases[i].ocsp;
            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            test_ctx.s_cb.method = wolfTLSv1_2_server_method;
            test_ctx.s_cb.certPemFile = "./certs/server-cert.pem";
            test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
            test_ctx.s_cb.ctx_ready =
                test_ocsp_acked_no_leaf_staple_srv_ctx_ready;
            test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
            test_ctx.c_cb.crlPemFile = cases[i].crl;
            test_ctx.c_cb.ctx_ready =
                test_ocsp_acked_no_leaf_staple_policy_ctx_ready;
            test_ctx.c_cb.ssl_ready =
                test_ocsp_acked_no_leaf_staple_policy_ssl_ready;
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
            if (cases[i].expect == 0) {
                ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10,
                    NULL), TEST_SUCCESS);
            }
            else {
                ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10,
                    NULL), TEST_SUCCESS);
                ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                    cases[i].expect);
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                ExpectIntEQ(wolfSSL_get_verify_result(test_ctx.c_ssl),
                    cases[i].expect == WC_NO_ERR_TRACE(CRL_MISSING) ?
                    WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL :
                    WOLFSSL_X509_V_ERR_CERT_REJECTED);
#endif
            }
            if (EXPECT_FAIL()) {
                fprintf(stderr, "csr %d, case %d\n", csr, (int)i);
            }
            test_ssl_memio_cleanup(&test_ctx);
        }
    }

    return EXPECT_RESULT();
}

int test_ocsp_acked_no_leaf_staple_crl(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    /* The server echoes status_request but server-revoked-cert.pem names
     * no responder, so no CertificateStatus follows. crl.pem revokes it. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/server-revoked-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-revoked-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_srv_ctx_ready;
    test_ctx.c_cb.crlPemFile = "./certs/crl/crl.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_crl_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    ExpectIntEQ(wolfSSL_get_verify_result(test_ctx.c_ssl),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);
#endif
    test_ssl_memio_cleanup(&test_ctx);

    /* A clean CRL verdict must not stand in for the staple the client
     * required, so this handshake still fails. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/server-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
    test_ctx.c_cb.crlPemFile = "./certs/crl/crl.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_must_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN));
    test_ssl_memio_cleanup(&test_ctx);

    /* Same again with OCSP also enabled on the client. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/server-revoked-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-revoked-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_srv_ctx_ready;
    test_ctx.c_cb.crlPemFile = "./certs/crl/crl.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_crl_ocsp_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    ExpectIntEQ(wolfSSL_get_verify_result(test_ctx.c_ssl),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);
#endif
    test_ssl_memio_cleanup(&test_ctx);

    ExpectIntEQ(test_ocsp_acked_no_leaf_staple_policy(), TEST_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_crl_verify_cb_calls;
static int test_ocsp_crl_verify_cb_accept;

static int test_ocsp_crl_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    if (!preverify) {
        test_ocsp_crl_verify_cb_calls++;
        return test_ocsp_crl_verify_cb_accept;
    }
    return preverify;
}

static int test_ocsp_crl_verify_cb_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, test_ocsp_crl_verify_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* A missing leaf CRL reaches the verify callback once whether or not the
 * server acknowledged stapling, and the callback may waive it. */
int test_ocsp_acked_no_status_crl_verify_cb(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    int staple;
    int accept;

    for (staple = 0; staple < 2 && !EXPECT_FAIL(); staple++) {
        for (accept = 0; accept < 2 && !EXPECT_FAIL(); accept++) {
            test_ocsp_crl_verify_cb_calls = 0;
            test_ocsp_crl_verify_cb_accept = accept;
            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            test_ctx.s_cb.method = wolfTLSv1_2_server_method;
            test_ctx.s_cb.certPemFile = "./certs/server-cert.pem";
            test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
            test_ctx.s_cb.ctx_ready =
                test_ocsp_acked_no_leaf_staple_srv_ctx_ready;
            test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
            test_ctx.c_cb.ctx_ready = test_ocsp_crl_verify_cb_ctx_ready;
            if (staple) {
                test_ctx.c_cb.ssl_ready =
                    test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
            }
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
            if (accept) {
                ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                    TEST_SUCCESS);
            }
            else {
                ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                    TEST_SUCCESS);
                ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                    WC_NO_ERR_TRACE(CRL_MISSING));
            }
            ExpectIntEQ(test_ocsp_crl_verify_cb_calls, 1);
            if (EXPECT_FAIL())
                fprintf(stderr, "staple %d, accept %d\n", staple, accept);
            test_ssl_memio_cleanup(&test_ctx);
        }
    }

    return EXPECT_RESULT();
}

static struct {
    const char* rootCrl;
    int staple;
    int noLeafCrl;
    int pinFail;
    int waive;
    int cbCalls;
} test_ocsp_crl_ca_walk_opts;

/* Passes preverify through, rejects the leaf as a failed pin would, or waives
 * any error on it. */
static int test_ocsp_crl_ca_walk_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    if (store->error_depth != 0)
        return preverify;
    test_ocsp_crl_ca_walk_opts.cbCalls++;
    if (test_ocsp_crl_ca_walk_opts.pinFail)
        return 0;
    if (test_ocsp_crl_ca_walk_opts.waive)
        return 1;
    return preverify;
}

/* Staples the leaf, or acknowledges status_request and sends nothing. */
static int test_ocsp_crl_ca_walk_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    if (!test_ocsp_crl_ca_walk_opts.staple)
        return WOLFSSL_OCSP_STATUS_CB_NOACK;
    return test_ocsp_set_staple(ssl, resp_server1_cert,
        (int)sizeof(resp_server1_cert), 0);
}

static int test_ocsp_crl_ca_walk_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER,
        test_ocsp_crl_ca_walk_verify_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    /* The server sends only its leaf, so the client holds intermediate1. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    if (!test_ocsp_crl_ca_walk_opts.noLeafCrl) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                "./certs/ocsp/intermediate1-ca-crl.pem", WOLFSSL_FILETYPE_PEM),
            WOLFSSL_SUCCESS);
    }
    if (test_ocsp_crl_ca_walk_opts.rootCrl != NULL) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                test_ocsp_crl_ca_walk_opts.rootCrl, WOLFSSL_FILETYPE_PEM),
            WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

/* The CRL check of the CAs above a leaf-only chain, which no staple covers. */
int test_ocsp_acked_no_status_crl_ca_walk(void)
{
    EXPECT_DECLS;
    size_t i;
    static const struct {
        const char* desc;
        int tls13;
        int request;
        int staple;
        const char* rootCrl;
        int expect;
        int noLeafCrl;
        int waive;
    } params[] = {
        { "no stapling, revoked intermediate", 0, 0, 0,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0 },
        { "acked, nothing stapled, revoked intermediate", 0, 1, 0,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0 },
        { "leaf stapled, revoked intermediate", 0, 1, 1,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0 },
        { "acked, nothing stapled, no CRL for intermediate", 0, 1, 0, NULL,
          WC_NO_ERR_TRACE(CRL_MISSING), 0, 0 },
        { "leaf stapled, no CRL for intermediate", 0, 1, 1, NULL,
          WC_NO_ERR_TRACE(CRL_MISSING), 0, 0 },
        { "leaf stapled, no leaf CRL, revoked intermediate", 0, 1, 1,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 1, 0 },
        { "acked, nothing stapled, clean CRL", 0, 1, 0,
          "./certs/ocsp/root-ca-crl.pem", 0, 0, 0 },
        { "acked, nothing stapled, callback waives both missing CRLs", 0, 1, 0,
          NULL, 0, 1, 1 },
#ifdef WOLFSSL_TLS13
        { "TLS 1.3, nothing stapled, revoked intermediate", 1, 1, 0,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0 },
        { "TLS 1.3, leaf stapled, revoked intermediate", 1, 1, 1,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0 },
        { "TLS 1.3, leaf stapled, no CRL for intermediate", 1, 1, 1, NULL,
          WC_NO_ERR_TRACE(CRL_MISSING), 0, 0 },
        { "TLS 1.3, leaf stapled, no leaf CRL, revoked intermediate", 1, 1, 1,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 1, 0 },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;
        WOLFSSL_ALERT_HISTORY h;

        XMEMSET(&test_ocsp_crl_ca_walk_opts, 0,
            sizeof(test_ocsp_crl_ca_walk_opts));
        test_ocsp_crl_ca_walk_opts.rootCrl = params[i].rootCrl;
        test_ocsp_crl_ca_walk_opts.staple = params[i].staple;
        test_ocsp_crl_ca_walk_opts.noLeafCrl = params[i].noLeafCrl;
        test_ocsp_crl_ca_walk_opts.waive = params[i].waive;
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        if (params[i].tls13) {
#ifdef WOLFSSL_TLS13
            test_ctx.c_cb.method = wolfTLSv1_3_client_method;
            test_ctx.s_cb.method = wolfTLSv1_3_server_method;
#endif
        }
        else {
            test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        }
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-leaf.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_crl_ca_walk_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_crl_ca_walk_ctx_ready;
        if (params[i].request) {
            test_ctx.c_cb.ssl_ready =
                test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
        }
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        if (params[i].expect == 0) {
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
        }
        else {
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                params[i].expect);
            XMEMSET(&h, 0, sizeof(h));
            ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(h.last_rx.code,
                params[i].expect == WC_NO_ERR_TRACE(CRL_CERT_REVOKED) ?
                certificate_revoked : certificate_unknown);
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
            ExpectIntEQ(wolfSSL_get_verify_result(test_ctx.c_ssl),
                params[i].expect == WC_NO_ERR_TRACE(CRL_CERT_REVOKED) ?
                WOLFSSL_X509_V_ERR_CERT_REVOKED :
                WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL);
#endif
        }
        /* Asked about the intermediate's missing CRL, then the leaf's. */
        if (params[i].waive) {
            ExpectIntEQ(test_ocsp_crl_ca_walk_opts.cbCalls, 2);
        }
        if (EXPECT_FAIL())
            fprintf(stderr, "case: %s\n", params[i].desc);
        test_ssl_memio_cleanup(&test_ctx);
    }
    XMEMSET(&test_ocsp_crl_ca_walk_opts, 0,
        sizeof(test_ocsp_crl_ca_walk_opts));

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

/* A good leaf staple answers a missing leaf CRL, but not a verify callback
 * that rejects the certificate on other grounds. */
int test_ocsp_staple_crl_verify_cb_reject(void)
{
    EXPECT_DECLS;
    int pinFail;

    for (pinFail = 0; pinFail < 2 && !EXPECT_FAIL(); pinFail++) {
        struct test_ssl_memio_ctx test_ctx;

        XMEMSET(&test_ocsp_crl_ca_walk_opts, 0,
            sizeof(test_ocsp_crl_ca_walk_opts));
        test_ocsp_crl_ca_walk_opts.rootCrl = "./certs/ocsp/root-ca-crl.pem";
        test_ocsp_crl_ca_walk_opts.staple = 1;
        test_ocsp_crl_ca_walk_opts.noLeafCrl = 1;
        test_ocsp_crl_ca_walk_opts.pinFail = pinFail;
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_cb.method = wolfTLSv1_2_client_method;
        test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-leaf.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_crl_ca_walk_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_crl_ca_walk_ctx_ready;
        test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_crl_ssl_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
#ifdef WOLFSSL_ALWAYS_VERIFY_CB
        if (pinFail) {
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                WC_NO_ERR_TRACE(VERIFY_CERT_ERROR));
        }
        else
#endif
        {
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
        }
        /* Asked about the missing CRL, then about the certificate alone. */
#ifdef WOLFSSL_ALWAYS_VERIFY_CB
        ExpectIntEQ(test_ocsp_crl_ca_walk_opts.cbCalls, 2);
#else
        ExpectIntEQ(test_ocsp_crl_ca_walk_opts.cbCalls, 1);
#endif
        if (EXPECT_FAIL())
            fprintf(stderr, "pinFail %d\n", pinFail);
        test_ssl_memio_cleanup(&test_ctx);
    }
    XMEMSET(&test_ocsp_crl_ca_walk_opts, 0,
        sizeof(test_ocsp_crl_ca_walk_opts));

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#else
int test_ocsp_acked_no_leaf_staple_crl(void)
{
    return TEST_SKIPPED;
}

int test_ocsp_acked_no_status_crl_verify_cb(void)
{
    return TEST_SKIPPED;
}

int test_ocsp_acked_no_status_crl_ca_walk(void)
{
    return TEST_SKIPPED;
}

int test_ocsp_staple_crl_verify_cb_reject(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && HAVE_CERTIFICATE_STATUS_REQUEST && */
       /* HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && !WOLFSSL_NO_TLS12 && */
       /* !NO_RSA && !NO_SHA */

#if defined(HAVE_OCSP) && defined(HAVE_CRL) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    !defined(NO_RSA) && !defined(NO_SHA)

static int test_ocsp_staple_crl_policy_leaf;

static int test_ocsp_staple_crl_policy_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* Staples the leaf, or only the intermediate to leave the leaf's slot empty. */
static int test_ocsp_staple_crl_policy_status_cb(WOLFSSL* ssl, void* ctx)
{
    unsigned char* src;
    int sz;
    word32 idx;

    (void)ctx;
    if (test_ocsp_staple_crl_policy_leaf) {
        src = resp_server1_cert;
        sz = (int)sizeof(resp_server1_cert);
        idx = 0;
    }
    else {
        src = resp_intermediate1_cert;
        sz = (int)sizeof(resp_intermediate1_cert);
        idx = 1;
    }

    return test_ocsp_set_staple(ssl, src, sz, idx);
}

static int test_ocsp_staple_crl_policy_nostaple_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_staple_crl_policy_badresp_io_cb(void* ioCtx,
    const char* url, int urlSz, unsigned char* request, int requestSz,
    unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;

    *response = resp_forged_responder_cert;

    return (int)sizeof(resp_forged_responder_cert);
}

static int test_ocsp_staple_crl_policy_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/ocsp/root-ca-crl.pem",
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* As above, plus the CRL the leaf's own issuer signed, which revokes nothing. */
static int test_ocsp_staple_crl_policy_badresp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(test_ocsp_staple_crl_policy_ctx_ready(ctx), TEST_SUCCESS);
    /* The CRL below is signed by this CA, so it has to be loaded first. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
                    "./certs/ocsp/intermediate1-ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                    "./certs/ocsp/intermediate1-ca-crl.pem",
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
                    WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                    test_ocsp_staple_crl_policy_badresp_io_cb, NULL, NULL),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_staple_crl_policy_cb_err;

static int test_ocsp_staple_crl_policy_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    if (!preverify && store->error_depth == 0)
        test_ocsp_staple_crl_policy_cb_err = store->error;
    return preverify;
}

/* The CRL the leaf's own issuer signed, revoking the leaf itself. */
static int test_ocsp_staple_crl_policy_revoked_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER,
        test_ocsp_staple_crl_policy_verify_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, 0), WOLFSSL_SUCCESS);
    /* The CRL below is signed by this CA, so it has to be loaded first. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
                    "./certs/ocsp/intermediate1-ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                    "./certs/ocsp/intermediate1-ca-crl-revoked.pem",
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_staple_crl_policy_crl_pem_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/crl/crl.pem",
                    WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_staple_crl_policy(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    WOLFSSL_ALERT_HISTORY h;

    test_ocsp_srv_status_cb = test_ocsp_staple_crl_policy_status_cb;

    /* A validated leaf staple answers the leaf's revocation status, so a CRL
     * store holding nothing for its issuer must not reject the handshake. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_staple_crl_policy_leaf = 1;
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    test_ssl_memio_cleanup(&test_ctx);

    /* Nothing stapled for the leaf, so the client looks it up and rejects the
     * responder. A CRL that revokes nothing must not overturn that. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_staple_crl_policy_leaf = 0;
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_badresp_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(OCSP_LOOKUP_FAIL));
    test_ssl_memio_cleanup(&test_ctx);

#ifndef WOLFSSL_NO_TLS12
    /* TLS 1.2 reaches the same verdict through the held CRL result: a
     * validated staple answers the leaf, so an empty store must not reject. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_staple_crl_policy_leaf = 1;
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    test_ssl_memio_cleanup(&test_ctx);
#endif

    /* A CRL that revokes the leaf overrides its staple, on both versions. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_staple_crl_policy_leaf = 1;
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_revoked_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    test_ocsp_staple_crl_policy_cb_err = 0;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    /* The verify callback is told, as for a leaf without a staple. */
#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    ExpectIntEQ(test_ocsp_staple_crl_policy_cb_err,
        WOLFSSL_X509_V_ERR_CERT_REVOKED);
#else
    ExpectIntEQ(test_ocsp_staple_crl_policy_cb_err,
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#endif
    XMEMSET(&h, 0, sizeof(h));
    ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.level, alert_fatal);
    ExpectIntEQ(h.last_rx.code, certificate_revoked);
    test_ssl_memio_cleanup(&test_ctx);

#ifndef WOLFSSL_NO_TLS12
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_staple_crl_policy_leaf = 1;
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_revoked_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    test_ocsp_staple_crl_policy_cb_err = 0;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    /* The verify callback is told, as for a leaf without a staple. */
#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    ExpectIntEQ(test_ocsp_staple_crl_policy_cb_err,
        WOLFSSL_X509_V_ERR_CERT_REVOKED);
#else
    ExpectIntEQ(test_ocsp_staple_crl_policy_cb_err,
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#endif
    XMEMSET(&h, 0, sizeof(h));
    ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(h.last_rx.level, alert_fatal);
    ExpectIntEQ(h.last_rx.code, certificate_revoked);
    test_ssl_memio_cleanup(&test_ctx);
#endif

    /* The server echoes status_request but server-revoked-cert.pem names no
     * responder, so the CRL still decides on TLS 1.3 as it does on TLS 1.2. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/server-revoked-cert.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-revoked-key.pem";
    test_ctx.s_cb.ctx_ready = test_ocsp_staple_crl_policy_nostaple_ctx_ready;
    test_ctx.c_cb.ctx_ready = test_ocsp_staple_crl_policy_crl_pem_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    test_ssl_memio_cleanup(&test_ctx);

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#ifdef HAVE_CRL_IO
static int test_ocsp_leaf_staple_crl_io_calls;
static int test_ocsp_leaf_staple_crl_io_block;

/* Never finds a CRL; with block set, each fetch first reports would-block. */
static int test_ocsp_leaf_staple_crl_io_cb(WOLFSSL_CRL* crl, const char* url,
    int urlSz)
{
    (void)crl;
    (void)url;
    (void)urlSz;

    test_ocsp_leaf_staple_crl_io_calls++;
    if (test_ocsp_leaf_staple_crl_io_block &&
            (test_ocsp_leaf_staple_crl_io_calls % 2) == 1) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return -1;
}

static int test_ocsp_leaf_staple_crl_io_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPMustStaple(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetCRL_IOCb(ctx, test_ocsp_leaf_staple_crl_io_cb),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_crl_io_ancestor_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/ocsp/intermediate1-ca-crl.pem", WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetCRL_IOCb(ctx, test_ocsp_leaf_staple_crl_io_cb),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_crl_io_nostaple_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetCRL_IOCb(ctx, test_ocsp_leaf_staple_crl_io_cb),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

/* The leaf's CRL is fetched after its staple verified; a fetch that first
 * blocks must not cost the must-staple client that staple on the retry. */
int test_ocsp_leaf_staple_crl_would_block(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CRL_IO
    struct test_ssl_memio_ctx test_ctx;
    int blocking;
#ifndef NO_FILESYSTEM
    WOLFSSL_CERT_MANAGER* cm = NULL;
    byte der[2048];
    int derSz = 0;
    XFILE f = XBADFILE;
#endif

    for (blocking = 0; blocking <= 1 && !EXPECT_FAIL(); blocking++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ocsp_leaf_staple_crl_io_calls = 0;
        test_ocsp_leaf_staple_crl_io_block = blocking;
        test_ocsp_staple_crl_policy_leaf = 1;
        test_ctx.c_cb.method = wolfTLSv1_3_client_method;
        test_ctx.s_cb.method = wolfTLSv1_3_server_method;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_staple_crl_policy_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_leaf_staple_crl_io_ctx_ready;
        test_ctx.c_cb.ssl_ready = test_ocsp_staple_crl_policy_ssl_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
            TEST_SUCCESS);
        /* The fetch ran, and ran again after it blocked; a blocking build
         * takes the would-block as a missing CRL instead. */
        ExpectIntEQ(test_ocsp_leaf_staple_crl_io_calls,
            1 + blocking * TEST_OCSP_NONBLOCK_MAX);
        if (EXPECT_FAIL())
            fprintf(stderr, "block %d\n", blocking);
        test_ssl_memio_cleanup(&test_ctx);
    }

    /* With nothing stapled the CRL decides, and a fetch that never finds one
     * is a missing CRL whether or not it first blocked. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_leaf_staple_crl_io_calls = 0;
    test_ocsp_leaf_staple_crl_io_block = 1;
    test_ctx.c_cb.ctx_ready = test_ocsp_crl_io_nostaple_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_MISSING));
    ExpectIntEQ(test_ocsp_leaf_staple_crl_io_calls,
        1 + TEST_OCSP_NONBLOCK_MAX);
    test_ssl_memio_cleanup(&test_ctx);

    /* Only the leaf arrives, so the walk over the CAs above it fetches the
     * root's CRL, which first blocks and is then missing. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_leaf_staple_crl_io_calls = 0;
    test_ocsp_leaf_staple_crl_io_block = 1;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-leaf.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_crl_io_ancestor_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_MISSING));
    ExpectIntEQ(test_ocsp_leaf_staple_crl_io_calls,
        1 + TEST_OCSP_NONBLOCK_MAX);
    test_ssl_memio_cleanup(&test_ctx);

#ifndef NO_FILESYSTEM
    /* A synchronous check has nothing to retry, so the same fetch reports
     * the CRL missing. */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(cm, "./certs/ca-cert.pem", NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerEnableCRL(cm, WOLFSSL_CRL_CHECK),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CertManagerSetCRL_IOCb(cm,
            test_ocsp_leaf_staple_crl_io_cb), WOLFSSL_SUCCESS);
    test_ocsp_leaf_staple_crl_io_calls = 0;
    ExpectIntEQ(wolfSSL_CertManagerVerify(cm, "./certs/server-cert.pem",
            WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(CRL_MISSING));
    ExpectTrue((f = XFOPEN("./certs/server-cert.der", "rb")) != XBADFILE);
    ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);
    test_ocsp_leaf_staple_crl_io_calls = 0;
    ExpectIntEQ(wolfSSL_CertManagerCheckCRL(cm, der, derSz),
        WC_NO_ERR_TRACE(CRL_MISSING));
    wolfSSL_CertManagerFree(cm);
#endif
#endif
    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#else
int test_ocsp_staple_crl_policy(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_leaf_staple_crl_would_block(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && WOLFSSL_TLS13 && */
       /* HAVE_CERTIFICATE_STATUS_REQUEST && */
       /* HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && */
       /* !WOLFSSL_CRL_ALLOW_MISSING_CDP && !NO_RSA && !NO_SHA */

#if defined(HAVE_OCSP) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA)

static int test_ocsp_acked_no_leaf_staple_ocsp_cnt;
static int test_ocsp_acked_no_leaf_staple_ocsp_block;
static const char* test_ocsp_acked_no_leaf_staple_ocsp_crl;

static int test_ocsp_acked_no_leaf_staple_ocsp_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_acked_no_leaf_staple_ocsp_io_cb(void* ioCtx,
    const char* url, int urlSz, unsigned char* request, int requestSz,
    unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;

    if (test_ocsp_acked_no_leaf_staple_ocsp_block > 0) {
        test_ocsp_acked_no_leaf_staple_ocsp_block--;
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    test_ocsp_acked_no_leaf_staple_ocsp_cnt++;
    *response = (unsigned char*)resp_server1_cert;

    return (int)sizeof(resp_server1_cert);
}

/* Staple for the intermediate only, leaving the leaf's slot empty. */
static int test_ocsp_acked_no_leaf_staple_status_cb(WOLFSSL* ssl, void* ctx)
{
    (void)ctx;
    return test_ocsp_set_staple(ssl, resp_intermediate1_cert,
        (int)sizeof(resp_intermediate1_cert), 1);
}

static int test_ocsp_acked_no_leaf_staple_ocsp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
                    WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                    test_ocsp_acked_no_leaf_staple_ocsp_io_cb, NULL, NULL),
        WOLFSSL_SUCCESS);
#ifdef HAVE_CRL
    if (test_ocsp_acked_no_leaf_staple_ocsp_crl != NULL) {
        ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, 0), WOLFSSL_SUCCESS);
        /* The CRL below is signed by this CA, so it has to be loaded first. */
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
                        "./certs/ocsp/intermediate1-ca-cert.pem", NULL),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                        test_ocsp_acked_no_leaf_staple_ocsp_crl,
                        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }
#endif

    return EXPECT_RESULT();
}

int test_ocsp_acked_no_leaf_staple_ocsp(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
#if defined(HAVE_CRL) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    int blocking;
#endif

    /* Only the intermediate is stapled, so the client still looks the leaf
     * up. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ocsp_acked_no_leaf_staple_ocsp_cnt = 0;
    test_ocsp_acked_no_leaf_staple_ocsp_block = 0;
    test_ocsp_acked_no_leaf_staple_ocsp_crl = NULL;
    test_ctx.c_cb.method = wolfTLSv1_3_client_method;
    test_ctx.s_cb.method = wolfTLSv1_3_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ocsp_srv_status_cb = test_ocsp_acked_no_leaf_staple_status_cb;
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_ocsp_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_ocsp_ssl_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(test_ocsp_acked_no_leaf_staple_ocsp_cnt, 1);
    test_ssl_memio_cleanup(&test_ctx);

#if defined(HAVE_CRL) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    /* The responder vouches for the leaf and its issuer's CRL revokes it, so
     * the CRL wins, including when the lookup first has to be retried. */
    for (blocking = 0; blocking <= TEST_OCSP_NONBLOCK_MAX && !EXPECT_FAIL();
            blocking++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ocsp_acked_no_leaf_staple_ocsp_cnt = 0;
        test_ocsp_acked_no_leaf_staple_ocsp_block = blocking;
        test_ocsp_acked_no_leaf_staple_ocsp_crl =
            "./certs/ocsp/intermediate1-ca-crl-revoked.pem";
        test_ctx.c_cb.method = wolfTLSv1_3_client_method;
        test_ctx.s_cb.method = wolfTLSv1_3_server_method;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_acked_no_leaf_staple_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_acked_no_leaf_staple_ocsp_ctx_ready;
        test_ctx.c_cb.ssl_ready = test_ocsp_acked_no_leaf_staple_ocsp_ssl_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
            TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
            WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
        ExpectIntEQ(test_ocsp_acked_no_leaf_staple_ocsp_cnt, 1);
        ExpectIntEQ(test_ocsp_acked_no_leaf_staple_ocsp_block, 0);
        if (EXPECT_FAIL())
            fprintf(stderr, "revoking CRL, block %d\n", blocking);
        test_ssl_memio_cleanup(&test_ctx);
    }
    test_ocsp_acked_no_leaf_staple_ocsp_crl = NULL;
#endif

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#else
int test_ocsp_acked_no_leaf_staple_ocsp(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && WOLFSSL_TLS13 && HAVE_CERTIFICATE_STATUS_REQUEST && */
       /* HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && !NO_RSA && !NO_SHA */

#if defined(HAVE_OCSP) && defined(HAVE_OCSP_RESPONDER) && \
    defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA)
static OcspResponder* test_ocsp_resp_responder;

/* Lets the responder answer for cert with the given status. */
static int test_ocsp_resp_add(const char* certFile,
    const char* issuerFile, const char* keyFile, enum Ocsp_Cert_Status status)
{
    EXPECT_DECLS;
    byte* cert = NULL;
    byte* issuer = NULL;
    byte* key = NULL;
    size_t certSz = 0;
    size_t issuerSz = 0;
    size_t keySz = 0;
    DecodedCert dCert;
    DecodedCert dIssuer;
    char subject[WC_ASN_NAME_MAX];
    word32 subjectSz = sizeof(subject);
    byte serial[EXTERNAL_SERIAL_SIZE];
    word32 serialSz = sizeof(serial);

    ExpectIntEQ(load_file(certFile, &cert, &certSz), 0);
    ExpectIntEQ(load_file(issuerFile, &issuer, &issuerSz), 0);
    ExpectIntEQ(load_file(keyFile, &key, &keySz), 0);
    wc_InitDecodedCert(&dCert, cert, (word32)certSz, NULL);
    wc_InitDecodedCert(&dIssuer, issuer, (word32)issuerSz, NULL);
    ExpectIntEQ(wc_ParseCert(&dCert, CERT_TYPE, 0, NULL), 0);
    ExpectIntEQ(wc_ParseCert(&dIssuer, CERT_TYPE, 0, NULL), 0);
    ExpectIntEQ(wc_OcspResponder_AddSigner(
        test_ocsp_resp_responder, issuer, (word32)issuerSz, key,
        (word32)keySz, NULL, 0), 0);
    ExpectIntEQ(wc_GetDecodedCertSubject(&dIssuer, subject, &subjectSz), 0);
    ExpectIntEQ(wc_GetDecodedCertSerial(&dCert, serial, &serialSz), 0);
    ExpectIntEQ(wc_OcspResponder_SetCertStatus(
        test_ocsp_resp_responder, subject, subjectSz, serial,
        serialSz, status, status == CERT_REVOKED ? wc_Time(NULL) - 3600 : 0,
        status == CERT_REVOKED ? WC_CRL_REASON_KEY_COMPROMISE :
        WC_CRL_REASON_UNSPECIFIED, status == CERT_GOOD ? 3600 : 0), 0);

    wc_FreeDecodedCert(&dCert);
    wc_FreeDecodedCert(&dIssuer);
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(issuer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}

static int test_ocsp_resp_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** response)
{
    word32 respSz = 0;

    (void)ioCtx;
    (void)url;
    (void)urlSz;
    if (wc_OcspResponder_WriteResponse(test_ocsp_resp_responder,
            req, (word32)reqSz, NULL, &respSz) != 0)
        return -1;
    *response = (unsigned char*)XMALLOC(respSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (*response == NULL)
        return -1;
    if (wc_OcspResponder_WriteResponse(test_ocsp_resp_responder,
            req, (word32)reqSz, *response, &respSz) != 0) {
        XFREE(*response, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *response = NULL;
        return -1;
    }
    return (int)respSz;
}

static void test_ocsp_resp_io_free(void* ioCtx,
    unsigned char* response)
{
    (void)ioCtx;
    XFREE(response, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

static int test_ocsp_revocation_alert_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
            WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ocsp_resp_io_cb,
            test_ocsp_resp_io_free, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* A leaf the lookup finds revoked gets certificate_revoked, one it cannot
 * settle certificate_unknown. */
int test_ocsp_revocation_alert(void)
{
    EXPECT_DECLS;
    size_t i;
    int tls13;
    static const struct {
        enum Ocsp_Cert_Status status;
        int expect;
        int alert;
    } params[] = {
        { CERT_REVOKED, WC_NO_ERR_TRACE(OCSP_CERT_REVOKED),
          certificate_revoked },
        { CERT_UNKNOWN, WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN),
          certificate_unknown },
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        ExpectNotNull(test_ocsp_resp_responder = wc_OcspResponder_new(NULL,
            0));
        ExpectIntEQ(test_ocsp_resp_add(
            "./certs/intermediate/server-int-cert.der",
            "./certs/intermediate/ca-int2-cert.der",
            "./certs/intermediate/ca-int2-key.der", params[i].status),
            TEST_SUCCESS);
        for (tls13 = 0; tls13 < 2 && !EXPECT_FAIL(); tls13++) {
            struct test_ssl_memio_ctx test_ctx;
            WOLFSSL_ALERT_HISTORY h;

        #ifndef WOLFSSL_TLS13
            if (tls13)
                break;
        #endif
        #ifdef WOLFSSL_NO_TLS12
            if (!tls13)
                continue;
        #endif
            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        #ifdef WOLFSSL_TLS13
            if (tls13) {
                test_ctx.s_cb.method = wolfTLSv1_3_server_method;
                test_ctx.c_cb.method = wolfTLSv1_3_client_method;
            }
        #endif
        #ifndef WOLFSSL_NO_TLS12
            if (!tls13) {
                test_ctx.s_cb.method = wolfTLSv1_2_server_method;
                test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            }
        #endif
            test_ctx.s_cb.certPemFile =
                "./certs/intermediate/server-chain-short.pem";
            test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
            test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
            test_ctx.c_cb.ctx_ready = test_ocsp_revocation_alert_ctx_ready;
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                params[i].expect);
            XMEMSET(&h, 0, sizeof(h));
            ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(h.last_rx.level, alert_fatal);
            ExpectIntEQ(h.last_rx.code, params[i].alert);
            if (EXPECT_FAIL())
                fprintf(stderr, "status %d, tls13 %d\n", params[i].status,
                    tls13);
            test_ssl_memio_cleanup(&test_ctx);
        }
        wc_OcspResponder_free(test_ocsp_resp_responder);
        test_ocsp_resp_responder = NULL;
    }

    return EXPECT_RESULT();
}
#else
int test_ocsp_revocation_alert(void)
{
    return TEST_SKIPPED;
}
#endif

/* CHECKALL CRL client with stapling: each chain CRL verdict is held back for a
 * staple, so an entry that no staple and no OCSP answer covered must get it. */
#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    !defined(NO_RSA) && !defined(NO_SHA) && \
    ((defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)) || \
     (defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
      !defined(WOLFSSL_NO_TLS12)))

static struct {
    const char* crlFile;
    int staple;
    int checkAll;
    int verifyNone;
    int waive;
    int waived;
    int depthLimit;
    int cmWaive;
} test_ocsp_unstapled_chain_crl_opts;

/* Waives any error on the intermediate, or passes preverify through. */
static int test_ocsp_unstapled_chain_crl_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    if (test_ocsp_unstapled_chain_crl_opts.waive && !preverify &&
            store->error_depth == 1) {
        test_ocsp_unstapled_chain_crl_opts.waived++;
        return 1;
    }
    return preverify;
}

#ifndef NO_WOLFSSL_CM_VERIFY
static int test_ocsp_unstapled_chain_crl_cm_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    (void)preverify;
    (void)store;
    return 1;
}
#endif

/* Index 1, intermediate1, is deliberately left unstapled. */
static int test_ocsp_unstapled_chain_crl_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    if (!test_ocsp_unstapled_chain_crl_opts.staple)
        return WOLFSSL_OCSP_STATUS_CB_NOACK;
    return test_ocsp_set_staple(ssl, resp_server1_cert,
        (int)sizeof(resp_server1_cert), 0);
}

/* The leaf is good, the intermediate is unknown to the responder. */
static int test_ocsp_unstapled_chain_crl_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** response)
{
    int i;
    int serial = -1;

    (void)ioCtx;
    (void)url;
    (void)urlSz;

    for (i = 0; i + 24 < reqSz; i++) {
        if (req[i] == 0x04 && req[i + 1] == 0x14 && req[i + 22] == 0x02 &&
                req[i + 23] == 0x01) {
            serial = req[i + 24];
            break;
        }
    }
    if (serial == 0x05) {
        *response = (unsigned char*)resp_server1_cert;
        return (int)sizeof(resp_server1_cert);
    }
    if (serial == 0x01) {
        *response = (unsigned char*)resp_cert_unknown;
        return (int)sizeof(resp_cert_unknown);
    }
    return -1;
}

static int test_ocsp_unstapled_chain_crl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    int options = WOLFSSL_OCSP_NO_NONCE;

    if (test_ocsp_unstapled_chain_crl_opts.checkAll)
        options |= WOLFSSL_OCSP_CHECKALL | WOLFSSL_OCSP_URL_OVERRIDE;

    wolfSSL_CTX_set_verify(ctx, test_ocsp_unstapled_chain_crl_opts.verifyNone ?
        WOLFSSL_VERIFY_NONE : WOLFSSL_VERIFY_PEER,
        (test_ocsp_unstapled_chain_crl_opts.waive ||
         test_ocsp_unstapled_chain_crl_opts.cmWaive) ?
        test_ocsp_unstapled_chain_crl_verify_cb : NULL);
    if (test_ocsp_unstapled_chain_crl_opts.depthLimit)
        wolfSSL_CTX_set_verify_depth(ctx, 0);
#ifndef NO_WOLFSSL_CM_VERIFY
    if (test_ocsp_unstapled_chain_crl_opts.cmWaive) {
        wolfSSL_CertManagerSetVerify(wolfSSL_CTX_GetCertManager(ctx),
            test_ocsp_unstapled_chain_crl_cm_verify_cb);
    }
#endif
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, options), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    if (test_ocsp_unstapled_chain_crl_opts.checkAll) {
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
            WOLFSSL_SUCCESS);
        /* After EnableOCSPStapling, which installs the built-in lookup. */
        ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                test_ocsp_unstapled_chain_crl_io_cb, NULL, NULL),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    /* The CRL signer has to be in the manager before its CRL loads. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
            "./certs/ocsp/intermediate1-ca-crl.pem", WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);
    if (test_ocsp_unstapled_chain_crl_opts.crlFile != NULL) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx,
                test_ocsp_unstapled_chain_crl_opts.crlFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

int test_ocsp_unstapled_chain_crl(void)
{
    EXPECT_DECLS;
    size_t i;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* desc;
        int useV2;
        int staple;
        int checkAll;
        const char* crlFile;
        int expected;
        int verifyNone;
        int waive;
        int depthLimit;
        int cmWaive;
    } params[] = {
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, no CRL for the unstapled intermediate", 0, 1, 0,
          NULL, WC_NO_ERR_TRACE(CRL_MISSING), 0, 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, a CRL that covers the unstapled intermediate", 0, 1, 0,
          "./certs/ocsp/root-ca-crl.pem", 0, 0, 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, a CRL that revokes the unstapled intermediate", 0, 1, 0,
          "./certs/ocsp/root-ca-crl-revoked.pem",
          WC_NO_ERR_TRACE(CRL_CERT_REVOKED), 0, 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, the responder does not know the intermediate", 0, 1, 1,
          "./certs/ocsp/root-ca-crl.pem", 0, 0, 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, neither the responder nor a CRL covers it", 0, 1, 1,
          NULL, WC_NO_ERR_TRACE(CRL_MISSING), 0, 0, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, neither covers it and verification is off", 0, 1, 1,
          NULL, 0, 1, 0, 0, 0 },
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, no CRL for the unstapled intermediate", 1, 1, 0,
          NULL, WC_NO_ERR_TRACE(CRL_MISSING), 0, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, a CRL that covers it", 1, 1, 0,
          "./certs/ocsp/root-ca-crl.pem", 0, 0, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, no CertificateStatus at all", 1, 0, 1,
          "./certs/ocsp/root-ca-crl.pem", 0, 0, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, neither the responder nor a CRL covers it",
          1, 1, 1, NULL, WC_NO_ERR_TRACE(CRL_MISSING), 0, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, neither covers it and verification is off",
          1, 1, 1, NULL, 0, 1, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, the verify callback waives the missing CRL",
          1, 1, 1, NULL, 0, 0, 1, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, the verify callback waives the revocation",
          1, 1, 1, "./certs/ocsp/root-ca-crl-revoked.pem", 0, 0, 1, 0, 0 },
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, the callback waives a depth error, then the CRL",
          1, 1, 1, NULL, 0, 0, 2, 1, 0 },
#endif
#ifndef NO_WOLFSSL_CM_VERIFY
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, only the CM callback waives the missing CRL",
          1, 1, 1, NULL, WC_NO_ERR_TRACE(CRL_MISSING), 0, 0, 0, 1 },
#endif
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;

        XMEMSET(&test_ocsp_unstapled_chain_crl_opts, 0,
            sizeof(test_ocsp_unstapled_chain_crl_opts));
        test_ocsp_unstapled_chain_crl_opts.crlFile = params[i].crlFile;
        test_ocsp_unstapled_chain_crl_opts.staple = params[i].staple;
        test_ocsp_unstapled_chain_crl_opts.checkAll = params[i].checkAll;
        test_ocsp_unstapled_chain_crl_opts.verifyNone = params[i].verifyNone;
        test_ocsp_unstapled_chain_crl_opts.waive = params[i].waive;
        test_ocsp_unstapled_chain_crl_opts.depthLimit = params[i].depthLimit;
        test_ocsp_unstapled_chain_crl_opts.cmWaive = params[i].cmWaive;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.s_cb.method = params[i].server_meth;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_unstapled_chain_crl_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.method = params[i].client_meth;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_unstapled_chain_crl_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);

        if (params[i].useV2) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
            ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
#endif
        }
        else {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
            ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                WOLFSSL_CSR_OCSP, 0), WOLFSSL_SUCCESS);
#endif
        }

        if (params[i].expected == 0) {
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
        }
        else {
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                params[i].expected);
        }
        if (params[i].waive) {
            ExpectIntEQ(test_ocsp_unstapled_chain_crl_opts.waived,
                params[i].waive);
        }
        if (EXPECT_FAIL()) {
            fprintf(stderr, "case: %s\n", params[i].desc);
        }

        test_ssl_memio_cleanup(&test_ctx);
    }

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#ifdef HAVE_CRL_IO
static int test_ocsp_unstapled_chain_crl_io_calls;
static int test_ocsp_unstapled_chain_crl_io_block;

/* Never finds a CRL; with block set, each fetch first reports would-block. */
static int test_ocsp_unstapled_chain_crl_fetch_cb(WOLFSSL_CRL* crl,
    const char* url, int urlSz)
{
    (void)crl;
    (void)url;
    (void)urlSz;

    test_ocsp_unstapled_chain_crl_io_calls++;
    if (test_ocsp_unstapled_chain_crl_io_block &&
            (test_ocsp_unstapled_chain_crl_io_calls % 2) == 1) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return -1;
}

static int test_ocsp_unstapled_chain_crl_fetch_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
            test_ocsp_unstapled_chain_crl_io_cb, NULL, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetCRL_IOCb(ctx,
            test_ocsp_unstapled_chain_crl_fetch_cb), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

/* Retried CRL fetches must keep each certificate's staple index, or one
 * certificate is judged by another's verdict. */
int test_ocsp_unstapled_chain_crl_would_block(void)
{
    EXPECT_DECLS;
#ifdef HAVE_CRL_IO
    size_t i;
    int blocking;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* desc;
        int useV2;
        int fetches;
    } params[] = {
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3 status_request, the fallback fails before the leaf's",
          0, 1 },
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, both before CertificateStatus", 1, 2 },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        for (blocking = 0; blocking <= TEST_OCSP_NONBLOCK_MAX && !EXPECT_FAIL();
                blocking++) {
            struct test_ssl_memio_ctx test_ctx;

            XMEMSET(&test_ocsp_unstapled_chain_crl_opts, 0,
                sizeof(test_ocsp_unstapled_chain_crl_opts));
            test_ocsp_unstapled_chain_crl_opts.staple = 1;
            test_ocsp_unstapled_chain_crl_io_calls = 0;
            test_ocsp_unstapled_chain_crl_io_block = blocking;

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            test_ctx.s_cb.method = params[i].server_meth;
            test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
            test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
            test_ocsp_srv_status_cb = test_ocsp_unstapled_chain_crl_status_cb;
            test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
            test_ctx.c_cb.method = params[i].client_meth;
            test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
            test_ctx.c_cb.ctx_ready =
                test_ocsp_unstapled_chain_crl_fetch_ctx_ready;
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
            if (params[i].useV2) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                    WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
#endif
            }
            else {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                    WOLFSSL_CSR_OCSP, 0), WOLFSSL_SUCCESS);
#endif
            }

            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                WC_NO_ERR_TRACE(CRL_MISSING));
            /* Each fetch ran once more after it blocked. */
            ExpectIntEQ(test_ocsp_unstapled_chain_crl_io_calls,
                params[i].fetches * (1 + blocking));
            if (EXPECT_FAIL()) {
                fprintf(stderr, "case: %s, block %d\n", params[i].desc,
                    blocking);
            }

            test_ssl_memio_cleanup(&test_ctx);
        }
    }
#endif
    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

static byte test_ocsp_no_url_staple[4096];
static int  test_ocsp_no_url_stapleSz;
static struct {
    const char* crlFile;
    int failIfNotSupported;
} test_ocsp_no_url_opts;

/* server6's own response; intermediate4 is left unstapled. */
static int test_ocsp_no_url_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    return test_ocsp_set_staple(ssl, test_ocsp_no_url_staple,
        test_ocsp_no_url_stapleSz, 0);
}

static int test_ocsp_no_url_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    int options = WOLFSSL_OCSP_CHECKALL | WOLFSSL_OCSP_NO_NONCE;

    if (test_ocsp_no_url_opts.failIfNotSupported)
        options |= WOLFSSL_OCSP_FAIL_IF_NOT_SUPPORTED;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, options), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    if (test_ocsp_no_url_opts.crlFile != NULL) {
        ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, test_ocsp_no_url_opts.crlFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

/* intermediate4-ca names no OCSP responder, so the no-URL policy decides,
 * and a soft pass must not skip the CRL. */
int test_ocsp_unstapled_chain_no_url(void)
{
    EXPECT_DECLS;
    size_t i;
    XFILE f = XBADFILE;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* desc;
        int useV2;
        int failIfNotSupported;
        const char* crlFile;
        int expected;
    } params[] = {
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, no CRL either", 0, 0, NULL,
          WC_NO_ERR_TRACE(CRL_MISSING) },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, a CRL covers it", 0, 0, "./certs/ocsp/root-ca-crl.pem",
          0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3, OCSP required for every certificate", 0, 1,
          "./certs/ocsp/root-ca-crl.pem", WC_NO_ERR_TRACE(OCSP_NEED_URL) },
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, no CRL either", 1, 0, NULL,
          WC_NO_ERR_TRACE(CRL_MISSING) },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, a CRL covers it", 1, 0,
          "./certs/ocsp/root-ca-crl.pem", 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, OCSP required for every certificate", 1, 1,
          "./certs/ocsp/root-ca-crl.pem", WC_NO_ERR_TRACE(OCSP_NEED_URL) },
#endif
    };

    ExpectTrue((f = XFOPEN("./certs/ocsp/test-server6-response.der", "rb"))
        != XBADFILE);
    if (f != XBADFILE) {
        test_ocsp_no_url_stapleSz = (int)XFREAD(test_ocsp_no_url_staple, 1,
            sizeof(test_ocsp_no_url_staple), f);
        XFCLOSE(f);
    }
    ExpectIntGT(test_ocsp_no_url_stapleSz, 0);

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        struct test_ssl_memio_ctx test_ctx;

        test_ocsp_no_url_opts.crlFile = params[i].crlFile;
        test_ocsp_no_url_opts.failIfNotSupported =
            params[i].failIfNotSupported;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.s_cb.method = params[i].server_meth;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server6-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server6-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_no_url_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.method = params[i].client_meth;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_no_url_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        if (params[i].useV2) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
            ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
#endif
        }
        else {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
            ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                WOLFSSL_CSR_OCSP, 0), WOLFSSL_SUCCESS);
#endif
        }

        if (params[i].expected == 0) {
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
        }
        else {
            ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                params[i].expected);
        }
        if (EXPECT_FAIL())
            fprintf(stderr, "case: %s\n", params[i].desc);

        test_ssl_memio_cleanup(&test_ctx);
    }

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_OCSP_RESPONDER) && \
    defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_FILESYSTEM)
static byte* test_ocsp_multi_waived_leaf_chain;
static size_t test_ocsp_multi_waived_leaf_chain_sz;

static int test_ocsp_multi_waived_leaf_srv_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(test_ocsp_srv_ctx_ready(ctx), TEST_SUCCESS);
    if (test_ocsp_multi_waived_leaf_chain != NULL) {
        ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
                test_ocsp_multi_waived_leaf_chain,
                (long)test_ocsp_multi_waived_leaf_chain_sz,
                WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

/* Waives any error on the leaf. */
static int test_ocsp_multi_waived_leaf_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    if (store->error_depth == 0)
        return 1;
    return preverify;
}

static int test_ocsp_multi_waived_leaf_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER,
        test_ocsp_multi_waived_leaf_verify_cb);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ocsp_resp_io_cb,
            test_ocsp_resp_io_free, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    /* The CRL signer has to be in the manager before its CRL loads. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/intermediate/ca-int-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(ctx, "./certs/crl/ca-int.pem",
            WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

/* Nothing is stapled, the responder does not know ca-int and no CRL covers
 * it, so the handshake fails even when the leaf had a waived error. */
int test_ocsp_multi_fallback_waived_leaf(void)
{
    EXPECT_DECLS;
    int leafErr;
    byte* chain = NULL;
    size_t chainSz = 0;
    byte* leaf = NULL;
    size_t leafSz = 0;

    /* The leaf with a broken signature, then its CAs. */
    ExpectIntEQ(load_file("./certs/intermediate/server-chain.der", &chain,
        &chainSz), 0);
    ExpectIntEQ(load_file("./certs/intermediate/server-int-cert.der", &leaf,
        &leafSz), 0);
    if (chain != NULL && leafSz > 0 && leafSz <= chainSz)
        chain[leafSz - 1] ^= 0x01;
    XFREE(leaf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    ExpectNotNull(test_ocsp_resp_responder =
        wc_OcspResponder_new(NULL, 0));
    ExpectIntEQ(test_ocsp_resp_add(
        "./certs/intermediate/server-int-cert.der",
        "./certs/intermediate/ca-int2-cert.der",
        "./certs/intermediate/ca-int2-key.der", CERT_GOOD), TEST_SUCCESS);
    ExpectIntEQ(test_ocsp_resp_add(
        "./certs/intermediate/ca-int2-cert.der",
        "./certs/intermediate/ca-int-cert.der",
        "./certs/intermediate/ca-int-key.der", CERT_GOOD), TEST_SUCCESS);
    ExpectIntEQ(test_ocsp_resp_add(
        "./certs/intermediate/ca-int-cert.der", "./certs/ca-cert.der",
        "./certs/ca-key.der", CERT_UNKNOWN), TEST_SUCCESS);

    for (leafErr = 0; leafErr < 2 && !EXPECT_FAIL(); leafErr++) {
        struct test_ssl_memio_ctx test_ctx;

        XMEMSET(&test_ocsp_unstapled_chain_crl_opts, 0,
            sizeof(test_ocsp_unstapled_chain_crl_opts));
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        test_ctx.s_cb.certPemFile = "./certs/intermediate/server-chain.pem";
        test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_unstapled_chain_crl_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_multi_waived_leaf_srv_ctx_ready;
        test_ctx.c_cb.method = wolfTLSv1_2_client_method;
        test_ctx.c_cb.caPemFile = "./certs/ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_multi_waived_leaf_ctx_ready;
        test_ocsp_multi_waived_leaf_chain = leafErr ? chain : NULL;
        test_ocsp_multi_waived_leaf_chain_sz = chainSz;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
            WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
        ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
            TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
            WC_NO_ERR_TRACE(CRL_MISSING));
        if (EXPECT_FAIL())
            fprintf(stderr, "leafErr %d\n", leafErr);
        test_ssl_memio_cleanup(&test_ctx);
    }

    wc_OcspResponder_free(test_ocsp_resp_responder);
    test_ocsp_resp_responder = NULL;
    test_ocsp_multi_waived_leaf_chain = NULL;
    XFREE(chain, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}
#else
int test_ocsp_multi_fallback_waived_leaf(void)
{
    return TEST_SKIPPED;
}
#endif

#else
int test_ocsp_unstapled_chain_crl(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_unstapled_chain_crl_would_block(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_unstapled_chain_no_url(void)
{
    return TEST_SKIPPED;
}
int test_ocsp_multi_fallback_waived_leaf(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_CRL && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && */
       /* !WOLFSSL_CRL_ALLOW_MISSING_CDP && !NO_RSA && !NO_SHA && */
       /* ((CSR && TLS13) || (CSR_V2 && !NO_TLS12)) */

#if defined(HAVE_CRL) && defined(HAVE_CRL_IO) && \
    defined(WOLFSSL_NONBLOCK_OCSP) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_LOCAL_X509_STORE) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && \
    !defined(NO_ASN_TIME) && !defined(NO_RSA)
static int test_crl_get_crl_cb_fetches;

static int test_crl_get_crl_cb_fetch_cb(WOLFSSL_CRL* crl, const char* url,
    int urlSz)
{
    (void)crl;
    (void)url;
    (void)urlSz;
    test_crl_get_crl_cb_fetches++;
    return WOLFSSL_CBIO_ERR_WANT_READ;
}

/* Hands out an empty CRL whose fetch always blocks. */
static int test_crl_get_crl_cb_provider(WOLFSSL_X509_STORE_CTX* ctx,
    WOLFSSL_X509_CRL** crl, WOLFSSL_X509* cert)
{
    (void)ctx;
    (void)cert;
    *crl = wolfSSL_X509_CRL_new();
    if (*crl == NULL)
        return 0;
    (*crl)->crlIOCb = test_crl_get_crl_cb_fetch_cb;
    return 1;
}

static int test_crl_get_crl_cb_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    WOLFSSL_X509_STORE* store = NULL;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectNotNull(store = wolfSSL_CTX_get_cert_store(ctx));
    wolfSSL_X509_STORE_set_get_crl(store, test_crl_get_crl_cb_provider);

    return EXPECT_RESULT();
}

/* The CRL from get_crl_cb is freed right after the check, so a fetch on it
 * that would block cannot be retried and counts as a missing CRL. */
int test_crl_get_crl_cb_would_block(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    test_crl_get_crl_cb_fetches = 0;
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_crl_get_crl_cb_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(CRL_MISSING));
    ExpectIntEQ(test_crl_get_crl_cb_fetches, 1);
    test_ssl_memio_cleanup(&test_ctx);

    return EXPECT_RESULT();
}
#else
int test_crl_get_crl_cb_would_block(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA)
static int test_ocsp_no_cdp_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl;
    (void)arg;
    return WOLFSSL_OCSP_STATUS_CB_NOACK;
}

/* The leaf (serial 5) is good, intermediate1 (serial 1) unknown. */
static int test_ocsp_no_cdp_io_cb(void* ioCtx, const char* url, int urlSz,
    unsigned char* req, int reqSz, unsigned char** response)
{
    int i;

    (void)ioCtx;
    (void)url;
    (void)urlSz;
    for (i = 0; i + 24 < reqSz; i++) {
        if (req[i] == 0x04 && req[i + 1] == 0x14 && req[i + 22] == 0x02 &&
                req[i + 23] == 0x01) {
            if (req[i + 24] == 0x05) {
                *response = (unsigned char*)resp_server1_cert;
                return (int)sizeof(resp_server1_cert);
            }
            if (req[i + 24] == 0x01) {
                *response = (unsigned char*)resp_cert_unknown;
                return (int)sizeof(resp_cert_unknown);
            }
        }
    }
    return -1;
}

static int test_ocsp_no_cdp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ocsp_no_cdp_io_cb, NULL,
            NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

/* With no CDP the CRL check is skipped, which must not settle an intermediate
 * the responder does not know, as it does not for the leaf. */
int test_ocsp_multi_fallback_no_cdp(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(HAVE_CRL) && \
    defined(WOLFSSL_CRL_ALLOW_MISSING_CDP) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA)
    struct test_ssl_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
    test_ocsp_srv_status_cb = test_ocsp_no_cdp_status_cb;
    test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.ctx_ready = test_ocsp_no_cdp_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
        WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
    ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
        WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN));
    test_ssl_memio_cleanup(&test_ctx);
    test_ocsp_srv_status_cb = NULL;
#endif
    return EXPECT_RESULT();
}

/* CHECKALL client with stapling: the server staples its leaf only, so the
 * client must look the unstapled intermediate up instead of skipping it. */
#if defined(HAVE_OCSP) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA) && \
    ((defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)) || \
     (defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
      !defined(WOLFSSL_NO_TLS12)))

static struct {
    int staple;
    int unknown;
    int ioErr;
    int block;
    int leafBlocked;
    int intBlocked;
    int leafLookups;
    int intLookups;
    int intNonce;
    int verifyCbCalls;
} test_ocsp_checkall_staple_opts;

static int test_ocsp_checkall_staple_verify_cb(WOLFSSL* ssl, int err,
    byte* staple, word32 stapleSz, word32 entry, void* arg)
{
    (void)ssl;
    (void)staple;
    (void)stapleSz;
    (void)entry;
    (void)arg;

    test_ocsp_checkall_staple_opts.verifyCbCalls++;
    return err;
}

/* 0 for a request without a nonce, 1 for a nonce, 2 for an all-zero one. */
static int test_ocsp_checkall_staple_nonce(const unsigned char* req,
    int reqSz)
{
    static const byte nonceOid[] = { 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05,
                                     0x07, 0x30, 0x01, 0x02 };
    int i;
    int j;

    for (i = 0; i + (int)sizeof(nonceOid) + 4 < reqSz; i++) {
        if (XMEMCMP(req + i, nonceOid, sizeof(nonceOid)) == 0) {
            const unsigned char* nonce = req + i + sizeof(nonceOid) + 4;
            int nonceSz = req[i + sizeof(nonceOid) + 3];

            if (nonce + nonceSz > req + reqSz)
                return 0;
            for (j = 0; j < nonceSz; j++) {
                if (nonce[j] != 0)
                    return 1;
            }
            return 2;
        }
    }
    return 0;
}

static int test_ocsp_checkall_staple_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)arg;
    if (!test_ocsp_checkall_staple_opts.staple)
        return WOLFSSL_OCSP_STATUS_CB_NOACK;
    /* Index 1, intermediate1, is deliberately left unstapled. */
    return test_ocsp_set_staple(ssl, resp_server1_cert,
        (int)sizeof(resp_server1_cert), 0);
}

static int test_ocsp_checkall_staple_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** response)
{
    int i;
    int serial = -1;
    (void)ioCtx;
    (void)url;
    (void)urlSz;

    /* The CertID tail is 04 14 <20 byte issuerKeyHash> 02 01 <serial>. */
    for (i = 0; i + 24 < reqSz; i++) {
        if (req[i] == 0x04 && req[i + 1] == 0x14 && req[i + 22] == 0x02 &&
                req[i + 23] == 0x01) {
            serial = req[i + 24];
            break;
        }
    }

    /* Each certificate's first lookup would block before it is answered. */
    if (test_ocsp_checkall_staple_opts.block) {
        int* blocked = (serial == 0x05) ?
            &test_ocsp_checkall_staple_opts.leafBlocked :
            &test_ocsp_checkall_staple_opts.intBlocked;

        if (!*blocked) {
            *blocked = 1;
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
    }

    if (serial == 0x05) {
        test_ocsp_checkall_staple_opts.leafLookups++;
        *response = (unsigned char*)resp_server1_cert;
        return (int)sizeof(resp_server1_cert);
    }
    if (serial == 0x01) {
        test_ocsp_checkall_staple_opts.intLookups++;
        test_ocsp_checkall_staple_opts.intNonce =
            test_ocsp_checkall_staple_nonce(req, reqSz);
        if (test_ocsp_checkall_staple_opts.ioErr != 0)
            return test_ocsp_checkall_staple_opts.ioErr;
        if (test_ocsp_checkall_staple_opts.unknown) {
            *response = (unsigned char*)resp_cert_unknown;
            return (int)sizeof(resp_cert_unknown);
        }
        *response = (unsigned char*)resp_intermediate1_cert;
        return (int)sizeof(resp_intermediate1_cert);
    }
    return -1;
}

/* Stapling lookups for the stock server: the leaf succeeds, the intermediate
 * fails, which leaves a zero-length entry in the ocsp_multi list. */
static int test_ocsp_checkall_staple_srv_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** response)
{
    int i;
    int serial = -1;
    (void)ioCtx;
    (void)url;
    (void)urlSz;

    for (i = 0; i + 24 < reqSz; i++) {
        if (req[i] == 0x04 && req[i + 1] == 0x14 && req[i + 22] == 0x02 &&
                req[i + 23] == 0x01) {
            serial = req[i + 24];
            break;
        }
    }
    if (serial == 0x05) {
        *response = (unsigned char*)resp_server1_cert;
        return (int)sizeof(resp_server1_cert);
    }
    return -1;
}

static int test_ocsp_checkall_staple_srv_stock_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    /* Added to the client CA the harness already loaded, so the server can
     * verify the delegated responder that signs the responses it staples. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/root-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    /* No EnableOCSP: the server must not OCSP check the client's own cert.
     * The staple lookups reach the callback through the cert's AIA URL. */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
            test_ocsp_checkall_staple_srv_io_cb, NULL, NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_checkall_staple_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_CHECKALL |
            WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    /* After EnableOCSPStapling, which installs the built-in lookup. */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ocsp_checkall_staple_io_cb,
            NULL, NULL), WOLFSSL_SUCCESS);
    wolfSSL_CTX_set_ocsp_status_verify_cb(ctx,
        test_ocsp_checkall_staple_verify_cb, NULL);

    return EXPECT_RESULT();
}

/* The intermediate is already trusted, as after an earlier stapled handshake,
 * so the ocsp item's leaf response verifies without the pending CA pool. */
static int test_ocsp_checkall_staple_preload_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(test_ocsp_checkall_staple_ctx_ready(ctx), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
            "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

#if defined(HAVE_CRL) && defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12)
static int test_ocsp_checkall_staple_noleafcrl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(test_ocsp_checkall_staple_ctx_ready(ctx), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}
#endif

int test_ocsp_checkall_staple_missing_chain(void)
{
    EXPECT_DECLS;
    size_t i;
    int run;
    int fail;
    int ioErr;
    int blocking;
    struct {
        method_provider client_meth;
        method_provider server_meth;
        const char* desc;
        int useV2; /* -1 requests no stapling, 2 ocsp then ocsp_multi */
        int staple;
        int stock;
        int nonce;
    } params[] = {
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12)
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, leaf stapled only", 1, 1, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, no CertificateStatus", 1, 0, 0, 0 },
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp_multi, zero-length entry for the intermediate",
          1, 0, 1, 0 },
        /* The server picks the ocsp item, which covers only the leaf. */
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 ocsp then ocsp_multi offered, ocsp chosen", 2, 1, 0, 0 },
#ifdef WOLFSSL_DTLS
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "DTLS 1.2 ocsp_multi, leaf stapled only", 1, 1, 0, 0 },
        /* The blocked lookup at ServerHelloDone replays a DTLS header. */
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "DTLS 1.2 ocsp_multi, no CertificateStatus", 1, 0, 0, 0 },
#endif
#endif
#ifndef WOLFSSL_NO_TLS12
        { wolfTLSv1_2_client_method, wolfTLSv1_2_server_method,
          "TLS 1.2 no stapling", -1, 0, 0, 0 },
#endif
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
        /* The Certificate spans several datagrams, so it is drained from the
         * receive list. */
        { wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method,
          "DTLS 1.2 no stapling, reassembled Certificate", -1, 0, 0, 0 },
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13)
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3 status_request, leaf stapled only", 0, 1, 0, 0 },
        { wolfTLSv1_3_client_method, wolfTLSv1_3_server_method,
          "TLS 1.3 status_request with nonce, leaf stapled only", 0, 1, 0, 1 },
#endif
    };

    for (i = 0; i < XELEM_CNT(params) && !EXPECT_FAIL(); i++) {
        for (run = 0; run < 4 * (TEST_OCSP_NONBLOCK_MAX + 1) &&
                !EXPECT_FAIL(); run++) {
            struct test_ssl_memio_ctx test_ctx;

            /* The intermediate's lookup answers good or unknown, times out or
             * fails in the I/O callback. */
            fail = (run % 4) != 0;
            ioErr = (run % 4) == 2 ? WOLFSSL_CBIO_ERR_TIMEOUT :
                    (run % 4) == 3 ? -1 : 0;
            blocking = run / 4;

            XMEMSET(&test_ocsp_checkall_staple_opts, 0,
                sizeof(test_ocsp_checkall_staple_opts));
            test_ocsp_checkall_staple_opts.staple = params[i].staple;
            test_ocsp_checkall_staple_opts.unknown = fail;
            test_ocsp_checkall_staple_opts.ioErr = ioErr;
            test_ocsp_checkall_staple_opts.block = blocking;

            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            test_ctx.s_cb.method = params[i].server_meth;
            test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
            test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
            test_ocsp_srv_status_cb = test_ocsp_checkall_staple_status_cb;
            test_ctx.s_cb.ctx_ready = params[i].stock ?
                test_ocsp_checkall_staple_srv_stock_ctx_ready :
                test_ocsp_srv_ctx_ready;
            test_ctx.c_cb.method = params[i].client_meth;
            test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
            test_ctx.c_cb.ctx_ready = params[i].useV2 == 2 ?
                test_ocsp_checkall_staple_preload_ctx_ready :
                test_ocsp_checkall_staple_ctx_ready;
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);

            if (params[i].useV2 >= 1) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                if (params[i].useV2 == 2) {
                    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                        WOLFSSL_CSR2_OCSP, 0), WOLFSSL_SUCCESS);
                }
                ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                    WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
#endif
            }
            else if (params[i].useV2 == 0) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                    WOLFSSL_CSR_OCSP, params[i].nonce ?
                        WOLFSSL_CSR_OCSP_USE_NONCE : 0), WOLFSSL_SUCCESS);
#endif
            }

            if (!fail) {
                ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
                    TEST_SUCCESS);
            }
            else {
                ExpectIntNE(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
                    TEST_SUCCESS);
                ExpectIntEQ(wolfSSL_get_error(test_ctx.c_ssl, 0),
                    ioErr == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_TIMEOUT) ?
                        WC_NO_ERR_TRACE(HTTP_TIMEOUT) :
                    ioErr != 0 ? WC_NO_ERR_TRACE(OCSP_INVALID_STATUS) :
                        WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN));
                /* The server is told, rather than left waiting. */
#ifndef WOLFSSL_EXTRA_ALERTS
                if (wolfSSL_version(test_ctx.c_ssl) == TLS1_3_VERSION)
#endif
                {
                    ExpectIntEQ(wolfSSL_get_error(test_ctx.s_ssl, 0),
                        WC_NO_ERR_TRACE(FATAL_ERROR));
                }
                /* The client's own lookup failed, not the staple it got. */
                if (params[i].useV2 >= 1 &&
                        (params[i].staple || params[i].stock) &&
                        !wolfSSL_dtls(test_ctx.c_ssl)) {
                    WOLFSSL_ALERT_HISTORY h;

                    XMEMSET(&h, 0, sizeof(h));
                    ExpectIntEQ(wolfSSL_get_alert_history(test_ctx.s_ssl, &h),
                        WOLFSSL_SUCCESS);
                    ExpectIntEQ(h.last_rx.level, alert_fatal);
                    ExpectIntEQ(h.last_rx.code, certificate_unknown);
                }
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                /* A rejected chain certificate must reach the compatibility
                 * verify result too, not just the handshake error. */
                ExpectIntEQ(wolfSSL_get_verify_result(test_ctx.c_ssl),
                    WOLFSSL_X509_V_ERR_CERT_REJECTED);
#endif
            }
            /* The unstapled intermediate was looked up, and so was the leaf
             * when the server stapled nothing at all. */
            ExpectIntEQ(test_ocsp_checkall_staple_opts.intLookups, 1);
            if (!fail && (params[i].staple || params[i].stock)) {
                ExpectIntEQ(test_ocsp_checkall_staple_opts.leafLookups, 0);
            }
            else if (!fail) {
                ExpectIntEQ(test_ocsp_checkall_staple_opts.leafLookups, 1);
            }
            /* Each staple is verified once, even when a later lookup blocks. */
            ExpectIntEQ(test_ocsp_checkall_staple_opts.verifyCbCalls,
                (params[i].staple || params[i].stock) ? 1 : 0);
            /* The chain request reuses the nonce the leaf's request carries. */
            ExpectIntEQ(test_ocsp_checkall_staple_opts.intNonce,
                params[i].nonce ? 1 : 0);
            if (EXPECT_FAIL()) {
                fprintf(stderr, "case: %s, fail %d, ioErr %d, block %d\n",
                    params[i].desc, fail, ioErr, blocking);
            }

            test_ssl_memio_cleanup(&test_ctx);
        }
    }

#if defined(HAVE_CRL) && defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12)
    /* The leaf's good OCSP answer must survive a retry of the chain lookup, or
     * the CRL the client holds nothing for would decide in its place. */
    for (blocking = 0; blocking <= TEST_OCSP_NONBLOCK_MAX && !EXPECT_FAIL();
            blocking++) {
        struct test_ssl_memio_ctx test_ctx;

        XMEMSET(&test_ocsp_checkall_staple_opts, 0,
            sizeof(test_ocsp_checkall_staple_opts));
        test_ocsp_checkall_staple_opts.block = blocking;
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ocsp_srv_status_cb = test_ocsp_checkall_staple_status_cb;
        test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
        test_ctx.c_cb.method = wolfTLSv1_2_client_method;
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_ocsp_checkall_staple_noleafcrl_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
            WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
            TEST_SUCCESS);
        ExpectIntEQ(test_ocsp_checkall_staple_opts.leafLookups, 1);
        ExpectIntEQ(test_ocsp_checkall_staple_opts.intLookups, 1);
        if (EXPECT_FAIL())
            fprintf(stderr, "no CRL for the leaf, block %d\n", blocking);
        test_ssl_memio_cleanup(&test_ctx);
    }
#endif

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}

#else
int test_ocsp_checkall_staple_missing_chain(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES && !NO_RSA && */
       /* !NO_SHA && ((CSR && TLS13) || (CSR_V2 && !NO_TLS12)) */

#if defined(HAVE_OCSP) && defined(WOLFSSL_TLS13) &&                 \
    defined(WOLFSSL_NONBLOCK_OCSP) && defined(HAVE_MAX_FRAGMENT) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) &&                   \
    !defined(NO_RSA) && !defined(NO_SHA)

/* Number of times the OCSP IO callback has been called. */
static int test_tls13_nonblock_ocsp_mfl_cb_cnt;

/*
 * OCSP IO callback: simulates a nonblocking responder. Returns WANT_READ
 * a few times before finally returning the OCSP response.
 */
static int test_tls13_nonblock_ocsp_mfl_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** respBuf)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;

    if (test_tls13_nonblock_ocsp_mfl_cb_cnt++ < 5)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    *respBuf = (unsigned char*)resp_server1_cert;
    return (int)sizeof(resp_server1_cert);
}

/* CTX-ready callback: enable client-side OCSP with URL override. */
static int test_tls13_nonblock_ocsp_mfl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx,
                    WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://example.com"),
        WOLFSSL_SUCCESS);
    /* NULL free-callback: resp points to static array, must not be freed. */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
                    test_tls13_nonblock_ocsp_mfl_io_cb, NULL, NULL),
        WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

/* SSL-ready callback: cap record payload at 1024 bytes. */
static int test_tls13_nonblock_ocsp_mfl_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_10), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}

int test_tls13_nonblock_ocsp_low_mfl(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_tls13_nonblock_ocsp_mfl_cb_cnt = 0;

    /*
     * Server: two-cert chain (server1 + intermediate1, no root).
     * Total DER size ~2534 bytes -> splits into 3 TLS records at MFL=1024.
     */
    test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
    test_ctx.s_cb.keyPemFile  = "./certs/ocsp/server1-key.pem";
    test_ctx.s_cb.method      = wolfTLSv1_3_server_method;

    /* Client: trust root-ca, TLS 1.3, OCSP + MFL=1024. */
    test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
    test_ctx.c_cb.method    = wolfTLSv1_3_client_method;
    test_ctx.c_cb.ctx_ready = test_tls13_nonblock_ocsp_mfl_ctx_ready;
    test_ctx.c_cb.ssl_ready = test_tls13_nonblock_ocsp_mfl_ssl_ready;

    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);

    /* The OCSP callback must have been retried (called more than once). */
    ExpectIntGT(test_tls13_nonblock_ocsp_mfl_cb_cnt, 1);

    test_ssl_memio_cleanup(&test_ctx);
    return EXPECT_RESULT();
}

#else
int test_tls13_nonblock_ocsp_low_mfl(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(WOLFSSL_DTLS13) && \
    defined(WOLFSSL_NONBLOCK_OCSP) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_SHA)
static int test_dtls13_nonblock_ocsp_block;
static int test_dtls13_nonblock_ocsp_cnt;

static int test_dtls13_nonblock_ocsp_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* request, int requestSz,
    unsigned char** response)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)request;
    (void)requestSz;

    if (test_dtls13_nonblock_ocsp_block > 0) {
        test_dtls13_nonblock_ocsp_block--;
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    test_dtls13_nonblock_ocsp_cnt++;
    *response = (unsigned char*)resp_server1_cert;
    return (int)sizeof(resp_server1_cert);
}

static int test_dtls13_nonblock_ocsp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
        WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_dtls13_nonblock_ocsp_io_cb,
        NULL, NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_dtls13_nonblock_ocsp_unfragmented_cert(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    int blocking;

    /* The leaf alone fits one record, so the client processes the Certificate
     * directly instead of from its reassembly buffer. */
    for (blocking = 0; blocking <= TEST_OCSP_NONBLOCK_MAX && !EXPECT_FAIL();
            blocking++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_dtls13_nonblock_ocsp_block = blocking;
        test_dtls13_nonblock_ocsp_cnt = 0;
        test_ctx.c_cb.method = wolfDTLSv1_3_client_method;
        test_ctx.s_cb.method = wolfDTLSv1_3_server_method;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-leaf.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready = test_dtls13_nonblock_ocsp_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_nonblock_ocsp_cnt, 1);
        ExpectIntEQ(test_dtls13_nonblock_ocsp_block, 0);
        if (EXPECT_FAIL()) {
            fprintf(stderr, "block %d, client error %d\n", blocking,
                wolfSSL_get_error(test_ctx.c_ssl, 0));
        }
        test_ssl_memio_cleanup(&test_ctx);
    }

    return EXPECT_RESULT();
}
#else
int test_dtls13_nonblock_ocsp_unfragmented_cert(void)
{
    return TEST_SKIPPED;
}
#endif

/* WOLFSSL_COPY_CERT (implied by OPENSSL_ALL) gives every WOLFSSL its own copy of
 * the CTX certificate, which sets ssl->buffers.weOwnCert and takes the CTX
 * request cache out of play entirely - there is nothing to test in that
 * configuration. */
#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_RSA) && !defined(NO_SHA)

static int test_ocsp_status_verify_block;
static int test_ocsp_status_verify_cnt;
static int test_ocsp_status_verify_v2;

static int test_ocsp_status_verify_block_cb(WOLFSSL* ssl, int err,
    byte* staple, word32 stapleSz, word32 idx, void* arg)
{
    (void)ssl;
    (void)staple;
    (void)stapleSz;
    (void)idx;
    (void)arg;

    test_ocsp_status_verify_cnt++;
    if (test_ocsp_status_verify_block > 0) {
        test_ocsp_status_verify_block--;
        return OCSP_WANT_READ;
    }
    return err;
}

static int test_ocsp_status_verify_block_status_cb(WOLFSSL* ssl, void* ctx)
{
    (void)ctx;
    return test_ocsp_set_staple(ssl, resp_server1_cert,
        (int)sizeof(resp_server1_cert), 0);
}

static int test_ocsp_status_verify_block_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    wolfSSL_CTX_set_ocsp_status_verify_cb(ctx,
        test_ocsp_status_verify_block_cb, NULL);

    return EXPECT_RESULT();
}

static int test_ocsp_status_verify_block_ssl_ready(WOLFSSL* ssl)
{
    EXPECT_DECLS;

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    if (test_ocsp_status_verify_v2) {
        ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP, 0),
            WOLFSSL_SUCCESS);
    }
    else
#endif
    {
        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
            WOLFSSL_SUCCESS);
    }

    return EXPECT_RESULT();
}

/* A status verify callback that would block has the staple replayed. */
int test_ocsp_status_verify_cb_would_block(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    int blocking;
    int v2;

    for (v2 = 0; v2 < 2 && !EXPECT_FAIL(); v2++) {
#ifndef HAVE_CERTIFICATE_STATUS_REQUEST_V2
        if (v2)
            break;
#endif
        for (blocking = 0; blocking <= TEST_OCSP_NONBLOCK_MAX &&
                !EXPECT_FAIL(); blocking++) {
            test_ocsp_status_verify_v2 = v2;
            test_ocsp_status_verify_block = blocking;
            test_ocsp_status_verify_cnt = 0;
            XMEMSET(&test_ctx, 0, sizeof(test_ctx));
            test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            test_ctx.s_cb.method = wolfTLSv1_2_server_method;
            test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
            test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
            test_ocsp_srv_status_cb = test_ocsp_status_verify_block_status_cb;
            test_ctx.s_cb.ctx_ready = test_ocsp_srv_ctx_ready;
            test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
            test_ctx.c_cb.ctx_ready = test_ocsp_status_verify_block_ctx_ready;
            test_ctx.c_cb.ssl_ready = test_ocsp_status_verify_block_ssl_ready;
            ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
            ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 20, NULL),
                TEST_SUCCESS);
            ExpectIntEQ(test_ocsp_status_verify_cnt, 1 + blocking);
            ExpectIntEQ(test_ocsp_status_verify_block, 0);
            if (EXPECT_FAIL())
                fprintf(stderr, "v2 %d, block %d\n", v2, blocking);
            test_ssl_memio_cleanup(&test_ctx);
        }
    }

    test_ocsp_srv_status_cb = NULL;
    return EXPECT_RESULT();
}
#else
int test_ocsp_status_verify_cb_would_block(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(HAVE_TLS_EXTENSIONS) && !defined(NO_WOLFSSL_SERVER) &&    \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                  \
    !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_COPY_CERT) &&      \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_SHA)

/* Number of times the server's OCSP IO callback has been called. */
static int test_ocsp_ctx_request_cache_cb_cnt;
/* The encoded request seen by the first call, kept to compare later ones
 * against. 512 bytes is well past the size of an OCSP request for one cert. */
static byte test_ocsp_ctx_request_cache_first[512];
static int  test_ocsp_ctx_request_cache_firstSz;
/* Set when a later call encoded something other than what the first did. */
static int  test_ocsp_ctx_request_cache_differs;

/* Answers with the canned good response for server1, so that the stapling path
 * runs to completion and the ownership decision it makes about the request is
 * actually acted on. The encoded request is kept so the caller can tell which
 * OcspRequest object produced it.
 */
static int test_ocsp_ctx_request_cache_io_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** respBuf)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;

    if (test_ocsp_ctx_request_cache_cb_cnt == 0) {
        if (req != NULL && reqSz > 0 &&
                reqSz <= (int)sizeof(test_ocsp_ctx_request_cache_first)) {
            XMEMCPY(test_ocsp_ctx_request_cache_first, req, (size_t)reqSz);
            test_ocsp_ctx_request_cache_firstSz = reqSz;
        }
    }
    else if (test_ocsp_ctx_request_cache_firstSz > 0) {
        test_ocsp_ctx_request_cache_differs =
            (reqSz != test_ocsp_ctx_request_cache_firstSz) ||
            (XMEMCMP(req, test_ocsp_ctx_request_cache_first,
                     (size_t)reqSz) != 0);
    }

    test_ocsp_ctx_request_cache_cb_cnt++;

    /* Static blob - the NULL free callback registered alongside this one keeps
     * it from being freed. */
    *respBuf = (unsigned char*)resp_server1_cert;
    return (int)sizeof(resp_server1_cert);
}

/* The leaf OCSP request that stapling builds is cached on the WOLFSSL_CTX, and
 * every later connection on that CTX reuses it. The CTX owns it from that point
 * on and frees it in wolfSSL_CTX_free(), so no connection may free it.
 *
 * Runs three handshakes over one CTX pair:
 *   pass 0 - builds the request and publishes it on the CTX,
 *   pass 1 - reuses the published one,
 *   pass 2 - reuses it again, after it has been marked so that reuse can be
 *            told apart from a rebuild off the same certificate.
 *
 * The responder answers with a good response on every pass, so stapling runs
 * all the way through and the ownership decision each connection makes about
 * the request is actually acted on. That is what puts the rules themselves
 * under test: a connection that frees the cached request shows up as a use
 * after free on the next pass and a double free at CTX teardown, both of which
 * the ASan CI job turns into a failure.
 */
int test_ocsp_ctx_request_cache(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL*     ssl_c = NULL;
    WOLFSSL*     ssl_s = NULL;
    OcspRequest* cached = NULL;
    int          i;
    struct test_memio_ctx test_ctx;

    test_ocsp_ctx_request_cache_cb_cnt = 0;
    test_ocsp_ctx_request_cache_firstSz = 0;
    test_ocsp_ctx_request_cache_differs = 0;

    /* Build the CTX pair on its own first: the certificate has to be in place
     * before any WOLFSSL is made from the CTX, since each one latches the
     * certificate buffer at wolfSSL_new(). */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, NULL, NULL,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    /* server1 is the certificate the canned OCSP response answers for, sent
     * with its intermediate so the client can build a path to the root. */
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx_s,
        "./certs/ocsp/server1-chain-noroot.pem"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s,
        "./certs/ocsp/server1-key.pem", WOLFSSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);
    /* The server needs the issuing CAs to verify the response it staples. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
        "./certs/ocsp/root-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    /* The client needs the intermediate too: it has to verify the responder
     * certificate inside the stapled response, and a build whose default verify
     * mode is NONE (OPENSSL_COMPATIBLE_DEFAULTS) never registers the chain
     * certificates the handshake carried. */
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
        "./certs/ocsp/root-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_c,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx_s), WOLFSSL_SUCCESS);
    /* The test certificate carries no AuthInfo, so point the lookup at a dummy
     * responder to get past the no-URL check. */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx_s, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx_s,
        WOLFSSL_OCSP_NO_NONCE | WOLFSSL_OCSP_URL_OVERRIDE), WOLFSSL_SUCCESS);
    /* NULL free callback: the response points at a static array. */
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx_s,
        test_ocsp_ctx_request_cache_io_cb, NULL, NULL), WOLFSSL_SUCCESS);

    for (i = 0; i < 3 && EXPECT_SUCCESS(); i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        /* The CTXs already exist, so this only makes the connection pair - all
         * three handshakes run on the same CTXs, which is what puts the cache
         * in play. */
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl_c, WOLFSSL_CSR_OCSP, 0),
            WOLFSSL_SUCCESS);

        if (i < 2) {
            /* A good response is stapled and accepted, so the handshake has to
             * complete. */
            ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        }
        else {
            /* The marked request no longer matches the response, so this pass
             * is only about which object got encoded. */
            (void)test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
        }

        /* Every pass went out to the responder, so every pass really did run
         * the stapling path. */
        ExpectIntEQ(test_ocsp_ctx_request_cache_cb_cnt, i + 1);

        if (i == 0) {
            /* First pass builds the request and publishes it on the CTX. */
            ExpectNotNull(cached = ctx_s->certOcspRequest);
        }
        else {
            /* Later passes reuse that one instead of publishing another, which
             * is what leaves the CTX as the single owner. Reaching this with
             * the object intact is the point: a connection that had freed it
             * would have left a dangling pointer here. */
            ExpectPtrEq(ctx_s->certOcspRequest, cached);
        }

        if (i == 1) {
            /* Mark the cached request so the next pass can be told apart from
             * one that rebuilt the request off the same certificate: both would
             * otherwise encode byte for byte the same. */
            if (cached != NULL && cached->serial != NULL &&
                    cached->serialSz > 0) {
                cached->serial[0] = (byte)(cached->serial[0] ^ 0xFF);
            }
        }
        else if (i == 2) {
            /* It really was the cached object that went to the responder, not a
             * fresh request that happens to be cached alongside it. */
            ExpectIntEQ(test_ocsp_ctx_request_cache_differs, 1);
        }

        wolfSSL_free(ssl_c);
        ssl_c = NULL;
        wolfSSL_free(ssl_s);
        ssl_s = NULL;
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
int test_ocsp_ctx_request_cache(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_TLS_OCSP_MULTI) &&      \
    defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_RSA) && \
    !defined(NO_SHA)

static int test_ocsp_chain_stapling_timeout_calls;
static byte test_ocsp_chain_stapling_leaf_response[4096];
static int test_ocsp_chain_stapling_leaf_response_sz;

static int test_ocsp_chain_stapling_timeout_cb(void* ioCtx, const char* url,
    int urlSz, unsigned char* req, int reqSz, unsigned char** respBuf)
{
    (void)ioCtx;
    (void)url;
    (void)urlSz;
    (void)req;
    (void)reqSz;
    if (test_ocsp_chain_stapling_timeout_calls++ == 0) {
        *respBuf = test_ocsp_chain_stapling_leaf_response;
        return test_ocsp_chain_stapling_leaf_response_sz;
    }
    return WOLFSSL_CBIO_ERR_TIMEOUT;
}

static int test_ocsp_chain_stapling_timeout_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
        "./certs/ocsp/root-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx,
        WOLFSSL_OCSP_NO_NONCE | WOLFSSL_OCSP_URL_OVERRIDE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx,
        test_ocsp_chain_stapling_timeout_cb, NULL, NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

static int test_ocsp_chain_stapling_timeout_client_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;

    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
        "./certs/ocsp/intermediate1-ca-cert.pem", NULL), WOLFSSL_SUCCESS);

    return EXPECT_RESULT();
}

int test_ocsp_chain_stapling_timeout(void)
{
    EXPECT_DECLS;
    struct test_ssl_memio_ctx test_ctx;
    XFILE f = XBADFILE;
    int mode;
    int modes = 1;

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12)
    modes = 2;
#endif

    ExpectTrue((f = XFOPEN("./certs/ocsp/test-leaf-response.der", "rb")) !=
        XBADFILE);
    if (f != XBADFILE) {
        test_ocsp_chain_stapling_leaf_response_sz = (int)XFREAD(
            test_ocsp_chain_stapling_leaf_response, 1,
            sizeof(test_ocsp_chain_stapling_leaf_response), f);
        XFCLOSE(f);
    }
    ExpectIntGT(test_ocsp_chain_stapling_leaf_response_sz, 0);

    /* The leaf has a valid response. The intermediate's responder times out. */
    for (mode = 0; mode < modes && EXPECT_SUCCESS(); mode++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ocsp_chain_stapling_timeout_calls = 0;
        test_ctx.c_cb.method = wolfTLSv1_3_client_method;
        test_ctx.s_cb.method = wolfTLSv1_3_server_method;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12)
        if (mode == 1) {
            test_ctx.c_cb.method = wolfTLSv1_2_client_method;
            test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        }
#endif
        test_ctx.c_cb.caPemFile = "./certs/ocsp/root-ca-cert.pem";
        test_ctx.c_cb.ctx_ready =
            test_ocsp_chain_stapling_timeout_client_ctx_ready;
        test_ctx.s_cb.certPemFile = "./certs/ocsp/server1-chain-noroot.pem";
        test_ctx.s_cb.keyPemFile = "./certs/ocsp/server1-key.pem";
        test_ctx.s_cb.ctx_ready = test_ocsp_chain_stapling_timeout_ctx_ready;

        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        /* OCSP is enabled for stapling, but the server need not check the
         * client's certificate against its responder in this test. */
        wolfSSL_set_verify(test_ctx.s_ssl, WOLFSSL_VERIFY_NONE, NULL);
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(test_ctx.c_ctx),
            WOLFSSL_SUCCESS);
        if (mode == 0) {
            ExpectIntEQ(wolfSSL_UseOCSPStapling(test_ctx.c_ssl,
                WOLFSSL_CSR_OCSP, 0), WOLFSSL_SUCCESS);
        }
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
    !defined(WOLFSSL_NO_TLS12)
        else {
            ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(test_ctx.c_ssl,
                WOLFSSL_CSR2_OCSP_MULTI, 0), WOLFSSL_SUCCESS);
        }
#endif
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
            TEST_SUCCESS);
        ExpectIntGT(test_ocsp_chain_stapling_timeout_calls, 1);
        test_ssl_memio_cleanup(&test_ctx);
    }

    return EXPECT_RESULT();
}
#else
int test_ocsp_chain_stapling_timeout(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_OCSP_RESPONDER) && defined(WOLFSSL_ASN_TEMPLATE) && \
    !defined(NO_SHA) && !defined(NO_RSA)
/* Structure to hold test configuration */
typedef struct {
    const char* caCertPath;
    const char* responderCertPath;
    const char* responderKeyPath;
    const char* targetCertPath;
    enum Ocsp_Cert_Status certStatus;
    time_t revocationTime;               /* Used when status is CERT_REVOKED */
    enum WC_CRL_Reason revocationReason; /* Used when status is CERT_REVOKED */
    word32 validityPeriod;               /* Used when status is CERT_GOOD */
    int expectedResult;
    const char* testName;
} OcspResponderTestConfig;

/* Helper function to run a single OCSP responder test configuration */
static int ocspResponderTest_Run(OcspResponderTestConfig* config, int sendCerts)
{
    EXPECT_DECLS;
    OcspResponder* responder = NULL;
    OcspRequest* clientReq = NULL;
    DecodedCert targetCert;
    DecodedCert decodedCaCert;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    byte caCertDer[4096];
    byte responderCertDer[4096];
    byte responderKeyDer[4096];
    byte targetCertDer[4096];
    byte* respBuf = NULL;
    word32 caCertSz = sizeof(caCertDer);
    word32 responderCertSz = sizeof(responderCertDer);
    word32 responderKeyDerSz = sizeof(responderKeyDer);
    word32 targetCertSz = sizeof(targetCertDer);
    word32 respSz = 0;
    byte reqBuf[1024];
    int reqSz = 0;
    char caSubject[WC_ASN_NAME_MAX];
    word32 caSubjectSz = sizeof(caSubject);
    byte serial[EXTERNAL_SERIAL_SIZE];
    word32 serialSz = sizeof(serial);
    XFILE f = XBADFILE;
    byte usingAuthCa = XSTRCMP(config->caCertPath, config->responderCertPath) != 0;

    printf("\nRunning OCSP Responder Test: %s (sendCerts=%d)\n",
           config->testName, sendCerts);

    XMEMSET(&targetCert, 0, sizeof(targetCert));
    XMEMSET(&decodedCaCert, 0, sizeof(decodedCaCert));

    /* Create certificate manager */
    ExpectNotNull(cm = wolfSSL_CertManagerNew());

    /* Load CA certificate */
    ExpectTrue((f = XFOPEN(config->caCertPath, "rb")) != XBADFILE);
    ExpectIntGT(caCertSz = (word32)XFREAD(caCertDer, 1,
                                          caCertSz, f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }
    ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, caCertDer, caCertSz,
                                                WOLFSSL_FILETYPE_ASN1),
                WOLFSSL_SUCCESS);

    wc_InitDecodedCert(&decodedCaCert, caCertDer, caCertSz, NULL);
    ExpectIntEQ(wc_ParseCert(&decodedCaCert, CERT_TYPE, 0, NULL), 0);

    /* Load responder certificate */
    ExpectTrue((f = XFOPEN(config->responderCertPath, "rb")) != XBADFILE);
    ExpectIntGT(responderCertSz = (word32)XFREAD(responderCertDer, 1,
                                          responderCertSz, f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    if (usingAuthCa && !sendCerts) {
        /* If responder is not sending certs then it must be loaded into cm */
        ExpectIntEQ(wolfSSL_CertManagerLoadCABuffer(cm, responderCertDer,
                responderCertSz, WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    }

    /* Load responder private key */
    ExpectTrue((f = XFOPEN(config->responderKeyPath, "rb")) != XBADFILE);
    ExpectIntGT(responderKeyDerSz = (word32)XFREAD(responderKeyDer, 1,
                                          responderKeyDerSz, f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Load target certificate */
    ExpectTrue((f = XFOPEN(config->targetCertPath, "rb")) != XBADFILE);
    ExpectIntGT(targetCertSz = (word32)XFREAD(targetCertDer, 1,
                                          targetCertSz, f), 0);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    /* Parse target certificate */
    wc_InitDecodedCert(&targetCert, targetCertDer, targetCertSz, NULL);
    ExpectIntEQ(wc_ParseCert(&targetCert, CERT_TYPE, 0, cm), 0);

    /* Create OCSP request from target certificate */
    ExpectNotNull(clientReq = wc_OcspRequest_new(NULL));
    ExpectIntEQ(wc_InitOcspRequest(clientReq, &targetCert, 1, NULL), 0);
    ExpectIntGT(reqSz = wc_EncodeOcspRequest(clientReq, reqBuf,
                                              sizeof(reqBuf)), 0);

    /* Create OCSP Responder */
    ExpectNotNull(responder = wc_OcspResponder_new(NULL, sendCerts));

    /* Add responder (authorized) to responder */
    ExpectIntEQ(wc_OcspResponder_AddSigner(responder,
            responderCertDer, responderCertSz,
            responderKeyDer, responderKeyDerSz,
            usingAuthCa ? caCertDer : NULL, usingAuthCa ? caCertSz : 0), 0);

    /* Set certificate status */
    ExpectIntEQ(wc_GetDecodedCertSubject(&decodedCaCert, caSubject, &caSubjectSz), 0);
    ExpectIntGT(caSubjectSz, 0);
    ExpectIntEQ(wc_GetDecodedCertSerial(&targetCert, serial, &serialSz), 0);
    ExpectIntGT(serialSz, 0);

    ExpectIntEQ(wc_OcspResponder_SetCertStatus(responder,
                                               caSubject, caSubjectSz,
                                               serial, serialSz,
                                               config->certStatus,
                                               config->revocationTime,
                                               config->revocationReason,
                                               config->validityPeriod), 0);

    /* Get required response size */
    ExpectIntEQ(wc_OcspResponder_WriteResponse(responder, reqBuf, reqSz,
                                               NULL, &respSz), 0);

    /* Allocate response buffer */
    ExpectNotNull(respBuf = (byte*)XMALLOC(respSz, NULL,
            DYNAMIC_TYPE_TMP_BUFFER));

    /* Generate OCSP response */
    ExpectIntEQ(wc_OcspResponder_WriteResponse(responder, reqBuf, reqSz,
                                               respBuf, &respSz), 0);

    /* Verify response matches expected result */
    {
        WOLFSSL_OCSP* ocsp = NULL;
        ExpectNotNull(ocsp = wc_NewOCSP(cm));
        ExpectIntEQ(wc_CheckCertOcspResponse(ocsp, &targetCert, respBuf,
                respSz, NULL), config->expectedResult);
        wc_FreeOCSP(ocsp);
    }

    /* Cleanup */
    XFREE(respBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_OcspRequest_free(clientReq);
    wc_OcspResponder_free(responder);
    wc_FreeDecodedCert(&targetCert);
    wc_FreeDecodedCert(&decodedCaCert);
    wolfSSL_CertManagerFree(cm);

    return EXPECT_RESULT();
}

int test_ocsp_responder(void)
{
    EXPECT_DECLS;
    time_t now = wc_Time(NULL);
    OcspResponderTestConfig configs[] = {
        {
            "./certs/ca-cert.der",
            "./certs/ca-cert.der",
            "./certs/ca-key.der",
            "./certs/server-cert.der",
            CERT_GOOD,
            0, WC_CRL_REASON_UNSPECIFIED,
            86400, /* validityPeriod - 24 hours */
            0,
            "RSA server cert - GOOD status"
        },
        {
            "./certs/ca-cert.der",
            "./certs/ca-cert.der",
            "./certs/ca-key.der",
            "./certs/server-cert.der",
            CERT_REVOKED,
            now, WC_CRL_REASON_KEY_COMPROMISE,  /* Revoked due to key compromise */
            0,     /* validityPeriod (not used for REVOKED) */
            OCSP_CERT_REVOKED,
            "RSA server cert - REVOKED status"
        },
        {
            "./certs/ca-cert.der",
            "./certs/ca-cert.der",
            "./certs/ca-key.der",
            "./certs/server-cert.der",
            CERT_UNKNOWN,
            0, WC_CRL_REASON_UNSPECIFIED,
            0,     /* validityPeriod (not used for UNKNOWN) */
            OCSP_CERT_UNKNOWN,
            "RSA server cert - UNKNOWN status"
        },
        {
            "./certs/ocsp/root-ca-cert.der",
            "./certs/ocsp/ocsp-responder-cert.der",
            "./certs/ocsp/ocsp-responder-key.der",
            "./certs/ocsp/intermediate1-ca-cert.der",
            CERT_GOOD,
            0, WC_CRL_REASON_UNSPECIFIED,
            86400, /* validityPeriod - 24 hours */
            0,
            "RSA int1 cert with responder - GOOD status"
        },
        {
            "./certs/ocsp/root-ca-cert.der",
            "./certs/ocsp/ocsp-responder-cert.der",
            "./certs/ocsp/ocsp-responder-key.der",
            "./certs/ocsp/intermediate1-ca-cert.der",
            CERT_REVOKED,
            now, WC_CRL_REASON_KEY_COMPROMISE,  /* Revoked due to key compromise */
            0,     /* validityPeriod (not used for REVOKED) */
            OCSP_CERT_REVOKED,
            "RSA int1 cert with responder - REVOKED status"
        },
        {
            "./certs/ocsp/root-ca-cert.der",
            "./certs/ocsp/ocsp-responder-cert.der",
            "./certs/ocsp/ocsp-responder-key.der",
            "./certs/ocsp/intermediate1-ca-cert.der",
            CERT_UNKNOWN,
            0, WC_CRL_REASON_UNSPECIFIED,
            0,     /* validityPeriod (not used for UNKNOWN) */
            OCSP_CERT_UNKNOWN,
            "RSA int1 cert with responder - UNKNOWN status"
        },
#ifdef HAVE_ECC
        {
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-key.der",
            "./certs/server-ecc.der",
            CERT_GOOD,
            0, WC_CRL_REASON_UNSPECIFIED,
            86400, /* validityPeriod - 24 hours */
            0,
            "ECC server cert - GOOD status"
        },
        {
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-key.der",
            "./certs/server-ecc.der",
            CERT_REVOKED,
            now, WC_CRL_REASON_AFFILIATION_CHANGED,
            0,     /* validityPeriod (not used for REVOKED) */
            OCSP_CERT_REVOKED,
            "ECC server cert - REVOKED status"
        },
        {
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-cert.der",
            "./certs/ca-ecc-key.der",
            "./certs/server-ecc.der",
            CERT_UNKNOWN,
            0, WC_CRL_REASON_UNSPECIFIED,
            0,     /* validityPeriod (not used for UNKNOWN) */
            OCSP_CERT_UNKNOWN,
            "ECC server cert - UNKNOWN status"
        }
#endif
    };
    int i;
    int numTests = (int)(sizeof(configs) / sizeof(configs[0]));

    /* Run each test configuration twice: once without certs, once with certs */
    for (i = 0; i < numTests; i++) {
        ExpectIntEQ(ocspResponderTest_Run(&configs[i], 0), TEST_SUCCESS);
        ExpectIntEQ(ocspResponderTest_Run(&configs[i], 1), TEST_SUCCESS);
    }

    return EXPECT_RESULT();
}
#else
int test_ocsp_responder(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_OCSP_RESPONDER && !NO_SHA && !NO_RSA */

#if defined(HAVE_HTTP_CLIENT)
/* A peer-supplied AIA/CRL URL must not be able to smuggle CR/LF into the
 * outbound OCSP/CRL HTTP request (header injection / request splitting). */
/* MC/DC vectors for wolfIO_DecodeUrl's host-parsing loops.
 *
 * The bracketed-IPv6 loop and the plain-host loop each carry four operands:
 *
 *     while (i < MAX_URL_ITEM_SIZE-1 && cur < urlSz && url[cur] != 0 &&
 *            url[cur] != ']')          (or != ':' && != '/')
 *
 * and the bracket path is followed by
 *
 *     if (cur >= urlSz || url[cur] != ']')
 *
 * The existing CR/LF tests drive the injection guard but always terminate the
 * host normally, so three of the four loop operands never take the value that
 * ends the loop, and the unterminated-bracket rejection never fires. Each
 * vector below stops the loop on a DIFFERENT operand, which is what gives each
 * one its independence pair; the well-formed URLs at the end are the accepting
 * partners.
 *
 * These are the shapes an attacker controls -- an unterminated literal, a host
 * that runs to the end of the buffer, a host longer than the item cap -- and
 * none of them is produced by any in-tree caller, which is why they were
 * uncovered. */
int test_wolfIO_DecodeUrl_host_bounds(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) || defined(HAVE_CRL_IO)
    /* wolfio.c keeps MAX_URL_ITEM_SIZE private (src/wolfio.c), so mirror the
     * value here rather than reaching into the implementation. Only the
     * "longer than the cap" vector depends on it, and it just has to exceed
     * the real cap for the first loop operand to go false. */
    #define WOLFIO_URL_ITEM_CAP 80
    char   domainName[WOLFIO_URL_ITEM_CAP];
    char   path[WOLFIO_URL_ITEM_CAP];
    word16 port;
    int    i;
    char   longHost[WOLFIO_URL_ITEM_CAP + 32];
    /* bracketed IPv6 with no closing ']' -- loop ends on cur < urlSz going
     * false, then the terminator check rejects. */
    const char* v6Unterminated = "http://[::1";
    /* bracketed IPv6 whose host hits a NUL before ']' -- loop ends on
     * url[cur] != 0 going false. */
    static const char v6Nul[] = "http://[::1\0]/ocsp";
    /* well-formed bracketed literal: loop ends on url[cur] != ']' going
     * false, and the terminator check accepts. The accepting partner. */
    const char* v6Good = "http://[::1]:8080/ocsp";
    /* plain host running to the end of the buffer with no ':' or '/' -- loop
     * ends on cur < urlSz. */
    const char* hostEof = "http://ocsp.example.com";
    /* plain host terminated by '/' and by ':' respectively: the accepting
     * partners for the last two operands of the plain-host loop. */
    const char* hostSlash = "http://ocsp.example.com/ocsp";
    const char* hostColon = "http://ocsp.example.com:8080/ocsp";

    /* A host longer than the item cap ends the loop on the FIRST operand,
     * i < MAX_URL_ITEM_SIZE-1, which nothing else in the suite reaches. */
    /* XMEMCPY, not XSTRNCPY: gcc's -Werror=stringop-truncation fires on a
     * bounded copy it cannot prove NUL-terminates, and the rest of this buffer
     * is filled and terminated by hand immediately below anyway. */
    XMEMCPY(longHost, "http://", 7);
    for (i = 7; i < (int)sizeof(longHost) - 2; i++)
        longHost[i] = 'a';
    longHost[sizeof(longHost) - 2] = '/';
    longHost[sizeof(longHost) - 1] = '\0';

    /* --- rejecting vectors, one per loop-exit operand --- */
    ExpectIntLT(wolfIO_DecodeUrl(v6Unterminated, (int)XSTRLEN(v6Unterminated),
        domainName, path, &port), 0);
    ExpectIntLT(wolfIO_DecodeUrl(v6Nul, (int)sizeof(v6Nul) - 1,
        domainName, path, &port), 0);

    /* --- accepting partners --- */
    ExpectIntEQ(wolfIO_DecodeUrl(v6Good, (int)XSTRLEN(v6Good),
        domainName, path, &port), 0);
    ExpectIntEQ(wolfIO_DecodeUrl(hostEof, (int)XSTRLEN(hostEof),
        domainName, path, &port), 0);
    ExpectIntEQ(wolfIO_DecodeUrl(hostSlash, (int)XSTRLEN(hostSlash),
        domainName, path, &port), 0);
    ExpectIntEQ(wolfIO_DecodeUrl(hostColon, (int)XSTRLEN(hostColon),
        domainName, path, &port), 0);

    /* Cap-length host: whatever the parser decides, the point is that the
     * first loop operand goes false, so no return value is asserted beyond
     * it not crashing. */
    (void)wolfIO_DecodeUrl(longHost, (int)XSTRLEN(longHost),
        domainName, path, &port);

    /* Null and zero-length arguments: both operands of
     * `if (url == NULL || urlSz == 0)`, with the accepting partner above. */
    ExpectIntLT(wolfIO_DecodeUrl(NULL, 10, domainName, path, &port), 0);
    ExpectIntLT(wolfIO_DecodeUrl(hostSlash, 0, domainName, path, &port), 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfIO_DecodeUrl_crlf_reject(void)
{
    EXPECT_DECLS;
    char   domainName[80];
    char   path[80];
    word16 port;
    byte   reqBuf[512];
    char*  tightPath = NULL;
    int    tightLen  = 16;
    const char* crlfInPath = "http://ocsp.example.com/ocsp\r\nX-Injected: 1";
    const char* crlfInHost = "http://evil\r\nHost: x/ocsp";
    const char* crlfInV6Host = "http://[::1\r\n]/ocsp";
    const char* cleanUrl   = "http://ocsp.example.com/ocsp";
    const char* taintedPath = "/ocsp\r\nX-Injected: 1";
    const char* crlfAfterCap =
        "http://ocsp.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nX: 1";

    /* parser rejects CR/LF in the path */
    ExpectIntLT(wolfIO_DecodeUrl(crlfInPath, (int)XSTRLEN(crlfInPath),
        domainName, path, &port), 0);

    /* parser rejects CR/LF in the host */
    ExpectIntLT(wolfIO_DecodeUrl(crlfInHost, (int)XSTRLEN(crlfInHost),
        domainName, path, &port), 0);

    /* parser rejects CR/LF in an IPv6 bracket-literal host */
    ExpectIntLT(wolfIO_DecodeUrl(crlfInV6Host, (int)XSTRLEN(crlfInV6Host),
        domainName, path, &port), 0);

    /* sink rejects a tainted path even when the parser is bypassed, which is
     * the CRL raw-URL case */
    ExpectIntEQ(wolfIO_HttpBuildRequest("POST", "ocsp.example.com",
        taintedPath, (int)XSTRLEN(taintedPath), 0, "application/ocsp-request",
        reqBuf, (int)sizeof(reqBuf)), 0);

    /* sink rejects CR/LF even when it appears beyond the decoder cap */
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", "ocsp.example.com",
        crlfAfterCap, (int)XSTRLEN(crlfAfterCap), 0, "", reqBuf,
        (int)sizeof(reqBuf)), 0);

    /* sink rejects CR/LF in the host (domainName) with a clean path */
    ExpectIntEQ(wolfIO_HttpBuildRequest("POST", "evil.example.com\r\nX: 1",
        "/ocsp", (int)XSTRLEN("/ocsp"), 0, "application/ocsp-request", reqBuf,
        (int)sizeof(reqBuf)), 0);

    /* the CRL raw-URL path is not NUL terminated, so the request builder must
     * copy only pathLen bytes. Allocate exactly pathLen bytes with no
     * terminator so an over-read past the buffer is caught under ASAN. */
    tightPath = (char*)XMALLOC((size_t)tightLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(tightPath);
    if (tightPath != NULL) {
        XMEMSET(tightPath, 'a', (size_t)tightLen);
        tightPath[0] = '/';
        ExpectIntGT(wolfIO_HttpBuildRequest("GET", "ocsp.example.com",
            tightPath, tightLen, 0, "", reqBuf, (int)sizeof(reqBuf)), 0);
    }

    /* sink rejects a negative pathLen before any length math or copy: with the
     * old XMEMCPY this wrapped (word32)pathLen and overran the output buffer */
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", "ocsp.example.com", "/ocsp",
        -1, 0, "", reqBuf, (int)sizeof(reqBuf)), 0);

    /* sink rejects a non-positive bufSize before any copy */
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", "ocsp.example.com", "/ocsp",
        (int)XSTRLEN("/ocsp"), 0, "", reqBuf, 0), 0);

    /* sink rejects NULL pointer parameters at the boundary, before any
     * XSTRLEN deref */
    ExpectIntEQ(wolfIO_HttpBuildRequest(NULL, "ocsp.example.com", "/ocsp",
        (int)XSTRLEN("/ocsp"), 0, "", reqBuf, (int)sizeof(reqBuf)), 0);
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", NULL, "/ocsp",
        (int)XSTRLEN("/ocsp"), 0, "", reqBuf, (int)sizeof(reqBuf)), 0);
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", "ocsp.example.com", NULL,
        0, 0, "", reqBuf, (int)sizeof(reqBuf)), 0);
    ExpectIntEQ(wolfIO_HttpBuildRequest("GET", "ocsp.example.com", "/ocsp",
        (int)XSTRLEN("/ocsp"), 0, NULL, reqBuf, (int)sizeof(reqBuf)), 0);

    /* positive control: a clean URL decodes and still builds a request */
    ExpectIntEQ(wolfIO_DecodeUrl(cleanUrl, (int)XSTRLEN(cleanUrl), domainName,
        path, &port), 0);
    ExpectIntGT(wolfIO_HttpBuildRequest("POST", domainName, path,
        (int)XSTRLEN(path), 0, "application/ocsp-request", reqBuf,
        (int)sizeof(reqBuf)), 0);

    XFREE(tightPath, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#else
int test_wolfIO_DecodeUrl_crlf_reject(void)
{
    return TEST_SKIPPED;
}
/* Same fallback its sibling has: the test table in api.c references this
 * unconditionally, so without a stub the symbol is undefined wherever
 * HAVE_HTTP_CLIENT is off and unit.test fails to link. */
int test_wolfIO_DecodeUrl_host_bounds(void)
{
    return TEST_SKIPPED;
}
#endif /* HAVE_HTTP_CLIENT */
