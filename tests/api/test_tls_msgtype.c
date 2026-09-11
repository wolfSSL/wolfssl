/* test_tls_msgtype.c
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
#include <tests/api/api.h>
#include <tests/api/test_tls_msgtype.h>

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#if defined(__GNUC__) || defined(__clang__)
    #define TEST_TLS_MSGTYPE_UNUSED __attribute__((unused))
#else
    #define TEST_TLS_MSGTYPE_UNUSED
#endif


/* This file drives TLSX_Parse() (src/tls.c) directly with hand-built
 * extension records to exercise the per-extension "not permitted in this
 * message" gates from RFC 8446 Section 4.2, plus the argument validation and
 * ClientHello-consistency checks at the top and bottom of the same function.
 * TLSX_Parse() is WOLFSSL_TEST_VIS, so it is callable here without a
 * WOLFSSL_TEST_STATIC_BUILD guard. */

#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)

/* TLSX_SNI_Free() is file-static in src/tls.c. A test that detaches an SNI
 * list from its extension has to release it the same way: the host name, then
 * the node. */
#ifdef HAVE_SNI
TEST_TLS_MSGTYPE_UNUSED
static void test_tls_msgtype_free_sni(void* p, void* heap)
{
    SNI* sni = (SNI*)p;

    while (sni != NULL) {
        SNI* next = sni->next;

        if (sni->type == WOLFSSL_SNI_HOST_NAME)
            XFREE(sni->data.host_name, heap, DYNAMIC_TYPE_TLSX);
        XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
        sni = next;
    }
}
#endif /* HAVE_SNI */


/* Build one extension record (2-byte type, 2-byte length, N zero data
 * bytes) into buf and return its total length. Content is all-zero: gates
 * are checked before an extension's data is interpreted, so the exact bytes
 * only need to satisfy the minimum-size gate, not be semantically valid. */
TEST_TLS_MSGTYPE_UNUSED
static word16 build_ext(byte* buf, word16 type, word16 dataSz)
{
    buf[0] = (byte)(type >> 8);
    buf[1] = (byte)type;
    buf[2] = (byte)(dataSz >> 8);
    buf[3] = (byte)dataSz;
    if (dataSz > 0)
        XMEMSET(buf + 4, 0, dataSz);
    return (word16)(4 + dataSz);
}

/* Build one extension record (2-byte type, 2-byte length, then bodyLen
 * bytes copied verbatim from body) into buf and return its total length.
 * Unlike build_ext(), the data is caller-supplied, for extensions whose
 * gates require structurally meaningful content rather than zero bytes. */
TEST_TLS_MSGTYPE_UNUSED
static word16 build_ext_with_body(byte* buf, word16 type, const byte* body,
        word16 bodyLen)
{
    buf[0] = (byte)(type >> 8);
    buf[1] = (byte)type;
    buf[2] = (byte)(bodyLen >> 8);
    buf[3] = (byte)bodyLen;
    if (bodyLen > 0)
        XMEMCPY(buf + 4, body, bodyLen);
    return (word16)(4 + bodyLen);
}

#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS && HAVE_TLS_EXTENSIONS */

/* ---- TLSX_Parse() argument validation ------------------------------- */
/* if (!ssl || !input || (isRequest && !suites)) return BAD_FUNC_ARG; */
int test_tls_msgtype_arg_guard(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte dummy[4] = { 0 };
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    /* !ssl */
    ExpectIntEQ(TLSX_Parse(NULL, dummy, 0, finished, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* !input, ssl valid */
    ExpectIntEQ(TLSX_Parse(ssl, NULL, 4, finished, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* baseline: ssl and input valid, isRequest false (finished), no
     * extensions - accepted. */
    ExpectIntEQ(TLSX_Parse(ssl, dummy, 0, finished, NULL), 0);
    /* isRequest true (client_hello), suites missing */
    ExpectIntEQ(TLSX_Parse(ssl, dummy, 0, client_hello, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* isRequest true (client_hello), suites present - accepted. */
    ExpectIntEQ(TLSX_Parse(ssl, dummy, 0, client_hello, &suites), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- duplicate Pre-Shared Key extension in one ClientHello ----------- */
/* if (msgType == client_hello && pskDone) return PSK_KEY_ERROR; */
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK))
/* A minimal, structurally valid ClientHello pre_shared_key body: one
 * zero-length identity (6 bytes: 2-byte identities-length of a single
 * 6-byte entry, 2-byte identity length of 0, 4-byte age of 0) and one
 * binder sized at the SHA-256 digest length (33 bytes: 1-byte binder length
 * of 32, 32 zero binder bytes). See TLSX_PreSharedKey_Parse_ClientHello() /
 * MIN_PSK_ID_LEN / MIN_PSK_BINDERS_LEN. */
TEST_TLS_MSGTYPE_UNUSED
static const byte psk_ch_body[] = {
    0x00, 0x06,                                     /* identities len */
    0x00, 0x00,                                     /* identity len = 0 */
    0x00, 0x00, 0x00, 0x00,                          /* ticket age = 0 */
    0x00, 0x21,                                     /* binders len = 33 */
    0x20,                                           /* binder len = 32 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* binder data */
};
#endif

int test_tls_msgtype_psk_duplicate(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[64];
    word16 len, pskExtLen;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    /* op0 false: not a ClientHello, pskDone is never even examined. */
    len = build_ext(buf, 0xfff0, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL), 0);

    /* op0 true, op1 false: single ClientHello extension, pskDone stays 0
     * through the only loop iteration. */
    len = build_ext(buf, 0xfff0, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);

    /* op0 true, op1 true: a valid pre_shared_key extension sets pskDone,
     * then a second extension record in the same ClientHello re-enters the
     * loop with pskDone already set. */
    pskExtLen = build_ext(buf, TLSX_PRE_SHARED_KEY, (word16)sizeof(psk_ch_body));
    XMEMCPY(buf + 4, psk_ch_body, sizeof(psk_ch_body));
    buf[pskExtLen] = 0x00; /* one trailing byte so offset < length again */
    len = (word16)(pskExtLen + 1);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Certificate-message extension must have been offered ------------ */
/* if (msgType == certificate && IsAtLeastTLSv1_3(ssl->version) &&
 *     TLSX_Find(ssl->extensions, type) == NULL &&
 *     (ssl->ctx == NULL || TLSX_Find(ssl->ctx->extensions, type) == NULL)) */
int test_tls_msgtype_certificate_ext_offered(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) &&  defined(HAVE_MAX_FRAGMENT) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    WOLFSSL_CTX* savedCtx = NULL;

    /* op0 false: not a Certificate message. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Baseline reject (op0..op4 all "true", via the ctx->extensions arm):
     * Certificate message, TLS 1.3, type not offered anywhere. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op1 false: Certificate message, but not TLS 1.3. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op2 false: the type was offered at the ssl level. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_9), WOLFSSL_SUCCESS);
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op3 false, op4 false: not offered at the ssl level, but the ctx has
     * it - so the type was still offered (CTX-level extensions apply to
     * every ssl created from this ctx). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_9), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op3 true: ctx forcibly NULL (restored before free). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    if (ssl != NULL) {
        savedCtx = ssl->ctx;
        ssl->ctx = NULL;
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, certificate, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
        ssl->ctx = savedCtx;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- RFC 8446 4.2 "not permitted in this message" per-extension gates */

int test_tls_msgtype_sni_tls13(void)
{
    EXPECT_DECLS;
/* Drives TLSX_SNI_Parse's isRequest path, which is server-side code and
 * is compiled out by NO_WOLFSSL_SERVER. */
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SERVER_NAME, WOLFSSL_SNI_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_NAME, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_NAME, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_sni_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SERVER_NAME, WOLFSSL_SNI_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_NAME, WOLFSSL_SNI_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_NAME, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_tca(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, WOLFSSL_TCA_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, WOLFSSL_TCA_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_mfl_tls13(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, WOLFSSL_MFL_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_mfl_tls12(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, WOLFSSL_MFL_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, WOLFSSL_MFL_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_MAX_FRAGMENT_LENGTH, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_supported_groups_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SUPPORTED_GROUPS, WOLFSSL_EC_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SUPPORTED_GROUPS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SUPPORTED_GROUPS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_point_formats(void)
{
    EXPECT_DECLS;
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_EC_POINT_FORMATS, WOLFSSL_PF_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_EC_POINT_FORMATS, WOLFSSL_PF_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_EC_POINT_FORMATS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_csr_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    /* Offer status_request in our own ClientHello first, so the
     * Certificate-message extension is recognized as one we asked for by
     * the check earlier in TLSX_Parse() (RFC 8446 4.4.2). */
    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
                WOLFSSL_SUCCESS);

    len = build_ext(buf, TLSX_STATUS_REQUEST, WOLFSSL_CSR_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate_request, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_csr_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_STATUS_REQUEST, WOLFSSL_CSR_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST, WOLFSSL_CSR_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_csr2_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_STATUS_REQUEST_V2, WOLFSSL_CSR2_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST_V2, WOLFSSL_CSR2_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_STATUS_REQUEST_V2, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_extms(void)
{
    EXPECT_DECLS;
#if defined(HAVE_EXTENDED_MASTER) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, HELLO_EXT_EXTMS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, HELLO_EXT_EXTMS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, HELLO_EXT_EXTMS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_renegotiation_info(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_RENEGOTIATION_INFO, WOLFSSL_SCR_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_RENEGOTIATION_INFO, WOLFSSL_SCR_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_RENEGOTIATION_INFO, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_session_ticket_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SESSION_TICKET, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SESSION_TICKET, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SESSION_TICKET, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_alpn_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL,
            WOLFSSL_ALPN_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_alpn_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL,
            WOLFSSL_ALPN_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL,
            WOLFSSL_ALPN_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_APPLICATION_LAYER_PROTOCOL, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_sigalgs_tls13(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG) &&  defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS, WOLFSSL_SA_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate_request, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_etm(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY) &&  !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_ENCRYPT_THEN_MAC, WOLFSSL_ETM_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_ENCRYPT_THEN_MAC, WOLFSSL_ETM_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_ENCRYPT_THEN_MAC, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_supported_versions(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SUPPORTED_VERSIONS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SUPPORTED_VERSIONS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SUPPORTED_VERSIONS, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, hello_retry_request, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SUPPORTED_VERSIONS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_cookie(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_COOKIE, WOLFSSL_CKE_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_COOKIE, WOLFSSL_CKE_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, hello_retry_request, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_COOKIE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_psk(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_PRE_SHARED_KEY, WOLFSSL_PSK_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_PRE_SHARED_KEY, WOLFSSL_PSK_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_PRE_SHARED_KEY, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_cert_with_extern_psk(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) &&  !defined(NO_PSK) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    /* TLSX_CertWithExternPsk_Parse() only records the ClientHello offer -
     * and only answers a ServerHello with anything but EXT_NOT_ALLOWED -
     * once the server has opted in. */
    ExpectIntEQ(wolfSSL_set_cert_with_extern_psk(ssl, 1), WOLFSSL_SUCCESS);

    len = build_ext(buf, TLSX_CERT_WITH_EXTERN_PSK, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CERT_WITH_EXTERN_PSK, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CERT_WITH_EXTERN_PSK, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_early_data(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_EARLY_DATA) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_EARLY_DATA, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_EARLY_DATA, 4);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, session_ticket, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_EARLY_DATA, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_EARLY_DATA, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_sigalgs_cert(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG) &&  defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[16];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS_CERT, WOLFSSL_SA_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS_CERT, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, certificate_request, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SIGNATURE_ALGORITHMS_CERT, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_key_share(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_KEY_SHARE, WOLFSSL_KS_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_KEY_SHARE, WOLFSSL_KS_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_KEY_SHARE, WOLFSSL_KS_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, hello_retry_request, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_KEY_SHARE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_client_cert_type_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, WOLFSSL_CCT_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_client_cert_type_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, WOLFSSL_CCT_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, WOLFSSL_CCT_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CLIENT_CERTIFICATE_TYPE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_server_cert_type_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, WOLFSSL_SCT_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_server_cert_type_tls12(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, WOLFSSL_SCT_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, WOLFSSL_SCT_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_SERVER_CERTIFICATE_TYPE, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_connection_id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_DTLS_CID) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_CONNECTION_ID, WOLFSSL_CID_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CONNECTION_ID, WOLFSSL_CID_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_CONNECTION_ID, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_tls_msgtype_ech(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    Suites suites;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));

    len = build_ext(buf, TLSX_ECH, WOLFSSL_ECH_MIN_SIZE_CLIENT);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_ECH, 0);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, encrypted_extensions, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_ECH, WOLFSSL_ECH_MIN_SIZE_SERVER);
    ExpectIntNE(TLSX_Parse(ssl, buf, len, hello_retry_request, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));
    len = build_ext(buf, TLSX_ECH, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, finished, NULL),
                WC_NO_ERR_TRACE(EXT_NOT_ALLOWED));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
/* Builds an SNI extension body: 2-byte list length, 1-byte name type
 * (WOLFSSL_SNI_HOST_NAME), 2-byte name length, name bytes. Returns the
 * total body length. */
TEST_TLS_MSGTYPE_UNUSED
static word16 build_sni_body(byte* buf, const char* host)
{
    word16 hostLen = (word16)XSTRLEN(host);
    word16 listLen = (word16)(ENUM_LEN + OPAQUE16_LEN + hostLen);

    buf[0] = (byte)(listLen >> 8);
    buf[1] = (byte)listLen;
    buf[2] = WOLFSSL_SNI_HOST_NAME;
    buf[3] = (byte)(hostLen >> 8);
    buf[4] = (byte)hostLen;
    XMEMCPY(buf + 5, host, hostLen);
    return (word16)(5 + hostLen);
}
#endif /* HAVE_SNI && !NO_WOLFSSL_CLIENT && !NO_TLS */

/* ---- TLSX_SNI_Find() -------------------------------------------------- */
/* while (sni && sni->type != type) sni = sni->next; */
int test_tls_msgtype_sni_find(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const char* host = "example.com";

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);

    /* sni != NULL, sni->type == type: the loop body is never entered - the
     * only list entry is found immediately. */
    ExpectIntEQ(wolfSSL_SNI_Status(ssl, WOLFSSL_SNI_HOST_NAME),
                WOLFSSL_SNI_NO_MATCH);

    /* sni != NULL, sni->type != type: one non-matching iteration advances
     * to sni->next, which is NULL, ending the loop without a match. There
     * is only one SNI name type, so a type the list does not hold is the
     * only way to exercise this. */
    ExpectIntEQ(wolfSSL_SNI_Status(ssl, (byte)(WOLFSSL_SNI_HOST_NAME + 1)),
                0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_SNI_Parse(): client-side response gate ---------------------- */
/* !isRequest branch: if (!extension || !extension->data)
 *     return TLSX_HandleUnsupportedExtension(ssl); */
int test_tls_msgtype_sni_parse_response_gate(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) &&  !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* extension = NULL;
    void*  savedExtData = NULL;
    const char* host = "example.com";
    byte buf[8];
    word16 len;

    /* extension found, but its data was cleared: the client must still
     * treat a ServerHello SNI response as unsolicited rather than
     * dereference a NULL SNI list. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME));
    if (extension != NULL) {
        savedExtData = extension->data;
        extension->data = NULL;
    }

    len = build_ext(buf, TLSX_SERVER_NAME, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));

    if (extension != NULL) {
        if (extension->data == NULL)
            extension->data = savedExtData;
        else if (extension->data != savedExtData)
            test_tls_msgtype_free_sni(savedExtData, ssl->heap);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_SNI_Parse(): server-side list-length gate -------------------- */
/* if (length != OPAQUE16_LEN + size || size == 0) return BUFFER_ERROR;
 * A record this short is already rejected by TLSX_Parse()'s own minimum-
 * size gate (WOLFSSL_SNI_MIN_SIZE_CLIENT) before TLSX_SNI_Parse() is ever
 * called, so this exercises that outer gate rather than the size == 0
 * check specifically - both return BUFFER_ERROR either way. */
int test_tls_msgtype_sni_parse_size_gates(void)
{
    EXPECT_DECLS;
/* Drives TLSX_SNI_Parse's isRequest path, which is server-side code and
 * is compiled out by NO_WOLFSSL_SERVER. */
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const char* host = "srv.example";
    byte buf[16];
    byte zeroSize[OPAQUE16_LEN] = { 0x00, 0x00 };
    word16 len;
    Suites suites;

    /* An empty server_name_list is rejected as malformed. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);

    len = build_ext_with_body(buf, TLSX_SERVER_NAME, zeroSize,
            (word16)sizeof(zeroSize));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(BUFFER_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
/* SNI receive callback used to force cacheOnly in TLSX_SNI_Parse() when no
 * SNI has been configured on the SSL object. */
TEST_TLS_MSGTYPE_UNUSED
static int sni_recv_cb(WOLFSSL* ssl, int* ret, void* arg)
{
    (void)ssl; (void)ret; (void)arg;
    return 0;
}
#endif

/* ---- TLSX_SNI_Parse(): forced-keep (cacheOnly) path -------------------- */
/* if (!cacheOnly && !checkPublic && !(sni = TLSX_SNI_Find(...)))
 *     return 0;
 * matched = cacheOnly || (...);
 * if (matched || ...) { ... } */
int test_tls_msgtype_sni_parse_cacheonly(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) &&  !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* extension = NULL;
    void*  savedExtData = NULL;
    const char* host = "example.com";
    byte sniBody[24];
    byte buf[32];
    word16 sniLen, len;
    Suites suites;

    /* extension found (wolfSSL_UseSNI was called) but its data was
     * cleared, and a servername callback is registered: cacheOnly is
     * forced on, so the extension is silently kept without a real match
     * even though the type wasn't actually configured any more. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    wolfSSL_CTX_set_servername_callback(ctx, sni_recv_cb);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME));
    if (extension != NULL) {
        savedExtData = extension->data;
        extension->data = NULL;
    }

    sniLen = build_sni_body(sniBody, "test.example");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    XMEMSET(&suites, 0, sizeof(suites));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);

    if (extension != NULL) {
        if (extension->data == NULL)
            extension->data = savedExtData;
        else if (extension->data != savedExtData)
            test_tls_msgtype_free_sni(savedExtData, ssl->heap);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_SNI_Parse(): real match / mismatch, options ------------------ */
/* if (!cacheOnly && !checkPublic && !(sni = TLSX_SNI_Find(...))) return 0;
 *     - TLSX_SNI_New() only ever constructs an SNI object of type
 *       WOLFSSL_SNI_HOST_NAME (any other type hits its "invalid type"
 *       branch and fails), and the incoming record's type is rejected
 *       earlier in this function unless it is also WOLFSSL_SNI_HOST_NAME.
 *       So whenever this line is reached with cacheOnly and checkPublic
 *       both false (i.e. extension->data was non-NULL to begin with),
 *       TLSX_SNI_Find() is guaranteed to find that single entry, so this
 *       "not using this type of SNI" return is not reachable that way.
 * if (!cacheOnly && sni != NULL && sni->status != WOLFSSL_SNI_NO_MATCH)
 *     return 0;
 * matched = cacheOnly || (hostName != NULL && XSTRLEN(hostName) == size &&
 *     XSTRNCMP(hostName, ..., size) == 0);
 * if (!matched && checkPublic) return 0;
 * if (matched || (sni != NULL && (sni->options & ANSWER_ON_MISMATCH))) {...}
 * else if ((sni == NULL) || !(sni->options & CONTINUE_ON_MISMATCH)) {
 *     ... return UNKNOWN_SNI_HOST_NAME_E; } */
int test_tls_msgtype_sni_parse_match(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) &&  !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte sniBody[24];
    byte buf[32];
    word16 sniLen, len;
    Suites suites;
    const char* configured = "a.example";

    /* M1: configured host matches the ClientHello's host exactly. sni is
     * found (not the mismatched-type case below), its status starts at
     * WOLFSSL_SNI_NO_MATCH, and every hostName comparison operand is true,
     * so the extension is installed and the response is queued. Reusing
     * this ssl for a second, identical parse also exercises the "already
     * resolved" skip: the second call's sni->status is no longer
     * WOLFSSL_SNI_NO_MATCH, so it returns immediately. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, configured,
                (word16)XSTRLEN(configured)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, configured);
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* M2: configured host does not match, and differs in length, so
     * XSTRLEN(hostName) == size is false (masking XSTRNCMP). No mismatch
     * options are set, so the handshake is aborted. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, configured,
                (word16)XSTRLEN(configured)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, "bb.example2");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(UNKNOWN_SNI_HOST_NAME_E));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* M3: configured host does not match, but is the same length, so
     * XSTRLEN(hostName) == size is true and XSTRNCMP(...) == 0 is false. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, configured,
                (word16)XSTRLEN(configured)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, "b.example");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(UNKNOWN_SNI_HOST_NAME_E));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* M4: mismatch, but WOLFSSL_SNI_ANSWER_ON_MISMATCH is set on the
     * configured name - the handshake proceeds with a fake match instead
     * of aborting. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, configured,
                (word16)XSTRLEN(configured)), WOLFSSL_SUCCESS);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
            WOLFSSL_SNI_ANSWER_ON_MISMATCH);
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, "bb.example2");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* M5: mismatch, but WOLFSSL_SNI_CONTINUE_ON_MISMATCH is set - the
     * handshake continues without installing a response or aborting. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, configured,
                (word16)XSTRLEN(configured)), WOLFSSL_SUCCESS);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
            WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, "bb.example2");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_SNI_Parse(): outer SNI vs. ECH config publicName ------------- */
/* checkPublic is only ever set when an ECH extension is already attached
 * to ssl->extensions and no SNI was configured for this SSL/CTX; the outer
 * SNI is then matched against every configured ECH config's publicName
 * instead of a locally configured host name.
 *   if (XSTRLEN(workingConfig->publicName) == size &&
 *       XSTRNCMP(workingConfig->publicName, ..., size) == 0) matched = 1;
 *   if (!matched && checkPublic) return 0; */
int test_tls_msgtype_sni_parse_ech_public(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) && defined(HAVE_ECH) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && !defined(NO_WOLFSSL_CLIENT) &&  !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_EchConfig echConfig;
    WOLFSSL_ECH* ech = NULL;
    char publicName[] = "pub.example";
    byte sniBody[24];
    byte buf[32];
    word16 sniLen, len;
    Suites suites;

    /* Outer SNI equals the ECH config's publicName: the while loop's
     * XSTRLEN/XSTRNCMP operands are both true, matched is set, and the
     * response is installed onto ech->extensions instead of
     * ssl->extensions. No local SNI is configured, so checkPublic is what
     * drove this parse at all. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&echConfig, 0, sizeof(echConfig));
    echConfig.publicName = publicName;
    ExpectNotNull(ech = (WOLFSSL_ECH*)XMALLOC(sizeof(WOLFSSL_ECH), ssl->heap,
                DYNAMIC_TYPE_TMP_BUFFER));
    if (ech != NULL) {
        XMEMSET(ech, 0, sizeof(WOLFSSL_ECH));
        ech->echConfig = &echConfig;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_ECH, ech, ssl->heap), 0);
    }
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, publicName);
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Outer SNI is the same length as the publicName but differs in
     * content: XSTRLEN(...) == size is true, XSTRNCMP(...) == 0 is false,
     * so the loop does not match. checkPublic then makes the mismatch a
     * silent no-op instead of an alert - unlike a locally configured SNI
     * mismatch, which aborts the handshake. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&echConfig, 0, sizeof(echConfig));
    echConfig.publicName = publicName;
    ExpectNotNull(ech = (WOLFSSL_ECH*)XMALLOC(sizeof(WOLFSSL_ECH), ssl->heap,
                DYNAMIC_TYPE_TMP_BUFFER));
    if (ech != NULL) {
        XMEMSET(ech, 0, sizeof(WOLFSSL_ECH));
        ech->echConfig = &echConfig;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_ECH, ech, ssl->heap), 0);
    }
    XMEMSET(&suites, 0, sizeof(suites));
    sniLen = build_sni_body(sniBody, "pub.examplx");
    len = build_ext_with_body(buf, TLSX_SERVER_NAME, sniBody, sniLen);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_PreSharedKey_Parse_ClientHello(): identity list --------------- */
/* if (len < MIN_PSK_ID_LEN || length - idx < len) return BUFFER_E;
 * ...
 * if (len < OPAQUE16_LEN + identityLen + OPAQUE32_LEN ||
 *         identityLen > MAX_PSK_ID_LEN) return BUFFER_E; */
int test_tls_msgtype_psk_ch_id_gates(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[MAX_PSK_ID_LEN + 64];
    byte body[MAX_PSK_ID_LEN + 48];
    word16 len;
    Suites suites;

    /* op0 true: identities length (5) is below MIN_PSK_ID_LEN (6). Padded
     * to 4 bytes total so the earlier "room for both length fields" check
     * (length - idx < 2*OPAQUE16_LEN) passes and this is the check that
     * fires. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    {
        byte shortLen[2 * OPAQUE16_LEN] = { 0x00, 0x05, 0x00, 0x00 };
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, shortLen,
                (word16)sizeof(shortLen));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 false, op1 true: identities length (6) meets MIN_PSK_ID_LEN, but
     * fewer than 6 bytes actually follow in the extension. (op0 false,
     * op1 false is the psk_duplicate test's valid ClientHello body.) */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    {
        byte truncated[4] = { 0x00, 0x06, 0x00, 0x00 };
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, truncated,
                (word16)sizeof(truncated));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Per-identity op0 true: identities length (6) is consistent with the
     * outer check, but the single identity inside it claims a 10-byte
     * identity plus age though only 4 bytes remain for them. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    {
        byte b[8] = { 0x00, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00 };
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, b,
                (word16)sizeof(b));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Per-identity op0 false, op1 true: identityLen is one more than
     * MAX_PSK_ID_LEN, with enough buffer supplied to hold it in full. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    {
        word16 idLen = MAX_PSK_ID_LEN + 1;
        word16 identitiesLen = (word16)(OPAQUE16_LEN + idLen + OPAQUE32_LEN);
        word16 idx = 0;

        body[idx++] = (byte)(identitiesLen >> 8);
        body[idx++] = (byte)identitiesLen;
        body[idx++] = (byte)(idLen >> 8);
        body[idx++] = (byte)idLen;
        XMEMSET(body + idx, 0x41, idLen);
        idx = (word16)(idx + idLen);
        body[idx++] = 0; body[idx++] = 0; body[idx++] = 0; body[idx++] = 0;
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, body, idx);
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/* A two-identity ClientHello pre_shared_key body: two distinct identities
 * (so TLSX_PreSharedKey_Use() creates two list entries instead of
 * deduplicating on identical content) and two SHA-256-sized binders. */
static const byte psk_ch_body_two[] = {
    0x00, 0x0D,                                     /* identities len */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,              /* identity #1 (empty) */
    0x00, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00,        /* identity #2 (1 byte) */
    0x00, 0x42,                                     /* binders len = 66 */
    0x20,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0x20,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
};
#endif

/* ---- TLSX_PreSharedKey_Parse(): server-selected identity index --------- */
/* for (; list != NULL && idx > 0; idx--) list = list->next; */
int test_tls_msgtype_psk_sh_index(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* extension = NULL;
    PreSharedKey* list = NULL;
    byte chBuf[96];
    byte shBuf[8];
    byte idxBody[OPAQUE16_LEN];
    word16 chLen, shLen;
    Suites suites;

    /* op0 true, op1 true (continue) then op0 true, op1 false (stop): two
     * identities on the list, server selects index 1 (the second). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body_two,
            (word16)sizeof(psk_ch_body_two));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY));
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL)
        ssl->session->version = ssl->ctx->method->version;
    idxBody[0] = 0x00; idxBody[1] = 0x01; /* choose index 1 */
    shLen = build_ext_with_body(shBuf, TLSX_PRE_SHARED_KEY, idxBody,
            (word16)sizeof(idxBody));
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL), 0);
    if (extension != NULL)
        list = (PreSharedKey*)extension->data;
    ExpectNotNull(list);
    if (list != NULL) {
        ExpectIntEQ(list->chosen, 0);
        ExpectNotNull(list->next);
        if (list->next != NULL)
            ExpectIntEQ(list->next->chosen, 1);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 false: a single identity, server selects index 1 - the loop
     * runs out of list (masking op1) before idx reaches 0. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    idxBody[0] = 0x00; idxBody[1] = 0x01; /* index 1, out of range */
    shLen = build_ext_with_body(shBuf, TLSX_PRE_SHARED_KEY, idxBody,
            (word16)sizeof(idxBody));
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_PreSharedKey_Parse(): resumed-session consistency ------------ */
/* if (ssl->options.cipherSuite0  != ssl->session->cipherSuite0       ||
 *     ssl->options.cipherSuite   != ssl->session->cipherSuite        ||
 *     ssl->session->version.major != ssl->ctx->method->version.major ||
 *     ssl->session->version.minor != ssl->ctx->method->version.minor)
 *     return PSK_KEY_ERROR; */
int test_tls_msgtype_psk_sh_resumption(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte chBuf[64];
    byte shBuf[8];
    static const byte idxBody[OPAQUE16_LEN] = { 0x00, 0x00 };
    word16 chLen, shLen;
    Suites suites;

    shLen = build_ext_with_body(shBuf, TLSX_PRE_SHARED_KEY, idxBody,
            (word16)sizeof(idxBody));

    /* Baseline: cipherSuite0/cipherSuite/version all match - success. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL)
        ssl->session->version = ssl->ctx->method->version;
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 true: cipherSuite0 mismatch. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL) {
        ssl->session->version = ssl->ctx->method->version;
        ssl->session->cipherSuite0 = 1;
    }
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op1 true: cipherSuite mismatch. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL) {
        ssl->session->version = ssl->ctx->method->version;
        ssl->session->cipherSuite = 1;
    }
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op2 true: session version.major mismatch. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL) {
        ssl->session->version = ssl->ctx->method->version;
        ssl->session->version.major = (byte)(ssl->session->version.major + 1);
    }
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op3 true: session version.minor mismatch. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    chLen = build_ext_with_body(chBuf, TLSX_PRE_SHARED_KEY, psk_ch_body,
            (word16)sizeof(psk_ch_body));
    ExpectIntEQ(TLSX_Parse(ssl, chBuf, chLen, client_hello, &suites), 0);
    if (ssl != NULL && ssl->session != NULL && ssl->ctx != NULL) {
        ssl->session->version = ssl->ctx->method->version;
        ssl->session->version.minor = (byte)(ssl->session->version.minor + 1);
    }
    ExpectIntEQ(TLSX_Parse(ssl, shBuf, shLen, server_hello, NULL),
                WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_PreSharedKey_Parse_ClientHello(): binder list ----------------- */
/* if (len < MIN_PSK_BINDERS_LEN || length - idx < len) return BUFFER_E;
 * while (list != NULL && len > 0) {
 *     if (list->binderLen < WC_SHA256_DIGEST_SIZE ||
 *             list->binderLen > WC_MAX_DIGEST_SIZE) return BUFFER_E;
 *     ...
 * }
 * if (list != NULL || len != 0) return BUFFER_E; */
int test_tls_msgtype_psk_ch_binder_gates(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[128];
    byte body[128];
    word16 len, idx;

    /* op0 true: binders length (10) is below MIN_PSK_BINDERS_LEN (33). One
     * valid identity precedes it so the identity list itself is accepted. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;
        static const byte shortBinders[] = {
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 1 identity */
            0x00, 0x0A,                                     /* binders len = 10 */
            0,0,0,0,0,0,0,0,0,0                              /* 10 filler bytes */
        };
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, shortBinders,
                (word16)sizeof(shortBinders));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 false, op1 true: binders length (33) meets MIN_PSK_BINDERS_LEN,
     * but far fewer bytes actually remain in the extension. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;
        static const byte truncatedBinders[] = {
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 1 identity */
            0x00, 0x21,                                     /* binders len = 33 */
            0,0,0,0,0                                        /* only 5 remain */
        };
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, truncatedBinders,
                (word16)sizeof(truncatedBinders));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Per-binder op0 true: the binder length byte (10) is below
     * WC_SHA256_DIGEST_SIZE (32). The declared binders length (34) still
     * needs to cover the length byte plus filler so the outer binders-
     * length gate passes and this check is the one that fires. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;

        idx = 0;
        body[idx++] = 0x00; body[idx++] = 0x06; /* identities len */
        body[idx++] = 0x00; body[idx++] = 0x00; /* identityLen = 0 */
        body[idx++] = 0; body[idx++] = 0; body[idx++] = 0; body[idx++] = 0;
        body[idx++] = 0x00; body[idx++] = 0x22; /* binders len = 34 */
        body[idx++] = 10;                       /* binderLen = 10 (< 32) */
        XMEMSET(body + idx, 0, 33);
        idx = (word16)(idx + 33);
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, body, idx);
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Per-binder op1 true (op0 false): the binder length byte (100) is
     * above WC_MAX_DIGEST_SIZE (64). The declared binders length (34) only
     * needs to cover the length byte itself plus filler - the check fires
     * before any binder bytes are read. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;

        idx = 0;
        body[idx++] = 0x00; body[idx++] = 0x06; /* identities len */
        body[idx++] = 0x00; body[idx++] = 0x00; /* identityLen = 0 */
        body[idx++] = 0; body[idx++] = 0; body[idx++] = 0; body[idx++] = 0;
        body[idx++] = 0x00; body[idx++] = 0x22; /* binders len = 34 */
        body[idx++] = 100;                      /* binderLen = 100 (> 64) */
        XMEMSET(body + idx, 0, 33);
        idx = (word16)(idx + 33);
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, body, idx);
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* while(list!=NULL && len>0) op1 (len>0), and the trailing "list !=
     * NULL" gate: two identities, but only one binder - after consuming
     * it, len reaches 0 while list still points at the second identity. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;
        static const byte twoIdOneBinder[] = {
            0x00, 0x0D,                            /* identities len = 13 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* identity #1, age = 0 */
            0x00, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x00, /* identity #2 (1 byte), age = 0 */
            0x00, 0x21,                            /* binders len = 33 */
            0x20,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        };
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, twoIdOneBinder,
                (word16)sizeof(twoIdOneBinder));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Trailing "len != 0" gate: one identity but two binders' worth of
     * data - list runs out (becomes NULL) while len still has a second
     * binder's length left over. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    {
        Suites suites;
        static const byte oneIdTwoBinders[] = {
            0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 1 identity */
            0x00, 0x42,                            /* binders len = 66 */
            0x20,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
            0x20,
            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
        };
        XMEMSET(&suites, 0, sizeof(suites));
        len = build_ext_with_body(buf, TLSX_PRE_SHARED_KEY, oneIdTwoBinders,
                (word16)sizeof(oneIdTwoBinders));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(BUFFER_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_Cookie_Parse() ------------------------------------------------ */
/* This function is only ever reached through TLSX_Parse()'s own extension
 * dispatch (src/tls.c, the TLSX_COOKIE case), which already requires
 * IsAtLeastTLSv1_3(ssl->version) and msgType being client_hello or
 * hello_retry_request before calling it - both are argued as exclusions in
 * the campaign report rather than tested here:
 *   if (msgType != client_hello && msgType != hello_retry_request) {...}
 *       - the caller's identical check makes this always false.
 *   if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version))
 *       - the second operand is always true here for the same reason;
 *         only the dtls operand can vary.
 *
 * if (cookie->len != len || XMEMCMP(cookie->data, input + idx, len) != 0) {
 *     ... return HRR_COOKIE_ERROR; } */
int test_tls_msgtype_cookie_parse_gates(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_SEND_HRR_COOKIE) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[24];
    byte body[16];
    word16 len;
    Suites suites;

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
    /* dtls operand true: no Cookie extension configured yet, and the SSL
     * object is DTLS 1.3 - the cookie is accepted and stored rather than
     * rejected with HRR_COOKIE_ERROR. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    body[0] = 0x00; body[1] = 0x04; body[2] = 1; body[3] = 2; body[4] = 3;
    body[5] = 4;
    len = build_ext_with_body(buf, TLSX_COOKIE, body, 6);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    /* dtls operand false: same setup, but a plain (non-DTLS) TLS 1.3
     * client - HRR_COOKIE_ERROR because no HelloRetryRequest was sent. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    XMEMSET(&suites, 0, sizeof(suites));
    body[0] = 0x00; body[1] = 0x04; body[2] = 1; body[3] = 2; body[4] = 3;
    body[5] = 4;
    len = build_ext_with_body(buf, TLSX_COOKIE, body, 6);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                WC_NO_ERR_TRACE(HRR_COOKIE_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#if defined(WOLFSSL_TEST_STATIC_BUILD)
    /* An existing Cookie extension (as if this SSL object had already
     * sent a HelloRetryRequest cookie) is compared against a second
     * ClientHello's cookie. */
    {
        static const byte seedCookie[4] = { 1, 2, 3, 4 };

        /* op0 true: the echoed cookie's length does not match. */
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        ExpectIntEQ(TLSX_Cookie_Use(ssl, seedCookie, sizeof(seedCookie),
                    NULL, 0, 1, &ssl->extensions), 0);
        XMEMSET(&suites, 0, sizeof(suites));
        body[0] = 0x00; body[1] = 0x02; body[2] = 1; body[3] = 2;
        len = build_ext_with_body(buf, TLSX_COOKIE, body, 4);
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites),
                    WC_NO_ERR_TRACE(HRR_COOKIE_ERROR));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);

        /* op0 false, op1 false: length and content both match - the
         * cookie is accepted and the request-seen flag is cleared. */
        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        ExpectIntEQ(TLSX_Cookie_Use(ssl, seedCookie, sizeof(seedCookie),
                    NULL, 0, 1, &ssl->extensions), 0);
        XMEMSET(&suites, 0, sizeof(suites));
        body[0] = 0x00; body[1] = 0x04;
        body[2] = 1; body[3] = 2; body[4] = 3; body[5] = 4;
        len = build_ext_with_body(buf, TLSX_COOKIE, body, 6);
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
    }
#endif /* WOLFSSL_TEST_STATIC_BUILD */
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_TCA_Parse(): gates -------------------------------------------- */
/* !isRequest branch: if (!extension || !extension->data)
 *     return TLSX_HandleUnsupportedExtension(ssl);
 * server branch:     if (!extension || !extension->data) return 0;
 * X509_NAME branch:  if ((offset > length) || (idSz > length - offset))
 *     return BUFFER_ERROR;
 *     - offset > length is unreachable here: the immediately preceding
 *       check (offset + OPAQUE16_LEN > length) guarantees offset <= length
 *       after the OPAQUE16_LEN advance, so this operand never pairs
 *       (excluded in the campaign report, not tested here). */
int test_tls_msgtype_tca_parse_gates(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && !defined(NO_WOLFSSL_CLIENT) &&  !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) &&  !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* extension = NULL;
    void*  savedExtData = NULL;
    const byte id[] = { 1, 2, 3, 4 };
    byte buf[16];
    word16 len;

    /* 3131 op0 true: no TCA configured at all - the client must treat an
     * unsolicited response as unsupported. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* 3131 op1 true: TCA configured, but its data was cleared - same
     * outcome via the other operand. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                id, (word32)sizeof(id)), WOLFSSL_SUCCESS);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions,
                TLSX_TRUSTED_CA_KEYS));
    if (extension != NULL) {
        savedExtData = extension->data;
        extension->data = NULL;
    }
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, server_hello, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    if (extension != NULL)
        extension->data = savedExtData;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* 3131 both false: TCA configured normally, empty response body -
     * accepted, response flag set. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                id, (word32)sizeof(id)), WOLFSSL_SUCCESS);
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, 0);
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, server_hello, NULL), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* 3145 op1 true: server side, TCA configured but its data was
     * cleared - "not enabled at server side" is taken, not a crash. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                id, (word32)sizeof(id)), WOLFSSL_SUCCESS);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions,
                TLSX_TRUSTED_CA_KEYS));
    if (extension != NULL) {
        savedExtData = extension->data;
        extension->data = NULL;
    }
    /* A ClientHello TCA extension must be at least WOLFSSL_TCA_MIN_SIZE_CLIENT
     * bytes to pass TLSX_Parse()'s own minimum-size gate; the body content
     * is irrelevant here since extension->data == NULL returns before the
     * body is ever read. */
    len = build_ext(buf, TLSX_TRUSTED_CA_KEYS, WOLFSSL_TCA_MIN_SIZE_CLIENT);
    {
        Suites suites;
        XMEMSET(&suites, 0, sizeof(suites));
        ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    }
    if (extension != NULL)
        extension->data = savedExtData;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_TCA_Find() ----------------------------------------------------- */
/* if (tca->type == type && idSz == tca->idSz &&
 *         XMEMCMP(id, tca->id, idSz) == 0) break; */
int test_tls_msgtype_tca_find(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && !defined(NO_WOLFSSL_CLIENT) &&  !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && !defined(NO_SHA) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[24];
    byte body[16];
    word16 len, entryLen;
    Suites suites;
    const byte sha1Id[WC_SHA_DIGEST_SIZE] = {
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
    };
    const byte idA[] = { 'A','A','A','A' };
    const byte idB[] = { 'B','B','B','B' };
    const byte idAX[] = { 'A','A','A','A','X' };

    /* op0 false: the configured entry is CERT_SHA1, the query is
     * X509_NAME - tca->type != type on the only list entry. Each body is
     * a 2-byte list length followed by one type + idSz + id entry. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_CERT_SHA1,
                sha1Id, sizeof(sha1Id)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    entryLen = (word16)(1 + OPAQUE16_LEN + sizeof(idA));
    body[0] = (byte)(entryLen >> 8); body[1] = (byte)entryLen;
    body[2] = WOLFSSL_TRUSTED_CA_X509_NAME;
    body[3] = 0x00; body[4] = (byte)sizeof(idA);
    XMEMCPY(body + 5, idA, sizeof(idA));
    len = build_ext_with_body(buf, TLSX_TRUSTED_CA_KEYS, body,
            (word16)(2 + entryLen));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 true, op1 false: type matches, but the query's idSz (5)
     * differs from the configured entry's idSz (4). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                idA, (word32)sizeof(idA)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    entryLen = (word16)(1 + OPAQUE16_LEN + sizeof(idAX));
    body[0] = (byte)(entryLen >> 8); body[1] = (byte)entryLen;
    body[2] = WOLFSSL_TRUSTED_CA_X509_NAME;
    body[3] = 0x00; body[4] = (byte)sizeof(idAX);
    XMEMCPY(body + 5, idAX, sizeof(idAX));
    len = build_ext_with_body(buf, TLSX_TRUSTED_CA_KEYS, body,
            (word16)(2 + entryLen));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 true, op1 true, op2 false: type and length match, content
     * does not. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                idA, (word32)sizeof(idA)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    entryLen = (word16)(1 + OPAQUE16_LEN + sizeof(idB));
    body[0] = (byte)(entryLen >> 8); body[1] = (byte)entryLen;
    body[2] = WOLFSSL_TRUSTED_CA_X509_NAME;
    body[3] = 0x00; body[4] = (byte)sizeof(idB);
    XMEMCPY(body + 5, idB, sizeof(idB));
    len = build_ext_with_body(buf, TLSX_TRUSTED_CA_KEYS, body,
            (word16)(2 + entryLen));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 true, op1 true, op2 true: exact match - found on the first
     * (only) list entry. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                idA, (word32)sizeof(idA)), WOLFSSL_SUCCESS);
    XMEMSET(&suites, 0, sizeof(suites));
    entryLen = (word16)(1 + OPAQUE16_LEN + sizeof(idA));
    body[0] = (byte)(entryLen >> 8); body[1] = (byte)entryLen;
    body[2] = WOLFSSL_TRUSTED_CA_X509_NAME;
    body[3] = 0x00; body[4] = (byte)sizeof(idA);
    XMEMCPY(body + 5, idA, sizeof(idA));
    len = build_ext_with_body(buf, TLSX_TRUSTED_CA_KEYS, body,
            (word16)(2 + entryLen));
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, client_hello, &suites), 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_TRUSTED_CA) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
/* A small counting allocator used to force a single, targeted malloc
 * failure inside TLSX_TCA_New(). Installed narrowly around the call under
 * test and restored immediately after. */
static int tca_fail_after = -1;
static int tca_alloc_seen = 0;

TEST_TLS_MSGTYPE_UNUSED
static void* tca_fail_malloc(size_t size)
{
    if (tca_fail_after >= 0) {
        if (tca_alloc_seen == tca_fail_after) {
            tca_alloc_seen++;
            return NULL;
        }
        tca_alloc_seen++;
    }
    return malloc(size);
}

TEST_TLS_MSGTYPE_UNUSED
static void tca_fail_free(void* ptr)
{
    free(ptr);
}

TEST_TLS_MSGTYPE_UNUSED
static void* tca_fail_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}
#endif /* HAVE_TRUSTED_CA && !NO_WOLFSSL_CLIENT && !NO_TLS */

/* ---- TLSX_TCA_New(): id allocation failure ------------------------------ */
/* KEY_SHA1/CERT_SHA1: if (idSz == WC_SHA_DIGEST_SIZE &&
 *     (tca->id = XMALLOC(idSz, ...))) {...}
 * X509_NAME:          if (idSz > 0 &&
 *     (tca->id = XMALLOC(idSz, ...))) {...}
 * In both cases the length operand's pair is already covered elsewhere;
 * only the allocation succeeding vs. failing is exercised here. */
int test_tls_msgtype_tca_new_alloc(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) &&  !defined(NO_SHA) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12) && \
    defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    wolfSSL_Malloc_cb prevM = NULL;
    wolfSSL_Free_cb prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;
    const byte sha1Id[WC_SHA_DIGEST_SIZE] = {
        0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
        0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22
    };
    const byte nameId[] = { 5, 6, 7, 8 };

    /* CERT_SHA1: the TCA struct itself (allocation #0) succeeds, the id
     * buffer (allocation #1) fails. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(tca_fail_malloc, tca_fail_free,
                tca_fail_realloc), 0);
    tca_alloc_seen = 0;
    tca_fail_after = 1;
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_CERT_SHA1,
                sha1Id, sizeof(sha1Id)), WC_NO_ERR_TRACE(MEMORY_E));
    tca_fail_after = -1;
    (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* X509_NAME: same shape - struct allocation succeeds, id buffer
     * allocation fails. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(tca_fail_malloc, tca_fail_free,
                tca_fail_realloc), 0);
    tca_alloc_seen = 0;
    tca_fail_after = 1;
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_X509_NAME,
                nameId, (word32)sizeof(nameId)), WC_NO_ERR_TRACE(MEMORY_E));
    tca_fail_after = -1;
    (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_PreSharedKey_Write(): server's chosen identity ---------------- */
/* for (i=0; list != NULL && !list->chosen; i++) list = list->next; */
int test_tls_msgtype_psk_write_chosen(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* extension = NULL;
    PreSharedKey* pskA = NULL;
    PreSharedKey* pskB = NULL;
    byte identityA[] = { 0xAA };
    byte identityB[] = { 0xBB };
    byte output[32];
    word16 offset;

    /* op0 true, op1 true (continue) then op0 true, op1 false (stop): two
     * identities, the second one chosen. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_PreSharedKey_Use(&ssl->extensions, identityA,
                (word16)sizeof(identityA), 0, no_mac, 0, 0, 1, &pskA,
                ssl->heap), 0);
    ExpectIntEQ(TLSX_PreSharedKey_Use(&ssl->extensions, identityB,
                (word16)sizeof(identityB), 0, no_mac, 0, 0, 1, &pskB,
                ssl->heap), 0);
    if (pskB != NULL)
        pskB->chosen = 1;
    ExpectNotNull(extension = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY));
    if (extension != NULL)
        extension->resp = 1;
    offset = 0;
    ExpectIntEQ(TLSX_WriteResponse(ssl, output, server_hello, &offset), 0);
    ExpectIntGT(offset, 0);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* op0 false: a single, unchosen identity - the loop runs off the end
     * of the list before finding a chosen entry. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_PreSharedKey_Use(&ssl->extensions, identityA,
                (word16)sizeof(identityA), 0, no_mac, 0, 0, 1, &pskA,
                ssl->heap), 0);
    ExpectNotNull(extension = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY));
    if (extension != NULL)
        extension->resp = 1;
    offset = 0;
    ExpectIntEQ(TLSX_WriteResponse(ssl, output, server_hello, &offset),
                WC_NO_ERR_TRACE(BUILD_MSG_ERROR));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
