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

/* This file drives TLSX_Parse() (src/tls.c) directly with hand-built
 * extension records to exercise the per-extension "not permitted in this
 * message" gates from RFC 8446 Section 4.2, plus the argument validation and
 * ClientHello-consistency checks at the top and bottom of the same function.
 * TLSX_Parse() is WOLFSSL_TEST_VIS, so it is callable here without a
 * WOLFSSL_TEST_STATIC_BUILD guard. */

#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_TLS_EXTENSIONS)

/* Build one extension record (2-byte type, 2-byte length, N zero data
 * bytes) into buf and return its total length. Content is all-zero: gates
 * are checked before an extension's data is interpreted, so the exact bytes
 * only need to satisfy the minimum-size gate, not be semantically valid. */
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

#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS && HAVE_TLS_EXTENSIONS */

/* ---- TLSX_Parse() argument validation ------------------------------- */
/* if (!ssl || !input || (isRequest && !suites)) return BAD_FUNC_ARG; */
int test_tls_msgtype_arg_guard(void)
{
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS) && \
    defined(HAVE_MAX_FRAGMENT) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte buf[8];
    word16 len;
    WOLFSSL_CTX* savedCtx;

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
    savedCtx = ssl->ctx;
    ssl->ctx = NULL;
    ExpectIntEQ(TLSX_Parse(ssl, buf, len, certificate, NULL),
                WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    ssl->ctx = savedCtx;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- RFC 8446 4.2 "not permitted in this message" per-extension gates */

int test_tls_msgtype_sni_tls13(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_SNI) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_SUPPORTED_CURVES) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_EXTENDED_MASTER) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_ALPN) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_ALPN) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG) && \
    defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK) && \
    !defined(NO_PSK) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_EARLY_DATA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG) && \
    defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_SUPPORTED_CURVES) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_RPK) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_RPK) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_RPK) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(HAVE_RPK) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_DTLS_CID) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
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
