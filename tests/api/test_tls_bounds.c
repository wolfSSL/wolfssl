/* test_tls_bounds.h
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
#include <tests/api/test_tls_bounds.h>

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

/* Named guards for the regions below: each covers a file-scope helper or
 * fixture plus the test(s) that use it, so the condition is written once
 * and the region and the in-body guard cannot drift apart. */
#if defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_CERTS)
    #define TEST_TLS_BOUNDS_CSR2_REQUESTS
#endif
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_OCSP)
    #define TEST_TLS_BOUNDS_CSR_STATUS_CB
#endif
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_TLS_OCSP_MULTI) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && defined(HAVE_OCSP) && \
    !defined(NO_RSA) && !defined(NO_SHA256)
    #define TEST_TLS_BOUNDS_OCSP_CHAIN
#endif
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SUPPORTED_CURVES) && \
    (defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)) && !defined(NO_PSK) && \
    defined(HAVE_AESGCM) && !defined(NO_AES) && !defined(NO_SHA256)
    #define TEST_TLS_BOUNDS_POPULATE_EXT
#endif
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    #define TEST_TLS_BOUNDS_CSR_PARSE
#endif
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)
    #define TEST_TLS_BOUNDS_SESSION_TICKET_FF
#endif

/* Each helper below is called only from test bodies whose feature guards differ
 * from one another, so no single condition describes "some caller is compiled
 * in" -- a shared build, for instance, compiles out every WOLFSSL_TEST_STATIC_BUILD
 * body at once. Mark them instead of trying to track the union by hand. */
#if defined(__GNUC__) || defined(__clang__)
    #define TEST_TLS_BOUNDS_UNUSED __attribute__((unused))
#else
    #define TEST_TLS_BOUNDS_UNUSED
#endif

/* c32to24() (wolfcrypt/src/misc.c) is only externally linkable when NO_INLINE
 * is defined; this build inlines it into each translation unit that already
 * needs it, so it is not visible here. Same 3-byte big-endian length write,
 * spelled out locally. */
TEST_TLS_BOUNDS_UNUSED
static void test_tls_bounds_c32to24(word32 in, byte* out)
{
    out[0] = (byte)(in >> 16);
    out[1] = (byte)(in >> 8);
    out[2] = (byte)in;
}

#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM)
/* SetSSL_CTX() (InitSSL()'s caller) fails wolfSSL_new() with NO_PRIVATE_KEY
 * for a server-side ssl with no certificate/key and no PSK/anon/cert-setup-cb
 * fallback, so every server-side ssl created only to unit-test a WOLFSSL_LOCAL
 * function directly (never running a real handshake) still needs a loaded
 * cert/key to get past wolfSSL_new() at all. */
TEST_TLS_BOUNDS_UNUSED
static int test_tls_bounds_load_server_cert(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem",
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem",
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_UseSNI - the extensions list argument is always &ssl->extensions or
 * &ctx->extensions (wolfSSL_UseSNI / wolfSSL_CTX_UseSNI), or &ech->extensions
 * (the ECH echo path in TLSX_SNI_Parse) - always the address of a struct
 * member, never NULL. The "extensions == NULL" half of the guard has no
 * reachable caller and is excluded (argued in the report, not retested here).
 * The "data == NULL" half, the host-name-length guard, and the duplicate-type
 * removal in the linked list are all reachable through wolfSSL_UseSNI(). */
int test_TLSX_UseSNI_bounds(void)
{
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char longName[WOLFSSL_HOST_NAME_MAX + 1];

    XMEMSET(longName, 'a', sizeof(longName) - 1);
    longName[sizeof(longName) - 1] = '\0';

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* data == NULL -> BAD_FUNC_ARG (extensions is always non-NULL here). */
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, NULL, 8),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* type == HOST_NAME && size >= MAX -> BAD_LENGTH_E. */
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, longName,
                (word16)XSTRLEN(longName)), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* type != HOST_NAME: the length guard is skipped regardless of size (the
     * BAD_LENGTH_E path is not taken), independence for the first operand of
     * the (type == HOST_NAME) && (size >= MAX) guard. WOLFSSL_SNI_HOST_NAME
     * is the only type TLSX_SNI_New() accepts, so this then fails later,
     * inside TLSX_SNI_New()'s own type switch, with MEMORY_E - a different
     * and later guard than the one under test here. */
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME + 1, longName,
                (word16)XSTRLEN(longName)), WC_NO_ERR_TRACE(MEMORY_E));

    /* type == HOST_NAME && size < MAX -> accepted; also the first insert,
     * so the duplicate-type list walk has nothing to match yet. */
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "a.example.com",
                13), WOLFSSL_SUCCESS);

    /* A second insert: the walk finds sni->next->type == type on the first
     * node and removes the duplicate.
     *
     * "sni->next && sni->next->type == type" (the duplicate-removal check)
     * is not driven for independence anywhere in this file: WOLFSSL_SNI_
     * HOST_NAME is the only type TLSX_SNI_New() will ever construct (its
     * switch on sni->type frees and rejects anything else), so every node
     * that ever exists in the list has type == WOLFSSL_SNI_HOST_NAME, and
     * "type" here (the argument of the call reaching this loop) must also
     * be WOLFSSL_SNI_HOST_NAME or TLSX_UseSNI() would already have returned
     * MEMORY_E from TLSX_SNI_New() before the loop is reached. So whenever
     * "sni->next" is true, "sni->next->type == type" is true too - the loop
     * always removes the one prior node on its first check and breaks,
     * which also means a second loop iteration (where sni->next could be
     * NULL) is never reached. Both operands are pinned to true on every
     * real execution; excluded (family 4: contradicted by the callee
     * postcondition of TLSX_SNI_New()). */
    ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "c.example.com",
                13), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_UseALPN - extensions is always &ssl->extensions (wolfSSL_UseALPN());
 * unreachable-NULL, excluded. data == NULL: wolfSSL_UseALPN() only calls
 * TLSX_UseALPN() with tokens produced by XSTRTOK(), which are never NULL
 * inside the "while (token[idx] != NULL)" loop, so the only way to reach
 * TLSX_UseALPN() with a NULL data pointer at all is to call it directly. */
int test_TLSX_UseALPN_bounds(void)
{
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"http/1.1", 8,
                WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);

#ifdef WOLFSSL_TEST_STATIC_BUILD
    /* No wrapper can pass data == NULL; extensions == NULL is likewise
     * unreachable through any caller (always &ssl->extensions), and is
     * exercised here only to document that the guard exists, not to claim
     * it as a caller-reachable pair. */
    ExpectIntEQ(TLSX_UseALPN(&ssl->extensions, NULL, 4,
                WOLFSSL_ALPN_FAILED_ON_MISMATCH, ssl->heap),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_UseMaxFragment - extensions always &ssl->extensions / &ctx->extensions;
 * unreachable-NULL, excluded. mfl < MIN and mfl > MAX are both reachable
 * through the public wrapper with an out-of-range code, alongside a valid
 * in-range call. */
int test_TLSX_UseMaxFragment_bounds(void)
{
#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* mfl < WOLFSSL_MFL_MIN (0 is below WOLFSSL_MFL_2_9 == 1). */
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_DISABLED),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* mfl > WOLFSSL_MFL_MAX (WOLFSSL_MFL_2_8 == 6 is the maximum code). */
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, (byte)(WOLFSSL_MFL_MAX + 1)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* In range: accepted. */
    ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11),
                WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_UseCertificateStatusRequest - extensions is always &ssl->extensions /
 * &ctx->extensions (wolfSSL_UseOCSPStapling() / _CTX_); unreachable-NULL,
 * excluded. status_type != WOLFSSL_CSR_OCSP is reachable directly: the
 * wrapper passes the caller's status_type straight through with no
 * validation of its own. */
int test_TLSX_UseCertificateStatusRequest_bounds(void)
{
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* status_type != WOLFSSL_CSR_OCSP. */
    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP + 1, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid request. */
    ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP,
                WOLFSSL_CSR_OCSP_USE_NONCE), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_UseCertificateStatusRequestV2 - same pattern as V1 above. */
int test_TLSX_UseCertificateStatusRequestV2_bounds(void)
{
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Neither WOLFSSL_CSR2_OCSP nor WOLFSSL_CSR2_OCSP_MULTI: both operands
     * of "status_type != OCSP && status_type != OCSP_MULTI" true. */
    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(ssl,
                WOLFSSL_CSR2_OCSP_MULTI + 1, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* status_type == OCSP_MULTI: first operand true (MULTI != OCSP), second
     * operand false (MULTI == MULTI) - independence for the second operand,
     * paired against the invalid-type call above. */
    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI,
                WOLFSSL_CSR2_OCSP_USE_NONCE), WOLFSSL_SUCCESS);

    /* status_type == OCSP: first operand false, short-circuits past the
     * second - independence for the first operand. */
    ExpectIntEQ(wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP,
                WOLFSSL_CSR2_OCSP_USE_NONCE), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_SupportExtensions() - "return ssl && (IsTLS(ssl) ||
 * ssl->version.major == DTLS_MAJOR);" reached through the WOLFSSL_TEST_VIS
 * TLSX_WriteRequest(), which calls it as its leading guard.
 *
 * With WOLFSSL_DTLS defined (as it is in this build), IsTLS() itself already
 * returns true for ssl->version.major == DTLS_MAJOR (it has its own
 * "#ifdef WOLFSSL_DTLS if (ssl->version.major == DTLS_MAJOR) return 1;"
 * check). So the third operand here can only be evaluated (IsTLS() false)
 * when major is neither a valid TLS major/minor pair nor DTLS_MAJOR - and in
 * that same case the third operand's own check of major == DTLS_MAJOR is
 * false too. The third operand's true side is therefore contradicted by
 * IsTLS()'s postcondition in this build and is excluded (family 4); only its
 * (always-false-when-reached) value is exercised below, alongside the first
 * and second operands. */
int test_TLSX_SupportExtensions_bounds(void)
{
#if !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte out[512];
    word32 offset = 0;

    /* ssl == NULL: the leading operand alone decides the result. */
    ExpectIntEQ(TLSX_WriteRequest(NULL, out, client_hello, &offset), 0);

    /* A live ssl object: IsTLS(ssl) true (real major/minor), so ssl &&
     * IsTLS(ssl) is already true and the third operand is never reached -
     * independence for the first and second operands. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);

    /* Corrupt ssl->version.major to a value IsTLS() does not recognize
     * (neither SSLv3_MAJOR nor DTLS_MAJOR): IsTLS(ssl) is now false, and the
     * third operand - checking that very same field for DTLS_MAJOR - is
     * false too. This is the only way to make IsTLS(ssl) false at all: every
     * ssl created through a real method sets a recognized major/minor. */
    if (ssl != NULL) {
        ssl->version.major = 0;
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_2_MINOR;
    }

    /* TLSX_WriteRequest()'s own leading guard is
     * "!TLSX_SupportExtensions(ssl) || output == NULL": a supported ssl with
     * output == NULL exercises the second operand independently of the
     * ssl == NULL call above. */
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, NULL, client_hello, &offset), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_EarlyData_Use() - "extension->val = (WOLFSSL_IS_QUIC(ssl) &&
 * is_response && maxSz > 0) ? WOLFSSL_MAX_32BIT : maxSz;" - this build has no
 * WOLFSSL_QUIC, so WOLFSSL_IS_QUIC() expands to the literal 0: the first
 * operand is a compile-time constant false in every translation unit of this
 * binary. Because of the left-to-right && short circuit, is_response and
 * maxSz > 0 can never be evaluated either - all three operands of this
 * decision are unreachable in this configuration. Excluded (family 3: fixed
 * by the branch/config that reaches it).
 * No test body: nothing to drive. */

/* ---------------------------------------------------------------------- */
/* TLSX_CSR2_InitRequests(), TLSX_CSR2_ForceRequest(), TLSX_CSR_GetRequest_ex()
 * are WOLFSSL_LOCAL with no public wrapper; each is unit-tested directly by
 * building the minimal extension/context state each one dereferences. */
int test_TLSX_CSR2_InitRequests_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_CSR2_REQUESTS) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    DecodedCert cert;
    TLSX* ext = NULL;
    CertificateStatusRequestItemV2* csr2;

    XMEMSET(&cert, 0, sizeof(cert));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(TLSX_UseCertificateStatusRequestV2(&ssl->extensions,
                WOLFSSL_CSR2_OCSP, 0, ssl->heap, ssl->devId), WOLFSSL_SUCCESS);
    ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
    ExpectNotNull(ext);

    if (ext != NULL) {
        csr2 = (CertificateStatusRequestItemV2*)ext->data;

        /* isPeer == 0: "!isPeer" true, short-circuits past requests != 0. */
        ExpectIntEQ(TLSX_CSR2_InitRequests(ssl->extensions, &cert, 0,
                    ssl->heap), 0);

        /* isPeer == 1, requests == 0: both operands false, falls through to
         * build the request from the (empty) DecodedCert. */
        ExpectIntEQ(TLSX_CSR2_InitRequests(ssl->extensions, &cert, 1,
                    ssl->heap), 0);
        ExpectIntEQ(csr2->requests, 1);

        /* isPeer == 1, requests != 0: "!isPeer" false, "requests != 0"
         * true - independence for the second operand. */
        ExpectIntEQ(TLSX_CSR2_InitRequests(ssl->extensions, &cert, 1,
                    ssl->heap), 0);
        ExpectIntEQ(csr2->requests, 1);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

int test_TLSX_CSR2_ForceRequest_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_CSR2_REQUESTS) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext = NULL;
    CertificateStatusRequestItemV2* csr2;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(TLSX_UseCertificateStatusRequestV2(&ssl->extensions,
                WOLFSSL_CSR2_OCSP, 0, ssl->heap, ssl->devId), WOLFSSL_SUCCESS);
    ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
    ExpectNotNull(ext);

    if (ext != NULL) {
        csr2 = (CertificateStatusRequestItemV2*)ext->data;

        /* ocspEnabled false: whole AND is false regardless of requests. */
        SSL_CM(ssl)->ocspEnabled = 0;
        csr2->requests = 1;
        ExpectIntEQ(TLSX_CSR2_ForceRequest(ssl), WC_NO_ERR_TRACE(OCSP_LOOKUP_FAIL));

        /* ocspEnabled true, requests == 0: first operand true, second
         * false - independence for the second operand's false side. */
        SSL_CM(ssl)->ocspEnabled = 1;
        csr2->requests = 0;
        ExpectIntEQ(TLSX_CSR2_ForceRequest(ssl), WC_NO_ERR_TRACE(OCSP_LOOKUP_FAIL));

        /* ocspEnabled true, requests >= 1: both operands true, so the
         * lookup runs. No responder is configured on this CertManager, so
         * CheckOcspRequest() reports BAD_FUNC_ARG on its own ocsp == NULL
         * guard rather than reaching the network. */
        csr2->requests = 1;
        ExpectIntEQ(TLSX_CSR2_ForceRequest(ssl), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

int test_TLSX_CSR_GetRequest_ex_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) &&  defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A TLS 1.2-only method keeps IsAtLeastTLSv1_3(csr->ssl->version) false,
     * so the idx == 0 branch below is deterministic without negotiating a
     * version first. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* csr == NULL: no TLSX_STATUS_REQUEST extension present at all. */
    ExpectNull(TLSX_CSR_GetRequest_ex(ssl->extensions, 0));

    /* csr != NULL, csr->ssl == NULL - reachable only by calling the
     * WOLFSSL_LOCAL constructor directly with a NULL ssl; the public
     * wrapper (wolfSSL_UseOCSPStapling -> TLSX_UseCertificateStatusRequest)
     * always forwards a live ssl pointer, so this half needs the direct
     * call too. */
    ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                WOLFSSL_CSR_OCSP, 0, NULL, ssl->heap, ssl->devId),
                WOLFSSL_SUCCESS);
    ExpectNull(TLSX_CSR_GetRequest_ex(ssl->extensions, 0));

    /* csr != NULL, csr->ssl != NULL. */
    TLSX_Remove(&ssl->extensions, TLSX_STATUS_REQUEST, ssl->heap);
    ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                WOLFSSL_SUCCESS);
    /* Pre-TLS1.3 ssl: idx == 0 returns the sole ocsp[0] slot. */
    ExpectNotNull(TLSX_CSR_GetRequest_ex(ssl->extensions, 0));
    ExpectNull(TLSX_CSR_GetRequest_ex(ssl->extensions, 1));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}


/* ---------------------------------------------------------------------- */
/* wolfSSL_make_eap_keys() - "ssl == NULL || ssl->arrays == NULL". ssl->arrays
 * is allocated lazily by the handshake and is still NULL on a freshly
 * created object, so both operands are reachable without completing a
 * handshake at all. */
int test_wolfSSL_make_eap_keys_bounds(void)
{
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TEST_STATIC_BUILD)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte key[32];

    /* ssl == NULL. */
    ExpectIntEQ(wolfSSL_make_eap_keys(NULL, key, sizeof(key), "label"),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* ssl != NULL, ssl->arrays != NULL: wolfSSL_new() -> ReinitSSL() already
     * allocated it, so this is the default state. */
    ExpectNotNull(ssl->arrays);
    ssl->specs.mac_algorithm = sha256_mac;
    ExpectIntEQ(wolfSSL_make_eap_keys(ssl, key, sizeof(key), "label"), 0);

    /* ssl != NULL, ssl->arrays == NULL: FreeArrays() is what clears it in
     * real use, once the handshake has finished with the randoms/master
     * secret and no longer needs them - called directly here (WOLFSSL_LOCAL)
     * rather than running a full handshake just to reach the same state. */
    FreeArrays(ssl, 0);
    ExpectNull(ssl->arrays);
    ExpectIntEQ(wolfSSL_make_eap_keys(ssl, key, sizeof(key), "label"),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* wolfSSL_SetTlsHmacInner() - "ssl == NULL || inner == NULL", then
 * "content == dtls12_cid || (ssl->options.dtls && DtlsGetCidTxSize(ssl) >
 * 0)". Both are public (WOLFSSL_API) and reachable directly. */
int test_wolfSSL_SetTlsHmacInner_bounds(void)
{
#if !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_AEAD_ONLY) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte inner[WOLFSSL_TLS_HMAC_INNER_SZ];

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* ssl == NULL. */
    ExpectIntEQ(wolfSSL_SetTlsHmacInner(NULL, inner, 10, application_data, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ssl != NULL, inner == NULL. */
    ExpectIntEQ(wolfSSL_SetTlsHmacInner(ssl, NULL, 10, application_data, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* content == dtls12_cid: true on its own, regardless of ssl->options.
     * dtls, on a plain TLS object. */
    ExpectIntEQ(wolfSSL_SetTlsHmacInner(ssl, inner, 10, dtls12_cid, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* content != dtls12_cid, ssl->options.dtls == 0: both operands of the
     * inner OR are false without evaluating DtlsGetCidTxSize() at all. */
    ExpectIntEQ(wolfSSL_SetTlsHmacInner(ssl, inner, 10, application_data, 0),
                0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

/* DtlsGetCidTxSize() is WOLFSSL_LOCAL, so this block only builds when the
 * test links against the static library. */
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_DTLS) && \
    defined(WOLFSSL_DTLS_CID) && defined(WOLFSSL_DTLS13)
    /* content != dtls12_cid, ssl->options.dtls == 1, no CID negotiated:
     * independence for the second operand while the third is false. */
    ctx = NULL;
    ssl = NULL;
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_SetTlsHmacInner(ssl, inner, 10, application_data, 0),
                0);

    /* content != dtls12_cid, ssl->options.dtls == 1, a tx CID configured:
     * independence for the third operand. */
    ExpectIntEQ(wolfSSL_dtls_cid_use(ssl), WOLFSSL_SUCCESS);
    {
        byte cid[4] = { 1, 2, 3, 4 };
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl, cid, sizeof(cid)),
                    WOLFSSL_SUCCESS);
    }
    if (DtlsGetCidTxSize(ssl) > 0) {
        ExpectIntEQ(wolfSSL_SetTlsHmacInner(ssl, inner, 10, application_data,
                    0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* BuildTlsHandshakeHash() - the leading 4-operand NULL/size guard has no
 * public wrapper, so it is unit-tested directly (WOLFSSL_TEST_STATIC_BUILD).
 * The mac_algorithm <= sha256_mac || mac_algorithm == blake2b_mac branch
 * (choosing the SHA-256 handshake hash) only needs its second operand:
 * mac_algorithm <= sha256_mac already has an independence pair elsewhere in
 * the suite; blake2b_mac (8) is above sha256_mac (4) in enum wc_MACAlgorithm
 * ordering regardless of whether HAVE_BLAKE2B is built, so setting
 * specs.mac_algorithm to it exercises the SHA-256 path through the second
 * operand without requiring BLAKE2b support. */
int test_BuildTlsHandshakeHash_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_SHA256)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte hash[WC_MAX_DIGEST_SIZE];
    word32 hashLen;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(InitHandshakeHashes(ssl), 0);

    /* ssl == NULL. */
    hashLen = sizeof(hash);
    ExpectIntEQ(BuildTlsHandshakeHash(NULL, hash, &hashLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* hash == NULL. */
    hashLen = sizeof(hash);
    ExpectIntEQ(BuildTlsHandshakeHash(ssl, NULL, &hashLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* hashLen == NULL. */
    ExpectIntEQ(BuildTlsHandshakeHash(ssl, hash, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* *hashLen < HSHASH_SZ. */
    hashLen = 1;
    ExpectIntEQ(BuildTlsHandshakeHash(ssl, hash, &hashLen),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* All valid, mac_algorithm <= sha256_mac (sha256_mac itself): the
     * already-covered independence pair for the first operand. */
    ssl->specs.mac_algorithm = sha256_mac;
    hashLen = sizeof(hash);
    ExpectIntEQ(BuildTlsHandshakeHash(ssl, hash, &hashLen), 0);
    ExpectIntEQ(hashLen, WC_SHA256_DIGEST_SIZE);

    /* mac_algorithm == blake2b_mac: first operand false (8 > sha256_mac's
     * 4), second operand true - still routes to the SHA-256 hash object
     * (populated regardless of the negotiated MAC, for exactly this kind of
     * lookup), not to an unbuilt BLAKE2b one. */
    ssl->specs.mac_algorithm = blake2b_mac;
    hashLen = sizeof(hash);
    ExpectIntEQ(BuildTlsHandshakeHash(ssl, hash, &hashLen), 0);
    ExpectIntEQ(hashLen, WC_SHA256_DIGEST_SIZE);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLS_hmac() / Hmac_UpdateFinal_CT() - driven directly through ssl->hmac(),
 * which InitSSL() points at TLS_hmac() by default whenever TLS 1.2 (or
 * older) CBC-MAC support is built, before any handshake runs (see the
 * existing test_tls_hmac_size_overflow() in test_hmac.c for the same
 * pattern). No live connection is needed: the size-overflow guard and the
 * verify/padSz dispatch are pure argument checks over ssl->specs and the
 * caller-supplied lengths. */
int test_TLS_hmac_bounds(void)
{
#if !defined(NO_HMAC) && !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_TLS) &&  defined(NO_OLD_TLS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_SHA256) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte digest[WC_MAX_DIGEST_SIZE];
    byte in[256];

    XMEMSET(in, 0xAA, sizeof(in));
    XMEMSET(digest, 0, sizeof(digest));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectNotNull(ssl->hmac);

    if (EXPECT_SUCCESS()) {
        ssl->specs.mac_algorithm = sha256_mac;
        ssl->specs.hash_size = WC_SHA256_DIGEST_SIZE;

        /* "verify && padSz >= 0" (first occurrence, guards the size-overflow
         * pre-check): verify == 0 - first operand false, independence
         * against the verify == 1 calls below. Neither the pre-check nor
         * the second occurrence at line ~1465 are reached; the plain
         * wc_HmacUpdate/Final path below runs instead. */
        ExpectIntEQ(ssl->hmac(ssl, digest, in, 50, 10, application_data, 0,
                    PEER_ORDER), 0);

        /* verify == 1, padSz == -1: second operand false - independence for
         * the second operand of the same guard, and for the second
         * occurrence at line ~1465 (both are skipped, same as above). */
        ExpectIntEQ(ssl->hmac(ssl, digest, in, 50, -1, application_data, 1,
                    PEER_ORDER), 0);

        /* verify == 1, padSz == 10: both operands true. Reaches the
         * overflow pre-check with ordinary values (no overflow) and then
         * the constant-time verify path (Hmac_UpdateFinal_CT(), and within
         * it Hmac_OuterHash() - both only reachable from here). */
        ExpectIntEQ(ssl->hmac(ssl, digest, in, 50, 10, application_data, 1,
                    PEER_ORDER), 0);

        /* Overflow in the first addition (sz + hashSz): sz alone is already
         * within 32 of the word32 max. */
        ExpectIntEQ(ssl->hmac(ssl, digest, in,
                    (word32)(WOLFSSL_MAX_32BIT - 10), 0, application_data, 1,
                    PEER_ORDER), WC_NO_ERR_TRACE(BUFFER_E));

        /* First addition safe (sz + hashSz == WOLFSSL_MAX_32BIT - 5), but
         * adding padSz overflows - independence for the second addition,
         * with the first false. */
        ExpectIntEQ(ssl->hmac(ssl, digest, in,
                    (word32)(WOLFSSL_MAX_32BIT - 32 - 5), 10,
                    application_data, 1, PEER_ORDER),
                    WC_NO_ERR_TRACE(BUFFER_E));

        /* First two additions land exactly on WOLFSSL_MAX_32BIT (sz +
         * hashSz(32) + padSz(0)), so neither overflows, but the final "+ 1"
         * does - independence for the third addition, with the first two
         * false. */
        ExpectIntEQ(ssl->hmac(ssl, digest, in,
                    (word32)(WOLFSSL_MAX_32BIT - 32), 0, application_data, 1,
                    PEER_ORDER), WC_NO_ERR_TRACE(BUFFER_E));

#ifdef WOLFSSL_TEST_STATIC_BUILD
        /* Hmac_UpdateFinal_CT()'s own "macLen <= 0" guard: force hash_size
         * to 0 for this call only. wc_HmacSetKey() accepts a zero-length
         * key (RFC 2104 permits an empty key), so ret stays 0 and this
         * still reaches the constant-time path with macLen == 0.
         *
         * The guard's other half, "macLen > sizeof(hmac->innerHash)"
         * (innerHash is WC_MAX_DIGEST_SIZE bytes), is excluded: macLen is
         * always ssl->specs.hash_size or TRUNCATED_HMAC_SZ, and hash_size
         * is also the key length wc_HmacSetKey() reads out of
         * ssl->keys.*_write_MAC_secret, a fixed WC_MAX_DIGEST_SIZE-byte
         * array - so any hash_size big enough to take this branch would
         * already have made wc_HmacSetKey() (immediately above, in the same
         * call) read out of bounds. Every real MAC algorithm's digest size
         * fits within WC_MAX_DIGEST_SIZE by construction, so this half is
         * contradicted by that shared field's own bound (family 4). */
        ssl->specs.hash_size = 0;
        ExpectIntEQ(ssl->hmac(ssl, digest, in, 50, 0, application_data, 1,
                    PEER_ORDER), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ssl->specs.hash_size = WC_SHA256_DIGEST_SIZE;
#endif
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_ALPN_GetSize() (reached through the WOLFSSL_TEST_VIS
 * TLSX_GetRequestSize()) - "alpnSz == 0 && extension->data != NULL" is the
 * 16-bit overflow guard on the accumulated ALPN protocol list size. The only
 * producer of a TLSX_APPLICATION_LAYER_PROTOCOL extension is TLSX_UseALPN(),
 * which always supplies a non-NULL ALPN entry before pushing - so
 * extension->data is never NULL while this extension exists, and the second
 * operand is true on every real execution that reaches it (which only
 * happens when the first operand is already true, i.e. on overflow).
 * Excluded (family 4: contradicted by TLSX_UseALPN()'s own postcondition);
 * only the first operand is driven here. WOLFSSL_MAX_ALPN_NUMBER (257)
 * entries of the maximum WOLFSSL_MAX_ALPN_PROTO_NAME_LEN (255) push the
 * running total past 0xFFFF (257 * 256 + 2 == 65794). */
int test_TLSX_ALPN_GetSize_overflow(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_ALPN) &&  !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char name[WOLFSSL_MAX_ALPN_PROTO_NAME_LEN];
    word32 len;
    int i;

    XMEMSET(name, 'a', sizeof(name));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* alpnSz != 0 (no overflow): first operand false, short-circuits past
     * the second - independence for the first operand, paired against the
     * overflow case below. */
    len = 0;
    ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"http/1.1", 8,
                WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &len), 0);

    wolfSSL_free(ssl);
    ssl = NULL;
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    for (i = 0; EXPECT_SUCCESS() && i < WOLFSSL_MAX_ALPN_NUMBER; i++) {
        ExpectIntEQ(TLSX_UseALPN(&ssl->extensions, name, sizeof(name),
                    WOLFSSL_ALPN_FAILED_ON_MISMATCH, ssl->heap),
                    WOLFSSL_SUCCESS);
    }
    len = 0;
    ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &len),
                WC_NO_ERR_TRACE(LENGTH_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_Cookie_GetSize() / TLSX_Cookie_Write() - "msgType == client_hello ||
 * msgType == hello_retry_request", reached through the WOLFSSL_TEST_VIS
 * TLSX_GetRequestSize()/TLSX_WriteRequest() by passing the message type
 * directly: the dispatch inside TLSX_GetSize()/TLSX_Write() only looks at
 * the msgType argument (and, once the extension already exists,
 * extension->resp for the "is this message type getting a response-only
 * extension" skip), not at which top-level wrapper made the call. */
int test_TLSX_Cookie_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) &&  defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext = NULL;
    byte cookieData[4] = { 1, 2, 3, 4 };
    byte out[64];
    word32 offset;
    word32 pLen;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(TLSX_Cookie_Use(ssl, cookieData, sizeof(cookieData), NULL, 0,
                0, &ssl->extensions), 0);

    /* msgType == client_hello: first operand true. isRequest is true for
     * client_hello, so the extension is included regardless of resp. Drives
     * both TLSX_Cookie_GetSize() (via TLSX_GetRequestSize()) and
     * TLSX_Cookie_Write() (via TLSX_WriteRequest()) - the two functions have
     * the same guard at the same relative position, reached the same way. */
    pLen = 0;
    ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &pLen), 0);
    ExpectTrue(pLen > OPAQUE16_LEN);
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
    ExpectTrue(offset > OPAQUE16_LEN);

    /* msgType == hello_retry_request: second operand true, first false -
     * independence for the second operand. hello_retry_request is not
     * "isRequest" (only client_hello/certificate_request are), so resp must
     * be set for TLSX_GetSize()/TLSX_Write() to not skip the extension. */
    ext = TLSX_Find(ssl->extensions, TLSX_COOKIE);
    ExpectNotNull(ext);
    if (ext != NULL)
        ext->resp = 1;
    pLen = 0;
    ExpectIntEQ(TLSX_GetRequestSize(ssl, hello_retry_request, &pLen), 0);
    ExpectTrue(pLen > OPAQUE16_LEN);
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, out, hello_retry_request, &offset), 0);
    ExpectTrue(offset > OPAQUE16_LEN);

    /* msgType == server_hello: both operands false - independence for the
     * second operand's false side, paired against the hello_retry_request
     * case above (both with resp == 1, so the extension is not skipped
     * before TLSX_Cookie_GetSize()/_Write() run). */
    pLen = 0;
    ExpectIntEQ(TLSX_GetRequestSize(ssl, server_hello, &pLen),
                WC_NO_ERR_TRACE(SANITY_MSG_E));
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, out, server_hello, &offset),
                WC_NO_ERR_TRACE(SANITY_MSG_E));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_CSR_GetSize_ex() / TLSX_CSR_Write_ex() - both share the same
 * response-side shape:
 *   if (!isRequest && csr->ssl != NULL && IsAtLeastTLSv1_3(csr->ssl->version)) {
 *       if (csr->ssl != NULL && SSL_CM(csr->ssl) != NULL &&
 *               SSL_CM(csr->ssl)->ocsp_stapling != NULL &&
 *               SSL_CM(csr->ssl)->ocsp_stapling->statusCb != NULL) {
 *           <use the status callback response>
 *       }
 *       <use csr->responses[idx] directly>
 *   }
 *
 * In TLSX_CSR_Write_ex() specifically, the leading "!isRequest" operand of
 * the outer decision is unreachable as false: the function's own
 * "#ifndef NO_WOLFSSL_CLIENT if (isRequest) { ...; return (int)offset; }"
 * block (present in this build) always returns before this line whenever
 * isRequest is true, so control only ever reaches the response-side "if"
 * with isRequest already false. Excluded (family 3: fixed by the branch
 * that reaches it). TLSX_CSR_GetSize_ex()'s twin block has no such
 * unconditional return ahead of it (the request-side "if (isRequest) {...}"
 * just falls through), so its !isRequest/csr->ssl!=NULL operands are
 * independently reachable there - which is exactly why the worklist only
 * carries TLSX_CSR_GetSize_ex's third operand (the version check) and not
 * its first two.
 *
 * The nested decision's leading "csr->ssl != NULL" (in both functions) is
 * likewise fixed true: it re-tests the same csr->ssl pointer the enclosing
 * "if" already required to be non-NULL two lines above, with no assignment
 * to csr->ssl in between. Excluded (family 3) in both functions.
 */
#ifdef TEST_TLS_BOUNDS_CSR_STATUS_CB
TEST_TLS_BOUNDS_UNUSED
static int test_TLSX_CSR_write_getsize_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl; (void)arg;
    return WOLFSSL_OCSP_STATUS_CB_OK;
}
#endif

int test_TLSX_CSR_write_getsize_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_CSR_STATUS_CB) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext = NULL;
    CertificateStatusRequest* csr = NULL;
    WOLFSSL_CERT_MANAGER* origCM = NULL;
    ProtocolVersion origVersion;
    byte out[OPAQUE8_LEN + OPAQUE24_LEN + 8];
    word16 sz;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                WOLFSSL_SUCCESS);
    ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST));
    if (ext != NULL)
        csr = (CertificateStatusRequest*)ext->data;
    ExpectNotNull(csr);

    if (csr != NULL) {
        origVersion = ssl->version;

        /* Outer decision, operand 1 (csr->ssl != NULL): false side. Short-
         * circuits before the version check (csr->ssl->version) is ever
         * dereferenced, so this is safe even though ssl is TLS 1.3. Only
         * TLSX_CSR_Write_ex() needs this pair (TLSX_CSR_GetSize_ex()'s
         * operand 1 is already covered elsewhere). */
        csr->ssl = NULL;
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0), 0);
        csr->ssl = ssl;

        /* Outer decision, operand 2 (IsAtLeastTLSv1_3): false side, with
         * operand 1 true (csr->ssl == ssl, unchanged). Paired against the
         * TLS 1.3 calls below (operand 2 true). */
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_2_MINOR;
        ExpectIntEQ(TLSX_CSR_GetSize_ex(csr, 0, 0), 0);
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0), 0);
        ssl->version = origVersion;

        /* Nested decision, operand 1 (SSL_CM(csr->ssl) != NULL): false
         * side. Outer decision is true throughout (TLS 1.3, csr->ssl set),
         * so this also covers operand 2 of the outer decision (true side). */
        origCM = ssl->ctx->cm;
        ssl->ctx->cm = NULL;
        ExpectIntEQ(TLSX_CSR_GetSize_ex(csr, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);
        ssl->ctx->cm = origCM;

        /* Nested decision, operand 2 (ocsp_stapling != NULL): false side,
         * operand 1 now true (cm restored, no stapling object allocated
         * yet). */
        ExpectIntEQ(TLSX_CSR_GetSize_ex(csr, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);

        /* Nested decision, operand 3 (statusCb != NULL): false side,
         * operands 1 and 2 now true (stapling object allocated, no
         * callback registered yet). */
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_CSR_GetSize_ex(csr, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN);

        /* Nested decision, all operands true: routes through
         * TLSX_CSR_WriteWithStatusCB() / the status-callback size path.
         * TLSX_CSR_WriteWithStatusCB()'s own leading NULL guards
         * ("ssl == NULL || SSL_CM(ssl) == NULL" and "ocsp == NULL ||
         * ocsp->statusCb == NULL") are unreachable as true: it has exactly
         * one caller (this line), which has just proven all four of those
         * facts true. Excluded (family 1). Its response==NULL/respSz==0
         * guard is not established by the caller and is driven below. */
        ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(ctx,
                    test_TLSX_CSR_write_getsize_status_cb), WOLFSSL_SUCCESS);

        /* response == NULL (respSz == 0 too, both untouched): operand 0
         * of the response/respSz guard true. */
        ssl->ocspCsrResp[0].buffer = NULL;
        ssl->ocspCsrResp[0].length = 0;
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* response != NULL, respSz == 0: operand 0 false, operand 1 true -
         * independence for operand 1. */
        ssl->ocspCsrResp[0].buffer = out;
        ssl->ocspCsrResp[0].length = 0;
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* response != NULL, respSz > 0: both operands false - the write
         * succeeds. Also exercises TLSX_CSR_GetSize_ex()'s status-callback
         * size path (not itself an open condition, but the same call site). */
        ssl->ocspCsrResp[0].length = 4;
        sz = TLSX_CSR_GetSize_ex(csr, 0, 0);
        ExpectIntEQ(sz, OPAQUE8_LEN + OPAQUE24_LEN + 4);
        ExpectIntEQ(TLSX_CSR_Write_ex(csr, out, 0, 0),
                    OPAQUE8_LEN + OPAQUE24_LEN + 4);

        ssl->ocspCsrResp[0].buffer = NULL;
        ssl->ocspCsrResp[0].length = 0;
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_CSR_SetResponseWithStatusCB() - unlike TLSX_CSR_WriteWithStatusCB(),
 * this one is WOLFSSL_LOCAL (not static-in-file), so it is unit-tested
 * directly rather than only through its one real caller (SetupOcspResp() in
 * tls13.c, which - like TLSX_CSR_Write_ex() above - already guarantees
 * ssl/SSL_CM(ssl)/ocsp_stapling/statusCb are non-NULL before calling it).
 * Called directly, none of those preconditions are established, so all four
 * operands are independently reachable here. */
int test_TLSX_CSR_SetResponseWithStatusCB_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_CSR_STATUS_CB) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CERT_MANAGER* origCM = NULL;

    /* ssl == NULL: first operand of "ssl == NULL || SSL_CM(ssl) == NULL". */
    ExpectIntEQ(TLSX_CSR_SetResponseWithStatusCB(NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* ssl != NULL, SSL_CM(ssl) == NULL: second operand true, first false -
     * independence for the second operand. */
    origCM = ssl->ctx->cm;
    ssl->ctx->cm = NULL;
    ExpectIntEQ(TLSX_CSR_SetResponseWithStatusCB(ssl),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ssl->ctx->cm = origCM;

    /* ssl != NULL, SSL_CM(ssl) != NULL, ocsp == NULL (no stapling object
     * allocated yet): both operands of the first guard false, first
     * operand of the second guard ("ocsp == NULL") true. */
    ExpectIntEQ(TLSX_CSR_SetResponseWithStatusCB(ssl),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ocsp != NULL, statusCb == NULL: second operand of the second guard
     * true, first false - independence for that operand. */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(TLSX_CSR_SetResponseWithStatusCB(ssl),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Both guards false: reaches the callback itself. No status_request
     * extension is present on ssl, so the callback's WOLFSSL_OCSP_STATUS_CB_OK
     * finds nothing in ssl->ocspCsrResp to ack and returns cleanly. */
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(ctx,
                test_TLSX_CSR_write_getsize_status_cb), WOLFSSL_SUCCESS);
    ExpectIntEQ(TLSX_CSR_SetResponseWithStatusCB(ssl), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* ProcessChainOCSPRequest() - walks ssl->buffers.certChain (each entry a
 * 3-byte length followed by a DER certificate) and, for each one, builds
 * and checks an OCSP request against SSL_CM(ssl)->ocsp_stapling. Response
 * bytes below are the same "resp_cert_unknown" fixture used by
 * tests/api/test_ocsp.c (generated by create_ocsp_test_blobs.py for
 * certs/ocsp/intermediate1-ca-cert.pem against certs/ocsp/root-ca-cert.pem),
 * copied here under a local name so this file does not pull in
 * test_ocsp_test_blobs.h's non-static globals into a second translation
 * unit. */
#ifdef TEST_TLS_BOUNDS_OCSP_CHAIN
static const unsigned char csrocsp_resp_unknown[] = {
    0x30, 0x82, 0x07, 0x29, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x07, 0x22, 0x30,
    0x82, 0x07, 0x1e, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x01, 0x01, 0x04, 0x82, 0x07, 0x0f, 0x30, 0x82, 0x07, 0x0b, 0x30, 0x82,
    0x01, 0x00, 0xa1, 0x81, 0x9b, 0x30, 0x81, 0x98, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68,
    0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
    0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, 0x65,
    0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77,
    0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65,
    0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x72,
    0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x66,
    0x61, 0x63, 0x74, 0x73, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c,
    0x2e, 0x63, 0x6f, 0x6d, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x36,
    0x32, 0x34, 0x31, 0x36, 0x33, 0x37, 0x30, 0x35, 0x5a, 0x30, 0x4f, 0x30,
    0x4d, 0x30, 0x38, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
    0x04, 0x14, 0x7a, 0x34, 0xec, 0xb3, 0x2b, 0x4f, 0x1b, 0xa2, 0x72, 0x22,
    0x92, 0xa8, 0x4c, 0xc0, 0x12, 0xc7, 0x7a, 0x56, 0x9e, 0x20, 0x04, 0x14,
    0x73, 0xb0, 0x1c, 0xa4, 0x2f, 0x82, 0xcb, 0xcf, 0x47, 0xa5, 0x38, 0xd7,
    0xb0, 0x04, 0x82, 0x3a, 0x7e, 0x72, 0x15, 0x21, 0x02, 0x01, 0x01, 0x82,
    0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x36, 0x32, 0x34, 0x31,
    0x36, 0x33, 0x37, 0x30, 0x35, 0x5a, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x03, 0x82, 0x01, 0x01, 0x00,
    0x1c, 0x64, 0xcb, 0x8a, 0x8e, 0x9c, 0x63, 0x4e, 0xd5, 0x6d, 0xbc, 0xac,
    0x92, 0x78, 0x02, 0xf2, 0xb5, 0x40, 0x93, 0x38, 0x5d, 0x28, 0x6c, 0x05,
    0x57, 0x81, 0xf3, 0x8b, 0xd7, 0x0e, 0xbb, 0xfc, 0xee, 0x63, 0x9a, 0x4a,
    0x02, 0x04, 0xd9, 0xa2, 0x61, 0x0f, 0x8e, 0x44, 0xb6, 0x48, 0xf4, 0xfe,
    0x23, 0xab, 0xd6, 0x0c, 0x92, 0xe3, 0x8e, 0xcf, 0x36, 0xf1, 0x7b, 0x6c,
    0xf7, 0x99, 0xb0, 0x83, 0xa0, 0xbd, 0x66, 0x98, 0x02, 0xb0, 0x4b, 0x7a,
    0xf7, 0x77, 0x6e, 0x47, 0xa4, 0xd0, 0x27, 0x2e, 0xa0, 0xbd, 0xb0, 0xa7,
    0xfa, 0xb6, 0x8d, 0x84, 0xef, 0x3a, 0x38, 0xa3, 0x6b, 0x26, 0x73, 0xc0,
    0xd6, 0xef, 0x2f, 0xf9, 0x1b, 0xef, 0x01, 0x2c, 0x4e, 0x36, 0x8d, 0x9b,
    0x45, 0x58, 0xb3, 0x97, 0x46, 0x9f, 0xb5, 0xd2, 0x5a, 0x7d, 0xa6, 0x47,
    0x37, 0xd6, 0xa4, 0x3b, 0x61, 0x97, 0x20, 0xd3, 0x32, 0x0e, 0x7f, 0xac,
    0x76, 0x62, 0x19, 0xab, 0x74, 0x71, 0x7b, 0x89, 0x75, 0xfa, 0x3f, 0x89,
    0xe7, 0xf2, 0x55, 0xeb, 0x32, 0xce, 0xe2, 0x55, 0x98, 0x0b, 0x67, 0x9a,
    0x94, 0x48, 0x95, 0x8e, 0xa3, 0x61, 0x8a, 0x4c, 0x2e, 0xe9, 0xbe, 0x65,
    0xe5, 0x7c, 0x9e, 0x5f, 0xcc, 0xeb, 0x74, 0xee, 0xb2, 0x59, 0x5a, 0x03,
    0xa0, 0xbd, 0xcf, 0x06, 0x95, 0x6b, 0x34, 0x47, 0x19, 0x7e, 0xd0, 0xb4,
    0xcc, 0xf6, 0xb3, 0xdc, 0x46, 0x74, 0x0a, 0x9a, 0x28, 0x57, 0xba, 0x46,
    0x6f, 0xfc, 0x24, 0xcd, 0x82, 0x20, 0x1a, 0x1c, 0x74, 0x0c, 0x37, 0x8e,
    0x22, 0x1f, 0x00, 0x9c, 0x66, 0x4f, 0xf5, 0xbb, 0xeb, 0xe1, 0x7f, 0x0e,
    0xb0, 0x39, 0xde, 0xd8, 0xf2, 0x56, 0xe0, 0xc2, 0xa2, 0x95, 0xbe, 0xad,
    0x9c, 0x10, 0x56, 0x28, 0x8e, 0x50, 0x79, 0x2f, 0xb6, 0xbf, 0x31, 0x6e,
    0x71, 0x53, 0x13, 0x63, 0xa0, 0x82, 0x04, 0xf1, 0x30, 0x82, 0x04, 0xed,
    0x30, 0x82, 0x04, 0xe9, 0x30, 0x82, 0x03, 0xd1, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x63, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x81, 0x98, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61,
    0x73, 0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74,
    0x6c, 0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x07, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e,
    0x65, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c,
    0x20, 0x72, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
    0x11, 0x66, 0x61, 0x63, 0x74, 0x73, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73,
    0x73, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36,
    0x30, 0x36, 0x31, 0x31, 0x32, 0x31, 0x34, 0x34, 0x33, 0x34, 0x5a, 0x17,
    0x0d, 0x32, 0x39, 0x30, 0x33, 0x30, 0x37, 0x32, 0x31, 0x34, 0x34, 0x33,
    0x34, 0x5a, 0x30, 0x81, 0x98, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
    0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x31, 0x10, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x77, 0x6f, 0x6c, 0x66,
    0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72, 0x69, 0x6e,
    0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f,
    0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20, 0x72, 0x6f, 0x6f, 0x74,
    0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x66, 0x61, 0x63, 0x74,
    0x73, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73, 0x6c, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
    0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xab, 0x2c,
    0xb4, 0x2f, 0x1d, 0x06, 0x09, 0xef, 0x4e, 0x29, 0x86, 0x84, 0x7e, 0xcc,
    0xbf, 0xa6, 0x79, 0x7c, 0xf0, 0xc0, 0xc1, 0x64, 0x25, 0x8c, 0x75, 0xb7,
    0x10, 0x05, 0xca, 0x48, 0x27, 0x0c, 0x0e, 0x32, 0x1c, 0xb0, 0xfe, 0x99,
    0x85, 0x39, 0xb6, 0xb9, 0xa2, 0xf7, 0x27, 0xff, 0x6d, 0x3c, 0x8c, 0x16,
    0x73, 0x29, 0x21, 0x7f, 0x8b, 0xa6, 0x54, 0x71, 0x90, 0xad, 0xcc, 0x05,
    0xb9, 0x9f, 0x15, 0xc7, 0x0a, 0x3f, 0x5f, 0x69, 0xf4, 0x0a, 0x5f, 0x8c,
    0x71, 0xb5, 0x2c, 0xbf, 0x66, 0xe2, 0x03, 0x9a, 0x32, 0xf4, 0xd2, 0xec,
    0x2a, 0x89, 0x4b, 0xf9, 0x35, 0x88, 0x14, 0x33, 0x47, 0x4e, 0x2e, 0x05,
    0x79, 0x01, 0xed, 0x64, 0x36, 0x76, 0xb9, 0xf8, 0x85, 0xcd, 0x01, 0x88,
    0xac, 0xc5, 0xb2, 0xb1, 0x59, 0xb8, 0xcd, 0x5a, 0xf4, 0x09, 0x09, 0x38,
    0x9b, 0xda, 0x5a, 0xcf, 0xce, 0x78, 0x99, 0x1f, 0x49, 0x3d, 0x41, 0xd6,
    0x06, 0x7c, 0x52, 0x99, 0xc8, 0x97, 0xd1, 0xb3, 0x80, 0x3a, 0xa2, 0x4f,
    0x36, 0xc4, 0xc5, 0x96, 0x30, 0x77, 0x31, 0x38, 0xc8, 0x70, 0xcc, 0xe1,
    0x67, 0x06, 0xb3, 0x2b, 0x2f, 0x93, 0xb5, 0x69, 0xcf, 0x83, 0x7e, 0x88,
    0x53, 0x9b, 0x0f, 0x46, 0x21, 0x4c, 0xd6, 0x05, 0x36, 0x44, 0x99, 0x60,
    0x68, 0x47, 0xe5, 0x32, 0x01, 0x12, 0xd4, 0x10, 0x73, 0xae, 0x9a, 0x34,
    0x94, 0xfa, 0x6e, 0xb8, 0x58, 0x4f, 0x7b, 0x5b, 0x8a, 0x92, 0x97, 0xad,
    0xfd, 0x97, 0xb9, 0x75, 0xca, 0xc2, 0xd4, 0x45, 0x7d, 0x17, 0x6b, 0xcd,
    0x2f, 0xf3, 0x63, 0x7a, 0x0e, 0x30, 0xb5, 0x0b, 0xa9, 0xd9, 0xa6, 0x7c,
    0x74, 0x60, 0x9d, 0xcc, 0x09, 0x03, 0x43, 0xf1, 0x0f, 0x90, 0xd3, 0xb7,
    0xfe, 0x6c, 0x9f, 0xd9, 0xcd, 0x78, 0x4b, 0x15, 0xae, 0x8c, 0x5b, 0xf9,
    0x99, 0x81, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x3a, 0x30,
    0x82, 0x01, 0x36, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0x73, 0xb0, 0x1c, 0xa4, 0x2f, 0x82, 0xcb, 0xcf,
    0x47, 0xa5, 0x38, 0xd7, 0xb0, 0x04, 0x82, 0x3a, 0x7e, 0x72, 0x15, 0x21,
    0x30, 0x81, 0xc5, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x81, 0xbd, 0x30,
    0x81, 0xba, 0x80, 0x14, 0x73, 0xb0, 0x1c, 0xa4, 0x2f, 0x82, 0xcb, 0xcf,
    0x47, 0xa5, 0x38, 0xd7, 0xb0, 0x04, 0x82, 0x3a, 0x7e, 0x72, 0x15, 0x21,
    0xa1, 0x81, 0x9e, 0xa4, 0x81, 0x9b, 0x30, 0x81, 0x98, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x57, 0x61, 0x73,
    0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x53, 0x65, 0x61, 0x74, 0x74, 0x6c,
    0x65, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07,
    0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65,
    0x65, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x0f, 0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20,
    0x72, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11,
    0x66, 0x61, 0x63, 0x74, 0x73, 0x40, 0x77, 0x6f, 0x6c, 0x66, 0x73, 0x73,
    0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x01, 0x63, 0x30, 0x0b, 0x06, 0x03,
    0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x32, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x26, 0x30,
    0x24, 0x30, 0x22, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x01, 0x86, 0x16, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x32,
    0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x32, 0x32, 0x32, 0x32,
    0x30, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x36, 0xb1, 0x86,
    0xd6, 0x72, 0xf8, 0xe7, 0x6a, 0xae, 0x43, 0xfb, 0xc0, 0xed, 0xf1, 0x36,
    0x64, 0x8a, 0xda, 0x8e, 0x5f, 0xf7, 0xc4, 0xad, 0x64, 0xc8, 0x29, 0x03,
    0x74, 0x58, 0xb0, 0x9e, 0xee, 0x41, 0x89, 0x5b, 0x2a, 0x12, 0xf4, 0x82,
    0xa4, 0x03, 0xa5, 0xf0, 0xdf, 0xa2, 0x84, 0xcb, 0x2b, 0xb3, 0x16, 0x0f,
    0xdc, 0xcf, 0xcc, 0x56, 0x99, 0x61, 0xa9, 0xf9, 0x3d, 0x3a, 0x7e, 0xe4,
    0x12, 0x43, 0xc3, 0xb1, 0x4f, 0x58, 0x26, 0x79, 0xe7, 0xe4, 0x0d, 0xa5,
    0x88, 0x3d, 0x79, 0x33, 0xa1, 0x09, 0x7d, 0x78, 0xaf, 0xbd, 0x59, 0x71,
    0x11, 0x54, 0x4a, 0xcc, 0xd6, 0xd2, 0x6d, 0x1f, 0x88, 0x27, 0xac, 0xd5,
    0xbf, 0x75, 0xfc, 0xc3, 0x05, 0x0b, 0xcd, 0xc8, 0x0e, 0x72, 0x41, 0x1d,
    0xd8, 0x68, 0x62, 0xbe, 0x94, 0xd7, 0x60, 0xbe, 0x05, 0x4a, 0x42, 0x9c,
    0x50, 0xb7, 0x45, 0x71, 0x6d, 0x83, 0x9a, 0xef, 0x08, 0x5c, 0x41, 0xdb,
    0xc8, 0x62, 0x33, 0x3c, 0x69, 0xa2, 0x8a, 0xb4, 0x0f, 0xdb, 0x65, 0xc4,
    0xb7, 0x92, 0x0a, 0x76, 0xf7, 0x55, 0x06, 0x77, 0x8c, 0xff, 0x8c, 0x84,
    0x84, 0xd9, 0xdd, 0x46, 0x11, 0x2a, 0x2d, 0x27, 0x96, 0xa7, 0xf5, 0x47,
    0xc1, 0x43, 0x4b, 0xfe, 0x53, 0xd8, 0xbe, 0x16, 0x94, 0x36, 0x0a, 0xd4,
    0xbe, 0xc3, 0x6c, 0x9b, 0x0c, 0x52, 0x31, 0x4a, 0xeb, 0x62, 0xb4, 0x81,
    0x4b, 0x2d, 0xf7, 0xf1, 0x65, 0xc1, 0xee, 0x36, 0x79, 0x19, 0xf7, 0xab,
    0x16, 0xf8, 0x38, 0xd2, 0xea, 0x87, 0x8d, 0xf8, 0xf9, 0x14, 0x82, 0xdb,
    0x67, 0xb6, 0x94, 0xa8, 0x55, 0x0b, 0x90, 0x6b, 0xaf, 0xb0, 0xe9, 0x42,
    0x64, 0x42, 0x6d, 0x2c, 0xe3, 0xf1, 0xb6, 0xe0, 0xf9, 0x58, 0xed, 0x69,
    0x66, 0x62, 0x98, 0xdc, 0x5a, 0x7b, 0xfa, 0x35, 0x5a, 0x23, 0x84, 0x91,
    0x0e,
};

enum {
    CSROCSP_MODE_UNKNOWN = 0,
    CSROCSP_MODE_LOOKUP_FAIL,
    CSROCSP_MODE_WANT_READ
};

TEST_TLS_BOUNDS_UNUSED
static int test_ProcessChainOCSPRequest_io_cb(void* ctx, const char* url,
        int urlSz, unsigned char* req, int reqSz, unsigned char** respBuf)
{
    int mode = *(int*)ctx;
    static const unsigned char garbage[] = { 0xFF, 0x00, 0x11, 0x22 };
    (void)url; (void)urlSz; (void)req; (void)reqSz;

    switch (mode) {
        case CSROCSP_MODE_UNKNOWN:
            *respBuf = (unsigned char*)csrocsp_resp_unknown;
            return (int)sizeof(csrocsp_resp_unknown);
        case CSROCSP_MODE_LOOKUP_FAIL:
            *respBuf = (unsigned char*)garbage;
            return (int)sizeof(garbage);
        case CSROCSP_MODE_WANT_READ:
        default:
            return WOLFSSL_CBIO_ERR_WANT_READ;
    }
}

/* Common setup for the "one real, matching chain entry" vectors: server1
 * (leaf) + intermediate1 (the chain entry ProcessChainOCSPRequest() will
 * process) issued off root-ca, matching the identity the csrocsp_resp_*
 * fixtures above were generated against. */
TEST_TLS_BOUNDS_UNUSED
static int test_ProcessChainOCSPRequest_setup(WOLFSSL_CTX** pctx,
        WOLFSSL** pssl, CertificateStatusRequest** pcsr, int* mode)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx,
                "./certs/ocsp/server1-chain-noroot.pem"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx,
                "./certs/ocsp/server1-key.pem", WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
                "./certs/ocsp/root-ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE |
                WOLFSSL_OCSP_NO_NONCE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://dummy.test"),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_SetOCSP_Cb(ctx, test_ProcessChainOCSPRequest_io_cb,
                NULL, (void*)mode), WOLFSSL_SUCCESS);

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                    WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST));
        if (ext != NULL)
            *pcsr = (CertificateStatusRequest*)ext->data;
    }

    *pctx = ctx;
    *pssl = ssl;
    return EXPECT_RESULT();
}
#endif

int test_ProcessChainOCSPRequest_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_OCSP_CHAIN) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    CertificateStatusRequest* csr = NULL;
    int mode;
    byte garbageThenValid[8 + 3 + 4096];
    byte intermediate1Der[4096];
    word32 interLen = 0;
    XFILE f = XBADFILE;
    DerBuffer fakeChain;

    /* chain == NULL (both certChain and certificate unset): the leading
     * "chain && chain->buffer" guard is false at its first operand, the
     * whole walk is skipped, and the function returns success with
     * nothing done. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                    WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST));
        if (ext != NULL)
            csr = (CertificateStatusRequest*)ext->data;
        /* A certificate had to be loaded for wolfSSL_new() to succeed (see
         * test_tls_bounds_load_server_cert()); clear both buffers back to
         * NULL so ProcessChainOCSPRequest() sees exactly the "chain ==
         * NULL" state under test. */
        ssl->buffers.certChain = NULL;
        ssl->buffers.certificate = NULL;
        ExpectIntEQ(ProcessChainOCSPRequest(ssl), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* chain != NULL, chain->buffer == NULL: second operand false,
     * independence from the chain == NULL vector above (first operand). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                    WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST));
        if (ext != NULL)
            csr = (CertificateStatusRequest*)ext->data;
        XMEMSET(&fakeChain, 0, sizeof(fakeChain));
        ssl->buffers.certChain = &fakeChain;
        ExpectIntEQ(ProcessChainOCSPRequest(ssl), 0);
        ssl->buffers.certChain = NULL;
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* while-loop operand 0 (ret == 0) false side: a two-entry chain whose
     * first entry is not a certificate at all, so CreateOcspRequest() fails
     * with a hard ASN.1 parse error - not one of the soft-fail codes the
     * loop body resets to 0 - while its second (valid) entry is still
     * unconsumed, forcing the while condition's re-check to see ret != 0
     * with more chain data pending. */
    ExpectNotNull(f = XFOPEN("./certs/ocsp/intermediate1-ca-cert.der", "rb"));
    if (f != XBADFILE) {
        interLen = (word32)XFREAD(intermediate1Der, 1, sizeof(intermediate1Der),
                f);
        XFCLOSE(f);
    }
    ExpectIntGT(interLen, 0);
    ExpectIntLT(interLen, sizeof(intermediate1Der));
    {
        word32 idx = 0;
        static const byte notACert[] = { 0xFF, 0xFF, 0xFF, 0xFF };

        test_tls_bounds_c32to24(sizeof(notACert), garbageThenValid + idx);
        idx += OPAQUE24_LEN;
        XMEMCPY(garbageThenValid + idx, notACert, sizeof(notACert));
        idx += sizeof(notACert);

        test_tls_bounds_c32to24(interLen, garbageThenValid + idx);
        idx += OPAQUE24_LEN;
        XMEMCPY(garbageThenValid + idx, intermediate1Der, interLen);
        idx += interLen;

        ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
        ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
        ExpectNotNull(ssl = wolfSSL_new(ctx));
        if (ssl != NULL) {
            TLSX* ext = NULL;
            ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                        WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                        WOLFSSL_SUCCESS);
            ExpectNotNull(ext = TLSX_Find(ssl->extensions,
                        TLSX_STATUS_REQUEST));
            if (ext != NULL)
                csr = (CertificateStatusRequest*)ext->data;

            XMEMSET(&fakeChain, 0, sizeof(fakeChain));
            fakeChain.buffer = garbageThenValid;
            fakeChain.length = idx;
            ssl->buffers.certChain = &fakeChain;

            /* Not zero (ASN parse error) and not one of ProcessChainOCSPRequest's
             * own soft-fail codes, so it propagates as the loop's exit ret. */
            ExpectIntNE(ProcessChainOCSPRequest(ssl), 0);
            ExpectIntNE(ProcessChainOCSPRequest(ssl),
                        WC_NO_ERR_TRACE(OCSP_CERT_UNKNOWN));
            ExpectIntNE(ProcessChainOCSPRequest(ssl),
                        WC_NO_ERR_TRACE(OCSP_LOOKUP_FAIL));
            ExpectIntNE(ProcessChainOCSPRequest(ssl),
                        WC_NO_ERR_TRACE(OCSP_NO_URL));

            ssl->buffers.certChain = NULL;
        }
        wolfSSL_free(ssl);
        ssl = NULL;
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }

    /* One real, matching chain entry (intermediate1): the while loop enters
     * (operand 0 and operand 1 both true) and, after processing the single
     * entry, exits normally with pos == chain->length (operand 1 false,
     * operand 0 still true) - independence for operand 1, paired against
     * the forced-error vector above (operand 0 false). Run three times with
     * a different responder outcome each time (a fresh CertManager each
     * time, so no cached status from one run leaks into the next), driving
     * the three-way soft-fail classification. */
    mode = CSROCSP_MODE_UNKNOWN;
    ExpectIntEQ(test_ProcessChainOCSPRequest_setup(&ctx, &ssl, &csr, &mode),
                TEST_SUCCESS);
    if (csr != NULL) {
        /* ret is OCSP_CERT_UNKNOWN: first operand of the three-way OR. */
        ExpectIntEQ(ProcessChainOCSPRequest(ssl), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    csr = NULL;

    mode = CSROCSP_MODE_LOOKUP_FAIL;
    ExpectIntEQ(test_ProcessChainOCSPRequest_setup(&ctx, &ssl, &csr, &mode),
                TEST_SUCCESS);
    if (csr != NULL) {
        /* ret is OCSP_LOOKUP_FAIL (garbage response bytes fail to decode):
         * second operand true, first false - independence for the second
         * operand. */
        ExpectIntEQ(ProcessChainOCSPRequest(ssl), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    csr = NULL;

    /* ret is OCSP_NO_URL: reached without any responder call at all, by
     * leaving the override URL unset and using a chain (server-cert.pem +
     * ca-cert.pem) whose certificates carry no OCSP responder AIA URL. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_file(ctx,
                "./certs/server-cert.pem"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx,
                "./certs/server-key.pem", WOLFSSL_FILETYPE_PEM),
                WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx,
                "./certs/ca-cert.pem", NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_NO_NONCE),
                WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                    WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST));
        if (ext != NULL)
            csr = (CertificateStatusRequest*)ext->data;
        ExpectNotNull(ssl->buffers.certChain);
        if (csr != NULL) {
            /* ret is OCSP_NO_URL: third operand true, first and second
             * false - independence for the third operand. */
            ExpectIntEQ(ProcessChainOCSPRequest(ssl), 0);
        }
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    csr = NULL;

    /* ret is OCSP_WANT_READ (via WOLFSSL_CBIO_ERR_WANT_READ from the I/O
     * callback): none of the three - the baseline all-false vector paired
     * against each of the three above. */
    mode = CSROCSP_MODE_WANT_READ;
    ExpectIntEQ(test_ProcessChainOCSPRequest_setup(&ctx, &ssl, &csr, &mode),
                TEST_SUCCESS);
    if (csr != NULL) {
        ExpectIntEQ(ProcessChainOCSPRequest(ssl),
                    WC_NO_ERR_TRACE(OCSP_WANT_READ));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_PopulateExtensions() - called directly (WOLFSSL_LOCAL), the same way
 * SendClientHello()/SendTls13ClientHello() call it before any handshake
 * bytes are produced, so a bare freshly-created ssl is exactly the state a
 * real caller reaches this function with.
 *
 * "16880:17:16880:60:0" - "if (!isServer && ssl->options.postHandshakeAuth)"
 * - is not covered here and is excluded rather than driven: it sits inside
 * "if (!isServer && IsAtLeastTLSv1_3(ssl->version)) { ... }" (opened many
 * lines above, never re-assigning isServer in between), so reaching this
 * line at all already requires isServer == 0. Its own "!isServer" operand
 * is therefore fixed true on every execution that reaches it - excluded
 * (family 3: fixed by the branch that reaches it). */
#ifdef TEST_TLS_BOUNDS_POPULATE_EXT
TEST_TLS_BOUNDS_UNUSED
static unsigned int test_TLSX_PopulateExtensions_psk_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len)
{
    int mode = *(int*)wolfSSL_get_psk_callback_ctx(ssl);
    (void)hint; (void)key_max_len;

    XSTRNCPY(identity, "id", id_max_len);
    key[0] = 0x01;

    /* mode 0: > MAX_PSK_KEY_LEN and not equal to USE_HW_PSK - both operands true.
     * mode 1: > MAX_PSK_KEY_LEN and equal to USE_HW_PSK - operand 0 true, operand
     *         1 false.
     * mode 2: <= MAX_PSK_KEY_LEN - operand 0 false, short-circuits. */
    switch (mode) {
        case 0:
            return MAX_PSK_KEY_LEN + 1;
        case 1:
            return (unsigned int)WC_NO_ERR_TRACE(USE_HW_PSK);
        default:
            return 4;
    }
}

TEST_TLS_BOUNDS_UNUSED
static unsigned int test_TLSX_PopulateExtensions_psk_tls13_cb(WOLFSSL* ssl,
        const char* hint, char* identity, unsigned int id_max_len,
        unsigned char* key, unsigned int key_max_len, const char** ciphersuite)
{
    (void)ssl; (void)hint; (void)key_max_len;
    XSTRNCPY(identity, "id", id_max_len);
    key[0] = 0x01;
    *ciphersuite = "TLS13-AES128-GCM-SHA256";
    return 4;
}
#endif

int test_TLSX_PopulateExtensions_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_POPULATE_EXT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int mode;

    /* Operand 1 of "!ssl->options.userCurves && !ssl->ctx->userCurves":
     * ssl->options.userCurves inherits from ctx->userCurves at wolfSSL_new()
     * (InitSSL()), so a ctx with a user curve list makes both true unless
     * the ssl-level copy is forced back to 0 - no public caller can produce
     * "ctx->userCurves set, ssl->options.userCurves clear" any other way. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1),
                WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(ssl->options.userCurves, 1);
        ssl->options.userCurves = 0;
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ExpectNull(TLSX_Find(ssl->extensions, TLSX_SUPPORTED_GROUPS));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* The point-format decision's four leaf conditions are
     * "(!IsAtLeastTLSv1_3(ssl->version) || ssl->options.downgrade) &&
     *  TLSX_Find(ssl->ctx->extensions, TLSX_EC_POINT_FORMATS) == NULL &&
     *  TLSX_Find(ssl->extensions, TLSX_EC_POINT_FORMATS) == NULL"
     * (operand indices 0-3); the worklist's ":2" is the ctx-level Find, not
     * the ssl-level one (index 3, already paired elsewhere). TLS 1.2 keeps
     * operand 0 true throughout; ssl->extensions is left without the
     * extension in both vectors below so operand 3 stays fixed true while
     * only the ctx-level Find (operand 2) is flipped. */
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* ctx-level Find != NULL: operand 2 false. */
        ExpectIntEQ(TLSX_UsePointFormat(&ssl->ctx->extensions,
                    WOLFSSL_EC_PF_UNCOMPRESSED, ssl->ctx->heap),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ExpectNull(TLSX_Find(ssl->extensions, TLSX_EC_POINT_FORMATS));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* ctx-level Find == NULL (default, fresh ctx): operand 2 true -
     * independence for operand 2, paired against the vector above. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    ExpectNotNull(TLSX_Find(ssl->extensions, TLSX_EC_POINT_FORMATS));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

    /* Operand 1 of "ssl->options.resuming && ssl->session->namedGroup != 0":
     * resuming fixed true, namedGroup flipped. A default (non-resuming) call
     * is the false/false pair already exercised in ordinary handshake tests
     * elsewhere; this isolates the second operand specifically. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ssl->options.resuming = 1;
        ssl->session->namedGroup = 0;
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ssl->session->namedGroup = WOLFSSL_ECC_SECP256R1;
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ssl->options.resuming = 0;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#ifdef HAVE_SESSION_TICKET
    /* Operand 1 of "ssl->options.resuming && ssl->session->ticketLen > 0":
     * resuming fixed true, ticketLen flipped. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte ticket[4] = { 1, 2, 3, 4 };

        ssl->options.resuming = 1;
        ssl->session->ticketLen = 0;
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);

        XMEMCPY(ssl->session->ticket, ticket, sizeof(ticket));
        ssl->session->ticketLen = sizeof(ticket);
        /* SetCipherSpecs(ssl) (reached because ticketLen > 0) needs a
         * suite it recognizes; a fresh session's cipherSuite0/cipherSuite
         * default to 0, which is not one. */
        ssl->session->cipherSuite0 = TLS13_BYTE;
        ssl->session->cipherSuite = TLS_AES_128_GCM_SHA256;
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ssl->options.resuming = 0;
        ssl->session->ticketLen = 0;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_SESSION_TICKET */

    /* Operand 1 of "client_psk_cb != NULL || client_psk_tls13_cb != NULL":
     * operand 0 fixed false (no client_psk_cb), operand 1 flipped true by
     * registering a tls13 callback that reports "no key available" (a
     * 0-length key), which OPENSSL_EXTRA would treat specially but this
     * build (no OPENSSL_EXTRA) routes through the same
     * "> MAX_PSK_KEY_LEN" guard as any other size, taking its false side. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        wolfSSL_set_psk_client_tls13_callback(ssl,
                test_TLSX_PopulateExtensions_psk_tls13_cb);
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Both operands of "psk_keySz > MAX_PSK_KEY_LEN" and "not equal to USE_HW_PSK",
     * reached through the plain client_psk_cb path. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));

#ifndef OPENSSL_EXTRA
    /* An over-long key is rejected with PSK_KEY_ERROR. Under OPENSSL_EXTRA the
     * assignment is compiled out and the handshake carries on with a key size
     * larger than the buffer holding it, so this case is not driven there. */
    mode = 0;
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        wolfSSL_set_psk_client_callback(ssl,
                test_TLSX_PopulateExtensions_psk_cb);
        wolfSSL_set_psk_callback_ctx(ssl, &mode);
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0),
                    WC_NO_ERR_TRACE(PSK_KEY_ERROR));
    }
    wolfSSL_free(ssl);
#endif

    mode = 1;
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        wolfSSL_set_psk_client_callback(ssl,
                test_TLSX_PopulateExtensions_psk_cb);
        wolfSSL_set_psk_callback_ctx(ssl, &mode);
        /* Operand 0 true, operand 1 false - independence for operand 1. */
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    }
    wolfSSL_free(ssl);

    mode = 2;
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        wolfSSL_set_psk_client_callback(ssl,
                test_TLSX_PopulateExtensions_psk_cb);
        wolfSSL_set_psk_callback_ctx(ssl, &mode);
        /* Operand 0 false - independence for operand 0. */
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    }
    wolfSSL_free(ssl);

    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_PopulateSupportedGroups() is static-in-file, reached only through
 * TLSX_PopulateExtensions(). Its ML-KEM blocks all share
 * "IsAtLeastTLSv1_3(ssl->version) && TLSX_IsMlKemGroupSupported(ssl->options.side)";
 * the worklist carries only the second operand (the first already has a
 * pair elsewhere). TLSX_IsMlKemGroupSupported() is:
 *     if (side == WOLFSSL_CLIENT_END) return <MLKEM_CLIENT_SUPPORT ? 1 : 0>;
 *     else if (side == WOLFSSL_SERVER_END) return <MLKEM_SERVER_SUPPORT ? 1 : 0>;
 *     else return <MLKEM_CLIENT_SUPPORT || MLKEM_SERVER_SUPPORT ? 1 : 0>;
 * and this build has both WOLFSSL_HAVE_MLKEM_CLIENT_SUPPORT and
 * WOLFSSL_HAVE_MLKEM_SERVER_SUPPORT defined (neither
 * WOLFSSL_MLKEM_NO_MAKE_KEY/_NO_DECAPSULATE/_NO_ENCAPSULATE is set) - so
 * every one of its three branches returns 1, for every possible byte value
 * of ssl->options.side, not just WOLFSSL_CLIENT_END/_SERVER_END/_NEITHER_END.
 * Confirmed by direct call: TLSX_IsMlKemGroupSupported(WOLFSSL_NEITHER_END)
 * returns 1 here, not 0. There is no side value - real or corrupted - that
 * makes this operand false in this build. Excluded (family 4: contradicted
 * by TLSX_IsMlKemGroupSupported()'s own postcondition under this build's
 * feature set). */
int test_TLSX_PopulateSupportedGroups_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SUPPORTED_CURVES) &&  defined(WOLFSSL_HAVE_MLKEM_CLIENT_SUPPORT) && !defined(WOLFSSL_NO_ML_KEM) &&  !defined(NO_DH) && defined(HAVE_FFDHE_2048) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* Default client: side == WOLFSSL_CLIENT_END, so
     * TLSX_IsMlKemGroupSupported() is true for all four ML-KEM blocks
     * (its only reachable value in this build - see above). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);

    /* "2048/8 >= minDhKeySz && 2048/8 <= maxDhKeySz": both operands. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));

    /* Default range: both operands true. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    wolfSSL_free(ssl);
    ssl = NULL;

    /* minDhKeySz raised above 2048 bits: first operand false. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(wolfSSL_SetMinDhKey_Sz(ssl, 4096), WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* maxDhKeySz lowered below 2048 bits, minDhKeySz left at its default
     * (below 2048 bits): first operand true, second false - independence
     * for the second operand. */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(wolfSSL_SetMaxDhKey_Sz(ssl, 1024), WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
    }
    wolfSSL_free(ssl);

    wolfSSL_CTX_free(ctx);
    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_CSR_Parse() (client, TLS 1.3, receiving a CertificateStatus
 * response) and TLSX_CSR2_Parse() / TLSX_CSR_Parse() (server, parsing a
 * status_request(_v2) request from a ClientHello) - reached through the
 * WOLFSSL_TEST_VIS TLSX_Parse(). */
#ifdef TEST_TLS_BOUNDS_CSR_PARSE
static int test_TLSX_CSR_Parse_fail_after = -1;
static int test_TLSX_CSR_Parse_alloc_seen = 0;

TEST_TLS_BOUNDS_UNUSED
static void* test_TLSX_CSR_Parse_fail_malloc(size_t size)
{
    if (test_TLSX_CSR_Parse_fail_after >= 0) {
        if (test_TLSX_CSR_Parse_alloc_seen == test_TLSX_CSR_Parse_fail_after) {
            test_TLSX_CSR_Parse_alloc_seen++;
            return NULL;
        }
        test_TLSX_CSR_Parse_alloc_seen++;
    }
    return malloc(size);
}

TEST_TLS_BOUNDS_UNUSED
static void test_TLSX_CSR_Parse_fail_free(void* ptr)
{
    free(ptr);
}

TEST_TLS_BOUNDS_UNUSED
static void* test_TLSX_CSR_Parse_fail_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}
#endif

int test_TLSX_CSR_Parse_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_CSR_PARSE) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[16];
    word16 extLen;
    wolfSSL_Malloc_cb prevM = NULL;
    wolfSSL_Free_cb prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;

    /* Server side, isRequest == true: "SSL_CM(ssl) == NULL ||
     * !SSL_CM(ssl)->ocspStaplingEnabled". A single status_request entry
     * (status_type == OCSP, empty responder_id_list and request_extensions)
     * with SSL_CM(ssl) forced NULL - first operand true. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        WOLFSSL_CERT_MANAGER* origCM = ssl->ctx->cm;

        /* type(2) + len(2) + status_type(1) + responder_id_list len(2)=0 +
         * request_ext len(2)=0 */
        ext[0] = (byte)(TLSXT_STATUS_REQUEST >> 8);
        ext[1] = (byte)(TLSXT_STATUS_REQUEST & 0xFF);
        ext[2] = 0; ext[3] = 5; /* extension body length */
        ext[4] = WOLFSSL_CSR_OCSP;
        ext[5] = 0; ext[6] = 0;
        ext[7] = 0; ext[8] = 0;
        extLen = 4 + 5;

        ssl->ctx->cm = NULL;
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ssl->ctx->cm = origCM;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Client side, isRequest == false, TLS 1.3: the internal ticket-style
     * malloc for csr->responses[idx].buffer.
     * Operand 0 (ret == 0) of "if (ret == 0 &&
     * csr->responses[ssl->response_idx].buffer == NULL)": forced to true
     * by failing that allocation (operand 1 held true), then to false by
     * pushing ssl->response_idx out of range so an earlier guard already
     * set ret != 0 before this line is reached - independence for operand
     * 0, with operand 1's own pair already covered elsewhere. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* type(2) + length(2) + status_type(1) + resp_length(3) + 4 bytes
         * of (fake) response data. */
        byte body[HELLO_EXT_TYPE_SZ + OPAQUE16_LEN + OPAQUE8_LEN +
                  OPAQUE24_LEN + 4];
        word16 bodyLen;

        ExpectIntEQ(TLSX_UseCertificateStatusRequest(&ssl->extensions,
                    WOLFSSL_CSR_OCSP, 0, ssl, ssl->heap, ssl->devId),
                    WOLFSSL_SUCCESS);
        ssl->options.tls1_3 = 1;

        body[0] = (byte)(TLSXT_STATUS_REQUEST >> 8);
        body[1] = (byte)(TLSXT_STATUS_REQUEST & 0xFF);
        body[2] = 0;
        body[3] = OPAQUE8_LEN + OPAQUE24_LEN + 4;
        body[4] = WOLFSSL_CSR_OCSP;
        test_tls_bounds_c32to24(4, body + 4 + OPAQUE8_LEN);
        XMEMSET(body + 4 + OPAQUE8_LEN + OPAQUE24_LEN, 0xAB, 4);
        bodyLen = 4 + OPAQUE8_LEN + OPAQUE24_LEN + 4;

        /* ret == 0, forced allocation failure: operand 0 true, operand 1
         * (buffer == NULL) true - overall true, ret becomes MEMORY_ERROR. */
        ssl->response_idx = 0;
        ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
        ExpectIntEQ(wolfSSL_SetAllocators(test_TLSX_CSR_Parse_fail_malloc,
                    test_TLSX_CSR_Parse_fail_free,
                    test_TLSX_CSR_Parse_fail_realloc), 0);
        test_TLSX_CSR_Parse_alloc_seen = 0;
        test_TLSX_CSR_Parse_fail_after = 0;
        ExpectIntEQ(TLSX_Parse(ssl, body, bodyLen, certificate, NULL),
                    WC_NO_ERR_TRACE(MEMORY_ERROR));
        test_TLSX_CSR_Parse_fail_after = -1;
        (void)wolfSSL_SetAllocators(prevM, prevF, prevR);

        /* response_idx out of range: an earlier guard sets ret ==
         * BAD_FUNC_ARG before this decision is reached at all - operand 0
         * false, independence from the vector above. */
        ssl->response_idx = 1 + MAX_CHAIN_DEPTH;
        ExpectIntEQ(TLSX_Parse(ssl, body, bodyLen, certificate, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ssl->response_idx = 0;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

int test_TLSX_CSR2_Parse_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) &&  defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[9];
    WOLFSSL_CERT_MANAGER* origCM = NULL;

    /* Server side: "SSL_CM(ssl) == NULL || !SSL_CM(ssl)->ocspStaplingEnabled",
     * SSL_CM(ssl) forced NULL - first operand true. One status_request_v2
     * entry (status_type == OCSP, empty responder_id_list/request_extensions). */
    ext[0] = 0; ext[1] = 7;               /* overall list size */
    ext[2] = WOLFSSL_CSR2_OCSP;           /* status_type */
    ext[3] = 0; ext[4] = 4;               /* inner request length */
    ext[5] = 0; ext[6] = 0;               /* responder_id_list length */
    ext[7] = 0; ext[8] = 0;               /* request_extensions length */

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        byte full[9 + 4];
        word16 fullLen;

        full[0] = (byte)(TLSXT_STATUS_REQUEST_V2 >> 8);
        full[1] = (byte)(TLSXT_STATUS_REQUEST_V2 & 0xFF);
        full[2] = 0; full[3] = sizeof(ext);
        XMEMCPY(full + 4, ext, sizeof(ext));
        fullLen = 4 + sizeof(ext);

        origCM = ssl->ctx->cm;
        ssl->ctx->cm = NULL;
        ExpectIntEQ(TLSX_Parse(ssl, full, fullLen, client_hello, suites), 0);
        ssl->ctx->cm = origCM;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_WriteRequest() / TLSX_GetRequestSize() - the "ssl->ctx &&
 * ssl->ctx->extensions" merge guard. msgType values other than client_hello
 * and certificate_request skip the whole leading block (including the
 * SSL_CM(ssl) dereference that a NULL ssl->ctx could not survive), landing
 * directly on this guard, so ssl->ctx can safely be forced NULL only for
 * such a msgType. */
int test_TLSX_ext_dispatch_ctx_extensions_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* savedCtx = NULL;
    byte out[64];
    word32 offset;
    word32 len;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* ssl->ctx == NULL: first operand false. server_hello is neither
         * client_hello nor certificate_request, so the leading blocks that
         * dereference ssl->ctx are skipped entirely before this line. */
        savedCtx = ssl->ctx;
        ssl->ctx = NULL;
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, server_hello, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, server_hello, &offset), 0);
        ssl->ctx = savedCtx;

        /* ssl->ctx != NULL, ssl->ctx->extensions == NULL (default): second
         * operand false, first true. Still server_hello: with HAVE_ECH
         * defined (as it is in this build), msgType == client_hello takes
         * a wholly different "if (!ssl->options.disableECH && msgType ==
         * client_hello) { ... } else { <this line> }" branch that never
         * reaches this guard at all - server_hello is what actually lands
         * on it, for every vector here. */
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, server_hello, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, server_hello, &offset), 0);

        /* ssl->ctx != NULL, ssl->ctx->extensions != NULL: both true. A
         * renegotiation-info extension with NULL data writes just its
         * length byte. server_hello has isRequest == false, so it also
         * needs resp marked or TLSX_GetSize()/TLSX_Write()'s own
         * "!isRequest && !extension->resp" guard skips it before ever
         * reaching the ssl->ctx merge under test. */
        {
            /* ExpectNotNull() does not assign once an earlier expectation in
             * the same test has failed, so this must start defined. */
            TLSX* ext = NULL;
            ExpectIntEQ(TLSX_Push(&ssl->ctx->extensions,
                        TLSX_RENEGOTIATION_INFO, NULL, ssl->ctx->heap), 0);
            ExpectNotNull(ext = TLSX_Find(ssl->ctx->extensions,
                        TLSX_RENEGOTIATION_INFO));
            if (ext != NULL)
                ext->resp = 1;
        }
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, server_hello, &len), 0);
        ExpectTrue(len > 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, server_hello, &offset), 0);
        ExpectTrue(offset > 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_WriteRequest()'s and TLSX_GetRequestSize()'s extended-master-secret
 * tails - both "msgType == client_hello && ssl->options.haveEMS &&
 * (!IsAtLeastTLSv1_3(ssl->version) || ssl->options.downgrade)" - only the
 * second operand (haveEMS) is open on each; the worklist's ":1" suffix. The
 * first (msgType) and third (version/downgrade) already have pairs
 * elsewhere. Both tails sit after the HAVE_ECH branch merges back together,
 * so client_hello reaches them the same way in either function. */
int test_TLSX_WriteRequest_ems_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_EXTENDED_MASTER) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte out[64];
    word32 offset;
    word32 len;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* haveEMS == 0 (HAVE_EXTENDED_MASTER defaults it to 1; forced off
         * here): second operand false. */
        ssl->options.haveEMS = 0;
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);

        /* haveEMS == 1: second operand true - independence for the second
         * operand, first and third held at the same values as above. */
        ssl->options.haveEMS = 1;
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &len), 0);
        ExpectTrue(len >= HELLO_EXT_SZ);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
        ExpectTrue(offset > 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_WriteRequest()'s trailing length-prefix guard -
 * "offset > OPAQUE16_LEN || msgType != client_hello". */
int test_TLSX_WriteRequest_length_prefix_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte out[64];
    word32 offset;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* offset == OPAQUE16_LEN (nothing written), msgType == client_hello:
         * both operands false - the length prefix is left unwritten. A
         * fixed TLS 1.2 method with EMS explicitly off, and the
         * empty renegotiation_info InitSSL() advertises by default for
         * every client (SetupClientSecureRenegotiation()) removed, keeps
         * this ssl from writing anything else of its own accord. */
        ssl->options.haveEMS = 0;
        TLSX_Remove(&ssl->extensions, TLSX_RENEGOTIATION_INFO, ssl->heap);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset),
                    0);
        ExpectIntEQ(offset, OPAQUE16_LEN);

        /* offset == OPAQUE16_LEN, msgType == certificate_request: second
         * operand true, first false - independence for the second
         * operand. */
        offset = 0;
#if defined(WOLFSSL_TLS13) && !defined(NO_CERTS)
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, certificate_request, &offset),
                    0);
#endif

        /* offset > OPAQUE16_LEN, msgType == client_hello: first operand
         * true - independence for the first operand. A pushed
         * renegotiation-info extension guarantees at least one byte gets
         * written. */
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_RENEGOTIATION_INFO,
                    NULL, ssl->heap), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
        ExpectTrue(offset > OPAQUE16_LEN);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_WriteResponse() - "TLSX_SupportExtensions(ssl) && output" (its own
 * independence pair, separate from TLSX_WriteRequest()'s call to the same
 * predicate) and the extended-master-secret tail
 * "ssl->options.haveEMS && msgType == server_hello &&
 *  !IsAtLeastTLSv1_3(ssl->version)" (operands 1 and 2; operand 0 already
 * has a pair elsewhere). TLSX_GetResponseSize() has the identical EMS tail
 * one call earlier and is driven by the same three vectors. Both are
 * WOLFSSL_LOCAL, reachable directly in this static build. */
int test_TLSX_WriteResponse_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_EXTENDED_MASTER) &&  !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte out[64];
    word16 offset;
    word16 len;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(test_tls_bounds_load_server_cert(ctx), TEST_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* TLSX_SupportExtensions(ssl) false (corrupted version.major, the
         * only way to make it false - see test_TLSX_SupportExtensions_bounds
         * above), output != NULL: first operand false. */
        ssl->version.major = 0;
        offset = 0;
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, server_hello, &offset), 0);
        ExpectIntEQ(offset, 0);
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_2_MINOR;

        /* TLSX_SupportExtensions(ssl) true, output == NULL: second operand
         * false, first true - independence for the second operand. */
        offset = 0;
        ExpectIntEQ(TLSX_WriteResponse(ssl, NULL, server_hello, &offset), 0);
        ExpectIntEQ(offset, 0);

        /* Both true, haveEMS && server_hello && !TLS1.3: all three EMS
         * operands true. */
        ssl->options.haveEMS = 1;
        len = 0;
        ExpectIntEQ(TLSX_GetResponseSize(ssl, server_hello, &len), 0);
        ExpectTrue(len >= HELLO_EXT_SZ);
        offset = 0;
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, server_hello, &offset), 0);
        ExpectTrue(offset > 0);

        /* haveEMS true, msgType != server_hello: EMS operand 1 false -
         * independence for operand 1 (operand 0 held true). */
        len = 0;
        ExpectIntEQ(TLSX_GetResponseSize(ssl, encrypted_extensions, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, encrypted_extensions,
                    &offset), 0);

        /* haveEMS true, msgType == server_hello, TLS 1.3: EMS operand 2
         * false - independence for operand 2 (operands 0 and 1 held true). */
        ssl->version.major = SSLv3_MAJOR;
        ssl->version.minor = TLSv1_3_MINOR;
        ssl->options.tls1_3 = 1;
        len = 0;
        ExpectIntEQ(TLSX_GetResponseSize(ssl, server_hello, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, server_hello, &offset), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* The msgType splits shared by TLSX_SupportedVersions_GetSize()/_Write(),
 * TLSX_EncryptThenMac_GetSize()/_Write(), TLSX_ClientCertificateType_GetSize()/
 * _Write() and TLSX_ServerCertificateType_GetSize()/_Write() - all static-
 * in-file, reached only through the generic TLSX_GetSize()/TLSX_Write()
 * dispatch inside the WOLFSSL_TEST_VIS TLSX_GetRequestSize()/
 * TLSX_WriteRequest(). Those two only use msgType to decide which top-level
 * semaphore bits to set before the dispatch; the dispatch itself passes
 * msgType straight through to each extension's own handler regardless of
 * which wrapper made the call (see test_TLSX_Cookie_bounds() above for the
 * same pattern). One ssl populated with all four extensions and driven
 * through client_hello/server_hello/hello_retry_request/encrypted_extensions
 * therefore exercises every open condition in this group in one binary. */
int test_TLSX_ext_msgtype_dispatch_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12) &&  defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY) &&  defined(HAVE_RPK) && \
    defined(HAVE_TLS_EXTENSIONS)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* TLSX_PopulateExtensions() on a TLS 1.3 client also builds a real
     * KeyShare (possibly a large post-quantum/hybrid group) and signature
     * algorithm list, so this needs to be sized well past a single
     * extension's record, not just the two pushed-by-hand ones under
     * test - undersizing this the way an early pass did with a 16-byte
     * buffer for a 29-byte record corrupts the stack. */
    byte out[8192];
    word32 offset;
    word32 len;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* SupportedVersions and EncryptThenMac come from the normal
         * client-side extension population; ClientCertificateType/
         * ServerCertificateType are pushed directly (their real Use()
         * paths need a loaded RPK certificate, which is not needed to
         * reach the GetSize/Write msgType split under test). */
        ExpectIntEQ(TLSX_PopulateExtensions(ssl, 0), 0);
        ExpectNotNull(TLSX_Find(ssl->extensions, TLSX_SUPPORTED_VERSIONS));
        ExpectNotNull(TLSX_Find(ssl->extensions, TLSX_ENCRYPT_THEN_MAC));

        ssl->options.rpkState.sending_ClientCertTypeCnt = 1;
        ssl->options.rpkState.sending_ClientCertTypes[0] = 0;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_CLIENT_CERTIFICATE_TYPE,
                    ssl, ssl->heap), 0);
        ssl->options.rpkState.sending_ServerCertTypeCnt = 1;
        ssl->options.rpkState.sending_ServerCertTypes[0] = 0;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_SERVER_CERTIFICATE_TYPE,
                    ssl, ssl->heap), 0);

        /* TLSX_GetSize()/TLSX_Write() skip any extension with resp == 0
         * outright for every msgType that is not client_hello/
         * certificate_request (their own leading "!isRequest &&
         * !extension->resp" guard) - server_hello, hello_retry_request and
         * encrypted_extensions all fall in that set. Each is marked resp
         * only for the call(s) that actually exercise it: ServerHello
         * needs all four; hello_retry_request only means anything to
         * SupportedVersions/EncryptThenMac (ClientCertificateType/
         * ServerCertificateType's own GetSize() has no case for it at all,
         * and unlike TLSX_CSR_GetSize_ex() it does not clamp a negative
         * SANITY_MSG_E before folding it into the word32 running total,
         * so marking it resp for a msgType it was never meant to answer
         * corrupts TLSX_GetSize()'s own accumulator - not the thing under
         * test here); encrypted_extensions only means anything to
         * ClientCertificateType/ServerCertificateType. */
        {
            TLSX* svExt = TLSX_Find(ssl->extensions, TLSX_SUPPORTED_VERSIONS);
            TLSX* etmExt = TLSX_Find(ssl->extensions, TLSX_ENCRYPT_THEN_MAC);
            TLSX* cctExt = TLSX_Find(ssl->extensions,
                    TLSX_CLIENT_CERTIFICATE_TYPE);
            TLSX* sctExt = TLSX_Find(ssl->extensions,
                    TLSX_SERVER_CERTIFICATE_TYPE);
            ExpectNotNull(svExt);
            ExpectNotNull(etmExt);
            ExpectNotNull(cctExt);
            ExpectNotNull(sctExt);

            /* msgType == client_hello: SupportedVersions/ClientCertificateType/
             * ServerCertificateType all take their "if (msgType ==
             * client_hello)" branch (not part of any open condition here);
             * EncryptThenMac's "msgType != client_hello" operand false. */
            len = 0;
            ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &len), 0);
            offset = 0;
            ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset),
                        0);

            /* msgType == server_hello: SupportedVersions/
             * ClientCertificateType/ServerCertificateType operand 0 true;
             * EncryptThenMac operand 0 true, operand 1 false. */
            if (svExt != NULL) svExt->resp = 1;
            if (etmExt != NULL) etmExt->resp = 1;
            if (cctExt != NULL) cctExt->resp = 1;
            if (sctExt != NULL) sctExt->resp = 1;
            len = 0;
            ExpectIntEQ(TLSX_GetRequestSize(ssl, server_hello, &len), 0);
            offset = 0;
            ExpectIntEQ(TLSX_WriteRequest(ssl, out, server_hello, &offset),
                        0);
            if (cctExt != NULL) cctExt->resp = 0;
            if (sctExt != NULL) sctExt->resp = 0;

            /* msgType == hello_retry_request: SupportedVersions operand 0
             * false, operand 1 true; EncryptThenMac both operands true -
             * SANITY_MSG_E, which TLSX_GetSize()/TLSX_Write() propagate up.
             * ClientCertificateType/ServerCertificateType left resp == 0
             * (skipped) for exactly the reason in the comment above. */
            len = 0;
            ExpectIntEQ(TLSX_GetRequestSize(ssl, hello_retry_request, &len),
                        WC_NO_ERR_TRACE(SANITY_MSG_E));
            offset = 0;
            ExpectIntEQ(TLSX_WriteRequest(ssl, out, hello_retry_request,
                        &offset), WC_NO_ERR_TRACE(SANITY_MSG_E));
            if (svExt != NULL) svExt->resp = 0;
            if (etmExt != NULL) etmExt->resp = 0;
        }

        /* msgType == encrypted_extensions: ClientCertificateType/
         * ServerCertificateType operand 0 false, operand 1 true. */
        {
            TLSX* cctExt = TLSX_Find(ssl->extensions,
                    TLSX_CLIENT_CERTIFICATE_TYPE);
            TLSX* sctExt = TLSX_Find(ssl->extensions,
                    TLSX_SERVER_CERTIFICATE_TYPE);
            if (cctExt != NULL) cctExt->resp = 1;
            if (sctExt != NULL) sctExt->resp = 1;
        }
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, encrypted_extensions, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, encrypted_extensions,
                    &offset), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* The "both false" baseline row for each of the three OR-shaped msgType
     * splits above (SupportedVersions/ClientCertificateType/
     * ServerCertificateType) still needs one more vector each: a msgType
     * that is neither of the two the extension recognizes. server_hello/
     * hello_retry_request/encrypted_extensions above only ever showed one
     * extension's operands both false as a side effect of some OTHER
     * extension being absent or skipped from that same call - never this
     * extension, reached with resp honored, on a call of its own. Each
     * pushed alone (fresh ssl, so no cross-extension interaction) with an
     * unused msgType supplies it. ClientCertificateType/
     * ServerCertificateType's TLSX_GetSize() case does not clamp the
     * SANITY_MSG_E their GetSize() returns here (unlike TLSX_Write()'s
     * case, which returns a word16 that is always 0 in this branch) before
     * folding it into the running total, so TLSX_GetRequestSize() itself
     * comes back BUFFER_E rather than SANITY_MSG_E - a preexisting
     * TLSX_GetSize() quirk, not the thing under test, and not asserted on
     * beyond "some error". */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        /* TLSX_SetSupportedVersions() is static-in-file; its whole body is
         * "return TLSX_Push(extensions, TLSX_SUPPORTED_VERSIONS, data,
         * heap);" with data == ssl, called directly here instead. */
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_SUPPORTED_VERSIONS, ssl,
                    ssl->heap), 0);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions,
                    TLSX_SUPPORTED_VERSIONS));
        if (ext != NULL)
            ext->resp = 1;
        len = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, encrypted_extensions, &len),
                    WC_NO_ERR_TRACE(SANITY_MSG_E));
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, encrypted_extensions,
                    &offset), WC_NO_ERR_TRACE(SANITY_MSG_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        ssl->options.rpkState.sending_ClientCertTypeCnt = 1;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_CLIENT_CERTIFICATE_TYPE,
                    ssl, ssl->heap), 0);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions,
                    TLSX_CLIENT_CERTIFICATE_TYPE));
        if (ext != NULL)
            ext->resp = 1;
        len = 0;
        ExpectIntNE(TLSX_GetRequestSize(ssl, hello_retry_request, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, hello_retry_request,
                    &offset), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        ssl->options.rpkState.sending_ServerCertTypeCnt = 1;
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_SERVER_CERTIFICATE_TYPE,
                    ssl, ssl->heap), 0);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions,
                    TLSX_SERVER_CERTIFICATE_TYPE));
        if (ext != NULL)
            ext->resp = 1;
        len = 0;
        ExpectIntNE(TLSX_GetRequestSize(ssl, hello_retry_request, &len), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, hello_retry_request,
                    &offset), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_SecureRenegotiation_Write() - "data && data->enabled &&
 * data->verifySet". Only the first operand is open; a NULL data pointer is
 * the "HAVE_SERVER_RENEGOTIATION_INFO only" empty-extension shape the
 * function's own comment describes, produced here directly with
 * TLSX_Push() rather than through a real renegotiation handshake. */
int test_TLSX_SecureRenegotiation_Write_bounds(void)
{
#if defined(WOLFSSL_TEST_STATIC_BUILD) &&  (defined(HAVE_SECURE_RENEGOTIATION) || defined(HAVE_SERVER_RENEGOTIATION_INFO)) &&  !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* Sized from the vector: prefix(2) + type(2) + len(2) + reneg length
     * byte(1) + client_verify_data(TLS_FINISHED_SZ==12) == 19 bytes for
     * the enabled/verifySet case below. */
    byte out[32];
    word32 offset;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* data == NULL: first operand false. InitSSL() already advertises
         * an empty renegotiation_info by default for every client
         * (SetupClientSecureRenegotiation(), with real, non-NULL data) -
         * remove it first so this vector's own NULL-data push is the only
         * TLSX_RENEGOTIATION_INFO node on the list. */
        ssl->options.haveEMS = 0;
        TLSX_Remove(&ssl->extensions, TLSX_RENEGOTIATION_INFO, ssl->heap);
        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_RENEGOTIATION_INFO,
                    NULL, ssl->heap), 0);
        offset = 0;
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
        ExpectIntEQ(offset, OPAQUE16_LEN + HELLO_EXT_TYPE_SZ + OPAQUE16_LEN +
                    OPAQUE8_LEN);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* data != NULL, enabled and verifySet both true: first operand true -
     * independence for the first operand. wolfSSL_UseSecureRenegotiation()
     * allocates data; verifySet/enabled are then set directly (only ever
     * set true together, by a real Finished exchange in the non-test
     * path). */
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* ext = NULL;
        SecureRenegotiation* data;

        ssl->options.haveEMS = 0;
        ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl), WOLFSSL_SUCCESS);
        ExpectNotNull(ext = TLSX_Find(ssl->extensions, TLSX_RENEGOTIATION_INFO));
        if (ext != NULL) {
            data = (SecureRenegotiation*)ext->data;
            data->enabled = 1;
            data->verifySet = 1;
            offset = 0;
            ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset),
                        0);
            ExpectIntEQ(offset, OPAQUE16_LEN + HELLO_EXT_TYPE_SZ +
                        OPAQUE16_LEN + OPAQUE8_LEN + TLS_FINISHED_SZ);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}

/* ---------------------------------------------------------------------- */
/* TLSX_SessionTicket_Parse() (server, TLS 1.2), the "ret is REJECT or
 * VERSION_ERROR" branch after "ret = DoClientTicket(...)". The
 * false/false row - ret is neither value - needs a DoClientTicket() return
 * that is none of WOLFSSL_TICKET_RET_OK/_CREATE/_REJECT or VERSION_ERROR.
 * DoDecryptTicket() has exactly one such path: when the registered
 * SessionTicketEncCb reports success but writes an out-of-range outLen,
 * DoDecryptTicket() returns BAD_TICKET_KEY_CB_SZ directly - none of the
 * four TicketEncRet values and unrelated to VERSION_ERROR - and
 * DoClientTicket() passes that straight back up unchanged (it does not
 * reach WOLFSSL_TICKET_RET_REJECT; every REJECT return in DoDecryptTicket()
 * is a distinct, earlier guard). TLSX_SessionTicket_Parse() then falls to
 * its own "else if (ret < 0)" tail, leaving ret untouched, so the negative
 * value propagates out of TLSX_Parse() and fails the handshake - a real,
 * protocol-level row, not a callee postcondition that collapses it into
 * REJECT. So: covered, not excluded. */
#ifdef TEST_TLS_BOUNDS_SESSION_TICKET_FF
TEST_TLS_BOUNDS_UNUSED
static int test_TLSX_SessionTicket_ff_enc_cb(WOLFSSL* ssl,
        byte key_name[WOLFSSL_TICKET_NAME_SZ], byte iv[WOLFSSL_TICKET_IV_SZ],
        byte mac[WOLFSSL_TICKET_MAC_SZ], int enc, byte* ticket, int inLen,
        int* outLen, void* userCtx)
{
    int i;
    (void)ssl; (void)userCtx;

    if (enc) {
        XMEMSET(key_name, 0x11, WOLFSSL_TICKET_NAME_SZ);
        XMEMSET(iv, 0x22, WOLFSSL_TICKET_IV_SZ);
        XMEMSET(mac, 0x33, WOLFSSL_TICKET_MAC_SZ);
        /* DoCreateTicket()'s own sanity check rejects an encrypt callback
         * that leaves the internal ticket bytes unchanged, so this has to
         * actually transform them, not just report success. */
        for (i = 0; i < inLen; i++)
            ticket[i] = (byte)(ticket[i] ^ 0xA5);
        *outLen = inLen;
    }
    else {
        /* Report success with an out-of-range outLen: DoDecryptTicket()'s
         * own "outLen > inLen || outLen < WOLFSSL_INTERNAL_TICKET_LEN"
         * guard turns this into BAD_TICKET_KEY_CB_SZ. */
        *outLen = 0;
    }
    return WOLFSSL_TICKET_RET_OK;
}

TEST_TLS_BOUNDS_UNUSED
static int test_TLSX_SessionTicket_ff_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_set_TicketEncCb(ctx,
                test_TLSX_SessionTicket_ff_enc_cb), WOLFSSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif

int test_TLSX_SessionTicket_Parse_falsefalse_bounds(void)
{
#if defined(TEST_TLS_BOUNDS_SESSION_TICKET_FF) && \
    !defined(WOLFSSL_NO_TLS12)
    EXPECT_DECLS;
    test_ssl_memio_ctx test_ctx;
    WOLFSSL_SESSION* sess = NULL;

    /* First connection: issue a ticket (enc == 1 path only). */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.method = wolfTLSv1_2_client_method;
    test_ctx.s_cb.method = wolfTLSv1_2_server_method;
    test_ctx.s_cb.ctx_ready = test_TLSX_SessionTicket_ff_ctx_ready;
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSessionTicket(test_ctx.c_ssl), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                TEST_SUCCESS);
    ExpectNotNull(sess = wolfSSL_get1_session(test_ctx.c_ssl));
    test_ssl_memio_cleanup(&test_ctx);

    /* Second connection: present that ticket back (enc == 0 path), which
     * the callback now deliberately corrupts. */
    if (sess != NULL) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        test_ctx.c_cb.method = wolfTLSv1_2_client_method;
        test_ctx.s_cb.method = wolfTLSv1_2_server_method;
        test_ctx.s_cb.ctx_ready = test_TLSX_SessionTicket_ff_ctx_ready;
        ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
        ExpectIntEQ(wolfSSL_set_session(test_ctx.c_ssl, sess),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
                    TEST_FAIL);
        test_ssl_memio_cleanup(&test_ctx);
    }
    wolfSSL_SESSION_free(sess);

    return EXPECT_RESULT();
#else
    return TEST_SKIPPED;
#endif
}
