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

/* ---------------------------------------------------------------------- */
/* TLSX_UseSNI - the extensions list argument is always &ssl->extensions or
 * &ctx->extensions (wolfSSL_UseSNI / wolfSSL_CTX_UseSNI), or &ech->extensions
 * (the ECH echo path in TLSX_SNI_Parse) - always the address of a struct
 * member, never NULL. The "extensions == NULL" half of the guard has no
 * reachable caller and is excluded (argued in the report, not retested here).
 * The "data == NULL" half, the host-name-length guard, and the duplicate-type
 * removal in the linked list are all reachable through wolfSSL_UseSNI(). */
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_UseSNI_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_UseALPN - extensions is always &ssl->extensions (wolfSSL_UseALPN());
 * unreachable-NULL, excluded. data == NULL: wolfSSL_UseALPN() only calls
 * TLSX_UseALPN() with tokens produced by XSTRTOK(), which are never NULL
 * inside the "while (token[idx] != NULL)" loop, so the only way to reach
 * TLSX_UseALPN() with a NULL data pointer at all is to call it directly. */
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_UseALPN_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_UseMaxFragment - extensions always &ssl->extensions / &ctx->extensions;
 * unreachable-NULL, excluded. mfl < MIN and mfl > MAX are both reachable
 * through the public wrapper with an out-of-range code, alongside a valid
 * in-range call. */
#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_UseMaxFragment_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_UseCertificateStatusRequest - extensions is always &ssl->extensions /
 * &ctx->extensions (wolfSSL_UseOCSPStapling() / _CTX_); unreachable-NULL,
 * excluded. status_type != WOLFSSL_CSR_OCSP is reachable directly: the
 * wrapper passes the caller's status_type straight through with no
 * validation of its own. */
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_UseCertificateStatusRequest_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_UseCertificateStatusRequestV2 - same pattern as V1 above. */
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_UseCertificateStatusRequestV2_bounds(void)
{
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
}
#endif

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
#if !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_SupportExtensions_bounds(void)
{
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
    ssl->version.major = 0;
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &offset), 0);
    ssl->version.major = SSLv3_MAJOR;
    ssl->version.minor = TLSv1_2_MINOR;

    /* TLSX_WriteRequest()'s own leading guard is
     * "!TLSX_SupportExtensions(ssl) || output == NULL": a supported ssl with
     * output == NULL exercises the second operand independently of the
     * ssl == NULL call above. */
    offset = 0;
    ExpectIntEQ(TLSX_WriteRequest(ssl, NULL, client_hello, &offset), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return EXPECT_RESULT();
}
#endif

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
#if defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_CERTS)
int test_TLSX_CSR2_InitRequests_bounds(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    DecodedCert cert;
    TLSX* ext;
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
}

int test_TLSX_CSR2_ForceRequest_bounds(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext;
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
}
#endif

#if defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_CSR_GetRequest_ex_bounds(void)
{
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
}
#endif


/* ---------------------------------------------------------------------- */
/* wolfSSL_make_eap_keys() - "ssl == NULL || ssl->arrays == NULL". ssl->arrays
 * is allocated lazily by the handshake and is still NULL on a freshly
 * created object, so both operands are reachable without completing a
 * handshake at all. */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TEST_STATIC_BUILD)
int test_wolfSSL_make_eap_keys_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* wolfSSL_SetTlsHmacInner() - "ssl == NULL || inner == NULL", then
 * "content == dtls12_cid || (ssl->options.dtls && DtlsGetCidTxSize(ssl) >
 * 0)". Both are public (WOLFSSL_API) and reachable directly. */
#if !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_AEAD_ONLY)
int test_wolfSSL_SetTlsHmacInner_bounds(void)
{
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

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID) && \
    defined(WOLFSSL_DTLS13)
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
}
#endif

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
#if defined(WOLFSSL_TEST_STATIC_BUILD) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_SHA256)
int test_BuildTlsHandshakeHash_bounds(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLS_hmac() / Hmac_UpdateFinal_CT() - driven directly through ssl->hmac(),
 * which InitSSL() points at TLS_hmac() by default whenever TLS 1.2 (or
 * older) CBC-MAC support is built, before any handshake runs (see the
 * existing test_tls_hmac_size_overflow() in test_hmac.c for the same
 * pattern). No live connection is needed: the size-overflow guard and the
 * verify/padSz dispatch are pure argument checks over ssl->specs and the
 * caller-supplied lengths. */
#if !defined(NO_HMAC) && !defined(WOLFSSL_AEAD_ONLY) && !defined(NO_TLS) && \
    defined(NO_OLD_TLS) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_SHA256)
int test_TLS_hmac_bounds(void)
{
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
}
#endif

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
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_ALPN) && \
    !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_ALPN_GetSize_overflow(void)
{
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
}
#endif

/* ---------------------------------------------------------------------- */
/* TLSX_Cookie_GetSize() / TLSX_Cookie_Write() - "msgType == client_hello ||
 * msgType == hello_retry_request", reached through the WOLFSSL_TEST_VIS
 * TLSX_GetRequestSize()/TLSX_WriteRequest() by passing the message type
 * directly: the dispatch inside TLSX_GetSize()/TLSX_Write() only looks at
 * the msgType argument (and, once the extension already exists,
 * extension->resp for the "is this message type getting a response-only
 * extension" skip), not at which top-level wrapper made the call. */
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_CLIENT)
int test_TLSX_Cookie_bounds(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    TLSX* ext;
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
}
#endif
