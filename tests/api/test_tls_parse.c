/* test_tls_parse.c
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
#include <tests/api/test_tls_parse.h>

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#ifndef NO_DH
#include <wolfssl/wolfcrypt/dh.h>
#endif

/* Several helpers below are called only from test bodies whose feature guards
 * differ, so a configuration can compile in none of their callers. */
#if defined(__GNUC__) || defined(__clang__)
    #define TEST_TLS_PARSE_UNUSED __attribute__((unused))
#else
    #define TEST_TLS_PARSE_UNUSED
#endif

/* Helper to build a server-side WOLFSSL_CTX with a certificate/key loaded,
 * as required for wolfSSL_new() to succeed on a server context.
 */
TEST_TLS_PARSE_UNUSED
static WOLFSSL_CTX* test_tls_parse_server_ctx(WOLFSSL_METHOD* method)
{
    WOLFSSL_CTX* ctx = NULL;
#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
    /* An ECC-only build has no RSA server certificate to load. */
    #ifndef NO_RSA
    const char* certFile = svrCertFile;
    const char* keyFile  = svrKeyFile;
    #else
    const char* certFile = eccCertFile;
    const char* keyFile  = eccKeyFile;
    #endif
#endif

    if (method == NULL)
        return NULL;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL)
        return NULL;

#if !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
    if (wolfSSL_CTX_use_certificate_file(ctx, certFile, CERT_FILETYPE)
            != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx, keyFile, CERT_FILETYPE)
            != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
#else
    wolfSSL_CTX_free(ctx);
    return NULL;
#endif

    return ctx;
}

/* TLSX_Parse() walks a concatenated list of type(2)/length(2)/body
 * extensions, exactly as they appear on the wire -- not a single
 * extension's body on its own. This wraps one extension's body with that
 * header into 'out', which must be at least bodyLen + 4 bytes, and returns
 * the total length.
 */
TEST_TLS_PARSE_UNUSED
static word16 test_tls_parse_build_ext(byte* out, word16 outCap,
        word16 type, const byte* body, word16 bodyLen)
{
    /* A body that doesn't fit the caller's buffer is a fixture bug: fail
     * loudly and locally rather than silently overrunning the stack. */
    if ((word32)bodyLen + 4 > outCap) {
        fprintf(stderr, "test_tls_parse_build_ext: body of %u bytes does "
                "not fit a %u byte buffer\n", (unsigned)bodyLen,
                (unsigned)outCap);
        abort();
    }
    out[0] = (byte)(type >> 8);
    out[1] = (byte)(type & 0xFF);
    out[2] = (byte)(bodyLen >> 8);
    out[3] = (byte)(bodyLen & 0xFF);
    if (bodyLen > 0 && body != NULL)
        XMEMCPY(out + 4, body, bodyLen);
    return (word16)(4 + bodyLen);
}

/* A small counting allocator used to force a single, targeted malloc
 * failure. Installed narrowly around the call under test and restored
 * immediately after, so it never affects unrelated allocations.
 */
#if defined(WOLFSSL_TEST_STATIC_BUILD) && !defined(NO_TLS) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
static int tls_parse_fail_after = -1;
static int tls_parse_alloc_seen = 0;

TEST_TLS_PARSE_UNUSED
static void* tls_parse_fail_malloc(size_t size)
{
    if (tls_parse_fail_after >= 0) {
        if (tls_parse_alloc_seen == tls_parse_fail_after) {
            tls_parse_alloc_seen++;
            return NULL;
        }
        tls_parse_alloc_seen++;
    }
    return malloc(size);
}

TEST_TLS_PARSE_UNUSED
static void tls_parse_fail_free(void* ptr)
{
    free(ptr);
}

TEST_TLS_PARSE_UNUSED
static void* tls_parse_fail_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}
#endif /* WOLFSSL_TEST_STATIC_BUILD && !NO_TLS */

#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SUPPORTED_CURVES)
/* Pushes a single-entry supported_groups restriction directly, bypassing
 * TLSX_UseSupportedCurve()'s TLSX_IsGroupSupported() gate -- needed to name
 * a group id this build does not itself recognise, the same as a peer's
 * raw wire value would. */
TEST_TLS_PARSE_UNUSED
static int test_tls_parse_push_curve(TLSX** extensions, WOLFSSL* ssl,
        word16 name)
{
    SupportedCurve* curve = (SupportedCurve*)XMALLOC(sizeof(SupportedCurve),
            ssl->heap, DYNAMIC_TYPE_TLSX);
    if (curve == NULL)
        return WC_NO_ERR_TRACE(MEMORY_E);
    curve->name = name;
    curve->next = NULL;
    return TLSX_Push(extensions, TLSX_SUPPORTED_GROUPS, curve, ssl->heap);
}

/* Builds and pushes a minimal key share entry -- a peer offer that was
 * never processed into a real key -- for tests that only need the
 * bookkeeping fields (group, ke) a negotiation helper looks at. */
TEST_TLS_PARSE_UNUSED
static KeyShareEntry* test_tls_parse_push_kse(TLSX** extensions, WOLFSSL* ssl,
        word16 group)
{
    KeyShareEntry* kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
            ssl->heap, DYNAMIC_TYPE_TLSX);
    if (kse == NULL)
        return NULL;
    XMEMSET(kse, 0, sizeof(*kse));
    kse->group = group;
    kse->ke = (byte*)XMALLOC(1, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (kse->ke == NULL) {
        XFREE(kse, ssl->heap, DYNAMIC_TYPE_TLSX);
        return NULL;
    }
    kse->ke[0] = 0xAA;
    kse->keLen = 1;
    if (TLSX_Push(extensions, TLSX_KEY_SHARE, kse, ssl->heap) != 0) {
        XFREE(kse->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(kse, ssl->heap, DYNAMIC_TYPE_TLSX);
        return NULL;
    }
    return kse;
}

/* TLSX_KeyShare_FreeAll() is not visible outside src/tls.c even as
 * WOLFSSL_LOCAL; releasing a standalone (not already list-linked) entry
 * built directly for a test goes through the generic TLSX_FreeAll()
 * instead, via a throwaway one-node extension list. */
TEST_TLS_PARSE_UNUSED
static void test_tls_parse_free_kse(WOLFSSL* ssl, KeyShareEntry* kse)
{
    TLSX* extensions = NULL;
    if (kse == NULL)
        return;
    if (TLSX_Push(&extensions, TLSX_KEY_SHARE, kse, ssl->heap) != 0)
        return;
    TLSX_FreeAll(extensions, ssl->heap);
}
#endif /* WOLFSSL_TEST_STATIC_BUILD && WOLFSSL_TLS13 && HAVE_SUPPORTED_CURVES */

/* ---- ALPN --------------------------------------------------------------- */
/* RFC 7301: covers the TLSX_APPLICATION_LAYER_PROTOCOL parse helpers that
 * TLSX_Parse() reaches for both the client_hello (isRequest) and
 * server_hello (response) directions.
 */
int test_TLSX_ALPN_parse(void)
{
    EXPECT_DECLS;
/* TLSX_ALPN_GetRequest() below is WOLFSSL_LOCAL: needs the static library. */
#if defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_ALPN) &&  defined(HAVE_TLS_EXTENSIONS) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_CLIENT) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[300];
    word16 extLen;

    /* TLSX_ALPN_New(), reached through TLSX_UseALPN(): an over-length name
     * is rejected; a normal one is accepted. (A NULL name is rejected by
     * TLSX_UseALPN()'s own guard before TLSX_ALPN_New() is reached at all.)
     */
#ifdef WOLFSSL_TEST_STATIC_BUILD
    {
        TLSX* extensions = NULL;
        byte tooLong[WOLFSSL_MAX_ALPN_PROTO_NAME_LEN + 1];
        XMEMSET(tooLong, 'a', sizeof(tooLong));

        ExpectIntEQ(TLSX_UseALPN(&extensions, tooLong, sizeof(tooLong), 0,
                    NULL), WC_NO_ERR_TRACE(MEMORY_E));
        ExpectNull(extensions);
        ExpectIntEQ(TLSX_UseALPN(&extensions, "http/1.1", 8, 0, NULL),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(extensions);
        TLSX_FreeAll(extensions, NULL);
    }
#endif

    /* TLSX_ALPN_GetRequest(): each NULL argument independently. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        void* data = NULL;
        word16 dataSz = 0;

        ExpectIntEQ(TLSX_ALPN_GetRequest(NULL, &data, &dataSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"http/1.1", 8,
                    WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_ALPN_GetRequest(ssl->extensions, NULL, &dataSz),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(TLSX_ALPN_GetRequest(ssl->extensions, &data, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(TLSX_ALPN_GetRequest(ssl->extensions, &data, &dataSz),
                    WOLFSSL_ALPN_NOT_FOUND);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

    /* TLSX_ALPN_ParseAndSet() response direction and TLSX_ALPN_Find()/
     * ALPN_find_match(), all reached through TLSX_Parse(). The client
     * configures a multi-entry ALPN list; the crafted server_hello
     * response searches it, exercising exact match, same-length mismatch
     * and different-length mismatch.
     */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"aa", 2, WOLFSSL_ALPN_FAILED_ON_MISMATCH), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"bb", 2,
                WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WOLFSSL_SUCCESS);
    {
        /* mismatched content, same length as "bb": exercises the
         * XSTRNCMP() half of the search without an early length miss. */
        const byte respSameLen[] = { 0x00, 0x03, 0x02, 'z', 'z' };
        /* mismatched, longer than any configured name: every configured
         * entry is rejected on length before content is compared. */
        const byte respDiffLen[] = { 0x00, 0x04, 0x03, 'z', 'z', 'z' };
        /* server_hello response, exact match on "bb". Run last: a
         * successful match rewrites the ALPN list (marks the negotiated
         * entry), so it must not run before the mismatch cases above. */
        const byte respExact[] = { 0x00, 0x03, 0x02, 'b', 'b' };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, respSameLen,
                (word16)sizeof(respSameLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, respDiffLen,
                (word16)sizeof(respDiffLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, respExact,
                (word16)sizeof(respExact));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Response direction, nothing configured on this client at all:
     * ALPN_find_match()'s extension == NULL path. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte resp[] = { 0x00, 0x03, 0x02, 'h', 'i' };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, resp,
                (word16)sizeof(resp));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Response direction, two protocol names instead of the one RFC 7301
     * Section 3.1 allows in a response. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_UseALPN(ssl, (char*)"xx", 2,
                WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        const byte twoEntries[] = { 0x00, 0x06, 0x02, 'x', 'x', 0x02, 'y', 'y' };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, twoEntries,
                (word16)sizeof(twoEntries));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Request direction: server parses and stores a client_hello ALPN
     * list. Exercises TLSX_ALPN_ParseAndSet()'s length bookkeeping (shared
     * with the response direction) on the request side, including the
     * per-entry wlen == 0 and length-overflow checks and the overall list
     * size mismatch.
     */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        /* list size claims 5 bytes, only 3 are present. */
        const byte badListLen[] = { 0x00, 0x05, 0x02, 'h', 'i' };
        /* first entry's own length prefix is 0. */
        const byte zeroWlen[] = { 0x00, 0x01, 0x00 };
        /* first entry's length prefix (5) runs past the list. */
        const byte overWlen[] = { 0x00, 0x03, 0x05, 'h', 'i' };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, badListLen,
                (word16)sizeof(badListLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, zeroWlen,
                (word16)sizeof(zeroWlen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, overWlen,
                (word16)sizeof(overWlen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte req[] = { 0x00, 0x03, 0x02, 'h', 'i' };
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_APPLICATION_LAYER_PROTOCOL, req, (word16)sizeof(req));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Trusted CA Keys ------------------------------------------------------
 * RFC 6066 Section 6. TLSX_TCA_New()'s per-type id validation, TLSX_TCA_Find()
 * and the bounds checks in TLSX_TCA_Parse(), all server side.
 */
int test_TLSX_TCA_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && defined(HAVE_TLS_EXTENSIONS) &&  !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_SHA) && \
    !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[64];
    word16 extLen;

    /* TLSX_TCA_New(): SHA1 id of the wrong size is rejected; the right
     * size is accepted. Also the X509 name id case (any idSz > 0).
     */
#ifdef WOLFSSL_TEST_STATIC_BUILD
    {
        TLSX* extensions = NULL;
        byte id[WC_SHA_DIGEST_SIZE + 1];
        XMEMSET(id, 0x11, sizeof(id));

        ExpectIntEQ(TLSX_UseTrustedCA(&extensions,
                    WOLFSSL_TRUSTED_CA_KEY_SHA1, id, WC_SHA_DIGEST_SIZE + 1,
                    NULL), WC_NO_ERR_TRACE(MEMORY_E));
        ExpectNull(extensions);
        ExpectIntEQ(TLSX_UseTrustedCA(&extensions,
                    WOLFSSL_TRUSTED_CA_KEY_SHA1, id, WC_SHA_DIGEST_SIZE,
                    NULL), WOLFSSL_SUCCESS);
        ExpectNotNull(extensions);
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        ExpectIntEQ(TLSX_UseTrustedCA(&extensions,
                    WOLFSSL_TRUSTED_CA_X509_NAME, id, 0, NULL),
                    WC_NO_ERR_TRACE(MEMORY_E));
        ExpectNull(extensions);
        ExpectIntEQ(TLSX_UseTrustedCA(&extensions,
                    WOLFSSL_TRUSTED_CA_X509_NAME, id, 1, NULL),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(extensions);
        TLSX_FreeAll(extensions, NULL);
    }
#endif

    /* TLSX_TCA_Parse(), server side: not configured (no-op success), a
     * length-prefix mismatch, and a well-formed list that TLSX_TCA_Find()
     * matches by a pre-agreed entry (no id comparison needed).
     */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* No trusted_ca_keys configured on the server: skip, success.
         * An empty list (list length 0) is the shortest body that still
         * satisfies the extension's minimum-size gate. */
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte empty[] = { 0x00, 0x00 };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUSTED_CA_KEYS, empty,
                (word16)sizeof(empty));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        /* list length (1) does not match actual body (3 bytes follow). */
        const byte badLen[] = { 0x00, 0x01, 0x00, 0x00, 0x00 };
        /* trusted_ca_keys list: one entry, type pre_agreed(0), matches the
         * configured entry via TLSX_TCA_Find()'s type-only comparison. */
        const byte good[] = { 0x00, 0x01, WOLFSSL_TRUSTED_CA_PRE_AGREED };

        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_PRE_AGREED,
                    NULL, 0), WOLFSSL_SUCCESS);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUSTED_CA_KEYS, badLen,
                (word16)sizeof(badLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUSTED_CA_KEYS, good,
                (word16)sizeof(good));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        byte id[WC_SHA_DIGEST_SIZE];
        /* X509 name id: id length prefix claims more than remains. */
        const byte truncated[] = {
            0x00, 0x05, /* list length */
            WOLFSSL_TRUSTED_CA_X509_NAME, 0x00, 0x03, 0xAA, 0xBB
            /* idSz=3 claimed, only 2 bytes remain: offset+idSz > length. */
        };
        const byte fits[] = {
            0x00, 0x05,
            WOLFSSL_TRUSTED_CA_X509_NAME, 0x00, 0x02, 0xAA, 0xBB
        };

        XMEMSET(id, 0x33, sizeof(id));
        ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_KEY_SHA1,
                    id, sizeof(id)), WOLFSSL_SUCCESS);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUSTED_CA_KEYS,
                truncated, (word16)sizeof(truncated));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUSTED_CA_KEYS, fits,
                (word16)sizeof(fits));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Client side, response direction, trusted_ca_keys never requested:
     * unsupported extension. */
#ifndef NO_WOLFSSL_CLIENT
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_TRUSTED_CA_KEYS, NULL, 0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

/* ---- Client/Server Certificate Type (RFC 7250, raw public keys) --------- */
int test_TLSX_certtype_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_RPK) && defined(HAVE_TLS_EXTENSIONS) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[16];
    word16 extLen;

    /* IsCertTypeListed(): value present vs. absent in an offered list,
     * reached through TLSX_ClientCertificateType_Parse()'s client-side
     * (server_hello) branch. The offered-type bookkeeping is set directly,
     * mirroring what the write side records after a real ClientHello is
     * built; only the received value's parse is under test here.
     */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte respX509[] = { WOLFSSL_CERT_TYPE_X509 };
        const byte respRpk[]  = { WOLFSSL_CERT_TYPE_RPK };

        ssl->options.rpkState.sending_ClientCertTypeCnt = 1;
        ssl->options.rpkState.sending_ClientCertTypes[0] =
                WOLFSSL_CERT_TYPE_X509;

        /* offered X509, server confirms X509: listed. */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_CLIENT_CERTIFICATE,
                respX509, (word16)sizeof(respX509));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);

        /* offered X509, server claims RPK: not listed, rejected. */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_CLIENT_CERTIFICATE,
                respRpk, (word16)sizeof(respRpk));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));

        /* A count past MAX_CLIENT_CERT_TYPE_CNT is treated as not listed
         * without reading past the fixed-size offered-types array. */
        ssl->options.rpkState.sending_ClientCertTypeCnt = 5;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_CLIENT_CERTIFICATE, respX509, (word16)sizeof(respX509));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Cookie (RFC 8446 4.2.2 / DTLS 1.3 HelloRetryRequest) ---------------- */
int test_TLSX_Cookie_parse(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_SEND_HRR_COOKIE) &&  !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[16];
    word16 extLen;

    /* client_hello direction with a previously stored cookie: length/value
     * mismatch is rejected, a match is accepted. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte hrr[] = { 0x00, 0x03, 0xAA, 0xBB, 0xCC };
        const byte chBad[] = { 0x00, 0x03, 0xAA, 0xBB, 0xFF };
        const byte chGood[] = { 0x00, 0x03, 0xAA, 0xBB, 0xCC };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_COOKIE, hrr,
                (word16)sizeof(hrr));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, hello_retry_request, NULL),
                    0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_COOKIE, chBad,
                (word16)sizeof(chBad));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(HRR_COOKIE_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_COOKIE, chGood,
                (word16)sizeof(chGood));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#ifdef WOLFSSL_DTLS13
    /* DTLS 1.3: a cookie in client_hello with none stored yet and no
     * matching extension is accepted (a different SSL instance may have
     * issued it). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte ch[] = { 0x00, 0x01, 0xAA };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_COOKIE, ch,
                (word16)sizeof(ch));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

/* ---- Encrypt-Then-Mac (RFC 7366) ----------------------------------------- */
int test_TLSX_EncryptThenMac_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY) &&  !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[8];
    word16 extLen;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* server_hello, empty body: accepted. */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_ENCRYPT_THEN_MAC, NULL,
                0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Maximum Fragment Length (RFC 6066 Section 4) ------------------------ */
int test_TLSX_MFL_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MAX_FRAGMENT) && !defined(WOLFSSL_OLD_UNSUPPORTED_EXTENSION)  && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[8];
    word16 extLen;

    /* Client did not request MFL: any server_hello response is flagged as
     * an unrequested extension before the value is even looked at. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte resp[] = { WOLFSSL_MFL_2_9 };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_MAX_FRAGMENT_LENGTH,
                resp, (word16)sizeof(resp));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Client requested MFL_2_9: a mismatching echo is rejected, the same
     * value is accepted. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte mismatch[] = { WOLFSSL_MFL_2_10 };
        const byte match[] = { WOLFSSL_MFL_2_9 };

        ExpectIntEQ(wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_9),
                    WOLFSSL_SUCCESS);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_MAX_FRAGMENT_LENGTH,
                mismatch, (word16)sizeof(mismatch));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNKNOWN_MAX_FRAG_LEN_E));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_MAX_FRAGMENT_LENGTH,
                match, (word16)sizeof(match));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Truncated HMAC (RFC 6066 Section 7, deprecated) --------------------- */
int test_TLSX_THM_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUNCATED_HMAC) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[8];
    word16 extLen;

    /* Truncated HMAC is only ever dispatched to on client_hello (the
     * server side of the extension); the response direction is not
     * reachable through TLSX_Parse() at all. */
    ExpectNotNull(ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        byte dummy = 0;

        /* Non-empty body is invalid: extension_data MUST be empty. */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUNCATED_HMAC, &dummy,
                1);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        /* Empty body, valid: enables the extension for this connection. */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_TRUNCATED_HMAC, NULL,
                0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Session Ticket (RFC 5077 / RFC 8446 4.6.1) -------------------------- */
int test_TLSX_SessionTicket_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12) &&  !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL* ssl2 = NULL;
    byte ext[600];
    word16 extLen;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        /* Too short to be a real ticket: DoClientTicket() rejects it
         * without attempting decryption. */
        const byte tooShort[] = { 0x01, 0x02, 0x03, 0x04 };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SESSION_TICKET,
                tooShort, (word16)sizeof(tooShort));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(ssl->options.rejectTicket, 1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* A genuine ticket, decryptable by the ctx that issued it, but
     * presented to a connection whose negotiated version is older than
     * the ticket's: the ticket must be rejected with a version mismatch,
     * not just a generic reject. Uses its own ctx pair (test_memio_setup()
     * only wires up its I/O callbacks on a ctx it creates itself). */
    {
        struct test_memio_ctx memio;
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx2 = NULL;
        WOLFSSL* ssl_c = NULL;
        byte ticket[512];
        word32 ticketSz = (word32)sizeof(ticket);

        XMEMSET(&memio, 0, sizeof(memio));
        ExpectIntEQ(test_memio_setup(&memio, &ctx_c, &ctx2, &ssl_c, &ssl,
                    wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
        if (ssl_c != NULL)
            ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl, 10, NULL), 0);
        ExpectIntEQ(wolfSSL_get_SessionTicket(ssl_c, ticket, &ticketSz),
                    WOLFSSL_SUCCESS);
        ExpectIntGT(ticketSz, 0);

        if (EXPECT_SUCCESS() && ticketSz > 0) {
            ExpectNotNull(ssl2 = wolfSSL_new(ctx2));
            if (ssl2 != NULL) {
                Suites* suites = (Suites*)WOLFSSL_SUITES(ssl2);
                /* Force this connection to look like it negotiated a
                 * version older than the ticket's original session. */
                ssl2->version.minor = SSLv3_MINOR;
                extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SESSION_TICKET,
                        ticket, (word16)ticketSz);
                /* The internal VERSION_ERROR is caught and downgraded to a
                 * non-fatal reject, same as any other undecryptable
                 * ticket -- it does not propagate out of TLSX_Parse(). */
                ExpectIntEQ(TLSX_Parse(ssl2, ext, extLen, client_hello,
                            suites), 0);
                ExpectIntEQ(ssl2->options.rejectTicket, 1);
            }
        }
        wolfSSL_free(ssl2);
        wolfSSL_free(ssl);
        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx2);
        wolfSSL_CTX_free(ctx_c);
        ssl = NULL;
    }
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Secure Renegotiation (RFC 5746) -------------------------------------
 * ret starts at SECURE_RENEGOTIATION_E and is only touched by
 * wolfSSL_UseSecureRenegotiation()'s single allocation; forcing that
 * allocation to fail is the only way to observe a third value.
 */
int test_TLSX_SecureRenegotiation_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12) && \
    defined(USE_WOLFSSL_MEMORY) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[8 + 2 * TLS_FINISHED_SZ];
    word16 extLen;
    wolfSSL_Malloc_cb prevM = NULL;
    wolfSSL_Free_cb prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);

    /* ret stays SECURE_RENEGOTIATION_E: secure_renegotiation is already
     * set up and enabled (as if a prior renegotiation_info round trip had
     * already completed on this connection), so the allocating branch is
     * skipped, and so are the "not yet enabled" / verify-data branches
     * further down the if/else-if chain -- ret is simply never touched. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte arm[] = { 0x00 };
        /* neither 0 (the "not yet enabled" trigger) nor TLS_FINISHED_SZ. */
        const byte req[] = { 0xFF };

        ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl), WOLFSSL_SUCCESS);
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                arm, (word16)sizeof(arm));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                req, (word16)sizeof(req));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(SECURE_RENEGOTIATION_E));
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* ret == 0: a normal first-time allocation succeeds. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte req[] = { 0x00 };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                req, (word16)sizeof(req));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Force the one allocation inside TLSX_UseSecureRenegotiation() to
     * fail, so ret picks up a third, distinct value. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte req[] = { 0x00 };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                req, (word16)sizeof(req));

        ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
        ExpectIntEQ(wolfSSL_SetAllocators(tls_parse_fail_malloc,
                    tls_parse_fail_free, tls_parse_fail_realloc), 0);
        tls_parse_alloc_seen = 0;
        tls_parse_fail_after = 0;

        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(MEMORY_E));

        tls_parse_fail_after = -1;
        (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Client side response direction: *input == 2*TLS_FINISHED_SZ, but the
     * declared extension length disagrees with it -- length is the
     * second, independent half of that check. */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte full[1 + 2 * TLS_FINISHED_SZ];
        /* declares the full double-verify-data size, but is one byte
         * short of it. */
        byte shortBody[2 * TLS_FINISHED_SZ];

        XMEMSET(full, 0, sizeof(full));
        full[0] = 2 * TLS_FINISHED_SZ;
        XMEMSET(shortBody, 0, sizeof(shortBody));
        shortBody[0] = 2 * TLS_FINISHED_SZ;

        ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl), WOLFSSL_SUCCESS);
        ssl->secure_renegotiation->enabled = 1;

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                shortBody, (word16)sizeof(shortBody));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(SECURE_RENEGOTIATION_E));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_RENEGOTIATION_INFO,
                full, (word16)sizeof(full));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Supported Versions (RFC 8446 4.2.1) --------------------------------- */
int test_TLSX_SupportedVersions_parse(void)
{
    EXPECT_DECLS;
    /* TLSX_Parse()'s own per-extension dispatch never reaches
     * TLSX_SupportedVersions_Parse(): supported_versions is scanned and
     * consumed by TLSX_ParseVersion() in an earlier pass (it must be known
     * before any other extension can be interpreted), and the main loop's
     * TLSX_SUPPORTED_VERSIONS case only re-validates the message type.
     * WOLFSSL_LOCAL: called directly (guarded). */
#if defined(WOLFSSL_TLS13) && !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER)  && !defined(NO_WOLFSSL_CLIENT) && defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[8 + MAX_SV_EXT_LEN];
    word16 extLen;
    int found;

    /* client_hello direction, server side: the three independent ways the
     * body can fail the initial length sanity check. */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* length (2) < OPAQUE8_LEN + OPAQUE16_LEN (3): too short. */
        const byte tooShort[] = { 0x02, 0x03 };
        /* even length: fails (length & 1) != 1. list len byte says 2, but
         * total length here is even (4). */
        const byte evenLen[] = { 0x02, 0x03, 0x04, 0x00 };
        /* well-formed, single TLS 1.3 entry. */
        const byte good[] = { 0x02, 0x03, TLSv1_3_MINOR };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS,
                tooShort, (word16)sizeof(tooShort));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, client_hello,
                    &found), WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS,
                evenLen, (word16)sizeof(evenLen));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, client_hello,
                    &found), WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS,
                good, (word16)sizeof(good));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, client_hello,
                    &found), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* An over-long list also fails on its own: odd total length (so the
     * parity check already passes) but still over MAX_SV_EXT_LEN. */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte body[MAX_SV_EXT_LEN + 2];
        word16 i;

        body[0] = (byte)(MAX_SV_EXT_LEN + 1);
        for (i = 1; i < sizeof(body); i += 2) {
            body[i] = SSLv3_MAJOR;
            body[i + 1] = TLSv1_3_MINOR;
        }
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS,
                body, (word16)sizeof(body));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, client_hello,
                    &found), WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* server_hello / hello_retry_request direction, client side. */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte v[] = { SSLv3_MAJOR, TLSv1_3_MINOR };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS, v,
                (word16)sizeof(v));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, server_hello,
                    &found), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte v[] = { SSLv3_MAJOR, TLSv1_3_MINOR };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS, v,
                (word16)sizeof(v));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, hello_retry_request,
                    &found), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* Neither client_hello, server_hello nor hello_retry_request. */
        const byte v[] = { SSLv3_MAJOR, TLSv1_3_MINOR };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS, v,
                (word16)sizeof(v));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, finished, &found),
                    WC_NO_ERR_TRACE(SANITY_MSG_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Downgrade bookkeeping: ssl->options.downgrade set and the connection
     * already sitting at TLS 1.2 minor -- vs. either being false. */
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte v[] = { SSLv3_MAJOR, TLSv1_3_MINOR };
        ssl->options.downgrade = 1;
        ssl->version.minor = TLSv1_2_MINOR;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS, v,
                (word16)sizeof(v));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, server_hello,
                    &found), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* downgrade left false and version.minor left at its default
         * (TLS 1.3): the "no upgrade allowed" check right after this one
         * would otherwise reject a version.minor that was forced down
         * without downgrade being set. */
        const byte v[] = { SSLv3_MAJOR, TLSv1_3_MINOR };
        ssl->options.downgrade = 0;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_VERSIONS, v,
                (word16)sizeof(v));
        ExpectIntEQ(TLSX_ParseVersion(ssl, ext, extLen, server_hello,
                    &found), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Signature Algorithms (RFC 8446 4.2.3) ------------------------------- */
int test_TLSX_SignatureAlgorithms_parse(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(WOLFSSL_NO_SIGALG) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) &&  (!defined(NO_RSA) || defined(HAVE_ECC)) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[16];
    word16 extLen;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        /* length (3) < OPAQUE16_LEN*2 (4): too short. */
        const byte tooShort[] = { 0x00, 0x02, 0x04 };
        /* odd overall length: fails (length & 1) != 0. */
        const byte oddLen[] = { 0x00, 0x02, 0x04, 0x03, 0x00 };
        /* well-formed, one algorithm. */
        const byte good[] = { 0x00, 0x02, 0x04, 0x03 };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SIGNATURE_ALGORITHMS,
                tooShort, (word16)sizeof(tooShort));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SIGNATURE_ALGORITHMS,
                oddLen, (word16)sizeof(oddLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SIGNATURE_ALGORITHMS,
                good, (word16)sizeof(good));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#if !defined(NO_RSA) && defined(HAVE_TLS_EXTENSIONS) && defined(WOLFSSL_TLS13)
    /* SignatureAlgorithmsCert: same length checks, separate extension.
     * Only dispatched to on a TLS 1.3+ connection. */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte tooShort[] = { 0x00, 0x02, 0x04 };
        /* long enough, but an odd total length. */
        const byte oddLen[] = { 0x00, 0x02, 0x04, 0x03, 0x00 };
        const byte good[] = { 0x00, 0x02, 0x04, 0x03 };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_SIGNATURE_ALGORITHMS_CERT, tooShort,
                (word16)sizeof(tooShort));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_SIGNATURE_ALGORITHMS_CERT, oddLen,
                (word16)sizeof(oddLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext),
                TLSXT_SIGNATURE_ALGORITHMS_CERT, good,
                (word16)sizeof(good));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* TLSX_SignatureAlgorithms_MapPss(): rsa_pss_sa_algo entries whose
     * second byte is within [pss_sha256, pss_sha512] vs. just above it,
     * both already >= pss_sha256. Reached via the plain SignatureAlgorithms
     * extension's TLS 1.3 PSS-with-SHA remap. */
#ifdef WOLFSSL_TLS13
    ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte inRange[] = { 0x00, 0x02, rsa_pss_sa_algo, pss_sha512 };
        const byte aboveRange[] = {
            0x00, 0x02, rsa_pss_sa_algo, (byte)(pss_sha512 + 1)
        };

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SIGNATURE_ALGORITHMS,
                inRange, (word16)sizeof(inRange));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SIGNATURE_ALGORITHMS,
                aboveRange, (word16)sizeof(aboveRange));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
#endif
#endif
    return EXPECT_RESULT();
}

/* ---- Certificate Status Request / v2 (RFC 6066 8, RFC 6961) -------------- */
int test_TLSX_CSR_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12) && \
    defined(USE_WOLFSSL_MEMORY)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[32];
    word16 extLen;

    /* Server side: not able to staple (no OCSP stapling enabled) skips
     * rather than failing. */
    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte req[] = {
            WOLFSSL_CSR_OCSP,
            0x00, 0x00, /* responder_id_list, empty */
            0x00, 0x00  /* request_extensions, empty */
        };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST, req,
                (word16)sizeof(req));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Same request, but with OCSP stapling enabled on the ctx: taken. */
    ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx), WOLFSSL_SUCCESS);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte req[] = {
            WOLFSSL_CSR_OCSP,
            0x00, 0x00,
            0x00, 0x00
        };
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST, req,
                (word16)sizeof(req));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#if defined(WOLFSSL_TLS13) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES)
    /* Client side, TLS 1.3 certificate direction (RFC 8446 4.4.2): the OCSP
     * response TLV's status_type and length bookkeeping. */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte respBadType[] = {
            0x00, /* status_type: not WOLFSSL_CSR_OCSP */
            0x00, 0x00, 0x00 /* 24-bit response length: 0 */
        };

        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
                    WOLFSSL_SUCCESS);
        /* This synthetic parse never ran a real handshake, so the
         * negotiated-TLS-1.3 flag was never set by version negotiation. */
        ssl->options.tls1_3 = 1;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST,
                respBadType, (word16)sizeof(respBadType));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, certificate, NULL),
                    WC_NO_ERR_TRACE(BAD_CERTIFICATE_STATUS_ERROR));
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* Too short even for the status_type byte and the 24-bit response
         * length: rejected before the status_type byte is looked at. */
        const byte tooShort[] = { 0x00, 0x00, 0x00 };

        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
                    WOLFSSL_SUCCESS);
        ssl->options.tls1_3 = 1;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST,
                tooShort, (word16)sizeof(tooShort));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, certificate, NULL),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte respGood[] = {
            WOLFSSL_CSR_OCSP,
            0x00, 0x00, 0x01,
            0xAA
        };
        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
                    WOLFSSL_SUCCESS);
        ssl->options.tls1_3 = 1;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST,
                respGood, (word16)sizeof(respGood));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, certificate, NULL),
                    0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* The response buffer allocation: response_idx is always 0 at this
     * point in a synthetic parse (no prior certificate chain was
     * processed), so a real handshake is not needed to force a memory
     * failure at that one allocation. */
#ifdef WOLFSSL_TEST_STATIC_BUILD
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const byte respGood[] = {
            WOLFSSL_CSR_OCSP,
            0x00, 0x00, 0x01,
            0xAA
        };
        wolfSSL_Malloc_cb prevM = NULL;
        wolfSSL_Free_cb prevF = NULL;
        wolfSSL_Realloc_cb prevR = NULL;

        ExpectIntEQ(wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP, 0),
                    WOLFSSL_SUCCESS);
        ssl->options.tls1_3 = 1;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_STATUS_REQUEST,
                respGood, (word16)sizeof(respGood));

        ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
        ExpectIntEQ(wolfSSL_SetAllocators(tls_parse_fail_malloc,
                    tls_parse_fail_free, tls_parse_fail_realloc), 0);
        tls_parse_alloc_seen = 0;
        tls_parse_fail_after = 0;

        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, certificate, NULL),
                    WC_NO_ERR_TRACE(MEMORY_ERROR));

        tls_parse_fail_after = -1;
        (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
    }
    wolfSSL_free(ssl);
    ssl = NULL;
#endif
    wolfSSL_CTX_free(ctx);
#endif /* WOLFSSL_TLS13 && HAVE_SSL_MEMIO_TESTS_DEPENDENCIES */
#endif

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_SERVER)
    {
        WOLFSSL_CTX* ctx2 = test_tls_parse_server_ctx(
                wolfTLSv1_2_server_method());
        WOLFSSL* ssl2 = NULL;
        byte ext2[16];
        word16 ext2Len;
        /* One status_request_v2 entry: type OCSP, empty responder_id_list
         * and empty request_extensions. */
        const byte req[] = {
            0x00, 0x07, /* overall list length */
            WOLFSSL_CSR2_OCSP,
            0x00, 0x04, /* this entry's length */
            0x00, 0x00, /* responder_id_list, empty */
            0x00, 0x00  /* request_extensions, empty */
        };

        ExpectNotNull(ctx2);

        /* No OCSP stapling enabled: this entry is skipped (continue). */
        if (ctx2 != NULL)
            ExpectNotNull(ssl2 = wolfSSL_new(ctx2));
        if (ssl2 != NULL) {
            Suites* suites = (Suites*)WOLFSSL_SUITES(ssl2);
            ext2Len = test_tls_parse_build_ext(ext2, sizeof(ext2), TLSXT_STATUS_REQUEST_V2,
                    req, (word16)sizeof(req));
            ExpectIntEQ(TLSX_Parse(ssl2, ext2, ext2Len, client_hello,
                        suites), 0);
        }
        wolfSSL_free(ssl2);
        ssl2 = NULL;

        /* OCSP stapling enabled: the entry is used. */
        ExpectIntEQ(wolfSSL_CTX_EnableOCSPStapling(ctx2), WOLFSSL_SUCCESS);
        if (ctx2 != NULL)
            ExpectNotNull(ssl2 = wolfSSL_new(ctx2));
        if (ssl2 != NULL) {
            Suites* suites = (Suites*)WOLFSSL_SUITES(ssl2);
            ext2Len = test_tls_parse_build_ext(ext2, sizeof(ext2), TLSXT_STATUS_REQUEST_V2,
                    req, (word16)sizeof(req));
            ExpectIntEQ(TLSX_Parse(ssl2, ext2, ext2Len, client_hello,
                        suites), 0);
        }
        wolfSSL_free(ssl2);
        wolfSSL_CTX_free(ctx2);
    }
#endif
    return EXPECT_RESULT();
}

/* ---- EC Point Formats (RFC 8422 5.1.2) ----------------------------------- */
int test_TLSX_PointFormat_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && !defined(NO_TLS) &&  !defined(NO_WOLFSSL_SERVER) &&  (!defined(NO_RSA) || defined(HAVE_ECC)) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[16];
    word16 extLen;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        /* list length byte (2) disagrees with the actual body length (2
         * total, 1 format byte). */
        const byte badLen[] = { 0x02, WOLFSSL_EC_PF_UNCOMPRESSED };
        /* well formed: one format, uncompressed. */
        const byte good[] = { 0x01, WOLFSSL_EC_PF_UNCOMPRESSED };

        /* length (0) < ENUM_LEN (1). */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_EC_POINT_FORMATS, NULL,
                0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_EC_POINT_FORMATS,
                badLen, (word16)sizeof(badLen));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_EC_POINT_FORMATS,
                good, (word16)sizeof(good));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES) && \
    !defined(WOLFSSL_NO_SERVER_GROUPS_EXT) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_TEST_STATIC_BUILD)
    /* TLSX_SupportedCurve_Preferred(): checkSupported gating and the
     * TLSX_IsGroupSupported() result, driven by a raw (unfiltered) offered
     * groups list -- TLSX_SupportedCurve_Parse() records whatever the peer
     * sent, support is only checked later by this function. A TLS 1.2
     * server ssl is used so RFC 8446 9.2's "KeyShare requires
     * SupportedGroups and vice-versa" check does not apply; the function
     * under test does not itself depend on the negotiated version. */
    {
        WOLFSSL_CTX* ctxp = test_tls_parse_server_ctx(
                wolfTLSv1_2_server_method());
        WOLFSSL* sslp = NULL;

        ExpectNotNull(ctxp);
        if (ctxp != NULL)
            ExpectNotNull(sslp = wolfSSL_new(ctxp));
#if !defined(NO_DH) && !defined(WOLFSSL_NO_TLS12)
        if (sslp != NULL) {
            Suites* suites = (Suites*)WOLFSSL_SUITES(sslp);
            /* An FFDHE codepoint this build does not have enabled (only
             * WOLFSSL_FFDHE_2048 is): recorded with its real group id
             * per RFC 7919 Section 4, but TLSX_IsGroupSupported() is false
             * for it -- unlike a non-FFDHE unrecognised id, which is
             * recorded as an empty (data == NULL) restriction instead. */
            const byte groups[] = { 0x00, 0x02, 0x01, 0x01 }; /* FFDHE 3072 */

            extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                    groups, (word16)sizeof(groups));
            ExpectIntEQ(TLSX_Parse(sslp, ext, extLen, client_hello, suites),
                        0);

            ExpectIntEQ(TLSX_SupportedCurve_Preferred(sslp, 0),
                        WOLFSSL_FFDHE_3072);
#ifdef HAVE_FFDHE_3072
            /* The group is in the supported set here, so the first entry is
             * returned rather than skipped. */
            ExpectIntEQ(TLSX_SupportedCurve_Preferred(sslp, 1),
                        WOLFSSL_FFDHE_3072);
#else
            ExpectIntEQ(TLSX_SupportedCurve_Preferred(sslp, 1),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
        }
#endif
        wolfSSL_free(sslp);
        sslp = NULL;
        if (ctxp != NULL)
            ExpectNotNull(sslp = wolfSSL_new(ctxp));
        if (sslp != NULL) {
#ifdef HAVE_CURVE25519
            Suites* suites = (Suites*)WOLFSSL_SUITES(sslp);
            const byte groups[] = { 0x00, 0x02, 0x00, 0x1D }; /* X25519 */

            extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                    groups, (word16)sizeof(groups));
            ExpectIntEQ(TLSX_Parse(sslp, ext, extLen, client_hello, suites),
                        0);
            ExpectIntEQ(TLSX_SupportedCurve_Preferred(sslp, 1),
                        WOLFSSL_ECC_X25519);
#endif
        }
        wolfSSL_free(sslp);
        wolfSSL_CTX_free(ctxp);
    }
#endif

#if defined(HAVE_SUPPORTED_CURVES) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_SERVER) && defined(WOLFSSL_TEST_STATIC_BUILD)
    /* TLSX_PointFormat_ValidateResponse(): reached while sizing/writing a
     * ServerHello, through the WOLFSSL_LOCAL TLSX_GetResponseSize() rather
     * than TLSX_Parse() (there is no wire input on this side). A cipher
     * suite whose first byte is ECDHE_PSK_BYTE takes the same "already
     * covered by the peer's key exchange, do not also send point formats"
     * path as ECC_BYTE/CHACHA_BYTE. */
    {
        WOLFSSL_CTX* ctxr = test_tls_parse_server_ctx(
                wolfTLSv1_2_server_method());
        WOLFSSL* sslr = NULL;

        ExpectNotNull(ctxr);
        if (ctxr != NULL)
            ExpectNotNull(sslr = wolfSSL_new(ctxr));
        if (sslr != NULL) {
            word16 length = 0;

            ExpectIntEQ(TLSX_UsePointFormat(&sslr->extensions,
                        WOLFSSL_EC_PF_UNCOMPRESSED, sslr->heap),
                        WOLFSSL_SUCCESS);
            {
                TLSX* pf = TLSX_Find(sslr->extensions, TLSX_EC_POINT_FORMATS);
                ExpectNotNull(pf);
                if (pf != NULL)
                    pf->resp = 1;
            }
            sslr->options.cipherSuite0 = ECDHE_PSK_BYTE;
            ExpectIntEQ(TLSX_GetResponseSize(sslr, server_hello, &length),
                        0);
            /* Early return leaves the suppression semaphore untouched, so
             * the extension is still included (unlike a cipher suite that
             * falls all the way through to the TURN_ON() at the end). */
            ExpectIntGT(length, 0);
        }
        wolfSSL_free(sslr);
        wolfSSL_CTX_free(ctxr);
    }
#endif
    return EXPECT_RESULT();
}

/* ---- Server Name Indication (RFC 6066 Section 3) ------------------------- */
int test_TLSX_SNI_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER) &&  (!defined(NO_RSA) || defined(HAVE_ECC)) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte ext[64];
    word16 extLen;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);

    /* server_name_list length disagreements: total-length mismatch and
     * zero-length list, then a well-formed one-entry list. SNI must be
     * configured on the server for the match logic below it to run. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const char* host = "example.com";
        /* list length (5) does not match the 6 bytes that actually follow
         * it. */
        const byte lenMismatch[] = {
            0x00, 0x05, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
        };
        /* [server_name_list length(2)][name_type(1)][name length(2)][name] */
        byte good[2 + 1 + 2 + 11];
        word16 off = 2;

        ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                    (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME,
                lenMismatch, (word16)sizeof(lenMismatch));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        good[off++] = WOLFSSL_SNI_HOST_NAME;
        good[off++] = 0x00; good[off++] = 11;
        XMEMCPY(good + off, host, 11);
        off += 11;
        good[0] = 0x00; good[1] = (byte)(off - 2); /* list length */
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, good, off);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Host-name length disagreements within an otherwise valid list: the
     * declared name length runs past the extension body, and a
     * zero-length name. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const char* host = "example.com";
        byte truncated[2 + 1 + 2 + 11];
        byte zeroName[2 + 1 + 2];
        word16 off;

        ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                    (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);

        off = 2;
        truncated[off++] = WOLFSSL_SNI_HOST_NAME;
        /* claim a name length of 12 (one more than provided). */
        truncated[off++] = 0x00; truncated[off++] = 12;
        XMEMCPY(truncated + off, host, 11);
        off += 11;
        truncated[0] = 0x00; truncated[1] = (byte)(off - 2);
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, truncated,
                off);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));

        off = 2;
        zeroName[off++] = WOLFSSL_SNI_HOST_NAME;
        zeroName[off++] = 0x00; zeroName[off++] = 0x00;
        zeroName[0] = 0x00; zeroName[1] = (byte)(off - 2);
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, zeroName,
                off);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#ifndef NO_WOLFSSL_CLIENT
    /* Client side response direction: SNI configured (extension and its
     * data both present) accepts the empty echo; a non-empty echo is
     * rejected. */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        const char* host = "example.com";
        byte extra = 0;

        ExpectIntEQ(wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
                    (word16)XSTRLEN(host)), WOLFSSL_SUCCESS);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, NULL, 0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL), 0);

        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, &extra, 1);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Client side, SNI not requested at all: response is an unsupported
     * extension. */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    ExpectNotNull(ctx);
    ssl = NULL;
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SERVER_NAME, NULL, 0);
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, server_hello, NULL),
                    WC_NO_ERR_TRACE(UNSUPPORTED_EXTENSION));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* !NO_WOLFSSL_CLIENT */
#endif
    return EXPECT_RESULT();
}

/* ---- TLSX_ValidateSupportedCurves() -------------------------------------
 * Cipher-suite/curve compatibility check used while building a ServerHello.
 * WOLFSSL_LOCAL: called directly (guarded), with a supported_groups list
 * built by parsing a raw ClientHello extension body -- that path records
 * whatever the peer sent without filtering for local support, which is
 * what lets a specific curve be selected precisely for this test.
 */
int test_TLSX_ValidateSupportedCurves(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) ||  defined(HAVE_CURVE448)) && defined(HAVE_SUPPORTED_CURVES) &&  !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && defined(HAVE_CURVE25519) &&  defined(HAVE_CURVE448) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    word32 oid;
    byte ext[16];
    word16 extLen;

    ctx = test_tls_parse_server_ctx(wolfTLSv1_2_server_method());
    ExpectNotNull(ctx);

    /* first != {ECC_BYTE, ECDHE_PSK_BYTE, CHACHA_BYTE}: no restriction,
     * independent of any configured groups. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, 0x00, 0x00, &oid), 1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* first == ECDHE_PSK_BYTE: takes the same restriction-lookup branch as
     * ECC_BYTE/CHACHA_BYTE. No supported_groups configured: still no
     * restriction, but by way of the extension == NULL check instead of
     * skipping the lookup outright. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECDHE_PSK_BYTE, 0x00,
                    &oid), 1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* first == ECC_BYTE, with a supported_groups list offering X25519
     * then X448: exercises the X25519/X448 default-case defOid reset
     * (second entry is not the one that set defOid). */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = {
            0x00, 0x04,
            0x00, 0x1D, /* X25519 */
            0x00, 0x1E  /* X448 */
        };
        ssl->eccTempKeySz = 0;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        /* second == some value not matched by any explicit ECC_BYTE case
         * (no ECDHE_ECDSA/ECDHE_RSA cipher id): falls to "default". */
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Single-entry X25519 list: defOid gets set to X25519 by the first
     * curve seen, and the default-case reset then fires for that very
     * entry (oid == defOid). */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x1D };
        ssl->eccTempKeySz = 0;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* eccTempKeySz larger than any real curve size: the "set default",
     * "current" and "next" bookkeeping (all gated on eccTempKeySz <=
     * octets, or == for current) never fires for any offered curve, so
     * ecdhCurveOID is never resolved away from 0 -- the ephemeral-suite
     * rejection at the very end is reached with *ecdhCurveOID still 0
     * (index 0), but a "default" (non-ECDHE_ECDSA/RSA) second byte never
     * sets ephmSuite (index 1 false). */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x17 }; /* secp256r1 */
        ssl->eccTempKeySz = 100;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* Same eccTempKeySz, but second is a real ECDHE_ECDSA suite id:
     * ephmSuite is now set (index 1 true) while *ecdhCurveOID is still 0
     * (index 0 true, same as above) -- the suite is rejected outright. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x17 };
        ssl->eccTempKeySz = 100;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE,
                    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, &oid), 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* eccTempKeySz back to the default (0) with the same real ECDHE_ECDSA
     * suite id: *ecdhCurveOID does resolve away from 0 this time (via the
     * "next highest strength" fallback), so the rejection at the end is
     * never reached (index 0 false, index 1 held true as above). */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x17 };
        ssl->eccTempKeySz = 0;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE,
                    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, &oid), 1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* X25519 alone, eccTempKeySz larger than its octets: the "set default"
     * assignment at the top of the loop body does not fire for this entry
     * (same eccTempKeySz <= octets gate as the 5963 case above), so defOid
     * is still 0 -- not equal to this entry's own (non-zero) oid -- when
     * the default-case reset check runs. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x1D }; /* X25519 */
        ssl->eccTempKeySz = 100;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* X448 alone, same oversized eccTempKeySz shape: the X448 counterpart
     * of the X25519 case just above. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x1E }; /* X448 */
        ssl->eccTempKeySz = 100;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    /* X448 alone: defOid gets set to X448 by the first (and only) curve
     * seen, and the default-case reset then fires for that very entry
     * (oid == defOid) -- the X448 counterpart of the X25519-alone case
     * above. */
    if (ctx != NULL)
        ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        Suites* suites = (Suites*)WOLFSSL_SUITES(ssl);
        const byte groups[] = { 0x00, 0x02, 0x00, 0x1E }; /* X448 */
        ssl->eccTempKeySz = 0;
        extLen = test_tls_parse_build_ext(ext, sizeof(ext), TLSXT_SUPPORTED_GROUPS,
                groups, (word16)sizeof(groups));
        ExpectIntEQ(TLSX_Parse(ssl, ext, extLen, client_hello, suites), 0);
        ExpectIntEQ(TLSX_ValidateSupportedCurves(ssl, ECC_BYTE, 0xFF, &oid),
                    1);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Supported Groups (RFC 8422 Section 5.1.1 / RFC 8446 4.2.7) --------- */
/* TLSX_SupportedCurve_Parse() is dispatched to only for client_hello (and,
 * on TLS 1.3, encrypted_extensions) through TLSX_Parse(); the server_hello
 * direction it itself validates is never reached that way, so it is called
 * directly here (WOLFSSL_LOCAL). */
int test_TLSX_SupportedGroups_parse(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && defined(WOLFSSL_TLS13) &&  !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(WOLFSSL_NO_TLS12) && \
    defined(USE_WOLFSSL_MEMORY) && \
    !defined(NO_DH) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* secp256r1: a real, locally supported curve. */
    const byte goodBody[] = { 0x00, 0x02, 0x00, 0x17 };

    /* server_hello direction, pre-TLS-1.3: rejected before the body is
     * looked at (this build does not define WOLFSSL_ALLOW_SERVER_SC_EXT). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, goodBody,
                    (word16)sizeof(goodBody), 0, &extensions),
                    WC_NO_ERR_TRACE(BUFFER_ERROR));
        ExpectNull(extensions);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* server_hello direction, TLS 1.3: the version half of the guard no
     * longer applies, so parsing proceeds. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, goodBody,
                    (word16)sizeof(goodBody), 0, &extensions), 0);
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* A single FFDHE-range group id this build has no key size table
         * for (only WOLFSSL_FFDHE_2048 is compiled in): tolerated as
         * BAD_FUNC_ARG from TLSX_UseSupportedCurve(), and on the response
         * direction (isRequest == 0) the RFC 7919 restriction bookkeeping
         * further down is skipped entirely -- it exists only for a server
         * recording what a client offered. */
        {
            const byte ffdheUnknown[] = { 0x00, 0x02, 0x01, 0x05 };
            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, ffdheUnknown,
                        (word16)sizeof(ffdheUnknown), 0, &extensions), 0);
            ExpectNull(extensions);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* client_hello direction is never checked against the version; a TLS
     * 1.2 connection reaches the same body parsing as above. Also the
     * first, "accept whatever the peer wants" shape (no local restriction
     * configured): a single well-known, supported curve is recorded. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;

        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, goodBody,
                    (word16)sizeof(goodBody), 1, &extensions), 0);
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* Odd total length fails the OPAQUE16_LEN modulus check (the
         * length-too-short half is exercised elsewhere already). */
        {
            const byte oddLen[] = { 0x00, 0x01, 0x17 };
            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, oddLen,
                        (word16)sizeof(oddLen), 1, &extensions),
                        WC_NO_ERR_TRACE(BUFFER_ERROR));
            ExpectNull(extensions);
        }

        /* Same unknown FFDHE id, as a client_hello (isRequest == 1):
         * recorded as an explicit (non-empty) restriction so DHE suite
         * selection still sees the offer. */
        {
            const byte ffdheUnknown[] = { 0x00, 0x02, 0x01, 0x05 };
            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, ffdheUnknown,
                        (word16)sizeof(ffdheUnknown), 1, &extensions), 0);
            ExpectNotNull(extensions);
        }
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* A single group id above the FFDHE range entirely: also
         * BAD_FUNC_ARG, but not FFDHE, so no restriction is recorded for
         * it specifically -- yet since it is the only (unsupported) group
         * offered, the list is still empty afterwards and the "record an
         * empty restriction" fallback fires. */
        {
            const byte aboveFfdhe[] = { 0x00, 0x02, 0x02, 0x58 };
            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, aboveFfdhe,
                        (word16)sizeof(aboveFfdhe), 1, &extensions), 0);
            ExpectNotNull(extensions);
        }
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

#ifdef WOLFSSL_TEST_STATIC_BUILD
        /* First entry is a real, supported curve, but its allocation is
         * forced to fail: a distinct error (neither WOLFSSL_SUCCESS nor
         * BAD_FUNC_ARG) that aborts the scan immediately. */
        {
            wolfSSL_Malloc_cb prevM = NULL;
            wolfSSL_Free_cb prevF = NULL;
            wolfSSL_Realloc_cb prevR = NULL;

            ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
            ExpectIntEQ(wolfSSL_SetAllocators(tls_parse_fail_malloc,
                        tls_parse_fail_free, tls_parse_fail_realloc), 0);
            tls_parse_alloc_seen = 0;
            tls_parse_fail_after = 0;

            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, goodBody,
                        (word16)sizeof(goodBody), 1, &extensions),
                        WC_NO_ERR_TRACE(MEMORY_E));

            tls_parse_fail_after = -1;
            (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
            ExpectNull(extensions);
        }
#endif
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Second shape: a local restriction is already configured (as if from
     * wolfSSL_CTX_set1_groups_list()), so parsing intersects the peer's
     * list against it instead of accepting it outright. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;
        const byte noMatch261[] = { 0x00, 0x02, 0x01, 0x05 };
        const byte noMatch100[] = { 0x00, 0x02, 0x00, 0x64 };
        const byte noMatch600[] = { 0x00, 0x02, 0x02, 0x58 };
        const byte noMatch256[] = { 0x00, 0x02, 0x01, 0x00 };

        /* client_hello, offered group in the FFDHE range but not one this
         * build knows: no match against the local restriction, but the
         * restriction bookkeeping records it anyway. */
        ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                    WOLFSSL_ECC_SECP256R1, ssl->heap, ssl->options.side),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, noMatch261,
                    (word16)sizeof(noMatch261), 1, &extensions), 0);
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* client_hello, offered group below the FFDHE range: not FFDHE,
         * no match, nothing recorded for it -- no common curve, and this
         * connection is not TLS 1.3, so that is a hard error. */
        ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                    WOLFSSL_ECC_SECP256R1, ssl->heap, ssl->options.side),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, noMatch100,
                    (word16)sizeof(noMatch100), 1, &extensions),
                    WC_NO_ERR_TRACE(ECC_CURVE_ERROR));
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* client_hello, offered group above the FFDHE range: same as
         * below-range, not FFDHE. */
        ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                    WOLFSSL_ECC_SECP256R1, ssl->heap, ssl->options.side),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, noMatch600,
                    (word16)sizeof(noMatch600), 1, &extensions),
                    WC_NO_ERR_TRACE(ECC_CURVE_ERROR));
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        /* client_hello, offered group is WOLFSSL_FFDHE_2048 (0x0100): in
         * range, but this build does support it, so the "unsupported
         * FFDHE codepoint" restriction bookkeeping does not apply to it
         * either -- it just is not in the local restriction's curve list. */
        ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                    WOLFSSL_ECC_SECP256R1, ssl->heap, ssl->options.side),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, noMatch256,
                    (word16)sizeof(noMatch256), 1, &extensions),
                    WC_NO_ERR_TRACE(ECC_CURVE_ERROR));
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

#ifdef WOLFSSL_TEST_STATIC_BUILD
        /* Offered group matches the local restriction, but recording it
         * in the intersection list is forced to fail: a non-zero ret
         * reaches the "no common curve" check below without commonCurves
         * ever becoming non-NULL through the normal path. */
        {
            wolfSSL_Malloc_cb prevM = NULL;
            wolfSSL_Free_cb prevF = NULL;
            wolfSSL_Realloc_cb prevR = NULL;

            ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                        WOLFSSL_ECC_SECP256R1, ssl->heap,
                        ssl->options.side), WOLFSSL_SUCCESS);

            ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
            ExpectIntEQ(wolfSSL_SetAllocators(tls_parse_fail_malloc,
                        tls_parse_fail_free, tls_parse_fail_realloc), 0);
            tls_parse_alloc_seen = 0;
            tls_parse_fail_after = 0;

            ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, goodBody,
                        (word16)sizeof(goodBody), 1, &extensions),
                        WC_NO_ERR_TRACE(MEMORY_E));

            tls_parse_fail_after = -1;
            (void)wolfSSL_SetAllocators(prevM, prevF, prevR);
            TLSX_FreeAll(extensions, NULL);
        }
#endif
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Same restriction shape, response direction: needs a TLS 1.3
     * connection to get past the version guard tested first (a TLS 1.2
     * connection would be rejected before the body is even looked at).
     * The FFDHE restriction bookkeeping is for a server reading a
     * ClientHello only, so it is skipped regardless of the offered
     * group. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;
        const byte noMatch261[] = { 0x00, 0x02, 0x01, 0x05 };

        ExpectIntEQ(TLSX_UseSupportedCurve(&extensions,
                    WOLFSSL_ECC_SECP256R1, ssl->heap, ssl->options.side),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(TLSX_SupportedCurve_Parse(ssl, noMatch261,
                    (word16)sizeof(noMatch261), 0, &extensions), 0);
        TLSX_FreeAll(extensions, NULL);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Key Share negotiation (RFC 8446 4.2.8) ------------------------------
 * TLSX_KeyShare_Choose(), TLSX_KeyShare_Setup() and
 * TLSX_KeyShare_Parse_ClientHello() are WOLFSSL_LOCAL: called directly here
 * (guarded), with a client list built by hand for the shapes that would be
 * awkward to reach through a real handshake.
 */
int test_TLSX_KeyShare_negotiate(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES) &&  !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* TLSX_KeyShare_Choose(): ssl == NULL / wrong side argument guard. */
    {
        KeyShareEntry* kse = NULL;
        byte searched = 0;

        ExpectIntEQ(TLSX_KeyShare_Choose(NULL, NULL, 0, 0, &kse, &searched),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;
        byte searched = 0;
        /* Right type, wrong side: a client-side ssl. */
        ExpectIntEQ(TLSX_KeyShare_Choose(ssl, ssl->extensions, 0, 0, &kse,
                    &searched), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;
        byte searched = 0;
        /* Both false: right side, no KeyShare extension at all -- an empty
         * candidate list, not an error. */
        ExpectIntEQ(TLSX_KeyShare_Choose(ssl, ssl->extensions, 0, 0, &kse,
                    &searched), 0);
        ExpectIntEQ(searched, 1);
        ExpectNull(kse);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* TLSX_KeyShare_Choose(): extension->resp == 1 means a server key share
     * was already chosen (e.g. after a HelloRetryRequest) -- outside of
     * async key generation this is state that should not recur. */
    ExpectNotNull(ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extension = NULL;
        KeyShareEntry* kse = NULL;
        byte searched = 0;

        ExpectIntEQ(TLSX_Push(&ssl->extensions, TLSX_KEY_SHARE, NULL,
                    ssl->heap), 0);
        extension = TLSX_Find(ssl->extensions, TLSX_KEY_SHARE);
        ExpectNotNull(extension);
        if (extension != NULL)
            extension->resp = 1;
        ExpectIntEQ(TLSX_KeyShare_Choose(ssl, ssl->extensions, 0, 0, &kse,
                    &searched), WC_NO_ERR_TRACE(INCOMPLETE_DATA));

        /* Same extension, resp == 0: falls through to the normal search
         * instead (an empty list here too, since data is NULL). */
        if (extension != NULL)
            extension->resp = 0;
        searched = 0;
        ExpectIntEQ(TLSX_KeyShare_Choose(ssl, ssl->extensions, 0, 0, &kse,
                    &searched), 0);
        ExpectIntEQ(searched, 1);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

#ifdef WOLFSSL_HAVE_MLKEM
    /* TLSX_KeyShare_Choose(): a client-offered group above WOLFSSL_ECC_MAX
     * is only kept as a candidate when it is a recognised PQC or PQC
     * hybrid group id -- anything else in that numeric space is skipped.
     * All three group ids below are recorded as a matching
     * supported_groups entry directly (bypassing the "is this build
     * capable of it" gate TLSX_UseSupportedCurve() would apply), exactly
     * as TLSX_SupportedCurve_Parse() would record whatever id a peer
     * offered. */
    {
        static const word16 groupIds[] = {
            WOLFSSL_ML_KEM_512,       /* pure PQC: !IS_PQC is false */
            WOLFSSL_SECP256R1MLKEM768,/* hybrid: !IS_PQC true, !IS_HYBRID false */
            0xBEEF                    /* neither: both operands true */
        };
        size_t i;

        for (i = 0; i < sizeof(groupIds) / sizeof(groupIds[0]); i++) {
            KeyShareEntry* kse = NULL;
            byte searched = 0;

            ExpectNotNull(ctx = test_tls_parse_server_ctx(
                        wolfTLSv1_3_server_method()));
            ExpectNotNull(ssl = wolfSSL_new(ctx));
            if (ssl != NULL) {
                ExpectIntEQ(test_tls_parse_push_curve(&ssl->extensions, ssl,
                            groupIds[i]), 0);
                ExpectNotNull(test_tls_parse_push_kse(&ssl->extensions, ssl,
                            groupIds[i]));
                ExpectIntEQ(TLSX_KeyShare_Choose(ssl, ssl->extensions, 0, 0,
                            &kse, &searched), 0);
                ExpectIntEQ(searched, 1);
            }
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
        }
    }
#endif /* WOLFSSL_HAVE_MLKEM */

    /* TLSX_KeyShare_Setup(): the same ssl == NULL / wrong side guard as
     * Choose(), on a different public entry point. */
    ExpectIntEQ(TLSX_KeyShare_Setup(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        ExpectIntEQ(TLSX_KeyShare_Setup(ssl, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        /* Right side, right type: falls through to the "no KeyShare
         * extension yet" state check instead of the argument guard. */
        ExpectIntEQ(TLSX_KeyShare_Setup(ssl, NULL),
                    WC_NO_ERR_TRACE(BAD_STATE_E));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* TLSX_KeyShare_Parse_ClientHello(): the list-length prefix and the
     * MAX_EXT_DATA_LEN bound. Both are checked against the 'length'
     * argument before any byte past the 2-byte prefix is read, so an
     * over-large 'length' is exercised without actually allocating an
     * extension body anywhere near that size. */
    ExpectNotNull(ctx = test_tls_parse_server_ctx(wolfTLSv1_3_server_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        TLSX* extensions = NULL;
        /* declares a 5-entry list length but length says only 10 bytes of
         * body follow (short by OPAQUE16_LEN). */
        const byte lenMismatch[] = { 0x00, 0x05 };
        /* declared length matches, but MAX_EXT_DATA_LEN - HELLO_EXT_SZ is
         * exceeded; only the first 2 bytes are ever read. */
        const byte overLarge[] = { 0xFF, 0xFD };
        /* an empty list: both checks pass. */
        const byte empty[] = { 0x00, 0x00 };

        ExpectIntEQ(TLSX_KeyShare_Parse_ClientHello(ssl, lenMismatch, 10,
                    &extensions), WC_NO_ERR_TRACE(BUFFER_ERROR));
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        ExpectIntEQ(TLSX_KeyShare_Parse_ClientHello(ssl, overLarge, 65535,
                    &extensions), WC_NO_ERR_TRACE(BUFFER_ERROR));
        TLSX_FreeAll(extensions, NULL);
        extensions = NULL;

        ExpectIntEQ(TLSX_KeyShare_Parse_ClientHello(ssl, empty,
                    (word16)sizeof(empty), &extensions), 0);
        TLSX_FreeAll(extensions, NULL);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* TLSX_KeyShare_Parse(), server_hello direction: "not in the list sent
     * if there isn't a private key". A group that was offered (both
     * supported_groups and key_share list it) is guaranteed a non-NULL
     * KeyShareEntry by TLSX_KeyShareEntry_Parse()'s own postcondition (it
     * only returns a length equal to the input's when it also produced an
     * entry), so keyShareEntry itself is never NULL here; only the
     * key/privKey half is under test. */
#if !defined(NO_DH) && defined(HAVE_FFDHE_2048)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte body[2 + 2 + 256];
        word16 off = 0;

        body[off++] = (byte)(WOLFSSL_FFDHE_2048 >> 8);
        body[off++] = (byte)(WOLFSSL_FFDHE_2048 & 0xFF);
        body[off++] = 0x01; body[off++] = 0x00; /* keLen == 256 */
        XMEMSET(body + off, 0, 256); /* 0: never a valid DH public value */
        off += 256;

        ExpectIntEQ(test_tls_parse_push_curve(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048), 0);
        /* client's own offer: no key generated for it (as if the server
         * chose a group the client never actually built a key for -- not
         * how a real client behaves, but the field state under test). */
        ExpectNotNull(test_tls_parse_push_kse(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048));

        ExpectIntEQ(TLSX_KeyShare_Parse(ssl, body, off, server_hello),
                    WC_NO_ERR_TRACE(BAD_KEY_SHARE_DATA));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Same shape, but the client's entry already has a (fully initialised,
     * so freeing it later is safe) DH key object -- key != NULL alone is
     * enough for the gate to pass, independent of privKey. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte body[2 + 2 + 256];
        word16 off = 0;
        KeyShareEntry* kse = NULL;
        DhKey* dhKey = NULL;

        body[off++] = (byte)(WOLFSSL_FFDHE_2048 >> 8);
        body[off++] = (byte)(WOLFSSL_FFDHE_2048 & 0xFF);
        body[off++] = 0x01; body[off++] = 0x00;
        XMEMSET(body + off, 0, 256);
        off += 256;

        ExpectIntEQ(test_tls_parse_push_curve(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048), 0);
        kse = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_FFDHE_2048);
        ExpectNotNull(kse);
        ExpectNotNull(dhKey = (DhKey*)XMALLOC(sizeof(DhKey), ssl->heap,
                    DYNAMIC_TYPE_DH));
        if (dhKey != NULL)
            ExpectIntEQ(wc_InitDhKey_ex(dhKey, ssl->heap, INVALID_DEVID), 0);
        if (kse != NULL)
            kse->key = dhKey;

        /* key != NULL, privKey == NULL: gate passes; the derivation itself
         * then rejects the all-zero peer public value (never a valid DH
         * public key) before privKey's absence would even matter. */
        ExpectIntEQ(TLSX_KeyShare_Parse(ssl, body, off, server_hello),
                    WC_NO_ERR_TRACE(PEER_KEY_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Same shape, but the client's entry already has a private key (as a
     * real one would by the time a ServerHello arrives): the gate passes
     * and parsing proceeds to deriving the secret, which then fails on
     * the all-zero peer value above instead. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        byte body[2 + 2 + 256];
        word16 off = 0;
        KeyShareEntry* kse = NULL;

        body[off++] = (byte)(WOLFSSL_FFDHE_2048 >> 8);
        body[off++] = (byte)(WOLFSSL_FFDHE_2048 & 0xFF);
        body[off++] = 0x01; body[off++] = 0x00;
        XMEMSET(body + off, 0, 256);
        off += 256;

        ExpectIntEQ(test_tls_parse_push_curve(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048), 0);
        kse = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_FFDHE_2048);
        ExpectNotNull(kse);
        if (kse != NULL) {
            kse->privKey = (byte*)XMALLOC(1, ssl->heap,
                    DYNAMIC_TYPE_PRIVATE_KEY);
            ExpectNotNull(kse->privKey);
            if (kse->privKey != NULL) {
                kse->privKey[0] = 0x01;
                kse->privKeyLen = 1;
                kse->keyLen = 1;
            }
        }

        ExpectIntEQ(TLSX_KeyShare_Parse(ssl, body, off, server_hello),
                    WC_NO_ERR_TRACE(PEER_KEY_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* !NO_DH && HAVE_FFDHE_2048 */
#endif
    return EXPECT_RESULT();
}

/* ---- Key Share key generation (RFC 8446 4.2.8) --------------------------
 * TLSX_KeyShare_GenKey() dispatches by group to the per-algorithm Gen*Key()
 * helpers, all WOLFSSL_LOCAL, called directly on a hand-built KeyShareEntry
 * (a real handshake would need a full ClientHello round trip to reach the
 * same pubKey/privKey states). Entries are heap-allocated and released via
 * test_tls_parse_free_kse(), matching what TLSX_KeyShare_FreeAll() (not
 * itself visible here) expects to own.
 */
int test_TLSX_KeyShare_gen(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    defined(USE_WOLFSSL_MEMORY) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

#if !defined(NO_DH) && defined(HAVE_FFDHE_2048)
    /* TLSX_KeyShare_GenDhKey(): "no key material yet" is true when either
     * buffer is missing. A generation from a completely fresh entry hits
     * both; pre-seeding one buffer while leaving the other NULL isolates
     * each half. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;

        /* Fresh: pubKey == NULL && privKey == NULL. */
        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_FFDHE_2048;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            ExpectNotNull(kse->pubKey);
            ExpectNotNull(kse->privKey);

            /* Same entry, called again: both buffers already present, the
             * whole generation block (and the two allocation guards
             * inside it) is skipped entirely. */
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);

            test_tls_parse_free_kse(ssl, kse);
        }

        /* pubKey missing, privKey pre-seeded: the outer guard is true from
         * pubKey alone; the privKey allocation guard is then false. */
        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_FFDHE_2048;
            kse->privKey = (byte*)XMALLOC(128, ssl->heap,
                    DYNAMIC_TYPE_PRIVATE_KEY);
            ExpectNotNull(kse->privKey);
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            ExpectNotNull(kse->pubKey);
            test_tls_parse_free_kse(ssl, kse);
        }

        /* privKey missing, pubKey pre-seeded (sized for the FFDHE 2048
         * prime): the outer guard is true from privKey alone; the pubKey
         * allocation guard is then false. */
        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_FFDHE_2048;
            kse->pubKey = (byte*)XMALLOC(256, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(kse->pubKey);
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            ExpectNotNull(kse->privKey);
            test_tls_parse_free_kse(ssl, kse);
        }

#ifdef WOLFSSL_TEST_STATIC_BUILD
        /* "ret == 0" itself: force some allocation inside the shared DH
         * key setup (the params/key object itself, ahead of either
         * buffer's own allocation) to fail, so ret is non-zero by the
         * time the pubKey/privKey allocation guards are reached and
         * neither one fires. The exact allocation count spent on key
         * object setup before either buffer is not part of this
         * function's contract, so a small range of failure points is
         * tried; harmless if a given one instead lands after a guard
         * already ran (that attempt just contributes nothing new). */
        {
            int fa;
            for (fa = 0; fa <= 12; fa++) {
                wolfSSL_Malloc_cb prevM = NULL;
                wolfSSL_Free_cb prevF = NULL;
                wolfSSL_Realloc_cb prevR = NULL;

                ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(
                            sizeof(KeyShareEntry), ssl->heap,
                            DYNAMIC_TYPE_TLSX));
                if (kse == NULL)
                    break;
                XMEMSET(kse, 0, sizeof(*kse));
                kse->group = WOLFSSL_FFDHE_2048;

                ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
                ExpectIntEQ(wolfSSL_SetAllocators(tls_parse_fail_malloc,
                            tls_parse_fail_free, tls_parse_fail_realloc), 0);
                tls_parse_alloc_seen = 0;
                tls_parse_fail_after = fa;

                (void)TLSX_KeyShare_GenKey(ssl, kse);

                tls_parse_fail_after = -1;
                (void)wolfSSL_SetAllocators(prevM, prevF, prevR);

                test_tls_parse_free_kse(ssl, kse);
            }
        }
#endif
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* !NO_DH && HAVE_FFDHE_2048 */

#ifdef HAVE_CURVE25519
    /* TLSX_KeyShare_GenX25519Key(): "ret == 0 && pubKey == NULL". A fresh
     * entry gives both true; a second call on the same (now fully
     * populated) entry gives pubKey == NULL false while ret stays 0.
     * Clearing ssl->rng first forces the key generation itself to fail
     * (WC_RNG* rng == NULL is rejected before anything else), giving
     * ret == 0 false without needing a malformed group or corrupt state. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;
        WC_RNG* savedRng = ssl->rng;

        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_ECC_X25519;
            ssl->rng = NULL;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectNull(kse->pubKey);
            ssl->rng = savedRng;
            test_tls_parse_free_kse(ssl, kse);
        }

        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_ECC_X25519;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            ExpectNotNull(kse->pubKey);
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            test_tls_parse_free_kse(ssl, kse);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_CURVE448
    /* TLSX_KeyShare_GenX448Key(): same shape as X25519 above. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;
        WC_RNG* savedRng = ssl->rng;

        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_ECC_X448;
            ssl->rng = NULL;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectNull(kse->pubKey);
            ssl->rng = savedRng;
            test_tls_parse_free_kse(ssl, kse);
        }

        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_ECC_X448;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            ExpectNotNull(kse->pubKey);
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse), 0);
            test_tls_parse_free_kse(ssl, kse);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_CURVE448 */

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
    /* TLSX_KeyShare_GenEccKey(): only the "ret == 0" half of "ret == 0 &&
     * pubKey == NULL" is open (the pubKey half already has coverage
     * elsewhere); force it false the same way as the Curve25519/X448
     * cases above. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* kse = NULL;
        WC_RNG* savedRng = ssl->rng;

        ExpectNotNull(kse = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (kse != NULL) {
            XMEMSET(kse, 0, sizeof(*kse));
            kse->group = WOLFSSL_ECC_SECP256R1;
            ssl->rng = NULL;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, kse),
                        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
            ExpectNull(kse->pubKey);
            ssl->rng = savedRng;
            test_tls_parse_free_kse(ssl, kse);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */
#endif
    return EXPECT_RESULT();
}

/* ---- Key Share free/size/write (RFC 8446 4.2.8) -------------------------- */
int test_TLSX_KeyShare_freesizewrite(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES) &&  !defined(NO_DH) && defined(HAVE_FFDHE_2048) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* TLSX_KeyShare_FreeAll(): "privKey != NULL && privKeyLen > 0" gates
     * zeroing an FFDHE entry's private key before it is freed. All four
     * combinations are driven directly on a standalone extension list
     * (not tied to ssl->extensions), each freed by the same call under
     * test. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        int i;
        for (i = 0; i < 4; i++) {
            TLSX* extensions = NULL;
            KeyShareEntry* kse = NULL;

            ExpectNotNull(kse = test_tls_parse_push_kse(&extensions, ssl,
                        WOLFSSL_FFDHE_2048));
            if (kse != NULL) {
                switch (i) {
                    case 0: /* privKey == NULL, privKeyLen == 0 */
                        break;
                    case 1: /* privKey != NULL, privKeyLen == 0 */
                        kse->privKey = (byte*)XMALLOC(1, ssl->heap,
                                DYNAMIC_TYPE_PRIVATE_KEY);
                        ExpectNotNull(kse->privKey);
                        break;
                    case 2: /* privKey != NULL, privKeyLen > 0 */
                        kse->privKey = (byte*)XMALLOC(4, ssl->heap,
                                DYNAMIC_TYPE_PRIVATE_KEY);
                        ExpectNotNull(kse->privKey);
                        kse->privKeyLen = 4;
                        break;
                    case 3: /* privKey == NULL, privKeyLen > 0 */
                        kse->privKeyLen = 4;
                        break;
                }
            }
            TLSX_FreeAll(extensions, ssl->heap);
        }
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* TLSX_KeyShare_GetSize() / TLSX_KeyShare_Write(): "!isRequest &&
     * pubKey == NULL" -- a request-direction (client_hello) list always
     * writes every entry regardless of pubKey; a response-direction
     * (server_hello) list skips any entry without one. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        word32 reqLen;
        word16 respLen;
        byte out[64];
        word32 reqOff;
        word16 respOff;
        KeyShareEntry* kse = NULL;

        /* pubKey == NULL: response direction skips it (0 bytes); request
         * direction still writes it (pubKeyLen == 0, so just the header).
         * resp must be set for the response direction to consider this
         * extension at all (TLSX_GetSize()'s own, outer "only marked
         * extensions are sent back" rule) -- otherwise it would be
         * skipped one level up, before ever reaching the pubKey check
         * under test. */
        ExpectNotNull(kse = test_tls_parse_push_kse(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048));
        {
            TLSX* ext = TLSX_Find(ssl->extensions, TLSX_KEY_SHARE);
            ExpectNotNull(ext);
            if (ext != NULL)
                ext->resp = 1;
        }

        respLen = 0;
        ExpectIntEQ(TLSX_GetResponseSize(ssl, server_hello, &respLen), 0);
        respOff = 0;
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, server_hello, &respOff), 0);

        /* The request direction never reaches the pubKey test -- isRequest
         * short-circuits it -- but it does copy pubKey unconditionally, so
         * give the entry one before writing a ClientHello. */
        if (kse != NULL) {
            kse->pubKey = (byte*)XMALLOC(2, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(kse->pubKey);
            if (kse->pubKey != NULL) {
                XMEMSET(kse->pubKey, 0, 2);
                kse->pubKeyLen = 2;
            }
        }

        reqLen = 0;
        ExpectIntEQ(TLSX_GetRequestSize(ssl, client_hello, &reqLen), 0);
        ExpectIntGT(reqLen, 0);
        reqOff = 0;
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(TLSX_WriteRequest(ssl, out, client_hello, &reqOff), 0);
        ExpectIntGT(reqOff, 0);
    }
    wolfSSL_free(ssl);
    ssl = NULL;

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        word16 respLen;
        byte out[64];
        word16 respOff;
        KeyShareEntry* kse = NULL;

        /* pubKey != NULL: response direction includes it too. */
        ExpectNotNull(kse = test_tls_parse_push_kse(&ssl->extensions, ssl,
                    WOLFSSL_FFDHE_2048));
        if (kse != NULL) {
            kse->pubKey = (byte*)XMALLOC(4, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(kse->pubKey);
            kse->pubKeyLen = 4;
        }
        {
            TLSX* ext = TLSX_Find(ssl->extensions, TLSX_KEY_SHARE);
            ExpectNotNull(ext);
            if (ext != NULL)
                ext->resp = 1;
        }

        respLen = 0;
        ExpectIntEQ(TLSX_GetResponseSize(ssl, server_hello, &respLen), 0);
        ExpectIntGT(respLen, 0);
        respOff = 0;
        XMEMSET(out, 0, sizeof(out));
        ExpectIntEQ(TLSX_WriteResponse(ssl, out, server_hello, &respOff), 0);
        ExpectIntGT(respOff, 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* ---- Key Share secret derivation (RFC 8446 4.2.8, TLS 1.2 legacy DH) ----
 * TLSX_KeyShare_ProcessDh(), TLSX_KeyShare_ProcessX25519_ex() and
 * TLSX_KeyShare_ProcessEcc_ex() are all fully static; TLSX_KeyShare_
 * DeriveSecret() (WOLFSSL_LOCAL) reaches them by dispatching on whatever
 * single entry is in the KeyShare extension, so it is used here as the
 * entry point, with a hand-built entry standing in for what a real
 * handshake would have produced by this point.
 */
int test_TLSX_KeyShare_process(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES) &&  defined(WOLFSSL_TEST_STATIC_BUILD) && \
    defined(HAVE_TLS_EXTENSIONS) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

#ifdef HAVE_CURVE25519
    /* TLSX_KeyShare_ProcessX25519_ex(): "ret == 0 && key == NULL" -- our
     * own side's key. A peer public value is needed either way; borrow
     * one from a throwaway key pair generated for this test alone. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* peer = NULL;
        KeyShareEntry* target = NULL;

        ExpectNotNull(peer = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (peer != NULL) {
            XMEMSET(peer, 0, sizeof(*peer));
            peer->group = WOLFSSL_ECC_X25519;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, peer), 0);
        }

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_X25519);
        ExpectNotNull(target);
        if (target != NULL && peer != NULL && peer->pubKey != NULL) {
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            target->ke = (byte*)XMALLOC(peer->pubKeyLen, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(target->ke);
            if (target->ke != NULL) {
                XMEMCPY(target->ke, peer->pubKey, peer->pubKeyLen);
                target->keLen = (word16)peer->pubKeyLen;
            }
        }
        /* target->key stays NULL: our own side never generated a key. */
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        test_tls_parse_free_kse(ssl, peer);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* Same shape, but our own side has a real key too: both operands
     * false, and the exchange actually completes. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* peer = NULL;
        KeyShareEntry* target = NULL;

        ExpectNotNull(peer = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (peer != NULL) {
            XMEMSET(peer, 0, sizeof(*peer));
            peer->group = WOLFSSL_ECC_X25519;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, peer), 0);
        }

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_X25519);
        ExpectNotNull(target);
        if (target != NULL) {
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, target), 0);
            if (peer != NULL && peer->pubKey != NULL) {
                XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                target->ke = (byte*)XMALLOC(peer->pubKeyLen, ssl->heap,
                        DYNAMIC_TYPE_PUBLIC_KEY);
                ExpectNotNull(target->ke);
                if (target->ke != NULL) {
                    XMEMCPY(target->ke, peer->pubKey, peer->pubKeyLen);
                    target->keLen = (word16)peer->pubKeyLen;
                }
            }
        }
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl), 0);

        test_tls_parse_free_kse(ssl, peer);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* "ret == 0" itself: an invalid peer value is rejected before our own
     * key is ever looked at, independent of whether one was generated. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* target = NULL;

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_X25519);
        ExpectNotNull(target);
        if (target != NULL) {
            /* wrong length for a Curve25519 public value: rejected by
             * wc_curve25519_check_public() before the peer key is even
             * imported. */
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            target->ke = (byte*)XMALLOC(4, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(target->ke);
            if (target->ke != NULL) {
                XMEMSET(target->ke, 0, 4);
                target->keLen = 4;
            }
        }
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl),
                    WC_NO_ERR_TRACE(ECC_PEERKEY_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
    /* TLSX_KeyShare_ProcessEcc_ex(): same "ret == 0 && key == NULL" shape,
     * for a plain named ECC curve instead of X25519. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* peer = NULL;
        KeyShareEntry* target = NULL;

        ExpectNotNull(peer = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (peer != NULL) {
            XMEMSET(peer, 0, sizeof(*peer));
            peer->group = WOLFSSL_ECC_SECP256R1;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, peer), 0);
        }

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_SECP256R1);
        ExpectNotNull(target);
        if (target != NULL && peer != NULL && peer->pubKey != NULL) {
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            target->ke = (byte*)XMALLOC(peer->pubKeyLen, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(target->ke);
            if (target->ke != NULL) {
                XMEMCPY(target->ke, peer->pubKey, peer->pubKeyLen);
                target->keLen = (word16)peer->pubKeyLen;
            }
        }
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        test_tls_parse_free_kse(ssl, peer);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* peer = NULL;
        KeyShareEntry* target = NULL;

        ExpectNotNull(peer = (KeyShareEntry*)XMALLOC(sizeof(KeyShareEntry),
                    ssl->heap, DYNAMIC_TYPE_TLSX));
        if (peer != NULL) {
            XMEMSET(peer, 0, sizeof(*peer));
            peer->group = WOLFSSL_ECC_SECP256R1;
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, peer), 0);
        }

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_SECP256R1);
        ExpectNotNull(target);
        if (target != NULL) {
            ExpectIntEQ(TLSX_KeyShare_GenKey(ssl, target), 0);
            if (peer != NULL && peer->pubKey != NULL) {
                XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                target->ke = (byte*)XMALLOC(peer->pubKeyLen, ssl->heap,
                        DYNAMIC_TYPE_PUBLIC_KEY);
                ExpectNotNull(target->ke);
                if (target->ke != NULL) {
                    XMEMCPY(target->ke, peer->pubKey, peer->pubKeyLen);
                    target->keLen = (word16)peer->pubKeyLen;
                }
            }
        }
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl), 0);

        test_tls_parse_free_kse(ssl, peer);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    /* "ret == 0" itself: an invalid (wrong-length) peer value is rejected
     * while importing it, before our own key is ever looked at. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* target = NULL;

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_ECC_SECP256R1);
        ExpectNotNull(target);
        if (target != NULL) {
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            target->ke = (byte*)XMALLOC(4, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(target->ke);
            if (target->ke != NULL) {
                XMEMSET(target->ke, 0, 4);
                target->keLen = 4;
            }
        }
        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl),
                    WC_NO_ERR_TRACE(ECC_PEERKEY_ERROR));
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */

#if !defined(NO_DH) && defined(HAVE_FFDHE_2048)
    /* TLSX_KeyShare_ProcessDh(): "ret == 0 && dhKeySz > preMasterSz" -- a
     * raw Diffie-Hellman agreement can legitimately produce a shared value
     * shorter than the prime's byte length (a leading zero byte), which is
     * then re-padded; a value with no leading zero byte does not need it.
     * Both are reached deterministically by fixing our own private
     * exponent at 1, so the derived secret is exactly the peer's public
     * value (chosen well below the prime either way, so no modular
     * reduction occurs). */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* target = NULL;
        byte* ke = NULL;

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_FFDHE_2048);
        ExpectNotNull(target);
        if (target != NULL) {
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(ke = (byte*)XMALLOC(256, ssl->heap,
                        DYNAMIC_TYPE_PUBLIC_KEY));
            target->ke = ke;
            if (ke != NULL) {
                /* peer public value 2, left-padded to 256 bytes: a
                 * leading zero byte. */
                XMEMSET(ke, 0, 256);
                ke[255] = 0x02;
                target->keLen = 256;
            }
            target->privKey = (byte*)XMALLOC(1, ssl->heap,
                    DYNAMIC_TYPE_PRIVATE_KEY);
            ExpectNotNull(target->privKey);
            if (target->privKey != NULL) {
                target->privKey[0] = 0x01;
                target->keyLen = 1;
            }
        }

        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    if (ssl != NULL) {
        KeyShareEntry* target = NULL;
        byte* ke = NULL;

        target = test_tls_parse_push_kse(&ssl->extensions, ssl,
                WOLFSSL_FFDHE_2048);
        ExpectNotNull(target);
        if (target != NULL) {
            XFREE(target->ke, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ExpectNotNull(ke = (byte*)XMALLOC(256, ssl->heap,
                        DYNAMIC_TYPE_PUBLIC_KEY));
            target->ke = ke;
            if (ke != NULL) {
                /* peer public value 2^2040, left-padded to 256 bytes: no
                 * leading zero byte. */
                XMEMSET(ke, 0, 256);
                ke[0] = 0x01;
                target->keLen = 256;
            }
            target->privKey = (byte*)XMALLOC(1, ssl->heap,
                    DYNAMIC_TYPE_PRIVATE_KEY);
            ExpectNotNull(target->privKey);
            if (target->privKey != NULL) {
                target->privKey[0] = 0x01;
                target->keyLen = 1;
            }
        }

        ExpectIntEQ(TLSX_KeyShare_DeriveSecret(ssl), 0);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif /* !NO_DH && HAVE_FFDHE_2048 */
#endif
    return EXPECT_RESULT();
}
