/* test_ssl_crl_ocsp.c
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
#include <wolfssl/internal.h>
/* For the OCSP_parse_url compatibility name, which is how applications reach
 * wolfSSL_OCSP_parse_url(). */
#include <wolfssl/openssl/ssl.h>

#include <tests/utils.h>
#include <tests/api/test_ssl_crl_ocsp.h>

/* Tests for the CRL and OCSP APIs in src/ssl_api_crl_ocsp.c (moved from
 * ssl.c). */

/* Test setting the OCSP responder URL on an object.
 *
 * wolfSSL_get_ocsp_url() and wolfSSL_get_ocsp_response() are WOLFSSL_LOCAL, so
 * only the setter can be reached from here.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_ocsp_url_api(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY)) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char url[] = "http://127.0.0.1:22221";

    /* A NULL object cannot hold a URL. */
    ExpectIntEQ(wolfSSL_set_ocsp_url(NULL, url), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_set_ocsp_url(ssl, url), WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        ExpectStrEQ(ssl->url, url);
    }
    /* The URL can be cleared again. */
    ExpectIntEQ(wolfSSL_set_ocsp_url(ssl, NULL), WOLFSSL_SUCCESS);
    if (ssl != NULL) {
        ExpectNull(ssl->url);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test reading the produced date of the last OCSP response.
 *
 * The date is normally filled in while a response is processed; it is set
 * directly here so that each way of reporting it can be reached.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_ocsp_producedDate(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && !defined(NO_ASN_TIME) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte date[MAX_DATE_SIZE];
    int format = 0;
    struct tm producedTm;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The object is required by both. */
    ExpectIntEQ(wolfSSL_get_ocsp_producedDate(NULL, date, sizeof(date),
        &format), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_ocsp_producedDate_tm(NULL, &producedTm),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* No response processed, so no date format is recorded yet. */
    ExpectIntEQ(wolfSSL_get_ocsp_producedDate(ssl, date, sizeof(date),
        &format), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_ocsp_producedDate_tm(ssl, &producedTm),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    if (ssl != NULL) {
        /* Pretend a response carrying this date was processed. */
        XMEMSET(ssl->ocspProducedDate, 0, sizeof(ssl->ocspProducedDate));
        XMEMCPY(ssl->ocspProducedDate, "250101000000Z", 14);
        ssl->ocspProducedDateFormat = ASN_UTC_TIME;

        /* Both output parameters are required. */
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate(ssl, NULL, sizeof(date),
            &format), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate(ssl, date, sizeof(date),
            NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* The buffer must be able to hold the whole date. */
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate(ssl, date, 4, &format),
            WC_NO_ERR_TRACE(BUFFER_E));

        ExpectIntEQ(wolfSSL_get_ocsp_producedDate(ssl, date, sizeof(date),
            &format), 0);
        ExpectIntEQ(format, ASN_UTC_TIME);
        ExpectStrEQ((char*)date, "250101000000Z");

        /* The same date is also reported as a broken-down time. */
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate_tm(ssl, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        XMEMSET(&producedTm, 0, sizeof(producedTm));
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate_tm(ssl, &producedTm), 0);
        ExpectIntEQ(producedTm.tm_year, 125);

        /* A date that cannot be parsed is reported as such. */
        XMEMSET(ssl->ocspProducedDate, 0, sizeof(ssl->ocspProducedDate));
        XMEMCPY(ssl->ocspProducedDate, "not-a-date", 11);
        ExpectIntEQ(wolfSSL_get_ocsp_producedDate_tm(ssl, &producedTm),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test setting and getting the certificate status request type.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_tlsext_status_type(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CERTIFICATE_STATUS_REQUEST) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_CERTS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_set_tlsext_status_type(NULL,
        WOLFSSL_TLSEXT_STATUSTYPE_ocsp), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_get_tlsext_status_type(NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The extension is not requested until asked for. */
    ExpectIntEQ(wolfSSL_get_tlsext_status_type(ssl),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

    /* Only the OCSP status type is supported. */
    ExpectIntEQ(wolfSSL_set_tlsext_status_type(ssl, 99), WOLFSSL_FAILURE);

    ExpectIntEQ(wolfSSL_set_tlsext_status_type(ssl,
        WOLFSSL_TLSEXT_STATUSTYPE_ocsp), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_tlsext_status_type(ssl),
        WOLFSSL_TLSEXT_STATUSTYPE_ocsp);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Guarded to match its only caller, test_wolfSSL_CTX_tlsext_status_cb(). */
#if (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && defined(WOLFSSL_PEM_TO_DER) && !defined(NO_CERTS)
/* Certificate status callback that does nothing.
 *
 * @param [in] ssl  SSL/TLS object. Unused.
 * @param [in] arg  User argument. Unused.
 * @return  0 always.
 */
static int test_ssl_crl_ocsp_status_cb(WOLFSSL* ssl, void* arg)
{
    (void)ssl;
    (void)arg;
    return 0;
}
#endif

/* Test setting and getting the certificate status callback and its argument.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_tlsext_status_cb(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS) && \
    !defined(WOLFSSL_NO_TLS12) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) \
    && defined(WOLFSSL_PEM_TO_DER) && !defined(NO_CERTS)
    WOLFSSL_CTX* ctx = NULL;
    tlsextStatusCb cb = NULL;
    int arg = 0;

    /* Every argument is required. */
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_status_cb(NULL, &cb), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(NULL,
        test_ssl_crl_ocsp_status_cb), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_arg(NULL, &arg),
        WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_CTX_get_tlsext_status_cb(ctx, NULL), WOLFSSL_FAILURE);

    /* Setting the callback turns stapling on so it can be used. */
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_cb(ctx,
        test_ssl_crl_ocsp_status_cb), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_get_tlsext_status_cb(ctx, &cb), WOLFSSL_SUCCESS);
    ExpectTrue(cb == test_ssl_crl_ocsp_status_cb);

    ExpectIntEQ(wolfSSL_CTX_set_tlsext_status_arg(ctx, &arg), WOLFSSL_SUCCESS);

    wolfSSL_CTX_set_ocsp_status_verify_cb(NULL, NULL, NULL);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test storing and retrieving a stapled OCSP response.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_tlsext_status_ocsp_resp(void)
{
    EXPECT_DECLS;
#if (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)) && \
    !defined(NO_TLS) && !defined(WOLFSSL_NO_TLS12) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_CERTS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    unsigned char* resp = NULL;
    unsigned char* stored = NULL;
    unsigned char* bad = NULL;
    int owned = 0;

    /* Both arguments are required. */
    ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(NULL, &resp), 0);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(ssl, NULL), 0);

    /* Nothing stapled yet. */
    ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(ssl, &resp), 0);
    ExpectNull(resp);

    /* A response and a length must be given together. */
    ExpectIntEQ(wolfSSL_set_tlsext_status_ocsp_resp(ssl, NULL, 4),
        WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, NULL, 0,
        1 + MAX_CHAIN_DEPTH), WOLFSSL_FAILURE);

    /* The other half of the same rule: a response with no length. A negative
     * length is rejected before it, by the range check. */
    ExpectNotNull(bad = (unsigned char*)XMALLOC(4, NULL, 0));
    ExpectIntEQ(wolfSSL_set_tlsext_status_ocsp_resp(ssl, bad, 0),
        WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set_tlsext_status_ocsp_resp(ssl, bad, -1),
        WOLFSSL_FAILURE);
    /* A failed call takes no ownership, so nothing was stored and this side
     * still has the response to free. */
    resp = NULL;
    ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(ssl, &resp), 0);
    ExpectNull(resp);
    XFREE(bad, NULL, 0);
    bad = NULL;

    /* The object takes ownership of the response and releases it with a heap
     * hint of NULL and a type of 0, so allocate it to match. */
    ExpectNotNull(stored = (unsigned char*)XMALLOC(4, NULL, 0));
    if (stored != NULL) {
        XMEMCPY(stored, "resp", 4);
        owned = (wolfSSL_set_tlsext_status_ocsp_resp(ssl, stored, 4) ==
            WOLFSSL_SUCCESS);
        ExpectIntEQ(owned, 1);
        if (owned) {
            ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(ssl, &resp), 4);
            ExpectPtrEq(resp, stored);
        }
        else {
            /* Ownership was not handed over, so this side still has it. */
            XFREE(stored, NULL, 0);
        }
    }

    /* Clearing it releases the stored response and leaves nothing to get. */
    ExpectIntEQ(wolfSSL_set_tlsext_status_ocsp_resp(ssl, NULL, 0),
        WOLFSSL_SUCCESS);
    resp = NULL;
    ExpectIntEQ(wolfSSL_get_tlsext_status_ocsp_resp(ssl, &resp), 0);
    ExpectNull(resp);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
/* Check one URL parses into the expected parts, then release them.
 *
 * @param [in] url   URL to parse.
 * @param [in] eh    Expected host.
 * @param [in] ep    Expected port.
 * @param [in] epa   Expected path.
 * @param [in] es    Expected secure flag.
 * @return  TEST_SUCCESS on success.
 */
static int test_ssl_crl_ocsp_url_ok(const char* url, const char* eh,
    const char* ep, const char* epa, int es)
{
    EXPECT_DECLS;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int isSsl = -1;

    ExpectIntEQ(wolfSSL_OCSP_parse_url(url, &host, &port, &path, &isSsl),
        WOLFSSL_SUCCESS);
    ExpectStrEQ(host, eh);
    ExpectStrEQ(port, ep);
    ExpectStrEQ(path, epa);
    ExpectIntEQ(isSsl, es);

    XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL);

    return EXPECT_RESULT();
}

/* Check one URL is rejected and nothing is left allocated.
 *
 * @param [in] url  URL to parse.
 * @return  TEST_SUCCESS on success.
 */
static int test_ssl_crl_ocsp_url_bad(const char* url)
{
    EXPECT_DECLS;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int isSsl = -1;

    ExpectIntEQ(wolfSSL_OCSP_parse_url(url, &host, &port, &path, &isSsl),
        WOLFSSL_FAILURE);
    ExpectNull(host);
    ExpectNull(port);
    ExpectNull(path);
    ExpectIntEQ(isSsl, 0);

    XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL);

    return EXPECT_RESULT();
}

#endif /* HAVE_OCSP && OPENSSL_EXTRA */

/* Test splitting an OCSP responder URL into its parts.
 *
 * The expected values were taken from OpenSSL's OCSP_parse_url() - every case
 * below other than the two empty-host rejections was confirmed against it.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_OCSP_parse_url_api(void)
{
    EXPECT_DECLS;
#if defined(HAVE_OCSP) && defined(OPENSSL_EXTRA)
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int isSsl = -1;

    /* Every argument is required. A NULL argument is reported before any of
     * the out parameters is written, so - unlike the malformed URLs below -
     * there is nothing to assert about them here: they still hold whatever
     * the caller left in them. */
    ExpectIntEQ(wolfSSL_OCSP_parse_url(NULL, &host, &port, &path, &isSsl),
        WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_OCSP_parse_url("http://a/", NULL, &port, &path,
        &isSsl), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_OCSP_parse_url("http://a/", &host, NULL, &path,
        &isSsl), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_OCSP_parse_url("http://a/", &host, &port, NULL,
        &isSsl), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_OCSP_parse_url("http://a/", &host, &port, &path,
        NULL), WOLFSSL_FAILURE);

    /* Reached through the OpenSSL compatibility name, which is how
     * applications call this. The rest of the cases use the wolfSSL name so
     * they read as tests of this implementation rather than of the macro. */
    ExpectIntEQ(OCSP_parse_url("http://example.com/ocsp", &host, &port, &path,
        &isSsl), WOLFSSL_SUCCESS);
    ExpectStrEQ(host, "example.com");
    ExpectStrEQ(port, "80");
    ExpectStrEQ(path, "/ocsp");
    ExpectIntEQ(isSsl, 0);
    XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL);
    host = NULL; port = NULL; path = NULL;

    /* Scheme, default ports and the default path. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/ocsp",
        "example.com", "80", "/ocsp", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com",
        "example.com", "80", "/", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://example.com",
        "example.com", "443", "/", 1), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://example.com/some/path/",
        "example.com", "443", "/some/path/", 1), TEST_SUCCESS);
    /* The scheme may be left out entirely, and is then http. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("example.com/ocsp",
        "example.com", "80", "/ocsp", 0), TEST_SUCCESS);
    /* Which means a scheme written without its colon is not rejected: there
     * is no "://" to find, so "http" is read as the host and the rest as the
     * path. The old parser refused this. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http" "//localhost",
        "http", "80", "//localhost", 0), TEST_SUCCESS);
    /* It is matched case sensitively, so these are not schemes at all - and
     * without a "://" there is no authority either, so the whole string is a
     * host that happens to contain a colon. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("HTTP://example.com/ocsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("HttpS://example.com/p"),
        TEST_SUCCESS);
    /* An unknown scheme is rejected. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("ftp://example.com/"), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("httpx://example.com/"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("://example.com/"), TEST_SUCCESS);
    /* Missing separator after the scheme: no "://", so "http:/example.com/"
     * is a host of "http" with a bad port. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http:/example.com/"), TEST_SUCCESS);

    /* Ports. Returned as written rather than canonicalized, and an explicit
     * ":0" is reported as the scheme's default. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:8080/ocsp",
        "example.com", "8080", "/ocsp", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://example.com:1234",
        "example.com", "1234", "/", 1), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:00080/p",
        "example.com", "00080", "/p", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:0/p",
        "example.com", "80", "/p", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://example.com:0/p",
        "example.com", "443", "/p", 1), TEST_SUCCESS);
    /* Only an exact ":0" is the default; "000" is a port in its own right. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:000/p",
        "example.com", "000", "/p", 0), TEST_SUCCESS);
    /* Length is not limited, only the value. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:065535/p",
        "example.com", "065535", "/p", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com:65536/p"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com:/p"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com:"), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com:8080junk/ocsp"),
        TEST_SUCCESS);

    /* An IPv6 literal keeps its brackets - note wolfIO_DecodeUrl() strips
     * them. Only a port may follow the literal. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://[::1]/ocsp",
        "[::1]", "80", "/ocsp", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://[::1]:8443/p",
        "[::1]", "8443", "/p", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://[2001:db8::1]:8443/ocsp",
        "[2001:db8::1]", "8443", "/ocsp", 1), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://[::1/ocsp"), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://[::1]junk"), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://[::1]junk/ocsp"),
        TEST_SUCCESS);

    /* Userinfo runs to the FIRST '@' of the authority and is discarded, so
     * the host is what follows it - not the name that reads first. A caller
     * that logs or pins the responder must use the parsed host. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://good.example@evil.example/x",
        "evil.example", "80", "/x", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("https://u:p@ocsp.example:8443/x",
        "ocsp.example", "8443", "/x", 1), TEST_SUCCESS);
    /* The first '@' delimits, so a second one is part of the host. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://a@b@c/", "b@c", "80", "/", 0),
        TEST_SUCCESS);
    /* The scan is bounded by the authority, so an '@' in the path stays in
     * the path. OpenSSL 3.5 and earlier scanned the whole URL and took "b"
     * as the host here; that was fixed upstream. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/a@b",
        "example.com", "80", "/a@b", 0), TEST_SUCCESS);
    /* Userinfo with nothing after it leaves no host. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://user@/x"), TEST_SUCCESS);

    /* The query stays with the path; the fragment is dropped. A path is
     * prepended when the URL has none. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com?q=1",
        "example.com", "80", "/?q=1", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com#f",
        "example.com", "80", "/", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/p?q=1",
        "example.com", "80", "/p?q=1", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/p#f",
        "example.com", "80", "/p", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/p?q#f",
        "example.com", "80", "/p?q", 0), TEST_SUCCESS);
    /* The fragment is looked for from the query onwards, so a '#' before the
     * query stays in the path. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/p#a?b",
        "example.com", "80", "/p#a?b", 0), TEST_SUCCESS);
    /* A ':' in the path is not a port and is kept. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com/ocsp:8080",
        "example.com", "80", "/ocsp:8080", 0), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_ok("http://example.com:8080/ocsp:1",
        "example.com", "8080", "/ocsp:1", 0), TEST_SUCCESS);

    /* An empty host is refused rather than returned as "", which is where
     * this deliberately differs from OpenSSL - nothing can be fetched from
     * it. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://:8080/ocsp"), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://"), TEST_SUCCESS);

    /* CR/LF anywhere is refused so the parts cannot inject header lines into
     * a request built from them. Also not a check OpenSSL makes. */
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com\r\n/ocsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com/oc\rsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://example.com/oc\nsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://exa\rmple.com/ocsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("http://exa\nmple.com/ocsp"),
        TEST_SUCCESS);
    ExpectIntEQ(test_ssl_crl_ocsp_url_bad("\rhttp://example.com/ocsp"),
        TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}
