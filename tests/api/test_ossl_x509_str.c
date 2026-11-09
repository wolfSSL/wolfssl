/* test_ossl_x509_str.c
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
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/x509_vfy.h>
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/utils.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_str.h>

#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_ASN_TIME)
static int last_errcodes[10];
static int last_errdepths[10];
static int err_index = 0;

static int X509CallbackCount(int ok, X509_STORE_CTX *ctx)
{
    if (!ok) {
        if (err_index < 10) {
            last_errcodes[err_index]  = X509_STORE_CTX_get_error(ctx);
            last_errdepths[err_index] = X509_STORE_CTX_get_error_depth(ctx);
            err_index++;
        } else {
            /* Should not happen in test */
            WOLFSSL_MSG("Error index overflow in X509CallbackCount");
            err_index = 0;
        }
    }
    /* Always return OK to allow verification to continue.*/
    return 1;
}
#endif

int test_wolfSSL_X509_STORE_CTX_set_time(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    time_t c_time;

    ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
    c_time = 365*24*60*60;
    wolfSSL_X509_STORE_CTX_set_time(ctx, 0, c_time);
    ExpectTrue((ctx->param->flags & WOLFSSL_USE_CHECK_TIME) ==
        WOLFSSL_USE_CHECK_TIME);
    ExpectTrue(ctx->param->check_time == c_time);
    wolfSSL_X509_STORE_CTX_free(ctx);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_check_time(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
        !defined(NO_ASN_TIME) && !defined(NO_RSA)
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_X509_STORE_CTX* ctx = NULL;
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_X509* cert = NULL;
#ifdef HAVE_CRL
    WOLF_STACK_OF(WOLFSSL_X509_CRL)* crls = NULL;
    WOLFSSL_X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;
#endif
    int ret;
    time_t check_time;
    const char* srvCertFile = "./certs/server-cert.pem";
    const char* expiredCertFile = "./certs/test/expired/expired-cert.pem";
    WOLFSSL_ASN1_TIME* epoch = NULL;
    int day = 0;
    int sec = 0;

    /* Set check_time to May 26, 2000 - should fail "not yet valid" check */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    if (store != NULL) {
        /* Load CA certificate - should validate with current time by default */
        ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
                            SSL_FILETYPE_PEM));
        ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);

        /* Set check_time to May 26, 2000 (timestamp: 959320800) */
        check_time = (time_t)959320800; /* May 26, 2000 00:00:00 UTC */
        store->param->check_time = check_time;
        wolfSSL_X509_VERIFY_PARAM_set_flags(store->param,
            WOLFSSL_USE_CHECK_TIME);
        ExpectTrue(store->param->check_time == check_time);
        ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(srvCertFile,
                        SSL_FILETYPE_PEM));
        ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);

        /* Verify that check_time was copied to context */
        ExpectTrue((ctx->param->flags & WOLFSSL_USE_CHECK_TIME) ==
            WOLFSSL_USE_CHECK_TIME);
        ExpectTrue(ctx->param->check_time == check_time);

        /* Verify certificate using the custom check_time - should fail because
        * certificate is not yet valid (use before check fails) */
        ret = wolfSSL_X509_verify_cert(ctx);
        ExpectIntNE(ret, WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error(ctx),
                    WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID);
        wolfSSL_X509_STORE_CTX_free(ctx);
        ctx = NULL;
    }
    wolfSSL_X509_STORE_free(store);
    store = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;
    wolfSSL_X509_free(ca);
    ca = NULL;

    /* Verify without setting check_time - should work with current time */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    if (store != NULL) {
        ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
                            SSL_FILETYPE_PEM));
        ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);
        ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(srvCertFile,
                        SSL_FILETYPE_PEM));
        ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        ret = wolfSSL_X509_verify_cert(ctx);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);

        /* As OpenSSL's X509_cmp_time(), the CA expires at its notAfter */
        ExpectNotNull(epoch = wolfSSL_ASN1_TIME_new());
        ExpectIntEQ(wolfSSL_ASN1_TIME_set_string(epoch, "19700101000000Z"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_ASN1_TIME_diff(&day, &sec, epoch,
            wolfSSL_X509_get_notAfter(ca)), WOLFSSL_SUCCESS);
        check_time = (time_t)day * 86400 + sec;
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        wolfSSL_X509_STORE_CTX_set_time(ctx, 0, check_time - 1);
        ExpectIntEQ(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        wolfSSL_X509_STORE_CTX_set_time(ctx, 0, check_time);
        ExpectIntNE(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error(ctx),
                    WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED);
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error_depth(ctx), 1);
        wolfSSL_ASN1_TIME_free(epoch);
        wolfSSL_X509_STORE_CTX_free(ctx);
        ctx = NULL;
    }
    wolfSSL_X509_STORE_free(store);
    store = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;
    wolfSSL_X509_free(ca);
    ca = NULL;

    /* A CRL flag must not make verification use check_time. As in OpenSSL,
     * it turns on CRL checks: the CA's CRL does not list the cert. */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    if (store != NULL) {
        ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
                            SSL_FILETYPE_PEM));
        ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);
        ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(srvCertFile,
                        SSL_FILETYPE_PEM));
        ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        if (ctx != NULL) {
            ctx->param->check_time = (time_t)959320800;
            ExpectIntEQ(wolfSSL_X509_VERIFY_PARAM_set_flags(ctx->param,
                WOLFSSL_X509_V_FLAG_CRL_CHECK), WOLFSSL_SUCCESS);
            ExpectIntEQ(ctx->param->flags & WOLFSSL_USE_CHECK_TIME, 0);
        }
#ifdef HAVE_CRL
        ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
        ExpectNotNull(crl = wolfSSL_PEM_read_X509_CRL(fp, NULL, NULL, NULL));
        if (fp != XBADFILE)
            XFCLOSE(fp);
        ExpectNotNull(crls = wolfSSL_sk_X509_CRL_new_null());
        ExpectIntGT(wolfSSL_sk_X509_CRL_push(crls, crl), 0);
        wolfSSL_X509_STORE_CTX_set0_crls(ctx, crls);
#endif
        ret = wolfSSL_X509_verify_cert(ctx);
#ifdef HAVE_CRL
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
#else
        /* Without HAVE_CRL there is no CRL */
        ExpectIntNE(ret, WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_get_error(ctx),
                    WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL);
#endif
        wolfSSL_X509_STORE_CTX_free(ctx);
        ctx = NULL;
#ifdef HAVE_CRL
        wolfSSL_sk_X509_CRL_free(crls);
        crls = NULL;
        wolfSSL_X509_CRL_free(crl);
        crl = NULL;
#endif
    }
    wolfSSL_X509_STORE_free(store);
    store = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;
    wolfSSL_X509_free(ca);
    ca = NULL;

    /* Test WOLFSSL_NO_CHECK_TIME flag with expired certificate */
    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    if (store != NULL) {
        /* Set NO_CHECK_TIME flag to skip time validation */
        wolfSSL_X509_VERIFY_PARAM_set_flags(store->param,
            WOLFSSL_NO_CHECK_TIME);
        ExpectTrue((store->param->flags & WOLFSSL_NO_CHECK_TIME) ==
            WOLFSSL_NO_CHECK_TIME);

        /* Load expired certificate (self-signed) */
        ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(expiredCertFile,
                        SSL_FILETYPE_PEM));
        /* Add expired certificate as trusted CA (self-signed) */
        ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, cert), WOLFSSL_SUCCESS);

        ExpectNotNull(ctx = wolfSSL_X509_STORE_CTX_new());
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        /* Verify expired certificate with NO_CHECK_TIME - should succeed
        * because time validation is skipped */
        ret = wolfSSL_X509_verify_cert(ctx);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);

        /* As OpenSSL, X509_V_FLAG_USE_CHECK_TIME wins, also with time 0, the
         * current time in wolfSSL */
        ExpectIntEQ(wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL),
                    WOLFSSL_SUCCESS);
        wolfSSL_X509_STORE_CTX_set_time(ctx, 0, 0);
        ExpectIntNE(wolfSSL_X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    }
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;
    wolfSSL_X509_STORE_free(store);
    store = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;

#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)

    err_index = 0;

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
                        SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);

    X509_STORE_set_verify_cb(store, X509CallbackCount);

    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(expiredCertFile,
                        SSL_FILETYPE_PEM));

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, cert, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    /* while verifying the certificate, it should have two errors */
    ExpectIntEQ(err_index, 2);
    /* self-signed */
    ExpectIntEQ(last_errcodes[err_index - 2],
                WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    /* expired */
    ExpectIntEQ(last_errcodes[err_index - 1],
                WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED);

    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(store);
    store = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;

    err_index = 0;

    ExpectNotNull(store = X509_STORE_new());
    /* Set NO_CHECK_TIME flag to skip time validation */
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(store->param,
                        WOLFSSL_NO_CHECK_TIME), WOLFSSL_SUCCESS);
    ExpectTrue((store->param->flags & WOLFSSL_NO_CHECK_TIME) ==
        WOLFSSL_NO_CHECK_TIME);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
                        SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);

    X509_STORE_set_verify_cb(store, X509CallbackCount);

    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(expiredCertFile,
                        SSL_FILETYPE_PEM));

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, cert, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_verify_cert(ctx), WOLFSSL_SUCCESS);
    /* while verifying the certificate, it should have an error */
    ExpectIntEQ(err_index, 1);
    /* self-signed */
    ExpectIntEQ(last_errcodes[err_index - 1],
                WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    /* no expired because of no_check_time */
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(store);
    store = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;
#endif
#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_ASN_TIME && !NO_RSA */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
/* 2021-01-01, before the test certificates become valid and well before the
 * test CRL's nextUpdate. */
#define TEST_CRL_DATE_BEFORE_NOTBEFORE 1609459200L

static time_t test_crl_date_override_time_cb(time_t* t)
{
    if (t != NULL)
        *t = (time_t)TEST_CRL_DATE_BEFORE_NOTBEFORE;
    return (time_t)TEST_CRL_DATE_BEFORE_NOTBEFORE;
}
#endif

int test_wolfSSL_X509_verify_cert_crl_date_override(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    X509_STORE* store = NULL;
    X509_STORE_CTX* storeCtx = NULL;
    X509* ca = NULL;
    X509* revoked = NULL;
    X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;
    const char caCert[] = "./certs/ca-cert.pem";
    const char srvRevokedCert[] = "./certs/server-revoked-cert.pem";
    const char crlRevoked[] = "./certs/crl/crl.revoked";
    /* The suite relies on the test certificates being valid now. */
    time_t inValidity = wc_Time(NULL);

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);
    ExpectTrue((fp = XFOPEN(crlRevoked, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);
    ExpectNotNull(revoked = wolfSSL_X509_load_certificate_file(srvRevokedCert,
        SSL_FILETYPE_PEM));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());

    /* The store's CRL is enforced while the certificate is in date. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, revoked, NULL),
        SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);

    /* Put the clock before the certificate's notBefore. The CRL stays
     * current: its nextUpdate is later than either date. */
    ExpectIntEQ(wc_SetTimeCb(test_crl_date_override_time_cb), 0);

    /* Out of date and no override: still rejected. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, revoked, NULL),
        SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);

    /* Waiving the date check must not waive revocation. */
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store),
        X509_V_FLAG_NO_CHECK_TIME), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, revoked, NULL),
        SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);
    ExpectIntEQ(X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(store),
        X509_V_FLAG_NO_CHECK_TIME), SSL_SUCCESS);

    /* Same for a check time that does fall inside the validity period. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, revoked, NULL),
        SSL_SUCCESS);
    X509_STORE_CTX_set_time(storeCtx, 0, inValidity);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);

    /* Restore the real time source even if an expectation above failed. */
    wc_SetTimeCb(NULL);

    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);
    X509_CRL_free(crl);
    X509_free(revoked);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
/* The third verdict to waive is set by the test itself. */
static int test_crl_date_cb_waive[3];
static int test_crl_date_cb_seen[4];
static int test_crl_date_cb_calls;
#ifdef OPENSSL_ALL
static int test_crl_date_cb_ok_calls;
#endif

static int test_crl_date_verify_cb(int ok, X509_STORE_CTX* ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    if (ok) {
#ifdef OPENSSL_ALL
        test_crl_date_cb_ok_calls++;
#endif
        return ok;
    }
    if (test_crl_date_cb_calls < 4)
        test_crl_date_cb_seen[test_crl_date_cb_calls] = err;
    test_crl_date_cb_calls++;
    return (err == test_crl_date_cb_waive[0]) ||
           (err == test_crl_date_cb_waive[1]) ||
           (err == test_crl_date_cb_waive[2]);
}

static int test_crl_date_verify(X509_STORE* store, X509* cert, int waive0,
    int waive1, int* err)
{
    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    test_crl_date_cb_waive[0] = waive0;
    test_crl_date_cb_waive[1] = waive1;
    test_crl_date_cb_calls = 0;
#ifdef OPENSSL_ALL
    test_crl_date_cb_ok_calls = 0;
#endif
    XMEMSET(test_crl_date_cb_seen, 0, sizeof(test_crl_date_cb_seen));
    if ((storeCtx != NULL) &&
            (X509_STORE_CTX_init(storeCtx, store, cert, NULL) ==
             WOLFSSL_SUCCESS)) {
        if ((waive0 != 0) || (waive1 != 0))
            X509_STORE_CTX_set_verify_cb(storeCtx, test_crl_date_verify_cb);
        ret = X509_verify_cert(storeCtx);
        *err = X509_STORE_CTX_get_error(storeCtx);
    }
    X509_STORE_CTX_free(storeCtx);
    return ret;
}

#ifdef OPENSSL_ALL
static int test_crl_date_reject_cb(int ok, X509_STORE_CTX* ctx)
{
    (void)ok;
    (void)ctx;
    return 0;
}
#endif

#if !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(WOLFSSL_SIGNER_DER_CERT)
static int test_crl_date_read_crl(STACK_OF(X509_CRL)* sk, const char* file)
{
    XFILE fp = XFOPEN(file, "rb");
    X509_CRL* crl = NULL;

    if (fp != XBADFILE) {
        crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL, NULL, NULL);
        XFCLOSE(fp);
    }
    if ((crl != NULL) && (sk_X509_CRL_push(sk, crl) > 0))
        return TEST_SUCCESS;
    X509_CRL_free(crl);
    return TEST_FAIL;
}

static int test_crl_date_cm_cb_waive;
static int test_crl_date_cm_cb_calls;

static int test_crl_date_cm_verify_cb(int preverify,
    WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    if (preverify)
        return preverify;
    test_crl_date_cm_cb_calls++;
    return test_crl_date_cm_cb_calls <= test_crl_date_cm_cb_waive;
}
#endif
#endif

/* Each verdict reaches the callback once, revocation first, as in OpenSSL. */
int test_wolfSSL_X509_verify_cert_crl_date_callback(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    X509_STORE* store = NULL;
    X509_STORE* setStore = NULL;
#ifdef OPENSSL_ALL
    X509_STORE* plainStore = NULL;
#endif
    X509_STORE_CTX* storeCtx = NULL;
    STACK_OF(X509_CRL)* crls = NULL;
    X509* ca = NULL;
    X509* cert = NULL;
    X509* revoked = NULL;
    X509_CRL* crl = NULL;
    X509_CRL* ctxCrl = NULL;
    XFILE fp = XBADFILE;
    int err = 0;
    const int noCrl = WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL;
    const int notYet = WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID;
    const int revokedErr = WOLFSSL_X509_V_ERR_CERT_REVOKED;
    const int crlNotYet = WOLFSSL_X509_V_ERR_CRL_NOT_YET_VALID;
    /* Waives no verdict the store reports. */
    const int none = -1;

    test_crl_date_cb_waive[2] = none;

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(
        "./certs/ca-cert.pem", SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);
    ExpectNotNull(setStore = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(setStore, ca), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(setStore, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);
    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(
        "./certs/server-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(revoked = wolfSSL_X509_load_certificate_file(
        "./certs/server-revoked-cert.pem", SSL_FILETYPE_PEM));

    /* A rejected missing CRL is reported once and ends the verification. */
    ExpectIntEQ(test_crl_date_verify(store, cert, notYet, none, &err), 0);
    ExpectIntEQ(err, noCrl);
    ExpectIntEQ(test_crl_date_cb_calls, 1);

#ifdef OPENSSL_ALL
    /* Each certificate that verified is passed to the callback once, the
     * trust anchor included, as in OpenSSL. */
    ExpectNotNull(plainStore = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(plainStore, ca), SSL_SUCCESS);
    ExpectIntEQ(test_crl_date_verify(plainStore, cert, none, none, &err), 1);
    ExpectIntEQ(test_crl_date_cb_ok_calls, 2);
    ExpectIntEQ(test_crl_date_cb_calls, 0);
    /* A store callback can still reject it. */
    if (plainStore != NULL)
        X509_STORE_set_verify_cb(plainStore, test_crl_date_reject_cb);
    ExpectIntNE(test_crl_date_verify(plainStore, cert, 0, 0, &err), 1);
    ExpectIntEQ(err, WOLFSSL_X509_V_ERR_UNSPECIFIED);
    X509_STORE_free(plainStore);
    plainStore = NULL;
#endif

#if !defined(NO_WOLFSSL_CM_VERIFY) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(WOLFSSL_SIGNER_DER_CERT)
    {
        WOLFSSL_CTX* sslCtx = NULL;
        X509_STORE* ctxStore = NULL;

        /* A CertManager callback on the context's store sees the CRL
         * verdict. The context's CA goes on the chain only with its DER. */
        ExpectNotNull(sslCtx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
        ExpectIntEQ(wolfSSL_CTX_load_verify_locations(sslCtx,
            "./certs/ca-cert.pem", NULL), WOLFSSL_SUCCESS);
        ExpectNotNull(ctxStore = wolfSSL_CTX_get_cert_store(sslCtx));
        ExpectIntEQ(X509_STORE_set_flags(ctxStore, X509_V_FLAG_CRL_CHECK),
            SSL_SUCCESS);
        if (sslCtx != NULL) {
            wolfSSL_CertManagerSetVerify(wolfSSL_CTX_GetCertManager(sslCtx),
                test_crl_date_cm_verify_cb);
        }

        test_crl_date_cm_cb_waive = 1;
        test_crl_date_cm_cb_calls = 0;
        ExpectIntEQ(test_crl_date_verify(ctxStore, cert, 0, 0, &err), 1);
        ExpectIntEQ(test_crl_date_cm_cb_calls, 1);

        test_crl_date_cm_cb_waive = 0;
        test_crl_date_cm_cb_calls = 0;
        ExpectIntEQ(test_crl_date_verify(ctxStore, cert, 0, 0, &err), 0);
        ExpectIntEQ(err, noCrl);
        ExpectIntEQ(test_crl_date_cm_cb_calls, 1);

        /* The context CRLs still apply after it rejected the missing CRL. */
        ExpectNotNull(crls = sk_X509_CRL_new_null());
        ExpectIntEQ(test_crl_date_read_crl(crls, "./certs/crl/crl.pem"),
            TEST_SUCCESS);
        ExpectNotNull(storeCtx = X509_STORE_CTX_new());
        ExpectIntEQ(X509_STORE_CTX_init(storeCtx, ctxStore, cert, NULL),
            SSL_SUCCESS);
        X509_STORE_CTX_set0_crls(storeCtx, crls);
        ExpectIntEQ(X509_verify_cert(storeCtx), SSL_SUCCESS);
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        crls = NULL;

        ExpectNotNull(crls = sk_X509_CRL_new_null());
        ExpectIntEQ(test_crl_date_read_crl(crls, "./certs/crl/crl.revoked"),
            TEST_SUCCESS);
        ExpectIntEQ(X509_STORE_CTX_init(storeCtx, ctxStore, revoked, NULL),
            SSL_SUCCESS);
        X509_STORE_CTX_set0_crls(storeCtx, crls);
        X509_STORE_CTX_set_verify_cb(storeCtx, test_crl_date_verify_cb);
        test_crl_date_cb_waive[0] = noCrl;
        test_crl_date_cb_waive[1] = none;
        test_crl_date_cb_calls = 0;
        ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
        ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx), revokedErr);
        X509_STORE_CTX_free(storeCtx);
        storeCtx = NULL;
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        crls = NULL;

        /* As with the store callback, revocation is reported first, so
         * the date error is what is left to reject. */
        ExpectIntEQ(wc_SetTimeCb(test_crl_date_override_time_cb), 0);
        test_crl_date_cm_cb_waive = 1;
        test_crl_date_cm_cb_calls = 0;
        ExpectIntEQ(test_crl_date_verify(ctxStore, cert, 0, 0, &err), 0);
        ExpectIntEQ(err, notYet);
        ExpectIntEQ(test_crl_date_cm_cb_calls, 2);
        wc_SetTimeCb(NULL);

        wolfSSL_CTX_free(sslCtx);
    }
#endif

    /* No CRL is loaded and the certificate is not yet valid. */
    ExpectIntEQ(wc_SetTimeCb(test_crl_date_override_time_cb), 0);

    ExpectIntEQ(test_crl_date_verify(store, cert, notYet, none, &err), 0);
    ExpectIntEQ(err, noCrl);
    ExpectIntEQ(test_crl_date_cb_calls, 1);

    ExpectIntEQ(test_crl_date_verify(store, cert, noCrl, none, &err), 0);
    ExpectIntEQ(err, notYet);
    ExpectIntEQ(test_crl_date_cb_calls, 2);
    ExpectIntEQ(test_crl_date_cb_seen[0], noCrl);
    ExpectIntEQ(test_crl_date_cb_seen[1], notYet);

    /* As in OpenSSL, the dates of the trust anchor are checked too. */
    ExpectIntEQ(test_crl_date_verify(store, cert, noCrl, notYet, &err), 1);
    ExpectIntEQ(err, notYet);
    ExpectIntEQ(test_crl_date_cb_calls, 3);

#ifdef OPENSSL_ALL
    /* The dates are still checked once a missing issuer is waived. As in
     * OpenSSL, the leaf signature that cannot be verified is reported too. */
    ExpectNotNull(plainStore = X509_STORE_new());
    ExpectIntEQ(test_crl_date_verify(plainStore, cert,
        WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE, &err), 0);
    ExpectIntEQ(err, notYet);
    ExpectIntEQ(test_crl_date_cb_calls, 3);
    ExpectIntEQ(test_crl_date_cb_seen[2], notYet);
    X509_STORE_free(plainStore);
    plainStore = NULL;
#endif

    /* Waiving the date check does not waive the missing CRL. */
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store),
        X509_V_FLAG_NO_CHECK_TIME), SSL_SUCCESS);
    ExpectIntEQ(test_crl_date_verify(store, cert, 0, 0, &err), 0);
    ExpectIntEQ(err, noCrl);
    ExpectIntEQ(X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(store),
        X509_V_FLAG_NO_CHECK_TIME), SSL_SUCCESS);

    ExpectTrue((fp = XFOPEN("./certs/crl/crl.revoked", "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    /* As in OpenSSL, the CRL is not yet valid either, and that is reported
     * first. */
    test_crl_date_cb_waive[2] = crlNotYet;
    ExpectIntEQ(test_crl_date_verify(store, revoked, revokedErr, notYet,
        &err), 1);
    ExpectIntEQ(err, notYet);
    ExpectIntEQ(test_crl_date_cb_calls, 4);
    ExpectIntEQ(test_crl_date_cb_seen[0], crlNotYet);
    ExpectIntEQ(test_crl_date_cb_seen[1], revokedErr);
    ExpectIntEQ(test_crl_date_cb_seen[2], notYet);
    ExpectIntEQ(test_crl_date_cb_seen[3], notYet);

    /* A CRL set on the context is consulted before the dates as well. */
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.revoked", "rb")) != XBADFILE);
    ExpectNotNull(ctxCrl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectNotNull(crls = sk_X509_CRL_new_null());
    if (EXPECT_SUCCESS() && (sk_X509_CRL_push(crls, ctxCrl) > 0))
        ctxCrl = NULL;
    ExpectNull(ctxCrl);
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, setStore, revoked, NULL),
        SSL_SUCCESS);
    X509_STORE_CTX_set0_crls(storeCtx, crls);
    X509_STORE_CTX_set_verify_cb(storeCtx, test_crl_date_verify_cb);
    test_crl_date_cb_waive[0] = notYet;
    test_crl_date_cb_waive[1] = none;
    test_crl_date_cb_calls = 0;
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx), revokedErr);
    ExpectIntEQ(test_crl_date_cb_calls, 2);
    ExpectIntEQ(test_crl_date_cb_seen[0], crlNotYet);
    X509_STORE_CTX_free(storeCtx);
    test_crl_date_cb_waive[2] = none;

    wc_SetTimeCb(NULL);

    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_CRL_free(ctxCrl);
    X509_STORE_free(setStore);
    X509_STORE_free(store);
    X509_CRL_free(crl);
    X509_free(revoked);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_CTX_get0_store(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE_CTX* ctx_no_init = NULL;

    ExpectNotNull((store = X509_STORE_new()));
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(ctx_no_init = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, NULL, NULL), SSL_SUCCESS);

    ExpectNull(X509_STORE_CTX_get0_store(NULL));
    /* should return NULL if ctx has not bee initialized */
    ExpectNull(X509_STORE_CTX_get0_store(ctx_no_init));
    ExpectNotNull(X509_STORE_CTX_get0_store(ctx));

    wolfSSL_X509_STORE_CTX_free(ctx);
    wolfSSL_X509_STORE_CTX_free(ctx_no_init);
    X509_STORE_free(store);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    (void) ok;
    (void) ctx;
    fprintf(stderr, "ENTER verify_cb\n");
    return SSL_SUCCESS;
}
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_TLS)
static WOLFSSL* test_app_data_ssl;
static int test_app_data_calls;
static int test_app_data_bad;

/* App data starts NULL and is apart from the SSL. */
static int test_app_data_verify_cb(int ok, X509_STORE_CTX* ctx)
{
    static int data;
    int idx = SSL_get_ex_data_X509_STORE_CTX_idx();

    test_app_data_calls++;
    if ((test_app_data_calls == 1) &&
            (X509_STORE_CTX_get_app_data(ctx) != NULL)) {
        test_app_data_bad = 1;
    }
#ifdef HAVE_EX_DATA
    if ((X509_STORE_CTX_set_app_data(ctx, &data) != WOLFSSL_SUCCESS) ||
            (X509_STORE_CTX_get_app_data(ctx) != &data) ||
            (X509_STORE_CTX_get_ex_data(ctx, idx) != test_app_data_ssl)) {
        test_app_data_bad = 1;
    }
#else
    (void)idx;
    if ((X509_STORE_CTX_set_app_data(ctx, &data) !=
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) ||
            (X509_STORE_CTX_get_app_data(ctx) != NULL)) {
        test_app_data_bad = 1;
    }
#endif
    return ok;
}

static int test_X509_STORE_CTX_app_data_tls(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
#ifndef WOLFSSL_NO_TLS12
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);
#else
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
#endif
    test_app_data_ssl = ssl_c;
    test_app_data_calls = 0;
    test_app_data_bad = 0;
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_PEER, test_app_data_verify_cb);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntGT(test_app_data_calls, 0);
    ExpectIntEQ(test_app_data_bad, 0);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_X509_STORE_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    X509* x509 = NULL;
#ifdef OPENSSL_ALL
    X509* x5092 = NULL;
    STACK_OF(X509) *sk = NULL;
    STACK_OF(X509) *sk2 = NULL;
    STACK_OF(X509) *sk3 = NULL;
#endif

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull((x509 =
        wolfSSL_X509_load_certificate_file(svrCertFile, SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(str, x509), SSL_SUCCESS);
#ifdef OPENSSL_ALL
    /* sk_X509_new only in OPENSSL_ALL */
    sk = sk_X509_new_null();
    ExpectNotNull(sk);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, x509, sk), SSL_SUCCESS);
#else
    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, x509, NULL), SSL_SUCCESS);
#endif
    ExpectIntEQ(SSL_get_ex_data_X509_STORE_CTX_idx(), 0);
    X509_STORE_CTX_set_error(ctx, -5);
    X509_STORE_CTX_set_error(NULL, -5);

    X509_STORE_CTX_free(ctx);
    ctx = NULL;
#ifdef OPENSSL_ALL
    sk_X509_pop_free(sk, NULL);
    sk = NULL;
#endif
    X509_STORE_free(str);
    str = NULL;
    X509_free(x509);
    x509 = NULL;

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    X509_STORE_CTX_set_verify_cb(ctx, verify_cb);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

#ifdef OPENSSL_ALL
    /* test X509_STORE_CTX_get(1)_chain */
    ExpectNotNull((x509 = X509_load_certificate_file(svrCertFile,
                                                     SSL_FILETYPE_PEM)));
    ExpectNotNull((x5092 = X509_load_certificate_file(cliCertFile,
                                                     SSL_FILETYPE_PEM)));
    ExpectNotNull((sk = sk_X509_new_null()));
    ExpectIntEQ(sk_X509_push(sk, x509), 1);
    if (EXPECT_FAIL()) {
        X509_free(x509);
        x509 = NULL;
    }
    ExpectNotNull((str = X509_STORE_new()));
    ExpectNotNull((ctx = X509_STORE_CTX_new()));
    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, x5092, sk), 1);
    ExpectNull((sk2 = X509_STORE_CTX_get_chain(NULL)));
    ExpectNull((sk2 = X509_STORE_CTX_get_chain(ctx)));
    ExpectNull((sk3 = X509_STORE_CTX_get1_chain(NULL)));
    ExpectNull((sk3 = X509_STORE_CTX_get1_chain(ctx)));
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(str);
    str = NULL;
    /* CTX certs not freed yet */
    X509_free(x5092);
    x5092 = NULL;
    sk_X509_pop_free(sk, NULL);
    sk = NULL;
    /* sk3 is dup so free here */
    sk_X509_pop_free(sk3, NULL);
    sk3 = NULL;
#endif

    /* test X509_STORE_CTX_get/set_ex_data */
    {
        int i = 0, tmpData = 5;
        void* tmpDataRet;
        ExpectNotNull(ctx = X509_STORE_CTX_new());
    #ifdef HAVE_EX_DATA
        for (i = 0; i < MAX_EX_DATA; i++) {
            ExpectIntEQ(X509_STORE_CTX_set_ex_data(ctx, i, &tmpData),
                        WOLFSSL_SUCCESS);
            tmpDataRet = (int*)X509_STORE_CTX_get_ex_data(ctx, i);
            ExpectNotNull(tmpDataRet);
            ExpectIntEQ(tmpData, *(int*)tmpDataRet);
        }
    #else
        ExpectIntEQ(X509_STORE_CTX_set_ex_data(ctx, i, &tmpData),
                    WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
        tmpDataRet = (int*)X509_STORE_CTX_get_ex_data(ctx, i);
        ExpectNull(tmpDataRet);
    #endif
        X509_STORE_CTX_free(ctx);
        ctx = NULL;
    }

    /* test X509_STORE_CTX_get/set_app_data */
    {
        int tmpData = 7;
        ExpectNotNull(ctx = X509_STORE_CTX_new());
        ExpectNull(X509_STORE_CTX_get_app_data(ctx));
    #ifdef HAVE_EX_DATA
        ExpectIntEQ(X509_STORE_CTX_set_app_data(ctx, &tmpData),
                    WOLFSSL_SUCCESS);
        ExpectPtrEq(X509_STORE_CTX_get_app_data(ctx), &tmpData);
        ExpectNull(X509_STORE_CTX_get_ex_data(ctx, 0));
        /* init and cleanup clear it */
        ExpectIntEQ(X509_STORE_CTX_init(ctx, NULL, NULL, NULL),
                    WOLFSSL_SUCCESS);
        ExpectNull(X509_STORE_CTX_get_app_data(ctx));
        ExpectIntEQ(X509_STORE_CTX_set_app_data(ctx, &tmpData),
                    WOLFSSL_SUCCESS);
        X509_STORE_CTX_cleanup(ctx);
        ExpectNull(X509_STORE_CTX_get_app_data(ctx));
    #else
        ExpectIntEQ(X509_STORE_CTX_set_app_data(ctx, &tmpData),
                    WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
        ExpectNull(X509_STORE_CTX_get_app_data(ctx));
    #endif
        X509_STORE_CTX_free(ctx);
        ctx = NULL;
    }
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && !defined(NO_TLS)
    ExpectIntEQ(test_X509_STORE_CTX_app_data_tls(), TEST_SUCCESS);
#endif

    /* test X509_STORE_get/set_ex_data */
    {
        int i = 0, tmpData = 99;
        void* tmpDataRet;
        ExpectNotNull(str = X509_STORE_new());
    #ifdef HAVE_EX_DATA
        for (i = 0; i < MAX_EX_DATA; i++) {
            ExpectIntEQ(X509_STORE_set_ex_data(str, i, &tmpData),
                        WOLFSSL_SUCCESS);
            tmpDataRet = (int*)X509_STORE_get_ex_data(str, i);
            ExpectNotNull(tmpDataRet);
            ExpectIntEQ(tmpData, *(int*)tmpDataRet);
        }
    #else
        ExpectIntEQ(X509_STORE_set_ex_data(str, i, &tmpData),
                    WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
        tmpDataRet = (int*)X509_STORE_get_ex_data(str, i);
        ExpectNull(tmpDataRet);
    #endif
        X509_STORE_free(str);
        str = NULL;
    }

#endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
        * !defined(NO_FILESYSTEM) && !defined(NO_RSA) */

    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA)

typedef struct {
    const char *caFile;
    const char *caIntFile;
    const char *caInt2File;
    const char *leafFile;
    X509 *x509Ca;
    X509 *x509CaInt;
    X509 *x509CaInt2;
    X509 *x509Leaf;
    STACK_OF(X509)* expectedChain;
} X509_STORE_test_data;

static X509 * test_wolfSSL_X509_STORE_CTX_ex_helper(const char *file)
{
    XFILE fp = XBADFILE;
    X509 *x = NULL;

    fp = XFOPEN(file, "rb");
    if (fp == NULL) {
        return NULL;
    }
    x = PEM_read_X509(fp, 0, 0, 0);
    XFCLOSE(fp);

    return x;
}

static int test_wolfSSL_X509_STORE_CTX_ex1(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    STACK_OF(X509)* chain1 = NULL;
    int i = 0;

    /* Test case 1, add X509 certs to store and verify */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    /* get1_chain references the same certs. */
    ExpectNotNull(chain1 = X509_STORE_CTX_get1_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain1), sk_X509_num(chain));
    for (i = 0; i < sk_X509_num(chain1); i++) {
        ExpectPtrEq(sk_X509_value(chain1, i), sk_X509_value(chain, i));
    }
    sk_X509_pop_free(chain1, X509_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex2(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    int i = 0;

    /* Test case 2, add certs by filename to store and verify */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_load_locations(
        store, testData->caFile, NULL), 1);
    ExpectIntEQ(X509_STORE_load_locations(
        store, testData->caIntFile, NULL), 1);
    ExpectIntEQ(X509_STORE_load_locations(
        store, testData->caInt2File, NULL), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex3(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    int i = 0;

    /* Test case 3, mix and match X509 with files */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectIntEQ(X509_STORE_load_locations(
        store, testData->caFile, NULL), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex4(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    STACK_OF(X509)* inter = NULL;
    int i = 0;

    /* Test case 4, CA loaded by file, intermediates passed on init */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_load_locations(
        store, testData->caFile, NULL), 1);
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(inter, testData->x509CaInt), 1);
    ExpectIntGE(sk_X509_push(inter, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, inter), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(inter);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex5(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    STACK_OF(X509)* trusted = NULL;
    int i = 0;

    /* Test case 5, manually set trusted stack */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(trusted, testData->x509Ca), 1);
    ExpectIntGE(sk_X509_push(trusted, testData->x509CaInt), 1);
    ExpectIntGE(sk_X509_push(trusted, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex6(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* inter = NULL;
    int i = 0;

    /* Test case 6, manually set trusted stack will be unified with
     * any intermediates provided on init */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(trusted, testData->x509Ca), 1);
    ExpectIntGE(sk_X509_push(inter, testData->x509CaInt), 1);
    ExpectIntGE(sk_X509_push(inter, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, inter), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    sk_X509_free(inter);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex7(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    int i = 0;

    /* Test case 7, certs added to store after ctx init are still used */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex8(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    int i = 0;

    /* Test case 8, Only full chain verifies */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    ExpectIntEQ(sk_X509_num(chain), sk_X509_num(testData->expectedChain));
    for (i = 0; i < sk_X509_num(chain); i++) {
        ExpectIntEQ(X509_cmp(sk_X509_value(chain, i),
                             sk_X509_value(testData->expectedChain, i)), 0);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex9(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE_CTX* ctx2 = NULL;
    STACK_OF(X509)* trusted = NULL;

    /* Test case 9, certs added to store should not be reflected in ctx that
     * has been manually set with a trusted stack, but are reflected in ctx
     * that has not set trusted stack */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(ctx2 = X509_STORE_CTX_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(trusted, testData->x509Ca), 1);
    ExpectIntGE(sk_X509_push(trusted, testData->x509CaInt), 1);
    ExpectIntGE(sk_X509_push(trusted, testData->x509CaInt2), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx2, store, testData->x509Leaf, NULL), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntNE(X509_verify_cert(ctx2), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    /* CTX1 should now verify */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntNE(X509_verify_cert(ctx2), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    /* CTX2 should now verify */
    ExpectIntEQ(X509_verify_cert(ctx2), 1);
    X509_STORE_CTX_free(ctx);
    X509_STORE_CTX_free(ctx2);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex10(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;

    /* Test case 10, ensure partial chain flag works */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    /* Fails because chain is incomplete */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);
    /* As in OpenSSL, init takes the store's flags */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    /* Partial chain now OK */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex11(X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;

    /* Test case 11, test partial chain flag on ctx itself */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    /* Fails because chain is incomplete */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    /* Partial chain now OK */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex_partial_chain_neg(
    X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    /* Negative partial-chain test: with X509_V_FLAG_PARTIAL_CHAIN set, the
     * intermediates are supplied ONLY as untrusted (passed through the
     * X509_STORE_CTX_init "chain" argument and never added to the store).
     * No certificate in the chain is in the store, so verification must
     * fail.  Pre-fix, wolfSSL_X509_verify_cert would incorrectly accept
     * this chain because its partial-chain fallback only checked that some
     * intermediate had been temporarily loaded into the CertManager, not
     * that any chain certificate was actually trusted. */
    ExpectNotNull(store = X509_STORE_new());
    /* Intentionally do NOT add x509CaInt, x509CaInt2, or x509Ca. */
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);

    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, testData->x509CaInt2), 0);
    ExpectIntGT(sk_X509_push(untrusted, testData->x509CaInt), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, untrusted),
        1);
    /* Must NOT verify: partial-chain does not relax the trust requirement. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    /* Verify the failure is specifically due to missing trust anchor, not
     * some unrelated error. */
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex_partial_chain_mixed(
    X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    /* Mixed trusted-store + untrusted-chain partial-chain test: the store
     * trusts an intermediate (x509CaInt2, the leaf's direct issuer), while
     * an additional intermediate (x509CaInt) is supplied only as untrusted
     * via the chain argument.  With X509_V_FLAG_PARTIAL_CHAIN, verification
     * must succeed by terminating at the trusted intermediate.  This test
     * exercises the snapshot-based trust check in X509StoreCertIsTrusted:
     * the untrusted intermediate injected during verification must not be
     * treated as a trust anchor, but the intermediate already in the store
     * must be. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509CaInt2), 1);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);

    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, testData->x509CaInt), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, untrusted),
        1);
    /* Must verify: chain terminates at trusted intermediate in the store. */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_CTX_ex_partial_chain_untrusted_terminal(
    X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    /* Partial-chain boundary test: the store trusts a CA (x509Ca) that is
     * NOT reachable from the leaf given the supplied untrusted intermediates,
     * and an untrusted intermediate (x509CaInt2) IS the terminal of the
     * (truncated) chain.  With X509_V_FLAG_PARTIAL_CHAIN set, verification
     * must FAIL because the chain terminates at an untrusted certificate.
     *
     * This test specifically targets the snapshot-based trust check in
     * X509StoreCertIsTrusted.  Before addAllButSelfSigned injects
     * x509CaInt2, origTrustedSk is snapshotted from the caller-trusted set
     * and contains only x509Ca.  When the chain terminates at x509CaInt2,
     * the trust check consults origTrustedSk (not the mutated working
     * stack) and correctly finds no match.  A regression that consulted
     * the post-injection working stack instead of the snapshot would
     * incorrectly mark x509CaInt2 as trusted and cause verification to
     * succeed. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);

    /* Only x509CaInt2 supplied as untrusted; x509CaInt is intentionally
     * withheld so the chain cannot actually reach the trusted x509Ca. */
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, testData->x509CaInt2), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, untrusted),
        1);
    /* Must NOT verify: the chain terminal (x509CaInt2) is not in the
     * original trust set, even though the store is non-empty. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Certificate the callback below vetoes, and whether it ever got to. */
static X509* partialChainRejectCert;
static int partialChainRejectSeen;

static int partial_chain_reject_cb(int ok, X509_STORE_CTX* store_ctx)
{
    if (ok && X509_STORE_CTX_get_current_cert(store_ctx) ==
            partialChainRejectCert) {
        partialChainRejectSeen = 1;
        /* Reject a certificate the verification itself accepted. */
        return 0;
    }
    return ok;
}

static int test_wolfSSL_X509_STORE_CTX_ex_partial_chain_cb_reject(
    X509_STORE_test_data *testData)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;

    /* A per-context verify callback that rejects a certificate must not be
     * overruled by the partial-chain terminus.  The chain ends at the trusted
     * intermediate, which verifies successfully - only the callback rejects
     * it, when signalled success at its depth.  A WOLFSSL_PARTIAL_CHAIN
     * fallback must not accept the chain at that same (caller-trusted)
     * certificate and clear ctx->error, reporting X509_V_OK for a chain the
     * application refused. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, testData->x509Ca), 1);

    /* Trust the two intermediates through the ctx override instead of the
     * store. */
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(trusted, testData->x509CaInt2), 0);
    ExpectIntGT(sk_X509_push(trusted, testData->x509CaInt), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, testData->x509Leaf, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    /* After init, which clears any callback already on the context.
     * With X509_V_FLAG_PARTIAL_CHAIN the chain ends at the first trusted
     * cert, x509CaInt2, as in OpenSSL: x509CaInt is never seen. */
    partialChainRejectCert = testData->x509CaInt2;
    partialChainRejectSeen = 0;
    X509_STORE_CTX_set_verify_cb(ctx, partial_chain_reject_cb);

    /* Sanity check that the setup reached the veto at all - without it the
     * verification result below would prove nothing. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(partialChainRejectSeen, 1);
    /* The rejection has to be reportable, not X509_V_OK. */
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNSPECIFIED);
#ifndef NO_ERROR_STRINGS
    /* And it has to render as a verification error.  Without a reason string
     * of its own, X509_V_ERR_UNSPECIFIED (1) falls through to the negated
     * lookup and comes back out as the unrelated TLS "fatal error". */
    ExpectStrEQ(X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
        "unspecified certificate verification error");
#endif

    partialChainRejectCert = NULL;
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

#ifdef HAVE_ECC
static int test_wolfSSL_X509_STORE_CTX_ex12(void)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;
    X509* rootEccX509 = NULL;
    X509* badAkiX509 = NULL;
    X509* ca1X509 = NULL;

    const char* intCARootECCFile   = "./certs/ca-ecc-cert.pem";
    const char* intCA1ECCFile      = "./certs/intermediate/ca-int-ecc-cert.pem";
    const char* intCABadAKIECCFile = "./certs/intermediate/ca-ecc-bad-aki.pem";

    /* Test case 12, multiple CAs with the same SKI including 1 with
       intentionally bad/unregistered AKI.  x509_verify_cert should still form a
       valid chain using the valid CA, ignoring the bad CA. Developed from
       customer provided reproducer. */

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(rootEccX509 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        intCARootECCFile));
    ExpectIntEQ(X509_STORE_add_cert(store, rootEccX509), 1);
    ExpectNotNull(badAkiX509 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        intCABadAKIECCFile));
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, badAkiX509, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    X509_STORE_CTX_cleanup(ctx);

    ExpectIntEQ(X509_STORE_add_cert(store, badAkiX509), 1);
    ExpectNotNull(ca1X509 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        intCA1ECCFile));
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, ca1X509, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(chain = X509_STORE_CTX_get_chain(ctx));

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(rootEccX509);
    X509_free(badAkiX509);
    X509_free(ca1X509);
    return EXPECT_RESULT();
}
#endif
#endif

/* Regression test for the x509-limbo "pathlen" finding:
 * wolfSSL_X509_verify_cert() must enforce the BasicConstraints
 * pathLenConstraint (RFC 5280 sec. 4.2.1.9 / sec. 6.1.4).  A CA asserting
 * pathlen:0 may only issue end-entity certificates; it must not be permitted
 * to issue a further intermediate CA.  Reuses the certs/test-pathlen chains
 * (see certs/test-pathlen/assemble-chains.sh):
 *
 *   ca-cert -> chainF-ICA2 (CA, pathlen:0) -> chainF-ICA1 (CA) -> entity
 *
 * chainF-ICA1 is an intermediate CA following the pathlen:0 chainF-ICA2, which
 * RFC 5280 sec. 6.1.4 forbids, so the chain must be rejected with
 * X509_V_ERR_PATH_LENGTH_EXCEEDED.  Before the fix this OpenSSL-compatibility
 * path accepted the chain because each certificate was verified individually
 * (as CERT_TYPE) without the issuer pathLen check the TLS handshake path
 * performs. */
int test_wolfSSL_X509_verify_cert_pathlen(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509* root = NULL;
    X509* ica2 = NULL;
    X509* ica1 = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* inter = NULL;

    ExpectNotNull(root = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/ca-cert.pem"));
    ExpectNotNull(ica2 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA2-pathlen0.pem"));
    ExpectNotNull(ica1 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA1-pathlen1.pem"));
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-entity.pem"));

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(inter, ica2), 0);
    ExpectIntGT(sk_X509_push(inter, ica1), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, inter), 1);
    /* Must be rejected: chainF-ICA1 violates chainF-ICA2's pathlen:0. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_PATH_LENGTH_EXCEEDED);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(inter);
    X509_free(root);
    X509_free(ica2);
    X509_free(ica1);
    X509_free(leaf);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

/* Positive control: a legitimate chain whose intermediates assert pathlen:1
 * then pathlen:0 must still verify, guarding pathLen enforcement against
 * over-rejection.  Reuses the certs/test-pathlen chainB:
 *
 *   ca-cert -> chainB-ICA2 (CA, pathlen:1) -> chainB-ICA1 (CA, pathlen:0)
 *           -> entity
 *
 * chainB-ICA2 permits one following intermediate (chainB-ICA1), so the chain
 * is valid. */
int test_wolfSSL_X509_verify_cert_pathlen_ok(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509* root = NULL;
    X509* ica2 = NULL;
    X509* ica1 = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* inter = NULL;

    ExpectNotNull(root = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/ca-cert.pem"));
    ExpectNotNull(ica2 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainB-ICA2-pathlen1.pem"));
    ExpectNotNull(ica1 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainB-ICA1-pathlen0.pem"));
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainB-entity.pem"));

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(inter, ica2), 0);
    ExpectIntGT(sk_X509_push(inter, ica1), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, inter), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(inter);
    X509_free(root);
    X509_free(ica2);
    X509_free(ica1);
    X509_free(leaf);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
/* Records whether the pathLen violation was surfaced to the verify callback,
 * then overrides it (returns 1) so verification continues - exercising the
 * verify_cb override branch in X509StoreCheckPathLen(). */
static int pathlen_override_seen = 0;
static int pathlen_override_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_PATH_LENGTH_EXCEEDED)
        pathlen_override_seen = 1;
    return 1; /* override: accept despite the error */
}

/* Drives the rejecting chainF with pathlen_override_cb installed on the store
 * context (onCtx) or on the store itself.  Either way the callback must reach
 * the override branch in X509StoreCheckPathLen() and the chain must verify. */
static int test_pathlen_override_with_cb(int onCtx)
{
    EXPECT_DECLS;
    X509* root = NULL;
    X509* ica2 = NULL;
    X509* ica1 = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* inter = NULL;

    pathlen_override_seen = 0;

    ExpectNotNull(root = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/ca-cert.pem"));
    ExpectNotNull(ica2 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA2-pathlen0.pem"));
    ExpectNotNull(ica1 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA1-pathlen1.pem"));
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-entity.pem"));

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    if (!onCtx) {
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        X509_STORE_set_verify_cb(store, pathlen_override_cb);
    #endif
    }
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(inter, ica2), 0);
    ExpectIntGT(sk_X509_push(inter, ica1), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, inter), 1);
    if (onCtx) {
        /* After init, which clears any callback already on the context. */
        X509_STORE_CTX_set_verify_cb(ctx, pathlen_override_cb);
    }
    /* The callback overrides the violation, so verification now succeeds... */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* ...and the callback must actually have seen the pathLen error. */
    ExpectIntEQ(pathlen_override_seen, 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(inter);
    X509_free(root);
    X509_free(ica2);
    X509_free(ica1);
    X509_free(leaf);
    return EXPECT_RESULT();
}
#endif

/* A verify callback that returns 1 must be able to override the pathLen
 * violation, matching the INVALID_CA override handling in
 * wolfSSL_X509_verify_cert().  Reuses the rejecting chainF: with the override
 * callback installed the same chain must now verify, and the callback must have
 * observed X509_V_ERR_PATH_LENGTH_EXCEEDED. */
int test_wolfSSL_X509_verify_cert_pathlen_override(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    ExpectIntEQ(test_pathlen_override_with_cb(0), TEST_SUCCESS);
#endif /* OPENSSL_ALL && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

/* Same override, but through the per-context callback, which every
 * OPENSSL_EXTRA build can install - the store callback needs OPENSSL_ALL or
 * WOLFSSL_QT.  Without this the pathLen override branch goes untested in a
 * plain --enable-opensslextra build. */
int test_wolfSSL_X509_verify_cert_pathlen_override_ctx_cb(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    ExpectIntEQ(test_pathlen_override_with_cb(1), TEST_SUCCESS);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_ASN_TIME)
/* Rejects whatever it is handed and records that it ran. Installed on the
 * store ctx, to prove the per-context callback is consulted. */
static int ctx_reject_seen = 0;
static int ctx_reject_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;
    ctx_reject_seen = 1;
    return 0; /* reject */
}

/* Rejects, but records an error of its own first, the way an application
 * enforcing extra policy does. That error must survive. */
static int ctx_reject_seterr_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0; /* reject */
}

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
/* Accepts whatever it is handed. Installed on the store, so the rejecting
 * per-context callback has something to take precedence over. */
static int store_accept_seen = 0;
static int store_accept_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;
    store_accept_seen = 1;
    return 1; /* accept */
}
#endif
#endif

/* A callback installed with X509_STORE_CTX_set_verify_cb must be honored by
 * X509_verify_cert().  The chain verifies cleanly on its own, so a rejecting
 * callback is the only thing that can fail it.  Also pins that the
 * per-context callback wins over the store's, and that
 * X509_STORE_CTX_init() clears it. */
int test_wolfSSL_X509_STORE_CTX_verify_cb(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_ASN_TIME)
    X509* ca = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;

    ctx_reject_seen = 0;

    ExpectNotNull(ca = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/ca-cert.pem"));
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/server-cert.pem"));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);

    /* Sanity check: the chain verifies with no callback installed. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Same chain, but now a per-context callback rejects it. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, ctx_reject_cb);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(ctx_reject_seen, 1);
    /* A rejected verification must be reportable through get_error(). The
     * callback set no error of its own, so the generic one stands in, as in
     * OpenSSL. Leaving X509_V_OK here would tell the application the chain
     * was fine. */
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNSPECIFIED);

    /* Re-initializing the same context must drop that callback again. */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ctx_reject_seen = 0;
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(ctx_reject_seen, 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* An error the callback records itself must not be replaced. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, ctx_reject_seterr_cb);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_APPLICATION_VERIFICATION);

    X509_STORE_CTX_free(ctx);
    ctx = NULL;

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    /* The per-context callback takes precedence over the store's, so the
     * rejecting one still decides even though the store accepts. */
    X509_STORE_set_verify_cb(store, store_accept_cb);
    store_accept_seen = 0;
    ctx_reject_seen = 0;

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, ctx_reject_cb);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(ctx_reject_seen, 1);
    ExpectIntEQ(store_accept_seen, 0);
#endif

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(ca);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA &&
        * !NO_ASN_TIME */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_ASN_TIME) && !defined(NO_ASN)
/* Records each rejection and its error, then overrides it only if
 * checkid_cb_accept says to; anything else is accepted. */
static int checkid_cb_rejects = 0;
static int checkid_cb_error = 0;
static int checkid_cb_accept = 1;
static int checkid_override_cb(int ok, X509_STORE_CTX* ctx)
{
    if (ok == 0) {
        checkid_cb_rejects++;
        checkid_cb_error = X509_STORE_CTX_get_error(ctx);
        return checkid_cb_accept;
    }
    return 1; /* accept */
}
#endif

/* A hostname or IP mismatch from X509_VERIFY_PARAM must be reported to the
 * verify callback with ok=0, and the callback's acceptance must override it,
 * as OpenSSL's check_id_error() does. */
int test_wolfSSL_X509_STORE_CTX_verify_cb_check_id(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_ASN_TIME) && !defined(NO_ASN)
    X509* ca = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_VERIFY_PARAM* param = NULL;

    ExpectNotNull(ca = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/ca-cert.pem"));
    /* server-cert.pem carries SAN DNS:example.com and IP:127.0.0.1. */
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/server-cert.pem"));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);

    /* Sanity check: with a matching hostname the chain verifies and the
     * callback is never handed a rejection. */
    checkid_cb_rejects = 0;
    checkid_cb_error = 0;
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, checkid_override_cb);
    ExpectNotNull(param = X509_STORE_CTX_get0_param(ctx));
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(param, "example.com", 0), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(checkid_cb_rejects, 0);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    param = NULL;

    /* Same chain, mismatching hostname: the callback must see ok=0 with
     * X509_V_ERR_HOSTNAME_MISMATCH, and its acceptance must stand. */
    checkid_cb_rejects = 0;
    checkid_cb_error = 0;
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, checkid_override_cb);
    ExpectNotNull(param = X509_STORE_CTX_get0_param(ctx));
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(param, "not-example.com", 0), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(checkid_cb_rejects, 1);
    ExpectIntEQ(checkid_cb_error, X509_V_ERR_HOSTNAME_MISMATCH);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    param = NULL;

#ifdef WOLFSSL_IP_ALT_NAME
    /* Mismatching IP: same contract, with X509_V_ERR_IP_ADDRESS_MISMATCH. */
    checkid_cb_rejects = 0;
    checkid_cb_error = 0;
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, checkid_override_cb);
    ExpectNotNull(param = X509_STORE_CTX_get0_param(ctx));
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(param, "10.0.0.1"), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(checkid_cb_rejects, 1);
    ExpectIntEQ(checkid_cb_error, X509_V_ERR_IP_ADDRESS_MISMATCH);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    param = NULL;
#endif /* WOLFSSL_IP_ALT_NAME */

    /* A callback that declines to override must leave the mismatch fatal: only
     * a return of 1 overrides it. */
    checkid_cb_rejects = 0;
    checkid_cb_error = 0;
    checkid_cb_accept = 0;
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, checkid_override_cb);
    ExpectNotNull(param = X509_STORE_CTX_get0_param(ctx));
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(param, "not-example.com", 0), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(checkid_cb_rejects, 1);
    ExpectIntEQ(checkid_cb_error, X509_V_ERR_HOSTNAME_MISMATCH);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_HOSTNAME_MISMATCH);
    checkid_cb_accept = 1;
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    param = NULL;

    /* With no callback installed the mismatch must still fail closed and stay
     * reportable through get_error(). */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectNotNull(param = X509_STORE_CTX_get0_param(ctx));
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(param, "not-example.com", 0), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_HOSTNAME_MISMATCH);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(ca);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA &&
        * !NO_ASN_TIME && !NO_ASN */
    return EXPECT_RESULT();
}

/* The trust anchor's own pathLenConstraint must bound the path (matching
 * OpenSSL's -partial_chain behavior and wolfSSL's native ParseCertRelative).
 * Trust chainF-ICA2 (pathlen:0) directly as a partial-chain anchor and verify
 * the entity through chainF-ICA1 (a CA): chainF-ICA1 exceeds the anchor's
 * pathlen:0, so it must be rejected.  This exercises the anchor-seeding branch
 * of X509StoreCheckPathLen() (the violation comes from the anchor's constraint,
 * not an intermediate's). */
int test_wolfSSL_X509_verify_cert_pathlen_anchor(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509* ica2 = NULL;
    X509* ica1 = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* inter = NULL;

    ExpectNotNull(ica2 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA2-pathlen0.pem"));
    ExpectNotNull(ica1 = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-ICA1-pathlen1.pem"));
    ExpectNotNull(leaf = test_wolfSSL_X509_STORE_CTX_ex_helper(
        "./certs/test-pathlen/chainF-entity.pem"));

    /* Trust the pathlen:0 intermediate directly as a partial-chain anchor. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, ica2), 1);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);
    ExpectNotNull(inter = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(inter, ica1), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, inter), 1);
    /* Must be rejected: chainF-ICA1 exceeds anchor chainF-ICA2's pathlen:0. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_PATH_LENGTH_EXCEEDED);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(inter);
    X509_free(ica2);
    X509_free(ica1);
    X509_free(leaf);
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_FILESYSTEM && !NO_RSA */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_CTX_ex(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE_test_data testData;
    XMEMSET((void *)&testData, 0, sizeof(X509_STORE_test_data));
    testData.caFile =     "./certs/ca-cert.pem";
    testData.caIntFile =  "./certs/intermediate/ca-int-cert.pem";
    testData.caInt2File = "./certs/intermediate/ca-int2-cert.pem";
    testData.leafFile =   "./certs/intermediate/server-chain.pem";

    ExpectNotNull(testData.x509Ca = \
                  test_wolfSSL_X509_STORE_CTX_ex_helper(testData.caFile));
    ExpectNotNull(testData.x509CaInt = \
                  test_wolfSSL_X509_STORE_CTX_ex_helper(testData.caIntFile));
    ExpectNotNull(testData.x509CaInt2 = \
                  test_wolfSSL_X509_STORE_CTX_ex_helper(testData.caInt2File));
    ExpectNotNull(testData.x509Leaf = \
                  test_wolfSSL_X509_STORE_CTX_ex_helper(testData.leafFile));
    ExpectNotNull(testData.expectedChain = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(testData.expectedChain, testData.x509Leaf), 1);
    ExpectIntGE(sk_X509_push(testData.expectedChain, testData.x509CaInt2), 1);
    ExpectIntGE(sk_X509_push(testData.expectedChain, testData.x509CaInt), 1);
    ExpectIntGE(sk_X509_push(testData.expectedChain, testData.x509Ca), 1);

    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex1(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex2(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex3(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex4(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex5(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex6(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex7(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex8(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex9(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex10(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex11(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex_partial_chain_neg(&testData), 1);
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex_partial_chain_mixed(&testData),
        1);
    ExpectIntEQ(
        test_wolfSSL_X509_STORE_CTX_ex_partial_chain_untrusted_terminal(
            &testData), 1);
    ExpectIntEQ(
        test_wolfSSL_X509_STORE_CTX_ex_partial_chain_cb_reject(&testData), 1);
#ifdef HAVE_ECC
    ExpectIntEQ(test_wolfSSL_X509_STORE_CTX_ex12(), 1);
#endif

    if(testData.x509Ca) {
        X509_free(testData.x509Ca);
    }
    if(testData.x509CaInt) {
        X509_free(testData.x509CaInt);
    }
    if(testData.x509CaInt2) {
        X509_free(testData.x509CaInt2);
    }
    if(testData.x509Leaf) {
        X509_free(testData.x509Leaf);
    }
    if (testData.expectedChain) {
        sk_X509_free(testData.expectedChain);
    }

#endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
        * !defined(NO_FILESYSTEM) && !defined(NO_RSA) */

    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
/* Regression: an untrusted intermediate supplied to wolfSSL_X509_verify_cert()
 * via the X509_STORE_CTX_init "chain" argument must never be treated as a
 * trust anchor.  Verification may only succeed when the chain terminates at a
 * certificate the caller actually trusts.
 *
 *     leaf (CN=www.example.test) <- int-ca (CA) <- root-ca (self-signed)
 *
 * The attack sub-cases (empty trust store, a populated-but-wrong trust anchor,
 * and a tampered intermediate signature) must all be rejected; the single- and
 * two-intermediate chains that genuinely reach the trusted root must still
 * verify.  Certificates live in certs/intermediate/untrusted_anchor/.
 */
#define UA_CERT_DIR "./certs/intermediate/untrusted_anchor/"

static X509* untrusted_inter_load(const char* file)
{
    return X509_load_certificate_file(file, SSL_FILETYPE_PEM);
}

/* Positive control: leaf <- int-ca <- root with the genuine self-signed root
 * trusted.  Must verify - guards against a test that merely rejects
 * everything. */
static int test_untrusted_inter_sanity(X509* leaf, X509* inter, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    /* Chain reaches the trusted root -> must verify. */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Positive control with two untrusted intermediates:
 *     leaf-deep <- int-ca2 <- int-ca <- root  (root trusted).
 * A legitimate multi-level chain that genuinely reaches the trusted root must
 * still verify; guards against over-rejecting deeper chains. */
static int test_untrusted_inter_two_level(X509* leafDeep, X509* inter,
    X509* inter2, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectIntGT(sk_X509_push(untrusted, inter2), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    /* Two-level chain reaches the trusted root -> must verify. */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Empty trust store.  The untrusted intermediate must not anchor the path -
 * with nothing trusted, verification must fail. */
static int test_untrusted_inter_empty_store(X509* leaf, X509* inter)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    /* Intentionally empty: no trusted certificates added. */
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    /* No trust anchor exists -> rejected with "issuer not found". */
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Populated but wrong trust store.  An unrelated self-signed root is trusted;
 * it did not issue the intermediate, so verification must fail. */
static int test_untrusted_inter_wrong_anchor(X509* leaf, X509* inter,
    X509* wrongRoot)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, wrongRoot), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    /* Trusted root did not issue the intermediate -> "issuer not found". */
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Tampered intermediate signature.  The real root is trusted but the
 * intermediate's outer signature is corrupt, so it is not authentically
 * signed - verification must fail. */
static int test_untrusted_inter_tampered(X509* leaf, X509* tamperedInter,
    X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, tamperedInter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    /* Intermediate is not authentically signed -> rejected.  Assert only the
     * rejection (error != X509_V_OK), not a specific code: wolfSSL currently
     * surfaces the corrupt intermediate as "no valid issuer" rather than a
     * signature-failure error, and pinning that quirk would turn a future
     * error-reporting improvement into a spurious test failure. */
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Reuse one store across a rejected verification followed immediately by a
 * good one.  The rejected attempt temporarily loads an intermediate into the
 * store's CertManager and pushes the caller intermediates onto its working
 * list; a failed check must clean both up so the store is left in a pristine
 * state.  Verifying a genuine chain on the same store right afterwards proves
 * nothing stale was left behind. */
static int test_untrusted_inter_reused_store(X509* leaf, X509* inter,
    X509* tamperedInter, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* badChain = NULL;
    STACK_OF(X509)* goodChain = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);

    /* First: a chain that must be rejected (tampered intermediate signature).
     * This is the path that loads the intermediate into the store. */
    ExpectNotNull(badChain = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(badChain, tamperedInter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, badChain), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Then: reuse the SAME store for the genuine chain.  If the failed check
     * left stale state behind (a temporarily-loaded intermediate or
     * unrestored working list), this would misbehave. */
    ExpectNotNull(goodChain = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(goodChain, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, goodChain), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(badChain);
    sk_X509_free(goodChain);
    return EXPECT_RESULT();
}

/* A verification that loads an intermediate must not leave it behind to anchor
 * a later chain.  Verify a genuine chain on the store (which temporarily loads
 * the intermediate), then reuse the SAME store to verify the leaf alone with
 * NO intermediate supplied: the leaf's issuer is not in the trusted store, so
 * it must be rejected.  If the first check left the intermediate loaded, this
 * second one would wrongly succeed. */
static int test_untrusted_inter_no_stale_anchor(X509* leaf, X509* inter,
    X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* chain = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);

    /* First: genuine chain verifies (temporarily loads the intermediate). */
    ExpectNotNull(chain = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(chain, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, chain), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Then: reuse the SAME store, leaf alone, NO intermediate supplied.  The
     * leaf's issuer is not trusted, so this must be rejected.  A stale
     * intermediate left behind by the first check would wrongly anchor it. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(chain);
    return EXPECT_RESULT();
}

/* Depth exhaustion: a chain that cannot be walked to the trusted anchor within
 * the configured path-building depth budget must be rejected,.
 *
 *     leaf-deep <- int-ca2 <- int-ca <- root  (root trusted)
 *
 * The chain is genuine and verifies at the default depth (covered by
 * test_untrusted_inter_two_level); here the depth is capped below the chain
 * length so the budget is consumed before the trusted root is reached.  The
 * fix must report it as "certificate chain too long". Also covers valid,
 * negative, INT_MAX and unset depths. */
static int test_untrusted_inter_depth_exhaustion(X509* leafDeep, X509* inter,
    X509* inter2, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectIntGT(sk_X509_push(untrusted, inter2), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    /* depth N allows N intermediates; this chain has two */
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    /* Check that depth of 1 also fails */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    /* check that correct depth value is accepted */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, 2);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* init clears a depth set before it */
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* negative depth rejects the chain */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, -1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    /* INT_MAX must not overflow the depth budget */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, INT_MAX);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* a positive depth set after init is honored */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leafDeep, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Cert the callback below vetoes, and whether it was asked about it. */
static X509* depthRejectCert;
static int depthRejectSeen;

static int depth_reject_cb(int ok, X509_STORE_CTX* store_ctx)
{
    if (ok && X509_STORE_CTX_get_current_cert(store_ctx) == depthRejectCert) {
        depthRejectSeen = 1;
        /* Reject a certificate the verification itself accepted. */
        return 0;
    }
    return ok;
}

/* The trust anchor never counts against depth, including one from
 * trusted_stack or store->certs + PARTIAL_CHAIN.
 *
 *     int-ca <- root          verifies at depth 0
 *     leaf <- int-ca <- root  verifies at depth 1, too long at depth 0
 *     leaf <- int-ca          int-ca in store->certs: verifies at depth 0
 *                             only with PARTIAL_CHAIN (store or ctx flag);
 *                             int-ca is not self-issued, so without it the
 *                             chain is too long */
static int test_untrusted_inter_depth_trusted_stack(X509* leaf, X509* inter,
    X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(trusted, root), 0);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, inter, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* A negative depth rejects every chain, even a cert issued
     * directly by the anchor or the self-signed anchor itself */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, inter, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, -1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 0);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, root, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, root, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, INT_MIN);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(store);
    store = NULL;

    /* int-ca in store->certs is trusted but not self-issued: without
     * PARTIAL_CHAIN it cannot end the path, so depth 0 is too long */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, inter), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);

    /* ctx-level PARTIAL_CHAIN anchors the leaf at int-ca at depth 0 */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* As in OpenSSL, init drops it */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_CERT_CHAIN_TOO_LONG);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* store-level PARTIAL_CHAIN does the same */
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_depth(ctx, 0);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* With root in the CertManager, int-ca verifies and only the verify
     * callback rejects it. That veto must hold at depth 0, where the budget
     * runs out on int-ca, just as it does at depth 1. */
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    depthRejectCert = inter;

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, depth_reject_cb);
    X509_STORE_CTX_set_depth(ctx, 1);
    depthRejectSeen = 0;
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(depthRejectSeen, 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNSPECIFIED);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, depth_reject_cb);
    X509_STORE_CTX_set_depth(ctx, 0);
    depthRejectSeen = 0;
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(depthRejectSeen, 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNSPECIFIED);
    depthRejectCert = NULL;

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

/* Issuer cycle: loop-a and loop-b are CAs that issued each other and
 * loop-leaf is issued by loop-a; none reach the trusted root.  Path building
 * must not walk leaf <- loop-a <- loop-b <- loop-a <- ... until the depth
 * budget runs out: at INT_MAX ("unlimited") that is ~2^31 signature checks
 * and chain pushes.  A cert already on the path is never reused as an issuer,
 * so the cycle, not the budget, ends the search. */
static int test_untrusted_inter_issuer_cycle(X509* loopLeaf, X509* loopA,
    X509* loopB, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, loopA), 0);
    ExpectIntGT(sk_X509_push(untrusted, loopB), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, loopLeaf, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, INT_MAX);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    /* default depth: still "no issuer", not "chain too long" */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, loopLeaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}

/* Caller-owned trusted stack (X509_STORE_CTX_set0_trusted_stack): chain
 * building appends the caller-supplied intermediates to an internal working
 * copy, never to the caller's stack.  If the caller's stack were modified and
 * an intermediate left behind, a later verification reusing the stack/ctx
 * would treat it as a trust anchor.
 *
 *     leaf <- int-ca <- root, with root supplied via the trusted_stack.
 *
 * Verify the chain (which reaches root in the trusted stack), then assert the
 * trusted stack is left exactly as the caller supplied it: only root. */
static int test_untrusted_inter_trusted_stack_cleanup(X509* leaf, X509* inter,
    X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(trusted, root), 0);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    /* Chain reaches root in the trusted stack -> verifies. */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    /* The trusted stack must be left exactly as supplied: verification builds
     * the chain on a private copy, so nothing is appended to or removed from
     * the caller's stack - only root remains. */
    ExpectIntEQ(sk_X509_num(trusted), 1);
    ExpectPtrEq(sk_X509_value(trusted, 0), root);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

/* Trusted-stack counterpart of test_untrusted_inter_store_stack_unchanged: the
 * caller's set0_trusted_stack must not be mutated - not even reordered - by
 * X509_verify_cert().  Put the tampered candidate ahead of root in the trusted
 * stack and the genuine int-ca in the untrusted stack, then assert the trusted
 * stack's exact contents and order after each verification. */
static int test_untrusted_inter_trusted_stack_unchanged(X509* leaf, X509* inter,
    X509* tamperedInter, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(trusted = sk_X509_new_null());
    /* Tampered candidate ahead of root: it is found first. */
    ExpectIntGT(sk_X509_push(trusted, tamperedInter), 0);
    ExpectIntGT(sk_X509_push(trusted, root), 0);

    /* Genuine int-ca via the untrusted stack. The tampered cert is found
     * first and is final: wolfSSL fails closed. OpenSSL rejects too, root did
     * not sign it. */
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Trusted stack unchanged in contents and order. */
    ExpectIntEQ(sk_X509_num(trusted), 2);
    ExpectPtrEq(sk_X509_value(trusted, 0), tamperedInter);
    ExpectPtrEq(sk_X509_value(trusted, 1), root);

    /* Failing verification on the same trusted stack: no genuine issuer. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);

    ExpectIntEQ(sk_X509_num(trusted), 2);
    ExpectPtrEq(sk_X509_value(trusted, 0), tamperedInter);
    ExpectPtrEq(sk_X509_value(trusted, 1), root);

    X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
    return EXPECT_RESULT();
}

/* One mixed-candidate verification: leaf with both the tampered intermediate
 * (broken outer signature, same subject and key as int-ca) and the genuine
 * int-ca in the untrusted stack, in the given push order. The first one is
 * the issuer: the chain verifies as expected only with int-ca first. */
static int untrusted_inter_retry_one(X509_STORE* store, X509* leaf,
    X509* first, X509* second, int expected)
{
    EXPECT_DECLS;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* mixed = NULL;

    ExpectNotNull(mixed = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(mixed, first), 0);
    ExpectIntGT(sk_X509_push(mixed, second), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, mixed), 1);
    ExpectIntEQ(X509_verify_cert(ctx), expected);
    X509_STORE_CTX_free(ctx);
    sk_X509_free(mixed);
    return EXPECT_RESULT();
}

/* Same-subject candidates in the untrusted stack: the first issuer found is
 * final, as in OpenSSL.  With the tampered cert first the chain fails; with
 * int-ca first it verifies.  Then prove the store is left clean: a later
 * verification on the same store with only the tampered intermediate must fail
 * (no genuine int-ca left behind), and one with the genuine intermediate must
 * still succeed.  The name is kept from when another candidate was tried. */
static int test_untrusted_inter_retry(X509* leaf, X509* inter,
    X509* tamperedInter, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* goodOnly = NULL;
    STACK_OF(X509)* badOnly = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);

    /* The first issuer found is final: with the tampered cert first,
     * wolfSSL fails closed. OpenSSL rejects too, root did not sign it. */
    ExpectIntEQ(untrusted_inter_retry_one(store, leaf, tamperedInter, inter,
        0), 1);
    ExpectIntEQ(untrusted_inter_retry_one(store, leaf, inter, tamperedInter,
        1), 1);

    /* Reuse the SAME store with only the tampered intermediate: must fail.  If
     * a verification above left the genuine int-ca behind in the store, this
     * would wrongly succeed. */
    ExpectNotNull(badOnly = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(badOnly, tamperedInter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, badOnly), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    /* Reuse the SAME store with the genuine intermediate: must still succeed,
     * proving the verifications above left no stale state. */
    ExpectNotNull(goodOnly = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(goodOnly, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, goodOnly), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(goodOnly);
    sk_X509_free(badOnly);
    return EXPECT_RESULT();
}

/* A first-link signature failure must not leave the caller-supplied issuer
 * loaded in the store's CertManager: X509_verify_cert() loads no temporary
 * CAs.  Residue would only be visible through another user of the same
 * CertManager - signer lookups there do not filter on type. */
static int test_untrusted_inter_no_temp_ca_residue(X509* leaf, X509* inter,
    X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;
    X509* badLeaf = NULL;
    unsigned char* der = NULL;
    const unsigned char* p = NULL;
    int derSz = 0;

    /* Flip a bit in the trailing signature BIT STRING: the leaf still names
     * inter as its issuer, so inter is still selected and loaded, but the
     * signature check against it now fails. */
    ExpectIntGT(derSz = wolfSSL_i2d_X509(leaf, &der), 0);
    ExpectNotNull(der);
    if (EXPECT_SUCCESS() && der != NULL) {
        der[derSz - 1] ^= 0x01;
        p = der;
        ExpectNotNull(badLeaf = wolfSSL_d2i_X509(NULL, &p, derSz));
        der[derSz - 1] ^= 0x01;
    }

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, badLeaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);

    /* Only root was ever trusted, so the genuine leaf must not verify through
     * the CertManager.  It would if inter were still resident as a TEMP_CA. */
    if (EXPECT_SUCCESS() && store != NULL && der != NULL) {
        ExpectIntNE(wolfSSL_CertManagerVerifyBuffer(store->cm, der, derSz,
            WOLFSSL_FILETYPE_ASN1), WOLFSSL_SUCCESS);
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    X509_free(badLeaf);
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    return EXPECT_RESULT();
}

/* Reported chain with the tampered sibling ahead of int-ca in the untrusted
 * stack: the tampered cert is the leaf's issuer and is final, so the chain
 * holds it and never int-ca, as in OpenSSL (leaf, tampered, root).  Certs are
 * compared by content (X509_cmp) since the chain need not hold the caller's
 * pointers.  The name is kept from when the sibling was rejected and int-ca
 * tried. */
static int test_untrusted_inter_chain_excludes_rejected(X509* leaf, X509* inter,
    X509* tamperedInter, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* mixed = NULL;
    STACK_OF(X509)* chain = NULL;
    int i;
    int foundInter = 0;
    int foundTampered = 0;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);

    /* Tampered candidate first. */
    ExpectNotNull(mixed = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(mixed, tamperedInter), 0);
    ExpectIntGT(sk_X509_push(mixed, inter), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, mixed), 1);
    /* The tampered cert is found first and is final: wolfSSL fails closed
     * and the genuine int-ca is not tried. OpenSSL rejects too. */
    ExpectIntEQ(X509_verify_cert(ctx), 0);

    ExpectNotNull(chain = X509_STORE_CTX_get0_chain(ctx));
    for (i = 0; i < sk_X509_num(chain); i++) {
        X509* c = sk_X509_value(chain, i);
        if (c != NULL && X509_cmp(c, inter) == 0)
            foundInter = 1;
        if (c != NULL && X509_cmp(c, tamperedInter) == 0)
            foundTampered = 1;
    }
    ExpectIntEQ(foundInter, 0);
    ExpectIntEQ(foundTampered, 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(mixed);
    return EXPECT_RESULT();
}

#ifndef NO_TLS
/* A trusted stack replaces the store's CAs, as in OpenSSL.  root and int-ca
 * are only in the CertManager (SSL_CTX_set_cert_store() moves store->certs
 * there); the trusted stack holds only the tampered sibling of int-ca.  It is
 * the leaf's trusted issuer and nothing trusted issues it, so verification
 * fails with UNABLE_TO_GET_ISSUER_CERT at depth 1 and the chain holds it.
 * The name is kept from when the sibling was rejected. */
static int test_untrusted_inter_terminal_anchor_rejected(X509* leaf,
    X509* inter, X509* tamperedInter, X509* root)
{
    EXPECT_DECLS;
    SSL_CTX* sslCtx = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* chain = NULL;
    int i;
    int foundTampered = 0;
    int storeOwned = 0;

    /* SSL_CTX_set_cert_store() pushes store->certs into the CertManager and
     * detaches the stack, so int-ca is only a CM CA, which the trusted stack
     * replaces. */
#ifndef NO_WOLFSSL_SERVER
    ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_server_method()));
#else
    ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_client_method()));
#endif
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, inter), 1);
    if (store != NULL && sslCtx != NULL) {
        SSL_CTX_set_cert_store(sslCtx, store);
        storeOwned = 1;
    }

    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(trusted, tamperedInter), 0);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);

    /* As in OpenSSL, the trusted stack replaces the CAs of the store: the
     * tampered cert is the only trusted issuer and root did not sign it. */
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 1);

    ExpectNotNull(chain = X509_STORE_CTX_get0_chain(ctx));
    for (i = 0; i < sk_X509_num(chain); i++) {
        X509* c = sk_X509_value(chain, i);
        if (c != NULL && X509_cmp(c, tamperedInter) == 0)
            foundTampered = 1;
    }
    ExpectIntEQ(foundTampered, 1);

    X509_STORE_CTX_free(ctx);
    sk_X509_free(trusted);
    /* store ownership passes to sslCtx only when both allocations succeeded */
    if (!storeOwned)
        X509_STORE_free(store);
    SSL_CTX_free(sslCtx);
    return EXPECT_RESULT();
}
#endif /* NO_TLS */

/* The store's cert stack is shared by every X509_STORE_CTX (and every SSL
 * connection) using the store, so verification must not modify it.  Put a
 * tampered candidate on store->certs ahead of inter2, then assert the stack's
 * exact contents and order after each verification. */
static int test_untrusted_inter_store_stack_unchanged(X509* leaf, X509* inter,
    X509* tamperedInter, X509* inter2, X509* root)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    /* Non-self-signed certs land on store->certs, in add order. */
    ExpectIntEQ(X509_STORE_add_cert(store, tamperedInter), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, inter2), 1);
    ExpectIntEQ(sk_X509_num(store->certs), 2);

    /* Genuine int-ca via the untrusted stack. The tampered cert of the store
     * is found first and is final: wolfSSL fails closed. OpenSSL rejects
     * too, root did not sign it. */
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    X509_STORE_CTX_free(ctx);
    ctx = NULL;

    ExpectIntEQ(sk_X509_num(store->certs), 2);
    ExpectPtrEq(sk_X509_value(store->certs, 0), tamperedInter);
    ExpectPtrEq(sk_X509_value(store->certs, 1), inter2);

    /* Failing verification on the same store: no genuine issuer available. */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntNE(X509_STORE_CTX_get_error(ctx), X509_V_OK);
    X509_STORE_CTX_free(ctx);

    ExpectIntEQ(sk_X509_num(store->certs), 2);
    ExpectPtrEq(sk_X509_value(store->certs, 0), tamperedInter);
    ExpectPtrEq(sk_X509_value(store->certs, 1), inter2);

    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return EXPECT_RESULT();
}
#endif /* OPENSSL_EXTRA && !NO_RSA && !NO_CERTS && !NO_FILESYSTEM */

int test_X509_verify_cert_untrusted_inter(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
    X509* leaf = NULL;
    X509* leafDeep = NULL;
    X509* inter = NULL;
    X509* inter2 = NULL;
    X509* tamperedInter = NULL;
    X509* root = NULL;
    X509* wrongRoot = NULL;
    X509* loopA = NULL;
    X509* loopB = NULL;
    X509* loopLeaf = NULL;
    int sanityRes = 0;
    int twoLevelRes = 0;
    int emptyStoreRes = 0;
    int wrongAnchorRes = 0;
    int tamperedRes = 0;
    int reusedStoreRes = 0;
    int noStaleRes = 0;
    int depthExhaustRes = 0;
    int depthTrustedStackRes = 0;
    int issuerCycleRes = 0;
    int trustedStackCleanupRes = 0;
    int trustedStackUnchangedRes = 0;
    int retryRes = 0;
    int noTempCaResidueRes = 0;
    int chainExcludesRes = 0;
#ifndef NO_TLS
    int terminalAnchorRes = 0;
#endif
    int storeStackRes = 0;

    ExpectNotNull(leaf = untrusted_inter_load(UA_CERT_DIR "leaf-cert.pem"));
    ExpectNotNull(leafDeep =
        untrusted_inter_load(UA_CERT_DIR "leaf-deep-cert.pem"));
    ExpectNotNull(inter = untrusted_inter_load(UA_CERT_DIR "int-ca-cert.pem"));
    ExpectNotNull(inter2 =
        untrusted_inter_load(UA_CERT_DIR "int-ca2-cert.pem"));
    ExpectNotNull(tamperedInter =
        untrusted_inter_load(UA_CERT_DIR "int-ca-tampered-cert.pem"));
    ExpectNotNull(root = untrusted_inter_load(UA_CERT_DIR "root-ca-cert.pem"));
    ExpectNotNull(wrongRoot =
        untrusted_inter_load(UA_CERT_DIR "alt-ca-cert.pem"));
    ExpectNotNull(loopA = untrusted_inter_load(UA_CERT_DIR "loop-a-cert.pem"));
    ExpectNotNull(loopB = untrusted_inter_load(UA_CERT_DIR "loop-b-cert.pem"));
    ExpectNotNull(loopLeaf =
        untrusted_inter_load(UA_CERT_DIR "loop-leaf-cert.pem"));

    /* Run every sub-case unconditionally - each reports its own result - so a
     * regression in one does not mask the others. */
    if (leaf != NULL && leafDeep != NULL && inter != NULL && inter2 != NULL &&
            tamperedInter != NULL && root != NULL && wrongRoot != NULL) {
        sanityRes      = test_untrusted_inter_sanity(leaf, inter, root);
        twoLevelRes    = test_untrusted_inter_two_level(leafDeep, inter,
                            inter2, root);
        emptyStoreRes  = test_untrusted_inter_empty_store(leaf, inter);
        wrongAnchorRes = test_untrusted_inter_wrong_anchor(leaf, inter,
                            wrongRoot);
        tamperedRes    = test_untrusted_inter_tampered(leaf, tamperedInter,
                            root);
        reusedStoreRes = test_untrusted_inter_reused_store(leaf, inter,
                            tamperedInter, root);
        noStaleRes     = test_untrusted_inter_no_stale_anchor(leaf, inter,
                            root);
        depthExhaustRes = test_untrusted_inter_depth_exhaustion(leafDeep,
                            inter, inter2, root);
        depthTrustedStackRes = test_untrusted_inter_depth_trusted_stack(leaf,
                            inter, root);
        trustedStackCleanupRes = test_untrusted_inter_trusted_stack_cleanup(
                            leaf, inter, root);
        trustedStackUnchangedRes =
                            test_untrusted_inter_trusted_stack_unchanged(
                            leaf, inter, tamperedInter, root);
        retryRes = test_untrusted_inter_retry(leaf, inter, tamperedInter, root);
        noTempCaResidueRes = test_untrusted_inter_no_temp_ca_residue(leaf,
                            inter, root);
        chainExcludesRes = test_untrusted_inter_chain_excludes_rejected(leaf,
                            inter, tamperedInter, root);
#ifndef NO_TLS
        terminalAnchorRes = test_untrusted_inter_terminal_anchor_rejected(leaf,
                            inter, tamperedInter, root);
#endif
        storeStackRes = test_untrusted_inter_store_stack_unchanged(leaf, inter,
                            tamperedInter, inter2, root);
        ExpectIntEQ(sanityRes, 1);
        ExpectIntEQ(twoLevelRes, 1);
        ExpectIntEQ(emptyStoreRes, 1);
        ExpectIntEQ(wrongAnchorRes, 1);
        ExpectIntEQ(tamperedRes, 1);
        ExpectIntEQ(reusedStoreRes, 1);
        ExpectIntEQ(noStaleRes, 1);
        ExpectIntEQ(depthExhaustRes, 1);
        ExpectIntEQ(depthTrustedStackRes, 1);
        ExpectIntEQ(trustedStackCleanupRes, 1);
        ExpectIntEQ(trustedStackUnchangedRes, 1);
        ExpectIntEQ(retryRes, 1);
        ExpectIntEQ(noTempCaResidueRes, 1);
        ExpectIntEQ(chainExcludesRes, 1);
#ifndef NO_TLS
        ExpectIntEQ(terminalAnchorRes, 1);
#endif
        ExpectIntEQ(storeStackRes, 1);
    }
    /* Own guard so a missing loop fixture does not skip the sub-cases above. */
    if (loopA != NULL && loopB != NULL && loopLeaf != NULL && root != NULL) {
        issuerCycleRes = test_untrusted_inter_issuer_cycle(loopLeaf, loopA,
                            loopB, root);
        ExpectIntEQ(issuerCycleRes, 1);
    }

    X509_free(leaf);
    X509_free(leafDeep);
    X509_free(inter);
    X509_free(inter2);
    X509_free(tamperedInter);
    X509_free(root);
    X509_free(wrongRoot);
    X509_free(loopA);
    X509_free(loopB);
    X509_free(loopLeaf);
#undef UA_CERT_DIR
#endif /* OPENSSL_EXTRA && !NO_RSA && !NO_CERTS && !NO_FILESYSTEM */
    return EXPECT_RESULT();
}

/* Depth from X509_VERIFY_PARAM, set as xmlsec does. leaf-deep <- int-ca2 <-
 * int-ca <- root has two intermediates: depth 1 is too small, 2 is enough. */
int test_wolfSSL_X509_VERIFY_PARAM_set_depth(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
    X509* leaf = NULL;
    X509* inter = NULL;
    X509* inter2 = NULL;
    X509* root = NULL;
    STACK_OF(X509)* untrusted = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_VERIFY_PARAM* vpm = NULL;
    X509_VERIFY_PARAM* vpm2 = NULL;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX* sslCtx = NULL;
    SSL* ssl = NULL;
#endif

    ExpectNotNull(leaf = X509_load_certificate_file(
        "./certs/intermediate/untrusted_anchor/leaf-deep-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(inter = X509_load_certificate_file(
        "./certs/intermediate/untrusted_anchor/int-ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(inter2 = X509_load_certificate_file(
        "./certs/intermediate/untrusted_anchor/int-ca2-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(root = X509_load_certificate_file(
        "./certs/intermediate/untrusted_anchor/root-ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectIntGT(sk_X509_push(untrusted, inter2), 0);
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(vpm = X509_VERIFY_PARAM_new());

    /* A param without a depth does not limit the chain */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_set1_param(store, vpm), 1);
    /* A builtin leaves the depth unset. ssl_server fits the leaf's EKU. */
    ExpectIntEQ(X509_VERIFY_PARAM_set1(X509_STORE_get0_param(store),
        X509_VERIFY_PARAM_lookup("ssl_server")), 1);
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = SSL_new(sslCtx));
    ExpectIntEQ(X509_STORE_set1_param(store, SSL_CTX_get0_param(sslCtx)), 1);
    ExpectIntEQ(X509_STORE_set1_param(store, SSL_get0_param(ssl)), 1);
    ExpectIntEQ(X509_STORE_set1_param(store,
        X509_STORE_get0_param(SSL_CTX_get_cert_store(sslCtx))), 1);
#endif
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* The context inherits the store depth */
    X509_VERIFY_PARAM_set_depth(vpm, 1);
    ExpectIntEQ(X509_STORE_set1_param(store, vpm), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);
    X509_VERIFY_PARAM_set_depth(vpm, 2);
    ExpectIntEQ(X509_STORE_set1_param(store, vpm), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* set0_param() replaces the inherited param: depth 1 fails here */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectNotNull(vpm2 = X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_depth(vpm2, 1);
    X509_STORE_CTX_set0_param(ctx, vpm2);
    vpm2 = NULL;
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);
    /* A negative depth rejects every chain. Only -1 is unset, so the store
     * passes on -2, and -1 left in the context's param rejects too. */
    X509_VERIFY_PARAM_set_depth(vpm, -2);
    ExpectIntEQ(X509_STORE_set1_param(store, vpm), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_VERIFY_PARAM_set_depth(X509_STORE_CTX_get0_param(ctx), -1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);

    /* With a store depth of 1, a later depth of 2 is honored */
    X509_VERIFY_PARAM_set_depth(vpm, 1);
    ExpectIntEQ(X509_STORE_set1_param(store, vpm), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectNotNull(vpm2 = X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_depth(vpm2, 2);
    X509_STORE_CTX_set0_param(ctx, vpm2);
    vpm2 = NULL;
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* cleanup frees the param, the next init inherits depth 1 again */
    X509_STORE_CTX_cleanup(ctx);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_VERIFY_PARAM_set_depth(X509_STORE_CTX_get0_param(ctx), 2);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, 2);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* the last setter wins */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    X509_STORE_CTX_set_depth(ctx, 1);
    X509_VERIFY_PARAM_set_depth(X509_STORE_CTX_get0_param(ctx), 2);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* A param without a depth rejects every chain, as in OpenSSL. A second
     * set0_param() frees the first, NULL or the current one keeps it and
     * X509_STORE_CTX_free() frees the last. */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectNotNull(vpm2 = X509_VERIFY_PARAM_new());
    X509_STORE_CTX_set0_param(ctx, vpm2);
    vpm2 = NULL;
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_CHAIN_TOO_LONG);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    ExpectNotNull(vpm2 = X509_VERIFY_PARAM_new());
    X509_VERIFY_PARAM_set_depth(vpm2, 2);
    X509_STORE_CTX_set0_param(ctx, vpm2);
    X509_STORE_CTX_set0_param(ctx, NULL);
    X509_STORE_CTX_set0_param(ctx, vpm2);
    X509_STORE_CTX_set0_param(NULL, NULL);
    X509_VERIFY_PARAM_set_depth(NULL, 2);
    ExpectPtrEq(X509_STORE_CTX_get0_param(ctx), vpm2);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    X509_STORE_CTX_free(ctx);
    X509_VERIFY_PARAM_free(vpm);
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_free(ssl);
    SSL_CTX_free(sslCtx);
#endif
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    X509_free(leaf);
    X509_free(inter);
    X509_free(inter2);
    X509_free(root);
#endif /* OPENSSL_EXTRA && !NO_RSA && !NO_CERTS && !NO_FILESYSTEM */
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
static int test_X509_verify_cert_accept_cb(int ok, X509_STORE_CTX* ctx)
{
    (void)ok;
    (void)ctx;
    return 1;
}
#endif

/* An X509 made in memory has no DER. Failing closed, it is never an issuer,
 * trusted or not, so every cert on the chain is checked. As in OpenSSL, the
 * leaf then has no issuer. */
int test_X509_verify_cert_no_der(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
    X509* ca = NULL;
    X509* inter = NULL;
    X509* leaf = NULL;
    X509* leaf2 = NULL;
    X509* fake = NULL;
    X509* fakeInter = NULL;
    STACK_OF(X509)* sk = NULL;
    STACK_OF(X509)* untrusted = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
#ifdef HAVE_CRL
    X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;
#endif

    ExpectNotNull(ca = X509_load_certificate_file("./certs/ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(inter = X509_load_certificate_file(
        "./certs/intermediate/ca-int-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file("./certs/server-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(leaf2 = X509_load_certificate_file(
        "./certs/intermediate/ca-int2-cert.pem", SSL_FILETYPE_PEM));
    /* The names and key of ca-cert and ca-int, without DER */
    ExpectNotNull(fake = X509_new());
    ExpectIntEQ(X509_set_subject_name(fake, X509_get_subject_name(ca)), 1);
    ExpectIntEQ(X509_set_issuer_name(fake, X509_get_subject_name(ca)), 1);
    ExpectIntEQ(X509_set_pubkey(fake, X509_get0_pubkey(ca)), 1);
    ExpectNotNull(fakeInter = X509_new());
    ExpectIntEQ(X509_set_subject_name(fakeInter,
        X509_get_subject_name(inter)), 1);
    ExpectIntEQ(X509_set_issuer_name(fakeInter,
        X509_get_issuer_name(inter)), 1);
    ExpectIntEQ(X509_set_pubkey(fakeInter, X509_get0_pubkey(inter)), 1);

    /* A trusted stack cert with PARTIAL_CHAIN would end the chain */
    ExpectNotNull(sk = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(sk, fake), 0);
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_trusted_stack(ctx, sk);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 0);
    /* Nor is it verified: the error is not X509_V_OK */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, fake, NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNSPECIFIED);

    /* An untrusted one below a trusted root, every CRL checked. The
     * callback accepts each error: 20, 3 and 21 at depth 0. */
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, fakeInter), 0);
    ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);
#ifdef HAVE_CRL
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
    ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), 1);
#endif
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf2, untrusted), 1);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK |
        X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_CTX_set_verify_cb(ctx, test_X509_verify_cert_accept_cb);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 0);
    ExpectIntEQ(sk_X509_num(X509_STORE_CTX_get0_chain(ctx)), 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
#ifdef HAVE_CRL
    X509_CRL_free(crl);
#endif
    sk_X509_free(sk);
    sk_X509_free(untrusted);
    X509_free(fake);
    X509_free(fakeInter);
    X509_free(ca);
    X509_free(inter);
    X509_free(leaf);
    X509_free(leaf2);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME)
static int test_crl_time_accept; /* the callback accepts CRL date errors */
static int test_crl_time_errs;   /* CRL date errors the callback saw */

/* Accepts the date errors of certs, and of CRLs with test_crl_time_accept */
static int test_crl_time_cb(int ok, X509_STORE_CTX* ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    if (!ok && (err == X509_V_ERR_CRL_NOT_YET_VALID ||
            err == X509_V_ERR_CRL_HAS_EXPIRED)) {
        test_crl_time_errs++;
        return test_crl_time_accept;
    }
    return ok || err == X509_V_ERR_CERT_NOT_YET_VALID ||
        err == X509_V_ERR_CERT_HAS_EXPIRED;
}

/* The time of asn1Time in *t */
static int test_crl_time_get(const ASN1_TIME* asn1Time, time_t* t)
{
    ASN1_TIME* epoch = ASN1_TIME_adj(NULL, 0, 0, 0);
    int day = 0;
    int sec = 0;
    int ret = epoch != NULL &&
        ASN1_TIME_diff(&day, &sec, epoch, asn1Time) == 1;

    *t = (time_t)day * 86400 + sec;
    ASN1_TIME_free(epoch);
    return ret;
}

/* X509_verify_cert() of leaf with the trusted ca and crl, of the store or,
 * with toCtx, of the ctx, CRL_CHECK and flags on the ctx at time t. The error
 * is put in *err. */
static int test_crl_time_run(X509* ca, X509* leaf, X509_CRL* crl, int toCtx,
    time_t t, unsigned long flags, int* err)
{
    X509_STORE* store = X509_STORE_new();
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    STACK_OF(X509_CRL)* crls = sk_X509_CRL_new_null();
    int ret = -1;

    if (store != NULL && ctx != NULL && crls != NULL &&
            X509_STORE_add_cert(store, ca) == 1 &&
            (toCtx ? sk_X509_CRL_push(crls, crl) > 0 :
                X509_STORE_add_crl(store, crl) == 1) &&
            X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1) {
        if (toCtx)
            X509_STORE_CTX_set0_crls(ctx, crls);
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK | flags);
        X509_STORE_CTX_set_time(ctx, 0, t);
        X509_STORE_CTX_set_verify_cb(ctx, test_crl_time_cb);
        test_crl_time_errs = 0;
        ret = X509_verify_cert(ctx);
        *err = X509_STORE_CTX_get_error(ctx);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_CRL_free(crls);
    return ret;
}
#endif

/* As OpenSSL's check_crl_time(), a CRL of the store or of the ctx is current
 * from its thisUpdate to its nextUpdate at the verification time: else 11 or
 * 12, once accepted the CRL is used. X509_V_FLAG_USE_CHECK_TIME wins over
 * X509_V_FLAG_NO_CHECK_TIME. The times are taken from the CRL. */
int test_X509_verify_cert_crl_time(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME)
    X509* ca = NULL;
    X509* leaf = NULL;
    X509* revoked = NULL;
    X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;
    time_t thisUpdate = 0;
    time_t nextUpdate = 0;
    int toCtx;
    int err = 0;

    ExpectNotNull(ca = X509_load_certificate_file("./certs/ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file("./certs/server-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(revoked = X509_load_certificate_file(
        "./certs/server-revoked-cert.pem", SSL_FILETYPE_PEM));
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
    ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(test_crl_time_get(X509_CRL_get0_lastUpdate(crl),
        &thisUpdate), 1);
    ExpectIntEQ(test_crl_time_get(X509_CRL_get0_nextUpdate(crl),
        &nextUpdate), 1);
    ExpectTrue(thisUpdate + 1 < nextUpdate - 1);

    for (toCtx = 0; toCtx <= 1 && EXPECT_SUCCESS(); toCtx++) {
        test_crl_time_accept = 0;
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, thisUpdate + 1,
            0, &err), 1);
        ExpectIntEQ(test_crl_time_errs, 0);
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, nextUpdate - 1,
            0, &err), 1);
        ExpectIntEQ(test_crl_time_errs, 0);
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, thisUpdate - 1,
            0, &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CRL_NOT_YET_VALID);
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, nextUpdate + 1,
            0, &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CRL_HAS_EXPIRED);
        /* As OpenSSL's X509_cmp_time(), current at its thisUpdate, expired
         * at its nextUpdate */
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, thisUpdate, 0,
            &err), 1);
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, nextUpdate, 0,
            &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CRL_HAS_EXPIRED);
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, nextUpdate + 1,
            X509_V_FLAG_NO_CHECK_TIME, &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CRL_HAS_EXPIRED);

        test_crl_time_accept = 1;
        ExpectIntEQ(test_crl_time_run(ca, leaf, crl, toCtx, nextUpdate + 1,
            0, &err), 1);
        ExpectIntEQ(test_crl_time_errs, 1);
        ExpectIntEQ(test_crl_time_run(ca, revoked, crl, toCtx,
            thisUpdate - 1, 0, &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CERT_REVOKED);
        ExpectIntEQ(test_crl_time_errs, 1);
        ExpectIntEQ(test_crl_time_run(ca, revoked, crl, toCtx,
            nextUpdate + 1, 0, &err), 0);
        ExpectIntEQ(err, X509_V_ERR_CERT_REVOKED);
        ExpectIntEQ(test_crl_time_errs, 1);
    }

    X509_CRL_free(crl);
    X509_free(ca);
    X509_free(leaf);
    X509_free(revoked);
#endif
    return EXPECT_RESULT();
}

/* A CRL loaded after its CA is verified then and keeps no signature. As in
 * OpenSSL, it is used for the certs of that CA: loaded with
 * X509_STORE_load_locations(), X509_LOOKUP_load_file() or, into an SSL_CTX,
 * wolfSSL_CTX_LoadCRLFile(). */
int test_X509_verify_cert_crl_loaded(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_DIR) && defined(WOLFSSL_PEM_TO_DER)
    const char* crlFile = "./certs/crl/crl.pem";
    X509* ca = NULL;
    X509* leaf = NULL;
    X509* revoked = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX* sslCtx = NULL;
#endif
    int i;

    ExpectNotNull(ca = X509_load_certificate_file("./certs/ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file("./certs/server-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(revoked = X509_load_certificate_file(
        "./certs/server-revoked-cert.pem", SSL_FILETYPE_PEM));
    for (i = 0; i < 3 && EXPECT_SUCCESS(); i++) {
        if (i < 2) {
            ExpectNotNull(store = X509_STORE_new());
            ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);
        }
        if (i == 0) {
            ExpectIntEQ(X509_STORE_load_locations(store, crlFile, NULL), 1);
        }
        else if (i == 1) {
            ExpectIntEQ(X509_LOOKUP_load_file(X509_STORE_add_lookup(store,
                X509_LOOKUP_file()), crlFile, X509_FILETYPE_PEM), 1);
        }
        else {
        /* A CA of an SSL_CTX goes on the chain only with its DER */
        #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
            defined(WOLFSSL_SIGNER_DER_CERT)
            ExpectNotNull(sslCtx = SSL_CTX_new(SSLv23_client_method()));
            ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx,
                "./certs/ca-cert.pem", NULL), 1);
            ExpectIntEQ(wolfSSL_CTX_EnableCRL(sslCtx, 0), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(sslCtx, crlFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
            ExpectNotNull(store = SSL_CTX_get_cert_store(sslCtx));
        #else
            break;
        #endif
        }

        ExpectNotNull(ctx = X509_STORE_CTX_new());
        ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);
        ExpectIntEQ(X509_verify_cert(ctx), 1);
        ExpectIntEQ(X509_STORE_CTX_init(ctx, store, revoked, NULL), 1);
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);
        ExpectIntEQ(X509_verify_cert(ctx), 0);
        ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_CERT_REVOKED);
        X509_STORE_CTX_free(ctx);
        ctx = NULL;
    #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
        if (sslCtx != NULL) {
            SSL_CTX_free(sslCtx);
            sslCtx = NULL;
            store = NULL;
        }
    #endif
        X509_STORE_free(store);
        store = NULL;
    }

    X509_free(ca);
    X509_free(leaf);
    X509_free(revoked);
#endif
    return EXPECT_RESULT();
}

/* An intermediate CA of an SSL_CTX, without its issuer there, is the trust
 * anchor. As TLS, the CRL check-all of the cert manager leaves it out, so the
 * chain the handshake verified is returned. The leaf is still checked.
 * X509_V_FLAG_CRL_CHECK_ALL checks the anchor: no CRL, as OpenSSL with
 * X509_V_FLAG_PARTIAL_CHAIN. */
int test_X509_verify_cert_crl_cm_anchor(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CLIENT) && defined(WOLFSSL_PEM_TO_DER) && \
    defined(WOLFSSL_SIGNER_DER_CERT)
    const char* caFile = "./certs/intermediate/ca-int2-cert.pem";
    const char* crlFile = "./certs/crl/ca-int2.pem";
    X509* leaf = NULL;
    SSL_CTX* sslCtx = NULL;
    X509_STORE_CTX* ctx = NULL;
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_ALT_CERT_CHAINS) && defined(SESSION_CERTS) && \
    defined(KEEP_PEER_CERT)
    test_ssl_memio_ctx test_ctx;
    STACK_OF(X509)* chain = NULL;
#endif

    ExpectNotNull(leaf = X509_load_certificate_file(
        "./certs/intermediate/server-int-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(sslCtx = SSL_CTX_new(SSLv23_client_method()));
    ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx, caFile, NULL), 1);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(sslCtx, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, SSL_CTX_get_cert_store(sslCtx), leaf,
        NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNABLE_TO_GET_CRL);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 0);
    ExpectIntEQ(wolfSSL_CTX_LoadCRLFile(sslCtx, crlFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, SSL_CTX_get_cert_store(sslCtx), leaf,
        NULL), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(sk_X509_num(X509_STORE_CTX_get0_chain(ctx)), 2);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, SSL_CTX_get_cert_store(sslCtx), leaf,
        NULL), 1);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK |
        X509_V_FLAG_CRL_CHECK_ALL);
    ExpectIntEQ(X509_verify_cert(ctx), 0);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_UNABLE_TO_GET_CRL);
    ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), 1);
    X509_STORE_CTX_free(ctx);
    SSL_CTX_free(sslCtx);
    X509_free(leaf);

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_ALT_CERT_CHAINS) && defined(SESSION_CERTS) && \
    defined(KEEP_PEER_CERT)
    /* The server sends the anchor too: only then does TLS leave it out */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_cb.caPemFile = caFile;
    test_ctx.c_cb.crlPemFile = crlFile;
    test_ctx.s_cb.certPemFile = "./certs/intermediate/server-chain-short.pem";
    test_ctx.s_cb.keyPemFile = "./certs/server-key.pem";
    ExpectIntEQ(test_ssl_memio_setup(&test_ctx), TEST_SUCCESS);
    ExpectIntEQ(test_ssl_memio_do_handshake(&test_ctx, 10, NULL),
        TEST_SUCCESS);
    ExpectNotNull(chain = SSL_get0_verified_chain(test_ctx.c_ssl));
    ExpectIntEQ(sk_X509_num(chain), 2);
    test_ssl_memio_cleanup(&test_ctx);
#endif
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
static int test_internal_err_calls; /* calls of the verify callback */

static int test_internal_err_cb(int ok, X509_STORE_CTX* ctx)
{
    (void)ok;
    (void)ctx;
    test_internal_err_calls++;
    return 1;
}

/* Verifies leaf with the CA of store and returns X509_verify_cert() */
static int test_internal_err_run(X509_STORE* store, X509* leaf, int* err)
{
    EXPECT_DECLS;
    X509_STORE_CTX* ctx = NULL;
    int ret = -1;

    test_internal_err_calls = 0;
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_verify_cb(ctx, test_internal_err_cb);
    if (EXPECT_SUCCESS()) {
        ret = X509_verify_cert(ctx);
        *err = X509_STORE_CTX_get_error(ctx);
    }
    X509_STORE_CTX_free(ctx);
    return ret;
}
#endif

/* An internal error fails the verification with X509_V_ERR_UNSPECIFIED and
 * the verify callback is not asked. The DER of the leaf is broken after it
 * decoded, so checking its signature fails to parse it, with a cert of the
 * store and with a CA of an SSL_CTX. */
int test_X509_verify_cert_internal_err(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
    X509* ca = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX* sslCtx = NULL;
#endif
    int err = 0;

    ExpectNotNull(ca = X509_load_certificate_file("./certs/ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file("./certs/server-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);
    ExpectIntEQ(test_internal_err_run(store, leaf, &err), 1);
    ExpectIntEQ(err, X509_V_OK);
    ExpectIntEQ(test_internal_err_calls, 2);

    /* The outer SEQUENCE of the leaf becomes a SET */
    ExpectTrue(leaf != NULL && leaf->derCert != NULL &&
        leaf->derCert->buffer[0] == (ASN_SEQUENCE | ASN_CONSTRUCTED));
    if (EXPECT_SUCCESS()) {
        leaf->derCert->buffer[0] = ASN_SET | ASN_CONSTRUCTED;
    }
    ExpectIntEQ(test_internal_err_run(store, leaf, &err), 0);
    ExpectIntEQ(err, X509_V_ERR_UNSPECIFIED);
    ExpectIntEQ(test_internal_err_calls, 0);
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    ExpectNotNull(sslCtx = SSL_CTX_new(SSLv23_client_method()));
    ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx, "./certs/ca-cert.pem",
        NULL), 1);
    ExpectIntEQ(test_internal_err_run(SSL_CTX_get_cert_store(sslCtx), leaf,
        &err), 0);
    ExpectIntEQ(err, X509_V_ERR_UNSPECIFIED);
    ExpectIntEQ(test_internal_err_calls, 0);
#endif
    if (EXPECT_SUCCESS()) {
        leaf->derCert->buffer[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    }

#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX_free(sslCtx);
#endif
    X509_STORE_free(store);
    X509_free(ca);
    X509_free(leaf);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
/* Build a CA:TRUE certificate signed by the 2048-bit test root, or self-signed
 * with subjKey when selfSigned is set (caKey may then be NULL). cn NULL copies
 * the root's subject. keyUsage NULL omits the KeyUsage extension. */
static int gen_ca_int_keyusage(byte* out, int outMax, RsaKey* subjKey,
    RsaKey* caKey, WC_RNG* rng, const char* cn, const char* keyUsage,
    int selfSigned)
{
    Cert cert;

    if (wc_InitCert(&cert) != 0)
        return -1;
    cert.isCA    = 1;
    cert.sigType = CTC_SHA256wRSA;
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.org, "wolfSSL_test", CTC_NAME_SIZE - 1);
    if (cn != NULL)
        XSTRNCPY(cert.subject.commonName, cn, CTC_NAME_SIZE - 1);
    else if (wc_SetSubjectBuffer(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0)
        return -1;
    if (wc_SetSubjectKeyIdFromPublicKey(&cert, subjKey, NULL) != 0)
        return -1;
    if (!selfSigned && wc_SetAuthKeyIdFromCert(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0)
        return -1;
    if (keyUsage != NULL && wc_SetKeyUsage(&cert, keyUsage) != 0)
        return -1;
    /* A self-signed certificate names no issuer; the subject stands in. */
    if (!selfSigned && wc_SetIssuerBuffer(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0)
        return -1;
    if (wc_MakeCert(&cert, out, (word32)outMax, subjKey, NULL, rng) < 0)
        return -1;
    return wc_SignCert(cert.bodySz, cert.sigType, out, (word32)outMax,
        selfSigned ? subjKey : caKey, NULL, rng);
}

/* Build a leaf signed by the given intermediate (its DER + private key). */
static int gen_leaf_under_int(byte* out, int outMax, RsaKey* leafKey,
    const byte* issuerDer, int issuerDerSz, RsaKey* issuerKey, WC_RNG* rng,
    const char* cn)
{
    Cert cert;

    if (wc_InitCert(&cert) != 0)
        return -1;
    cert.isCA    = 0;
    cert.sigType = CTC_SHA256wRSA;
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.org, "wolfSSL_test", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.commonName, cn, CTC_NAME_SIZE - 1);
    if (wc_SetSubjectKeyIdFromPublicKey(&cert, leafKey, NULL) != 0)
        return -1;
    if (wc_SetAuthKeyIdFromCert(&cert, issuerDer, issuerDerSz) != 0)
        return -1;
    if (wc_SetKeyUsage(&cert, "digitalSignature") != 0)
        return -1;
    if (wc_SetIssuerBuffer(&cert, issuerDer, issuerDerSz) != 0)
        return -1;
    if (wc_MakeCert(&cert, out, (word32)outMax, leafKey, NULL, rng) < 0)
        return -1;
    return wc_SignCert(cert.bodySz, cert.sigType, out, (word32)outMax,
        issuerKey, NULL, rng);
}

/* Verify "leaf <- intermediate <- root(ca-cert)" where the intermediate is
 * supplied only as an untrusted candidate.  Returns the X509_verify_cert()
 * result (1 verified, 0 rejected) via *verifyRet, and the error and its depth
 * via *verifyErr and *verifyDepth. */
static int run_int_keyusage_case(const byte* intDer, int intSz,
    const byte* leafDer, int leafSz, X509* root, int* verifyRet,
    int* verifyErr, int* verifyDepth)
{
    EXPECT_DECLS;
    X509* inter = NULL;
    X509* leaf  = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;
    const byte* p;

    p = intDer;
    ExpectNotNull(inter = d2i_X509(NULL, &p, intSz));
    p = leafDer;
    ExpectNotNull(leaf = d2i_X509(NULL, &p, leafSz));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectNotNull(untrusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(untrusted, inter), 0);
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    *verifyRet = X509_verify_cert(ctx);
    *verifyErr = X509_STORE_CTX_get_error(ctx);
    *verifyDepth = X509_STORE_CTX_get_error_depth(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    X509_free(leaf);
    X509_free(inter);
    return EXPECT_RESULT();
}

/* Verify leafDer with caDer trusted only through the context, so that path
 * building can reach the anchor only as a temporary CA. Partial chains are
 * allowed so an anchor that is not self-signed can end the path. Returns the
 * X509_verify_cert() result, the error and its depth through the pointers. */
static int run_selfsigned_anchor_case(const byte* caDer, int caSz,
    const byte* leafDer, int leafSz, int* verifyRet, int* verifyErr,
    int* verifyDepth)
{
    EXPECT_DECLS;
    X509* ca   = NULL;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* trusted = NULL;
    const byte* p;

    p = caDer;
    ExpectNotNull(ca = d2i_X509(NULL, &p, caSz));
    p = leafDer;
    ExpectNotNull(leaf = d2i_X509(NULL, &p, leafSz));
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGT(sk_X509_push(trusted, ca), 0);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_PARTIAL_CHAIN);
    *verifyRet = X509_verify_cert(ctx);
    *verifyErr = X509_STORE_CTX_get_error(ctx);
    *verifyDepth = X509_STORE_CTX_get_error_depth(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(trusted);
    X509_free(leaf);
    X509_free(ca);
    return EXPECT_RESULT();
}
#endif

/* Regression: a chain-supplied (untrusted) intermediate that is CA:TRUE but
 * whose KeyUsage extension does NOT assert keyCertSign must NOT be usable to
 * sign the leaf - RFC 5280 4.2.1.3.  Previously such an intermediate, added as
 * a temporary CA during path building, was accepted as a signing CA.
 *
 * Conversely, an intermediate with NO KeyUsage extension implies all usages
 * (including keyCertSign) and must still verify - the fix must not over-reject
 * those. */
int test_X509_verify_cert_ca_no_keycertsign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
    /* ALLOW_INVALID_CERTSIGN disables the keyCertSign enforcement that Case 1
     * relies on, so the test is only meaningful when it is not defined. */
    WC_RNG rng;
    RsaKey caKey, intKey, leafKey;
    int rngI = 0, caI = 0, intI = 0, leafI = 0;
    word32 idx;
    byte* intDer = NULL;
    byte* leafDer = NULL;
    int intSz = 0, leafSz = 0;
    int verifyRet = -1;
    int verifyErr = 0, verifyDepth = 0;
    const byte* p;
    X509* root = NULL;

    intDer  = (byte*)XMALLOC(FOURK_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    leafDer = (byte*)XMALLOC(FOURK_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(intDer);
    ExpectNotNull(leafDer);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngI = 1;
    ExpectIntEQ(wc_InitRsaKey(&caKey, NULL), 0);
    if (EXPECT_SUCCESS()) caI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, &caKey,
        sizeof_ca_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&intKey, NULL), 0);
    if (EXPECT_SUCCESS()) intI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &intKey,
        sizeof_server_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&leafKey, NULL), 0);
    if (EXPECT_SUCCESS()) leafI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &leafKey,
        sizeof_client_key_der_2048), 0);

    p = ca_cert_der_2048;
    ExpectNotNull(root = d2i_X509(NULL, &p, (int)sizeof_ca_cert_der_2048));

    /* Case 1: intermediate CA WITHOUT keyCertSign -> verification must fail. */
    ExpectIntGT((intSz = gen_ca_int_keyusage(intDer, FOURK_BUF, &intKey, &caKey,
        &rng, "No keyCertSign Intermediate", "digitalSignature", 0)), 0);
    ExpectIntGT((leafSz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey,
        intDer, intSz, &intKey, &rng, "Leaf under bad int")), 0);
    verifyRet = -1;
    ExpectIntEQ(run_int_keyusage_case(intDer, intSz, leafDer, leafSz, root,
        &verifyRet, &verifyErr, &verifyDepth), 1);
    ExpectIntNE(verifyRet, 1);
    ExpectIntEQ(verifyErr, X509_V_ERR_INVALID_CA);
    ExpectIntEQ(verifyDepth, 1);

    /* Case 2: intermediate CA with NO KeyUsage extension -> must verify. */
    ExpectIntGT((intSz = gen_ca_int_keyusage(intDer, FOURK_BUF, &intKey, &caKey,
        &rng, "No KeyUsage Intermediate", NULL, 0)), 0);
    ExpectIntGT((leafSz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey,
        intDer, intSz, &intKey, &rng, "Leaf under noKU int")), 0);
    verifyRet = -1;
    ExpectIntEQ(run_int_keyusage_case(intDer, intSz, leafDer, leafSz, root,
        &verifyRet, &verifyErr, &verifyDepth), 1);
    ExpectIntEQ(verifyRet, 1);

    X509_free(root);
    if (rngI)  wc_FreeRng(&rng);
    if (caI)   wc_FreeRsaKey(&caKey);
    if (intI)  wc_FreeRsaKey(&intKey);
    if (leafI) wc_FreeRsaKey(&leafKey);
    XFREE(intDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* As in OpenSSL, a trust anchor whose KeyUsage extension omits keyCertSign
 * cannot issue certificates, also when it is self-signed. A self-issued key
 * rollover certificate signed by the root acts as a trust anchor with
 * keyCertSign.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_X509_verify_cert_selfsigned_anchor_no_keycertsign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
    static const struct {
        int selfSigned;         /* else a rollover signed by the test root */
        const char* keyUsage;
        int expectVerify;       /* expected X509_verify_cert() result */
        int expectErr;          /* expected error */
    } cases[] = {
        { 1, "digitalSignature",             0, X509_V_ERR_INVALID_CA },
        { 0, "digitalSignature",             0, X509_V_ERR_INVALID_CA },
        { 0, "digitalSignature,keyCertSign", 1, X509_V_OK },
    };
    WC_RNG rng;
    RsaKey rootKey, caKey, leafKey;
    int rngI = 0, rootI = 0, caI = 0, leafI = 0;
    word32 idx;
    byte* caDer = NULL;
    byte* leafDer = NULL;
    DecodedCert* dc = NULL;
    int caSz = 0, leafSz = 0;
    int verifyRet;
    int verifyErr = 0, verifyDepth = 0;
    size_t i;

    caDer   = (byte*)XMALLOC(FOURK_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    leafDer = (byte*)XMALLOC(FOURK_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    dc      = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                    DYNAMIC_TYPE_DCERT);
    ExpectNotNull(caDer);
    ExpectNotNull(leafDer);
    ExpectNotNull(dc);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngI = 1;
    ExpectIntEQ(wc_InitRsaKey(&rootKey, NULL), 0);
    if (EXPECT_SUCCESS()) rootI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, &rootKey,
        sizeof_ca_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&caKey, NULL), 0);
    if (EXPECT_SUCCESS()) caI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &caKey,
        sizeof_server_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&leafKey, NULL), 0);
    if (EXPECT_SUCCESS()) leafI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &leafKey,
        sizeof_client_key_der_2048), 0);

    for (i = 0; i < XELEM_CNT(cases) && EXPECT_SUCCESS(); i++) {
        ExpectIntGT((caSz = gen_ca_int_keyusage(caDer, FOURK_BUF, &caKey,
            &rootKey, &rng, cases[i].selfSigned ? "Self Signed Anchor" : NULL,
            cases[i].keyUsage, cases[i].selfSigned)), 0);
        /* A plain parse sets selfSigned only for the self-signed anchor. */
        wc_InitDecodedCert(dc, caDer, (word32)caSz, NULL);
        ExpectIntEQ(wc_ParseCert(dc, CA_TYPE, NO_VERIFY, NULL), 0);
        ExpectIntEQ(dc->selfIssued, 1);
        ExpectIntEQ(dc->selfSigned, cases[i].selfSigned);
        wc_FreeDecodedCert(dc);
        ExpectIntGT((leafSz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey,
            caDer, caSz, &caKey, &rng, "Leaf under anchor")), 0);
        verifyRet = -1;
        ExpectIntEQ(run_selfsigned_anchor_case(caDer, caSz, leafDer, leafSz,
            &verifyRet, &verifyErr, &verifyDepth), 1);
        ExpectIntEQ(verifyRet, cases[i].expectVerify);
        ExpectIntEQ(verifyErr, cases[i].expectErr);
        if (cases[i].expectVerify == 0)
            ExpectIntEQ(verifyDepth, 1);
    }

    if (rngI)  wc_FreeRng(&rng);
    if (rootI) wc_FreeRsaKey(&rootKey);
    if (caI)   wc_FreeRsaKey(&caKey);
    if (leafI) wc_FreeRsaKey(&leafKey);
    XFREE(caDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(dc, NULL, DYNAMIC_TYPE_DCERT);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME)
/* Build a certificate for key, signed with signKey, from bare common names.
 * issuerCn NULL names the 2048-bit test root. skid and akid fill a key id with
 * that byte, 0 omits the extension. */
static X509* gen_named_cert(const char* subjCn, const char* issuerCn, int isCA,
    byte skid, byte akid, RsaKey* key, RsaKey* signKey, WC_RNG* rng)
{
    Cert cert;
    X509* x509 = NULL;
    byte* der = NULL;
    const byte* p;
    int derSz = -1;

    if (wc_InitCert(&cert) != 0)
        return NULL;
    cert.isCA       = isCA;
    cert.sigType    = CTC_SHA256wRSA;
    cert.selfSigned = 0;
    XSTRNCPY(cert.subject.commonName, subjCn, CTC_NAME_SIZE - 1);
    if (issuerCn != NULL)
        XSTRNCPY(cert.issuer.commonName, issuerCn, CTC_NAME_SIZE - 1);
    else if (wc_SetIssuerBuffer(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0) {
    #ifdef WOLFSSL_CERT_GEN_CACHE
        wc_SetCert_Free(&cert); /* release DecodedCert from wc_SetIssuerBuffer */
    #endif
        return NULL;
    }
    if (skid != 0) {
        XMEMSET(cert.skid, skid, KEYID_SIZE);
        cert.skidSz = KEYID_SIZE;
    }
    if (akid != 0) {
        XMEMSET(cert.akid, akid, KEYID_SIZE);
        cert.akidSz = KEYID_SIZE;
    }

    der = (byte*)XMALLOC(FOURK_BUF, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der != NULL && wc_MakeCert(&cert, der, FOURK_BUF, key, NULL, rng) > 0)
        derSz = wc_SignCert(cert.bodySz, cert.sigType, der, FOURK_BUF, signKey,
            NULL, rng);
    if (derSz > 0) {
        p = der;
        x509 = d2i_X509(NULL, &p, derSz);
    }
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_CERT_GEN_CACHE
    wc_SetCert_Free(&cert); /* release DecodedCert from wc_SetIssuerBuffer */
#endif
    return x509;
}
#endif

/* X509_verify_cert() loads each candidate issuer into the CertManager as a
 * temporary CA, and the CertManager picks the signer on its own from all it
 * holds. An untrusted CA loaded for a link below, or for a path that was
 * abandoned, must be gone when the next link is verified: otherwise a
 * certificate signed by it passes while the path goes on with a same-named
 * genuine intermediate that leads to the root.
 *
 * The attacker knows the genuine intermediate's certificate and holds none of
 * its keys. Every forged path must be rejected. */
int test_X509_verify_cert_stale_temp_ca(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME)
    enum { K_ROOT, K_INT, K_ATK, K_CNT };
    enum { C_INT, C_HONEST, C_FORGED, C_LOOP_TWIN, C_LOOP_UP, C_BARE_TWIN,
           C_DECOY, C_FORGED_B, C_TWIN_A, C_TWIN_B, C_UP, C_UP_OTHER, C_CNT };
    static const struct {
        const char* subj;
        const char* issuer;     /* NULL is the test root */
        int  isCA;
        byte skid;
        byte akid;
        int  key;
        int  signKey;
    } certs[C_CNT] = {
        /* The genuine intermediate and a leaf it issued. */
        { "Issuing CA", NULL,         1, 0x03, 0,    K_INT, K_ROOT },
        { "honest",     "Issuing CA", 0, 0,    0x03, K_ATK, K_INT  },
        /* Signed by the attacker in the intermediate's name. */
        { "forged",     "Issuing CA", 0, 0,    0,    K_ATK, K_ATK  },
        /* Two CAs that issued each other, one named like the intermediate. */
        { "Issuing CA", "Upper CA",   1, 0x0b, 0,    K_ATK, K_ATK  },
        { "Upper CA",   "Issuing CA", 1, 0x16, 0,    K_ATK, K_ATK  },
        /* No subject key id, and not signed by the issuer it names. */
        { "Issuing CA", "Decoy CA",   1, 0,    0,    K_ATK, K_ATK  },
        { "Decoy CA",   "Nowhere",    1, 0x16, 0,    K_INT, K_ATK  },
        /* Twin A verifies under Upper CA, which names twin B as its issuer but
         * is not signed by it. The other Upper CA did not sign twin A. */
        { "forged",     "Issuing CA", 0, 0x16, 0,    K_ATK, K_ATK  },
        { "Issuing CA", "Upper CA",   1, 0x0b, 0,    K_ATK, K_INT  },
        { "Issuing CA", "Nowhere",    1, 0x16, 0,    K_ATK, K_ROOT },
        { "Upper CA",   "Issuing CA", 1, 0x21, 0x16, K_INT, K_ROOT },
        { "Upper CA",   "Nowhere",    1, 0x2c, 0,    K_ATK, K_ROOT },
    };
    static const struct {
        int leaf;
        int untrusted[6];       /* in push order, ends with -1 */
        int expectVerify;       /* expected X509_verify_cert() result */
    } cases[] = {
        { C_HONEST,   { C_INT, -1 }, 1 },
        { C_FORGED,   { C_INT, -1 }, 0 },
        /* Left from a link below: no link fails on the way up. */
        { C_FORGED,   { C_LOOP_TWIN, C_LOOP_UP, C_INT, -1 }, 0 },
        /* Left from an abandoned path: the certificate that failed. */
        { C_FORGED,   { C_BARE_TWIN, C_DECOY, C_INT, -1 }, 0 },
        /* Left from an abandoned path: the issuer it failed against. */
        { C_FORGED_B, { C_TWIN_A, C_INT, C_TWIN_B, C_UP, C_UP_OTHER, -1 }, 0 },
    };
    WC_RNG rng;
    RsaKey keys[K_CNT];
    int rngI = 0;
    int keysI = 0;
    word32 idx;
    X509* x509[C_CNT];
    X509* root = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    STACK_OF(X509)* untrusted = NULL;
    const byte* p;
    size_t i;
    int j;

    XMEMSET(x509, 0, sizeof(x509));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngI = 1;
    for (j = 0; j < K_CNT; j++) {
        ExpectIntEQ(wc_InitRsaKey(&keys[j], NULL), 0);
        if (EXPECT_SUCCESS()) keysI = j + 1;
    }
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, &keys[K_ROOT],
        sizeof_ca_key_der_2048), 0);
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &keys[K_INT],
        sizeof_server_key_der_2048), 0);
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &keys[K_ATK],
        sizeof_client_key_der_2048), 0);

    p = ca_cert_der_2048;
    ExpectNotNull(root = d2i_X509(NULL, &p, (int)sizeof_ca_cert_der_2048));
    for (j = 0; j < C_CNT; j++) {
        ExpectNotNull(x509[j] = gen_named_cert(certs[j].subj, certs[j].issuer,
            certs[j].isCA, certs[j].skid, certs[j].akid, &keys[certs[j].key],
            &keys[certs[j].signKey], &rng));
    }

    for (i = 0; i < XELEM_CNT(cases) && EXPECT_SUCCESS(); i++) {
        ExpectNotNull(store = X509_STORE_new());
        ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
        ExpectNotNull(untrusted = sk_X509_new_null());
        for (j = 0; cases[i].untrusted[j] >= 0; j++) {
            ExpectIntGT(sk_X509_push(untrusted, x509[cases[i].untrusted[j]]),
                0);
        }
        ExpectNotNull(ctx = X509_STORE_CTX_new());
        ExpectIntEQ(X509_STORE_CTX_init(ctx, store, x509[cases[i].leaf],
            untrusted), 1);
        ExpectIntEQ(X509_verify_cert(ctx), cases[i].expectVerify);
        X509_STORE_CTX_free(ctx);
        ctx = NULL;
        X509_STORE_free(store);
        store = NULL;
        sk_X509_free(untrusted);
        untrusted = NULL;
    }

    for (j = 0; j < C_CNT; j++)
        X509_free(x509[j]);
    X509_free(root);
    while (keysI > 0)
        wc_FreeRsaKey(&keys[--keysI]);
    if (rngI) wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
/* See certs/intermediate/trust_anchor/gen_certs.sh and gen_dated_certs.sh */
#define TA_CERT_DIR "./certs/intermediate/trust_anchor/"
#if defined(HAVE_CRL) && defined(WOLFSSL_CERT_GEN) && \
    !defined(NO_ASN_TIME) && !defined(NO_STDIO_FILESYSTEM)
/* CRLs are generated */
#define X509_VFY_GEN_CRLS
#endif

/* Verify errors */
#define VE_OK       X509_V_OK
#define VE_ISSUER   X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
#define VE_NOCRL    X509_V_ERR_UNABLE_TO_GET_CRL
#define VE_CRLSIG   X509_V_ERR_CRL_SIGNATURE_FAILURE
#define VE_SIG      X509_V_ERR_CERT_SIGNATURE_FAILURE
#define VE_NOTYET   X509_V_ERR_CERT_NOT_YET_VALID
#define VE_EXPIRED  X509_V_ERR_CERT_HAS_EXPIRED
#define VE_SELF0    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
#define VE_SELF     X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
#define VE_LOCAL    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
#define VE_LEAFSIG  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
#define VE_LONG     X509_V_ERR_CERT_CHAIN_TOO_LONG
#define VE_REVOKED  X509_V_ERR_CERT_REVOKED
#define VE_CA       X509_V_ERR_INVALID_CA
#define VE_CERTSIGN X509_V_ERR_KEYUSAGE_NO_CERTSIGN
#define VE_KEYSIZE  X509_V_ERR_CA_KEY_TOO_SMALL
#define VE_NCPERM   X509_V_ERR_PERMITTED_VIOLATION
#define VE_NCEXCL   X509_V_ERR_EXCLUDED_VIOLATION
#define VE_PATHLEN  X509_V_ERR_PATH_LENGTH_EXCEEDED
#define VE_CRLEXP   X509_V_ERR_CRL_HAS_EXPIRED
#define VE_CRLNYV   X509_V_ERR_CRL_NOT_YET_VALID
#define VE_CRLKU    X509_V_ERR_KEYUSAGE_NO_CRL_SIGN

/* Options of a case */
#define VO_XMLSEC   0x00001 /* a new param, as xmlsec: no TRUSTED_FIRST */
#define VO_PARTIAL  0x00002 /* X509_V_FLAG_PARTIAL_CHAIN */
#define VO_STRICT   0x00004 /* X509_V_FLAG_X509_STRICT */
#define VO_NOTIME   0x00008 /* X509_V_FLAG_NO_CHECK_TIME */
#define VO_S_STRICT 0x00010 /* X509_V_FLAG_X509_STRICT on the store */
#define VO_S_NOTIME 0x00020 /* X509_V_FLAG_NO_CHECK_TIME on the store */
#define VO_CRL      0x00040 /* X509_V_FLAG_CRL_CHECK on the store */
#define VO_CRL_ALL  0x000C0 /* and X509_V_FLAG_CRL_CHECK_ALL */
#define VO_FILE     0x00100 /* trusted certs by X509_STORE_load_locations */
#define VO_LOOKUP   0x00200 /* by X509_LOOKUP_load_file */
#define VO_SSLCTX   0x00400 /* by SSL_CTX_load_verify_locations */
#define VO_ADD1999  0x00800 /* trusted certs added in 1999 */
#define VO_MINRSA   0x01000 /* a minimum RSA CA key of 4096 bits */
#define VO_DEPTH0   0x02000 /* X509_STORE_CTX_set_depth(ctx, 0) */
#define VO_DEPTH1   0x04000 /* X509_STORE_CTX_set_depth(ctx, 1) */
#define VO_MINECC   0x08000 /* a minimum ECC CA key of 384 bits */
#define VO_T2005    0x10000 /* verification time 2005 */
#define VO_T2015    0x20000 /* 2015 */
#define VO_T2025    0x30000 /* 2025 */
#define VO_TIME     0x30000
#define VO_S_PARTIAL 0x40000 /* X509_V_FLAG_PARTIAL_CHAIN on the store */
#define VO_C_CRL    0x80000 /* X509_V_FLAG_CRL_CHECK on the ctx */
#define VO_C_CRL_ALL 0x180000 /* and X509_V_FLAG_CRL_CHECK_ALL */

/* The verify callback logs every error and accepts these */
#define VA_ISSUER   0x01 /* VE_ISSUER */
#define VA_LOCAL    0x02 /* VE_LOCAL */
#define VA_SELF     0x04 /* VE_SELF0 and VE_SELF */
#define VA_DATES    0x08 /* VE_NOTYET and VE_EXPIRED */
#define VA_CA       0x10 /* VE_CA */
#define VA_KEYSIZE  0x20 /* VE_KEYSIZE */
#define VA_NOCRL    0x40 /* VE_NOCRL */
#define VA_CRLKU    0x100 /* VE_CRLKU */
#define VA_CRLEXP   0x200 /* VE_CRLEXP */
#define VA_ALL      0x80 /* any */

/* A verification. Certs are named by file: TA_CERT_DIR <name>-cert.pem or
 * an alias of x509VfyFiles; "<name>#2" is another copy of it. CRLs alike,
 * with -crl.pem; "+<name>" is given with X509_STORE_CTX_set0_crls(). */
typedef struct x509_vfy_case {
    const char* name;
    const char* trusted;    /* store certs, in the order added */
    const char* stack;      /* X509_STORE_CTX_trusted_stack() */
    const char* untrusted;
    const char* leaf;
    const char* crls;
    int opts;               /* VO_* */
    int cb;                 /* VA_*, 0: no verify callback */
    int ret;                /* of X509_verify_cert() */
    int err;
    int depth;              /* of err, unless VE_OK */
    const char* chain;      /* leaf first, NULL: not checked */
    int cbLog[6];           /* errors and depths the callback saw */
} x509_vfy_case;

static const x509_vfy_case x509VfyCases[] = {
    /* Every issuer, untrusted or trusted, meets the cert manager's minimum
     * CA key size. All keys are 2048 bits. OpenSSL has no minimum for CAs
     * only: at auth level 3 it first reports
     * X509_V_ERR_EE_KEY_TOO_SMALL for the leaf, then the same errors. */
    { "key_size: 2048 bits",
      "ca", NULL, "int1 int2", "server-int", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "key_size: 4096 bits minimum",
      "ca", NULL, "int1 int2", "server-int", NULL,
      VO_MINRSA, 0, 0, VE_KEYSIZE, 1, NULL, { 0 } },
    { "key_size: callback accepts each issuer, the anchor too",
      "ca", NULL, "int1 int2", "server-int", NULL,
      VO_MINRSA, VA_KEYSIZE, 1, VE_KEYSIZE, 0, NULL,
      { VE_KEYSIZE, 1, VE_KEYSIZE, 2, VE_KEYSIZE, 3 } },
#ifdef HAVE_ECC
    /* The size of an ECC key is that of its curve. All keys are P-256. */
    { "key_size: P-256",
      "ca-ecc", NULL, "int1-ecc int2-ecc", "server-int-ecc", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "key_size: 384 bits ECC minimum",
      "ca-ecc", NULL, "int1-ecc int2-ecc", "server-int-ecc", NULL,
      VO_MINECC, 0, 0, VE_KEYSIZE, 1, NULL, { 0 } },
#endif

    /* A self-signed cert ends the chain. self-copy has the name and key of
     * the trusted self, which verifies it, but only a trusted cert itself
     * ends the chain. */
    { "selfsigned_copy: trusted",
      "self", NULL, NULL, "self", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfsigned_copy: copy",
      "self", NULL, NULL, "self-copy", NULL,
      0, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "selfsigned_copy: callback accepts copy",
      "self", NULL, NULL, "self-copy", NULL,
      0, VA_ALL, 1, VE_SELF0, 0, "self-copy", { VE_SELF0, 0 } },
    { "selfsigned_copy: copy, partial chain",
      "self", NULL, NULL, "self-copy", NULL,
      VO_PARTIAL, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    /* As in OpenSSL, the first trusted cert of the name, self, is taken: the
     * copy is a mimic of it. Added first, the copy is taken. */
    { "selfsigned_copy: copy trusted too",
      "self self-copy", NULL, NULL, "self-copy", NULL,
      0, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "selfsigned_copy: copy trusted first",
      "self-copy self", NULL, NULL, "self-copy", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfsigned_copy: copy, trusted stack",
      NULL, "self", NULL, "self-copy", NULL,
      0, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "selfsigned_copy: trusted stack",
      NULL, "self", NULL, "self", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfsigned_copy: copy, store file",
      "self", NULL, NULL, "self-copy", NULL,
      VO_FILE, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "selfsigned_copy: store file",
      "self", NULL, NULL, "self", NULL,
      VO_FILE, 0, 1, VE_OK, 0, NULL, { 0 } },
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    { "selfsigned_copy: copy, lookup file",
      "self", NULL, NULL, "self-copy", NULL,
      VO_LOOKUP, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "selfsigned_copy: lookup file",
      "self", NULL, NULL, "self", NULL,
      VO_LOOKUP, 0, 1, VE_OK, 0, NULL, { 0 } },
#endif
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    /* An SSL_CTX keeps its CAs in the cert manager only */
    { "selfsigned_copy: SSL_CTX",
      "self", NULL, NULL, "self", NULL,
      VO_SSLCTX, 0, 1, VE_OK, 0, NULL, { 0 } },
#endif

    /* A trusted cert is a root only when self-signed. link has the name of
     * root and its own key, and root issued it: it is self-issued, but its
     * authority key id names root's key. */
    { "selfissued_anchor: link",
      "link", NULL, NULL, "leaf", NULL,
      0, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "selfissued_anchor: callback accepts link",
      "link", NULL, NULL, "leaf", NULL,
      0, VA_ALL, 1, VE_ISSUER, 0, "leaf link", { VE_ISSUER, 1 } },
    { "selfissued_anchor: link, partial chain",
      "link", NULL, NULL, "leaf", NULL,
      VO_PARTIAL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfissued_anchor: link without aki is self-signed",
      "link-noaki", NULL, NULL, "leaf", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfissued_anchor: link and root",
      "link root", NULL, NULL, "leaf", NULL,
      0, 0, 1, VE_OK, 0, "leaf link root", { 0 } },
    /* link is not the anchor: it counts against the depth */
    { "selfissued_anchor: link and root, depth 0",
      "link root", NULL, NULL, "leaf", NULL,
      VO_DEPTH0, 0, 0, VE_LONG, 1, NULL, { 0 } },
    { "selfissued_anchor: link and root, depth 1",
      "link root", NULL, NULL, "leaf", NULL,
      VO_DEPTH1, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "selfissued_anchor: link, store file",
      "link", NULL, NULL, "leaf", NULL,
      VO_FILE, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "selfissued_anchor: link and root, store file",
      "link root", NULL, NULL, "leaf", NULL,
      VO_FILE, 0, 1, VE_OK, 0, NULL, { 0 } },
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    { "selfissued_anchor: link, lookup file",
      "link", NULL, NULL, "leaf", NULL,
      VO_LOOKUP, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "selfissued_anchor: link and root, lookup file",
      "link root", NULL, NULL, "leaf", NULL,
      VO_LOOKUP, 0, 1, VE_OK, 0, NULL, { 0 } },
#endif
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_SIGNER_DER_CERT)
    /* A CA of an SSL_CTX is a trusted cert, the chain goes on to its
     * issuer there */
    { "selfissued_anchor: root and link, SSL_CTX",
      "root link", NULL, NULL, "leaf", NULL,
      VO_SSLCTX, 0, 1, VE_OK, 0, "leaf link root", { 0 } },
    { "selfissued_anchor: link, SSL_CTX",
      "link", NULL, NULL, "leaf", NULL,
      VO_SSLCTX, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
#endif

    /* Every cert above the leaf is a CA that may sign certs, a trusted one
     * too. Without basicConstraints only a v1 self-signed root is one,
     * unless X509_V_FLAG_X509_STRICT is set. With that flag OpenSSL first
     * reports that v1-root-leaf has no authority key id:
     * X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER at depth 0. */
    { "trusted_ca: CA:FALSE root",
      "notca-root nobc-root v1-root", NULL, NULL, "notca-root-leaf", NULL,
      0, 0, 0, VE_CA, 1, NULL, { 0 } },
    { "trusted_ca: callback accepts CA:FALSE root",
      "notca-root nobc-root v1-root", NULL, NULL, "notca-root-leaf", NULL,
      0, VA_ALL, 1, VE_CA, 0, "notca-root-leaf notca-root", { VE_CA, 1 } },
    { "trusted_ca: CA:FALSE root, a stack without it",
      "notca-root nobc-root v1-root", "v1-root", NULL, "notca-root-leaf",
      NULL, 0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    /* The stack's leaf ends the chain: the store's root is not on it */
    { "trusted_ca: leaf in a stack, partial chain",
      "notca-root nobc-root v1-root", "notca-root-leaf", NULL,
      "notca-root-leaf", NULL,
      VO_PARTIAL, 0, 1, VE_OK, 0, "notca-root-leaf", { 0 } },
    { "trusted_ca: CA:FALSE root as the leaf",
      "notca-root nobc-root v1-root", NULL, NULL, "notca-root", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "trusted_ca: copy of a stack cert",
      NULL, "notca-root", NULL, "notca-root#2", NULL,
      0, 0, 1, VE_OK, 0, "notca-root", { 0 } },
    { "trusted_ca: v3 root without basicConstraints",
      "notca-root nobc-root v1-root", NULL, NULL, "nobc-root-leaf", NULL,
      0, 0, 0, VE_CA, 1, NULL, { 0 } },
    { "trusted_ca: callback accepts v3 root without basicConstraints",
      "notca-root nobc-root v1-root", NULL, NULL, "nobc-root-leaf", NULL,
      0, VA_ALL, 1, VE_CA, 0, "nobc-root-leaf nobc-root", { VE_CA, 1 } },
    { "trusted_ca: v1 root",
      "notca-root nobc-root v1-root", NULL, NULL, "v1-root-leaf", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "trusted_ca: v1 root, strict",
      "notca-root nobc-root v1-root", NULL, NULL, "v1-root-leaf", NULL,
      VO_STRICT, 0, 0, VE_CA, 1, NULL, { 0 } },
    { "trusted_ca: v1 root in a stack",
      NULL, "notca-root v1-root", NULL, "v1-root-leaf", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "trusted_ca: v1 root in a stack, strict",
      NULL, "notca-root v1-root", NULL, "v1-root-leaf", NULL,
      VO_STRICT, 0, 0, VE_CA, 1, NULL, { 0 } },
    { "trusted_ca: v1 root, strict store",
      "notca-root nobc-root v1-root", NULL, NULL, "v1-root-leaf", NULL,
      VO_S_STRICT, 0, 0, VE_CA, 1, NULL, { 0 } },
#ifndef WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE
    /* An untrusted CA:FALSE intermediate is reported as itself, then its
     * keyUsage without keyCertSign */
    { "trusted_ca: CA:FALSE intermediate",
      "nca-ca", NULL, "nca-int", "nca-leaf", NULL,
      VO_FILE, VA_ALL, 1, VE_CERTSIGN, 0, "nca-leaf nca-int nca-ca",
      { VE_CA, 1, VE_CERTSIGN, 1 } },
    /* The leaf signature is still checked after that */
    { "trusted_ca: CA:FALSE intermediate, bad leaf signature",
      "nca-ca", NULL, "nca-int", "nca-leaf-badsig", NULL,
      VO_FILE, VA_ALL, 1, VE_SIG, 0, "nca-leaf-badsig nca-int nca-ca",
      { VE_CA, 1, VE_CERTSIGN, 1, VE_SIG, 0 } },
#else
    /* An untrusted CA:FALSE intermediate is allowed */
    { "trusted_ca: CA:FALSE intermediate allowed",
      "nca-ca", NULL, "nca-int", "nca-leaf", NULL,
      VO_FILE, VA_ALL, 1, VE_OK, 0, "nca-leaf nca-int nca-ca", { 0 } },
    { "trusted_ca: CA:FALSE intermediate allowed, bad leaf signature",
      "nca-ca", NULL, "nca-int", "nca-leaf-badsig", NULL,
      VO_FILE, VA_ALL, 1, VE_SIG, 0, "nca-leaf-badsig nca-int nca-ca",
      { VE_SIG, 0 } },
#endif

    /* With X509_V_FLAG_TRUSTED_FIRST, the default, a trusted root that
     * issues a cert ends the chain, also when an untrusted cross-signed copy
     * of it issues it too. cross-root is dated-root issued by expired-root.
     * Without the flag the untrusted certs come first. */
    { "trusted_first: trusted root first",
      "dated-root expired-root", NULL, "dated-int cross-root",
      "dated-int-leaf", NULL,
      0, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root", { 0 } },
#ifndef NO_ASN_TIME
    { "trusted_first: untrusted first",
      "dated-root expired-root", NULL, "dated-int cross-root",
      "dated-int-leaf", NULL,
      VO_XMLSEC, 0, 0, VE_EXPIRED, 3, NULL, { 0 } },
    /* dated-root-late is not valid in 2015, expired-root is */
    { "trusted_first: late root",
      "dated-root-late expired-root", NULL, "dated-int cross-root",
      "dated-int-leaf", NULL,
      VO_T2015, 0, 0, VE_NOTYET, 2, NULL, { 0 } },
    { "trusted_first: late root, untrusted first",
      "dated-root-late expired-root", NULL, "dated-int cross-root",
      "dated-int-leaf", NULL,
      VO_XMLSEC | VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int cross-root expired-root", { 0 } },
    /* A trusted cert valid at the verification time comes first, also
     * before a trusted root */
    { "trusted_first: trusted cross-root valid in 2015",
      "dated-root-late expired-root cross-root", NULL,
      "dated-int cross-root", "dated-int-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int cross-root expired-root", { 0 } },

    /* Without X509_V_FLAG_TRUSTED_FIRST the issuer of an untrusted cert
     * comes from the untrusted certs first, then from the trusted certs, one
     * valid at the verification time first. Above a trusted cert only a
     * trusted cert issues, with the flag too. */
    { "untrusted_first: trusted root valid in 2015",
      "dated-root expired-root cross-root-late", NULL, "dated-int",
      "dated-int-leaf", NULL,
      VO_XMLSEC | VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int dated-root", { 0 } },
    { "untrusted_first: no untrusted issuer of a trusted cert",
      "dated-root expired-root dated-int", NULL, "cross-root",
      "dated-int-leaf", NULL,
      VO_XMLSEC, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root",
      { 0 } },
    { "untrusted_first: no untrusted issuer of a trusted cert, no root",
      "expired-root dated-int", NULL, "cross-root", "dated-int-leaf", NULL,
      VO_XMLSEC | VO_T2015, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "untrusted_first: no root, trusted first",
      "expired-root dated-int", NULL, "cross-root", "dated-int-leaf", NULL,
      VO_T2015, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "untrusted_first: trusted cross-root valid in 2015",
      "dated-root-late expired-root cross-root", NULL, "dated-int",
      "dated-int-leaf", NULL,
      VO_XMLSEC | VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int cross-root expired-root", { 0 } },

    /* Without X509_V_FLAG_TRUSTED_FIRST the untrusted certs are searched in
     * their order, self-signed ones included */
    { "untrusted_order: copy of the root first",
      "dated-root expired-root", NULL, "dated-int dated-root#2 cross-root",
      "dated-int-leaf", NULL,
      VO_XMLSEC, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root",
      { 0 } },
    { "untrusted_order: cross-root first",
      "dated-root expired-root", NULL, "dated-int cross-root dated-root#2",
      "dated-int-leaf", NULL,
      VO_XMLSEC, 0, 0, VE_EXPIRED, 3, NULL, { 0 } },

    /* alt-end, issued by a cert not given, is above the untrusted twins of
     * alt-int, which alt-root issued. OpenSSL goes on from the trusted
     * alt-int and verifies. wolfSSL fails closed: the twin is the issuer and
     * alt-end above it has none. */
    { "dead_end: twin out of date",
      "alt-end alt-int alt-root", NULL, "alt-old-int", "alt-int-leaf", NULL,
      VO_XMLSEC, 0, 0, VE_ISSUER, 2, NULL, { 0 } },
    { "dead_end: twin not a CA",
      "alt-end alt-int alt-root", NULL, "alt-notca-int", "alt-int-leaf",
      NULL, VO_XMLSEC, 0, 0, VE_ISSUER, 2, NULL, { 0 } },
    /* OpenSSL: VE_NOTYET at depth 1 on its chain through alt-int, which
     * the callback accepts. The missing issuer is final as a trusted cert
     * issued the leaf. */
    { "dead_end: alt-int not valid yet",
      "alt-end alt-int alt-root", NULL, "alt-end-int", "alt-int-leaf", NULL,
      VO_XMLSEC | VO_T2015, VA_ALL, 0, VE_ISSUER, 2,
      "alt-int-leaf alt-end-int alt-end", { VE_ISSUER, 2 } },
    /* OpenSSL: VE_CA at depth 1 on its chain through the trusted twin */
    { "dead_end: trusted twin not a CA",
      "alt-notca-int alt-end", NULL, "alt-end-int", "alt-int-leaf", NULL,
      VO_XMLSEC, VA_ISSUER | VA_LOCAL, 0, VE_ISSUER, 2, NULL,
      { VE_ISSUER, 2 } },
#endif

    /* A trusted self-signed root ends the chain. noaki-root has no authority
     * key id, so by name noaki-root-link, a trusted CA it issued, could
     * issue it too. */
    { "noaki_root: root ends the chain",
      NULL, "noaki-root-link noaki-root", NULL, "noaki-root-leaf", NULL,
      0, VA_ALL, 1, VE_OK, 0, "noaki-root-leaf noaki-root", { 0 } },

    /* A cert is verified with the issuer chosen for it only. The cert
     * manager finds forge-fake-int by name before forge-int. */
    { "forged_issuer: forge-int",
      "forge-root", NULL, NULL, "forge-int", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "forged_issuer: bad sub first",
      "forge-root", NULL, "forge-bad-sub forge-sub forge-int forge-fake-int",
      "forge-sub-leaf", NULL,
      0, 0, 0, VE_LOCAL, 2, NULL, { 0 } },
    { "forged_issuer: fake int",
      "forge-root", NULL, "forge-fake-int forge-q forge-int",
      "forge-fake-int-leaf", NULL,
      0, 0, 0, VE_SIG, 2, NULL, { 0 } },

    /* The issuer chosen for a cert must have signed it. notca-twin has the
     * name of notca-root, which signed the leaf, but not its key. Without a
     * subject key id it issues the leaf by name. */
    { "wrong_signer: trusted notca-root first",
      "root notca-root", NULL, "notca-twin", "notca-root-leaf", NULL,
      0, 0, 0, VE_CA, 1, NULL, { 0 } },
    /* The untrusted twin is taken by name: VE_SIG at depth 0 */
    { "wrong_signer: untrusted first",
      "root notca-root", NULL, "notca-twin", "notca-root-leaf", NULL,
      VO_XMLSEC, 0, 0, VE_SIG, 0, "notca-root-leaf notca-twin root",
      { 0 } },
    { "wrong_signer: only a stack issues",
      "notca-root", "root", "notca-twin", "notca-root-leaf", NULL,
      0, 0, 0, VE_SIG, 0, NULL, { 0 } },

#ifndef NO_ASN_TIME
    /* A callback that rejects an error of a trusted cert ends the
     * verification. The trusted wrongca-int names wrongca as its issuer,
     * whose key did not sign it. Its untrusted twin wrongca-old-int, out of
     * date, has no issuer. OpenSSL: VE_SIG at depth 1 through the trusted
     * twin. wolfSSL fails closed on the missing issuer. */
    { "trusted_cert_error: no root",
      "wrongca-int wrongca", NULL, "wrongca-old-int", "wrongca-int-leaf",
      NULL, VO_XMLSEC, VA_ISSUER | VA_LOCAL, 0, VE_LOCAL, 1, NULL,
      { VE_LOCAL, 1 } },
    { "trusted_cert_error: root",
      "wrongca-int wrongca wrongca-root", NULL, "wrongca-old-int",
      "wrongca-int-leaf", NULL,
      VO_XMLSEC, VA_ISSUER | VA_LOCAL, 0, VE_LOCAL, 1, NULL,
      { VE_LOCAL, 1 } },
#endif

    /* With a trusted stack, trusted certs come only from the stack. The
     * store's dated-root has the name and key of the stack's cross-root but
     * does not issue it, nor dated-int in a stack, nor any other cert. */
    { "trusted_stack_only: stack cert without issuer",
      "dated-root", "cross-root", NULL, "dated-int", NULL,
      0, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "trusted_stack_only: leaf",
      "dated-root", "cross-root", "dated-int", "dated-int-leaf", NULL,
      0, 0, 0, VE_ISSUER, 2, NULL, { 0 } },
    { "trusted_stack_only: dated-int in the stack",
      "dated-root", "dated-int", NULL, "dated-int-leaf", NULL,
      0, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "trusted_stack_only: callback accepts, the chain ends there",
      "dated-root", "dated-int", NULL, "dated-int-leaf", NULL,
      0, VA_ALL, 1, VE_ISSUER, 0, "dated-int-leaf dated-int",
      { VE_ISSUER, 1 } },
    { "trusted_stack_only: partial chain",
      "dated-root", "cross-root", "dated-int", "dated-int-leaf", NULL,
      VO_PARTIAL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "trusted_stack_only: store CA does not issue the leaf",
      "dated-root", "expired-root", NULL, "dated-int", NULL,
      0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    { "trusted_stack_only: store CA does not issue an untrusted cert",
      "dated-root", "expired-root", "dated-int", "dated-int-leaf", NULL,
      0, 0, 0, VE_LOCAL, 1, NULL, { 0 } },
    /* The top of a partial chain: its dates are not checked */
    { "trusted_stack_only: expired stack cert",
      "dated-root", "expired-int", NULL, "dated-int-leaf", NULL,
      0, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "trusted_stack_only: callback accepts expired stack cert",
      "dated-root", "expired-int", NULL, "dated-int-leaf", NULL,
      0, VA_ALL, 1, VE_ISSUER, 0, NULL, { VE_ISSUER, 1 } },
    { "trusted_stack_only: store root not trusted",
      "dated-root", "expired-int", NULL, "dated-root", NULL,
      0, 0, 0, VE_SELF0, 0, NULL, { 0 } },
    { "trusted_stack_only: store root not trusted, partial chain",
      "dated-root", "expired-int", NULL, "dated-root", NULL,
      VO_PARTIAL, 0, 0, VE_SELF0, 0, NULL, { 0 } },

#ifdef HAVE_CRL
    /* With X509_V_FLAG_CRL_CHECK_ALL the CRL of a stack cert that no stack
     * cert issues cannot be checked: its issuer is not on the chain.
     * Accepting the missing issuer does not accept that. */
    { "trusted_stack_crl: missing issuer accepted",
      "ca", "int1", NULL, "int2", "ca-int-crl",
      VO_CRL_ALL, VA_ISSUER | VA_LOCAL, 0, VE_NOCRL, 1, NULL,
      { VE_ISSUER, 1, VE_NOCRL, 1 } },
    { "trusted_stack_crl: callback accepts both",
      "ca", "int1", NULL, "int2", "ca-int-crl",
      VO_CRL_ALL, VA_ALL, 1, VE_NOCRL, 0, "int2 int1",
      { VE_ISSUER, 1, VE_NOCRL, 1 } },
    { "trusted_stack_crl: partial chain",
      "ca", "int1", NULL, "int2", "ca-int-crl",
      VO_CRL_ALL | VO_PARTIAL, 0, 0, VE_NOCRL, 1, NULL, { 0 } },
#endif

    /* A trusted root of the name of a cert's issuer issues it when the key
     * ids do not tell otherwise, also when its key did not sign it.
     * expired-root-nokid has expired-root's name, a new key, no key ids. */
    { "nokid_issuer: wrong key",
      "expired-root-nokid", NULL, NULL, "expired-root-leaf", NULL,
      0, 0, 0, VE_SIG, 0, NULL, { 0 } },
    { "nokid_issuer: callback accepts",
      "expired-root-nokid", NULL, NULL, "expired-root-leaf", NULL,
      0, VA_ALL, 1, VE_SIG, 0, "expired-root-leaf expired-root-nokid",
      { VE_SIG, 0 } },

#ifdef HAVE_ECC
    /* An issuer has a key of the type of the cert's signature. ec-name-root,
     * an EC root without key ids, has the name of the RSA link, which issued
     * the leaf. */
    { "keytype_issuer: EC root of the name",
      "ec-name-root", NULL, NULL, "leaf", NULL,
      0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    { "keytype_issuer: callback accepts",
      "ec-name-root", NULL, NULL, "leaf", NULL,
      0, VA_ALL, 1, VE_LEAFSIG, 0, "leaf",
      { VE_LOCAL, 0, VE_LEAFSIG, 0 } },
#endif

#ifndef NO_ASN_TIME
    /* The dates of every cert of the chain are checked at the verification
     * time, the trust anchor too. expired-root is valid from 2010 to 2019,
     * the leaf it issued from 2000 to 2049. */
    { "anchor_dates: no check time on the store",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_S_NOTIME, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "anchor_dates: expired root",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      0, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "anchor_dates: 2015",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "anchor_dates: 2005",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2005, 0, 0, VE_NOTYET, 1, NULL, { 0 } },
    /* The verification time wins over X509_V_FLAG_NO_CHECK_TIME */
    { "anchor_dates: 2025 and no check time",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2025 | VO_NOTIME, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "anchor_dates: no check time",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_NOTIME, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "anchor_dates: callback accepts",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, "expired-root-leaf expired-root",
      { VE_EXPIRED, 1 } },
    /* A trusted leaf is checked once, as the current cert */
    { "anchor_dates: trusted leaf",
      "expired-root", NULL, NULL, "expired-root", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, "expired-root", { VE_EXPIRED, 0 } },
    { "anchor_dates: copy of a stack cert",
      NULL, "expired-root", NULL, "expired-root#2", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, "expired-root", { VE_EXPIRED, 0 } },
    /* With X509_V_FLAG_PARTIAL_CHAIN the first trusted cert ends the chain.
     * The root above it is not checked. */
    { "anchor_dates: trusted intermediate",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, 0, 0, 0, VE_EXPIRED, 2, NULL, { 0 } },
    { "anchor_dates: trusted intermediate, partial chain",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, VO_PARTIAL, 0, 1, VE_OK, 0, NULL, { 0 } },
    /* A cert above that trusted cert is not on the chain. Its date error
     * does not end the verification: cross-root-late issues the trusted
     * dated-int and is valid from 2020. */
    { "anchor_dates: late cert above",
      "expired-root expired-root-int dated-int", NULL, "cross-root-late",
      "dated-int-leaf", NULL,
      VO_T2015, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "anchor_dates: late cert above, partial chain",
      "expired-root expired-root-int dated-int", NULL, "cross-root-late",
      "dated-int-leaf", NULL,
      VO_T2015 | VO_PARTIAL, 0, 1, VE_OK, 0, "dated-int-leaf dated-int",
      { 0 } },
    /* The store is not used with a trusted stack. With the leaf in the
     * stack, the partial chain ends below the store's dated-root-late, not
     * valid in 2015. */
    { "anchor_dates: stack cert as the leaf",
      "dated-root-late", "dated-int", NULL, "dated-int", NULL,
      VO_T2015 | VO_PARTIAL, 0, 1, VE_OK, 0, "dated-int", { 0 } },
    /* As in OpenSSL, the leaf ends the partial chain only when no issuer
     * is found: the untrusted dated-int is put on it */
    { "anchor_dates: stack cert as the leaf, untrusted issuer",
      "dated-root-late", "dated-int-leaf", "dated-int", "dated-int-leaf",
      NULL, VO_T2015 | VO_PARTIAL, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int", { 0 } },

    /* The ctx param inherits the store's X509_V_FLAG_PARTIAL_CHAIN. As in
     * OpenSSL, a new param, as xmlsec sets, does not have it. */
    { "partial_chain: store flag",
      "int2", NULL, NULL, "server-int", NULL,
      VO_S_PARTIAL, 0, 1, VE_OK, 0, "server-int int2", { 0 } },
    { "partial_chain: store flag, new param",
      "int2", NULL, NULL, "server-int", NULL,
      VO_S_PARTIAL | VO_XMLSEC, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "partial_chain: new param with the flag",
      "int2", NULL, NULL, "server-int", NULL,
      VO_PARTIAL | VO_XMLSEC, 0, 1, VE_OK, 0, "server-int int2", { 0 } },

    /* As OpenSSL, the callback is told of a chain too long. Failing closed,
     * the error is final: once it is accepted, OpenSSL reports VE_LOCAL at
     * depth 1 and verifies. */
    { "depth: callback told",
      "ca", NULL, "int1 int2", "server-int", NULL,
      VO_DEPTH0, VA_ISSUER, 0, VE_LONG, 1, NULL, { VE_LONG, 1 } },
    { "depth: callback accepts",
      "ca", NULL, "int1 int2", "server-int", NULL,
      VO_DEPTH0, VA_ALL, 0, VE_LONG, 1, NULL, { VE_LONG, 1 } },

    /* X509_V_FLAG_CRL_CHECK(_ALL) on the ctx without CRLs, also without
     * HAVE_CRL: each cert checked has no CRL */
    { "crl_none: CRL_CHECK on the ctx",
      "ca", NULL, NULL, "server", NULL,
      VO_C_CRL, 0, 0, VE_NOCRL, 0, NULL, { 0 } },
    { "crl_none: CRL_CHECK on the ctx, callback accepts",
      "ca", NULL, NULL, "server", NULL,
      VO_C_CRL, VA_NOCRL, 1, VE_NOCRL, 0, NULL, { VE_NOCRL, 0 } },
    { "crl_none: CRL_CHECK_ALL on the ctx, partial chain",
      "int2", NULL, NULL, "server-int", NULL,
      VO_C_CRL_ALL | VO_PARTIAL, VA_NOCRL, 1, VE_NOCRL, 0, NULL,
      { VE_NOCRL, 0, VE_NOCRL, 1 } },
    /* As OpenSSL, a self-signed anchor has its own CRLs */
    { "crl_none: CRL_CHECK_ALL on the ctx, anchor",
      "ca", NULL, NULL, "server", NULL,
      VO_C_CRL_ALL, VA_NOCRL, 1, VE_NOCRL, 0, NULL,
      { VE_NOCRL, 0, VE_NOCRL, 1 } },
    { "crl_none: CRL_CHECK on the ctx, the anchor alone",
      "ca", NULL, NULL, "ca", NULL,
      VO_C_CRL, 0, 0, VE_NOCRL, 0, NULL, { 0 } },

#ifdef HAVE_CRL
    /* The store's CRLs are checked for a cert out of date now but valid at
     * the verification time. dated-root-crl revokes expired-int. */
    { "crl_dates: no CRL check",
      "dated-root", NULL, NULL, "expired-int", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_dates: no CRL",
      "dated-root", NULL, NULL, "expired-int", NULL,
      VO_T2015 | VO_CRL, 0, 0, VE_NOCRL, 0, NULL, { 0 } },
    { "crl_dates: revoked",
      "dated-root", NULL, NULL, "expired-int", "dated-root",
      VO_T2015 | VO_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    /* Out of date now: revoked first, then the date error */
    { "crl_dates: dates accepted",
      "dated-root", NULL, NULL, "expired-int", "dated-root",
      VO_CRL, VA_DATES, 0, VE_REVOKED, 0, NULL, { VE_REVOKED, 0 } },
    { "crl_dates: callback accepts",
      "dated-root", NULL, NULL, "expired-int", "dated-root",
      VO_CRL, VA_ALL, 1, VE_EXPIRED, 0, NULL,
      { VE_REVOKED, 0, VE_EXPIRED, 0 } },
    { "crl_dates: CRL of X509_STORE_CTX_set0_crls",
      "dated-root", NULL, NULL, "expired-int", "dated-root-empty +dated-root",
      VO_CRL, VA_DATES, 0, VE_REVOKED, 0, NULL, { VE_REVOKED, 0 } },
    /* As in OpenSSL, the flag on the ctx turns on the check */
    { "crl_dates: CRL_CHECK on the ctx, revoked",
      "dated-root", NULL, NULL, "expired-int", "+dated-root",
      VO_T2015 | VO_C_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_dates: CRL_CHECK on the ctx, no CRL",
      "dated-root", NULL, NULL, "expired-int", NULL,
      VO_T2015 | VO_C_CRL, 0, 0, VE_NOCRL, 0, NULL, { 0 } },
    { "crl_dates: CRL_CHECK on the ctx, xmlsec param, revoked",
      "dated-root", NULL, NULL, "expired-int", "+dated-root",
      VO_XMLSEC | VO_T2015 | VO_C_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_dates: CRL_CHECK on the ctx, not revoked",
      "dated-root", NULL, NULL, "expired-int", "+dated-root-empty",
      VO_T2015 | VO_C_CRL_ALL, 0, 1, VE_OK, 0, NULL, { 0 } },
    /* A CRL whose signature does not verify is not used: its error is
     * final. Once the callback accepts it, OpenSSL takes its entries:
     * VE_REVOKED, accepted. */
    { "crl_dates: bad CRL signature",
      "dated-root", NULL, NULL, "expired-int", "+dated-root-badsig",
      VO_T2015 | VO_CRL, 0, 0, VE_CRLSIG, 0, NULL, { 0 } },
    { "crl_dates: bad CRL signature, callback accepts",
      "dated-root", NULL, NULL, "expired-int", "+dated-root-badsig",
      VO_T2015 | VO_CRL, VA_ALL, 0, VE_CRLSIG, 0, NULL, { VE_CRLSIG, 0 } },
#endif
#ifdef X509_VFY_GEN_CRLS
    /* A stale CRL is reported. As in OpenSSL, once that is accepted its
     * entries are still checked. A current CRL of the ctx is used over a
     * stale one of the store. ca-stale and ca-revoked list server. */
    { "crl_stale: stale CRL",
      "ca", NULL, NULL, "server", "ca-stale",
      VO_CRL, 0, 0, VE_CRLEXP, 0, NULL, { 0 } },
    { "crl_stale: stale CRL, callback accepts it",
      "ca", NULL, NULL, "server", "ca-stale",
      VO_CRL, VA_CRLEXP, 0, VE_REVOKED, 0, NULL,
      { VE_CRLEXP, 0, VE_REVOKED, 0 } },
    { "crl_stale: stale CRL without the cert, callback accepts it",
      "ca", NULL, NULL, "server", "ca-stale-empty",
      VO_CRL, VA_CRLEXP, 1, VE_CRLEXP, 0, NULL, { VE_CRLEXP, 0 } },
    { "crl_stale: current CRL of the ctx",
      "ca", NULL, NULL, "server", "ca-stale-empty +ca-revoked",
      VO_CRL, VA_CRLEXP, 0, VE_REVOKED, 0, NULL, { VE_REVOKED, 0 } },
    { "crl_stale: current CRL of the ctx without the cert",
      "ca", NULL, NULL, "server", "ca-stale +ca-empty",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    /* X509_V_FLAG_NO_CHECK_TIME skips the dates of CRLs too */
    { "crl_stale: stale CRL, no time check",
      "ca", NULL, NULL, "server", "ca-stale",
      VO_CRL | VO_NOTIME, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_stale: stale CRL without the cert, no time check",
      "ca", NULL, NULL, "server", "ca-stale-empty",
      VO_CRL | VO_NOTIME, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_stale: stale CRL of the ctx, no time check on the store",
      "ca", NULL, NULL, "server", "+ca-stale",
      VO_C_CRL | VO_S_NOTIME, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    /* As OpenSSL, the dates of a CRL before its signature */
    { "crl_stale: stale CRL with a bad signature",
      "ca", NULL, NULL, "server", "ca-stale-empty-badsig",
      VO_CRL, 0, 0, VE_CRLEXP, 0, NULL, { 0 } },
    { "crl_stale: stale CRL with a bad signature, callback accepts it",
      "ca", NULL, NULL, "server", "ca-stale-empty-badsig",
      VO_CRL, VA_CRLEXP, 0, VE_CRLSIG, 0, NULL,
      { VE_CRLEXP, 0, VE_CRLSIG, 0 } },
    /* As OpenSSL, the CRLs of the ctx are used over the store's, which are
     * not looked at */
    { "crl_stale: current CRL of the ctx, the store's revokes",
      "ca", NULL, NULL, "server", "ca-revoked +ca-empty",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_stale: current CRL of the ctx, the store's does not verify",
      "ca", NULL, NULL, "server", "ca-empty-badsig +ca-empty",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_stale: stale CRL of the ctx, the store's revokes",
      "ca", NULL, NULL, "server", "ca-revoked +ca-stale-empty",
      VO_CRL, VA_CRLEXP, 1, VE_CRLEXP, 0, NULL, { VE_CRLEXP, 0 } },
    { "crl_stale: CRL of the store not yet valid",
      "ca", NULL, NULL, "server", "ca-nyv-empty",
      VO_CRL, 0, 0, VE_CRLNYV, 0, NULL, { 0 } },
    { "crl_stale: CRL of the store not yet valid, current one of the ctx",
      "ca", NULL, NULL, "server", "ca-nyv-empty +ca-empty",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    /* Not yet valid over expired, as OpenSSL takes the CRL of the latest
     * thisUpdate */
    { "crl_stale: CRLs of the ctx expired and not yet valid",
      "ca", NULL, NULL, "server", "+ca-stale-empty +ca-nyv-empty",
      VO_CRL, 0, 0, VE_CRLNYV, 0, NULL, { 0 } },
    { "crl_stale: CRLs of the ctx not yet valid and expired",
      "ca", NULL, NULL, "server", "+ca-nyv-empty +ca-stale-empty",
      VO_CRL, 0, 0, VE_CRLNYV, 0, NULL, { 0 } },

    /* As OpenSSL's get_crl_sk(), only the best CRL is checked: a current
     * one, then the latest. ca-otherkey has the name of ca, no AKID and
     * another key: its signature fails. The -old CRLs are a day older. */
    { "crl_pick: older CRL of another key",
      "ca", NULL, NULL, "server", "ca-otherkey-old ca-empty",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_pick: older CRL of another key, added last",
      "ca", NULL, NULL, "server", "ca-empty ca-otherkey-old",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_pick: newer CRL of another key",
      "ca", NULL, NULL, "server", "ca-otherkey ca-empty-old",
      VO_CRL, 0, 0, VE_CRLSIG, 0, NULL, { 0 } },
    { "crl_pick: newer CRL of another key, added last",
      "ca", NULL, NULL, "server", "ca-empty-old ca-otherkey",
      VO_CRL, 0, 0, VE_CRLSIG, 0, NULL, { 0 } },
    { "crl_pick: older CRL of another key, ctx",
      "ca", NULL, NULL, "server", "+ca-otherkey-old +ca-empty",
      VO_C_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_pick: older CRL of another key, ctx, last",
      "ca", NULL, NULL, "server", "+ca-empty +ca-otherkey-old",
      VO_C_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_pick: newer CRL of another key, ctx",
      "ca", NULL, NULL, "server", "+ca-otherkey +ca-empty-old",
      VO_C_CRL, 0, 0, VE_CRLSIG, 0, NULL, { 0 } },
    { "crl_pick: newer CRL of another key, ctx, last",
      "ca", NULL, NULL, "server", "+ca-empty-old +ca-otherkey",
      VO_C_CRL, 0, 0, VE_CRLSIG, 0, NULL, { 0 } },
    { "crl_pick: current CRL over a newer one not yet valid",
      "ca", NULL, NULL, "server", "ca-revoked ca-nyv-empty",
      VO_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_pick: current CRL over a newer one not yet valid, ctx",
      "ca", NULL, NULL, "server", "+ca-nyv-empty +ca-revoked",
      VO_C_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_pick: same thisUpdate, the first",
      "ca", NULL, NULL, "server", "ca-revoked ca-empty",
      VO_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_pick: same thisUpdate, the first, other order",
      "ca", NULL, NULL, "server", "ca-empty ca-revoked",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_pick: same thisUpdate, the first, ctx",
      "ca", NULL, NULL, "server", "+ca-revoked +ca-empty",
      VO_C_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_pick: same thisUpdate, the first, ctx, other order",
      "ca", NULL, NULL, "server", "+ca-empty +ca-revoked",
      VO_C_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },

    /* As OpenSSL, a self-signed anchor has its own CRLs: checked with
     * X509_V_FLAG_CRL_CHECK_ALL, or as the leaf. ca-self lists ca. */
    { "crl_anchor: anchor revoked",
      "ca", NULL, NULL, "server", "ca-self",
      VO_CRL_ALL, 0, 0, VE_REVOKED, 1, NULL, { 0 } },
    { "crl_anchor: anchor revoked, CRL_CHECK_ALL on the ctx",
      "ca", NULL, NULL, "server", "+ca-self",
      VO_C_CRL_ALL, 0, 0, VE_REVOKED, 1, NULL, { 0 } },
    { "crl_anchor: anchor revoked, only the leaf checked",
      "ca", NULL, NULL, "server", "ca-self",
      VO_CRL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "crl_anchor: anchor revoked, the leaf",
      "ca", NULL, NULL, "ca", "ca-self",
      VO_CRL, 0, 0, VE_REVOKED, 0, NULL, { 0 } },
    { "crl_anchor: anchor not revoked",
      "ca", NULL, NULL, "server", "ca-empty",
      VO_CRL_ALL, 0, 1, VE_OK, 0, NULL, { 0 } },
#endif

    /* The error is reported at the CA whose path length is exceeded:
     * pl0-int, of pathlen:0, issued the CA pl0-sub */
    { "path_len: trusted CA",
      "ca pl0-int", NULL, "pl0-sub", "pl0-leaf", NULL,
      0, 0, 0, VE_PATHLEN, 2, NULL, { 0 } },
    { "path_len: untrusted CA",
      "ca", NULL, "pl0-int pl0-sub", "pl0-leaf", NULL,
      0, 0, 0, VE_PATHLEN, 2, NULL, { 0 } },
    { "path_len: callback accepts",
      "ca", NULL, "pl0-int pl0-sub", "pl0-leaf", NULL,
      0, VA_ALL, 1, VE_PATHLEN, 0, "pl0-leaf pl0-sub pl0-int ca",
      { VE_PATHLEN, 2 } },
    { "path_len: partial chain",
      "pl0-int", NULL, "pl0-sub", "pl0-leaf", NULL,
      VO_PARTIAL, VA_ALL, 1, VE_PATHLEN, 0, "pl0-leaf pl0-sub pl0-int",
      { VE_PATHLEN, 2 } },

#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
#ifdef WOLFSSL_SIGNER_DER_CERT
    /* With X509_V_FLAG_TRUSTED_FIRST the trusted dated-int of an SSL_CTX is
     * taken over an untrusted twin out of date, then its issuer there */
    { "ctx_store_twin: only the root trusted",
      "dated-root", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "ctx_store_twin: trusted twin",
      "dated-root dated-int", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_SSLCTX, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int dated-root", { 0 } },
    { "ctx_store_twin: trusted twin, 2005",
      "dated-root dated-int", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_SSLCTX | VO_T2005, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int dated-root", { 0 } },
    { "ctx_store_twin: trusted twin, 2015",
      "dated-root dated-int", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_SSLCTX | VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int dated-root", { 0 } },
    { "ctx_store_twin: untrusted first",
      "dated-root dated-int", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_SSLCTX | VO_XMLSEC, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    /* A CA of an SSL_CTX is a trusted cert: it goes on the chain, then its
     * issuer there, each checked as in a store: pl0-int, of pathlen:0, may
     * not issue the CA pl0-sub, and a CA:FALSE root may not issue */
    { "ctx_store_ca: path length",
      "ca pl0-int", NULL, "pl0-sub", "pl0-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_PATHLEN, 2, NULL, { 0 } },
    { "ctx_store_ca: path length, callback accepts",
      "ca pl0-int", NULL, "pl0-sub", "pl0-leaf", NULL,
      VO_SSLCTX, VA_ALL, 1, VE_PATHLEN, 0, NULL, { VE_PATHLEN, 2 } },
    { "ctx_store_ca: CA:FALSE root",
      "notca-root", NULL, NULL, "notca-root-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_CA, 1, NULL, { 0 } },
    { "ctx_store_ca: path length of the root of a trusted CA",
      "ca pl0-sub pl0-int", NULL, NULL, "pl0-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_PATHLEN, 2, NULL, { 0 } },
    { "ctx_store_ca: expired root of a trusted CA",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, VO_SSLCTX, 0, 0, VE_EXPIRED, 2, NULL, { 0 } },
    { "ctx_store_ca: root of a trusted CA, 2015",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, VO_SSLCTX | VO_T2015, 0, 1, VE_OK, 0,
      "expired-root-int-leaf expired-root-int expired-root", { 0 } },
#ifdef HAVE_CRL
    { "ctx_store_ca: root revokes a trusted CA",
      "dated-root expired-int", NULL, NULL, "dated-int-leaf",
      "dated-root int", VO_SSLCTX | VO_T2015 | VO_CRL_ALL, 0, 0,
      VE_REVOKED, 1, NULL, { 0 } },
#endif
    /* wolfSSL trusts a CA of an SSL_CTX without its issuer there, as its
     * handshake does. OpenSSL: VE_ISSUER at depth 2. */
    { "ctx_store_ca: CA without its root",
      "int1", NULL, "int2", "server-int", NULL,
      VO_SSLCTX, 0, 1, VE_OK, 0, "server-int int2 int1", { 0 } },
    /* That CA is the trust anchor: it does not count against the depth,
     * as the anchor of a partial chain in OpenSSL. OpenSSL, without the
     * root: VE_LONG at depth 1 and 2 where these verify. */
    { "ctx_store_ca: CA without its root, depth 0",
      "int2", NULL, NULL, "server-int", NULL,
      VO_SSLCTX | VO_DEPTH0, 0, 1, VE_OK, 0, "server-int int2", { 0 } },
    { "ctx_store_ca: CA without its root, intermediate, depth 0",
      "int1", NULL, "int2", "server-int", NULL,
      VO_SSLCTX | VO_DEPTH0, 0, 0, VE_LONG, 1, NULL, { 0 } },
    { "ctx_store_ca: CA without its root, intermediate, depth 1",
      "int1", NULL, "int2", "server-int", NULL,
      VO_SSLCTX | VO_DEPTH1, 0, 1, VE_OK, 0, "server-int int2 int1",
      { 0 } },
#else
    /* Without its DER a CA of an SSL_CTX cannot go on the chain: the cert
     * it issued has no issuer */
    { "ctx_store_ca: CA without DER",
      "ca pl0-int", NULL, "pl0-sub", "pl0-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_LOCAL, 1, NULL, { 0 } },
#endif
#endif

    /* An untrusted intermediate is date checked when verified, at the
     * verification time, and one valid then is chosen first. expired-int is
     * valid from 2010 to 2019, dated-int is the same CA valid until 2049. */
    { "untrusted_dates: expired",
      "dated-root", NULL, "expired-int", "dated-int-leaf", NULL,
      0, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "untrusted_dates: 2015",
      "dated-root", NULL, "expired-int", "dated-int-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "untrusted_dates: callback accepts",
      "dated-root", NULL, "expired-int", "dated-int-leaf", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, "dated-int-leaf expired-int dated-root",
      { VE_EXPIRED, 1 } },
#ifdef HAVE_CRL
    /* The store's CRLs are checked for it too, dated-root-crl revokes it */
    { "untrusted_dates: revoked",
      "dated-root", NULL, "expired-int", "dated-int-leaf", "dated-root int",
      VO_T2015 | VO_CRL_ALL, 0, 0, VE_REVOKED, 1, NULL, { 0 } },
    { "untrusted_dates: callback accepts revoked",
      "dated-root", NULL, "expired-int", "dated-int-leaf", "dated-root int",
      VO_T2015 | VO_CRL_ALL, VA_ALL, 1, VE_REVOKED, 0,
      "dated-int-leaf expired-int dated-root", { VE_REVOKED, 1 } },
    /* Out of date now: revoked first, then the date error */
    { "untrusted_dates: revoked, dates accepted",
      "dated-root", NULL, "expired-int", "dated-int-leaf", "dated-root int",
      VO_CRL_ALL, VA_DATES, 0, VE_REVOKED, 1, NULL, { VE_REVOKED, 1 } },
    { "untrusted_dates: callback accepts revoked and expired",
      "dated-root", NULL, "expired-int", "dated-int-leaf", "dated-root int",
      VO_CRL_ALL, VA_ALL, 1, VE_EXPIRED, 0, NULL,
      { VE_REVOKED, 1, VE_EXPIRED, 1 } },
#endif
    { "untrusted_dates: valid twin chosen",
      "dated-root", NULL, "expired-int dated-int", "dated-int-leaf", NULL,
      0, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root", { 0 } },
    /* With X509_V_FLAG_TRUSTED_FIRST a trusted issuer is taken first, also
     * one out of date */
    { "untrusted_dates: trusted twin out of date",
      "dated-root expired-int", NULL, "expired-int dated-int",
      "dated-int-leaf", NULL,
      0, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "untrusted_dates: trusted twin out of date, 2015",
      "dated-root expired-int", NULL, "expired-int dated-int",
      "dated-int-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "untrusted_dates: trusted twin out of date, untrusted first",
      "dated-root expired-int", NULL, "expired-int dated-int",
      "dated-int-leaf", NULL,
      VO_XMLSEC, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root",
      { 0 } },
    /* The top of a partial chain is not date checked */
    { "untrusted_dates: top of a partial chain",
      NULL, NULL, "expired-int", "dated-int-leaf", NULL,
      0, VA_LOCAL, 1, VE_LOCAL, 0, NULL, { VE_LOCAL, 1 } },
    /* Unless it is a lone leaf */
    { "untrusted_dates: lone leaf",
      NULL, NULL, NULL, "expired-int", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, "expired-int",
      { VE_LOCAL, 0, VE_LEAFSIG, 0, VE_EXPIRED, 0 } },
    /* With an untrusted issuer above it, it is date checked. A rejection is
     * final. */
    { "untrusted_dates: untrusted issuer above",
      NULL, NULL, "expired-int cross-root", "dated-int-leaf", NULL,
      0, VA_LOCAL, 0, VE_EXPIRED, 1, NULL,
      { VE_LOCAL, 2, VE_EXPIRED, 1 } },
    /* Also with a trusted issuer above that the cert manager does not find:
     * badkid-int names nokid-root by a key id that does not match */
    { "untrusted_dates: trusted issuer by name",
      "nokid-root", NULL, "badkid-int", "badkid-int-leaf", NULL,
      0, VA_LOCAL, 0, VE_EXPIRED, 1, NULL, { VE_EXPIRED, 1 } },
    { "untrusted_dates: trusted issuer by name, 2015",
      "nokid-root", NULL, "badkid-int", "badkid-int-leaf", NULL,
      VO_T2015, VA_LOCAL, 1, VE_OK, 0,
      "badkid-int-leaf badkid-int nokid-root", { 0 } },
    { "untrusted_dates: top of a partial chain, partial chain flag",
      NULL, NULL, "expired-int", "dated-int-leaf", NULL,
      VO_PARTIAL, VA_LOCAL, 0, VE_EXPIRED, 1, NULL,
      { VE_LOCAL, 1, VE_EXPIRED, 1 } },
    /* A trusted one that ends a partial chain */
    { "untrusted_dates: trusted, partial chain",
      "expired-int", NULL, NULL, "dated-int-leaf", NULL,
      VO_PARTIAL, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "untrusted_dates: trusted, partial chain, 2015",
      "expired-int", NULL, NULL, "dated-int-leaf", NULL,
      VO_PARTIAL | VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "untrusted_dates: trusted with its root, partial chain",
      "expired-int dated-root", NULL, NULL, "dated-int-leaf", NULL,
      VO_PARTIAL, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    /* Also when the depth limit ends the chain at it */
    { "untrusted_dates: trusted with its root, partial chain, depth 0",
      "expired-int dated-root", NULL, NULL, "dated-int-leaf", NULL,
      VO_PARTIAL | VO_DEPTH0, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },

    /* A store of its own takes a trusted cert that is out of date. Its dates
     * are checked at the verification time. */
    { "add_cert_expired: expired root",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      0, 0, 0, VE_EXPIRED, 1, NULL, { 0 } },
    { "add_cert_expired: 2005",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2005, 0, 0, VE_NOTYET, 1, NULL, { 0 } },
    { "add_cert_expired: 2015",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: callback accepts",
      "expired-root", NULL, NULL, "expired-root-leaf", NULL,
      0, VA_ALL, 1, VE_EXPIRED, 0, NULL, { VE_EXPIRED, 1 } },
    /* A valid root of the same name with a new key does not hide it. Nor is
     * it the anchor of a leaf it did not sign: renewed-root signed
     * renewed-root-leaf and is valid from 2020. Both orders. In 2015
     * expired-root, valid then, is taken by name for renewed-root-leaf:
     * VE_SIG at depth 0. */
    { "add_cert_expired: renewed root first",
      "renewed-root expired-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: renewed root first, renewed leaf",
      "renewed-root expired-root", NULL, NULL, "renewed-root-leaf", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: renewed root first, renewed leaf, 2015",
      "renewed-root expired-root", NULL, NULL, "renewed-root-leaf", NULL,
      VO_T2015, 0, 0, VE_SIG, 0, "renewed-root-leaf expired-root", { 0 } },
    { "add_cert_expired: renewed root last",
      "expired-root renewed-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: renewed root last, renewed leaf",
      "expired-root renewed-root", NULL, NULL, "renewed-root-leaf", NULL,
      0, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: renewed root last, renewed leaf, 2015",
      "expired-root renewed-root", NULL, NULL, "renewed-root-leaf", NULL,
      VO_T2015, 0, 0, VE_SIG, 0, "renewed-root-leaf expired-root", { 0 } },
    /* A root not yet valid when added anchors a chain once valid */
    { "add_cert_expired: root added in 1999",
      "dated-root", NULL, NULL, "dated-int", NULL,
      VO_ADD1999, 0, 1, VE_OK, 0, NULL, { 0 } },
    /* A trusted root comes before an untrusted cross-signed copy of it */
    { "add_cert_expired: trusted root before cross-root",
      "dated-root expired-root", NULL, "dated-int cross-root",
      "dated-int-leaf", NULL,
      0, 0, 1, VE_OK, 0, "dated-int-leaf dated-int dated-root", { 0 } },
    /* Of two roots with the same name and key, the anchor is the one valid
     * at the verification time: dated-root-late is valid from 2020 */
    { "add_cert_expired: late twin of the root",
      "dated-root-late dated-root", NULL, "dated-int", "dated-int-leaf",
      NULL, VO_T2015, 0, 1, VE_OK, 0,
      "dated-int-leaf dated-int dated-root", { 0 } },
    /* With a trusted stack the store's certs are not used */
    { "add_cert_expired: stack without the root",
      "expired-root", "expired-root-int", NULL, "expired-root-int-leaf",
      NULL, 0, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    { "add_cert_expired: stack without the root, 2015",
      "expired-root", "expired-root-int", NULL, "expired-root-int-leaf",
      NULL, VO_T2015, 0, 0, VE_ISSUER, 1, NULL, { 0 } },
    /* Nor does it end a chain whose missing issuer the callback accepts */
    { "add_cert_expired: stack without the root, callback accepts",
      "expired-root", "expired-root-int", NULL, "expired-root-int-leaf",
      NULL, 0, VA_ALL, 1, VE_ISSUER, 0,
      "expired-root-int-leaf expired-root-int", { VE_ISSUER, 1 } },
    /* Nor does a root of the missing issuer's name with another key:
     * renewed-root did not sign cross-root. It is not valid in 2015 either. */
    { "add_cert_expired: renewed root not the issuer",
      "renewed-root", NULL, "dated-int cross-root", "dated-int-leaf", NULL,
      VO_T2015, VA_ALL, 1, VE_LOCAL, 0,
      "dated-int-leaf dated-int cross-root", { VE_LOCAL, 2 } },
    /* Nor for a lone leaf, whose signature is then reported unverified */
    { "add_cert_expired: renewed root, lone leaf",
      "renewed-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, VA_ALL, 1, VE_LEAFSIG, 0, "expired-root-leaf",
      { VE_LOCAL, 0, VE_LEAFSIG, 0 } },
    { "add_cert_expired: renewed root, lone leaf, missing issuer accepted",
      "renewed-root", NULL, NULL, "expired-root-leaf", NULL,
      VO_T2015, VA_LOCAL, 0, VE_LEAFSIG, 0, NULL,
      { VE_LOCAL, 0, VE_LEAFSIG, 0 } },
    /* With X509_V_FLAG_PARTIAL_CHAIN the first trusted cert ends the chain.
     * The root above it is not used. */
    { "add_cert_expired: trusted intermediate",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, 0, 0, 0, VE_EXPIRED, 2, NULL, { 0 } },
    { "add_cert_expired: trusted intermediate in a stack",
      NULL, "expired-root-int expired-root", NULL, "expired-root-int-leaf",
      NULL, 0, 0, 0, VE_EXPIRED, 2, NULL, { 0 } },
    { "add_cert_expired: trusted intermediate, partial chain",
      "expired-root expired-root-int", NULL, NULL, "expired-root-int-leaf",
      NULL, VO_PARTIAL, 0, 1, VE_OK, 0,
      "expired-root-int-leaf expired-root-int", { 0 } },
    { "add_cert_expired: trusted intermediate in a stack, partial chain",
      NULL, "expired-root-int expired-root", NULL, "expired-root-int-leaf",
      NULL, VO_PARTIAL, 0, 1, VE_OK, 0, NULL, { 0 } },
    { "add_cert_expired: renewed root not the issuer, partial chain",
      "renewed-root", NULL, "dated-int cross-root", "dated-int-leaf", NULL,
      VO_T2015 | VO_PARTIAL, VA_ALL, 1, VE_LOCAL, 0,
      "dated-int-leaf dated-int cross-root", { VE_LOCAL, 2 } },

    /* An untrusted self-signed cert issues a cert that no other cert
     * issues. It ends the chain as VE_SELF. */
    { "untrusted_root: self-signed in the chain",
      NULL, NULL, "dated-root", "dated-int", NULL,
      0, 0, 0, VE_SELF, 1, NULL, { 0 } },
    { "untrusted_root: missing issuer accepted",
      NULL, NULL, "dated-root", "dated-int", NULL,
      0, VA_LOCAL, 0, VE_SELF, 1, NULL, { VE_SELF, 1 } },
    { "untrusted_root: callback accepts",
      NULL, NULL, "dated-root", "dated-int", NULL,
      0, VA_SELF | VA_ISSUER | VA_LOCAL, 1, VE_SELF, 0,
      "dated-int dated-root", { VE_SELF, 1 } },
    { "untrusted_root: untrusted first",
      NULL, NULL, "dated-root", "dated-int", NULL,
      VO_XMLSEC, 0, 0, VE_SELF, 1, NULL, { 0 } },
    { "untrusted_root: partial chain",
      NULL, NULL, "dated-root", "dated-int", NULL,
      VO_PARTIAL, 0, 0, VE_SELF, 1, NULL, { 0 } },
    { "untrusted_root: trusted",
      "dated-root", NULL, "dated-root", "dated-int", NULL,
      0, 0, 1, VE_OK, 0, "dated-int dated-root", { 0 } },
    /* A trusted leaf ends a partial chain without a trusted cert, as
     * OpenSSL's last resort, also above a self-signed cert */
    { "untrusted_root: trusted leaf",
      "dated-int", NULL, "dated-root", "dated-int", NULL,
      0, 0, 0, VE_SELF, 1, NULL, { 0 } },
    { "untrusted_root: trusted leaf, partial chain",
      "dated-int", NULL, "dated-root", "dated-int", NULL,
      VO_PARTIAL, 0, 1, VE_OK, 0, "dated-int dated-root", { 0 } },

    /* A trusted self-issued cert that is not self-signed is not a root.
     * expired-root-link has expired-root's name and a new key. The chain
     * goes on to expired-root, out of date now, and its dates are checked at
     * the verification time. */
    { "selfissued_dates: link as the leaf",
      "expired-root", NULL, NULL, "expired-root-link", NULL,
      0, 0, 0, VE_EXPIRED, 1, "expired-root-link expired-root", { 0 } },
    { "selfissued_dates: link as the leaf, 2005",
      "expired-root", NULL, NULL, "expired-root-link", NULL,
      VO_T2005, 0, 0, VE_NOTYET, 1, NULL, { 0 } },
    { "selfissued_dates: link as the leaf, 2015",
      "expired-root", NULL, NULL, "expired-root-link", NULL,
      VO_T2015, 0, 1, VE_OK, 0, "expired-root-link expired-root", { 0 } },
    { "selfissued_dates: link trusted, 2015",
      "expired-root expired-root-link", NULL, NULL,
      "expired-root-link-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0,
      "expired-root-link-leaf expired-root-link expired-root", { 0 } },
    { "selfissued_dates: link trusted",
      "expired-root expired-root-link", NULL, NULL,
      "expired-root-link-leaf", NULL,
      0, 0, 0, VE_EXPIRED, 2, NULL, { 0 } },
    /* A valid root of the name without key ids did not sign the link. It is
     * taken by name as it is valid now: VE_SIG at depth 1. */
    { "selfissued_dates: valid nokid twin of the root",
      "expired-root expired-root-link expired-root-nokid", NULL, NULL,
      "expired-root-link-leaf", NULL,
      0, 0, 0, VE_SIG, 1,
      "expired-root-link-leaf expired-root-link expired-root-nokid",
      { 0 } },
    { "selfissued_dates: valid nokid twin of the root, 2015",
      "expired-root expired-root-link expired-root-nokid", NULL, NULL,
      "expired-root-link-leaf", NULL,
      VO_T2015, 0, 1, VE_OK, 0,
      "expired-root-link-leaf expired-root-link expired-root", { 0 } },
    /* Alone, the link out of date ends a partial chain the callback
     * accepts. Its dates are not checked then. */
    { "selfissued_dates: old link alone",
      "expired-root-old-link", NULL, NULL, "expired-root-link-leaf", NULL,
      0, VA_ALL, 1, VE_ISSUER, 0, NULL, { VE_ISSUER, 1 } },
#endif

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(IGNORE_NAME_CONSTRAINTS)
    /* The names of every cert meet the name constraints of the certs above
     * it, the anchor's too: nc-ca permits only the email addresses of
     * .wolfssl.com */
    { "name_constraints: email permitted",
      "nc-ca", NULL, NULL, "nc-leaf", NULL,
      0, 0, 1, VE_OK, 0, "nc-leaf nc-ca", { 0 } },
    { "name_constraints: email not permitted",
      "nc-ca", NULL, NULL, "nc-leaf-bad", NULL,
      0, 0, 0, VE_NCPERM, 0, NULL, { 0 } },
    { "name_constraints: callback accepts",
      "nc-ca", NULL, NULL, "nc-leaf-bad", NULL,
      0, VA_ALL, 1, VE_NCPERM, 0, "nc-leaf-bad nc-ca", { VE_NCPERM, 0 } },
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_SIGNER_DER_CERT)
    { "name_constraints: CA of an SSL_CTX",
      "nc-ca", NULL, NULL, "nc-leaf-bad", NULL,
      VO_SSLCTX, VA_ALL, 1, VE_NCPERM, 0, "nc-leaf-bad nc-ca",
      { VE_NCPERM, 0 } },
#endif
    /* The CN of the leaf, CA or not, meets the DNS constraints when it has
     * no dNSName SAN: ncdns-ca permits .example.com but .blocked.example.com */
    { "name_constraints: CA leaf CN permitted",
      "ncdns-ca", NULL, NULL, "ncdns-leaf", NULL,
      0, 0, 1, VE_OK, 0, "ncdns-leaf ncdns-ca", { 0 } },
    { "name_constraints: CA leaf CN not permitted",
      "ncdns-ca", NULL, NULL, "ncdns-leaf-bad", NULL,
      0, 0, 0, VE_NCPERM, 0, NULL, { 0 } },
    { "name_constraints: CA leaf CN excluded",
      "ncdns-ca", NULL, NULL, "ncdns-leaf-excl", NULL,
      0, 0, 0, VE_NCEXCL, 0, NULL, { 0 } },
#endif

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
    /* Without X509_V_FLAG_TRUSTED_FIRST the untrusted twin-bad, a CA without
     * keyCertSign, issues the leaf. twin-good is the same CA, trusted, with
     * keyCertSign. Once the callback accepts VE_CA, VE_CERTSIGN is reported
     * at depth 1, so a callback that accepts VE_CA only rejects. */
    { "no_keycertsign: callback accepts",
      "ca twin-good", NULL, "twin-bad", "twin-leaf", NULL,
      VO_XMLSEC, VA_ALL, 1, VE_CERTSIGN, 0, "twin-leaf twin-bad ca",
      { VE_CA, 1, VE_CERTSIGN, 1 } },
    { "no_keycertsign: callback accepts VE_CA only",
      "ca twin-good", NULL, "twin-bad", "twin-leaf", NULL,
      VO_XMLSEC, VA_CA, 0, VE_CERTSIGN, 1, "twin-leaf twin-bad ca",
      { VE_CA, 1, VE_CERTSIGN, 1 } },
#ifdef X509_VFY_GEN_CRLS
    /* nocrlsign has keyUsage keyCertSign only. Its CRL nocrlsign-revoked,
     * listing nocrlsign-leaf, is reported. As in OpenSSL, once that is
     * accepted, the CRL is used. */
    { "crl_sign: issuer without cRLSign",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "+nocrlsign-revoked",
      VO_C_CRL, 0, 0, VE_CRLKU, 0, NULL, { 0 } },
    { "crl_sign: callback accepts a missing CRL",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "+nocrlsign-revoked",
      VO_C_CRL, VA_NOCRL, 0, VE_CRLKU, 0, NULL, { VE_CRLKU, 0 } },
    { "crl_sign: callback accepts it",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "+nocrlsign-revoked",
      VO_C_CRL, VA_CRLKU, 0, VE_REVOKED, 0, NULL,
      { VE_CRLKU, 0, VE_REVOKED, 0 } },
    { "crl_sign: callback accepts it, store CRLs",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "ca-empty nocrlsign-revoked",
      VO_CRL_ALL, VA_CRLKU, 0, VE_REVOKED, 0, NULL,
      { VE_CRLKU, 0, VE_REVOKED, 0 } },
    /* As OpenSSL's check_crl(), cRLSign before the CRL dates */
    { "crl_sign: stale CRL",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "+nocrlsign-stale-empty",
      VO_C_CRL, 0, 0, VE_CRLKU, 0, NULL, { 0 } },
    { "crl_sign: stale CRL, callback accepts both, store CRLs",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf",
      "ca-empty nocrlsign-stale-empty",
      VO_CRL_ALL, VA_CRLKU | VA_CRLEXP, 1, VE_CRLEXP, 0, NULL,
      { VE_CRLKU, 0, VE_CRLEXP, 0 } },
    { "crl_sign: stale CRL, callback accepts both",
      "ca", NULL, "nocrlsign", "nocrlsign-leaf", "+nocrlsign-stale-empty",
      VO_C_CRL, VA_CRLKU | VA_CRLEXP, 1, VE_CRLEXP, 0, NULL,
      { VE_CRLKU, 0, VE_CRLEXP, 0 } },
#endif
    /* pl0-notca is not a CA. As in OpenSSL, it counts against the path
     * length of pl0-ca, of pathlen:0, also once its VE_CA is accepted. */
#ifndef WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE
    { "path_len: not a CA, callback accepts VE_CA",
      "ca", NULL, "pl0-ca pl0-notca", "pl0-notca-leaf", NULL,
      0, VA_CA, 0, VE_PATHLEN, 2, NULL, { VE_CA, 1, VE_PATHLEN, 2 } },
#else
    { "path_len: not a CA",
      "ca", NULL, "pl0-ca pl0-notca", "pl0-notca-leaf", NULL,
      0, 0, 0, VE_PATHLEN, 2, NULL, { 0 } },
#endif
#endif

#if defined(WOLFSSL_AKID_NAME) && defined(WOLFSSL_ASN_TEMPLATE) && \
    defined(HAVE_ECC) && !defined(NO_SHA256)
    /* RFC 5280, 4.2.1.1: akid-twin has the name and key of akid-ca but not
     * the serial in the AKID of akid-leaf, so it is not its issuer, as in
     * OpenSSL's X509_check_akid(). akid-leaf-twin names akid-twin. The AKID
     * of akid-leaf-issuer has the serial of akid-ca and another issuer. */
    { "akid_serial: trusted CA of the AKID",
      "akid-root akid-ca", NULL, NULL, "akid-leaf", NULL,
      0, 0, 1, VE_OK, 0, "akid-leaf akid-ca akid-root", { 0 } },
    { "akid_serial: trusted CA of another serial",
      "akid-root akid-twin", NULL, NULL, "akid-leaf", NULL,
      0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    { "akid_serial: trusted CAs of both serials",
      "akid-root akid-twin akid-ca", NULL, NULL, "akid-leaf-twin", NULL,
      0, 0, 1, VE_OK, 0, "akid-leaf-twin akid-twin akid-root", { 0 } },
    { "akid_serial: untrusted CA of another serial",
      "akid-root", NULL, "akid-twin", "akid-leaf", NULL,
      0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    { "akid_serial: untrusted CAs of both serials",
      "akid-root", NULL, "akid-twin akid-ca", "akid-leaf", NULL,
      0, 0, 1, VE_OK, 0, "akid-leaf akid-ca akid-root", { 0 } },
    { "akid_serial: callback accepts",
      "akid-root", NULL, "akid-twin", "akid-leaf", NULL,
      0, VA_ALL, 1, VE_LEAFSIG, 0, "akid-leaf",
      { VE_LOCAL, 0, VE_LEAFSIG, 0 } },
    { "akid_serial: another issuer of the CA",
      "akid-root akid-ca", NULL, NULL, "akid-leaf-issuer", NULL,
      0, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    { "akid_serial: CA of another serial in an SSL_CTX",
      "akid-root akid-twin", NULL, NULL, "akid-leaf", NULL,
      VO_SSLCTX, 0, 0, VE_LOCAL, 0, NULL, { 0 } },
    { "akid_serial: CA of the AKID in an SSL_CTX",
      "akid-root akid-ca", NULL, NULL, "akid-leaf", NULL,
      VO_SSLCTX, 0, 1, VE_OK, 0, NULL, { 0 } },
#endif
#endif
};

/* Files of the names not in TA_CERT_DIR */
static const struct {
    const char* name;
    const char* file;
} x509VfyFiles[] = {
    { "ca",         "./certs/ca-cert.pem" },
    { "int1",       "./certs/intermediate/ca-int-cert.pem" },
    { "int2",       "./certs/intermediate/ca-int2-cert.pem" },
    { "server-int", "./certs/intermediate/server-int-cert.pem" },
    { "server",     "./certs/server-cert.pem" },
    { "ca-ecc",     "./certs/ca-ecc-cert.pem" },
    { "int1-ecc",   "./certs/intermediate/ca-int-ecc-cert.pem" },
    { "int2-ecc",   "./certs/intermediate/ca-int2-ecc-cert.pem" },
    { "server-int-ecc", "./certs/intermediate/server-int-ecc-cert.pem" },
    { "nca-ca",     "./certs/intermediate/ca_false_intermediate/test_ca.pem" },
    { "nca-int",
      "./certs/intermediate/ca_false_intermediate/test_int_not_cacert.pem" },
    { "nca-leaf",
      "./certs/intermediate/ca_false_intermediate/test_sign_bynoca_srv.pem" },
    { "ca-int-crl", "./certs/crl/ca-int.pem" },
    { "nc-ca",      "./certs/test/cert-ext-nc.pem" },
    { "ncdns-ca",   "./certs/test/cert-ext-ncmulti.pem" },
    { "pl0-int",    "./certs/test-pathlen/chainF-ICA2-pathlen0.pem" },
    { "pl0-sub",    "./certs/test-pathlen/chainF-ICA1-pathlen1.pem" },
    { "pl0-leaf",   "./certs/test-pathlen/chainF-entity.pem" },
    { "akid-root",  "./certs/test/akid-serial/root-cert.pem" },
    { "akid-ca",    "./certs/test/akid-serial/ca-cert.pem" },
    { "akid-twin",  "./certs/test/akid-serial/ca-twin-cert.pem" },
    { "akid-leaf",  "./certs/test/akid-serial/leaf-cert.pem" },
    { "akid-leaf-twin", "./certs/test/akid-serial/leaf-twin-cert.pem" },
    { "akid-leaf-issuer", "./certs/test/akid-serial/leaf-issuer-cert.pem" }
};

/* The certs by name, loaded once */
#define X509_VFY_NAME_SZ 32
static struct {
    char name[X509_VFY_NAME_SZ];
    X509* x509;
} x509VfyCerts[128];
static int x509VfyCertsNum = 0;

/* What the verify callback saw */
static int x509VfyAccept;
static struct {
    int err;
    int depth;
    X509* cert;
} x509VfyLog[4];
static int x509VfyLogNum;

/* Copies the next space separated name of *list to name. Returns 0 when
 * there is none. */
static int x509_vfy_next(const char** list, char* name)
{
    const char* p = *list;
    int n = 0;

    if (p == NULL)
        return 0;
    while (*p == ' ')
        p++;
    while (*p != '\0' && *p != ' ' && n < X509_VFY_NAME_SZ - 1)
        name[n++] = *p++;
    name[n] = '\0';
    *list = p;
    return n > 0;
}

/* Writes the file of a cert or CRL name to path */
static void x509_vfy_path(const char* name, const char* suffix, char* path,
    int pathSz)
{
    char base[X509_VFY_NAME_SZ];
    size_t i;
    int n = 0;

    while (name[n] != '\0' && name[n] != '#' && n < X509_VFY_NAME_SZ - 1) {
        base[n] = name[n];
        n++;
    }
    base[n] = '\0';
    for (i = 0; i < XELEM_CNT(x509VfyFiles); i++) {
        if (XSTRCMP(base, x509VfyFiles[i].name) == 0) {
            XSNPRINTF(path, (size_t)pathSz, "%s", x509VfyFiles[i].file);
            return;
        }
    }
    XSNPRINTF(path, (size_t)pathSz, "%s%s%s", TA_CERT_DIR, base, suffix);
}

/* Keeps x509 under name */
static int x509_vfy_keep(const char* name, X509* x509)
{
    if (x509 == NULL || x509VfyCertsNum == (int)XELEM_CNT(x509VfyCerts))
        return 0;
    XSTRNCPY(x509VfyCerts[x509VfyCertsNum].name, name, X509_VFY_NAME_SZ - 1);
    x509VfyCerts[x509VfyCertsNum].name[X509_VFY_NAME_SZ - 1] = '\0';
    x509VfyCerts[x509VfyCertsNum].x509 = x509;
    x509VfyCertsNum++;
    return 1;
}

/* The cert of name, loaded on first use. NULL on failure. */
static X509* x509_vfy_cert(const char* name)
{
    char path[160];
    X509* x509;
    int i;

    for (i = 0; i < x509VfyCertsNum; i++) {
        if (XSTRCMP(x509VfyCerts[i].name, name) == 0)
            return x509VfyCerts[i].x509;
    }
    x509_vfy_path(name, "-cert.pem", path, (int)sizeof(path));
    x509 = X509_load_certificate_file(path, SSL_FILETYPE_PEM);
    if (!x509_vfy_keep(name, x509)) {
        X509_free(x509);
        x509 = NULL;
    }
    return x509;
}

#ifdef X509_VFY_GEN_CRLS
/* Generated CRLs by name, as DER */
static struct {
    char name[X509_VFY_NAME_SZ];
    unsigned char* der;
    int derSz;
} x509VfyCrls[12];
static int x509VfyCrlsNum = 0;

/* A new copy of the generated CRL of name, NULL when there is none */
static X509_CRL* x509_vfy_gen_crl(const char* name)
{
    const unsigned char* p;
    int i;

    for (i = 0; i < x509VfyCrlsNum; i++) {
        if (XSTRCMP(x509VfyCrls[i].name, name) == 0) {
            p = x509VfyCrls[i].der;
            return d2i_X509_CRL(NULL, &p, x509VfyCrls[i].derSz);
        }
    }
    return NULL;
}
#endif

static void x509_vfy_free_certs(void)
{
    int i;

    for (i = 0; i < x509VfyCertsNum; i++)
        X509_free(x509VfyCerts[i].x509);
    x509VfyCertsNum = 0;
#ifdef X509_VFY_GEN_CRLS
    for (i = 0; i < x509VfyCrlsNum; i++)
        XFREE(x509VfyCrls[i].der, NULL, DYNAMIC_TYPE_OPENSSL);
    x509VfyCrlsNum = 0;
#endif
}

/* Pushes the certs of list on sk. Returns 1 on success. */
static int x509_vfy_push(STACK_OF(X509)* sk, const char* list)
{
    char name[X509_VFY_NAME_SZ];
    X509* x509;

    while (x509_vfy_next(&list, name)) {
        if ((x509 = x509_vfy_cert(name)) == NULL ||
                sk_X509_push(sk, x509) <= 0)
            return 0;
    }
    return 1;
}

/* Returns 1 when sk holds the certs of list in order: the same objects when
 * same is set, else equal ones. */
static int x509_vfy_match(STACK_OF(X509)* sk, const char* list, int same)
{
    char name[X509_VFY_NAME_SZ];
    X509* x509;
    X509* x509Sk;
    int i = 0;

    while (x509_vfy_next(&list, name)) {
        if (i >= sk_X509_num(sk) || (x509 = x509_vfy_cert(name)) == NULL)
            return 0;
        x509Sk = sk_X509_value(sk, i);
        if (same ? (x509Sk != x509) : (X509_cmp(x509Sk, x509) != 0))
            return 0;
        i++;
    }
    return i == sk_X509_num(sk);
}

static int x509_vfy_cb(int ok, X509_STORE_CTX* ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    if (!ok) {
        if (x509VfyLogNum < (int)XELEM_CNT(x509VfyLog)) {
            x509VfyLog[x509VfyLogNum].err = err;
            x509VfyLog[x509VfyLogNum].depth =
                X509_STORE_CTX_get_error_depth(ctx);
            x509VfyLog[x509VfyLogNum].cert =
                X509_STORE_CTX_get_current_cert(ctx);
        }
        x509VfyLogNum++;
        ok = (x509VfyAccept & VA_ALL) ||
            ((x509VfyAccept & VA_ISSUER) && err == VE_ISSUER) ||
            ((x509VfyAccept & VA_LOCAL) && err == VE_LOCAL) ||
            ((x509VfyAccept & VA_SELF) &&
                (err == VE_SELF0 || err == VE_SELF)) ||
            ((x509VfyAccept & VA_DATES) &&
                (err == VE_NOTYET || err == VE_EXPIRED)) ||
            ((x509VfyAccept & VA_CA) && err == VE_CA) ||
            ((x509VfyAccept & VA_KEYSIZE) && err == VE_KEYSIZE) ||
            ((x509VfyAccept & VA_NOCRL) && err == VE_NOCRL) ||
            ((x509VfyAccept & VA_CRLKU) && err == VE_CRLKU) ||
            ((x509VfyAccept & VA_CRLEXP) && err == VE_CRLEXP);
    }
    return ok;
}

#ifndef NO_ASN_TIME
/* The current time in 1999, before the dated certs */
static time_t x509_vfy_time_1999(time_t* t)
{
    time_t now = (time_t)915148800;

    if (t != NULL)
        *t = now;
    return now;
}
#endif

/* nca-leaf with a broken signature, as nca-leaf-badsig */
static int x509_vfy_gen_badsig(void)
{
    X509* x509 = x509_vfy_cert("nca-leaf");
    X509* bad = NULL;
    unsigned char* der = NULL;
    const unsigned char* p;
    int derSz;

    if (x509 != NULL && (derSz = i2d_X509(x509, &der)) > 0) {
        der[derSz - 1] ^= 0x01;
        p = der;
        bad = d2i_X509(NULL, &p, derSz);
    }
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    if (!x509_vfy_keep("nca-leaf-badsig", bad)) {
        X509_free(bad);
        return 0;
    }
    return 1;
}

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    ((!defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)) || \
     !defined(IGNORE_NAME_CONSTRAINTS))
/* Keeps the DER cert of der under name */
static int x509_vfy_keep_der(const char* name, const byte* der, int derSz)
{
    X509* x509;

    if (derSz <= 0)
        return 0;
    x509 = d2i_X509(NULL, &der, derSz);
    if (!x509_vfy_keep(name, x509)) {
        X509_free(x509);
        return 0;
    }
    return 1;
}
#endif

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
/* Twin CAs of one name and key issued by ca-cert: twin-good with
 * keyCertSign, twin-bad without. twin-bad issued twin-leaf. Also pl0-ca, of
 * pathlen:0, issued by ca-cert, pl0-notca, not a CA, issued by it, and
 * pl0-notca-leaf. nocrlsign, issued by ca-cert, may sign certs but not
 * CRLs; it issued nocrlsign-leaf. */
static int x509_vfy_gen_twins(void)
{
    EXPECT_DECLS;
    WC_RNG rng;
    RsaKey caKey, intKey, leafKey;
    int rngI = 0, caI = 0, intI = 0, leafI = 0;
    word32 idx;
    byte* der = NULL;
    byte* leafDer = NULL;
    int sz = 0;
    Cert cert;

    ExpectNotNull(der = (byte*)XMALLOC(FOURK_BUF, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngI = 1;
    ExpectIntEQ(wc_InitRsaKey(&caKey, NULL), 0);
    if (EXPECT_SUCCESS()) caI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, &caKey,
        sizeof_ca_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&intKey, NULL), 0);
    if (EXPECT_SUCCESS()) intI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &intKey,
        sizeof_server_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&leafKey, NULL), 0);
    if (EXPECT_SUCCESS()) leafI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &leafKey,
        sizeof_client_key_der_2048), 0);

    if (EXPECT_SUCCESS()) {
        sz = gen_ca_int_keyusage(der, FOURK_BUF, &intKey, &caKey, &rng,
            "Twin Intermediate", "keyCertSign,cRLSign", 0);
    }
    ExpectIntEQ(x509_vfy_keep_der("twin-good", der, sz), 1);
    if (EXPECT_SUCCESS()) {
        sz = gen_ca_int_keyusage(der, FOURK_BUF, &intKey, &caKey, &rng,
            "Twin Intermediate", "digitalSignature", 0);
    }
    ExpectIntEQ(x509_vfy_keep_der("twin-bad", der, sz), 1);
    if (EXPECT_SUCCESS()) {
        sz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey, der, sz,
            &intKey, &rng, "Leaf under twins");
    }
    ExpectIntEQ(x509_vfy_keep_der("twin-leaf", leafDer, sz), 1);

    ExpectIntEQ(wc_InitCert(&cert), 0);
    cert.isCA = 1;
    cert.pathLen = 0;
    cert.pathLenSet = 1;
    cert.sigType = CTC_SHA256wRSA;
    XSTRNCPY(cert.subject.commonName, "Pathlen 0 CA", CTC_NAME_SIZE - 1);
    ExpectIntEQ(wc_SetSubjectKeyIdFromPublicKey(&cert, &intKey, NULL), 0);
    ExpectIntEQ(wc_SetAuthKeyIdFromCert(&cert, ca_cert_der_2048,
        (int)sizeof_ca_cert_der_2048), 0);
    ExpectIntEQ(wc_SetIssuerBuffer(&cert, ca_cert_der_2048,
        (int)sizeof_ca_cert_der_2048), 0);
    ExpectIntGT(wc_MakeCert(&cert, der, FOURK_BUF, &intKey, NULL, &rng), 0);
    if (EXPECT_SUCCESS()) {
        sz = wc_SignCert(cert.bodySz, cert.sigType, der, FOURK_BUF, &caKey,
            NULL, &rng);
    }
    ExpectIntEQ(x509_vfy_keep_der("pl0-ca", der, sz), 1);
    if (EXPECT_SUCCESS()) {
        sz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey, der, sz,
            &intKey, &rng, "Not a CA");
    }
    ExpectIntEQ(x509_vfy_keep_der("pl0-notca", leafDer, sz), 1);
    if (EXPECT_SUCCESS()) {
        sz = gen_leaf_under_int(der, FOURK_BUF, &caKey, leafDer, sz,
            &leafKey, &rng, "Leaf of not a CA");
    }
    ExpectIntEQ(x509_vfy_keep_der("pl0-notca-leaf", der, sz), 1);

    if (EXPECT_SUCCESS()) {
        sz = gen_ca_int_keyusage(der, FOURK_BUF, &intKey, &caKey, &rng,
            "No CRL Sign CA", "keyCertSign", 0);
    }
    ExpectIntEQ(x509_vfy_keep_der("nocrlsign", der, sz), 1);
    if (EXPECT_SUCCESS()) {
        sz = gen_leaf_under_int(leafDer, FOURK_BUF, &leafKey, der, sz,
            &intKey, &rng, "Leaf of no CRL Sign CA");
    }
    ExpectIntEQ(x509_vfy_keep_der("nocrlsign-leaf", leafDer, sz), 1);

    if (rngI)  wc_FreeRng(&rng);
    if (caI)   wc_FreeRsaKey(&caKey);
    if (intI)  wc_FreeRsaKey(&intKey);
    if (leafI) wc_FreeRsaKey(&leafKey);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(IGNORE_NAME_CONSTRAINTS)
/* Leaves of nc-ca, which permits only the email addresses of .wolfssl.com:
 * nc-leaf with one, nc-leaf-bad with another. Leaves of ncdns-ca, CAs with a
 * CN and no SAN: ncdns-leaf in .example.com, ncdns-leaf-bad outside it,
 * ncdns-leaf-excl in the excluded .blocked.example.com. */
static int x509_vfy_gen_nc(void)
{
    EXPECT_DECLS;
    static const struct {
        const char* name;
        const char* ca;
        int isCA;
        const char* cn;
        const char* email;
    } leaves[] = {
        { "nc-leaf",         "nc-ca",    0, "NC Leaf",
          "leaf@info.wolfssl.com" },
        { "nc-leaf-bad",     "nc-ca",    0, "NC Leaf",
          "leaf@info.example.com" },
        { "ncdns-leaf",      "ncdns-ca", 1, "www.example.com",         "" },
        { "ncdns-leaf-bad",  "ncdns-ca", 1, "www.bank.com",            "" },
        { "ncdns-leaf-excl", "ncdns-ca", 1, "www.blocked.example.com", "" }
    };
    WC_RNG rng;
    RsaKey caKey, leafKey;
    int rngI = 0, caI = 0, leafI = 0;
    word32 idx;
    byte* der = NULL;
    X509* ca = NULL;
    const byte* caDer = NULL;
    int caDerSz = 0;
    Cert cert;
    int sz = 0;
    int i;

    ExpectNotNull(der = (byte*)XMALLOC(FOURK_BUF, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngI = 1;
    ExpectIntEQ(wc_InitRsaKey(&caKey, NULL), 0);
    if (EXPECT_SUCCESS()) caI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &caKey,
        sizeof_server_key_der_2048), 0);
    ExpectIntEQ(wc_InitRsaKey(&leafKey, NULL), 0);
    if (EXPECT_SUCCESS()) leafI = 1;
    idx = 0;
    ExpectIntEQ(wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &leafKey,
        sizeof_client_key_der_2048), 0);

    for (i = 0; i < (int)XELEM_CNT(leaves) && EXPECT_SUCCESS(); i++) {
        ExpectNotNull(ca = x509_vfy_cert(leaves[i].ca));
        ExpectNotNull(caDer = wolfSSL_X509_get_der(ca, &caDerSz));
        ExpectIntEQ(wc_InitCert(&cert), 0);
        cert.isCA    = leaves[i].isCA;
        cert.sigType = CTC_SHA256wRSA;
        XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
        XSTRNCPY(cert.subject.commonName, leaves[i].cn, CTC_NAME_SIZE - 1);
        XSTRNCPY(cert.subject.email, leaves[i].email, CTC_NAME_SIZE - 1);
        ExpectIntEQ(wc_SetAuthKeyIdFromCert(&cert, caDer, caDerSz), 0);
        ExpectIntEQ(wc_SetIssuerBuffer(&cert, caDer, caDerSz), 0);
        ExpectIntGT(wc_MakeCert(&cert, der, FOURK_BUF, &leafKey, NULL, &rng),
            0);
        if (EXPECT_SUCCESS()) {
            sz = wc_SignCert(cert.bodySz, cert.sigType, der, FOURK_BUF,
                &caKey, NULL, &rng);
        }
        ExpectIntEQ(x509_vfy_keep_der(leaves[i].name, der, sz), 1);
    }

    if (rngI)  wc_FreeRng(&rng);
    if (caI)   wc_FreeRsaKey(&caKey);
    if (leafI) wc_FreeRsaKey(&leafKey);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return EXPECT_RESULT();
}
#endif

/* Adds the trusted certs of c to store */
static int x509_vfy_add_trusted(const x509_vfy_case* c, X509_STORE* store,
    SSL_CTX* sslCtx)
{
    EXPECT_DECLS;
    const char* list = c->trusted;
    char name[X509_VFY_NAME_SZ];
    char path[160];
    X509_LOOKUP* lookup = NULL;

    (void)sslCtx;
    while (EXPECT_SUCCESS() && x509_vfy_next(&list, name)) {
        x509_vfy_path(name, "-cert.pem", path, (int)sizeof(path));
        if (c->opts & VO_FILE) {
            ExpectIntEQ(X509_STORE_load_locations(store, path, NULL), 1);
        }
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
        else if (c->opts & VO_LOOKUP) {
            if (lookup == NULL) {
                ExpectNotNull(lookup = X509_STORE_add_lookup(store,
                    X509_LOOKUP_file()));
            }
            ExpectIntEQ(X509_LOOKUP_load_file(lookup, path,
                X509_FILETYPE_PEM), 1);
        }
#endif
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
        else if (c->opts & VO_SSLCTX) {
            ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx, path, NULL),
                1);
        }
#endif
        else {
            ExpectIntEQ(X509_STORE_add_cert(store, x509_vfy_cert(name)), 1);
        }
    }
    (void)lookup;
    return EXPECT_RESULT();
}

#ifdef HAVE_CRL
/* Breaks the signature of *crl */
static int x509_vfy_crl_badsig(X509_CRL** crl)
{
    X509_CRL* bad = NULL;
    unsigned char* der = NULL;
    const unsigned char* p;
    int derSz;

    if ((derSz = i2d_X509_CRL(*crl, &der)) > 0) {
        der[derSz - 1] ^= 0x01;
        p = der;
        bad = d2i_X509_CRL(NULL, &p, derSz);
    }
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    if (bad == NULL)
        return 0;
    X509_CRL_free(*crl);
    *crl = bad;
    return 1;
}

/* Adds the CRLs of c to store or, with a '+', to *crls. "<name>-badsig" is
 * the CRL of name with a broken signature. */
static int x509_vfy_add_crls(const x509_vfy_case* c, X509_STORE* store,
    STACK_OF(X509_CRL)** crls)
{
    EXPECT_DECLS;
    const char* list = c->crls;
    char name[X509_VFY_NAME_SZ];
    char path[160];
    XFILE fp = XBADFILE;
    X509_CRL* crl = NULL;
    int toCtx;
    int badSig;
    size_t len;

    while (EXPECT_SUCCESS() && x509_vfy_next(&list, name)) {
        toCtx = (name[0] == '+');
        len = XSTRLEN(name);
        badSig = len > 7 && XSTRCMP(name + len - 7, "-badsig") == 0;
        if (badSig)
            name[len - 7] = '\0';
    #ifdef X509_VFY_GEN_CRLS
        crl = x509_vfy_gen_crl(name + toCtx);
    #endif
        if (crl == NULL) {
            x509_vfy_path(name + toCtx, "-crl.pem", path, (int)sizeof(path));
            ExpectTrue((fp = XFOPEN(path, "rb")) != XBADFILE);
            ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
            if (fp != XBADFILE) {
                XFCLOSE(fp);
                fp = XBADFILE;
            }
        }
        if (badSig) {
            ExpectIntEQ(x509_vfy_crl_badsig(&crl), 1);
        }
        if (!toCtx) {
            ExpectIntEQ(X509_STORE_add_crl(store, crl), 1);
        }
        else {
            if (*crls == NULL) {
                ExpectNotNull(*crls = sk_X509_CRL_new_null());
            }
            ExpectIntGT(sk_X509_CRL_push(*crls, crl), 0);
            if (EXPECT_SUCCESS())
                crl = NULL;
        }
        X509_CRL_free(crl);
        crl = NULL;
    }
    return EXPECT_RESULT();
}
#endif

/* Runs the verification of c and checks its results */
static int x509_vfy_run(const x509_vfy_case* c)
{
    EXPECT_DECLS;
    X509* leaf = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_VERIFY_PARAM* vpm = NULL;
    STACK_OF(X509)* untrusted = NULL;
    STACK_OF(X509)* trusted = NULL;
    STACK_OF(X509)* chain = NULL;
#ifdef HAVE_CRL
    STACK_OF(X509_CRL)* crls = NULL;
#endif
    SSL_CTX* sslCtx = NULL;
    unsigned long flags = 0;
    time_t t = 0;
    int i;
    int n;

    if (c->opts & VO_SSLCTX) {
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
        ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_client_method()));
        /* As OpenSSL, load CAs unverified */
        SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
        ExpectNotNull(store = SSL_CTX_get_cert_store(sslCtx));
#endif
    }
    else {
        ExpectNotNull(store = X509_STORE_new());
    }
    if (c->opts & VO_S_NOTIME) {
        ExpectIntEQ(X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store),
            X509_V_FLAG_NO_CHECK_TIME), 1);
    }
    if (c->opts & VO_S_STRICT)
        flags |= X509_V_FLAG_X509_STRICT;
    if (c->opts & VO_S_PARTIAL)
        flags |= X509_V_FLAG_PARTIAL_CHAIN;
    if (c->opts & VO_CRL)
        flags |= X509_V_FLAG_CRL_CHECK;
    if ((c->opts & VO_CRL_ALL) == VO_CRL_ALL)
        flags |= X509_V_FLAG_CRL_CHECK_ALL;
    if (flags != 0) {
        ExpectIntEQ(X509_STORE_set_flags(store, flags), 1);
    }
#ifndef NO_ASN_TIME
    if (c->opts & VO_ADD1999) {
        ExpectIntEQ(wc_SetTimeCb(x509_vfy_time_1999), 0);
    }
#endif
    if (c->trusted != NULL) {
        ExpectIntEQ(x509_vfy_add_trusted(c, store, sslCtx), TEST_SUCCESS);
    }
#ifndef NO_ASN_TIME
    if (c->opts & VO_ADD1999)
        wc_SetTimeCb(NULL);
#endif
    if ((c->opts & VO_MINRSA) && store != NULL)
        store->cm->minRsaKeySz = 4096 / 8;
    if ((c->opts & VO_MINECC) && store != NULL)
        store->cm->minEccKeySz = 384 / 8;
#ifdef HAVE_CRL
    if (c->crls != NULL) {
        ExpectIntEQ(x509_vfy_add_crls(c, store, &crls), TEST_SUCCESS);
    }
#else
    ExpectNull(c->crls);
#endif
    if (c->untrusted != NULL) {
        ExpectNotNull(untrusted = sk_X509_new_null());
        ExpectIntEQ(x509_vfy_push(untrusted, c->untrusted), 1);
    }
    if (c->stack != NULL) {
        ExpectNotNull(trusted = sk_X509_new_null());
        ExpectIntEQ(x509_vfy_push(trusted, c->stack), 1);
    }

    ExpectNotNull(leaf = x509_vfy_cert(c->leaf));
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted), 1);
    if (EXPECT_SUCCESS()) {
        if (trusted != NULL)
            X509_STORE_CTX_trusted_stack(ctx, trusted);
        switch (c->opts & VO_TIME) {
            case VO_T2005: t = (time_t)1104537600; break;
            case VO_T2015: t = (time_t)1420070400; break;
            case VO_T2025: t = (time_t)1735689600; break;
            default: break;
        }
        if (c->opts & VO_XMLSEC) {
            ExpectNotNull(vpm = X509_VERIFY_PARAM_new());
            if (vpm != NULL) {
                X509_VERIFY_PARAM_set_depth(vpm, 9);
                if (t != 0)
                    X509_VERIFY_PARAM_set_time(vpm, t);
                X509_STORE_CTX_set0_param(ctx, vpm);
            }
        }
        else if (t != 0) {
            X509_STORE_CTX_set_time(ctx, 0, t);
        }
        flags = 0;
        if (c->opts & VO_PARTIAL)
            flags |= X509_V_FLAG_PARTIAL_CHAIN;
        if (c->opts & VO_STRICT)
            flags |= X509_V_FLAG_X509_STRICT;
        if (c->opts & VO_NOTIME)
            flags |= X509_V_FLAG_NO_CHECK_TIME;
        if (c->opts & VO_C_CRL)
            flags |= X509_V_FLAG_CRL_CHECK;
        if ((c->opts & VO_C_CRL_ALL) == VO_C_CRL_ALL)
            flags |= X509_V_FLAG_CRL_CHECK_ALL;
        if (flags != 0)
            X509_STORE_CTX_set_flags(ctx, flags);
        if (c->opts & VO_DEPTH0)
            X509_STORE_CTX_set_depth(ctx, 0);
        if (c->opts & VO_DEPTH1)
            X509_STORE_CTX_set_depth(ctx, 1);
#ifdef HAVE_CRL
        if (crls != NULL) {
            X509_STORE_CTX_set0_crls(ctx, crls);
        }
#endif
        x509VfyAccept = c->cb;
        x509VfyLogNum = 0;
        if (c->cb != 0)
            X509_STORE_CTX_set_verify_cb(ctx, x509_vfy_cb);
    }

    ExpectIntEQ(X509_verify_cert(ctx), c->ret);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), c->err);
    if (c->err != VE_OK) {
        ExpectIntEQ(X509_STORE_CTX_get_error_depth(ctx), c->depth);
    }
    if (EXPECT_SUCCESS())
        chain = X509_STORE_CTX_get0_chain(ctx);
    if (c->chain != NULL) {
        ExpectNotNull(chain);
        ExpectIntEQ(x509_vfy_match(chain, c->chain, 0), 1);
    }
    if (c->cb != 0) {
        for (n = 0; n < 3 && c->cbLog[2 * n] != 0; n++) {
            ExpectIntLT(n, x509VfyLogNum);
            ExpectIntEQ(x509VfyLog[n].err, c->cbLog[2 * n]);
            ExpectIntEQ(x509VfyLog[n].depth, c->cbLog[2 * n + 1]);
        }
        ExpectIntEQ(x509VfyLogNum, n);
        /* The current cert of each error is the cert at its depth */
        for (i = 0; i < n && chain != NULL && EXPECT_SUCCESS(); i++) {
            if (x509VfyLog[i].depth < sk_X509_num(chain)) {
                ExpectIntEQ(X509_cmp(x509VfyLog[i].cert,
                    sk_X509_value(chain, x509VfyLog[i].depth)), 0);
            }
        }
    }
    /* The caller's stacks are left as they were */
    if (untrusted != NULL) {
        ExpectIntEQ(x509_vfy_match(untrusted, c->untrusted, 1), 1);
    }
    if (trusted != NULL) {
        ExpectIntEQ(x509_vfy_match(trusted, c->stack, 1), 1);
    }

    X509_STORE_CTX_free(ctx);
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    if (sslCtx != NULL)
        SSL_CTX_free(sslCtx);
    else
#endif
        X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
#ifdef HAVE_CRL
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
#endif
    return EXPECT_RESULT();
}
#endif

#ifdef X509_VFY_GEN_CRLS
/* CRLs of ca: ca-stale and ca-stale-empty out of date for a month,
 * ca-revoked, ca-empty and ca-self current, ca-nyv-empty valid in a month.
 * ca-stale and ca-revoked list server, ca-self lists ca. ca-empty-old is a
 * day older than ca-empty. ca-otherkey and ca-otherkey-old, a day older, are
 * signed with another key. The current ones have the same thisUpdate.
 * nocrlsign-revoked of nocrlsign lists nocrlsign-leaf. nocrlsign-stale-empty
 * is out of date for a month. */
static int x509_vfy_gen_crls(void)
{
    EXPECT_DECLS;
    static const struct {
        const char* name;
        const char* issuer;
        const char* key;        /* of the issuer */
        int days;               /* from now to the next update */
        const char* revoked;    /* NULL: none */
    } crls[] = {
        { "ca-stale",       "ca", "./certs/ca-key.pem", -30, "server" },
        { "ca-stale-empty", "ca", "./certs/ca-key.pem", -30, NULL },
        { "ca-revoked",     "ca", "./certs/ca-key.pem",  30, "server" },
        { "ca-empty",       "ca", "./certs/ca-key.pem",  30, NULL },
        { "ca-nyv-empty",   "ca", "./certs/ca-key.pem",  60, NULL },
        { "ca-self",        "ca", "./certs/ca-key.pem",  30, "ca" },
        { "ca-empty-old",   "ca", "./certs/ca-key.pem",  29, NULL },
        { "ca-otherkey",    "ca", "./certs/server-key.pem", 30, NULL },
        { "ca-otherkey-old", "ca", "./certs/server-key.pem", 29, NULL },
    #if defined(WOLFSSL_CERT_EXT) && !defined(NO_SHA256) && \
        defined(USE_CERT_BUFFERS_2048) && !defined(ALLOW_INVALID_CERTSIGN)
        { "nocrlsign-revoked", "nocrlsign", "./certs/server-key.pem", 30,
          "nocrlsign-leaf" },
        { "nocrlsign-stale-empty", "nocrlsign", "./certs/server-key.pem", -30,
          NULL }
    #endif
    };
    EVP_PKEY* key = NULL;
    X509_CRL* crl = NULL;
    ASN1_TIME t;
    XFILE fp = XBADFILE;
    const unsigned char* der = NULL;
    int derSz = 0;
    time_t now = XTIME(NULL);
    size_t i;

    for (i = 0; i < XELEM_CNT(crls) && EXPECT_SUCCESS(); i++) {
        ExpectTrue((fp = XFOPEN(crls[i].key, "rb")) != XBADFILE);
        if (fp != XBADFILE) {
            ExpectNotNull(key = PEM_read_PrivateKey(fp, NULL, NULL, NULL));
            XFCLOSE(fp);
        }
        ExpectNotNull(crl = wolfSSL_X509_CRL_new());
        ExpectIntEQ(wolfSSL_X509_CRL_set_issuer_name(crl,
            X509_get_subject_name(x509_vfy_cert(crls[i].issuer))),
            WOLFSSL_SUCCESS);
        XMEMSET(&t, 0, sizeof(t));
        ExpectNotNull(ASN1_TIME_adj(&t, now, crls[i].days - 30, 0));
        ExpectIntEQ(wolfSSL_X509_CRL_set_lastUpdate(crl, &t),
            WOLFSSL_SUCCESS);
        ExpectNotNull(ASN1_TIME_adj(&t, now, crls[i].days, 0));
        ExpectIntEQ(wolfSSL_X509_CRL_set_nextUpdate(crl, &t),
            WOLFSSL_SUCCESS);
        if (crls[i].revoked != NULL) {
            ExpectNotNull(der = wolfSSL_X509_get_der(
                x509_vfy_cert(crls[i].revoked), &derSz));
            ExpectIntEQ(wolfSSL_X509_CRL_add_revoked_cert(crl, der, derSz),
                WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(wolfSSL_X509_CRL_sign(crl, key, wolfSSL_EVP_sha256()),
            WOLFSSL_SUCCESS);
        if (EXPECT_SUCCESS()) {
            XSTRNCPY(x509VfyCrls[i].name, crls[i].name,
                X509_VFY_NAME_SZ - 1);
            x509VfyCrls[i].der = NULL;
            x509VfyCrls[i].derSz = i2d_X509_CRL(crl, &x509VfyCrls[i].der);
            x509VfyCrlsNum = (int)i + 1;
        }
        ExpectIntGT(x509VfyCrls[i].derSz, 0);
        X509_CRL_free(crl);
        crl = NULL;
        EVP_PKEY_free(key);
        key = NULL;
    }
    return EXPECT_RESULT();
}
#endif

/* X509_verify_cert() on the chains of x509VfyCases, each compared with
 * OpenSSL 3.0. A comment tells where OpenSSL gives another result. */
int test_X509_verify_cert_chains(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM)
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    size_t i;
    int failed = 0;

    ExpectIntEQ(x509_vfy_gen_badsig(), 1);
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(NO_ASN_TIME) && !defined(ALLOW_INVALID_CERTSIGN)
    ExpectIntEQ(x509_vfy_gen_twins(), TEST_SUCCESS);
#endif
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    !defined(NO_SHA256) && defined(USE_CERT_BUFFERS_2048) && \
    !defined(IGNORE_NAME_CONSTRAINTS)
    ExpectIntEQ(x509_vfy_gen_nc(), TEST_SUCCESS);
#endif
#ifdef X509_VFY_GEN_CRLS
    ExpectIntEQ(x509_vfy_gen_crls(), TEST_SUCCESS);
#endif

    /* A context has X509_V_FLAG_TRUSTED_FIRST: VO_XMLSEC replaces its
     * param */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, x509_vfy_cert("leaf"), NULL),
        1);
    ExpectIntNE(X509_VERIFY_PARAM_get_flags(X509_STORE_CTX_get0_param(ctx)) &
        X509_V_FLAG_TRUSTED_FIRST, 0);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    for (i = 0; i < XELEM_CNT(x509VfyCases) && EXPECT_SUCCESS(); i++) {
        if (x509_vfy_run(&x509VfyCases[i]) != TEST_SUCCESS) {
            fprintf(stderr, "X509_verify_cert() case %d failed: %s\n",
                (int)i, x509VfyCases[i].name);
            failed++;
        }
    }
    ExpectIntEQ(failed, 0);
    x509_vfy_free_certs();
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_NO_MALLOC) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
#define TEST_X509_VERIFY_CERT_OOM
static wolfSSL_Malloc_cb x509VfyOomMalloc = NULL;
static wolfSSL_Realloc_cb x509VfyOomRealloc = NULL;
static int x509VfyOomNum = 0;
static int x509VfyOomAt = 0;

/* Fails allocation number x509VfyOomAt */
static void* x509_vfy_oom_malloc(size_t size)
{
    if (++x509VfyOomNum == x509VfyOomAt)
        return NULL;
    if (x509VfyOomMalloc != NULL)
        return x509VfyOomMalloc(size);
    return malloc(size);
}

static void* x509_vfy_oom_realloc(void* ptr, size_t size)
{
    if (++x509VfyOomNum == x509VfyOomAt)
        return NULL;
    if (x509VfyOomRealloc != NULL)
        return x509VfyOomRealloc(ptr, size);
    return realloc(ptr, size);
}

/* Returns 1 when verifying a signature with the RSA key of ca allocates */
static int x509_vfy_oom_rsa_allocs(X509* ca, wolfSSL_Free_cb freeCb)
{
    RsaKey* key = NULL;
    byte sig[256];
    byte* out = NULL;
    word32 idx = 0;
    int ret = 0;

    key = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA);
    if (key != NULL && wc_InitRsaKey(key, NULL) == 0) {
        if (wc_RsaPublicKeyDecode(ca->pubKey.buffer, &idx, key,
                ca->pubKey.length) == 0 &&
                wc_RsaEncryptSize(key) == (int)sizeof(sig)) {
            XMEMSET(sig, 1, sizeof(sig));
            sig[0] = 0;
            x509VfyOomNum = 0;
            x509VfyOomAt = 0;
            if (wolfSSL_SetAllocators(x509_vfy_oom_malloc, freeCb,
                    x509_vfy_oom_realloc) == 0) {
                (void)wc_RsaSSL_VerifyInline(sig, sizeof(sig), &out, key);
                (void)wolfSSL_SetAllocators(x509VfyOomMalloc, freeCb,
                    x509VfyOomRealloc);
                ret = x509VfyOomNum > 0;
            }
        }
        wc_FreeRsaKey(key);
    }
    XFREE(key, NULL, DYNAMIC_TYPE_RSA);
    return ret;
}
#endif

/* RFC 5280, 4.2.1.1: as OpenSSL's X509_check_akid(), a cert of another
 * serial or issuer name than the AKID's did not issue the subject. */
int test_X509_check_issued_akid(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_AKID_NAME) && defined(WOLFSSL_ASN_TEMPLATE) && \
    defined(HAVE_ECC) && !defined(NO_SHA256)
    X509* ca = NULL;
    X509* twin = NULL;
    X509* leaf = NULL;
    X509* leafIssuer = NULL;

    ExpectNotNull(ca = X509_load_certificate_file(
        "./certs/test/akid-serial/ca-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(twin = X509_load_certificate_file(
        "./certs/test/akid-serial/ca-twin-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file(
        "./certs/test/akid-serial/leaf-cert.pem", WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(leafIssuer = X509_load_certificate_file(
        "./certs/test/akid-serial/leaf-issuer-cert.pem",
        WOLFSSL_FILETYPE_PEM));

    ExpectIntEQ(X509_check_issued(ca, leaf), X509_V_OK);
    ExpectIntEQ(X509_check_issued(twin, leaf),
        X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
    ExpectIntEQ(X509_check_issued(ca, leafIssuer),
        X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);

    X509_free(leafIssuer);
    X509_free(leaf);
    X509_free(twin);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

/* X509_verify_cert() rejects whichever allocation fails: a chain without a
 * trusted issuer, a chain through a CA of an SSL_CTX of pathlen:0, a cert
 * that a CRL of X509_STORE_CTX_set0_crls revokes while a CRL of the store
 * does not, and an expired self-signed CA of an SSL_CTX. A callback that
 * accepts every error cannot accept a failed allocation, and some is
 * reported as X509_V_ERR_OUT_OF_MEM. Where verifying an RSA signature
 * allocates, a failure there is a bad signature, as in OpenSSL: then only
 * that a failing chain still fails without a callback is checked. */
int test_X509_verify_cert_oom(void)
{
    EXPECT_DECLS;
#ifdef TEST_X509_VERIFY_CERT_OOM
    static const struct {
        const char* leaf;
        const char* untrusted;  /* NULL: none */
        const char* sslCtxCa;   /* with ca-cert, the CAs of an SSL_CTX */
        const char* storeCrl;
        const char* ctxCrl;
        int err;
    } cases[] = {
        { "./certs/intermediate/server-int-cert.pem", NULL, NULL, NULL, NULL,
          X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
        defined(WOLFSSL_SIGNER_DER_CERT)
        { "./certs/test-pathlen/chainF-entity.pem",
          "./certs/test-pathlen/chainF-ICA1-pathlen1.pem",
          "./certs/test-pathlen/chainF-ICA2-pathlen0.pem", NULL, NULL,
          X509_V_ERR_PATH_LENGTH_EXCEEDED },
    #endif
    #ifdef HAVE_CRL
        { "./certs/server-cert.pem", NULL, NULL,
          "./certs/crl/extra-crls/ca-int-cert-revoked.pem",
          "./certs/crl/extra-crls/general-server-crl.pem",
          X509_V_ERR_CERT_REVOKED },
    #endif
    #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT) && \
        defined(WOLFSSL_SIGNER_DER_CERT)
        { TA_CERT_DIR "expired-root-cert.pem", NULL,
          TA_CERT_DIR "expired-root-cert.pem", NULL, NULL,
          X509_V_ERR_CERT_HAS_EXPIRED },
    #endif
    };
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509* ca = NULL;
    X509* leaf = NULL;
    X509* inter = NULL;
    STACK_OF(X509)* untrusted = NULL;
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX* sslCtx = NULL;
#endif
#ifdef HAVE_CRL
    X509_CRL* crl = NULL;
    STACK_OF(X509_CRL)* crls = NULL;
    XFILE fp = XBADFILE;
#endif
    wolfSSL_Free_cb prevF = NULL;
    int allocs;
    int acceptAll;
    int ret;
    int err;
    int baseErr = 0;
    int baseLogNum = 0;
    int baseLog[2 * 4]; /* x509VfyLog without a failure: errors, depths */
    int same;
    int rsaAllocs = 0;
    int outOfMem;
    int i;
    int n;
    size_t c;

    ExpectNotNull(ca = X509_load_certificate_file("./certs/ca-cert.pem",
        SSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_GetAllocators(&x509VfyOomMalloc, &prevF,
        &x509VfyOomRealloc), 0);
    if (EXPECT_SUCCESS())
        rsaAllocs = x509_vfy_oom_rsa_allocs(ca, prevF);
    for (c = 0; c < XELEM_CNT(cases) && EXPECT_SUCCESS(); c++) {
        ExpectNotNull(leaf = X509_load_certificate_file(cases[c].leaf,
            SSL_FILETYPE_PEM));
        if (cases[c].untrusted != NULL) {
            ExpectNotNull(inter = X509_load_certificate_file(
                cases[c].untrusted, SSL_FILETYPE_PEM));
            ExpectNotNull(untrusted = sk_X509_new_null());
            ExpectIntGT(sk_X509_push(untrusted, inter), 0);
        }
    #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
        if (cases[c].sslCtxCa != NULL) {
            ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_client_method()));
            SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
            ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx,
                "./certs/ca-cert.pem", NULL), 1);
            ExpectIntEQ(SSL_CTX_load_verify_locations(sslCtx,
                cases[c].sslCtxCa, NULL), 1);
            ExpectNotNull(store = SSL_CTX_get_cert_store(sslCtx));
        }
        else
    #endif
        {
            ExpectNotNull(store = X509_STORE_new());
            ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);
        }
    #ifdef HAVE_CRL
        if (cases[c].storeCrl != NULL) {
            ExpectTrue((fp = XFOPEN(cases[c].storeCrl, "rb")) != XBADFILE);
            ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
            if (fp != XBADFILE)
                XFCLOSE(fp);
            ExpectIntEQ(X509_STORE_add_crl(store, crl), 1);
            X509_CRL_free(crl);
            crl = NULL;
        }
        if (cases[c].ctxCrl != NULL) {
            ExpectTrue((fp = XFOPEN(cases[c].ctxCrl, "rb")) != XBADFILE);
            ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
            if (fp != XBADFILE)
                XFCLOSE(fp);
            ExpectNotNull(crls = sk_X509_CRL_new_null());
            ExpectIntGT(sk_X509_CRL_push(crls, crl), 0);
        }
    #endif
        /* First without a failure, to count the allocations. A callback
         * that accepts every error is not asked about a failed allocation,
         * as OpenSSL: X509_V_ERR_OUT_OF_MEM, or X509_V_ERR_UNSPECIFIED
         * where it is not known. */
        for (acceptAll = 0; acceptAll <= 1 && EXPECT_SUCCESS(); acceptAll++) {
            allocs = 0;
            outOfMem = 0;
            for (i = 0; i <= allocs && EXPECT_SUCCESS(); i++) {
                ExpectNotNull(ctx = X509_STORE_CTX_new());
                ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, untrusted),
                    1);
            #ifdef HAVE_CRL
                if (crls != NULL)
                    X509_STORE_CTX_set0_crls(ctx, crls);
            #endif
                x509VfyAccept = VA_ALL;
                x509VfyLogNum = 0;
                if (acceptAll)
                    X509_STORE_CTX_set_verify_cb(ctx, x509_vfy_cb);
                x509VfyOomNum = 0;
                x509VfyOomAt = i;
                ExpectIntEQ(wolfSSL_SetAllocators(x509_vfy_oom_malloc, prevF,
                    x509_vfy_oom_realloc), 0);
                ret = X509_verify_cert(ctx);
                (void)wolfSSL_SetAllocators(x509VfyOomMalloc, prevF,
                    x509VfyOomRealloc);
                err = X509_STORE_CTX_get_error(ctx);
                if (i == 0) {
                    allocs = x509VfyOomNum;
                    if (!acceptAll)
                        ExpectIntEQ(err, cases[c].err);
                    ExpectIntEQ(ret, acceptAll);
                    baseErr = err;
                    baseLogNum = x509VfyLogNum;
                    for (n = 0; n < (int)XELEM_CNT(x509VfyLog); n++) {
                        baseLog[2 * n] = x509VfyLog[n].err;
                        baseLog[2 * n + 1] = x509VfyLog[n].depth;
                    }
                }
                else {
                    /* Without effect, or internal: the callback saw only
                     * errors it sees without a failure */
                    same = x509VfyLogNum <= baseLogNum;
                    for (n = 0; same && n < x509VfyLogNum &&
                            n < (int)XELEM_CNT(x509VfyLog); n++) {
                        same = x509VfyLog[n].err == baseLog[2 * n] &&
                            x509VfyLog[n].depth == baseLog[2 * n + 1];
                    }
                    if (ret == 1) {
                        same = acceptAll && (rsaAllocs || (same &&
                            err == baseErr && x509VfyLogNum == baseLogNum));
                    }
                    else if (err != X509_V_ERR_OUT_OF_MEM &&
                            err != X509_V_ERR_UNSPECIFIED) {
                        same = rsaAllocs ||
                            (same && !acceptAll && err == baseErr);
                    }
                    if (!same) {
                        fprintf(stderr, "X509_verify_cert() of %s with "
                            "allocation %d failing: %d, error %d\n",
                            cases[c].leaf, i, ret, err);
                    }
                    ExpectTrue(same);
                    outOfMem |= (err == X509_V_ERR_OUT_OF_MEM);
                }
                X509_STORE_CTX_free(ctx);
                ctx = NULL;
            }
            ExpectIntGT(allocs, 0);
            /* Some failed allocation is reported as such */
            ExpectTrue(outOfMem);
        }
    #ifdef HAVE_CRL
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
        crls = NULL;
    #endif
    #if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
        if (sslCtx != NULL) {
            SSL_CTX_free(sslCtx);
            sslCtx = NULL;
            store = NULL;
        }
    #endif
        X509_STORE_free(store);
        store = NULL;
        sk_X509_pop_free(untrusted, X509_free);
        untrusted = NULL;
        X509_free(leaf);
        leaf = NULL;
    }
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

/* A store of its own takes a trusted cert that is out of date, as in
 * OpenSSL (the add_cert_expired cases of x509VfyCases). The cert stays out
 * of the cert manager, so TLS does not trust it. */
int test_X509_STORE_add_cert_expired(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_ASN_TIME)
    const char* leafFile = TA_CERT_DIR "expired-root-leaf-cert.pem";
    X509* root = NULL;
    X509* renewed = NULL;
    X509* leaf = NULL;
    X509* issuer = NULL;
    X509_STORE* store = NULL;
    X509_STORE* store2 = NULL;
    X509_STORE_CTX* ctx = NULL;
#if defined(WOLFSSL_SIGNER_DER_CERT)
    STACK_OF(X509)* certs = NULL;
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_SIGNER_DER_CERT)
    STACK_OF(X509_OBJECT)* objs = NULL;
    int i;
#endif
#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    SSL_CTX* sslCtx = NULL;
    X509* datedRoot = NULL;
    X509* expiredInt = NULL;
#endif

    ExpectNotNull(root = X509_load_certificate_file(
        TA_CERT_DIR "expired-root-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(renewed = X509_load_certificate_file(
        TA_CERT_DIR "renewed-root-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(leaf = X509_load_certificate_file(leafFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, leafFile,
        SSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    /* Adding it again keeps one copy */
    ExpectIntEQ(X509_STORE_add_cert(store, root), 1);
    ExpectIntEQ(sk_X509_num(store->trusted), 1);

    /* Verifying with it does not put it in the cert manager */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    X509_STORE_CTX_set_time(ctx, 0, (time_t)1420070400);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, leafFile,
        SSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    /* The issuer lookups find it */
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, leaf, NULL), 1);
    ExpectIntEQ(X509_STORE_CTX_get1_issuer(&issuer, ctx, leaf), 1);
    ExpectIntEQ(X509_cmp(issuer, root), 0);
    X509_free(issuer);
#if defined(WOLFSSL_SIGNER_DER_CERT)
    ExpectNotNull(certs = X509_STORE_get1_certs(ctx,
        X509_get_subject_name(root)));
    ExpectIntEQ(sk_X509_num(certs), 1);
    sk_X509_pop_free(certs, X509_free);
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_SIGNER_DER_CERT)
    ExpectNotNull(objs = X509_STORE_get0_objects(store));
    ExpectIntEQ(sk_X509_OBJECT_num(objs), 1);
    ExpectIntEQ(X509_cmp(X509_OBJECT_get0_X509(
        (X509_OBJECT*)sk_X509_OBJECT_value(objs, 0)), root), 0);
#endif

    /* Nor with X509_V_FLAG_NO_CHECK_TIME */
    ExpectNotNull(store2 = X509_STORE_new());
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store2),
        X509_V_FLAG_NO_CHECK_TIME), 1);
    ExpectIntEQ(X509_STORE_add_cert(store2, root), 1);
    ExpectIntEQ(wolfSSL_CertManagerVerify(store2->cm, leafFile,
        SSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    X509_STORE_free(store2);
    store2 = NULL;

#if defined(OPENSSL_ALL) && defined(WOLFSSL_SIGNER_DER_CERT)
    /* A valid root of the same name with a new key does not hide it */
    for (i = 0; i < 2; i++) {
        ExpectNotNull(store2 = X509_STORE_new());
        ExpectIntEQ(X509_STORE_add_cert(store2, (i == 0) ? renewed : root),
            1);
        ExpectIntEQ(X509_STORE_add_cert(store2, (i == 0) ? root : renewed),
            1);
        ExpectNotNull(objs = X509_STORE_get0_objects(store2));
        ExpectIntEQ(sk_X509_OBJECT_num(objs), 2);
        X509_STORE_free(store2);
        store2 = NULL;
    }
#endif

#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    /* The store of an SSL_CTX still refuses it */
    ExpectNotNull(datedRoot = X509_load_certificate_file(
        TA_CERT_DIR "dated-root-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(expiredInt = X509_load_certificate_file(
        TA_CERT_DIR "expired-int-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(sslCtx = SSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(X509_STORE_add_cert(SSL_CTX_get_cert_store(sslCtx), root),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(X509_STORE_set_flags(SSL_CTX_get_cert_store(sslCtx),
        X509_V_FLAG_NO_CHECK_TIME), 1);
    ExpectIntEQ(X509_STORE_add_cert(SSL_CTX_get_cert_store(sslCtx), root),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* Nor does an SSL_CTX trust it when given the store. The intermediates
     * of the store go in as before. */
    ExpectIntEQ(X509_STORE_add_cert(store, datedRoot), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, expiredInt), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(X509_STORE_get0_param(store),
        X509_V_FLAG_NO_CHECK_TIME), 1);
    SSL_CTX_set_cert_store(sslCtx, store);
    if (SSL_CTX_get_cert_store(sslCtx) == store) {
        store = NULL;
    }
    ExpectIntEQ(wolfSSL_CertManagerVerify(wolfSSL_CTX_GetCertManager(sslCtx),
        leafFile, SSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    ExpectIntEQ(wolfSSL_CertManagerVerify(wolfSSL_CTX_GetCertManager(sslCtx),
        TA_CERT_DIR "dated-int-leaf-cert.pem", SSL_FILETYPE_PEM),
        WOLFSSL_SUCCESS);
    SSL_CTX_free(sslCtx);
    X509_free(datedRoot);
    X509_free(expiredInt);
#endif

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(root);
    X509_free(renewed);
    X509_free(leaf);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
static int test_X509_STORE_untrusted_load_cert_to_stack(const char* filename,
        STACK_OF(X509)* chain)
{
    EXPECT_DECLS;
    XFILE fp = XBADFILE;
    X509* cert = NULL;

    ExpectTrue((fp = XFOPEN(filename, "rb"))
            != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntGT(sk_X509_push(chain, cert), 0);
    if (EXPECT_FAIL())
        X509_free(cert);

    return EXPECT_RESULT();
}

static int test_X509_STORE_untrusted_certs(const char** filenames, int ret,
        int err, int loadCA)
{
    EXPECT_DECLS;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    XFILE fp = XBADFILE;
    X509* cert = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectTrue((fp = XFOPEN("./certs/intermediate/server-int-cert.pem", "rb"))
            != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(str = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(untrusted = sk_X509_new_null());

    ExpectIntEQ(X509_STORE_set_flags(str, 0), 1);
    if (loadCA) {
        ExpectIntEQ(X509_STORE_load_locations(str, "./certs/ca-cert.pem", NULL),
                1);
    }
    for (; *filenames; filenames++) {
        ExpectIntEQ(test_X509_STORE_untrusted_load_cert_to_stack(*filenames,
                untrusted), TEST_SUCCESS);
    }

    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, cert, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), ret);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), err);

    X509_free(cert);
    X509_STORE_free(str);
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, NULL);

    return EXPECT_RESULT();
}
#endif

int test_X509_STORE_untrusted(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
    const char* untrusted1[] = {
        "./certs/intermediate/ca-int2-cert.pem",
        NULL
    };
    const char* untrusted2[] = {
        "./certs/intermediate/ca-int-cert.pem",
        "./certs/intermediate/ca-int2-cert.pem",
        NULL
    };
    const char* untrusted3[] = {
        "./certs/intermediate/ca-int-cert.pem",
        "./certs/intermediate/ca-int2-cert.pem",
        "./certs/ca-cert.pem",
        NULL
    };
    /* Adding unrelated certs that should be ignored */
    const char* untrusted4[] = {
        "./certs/client-ca.pem",
        "./certs/intermediate/ca-int-cert.pem",
        "./certs/server-cert.pem",
        "./certs/intermediate/ca-int2-cert.pem",
        NULL
    };

    /* Only immediate issuer in untrusted chain. Fails since can't build chain
     * to loaded CA. */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted1, 0,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, 1), TEST_SUCCESS);
    /* Succeeds because path to loaded CA is available. */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted2, 1, 0, 1),
            TEST_SUCCESS);
    /* Root CA in untrusted chain is OK so long as CA has been loaded
     * properly */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted3, 1, 0, 1),
            TEST_SUCCESS);
    /* Still needs properly loaded CA. As in OpenSSL, the untrusted root
     * ends the chain and is reported. */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted3, 0,
                X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, 0),
            TEST_SUCCESS);
    /* Succeeds because path to loaded CA is available. */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted4, 1, 0, 1),
            TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE)

static int first_errcode;
static int last_errcode;
static int last_errdepth;

static int X509Callback(int ok, X509_STORE_CTX *ctx)
{

    if (!ok) {
        if (first_errcode == 0)
            first_errcode = X509_STORE_CTX_get_error(ctx);
        last_errcode  = X509_STORE_CTX_get_error(ctx);
        last_errdepth = X509_STORE_CTX_get_error_depth(ctx);
    }
    /* Always return OK to allow verification to continue.*/
    return 1;
}

#endif

int test_X509_STORE_InvalidCa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE)
    const char* filename = "./certs/intermediate/ca_false_intermediate/"
                                                    "test_int_not_cacert.pem";
    const char* srvfile = "./certs/intermediate/ca_false_intermediate/"
                                            "test_sign_bynoca_srv.pem";
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    XFILE fp = XBADFILE;
    X509* cert = NULL;
    STACK_OF(X509)* untrusted = NULL;

    first_errcode = 0;
    last_errcode = 0;
    last_errdepth = 0;

    ExpectTrue((fp = XFOPEN(srvfile, "rb"))
            != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(str = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(untrusted = sk_X509_new_null());

    /* create cert chain stack */
    ExpectIntEQ(test_X509_STORE_untrusted_load_cert_to_stack(filename,
                untrusted), TEST_SUCCESS);

    X509_STORE_set_verify_cb(str, X509Callback);

    ExpectIntEQ(X509_STORE_load_locations(str,
                "./certs/intermediate/ca_false_intermediate/test_ca.pem",
                                                                    NULL), 1);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, cert, untrusted), 1);
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectIntEQ(first_errcode, X509_V_ERR_INVALID_CA);
    /* As in OpenSSL, its keyUsage without keyCertSign is reported next */
    ExpectIntEQ(last_errcode, X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
    (void)last_errdepth;
    /* Defense in depth: ctx->error must not be clobbered back to X509_V_OK
     * by the later successful verification of the intermediate against the
     * trusted root.  The worst-seen error must persist. */
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_KEYUSAGE_NO_CERTSIGN);

    X509_free(cert);
    X509_STORE_free(str);
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, NULL);
#endif
    return EXPECT_RESULT();
}

/* Same override as test_X509_STORE_InvalidCa, but through the per-context
 * callback.  It is settable in every OPENSSL_EXTRA build, so the INVALID_CA
 * override in wolfSSL_X509_verify_cert() is reachable there too - the store
 * callback the test above uses needs OPENSSL_ALL or WOLFSSL_QT. */
int test_X509_STORE_InvalidCa_CtxCallback(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE)
    const char* filename = "./certs/intermediate/ca_false_intermediate/"
                                                    "test_int_not_cacert.pem";
    const char* srvfile = "./certs/intermediate/ca_false_intermediate/"
                                            "test_sign_bynoca_srv.pem";
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    XFILE fp = XBADFILE;
    X509* cert = NULL;
    STACK_OF(X509)* untrusted = NULL;

    first_errcode = 0;
    last_errcode = 0;
    last_errdepth = 0;

    ExpectTrue((fp = XFOPEN(srvfile, "rb"))
            != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(str = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(untrusted = sk_X509_new_null());

    /* Create cert chain stack with an intermediate that is CA:FALSE. */
    ExpectIntEQ(test_X509_STORE_untrusted_load_cert_to_stack(filename,
                untrusted), TEST_SUCCESS);

    ExpectIntEQ(X509_STORE_load_locations(str,
                "./certs/intermediate/ca_false_intermediate/test_ca.pem",
                                                                    NULL), 1);

    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, cert, untrusted), 1);
    /* After init, which clears any callback already on the context. */
    X509_STORE_CTX_set_verify_cb(ctx, X509Callback);
    /* The callback overrides the CA:FALSE issuer, so verification succeeds... */
    ExpectIntEQ(X509_verify_cert(ctx), 1);
    /* ...and it must actually have been handed the INVALID_CA error. */
    ExpectIntEQ(first_errcode, X509_V_ERR_INVALID_CA);
    /* As in OpenSSL, its keyUsage without keyCertSign is reported next */
    ExpectIntEQ(last_errcode, X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
    (void)last_errdepth;
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx),
        X509_V_ERR_KEYUSAGE_NO_CERTSIGN);

    X509_free(cert);
    X509_STORE_free(str);
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, NULL);
#endif
    return EXPECT_RESULT();
}

int test_X509_STORE_InvalidCa_NoCallback(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE)
    const char* filename = "./certs/intermediate/ca_false_intermediate/"
                                                    "test_int_not_cacert.pem";
    const char* srvfile = "./certs/intermediate/ca_false_intermediate/"
                                            "test_sign_bynoca_srv.pem";
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    XFILE fp = XBADFILE;
    X509* cert = NULL;
    STACK_OF(X509)* untrusted = NULL;

    ExpectTrue((fp = XFOPEN(srvfile, "rb"))
            != XBADFILE);
    ExpectNotNull(cert = PEM_read_X509(fp, 0, 0, 0 ));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }

    ExpectNotNull(str = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(untrusted = sk_X509_new_null());

    /* Create cert chain stack with an intermediate that is CA:FALSE. */
    ExpectIntEQ(test_X509_STORE_untrusted_load_cert_to_stack(filename,
                untrusted), TEST_SUCCESS);

    ExpectIntEQ(X509_STORE_load_locations(str,
                "./certs/intermediate/ca_false_intermediate/test_ca.pem",
                                                                    NULL), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, cert, untrusted), 1);
    /* No verify callback: verification must fail on CA:FALSE issuer. */
    ExpectIntNE(X509_verify_cert(ctx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(ctx), X509_V_ERR_INVALID_CA);

    X509_free(cert);
    X509_STORE_free(str);
    X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, NULL);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_CTX_trusted_stack_cleanup(void)
{
    int res = TEST_SKIPPED;
#if defined(OPENSSL_EXTRA)
    X509_STORE_CTX_cleanup(NULL);
    X509_STORE_CTX_trusted_stack(NULL, NULL);

    res = TEST_SUCCESS;
#endif
    return res;
}

/* The trusted stack set with X509_STORE_CTX_trusted_stack() is borrowed from
 * the caller and must not survive a cleanup/re-init into a different store. */
int test_wolfSSL_X509_STORE_CTX_trusted_stack_reinit(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* store1 = NULL;
    X509_STORE* store2 = NULL;
    X509* x509Ca = NULL;
    X509* x509Svr = NULL;
    STACK_OF(X509)* trusted = NULL;
#ifdef WOLFSSL_TEST_STALE_TRUSTED_STACK_UAF
    int verifyRet = 0;
#endif

    ExpectNotNull(x509Ca = wolfSSL_X509_load_certificate_file(caCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(x509Svr = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(trusted = sk_X509_new_null());
    ExpectIntGE(sk_X509_push(trusted, x509Ca), 1);

    /* Both stores are empty, so the caller's stack is the only trust source. */
    ExpectNotNull(store1 = X509_STORE_new());
    ExpectNotNull(store2 = X509_STORE_new());
    ExpectNotNull(ctx = X509_STORE_CTX_new());

    ExpectIntEQ(X509_STORE_CTX_init(ctx, store1, x509Svr, NULL), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);
    X509_STORE_CTX_trusted_stack(ctx, trusted);
    ExpectIntEQ(X509_verify_cert(ctx), 1);

    /* Re-init against a different store: the previous trust domain must be
     * gone, so this must fail. */
    X509_STORE_CTX_cleanup(ctx);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store2, x509Svr, NULL), 1);
    ExpectIntNE(X509_verify_cert(ctx), 1);

#ifdef WOLFSSL_TEST_STALE_TRUSTED_STACK_UAF
    /* Opt-in ASAN repro: the ctx must hold no reference left to free. Call
     * verify outside the Expect macro, which stops running after a failure. */
    sk_X509_free(trusted);
    trusted = NULL;
    verifyRet = X509_verify_cert(ctx);
    ExpectIntNE(verifyRet, 1);
#endif

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store1);
    X509_STORE_free(store2);
    sk_X509_free(trusted);
    X509_free(x509Svr);
    X509_free(x509Ca);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_CTX_get_issuer(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    X509* x509Ca = NULL;
    X509* x509Svr = NULL;
    X509* issuer = NULL;
    X509_NAME* caName = NULL;
    X509_NAME* issuerName = NULL;

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull((x509Ca =
            wolfSSL_X509_load_certificate_file(caCertFile, SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(str, x509Ca), SSL_SUCCESS);
    ExpectNotNull((x509Svr =
            wolfSSL_X509_load_certificate_file(svrCertFile, SSL_FILETYPE_PEM)));

    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, x509Svr, NULL), SSL_SUCCESS);

    /* Issuer0 is not set until chain is built for verification */
    ExpectNull(X509_STORE_CTX_get0_current_issuer(NULL));
    ExpectNull(issuer = X509_STORE_CTX_get0_current_issuer(ctx));

    /* Issuer1 will use the store to make a new issuer */
    ExpectIntEQ(X509_STORE_CTX_get1_issuer(&issuer, ctx, x509Svr), 1);
    ExpectNotNull(issuer);
    X509_free(issuer);

    ExpectIntEQ(X509_verify_cert(ctx), 1);
    ExpectNotNull(issuer = X509_STORE_CTX_get0_current_issuer(ctx));
    ExpectNotNull(caName = X509_get_subject_name(x509Ca));
    ExpectNotNull(issuerName = X509_get_subject_name(issuer));
#ifdef WOLFSSL_SIGNER_DER_CERT
    ExpectIntEQ(X509_NAME_cmp(caName, issuerName), 0);
#endif

    X509_STORE_CTX_free(ctx);
    X509_free(x509Svr);
    X509_STORE_free(str);
    X509_free(x509Ca);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_set_flags(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE* store = NULL;
    X509* x509 = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_STORE_CTX* storeCtx = NULL;
    X509* ca = NULL;
    int err = 0;

    /* The CRL flags must not share bits with the other verify flags */
    ExpectIntEQ((X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) &
        (X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_NO_CHECK_TIME |
         X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_X509_STRICT), 0);

    ExpectNotNull((store = wolfSSL_X509_STORE_new()));
    ExpectNotNull((x509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        WOLFSSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, x509), WOLFSSL_SUCCESS);

    /* As in OpenSSL, the flags go on the verify param */
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, x509, NULL), WOLFSSL_SUCCESS);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_X509_STRICT);
    ExpectIntNE(X509_VERIFY_PARAM_get_flags(X509_STORE_CTX_get0_param(ctx)) &
        X509_V_FLAG_X509_STRICT, 0);
    X509_STORE_CTX_free(ctx);

#ifdef HAVE_CRL
    ExpectIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    /* As OpenSSL, the CRL flags go on the param, also without HAVE_CRL */
    ExpectIntEQ(X509_VERIFY_PARAM_get_flags(X509_STORE_get0_param(store)) &
        (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL),
        X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    wolfSSL_X509_STORE_free(store);
    store = NULL;

    /* X509_V_FLAG_CRL_CHECK turns on CRL checks. No CRL is loaded. */
    ExpectNotNull((store = wolfSSL_X509_STORE_new()));
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCertFile,
        WOLFSSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), WOLFSSL_SUCCESS);
#ifdef HAVE_CRL
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, x509, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), WOLFSSL_SUCCESS);
    err = X509_STORE_CTX_get_error(storeCtx);
    ExpectTrue((err == WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL) ||
               (err == WC_NO_ERR_TRACE(CRL_MISSING)));
    X509_STORE_CTX_free(storeCtx);
    wolfSSL_X509_free(ca);
    wolfSSL_X509_STORE_free(store);

    wolfSSL_X509_free(x509);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) &&
        * !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_TLS) && \
    !defined(NO_FILESYSTEM)
    X509_STORE *store = NULL;

#ifdef HAVE_CRL
    X509_STORE_CTX *storeCtx = NULL;
    X509 *ca = NULL;
    X509 *cert = NULL;
    const char srvCert[] = "./certs/server-revoked-cert.pem";
    const char caCert[] = "./certs/ca-cert.pem";
#ifndef WOLFSSL_CRL_ALLOW_MISSING_CDP
    X509_CRL *crl = NULL;
    const char crlPem[] = "./certs/crl/crl.revoked";
    XFILE fp = XBADFILE;
#endif /* !WOLFSSL_CRL_ALLOW_MISSING_CDP */

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
                           SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
                    SSL_FILETYPE_PEM)));
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);
    ExpectIntEQ(X509_verify_cert(storeCtx), SSL_SUCCESS);
    X509_STORE_free(store);
    store = NULL;
    X509_STORE_CTX_free(storeCtx);
    storeCtx = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;

#ifndef WOLFSSL_CRL_ALLOW_MISSING_CDP
    /* should fail to verify now after adding in CRL */
    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
                           SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);
    ExpectTrue((fp = XFOPEN(crlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
                NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),SSL_SUCCESS);
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
                    SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
                WOLFSSL_X509_V_ERR_CERT_REVOKED);
    X509_CRL_free(crl);
    crl = NULL;
    X509_STORE_free(store);
    store = NULL;
    X509_STORE_CTX_free(storeCtx);
    storeCtx = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;
#endif /* !WOLFSSL_CRL_ALLOW_MISSING_CDP */
#endif /* HAVE_CRL */

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_FILESYSTEM)
    {
    #if !defined(NO_WOLFSSL_CLIENT) || !defined(NO_WOLFSSL_SERVER)
        SSL_CTX* ctx = NULL;
        SSL* ssl = NULL;
        int i;
        for (i = 0; i < 2; i++) {
        #ifndef NO_WOLFSSL_SERVER
            ExpectNotNull(ctx = SSL_CTX_new(wolfSSLv23_server_method()));
        #else
            ExpectNotNull(ctx = SSL_CTX_new(wolfSSLv23_client_method()));
        #endif
            ExpectNotNull(store = (X509_STORE *)X509_STORE_new());
            SSL_CTX_set_cert_store(ctx, store);
            ExpectNotNull(store = (X509_STORE *)X509_STORE_new());
            SSL_CTX_set_cert_store(ctx, store);
            ExpectNotNull(store = (X509_STORE *)X509_STORE_new());
            ExpectIntEQ(SSL_CTX_use_certificate_file(ctx, svrCertFile,
                    SSL_FILETYPE_PEM), SSL_SUCCESS);
            ExpectIntEQ(SSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
                    SSL_FILETYPE_PEM), SSL_SUCCESS);
            ExpectNotNull(ssl = SSL_new(ctx));
            if (i == 0) {
                ExpectIntEQ(SSL_set0_verify_cert_store(ssl, store),
                    SSL_SUCCESS);
            }
            else {
                ExpectIntEQ(SSL_set1_verify_cert_store(ssl, store),
                    SSL_SUCCESS);
                #ifdef OPENSSL_ALL
                ExpectIntEQ(SSL_CTX_set1_verify_cert_store(ctx, store),
                    SSL_SUCCESS);
                #endif
            }
            if (EXPECT_FAIL() || (i == 1)) {
                X509_STORE_free(store);
                store = NULL;
            }
            SSL_free(ssl);
            ssl = NULL;
            SSL_CTX_free(ctx);
            ctx = NULL;
        }
    #endif /* !NO_WOLFSSL_CLIENT || !NO_WOLFSSL_SERVER */
    }
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_load_locations(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR) && !defined(NO_RSA) && \
    !defined(NO_TLS)
    SSL_CTX *ctx = NULL;
    X509_STORE *store = NULL;

    const char ca_file[] = "./certs/ca-cert.pem";
    const char client_pem_file[] = "./certs/client-cert.pem";
    const char client_der_file[] = "./certs/client-cert.der";
    const char ecc_file[] = "./certs/ecc-key.pem";
    const char certs_path[] = "./certs/";
    const char bad_path[] = "./bad-path/";
#ifdef HAVE_CRL
    const char crl_path[] = "./certs/crl/";
    const char crl_file[] = "./certs/crl/crl.pem";
#endif

#ifndef NO_WOLFSSL_SERVER
    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_server_method()));
#else
    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_client_method()));
#endif
    ExpectNotNull(store = SSL_CTX_get_cert_store(ctx));
    ExpectIntEQ(wolfSSL_CertManagerLoadCA(store->cm, ca_file, NULL),
        WOLFSSL_SUCCESS);

    /* The default dir is optional. */
    {
        X509_LOOKUP* lookup = NULL;

        ExpectNotNull(lookup = X509_STORE_add_lookup(store,
            X509_LOOKUP_hash_dir()));
        ExpectIntEQ(X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT),
            WOLFSSL_SUCCESS);
    }

    /* Test bad arguments */
    ExpectIntEQ(X509_STORE_load_locations(NULL, ca_file, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_load_locations(store, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_load_locations(store, client_der_file, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_load_locations(store, ecc_file, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_load_locations(store, NULL, bad_path),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

#ifdef HAVE_CRL
    /* Test with CRL */
    ExpectIntEQ(X509_STORE_load_locations(store, crl_file, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_load_locations(store, NULL, crl_path),
        WOLFSSL_SUCCESS);
#endif

    /* Test with CA */
    ExpectIntEQ(X509_STORE_load_locations(store, ca_file, NULL),
        WOLFSSL_SUCCESS);

    /* Test with client_cert and certs path */
    ExpectIntEQ(X509_STORE_load_locations(store, client_pem_file, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_load_locations(store, NULL, certs_path),
        WOLFSSL_SUCCESS);

#if defined(XGETENV) && !defined(NO_GETENV) && defined(_POSIX_C_SOURCE) && \
    _POSIX_C_SOURCE >= 200112L
    ExpectIntEQ(wolfSSL_CTX_UnloadCAs(ctx), WOLFSSL_SUCCESS);
    /* Test with env vars */
    ExpectIntEQ(setenv("SSL_CERT_FILE", client_pem_file, 1), 0);
    ExpectIntEQ(setenv("SSL_CERT_DIR", certs_path, 1), 0);
    ExpectIntEQ(X509_STORE_set_default_paths(store), WOLFSSL_SUCCESS);
    /* Default locations are optional, as with OpenSSL. */
    ExpectIntEQ(X509_STORE_set_default_paths(NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(unsetenv("SSL_CERT_FILE"), 0);
    ExpectIntEQ(unsetenv("SSL_CERT_DIR"), 0);
    ExpectIntEQ(X509_STORE_set_default_paths(store), WOLFSSL_SUCCESS);
    ExpectIntEQ(setenv("SSL_CERT_DIR", bad_path, 1), 0);
    ExpectIntEQ(X509_STORE_set_default_paths(store), WOLFSSL_SUCCESS);
    ExpectIntEQ(setenv("SSL_CERT_FILE", client_pem_file, 1), 0);
    ExpectIntEQ(setenv("SSL_CERT_DIR", certs_path, 1), 0);
#endif

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
    /* Clear nodes */
    ERR_clear_error();
#endif

    SSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_X509_STORE_get0_objects(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_DIR) && !defined(NO_RSA)
    X509_STORE *store = NULL;
    X509_STORE *store_cpy = NULL;
    SSL_CTX *ctx = NULL;
    X509_OBJECT *obj = NULL;
#ifdef HAVE_CRL
    X509_OBJECT *objCopy = NULL;
#endif
    STACK_OF(X509_OBJECT) *objs = NULL;
    STACK_OF(X509_OBJECT) *objsCopy = NULL;
    int i;

    /* Setup store */
#ifndef NO_WOLFSSL_SERVER
    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_server_method()));
#else
    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_client_method()));
#endif
    ExpectNotNull(store_cpy = X509_STORE_new());
    ExpectNotNull(store = SSL_CTX_get_cert_store(ctx));
    ExpectIntEQ(X509_STORE_load_locations(store, cliCertFile, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_load_locations(store, caCertFile, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_STORE_load_locations(store, svrCertFile, NULL),
        WOLFSSL_SUCCESS);
#ifdef HAVE_CRL
    ExpectIntEQ(X509_STORE_load_locations(store, NULL, crlPemDir),
        WOLFSSL_SUCCESS);
#endif
    /* Store ready */

    /* Similar to HaProxy ssl_set_cert_crl_file use case */
    ExpectNotNull(objs = X509_STORE_get0_objects(store));
#ifdef HAVE_CRL
#ifdef WOLFSSL_SIGNER_DER_CERT
    ExpectIntEQ(sk_X509_OBJECT_num(objs), 4);
#else
    ExpectIntEQ(sk_X509_OBJECT_num(objs), 1);
#endif
#else
#ifdef WOLFSSL_SIGNER_DER_CERT
    ExpectIntEQ(sk_X509_OBJECT_num(objs), 3);
#else
    ExpectIntEQ(sk_X509_OBJECT_num(objs), 0);
#endif
#endif
    ExpectIntEQ(sk_X509_OBJECT_num(NULL), 0);
    ExpectNull(sk_X509_OBJECT_value(NULL, 0));
    ExpectNull(sk_X509_OBJECT_value(NULL, 1));
    ExpectNull(sk_X509_OBJECT_value(objs, sk_X509_OBJECT_num(objs)));
    ExpectNull(sk_X509_OBJECT_value(objs, sk_X509_OBJECT_num(objs) + 1));
#ifndef NO_WOLFSSL_STUB
    ExpectNull(sk_X509_OBJECT_delete(objs, 0));
#endif
    ExpectNotNull(objsCopy = sk_X509_OBJECT_deep_copy(objs, NULL, NULL));
    ExpectIntEQ(sk_X509_OBJECT_num(objs), sk_X509_OBJECT_num(objsCopy));
    for (i = 0; i < sk_X509_OBJECT_num(objs) && EXPECT_SUCCESS(); i++) {
        obj = (X509_OBJECT*)sk_X509_OBJECT_value(objs, i);
    #ifdef HAVE_CRL
        objCopy = (X509_OBJECT*)sk_X509_OBJECT_value(objsCopy, i);
    #endif
        switch (X509_OBJECT_get_type(obj)) {
        case X509_LU_X509:
        {
            X509* x509 = NULL;
            X509_NAME *subj_name = NULL;
            ExpectNull(X509_OBJECT_get0_X509_CRL(NULL));
            ExpectNull(X509_OBJECT_get0_X509_CRL(obj));
            ExpectNotNull(x509 = X509_OBJECT_get0_X509(obj));
            ExpectIntEQ(X509_STORE_add_cert(store_cpy, x509), WOLFSSL_SUCCESS);
            ExpectNotNull(subj_name = X509_get_subject_name(x509));
            ExpectPtrEq(obj, X509_OBJECT_retrieve_by_subject(objs, X509_LU_X509,
                    subj_name));

            break;
        }
        case X509_LU_CRL:
#ifdef HAVE_CRL
        {
            X509_CRL* crl = NULL;
            ExpectNull(X509_OBJECT_get0_X509(NULL));
            ExpectNull(X509_OBJECT_get0_X509(obj));
            ExpectNotNull(crl = X509_OBJECT_get0_X509_CRL(obj));
            ExpectIntEQ(X509_STORE_add_crl(store_cpy, crl), WOLFSSL_SUCCESS);
            ExpectNotNull(crl = X509_OBJECT_get0_X509_CRL(objCopy));
            break;
        }
#endif
        case X509_LU_NONE:
        default:
            Fail(("X509_OBJECT_get_type should return x509 or crl "
                    "(when built with crl support)"),
                    ("Unrecognized X509_OBJECT type or none"));
        }
    }

    X509_STORE_free(store_cpy);
    SSL_CTX_free(ctx);

    wolfSSL_sk_X509_OBJECT_free(NULL);
    objs = NULL;
    wolfSSL_sk_pop_free(objsCopy, NULL);
    objsCopy = NULL;
    ExpectNotNull(objs = wolfSSL_sk_X509_OBJECT_new());
    ExpectIntEQ(wolfSSL_sk_X509_OBJECT_push(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_sk_X509_OBJECT_push(objs, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_sk_X509_OBJECT_push(NULL, obj), WOLFSSL_FAILURE);
    ExpectNotNull(objsCopy = sk_X509_OBJECT_deep_copy(objs, NULL, NULL));
    wolfSSL_sk_X509_OBJECT_free(objsCopy);
    wolfSSL_sk_X509_OBJECT_free(objs);
#endif
    return EXPECT_RESULT();
}

int test_X509_STORE_get0_objects_borrowed_crl(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_CRL) && \
    defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA)
    int pass;

    /* pass 0: one get0_objects call.  pass 1: a second call, which rebuilds
     * the list and so tears the first one down while the store is alive. */
    for (pass = 0; pass < 2 && EXPECT_SUCCESS(); pass++) {
        X509_STORE* store = NULL;
        X509* borrowed = NULL;
        STACK_OF(X509_OBJECT)* objs = NULL;

        /* Not self-signed, so add_cert up_refs it onto store->certs. */
        ExpectNotNull(borrowed = wolfSSL_X509_load_certificate_file(svrCertFile,
            WOLFSSL_FILETYPE_PEM));
        ExpectNotNull(store = X509_STORE_new());
        ExpectIntEQ(X509_STORE_add_cert(store, borrowed), 1);
        /* Arms cm->crl and puts one decoded CA in the CertManager. */
        ExpectIntEQ(X509_STORE_load_locations(store, caCertFile, NULL),
            WOLFSSL_SUCCESS);

        ExpectNotNull(objs = X509_STORE_get0_objects(store));
        /* CM decode + borrowed cert + CRL. */
        ExpectIntEQ(sk_X509_OBJECT_num(objs), 3);
        if (pass == 1) {
            ExpectNotNull(objs = X509_STORE_get0_objects(store));
            ExpectIntEQ(sk_X509_OBJECT_num(objs), 3);
        }

        X509_STORE_free(store);

        /* The store is gone but the caller's reference must have survived. */
        ExpectNotNull(X509_get_subject_name(borrowed));
        X509_free(borrowed);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_get1_certs(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_SIGNER_DER_CERT) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE_CTX *storeCtx = NULL;
    X509_STORE *store = NULL;
    X509 *caX509 = NULL;
    X509 *svrX509 = NULL;
    X509_NAME *subject = NULL;
    WOLF_STACK_OF(WOLFSSL_X509) *certs = NULL;

    ExpectNotNull(caX509 = X509_load_certificate_file(caCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull((svrX509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM)));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(subject = X509_get_subject_name(caX509));

    /* Errors */
    ExpectNull(X509_STORE_get1_certs(storeCtx, subject));
    ExpectNull(X509_STORE_get1_certs(NULL, subject));
    ExpectNull(X509_STORE_get1_certs(storeCtx, NULL));

    ExpectIntEQ(X509_STORE_add_cert(store, caX509), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, caX509, NULL),
        SSL_SUCCESS);

    /* Should find the cert */
    ExpectNotNull(certs = X509_STORE_get1_certs(storeCtx, subject));
    ExpectIntEQ(1, wolfSSL_sk_X509_num(certs));

    sk_X509_pop_free(certs, NULL);
    certs = NULL;

    /* Should not find the cert */
    ExpectNotNull(subject = X509_get_subject_name(svrX509));
    ExpectNotNull(certs = X509_STORE_get1_certs(storeCtx, subject));
    ExpectIntEQ(0, wolfSSL_sk_X509_num(certs));

    sk_X509_pop_free(certs, NULL);
    certs = NULL;

    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(svrX509);
    X509_free(caX509);
#endif /* OPENSSL_EXTRA && WOLFSSL_SIGNER_DER_CERT && !NO_FILESYSTEM */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_STORE_CTX_get_by_subject(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* store = NULL;
    X509* ca = NULL;
    X509* svr = NULL;
    X509* cli = NULL;
    X509_OBJECT* obj = NULL;

    ExpectNotNull(ca = X509_load_certificate_file(caCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(svr = X509_load_certificate_file(svrCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(cli = X509_load_certificate_file(cliCertFile,
        SSL_FILETYPE_PEM));
    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(obj = X509_OBJECT_new());

    /* Errors */
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(NULL, X509_LU_X509,
        X509_get_subject_name(ca), obj), 0);
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(ca), obj), 0);

    /* Trusted self-signed cert and untrusted intermediate. */
    ExpectIntEQ(X509_STORE_add_cert(store, ca), 1);
    ExpectIntEQ(X509_STORE_add_cert(store, svr), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, NULL, NULL), 1);
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509, NULL, obj),
        0);
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(ca), NULL), 0);
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_CRL,
        X509_get_subject_name(ca), obj), 0);
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(cli), obj), 0);
    ExpectTrue(X509_OBJECT_get_type(obj) == X509_LU_NONE);

    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(ca), obj), 1);
    ExpectTrue(X509_OBJECT_get_type(obj) == X509_LU_X509);
    ExpectPtrEq(X509_OBJECT_get0_X509(obj), ca);
    X509_OBJECT_free(obj);
    obj = NULL;

    /* free_contents releases the reference and empties the object */
    ExpectNotNull(obj = X509_OBJECT_new());
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(ca), obj), 1);
    X509_OBJECT_free_contents(obj);
    ExpectTrue(X509_OBJECT_get_type(obj) == X509_LU_NONE);
    ExpectNull(X509_OBJECT_get0_X509(obj));
    X509_OBJECT_free_contents(obj);
    X509_OBJECT_free(obj);
    obj = NULL;

    ExpectNotNull(obj = X509_OBJECT_new());
    ExpectIntEQ(X509_STORE_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(svr), obj), 1);
    ExpectPtrEq(X509_OBJECT_get0_X509(obj), svr);
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_free(store);
    store = NULL;
    X509_free(svr);
    svr = NULL;

    /* The object holds the last reference to the cert. */
    ExpectIntEQ(X509_check_issued(ca, X509_OBJECT_get0_X509(obj)), X509_V_OK);
    X509_OBJECT_free(obj);
    obj = NULL;

#ifdef WOLFSSL_SIGNER_DER_CERT
    /* CA loaded from a file into the cert manager. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectIntEQ(X509_STORE_load_locations(store, caCertFile, NULL), 1);
    ExpectIntEQ(X509_STORE_CTX_init(ctx, store, NULL, NULL), 1);
    ExpectNotNull(obj = X509_OBJECT_new());
    ExpectIntEQ(X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
        X509_get_subject_name(ca), obj), 1);
    ExpectIntEQ(X509_cmp(X509_OBJECT_get0_X509(obj), ca), 0);
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_free(store);
    ExpectNotNull(X509_get_subject_name(X509_OBJECT_get0_X509(obj)));
#endif

    X509_OBJECT_free(obj);
    X509_STORE_CTX_free(ctx);
    X509_free(cli);
    X509_free(svr);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_LOCAL_X509_STORE) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && defined(HAVE_CRL)
static int test_wolfSSL_X509_STORE_set_get_crl_provider(X509_STORE_CTX* ctx,
        X509_CRL** crl_out, X509* cert) {
    X509_CRL *crl = NULL;
    XFILE fp = XBADFILE;
    char* cert_issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    int ret = 0;

    (void)ctx;

    if (cert_issuer == NULL)
        return 0;

    if ((fp = XFOPEN("certs/crl/crl.pem", "rb")) != XBADFILE) {
        PEM_read_X509_CRL(fp, &crl, NULL, NULL);
        XFCLOSE(fp);
        if (crl != NULL) {
            char* crl_issuer = X509_NAME_oneline(
                    X509_CRL_get_issuer(crl), NULL, 0);
            if ((crl_issuer != NULL) &&
                   (XSTRCMP(cert_issuer, crl_issuer) == 0)) {
                *crl_out = X509_CRL_dup(crl);
                if (*crl_out != NULL)
                    ret = 1;
            }
            OPENSSL_free(crl_issuer);
        }
    }

    X509_CRL_free(crl);
    OPENSSL_free(cert_issuer);
    return ret;
}

static int test_wolfSSL_X509_STORE_set_get_crl_provider2(X509_STORE_CTX* ctx,
        X509_CRL** crl_out, X509* cert) {
    (void)ctx;
    (void)cert;
    *crl_out = NULL;
    return 1;
}

#ifndef NO_WOLFSSL_STUB
static int test_wolfSSL_X509_STORE_set_get_crl_check(X509_STORE_CTX* ctx,
        X509_CRL* crl) {
    (void)ctx;
    (void)crl;
    return 1;
}
#endif

static int test_wolfSSL_X509_STORE_set_get_crl_verify(int ok,
        X509_STORE_CTX* ctx) {
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    int flags = X509_VERIFY_PARAM_get_flags(param);
    if ((flags & (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) !=
            (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) {
        /* Make sure the flags are set */
        return 0;
    }
    /* Ignore CRL missing error */
#ifndef OPENSSL_COMPATIBLE_DEFAULTS
    if (cert_error == WC_NO_ERR_TRACE(CRL_MISSING))
#else
    if (cert_error == X509_V_ERR_UNABLE_TO_GET_CRL)
#endif
        return 1;
    return ok;
}

static int test_wolfSSL_X509_STORE_set_get_crl_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    X509_STORE* cert_store = NULL;

    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectNotNull(cert_store = SSL_CTX_get_cert_store(ctx));
    X509_STORE_set_get_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_provider);
#ifndef NO_WOLFSSL_STUB
    X509_STORE_set_check_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_check);
#endif

    return EXPECT_RESULT();
}

static int test_wolfSSL_X509_STORE_set_get_crl_ctx_ready2(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    X509_STORE* cert_store = NULL;
    X509_VERIFY_PARAM* param = NULL;

    SSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    ExpectIntEQ(wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECKALL),
            WOLFSSL_SUCCESS);
    ExpectNotNull(cert_store = SSL_CTX_get_cert_store(ctx));
    X509_STORE_set_get_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_provider2);
#ifndef NO_WOLFSSL_STUB
    X509_STORE_set_check_crl(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_check);
#endif
    X509_STORE_set_verify_cb(cert_store,
            test_wolfSSL_X509_STORE_set_get_crl_verify);
    ExpectNotNull(X509_STORE_get0_param(cert_store));
    ExpectNotNull(param = X509_VERIFY_PARAM_new());
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(NULL, NULL) , WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param, NULL) , WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param,
            X509_STORE_get0_param(cert_store)), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_VERIFY_PARAM_inherit(param,
            X509_STORE_get0_param(cert_store)), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(
        param, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), 1);
    ExpectIntEQ(X509_STORE_set1_param(cert_store, param), 1);
    ExpectIntEQ(X509_STORE_set_flags(cert_store,
            X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), 1);


    X509_VERIFY_PARAM_free(param);
    return EXPECT_RESULT();
}
#endif

/* This test mimics the usage of the CRL provider in gRPC */
int test_wolfSSL_X509_STORE_set_get_crl(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_LOCAL_X509_STORE) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_QT)) && defined(HAVE_CRL)
    test_ssl_cbf func_cb_client;
    test_ssl_cbf func_cb_server;

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    func_cb_client.ctx_ready = test_wolfSSL_X509_STORE_set_get_crl_ctx_ready;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), TEST_SUCCESS);

    XMEMSET(&func_cb_client, 0, sizeof(func_cb_client));
    XMEMSET(&func_cb_server, 0, sizeof(func_cb_server));

    func_cb_client.ctx_ready = test_wolfSSL_X509_STORE_set_get_crl_ctx_ready2;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&func_cb_client,
        &func_cb_server, NULL), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
/* Load a CRL from a PEM file and push it onto sk. */
static int test_set0_crls_push_crl(STACK_OF(X509_CRL)* sk, const char* file)
{
    EXPECT_DECLS;
    X509_CRL* crl = NULL;
    XFILE fp = XBADFILE;

    ExpectTrue((fp = XFOPEN(file, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntGT(sk_X509_CRL_push(sk, crl), 0);
    if (EXPECT_RESULT() != TEST_SUCCESS)
        X509_CRL_free(crl);
    return EXPECT_RESULT();
}
#endif

int test_wolfSSL_X509_STORE_CTX_set0_crls(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    X509_STORE* store = NULL;
    X509_STORE_CTX* storeCtx = NULL;
    X509* ca = NULL;
    X509* cert = NULL;
    X509* revoked = NULL;
    STACK_OF(X509_CRL)* crls = NULL;
    const char caCert[] = "./certs/ca-cert.pem";
    const char srvCert[] = "./certs/server-cert.pem";
    const char srvRevokedCert[] = "./certs/server-revoked-cert.pem";
    const char crlPem[] = "./certs/crl/crl.pem";
    const char crlRevoked[] = "./certs/crl/crl.revoked";

    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_set_flags(store,
        X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), SSL_SUCCESS);
    ExpectNotNull(cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM));
    ExpectNotNull(revoked = wolfSSL_X509_load_certificate_file(srvRevokedCert,
        SSL_FILETYPE_PEM));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());

    ExpectNotNull(crls = sk_X509_CRL_new_null());
    ExpectIntEQ(test_set0_crls_push_crl(crls, crlPem), TEST_SUCCESS);

    /* No CRLs available. Verification has to fail. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL);

    /* The CRL from the ctx satisfies the CRL check. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);
    X509_STORE_CTX_set0_crls(storeCtx, crls);
    ExpectIntEQ(X509_verify_cert(storeCtx), SSL_SUCCESS);

    /* X509_STORE_CTX_init clears the CRLs again. */
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL);

    /* A revocation in any CRL of the stack is found. */
    ExpectIntEQ(test_set0_crls_push_crl(crls, crlRevoked), TEST_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, revoked, NULL),
        SSL_SUCCESS);
    X509_STORE_CTX_set0_crls(storeCtx, crls);
    ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        WOLFSSL_X509_V_ERR_CERT_REVOKED);

    /* The ctx does not own the CRL stack. Freeing it here must not lead to a
     * double free when the ctx is freed. */
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);
    X509_free(revoked);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
static void* test_add_crl_fail_malloc(size_t size)
{
    (void)size;
    return NULL;
}
#endif

/* Adding a CRL to a store that already holds one fails when copying the new
 * CRL's entries runs out of memory. */
int test_wolfSSL_X509_STORE_add_crl_oom(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
    X509_STORE* store = NULL;
    X509_CRL* crl = NULL;
    X509_CRL* crl2 = NULL;
    XFILE fp = XBADFILE;
    wolfSSL_Malloc_cb prevM = NULL;
    wolfSSL_Free_cb prevF = NULL;
    wolfSSL_Realloc_cb prevR = NULL;

    ExpectNotNull(store = X509_STORE_new());
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.pem", "rb")) != XBADFILE);
    ExpectNotNull(crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectTrue((fp = XFOPEN("./certs/crl/crl.revoked", "rb")) != XBADFILE);
    ExpectNotNull(crl2 = PEM_read_X509_CRL(fp, NULL, NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_GetAllocators(&prevM, &prevF, &prevR), 0);
    ExpectIntEQ(wolfSSL_SetAllocators(test_add_crl_fail_malloc, prevF, prevR),
        0);
    ExpectIntNE(X509_STORE_add_crl(store, crl2), WOLFSSL_SUCCESS);
    (void)wolfSSL_SetAllocators(prevM, prevF, prevR);

    X509_CRL_free(crl2);
    X509_CRL_free(crl);
    X509_STORE_free(store);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_ALL) && \
    defined(HAVE_CRL) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
static STACK_OF(X509_CRL)* test_set0_crls_stack;
static int test_set0_crls_preverify; /* preverify_ok seen at depth 0 */
static int test_set0_crls_error;     /* error seen when preverify_ok == 0 */

/* Mimics OpenVPN's cert_verify_callback. */
static int test_set0_crls_cert_verify_cb(X509_STORE_CTX* ctx, void* arg)
{
    (void)arg;
    X509_STORE_CTX_set0_crls(ctx, test_set0_crls_stack);
    return X509_verify_cert(ctx);
}

/* Mimics OpenVPN's verify_callback. */
static int test_set0_crls_verify_cb(int preverify_ok, X509_STORE_CTX* ctx)
{
    if (X509_STORE_CTX_get_error_depth(ctx) == 0)
        test_set0_crls_preverify = preverify_ok;
    if (!preverify_ok) {
        test_set0_crls_error = X509_STORE_CTX_get_error(ctx);
        return 0;
    }
    return 1;
}

static int test_set0_crls_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    X509_STORE* store = NULL;

    SSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, test_set0_crls_verify_cb);
    SSL_CTX_set_cert_verify_callback(ctx, test_set0_crls_cert_verify_cb, NULL);
    ExpectNotNull(store = SSL_CTX_get_cert_store(ctx));
    ExpectIntEQ(X509_STORE_set_flags(store,
        X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL), SSL_SUCCESS);
    return EXPECT_RESULT();
}
#endif

/* Mimics OpenVPN's CRL handling. OpenVPN keeps the CRLs in its own stack and
 * passes them to each verification with X509_STORE_CTX_set0_crls from the
 * cert verify callback. No CRLs are ever loaded into the store. */
int test_wolfSSL_X509_STORE_CTX_set0_crls_handshake(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && defined(OPENSSL_ALL) && \
    defined(HAVE_CRL) && !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    test_ssl_cbf client_cbs;
    test_ssl_cbf server_cbs;

    /* The CRL stack covers the whole chain. The handshake succeeds and the
     * verify callback sees the good result of the cert verify callback. */
    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.ctx_ready = test_set0_crls_ctx_ready;
    ExpectNotNull(test_set0_crls_stack = sk_X509_CRL_new_null());
    ExpectIntEQ(test_set0_crls_push_crl(test_set0_crls_stack,
        "./certs/crl/crl.pem"), TEST_SUCCESS);
    test_set0_crls_preverify = -1;
    test_set0_crls_error = 0;
    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
        &server_cbs, NULL), TEST_SUCCESS);
    ExpectIntEQ(test_set0_crls_preverify, 1);
    sk_X509_CRL_pop_free(test_set0_crls_stack, X509_CRL_free);
    test_set0_crls_stack = NULL;

    /* The server presents a revoked cert. The handshake has to fail. */
    XMEMSET(&client_cbs, 0, sizeof(client_cbs));
    XMEMSET(&server_cbs, 0, sizeof(server_cbs));
    client_cbs.ctx_ready = test_set0_crls_ctx_ready;
    server_cbs.certPemFile = "./certs/server-revoked-cert.pem";
    server_cbs.keyPemFile = "./certs/server-revoked-key.pem";
    ExpectNotNull(test_set0_crls_stack = sk_X509_CRL_new_null());
    ExpectIntEQ(test_set0_crls_push_crl(test_set0_crls_stack,
        "./certs/crl/crl.pem"), TEST_SUCCESS);
    ExpectIntEQ(test_set0_crls_push_crl(test_set0_crls_stack,
        "./certs/crl/crl.revoked"), TEST_SUCCESS);
    test_set0_crls_preverify = -1;
    test_set0_crls_error = 0;
    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbs,
        &server_cbs, NULL), -1001);
    ExpectIntEQ(test_set0_crls_error, WOLFSSL_X509_V_ERR_CERT_REVOKED);
    sk_X509_CRL_pop_free(test_set0_crls_stack, X509_CRL_free);
    test_set0_crls_stack = NULL;
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_CA_num(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_ECC) && !defined(NO_RSA)
    WOLFSSL_X509_STORE *store = NULL;
    WOLFSSL_X509 *x509_1 = NULL;
    WOLFSSL_X509 *x509_2 = NULL;
    int ca_num = 0;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(x509_1 = wolfSSL_X509_load_certificate_file(svrCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, x509_1), 1);
    ExpectIntEQ(ca_num = wolfSSL_X509_CA_num(store), 1);

    ExpectNotNull(x509_2 = wolfSSL_X509_load_certificate_file(eccCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectIntEQ(wolfSSL_X509_STORE_add_cert(store, x509_2), 1);
    ExpectIntEQ(ca_num = wolfSSL_X509_CA_num(store), 2);

    wolfSSL_X509_free(x509_1);
    wolfSSL_X509_free(x509_2);
    wolfSSL_X509_STORE_free(store);
#endif
    return EXPECT_RESULT();
}

/* Test of X509 store use outside of SSL context w/ CRL lookup (ALWAYS
 * returns 0) */
int test_X509_STORE_No_SSL_CTX(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)  && \
    (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_CRL) && !defined(NO_RSA)

    X509_STORE *     store = NULL;
    X509_STORE_CTX * storeCtx = NULL;
    X509_CRL *       crl = NULL;
    X509 *           ca = NULL;
    X509 *           cert = NULL;
    const char       cliCrlPem[] = "./certs/crl/cliCrl.pem";
    const char       srvCert[] = "./certs/server-cert.pem";
    const char       caCert[] = "./certs/ca-cert.pem";
    const char       caDir[] = "./certs/crl/hash_pem";
    XFILE            fp = XBADFILE;
    X509_LOOKUP *    lookup = NULL;

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    /* Set up store with CA */
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    /* Add CRL lookup directory to store
     * NOTE: test uses ./certs/crl/hash_pem/0fdb2da4.r0, which is a copy
     * of crl.pem */
    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, caDir,
        X509_FILETYPE_PEM, NULL), SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);

    /* Add CRL to store NOT containing the verified certificate, which
     * forces use of the CRL lookup directory */
    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    /* Create verification context outside of an SSL session */
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Perform verification, which should NOT indicate CRL missing due to the
     * store CM's X509 store pointer being NULL */
    ExpectIntNE(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(CRL_MISSING));

    X509_CRL_free(crl);
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

/* Test that SSL_CTX_set_cert_store propagates certificates (including
 * non-self-signed intermediates) into the CertManager, and that certs
 * added to the store after set_cert_store also reach the CertManager.
 * Regression test for ZD 19760 / GitHub PR #8708.
 */
int test_wolfSSL_CTX_set_cert_store(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    X509_STORE* store = NULL;
    X509* rootCa = NULL;
    X509* intCa = NULL;
    X509* int2Ca = NULL;
    X509_STORE_CTX* storeCtx = NULL;
    X509* svrCert = NULL;

    const char caCert[]     = "./certs/ca-cert.pem";
    const char intCaCert[]  = "./certs/intermediate/ca-int-cert.pem";
    const char int2CaCert[] = "./certs/intermediate/ca-int2-cert.pem";
    const char svrIntCert[] = "./certs/intermediate/server-int-cert.pem";

    /* --- Part 1: Add certs to store BEFORE set_cert_store ---
     * Non-self-signed intermediates should be pushed into the CertManager
     * when set_cert_store is called. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(rootCa = wolfSSL_X509_load_certificate_file(caCert,
                    SSL_FILETYPE_PEM));
    ExpectNotNull(intCa = wolfSSL_X509_load_certificate_file(intCaCert,
                    SSL_FILETYPE_PEM));
    ExpectNotNull(int2Ca = wolfSSL_X509_load_certificate_file(int2CaCert,
                    SSL_FILETYPE_PEM));

    ExpectIntEQ(X509_STORE_add_cert(store, rootCa), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_add_cert(store, intCa), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_add_cert(store, int2Ca), SSL_SUCCESS);

    ExpectNotNull(ctx = SSL_CTX_new(TLS_client_method()));

    /* This should push intermediates from store->certs into the CM */
    SSL_CTX_set_cert_store(ctx, store);
    if (SSL_CTX_get_cert_store(ctx) != store) {
        X509_STORE_free(store);
        store = NULL;
    }

    /* After set_cert_store, store->certs and store->trusted should be NULLed
     * to signal CTX ownership */
    if ((store != NULL) && EXPECT_SUCCESS()) {
        ExpectNull(store->certs);
        ExpectNull(store->trusted);
    }

    /* Verify using CertManagerVerify - this only checks the CM, not the
     * store's certs stack, so it proves the intermediates were pushed */
    ExpectIntEQ(wolfSSL_CertManagerVerify(wolfSSL_CTX_GetCertManager(ctx),
                svrIntCert, SSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    /* Also verify using X509_verify_cert for completeness */
    ExpectNotNull(svrCert = wolfSSL_X509_load_certificate_file(svrIntCert,
                    SSL_FILETYPE_PEM));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(X509_STORE_CTX_init(storeCtx,
                    SSL_CTX_get_cert_store(ctx), svrCert, NULL), SSL_SUCCESS);
    #ifdef WOLFSSL_SIGNER_DER_CERT
        ExpectIntEQ(X509_verify_cert(storeCtx), SSL_SUCCESS);
    #else
        /* Without their DER the CAs cannot go on the chain */
        ExpectIntNE(X509_verify_cert(storeCtx), SSL_SUCCESS);
    #endif
    }

    X509_STORE_CTX_free(storeCtx);
    storeCtx = NULL;
    X509_free(svrCert);
    svrCert = NULL;
    SSL_CTX_free(ctx);
    ctx = NULL;
    /* store is freed by SSL_CTX_free */
    store = NULL;

    X509_free(rootCa);
    rootCa = NULL;
    X509_free(intCa);
    intCa = NULL;
    X509_free(int2Ca);
    int2Ca = NULL;

    /* --- Part 2: Add certs to store AFTER set_cert_store ---
     * When store->certs is NULL (CTX-owned), X509_STORE_add_cert should
     * route non-self-signed certs directly to the CertManager. */
    ExpectNotNull(store = X509_STORE_new());
    ExpectNotNull(ctx = SSL_CTX_new(TLS_client_method()));

    /* Attach empty store first */
    SSL_CTX_set_cert_store(ctx, store);
    if (!EXPECT_SUCCESS()) {
        X509_STORE_free(store);
    }

    /* Now add certs after ownership transfer */
    ExpectNotNull(rootCa = wolfSSL_X509_load_certificate_file(caCert,
                    SSL_FILETYPE_PEM));
    ExpectNotNull(intCa = wolfSSL_X509_load_certificate_file(intCaCert,
                    SSL_FILETYPE_PEM));
    ExpectNotNull(int2Ca = wolfSSL_X509_load_certificate_file(int2CaCert,
                    SSL_FILETYPE_PEM));

    ExpectIntEQ(X509_STORE_add_cert(store, rootCa), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_add_cert(store, intCa), SSL_SUCCESS);
    ExpectIntEQ(X509_STORE_add_cert(store, int2Ca), SSL_SUCCESS);

    /* Verify that certs added after set_cert_store are in the CM */
    ExpectIntEQ(wolfSSL_CertManagerVerify(wolfSSL_CTX_GetCertManager(ctx),
                svrIntCert, SSL_FILETYPE_PEM), WOLFSSL_SUCCESS);

    SSL_CTX_free(ctx);
    /* store freed by SSL_CTX_free */
    X509_free(rootCa);
    X509_free(intCa);
    X509_free(int2Ca);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_FILESYSTEM)
static int test_X509_verify_cert_tls_cached_ca_cb(int ok, X509_STORE_CTX* ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);

    return ok || err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
        err == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E);
}
#endif

/* A CA that TLS cached from a peer's chain, after the verify callback waived
 * its missing issuer, is not a trust anchor for X509_verify_cert() on the
 * SSL_CTX's store. OpenSSL never adds the peer's certs to the store. */
int test_X509_verify_cert_tls_cached_ca(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(NO_FILESYSTEM)
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    X509_STORE_CTX* storeCtx = NULL;
    X509* leaf = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfSSLv23_client_method, wolfSSLv23_server_method), 0);
    /* The client trusts no CA of the server's chain. */
    ExpectIntEQ(wolfSSL_CTX_UnloadCAs(ctx_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_certificate_chain_file(ssl_s,
        "./certs/intermediate/server-chain.pem"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_s, "./certs/server-key.pem",
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    wolfSSL_set_verify(ssl_c, WOLFSSL_VERIFY_PEER,
        test_X509_verify_cert_tls_cached_ca_cb);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Issued by an intermediate of the server's chain */
    ExpectNotNull(leaf = X509_load_certificate_file(
        "./certs/intermediate/client-int-cert.pem", SSL_FILETYPE_PEM));
    ExpectNotNull(storeCtx = X509_STORE_CTX_new());
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, SSL_CTX_get_cert_store(ctx_c),
        leaf, NULL), 1);
    ExpectIntNE(X509_verify_cert(storeCtx), 1);
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    X509_STORE_CTX_free(storeCtx);
    X509_free(leaf);
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}
