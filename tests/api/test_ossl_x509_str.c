/* test_ossl_x509_str.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/x509_vfy.h>
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_str.h>

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
    int ret;
    time_t check_time;
    const char* srvCertFile = "./certs/server-cert.pem";
    const char* expiredCertFile = "./certs/test/expired/expired-cert.pem";

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
        wolfSSL_X509_STORE_CTX_free(ctx);
        ctx = NULL;
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
    }
    wolfSSL_X509_STORE_CTX_free(ctx);
    ctx = NULL;
    wolfSSL_X509_STORE_free(store);
    store = NULL;
    wolfSSL_X509_free(cert);
    cert = NULL;
#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM && !NO_ASN_TIME && !NO_RSA */
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
    /* Still needs properly loaded CA, while including it in untrusted
     * list is not an error, it also doesn't count for verify */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted3, 0,
                X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, 0),
            TEST_SUCCESS);
    /* Succeeds because path to loaded CA is available. */
    ExpectIntEQ(test_X509_STORE_untrusted_certs(untrusted4, 1, 0, 1),
            TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)

static int last_errcode;
static int last_errdepth;

static int X509Callback(int ok, X509_STORE_CTX *ctx)
{

    if (!ok) {
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
#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
    const char* filename = "./certs/intermediate/ca_false_intermediate/"
                                                    "test_int_not_cacert.pem";
    const char* srvfile = "./certs/intermediate/ca_false_intermediate/"
                                            "test_sign_bynoca_srv.pem";
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    XFILE fp = XBADFILE;
    X509* cert = NULL;
    STACK_OF(X509)* untrusted = NULL;

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
    ExpectIntEQ(last_errcode, X509_V_ERR_INVALID_CA);

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

    ExpectNotNull((store = wolfSSL_X509_STORE_new()));
    ExpectNotNull((x509 = wolfSSL_X509_load_certificate_file(svrCertFile,
        WOLFSSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, x509), WOLFSSL_SUCCESS);

#ifdef HAVE_CRL
    ExpectIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL),
        WOLFSSL_SUCCESS);
#else
    ExpectIntEQ(X509_STORE_set_flags(store, WOLFSSL_CRL_CHECKALL),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
#endif

    wolfSSL_X509_free(x509);
    wolfSSL_X509_STORE_free(store);
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

