/* api.c API unit tests
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#include <stdlib.h>
#include <cyassl/ssl.h>
#include <cyassl/test.h>
#include <tests/unit.h>

#define TEST_FAIL       (-1)
#define TEST_SUCCESS    (0)

static int test_CyaSSL_Init(void);
static int test_CyaSSL_Cleanup(void);
static int test_CyaSSL_Method_Allocators(void);
static int test_CyaSSL_CTX_new(CYASSL_METHOD *method);
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int test_CyaSSL_CTX_use_certificate_file(void);
static int test_CyaSSL_CTX_use_PrivateKey_file(void);
static int test_CyaSSL_CTX_load_verify_locations(void);
#ifndef NO_RSA
static int test_server_CyaSSL_new(void);
static int test_client_CyaSSL_new(void);
static int test_CyaSSL_read_write(void);
#endif /* NO_RSA */
#endif /* NO_FILESYSTEM */
#ifdef HAVE_SNI
static void test_CyaSSL_UseSNI(void);
#endif /* HAVE_SNI */
#ifdef HAVE_MAX_FRAGMENT
static void test_CyaSSL_UseMaxFragment(void);
#endif /* HAVE_MAX_FRAGMENT */
#ifdef HAVE_TRUNCATED_HMAC
static void test_CyaSSL_UseTruncatedHMAC(void);
#endif /* HAVE_TRUNCATED_HMAC */

/* test function helpers */
static int test_method(CYASSL_METHOD *method, const char *name);
#ifdef OPENSSL_EXTRA
static int test_method2(CYASSL_METHOD *method, const char *name);
#endif
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static int test_ucf(CYASSL_CTX *ctx, const char* file, int type,
    int cond, const char* name);
static int test_upkf(CYASSL_CTX *ctx, const char* file, int type,
    int cond, const char* name);
static int test_lvl(CYASSL_CTX *ctx, const char* file, const char* path,
    int cond, const char* name);

THREAD_RETURN CYASSL_THREAD test_server_nofail(void*);
void test_client_nofail(void*);

void run_cyassl_client(void* args);
THREAD_RETURN CYASSL_THREAD run_cyassl_server(void* args);

void test_CyaSSL_client_server(callback_functions* client_callbacks,
                                          callback_functions* server_callbacks);

static const char* bogusFile  = "/dev/null";
#endif

#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed     = "passed";
static const char* failed     = "failed";

/* List of methods found in echoserver.c that I'm skipping for the moment:
 * - CyaSSL_CTX_set_session_cache_mode()
 */

int ApiTest(void)
{
    printf(" Begin API Tests\n");
    test_CyaSSL_Init();
    test_CyaSSL_Method_Allocators();
    test_CyaSSL_CTX_new(CyaSSLv23_server_method());
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    test_CyaSSL_CTX_use_certificate_file();
    test_CyaSSL_CTX_use_PrivateKey_file();
    test_CyaSSL_CTX_load_verify_locations();
#ifndef NO_RSA
    test_server_CyaSSL_new();
    test_client_CyaSSL_new();
    test_CyaSSL_read_write();
#endif /* NO_RSA */
#endif /* NO_FILESYSTEM */
#ifdef HAVE_SNI
    test_CyaSSL_UseSNI();
#endif /* HAVE_SNI */
#ifdef HAVE_MAX_FRAGMENT
    test_CyaSSL_UseMaxFragment();
#endif /* HAVE_MAX_FRAGMENT */
#ifdef HAVE_TRUNCATED_HMAC
    test_CyaSSL_UseTruncatedHMAC();
#endif /* HAVE_TRUNCATED_HMAC */
    test_CyaSSL_Cleanup();
    printf(" End API Tests\n");

    return TEST_SUCCESS;
}

int test_CyaSSL_Init(void)
{
    int result;

    printf(testingFmt, "CyaSSL_Init()");
    result = CyaSSL_Init();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}

static int test_CyaSSL_Cleanup(void)
{
    int result;

    printf(testingFmt, "CyaSSL_Cleanup()");
    result = CyaSSL_Cleanup();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}

int test_method(CYASSL_METHOD *method, const char *name)
{
    printf(testingFmt, name);
    if (method == NULL)
    {
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    XFREE(method, 0, DYNAMIC_TYPE_METHOD);
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

#ifdef OPENSSL_EXTRA
int test_method2(CYASSL_METHOD *method, const char *name)
{
    printf(testingFmt, name);
    if (method != NULL)
    {
        XFREE(method, 0, DYNAMIC_TYPE_METHOD);
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}
#endif

int test_CyaSSL_Method_Allocators(void)
{
#ifndef NO_OLD_TLS
    test_method(CyaSSLv3_server_method(), "CyaSSLv3_server_method()");
    test_method(CyaSSLv3_client_method(), "CyaSSLv3_client_method()");
    test_method(CyaTLSv1_server_method(), "CyaTLSv1_server_method()");
    test_method(CyaTLSv1_client_method(), "CyaTLSv1_client_method()");
    test_method(CyaTLSv1_1_server_method(), "CyaTLSv1_1_server_method()");
    test_method(CyaTLSv1_1_client_method(), "CyaTLSv1_1_client_method()");
#endif /* NO_OLD_TLS */
    test_method(CyaTLSv1_2_server_method(), "CyaTLSv1_2_server_method()");
    test_method(CyaTLSv1_2_client_method(), "CyaTLSv1_2_client_method()");
    test_method(CyaSSLv23_client_method(), "CyaSSLv23_client_method()");

#ifdef CYASSL_DTLS
    test_method(CyaDTLSv1_server_method(), "CyaDTLSv1_server_method()");
    test_method(CyaDTLSv1_client_method(), "CyaDTLSv1_client_method()");
#endif /* CYASSL_DTLS */

#ifdef OPENSSL_EXTRA
    test_method2(CyaSSLv2_server_method(), "CyaSSLv2_server_method()");
    test_method2(CyaSSLv2_client_method(), "CyaSSLv2_client_method()");
#endif /* OPENSSL_EXTRA */

    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_new(CYASSL_METHOD *method)
{
    if (method != NULL)
    {
        CYASSL_CTX *ctx;
    
        printf(testingFmt, "CyaSSL_CTX_new(NULL)");
        ctx = CyaSSL_CTX_new(NULL);
        if (ctx != NULL)
        {
            CyaSSL_CTX_free(ctx);
            printf(resultFmt, failed);
        }
        else
            printf(resultFmt, passed);
    
        printf(testingFmt, "CyaSSL_CTX_new(method)");
        ctx = CyaSSL_CTX_new(method);
        if (ctx == NULL)
        {
            printf(resultFmt, failed);
            XFREE(method, 0, DYNAMIC_TYPE_METHOD);
            /* free the method data. if this was successful, freeing
               the CTX frees the method. */
        }
        else
        {
            CyaSSL_CTX_free(ctx);
            printf(resultFmt, passed);
        }
    }
    else
        printf("test_CyaSSL_CTX_new() called without method\n");

    return TEST_SUCCESS;
}

#ifdef HAVE_TLS_EXTENSIONS
#ifdef HAVE_SNI
static void use_SNI_at_ctx(CYASSL_CTX* ctx)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "www.yassl.com";

    AssertIntEQ(0, CyaSSL_CTX_UseSNI(ctx, type, (void *) name, XSTRLEN(name)));
}

static void use_SNI_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "www.yassl.com";

    AssertIntEQ(0, CyaSSL_UseSNI(ssl, type, (void *) name, XSTRLEN(name)));
}

static void different_SNI_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "ww2.yassl.com";

    AssertIntEQ(0, CyaSSL_UseSNI(ssl, type, (void *) name, XSTRLEN(name)));
}

static void use_SNI_WITH_CONTINUE_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;

    use_SNI_at_ssl(ssl);

    CyaSSL_SNI_SetOptions(ssl, type, CYASSL_SNI_CONTINUE_ON_MISMATCH);
}

static void use_SNI_WITH_FAKE_ANSWER_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;

    use_SNI_at_ssl(ssl);

    CyaSSL_SNI_SetOptions(ssl, type, CYASSL_SNI_ANSWER_ON_MISMATCH);
}

static void verify_SNI_abort_on_client(CYASSL* ssl)
{
    /* FATAL_ERROR */
    AssertIntEQ(-213, CyaSSL_get_error(ssl, 0));
}

static void verify_SNI_abort_on_server(CYASSL* ssl)
{
    /* UNKNOWN_SNI_HOST_NAME_E */
    AssertIntEQ(-281, CyaSSL_get_error(ssl, 0));
}

static void verify_SNI_no_matching(CYASSL* ssl)
{
    byte  type    = CYASSL_SNI_HOST_NAME;
    char* request = (char*) &type; /* to be overwriten */

    AssertIntEQ(CYASSL_SNI_NO_MATCH, CyaSSL_SNI_Status(ssl, type));

    AssertNotNull(request);
    AssertIntEQ(0, CyaSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNull(request);
}

static void verify_SNI_real_matching(CYASSL* ssl)
{
    byte   type    = CYASSL_SNI_HOST_NAME;
    char*  request = NULL;
    char   name[]  = "www.yassl.com";
    word16 length  = XSTRLEN(name);

    AssertIntEQ(CYASSL_SNI_REAL_MATCH, CyaSSL_SNI_Status(ssl, type));

    AssertIntEQ(length, CyaSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ(name, request);
}

static void verify_SNI_fake_matching(CYASSL* ssl)
{
    byte   type    = CYASSL_SNI_HOST_NAME;
    char*  request = NULL;
    char   name[]  = "ww2.yassl.com";
    word16 length  = XSTRLEN(name);

    AssertIntEQ(CYASSL_SNI_FAKE_MATCH, CyaSSL_SNI_Status(ssl, type));

    AssertIntEQ(length, CyaSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ(name, request);
}

void test_CyaSSL_UseSNI(void)
{
    callback_functions client_callbacks = {CyaSSLv23_client_method, 0, 0, 0};
    callback_functions server_callbacks = {CyaSSLv23_server_method, 0, 0, 0};

    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(0, CyaSSL_CTX_UseSNI(NULL, 0, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntNE(0, CyaSSL_UseSNI(    NULL, 0, (void *) "ssl", XSTRLEN("ssl")));
    AssertIntNE(0, CyaSSL_CTX_UseSNI(ctx, -1, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntNE(0, CyaSSL_UseSNI(    ssl, -1, (void *) "ssl", XSTRLEN("ssl")));
    AssertIntNE(0, CyaSSL_CTX_UseSNI(ctx,  0, (void *) NULL,  XSTRLEN("ctx")));
    AssertIntNE(0, CyaSSL_UseSNI(    ssl,  0, (void *) NULL,  XSTRLEN("ssl")));

    /* success case */
    AssertIntEQ(0, CyaSSL_CTX_UseSNI(ctx,  0, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntEQ(0, CyaSSL_UseSNI(    ssl,  0, (void *) "ssl", XSTRLEN("ssl")));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);

    /* Testing success case at ctx */
    client_callbacks.ctx_ready = server_callbacks.ctx_ready = use_SNI_at_ctx;
    server_callbacks.on_result = verify_SNI_real_matching;

    test_CyaSSL_client_server(&client_callbacks, &server_callbacks);

    /* Testing success case at ssl */
    client_callbacks.ctx_ready = server_callbacks.ctx_ready = NULL;
    client_callbacks.ssl_ready = server_callbacks.ssl_ready = use_SNI_at_ssl;

    test_CyaSSL_client_server(&client_callbacks, &server_callbacks);

    /* Testing default mismatch behaviour */
    client_callbacks.ssl_ready = different_SNI_at_ssl;
    client_callbacks.on_result = verify_SNI_abort_on_client;
    server_callbacks.on_result = verify_SNI_abort_on_server;

    test_CyaSSL_client_server(&client_callbacks, &server_callbacks);
    client_callbacks.on_result = NULL;

    /* Testing continue on mismatch */
    client_callbacks.ssl_ready = different_SNI_at_ssl;
    server_callbacks.ssl_ready = use_SNI_WITH_CONTINUE_at_ssl;
    server_callbacks.on_result = verify_SNI_no_matching;

    test_CyaSSL_client_server(&client_callbacks, &server_callbacks);

    /* Testing fake answer on mismatch */
    server_callbacks.ssl_ready = use_SNI_WITH_FAKE_ANSWER_at_ssl;
    server_callbacks.on_result = verify_SNI_fake_matching;

    test_CyaSSL_client_server(&client_callbacks, &server_callbacks);
}
#endif /* HAVE_SNI */

#ifdef HAVE_MAX_FRAGMENT
static void test_CyaSSL_UseMaxFragment(void)
{
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(0, CyaSSL_CTX_UseMaxFragment(NULL, CYASSL_MFL_2_9));
    AssertIntNE(0, CyaSSL_UseMaxFragment(    NULL, CYASSL_MFL_2_9));
    AssertIntNE(0, CyaSSL_CTX_UseMaxFragment(ctx, 0));
    AssertIntNE(0, CyaSSL_CTX_UseMaxFragment(ctx, 6));
    AssertIntNE(0, CyaSSL_UseMaxFragment(ssl, 0));
    AssertIntNE(0, CyaSSL_UseMaxFragment(ssl, 6));

    /* success case */
    AssertIntEQ(0, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_9));
    AssertIntEQ(0, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_10));
    AssertIntEQ(0, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_11));
    AssertIntEQ(0, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_12));
    AssertIntEQ(0, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_13));
    AssertIntEQ(0, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_9));
    AssertIntEQ(0, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_10));
    AssertIntEQ(0, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_11));
    AssertIntEQ(0, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_12));
    AssertIntEQ(0, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_13));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
}
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
static void test_CyaSSL_UseTruncatedHMAC(void)
{
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(0, CyaSSL_CTX_UseTruncatedHMAC(NULL));
    AssertIntNE(0, CyaSSL_UseTruncatedHMAC(NULL));

    /* success case */
    AssertIntEQ(0, CyaSSL_CTX_UseTruncatedHMAC(ctx));
    AssertIntEQ(0, CyaSSL_UseTruncatedHMAC(ssl));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
}
#endif /* HAVE_TRUNCATED_HMAC */

#endif /* HAVE_TLS_EXTENSIONS */

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
/* Helper for testing CyaSSL_CTX_use_certificate_file() */
int test_ucf(CYASSL_CTX *ctx, const char* file, int type, int cond,
    const char* name)
{
    int result;

    printf(testingFmt, name);
    result = CyaSSL_CTX_use_certificate_file(ctx, file, type);
    if (result != cond)
    {
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_use_certificate_file(void)
{
    CYASSL_METHOD *method;
    CYASSL_CTX *ctx;

    method = CyaSSLv23_server_method();
    if (method == NULL)
    {
        printf("test_CyaSSL_CTX_use_certificate_file() cannot create method\n");
        return TEST_FAIL;
    }

    ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("test_CyaSSL_CTX_use_certificate_file() cannot create context\n");
        XFREE(method, 0, DYNAMIC_TYPE_METHOD);
        return TEST_FAIL;
    }

    /* setting all parameters to garbage. this should succeed with
        failure */
    /* Then set the parameters to legit values but set each item to
        bogus and call again. Finish with a successful success. */
    /* If the build is configured to not have RSA, loading the
       certificate files will fail. */

    test_ucf(NULL, NULL, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(NULL, NULL, 9999)");
/*  test_ucf(NULL, svrCert, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(NULL, svrCert, SSL_FILETYPE_PEM)");*/
    test_ucf(ctx, bogusFile, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(ctx, bogusFile, SSL_FILETYPE_PEM)");
    test_ucf(ctx, svrCert, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(ctx, svrCert, 9999)");
#ifndef NO_RSA
    test_ucf(ctx, svrCert, SSL_FILETYPE_PEM, SSL_SUCCESS,
        "CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)");
#else
    test_ucf(ctx, svrCert, SSL_FILETYPE_PEM, SSL_FAILURE,
        "NO_RSA: CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)");
#endif

    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

/* Helper for testing CyaSSL_CTX_use_PrivateKey_file() */
int test_upkf(CYASSL_CTX *ctx, const char* file, int type, int cond,
    const char* name)
{
    int result;

    printf(testingFmt, name);
    result = CyaSSL_CTX_use_PrivateKey_file(ctx, file, type);
    if (result != cond)
    {
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_use_PrivateKey_file(void)
{
    CYASSL_METHOD *method;
    CYASSL_CTX *ctx;

    method = CyaSSLv23_server_method();
    if (method == NULL)
    {
        printf("test_CyaSSL_CTX_use_PrivateKey_file() cannot create method\n");
        return TEST_FAIL;
    }

    ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("test_CyaSSL_CTX_use_PrivateKey_file() cannot create context\n");
        XFREE(method, 0, DYNAMIC_TYPE_METHOD);
        return TEST_FAIL;
    }

    test_upkf(NULL, NULL, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_PrivateKey_file(NULL, NULL, 9999)");
/*  test_upkf(NULL, svrKey, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_PrivateKey_file(NULL, svrKey, SSL_FILETYPE_PEM)");*/
    test_upkf(ctx, bogusFile, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_PrivateKey_file(ctx, bogusFile, SSL_FILETYPE_PEM)");
    test_upkf(ctx, svrKey, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, 9999)");
    test_upkf(ctx, svrKey, SSL_FILETYPE_PEM, SSL_SUCCESS,
        "CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)");

    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

/* Helper for testing CyaSSL_CTX_load_verify_locations() */
int test_lvl(CYASSL_CTX *ctx, const char* file, const char* path, int cond,
    const char* name)
{
    int result;

    printf(testingFmt, name);
    /*
     * CyaSSL_CTX_load_verify_locations() returns SSL_SUCCESS (1) for 
     * success, SSL_FAILURE (0) for a non-specific failure, or a specific
     * failure code (<0). Need to normalize the return code to 1 or 0.
     */
    result = CyaSSL_CTX_load_verify_locations(ctx, file, path) >= SSL_SUCCESS;
    if (result != cond)
    {
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_load_verify_locations(void)
{
    CYASSL_METHOD *method;
    CYASSL_CTX *ctx;

    method = CyaSSLv23_client_method();
    if (method == NULL)
    {
        printf("test_CyaSSL_CTX_load_verify_locations() cannot create method\n");
        return TEST_FAIL;
    }

    ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("test_CyaSSL_CTX_load_verify_locations() cannot create context\n");
        free(method);
        return TEST_FAIL;
    }
    
    test_lvl(NULL, NULL, NULL, SSL_FAILURE,
        "CyaSSL_CTX_load_verify_locations(NULL, NULL, NULL)");
    test_lvl(ctx, NULL, NULL, SSL_FAILURE,
        "CyaSSL_CTX_load_verify_locations(ctx, NULL, NULL)");
    test_lvl(NULL, caCert, NULL, SSL_FAILURE,
        "CyaSSL_CTX_load_verify_locations(ctx, NULL, NULL)");
    test_lvl(ctx, caCert, bogusFile, SSL_FAILURE,
        "CyaSSL_CTX_load_verify_locations(ctx, caCert, bogusFile)");
    /* Add a test for the certs directory path loading. */
    /* There is a leak here. If you load a second cert, the first one
       is lost. */
#ifndef NO_RSA
    test_lvl(ctx, caCert, 0, SSL_SUCCESS,
        "CyaSSL_CTX_load_verify_locations(ctx, caCert, 0)");
#else
    test_lvl(ctx, caCert, 0, SSL_FAILURE,
        "NO_RSA: CyaSSL_CTX_load_verify_locations(ctx, caCert, 0)");
#endif

    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

#ifndef NO_RSA

int test_server_CyaSSL_new(void)
{
    int result;
    CYASSL_CTX *ctx;
    CYASSL_CTX *ctx_nocert;
    CYASSL *ssl;

    ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (ctx == NULL)
    {
        printf("test_server_CyaSSL_new() cannot create context\n");
        return TEST_FAIL;
    }

    result = CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM);
    if (result == SSL_FAILURE)
    {
        printf("test_server_CyaSSL_new() cannot obtain certificate\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    result = CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM);
    if (result == SSL_FAILURE)
    {
        printf("test_server_CyaSSL_new() cannot obtain key\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    ctx_nocert = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (ctx_nocert == NULL)
    {
        printf("test_server_CyaSSL_new() cannot create bogus context\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    printf(testingFmt, "CyaSSL_new(NULL) server");
    ssl = CyaSSL_new(NULL);
    if (ssl != NULL)
    {
        printf(resultFmt, failed);
        CyaSSL_free(ssl);
    }
    else
        printf(resultFmt, passed);

    printf(testingFmt, "CyaSSL_new(ctx_nocert) server");
    ssl = CyaSSL_new(ctx_nocert);
    if (ssl != NULL)
    {
        printf(resultFmt, failed);
        CyaSSL_free(ssl);
    }
    else
        printf(resultFmt, passed);

    printf(testingFmt, "CyaSSL_new(ctx) server");
    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
        printf(resultFmt, failed);
    else
    {
        printf(resultFmt, passed);
        CyaSSL_free(ssl);
    }
    
    CyaSSL_CTX_free(ctx_nocert);
    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

int test_client_CyaSSL_new(void)
{
    int result;
    CYASSL_CTX *ctx;
    CYASSL_CTX *ctx_nocert;
    CYASSL *ssl;

    ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    if (ctx == NULL)
    {
        printf("test_client_CyaSSL_new() cannot create context\n");
        return TEST_FAIL;
    }

    result = CyaSSL_CTX_load_verify_locations(ctx, caCert, 0);
    if (result == SSL_FAILURE)
    {
        printf("test_client_CyaSSL_new() cannot obtain certificate\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    ctx_nocert = CyaSSL_CTX_new(CyaSSLv23_client_method());
    if (ctx_nocert == NULL)
    {
        printf("test_client_CyaSSL_new() cannot create bogus context\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    printf(testingFmt, "CyaSSL_new(NULL) client");
    ssl = CyaSSL_new(NULL);
    if (ssl != NULL)
    {
        printf(resultFmt, failed);
        CyaSSL_free(ssl);
    }
    else
        printf(resultFmt, passed);

    printf(testingFmt, "CyaSSL_new(ctx_nocert) client");
    ssl = CyaSSL_new(ctx_nocert);
    if (ssl == NULL)
        printf(resultFmt, failed);
    else
    {
        printf(resultFmt, passed);
        CyaSSL_free(ssl);
    }

    printf(testingFmt, "CyaSSL_new(ctx) client");
    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
        printf(resultFmt, failed);
    else
    {
        printf(resultFmt, passed);
        CyaSSL_free(ssl);
    }

    CyaSSL_CTX_free(ctx_nocert);
    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}


static int test_CyaSSL_read_write(void)
{
    /* The unit testing for read and write shall happen simutaneously, since
     * one can't do anything with one without the other. (Except for a failure
     * test case.) This function will call all the others that will set up,
     * execute, and report their test findings.
     *
     * Set up the success case first. This function will become the template
     * for the other tests. This should eventually be renamed
     *
     * The success case isn't interesting, how can this fail?
     * - Do not give the client context a CA certificate. The connect should
     *   fail. Do not need server for this?
     * - Using NULL for the ssl object on server. Do not need client for this.
     * - Using NULL for the ssl object on client. Do not need server for this.
     * - Good ssl objects for client and server. Client write() without server
     *   read().
     * - Good ssl objects for client and server. Server write() without client
     *   read().
     * - Forgetting the password callback?
    */
    int test_result = TEST_SUCCESS;
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

    StartTCP();

    InitTcpReady(&ready);
    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    test_client_nofail(&client_args);
    join_thread(serverThread);

    if (client_args.return_code != TEST_SUCCESS)
    {
        printf(resultFmt, "client failure");
        test_result = TEST_FAIL;
    }
    if (server_args.return_code != TEST_SUCCESS)
    {
        printf(resultFmt, "server failure");
        test_result = TEST_FAIL;
    }

    FreeTcpReady(&ready);

    return test_result;
};

#endif

THREAD_RETURN CYASSL_THREAD test_server_nofail(void* args)
{
    SOCKET_T sockfd = 0;
    SOCKET_T clientfd = 0;

    CYASSL_METHOD* method = 0;
    CYASSL_CTX* ctx = 0;
    CYASSL* ssl = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];
    int idx;
   
    ((func_args*)args)->return_code = TEST_FAIL;
    method = CyaSSLv23_server_method();
    ctx = CyaSSL_CTX_new(method);

    CyaSSL_CTX_set_verify(ctx,
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    CyaSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (CyaSSL_CTX_load_verify_locations(ctx, cliCert, 0) != SSL_SUCCESS)
    {
        /*err_sys("can't load ca file, Please run from CyaSSL home dir");*/
        goto done;
    }
    if (CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server cert chain file, "
                "Please run from CyaSSL home dir");*/
        goto done;
    }
    if (CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server key file, "
                "Please run from CyaSSL home dir");*/
        goto done;
    }
    ssl = CyaSSL_new(ctx);
    tcp_accept(&sockfd, &clientfd, (func_args*)args, yasslPort, 0, 0);
    CloseSocket(sockfd);

    CyaSSL_set_fd(ssl, clientfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA)
        CyaSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #else
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif
    if (CyaSSL_accept(ssl) != SSL_SUCCESS)
    {
        int err = CyaSSL_get_error(ssl, 0);
        char buffer[CYASSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_accept failed");*/
        goto done;
    }

    idx = CyaSSL_read(ssl, input, sizeof(input)-1);
    if (idx > 0) {
        input[idx] = 0;
        printf("Client message: %s\n", input);
    }
    
    if (CyaSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
    {
        /*err_sys("SSL_write failed");*/
        return 0;
    }

done:
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    
    CloseSocket(clientfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;
    return 0;
}

void test_client_nofail(void* args)
{
    SOCKET_T sockfd = 0;

    CYASSL_METHOD*  method  = 0;
    CYASSL_CTX*     ctx     = 0;
    CYASSL*         ssl     = 0;

    char msg[64] = "hello cyassl!";
    char reply[1024];
    int  input;
    int  msgSz = (int)strlen(msg);

    ((func_args*)args)->return_code = TEST_FAIL;
    method = CyaSSLv23_client_method();
    ctx = CyaSSL_CTX_new(method);

#ifdef OPENSSL_EXTRA
    CyaSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (CyaSSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
    {
        /* err_sys("can't load ca file, Please run from CyaSSL home dir");*/
        goto done2;
    }
    if (CyaSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client cert file, "
                "Please run from CyaSSL home dir");*/
        goto done2;
    }
    if (CyaSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client key file, "
                "Please run from CyaSSL home dir");*/
        goto done2;
    }

    tcp_connect(&sockfd, yasslIP, yasslPort, 0);

    ssl = CyaSSL_new(ctx);
    CyaSSL_set_fd(ssl, sockfd);
    if (CyaSSL_connect(ssl) != SSL_SUCCESS)
    {
        int  err = CyaSSL_get_error(ssl, 0);
        char buffer[CYASSL_MAX_ERROR_SZ];
        printf("err = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));
        /*printf("SSL_connect failed");*/
        goto done2;
    }

    if (CyaSSL_write(ssl, msg, msgSz) != msgSz)
    {
        /*err_sys("SSL_write failed");*/
        goto done2;
    }

    input = CyaSSL_read(ssl, reply, sizeof(reply)-1);
    if (input > 0)
    {
        reply[input] = 0;
        printf("Server response: %s\n", reply);
    }

done2:
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    
    CloseSocket(sockfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;
    return;
}

void run_cyassl_client(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    CYASSL_CTX* ctx = CyaSSL_CTX_new(callbacks->method());
    CYASSL*     ssl = NULL;
    SOCKET_T    sfd = 0;

    char msg[] = "hello cyassl server!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

    ((func_args*)args)->return_code = TEST_FAIL;

#ifdef OPENSSL_EXTRA
    CyaSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_load_verify_locations(ctx, caCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               CyaSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 CyaSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    tcp_connect(&sfd, yasslIP, yasslPort, 0);

    ssl = CyaSSL_new(ctx);
    CyaSSL_set_fd(ssl, sfd);

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    if (CyaSSL_connect(ssl) != SSL_SUCCESS) {
        int err = CyaSSL_get_error(ssl, 0);
        char buffer[CYASSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));

    } else {
        AssertIntEQ(len, CyaSSL_write(ssl, msg, len));

        if (0 < (idx = CyaSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Server response: %s\n", input);
        }
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CloseSocket(sfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;
}

THREAD_RETURN CYASSL_THREAD run_cyassl_server(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    CYASSL_CTX* ctx = CyaSSL_CTX_new(callbacks->method());
    CYASSL*     ssl = NULL;
    SOCKET_T    sfd = 0;
    SOCKET_T    cfd = 0;

    char msg[] = "I hear you fa shizzle!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

    ((func_args*)args)->return_code = TEST_FAIL;

    CyaSSL_CTX_set_verify(ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    CyaSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif


    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_load_verify_locations(ctx, cliCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = CyaSSL_new(ctx);

    tcp_accept(&sfd, &cfd, (func_args*)args, yasslPort, 0, 0);
    CloseSocket(sfd);

    CyaSSL_set_fd(ssl, cfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA)
        CyaSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #else
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    /* AssertIntEQ(SSL_SUCCESS, CyaSSL_accept(ssl)); */
    if (CyaSSL_accept(ssl) != SSL_SUCCESS) {
        int err = CyaSSL_get_error(ssl, 0);
        char buffer[CYASSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));

    } else {
        if (0 < (idx = CyaSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Client message: %s\n", input);
        }

        AssertIntEQ(len, CyaSSL_write(ssl, msg, len));

        CyaSSL_shutdown(ssl);
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CloseSocket(cfd);

    ((func_args*)args)->return_code = TEST_SUCCESS;

    return 0;
}

void test_CyaSSL_client_server(callback_functions* client_callbacks,
                                           callback_functions* server_callbacks)
{
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

    StartTCP();

    client_args.callbacks = client_callbacks;
    server_args.callbacks = server_callbacks;

    /* RUN Server side */
    InitTcpReady(&ready);
    server_args.signal = &ready;
    start_thread(run_cyassl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* RUN Client side */
    run_cyassl_client(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);
}

#endif /* NO_FILESYSTEM */
