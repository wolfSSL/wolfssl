/* api.c API unit tests
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
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

#include <stdlib.h>
#include <cyassl/ssl.h>
#include "unit.h"

#define TEST_FAIL       (-1)
#define TEST_SUCCESS    (0)

static int test_CyaSSL_Init(void);
static int test_CyaSSL_Cleanup(void);
static int test_CyaSSL_Method_Allocators(void);
static int test_meth(CYASSL_METHOD *meth, const char *name);
static int test_meth2(CYASSL_METHOD *meth, const char *name);
static int test_CyaSSL_CTX_new(CYASSL_METHOD *method);
static int test_CyaSSL_CTX_use_certificate_file(void);
static int test_cert(CYASSL_CTX *ctx, const char* path, int type, int cond,
    const char* name);
static int test_CyaSSL_new(void);

static const char* svrCert    = "./certs/server-cert.pem";
static const char* svrKey     = "./certs/server-key.pem";
static const char* bogusCert  = "/dev/null";
static const char* testingFmt = "   %s:";
static const char* resultFmt  = " %s\n";
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
    test_CyaSSL_CTX_use_certificate_file();
    test_CyaSSL_new();
    test_CyaSSL_Cleanup();
    printf(" End API Tests\n");

    return TEST_SUCCESS;
}

int test_CyaSSL_Init(void)
{
    printf(testingFmt, "CyaSSL_Init()");

    int result = CyaSSL_Init();
    
    printf(resultFmt, result ? failed : passed);

    return result;
}

static int test_CyaSSL_Cleanup(void)
{
    printf(testingFmt, "CyaSSL_Cleanup()");

    int result = CyaSSL_Cleanup();

    printf(resultFmt, result ? failed : passed);

    return result;
}

int test_meth(CYASSL_METHOD *meth, const char *name)
{
    printf(testingFmt, name);
    if (meth == NULL)
    {
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    free(meth);
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

int test_meth2(CYASSL_METHOD *meth, const char *name)
{
    printf(testingFmt, name);
    if (meth != NULL)
    {
        free(meth);
        printf(resultFmt, failed);
        return TEST_FAIL;
    }
    printf(resultFmt, passed);
    return TEST_SUCCESS;
}

int test_CyaSSL_Method_Allocators(void)
{
    test_meth(CyaSSLv3_server_method(), "CyaSSLv3_server_method()");
    test_meth(CyaSSLv3_client_method(), "CyaSSLv3_client_method()");
    test_meth(CyaTLSv1_server_method(), "CyaTLSv1_server_method()");
    test_meth(CyaTLSv1_client_method(), "CyaTLSv1_client_method()");
    test_meth(CyaTLSv1_1_server_method(), "CyaTLSv1_1_server_method()");
    test_meth(CyaTLSv1_1_client_method(), "CyaTLSv1_1_client_method()");
    test_meth(CyaTLSv1_2_server_method(), "CyaTLSv1_2_server_method()");
    test_meth(CyaTLSv1_2_client_method(), "CyaTLSv1_2_client_method()");
    test_meth(CyaSSLv23_client_method(), "CyaSSLv23_client_method()");

#ifdef CYASSL_DTLS
    test_meth(CyaDTLSv1_server_method(), "CyaDTLSv1_server_method()");
    test_meth(CyaDTLSv1_client_method(), "CyaDTLSv1_client_method()");
#endif /* CYASSL_DTLS */

#ifdef OPENSSL_EXTRA
    test_meth2(CyaSSLv2_server_method(), "CyaSSLv2_server_method()");
    test_meth2(CyaSSLv2_client_method(), "CyaSSLv2_client_method()");
#endif /* OPENSSL_EXTRA */

    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_new(CYASSL_METHOD *method)
{
    if (method != NULL)
    {
        CYASSL_CTX *ctx = NULL;
    
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
            free(method);
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

int test_cert(CYASSL_CTX *ctx, const char* path, int type, int cond,
    const char* name)
{
    printf(testingFmt, name);
    int result = CyaSSL_CTX_use_certificate_file(ctx, path, type);
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
    CYASSL_METHOD *method = CyaSSLv23_server_method();
    if (method == NULL)
    {
        printf("test_CyaSSL_CTX_use_certificate_file() cannot create method\n");
        return TEST_FAIL;
    }

    CYASSL_CTX *ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL)
    {
        printf("test_CyaSSL_CTX_use_certificate_file() cannot create context\n");
        free(method);
        return TEST_FAIL;
    }

    /* setting all parameters to garbage. this should succeed with
        failure */
    /* Then set the parameters to legit values but set each item to
        bogus and call again. Finish with a successful success. */
#if 0
    /* This test case is known to fail with a segfault */
    test_cert(NULL, NULL, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(NULL, NULL, 9999)");
    test_cert(NULL, svrCert, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(NULL, svrCert, SSL_FILETYPE_PEM)");
#endif
    test_cert(ctx, bogusCert, SSL_FILETYPE_PEM, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(ctx, bogusCert, SSL_FILETYPE_PEM)");
    test_cert(ctx, svrCert, 9999, SSL_FAILURE,
        "CyaSSL_CTX_use_certificate_file(ctx, svrCert, 9999)");
    test_cert(ctx, svrCert, SSL_FILETYPE_PEM, SSL_SUCCESS,
        "CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)");

    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

int test_CyaSSL_new(void)
{
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (ctx == NULL)
    {
        printf("test_CyaSSL_new() cannot create context\n");
        return TEST_FAIL;
    }

    int result;

    result = CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM);
    if (result == SSL_FAILURE)
    {
        printf("test_CyaSSL_new() cannot obtain certificate\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    result = CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM);
    if (result == SSL_FAILURE)
    {
        printf("test_CyaSSL_new() cannot obtain key\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    CYASSL_CTX *bad_ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (bad_ctx == NULL)
    {
        printf("test_CyaSSL_new() cannot create bogus context\n");
        CyaSSL_CTX_free(ctx);
        return TEST_FAIL;
    }

    CYASSL *ssl;

    printf(testingFmt, "CyaSSL_new(NULL)");
    ssl = CyaSSL_new(NULL);
    if (ssl != NULL)
    {
        printf(resultFmt, failed);
        CyaSSL_free(ssl);
    }
    else
        printf(resultFmt, passed);

    printf(testingFmt, "CyaSSL_new(bad_ctx)");
    ssl = CyaSSL_new(bad_ctx);
    if (ssl != NULL)
    {
        printf(resultFmt, failed);
        CyaSSL_free(ssl);
    }
    else
        printf(resultFmt, passed);
    
    printf(testingFmt, "CyaSSL_new(ctx)");
    ssl = CyaSSL_new(ctx);
    if (ssl == NULL)
        printf(resultFmt, failed);
    else
    {
        printf(resultFmt, passed);
        CyaSSL_free(ssl);
    }
    
    CyaSSL_CTX_free(bad_ctx);
    CyaSSL_CTX_free(ctx);
    return TEST_SUCCESS;
}

