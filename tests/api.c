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

/* XXX I'm just not happy with this. */

#include <stdlib.h>
#include <cyassl/ssl.h>
#include "unit.h"

#define TEST_FAIL       (-1)
#define TEST_SUCCESS    (0)

/* Use a set of negative numbers for error codes */

static int test_CyaSSL_Init(void);
static int test_CyaSSL_Cleanup(void);
static int test_CyaSSL_Method_Allocators(void);
static int test_CyaSSL_CTX_new(CYASSL_METHOD *method);
static int test_CyaSSL_CTX_user_certificate_file(void);
static int test_CyaSSL_new(void);

/* List of methods found in echoserver.c that I'm skipping for the moment:
 * - CyaSSL_Debugging_ON()
 * - CyaSSL_CTX_set_session_cache_mode()
 * - CyaSSL_CTX_use_certificate_file
 */

int ApiTest(void)
{
    if (test_CyaSSL_Init()) return TEST_FAIL;
    if (test_CyaSSL_Method_Allocators()) return TEST_FAIL;
    if (test_CyaSSL_CTX_new(CyaSSLv3_server_method())) return TEST_FAIL;
    if (test_CyaSSL_CTX_user_certificate_file()) return TEST_FAIL;
    if (test_CyaSSL_new()) return TEST_FAIL;
    if (test_CyaSSL_Cleanup()) return TEST_FAIL;

    return TEST_SUCCESS;
}

int test_CyaSSL_Init(void)
{
    int result = CyaSSL_Init();
    
    if (result) printf("test_CyaSSL_Init(): failed\n");

    return result;
}

static int test_CyaSSL_Cleanup(void)
{
    int result = CyaSSL_Cleanup();

    if (result) printf("test_CyaSSL_Cleanup(): failed\n");

    return result;
}

int test_CyaSSL_Method_Allocators(void)
{
    CYASSL_METHOD *method = NULL;

    method = CyaSSLv3_server_method();
    if (method == NULL)
    {
        printf("test CyaSSLv3_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;

    method = CyaSSLv3_client_method();
    if (method == NULL)
    {
        printf("test CyaSSLv3_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_server_method();  
    if (method == NULL)
    {
        printf("test CyaTLSv1_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_client_method();
    if (method == NULL)
    {
        printf("test CyaTLSv1_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_1_server_method();  
    if (method == NULL)
    {
        printf("test CyaTLSv1_1_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_1_client_method();
    if (method == NULL)
    {
        printf("test CyaTLSv1_1_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_2_server_method();  
    if (method == NULL)
    {
        printf("test CyaTLSv1_2_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaTLSv1_2_client_method();
    if (method == NULL)
    {
        printf("test CyaTLSv1_2_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;

#ifdef CYASSL_DTLS
    method = CyaDTLSv1_client_method();
    if (method == NULL)
    {
        printf("test CyaDTLSv1_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
        
    method = CyaDTLSv1_server_method();
    if (method == NULL)
    {
        printf("test CyaDTLSv1_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
#endif

    method = CyaSSLv23_client_method();
    if (method == NULL)
    {
        printf("test CyaSSLv23_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
  
#ifdef OPENSSL_EXTRA  
    method = CyaSSLv2_client_method();
    if (method == NULL)
    {
        printf("test CyaSSLv2_client_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
    
    method = CyaSSLv2_server_method();
    if (method == NULL)
    {
        printf("test CyaSSLv2_server_method: failed\n");
        return TEST_FAIL;
    }
    free(method);
    method = NULL;
#endif /* OPENSSL_EXTRA */

    return TEST_SUCCESS;
}

int test_CyaSSL_CTX_new(CYASSL_METHOD *method)
{
    if (method != NULL)
    {
        CYASSL_CTX *ctx = NULL;
    
        ctx = CyaSSL_CTX_new(NULL);
        if (ctx != NULL)
        {
            CyaSSL_CTX_free(ctx);
            printf("test_CyaSSL_CTX_new: passed null to new(), failed\n");
            return TEST_FAIL;
        }
    
        ctx = CyaSSL_CTX_new(method);
        if (ctx == NULL)
        {
            printf("test_CyaSSL_CTX_new: failed\n");
            return TEST_FAIL;
        }
        CyaSSL_CTX_free(ctx);
        return TEST_SUCCESS;
    }

    printf("test_CyaSSL_CTX_new: failed, no method\n");
    return TEST_FAIL;
}

int test_CyaSSL_CTX_user_certificate_file(void)
{
    CYASSL_METHOD *method = CyaSSLv23_server_method();
    if (method != NULL)
    {
        CYASSL_CTX *ctx = CyaSSL_CTX_new(method);
        if (ctx != NULL)
        {
            int result;
            
            /* setting all parameters to garbage. this should succeed with failure */
            /* Then set the parameters to legit values but set each item to bogus
               and call again. Finish with a successful success. */
            result = CyaSSL_CTX_use_certificate_file(NULL, NULL, 9999);
            if (result != SSL_FAILURE)
            {
                printf("test_CyaSSL_CTX_user_certificate_file: should have rejected bad params, failure\n");
                return TEST_FAIL;
            }

            result = CyaSSL_CTX_use_certificate_file(NULL, "../certs/server-cert.pem", SSL_FILETYPE_PEM);
            if (result != SSL_FAILURE)
            {
                printf("test_CyaSSL_CTX_user_certificate_file: should have rejected NULL CTX, failure\n");
                return TEST_FAIL;
            }

            result = CyaSSL_CTX_use_certificate_file(ctx, "/dev/null", SSL_FILETYPE_PEM);
            if (result != SSL_FAILURE)
            {
                printf("test_CyaSSL_CTX_user_certificate_file: should have rejected bad filename, failure\n");
                return TEST_FAIL;
            }

            result = CyaSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem", 9999);
            if (result != SSL_FAILURE)
            {
                printf("test_CyaSSL_CTX_user_certificate_file: should have rejected invalid format, failure\n");
                return TEST_FAIL;
            }

            result = CyaSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem", SSL_FILETYPE_PEM);
            if (result != SSL_SUCCESS)
            {
                printf("test_CyaSSL_CTX_user_certificate_file: should have accepted known good params, failure\n");
                return TEST_FAIL;
            }

            CyaSSL_CTX_free(ctx);
            return TEST_SUCCESS;
        }
    }

    printf("test_CyaSSL_new: failed, no method\n");
    return TEST_FAIL;
}

int test_CyaSSL_new(void)
{
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (ctx != NULL)
    {
        int result;
        result = CyaSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem", SSL_FILETYPE_PEM);

	if (result != SSL_SUCCESS)
	{
	    printf("test_CyaSSL_new(): couldn't prepare test\n");
	    return TEST_FAIL;
	}

	CYASSL *ssl;
	/* how about using a context without a certificate? */	
	ssl = CyaSSL_new(NULL);
	ssl = CyaSSL_new(ctx);
    }
    return TEST_SUCCESS;
}

