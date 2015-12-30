/* api.c API unit tests
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*----------------------------------------------------------------------------*
 | Includes
 *----------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>   /* wc_ecc_fp_free */
#endif
#include <wolfssl/error-ssl.h>

#include <stdlib.h>
#include <wolfssl/ssl.h>  /* compatibility layer */
#include <wolfssl/test.h>
#include <tests/unit.h>

/* enable testing buffer load functions */
#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

/*----------------------------------------------------------------------------*
 | Constants
 *----------------------------------------------------------------------------*/

#define TEST_SUCCESS    (1)
#define TEST_FAIL       (0)

#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed = "passed";
static const char* failed = "failed";

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
static const char* bogusFile  = "/dev/null";
#endif

/*----------------------------------------------------------------------------*
 | Setup
 *----------------------------------------------------------------------------*/

static int test_wolfSSL_Init(void)
{
    int result;

    printf(testingFmt, "wolfSSL_Init()");
    result = wolfSSL_Init();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}


static int test_wolfSSL_Cleanup(void)
{
    int result;

    printf(testingFmt, "wolfSSL_Cleanup()");
    result = wolfSSL_Cleanup();
    printf(resultFmt, result == SSL_SUCCESS ? passed : failed);

    return result;
}

/*----------------------------------------------------------------------------*
 | Method Allocators
 *----------------------------------------------------------------------------*/

static void test_wolfSSL_Method_Allocators(void)
{
    #define TEST_METHOD_ALLOCATOR(allocator, condition) \
        do {                                            \
            WOLFSSL_METHOD *method;                      \
            condition(method = allocator());            \
            XFREE(method, 0, DYNAMIC_TYPE_METHOD);      \
        } while(0)

    #define TEST_VALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNotNull)

    #define TEST_INVALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNull)

#ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
        TEST_VALID_METHOD_ALLOCATOR(wolfSSLv3_server_method);
        TEST_VALID_METHOD_ALLOCATOR(wolfSSLv3_client_method);
    #endif
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_client_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_1_client_method);
#endif
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_2_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfTLSv1_2_client_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfSSLv23_client_method);

#ifdef WOLFSSL_DTLS
    #ifndef NO_OLD_TLS
        TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_server_method);
        TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_client_method);
    #endif
    TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_2_server_method);
    TEST_VALID_METHOD_ALLOCATOR(wolfDTLSv1_2_client_method);
#endif

#ifdef OPENSSL_EXTRA
    TEST_INVALID_METHOD_ALLOCATOR(wolfSSLv2_server_method);
    TEST_INVALID_METHOD_ALLOCATOR(wolfSSLv2_client_method);
#endif
}

/*----------------------------------------------------------------------------*
 | Context
 *----------------------------------------------------------------------------*/

static void test_wolfSSL_CTX_new(WOLFSSL_METHOD *method)
{
    WOLFSSL_CTX *ctx;

    AssertNull(ctx = wolfSSL_CTX_new(NULL));

    AssertNotNull(method);
    AssertNotNull(ctx = wolfSSL_CTX_new(method));

    wolfSSL_CTX_free(ctx);
}


static void test_wolfSSL_CTX_use_certificate_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_use_certificate_file(NULL, svrCert,
                                                             SSL_FILETYPE_PEM));
    /* invalid cert file */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, bogusFile,
                                                             SSL_FILETYPE_PEM));
    /* invalid cert type */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, svrCert, 9999));

#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(wolfSSL_CTX_use_certificate_file(ctx, svrCert,SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
#endif

    wolfSSL_CTX_free(ctx);
#endif
}


static void test_wolfSSL_CTX_use_PrivateKey_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(NULL, svrKey,
                                                             SSL_FILETYPE_PEM));
    /* invalid key file */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, bogusFile,
                                                             SSL_FILETYPE_PEM));
    /* invalid key type */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, 9999));

    /* success */
#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#endif

    wolfSSL_CTX_free(ctx);
#endif
}


static void test_wolfSSL_CTX_load_verify_locations(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertFalse(wolfSSL_CTX_load_verify_locations(NULL, caCert, 0));

    /* invalid ca file */
    AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, NULL,      0));
    AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, bogusFile, 0));

#ifndef WOLFSSL_TIRTOS
    /* invalid path */
    /* not working... investigate! */
    /* AssertFalse(wolfSSL_CTX_load_verify_locations(ctx, caCert, bogusFile)); */
#endif

    /* success */
    AssertTrue(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_CTX_SetTmpDH_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL,
                dhParam, SSL_FILETYPE_PEM));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx,
                NULL, SSL_FILETYPE_PEM));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx,
                bogusFile, SSL_FILETYPE_PEM));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(ctx, dhParam,
                SSL_FILETYPE_PEM));

    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_CTX_SetTmpDH_buffer(void)
{
#if !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    /* invalid context */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(NULL, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(NULL, NULL,
                0, SSL_FILETYPE_ASN1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(ctx, dsa_key_der_2048,
                sizeof_dsa_key_der_2048, SSL_FILETYPE_ASN1));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_buffer(ctx, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    wolfSSL_CTX_free(ctx);
#endif
}

/*----------------------------------------------------------------------------*
 | SSL
 *----------------------------------------------------------------------------*/

static void test_server_wolfSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx;
    WOLFSSL_CTX *ctx_nocert;
    WOLFSSL *ssl;

    AssertNotNull(ctx_nocert = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    AssertNotNull(ctx        = wolfSSL_CTX_new(wolfSSLv23_server_method()));

    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    /* invalid context */
    AssertNull(ssl = wolfSSL_new(NULL));
    AssertNull(ssl = wolfSSL_new(ctx_nocert));

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_CTX_free(ctx_nocert);
#endif
}


static void test_client_wolfSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx;
    WOLFSSL_CTX *ctx_nocert;
    WOLFSSL *ssl;

    AssertNotNull(ctx_nocert = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    AssertNotNull(ctx        = wolfSSL_CTX_new(wolfSSLv23_client_method()));

    AssertTrue(wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    /* invalid context */
    AssertNull(ssl = wolfSSL_new(NULL));

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx_nocert));
    wolfSSL_free(ssl);

    /* success */
    AssertNotNull(ssl = wolfSSL_new(ctx));
    wolfSSL_free(ssl);

    wolfSSL_CTX_free(ctx);
    wolfSSL_CTX_free(ctx_nocert);
#endif
}

static void test_wolfSSL_SetTmpDH_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCert,
                SSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey,
                SSL_FILETYPE_PEM));
    AssertNotNull(ssl = wolfSSL_new(ctx));

    /* invalid ssl */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(NULL,
                dhParam, SSL_FILETYPE_PEM));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl,
                NULL, SSL_FILETYPE_PEM));
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl,
                bogusFile, SSL_FILETYPE_PEM));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_SetTmpDH_file(ssl, dhParam,
                SSL_FILETYPE_PEM));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_SetTmpDH_buffer(void)
{
#if !defined(NO_CERTS) && !defined(NO_DH)
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    AssertTrue(wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key_der_2048,
                sizeof_server_key_der_2048, SSL_FILETYPE_ASN1));
    AssertNotNull(ssl = wolfSSL_new(ctx));

    /* invalid ssl */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(NULL, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    /* invalid dhParam file */
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(NULL, NULL,
                0, SSL_FILETYPE_ASN1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(ssl, dsa_key_der_2048,
                sizeof_dsa_key_der_2048, SSL_FILETYPE_ASN1));

    /* success */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_SetTmpDH_buffer(ssl, dh_key_der_2048,
                sizeof_dh_key_der_2048, SSL_FILETYPE_ASN1));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    printf("SUCCESS4\n");
#endif
}

/*----------------------------------------------------------------------------*
 | IO
 *----------------------------------------------------------------------------*/
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA)        && !defined(SINGLE_THREADED)
#define HAVE_IO_TESTS_DEPENDENCIES
#endif

/* helper functions */
#ifdef HAVE_IO_TESTS_DEPENDENCIES
static THREAD_RETURN WOLFSSL_THREAD test_server_nofail(void* args)
{
    SOCKET_T sockfd = 0;
    SOCKET_T clientfd = 0;
    word16 port = wolfSSLPort;

    WOLFSSL_METHOD* method = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];
    int idx;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;
    method = wolfSSLv23_server_method();
    ctx = wolfSSL_CTX_new(method);

#if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && \
   !defined(WOLFSSL_SNIFFER) && !defined(WOLFSSL_MDK_SHELL) && \
   !defined(WOLFSSL_TIRTOS)
    port = 0;
#endif

    wolfSSL_CTX_set_verify(ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (wolfSSL_CTX_load_verify_locations(ctx, cliCert, 0) != SSL_SUCCESS)
    {
        /*err_sys("can't load ca file, Please run from wolfSSL home dir");*/
        goto done;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server cert chain file, "
                "Please run from wolfSSL home dir");*/
        goto done;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load server key file, "
                "Please run from wolfSSL home dir");*/
        goto done;
    }

    ssl = wolfSSL_new(ctx);
    tcp_accept(&sockfd, &clientfd, (func_args*)args, port, 0, 0, 0, 1);
    CloseSocket(sockfd);

    wolfSSL_set_fd(ssl, clientfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif

    if (wolfSSL_accept(ssl) != SSL_SUCCESS)
    {
        int err = wolfSSL_get_error(ssl, 0);
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*err_sys("SSL_accept failed");*/
        goto done;
    }

    idx = wolfSSL_read(ssl, input, sizeof(input)-1);
    if (idx > 0) {
        input[idx] = 0;
        printf("Client message: %s\n", input);
    }

    if (wolfSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg))
    {
        /*err_sys("SSL_write failed");*/
#ifdef WOLFSSL_TIRTOS
        return;
#else
        return 0;
#endif
    }

#ifdef WOLFSSL_TIRTOS
    Task_yield();
#endif

done:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    CloseSocket(clientfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

#ifndef WOLFSSL_TIRTOS
    return 0;
#endif
}


static void test_client_nofail(void* args)
{
    SOCKET_T sockfd = 0;

    WOLFSSL_METHOD*  method  = 0;
    WOLFSSL_CTX*     ctx     = 0;
    WOLFSSL*         ssl     = 0;

    char msg[64] = "hello wolfssl!";
    char reply[1024];
    int  input;
    int  msgSz = (int)strlen(msg);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;
    method = wolfSSLv23_client_method();
    ctx = wolfSSL_CTX_new(method);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    if (wolfSSL_CTX_load_verify_locations(ctx, caCert, 0) != SSL_SUCCESS)
    {
        /* err_sys("can't load ca file, Please run from wolfSSL home dir");*/
        goto done2;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client cert file, "
                "Please run from wolfSSL home dir");*/
        goto done2;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM)
            != SSL_SUCCESS)
    {
        /*err_sys("can't load client key file, "
                "Please run from wolfSSL home dir");*/
        goto done2;
    }

    ssl = wolfSSL_new(ctx);
    tcp_connect(&sockfd, wolfSSLIP, ((func_args*)args)->signal->port, 0, ssl);
    wolfSSL_set_fd(ssl, sockfd);
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        int  err = wolfSSL_get_error(ssl, 0);
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("err = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));
        /*printf("SSL_connect failed");*/
        goto done2;
    }

    if (wolfSSL_write(ssl, msg, msgSz) != msgSz)
    {
        /*err_sys("SSL_write failed");*/
        goto done2;
    }

    input = wolfSSL_read(ssl, reply, sizeof(reply)-1);
    if (input > 0)
    {
        reply[input] = 0;
        printf("Server response: %s\n", reply);
    }

done2:
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    CloseSocket(sockfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

    return;
}

/* SNI / ALPN helper functions */
#if defined(HAVE_SNI) || defined(HAVE_ALPN)

static THREAD_RETURN WOLFSSL_THREAD run_wolfssl_server(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(callbacks->method());
    WOLFSSL*     ssl = NULL;
    SOCKET_T    sfd = 0;
    SOCKET_T    cfd = 0;
    word16      port = wolfSSLPort;

    char msg[] = "I hear you fa shizzle!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    ((func_args*)args)->return_code = TEST_FAIL;

#if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && \
   !defined(WOLFSSL_SNIFFER) && !defined(WOLFSSL_MDK_SHELL) && \
   !defined(WOLFSSL_TIRTOS)
    port = 0;
#endif

    wolfSSL_CTX_set_verify(ctx,
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif


    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx, cliCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = wolfSSL_new(ctx);

    tcp_accept(&sfd, &cfd, (func_args*)args, port, 0, 0, 0, 1);
    CloseSocket(sfd);

    wolfSSL_set_fd(ssl, cfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
        SetDH(ssl);  /* will repick suites with DHE, higher priority than PSK */
    #endif
#endif

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    /* AssertIntEQ(SSL_SUCCESS, wolfSSL_accept(ssl)); */
    if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));

    } else {
        if (0 < (idx = wolfSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Client message: %s\n", input);
        }

        AssertIntEQ(len, wolfSSL_write(ssl, msg, len));
#ifdef WOLFSSL_TIRTOS
        Task_yield();
#endif
        wolfSSL_shutdown(ssl);
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(cfd);

    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

#ifndef WOLFSSL_TIRTOS
    return 0;
#endif
}


static void run_wolfssl_client(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(callbacks->method());
    WOLFSSL*     ssl = NULL;
    SOCKET_T    sfd = 0;

    char msg[] = "hello wolfssl server!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;

#ifdef OPENSSL_EXTRA
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_load_verify_locations(ctx, caCert, 0));

    AssertIntEQ(SSL_SUCCESS,
               wolfSSL_CTX_use_certificate_file(ctx, cliCert, SSL_FILETYPE_PEM));

    AssertIntEQ(SSL_SUCCESS,
                 wolfSSL_CTX_use_PrivateKey_file(ctx, cliKey, SSL_FILETYPE_PEM));

    if (callbacks->ctx_ready)
        callbacks->ctx_ready(ctx);

    ssl = wolfSSL_new(ctx);
    tcp_connect(&sfd, wolfSSLIP, ((func_args*)args)->signal->port, 0, ssl);
    wolfSSL_set_fd(ssl, sfd);

    if (callbacks->ssl_ready)
        callbacks->ssl_ready(ssl);

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        printf("error = %d, %s\n", err, wolfSSL_ERR_error_string(err, buffer));

    } else {
        AssertIntEQ(len, wolfSSL_write(ssl, msg, len));

        if (0 < (idx = wolfSSL_read(ssl, input, sizeof(input)-1))) {
            input[idx] = 0;
            printf("Server response: %s\n", input);
        }
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    CloseSocket(sfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif
}

#endif /* defined(HAVE_SNI) || defined(HAVE_ALPN) */
#endif /* io tests dependencies */


static void test_wolfSSL_read_write(void)
{
#ifdef HAVE_IO_TESTS_DEPENDENCIES
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
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    StartTCP();
    InitTcpReady(&ready);

    server_args.signal = &ready;
    client_args.signal = &ready;

    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    test_client_nofail(&client_args);
    join_thread(serverThread);

    AssertTrue(client_args.return_code);
    AssertTrue(server_args.return_code);

    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

#endif
}

/*----------------------------------------------------------------------------*
 | TLS extensions tests
 *----------------------------------------------------------------------------*/

#if defined(HAVE_SNI) || defined(HAVE_ALPN)
/* connection test runner */
static void test_wolfSSL_client_server(callback_functions* client_callbacks,
                                       callback_functions* server_callbacks)
{
#ifdef HAVE_IO_TESTS_DEPENDENCIES
    tcp_ready ready;
    func_args client_args;
    func_args server_args;
    THREAD_TYPE serverThread;

    StartTCP();

    client_args.callbacks = client_callbacks;
    server_args.callbacks = server_callbacks;

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    /* RUN Server side */
    InitTcpReady(&ready);
    server_args.signal = &ready;
    client_args.signal = &ready;
    start_thread(run_wolfssl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* RUN Client side */
    run_wolfssl_client(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);
#ifdef WOLFSSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#else
    (void)client_callbacks;
    (void)server_callbacks;
#endif
}

#endif /* defined(HAVE_SNI) || defined(HAVE_ALPN) */


#ifdef HAVE_SNI
static void test_wolfSSL_UseSNI_params(void)
{
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* invalid [ctx|ssl] */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(NULL, 0, "ctx", 3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    NULL, 0, "ssl", 3));
    /* invalid type */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx, -1, "ctx", 3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    ssl, -1, "ssl", 3));
    /* invalid data */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx,  0, NULL,  3));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSNI(    ssl,  0, NULL,  3));
    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseSNI(ctx,  0, "ctx", 3));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseSNI(    ssl,  0, "ssl", 3));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

/* BEGIN of connection tests callbacks */
static void use_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    AssertIntEQ(SSL_SUCCESS,
        wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.wolfssl.com", 15));
}

static void use_SNI_at_ssl(WOLFSSL* ssl)
{
    AssertIntEQ(SSL_SUCCESS,
             wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.wolfssl.com", 15));
}

static void different_SNI_at_ssl(WOLFSSL* ssl)
{
    AssertIntEQ(SSL_SUCCESS,
             wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "ww2.wolfssl.com", 15));
}

static void use_SNI_WITH_CONTINUE_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                              WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
}

static void use_SNI_WITH_FAKE_ANSWER_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                                WOLFSSL_SNI_ANSWER_ON_MISMATCH);
}

static void use_MANDATORY_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    use_SNI_at_ctx(ctx);
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
                                                  WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void use_MANDATORY_SNI_at_ssl(WOLFSSL* ssl)
{
    use_SNI_at_ssl(ssl);
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
                                                  WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void use_PSEUDO_MANDATORY_SNI_at_ctx(WOLFSSL_CTX* ctx)
{
    use_SNI_at_ctx(ctx);
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
                 WOLFSSL_SNI_ANSWER_ON_MISMATCH | WOLFSSL_SNI_ABORT_ON_ABSENCE);
}

static void verify_UNKNOWN_SNI_on_server(WOLFSSL* ssl)
{
    AssertIntEQ(UNKNOWN_SNI_HOST_NAME_E, wolfSSL_get_error(ssl, 0));
}

static void verify_SNI_ABSENT_on_server(WOLFSSL* ssl)
{
    AssertIntEQ(SNI_ABSENT_ERROR, wolfSSL_get_error(ssl, 0));
}

static void verify_SNI_no_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*) &type; /* to be overwriten */

    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertNotNull(request);
    AssertIntEQ(0, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNull(request);
}

static void verify_SNI_real_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = NULL;

    AssertIntEQ(WOLFSSL_SNI_REAL_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertIntEQ(15, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ("www.wolfssl.com", request);
}

static void verify_SNI_fake_matching(WOLFSSL* ssl)
{
    byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = NULL;

    AssertIntEQ(WOLFSSL_SNI_FAKE_MATCH, wolfSSL_SNI_Status(ssl, type));
    AssertIntEQ(15, wolfSSL_SNI_GetRequest(ssl, type, (void**) &request));
    AssertNotNull(request);
    AssertStrEQ("ww2.wolfssl.com", request);
}

static void verify_FATAL_ERROR_on_client(WOLFSSL* ssl)
{
    AssertIntEQ(FATAL_ERROR, wolfSSL_get_error(ssl, 0));
}
/* END of connection tests callbacks */

static void test_wolfSSL_UseSNI_connection(void)
{
    unsigned long i;
    callback_functions callbacks[] = {
        /* success case at ctx */
        {0, use_SNI_at_ctx, 0, 0},
        {0, use_SNI_at_ctx, 0, verify_SNI_real_matching},

        /* success case at ssl */
        {0, 0, use_SNI_at_ssl, 0},
        {0, 0, use_SNI_at_ssl, verify_SNI_real_matching},

        /* default missmatch behavior */
        {0, 0, different_SNI_at_ssl, verify_FATAL_ERROR_on_client},
        {0, 0, use_SNI_at_ssl,       verify_UNKNOWN_SNI_on_server},

        /* continue on missmatch */
        {0, 0, different_SNI_at_ssl,         0},
        {0, 0, use_SNI_WITH_CONTINUE_at_ssl, verify_SNI_no_matching},

        /* fake answer on missmatch */
        {0, 0, different_SNI_at_ssl,            0},
        {0, 0, use_SNI_WITH_FAKE_ANSWER_at_ssl, verify_SNI_fake_matching},

        /* sni abort - success */
        {0, use_SNI_at_ctx,           0, 0},
        {0, use_MANDATORY_SNI_at_ctx, 0, verify_SNI_real_matching},

        /* sni abort - abort when absent (ctx) */
        {0, 0,                        0, verify_FATAL_ERROR_on_client},
        {0, use_MANDATORY_SNI_at_ctx, 0, verify_SNI_ABSENT_on_server},

        /* sni abort - abort when absent (ssl) */
        {0, 0, 0,                        verify_FATAL_ERROR_on_client},
        {0, 0, use_MANDATORY_SNI_at_ssl, verify_SNI_ABSENT_on_server},

        /* sni abort - success when overwriten */
        {0, 0, 0, 0},
        {0, use_MANDATORY_SNI_at_ctx, use_SNI_at_ssl, verify_SNI_no_matching},

        /* sni abort - success when allowing missmatches */
        {0, 0, different_SNI_at_ssl, 0},
        {0, use_PSEUDO_MANDATORY_SNI_at_ctx, 0, verify_SNI_fake_matching},
    };

    for (i = 0; i < sizeof(callbacks) / sizeof(callback_functions); i += 2) {
        callbacks[i    ].method = wolfSSLv23_client_method;
        callbacks[i + 1].method = wolfSSLv23_server_method;
        test_wolfSSL_client_server(&callbacks[i], &callbacks[i + 1]);
    }
}

static void test_wolfSSL_SNI_GetFromBuffer(void)
{
    byte buffer[] = { /* www.paypal.com */
        0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03, 0x5c,
        0xc4, 0xb3, 0x8c, 0x87, 0xef, 0xa4, 0x09, 0xe0, 0x02, 0xab, 0x86, 0xca,
        0x76, 0xf0, 0x9e, 0x01, 0x65, 0xf6, 0xa6, 0x06, 0x13, 0x1d, 0x0f, 0xa5,
        0x79, 0xb0, 0xd4, 0x77, 0x22, 0xeb, 0x1a, 0x00, 0x00, 0x16, 0x00, 0x6b,
        0x00, 0x67, 0x00, 0x39, 0x00, 0x33, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
        0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x21,
        0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77,
        0x2e, 0x70, 0x61, 0x79, 0x70, 0x61, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x00,
        0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01
    };

    byte buffer2[] = { /* api.textmate.org */
        0x16, 0x03, 0x01, 0x00, 0xc6, 0x01, 0x00, 0x00, 0xc2, 0x03, 0x03, 0x52,
        0x8b, 0x7b, 0xca, 0x69, 0xec, 0x97, 0xd5, 0x08, 0x03, 0x50, 0xfe, 0x3b,
        0x99, 0xc3, 0x20, 0xce, 0xa5, 0xf6, 0x99, 0xa5, 0x71, 0xf9, 0x57, 0x7f,
        0x04, 0x38, 0xf6, 0x11, 0x0b, 0xb8, 0xd3, 0x00, 0x00, 0x5e, 0x00, 0xff,
        0xc0, 0x24, 0xc0, 0x23, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x07, 0xc0, 0x08,
        0xc0, 0x28, 0xc0, 0x27, 0xc0, 0x14, 0xc0, 0x13, 0xc0, 0x11, 0xc0, 0x12,
        0xc0, 0x26, 0xc0, 0x25, 0xc0, 0x2a, 0xc0, 0x29, 0xc0, 0x05, 0xc0, 0x04,
        0xc0, 0x02, 0xc0, 0x03, 0xc0, 0x0f, 0xc0, 0x0e, 0xc0, 0x0c, 0xc0, 0x0d,
        0x00, 0x3d, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x35,
        0x00, 0x0a, 0x00, 0x67, 0x00, 0x6b, 0x00, 0x33, 0x00, 0x39, 0x00, 0x16,
        0x00, 0xaf, 0x00, 0xae, 0x00, 0x8d, 0x00, 0x8c, 0x00, 0x8a, 0x00, 0x8b,
        0x00, 0xb1, 0x00, 0xb0, 0x00, 0x2c, 0x00, 0x3b, 0x01, 0x00, 0x00, 0x3b,
        0x00, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x00, 0x10, 0x61, 0x70, 0x69,
        0x2e, 0x74, 0x65, 0x78, 0x74, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x6f, 0x72,
        0x67, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00,
        0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x0c, 0x00,
        0x0a, 0x05, 0x01, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03
    };

    byte buffer3[] = { /* no sni extension */
        0x16, 0x03, 0x03, 0x00, 0x4d, 0x01, 0x00, 0x00, 0x49, 0x03, 0x03, 0xea,
        0xa1, 0x9f, 0x60, 0xdd, 0x52, 0x12, 0x13, 0xbd, 0x84, 0x34, 0xd5, 0x1c,
        0x38, 0x25, 0xa8, 0x97, 0xd2, 0xd5, 0xc6, 0x45, 0xaf, 0x1b, 0x08, 0xe4,
        0x1e, 0xbb, 0xdf, 0x9d, 0x39, 0xf0, 0x65, 0x00, 0x00, 0x16, 0x00, 0x6b,
        0x00, 0x67, 0x00, 0x39, 0x00, 0x33, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
        0x00, 0x2f, 0x00, 0x05, 0x00, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x0a,
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x02, 0x01
    };

    byte buffer4[] = { /* last extension has zero size */
        0x16, 0x03, 0x01, 0x00, 0xba, 0x01, 0x00, 0x00,
        0xb6, 0x03, 0x03, 0x83, 0xa3, 0xe6, 0xdc, 0x16, 0xa1, 0x43, 0xe9, 0x45,
        0x15, 0xbd, 0x64, 0xa9, 0xb6, 0x07, 0xb4, 0x50, 0xc6, 0xdd, 0xff, 0xc2,
        0xd3, 0x0d, 0x4f, 0x36, 0xb4, 0x41, 0x51, 0x61, 0xc1, 0xa5, 0x9e, 0x00,
        0x00, 0x28, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
        0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x07, 0xc0, 0x11,
        0x00, 0x33, 0x00, 0x32, 0x00, 0x39, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35,
        0x00, 0x0a, 0x00, 0x05, 0x00, 0x04, 0x01, 0x00, 0x00, 0x65, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00,
        0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
        0x00, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x1b, 0x00, 0x19, 0x06,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x08, 0x73, 0x70, 0x64, 0x79, 0x2f,
        0x33, 0x2e, 0x31, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
        0x75, 0x50, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x05, 0x01, 0x02,
        0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x04, 0x02, 0x02, 0x02, 0x00,
        0x12, 0x00, 0x00
    };

    byte buffer5[] = { /* SSL v2.0 client hello */
        0x00, 0x2b, 0x01, 0x03, 0x01, 0x00, 0x09, 0x00, 0x00,
        /* dummy bytes bellow, just to pass size check */
        0xb6, 0x03, 0x03, 0x83, 0xa3, 0xe6, 0xdc, 0x16, 0xa1, 0x43, 0xe9, 0x45,
        0x15, 0xbd, 0x64, 0xa9, 0xb6, 0x07, 0xb4, 0x50, 0xc6, 0xdd, 0xff, 0xc2,
        0xd3, 0x0d, 0x4f, 0x36, 0xb4, 0x41, 0x51, 0x61, 0xc1, 0xa5, 0x9e, 0x00,
    };

    byte result[32] = {0};
    word32 length   = 32;

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer4, sizeof(buffer4),
                                                           0, result, &length));

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer3, sizeof(buffer3),
                                                           0, result, &length));

    AssertIntEQ(0, wolfSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           1, result, &length));

    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[0] = 0x16;

    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[1] = 0x03;

    AssertIntEQ(SNI_UNSUPPORTED, wolfSSL_SNI_GetFromBuffer(buffer,
                                           sizeof(buffer), 0, result, &length));
    buffer[2] = 0x03;

    AssertIntEQ(INCOMPLETE_DATA, wolfSSL_SNI_GetFromBuffer(buffer,
                                           sizeof(buffer), 0, result, &length));
    buffer[4] = 0x64;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("www.paypal.com", (const char*) result);

    length = 32;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("api.textmate.org", (const char*) result);

    /* SSL v2.0 tests */
    AssertIntEQ(SNI_UNSUPPORTED, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[2] = 0x02;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[2] = 0x01; buffer5[6] = 0x08;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));

    buffer5[6] = 0x09; buffer5[8] = 0x01;
    AssertIntEQ(BUFFER_ERROR, wolfSSL_SNI_GetFromBuffer(buffer5,
                                          sizeof(buffer5), 0, result, &length));
}

#endif /* HAVE_SNI */

static void test_wolfSSL_UseSNI(void)
{
#ifdef HAVE_SNI
    test_wolfSSL_UseSNI_params();
    test_wolfSSL_UseSNI_connection();

    test_wolfSSL_SNI_GetFromBuffer();
#endif
}

static void test_wolfSSL_UseMaxFragment(void)
{
#ifdef HAVE_MAX_FRAGMENT
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(NULL, WOLFSSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(    NULL, WOLFSSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx, 0));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx, 6));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(ssl, 0));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseMaxFragment(ssl, 6));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseMaxFragment(ctx,  WOLFSSL_MFL_2_13));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseMaxFragment(    ssl,  WOLFSSL_MFL_2_13));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_UseTruncatedHMAC(void)
{
#ifdef HAVE_TRUNCATED_HMAC
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseTruncatedHMAC(NULL));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseTruncatedHMAC(NULL));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, wolfSSL_CTX_UseTruncatedHMAC(ctx));
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseTruncatedHMAC(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

static void test_wolfSSL_UseSupportedCurve(void)
{
#ifdef HAVE_SUPPORTED_CURVES
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

#ifndef NO_WOLFSSL_CLIENT
    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                      wolfSSL_CTX_UseSupportedCurve(NULL, WOLFSSL_ECC_SECP256R1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_UseSupportedCurve(ctx,  0));

    AssertIntNE(SSL_SUCCESS,
                          wolfSSL_UseSupportedCurve(NULL, WOLFSSL_ECC_SECP256R1));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseSupportedCurve(ssl,  0));

    /* success case */
    AssertIntEQ(SSL_SUCCESS,
                       wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1));
    AssertIntEQ(SSL_SUCCESS,
                           wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1));
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
}

#ifdef HAVE_ALPN

static void verify_ALPN_FATAL_ERROR_on_client(WOLFSSL* ssl)
{
    AssertIntEQ(UNKNOWN_ALPN_PROTOCOL_NAME_E, wolfSSL_get_error(ssl, 0));
}

static void use_ALPN_all(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_all_continue(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));
}

static void use_ALPN_one(WOLFSSL* ssl)
{
    /* spdy/2 */
    char proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_unknown(WOLFSSL* ssl)
{
    /* http/2.0 */
    char proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x32, 0x2e, 0x30};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));
}

static void use_ALPN_unknown_continue(WOLFSSL* ssl)
{
    /* http/2.0 */
    char proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x32, 0x2e, 0x30};

    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, proto, sizeof(proto),
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));
}

static void verify_ALPN_not_matching_spdy3(WOLFSSL* ssl)
{
    /* spdy/3 */
    char nego_proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};

    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntNE(1, sizeof(nego_proto) == protoSz);
    AssertIntNE(0, XMEMCMP(nego_proto, proto, sizeof(nego_proto)));
}

static void verify_ALPN_not_matching_continue(WOLFSSL* ssl)
{
    char *proto = NULL;
    word16 protoSz = 0;

    AssertIntEQ(SSL_ALPN_NOT_FOUND,
                wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, 0 == protoSz);
    AssertIntEQ(1, NULL == proto);
}

static void verify_ALPN_matching_http1(WOLFSSL* ssl)
{
    /* http/1.1 */
    char nego_proto[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, sizeof(nego_proto) == protoSz);
    AssertIntEQ(0, XMEMCMP(nego_proto, proto, protoSz));
}

static void verify_ALPN_matching_spdy2(WOLFSSL* ssl)
{
    /* spdy/2 */
    char nego_proto[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};
    char *proto;
    word16 protoSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetProtocol(ssl, &proto, &protoSz));

    /* check value */
    AssertIntEQ(1, sizeof(nego_proto) == protoSz);
    AssertIntEQ(0, XMEMCMP(nego_proto, proto, protoSz));
}

static void verify_ALPN_client_list(WOLFSSL* ssl)
{
    /* http/1.1,spdy/1,spdy/2,spdy/3 */
    char alpn_list[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x31, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x32, 0x2c,
                        0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    char    *clist = NULL;
    word16  clistSz = 0;

    AssertIntEQ(SSL_SUCCESS, wolfSSL_ALPN_GetPeerProtocol(ssl, &clist,
                                                          &clistSz));

    /* check value */
    AssertIntEQ(1, sizeof(alpn_list) == clistSz);
    AssertIntEQ(0, XMEMCMP(alpn_list, clist, clistSz));

    XFREE(clist, 0, DYNAMIC_TYPE_TLSX);
}

static void test_wolfSSL_UseALPN_connection(void)
{
    unsigned long i;
    callback_functions callbacks[] = {
        /* success case same list */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_all, verify_ALPN_matching_http1},

        /* success case only one for server */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_one, verify_ALPN_matching_spdy2},

        /* success case only one for client */
        {0, 0, use_ALPN_one, 0},
        {0, 0, use_ALPN_all, verify_ALPN_matching_spdy2},

        /* success case none for client */
        {0, 0, 0, 0},
        {0, 0, use_ALPN_all, 0},

        /* success case missmatch behavior but option 'continue' set */
        {0, 0, use_ALPN_all_continue, verify_ALPN_not_matching_continue},
        {0, 0, use_ALPN_unknown_continue, 0},

        /* success case read protocol send by client */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_one, verify_ALPN_client_list},

        /* missmatch behavior with same list
         * the first and only this one must be taken */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_all, verify_ALPN_not_matching_spdy3},

        /* default missmatch behavior */
        {0, 0, use_ALPN_all, 0},
        {0, 0, use_ALPN_unknown, verify_ALPN_FATAL_ERROR_on_client},
    };

    for (i = 0; i < sizeof(callbacks) / sizeof(callback_functions); i += 2) {
        callbacks[i    ].method = wolfSSLv23_client_method;
        callbacks[i + 1].method = wolfSSLv23_server_method;
        test_wolfSSL_client_server(&callbacks[i], &callbacks[i + 1]);
    }
}

static void test_wolfSSL_UseALPN_params(void)
{
    /* "http/1.1" */
    char http1[] = {0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
    /* "spdy/1" */
    char spdy1[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x31};
    /* "spdy/2" */
    char spdy2[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x32};
    /* "spdy/3" */
    char spdy3[] = {0x73, 0x70, 0x64, 0x79, 0x2f, 0x33};
    char buff[256];
    word32 idx;

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                wolfSSL_UseALPN(NULL, http1, sizeof(http1),
                                WOLFSSL_ALPN_FAILED_ON_MISMATCH));
    AssertIntNE(SSL_SUCCESS, wolfSSL_UseALPN(ssl, NULL, 0,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* success case */
    /* http1 only */
    AssertIntEQ(SSL_SUCCESS,
                wolfSSL_UseALPN(ssl, http1, sizeof(http1),
                                WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* http1, spdy1 */
    memcpy(buff, http1, sizeof(http1));
    idx = sizeof(http1);
    buff[idx++] = ',';
    memcpy(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* http1, spdy2, spdy1 */
    memcpy(buff, http1, sizeof(http1));
    idx = sizeof(http1);
    buff[idx++] = ',';
    memcpy(buff+idx, spdy2, sizeof(spdy2));
    idx += sizeof(spdy2);
    buff[idx++] = ',';
    memcpy(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_FAILED_ON_MISMATCH));

    /* spdy3, http1, spdy2, spdy1 */
    memcpy(buff, spdy3, sizeof(spdy3));
    idx = sizeof(spdy3);
    buff[idx++] = ',';
    memcpy(buff+idx, http1, sizeof(http1));
    idx += sizeof(http1);
    buff[idx++] = ',';
    memcpy(buff+idx, spdy2, sizeof(spdy2));
    idx += sizeof(spdy2);
    buff[idx++] = ',';
    memcpy(buff+idx, spdy1, sizeof(spdy1));
    idx += sizeof(spdy1);
    AssertIntEQ(SSL_SUCCESS, wolfSSL_UseALPN(ssl, buff, idx,
                                             WOLFSSL_ALPN_CONTINUE_ON_MISMATCH));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}
#endif /* HAVE_ALPN  */

static void test_wolfSSL_UseALPN(void)
{
#ifdef HAVE_ALPN
    test_wolfSSL_UseALPN_connection();
    test_wolfSSL_UseALPN_params();
#endif
}

/*----------------------------------------------------------------------------*
 | Main
 *----------------------------------------------------------------------------*/

void ApiTest(void)
{
    printf(" Begin API Tests\n");
    test_wolfSSL_Init();

    test_wolfSSL_Method_Allocators();
    test_wolfSSL_CTX_new(wolfSSLv23_server_method());
    test_wolfSSL_CTX_use_certificate_file();
    test_wolfSSL_CTX_use_PrivateKey_file();
    test_wolfSSL_CTX_load_verify_locations();
    test_wolfSSL_CTX_SetTmpDH_file();
    test_wolfSSL_CTX_SetTmpDH_buffer();
    test_server_wolfSSL_new();
    test_client_wolfSSL_new();
    test_wolfSSL_SetTmpDH_file();
    test_wolfSSL_SetTmpDH_buffer();
    test_wolfSSL_read_write();

    /* TLS extensions tests */
    test_wolfSSL_UseSNI();
    test_wolfSSL_UseMaxFragment();
    test_wolfSSL_UseTruncatedHMAC();
    test_wolfSSL_UseSupportedCurve();
    test_wolfSSL_UseALPN();

    test_wolfSSL_Cleanup();
    printf(" End API Tests\n");
}
