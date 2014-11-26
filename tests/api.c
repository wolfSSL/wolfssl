/* api.c API unit tests
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*----------------------------------------------------------------------------*
 | Includes
 *----------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>
#ifdef HAVE_ECC
    #include <cyassl/ctaocrypt/ecc.h>   /* ecc_fp_free */
#endif
#include <cyassl/error-ssl.h>

#include <stdlib.h>
#include <cyassl/ssl.h>
#include <cyassl/test.h>
#include <tests/unit.h>

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

static int test_CyaSSL_Init(void)
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

/*----------------------------------------------------------------------------*
 | Method Allocators
 *----------------------------------------------------------------------------*/

static void test_CyaSSL_Method_Allocators(void)
{
    #define TEST_METHOD_ALLOCATOR(allocator, condition) \
        do {                                            \
            CYASSL_METHOD *method;                      \
            condition(method = allocator());            \
            XFREE(method, 0, DYNAMIC_TYPE_METHOD);      \
        } while(0)

    #define TEST_VALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNotNull)

    #define TEST_INVALID_METHOD_ALLOCATOR(a) \
            TEST_METHOD_ALLOCATOR(a, AssertNull)

#ifndef NO_OLD_TLS
    TEST_VALID_METHOD_ALLOCATOR(CyaSSLv3_server_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaSSLv3_client_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_client_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_1_client_method);
#endif
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_2_server_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaTLSv1_2_client_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaSSLv23_client_method);

#ifdef CYASSL_DTLS
    TEST_VALID_METHOD_ALLOCATOR(CyaDTLSv1_server_method);
    TEST_VALID_METHOD_ALLOCATOR(CyaDTLSv1_client_method);
#endif

#ifdef OPENSSL_EXTRA
    TEST_INVALID_METHOD_ALLOCATOR(CyaSSLv2_server_method);
    TEST_INVALID_METHOD_ALLOCATOR(CyaSSLv2_client_method);
#endif
}

/*----------------------------------------------------------------------------*
 | Context
 *----------------------------------------------------------------------------*/

static void test_CyaSSL_CTX_new(CYASSL_METHOD *method)
{
    CYASSL_CTX *ctx;
    
    AssertNull(ctx = CyaSSL_CTX_new(NULL));
    
    AssertNotNull(method);
    AssertNotNull(ctx = CyaSSL_CTX_new(method));

    CyaSSL_CTX_free(ctx);
}


static void test_CyaSSL_CTX_use_certificate_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    CYASSL_CTX *ctx;

    AssertNotNull(ctx = CyaSSL_CTX_new(CyaSSLv23_server_method()));

    /* invalid context */
    AssertFalse(CyaSSL_CTX_use_certificate_file(NULL, svrCert, 
                                                             SSL_FILETYPE_PEM));
    /* invalid cert file */
    AssertFalse(CyaSSL_CTX_use_certificate_file(ctx, bogusFile, 
                                                             SSL_FILETYPE_PEM));
    /* invalid cert type */
    AssertFalse(CyaSSL_CTX_use_certificate_file(ctx, svrCert, 9999));

#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(CyaSSL_CTX_use_certificate_file(ctx, svrCert,SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
#endif

    CyaSSL_CTX_free(ctx);
#endif
}


static void test_CyaSSL_CTX_use_PrivateKey_file(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    CYASSL_CTX *ctx;

    AssertNotNull(ctx = CyaSSL_CTX_new(CyaSSLv23_server_method()));

    /* invalid context */
    AssertFalse(CyaSSL_CTX_use_PrivateKey_file(NULL, svrKey, 
                                                             SSL_FILETYPE_PEM));
    /* invalid key file */
    AssertFalse(CyaSSL_CTX_use_PrivateKey_file(ctx, bogusFile, 
                                                             SSL_FILETYPE_PEM));
    /* invalid key type */
    AssertFalse(CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, 9999));

    /* success */
#ifdef NO_RSA
    /* rsa needed */
    AssertFalse(CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#else
    /* success */
    AssertTrue(CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));
#endif

    CyaSSL_CTX_free(ctx);
#endif
}


static void test_CyaSSL_CTX_load_verify_locations(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    CYASSL_CTX *ctx;

    AssertNotNull(ctx = CyaSSL_CTX_new(CyaSSLv23_client_method()));
    
    /* invalid context */
    AssertFalse(CyaSSL_CTX_load_verify_locations(NULL, caCert, 0));

    /* invalid ca file */
    AssertFalse(CyaSSL_CTX_load_verify_locations(ctx, NULL,      0));
    AssertFalse(CyaSSL_CTX_load_verify_locations(ctx, bogusFile, 0));

#ifndef CYASSL_TIRTOS
    /* invalid path */
    /* not working... investigate! */
    /* AssertFalse(CyaSSL_CTX_load_verify_locations(ctx, caCert, bogusFile)); */
#endif

    /* success */
    AssertTrue(CyaSSL_CTX_load_verify_locations(ctx, caCert, 0));

    CyaSSL_CTX_free(ctx);
#endif
}

/*----------------------------------------------------------------------------*
 | SSL
 *----------------------------------------------------------------------------*/

static void test_server_CyaSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    CYASSL_CTX *ctx;
    CYASSL_CTX *ctx_nocert;
    CYASSL *ssl;

    AssertNotNull(ctx_nocert = CyaSSL_CTX_new(CyaSSLv23_server_method()));
    AssertNotNull(ctx        = CyaSSL_CTX_new(CyaSSLv23_server_method()));

    AssertTrue(CyaSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM));
    AssertTrue(CyaSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM));

    /* invalid context */
    AssertNull(ssl = CyaSSL_new(NULL));
    AssertNull(ssl = CyaSSL_new(ctx_nocert));

    /* success */
    AssertNotNull(ssl = CyaSSL_new(ctx));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_CTX_free(ctx_nocert);
#endif
}


static void test_client_CyaSSL_new(void)
{
#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA)
    CYASSL_CTX *ctx;
    CYASSL_CTX *ctx_nocert;
    CYASSL *ssl;

    AssertNotNull(ctx_nocert = CyaSSL_CTX_new(CyaSSLv23_client_method()));
    AssertNotNull(ctx        = CyaSSL_CTX_new(CyaSSLv23_client_method()));

    AssertTrue(CyaSSL_CTX_load_verify_locations(ctx, caCert, 0));
    
    /* invalid context */
    AssertNull(ssl = CyaSSL_new(NULL));

    /* success */
    AssertNotNull(ssl = CyaSSL_new(ctx_nocert));
    CyaSSL_free(ssl);
    
    /* success */
    AssertNotNull(ssl = CyaSSL_new(ctx));
    CyaSSL_free(ssl);
    
    CyaSSL_CTX_free(ctx);
    CyaSSL_CTX_free(ctx_nocert);
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
static THREAD_RETURN CYASSL_THREAD test_server_nofail(void* args)
{
    SOCKET_T sockfd = 0;
    SOCKET_T clientfd = 0;
    word16 port = yasslPort;

    CYASSL_METHOD* method = 0;
    CYASSL_CTX* ctx = 0;
    CYASSL* ssl = 0;

    char msg[] = "I hear you fa shizzle!";
    char input[1024];
    int idx;

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    ((func_args*)args)->return_code = TEST_FAIL;
    method = CyaSSLv23_server_method();
    ctx = CyaSSL_CTX_new(method);

#if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && \
   !defined(CYASSL_SNIFFER) && !defined(CYASSL_MDK_SHELL) && \
   !defined(CYASSL_TIRTOS)
    port = 0;
#endif

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
    tcp_accept(&sockfd, &clientfd, (func_args*)args, port, 0, 0, 0);
    CloseSocket(sockfd);

    CyaSSL_set_fd(ssl, clientfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        CyaSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
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
#ifdef CYASSL_TIRTOS
        return;
#else
        return 0;
#endif
    }

#ifdef CYASSL_TIRTOS
    Task_yield();
#endif

done:
    CyaSSL_shutdown(ssl);
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    
    CloseSocket(clientfd);
    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    ecc_fp_free();  /* free per thread cache */
#endif

#ifndef CYASSL_TIRTOS
    return 0;
#endif
}


static void test_client_nofail(void* args)
{
    SOCKET_T sockfd = 0;

    CYASSL_METHOD*  method  = 0;
    CYASSL_CTX*     ctx     = 0;
    CYASSL*         ssl     = 0;

    char msg[64] = "hello cyassl!";
    char reply[1024];
    int  input;
    int  msgSz = (int)strlen(msg);

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

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

    tcp_connect(&sockfd, yasslIP, ((func_args*)args)->signal->port, 0);

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

#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif

    return;
}

/* SNI helper functions */
#ifdef HAVE_SNI

static THREAD_RETURN CYASSL_THREAD run_cyassl_server(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    CYASSL_CTX* ctx = CyaSSL_CTX_new(callbacks->method());
    CYASSL*     ssl = NULL;
    SOCKET_T    sfd = 0;
    SOCKET_T    cfd = 0;
    word16      port = yasslPort;

    char msg[] = "I hear you fa shizzle!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif
    ((func_args*)args)->return_code = TEST_FAIL;

#if defined(NO_MAIN_DRIVER) && !defined(USE_WINDOWS_API) && \
   !defined(CYASSL_SNIFFER) && !defined(CYASSL_MDK_SHELL) && \
   !defined(CYASSL_TIRTOS)
    port = 0;
#endif

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

    tcp_accept(&sfd, &cfd, (func_args*)args, port, 0, 0, 0);
    CloseSocket(sfd);

    CyaSSL_set_fd(ssl, cfd);

#ifdef NO_PSK
    #if !defined(NO_FILESYSTEM) && !defined(NO_DH)
        CyaSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
    #elif !defined(NO_DH)
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
#ifdef CYASSL_TIRTOS
        Task_yield();
#endif
        CyaSSL_shutdown(ssl);
    }

    if (callbacks->on_result)
        callbacks->on_result(ssl);

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CloseSocket(cfd);

    ((func_args*)args)->return_code = TEST_SUCCESS;

#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif

#if defined(NO_MAIN_DRIVER) && defined(HAVE_ECC) && defined(FP_ECC) \
                            && defined(HAVE_THREAD_LS)
    ecc_fp_free();  /* free per thread cache */
#endif

#ifndef CYASSL_TIRTOS
    return 0;
#endif
}


static void run_cyassl_client(void* args)
{
    callback_functions* callbacks = ((func_args*)args)->callbacks;

    CYASSL_CTX* ctx = CyaSSL_CTX_new(callbacks->method());
    CYASSL*     ssl = NULL;
    SOCKET_T    sfd = 0;

    char msg[] = "hello cyassl server!";
    int  len   = (int) XSTRLEN(msg);
    char input[1024];
    int  idx;

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

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

    tcp_connect(&sfd, yasslIP, ((func_args*)args)->signal->port, 0);

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

#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif
}

#endif /* HAVE_SNI */
#endif /* io tests dependencies */


static void test_CyaSSL_read_write(void)
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

#ifdef CYASSL_TIRTOS
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

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

#endif
}

/*----------------------------------------------------------------------------*
 | TLS extensions tests
 *----------------------------------------------------------------------------*/

#ifdef HAVE_SNI
static void use_SNI_at_ctx(CYASSL_CTX* ctx)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "www.yassl.com";

    AssertIntEQ(SSL_SUCCESS,
                    CyaSSL_CTX_UseSNI(ctx, type, (void *) name, XSTRLEN(name)));
}

static void use_SNI_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "www.yassl.com";

    AssertIntEQ(SSL_SUCCESS,
                        CyaSSL_UseSNI(ssl, type, (void *) name, XSTRLEN(name)));
}

static void different_SNI_at_ssl(CYASSL* ssl)
{
    byte type = CYASSL_SNI_HOST_NAME;
    char name[] = "ww2.yassl.com";

    AssertIntEQ(SSL_SUCCESS,
                        CyaSSL_UseSNI(ssl, type, (void *) name, XSTRLEN(name)));
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
    AssertIntEQ(FATAL_ERROR, CyaSSL_get_error(ssl, 0));
}

static void verify_SNI_abort_on_server(CYASSL* ssl)
{
    AssertIntEQ(UNKNOWN_SNI_HOST_NAME_E, CyaSSL_get_error(ssl, 0));
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

static void test_CyaSSL_SNI_GetFromBuffer(void)
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

    byte result[32] = {0};
    word32 length   = 32;

    AssertIntEQ(0, CyaSSL_SNI_GetFromBuffer(buffer4, sizeof(buffer4),
                                                           0, result, &length));

    AssertIntEQ(0, CyaSSL_SNI_GetFromBuffer(buffer3, sizeof(buffer3),
                                                           0, result, &length));

    AssertIntEQ(0, CyaSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           1, result, &length));

    AssertIntEQ(BUFFER_ERROR, CyaSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[0] = 0x16;

    AssertIntEQ(BUFFER_ERROR, CyaSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[1] = 0x03;

    AssertIntEQ(BUFFER_ERROR, CyaSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    buffer[2] = 0x03;

    AssertIntEQ(INCOMPLETE_DATA, CyaSSL_SNI_GetFromBuffer(buffer,
                                           sizeof(buffer), 0, result, &length));
    buffer[4] = 0x64;

    AssertIntEQ(SSL_SUCCESS, CyaSSL_SNI_GetFromBuffer(buffer, sizeof(buffer),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("www.paypal.com", (const char*) result);

    length = 32;

    AssertIntEQ(SSL_SUCCESS, CyaSSL_SNI_GetFromBuffer(buffer2, sizeof(buffer2),
                                                           0, result, &length));
    result[length] = 0;
    AssertStrEQ("api.textmate.org", (const char*) result);
}

static void test_CyaSSL_client_server(callback_functions* client_callbacks,
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

#ifdef CYASSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    /* RUN Server side */
    InitTcpReady(&ready);
    server_args.signal = &ready;
    client_args.signal = &ready;
    start_thread(run_cyassl_server, &server_args, &serverThread);
    wait_tcp_ready(&server_args);

    /* RUN Client side */
    run_cyassl_client(&client_args);
    join_thread(serverThread);

    FreeTcpReady(&ready);
#ifdef CYASSL_TIRTOS
    fdCloseSession(Task_self());
#endif
    
#else
    (void)client_callbacks;
    (void)server_callbacks;
#endif
}

#endif /* HAVE_SNI */

static void test_CyaSSL_UseSNI(void)
{
#ifdef HAVE_SNI
    callback_functions client_callbacks = {CyaSSLv23_client_method, 0, 0, 0};
    callback_functions server_callbacks = {CyaSSLv23_server_method, 0, 0, 0};

    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_CTX_UseSNI(NULL, 0, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_UseSNI(    NULL, 0, (void *) "ssl", XSTRLEN("ssl")));
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_CTX_UseSNI(ctx, -1, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_UseSNI(    ssl, -1, (void *) "ssl", XSTRLEN("ssl")));
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_CTX_UseSNI(ctx,  0, (void *) NULL,  XSTRLEN("ctx")));
    AssertIntNE(SSL_SUCCESS,
                    CyaSSL_UseSNI(    ssl,  0, (void *) NULL,  XSTRLEN("ssl")));

    /* success case */
    AssertIntEQ(SSL_SUCCESS,
                    CyaSSL_CTX_UseSNI(ctx,  0, (void *) "ctx", XSTRLEN("ctx")));
    AssertIntEQ(SSL_SUCCESS,
                    CyaSSL_UseSNI(    ssl,  0, (void *) "ssl", XSTRLEN("ssl")));

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

    test_CyaSSL_SNI_GetFromBuffer();
#endif
}

static void test_CyaSSL_UseMaxFragment(void)
{
#ifdef HAVE_MAX_FRAGMENT
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(NULL, CYASSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, CyaSSL_UseMaxFragment(    NULL, CYASSL_MFL_2_9));
    AssertIntNE(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx, 0));
    AssertIntNE(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx, 6));
    AssertIntNE(SSL_SUCCESS, CyaSSL_UseMaxFragment(ssl, 0));
    AssertIntNE(SSL_SUCCESS, CyaSSL_UseMaxFragment(ssl, 6));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseMaxFragment(ctx,  CYASSL_MFL_2_13));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_9));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_10));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_11));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_12));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseMaxFragment(    ssl,  CYASSL_MFL_2_13));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
#endif
}

static void test_CyaSSL_UseTruncatedHMAC(void)
{
#ifdef HAVE_TRUNCATED_HMAC
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

    /* error cases */
    AssertIntNE(SSL_SUCCESS, CyaSSL_CTX_UseTruncatedHMAC(NULL));
    AssertIntNE(SSL_SUCCESS, CyaSSL_UseTruncatedHMAC(NULL));

    /* success case */
    AssertIntEQ(SSL_SUCCESS, CyaSSL_CTX_UseTruncatedHMAC(ctx));
    AssertIntEQ(SSL_SUCCESS, CyaSSL_UseTruncatedHMAC(ssl));

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
#endif
}

static void test_CyaSSL_UseSupportedCurve(void)
{
#ifdef HAVE_SUPPORTED_CURVES
    CYASSL_CTX *ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
    CYASSL     *ssl = CyaSSL_new(ctx);

    AssertNotNull(ctx);
    AssertNotNull(ssl);

#ifndef NO_CYASSL_CLIENT
    /* error cases */
    AssertIntNE(SSL_SUCCESS,
                      CyaSSL_CTX_UseSupportedCurve(NULL, CYASSL_ECC_SECP160R1));
    AssertIntNE(SSL_SUCCESS, CyaSSL_CTX_UseSupportedCurve(ctx,  0));

    AssertIntNE(SSL_SUCCESS,
                          CyaSSL_UseSupportedCurve(NULL, CYASSL_ECC_SECP160R1));
    AssertIntNE(SSL_SUCCESS, CyaSSL_UseSupportedCurve(ssl,  0));

    /* success case */
    AssertIntEQ(SSL_SUCCESS,
                       CyaSSL_CTX_UseSupportedCurve(ctx, CYASSL_ECC_SECP160R1));
    AssertIntEQ(SSL_SUCCESS,
                           CyaSSL_UseSupportedCurve(ssl, CYASSL_ECC_SECP160R1));
#endif

    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
#endif
}

/*----------------------------------------------------------------------------*
 | Main
 *----------------------------------------------------------------------------*/

void ApiTest(void)
{
    printf(" Begin API Tests\n");
    test_CyaSSL_Init();

    test_CyaSSL_Method_Allocators();
    test_CyaSSL_CTX_new(CyaSSLv23_server_method());
    test_CyaSSL_CTX_use_certificate_file();
    test_CyaSSL_CTX_use_PrivateKey_file();
    test_CyaSSL_CTX_load_verify_locations();
    test_server_CyaSSL_new();
    test_client_CyaSSL_new();
    test_CyaSSL_read_write();

    /* TLS extensions tests */
    test_CyaSSL_UseSNI();
    test_CyaSSL_UseMaxFragment();
    test_CyaSSL_UseTruncatedHMAC();
    test_CyaSSL_UseSupportedCurve();

    test_CyaSSL_Cleanup();
    printf(" End API Tests\n");
}
