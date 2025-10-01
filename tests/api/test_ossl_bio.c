/* test_ossl_bio.c
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

#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/buffer.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_bio.h>

/*******************************************************************************
 * BIO OpenSSL compatibility API Testing
 ******************************************************************************/

#ifndef NO_BIO

int test_wolfSSL_BIO_gets(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    BIO* bio = NULL;
    BIO* bio2 = NULL;
    char msg[] = "\nhello wolfSSL\n security plus\t---...**adf\na...b.c";
    char emp[] = "";
    char bio_buffer[20];
    int bufferSz = 20;
#ifdef OPENSSL_ALL
    BUF_MEM* emp_bm = NULL;
    BUF_MEM* msg_bm = NULL;
#endif

    /* try with bad args */
    ExpectNull(bio = BIO_new_mem_buf(NULL, sizeof(msg)));
#ifdef OPENSSL_ALL
    ExpectIntEQ(BIO_set_mem_buf(bio, NULL, BIO_NOCLOSE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* try with real msg */
    ExpectNotNull(bio = BIO_new_mem_buf((void*)msg, -1));
    XMEMSET(bio_buffer, 0, bufferSz);
    ExpectNotNull(BIO_push(bio, BIO_new(BIO_s_bio())));
    ExpectNull(bio2 = BIO_find_type(bio, BIO_TYPE_FILE));
    ExpectNotNull(bio2 = BIO_find_type(bio, BIO_TYPE_BIO));
    ExpectFalse(bio2 != BIO_next(bio));

    /* make buffer filled with no terminating characters */
    XMEMSET(bio_buffer, 1, bufferSz);

    /* BIO_gets reads a line of data */
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -3), 0);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 1);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 14);
    ExpectStrEQ(bio_buffer, "hello wolfSSL\n");
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 19);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 8);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -1), 0);

#ifdef OPENSSL_ALL
    /* test setting the mem_buf manually */
    BIO_free(bio);
    ExpectNotNull(bio = BIO_new_mem_buf((void*)msg, -1));
    ExpectNotNull(emp_bm = BUF_MEM_new());
    ExpectNotNull(msg_bm = BUF_MEM_new());
    ExpectIntEQ(BUF_MEM_grow(msg_bm, sizeof(msg)), sizeof(msg));
    if (EXPECT_SUCCESS()) {
        XFREE(msg_bm->data, NULL, DYNAMIC_TYPE_OPENSSL);
        msg_bm->data = NULL;
    }
    /* emp size is 1 for terminator */
    ExpectIntEQ(BUF_MEM_grow(emp_bm, sizeof(emp)), sizeof(emp));
    if (EXPECT_SUCCESS()) {
        XFREE(emp_bm->data, NULL, DYNAMIC_TYPE_OPENSSL);
        emp_bm->data = emp;
        msg_bm->data = msg;
    }
    ExpectIntEQ(BIO_set_mem_buf(bio, emp_bm, BIO_CLOSE), WOLFSSL_SUCCESS);

    /* check reading an empty string */
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 1); /* just terminator */
    ExpectStrEQ(emp, bio_buffer);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 0); /* Nothing to read */

    /* BIO_gets reads a line of data */
    ExpectIntEQ(BIO_set_mem_buf(bio, msg_bm, BIO_NOCLOSE), WOLFSSL_SUCCESS);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -3), 0);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 1);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 14);
    ExpectStrEQ(bio_buffer, "hello wolfSSL\n");
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 19);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 8);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -1), 0);

    if (EXPECT_SUCCESS())
        emp_bm->data = NULL;
    BUF_MEM_free(emp_bm);
    if (EXPECT_SUCCESS())
        msg_bm->data = NULL;
    BUF_MEM_free(msg_bm);
#endif

    /* check not null terminated string */
    BIO_free(bio);
    bio = NULL;
    msg[0] = 0x33;
    msg[1] = 0x33;
    msg[2] = 0x33;
    ExpectNotNull(bio = BIO_new_mem_buf((void*)msg, 3));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, 3), 2);
    ExpectIntEQ(bio_buffer[0], msg[0]);
    ExpectIntEQ(bio_buffer[1], msg[1]);
    ExpectIntNE(bio_buffer[2], msg[2]);

    BIO_free(bio);
    bio = NULL;
    msg[3]    = 0x33;
    bio_buffer[3] = 0x33;
    ExpectNotNull(bio = BIO_new_mem_buf((void*)msg, 3));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 3);
    ExpectIntEQ(bio_buffer[0], msg[0]);
    ExpectIntEQ(bio_buffer[1], msg[1]);
    ExpectIntEQ(bio_buffer[2], msg[2]);
    ExpectIntNE(bio_buffer[3], 0x33); /* make sure null terminator was set */

    /* check reading an empty string */
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = BIO_new_mem_buf((void*)emp, sizeof(emp)));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 1); /* just terminator */
    ExpectStrEQ(emp, bio_buffer);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 0); /* Nothing to read */

    /* check error cases */
    BIO_free(bio);
    bio = NULL;
    ExpectIntEQ(BIO_gets(NULL, NULL, 0), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, 2), 0); /* nothing to read */

#if !defined(NO_FILESYSTEM)
    {
        BIO*  f_bio = NULL;
        XFILE f = XBADFILE;

        ExpectNotNull(f_bio = BIO_new(BIO_s_file()));
        ExpectIntLE(BIO_gets(f_bio, bio_buffer, bufferSz), 0);

        ExpectTrue((f = XFOPEN(svrCertFile, "rb")) != XBADFILE);
        ExpectIntEQ((int)BIO_set_fp(f_bio, f, BIO_CLOSE), SSL_SUCCESS);
        if (EXPECT_FAIL() && (f != XBADFILE)) {
            XFCLOSE(f);
        }
        ExpectIntGT(BIO_gets(f_bio, bio_buffer, bufferSz), 0);

        BIO_free(f_bio);
        f_bio = NULL;
    }
#endif /* NO_FILESYSTEM */

    BIO_free(bio);
    bio = NULL;
    BIO_free(bio2);
    bio2 = NULL;

    /* try with type BIO */
    XMEMCPY(msg, "\nhello wolfSSL\n security plus\t---...**adf\na...b.c",
        sizeof(msg));
    ExpectNotNull(bio = BIO_new(BIO_s_bio()));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, 2), 0); /* nothing to read */
    ExpectNotNull(bio2 = BIO_new(BIO_s_bio()));

    ExpectIntEQ(BIO_set_write_buf_size(bio, 10),           SSL_SUCCESS);
    ExpectIntEQ(BIO_set_write_buf_size(bio2, sizeof(msg)), SSL_SUCCESS);
    ExpectIntEQ(BIO_make_bio_pair(bio, bio2),              SSL_SUCCESS);

    ExpectIntEQ(BIO_write(bio2, msg, sizeof(msg)), sizeof(msg));
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -3), 0);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 1);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 14);
    ExpectStrEQ(bio_buffer, "hello wolfSSL\n");
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 19);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 8);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, -1), 0);

    BIO_free(bio);
    bio = NULL;
    BIO_free(bio2);
    bio2 = NULL;

    /* check reading an empty string */
    ExpectNotNull(bio = BIO_new(BIO_s_bio()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, sizeof(emp)), SSL_SUCCESS);
    ExpectIntEQ(BIO_gets(bio, bio_buffer, bufferSz), 0); /* Nothing to read */
    ExpectStrEQ(emp, bio_buffer);

    BIO_free(bio);
    bio = NULL;
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_BIO_puts(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    BIO* bio = NULL;
    char input[] = "hello\0world\n.....ok\n\0";
    char output[128];

    XMEMSET(output, 0, sizeof(output));
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_puts(bio, input), 5);
    ExpectIntEQ(BIO_pending(bio), 5);
    ExpectIntEQ(BIO_puts(bio, input + 6), 14);
    ExpectIntEQ(BIO_pending(bio), 19);
    ExpectIntEQ(BIO_gets(bio, output, sizeof(output)), 11);
    ExpectStrEQ(output, "helloworld\n");
    ExpectIntEQ(BIO_pending(bio), 8);
    ExpectIntEQ(BIO_gets(bio, output, sizeof(output)), 8);
    ExpectStrEQ(output, ".....ok\n");
    ExpectIntEQ(BIO_pending(bio), 0);
    ExpectIntEQ(BIO_puts(bio, ""), -1);

    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_dump(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    BIO* bio;
    static const unsigned char data[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x55, 0xBF, 0xF4,
        0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
        0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80,
        0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B, 0xDA,
        0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xC6, 0x56,
        0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
        0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F,
        0xB4
    };
    /* Generated with OpenSSL. */
    static const char expected[] =
"0000 - 30 59 30 13 06 07 2a 86-48 ce 3d 02 01 06 08 2a   0Y0...*.H.=....*\n"
"0010 - 86 48 ce 3d 03 01 07 03-42 00 04 55 bf f4 0f 44   .H.=....B..U...D\n"
"0020 - 50 9a 3d ce 9b b7 f0 c5-4d f5 70 7b d4 ec 24 8e   P.=.....M.p{..$.\n"
"0030 - 19 80 ec 5a 4c a2 24 03-62 2c 9b da ef a2 35 12   ...ZL.$.b,....5.\n"
"0040 - 43 84 76 16 c6 56 95 06-cc 01 a9 bd f6 75 1a 42   C.v..V.......u.B\n"
"0050 - f7 bd a9 b2 36 22 5f c7-5d 7f b4                  ....6\"_.]..\n";
    static const char expectedAll[] =
"0000 - 00 01 02 03 04 05 06 07-08 09 0a 0b 0c 0d 0e 0f   ................\n"
"0010 - 10 11 12 13 14 15 16 17-18 19 1a 1b 1c 1d 1e 1f   ................\n"
"0020 - 20 21 22 23 24 25 26 27-28 29 2a 2b 2c 2d 2e 2f    !\"#$%&'()*+,-./\n"
"0030 - 30 31 32 33 34 35 36 37-38 39 3a 3b 3c 3d 3e 3f   0123456789:;<=>?\n"
"0040 - 40 41 42 43 44 45 46 47-48 49 4a 4b 4c 4d 4e 4f   @ABCDEFGHIJKLMNO\n"
"0050 - 50 51 52 53 54 55 56 57-58 59 5a 5b 5c 5d 5e 5f   PQRSTUVWXYZ[\\]^_\n"
"0060 - 60 61 62 63 64 65 66 67-68 69 6a 6b 6c 6d 6e 6f   `abcdefghijklmno\n"
"0070 - 70 71 72 73 74 75 76 77-78 79 7a 7b 7c 7d 7e 7f   pqrstuvwxyz{|}~.\n"
"0080 - 80 81 82 83 84 85 86 87-88 89 8a 8b 8c 8d 8e 8f   ................\n"
"0090 - 90 91 92 93 94 95 96 97-98 99 9a 9b 9c 9d 9e 9f   ................\n"
"00a0 - a0 a1 a2 a3 a4 a5 a6 a7-a8 a9 aa ab ac ad ae af   ................\n"
"00b0 - b0 b1 b2 b3 b4 b5 b6 b7-b8 b9 ba bb bc bd be bf   ................\n"
"00c0 - c0 c1 c2 c3 c4 c5 c6 c7-c8 c9 ca cb cc cd ce cf   ................\n"
"00d0 - d0 d1 d2 d3 d4 d5 d6 d7-d8 d9 da db dc dd de df   ................\n"
"00e0 - e0 e1 e2 e3 e4 e5 e6 e7-e8 e9 ea eb ec ed ee ef   ................\n"
"00f0 - f0 f1 f2 f3 f4 f5 f6 f7-f8 f9 fa fb fc fd fe ff   ................\n";
    char output[16 * 80];
    int i;

    ExpectNotNull(bio = BIO_new(BIO_s_mem()));

    /* Example key dumped. */
    ExpectIntEQ(BIO_dump(bio, (const char*)data, (int)sizeof(data)),
        sizeof(expected) - 1);
    ExpectIntEQ(BIO_read(bio, output, sizeof(output)), sizeof(expected) - 1);
    ExpectIntEQ(XMEMCMP(output, expected, sizeof(expected) - 1), 0);

    /* Try every possible value for a character. */
    for (i = 0; i < 256; i++)
       output[i] = i;
    ExpectIntEQ(BIO_dump(bio, output, 256), sizeof(expectedAll) - 1);
    ExpectIntEQ(BIO_read(bio, output, sizeof(output)), sizeof(expectedAll) - 1);
    ExpectIntEQ(XMEMCMP(output, expectedAll, sizeof(expectedAll) - 1), 0);

    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(HAVE_EXT_CACHE) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(USE_WOLFSSL_IO)
static int forceWantRead(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl;
    (void)buf;
    (void)sz;
    (void)ctx;
    return WOLFSSL_CBIO_ERR_WANT_READ;
}
#endif

int test_wolfSSL_BIO_should_retry(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(HAVE_EXT_CACHE) && \
    defined(HAVE_IO_TESTS_DEPENDENCIES) && defined(USE_WOLFSSL_IO)
    tcp_ready ready;
    func_args server_args;
    THREAD_TYPE serverThread;
    SOCKET_T sockfd = 0;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    char msg[64] = "hello wolfssl!";
    char reply[1024];
    int  msgSz = (int)XSTRLEN(msg);
    int  ret;
    BIO* bio = NULL;

    XMEMSET(&server_args, 0, sizeof(func_args));
#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif

    StartTCP();
    InitTcpReady(&ready);

#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif

    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);


    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    ExpectIntEQ(wolfSSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY), 0);
#endif
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0));
    ExpectIntEQ(WOLFSSL_SUCCESS,
          wolfSSL_CTX_use_certificate_file(ctx, cliCertFile, SSL_FILETYPE_PEM));
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_use_PrivateKey_file(ctx, cliKeyFile, SSL_FILETYPE_PEM));
    tcp_connect(&sockfd, wolfSSLIP, server_args.signal->port, 0, 0, NULL);

    /* force retry */
    ExpectNotNull(bio = wolfSSL_BIO_new_ssl(ctx, 1));
    ExpectIntEQ(BIO_get_ssl(bio, &ssl), 1);
    ExpectNotNull(ssl);
    ExpectIntEQ(wolfSSL_set_fd(ssl, sockfd), WOLFSSL_SUCCESS);
    wolfSSL_SSLSetIORecv(ssl, forceWantRead);
    if (EXPECT_FAIL()) {
        wolfSSL_free(ssl);
        ssl = NULL;
    }

    ExpectIntLE(BIO_write(bio, msg, msgSz), 0);
    ExpectIntNE(BIO_should_retry(bio), 0);
    ExpectIntEQ(BIO_should_read(bio), 0);
    ExpectIntEQ(BIO_should_write(bio), 0);


    /* now perform successful connection */
    wolfSSL_SSLSetIORecv(ssl, EmbedReceive);
    ExpectIntEQ(BIO_write(bio, msg, msgSz), msgSz);
    ExpectIntNE(BIO_read(bio, reply, sizeof(reply)), 0);
    ret = wolfSSL_get_error(ssl, -1);
    if (ret == WOLFSSL_ERROR_WANT_READ || ret == WOLFSSL_ERROR_WANT_WRITE) {
        ExpectIntNE(BIO_should_retry(bio), 0);

        if (ret == WOLFSSL_ERROR_WANT_READ)
            ExpectIntEQ(BIO_should_read(bio), 1);
        else
            ExpectIntEQ(BIO_should_read(bio), 0);

        if (ret == WOLFSSL_ERROR_WANT_WRITE)
            ExpectIntEQ(BIO_should_write(bio), 1);
        else
            ExpectIntEQ(BIO_should_write(bio), 0);
    }
    else {
        ExpectIntEQ(BIO_should_retry(bio), 0);
        ExpectIntEQ(BIO_should_read(bio), 0);
        ExpectIntEQ(BIO_should_write(bio), 0);
    }
    ExpectIntEQ(XMEMCMP(reply, "I hear you fa shizzle!",
                XSTRLEN("I hear you fa shizzle!")), 0);
    BIO_free(bio);
    wolfSSL_CTX_free(ctx);

    CloseSocket(sockfd);

    join_thread(serverThread);
    FreeTcpReady(&ready);

#ifdef WOLFSSL_TIRTOS
    fdOpenSession(Task_self());
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_connect(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
            defined(HAVE_HTTP_CLIENT) && !defined(NO_WOLFSSL_CLIENT)
    tcp_ready ready;
    func_args server_args;
    THREAD_TYPE serverThread;
    BIO *tcpBio = NULL;
    BIO *sslBio = NULL;
    SSL_CTX* ctx = NULL;
    SSL *ssl = NULL;
    SSL *sslPtr;
    char msg[] = "hello wolfssl!";
    char reply[30];
    char buff[10] = {0};

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0));
    ExpectIntEQ(WOLFSSL_SUCCESS,
          wolfSSL_CTX_use_certificate_file(ctx, cliCertFile, SSL_FILETYPE_PEM));
    ExpectIntEQ(WOLFSSL_SUCCESS,
            wolfSSL_CTX_use_PrivateKey_file(ctx, cliKeyFile, SSL_FILETYPE_PEM));

    /* Setup server */
    XMEMSET(&server_args, 0, sizeof(func_args));
    StartTCP();
    InitTcpReady(&ready);
#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif
    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    ExpectIntGT(XSNPRINTF(buff, sizeof(buff), "%d", ready.port), 0);

    /* Start the test proper */
    /* Setup the TCP BIO */
    ExpectNotNull(tcpBio = BIO_new_connect(wolfSSLIP));
    ExpectIntEQ(BIO_set_conn_port(tcpBio, buff), 1);
    /* Setup the SSL object */
    ExpectNotNull(ssl = SSL_new(ctx));
    SSL_set_connect_state(ssl);
    /* Setup the SSL BIO */
    ExpectNotNull(sslBio = BIO_new(BIO_f_ssl()));
    ExpectIntEQ(BIO_set_ssl(sslBio, ssl, BIO_CLOSE), 1);
    if (EXPECT_FAIL()) {
        wolfSSL_free(ssl);
    }
    /* Verify that BIO_get_ssl works. */
    ExpectIntEQ(BIO_get_ssl(sslBio, &sslPtr), 1);
    ExpectPtrEq(ssl, sslPtr);
    /* Link BIO's so that sslBio uses tcpBio for IO */
    ExpectPtrEq(BIO_push(sslBio, tcpBio), sslBio);
    /* Do TCP connect */
    ExpectIntEQ(BIO_do_connect(sslBio), 1);
    /* Do TLS handshake */
    ExpectIntEQ(BIO_do_handshake(sslBio), 1);
    /* Test writing */
    ExpectIntEQ(BIO_write(sslBio, msg, sizeof(msg)), sizeof(msg));
    /* Expect length of default wolfSSL reply */
    ExpectIntEQ(BIO_read(sslBio, reply, sizeof(reply)), 23);

    /* Clean it all up */
    BIO_free_all(sslBio);
    /* Server clean up */
    join_thread(serverThread);
    FreeTcpReady(&ready);

    /* Run the same test, but use BIO_new_ssl_connect and set the IP and port
     * after. */
    XMEMSET(&server_args, 0, sizeof(func_args));
    StartTCP();
    InitTcpReady(&ready);
#if defined(USE_WINDOWS_API)
    /* use RNG to get random port if using windows */
    ready.port = GetRandomPort();
#endif
    server_args.signal = &ready;
    start_thread(test_server_nofail, &server_args, &serverThread);
    wait_tcp_ready(&server_args);
    ExpectIntGT(XSNPRINTF(buff, sizeof(buff), "%d", ready.port), 0);

    ExpectNotNull(sslBio = BIO_new_ssl_connect(ctx));
    ExpectIntEQ(BIO_set_conn_hostname(sslBio, (char*)wolfSSLIP), 1);
    ExpectIntEQ(BIO_set_conn_port(sslBio, buff), 1);
    ExpectIntEQ(BIO_do_connect(sslBio), 1);
    ExpectIntEQ(BIO_do_handshake(sslBio), 1);
    ExpectIntEQ(BIO_write(sslBio, msg, sizeof(msg)), sizeof(msg));
    ExpectIntEQ(BIO_read(sslBio, reply, sizeof(reply)), 23);
    /* Attempt to close the TLS connection gracefully. */
    BIO_ssl_shutdown(sslBio);

    BIO_free_all(sslBio);
    join_thread(serverThread);
    FreeTcpReady(&ready);

    SSL_CTX_free(ctx);

#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_BIO_tls(void)
{
    EXPECT_DECLS;
#if !defined(NO_BIO) && defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    SSL_CTX* ctx = NULL;
    SSL *ssl = NULL;
    BIO *readBio = NULL;
    BIO *writeBio = NULL;
    int ret;
    int err = 0;

    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_method()));
    ExpectNotNull(ssl = SSL_new(ctx));

    ExpectNotNull(readBio = BIO_new(BIO_s_mem()));
    ExpectNotNull(writeBio = BIO_new(BIO_s_mem()));
    /* Qt reads data from write-bio,
     * then writes the read data into plain packet.
     * Qt reads data from plain packet,
     * then writes the read data into read-bio.
     */
    SSL_set_bio(ssl, readBio, writeBio);

    do {
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) { break; } else if (ret == 0) { continue; }
        }
    #endif
        ret = SSL_connect(ssl);
        err = SSL_get_error(ssl, 0);
    } while (err == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    /* in this use case, should return WANT READ
     * so that Qt will read the data from plain packet for next state.
     */
    ExpectIntEQ(err, SSL_ERROR_WANT_READ);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_BIO_datagram(void)
{
    EXPECT_DECLS;
#if !defined(NO_BIO) && defined(WOLFSSL_DTLS) && defined(WOLFSSL_HAVE_BIO_ADDR) && defined(OPENSSL_EXTRA)
    int ret;
    SOCKET_T fd1 = SOCKET_INVALID, fd2 = SOCKET_INVALID;
    WOLFSSL_BIO *bio1 = NULL, *bio2 = NULL;
    WOLFSSL_BIO_ADDR *bio_addr1 = NULL, *bio_addr2 = NULL;
    SOCKADDR_IN sin1, sin2;
    socklen_t slen;
    static const char test_msg[] = "I am a datagram, short and stout.";
    char test_msg_recvd[sizeof(test_msg) + 10];
#ifdef USE_WINDOWS_API
    static const DWORD timeout = 250; /* ms */
#else
    static const struct timeval timeout = { 0, 250000 };
#endif

    StartTCP();

    if (EXPECT_SUCCESS()) {
        fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ExpectIntNE(fd1, SOCKET_INVALID);
    }
    if (EXPECT_SUCCESS()) {
        fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        ExpectIntNE(fd2, SOCKET_INVALID);
    }

    if (EXPECT_SUCCESS()) {
        bio1 = wolfSSL_BIO_new_dgram(fd1, 1 /* closeF */);
        ExpectNotNull(bio1);
    }

    if (EXPECT_SUCCESS()) {
        bio2 = wolfSSL_BIO_new_dgram(fd2, 1 /* closeF */);
        ExpectNotNull(bio2);
    }

    if (EXPECT_SUCCESS()) {
        sin1.sin_family = AF_INET;
        sin1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin1.sin_port = 0;
        slen = (socklen_t)sizeof(sin1);
        ExpectIntEQ(bind(fd1, (const struct sockaddr *)&sin1, slen), 0);
        ExpectIntEQ(setsockopt(fd1, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)), 0);
        ExpectIntEQ(getsockname(fd1, (struct sockaddr *)&sin1, &slen), 0);
    }

    if (EXPECT_SUCCESS()) {
        sin2.sin_family = AF_INET;
        sin2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin2.sin_port = 0;
        slen = (socklen_t)sizeof(sin2);
        ExpectIntEQ(bind(fd2, (const struct sockaddr *)&sin2, slen), 0);
        ExpectIntEQ(setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)), 0);
        ExpectIntEQ(getsockname(fd2, (struct sockaddr *)&sin2, &slen), 0);
    }

    if (EXPECT_SUCCESS()) {
        bio_addr1 = wolfSSL_BIO_ADDR_new();
        ExpectNotNull(bio_addr1);
    }

    if (EXPECT_SUCCESS()) {
        bio_addr2 = wolfSSL_BIO_ADDR_new();
        ExpectNotNull(bio_addr2);
    }

    if (EXPECT_SUCCESS()) {
        /* for OpenSSL compatibility, direct copying of sockaddrs into BIO_ADDRs must work right. */
        XMEMCPY(&bio_addr2->sa_in, &sin2, sizeof(sin2));
        ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio1, BIO_CTRL_DGRAM_SET_PEER, 0, bio_addr2), WOLFSSL_SUCCESS);
        wolfSSL_BIO_ADDR_clear(bio_addr2);
    }

    test_msg_recvd[0] = 0;
    ExpectIntEQ(wolfSSL_BIO_write(bio1, test_msg, sizeof(test_msg)), (int)sizeof(test_msg));
    ExpectIntEQ(wolfSSL_BIO_read(bio2, test_msg_recvd, sizeof(test_msg_recvd)), (int)sizeof(test_msg));
    ExpectIntEQ(XMEMCMP(test_msg_recvd, test_msg, sizeof(test_msg)), 0);

#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
    ExpectIntEQ(wolfSSL_BIO_number_written(bio1), sizeof(test_msg));
    ExpectIntEQ(wolfSSL_BIO_number_read(bio2), sizeof(test_msg));
#endif

    /* bio2 should now have bio1's addr stored as its peer_addr, because the
     * BIOs aren't "connected" yet.  use it to send a reply.
     */

    test_msg_recvd[0] = 0;
    ExpectIntEQ(wolfSSL_BIO_write(bio2, test_msg, sizeof(test_msg)), (int)sizeof(test_msg));
    ExpectIntEQ(wolfSSL_BIO_read(bio1, test_msg_recvd, sizeof(test_msg_recvd)), (int)sizeof(test_msg));
    ExpectIntEQ(XMEMCMP(test_msg_recvd, test_msg, sizeof(test_msg)), 0);

    ExpectIntEQ(wolfSSL_BIO_read(bio1, test_msg_recvd, sizeof(test_msg_recvd)), WOLFSSL_BIO_ERROR);
    ExpectIntNE(BIO_should_retry(bio1), 0);

    ExpectIntEQ(wolfSSL_BIO_read(bio2, test_msg_recvd, sizeof(test_msg_recvd)), WOLFSSL_BIO_ERROR);
    ExpectIntNE(BIO_should_retry(bio2), 0);

    /* now "connect" the sockets. */

    ExpectIntEQ(connect(fd1, (const struct sockaddr *)&sin2, (socklen_t)sizeof(sin2)), 0);
    ExpectIntEQ(connect(fd2, (const struct sockaddr *)&sin1, (socklen_t)sizeof(sin1)), 0);

    if (EXPECT_SUCCESS()) {
        XMEMCPY(&bio_addr2->sa_in, &sin2, sizeof(sin2));
        ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio1, BIO_CTRL_DGRAM_SET_CONNECTED, 0, bio_addr2), WOLFSSL_SUCCESS);
        wolfSSL_BIO_ADDR_clear(bio_addr2);
    }

    if (EXPECT_SUCCESS()) {
        XMEMCPY(&bio_addr1->sa_in, &sin1, sizeof(sin1));
        ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio2, BIO_CTRL_DGRAM_SET_CONNECTED, 0, bio_addr1), WOLFSSL_SUCCESS);
        wolfSSL_BIO_ADDR_clear(bio_addr1);
    }

    test_msg_recvd[0] = 0;
    ExpectIntEQ(wolfSSL_BIO_write(bio2, test_msg, sizeof(test_msg)), (int)sizeof(test_msg));
    ExpectIntEQ(wolfSSL_BIO_read(bio1, test_msg_recvd, sizeof(test_msg_recvd)), (int)sizeof(test_msg));
    ExpectIntEQ(XMEMCMP(test_msg_recvd, test_msg, sizeof(test_msg)), 0);

    test_msg_recvd[0] = 0;
    ExpectIntEQ(wolfSSL_BIO_write(bio1, test_msg, sizeof(test_msg)), (int)sizeof(test_msg));
    ExpectIntEQ(wolfSSL_BIO_read(bio2, test_msg_recvd, sizeof(test_msg_recvd)), (int)sizeof(test_msg));
    ExpectIntEQ(XMEMCMP(test_msg_recvd, test_msg, sizeof(test_msg)), 0);

#ifdef __linux__
    /* now "disconnect" the sockets and attempt transmits expected to fail. */

    sin1.sin_family = AF_UNSPEC;
    ExpectIntEQ(connect(fd1, (const struct sockaddr *)&sin1, (socklen_t)sizeof(sin1)), 0);
    ExpectIntEQ(connect(fd2, (const struct sockaddr *)&sin1, (socklen_t)sizeof(sin1)), 0);
    sin1.sin_family = AF_INET;

    ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio1, BIO_CTRL_DGRAM_SET_CONNECTED, 0, NULL), WOLFSSL_SUCCESS);
    ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio2, BIO_CTRL_DGRAM_SET_CONNECTED, 0, NULL), WOLFSSL_SUCCESS);

    if (EXPECT_SUCCESS()) {
        sin2.sin_addr.s_addr = htonl(0xc0a8c0a8); /* 192.168.192.168 -- invalid for loopback interface. */
        XMEMCPY(&bio_addr2->sa_in, &sin2, sizeof(sin2));
        ExpectIntEQ((int)wolfSSL_BIO_ctrl(bio1, BIO_CTRL_DGRAM_SET_PEER, 0, bio_addr2), WOLFSSL_SUCCESS);
        wolfSSL_BIO_ADDR_clear(bio_addr2);
    }

    test_msg_recvd[0] = 0;
    errno = 0;
    ExpectIntEQ(wolfSSL_BIO_write(bio1, test_msg, sizeof(test_msg)), -1);
    ExpectTrue((errno == EINVAL) || (errno == ENETUNREACH));

#endif /* __linux__ */


    if (bio1) {
        ret = wolfSSL_BIO_free(bio1);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    } else if (fd1 != SOCKET_INVALID)
        CloseSocket(fd1);
    if (bio2) {
        ret = wolfSSL_BIO_free(bio2);
        ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    } else if (fd2 != SOCKET_INVALID)
        CloseSocket(fd2);
    if (bio_addr1)
        wolfSSL_BIO_ADDR_free(bio_addr1);
    if (bio_addr2)
        wolfSSL_BIO_ADDR_free(bio_addr2);

#endif /* !NO_BIO && WOLFSSL_DTLS && WOLFSSL_HAVE_BIO_ADDR && OPENSSL_EXTRA */

    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_s_null(void)
{
    EXPECT_DECLS;
#if !defined(NO_BIO) && defined(OPENSSL_EXTRA)
    BIO *b = NULL;
    char testData[10] = {'t','e','s','t',0};

    ExpectNotNull(b = BIO_new(BIO_s_null()));
    ExpectIntEQ(BIO_write(b, testData, sizeof(testData)), sizeof(testData));
    ExpectIntEQ(BIO_read(b, testData, sizeof(testData)), 0);
    ExpectIntEQ(BIO_puts(b, testData), 4);
    ExpectIntEQ(BIO_gets(b, testData, sizeof(testData)), 0);
    ExpectIntEQ(BIO_pending(b), 0);
    ExpectIntEQ(BIO_eof(b), 1);

    BIO_free(b);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_ALL) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
    defined(HAVE_HTTP_CLIENT)
static THREAD_RETURN WOLFSSL_THREAD test_wolfSSL_BIO_accept_client(void* args)
{
    BIO* clientBio;
    SSL* sslClient;
    SSL_CTX* ctx;
    char connectAddr[20]; /* IP + port */;

    (void)args;

    AssertIntGT(snprintf(connectAddr, sizeof(connectAddr), "%s:%d", wolfSSLIP, wolfSSLPort), 0);
    clientBio = BIO_new_connect(connectAddr);
    AssertNotNull(clientBio);
    AssertIntEQ(BIO_do_connect(clientBio), 1);
    ctx = SSL_CTX_new(SSLv23_method());
    AssertNotNull(ctx);
    sslClient = SSL_new(ctx);
    AssertNotNull(sslClient);
    AssertIntEQ(wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0), WOLFSSL_SUCCESS);
    SSL_set_bio(sslClient, clientBio, clientBio);
    AssertIntEQ(SSL_connect(sslClient), 1);

    SSL_free(sslClient);
    SSL_CTX_free(ctx);

#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif

int test_wolfSSL_BIO_accept(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(HAVE_IO_TESTS_DEPENDENCIES) && \
    defined(HAVE_HTTP_CLIENT)
    BIO* serverBindBio = NULL;
    BIO* serverAcceptBio = NULL;
    SSL* sslServer = NULL;
    SSL_CTX* ctx = NULL;
    func_args args;
    THREAD_TYPE thread;
    char port[10]; /* 10 bytes should be enough to store the string
                    * representation of the port */

    ExpectIntGT(snprintf(port, sizeof(port), "%d", wolfSSLPort), 0);
    ExpectNotNull(serverBindBio = BIO_new_accept(port));

    /* First BIO_do_accept binds the port */
    ExpectIntEQ(BIO_do_accept(serverBindBio), 1);

    XMEMSET(&args, 0, sizeof(func_args));
    start_thread(test_wolfSSL_BIO_accept_client, &args, &thread);

    ExpectIntEQ(BIO_do_accept(serverBindBio), 1);
    /* Let's plug it into SSL to test */
    ExpectNotNull(ctx = SSL_CTX_new(SSLv23_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        SSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
        SSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    ExpectNotNull(sslServer = SSL_new(ctx));
    ExpectNotNull(serverAcceptBio = BIO_pop(serverBindBio));
    SSL_set_bio(sslServer, serverAcceptBio, serverAcceptBio);
    ExpectIntEQ(SSL_accept(sslServer), 1);

    join_thread(thread);

    BIO_free(serverBindBio);
    SSL_free(sslServer);
    SSL_CTX_free(ctx);

#if defined(HAVE_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_write(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_BASE64_ENCODE)
    BIO* bio = NULL;
    BIO* bio64 = NULL;
    BIO* bio_mem = NULL;
    BIO* ptr = NULL;
    int  sz;
    char msg[] = "conversion test";
    char out[40];
    char expected[] = "Y29udmVyc2lvbiB0ZXN0AA==\n";
    void* bufPtr = NULL;
    BUF_MEM* buf = NULL;

    ExpectNotNull(bio64 = BIO_new(BIO_f_base64()));
    ExpectNotNull(bio   = BIO_push(bio64, BIO_new(BIO_s_mem())));
    if (EXPECT_FAIL()) {
        BIO_free(bio64);
    }

    /* now should convert to base64 then write to memory */
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), sizeof(msg));
    BIO_flush(bio);

    /* test BIO chain */
    ExpectIntEQ(SSL_SUCCESS, (int)BIO_get_mem_ptr(bio, &buf));
    ExpectNotNull(buf);
    ExpectIntEQ(buf->length, 25);
    ExpectIntEQ(BIO_get_mem_data(bio, &bufPtr), 25);
    ExpectPtrEq(buf->data, bufPtr);

    ExpectNotNull(ptr = BIO_find_type(bio, BIO_TYPE_MEM));
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    ExpectIntEQ((sz = BIO_read(ptr, out, sz)), 25);
    ExpectIntEQ(XMEMCMP(out, expected, sz), 0);

    /* write then read should return the same message */
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), sizeof(msg));
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    ExpectIntEQ(BIO_read(bio, out, sz), 16);
    ExpectIntEQ(XMEMCMP(out, msg, sizeof(msg)), 0);

    /* now try encoding with no line ending */
    BIO_set_flags(bio64, BIO_FLAGS_BASE64_NO_NL);
#ifdef HAVE_EX_DATA
    BIO_set_ex_data(bio64, 0, (void*) "data");
    ExpectIntEQ(strcmp((const char*)BIO_get_ex_data(bio64, 0), "data"), 0);
#endif
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), sizeof(msg));
    BIO_flush(bio);
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    ExpectIntEQ((sz = BIO_read(ptr, out, sz)), 24);
    ExpectIntEQ(XMEMCMP(out, expected, sz), 0);

    BIO_free_all(bio); /* frees bio64 also */
    bio = NULL;

    /* test with more than one bio64 in list */
    ExpectNotNull(bio64 = BIO_new(BIO_f_base64()));
    ExpectNotNull(bio   = BIO_push(BIO_new(BIO_f_base64()), bio64));
    if (EXPECT_FAIL()) {
        BIO_free_all(bio);
        bio = NULL;
        bio64 = NULL;
    }
    ExpectNotNull(bio_mem = BIO_new(BIO_s_mem()));
    ExpectNotNull(BIO_push(bio64, bio_mem));
    if (EXPECT_FAIL()) {
        BIO_free(bio_mem);
    }

    /* now should convert to base64 when stored and then decode with read */
    if (bio == NULL) {
        ExpectNotNull(bio = BIO_new(BIO_f_base64()));
    }
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), 25);
    BIO_flush(bio);
    sz = sizeof(out);
    XMEMSET(out, 0, sz);
    ExpectIntEQ((sz = BIO_read(bio, out, sz)), 16);
    ExpectIntEQ(XMEMCMP(out, msg, sz), 0);
    BIO_clear_flags(bio64, ~0);
    BIO_set_retry_read(bio);
    BIO_free_all(bio); /* frees bio64s also */
    bio = NULL;

    ExpectNotNull(bio = BIO_new_mem_buf(out, 0));
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), sizeof(msg));
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_BIO_printf(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL)
    BIO* bio = NULL;
    int  sz = 7;
    char msg[] = "TLS 1.3 for the world";
    char out[60];
    char expected[] = "TLS 1.3 for the world : sz = 7";

    XMEMSET(out, 0, sizeof(out));
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_printf(bio, "%s : sz = %d", msg, sz), 30);
    ExpectIntEQ(BIO_printf(NULL, ""), WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(BIO_read(bio, out, sizeof(out)), 30);
    ExpectIntEQ(XSTRNCMP(out, expected, sizeof(expected)), 0);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_f_md(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_SHA256)
    BIO* bio = NULL;
    BIO* mem = NULL;
    char msg[] = "message to hash";
    char out[60];
    EVP_MD_CTX* ctx = NULL;
    const unsigned char testKey[] =
    {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    const char testData[] = "Hi There";
    const unsigned char testResult[] =
    {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    const unsigned char expectedHash[] =
    {
       0x66, 0x49, 0x3C, 0xE8, 0x8A, 0x57, 0xB0, 0x60,
       0xDC, 0x55, 0x7D, 0xFC, 0x1F, 0xA5, 0xE5, 0x07,
       0x70, 0x5A, 0xF6, 0xD7, 0xC4, 0x1F, 0x1A, 0xE4,
       0x2D, 0xA6, 0xFD, 0xD1, 0x29, 0x7D, 0x60, 0x0D
    };
    const unsigned char emptyHash[] =
    {
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
        0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
        0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
        0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
    };
    unsigned char check[sizeof(testResult) + 1];
    size_t checkSz = sizeof(check);
    EVP_PKEY* key = NULL;

    XMEMSET(out, 0, sizeof(out));
    ExpectNotNull(bio = BIO_new(BIO_f_md()));
    ExpectNotNull(mem = BIO_new(BIO_s_mem()));

    ExpectIntEQ(BIO_get_md_ctx(bio, &ctx), 1);
    ExpectIntEQ(EVP_DigestInit(ctx, EVP_sha256()), 1);

    /* should not be able to write/read yet since just digest wrapper and no
     * data is passing through the bio */
    ExpectIntEQ(BIO_write(bio, msg, 0), 0);
    ExpectIntEQ(BIO_pending(bio), 0);
    ExpectIntEQ(BIO_read(bio, out, sizeof(out)), 0);
    ExpectIntEQ(BIO_gets(bio, out, 3), 0);
    ExpectIntEQ(BIO_gets(bio, out, sizeof(out)), 32);
    ExpectIntEQ(XMEMCMP(emptyHash, out, 32), 0);
    BIO_reset(bio);

    /* append BIO mem to bio in order to read/write */
    ExpectNotNull(bio = BIO_push(bio, mem));

    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(BIO_write(mem, msg, sizeof(msg)), 16);
    ExpectIntEQ(BIO_pending(bio), 16);

    /* this just reads the message and does not hash it (gets calls final) */
    ExpectIntEQ(BIO_read(bio, out, sizeof(out)), 16);
    ExpectIntEQ(XMEMCMP(out, msg, sizeof(msg)), 0);

    /* create a message digest using BIO */
    XMEMSET(out, 0, sizeof(out));
    ExpectIntEQ(BIO_write(bio, msg, sizeof(msg)), 16);
    ExpectIntEQ(BIO_pending(mem), 16);
    ExpectIntEQ(BIO_pending(bio), 16);
    ExpectIntEQ(BIO_gets(bio, out, sizeof(out)), 32);
    ExpectIntEQ(XMEMCMP(expectedHash, out, 32), 0);
    BIO_free(bio);
    bio = NULL;
    BIO_free(mem);
    mem = NULL;

    /* test with HMAC */
    XMEMSET(out, 0, sizeof(out));
    ExpectNotNull(bio = BIO_new(BIO_f_md()));
    ExpectNotNull(mem = BIO_new(BIO_s_mem()));
    BIO_get_md_ctx(bio, &ctx);
    ExpectNotNull(key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testKey,
        (int)sizeof(testKey)));
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    ExpectNotNull(bio = BIO_push(bio, mem));
    BIO_write(bio, testData, (int)strlen(testData));
    checkSz = sizeof(check);
    ExpectIntEQ(EVP_DigestSignFinal(ctx, NULL, &checkSz), 1);
    checkSz = sizeof(check);
    ExpectIntEQ(EVP_DigestSignFinal(ctx, check, &checkSz), 1);

    ExpectIntEQ(XMEMCMP(check, testResult, sizeof(testResult)), 0);

    EVP_PKEY_free(key);
    BIO_free(bio);
    BIO_free(mem);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_up_ref(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
    BIO* bio = NULL;

    ExpectNotNull(bio = BIO_new(BIO_f_md()));
    ExpectIntEQ(BIO_up_ref(NULL), 0);
    ExpectIntEQ(BIO_up_ref(bio), 1);
    BIO_free(bio);
    ExpectIntEQ(BIO_up_ref(bio), 1);
    BIO_free(bio);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}
int test_wolfSSL_BIO_reset(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
    BIO* bio = NULL;
    byte buf[16];

    ExpectNotNull(bio = BIO_new_mem_buf("secure your data",
        (word32)XSTRLEN("secure your data")));
    ExpectIntEQ(BIO_read(bio, buf, 6), 6);
    ExpectIntEQ(XMEMCMP(buf, "secure", 6), 0);
    XMEMSET(buf, 0, 16);
    ExpectIntEQ(BIO_read(bio, buf, 16), 10);
    ExpectIntEQ(XMEMCMP(buf, " your data", 10), 0);
    /* You cannot write to MEM BIO with read-only mode. */
    ExpectIntEQ(BIO_write(bio, "WriteToReadonly", 15), 0);
    ExpectIntEQ(BIO_read(bio, buf, 16), -1);
    XMEMSET(buf, 0, 16);
    ExpectIntEQ(BIO_reset(bio), 1);
    ExpectIntEQ(BIO_read(bio, buf, 16), 16);
    ExpectIntEQ(XMEMCMP(buf, "secure your data", 16), 0);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_BIO_get_len(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO) && !defined(NO_FILESYSTEM)
    BIO *bio = NULL;
    const char txt[] = "Some example text to push to the BIO.";

    ExpectIntEQ(wolfSSL_BIO_get_len(bio), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));

    ExpectIntEQ(wolfSSL_BIO_write(bio, txt, sizeof(txt)), sizeof(txt));
    ExpectIntEQ(wolfSSL_BIO_get_len(bio), sizeof(txt));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = BIO_new_fd(STDERR_FILENO, BIO_NOCLOSE));
    ExpectIntEQ(wolfSSL_BIO_get_len(bio), WC_NO_ERR_TRACE(WOLFSSL_BAD_FILE));
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

#endif /* !NO_BIO */

