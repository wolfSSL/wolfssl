/* utils.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <tests/unit.h>

#ifndef NO_FILESYSTEM

#ifdef _MSC_VER
#include <direct.h>
#endif

#define TMP_DIR_PREFIX "tmpDir-"
/* len is length of tmpDir name, assuming
 * len does not include null terminating character */
char* create_tmp_dir(char *tmpDir, int len)
{
    if (len < (int)XSTR_SIZEOF(TMP_DIR_PREFIX))
        return NULL;

    XMEMCPY(tmpDir, TMP_DIR_PREFIX, XSTR_SIZEOF(TMP_DIR_PREFIX));

    if (mymktemp(tmpDir, len, len - (int)XSTR_SIZEOF(TMP_DIR_PREFIX)) == NULL)
        return NULL;

#ifdef _MSC_VER
    if (_mkdir(tmpDir) != 0)
        return NULL;
#elif defined(__MINGW32__)
    if (mkdir(tmpDir) != 0)
        return NULL;
#else
    if (mkdir(tmpDir, 0700) != 0)
        return NULL;
#endif

    return tmpDir;
}

int rem_dir(const char* dirName)
{
#ifdef _MSC_VER
    if (_rmdir(dirName) != 0)
        return -1;
#else
    if (rmdir(dirName) != 0)
        return -1;
#endif
    return 0;
}

int rem_file(const char* fileName)
{
#ifdef _MSC_VER
    if (_unlink(fileName) != 0)
        return -1;
#else
    if (unlink(fileName) != 0)
        return -1;
#endif
    return 0;
}

int copy_file(const char* in, const char* out)
{
    byte buf[100];
    XFILE inFile = XBADFILE;
    XFILE outFile = XBADFILE;
    size_t sz;
    int ret = -1;

    inFile = XFOPEN(in, "rb");
    if (inFile == XBADFILE)
        goto cleanup;

    outFile = XFOPEN(out, "wb");
    if (outFile == XBADFILE)
        goto cleanup;

    while ((sz = XFREAD(buf, 1, sizeof(buf), inFile)) != 0) {
        if (XFERROR(inFile))
            goto cleanup;
        if (XFWRITE(buf, 1, sz, outFile) != sz)
            goto cleanup;
        if (XFEOF(inFile))
            break;
    }

    ret = 0;
cleanup:
    if (inFile != XBADFILE)
        XFCLOSE(inFile);
    if (outFile != XBADFILE)
        XFCLOSE(outFile);
    return ret;
}

#if defined(__MACH__) || defined(__FreeBSD__)
int link_file(const char* in, const char* out)
{
    return link(in, out);
}
#endif
#endif /* !NO_FILESYSTEM */

#if !defined(NO_FILESYSTEM) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    !defined(NO_WOLFSSL_SERVER) && !defined(NO_WOLFSSL_CLIENT)

/* This set of memio functions allows for more fine tuned control of the TLS
 * connection operations. For new tests, try to use ssl_memio first. */

/* To dump the memory in gdb use
 *   dump memory client.bin test_ctx.c_buff test_ctx.c_buff+test_ctx.c_len
 *   dump memory server.bin test_ctx.s_buff test_ctx.s_buff+test_ctx.s_len
 * This can be imported into Wireshark by transforming the file with
 *   od -Ax -tx1 -v client.bin > client.bin.hex
 *   od -Ax -tx1 -v server.bin > server.bin.hex
 * And then loading test_output.dump.hex into Wireshark using the
 * "Import from Hex Dump..." option ion and selecting the TCP
 * encapsulation option.
 */

#define HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES

#define TEST_MEMIO_BUF_SZ (64 * 1024)
struct test_memio_ctx
{
    byte c_buff[TEST_MEMIO_BUF_SZ];
    int c_len;
    const char* c_ciphers;
    byte s_buff[TEST_MEMIO_BUF_SZ];
    int s_len;
    const char* s_ciphers;
};

int test_memio_do_handshake(WOLFSSL *ssl_c, WOLFSSL *ssl_s,
    int max_rounds, int *rounds);
int test_memio_setup(struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c, WOLFSSL_CTX **ctx_s, WOLFSSL **ssl_c, WOLFSSL **ssl_s,
    method_provider method_c, method_provider method_s);
int test_memio_setup_ex(struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c, WOLFSSL_CTX **ctx_s, WOLFSSL **ssl_c, WOLFSSL **ssl_s,
    method_provider method_c, method_provider method_s,
    byte *caCert, int caCertSz, byte *serverCert, int serverCertSz,
    byte *serverKey, int serverKeySz);


static WC_INLINE int test_memio_write_cb(WOLFSSL *ssl, char *data, int sz,
    void *ctx)
{
    struct test_memio_ctx *test_ctx;
    byte *buf;
    int *len;

    test_ctx = (struct test_memio_ctx*)ctx;

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = test_ctx->c_buff;
        len = &test_ctx->c_len;
    }
    else {
        buf = test_ctx->s_buff;
        len = &test_ctx->s_len;
    }

    if ((unsigned)(*len + sz) > TEST_MEMIO_BUF_SZ)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;

#ifdef WOLFSSL_DUMP_MEMIO_STREAM
    {
        WOLFSSL_BIO *dump_file = wolfSSL_BIO_new_file("test_memio.dump", "a");
        if (dump_file != NULL) {
            (void)wolfSSL_BIO_write(dump_file, data, sz);
            wolfSSL_BIO_free(dump_file);
        }
    }
#endif
    XMEMCPY(buf + *len, data, (size_t)sz);
    *len += sz;

    return sz;
}

static WC_INLINE int test_memio_read_cb(WOLFSSL *ssl, char *data, int sz,
    void *ctx)
{
    struct test_memio_ctx *test_ctx;
    int read_sz;
    byte *buf;
    int *len;

    test_ctx = (struct test_memio_ctx*)ctx;

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = test_ctx->s_buff;
        len = &test_ctx->s_len;
    }
    else {
        buf = test_ctx->c_buff;
        len = &test_ctx->c_len;
    }

    if (*len == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    read_sz = sz < *len ? sz : *len;

    XMEMCPY(data, buf, (size_t)read_sz);
    XMEMMOVE(buf, buf + read_sz,(size_t) (*len - read_sz));

    *len -= read_sz;

    return read_sz;
}

int test_memio_do_handshake(WOLFSSL *ssl_c, WOLFSSL *ssl_s,
    int max_rounds, int *rounds)
{
    byte handshake_complete = 0, hs_c = 0, hs_s = 0;
    int ret, err;

    if (rounds != NULL)
        *rounds = 0;
    while (!handshake_complete && max_rounds > 0) {
        if (!hs_c) {
            wolfSSL_SetLoggingPrefix("client");
            ret = wolfSSL_connect(ssl_c);
            wolfSSL_SetLoggingPrefix(NULL);
            if (ret == WOLFSSL_SUCCESS) {
                hs_c = 1;
            }
            else {
                err = wolfSSL_get_error(ssl_c, ret);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE)
                    return -1;
            }
        }
        if (!hs_s) {
            wolfSSL_SetLoggingPrefix("server");
            ret = wolfSSL_accept(ssl_s);
            wolfSSL_SetLoggingPrefix(NULL);
            if (ret == WOLFSSL_SUCCESS) {
                hs_s = 1;
            }
            else {
                err = wolfSSL_get_error(ssl_s, ret);
                if (err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE)
                    return -1;
            }
        }
        handshake_complete = hs_c && hs_s;
        max_rounds--;
        if (rounds != NULL)
            *rounds = *rounds + 1;
    }

    if (!handshake_complete)
        return -1;

    return 0;
}

int test_memio_setup_ex(struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c, WOLFSSL_CTX **ctx_s, WOLFSSL **ssl_c, WOLFSSL **ssl_s,
    method_provider method_c, method_provider method_s,
    byte *caCert, int caCertSz, byte *serverCert, int serverCertSz,
    byte *serverKey, int serverKeySz)
{
    int ret;
    (void)caCert;
    (void)caCertSz;
    (void)serverCert;
    (void)serverCertSz;
    (void)serverKey;
    (void)serverKeySz;

    if (ctx_c != NULL && *ctx_c == NULL) {
        *ctx_c = wolfSSL_CTX_new(method_c());
        if (*ctx_c == NULL)
            return -1;
#ifndef NO_CERTS
        if (caCert == NULL) {
            ret = wolfSSL_CTX_load_verify_locations(*ctx_c, caCertFile, 0);
        }
        else {
            ret = wolfSSL_CTX_load_verify_buffer(*ctx_c, caCert, (long)caCertSz,
                                                 WOLFSSL_FILETYPE_ASN1);
        }
        if (ret != WOLFSSL_SUCCESS)
            return -1;
#endif /* NO_CERTS */
        wolfSSL_SetIORecv(*ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_c, test_memio_write_cb);
        if (ctx->c_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_c, ctx->c_ciphers);
            if (ret != WOLFSSL_SUCCESS)
                return -1;
        }
    }

    if (ctx_s != NULL && *ctx_s == NULL) {
        *ctx_s = wolfSSL_CTX_new(method_s());
        if (*ctx_s == NULL)
            return -1;
#ifndef NO_CERTS
        if (serverKey == NULL) {
            ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_s, svrKeyFile,
                WOLFSSL_FILETYPE_PEM);
        }
        else {
            ret = wolfSSL_CTX_use_PrivateKey_buffer(*ctx_s, serverKey,
                (long)serverKeySz, WOLFSSL_FILETYPE_ASN1);
        }
        if (ret != WOLFSSL_SUCCESS)
            return- -1;

        if (serverCert == NULL) {
            ret = wolfSSL_CTX_use_certificate_file(*ctx_s, svrCertFile,
                                                   WOLFSSL_FILETYPE_PEM);
        }
        else {
            ret = wolfSSL_CTX_use_certificate_chain_buffer_format(*ctx_s,
                serverCert, (long)serverCertSz, WOLFSSL_FILETYPE_ASN1);
        }
        if (ret != WOLFSSL_SUCCESS)
            return -1;
#endif /* NO_CERTS */
        wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_s, test_memio_write_cb);
        if (ctx->s_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_s, ctx->s_ciphers);
            if (ret != WOLFSSL_SUCCESS)
                return -1;
        }
    }

    if (ctx_c != NULL && ssl_c != NULL) {
        *ssl_c = wolfSSL_new(*ctx_c);
        if (*ssl_c == NULL)
            return -1;
        wolfSSL_SetIOWriteCtx(*ssl_c, ctx);
        wolfSSL_SetIOReadCtx(*ssl_c, ctx);
    }
    if (ctx_s != NULL && ssl_s != NULL) {
        *ssl_s = wolfSSL_new(*ctx_s);
        if (*ssl_s == NULL)
            return -1;
        wolfSSL_SetIOWriteCtx(*ssl_s, ctx);
        wolfSSL_SetIOReadCtx(*ssl_s, ctx);
#if !defined(NO_DH)
        SetDH(*ssl_s);
#endif
    }

    return 0;
}

int test_memio_setup(struct test_memio_ctx *ctx,
    WOLFSSL_CTX **ctx_c, WOLFSSL_CTX **ctx_s, WOLFSSL **ssl_c, WOLFSSL **ssl_s,
    method_provider method_c, method_provider method_s)
{
    return test_memio_setup_ex(ctx, ctx_c, ctx_s, ssl_c, ssl_s, method_c,
                               method_s, NULL, 0, NULL, 0, NULL, 0);
}
#endif

#if !defined(SINGLE_THREADED) && defined(WOLFSSL_COND)
void signal_ready(tcp_ready* ready)
{
    THREAD_CHECK_RET(wolfSSL_CondStart(&ready->cond));
    ready->ready = 1;
    THREAD_CHECK_RET(wolfSSL_CondSignal(&ready->cond));
    THREAD_CHECK_RET(wolfSSL_CondEnd(&ready->cond));
}
#endif

void wait_tcp_ready(func_args* args)
{
#if !defined(SINGLE_THREADED) && defined(WOLFSSL_COND)
    tcp_ready* ready = args->signal;
    THREAD_CHECK_RET(wolfSSL_CondStart(&ready->cond));
    if (!ready->ready) {
        THREAD_CHECK_RET(wolfSSL_CondWait(&ready->cond));
    }
    ready->ready = 0; /* reset */
    THREAD_CHECK_RET(wolfSSL_CondEnd(&ready->cond));
#else
    /* no threading wait or single threaded */
    (void)args;
#endif
}

#ifndef SINGLE_THREADED
/* Start a thread.
 *
 * @param [in]  fun     Function to execute in thread.
 * @param [in]  args    Object to send to function in thread.
 * @param [out] thread  Handle to thread.
 */
void start_thread(THREAD_CB fun, func_args* args, THREAD_TYPE* thread)
{
    THREAD_CHECK_RET(wolfSSL_NewThread(thread, fun, args));
}


/* Join thread to wait for completion.
 *
 * @param [in] thread  Handle to thread.
 */
void join_thread(THREAD_TYPE thread)
{
    THREAD_CHECK_RET(wolfSSL_JoinThread(thread));
}
#endif /* SINGLE_THREADED */

/* These correspond to WOLFSSL_SSLV3...WOLFSSL_DTLSV1_3 */
const char* tls_desc[] = {
    "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3",
    "DTLSv1.0", "DTLSv1.2", "DTLSv1.3"
};
