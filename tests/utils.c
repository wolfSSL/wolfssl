/* utils.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <tests/unit.h>
#include <tests/utils.h>

#ifdef HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES

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

int test_memio_write_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
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
        char dump_file_name[64];
        WOLFSSL_BIO *dump_file;
        sprintf(dump_file_name, "%s/%s.dump", tmpDirName, currentTestName);
        dump_file = wolfSSL_BIO_new_file(dump_file_name, "a");
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

int test_memio_read_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
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

#endif /* HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES */

