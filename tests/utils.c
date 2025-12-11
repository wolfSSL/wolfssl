/* utils.c
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
#include <tests/utils.h>

#ifdef HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES

/* This set of memio functions allows for more fine tuned control of the TLS
 * connection operations. For new tests, try to use ssl_memio first. */

/* To dump the memory in gdb use
 *   dump memory client.bin test_ctx.c_buff test_ctx.c_buff+test_ctx.c_len
 *   dump memory server.bin test_ctx.s_buff test_ctx.s_buff+test_ctx.s_len
 * This can be imported into Wireshark by transforming the file with
 *   od -Ax -tx1 -v client.bin > client.hex
 *   od -Ax -tx1 -v server.bin > server.hex
 * Then transform the files into pcap (use -u instead of -T for UDP)
 *   text2pcap -T 50,60 client.hex client.pcap
 *   text2pcap -T 50,60 server.hex server.pcap
 * Then open in wireshark
 *   wireshark client.pcap
 *   wireshark server.pcap
 */

int test_memio_write_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
{
    struct test_memio_ctx *test_ctx;
    byte *buf;
    int *len;
    int *msg_sizes;
    int *msg_count;
    int *forceWantWrite;

    test_ctx = (struct test_memio_ctx*)ctx;

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = test_ctx->c_buff;
        len = &test_ctx->c_len;
        msg_sizes = test_ctx->c_msg_sizes;
        msg_count = &test_ctx->c_msg_count;
        forceWantWrite = &test_ctx->s_force_want_write;
    }
    else {
        buf = test_ctx->s_buff;
        len = &test_ctx->s_len;
        msg_sizes = test_ctx->s_msg_sizes;
        msg_count = &test_ctx->s_msg_count;
        forceWantWrite = &test_ctx->c_force_want_write;
    }

    if (*forceWantWrite)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;

    if ((unsigned)(*len + sz) > TEST_MEMIO_BUF_SZ)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;

    if (*msg_count >= TEST_MEMIO_MAX_MSGS)
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
    msg_sizes[*msg_count] = sz;
    (*msg_count)++;
    *len += sz;

    return sz;
}

int test_memio_read_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
{
    struct test_memio_ctx *test_ctx;
    int read_sz;
    byte *buf;
    int *len;
    int *msg_sizes;
    int *msg_count;
    int *msg_pos;
    int is_dtls;

    test_ctx = (struct test_memio_ctx*)ctx;
    is_dtls = wolfSSL_dtls(ssl);

    if (wolfSSL_GetSide(ssl) == WOLFSSL_SERVER_END) {
        buf = test_ctx->s_buff;
        len = &test_ctx->s_len;
        msg_sizes = test_ctx->s_msg_sizes;
        msg_count = &test_ctx->s_msg_count;
        msg_pos = &test_ctx->s_msg_pos;
    }
    else {
        buf = test_ctx->c_buff;
        len = &test_ctx->c_len;
        msg_sizes = test_ctx->c_msg_sizes;
        msg_count = &test_ctx->c_msg_count;
        msg_pos = &test_ctx->c_msg_pos;
    }

    if (*len == 0 || *msg_pos >= *msg_count)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    /* Calculate how much we can read from current message */
    read_sz = msg_sizes[*msg_pos];
    if (read_sz > sz)
        read_sz = sz;

    if (read_sz > *len) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* Copy data from current message */
    XMEMCPY(data, buf, (size_t)read_sz);
    /* remove the read data from the buffer */
    XMEMMOVE(buf, buf + read_sz, (size_t)(*len - read_sz));
    *len -= read_sz;
    msg_sizes[*msg_pos] -= read_sz;

    /* if we are on dtls, discard the rest of the message */
    if (is_dtls && msg_sizes[*msg_pos] > 0) {
        XMEMMOVE(buf, buf + msg_sizes[*msg_pos], (size_t)(*len - msg_sizes[*msg_pos]));
        *len -= msg_sizes[*msg_pos];
        msg_sizes[*msg_pos] = 0;
    }

    /* If we've read the entire message */
    if (msg_sizes[*msg_pos] == 0) {
        /* Move to next message */
        (*msg_pos)++;
        if (*msg_pos >= *msg_count) {
            *msg_pos = 0;
            *msg_count = 0;
        }
    }

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
        if (ret != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(*ctx_c);
            *ctx_c = NULL;
            return -1;
        }
#endif /* NO_CERTS */
        wolfSSL_SetIORecv(*ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_c, test_memio_write_cb);
        if (ctx->c_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_c, ctx->c_ciphers);
            if (ret != WOLFSSL_SUCCESS) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
                return -1;
            }
        }
    }

    if (ctx_s != NULL && *ctx_s == NULL) {
        *ctx_s = wolfSSL_CTX_new(method_s());
        if (*ctx_s == NULL) {
            if (ctx_c != NULL) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
            }
            return -1;
        }
#ifndef NO_CERTS
        if (serverKey == NULL) {
            ret = wolfSSL_CTX_use_PrivateKey_file(*ctx_s, svrKeyFile,
                CERT_FILETYPE);
        }
        else {
            ret = wolfSSL_CTX_use_PrivateKey_buffer(*ctx_s, serverKey,
                (long)serverKeySz, WOLFSSL_FILETYPE_ASN1);
        }
        if (ret != WOLFSSL_SUCCESS) {
            if (ctx_s != NULL) {
                wolfSSL_CTX_free(*ctx_s);
                *ctx_s = NULL;
            }
            if (ctx_c != NULL) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
            }
            return -1;
        }

        if (serverCert == NULL) {
            ret = wolfSSL_CTX_use_certificate_file(*ctx_s, svrCertFile,
                                                   CERT_FILETYPE);
        }
        else {
            ret = wolfSSL_CTX_use_certificate_chain_buffer_format(*ctx_s,
                serverCert, (long)serverCertSz, WOLFSSL_FILETYPE_ASN1);
        }
        if (ret != WOLFSSL_SUCCESS) {
            if (ctx_s != NULL) {
                wolfSSL_CTX_free(*ctx_s);
                *ctx_s = NULL;
            }
            if (ctx_c != NULL) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
            }
            return -1;
        }
#endif /* NO_CERTS */
        wolfSSL_SetIORecv(*ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(*ctx_s, test_memio_write_cb);
        if (ctx->s_ciphers != NULL) {
            ret = wolfSSL_CTX_set_cipher_list(*ctx_s, ctx->s_ciphers);
            if (ret != WOLFSSL_SUCCESS) {
                if (ctx_s != NULL) {
                    wolfSSL_CTX_free(*ctx_s);
                    *ctx_s = NULL;
                }
                if (ctx_c != NULL) {
                    wolfSSL_CTX_free(*ctx_c);
                    *ctx_c = NULL;
                }
                return -1;
            }
        }
    }

    if (ctx_c != NULL && ssl_c != NULL) {
        *ssl_c = wolfSSL_new(*ctx_c);
        if (*ssl_c == NULL) {
            if (ctx_s != NULL) {
                wolfSSL_CTX_free(*ctx_s);
                *ctx_s = NULL;
            }
            if (ctx_c != NULL) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
            }
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_c, ctx);
        wolfSSL_SetIOReadCtx(*ssl_c, ctx);
    }
    if (ctx_s != NULL && ssl_s != NULL) {
        *ssl_s = wolfSSL_new(*ctx_s);
        if (*ssl_s == NULL) {
            if (ssl_c != NULL) {
                wolfSSL_free(*ssl_c);
                *ssl_c = NULL;
            }
            if (ctx_s != NULL) {
                wolfSSL_CTX_free(*ctx_s);
                *ctx_s = NULL;
            }
            if (ctx_c != NULL) {
                wolfSSL_CTX_free(*ctx_c);
                *ctx_c = NULL;
            }
            return -1;
        }
        wolfSSL_SetIOWriteCtx(*ssl_s, ctx);
        wolfSSL_SetIOReadCtx(*ssl_s, ctx);
#if !defined(NO_DH)
        SetDH(*ssl_s);
#endif
    }

    return 0;
}

void test_memio_simulate_want_write(struct test_memio_ctx *ctx, int is_client,
        int enable)
{
    if (ctx == NULL)
        return;

    if (is_client)
        ctx->c_force_want_write = (enable != 0);
    else
        ctx->s_force_want_write = (enable != 0);
}

void test_memio_clear_buffer(struct test_memio_ctx *ctx, int is_client)
{
    if (is_client) {
        ctx->c_len = 0;
        ctx->c_msg_pos = 0;
        ctx->c_msg_count = 0;
        ctx->c_force_want_write = 0;
    } else {
        ctx->s_len = 0;
        ctx->s_msg_pos = 0;
        ctx->s_msg_count = 0;
        ctx->s_force_want_write = 0;
    }
}

/* Inject a message into the buffer for client or server */
int test_memio_inject_message(struct test_memio_ctx* ctx, int client,
    const char* data, int sz)
{
    int* len;
    int* msg_count;
    int* msg_sizes;
    byte* buff;

    /* Select buffer and metadata for client or server */
    if (client) {
        buff = ctx->c_buff;
        len = &ctx->c_len;
        msg_count = &ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    }
    else {
        buff = ctx->s_buff;
        len = &ctx->s_len;
        msg_count = &ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Check if buffer has enough space for new message */
    if (*len + sz > TEST_MEMIO_BUF_SZ) {
        return -1;
    }
    /* Check if message count does not exceed maximum allowed */
    if (*msg_count >= TEST_MEMIO_MAX_MSGS) {
        return -1;
    }

    /* Copy message data into buffer */
    XMEMCPY(buff + *len, data, (size_t)sz);

    /* Record message size and increment message count */
    msg_sizes[*msg_count] = sz;
    (*msg_count)++;
    *len += sz;

    return 0;
}

/* Copy a message from the buffer to an output buffer */
int test_memio_copy_message(const struct test_memio_ctx *ctx, int client,
        char *out, int *out_sz, int msg_pos)
{
    const char* buff = NULL;
    int buff_sz = 0;

    /* Retrieve message pointer and size for given position */
    if (test_memio_get_message(ctx, client, &buff, &buff_sz, msg_pos) != 0)
        return -1;

    /* Ensure output buffer is large enough */
    if (*out_sz < buff_sz)
        return -1;

    /* Copy message to output buffer */
    XMEMCPY(out, buff, (size_t)buff_sz);
    *out_sz = buff_sz;

    return 0;
}

/* Get a pointer and size to a message in the buffer */
int test_memio_get_message(const struct test_memio_ctx *ctx, int client,
        const char **out, int *out_sz, int msg_pos)
{
    int msg_count;
    const int* msg_sizes;
    int i;
    const byte* buff;

    /* Select buffer and message metadata for client or server */
    if (client) {
        buff = ctx->c_buff;
        msg_count = ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    }
    else {
        buff = ctx->s_buff;
        msg_count = ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Validate message position */
    if (msg_pos < 0 || msg_pos >= msg_count) {
        return -1;
    }

    /* Find start of the message in the buffer */
    for (i = 0; i < msg_pos; i++) {
        buff += msg_sizes[i];
    }

    /* Set output pointers to message data and size */
    *out = (const char*)buff;
    *out_sz = msg_sizes[msg_pos];

    return 0;
}

int test_memio_move_message(struct test_memio_ctx *ctx, int client,
        int msg_pos_in, int msg_pos_out)
{
    int msg_count;
    int* msg_sizes;
    int i;
    byte* buff;
    byte* buff_in;
    byte* buff_out;
    int total_size = 0;
    int msg_in_size;

    /* Select buffer and message metadata for client or server */
    if (client) {
        buff = buff_in = buff_out = ctx->c_buff;
        msg_count = ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    }
    else {
        buff = buff_in = buff_out = ctx->s_buff;
        msg_count = ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Validate input and output message positions */
    if (msg_pos_in < 0 || msg_pos_in >= msg_count)
        return -1;
    if (msg_pos_out < 0 || msg_pos_out >= msg_count)
        msg_pos_out = msg_count-1;
    if (msg_pos_in == msg_pos_out)
        return 0;

    /* Get the size of the message to move */
    msg_in_size = msg_sizes[msg_pos_in];

    /* Calculate the total size of all messages */
    for (i = 0; i < msg_count; i++)
        total_size += msg_sizes[i];

    /* Check if buffer has enough space for the move */
    if (total_size + msg_in_size > TEST_MEMIO_BUF_SZ)
        return -1;

    /* Find the start of the input message in the buffer */
    for (i = 0; i < msg_pos_in; i++)
        buff_in += msg_sizes[i];

    /* Find the position to move the message to in the buffer */
    for (i = 0; i < msg_pos_out + (msg_pos_out > msg_pos_in ? 1 : 0); i++)
        buff_out += msg_sizes[i];

    /* Make space for the moved message at the output position */
    XMEMMOVE(buff_out + msg_in_size, buff_out,
            total_size - (buff_out - buff));
    total_size += msg_in_size;

    /* Adjust input pointer if it was after the output position */
    if (buff_in > buff_out)
        buff_in += msg_in_size;

    /* Copy the message to its new position */
    XMEMCPY(buff_out, buff_in, msg_in_size);

    /* Remove the original message from its old position */
    XMEMMOVE(buff_in, buff_in + msg_in_size,
            total_size - (buff_in - buff) - msg_in_size);

    /* Update the message sizes array to reflect the move */
    if (msg_pos_in < msg_pos_out) {
        XMEMMOVE(msg_sizes + msg_pos_in, msg_sizes + msg_pos_in + 1,
                sizeof(*msg_sizes) *
                    ((msg_sizes + msg_pos_out) - (msg_sizes + msg_pos_in)));
        msg_sizes[msg_pos_out] = msg_in_size;
    }
    else {
        XMEMMOVE(msg_sizes + msg_pos_out + 1, msg_sizes + msg_pos_out,
                sizeof(*msg_sizes) *
                    ((msg_sizes + msg_pos_in) - (msg_sizes + msg_pos_out)));
        msg_sizes[msg_pos_out] = msg_in_size;
    }

    return 0;
}

/* Drop (remove) a message from the buffer and update metadata */
int test_memio_drop_message(struct test_memio_ctx *ctx, int client, int msg_pos)
{
    int *len;
    int *msg_count;
    int *msg_sizes;
    int msg_off, msg_sz;
    int i;
    byte *buff;

    /* Select buffer and metadata for client or server */
    if (client) {
        buff = ctx->c_buff;
        len = &ctx->c_len;
        msg_count = &ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    } else {
        buff = ctx->s_buff;
        len = &ctx->s_len;
        msg_count = &ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Check for empty message list */
    if (*msg_count == 0) {
        return -1;
    }

    msg_off = 0;
    /* Validate message position */
    if (msg_pos >= *msg_count) {
        return -1;
    }

    /* Find offset and size of message to drop */
    msg_sz = msg_sizes[msg_pos];
    for (i = 0; i < msg_pos; i++) {
        msg_off += msg_sizes[i];
    }

    /* Remove message from buffer by shifting remaining data */
    XMEMMOVE(buff + msg_off, buff + msg_off + msg_sz, *len - msg_off - msg_sz);

    /* Update message sizes array */
    for (i = msg_pos; i < *msg_count - 1; i++) {
        msg_sizes[i] = msg_sizes[i + 1];
    }

    /* Update buffer length and message count */
    *len -= msg_sz;
    (*msg_count)--;

    return 0;
}

/* Remove a region from the buffer, possibly dropping or shrinking a message */
int test_memio_remove_from_buffer(struct test_memio_ctx* ctx, int client,
    int off, int sz)
{
    int* len;
    int* msg_count;
    int* msg_sizes;
    int msg_off;
    int i;
    byte* buff;

    /* Select buffer and metadata for client or server */
    if (client) {
        buff = ctx->c_buff;
        len = &ctx->c_len;
        msg_count = &ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    }
    else {
        buff = ctx->s_buff;
        len = &ctx->s_len;
        msg_count = &ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Validate buffer and offset */
    if (*len == 0) {
        return -1;
    }
    if (off >= *len) {
        return -1;
    }
    if (off + sz > *len) {
        return -1;
    }

    /* Find which message the offset is in */
    msg_off = 0;
    for (i = 0; i < *msg_count; i++) {
        if (off >= msg_off && off < msg_off + msg_sizes[i]) {
            break;
        }
        msg_off += msg_sizes[i];
    }

    /* Don't support records split across messages */
    if (off + sz > msg_off + msg_sizes[i]) {
        return -1;
    }
    if (i == *msg_count) {
        return -1;
    }

    /* If removing entire message, drop it */
    if (sz == msg_sizes[i]) {
        return test_memio_drop_message(ctx, client, i);
    }

    /* Remove part of message by shifting buffer and updating size */
    XMEMMOVE(buff + off, buff + off + sz, *len - off - sz);
    msg_sizes[i] -= sz;
    *len -= sz;

    return 0;
}

/* Modify the length of a message in the buffer, shifting data as needed */
int test_memio_modify_message_len(struct test_memio_ctx* ctx, int client,
    int msg_pos, int new_len)
{
    int* len;
    int* msg_count;
    int* msg_sizes;
    int msg_off, msg_sz;
    int i;
    byte* buff;

    /* Select buffer and metadata for client or server */
    if (client) {
        buff = ctx->c_buff;
        len = &ctx->c_len;
        msg_count = &ctx->c_msg_count;
        msg_sizes = ctx->c_msg_sizes;
    }
    else {
        buff = ctx->s_buff;
        len = &ctx->s_len;
        msg_count = &ctx->s_msg_count;
        msg_sizes = ctx->s_msg_sizes;
    }

    /* Validate message count and position */
    if (*msg_count == 0) {
        return -1;
    }
    if (msg_pos >= *msg_count) {
        return -1;
    }

    /* Find offset and size of message to modify */
    msg_off = 0;
    for (i = 0; i < msg_pos; i++) {
        msg_off += msg_sizes[i];
    }
    msg_sz = msg_sizes[msg_pos];

    /* Check if buffer has enough space for length increase */
    if (new_len > msg_sz) {
        if (*len + (new_len - msg_sz) > TEST_MEMIO_BUF_SZ) {
            return -1;
        }
    }

    /* Shift buffer contents to accommodate new message length */
    XMEMMOVE(buff + msg_off + new_len, buff + msg_off + msg_sz,
        *len - msg_off - msg_sz);

    /* Update message size and buffer length */
    msg_sizes[msg_pos] = new_len;
    *len = *len - msg_sz + new_len;

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
