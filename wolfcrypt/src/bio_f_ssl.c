/* bio_f_ssl.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>

#ifdef OPENSSL_EXTRA

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#include <wolfssl/openssl/bio.h>

typedef struct {
    WOLFSSL *ssl;
    /* re-negotiate every time the total number of bytes is this size */
    int           num_renegotiates;
    unsigned long renegotiate_count;
    unsigned long byte_count;
    unsigned long renegotiate_timeout;
    unsigned long last_time;
} WOLFCRYPT_BIO_SSL;

static int WOLFCRYPT_BIO_ssl_write(WOLFCRYPT_BIO *bio,
                                    const char *data, int size);
static int WOLFCRYPT_BIO_ssl_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int WOLFCRYPT_BIO_ssl_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_ssl_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                    long num, void *ptr);
static int WOLFCRYPT_BIO_ssl_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_ssl_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_ssl_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                            WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_ssl_method = {
    BIO_TYPE_SSL,
    "SSL",
    WOLFCRYPT_BIO_ssl_write,
    WOLFCRYPT_BIO_ssl_read,
    WOLFCRYPT_BIO_ssl_puts,
    NULL, /* gets */
    WOLFCRYPT_BIO_ssl_ctrl,
    WOLFCRYPT_BIO_ssl_new,
    WOLFCRYPT_BIO_ssl_free,
    WOLFCRYPT_BIO_ssl_callback_ctrl,
};

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_ssl(void)
{
    return (&WOLFCRYPT_BIO_ssl_method);
}

static int WOLFCRYPT_BIO_ssl_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = (WOLFCRYPT_BIO_SSL *)XMALLOC(sizeof(WOLFCRYPT_BIO_SSL),
                                            0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_SSL));

    bio->init = 0;
    bio->flags = 0;
    return 1;
}

static int WOLFCRYPT_BIO_ssl_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->ptr != NULL) {
        WOLFCRYPT_BIO_SSL *bssl = (WOLFCRYPT_BIO_SSL *)bio->ptr;
        if (bssl->ssl != NULL) {
            wolfSSL_shutdown(bssl->ssl);

            if (bio->shutdown && bio->init) {
                WOLFSSL_MSG("Free BIO ssl");
                wolfSSL_free(bssl->ssl);
            }
        }

        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        bio->ptr = NULL;
    }

    if (bio->shutdown) {
        bio->init = 0;
        bio->flags = 0;
    }

    return 1;
}

static int WOLFCRYPT_BIO_ssl_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 1;
    WOLFCRYPT_BIO_SSL *bssl;

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if  (data == NULL)
        return 0;

    bssl = (WOLFCRYPT_BIO_SSL *)bio->ptr;

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ret = wolfSSL_read(bssl->ssl, data, size);

    switch (wolfSSL_get_error(bssl->ssl, ret)) {
        case SSL_ERROR_NONE:
            if (ret <= 0)
                break;

#ifdef HAVE_SECURE_RENEGOTIATION
            {
                int r = 0;

                if (bssl->renegotiate_count > 0) {
                    bssl->byte_count += ret;
                    if (bssl->byte_count > bssl->renegotiate_count) {
                        bssl->byte_count = 0;
                        bssl->num_renegotiates++;
                        wolfSSL_Rehandshake(bssl->ssl);
                        r = 1;
                    }
                }

                if ((bssl->renegotiate_timeout > 0) && !r) {
                    unsigned long tm;
                    tm = (unsigned long)time(NULL);
                    if (tm > bssl->last_time + bssl->renegotiate_timeout) {
                        bssl->last_time = tm;
                        bssl->num_renegotiates++;
                        wolfSSL_Rehandshake(bssl->ssl);
                    }
                }
            }
#endif
            break;

        case SSL_ERROR_WANT_READ:
            WOLFCRYPT_BIO_set_retry_read(bio);
            break;

        case SSL_ERROR_WANT_WRITE:
            WOLFCRYPT_BIO_set_retry_write(bio);
            break;

        case SSL_ERROR_WANT_X509_LOOKUP:
            WOLFCRYPT_BIO_set_retry_special(bio);
            bio->retry_reason = BIO_RR_SSL_X509_LOOKUP;
            break;

        case SSL_ERROR_WANT_ACCEPT:
            WOLFCRYPT_BIO_set_retry_special(bio);
            bio->retry_reason = BIO_RR_ACCEPT;
            break;

        case SSL_ERROR_WANT_CONNECT:
            WOLFCRYPT_BIO_set_retry_special(bio);
            bio->retry_reason = BIO_RR_CONNECT;
            break;

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        case SSL_ERROR_ZERO_RETURN:
            break;

        default:
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_ssl_write(WOLFCRYPT_BIO *bio,
                                   const char *data, int size)
{
    int ret;
    WOLFCRYPT_BIO_SSL *bssl;

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if  (data == NULL)
        return 0;

    bssl = (WOLFCRYPT_BIO_SSL *)bio->ptr;

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ret = wolfSSL_write(bssl->ssl, data, size);

    switch (wolfSSL_get_error(bssl->ssl, ret)) {
        case SSL_ERROR_NONE:
            if (ret <= 0)
                break;

#ifdef HAVE_SECURE_RENEGOTIATION
            {
                int r = 0;

                if (bssl->renegotiate_count > 0) {
                    bssl->byte_count += ret;
                    if (bssl->byte_count > bssl->renegotiate_count) {
                        bssl->byte_count = 0;
                        bssl->num_renegotiates++;
                        wolfSSL_Rehandshake(bssl->ssl);
                        r = 1;
                    }
                }

                if ((bssl->renegotiate_timeout > 0) && !r) {
                    unsigned long tm;

                    tm = (unsigned long)time(NULL);
                    if (tm > bssl->last_time + bssl->renegotiate_timeout) {
                        bssl->last_time = tm;
                        bssl->num_renegotiates++;
                        wolfSSL_Rehandshake(bssl->ssl);
                    }
                }
            }
#endif
            break;

        case SSL_ERROR_WANT_WRITE:
            WOLFCRYPT_BIO_set_retry_write(bio);
            break;

        case SSL_ERROR_WANT_READ:
            WOLFCRYPT_BIO_set_retry_read(bio);
            break;

        case SSL_ERROR_WANT_X509_LOOKUP:
            WOLFCRYPT_BIO_set_retry_special(bio);
            bio->retry_reason = BIO_RR_SSL_X509_LOOKUP;
            break;

        case SSL_ERROR_WANT_CONNECT:
            WOLFCRYPT_BIO_set_retry_special(bio);
            bio->retry_reason = BIO_RR_CONNECT;
                break;

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            break;

        default:
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_ssl_set_bio(WOLFSSL *ssl, WOLFCRYPT_BIO *rbio,
                                     WOLFCRYPT_BIO *wbio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_set_bio");

    if (ssl == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if (ssl->biord != NULL && ssl->biord != rbio)
        WOLFCRYPT_BIO_free_all(ssl->biord);
    if (ssl->biowr != NULL && ssl->biowr != wbio && ssl->biord != ssl->biowr)
        WOLFCRYPT_BIO_free_all(ssl->biowr);

    ssl->biord = rbio;
    wolfSSL_set_rfd(ssl, rbio->num);

    ssl->biowr = wbio;
    wolfSSL_set_wfd(ssl, wbio->num);

    return 1;
}

static long WOLFCRYPT_BIO_ssl_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                   long num, void *ptr)
{
    WOLFCRYPT_BIO_SSL *bssl;
    long ret = 1;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_ctrl");

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bssl = (WOLFCRYPT_BIO_SSL *)bio->ptr;

    if ((bssl->ssl == NULL) && (cmd != BIO_C_SET_SSL)) {
        WOLFSSL_MSG("Set SSL not possible, ssl pointer NULL\n");
        return 0;
    }

    switch (cmd) {
        case BIO_CTRL_RESET:
            wolfSSL_shutdown(bssl->ssl);
            ret = (long)wolfSSL_negotiate(bssl->ssl);
            if (ret <= 0)
                break;
            wolfSSL_clear(bssl->ssl);

            if (bio->next_bio != NULL)
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            else if (bssl->ssl->biord != NULL)
                ret = WOLFCRYPT_BIO_ctrl(bssl->ssl->biord, cmd, num, ptr);
            else
                ret = 1;
            break;

        case BIO_CTRL_INFO:
            ret = 0;
            break;

        case BIO_C_SSL_MODE:
            if (num) /* client mode */
                wolfSSL_set_connect_state(bssl->ssl);
            else
                wolfSSL_set_accept_state(bssl->ssl);
            break;

        case BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT:
            ret = bssl->renegotiate_timeout;
            if (num < 60)
                num = 5;
            bssl->renegotiate_timeout = (unsigned long)num;
            bssl->last_time = (unsigned long)time(NULL);
            break;

        case BIO_C_SET_SSL_RENEGOTIATE_BYTES:
            ret = bssl->renegotiate_count;
            if (num >= 512)
                bssl->renegotiate_count = (unsigned long)num;
            break;

        case BIO_C_GET_SSL_NUM_RENEGOTIATES:
            ret = bssl->num_renegotiates;
            break;

        case BIO_C_SET_SSL:
                if (bssl->ssl != NULL) {
                    WOLFCRYPT_BIO_ssl_free(bio);
                    if (!WOLFCRYPT_BIO_ssl_new(bio))
                        return 0;
                }

                bio->shutdown = (int)num;
                bssl->ssl = (WOLFSSL *)ptr;

                if (bssl->ssl->biord != NULL) {
                    if (bio->next_bio != NULL)
                        WOLFCRYPT_BIO_push(bssl->ssl->biord, bio->next_bio);
                    bio->next_bio = bssl->ssl->biord;

                    if (LockMutex(&bssl->ssl->biord->refMutex) != 0) {
                        WOLFSSL_MSG("Couldn't lock count mutex");
                        ret = 0;
                        break;
                    }
                    bssl->ssl->biord->references++;
                    UnLockMutex(&bssl->ssl->biord->refMutex);
                }
                bio->init = 1;
            break;

        case BIO_C_GET_SSL:
            if (ptr != NULL)
                *(WOLFSSL **)ptr = bssl->ssl;
            else
                ret = 0;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_WPENDING:
            ret = WOLFCRYPT_BIO_ctrl(bssl->ssl->biowr, cmd, num, ptr);
            break;

        case BIO_CTRL_PENDING:
            ret = wolfSSL_pending(bssl->ssl);
            if (!ret)
                ret = WOLFCRYPT_BIO_pending(bssl->ssl->biord);
            break;

        case BIO_CTRL_FLUSH:
            WOLFCRYPT_BIO_clear_retry_flags(bio);
            ret = WOLFCRYPT_BIO_ctrl(bssl->ssl->biowr, cmd, num, ptr);
            WOLFCRYPT_BIO_copy_next_retry(bio);
            break;

        case BIO_CTRL_PUSH:
            if (bio->next_bio != NULL && bio->next_bio != bssl->ssl->biord) {
                ret = WOLFCRYPT_BIO_ssl_set_bio(bssl->ssl,
                                                bio->next_bio, bio->next_bio);
                if (LockMutex(&bio->next_bio->refMutex) != 0) {
                    WOLFSSL_MSG("Couldn't lock count mutex");
                    ret = 0;
                    break;
                }
                bio->next_bio->references++;
                UnLockMutex(&bio->next_bio->refMutex);
            }
            break;

        case BIO_CTRL_POP:
            if (bio == ptr) {
                if (bssl->ssl->biord != bssl->ssl->biowr)
                    WOLFCRYPT_BIO_free_all(bssl->ssl->biowr);
                if (bio->next_bio != NULL) {
                    if (LockMutex(&bio->next_bio->refMutex) != 0) {
                        WOLFSSL_MSG("Couldn't lock count mutex");
                        ret = 0;
                        break;
                    }
                    bio->next_bio->references--;
                    UnLockMutex(&bio->next_bio->refMutex);
                }
                bssl->ssl->biowr = NULL;
                bssl->ssl->biord = NULL;
            }
            break;

        case BIO_C_DO_STATE_MACHINE:
            WOLFCRYPT_BIO_clear_retry_flags(bio);

            bio->retry_reason = 0;
            ret = (long)wolfSSL_negotiate(bssl->ssl);

            switch (wolfSSL_get_error(bssl->ssl, (int)ret)) {
                case SSL_ERROR_WANT_READ:
                    WOLFCRYPT_BIO_set_flags(bio, BIO_FLAGS_READ |
                                                 BIO_FLAGS_SHOULD_RETRY);
                    break;

                case SSL_ERROR_WANT_WRITE:
                    WOLFCRYPT_BIO_set_flags(bio, BIO_FLAGS_WRITE |
                                                 BIO_FLAGS_SHOULD_RETRY);
                    break;

                case SSL_ERROR_WANT_CONNECT:
                    WOLFCRYPT_BIO_set_flags(bio, BIO_FLAGS_IO_SPECIAL |
                                                 BIO_FLAGS_SHOULD_RETRY);
                    bio->retry_reason = bio->next_bio->retry_reason;
                    break;

                case SSL_ERROR_WANT_X509_LOOKUP:
                    WOLFCRYPT_BIO_set_retry_special(bio);
                    bio->retry_reason = BIO_RR_SSL_X509_LOOKUP;
                    break;

                default:
                    break;
                }
            break;

        case BIO_CTRL_DUP:
            {
                WOLFCRYPT_BIO *dbio;
                dbio = (WOLFCRYPT_BIO *)ptr;

                if (((WOLFCRYPT_BIO_SSL *)dbio->ptr)->ssl != NULL)
                       wolfSSL_free(((WOLFCRYPT_BIO_SSL *)dbio->ptr)->ssl);

                /* add copy ssl */
                ((WOLFCRYPT_BIO_SSL *)dbio->ptr)->ssl = wolfSSL_dup(bssl->ssl);

                ((WOLFCRYPT_BIO_SSL *)dbio->ptr)->renegotiate_count =
                                                    bssl->renegotiate_count;

                ((WOLFCRYPT_BIO_SSL *)dbio->ptr)->byte_count = bssl->byte_count;

                ((WOLFCRYPT_BIO_SSL *)dbio->ptr)->renegotiate_timeout =
                                                    bssl->renegotiate_timeout;

                ((WOLFCRYPT_BIO_SSL *)dbio->ptr)->last_time = bssl->last_time;

                if (((WOLFCRYPT_BIO_SSL *)dbio->ptr)->ssl == NULL)
                    ret = 0;
            }
            break;

        case BIO_C_GET_FD:
            ret = WOLFCRYPT_BIO_ctrl(bssl->ssl->biord, cmd, num, ptr);
            break;

        case BIO_CTRL_SET_CALLBACK:
            /* not supported */
            WOLFSSL_MSG("BIO_CTRL_SET_CALLBACK not supported\n");
            ret = 0;
            break;

        case BIO_CTRL_GET_CALLBACK:
            /* not supported */
            WOLFSSL_MSG("BIO_CTRL_GET_CALLBACK not supported\n");
            ptr = NULL;
            ret = 0;
            break;

        default:
            ret = WOLFCRYPT_BIO_ctrl(bssl->ssl->biord, cmd, num, ptr);
            break;
    }

    return ret;
}

static long WOLFCRYPT_BIO_ssl_callback_ctrl(WOLFCRYPT_BIO *bio,
                                            int cmd, WOLFCRYPT_BIO_info_cb *fp)
{
    long ret = 1;
    WOLFCRYPT_BIO_SSL *bssl;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_callback_ctrl");

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bssl = (WOLFCRYPT_BIO_SSL *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_SET_CALLBACK:
            /* not supported */
            WOLFSSL_MSG("BIO_CTRL_GET_CALLBACK not supported\n");
            ret = 0;
            break;

        default:
            ret = WOLFCRYPT_BIO_callback_ctrl(bssl->ssl->biord, cmd, fp);
        break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_ssl_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_puts");

    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return WOLFCRYPT_BIO_ssl_write(bio, str, (int)strlen(str));
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_buffer_ssl_connect(WOLFSSL_CTX *ctx)
{
    WOLFCRYPT_BIO *bio = NULL, *buf = NULL, *ssl = NULL;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_new_buffer_ssl_connect");

    if (ctx == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    buf = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_f_buffer());
    if (buf == NULL)
        return NULL;

    ssl = WOLFCRYPT_BIO_new_ssl_connect(ctx);
    if (ssl == NULL)
        goto err;

    bio = WOLFCRYPT_BIO_push(buf, ssl);
    if (bio == NULL)
        goto err;

    return bio;

 err:
    if (buf != NULL)
        WOLFCRYPT_BIO_free(buf);
    if (ssl != NULL)
        WOLFCRYPT_BIO_free(ssl);

    return NULL;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_ssl_connect(WOLFSSL_CTX *ctx)
{
    WOLFCRYPT_BIO *bio = NULL, *con = NULL, *ssl = NULL;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_new_ssl_connect");

    if (ctx == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    con = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_connect());
    if (con == NULL)
        return NULL;

    ssl = WOLFCRYPT_BIO_new_ssl(ctx, 1);
    if (ssl == NULL)
        goto err;

    bio = WOLFCRYPT_BIO_push(ssl, con);
    if (bio == NULL)
        goto err;

    return bio;

 err:
    if (con != NULL)
        WOLFCRYPT_BIO_free(con);
    if (ssl != NULL)
        WOLFCRYPT_BIO_free(ssl);
    return NULL;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_ssl(WOLFSSL_CTX *ctx, int mode)
{
    WOLFCRYPT_BIO *bio;
    WOLFSSL *ssl;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_new_ssl");

    if (ctx == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_f_ssl());
    if (bio == NULL)
        return NULL;

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        WOLFCRYPT_BIO_free(bio);
        return NULL;
    }

    if (mode) /* client */
        wolfSSL_set_connect_state(ssl);
    else
        wolfSSL_set_accept_state(ssl);

    WOLFCRYPT_BIO_set_ssl(bio, ssl, BIO_CLOSE);

    return bio;
}

void WOLFCRYPT_BIO_ssl_shutdown(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_ssl_shutdown");

    while (bio != NULL) {
        if (bio->method->type == BIO_TYPE_SSL) {
            wolfSSL_shutdown(((WOLFCRYPT_BIO_SSL *)bio->ptr)->ssl);
            break;
        }

        bio = bio->next_bio;
    }
}


#endif /* OPENSSL_EXTRA */
