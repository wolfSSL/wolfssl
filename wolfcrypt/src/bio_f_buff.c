/* bio_f_buff.c
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

#include <wolfssl/wolfcrypt/settings.h>

#ifdef OPENSSL_EXTRA

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/openssl/bio.h>

typedef struct {
    /*-
     * Buffers are setup like this:
     *
     * <---------------------- size ----------------------->
     * +---------------------------------------------------+
     * | consumed | remaining          | free space        |
     * +---------------------------------------------------+
     * <-- off --><------- len ------->
     */

    /* input buffer */
    char *in;   /* the char array */
    int inSz;   /* how big is the input buffer */
    int inLen;  /* how many bytes are in it */
    int inIdx;  /* write/read offset */

    /* output buffer */
    char *out;  /* the char array */
    int outSz;  /* how big is the output buffer */
    int outLen; /* how many bytes are in it */
    int outIdx; /* write/read offset */

} WOLFCRYPT_BIO_F_BUFFER_CTX;

/* OpenSSL default value */
#define WOLFSSL_F_BUFFER_SIZE_DEFAULT 4096

static int WOLFCRYPT_BIO_buffer_write(WOLFCRYPT_BIO *bio,
                                   const char *buf, int size);
static int WOLFCRYPT_BIO_buffer_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_buffer_puts(WOLFCRYPT_BIO *bio, const char *str);
static int WOLFCRYPT_BIO_buffer_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_buffer_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_buffer_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_buffer_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_buffer_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_buffer_method = {
    BIO_TYPE_BUFFER,
    "Buffer",
    WOLFCRYPT_BIO_buffer_write,
    WOLFCRYPT_BIO_buffer_read,
    WOLFCRYPT_BIO_buffer_puts,
    WOLFCRYPT_BIO_buffer_gets,
    WOLFCRYPT_BIO_buffer_ctrl,
    WOLFCRYPT_BIO_buffer_new,
    WOLFCRYPT_BIO_buffer_free,
    WOLFCRYPT_BIO_buffer_callback_ctrl,
};


static long WOLFCRYPT_BIO_buffer_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp)
{
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return WOLFCRYPT_BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_buffer(void)
{
    return (&WOLFCRYPT_BIO_buffer_method);
}

static int WOLFCRYPT_BIO_buffer_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->ptr = (WOLFCRYPT_BIO_F_BUFFER_CTX *)
               XMALLOC(sizeof(WOLFCRYPT_BIO_F_BUFFER_CTX),
                       0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    ctx->in = (char *)XMALLOC(WOLFSSL_F_BUFFER_SIZE_DEFAULT, 0,
                                   DYNAMIC_TYPE_OPENSSL);
    if (ctx->in == NULL) {
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx->out = (char *)XMALLOC(WOLFSSL_F_BUFFER_SIZE_DEFAULT, 0,
                                    DYNAMIC_TYPE_OPENSSL);
    if (ctx->out == NULL) {
        XFREE(ctx->in, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx->inSz = WOLFSSL_F_BUFFER_SIZE_DEFAULT;
    ctx->inLen = 0;
    ctx->inIdx = 0;
    ctx->outSz = WOLFSSL_F_BUFFER_SIZE_DEFAULT;
    ctx->outLen = 0;
    ctx->outIdx = 0;

    bio->init = 1;
    bio->flags = 0;
    return 1;
}

static int WOLFCRYPT_BIO_buffer_free(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_buffer_free");

    if (bio == NULL)
        return 0;

    if (!bio->init || bio->ptr == NULL)
        return 1;

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    if (ctx->in != NULL) {
        XFREE(ctx->in, 0, DYNAMIC_TYPE_OPENSSL);
        ctx->in = NULL;
    }

    if (ctx->out != NULL) {
        XFREE(ctx->out, 0, DYNAMIC_TYPE_OPENSSL);
        ctx->out = NULL;
    }

    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;

    bio->init = 0;
    bio->flags = 0;
    return 1;
}

static int WOLFCRYPT_BIO_buffer_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int i, num = 0;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || !bio->init ||
        bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    for (;;) {
        i = ctx->inLen;
        if (i != 0) {
            if (i > size)
                i = size;
            XMEMCPY(data, &(ctx->in[ctx->inIdx]), i);
            ctx->inIdx += i;
            ctx->inLen -= i;
            num += i;
            if (size == i)
                return num;
            size -= i;
            data += i;
        }

        /* case of partial read */
        if (size > ctx->inSz) {
            for (;;) {
                i = WOLFCRYPT_BIO_read(bio->next_bio, data, size);
                if (i <= 0) {
                    WOLFCRYPT_BIO_copy_next_retry(bio);
                    if (i < 0)
                        return (num > 0 ? num : i);
                    else if (i == 0)
                        return num;
                }
                num += i;

                if (size == i)
                    return num;
                data += i;
                size -= i;
            }
        }

        /* we are going to be doing some buffering */
        i = WOLFCRYPT_BIO_read(bio->next_bio, ctx->in, ctx->inSz);
        if (i <= 0) {
            WOLFCRYPT_BIO_copy_next_retry(bio);
            if (i < 0)
                return (num > 0 ? num : i);
            if (i == 0)
                return num;
        }
        ctx->inIdx = 0;
        ctx->inLen = i;
    }

    return 1;
}

static int WOLFCRYPT_BIO_buffer_write(WOLFCRYPT_BIO *bio,
                                   const char *data, int size)
{
    int i, num = 0;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    for (;;) {
        i = ctx->outSz - (ctx->outLen + ctx->outIdx);

        /* add to buffer and return */
        if (i >= size) {
            XMEMCPY(&(ctx->out[ctx->outIdx + ctx->outLen]), data, size);
            ctx->outLen += size;
            return (num + size);
        }

        /* stuff already in buffer, so add to it first, then flush */
        if (ctx->outLen != 0) {
            if (i > 0) {
                XMEMCPY(&(ctx->out[ctx->outIdx + ctx->outLen]), data, i);
                data += i;
                size -= i;
                num += i;
                ctx->outLen += i;
            }

            /* we now have a full buffer needing flushing */
            do {
                i = WOLFCRYPT_BIO_write(bio->next_bio,
                                        &(ctx->out[ctx->outIdx]), ctx->outLen);
                if (i <= 0) {
                    WOLFCRYPT_BIO_copy_next_retry(bio);

                    if (i < 0)
                        return (num > 0 ? num : i);
                    if (i == 0)
                        return num;
                }

                ctx->outIdx += i;
                ctx->outLen -= i;

            } while (ctx->outLen != 0);
        }

        ctx->outIdx = 0;

        /* we now have size bytes to write */
        while (size >= ctx->outSz) {
            i = WOLFCRYPT_BIO_write(bio->next_bio, data, size);
            if (i <= 0) {
                WOLFCRYPT_BIO_copy_next_retry(bio);
                if (i < 0)
                    return (num > 0 ? num : i);
                if (i == 0)
                    return num;
            }
            num += i;
            data += i;
            size -= i;
            if (size == 0)
                return num;
        }
    }

    return 1;
}

static long WOLFCRYPT_BIO_buffer_ctrl(WOLFCRYPT_BIO *bio,
                                  int cmd, long num, void *ptr)
{

    int i, *ip, ibs, obs;
    long ret = 1;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->inLen = 0;
            ctx->inIdx = 0;
            ctx->outLen = 0;
            ctx->outIdx = 0;

            if (bio->next_bio == NULL)
                return 0;

            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_INFO:
            ret = (long)ctx->outLen;
            break;

        case BIO_C_GET_BUFF_NUM_LINES:
            ret = 0;
            for (i = 0; i < ctx->inLen; i++) {
                if (ctx->in[ctx->inIdx + i] == '\n')
                    ret++;
            }
            break;

        case BIO_CTRL_WPENDING:
            ret = (long)ctx->outLen;
            if (ret == 0) {
                if (bio->next_bio == NULL)
                    return 0;
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            }
            break;

        case BIO_CTRL_PENDING:
            ret = (long)ctx->inLen;
            if (ret == 0) {
                if (bio->next_bio == NULL)
                    return 0;
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            }
            break;

        case BIO_C_SET_BUFF_READ_DATA:
            if (num > ctx->inSz) {
                ctx->in = XREALLOC(ctx->in, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->in == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }
            }

            ctx->inIdx = 0;
            ctx->inLen = (int)num;
            XMEMCPY(ctx->in, ptr, num);
            ret = 1;
            break;

        case BIO_C_SET_BUFF_SIZE:
            if (ptr != NULL) {
                ip = (int *)ptr;
                if (*ip == 0) {
                    ibs = (int)num;
                    obs = ctx->outSz;
                } else {
                    ibs = ctx->inSz;
                    obs = (int)num;
                }
            } else {
                ibs = (int)num;
                obs = (int)num;
            }

            if ((ibs > WOLFSSL_F_BUFFER_SIZE_DEFAULT) && (ibs != ctx->inSz)) {
                ctx->in = XREALLOC(ctx->in, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->in == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }

                ctx->inIdx = 0;
                ctx->inLen = 0;
                ctx->inSz = ibs;
            }

            if ((obs > WOLFSSL_F_BUFFER_SIZE_DEFAULT) && (obs != ctx->outSz)) {
                ctx->out = XREALLOC(ctx->out, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->out == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }

                ctx->outIdx = 0;
                ctx->outLen = 0;
                ctx->outSz = obs;
            }
            break;

        case BIO_C_DO_STATE_MACHINE:
            if (bio->next_bio == NULL) {
                WOLFSSL_ERROR(BAD_FUNC_ARG);
                return 0;
            }

            WOLFCRYPT_BIO_clear_retry_flags(bio);
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            WOLFCRYPT_BIO_copy_next_retry(bio);
            break;

        case BIO_CTRL_FLUSH:
            if (bio->next_bio == NULL) {
                WOLFSSL_ERROR(BAD_FUNC_ARG);
                return 0;
            }

            if (ctx->outLen <= 0) {
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
                break;
            }

            for (;;) {
                WOLFCRYPT_BIO_clear_retry_flags(bio);
                if (ctx->outLen > 0) {
                    ret = WOLFCRYPT_BIO_write(bio->next_bio,
                                  &(ctx->out[ctx->outIdx]), ctx->outLen);
                    WOLFCRYPT_BIO_copy_next_retry(bio);
                    if (ret <= 0)
                        return ret;
                    ctx->outIdx += ret;
                    ctx->outLen -= ret;
                } else {
                    ctx->outLen = 0;
                    ctx->outIdx = 0;
                    ret = 1;
                    break;
                }
            }

            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_DUP:
            ret = WOLFCRYPT_BIO_set_read_buffer_size((WOLFCRYPT_BIO *)ptr,
                                                     ctx->inSz);
            if (!ret)
                break;

            ret = WOLFCRYPT_BIO_set_write_buffer_size((WOLFCRYPT_BIO *)ptr,
                                                       ctx->outSz);
            if (!ret)
                break;

            ret = 1;
            break;

        default:
            if (bio->next_bio == NULL)
                return 0;

            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_buffer_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;
    int num = 0, i, flag;

    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    /* to put end of string */
    size--;

    for (;;) {
        if (ctx->inLen > 0) {
                //            p = &(ctx->in[ctx->inIdx]);
            flag = 0;

            for (i = 0; (i < ctx->inLen) && (i < size); i++) {
                *(buf++) = ctx->in[ctx->inIdx+i];
                if (ctx->in[ctx->inIdx+i] == '\n') {
                    flag = 1;
                    i++;
                    break;
                }
            }
            num += i;
            size -= i;
            ctx->inLen -= i;
            ctx->inIdx += i;
            if (flag || !size) {
                *buf = '\0';
                return num;
            }
        } else {
            i = WOLFCRYPT_BIO_read(bio->next_bio, ctx->in, ctx->inSz);
            if (i <= 0) {
                WOLFCRYPT_BIO_copy_next_retry(bio);
                *buf = '\0';
                if (i < 0)
                    return (num > 0 ? num : i);
                if (i == 0)
                    return num;
            }
            ctx->inLen = i;
            ctx->inIdx = 0;
        }
    }

    return i;
}

static int WOLFCRYPT_BIO_buffer_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return WOLFCRYPT_BIO_buffer_write(bio, str, (int)strlen(str));
}

#endif /* OPENSSL_EXTRA */
