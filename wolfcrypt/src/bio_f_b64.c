/* bio_f_b64.c
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
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/openssl/bio.h>

static int WOLFCRYPT_BIO_b64_write(WOLFCRYPT_BIO *bio,
                                   const char *buf, int size);
static int WOLFCRYPT_BIO_b64_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_b64_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_b64_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                   long num, void *ptr);
static int WOLFCRYPT_BIO_b64_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_b64_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_b64_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                            WOLFCRYPT_BIO_info_cb *fp);

#define WOLFCRYPT_B64_BLOCK_SIZE  20*48
#define WOLFCRYPT_B64_ENCODE_SIZE 20*64 + 40 // 40 : 20 CR LF
#define WOLFCRYPT_B64_NONE        0
#define WOLFCRYPT_B64_ENCODE      1
#define WOLFCRYPT_B64_DECODE      2


typedef struct {
    int dataLen; /* data length */
    int dataIdx; /* data index */
    int workLen; /* working buffer length */
    int workNl;  /* used to stop when find a '\n' */
    int encode;  /* base64 operation */
    int start;   /* decoding started */
    int cont;    /* <= 0 when finished */

    char data[WOLFCRYPT_B64_ENCODE_SIZE];
    char work[WOLFCRYPT_B64_BLOCK_SIZE];
} WOLFCRYPT_BIO_F_B64_CTX;

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_b64_method = {
    BIO_TYPE_BASE64,
    "Base64",
    WOLFCRYPT_BIO_b64_write,
    WOLFCRYPT_BIO_b64_read,
    WOLFCRYPT_BIO_b64_puts,
    NULL,                       /* gets */
    WOLFCRYPT_BIO_b64_ctrl,
    WOLFCRYPT_BIO_b64_new,
    WOLFCRYPT_BIO_b64_free,
    WOLFCRYPT_BIO_b64_callback_ctrl,
};


WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_base64(void)
{
    return (&WOLFCRYPT_BIO_b64_method);
}

static int WOLFCRYPT_BIO_b64_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_B64_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->ptr = (WOLFCRYPT_BIO_F_B64_CTX *)
                XMALLOC(sizeof(WOLFCRYPT_BIO_F_B64_CTX),
                        0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    ctx->dataLen = 0;
    ctx->workLen = 0;
    ctx->workNl = 0;
    ctx->dataIdx = 0;
    ctx->cont = 1;
    ctx->start = 1;
    ctx->encode = 0;

    bio->init = 1;
    bio->flags = 0;
    bio->num = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_new", 1);
    return 1;
}

static int WOLFCRYPT_BIO_b64_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->ptr != NULL) {
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        bio->ptr = NULL;
    }

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_free", 1);

    return 1;
}


static int WOLFCRYPT_BIO_b64_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0, idx, bread, j, k, num, ret_code = 0;
    WOLFCRYPT_BIO_F_B64_CTX *ctx;
        //unsigned char *p, *q;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_read");

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    /* decode when reading */
    if (ctx->encode != WOLFCRYPT_B64_DECODE) {
        ctx->encode = WOLFCRYPT_B64_DECODE;
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
        ctx->workLen = 0;
            //WOLFCRYPT_EVP_DecodeInit(&(ctx->b64_ctx));
    }

    /* First check if there are bytes decoded/encoded */
    if (ctx->dataLen > 0) {
        if (ctx->dataLen < ctx->dataIdx) {
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_read", -1);
            return -1;
        }

        bread = ctx->dataLen - ctx->dataIdx;
        if (bread > size)
            bread = size;

        if (ctx->dataIdx + bread >= (int)sizeof(ctx->data)) {
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_read", -1);
            return -1;
        }

        XMEMCPY(data, &(ctx->data[ctx->dataIdx]), bread);

        ret = bread;
        data += bread;
        size -= bread;
        ctx->dataIdx += bread;

        if (ctx->dataLen == ctx->dataIdx) {
            ctx->dataLen = 0;
            ctx->dataIdx = 0;
        }
    }

    /*
     * At this point, we have room of size bytes and an empty buffer, so we
     * should read in some more.
     */

    ret_code = 0;
    idx = 0;

    while (size > 0) {
        if (ctx->cont <= 0)
            break;

        bread = WOLFCRYPT_BIO_read(bio->next_bio, &ctx->work[ctx->workLen],
                               sizeof(ctx->work) - ctx->workLen);

        if (bread <= 0) {
            ret_code = bread;

            /* Should we continue next time we are called? */
            if (!WOLFCRYPT_BIO_should_retry(bio->next_bio)) {
                ctx->cont = bread;
                /* If buffer empty break */
                if (!ctx->workLen)
                    break;
                else
                    bread = 0;
            }
            /* else we retry and add more data to buffer */
            else
                break;
        }

        bread += ctx->workLen;
        ctx->workLen = bread;

        /*
         * We need to scan, a line at a time until we have a valid line if we
         * are starting.
         */
        if (ctx->start && (WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL))
            ctx->workLen = 0;
        else if (ctx->start) {
            /* search \n */
            ctx->workNl = -1;

            /* parse working buffer to find line endings */
            for (j = 0; j < bread; j++) {

                /* no end of line, continue */
                if (ctx->work[j] != '\n')
                    continue;

                /* we found an end of line, keep the position to
                 * decode the line */
                ctx->workNl = j;

                /* decode the line found */
                num = sizeof(ctx->data) - ctx->dataIdx;

                k = Base64_Decode((const byte*)ctx->work+idx,ctx->workNl-idx,
                                  (byte *)ctx->data+ctx->dataIdx, (word32 *)&num);
                if (k < 0 && !num && ctx->start) {
                    WOLFSSL_ERROR(BIO_B64_DECODE_E);
                    return -1;
                }
                else
                    ctx->start = 0;

                /* +1 => skeep \n */
                idx = (ctx->workNl + 1);

                ctx->dataLen += num;
                ctx->dataIdx += num;
            }
        } else if ((bread < WOLFCRYPT_B64_BLOCK_SIZE) && (ctx->cont > 0)) {
            /*
             * If buffer isn't full and we can retry then restart to read in
             * more data.
             */
            continue;
        }

        if (WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL) {
            int z, jj;

            jj = bread & ~3;

            z = sizeof(ctx->data);
            k = Base64_Decode((const byte*)ctx->work, jj,
                              (byte *)ctx->data, (word32 *)&z);
            if (k < 0 || !z) {
                WOLFSSL_ERROR(BIO_B64_DECODE_E);
                return -1;
            }

            /* z is now number of output bytes and jj is the number consumed
             */
            if (jj != bread) {
                ctx->workLen = bread - jj;
                XMEMMOVE(ctx->work, &ctx->work[jj], ctx->workLen);
            }

            if (z > 0)
                ctx->dataLen = z;
            else
                ctx->dataLen = 0;

            bread = z;
        }

        ctx->dataIdx = 0;
        if (bread < 0) {
            ret_code = 0;
            ctx->dataLen = 0;
            break;
        }

        if (!(WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL)) {
            /* keep no parsed data in working buffer */
            XMEMMOVE(ctx->work, ctx->work+idx, ctx->workLen-idx);
            ctx->workLen -= idx;
            idx = 0;
            ctx->start = 1;
        }

        bread = (ctx->dataLen <= size ? ctx->dataLen : size);

        XMEMCPY(data, ctx->data, bread);
        ret += bread;

        if (bread == ctx->dataLen) {
            ctx->dataLen = 0;
            ctx->dataIdx = 0;
        }
        else
            ctx->dataIdx = bread;

        size -= bread;
        data += bread;
    }

    WOLFCRYPT_BIO_copy_next_retry(bio);

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_read", (!ret ? ret_code : ret));

    return (!ret ? ret_code : ret);
}

static int WOLFCRYPT_BIO_b64_write(WOLFCRYPT_BIO *bio,
                                   const char *data, int size)
{
    int ret = 0;
    int n;
    int i;
    WOLFCRYPT_BIO_F_B64_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_write");

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    /* encode when writing */
    if (ctx->encode != WOLFCRYPT_B64_ENCODE) {
        ctx->encode = WOLFCRYPT_B64_ENCODE;
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
        ctx->workLen = 0;
    }

    if (ctx->dataIdx >= (int)sizeof(ctx->data) ||
        ctx->dataLen > (int)sizeof(ctx->data) ||
        ctx->dataLen < ctx->dataIdx) {
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
        return -1;
    }

    n = ctx->dataLen - ctx->dataIdx;
    while (n > 0) {
        i = WOLFCRYPT_BIO_write(bio->next_bio, &ctx->data[ctx->dataIdx], n);
        if (i <= 0) {
            WOLFCRYPT_BIO_copy_next_retry(bio);
            return i;
        }

        /* mustn't appen, just to be sure */
        if (i > n) {
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
            return -1;
        }

        ctx->dataIdx += i;
        n -= i;
        
        if (ctx->dataIdx > (int)sizeof(ctx->data) ||
            ctx->dataLen < ctx->dataIdx) {
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
            return -1;
        }
    }

    /* at this point all pending data has been written */
    ctx->dataIdx = 0;
    ctx->dataLen = 0;

    if (data == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    while (size > 0) {
        n = (size > WOLFCRYPT_B64_BLOCK_SIZE) ? WOLFCRYPT_B64_BLOCK_SIZE : size;

        if (ctx->workLen > 0) {
            if (ctx->workLen > WOLFCRYPT_B64_BLOCK_SIZE) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            n = WOLFCRYPT_B64_BLOCK_SIZE - ctx->workLen;

            if (n > size)
                n = size;

            XMEMCPY(&ctx->work[ctx->workLen], data, n);
            ctx->workLen += n;
            ret += n;
            if (ctx->workLen < WOLFCRYPT_B64_BLOCK_SIZE)
                break;

            ctx->dataLen = sizeof(ctx->data);

            if (WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL)
                Base64_Encode_NoNl((const byte *)ctx->work, ctx->workLen,
                                   (byte *)ctx->data,
                                   (word32 *)&ctx->dataLen);
            else
                Base64_Encode((const byte *)ctx->work, ctx->workLen,
                              (byte *)ctx->data, (word32 *)&ctx->dataLen);

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            ctx->workLen = 0;
        }
        else {
            /* keep data and wait for more before encoding */
            if (n < WOLFCRYPT_B64_BLOCK_SIZE) {
                XMEMCPY(ctx->work, data, n);
                ctx->workLen = n;
                ret += n;
                break;
            }
            n -= n % WOLFCRYPT_B64_BLOCK_SIZE;

            ctx->dataLen = sizeof(ctx->data);

            if (WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL)
                Base64_Encode_NoNl((const byte *)data, n,
                                   (byte *)ctx->data,
                                   (word32 *)&ctx->dataLen);
            else
                Base64_Encode((const byte *)data, n,
                              (byte *)ctx->data, (word32 *)&ctx->dataLen);

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            ret += n;
        }

        size -= n;
        data += n;

        ctx->dataIdx = 0;
        n = ctx->dataLen;
        while (n > 0) {
            i = WOLFCRYPT_BIO_write(bio->next_bio,
                                    &(ctx->data[ctx->dataIdx]), n);
            if (i <= 0) {
                WOLFCRYPT_BIO_copy_next_retry(bio);
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", !ret ? i : ret);
                return (!ret ? i : ret);
            }

            if (i > n) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            n -= i;
            ctx->dataIdx += i;

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }
        }

        ctx->dataLen = 0;
        ctx->dataIdx = 0;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", ret);

    return ret;
}

static long WOLFCRYPT_BIO_b64_ctrl(WOLFCRYPT_BIO *bio,
                                   int cmd, long num, void *ptr)
{
    WOLFCRYPT_BIO_F_B64_CTX *ctx;
    long ret = 1;
    int i;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_ctrl");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->cont = 1;
            ctx->start = 1;
            ctx->encode = WOLFCRYPT_B64_NONE;
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_EOF:
            ret = (ctx->cont <= 0 ? 1 :
                   WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr));
            break;

        case BIO_CTRL_WPENDING:
            if (ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            ret = ctx->dataLen - ctx->dataIdx;
            if (!ret && (ctx->encode != WOLFCRYPT_B64_NONE) &&
                (ctx->workLen != 0))
                ret = 1;
            else if (ret <= 0)
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_PENDING:
            if (ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                return -1;
            }

            ret = ctx->dataLen - ctx->dataIdx;
            if (ret <= 0)
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_FLUSH:
            /* do a final write */
 again:
            while (ctx->dataLen != ctx->dataIdx) {
                i = WOLFCRYPT_BIO_b64_write(bio, NULL, 0);
                if (i < 0)
                    return i;
            }

            if (ctx->workLen != 0) {
                ctx->dataLen = sizeof(ctx->data);

                if (WOLFCRYPT_BIO_get_flags(bio) & BIO_FLAGS_BASE64_NO_NL)
                    Base64_Encode_NoNl((const byte *)ctx->work, ctx->workLen,
                                       (byte *)ctx->data,
                                       (word32 *)&ctx->dataLen);
                else {
                    Base64_Encode((const byte *)ctx->work, ctx->workLen,
                                  (byte *)ctx->data, (word32 *)&ctx->dataLen);

                    if (ctx->dataLen > (int)sizeof(ctx->data)) {
                        WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_write", -1);
                        return -1;
                    }
                }

                ctx->dataIdx = 0;
                ctx->workLen = 0;

                goto again;
            }

            /* Finally flush the underlying BIO */
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_DO_STATE_MACHINE:
            WOLFCRYPT_BIO_clear_retry_flags(bio);
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            WOLFCRYPT_BIO_copy_next_retry(bio);
            break;

        case BIO_CTRL_DUP:
            break;

        case BIO_CTRL_INFO:
        case BIO_CTRL_GET:
        case BIO_CTRL_SET:
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        default:
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_b64_ctrl", (int)ret);
    return ret;
}

static long WOLFCRYPT_BIO_b64_callback_ctrl(WOLFCRYPT_BIO *bio,
                                            int cmd, WOLFCRYPT_BIO_info_cb *fp)
{
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_callback_ctrl");

    return WOLFCRYPT_BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

static int WOLFCRYPT_BIO_b64_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_b64_puts");

    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return WOLFCRYPT_BIO_b64_write(bio, str, (int)strlen(str));
}

#endif /* OPENSSL_EXTRA */
