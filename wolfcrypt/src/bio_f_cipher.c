/* bio_f_cipher.c
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
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/bio.h>

typedef struct {
    int dataLen;
    int dataIdx;
    int cont;
    int finished;
    int ok; /* bad decrypt */

    WOLFSSL_EVP_CIPHER_CTX cipher;
    /*
     * buf is larger than ENC_BLOCK_SIZE because EVP_DecryptUpdate can return
     * up to a block more data than is presented to it
     */

#define WOLFCRYPT_ENC_BLOCK_SIZE  128
#define WOLFCRYPT_BUF_OFFSET      64

    byte data[WOLFCRYPT_ENC_BLOCK_SIZE + WOLFCRYPT_BUF_OFFSET + 2];
} WOLFCRYPT_BIO_ENC_CTX;


static int WOLFCRYPT_BIO_cipher_write(WOLFCRYPT_BIO *bio,
                                   const char *buf, int size);
static int WOLFCRYPT_BIO_cipher_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_cipher_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                   long num, void *ptr);
static int WOLFCRYPT_BIO_cipher_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_cipher_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_cipher_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_cipher_method = {
    BIO_TYPE_CIPHER,
    "Cipher",
    WOLFCRYPT_BIO_cipher_write,
    WOLFCRYPT_BIO_cipher_read,
    NULL, /* puts */
    NULL, /* gets */
    WOLFCRYPT_BIO_cipher_ctrl,
    WOLFCRYPT_BIO_cipher_new,
    WOLFCRYPT_BIO_cipher_free,
    WOLFCRYPT_BIO_cipher_callback_ctrl,
};

static long WOLFCRYPT_BIO_cipher_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_callback_ctrl");
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return  WOLFCRYPT_BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_cipher(void)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_f_cipher");
    return (&WOLFCRYPT_BIO_cipher_method);
}

void WOLFCRYPT_BIO_set_cipher(WOLFCRYPT_BIO *bio,
                              const WOLFSSL_EVP_CIPHER *cipher,
                              const unsigned char *key,
                              const unsigned char *iv, int enc)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_set_cipher");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }


    if ((bio->callback != NULL) &&
        bio->callback(bio, BIO_CB_CTRL, (const char *)cipher,
                      BIO_CTRL_SET, enc, 0) <= 0) {
        WOLFSSL_ERROR(BIO_CALLBACK_E);
        return;
    }

    bio->init = 1;

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wolfSSL_EVP_CipherInit(&(ctx->cipher), cipher, (unsigned char *)key,
                           (unsigned char *)iv, enc);

    if ((bio->callback != NULL) &&
        bio->callback(bio, BIO_CB_CTRL, (const char *)cipher,
                      BIO_CTRL_SET, enc, 1) <= 0)
        WOLFSSL_ERROR(BIO_CALLBACK_E);
}

static int WOLFCRYPT_BIO_cipher_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = (WOLFCRYPT_BIO_ENC_CTX *)XMALLOC(sizeof(WOLFCRYPT_BIO_ENC_CTX),
                                                0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wolfSSL_EVP_CIPHER_CTX_init(&ctx->cipher);

    ctx->dataLen = 0;
    ctx->dataIdx = 0;
    ctx->cont = 1;
    ctx->finished = 0;
    ctx->ok = 1;

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_cipher_new", 1);
    return 1;
}

static int WOLFCRYPT_BIO_cipher_free(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wolfSSL_EVP_CIPHER_CTX_cleanup(&(ctx->cipher));

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_ENC_CTX));
    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;
    
    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_cipher_free", 1);
    return 1;
}

static int WOLFCRYPT_BIO_cipher_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0, i;
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_read");
    
    if (bio == NULL || data == NULL ||
        bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    /* First check if there are bytes decoded/encoded */
    if (ctx->dataLen > 0) {
        i = ctx->dataLen - ctx->dataIdx;
        if (i > size)
            i = size;

        XMEMCPY(data, &ctx->data[ctx->dataIdx], i);
        ret = i;
        data += i;
        size -= i;
        ctx->dataIdx += i;

        /* all read */
        if (ctx->dataLen == ctx->dataIdx)
            ctx->dataLen = ctx->dataIdx = 0;
    }

    /*
     * At this point, we have room of size bytes and an empty buffer, so we
     * should read in some more.
     */
    while (size > 0) {
        if (ctx->cont <= 0)
            break;

        /* read in at IV offset, read the EVP_Cipher documentation about why
         */
        i = WOLFCRYPT_BIO_read(bio->next_bio, &ctx->data[WOLFCRYPT_BUF_OFFSET],
                               WOLFCRYPT_ENC_BLOCK_SIZE);
        if (i <= 0) {
            /* Should be continue next time we are called ? */
            if (!WOLFCRYPT_BIO_should_retry(bio->next_bio)) {
                ctx->cont = i;

                i = wolfSSL_EVP_CipherFinal(&ctx->cipher, ctx->data,
                                            &ctx->dataLen);

                ctx->ok = i;
                ctx->dataIdx = 0;
            } else {
                if (!ret)
                    ret = i;
                break;
            }
        } else {
            wolfSSL_EVP_CipherUpdate(&ctx->cipher,
                                     ctx->data, &ctx->dataLen,
                                     &ctx->data[WOLFCRYPT_BUF_OFFSET], i);
            ctx->cont = 1;

            if (!ctx->dataLen)
                continue;
        }

        i = (ctx->dataLen <= size ? ctx->dataLen : size);
        if (i <= 0)
            break;

        XMEMCPY(data, ctx->data, i);

        ret += i;
        ctx->dataIdx = i;
        size -= i;
        data += i;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    WOLFCRYPT_BIO_copy_next_retry(bio);

    return (!ret ? ctx->cont : ret);
}

static int WOLFCRYPT_BIO_cipher_write(WOLFCRYPT_BIO *bio,
                                      const char *data, int size)
{
    int ret, n, i;
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_write");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    ret = size;

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    n = ctx->dataLen - ctx->dataIdx;
    while (n > 0) {
        i = WOLFCRYPT_BIO_write(bio->next_bio, &ctx->data[ctx->dataIdx], n);
        if (i <= 0) {
            WOLFCRYPT_BIO_copy_next_retry(bio);
            return i;
        }
        ctx->dataIdx += i;
        n -= i;
    }

    /* at this point all pending data has been written
     * return if we haven't new data to write */
    if (data == NULL || size <= 0)
        return 0;

    while (size > 0) {
        n = (size > WOLFCRYPT_ENC_BLOCK_SIZE ? WOLFCRYPT_ENC_BLOCK_SIZE : size);
        wolfSSL_EVP_CipherUpdate(&ctx->cipher, ctx->data, &ctx->dataLen,
                                 (byte *)data, n);

        size -= n;
        data += n;

        ctx->dataIdx = 0;
        n = ctx->dataLen;
        while (n > 0) {
            i = WOLFCRYPT_BIO_write(bio->next_bio,
                                    &ctx->data[ctx->dataIdx], n);
            if (i <= 0) {
                WOLFCRYPT_BIO_copy_next_retry(bio);
                return (ret == size ? i : ret - size);
            }
            n -= i;
            ctx->dataIdx += i;
        }
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
    }

    WOLFCRYPT_BIO_copy_next_retry(bio);
    return ret;
}

static long WOLFCRYPT_BIO_cipher_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                      long num, void *ptr)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;
    long ret = 1;
    int i;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_cipher_ctrl");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->ok = 1;
            ctx->finished = 0;
            wolfSSL_EVP_CipherInit(&ctx->cipher, NULL, NULL, NULL,
                                   ctx->cipher.enc);
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_EOF:         /* More to read */
            if (ctx->cont <= 0)
                ret = 1;
            else
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
            ret = ctx->dataLen - ctx->dataIdx;
            if (ret <= 0)
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_FLUSH:
loop:
            while (ctx->dataLen != ctx->dataIdx) {
                    i = WOLFCRYPT_BIO_cipher_write(bio, NULL, 0);
                    if (i < 0)
                        return i;
                }

                if (!ctx->finished) {
                    ctx->finished = 1;
                    ctx->dataIdx = 0;

                    ret = wolfSSL_EVP_CipherFinal(&ctx->cipher, ctx->data,
                                                  &ctx->dataLen);
                    ctx->ok = (int)ret;
                    if (ret <= 0)
                        break;

                    goto loop;
                }

            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_GET_CIPHER_STATUS:
            ret = (long)ctx->ok;
            break;

        case BIO_C_DO_STATE_MACHINE:
            WOLFCRYPT_BIO_clear_retry_flags(bio);
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            WOLFCRYPT_BIO_copy_next_retry(bio);
            break;

        case BIO_C_GET_CIPHER_CTX:
            {
                WOLFSSL_EVP_CIPHER_CTX **c_ctx;
                c_ctx = (WOLFSSL_EVP_CIPHER_CTX **)ptr;
                *c_ctx = &ctx->cipher;
                bio->init = 1;
            }
            break;

        case BIO_CTRL_DUP:
            {
                WOLFCRYPT_BIO *dbio;
                WOLFCRYPT_BIO_ENC_CTX *dctx;

                dbio = (WOLFCRYPT_BIO *)ptr;
                dctx = (WOLFCRYPT_BIO_ENC_CTX *)dbio->ptr;

                wolfSSL_EVP_CIPHER_CTX_init(&dctx->cipher);
                ret = wolfSSL_EVP_CIPHER_CTX_copy(&dctx->cipher, &ctx->cipher);
                if (ret)
                    dbio->init = 1;
            }
            break;

        default:
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_cipher_ctrl", (int)ret);
    return ret;
}

#endif /* OPENSSL_EXTRA */
