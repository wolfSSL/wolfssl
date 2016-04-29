/* bio_f_dgst.c
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

static int WOLFCRYPT_BIO_digest_write(WOLFCRYPT_BIO *bio,
                                      const char *buf, int size);
static int WOLFCRYPT_BIO_digest_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_digest_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_digest_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                      long num, void *ptr);
static int WOLFCRYPT_BIO_digest_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_digest_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_digest_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_digest_method = {
    BIO_TYPE_MD,
    "Message digest",
    WOLFCRYPT_BIO_digest_write,
    WOLFCRYPT_BIO_digest_read,
    NULL, /* puts */
    WOLFCRYPT_BIO_digest_gets,
    WOLFCRYPT_BIO_digest_ctrl,
    WOLFCRYPT_BIO_digest_new,
    WOLFCRYPT_BIO_digest_free,
    WOLFCRYPT_BIO_digest_callback_ctrl,
};

static long WOLFCRYPT_BIO_digest_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_callback_ctrl");
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return  WOLFCRYPT_BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_md(void)
{
    return (&WOLFCRYPT_BIO_digest_method);
}

static int WOLFCRYPT_BIO_digest_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = (WOLFSSL_EVP_MD_CTX *)XMALLOC(sizeof(WOLFSSL_EVP_MD_CTX),
                                                0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return -1;
    }

    wolfSSL_EVP_MD_CTX_init((WOLFSSL_EVP_MD_CTX *)bio->ptr);

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_digest_new", 1);
    return 1;
}

static int WOLFCRYPT_BIO_digest_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wolfSSL_EVP_MD_CTX_cleanup((WOLFSSL_EVP_MD_CTX *)bio->ptr);

    XMEMSET(bio->ptr, 0, sizeof(WOLFSSL_EVP_MD_CTX));
    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_digest_free", 1);
    return 1;
}

static int WOLFCRYPT_BIO_digest_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    WOLFSSL_EVP_MD_CTX *ctx;
    int ret = 0;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_read");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL ||
        data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFSSL_EVP_MD_CTX *)bio->ptr;

    ret = WOLFCRYPT_BIO_read(bio->next_bio, data, size);
    if (bio->init && ret > 0) {
        if (wolfSSL_EVP_DigestUpdate(ctx, data, (word32)ret) != SSL_SUCCESS) {
            WOLFSSL_ERROR(BIO_DGST_UPDATE_E);
            return -1;
        }
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    WOLFCRYPT_BIO_copy_next_retry(bio);

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_digest_read", ret);
    return ret;
}

static int WOLFCRYPT_BIO_digest_write(WOLFCRYPT_BIO *bio,
                                      const char *data, int size)
{
    WOLFSSL_EVP_MD_CTX *ctx;
    int ret = 0;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_write");

    if (bio == NULL || bio->ptr == NULL || data == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFSSL_EVP_MD_CTX *)bio->ptr;

    ret = WOLFCRYPT_BIO_write(bio->next_bio, data, size);

    if (bio->init && ret > 0) {
        if (wolfSSL_EVP_DigestUpdate(ctx, data, (word32)ret) != SSL_SUCCESS) {
            WOLFSSL_ERROR(BIO_DGST_UPDATE_E);
            WOLFCRYPT_BIO_clear_retry_flags(bio);
            return -1;
        }
    }

    if (bio->next_bio != NULL) {
         WOLFCRYPT_BIO_clear_retry_flags(bio);
         WOLFCRYPT_BIO_copy_next_retry(bio);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_digest_write", ret);

    return ret;
}

static long WOLFCRYPT_BIO_digest_ctrl(WOLFCRYPT_BIO *bio,
                                      int cmd, long num, void *ptr)
{
    WOLFSSL_EVP_MD_CTX *ctx;
    long ret = 1;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_ctrl");

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFSSL_EVP_MD_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            if (bio->init)
                ret = wolfSSL_EVP_DigestInit(ctx, ctx->digest);
            else
                ret = 0;

            if (ret > 0)
                ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_GET_MD:
            if (bio->init) {
                const WOLFSSL_EVP_MD **pmd;
                pmd = (const WOLFSSL_EVP_MD **)ptr;
                *pmd = ctx->digest;
            } else
                ret = 0;
            break;

        case BIO_C_GET_MD_CTX:
            {
                WOLFSSL_EVP_MD_CTX **pctx;
                pctx = (WOLFSSL_EVP_MD_CTX **)ptr;
                *pctx = ctx;
            }
            bio->init = 1;
            break;

        case BIO_C_SET_MD_CTX:
            if (bio->init)
                bio->ptr = ptr;
            else
                ret = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            WOLFCRYPT_BIO_clear_retry_flags(bio);
            ret =  WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            WOLFCRYPT_BIO_copy_next_retry(bio);
            break;

        case BIO_C_SET_MD:
            ret = wolfSSL_EVP_DigestInit(ctx, (WOLFSSL_EVP_MD *)ptr);
            if (ret > 0)
                bio->init = 1;
            else
                WOLFSSL_ERROR(BIO_DGST_INIT_E);
            break;

        case BIO_CTRL_DUP:
            {
                WOLFCRYPT_BIO   *dbio;
                WOLFSSL_EVP_MD_CTX  *dctx;

                dbio = (WOLFCRYPT_BIO *)ptr;
                dctx = (WOLFSSL_EVP_MD_CTX *)dbio->ptr;

                ret = wolfSSL_EVP_MD_CTX_copy(dctx, ctx);
                if (ret)
                    bio->init = 1;
            }
            break;

        default:
            ret = WOLFCRYPT_BIO_ctrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_digest_ctrl", (int)ret);
    return ret;
}

static int WOLFCRYPT_BIO_digest_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFSSL_EVP_MD_CTX *ctx;
    unsigned int dgstLen = 0;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_digest_gets");

    if (bio == NULL || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFSSL_EVP_MD_CTX *)bio->ptr;

    if (size < ctx->macSize) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (wolfSSL_EVP_DigestFinal(ctx, (byte *)buf, &dgstLen) != SSL_SUCCESS) {
        WOLFSSL_ERROR(BIO_DGST_FINAL_E);
        return -1;
    }

    return dgstLen;
}

#endif /* OPENSSL_EXTRA */