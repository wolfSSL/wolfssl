/* bio_m_null.c
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

#include <wolfssl/openssl/bio.h>

static int WOLFCRYPT_BIO_null_write(WOLFCRYPT_BIO *bio,
                                    const char *buf, int size);
static int WOLFCRYPT_BIO_null_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_null_puts(WOLFCRYPT_BIO *bio, const char *str);
static int WOLFCRYPT_BIO_null_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_null_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_null_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_null_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_null_method = {
    BIO_TYPE_NULL,
    "NULL",
    WOLFCRYPT_BIO_null_write,
    WOLFCRYPT_BIO_null_read,
    WOLFCRYPT_BIO_null_puts,
    WOLFCRYPT_BIO_null_gets,
    WOLFCRYPT_BIO_null_ctrl,
    WOLFCRYPT_BIO_null_new,
    WOLFCRYPT_BIO_null_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_null(void)
{
    return (&WOLFCRYPT_BIO_null_method);
}

static int WOLFCRYPT_BIO_null_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return 0;

    bio->init = 1;
    bio->num = 0;
    bio->ptr = NULL;

    return 1;
}

static int WOLFCRYPT_BIO_null_free(WOLFCRYPT_BIO *bio)
{
    return bio == NULL ? 0 : 1;
}

static int WOLFCRYPT_BIO_null_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;

    return 0;
}

static int WOLFCRYPT_BIO_null_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    (void)bio;
    (void)buf;

    return size;
}

static long WOLFCRYPT_BIO_null_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)ptr;
    (void)num;

    long ret = 1;

    switch (cmd) {
        case BIO_CTRL_RESET:
        case BIO_CTRL_EOF:
        case BIO_CTRL_SET:
        case BIO_CTRL_SET_CLOSE:
        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            ret = 1;
            break;
        case BIO_CTRL_GET_CLOSE:
        case BIO_CTRL_INFO:
        case BIO_CTRL_GET:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_null_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;

    return 0;
}

static int WOLFCRYPT_BIO_null_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    (void)bio;

    if (str == NULL)
        return 0;

    return (int)strlen(str);
}

#endif /* OPENSSL_EXTRA */
