/* bio_m_fd.c
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

static int WOLFCRYPT_BIO_fd_write(WOLFCRYPT_BIO *bio,
                                    const char *buf, int size);
static int WOLFCRYPT_BIO_fd_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_fd_puts(WOLFCRYPT_BIO *bio, const char *str);
static int WOLFCRYPT_BIO_fd_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_fd_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_fd_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_fd_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_fd_method = {
    BIO_TYPE_FD,
    "File descriptor",
    WOLFCRYPT_BIO_fd_write,
    WOLFCRYPT_BIO_fd_read,
    WOLFCRYPT_BIO_fd_puts,
    WOLFCRYPT_BIO_fd_gets,
    WOLFCRYPT_BIO_fd_ctrl,
    WOLFCRYPT_BIO_fd_new,
    WOLFCRYPT_BIO_fd_free,
    NULL,
};

/* functions are not implemented as not really used in OpenSSL except for two
 * cases :
 *   * get password giving 'fd file' instead of 'file name'
 *       (see app_get_pass(), apps/apps.c)
 *   * open STDOUT and STDERR by giving fd instead of name
 *       (see main(), crypto/threads/mttest.c)
 */
WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_fd(void)
{
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return (&WOLFCRYPT_BIO_fd_method);
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_fd(int fd, int close_flag)
{
    (void)fd;
    (void)close_flag;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return NULL;
}

static int WOLFCRYPT_BIO_fd_new(WOLFCRYPT_BIO *bio)
{
    (void)bio;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int WOLFCRYPT_BIO_fd_free(WOLFCRYPT_BIO *bio)
{
    (void)bio;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int WOLFCRYPT_BIO_fd_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int WOLFCRYPT_BIO_fd_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static long WOLFCRYPT_BIO_fd_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr)
{
    (void)bio;
    (void)ptr;
    (void)cmd;
    (void)num;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int WOLFCRYPT_BIO_fd_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int WOLFCRYPT_BIO_fd_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    (void)bio;
    (void)str;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

#endif /* OPENSSL_EXTRA */
