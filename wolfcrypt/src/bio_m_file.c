/* bio_m_file.c
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

#include <stdio.h>

#include <wolfssl/wolfcrypt/settings.h>

#ifdef OPENSSL_EXTRA

#ifndef NO_FILESYSTEM

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/openssl/bio.h>


/* TO BE REMOVED */
#ifndef XFERROR
#define XFERROR ferror
#endif

#ifndef XFILENO
#define XFILENO fileno
#endif

#if defined(USE_WINDOWS_API)
#include <io.h>
    #ifndef XSETMODE
    #define XSETMODE _setmode
    #endif
#endif /* USE_WINDOWS_API */

#ifndef XFFLUSH
#define XFFLUSH fflush
#endif

#ifndef XFEOF
#define XFEOF feof
#endif

#ifndef XFGETS
#define XFGETS fgets
#endif

static int WOLFCRYPT_BIO_file_write(WOLFCRYPT_BIO *bio,
                                    const char *buf, int size);
static int WOLFCRYPT_BIO_file_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_file_puts(WOLFCRYPT_BIO *bio, const char *str);
static int WOLFCRYPT_BIO_file_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_file_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_file_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_file_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_file_method = {
    BIO_TYPE_FILE,
    "FILE pointer",
    WOLFCRYPT_BIO_file_write,
    WOLFCRYPT_BIO_file_read,
    WOLFCRYPT_BIO_file_puts,
    WOLFCRYPT_BIO_file_gets,
    WOLFCRYPT_BIO_file_ctrl,
    WOLFCRYPT_BIO_file_new,
    WOLFCRYPT_BIO_file_free,
    NULL,
};

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_file(const char *name, const char *mode)
{
    XFILE f;

    if (name == NULL || mode == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    f = XFOPEN(name, mode);
    if (f == NULL) {
        WOLFSSL_ERROR(BIO_FILE_OPEN_E);
        return NULL;
    }

    return WOLFCRYPT_BIO_new_fp(f, BIO_CLOSE);
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_fp(XFILE f, int close_flag)
{
    WOLFCRYPT_BIO *bio;

    if (f == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_file());
    if (bio == NULL)
        return NULL;

    WOLFCRYPT_BIO_set_fp(bio, f, close_flag);

    return bio;
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_file(void)
{
    return (&WOLFCRYPT_BIO_file_method);
}

static int WOLFCRYPT_BIO_file_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->init = 0;
    bio->num = 0;
    bio->ptr = NULL;

    return 1;
}

static int WOLFCRYPT_BIO_file_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return 0;

    if (!bio->shutdown || !bio->init)
        return 1;

    if (bio->ptr != NULL) {
        XFCLOSE(bio->ptr);
        bio->ptr = NULL;
    }
    bio->init = 0;

    return 1;
}

static int WOLFCRYPT_BIO_file_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    int ret = 0;

    if (bio == NULL || !bio->init || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ret = (int)XFREAD(buf, sizeof(char), size, (FILE *)bio->ptr);
    if (ret == 0 && XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_READ_E);
        ret = -1;
    }

    return ret;
}

static int WOLFCRYPT_BIO_file_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    int ret = 0;

    if (bio == NULL || !bio->init || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ret = (int)XFWRITE(buf, sizeof(char), size, (FILE *)bio->ptr);
    if (ret == 0 && XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_WRITE_E);
        ret = -1;
    }

    return ret;
}

static long WOLFCRYPT_BIO_file_ctrl(WOLFCRYPT_BIO *bio,
                                  int cmd, long num, void *ptr)
{
    long ret = 1;
    char buf[4];

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (cmd) {
        case BIO_C_FILE_SEEK:
        case BIO_CTRL_RESET:
            ret = (long)XFSEEK((FILE *)bio->ptr, num, 0);
            break;

        case BIO_CTRL_EOF:
            ret = (long)XFEOF((FILE *)bio->ptr);
            break;

        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
            ret = (long)XFTELL((FILE *)bio->ptr);
            break;

        case BIO_C_SET_FILE_PTR:
            WOLFCRYPT_BIO_file_free(bio);
            bio->shutdown = (int)num & BIO_CLOSE;
            bio->ptr = ptr;
            bio->init = 1;

#ifdef USE_WINDOWS_API
            {
                int fd;

                fd = XFILENO((FILE *)bio->ptr);
                if (num & BIO_FP_TEXT)
                    XSETMODE(fd, O_TEXT);
                else
                    XSETMODE(fd, O_BINARY);
            }
#endif /* USE_WINDOWS_API */
            break;

        case BIO_C_SET_FILENAME:
            WOLFCRYPT_BIO_file_free(bio);
            bio->shutdown = (int)num & BIO_CLOSE;
            if (num & BIO_FP_APPEND) {
                if (num & BIO_FP_READ)
                    XSTRNCPY(buf, "a+", sizeof(buf) - 1);
                else
                    XSTRNCPY(buf, "a", sizeof(buf) - 1);
            }
            else if (num & BIO_FP_READ) {
                if (num & BIO_FP_WRITE)
                    XSTRNCPY(buf, "r+", sizeof(buf) - 1);
                else
                    XSTRNCPY(buf, "r", sizeof(buf));
            }
            else if (num & BIO_FP_WRITE)
                XSTRNCPY(buf, "w", sizeof(buf) - 1);
            else {
                WOLFSSL_ERROR(BIO_FILE_MODE_E);
                ret = 0;
                break;
            }

            if (num & BIO_FP_TEXT)
                XSTRNCAT(buf, "t", sizeof(buf) - 1);
            else
                XSTRNCAT(buf, "b", sizeof(buf) - 1);

            bio->ptr = XFOPEN(ptr, buf);
            if (bio->ptr == NULL) {
                WOLFSSL_ERROR(BIO_FILE_OPEN_E);
                ret = 0;
                break;
            }
            bio->init = 1;

            break;

        case BIO_C_GET_FILE_PTR:
            /* the ptr parameter is a FILE ** in this case. */
            if (ptr != NULL)
                *((FILE **)ptr) = (FILE *)bio->ptr;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = (long)bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_FLUSH:
            XFFLUSH((FILE *)bio->ptr);
            break;

        case BIO_CTRL_DUP:
            ret = 1;
            break;

        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_file_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    /* init buffer */
    XMEMSET(buf, 0, size);

    if ((XFGETS(buf, size, (FILE *)bio->ptr) == NULL) &&
        XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_GETS_E);
        return -1;
    }

    return (int)strlen(buf);
}

static int WOLFCRYPT_BIO_file_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || bio->ptr == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }
    
    return WOLFCRYPT_BIO_file_write(bio, str, (int)strlen(str));
}

#endif /* NO_FILESYSTEM */

#endif /* OPENSSL_EXTRA */
