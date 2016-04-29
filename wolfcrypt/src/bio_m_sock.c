/* bio_m_sock.c
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

#include <wolfssl/openssl/bio.h>

static int WOLFCRYPT_BIO_sock_write(WOLFCRYPT_BIO *bio,
                                  const char *data, int size);
static int WOLFCRYPT_BIO_sock_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int WOLFCRYPT_BIO_sock_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_sock_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_sock_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_sock_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_sock_method = {
    BIO_TYPE_SOCKET,
    "Socket",
    WOLFCRYPT_BIO_sock_write,
    WOLFCRYPT_BIO_sock_read,
    WOLFCRYPT_BIO_sock_puts,
    NULL, /* gets */
    WOLFCRYPT_BIO_sock_ctrl,
    WOLFCRYPT_BIO_sock_new,
    WOLFCRYPT_BIO_sock_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_socket(void)
{
    return (&WOLFCRYPT_BIO_sock_method);
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_socket(int fd, int close_flag)
{
    WOLFCRYPT_BIO *ret;

    ret = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_socket());
    if (ret == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    WOLFCRYPT_BIO_set_fd(ret, fd, close_flag);
    return ret;
}

static int WOLFCRYPT_BIO_sock_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->init = 0;
    bio->num = 0; /* used for fd */
    bio->ptr = NULL;
    bio->flags = 0;

    return 1;
}

static int WOLFCRYPT_BIO_sock_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!bio->shutdown)
        return 1;

    if (bio->init) {
        shutdown(bio->num, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(bio->num);
#else
        close(bio->num);
#endif
    }

    bio->init = 0;
    bio->flags = 0;

    return 1;
}

static int WOLFCRYPT_BIO_sock_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret;

    if (bio == NULL || !bio->init || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)recv(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)read(bio->num, data, size);
#endif

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    if (ret <= 0) {
        if (WOLFCRYPT_BIO_sock_should_retry(ret))
            WOLFCRYPT_BIO_set_retry_read(bio);
    }

    return ret;
}

static int WOLFCRYPT_BIO_sock_write(WOLFCRYPT_BIO *bio,
                                    const char *data, int size)
{
    int ret;

    if (bio == NULL || !bio->init || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)send(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)write(bio->num, data, size);
#endif

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    if (ret <= 0) {
        if (WOLFCRYPT_BIO_sock_should_retry(ret))
            WOLFCRYPT_BIO_set_retry_write(bio);
    }

    return ret;
}

static long WOLFCRYPT_BIO_sock_ctrl(WOLFCRYPT_BIO *bio,
                                    int cmd, long num, void *ptr)
{
    long ret = 1;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (cmd) {
        case BIO_C_SET_FD:
            WOLFCRYPT_BIO_sock_free(bio);
            bio->num = *((int *)ptr);
            bio->shutdown = (int)num;
            bio->init = 1;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                if (ptr != NULL)
                    *((int *)ptr) = bio->num;
                ret = bio->num;
            }
            else
                ret = -1;
        break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_sock_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return WOLFCRYPT_BIO_sock_write(bio, str, (int)strlen(str));
}

int WOLCRYPT_BIO_sock_non_fatal_error(int err)
{
    switch (err) {
#if defined(WSAEWOULDBLOCK)
        case WSAEWOULDBLOCK:
#endif

#ifdef EWOULDBLOCK
    #ifdef WSAEWOULDBLOCK
        #if WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
        #endif
    #else
        case EWOULDBLOCK:
    #endif
#endif

#if defined(ENOTCONN)
        case ENOTCONN:
#endif

#ifdef EINTR
        case EINTR:
#endif

#ifdef EAGAIN
    #if EWOULDBLOCK != EAGAIN
        case EAGAIN:
    #endif
#endif

#ifdef EPROTO
        case EPROTO:
#endif

#ifdef EINPROGRESS
        case EINPROGRESS:
#endif

#ifdef EALREADY
        case EALREADY:
#endif
            return 1;
            break;

        default:
            break;
    }

    return 0;
}

int WOLFCRYPT_BIO_sock_should_retry(int i)
{
    if (!i || i == -1) {
        int ret;
#ifdef USE_WINDOWS_API
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        return WOLCRYPT_BIO_sock_non_fatal_error(ret);
    }

    return 0;
}


#endif /* OPENSSL_EXTRA */
