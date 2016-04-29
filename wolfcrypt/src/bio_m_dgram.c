/* bio_m_dgram.c
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

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#ifdef USE_WINDOWS_API
#include <winsock2.h>
#include <process.h>
#else
#include <sys/time.h>
#endif /* USE_WINDOWS_API */

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

/* Socket Handling */
#ifndef WOLFSSL_SOCKET_INVALID
#ifdef USE_WINDOWS_API
#define WOLFSSL_SOCKET_INVALID  ((SOCKET)WOLFSSL_SOCKET_INVALID)
#else
#define WOLFSSL_SOCKET_INVALID  (0)
#endif
#endif /* WOLFSSL_SOCKET_INVALID */

#if !defined(IP_MTU)
#define IP_MTU 14
#endif

#if defined(TEST_IPV6) && !defined(IPPROTO_IPV6)
#define IPPROTO_IPV6 41
#endif

static int WOLFCRYPT_BIO_DATAGRAM_write(WOLFCRYPT_BIO *bio,
                                        const char *data, int size);
static int WOLFCRYPT_BIO_DATAGRAM_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int WOLFCRYPT_BIO_DATAGRAM_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_DATAGRAM_ctrl(WOLFCRYPT_BIO *bio,
                                        int cmd, long num, void *ptr);
static int WOLFCRYPT_BIO_DATAGRAM_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_DATAGRAM_free(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_DATAGRAM_clear(WOLFCRYPT_BIO *bio);

static int WOLFCRYPT_BIO_DATAGRAM_should_retry(int s);

static void get_current_time(struct timeval *t);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_dgram_method = {
    BIO_TYPE_DGRAM,
    "Datagram socket",
    WOLFCRYPT_BIO_DATAGRAM_write,
    WOLFCRYPT_BIO_DATAGRAM_read,
    WOLFCRYPT_BIO_DATAGRAM_puts,
    NULL,  /* gets */
    WOLFCRYPT_BIO_DATAGRAM_ctrl,
    WOLFCRYPT_BIO_DATAGRAM_new,
    WOLFCRYPT_BIO_DATAGRAM_free,
    NULL,
};

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
#ifdef TEST_IPV6
        struct sockaddr_in6 sa_in6;
# endif
    } peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct timeval next_timeout;
    struct timeval socket_timeout;
} WOLFCRYPT_BIO_DATAGRAM;

static int WOLFCRYPT_BIO_DATAGRAM_should_retry(int i)
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

static void get_current_time(struct timeval *t)
{
#ifdef USE_WINDOWS_API
    SYSTEMTIME st;
    union {
        unsigned __int64 ul;
        FILETIME ft;
    } now;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &now.ft);
    now.ul -= 116444736000000000UI64; /* re-bias to 1/1/1970 */
    t->tv_sec = (long)(now.ul / 10000000);
    t->tv_usec = ((int)(now.ul % 10000000)) / 10;
# else
    gettimeofday(t, NULL);
# endif
}


WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_datagram(void)
{
    return (&WOLFCRYPT_BIO_dgram_method);
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_dgram(int fd, int close_flag)
{
    WOLFCRYPT_BIO *bio;

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_datagram());
    if (bio == NULL)
        return NULL;

    WOLFCRYPT_BIO_set_fd(bio, fd, close_flag);
    return bio;
}

static int WOLFCRYPT_BIO_DATAGRAM_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->num = 0;
    bio->flags = 0;

    bio->ptr = XMALLOC(sizeof(WOLFCRYPT_BIO_DATAGRAM), 0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL)
        return 0;

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_DATAGRAM));
    return 1;
}

static int WOLFCRYPT_BIO_DATAGRAM_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!WOLFCRYPT_BIO_DATAGRAM_clear(bio))
        return 0;

    if (bio->ptr != NULL)
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);

    return 1;
}

static int WOLFCRYPT_BIO_DATAGRAM_clear(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->shutdown) {
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
    }

    return 1;
}

static void WOLFCRYPT_BIO_DATAGRAM_adjust_rcv_timeout(WOLFCRYPT_BIO *bio)
{
#ifdef SO_RCVTIMEO
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    union {
        size_t s;
        int i;
    } sz = { 0 };

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    /* Is a timer active? */
    if (dgram->next_timeout.tv_sec > 0 || dgram->next_timeout.tv_usec > 0) {
        struct timeval timenow, timeleft;

        /* Read current socket timeout */
#ifdef USE_WINDOWS_API
        int timeout;

        sz.i = sizeof(timeout);
        if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, &sz.i) >= 0) {
            dgram->socket_timeout.tv_sec = timeout / 1000;
            dgram->socket_timeout.tv_usec = (timeout % 1000) * 1000;
        }
#else
        sz.i = sizeof(dgram->socket_timeout);
        if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                       &(dgram->socket_timeout), (void *)&sz) >= 0) {
            if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0)
                if (sz.s > sizeof(dgram->socket_timeout))
                    return ;
        }
#endif /* USE_WINDOWS_API */

        /* Get current time */
        get_current_time(&timenow);

        /* Calculate time left until timer expires */
        XMEMCPY(&timeleft, &dgram->next_timeout, sizeof(struct timeval));
        if (timeleft.tv_usec < timenow.tv_usec) {
            timeleft.tv_usec = 1000000 - timenow.tv_usec + timeleft.tv_usec;
            timeleft.tv_sec--;
        }
        else
            timeleft.tv_usec -= timenow.tv_usec;

        if (timeleft.tv_sec < timenow.tv_sec) {
            timeleft.tv_sec = 0;
            timeleft.tv_usec = 1;
        }
        else
            timeleft.tv_sec -= timenow.tv_sec;

        /*
         * Adjust socket timeout if next handhake message timer will expire
         * earlier.
         */
        if ((!dgram->socket_timeout.tv_sec && !dgram->socket_timeout.tv_usec) ||
            (dgram->socket_timeout.tv_sec > timeleft.tv_sec) ||
            (dgram->socket_timeout.tv_sec == timeleft.tv_sec &&
             dgram->socket_timeout.tv_usec >= timeleft.tv_usec)) {
#ifdef USE_WINDOWS_API
            timeout = timeleft.tv_sec * 1000 + timeleft.tv_usec / 1000;
            setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, sizeof(timeout));
#else
            setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, &timeleft,
                       sizeof(struct timeval));
#endif /* USE_WINDOWS_API */
        }
    }
#endif /* SO_RCVTIMEO */
}

static void WOLFCRYPT_BIO_DATAGRAM_reset_rcv_timeout(WOLFCRYPT_BIO *bio)
{
#if defined(SO_RCVTIMEO)
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    /* Is a timer active? */
    if (dgram->next_timeout.tv_sec > 0 || dgram->next_timeout.tv_usec > 0) {
#ifdef USE_WINDOWS_API
        int timeout = dgram->socket_timeout.tv_sec * 1000 +
                      dgram->socket_timeout.tv_usec / 1000;
        setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                   (void *)&timeout, sizeof(timeout));
#else
        setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, &(dgram->socket_timeout),
                   sizeof(struct timeval));
#endif
    }
#endif
}

static int WOLFCRYPT_BIO_DATAGRAM_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    struct {
        union {
            size_t s;
            int i;
        } len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
#ifdef TEST_IPV6
            struct sockaddr_in6 sa_in6;
#endif
        } peer;
    } sa;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    sa.len.s = 0;
    sa.len.i = sizeof(sa.peer);

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
#else
    errno = 0;
#endif

    XMEMSET(&sa.peer, 0, sizeof(sa.peer));

    WOLFCRYPT_BIO_DATAGRAM_adjust_rcv_timeout(bio);

    ret = (int)recvfrom(bio->num, data, size, 0, &sa.peer.sa, (void *)&sa.len);
    if (sizeof(sa.len.i) != sizeof(sa.len.s) && sa.len.i == 0) {
        if (sa.len.s > sizeof(sa.peer))
            return 0;

        sa.len.i = (int)sa.len.s;
    }

    if (!dgram->connected && ret >= 0)
        WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &sa.peer);

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    if (ret < 0) {
        if (WOLFCRYPT_BIO_DATAGRAM_should_retry(ret)) {
            WOLFCRYPT_BIO_set_retry_read(bio);
#ifdef USE_WINDOWS_API
            dgram->_errno = WSAGetLastError();
#else
            dgram->_errno = errno;
#endif
        }
    }

    WOLFCRYPT_BIO_DATAGRAM_reset_rcv_timeout(bio);

    return ret;
}

static int WOLFCRYPT_BIO_DATAGRAM_write(WOLFCRYPT_BIO *bio,
                                        const char *data, int size)
{
    int ret;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
#else
    errno = 0;
#endif

    if (dgram->connected)
#ifdef USE_WINDOWS_API
        ret = (int)send(bio->num, data, size, 0);
#else
        ret = (int)write(bio->num, data, size);
#endif
    else {
        int peerlen = sizeof(dgram->peer);

        if (dgram->peer.sa.sa_family == AF_INET)
            peerlen = sizeof(dgram->peer.sa_in);
#ifdef TEST_IPV6
        else if (dgram->peer.sa.sa_family == AF_INET6)
            peerlen = sizeof(dgram->peer.sa_in6);
#endif
        ret = (int)sendto(bio->num, data, size, 0, &dgram->peer.sa, peerlen);
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    if (ret <= 0 && WOLFCRYPT_BIO_DATAGRAM_should_retry(ret)) {
        WOLFCRYPT_BIO_set_retry_write(bio);
#ifdef USE_WINDOWS_API
        dgram->_errno = WSAGetLastError();
#else
        dgram->_errno = errno;
#endif
    }

    return ret;
}

static long WOLFCRYPT_BIO_DATAGRAM_get_mtu_overhead(WOLFCRYPT_BIO_DATAGRAM *dgram)
{
    long ret;

    if (dgram == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (dgram->peer.sa.sa_family) {
        case AF_INET:
            ret = 28;
            break;
#ifdef TEST_IPV6
        case AF_INET6:
            ret = 48;
            break;
#endif
        default:
            ret = 28;
            break;
    }

    return ret;
}

static long WOLFCRYPT_BIO_DATAGRAM_ctrl(WOLFCRYPT_BIO *bio,
                                        int cmd, long num, void *ptr)
{
    long ret = 1;
    struct sockaddr *to = NULL;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            num = 0;

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
        case BIO_C_FILE_SEEK:
        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
            ret = 0;
            break;

        case BIO_C_SET_FD:
            WOLFCRYPT_BIO_DATAGRAM_clear(bio);
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

        case BIO_CTRL_DGRAM_CONNECT:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in));
                    break;
#ifdef TEST_IPV6
                case AF_INET6:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in6));
                    break;
#endif
                default:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                    break;
            }
            break;

        /* (Linux)kernel sets DF bit on outgoing IP packets */
        case BIO_CTRL_DGRAM_MTU_DISCOVER:
        break;

        case BIO_CTRL_DGRAM_QUERY_MTU:
        ret = 0;
        break;

        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
            ret = -WOLFCRYPT_BIO_DATAGRAM_get_mtu_overhead(dgram);
            switch (dgram->peer.sa.sa_family) {
                case AF_INET:
                    ret += 576;
                    break;
#ifdef TEST_IPV6
                case AF_INET6:
                    ret += 1280;
                    break;
#endif
                default:
                    ret += 576;
                    break;
            }
            break;

        case BIO_CTRL_DGRAM_GET_MTU:
            return dgram->mtu;
            break;

        case BIO_CTRL_DGRAM_SET_MTU:
            dgram->mtu = (int)num;
            ret = num;
            break;

        case BIO_CTRL_DGRAM_SET_CONNECTED:
            to = (struct sockaddr *)ptr;
            if (to != NULL) {
                dgram->connected = 1;
                switch (to->sa_family) {
                    case AF_INET:
                        XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in));
                        break;
#ifdef TEST_IPV6
                    case AF_INET6:
                        XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in6));
                        break;
#endif
                    default:
                        XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                        break;
                    }
            }
            else {
                dgram->connected = 0;
                XMEMSET(&dgram->peer, 0, sizeof(dgram->peer));
            }
            break;

        case BIO_CTRL_DGRAM_GET_PEER:
            switch (dgram->peer.sa.sa_family) {
                case AF_INET:
                    ret = sizeof(dgram->peer.sa_in);
                    break;
#ifdef TEST_IPV6
                case AF_INET6:
                    ret = sizeof(dgram->peer.sa_in6);
                    break;
#endif
                default:
                    ret = sizeof(dgram->peer.sa);
                    break;
            }

            if (num == 0 || num > ret)
                num = ret;
            XMEMCPY(ptr, &dgram->peer, (ret = num));
            break;

        case BIO_CTRL_DGRAM_SET_PEER:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in));
                    break;
#ifdef TEST_IPV6
                case AF_INET6:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in6));
                    break;
#endif
                default:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                    break;
            }
            break;

        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
            XMEMCPY(&dgram->next_timeout, ptr, sizeof(struct timeval));
            break;

#if defined(SO_RCVTIMEO)
        case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
#ifdef USE_WINDOWS_API
            {
                struct timeval *tv = (struct timeval *)ptr;
                int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
                if (setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                               (void *)&timeout, sizeof(timeout)) < 0)
                    ret = -1;
            }
#else
            if (setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, ptr,
                           sizeof(struct timeval)) < 0)
                ret = -1;
#endif /* USE_WINDOWS_API */
            break;

        case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
            {
                union {
                    size_t s;
                    int i;
                } sz = { 0 };
#ifdef USE_WINDOWS_API
                int timeout;
                struct timeval *tv = (struct timeval *)ptr;

                sz.i = sizeof(timeout);
                if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                               (void *)&timeout, &sz.i) < 0)
                    ret = -1;
                else {
                    tv->tv_sec = timeout / 1000;
                    tv->tv_usec = (timeout % 1000) * 1000;
                    ret = sizeof(*tv);
                }
#else
                sz.i = sizeof(struct timeval);
                if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                               ptr, (void *)&sz) < 0)
                        ret = -1;
                else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                    if (sz.s > sizeof(struct timeval))
                        ret = -1;
                    else
                        ret = (int)sz.s;
                }
                else
                    ret = sz.i;
#endif /* USE_WINDOWS_API */
            }
            break;
# endif /* defined(SO_RCVTIMEO) */

# if defined(SO_SNDTIMEO)
        case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
#ifdef USE_WINDOWS_API
            {
                struct timeval *tv = (struct timeval *)ptr;
                int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
                if (setsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                               (void *)&timeout, sizeof(timeout)) < 0)
                    ret = -1;
            }
#else
            if (setsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO, ptr,
                           sizeof(struct timeval)) < 0)
                ret = -1;
#endif /* USE_WINDOWS_API */
            break;

        case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
            {
                union {
                    size_t s;
                    int i;
                } sz = { 0 };
#ifdef USE_WINDOWS_API
                int timeout;
                struct timeval *tv = (struct timeval *)ptr;

                sz.i = sizeof(timeout);
                if (getsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                               (void *)&timeout, &sz.i) < 0)
                    ret = -1;
                else {
                    tv->tv_sec = timeout / 1000;
                    tv->tv_usec = (timeout % 1000) * 1000;
                    ret = sizeof(*tv);
                }
#else
                sz.i = sizeof(struct timeval);
                if (getsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                               ptr, (void *)&sz) < 0)
                    ret = -1;
                else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                    if (sz.s > sizeof(struct timeval))
                        ret = -1;
                    else
                        ret = (int)sz.s;
                }
                else
                    ret = sz.i;
#endif /* USE_WINDOWS_API */
            }
            break;
#endif /* defined(SO_SNDTIMEO) */

        case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
#ifdef USE_WINDOWS_API
            if (dgram->_errno == WSAETIMEDOUT)
#else
            if (dgram->_errno == EAGAIN)
#endif
            {
                ret = 1;
                dgram->_errno = 0;
            }
            else
                ret = 0;
            break;

        case BIO_CTRL_DGRAM_SET_DONT_FRAG:
           ret = -1;
            break;

        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            ret = WOLFCRYPT_BIO_DATAGRAM_get_mtu_overhead(dgram);
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_DATAGRAM_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return WOLFCRYPT_BIO_DATAGRAM_write(bio, str, (int)strlen(str));
}

#endif /* OPENSSL_EXTRA */
