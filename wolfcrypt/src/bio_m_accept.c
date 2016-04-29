/* bio_m_accept.c
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

typedef struct {
    int state;
    int nbio;

    char *param_addr;
    char *ip_port;
    int accept_sock;
    int accept_nbio;

    /*
     * If 0, it means normal, if 1, do a connect on bind failure, and if
     * there is no-one listening, bind with SO_REUSEADDR. If 2, always use
     * SO_REUSEADDR.
     */
    int bind_mode;

    /* used to force some socket options like NO_SIGPIPE, TCP_NODELAY */
    int options;

    WOLFCRYPT_BIO *bio_chain;
} WOLFCRYPT_BIO_ACCEPT;

static int WOLFCRYPT_BIO_accept_write(WOLFCRYPT_BIO *bio,
                                      const char *data, int size);
static int WOLFCRYPT_BIO_accept_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int WOLFCRYPT_BIO_accept_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_accept_ctrl(WOLFCRYPT_BIO *bio,
                                      int cmd, long num, void *ptr);
static int WOLFCRYPT_BIO_accept_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_accept_free(WOLFCRYPT_BIO *bio);
static void WOLFCRYPT_BIO_accept_close_socket(WOLFCRYPT_BIO *bio);

static int WOLFCRYPT_BIO_accept_state(WOLFCRYPT_BIO *bio,
                                      WOLFCRYPT_BIO_ACCEPT *c);

# define ACPT_S_BEFORE                   1
# define ACPT_S_GET_ACCEPT_SOCKET        2
# define ACPT_S_OK                       3

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_accept_method = {
    BIO_TYPE_ACCEPT,
    "Socket accept",
    WOLFCRYPT_BIO_accept_write,
    WOLFCRYPT_BIO_accept_read,
    WOLFCRYPT_BIO_accept_puts,
    NULL, /* gets */
    WOLFCRYPT_BIO_accept_ctrl,
    WOLFCRYPT_BIO_accept_new,
    WOLFCRYPT_BIO_accept_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_accept(void)
{
    return (&WOLFCRYPT_BIO_accept_method);
}

static int WOLFCRYPT_BIO_accept_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_accept_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->num = WOLFSSL_SOCKET_INVALID;
    bio->flags = 0;

    bio->ptr = (WOLFCRYPT_BIO_ACCEPT *)
                XMALLOC(sizeof(WOLFCRYPT_BIO_ACCEPT), 0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL)
        return 0;

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_ACCEPT));

    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->accept_sock = WOLFSSL_SOCKET_INVALID;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->bind_mode = BIO_BIND_NORMAL;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->options = 0;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->state = ACPT_S_BEFORE;

    bio->shutdown = 1;

    return 1;
}

static void WOLFCRYPT_BIO_accept_close_socket(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ACCEPT *accept;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    accept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;
    if (accept->accept_sock != WOLFSSL_SOCKET_INVALID) {
        shutdown(accept->accept_sock, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(accept->accept_sock);
#else
        close(accept->accept_sock);
#endif
        accept->accept_sock = WOLFSSL_SOCKET_INVALID;
        bio->num = WOLFSSL_SOCKET_INVALID;
    }
}

static int WOLFCRYPT_BIO_accept_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_accept_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!bio->shutdown)
        return 1;

    WOLFCRYPT_BIO_accept_close_socket(bio);

    if (bio->ptr != NULL) {
        WOLFCRYPT_BIO_ACCEPT *accept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

        if (accept->param_addr != NULL)
            XFREE(accept->param_addr, 0, DYNAMIC_TYPE_OPENSSL);
        if (accept->ip_port != NULL)
            XFREE(accept->ip_port, 0, DYNAMIC_TYPE_OPENSSL);
        if (accept->bio_chain != NULL)
            WOLFCRYPT_BIO_free(accept->bio_chain);

        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        bio->ptr = NULL;
    }

    bio->flags = 0;
    bio->init = 0;

    return 1;
}

static int WOLFCRYPT_BIO_accept_state(WOLFCRYPT_BIO *bio,
                                      WOLFCRYPT_BIO_ACCEPT *accept)
{
    WOLFCRYPT_BIO *nbio = NULL;
    int s = -1;
    int dsock;

    if (bio == NULL || accept == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

 again:
    switch (accept->state) {
        case ACPT_S_BEFORE:
            if (accept->param_addr == NULL) {
                WOLFSSL_ERROR(BIO_NO_PORT_E);
                return -1;
            }

            s = WOLFCRYPT_BIO_get_accept_socket(accept->param_addr,
                                                accept->bind_mode);
            if (s == WOLFSSL_SOCKET_INVALID)
                return -1;

            if (accept->accept_nbio) {
                if (!WOLFCRYPT_BIO_socket_nbio(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_NBIO_E);
                    return -1;
                }
            }

            /* TCP NO DELAY */
            if (accept->options & 1) {
                if (!WOLFCRYPT_BIO_set_tcp_ndelay(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_OPTIONS_E);
                    return -1;
                }
            }

            /* IGNORE SIGPIPE */
            if (accept->options & 2) {
                if (!WOLFCRYPT_BIO_set_tcp_nsigpipe(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_OPTIONS_E);
                    return -1;
                }
            }

            accept->accept_sock = s;
            bio->num = s;
            accept->state = ACPT_S_GET_ACCEPT_SOCKET;
            return 1;
            break;

        case ACPT_S_GET_ACCEPT_SOCKET:
            if (bio->next_bio != NULL) {
                accept->state = ACPT_S_OK;
                goto again;
            }

            WOLFCRYPT_BIO_clear_retry_flags(bio);
            bio->retry_reason = 0;
            dsock = WOLFCRYPT_BIO_accept(accept->accept_sock, &accept->ip_port);

            /* retry case */
            if (dsock == -2) {
                WOLFCRYPT_BIO_set_retry_special(bio);
                bio->retry_reason = BIO_RR_ACCEPT;
                return -1;
            }

            if (dsock < 0)
                return dsock;

            nbio = WOLFCRYPT_BIO_new_socket(dsock, BIO_CLOSE);
            if (nbio == NULL)
                goto err;

            WOLFCRYPT_BIO_set_callback(nbio,
                                       WOLFCRYPT_BIO_get_callback(bio));
            WOLFCRYPT_BIO_set_callback_arg(nbio,
                                           WOLFCRYPT_BIO_get_callback_arg(bio));

            if (accept->nbio) {
                if (!WOLFCRYPT_BIO_socket_nbio(dsock, 1)) {
                    WOLFSSL_ERROR(BIO_NBIO_E);
                    goto err;
                }
            }

            /*
             * If the accept BIO has an bio_chain, we dup it and put the new
             * socket at the end.
             */
            if (accept->bio_chain != NULL) {
                WOLFCRYPT_BIO *dbio = WOLFCRYPT_BIO_dup_chain(accept->bio_chain);
                if (dbio == NULL)
                    goto err;
                if (!WOLFCRYPT_BIO_push(dbio, nbio))
                    goto err;
                nbio = dbio;
            }

            if (WOLFCRYPT_BIO_push(bio, nbio) == NULL)
                goto err;

            accept->state = ACPT_S_OK;
            return 1;
err:
            if (nbio != NULL)
                WOLFCRYPT_BIO_free(nbio);
            else if (s >= 0)
#ifdef USE_WINDOWS_API
                closesocket(s);
#else
                close(s);
#endif
            break;

        case ACPT_S_OK:
            if (bio->next_bio == NULL) {
                accept->state = ACPT_S_GET_ACCEPT_SOCKET;
                goto again;
            }
            return 1;
            break;

        default:
            break;
    }

    return 0;
}

static int WOLFCRYPT_BIO_accept_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_ACCEPT *accept;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    accept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    while (bio->next_bio == NULL) {
        ret = WOLFCRYPT_BIO_accept_state(bio, accept);
        if (ret <= 0)
            return ret;
    }

    ret = WOLFCRYPT_BIO_read(bio->next_bio, data, size);
    WOLFCRYPT_BIO_copy_next_retry(bio);

    return ret;
}

static int WOLFCRYPT_BIO_accept_write(WOLFCRYPT_BIO *bio,
                                      const char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_ACCEPT *accept;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);
    accept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    while (bio->next_bio == NULL) {
        ret = WOLFCRYPT_BIO_accept_state(bio, accept);
        if (ret <= 0)
            return ret;
    }

    ret = WOLFCRYPT_BIO_write(bio->next_bio, data, size);
    WOLFCRYPT_BIO_copy_next_retry(bio);

    return ret;
}

static long WOLFCRYPT_BIO_accept_ctrl(WOLFCRYPT_BIO *bio,
                                      int cmd, long num, void *ptr)
{
    int *ip;
    long ret = 1;
    WOLFCRYPT_BIO_ACCEPT *accept;
    char **pp;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    accept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ret = 0;
            accept->state = ACPT_S_BEFORE;
            WOLFCRYPT_BIO_accept_close_socket(bio);
            bio->flags = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            /* use this one to start the connection */
            ret = (long)WOLFCRYPT_BIO_accept_state(bio, accept);
            break;

        case BIO_C_SET_ACCEPT:
            if (ptr != NULL) {
                if (num == 0) {
                    bio->init = 1;
                    if (accept->param_addr != NULL)
                        XFREE(accept->param_addr, 0, DYNAMIC_TYPE_OPENSSL);
                    accept->param_addr = strdup(ptr);
                }
                else if (num == 1) {
                    accept->accept_nbio = (ptr != NULL);
                }
                else if (num == 2) {
                    if (accept->bio_chain != NULL)
                        WOLFCRYPT_BIO_free(accept->bio_chain);
                    accept->bio_chain = (WOLFCRYPT_BIO *)ptr;
                }
            }
            break;

        case BIO_C_SET_NBIO:
            accept->nbio = (int)num;
            break;

        case BIO_C_SET_FD:
            bio->init = 1;
            bio->num = *((int *)ptr);
            accept->accept_sock = bio->num;
            accept->state = ACPT_S_GET_ACCEPT_SOCKET;
            bio->shutdown = (int)num;
            bio->init = 1;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                ip = (int *)ptr;
                if (ip != NULL)
                    *ip = accept->accept_sock;
                ret = accept->accept_sock;
            }
            else
                ret = -1;
            break;

        case BIO_C_GET_ACCEPT:
            if (bio->init) {
                if (ptr != NULL) {
                    pp = (char **)ptr;
                    *pp = accept->param_addr;
                }
                else
                    ret = -1;
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

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            ret = 0;
            break;

        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            break;

        case BIO_C_SET_BIND_MODE:
            accept->bind_mode = (int)num;
            break;

        case BIO_C_GET_BIND_MODE:
            ret = (long)accept->bind_mode;
            break;

        case BIO_C_SET_EX_ARG:
            accept->options = (int)num;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_accept_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return WOLFCRYPT_BIO_accept_write(bio, str, (int)strlen(str));
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_accept(const char *str)
{
    WOLFCRYPT_BIO *bio;

    if (str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_accept());
    if (bio == NULL)
        return NULL;

    if (WOLFCRYPT_BIO_set_accept_port(bio, str))
        return bio;

    WOLFCRYPT_BIO_free(bio);
    return NULL;
}

#endif /* OPENSSL_EXTRA */
