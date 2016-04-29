/* bio_m_conn.c
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
        #define WOLFSSL_SOCKET_INVALID  ((SOCKET)INVALID_SOCKET)
    #else
        #define WOLFSSL_SOCKET_INVALID  (0)
    #endif
#endif /* WOLFSSL_SOCKET_INVALID */

static int WOLFCRYPT_BIO_conn_write(WOLFCRYPT_BIO *bio,
                                    const char *data, int size);
static int WOLFCRYPT_BIO_conn_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int WOLFCRYPT_BIO_conn_puts(WOLFCRYPT_BIO *bio, const char *str);
static long WOLFCRYPT_BIO_conn_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                    long num, void *ptr);
static int WOLFCRYPT_BIO_conn_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_conn_free(WOLFCRYPT_BIO *bio);
static long WOLFCRYPT_BIO_conn_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                               WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_conn_method = {
    BIO_TYPE_SOCKET,
    "Socket connect",
    WOLFCRYPT_BIO_conn_write,
    WOLFCRYPT_BIO_conn_read,
    WOLFCRYPT_BIO_conn_puts,
    NULL, /* gets */
    WOLFCRYPT_BIO_conn_ctrl,
    WOLFCRYPT_BIO_conn_new,
    WOLFCRYPT_BIO_conn_free,
    WOLFCRYPT_BIO_conn_callback_ctrl,
};

typedef struct {
    int state;
    int nbio;

    /* keep received Hostname and Port */
    char *pHostname;
    char *pPort;

    /* internal usage */
    unsigned char ip[4];
    unsigned short port;

    struct sockaddr_in them;

    /*
     * called when the connection is initially made callback(BIO,state,ret);
     * The callback should return 'ret'.  state is for compatibility with the
     * ssl info_callback
     */
    int (*info_callback) (const WOLFCRYPT_BIO *bio, int state, int ret);
} WOLFCRYPT_BIO_CONNECT;

static int WOLFCRYPT_BIO_conn_state(WOLFCRYPT_BIO *bio,
                                    WOLFCRYPT_BIO_CONNECT *conn)
{
    int ret = -1, i;
    word32 l;
    char *p, *q;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_state");

    if (bio == NULL || conn == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    for (;;) {
        switch (conn->state) {
            case BIO_CONN_S_BEFORE:
                p = conn->pHostname;
                if (p == NULL) {
                    WOLFSSL_ERROR(BIO_NO_HOSTNAME_E);
                    goto exit_loop;
                }

                for (; *p != '\0'; p++) {
                    if ((*p == ':') || (*p == '/'))
                        break;
                }

                i = *p;
                if ((i == ':') || (i == '/')) {
                    *(p++) = '\0';
                    if (i == ':') {
                        for (q = p; *q; q++)
                            if (*q == '/') {
                                *q = '\0';
                                break;
                            }

                        if (conn->pPort != NULL)
                            XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                        conn->pPort = XMALLOC(strlen(p)+1,
                                              0, DYNAMIC_TYPE_OPENSSL);
                        if (conn->pPort == NULL) {
                            WOLFSSL_ERROR(MEMORY_E);
                            goto exit_loop;
                            break;
                        }
                        XSTRNCPY(conn->pPort, p, strlen(p)+1);
                    }
                }

                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(BIO_NO_PORT_E);
                    goto exit_loop;
                }

                conn->state = BIO_CONN_S_GET_IP;
                break;

            case BIO_CONN_S_GET_IP:
                if (WOLFCRYPT_BIO_get_host_ip(conn->pHostname,
                                              conn->ip) <= 0)
                    goto exit_loop;
                conn->state = BIO_CONN_S_GET_PORT;
                break;

            case BIO_CONN_S_GET_PORT:
                if (conn->pPort == NULL ||
                    WOLFCRYPT_BIO_get_port(conn->pPort, &conn->port) <= 0)
                    goto exit_loop;
                conn->state = BIO_CONN_S_CREATE_SOCKET;
                break;

            case BIO_CONN_S_CREATE_SOCKET:
                /* now setup address */
                XMEMSET(&conn->them, 0, sizeof(conn->them));
                conn->them.sin_family = AF_INET;
                conn->them.sin_port = htons((unsigned short)conn->port);
                l = ((word32)conn->ip[0] << 24L) |
                    ((word32)conn->ip[1] << 16L) |
                    ((word32)conn->ip[2] << 8L)  |
                    ((word32)conn->ip[3]);
                conn->them.sin_addr.s_addr = htonl(l);
                conn->state = BIO_CONN_S_CREATE_SOCKET;

                ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (ret <= 0) {
                    WOLFSSL_ERROR(BIO_CREATE_SOCKET_E);
                    goto exit_loop;
                }

                bio->num = ret;
                conn->state = BIO_CONN_S_NBIO;
                break;

            case BIO_CONN_S_NBIO:
                if (conn->nbio) {
                    if (!WOLFCRYPT_BIO_socket_nbio(bio->num, 1)) {
                        WOLFSSL_ERROR(BIO_NBIO_E);
                        goto exit_loop;
                    }
                }
                conn->state = BIO_CONN_S_CONNECT;

# if defined(SO_KEEPALIVE)
                i = 1;
                i = setsockopt(bio->num, SOL_SOCKET, SO_KEEPALIVE, (char *)&i,
                               sizeof(i));
                if (i < 0) {
                    WOLFSSL_ERROR(BIO_KEEPALIVE_E);
                    goto exit_loop;
                }
# endif
                break;


            case BIO_CONN_S_CONNECT:
                WOLFCRYPT_BIO_clear_retry_flags(bio);
                ret = connect(bio->num, (struct sockaddr *)&conn->them,
                              sizeof(conn->them));
                bio->retry_reason = 0;
                if (ret < 0) {
                    if (WOLFCRYPT_BIO_sock_should_retry(ret)) {
                        WOLFCRYPT_BIO_set_retry_special(bio);
                        conn->state = BIO_CONN_S_BLOCKED_CONNECT;
                        bio->retry_reason = BIO_RR_CONNECT;
                    }
                    else
                        WOLFSSL_ERROR(BIO_CONNECT_E);
                    goto exit_loop;
                }
                else
                    conn->state = BIO_CONN_S_OK;
                break;

            case BIO_CONN_S_BLOCKED_CONNECT:
                i = WOLFCRYPT_BIO_sock_error(bio->num);
                if (i != 0) {
                    WOLFSSL_ERROR(BIO_CONNECT_E);
                    ret = 0;
                    goto exit_loop;
                }
                else
                    conn->state = BIO_CONN_S_OK;
                break;

            case BIO_CONN_S_OK:
                ret = 1;
                goto exit_loop;
                break;

            default:
                goto exit_loop;
                break;
        }

        if (conn->info_callback != NULL) {
            ret = conn->info_callback(bio, conn->state, ret);
            if (!ret)
                goto end;
        }
    }

exit_loop:
    if (conn->info_callback != NULL)
        ret = conn->info_callback(bio, conn->state, ret);
end:
    return ret;
}

static WOLFCRYPT_BIO_CONNECT *WOLFCRYPT_BIO_CONNECT_new(void)
{
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_CONNECT_new");

    conn = (WOLFCRYPT_BIO_CONNECT *)XMALLOC(sizeof(WOLFCRYPT_BIO_CONNECT),
                                            0, DYNAMIC_TYPE_OPENSSL);
    if (conn == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    XMEMSET(conn, 0, sizeof(WOLFCRYPT_BIO_CONNECT));

    conn->state = BIO_CONN_S_BEFORE;
    return conn;
}

static void WOLFCRYPT_BIO_CONNECT_free(WOLFCRYPT_BIO_CONNECT *conn)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_CONNECT_free");

    if (conn == NULL)
        return;

    if (conn->pHostname != NULL) {
        XFREE(conn->pHostname, 0, DYNAMIC_TYPE_OPENSSL);
        conn->pHostname = NULL;
    }

    if (conn->pPort != NULL) {
        XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);
        conn->pPort = NULL;
    }

    XFREE(conn, 0, DYNAMIC_TYPE_OPENSSL);
    conn = NULL;
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_connect(void)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_s_connect");

    return (&WOLFCRYPT_BIO_conn_method);
}

static int WOLFCRYPT_BIO_conn_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->flags = 0;
    bio->num = WOLFSSL_SOCKET_INVALID;

    bio->ptr = WOLFCRYPT_BIO_CONNECT_new();
    if (bio->ptr == NULL)
        return 0;

    return 1;
}

static void WOLFCRYPT_BIO_conn_close_socket(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_close_socket");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return ;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    if (bio->num > 0) {
        /* Only do a shutdown if things were established */
        if (conn->state == BIO_CONN_S_OK)
            shutdown(bio->num, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(bio->num);
#else
        close(bio->num);
#endif
        bio->num = WOLFSSL_SOCKET_INVALID;
    }
}

static int WOLFCRYPT_BIO_conn_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->shutdown) {
        WOLFCRYPT_BIO_conn_close_socket(bio);
        WOLFCRYPT_BIO_CONNECT_free((WOLFCRYPT_BIO_CONNECT *)bio->ptr);
        bio->ptr = NULL;
        bio->flags = 0;
        bio->init = 0;
    }

    return 1;
}

static int WOLFCRYPT_BIO_conn_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_read");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;
    if (conn->state != BIO_CONN_S_OK) {
        ret = WOLFCRYPT_BIO_conn_state(bio, conn);
        if (ret <= 0)
            return (ret);
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

static int WOLFCRYPT_BIO_conn_write(WOLFCRYPT_BIO *bio,
                                    const char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_write");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;
    if (conn->state != BIO_CONN_S_OK) {
        ret = WOLFCRYPT_BIO_conn_state(bio, conn);
        if (ret <= 0)
            return (ret);
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

static long WOLFCRYPT_BIO_conn_ctrl(WOLFCRYPT_BIO *bio,
                                    int cmd, long num, void *ptr)
{
    long ret = 1;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ret = 0;
            conn->state = BIO_CONN_S_BEFORE;
            WOLFCRYPT_BIO_conn_close_socket(bio);
            bio->flags = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            /* use this one to start the connection */
            if (conn->state != BIO_CONN_S_OK)
                ret = (long)WOLFCRYPT_BIO_conn_state(bio, conn);
            else
                ret = 1;
            break;

        case BIO_C_GET_CONNECT:
            if (ptr == NULL)
                break;

            if (num == 0)
                *((const char **)ptr) = conn->pHostname;
            else if (num == 1)
                *((const char **)ptr) = conn->pPort;
            else if (num == 2)
                *((const char **)ptr) = (char *)conn->ip;
            else if (num == 3)
                *((int *)ptr) = conn->port;

            if (!bio->init || ptr == NULL)
                *((const char **)ptr) = "not initialized";

            ret = 1;
            break;

        case BIO_C_SET_CONNECT:
            if (ptr == NULL)
                break;

            bio->init = 1;
            if (num == 0) {
                if (conn->pHostname != NULL)
                    XFREE(conn->pHostname, 0, DYNAMIC_TYPE_OPENSSL);
                conn->pHostname = XMALLOC(strlen((char *)ptr)+1,
                                          0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pHostname == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pHostname, (char *)ptr, strlen((char *)ptr)+1);
            }
            else if (num == 1) {
                if (conn->pPort != NULL)
                    XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pPort = XMALLOC(strlen((char *)ptr)+1,
                                      0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pPort, (char *)ptr, strlen((char *)ptr)+1);
            }
            else if (num == 2) {
                char buf[16];
                unsigned char *p = ptr;

                XSNPRINTF(buf, sizeof(buf), "%d.%d.%d.%d",
                          p[0], p[1], p[2], p[3]);

                if (conn->pHostname != NULL)
                    XFREE(conn->pHostname, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pHostname = XMALLOC(strlen(buf)+1,
                                          0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pHostname == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pHostname, buf, strlen(buf)+1);

                memcpy(conn->ip, ptr, 4);
            }
            else if (num == 3) {
                char buf[6];

                XSNPRINTF(buf, sizeof(buf), "%d", *(int *)ptr);
                if (conn->pPort != NULL)
                    XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pPort = XMALLOC(strlen(buf)+1,
                                      0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pPort, buf, strlen(buf)+1);

                conn->port = *(int *)ptr;
            }
            break;

        case BIO_C_SET_NBIO:
            conn->nbio = (int)num;
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

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            ret = 0;
            break;

        case BIO_CTRL_FLUSH:
            break;

        case BIO_CTRL_DUP:
            {
                WOLFCRYPT_BIO *dbio = (WOLFCRYPT_BIO *)ptr;

                if (conn->pPort != NULL)
                    WOLFCRYPT_BIO_set_conn_port(dbio, conn->pPort);

                if (conn->pHostname != NULL)
                    WOLFCRYPT_BIO_set_conn_hostname(dbio, conn->pHostname);

                WOLFCRYPT_BIO_set_nbio(dbio, conn->nbio);

                WOLFCRYPT_BIO_set_info_callback(dbio,
                                (WOLFCRYPT_BIO_info_cb *)conn->info_callback);
            }
            break;

        case BIO_CTRL_SET_CALLBACK:
            ret = 0;
            break;

        case BIO_CTRL_GET_CALLBACK:
            {
                int (**fptr) (const WOLFCRYPT_BIO *bio, int state, int xret);

                fptr = (int (**)(const WOLFCRYPT_BIO *bio,
                                 int state, int xret))ptr;
                *fptr = conn->info_callback;
            }
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static long WOLFCRYPT_BIO_conn_callback_ctrl(WOLFCRYPT_BIO *bio,
                                             int cmd, WOLFCRYPT_BIO_info_cb *fp)
{
    long ret = 1;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_callback_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_SET_CALLBACK:
            conn->info_callback = (int (*)(const WOLFCRYPT_BIO *, int, int))fp;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_conn_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_conn_puts");

    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return WOLFCRYPT_BIO_conn_write(bio, str, (int)strlen(str));
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_connect(const char *str)
{
    WOLFCRYPT_BIO *bio;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_new_connect");

    if (str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_connect());
    if (bio == NULL)
        return NULL;

    if (WOLFCRYPT_BIO_set_conn_hostname(bio, str))
        return bio;

    WOLFCRYPT_BIO_free(bio);
    return NULL;
}

#endif /* OPENSSL_EXTRA */
