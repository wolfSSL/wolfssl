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
#else
#include <fcntl.h>
#include <netdb.h>
#ifdef SO_NOSIGPIPE
#include <signal.h>
#endif
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

#define MAX_LISTEN  32

#ifdef USE_WINDOWS_API
static int wsa_init_done = 0;
#endif

int WOLFCRYPT_BIO_get_host_ip(const char *str, unsigned char *ip)
{
    struct hostent *he;
    unsigned int iip[4];

    if (WOLFCRYPT_BIO_sock_init() != 1)
        return 0;

    /* IP found */
    if (sscanf(str, "%d.%d.%d.%d", &iip[0], &iip[1], &iip[2], &iip[3]) == 4)
    {
        ip[0] = (iip[0] & 0xff000000) >> 24;
        ip[1] = (iip[1] & 0x00ff0000) >> 16;
        ip[2] = (iip[2] & 0x0000ff00) >> 8;
        ip[3] = (iip[3] & 0x000000ff);
        return 1;
    }

    /* IP not found, check with a gethostbyname */
    he = gethostbyname(str);
    if (he == NULL) {
        WOLFSSL_ERROR(BIO_NO_HOSTNAME_E);
        return 0;
    }

    if (he->h_addrtype != AF_INET) {
        WOLFSSL_ERROR(BIO_ADDR_AF_INET_E);
        return 0;
    }

    XMEMCPY(ip, he->h_addr_list[0], 4);

    return 1;
}

int WOLFCRYPT_BIO_get_port(const char *str, unsigned short *port_ptr)
{
    int i;
    struct servent *s;

    if (str == NULL) {
        WOLFSSL_ERROR(BIO_NO_PORT_E);
        return 0;
    }

    i = atoi(str);
    if (i != 0) {
        *port_ptr = (unsigned short)i;
        return 1;
    }

    s = getservbyname(str, "tcp");
    if (s != NULL) {
        *port_ptr = ntohs((unsigned short)s->s_port);
        return 1;
    }

    if (strcmp(str, "http") == 0)
        *port_ptr = 80;
    else if (strcmp(str, "telnet") == 0)
        *port_ptr = 23;
    else if (strcmp(str, "socks") == 0)
        *port_ptr = 1080;
    else if (strcmp(str, "https") == 0)
        *port_ptr = 443;
    else if (strcmp(str, "ssl") == 0)
        *port_ptr = 443;
    else if (strcmp(str, "ftp") == 0)
        *port_ptr = 21;
    else if (strcmp(str, "gopher") == 0)
        *port_ptr = 70;
    else {
        WOLFSSL_ERROR(BIO_SRV_PROTO_E);
        return 0;
    }

    return 1;
}

int WOLFCRYPT_BIO_sock_error(int sock)
{
    int j = 0, i;
    union {
        size_t s;
        int i;
    } size;

    /* heuristic way to adapt for platforms that expect 64-bit optlen */
    size.s = 0, size.i = sizeof(j);
    /*
     * Note: under Windows the third parameter is of type (char *) whereas
     * under other systems it is (void *) if you don't have a cast it will
     * choke the compiler: if you do have a cast then you can either go for
     * (char *) or (void *).
     */
    i = getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *)&j, (void *)&size);
    if (i < 0)
        return 1;

    return j;
}

int WOLFCRYPT_BIO_sock_init(void)
{
# ifdef USE_WINDOWS_API
    static struct WSAData wsa_state;

    if (!wsa_init_done) {
        int err;

        wsa_init_done = 1;
        memset(&wsa_state, 0, sizeof(wsa_state));
        /*
         * Not making wsa_state available to the rest of the code is formally
         * wrong. But the structures we use are [beleived to be] invariable
         * among Winsock DLLs, while API availability is [expected to be]
         * probed at run-time with DSO_global_lookup.
         */
        if (WSAStartup(0x0202, &wsa_state) != 0) {
            err = WSAGetLastError();
            WOLFSSL_ERROR(BIO_WSASTARTUP_E);
            return -1;
        }
    }
# endif /* USE_WINDOWS_API */

    return 1;
}

void WOLFCRYPT_BIO_sock_cleanup(void)
{
#ifdef USE_WINDOWS_API
    if (wsa_init_done) {
        wsa_init_done = 0;
        WSACleanup();
    }
#endif
}

int WOLFCRYPT_BIO_get_accept_socket(char *host, int bind_mode)
{
    int ret = 0;
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
#ifdef TEST_IPV6
        struct sockaddr_in6 sa_in6;
#endif
    } server, client;
    int s = WOLFSSL_SOCKET_INVALID, cs, addrlen;
    unsigned char ip[4];
    unsigned short port;
    char *str = NULL;
    char *h, *p, *e;
    unsigned long l;
    int err_num;

    if (WOLFCRYPT_BIO_sock_init() != 1)
        return WOLFSSL_SOCKET_INVALID;

    str = strdup(host);
    if (str == NULL)
        return WOLFSSL_SOCKET_INVALID;

    h = p = NULL;
    h = str;
    for (e = str; *e; e++) {
        if (*e == ':') {
            p = e;
        } else if (*e == '/') {
            *e = '\0';
            break;
        }
    }
    if (p)
        *p++ = '\0';            /* points at last ':', '::port' is special
                                 * [see below] */
    else
        p = h, h = NULL;

    if (!WOLFCRYPT_BIO_get_port(p, &port))
        goto err;

    memset((char *)&server, 0, sizeof(server));
    server.sa_in.sin_family = AF_INET;
    server.sa_in.sin_port = htons(port);
    addrlen = sizeof(server.sa_in);

    if (h == NULL || strcmp(h, "*") == 0)
        server.sa_in.sin_addr.s_addr = INADDR_ANY;
    else {
        if (!WOLFCRYPT_BIO_get_host_ip(h, &(ip[0])))
            goto err;
        l = (unsigned long)
            ((unsigned long)ip[0] << 24L) |
            ((unsigned long)ip[1] << 16L) |
            ((unsigned long)ip[2] << 8L)  |
            ((unsigned long)ip[3]);
        server.sa_in.sin_addr.s_addr = htonl(l);
    }

 again:
    s = socket(server.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == WOLFSSL_SOCKET_INVALID) {
        WOLFSSL_ERROR(BIO_CREATE_SOCKET_E);
        goto err;
    }

#ifdef SO_REUSEADDR
    if (bind_mode == BIO_BIND_REUSEADDR) {
        int i = 1;

        ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&i, sizeof(i));
        bind_mode = BIO_BIND_NORMAL;
    }
#endif /* SO_REUSEADDR */
    if (bind(s, &server.sa, addrlen) == -1) {
#ifdef SO_REUSEADDR
#ifdef USE_WINDOWS_API
        err_num = WSAGetLastError();
        if ((bind_mode == BIO_BIND_REUSEADDR_IF_UNUSED) &&
            (err_num == WSAEADDRINUSE))
#else
        err_num = errno;
        if ((bind_mode == BIO_BIND_REUSEADDR_IF_UNUSED) &&
            (err_num == EADDRINUSE))
#endif /* USE_WINDOWS_API */
        {
            client = server;
            if (h == NULL || strcmp(h, "*") == 0) {
#ifdef TEST_IPV6
                if (client.sa.sa_family == AF_INET6) {
                    XMEMSET(&client.sa_in6.sin6_addr, 0,
                           sizeof(client.sa_in6.sin6_addr));
                    client.sa_in6.sin6_addr.s6_addr[15] = 1;
                }
                else
#endif
                if (client.sa.sa_family == AF_INET) {
                    client.sa_in.sin_addr.s_addr = htonl(0x7F000001);
                }
                else
                    goto err;
            }

            cs = socket(client.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
            if (cs != WOLFSSL_SOCKET_INVALID) {
                int ii;
                ii = connect(cs, &client.sa, addrlen);
#ifdef USE_WINDOWS_API
                closesocket(cs);
#else
                close(cs);
#endif
                if (ii == WOLFSSL_SOCKET_INVALID) {
                    bind_mode = BIO_BIND_REUSEADDR;
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    goto again;
                }
            }
        }
#endif /* SO_REUSEADDR */

        WOLFSSL_ERROR(BIO_BIND_SOCKET_E);
        goto err;
    }

    if (listen(s, MAX_LISTEN) == -1) {
        WOLFSSL_ERROR(BIO_LISTEN_SOCKET_E);
        goto err;
    }

    ret = 1;

 err:

    if (str != NULL)
        free(str);

    if (!ret && (s != WOLFSSL_SOCKET_INVALID)) {
#ifdef USE_WINDOWS_API
        closesocket(s);
#else
        close(s);
#endif
        s = WOLFSSL_SOCKET_INVALID;
    }

    return s;
}

int WOLFCRYPT_BIO_accept(int sock, char **addr)
{
    int dsock = WOLFSSL_SOCKET_INVALID;
    unsigned long l;

    struct {
        union {
            size_t s;
            int i;
        } len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
#ifdef TEST_IPV6
            struct sockaddr_in sa_in6;
#endif
        } from;
    } sa;

    sa.len.s = 0;
    sa.len.i = sizeof(sa.from);
    memset(&sa.from, 0, sizeof(sa.from));

    dsock = accept(sock, &sa.from.sa, (void *)&sa.len);
    if (sizeof(sa.len.i) != sizeof(sa.len.s) && !sa.len.i) {
        if (sa.len.s > sizeof(sa.from)) {
            WOLFSSL_ERROR(MEMORY_E);
            goto end;
        }

        sa.len.i = (int)sa.len.s;
    }

    if (dsock == WOLFSSL_SOCKET_INVALID) {
        if (WOLFCRYPT_BIO_sock_should_retry(dsock))
            return -2;
        WOLFSSL_ERROR(BIO_ACCEPT_E);
        goto end;
    }

    if (addr == NULL || sa.from.sa.sa_family != AF_INET)
        goto end;

    if (*addr == NULL) {
        *addr = XMALLOC(24, 0, DYNAMIC_TYPE_OPENSSL);
        if (*addr == NULL) {
            WOLFSSL_ERROR(MEMORY_E);
            goto end;
        }
    }

    l = ntohl(sa.from.sa_in.sin_addr.s_addr);

    XSNPRINTF(*addr, 24, "%d.%d.%d.%d:%d",
              (unsigned char)(l >> 24L) & 0xff,
              (unsigned char)(l >> 16L) & 0xff,
              (unsigned char)(l >> 8L) & 0xff,
              (unsigned char)(l) & 0xff, ntohs(sa.from.sa_in.sin_port));
 end:
    return dsock;
}

int WOLFCRYPT_BIO_set_tcp_nsigpipe(int s, int on)
{
    int ret = 0;

#ifndef USE_WINDOWS_API
#ifdef SO_NOSIGPIPE
    ret = setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else  /* no S_NOSIGPIPE */
    (void) s;
    (void) on;

    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */
#endif /* USE_WINDOWS_API */

    return (ret == 0);
}

int WOLFCRYPT_BIO_set_tcp_ndelay(int s, int on)
{
    int ret = 0;
#if defined(TCP_NODELAY)
#ifdef SOL_TCP
    int opt = SOL_TCP;
#else
    int opt = IPPROTO_TCP;
#endif

    ret = setsockopt(s, opt, TCP_NODELAY, (char *)&on, sizeof(on));
#else
    (void) s;
    (void) on;
#endif /* TCP_NODELAY */

    return (ret == 0);
}

int WOLFCRYPT_BIO_socket_nbio(int s, int mode)
{
#ifdef USE_WINDOWS_API
    unsigned long blocking = mode;
    int ret = ioctlsocket(s, FIONBIO, &blocking);
    return (ret == 0);
#elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
|| defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS)
    /* non blocking not supported, for now */
    return -1;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags)
        flags = fcntl(s, F_SETFL, flags | mode);
    return (flags == 0);
#endif
}

#endif /* OPENSSL_EXTRA */
