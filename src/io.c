/* io.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef _WIN32_WCE
    /* On WinCE winsock2.h must be included before windows.h for socket stuff */
    #include <winsock2.h>
#endif

#include <cyassl/internal.h>

/* if user writes own I/O callbacks they can define CYASSL_USER_IO to remove
   automatic setting of default I/O functions EmbedSend() and EmbedReceive()
   but they'll still need SetCallback xxx() at end of file 
*/
#ifndef CYASSL_USER_IO

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifndef USE_WINDOWS_API
    #ifdef CYASSL_LWIP
        /* lwIP needs to be configured to use sockets API in this mode */
        /* LWIP_SOCKET 1 in lwip/opt.h or in build */
        #include "lwip/sockets.h"
        #ifndef LWIP_PROVIDE_ERRNO
            #define LWIP_PROVIDE_ERRNO 1
        #endif
    #else
        #include <sys/types.h>
        #include <errno.h>
        #ifndef EBSNET
            #include <unistd.h>
        #endif
        #include <fcntl.h>
        #if !(defined(DEVKITPRO) || defined(THREADX) || defined(EBSNET))
            #include <sys/socket.h>
            #include <arpa/inet.h>
            #include <netinet/in.h>
            #include <netdb.h>
            #ifdef __PPU
                #include <netex/errno.h>
            #else
                #include <sys/ioctl.h>
            #endif
        #endif
        #ifdef THREADX
            #include <socket.h>
        #endif
        #ifdef EBSNET
            #include "rtipapi.h"  /* errno */
            #include "socket.h"
        #endif
    #endif
#endif /* USE_WINDOWS_API */

#ifdef __sun
    #include <sys/filio.h>
#endif

#ifdef USE_WINDOWS_API 
    /* no epipe yet */
    #ifndef WSAEPIPE
        #define WSAEPIPE       -12345
    #endif
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
    #define SOCKET_EAGAIN      WSAEWOULDBLOCK
    #define SOCKET_ECONNRESET  WSAECONNRESET
    #define SOCKET_EINTR       WSAEINTR
    #define SOCKET_EPIPE       WSAEPIPE
#elif defined(__PPU)
    #define SOCKET_EWOULDBLOCK SYS_NET_EWOULDBLOCK
    #define SOCKET_EAGAIN      SYS_NET_EAGAIN
    #define SOCKET_ECONNRESET  SYS_NET_ECONNRESET
    #define SOCKET_EINTR       SYS_NET_EINTR
    #define SOCKET_EPIPE       SYS_NET_EPIPE
#else
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  ECONNRESET
    #define SOCKET_EINTR       EINTR
    #define SOCKET_EPIPE       EPIPE
#endif /* USE_WINDOWS_API */


#ifdef DEVKITPRO
    /* from network.h */
    int net_send(int, const void*, int, unsigned int);
    int net_recv(int, void*, int, unsigned int);
    #define SEND_FUNCTION net_send
    #define RECV_FUNCTION net_recv
#elif defined(CYASSL_LWIP)
    #define SEND_FUNCTION lwip_send
    #define RECV_FUNCTION lwip_recv
#else
    #define SEND_FUNCTION send
    #define RECV_FUNCTION recv
#endif


static INLINE int LastError(void)
{
#ifdef USE_WINDOWS_API 
    return WSAGetLastError();
#elif defined(EBSNET)
    return xn_getlasterror();
#else
    return errno;
#endif
}

/* The receive embedded callback
 *  return : nb bytes read, or error
 */
int EmbedReceive(CYASSL *ssl, char *buf, int sz, void *ctx)
{
    int recvd;
    int err;
    int sd = *(int*)ctx;

#ifdef CYASSL_DTLS
    if (ssl->options.dtls
                     && !ssl->options.usingNonblock && ssl->dtls_timeout != 0) {
        #ifdef USE_WINDOWS_API
            DWORD timeout = ssl->dtls_timeout;
        #else
            struct timeval timeout = {ssl->dtls_timeout, 0};
        #endif
        setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
#endif

    recvd = RECV_FUNCTION(sd, (char *)buf, sz, 0);

    if (recvd < 0) {
        err = LastError();
        CYASSL_MSG("Embed Receive error");

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            if (ssl->options.usingNonblock) {
                CYASSL_MSG("    Would block");
                return IO_ERR_WANT_READ;
            }
            else {
                CYASSL_MSG("    Socket timeout");
                return IO_ERR_TIMEOUT;
            }
        }
        else if (err == SOCKET_ECONNRESET) {
            CYASSL_MSG("    Connection reset");
            return IO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            CYASSL_MSG("    Socket interrupted");
            return IO_ERR_ISR;
        }
        else {
            CYASSL_MSG("    General error");
            return IO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        CYASSL_MSG("Embed receive connection closed");
        return IO_ERR_CONN_CLOSE;
    }

    return recvd;
}

/* The send embedded callback
 *  return : nb bytes sent, or error
 */
int EmbedSend(CYASSL* ssl, char *buf, int sz, void *ctx)
{
    int sd = *(int*)ctx;
    int sent;
    int len = sz;
    int err;

    (void)ssl;

    sent = SEND_FUNCTION(sd, &buf[sz - len], len, 0);

    if (sent < 0) {
        err = LastError();
        CYASSL_MSG("Embed Send error");

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            CYASSL_MSG("    Would Block");
            return IO_ERR_WANT_WRITE;
        }
        else if (err == SOCKET_ECONNRESET) {
            CYASSL_MSG("    Connection reset");
            return IO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            CYASSL_MSG("    Socket interrupted");
            return IO_ERR_ISR;
        }
        else if (err == SOCKET_EPIPE) {
            CYASSL_MSG("    Socket EPIPE");
            return IO_ERR_CONN_CLOSE;
        }
        else {
            CYASSL_MSG("    General error");
            return IO_ERR_GENERAL;
        }
    }
 
    return sent;
}


#ifdef CYASSL_DTLS

#include <cyassl/ctaocrypt/sha.h>

#ifdef USE_WINDOWS_API
   #define XSOCKLENT int
#else
   #define XSOCKLENT socklen_t
#endif


/* The DTLS Generate Cookie callback
 *  return : number of bytes copied into buf, or error
 */
int EmbedGenerateCookie(byte *buf, int sz, void *ctx)
{
    CYASSL* ssl = (CYASSL*)ctx;
    int sd = ssl->wfd;
    struct sockaddr_in peer;
    XSOCKLENT peerSz = sizeof(peer);
    byte cookieSrc[sizeof(struct in_addr) + sizeof(int)];
    int cookieSrcSz = 0;
    Sha sha;

    getpeername(sd, (struct sockaddr*)&peer, &peerSz);
    
    if (peer.sin_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in*)&peer;

        cookieSrcSz = sizeof(struct in_addr) + sizeof(s->sin_port);
        XMEMCPY(cookieSrc, &s->sin_port, sizeof(s->sin_port));
        XMEMCPY(cookieSrc + sizeof(s->sin_port),
                                     &s->sin_addr, sizeof(struct in_addr));
    }

    InitSha(&sha);
    ShaUpdate(&sha, cookieSrc, cookieSrcSz);

    if (sz < SHA_DIGEST_SIZE) {
        byte digest[SHA_DIGEST_SIZE];
        ShaFinal(&sha, digest);
        XMEMCPY(buf, digest, sz);
        return sz;
    }

    ShaFinal(&sha, buf);

    return SHA_DIGEST_SIZE;
}

#endif /* CYASSL_DTLS */


#endif /* CYASSL_USER_IO */

CYASSL_API void CyaSSL_SetIORecv(CYASSL_CTX *ctx, CallbackIORecv CBIORecv)
{
    ctx->CBIORecv = CBIORecv;
}


CYASSL_API void CyaSSL_SetIOSend(CYASSL_CTX *ctx, CallbackIOSend CBIOSend)
{
    ctx->CBIOSend = CBIOSend;
}


CYASSL_API void CyaSSL_SetIOReadCtx(CYASSL* ssl, void *rctx)
{
	ssl->IOCB_ReadCtx = rctx;
}


CYASSL_API void CyaSSL_SetIOWriteCtx(CYASSL* ssl, void *wctx)
{
	ssl->IOCB_WriteCtx = wctx;
}

