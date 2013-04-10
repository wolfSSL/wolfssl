/* io.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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

#include <cyassl/ctaocrypt/settings.h>

#ifdef _WIN32_WCE
    /* On WinCE winsock2.h must be included before windows.h for socket stuff */
    #include <winsock2.h>
#endif

#include <cyassl/internal.h>
#include <cyassl/error.h>

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
        #include <errno.h>
        #ifndef LWIP_PROVIDE_ERRNO
            #define LWIP_PROVIDE_ERRNO 1
        #endif
    #elif defined(FREESCALE_MQX)
        #include <posix.h>
        #include <rtcs.h>
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
    #define SOCKET_EAGAIN      WSAETIMEDOUT
    #define SOCKET_ECONNRESET  WSAECONNRESET
    #define SOCKET_EINTR       WSAEINTR
    #define SOCKET_EPIPE       WSAEPIPE
    #define SOCKET_ECONNREFUSED WSAENOTCONN
    #define SOCKET_ECONNABORTED WSAECONNABORTED
#elif defined(__PPU)
    #define SOCKET_EWOULDBLOCK SYS_NET_EWOULDBLOCK
    #define SOCKET_EAGAIN      SYS_NET_EAGAIN
    #define SOCKET_ECONNRESET  SYS_NET_ECONNRESET
    #define SOCKET_EINTR       SYS_NET_EINTR
    #define SOCKET_EPIPE       SYS_NET_EPIPE
    #define SOCKET_ECONNREFUSED SYS_NET_ECONNREFUSED
    #define SOCKET_ECONNABORTED SYS_NET_ECONNABORTED
#elif defined(FREESCALE_MQX)
    /* RTCS doesn't have an EWOULDBLOCK error */
    #define SOCKET_EWOULDBLOCK EAGAIN
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  RTCSERR_TCP_CONN_RESET
    #define SOCKET_EINTR       EINTR
    #define SOCKET_EPIPE       EPIPE
    #define SOCKET_ECONNREFUSED RTCSERR_TCP_CONN_REFUSED
    #define SOCKET_ECONNABORTED RTCSERR_TCP_CONN_ABORTED
#else
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_EAGAIN      EAGAIN
    #define SOCKET_ECONNRESET  ECONNRESET
    #define SOCKET_EINTR       EINTR
    #define SOCKET_EPIPE       EPIPE
    #define SOCKET_ECONNREFUSED ECONNREFUSED
    #define SOCKET_ECONNABORTED ECONNABORTED
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


/* Translates return codes returned from 
 * send() and recv() if need be. 
 */
static INLINE int TranslateReturnCode(int old, int sd)
{
    (void)sd;

#ifdef FREESCALE_MQX
    if (old == 0) {
        errno = SOCKET_EWOULDBLOCK;
        return -1;  /* convert to BSD style wouldblock as error */
    }

    if (old < 0) {
        errno = RTCS_geterror(sd);
        if (errno == RTCSERR_TCP_CONN_CLOSING)
            return 0;   /* convert to BSD style closing */
    }
#endif

    return old;
}

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
    {
        int dtls_timeout = CyaSSL_dtls_get_current_timeout(ssl);
        if (CyaSSL_dtls(ssl)
                     && !CyaSSL_get_using_nonblock(ssl)
                     && dtls_timeout != 0) {
            #ifdef USE_WINDOWS_API
                DWORD timeout = dtls_timeout * 1000;
            #else
                struct timeval timeout;
                XMEMSET(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = dtls_timeout;
            #endif
            if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                           sizeof(timeout)) != 0) {
                CYASSL_MSG("setsockopt rcvtimeo failed");
            }
        }
    }
#endif

    recvd = (int)RECV_FUNCTION(sd, buf, sz, ssl->rflags);

    recvd = TranslateReturnCode(recvd, sd);

    if (recvd < 0) {
        err = LastError();
        CYASSL_MSG("Embed Receive error");

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            if (!CyaSSL_dtls(ssl) || CyaSSL_get_using_nonblock(ssl)) {
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
        else if (err == SOCKET_ECONNREFUSED) {
            CYASSL_MSG("    Connection refused");
            return IO_ERR_WANT_READ;
        }
        else if (err == SOCKET_ECONNABORTED) {
            CYASSL_MSG("    Connection aborted");
            return IO_ERR_CONN_CLOSE;
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

    sent = (int)SEND_FUNCTION(sd, &buf[sz - len], len, ssl->wflags);

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

#define SENDTO_FUNCTION sendto
#define RECVFROM_FUNCTION recvfrom


/* The receive embedded callback
 *  return : nb bytes read, or error
 */
int EmbedReceiveFrom(CYASSL *ssl, char *buf, int sz, void *ctx)
{
    CYASSL_DTLS_CTX* dtlsCtx = (CYASSL_DTLS_CTX*)ctx;
    int recvd;
    int err;
    int sd = dtlsCtx->fd;
    int dtls_timeout = CyaSSL_dtls_get_current_timeout(ssl);
    struct sockaddr_in peer;
    XSOCKLENT peerSz = sizeof(peer);

    CYASSL_ENTER("EmbedReceiveFrom()");

    if (!CyaSSL_get_using_nonblock(ssl) && dtls_timeout != 0) {
        #ifdef USE_WINDOWS_API
            DWORD timeout = dtls_timeout * 1000;
        #else
            struct timeval timeout;
            XMEMSET(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = dtls_timeout;
        #endif
        if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                       sizeof(timeout)) != 0) {
                CYASSL_MSG("setsockopt rcvtimeo failed");
        }
    }

    recvd = (int)RECVFROM_FUNCTION(sd, buf, sz, ssl->rflags,
                                  (struct sockaddr*)&peer, &peerSz);

    recvd = TranslateReturnCode(recvd, sd);

    if (recvd < 0) {
        err = LastError();
        CYASSL_MSG("Embed Receive From error");

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            if (CyaSSL_get_using_nonblock(ssl)) {
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
        else if (err == SOCKET_ECONNREFUSED) {
            CYASSL_MSG("    Connection refused");
            return IO_ERR_WANT_READ;
        }
        else {
            CYASSL_MSG("    General error");
            return IO_ERR_GENERAL;
        }
    }
    else {
        if (dtlsCtx->peer.sz > 0
                && peerSz != (XSOCKLENT)dtlsCtx->peer.sz
                && memcmp(&peer, dtlsCtx->peer.sa, peerSz) != 0) {
            CYASSL_MSG("    Ignored packet from invalid peer");
            return IO_ERR_WANT_READ;
        }
    }

    return recvd;
}


/* The send embedded callback
 *  return : nb bytes sent, or error
 */
int EmbedSendTo(CYASSL* ssl, char *buf, int sz, void *ctx)
{
    CYASSL_DTLS_CTX* dtlsCtx = (CYASSL_DTLS_CTX*)ctx;
    int sd = dtlsCtx->fd;
    int sent;
    int len = sz;
    int err;

    CYASSL_ENTER("EmbedSendTo()");

    sent = (int)SENDTO_FUNCTION(sd, &buf[sz - len], len, ssl->wflags,
                                dtlsCtx->peer.sa, dtlsCtx->peer.sz);
    if (sent < 0) {
        err = LastError();
        CYASSL_MSG("Embed Send To error");

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


/* The DTLS Generate Cookie callback
 *  return : number of bytes copied into buf, or error
 */
int EmbedGenerateCookie(CYASSL* ssl, byte *buf, int sz, void *ctx)
{
    int sd = ssl->wfd;
    struct sockaddr_in peer;
    XSOCKLENT peerSz = sizeof(peer);
    byte cookieSrc[sizeof(struct in_addr) + sizeof(int)];
    int cookieSrcSz = 0;
    Sha sha;

    (void)ctx;

    if (getpeername(sd, (struct sockaddr*)&peer, &peerSz) != 0) {
        CYASSL_MSG("getpeername failed in EmbedGenerateCookie");
        return GEN_COOKIE_E;
    }
    
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

#ifdef HAVE_OCSP

#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET6
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET
#endif


static INLINE int tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port)
{
    SOCKADDR_IN_T addr;
    const char* host = ip;

    /* peer could be in human readable form */
    if (ip != INADDR_ANY && isalpha(ip[0])) {
        struct hostent* entry = gethostbyname(ip);

        if (entry) {
            struct sockaddr_in tmp;
            XMEMSET(&tmp, 0, sizeof(struct sockaddr_in));
            XMEMCPY(&tmp.sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            host = inet_ntoa(tmp.sin_addr);
        }
        else {
            CYASSL_MSG("no addr entry for OCSP responder");
            return -1;
        }
    }

    *sockfd = socket(AF_INET_V, SOCK_STREAM, 0);
    if (*sockfd < 0) {
        CYASSL_MSG("bad socket fd, out of fds?");
        return -1;
    }
    XMEMSET(&addr, 0, sizeof(SOCKADDR_IN_T));

    addr.sin_family = AF_INET_V;
    addr.sin_port = htons(port);
    if (host == INADDR_ANY)
        addr.sin_addr.s_addr = INADDR_ANY;
    else
        addr.sin_addr.s_addr = inet_addr(host);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0) {
        CYASSL_MSG("OCSP responder tcp connect failed");
        return -1;
    }

    return 0;
}


static int build_http_request(const char* domainName, const char* path,
                                    int ocspReqSz, byte* buf, int bufSize)
{
    return snprintf((char*)buf, bufSize,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "\r\n", 
        path, domainName, ocspReqSz);
}


static int decode_http_response(byte* httpBuf, int httpBufSz, byte** dst)
{
    int idx = 0;
    int stop = 0;
    int len = 0;
    byte* contentType = NULL;
    byte* contentLength = NULL;
    char* buf = (char*)httpBuf; /* kludge so I'm not constantly casting */

    if (XSTRNCASECMP(buf, "HTTP/1", 6) != 0)
        return 0;
    
    idx = 9; /* sets to the first byte after "HTTP/1.X ", which should be the
              * HTTP result code */

     if (XSTRNCASECMP(&buf[idx], "200 OK", 6) != 0)
        return 0;
    
    idx += 8;

    while (idx < httpBufSz && !stop) {
        if (buf[idx] == '\r' && buf[idx+1] == '\n') {
            stop = 1;
            idx += 2;
        }
        else {
            if (contentType == NULL &&
                           XSTRNCASECMP(&buf[idx], "Content-Type:", 13) == 0) {
                idx += 13;
                if (buf[idx] == ' ') idx++;
                if (XSTRNCASECMP(&buf[idx],
                                       "application/ocsp-response", 25) != 0) {
                    return 0;
                }
                idx += 27;
            }
            else if (contentLength == NULL &&
                         XSTRNCASECMP(&buf[idx], "Content-Length:", 15) == 0) {
                idx += 15;
                if (buf[idx] == ' ') idx++;
                while (buf[idx] >= '0' && buf[idx] <= '9' && idx < httpBufSz) {
                    len = (len * 10) + (buf[idx] - '0');
                    idx++;
                }
                idx += 2; /* skip the crlf */
            }
            else {
                /* Advance idx past the next \r\n */
                char* end = XSTRSTR(&buf[idx], "\r\n");
                idx = (int)(end - buf + 2);
                stop = 1;
            }
        }
    }
    
    if (len > 0) {
        *dst = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_IN_BUFFER);
        XMEMCPY(*dst, httpBuf + idx, len);
    }

    return len;
}


static int decode_url(const char* url, int urlSz,
    char* outName, char* outPath, int* outPort)
{
    if (outName != NULL && outPath != NULL && outPort != NULL)
    {
        if (url == NULL || urlSz == 0)
        {
            *outName = 0;
            *outPath = 0;
            *outPort = 0;
        }
        else
        {
            int i, cur;
    
            /* need to break the url down into scheme, address, and port */
            /* "http://example.com:8080/" */
            if (XSTRNCMP(url, "http://", 7) == 0) {
                cur = 7;
            } else cur = 0;
    
            i = 0;
            while (url[cur] != 0 && url[cur] != ':' && url[cur] != '/') {
                outName[i++] = url[cur++];
            }
            outName[i] = 0;
            /* Need to pick out the path after the domain name */
    
            if (cur < urlSz && url[cur] == ':') {
                char port[6];
                int j;
                i = 0;
                cur++;
                while (cur < urlSz && url[cur] != 0 && url[cur] != '/' &&
                        i < 6) {
                    port[i++] = url[cur++];
                }
    
                *outPort = 0;
                for (j = 0; j < i; j++) {
                    if (port[j] < '0' || port[j] > '9') return -1;
                    *outPort = (*outPort * 10) + (port[j] - '0');
                }
            }
            else
                *outPort = 80;
    
            if (cur < urlSz && url[cur] == '/') {
                i = 0;
                while (cur < urlSz && url[cur] != 0 && i < 80) {
                    outPath[i++] = url[cur++];
                }
                outPath[i] = 0;
            }
            else {
                outPath[0] = '/';
                outPath[1] = 0;
            }
        }
    }

    return 0;
}


#define SCRATCH_BUFFER_SIZE 2048

int EmbedOcspLookup(void* ctx, const char* url, int urlSz,
                        byte* ocspReqBuf, int ocspReqSz, byte** ocspRespBuf)
{
    char domainName[80], path[80];
    int port, httpBufSz, sfd = -1;
    int ocspRespSz = 0;
    byte* httpBuf = NULL;

    (void)ctx;

    if (ocspReqBuf == NULL || ocspReqSz == 0) {
        CYASSL_MSG("OCSP request is required for lookup");
        return -1;
    }

    if (ocspRespBuf == NULL) {
        CYASSL_MSG("Cannot save OCSP response");
        return -1;
    }

    if (decode_url(url, urlSz, domainName, path, &port) < 0) {
        CYASSL_MSG("Unable to decode OCSP URL");
        return -1;
    }
    
    httpBufSz = SCRATCH_BUFFER_SIZE;
    httpBuf = (byte*)XMALLOC(httpBufSz, NULL, DYNAMIC_TYPE_IN_BUFFER);

    if (httpBuf == NULL) {
        CYASSL_MSG("Unable to create OCSP response buffer");
        return -1;
    }
    *ocspRespBuf = httpBuf;

    httpBufSz = build_http_request(domainName, path, ocspReqSz,
                                                        httpBuf, httpBufSz);

    if ((tcp_connect(&sfd, domainName, port) == 0) && (sfd > 0)) {
        int written;
        written = (int)write(sfd, httpBuf, httpBufSz);
        if (written == httpBufSz) {
            written = (int)write(sfd, ocspReqBuf, ocspReqSz);
            if (written == ocspReqSz) {
                httpBufSz = (int)read(sfd, httpBuf, SCRATCH_BUFFER_SIZE);
                if (httpBufSz > 0) {
                    ocspRespSz = decode_http_response(httpBuf, httpBufSz,
                        ocspRespBuf);
                }
            }
        }
        close(sfd);
        if (ocspRespSz == 0) {
            CYASSL_MSG("OCSP response was not OK, no OCSP response");
            return -1;
        }
    } else {
        CYASSL_MSG("OCSP Responder connection failed");
        close(sfd);
        return -1;
    }

    return ocspRespSz;
}


void EmbedOcspRespFree(void* ctx, byte *resp)
{
    (void)ctx;

    if (resp)
        XFREE(resp, NULL, DYNAMIC_TYPE_IN_BUFFER);
}


#endif

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


CYASSL_API void CyaSSL_SetIOReadFlags(CYASSL* ssl, int flags)
{
    ssl->rflags = flags; 
}


CYASSL_API void CyaSSL_SetIOWriteFlags(CYASSL* ssl, int flags)
{
    ssl->wflags = flags;
}


#ifdef CYASSL_DTLS

CYASSL_API void CyaSSL_CTX_SetGenCookie(CYASSL_CTX* ctx, CallbackGenCookie cb)
{
    ctx->CBIOCookie = cb;
}


CYASSL_API void CyaSSL_SetCookieCtx(CYASSL* ssl, void *ctx)
{
	ssl->IOCB_CookieCtx = ctx;
}

#endif /* CYASSL_DTLS */


#ifdef HAVE_OCSP

CYASSL_API void CyaSSL_SetIOOcsp(CYASSL_CTX* ctx, CallbackIOOcsp cb)
{
    ctx->ocsp.CBIOOcsp = cb;
}

CYASSL_API void CyaSSL_SetIOOcspRespFree(CYASSL_CTX* ctx,
                                                     CallbackIOOcspRespFree cb)
{
    ctx->ocsp.CBIOOcspRespFree = cb;
}

CYASSL_API void CyaSSL_SetIOOcspCtx(CYASSL_CTX* ctx, void *octx)
{
    ctx->ocsp.IOCB_OcspCtx = octx;
}

#endif
