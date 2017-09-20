/* io.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file io.h
*/

#ifndef WOLFSSL_IO_H
#define WOLFSSL_IO_H

#ifdef __cplusplus
    extern "C" {
#endif

/* OCSP and CRL_IO require HTTP client */
#if defined(HAVE_OCSP) || defined(HAVE_CRL_IO)
    #ifndef HAVE_HTTP_CLIENT
        #define HAVE_HTTP_CLIENT
    #endif
#endif

#if !defined(WOLFSSL_USER_IO)
    /* Micrium uses NetSock I/O callbacks in io.c */
    #if !defined(USE_WOLFSSL_IO) && !defined(MICRIUM)
        #define USE_WOLFSSL_IO
    #endif
#endif


#if defined(USE_WOLFSSL_IO) || defined(HAVE_HTTP_CLIENT)

#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifndef USE_WINDOWS_API
    #ifdef WOLFSSL_LWIP
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
    #elif defined(FREESCALE_KSDK_MQX)
        #include <rtcs.h>
    #elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        #if !defined(WOLFSSL_MDK_ARM)
            #include "cmsis_os.h"
            #include "rl_net.h"
        #else
            #include <rtl.h>
        #endif
        #include "errno.h"
        #define SOCKET_T int
    #elif defined(WOLFSSL_TIRTOS)
        #include <sys/socket.h>
    #elif defined(FREERTOS_TCP)
        #include "FreeRTOS_Sockets.h"
    #elif defined(WOLFSSL_IAR_ARM)
        /* nothing */
    #elif defined(WOLFSSL_VXWORKS)
        #include <sockLib.h>
        #include <errno.h>
    #elif defined(WOLFSSL_ATMEL)
        #include "socket/include/socket.h"
    #elif defined(INTIME_RTOS)
        #undef MIN
        #undef MAX
        #include <rt.h>
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netdb.h>
        #include <netinet/in.h>
        #include <io.h>
        /* <sys/socket.h> defines these, to avoid conflict, do undef */
        #undef SOCKADDR
        #undef SOCKADDR_IN
    #elif defined(WOLFSSL_PRCONNECT_PRO)
        #include <prconnect_pro/prconnect_pro.h>
        #include <sys/types.h>
        #include <errno.h>
        #include <unistd.h>
        #include <fcntl.h>
        #include <netdb.h>
        #include <sys/ioctl.h>
    #elif defined(WOLFSSL_SGX)
        #include <errno.h>
    #elif !defined(WOLFSSL_NO_SOCK)
        #include <sys/types.h>
        #include <errno.h>
        #ifndef EBSNET
            #include <unistd.h>
        #endif
        #include <fcntl.h>

        #if defined(HAVE_RTP_SYS)
            #include <socket.h>
        #elif defined(EBSNET)
            #include "rtipapi.h"  /* errno */
            #include "socket.h"
        #elif !defined(DEVKITPRO) && !defined(WOLFSSL_PICOTCP)
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
    #define close(s) closesocket(s)
#elif defined(__PPU)
    #define SOCKET_EWOULDBLOCK SYS_NET_EWOULDBLOCK
    #define SOCKET_EAGAIN      SYS_NET_EAGAIN
    #define SOCKET_ECONNRESET  SYS_NET_ECONNRESET
    #define SOCKET_EINTR       SYS_NET_EINTR
    #define SOCKET_EPIPE       SYS_NET_EPIPE
    #define SOCKET_ECONNREFUSED SYS_NET_ECONNREFUSED
    #define SOCKET_ECONNABORTED SYS_NET_ECONNABORTED
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #if MQX_USE_IO_OLD
        /* RTCS old I/O doesn't have an EWOULDBLOCK */
        #define SOCKET_EWOULDBLOCK  EAGAIN
        #define SOCKET_EAGAIN       EAGAIN
        #define SOCKET_ECONNRESET   RTCSERR_TCP_CONN_RESET
        #define SOCKET_EINTR        EINTR
        #define SOCKET_EPIPE        EPIPE
        #define SOCKET_ECONNREFUSED RTCSERR_TCP_CONN_REFUSED
        #define SOCKET_ECONNABORTED RTCSERR_TCP_CONN_ABORTED
    #else
        #define SOCKET_EWOULDBLOCK  NIO_EWOULDBLOCK
        #define SOCKET_EAGAIN       NIO_EAGAIN
        #define SOCKET_ECONNRESET   NIO_ECONNRESET
        #define SOCKET_EINTR        NIO_EINTR
        #define SOCKET_EPIPE        NIO_EPIPE
        #define SOCKET_ECONNREFUSED NIO_ECONNREFUSED
        #define SOCKET_ECONNABORTED NIO_ECONNABORTED
    #endif
#elif defined(WOLFSSL_MDK_ARM)|| defined(WOLFSSL_KEIL_TCP_NET)
    #if !defined(WOLFSSL_MDK_ARM)
        #define SOCKET_EWOULDBLOCK BSD_ERROR_WOULDBLOCK
        #define SOCKET_EAGAIN      BSD_ERROR_LOCKED
        #define SOCKET_ECONNRESET  BSD_ERROR_CLOSED
        #define SOCKET_EINTR       BSD_ERROR
        #define SOCKET_EPIPE       BSD_ERROR
        #define SOCKET_ECONNREFUSED BSD_ERROR
        #define SOCKET_ECONNABORTED BSD_ERROR
    #else
        #define SOCKET_EWOULDBLOCK SCK_EWOULDBLOCK
        #define SOCKET_EAGAIN      SCK_ELOCKED
        #define SOCKET_ECONNRESET  SCK_ECLOSED
        #define SOCKET_EINTR       SCK_ERROR
        #define SOCKET_EPIPE       SCK_ERROR
        #define SOCKET_ECONNREFUSED SCK_ERROR
        #define SOCKET_ECONNABORTED SCK_ERROR
    #endif
#elif defined(WOLFSSL_PICOTCP)
    #define SOCKET_EWOULDBLOCK  PICO_ERR_EAGAIN
    #define SOCKET_EAGAIN       PICO_ERR_EAGAIN
    #define SOCKET_ECONNRESET   PICO_ERR_ECONNRESET
    #define SOCKET_EINTR        PICO_ERR_EINTR
    #define SOCKET_EPIPE        PICO_ERR_EIO
    #define SOCKET_ECONNREFUSED PICO_ERR_ECONNREFUSED
    #define SOCKET_ECONNABORTED PICO_ERR_ESHUTDOWN
#elif defined(FREERTOS_TCP)
    #define SOCKET_EWOULDBLOCK FREERTOS_EWOULDBLOCK
    #define SOCKET_EAGAIN       FREERTOS_EWOULDBLOCK
    #define SOCKET_ECONNRESET   FREERTOS_SOCKET_ERROR
    #define SOCKET_EINTR        FREERTOS_SOCKET_ERROR
    #define SOCKET_EPIPE        FREERTOS_SOCKET_ERROR
    #define SOCKET_ECONNREFUSED FREERTOS_SOCKET_ERROR
    #define SOCKET_ECONNABORTED FREERTOS_SOCKET_ERROR
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
#elif defined(WOLFSSL_LWIP)
    #define SEND_FUNCTION lwip_send
    #define RECV_FUNCTION lwip_recv
#elif defined(WOLFSSL_PICOTCP)
    #define SEND_FUNCTION pico_send
    #define RECV_FUNCTION pico_recv
#elif defined(FREERTOS_TCP)
    #define RECV_FUNCTION(a,b,c,d)  FreeRTOS_recv((Socket_t)(a),(void*)(b), (size_t)(c), (BaseType_t)(d))
    #define SEND_FUNCTION(a,b,c,d)  FreeRTOS_send((Socket_t)(a),(void*)(b), (size_t)(c), (BaseType_t)(d))
#else
    #define SEND_FUNCTION send
    #define RECV_FUNCTION recv
    #if !defined(HAVE_SOCKADDR) && !defined(WOLFSSL_NO_SOCK)
        #define HAVE_SOCKADDR
    #endif
#endif

#ifdef USE_WINDOWS_API
    typedef unsigned int SOCKET_T;
#else
    typedef int SOCKET_T;
#endif

#ifndef WOLFSSL_NO_SOCK
    #ifndef XSOCKLENT
        #ifdef USE_WINDOWS_API
            #define XSOCKLENT int
        #else
            #define XSOCKLENT socklen_t
        #endif
    #endif

    /* Socket Addr Support */
    #ifdef HAVE_SOCKADDR
        typedef struct sockaddr         SOCKADDR;
        typedef struct sockaddr_storage SOCKADDR_S;
        typedef struct sockaddr_in      SOCKADDR_IN;
        #ifdef WOLFSSL_IPV6
            typedef struct sockaddr_in6 SOCKADDR_IN6;
        #endif
        typedef struct hostent          HOSTENT;
    #endif /* HAVE_SOCKADDR */

    #ifdef HAVE_GETADDRINFO
        typedef struct addrinfo         ADDRINFO;
    #endif
#endif /* WOLFSSL_NO_SOCK */


/* IO API's */
#ifdef HAVE_IO_TIMEOUT
    WOLFSSL_API  int wolfIO_SetBlockingMode(SOCKET_T sockfd, int non_blocking);
    WOLFSSL_API void wolfIO_SetTimeout(int to_sec);;
    WOLFSSL_API  int wolfIO_Select(SOCKET_T sockfd, int to_sec);
#endif
WOLFSSL_API  int wolfIO_TcpConnect(SOCKET_T* sockfd, const char* ip,
    unsigned short port, int to_sec);
WOLFSSL_API  int wolfIO_Send(SOCKET_T sd, char *buf, int sz, int wrFlags);
WOLFSSL_API  int wolfIO_Recv(SOCKET_T sd, char *buf, int sz, int rdFlags);

#endif /* USE_WOLFSSL_IO || HAVE_HTTP_CLIENT */


#if defined(USE_WOLFSSL_IO)
    /* default IO callbacks */
/*!
    \ingroup wolfssl

    \brief This function is the receive embedded callback.
    
    \return Success This function returns the number of bytes read.
    \return WOLFSSL_CBIO_ERR_WANT_READ returned with a “Would block” message if the last error was SOCKET_EWOULDBLCOK or SOCKET_EAGAIN.
    \return WOLFSSL_CBIO_ERR_TIMEOUT returned with a “Socket timeout” message.
    \return WOLFSSL_CBIO_ERR_CONN_RST returned with a “Connection reset” message if the last error was  SOCKET_ECONNRESET.
    \return WOLFSSL_CBIO_ERR_ISR returned with a “Socket interrupted” message if the last error was SOCKET_EINTR.
    \return WOLFSSL_CBIO_ERR_WANT_READ returned with a “Connection refused” messag if the last error was SOCKET_ECONNREFUSED.
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE returned with a “Connection aborted” message if the last error was SOCKET_ECONNABORTED.
    \return WOLFSSL_CBIO_ERR_GENERAL returned with a “General error” message if the last error was not specified.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a char pointer representation of the buffer.
    \param sz the size of the buffer.
    \param ctx a void pointer to user registered context. In the default case the ctx is a socket descriptor pointer.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* buf;
    int sz;
    void* ctx;
    int bytesRead = EmbedReceive(ssl, buf, sz, ctx);
    if(bytesRead <= 0){
	    // There were no bytes read. Failure case.
    }
    \endcode
    
    \sa wolfSSL_dtls_get_current_timeout
    \sa TranslateReturnCode
    \sa RECV_FUNCTION
*/
    WOLFSSL_API int EmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
/*!
    \ingroup wolfssl

    \brief This function is the send embedded callback.
    
    \return Success This function returns the number of bytes sent.
    \return WOLFSSL_CBIO_ERR_WANT_WRITE returned with a “Would block” message if the last error was SOCKET_EWOULDBLOCK or SOCKET_EAGAIN.
    \return WOLFSSL_CBIO_ERR_CONN_RST returned with a “Connection reset” message if the last error was SOCKET_ECONNRESET.
    \return WOLFSSL_CBIO_ERR_ISR returned with a “Socket interrupted” message if the last error was SOCKET_EINTR.
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE returned with a “Socket EPIPE” message if the last error was SOCKET_EPIPE.
    \return WOLFSSL_CBIO_ERR_GENERAL returned with a “General error” message if the last error was not specified.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a char pointer representing the buffer.
    \param sz the size of the buffer.
    \param ctx a void pointer to user registered context.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* buf;
    int sz;
    void* ctx;  
    int dSent = EmbedSend(ssl, buf, sz, ctx);
    if(dSent <= 0){
    	// No byes sent. Failure case.
    }
    \endcode
    
    \sa TranslateReturnCode
    \sa SEND_FUNCTION
    \sa LastError
    \sa InitSSL_Ctx
    \sa LastError
*/
    WOLFSSL_API int EmbedSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);

    #ifdef WOLFSSL_DTLS
/*!
    \ingroup wolfssl

    \brief This function is the receive embedded callback.
    
    \return Success This function returns the nb bytes read if the execution was successful.
    \return WOLFSSL_CBIO_ERR_WANT_READ if the connection refused or if a ‘would block’ error was thrown in the function.
    \return WOLFSSL_CBIO_ERR_TIMEOUT returned if the socket timed out.
    \return WOLFSSL_CBIO_ERR_CONN_RST returned if the connection reset.
    \return WOLFSSL_CBIO_ERR_ISR returned if the socket was interrupted.
    \return WOLFSSL_CBIO_ERR_GENERAL returned if there was a general error.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a constant char pointer to the buffer.
    \param sz an int type representing the size of the buffer.
    \param ctx a void pointer to the WOLFSSL_CTX context.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    char* buf;
    int sz = sizeof(buf)/sizeof(char);
    (void*)ctx;
    …
    int nb = EmbedReceiveFrom(ssl, buf, sz, ctx);
    if(nb > 0){
	    // nb is the number of bytes written and is positive
    }
    \endcode
    
    \sa TranslateReturnCode
    \sa RECVFROM_FUNCTION
    \sa Setsockopt
*/
        WOLFSSL_API int EmbedReceiveFrom(WOLFSSL* ssl, char* buf, int sz, void*);
/*!
    \ingroup wolfssl

    \brief This function is the send embedded callback.
    
    \return Success This function returns the number of bytes sent.
    \return WOLFSSL_CBIO_ERR_WANT_WRITE returned with a “Would Block” message if the last error was either SOCKET_EWOULDBLOCK or SOCKET_EAGAIN error.
    \return WOLFSSL_CBIO_ERR_CONN_RST returned with a “Connection reset” message if the last error was SOCKET_ECONNRESET.
    \return WOLFSSL_CBIO_ERR_ISR returned with a “Socket interrupted” message if the last error was SOCKET_EINTR.
    \return WOLFSSL_CBIO_ERR_CONN_CLOSE returned with a “Socket EPIPE” message if the last error was WOLFSSL_CBIO_ERR_CONN_CLOSE.
    \return WOLFSSL_CBIO_ERR_GENERAL returned with a “General error” message if the last error was not specified.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a char pointer representing the buffer.
    \param sz the size of the buffer.
    \param ctx a void pointer to the user registered context. The default case is a WOLFSSL_DTLS_CTX sructure.
    
    _Example_
    \code
    WOLFSSL* ssl;
    …
    char* buf;
    int sz;
    void* ctx;

    int sEmbed = EmbedSendto(ssl, buf, sz, ctx);
    if(sEmbed <= 0){
    	// No bytes sent. Failure case.
    }
    \endcode
    
    \sa LastError
    \sa EmbedSend
    \sa EmbedReceive
*/
        WOLFSSL_API int EmbedSendTo(WOLFSSL* ssl, char* buf, int sz, void* ctx);
/*!
    \ingroup wolfssl

    \brief This function is the DTLS Generate Cookie callback.
    
    \return Success This function returns the number of bytes copied into the buffer.
    \return GEN_COOKIE_E returned if the getpeername failed in EmbedGenerateCookie.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf byte pointer representing the buffer. It is the destination from XMEMCPY().
    \param sz the size of the buffer.
    \param ctx a void pointer to user registered context.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte buffer[BUFFER_SIZE];
    int sz = sizeof(buffer)/sizeof(byte);
    void* ctx;
    …
    int ret = EmbedGenerateCookie(ssl, buffer, sz, ctx);

    if(ret > 0){
    	// EmbedGenerateCookie code block for success
    }
    \endcode
    
    \sa wc_ShaHash
    \sa EmbedGenerateCookie
    \sa XMEMCPY
    \sa XMEMSET
*/
        WOLFSSL_API int EmbedGenerateCookie(WOLFSSL* ssl, unsigned char* buf,
                                           int sz, void*);
        #ifdef WOLFSSL_SESSION_EXPORT
            WOLFSSL_API int EmbedGetPeer(WOLFSSL* ssl, char* ip, int* ipSz,
                                                unsigned short* port, int* fam);
            WOLFSSL_API int EmbedSetPeer(WOLFSSL* ssl, char* ip, int ipSz,
                                                  unsigned short port, int fam);
        #endif /* WOLFSSL_SESSION_EXPORT */
    #endif /* WOLFSSL_DTLS */
#endif /* USE_WOLFSSL_IO */

#ifdef HAVE_OCSP
    WOLFSSL_API int wolfIO_HttpBuildRequestOcsp(const char* domainName,
        const char* path, int ocspReqSz, unsigned char* buf, int bufSize);
    WOLFSSL_API int wolfIO_HttpProcessResponseOcsp(int sfd,
        unsigned char** respBuf, unsigned char* httpBuf, int httpBufSz,
        void* heap);

    WOLFSSL_API int EmbedOcspLookup(void*, const char*, int, unsigned char*,
                                   int, unsigned char**);
/*!
    \ingroup wolfssl

    \brief This function frees the response buffer.
    
    \return none No returns.
    
    \param ctx a void pointer to heap hint.
    \param resp a byte pointer representing the response.
    
    _Example_
    \code
    void* ctx;
    byte* resp; // Response buffer.
    …
    EmbedOcspRespFree(ctx, resp);
    \endcode
    
    \sa XFREE
*/
    WOLFSSL_API void EmbedOcspRespFree(void*, unsigned char*);
#endif

#ifdef HAVE_CRL_IO
    WOLFSSL_API int wolfIO_HttpBuildRequestCrl(const char* url, int urlSz,
        const char* domainName, unsigned char* buf, int bufSize);
    WOLFSSL_API int wolfIO_HttpProcessResponseCrl(WOLFSSL_CRL* crl, int sfd,
        unsigned char* httpBuf, int httpBufSz);

    WOLFSSL_API int EmbedCrlLookup(WOLFSSL_CRL* crl, const char* url,
        int urlSz);
#endif


#if defined(HAVE_HTTP_CLIENT)
    WOLFSSL_API  int wolfIO_DecodeUrl(const char* url, int urlSz, char* outName,
        char* outPath, unsigned short* outPort);

    WOLFSSL_API  int wolfIO_HttpBuildRequest(const char* reqType,
        const char* domainName, const char* path, int pathLen, int reqSz,
        const char* contentType, unsigned char* buf, int bufSize);
    WOLFSSL_API  int wolfIO_HttpProcessResponse(int sfd, const char* appStr,
        unsigned char** respBuf, unsigned char* httpBuf, int httpBufSz,
        int dynType, void* heap);
#endif /* HAVE_HTTP_CLIENT */


/* I/O callbacks */
typedef int (*CallbackIORecv)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
/*!
    \ingroup wolfssl

    \brief This function registers a receive callback for wolfSSL to get input data.  By default, wolfSSL uses EmbedReceive() as the callback which uses the system’s TCP recv() function.  The user can register a function to get input from memory, some other network module, or from anywhere.  Please see the EmbedReceive() function in src/io.c as a guide for how the function should work and for error codes.  In particular, IO_ERR_WANT_READ should be returned for non blocking receive when no data is ready.
    
    \return none no Returns.
    
    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param callback function to be registered as the receive callback for the wolfSSL context, ctx. The signature of this function must follow that as shown above in the Synopsis section.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    // Receive callback prototype
    int MyEmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
    // Register the custom receive callback with wolfSSL
    wolfSSL_SetIORecv(ctx, MyEmbedReceive);
    int MyEmbedReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx)                   
    {
	// custom EmbedReceive function
    }
    \endcode
    
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
WOLFSSL_API void wolfSSL_SetIORecv(WOLFSSL_CTX*, CallbackIORecv);
WOLFSSL_API void wolfSSL_SetIOSend(WOLFSSL_CTX*, CallbackIOSend);

/*!
    \ingroup wolfssl

    \brief This function registers a context for the SSL session’s receive callback function.  By default, wolfSSL sets the file descriptor passed to wolfSSL_set_fd() as the context when wolfSSL is using the system’s TCP library.  If you’ve registered your own receive callback you may want to set a specific context for the session.  For example, if you’re using memory buffers the context may be a pointer to a structure describing where and how to access the memory buffers.
    
    \return none No returns.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param rctx pointer to the context to be registered with the SSL session’s (ssl) receive callback function.
    
    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    // Manually setting the socket fd as the receive CTX, for example
    wolfSSL_SetIOReadCtx(ssl, &sockfd);
    ...
    \endcode
    
    \sa wolfSSL_SetIORecv
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIOWriteCtx
*/
WOLFSSL_API void wolfSSL_SetIOReadCtx( WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief This function registers a context for the SSL session’s send callback function.  By default, wolfSSL sets the file descriptor passed to wolfSSL_set_fd() as the context when wolfSSL is using the system’s TCP library.  If you’ve registered your own send callback you may want to set a specific context for the session.  For example, if you’re using memory buffers the context may be a pointer to a structure describing where and how to access the memory buffers.
    
    \return none No returns.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param wctx pointer to the context to be registered with the SSL session’s (ssl) send callback function.
    
    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    // Manually setting the socket fd as the send CTX, for example
    wolfSSL_SetIOSendCtx(ssl, &sockfd);
    ...
    \endcode
    
    \sa wolfSSL_SetIORecv
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
WOLFSSL_API void wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup wolfssl

    \brief This function returns the IOCB_ReadCtx member of the WOLFSSL struct.
    
    \return pointer This function returns a void pointer to the IOCB_ReadCtx member of the WOLFSSL structure.
    \return NULL returned if the WOLFSSL struct is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* ioRead;
    ...
    ioRead = wolfSSL_GetIOReadCtx(ssl);
    if(ioRead == NULL){
    	// Failure case. The ssl object was NULL.
    }
    \endcode
    
    \sa wolfSSL_GetIOWriteCtx
    \sa wolfSSL_SetIOReadFlags
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOSend
*/
WOLFSSL_API void* wolfSSL_GetIOReadCtx( WOLFSSL* ssl);
/*!
    \ingroup wolfssl

    \brief This function returns the IOCB_WriteCtx member of the WOLFSSL structure.
    
    \return pointer This function returns a void pointer to the IOCB_WriteCtx member of the WOLFSSL structure.
    \return NULL returned if the WOLFSSL struct is NULL.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL* ssl;
    void* ioWrite;
    ...
    ioWrite = wolfSSL_GetIOWriteCtx(ssl);
    if(ioWrite == NULL){
    	// The funciton returned NULL.
    }
    \endcode
    
    \sa wolfSSL_GetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOSend
*/
WOLFSSL_API void* wolfSSL_GetIOWriteCtx(WOLFSSL* ssl);

/*!
    \ingroup wolfssl

    \brief This function sets the flags for the receive callback to use for the given SSL session.  The receive callback could be either the default wolfSSL EmbedReceive callback, or a custom callback specified by the user (see  wolfSSL_SetIORecv). The default flag value is set internally by wolfSSL to the value of 0. The default wolfSSL receive callback uses the recv() function to receive data from the socket. From the recv() man page: “The flags argument to a recv() function is formed by or'ing one or more of the values: MSG_OOB process out-of-band data, MSG_PEEK peek at incoming message, MSG_WAITALL	wait for full request or error. The MSG_OOB flag requests receipt of out-of-band data that would not be received in the normal data stream. Some protocols place expedited data at the head of the normal data queue, and thus this flag cannot be used with such protocols.  The MSG_PEEK flag causes the receive operation to return data from the beginning of the receive queue without removing that data from the queue.  Thus, a subsequent receive call will return the same data.  The MSG_WAITALL flag requests that the operation block until the full request is satisfied.  However, the call may still return less data than requested if a signal is caught, an error or disconnect occurs, or the next data to be received is of a different type than that returned.”
    
    \return none No returns.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param flags value of the I/O read flags for the specified SSL session (ssl).
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    // Manually setting recv flags to 0
    wolfSSL_SetIOReadFlags(ssl, 0);
    ...
    \endcode
    
    \sa wolfSSL_SetIORecv
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
WOLFSSL_API void wolfSSL_SetIOReadFlags( WOLFSSL* ssl, int flags);
/*!
    \ingroup wolfssl

    \brief This function sets the flags for the send callback to use for the given SSL session.  The send callback could be either the default wolfSSL EmbedSend callback, or a custom callback specified by the user (see  wolfSSL_SetIOSend). The default flag value is set internally by wolfSSL to the value of 0. The default wolfSSL send callback uses the send() function to send data from the socket.  From the send() man page: “The flags parameter may include one or more of the following: #define MSG_OOB        0x1  /* process out-of-band data, #define MSG_DONTROUTE  0x4  /* bypass routing, use direct interface. The flag MSG_OOB is used to send ``out-of-band'' data on sockets that support this notion (e.g.  SOCK_STREAM); the underlying protocol must also support ``out-of-band'' data.  MSG_DONTROUTE is usually used only by diagnostic or routing programs.”

    \return none No returns.
    
    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param flags value of the I/O send flags for the specified SSL session (ssl).
    
    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    // Manually setting send flags to 0
    wolfSSL_SetIOSendFlags(ssl, 0);
    ...
    \endcode
    
    \sa wolfSSL_SetIORecv
    \sa wolfSSL_SetIOSend
    \sa wolfSSL_SetIOReadCtx
*/
WOLFSSL_API void wolfSSL_SetIOWriteFlags(WOLFSSL* ssl, int flags);


#ifdef HAVE_NETX
    WOLFSSL_LOCAL int NetX_Receive(WOLFSSL *ssl, char *buf, int sz, void *ctx);
    WOLFSSL_LOCAL int NetX_Send(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/*!
    \ingroup wolfssl

    \brief This function sets the nxSocket and nxWait members of the nxCtx struct within the WOLFSSL structure.
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param nxSocket a pointer to type NX_TCP_SOCKET that is set to the nxSocket member of the nxCTX structure.
    \param waitOption a ULONG type that is set to the nxWait member of the nxCtx structure.
    
    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    NX_TCP_SOCKET* nxSocket;
    ULONG waitOption;
    …
    if(ssl != NULL || nxSocket != NULL || waitOption <= 0){ 
    wolfSSL_SetIO_NetX(ssl, nxSocket, waitOption);
    } else {
    	// You need to pass in good parameters.
    }
    \endcode
    
    \sa set_fd
    \sa NetX_Send
    \sa NetX_Receive
*/
    WOLFSSL_API void wolfSSL_SetIO_NetX(WOLFSSL* ssl, NX_TCP_SOCKET* nxsocket,
                                      ULONG waitoption);
#endif /* HAVE_NETX */

#ifdef MICRIUM
    WOLFSSL_LOCAL int MicriumSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);
    WOLFSSL_LOCAL int MicriumReceive(WOLFSSL* ssl, char* buf, int sz,
                                     void* ctx);
    WOLFSSL_LOCAL int MicriumReceiveFrom(WOLFSSL* ssl, char* buf, int sz,
                                         void* ctx);
    WOLFSSL_LOCAL int MicriumSendTo(WOLFSSL* ssl, char* buf, int sz, void* ctx);
#endif /* MICRIUM */

#ifdef WOLFSSL_DTLS
    typedef int (*CallbackGenCookie)(WOLFSSL* ssl, unsigned char* buf, int sz,
                                     void* ctx);
/*!
    \ingroup wolfssl

    \brief This function sets the callback for the CBIOCookie member of the WOLFSSL_CTX structure. The CallbackGenCookie type is a function pointer and has the signature:	int (*CallbackGenCookie)(WOLFSSL* ssl, unsigned char* buf, int sz, void* ctx);
    
    \return none No returns.
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a CallbackGenCookie type function pointer with the signature of CallbackGenCookie.
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int SetGenCookieCB(WOLFSSL* ssl, unsigned char* buf, int sz, void* ctx){
	// Callback function body.
    }
    …
    wolfSSL_CTX_SetGenCookie(ssl->ctx, SetGenCookieCB);
    \endcode
    
    \sa CallbackGenCookie
*/
    WOLFSSL_API void  wolfSSL_CTX_SetGenCookie(WOLFSSL_CTX*, CallbackGenCookie);
    WOLFSSL_API void  wolfSSL_SetCookieCtx(WOLFSSL* ssl, void *ctx);
/*!
    \ingroup wolfssl

    \brief This function returns the IOCB_CookieCtx member of the WOLFSSL structure.
    
    \return pointer The function returns a void pointer value stored in the IOCB_CookieCtx.
    \return NULL if the WOLFSSL struct is NULL
    
    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    
    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* cookie;
    ...
    cookie = wolfSSL_GetCookieCtx(ssl);
    if(cookie != NULL){
	// You have the cookie
    }
    \endcode
    
    \sa wolfSSL_SetCookieCtx
    \sa wolfSSL_CTX_SetGenCookie
*/
    WOLFSSL_API void* wolfSSL_GetCookieCtx(WOLFSSL* ssl);

    #ifdef WOLFSSL_SESSION_EXPORT
        typedef int (*CallbackGetPeer)(WOLFSSL* ssl, char* ip, int* ipSz,
                                            unsigned short* port, int* fam);
        typedef int (*CallbackSetPeer)(WOLFSSL* ssl, char* ip, int ipSz,
                                              unsigned short port, int fam);

        WOLFSSL_API void wolfSSL_CTX_SetIOGetPeer(WOLFSSL_CTX*, CallbackGetPeer);
        WOLFSSL_API void wolfSSL_CTX_SetIOSetPeer(WOLFSSL_CTX*, CallbackSetPeer);
    #endif /* WOLFSSL_SESSION_EXPORT */
#endif



#ifndef XINET_NTOP
    #define XINET_NTOP(a,b,c,d) inet_ntop((a),(b),(c),(d))
#endif
#ifndef XINET_PTON
    #define XINET_PTON(a,b,c)   inet_pton((a),(b),(c))
#endif
#ifndef XHTONS
    #define XHTONS(a) htons((a))
#endif
#ifndef XNTOHS
    #define XNTOHS(a) ntohs((a))
#endif

#ifndef WOLFSSL_IP4
    #define WOLFSSL_IP4 AF_INET
#endif
#ifndef WOLFSSL_IP6
    #define WOLFSSL_IP6 AF_INET6
#endif


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_IO_H */
