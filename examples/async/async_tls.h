/* async-tls.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


#ifndef WOLFSSL_ASYNC_TLS_EXAMPLES_H
#define WOLFSSL_ASYNC_TLS_EXAMPLES_H

typedef struct WOLFSSL WOLFSSL;
#ifdef WOLF_CRYPTO_CB
typedef struct wc_CryptoInfo wc_CryptoInfo;
#endif

#define DEFAULT_PORT 11111
#define DEFAULT_TLS_PORT 11111
#define DEFAULT_TLS_HOST "127.0.0.1"
#define TEST_BUF_SZ  256
#define WOLFSSL_ASYNC_READYFILE_ENV "WOLFSSL_ASYNC_READYFILE"
#define WOLFSSL_ASYNC_READYFILE_TIMEOUT_MS 5000

/* Force ECC-only certs/keys for these async TLS examples. */
#ifndef ASYNC_ECC_ONLY
#if defined(WC_ECC_NONBLOCK)
#define ASYNC_ECC_ONLY 1
#else
#define ASYNC_ECC_ONLY 0
#endif
#endif

#ifdef WOLF_CRYPTO_CB
/* Example custom context for crypto callback */
typedef struct {
    int pendingCount; /* track pending tries test count */
} AsyncTlsCryptoCbCtx;
int AsyncTlsCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx);
#endif /* WOLF_CRYPTO_CB */

/* Override transport by defining NET_USER_HEADER and/or NET_*.
 * Example: -DNET_USER_HEADER='"my_net_port.h"' */
#ifdef NET_USER_HEADER
    #include NET_USER_HEADER
#define NET_CUSTOM 1
#endif

int async_readyfile_touch(const char* path);
int async_readyfile_wait(const char* path, int timeout_ms);
void async_readyfile_clear(const char* path);

/* Default POSIX transport hooks (override with NET_* macros). */
#ifndef NET_CUSTOM
#ifndef NET_CONNECT
#define NET_CONNECT(host, port) posix_net_connect((host), (port))
#define NET_SET_NONBLOCKING(fd) posix_set_nonblocking((fd))
#define NET_ACCEPT(fd, addr, len) accept((fd), (addr), (len))
#define NET_SEND(fd, buf, sz) send((fd), (buf), (size_t)(sz), 0)
#define NET_RECV(fd, buf, sz) recv((fd), (buf), (size_t)(sz), 0)
#define NET_CLOSE(fd) close((fd))
#endif
#endif

int async_posix_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int async_posix_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int async_posix_getdevrandom(unsigned char *out, unsigned int sz);

#ifndef NET_CUSTOM
#define NET_IO_SEND_CB async_posix_send_cb
#define NET_IO_RECV_CB async_posix_recv_cb
#else
#ifndef NET_IO_SEND_CB
#error NET_IO_SEND_CB must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_IO_RECV_CB
#error NET_IO_RECV_CB must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_CONNECT
#error NET_CONNECT must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_SET_NONBLOCKING
#error NET_SET_NONBLOCKING must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_ACCEPT
#error NET_ACCEPT must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_SEND
#error NET_SEND must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_RECV
#error NET_RECV must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_CLOSE
#error NET_CLOSE must be defined when NET_USER_HEADER is used
#endif
#ifndef NET_GETDEVRANDOM
#error NET_GETDEVRANDOM must be defined when NET_USER_HEADER is used
#endif
#endif


int client_async_test(int argc, char** argv);
int server_async_test(int argc, char** argv);


#endif /* WOLFSSL_ASYNC_TLS_EXAMPLES_H */
