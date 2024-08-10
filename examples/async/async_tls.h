/* async-tls.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


#ifndef WOLFSSL_ASYNC_TLS_EXAMPLES_H
#define WOLFSSL_ASYNC_TLS_EXAMPLES_H

#define DEFAULT_PORT 11111
#define TEST_BUF_SZ  256

#ifdef WOLF_CRYPTO_CB
/* Example custom context for crypto callback */
typedef struct {
    int pendingCount; /* track pending tries test count */
} AsyncTlsCryptoCbCtx;
int AsyncTlsCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx);
#endif /* WOLF_CRYPTO_CB */


int client_async_test(int argc, char** argv);
int server_async_test(int argc, char** argv);


#endif /* WOLFSSL_ASYNC_TLS_EXAMPLES_H */
