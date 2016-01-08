/* client.h
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

#ifndef WOLFSSL_CLIENT_H
#define WOLFSSL_CLIENT_H


THREAD_RETURN WOLFSSL_THREAD client_test(void* args);

/* Measures average time to create, connect and disconnect a connection (TPS).
Benchmark = number of connections. */
int ClientBenchmarkConnections(WOLFSSL_CTX* ctx, char* host, word16 port,
	int doDTLS, int benchmark, int resumeSession);

/* Measures throughput in kbps. Throughput = number of bytes */
int ClientBenchmarkThroughput(WOLFSSL_CTX* ctx, char* host, word16 port,
	int doDTLS, int throughput);


#endif /* WOLFSSL_CLIENT_H */

