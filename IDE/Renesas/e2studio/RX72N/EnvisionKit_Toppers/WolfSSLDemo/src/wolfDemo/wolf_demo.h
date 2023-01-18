/*wolf_demo.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 */#ifndef WOLFDEMO_H_
#define WOLFDEMO_H_


typedef struct func_args
{
    int argc;
    char **argv;
    int return_code;
} func_args;

void wolfSSL_init(void) ;
void wolfSSL_main(void) ;
WOLFSSL_CTX *wolfSSL_TLS_server_init(void);
WOLFSSL_CTX *wolfSSL_TLS_client_init(void);

void benchmark_test(void *args);
void wolfcrypt_test(void *args);
void wolfSSL_TLS_client(void *ctx, func_args *args);
void wolfSSL_TLS_server(void *ctx, func_args *args);
#define SERVER_IP "192.168.11.4"
#define SERVER_PortNo (1024)
#endif /* WOLFDEMO_H_ */
