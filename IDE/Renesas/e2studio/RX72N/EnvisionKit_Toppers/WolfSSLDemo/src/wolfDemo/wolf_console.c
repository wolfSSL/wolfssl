/* wolf_console.c
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
 */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include <stdio.h>
#include <stdint.h>
#include "wolf_demo.h"

extern void wolfSSL_TLS_server(void *v_ctx, func_args *args);
extern void wolfSSL_TLS_client(void *v_ctx, func_args *args);

static WOLFSSL_CTX *wolfSSL_sv_ctx;
static WOLFSSL_CTX *wolfSSL_cl_ctx;

static long tick;
 void timeTick(void *pdata)
{
    tick++;
}

#define FREQ 10000 /* Hz */

double current_time(int reset)
{
    if (reset) 
        tick = 0 ;
    return ((double)tick/FREQ) ;	
}

void wolfSSL_init()
{
    uint32_t channel;
    wolfSSL_sv_ctx = wolfSSL_TLS_server_init();
    wolfSSL_cl_ctx = wolfSSL_TLS_client_init();
}

void wolfSSL_TLS_client_Wrapper() {
    func_args args = {0};

	printf("Start TLS Client\n");

	wolfSSL_TLS_client(wolfSSL_cl_ctx, &args);
}
void wolfSSL_TLS_server_Wrapper() {
    func_args args = {0};

	printf("Start TLS Server\n");

	wolfSSL_TLS_server(wolfSSL_sv_ctx, &args);
}
