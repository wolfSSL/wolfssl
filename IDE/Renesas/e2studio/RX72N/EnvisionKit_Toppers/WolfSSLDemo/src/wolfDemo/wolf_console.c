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
      if(reset) tick = 0 ;
      return ((double)tick/FREQ) ;	
}

#define ARG_SZ 256
static char argBuff[ARG_SZ];
static int get_arg(func_args *args)
{
    int i;
    char *arg = argBuff;
    args->argc = 0;
    
    for(i=0; i<ARG_SZ; i++) {
        *arg = getchar();
        
	switch(*arg){
	case '\n':
	     *arg = '\0';
	     return args->argc;
	case ' ':
	     *arg++ = '\0';
	     while(*arg++ == ' '); /* Skip space */
	     args->argv[++args->argc] = arg;
	     break;
	default:
	     arg++;
	}
    }
    return args->argc ;
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
void wolfSSL_main()
{
    int c;
    func_args args = {0};
    
    #ifdef DEBUG_WOLFSSL
       wolfSSL_Debugging_ON();
    #endif
    
    printf("wolfSSL Demo\nt: test, b: benchmark, s: server, or c <IP addr> <Port>: client\n$ ");
    c = getchar();
    
    switch(c) {
    case 't':
        get_arg(&args);
        printf("Start wolfCrypt Test\n");
#ifndef NO_CRYPT_TEST
        wolfcrypt_test(&args);
#endif
        printf("End wolfCrypt Test\n");
	break;
	
    case 'b':
        get_arg(&args);
        printf("Start wolfCrypt Benchmark\n");
#ifndef NO_CRYPT_BENCHMARK
        benchmark_test(NULL);
#endif
        printf("End wolfCrypt Benchmark\n");
	break;
	
    case 'c':
        if(get_arg(&args) < 0)
            break;
	printf("Start TLS Client(%s, %s)\n", "192.168.11.4", "1024");
	wolfSSL_TLS_client(wolfSSL_cl_ctx, &args);
        printf("End TLS Client\n");
	break;
	
    case 's':
        if(get_arg(&args) < 0)
            break;
	printf("Start TLS Server\n");
	wolfSSL_TLS_server(wolfSSL_sv_ctx, &args);
        printf("End TLS Server\n");
	break;

    default:
    	printf("Command Error\n");
    }
}
