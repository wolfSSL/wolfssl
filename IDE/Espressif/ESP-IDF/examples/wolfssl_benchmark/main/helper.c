/* helper.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdkconfig.h"

#define WOLFSSL_BENCH_ARGV              CONFIG_BENCH_ARGV

char* __argv[22];

int construct_argv()
{
    int cnt = 0;
    int i = 0;
    int len = 0;
    char *_argv;            /* buffer for copying the string    */
    char *ch;               /* char pointer to trace the string */
    char buff[16] = { 0 };  /* buffer for a argument copy       */

    printf("arg:%s\n", CONFIG_BENCH_ARGV);
    len = strlen(CONFIG_BENCH_ARGV);
    _argv = (char*)malloc(len + 1);
    if (!_argv) {
        return -1;
    }
    memset(_argv, 0, len+1);
    memcpy(_argv, CONFIG_BENCH_ARGV, len);
    _argv[len] = '\0';
    ch = _argv;

    __argv[cnt] = malloc(10);
    sprintf(__argv[cnt], "benchmark");
    __argv[9] = '\0';
    cnt = 1;

    while (*ch != '\0')
    {
        /* skip white-space */
        while (*ch == ' ') { ++ch; }

        memset(buff, 0, sizeof(buff));
        /* copy each args into buffer */
        i = 0;
        while ((*ch != ' ') && (*ch != '\0') && (i < 16)) {
            buff[i] = *ch;
            ++i;
            ++ch;
        }
        /* copy the string into argv */
        __argv[cnt] = (char*)malloc(i + 1);
        memset(__argv[cnt], 0, i + 1);
        memcpy(__argv[cnt], buff, i + 1);
        /* next args */
        ++cnt;
    }

    free(_argv);

    return (cnt);
}
