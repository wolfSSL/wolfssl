/* wolfssl_dummy.c
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
#include <wolfssl/wolfcrypt/wc_port.h>

static int tick = 0;
#define YEAR  ( \
    ((__DATE__)[7]  - '0') * 1000 + \
    ((__DATE__)[8]  - '0') * 100  + \
    ((__DATE__)[9]  - '0') * 10   + \
    ((__DATE__)[10] - '0') * 1      \
)

#define MONTH ( \
    __DATE__[2] == 'n' ? (__DATE__[1] == 'a' ? 1 : 6) \
  : __DATE__[2] == 'b' ? 2 \
  : __DATE__[2] == 'r' ? (__DATE__[0] == 'M' ? 3 : 4) \
  : __DATE__[2] == 'y' ? 5 \
  : __DATE__[2] == 'l' ? 7 \
  : __DATE__[2] == 'g' ? 8 \
  : __DATE__[2] == 'p' ? 9 \
  : __DATE__[2] == 't' ? 10 \
  : __DATE__[2] == 'v' ? 11 \
  : 12 \
	)

time_t time(time_t *t)
{
    (void)t;
    return ((YEAR-1970)*365+30*MONTH)*24*60*60 + tick++;
}

#include <ctype.h>
int strncasecmp(const char *s1, const char * s2, unsigned int sz)
{
    for( ; sz>0; sz--)
        if(toupper(s1++) != toupper(s2++))
        return 1;
    return 0;
}

#if !defined(WOLFSSL_RENESAS_TSIP)
/* dummy return true when char is alphanumeric character */
int isascii(const char *s)
{
    return isalnum(s);
}
#endif

