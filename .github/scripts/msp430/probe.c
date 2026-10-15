/* probe.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef MSP430_PROBE_EXIT
    #define MSP430_PROBE_EXIT 0
#endif

int main(void)
{
    volatile unsigned long long a = 0xfedcba9876543210ULL;
    volatile unsigned long long b = 0x0102030405060708ULL;
    printf("MSP430_ABI CHAR_BIT=%d int=%u long=%u pointer=%u size_t=%u\n",
        CHAR_BIT, (unsigned int)sizeof(int), (unsigned int)sizeof(long),
        (unsigned int)sizeof(void*), (unsigned int)sizeof(size_t));
    if (CHAR_BIT != 8 || sizeof(int) != 2 || sizeof(long) != 4)
        return 99;
    if (a * b != 0xa3e963337c600080ULL)
        return 98;
    return MSP430_PROBE_EXIT;
}
