/* app_print.c
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "hal_data.h"

static char         g_uart_buf[256];        ///< uart tx buffer
extern volatile uint32_t g_tx_complete;
void uart_printf( const char *format, ... );

void uart_printf( const char *format, ... )
{
    va_list  va;
    uint32_t bytes;
    uint32_t offset, len, skip;
    char  chara;
    const char ch = '\r';
    char* p;

    va_start( va, format );
    bytes =  (uint32_t)vsprintf(g_uart_buf, format, va);
    va_end( va );

    if (bytes > 0) {
        p = &g_uart_buf[0];
        offset = 0;
        skip = 0;

        do {
            len = 0;
            skip = 0;
            for (;offset < bytes; offset++, len++) {
                chara = g_uart_buf[offset];
                if ('\n' == chara) {
                    skip = 1;
                    len += 1;
                    break;
                }
                if ('\r' == chara && (offset + 1) < bytes &&
                        '\n' == g_uart_buf[offset + 1]){
                    skip = 2;
                    len += 2;
                    break;
                }
            }
            /* write buffer without LF */
            R_SCI_UART_Write(&g_uart0_ctrl, (uint8_t*)p, len);
            while(!g_tx_complete);
            g_tx_complete = 0;
            if (skip > 0) {
                R_SCI_UART_Write(&g_uart0_ctrl, (uint8_t*)&ch, 1);
                while(!g_tx_complete);
            }
            p += (len + skip);
            offset += skip;
        } while(offset < bytes);
    }


    g_tx_complete = 0;
}
