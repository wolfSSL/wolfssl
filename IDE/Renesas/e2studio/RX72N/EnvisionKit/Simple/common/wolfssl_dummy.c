/* wolfssl_dummy.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/wc_port.h>
#include "platform.h"

/*
 * printf() is routed here via the r_bsp charput() hook
 * (BSP_CFG_USER_CHARPUT_ENABLED / BSP_CFG_USER_CHARPUT_FUNCTION in
 * r_bsp_config.h, sourced from test.scfg). Set BSP_CFG_USER_CHARPUT_ENABLED
 * to 0 there to switch printf() back to the E1/E2 emulator's Virtual
 * Console. */

static void sci2_uart_putraw(unsigned char c)
{
    volatile int timeout = 200000;
    while (SCI2.SSR.BIT.TDRE == 0 && --timeout > 0) {}
    if (timeout > 0)
        SCI2.TDR = c;
}

/* Translate LF to CR+LF so terminals (Tera Term) return to column 0 on
 * newline, matching printf()'s "\n"-only line endings. */
void sci2_uart_charput(char c)
{
    if (c == '\n')
        sci2_uart_putraw('\r');
    sci2_uart_putraw((unsigned char)c);
}

void sci2_uart_init(void)
{
    unsigned char ick, pckb;
    unsigned long iclk_hz, src_hz, pclkb_hz;
    unsigned long brr_val;

    SYSTEM.PRCR.WORD = 0xA503;        //PRC1,0 Write Enable
    SYSTEM.MSTPCRB.BIT.MSTPB29 = 0;   //SCI2

    MPC.PWPR.BYTE = 0x00;             //B0WI=0
    MPC.PWPR.BYTE = 0x40;             //PFS Write Enable
    PORT1.PMR.BYTE = 0x0C;            //P12,13:peripheral
    MPC.P12PFS.BYTE = 0x0A;           //P12:RXD2
    MPC.P13PFS.BYTE = 0x0A;           //P13:TXD2

    SCI2.SCR.BYTE  = 0x00;            /* TE=0,RE=0 */
    SCI2.SMR.BYTE  = 0x00;            /* async,8bit,no parity,1stop,Phi/1 */
    SCI2.SCMR.BYTE = 0xF2;            /* LSB first,no invert,no smart card I/F */
    SCI2.SEMR.BYTE = 0x00;

    /* Derive PCLKB from R_BSP_GetIClkFreqHz() (which already resolves the
     * *current* clock source -- PLL/HOCO/MOSC/etc -- and ICK divisor)
     * instead of assuming a fixed PLL frequency, so this stays correct
     * even if wolfCrypt_Init() (TSIP) changes the clock dividers, and the
     * ICLK/CMT tick rate used by current_time() is left alone. */
    iclk_hz  = R_BSP_GetIClkFreqHz();
    ick      = (unsigned char)SYSTEM.SCKCR.BIT.ICK;   /* 0-6: divisor=2^ick */
    pckb     = (unsigned char)SYSTEM.SCKCR.BIT.PCKB;  /* 0-6: divisor=2^pckb */
    src_hz   = iclk_hz << ick;                        /* undo ICK divisor -> raw source clock */
    pclkb_hz = src_hz >> pckb;                        /* apply PCKB divisor */
    /* N = PCLKB / (64 * 2^-1 * baud) - 1 = PCLKB / (32 * baud) - 1 (CKS=0,
     * SMR.BIT.CKS=00 selects the 2^-1 baud-generator divisor). */
    brr_val  = (pclkb_hz / (32UL * 19200UL)) - 1UL;   /* BRR for 19200 baud */
    SCI2.BRR = (unsigned char)(brr_val & 0xFFUL);
    SCI2.SSR.BYTE = 0x00;             /* status clear */
    SCI2.SCR.BYTE = 0x30;             /* TIE=0,RIE=0,TE=1,RE=1 */
}

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
/* dummy return true when char is alphanumeric character */
int isascii(const char *s)
{
    return isalnum(s);
}
