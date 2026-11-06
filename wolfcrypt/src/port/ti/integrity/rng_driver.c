/* rng_driver.c
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

/* Direct register driver for the AM64x SA2UL TRNG
 *
 * Note: optee initializes the TRNG in NRBG mode and opens the firewall.
 * See optee sa2ul_init()
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <INTEGRITY_intrinsics.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/rng_driver.h>

#define TRNG_INPUT_0     0x00u
#define TRNG_INPUT_1     0x04u
#define TRNG_INPUT_2     0x08u
#define TRNG_INPUT_3     0x0Cu
#define TRNG_STATUS      0x10u
#define TRNG_INTACK      0x10u

#define TRNG_STATUS_READY_MASK   0x1u

/* Polling budget for one 128-bit TRNG result */
#ifndef RNG_POLL_LIMIT
    #define RNG_POLL_LIMIT 10000000u
#endif

static volatile uint8_t *gTrngBase = NULL;

#define TRNG_REG32(off)  (*(volatile uint32_t *)(gTrngBase + (off)))

/* TrngBase: mapped from the "inside-secure,safexcel-eip76" rng device tree node
 * CpAceBase: mapped from the "ti,am64-sa2ul" sa2ul device tree node
 * Must be called before rng_driver_init()/rng_driver_read(). */
void rng_driver_set_base(volatile void *TrngBase, volatile void *CpAceBase)
{
    gTrngBase = (volatile uint8_t *)TrngBase;
    (void)CpAceBase;
}

int rng_driver_init(void)
{
    if (gTrngBase == NULL) {
        printf("rng_driver_init: rng_driver_set_base() not called\n");
        return -1;
    }
    return 0;
}

/* Returns 0 on success, -1 if no result became ready within RNG_POLL_LIMIT */
static int sa2ul_rng_read128(uint32_t *w0, uint32_t *w1, uint32_t *w2,
        uint32_t *w3)
{
    uint32_t polls;

    for (polls = 0; !(TRNG_REG32(TRNG_STATUS) & TRNG_STATUS_READY_MASK);
            polls++) {
        if (polls >= RNG_POLL_LIMIT) {
            return -1;
        }
    }

    *w0 = TRNG_REG32(TRNG_INPUT_0);
    *w1 = TRNG_REG32(TRNG_INPUT_1);
    *w2 = TRNG_REG32(TRNG_INPUT_2);
    *w3 = TRNG_REG32(TRNG_INPUT_3);

    /* ack read complete */
    TRNG_REG32(TRNG_INTACK) = TRNG_STATUS_READY_MASK;

    return 0;
}


static volatile unsigned int gRngLock = 0u;

static void rng_lock(void)
{
    for (;;) {
        if (__LDXR32((unsigned int *)&gRngLock) == 0u) {
            if (__STXR32(1u, (unsigned int *)&gRngLock) == 0) {
                break; /* acquired */
            }
        }
    }
    __DMB();
}

static void rng_unlock(void)
{
    __DMB();
    gRngLock = 0u;
}

int rng_driver_read(unsigned char *output, unsigned int sz)
{
    /* TRNG provides 128 bits of entropy at a time */
    static union {
        uint32_t val[4];
        uint8_t byte[16];
    } fifo;
    static size_t fifo_pos = 0;
    unsigned int i;
    int ret = 0;

    rng_lock();

    if (gTrngBase == NULL) {
        if (rng_driver_init() != 0) {
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < sz; i++) {
        if (fifo_pos == 0) {
            if (sa2ul_rng_read128(&fifo.val[0], &fifo.val[1], &fifo.val[2],
                    &fifo.val[3]) != 0) {
                /* TRNG timed out: don't hand back a partial buffer */
                volatile unsigned char *p = output;
                unsigned int j;
                for (j = 0; j < i; j++) {
                    p[j] = 0;
                }
                ret = -1;
                goto out;
            }
        }
        output[i] = fifo.byte[fifo_pos++];
        fifo_pos %= 16u;
    }

out:
    rng_unlock();
    return ret;
}
