/* rng_port.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>


#ifdef WOLFSSL_NXP_RNG_1

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "fsl_rng.h"

int wc_nxp_rng_init(void)
{
    CLOCK_EnableClock(kCLOCK_Rng);
    RESET_PeripheralReset(kRNG_RST_SHIFT_RSTn);

    RNG_Init(RNG);

    return 0;
}

int wc_nxp_rng_get_random_data(byte* output, word32 sz)
{
    if (RNG_GetRandomData(RNG, output, sz) != kStatus_Success)
        return RNG_FAILURE_E;

    return 0;
}

#endif /* WOLFSSL_NXP_RNG_1 */
