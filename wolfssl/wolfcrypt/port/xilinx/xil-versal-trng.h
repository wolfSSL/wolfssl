/* xil-versal-trng.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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


#ifndef WOLF_XIL_CRYPT_VERSAL_TRNG_H
#define WOLF_XIL_CRYPT_VERSAL_TRNG_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_XILINX_CRYPT_VERSAL

#ifdef __cplusplus
extern "C" {
#endif
WOLFSSL_LOCAL int wc_VersalTrngInit(byte* nonce, word32 nonceSz);
WOLFSSL_LOCAL int wc_VersalTrngReset(void);
WOLFSSL_LOCAL int wc_VersalTrngSelftest(void);
WOLFSSL_LOCAL int wc_VersalTrngGenerate(byte *output, word32 sz);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* versal */
#endif /* WOLF_XIL_CRYPT_VERSAL_TRNG_H */

