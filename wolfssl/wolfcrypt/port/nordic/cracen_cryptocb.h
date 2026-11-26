/* cracen_cryptocb.h
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

#ifndef WOLFSSL_CRACEN_CRYPTOCB_H
#define WOLFSSL_CRACEN_CRYPTOCB_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_NRF54L_CRACEN

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/port/nordic/cracen_hw.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Bring the hardware up and register the device as WOLFSSL_CRACEN_DEVID. */
WOLFSSL_API int  wc_CracenInit(void);
WOLFSSL_API void wc_CracenCleanup(void);

WOLFSSL_API int  wc_CracenCryptoCb_RegisterDevice(int devId);
WOLFSSL_API int  wc_CracenCryptoCb_UnRegisterDevice(int devId);

/* Hardware configuration snapshot taken at init, for diagnostics. */
WOLFSSL_API int  wc_CracenGetInfo(wc_CracenHwInfo* info);

/* Raw conditioned TRNG output, independent of the DRBG. Initialises the
 * hardware if the application has not. */
WOLFSSL_API int  wc_CracenTrngRead(byte* out, word32 sz);
/* Power the TRNG down until the next read. */
WOLFSSL_API void wc_CracenTrngOff(void);
WOLFSSL_API int  wc_CracenTrngGetStats(wc_CracenTrngStats* stats);

/* Load the public key engine microcode (Nordic's ba414ep_ucode, supplied by
 * the application) and enable public key offload. Without it every public
 * key request runs in software. wc_CracenPkReady returns 1 once loaded. */
WOLFSSL_API int  wc_CracenPkLoadMicrocode(const word32* ucode, word32 words);
WOLFSSL_API int  wc_CracenPkReady(void);

/* Marker values kept in an object's devCtx while the port owns it. */
#define WC_CRACEN_MARK_FRESH ((void*)1) /* fields reset, no hardware state */
#define WC_CRACEN_MARK_STATE ((void*)2) /* hardware state exported into object */

/* Engine handlers, one per wc_AlgoType. */
WOLFSSL_LOCAL int wc_CracenHash(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_CracenCipher(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_CracenCmac(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_CracenRng(wc_CryptoInfo* info);
WOLFSSL_LOCAL int wc_CracenPk(wc_CryptoInfo* info);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_NRF54L_CRACEN */

#endif /* WOLFSSL_CRACEN_CRYPTOCB_H */
