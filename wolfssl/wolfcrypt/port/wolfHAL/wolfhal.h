/* wolfhal.h
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

#ifndef WOLF_CRYPT_PORT_WOLFHAL_H
#define WOLF_CRYPT_PORT_WOLFHAL_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_WOLFHAL

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* WOLFSSL_WOLFHAL_DEVID and WC_USE_DEVID come from wolfhal_settings.h, which
 * settings.h pulls in above.
 *
 * This header deliberately pulls in no wolfHAL headers, so wc_port.c can reach
 * wc_wolfHAL_RegisterDevice() without the BSP on its include path. The wolfHAL
 * types are needed only by wolfhal.c, which gets them from wolfHAL_board.h.
 *
 * wolfHAL_board.h is supplied by the application, on the include path, in the
 * same way settings.h expects a user_settings.h. It must provide:
 *
 *   - the wolfHAL platform driver headers for the part (e.g.
 *     <wolfHAL/crypto/stm32wb_aes.h>), which is what brings the direct API
 *     mapping defines into scope;
 *   - the WHAL_CFG_*_DEV initializers wolfHAL's own driver TUs expand to
 *     define their device singletons;
 *   - one device macro per algorithm this port dispatches,
 *     WC_WOLFHAL_AES_{ECB,CBC,GCM,CCM}_DEV and WC_WOLFHAL_RNG_DEV, or the
 *     BOARD_AES_*_DEV / BOARD_RNG_DEV names a stock wolfHAL_board.h already
 *     uses, which wolfhal.c accepts directly.
 *
 * Only the modes wolfHAL_board.h names a device for are offloaded; the rest
 * fall back to wolfCrypt's software implementations. WC_WOLFHAL_RNG_DEV is the
 * exception and has no fallback; see wolfhal.c.
 */

#ifdef WOLF_CRYPTO_CB
struct wc_CryptoInfo;

/* Register the wolfHAL device with the wolfSSL crypto callback framework.
 * The board's peripherals must already be brought up by the application with
 * whal_Board_Init(). Pass the same devId that WC_USE_DEVID is set to so
 * wolfSSL routes operations to this device.
 *
 * wolfCrypt_Init() registers WOLFSSL_WOLFHAL_DEVID automatically; call this
 * directly only to register at an additional or different devId. */
WOLFSSL_API int wc_wolfHAL_RegisterDevice(int devId);

/* Remove the wolfHAL device from the crypto callback framework. */
WOLFSSL_API void wc_wolfHAL_UnRegisterDevice(int devId);

/* Crypto device callback for wolfHAL hardware acceleration */
WOLFSSL_LOCAL int wc_wolfHAL_CryptoDevCb(int devId, struct wc_CryptoInfo* info,
                                          void* ctx);
#endif

#ifdef WOLFSSL_WOLFHAL_RNG
/* Seed material from the wolfHAL RNG device. wolfhal_settings.h wires this in
 * as CUSTOM_RAND_GENERATE_SEED. */
WOLFSSL_API int wc_wolfHAL_GenerateSeed(unsigned char* output,
                                         unsigned int sz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_WOLFHAL */
#endif /* WOLF_CRYPT_PORT_WOLFHAL_H */
