/* esp32-ecc.h
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

#ifndef WOLFSSL_ESP32_ECC_H
#define WOLFSSL_ESP32_ECC_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
extern "C" {
#endif

WOLFSSL_LOCAL int esp32_ecc_mulmod(const mp_int* k, ecc_point* G,
    ecc_point* R, mp_int* a, mp_int* modulus, int map, void* heap);

WOLFSSL_LOCAL int esp32_ecdsa_verify_hash(mp_int* r, mp_int* s,
    const byte* hash, word32 hashLen, int* res, ecc_key* key);
#if defined(WOLFSSL_HW_METRICS)
WOLFSSL_LOCAL int esp_hw_show_ecc_metrics(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_ESPIDF && HAVE_ECC */

#endif /* WOLFSSL_ESP32_ECC_H */
