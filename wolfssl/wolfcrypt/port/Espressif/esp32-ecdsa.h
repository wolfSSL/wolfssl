/* esp32-ecdsa.h
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

#ifndef WOLFSSL_ESP32_ECDSA_H
#define WOLFSSL_ESP32_ECDSA_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) && defined(HAVE_ECC) && \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA_OPAQUE)

#include <wolfssl/wolfcrypt/ecc.h>
#include <esp_key_mgr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bind an existing eFuse ECDSA key. The key and its purpose must have been
 * provisioned separately. This function never writes eFuse. highBlock is
 * required only for SECP384R1 and must be -1 for the other curves. */
WOLFSSL_API int wc_esp32_ecdsa_use_efuse_key(ecc_key* key, int curveId,
    int lowBlock, int highBlock);

/* Bind an existing Key Manager recovery record. The recovery data is copied,
 * so it can be released after this call returns. */
WOLFSSL_API int wc_esp32_ecdsa_use_km_key(ecc_key* key, int curveId,
    const esp_key_mgr_key_recovery_info_t* recovery);

WOLFSSL_LOCAL int wc_esp32_ecdsa_sign_hash(const byte* in, word32 inLen,
    ecc_key* key, mp_int* r, mp_int* s);
WOLFSSL_LOCAL int wc_esp32_ecdsa_copy(ecc_key* src, ecc_key* dst);
WOLFSSL_LOCAL int wc_esp32_ecdsa_free(ecc_key* key);
WOLFSSL_LOCAL int wc_esp32_ecdsa_is_opaque(ecc_key* key);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_ESPIDF && HAVE_ECC && OPAQUE */

#endif /* WOLFSSL_ESP32_ECDSA_H */
