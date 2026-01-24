/* user_settings.h
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
 *
 * Configuration for the external crypto callback provider.
 * Includes the main library's options.h for ABI compatibility, then
 * undefines WOLF_CRYPTO_CB_ONLY_* flags to enable software implementations.
 */

#ifndef CRYPTOCB_PROVIDER_USER_SETTINGS_H
#define CRYPTOCB_PROVIDER_USER_SETTINGS_H

/* Include the main library's options.h to get the exact same
 * structure definitions and feature set. This is CRITICAL for ABI
 * compatibility - the wc_CryptoInfo, RsaKey, ecc_key, etc. structures
 * must be identical in both the main library and this provider.
 */
/* TODO: include conditionally main library user settings if no autotool is
 * used */
#include <wolfssl/options.h>

/* Remove TLS stack - only need wolfCrypt */
#define WOLFCRYPT_ONLY

/* CRITICAL: Undefine WOLF_CRYPTO_CB_ONLY_* to enable software implementations */
#undef WOLF_CRYPTO_CB_ONLY_RSA
#undef WOLF_CRYPTO_CB_ONLY_ECC
#undef WOLF_CRYPTO_CB_ONLY_SHA512

/* Ensure WOLF_CRYPTO_CB is defined for callback structures */
#ifndef WOLF_CRYPTO_CB
#error "Building CRYPTOCB_PROVIDER without WOLF_CRYPTO_CB"
#endif

#endif /* CRYPTOCB_PROVIDER_USER_SETTINGS_H */
