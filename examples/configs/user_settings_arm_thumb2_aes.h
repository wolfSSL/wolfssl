/* user_settings_arm_thumb2_aes.h
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

/* Minimal Arm Thumb-2 software-table AES configuration (wolfCrypt only), with
 * ECB/CBC/CTR/GCM/GCM-SIV. Add -DWOLFSSL_AES_TOUCH_LINES to route AES through
 * the C constant-time table core, which honors it where the assembly cannot.
 */

/* Build (cross-compile, Cortex-M4):
cp ./examples/configs/user_settings_arm_thumb2_aes.h user_settings.h
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -Os -Wall -Wextra -Werror -c \
    -I. -DWOLFSSL_USER_SETTINGS wolfcrypt/src/aes.c -o aes.o
*/

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM

/* Thumb-2 software-table AES (no hardware crypto, no NEON) */
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_THUMB2
#define WOLFSSL_ARMASM_INLINE
#define WOLFSSL_ARMASM_NO_HW_CRYPTO
#define WOLFSSL_ARMASM_NO_NEON

/* AES modes */
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define WOLFSSL_AESGCM_SIV
#define HAVE_AES_DECRYPT

/* No RNG needed for the AES-only build */
#define WC_NO_RNG
#define WC_NO_HASHDRBG

/* Disabled algorithms */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_ASN
#define NO_CERTS
#define NO_DES3
#define NO_MD5
#define NO_SHA
#define NO_SHA256
#define NO_HMAC
#define NO_PWDBASED

/* Platform */
#define LITTLE_ENDIAN_ORDER
#define WC_32BIT_CPU

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
