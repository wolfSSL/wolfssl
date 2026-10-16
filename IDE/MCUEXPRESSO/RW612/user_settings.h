/* user_settings.h
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

/* wolfSSL settings for the RW612 EdgeLock port in an MCUXpresso SDK project.
 * See README.md. */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED

/* Bare-metal startup never sets the thread pointer wolfCrypt_Init() reads. */
#define NO_THREAD_LS

/* newlib does not declare getpid(); nosys.specs hides that from configure. */
#define WOLFSSL_NO_GETPID
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM           /* entropy comes from the ELS DRBG, below */
#define WOLFCRYPT_ONLY          /* drop for TLS; then supply IO and time */

/* No RTC by default on this board. Supply a real time source and remove this
 * if certificate validity has to be checked. */
#define NO_ASN_TIME

#define WOLFSSL_ELS_PKC

#define WOLF_CRYPTO_CB

/* Seed wolfCrypt's DRBG from the ELS hardware DRBG. */
#define HAVE_HASHDRBG

/* Anything not listed here falls back to software through the normal
 * CRYPTOCB_UNAVAILABLE path. */

#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_CMAC

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS
#define WOLFSSL_SMALL_STACK

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
