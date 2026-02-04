/* user_settings_curve25519nonblock.h
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
 */

/* Example wolfSSL user_settings.h file for Curve25519 (X25519) non-blocking.
 * See doc/dox_comments/header_files/curve25519.h wc_curve25519_set_nonblock.
 */

/* Settings based on this configure:
./configure --enable-curve25519=nonblock --enable-ecc=nonblock \
    --enable-sp=yes,nonblock \
    CFLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_DEBUG_NONBLOCK"
*/

/* Tested using:
cp ./examples/configs/user_settings_curve25519nonblock.h user_settings.h
./configure --enable-usersettings --enable-debug --disable-examples
make
./wolfcrypt/test/testwolfcrypt
*/

/* Example test results:
CURVE25519 non-block key gen: 1273 times
CURVE25519 non-block shared secret: 1275 times
CURVE25519 test passed!
*/

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Features */
#define WOLFCRYPT_ONLY
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_PUBLIC_MP /* expose mp_ math API's */
#define HAVE_HASHDRBG

/* Curve25519 (X25519) */
#define HAVE_CURVE25519
#define CURVE25519_SMALL
#define WC_X25519_NONBLOCK

/* Debugging */
#if 1
    #undef  DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
    #define WOLFSSL_DEBUG_NONBLOCK
#endif

/* Disabled algorithms */
#define NO_OLD_TLS
#define NO_RSA
#define NO_DH
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
