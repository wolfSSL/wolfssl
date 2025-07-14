/* user_settings_eccnonblock.h
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

/* Example wolfSSL user_settings.h file for ECC only non-blocking crypto.
 * See doc/dox_comments/header_files/ecc.h wc_ecc_set_nonblock for example.
 */

/* Settings based on this configure:
./configure --enable-cryptonly --enable-ecc=nonblock --with-eccminsz=256 \
    --enable-sp=nonblock,ec256,nomalloc --enable-sp-math --disable-sp-asm \
    --disable-rsa --disable-dh \
    CFLAGS="-DWOLFSSL_DEBUG_NONBLOCK -DSP_WORD_SIZE=32 -DECC_USER_CURVES \
            -DWOLFSSL_PUBLIC_MP"
*/

/* Tested using:
cp ./examples/configs/user_settings_eccnonblock.h user_settings.h
./configure --enable-usersettings --enable-debug --disable-examples
make
./wolfcrypt/test/test/wolfcrypt
*/

/* Example test results:
ecc_test_curve keySize = 32
ECC non-block sign: 12301 times
ECC non-block verify: 24109 times
ECC non-block key gen: 11784 times
ECC non-block shared secret: 11783 times

ecc_test_curve keySize = 48
ECC non-block sign: 18445 times
ECC non-block verify: 36141 times
ECC non-block key gen: 17672 times
ECC non-block shared secret: 17671 times

ecc_test_curve keySize = 66
ECC non-block sign: 25021 times
ECC non-block verify: 49019 times
ECC non-block key gen: 23974 times
ECC non-block shared secret: 23973 times
*/

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Choose the ECC curve */
#define ECC_USER_CURVES /* Manually specify curves enabled */
#if   1 /* SECP256R1 */
    #define ECC_MIN_KEY_SZ 256
#elif 1 /* SECP384R1 */
    #define HAVE_ECC384
    #define NO_ECC256
    #define ECC_MIN_KEY_SZ 384
    #define WOLFSSL_SP_NO_256
    #define WOLFSSL_SP_384
#else /* SECP521R1 */
    #define HAVE_ECC521
    #define NO_ECC256
    #define ECC_MIN_KEY_SZ 521
    #define WOLFSSL_SP_NO_256
    #define WOLFSSL_SP_521
#endif

/* Features */
#define WOLFCRYPT_ONLY
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_PUBLIC_MP /* expose mp_ math API's */
#define HAVE_HASHDRBG /* enable hash based pseudo RNG */

/* ECC */
#define HAVE_ECC
#define WC_ECC_NONBLOCK
#define ECC_TIMING_RESISTANT

/* Math options */
/* sp_c32.c */
#define SP_WORD_SIZE 32
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NONBLOCK
#define WOLFSSL_SP_MATH /* forces only single precision */

/* Hashing */
#define WOLFSL_SHA512
#define WOLFSL_SHA384
#undef NO_SHA256

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
