/* test_aes.h
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

#ifndef WOLFCRYPT_TEST_AES_H
#define WOLFCRYPT_TEST_AES_H

int test_wc_AesSetKey(void);
int test_wc_AesSetIV(void);
int test_wc_AesCbcEncryptDecrypt(void);
int test_wc_AesCtrEncryptDecrypt(void);
int test_wc_AesGcmSetKey(void);
int test_wc_AesGcmEncryptDecrypt(void);
int test_wc_AesGcmMixedEncDecLongIV(void);
int test_wc_AesGcmStream(void);
int test_wc_GmacSetKey(void);
int test_wc_GmacUpdate(void);
int test_wc_AesCcmSetKey(void);
int test_wc_AesCcmEncryptDecrypt(void);
#if defined(WOLFSSL_AES_EAX) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 3)) && !defined(HAVE_SELFTEST)
int test_wc_AesEaxVectors(void);
int test_wc_AesEaxEncryptAuth(void);
int test_wc_AesEaxDecryptAuth(void);
#endif /* WOLFSSL_AES_EAX */

#endif /* WOLFCRYPT_TEST_AES_H */
