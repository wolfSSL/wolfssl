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
 */

#ifndef WOLFCRYPT_TEST_AES_H
#define WOLFCRYPT_TEST_AES_H

int test_wc_AesInit(void);
int test_wc_AesSetKey(void);
int test_wc_AesCbcEncrypt(void);
int test_wc_AesCbcDecrypt(void);
int test_wc_AesGcmSetKey(void);
int test_wc_AesGcmEncrypt(void);
int test_wc_AesGcmDecrypt(void);
int test_wc_AesCtrEncrypt(void);
int test_wc_AesFree(void);

#endif /* WOLFCRYPT_TEST_AES_H */
