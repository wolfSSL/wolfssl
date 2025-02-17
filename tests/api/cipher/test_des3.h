/* test_des3.h
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

#ifndef WOLFCRYPT_TEST_DES3_H
#define WOLFCRYPT_TEST_DES3_H

int test_wc_Des3Init(void);
int test_wc_Des3SetKey(void);
int test_wc_Des3CbcEncrypt(void);
int test_wc_Des3CbcDecrypt(void);
int test_wc_Des3Free(void);

#endif /* WOLFCRYPT_TEST_DES3_H */
