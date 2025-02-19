/* test_dsa.h
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

#ifndef WOLFCRYPT_TEST_DSA_H
#define WOLFCRYPT_TEST_DSA_H

int test_wc_InitDsaKey(void);
int test_wc_DsaSign(void);
int test_wc_DsaVerify(void);
int test_wc_DsaPublicPrivateKeyDecode(void);
int test_wc_DsaFree(void);

#endif /* WOLFCRYPT_TEST_DSA_H */
