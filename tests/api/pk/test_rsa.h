/* test_rsa.h
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

#ifndef WOLFCRYPT_TEST_RSA_H
#define WOLFCRYPT_TEST_RSA_H

int test_wc_InitRsaKey(void);
int test_wc_RsaPrivateKeyDecode(void);
int test_wc_RsaPublicKeyDecode(void);
int test_wc_RsaPublicEncrypt(void);
int test_wc_RsaPrivateDecrypt(void);
int test_wc_RsaFree(void);

#endif /* WOLFCRYPT_TEST_RSA_H */
