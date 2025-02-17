/* test_camellia.h
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

#ifndef WOLFCRYPT_TEST_CAMELLIA_H
#define WOLFCRYPT_TEST_CAMELLIA_H

int test_wc_CamelliaInit(void);
int test_wc_CamelliaSetKey(void);
int test_wc_CamelliaCbcEncrypt(void);
int test_wc_CamelliaCbcDecrypt(void);
int test_wc_CamelliaFree(void);

#endif /* WOLFCRYPT_TEST_CAMELLIA_H */
