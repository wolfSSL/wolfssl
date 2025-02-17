/* test_ecc.h
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

#ifndef WOLFCRYPT_TEST_ECC_H
#define WOLFCRYPT_TEST_ECC_H

int test_wc_ecc_init(void);
int test_wc_ecc_sign_hash(void);
int test_wc_ecc_verify_hash(void);
int test_wc_ecc_make_key(void);
int test_wc_ecc_shared_secret(void);
int test_wc_ecc_free(void);

#endif /* WOLFCRYPT_TEST_ECC_H */
