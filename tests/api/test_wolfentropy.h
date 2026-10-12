/* test_wolfentropy.h
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

#ifndef WOLFCRYPT_TEST_WOLFENTROPY_H
#define WOLFCRYPT_TEST_WOLFENTROPY_H

#include <tests/api/api_decl.h>

int test_wc_Entropy_GetRawEntropy(void);
int test_wc_Entropy_OnDemandTest(void);
int test_wc_EntropyDecisionCoverage(void);
int test_wc_EntropyFeatureCoverage(void);

#define TEST_WOLFENTROPY_DECLS                                              \
    TEST_DECL_GROUP("wolfentropy", test_wc_Entropy_GetRawEntropy),         \
    TEST_DECL_GROUP("wolfentropy", test_wc_Entropy_OnDemandTest),          \
    TEST_DECL_GROUP("wolfentropy", test_wc_EntropyDecisionCoverage),       \
    TEST_DECL_GROUP("wolfentropy", test_wc_EntropyFeatureCoverage)

#endif /* WOLFCRYPT_TEST_WOLFENTROPY_H */
