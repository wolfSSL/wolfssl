/* test_wolfmath.h
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

#ifndef WOLFCRYPT_TEST_WOLFMATH_H
#define WOLFCRYPT_TEST_WOLFMATH_H

#include <tests/api/api_decl.h>

int test_mp_get_digit_count(void);
int test_mp_get_digit(void);
int test_mp_get_rand_digit(void);
int test_mp_cond_copy(void);
int test_mp_rand(void);
int test_wc_export_int(void);
int test_wc_SpIntSizeDecisionCoverage(void);
int test_wc_SpIntShiftDecisionCoverage(void);
int test_wc_SpIntDigitArithDecisionCoverage(void);
int test_wc_SpIntArithDecisionCoverage(void);
int test_wc_SpIntConvDecisionCoverage(void);
int test_wc_SpIntExptGcdDecisionCoverage(void);
int test_wc_TfmDecisionCoverage(void);
int test_wc_TfmExptModDecisionCoverage(void);
int test_wc_IntegerDecisionCoverage(void);

#define TEST_WOLFMATH_DECLS                             \
    TEST_DECL_GROUP("wolfmath", test_mp_get_digit_count),  \
    TEST_DECL_GROUP("wolfmath", test_mp_get_digit),        \
    TEST_DECL_GROUP("wolfmath", test_mp_get_rand_digit),   \
    TEST_DECL_GROUP("wolfmath", test_mp_cond_copy),     \
    TEST_DECL_GROUP("wolfmath", test_mp_rand),          \
    TEST_DECL_GROUP("wolfmath", test_wc_export_int),    \
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntSizeDecisionCoverage),      \
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntShiftDecisionCoverage),     \
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntDigitArithDecisionCoverage),\
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntArithDecisionCoverage),     \
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntConvDecisionCoverage),      \
    TEST_DECL_GROUP("wolfmath", test_wc_SpIntExptGcdDecisionCoverage),   \
    TEST_DECL_GROUP("wolfmath", test_wc_TfmDecisionCoverage),            \
    TEST_DECL_GROUP("wolfmath", test_wc_TfmExptModDecisionCoverage),     \
    TEST_DECL_GROUP("wolfmath", test_wc_IntegerDecisionCoverage)

#endif /* WOLFCRYPT_TEST_WOLFMATH_H */
