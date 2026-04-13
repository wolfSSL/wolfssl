/* test_asn.h
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

#ifndef WOLFCRYPT_TEST_ASN_H
#define WOLFCRYPT_TEST_ASN_H

#include <tests/api/api_decl.h>

int test_SetAsymKeyDer(void);
int test_GetSetShortInt(void);
int test_wc_IndexSequenceOf(void);
int test_wolfssl_local_MatchBaseName(void);
int test_wc_DecodeRsaPssParams(void);
int test_DecodeAltNames_length_underflow(void);
int test_wc_DecodeObjectId(void);
int test_wc_AsnDecisionCoverage(void);
int test_wc_AsnDerGuardrailCoverage(void);
int test_wc_AsnFeatureCoverage(void);
int test_wc_AsnDateCoverage(void);
int test_wc_AsnPemCoverage(void);
int test_wc_AsnDecodeAuthKeyCoverage(void);
int test_wc_AsnGetRdnCoverage(void);
int test_wc_AsnPrintCoverage(void);
int test_wc_AsnCrlCoverage(void);
int test_wc_AsnPkcs8Coverage(void);
int test_wc_AsnCertDecodeCoverage(void);
int test_wc_AsnCheckSigCoverage(void);
int test_wc_AsnValidateGmtimeCoverage(void);
int test_wc_AsnStoreDataCoverage(void);
int test_wc_AsnPemResidualCoverage(void);
int test_wc_AsnGetRdnResidualCoverage(void);
int test_wc_AsnUriNameConstraintCoverage(void);
int test_wc_AsnDhParamsCoverage(void);
int test_wc_AsnFormattedTimeCoverage(void);
int test_wc_AsnSetAlgoCoverage(void);
int test_wc_AsnDecodePolicyCoverage(void);
int test_wc_AsnMatchIpSubnetCoverage(void);
int test_wc_AsnConfirmSigCoverage(void);

#define TEST_ASN_DECLS                                              \
    TEST_DECL_GROUP("asn", test_SetAsymKeyDer),                     \
    TEST_DECL_GROUP("asn", test_GetSetShortInt),                    \
    TEST_DECL_GROUP("asn", test_wc_IndexSequenceOf),                \
    TEST_DECL_GROUP("asn", test_wolfssl_local_MatchBaseName),       \
    TEST_DECL_GROUP("asn", test_wc_DecodeRsaPssParams),             \
    TEST_DECL_GROUP("asn", test_DecodeAltNames_length_underflow),    \
    TEST_DECL_GROUP("asn", test_wc_DecodeObjectId),                 \
    TEST_DECL_GROUP("asn", test_wc_AsnDecisionCoverage),            \
    TEST_DECL_GROUP("asn", test_wc_AsnDerGuardrailCoverage),        \
    TEST_DECL_GROUP("asn", test_wc_AsnFeatureCoverage),             \
    TEST_DECL_GROUP("asn", test_wc_AsnDateCoverage),                \
    TEST_DECL_GROUP("asn", test_wc_AsnPemCoverage),                 \
    TEST_DECL_GROUP("asn", test_wc_AsnDecodeAuthKeyCoverage),       \
    TEST_DECL_GROUP("asn", test_wc_AsnGetRdnCoverage),              \
    TEST_DECL_GROUP("asn", test_wc_AsnPrintCoverage),               \
    TEST_DECL_GROUP("asn", test_wc_AsnCrlCoverage),                 \
    TEST_DECL_GROUP("asn", test_wc_AsnPkcs8Coverage),               \
    TEST_DECL_GROUP("asn", test_wc_AsnCertDecodeCoverage),          \
    TEST_DECL_GROUP("asn", test_wc_AsnCheckSigCoverage),            \
    TEST_DECL_GROUP("asn", test_wc_AsnValidateGmtimeCoverage),      \
    TEST_DECL_GROUP("asn", test_wc_AsnStoreDataCoverage),           \
    TEST_DECL_GROUP("asn", test_wc_AsnPemResidualCoverage),         \
    TEST_DECL_GROUP("asn", test_wc_AsnGetRdnResidualCoverage),      \
    TEST_DECL_GROUP("asn", test_wc_AsnUriNameConstraintCoverage),   \
    TEST_DECL_GROUP("asn", test_wc_AsnDhParamsCoverage),            \
    TEST_DECL_GROUP("asn", test_wc_AsnFormattedTimeCoverage),       \
    TEST_DECL_GROUP("asn", test_wc_AsnSetAlgoCoverage),             \
    TEST_DECL_GROUP("asn", test_wc_AsnDecodePolicyCoverage),        \
    TEST_DECL_GROUP("asn", test_wc_AsnMatchIpSubnetCoverage),       \
    TEST_DECL_GROUP("asn", test_wc_AsnConfirmSigCoverage)

#endif /* WOLFCRYPT_TEST_ASN_H */
