/* test_tsp.h
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

#ifndef WOLFCRYPT_TEST_TSP_H
#define WOLFCRYPT_TEST_TSP_H

#include <tests/api/api_decl.h>

int test_wc_TspRequest_Init(void);
int test_wc_TspRequest_SetHashType(void);
int test_wc_TspRequest_GetHashType(void);
int test_wc_TspRequest_GetSetHash(void);
int test_wc_TspRequest_GetSetNonce(void);
int test_wc_TspGenerateNonce(void);
int test_wc_TspRequest_GetSetPolicy(void);
int test_wc_TspRequest_GetSetCertReq(void);
int test_wc_TspTstInfo_GetSetSerial(void);
int test_wc_TspRequest_Encode(void);
int test_wc_TspRequest_Decode(void);
int test_wc_TspTstInfo_Init(void);
int test_wc_TspTstInfo_Getters(void);
int test_wc_TspTstInfo_Setters(void);
int test_wc_TspTstInfo_Encode(void);
int test_wc_TspTstInfo_Decode(void);
int test_wc_TspTstInfo_CheckGenTime(void);
int test_wc_TspTstInfo_GetSetGenTimeAsTime(void);
int test_wc_TspResponse_Init(void);
int test_wc_TspGetSetStatus(void);
int test_wc_TspStrings(void);
int test_wc_TspResponse_Encode(void);
int test_wc_TspResponse_Decode(void);
int test_wc_TspTstInfo_CheckRequest(void);
int test_wc_TspTstInfo_CheckTsaName(void);
int test_wc_TspTstInfo_SignWithPkcs7(void);
int test_wc_TspTstInfo_SignWithPkcs7_create(void);
int test_wc_TspTstInfo_SignWithPkcs7_signer_required(void);
int test_wc_TspTstInfo_SignWithPkcs7_hash_and_buffer(void);
int test_wc_TspTstInfo_Sign(void);
int test_wc_TspTstInfo_SignWithPkcs7_attribs(void);
int test_wc_TspTstInfo_SignWithPkcs7_attribs_verify(void);
int test_wc_TspTstInfo_SignWithPkcs7_attribs_sha384(void);
int test_wc_TspTstInfo_VerifyWithPKCS7(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_modified(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_no_signer(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_not_tst(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_bad_eku(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_bad_ku(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_extra_eku(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_nocerts(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_nocerts_supplied(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_ess_no_attrib(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_hash(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_alg(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_ess_v1(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_mismatch(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_unsupported(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_bad_enc(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_dirname(void);
int test_wc_TspTstInfo_VerifyWithPKCS7_ecc(void);
int test_wc_TspResponse_Verify(void);
int test_wc_TspResponse_Verify_wrong_cert(void);
int test_wc_TspResponse_Verify_status(void);
int test_wc_TspResponse_Verify_modified(void);
int test_wc_TspResponse_Verify_nocerts(void);
int test_wc_TspResponse_VerifyData(void);
int test_wc_TspTstInfo_SetFromRequest(void);

#define TEST_TSP_DECLS                                       \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_Init),         \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_SetHashType),  \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_GetHashType),  \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_GetSetHash),   \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_GetSetNonce),  \
    TEST_DECL_GROUP("tsp", test_wc_TspGenerateNonce),        \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_GetSetPolicy), \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_GetSetCertReq), \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_Encode),        \
    TEST_DECL_GROUP("tsp", test_wc_TspRequest_Decode),        \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Init),         \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_GetSetSerial), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Getters),      \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Setters),      \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Encode),        \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Decode),       \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_CheckGenTime),        \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_GetSetGenTimeAsTime), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Init),        \
    TEST_DECL_GROUP("tsp", test_wc_TspGetSetStatus),         \
    TEST_DECL_GROUP("tsp", test_wc_TspStrings),              \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Encode),       \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Decode),       \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_CheckRequest),         \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_CheckTsaName),         \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7),          \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_create),   \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_signer_required), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_hash_and_buffer), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_Sign),   \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_attribs),  \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_attribs_verify), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SignWithPkcs7_attribs_sha384), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7),          \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_modified),   \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_no_signer),  \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_not_tst),    \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_bad_eku),    \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_bad_ku),     \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_extra_eku),  \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_nocerts),    \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_nocerts_supplied), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_ess_no_attrib), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_hash), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_ess_bad_alg), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_ess_v1),     \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name),  \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_mismatch), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_unsupported), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_bad_enc), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_tsa_name_dirname), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_VerifyWithPKCS7_ecc),       \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Verify), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Verify_wrong_cert), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Verify_status), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Verify_modified), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_Verify_nocerts), \
    TEST_DECL_GROUP("tsp", test_wc_TspResponse_VerifyData), \
    TEST_DECL_GROUP("tsp", test_wc_TspTstInfo_SetFromRequest)

#endif /* WOLFCRYPT_TEST_TSP_H */
