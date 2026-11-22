/* test_mlkem.h
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

#ifndef WOLFCRYPT_TEST_MLKEM_H
#define WOLFCRYPT_TEST_MLKEM_H

#include <tests/api/api_decl.h>

int test_wc_mlkem_make_key_kats(void);
int test_wc_MlKemKey_seed_service_indicator(void);
int test_wc_mlkem_encapsulate_kats(void);
int test_wc_mlkem_decapsulate_kats(void);
int test_wc_mlkem_decapsulate_pubonly_fails(void);
int test_wc_mlkem_decap_fo_reject(void);
int test_wc_mlkem_decode_privkey_bad_pubhash(void);
int test_wc_MlkemFeatureCoverage(void);
int test_wc_MlkemDecisionCoverage(void);
int test_wc_mlkem_init_id_decision(void);
int test_wc_mlkem_init_label_decision(void);
int test_wc_mlkem_encapsulate_pubkey_unset_decision(void);
int test_wc_mlkem_encode_key_len_decision(void);
int test_wc_mlkem_cb_free(void);
int test_wc_mlkem_cb_pending_rejected(void);
int test_wc_mlkem_decapsulate_id_key(void);
int test_wc_mlkem_encapsulate_id_key(void);
int test_wc_mlkem_decode_pubkey_refused_save(void);
int test_wc_mlkem_decode_reused_key(void);
int test_wc_mlkem_decode_alloc_fail(void);
int test_wc_mlkem_make_key_id_dev(void);
int test_wc_mlkem_operation_cleanup(void);

/* The key-pair test is FIPS v7 (or WOLFSSL_VALIDATE_MLKEM_KEYGEN) only, and
 * allocates its buffer only in small-stack builds. */
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_NO_ML_KEM) && \
    !defined(WOLFSSL_NO_ML_KEM_768) && defined(WC_DECLARE_VAR_IS_HEAP_ALLOC) && \
    (FIPS_VERSION3_GE(7,0,0) || defined(WOLFSSL_VALIDATE_MLKEM_KEYGEN)) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY) && !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLF_CRYPTO_CB_ONLY_MLKEM) && !defined(WC_NO_RNG)
#define MLKEM_PCT_OOM_TEST
int test_wc_mlkem_pct_alloc_fail(void);
#define TEST_MLKEM_PCT_OOM_DECL \
    , TEST_DECL_GROUP("mlkem", test_wc_mlkem_pct_alloc_fail)
#else
#define TEST_MLKEM_PCT_OOM_DECL
#endif

#define TEST_MLKEM_DECLS                                                \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_make_key_kats),              \
    TEST_DECL_GROUP("mlkem", test_wc_MlKemKey_seed_service_indicator),  \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_encapsulate_kats),           \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decapsulate_kats),           \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decapsulate_pubonly_fails),  \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decap_fo_reject),            \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decode_privkey_bad_pubhash), \
    TEST_DECL_GROUP("mlkem", test_wc_MlkemFeatureCoverage),             \
    TEST_DECL_GROUP("mlkem", test_wc_MlkemDecisionCoverage),            \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_init_id_decision),           \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_init_label_decision),        \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_encapsulate_pubkey_unset_decision), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_encode_key_len_decision), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_cb_free),                    \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_cb_pending_rejected),        \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decapsulate_id_key),         \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_encapsulate_id_key),         \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decode_pubkey_refused_save), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decode_reused_key), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_decode_alloc_fail), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_make_key_id_dev), \
    TEST_DECL_GROUP("mlkem", test_wc_mlkem_operation_cleanup)           \
    TEST_MLKEM_PCT_OOM_DECL

#endif /* WOLFCRYPT_TEST_MLKEM_H */
