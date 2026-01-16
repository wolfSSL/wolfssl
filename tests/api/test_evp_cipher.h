/* test_evp_cipher.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_EVP_CIPHER_H
#define WOLFCRYPT_TEST_EVP_CIPHER_H

#include <tests/api/api_decl.h>

int test_wolfSSL_EVP_CIPHER_CTX(void);
int test_wolfSSL_EVP_CIPHER_CTX_iv_length(void);
int test_wolfSSL_EVP_CIPHER_CTX_key_length(void);
int test_wolfSSL_EVP_CIPHER_CTX_set_iv(void);
int test_wolfSSL_EVP_get_cipherbynid(void);
int test_wolfSSL_EVP_CIPHER_block_size(void);
int test_wolfSSL_EVP_CIPHER_iv_length(void);
int test_wolfSSL_EVP_CipherUpdate_Null(void);
int test_wolfSSL_EVP_CIPHER_type_string(void);
int test_wolfSSL_EVP_BytesToKey(void);
int test_wolfSSL_EVP_Cipher_extra(void);
int test_wolfSSL_EVP_X_STATE(void);
int test_wolfSSL_EVP_X_STATE_LEN(void);
int test_wolfSSL_EVP_aes_256_gcm(void);
int test_wolfSSL_EVP_aes_192_gcm(void);
int test_wolfSSL_EVP_aes_128_gcm(void);
int test_evp_cipher_aes_gcm(void);
int test_wolfssl_EVP_aes_gcm(void);
int test_wolfssl_EVP_aes_gcm_AAD_2_parts(void);
int test_wolfssl_EVP_aes_gcm_zeroLen(void);
int test_wolfSSL_EVP_aes_256_ccm(void);
int test_wolfSSL_EVP_aes_192_ccm(void);
int test_wolfSSL_EVP_aes_128_ccm(void);
int test_wolfssl_EVP_aes_ccm(void);
int test_wolfssl_EVP_aes_ccm_zeroLen(void);
int test_wolfssl_EVP_chacha20(void);
int test_wolfssl_EVP_chacha20_poly1305(void);
int test_wolfssl_EVP_aria_gcm(void);
int test_wolfssl_EVP_sm4_ecb(void);
int test_wolfssl_EVP_sm4_cbc(void);
int test_wolfssl_EVP_sm4_ctr(void);
int test_wolfssl_EVP_sm4_gcm_zeroLen(void);
int test_wolfssl_EVP_sm4_gcm(void);
int test_wolfssl_EVP_sm4_ccm_zeroLen(void);
int test_wolfssl_EVP_sm4_ccm(void);
int test_wolfSSL_EVP_rc4(void);
int test_wolfSSL_EVP_enc_null(void);
int test_wolfSSL_EVP_rc2_cbc(void);
int test_wolfSSL_EVP_mdc2(void);

#define TEST_EVP_CIPHER_DECLS                                               \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_CTX),             \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_CTX_iv_length),   \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_CTX_key_length),  \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_CTX_set_iv),      \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_get_cipherbynid),        \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_block_size),      \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_iv_length),       \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CipherUpdate_Null),      \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_CIPHER_type_string),     \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_BytesToKey),             \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_Cipher_extra),           \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_X_STATE),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_X_STATE_LEN),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_256_gcm),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_192_gcm),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_128_gcm),            \
    TEST_DECL_GROUP("evp_cipher", test_evp_cipher_aes_gcm),                 \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aes_gcm),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aes_gcm_AAD_2_parts),    \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aes_gcm_zeroLen),        \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_256_ccm),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_192_ccm),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_aes_128_ccm),            \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aes_ccm),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aes_ccm_zeroLen),        \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_chacha20),               \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_chacha20_poly1305),      \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_aria_gcm),               \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_ecb),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_cbc),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_ctr),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_gcm_zeroLen),        \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_gcm),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_ccm_zeroLen),        \
    TEST_DECL_GROUP("evp_cipher", test_wolfssl_EVP_sm4_ccm),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_rc4),                    \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_enc_null),               \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_rc2_cbc),                \
    TEST_DECL_GROUP("evp_cipher", test_wolfSSL_EVP_mdc2)

#endif /* WOLFCRYPT_TEST_EVP_CIPHER_H */
