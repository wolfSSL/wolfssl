/* libfcs.h
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

/* Minimal libfcs interface for host build tests. No cryptography is mocked. */

#ifndef WOLFSSL_TEST_ALTERA_FCS_LIBFCS_H
#define WOLFSSL_TEST_ALTERA_FCS_LIBFCS_H

#include "libfcs_osal_types.h"

#define FCS_AES_BLOCK_MODE_CBC 1
#define FCS_AES_BLOCK_MODE_CTR 2
#define FCS_AES_IV_SOURCE_EXTERNAL 0
#define FCS_AES_ENCRYPT 0
#define FCS_AES_DECRYPT 1

#define FCS_ECC_CURVE_NIST_P256      1
#define FCS_ECC_CURVE_NIST_P384      2
#define FCS_ECC_CURVE_BRAINPOOL_P256 3
#define FCS_ECC_CURVE_BRAINPOOL_P384 4

struct fcs_digest_get_req {
    FCS_OSAL_U32 sha_op_mode;
    FCS_OSAL_U32 sha_digest_sz;
    FCS_OSAL_CHAR* src;
    FCS_OSAL_U32 src_len;
    FCS_OSAL_CHAR* digest;
    FCS_OSAL_U32* digest_len;
};

struct fcs_aes_req {
    FCS_OSAL_U32 crypt_mode;
    FCS_OSAL_U32 block_mode;
    FCS_OSAL_U32 iv_source;
    FCS_OSAL_CHAR* iv;
    FCS_OSAL_U32 iv_len;
    FCS_OSAL_CHAR* tag;
    FCS_OSAL_U32 tag_len;
    FCS_OSAL_U32 aad_len;
    FCS_OSAL_CHAR* aad;
    FCS_OSAL_CHAR* input;
    FCS_OSAL_U32 ip_len;
    FCS_OSAL_CHAR* output;
    FCS_OSAL_U32* op_len;
};

struct fcs_ecdsa_req {
    FCS_OSAL_U32 ecc_curve;
    FCS_OSAL_CHAR* src;
    FCS_OSAL_U32 src_len;
    FCS_OSAL_CHAR* dst;
    FCS_OSAL_U32* dst_len;
};

struct fcs_ecdh_req {
    FCS_OSAL_U32 ecc_curve;
    FCS_OSAL_CHAR* pubkey;
    FCS_OSAL_U32 pubkey_len;
    FCS_OSAL_CHAR* shared_secret;
    FCS_OSAL_U32* shared_secret_len;
};

struct fcs_mac_verify_req {
    FCS_OSAL_U32 op_mode;
    FCS_OSAL_U32 dig_sz;
    FCS_OSAL_CHAR* src;
    FCS_OSAL_U32 src_sz;
    FCS_OSAL_CHAR* dst;
    FCS_OSAL_U32* dst_sz;
    FCS_OSAL_U32 user_data_sz;
};

FCS_OSAL_INT libfcs_init(FCS_OSAL_CHAR* loglevel);
FCS_OSAL_INT fcs_open_service_session(FCS_OSAL_UUID* sessionId);
FCS_OSAL_INT fcs_close_service_session(FCS_OSAL_UUID* sessionId);
FCS_OSAL_INT fcs_random_number_ext(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_CHAR* rng, FCS_OSAL_U32 rngSz);
FCS_OSAL_INT fcs_import_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_CHAR* key, FCS_OSAL_INT keySz, FCS_OSAL_CHAR* status,
    FCS_OSAL_UINT* statusSz);
FCS_OSAL_INT fcs_create_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_CHAR* key, FCS_OSAL_INT keySz, FCS_OSAL_CHAR* status,
    FCS_OSAL_UINT statusSz);
FCS_OSAL_INT fcs_remove_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 keyId);
FCS_OSAL_INT fcs_get_digest(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_digest_get_req* req);
FCS_OSAL_INT fcs_aes_crypt(FCS_OSAL_UUID* sessionId, FCS_OSAL_U32 keyId,
    FCS_OSAL_U32 contextId, struct fcs_aes_req* req);
FCS_OSAL_INT fcs_ecdsa_get_pub_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId, FCS_OSAL_U32 curve,
    FCS_OSAL_CHAR* publicKey, FCS_OSAL_U32* publicKeySz);
FCS_OSAL_INT fcs_ecdsa_hash_sign(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_ecdsa_req* req);
FCS_OSAL_INT fcs_ecdh_request(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 keyId, FCS_OSAL_U32 contextId, struct fcs_ecdh_req* req);
FCS_OSAL_INT fcs_mac_verify(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_mac_verify_req* req);

#endif /* WOLFSSL_TEST_ALTERA_FCS_LIBFCS_H */
