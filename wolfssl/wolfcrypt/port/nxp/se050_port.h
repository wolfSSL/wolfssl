/* se050_port.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifndef _SE050_PORT_H_
#define _SE050_PORT_H_


#include <wolfssl/wolfcrypt/settings.h>

#include "fsl_sss_api.h"

enum {
    SSS_BLOCK_SIZE = 512
};

typedef struct {
    void*  heap;
    byte*  msg;
    word32 used;
    word32 len;
} SE050_HASH_Context;


WOLFSSL_API int wolfcrypt_se050_SetConfig(sss_session_t *pSession, sss_key_store_t *pHostKeyStore, sss_key_store_t *pKeyStore);

int se050_allocate_key(void);

int se050_get_random_number(uint32_t count, uint8_t* rand_out);



int se050_hash_init(SE050_HASH_Context* se050Ctx, void* heap);
int se050_hash_update(SE050_HASH_Context* se050Ctx, const byte* data, word32 len);
int se050_hash_final(SE050_HASH_Context* se050Ctx, byte* hash, size_t digestLen, word32 algo);
void se050_hash_free(SE050_HASH_Context* se050Ctx);



struct Aes;
int se050_aes_set_key(struct Aes* aes, const byte* key, word32 len, const byte* iv, int dir);
int se050_aes_crypt(struct Aes* aes, const byte* in, byte* out, word32 sz, int dir, sss_algorithm_t algorithm);
void se050_aes_free(struct Aes* aes);
//int se050_aes_ctr_crypt(struct Aes* aes, const byte* in, byte* out, word32 sz);



struct ecc_key;
struct WC_RNG;
#ifdef WOLFSSL_SP_MATH
    struct sp_int;
    #define MATH_INT_T struct sp_int
#elif defined(USE_FAST_MATH)
    struct fp_int;
    #define MATH_INT_T struct fp_int
#else
    struct mp_int;
	#define MATH_INT_T struct mp_int
#endif
int se050_ecc_sign_hash_ex(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, struct ecc_key* key);

int se050_ecc_verify_hash_ex(const byte* hash, word32 hashlen, byte* signature,
                             word32 signatureLen, struct ecc_key* key, int* res);

int se050_ecc_create_key(struct ecc_key* key, int keyId, int keySize);
int se050_ecc_shared_secret(struct ecc_key* private_key, struct ecc_key* public_key, byte* out,
                      word32* outlen);
int se050_ecc_free_key(struct ecc_key* key);

struct ed25519_key;
//#include <wolfssl/wolfcrypt/ed25519.h>
int se050_ed25519_create_key(struct ed25519_key* key);
void se050_ed25519_free_key(struct ed25519_key* key);
int se050_ed25519_sign_msg(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, struct ed25519_key* key);

int se050_ed25519_verify_msg(const byte* signature, word32 signatureLen, const byte* msg,
                             word32 msgLen, struct ed25519_key* key, int* res);

#endif /* _SE050_PORT_H_ */
