/* atmel.h
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _ATECC508_H_
#define _ATECC508_H_

#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC_PKCB)
    #undef  SHA_BLOCK_SIZE
    #define SHA_BLOCK_SIZE  SHA_BLOCK_SIZE_REMAP
    #include <cryptoauthlib.h>
    #include <tls/atcatls.h>
    #include <atcacert/atcacert_client.h>
    #include <tls/atcatls_cfg.h>
    #undef SHA_BLOCK_SIZE
#endif

/* ATECC508A only supports ECC-256 */
#define ATECC_KEY_SIZE      (32)
#define ATECC_PUBKEY_SIZE   (ATECC_KEY_SIZE*2) /* X and Y */
#define ATECC_SIG_SIZE      (ATECC_KEY_SIZE*2) /* R and S */
#ifndef ATECC_MAX_SLOT
#define ATECC_MAX_SLOT      (0x7) /* Only use 0-7 */
#endif
#define ATECC_INVALID_SLOT  (-1)

/* ATECC_KEY_SIZE required for ecc.h */
#include <wolfssl/wolfcrypt/ecc.h>

struct WOLFSSL;
struct WOLFSSL_CTX;
struct WOLFSSL_X509_STORE_CTX;
struct ecc_key;

/* Cert Structure */
typedef struct t_atcert {
	uint32_t signer_ca_size;
	uint8_t signer_ca[512];
	uint8_t signer_ca_pubkey[64];
	uint32_t end_user_size;
	uint8_t end_user[512];
	uint8_t end_user_pubkey[64];
} t_atcert;

extern t_atcert atcert;

/* Amtel port functions */
void atmel_init(void);
void atmel_finish(void);
int  atmel_get_random_number(uint32_t count, uint8_t* rand_out);
int atmel_get_random_block(unsigned char* output, unsigned int sz);
long atmel_get_curr_time_and_date(long* tm);

#ifdef WOLFSSL_ATECC508A

enum atmelSlotType {
    ATMEL_SLOT_ANY,
    ATMEL_SLOT_ENCKEY,
    ATMEL_SLOT_DEVICE,
    ATMEL_SLOT_ECDHE,
    ATMEL_SLOT_ECDHEPUB,
};

int  atmel_ecc_alloc(int slotType);
void atmel_ecc_free(int slot);

typedef int  (*atmel_slot_alloc_cb)(int);
typedef void (*atmel_slot_dealloc_cb)(int);
int atmel_set_slot_allocator(atmel_slot_alloc_cb alloc, 
    atmel_slot_dealloc_cb dealloc);

#endif /* WOLFSSL_ATECC508A */

#ifdef HAVE_PK_CALLBACKS
    int atcatls_create_key_cb(struct WOLFSSL* ssl, struct ecc_key* key, word32 keySz,
        int ecc_curve, void* ctx);
    int atcatls_create_pms_cb(struct WOLFSSL* ssl, struct ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx);
    int atcatls_sign_certificate_cb(struct WOLFSSL* ssl, const byte* in, word32 inSz,
        byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx);
    int atcatls_verify_signature_cb(struct WOLFSSL* ssl, const byte* sig, word32 sigSz,
        const byte* hash, word32 hashSz, const byte* key, word32 keySz, int* result,
        void* ctx);

    int atcatls_set_callbacks(struct WOLFSSL_CTX* ctx);
    int atcatls_set_callback_ctx(struct WOLFSSL* ssl, void* user_ctx);
#endif

#endif /* _ATECC508_H_ */
