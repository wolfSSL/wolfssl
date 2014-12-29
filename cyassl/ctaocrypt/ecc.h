/* ecc.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_ECC

#ifndef CTAO_CRYPT_ECC_H
#define CTAO_CRYPT_ECC_H

#include <wolfssl/wolfcrypt/ecc.h>

/* for ecc reverse compatibility */
#ifdef HAVE_ECC
	#define ecc_make_key      wc_ecc_make_key
	#define ecc_shared_secret wc_ecc_shared_secret
	#define ecc_sign_hash     wc_ecc_sign_hash
	#define ecc_verify_hash   wc_ecc_verify_hash
	#define ecc_init          wc_ecc_init
	#define ecc_free          wc_ecc_free
	#define ecc_fp_free       wc_ecc_fp_free
	#define ecc_export_x963   wc_ecc_export_x963
	#define ecc_size          wc_ecc_size
	#define ecc_sig_size      wc_ecc_sig_size
	#define ecc_export_x963_ex      wc_ecc_export_x963_ex
	#define ecc_import_x963         wc_ecc_import_x963
	#define ecc_import_private_key  wc_ecc_import_private_key
	#define ecc_rs_to_sig           wc_ecc_rs_to_sig
	#define ecc_import_raw          wc_ecc_import_raw
	#define ecc_export_private_only wc_ecc_export_private_only

#ifdef HAVE_ECC_ENCRYPT
	/* ecc encrypt */
	#define ecc_ctx_new           wc_ecc_ctx_new
	#define ecc_ctx_free          wc_ecc_ctx_free
	#define ecc_ctx_reset         wc_ecc_ctx_reset
	#define ecc_ctx_get_own_salt  wc_ecc_ctx_get_own_salt
	#define ecc_ctx_set_peer_salt wc_ecc_ctx_set_peer_salt
	#define ecc_ctx_set_info      wc_ecc_ctx_set_info
	#define ecc_encrypt           wc_ecc_encrypt
	#define ecc_decrypt           wc_ecc_decrypt
#endif /* HAVE_ECC_ENCRYPT */
#endif

//
//#include <cyassl/ctaocrypt/types.h>
//#include <cyassl/ctaocrypt/integer.h>
//#include <cyassl/ctaocrypt/random.h>
//
//#ifdef __cplusplus
//    extern "C" {
//#endif
//
//
//enum {
//    ECC_PUBLICKEY  = 1,
//    ECC_PRIVATEKEY = 2,
//    ECC_MAXNAME    = 16,     /* MAX CURVE NAME LENGTH */
//    SIG_HEADER_SZ  =  6,     /* ECC signature header size */
//    ECC_BUFSIZE    = 256,    /* for exported keys temp buffer */
//    ECC_MINSIZE    = 20,     /* MIN Private Key size */
//    ECC_MAXSIZE    = 66      /* MAX Private Key size */
//};
//
//
///* ECC set type defined a NIST GF(p) curve */
//typedef struct {
//    int size;       /* The size of the curve in octets */
//    const char* name;     /* name of this curve */
//    const char* prime;    /* prime that defines the field, curve is in (hex) */
//    const char* Af;       /* fields A param (hex) */
//    const char* Bf;       /* fields B param (hex) */
//    const char* order;    /* order of the curve (hex) */
//    const char* Gx;       /* x coordinate of the base point on curve (hex) */
//    const char* Gy;       /* y coordinate of the base point on curve (hex) */
//} ecc_set_type;
//
//
///* A point on an ECC curve, stored in Jacbobian format such that (x,y,z) =>
//   (x/z^2, y/z^3, 1) when interpreted as affine */
//typedef struct {
//    mp_int x;        /* The x coordinate */
//    mp_int y;        /* The y coordinate */
//    mp_int z;        /* The z coordinate */
//} ecc_point;
//
//
///* An ECC Key */
//typedef struct {
//    int type;           /* Public or Private */
//    int idx;            /* Index into the ecc_sets[] for the parameters of
//                           this curve if -1, this key is using user supplied
//                           curve in dp */
//    const ecc_set_type* dp;     /* domain parameters, either points to NIST
//                                   curves (idx >= 0) or user supplied */
//    ecc_point pubkey;   /* public key */  
//    mp_int    k;        /* private key */
//} ecc_key;
//
//
///* ECC predefined curve sets  */
//extern const ecc_set_type ecc_sets[];
//
//
//CYASSL_API
//int ecc_make_key(RNG* rng, int keysize, ecc_key* key);
//CYASSL_API
//int ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
//                      word32* outlen);
//CYASSL_API
//int ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen, 
//                  RNG* rng, ecc_key* key);
//CYASSL_API
//int ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
//                    word32 hashlen, int* stat, ecc_key* key);
//CYASSL_API
//void ecc_init(ecc_key* key);
//CYASSL_API
//void ecc_free(ecc_key* key);
//CYASSL_API
//void ecc_fp_free(void);
//
//
///* ASN key helpers */
//CYASSL_API
//int ecc_export_x963(ecc_key*, byte* out, word32* outLen);
//CYASSL_API
//int ecc_export_x963_ex(ecc_key*, byte* out, word32* outLen, int compressed);
//    /* extended functionality with compressed option */
//CYASSL_API
//int ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);
//CYASSL_API
//int ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
//                           word32 pubSz, ecc_key* key);
//CYASSL_API
//int ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen);
//CYASSL_API
//int ecc_import_raw(ecc_key* key, const char* qx, const char* qy,
//                   const char* d, const char* curveName);
//
//CYASSL_API
//int ecc_export_private_only(ecc_key* key, byte* out, word32* outLen);
//
///* size helper */
//CYASSL_API
//int ecc_size(ecc_key* key);
//CYASSL_API
//int ecc_sig_size(ecc_key* key);
//
//
//#ifdef HAVE_ECC_ENCRYPT
///* ecc encrypt */
//
//enum ecEncAlgo {
//    ecAES_128_CBC = 1,  /* default */
//    ecAES_256_CBC = 2
//};
//
//enum ecKdfAlgo {
//    ecHKDF_SHA256 = 1,  /* default */
//    ecHKDF_SHA1   = 2
//};
//
//enum ecMacAlgo {
//    ecHMAC_SHA256 = 1,  /* default */
//    ecHMAC_SHA1   = 2
//};
//
//enum {
//    KEY_SIZE_128     = 16,   
//    KEY_SIZE_256     = 32,   
//    IV_SIZE_64       =  8,
//    EXCHANGE_SALT_SZ = 16,  
//    EXCHANGE_INFO_SZ = 23  
//};
//
//enum ecFlags {
//    REQ_RESP_CLIENT = 1,
//    REQ_RESP_SERVER = 2
//};
//
//
//typedef struct ecEncCtx ecEncCtx;
//
//CYASSL_API
//ecEncCtx* ecc_ctx_new(int flags, RNG* rng);
//CYASSL_API
//void ecc_ctx_free(ecEncCtx*);
//CYASSL_API
//int ecc_ctx_reset(ecEncCtx*, RNG*);   /* reset for use again w/o alloc/free */
//
//CYASSL_API
//const byte* ecc_ctx_get_own_salt(ecEncCtx*);
//CYASSL_API
//int ecc_ctx_set_peer_salt(ecEncCtx*, const byte* salt);
//CYASSL_API
//int ecc_ctx_set_info(ecEncCtx*, const byte* info, int sz);
//
//CYASSL_API
//int ecc_encrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
//                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);
//CYASSL_API
//int ecc_decrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
//                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);
//
//#endif /* HAVE_ECC_ENCRYPT */

#ifdef __cplusplus
    }    /* extern "C" */    
#endif

#endif /* CTAO_CRYPT_ECC_H */
#endif /* HAVE_ECC */
