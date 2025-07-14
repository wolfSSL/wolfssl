/* wc_mlkem.h
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

/*!
    \file wolfssl/wolfcrypt/wc_mlkem.h
*/


#ifndef WOLF_CRYPT_WC_MLKEM_H
#define WOLF_CRYPT_WC_MLKEM_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/mlkem.h>

#ifdef WOLFSSL_HAVE_MLKEM

#ifdef WOLFSSL_KYBER_NO_MAKE_KEY
    #define WOLFSSL_MLKEM_NO_MAKE_KEY
#endif
#ifdef WOLFSSL_KYBER_NO_ENCAPSULATE
    #define WOLFSSL_MLKEM_NO_ENCAPSULATE
#endif
#ifdef WOLFSSL_KYBER_NO_DECAPSULATE
    #define WOLFSSL_MLKEM_NO_DECAPSULATE
#endif

#ifdef noinline
    #define MLKEM_NOINLINE noinline
#elif defined(_MSC_VER)
    #define MLKEM_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
    #define MLKEM_NOINLINE __attribute__((noinline))
#else
    #define MLKEM_NOINLINE
#endif

enum {
    /* Flags of Kyber keys. */
    MLKEM_FLAG_PRIV_SET = 0x0001,
    MLKEM_FLAG_PUB_SET  = 0x0002,
    MLKEM_FLAG_BOTH_SET = 0x0003,
    MLKEM_FLAG_H_SET    = 0x0004,
    MLKEM_FLAG_A_SET    = 0x0008,

    /* 2 bits of random used to create noise value. */
    MLKEM_CBD_ETA2      = 2,
    /* 3 bits of random used to create noise value. */
    MLKEM_CBD_ETA3      = 3,

    /* Number of bits to compress to. */
    MLKEM_COMP_4BITS    =  4,
    MLKEM_COMP_5BITS    =  5,
    MLKEM_COMP_10BITS   = 10,
    MLKEM_COMP_11BITS   = 11,
};


/* SHAKE128 rate. */
#define XOF_BLOCK_SIZE      168

/* Modulus of co-efficients of polynomial. */
#define MLKEM_Q             3329


/* Kyber-512 parameters */
#ifdef WOLFSSL_WC_ML_KEM_512
/* Number of bits of random to create noise from. */
#define WC_ML_KEM_512_ETA1       MLKEM_CBD_ETA3
#endif /* WOLFSSL_WC_ML_KEM_512 */

/* Kyber-768 parameters */
#ifdef WOLFSSL_WC_ML_KEM_768
/* Number of bits of random to create noise from. */
#define WC_ML_KEM_768_ETA1       MLKEM_CBD_ETA2
#endif /* WOLFSSL_WC_ML_KEM_768 */

/* Kyber-1024 parameters */
#ifdef WOLFSSL_WC_ML_KEM_1024
/* Number of bits of random to create noise from. */
#define WC_ML_KEM_1024_ETA1      MLKEM_CBD_ETA2
#endif /* WOLFSSL_KYBER1024 */



/* The data type of the hash function. */
#define MLKEM_HASH_T    wc_Sha3

/* The data type of the pseudo-random function. */
#define MLKEM_PRF_T     wc_Shake

/* ML-KEM key. */
struct MlKemKey {
    /* Type of key: WC_ML_KEM_512, WC_ML_KEM_768, WC_ML_KEM_1024 */
    int type;
    /* Dynamic memory allocation hint. */
    void* heap;
#if defined(WOLF_CRYPTO_CB)
    /* Device Id. */
    int devId;
#endif
    /* Flags indicating what is stored in the key. */
    int flags;

    /* A pseudo-random function object. */
    MLKEM_HASH_T hash;
    /* A pseudo-random function object. */
    MLKEM_PRF_T prf;

    /* Private key as a vector. */
    sword16 priv[WC_ML_KEM_MAX_K * MLKEM_N];
    /* Public key as a vector. */
    sword16 pub[WC_ML_KEM_MAX_K * MLKEM_N];
    /* Public seed. */
    byte pubSeed[WC_ML_KEM_SYM_SZ];
    /* Public hash - hash of encoded public key. */
    byte h[WC_ML_KEM_SYM_SZ];
    /* Randomizer for decapsulation. */
    byte z[WC_ML_KEM_SYM_SZ];
#ifdef WOLFSSL_MLKEM_CACHE_A
    /* A matrix from key generation. */
    sword16 a[WC_ML_KEM_MAX_K * WC_ML_KEM_MAX_K * MLKEM_N];
#endif
};

#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_LOCAL
void mlkem_init(void);

#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
WOLFSSL_LOCAL
void mlkem_keygen(sword16* priv, sword16* pub, sword16* e, const sword16* a,
    int kp);
#else
WOLFSSL_LOCAL
int mlkem_keygen_seeds(sword16* priv, sword16* pub, MLKEM_PRF_T* prf,
    sword16* e, int kp, byte* seed, byte* noiseSeed);
#endif
#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
WOLFSSL_LOCAL
void mlkem_encapsulate(const sword16* pub, sword16* bp, sword16* v,
    const sword16* at, sword16* sp, const sword16* ep, const sword16* epp,
    const sword16* m, int kp);
#else
WOLFSSL_LOCAL
int mlkem_encapsulate_seeds(const sword16* pub, MLKEM_PRF_T* prf, sword16* bp,
    sword16* tp, sword16* sp, int kp, const byte* msg, byte* seed,
    byte* coins);
#endif
WOLFSSL_LOCAL
void mlkem_decapsulate(const sword16* priv, sword16* mp, sword16* bp,
    const sword16* v, int kp);

WOLFSSL_LOCAL
int mlkem_gen_matrix(MLKEM_PRF_T* prf, sword16* a, int kp, byte* seed,
    int transposed);
WOLFSSL_LOCAL
int mlkem_get_noise(MLKEM_PRF_T* prf, int kp, sword16* vec1, sword16* vec2,
    sword16* poly, byte* seed);

#if defined(USE_INTEL_SPEEDUP) || \
        (defined(WOLFSSL_ARMASM) && defined(__aarch64__))
WOLFSSL_LOCAL
int mlkem_kdf(byte* seed, int seedLen, byte* out, int outLen);
#endif
WOLFSSL_LOCAL
void mlkem_hash_init(MLKEM_HASH_T* hash);
WOLFSSL_LOCAL
int mlkem_hash_new(MLKEM_HASH_T* hash, void* heap, int devId);
WOLFSSL_LOCAL
void mlkem_hash_free(MLKEM_HASH_T* hash);
WOLFSSL_LOCAL
int mlkem_hash256(wc_Sha3* hash, const byte* data, word32 dataLen, byte* out);
WOLFSSL_LOCAL
int mlkem_hash512(wc_Sha3* hash, const byte* data1, word32 data1Len,
    const byte* data2, word32 data2Len, byte* out);

WOLFSSL_LOCAL
int mlkem_derive_secret(MLKEM_PRF_T* prf, const byte* z, const byte* ct,
    word32 ctSz, byte* ss);

WOLFSSL_LOCAL
void mlkem_prf_init(MLKEM_PRF_T* prf);
WOLFSSL_LOCAL
int mlkem_prf_new(MLKEM_PRF_T* prf, void* heap, int devId);
WOLFSSL_LOCAL
void mlkem_prf_free(MLKEM_PRF_T* prf);

WOLFSSL_LOCAL
int mlkem_cmp(const byte* a, const byte* b, int sz);

WOLFSSL_LOCAL
void mlkem_vec_compress_10(byte* r, sword16* v, unsigned int kp);
WOLFSSL_LOCAL
void mlkem_vec_compress_11(byte* r, sword16* v);
WOLFSSL_LOCAL
void mlkem_vec_decompress_10(sword16* v, const unsigned char* b,
    unsigned int kp);
WOLFSSL_LOCAL
void mlkem_vec_decompress_11(sword16* v, const unsigned char* b);

WOLFSSL_LOCAL
void mlkem_compress_4(byte* b, sword16* p);
WOLFSSL_LOCAL
void mlkem_compress_5(byte* b, sword16* p);
WOLFSSL_LOCAL
void mlkem_decompress_4(sword16* p, const unsigned char* b);
WOLFSSL_LOCAL
void mlkem_decompress_5(sword16* p, const unsigned char* b);

WOLFSSL_LOCAL
void mlkem_from_msg(sword16* p, const byte* msg);
WOLFSSL_LOCAL
void mlkem_to_msg(byte* msg, sword16* p);
WOLFSSL_LOCAL
void mlkem_from_bytes(sword16* p, const byte* b, int k);
WOLFSSL_LOCAL
void mlkem_to_bytes(byte* b, sword16* p, int k);

#ifdef USE_INTEL_SPEEDUP
WOLFSSL_LOCAL
void mlkem_keygen_avx2(sword16* priv, sword16* pub, sword16* e,
    const sword16* a, int kp);
WOLFSSL_LOCAL
void mlkem_encapsulate_avx2(const sword16* pub, sword16* bp, sword16* v,
    const sword16* at, sword16* sp, const sword16* ep, const sword16* epp,
    const sword16* m, int kp);
WOLFSSL_LOCAL
void mlkem_decapsulate_avx2(const sword16* priv, sword16* mp, sword16* bp,
    const sword16* v, int kp);

WOLFSSL_LOCAL
unsigned int mlkem_rej_uniform_n_avx2(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
WOLFSSL_LOCAL
unsigned int mlkem_rej_uniform_avx2(sword16* p, unsigned int len, const byte* r,
    unsigned int rLen);
WOLFSSL_LOCAL
void mlkem_redistribute_21_rand_avx2(const word64* s, byte* r0, byte* r1,
    byte* r2, byte* r3);
void mlkem_redistribute_17_rand_avx2(const word64* s, byte* r0, byte* r1,
    byte* r2, byte* r3);
void mlkem_redistribute_16_rand_avx2(const word64* s, byte* r0, byte* r1,
    byte* r2, byte* r3);
void mlkem_redistribute_8_rand_avx2(const word64* s, byte* r0, byte* r1,
    byte* r2, byte* r3);

WOLFSSL_LOCAL
void mlkem_sha3_128_blocksx4_seed_avx2(word64* s, byte* seed);
WOLFSSL_LOCAL
void mlkem_sha3_256_blocksx4_seed_avx2(word64* s, byte* seed);

WOLFSSL_LOCAL
void mlkem_cbd_eta2_avx2(sword16* p, const byte* r);
WOLFSSL_LOCAL
void mlkem_cbd_eta3_avx2(sword16* p, const byte* r);

WOLFSSL_LOCAL
void mlkem_from_msg_avx2(sword16* p, const byte* msg);
WOLFSSL_LOCAL
void mlkem_to_msg_avx2(byte* msg, sword16* p);

WOLFSSL_LOCAL
void mlkem_from_bytes_avx2(sword16* p, const byte* b);
WOLFSSL_LOCAL
void mlkem_to_bytes_avx2(byte* b, sword16* p);

WOLFSSL_LOCAL
void mlkem_compress_10_avx2(byte* r, const sword16* p, int n);
WOLFSSL_LOCAL
void mlkem_decompress_10_avx2(sword16* p, const byte* r, int n);
WOLFSSL_LOCAL
void mlkem_compress_11_avx2(byte* r, const sword16* p, int n);
WOLFSSL_LOCAL
void mlkem_decompress_11_avx2(sword16* p, const byte* r, int n);

WOLFSSL_LOCAL
void mlkem_compress_4_avx2(byte* r, const sword16* p);
WOLFSSL_LOCAL
void mlkem_decompress_4_avx2(sword16* p, const byte* r);
WOLFSSL_LOCAL
void mlkem_compress_5_avx2(byte* r, const sword16* p);
WOLFSSL_LOCAL
void mlkem_decompress_5_avx2(sword16* p, const byte* r);


WOLFSSL_LOCAL
int mlkem_cmp_avx2(const byte* a, const byte* b, int sz);
#elif defined(__aarch64__) && defined(WOLFSSL_ARMASM)
WOLFSSL_LOCAL void mlkem_ntt(sword16* r);
WOLFSSL_LOCAL void mlkem_invntt(sword16* r);
WOLFSSL_LOCAL void mlkem_ntt_sqrdmlsh(sword16* r);
WOLFSSL_LOCAL void mlkem_invntt_sqrdmlsh(sword16* r);
WOLFSSL_LOCAL void mlkem_basemul_mont(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_basemul_mont_add(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_add_reduce(sword16* r, const sword16* a);
WOLFSSL_LOCAL void mlkem_add3_reduce(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_rsub_reduce(sword16* r, const sword16* a);
WOLFSSL_LOCAL void mlkem_to_mont(sword16* p);
WOLFSSL_LOCAL void mlkem_to_mont_sqrdmlsh(sword16* p);
WOLFSSL_LOCAL void mlkem_sha3_blocksx3_neon(word64* state);
WOLFSSL_LOCAL void mlkem_shake128_blocksx3_seed_neon(word64* state, byte* seed);
WOLFSSL_LOCAL void mlkem_shake256_blocksx3_seed_neon(word64* state, byte* seed);
WOLFSSL_LOCAL unsigned int mlkem_rej_uniform_neon(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
WOLFSSL_LOCAL int mlkem_cmp_neon(const byte* a, const byte* b, int sz);
WOLFSSL_LOCAL void mlkem_csubq_neon(sword16* p);
WOLFSSL_LOCAL void mlkem_from_msg_neon(sword16* p, const byte* msg);
WOLFSSL_LOCAL void mlkem_to_msg_neon(byte* msg, sword16* p);
#elif defined(WOLFSSL_ARMASM_THUMB2) && defined(WOLFSSL_ARMASM)
#define mlkem_ntt                   mlkem_thumb2_ntt
#define mlkem_invntt                mlkem_thumb2_invntt
#define mlkem_basemul_mont          mlkem_thumb2_basemul_mont
#define mlkem_basemul_mont_add      mlkem_thumb2_basemul_mont_add
#define mlkem_rej_uniform_c         mlkem_thumb2_rej_uniform

WOLFSSL_LOCAL void mlkem_thumb2_ntt(sword16* r);
WOLFSSL_LOCAL void mlkem_thumb2_invntt(sword16* r);
WOLFSSL_LOCAL void mlkem_thumb2_basemul_mont(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_thumb2_basemul_mont_add(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_thumb2_csubq(sword16* p);
WOLFSSL_LOCAL unsigned int mlkem_thumb2_rej_uniform(sword16* p,
    unsigned int len, const byte* r, unsigned int rLen);
#elif defined(WOLFSSL_ARMASM)
#define mlkem_ntt                   mlkem_arm32_ntt
#define mlkem_invntt                mlkem_arm32_invntt
#define mlkem_basemul_mont          mlkem_arm32_basemul_mont
#define mlkem_basemul_mont_add      mlkem_arm32_basemul_mont_add
#define mlkem_rej_uniform_c         mlkem_arm32_rej_uniform

WOLFSSL_LOCAL void mlkem_arm32_ntt(sword16* r);
WOLFSSL_LOCAL void mlkem_arm32_invntt(sword16* r);
WOLFSSL_LOCAL void mlkem_arm32_basemul_mont(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_arm32_basemul_mont_add(sword16* r, const sword16* a,
    const sword16* b);
WOLFSSL_LOCAL void mlkem_arm32_csubq(sword16* p);
WOLFSSL_LOCAL unsigned int mlkem_arm32_rej_uniform(sword16* p, unsigned int len,
    const byte* r, unsigned int rLen);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* WOLF_CRYPT_WC_MLKEM_H */
