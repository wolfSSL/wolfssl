/* wc_mlkem.c
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

/* Implementation based on FIPS 203:
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
 *
 * Original implementation based on NIST 3rd Round submission package.
 * See link at:
 *   https://csrc.nist.gov/Projects/post-quantum-cryptography/
 *   post-quantum-cryptography-standardization/round-3-submissions
 */

/* Possible Kyber options:
 *
 * WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM                                  Default: OFF
 *   Uses less dynamic memory to perform key generation.
 *   Has a small performance trade-off.
 *   Only usable with C implementation.
 *
 * WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM                              Default: OFF
 *   Uses less dynamic memory to perform encapsulation.
 *   Affects decapsulation too as encapsulation called.
 *   Has a small performance trade-off.
 *   Only usable with C implementation.
 *
 * WOLFSSL_MLKEM_NO_MAKE_KEY                                        Default: OFF
 *   Disable the make key or key generation API.
 *   Reduces the code size.
 *   Turn on when only doing encapsulation.
 *
 * WOLFSSL_MLKEM_NO_ENCAPSULATE                                     Default: OFF
 *   Disable the encapsulation API.
 *   Reduces the code size.
 *   Turn on when doing make key/decapsulation.
 *
 * WOLFSSL_MLKEM_NO_DECAPSULATE                                     Default: OFF
 *   Disable the decapsulation API.
 *   Reduces the code size.
 *   Turn on when only doing encapsulation.
 *
 * WOLFSSL_MLKEM_CACHE_A                                           Default: OFF
 *   Stores the matrix A during key generation for use in encapsulation when
 *   performing decapsulation.
 *   KyberKey is 8KB larger but decapsulation is significantly faster.
 *   Turn on when performing make key and decapsualtion with same object.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WC_MLKEM_NO_ASM
    #undef USE_INTEL_SPEEDUP
    #undef WOLFSSL_ARMASM
    #undef WOLFSSL_RISCV_ASM
#endif

#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(USE_INTEL_SPEEDUP) || \
    (defined(__aarch64__) && defined(WOLFSSL_ARMASM))
    #if defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
        defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)
        #error "Can't use small memory with assembly optimized code"
    #endif
#endif
#if defined(WOLFSSL_MLKEM_CACHE_A)
    #if defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM) || \
        defined(WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM)
        #error "Can't cache A with small memory code"
    #endif
#endif

#if defined(WOLFSSL_MLKEM_NO_MAKE_KEY) && \
    defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
    #error "No ML-KEM operations to be built."
#endif

#ifdef WOLFSSL_WC_MLKEM

/******************************************************************************/

/* Use SHA3-256 to generate 32-bytes of hash. */
#define MLKEM_HASH_H            mlkem_hash256
/* Use SHA3-512 to generate 64-bytes of hash. */
#define MLKEM_HASH_G            mlkem_hash512
/* Use SHAKE-256 as a key derivation function (KDF). */
#if defined(USE_INTEL_SPEEDUP) || \
        (defined(WOLFSSL_ARMASM) && defined(__aarch64__))
    #define MLKEM_KDF               mlkem_kdf
#else
    #define MLKEM_KDF               wc_Shake256Hash
#endif

/******************************************************************************/

/* Declare variable to make compiler not optimize code in mlkem_from_msg(). */
volatile sword16 mlkem_opt_blocker = 0;

/******************************************************************************/

/**
 * Initialize the Kyber key.
 *
 * @param  [in]   type   Type of key:
 *                         WC_ML_KEM_512, WC_ML_KEM_768, WC_ML_KEM_1024,
 *                         KYBER512, KYBER768, KYBER1024.
 * @param  [out]  key    Kyber key object to initialize.
 * @param  [in]   heap   Dynamic memory hint.
 * @param  [in]   devId  Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or type is unrecognized.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId)
{
    int ret = 0;

    /* Validate key. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Validate type. */
        switch (type) {
    #ifndef WOLFSSL_NO_ML_KEM
        case WC_ML_KEM_512:
        #ifndef WOLFSSL_WC_ML_KEM_512
            /* Code not compiled in for Kyber-512. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
        case WC_ML_KEM_768:
        #ifndef WOLFSSL_WC_ML_KEM_768
            /* Code not compiled in for Kyber-768. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
        case WC_ML_KEM_1024:
        #ifndef WOLFSSL_WC_ML_KEM_1024
            /* Code not compiled in for Kyber-1024. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
    #endif
    #ifdef WOLFSSL_MLKEM_KYBER
        case KYBER512:
        #ifndef WOLFSSL_KYBER512
            /* Code not compiled in for Kyber-512. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
        case KYBER768:
        #ifndef WOLFSSL_KYBER768
            /* Code not compiled in for Kyber-768. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
        case KYBER1024:
        #ifndef WOLFSSL_KYBER1024
            /* Code not compiled in for Kyber-1024. */
            ret = NOT_COMPILED_IN;
        #endif
            break;
    #endif
        default:
            /* No other values supported. */
            ret = BAD_FUNC_ARG;
            break;
        }
    }
    if (ret == 0) {
        /* Keep type for parameters. */
        key->type = type;
        /* Cache heap pointer. */
        key->heap = heap;
    #ifdef WOLF_CRYPTO_CB
        /* Cache device id - not used in for this algorithm yet. */
        key->devId = devId;
    #endif
        key->flags = 0;

        /* Zero out all data. */
        XMEMSET(&key->prf, 0, sizeof(key->prf));

        /* Initialize the hash algorithm object. */
        ret = mlkem_hash_new(&key->hash, heap, devId);
    }
    if (ret == 0) {
        /* Initialize the PRF algorithm object. */
        ret = mlkem_prf_new(&key->prf, heap, devId);
    }
    if (ret == 0) {
        mlkem_init();
    }

    (void)devId;

    return ret;
}

/**
 * Free the Kyber key object.
 *
 * @param  [in, out]  key   Kyber key object to dispose of.
 * @return  0 on success.
 */
int wc_MlKemKey_Free(MlKemKey* key)
{
    if (key != NULL) {
        /* Dispose of PRF object. */
        mlkem_prf_free(&key->prf);
        /* Dispose of hash object. */
        mlkem_hash_free(&key->hash);
        /* Ensure all private data is zeroed. */
        ForceZero(&key->hash, sizeof(key->hash));
        ForceZero(&key->prf, sizeof(key->prf));
        ForceZero(key->priv, sizeof(key->priv));
        ForceZero(key->z, sizeof(key->z));
    }

    return 0;
}

/******************************************************************************/

#ifndef WOLFSSL_MLKEM_NO_MAKE_KEY
/**
 * Make a Kyber key object using a random number generator.
 *
 * FIPS 203 - Algorithm 19: ML-KEM.KeyGen()
 * Generates an encapsulation key and a corresponding decapsulation key.
 *   1: d <- B_32                                        >  d is 32 random bytes
 *   2: z <- B_32                                        >  z is 32 random bytes
 *   3: if d == NULL or z == NULL then
 *   4:   return falsum
 *                  > return an error indication if random bit generation failed
 *   5: end if
 *   6: (ek,dk) <- ML-KEM.KeyGen_Interal(d, z)
 *                                       > run internal key generation algorithm
 *   &: return (ek,dk)
 *
 * @param  [in, out]  key   Kyber key object.
 * @param  [in]       rng   Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rng is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 * @return  MEMORY_E when dynamic memory allocation failed.
 * @return  RNG_FAILURE_E when  generating random numbers failed.
 * @return  DRBG_CONT_FAILURE when random number generator health check fails.
 */
int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned char rand[WC_ML_KEM_MAKEKEY_RAND_SZ];

    /* Validate parameters. */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Generate random to use with PRFs.
         * Step 1: d is 32 random bytes
         * Step 2: z is 32 random bytes
         */
        ret = wc_RNG_GenerateBlock(rng, rand, WC_ML_KEM_SYM_SZ * 2);
        /* Step 3: ret is not zero when d == NULL or z == NULL. */
    }
    if (ret == 0) {
        /* Make a key pair from the random.
         * Step 6. run internal key generation algorithm
         * Step 7. public and private key are stored in key
         */
        ret = wc_KyberKey_MakeKeyWithRandom(key, rand, sizeof(rand));
    }

    /* Ensure seeds are zeroized. */
    ForceZero((void*)rand, (word32)sizeof(rand));

    /* Step 4: return ret != 0 on falsum or internal key generation failure. */
    return ret;
}

/**
 * Make a Kyber key object using random data.
 *
 * FIPS 203 - Algorithm 16: ML-KEM.KeyGen_internal(d,z)
 * Uses randomness to generate an encapsulation key and a corresponding
 * decapsulation key.
 *   1: (ek_PKE,dk_PKE) < K-PKE.KeyGen(d)         > run key generation for K-PKE
 *   ...
 *
 * FIPS 203 - Algorithm 13: K-PKE.KeyGen(d)
 * Uses randomness to generate an encryption key and a corresponding decryption
 * key.
 *   1: (rho,sigma) <- G(d||k)A
 *                         > expand 32+1 bytes to two pseudorandom 32-byte seeds
 *   2: N <- 0
 *   3-7: generate matrix A_hat
 *   8-11: generate s
 *   12-15: generate e
 *   16-18: calculate t_hat from A_hat, s and e
 *   ...
 *
 * @param  [in, out]  key   Kyber key ovject.
 * @param  [in]       rand  Random data.
 * @param  [in]       len   Length of random data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rand is NULL.
 * @return  BUFFER_E when length is not WC_ML_KEM_MAKEKEY_RAND_SZ.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlKemKey_MakeKeyWithRandom(MlKemKey* key, const unsigned char* rand,
    int len)
{
    byte buf[2 * WC_ML_KEM_SYM_SZ + 1];
    byte* rho = buf;
    byte* sigma = buf + WC_ML_KEM_SYM_SZ;
#ifndef WOLFSSL_NO_MALLOC
    sword16* e = NULL;
#else
#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
#ifndef WOLFSSL_MLKEM_CACHE_A
    sword16 e[(WC_ML_KEM_MAX_K + 1) * WC_ML_KEM_MAX_K * MLKEM_N];
#else
    sword16 e[WC_ML_KEM_MAX_K * MLKEM_N];
#endif
#else
    sword16 e[WC_ML_KEM_MAX_K * MLKEM_N];
#endif
#endif
#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
    sword16* a = NULL;
#endif
    sword16* s = NULL;
    sword16* t = NULL;
    int ret = 0;
    int k = 0;

    /* Validate parameters. */
    if ((key == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (len != WC_ML_KEM_MAKEKEY_RAND_SZ)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        key->flags = 0;

        /* Establish parameters based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            k = WC_ML_KEM_512_K;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            k = WC_ML_KEM_768_K;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            k = WC_ML_KEM_1024_K;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            k = KYBER512_K;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            k = KYBER768_K;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            k = KYBER1024_K;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

#ifndef WOLFSSL_NO_MALLOC
    if (ret == 0) {
        /* Allocate dynamic memory for matrix and error vector. */
#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
#ifndef WOLFSSL_MLKEM_CACHE_A
        /* e (v) | a (m) */
        e = (sword16*)XMALLOC((k + 1) * k * MLKEM_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#else
        /* e (v) */
        e = (sword16*)XMALLOC(k * MLKEM_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
#else
        /* e (v) */
        e = (sword16*)XMALLOC(k * MLKEM_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        if (e == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        const byte* d = rand;

#ifdef WOLFSSL_MLKEM_CACHE_A
        a = key->a;
#elif !defined(WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM)
        /* Matrix A allocated at end of error vector. */
        a = e + (k * MLKEM_N);
#endif

#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & MLKEM_KYBER)
#endif
#ifdef WOLFSSL_MLKEM_KYBER
        {
            /* Expand 32 bytes of random to 32. */
            ret = MLKEM_HASH_G(&key->hash, d, WC_ML_KEM_SYM_SZ, NULL, 0, buf);
        }
#endif
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            buf[0] = k;
            /* Expand 33 bytes of random to 32.
             * Alg 13: Step 1: (rho,sigma) <- G(d||k)
             */
            ret = MLKEM_HASH_G(&key->hash, d, WC_ML_KEM_SYM_SZ, buf, 1, buf);
        }
#endif
    }
    if (ret == 0) {
        const byte* z = rand + WC_ML_KEM_SYM_SZ;
        s = key->priv;
        t = key->pub;

        /* Cache the public seed for use in encapsulation and encoding public
         * key. */
        XMEMCPY(key->pubSeed, rho, WC_ML_KEM_SYM_SZ);
        /* Cache the z value for decapsulation and encoding private key. */
        XMEMCPY(key->z, z, sizeof(key->z));

        /* Initialize PRF for use in noise generation. */
        mlkem_prf_init(&key->prf);
#ifndef WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
        /* Generate noise using PRF.
         * Alg 13: Steps 8-15: generate s and e
         */
        ret = mlkem_get_noise(&key->prf, k, s, e, NULL, sigma);
    }
    if (ret == 0) {
        /* Generate the matrix A.
         * Alg 13: Steps 3-7
         */
        ret = mlkem_gen_matrix(&key->prf, a, k, rho, 0);
    }
    if (ret == 0) {
        /* Generate key pair from random data.
         * Alg 13: Steps 16-18.
         */
        mlkem_keygen(s, t, e, a, k);
#else
        /* Generate noise using PRF.
         * Alg 13: Steps 8-11: generate s
         */
        ret = mlkem_get_noise(&key->prf, k, s, NULL, NULL, sigma);
    }
    if (ret == 0) {
        /* Generate key pair from private vector and seeds.
         * Alg 13: Steps 3-7: generate matrix A_hat
         * Alg 13: 12-15: generate e
         * Alg 13: 16-18: calculate t_hat from A_hat, s and e
         */
        ret = mlkem_keygen_seeds(s, t, &key->prf, e, k, rho, sigma);
    }
    if (ret == 0) {
#endif
        /* Private and public key are set/available. */
        key->flags |= MLKEM_FLAG_PRIV_SET | MLKEM_FLAG_PUB_SET;
#ifdef WOLFSSL_MLKEM_CACHE_A
        key->flags |= MLKEM_FLAG_A_SET;
#endif
    }

#ifndef WOLFSSL_NO_MALLOC
    /* Free dynamic memory allocated in function. */
    if (key != NULL) {
        XFREE(e, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return ret;
}
#endif /* !WOLFSSL_MLKEM_NO_MAKE_KEY */

/******************************************************************************/

/**
 * Get the size in bytes of cipher text for key.
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  len  Length of cipher text in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return in 'len' size of the cipher text for the type of this key. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            *len = WC_ML_KEM_512_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            *len = WC_ML_KEM_768_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            *len = WC_ML_KEM_1024_CIPHER_TEXT_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            *len = KYBER512_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            *len = KYBER768_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            *len = KYBER1024_CIPHER_TEXT_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

    return ret;
}

/**
 * Size of a shared secret in bytes. Always KYBER_SS_SZ.
 *
 * @param  [in]   key  Kyber key object. Not used.
 * @param  [out]  Size of the shared secret created with a Kyber key.
 * @return  0 on success.
 * @return  0 to indicate success.
 */
int wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len)
{
    (void)key;

    *len = WC_ML_KEM_SS_SZ;

    return 0;
}

#if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) || \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
/* Encapsulate data and derive secret.
 *
 * FIPS 203, Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r)
 * Uses the encryption key to encrypt a plaintext message using the randomness
 * r.
 *   1: N <- 0
 *   2: t_hat <- ByteDecode_12(ek_PKE[0:384k])
 *                                   > run ByteDecode_12 k times to decode t_hat
 *   3: rho <- ek_PKE[384k : 384K + 32]
 *                                            > extract 32-byte seed from ek_PKE
 *   4-8: generate matrix A_hat
 *   9-12: generate y
 *   13-16: generate e_1
 *   17: generate e_2
 *   18-19: calculate u
 *   20: mu <- Decompress_1(ByteDecode_1(m))
 *   21: calculate v
 *   22: c_1 <- ByteEncode_d_u(Compress_d_u(u))
 *                                 > run ByteEncode_d_u and Compress_d_u k times
 *   23: c_2 <- ByteEncode_d_v(Compress_d_v(v))
 *   24: return c <- (c_1||c_2)
 *
 * @param  [in]  key  Kyber key object.
 * @param  [in]  m    Random bytes.
 * @param  [in]  r    Seed to feed to PRF when generating y, e1 and e2.
 * @param  [out] c    Calculated cipher text.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
static int mlkemkey_encapsulate(MlKemKey* key, const byte* m, byte* r, byte* c)
{
    int ret = 0;
    sword16* a = NULL;
#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    sword16* mu = NULL;
    sword16* e1 = NULL;
    sword16* e2 = NULL;
#endif
    unsigned int k = 0;
    unsigned int compVecSz = 0;
#ifndef WOLFSSL_NO_MALLOC
    sword16* y = NULL;
#else
#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    sword16 y[((WC_ML_KEM_MAX_K + 3) * WC_ML_KEM_MAX_K + 3) * MLKEM_N];
#else
    sword16 y[3 * WC_ML_KEM_MAX_K * MLKEM_N];
#endif
#endif
    sword16* u = 0;
    sword16* v = 0;

    /* Establish parameters based on key type. */
    switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef WOLFSSL_WC_ML_KEM_512
    case WC_ML_KEM_512:
        k = WC_ML_KEM_512_K;
        compVecSz = WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case WC_ML_KEM_768:
        k = WC_ML_KEM_768_K;
        compVecSz = WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case WC_ML_KEM_1024:
        k = WC_ML_KEM_1024_K;
        compVecSz = WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
#ifdef WOLFSSL_KYBER512
    case KYBER512:
        k = KYBER512_K;
        compVecSz = KYBER512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER768
    case KYBER768:
        k = KYBER768_K;
        compVecSz = KYBER768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER1024
    case KYBER1024:
        k = KYBER1024_K;
        compVecSz = KYBER1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
    default:
        /* No other values supported. */
        ret = NOT_COMPILED_IN;
        break;
    }

#ifndef WOLFSSL_NO_MALLOC
    if (ret == 0) {
        /* Allocate dynamic memory for all matrices, vectors and polynomials. */
#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
        y = (sword16*)XMALLOC(((k + 3) * k + 3) * MLKEM_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#else
        y = (sword16*)XMALLOC(3 * k * MLKEM_N * sizeof(sword16), key->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
#endif
        if (y == NULL) {
            ret = MEMORY_E;
        }
    }
#endif

#ifndef WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    if (ret == 0) {
        /* Assign allocated dynamic memory to pointers.
         * y (b) | a (m) | mu (p) | e1 (p) | e2 (v) | u (v) | v (p) */
        a  = y  + MLKEM_N * k;
        mu = a  + MLKEM_N * k * k;
        e1 = mu + MLKEM_N;
        e2 = e1 + MLKEM_N * k;

        /* Convert msg to a polynomial.
         * Step 20: mu <- Decompress_1(ByteDecode_1(m)) */
        mlkem_from_msg(mu, m);

        /* Initialize the PRF for use in the noise generation. */
        mlkem_prf_init(&key->prf);
        /* Generate noise using PRF.
         * Steps 9-17: generate y, e_1, e_2
         */
        ret = mlkem_get_noise(&key->prf, k, y, e1, e2, r);
    }
    #ifdef WOLFSSL_MLKEM_CACHE_A
    if ((ret == 0) && ((key->flags & MLKEM_FLAG_A_SET) != 0)) {
        unsigned int i;
        /* Transpose matrix.
         *   Steps 4-8: generate matrix A_hat (from original) */
        for (i = 0; i < k; i++) {
            unsigned int j;
            for (j = 0; j < k; j++) {
                XMEMCPY(&a[(i * k + j) * MLKEM_N],
                        &key->a[(j * k + i) * MLKEM_N],
                        MLKEM_N * 2);
            }
        }
    }
    else
    #endif /* WOLFSSL_MLKEM_CACHE_A */
    if (ret == 0) {
        /* Generate the transposed matrix.
         *   Step 4-8: generate matrix A_hat */
        ret = mlkem_gen_matrix(&key->prf, a, k, key->pubSeed, 1);
    }
    if (ret == 0) {
        /* Assign remaining allocated dynamic memory to pointers.
         * y (v) | a (m) | mu (p) | e1 (p) | r2 (v) | u (v) | v (p)*/
        u  = e2 + MLKEM_N;
        v  = u  + MLKEM_N * k;

        /* Perform encapsulation maths.
         *   Steps 18-19, 21: calculate u and v */
        mlkem_encapsulate(key->pub, u, v, a, y, e1, e2, mu, k);
    }
#else /* WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM */
    if (ret == 0) {
        /* Assign allocated dynamic memory to pointers.
         * y (v) | a (v) | u (v) */
        a = y + MLKEM_N * k;

        /* Initialize the PRF for use in the noise generation. */
        mlkem_prf_init(&key->prf);
        /* Generate noise using PRF.
         * Steps 9-12: generate y */
        ret = mlkem_get_noise(&key->prf, k, y, NULL, NULL, r);
    }
    if (ret == 0) {
        /* Assign remaining allocated dynamic memory to pointers.
         * y (v) | at (v) | u (v) */
        u  = a + MLKEM_N * k;
        v  = a;

        /* Perform encapsulation maths.
         *   Steps 13-17: generate e_1 and e_2
         *   Steps 18-19, 21: calculate u and v */
        ret = mlkem_encapsulate_seeds(key->pub, &key->prf, u, a, y, k, m,
            key->pubSeed, r);
    }
#endif /* WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM */

    if (ret == 0) {
        byte* c1 = c;
        byte* c2 = c + compVecSz;

    #if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
        if (k == WC_ML_KEM_512_K) {
            /* Step 22: c_1 <- ByteEncode_d_u(Compress_d_u(u)) */
            mlkem_vec_compress_10(c1, u, k);
            /* Step 23: c_2 <- ByteEncode_d_v(Compress_d_v(v)) */
            mlkem_compress_4(c2, v);
            /* Step 24: return c <- (c_1||c_2) */
        }
    #endif
    #if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
        if (k == WC_ML_KEM_768_K) {
            /* Step 22: c_1 <- ByteEncode_d_u(Compress_d_u(u)) */
            mlkem_vec_compress_10(c1, u, k);
            /* Step 23: c_2 <- ByteEncode_d_v(Compress_d_v(v)) */
            mlkem_compress_4(c2, v);
            /* Step 24: return c <- (c_1||c_2) */
        }
    #endif
    #if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
        if (k == WC_ML_KEM_1024_K) {
            /* Step 22: c_1 <- ByteEncode_d_u(Compress_d_u(u)) */
            mlkem_vec_compress_11(c1, u);
            /* Step 23: c_2 <- ByteEncode_d_v(Compress_d_v(v)) */
            mlkem_compress_5(c2, v);
            /* Step 24: return c <- (c_1||c_2) */
        }
    #endif
    }

#ifndef WOLFSSL_NO_MALLOC
    /* Dispose of dynamic memory allocated in function. */
    XFREE(y, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif

#ifndef WOLFSSL_MLKEM_NO_ENCAPSULATE
/**
 * Encapsulate with random number generator and derive secret.
 *
 * FIPS 203, Algorithm 20: ML-KEM.Encaps(ek)
 * Uses the encapsulation key to generate a shared secret key and an associated
 * ciphertext.
 *   1: m <- B_32                                         > m is 32 random bytes
 *   2: if m == NULL then
 *   3:     return falsum
 *   4: end if
 *   5: (K,c) <- ML-KEM.Encaps_internal(ek,m)
 *                                        > run internal encapsulation algorithm
 *   6: return (K,c)
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  c    Cipher text.
 * @param  [out]  k    Shared secret generated.
 * @param  [in]   rng  Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, ct, ss or RNG is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* c, unsigned char* k,
    WC_RNG* rng)
{
    int ret = 0;
    unsigned char m[WC_ML_KEM_ENC_RAND_SZ];

    /* Validate parameters. */
    if ((key == NULL) || (c == NULL) || (k == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Generate seed for use with PRFs.
         * Step 1: m is 32 random bytes
         */
        ret = wc_RNG_GenerateBlock(rng, m, sizeof(m));
        /* Step 2: ret is not zero when m == NULL. */
    }
    if (ret == 0) {
        /* Encapsulate with the random.
         * Step 5: run internal encapsulation algorithm
         */
        ret = wc_KyberKey_EncapsulateWithRandom(key, c, k, m, sizeof(m));
    }

    /* Step 3: return ret != 0 on falsum or internal key generation failure. */
    return ret;
}

/**
 * Encapsulate with random data and derive secret.
 *
 * FIPS 203, Algorithm 17: ML-KEM.Encaps_internal(ek, m)
 * Uses the encapsulation key and randomness to generate a key and an associated
 * ciphertext.
 *   Step 1: (K,r) <- G(m||H(ek))
 *                                 > derive shared secret key K and randomness r
 *   Step 2: c <- K-PPKE.Encrypt(ek, m, r)
 *                                     > encrypt m using K-PKE with randomness r
 *   Step 3: return (K,c)
 *
 * @param  [out]  c    Cipher text.
 * @param  [out]  k    Shared secret generated.
 * @param  [in]   m    Random bytes.
 * @param  [in]   len  Length of random bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, c, k or RNG is NULL.
 * @return  BUFFER_E when len is not WC_ML_KEM_ENC_RAND_SZ.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlKemKey_EncapsulateWithRandom(MlKemKey* key, unsigned char* c,
    unsigned char* k, const unsigned char* m, int len)
{
#ifdef WOLFSSL_MLKEM_KYBER
    byte msg[KYBER_SYM_SZ];
#endif
    byte kr[2 * KYBER_SYM_SZ + 1];
    int ret = 0;
#ifdef WOLFSSL_MLKEM_KYBER
    unsigned int cSz = 0;
#endif

    /* Validate parameters. */
    if ((key == NULL) || (c == NULL) || (k == NULL) || (m == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (len != WC_ML_KEM_ENC_RAND_SZ)) {
        ret = BUFFER_E;
    }

#ifdef WOLFSSL_MLKEM_KYBER
    if (ret == 0) {
        /* Establish parameters based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
    #endif
            break;
#endif
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            cSz = KYBER512_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            cSz = KYBER768_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            cSz = KYBER1024_CIPHER_TEXT_SIZE;
            break;
    #endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
#endif

    /* If public hash (h) is not stored against key, calculate it
     * (fields set explicitly instead of using decode).
     * Step 1: ... H(ek)...
     */
    if ((ret == 0) && ((key->flags & MLKEM_FLAG_H_SET) == 0)) {
    #ifndef WOLFSSL_NO_MALLOC
        byte* pubKey = NULL;
        word32 pubKeyLen;
    #else
        byte pubKey[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
        word32 pubKeyLen = WC_ML_KEM_MAX_PUBLIC_KEY_SIZE;
    #endif

    #ifndef WOLFSSL_NO_MALLOC
        /* Determine how big an encoded public key will be. */
        ret = wc_KyberKey_PublicKeySize(key, &pubKeyLen);
        if (ret == 0) {
            /* Allocate dynamic memory for encoded public key. */
            pubKey = (byte*)XMALLOC(pubKeyLen, key->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (pubKey == NULL) {
                ret = MEMORY_E;
            }
        }
        if (ret == 0) {
    #endif
            /* Encode public key - h is hash of encoded public key. */
            ret = wc_KyberKey_EncodePublicKey(key, pubKey, pubKeyLen);
    #ifndef WOLFSSL_NO_MALLOC
        }
        /* Dispose of encoded public key. */
        XFREE(pubKey, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
     #endif
    }
    if ((ret == 0) && ((key->flags & MLKEM_FLAG_H_SET) == 0)) {
        /* Implementation issue if h not cached and flag set. */
        ret = BAD_STATE_E;
    }

#ifdef WOLFSSL_MLKEM_KYBER
    if (ret == 0) {
#ifndef WOLFSSL_NO_ML_KEM
        if (key->type & MLKEM_KYBER)
#endif
        {
            /* Hash random to anonymize as seed data. */
            ret = MLKEM_HASH_H(&key->hash, m, WC_ML_KEM_SYM_SZ, msg);
        }
    }
#endif
    if (ret == 0) {
        /* Hash message into seed buffer. */
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & MLKEM_KYBER)
#endif
#ifdef WOLFSSL_MLKEM_KYBER
        {
            ret = MLKEM_HASH_G(&key->hash, msg, WC_ML_KEM_SYM_SZ, key->h,
                WC_ML_KEM_SYM_SZ, kr);
        }
#endif
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            /* Step 1: (K,r) <- G(m||H(ek)) */
            ret = MLKEM_HASH_G(&key->hash, m, WC_ML_KEM_SYM_SZ, key->h,
                WC_ML_KEM_SYM_SZ, kr);
        }
#endif
    }

    if (ret == 0) {
        /* Encapsulate the message using the key and the seed. */
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & MLKEM_KYBER)
#endif
#ifdef WOLFSSL_MLKEM_KYBER
        {
            ret = mlkemkey_encapsulate(key, msg, kr + WC_ML_KEM_SYM_SZ, c);
        }
#endif
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            /* Step 2: c <- K-PKE.Encrypt(ek,m,r) */
            ret = mlkemkey_encapsulate(key, m, kr + WC_ML_KEM_SYM_SZ, c);
        }
#endif
    }

#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
    if (key->type & MLKEM_KYBER)
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    {
        if (ret == 0) {
            /* Hash the cipher text after the seed. */
            ret = MLKEM_HASH_H(&key->hash, c, cSz, kr + WC_ML_KEM_SYM_SZ);
        }
        if (ret == 0) {
            /* Derive the secret from the seed and hash of cipher text. */
            ret = MLKEM_KDF(kr, 2 * WC_ML_KEM_SYM_SZ, k, WC_ML_KEM_SS_SZ);
        }
    }
#endif
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
    else
#endif
#ifndef WOLFSSL_NO_ML_KEM
    {
        if (ret == 0) {
            /* return (K,c) */
            XMEMCPY(k, kr, WC_ML_KEM_SS_SZ);
        }
    }
#endif

    return ret;
}
#endif /* !WOLFSSL_MLKEM_NO_ENCAPSULATE */

/******************************************************************************/

#ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
/* Decapsulate cipher text to the message using key.
 *
 * FIPS 203, Algorithm 15: K-PKE.Decrypt(dk_PKE,c)
 * Uses the decryption key to decrypt a ciphertext.
 *   1: c1 <- c[0 : 32.d_u.k]
 *   2: c2 <= c[32.d_u.k : 32(d_u.k + d_v)]
 *   3: u' <= Decompress_d_u(ByteDecode_d_u(c1))
 *   4: v' <= Decompress_d_v(ByteDecode_d_v(c2))
 *   ...
 *   6: w <- v' - InvNTT(s_hat_trans o NTT(u'))
 *   7: m <- ByteEncode_1(Compress_1(w))
 *   8: return m
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  m    Message than was encapsulated.
 * @param  [in]   c    Cipher text.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static MLKEM_NOINLINE int mlkemkey_decapsulate(MlKemKey* key, byte* m,
    const byte* c)
{
    int ret = 0;
    sword16* v;
    sword16* w;
    unsigned int k = 0;
    unsigned int compVecSz;
#if defined(WOLFSSL_SMALL_STACK) || \
    (!defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC))
    sword16* u = NULL;
#else
    sword16 u[(WC_ML_KEM_MAX_K + 1) * MLKEM_N];
#endif

    /* Establish parameters based on key type. */
    switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef WOLFSSL_WC_ML_KEM_512
    case WC_ML_KEM_512:
        k = WC_ML_KEM_512_K;
        compVecSz = WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case WC_ML_KEM_768:
        k = WC_ML_KEM_768_K;
        compVecSz = WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case WC_ML_KEM_1024:
        k = WC_ML_KEM_1024_K;
        compVecSz = WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
#ifdef WOLFSSL_KYBER512
    case KYBER512:
        k = KYBER512_K;
        compVecSz = KYBER512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER768
    case KYBER768:
        k = KYBER768_K;
        compVecSz = KYBER768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER1024
    case KYBER1024:
        k = KYBER1024_K;
        compVecSz = KYBER1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
    default:
        /* No other values supported. */
        ret = NOT_COMPILED_IN;
        break;
    }

#if defined(WOLFSSL_SMALL_STACK) || \
    (!defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC))
    if (ret == 0) {
        /* Allocate dynamic memory for a vector and a polynomial. */
        u = (sword16*)XMALLOC((k + 1) * MLKEM_N * sizeof(sword16), key->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (u == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        /* Step 1: c1 <- c[0 : 32.d_u.k] */
        const byte* c1 = c;
        /* Step 2: c2 <= c[32.d_u.k : 32(d_u.k + d_v)] */
        const byte* c2 = c + compVecSz;

        /* Assign allocated dynamic memory to pointers.
         * u (v) | v (p) */
        v = u + k * MLKEM_N;
        w = u;

    #if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
        if (k == WC_ML_KEM_512_K) {
            /* Step 3: u' <= Decompress_d_u(ByteDecode_d_u(c1)) */
            mlkem_vec_decompress_10(u, c1, k);
            /* Step 4: v' <= Decompress_d_v(ByteDecode_d_v(c2)) */
            mlkem_decompress_4(v, c2);
        }
    #endif
    #if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
        if (k == WC_ML_KEM_768_K) {
            /* Step 3: u' <= Decompress_d_u(ByteDecode_d_u(c1)) */
            mlkem_vec_decompress_10(u, c1, k);
            /* Step 4: v' <= Decompress_d_v(ByteDecode_d_v(c2)) */
            mlkem_decompress_4(v, c2);
        }
    #endif
    #if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
        if (k == WC_ML_KEM_1024_K) {
            /* Step 3: u' <= Decompress_d_u(ByteDecode_d_u(c1)) */
            mlkem_vec_decompress_11(u, c1);
            /* Step 4: v' <= Decompress_d_v(ByteDecode_d_v(c2)) */
            mlkem_decompress_5(v, c2);
        }
    #endif

        /* Decapsulate the cipher text into polynomial.
         * Step 6: w <- v' - InvNTT(s_hat_trans o NTT(u')) */
        mlkem_decapsulate(key->priv, w, u, v, k);

        /* Convert the polynomial into a array of bytes (message).
         * Step 7: m <- ByteEncode_1(Compress_1(w)) */
        mlkem_to_msg(m, w);
        /* Step 8: return m */
    }

#if defined(WOLFSSL_SMALL_STACK) || \
    (!defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC))
    /* Dispose of dynamically memory allocated in function. */
    XFREE(u, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

/**
 * Decapsulate the cipher text to calculate the shared secret.
 *
 * Validates the cipher text by encapsulating and comparing with data passed in.
 *
 * FIPS 203, Algorithm 21: ML-KEM.Decaps(dk, c)
 * Uses the decapsulation key to produce a shared secret key from a ciphertext.
 *   1: K' <- ML-KEM.Decaps_internal(dk,c)
 *                                        > run internal decapsulation algorithm
 *   2: return K'
 *
 * FIPS 203, Algorithm 18: ML-KEM.Decaps_internal(dk, c)
 * Uses the decapsulation key to produce a shared secret key from a ciphertext.
 *   ...
 *   1: dk_PKE <- dk[0 : 384k]
 *                        > extract (from KEM decaps key) the PKE decryption key
 *   2: ek_PKE <- dk[384k : 768l + 32]
 *                                                  > extract PKE encryption key
 *   3: h <- dk[768K + 32 : 768k + 64]
 *                                          > extract hash of PKE encryption key
 *   4: z <- dk[768K + 64 : 768k + 96]
 *                                            > extract implicit rejection value
 *   5: m' <- K-PKE.Decrypt(dk_PKE, c)                      > decrypt ciphertext
 *   6: (K', r') <- G(m'||h)
 *   7: K_bar <- J(z||c)
 *   8: c' <- K-PKE.Encrypt(ek_PKE, m', r')
 *                                  > re-encrypt using the derived randomness r'
 *   9: if c != c' then
 *  10:      K' <= K_bar
 *                            > if ciphertexts do not match, "implicitly reject"
 *  11: end if
 *  12: return K'
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  ss   Shared secret.
 * @param  [in]   ct   Cipher text.
 * @param  [in]   len  Length of cipher text.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, ss or cr are NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  BUFFER_E when len is not the length of cipher text for the key type.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len)
{
    byte msg[WC_ML_KEM_SYM_SZ];
    byte kr[2 * WC_ML_KEM_SYM_SZ + 1];
    int ret = 0;
    unsigned int ctSz = 0;
    unsigned int i = 0;
    int fail = 0;
#if !defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC)
    byte* cmp = NULL;
#else
    byte cmp[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
#endif

    /* Validate parameters. */
    if ((key == NULL) || (ss == NULL) || (ct == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Establish cipher text size based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            ctSz = WC_ML_KEM_512_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            ctSz = WC_ML_KEM_768_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            ctSz = WC_ML_KEM_1024_CIPHER_TEXT_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            ctSz = KYBER512_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            ctSz = KYBER768_CIPHER_TEXT_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            ctSz = KYBER1024_CIPHER_TEXT_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

    /* Ensure the cipher text passed in is the correct size. */
    if ((ret == 0) && (len != ctSz)) {
        ret = BUFFER_E;
    }

#if !defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC)
    if (ret == 0) {
        /* Allocate memory for cipher text that is generated. */
        cmp = (byte*)XMALLOC(ctSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (cmp == NULL) {
            ret = MEMORY_E;
        }
    }
#endif

    if (ret == 0) {
        /* Decapsulate the cipher text. */
        ret = mlkemkey_decapsulate(key, msg, ct);
    }
    if (ret == 0) {
        /* Hash message into seed buffer. */
        ret = MLKEM_HASH_G(&key->hash, msg, WC_ML_KEM_SYM_SZ, key->h,
            WC_ML_KEM_SYM_SZ, kr);
    }
    if (ret == 0) {
        /* Encapsulate the message. */
        ret = mlkemkey_encapsulate(key, msg, kr + WC_ML_KEM_SYM_SZ, cmp);
    }
    if (ret == 0) {
        /* Compare generated cipher text with that passed in. */
        fail = mlkem_cmp(ct, cmp, ctSz);

#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & MLKEM_KYBER)
#endif
#ifdef WOLFSSL_MLKEM_KYBER
        {
            /* Hash the cipher text after the seed. */
            ret = MLKEM_HASH_H(&key->hash, ct, ctSz, kr + WC_ML_KEM_SYM_SZ);
            if (ret == 0) {
                /* Change seed to z on comparison failure. */
                for (i = 0; i < WC_ML_KEM_SYM_SZ; i++) {
                    kr[i] ^= (kr[i] ^ key->z[i]) & fail;
                }

                /* Derive the secret from the seed and hash of cipher text. */
                ret = MLKEM_KDF(kr, 2 * WC_ML_KEM_SYM_SZ, ss, WC_ML_KEM_SS_SZ);
            }
        }
#endif
#if defined(WOLFSSL_MLKEM_KYBER) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            ret = mlkem_derive_secret(&key->prf, key->z, ct, ctSz, msg);
            if (ret == 0) {
               /* Set secret to kr or fake secret on comparison failure. */
               for (i = 0; i < WC_ML_KEM_SYM_SZ; i++) {
                   ss[i] = kr[i] ^ ((kr[i] ^ msg[i]) & fail);
               }
            }
        }
#endif
    }

#if !defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_NO_MALLOC)
    /* Dispose of dynamic memory allocated in function. */
    if (key != NULL) {
        XFREE(cmp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return ret;
}
#endif /* WOLFSSL_MLKEM_NO_DECAPSULATE */

/******************************************************************************/

/**
 * Get the public key and public seed from bytes.
 *
 * FIPS 203, Algorithm 14 K-PKE.Encrypt(ek_PKE, m, r)
 *   ...
 *   2: t <- ByteDecode_12(ek_PKE[0 : 384k])
 *   3: rho <- ek_PKE[384k :  384k + 32]
 *   ...
 *
 * @param [out] pub      Public key - vector.
 * @param [out] pubSeed  Public seed.
 * @param [in]  p        Public key data.
 * @param [in]  k        Number of polynomials in vector.
 */
static void mlkemkey_decode_public(sword16* pub, byte* pubSeed, const byte* p,
    unsigned int k)
{
    unsigned int i;

    /* Decode public key that is vector of polynomials.
     * Step 2: t <- ByteDecode_12(ek_PKE[0 : 384k]) */
    mlkem_from_bytes(pub, p, k);
    p += k * WC_ML_KEM_POLY_SIZE;

    /* Read public key seed.
     * Step 3: rho <- ek_PKE[384k :  384k + 32] */
    for (i = 0; i < WC_ML_KEM_SYM_SZ; i++) {
        pubSeed[i] = p[i];
    }
}

/**
 * Decode the private key.
 *
 * Private Vector | Public Key | Public Hash | Randomizer
 *
 * FIPS 203, Algorithm 18: ML-KEM.Decaps_internal(dk, c)
 *   1: dk_PKE <- dk[0 : 384k]
 *                        > extract (from KEM decaps key) the PKE decryption key
 *   2: ek_PKE <- dk[384k : 768l + 32]
 *                                                  > extract PKE encryption key
 *   3: h <- dk[768K + 32 : 768k + 64]
 *                                          > extract hash of PKE encryption key
 *   4: z <- dk[768K + 64 : 768k + 96]
 *                                            > extract implicit rejection value
 *
 * FIPS 203, Algorithm 15: K-PKE.Decrypt(dk_PKE, c)
 *   ...
 *   5: s_hat <= ByteDecode_12(dk_PKE)
 *   ...
 *
 * @param  [in, out]  key  Kyber key object.
 * @param  [in]       in   Buffer holding encoded key.
 * @param  [in]       len  Length of data in buffer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  BUFFER_E when len is not the correct size.
 */
int wc_MlKemKey_DecodePrivateKey(MlKemKey* key, const unsigned char* in,
    word32 len)
{
    int ret = 0;
    word32 privLen = 0;
    word32 pubLen = 0;
    unsigned int k = 0;
    const unsigned char* p = in;

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Establish parameters based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            k = WC_ML_KEM_512_K;
            privLen = WC_ML_KEM_512_PRIVATE_KEY_SIZE;
            pubLen = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            k = WC_ML_KEM_768_K;
            privLen = WC_ML_KEM_768_PRIVATE_KEY_SIZE;
            pubLen = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            k = WC_ML_KEM_1024_K;
            privLen = WC_ML_KEM_1024_PRIVATE_KEY_SIZE;
            pubLen = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            k = KYBER512_K;
            privLen = KYBER512_PRIVATE_KEY_SIZE;
            pubLen = KYBER512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            k = KYBER768_K;
            privLen = KYBER768_PRIVATE_KEY_SIZE;
            pubLen = KYBER768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            k = KYBER1024_K;
            privLen = KYBER1024_PRIVATE_KEY_SIZE;
            pubLen = KYBER1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
    /* Ensure the data is the correct length for the key type. */
    if ((ret == 0) && (len != privLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Decode private key that is vector of polynomials.
         * Alg 18 Step 1: dk_PKE <- dk[0 : 384k]
         * Alg 15 Step 5: s_hat <- ByteDecode_12(dk_PKE) */
        mlkem_from_bytes(key->priv, p, k);
        p += k * WC_ML_KEM_POLY_SIZE;

        /* Decode the public key that is after the private key. */
        mlkemkey_decode_public(key->pub, key->pubSeed, p, k);
        p += pubLen;

        /* Copy the hash of the encoded public key that is after public key. */
        XMEMCPY(key->h, p, sizeof(key->h));
        p += WC_ML_KEM_SYM_SZ;
        /* Copy the z (randomizer) that is after hash. */
        XMEMCPY(key->z, p, sizeof(key->z));

        /* Set flags */
        key->flags |= MLKEM_FLAG_H_SET | MLKEM_FLAG_BOTH_SET;
    }

    return ret;
}

/**
 * Decode public key.
 *
 * Public vector | Public Seed
 *
 * @param  [in, out]  key  Kyber key object.
 * @param  [in]       in   Buffer holding encoded key.
 * @param  [in]       len  Length of data in buffer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  BUFFER_E when len is not the correct size.
 */
int wc_MlKemKey_DecodePublicKey(MlKemKey* key, const unsigned char* in,
    word32 len)
{
    int ret = 0;
    word32 pubLen = 0;
    unsigned int k = 0;
    const unsigned char* p = in;

    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Establish parameters based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            k = WC_ML_KEM_512_K;
            pubLen = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            k = WC_ML_KEM_768_K;
            pubLen = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            k = WC_ML_KEM_1024_K;
            pubLen = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            k = KYBER512_K;
            pubLen = KYBER512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            k = KYBER768_K;
            pubLen = KYBER768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            k = KYBER1024_K;
            pubLen = KYBER1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
    /* Ensure the data is the correct length for the key type. */
    if ((ret == 0) && (len != pubLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        mlkemkey_decode_public(key->pub, key->pubSeed, p, k);

        /* Calculate public hash. */
        ret = MLKEM_HASH_H(&key->hash, in, len, key->h);
    }
    if (ret == 0) {
        /* Record public key and public hash set. */
        key->flags |= MLKEM_FLAG_PUB_SET | MLKEM_FLAG_H_SET;
    }

    return ret;
}

/**
 * Get the size in bytes of encoded private key for the key.
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  len  Length of encoded private key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return in 'len' size of the encoded private key for the type of this
         * key. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            *len = WC_ML_KEM_512_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            *len = WC_ML_KEM_768_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            *len = WC_ML_KEM_1024_PRIVATE_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            *len = KYBER512_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            *len = KYBER768_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            *len = KYBER1024_PRIVATE_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

    return ret;
}

/**
 * Get the size in bytes of encoded public key for the key.
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  len  Length of encoded public key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return in 'len' size of the encoded public key for the type of this
         * key. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            *len = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            *len = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            *len = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            *len = KYBER512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            *len = KYBER768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            *len = KYBER1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

    return ret;
}

/**
 * Encode the private key.
 *
 * Private Vector | Public Key | Public Hash | Randomizer
 *
 * FIPS 203, Algorithm 16: ML-KEM.KeyGen_internal(d,z)
 *   ...
 *   3: dk <- (dk_PKE||ek||H(ek)||z)
 *   ...
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   20: dk_PKE  <- ByteEncode_12(s_hat)
 *   ...
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  out  Buffer to hold data.
 * @param  [in]   len  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL or private/public key not
 * available.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out, word32 len)
{
    int ret = 0;
    unsigned int k = 0;
    unsigned int pubLen = 0;
    unsigned int privLen = 0;
    unsigned char* p = out;

    if ((key == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) &&
            ((key->flags & MLKEM_FLAG_BOTH_SET) != MLKEM_FLAG_BOTH_SET)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            k = WC_ML_KEM_512_K;
            pubLen = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
            privLen = WC_ML_KEM_512_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            k = WC_ML_KEM_768_K;
            pubLen = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
            privLen = WC_ML_KEM_768_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            k = WC_ML_KEM_1024_K;
            pubLen = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
            privLen = WC_ML_KEM_1024_PRIVATE_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            k = KYBER512_K;
            pubLen = KYBER512_PUBLIC_KEY_SIZE;
            privLen = KYBER512_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            k = KYBER768_K;
            pubLen = KYBER768_PUBLIC_KEY_SIZE;
            privLen = KYBER768_PRIVATE_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            k = KYBER1024_K;
            pubLen = KYBER1024_PUBLIC_KEY_SIZE;
            privLen = KYBER1024_PRIVATE_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && (len != privLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Encode private key that is vector of polynomials. */
        mlkem_to_bytes(p, key->priv, k);
        p += WC_ML_KEM_POLY_SIZE * k;

        /* Encode public key. */
        ret = wc_KyberKey_EncodePublicKey(key, p, pubLen);
        p += pubLen;
    }
    /* Ensure hash of public key is available. */
    if ((ret == 0) && ((key->flags & MLKEM_FLAG_H_SET) == 0)) {
        ret = MLKEM_HASH_H(&key->hash, p - pubLen, pubLen, key->h);
    }
    if (ret == 0) {
        /* Public hash is available. */
        key->flags |= MLKEM_FLAG_H_SET;
        /* Append public hash. */
        XMEMCPY(p, key->h, sizeof(key->h));
        p += WC_ML_KEM_SYM_SZ;
        /* Append z (randomizer). */
        XMEMCPY(p, key->z, sizeof(key->z));
    }

    return ret;
}

/**
 * Encode the public key.
 *
 * Public vector | Public Seed
 *
 * FIPS 203, Algorithm 16: ML-KEM.KeyGen_internal(d,z)
 *   ...
 *   2: ek <- ek_PKE
 *   ...
 * FIPS 203, Algorithm 13: K-PKE.KeyGen(d)
 *   ...
 *   19: ek_PKE  <- ByteEncode_12(t_hat)||rho
 *   ...
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  out  Buffer to hold data.
 * @param  [in]   len  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL or public key not available.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out, word32 len)
{
    int ret = 0;
    unsigned int k = 0;
    unsigned int pubLen = 0;
    unsigned char* p = out;

    if ((key == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) &&
            ((key->flags & MLKEM_FLAG_PUB_SET) != MLKEM_FLAG_PUB_SET)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            k = WC_ML_KEM_512_K;
            pubLen = WC_ML_KEM_512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            k = WC_ML_KEM_768_K;
            pubLen = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            k = WC_ML_KEM_1024_K;
            pubLen = WC_ML_KEM_1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
#ifdef WOLFSSL_MLKEM_KYBER
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            k = KYBER512_K;
            pubLen = KYBER512_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            k = KYBER768_K;
            pubLen = KYBER768_PUBLIC_KEY_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            k = KYBER1024_K;
            pubLen = KYBER1024_PUBLIC_KEY_SIZE;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && (len != pubLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        int i;

        /* Encode public key polynomial by polynomial. */
        mlkem_to_bytes(p, key->pub, k);
        p += k * WC_ML_KEM_POLY_SIZE;

        /* Append public seed. */
        for (i = 0; i < WC_ML_KEM_SYM_SZ; i++) {
            p[i] = key->pubSeed[i];
        }

        /* Make sure public hash is set. */
        if ((key->flags & MLKEM_FLAG_H_SET) == 0) {
            ret = MLKEM_HASH_H(&key->hash, out, len, key->h);
        }
    }
    if (ret == 0) {
        /* Public hash is set. */
        key->flags |= MLKEM_FLAG_H_SET;
    }

    return ret;
}

#endif /* WOLFSSL_WC_MLKEM */
