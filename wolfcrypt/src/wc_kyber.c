/* wc_kyber.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* Implementation based on NIST 3rd Round submission package.
 * See link at:
 *   https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_WC_KYBER

/******************************************************************************/

/* Use SHA3-256 to generate 32-bytes of hash. */
#define KYBER_HASH_H            kyber_hash256
/* Use SHA3-512 to generate 64-bytes of hash. */
#define KYBER_HASH_G            kyber_hash512
/* Use SHAKE-256 as a key derivation function (KDF). */
#if defined(USE_INTEL_SPEEDUP) || \
        (defined(WOLFSSL_ARMASM) && defined(__aarch64__))
    #define KYBER_KDF               kyber_kdf
#else
    #define KYBER_KDF               wc_Shake256Hash
#endif

/******************************************************************************/

/* Declare variable to make compiler not optimize code in kyber_from_msg(). */
volatile sword16 kyber_opt_blocker = 0;

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
int wc_KyberKey_Init(int type, KyberKey* key, void* heap, int devId)
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
    #ifdef WOLFSSL_KYBER_ORIGINAL
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
        /* Zero out all data. */
        XMEMSET(key, 0, sizeof(*key));

        /* Keep type for parameters. */
        key->type = type;
        /* Cache heap pointer. */
        key->heap = heap;
    #ifdef WOLF_CRYPTO_CB
        /* Cache device id - not used in for this algorithm yet. */
        key->devId = devId;
    #endif

        /* Initialize the hash algorithm object. */
        ret = kyber_hash_new(&key->hash, heap, devId);
    }
    if (ret == 0) {
        /* Initialize the PRF algorithm object. */
        ret = kyber_prf_new(&key->prf, heap, devId);
    }
    if (ret == 0) {
        kyber_init();
    }

    (void)devId;

    return ret;
}

/**
 * Free the Kyber key object.
 *
 * @param  [in, out]  key   Kyber key object to dispose of.
 */
void wc_KyberKey_Free(KyberKey* key)
{
    if (key != NULL) {
        /* Dispose of PRF object. */
        kyber_prf_free(&key->prf);
        /* Dispose of hash object. */
        kyber_hash_free(&key->hash);
        /* Ensure all private data is zeroed. */
        ForceZero(key, sizeof(*key));
    }
}

/******************************************************************************/

/**
 * Make a Kyber key object using a random number generator.
 *
 * @param  [in, out]  key   Kyber key object.
 * @param  [in]       rng   Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rng is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_KyberKey_MakeKey(KyberKey* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned char rand[KYBER_MAKEKEY_RAND_SZ];

    /* Validate parameters. */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Generate random to with PRFs. */
        ret = wc_RNG_GenerateBlock(rng, rand, KYBER_SYM_SZ);
    }
    if (ret == 0) {
        /* Generate random to with PRFs. */
        ret = wc_RNG_GenerateBlock(rng, rand + KYBER_SYM_SZ, KYBER_SYM_SZ);
    }
    if (ret == 0) {
        /* Make a key pair from the random. */
        ret = wc_KyberKey_MakeKeyWithRandom(key, rand, sizeof(rand));
    }

    /* Ensure seeds are zeroized. */
    ForceZero((void*)rand, (word32)sizeof(rand));

    return ret;
}

/**
 * Make a Kyber key object using random data.
 *
 * @param  [in, out]  key   Kyber key ovject.
 * @param  [in]       rng   Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rand is NULL.
 * @return  BUFFER_E when length is not KYBER_MAKEKEY_RAND_SZ.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_KyberKey_MakeKeyWithRandom(KyberKey* key, const unsigned char* rand,
    int len)
{
    byte buf[2 * KYBER_SYM_SZ + 1];
    byte* pubSeed = buf;
    byte* noiseSeed = buf + KYBER_SYM_SZ;
    sword16* a = NULL;
    sword16* e = NULL;
    int ret = 0;
    int kp = 0;

    /* Validate parameters. */
    if ((key == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (len != KYBER_MAKEKEY_RAND_SZ)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Establish parameters based on key type. */
        switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifdef WOLFSSL_WC_ML_KEM_512
        case WC_ML_KEM_512:
            kp = WC_ML_KEM_512_K;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_768
        case WC_ML_KEM_768:
            kp = WC_ML_KEM_768_K;
            break;
    #endif
    #ifdef WOLFSSL_WC_ML_KEM_1024
        case WC_ML_KEM_1024:
            kp = WC_ML_KEM_1024_K;
            break;
    #endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
    #ifdef WOLFSSL_KYBER512
        case KYBER512:
            kp = KYBER512_K;
            break;
    #endif
    #ifdef WOLFSSL_KYBER768
        case KYBER768:
            kp = KYBER768_K;
            break;
    #endif
    #ifdef WOLFSSL_KYBER1024
        case KYBER1024:
            kp = KYBER1024_K;
            break;
    #endif
#endif
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }

    if (ret == 0) {
        /* Allocate dynamic memory for matrix and error vector. */
        a = (sword16*)XMALLOC((kp + 1) * kp * KYBER_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (a == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        const byte* d = rand;

        /* Error vector allocated at end of a. */
        e = a + (kp * kp * KYBER_N);

#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & KYBER_ORIGINAL)
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
        {
            /* Expand 32 bytes of random to 32. */
            ret = KYBER_HASH_G(&key->hash, d, KYBER_SYM_SZ, NULL, 0, buf);
        }
#endif
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            buf[0] = kp;
            /* Expand 33 bytes of random to 32. */
            ret = KYBER_HASH_G(&key->hash, d, KYBER_SYM_SZ, buf, 1, buf);
        }
#endif
    }
    if (ret == 0) {
        const byte* z = rand + KYBER_SYM_SZ;

        /* Cache the public seed for use in encapsulation and encoding public
         * key. */
        XMEMCPY(key->pubSeed, pubSeed, KYBER_SYM_SZ);
        /* Cache the z value for decapsulation and encoding private key. */
        XMEMCPY(key->z, z, sizeof(key->z));

        /* Generate the matrix A. */
        ret = kyber_gen_matrix(&key->prf, a, kp, pubSeed, 0);
    }

    if (ret == 0) {
        /* Initialize PRF for use in noise generation. */
        kyber_prf_init(&key->prf);
        /* Generate noise using PRF. */
        ret = kyber_get_noise(&key->prf, kp, key->priv, e, NULL, noiseSeed);
    }
    if (ret == 0) {
        /* Generate key pair from random data. */
        kyber_keygen(key->priv, key->pub, e, a, kp);

        /* Private and public key are set/available. */
        key->flags |= KYBER_FLAG_PRIV_SET | KYBER_FLAG_PUB_SET;
    }

    /* Free dynamic memory allocated in function. */
    if (key != NULL) {
        XFREE(a, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

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
int wc_KyberKey_CipherTextSize(KyberKey* key, word32* len)
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
int wc_KyberKey_SharedSecretSize(KyberKey* key, word32* len)
{
    (void)key;

    *len = KYBER_SS_SZ;

    return 0;
}

/* Encapsulate data and derive secret.
 *
 * @param  [in]  key    Kyber key object.
 * @param  [in]  msg    Message to encapsulate.
 * @param  [in]  coins  Coins (seed) to feed to PRF.
 * @param  [in]  ct     Calculated cipher text.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
static int kyberkey_encapsulate(KyberKey* key, const byte* msg, byte* coins,
    unsigned char* ct)
{
    int ret = 0;
    sword16* sp = NULL;
    sword16* ep = NULL;
    sword16* k = NULL;
    sword16* epp = NULL;
    unsigned int kp = 0;
    unsigned int compVecSz = 0;
    sword16* at = NULL;

    /* Establish parameters based on key type. */
    switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef WOLFSSL_WC_ML_KEM_512
    case WC_ML_KEM_512:
        kp = WC_ML_KEM_512_K;
        compVecSz = WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case WC_ML_KEM_768:
        kp = WC_ML_KEM_768_K;
        compVecSz = WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case WC_ML_KEM_1024:
        kp = WC_ML_KEM_1024_K;
        compVecSz = WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
#ifdef WOLFSSL_KYBER512
    case KYBER512:
        kp = KYBER512_K;
        compVecSz = KYBER512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER768
    case KYBER768:
        kp = KYBER768_K;
        compVecSz = KYBER768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER1024
    case KYBER1024:
        kp = KYBER1024_K;
        compVecSz = KYBER1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
    default:
        /* No other values supported. */
        ret = NOT_COMPILED_IN;
        break;
    }

    if (ret == 0) {
        /* Allocate dynamic memory for all matrices, vectors and polynomials. */
        at = (sword16*)XMALLOC(((kp + 3) * kp + 3) * KYBER_N * sizeof(sword16),
            key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (at == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Assign allocated dynamic memory to pointers.
         * at (m) | k (p) | sp (v) | sp (v) | epp (v) | bp (p) | v (v) */
        k   = at  + KYBER_N * kp * kp;
        sp  = k   + KYBER_N;
        ep  = sp  + KYBER_N * kp;
        epp = ep  + KYBER_N * kp;

        /* Convert msg to a polynomial. */
        kyber_from_msg(k, msg);

        /* Generate the transposed matrix. */
        ret = kyber_gen_matrix(&key->prf, at, kp, key->pubSeed, 1);
    }
    if (ret == 0) {
        /* Initialize the PRF for use in the noise generation. */
        kyber_prf_init(&key->prf);
        /* Generate noise using PRF. */
        ret = kyber_get_noise(&key->prf, kp, sp, ep, epp, coins);
    }
    if (ret == 0) {
        sword16* bp;
        sword16* v;

        /* Assign remaining allocated dynamic memory to pointers.
         * at (m) | k (p) | sp (v) | sp (v) | epp (v) | bp (p) | v (v)*/
        bp  = epp + KYBER_N;
        v   = bp  + KYBER_N * kp;

        /* Perform encapsulation maths. */
        kyber_encapsulate(key->pub, bp, v, at, sp, ep, epp, k, kp);

    #if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
        if (kp == KYBER512_K) {
            kyber_vec_compress_10(ct, bp, kp);
            kyber_compress_4(ct + compVecSz, v);
        }
    #endif
    #if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
        if (kp == KYBER768_K) {
            kyber_vec_compress_10(ct, bp, kp);
            kyber_compress_4(ct + compVecSz, v);
        }
    #endif
    #if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
        if (kp == KYBER1024_K) {
            kyber_vec_compress_11(ct, bp);
            kyber_compress_5(ct + compVecSz, v);
        }
    #endif
    }

    /* Dispose of dynamic memory allocated in function. */
    XFREE(at, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/**
 * Encapsulate with random number generator and derive secret.
 *
 * @param  [in]   key  Kyber key object.
 * @param  [out]  ct   Cipher text.
 * @param  [out]  ss   Shared secret generated.
 * @param  [in]   rng  Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, ct, ss or RNG is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_KyberKey_Encapsulate(KyberKey* key, unsigned char* ct, unsigned char* ss,
    WC_RNG* rng)
{
    int ret = 0;
    unsigned char rand[KYBER_ENC_RAND_SZ];

    /* Validate parameters. */
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Generate seed for use with PRFs. */
        ret = wc_RNG_GenerateBlock(rng, rand, sizeof(rand));
    }
    if (ret == 0) {
        /* Encapsulate with the random. */
        ret = wc_KyberKey_EncapsulateWithRandom(key, ct, ss, rand,
            sizeof(rand));
    }

    return ret;
}

/**
 * Encapsulate with random data and derive secret.
 *
 * @param  [out]  ct    Cipher text.
 * @param  [out]  ss    Shared secret generated.
 * @param  [in]   rand  Random data.
 * @param  [in]   len   Random data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, ct, ss or RNG is NULL.
 * @return  BUFFER_E when len is not KYBER_ENC_RAND_SZ.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_KyberKey_EncapsulateWithRandom(KyberKey* key, unsigned char* ct,
    unsigned char* ss, const unsigned char* rand, int len)
{
#ifdef WOLFSSL_KYBER_ORIGINAL
    byte msg[KYBER_SYM_SZ];
#endif
    byte kr[2 * KYBER_SYM_SZ + 1];
    int ret = 0;
#ifdef WOLFSSL_KYBER_ORIGINAL
    unsigned int ctSz = 0;
#endif

    /* Validate parameters. */
    if ((key == NULL) || (ct == NULL) || (ss == NULL) || (rand == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (len != KYBER_ENC_RAND_SZ)) {
        ret = BUFFER_E;
    }

#ifdef WOLFSSL_KYBER_ORIGINAL
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
        default:
            /* No other values supported. */
            ret = NOT_COMPILED_IN;
            break;
        }
    }
#endif

    /* If public hash (h) is not stored against key, calculate it. */
    if ((ret == 0) && ((key->flags & KYBER_FLAG_H_SET) == 0)) {
        byte* pubKey = NULL;
        word32 pubKeyLen;

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
            /* Encode public key - h is hash of encoded public key. */
            ret = wc_KyberKey_EncodePublicKey(key, pubKey, pubKeyLen);
        }
        /* Dispose of encoded public key. */
        XFREE(pubKey, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if ((ret == 0) && ((key->flags & KYBER_FLAG_H_SET) == 0)) {
        /* Implementation issue if h not cached and flag set. */
        ret = BAD_STATE_E;
    }

#ifdef WOLFSSL_KYBER_ORIGINAL
    if (ret == 0) {
#ifndef WOLFSSL_NO_ML_KEM
        if (key->type & KYBER_ORIGINAL)
#endif
        {
            /* Hash random to anonymize as seed data. */
            ret = KYBER_HASH_H(&key->hash, rand, KYBER_SYM_SZ, msg);
        }
    }
#endif
    if (ret == 0) {
        /* Hash message into seed buffer. */
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & KYBER_ORIGINAL)
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
        {
            ret = KYBER_HASH_G(&key->hash, msg, KYBER_SYM_SZ, key->h,
                KYBER_SYM_SZ, kr);
        }
#endif
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            ret = KYBER_HASH_G(&key->hash, rand, KYBER_SYM_SZ, key->h,
                KYBER_SYM_SZ, kr);
        }
#endif
    }

    if (ret == 0) {
        /* Encapsulate the message using the key and the seed (coins). */
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & KYBER_ORIGINAL)
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
        {
            ret = kyberkey_encapsulate(key, msg, kr + KYBER_SYM_SZ, ct);
        }
#endif
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            ret = kyberkey_encapsulate(key, rand, kr + KYBER_SYM_SZ, ct);
        }
#endif
    }

#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
    if (key->type & KYBER_ORIGINAL)
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
    {
        if (ret == 0) {
            /* Hash the cipher text after the seed. */
            ret = KYBER_HASH_H(&key->hash, ct, ctSz, kr + KYBER_SYM_SZ);
        }
        if (ret == 0) {
            /* Derive the secret from the seed and hash of cipher text. */
            ret = KYBER_KDF(kr, 2 * KYBER_SYM_SZ, ss, KYBER_SS_SZ);
        }
    }
#endif
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
    else
#endif
#ifndef WOLFSSL_NO_ML_KEM
    {
        if (ret == 0) {
            XMEMCPY(ss, kr, KYBER_SS_SZ);
        }
    }
#endif

    return ret;
}

/******************************************************************************/

/* Decapsulate cipher text to the message using key.
 *
 * @param  [in]   Kyber key object.
 * @param  [out]  Message than was encapsulated.
 * @param  [in]   Cipher text.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static KYBER_NOINLINE int kyberkey_decapsulate(KyberKey* key,
    unsigned char* msg, const unsigned char* ct)
{
    int ret = 0;
    sword16* v;
    sword16* mp;
    unsigned int kp = 0;
    unsigned int compVecSz;
#ifndef USE_INTEL_SPEEDUP
    sword16* bp = NULL;
#else
    sword16 bp[(KYBER_MAX_K + 2) * KYBER_N];
#endif

    /* Establish parameters based on key type. */
    switch (key->type) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef WOLFSSL_WC_ML_KEM_512
    case WC_ML_KEM_512:
        kp = WC_ML_KEM_512_K;
        compVecSz = WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case WC_ML_KEM_768:
        kp = WC_ML_KEM_768_K;
        compVecSz = WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case WC_ML_KEM_1024:
        kp = WC_ML_KEM_1024_K;
        compVecSz = WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
#ifdef WOLFSSL_KYBER512
    case KYBER512:
        kp = KYBER512_K;
        compVecSz = KYBER512_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER768
    case KYBER768:
        kp = KYBER768_K;
        compVecSz = KYBER768_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#ifdef WOLFSSL_KYBER1024
    case KYBER1024:
        kp = KYBER1024_K;
        compVecSz = KYBER1024_POLY_VEC_COMPRESSED_SZ;
        break;
#endif
#endif
    default:
        /* No other values supported. */
        ret = NOT_COMPILED_IN;
        break;
    }

#ifndef USE_INTEL_SPEEDUP
    if (ret == 0) {
        /* Allocate dynamic memory for a vector and two polynomials. */
        bp = (sword16*)XMALLOC((kp + 2) * KYBER_N * sizeof(sword16), key->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (bp == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        /* Assign allocated dynamic memory to pointers.
         * bp (v) | v (p) | mp (p) */
        v = bp + kp * KYBER_N;
        mp = v + KYBER_N;

    #if defined(WOLFSSL_KYBER512) || defined(WOLFSSL_WC_ML_KEM_512)
        if (kp == KYBER512_K) {
            kyber_vec_decompress_10(bp, ct, kp);
            kyber_decompress_4(v, ct + compVecSz);
        }
    #endif
    #if defined(WOLFSSL_KYBER768) || defined(WOLFSSL_WC_ML_KEM_768)
        if (kp == KYBER768_K) {
            kyber_vec_decompress_10(bp, ct, kp);
            kyber_decompress_4(v, ct + compVecSz);
        }
    #endif
    #if defined(WOLFSSL_KYBER1024) || defined(WOLFSSL_WC_ML_KEM_1024)
        if (kp == KYBER1024_K) {
            kyber_vec_decompress_11(bp, ct);
            kyber_decompress_5(v, ct + compVecSz);
        }
    #endif

        /* Decapsulate the cipher text into polynomial. */
        kyber_decapsulate(key->priv, mp, bp, v, kp);

        /* Convert the polynomial into a array of bytes (message). */
        kyber_to_msg(msg, mp);
    }

#ifndef USE_INTEL_SPEEDUP
    /* Dispose of dynamically memory allocated in function. */
    XFREE(bp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#ifndef WOLFSSL_NO_ML_KEM
/* Derive the secret from z and cipher text.
 *
 * @param [in]  z     Implicit rejection value.
 * @param [in]  ct    Cipher text.
 * @param [in]  ctSz  Length of cipher text in bytes.
 * @param [out] ss    Shared secret.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation failed.
 * @return  Other negative when a hash error occurred.
 */
static int kyber_derive_secret(const byte* z, const byte* ct, word32 ctSz,
    byte* ss)
{
    int ret;
    wc_Shake shake;

    ret = wc_InitShake256(&shake, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Shake256_Update(&shake, z, KYBER_SYM_SZ);
        if (ret == 0) {
            ret = wc_Shake256_Update(&shake, ct, ctSz);
        }
        if (ret == 0) {
            ret = wc_Shake256_Final(&shake, ss, KYBER_SS_SZ);
        }
        wc_Shake256_Free(&shake);
    }

    return ret;
}
#endif

/**
 * Decapsulate the cipher text to calculate the shared secret.
 *
 * Validates the cipher text by encapsulating and comparing with data passed in.
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
int wc_KyberKey_Decapsulate(KyberKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len)
{
    byte msg[KYBER_SYM_SZ];
    byte kr[2 * KYBER_SYM_SZ + 1];
    int ret = 0;
    unsigned int ctSz = 0;
    unsigned int i = 0;
    int fail = 0;
#ifndef USE_INTEL_SPEEDUP
    byte* cmp = NULL;
#else
    byte cmp[KYBER_MAX_CIPHER_TEXT_SIZE];
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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

#ifndef USE_INTEL_SPEEDUP
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
        ret = kyberkey_decapsulate(key, msg, ct);
    }
    if (ret == 0) {
        /* Hash message into seed buffer. */
        ret = KYBER_HASH_G(&key->hash, msg, KYBER_SYM_SZ, key->h, KYBER_SYM_SZ,
            kr);
    }
    if (ret == 0) {
        /* Encapsulate the message. */
        ret = kyberkey_encapsulate(key, msg, kr + KYBER_SYM_SZ, cmp);
    }
    if (ret == 0) {
        /* Compare generated cipher text with that passed in. */
        fail = kyber_cmp(ct, cmp, ctSz);

#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        if (key->type & KYBER_ORIGINAL)
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
        {
            /* Hash the cipher text after the seed. */
            ret = KYBER_HASH_H(&key->hash, ct, ctSz, kr + KYBER_SYM_SZ);
            if (ret == 0) {
                /* Change seed to z on comparison failure. */
                for (i = 0; i < KYBER_SYM_SZ; i++) {
                    kr[i] ^= (kr[i] ^ key->z[i]) & fail;
                }

                /* Derive the secret from the seed and hash of cipher text. */
                ret = KYBER_KDF(kr, 2 * KYBER_SYM_SZ, ss, KYBER_SS_SZ);
            }
        }
#endif
#if defined(WOLFSSL_KYBER_ORIGINAL) && !defined(WOLFSSL_NO_ML_KEM)
        else
#endif
#ifndef WOLFSSL_NO_ML_KEM
        {
            ret = kyber_derive_secret(key->z, ct, ctSz, msg);
            if (ret == 0) {
               /* Change seed to z on comparison failure. */
               for (i = 0; i < KYBER_SYM_SZ; i++) {
                   ss[i] = kr[i] ^ ((kr[i] ^ msg[i]) & fail);
               }
            }
        }
#endif
    }

#ifndef USE_INTEL_SPEEDUP
    /* Dispose of dynamic memory allocated in function. */
    if (key != NULL) {
        XFREE(cmp, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return ret;
}

/******************************************************************************/

/**
 * Decode the private key.
 *
 * Private Vector | Public Key | Public Hash | Randomizer
 *
 * @param  [in, out]  key  Kyber key object.
 * @param  [in]       in   Buffer holding encoded key.
 * @param  [in]       len  Length of data in buffer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  NOT_COMPILED_IN when key type is not supported.
 * @return  BUFFER_E when len is not the correct size.
 */
int wc_KyberKey_DecodePrivateKey(KyberKey* key, const unsigned char* in,
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
        /* Decode private key that is vector of polynomials. */
        kyber_from_bytes(key->priv, p, k);
        p += k * KYBER_POLY_SIZE;

        /* Decode the public key that is after the private key. */
        ret = wc_KyberKey_DecodePublicKey(key, p, pubLen);
    }
    if (ret == 0) {
        /* Skip over public key. */
        p += pubLen;
        /* Copy the hash of the encoded public key that is after public key. */
        XMEMCPY(key->h, p, sizeof(key->h));
        p += KYBER_SYM_SZ;
        /* Copy the z (randomizer) that is after hash. */
        XMEMCPY(key->z, p, sizeof(key->z));
        /* Set that private and public keys, and public hash are set. */
        key->flags |= KYBER_FLAG_H_SET | KYBER_FLAG_BOTH_SET;
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
int wc_KyberKey_DecodePublicKey(KyberKey* key, const unsigned char* in,
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
        unsigned int i;

        /* Decode public key that is vector of polynomials. */
        kyber_from_bytes(key->pub, p, k);
        p += k * KYBER_POLY_SIZE;

        /* Read public key seed. */
        for (i = 0; i < KYBER_SYM_SZ; i++) {
            key->pubSeed[i] = p[i];
        }
        /* Calculate public hash. */
        ret = KYBER_HASH_H(&key->hash, in, len, key->h);
    }
    if (ret == 0) {
        /* Record public key and public hash set. */
        key->flags |= KYBER_FLAG_PUB_SET | KYBER_FLAG_H_SET;
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
int wc_KyberKey_PrivateKeySize(KyberKey* key, word32* len)
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
int wc_KyberKey_PublicKeySize(KyberKey* key, word32* len)
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
 * @param  [in]   key  Kyber key object.
 * @param  [out]  out  Buffer to hold data.
 * @param  [in]   len  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL or private/public key not
 * available.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_KyberKey_EncodePrivateKey(KyberKey* key, unsigned char* out, word32 len)
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
            ((key->flags & KYBER_FLAG_BOTH_SET) != KYBER_FLAG_BOTH_SET)) {
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
        kyber_to_bytes(p, key->priv, k);
        p += KYBER_POLY_SIZE * k;

        /* Encode public key. */
        ret = wc_KyberKey_EncodePublicKey(key, p, pubLen);
        p += pubLen;
    }
    /* Ensure hash of public key is available. */
    if ((ret == 0) && ((key->flags & KYBER_FLAG_H_SET) == 0)) {
        ret = KYBER_HASH_H(&key->hash, p - pubLen, pubLen, key->h);
    }
    if (ret == 0) {
        /* Public hash is available. */
        key->flags |= KYBER_FLAG_H_SET;
        /* Append public hash. */
        XMEMCPY(p, key->h, sizeof(key->h));
        p += KYBER_SYM_SZ;
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
 * @param  [in]   key  Kyber key object.
 * @param  [out]  out  Buffer to hold data.
 * @param  [in]   len  Size of buffer in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or out is NULL or public key not available.
 * @return  NOT_COMPILED_IN when key type is not supported.
 */
int wc_KyberKey_EncodePublicKey(KyberKey* key, unsigned char* out, word32 len)
{
    int ret = 0;
    unsigned int k = 0;
    unsigned int pubLen = 0;
    unsigned char* p = out;

    if ((key == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) &&
            ((key->flags & KYBER_FLAG_PUB_SET) != KYBER_FLAG_PUB_SET)) {
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
#ifdef WOLFSSL_KYBER_ORIGINAL
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
        kyber_to_bytes(p, key->pub, k);
        p += k * KYBER_POLY_SIZE;

        /* Append public seed. */
        for (i = 0; i < KYBER_SYM_SZ; i++) {
            p[i] = key->pubSeed[i];
        }

        /* Make sure public hash is set. */
        if ((key->flags & KYBER_FLAG_H_SET) == 0) {
            ret = KYBER_HASH_H(&key->hash, out, len, key->h);
        }
    }
    if (ret == 0) {
        /* Public hash is set. */
        key->flags |= KYBER_FLAG_H_SET;
    }

    return ret;
}

#endif /* WOLFSSL_WC_KYBER */
