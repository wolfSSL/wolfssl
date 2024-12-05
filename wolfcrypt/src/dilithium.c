/* dilithium.c
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

/* Based on ed448.c and Reworked for Dilithium by Anthony Hu.
 * WolfSSL implementation by Sean Parkinson.
 */

/* Possible Dilithium/ML-DSA options:
 *
 * HAVE_DILITHIUM                                             Default: OFF
 *   Enables the code in this file to be compiled.
 * WOLFSSL_WC_DILITHIUM                                       Default: OFF
 *   Compiles the wolfSSL implementation of dilithium.
 *
 * WOLFSSL_NO_ML_DSA_44                                       Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_NO_ML_DSA_65                                       Default: OFF
 *   Does not compile in parameter set ML-DSA-65 and any code specific to that
 *   parameter set.
 * WOLFSSL_NO_ML_DSA_87                                       Default: OFF
 *   Does not compile in parameter set ML-DSA-87 and any code specific to that
 *   parameter set.
 *
 * WOLFSSL_DILITHIUM_NO_LARGE_CODE                            Default: OFF
 *   Compiles smaller, fast code with speed trade-off.
 * WOLFSSL_DILITHIUM_SMALL                                    Default: OFF
 *   Compiles to small code size with a speed trade-off.
 * WOLFSSL_DILITHIUM_VERIFY_ONLY                              Default: OFF
 *   Compiles in only the verification and public key operations.
 * WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM                         Default: OFF
 *   Compiles verification implementation that uses smaller amounts of memory.
 * WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC                         Default: OFF
 *   Only works with WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM.
 *   Don't allocate memory with XMALLOC. Memory is pinned against key.
 * WOLFSSL_DILITHIUM_ASSIGN_KEY                               Default: OFF
 *   Key data is assigned into Dilithium key rather than copied.
 *   Life of key data passed in is tightly coupled to life of Dilithium key.
 *   Cannot be used when make key is enabled.
 * WOLFSSL_DILITHIUM_SIGN_SMALL_MEM                           Default: OFF
 *   Compiles signature implementation that uses smaller amounts of memory but
 *   is considerably slower.
 * WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC                   Default: OFF
 *   Compiles signature implementation that uses smaller amounts of memory but
 *   is considerably slower. Allocates vectors and decodes private key data
 *   into them upfront.
 * WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A                 Default: OFF
 *   Compiles signature implementation that uses smaller amounts of memory but
 *   is slower. Allocates matrix A and calculates it upfront.
 * WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM                       Default: OFF
 *   Compiles key generation implementation that uses smaller amounts of memory
 *   but is slower.
 * WOLFSSL_DILITHIUM_SMALL_MEM_POLY64                         Default: OFF
 *   Compiles the small memory implementations to use a 64-bit polynomial.
 *   Uses 2KB of memory but is slightly quicker (2.75-7%).
 *
 * WOLFSSL_DILITHIUM_ALIGNMENT                                Default: 8
 *   Use to indicate whether loading and storing of words needs to be aligned.
 *   Default is to use WOLFSSL_GENERAL_ALIGNMENT - should be 4 on some ARM CPUs.
 *   Set this value explicitly if specific Dilithium implementation alignment is
 *   needed.
 *
 * WOLFSSL_DILITHIUM_NO_ASN1                                  Default: OFF
 *   Disables any ASN.1 encoding or decoding code.
 * WOLFSSL_DILITHIUM_REVERSE_HASH_OID                         Default: OFF
 *   Reverse the DER encoded hash oid when signing and verifying a pre-hashed
 *   message.
 *
 * WC_DILITHIUM_CACHE_MATRIX_A                                Default: OFF
 *   Enable caching of the A matrix on import.
 *   Less work is required in sign and verify operations.
 * WC_DILITHIUM_CACHE_PRIV_VECTORS                            Default: OFF
 *   Enable caching of private key vectors on import.
 *   Enables WC_DILITHIUM_CACHE_MATRIX_A.
 *   Less work is required in sign operations.
 * WC_DILITHIUM_CACHE_PUB_VECTORS                             Default: OFF
 *   Enable caching of public key vectors on import.
 *   Enables WC_DILITHIUM_CACHE_MATRIX_A.
 *   Less work is required in sign operations.
 * WC_DILITHIUM_FIXED_ARRAY                                   Default: OFF
 *   Make the matrix and vectors of cached data fixed arrays that have
 *   maximumal sizes for the configured parameters.
 *   Useful in low dynamic memory situations.
 *
 * WOLFSSL_DILITHIUM_SIGN_CHECK_Y                             Default: OFF
 *   Check vector y is in required range as an early check on valid vector z.
 *   Falsely reports invalid in approximately 1-2% of checks.
 *   All valid reports are true.
 *   Fast fail gives faster signing times on average.
 *   DO NOT enable this if implementation must be conformant to FIPS 204.
 * WOLFSSL_DILITHIUM_SIGN_CHECK_W0                            Default: OFF
 *   Check vector w0 is in required range as an early check on valid vector r0.
 *   Falsely reports invalid in approximately 3-5% of checks.
 *   All valid reports are true.
 *   Fast fail gives faster signing times on average.
 *   DO NOT enable this if implementation must be conformant to FIPS 204.
 *
 * DILITHIUM_MUL_SLOW                                         Default: OFF
 *   Define when multiplying by Q / 44 is slower than masking.
 *   Only applies to ML-DSA-44.
 * DILITHIUM_MUL_44_SLOW                                      Default: OFF
 *   Define when multiplying by 44 is slower than by 11.
 *   Only applies to ML-DSA-44.
 * DILITHIUM_MUL_11_SLOW                                      Default: OFF
 *   Define when multiplying by 11 is slower than adding and shifting.
 *   Only applies to ML-DSA-44.
 * DILITHIUM_MUL_QINV_SLOW                                    Default: OFF
 *   Define when multiplying by QINV 0x3802001 is slower than add, subtract and
 *   shift equivalent.
 * DILITHIUM_MUL_Q_SLOW                                       Default: OFF
 *   Define when multiplying by Q 0x7fe001 is slower than add, subtract and
 *   shift equivalent.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_PQC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_DILITHIUM_NO_ASN1
#include <wolfssl/wolfcrypt/asn.h>
#endif

#if defined(HAVE_DILITHIUM)

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC) && \
        !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)
    #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#endif
#if defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A) && \
        !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)
    #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
    #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
        #error "PRECALC and PRECALC_A is equivalent to non small mem"
    #endif
#endif

#ifdef WOLFSSL_WC_DILITHIUM

#ifdef DEBUG_DILITHIUM
void print_polys(const char* name, const sword32* a, int d1, int d2);
void print_polys(const char* name, const sword32* a, int d1, int d2)
{
    int i;
    int j;
    int k;

    fprintf(stderr, "%s\n", name);
    for (i = 0; i < d1; i++) {
        for (j = 0; j < d2; j++) {
            for (k = 0; k < 256; k++) {
                fprintf(stderr, "%9d,", a[(i*d2*256) + (j*256) + k]);
                if ((k % 8) == 7) fprintf(stderr, "\n");
            }
            fprintf(stderr, "\n");
        }
    }
}

void print_data(const char* name, const byte* d, int len);
void print_data(const char* name, const byte* d, int len)
{
    int i;

    fprintf(stderr, "%s\n", name);
    for (i = 0; i < len; i++) {
        fprintf(stderr, "0x%02x,", d[i]);
        if ((i % 16) == 15) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}
#endif

#if defined(WOLFSSL_NO_ML_DSA_44) && defined(WOLFSSL_NO_ML_DSA_65) && \
    defined(WOLFSSL_NO_ML_DSA_87)
    #error "No Dilithium parameters chosen"
#endif

#if defined(WOLFSSL_DILITHIUM_ASSIGN_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY)
    #error "Cannot use assign key when making keys"
#endif


/* Number of bytes from first block to use for sign. */
#define DILITHIUM_SIGN_BYTES            8


/* Length of seed in bytes when generating y. */
#define DILITHIUM_Y_SEED_SZ             (DILITHIUM_PRIV_RAND_SEED_SZ + 2)


/* Length of seed in bytes used in generating matrix a. */
#define DILITHIUM_GEN_A_SEED_SZ         (DILITHIUM_PUB_SEED_SZ + 2)
/* Length of seed in bytes used in generating vectors s1 and s2. */
#define DILITHIUM_GEN_S_SEED_SZ         (DILITHIUM_PRIV_SEED_SZ + 2)


/* MAX: (256 * 8 / (17 + 1)) = 576, or ((256 * 8 / (19 + 1)) = 640
 * but need blocks of 17 * 8 bytes: 5 * 17 * 8 = 680 */
#define DILITHIUM_MAX_V_BLOCKS          5
/* Maximum number of bytes to generate into v to make y. */
#define DILITHIUM_MAX_V                 (DILITHIUM_MAX_V_BLOCKS * 8 * 17)


/* 2 blocks, each block 136 bytes = 272 bytes.
 * ETA 2: Min req is 128 but reject rate is 2 in 16 so we need 146.3 on average.
 * ETA 4: Min req is 128 but reject rate is 7 in 16 so we need 227.6 on average.
 */
#define DILITHIUM_GEN_S_NBLOCKS         2
/* Number of bytes to generate with SHAKE-256 when generating s1 and s2. */
#define DILITHIUM_GEN_S_BYTES           \
    (DILITHIUM_GEN_S_NBLOCKS * WC_SHA3_256_COUNT * 8)
/* Number of bytes to a block of SHAKE-256 when generating s1 and s2. */
#define DILITHIUM_GEN_S_BLOCK_BYTES    (WC_SHA3_256_COUNT * 8)

/* Length of the hash OID to include in pre-hash message. */
#define DILITHIUM_HASH_OID_LEN         11


/* The ML-DSA parameters sets. */
static const wc_dilithium_params dilithium_params[] = {
#ifndef WOLFSSL_NO_ML_DSA_44
    { WC_ML_DSA_44, PARAMS_ML_DSA_44_K, PARAMS_ML_DSA_44_L,
      PARAMS_ML_DSA_44_ETA, PARAMS_ML_DSA_44_ETA_BITS,
      PARAMS_ML_DSA_44_TAU, PARAMS_ML_DSA_44_BETA, PARAMS_ML_DSA_44_OMEGA,
      PARAMS_ML_DSA_44_LAMBDA,
      PARAMS_ML_DSA_44_GAMMA1_BITS, PARAMS_ML_DSA_44_GAMMA2,
      PARAMS_ML_DSA_44_W1_ENC_SZ, PARAMS_ML_DSA_44_A_SIZE,
      PARAMS_ML_DSA_44_S1_SIZE, PARAMS_ML_DSA_44_S1_ENC_SIZE,
      PARAMS_ML_DSA_44_S2_SIZE, PARAMS_ML_DSA_44_S2_ENC_SIZE,
      PARAMS_ML_DSA_44_Z_ENC_SIZE,
      PARAMS_ML_DSA_44_PK_SIZE, PARAMS_ML_DSA_44_SIG_SIZE },
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    { WC_ML_DSA_65, PARAMS_ML_DSA_65_K, PARAMS_ML_DSA_65_L,
      PARAMS_ML_DSA_65_ETA, PARAMS_ML_DSA_65_ETA_BITS,
      PARAMS_ML_DSA_65_TAU, PARAMS_ML_DSA_65_BETA, PARAMS_ML_DSA_65_OMEGA,
      PARAMS_ML_DSA_65_LAMBDA,
      PARAMS_ML_DSA_65_GAMMA1_BITS, PARAMS_ML_DSA_65_GAMMA2,
      PARAMS_ML_DSA_65_W1_ENC_SZ, PARAMS_ML_DSA_65_A_SIZE,
      PARAMS_ML_DSA_65_S1_SIZE, PARAMS_ML_DSA_65_S1_ENC_SIZE,
      PARAMS_ML_DSA_65_S2_SIZE, PARAMS_ML_DSA_65_S2_ENC_SIZE,
      PARAMS_ML_DSA_65_Z_ENC_SIZE,
      PARAMS_ML_DSA_65_PK_SIZE, PARAMS_ML_DSA_65_SIG_SIZE },
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    { WC_ML_DSA_87, PARAMS_ML_DSA_87_K, PARAMS_ML_DSA_87_L,
      PARAMS_ML_DSA_87_ETA, PARAMS_ML_DSA_87_ETA_BITS,
      PARAMS_ML_DSA_87_TAU, PARAMS_ML_DSA_87_BETA, PARAMS_ML_DSA_87_OMEGA,
      PARAMS_ML_DSA_87_LAMBDA,
      PARAMS_ML_DSA_87_GAMMA1_BITS, PARAMS_ML_DSA_87_GAMMA2,
      PARAMS_ML_DSA_87_W1_ENC_SZ, PARAMS_ML_DSA_87_A_SIZE,
      PARAMS_ML_DSA_87_S1_SIZE, PARAMS_ML_DSA_87_S1_ENC_SIZE,
      PARAMS_ML_DSA_87_S2_SIZE, PARAMS_ML_DSA_87_S2_ENC_SIZE,
      PARAMS_ML_DSA_87_Z_ENC_SIZE,
      PARAMS_ML_DSA_87_PK_SIZE, PARAMS_ML_DSA_87_SIG_SIZE },
#endif
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
#ifndef WOLFSSL_NO_ML_DSA_44
    { WC_ML_DSA_44_DRAFT, PARAMS_ML_DSA_44_K, PARAMS_ML_DSA_44_L,
      PARAMS_ML_DSA_44_ETA, PARAMS_ML_DSA_44_ETA_BITS,
      PARAMS_ML_DSA_44_TAU, PARAMS_ML_DSA_44_BETA, PARAMS_ML_DSA_44_OMEGA,
      PARAMS_ML_DSA_44_LAMBDA,
      PARAMS_ML_DSA_44_GAMMA1_BITS, PARAMS_ML_DSA_44_GAMMA2,
      PARAMS_ML_DSA_44_W1_ENC_SZ, PARAMS_ML_DSA_44_A_SIZE,
      PARAMS_ML_DSA_44_S1_SIZE, PARAMS_ML_DSA_44_S1_ENC_SIZE,
      PARAMS_ML_DSA_44_S2_SIZE, PARAMS_ML_DSA_44_S2_ENC_SIZE,
      PARAMS_ML_DSA_44_Z_ENC_SIZE,
      PARAMS_ML_DSA_44_PK_SIZE, PARAMS_ML_DSA_44_SIG_SIZE },
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    { WC_ML_DSA_65_DRAFT, PARAMS_ML_DSA_65_K, PARAMS_ML_DSA_65_L,
      PARAMS_ML_DSA_65_ETA, PARAMS_ML_DSA_65_ETA_BITS,
      PARAMS_ML_DSA_65_TAU, PARAMS_ML_DSA_65_BETA, PARAMS_ML_DSA_65_OMEGA,
      PARAMS_ML_DSA_65_LAMBDA,
      PARAMS_ML_DSA_65_GAMMA1_BITS, PARAMS_ML_DSA_65_GAMMA2,
      PARAMS_ML_DSA_65_W1_ENC_SZ, PARAMS_ML_DSA_65_A_SIZE,
      PARAMS_ML_DSA_65_S1_SIZE, PARAMS_ML_DSA_65_S1_ENC_SIZE,
      PARAMS_ML_DSA_65_S2_SIZE, PARAMS_ML_DSA_65_S2_ENC_SIZE,
      PARAMS_ML_DSA_65_Z_ENC_SIZE,
      PARAMS_ML_DSA_65_PK_SIZE, PARAMS_ML_DSA_65_SIG_SIZE },
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
    { WC_ML_DSA_87_DRAFT, PARAMS_ML_DSA_87_K, PARAMS_ML_DSA_87_L,
      PARAMS_ML_DSA_87_ETA, PARAMS_ML_DSA_87_ETA_BITS,
      PARAMS_ML_DSA_87_TAU, PARAMS_ML_DSA_87_BETA, PARAMS_ML_DSA_87_OMEGA,
      PARAMS_ML_DSA_87_LAMBDA,
      PARAMS_ML_DSA_87_GAMMA1_BITS, PARAMS_ML_DSA_87_GAMMA2,
      PARAMS_ML_DSA_87_W1_ENC_SZ, PARAMS_ML_DSA_87_A_SIZE,
      PARAMS_ML_DSA_87_S1_SIZE, PARAMS_ML_DSA_87_S1_ENC_SIZE,
      PARAMS_ML_DSA_87_S2_SIZE, PARAMS_ML_DSA_87_S2_ENC_SIZE,
      PARAMS_ML_DSA_87_Z_ENC_SIZE,
      PARAMS_ML_DSA_87_PK_SIZE, PARAMS_ML_DSA_87_SIG_SIZE },
#endif
#endif
};
/* Number of ML-DSA parameter sets compiled in. */
#define DILITHIUM_PARAMS_CNT \
    ((unsigned int)(sizeof(dilithium_params) / sizeof(wc_dilithium_params)))

/* Get the ML-DSA parameters that match the level.
 *
 * @param [in]  level   Level required.
 * @param [out] params  Parameter set.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when parameters at level are not compiled in.
 */
static int dilithium_get_params(int level, const wc_dilithium_params** params)
{
    unsigned int i;
    int ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);

    for (i = 0; i < DILITHIUM_PARAMS_CNT; i++) {
        if (dilithium_params[i].level == level) {
            *params = &dilithium_params[i];
            ret = 0;
        }
    }

    return ret;
}

/******************************************************************************
 * Hash operations
 ******************************************************************************/

/* 256-bit hash using SHAKE-256.
 *
 * FIPS 204. 8.3: H(v,d) <- SHAKE256(v,d)
 *
 * @param [in, out] shake256  SHAKE-256 object.
 * @param [in]      data      Buffer holding data to hash.
 * @param [in]      dataLen   Length of data to hash in bytes.
 * @param [out]     hash      Buffer to hold hash result.
 * @param [in]      hashLen   Number of bytes of hash to return.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int dilithium_shake256(wc_Shake* shake256, const byte* data,
    word32 dataLen, byte* hash, word32 hashLen)
{
    int ret;

    /* Initialize SHAKE-256 operation. */
    ret = wc_InitShake256(shake256, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Update with data. */
        ret = wc_Shake256_Update(shake256, data, dataLen);
    }
    if (ret == 0) {
        /* Compute hash of data. */
        ret = wc_Shake256_Final(shake256, hash, hashLen);
    }

    return ret;
}

/* 256-bit hash using SHAKE-256.
 *
 * FIPS 204. 8.3: H(v,d) <- SHAKE256(v,d)
 *
 * @param [in, out] shake256  SHAKE-256 object.
 * @param [in]      data1     First block of data to hash.
 * @param [in]      data1Len  Length of first block in bytes.
 * @param [in]      data2     Second block of data to hash.
 * @param [in]      data2Len  Length of second block in bytes.
 * @param [out]     hash      Buffer to hold hash result.
 * @param [in]      hashLen   Number of bytes of hash to return.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int dilithium_hash256(wc_Shake* shake256, const byte* data1,
    word32 data1Len, const byte* data2, word32 data2Len, byte* hash,
    word32 hashLen)
{
    int ret;

    /* Initialize SHAKE-256 operation. */
    ret = wc_InitShake256(shake256, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Update with first data. */
        ret = wc_Shake256_Update(shake256, data1, data1Len);
    }
    if (ret == 0) {
        /* Update with second data. */
        ret = wc_Shake256_Update(shake256, data2, data2Len);
    }
    if (ret == 0) {
        /* Compute hash of data. */
        ret = wc_Shake256_Final(shake256, hash, hashLen);
    }

    return ret;
}

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
/* 256-bit hash of context and message using SHAKE-256.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.Sign(sk, M, ctx)
 *   ...
 *   10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                         ctx) || M
 *   ...
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.Sign_internal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64))
 *   ...
 *
 * @param [in, out] shake256  SHAKE-256 object.
 * @param [in]      tr        Public key hash.
 * @param [in]      trLen     Length of public key hash in bytes.
 * @param [in]      preHash   0 when message was not hashed,
 *                            1 when message was hashed.
 * @param [in]      ctx       Context of signature.
 * @param [in]      ctxLen    Length of context of signature in bytes.
 * @param [in]      ctx       Message to sign.
 * @param [in]      ctxLen    Length of message to sign in bytes.
 * @param [out]     hash      Buffer to hold hash result.
 * @param [in]      hashLen   Number of bytes of hash to return.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int dilithium_hash256_ctx_msg(wc_Shake* shake256, const byte* tr,
    byte trLen, byte preHash, const byte* ctx, byte ctxLen, const byte* msg,
    word32 msgLen, byte* hash, word32 hashLen)
{
    int ret;
    byte prefix[2];

    prefix[0] = preHash;
    prefix[1] = ctxLen;

    /* Initialize SHAKE-256 operation. */
    ret = wc_InitShake256(shake256, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Update with public key hash. */
        ret = wc_Shake256_Update(shake256, tr, trLen);
    }
    if (ret == 0) {
        /* Update with context prefix - 0 | ctxLen. */
        ret = wc_Shake256_Update(shake256, prefix, (word32)sizeof(prefix));
    }
    if (ret == 0) {
        /* Update with context. */
        ret = wc_Shake256_Update(shake256, ctx, ctxLen);
    }
    if (ret == 0) {
        /* Update with message. */
        ret = wc_Shake256_Update(shake256, msg, msgLen);
    }
    if (ret == 0) {
        /* Compute hash of data. */
        ret = wc_Shake256_Final(shake256, hash, hashLen);
    }

    return ret;
}

/* Get the OID for the digest hash.
 *
 * @param [in]  hash         Hash algorithm.
 * @param [out] oidBuffer   Buffer to hold OID.
 * @param [out] oidLen      Length of OID in buffer.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if hash algorithm not known.
 */
static int dilithium_get_hash_oid(int hash, byte* oidBuffer, word32* oidLen)
{
    int ret = 0;
    const byte* oid;

#ifndef WOLFSSL_DILITHIUM_NO_ASN1

    oid = OidFromId(wc_HashGetOID((enum wc_HashType)hash), oidHashType, oidLen);
    if ((oid != NULL) && (*oidLen <= DILITHIUM_HASH_OID_LEN - 2)) {
#ifndef WOLFSSL_DILITHIUM_REVERSE_HASH_OID
        oidBuffer[0] = 0x06;   /* ObjectID */
        oidBuffer[1] = *oidLen;   /* ObjectID */
        oidBuffer += 2;
        XMEMCPY(oidBuffer, oid, *oidLen);
#else
        int i;
        for (i = (int)*oidLen - 1; i >= 0; i--) {
            *(oidBuffer++) = oid[i];
        }
        *(oidBuffer++) = *oidLen;   /* ObjectID */
        * oidBuffer    = 0x06;   /* ObjectID */
#endif
        *oidLen += 2;
     }
     else {
        ret = BAD_FUNC_ARG;
    }

#else

    *oidLen = DILITHIUM_HASH_OID_LEN;
#ifndef NO_SHA256
    if (hash == WC_HASH_TYPE_SHA256) {
        static byte sha256Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
        };
        oid = sha256Oid;
    }
    else
#endif
#ifdef WOLFSSL_SHA384
    if (hash == WC_HASH_TYPE_SHA384) {
        static byte sha384Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
        };
        oid = sha384Oid;
    }
    else
#endif
#ifdef WOLFSSL_SHA512
    if (hash == WC_HASH_TYPE_SHA512) {
        static byte sha512Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
        };
        oid = sha512Oid;
    }
    else
#ifndef WOLFSSL_NOSHA512_256
    if (hash == WC_HASH_TYPE_SHA512_256) {
        static byte sha512_256Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06
        };
        oid = sha512_256Oid;
    }
    else
#endif
#endif
    if (hash == WC_HASH_TYPE_SHAKE128) {
        static byte shake128Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B
        };
        oid = shake128Oid;
    }
    else if (hash == WC_HASH_TYPE_SHAKE256) {
        static byte shake256Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C
        };
        oid = shake256Oid;
    }
    else if (hash == WC_HASH_TYPE_SHA3_256) {
        static byte sha3_256Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
        };
        oid = sha3_256Oid;
    }
    else if (hash == WC_HASH_TYPE_SHA3_384) {
        static byte sha3_384Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
        };
        oid = sha3_384Oid;
    }
    else if (hash == WC_HASH_TYPE_SHA3_512) {
        static byte sha3_512Oid[DILITHIUM_HASH_OID_LEN] = {
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A
        };
        oid = sha3_512Oid;
    }
    else {
        oid = NULL;
        ret = BAD_FUNC_ARG;
    }

    if ((oid != NULL) && (*oidLen <= DILITHIUM_HASH_OID_LEN)) {
#ifndef WOLFSSL_DILITHIUM_REVERSE_HASH_OID
        XMEMCPY(oidBuffer, oid, *oidLen);
#else
        int i;
        for (i = (int)*oidLen - 1; i >= 0; i--) {
            *(oidBuffer++) = oid[i];
        }
#endif
    }
#endif

    return ret;
}
#endif

#ifndef WOLFSSL_DILITHIUM_SMALL
/* 128-bit hash using SHAKE-128.
 *
 * FIPS 204. 8.3: H128(v,d) <- SHAKE128(v,d)
 *
 * @param [in, out] shake128  SHAKE-128 object.
 * @param [in]      in        Block of data to hash.
 * @param [in]      inLen     Length of data in bytes.
 * @param [out]     out       Buffer to hold hash result.
 * @param [in]      outLen    Number of hash blocks to return.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int dilithium_squeeze128(wc_Shake* shake128, const byte* in,
    word32 inLen, byte* out, word32 outBlocks)
{
    int ret;

    /* Initialize SHAKE-128 operation. */
    ret = wc_InitShake128(shake128, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Absorb data - update plus final. */
        ret = wc_Shake128_Absorb(shake128, in, inLen);
    }
    if (ret == 0) {
        /* Squeeze out hash data. */
        ret = wc_Shake128_SqueezeBlocks(shake128, out, outBlocks);
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_SMALL */

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
    (!defined(WOLFSSL_DILITHIUM_SMALL) && \
     !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY))
/* 256-bit hash using SHAKE-256.
 *
 * FIPS 204. 8.3: H(v,d) <- SHAKE256(v,d)
 * Using SqueezeBlocks interface to get larger amounts of output.
 *
 * @param [in, out] shake256  SHAKE-256 object.
 * @param [in]      in        Block of data to hash.
 * @param [in]      inLen     Length of data in bytes.
 * @param [out]     out       Buffer to hold hash result.
 * @param [in]      outLen    Number of hash blocks to return.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_squeeze256(wc_Shake* shake256, const byte* in,
    word32 inLen, byte* out, word32 outBlocks)
{
    int ret;

    /* Initialize SHAKE-256 operation. */
    ret = wc_InitShake256(shake256, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Absorb data - update plus final. */
        ret = wc_Shake256_Absorb(shake256, in, inLen);
    }
    if (ret == 0) {
        /* Squeeze out hash data. */
        ret = wc_Shake256_SqueezeBlocks(shake256, out, outBlocks);
    }

    return ret;
}
#endif

/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
/* Encode vector of polynomials with range -ETA..ETA.
 *
 * FIPS 204. 8.2: Algorithm 18 skEncode(rho, K, tr, s1, s2, t0)
 *   ...
 *   2: for i from 0 to l - 1 do
 *   3:     sk <- sk || BitPack(s1[i], eta, eta)
 *   4: end for
 *   ...
 *   OR
 *   ...
 *   5: for i from 0 to k - 1 do
 *   6:     sk <- sk || BitPack(s2[i], eta, eta)
 *   7: end for
 *   ...
 *
 * FIPS 204. 8.2: Algorithm 11 BitPack(w, a, b)
 *   1: z <- ()
 *   2: for i from 0 to 255 do
 *   3:     z <- z||IntegerToBits(b - wi, bitlen(a + b))
 *   4: end for
 *   5: return BitsToBytes(z)
 *
 *   IntegerToBits makes bit array with width specified from integer.
 *   BitToBytes make a byte array from a bit array.
 *
 * @param [in]  s    Vector of polynomials to encode.
 * @param [in]  d    Dimension of vector.
 * @param [in]  eta  Range specifier of each value.
 * @param [out] p    Buffer to encode into.
 */
static void dilthium_vec_encode_eta_bits(const sword32* s, byte d, byte eta,
    byte* p)
{
    unsigned int i;
    unsigned int j;

#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_87)
    /* -2..2 */
    if (eta == DILITHIUM_ETA_2) {
        /* Setp 2 or 5: For each polynomial of vector. */
        for (i = 0; i < d; i++) {
            /* Step 3 or 6.
             * 3 bits to encode each number.
             * 8 numbers become 3 bytes. (8 * 3 bits = 3 * 8 bits) */
            for (j = 0; j < DILITHIUM_N; j += 8) {
                /* Make value a positive integer. */
                byte s0 = 2 - s[j + 0];
                byte s1 = 2 - s[j + 1];
                byte s2 = 2 - s[j + 2];
                byte s3 = 2 - s[j + 3];
                byte s4 = 2 - s[j + 4];
                byte s5 = 2 - s[j + 5];
                byte s6 = 2 - s[j + 6];
                byte s7 = 2 - s[j + 7];

                /* Pack 8 3-bit values into 3 bytes. */
                p[0] = (s0 >> 0) | (s1 << 3) | (s2 << 6);
                p[1] = (s2 >> 2) | (s3 << 1) | (s4 << 4) | (s5 << 7);
                p[2] = (s5 >> 1) | (s6 << 2) | (s7 << 5);
                /* Move to next place to encode into. */
                p += DILITHIUM_ETA_2_BITS;
            }
            /* Next polynomial. */
            s += DILITHIUM_N;
        }
    }
    else
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    /* -4..4 */
    if (eta == DILITHIUM_ETA_4) {
        for (i = 0; i < d; i++) {
        #ifdef WOLFSSL_DILITHIUM_SMALL
            /* Step 3 or 6.
             * 4 bits to encode each number.
             * 2 numbers become 1 bytes. (2 * 4 bits = 1 * 8 bits) */
            for (j = 0; j < DILITHIUM_N / 2; j++) {
                /* Make values positive and pack 2 4-bit values into 1 byte. */
                p[j] = (((byte)(4 - s[j * 2 + 0])) << 0) |
                       (((byte)(4 - s[j * 2 + 1])) << 4);
            }
        #else
            /* Step 3 or 6.
             * 4 bits to encode each number.
             * 8 numbers become 4 bytes. (8 * 4 bits = 4 * 8 bits) */
            for (j = 0; j < DILITHIUM_N / 2; j += 4) {
                /* Make values positive and pack 2 4-bit values into 1 byte. */
                p[j + 0] = (((byte)(4 - s[j * 2 + 0])) << 0) |
                           (((byte)(4 - s[j * 2 + 1])) << 4);
                p[j + 1] = (((byte)(4 - s[j * 2 + 2])) << 0) |
                           (((byte)(4 - s[j * 2 + 3])) << 4);
                p[j + 2] = (((byte)(4 - s[j * 2 + 4])) << 0) |
                           (((byte)(4 - s[j * 2 + 5])) << 4);
                p[j + 3] = (((byte)(4 - s[j * 2 + 6])) << 0) |
                           (((byte)(4 - s[j * 2 + 7])) << 4);
            }
        #endif
            /* Move to next place to encode into. */
            p += DILITHIUM_N / 2;
            /* Next polynomial. */
            s += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }
}
#endif /* !WOLFSSL_DILITHIUM_NO_MAKE_KEY */

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || defined(WOLFSSL_DILITHIUM_CHECK_KEY)

#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Decode polynomial with range -2..2.
 *
 * FIPS 204. 8.2: Algorithm 19 skDecode(sk)
 *   ...
 *   5: for i from 0 to l - 1 do
 *   6:     s1[i] <- BitUnpack(yi, eta, eta)
 *   7: end for
 *   ...
 *   OR
 *   ...
 *   8: for i from 0 to k - 1 do
 *   9:     s2[i] <- BitUnpack(zi, eta, eta)
 *  10: end for
 *   ...
 *  Where y and z are arrays of bit arrays.
 *
 * @param [in]  p    Buffer of data to decode.
 * @param [in]  s    Vector of decoded polynomials.
 */
static void dilithium_decode_eta_2_bits(const byte* p, sword32* s)
{
    unsigned int j;

    /* Step 6 or 9.
     * 3 bits to encode each number.
     * 8 numbers from 3 bytes. (8 * 3 bits = 3 * 8 bits) */
    for (j = 0; j < DILITHIUM_N; j += 8) {
        /* Get 3 bits and put in range of -2..2. */
        s[j + 0] = 2 - ((p[0] >> 0) & 0x7                      );
        s[j + 1] = 2 - ((p[0] >> 3) & 0x7                      );
        s[j + 2] = 2 - ((p[0] >> 6)       | ((p[1] << 2) & 0x7));
        s[j + 3] = 2 - ((p[1] >> 1) & 0x7                      );
        s[j + 4] = 2 - ((p[1] >> 4) & 0x7                      );
        s[j + 5] = 2 - ((p[1] >> 7)       | ((p[2] << 1) & 0x7));
        s[j + 6] = 2 - ((p[2] >> 2) & 0x7                      );
        s[j + 7] = 2 - ((p[2] >> 5) & 0x7                      );
        /* Move to next place to decode from. */
        p += DILITHIUM_ETA_2_BITS;
    }
}
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
/* Decode polynomial with range -4..4.
 *
 * FIPS 204. 8.2: Algorithm 19 skDecode(sk)
 *   ...
 *   5: for i from 0 to l - 1 do
 *   6:     s1[i] <- BitUnpack(yi, eta, eta)
 *   7: end for
 *   ...
 *   OR
 *   ...
 *   8: for i from 0 to k - 1 do
 *   9:     s2[i] <- BitUnpack(zi, eta, eta)
 *  10: end for
 *   ...
 *  Where y and z are arrays of bit arrays.
 *
 * @param [in]  p    Buffer of data to decode.
 * @param [in]  s    Vector of decoded polynomials.
 */
static void dilithium_decode_eta_4_bits(const byte* p, sword32* s)
{
    unsigned int j;

#ifdef WOLFSSL_DILITHIUM_SMALL
    /* Step 6 or 9.
     * 4 bits to encode each number.
     * 2 numbers from 1 bytes. (2 * 4 bits = 1 * 8 bits) */
    for (j = 0; j < DILITHIUM_N / 2; j++) {
        /* Get 4 bits and put in range of -4..4. */
        s[j * 2 + 0] = 4 - (p[j] & 0xf);
        s[j * 2 + 1] = 4 - (p[j] >> 4);
    }
#else
    /* Step 6 or 9.
     * 4 bits to encode each number.
     * 8 numbers from 4 bytes. (8 * 4 bits = 4 * 8 bits) */
    for (j = 0; j < DILITHIUM_N / 2; j += 4) {
        /* Get 4 bits and put in range of -4..4. */
        s[j * 2 + 0] = 4 - (p[j + 0] & 0xf);
        s[j * 2 + 1] = 4 - (p[j + 0] >> 4);
        s[j * 2 + 2] = 4 - (p[j + 1] & 0xf);
        s[j * 2 + 3] = 4 - (p[j + 1] >> 4);
        s[j * 2 + 4] = 4 - (p[j + 2] & 0xf);
        s[j * 2 + 5] = 4 - (p[j + 2] >> 4);
        s[j * 2 + 6] = 4 - (p[j + 3] & 0xf);
        s[j * 2 + 7] = 4 - (p[j + 3] >> 4);
    }
#endif /* WOLFSSL_DILITHIUM_SMALL */
}
#endif

#if defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     (defined(WC_DILITHIUM_CACHE_PRIV_VECTORS) || \
      !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)))
/* Decode vector of polynomials with range -ETA..ETA.
 *
 * FIPS 204. 8.2: Algorithm 19 skDecode(sk)
 *   ...
 *   5: for i from 0 to l - 1 do
 *   6:     s1[i] <- BitUnpack(yi, eta, eta)
 *   7: end for
 *   ...
 *   OR
 *   ...
 *   8: for i from 0 to k - 1 do
 *   9:     s2[i] <- BitUnpack(zi, eta, eta)
 *  10: end for
 *   ...
 *  Where y and z are arrays of bit arrays.
 *
 * @param [in]  p    Buffer of data to decode.
 * @param [in]  eta  Range specifier of each value.
 * @param [in]  s    Vector of decoded polynomials.
 * @param [in]  d    Dimension of vector.
 */
static void dilithium_vec_decode_eta_bits(const byte* p, byte eta, sword32* s,
    byte d)
{
    unsigned int i;

#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_87)
    /* -2..2 */
    if (eta == DILITHIUM_ETA_2) {
        /* Step 5 or 8: For each polynomial of vector */
        for (i = 0; i < d; i++) {
            dilithium_decode_eta_2_bits(p, s);
            /* Move to next place to decode from. */
            p += DILITHIUM_ETA_2_BITS * DILITHIUM_N / 8;
            /* Next polynomial. */
            s += DILITHIUM_N;
        }
    }
    else
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
    /* -4..4 */
    if (eta == DILITHIUM_ETA_4) {
        /* Step 5 or 8: For each polynomial of vector */
        for (i = 0; i < d; i++) {
            dilithium_decode_eta_4_bits(p, s);
            /* Move to next place to decode from. */
            p += DILITHIUM_N / 2;
            /* Next polynomial. */
            s += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }
}
#endif
#endif /* !WOLFSSL_DILITHIUM_NO_SIGN || WOLFSSL_DILITHIUM_CHECK_KEY */

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
/* Encode t into t0 and t1.
 *
 * FIPS 204. 8.4: Algorithm 29 Power2Round(r)
 *   1: r+ <- r mod q
 *   2: r0 <- r+ mod +/- 2^d
 *   3: return ((r+ - r0) / 2^d, r0)
 *
 * FIPS 204. 7.2: Algorithm 24 skEncode(rho, K, tr, s1, s2, t0)
 *   ...
 *   8: for i form 0 to k - 1 do
 *   9:     sk <- sk || BitPack(t0[i], s^(d-1) - 1, 2^(d-1))
 *  10: end for
 *
 * FIPS 204. 7.2: Algorithm 22 pkEncode(rho, t1)
 *   ...
 *   2: for i from 0 to k - 1 do
 *   3:     pk <- pk || SimpleBitPack(t1[i], 2^bitlen(q-1) - d - 1)
 *   4: end for
 *
 * @param [in]  t    Vector of polynomials.
 * @param [in]  d    Dimension of vector.
 * @param [out] t0   Buffer to encode bottom part of value of t into.
 * @param [out] t1   Buffer to encode top part of value of t into.
 */
static void dilithium_vec_encode_t0_t1(sword32* t, byte d, byte* t0, byte* t1)
{
    unsigned int i;
    unsigned int j;

    /* Alg 24, Step 8 and Alg 22, Step 2. For each polynomial of vector. */
    for (i = 0; i < d; i++) {
        /* Alg 24, Step 9 and Alg 22, Step 3.
         * Do all polynomial values - 8 at a time. */
        for (j = 0; j < DILITHIUM_N; j += 8) {
            /* Take 8 values of t and take top bits and make positive. */
            word16 n1_0 = (t[j + 0] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_1 = (t[j + 1] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_2 = (t[j + 2] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_3 = (t[j + 3] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_4 = (t[j + 4] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_5 = (t[j + 5] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_6 = (t[j + 6] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            word16 n1_7 = (t[j + 7] + DILITHIUM_D_MAX_HALF - 1) >> DILITHIUM_D;
            /* Take 8 values of t and take bottom bits and make positive. */
            word16 n0_0 = DILITHIUM_D_MAX_HALF -
                          (t[j + 0] - (n1_0 << DILITHIUM_D));
            word16 n0_1 = DILITHIUM_D_MAX_HALF -
                          (t[j + 1] - (n1_1 << DILITHIUM_D));
            word16 n0_2 = DILITHIUM_D_MAX_HALF -
                          (t[j + 2] - (n1_2 << DILITHIUM_D));
            word16 n0_3 = DILITHIUM_D_MAX_HALF -
                          (t[j + 3] - (n1_3 << DILITHIUM_D));
            word16 n0_4 = DILITHIUM_D_MAX_HALF -
                          (t[j + 4] - (n1_4 << DILITHIUM_D));
            word16 n0_5 = DILITHIUM_D_MAX_HALF -
                          (t[j + 5] - (n1_5 << DILITHIUM_D));
            word16 n0_6 = DILITHIUM_D_MAX_HALF -
                          (t[j + 6] - (n1_6 << DILITHIUM_D));
            word16 n0_7 = DILITHIUM_D_MAX_HALF -
                          (t[j + 7] - (n1_7 << DILITHIUM_D));

            /* 13 bits per number.
             * 8 numbers become 13 bytes. (8 * 13 bits = 13 * 8 bits) */
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 2)
            word32* tp;
        #endif
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
            tp = (word32*)t0;
            tp[0] =  (n0_0      ) | ((word32)n0_1 << 13) | ((word32)n0_2 << 26);
            tp[1] =  (n0_2 >>  6) | ((word32)n0_3 <<  7) | ((word32)n0_4 << 20);
            tp[2] =  (n0_4 >> 12) | ((word32)n0_5 <<  1) |
                                    ((word32)n0_6 << 14) | ((word32)n0_7 << 27);
        #else
            t0[ 0] =                (n0_0 <<  0);
            t0[ 1] = (n0_0 >>  8) | (n0_1 <<  5);
            t0[ 2] = (n0_1 >>  3)               ;
            t0[ 3] = (n0_1 >> 11) | (n0_2 <<  2);
            t0[ 4] = (n0_2 >>  6) | (n0_3 <<  7);
            t0[ 5] = (n0_3 >>  1)               ;
            t0[ 6] = (n0_3 >>  9) | (n0_4 <<  4);
            t0[ 7] = (n0_4 >>  4)               ;
            t0[ 8] = (n0_4 >> 12) | (n0_5 <<  1);
            t0[ 9] = (n0_5 >>  7) | (n0_6 <<  6);
            t0[10] = (n0_6 >>  2)               ;
            t0[11] = (n0_6 >> 10) | (n0_7 <<  3);
        #endif
            t0[12] = (n0_7 >>  5)               ;

            /* 10 bits per number.
             * 8 bytes become 10 bytes. (8 * 10 bits = 10 * 8 bits) */
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 2)
            tp = (word32*)t1;
            tp[0] =  (n1_0      ) | ((word32)n1_1 << 10) |
                     ((word32)n1_2 << 20) | ((word32)n1_3 << 30);
            tp[1] =  (n1_3 >>  2) | ((word32)n1_4 <<  8) |
                     ((word32)n1_5 << 18) | ((word32)n1_6 << 28);
        #else
            t1[0] =                (n1_0 << 0);
            t1[1] = (n1_0 >> 8) |  (n1_1 << 2);
            t1[2] = (n1_1 >> 6) |  (n1_2 << 4);
            t1[3] = (n1_2 >> 4) |  (n1_3 << 6);
            t1[4] = (n1_3 >> 2)               ;
            t1[5] =                (n1_4 << 0);
            t1[6] = (n1_4 >> 8) |  (n1_5 << 2);
            t1[7] = (n1_5 >> 6) |  (n1_6 << 4);
        #endif
            t1[8] = (n1_6 >> 4) |  (n1_7 << 6);
            t1[9] = (n1_7 >> 2)               ;

            /* Move to next place to encode bottom bits to. */
            t0 += DILITHIUM_D;
            /* Move to next place to encode top bits to. */
            t1 += DILITHIUM_U;
        }
        /* Next polynomial. */
        t += DILITHIUM_N;
    }
}
#endif /* !WOLFSSL_DILITHIUM_NO_MAKE_KEY */

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || defined(WOLFSSL_DILITHIUM_CHECK_KEY)
/* Decode bottom D bits of t as t0.
 *
 * FIPS 204. 8.2: Algorithm 19 skDecode(sk)
 *   ...
 *   12:     t0[i] <- BitUnpack(wi, 2^(d-1) - 1, 2^(d-1)
 *   ...
 *
 * @param [in]  t0  Encoded values of t0.
 * @param [in]  d   Dimensions of vector t0.
 * @param [out] t   Vector of polynomials.
 */
static void dilithium_decode_t0(const byte* t0, sword32* t)
{
    unsigned int j;

    /* Step 12. Get 13 bits and convert to range (2^(d-1)-1)..2^(d-1). */
    for (j = 0; j < DILITHIUM_N; j += 8) {
        /* 13 bits used per number.
         * 8 numbers from 13 bytes. (8 * 13 bits = 13 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
        word32 t32_2 = ((const word32*)t0)[2];
    #ifdef WC_64BIT_CPU
        word64 t64 = *(const word64*)t0;
        t[j + 0] = DILITHIUM_D_MAX_HALF - ( t64        & 0x1fff);
        t[j + 1] = DILITHIUM_D_MAX_HALF - ((t64 >> 13) & 0x1fff);
        t[j + 2] = DILITHIUM_D_MAX_HALF - ((t64 >> 26) & 0x1fff);
        t[j + 3] = DILITHIUM_D_MAX_HALF - ((t64 >> 39) & 0x1fff);
        t[j + 4] = DILITHIUM_D_MAX_HALF -
                   ((t64 >> 52) | ((t32_2 & 0x0001) << 12));
    #else
        word32 t32_0 = ((const word32*)t0)[0];
        word32 t32_1 = ((const word32*)t0)[1];
        t[j + 0] = DILITHIUM_D_MAX_HALF -
                    ( t32_0        & 0x1fff);
        t[j + 1] = DILITHIUM_D_MAX_HALF -
                    ((t32_0 >> 13) & 0x1fff);
        t[j + 2] = DILITHIUM_D_MAX_HALF -
                   (( t32_0 >> 26          ) | ((t32_1 & 0x007f) <<  6));
        t[j + 3] = DILITHIUM_D_MAX_HALF -
                    ((t32_1 >>  7) & 0x1fff);
        t[j + 4] = DILITHIUM_D_MAX_HALF -
                   (( t32_1 >> 20          ) | ((t32_2 & 0x0001) << 12));
    #endif
        t[j + 5] = DILITHIUM_D_MAX_HALF -
                    ((t32_2 >>  1) & 0x1fff);
        t[j + 6] = DILITHIUM_D_MAX_HALF -
                    ((t32_2 >> 14) & 0x1fff);
        t[j + 7] = DILITHIUM_D_MAX_HALF -
                   (( t32_2 >> 27          ) | ((word32)t0[12] ) <<  5 );
#else
        t[j + 0] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 0]     ) | (((word16)(t0[ 1] & 0x1f)) <<  8));
        t[j + 1] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 1] >> 5) | (((word16)(t0[ 2]       )) <<  3) |
                                    (((word16)(t0[ 3] & 0x03)) << 11));
        t[j + 2] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 3] >> 2) | (((word16)(t0[ 4] & 0x7f)) <<  6));
        t[j + 3] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 4] >> 7) | (((word16)(t0[ 5]       )) <<  1) |
                                    (((word16)(t0[ 6] & 0x0f)) <<  9));
        t[j + 4] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 6] >> 4) | (((word16)(t0[ 7]       )) <<  4) |
                                    (((word16)(t0[ 8] & 0x01)) << 12));
        t[j + 5] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 8] >> 1) | (((word16)(t0[ 9] & 0x3f)) <<  7));
        t[j + 6] = DILITHIUM_D_MAX_HALF -
                   ((t0[ 9] >> 6) | (((word16)(t0[10]       )) <<  2) |
                                    (((word16)(t0[11] & 0x07)) << 10));
        t[j + 7] = DILITHIUM_D_MAX_HALF -
                   ((t0[11] >> 3) | (((word16)(t0[12]       )) <<  5));
#endif
        /* Move to next place to decode from. */
        t0 += DILITHIUM_D;
    }
}

#if defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     (defined(WC_DILITHIUM_CACHE_PRIV_VECTORS) || \
      !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)))
/* Decode bottom D bits of t as t0.
 *
 * FIPS 204. 8.2: Algorithm 19 skDecode(sk)
 *   ...
 *   11: for i from 0 to k - 1 do
 *   12:     t0[i] <- BitUnpack(wi, 2^(d-1) - 1, 2^(d-1)
 *   13: end for
 *   ...
 *
 * @param [in]  t0  Encoded values of t0.
 * @param [in]  d   Dimensions of vector t0.
 * @param [out] t   Vector of polynomials.
 */
static void dilithium_vec_decode_t0(const byte* t0, byte d, sword32* t)
{
    unsigned int i;

    /* Step 11. For each polynomial of vector. */
    for (i = 0; i < d; i++) {
        dilithium_decode_t0(t0, t);
        t0 += DILITHIUM_D * DILITHIUM_N / 8;
        /* Next polynomial. */
        t += DILITHIUM_N;
    }
}
#endif
#endif /* !WOLFSSL_DILITHIUM_NO_SIGN || WOLFSSL_DILITHIUM_CHECK_KEY */

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY)
/* Decode top bits of t as t1.
 *
 * FIPS 204. 8.2: Algorithm 17 pkDecode(pk)
 *   ...
 *   4:     t1[i] <- SimpleBitUnpack(zi, 2^(bitlen(q-1)-d) - 1)
 *   ...
 *
 * @param [in]  t1  Encoded values of t1.
 * @param [out] t   Polynomials.
 */
static void dilithium_decode_t1(const byte* t1, sword32* t)
{
    unsigned int j;
    /* Step 4. Get 10 bits as a number. */
    for (j = 0; j < DILITHIUM_N; j += 8) {
        /* 10 bits used per number.
         * 8 numbers from 10 bytes. (8 * 10 bits = 10 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
    #ifdef WC_64BIT_CPU
        word64 t64 = *(const word64*) t1;
        word16 t16 = *(const word16*)(t1 + 8);
        t[j+0] = (sword32)( ( t64                     & 0x03ff) << DILITHIUM_D);
        t[j+1] = (sword32)( ((t64 >> 10)              & 0x03ff) << DILITHIUM_D);
        t[j+2] = (sword32)( ((t64 >> 20)              & 0x03ff) << DILITHIUM_D);
        t[j+3] = (sword32)( ((t64 >> 30)              & 0x03ff) << DILITHIUM_D);
        t[j+4] = (sword32)( ((t64 >> 40)              & 0x03ff) << DILITHIUM_D);
        t[j+5] = (sword32)( ((t64 >> 50)              & 0x03ff) << DILITHIUM_D);
        t[j+6] = (sword32)((((t64 >> 60)| (t16 << 4)) & 0x03ff) << DILITHIUM_D);
        t[j+7] = (sword32)( ((t16 >>  6)              & 0x03ff) << DILITHIUM_D);
    #else
        word32 t32 = *((const word32*)t1);
        t[j + 0] = ( t32        & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 1] = ((t32 >> 10) & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 2] = ((t32 >> 20) & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 3] = ((t32 >> 30)          | (((word16)t1[4]) << 2)) <<
                   DILITHIUM_D;
        t32 = *((const word32*)(t1 + 5));
        t[j + 4] = ( t32        & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 5] = ((t32 >> 10) & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 6] = ((t32 >> 20) & 0x03ff                         ) <<
                   DILITHIUM_D;
        t[j + 7] = ((t32 >> 30)          | (((word16)t1[9]) << 2)) <<
                   DILITHIUM_D;
    #endif
#else
        t[j + 0] = (sword32)((t1[0] >> 0) | (((word16)(t1[1] & 0x03)) << 8))
                   << DILITHIUM_D;
        t[j + 1] = (sword32)((t1[1] >> 2) | (((word16)(t1[2] & 0x0f)) << 6))
                   << DILITHIUM_D;
        t[j + 2] = (sword32)((t1[2] >> 4) | (((word16)(t1[3] & 0x3f)) << 4))
                   << DILITHIUM_D;
        t[j + 3] = (sword32)((t1[3] >> 6) | (((word16)(t1[4]       )) << 2))
                   << DILITHIUM_D;
        t[j + 4] = (sword32)((t1[5] >> 0) | (((word16)(t1[6] & 0x03)) << 8))
                   << DILITHIUM_D;
        t[j + 5] = (sword32)((t1[6] >> 2) | (((word16)(t1[7] & 0x0f)) << 6))
                   << DILITHIUM_D;
        t[j + 6] = (sword32)((t1[7] >> 4) | (((word16)(t1[8] & 0x3f)) << 4))
                   << DILITHIUM_D;
        t[j + 7] = (sword32)((t1[8] >> 6) | (((word16)(t1[9]       )) << 2))
                   << DILITHIUM_D;
#endif
        /* Move to next place to decode from. */
        t1 += DILITHIUM_U;
    }
}
#endif

#if (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY)
/* Decode top bits of t as t1.
 *
 * FIPS 204. 8.2: Algorithm 17 pkDecode(pk)
 *   ...
 *   3: for i from 0 to k - 1 do
 *   4:     t1[i] <- SimpleBitUnpack(zi, 2^(bitlen(q-1)-d) - 1)
 *   5: end for
 *   ...
 *
 * @param [in]  t1  Encoded values of t1.
 * @param [in]  d   Dimensions of vector t1.
 * @param [out] t   Vector of polynomials.
 */
static void dilithium_vec_decode_t1(const byte* t1, byte d, sword32* t)
{
    unsigned int i;

    /* Step 3. For each polynomial of vector. */
    for (i = 0; i < d; i++) {
        dilithium_decode_t1(t1, t);
        /* Next polynomial. */
        t1 += DILITHIUM_U * DILITHIUM_N / 8;
        t += DILITHIUM_N;
    }
}
#endif

#ifndef WOLFSSL_DILITHIUM_NO_SIGN

#ifndef WOLFSSL_NO_ML_DSA_44
/* Encode z with range of -(GAMMA1-1)...GAMMA1
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   3:     sigma <- sigma || BitPack(z[i], GAMMA1 - 1, GAMMA1)
 *   ...
 *
 * @param [in]  z     Polynomial to encode.
 * @param [out] s     Buffer to encode into.
 */
static void dilithium_encode_gamma1_17_bits(const sword32* z, byte* s)
{
    unsigned int j;

    /* Step 3. Get 18 bits as a number. */
    for (j = 0; j < DILITHIUM_N; j += 4) {
        word32 z0 = DILITHIUM_GAMMA1_17 - z[j + 0];
        word32 z1 = DILITHIUM_GAMMA1_17 - z[j + 1];
        word32 z2 = DILITHIUM_GAMMA1_17 - z[j + 2];
        word32 z3 = DILITHIUM_GAMMA1_17 - z[j + 3];

        /* 18 bits per number.
         * 8 numbers become 9 bytes. (8 * 9 bits = 9 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
    #ifdef WC_64BIT_CPU
        word64* s64p = (word64*)s;
        s64p[0] =           z0        | ((word64)z1 << 18) |
                   ((word64)z2 << 36) | ((word64)z3 << 54);
    #else
        word32* s32p = (word32*)s;
        s32p[0] =  z0        | (z1 << 18)             ;
        s32p[1] = (z1 >> 14) | (z2 <<  4) | (z3 << 22);
    #endif
#else
        s[0] =  z0                   ;
        s[1] =  z0 >>  8             ;
        s[2] = (z0 >> 16) | (z1 << 2);
        s[3] =  z1 >>  6             ;
        s[4] = (z1 >> 14) | (z2 << 4);
        s[5] =  z2 >>  4             ;
        s[6] = (z2 >> 12) | (z3 << 6);
        s[7] =  z3 >>  2             ;
#endif
        s[8] =  z3 >> 10             ;
        /* Move to next place to encode to. */
        s += DILITHIUM_GAMMA1_17_ENC_BITS / 2;
    }
}
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Encode z with range of -(GAMMA1-1)...GAMMA1
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   3:     sigma <- sigma || BitPack(z[i], GAMMA1 - 1, GAMMA1)
 *   ...
 *
 * @param [in]  z     Polynomial to encode.
 * @param [out] s     Buffer to encode into.
 */
static void dilithium_encode_gamma1_19_bits(const sword32* z, byte* s)
{
    unsigned int j;

    /* Step 3. Get 20 bits as a number. */
    for (j = 0; j < DILITHIUM_N; j += 4) {
        sword32 z0 = DILITHIUM_GAMMA1_19 - z[j + 0];
        sword32 z1 = DILITHIUM_GAMMA1_19 - z[j + 1];
        sword32 z2 = DILITHIUM_GAMMA1_19 - z[j + 2];
        sword32 z3 = DILITHIUM_GAMMA1_19 - z[j + 3];

        /* 20 bits per number.
         * 4 numbers become 10 bytes. (4 * 20 bits = 10 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 2)
        word16* s16p = (word16*)s;
    #ifdef WC_64BIT_CPU
        word64* s64p = (word64*)s;
        s64p[0] =           z0        | ((word64)z1 << 20) |
                   ((word64)z2 << 40) | ((word64)z3 << 60);
    #else
        word32* s32p = (word32*)s;
        s32p[0] =  z0        | (z1 << 20)             ;
        s32p[1] = (z1 >> 12) | (z2 <<  8) | (z3 << 28);
    #endif
        s16p[4] = (z3 >>  4)                          ;
#else
        s[0] =  z0                   ;
        s[1] = (z0 >>  8)            ;
        s[2] = (z0 >> 16) | (z1 << 4);
        s[3] = (z1 >>  4)            ;
        s[4] = (z1 >> 12)            ;
        s[5] =  z2                   ;
        s[6] = (z2 >>  8)            ;
        s[7] = (z2 >> 16) | (z3 << 4);
        s[8] = (z3 >>  4)            ;
        s[9] = (z3 >> 12)            ;
#endif
        /* Move to next place to encode to. */
        s += DILITHIUM_GAMMA1_19_ENC_BITS / 2;
    }
}
#endif

#ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
/* Encode z with range of -(GAMMA1-1)...GAMMA1
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   2: for i form 0 to l - 1 do
 *   3:     sigma <- sigma || BitPack(z[i], GAMMA1 - 1, GAMMA1)
 *   4: end for
 *   ...
 *
 * @param [in]  z     Vector of polynomials to encode.
 * @param [in]  l     Dimension of vector.
 * @param [in]  bits  Number of bits used in encoding - GAMMA1 bits.
 * @param [out] s     Buffer to encode into.
 */
static void dilithium_vec_encode_gamma1(const sword32* z, byte l, int bits,
    byte* s)
{
    unsigned int i;

    (void)l;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (bits == DILITHIUM_GAMMA1_BITS_17) {
        /* Step 2. For each polynomial of vector. */
        for (i = 0; i < PARAMS_ML_DSA_44_L; i++) {
            dilithium_encode_gamma1_17_bits(z, s);
            /* Move to next place to encode to. */
            s += DILITHIUM_GAMMA1_17_ENC_BITS / 2 * DILITHIUM_N / 4;
            /* Next polynomial. */
            z += DILITHIUM_N;
        }
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (bits == DILITHIUM_GAMMA1_BITS_19) {
        /* Step 2. For each polynomial of vector. */
        for (i = 0; i < l; i++) {
            dilithium_encode_gamma1_19_bits(z, s);
            /* Move to next place to encode to. */
            s += DILITHIUM_GAMMA1_19_ENC_BITS / 2 * DILITHIUM_N / 4;
            /* Next polynomial. */
            z += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }
}
#endif /* WOLFSSL_DILITHIUM_SIGN_SMALL_MEM */

#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
/* Decode polynomial with range -(GAMMA1-1)..GAMMA1.
 *
 * FIPS 204. 8.2: Algorithm 21 sigDecode(sigma)
 *   ...
 *   4:     z[i] <- BitUnpack(xi, GAMMA1 - 1, GAMMA1)
 *   ...
 *
 * @param [in]  s     Encoded values of z.
 * @param [in]  bits  Number of bits used in encoding - GAMMA1 bits.
 * @param [out] z     Polynomial to fill.
 */
static void dilithium_decode_gamma1(const byte* s, int bits, sword32* z)
{
    unsigned int i;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (bits == DILITHIUM_GAMMA1_BITS_17) {
#if defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE) || defined(WOLFSSL_DILITHIUM_SMALL)
        /* Step 4: Get 18 bits as a number. */
        for (i = 0; i < DILITHIUM_N; i += 4) {
            /* 18 bits per number.
             * 4 numbers from 9 bytes. (4 * 18 bits = 9 * 8 bits) */
    #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
        #ifdef WC_64BIT_CPU
            word64 s64_0 = *(const word64*)(s+0);
            z[i+0] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s64_0        & 0x3ffff                   );
            z[i+1] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 18) & 0x3ffff                   );
            z[i+2] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 36) & 0x3ffff                   );
            z[i+3] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 54) | (((word32)s[8])     << 10));
        #else
            word32 s32_0 = ((const word32*)(s+0))[0];
            word32 s32_1 = ((const word32*)(s+0))[1];
            z[i+0] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s32_0        & 0x3ffff                    );
            z[i+1] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_0 >> 18) | (((s32_1 & 0x0000f) << 14)));
            z[i+2] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_1 >>  4) & 0x3ffff);
            z[i+3] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_1 >> 22) | (((word32)s[8])     << 10 ));
        #endif
    #else
            z[i+0] = DILITHIUM_GAMMA1_17 -
                     ( s[ 0]       | ((sword32)(s[ 1] << 8) |
                      (sword32)(s[ 2] & 0x03) << 16));
            z[i+1] = DILITHIUM_GAMMA1_17 -
                     ((s[ 2] >> 2) | ((sword32)(s[ 3] << 6) |
                      (sword32)(s[ 4] & 0x0f) << 14));
            z[i+2] = DILITHIUM_GAMMA1_17 -
                     ((s[ 4] >> 4) | ((sword32)(s[ 5] << 4) |
                      (sword32)(s[ 6] & 0x3f) << 12));
            z[i+3] = DILITHIUM_GAMMA1_17 -
                     ((s[ 6] >> 6) | ((sword32)(s[ 7] << 2) |
                      (sword32)(s[ 8]       ) << 10));
    #endif
            /* Move to next place to decode from. */
            s += DILITHIUM_GAMMA1_17_ENC_BITS / 2;
        }
#else
        /* Step 4: Get 18 bits as a number. */
        for (i = 0; i < DILITHIUM_N; i += 8) {
            /* 18 bits per number.
             * 8 numbers from 9 bytes. (8 * 18 bits = 18 * 8 bits) */
    #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
        #ifdef WC_64BIT_CPU
            word64 s64_0 = *(const word64*)(s+0);
            word64 s64_1 = *(const word64*)(s+9);
            z[i+0] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s64_0        & 0x3ffff                   );
            z[i+1] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 18) & 0x3ffff                   );
            z[i+2] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 36) & 0x3ffff                   );
            z[i+3] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_0 >> 54) | (((word32)s[8])     << 10));
            z[i+4] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s64_1        & 0x3ffff                   );
            z[i+5] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_1 >> 18) & 0x3ffff                   );
            z[i+6] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_1 >> 36) & 0x3ffff                   );
            z[i+7] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s64_1 >> 54) | (((word32)s[17])    << 10));
        #else
            word32 s32_0 = ((const word32*)(s+0))[0];
            word32 s32_1 = ((const word32*)(s+0))[1];
            word32 s32_2 = ((const word32*)(s+9))[0];
            word32 s32_3 = ((const word32*)(s+9))[1];
            z[i+0] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s32_0        & 0x3ffff                    );
            z[i+1] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_0 >> 18) | (((s32_1 & 0x0000f) << 14)));
            z[i+2] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_1 >>  4) & 0x3ffff);
            z[i+3] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_1 >> 22) | (((word32)s[8])     << 10 ));
            z[i+4] = (word32)DILITHIUM_GAMMA1_17 -
                             ( s32_2        & 0x3ffff                    );
            z[i+5] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_2 >> 18) | (((s32_3 & 0x0000f) << 14)));
            z[i+6] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_3 >>  4) & 0x3ffff);
            z[i+7] = (word32)DILITHIUM_GAMMA1_17 -
                             ((s32_3 >> 22) | (((word32)s[17])    << 10 ));
        #endif
    #else
            z[i+0] = DILITHIUM_GAMMA1_17 -
                     ( s[ 0]       | ((sword32)(s[ 1] << 8) |
                      (sword32)(s[ 2] & 0x03) << 16));
            z[i+1] = DILITHIUM_GAMMA1_17 -
                     ((s[ 2] >> 2) | ((sword32)(s[ 3] << 6) |
                      (sword32)(s[ 4] & 0x0f) << 14));
            z[i+2] = DILITHIUM_GAMMA1_17 -
                     ((s[ 4] >> 4) | ((sword32)(s[ 5] << 4) |
                      (sword32)(s[ 6] & 0x3f) << 12));
            z[i+3] = DILITHIUM_GAMMA1_17 -
                     ((s[ 6] >> 6) | ((sword32)(s[ 7] << 2) |
                      (sword32)(s[ 8]       ) << 10));
            z[i+4] = DILITHIUM_GAMMA1_17 -
                     ( s[ 9]       | ((sword32)(s[10] << 8) |
                      (sword32)(s[11] & 0x03) << 16));
            z[i+5] = DILITHIUM_GAMMA1_17 -
                     ((s[11] >> 2) | ((sword32)(s[12] << 6) |
                      (sword32)(s[13] & 0x0f) << 14));
            z[i+6] = DILITHIUM_GAMMA1_17 -
                     ((s[13] >> 4) | ((sword32)(s[14] << 4) |
                      (sword32)(s[15] & 0x3f) << 12));
            z[i+7] = DILITHIUM_GAMMA1_17 -
                     ((s[15] >> 6) | ((sword32)(s[16] << 2) |
                      (sword32)(s[17]       ) << 10));
    #endif
            /* Move to next place to decode from. */
            s += DILITHIUM_GAMMA1_17_ENC_BITS;
        }
#endif
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (bits == DILITHIUM_GAMMA1_BITS_19) {
#if defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE) || defined(WOLFSSL_DILITHIUM_SMALL)
        /* Step 4: Get 20 bits as a number. */
        for (i = 0; i < DILITHIUM_N; i += 4) {
            /* 20 bits per number.
             * 4 numbers from 10 bytes. (4 * 20 bits = 10 * 8 bits) */
    #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 2)
            word16 s16_0 = ((const word16*)s)[4];
        #ifdef WC_64BIT_CPU
            word64 s64_0 = *(const word64*)s;
            z[i+0] = DILITHIUM_GAMMA1_19 - (  s64_0        & 0xfffff)   ;
            z[i+1] = DILITHIUM_GAMMA1_19 - ( (s64_0 >> 20) & 0xfffff)   ;
            z[i+2] = DILITHIUM_GAMMA1_19 - ( (s64_0 >> 40) & 0xfffff)   ;
            z[i+3] = DILITHIUM_GAMMA1_19 - (((s64_0 >> 60) & 0xfffff)   |
                                            ((sword32)s16_0      <<  4));
        #else
            word32 s32_0 = ((const word32*)s)[0];
            word32 s32_1 = ((const word32*)s)[1];
            z[i+0] = DILITHIUM_GAMMA1_19 - (  s32_0       & 0xfffff);
            z[i+1] = DILITHIUM_GAMMA1_19 - (( s32_0            >> 20) |
                                            ((s32_1 & 0x000ff) << 12));
            z[i+2] = DILITHIUM_GAMMA1_19 - ( (s32_1 >>  8) & 0xfffff);
            z[i+3] = DILITHIUM_GAMMA1_19 - (( s32_1            >> 28) |
                                            ((sword32)s16_0    <<  4));
        #endif
    #else
            z[i+0] = DILITHIUM_GAMMA1_19 - ( s[0]       | ((sword32)s[1] << 8) |
                                            ((sword32)(s[2] & 0x0f) << 16));
            z[i+1] = DILITHIUM_GAMMA1_19 - ((s[2] >> 4) | ((sword32)s[3] << 4) |
                                            ((sword32)(s[4]       ) << 12));
            z[i+2] = DILITHIUM_GAMMA1_19 - ( s[5]       | ((sword32)s[6] << 8) |
                                            ((sword32)(s[7] & 0x0f) << 16));
            z[i+3] = DILITHIUM_GAMMA1_19 - ((s[7] >> 4) | ((sword32)s[8] << 4) |
                                            ((sword32)(s[9]       ) << 12));
    #endif
            /* Move to next place to decode from. */
            s += DILITHIUM_GAMMA1_19_ENC_BITS / 2;
        }
#else
        /* Step 4: Get 20 bits as a number. */
        for (i = 0; i < DILITHIUM_N; i += 8) {
            /* 20 bits per number.
             * 8 numbers from 10 bytes. (8 * 20 bits = 20 * 8 bits) */
    #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 2)
            word16 s16_0 = ((const word16*)s)[4];
            word16 s16_1 = ((const word16*)s)[9];
        #ifdef WC_64BIT_CPU
            word64 s64_0 = *(const word64*)(s+0);
            word64 s64_1 = *(const word64*)(s+10);
            z[i+0] = DILITHIUM_GAMMA1_19 - (  s64_0        & 0xfffff)   ;
            z[i+1] = DILITHIUM_GAMMA1_19 - ( (s64_0 >> 20) & 0xfffff)   ;
            z[i+2] = DILITHIUM_GAMMA1_19 - ( (s64_0 >> 40) & 0xfffff)   ;
            z[i+3] = DILITHIUM_GAMMA1_19 - (((s64_0 >> 60) & 0xfffff)   |
                                            ((sword32)s16_0      <<  4));
            z[i+4] = DILITHIUM_GAMMA1_19 - (  s64_1        & 0xfffff)   ;
            z[i+5] = DILITHIUM_GAMMA1_19 - ( (s64_1 >> 20) & 0xfffff)   ;
            z[i+6] = DILITHIUM_GAMMA1_19 - ( (s64_1 >> 40) & 0xfffff)   ;
            z[i+7] = DILITHIUM_GAMMA1_19 - (((s64_1 >> 60) & 0xfffff)   |
                                            ((sword32)s16_1      <<  4));
        #else
            word32 s32_0 = ((const word32*)(s+ 0))[0];
            word32 s32_1 = ((const word32*)(s+ 0))[1];
            word32 s32_2 = ((const word32*)(s+10))[0];
            word32 s32_3 = ((const word32*)(s+10))[1];
            z[i+0] = DILITHIUM_GAMMA1_19 - (  s32_0       & 0xfffff);
            z[i+1] = DILITHIUM_GAMMA1_19 - (( s32_0            >> 20) |
                                            ((s32_1 & 0x000ff) << 12));
            z[i+2] = DILITHIUM_GAMMA1_19 - ( (s32_1 >>  8) & 0xfffff);
            z[i+3] = DILITHIUM_GAMMA1_19 - (( s32_1            >> 28) |
                                            ((sword32)s16_0    <<  4));
            z[i+4] = DILITHIUM_GAMMA1_19 - (  s32_2       & 0xfffff);
            z[i+5] = DILITHIUM_GAMMA1_19 - (( s32_2            >> 20) |
                                            ((s32_3 & 0x000ff) << 12));
            z[i+6] = DILITHIUM_GAMMA1_19 - ( (s32_3 >>  8) & 0xfffff);
            z[i+7] = DILITHIUM_GAMMA1_19 - (( s32_3            >> 28) |
                                            ((sword32)s16_1    <<  4));
        #endif
    #else
            z[i+0] = DILITHIUM_GAMMA1_19 - ( s[ 0]       |
                                            ((sword32)s[ 1] << 8) |
                                            ((sword32)(s[ 2] & 0x0f) << 16));
            z[i+1] = DILITHIUM_GAMMA1_19 - ((s[ 2] >> 4) |
                                            ((sword32) s[ 3] << 4) |
                                            ((sword32)(s[ 4]       ) << 12));
            z[i+2] = DILITHIUM_GAMMA1_19 - ( s[ 5]       |
                                            ((sword32) s[ 6] << 8) |
                                            ((sword32)(s[ 7] & 0x0f) << 16));
            z[i+3] = DILITHIUM_GAMMA1_19 - ((s[ 7] >> 4) |
                                            ((sword32) s[ 8] << 4) |
                                            ((sword32)(s[ 9]       ) << 12));
            z[i+4] = DILITHIUM_GAMMA1_19 - ( s[10]       |
                                            ((sword32) s[11] << 8) |
                                            ((sword32)(s[12] & 0x0f) << 16));
            z[i+5] = DILITHIUM_GAMMA1_19 - ((s[12] >> 4) |
                                            ((sword32) s[13] << 4) |
                                            ((sword32)(s[14]       ) << 12));
            z[i+6] = DILITHIUM_GAMMA1_19 - ( s[15]       |
                                            ((sword32) s[16] << 8) |
                                            ((sword32)(s[17] & 0x0f) << 16));
            z[i+7] = DILITHIUM_GAMMA1_19 - ((s[17] >> 4) |
                                            ((sword32) s[18] << 4) |
                                            ((sword32)(s[19]       ) << 12));
    #endif
            /* Move to next place to decode from. */
            s += DILITHIUM_GAMMA1_19_ENC_BITS;
        }
#endif
    }
    else
#endif
    {
    }
}
#endif

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY
/* Decode polynomial with range -(GAMMA1-1)..GAMMA1.
 *
 * FIPS 204. 8.2: Algorithm 21 sigDecode(sigma)
 *   ...
 *   3: for i from 0 to l - 1 do
 *   4:     z[i] <- BitUnpack(xi, GAMMA1 - 1, GAMMA1)
 *   5: end for
 *   ...
 *
 * @param [in]  x  Encoded values of t0.
 * @param [in]  l  Dimensions of vector z.
 * @param [in]  bits  Number of bits used in encoding - GAMMA1 bits.
 * @param [out] z  Vector of polynomials.
 */
static void dilithium_vec_decode_gamma1(const byte* x, byte l, int bits,
    sword32* z)
{
    unsigned int i;

    /* Step 3: For each polynomial of vector. */
    for (i = 0; i < l; i++) {
        /* Step 4: Unpack a polynomial. */
        dilithium_decode_gamma1(x, bits, z);
        /* Move pointers on to next polynomial. */
        x += DILITHIUM_N / 8 * (bits + 1);
        z += DILITHIUM_N;
    }
}
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
#ifndef WOLFSSL_NO_ML_DSA_44
/* Encode w1 with range of 0..((q-1)/(2*GAMMA2)-1).
 *
 * FIPS 204. 8.2: Algorithm 22 w1Encode(w1)
 *   ...
 *   3:     w1_tilde <- w1_tilde ||
 *                      ByteToBits(SimpleBitPack(w1[i], (q-1)/(2*GAMMA2)-1))
 *   ...
 *
 * @param [in]  w1      Vector of polynomials to encode.
 * @param [in]  gamma2  Maximum value in range.
 * @param [out] w1e     Buffer to encode into.
 */
static void dilithium_encode_w1_88(const sword32* w1, byte* w1e)
{
    unsigned int j;

    /* Step 3: Encode a polynomial values 6 bits at a time. */
    for (j = 0; j < DILITHIUM_N; j += 16) {
        /* 6 bits per number.
         * 16 numbers in 12 bytes. (16 * 6 bits = 12 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 4)
        word32* w1e32 = (word32*)w1e;
        w1e32[0] =  w1[j+ 0]        | (w1[j+ 1] <<  6) |
                   (w1[j+ 2] << 12) | (w1[j+ 3] << 18) |
                   (w1[j+ 4] << 24) | (w1[j+ 5] << 30);
        w1e32[1] = (w1[j+ 5] >>  2) | (w1[j+ 6] <<  4) |
                   (w1[j+ 7] << 10) | (w1[j+ 8] << 16) |
                   (w1[j+ 9] << 22) | (w1[j+10] << 28);
        w1e32[2] = (w1[j+10] >>  4) | (w1[j+11] <<  2) |
                   (w1[j+12] <<  8) | (w1[j+13] << 14) |
                   (w1[j+14] << 20) | (w1[j+15] << 26);
#else
        w1e[ 0] =  w1[j+ 0]       | (w1[j+ 1] << 6);
        w1e[ 1] = (w1[j+ 1] >> 2) | (w1[j+ 2] << 4);
        w1e[ 2] = (w1[j+ 2] >> 4) | (w1[j+ 3] << 2);
        w1e[ 3] =  w1[j+ 4]       | (w1[j+ 5] << 6);
        w1e[ 4] = (w1[j+ 5] >> 2) | (w1[j+ 6] << 4);
        w1e[ 5] = (w1[j+ 6] >> 4) | (w1[j+ 7] << 2);
        w1e[ 6] =  w1[j+ 8]       | (w1[j+ 9] << 6);
        w1e[ 7] = (w1[j+ 9] >> 2) | (w1[j+10] << 4);
        w1e[ 8] = (w1[j+10] >> 4) | (w1[j+11] << 2);
        w1e[ 9] =  w1[j+12]       | (w1[j+13] << 6);
        w1e[10] = (w1[j+13] >> 2) | (w1[j+14] << 4);
        w1e[11] = (w1[j+14] >> 4) | (w1[j+15] << 2);
#endif
        /* Move to next place to encode to. */
        w1e += DILITHIUM_Q_HI_88_ENC_BITS * 2;
    }
}
#endif /* !WOLFSSL_NO_ML_DSA_44 */

#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Encode w1 with range of 0..((q-1)/(2*GAMMA2)-1).
 *
 * FIPS 204. 8.2: Algorithm 22 w1Encode(w1)
 *   ...
 *   3:     w1_tilde <- w1_tilde ||
 *                      ByteToBits(SimpleBitPack(w1[i], (q-1)/(2*GAMMA2)-1))
 *   ...
 *
 * @param [in]  w1      Vector of polynomials to encode.
 * @param [in]  gamma2  Maximum value in range.
 * @param [out] w1e     Buffer to encode into.
 */
static void dilithium_encode_w1_32(const sword32* w1, byte* w1e)
{
    unsigned int j;

    /* Step 3: Encode a polynomial values 4 bits at a time. */
    for (j = 0; j < DILITHIUM_N; j += 16) {
        /* 4 bits per number.
         * 16 numbers in 8 bytes. (16 * 4 bits = 8 * 8 bits) */
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT <= 8)
        word32* w1e32 = (word32*)w1e;
        w1e32[0] = (w1[j +  0] <<  0) | (w1[j +  1] <<  4) |
                   (w1[j +  2] <<  8) | (w1[j +  3] << 12) |
                   (w1[j +  4] << 16) | (w1[j +  5] << 20) |
                   (w1[j +  6] << 24) | (w1[j +  7] << 28);
        w1e32[1] = (w1[j +  8] <<  0) | (w1[j +  9] <<  4) |
                   (w1[j + 10] <<  8) | (w1[j + 11] << 12) |
                   (w1[j + 12] << 16) | (w1[j + 13] << 20) |
                   (w1[j + 14] << 24) | (w1[j + 15] << 28);
#else
        w1e[0] = w1[j +  0] | (w1[j +  1] << 4);
        w1e[1] = w1[j +  2] | (w1[j +  3] << 4);
        w1e[2] = w1[j +  4] | (w1[j +  5] << 4);
        w1e[3] = w1[j +  6] | (w1[j +  7] << 4);
        w1e[4] = w1[j +  8] | (w1[j +  9] << 4);
        w1e[5] = w1[j + 10] | (w1[j + 11] << 4);
        w1e[6] = w1[j + 12] | (w1[j + 13] << 4);
        w1e[7] = w1[j + 14] | (w1[j + 15] << 4);
#endif
        /* Move to next place to encode to. */
        w1e += DILITHIUM_Q_HI_32_ENC_BITS * 2;
    }
}
#endif
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
     (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
      !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))
/* Encode w1 with range of 0..((q-1)/(2*GAMMA2)-1).
 *
 * FIPS 204. 8.2: Algorithm 22 w1Encode(w1)
 *   1: w1_tilde = ()
 *   2: for i form 0 to k - 1 do
 *   3:     w1_tilde <- w1_tilde ||
 *                      ByteToBits(SimpleBitPack(w1[i], (q-1)/(2*GAMMA2)-1))
 *   4: end for
 *   5: return w1_tilde
 *
 * @param [in]  w1      Vector of polynomials to encode.
 * @param [in]  k       Dimension of vector.
 * @param [in]  gamma2  Maximum value in range.
 * @param [out] w1e     Buffer to encode into.
 */
static void dilithium_vec_encode_w1(const sword32* w1, byte k, sword32 gamma2,
    byte* w1e)
{
    unsigned int i;

    (void)k;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (gamma2 == DILITHIUM_Q_LOW_88) {
        /* Step 2. For each polynomial of vector. */
        for (i = 0; i < PARAMS_ML_DSA_44_K; i++) {
            dilithium_encode_w1_88(w1, w1e);
            /* Next polynomial. */
            w1 += DILITHIUM_N;
            w1e += DILITHIUM_Q_HI_88_ENC_BITS * 2 * DILITHIUM_N / 16;
        }
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (gamma2 == DILITHIUM_Q_LOW_32) {
        /* Step 2. For each polynomial of vector. */
        for (i = 0; i < k; i++) {
            dilithium_encode_w1_32(w1, w1e);
            /* Next polynomial. */
            w1 += DILITHIUM_N;
            w1e += DILITHIUM_Q_HI_32_ENC_BITS * 2 * DILITHIUM_N / 16;
        }
    }
    else
#endif
    {
    }
}
#endif

/******************************************************************************
 * Expand operations
 ******************************************************************************/

/* Generate a random polynomial by rejection.
 *
 * FIPS 204. 8.3: Algorithm 24 RejNTTPoly(rho)
 *   1: j <- 0
 *   2: c <- 0
 *   3: while j < 256 do
 *   4:    a_hat[j] <- CoeffFromThreeBytes(H128(rho)[[c]], H128(rho)[[c+1]],
 *                                         H128(rho)[[c+2]])
 *   5:    c <- c + 3
 *   6:    if a_hat[j] != falsam then
 *   7:       j <- j + 1
 *   8:    end if
 *   9: end while
 *  10: return a_hat
 *
 * FIPS 204. 8.1: Algorithm 8 CoeffFromThreeBytes(b0,b1,b2)
 *   1: if b2 > 127 then
 *   2:    b2 <- b2 - 128
 *   3. end if
 *   4. z <- 2^16.b2 + s^8.b1 + b0
 *   5. if z < q then return z
 *   6. else return falsam
 *   7. end if
 *
 * @param [in, out] shake128  SHAKE-128 object.
 * @param [in]      seed      Seed to hash to generate values.
 * @param [out]     a         Polynomial.
 * @param [in]      h         Buffer to hold hashes.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_rej_ntt_poly_ex(wc_Shake* shake128, byte* seed, sword32* a,
    byte* h)
{
    int ret = 0;
#ifdef WOLFSSL_DILITHIUM_SMALL
    int j = 0;

#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
    /* Reading 4 bytes for 3 so need to set 1 past for last read. */
    h[DILITHIUM_GEN_A_BLOCK_BYTES] = 0;
#endif

    /* Initialize SHAKE-128 object for new hash. */
    ret = wc_InitShake128(shake128, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Absorb the seed. */
        ret = wc_Shake128_Absorb(shake128, seed, DILITHIUM_GEN_A_SEED_SZ);
    }
    /* Keep generating more blocks and using triplets until we have enough.
     */
    while ((ret == 0) && (j < DILITHIUM_N)) {
         /* Squeeze out a block - 168 bytes = 56 values. */
        ret = wc_Shake128_SqueezeBlocks(shake128, h, 1);
        if (ret == 0) {
            int c;
            /* Use triplets until run out or have enough for polynomial. */
            for (c = 0; c < DILITHIUM_GEN_A_BLOCK_BYTES; c += 3) {
            #if defined(LITTLE_ENDIAN_ORDER) && \
                (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
                /* Load 32-bit value and mask out 23 bits. */
                sword32 t = *((sword32*)(h + c)) & 0x7fffff;
            #else
                /* Load 24-bit value and mask out 23 bits. */
                sword32 t = (h[c] + ((sword32)h[c+1] << 8) +
                             ((sword32)h[c+2] << 16)) & 0x7fffff;
            #endif
                /* Check if value is in valid range. */
                if (t < DILITHIUM_Q) {
                    /* Store value in polynomial and increment count of values.
                     */
                    a[j++] = t;
                    /* Check we whether we have enough yet. */
                    if (j == DILITHIUM_N) {
                        break;
                    }
                }
            }
        }
    }
#else
    unsigned int j = 0;
    unsigned int c;

    /* Generate enough SHAKE-128 output blocks to give high probability of
     * being able to get 256 valid 3-byte, 23-bit values from it. */
    ret = dilithium_squeeze128(shake128, seed, DILITHIUM_GEN_A_SEED_SZ, h,
        DILITHIUM_GEN_A_NBLOCKS);
    if (ret == 0) {
    #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
        /* Reading 4 bytes for 3 so need to set 1 past for last read. */
        h[DILITHIUM_GEN_A_BYTES] = 0;
    #endif

        /* Use the first 256 triplets and know we won't exceed required. */
    #ifdef WOLFSSL_DILITHIUM_NO_LARGE_CODE
        for (c = 0; c < (DILITHIUM_N - 1) * 3; c += 3) {
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
            /* Load 32-bit value and mask out 23 bits. */
            sword32 t = *((sword32*)(h + c)) & 0x7fffff;
        #else
            /* Load 24-bit value and mask out 23 bits. */
            sword32 t = (h[c] + ((sword32)h[c+1] << 8) +
                         ((sword32)h[c+2] << 16)) & 0x7fffff;
        #endif
            /* Check if value is in valid range. */
            if (t < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t;
            }
        }
        /* Use the remaining triplets, checking we have enough. */
        for (; c < DILITHIUM_GEN_A_BYTES; c += 3) {
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
            /* Load 32-bit value and mask out 23 bits. */
            sword32 t = *((sword32*)(h + c)) & 0x7fffff;
        #else
            /* Load 24-bit value and mask out 23 bits. */
            sword32 t = (h[c] + ((sword32)h[c+1] << 8) +
                         ((sword32)h[c+2] << 16)) & 0x7fffff;
        #endif
            /* Check if value is in valid range. */
            if (t < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t;
                /* Check we whether we have enough yet. */
                if (j == DILITHIUM_N) {
                    break;
                }
            }
        }
    #else
        /* Do 15 bytes at a time: 255 * 3 / 15 = 51 */
        for (c = 0; c < DILITHIUM_N * 3; c += 24) {
        #if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
            /* Load 32-bit value and mask out 23 bits. */
            sword32 t0 = *((sword32*)(h + c +  0)) & 0x7fffff;
            sword32 t1 = *((sword32*)(h + c +  3)) & 0x7fffff;
            sword32 t2 = *((sword32*)(h + c +  6)) & 0x7fffff;
            sword32 t3 = *((sword32*)(h + c +  9)) & 0x7fffff;
            sword32 t4 = *((sword32*)(h + c + 12)) & 0x7fffff;
            sword32 t5 = *((sword32*)(h + c + 15)) & 0x7fffff;
            sword32 t6 = *((sword32*)(h + c + 18)) & 0x7fffff;
            sword32 t7 = *((sword32*)(h + c + 21)) & 0x7fffff;
        #else
            /* Load 24-bit value and mask out 23 bits. */
            sword32 t0 = (h[c +  0] + ((sword32)h[c +  1] << 8) +
                          ((sword32)h[c +  2] << 16)) & 0x7fffff;
            sword32 t1 = (h[c +  3] + ((sword32)h[c +  4] << 8) +
                          ((sword32)h[c +  5] << 16)) & 0x7fffff;
            sword32 t2 = (h[c +  6] + ((sword32)h[c +  7] << 8) +
                          ((sword32)h[c +  8] << 16)) & 0x7fffff;
            sword32 t3 = (h[c +  9] + ((sword32)h[c + 10] << 8) +
                          ((sword32)h[c + 11] << 16)) & 0x7fffff;
            sword32 t4 = (h[c + 12] + ((sword32)h[c + 13] << 8) +
                          ((sword32)h[c + 14] << 16)) & 0x7fffff;
            sword32 t5 = (h[c + 15] + ((sword32)h[c + 16] << 8) +
                          ((sword32)h[c + 17] << 16)) & 0x7fffff;
            sword32 t6 = (h[c + 18] + ((sword32)h[c + 19] << 8) +
                          ((sword32)h[c + 20] << 16)) & 0x7fffff;
            sword32 t7 = (h[c + 21] + ((sword32)h[c + 22] << 8) +
                          ((sword32)h[c + 23] << 16)) & 0x7fffff;
        #endif
            /* Check if value is in valid range. */
            if (t0 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t0;
            }
            /* Check if value is in valid range. */
            if (t1 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t1;
            }
            /* Check if value is in valid range. */
            if (t2 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t2;
            }
            /* Check if value is in valid range. */
            if (t3 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t3;
            }
            /* Check if value is in valid range. */
            if (t4 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t4;
            }
            /* Check if value is in valid range. */
            if (t5 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t5;
            }
            /* Check if value is in valid range. */
            if (t6 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t6;
            }
            /* Check if value is in valid range. */
            if (t7 < DILITHIUM_Q) {
                /* Store value in polynomial and increment count of values. */
                a[j++] = t7;
            }
        }
        if (j < DILITHIUM_N) {
            /* Use the remaining triplets, checking we have enough. */
            for (; c < DILITHIUM_GEN_A_BYTES; c += 3) {
            #if defined(LITTLE_ENDIAN_ORDER) && \
                (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
                /* Load 32-bit value and mask out 23 bits. */
                sword32 t = *((sword32*)(h + c)) & 0x7fffff;
            #else
                /* Load 24-bit value and mask out 23 bits. */
                sword32 t = (h[c] + ((sword32)h[c+1] << 8) +
                             ((sword32)h[c+2] << 16)) & 0x7fffff;
            #endif
                /* Check if value is in valid range. */
                if (t < DILITHIUM_Q) {
                    /* Store value in polynomial and increment count of values.
                     */
                    a[j++] = t;
                    /* Check we whether we have enough yet. */
                    if (j == DILITHIUM_N) {
                        break;
                    }
                }
            }
        }
    #endif
        /* Keep generating more blocks and using triplets until we have enough.
         */
        while (j < DILITHIUM_N) {
            /* Squeeze out a block - 168 bytes = 56 values. */
            ret = wc_Shake128_SqueezeBlocks(shake128, h, 1);
            if (ret != 0) {
                break;
            }
            /* Use triplets until run out or have enough for polynomial. */
            for (c = 0; c < DILITHIUM_GEN_A_BLOCK_BYTES; c += 3) {
            #if defined(LITTLE_ENDIAN_ORDER) && \
                (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
                /* Load 32-bit value and mask out 23 bits. */
                sword32 t = *((sword32*)(h + c)) & 0x7fffff;
            #else
                /* Load 24-bit value and mask out 23 bits. */
                sword32 t = (h[c] + ((sword32)h[c+1] << 8) +
                             ((sword32)h[c+2] << 16)) & 0x7fffff;
            #endif
                /* Check if value is in valid range. */
                if (t < DILITHIUM_Q) {
                    /* Store value in polynomial and increment count of values.
                     */
                    a[j++] = t;
                    /* Check we whether we have enough yet. */
                    if (j == DILITHIUM_N) {
                        break;
                    }
                }
            }
        }
    }
#endif

    return ret;
}

#if (!defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
     !defined(WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM)) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))
/* Generate a random polynomial by rejection.
 *
 * @param [in, out] shake128  SHAKE-128 object.
 * @param [in]      seed      Seed to hash to generate values.
 * @param [out]     a         Polynomial.
 * @param [in]      heap      Dynamic memory hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Negative on hash error.
 */
static int dilithium_rej_ntt_poly(wc_Shake* shake128, byte* seed, sword32* a,
    void* heap)
{
    int ret;
#if defined(WOLFSSL_SMALL_STACK)
    byte* h = NULL;
#else
    byte h[DILITHIUM_REJ_NTT_POLY_H_SIZE];
#endif

    (void)heap;

#if defined(WOLFSSL_SMALL_STACK)
    h = (byte*)XMALLOC(DILITHIUM_REJ_NTT_POLY_H_SIZE, heap,
        DYNAMIC_TYPE_DILITHIUM);
    if (h == NULL) {
        ret = MEMORY_E;
    }
#endif

    ret = dilithium_rej_ntt_poly_ex(shake128, seed, a, h);

#if defined(WOLFSSL_SMALL_STACK)
    XFREE(h, heap, DYNAMIC_TYPE_DILITHIUM);
#endif

    return ret;
}
#endif

#if (!defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
     !defined(WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM)) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     (!defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM) || \
      defined(WC_DILITHIUM_CACHE_MATRIX_A)))
/* Expand the seed to create matrix a.
 *
 * FIPS 204. 8.3: Algorithm 26 ExpandA(rho)
 *   1: for r from 0 to k - 1 do
 *   2:     for s from 0 to l - 1 do
 *   3:         A_hat[r,s] <- RejNTTPoly(rho||IntegerToBits(s,8)||
 *                                       IntegerToBits(r,8))
 *   4:     end for
 *   5: end for
 *   6: return A_hat
 *
 * @param [in, out] shake128  SHAKE-128 object.
 * @param [in]      pub_seed  Seed to generate stream of data.
 * @param [in]      k         First dimension of matrix a.
 * @param [in]      l         Second dimension of matrix a.
 * @param [out]     a         Matrix of polynomials.
 * @param [in]      heap      Dynamic memory hint.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_expand_a(wc_Shake* shake128, const byte* pub_seed, byte k,
    byte l, sword32* a, void* heap)
{
    int ret = 0;
    byte r;
    byte s;
    byte seed[DILITHIUM_GEN_A_SEED_SZ];

    /* Copy the seed into a buffer that has space for s and r. */
    XMEMCPY(seed, pub_seed, DILITHIUM_PUB_SEED_SZ);
    /* Step 1: Loop over first dimension of matrix. */
    for (r = 0; (ret == 0) && (r < k); r++) {
        /* Put r into buffer to be hashed. */
        seed[DILITHIUM_PUB_SEED_SZ + 1] = r;
        /* Step 2: Loop over second dimension of matrix. */
        for (s = 0; (ret == 0) && (s < l); s++) {
            /* Put s into buffer to be hashed. */
            seed[DILITHIUM_PUB_SEED_SZ + 0] = s;
            /* Step 3: Create polynomial from hashing seed. */
            ret = dilithium_rej_ntt_poly(shake128, seed, a, heap);
            /* Next polynomial. */
            a += DILITHIUM_N;
        }
    }

    return ret;
}
#endif

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY

#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Check random value is in valid range.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1: if             b < 15
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 2 - unused.
 * @return  1 when value less than 9.
 * @return  0 when value greater than or equal to 9.
 */
#define DILITHIUM_COEFF_S_VALID_ETA2(b) \
    ((b) < DILITHIUM_ETA_2_MOD)

static const char dilithium_coeff_eta2[] = {
    2, 1, 0, -1, -2,
    2, 1, 0, -1, -2,
    2, 1, 0, -1, -2
};
/* Convert random value 0..15 to a value in range of -2..2.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1:                            return 2 - (b mod 5)
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @return  Value in range of -2..2 on success.
 */
#define DILITHIUM_COEFF_S_ETA2(b)       \
    (dilithium_coeff_eta2[b])
#endif

#ifndef WOLFSSL_NO_ML_DSA_65
/* Check random value is in valid range.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   3:     if             b < 9
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 4 - unused.
 * @return  1 when value less than 9.
 * @return  0 when value greater than or equal to 9.
 */
#define DILITHIUM_COEFF_S_VALID_ETA4(b) \
    ((b) < DILITHIUM_ETA_4_MOD)

/* Convert random value 0..15 to a value in range of -4..4.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   3:                               return 4 - b
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 4 - unused.
 * @return  Value in range of -4..4 on success.
 */
#define DILITHIUM_COEFF_S_ETA4(b)       \
    (4 - (b))
#endif

#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_87)
#ifndef WOLFSSL_NO_ML_DSA_65

/* Check random value is in valid range.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1: if eta = 2 and b < 15
 *   2: else
 *   3:     if eta = 4 and b < 9
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result.
 * @return  Value in range of -ETA..ETA on success.
 */
#define DILITHIUM_COEFF_S_VALID(b, eta)                             \
    (((eta) == DILITHIUM_ETA_2) ? DILITHIUM_COEFF_S_VALID_ETA2(b) : \
                                  DILITHIUM_COEFF_S_VALID_ETA4(b))

/* Convert random value 0..15 to a value in range of -ETA..ETA.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1: if eta = 2            then return 2 - (b mod 5)
 *   2: else
 *   3:     if eta = 4           then return 4 - b
 *   ...
 *   6: end if
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result.
 * @return  Value in range of -ETA..ETA on success.
 */
#define DILITHIUM_COEFF_S(b, eta)                               \
    (((eta) == DILITHIUM_ETA_2) ? DILITHIUM_COEFF_S_ETA2(b)     \
                                : DILITHIUM_COEFF_S_ETA4(b))

#else

/* Check random value is in valid range.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1: if             b < 15
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 2 - unused.
 * @return  1 when value less than 9.
 * @return  0 when value greater than or equal to 9.
 */
#define DILITHIUM_COEFF_S_VALID(b, eta) \
    DILITHIUM_COEFF_S_VALID_ETA2(b)

/* Convert random value 0..15 to a value in range of -2..2.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   1:                            return 2 - (b mod 5)
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 2 - unused.
 * @return  Value in range of -2..2 on success.
 */
#define DILITHIUM_COEFF_S(b, eta)   \
    DILITHIUM_COEFF_S_ETA2(b)

#endif /*  WOLFSSL_NO_ML_DSA_65 */

#else

/* Check random value is in valid range.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   3:     if             b < 9
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 4 - unused.
 * @return  1 when value less than 9.
 * @return  0 when value greater than or equal to 9.
 */
#define DILITHIUM_COEFF_S_VALID(b, eta) \
    DILITHIUM_COEFF_S_VALID_ETA4(b)

/* Convert random value 0..15 to a value in range of -4..4.
 *
 * FIPS 204. 8.1: Algorithm 9 CoeffFromHalfByte(b)
 *   3:                               return 4 - b
 *
 * @param [in] b    Random half-byte (nibble) value.
 * @param [in] eta  Range specifier of result. Will always be 4 - unused.
 * @return  Value in range of -4..4 on success.
 */
#define DILITHIUM_COEFF_S(b, eta)   \
    DILITHIUM_COEFF_S_ETA4(b)

#endif /* !WOLFSSL_NO_ML_DSA_44 || !WOLFSSL_NO_ML_DSA_87 */

/* Extract a coefficient from a nibble of z.
 *
 * Breaks out of loop when we have enough coefficients.
 *
 * @param [in] z    A random value.
 * @param [in] rs   Amount to shift right.
 * @param [in] t    Temporary result.
 * @param [in] eta  ETA value from parameters.
 * @return  Value in range -eta..eta on success.
 * @return  Falsam (0x10) when random value out of range.
 */
#define EXTRACT_COEFF_NIBBLE_CHECK_J(z, rs, t, eta)                     \
        (t) = (sword8)(((z) >> (rs)) & 0xf);                            \
        /* Step 7: Check we have a valid coefficient. */                \
        if (DILITHIUM_COEFF_S_VALID(t, eta)) {                          \
            (t) = DILITHIUM_COEFF_S(t, eta);                            \
            /* Step 8: Store coefficient as next polynomial value.      \
             * Step 9: Increment count of polynomial values set. */     \
            s[j++] = (sword32)(t);                                      \
            if (j == DILITHIUM_N) {                                     \
                break;                                                  \
            }                                                           \
        }

/* Extract a coefficient from a nibble of z.
 *
 * @param [in] z    A random value.
 * @param [in] rs   Amount to shift right.
 * @param [in] t    Temporary result.
 * @param [in] eta  ETA value from parameters.
 * @return  Value in range -eta..eta on success.
 * @return  Falsam (0x10) when random value out of range.
 */
#define EXTRACT_COEFF_NIBBLE(z, rs, t, eta)                             \
        (t) = (sword8)(((z) >> (rs)) & 0xf);                            \
        /* Step 7: Check we have a valid coefficient. */                \
        if (DILITHIUM_COEFF_S_VALID(t, eta)) {                          \
            (t) = DILITHIUM_COEFF_S(t, eta);                            \
            /* Step 8: Store coefficient as next polynomial value.      \
             * Step 9: Increment count of polynomial values set. */     \
            s[j++] = (sword32)(t);                                      \
        }


/* Extract coefficients from hash - z.
 *
 * FIPS 204. 8.3: Algorithm 25 RejBoundedPoly(rho)
 *   2: c <- 0
 *   5:    z0 <- CoeffFromHalfByte(z mod 16, eta)
 *   6:    z1 <- CoeffFromHalfByte(lower(z / 16), eta)
 *   7:    if z0 != falsam then
 *   8:         aj <- z0
 *   9:         j <- j + 1
 *  10:    end if
 *  11:    if z1 != falsam then
 *  12:         aj <- z1
 *  13:         j <- j + 1
 *  14:    end if
 *  15:    c <- c + 1
 *
 * @param [in]      z     Hash data to extract coefficients from.
 * @param [in]      zLen  Length of z in bytes.
 * @param [in]      eta   Range specifier of each value.
 * @param [out]     s     Polynomial to fill with coefficients.
 * @param [in, out] cnt   Current count of coefficients in polynomial.
 */
static void dilithium_extract_coeffs(byte* z, unsigned int zLen, byte eta,
    sword32* s, unsigned int* cnt)
{
#ifdef WOLFSSL_DILITHIUM_NO_LARGE_CODE
    unsigned int j = *cnt;
    unsigned int c;

    (void)eta;

    /* Extract values from the squeezed data. */
    for (c = 0; c < zLen; c++) {
        sword8 t;

        /* Step 5: Get coefficient from bottom nibble. */
        EXTRACT_COEFF_NIBBLE_CHECK_J(z[c], 0, t, eta);
        /* Step 6: Get coefficient from top nibble. */
        EXTRACT_COEFF_NIBBLE_CHECK_J(z[c], 4, t, eta);
    }

    *cnt = j;
#else
    unsigned int j = *cnt;
    unsigned int c;
    unsigned int min = (DILITHIUM_N - j) / 2;

    (void)eta;

#if defined(LITTLE_ENDIAN_ORDER)
#ifdef WC_64BIT_CPU
    min &= ~(unsigned int)7;
    /* Extract values from the squeezed data. */
    for (c = 0; c < min; c += 8) {
        word64 z64 = *(word64*)(z + c);
        sword8 t;

        /* Do each nibble from lowest to highest 16 at a time. */
        EXTRACT_COEFF_NIBBLE(z64,  0, t, eta);
        EXTRACT_COEFF_NIBBLE(z64,  4, t, eta);
        EXTRACT_COEFF_NIBBLE(z64,  8, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 12, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 16, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 20, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 24, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 28, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 32, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 36, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 40, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 44, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 48, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 52, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 56, t, eta);
        EXTRACT_COEFF_NIBBLE(z64, 60, t, eta);
    }
#else
    min &= ~(unsigned int)3;
    /* Extract values from the squeezed data. */
    for (c = 0; c < min; c += 4) {
        word32 z32 = *(word32*)(z + c);
        sword8 t;

        /* Do each nibble from lowest to highest 8 at a time. */
        EXTRACT_COEFF_NIBBLE(z32,  0, t, eta);
        EXTRACT_COEFF_NIBBLE(z32,  4, t, eta);
        EXTRACT_COEFF_NIBBLE(z32,  8, t, eta);
        EXTRACT_COEFF_NIBBLE(z32, 12, t, eta);
        EXTRACT_COEFF_NIBBLE(z32, 16, t, eta);
        EXTRACT_COEFF_NIBBLE(z32, 20, t, eta);
        EXTRACT_COEFF_NIBBLE(z32, 24, t, eta);
        EXTRACT_COEFF_NIBBLE(z32, 28, t, eta);
    }
#endif
#else
    /* Extract values from the squeezed data. */
    for (c = 0; c < min; c++) {
        sword8 t;

        /* Step 5: Get coefficient from bottom nibble. */
        EXTRACT_COEFF_NIBBLE(z[c], 0, t, eta);
        EXTRACT_COEFF_NIBBLE(z[c], 4, t, eta);
    }
#endif
    if (j != DILITHIUM_N) {
        /* Extract values from the squeezed data. */
        for (; c < zLen; c++) {
            sword8 t;

            EXTRACT_COEFF_NIBBLE_CHECK_J(z[c], 0, t, eta);
            EXTRACT_COEFF_NIBBLE_CHECK_J(z[c], 4, t, eta);
        }
    }

    *cnt = j;
#endif
}

/* Create polynomial from hashing the seed with bounded values.
 *
 * FIPS 204. 8.3: Algorithm 25 RejBoundedPoly(rho)
 *   1: j <- 0
 *      ...
 *   3: while j < 256 do
 *   4:    z <- H(rho)[[c]]
 *         ... [Extract coefficients into polynomial from z]
 *  16: end while
 *  17: return a
 *
 * @param [in, out] shake256  SHAKE-256 object.
 * @param [in]      seed      Seed, rho, to hash to generate values.
 * @param [in]      eta       Range specifier of each value.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_rej_bound_poly(wc_Shake* shake256, byte* seed, sword32* s,
    byte eta)
{
#ifdef WOLFSSL_DILITHIUM_SMALL
    int ret;
    unsigned int j = 0;
    byte z[DILITHIUM_GEN_S_BLOCK_BYTES];

    /* Initialize SHAKE-256 object for new hash. */
    ret = wc_InitShake256(shake256, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* Absorb the seed. */
        ret = wc_Shake256_Absorb(shake256, seed, DILITHIUM_GEN_S_SEED_SZ);
    }
    if (ret == 0) {
        do {
            /* Squeeze out another block. */
            ret = wc_Shake256_SqueezeBlocks(shake256, z, 1);
            if (ret != 0) {
                break;
            }
            /* Extract up to the 256 valid coefficients for polynomial. */
            dilithium_extract_coeffs(z, DILITHIUM_GEN_S_BLOCK_BYTES, eta, s,
                &j);
        }
        /* Check we got enough values to fill polynomial. */
        while (j < DILITHIUM_N);
    }

    return ret;
#else
    int ret;
    unsigned int j = 0;
    byte z[DILITHIUM_GEN_S_BYTES];

    /* Absorb seed and squeeze out some blocks. */
    ret = dilithium_squeeze256(shake256, seed, DILITHIUM_GEN_S_SEED_SZ, z,
        DILITHIUM_GEN_S_NBLOCKS);
    if (ret == 0) {
        /* Extract up to 256 valid coefficients for polynomial. */
        dilithium_extract_coeffs(z, DILITHIUM_GEN_S_BYTES, eta, s, &j);
        /* Check we got enough values to fill polynomial. */
        while (j < DILITHIUM_N) {
            /* Squeeze out another block. */
            ret = wc_Shake256_SqueezeBlocks(shake256, z, 1);
            if (ret != 0) {
                break;
            }
            /* Extract up to the 256 valid coefficients for polynomial. */
            dilithium_extract_coeffs(z, DILITHIUM_GEN_S_BLOCK_BYTES, eta, s,
                &j);
        }
    }

    return ret;
#endif
}

/* Expand private seed into vectors s1 and s2.
 *
 * FIPS 204. 8.3: Algorithm 27 ExpandS(rho)
 *   1: for r from 0 to l - 1 do
 *   2:     s1[r] <- RejBoundedPoly(rho||IntegerToBits(r,16))
 *   3: end for
 *   4: for r from 0 to k - 1 do
 *   5:     s2[r] <- RejBoundedPoly(rho||IntegerToBits(r + l,16))
 *   6: end for
 *   7: return (s1,s2)
 *
 * @param [in, out] shake256   SHAKE-256 object.
 * @param [in]      priv_seed  Private seed, rho, to expand.
 * @param [in]      eta        Range specifier of each value.
 * @param [out]     s1         First vector of polynomials.
 * @param [in]      s1Len      Dimension of first vector.
 * @param [out]     s2         Second vector of polynomials.
 * @param [in]      s2Len      Dimension of second vector.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_expand_s(wc_Shake* shake256, byte* priv_seed, byte eta,
    sword32* s1, byte s1Len, sword32* s2, byte s2Len)
{
    int ret = 0;
    byte r;
    byte seed[DILITHIUM_GEN_S_SEED_SZ];

    /* Copy the seed into a buffer that has space for r. */
    XMEMCPY(seed, priv_seed, DILITHIUM_PRIV_SEED_SZ);
    /* Set top 8-bits of r in buffer to 0. */
    seed[DILITHIUM_PRIV_SEED_SZ + 1] = 0;
    /* Step 1: Each polynomial in s1. */
    for (r = 0; (ret == 0) && (r < s1Len); r++) {
        /* Set bottom 8-bits of r into buffer - little endian. */
        seed[DILITHIUM_PRIV_SEED_SZ] = r;

        /* Step 2: Generate polynomial for s1. */
        ret = dilithium_rej_bound_poly(shake256, seed, s1, eta);
        /* Next polynomial in s1. */
        s1 += DILITHIUM_N;
    }
    /* Step 4: Each polynomial in s2. */
    for (r = 0; (ret == 0) && (r < s2Len); r++) {
        /* Set bottom 8-bits of r + l into buffer - little endian. */
        seed[DILITHIUM_PRIV_SEED_SZ] = r + s1Len;
        /* Step 5: Generate polynomial for s1. */
        ret = dilithium_rej_bound_poly(shake256, seed, s2, eta);
        /* Next polynomial in s2. */
        s2 += DILITHIUM_N;
    }

    return ret;
}

#endif /* !WOLFSSL_DILITHIUM_NO_MAKE_KEY */

#ifndef WOLFSSL_DILITHIUM_NO_SIGN
/* Expand the private random seed into vector y.
 *
 * FIPS 204. 8.3: Algorithm 28 ExpandMask(rho, mu)
 *   1: c <- 1 + bitlen(GAMMA1 - 1)
 *   2: for r from 0 to l - 1 do
 *   3:     n <- IntegerToBits(mu + r, 16)
 *   4:     v <- (H(rho||n)[[32rc]], H(rho||n)[[32rc + 1]], ...,
 *                H(rho||n)[[32rc + 32c - 1]])
 *   5:     s[r] <- BitUnpack(v, GAMMA-1, GAMMA1)
 *   6: end for
 *   7: return s
 *
 * @param [in, out] shake256     SHAKE-256 object.
 * @param [in, out] seed         Buffer containing seed to expand.
 *                               Has space for two bytes to be appended.
 * @param [in]      kappa        Base value to append to seed.
 * @param [in]      gamma1_bits  Number of bits per value.
 * @param [out]     y            Vector of polynomials.
 * @param [in]      l            Dimension of vector.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_vec_expand_mask(wc_Shake* shake256, byte* seed,
    word16 kappa, byte gamma1_bits, sword32* y, byte l)
{
    int ret = 0;
    byte r;
    byte v[DILITHIUM_MAX_V];

    /* Step 2: For each polynomial of vector. */
    for (r = 0; (ret == 0) && (r < l); r++) {
        /* Step 3: Calculate value to append to seed. */
        word16 n = kappa + r;

        /* Step 4: Append to seed and squeeze out data. */
        seed[DILITHIUM_PRIV_RAND_SEED_SZ + 0] = (byte)n;
        seed[DILITHIUM_PRIV_RAND_SEED_SZ + 1] = (byte)(n >> 8);
        ret = dilithium_squeeze256(shake256, seed, DILITHIUM_Y_SEED_SZ, v,
            DILITHIUM_MAX_V_BLOCKS);
        if (ret == 0) {
            /* Decode v into polynomial. */
            dilithium_decode_gamma1(v, gamma1_bits, y);
            /* Next polynomial. */
            y += DILITHIUM_N;
        }
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)

/* Expand commit to a polynomial.
 *
 * FIPS 204. 8.3: Algorithm 23 SampleInBall(rho)
 *   1: c <- 0
 *   2: k <- 8
 *   3: for i from 256 - TAU to 255 do
 *   4:     while H(rho)[[k]] > i do
 *   5:        k <- k + 1
 *   6:     end while
 *   7:     j <- H(rho)[[k]]
 *   8:     c[i] <- c[j]
 *   9:     c[j] <- (-1)^H(rho)[i+TAU-256]
 *  10:     k <- k + 1
 *  11: end for
 *  12: return c
 *
 * @param [in]  shake256  SHAKE-256 object.
 * @param [in]  seed      Buffer containing seed to expand.
 * @param [in]  seedLen   Length of seed in bytes.
 * @param [in]  tau       Number of +/- 1s in polynomial.
 * @param [out] c         Commit polynomial.
 * @param [in]  block     Memory to use for block from key.
 * @return  0 on success.
 * @return  Negative on hash error.
 */
static int dilithium_sample_in_ball_ex(int level, wc_Shake* shake256,
   const byte* seed, word32 seedLen, byte tau, sword32* c, byte* block)
{
    int ret = 0;
    unsigned int k;
    unsigned int i;
    unsigned int s;
    byte signs[DILITHIUM_SIGN_BYTES];

    if (ret == 0) {
        /* Set polynomial to all zeros. */
        XMEMSET(c, 0, DILITHIUM_POLY_SIZE);

        /* Generate a block of data from seed. */
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        if (level >= WC_ML_DSA_DRAFT) {
            ret = dilithium_shake256(shake256, seed, DILITHIUM_SEED_SZ, block,
                DILITHIUM_GEN_C_BLOCK_BYTES);
        }
        else
#endif
        {
            (void)level;
            ret = dilithium_shake256(shake256, seed, seedLen, block,
                DILITHIUM_GEN_C_BLOCK_BYTES);
        }
    }
    if (ret == 0) {
        /* Copy first 8 bytes of first hash block as random sign bits. */
        XMEMCPY(signs, block, DILITHIUM_SIGN_BYTES);
        /* Step 1: Initialize sign bit index. */
        s = 0;
        /* Step 2: First 8 bytes are used for sign. */
        k = DILITHIUM_SIGN_BYTES;
    }

    /* Step 3: Put in TAU +/- 1s. */
    for (i = DILITHIUM_N - tau; (ret == 0) && (i < DILITHIUM_N); i++) {
        unsigned int j;
        do {
            /* Check whether block is exhausted. */
            if (k == DILITHIUM_GEN_C_BLOCK_BYTES) {
                /* Generate a new block. */
                ret = wc_Shake256_SqueezeBlocks(shake256, block, 1);
                /* Restart hash block index. */
                k = 0;
            }
            /* Step 7: Get random byte from block as index.
             * Step 5 and 10: Increment hash block index.
             */
            j = block[k++];
        }
        /* Step 4: Get another random if random index is a future swap index. */
        while ((ret == 0) && (j > i));

        /* Step 8: Move value from random index to current index. */
        c[i] = c[j];
        /* Step 9: Set value at random index to +/- 1. */
        c[j] = 1 - ((((signs[s >> 3]) >> (s & 0x7)) & 0x1) << 1);
        /* Next sign bit index. */
        s++;
    }

    return ret;
}

#if (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))
/* Expand commit to a polynomial.
 *
 * @param [in]  shake256  SHAKE-256 object.
 * @param [in]  seed      Buffer containing seed to expand.
 * @param [in]  seedLen   Length of seed in bytes.
 * @param [in]  tau       Number of +/- 1s in polynomial.
 * @param [out] c         Commit polynomial.
 * @param [in]  heap      Dynamic memory hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Negative on hash error.
 */
static int dilithium_sample_in_ball(int level, wc_Shake* shake256,
   const byte* seed, word32 seedLen, byte tau, sword32* c, void* heap)
{
    int ret = 0;
#if defined(WOLFSSL_SMALL_STACK)
    byte* block = NULL;
#else
    byte block[DILITHIUM_GEN_C_BLOCK_BYTES];
#endif

    (void)heap;

#if defined(WOLFSSL_SMALL_STACK)
    block = (byte*)XMALLOC(DILITHIUM_GEN_C_BLOCK_BYTES, heap,
        DYNAMIC_TYPE_DILITHIUM);
    if (block == NULL) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0) {
        ret = dilithium_sample_in_ball_ex(level, shake256, seed, seedLen, tau,
            c, block);
    }

#if defined(WOLFSSL_SMALL_STACK)
    XFREE(block, heap, DYNAMIC_TYPE_DILITHIUM);
#endif
    return ret;
}
#endif

#endif

/******************************************************************************
 * Decompose operations
 ******************************************************************************/

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
#ifndef WOLFSSL_NO_ML_DSA_44
/* Decompose value into high and low based on GAMMA2 being ((q-1) / 88).
 *
 * FIPS 204. 8.4: Algorithm 30 Decompose(r)
 *   1: r+ <- r mod q
 *   2: r0 <- r+ mod+/- (2 * GAMMA2)
 *   3: if r+ - r0 = q - 1 then
 *   4:     r1 <- 0
 *   5:     r0 <- r0 - 1
 *   6: else r1 <- (r+ - r0) / (2 * GAMMA2)
 *   7: end if
 *   8: return (r1, r0)
 *
 * DILITHIUM_Q_LOW_88_2 = 0x2e800 = 0b101110100000000000
 * t1 * DILITHIUM_Q_LOW_88_2 = (t1 << 18) - (t1 << 16) - (t1 << 12) - (t1 << 11)
 *                           = ((93 * t1) << 11)
 * Nothing faster than straight multiply.
 *
 * Implementation using Barrett Reduction.
 *
 * @param [in]  r   Value to decompose.
 * @param [out] r0  Low bits.
 * @param [out] r1  High bits.
 */
static void dilithium_decompose_q88(sword32 r, sword32* r0, sword32* r1)
{
    sword32 t0;
    sword32 t1;
#ifdef DILITHIUM_MUL_SLOW
    sword32 t2;
#endif

    /* Roundup r and calculate approx high value. */
#if !defined(DILITHIUM_MUL_44_SLOW)
    t1 = ((r * 44) + ((DILITHIUM_Q_LOW_88 - 1) * 44)) >> 23;
#elif !defined(DILITHIUM_MUL_11_SLOW)
    t1 = ((r * 11) + ((DILITHIUM_Q_LOW_88 - 1) * 11)) >> 21;
#else
    t0 = r + DILITHIUM_Q_LOW_88 - 1;
    t1 = ((t0 << 3) + (t0 << 1) + t0) >> 21;
#endif
    /* Calculate approx low value. */
    t0 = r - (t1 * DILITHIUM_Q_LOW_88_2);
#ifndef DILITHIUM_MUL_SLOW
    /* Calculate real high value, When t0 > modulus, +1 to approx high value. */
    t1 += ((word32)(DILITHIUM_Q_LOW_88 - t0)) >> 31;
    /* Calculate real low value. */
    t0 = r - (t1 * DILITHIUM_Q_LOW_88_2);
#else
    /* Calculate real high value, When t0 > modulus, +1 to approx high value. */
    t2 = ((word32)(DILITHIUM_Q_LOW_88 - t0)) >> 31;
    t1 += t2;
    /* Calculate real low value. */
    t0 -= (0 - t2) & DILITHIUM_Q_LOW_88_2;
#endif
    /* -1 from low value if high value is 44. Was 43 but low is negative. */
    t0 -= ((word32)(43 - t1)) >> 31;
    /* When high value is 44, too large, set to 0. */
    t1 &= 0 - (((word32)(t1 - 44)) >> 31);

    *r0 = t0;
    *r1 = t1;
}
#endif

#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Decompose value into high and low based on GAMMA2 being ((q-1) / 32).
 *
 * FIPS 204. 8.4: Algorithm 30 Decompose(r)
 *   1: r+ <- r mod q
 *   2: r0 <- r+ mod+/- (2 * GAMMA2)
 *   3: if r+ - r0 = q - 1 then
 *   4:     r1 <- 0
 *   5:     r0 <- r0 - 1
 *   6: else r1 <- (r+ - r0) / (2 * GAMMA2)
 *   7: end if
 *   8: return (r1, r0)
 *
 * DILITHIUM_Q_LOW_32_2 = 0x7fe00 = 0b1111111111000000000
 * t1 * DILITHIUM_Q_LOW_32_2 = (t1 << 19) - (t1 << 9)
 *
 * Implementation using Barrett Reduction.
 *
 * @param [in]  r   Value to decompose.
 * @param [out] r0  Low bits.
 * @param [out] r1  High bits.
 */
static void dilithium_decompose_q32(sword32 r, sword32* r0, sword32* r1)
{
    sword32 t0;
    sword32 t1;

    /* Roundup r and calculate approx high value. */
    t1 = (r + DILITHIUM_Q_LOW_32 - 1) >> 19;
    /* Calculate approx low value. */
    t0 = r - (t1 << 19) + (t1 << 9);
    /* Calculate real high value, When t0 > modulus, +1 to approx high value. */
    t1 += ((word32)(DILITHIUM_Q_LOW_32 - t0)) >> 31;
    /* Calculate real low value. */
    t0 = r - (t1 << 19) + (t1 << 9);
    /* -1 from low value if high value is 16. Was 15 but low is negative. */
    t0 -= t1 >> 4;
    /* When high value is 16, too large, set to 0. */
    t1 &= 0xf;

    *r0 = t0;
    *r1 = t1;
}
#endif
#endif

#ifndef WOLFSSL_DILITHIUM_NO_SIGN

#if !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM) || \
    defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
/* Decompose vector of polynomials into high and low based on GAMMA2.
 *
 * @param [in]  r       Vector of polynomials to decompose.
 * @param [in]  k       Dimension of vector.
 * @param [in]  gamma2  Low-order rounding range, GAMMA2.
 * @param [out] r0      Low parts in vector of polynomials.
 * @param [out] r1      High parts in vector of polynomials.
 */
static void dilithium_vec_decompose(const sword32* r, byte k, sword32 gamma2,
    sword32* r0, sword32* r1)
{
    unsigned int i;
    unsigned int j;

    (void)k;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (gamma2 == DILITHIUM_Q_LOW_88) {
        /* For each polynomial of vector. */
        for (i = 0; i < PARAMS_ML_DSA_44_K; i++) {
            /* For each value of polynomial. */
            for (j = 0; j < DILITHIUM_N; j++) {
                /* Decompose value into two vectors. */
                dilithium_decompose_q88(r[j], &r0[j], &r1[j]);
            }
            /* Next polynomial of vectors. */
            r += DILITHIUM_N;
            r0 += DILITHIUM_N;
            r1 += DILITHIUM_N;
        }
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (gamma2 == DILITHIUM_Q_LOW_32) {
        /* For each polynomial of vector. */
        for (i = 0; i < k; i++) {
            /* For each value of polynomial. */
            for (j = 0; j < DILITHIUM_N; j++) {
                /* Decompose value into two vectors. */
                dilithium_decompose_q32(r[j], &r0[j], &r1[j]);
            }
            /* Next polynomial of vectors. */
            r += DILITHIUM_N;
            r0 += DILITHIUM_N;
            r1 += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }
}
#endif

#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

/******************************************************************************
 * Range check operation
 ******************************************************************************/

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
/* Check that the values of the polynomial are in range.
 *
 * Many places in FIPS 204. One example from Algorithm 2:
 *   23:    if ||z||inf >= GAMMA1 - BETA or ..., then (z, h) = falsam
 *
 * @param [in] a   Polynomial.
 * @param [in] hi  Largest value in range.
 */
static int dilithium_check_low(const sword32* a, sword32 hi)
{
    int ret = 1;
    unsigned int j;
    /* Calculate lowest range value. */
    sword32 nhi = -hi;

    /* For each value of polynomial. */
    for (j = 0; j < DILITHIUM_N; j++) {
        /* Check range is -(hi-1)..(hi-1). */
        if ((a[j] <= nhi) || (a[j] >= hi)) {
            /* Check failed. */
            ret = 0;
            break;
        }
    }

    return ret;
}

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Check that the values of the vector are in range.
 *
 * Many places in FIPS 204. One example from Algorithm 2:
 *   23:    if ||z||inf >= GAMMA1 - BETA or ..., then (z, h) = falsam
 *
 * @param [in] a   Vector of polynomials.
 * @param [in] l   Dimension of vector.
 * @param [in] hi  Largest value in range.
 */
static int dilithium_vec_check_low(const sword32* a, byte l, sword32 hi)
{
    int ret = 1;
    unsigned int i;

    /* For each polynomial of vector. */
    for (i = 0; (ret == 1) && (i < l); i++) {
        ret = dilithium_check_low(a, hi);
        if (ret == 0) {
            break;
        }
        /* Next polynomial. */
        a += DILITHIUM_N;
    }

    return ret;
}
#endif
#endif

/******************************************************************************
 * Hint operations
 ******************************************************************************/

#ifndef WOLFSSL_DILITHIUM_NO_SIGN

#ifndef WOLFSSL_NO_ML_DSA_44
/* Compute hints indicating whether adding ct0 to w alters high bits of w.
 *
 * FIPS 204. 6: Algorithm 2 ML-DSA.Sign(sk, M)
 *   ...
 *  26: h <- MakeHint(-<<ct0>>, w - <<sc2>> + <<ct0>>)
 *  27: if ... or the number of 1's in h is greater than OMEGA, then
 *      (z, h) <- falsam
 *   ...
 *  32: sigma <- sigEncode(c_tilda, z mod+/- q, h)
 *   ...
 *
 * FIPS 204. 8.4: Algorithm 33 MakeHint(z, r)
 *   1: r1 <- HighBits(r)
 *   2: v1 <- HightBits(r+z)
 *   3: return [[r1 != v1]]
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   5: sigma <- sigma || HintBitPack(h)
 *   ...
 *
 * FIPS 204. 8.1: Algorithm 14 HintBitPack(h)
 *   ...
 *   4:     for j from 0 to 255 do
 *   5:         if h[i]j != 0 then
 *   6:             y[Index] <- j
 *   7:             Index <- Index + 1
 *   8:         end if
 *   9:     end for
 *   ...
 *
 * @param [in]      s       Vector of polynomials that is sum of ct0 and w0.
 * @param [in]      w1      Vector of polynomials that is high part of w.
 * @param [out]     h       Encoded hints.
 * @param [in, out] idxp    Index to write next hint into.
 * return  Number of hints on success.
 * return  Falsam of -1 when too many hints.
 */
static int dilithium_make_hint_88(const sword32* s, const sword32* w1, byte* h,
    byte *idxp)
{
    unsigned int j;
    byte idx = *idxp;

    /* Alg 14, Step 3: For each value of polynomial. */
    for (j = 0; j < DILITHIUM_N; j++) {
        /* Alg 14, Step 4: Check whether hint is required.
         * Did sum end up greater than low modulus or
         * sum end up less than the negative of low modulus or
         * sum is the negative of the low modulus and w1 is not zero,
         * then w1 will be modified.
         */
        if ((s[j] > (sword32)DILITHIUM_Q_LOW_88) ||
                (s[j] < -(sword32)DILITHIUM_Q_LOW_88) ||
                ((s[j] == -(sword32)DILITHIUM_Q_LOW_88) &&
                 (w1[j] != 0))) {
            /* Alg 14, Step 6, 7: Put index as hint modifier. */
            h[idx++] = (byte)j;
            /* Alg 2, Step 27: If there are too many hints, return
             *                 falsam of -1. */
            if (idx > PARAMS_ML_DSA_44_OMEGA) {
                return -1;
            }
        }
    }

    *idxp = idx;
    return 0;
}
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Compute hints indicating whether adding ct0 to w alters high bits of w.
 *
 * FIPS 204. 6: Algorithm 2 ML-DSA.Sign(sk, M)
 *   ...
 *  26: h <- MakeHint(-<<ct0>>, w - <<sc2>> + <<ct0>>)
 *  27: if ... or the number of 1's in h is greater than OMEGA, then
 *      (z, h) <- falsam
 *   ...
 *  32: sigma <- sigEncode(c_tilda, z mod+/- q, h)
 *   ...
 *
 * FIPS 204. 8.4: Algorithm 33 MakeHint(z, r)
 *   1: r1 <- HighBits(r)
 *   2: v1 <- HightBits(r+z)
 *   3: return [[r1 != v1]]
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   5: sigma <- sigma || HintBitPack(h)
 *   ...
 *
 * FIPS 204. 8.1: Algorithm 14 HintBitPack(h)
 *   ...
 *   4:     for j from 0 to 255 do
 *   5:         if h[i]j != 0 then
 *   6:             y[Index] <- j
 *   7:             Index <- Index + 1
 *   8:         end if
 *   9:     end for
 *   ...
 *
 * @param [in]      s       Vector of polynomials that is sum of ct0 and w0.
 * @param [in]      w1      Vector of polynomials that is high part of w.
 * @param [in]      omega   Maximum number of hints allowed.
 * @param [out]     h       Encoded hints.
 * @param [in, out] idxp    Index to write next hint into.
 * return  Number of hints on success.
 * return  Falsam of -1 when too many hints.
 */
static int dilithium_make_hint_32(const sword32* s, const sword32* w1,
    byte omega, byte* h, byte *idxp)
{
    unsigned int j;
    byte idx = *idxp;

    (void)omega;

    /* Alg 14, Step 3: For each value of polynomial. */
    for (j = 0; j < DILITHIUM_N; j++) {
        /* Alg 14, Step 4: Check whether hint is required.
         * Did sum end up greater than low modulus or
         * sum end up less than the negative of low modulus or
         * sum is the negative of the low modulus and w1 is not zero,
         * then w1 will be modified.
         */
        if ((s[j] > (sword32)DILITHIUM_Q_LOW_32) ||
                (s[j] < -(sword32)DILITHIUM_Q_LOW_32) ||
                ((s[j] == -(sword32)DILITHIUM_Q_LOW_32) &&
                 (w1[j] != 0))) {
            /* Alg 14, Step 6, 7: Put index as hint modifier. */
            h[idx++] = (byte)j;
            /* Alg 2, Step 27: If there are too many hints, return
             *                 falsam of -1. */
            if (idx > omega) {
                return -1;
            }
        }
    }

    *idxp = idx;
    return 0;
}
#endif

#ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
/* Compute hints indicating whether adding ct0 to w alters high bits of w.
 *
 * FIPS 204. 6: Algorithm 2 ML-DSA.Sign(sk, M)
 *   ...
 *  26: h <- MakeHint(-<<ct0>>, w - <<sc2>> + <<ct0>>)
 *  27: if ... or the number of 1's in h is greater than OMEGA, then
 *      (z, h) <- falsam
 *   ...
 *  32: sigma <- sigEncode(c_tilda, z mod+/- q, h)
 *   ...
 *
 * FIPS 204. 8.4: Algorithm 33 MakeHint(z, r)
 *   1: r1 <- HighBits(r)
 *   2: v1 <- HightBits(r+z)
 *   3: return [[r1 != v1]]
 *
 * FIPS 204. 8.2: Algorithm 20 sigEncode(c_tilde, z, h)
 *   ...
 *   5: sigma <- sigma || HintBitPack(h)
 *   ...
 *
 * FIPS 204. 8.1: Algorithm 14 HintBitPack(h)
 *   ...
 *   2: Index <- 0
 *   3. for i from 0 to k - 1 do
 *   4:     for j from 0 to 255 do
 *   5:         if h[i]j != 0 then
 *   6:             y[Index] <- j
 *   7:             Index <- Index + 1
 *   8:         end if
 *   9:     end for
 *  10:     y[OMEGA + i] <- Index
 *  11: end for
 *  12: return y
 *
 * @param [in]  s       Vector of polynomials that is sum of ct0 and w0.
 * @param [in]  w1      Vector of polynomials that is high part of w.
 * @param [in]  k       Dimension of vectors.
 * @param [in]  gamma2  Low-order rounding range, GAMMA2.
 * @param [in]  omega   Maximum number of hints allowed.
 * @param [out] h       Encoded hints.
 * return  Number of hints on success.
 * return  Falsam of -1 when too many hints.
 */
static int dilithium_make_hint(const sword32* s, const sword32* w1, byte k,
    word32 gamma2, byte omega, byte* h)
{
    unsigned int i;
    byte idx = 0;

    (void)k;
    (void)omega;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (gamma2 == DILITHIUM_Q_LOW_88) {
        /* Alg 14, Step 2: For each polynomial of vector. */
        for (i = 0; i < PARAMS_ML_DSA_44_K; i++) {
            if (dilithium_make_hint_88(s, w1, h, &idx) == -1) {
                return -1;
            }
            /* Alg 14, Step 10: Store count of hints for polynomial at end of
             *                  list. */
            h[PARAMS_ML_DSA_44_OMEGA + i] = idx;
            /* Next polynomial. */
            s  += DILITHIUM_N;
            w1 += DILITHIUM_N;
        }
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (gamma2 == DILITHIUM_Q_LOW_32) {
        /* Alg 14, Step 2: For each polynomial of vector. */
        for (i = 0; i < k; i++) {
            if (dilithium_make_hint_32(s, w1, omega, h, &idx) == -1) {
                return -1;
            }
            /* Alg 14, Step 10: Store count of hints for polynomial at end of
             *                  list. */
            h[omega + i] = idx;
            /* Next polynomial. */
            s  += DILITHIUM_N;
            w1 += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }

    /* Set remaining hints to zero. */
    XMEMSET(h + idx, 0, omega - idx);
    return idx;
}
#endif /* !WOLFSSL_DILITHIUM_SIGN_SMALL_MEM */

#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY
/* Check that the hints are valid.
 *
 * @param [in] h      Hints to check
 * @param [in] k      Dimension of vector.
 * @param [in] omega  Maximum number of hints. Hint counts after this index.
 * @return  0 when hints valid.
 * @return  SIG_VERIFY_E when hints invalid.
 */
static int dilithium_check_hint(const byte* h, byte k, byte omega)
{
    int ret = 0;
    unsigned int o = 0;
    unsigned int i;

    /* Skip polynomial index while count is 0. */
    while ((o < k) && (h[omega + o] == 0)) {
        o++;
    }
    /* Check all possible hints. */
    for (i = 1; (o < k) && (i < omega); i++) {
        /* Done with polynomial if index equals count of hints. */
        if (i == h[omega + o]) {
            /* Next polynomial index while count is index. */
            do {
                o++;
            }
            while ((o < k) && (i == h[omega + o]));
            /* Stop if hints for all polynomials checked. */
            if (o == k) {
                break;
            }
        }
        /* Ensure the last hint is less than the current hint. */
        else if (h[i - 1] >= h[i]) {
            ret = SIG_VERIFY_E;
            break;
        }
    }
    if (ret == 0) {
        /* Use up any sizes that are the last element. */
        while ((o < k) && (i == h[omega + o])) {
            o++;
        }
        /* Ensure all sizes were used. */
        if (o != k) {
            ret = SIG_VERIFY_E;
        }
    }
    /* Check remaining hints are 0. */
    for (; (ret == 0) && (i < omega); i++) {
        if (h[i] != 0) {
           ret = SIG_VERIFY_E;
        }
    }

    return ret;
}

#ifndef WOLFSSL_NO_ML_DSA_44
/* Use hints to modify w1.
 *
 * FIPS 204. 8.4: Algorithm 34 UseHint(h, r)
 *   1: m <- (q - 1) / (2 * GAMMA2)
 *   2: (r1, r0) <- Decompose(r)
 *   3: if h == 1 and r0 > 0 return (r1 + 1) mod m
 *   4: if h == 1 and r0 <= 0 return (r1 - 1) mod m
 *   5: return r1
 *
 * @param [in, out] w1  Vector of polynomials needing hints applied to.
 * @param [in]      h   Hints to apply. In signature encoding.
 * @param [in]      i   Dimension index.
 * @param [in, out] op  Pointer to current offset into hints.
 */
static void dilithium_use_hint_88(sword32* w1, const byte* h, unsigned int i,
    byte* op)
{
    byte o = *op;
    unsigned int j;

    /* For each value of polynomial. */
    for (j = 0; j < DILITHIUM_N; j++) {
        sword32 r;
        sword32 r0;
        sword32 r1;
#ifdef DILITHIUM_USE_HINT_CT
        /* Hint is 1 when index is next in hint list. */
        sword32 hint = ((o < h[PARAMS_ML_DSA_44_OMEGA + i]) &
                        (h[o] == (byte)j));

        /* Increment hint offset if this index has hint. */
        o += hint;
        /* Convert value to positive only range. */
        r = w1[j] + ((0 - (((word32)w1[j]) >> 31)) & DILITHIUM_Q);
        /* Decompose value into low and high parts. */
        dilithium_decompose_q88(r, &r0, &r1);
        /* Make hint positive or negative based on sign of r0. */
        hint = (1 - (2 * (((word32)r0) >> 31))) & (0 - hint);
        /* Make w1 only the top part plus the hint. */
        w1[j] = r1 + hint;

        /* Fix up w1 to not be 44 but 0. */
        w1[j] &= 0 - (((word32)(w1[j] - 44)) >> 31);
        /* Hint may have reduced 0 to -1 which is actually 43. */
        w1[j] += (0 - (((word32)w1[j]) >> 31)) & 44;
#else
        /* Convert value to positive only range. */
        r = w1[j] + ((0 - (((word32)w1[j]) >> 31)) & DILITHIUM_Q);
        /* Decompose value into low and high parts. */
        dilithium_decompose_q88(r, &r0, &r1);
        /* Check for hint. */
        if ((o < h[PARAMS_ML_DSA_44_OMEGA + i]) && (h[o] == (byte)j)) {
            /* Add or subtrac hint based on sign of r0. */
            r1 += 1 - (2 * (((word32)r0) >> 31));
            /* Go to next hint offset. */
            o++;
        }
        /* Fix up w1 to not be 44 but 0. */
        r1 &= 0 - (((word32)(r1 - 44)) >> 31);
        /* Hint may have reduced 0 to -1 which is actually 43. */
        r1 += (0 - (((word32)r1) >> 31)) & 44;
        /* Make w1 only the top part plus any hint. */
        w1[j] = r1;
#endif
    }
    *op = o;
}
#endif /* !WOLFSSL_NO_ML_DSA_44 */

#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
/* Use hints to modify w1.
 *
 * FIPS 204. 8.4: Algorithm 34 UseHint(h, r)
 *   1: m <- (q - 1) / (2 * GAMMA2)
 *   2: (r1, r0) <- Decompose(r)
 *   3: if h == 1 and r0 > 0 return (r1 + 1) mod m
 *   4: if h == 1 and r0 <= 0 return (r1 - 1) mod m
 *   5: return r1
 *
 * @param [in, out] w1     Vector of polynomials needing hints applied to.
 * @param [in]      h      Hints to apply. In signature encoding.
 * @param [in]      omega  Max number of hints. Hint counts after this index.
 * @param [in]      i      Dimension index.
 * @param [in, out] op     Pointer to current offset into hints.
 */
static void dilithium_use_hint_32(sword32* w1, const byte* h, byte omega,
    unsigned int i, byte* op)
{
    byte o = *op;
    unsigned int j;

    /* For each value of polynomial. */
    for (j = 0; j < DILITHIUM_N; j++) {
        sword32 r;
        sword32 r0;
        sword32 r1;
#ifdef DILITHIUM_USE_HINT_CT
        /* Hint is 1 when index is next in hint list. */
        sword32 hint = ((o < h[omega + i]) & (h[o] == (byte)j));

        /* Increment hint offset if this index has hint. */
        o += hint;
        /* Convert value to positive only range. */
        r = w1[j] + ((0 - (((word32)w1[j]) >> 31)) & DILITHIUM_Q);
        /* Decompose value into low and high parts. */
        dilithium_decompose_q32(r, &r0, &r1);
        /* Make hint positive or negative based on sign of r0. */
        hint = (1 - (2 * (((word32)r0) >> 31))) & (0 - hint);
        /* Make w1 only the top part plus the hint. */
        w1[j] = r1 + hint;

        /* Fix up w1 not be 16 (-> 0) or -1 (-> 15). */
        w1[j] &= 0xf;
#else
        /* Convert value to positive only range. */
        r = w1[j] + ((0 - (((word32)w1[j]) >> 31)) & DILITHIUM_Q);
        /* Decompose value into low and high parts. */
        dilithium_decompose_q32(r, &r0, &r1);
        /* Check for hint. */
        if ((o < h[omega + i]) && (h[o] == (byte)j)) {
            /* Add or subtract hint based on sign of r0. */
            r1 += 1 - (2 * (((word32)r0) >> 31));
            /* Go to next hint offset. */
            o++;
        }
        /* Fix up w1 not be 16 (-> 0) or -1 (-> 15). */
        w1[j] = r1 & 0xf;
#endif
    }
    *op = o;
}
#endif

#ifndef WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
/* Use hints to modify w1.
 *
 * FIPS 204. 8.4: Algorithm 34 UseHint(h, r)
 *   1: m <- (q - 1) / (2 * GAMMA2)
 *   2: (r1, r0) <- Decompose(r)
 *   3: if h == 1 and r0 > 0 return (r1 + 1) mod m
 *   4: if h == 1 and r0 <= 0 return (r1 - 1) mod m
 *   5: return r1
 *
 * @param [in, out] w1      Vector of polynomials needing hints applied to.
 * @param [in]      k       Dimension of vector.
 * @param [in]      gamma2  Low-order rounding range, GAMMA2.
 * @param [in]      omega   Max number of hints. Hint counts after this index.
 * @param [in]      h       Hints to apply. In signature encoding.
 */
static void dilithium_vec_use_hint(sword32* w1, byte k, word32 gamma2,
    byte omega, const byte* h)
{
    unsigned int i;
    byte o = 0;

    (void)k;
    (void)omega;

#ifndef WOLFSSL_NO_ML_DSA_44
    if (gamma2 == DILITHIUM_Q_LOW_88) {
        /* For each polynomial of vector. */
        for (i = 0; i < PARAMS_ML_DSA_44_K; i++) {
            dilithium_use_hint_88(w1, h, i, &o);
            w1 += DILITHIUM_N;
        }
    }
    else
#endif
#if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
    if (gamma2 == DILITHIUM_Q_LOW_32) {
        /* For each polynomial of vector. */
        for (i = 0; i < k; i++) {
            dilithium_use_hint_32(w1, h, omega, i, &o);
            w1 += DILITHIUM_N;
        }
    }
    else
#endif
    {
    }
}
#endif
#endif /* !WOLFSSL_DILITHIUM_NO_VERIFY */

/******************************************************************************
 * Maths operations
 ******************************************************************************/

/* q^-1 mod 2^32 (inverse of 8380417 mod 2^32 = 58728449 = 0x3802001) */
#define DILITHIUM_QINV          58728449

/* Montgomery reduce a.
 *
 * @param  [in]  a  64-bit value to be reduced.
 * @return  Montgomery reduction result.
 */
static sword32 dilithium_mont_red(sword64 a)
{
#ifndef DILITHIUM_MUL_QINV_SLOW
    sword64 t = (sword32)((sword32)a * (sword32)DILITHIUM_QINV);
#else
    sword64 t = (sword32)((sword32)a + (sword32)((sword32)a << 13) -
        (sword32)((sword32)a << 23) + (sword32)((sword32)a << 26));
#endif
#ifndef DILITHIUM_MUL_Q_SLOW
    return (sword32)((a - ((sword32)t * (sword64)DILITHIUM_Q)) >> 32);
#else
    return (sword32)((a - (t << 23) + (t << 13) - t) >> 32);
#endif
}

#if !defined(WOLFSSL_DILITHIUM_SMALL) || !defined(WOLFSSL_DILITHIUM_NO_SIGN)

/* Reduce 32-bit a modulo q. r = a mod q.
 *
 * @param  [in]  a  32-bit value to be reduced to range of q.
 * @return  Modulo result.
 */
static sword32 dilithium_red(sword32 a)
{
    sword32 t = (sword32)((a + (1 << 22)) >> 23);
#ifndef DILITHIUM_MUL_Q_SLOW
    return (sword32)(a - (t * DILITHIUM_Q));
#else
    return (sword32)(a - (t << 23) + (t << 13) - t);
#endif
}

#endif /* !WOLFSSL_DILITHIUM_SMALL || !WOLFSSL_DILITHIUM_NO_SIGN */

/* Zetas for NTT. */
static const sword32 zetas[DILITHIUM_N] = {
   -41978,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
  1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
  2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
 -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
  2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
 -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
 -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
   811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
 -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
 -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
  3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
  -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
 -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
 -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
   189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
  1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
  2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
   266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
   900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
  -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
   342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
  2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
 -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
 -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
 -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
  -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
 -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
 -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
 -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
  -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
 -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
  -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

#ifndef WOLFSSL_DILITHIUM_SMALL
/* Zetas for inverse NTT. */
static const sword32 zetas_inv[DILITHIUM_N] = {
 -1976782,   846154, -1400424, -3937738,  1362209,    48306, -3919660,   554416,
  3545687, -1612842,   976891,  -183443,  2286327,   420899,  2235985,  2939036,
  3833893,   260646,  1104333,  1667432, -1910376,  1803090, -1723600,   426683,
  -472078, -1717735,   975884, -2213111,  -269760, -3866901, -3523897,  3038916,
  1799107,  3694233, -1652634,  -810149, -3014001, -1616392,  -162844,  3183426,
  1207385,  -185531, -3369112, -1957272,   164721, -2454455, -2432395,  2013608,
  3776993,  -594136,  3724270,  2584293,  1846953,  1671176,  2831860,   542412,
 -3406031, -2235880,  -777191, -1500165,  1374803,  2546312, -1917081,  1279661,
  1962642, -3306115, -1312455,   451100,  1430225,  3318210, -1237275,  1333058,
  1050970, -1903435, -1869119,  2994039,  3548272, -2635921, -1250494,  3767016,
 -1595974, -2486353, -1247620, -4055324, -1265009,  2590150, -2691481, -2842341,
  -203044, -1735879,  3342277, -3437287, -4108315,  2437823,  -286988,  -342297,
  3595838,   768622,   525098,  3556995, -3207046, -2031748,  3122442,   655327,
   522500,    43260,  1613174,  -495491,  -819034,  -909542, -1859098,  -900702,
  3193378,  1197226,  3759364,  3520352, -3513181,  1235728, -2434439,  -266997,
  3562462,  2446433, -2244091,  3342478, -3817976, -2316500, -3407706, -2091667,
 -3839961,  3628969,  3881060,  3019102,  1439742,   812732,  1584928, -1285669,
 -1341330, -1315589,   177440,  2409325,  1851402, -3159746,  3553272,  -189548,
  1316856,  -759969,   210977, -2389356,  3249728, -1653064,     8578,  3724342,
 -3958618,  -904516,  1100098,   -44288, -3097992,  -508951,  -264944,  3343383,
  1430430, -1852771, -1349076,   381987,  1308169,    22981,  1228525,   671102,
  2477047,   411027,  3693493,  2967645, -2715295, -2147896,   983419, -3412210,
  -126922,  3632928,  3157330,  3190144,  1000202,  4083598, -1939314,  1257611,
  1585221, -2176455, -3475950,  1452451,  3041255,  3677745,  1528703,  3930395,
  2797779, -2071892,  2556880, -3900724, -3881043,  -954230,  -531354,  -811944,
 -3699596,  1600420,  2140649, -3507263,  3821735, -3505694,  1643818,  1699267,
   539299, -2348700,   300467, -3539968,  2867647, -3574422,  3043716,  3861115,
 -3915439,  2537516,  3592148,  1661693, -3530437, -3077325,   -95776, -2706023,
  -280005, -4010497,    19422, -1757237,  3277672,  1399561,  3859737,  2118186,
  2108549, -2619752,  1119584,   549488, -3585928,  1079900, -1024112, -2725464,
 -2680103, -3111497,  2884855, -3119733,  2091905,   359251, -2353451, -1826347,
  -466468,   876248,   777960,  -237124,   518909,  2608894,   -25847,    41978
};
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
    !defined(WOLFSSL_DILITHIUM_NO_VERIFY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_MAKE) && defined(WOLFSSL_DILITHIUM_SMALL))

/* One iteration of Number-Theoretic Transform.
 *
 * @param [in] len  Length of sequence.
 */
#define NTT(len)                                                            \
do {                                                                        \
    for (start = 0; start < DILITHIUM_N; start += 2 * (len)) {              \
        zeta = zetas[++k];                                                  \
        for (j = 0; j < (len); ++j) {                                       \
            sword32 t =                                                     \
                dilithium_mont_red((sword64)zeta * r[start + j + (len)]);   \
            sword32 rj = r[start + j];                                      \
            r[start + j + (len)] = rj - t;                                  \
            r[start + j] = rj + t;                                          \
        }                                                                   \
    }                                                                       \
}                                                                           \
while (0)

/* Number-Theoretic Transform.
 *
 * @param [in, out] r  Polynomial to transform.
 */
static void dilithium_ntt(sword32* r)
{
#ifdef WOLFSSL_DILITHIUM_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;

    k = 0;
    for (len = DILITHIUM_N / 2; len >= 1; len >>= 1) {
        unsigned int start;
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            sword32 zeta = zetas[++k];
            for (j = start; j < start + len; ++j) {
                sword32 t = dilithium_mont_red((sword64)zeta * r[j + len]);
                sword32 rj = r[j];
                r[j + len] = rj - t;
                r[j] = rj + t;
            }
        }
    }
#elif defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE)
    unsigned int j;
    unsigned int k;
    unsigned int start;
    sword32 zeta;

    zeta = zetas[1];
    for (j = 0; j < DILITHIUM_N / 2; j++) {
        sword32 t =
            dilithium_mont_red((sword64)zeta * r[j + DILITHIUM_N / 2]);
        sword32 rj = r[j];
        r[j + DILITHIUM_N / 2] = rj - t;
        r[j] = rj + t;
    }

    k = 1;
    NTT(64);
    NTT(32);
    NTT(16);
    NTT(8);
    NTT(4);
    NTT(2);

    for (j = 0; j < DILITHIUM_N; j += 2) {
        sword32 t = dilithium_mont_red((sword64)zetas[++k] * r[j + 1]);
        sword32 rj = r[j];
        r[j + 1] = rj - t;
        r[j] = rj + t;
    }
#elif defined(WC_32BIT_CPU)
    unsigned int j;
    unsigned int k;
    sword32 t0;
    sword32 t2;

    sword32 zeta128 = zetas[1];
    sword32 zeta640 = zetas[2];
    sword32 zeta641 = zetas[3];
    for (j = 0; j < DILITHIUM_N / 4; j++) {
        sword32 r0 = r[j +   0];
        sword32 r2 = r[j +  64];
        sword32 r4 = r[j + 128];
        sword32 r6 = r[j + 192];

        t0 = dilithium_mont_red((sword64)zeta128 * r4);
        t2 = dilithium_mont_red((sword64)zeta128 * r6);
        r4 = r0 - t0;
        r6 = r2 - t2;
        r0 += t0;
        r2 += t2;

        t0 = dilithium_mont_red((sword64)zeta640 * r2);
        t2 = dilithium_mont_red((sword64)zeta641 * r6);
        r2 = r0 - t0;
        r6 = r4 - t2;
        r0 += t0;
        r4 += t2;

        r[j +   0] = r0;
        r[j +  64] = r2;
        r[j + 128] = r4;
        r[j + 192] = r6;
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta32  = zetas[ 4 + j / 64 + 0];
        sword32 zeta160 = zetas[ 8 + j / 32 + 0];
        sword32 zeta161 = zetas[ 8 + j / 32 + 1];
        for (i = 0; i < 16; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i + 16];
            sword32 r4 = r[j + i + 32];
            sword32 r6 = r[j + i + 48];

            t0 = dilithium_mont_red((sword64)zeta32 * r4);
            t2 = dilithium_mont_red((sword64)zeta32 * r6);
            r4 = r0 - t0;
            r6 = r2 - t2;
            r0 += t0;
            r2 += t2;

            t0 = dilithium_mont_red((sword64)zeta160 * r2);
            t2 = dilithium_mont_red((sword64)zeta161 * r6);
            r2 = r0 - t0;
            r6 = r4 - t2;
            r0 += t0;
            r4 += t2;

            r[j + i +  0] = r0;
            r[j + i + 16] = r2;
            r[j + i + 32] = r4;
            r[j + i + 48] = r6;
        }
    }

    for (j = 0; j < DILITHIUM_N; j += 16) {
        int i;
        sword32 zeta8   = zetas[16 + j / 16];
        sword32 zeta40  = zetas[32 + j / 8 + 0];
        sword32 zeta41  = zetas[32 + j / 8 + 1];
        for (i = 0; i < 4; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i +  4];
            sword32 r4 = r[j + i +  8];
            sword32 r6 = r[j + i + 12];

            t0 = dilithium_mont_red((sword64)zeta8 * r4);
            t2 = dilithium_mont_red((sword64)zeta8 * r6);
            r4 = r0 - t0;
            r6 = r2 - t2;
            r0 += t0;
            r2 += t2;

            t0 = dilithium_mont_red((sword64)zeta40 * r2);
            t2 = dilithium_mont_red((sword64)zeta41 * r6);
            r2 = r0 - t0;
            r6 = r4 - t2;
            r0 += t0;
            r4 += t2;

            r[j + i +  0] = r0;
            r[j + i +  4] = r2;
            r[j + i +  8] = r4;
            r[j + i + 12] = r6;
        }
    }

    k = 128;
    for (j = 0; j < DILITHIUM_N; j += 4) {
        sword32 zeta2 = zetas[64 + j / 4];
        sword32 r0 = r[j + 0];
        sword32 r2 = r[j + 1];
        sword32 r4 = r[j + 2];
        sword32 r6 = r[j + 3];

        t0 = dilithium_mont_red((sword64)zeta2 * r4);
        t2 = dilithium_mont_red((sword64)zeta2 * r6);
        r4 = r0 - t0;
        r6 = r2 - t2;
        r0 += t0;
        r2 += t2;

        t0 = dilithium_mont_red((sword64)zetas[k++] * r2);
        t2 = dilithium_mont_red((sword64)zetas[k++] * r6);
        r2 = r0 - t0;
        r6 = r4 - t2;
        r0 += t0;
        r4 += t2;

        r[j + 0] = r0;
        r[j + 1] = r2;
        r[j + 2] = r4;
        r[j + 3] = r6;
    }
#else
    unsigned int j;
    unsigned int k;
    sword32 t0;
    sword32 t1;
    sword32 t2;
    sword32 t3;

    sword32 zeta128 = zetas[1];
    sword32 zeta640 = zetas[2];
    sword32 zeta641 = zetas[3];
    for (j = 0; j < DILITHIUM_N / 8; j++) {
        sword32 r0 = r[j +   0];
        sword32 r1 = r[j +  32];
        sword32 r2 = r[j +  64];
        sword32 r3 = r[j +  96];
        sword32 r4 = r[j + 128];
        sword32 r5 = r[j + 160];
        sword32 r6 = r[j + 192];
        sword32 r7 = r[j + 224];

        t0 = dilithium_mont_red((sword64)zeta128 * r4);
        t1 = dilithium_mont_red((sword64)zeta128 * r5);
        t2 = dilithium_mont_red((sword64)zeta128 * r6);
        t3 = dilithium_mont_red((sword64)zeta128 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = dilithium_mont_red((sword64)zeta640 * r2);
        t1 = dilithium_mont_red((sword64)zeta640 * r3);
        t2 = dilithium_mont_red((sword64)zeta641 * r6);
        t3 = dilithium_mont_red((sword64)zeta641 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r[j +   0] = r0;
        r[j +  32] = r1;
        r[j +  64] = r2;
        r[j +  96] = r3;
        r[j + 128] = r4;
        r[j + 160] = r5;
        r[j + 192] = r6;
        r[j + 224] = r7;
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta32  = zetas[ 4 + j / 64 + 0];
        sword32 zeta160 = zetas[ 8 + j / 32 + 0];
        sword32 zeta161 = zetas[ 8 + j / 32 + 1];
        sword32 zeta80  = zetas[16 + j / 16 + 0];
        sword32 zeta81  = zetas[16 + j / 16 + 1];
        sword32 zeta82  = zetas[16 + j / 16 + 2];
        sword32 zeta83  = zetas[16 + j / 16 + 3];
        for (i = 0; i < 8; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r1 = r[j + i +  8];
            sword32 r2 = r[j + i + 16];
            sword32 r3 = r[j + i + 24];
            sword32 r4 = r[j + i + 32];
            sword32 r5 = r[j + i + 40];
            sword32 r6 = r[j + i + 48];
            sword32 r7 = r[j + i + 56];

            t0 = dilithium_mont_red((sword64)zeta32 * r4);
            t1 = dilithium_mont_red((sword64)zeta32 * r5);
            t2 = dilithium_mont_red((sword64)zeta32 * r6);
            t3 = dilithium_mont_red((sword64)zeta32 * r7);
            r4 = r0 - t0;
            r5 = r1 - t1;
            r6 = r2 - t2;
            r7 = r3 - t3;
            r0 += t0;
            r1 += t1;
            r2 += t2;
            r3 += t3;

            t0 = dilithium_mont_red((sword64)zeta160 * r2);
            t1 = dilithium_mont_red((sword64)zeta160 * r3);
            t2 = dilithium_mont_red((sword64)zeta161 * r6);
            t3 = dilithium_mont_red((sword64)zeta161 * r7);
            r2 = r0 - t0;
            r3 = r1 - t1;
            r6 = r4 - t2;
            r7 = r5 - t3;
            r0 += t0;
            r1 += t1;
            r4 += t2;
            r5 += t3;

            t0 = dilithium_mont_red((sword64)zeta80 * r1);
            t1 = dilithium_mont_red((sword64)zeta81 * r3);
            t2 = dilithium_mont_red((sword64)zeta82 * r5);
            t3 = dilithium_mont_red((sword64)zeta83 * r7);
            r1 = r0 - t0;
            r3 = r2 - t1;
            r5 = r4 - t2;
            r7 = r6 - t3;
            r0 += t0;
            r2 += t1;
            r4 += t2;
            r6 += t3;

            r[j + i +  0] = r0;
            r[j + i +  8] = r1;
            r[j + i + 16] = r2;
            r[j + i + 24] = r3;
            r[j + i + 32] = r4;
            r[j + i + 40] = r5;
            r[j + i + 48] = r6;
            r[j + i + 56] = r7;
        }
    }

    k = 128;
    for (j = 0; j < DILITHIUM_N; j += 8) {
        sword32 zeta4  = zetas[32 + j / 8 + 0];
        sword32 zeta20 = zetas[64 + j / 4 + 0];
        sword32 zeta21 = zetas[64 + j / 4 + 1];
        sword32 r0 = r[j + 0];
        sword32 r1 = r[j + 1];
        sword32 r2 = r[j + 2];
        sword32 r3 = r[j + 3];
        sword32 r4 = r[j + 4];
        sword32 r5 = r[j + 5];
        sword32 r6 = r[j + 6];
        sword32 r7 = r[j + 7];

        t0 = dilithium_mont_red((sword64)zeta4 * r4);
        t1 = dilithium_mont_red((sword64)zeta4 * r5);
        t2 = dilithium_mont_red((sword64)zeta4 * r6);
        t3 = dilithium_mont_red((sword64)zeta4 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = dilithium_mont_red((sword64)zeta20 * r2);
        t1 = dilithium_mont_red((sword64)zeta20 * r3);
        t2 = dilithium_mont_red((sword64)zeta21 * r6);
        t3 = dilithium_mont_red((sword64)zeta21 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        t0 = dilithium_mont_red((sword64)zetas[k++] * r1);
        t1 = dilithium_mont_red((sword64)zetas[k++] * r3);
        t2 = dilithium_mont_red((sword64)zetas[k++] * r5);
        t3 = dilithium_mont_red((sword64)zetas[k++] * r7);
        r1 = r0 - t0;
        r3 = r2 - t1;
        r5 = r4 - t2;
        r7 = r6 - t3;
        r0 += t0;
        r2 += t1;
        r4 += t2;
        r6 += t3;

        r[j + 0] = r0;
        r[j + 1] = r1;
        r[j + 2] = r2;
        r[j + 3] = r3;
        r[j + 4] = r4;
        r[j + 5] = r5;
        r[j + 6] = r6;
        r[j + 7] = r7;
    }
#endif
}

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) || \
     defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     (defined(WC_DILITHIUM_CACHE_PRIV_VECTORS) || \
      !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)))
/* Number-Theoretic Transform.
 *
 * @param [in, out]  r  Vector of polynomials to transform.
 * @param [in]       l  Dimension of polynomial.
 */
static void dilithium_vec_ntt(sword32* r, byte l)
{
    unsigned int i;

    for (i = 0; i < l; i++) {
        dilithium_ntt(r);
        r += DILITHIUM_N;
    }
}
#endif
#endif

#ifndef WOLFSSL_DILITHIUM_SMALL

/* Number-Theoretic Transform with small initial values.
 *
 * @param [in, out] r  Polynomial to transform.
 */
static void dilithium_ntt_small(sword32* r)
{
    unsigned int k;
    unsigned int j;
#ifdef WOLFSSL_DILITHIUM_NO_LARGE_CODE
    unsigned int start;
    sword32 zeta;

    for (j = 0; j < DILITHIUM_N / 2; ++j) {
        sword32 t = dilithium_red((sword32)-3572223 * r[j + DILITHIUM_N / 2]);
        sword32 rj = r[j];
        r[j + DILITHIUM_N / 2] = rj - t;
        r[j] = rj + t;
    }

    k = 1;
    NTT(64);
    NTT(32);
    NTT(16);
    NTT(8);
    NTT(4);
    NTT(2);

    for (j = 0; j < DILITHIUM_N; j += 2) {
        sword32 t = dilithium_mont_red((sword64)zetas[++k] * r[j + 1]);
        sword32 rj = r[j];
        r[j + 1] = rj - t;
        r[j] = rj + t;
    }
#elif defined(WC_32BIT_CPU)
    sword32 t0;
    sword32 t2;

    sword32 zeta640 = zetas[2];
    sword32 zeta641 = zetas[3];
    for (j = 0; j < DILITHIUM_N / 4; j++) {
        sword32 r0 = r[j +   0];
        sword32 r2 = r[j +  64];
        sword32 r4 = r[j + 128];
        sword32 r6 = r[j + 192];

        t0 = dilithium_red((sword32)-3572223 * r4);
        t2 = dilithium_red((sword32)-3572223 * r6);
        r4 = r0 - t0;
        r6 = r2 - t2;
        r0 += t0;
        r2 += t2;

        t0 = dilithium_mont_red((sword64)zeta640 * r2);
        t2 = dilithium_mont_red((sword64)zeta641 * r6);
        r2 = r0 - t0;
        r6 = r4 - t2;
        r0 += t0;
        r4 += t2;

        r[j +   0] = r0;
        r[j +  64] = r2;
        r[j + 128] = r4;
        r[j + 192] = r6;
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta32  = zetas[ 4 + j / 64 + 0];
        sword32 zeta160 = zetas[ 8 + j / 32 + 0];
        sword32 zeta161 = zetas[ 8 + j / 32 + 1];
        for (i = 0; i < 16; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i + 16];
            sword32 r4 = r[j + i + 32];
            sword32 r6 = r[j + i + 48];

            t0 = dilithium_mont_red((sword64)zeta32 * r4);
            t2 = dilithium_mont_red((sword64)zeta32 * r6);
            r4 = r0 - t0;
            r6 = r2 - t2;
            r0 += t0;
            r2 += t2;

            t0 = dilithium_mont_red((sword64)zeta160 * r2);
            t2 = dilithium_mont_red((sword64)zeta161 * r6);
            r2 = r0 - t0;
            r6 = r4 - t2;
            r0 += t0;
            r4 += t2;

            r[j + i +  0] = r0;
            r[j + i + 16] = r2;
            r[j + i + 32] = r4;
            r[j + i + 48] = r6;
        }
    }

    for (j = 0; j < DILITHIUM_N; j += 16) {
        int i;
        sword32 zeta8   = zetas[16 + j / 16];
        sword32 zeta40  = zetas[32 + j / 8 + 0];
        sword32 zeta41  = zetas[32 + j / 8 + 1];
        for (i = 0; i < 4; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i +  4];
            sword32 r4 = r[j + i +  8];
            sword32 r6 = r[j + i + 12];

            t0 = dilithium_mont_red((sword64)zeta8 * r4);
            t2 = dilithium_mont_red((sword64)zeta8 * r6);
            r4 = r0 - t0;
            r6 = r2 - t2;
            r0 += t0;
            r2 += t2;

            t0 = dilithium_mont_red((sword64)zeta40 * r2);
            t2 = dilithium_mont_red((sword64)zeta41 * r6);
            r2 = r0 - t0;
            r6 = r4 - t2;
            r0 += t0;
            r4 += t2;

            r[j + i +  0] = r0;
            r[j + i +  4] = r2;
            r[j + i +  8] = r4;
            r[j + i + 12] = r6;
        }
    }

    k = 128;
    for (j = 0; j < DILITHIUM_N; j += 4) {
        sword32 zeta2 = zetas[64 + j / 4];
        sword32 r0 = r[j + 0];
        sword32 r2 = r[j + 1];
        sword32 r4 = r[j + 2];
        sword32 r6 = r[j + 3];

        t0 = dilithium_mont_red((sword64)zeta2 * r4);
        t2 = dilithium_mont_red((sword64)zeta2 * r6);
        r4 = r0 - t0;
        r6 = r2 - t2;
        r0 += t0;
        r2 += t2;

        t0 = dilithium_mont_red((sword64)zetas[k++] * r2);
        t2 = dilithium_mont_red((sword64)zetas[k++] * r6);
        r2 = r0 - t0;
        r6 = r4 - t2;
        r0 += t0;
        r4 += t2;

        r[j + 0] = r0;
        r[j + 1] = r2;
        r[j + 2] = r4;
        r[j + 3] = r6;
    }
#else
    sword32 t0;
    sword32 t1;
    sword32 t2;
    sword32 t3;
    sword32 zeta640 = zetas[2];
    sword32 zeta641 = zetas[3];
    for (j = 0; j < DILITHIUM_N / 8; j++) {
        sword32 r0 = r[j +   0];
        sword32 r1 = r[j +  32];
        sword32 r2 = r[j +  64];
        sword32 r3 = r[j +  96];
        sword32 r4 = r[j + 128];
        sword32 r5 = r[j + 160];
        sword32 r6 = r[j + 192];
        sword32 r7 = r[j + 224];

        t0 = dilithium_red((sword32)-3572223 * r4);
        t1 = dilithium_red((sword32)-3572223 * r5);
        t2 = dilithium_red((sword32)-3572223 * r6);
        t3 = dilithium_red((sword32)-3572223 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = dilithium_mont_red((sword64)zeta640 * r2);
        t1 = dilithium_mont_red((sword64)zeta640 * r3);
        t2 = dilithium_mont_red((sword64)zeta641 * r6);
        t3 = dilithium_mont_red((sword64)zeta641 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        r[j +   0] = r0;
        r[j +  32] = r1;
        r[j +  64] = r2;
        r[j +  96] = r3;
        r[j + 128] = r4;
        r[j + 160] = r5;
        r[j + 192] = r6;
        r[j + 224] = r7;
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta32  = zetas[ 4 + j / 64 + 0];
        sword32 zeta160 = zetas[ 8 + j / 32 + 0];
        sword32 zeta161 = zetas[ 8 + j / 32 + 1];
        sword32 zeta80  = zetas[16 + j / 16 + 0];
        sword32 zeta81  = zetas[16 + j / 16 + 1];
        sword32 zeta82  = zetas[16 + j / 16 + 2];
        sword32 zeta83  = zetas[16 + j / 16 + 3];
        for (i = 0; i < 8; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r1 = r[j + i +  8];
            sword32 r2 = r[j + i + 16];
            sword32 r3 = r[j + i + 24];
            sword32 r4 = r[j + i + 32];
            sword32 r5 = r[j + i + 40];
            sword32 r6 = r[j + i + 48];
            sword32 r7 = r[j + i + 56];

            t0 = dilithium_mont_red((sword64)zeta32 * r4);
            t1 = dilithium_mont_red((sword64)zeta32 * r5);
            t2 = dilithium_mont_red((sword64)zeta32 * r6);
            t3 = dilithium_mont_red((sword64)zeta32 * r7);
            r4 = r0 - t0;
            r5 = r1 - t1;
            r6 = r2 - t2;
            r7 = r3 - t3;
            r0 += t0;
            r1 += t1;
            r2 += t2;
            r3 += t3;

            t0 = dilithium_mont_red((sword64)zeta160 * r2);
            t1 = dilithium_mont_red((sword64)zeta160 * r3);
            t2 = dilithium_mont_red((sword64)zeta161 * r6);
            t3 = dilithium_mont_red((sword64)zeta161 * r7);
            r2 = r0 - t0;
            r3 = r1 - t1;
            r6 = r4 - t2;
            r7 = r5 - t3;
            r0 += t0;
            r1 += t1;
            r4 += t2;
            r5 += t3;

            t0 = dilithium_mont_red((sword64)zeta80 * r1);
            t1 = dilithium_mont_red((sword64)zeta81 * r3);
            t2 = dilithium_mont_red((sword64)zeta82 * r5);
            t3 = dilithium_mont_red((sword64)zeta83 * r7);
            r1 = r0 - t0;
            r3 = r2 - t1;
            r5 = r4 - t2;
            r7 = r6 - t3;
            r0 += t0;
            r2 += t1;
            r4 += t2;
            r6 += t3;

            r[j + i +  0] = r0;
            r[j + i +  8] = r1;
            r[j + i + 16] = r2;
            r[j + i + 24] = r3;
            r[j + i + 32] = r4;
            r[j + i + 40] = r5;
            r[j + i + 48] = r6;
            r[j + i + 56] = r7;
        }
    }

    k = 128;
    for (j = 0; j < DILITHIUM_N; j += 8) {
        sword32 zeta4  = zetas[32 + j / 8 + 0];
        sword32 zeta20 = zetas[64 + j / 4 + 0];
        sword32 zeta21 = zetas[64 + j / 4 + 1];
        sword32 r0 = r[j + 0];
        sword32 r1 = r[j + 1];
        sword32 r2 = r[j + 2];
        sword32 r3 = r[j + 3];
        sword32 r4 = r[j + 4];
        sword32 r5 = r[j + 5];
        sword32 r6 = r[j + 6];
        sword32 r7 = r[j + 7];

        t0 = dilithium_mont_red((sword64)zeta4 * r4);
        t1 = dilithium_mont_red((sword64)zeta4 * r5);
        t2 = dilithium_mont_red((sword64)zeta4 * r6);
        t3 = dilithium_mont_red((sword64)zeta4 * r7);
        r4 = r0 - t0;
        r5 = r1 - t1;
        r6 = r2 - t2;
        r7 = r3 - t3;
        r0 += t0;
        r1 += t1;
        r2 += t2;
        r3 += t3;

        t0 = dilithium_mont_red((sword64)zeta20 * r2);
        t1 = dilithium_mont_red((sword64)zeta20 * r3);
        t2 = dilithium_mont_red((sword64)zeta21 * r6);
        t3 = dilithium_mont_red((sword64)zeta21 * r7);
        r2 = r0 - t0;
        r3 = r1 - t1;
        r6 = r4 - t2;
        r7 = r5 - t3;
        r0 += t0;
        r1 += t1;
        r4 += t2;
        r5 += t3;

        t0 = dilithium_mont_red((sword64)zetas[k++] * r1);
        t1 = dilithium_mont_red((sword64)zetas[k++] * r3);
        t2 = dilithium_mont_red((sword64)zetas[k++] * r5);
        t3 = dilithium_mont_red((sword64)zetas[k++] * r7);
        r1 = r0 - t0;
        r3 = r2 - t1;
        r5 = r4 - t2;
        r7 = r6 - t3;
        r0 += t0;
        r2 += t1;
        r4 += t2;
        r6 += t3;

        r[j + 0] = r0;
        r[j + 1] = r1;
        r[j + 2] = r2;
        r[j + 3] = r3;
        r[j + 4] = r4;
        r[j + 5] = r5;
        r[j + 6] = r6;
        r[j + 7] = r7;
    }
#endif
}

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
     defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     (defined(WC_DILITHIUM_CACHE_PRIV_VECTORS) || \
      !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)))
/* Number-Theoretic Transform with small initial values.
 *
 * @param [in, out]  r  Vector of polynomials to transform.
 * @param [in]       l  Dimension of polynomial.
 */
static void dilithium_vec_ntt_small(sword32* r, byte l)
{
    unsigned int i;

    for (i = 0; i < l; i++) {
        dilithium_ntt_small(r);
        r += DILITHIUM_N;
    }
}
#endif /* !WOLFSSL_DILITHIUM_VERIFY_ONLY */

#else

/* Number-Theoretic Transform with small initial values.
 *
 * @param [in, out] r  Polynomial to transform.
 */
#define dilithium_ntt_small          dilithium_ntt
/* Number-Theoretic Transform with small initial values.
 *
 * @param [in, out]  r  Vector of polynomials to transform.
 * @param [in]       l  Dimension of polynomial.
 */
#define dilithium_vec_ntt_small      dilithium_vec_ntt

#endif /* WOLFSSL_DILITHIUM_SMALL */


/* One iteration of Inverse Number-Theoretic Transform.
 *
 * @param [in] len  Length of sequence.
 */
#define INVNTT(len)                                                         \
do {                                                                        \
    for (start = 0; start < DILITHIUM_N; start += 2 * (len)) {              \
        zeta = zetas_inv[k++];                                              \
        for (j = 0; j < (len); ++j) {                                       \
            sword32 rj = r[start + j];                                      \
            sword32 rjl = r[start + j + (len)];                             \
            sword32 t = rj + rjl;                                           \
            r[start + j] = t;                                               \
            rjl = rj - rjl;                                                 \
            r[start + j + (len)] = dilithium_mont_red((sword64)zeta * rjl); \
        }                                                                   \
    }                                                                       \
}                                                                           \
while (0)

/* Inverse Number-Theoretic Transform.
 *
 * @param [in, out] r  Polynomial to transform.
 */
static void dilithium_invntt(sword32* r)
{
#ifdef WOLFSSL_DILITHIUM_SMALL
    unsigned int len;
    unsigned int k;
    unsigned int j;
    sword32 zeta;

    k = 256;
    for (len = 1; len <= DILITHIUM_N / 2; len <<= 1) {
        unsigned int start;
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; ++j) {
                sword32 rj = r[j];
                sword32 rjl = r[j + len];
                sword32 t = rj + rjl;
                r[j] = t;
                rjl = rj - rjl;
                r[j + len] = dilithium_mont_red((sword64)zeta * rjl);
            }
        }
    }

    zeta = -zetas[0];
    for (j = 0; j < DILITHIUM_N; ++j) {
        r[j] = dilithium_mont_red((sword64)zeta * r[j]);
    }
#elif defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE)
    unsigned int j;
    unsigned int k = 0;
    unsigned int start;
    sword32 zeta;

    for (j = 0; j < DILITHIUM_N; j += 2) {
        sword32 rj = r[j];
        sword32 rjl = r[j + 1];
        sword32 t = rj + rjl;
        r[j] = t;
        rjl = rj - rjl;
        r[j + 1] = dilithium_mont_red((sword64)zetas_inv[k++] * rjl);
    }

    INVNTT(2);
    INVNTT(4);
    INVNTT(8);
    INVNTT(16);
    INVNTT(32);
    INVNTT(64);
    INVNTT(128);

    zeta = zetas_inv[255];
    for (j = 0; j < DILITHIUM_N; ++j) {
        r[j] = dilithium_mont_red((sword64)zeta * r[j]);
    }
#elif defined(WC_32BIT_CPU)
    unsigned int j;
    unsigned int k = 0;
    sword32 t0;
    sword32 t2;

    sword32 zeta640;
    sword32 zeta641;
    sword32 zeta128;
    sword32 zeta256;
    for (j = 0; j < DILITHIUM_N; j += 4) {
        sword32 zeta2 = zetas_inv[128 + j / 4];
        sword32 r0 = r[j + 0];
        sword32 r2 = r[j + 1];
        sword32 r4 = r[j + 2];
        sword32 r6 = r[j + 3];

        t0 = dilithium_mont_red((sword64)zetas_inv[k++] * (r0 - r2));
        t2 = dilithium_mont_red((sword64)zetas_inv[k++] * (r4 - r6));
        r0 += r2;
        r4 += r6;
        r2 = t0;
        r6 = t2;

        t0 = dilithium_mont_red((sword64)zeta2 * (r0 - r4));
        t2 = dilithium_mont_red((sword64)zeta2 * (r2 - r6));
        r0 += r4;
        r2 += r6;
        r4 = t0;
        r6 = t2;

        r[j + 0] = r0;
        r[j + 1] = r2;
        r[j + 2] = r4;
        r[j + 3] = r6;
    }

    for (j = 0; j < DILITHIUM_N; j += 16) {
        int i;
        sword32 zeta40 = zetas_inv[192 + j / 8 + 0];
        sword32 zeta41 = zetas_inv[192 + j / 8 + 1];
        sword32 zeta8  = zetas_inv[224 + j / 16 + 0];
        for (i = 0; i < 4; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i +  4];
            sword32 r4 = r[j + i +  8];
            sword32 r6 = r[j + i + 12];

            t0 = dilithium_mont_red((sword64)zeta40 * (r0 - r2));
            t2 = dilithium_mont_red((sword64)zeta41 * (r4 - r6));
            r0 += r2;
            r4 += r6;
            r2 = t0;
            r6 = t2;

            t0 = dilithium_mont_red((sword64)zeta8 * (r0 - r4));
            t2 = dilithium_mont_red((sword64)zeta8 * (r2 - r6));
            r0 += r4;
            r2 += r6;
            r4 = t0;
            r6 = t2;

            r[j + i +  0] = r0;
            r[j + i +  4] = r2;
            r[j + i +  8] = r4;
            r[j + i + 12] = r6;
        }
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta160 = zetas_inv[240 + j / 32 + 0];
        sword32 zeta161 = zetas_inv[240 + j / 32 + 1];
        sword32 zeta32  = zetas_inv[248 + j / 64 + 0];
        for (i = 0; i < 16; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r2 = r[j + i + 16];
            sword32 r4 = r[j + i + 32];
            sword32 r6 = r[j + i + 48];

            t0 = dilithium_mont_red((sword64)zeta160 * (r0 - r2));
            t2 = dilithium_mont_red((sword64)zeta161 * (r4 - r6));
            r0 += r2;
            r4 += r6;
            r2 = t0;
            r6 = t2;

            t0 = dilithium_mont_red((sword64)zeta32 * (r0 - r4));
            t2 = dilithium_mont_red((sword64)zeta32 * (r2 - r6));
            r0 += r4;
            r2 += r6;
            r4 = t0;
            r6 = t2;

            r[j + i +  0] = r0;
            r[j + i + 16] = r2;
            r[j + i + 32] = r4;
            r[j + i + 48] = r6;
        }
    }

    zeta640 = zetas_inv[252];
    zeta641 = zetas_inv[253];
    zeta128 = zetas_inv[254];
    zeta256 = zetas_inv[255];
    for (j = 0; j < DILITHIUM_N / 4; j++) {
        sword32 r0 = r[j +   0];
        sword32 r2 = r[j +  64];
        sword32 r4 = r[j + 128];
        sword32 r6 = r[j + 192];

        t0 = dilithium_mont_red((sword64)zeta640 * (r0 - r2));
        t2 = dilithium_mont_red((sword64)zeta641 * (r4 - r6));
        r0 += r2;
        r4 += r6;
        r2 = t0;
        r6 = t2;

        t0 = dilithium_mont_red((sword64)zeta128 * (r0 - r4));
        t2 = dilithium_mont_red((sword64)zeta128 * (r2 - r6));
        r0 += r4;
        r2 += r6;
        r4 = t0;
        r6 = t2;

        r0 = dilithium_mont_red((sword64)zeta256 * r0);
        r2 = dilithium_mont_red((sword64)zeta256 * r2);
        r4 = dilithium_mont_red((sword64)zeta256 * r4);
        r6 = dilithium_mont_red((sword64)zeta256 * r6);

        r[j +   0] = r0;
        r[j +  64] = r2;
        r[j + 128] = r4;
        r[j + 192] = r6;
    }
#else
    unsigned int j;
    unsigned int k = 0;
    sword32 t0;
    sword32 t1;
    sword32 t2;
    sword32 t3;

    sword32 zeta640;
    sword32 zeta641;
    sword32 zeta128;
    sword32 zeta256;
    for (j = 0; j < DILITHIUM_N; j += 8) {
        sword32 zeta20 = zetas_inv[128 + j / 4 + 0];
        sword32 zeta21 = zetas_inv[128 + j / 4 + 1];
        sword32 zeta4  = zetas_inv[192 + j / 8 + 0];
        sword32 r0 = r[j + 0];
        sword32 r1 = r[j + 1];
        sword32 r2 = r[j + 2];
        sword32 r3 = r[j + 3];
        sword32 r4 = r[j + 4];
        sword32 r5 = r[j + 5];
        sword32 r6 = r[j + 6];
        sword32 r7 = r[j + 7];

        t0 = dilithium_mont_red((sword64)zetas_inv[k++] * (r0 - r1));
        t1 = dilithium_mont_red((sword64)zetas_inv[k++] * (r2 - r3));
        t2 = dilithium_mont_red((sword64)zetas_inv[k++] * (r4 - r5));
        t3 = dilithium_mont_red((sword64)zetas_inv[k++] * (r6 - r7));
        r0 += r1;
        r2 += r3;
        r4 += r5;
        r6 += r7;
        r1 = t0;
        r3 = t1;
        r5 = t2;
        r7 = t3;

        t0 = dilithium_mont_red((sword64)zeta20 * (r0 - r2));
        t1 = dilithium_mont_red((sword64)zeta20 * (r1 - r3));
        t2 = dilithium_mont_red((sword64)zeta21 * (r4 - r6));
        t3 = dilithium_mont_red((sword64)zeta21 * (r5 - r7));
        r0 += r2;
        r1 += r3;
        r4 += r6;
        r5 += r7;
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        t0 = dilithium_mont_red((sword64)zeta4 * (r0 - r4));
        t1 = dilithium_mont_red((sword64)zeta4 * (r1 - r5));
        t2 = dilithium_mont_red((sword64)zeta4 * (r2 - r6));
        t3 = dilithium_mont_red((sword64)zeta4 * (r3 - r7));
        r0 += r4;
        r1 += r5;
        r2 += r6;
        r3 += r7;
        r4 = t0;
        r5 = t1;
        r6 = t2;
        r7 = t3;

        r[j + 0] = r0;
        r[j + 1] = r1;
        r[j + 2] = r2;
        r[j + 3] = r3;
        r[j + 4] = r4;
        r[j + 5] = r5;
        r[j + 6] = r6;
        r[j + 7] = r7;
    }

    for (j = 0; j < DILITHIUM_N; j += 64) {
        int i;
        sword32 zeta80  = zetas_inv[224 + j / 16 + 0];
        sword32 zeta81  = zetas_inv[224 + j / 16 + 1];
        sword32 zeta82  = zetas_inv[224 + j / 16 + 2];
        sword32 zeta83  = zetas_inv[224 + j / 16 + 3];
        sword32 zeta160 = zetas_inv[240 + j / 32 + 0];
        sword32 zeta161 = zetas_inv[240 + j / 32 + 1];
        sword32 zeta32  = zetas_inv[248 + j / 64 + 0];
        for (i = 0; i < 8; i++) {
            sword32 r0 = r[j + i +  0];
            sword32 r1 = r[j + i +  8];
            sword32 r2 = r[j + i + 16];
            sword32 r3 = r[j + i + 24];
            sword32 r4 = r[j + i + 32];
            sword32 r5 = r[j + i + 40];
            sword32 r6 = r[j + i + 48];
            sword32 r7 = r[j + i + 56];

            t0 = dilithium_mont_red((sword64)zeta80 * (r0 - r1));
            t1 = dilithium_mont_red((sword64)zeta81 * (r2 - r3));
            t2 = dilithium_mont_red((sword64)zeta82 * (r4 - r5));
            t3 = dilithium_mont_red((sword64)zeta83 * (r6 - r7));
            r0 += r1;
            r2 += r3;
            r4 += r5;
            r6 += r7;
            r1 = t0;
            r3 = t1;
            r5 = t2;
            r7 = t3;

            t0 = dilithium_mont_red((sword64)zeta160 * (r0 - r2));
            t1 = dilithium_mont_red((sword64)zeta160 * (r1 - r3));
            t2 = dilithium_mont_red((sword64)zeta161 * (r4 - r6));
            t3 = dilithium_mont_red((sword64)zeta161 * (r5 - r7));
            r0 += r2;
            r1 += r3;
            r4 += r6;
            r5 += r7;
            r2 = t0;
            r3 = t1;
            r6 = t2;
            r7 = t3;

            t0 = dilithium_mont_red((sword64)zeta32 * (r0 - r4));
            t1 = dilithium_mont_red((sword64)zeta32 * (r1 - r5));
            t2 = dilithium_mont_red((sword64)zeta32 * (r2 - r6));
            t3 = dilithium_mont_red((sword64)zeta32 * (r3 - r7));
            r0 += r4;
            r1 += r5;
            r2 += r6;
            r3 += r7;
            r4 = t0;
            r5 = t1;
            r6 = t2;
            r7 = t3;

            r[j + i +  0] = r0;
            r[j + i +  8] = r1;
            r[j + i + 16] = r2;
            r[j + i + 24] = r3;
            r[j + i + 32] = r4;
            r[j + i + 40] = r5;
            r[j + i + 48] = r6;
            r[j + i + 56] = r7;
        }
    }

    zeta640 = zetas_inv[252];
    zeta641 = zetas_inv[253];
    zeta128 = zetas_inv[254];
    zeta256 = zetas_inv[255];
    for (j = 0; j < DILITHIUM_N / 8; j++) {
        sword32 r0 = r[j +   0];
        sword32 r1 = r[j +  32];
        sword32 r2 = r[j +  64];
        sword32 r3 = r[j +  96];
        sword32 r4 = r[j + 128];
        sword32 r5 = r[j + 160];
        sword32 r6 = r[j + 192];
        sword32 r7 = r[j + 224];

        t0 = dilithium_mont_red((sword64)zeta640 * (r0 - r2));
        t1 = dilithium_mont_red((sword64)zeta640 * (r1 - r3));
        t2 = dilithium_mont_red((sword64)zeta641 * (r4 - r6));
        t3 = dilithium_mont_red((sword64)zeta641 * (r5 - r7));
        r0 += r2;
        r1 += r3;
        r4 += r6;
        r5 += r7;
        r2 = t0;
        r3 = t1;
        r6 = t2;
        r7 = t3;

        t0 = dilithium_mont_red((sword64)zeta128 * (r0 - r4));
        t1 = dilithium_mont_red((sword64)zeta128 * (r1 - r5));
        t2 = dilithium_mont_red((sword64)zeta128 * (r2 - r6));
        t3 = dilithium_mont_red((sword64)zeta128 * (r3 - r7));
        r0 += r4;
        r1 += r5;
        r2 += r6;
        r3 += r7;
        r4 = t0;
        r5 = t1;
        r6 = t2;
        r7 = t3;

        r0 = dilithium_mont_red((sword64)zeta256 * r0);
        r1 = dilithium_mont_red((sword64)zeta256 * r1);
        r2 = dilithium_mont_red((sword64)zeta256 * r2);
        r3 = dilithium_mont_red((sword64)zeta256 * r3);
        r4 = dilithium_mont_red((sword64)zeta256 * r4);
        r5 = dilithium_mont_red((sword64)zeta256 * r5);
        r6 = dilithium_mont_red((sword64)zeta256 * r6);
        r7 = dilithium_mont_red((sword64)zeta256 * r7);

        r[j +   0] = r0;
        r[j +  32] = r1;
        r[j +  64] = r2;
        r[j +  96] = r3;
        r[j + 128] = r4;
        r[j + 160] = r5;
        r[j + 192] = r6;
        r[j + 224] = r7;
    }
#endif
}


#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
     defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Inverse Number-Theoretic Transform.
 *
 * @param [in, out]  r  Vector of polynomials to transform.
 * @param [in]       l  Dimension of polynomial.
 */
static void dilithium_vec_invntt(sword32* r, byte l)
{
    unsigned int i;

    for (i = 0; i < l; i++) {
        dilithium_invntt(r);
        r += DILITHIUM_N;
    }
}
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
     defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Matrix multiplication.
 *
 * @param [out] r  Vector of polynomials that is result.
 * @param [in]  m  Matrix of polynomials.
 * @param [in]  v  Vector of polynomials.
 * @param [in]  k  First dimension of matrix and dimension of result.
 * @param [in]  l  Second dimension of matrix and dimension of v.
 */
static void dilithium_matrix_mul(sword32* r, const sword32* m, const sword32* v,
     byte k, byte l)
{
    byte i;

    for (i = 0; i < k; i++) {
        byte j;
        unsigned int e;
        const sword32* vt = v;

#ifdef WOLFSSL_DILITHIUM_SMALL
        for (e = 0; e < DILITHIUM_N; e++) {
            r[e] = dilithium_mont_red((sword64)m[e] * vt[e]);
        }
        m += DILITHIUM_N;
        vt += DILITHIUM_N;
        for (j = 1; j < l; j++) {
            for (e = 0; e < DILITHIUM_N; e++) {
                r[e] += dilithium_mont_red((sword64)m[e] * vt[e]);
            }
            m += DILITHIUM_N;
            vt += DILITHIUM_N;
        }
#elif defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE)
        (void)j;
        if (l == 4) {
            for (e = 0; e < DILITHIUM_N; e++) {
                sword64 t = ((sword64)m[e + 0 * 256] * vt[e + 0 * 256]) +
                            ((sword64)m[e + 1 * 256] * vt[e + 1 * 256]) +
                            ((sword64)m[e + 2 * 256] * vt[e + 2 * 256]) +
                            ((sword64)m[e + 3 * 256] * vt[e + 3 * 256]);
                r[e] = dilithium_mont_red(t);
            }
            m += DILITHIUM_N * 4;
        }
        else if (l == 5) {
            for (e = 0; e < DILITHIUM_N; e++) {
                sword64 t = ((sword64)m[e + 0 * 256] * vt[e + 0 * 256]) +
                            ((sword64)m[e + 1 * 256] * vt[e + 1 * 256]) +
                            ((sword64)m[e + 2 * 256] * vt[e + 2 * 256]) +
                            ((sword64)m[e + 3 * 256] * vt[e + 3 * 256]) +
                            ((sword64)m[e + 4 * 256] * vt[e + 4 * 256]);
                r[e] = dilithium_mont_red(t);
            }
            m += DILITHIUM_N * 5;
        }
        else if (l == 7) {
            for (e = 0; e < DILITHIUM_N; e++) {
                sword64 t = ((sword64)m[e + 0 * 256] * vt[e + 0 * 256]) +
                            ((sword64)m[e + 1 * 256] * vt[e + 1 * 256]) +
                            ((sword64)m[e + 2 * 256] * vt[e + 2 * 256]) +
                            ((sword64)m[e + 3 * 256] * vt[e + 3 * 256]) +
                            ((sword64)m[e + 4 * 256] * vt[e + 4 * 256]) +
                            ((sword64)m[e + 5 * 256] * vt[e + 5 * 256]) +
                            ((sword64)m[e + 6 * 256] * vt[e + 6 * 256]);
                r[e] = dilithium_mont_red(t);
            }
            m += DILITHIUM_N * 7;
        }
#else
        sword64 t0;
        sword64 t1;
#if !defined(WOLFSSL_NO_ML_DSA_44) || !defined(WOLFSSL_NO_ML_DSA_65)
        sword64 t2;
        sword64 t3;
#endif

        (void)j;
#ifndef WOLFSSL_NO_ML_DSA_44
        if (l == 4) {
            for (e = 0; e < DILITHIUM_N; e += 4) {
                t0 = ((sword64)m[e + 0 + 0 * 256] * vt[e + 0 + 0 * 256]) +
                     ((sword64)m[e + 0 + 1 * 256] * vt[e + 0 + 1 * 256]) +
                     ((sword64)m[e + 0 + 2 * 256] * vt[e + 0 + 2 * 256]) +
                     ((sword64)m[e + 0 + 3 * 256] * vt[e + 0 + 3 * 256]);
                t1 = ((sword64)m[e + 1 + 0 * 256] * vt[e + 1 + 0 * 256]) +
                     ((sword64)m[e + 1 + 1 * 256] * vt[e + 1 + 1 * 256]) +
                     ((sword64)m[e + 1 + 2 * 256] * vt[e + 1 + 2 * 256]) +
                     ((sword64)m[e + 1 + 3 * 256] * vt[e + 1 + 3 * 256]);
                t2 = ((sword64)m[e + 2 + 0 * 256] * vt[e + 2 + 0 * 256]) +
                     ((sword64)m[e + 2 + 1 * 256] * vt[e + 2 + 1 * 256]) +
                     ((sword64)m[e + 2 + 2 * 256] * vt[e + 2 + 2 * 256]) +
                     ((sword64)m[e + 2 + 3 * 256] * vt[e + 2 + 3 * 256]);
                t3 = ((sword64)m[e + 3 + 0 * 256] * vt[e + 3 + 0 * 256]) +
                     ((sword64)m[e + 3 + 1 * 256] * vt[e + 3 + 1 * 256]) +
                     ((sword64)m[e + 3 + 2 * 256] * vt[e + 3 + 2 * 256]) +
                     ((sword64)m[e + 3 + 3 * 256] * vt[e + 3 + 3 * 256]);
                r[e + 0] = dilithium_mont_red(t0);
                r[e + 1] = dilithium_mont_red(t1);
                r[e + 2] = dilithium_mont_red(t2);
                r[e + 3] = dilithium_mont_red(t3);
            }
            m += DILITHIUM_N * 4;
        }
        else
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
        if (l == 5) {
            for (e = 0; e < DILITHIUM_N; e += 4) {
                t0 = ((sword64)m[e + 0 + 0 * 256] * vt[e + 0 + 0 * 256]) +
                     ((sword64)m[e + 0 + 1 * 256] * vt[e + 0 + 1 * 256]) +
                     ((sword64)m[e + 0 + 2 * 256] * vt[e + 0 + 2 * 256]) +
                     ((sword64)m[e + 0 + 3 * 256] * vt[e + 0 + 3 * 256]) +
                     ((sword64)m[e + 0 + 4 * 256] * vt[e + 0 + 4 * 256]);
                t1 = ((sword64)m[e + 1 + 0 * 256] * vt[e + 1 + 0 * 256]) +
                     ((sword64)m[e + 1 + 1 * 256] * vt[e + 1 + 1 * 256]) +
                     ((sword64)m[e + 1 + 2 * 256] * vt[e + 1 + 2 * 256]) +
                     ((sword64)m[e + 1 + 3 * 256] * vt[e + 1 + 3 * 256]) +
                     ((sword64)m[e + 1 + 4 * 256] * vt[e + 1 + 4 * 256]);
                t2 = ((sword64)m[e + 2 + 0 * 256] * vt[e + 2 + 0 * 256]) +
                     ((sword64)m[e + 2 + 1 * 256] * vt[e + 2 + 1 * 256]) +
                     ((sword64)m[e + 2 + 2 * 256] * vt[e + 2 + 2 * 256]) +
                     ((sword64)m[e + 2 + 3 * 256] * vt[e + 2 + 3 * 256]) +
                     ((sword64)m[e + 2 + 4 * 256] * vt[e + 2 + 4 * 256]);
                t3 = ((sword64)m[e + 3 + 0 * 256] * vt[e + 3 + 0 * 256]) +
                     ((sword64)m[e + 3 + 1 * 256] * vt[e + 3 + 1 * 256]) +
                     ((sword64)m[e + 3 + 2 * 256] * vt[e + 3 + 2 * 256]) +
                     ((sword64)m[e + 3 + 3 * 256] * vt[e + 3 + 3 * 256]) +
                     ((sword64)m[e + 3 + 4 * 256] * vt[e + 3 + 4 * 256]);
                r[e + 0] = dilithium_mont_red(t0);
                r[e + 1] = dilithium_mont_red(t1);
                r[e + 2] = dilithium_mont_red(t2);
                r[e + 3] = dilithium_mont_red(t3);
            }
            m += DILITHIUM_N * 5;
        }
        else
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
        if (l == 7) {
            for (e = 0; e < DILITHIUM_N; e += 2) {
                t0 = ((sword64)m[e + 0 + 0 * 256] * vt[e + 0 + 0 * 256]) +
                     ((sword64)m[e + 0 + 1 * 256] * vt[e + 0 + 1 * 256]) +
                     ((sword64)m[e + 0 + 2 * 256] * vt[e + 0 + 2 * 256]) +
                     ((sword64)m[e + 0 + 3 * 256] * vt[e + 0 + 3 * 256]) +
                     ((sword64)m[e + 0 + 4 * 256] * vt[e + 0 + 4 * 256]) +
                     ((sword64)m[e + 0 + 5 * 256] * vt[e + 0 + 5 * 256]) +
                     ((sword64)m[e + 0 + 6 * 256] * vt[e + 0 + 6 * 256]);
                t1 = ((sword64)m[e + 1 + 0 * 256] * vt[e + 1 + 0 * 256]) +
                     ((sword64)m[e + 1 + 1 * 256] * vt[e + 1 + 1 * 256]) +
                     ((sword64)m[e + 1 + 2 * 256] * vt[e + 1 + 2 * 256]) +
                     ((sword64)m[e + 1 + 3 * 256] * vt[e + 1 + 3 * 256]) +
                     ((sword64)m[e + 1 + 4 * 256] * vt[e + 1 + 4 * 256]) +
                     ((sword64)m[e + 1 + 5 * 256] * vt[e + 1 + 5 * 256]) +
                     ((sword64)m[e + 1 + 6 * 256] * vt[e + 1 + 6 * 256]);
                r[e + 0] = dilithium_mont_red(t0);
                r[e + 1] = dilithium_mont_red(t1);
            }
            m += DILITHIUM_N * 7;
        }
        else
#endif
        {
        }
#endif
        r += DILITHIUM_N;
    }
}
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))
/* Polynomial multiplication.
 *
 * @param [out] r  Polynomial result.
 * @param [in]  a  Polynomial
 * @param [in]  b  Polynomial.
 */
static void dilithium_mul(sword32* r, sword32* a, sword32* b)
{
    unsigned int e;
#ifdef WOLFSSL_DILITHIUM_SMALL
    for (e = 0; e < DILITHIUM_N; e++) {
        r[e] = dilithium_mont_red((sword64)a[e] * b[e]);
    }
#elif defined(WOLFSSL_DILITHIUM_NO_LARGE_CODE)
    for (e = 0; e < DILITHIUM_N; e += 8) {
        r[e+0] = dilithium_mont_red((sword64)a[e+0] * b[e+0]);
        r[e+1] = dilithium_mont_red((sword64)a[e+1] * b[e+1]);
        r[e+2] = dilithium_mont_red((sword64)a[e+2] * b[e+2]);
        r[e+3] = dilithium_mont_red((sword64)a[e+3] * b[e+3]);
        r[e+4] = dilithium_mont_red((sword64)a[e+4] * b[e+4]);
        r[e+5] = dilithium_mont_red((sword64)a[e+5] * b[e+5]);
        r[e+6] = dilithium_mont_red((sword64)a[e+6] * b[e+6]);
        r[e+7] = dilithium_mont_red((sword64)a[e+7] * b[e+7]);
    }
#else
    for (e = 0; e < DILITHIUM_N; e += 16) {
        r[e+ 0] = dilithium_mont_red((sword64)a[e+ 0] * b[e+ 0]);
        r[e+ 1] = dilithium_mont_red((sword64)a[e+ 1] * b[e+ 1]);
        r[e+ 2] = dilithium_mont_red((sword64)a[e+ 2] * b[e+ 2]);
        r[e+ 3] = dilithium_mont_red((sword64)a[e+ 3] * b[e+ 3]);
        r[e+ 4] = dilithium_mont_red((sword64)a[e+ 4] * b[e+ 4]);
        r[e+ 5] = dilithium_mont_red((sword64)a[e+ 5] * b[e+ 5]);
        r[e+ 6] = dilithium_mont_red((sword64)a[e+ 6] * b[e+ 6]);
        r[e+ 7] = dilithium_mont_red((sword64)a[e+ 7] * b[e+ 7]);
        r[e+ 8] = dilithium_mont_red((sword64)a[e+ 8] * b[e+ 8]);
        r[e+ 9] = dilithium_mont_red((sword64)a[e+ 9] * b[e+ 9]);
        r[e+10] = dilithium_mont_red((sword64)a[e+10] * b[e+10]);
        r[e+11] = dilithium_mont_red((sword64)a[e+11] * b[e+11]);
        r[e+12] = dilithium_mont_red((sword64)a[e+12] * b[e+12]);
        r[e+13] = dilithium_mont_red((sword64)a[e+13] * b[e+13]);
        r[e+14] = dilithium_mont_red((sword64)a[e+14] * b[e+14]);
        r[e+15] = dilithium_mont_red((sword64)a[e+15] * b[e+15]);
    }
#endif
}

#if (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
     !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))
/* Vector multiplication.
 *
 * @param [out] r  Vector of polynomials that is result.
 * @param [in]  a  Polynomials
 * @param [in]  b  Vector of polynomials.
 * @param [in]  l  Dimension of vectors.
 */
static void dilithium_vec_mul(sword32* r, sword32* a, sword32* b, byte l)
{
    byte i;

    for (i = 0; i < l; i++) {
        dilithium_mul(r, a, b);
        r += DILITHIUM_N;
        b += DILITHIUM_N;
    }
}
#endif
#endif

#ifndef WOLFSSL_DILITHIUM_NO_SIGN
/* Modulo reduce values in polynomial. Range (-2^31)..(2^31-1).
 *
 * @param [in, out] a  Polynomial.
 */
static void dilithium_poly_red(sword32* a)
{
    word16 j;
#ifdef WOLFSSL_DILITHIUM_SMALL
    for (j = 0; j < DILITHIUM_N; j++) {
        a[j] = dilithium_red(a[j]);
    }
#else
    for (j = 0; j < DILITHIUM_N; j += 8) {
        a[j+0] = dilithium_red(a[j+0]);
        a[j+1] = dilithium_red(a[j+1]);
        a[j+2] = dilithium_red(a[j+2]);
        a[j+3] = dilithium_red(a[j+3]);
        a[j+4] = dilithium_red(a[j+4]);
        a[j+5] = dilithium_red(a[j+5]);
        a[j+6] = dilithium_red(a[j+6]);
        a[j+7] = dilithium_red(a[j+7]);
    }
#endif
}

#ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
/* Modulo reduce values in polynomials of vector. Range (-2^31)..(2^31-1).
 *
 * @param [in, out] a  Vector of polynomials.
 * @param [in]      l  Dimension of vector.
 */
static void dilithium_vec_red(sword32* a, byte l)
{
    byte i;

    for (i = 0; i < l; i++) {
        dilithium_poly_red(a);
        a += DILITHIUM_N;
    }
}
#endif /*  WOLFSSL_DILITHIUM_SIGN_SMALL_MEM*/
#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

#if (!defined(WOLFSSL_DILITHIUM_NO_SIGN) || \
     (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
      !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM))) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY)
/* Subtract polynomials a from r. r -= a.
 *
 * @param [out] r  Polynomial to subtract from.
 * @param [in]  a  Polynomial to subtract.
 */
static void dilithium_sub(sword32* r, const sword32* a)
{
    word16 j;
#ifdef WOLFSSL_DILITHIUM_SMALL
    for (j = 0; j < DILITHIUM_N; j++) {
        r[j] -= a[j];
    }
#else
    for (j = 0; j < DILITHIUM_N; j += 8) {
        r[j+0] -= a[j+0];
        r[j+1] -= a[j+1];
        r[j+2] -= a[j+2];
        r[j+3] -= a[j+3];
        r[j+4] -= a[j+4];
        r[j+5] -= a[j+5];
        r[j+6] -= a[j+6];
        r[j+7] -= a[j+7];
    }
#endif
}

#if defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
   (!defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Subtract vector a from r. r -= a.
 *
 * @param [out] r  Vector of polynomials that is result.
 * @param [in]  a  Vector of polynomials to subtract.
 * @param [in]  l  Dimension of vectors.
 */
static void dilithium_vec_sub(sword32* r, const sword32* a, byte l)
{
    byte i;

    for (i = 0; i < l; i++) {
        dilithium_sub(r, a);
        r += DILITHIUM_N;
        a += DILITHIUM_N;
    }
}
#endif
#endif

#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
/* Add polynomials a to r. r += a.
 *
 * @param [out] r  Polynomial to add to.
 * @param [in]  a  Polynomial to add.
 */
static void dilithium_add(sword32* r, const sword32* a)
{
    word16 j;
#ifdef WOLFSSL_DILITHIUM_SMALL
    for (j = 0; j < DILITHIUM_N; j++) {
        r[j] += a[j];
    }
#else
    for (j = 0; j < DILITHIUM_N; j += 8) {
        r[j+0] += a[j+0];
        r[j+1] += a[j+1];
        r[j+2] += a[j+2];
        r[j+3] += a[j+3];
        r[j+4] += a[j+4];
        r[j+5] += a[j+5];
        r[j+6] += a[j+6];
        r[j+7] += a[j+7];
    }
#endif
}

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Add vector a to r. r += a.
 *
 * @param [out] r  Vector of polynomials that is result.
 * @param [in]  a  Vector of polynomials to add.
 * @param [in]  l  Dimension of vectors.
 */
static void dilithium_vec_add(sword32* r, const sword32* a, byte l)
{
    byte i;

    for (i = 0; i < l; i++) {
        dilithium_add(r, a);
        r += DILITHIUM_N;
        a += DILITHIUM_N;
    }
}
#endif

/* Make values in polynomial be in positive range.
 *
 * @param [in, out] a  Polynomial.
 */
static void dilithium_make_pos(sword32* a)
{
    word16 j;
#ifdef WOLFSSL_DILITHIUM_SMALL
    for (j = 0; j < DILITHIUM_N; j++) {
        a[j] += (0 - (((word32)a[j]) >> 31)) & DILITHIUM_Q;
    }
#else
    for (j = 0; j < DILITHIUM_N; j += 8) {
        a[j+0] += (0 - (((word32)a[j+0]) >> 31)) & DILITHIUM_Q;
        a[j+1] += (0 - (((word32)a[j+1]) >> 31)) & DILITHIUM_Q;
        a[j+2] += (0 - (((word32)a[j+2]) >> 31)) & DILITHIUM_Q;
        a[j+3] += (0 - (((word32)a[j+3]) >> 31)) & DILITHIUM_Q;
        a[j+4] += (0 - (((word32)a[j+4]) >> 31)) & DILITHIUM_Q;
        a[j+5] += (0 - (((word32)a[j+5]) >> 31)) & DILITHIUM_Q;
        a[j+6] += (0 - (((word32)a[j+6]) >> 31)) & DILITHIUM_Q;
        a[j+7] += (0 - (((word32)a[j+7]) >> 31)) & DILITHIUM_Q;
    }
#endif
}

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
    defined(WOLFSSL_DILITHIUM_CHECK_KEY) || \
    (!defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
     !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM))
/* Make values in polynomials of vector be in positive range.
 *
 * @param [in, out] a  Vector of polynomials.
 * @param [in]      l  Dimension of vector.
 */
static void dilithium_vec_make_pos(sword32* a, byte l)
{
    byte i;

    for (i = 0; i < l; i++) {
        dilithium_make_pos(a);
        a += DILITHIUM_N;
    }
}
#endif

#endif /* !WOLFSSL_DILITHIUM_VERIFY_ONLY */

/******************************************************************************/

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY

/* Make a key from a random seed.
 *
 * xi is seed passed in.
 * FIPS 204. 6.1: Algorithm 6 ML-DSA.KeyGen_internal(xi)
 *   1: (rho, rho', K) E B32 x B64 x B32 <- H(xi||k||l, 1024)
 *   2:
 *   3: A_circum <- ExpandA(rho)
 *   4: (s1,s2) <- ExpandS(rho')
 *   5: t <- NTT-1(A_circum o NTT(s1)) + s2
 *   6: (t1, t0) <- Power2Round(t, d)
 *   7: pk <- pkEncode(rho, t1)
 *   8: tr <- H(pk, 64)
 *   9: sk <- skEncode(rho, K, tr, s1, s2, t0)
 *  10: return (pk, sk)
 *
 * FIPS 204. 7.2: Algorithm 22 pkEncode(rho, t1)
 *   1: pk <- rho
 *   2: for i from 0 to k - 1 do
 *   3:     pk <- pk || SimpleBitPack(t1[i], 2^(bitlen(q-1)-d) - 1)
 *   4: end for
 *   5: return pk
 *
 * FIPS 204. 7.2: Algorithm 24 skEncode(rho, K, tr, s, s2, t0)
 *   1: sk <- rho || K || tr
 *   2: for i from 0 to l - 1 do
 *   3:     sk <- sk || BitPack(s1[i], eta, eta)
 *   4: end for
 *   5: for i from 0 to k - 1 do
 *   6:     sk <- sk || BitPack(s2[i], eta, eta)
 *   7: end for
 *   8: for i from 0 to k - 1 do
 *   9:     sk <- sk || BitPack(t0[i], 2^(d-1)-1, 2^(d-1))
 *  10: end for
 *  11: return sk
 *
 * Public and private key store in key.
 *
 * @param [in, out] key   Dilithium key.
 * @param [in]      seed  Seed to hash to generate values.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_make_key_from_seed(dilithium_key* key, const byte* seed)
{
#ifndef WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t = NULL;
    byte* pub_seed = key->k;
    byte kl[2];

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if (key->a == NULL) {
        key->a = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        key->s1 = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            key->s2 = key->s1  + params->s1Sz / sizeof(*s1);
            key->t0 = key->s2  + params->s2Sz / sizeof(*s2);
        }
    }
#endif
    if (ret == 0) {
        s1 = key->s1;
        s2 = key->s2;
        t  = key->t0;
    }
#else
    if (ret == 0) {
        unsigned int allocSz;

        allocSz = params->s1Sz + params->s2Sz + params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        allocSz += params->aSz;
#endif

        /* s1, s2, t, a */
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t  = s2 + params->s2Sz / sizeof(*s2);
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a  = t  + params->s2Sz / sizeof(*t);
#endif
        }
    }
#endif

    if (ret == 0) {
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        if (key->params->level >= WC_ML_DSA_DRAFT) {
            /* Step 2: Create public seed, private seed and K from seed.
             * Step 9; Alg 18, Step 1: Public seed is placed into private key.
             */
            ret = dilithium_shake256(&key->shake, seed, DILITHIUM_SEED_SZ,
                pub_seed, DILITHIUM_SEEDS_SZ);
        }
        else
#endif
        {
            kl[0] = params->k;
            kl[1] = params->l;
            /* Step 1: Create public seed, private seed and K from seed.
             * Step 9; Alg 24, Step 1: Public seed is placed into private key.
             */
            ret = dilithium_hash256(&key->shake, seed, DILITHIUM_SEED_SZ, kl, 2,
                pub_seed, DILITHIUM_SEEDS_SZ);
        }
    }
    if (ret == 0) {
        /* Step 7; Alg 22 Step 1: Copy public seed into public key. */
        XMEMCPY(key->p, pub_seed, DILITHIUM_PUB_SEED_SZ);

        /* Step 3: Expand public seed into a matrix of polynomials. */
        ret = dilithium_expand_a(&key->shake, pub_seed, params->k, params->l,
            a, key->heap);
    }
    if (ret == 0) {
        byte* priv_seed = key->k + DILITHIUM_PUB_SEED_SZ;

        /* Step 4: Expand private seed into to vectors of polynomials. */
        ret = dilithium_expand_s(&key->shake, priv_seed, params->eta, s1,
            params->l, s2, params->k);
    }
    if (ret == 0) {
        byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
        byte* tr = k + DILITHIUM_K_SZ;
        byte* s1p = tr + DILITHIUM_TR_SZ;
        byte* s2p = s1p + params->s1EncSz;
        byte* t0 = s2p + params->s2EncSz;
        byte* t1 = key->p + DILITHIUM_PUB_SEED_SZ;

        /* Step 9: Move k down to after public seed. */
        XMEMCPY(k, k + DILITHIUM_PRIV_SEED_SZ, DILITHIUM_K_SZ);
        /* Step 9. Alg 24 Steps 2-4: Encode s1 into private key. */
        dilthium_vec_encode_eta_bits(s1, params->l, params->eta, s1p);
        /* Step 9. Alg 24 Steps 5-7: Encode s2 into private key. */
        dilthium_vec_encode_eta_bits(s2, params->k, params->eta, s2p);

        /* Step 5: t <- NTT-1(A_circum o NTT(s1)) + s2 */
        dilithium_vec_ntt_small(s1, params->l);
        dilithium_matrix_mul(t, a, s1, params->k, params->l);
        dilithium_vec_invntt(t, params->k);
        dilithium_vec_add(t, s2, params->k);

        /* Make positive for decomposing. */
        dilithium_vec_make_pos(t, params->k);
        /* Step 6, Step 7, Step 9. Alg 22 Steps 2-4, Alg 24 Steps 8-10.
         * Decompose t in t0 and t1 and encode into public and private key.
         */
        dilithium_vec_encode_t0_t1(t, params->k, t0, t1);
        /* Step 8. Alg 24, Step 1: Hash public key into private key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Public key and private key are available. */
        key->prvKeySet = 1;
        key->pubKeySet = 1;
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Matrix A is available. */
        key->aSet = 1;
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* Private vectors are not available as they were overwritten. */
        key->privVecsSet = 0;
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        /* Public vector, t1, is not available as it was not created. */
        key->pubVecSet = 0;
#endif
    }

#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
    XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
#endif
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
    byte* h = NULL;
    byte* pub_seed = key->k;
    unsigned int r;
    unsigned int s;
    byte kl[2];

    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        unsigned int allocSz;

        /* s1-l, s2-k, t-k, a-1 */
        allocSz  = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_REJ_NTT_POLY_H_SIZE + DILITHIUM_POLY_SIZE;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        /* t64 */
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t  = s2 + params->s2Sz / sizeof(*s2);
            h  = (byte*)(t  + params->s2Sz / sizeof(*t));
            a  = (sword32*)(h + DILITHIUM_REJ_NTT_POLY_H_SIZE);
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64 = (sword64*)(a + DILITHIUM_N);
        #endif
        }
    }

    if (ret == 0) {
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        if (key->params->level >= WC_ML_DSA_DRAFT) {
            /* Step 2: Create public seed, private seed and K from seed.
             * Step 9; Alg 18, Step 1: Public seed is placed into private key.
             */
            ret = dilithium_shake256(&key->shake, seed, DILITHIUM_SEED_SZ,
                pub_seed, DILITHIUM_SEEDS_SZ);
        }
        else
#endif
        {
            kl[0] = params->k;
            kl[1] = params->l;
            /* Step 1: Create public seed, private seed and K from seed.
             * Step 9; Alg 24, Step 1: Public seed is placed into private key.
             */
            ret = dilithium_hash256(&key->shake, seed, DILITHIUM_SEED_SZ, kl, 2,
                pub_seed, DILITHIUM_SEEDS_SZ);
        }
    }
    if (ret == 0) {
        byte* priv_seed = key->k + DILITHIUM_PUB_SEED_SZ;

        /* Step 7; Alg 22 Step 1: Copy public seed into public key. */
        XMEMCPY(key->p, pub_seed, DILITHIUM_PUB_SEED_SZ);

        /* Step 4: Expand private seed into to vectors of polynomials. */
        ret = dilithium_expand_s(&key->shake, priv_seed, params->eta, s1,
            params->l, s2, params->k);
    }
    if (ret == 0) {
        byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
        byte* tr = k + DILITHIUM_K_SZ;
        byte* s1p = tr + DILITHIUM_TR_SZ;
        byte* s2p = s1p + params->s1EncSz;
        byte* t0 = s2p + params->s2EncSz;
        byte* t1 = key->p + DILITHIUM_PUB_SEED_SZ;
        byte aseed[DILITHIUM_GEN_A_SEED_SZ];
        sword32* s2t = s2;
        sword32* tt = t;

        /* Step 9: Move k down to after public seed. */
        XMEMCPY(k, k + DILITHIUM_PRIV_SEED_SZ, DILITHIUM_K_SZ);
        /* Step 9. Alg 24 Steps 2-4: Encode s1 into private key. */
        dilthium_vec_encode_eta_bits(s1, params->l, params->eta, s1p);
        /* Step 9. Alg 24 Steps 5-7: Encode s2 into private key. */
        dilthium_vec_encode_eta_bits(s2, params->k, params->eta, s2p);

        /* Step 5: NTT(s1) */
        dilithium_vec_ntt_small(s1, params->l);
        /* Step 5: t <- NTT-1(A_circum o NTT(s1)) + s2 */
        XMEMCPY(aseed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        for (r = 0; (ret == 0) && (r < params->k); r++) {
            sword32* s1t = s1;
            unsigned int e;

            /* Put r/i into buffer to be hashed. */
            aseed[DILITHIUM_PUB_SEED_SZ + 1] = r;
            for (s = 0; (ret == 0) && (s < params->l); s++) {

                /* Put s into buffer to be hashed. */
                aseed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                /* Step 3: Expand public seed into a matrix of polynomials. */
                ret = dilithium_rej_ntt_poly_ex(&key->shake, aseed, a, h);
                if (ret != 0) {
                    break;
                }
                /* Matrix multiply. */
            #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                if (s == 0) {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        tt[e] = dilithium_mont_red((sword64)a[e] * s1t[e]);
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        tt[e+0] = dilithium_mont_red((sword64)a[e+0]*s1t[e+0]);
                        tt[e+1] = dilithium_mont_red((sword64)a[e+1]*s1t[e+1]);
                        tt[e+2] = dilithium_mont_red((sword64)a[e+2]*s1t[e+2]);
                        tt[e+3] = dilithium_mont_red((sword64)a[e+3]*s1t[e+3]);
                        tt[e+4] = dilithium_mont_red((sword64)a[e+4]*s1t[e+4]);
                        tt[e+5] = dilithium_mont_red((sword64)a[e+5]*s1t[e+5]);
                        tt[e+6] = dilithium_mont_red((sword64)a[e+6]*s1t[e+6]);
                        tt[e+7] = dilithium_mont_red((sword64)a[e+7]*s1t[e+7]);
                    }
                #endif
                }
                else {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        tt[e] += dilithium_mont_red((sword64)a[e] * s1t[e]);
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        tt[e+0] += dilithium_mont_red((sword64)a[e+0]*s1t[e+0]);
                        tt[e+1] += dilithium_mont_red((sword64)a[e+1]*s1t[e+1]);
                        tt[e+2] += dilithium_mont_red((sword64)a[e+2]*s1t[e+2]);
                        tt[e+3] += dilithium_mont_red((sword64)a[e+3]*s1t[e+3]);
                        tt[e+4] += dilithium_mont_red((sword64)a[e+4]*s1t[e+4]);
                        tt[e+5] += dilithium_mont_red((sword64)a[e+5]*s1t[e+5]);
                        tt[e+6] += dilithium_mont_red((sword64)a[e+6]*s1t[e+6]);
                        tt[e+7] += dilithium_mont_red((sword64)a[e+7]*s1t[e+7]);
                    }
                #endif
                }
            #else
                if (s == 0) {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        t64[e] = (sword64)a[e] * s1t[e];
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        t64[e+0] = (sword64)a[e+0] * s1t[e+0];
                        t64[e+1] = (sword64)a[e+1] * s1t[e+1];
                        t64[e+2] = (sword64)a[e+2] * s1t[e+2];
                        t64[e+3] = (sword64)a[e+3] * s1t[e+3];
                        t64[e+4] = (sword64)a[e+4] * s1t[e+4];
                        t64[e+5] = (sword64)a[e+5] * s1t[e+5];
                        t64[e+6] = (sword64)a[e+6] * s1t[e+6];
                        t64[e+7] = (sword64)a[e+7] * s1t[e+7];
                    }
                #endif
                }
                else {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        t64[e] += (sword64)a[e] * s1t[e];
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        t64[e+0] += (sword64)a[e+0] * s1t[e+0];
                        t64[e+1] += (sword64)a[e+1] * s1t[e+1];
                        t64[e+2] += (sword64)a[e+2] * s1t[e+2];
                        t64[e+3] += (sword64)a[e+3] * s1t[e+3];
                        t64[e+4] += (sword64)a[e+4] * s1t[e+4];
                        t64[e+5] += (sword64)a[e+5] * s1t[e+5];
                        t64[e+6] += (sword64)a[e+6] * s1t[e+6];
                        t64[e+7] += (sword64)a[e+7] * s1t[e+7];
                    }
                #endif
                }
            #endif
                /* Next polynomial. */
                s1t += DILITHIUM_N;
            }
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            for (e = 0; e < DILITHIUM_N; e++) {
                tt[e] = dilithium_mont_red(t64[e]);
            }
        #endif
            dilithium_invntt(tt);
            dilithium_add(tt, s2t);
            /* Make positive for decomposing. */
            dilithium_make_pos(tt);

            tt += DILITHIUM_N;
            s2t += DILITHIUM_N;
        }

        /* Step 6, Step 7, Step 9. Alg 22 Steps 2-4, Alg 24 Steps 8-10.
         * Decompose t in t0 and t1 and encode into public and private key.
         */
        dilithium_vec_encode_t0_t1(t, params->k, t0, t1);
        /* Step 8. Alg 24, Step 1: Hash public key into private key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Public key and private key are available. */
        key->prvKeySet = 1;
        key->pubKeySet = 1;
    }

    XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#endif
}

/* Make a key from a random seed.
 *
 * FIPS 204. 5.1: Algorithm 1 ML-DSA.KeyGen()
 *   1: xi <- B32  [Choose random seed]
 *   2: if xi = NULL then
 *   3:   return falsam
 *   4: end if
 *   5: return ML-DSA.KeyGen_internal(xi)
 *
 * @param [in, out] key  Dilithium key.
 * @param [in]      rng  Random number generator.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_make_key(dilithium_key* key, WC_RNG* rng)
{
    int ret;
    byte seed[DILITHIUM_SEED_SZ];

    /* Step 1: Generate a 32 byte random seed. */
    ret = wc_RNG_GenerateBlock(rng, seed, DILITHIUM_SEED_SZ);
    /* Step 2: Check for error. */
    if (ret == 0) {
        /* Step 5: Make key with random seed. */
        ret = wc_dilithium_make_key_from_seed(key, seed);
    }

    return ret;
}
#endif /* !WOLFSSL_DILITHIUM_NO_MAKE_KEY */

#ifndef WOLFSSL_DILITHIUM_NO_SIGN

#if !defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM) || \
    defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC) || \
    defined(WC_DILITHIUM_CACHE_PRIV_VECTORS)
/* Decode, from private key, and NTT private key vectors s1, s2, and t0.
 *
 * FIPS 204. 6: Algorithm 2 ML-DSA.Sign(sk, M)
 *   1: (rho, K, tr, s1, s2, t0) <- skDecode(sk)
 *   2: s1_circum <- NTT(s1)
 *   3: s2_circum <- NTT(s2)
 *   4: t0_circum <- NTT(t0)
 *
 * @param [in, out] key  Dilithium key.
 * @param [out]     s1   Vector of polynomials s1.
 * @param [out]     s2   Vector of polynomials s2.
 * @param [out]     t0   Vector of polynomials t0.
 */
static void dilithium_make_priv_vecs(dilithium_key* key, sword32* s1,
    sword32* s2, sword32* t0)
{
    const wc_dilithium_params* params = key->params;
    const byte* pubSeed = key->k;
    const byte* k = pubSeed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    const byte* s1p = tr + DILITHIUM_TR_SZ;
    const byte* s2p = s1p + params->s1EncSz;
    const byte* t0p = s2p + params->s2EncSz;

    /* Step 1: Decode s1, s2, t0. */
    dilithium_vec_decode_eta_bits(s1p, params->eta, s1, params->l);
    dilithium_vec_decode_eta_bits(s2p, params->eta, s2, params->k);
    dilithium_vec_decode_t0(t0p, params->k, t0);

    /* Step 2: NTT s1. */
    dilithium_vec_ntt_small(s1, params->l);
    /* Step 3: NTT s2. */
    dilithium_vec_ntt_small(s2, params->k);
    /* Step 4: NTT t0. */
    dilithium_vec_ntt(t0, params->k);

#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
    /* Private key vectors have been created. */
    key->privVecsSet = 1;
#endif
}
#endif

/* Sign a message with the key and a seed.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.sign(sk, M, ctx)
 *   ...
 *  10: M' <- ByyesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx) || M
 *   ...
 *
 * FIPS 204. 6: Algorithm 2 ML-DSA.Sign(sk, M)
 *   1: (rho, K, tr, s1, s2, t0) <- skDecode(sk)
 *   2: s1_circum <- NTT(s1)
 *   3: s2_circum <- NTT(s2)
 *   4: t0_circum <- NTT(t0)
 *   5: A_circum <- ExpandA(rho)
 *   6: mu <- H(tr||M, 512)
 *   7: rnd <- {0,1}256
 *   8: rho' <- H(K||rnd||mu, 512)
 *   9: kappa <- 0
 *  10: (z, h) <- falsam
 *  11: while (z, h) = falsam do
 *  12:    y <- ExpandMask(rho', kappa)
 *  13:    w <- NTT-1(A_circum o NTT(y))
 *  14:    w1 <- HighBits(w)
 *  15:    c_tilde E {0,1}2*lambda <- H(mu|w1Encode(w1), 2 * lambda)
 *  16:    (c1_tilde, c2_tilde) E {0,1}256 x {0,1}2*lambda-256 <- c_tilde
 *  17:     c < SampleInBall(c1_tilde)
 *  18:     c_circum <- NTT(c)
 *  19:     <<cs1>> <- NTT-1(c_circum o s1_circum)
 *  20:     <<cs2>> <- NTT-1(c_circum o s2_circum)
 *  21:     z <- y + <<cs1>>
 *  22:     r0 <- LowBits(w - <<cs2>>
 *  23:     if ||z||inf >= GAMMA1 - BETA or ||r0||inf GAMMA2 - BETA then
 *                                                             (z, h) <- falsam
 *  24:     else
 *  25:         <<ct0>> <- NTT-1(c_circum o t0_circum)
 *  26:         h < MakeHint(-<<ct0>>, w - <<sc2>> + <<ct0>>)
 *  27:         if (||<<ct>>||inf >= GAMMMA1 or
 *                 the number of 1's in h is greater than OMEGA, then
 *                                                             (z, h) <- falsam
 *  28:         end if
 *  29:     end if
 *  30:     kappa <- kappa + l
 *  31: end while
 *  32: sigma <- sigEncode(c_tilde, z mod +/- q, h)
 *  33: return sigma
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      seedMu  Random seed || mu.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when context length is greater than 255.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_with_seed_mu(dilithium_key* key,
    const byte* seedMu, byte* sig, word32 *sigLen)
{
#ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* mu = seedMu + DILITHIUM_RND_SZ;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t0 = NULL;
    sword32* y = NULL;
    sword32* w0 = NULL;
    sword32* w1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* ct0 = NULL;
    byte priv_rand_seed[DILITHIUM_Y_SEED_SZ];
    byte* h = sig + params->lambda / 4 + params->zEncSz;

    /* Check the signature buffer isn't too small. */
    if (*sigLen < params->sigSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Return the size of the signature. */
        *sigLen = params->sigSz;
    }

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->a == NULL)) {
        a = (sword32*)XMALLOC(params->aSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        key->s1 = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            key->s2 = key->s1  + params->s1Sz / sizeof(*s1);
            key->t0 = key->s2  + params->s2Sz / sizeof(*s2);
        }
    }
#endif
    if (ret == 0) {
        s1 = key->s1;
        s2 = key->s2;
        t0 = key->t0;
    }
#endif
    if (ret == 0) {
        unsigned int allocSz;

        /* y-l, w0-k, w1-k, c-1, z-l, ct0-k */
        allocSz = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_POLY_SIZE + params->s1Sz + params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* s1-l, s2-k, t0-k */
        allocSz += params->s1Sz + params->s2Sz + params->s2Sz;
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        /* A */
        allocSz += params->aSz;
#endif
        y = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (y == NULL) {
            ret = MEMORY_E;
        }
        else {
            w0  = y   + params->s1Sz / sizeof(*y);
            w1  = w0  + params->s2Sz / sizeof(*w0);
            c   = w1  + params->s2Sz / sizeof(*w1);
            z   = c   + DILITHIUM_N;
            ct0 = z   + params->s1Sz / sizeof(*z);
#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
            s1  = ct0 + params->s2Sz / sizeof(*ct0);
            s2  = s1  + params->s1Sz / sizeof(*s1);
            t0  = s2  + params->s2Sz / sizeof(*s2);
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a   = t0  + params->s2Sz / sizeof(*s2);
#endif
        }
    }

    if (ret == 0) {
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* Check that we haven't already cached the private vectors. */
        if (!key->privVecsSet)
#endif
        {
            /* Steps 1-4: Decode and NTT vectors s1, s2, and t0. */
            dilithium_make_priv_vecs(key, s1, s2, t0);
        }

#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            /* Step 5: Create the matrix A from the public seed. */
            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            key->aSet = (ret == 0);
#endif
        }
    }
    if (ret == 0) {
        /* Step 9: Compute private random using hash. */
        ret = dilithium_hash256(&key->shake, k, DILITHIUM_K_SZ, seedMu,
            DILITHIUM_RND_SZ + DILITHIUM_MU_SZ, priv_rand_seed,
            DILITHIUM_PRIV_RAND_SEED_SZ);
    }
    if (ret == 0) {
        word16 kappa = 0;
        int valid = 0;

        /* Step 11: Start rejection sampling loop */
        do {
            byte w1e[DILITHIUM_MAX_W1_ENC_SZ];
            sword32* w = w1;
            sword32* y_ntt = z;
            sword32* cs2 = ct0;
            byte* commit = sig;

            /* Step 12: Compute vector y from private random seed and kappa. */
            dilithium_vec_expand_mask(&key->shake, priv_rand_seed, kappa,
                params->gamma1_bits, y, params->l);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_Y
            valid = dilithium_vec_check_low(y, params->l,
                (1 << params->gamma1_bits) - params->beta);
            if (valid)
        #endif
            {
                /* Step 13: NTT-1(A o NTT(y)) */
                XMEMCPY(y_ntt, y, params->s1Sz);
                dilithium_vec_ntt(y_ntt, params->l);
                dilithium_matrix_mul(w, a, y_ntt, params->k, params->l);
                dilithium_vec_invntt(w, params->k);
                /* Step 14, Step 22: Make values positive and decompose. */
                dilithium_vec_make_pos(w, params->k);
                dilithium_vec_decompose(w, params->k, params->gamma2, w0, w1);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_W0
                valid = dilithium_vec_check_low(w0, params->k,
                    params->gamma2 - params->beta);
            }
            if (valid) {
        #endif
                /* Step 15: Encode w1. */
                dilithium_vec_encode_w1(w1, params->k, params->gamma2, w1e);
                /* Step 15: Hash mu and encoded w1.
                 * Step 32: Hash is stored in signature. */
                ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ,
                    w1e, params->w1EncSz, commit, params->lambda / 4);
                if (ret == 0) {
                    /* Step 17: Compute c from first 256 bits of commit. */
                    ret = dilithium_sample_in_ball(params->level, &key->shake,
                        commit, params->lambda / 4, params->tau, c, key->heap);
                }
                if (ret == 0) {
                    sword32 hi;

                    /* Step 18: NTT(c). */
                    dilithium_ntt_small(c);
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_vec_mul(cs2, c, s2, params->k);
                    dilithium_vec_invntt(cs2, params->k);
                    /* Step 22: w0 - cs2 */
                    dilithium_vec_sub(w0, cs2, params->k);
                    dilithium_vec_red(w0, params->k);
                    /* Step 23: Check w0 - cs2 has low enough values. */
                    hi = params->gamma2 - params->beta;
                    valid = dilithium_vec_check_low(w0, params->k, hi);
                    if (valid) {
                        /* Step 19: cs1 = NTT-1(c o s1) */
                        dilithium_vec_mul(z, c, s1, params->l);
                        dilithium_vec_invntt(z, params->l);
                        /* Step 21: z = y + cs1 */
                        dilithium_vec_add(z, y, params->l);
                        dilithium_vec_red(z, params->l);
                        /* Step 23: Check z has low enough values. */
                        hi = (1 << params->gamma1_bits) - params->beta;
                        valid = dilithium_vec_check_low(z, params->l, hi);
                    }
                    if (valid) {
                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_vec_mul(ct0, c, t0, params->k);
                        dilithium_vec_invntt(ct0, params->k);
                        /* Step 27: Check ct0 has low enough values. */
                        hi = params->gamma2;
                        valid = dilithium_vec_check_low(ct0, params->k, hi);
                    }
                    if (valid) {
                        /* Step 26: ct0 = ct0 + w0 */
                        dilithium_vec_add(ct0, w0, params->k);
                        dilithium_vec_red(ct0, params->k);
                        /* Step 26, 27: Make hint from ct0 and w1 and check
                         * number of hints is valid.
                         * Step 32: h is encoded into signature.
                         */
                        valid = (dilithium_make_hint(ct0, w1, params->k,
                            params->gamma2, params->omega, h) >= 0);
                    }
                }
            }

            if (!valid) {
                /* Too many attempts - something wrong with implementation. */
                if ((kappa > (word16)(kappa + params->l))) {
                    ret = BAD_COND_E;
                }

                /* Step 30: increment value to append to seed to unique value.
                 */
                kappa += params->l;
            }
        }
        /* Step 11: Check we have a valid signature. */
        while ((ret == 0) && (!valid));
    }
    if (ret == 0) {
        byte* ze = sig + params->lambda / 4;
        /* Step 32: Encode z into signature.
         * Commit (c) and h already encoded into signature. */
        dilithium_vec_encode_gamma1(z, params->l, params->gamma1_bits, ze);
    }

    XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    const byte* s1p = tr + DILITHIUM_TR_SZ;
    const byte* s2p = s1p + params->s1EncSz;
    const byte* t0p = s2p + params->s2EncSz;
    const byte* mu = seedMu + DILITHIUM_RND_SZ;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t0 = NULL;
    sword32* y = NULL;
    sword32* y_ntt = NULL;
    sword32* w0 = NULL;
    sword32* w1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* ct0 = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
    byte* blocks = NULL;
    byte priv_rand_seed[DILITHIUM_Y_SEED_SZ];
    byte* h = sig + params->lambda / 4 + params->zEncSz;
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    byte maxK = (byte)min(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A,
        params->k);
#endif

    /* Check the signature buffer isn't too small. */
    if ((ret == 0) && (*sigLen < params->sigSz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Return the size of the signature. */
        *sigLen = params->sigSz;
    }

    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        unsigned int allocSz;

        /* y-l, w0-k, w1-k, blocks, c-1, z-1, A-1 */
        allocSz  = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_REJ_NTT_POLY_H_SIZE +
            DILITHIUM_POLY_SIZE +  DILITHIUM_POLY_SIZE + DILITHIUM_POLY_SIZE;
    #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
        allocSz += params->s1Sz + params->s2Sz + params->s2Sz;
    #elif defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
        allocSz += maxK * params->l * DILITHIUM_POLY_SIZE;
    #endif
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        y = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (y == NULL) {
            ret = MEMORY_E;
        }
        else {
            w0     = y  + params->s1Sz / sizeof(*y_ntt);
            w1     = w0 + params->s2Sz / sizeof(*w0);
            blocks = (byte*)(w1 + params->s2Sz / sizeof(*w1));
            c      = (sword32*)(blocks + DILITHIUM_REJ_NTT_POLY_H_SIZE);
            z      = c  + DILITHIUM_N;
            a      = z  + DILITHIUM_N;
            ct0    = z;
    #if defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
            y_ntt  = w0;
            s1     = z;
            s2     = z;
            t0     = z;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(a + (1 + maxK * params->l) * DILITHIUM_N);
        #endif
    #elif defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC)
            y_ntt  = z;
            s1     = a  + DILITHIUM_N;
            s2     = s1 + params->s1Sz / sizeof(*s1);
            t0     = s2 + params->s2Sz / sizeof(*s2);
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(t0 + params->s2Sz / sizeof(*t0));
        #endif
    #else
            y_ntt  = z;
            s1     = z;
            s2     = z;
            t0     = z;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(a + DILITHIUM_N);
        #endif
    #endif
        }
    }

    if (ret == 0) {
        /* Step 9: Compute private random using hash. */
        ret = dilithium_hash256(&key->shake, k, DILITHIUM_K_SZ, seedMu,
            DILITHIUM_RND_SZ + DILITHIUM_MU_SZ, priv_rand_seed,
            DILITHIUM_PRIV_RAND_SEED_SZ);
    }
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
    if (ret == 0) {
        dilithium_make_priv_vecs(key, s1, s2, t0);
    }
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    if (ret == 0) {
        /* Step 5: Create the matrix A from the public seed. */
        ret = dilithium_expand_a(&key->shake, pub_seed, maxK, params->l, a,
            key->heap);
    }
#endif
    if (ret == 0) {
        word16 kappa = 0;
        int valid;

        /* Step 11: Start rejection sampling loop */
        do {
            byte aseed[DILITHIUM_GEN_A_SEED_SZ];
            byte w1e[DILITHIUM_MAX_W1_ENC_SZ];
            sword32* w = w1;
            byte* commit = sig;
            byte r;
            byte s;
            sword32 hi;
            sword32* wt = w;
            sword32* w0t = w0;
            sword32* w1t = w1;
            sword32* at = a;

        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            w0t += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            w1t += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            wt += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            at += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * params->l *
                DILITHIUM_N;
        #endif

            valid = 1;
            /* Step 12: Compute vector y from private random seed and kappa. */
            dilithium_vec_expand_mask(&key->shake, priv_rand_seed, kappa,
                params->gamma1_bits, y, params->l);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_Y
            valid = dilithium_vec_check_low(y, params->l,
                (1 << params->gamma1_bits) - params->beta);
        #endif

        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            /* Step 13: NTT-1(A o NTT(y)) */
            XMEMCPY(y_ntt, y, params->s1Sz);
            dilithium_vec_ntt(y_ntt, params->l);
            dilithium_matrix_mul(w, a, y_ntt, maxK, params->l);
            dilithium_vec_invntt(w, maxK);
            /* Step 14, Step 22: Make values positive and decompose. */
            dilithium_vec_make_pos(w, maxK);
            dilithium_vec_decompose(w, maxK, params->gamma2, w0, w1);
        #endif
            /* Step 5: Create the matrix A from the public seed. */
            /* Copy the seed into a buffer that has space for s and r. */
            XMEMCPY(aseed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            r = WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A;
        #else
            r = 0;
        #endif
            /* Alg 26. Step 1: Loop over first dimension of matrix. */
            for (; (ret == 0) && valid && (r < params->k); r++) {
                unsigned int e;
                sword32* yt = y;
            #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
                sword32* y_ntt_t = z;
            #else
                sword32* y_ntt_t = y_ntt;
            #endif

                /* Put r/i into buffer to be hashed. */
                aseed[DILITHIUM_PUB_SEED_SZ + 1] = r;
                /* Alg 26. Step 2: Loop over second dimension of matrix. */
                for (s = 0; (ret == 0) && (s < params->l); s++) {
                    /* Put s into buffer to be hashed. */
                    aseed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                    /* Alg 26. Step 3: Create polynomial from hashing seed. */
                    ret = dilithium_rej_ntt_poly_ex(&key->shake, aseed, at,
                        blocks);
                    if (ret != 0) {
                        break;
                    }
                    XMEMCPY(y_ntt_t, yt, DILITHIUM_POLY_SIZE);
                    dilithium_ntt(y_ntt_t);
                    /* Matrix multiply. */
                #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                    if (s == 0) {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            wt[e] = dilithium_mont_red((sword64)at[e] *
                                y_ntt_t[e]);
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            wt[e + 0] = dilithium_mont_red((sword64)at[e + 0] *
                                y_ntt_t[e + 0]);
                            wt[e + 1] = dilithium_mont_red((sword64)at[e + 1] *
                                y_ntt_t[e + 1]);
                            wt[e + 2] = dilithium_mont_red((sword64)at[e + 2] *
                                y_ntt_t[e + 2]);
                            wt[e + 3] = dilithium_mont_red((sword64)at[e + 3] *
                                y_ntt_t[e + 3]);
                            wt[e + 4] = dilithium_mont_red((sword64)at[e + 4] *
                                y_ntt_t[e + 4]);
                            wt[e + 5] = dilithium_mont_red((sword64)at[e + 5] *
                                y_ntt_t[e + 5]);
                            wt[e + 6] = dilithium_mont_red((sword64)at[e + 6] *
                                y_ntt_t[e + 6]);
                            wt[e + 7] = dilithium_mont_red((sword64)at[e + 7] *
                                y_ntt_t[e + 7]);
                        }
                    #endif
                    }
                    else {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            wt[e] += dilithium_mont_red((sword64)at[e] *
                                y_ntt_t[e]);
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            wt[e + 0] += dilithium_mont_red((sword64)at[e + 0] *
                                y_ntt_t[e + 0]);
                            wt[e + 1] += dilithium_mont_red((sword64)at[e + 1] *
                                y_ntt_t[e + 1]);
                            wt[e + 2] += dilithium_mont_red((sword64)at[e + 2] *
                                y_ntt_t[e + 2]);
                            wt[e + 3] += dilithium_mont_red((sword64)at[e + 3] *
                                y_ntt_t[e + 3]);
                            wt[e + 4] += dilithium_mont_red((sword64)at[e + 4] *
                                y_ntt_t[e + 4]);
                            wt[e + 5] += dilithium_mont_red((sword64)at[e + 5] *
                                y_ntt_t[e + 5]);
                            wt[e + 6] += dilithium_mont_red((sword64)at[e + 6] *
                                y_ntt_t[e + 6]);
                            wt[e + 7] += dilithium_mont_red((sword64)at[e + 7] *
                                y_ntt_t[e + 7]);
                        }
                    #endif
                    }
                #else
                    if (s == 0) {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            t64[e] = (sword64)at[e] * y_ntt_t[e];
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            t64[e+0] = (sword64)at[e+0] * y_ntt_t[e+0];
                            t64[e+1] = (sword64)at[e+1] * y_ntt_t[e+1];
                            t64[e+2] = (sword64)at[e+2] * y_ntt_t[e+2];
                            t64[e+3] = (sword64)at[e+3] * y_ntt_t[e+3];
                            t64[e+4] = (sword64)at[e+4] * y_ntt_t[e+4];
                            t64[e+5] = (sword64)at[e+5] * y_ntt_t[e+5];
                            t64[e+6] = (sword64)at[e+6] * y_ntt_t[e+6];
                            t64[e+7] = (sword64)at[e+7] * y_ntt_t[e+7];
                        }
                    #endif
                    }
                    else {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            t64[e] += (sword64)at[e] * y_ntt_t[e];
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            t64[e+0] += (sword64)at[e+0] * y_ntt_t[e+0];
                            t64[e+1] += (sword64)at[e+1] * y_ntt_t[e+1];
                            t64[e+2] += (sword64)at[e+2] * y_ntt_t[e+2];
                            t64[e+3] += (sword64)at[e+3] * y_ntt_t[e+3];
                            t64[e+4] += (sword64)at[e+4] * y_ntt_t[e+4];
                            t64[e+5] += (sword64)at[e+5] * y_ntt_t[e+5];
                            t64[e+6] += (sword64)at[e+6] * y_ntt_t[e+6];
                            t64[e+7] += (sword64)at[e+7] * y_ntt_t[e+7];
                        }
                    #endif
                    }
                #endif
                    /* Next polynomial. */
                    yt += DILITHIUM_N;
                }
            #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                for (e = 0; e < DILITHIUM_N; e++) {
                    wt[e] = dilithium_mont_red(t64[e]);
                }
            #endif
                dilithium_invntt(wt);
                /* Step 14, Step 22: Make values positive and decompose. */
                dilithium_make_pos(wt);
            #ifndef WOLFSSL_NO_ML_DSA_44
                if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                    /* For each value of polynomial. */
                    for (e = 0; e < DILITHIUM_N; e++) {
                        /* Decompose value into two vectors. */
                        dilithium_decompose_q88(wt[e], &w0t[e], &w1t[e]);
                    }
                }
            #endif
            #if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
                if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                    /* For each value of polynomial. */
                    for (e = 0; e < DILITHIUM_N; e++) {
                        /* Decompose value into two vectors. */
                        dilithium_decompose_q32(wt[e], &w0t[e], &w1t[e]);
                    }
                }
            #endif
            #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_W0
                valid = dilithium_vec_check_low(w0t,
                    params->gamma2 - params->beta);
            #endif
                wt  += DILITHIUM_N;
                w0t += DILITHIUM_N;
                w1t += DILITHIUM_N;
            }
            if ((ret == 0) && valid) {
                sword32* yt = y;
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                const byte* s1pt = s1p;
            #endif
                byte* ze = sig + params->lambda / 4;

                /* Step 15: Encode w1. */
                dilithium_vec_encode_w1(w1, params->k, params->gamma2, w1e);
                /* Step 15: Hash mu and encoded w1.
                 * Step 32: Hash is stored in signature. */
                ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ,
                    w1e, params->w1EncSz, commit, params->lambda / 4);
                if (ret == 0) {
                    /* Step 17: Compute c from first 256 bits of commit. */
                    ret = dilithium_sample_in_ball_ex(params->level,
                        &key->shake, commit, params->lambda / 4, params->tau, c,
                        blocks);
                }
                if (ret == 0) {
                    /* Step 18: NTT(c). */
                    dilithium_ntt_small(c);
                }

                for (s = 0; (ret == 0) && valid && (s < params->l); s++) {
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                #if !defined(WOLFSSL_NO_ML_DSA_44) || \
                    !defined(WOLFSSL_NO_ML_DSA_87)
                    /* -2..2 */
                    if (params->eta == DILITHIUM_ETA_2) {
                        dilithium_decode_eta_2_bits(s1pt, s1);
                        s1pt += DILITHIUM_ETA_2_BITS * DILITHIUM_N / 8;
                    }
                #endif
                #ifndef WOLFSSL_NO_ML_DSA_65
                    /* -4..4 */
                    if (params->eta == DILITHIUM_ETA_4) {
                        dilithium_decode_eta_4_bits(s1pt, s1);
                        s1pt += DILITHIUM_N / 2;
                    }
                #endif
                    dilithium_ntt_small(s1);
                    dilithium_mul(z, c, s1);
            #else
                    dilithium_mul(z, c, s1 + s * DILITHIUM_N);
            #endif
                    /* Step 19: cs1 = NTT-1(c o s1) */
                    dilithium_invntt(z);
                    /* Step 21: z = y + cs1 */
                    dilithium_add(z, yt);
                    dilithium_poly_red(z);
                    /* Step 23: Check z has low enough values. */
                    hi = (1 << params->gamma1_bits) - params->beta;
                    valid = dilithium_check_low(z, hi);
                    if (valid) {
                        /* Step 32: Encode z into signature.
                         * Commit (c) and h already encoded into signature. */
                    #if !defined(WOLFSSL_NO_ML_DSA_44)
                        if (params->gamma1_bits == DILITHIUM_GAMMA1_BITS_17) {
                            dilithium_encode_gamma1_17_bits(z, ze);
                            /* Move to next place to encode to. */
                            ze += DILITHIUM_GAMMA1_17_ENC_BITS / 2 *
                                  DILITHIUM_N / 4;
                        }
                        else
                    #endif
                    #if !defined(WOLFSSL_NO_ML_DSA_65) || \
                        !defined(WOLFSSL_NO_ML_DSA_87)
                        if (params->gamma1_bits == DILITHIUM_GAMMA1_BITS_19) {
                            dilithium_encode_gamma1_19_bits(z, ze);
                            /* Move to next place to encode to. */
                            ze += DILITHIUM_GAMMA1_19_ENC_BITS / 2 *
                                  DILITHIUM_N / 4;
                        }
                    #endif
                    }

                    yt += DILITHIUM_N;
                }
            }
            if ((ret == 0) && valid) {
                const byte* t0pt = t0p;
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                const byte* s2pt = s2p;
            #endif
                sword32* cs2 = ct0;
                w0t = w0;
                w1t = w1;
                byte idx = 0;

                for (r = 0; valid && (r < params->k); r++) {
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                #if !defined(WOLFSSL_NO_ML_DSA_44) || \
                    !defined(WOLFSSL_NO_ML_DSA_87)
                    /* -2..2 */
                    if (params->eta == DILITHIUM_ETA_2) {
                        dilithium_decode_eta_2_bits(s2pt, s2);
                        s2pt += DILITHIUM_ETA_2_BITS * DILITHIUM_N / 8;
                    }
                #endif
                #ifndef WOLFSSL_NO_ML_DSA_65
                    /* -4..4 */
                    if (params->eta == DILITHIUM_ETA_4) {
                        dilithium_decode_eta_4_bits(s2pt, s2);
                        s2pt += DILITHIUM_N / 2;
                    }
                #endif
                    dilithium_ntt_small(s2);
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_mul(cs2, c, s2);
            #else
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_mul(cs2, c, s2 + r * DILITHIUM_N);
            #endif
                    dilithium_invntt(cs2);
                    /* Step 22: w0 - cs2 */
                    dilithium_sub(w0t, cs2);
                    dilithium_poly_red(w0t);
                    /* Step 23: Check w0 - cs2 has low enough values. */
                    hi = params->gamma2 - params->beta;
                    valid = dilithium_check_low(w0t, hi);
                    if (valid) {
                    #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                        dilithium_decode_t0(t0pt, t0);
                        dilithium_ntt(t0);

                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_mul(ct0, c, t0);
                    #else
                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_mul(ct0, c, t0 + r * DILITHIUM_N);
                    #endif
                        dilithium_invntt(ct0);
                        /* Step 27: Check ct0 has low enough values. */
                        valid = dilithium_check_low(ct0, params->gamma2);
                    }
                    if (valid) {
                        /* Step 26: ct0 = ct0 + w0 */
                        dilithium_add(ct0, w0t);
                        dilithium_poly_red(ct0);

                        /* Step 26, 27: Make hint from ct0 and w1 and check
                         * number of hints is valid.
                         * Step 32: h is encoded into signature.
                         */
                    #ifndef WOLFSSL_NO_ML_DSA_44
                        if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                            valid = (dilithium_make_hint_88(ct0, w1t, h,
                                &idx) == 0);
                            /* Alg 14, Step 10: Store count of hints for
                             *                  polynomial at end of list. */
                            h[PARAMS_ML_DSA_44_OMEGA + r] = idx;
                        }
                    #endif
                    #if !defined(WOLFSSL_NO_ML_DSA_65) || \
                        !defined(WOLFSSL_NO_ML_DSA_87)
                        if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                            valid = (dilithium_make_hint_32(ct0, w1t,
                                params->omega, h, &idx) == 0);
                            /* Alg 14, Step 10: Store count of hints for
                             *                  polynomial at end of list. */
                            h[params->omega + r] = idx;
                        }
                    #endif
                    }

                    t0pt += DILITHIUM_D * DILITHIUM_N / 8;
                    w0t += DILITHIUM_N;
                    w1t += DILITHIUM_N;
                }
                /* Set remaining hints to zero. */
                XMEMSET(h + idx, 0, params->omega - idx);
            }

            if (!valid) {
                /* Too many attempts - something wrong with implementation. */
                if ((kappa > (word16)(kappa + params->l))) {
                    ret = BAD_COND_E;
                }

                /* Step 30: increment value to append to seed to unique value.
                 */
                kappa += params->l;
            }
        }
        /* Step 11: Check we have a valid signature. */
        while ((ret == 0) && (!valid));
    }

    XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#endif
}

/* Sign a message with the key and a seed.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.Sign(sk, M, ctx)
 *   ...
 *  10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx || M)
 *  11: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
 *  12: return sigma
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.SignInternal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64)
 *   ...
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      seed    Random seed.
 * @param [in]      ctx     Context of signature.
 * @param [in]      ctxLen  Length of context in bytes.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when context length is greater than 255.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_ctx_msg_with_seed(dilithium_key* key,
    const byte* seed, const byte* ctx, byte ctxLen, const byte* msg,
    word32 msgLen, byte* sig, word32 *sigLen)
{
    int ret;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    byte seedMu[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = seedMu + DILITHIUM_RND_SZ;

    XMEMCPY(seedMu, seed, DILITHIUM_RND_SZ);
    /* Step 6. Calculate mu. */
    ret = dilithium_hash256_ctx_msg(&key->shake, tr, DILITHIUM_TR_SZ, 0,
        ctx, ctxLen, msg, msgLen, mu, DILITHIUM_MU_SZ);
    if (ret == 0) {
        ret = dilithium_sign_with_seed_mu(key, seedMu, sig, sigLen);
    }

    return ret;
}

/* Sign a message with the key and a seed.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.Sign(sk, M, ctx)
 *   ...
 *  10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx || M)
 *  11: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
 *  12: return sigma
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.SignInternal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64)
 *   ...
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      seed    Random seed.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when context length is greater than 255.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_msg_with_seed(dilithium_key* key, const byte* seed,
    const byte* msg, word32 msgLen, byte* sig, word32 *sigLen)
{
    int ret;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    byte seedMu[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = seedMu + DILITHIUM_RND_SZ;

    XMEMCPY(seedMu, seed, DILITHIUM_RND_SZ);
    /* Step 6. Calculate mu. */
    ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen, mu,
        DILITHIUM_MU_SZ);
    if (ret == 0) {
        ret = dilithium_sign_with_seed_mu(key, seedMu, sig, sigLen);
    }

    return ret;
}

/* Sign a message with the key and a random number generator.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.Sign(sk, M, ctx)
 *   ...
 *   5: rnd <- B32  [Randomly generated.]
 *   6: if rnd = NULL then
 *   7:     return falsam
 *   8: end if
 *   9:
 *  10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx || M)
 *   ...
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.SignInternal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64)
 *   ...
 *
 * @param [in, out] key     Dilithium key.
 * @param [in, out] rng     Random number generator.
 * @param [in]      ctx     Context of signature.
 * @param [in]      ctxLen  Length of context.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_ctx_msg(dilithium_key* key, WC_RNG* rng,
    const byte* ctx, byte ctxLen, const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen)
{
    int ret = 0;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    byte seedMu[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = seedMu + DILITHIUM_RND_SZ;

    /* Must have a random number generator. */
    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 7: Generate random seed. */
        ret = wc_RNG_GenerateBlock(rng, seedMu, DILITHIUM_RND_SZ);
    }
    if (ret == 0) {
        /* Step 6. Calculate mu. */
        ret = dilithium_hash256_ctx_msg(&key->shake, tr, DILITHIUM_TR_SZ, 0,
            ctx, ctxLen, msg, msgLen, mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_sign_with_seed_mu(key, seedMu, sig, sigLen);
    }

    return ret;
}

/* Sign a message with the key and a random number generator.
 *
 * FIPS 204. 5.2: Algorithm 2 ML-DSA.Sign(sk, M, ctx)
 *   ...
 *   5: rnd <- B32  [Randomly generated.]
 *   6: if rnd = NULL then
 *   7:     return falsam
 *   8: end if
 *   9:
 *  10: M' <- BytesToBits(IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx || M)
 *   ...
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.SignInternal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64)
 *   ...
 *
 * @param [in, out] key     Dilithium key.
 * @param [in, out] rng     Random number generator.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_msg(dilithium_key* key, WC_RNG* rng,
    const byte* msg, word32 msgLen, byte* sig, word32 *sigLen)
{
    int ret = 0;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    byte seedMu[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = seedMu + DILITHIUM_RND_SZ;

    /* Must have a random number generator. */
    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 7: Generate random seed. */
        ret = wc_RNG_GenerateBlock(rng, seedMu, DILITHIUM_RND_SZ);
    }
    if (ret == 0) {
        /* Step 6. Calculate mu. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_sign_with_seed_mu(key, seedMu, sig, sigLen);
    }

    return ret;
}

/* Sign a pre-hashed message with the key and a seed.
 *
 * FIPS 204. 5.4.1: Algorithm 4 HashML-DSA.Sign(sk, M, ctx, PH)
 *   ...
 *  10: switch PH do
 *  11:    case SHA-256:
 *  12:       OID <-  IntegerToBytes(0x0609608648016503040201, 11)
 *  13:       PHm <- SHA256(M)    (not done here as hash is passed in)
 *   ...
 *  22: end switch
 *  23: M' <- BytesToBits(IntegerToBytes(1, 1) || IntegerToBytes(|ctx|, 1) ||
 *                        ctx || OID || PHm)
 *  24: sigma <- ML-DSA.Sign_internal(sk, M', rnd)
 *  25: return sigma
 *
 * FIPS 204. 6.2: Algorithm 7 ML-DSA.SignInternal(sk, M', rnd)
 *   ...
 *   6: mu <- H(BytesToBits(tr)||M', 64)
 *   ...
 *
 * @param [in, out] key      Dilithium key.
 * @param [in]      seed     Random seed.
 * @param [in]      ctx      Context of signature.
 * @param [in]      ctxLen   Length of context.
 * @param [in]      hashAlg  Hash algorithm used on message.
 * @param [in]      hash     Message hash to sign.
 * @param [in]      hashLen  Length of message hash in bytes.
 * @param [out]     sig      Buffer to hold signature.
 * @param [in, out] sigLen   On in, length of buffer in bytes.
 *                           On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_ctx_hash_with_seed(dilithium_key* key,
    const byte* seed, const byte* ctx, byte ctxLen, int hashAlg,
    const byte* hash, word32 hashLen, byte* sig, word32 *sigLen)
{
    int ret = 0;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    byte seedMu[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = seedMu + DILITHIUM_RND_SZ;
    byte oidMsgHash[DILITHIUM_HASH_OID_LEN + WC_MAX_DIGEST_SIZE];
    word32 oidMsgHashLen;

    if ((ret == 0) && (hashLen > WC_MAX_DIGEST_SIZE)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(seedMu, seed, DILITHIUM_RND_SZ);

        ret = dilithium_get_hash_oid(hashAlg, oidMsgHash, &oidMsgHashLen);
    }
    if (ret == 0) {
        XMEMCPY(oidMsgHash + oidMsgHashLen, hash, hashLen);
        oidMsgHashLen += hashLen;

        /* Step 6. Calculate mu. */
        ret = dilithium_hash256_ctx_msg(&key->shake, tr, DILITHIUM_TR_SZ, 1,
            ctx, ctxLen, oidMsgHash, oidMsgHashLen, mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_sign_with_seed_mu(key, seedMu, sig, sigLen);
    }

    return ret;
}

/* Sign a pre-hashed message with the key and a random number generator.
 *
 * FIPS 204. 5.4.1: Algorithm 4 HashML-DSA.Sign(sk, M, ctx, PH)
 *   ...
 *   5: rnd <- B32  [Randomly generated.]
 *   6: if rnd = NULL then
 *   7:     return falsam
 *   8: end if
 *   ...
 *
 * @param [in, out] key      Dilithium key.
 * @param [in, out] rng      Random number generator.
 * @param [in]      ctx      Context of signature.
 * @param [in]      ctxLen   Length of context.
 * @param [in]      hashAlg  Hash algorithm used on message.
 * @param [in]      hash     Message hash to sign.
 * @param [in]      hashLen  Length of message hash in bytes.
 * @param [out]     sig      Buffer to hold signature.
 * @param [in, out] sigLen   On in, length of buffer in bytes.
 *                           On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_sign_ctx_hash(dilithium_key* key, WC_RNG* rng,
    const byte* ctx, byte ctxLen, int hashAlg, const byte* hash, word32 hashLen,
    byte* sig, word32 *sigLen)
{
    int ret = 0;
    byte seed[DILITHIUM_RND_SZ];

    /* Must have a random number generator. */
    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Step 7: Generate random seed. */
        ret = wc_RNG_GenerateBlock(rng, seed, DILITHIUM_RND_SZ);
    }

    if (ret == 0) {
        ret = dilithium_sign_ctx_hash_with_seed(key, seed, ctx, ctxLen, hashAlg,
            hash, hashLen, sig, sigLen);
    }

    return ret;
}

#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY

#if !defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM) || \
     defined(WC_DILITHIUM_CACHE_PUB_VECTORS)
/* Make public vector from public key data.
 *
 * @param [in, out] key  Key with public key data.
 * @param [out]     t1   Vector in NTT form.
 */
static void dilithium_make_pub_vec(dilithium_key* key, sword32* t1)
{
    const wc_dilithium_params* params = key->params;
    const byte* t1p = key->p + DILITHIUM_PUB_SEED_SZ;

    dilithium_vec_decode_t1(t1p, params->k, t1);
    dilithium_vec_ntt(t1, params->k);

#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    key->pubVecSet = 1;
#endif
}
#endif

/* Verify signature of message using public key.
 *
 * FIPS 204. 6: Algorithm 3 ML-DSA.Verify(pk, M, sigma)
 *  1: (rho, t1) <- pkDecode(pk)
 *  2: (c_tilde, z, h) <- sigDecode(sigma)
 *  3: if h = falsam then return false
 *  4: end if
 *  5: A_circum <- ExpandS(rho)
 *  6: tr <- H(BytesToBits(pk), 512)
 *  7: mu <- H(tr||M, 512)
 *  8: (c1_tilde, c2_tilde) E {0,1}256 x {0,1)2*lambda-256 <- c_tilde
 *  9: c <- SampleInBall(c1_tilde)
 * 10: w'approx <- NTT-1(A_circum o NTT(z) - NTT(c) o NTT(t1.2^d))
 * 11: w1' <- UseHint(h, w'approx)
 * 12: c'_tilde < H(mu||w1Encode(w1'), 2*lambda)
 * 13: return [[ ||z||inf < GAMMA1 - BETA]] and [[c_tilde = c'_tilde]] and
 *             [[number of 1's in h is <= OMEGA
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      mu      Data to verify.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_verify_mu(dilithium_key* key, const byte* mu,
    const byte* sig, word32 sigLen, int* res)
{
#ifndef WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->p;
    const byte* commit = sig;
    const byte* ze = sig + params->lambda / 4;
    const byte* h = ze + params->zEncSz;
    sword32* a = NULL;
    sword32* t1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* w = NULL;
    sword32* t1c = NULL;
    byte commit_calc[DILITHIUM_TR_SZ];
    byte* w1e = NULL;
    int valid = 0;
    sword32 hi;

    /* Ensure the signature is the right size for the parameters. */
    if (sigLen != params->sigSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Step 13: Verify the hint is well-formed. */
        ret = dilithium_check_hint(h, params->k, params->omega);
    }

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->a == NULL)) {
        key->a = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->t1 == NULL)) {
        key->t1 = (sword32*)XMALLOC(params->s2Sz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->t1 == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        t1 = key->t1;
    }
#endif
    if (ret == 0) {
        unsigned int allocSz;

        /* z, c, w, t1/t1c */
        allocSz = DILITHIUM_POLY_SIZE + params->s1Sz + params->s2Sz +
            params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        /* a */
        allocSz += params->aSz;
#endif

        z = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (z == NULL) {
            ret = MEMORY_E;
        }
        else {
            c   = z  + params->s1Sz / sizeof(*z);
            w   = c  + DILITHIUM_N;
#ifndef WC_DILITHIUM_CACHE_PUB_VECTORS
            t1  = w  + params->s2Sz / sizeof(*w);
            t1c = t1;
#else
            t1c = w  + params->s2Sz / sizeof(*w);
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a   = t1 + params->s2Sz / sizeof(*t1);
#endif
            w1e = (byte*)c;
        }
    }

    if (ret == 0) {
        /* Step 2: Decode z from signature. */
        dilithium_vec_decode_gamma1(ze, params->l, params->gamma1_bits, z);
        /* Step 13: Check z is valid - values are low enough. */
        hi = (1 << params->gamma1_bits) - params->beta;
        valid = dilithium_vec_check_low(z, params->l, hi);
    }
    if ((ret == 0) && valid) {
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        /* Check that we haven't already cached the public vector. */
        if (!key->pubVecSet)
#endif
        {
            /* Step 1: Decode and NTT vector t1. */
            dilithium_make_pub_vec(key, t1);
        }

#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            /* Step 5: Expand pub seed to compute matrix A. */
            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            /* Whether we have cached A is dependent on success of operation. */
            key->aSet = (ret == 0);
#endif
        }
    }
    if ((ret == 0) && valid) {
        /* Step 9: Compute c from commit. */
        ret = dilithium_sample_in_ball(params->level, &key->shake, commit,
            params->lambda / 4, params->tau, c, key->heap);
    }
    if ((ret == 0) && valid) {
        /* Step 10: w = NTT-1(A o NTT(z) - NTT(c) o NTT(t1)) */
        dilithium_vec_ntt(z, params->l);
        dilithium_matrix_mul(w, a, z, params->k, params->l);
        dilithium_ntt_small(c);
        dilithium_vec_mul(t1c, c, t1, params->k);
        dilithium_vec_sub(w, t1c, params->k);
        dilithium_vec_invntt(w, params->k);
        /* Step 11: Use hint to give full w1. */
        dilithium_vec_use_hint(w, params->k, params->gamma2, params->omega, h);
        /* Step 12: Encode w1. */
        dilithium_vec_encode_w1(w, params->k, params->gamma2, w1e);
        /* Step 12: Hash mu and encoded w1. */
        ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ, w1e,
            params->w1EncSz, commit_calc, params->lambda / 4);
    }
    if ((ret == 0) && valid) {
        /* Step 13: Compare commit. */
        valid = (XMEMCMP(commit, commit_calc, params->lambda / 4) == 0);
    }

    *res = valid;
    XFREE(z, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->p;
    const byte* t1p = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* commit = sig;
    const byte* ze = sig + params->lambda / 4;
    const byte* h = ze + params->zEncSz;
    sword32* t1 = NULL;
    sword32* a = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* w = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    byte*    block = NULL;
#endif
    byte* w1e = NULL;
    byte commit_calc[DILITHIUM_TR_SZ];
    int valid = 0;
    sword32 hi;
    unsigned int r;
    byte o;
    byte* encW1;
    byte* seed = commit_calc;

    /* Ensure the signature is the right size for the parameters. */
    if (sigLen != params->sigSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Step 13: Verify the hint is well-formed. */
        ret = dilithium_check_hint(h, params->k, params->omega);
    }

#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        /* z, c, w, t1, w1e. */
        unsigned int allocSz;

        allocSz  = params->s1Sz + 3 * DILITHIUM_POLY_SIZE +
            DILITHIUM_REJ_NTT_POLY_H_SIZE + params->w1EncSz;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        z = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (z == NULL) {
            ret = MEMORY_E;
        }
        else {
            c     = z + params->s1Sz / sizeof(*t1);
            w     = c + DILITHIUM_N;
            t1    = w + DILITHIUM_N;
            block = (byte*)(t1 + DILITHIUM_N);
            w1e   = block + DILITHIUM_REJ_NTT_POLY_H_SIZE;
            a     = t1;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64   = (sword64*)(w1e + params->w1EncSz);
        #endif
        }
    }
#else
    if (ret == 0) {
        z = key->z;
        c = key->c;
        w = key->w;
        t1 = key->t1;
        w1e = key->w1e;
        a = t1;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        t64 = key->t64;
    #endif
    }
#endif

    if (ret == 0) {
        /* Step 2: Decode z from signature. */
        dilithium_vec_decode_gamma1(ze, params->l, params->gamma1_bits, z);
        /* Step 13: Check z is valid - values are low enough. */
        hi = (1 << params->gamma1_bits) - params->beta;
        valid = dilithium_vec_check_low(z, params->l, hi);
    }
    if ((ret == 0) && valid) {
        /* Step 10: NTT(z) */
        dilithium_vec_ntt(z, params->l);

         /* Step 9: Compute c from first 256 bits of commit. */
#ifdef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
         ret = dilithium_sample_in_ball_ex(params->level, &key->shake, commit,
             params->lambda / 4, params->tau, c, key->block);
#else
         ret = dilithium_sample_in_ball_ex(params->level, &key->shake, commit,
             params->lambda / 4, params->tau, c, block);
#endif
    }
    if ((ret == 0) && valid) {
        dilithium_ntt_small(c);

        o = 0;
        encW1 = w1e;

        /* Copy the seed into a buffer that has space for s and r. */
        XMEMCPY(seed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        /* Step 1: Loop over first dimension of matrix. */
        for (r = 0; (ret == 0) && (r < params->k); r++) {
            unsigned int s;
            unsigned int e;
            const sword32* zt = z;

            /* Step 1: Decode and NTT vector t1. */
            dilithium_decode_t1(t1p, w);
            /* Next polynomial. */
            t1p += DILITHIUM_U * DILITHIUM_N / 8;

            /* Step 10: - NTT(c) o NTT(t1)) */
            dilithium_ntt(w);
    #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        #ifdef WOLFSSL_DILITHIUM_SMALL
            for (e = 0; e < DILITHIUM_N; e++) {
                w[e] = -dilithium_mont_red((sword64)c[e] * w[e]);
            }
        #else
            for (e = 0; e < DILITHIUM_N; e += 8) {
                w[e+0] = -dilithium_mont_red((sword64)c[e+0] * w[e+0]);
                w[e+1] = -dilithium_mont_red((sword64)c[e+1] * w[e+1]);
                w[e+2] = -dilithium_mont_red((sword64)c[e+2] * w[e+2]);
                w[e+3] = -dilithium_mont_red((sword64)c[e+3] * w[e+3]);
                w[e+4] = -dilithium_mont_red((sword64)c[e+4] * w[e+4]);
                w[e+5] = -dilithium_mont_red((sword64)c[e+5] * w[e+5]);
                w[e+6] = -dilithium_mont_red((sword64)c[e+6] * w[e+6]);
                w[e+7] = -dilithium_mont_red((sword64)c[e+7] * w[e+7]);
            }
        #endif
    #else
        #ifdef WOLFSSL_DILITHIUM_SMALL
            for (e = 0; e < DILITHIUM_N; e++) {
                t64[e] = -(sword64)c[e] * w[e];
            }
        #else
            for (e = 0; e < DILITHIUM_N; e += 8) {
                t64[e+0] = -(sword64)c[e+0] * w[e+0];
                t64[e+1] = -(sword64)c[e+1] * w[e+1];
                t64[e+2] = -(sword64)c[e+2] * w[e+2];
                t64[e+3] = -(sword64)c[e+3] * w[e+3];
                t64[e+4] = -(sword64)c[e+4] * w[e+4];
                t64[e+5] = -(sword64)c[e+5] * w[e+5];
                t64[e+6] = -(sword64)c[e+6] * w[e+6];
                t64[e+7] = -(sword64)c[e+7] * w[e+7];
            }
        #endif
    #endif

            /* Step 5: Expand pub seed to compute matrix A. */
            /* Put r into buffer to be hashed. */
            seed[DILITHIUM_PUB_SEED_SZ + 1] = r;
            for (s = 0; (ret == 0) && (s < params->l); s++) {
                /* Put s into buffer to be hashed. */
                seed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                /* Step 3: Create polynomial from hashing seed. */
            #ifdef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
                ret = dilithium_rej_ntt_poly_ex(&key->shake, seed, a, key->h);
            #else
                ret = dilithium_rej_ntt_poly_ex(&key->shake, seed, a, block);
            #endif

                /* Step 10: w = A o NTT(z) - NTT(c) o NTT(t1) */
        #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            #ifdef WOLFSSL_DILITHIUM_SMALL
                for (e = 0; e < DILITHIUM_N; e++) {
                    w[e] += dilithium_mont_red((sword64)a[e] * zt[e]);
                }
            #else
                for (e = 0; e < DILITHIUM_N; e += 8) {
                    w[e+0] += dilithium_mont_red((sword64)a[e+0] * zt[e+0]);
                    w[e+1] += dilithium_mont_red((sword64)a[e+1] * zt[e+1]);
                    w[e+2] += dilithium_mont_red((sword64)a[e+2] * zt[e+2]);
                    w[e+3] += dilithium_mont_red((sword64)a[e+3] * zt[e+3]);
                    w[e+4] += dilithium_mont_red((sword64)a[e+4] * zt[e+4]);
                    w[e+5] += dilithium_mont_red((sword64)a[e+5] * zt[e+5]);
                    w[e+6] += dilithium_mont_red((sword64)a[e+6] * zt[e+6]);
                    w[e+7] += dilithium_mont_red((sword64)a[e+7] * zt[e+7]);
                }
            #endif
        #else
            #ifdef WOLFSSL_DILITHIUM_SMALL
                for (e = 0; e < DILITHIUM_N; e++) {
                    t64[e] += (sword64)a[e] * zt[e];
                }
            #else
                for (e = 0; e < DILITHIUM_N; e += 8) {
                    t64[e+0] += (sword64)a[e+0] * zt[e+0];
                    t64[e+1] += (sword64)a[e+1] * zt[e+1];
                    t64[e+2] += (sword64)a[e+2] * zt[e+2];
                    t64[e+3] += (sword64)a[e+3] * zt[e+3];
                    t64[e+4] += (sword64)a[e+4] * zt[e+4];
                    t64[e+5] += (sword64)a[e+5] * zt[e+5];
                    t64[e+6] += (sword64)a[e+6] * zt[e+6];
                    t64[e+7] += (sword64)a[e+7] * zt[e+7];
                }
            #endif
        #endif
                /* Next polynomial. */
                zt += DILITHIUM_N;
            }
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            for (e = 0; e < DILITHIUM_N; e++) {
                w[e] = dilithium_mont_red(t64[e]);
            }
        #endif

            /* Step 10: w = NTT-1(A o NTT(z) - NTT(c) o NTT(t1)) */
            dilithium_invntt(w);

        #ifndef WOLFSSL_NO_ML_DSA_44
            if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                /* Step 11: Use hint to give full w1. */
                dilithium_use_hint_88(w, h, r, &o);
                /* Step 12: Encode w1. */
                dilithium_encode_w1_88(w, encW1);
                encW1 += DILITHIUM_Q_HI_88_ENC_BITS * 2 * DILITHIUM_N / 16;
            }
            else
        #endif
        #if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
            if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                /* Step 11: Use hint to give full w1. */
                dilithium_use_hint_32(w, h, params->omega, r, &o);
                /* Step 12: Encode w1. */
                dilithium_encode_w1_32(w, encW1);
                encW1 += DILITHIUM_Q_HI_32_ENC_BITS * 2 * DILITHIUM_N / 16;
            }
            else
        #endif
            {
            }
        }
    }
    if ((ret == 0) && valid) {
        /* Step 12: Hash mu and encoded w1. */
        ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ, w1e,
            params->w1EncSz, commit_calc, params->lambda / 4);
    }
    if ((ret == 0) && valid) {
        /* Step 13: Compare commit. */
        valid = (XMEMCMP(commit, commit_calc, params->lambda / 4) == 0);
    }

    *res = valid;
#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    XFREE(z, key->heap, DYNAMIC_TYPE_DILITHIUM);
#endif
    return ret;
#endif /* !WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM */
}

/* Verify signature of message using public key.
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      ctx     Context of verification.
 * @param [in]      ctxLen  Length of context in bytes.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_verify_ctx_msg(dilithium_key* key, const byte* ctx,
    word32 ctxLen, const byte* msg, word32 msgLen, const byte* sig,
    word32 sigLen, int* res)
{
    int ret = 0;
    byte tr[DILITHIUM_TR_SZ];
    byte* mu = tr;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 6: Hash public key. */
        ret = dilithium_shake256(&key->shake, key->p, key->params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Step 6. Calculate mu. */
        ret = dilithium_hash256_ctx_msg(&key->shake, tr, DILITHIUM_TR_SZ, 0,
            ctx, ctxLen, msg, msgLen, mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_verify_mu(key, mu, sig, sigLen, res);
    }

    return ret;
}

/* Verify signature of message using public key.
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_verify_msg(dilithium_key* key, const byte* msg,
    word32 msgLen, const byte* sig, word32 sigLen, int* res)
{
    int ret = 0;
    byte tr[DILITHIUM_TR_SZ];
    byte* mu = tr;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 6: Hash public key. */
        ret = dilithium_shake256(&key->shake, key->p, key->params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Step 6. Calculate mu. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_verify_mu(key, mu, sig, sigLen, res);
    }

    return ret;
}

/* Verify signature of message using public key.
 *
 * @param [in, out] key       Dilithium key.
 * @param [in]      ctx       Context of verification.
 * @param [in]      ctxLen    Length of context in bytes.
 * @param [iu]      hashAlg   Hash algorithm used on message.
 * @param [in]      hash      Hash of message to verify.
 * @param [in]      hashLen   Length of message hash in bytes.
 * @param [in]      sig       Signature to verify message.
 * @param [in]      sigLen    Length of message in bytes.
 * @param [out]     res       Result of verification.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int dilithium_verify_ctx_hash(dilithium_key* key, const byte* ctx,
    word32 ctxLen, int hashAlg, const byte* hash, word32 hashLen,
    const byte* sig, word32 sigLen, int* res)
{
    int ret = 0;
    byte tr[DILITHIUM_TR_SZ];
    byte* mu = tr;
    byte oidMsgHash[DILITHIUM_HASH_OID_LEN + WC_MAX_DIGEST_SIZE];
    word32 oidMsgHashLen;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 6: Hash public key. */
        ret = dilithium_shake256(&key->shake, key->p, key->params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        ret = dilithium_get_hash_oid(hashAlg, oidMsgHash, &oidMsgHashLen);
    }
    if (ret == 0) {
        XMEMCPY(oidMsgHash + oidMsgHashLen, hash, hashLen);
        oidMsgHashLen += hashLen;

        /* Step 6. Calculate mu. */
        ret = dilithium_hash256_ctx_msg(&key->shake, tr, DILITHIUM_TR_SZ, 1,
            ctx, ctxLen, oidMsgHash, oidMsgHashLen, mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        ret = dilithium_verify_mu(key, mu, sig, sigLen, res);
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_NO_VERIFY */

#elif defined(HAVE_LIBOQS)

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
static int oqs_dilithium_make_key(dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;
    OQS_SIG *oqssig = NULL;

    if (key->level == WC_ML_DSA_44) {
        oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44_ipd);
    }
    else if (key->level == WC_ML_DSA_65) {
        oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65_ipd);
    }
    else if (key->level == WC_ML_DSA_87) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87_ipd);
    }
    else {
        ret = SIG_TYPE_E;
    }

    if (ret == 0) {
        ret = wolfSSL_liboqsRngMutexLock(rng);
        if (ret == 0) {
            if (OQS_SIG_keypair(oqssig, key->p, key->k) != OQS_SUCCESS) {
                ret = BUFFER_E;
            }
        }
        wolfSSL_liboqsRngMutexUnlock();
    }
    if (ret == 0) {
        key->prvKeySet = 1;
        key->pubKeySet = 1;
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_NO_MAKE_KEY */

#ifndef WOLFSSL_DILITHIUM_NO_SIGN
static int oqs_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;
    OQS_SIG *oqssig = NULL;
    size_t localOutLen = 0;

    if (!key->prvKeySet) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == WC_ML_DSA_44) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44_ipd);
        }
        else if (key->level == WC_ML_DSA_65) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65_ipd);
        }
        else if (key->level == WC_ML_DSA_87) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87_ipd);
        }
        else {
            ret = SIG_TYPE_E;
        }
    }

    if ((ret == 0) && (oqssig == NULL)) {
        ret = BUFFER_E;
    }

    /* check and set up out length */
    if (ret == 0) {
        if ((key->level == WC_ML_DSA_44) &&
                (*sigLen < ML_DSA_LEVEL2_SIG_SIZE)) {
            *sigLen = ML_DSA_LEVEL2_SIG_SIZE;
            ret = BUFFER_E;
        }
        else if ((key->level == WC_ML_DSA_65) &&
                 (*sigLen < ML_DSA_LEVEL3_SIG_SIZE)) {
            *sigLen = ML_DSA_LEVEL3_SIG_SIZE;
            ret = BUFFER_E;
        }
        else if ((key->level == WC_ML_DSA_87) &&
                 (*sigLen < ML_DSA_LEVEL5_SIG_SIZE)) {
            *sigLen = ML_DSA_LEVEL5_SIG_SIZE;
            ret = BUFFER_E;
        }
        localOutLen = *sigLen;
    }

    if (ret == 0) {
        ret = wolfSSL_liboqsRngMutexLock(rng);
    }

    if ((ret == 0) &&
        (OQS_SIG_sign(oqssig, sig, &localOutLen, msg, msgLen, key->k)
         == OQS_ERROR)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        *sigLen = (word32)localOutLen;
    }

    wolfSSL_liboqsRngMutexUnlock();

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }
    return ret;
}
#endif

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY
static int oqs_dilithium_verify_msg(const byte* sig, word32 sigLen,
    const byte* msg, word32 msgLen, int* res, dilithium_key* key)
{
    int ret = 0;
    OQS_SIG *oqssig = NULL;

    if (!key->pubKeySet) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (key->level == WC_ML_DSA_44) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44_ipd);
        }
        else if (key->level == WC_ML_DSA_65) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65_ipd);
        }
        else if (key->level == WC_ML_DSA_87) {
            oqssig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87_ipd);
        }
        else {
            ret = SIG_TYPE_E;
        }
    }

    if ((ret == 0) && (oqssig == NULL)) {
        ret = BUFFER_E;
    }

    if ((ret == 0) &&
        (OQS_SIG_verify(oqssig, msg, msgLen, sig, sigLen, key->p)
         == OQS_ERROR)) {
         ret = SIG_VERIFY_E;
    }

    if (ret == 0) {
        *res = 1;
    }

    if (oqssig != NULL) {
        OQS_SIG_free(oqssig);
    }
    return ret;
}
#endif /* WOLFSSL_DILITHIUM_NO_VERIFY */

#else
    #error "No dilithium implementation chosen."
#endif

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
int wc_dilithium_make_key(dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
    #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
    #endif
        {
            ret = wc_CryptoCb_MakePqcSignatureKey(rng,
                WC_PQC_SIG_TYPE_DILITHIUM, key->level, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
#endif

    if (ret == 0) {
#ifdef WOLFSSL_WC_DILITHIUM
        /* Check the level or parameters have been set. */
        if (key->params == NULL) {
            ret = BAD_STATE_E;
        }
        else {
            /* Make the key. */
            ret = dilithium_make_key(key, rng);
        }
#elif defined(HAVE_LIBOQS)
        /* Make the key. */
        ret = oqs_dilithium_make_key(key, rng);
#endif
    }

    return ret;
}

int wc_dilithium_make_key_from_seed(dilithium_key* key, const byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (seed == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
#ifdef WOLFSSL_WC_DILITHIUM
        /* Check the level or parameters have been set. */
        if (key->params == NULL) {
            ret = BAD_STATE_E;
        }
        else {
            /* Make the key. */
            ret = dilithium_make_key_from_seed(key, seed);
        }
#elif defined(HAVE_LIBOQS)
        /* Make the key. */
        ret = NOT_COMPILED_IN;
#endif
    }

    return ret;
}
#endif

#ifndef WOLFSSL_DILITHIUM_NO_SIGN
/* Sign the message using the dilithium private key.
 *
 *  ctx         [in]      Context of signature.
 *  ctxLen      [in]      Length of context in bytes.
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_ctx_msg(const byte* ctx, byte ctxLen, const byte* msg,
    word32 msgLen, byte* sig, word32 *sigLen, dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
    #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
    #endif
        {
            ret = wc_CryptoCb_PqcSign(msg, msgLen, sig, sigLen, rng,
                WC_PQC_SIG_TYPE_DILITHIUM, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
#endif

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_ctx_msg(key, rng, ctx, ctxLen, msg, msgLen, sig,
            sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = oqs_dilithium_sign_msg(msg, msgLen, sig, sigLen, key, rng);
    #endif
    }

    return ret;
}

/* Sign the message using the dilithium private key.
 *
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL or public key not set,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
    #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
    #endif
        {
            ret = wc_CryptoCb_PqcSign(msg, msgLen, sig, sigLen, rng,
                WC_PQC_SIG_TYPE_DILITHIUM, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
#endif

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_msg(key, rng, msg, msgLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = oqs_dilithium_sign_msg(msg, msgLen, sig, sigLen, key, rng);
    #endif
    }

    return ret;
}

/* Sign the message hash using the dilithium private key.
 *
 *  ctx         [in]      Context of signature.
 *  ctxLen      [in]      Length of context in bytes.
 *  hashAlg     [in]      Hash algorithm used on message.
 *  hash        [in]      Hash of message to sign.
 *  hashLen     [in]      Length of the message hash in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_ctx_hash(const byte* ctx, byte ctxLen, int hashAlg,
   const byte* hash, word32 hashLen, byte* sig, word32 *sigLen,
   dilithium_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((hash == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_ctx_hash(key, rng, ctx, ctxLen, hashAlg, hash,
            hashLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)hashAlg;
        (void)hash;
        (void)hashLen;
        (void)rng;
    #endif
    }

    return ret;
}

/* Sign the message using the dilithium private key.
 *
 *  ctx         [in]      Context of signature.
 *  ctxLen      [in]      Length of context in bytes.
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_ctx_msg_with_seed(const byte* ctx, byte ctxLen,
    const byte* msg, word32 msgLen, byte* sig, word32 *sigLen,
    dilithium_key* key, const byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_ctx_msg_with_seed(key, seed, ctx, ctxLen, msg,
            msgLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)msgLen;
        (void)seed;
    #endif
    }

    return ret;
}

/* Sign the message using the dilithium private key.
 *
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL or public key not set,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_msg_with_seed(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, dilithium_key* key, const byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_msg_with_seed(key, seed, msg, msgLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)msgLen;
        (void)seed;
    #endif
    }

    return ret;
}

/* Sign the message using the dilithium private key.
 *
 *  ctx         [in]      Context of signature.
 *  ctxLen      [in]      Length of context in bytes.
 *  hashAlg     [in]      Hash algorithm used on message.
 *  hash        [in]      Hash of message to sign.
 *  hashLen     [in]      Length of the message hash in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_sign_ctx_hash_with_seed(const byte* ctx, byte ctxLen,
    int hashAlg, const byte* hash, word32 hashLen, byte* sig, word32 *sigLen,
    dilithium_key* key, const byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((hash == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_sign_ctx_hash_with_seed(key, seed, ctx, ctxLen,
            hashAlg, hash, hashLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)hashAlg;
        (void)hash;
        (void)hashLen;
        (void)seed;
    #endif
    }

    return ret;
}
#endif /* !WOLFSSL_DILITHIUM_NO_SIGN */

#ifndef WOLFSSL_DILITHIUM_NO_VERIFY
/* Verify the message using the dilithium public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  ctx         [in]  Context of signature.
 *  ctxLen      [in]  Length of context in bytes.
 *  msg         [in]  Message to verify.
 *  msgLen      [in]  Length of the message in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Dilithium key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when sigLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_verify_ctx_msg(const byte* sig, word32 sigLen, const byte* ctx,
    word32 ctxLen, const byte* msg, word32 msgLen, int* res, dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (msg == NULL) || (res == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Verify message with signature. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_verify_ctx_msg(key, ctx, ctxLen, msg, msgLen, sig,
            sigLen, res);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)sigLen;
        (void)msgLen;
        (void)res;
    #endif
    }

    return ret;
}

/* Verify the message using the dilithium public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  msg         [in]  Message to verify.
 *  msgLen      [in]  Length of the message in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Dilithium key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL or contextLen is zero when and
 *          BUFFER_E when sigLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (msg == NULL) || (res == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    #ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
        #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
        #endif
        {
            ret = wc_CryptoCb_PqcVerify(sig, sigLen, msg, msgLen, res,
                WC_PQC_SIG_TYPE_DILITHIUM, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
    #endif

    if (ret == 0) {
        /* Verify message with signature. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_verify_msg(key, msg, msgLen, sig, sigLen, res);
    #elif defined(HAVE_LIBOQS)
        ret = oqs_dilithium_verify_msg(sig, sigLen, msg, msgLen, res, key);
    #endif
    }

    return ret;
}

/* Verify the message using the dilithium public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  ctx         [in]  Context of signature.
 *  ctxLen      [in]  Length of context in bytes.
 *  hashAlg     [in]  Hash algorithm used on message.
 *  hash        [in]  Hash of message to verify.
 *  hashLen     [in]  Length of the message hash in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Dilithium key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL, public key not set
 *          or ctx is NULL and ctxLen is not 0,
 *          BUFFER_E when sigLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_dilithium_verify_ctx_hash(const byte* sig, word32 sigLen,
    const byte* ctx, word32 ctxLen, int hashAlg, const byte* hash,
    word32 hashLen, int* res, dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (hash == NULL) || (res == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (ctx == NULL) && (ctxLen > 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Verify message with signature. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = dilithium_verify_ctx_hash(key, ctx, ctxLen, hashAlg, hash,
            hashLen, sig, sigLen, res);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)sigLen;
        (void)hashAlg;
        (void)hash;
        (void)hashLen;
    #endif
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_NO_VERIFY */

/* Initialize the dilithium private/public key.
 *
 * key  [in]  Dilithium key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_dilithium_init(dilithium_key* key)
{
    return wc_dilithium_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the dilithium private/public key.
 *
 * key  [in]  Dilithium key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_dilithium_init_ex(dilithium_key* key, void* heap, int devId)
{
    int ret = 0;

    (void)devId;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Ensure all fields reset. */
        XMEMSET(key, 0, sizeof(*key));

    #ifdef WOLF_CRYPTO_CB
        key->devCtx = NULL;
        key->devId = devId;
    #endif
    #ifdef WOLF_PRIVATE_KEY_ID
        key->idLen = 0;
        key->labelLen = 0;
    #endif
        key->heap = heap;
    }

    return ret;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_dilithium_init_id(dilithium_key* key, const unsigned char* id, int len,
    void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((len < 0) || (len > DILITHIUM_MAX_ID_LEN))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_dilithium_init_ex(key, heap, devId);
    }
    if ((ret == 0) && (id != NULL) && (len != 0)) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    /* Set the maximum level here */
    wc_dilithium_set_level(key, WC_ML_DSA_87);

    return ret;
}

int wc_dilithium_init_label(dilithium_key* key, const char* label, void* heap,
    int devId)
{
    int ret = 0;
    int labelLen = 0;

    if ((key == NULL) || (label == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if ((labelLen == 0) || (labelLen > DILITHIUM_MAX_LABEL_LEN)) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        ret = wc_dilithium_init_ex(key, heap, devId);
    }
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    /* Set the maximum level here */
    wc_dilithium_set_level(key, WC_ML_DSA_87);

    return ret;
}
#endif

/* Set the level of the dilithium private/public key.
 *
 * key   [out]  Dilithium key.
 * level [in]   Either 2,3 or 5.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
int wc_dilithium_set_level(dilithium_key* key, byte level)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((level == WC_ML_DSA_44) || (level == WC_ML_DSA_65) ||
            (level == WC_ML_DSA_87))) {
        /* Nothing to do. */
    }
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
    else if ((ret == 0) && ((level == WC_ML_DSA_44_DRAFT) ||
             (level == WC_ML_DSA_65_DRAFT) || (level == WC_ML_DSA_87_DRAFT))) {
        /* Nothing to do. */
    }
#endif
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
#ifdef WOLFSSL_WC_DILITHIUM
        /* Get the parameters for level into key. */
        ret = dilithium_get_params(level, &key->params);
    }
    if (ret == 0) {
        /* Clear any cached items. */
#ifndef WC_DILITHIUM_FIXED_ARRAY
    #ifdef WC_DILITHIUM_CACHE_MATRIX_A
        XFREE(key->a, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->a = NULL;
        key->aSet = 0;
    #endif
    #ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        XFREE(key->s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->s1 = NULL;
        key->s2 = NULL;
        key->t0 = NULL;
        key->privVecsSet = 0;
    #endif
    #ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        XFREE(key->t1, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->t1 = NULL;
        key->pubVecSet = 0;
    #endif
#endif
#endif /* WOLFSSL_WC_DILITHIUM */

        /* Store level and indicate public and private key are not set. */
        key->level = level % WC_ML_DSA_DRAFT;
        key->pubKeySet = 0;
        key->prvKeySet = 0;
    }

    return ret;
}

/* Get the level of the dilithium private/public key.
 *
 * key   [in]  Dilithium key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_dilithium_get_level(dilithium_key* key, byte* level)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (level == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return level. */
        *level = key->level;
    }

    return ret;
}

/* Clears the dilithium key data
 *
 * key  [in]  Dilithium key.
 */
void wc_dilithium_free(dilithium_key* key)
{
    if (key != NULL) {
#ifdef WOLFSSL_WC_DILITHIUM
#ifndef WC_DILITHIUM_FIXED_ARRAY
        /* Dispose of cached items. */
    #ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        XFREE(key->t1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    #endif
    #ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        XFREE(key->s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    #endif
    #ifdef WC_DILITHIUM_CACHE_MATRIX_A
        XFREE(key->a, key->heap, DYNAMIC_TYPE_DILITHIUM);
    #endif
#endif
        /* Free the SHAKE-128/256 object. */
        wc_Shake256_Free(&key->shake);
#endif
        /* Ensure all private data is zeroized. */
        ForceZero(key, sizeof(*key));
    }
}

#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
/* Returns the size of a dilithium private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_dilithium_size(dilithium_key* key)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    if (key != NULL) {
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = DILITHIUM_LEVEL2_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = DILITHIUM_LEVEL3_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = DILITHIUM_LEVEL5_KEY_SIZE;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = ML_DSA_LEVEL2_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = ML_DSA_LEVEL3_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = ML_DSA_LEVEL5_KEY_SIZE;
        }
    }

    return ret;
}

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
/* Returns the size of a dilithium private plus public key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_dilithium_priv_size(dilithium_key* key)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    if (key != NULL) {
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = DILITHIUM_LEVEL2_PRV_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = DILITHIUM_LEVEL3_PRV_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = DILITHIUM_LEVEL5_PRV_KEY_SIZE;
        }
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = ML_DSA_LEVEL2_PRV_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = ML_DSA_LEVEL3_PRV_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = ML_DSA_LEVEL5_PRV_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a dilithium private plus public key.
 *
 * @param [in]  key  Dilithium private/public key.
 * @param [out] len  Private key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaKey_GetPrivLen(MlDsaKey* key, int* len)
{
    int ret = 0;

    *len = wc_dilithium_priv_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */
#endif /* WOLFSSL_DILITHIUM_PRIVATE_KEY */

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
/* Returns the size of a dilithium public key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_dilithium_pub_size(dilithium_key* key)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    if (key != NULL) {
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = ML_DSA_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = ML_DSA_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = ML_DSA_LEVEL5_PUB_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a dilithium public key.
 *
 * @param [in]  key  Dilithium private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaKey_GetPubLen(MlDsaKey* key, int* len)
{
    int ret = 0;

    *len = wc_dilithium_pub_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
/* Returns the size of a dilithium signature.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_dilithium_sig_size(dilithium_key* key)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    if (key != NULL) {
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = DILITHIUM_LEVEL2_SIG_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = DILITHIUM_LEVEL3_SIG_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = DILITHIUM_LEVEL5_SIG_SIZE;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = ML_DSA_LEVEL2_SIG_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = ML_DSA_LEVEL3_SIG_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = ML_DSA_LEVEL5_SIG_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a dilithium signature.
 *
 * @param [in]  key  Dilithium private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaKey_GetSigLen(MlDsaKey* key, int* len)
{
    int ret = 0;

    *len = wc_dilithium_sig_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_DILITHIUM_CHECK_KEY
/* Check the public key of the dilithium key matches the private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_dilithium_check_key(dilithium_key* key)
{
    int ret = 0;
#ifdef WOLFSSL_WC_DILITHIUM
    const wc_dilithium_params* params;
    sword32* a  = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t  = NULL;
    sword32* t0 = NULL;
    sword32* t1 = NULL;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = PUBLIC_KEY_E;
    }

    /* Any value in public key are valid.
     * Public seed is hashed to generate matrix A.
     * t1 is the top 10 bits of a number in range of 0..(Q-1).
     * Q >> 13 = 0x3ff so all encoded values are valid.
     */

    if (ret == 0) {
        params = key->params;
        unsigned int allocSz;

        /* s1-L, s2-K, t0-K, t-K, t1-K */
        allocSz = params->s1Sz + 4 * params->s2Sz;
#if !defined(WC_DILITHIUM_CACHE_MATRIX_A)
        /* A-KxL */
        allocSz += params->aSz;
#endif

        /* Allocate memory for large intermediates. */
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t0 = s2 + params->s2Sz / sizeof(*s2);
            t  = t0 + params->s2Sz / sizeof(*t0);
            t1 = t  + params->s2Sz / sizeof(*t);
#if !defined(WC_DILITHIUM_CACHE_MATRIX_A)
            a  = t1 + params->s2Sz / sizeof(*t1);
#else
            a = key->a;
#endif
        }
    }

    if (ret == 0) {
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            const byte* pub_seed = key->p;

            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            key->aSet = (ret == 0);
#endif
        }
    }
    if (ret == 0) {
        const byte* s1p = key->k + DILITHIUM_PUB_SEED_SZ + DILITHIUM_K_SZ +
                                   DILITHIUM_TR_SZ;
        const byte* s2p = s1p + params->s1EncSz;
        const byte* t0p = s2p + params->s2EncSz;
        const byte* t1p = key->p + DILITHIUM_PUB_SEED_SZ;
        sword32* tt = t;
        unsigned int i;
        unsigned int j;
        sword32 x = 0;

        /* Get s1, s2 and t0 from private key. */
        dilithium_vec_decode_eta_bits(s1p, params->eta, s1, params->l);
        dilithium_vec_decode_eta_bits(s2p, params->eta, s2, params->k);
        dilithium_vec_decode_t0(t0p, params->k, t0);

        /* Get t1 from public key. */
        dilithium_vec_decode_t1(t1p, params->k, t1);

        /* Calcaluate t = NTT-1(A o NTT(s1)) + s2 */
        dilithium_vec_ntt_small(s1, params->l);
        dilithium_matrix_mul(t, a, s1, params->k, params->l);
        dilithium_vec_invntt(t, params->k);
        dilithium_vec_add(t, s2, params->k);
        /* Subtract t0 from t. */
        dilithium_vec_sub(t, t0, params->k);
        /* Make t positive to match t1. */
        dilithium_vec_make_pos(t, params->k);

        /* Check t - t0 and t1 are the same. */
        for (i = 0; i < params->k; i++) {
            for (j = 0; j < DILITHIUM_N; j++) {
                x |= tt[j] ^ t1[j];
            }
            tt += DILITHIUM_N;
            t1 += DILITHIUM_N;
        }
        /* Check the public seed is the same in private and public key. */
        for (i = 0; i < DILITHIUM_PUB_SEED_SZ; i++) {
            x |= key->p[i] ^ key->k[i];
        }

        if ((ret == 0) && (x != 0)) {
            ret = PUBLIC_KEY_E;
        }
    }

    if (key != NULL) {
        /* Dispose of allocated memory. */
        XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    }
#else
    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = PUBLIC_KEY_E;
    }

    if (ret == 0) {
        int i;
        sword32 x = 0;

        /* Check the public seed is the same in private and public key. */
        for (i = 0; i < 32; i++) {
            x |= key->p[i] ^ key->k[i];
        }

        if (x != 0) {
            ret = PUBLIC_KEY_E;
        }
    }
#endif /* WOLFSSL_WC_DILITHIUM */
    return ret;
}
#endif /* WOLFSSL_DILITHIUM_CHECK_KEY */

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY

/* Export the dilithium public key.
 *
 * @param [in]      key     Dilithium public key.
 * @param [out]     out     Array to hold public key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
int wc_dilithium_export_public(dilithium_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Get length passed in for checking. */
        inLen = *outLen;
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL2_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL3_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL5_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            /* Set out length. */
            *outLen = ML_DSA_LEVEL2_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < ML_DSA_LEVEL2_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->level == WC_ML_DSA_65) {
            /* Set out length. */
            *outLen = ML_DSA_LEVEL3_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < ML_DSA_LEVEL3_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->level == WC_ML_DSA_87) {
            /* Set out length. */
            *outLen = ML_DSA_LEVEL5_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < ML_DSA_LEVEL5_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    /* Check public key available. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy public key out. */
        XMEMCPY(out, key->p, *outLen);
    }

    return ret;
}

/* Import a dilithium public key from a byte array.
 *
 * Public key encoded in big-endian.
 *
 * @param [in]      in     Array holding public key.
 * @param [in]      inLen  Number of bytes of data in array.
 * @param [in, out] key    Dilithium public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
int wc_dilithium_import_public(const byte* in, word32 inLen, dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL2_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL3_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL5_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            /* Check length. */
            if (inLen != ML_DSA_LEVEL2_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->level == WC_ML_DSA_65) {
            /* Check length. */
            if (inLen != ML_DSA_LEVEL3_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->level == WC_ML_DSA_87) {
            /* Check length. */
            if (inLen != ML_DSA_LEVEL5_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_DILITHIUM_ASSIGN_KEY
        XMEMCPY(key->p, in, inLen);
    #else
        key->p = in;
    #endif

#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    #ifndef WC_DILITHIUM_FIXED_ARRAY
        /* Allocate t1 if required. */
        if (key->t1 == NULL) {
            key->t1 = (sword32*)XMALLOC(key->params->s2Sz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->t1 == NULL) {
                ret = MEMORY_E;
            }
        }
    #endif
    }
    if (ret == 0) {
        /* Compute t1 from public key data. */
        dilithium_make_pub_vec(key, key->t1);
#endif
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    #ifndef WC_DILITHIUM_FIXED_ARRAY
        /* Allocate matrix a if required. */
        if (key->a == NULL) {
            key->a = (sword32*)XMALLOC(key->params->aSz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->a == NULL) {
                ret = MEMORY_E;
            }
        }
    #endif
    }
    if (ret == 0) {
        /* Compute matrix a from public key data. */
        ret = dilithium_expand_a(&key->shake, key->p, key->params->k,
            key->params->l, key->a, key->heap);
        if (ret == 0) {
            key->aSet = 1;
        }
    }
    if (ret == 0) {
#endif
        /* Public key is set. */
        key->pubKeySet = 1;
    }

    return ret;
}

#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY

/* Set the private key data into key.
 *
 * @param [in]     priv    Private key data.
 * @param [in]     privSz  Size of private key data in bytes.
 * @param in, out] key     Dilithium key to set into.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when private key size is invalid.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative on hash error.
 */
static int dilithium_set_priv_key(const byte* priv, word32 privSz,
    dilithium_key* key)
{
    int ret = 0;
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    const wc_dilithium_params* params = key->params;
#endif

    /* Validate parameters. */
    if ((privSz != ML_DSA_LEVEL2_KEY_SIZE) &&
            (privSz != ML_DSA_LEVEL3_KEY_SIZE) &&
            (privSz != ML_DSA_LEVEL5_KEY_SIZE)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_DILITHIUM_ASSIGN_KEY
        XMEMCPY(key->k, priv, privSz);
    #else
        key->k = priv;
    #endif
    }

        /* Allocate and create cached values. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if (ret == 0) {
        /* Allocate matrix a if required. */
        if (key->a == NULL) {
            key->a = (sword32*)XMALLOC(params->aSz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->a == NULL) {
                ret = MEMORY_E;
            }
        }
    }
#endif
    if (ret == 0) {
        /* Compute matrix a from private key data. */
        ret = dilithium_expand_a(&key->shake, key->k, params->k, params->l,
            key->a, key->heap);
        if (ret == 0) {
            key->aSet = 1;
        }
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        /* Allocate L vector s1, K vector s2 and K vector t0 if required. */
        key->s1 = (sword32*)XMALLOC(params->s1Sz + params->s2Sz + params->s2Sz,
            key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            /* Set pointers into allocated memory. */
            key->s2 = key->s1 + params->s1Sz / sizeof(*key->s1);
            key->t0 = key->s2 + params->s2Sz / sizeof(*key->s2);
        }
    }
#endif
    if (ret == 0) {
        /* Compute vectors from private key. */
        dilithium_make_priv_vecs(key, key->s1, key->s2, key->t0);
    }
#endif
    if (ret == 0) {
        /* Private key is set. */
        key->prvKeySet = 1;
    }

    return ret;
}

/* Import a dilithium private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     Dilithium private key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
int wc_dilithium_import_private(const byte* priv, word32 privSz,
    dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the private key data. */
        ret = dilithium_set_priv_key(priv, privSz, key);
    }

    return ret;
}

#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
/* Import a dilithium private and public keys from byte array(s).
 *
 * @param [in] priv    Array holding private key or private+public keys
 * @param [in] privSz  Number of bytes of data in private key array.
 * @param [in] pub     Array holding public key (or NULL).
 * @param [in] pubSz   Number of bytes of data in public key array (or 0).
 * @param [in] key     Dilithium private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required parameter is NULL an invalid
 *          combination of keys/lengths is supplied.
 */
int wc_dilithium_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, dilithium_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (pub != NULL)) {
        /* Import public key. */
        ret = wc_dilithium_import_public(pub, pubSz, key);
    }
    if (ret == 0) {
        ret = dilithium_set_priv_key(priv, privSz, key);
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

/* Export the dilithium private key.
 *
 * @param [in]      key     Dilithium private key.
 * @param [out]     out     Array to hold private key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
int wc_dilithium_export_private(dilithium_key* key, byte* out,
    word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters. */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check private key available. */
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        inLen = *outLen;
        /* check and set up out length */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            *outLen = DILITHIUM_LEVEL2_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            *outLen = DILITHIUM_LEVEL3_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            *outLen = DILITHIUM_LEVEL5_KEY_SIZE;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            *outLen = ML_DSA_LEVEL2_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            *outLen = ML_DSA_LEVEL3_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            *outLen = ML_DSA_LEVEL5_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    /* Check array length. */
    if ((ret == 0) && (inLen < *outLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Copy private key out key. */
        XMEMCPY(out, key->k, *outLen);
    }

    return ret;
}

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
/* Export the dilithium private and public key.
 *
 * @param [in]      key     Dilithium private/public key.
 * @param [out]     priv    Array to hold private key.
 * @param [in, out] privSz  On in, the number of bytes in private key array.
 *                          On out, the number bytes put into private key.
 * @param [out]     pub     Array to hold  public key.
 * @param [in, out] pubSz   On in, the number of bytes in public key array.
 *                          On out, the number bytes put into public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, priv, privSz, pub or pubSz is NULL.
 * @return  BUFFER_E when privSz or pubSz is less than required size.
 */
int wc_dilithium_export_key(dilithium_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz)
{
    int ret;

    /* Export private key only. */
    ret = wc_dilithium_export_private(key, priv, privSz);
    if (ret == 0) {
        /* Export public key. */
        ret = wc_dilithium_export_public(key, pub, pubSz);
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

#endif /* WOLFSSL_DILITHIUM_PRIVATE_KEY */

#ifndef WOLFSSL_DILITHIUM_NO_ASN1

/* Maps ASN.1 OID to wolfCrypt security level macros */
static int mapOidToSecLevel(word32 oid)
{
    switch (oid) {
        case ML_DSA_LEVEL2k:
            return WC_ML_DSA_44;
        case ML_DSA_LEVEL3k:
            return WC_ML_DSA_65;
        case ML_DSA_LEVEL5k:
            return WC_ML_DSA_87;
#ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
        case DILITHIUM_LEVEL2k:
            return WC_ML_DSA_44_DRAFT;
        case DILITHIUM_LEVEL3k:
            return WC_ML_DSA_65_DRAFT;
        case DILITHIUM_LEVEL5k:
            return WC_ML_DSA_87_DRAFT;
#endif
        default:
            return ASN_UNKNOWN_OID_E;
    }
}

#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)

/* Decode the DER encoded Dilithium key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       Dilithium key structure to hold the decoded key.
 *                            If the security level is set in the key structure
 *                            on input, the DER key will be decoded as such and
 *                            will fail if there is a mismatch. If the level
 *                            and parameters are not set in the key structure on
 *                            input, the level will be detected from the DER
 *                            file based on the algorithm OID, appropriately
 *                            decoded, then updated in the key structure on
 *                            output. Auto-detection of the security level is
 *                            not supported if compiled for FIPS 204 draft mode.
 * @param [in]      inSz      Total size of the input DER buffer array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  Other negative on parse error.
 */
int wc_Dilithium_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    dilithium_key* key, word32 inSz)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    int keytype = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID sum for level. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            keytype = DILITHIUM_LEVEL2k;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            keytype = DILITHIUM_LEVEL3k;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            keytype = DILITHIUM_LEVEL5k;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            keytype = ML_DSA_LEVEL2k;
        }
        else if (key->level == WC_ML_DSA_65) {
            keytype = ML_DSA_LEVEL3k;
        }
        else if (key->level == WC_ML_DSA_87) {
            keytype = ML_DSA_LEVEL5k;
        }
        else {
            /* Level not set by caller, decode from DER */
            keytype = ANONk; /* 0, not a valid key type in this situation*/
        }
    }

    if (ret == 0) {
        /* Decode the asymmetric key and get out private and public key data. */
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz,
                                   &privKey, &privKeyLen,
                                   &pubKey, &pubKeyLen, &keytype);
        if (ret == 0
#ifdef WOLFSSL_WC_DILITHIUM
            && key->params == NULL
#endif
        ) {
            /* Set the security level based on the decoded key. */
            ret = mapOidToSecLevel(keytype);
            if (ret > 0) {
                ret = wc_dilithium_set_level(key, ret);
            }
        }
    }
    if ((ret == 0) && (pubKey == NULL) && (pubKeyLen == 0)) {
        /* Check if the public key is included in the private key. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if ((key->params->level == WC_ML_DSA_44_DRAFT) &&
            (privKeyLen == DILITHIUM_LEVEL2_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL2_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if ((key->params->level == WC_ML_DSA_65_DRAFT) &&
                 (privKeyLen == DILITHIUM_LEVEL3_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL3_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if ((key->params->level == WC_ML_DSA_87_DRAFT) &&
                 (privKeyLen == DILITHIUM_LEVEL5_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL5_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
        else
    #endif
        if ((key->level == WC_ML_DSA_44) &&
            (privKeyLen == ML_DSA_LEVEL2_PRV_KEY_SIZE)) {
            pubKey = privKey + ML_DSA_LEVEL2_KEY_SIZE;
            pubKeyLen = ML_DSA_LEVEL2_PUB_KEY_SIZE;
            privKeyLen -= ML_DSA_LEVEL2_PUB_KEY_SIZE;
        }
        else if ((key->level == WC_ML_DSA_65) &&
                 (privKeyLen == ML_DSA_LEVEL3_PRV_KEY_SIZE)) {
            pubKey = privKey + ML_DSA_LEVEL3_KEY_SIZE;
            pubKeyLen = ML_DSA_LEVEL3_PUB_KEY_SIZE;
            privKeyLen -= ML_DSA_LEVEL3_PUB_KEY_SIZE;
        }
        else if ((key->level == WC_ML_DSA_87) &&
                 (privKeyLen == ML_DSA_LEVEL5_PRV_KEY_SIZE)) {
            pubKey = privKey + ML_DSA_LEVEL5_KEY_SIZE;
            pubKeyLen = ML_DSA_LEVEL5_PUB_KEY_SIZE;
            privKeyLen -= ML_DSA_LEVEL5_PUB_KEY_SIZE;
        }
    }

    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_dilithium_import_private(privKey, privKeyLen, key);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_dilithium_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, key);
        }
#endif
    }

    (void)pubKey;
    (void)pubKeyLen;

    return ret;
}

#endif /* WOLFSSL_DILITHIUM_PRIVATE_KEY */

#endif /* WOLFSSL_DILITHIUM_NO_ASN1 */

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY

#if defined(WOLFSSL_DILITHIUM_NO_ASN1)
#ifndef WOLFSSL_NO_ML_DSA_44
static unsigned char ml_dsa_oid_44[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
static unsigned char dilithium_oid_44[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b,
    0x0c, 0x04, 0x04
};
#endif
#endif
#ifndef WOLFSSL_NO_ML_DSA_65
static unsigned char ml_dsa_oid_65[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
static unsigned char dilithium_oid_65[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b,
    0x0c, 0x06, 0x05
};
#endif
#endif
#ifndef WOLFSSL_NO_ML_DSA_87
static unsigned char ml_dsa_oid_87[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};
#if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
static unsigned char dilithium_oid_87[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b,
    0x0c, 0x08, 0x07
};
#endif
#endif

static int dilitihium_get_der_length(const byte* input, word32* inOutIdx,
    int *length, word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;
    word32 len = 0;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] < 0x80) {
        len = input[idx];
        idx++;
    }
    else if ((input[idx] == 0x80) || (input[idx] >= 0x83)) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] == 0x81) {
        if (idx + 1 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else if (input[idx + 1] < 0x80) {
            ret = ASN_PARSE_E;
        }
        else {
            len = input[idx + 1];
            idx += 2;
        }
    }
    else if (input[idx] == 0x82) {
        if (idx + 2 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else {
            len = ((word16)input[idx + 1] << 8) + input[idx + 2];
            idx += 3;
            if (len < 0x100) {
                ret = ASN_PARSE_E;
            }
        }
    }

    if ((ret == 0) && ((idx + len) > inSz)) {
        ret = ASN_PARSE_E;
    }

    *length = (int)len;
    *inOutIdx = idx;
    return ret;
}

static int dilithium_check_type(const byte* input, word32* inOutIdx, byte type,
    word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] != type){
        ret = ASN_PARSE_E;
    }
    else {
        idx++;
    }

    *inOutIdx = idx;
    return ret;
}

#endif /* WOLFSSL_DILITHIUM_NO_ASN1 */

/* Decode the DER encoded Dilithium public key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       Dilithium key structure to hold the decoded key.
 *                            If the security level is set in the key structure
 *                            on input, the DER key will be decoded as such
 *                            and will fail if there is a mismatch. If the level
 *                            and parameters are not set in the key structure on
 *                            input, the level will be detected from the DER
 *                            file based on the algorithm OID, appropriately
 *                            decoded, then updated in the key structure on
 *                            output. Auto-detection of the security level is
 *                            not supported if compiled for FIPS 204
 *                            draft mode.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
int wc_Dilithium_PublicKeyDecode(const byte* input, word32* inOutIdx,
    dilithium_key* key, word32 inSz)
{
    int ret = 0;
    const byte* pubKey;
    word32 pubKeyLen = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Try to import the key directly. */
        ret = wc_dilithium_import_public(input, inSz, key);
        if (ret != 0) {
        #if !defined(WOLFSSL_DILITHIUM_NO_ASN1)
            int keytype = 0;
        #else
            int length;
            unsigned char* oid;
            int oidLen;
            word32 idx = 0;
        #endif

            /* Start again. */
            ret = 0;

    #if !defined(WOLFSSL_DILITHIUM_NO_ASN1)
            /* Get OID sum for level. */
        #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
            if (key->params == NULL) {
                ret = BAD_FUNC_ARG;
            }
            else if (key->params->level == WC_ML_DSA_44_DRAFT) {
                keytype = DILITHIUM_LEVEL2k;
            }
            else if (key->params->level == WC_ML_DSA_65_DRAFT) {
                keytype = DILITHIUM_LEVEL3k;
            }
            else if (key->params->level == WC_ML_DSA_87_DRAFT) {
                keytype = DILITHIUM_LEVEL5k;
            }
            else
        #endif
            if (key->level == WC_ML_DSA_44) {
                keytype = ML_DSA_LEVEL2k;
            }
            else if (key->level == WC_ML_DSA_65) {
                keytype = ML_DSA_LEVEL3k;
            }
            else if (key->level == WC_ML_DSA_87) {
                keytype = ML_DSA_LEVEL5k;
            }
            else {
                /* Level not set by caller, decode from DER */
                keytype = ANONk; /* 0, not a valid key type in this situation*/
            }
            if (ret == 0) {
                /* Decode the asymmetric key and get out public key data. */
                ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz,
                                                 &pubKey, &pubKeyLen,
                                                 &keytype);
                if (ret == 0
#ifdef WOLFSSL_WC_DILITHIUM
                    && key->params == NULL
#endif
                ) {
                    /* Set the security level based on the decoded key. */
                    ret = mapOidToSecLevel(keytype);
                    if (ret > 0) {
                        ret = wc_dilithium_set_level(key, ret);
                    }
                }
            }
    #else
            /* Get OID sum for level. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
            if (key->params == NULL) {
                ret = BAD_FUNC_ARG;
            }
            else
        #ifndef WOLFSSL_NO_ML_DSA_44
            if (key->params->level == WC_ML_DSA_44_DRAFT) {
                oid = dilithium_oid_44;
                oidLen = (int)sizeof(dilithium_oid_44);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_65
            if (key->params->level == WC_ML_DSA_65_DRAFT) {
                oid = dilithium_oid_65;
                oidLen = (int)sizeof(dilithium_oid_65);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_87
            if (key->params->level == WC_ML_DSA_87_DRAFT) {
                oid = dilithium_oid_87;
                oidLen = (int)sizeof(dilithium_oid_87);
            }
            else
        #endif
    #endif
        #ifndef WOLFSSL_NO_ML_DSA_44
            if (key->level == WC_ML_DSA_44) {
                oid = ml_dsa_oid_44;
                oidLen = (int)sizeof(ml_dsa_oid_44);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_65
            if (key->level == WC_ML_DSA_65) {
                oid = ml_dsa_oid_65;
                oidLen = (int)sizeof(ml_dsa_oid_65);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_87
            if (key->level == WC_ML_DSA_87) {
                oid = ml_dsa_oid_87;
                oidLen = (int)sizeof(ml_dsa_oid_87);
            }
            else
        #endif
            {
                /* Level not set. */
                ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x06, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if ((length != oidLen) ||
                        (XMEMCMP(input + idx, oid, oidLen) != 0)) {
                    ret = ASN_PARSE_E;
                }
                idx += oidLen;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x03, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if ((input[idx] != 0) || (length == 0)) {
                    ret = ASN_PARSE_E;
                }
                idx++;
                length--;
            }
            if (ret == 0) {
                /* This is the raw point data compressed or uncompressed. */
                pubKeyLen = (word32)length;
                pubKey = input + idx;
            }
    #endif
            if (ret == 0) {
                /* Import public key data. */
                ret = wc_dilithium_import_public(pubKey, pubKeyLen, key);
            }
        }
    }
    return ret;
}

#ifndef WOLFSSL_DILITHIUM_NO_ASN1

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of a Dilithium key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key      Dilithium key object.
 * @param [out] output   Buffer to put encoded data in.
 * @param [in]  len      Size of buffer in bytes.
 * @param [in]  withAlg  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_Dilithium_PublicKeyToDer(dilithium_key* key, byte* output, word32 len,
    int withAlg)
{
    int ret = 0;
    int keytype = 0;
    int pubKeyLen = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID and length for level. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            keytype = DILITHIUM_LEVEL2k;
            pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            keytype = DILITHIUM_LEVEL3k;
            pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            keytype = DILITHIUM_LEVEL5k;
            pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            keytype = ML_DSA_LEVEL2k;
            pubKeyLen = ML_DSA_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            keytype = ML_DSA_LEVEL3k;
            pubKeyLen = ML_DSA_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            keytype = ML_DSA_LEVEL5k;
            pubKeyLen = ML_DSA_LEVEL5_PUB_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = SetAsymKeyDerPublic(key->p, pubKeyLen, output, len, keytype,
            withAlg);
    }

    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#endif /* !WOLFSSL_DILITHIUM_NO_ASN1 */

#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY

#ifndef WOLFSSL_DILITHIUM_NO_ASN1

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
/* Encode the private and public data of a Dilithium key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     Dilithium key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_Dilithium_KeyToDer(dilithium_key* key, byte* output, word32 len)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    /* Validate parameters and check public and private key set. */
    if ((key != NULL) && key->prvKeySet && key->pubKeySet) {
        /* Create DER for level. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, key->p,
                DILITHIUM_LEVEL2_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL2k);
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, key->p,
                DILITHIUM_LEVEL3_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL3k);
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, key->p,
                DILITHIUM_LEVEL5_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL5k);
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL2_KEY_SIZE, key->p,
                ML_DSA_LEVEL2_PUB_KEY_SIZE, output, len, ML_DSA_LEVEL2k);
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL3_KEY_SIZE, key->p,
                ML_DSA_LEVEL3_PUB_KEY_SIZE, output, len, ML_DSA_LEVEL3k);
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL5_KEY_SIZE, key->p,
                ML_DSA_LEVEL5_PUB_KEY_SIZE, output, len, ML_DSA_LEVEL5k);
        }
    }

    return ret;
}
#endif /* WOLFSSL_DILITHIUM_PUBLIC_KEY */

/* Encode the private data of a Dilithium key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     Dilithium key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_Dilithium_PrivateKeyToDer(dilithium_key* key, byte* output, word32 len)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet) {
        /* Create DER for level. */
    #if defined(WOLFSSL_DILITHIUM_FIPS204_DRAFT)
        if (key->params == NULL) {
            ret = BAD_FUNC_ARG;
        }
        else if (key->params->level == WC_ML_DSA_44_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL2k);
        }
        else if (key->params->level == WC_ML_DSA_65_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL3k);
        }
        else if (key->params->level == WC_ML_DSA_87_DRAFT) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL5k);
        }
        else
    #endif
        if (key->level == WC_ML_DSA_44) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL2_KEY_SIZE, NULL, 0, output,
                len, ML_DSA_LEVEL2k);
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL3_KEY_SIZE, NULL, 0, output,
                len, ML_DSA_LEVEL3k);
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = SetAsymKeyDer(key->k, ML_DSA_LEVEL5_KEY_SIZE, NULL, 0, output,
                len, ML_DSA_LEVEL5k);
        }
    }

    return ret;
}

#endif /* WOLFSSL_DILITHIUM_NO_ASN1 */

#endif /* WOLFSSL_DILITHIUM_PRIVATE_KEY */

#endif /* HAVE_DILITHIUM */
