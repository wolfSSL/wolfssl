/* wc_slhdsa.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if FIPS_VERSION3_GE(2,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS
#endif

#include <wolfssl/wolfcrypt/wc_slhdsa.h>

#ifdef WOLFSSL_HAVE_SLHDSA

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifdef WOLFSSL_SLHDSA_SHA2
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/sha512.h>
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

#if defined(USE_INTEL_SPEEDUP)
/* CPU information for Intel. */
static cpuid_flags_t cpuid_flags = WC_CPUID_INITIALIZER;
#endif


/* Winternitz number. */
#define SLHDSA_W                16
/* Number of iterations of hashing itself from Winternitz number. */
#define SLHDSA_WM1              (SLHDSA_W - 1)


#ifndef WOLFSSL_SLHDSA_PARAM_NO_256
    /* Maximum size of hash output. */
    #define SLHDSA_MAX_N                32
    #ifndef WOLFSSL_SLHDSA_PARAM_NO_FAST
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   35
    #else
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   22
    #endif
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    /* Maximum size of hash output. */
    #define SLHDSA_MAX_N                24
    #ifndef WOLFSSL_SLHDSA_PARAM_NO_FAST
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   33
    #else
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   17
    #endif
#else
    /* Maximum size of hash output. */
    #define SLHDSA_MAX_N                16
    #ifndef WOLFSSL_SLHDSA_PARAM_NO_FAST
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   33
    #else
        /* Maximum number of indices for FORS signatures. */
        #define SLHDSA_MAX_INDICES_SZ   14
    #endif
#endif

#ifndef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    #if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            14
    #elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            14
    #else
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            12
    #endif
#else
    #if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            9
    #elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            8
    #else
        /* Maximum number of trees for FORS. */
        #define SLHDSA_MAX_A            6
    #endif
#endif

#ifndef WOLFSSL_SLHDSA_PARAM_NO_SMALL
    /* Maximum height of Merkle tree. */
    #define SLHDSA_MAX_H_M              9
#else
    /* Maximum height of Merkle tree. */
    #define SLHDSA_MAX_H_M              3
#endif

/* Maximum message size in nibbles. */
#define SLHDSA_MAX_MSG_SZ       ((2 * SLHDSA_MAX_N) + 3)

#ifndef WOLFSSL_SLHDSA_PARAM_NO_256F
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               49
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_256S)
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               47
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192F)
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               42
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_192S)
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               39
#elif !defined(WOLFSSL_SLHDSA_PARAM_NO_128F)
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               34
#else
    /* Maximum number of bytes to produce from digest of message. */
    #define SLHDSA_MAX_MD               30
#endif


/******************************************************************************
 * HashAddress
 ******************************************************************************/

/* HashAddress types. */
/* WOTS+ hash. */
#define HA_WOTS_HASH    0
/* WOTS+ Public Key. */
#define HA_WOTS_PK      1
/* XMSS tree. */
#define HA_TREE         2
/* FORS tree. */
#define HA_FORS_TREE    3
/* FORS Root. */
#define HA_FORS_ROOTS   4
/* WOTS Pseudo-random function. */
#define HA_WOTS_PRF     5
/* FORS Pseudo-random function. */
#define HA_FORS_PRF     6

/* Size of an encoded HashAddress. */
#define SLHDSA_HA_SZ    32

/* Initialize a HashAddress.
 *
 * @param [in] a  HashAddress to initialize.
 */
#define HA_Init(a)                  XMEMSET(a, 0, sizeof(HashAddress))
/* Copy a HashAddress.
 *
 * @param [out] a  HashAddress to copy into.
 * @param [in]  b  HashAddress to copy from.
 */
#define HA_Copy(a, b)               XMEMCPY(a, b, sizeof(HashAddress))
/* Set layer address into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 1.
 *
 * @param [in] a  HashAddress set.
 * @param [in] l  Layer address.
 */
#define HA_SetLayerAddress(a, l)    (a)[0] = (l)
/* Set tree address into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 2.
 *
 * @param [in] a  HashAddress set.
 * @param [in] t  Tree address.
 */
#define HA_SetTreeAddress(a, t)                                                \
    do { (a)[1] = (t)[0]; (a)[2] = (t)[1]; (a)[3] = (t)[2]; } while (0)
/* Set type and clear following fields.
 *
 * FIPS 205. Section 4.3. Table 1. Line 3.
 *
 * @param [in] a  HashAddress set.
 * @param [in] y  HashAddress type.
 */
#define HA_SetTypeAndClear(a, y)                                               \
    do { (a)[4] = y; (a)[5] = 0; (a)[6] = 0; (a)[7] = 0; } while (0)
/* Set type and clear following fields but not Key Pair Address.
 *
 * FIPS 205. Section 4.3. Table 1. Line 3. But don't clear Key Pair Address.
 *
 * @param [in] a  HashAddress set.
 * @param [in] y  HashAddress type.
 */
#define HA_SetTypeAndClearNotKPA(a, y)                                         \
    do { (a)[4] = y; (a)[6] = 0; (a)[7] = 0; } while (0)
/* Set key pair address into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 4.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Key pair address.
 */
#define HA_SetKeyPairAddress(a, i)  (a)[5] = (i)
/* Set chain address into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 5.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Chain address.
 */
#define HA_SetChainAddress(a, i)    (a)[6] = (i)
/* Set tree height into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 5.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Tree height.
 */
#define HA_SetTreeHeight(a, i)      (a)[6] = (i)
/* Set tree height as big-endian into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 5. But encode value big-endian.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Tree height.
 */
#define HA_SetTreeHeightBE(a, i)    c32toa(i, (a) + (6 * 4))
/* Set hash address into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 6.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Hash address.
 */
#define HA_SetHashAddress(a, i)     (a)[7] = (i)
/* Set tree index into HashAddress.
 *
 * FIPS 205. Section 4.3. Table 1. Line 6.
 *
 * @param [in] a  HashAddress set.
 * @param [in] i  Tree index.
 */
#define HA_SetTreeIndex(a, i)       (a)[7] = (i)
/* Copy key pair address from one HashAddress to another.
 *
 * FIPS 205. Section 4.3. Table 1. Line 4 and 7.
 *
 * @param [in] a  HashAddress to copy into.
 * @param [in] b  HashAddress to copy from.
 */
#define HA_CopyKeyPairAddress(a, b) (a)[5] = (b)[5]

/* FIPS 205. Section 4.3. Table 1. Line 8 - Get tree index is not needed as
 * index is set and index value modified before being set again.
 */

/* HashAddress type. */
typedef word32 HashAddress[8];

/* Encode a HashAddress.
 *
 * @param [in]  adrs     HashAddress to encode.
 * @param [out] address  Buffer to encode into.
 */
static void HA_Encode(const word32* adrs, byte* address)
{
#ifndef WOLFSSL_WC_SLHDSA_SMALL
    c32toa(adrs[0], address + (0 * 4));
    c32toa(adrs[1], address + (1 * 4));
    c32toa(adrs[2], address + (2 * 4));
    c32toa(adrs[3], address + (3 * 4));
    c32toa(adrs[4], address + (4 * 4));
    c32toa(adrs[5], address + (5 * 4));
    c32toa(adrs[6], address + (6 * 4));
    c32toa(adrs[7], address + (7 * 4));
#else
    int i;

    for (i = 0; i < 8; i++) {
        c32toa(adrs[i], address + (i * 4));
    }
#endif
}

/******************************************************************************
 * Index Tree - 3 x 32-bit words
 ******************************************************************************/

/* Mask the tree index.
 *
 * @param [in] t     Tree index.
 * @param [in] mask  Mask to apply to index.
 * @return  Masked tree index.
 */
#define INDEX_TREE_MASK(t, mask)    ((t)[2] & (mask))

/* Shift the tree index down by a number of bits.
 *
 * @param [in] t  Tree index.
 * @param [in] b  Number of bits to shift.
 */
#define INDEX_TREE_SHIFT_DOWN(t, b)                     \
    (t)[2] = ((t)[1] << (32 - (b))) | ((t)[2] >> (b));  \
    (t)[1] =                           (t)[1] >> (b);

/******************************************************************************
 * Parameters
 ******************************************************************************/

/* Create parameter entry.
 *
 * Other parameters:
 *   len = 2 * n + 3
 *   dl1 = upper((k * a) / 8)
 *   dl2 = upper((h - (h / d)) / 8)
 *   dl3 = upper(h / (8 * d))
 *   sigLen = Root +     FORS SK + FORS AUTH + d * (XMSS SIG + XMSS AUTH)
 *           (   1 +           k +     k * a + d * (      h2 +       len)) * n
 *
 * @param [in] p    Parameter name.
 * @param [in] n    Hash size in bytes.
 * @param [in] h    Total tree height.
 * @param [in] d    Depth of subtree.
 * @param [in] h_m  Height of message tree - XMSS tree.
 * @param [in] a    Number of authentication nodes.
 * @param [in] k    Number of FORS signatures.
 */
#define SLHDSA_PARAMETERS(p, n, h, d, h_m, a, k)    \
    { (p), (n), (h), (d), (h_m), (a), (k),          \
      2 * (n) + 3,                                  \
      (((k) * (a)) + 7) / 8,                        \
      (((h) - ((h) / (d))) + 7) / 8,                \
      ((h) + ((8 * (d)) - 1)) / (8 * (d)),          \
      (1 + (k) * (1 + (a)) + (d) * ((h_m) + 2*(n) + 3)) * (n) }

/* An array of known parameters.
 *
 * FIPS 205. Section 11. Table 2.
 */
static const SlhDsaParameters SlhDsaParams[] =
{
                                     /*  n,  h,  d, h_m,  a,  k */
#ifndef WOLFSSL_SLHDSA_PARAM_NO_128S
    SLHDSA_PARAMETERS(SLHDSA_SHAKE128S, 16, 63,  7,   9, 12, 14),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_128F
    SLHDSA_PARAMETERS(SLHDSA_SHAKE128F, 16, 66, 22,   3,  6, 33),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_192S
    SLHDSA_PARAMETERS(SLHDSA_SHAKE192S, 24, 63,  7,   9, 14, 17),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_192F
    SLHDSA_PARAMETERS(SLHDSA_SHAKE192F, 24, 66, 22,   3,  8, 33),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_256S
    SLHDSA_PARAMETERS(SLHDSA_SHAKE256S, 32, 64,  8,   8, 14, 22),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_256F
    SLHDSA_PARAMETERS(SLHDSA_SHAKE256F, 32, 68, 17,   4,  9, 35),
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
                                     /*  n,  h,  d, h_m,  a,  k */
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128S
    SLHDSA_PARAMETERS(SLHDSA_SHA2_128S,  16, 63,  7,   9, 12, 14),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_128F
    SLHDSA_PARAMETERS(SLHDSA_SHA2_128F,  16, 66, 22,   3,  6, 33),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192S
    SLHDSA_PARAMETERS(SLHDSA_SHA2_192S,  24, 63,  7,   9, 14, 17),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_192F
    SLHDSA_PARAMETERS(SLHDSA_SHA2_192F,  24, 66, 22,   3,  8, 33),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256S
    SLHDSA_PARAMETERS(SLHDSA_SHA2_256S,  32, 64,  8,   8, 14, 22),
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_SHA2_256F
    SLHDSA_PARAMETERS(SLHDSA_SHA2_256F,  32, 68, 17,   4,  9, 35),
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
};

/* Number of parameters in array. */
#define SLHDSA_PARAM_LEN    \
    ((int)(sizeof(SlhDsaParams) / sizeof(SlhDsaParameters)))

/******************************************************************************
 * Hashes
 ******************************************************************************/

#ifndef WOLFSSL_WC_SLHDSA_SMALL
/* Hash three data elements with SHAKE-256.
 *
 * Will be less than WC_SHA3_256_COUNT * 8 bytes of data.
 *
 * @param [in]  shake      SHAKE-256 object.
 * @param [in]  data1      First block of data to hash.
 * @param [in]  data1_len  Length of first block of data.
 * @param [in]  adrs       Unencoded HashAddress.
 * @param [in]  data2      Second block of data to hash.
 * @param [in]  data2_len  Length of second block of data.
 * @param [out] hash       Hash output.
 * @param [in]  hash_len   Length of hash to output in bytes.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_shake_3(wc_Shake* shake, const byte* data1,
    byte data1_len, const word32* adrs, const byte* data2, byte data2_len,
    byte* hash, byte hash_len)
{
#ifdef WOLFSSL_SLHDSA_FULL_HASH
    int ret;
    byte address[SLHDSA_HA_SZ];

    /* Encode hash address. */
    HA_Encode(adrs, address);

    /* Update the SHAKE-256 object with first block of data. */
    ret = wc_Shake256_Update(shake, data1, data1_len);
    if (ret == 0) {
        /* Update the SHAKE-256 object with encoded HashAddress. */
        ret = wc_Shake256_Update(shake, address, SLHDSA_HA_SZ);
    }
    if (ret == 0) {
        /* Update the SHAKE-256 object with second block of data. */
        ret = wc_Shake256_Update(shake, data2, data2_len);
    }
    if (ret == 0) {
        /* Calculate and output hash. */
        ret = wc_Shake256_Final(shake, hash, hash_len);
    }

    return ret;
#elif defined(USE_INTEL_SPEEDUP)
    word64* state = shake->s;
    word8* state8 = (word8*)shake->s;
    word32 o = 0;

    /* Move the first block of data into the state. */
    XMEMCPY(state8 + o, data1, data1_len);
    o += data1_len;
    /* Encode the HashAddress into the state next. */
    HA_Encode(adrs, state8 + o);
    o += SLHDSA_HA_SZ;
    /* Move the second block of data into the state next. */
    XMEMCPY(state8 + o, data2, data2_len);
    o += data2_len;
    /* Place SHAKE end-of-content marker. */
    state8[o] = 0x1f;
    o += 1;
    /* Zero out rest of state. */
    XMEMSET(state8 + o, 0, sizeof(shake->s) - o);
    /* Place SHAKE-256 end-of-data marker. */
    state8[WC_SHA3_256_COUNT * 8 - 1] ^= 0x80;

#ifndef WC_SHA3_NO_ASM
    /* Check availability of AVX2 instructions. */
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* Process the state using AVX2 instructions. */
        sha3_block_avx2(state);
        RESTORE_VECTOR_REGISTERS();
    }
    /* Check availability of BMI2 instructions. */
    else if (IS_INTEL_BMI2(cpuid_flags)) {
        /* Process the state using BMI2 instructions. */
        sha3_block_bmi2(state);
    }
    else
#endif
    {
        /* Process the state using C code. */
        BlockSha3(state);
    }
    /* Copy hash result, of the required length, from the state into hash. */
    XMEMCPY(hash, shake->s, hash_len);

    return 0;
#else
    /* Copy the first block of data into the cached data buffer. */
    XMEMCPY(shake->t, data1, data1_len);
    /* Encode HashAddress into the cached data buffer next. */
    HA_Encode(adrs, shake->t + data1_len);
    /* Copy the second block of data into the cached data buffer next. */
    XMEMCPY(shake->t + data1_len + SLHDSA_HA_SZ, data2, data2_len);

    /* Update count of bytes cached. */
    shake->i = data1_len + SLHDSA_HA_SZ + data2_len;

    /* Calculate and output hash. */
    return wc_Shake256_Final(shake, hash, hash_len);
#endif
}
#endif

/* Hash four data elements with SHAKE-256.
 *
 * Will be less than WC_SHA3_256_COUNT * 8 bytes of data.
 *
 * @param [in]  shake      SHAKE-256 object.
 * @param [in]  data1      First block of data to hash.
 * @param [in]  data1_len  Length of first block of data.
 * @param [in]  adrs       Unencoded HashAddress.
 * @param [in]  data2      Second block of data to hash.
 * @param [in]  data2_len  Length of second block of data.
 * @param [in]  data3      Third block of data to hash.
 * @param [in]  data3_len  Length of third block of data.
 * @param [out] hash       Hash output.
 * @param [in]  hash_len   Length of hash to output in bytes.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_shake_4(wc_Shake* shake, const byte* data1,
    byte data1_len, const word32* adrs, const byte* data2, byte data2_len,
    const byte* data3, byte data3_len, byte* hash, byte hash_len)
{
#ifdef WOLFSSL_SLHDSA_FULL_HASH
    int ret;
    byte address[SLHDSA_HA_SZ];

    /* Encode hash address. */
    HA_Encode(adrs, address);

    /* Update the SHAKE-256 object with first block of data. */
    ret = wc_Shake256_Update(shake, data1, data1_len);
    if (ret == 0) {
        /* Update the SHAKE-256 object with encoded HashAddress. */
        ret = wc_Shake256_Update(shake, address, SLHDSA_HA_SZ);
    }
    if (ret == 0) {
        /* Update the SHAKE-256 object with second block of data. */
        ret = wc_Shake256_Update(shake, data2, data2_len);
    }
    if (ret == 0) {
        /* Update the SHAKE-256 object with third block of data. */
        ret = wc_Shake256_Update(shake, data3, data3_len);
    }
    if (ret == 0) {
        /* Calculate and output hash. */
        ret = wc_Shake256_Final(shake, hash, hash_len);
    }

    return ret;
#elif defined(USE_INTEL_SPEEDUP)
    word64* state = shake->s;
    word8* state8 = (word8*)shake->s;
    word32 o = 0;

    /* Move the first block of data into the state. */
    XMEMCPY(state8 + o, data1, data1_len);
    o += data1_len;
    /* Encode the HashAddress into the state next. */
    HA_Encode(adrs, state8 + o);
    o += SLHDSA_HA_SZ;
    /* Move the second block of data into the state next. */
    XMEMCPY(state8 + o, data2, data2_len);
    o += data2_len;
    /* Move the third block of data into the state next. */
    XMEMCPY(state8 + o, data3, data3_len);
    o += data3_len;
    /* Place SHAKE end-of-content marker. */
    state8[o] = 0x1f;
    o += 1;
    /* Zero out rest of state. */
    XMEMSET(state8 + o, 0, sizeof(shake->s) - o);
    /* Place SHAKE-256 end-of-data marker. */
    state8[WC_SHA3_256_COUNT * 8 - 1] ^= 0x80;

#ifndef WC_SHA3_NO_ASM
    /* Check availability of AVX2 instructions. */
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* Process the state using AVX2 instructions. */
        sha3_block_avx2(state);
        RESTORE_VECTOR_REGISTERS();
    }
    /* Check availability of BMI2 instructions. */
    else if (IS_INTEL_BMI2(cpuid_flags)) {
        /* Process the state using BMI2 instructions. */
        sha3_block_bmi2(state);
    }
    else
#endif
    {
        /* Process the state using C code. */
        BlockSha3(state);
    }
    /* Copy hash result, of the required length, from the state into hash. */
    XMEMCPY(hash, shake->s, hash_len);

    return 0;
#else
    /* Copy the first block of data into the cached data buffer. */
    XMEMCPY(shake->t, data1, data1_len);
    /* Encode HashAddress into the cached data buffer next. */
    HA_Encode(adrs, shake->t + data1_len);
    /* Copy the second block of data into the cached data buffer next. */
    XMEMCPY(shake->t + data1_len + SLHDSA_HA_SZ, data2, data2_len);
    /* Copy the third block of data into the cached data buffer next. */
    XMEMCPY(shake->t + data1_len + SLHDSA_HA_SZ + data2_len, data3, data3_len);

    /* Update count of bytes cached. */
    shake->i = data1_len + SLHDSA_HA_SZ + data2_len + data3_len;

    /* Calculate and output hash. */
    return wc_Shake256_Final(shake, hash, hash_len);
#endif
}

/******************************************************************************
 * SHA2 Hash Functions (FIPS 205, Section 11.2)
 ******************************************************************************/

#ifdef WOLFSSL_SLHDSA_SHA2

/* Size of compressed HashAddress (ADRS^c) per FIPS 205 Section 11.2. */
#define SLHDSA_HAC_SZ   22

/* Encode a compressed HashAddress (ADRS^c).
 *
 * FIPS 205. Section 11.2.
 *   Byte 0:      low byte of adrs[0] (layer)
 *   Bytes 1-8:   adrs[2..3] (low 8 bytes of tree address)
 *   Byte 9:      low byte of adrs[4] (type)
 *   Bytes 10-21: adrs[5..7] (remaining 12 bytes, verbatim)
 *
 * @param [in]  adrs     HashAddress to encode (8 x word32).
 * @param [out] address  Buffer to encode into (22 bytes).
 */
static void HA_Encode_Compressed(const word32* adrs, byte* address)
{
    /* Byte 0: low byte of layer address. */
    address[0] = (byte)adrs[0];
    /* Bytes 1-4: adrs[2] (tree address high word). */
    c32toa(adrs[2], address + 1);
    /* Bytes 5-8: adrs[3] (tree address low word). */
    c32toa(adrs[3], address + 5);
    /* Byte 9: low byte of type. */
    address[9] = (byte)adrs[4];
    /* Bytes 10-13: adrs[5] (key pair address / padding). */
    c32toa(adrs[5], address + 10);
    /* Bytes 14-17: adrs[6] (chain address / tree height). */
    c32toa(adrs[6], address + 14);
    /* Bytes 18-21: adrs[7] (hash address / tree index). */
    c32toa(adrs[7], address + 18);
}

/* Pre-compute SHA2 midstates for PK.seed.
 *
 * SHA-256: PK.seed || pad(64 - n) is exactly one 64-byte block.
 * SHA-512: PK.seed || pad(128 - n) is exactly one 128-byte block.
 *
 * @param [in, out] key  SLH-DSA key with pk_seed set at key->sk[2*n].
 * @return  0 on success.
 */
static int slhdsakey_precompute_sha2_midstates(SlhDsaKey* key)
{
    int ret;
    byte n = key->params->n;
    const byte* pk_seed = key->sk + 2 * n;
    byte block[WC_SHA512_BLOCK_SIZE];

    /* SHA-256 midstate: PK.seed || zeros to fill 64-byte block. */
    XMEMSET(block, 0, WC_SHA256_BLOCK_SIZE);
    XMEMCPY(block, pk_seed, n);
    ret = wc_InitSha256(&key->hash.sha2.sha256_mid);
    if (ret == 0) {
        ret = wc_Sha256Update(&key->hash.sha2.sha256_mid, block,
            WC_SHA256_BLOCK_SIZE);
    }

    /* SHA-512 midstate: PK.seed || zeros to fill 128-byte block.
     * Only needed for categories 3 and 5 (n > 16). */
    if ((ret == 0) && (n > 16)) {
        XMEMSET(block, 0, WC_SHA512_BLOCK_SIZE);
        XMEMCPY(block, pk_seed, n);
        ret = wc_InitSha512(&key->hash.sha2.sha512_mid);
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_mid, block,
                WC_SHA512_BLOCK_SIZE);
        }
    }

    return ret;
}

/* SHA2 F function.
 *
 * FIPS 205. Section 11.2.
 *   F(PK.seed, ADRS, M1) = Trunc_n(SHA-256(PK.seed||pad(64-n)||ADRS^c||M1))
 *
 * Uses pre-computed midstate for the first block.
 *
 * @param [in]  key      SLH-DSA key (SHA2 hash objects + midstate).
 * @param [in]  pk_seed  Public key seed (unused - midstate).
 * @param [in]  adrs     HashAddress.
 * @param [in]  m        Message of n bytes.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 */
static int slhdsakey_hash_f_sha2(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* m, byte n, byte* hash)
{
    int ret;
    byte address[SLHDSA_HAC_SZ];
    byte digest[WC_SHA256_DIGEST_SIZE];
    int copy_succeeded = 0;

    (void)pk_seed;

    /* Encode compressed address. */
    HA_Encode_Compressed(adrs, address);

    /* Restore SHA-256 midstate. */

    ret = wc_Sha256Copy(&key->hash.sha2.sha256_mid, &key->hash.sha2.sha256);
    if (ret == 0) {
        copy_succeeded = 1;
        /* Update with compressed ADRS and message. */
        ret = wc_Sha256Update(&key->hash.sha2.sha256, address, SLHDSA_HAC_SZ);
    }
    if (ret == 0) {
        ret = wc_Sha256Update(&key->hash.sha2.sha256, m, n);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&key->hash.sha2.sha256, digest);
    }
    if (ret == 0) {
        /* Truncate to n bytes. */
        XMEMCPY(hash, digest, n);
    }
    if (copy_succeeded) {
        wc_Sha256Free(&key->hash.sha2.sha256);
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* SHA2 H function.
 *
 * FIPS 205. Section 11.2.
 *   Cat 1: H(PK.seed, ADRS, M2) = Trunc_n(SHA-256(PK.seed||pad||ADRS^c||M2))
 *   Cat 3,5: H(PK.seed, ADRS, M2) = Trunc_n(SHA-512(PK.seed||pad||ADRS^c||M2))
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  pk_seed  Public key seed (unused - midstate).
 * @param [in]  adrs     HashAddress.
 * @param [in]  node     Message of 2n bytes.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 */
static int slhdsakey_hash_h_sha2(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* node, byte n, byte* hash)
{
    int ret;
    byte address[SLHDSA_HAC_SZ];

    (void)pk_seed;

    /* Encode compressed address. */
    HA_Encode_Compressed(adrs, address);

    if (n == WC_SLHDSA_N_128) {
        /* Category 1: use SHA-256. */
        byte digest[WC_SHA256_DIGEST_SIZE];
        int copy_succeeded = 0;

        ret = wc_Sha256Copy(&key->hash.sha2.sha256_mid,
            &key->hash.sha2.sha256);
        if (ret == 0) {
            copy_succeeded = 1;
            ret = wc_Sha256Update(&key->hash.sha2.sha256, address,
                SLHDSA_HAC_SZ);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256, node, 2 * n);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&key->hash.sha2.sha256, digest);
        }
        if (ret == 0) {
            XMEMCPY(hash, digest, n);
        }
        if (copy_succeeded) {
            wc_Sha256Free(&key->hash.sha2.sha256);
        }
    }
    else {
        /* Categories 3, 5: use SHA-512. */
        byte digest[WC_SHA512_DIGEST_SIZE];
        int copy_succeeded = 0;

        ret = wc_Sha512Copy(&key->hash.sha2.sha512_mid,
            &key->hash.sha2.sha512);
        if (ret == 0) {
            copy_succeeded = 1;
            ret = wc_Sha512Update(&key->hash.sha2.sha512, address,
                SLHDSA_HAC_SZ);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512, node, 2 * n);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(&key->hash.sha2.sha512, digest);
        }
        if (ret == 0) {
            XMEMCPY(hash, digest, n);
        }
        if (copy_succeeded) {
            wc_Sha512Free(&key->hash.sha2.sha512);
        }
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* SHA2 H function with two separate n-byte halves.
 *
 * Same as slhdsakey_hash_h_sha2 but M2 = m1 || m2.
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  pk_seed  Public key seed (unused - midstate).
 * @param [in]  adrs     HashAddress.
 * @param [in]  m1       First n bytes of message.
 * @param [in]  m2       Second n bytes of message.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 */
static int slhdsakey_hash_h_2_sha2(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* m1, const byte* m2, byte n, byte* hash)
{
    int ret;
    byte address[SLHDSA_HAC_SZ];

    (void)pk_seed;

    /* Encode compressed address. */
    HA_Encode_Compressed(adrs, address);

    if (n == WC_SLHDSA_N_128) {
        /* Category 1: use SHA-256. */
        byte digest[WC_SHA256_DIGEST_SIZE];
        int copy_succeeded = 0;

        ret = wc_Sha256Copy(&key->hash.sha2.sha256_mid,
            &key->hash.sha2.sha256);
        if (ret == 0) {
            copy_succeeded = 1;
            ret = wc_Sha256Update(&key->hash.sha2.sha256, address,
                SLHDSA_HAC_SZ);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256, m1, n);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256, m2, n);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&key->hash.sha2.sha256, digest);
        }
        if (ret == 0) {
            XMEMCPY(hash, digest, n);
        }
        if (copy_succeeded) {
            wc_Sha256Free(&key->hash.sha2.sha256);
        }
    }
    else {
        /* Categories 3, 5: use SHA-512. */
        byte digest[WC_SHA512_DIGEST_SIZE];
        int copy_succeeded = 0;

        ret = wc_Sha512Copy(&key->hash.sha2.sha512_mid,
            &key->hash.sha2.sha512);
        if (ret == 0) {
            copy_succeeded = 1;
            ret = wc_Sha512Update(&key->hash.sha2.sha512, address,
                SLHDSA_HAC_SZ);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512, m1, n);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512, m2, n);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(&key->hash.sha2.sha512, digest);
        }
        if (ret == 0) {
            XMEMCPY(hash, digest, n);
        }
        if (copy_succeeded) {
            wc_Sha512Free(&key->hash.sha2.sha512);
        }
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* SHA2 PRF function.
 *
 * FIPS 205. Section 11.2.
 *   PRF(PK.seed, SK.seed, ADRS) =
 *       Trunc_n(SHA-256(PK.seed || pad(64-n) || ADRS^c || SK.seed))
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  pk_seed  Public key seed (unused - midstate).
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 */
static int slhdsakey_hash_prf_sha2(SlhDsaKey* key, const byte* pk_seed,
    const byte* sk_seed, const word32* adrs, byte n, byte* hash)
{
    int ret;
    byte address[SLHDSA_HAC_SZ];
    byte digest[WC_SHA256_DIGEST_SIZE];
    int copy_succeeded = 0;

    (void)pk_seed;

    /* Encode compressed address. */
    HA_Encode_Compressed(adrs, address);

    /* Restore SHA-256 midstate. */
    ret = wc_Sha256Copy(&key->hash.sha2.sha256_mid, &key->hash.sha2.sha256);
    if (ret == 0) {
        copy_succeeded = 1;
        ret = wc_Sha256Update(&key->hash.sha2.sha256, address, SLHDSA_HAC_SZ);
    }
    if (ret == 0) {
        ret = wc_Sha256Update(&key->hash.sha2.sha256, sk_seed, n);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(&key->hash.sha2.sha256, digest);
    }
    if (ret == 0) {
        XMEMCPY(hash, digest, n);
    }
    if (copy_succeeded) {
        wc_Sha256Free(&key->hash.sha2.sha256);
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* SHA2 T_l streaming: start with address.
 *
 * Restores midstate then updates with compressed ADRS.
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] pk_seed  Public key seed (unused - midstate).
 * @param [in] adrs     HashAddress.
 * @param [in] n        Number of bytes of hash output (determines cat).
 * @return  0 on success.
 */
static int slhdsakey_hash_start_addr_sha2(SlhDsaKey* key,
    const byte* pk_seed, const word32* adrs, byte n)
{
    int ret;
    byte address[SLHDSA_HAC_SZ];

    (void)pk_seed;

    HA_Encode_Compressed(adrs, address);

    if (n == WC_SLHDSA_N_128) {
        /* Category 1: SHA-256 -- use sha256_2 (T_l must not collide with
         * sha256 which is used by F and H). */
        ret = wc_Sha256Copy(&key->hash.sha2.sha256_mid,
            &key->hash.sha2.sha256_2);
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, address,
                SLHDSA_HAC_SZ);
        }
    }
    else {
        /* Categories 3, 5: SHA-512 -- use sha512_2 (T_l must not collide
         * with sha512 which is used by H). */
        ret = wc_Sha512Copy(&key->hash.sha2.sha512_mid,
            &key->hash.sha2.sha512_2);
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, address,
                SLHDSA_HAC_SZ);
        }
    }

    return ret;
}

/* SHA2 T_l streaming: update with data.
 *
 * @param [in] key   SLH-DSA key.
 * @param [in] data  Data to hash.
 * @param [in] len   Length of data.
 * @return  0 on success.
 */
static int slhdsakey_hash_update_sha2(SlhDsaKey* key, const byte* data,
    word32 len)
{
    if (key->params->n == WC_SLHDSA_N_128) {
        return wc_Sha256Update(&key->hash.sha2.sha256_2, data, len);
    }
    else {
        return wc_Sha512Update(&key->hash.sha2.sha512_2, data, len);
    }
}

/* SHA2 T_l streaming: finalize.
 *
 * @param [in]  key   SLH-DSA key.
 * @param [out] hash  Output buffer.
 * @param [in]  len   Desired output length (truncate to n).
 * @return  0 on success.
 */
static int slhdsakey_hash_final_sha2(SlhDsaKey* key, byte* hash, word32 len)
{
    int ret;
    byte n = key->params->n;

    if (n == WC_SLHDSA_N_128) {
        byte digest[WC_SHA256_DIGEST_SIZE];
        ret = wc_Sha256Final(&key->hash.sha2.sha256_2, digest);
        if (ret == 0) {
            XMEMCPY(hash, digest, (len < n) ? len : n);
        }
    }
    else {
        byte digest[WC_SHA512_DIGEST_SIZE];
        ret = wc_Sha512Final(&key->hash.sha2.sha512_2, digest);
        if (ret == 0) {
            XMEMCPY(hash, digest, (len < n) ? len : n);
        }
    }

    return ret;
}

/* SHA2 T_l streaming: free internal allocations.
 *
 * @param [in]  key   SLH-DSA key.
 */
static void slhdsakey_hash_free_sha2(SlhDsaKey* key)
{
    byte n = key->params->n;

    if (n == WC_SLHDSA_N_128) {
        wc_Sha256Free(&key->hash.sha2.sha256_2);
    }
    else {
        wc_Sha512Free(&key->hash.sha2.sha512_2);
    }

    return;
}

/* Local MGF1 implementation for H_msg.
 *
 * FIPS 205. Section 11.2.
 *   H_msg uses MGF1-SHA-256/512(R || PK.seed || digest, m) where m is the
 *   required output length.
 *
 * @param [in]  key       SLH-DSA key (for hash objects).
 * @param [in]  seed      Seed data for MGF1.
 * @param [in]  seedLen   Length of seed.
 * @param [out] out       Output buffer.
 * @param [in]  outLen    Required output length.
 * @return  0 on success.
 */
static int slhdsakey_mgf1_sha2(SlhDsaKey* key, const byte* seed,
    word32 seedLen, byte* out, word32 outLen)
{
    int ret = 0;
    word32 counter = 0;
    word32 done = 0;
    byte n = key->params->n;

    while ((ret == 0) && (done < outLen)) {
        byte cBuf[4];
        word32 left = outLen - done;

        c32toa(counter, cBuf);

        if (n == WC_SLHDSA_N_128) {
            /* Category 1: MGF1-SHA-256. */
            byte digest[WC_SHA256_DIGEST_SIZE];
            word32 cpLen = (left < WC_SHA256_DIGEST_SIZE) ?
                left : WC_SHA256_DIGEST_SIZE;
            int hash_inited = 0;

            ret = wc_InitSha256(&key->hash.sha2.sha256_2);
            if (ret == 0) {
                hash_inited = 1;
                ret = wc_Sha256Update(&key->hash.sha2.sha256_2, seed, seedLen);
            }
            if (ret == 0) {
                ret = wc_Sha256Update(&key->hash.sha2.sha256_2, cBuf, 4);
            }
            if (ret == 0) {
                ret = wc_Sha256Final(&key->hash.sha2.sha256_2, digest);
            }
            if (hash_inited) {
                wc_Sha256Free(&key->hash.sha2.sha256_2);
            }
            if (ret == 0) {
                XMEMCPY(out + done, digest, cpLen);
                done += cpLen;
            }
        }
        else {
            /* Categories 3, 5: MGF1-SHA-512. */
            byte digest[WC_SHA512_DIGEST_SIZE];
            word32 cpLen = (left < WC_SHA512_DIGEST_SIZE) ?
                left : WC_SHA512_DIGEST_SIZE;
            int hash_inited = 0;

            ret = wc_InitSha512(&key->hash.sha2.sha512_2);
            if (ret == 0) {
                hash_inited = 1;
                ret = wc_Sha512Update(&key->hash.sha2.sha512_2, seed, seedLen);
            }
            if (ret == 0) {
                ret = wc_Sha512Update(&key->hash.sha2.sha512_2, cBuf, 4);
            }
            if (ret == 0) {
                ret = wc_Sha512Final(&key->hash.sha2.sha512_2, digest);
            }
            if (hash_inited) {
                wc_Sha512Free(&key->hash.sha2.sha512_2);
            }
            if (ret == 0) {
                XMEMCPY(out + done, digest, cpLen);
                done += cpLen;
            }
        }
        counter++;
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* SHA2 PRF_msg function.
 *
 * FIPS 205. Section 11.2.
 *   PRF_msg(SK.prf, opt_rand, M) =
 *       Trunc_n(HMAC-SHA-256/512(SK.prf, opt_rand || M))
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_prf   SK.prf seed.
 * @param [in]  opt_rand Random or PK.seed.
 * @param [in]  hdr      Message header (2 bytes).
 * @param [in]  ctx      Context data (may be NULL).
 * @param [in]  ctxSz    Context data length.
 * @param [in]  msg      Message data.
 * @param [in]  msgSz    Message data length.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 */
static int slhdsakey_prf_msg_sha2(SlhDsaKey* key, const byte* sk_prf,
    const byte* opt_rand, const byte* hdr, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, byte n, byte* hash)
{
    int ret;
    Hmac hmac;
    int hmacType;
    byte digest[WC_SHA512_DIGEST_SIZE];

    if (n == WC_SLHDSA_N_128) {
        hmacType = WC_SHA256;
    }
    else {
        hmacType = WC_SHA512;
    }

    ret = wc_HmacInit(&hmac, key->heap, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(&hmac, hmacType, sk_prf, n);
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, opt_rand, n);
    }
    if ((ret == 0) && (hdr != NULL)) {
        ret = wc_HmacUpdate(&hmac, hdr, 2);
    }
    if ((ret == 0) && (ctxSz > 0) && (ctx != NULL)) {
        ret = wc_HmacUpdate(&hmac, ctx, ctxSz);
    }
    if (ret == 0) {
        ret = wc_HmacUpdate(&hmac, msg, msgSz);
    }
    if (ret == 0) {
        ret = wc_HmacFinal(&hmac, digest);
    }
    wc_HmacFree(&hmac);

    if (ret == 0) {
        XMEMCPY(hash, digest, n);
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* SHA2 H_msg function.
 *
 * FIPS 205. Section 11.2.
 *   H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256/512(
 *       R || PK.seed || SHA-256/512(R || PK.seed || PK.root || M), m)
 *
 * @param [in]  key    SLH-DSA key.
 * @param [in]  r      Randomizer (n bytes from signature).
 * @param [in]  hdr    Message header (2 bytes).
 * @param [in]  ctx    Context data (may be NULL).
 * @param [in]  ctxSz  Context data length.
 * @param [in]  msg    Message data.
 * @param [in]  msgSz  Message data length.
 * @param [out] md     Output message digest.
 * @param [in]  mdLen  Required digest length (dl1+dl2+dl3).
 * @return  0 on success.
 */
static int slhdsakey_h_msg_sha2(SlhDsaKey* key, const byte* r,
    const byte* hdr, const byte* ctx, byte ctxSz, const byte* msg,
    word32 msgSz, byte* md, word32 mdLen)
{
    int ret;
    byte n = key->params->n;
    const byte* pk_seed = key->sk + 2 * n;
    const byte* pk_root = key->sk + 3 * n;

    if (n == WC_SLHDSA_N_128) {
        /* Category 1: SHA-256 + MGF1-SHA-256. */
        byte innerHash[WC_SHA256_DIGEST_SIZE];
        /* Seed for MGF1: R || PK.seed || innerHash. */
        byte mgfSeed[32 + 16 + WC_SHA256_DIGEST_SIZE];
        int sha_inited = 0;

        /* Step 1: innerHash = SHA-256(R || PK.seed || PK.root || M). */
        ret = wc_InitSha256(&key->hash.sha2.sha256_2);
        if (ret == 0) {
            sha_inited = 1;
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, r, n);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, pk_seed, n);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, pk_root, n);
        }
        if ((ret == 0) && (hdr != NULL)) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, hdr, 2);
        }
        if ((ret == 0) && (ctxSz > 0) && (ctx != NULL)) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, ctx, ctxSz);
        }
        if (ret == 0) {
            ret = wc_Sha256Update(&key->hash.sha2.sha256_2, msg, msgSz);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&key->hash.sha2.sha256_2, innerHash);
        }
        if (sha_inited) {
            wc_Sha256Free(&key->hash.sha2.sha256_2);
        }

        /* Step 2: MGF1-SHA-256(R || PK.seed || innerHash, mdLen). */
        if (ret == 0) {
            XMEMCPY(mgfSeed, r, n);
            XMEMCPY(mgfSeed + n, pk_seed, n);
            XMEMCPY(mgfSeed + 2 * n, innerHash, WC_SHA256_DIGEST_SIZE);
            ret = slhdsakey_mgf1_sha2(key, mgfSeed,
                2 * n + WC_SHA256_DIGEST_SIZE, md, mdLen);
        }
    }
    else {
        /* Categories 3, 5: SHA-512 + MGF1-SHA-512. */
        byte innerHash[WC_SHA512_DIGEST_SIZE];
        /* Seed for MGF1: R || PK.seed || innerHash. */
        byte mgfSeed[32 + 32 + WC_SHA512_DIGEST_SIZE];
        int sha_inited = 0;

        /* Step 1: innerHash = SHA-512(R || PK.seed || PK.root || M). */
        ret = wc_InitSha512(&key->hash.sha2.sha512_2);
        if (ret == 0) {
            sha_inited = 1;
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, r, n);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, pk_seed, n);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, pk_root, n);
        }
        if ((ret == 0) && (hdr != NULL)) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, hdr, 2);
        }
        if ((ret == 0) && (ctxSz > 0) && (ctx != NULL)) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, ctx, ctxSz);
        }
        if (ret == 0) {
            ret = wc_Sha512Update(&key->hash.sha2.sha512_2, msg, msgSz);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(&key->hash.sha2.sha512_2, innerHash);
        }
        if (sha_inited) {
            wc_Sha512Free(&key->hash.sha2.sha512_2);
        }

        /* Step 2: MGF1-SHA-512(R || PK.seed || innerHash, mdLen). */
        if (ret == 0) {
            XMEMCPY(mgfSeed, r, n);
            XMEMCPY(mgfSeed + n, pk_seed, n);
            XMEMCPY(mgfSeed + 2 * n, innerHash, WC_SHA512_DIGEST_SIZE);
            ret = slhdsakey_mgf1_sha2(key, mgfSeed,
                2 * n + WC_SHA512_DIGEST_SIZE, md, mdLen);
        }
    }

    return ret;
}

#endif /* WOLFSSL_SLHDSA_SHA2 */

/******************************************************************************
 * Dispatching Hash Macros
 ******************************************************************************/

/* When WOLFSSL_SLHDSA_SHA2 is defined, macros dispatch between SHAKE and SHA2
 * based on the key's parameter set. When not defined, macros call SHAKE
 * directly (zero overhead). */

#ifdef WOLFSSL_SLHDSA_SHA2

/* SHAKE wrapper functions for SHA2 dispatch macros. */
static int slhdsakey_hash_f_shake(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* m, byte n, byte* hash)
{
#ifndef WOLFSSL_WC_SLHDSA_SMALL
    return slhdsakey_hash_shake_3(&key->hash.shk.shake, pk_seed, n, adrs, m,
        n, hash, n);
#else
    return slhdsakey_hash_shake_4(&key->hash.shk.shake, pk_seed, n, adrs, m,
        n, NULL, 0, hash, n);
#endif
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
static int slhdsakey_hash_h_shake(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* node, byte n, byte* hash)
{
#ifndef WOLFSSL_WC_SLHDSA_SMALL
    return slhdsakey_hash_shake_3(&key->hash.shk.shake, pk_seed, n, adrs, node,
        2 * n, hash, n);
#else
    return slhdsakey_hash_shake_4(&key->hash.shk.shake, pk_seed, n, adrs, node,
        2 * n, NULL, 0, hash, n);
#endif
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

static int slhdsakey_hash_h_2_shake(SlhDsaKey* key, const byte* pk_seed,
    const word32* adrs, const byte* m1, const byte* m2, byte n, byte* hash)
{
    return slhdsakey_hash_shake_4(&key->hash.shk.shake, pk_seed, n, adrs, m1,
        n, m2, n, hash, n);
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
static int slhdsakey_hash_prf_shake(SlhDsaKey* key, const byte* pk_seed,
    const byte* sk_seed, const word32* adrs, byte n, byte* hash)
{
#ifndef WOLFSSL_WC_SLHDSA_SMALL
    return slhdsakey_hash_shake_3(&key->hash.shk.shake, pk_seed, n, adrs,
        sk_seed, n, hash, n);
#else
    return slhdsakey_hash_shake_4(&key->hash.shk.shake, pk_seed, n, adrs,
        sk_seed, n, NULL, 0, hash, n);
#endif
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

#define HASH_PRF(k, pk_seed, sk_seed, adrs, n, o)                            \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_prf_sha2(k, pk_seed, sk_seed, adrs, n, o) :          \
        slhdsakey_hash_prf_shake(k, pk_seed, sk_seed, adrs, n, o))

#define HASH_F(k, pk_seed, adrs, m, n, o)                                   \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_f_sha2(k, pk_seed, adrs, m, n, o) :                  \
        slhdsakey_hash_f_shake(k, pk_seed, adrs, m, n, o))

#define HASH_H(k, pk_seed, adrs, node, n, o)                                \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_h_sha2(k, pk_seed, adrs, node, n, o) :               \
        slhdsakey_hash_h_shake(k, pk_seed, adrs, node, n, o))

#define HASH_H_2(k, pk_seed, adrs, m1, m2, n, o)                            \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_h_2_sha2(k, pk_seed, adrs, m1, m2, n, o) :           \
        slhdsakey_hash_h_2_shake(k, pk_seed, adrs, m1, m2, n, o))

#else /* !WOLFSSL_SLHDSA_SHA2 */

#ifndef WOLFSSL_WC_SLHDSA_SMALL
/* PRF hash.
 *
 * FIPS 205. Section 4.1.
 *   PRF(PK.seed, SK.seed, ADRS) (Bn x Bn x B32 -> Bn) is a PRF that is used to
 *   generate the secret values in WOTS+ and FORS private keys.
 * FIPS 205. Section 11.1.
 *   PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  n        Number of bytes in hash output.
 * @param [out] hash     Buffer to hold hash output.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
#define HASH_PRF(k, pk_seed, sk_seed, adrs, n, o)                            \
    slhdsakey_hash_shake_3(&(k)->hash.shk.shake, pk_seed, n, adrs,           \
        sk_seed, n, o, n)
/* Hash F. */
#define HASH_F(k, pk_seed, adrs, m, n, o)                                    \
    slhdsakey_hash_shake_3(&(k)->hash.shk.shake, pk_seed, n, adrs, m, n,    \
        o, n)
/* Hash H. */
#define HASH_H(k, pk_seed, adrs, node, n, o)                                \
    slhdsakey_hash_shake_3(&(k)->hash.shk.shake, pk_seed, n, adrs, node,    \
        2 * (n), o, (n))
#else
/* PRF hash. */
#define HASH_PRF(k, pk_seed, sk_seed, adrs, n, o)                           \
    slhdsakey_hash_shake_4(&(k)->hash.shk.shake, pk_seed, n, adrs,          \
        sk_seed, n, NULL, 0, o, n)
/* Hash F. */
#define HASH_F(k, pk_seed, adrs, m, n, o)                                   \
    slhdsakey_hash_shake_4(&(k)->hash.shk.shake, pk_seed, n, adrs, m, n,   \
        NULL, 0, o, n)
/* Hash H. */
#define HASH_H(k, pk_seed, adrs, node, n, o)                                \
    slhdsakey_hash_shake_4(&(k)->hash.shk.shake, pk_seed, n, adrs, node,   \
        2 * n, NULL, 0, o, n)
#endif

/* Hash H with 2n byte message as two separate n byte parameters. */
#define HASH_H_2(k, pk_seed, adrs, m1, m2, n, o)                            \
    slhdsakey_hash_shake_4(&(k)->hash.shk.shake, pk_seed, n, adrs, m1, n,  \
        m2, n, o, n)

#endif /* WOLFSSL_SLHDSA_SHA2 */

/* T_l streaming dispatch macros for the secondary hash (used by WOTS+ pk
 * compression and FORS root computation). */
#ifdef WOLFSSL_SLHDSA_SHA2

#define HASH_T_START_ADDR(k, pk_seed, adrs, n)                              \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_start_addr_sha2(k, pk_seed, adrs, n) :               \
        slhdsakey_hash_start_addr(&(k)->hash.shk.shake2, pk_seed, adrs, n))

#define HASH_T_UPDATE(k, d, l)                                               \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_update_sha2(k, d, l) :                                \
        slhdsakey_hash_update(&(k)->hash.shk.shake2, d, l))

#define HASH_T_FINAL(k, o, l)                                                \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_final_sha2(k, o, l) :                                 \
        slhdsakey_hash_final(&(k)->hash.shk.shake2, o, l))

#define HASH_T_FREE(k)                                                       \
    (SLHDSA_IS_SHA2((k)->params->param) ?                                    \
        slhdsakey_hash_free_sha2(k) :                                        \
        slhdsakey_hash_free(&(k)->hash.shk.shake2))

#else

#define HASH_T_START_ADDR(k, pk_seed, adrs, n)                               \
    slhdsakey_hash_start_addr(&(k)->hash.shk.shake2, pk_seed, adrs, n)

#define HASH_T_UPDATE(k, d, l)                                               \
    slhdsakey_hash_update(&(k)->hash.shk.shake2, d, l)

#define HASH_T_FINAL(k, o, l)                                                \
    slhdsakey_hash_final(&(k)->hash.shk.shake2, o, l)

#define HASH_T_FREE(k)                                                       \
    slhdsakey_hash_free(&(k)->hash.shk.shake2)

#endif /* WOLFSSL_SLHDSA_SHA2 */

/* Start hashing with SHAKE-256.
 *
 * @param [in] shake  SHAKE-256 object.
 * @param [in] data   First block of data to hash.
 * @param [in] len    Length in bytes of first block of data.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_start(wc_Shake* shake, const byte* data, byte len)
{
#if defined(USE_INTEL_SPEEDUP)
    /* Clear state for new hash. */
    XMEMSET(shake->s, 0, sizeof(shake->s));
#endif
#ifdef WOLFSSL_SLHDSA_FULL_HASH
    /* Update the hash. */
    return wc_Shake256_Update(shake, data, len);
#else
    /* Copy the data to hash into the cache and update cached length. */
    XMEMCPY(shake->t, data, len);
    shake->i = len;

    return 0;
#endif
}

/* Start hashing with SHAKE-256. HashAddress to update too.
 *
 * @param [in] shake    SHAKE-256 object.
 * @param [in] pk_seed  Public key seed - a hash output.
 * @param [in] adrs     HashAddress.
 * @param [in] n        Number of bytes in hash output.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_start_addr(wc_Shake* shake, const byte* pk_seed,
    const word32* adrs, byte n)
{
#ifdef WOLFSSL_SLHDSA_FULL_HASH
    int ret;
    byte address[SLHDSA_HA_SZ];

    /* Encode HashAddress. */
    HA_Encode(adrs, address);

#if defined(USE_INTEL_SPEEDUP)
    /* Clear state for new hash. */
    XMEMSET(shake->s, 0, sizeof(shake->s));
#endif
    /* Update the hash with the public key seed. */
    ret = wc_Shake256_Update(shake, pk_seed, n);
    if (ret == 0) {
        /* Update the hash with the encoded HashAddress. */
        ret = wc_Shake256_Update(shake, address, SLHDSA_HA_SZ);
    }

    return ret;
#else
#if defined(USE_INTEL_SPEEDUP)
    /* Clear state for new hash. */
    XMEMSET(shake->s, 0, sizeof(shake->s));
#endif
    /* Copy the data to hash into the cache and update cached length. */
    XMEMCPY(shake->t, pk_seed, n);
    HA_Encode(adrs, shake->t + n);
    shake->i = n + SLHDSA_HA_SZ;

    return 0;
#endif
}

/* Update the hash with more data.
 *
 * @param [in] shake  SHAKE-256 object.
 * @param [in] data   Block of data to hash.
 * @param [in] len    Length in bytes of first block of data.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_update(wc_Shake* shake, const byte* data, word32 len)
{
    return wc_Shake256_Update(shake, data, len);
}

/* Calculate and output hash.
 *
 * @param [in]  shake  SHAKE-256 object.
 * @param [out] hash   Hash output.
 * @param [in]  len    Length of hash to output in bytes.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_final(wc_Shake* shake, byte* hash, word32 len)
{
    return wc_Shake256_Final(shake, hash, len);
}

/* Free internal resources.
 *
 * @param [in]  shake  SHAKE-256 object.
 */
static void slhdsakey_hash_free(wc_Shake* shake)
{
    wc_Shake256_Free(shake);
}

/******************************************************************************
 * Conversion functions
 ******************************************************************************/

/* Convert array of bytes to array of b-bit values.
 *
 * b is 6, 8, 9, 12 or 14.
 *
 * FIPS 205. Section 4.4. Algorithm 4.
 * base_2b(X, b, out_len)
 *   1: in <- 0
 *   2: bits <- 0
 *   3: total <- 0
 *   4: for out from 0 to out_len - 1 do
 *   5:     while bits < b do
 *   6:         total <- (total << 8) + X[in]
 *   7:         in <- in + 1
 *   8:         bits <- bits + 8
 *   9:     end while
 *  10:     bits <- bits - b
 *  11:     baseb[out] <- (total >> bits mod 2^b
 *  12: end for
 *  13: return baseb
 *
 * @param [in]  x       Array of bytes.
 * @param [in]  b       Number of bits.
 * @param [in]  outLen  Length of output array.
 * @param [out] baseb   Array of b-bit values.
 */
static void slhdsakey_base_2b(const byte* x, byte b, byte outLen, word16* baseb)
{
    int j;
    int i = 0;
    int bits = 0;
    int total = 0;
    word16 mask = (1 << b) - 1;

    for (j = 0; j < outLen; j++) {
        while (bits < b) {
            total = (total << 8) + x[i++];
            bits += 8;
        }
        bits -= b;
        baseb[j] = (total >> bits) & mask;
    }
}

/******************************************************************************
 * WOTS+
 ******************************************************************************/

/* Iterate the hash function s times.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  x        n-byte string.
 * @param [in]  i        Start index iterations.
 * @param [in]  s        Number of times to iterate.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [out] node     Hash output - n bytes.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_chain(SlhDsaKey* key, const byte* x, byte i, byte s,
    const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;
    int j;
    byte n = key->params->n;

    /* When no steps, copy. */
    if (s == 0) {
        /* Only copy when input and output buffers different. */
        if (x != node) {
            XMEMCPY(node, x, n);
        }
    }
    else {
        /* Set the hash address for first iteration. */
        HA_SetHashAddress(adrs, i);
        /* First iteration of hash using input and writing to output buffers. */
        ret = HASH_F(key, pk_seed, adrs, x, n, node);
        if (ret == 0) {
            for (j = i + 1; j < i + s; j++) {
                /* Set the hash address. */
                HA_SetHashAddress(adrs, j);
                /* Iterate hash using output buffer as input. */
                ret = HASH_F(key, pk_seed, adrs, node, n, node);
                if (ret != 0) {
                    break;
                }
            }
        }
    }

    return ret;
}

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
#ifndef WOLFSSL_SLHDSA_PARAM_NO_128
/* Set into SHAKE-256 x4 state the 16-byte seed and encoded HashAddress.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      seed   Seed at start of each hash.
 * @param [in]      addr   Encoded HashAddress for each hash.
 */
#define SHAKE256_SET_SEED_HA_X4_16(state, seed, addr)                       \
do {                                                                        \
    /* Set 4 copies of the seed 64-bits at a time. */                       \
    (state)[0] = (state)[1] = (state)[2] = (state)[3] =                     \
                        readUnalignedWord64((seed) + (0 * sizeof(word64))); \
    (state)[4] = (state)[5] = (state)[6] = (state)[7] =                     \
                        readUnalignedWord64((seed) + (1 * sizeof(word64))); \
    /* 32 bytes copied 8 bytes at a time. */                                \
    (state)[ 8] = (state)[ 9] = (state)[10] = (state)[11] =                 \
                        readUnalignedWord64((addr) + (0 * sizeof(word64))); \
    (state)[12] = (state)[13] = (state)[14] = (state)[15] =                 \
                        readUnalignedWord64((addr) + (1 * sizeof(word64))); \
    (state)[16] = (state)[17] = (state)[18] = (state)[19] =                 \
                        readUnalignedWord64((addr) + (2 * sizeof(word64))); \
    (state)[20] = (state)[21] = (state)[22] = (state)[23] =                 \
                        readUnalignedWord64((addr) + (3 * sizeof(word64))); \
} while (0)

/* Append to SHAKE-256 x4 state the 16-byte hash.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      hash   Hash data for each hash.
 */
#define SHAKE256_SET_HASH_X4_16(state, hash)                                \
do {                                                                        \
    (state)[24] = ((word64*)((hash) + 0 * 16))[0];                          \
    (state)[25] = ((word64*)((hash) + 1 * 16))[0];                          \
    (state)[26] = ((word64*)((hash) + 2 * 16))[0];                          \
    (state)[27] = ((word64*)((hash) + 3 * 16))[0];                          \
    (state)[28] = ((word64*)((hash) + 0 * 16))[1];                          \
    (state)[29] = ((word64*)((hash) + 1 * 16))[1];                          \
    (state)[30] = ((word64*)((hash) + 2 * 16))[1];                          \
    (state)[31] = ((word64*)((hash) + 3 * 16))[1];                          \
} while (0)

/* Get the four SHAKE-256 16-byte hash results.
 *
 * @param [in]  state  SHAKE-256 x4 state.
 * @param [out] hash   Hash buffer to hold 4 16-byte hash results.
 */
#define SHAKE256_GET_HASH_X4_16(state, hash)                                \
do {                                                                        \
    ((word64*)((hash) + 0 * 16))[0] = (state)[0];                           \
    ((word64*)((hash) + 1 * 16))[0] = (state)[1];                           \
    ((word64*)((hash) + 2 * 16))[0] = (state)[2];                           \
    ((word64*)((hash) + 3 * 16))[0] = (state)[3];                           \
    ((word64*)((hash) + 0 * 16))[1] = (state)[4];                           \
    ((word64*)((hash) + 1 * 16))[1] = (state)[5];                           \
    ((word64*)((hash) + 2 * 16))[1] = (state)[6];                           \
    ((word64*)((hash) + 3 * 16))[1] = (state)[7];                           \
} while (0)
#endif

#ifndef WOLFSSL_SLHDSA_PARAM_NO_192
/* Set into SHAKE-256 x4 state the 24-byte seed and encoded HashAddress.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      seed   Seed at start of each hash.
 * @param [in]      addr   Encoded HashAddress for each hash.
 */
#define SHAKE256_SET_SEED_HA_X4_24(state, seed, addr)                       \
do {                                                                        \
    (state)[0] = (state)[1] = (state)[ 2] = (state)[ 3] =                   \
                        readUnalignedWord64((seed) + (0 * sizeof(word64))); \
    (state)[4] = (state)[5] = (state)[ 6] = (state)[ 7] =                   \
                        readUnalignedWord64((seed) + (1 * sizeof(word64))); \
    (state)[8] = (state)[9] = (state)[10] = (state)[11] =                   \
                        readUnalignedWord64((seed) + (2 * sizeof(word64))); \
    /* 32 bytes copied 8 bytes at a time. */                                \
    (state)[12] = (state)[13] = (state)[14] = (state)[15] =                 \
                        readUnalignedWord64((addr) + (0 * sizeof(word64))); \
    (state)[16] = (state)[17] = (state)[18] = (state)[19] =                 \
                        readUnalignedWord64((addr) + (1 * sizeof(word64))); \
    (state)[20] = (state)[21] = (state)[22] = (state)[23] =                 \
                        readUnalignedWord64((addr) + (2 * sizeof(word64))); \
    (state)[24] = (state)[25] = (state)[26] = (state)[27] =                 \
                        readUnalignedWord64((addr) + (3 * sizeof(word64))); \
} while (0)

/* Append to SHAKE-256 x4 state the 24-byte hash.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      hash   Hash data for each hash.
 */
#define SHAKE256_SET_HASH_X4_24(state, hash)                                \
do {                                                                        \
    (state)[28] = ((word64*)((hash) + 0 * 24))[0];                          \
    (state)[29] = ((word64*)((hash) + 1 * 24))[0];                          \
    (state)[30] = ((word64*)((hash) + 2 * 24))[0];                          \
    (state)[31] = ((word64*)((hash) + 3 * 24))[0];                          \
    (state)[32] = ((word64*)((hash) + 0 * 24))[1];                          \
    (state)[33] = ((word64*)((hash) + 1 * 24))[1];                          \
    (state)[34] = ((word64*)((hash) + 2 * 24))[1];                          \
    (state)[35] = ((word64*)((hash) + 3 * 24))[1];                          \
    (state)[36] = ((word64*)((hash) + 0 * 24))[2];                          \
    (state)[37] = ((word64*)((hash) + 1 * 24))[2];                          \
    (state)[38] = ((word64*)((hash) + 2 * 24))[2];                          \
    (state)[39] = ((word64*)((hash) + 3 * 24))[2];                          \
} while (0)

/* Get the four SHAKE-256 24-byte (hash) results.
 *
 * @param [in]  state  SHAKE-256 x4 state.
 * @param [out] hash   Hash buffer to hold 4 24-byte hash results.
 */
#define SHAKE256_GET_HASH_X4_24(state, hash)                                \
do {                                                                        \
    ((word64*)((hash) + 0 * 24))[0] = (state)[ 0];                          \
    ((word64*)((hash) + 1 * 24))[0] = (state)[ 1];                          \
    ((word64*)((hash) + 2 * 24))[0] = (state)[ 2];                          \
    ((word64*)((hash) + 3 * 24))[0] = (state)[ 3];                          \
    ((word64*)((hash) + 0 * 24))[1] = (state)[ 4];                          \
    ((word64*)((hash) + 1 * 24))[1] = (state)[ 5];                          \
    ((word64*)((hash) + 2 * 24))[1] = (state)[ 6];                          \
    ((word64*)((hash) + 3 * 24))[1] = (state)[ 7];                          \
    ((word64*)((hash) + 0 * 24))[2] = (state)[ 8];                          \
    ((word64*)((hash) + 1 * 24))[2] = (state)[ 9];                          \
    ((word64*)((hash) + 2 * 24))[2] = (state)[10];                          \
    ((word64*)((hash) + 3 * 24))[2] = (state)[11];                          \
} while (0)
#endif

#ifndef WOLFSSL_SLHDSA_PARAM_NO_256
/* Set into SHAKE-256 x4 state the 32-byte seed and encoded HashAddress.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      seed   Seed at start of each hash.
 * @param [in]      addr   Encoded HashAddress for each hash.
 */
#define SHAKE256_SET_SEED_HA_X4_32(state, seed, addr)                       \
do {                                                                        \
    (state)[ 0] = (state)[ 1] = (state)[ 2] = (state)[ 3] =                 \
                        readUnalignedWord64((seed) + (0 * sizeof(word64))); \
    (state)[ 4] = (state)[ 5] = (state)[ 6] = (state)[ 7] =                 \
                        readUnalignedWord64((seed) + (1 * sizeof(word64))); \
    (state)[ 8] = (state)[ 9] = (state)[10] = (state)[11] =                 \
                        readUnalignedWord64((seed) + (2 * sizeof(word64))); \
    (state)[12] = (state)[13] = (state)[14] = (state)[15] =                 \
                        readUnalignedWord64((seed) + (3 * sizeof(word64))); \
    /* 32 bytes copied 8 bytes at a time. */                                \
    (state)[16] = (state)[17] = (state)[18] = (state)[19] =                 \
                        readUnalignedWord64((addr) + (0 * sizeof(word64))); \
    (state)[20] = (state)[21] = (state)[22] = (state)[23] =                 \
                        readUnalignedWord64((addr) + (1 * sizeof(word64))); \
    (state)[24] = (state)[25] = (state)[26] = (state)[27] =                 \
                        readUnalignedWord64((addr) + (2 * sizeof(word64))); \
    (state)[28] = (state)[29] = (state)[30] = (state)[31] =                 \
                        readUnalignedWord64((addr) + (3 * sizeof(word64))); \
} while (0)

/* Append to SHAKE-256 x4 state the 32-byte hash.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      hash   Hash data for each hash.
 */
#define SHAKE256_SET_HASH_X4_32(state, hash)                                \
do {                                                                        \
    (state)[32] = ((word64*)((hash) + 0 * 32))[0];                          \
    (state)[33] = ((word64*)((hash) + 1 * 32))[0];                          \
    (state)[34] = ((word64*)((hash) + 2 * 32))[0];                          \
    (state)[35] = ((word64*)((hash) + 3 * 32))[0];                          \
    (state)[36] = ((word64*)((hash) + 0 * 32))[1];                          \
    (state)[37] = ((word64*)((hash) + 1 * 32))[1];                          \
    (state)[38] = ((word64*)((hash) + 2 * 32))[1];                          \
    (state)[39] = ((word64*)((hash) + 3 * 32))[1];                          \
    (state)[40] = ((word64*)((hash) + 0 * 32))[2];                          \
    (state)[41] = ((word64*)((hash) + 1 * 32))[2];                          \
    (state)[42] = ((word64*)((hash) + 2 * 32))[2];                          \
    (state)[43] = ((word64*)((hash) + 3 * 32))[2];                          \
    (state)[44] = ((word64*)((hash) + 0 * 32))[3];                          \
    (state)[45] = ((word64*)((hash) + 1 * 32))[3];                          \
    (state)[46] = ((word64*)((hash) + 2 * 32))[3];                          \
    (state)[47] = ((word64*)((hash) + 3 * 32))[3];                          \
} while (0)

/* Get the four SHAKE-256 32-byte hash results.
 *
 * @param [in]  state  SHAKE-256 x4 state.
 * @param [out] hash   Hash buffer to hold 4 32-byte hash results.
 */
#define SHAKE256_GET_HASH_X4_32(state, hash)                                \
do {                                                                        \
    ((word64*)((hash) + 0 * 32))[0] = (state)[ 0];                          \
    ((word64*)((hash) + 1 * 32))[0] = (state)[ 1];                          \
    ((word64*)((hash) + 2 * 32))[0] = (state)[ 2];                          \
    ((word64*)((hash) + 3 * 32))[0] = (state)[ 3];                          \
    ((word64*)((hash) + 0 * 32))[1] = (state)[ 4];                          \
    ((word64*)((hash) + 1 * 32))[1] = (state)[ 5];                          \
    ((word64*)((hash) + 2 * 32))[1] = (state)[ 6];                          \
    ((word64*)((hash) + 3 * 32))[1] = (state)[ 7];                          \
    ((word64*)((hash) + 0 * 32))[2] = (state)[ 8];                          \
    ((word64*)((hash) + 1 * 32))[2] = (state)[ 9];                          \
    ((word64*)((hash) + 2 * 32))[2] = (state)[10];                          \
    ((word64*)((hash) + 3 * 32))[2] = (state)[11];                          \
    ((word64*)((hash) + 0 * 32))[3] = (state)[12];                          \
    ((word64*)((hash) + 1 * 32))[3] = (state)[13];                          \
    ((word64*)((hash) + 2 * 32))[3] = (state)[14];                          \
    ((word64*)((hash) + 3 * 32))[3] = (state)[15];                          \
} while (0)
#endif

/* Set the end of the SHAKE256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      o      Offset to end of data.
 */
#define SHAKE256_SET_END_X4(state, o)                                       \
do {                                                                        \
    /* Data end marker. */                                                  \
    (state)[(o) + 0] = (word64)0x1f;                                        \
    (state)[(o) + 1] = (word64)0x1f;                                        \
    (state)[(o) + 2] = (word64)0x1f;                                        \
    (state)[(o) + 3] = (word64)0x1f;                                        \
    XMEMSET((state) + (o) + 4, 0, (25 * 4 - ((o) + 4)) * sizeof(word64));   \
    /* SHAKE-256 (state) end marker. */                                     \
    ((word8*)((state) + 4 * WC_SHA3_256_COUNT - 4))[7] ^= 0x80;             \
    ((word8*)((state) + 4 * WC_SHA3_256_COUNT - 3))[7] ^= 0x80;             \
    ((word8*)((state) + 4 * WC_SHA3_256_COUNT - 2))[7] ^= 0x80;             \
    ((word8*)((state) + 4 * WC_SHA3_256_COUNT - 1))[7] ^= 0x80;             \
} while (0)

/* Set into SHAKE-256 x4 state the n-byte seed and encoded HashAddress.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      seed   Seed at start of each hash.
 * @param [in]      addr   Encoded HashAddress for each hash.
 * @param [in]      n      Number of bytes of seed.
 * @return  Offset after seed and HashAddress.
 */
static int slhdsakey_shake256_set_seed_ha_x4(word64* state, const byte* seed,
    const byte* addr, int n)
{
    int i;
    int o = 0;

    /* Set 4 copies of the seed 64-bits at a time. */
    for (i = 0; i < n; i += 8) {
        state[o + 0] = state[o + 1] = state[o + 2] = state[o + 3] =
                readUnalignedWord64(seed + i);
        o += 4;
    }
    /* 32 bytes copied 8 bytes at a time. */
    for (i = 0; i < SLHDSA_HA_SZ; i += 8) {
        state[o + 0] = state[o + 1] = state[o + 2] = state[o + 3] =
            readUnalignedWord64(addr + i);
        o += 4;
    }

    return o;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Fill out SHAKE-256 x4 state with n-byte seed, encoded HashAddress and hash.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      seed   Seed at start of each hash.
 * @param [in]      addr   Encoded HashAddress for each hash.
 * @param [in]      hash   Hash data to put into each hash.
 * @param [in]      n      Number of bytes of seed.
 * @return  Offset after seed and HashAddress.
 */
static int slhdsakey_shake256_set_seed_ha_hash_x4(word64* state,
    const byte* seed, const byte* addr, const byte* hash, int n)
{
    int i;
    int o = 0;
    int ret;

    ret = o = slhdsakey_shake256_set_seed_ha_x4(state, seed, addr, n);
    for (i = 0; i < n; i += 8) {
        state[o + 0] = state[o + 1] = state[o + 2] = state[o + 3] =
            readUnalignedWord64(hash + i);
        o += 4;
    }

    SHAKE256_SET_END_X4(state, o);

    return ret;
}
#endif /* WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Get the four SHAKE-256 n-byte hash results.
 *
 * @param [in]  state  SHAKE-256 x4 state.
 * @param [out] hash   Hash buffer to hold 4 n-byte hash results.
 * @param [in]  n      Length of each hash in bytes.
 */
static void slhdsakey_shake256_get_hash_x4(const word64* state, byte* hash,
    int n)
{
    int i;

    for (i = 0; i < (n / 8); i++) {
        ((word64*)(hash + 0 * n))[i] = state[4 * i + 0];
        ((word64*)(hash + 1 * n))[i] = state[4 * i + 1];
        ((word64*)(hash + 2 * n))[i] = state[4 * i + 2];
        ((word64*)(hash + 3 * n))[i] = state[4 * i + 3];
    }
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Set the chain address into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      o      Offset of state after HashAddress.
 * @param [in]      a      Value to set that increments for each hash.
 */
#define SHAKE256_SET_CHAIN_ADDRESS(state, o, a)                             \
do {                                                                        \
    ((word8*)((state) + (o) - 4))[3] = (a) + 0;                             \
    ((word8*)((state) + (o) - 3))[3] = (a) + 1;                             \
    ((word8*)((state) + (o) - 2))[3] = (a) + 2;                             \
    ((word8*)((state) + (o) - 1))[3] = (a) + 3;                             \
} while (0)
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Set the chain address indices into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      o      Offset of state after HashAddress.
 * @param [in]      idx    Indices to set for each hash.
 */
#define SHAKE256_SET_CHAIN_ADDRESS_IDX(state, o, idx)                       \
do {                                                                        \
    ((word8*)((state) + (o) - 4))[3] = (idx)[0];                            \
    ((word8*)((state) + (o) - 3))[3] = (idx)[1];                            \
    ((word8*)((state) + (o) - 2))[3] = (idx)[2];                            \
    ((word8*)((state) + (o) - 1))[3] = (idx)[3];                            \
} while (0)

/* Set the hash address into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      (o)      Offset of state after HashAddress.
 * @param [in]      a      Value to set for each hash.
 */
#define SHAKE256_SET_HASH_ADDRESS(state, o, a)                              \
do {                                                                        \
    ((word8*)((state) + (o) - 4))[7] = (a);                                 \
    ((word8*)((state) + (o) - 3))[7] = (a);                                 \
    ((word8*)((state) + (o) - 2))[7] = (a);                                 \
    ((word8*)((state) + (o) - 1))[7] = (a);                                 \
} while (0)

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Set the tree index into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      (o)      Offset of state after HashAddress.
 * @param [in]      ti     Value to encode that increments for each hash.
 */
#define SHAKE256_SET_TREE_INDEX(state, o, ti)                               \
do {                                                                        \
    c32toa((ti) + 0, (byte*)&((word32*)((state) + (o) - 4))[1]);            \
    c32toa((ti) + 1, (byte*)&((word32*)((state) + (o) - 3))[1]);            \
    c32toa((ti) + 2, (byte*)&((word32*)((state) + (o) - 2))[1]);            \
    c32toa((ti) + 3, (byte*)&((word32*)((state) + (o) - 1))[1]);            \
} while (0)
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Set the tree indices into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      (o)      Offset of state after HashAddress.
 * @param [in]      ti     Indices to encode for each hash.
 */
#define SHAKE256_SET_TREE_INDEX_IDX(state, o, ti)                           \
do {                                                                        \
    c32toa((ti)[0], (byte*)&((word32*)((state) + (o) - 4))[1]);             \
    c32toa((ti)[1], (byte*)&((word32*)((state) + (o) - 3))[1]);             \
    c32toa((ti)[2], (byte*)&((word32*)((state) + (o) - 2))[1]);             \
    c32toa((ti)[3], (byte*)&((word32*)((state) + (o) - 1))[1]);             \
} while (0)

/* Set the tree height into the SHAKE-256 x4 state.
 *
 * @param [in, out] state  SHAKE-256 x4 state.
 * @param [in]      (o)      Offset of state after HashAddress.
 * @param [in]      ti     Value to encode for each hash.
 */
#define SHAKE256_SET_TREE_HEIGHT(state, o, th)                              \
do {                                                                        \
    c32toa((th), (byte*)&((word32*)((state) + (o) - 4))[0]);                \
    c32toa((th), (byte*)&((word32*)((state) + (o) - 3))[0]);                \
    c32toa((th), (byte*)&((word32*)((state) + (o) - 2))[0]);                \
    c32toa((th), (byte*)&((word32*)((state) + (o) - 1))[0]);                \
} while (0)

#ifndef WOLFSSL_SLHDSA_PARAM_NO_128
/* Iterate the hash function s times with 4 hashes when n=16.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      i        Start index iterations.
 * @param [in]      s        Number of times to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      idx      Indices for chain address.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_x4_16(byte* sk, byte i, byte s,
    const byte* pk_seed, byte* addr, byte* idx, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 6 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 6 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_16(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS_IDX(fixed, 24, idx);
        SHAKE256_SET_HASH_X4_16(state, sk);

        for (j = i; j < i + s; j++) {
            if (j != i) {
                XMEMCPY(state + 24, state, 16 * 4);
            }
            XMEMCPY(state, fixed, (6 * 4) * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 24, j);
            SHAKE256_SET_END_X4(state, 32);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                return ret;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        SHAKE256_GET_HASH_X4_16(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_192
/* Iterate the hash function s times with 4 hashes when n=24.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      i        Start index iterations.
 * @param [in]      s        Number of times to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      idx      Indices for chain address.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_x4_24(byte* sk, byte i, byte s,
    const byte* pk_seed, byte* addr, byte* idx, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 7 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 7 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_24(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS_IDX(fixed, 28, idx);
        SHAKE256_SET_HASH_X4_24(state, sk);

        for (j = i; j < i + s; j++) {
            if (j != i) {
                XMEMCPY(state + 28, state, 24 * 4);
            }
            XMEMCPY(state, fixed, 28 * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 28, j);
            SHAKE256_SET_END_X4(state, 40);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                return ret;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        SHAKE256_GET_HASH_X4_24(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif
#ifndef WOLFSSL_SLHDSA_PARAM_NO_256
/* Iterate the hash function s times with 4 hashes when n=32.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      i        Start index iterations.
 * @param [in]      s        Number of times to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      idx      Indices for chain address.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_x4_32(byte* sk, byte i, byte s,
    const byte* pk_seed, byte* addr, byte* idx, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 8 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 8 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_32(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS_IDX(fixed, 32, idx);
        SHAKE256_SET_HASH_X4_32(state, sk);

        for (j = i; j < i + s; j++) {
            if (j != i) {
                XMEMCPY(state + 32, state, 32 * 4);
            }
            XMEMCPY(state, fixed, 32 * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 32, j);
            SHAKE256_SET_END_X4(state, 48);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                return ret;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        SHAKE256_GET_HASH_X4_32(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif
#endif

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
/* PRF hash 4 simultaneously.
 *
 * Each hash varies by the chain address with the first value in sequence passed
 * in.
 *
 * FIPS 205. Section 4.1.
 *   PRF(PK.seed, SK.seed, ADRS) (Bn x Bn x B32 -> Bn) is a PRF that is used to
 *   generate the secret values in WOTS+ and FORS private keys.
 * FIPS 205. Section 11.1.
 *   PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
 *
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  n        Number of bytes in hash output.
 * @param [in]  ca       Chain address start index.
 * @param [out] sk       Buffer to hold hash output.
 * @param [in]  heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_prf_x4(const byte* pk_seed, const byte* sk_seed,
    byte* addr, byte n, byte ca, byte* sk, void* heap)
{
    int ret = 0;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_hash_x4(state, pk_seed, addr,
            sk_seed, n);
        SHAKE256_SET_CHAIN_ADDRESS(state, o, ca);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            slhdsakey_shake256_get_hash_x4(state, sk, n);
            RESTORE_VECTOR_REGISTERS();
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
/* Iterate the hash function 15 times with 4 hashes when n=16.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      ca       Chain address start index.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_x4_16(byte* sk, const byte* pk_seed, byte* addr,
    byte ca, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 8 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 8 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_16(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS(fixed, 24, ca);
        SHAKE256_SET_HASH_X4_16(state, sk);

        for (j = 0; j < 15; j++) {
            if (j != 0) {
                XMEMCPY(state + 24, state, 16 * 4);
            }
            XMEMCPY(state, fixed, 24 * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 24, j);
            SHAKE256_SET_END_X4(state, 32);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                break;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        if (ret == 0)
            SHAKE256_GET_HASH_X4_16(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
/* Iterate the hash function 15 times with 4 hashes when n=24.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      ca       Chain address start index.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_x4_24(byte* sk, const byte* pk_seed, byte* addr,
    byte ca, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 8 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 8 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_24(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS(fixed, 28, ca);
        SHAKE256_SET_HASH_X4_24(state, sk);

        for (j = 0; j < 15; j++) {
            if (j != 0) {
                XMEMCPY(state + 28, state, 24 * 4);
            }
            XMEMCPY(state, fixed, 28 * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 28, j);
            SHAKE256_SET_END_X4(state, 40);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                break;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        if (ret == 0)
            SHAKE256_GET_HASH_X4_24(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
/* Iterate the hash function 15 times with 4 hashes when n=32.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in, out] sk       4 hashes to iterate.
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in]      ca       Chain address start index.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_x4_32(byte* sk, const byte* pk_seed, byte* addr,
    byte ca, void* heap)
{
    int ret = 0;
    int j;
    WC_DECLARE_VAR(fixed, word64, 8 * 4, heap);
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(fixed, word64, 8 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
            ret = MEMORY_E);
    }
    if (ret == 0) {
        SHAKE256_SET_SEED_HA_X4_32(fixed, pk_seed, addr);
        SHAKE256_SET_CHAIN_ADDRESS(fixed, 32, ca);
        SHAKE256_SET_HASH_X4_32(state, sk);

        for (j = 0; j < 15; j++) {
            if (j != 0) {
                XMEMCPY(state + 32, state, 32 * 4);
            }
            XMEMCPY(state, fixed, 32 * sizeof(word64));
            SHAKE256_SET_HASH_ADDRESS(state, 32, j);
            SHAKE256_SET_END_X4(state, 48);
            ret = SAVE_VECTOR_REGISTERS2();
            if (ret != 0)
                break;
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
        }

        if (ret == 0)
            SHAKE256_GET_HASH_X4_32(state, sk);
    }

    WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    WC_FREE_VAR_EX(fixed, heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

/* PRF hash 4 simultaneously.
 *
 * Each hash varies by the chain address which is passed in as an array.
 *
 * FIPS 205. Section 4.1.
 *   PRF(PK.seed, SK.seed, ADRS) (Bn x Bn x B32 -> Bn) is a PRF that is used to
 *   generate the secret values in WOTS+ and FORS private keys.
 * FIPS 205. Section 11.1.
 *   PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
 *
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  n        Number of bytes in hash output.
 * @param [in]  idx      Four chain address indices.
 * @param [out] sk       Buffer to hold hash output.
 * @param [in]  heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_hash_prf_idx_x4(const byte* pk_seed, const byte* sk_seed,
    byte* addr, byte n, byte* idx, byte* sk, void* heap)
{
    int ret = 0;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_hash_x4(state, pk_seed, addr,
            sk_seed, n);
        SHAKE256_SET_CHAIN_ADDRESS_IDX(state, o, idx);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, sk, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
/* Iterate hash function up to index times for each of the hashes when n=16.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk       Hashes to iterate. Data modified.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  msg      Array of counts.
 * @param [in]  idx      Indices into array of counts.
 * @param [in]  j        Minimum number of iterations for all 4 hashes.
 * @param [in]  cnt      Number of hashes to iterate.
 * @param [out] sig      Hash results.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_16(SlhDsaKey* key, byte* sk,
     const byte* pk_seed, word32* adrs, byte* addr, const byte* msg, byte* idx,
     int j, int cnt, byte* sig)
{
    int ret = 0;

    /* Iterate the minimum number of iterations on all hashes. */
    if (j != 0) {
        ret = slhdsakey_chain_idx_x4_16(sk, 0, j, pk_seed, addr, idx,
            key->heap);
    }
    if (ret == 0) {
        if (cnt > 3) {
            /* Copy out hash at index 3 as it is finished. */
            XMEMCPY(sig + idx[3] * 16, sk + 3 * 16, 16);
        }
        /* Check if more iterations needed for index 2. */
        if (msg[idx[2]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_16(sk, j, msg[idx[2]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[2]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 2 as it is finished. */
        XMEMCPY(sig + idx[2] * 16, sk + 2 * 16, 16);
        /* Check if more iterations needed for index 1. */
        if (msg[idx[1]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_16(sk, j, msg[idx[1]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[1]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 1 as it is finished. */
        XMEMCPY(sig + idx[1] * 16, sk + 1 * 16, 16);
        /* Check if more iterations needed for index 0. */
        if (msg[idx[0]] != j) {
            /* Iterate 1 hash as it takes less time than doing 4. */
            HA_SetChainAddress(adrs, idx[0]);
            ret = slhdsakey_chain(key, sk, j, msg[idx[0]] - j, pk_seed, adrs,
                sk);
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 0 as it is finished. */
        XMEMCPY(sig + idx[0] * 16, sk + 0 * 16, 16);
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
/* Iterate hash function up to index times for each of the hashes when n=24.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk       Hashes to iterate. Data modified.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  msg      Array of counts.
 * @param [in]  idx      Indices into array of counts.
 * @param [in]  j        Minimum number of iterations for all 4 hashes.
 * @param [in]  cnt      Number of hashes to iterate.
 * @param [out] sig      Hash results.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_24(SlhDsaKey* key, byte* sk,
     const byte* pk_seed, word32* adrs, byte* addr, const byte* msg, byte* idx,
     int j, int cnt, byte* sig)
{
    int ret = 0;

    /* Iterate the minimum number of iterations on all hashes. */
    if (j != 0) {
        ret = slhdsakey_chain_idx_x4_24(sk, 0, j, pk_seed, addr, idx,
            key->heap);
    }
    if (ret == 0) {
        if (cnt > 3) {
            /* Copy out hash at index 3 as it is finished. */
            XMEMCPY(sig + idx[3] * 24, sk + 3 * 24, 24);
        }
        /* Check if more iterations needed for index 2. */
        if (msg[idx[2]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_24(sk, j, msg[idx[2]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[2]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 2 as it is finished. */
        XMEMCPY(sig + idx[2] * 24, sk + 2 * 24, 24);
        /* Check if more iterations needed for index 1. */
        if (msg[idx[1]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_24(sk, j, msg[idx[1]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[1]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 1 as it is finished. */
        XMEMCPY(sig + idx[1] * 24, sk + 1 * 24, 24);
        /* Check if more iterations needed for index 0. */
        if (msg[idx[0]] != j) {
            /* Iterate 1 hash as it takes less time than doing 4. */
            HA_SetChainAddress(adrs, idx[0]);
            ret = slhdsakey_chain(key, sk, j, msg[idx[0]] - j, pk_seed, adrs,
                sk);
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 0 as it is finished. */
        XMEMCPY(sig + idx[0] * 24, sk + 0 * 24, 24);
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
/* Iterate hash function up to index times for each of the hashes when n=32.
 *
 * FIPS 205. Section 5. Algorithm 5.
 * chain(X, i, s, PK.seed, ADRS)
 *   1: tmp <- X
 *   2: for j from i to i + s - 1 do
 *   3:     ADRS.setHashAddress(j)
 *   4:     tmp <- F(PK.seed, ADRS, tmp
 *   5: end for
 *   6: return tmp
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk       Hashes to iterate. Data modified.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  msg      Array of counts.
 * @param [in]  idx      Indices into array of counts.
 * @param [in]  j        Minimum number of iterations for all 4 hashes.
 * @param [in]  cnt      Number of hashes to iterate.
 * @param [out] sig      Hash results.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_32(SlhDsaKey* key, byte* sk,
     const byte* pk_seed, word32* adrs, byte* addr, const byte* msg, byte* idx,
     int j, int cnt, byte* sig)
{
    int ret = 0;

    /* Iterate the minimum number of iterations on all hashes. */
    if (j != 0) {
        ret = slhdsakey_chain_idx_x4_32(sk, 0, j, pk_seed, addr, idx,
            key->heap);
    }
    if (ret == 0) {
        if (cnt > 3) {
            /* Copy out hash at index 3 as it is finished. */
            XMEMCPY(sig + idx[3] * 32, sk + 3 * 32, 32);
        }
        /* Check if more iterations needed for index 2. */
        if (msg[idx[2]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_32(sk, j, msg[idx[2]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[2]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 2 as it is finished. */
        XMEMCPY(sig + idx[2] * 32, sk + 2 * 32, 32);
        /* Check if more iterations needed for index 1. */
        if (msg[idx[1]] != j) {
            /* Do 4 as we can't do less. */
            ret = slhdsakey_chain_idx_x4_32(sk, j, msg[idx[1]] - j, pk_seed,
                addr, idx, key->heap);
            /* Update number of iterations performed. */
            j = msg[idx[1]];
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 1 as it is finished. */
        XMEMCPY(sig + idx[1] * 32, sk + 1 * 32, 32);
        /* Check if more iterations needed for index 0. */
        if (msg[idx[0]] != j) {
            /* Iterate 1 hash as it takes less time than doing 4. */
            HA_SetChainAddress(adrs, idx[0]);
            ret = slhdsakey_chain(key, sk, j, msg[idx[0]] - j, pk_seed, adrs,
                sk);
        }
    }
    if (ret == 0) {
        /* Copy out hash at index 0 as it is finished. */
        XMEMCPY(sig + idx[0] * 32, sk + 0 * 32, 32);
    }

    return ret;
}
#endif
#endif

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
/* Generate WOTS+ public key, 16-byte hashes - 4 consecutive at a time.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *  ...
 *   4: for i from 0 to len - 1 do
 *   5:     skADRS.setChainAddress(i)
 *   6:     sk <- PRF(PK.seed, SK.seed, skADRS)
 *                                            > compute secret value for chain i
 *   7:     ADRS.setChainAddress(i)
 *   8:     tmp[i] <- chain(sk 0, w - 1, PK.seed, ADRS)
 *                                            > compute public value for chain i
 *   9: end for
 *  10: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  ...
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  ...
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] addr     Encoded HashAddress.
 * @param [in] sk_addr  Encoded WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_wots_pkgen_chain_x4_16(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, byte* addr, byte* sk_addr)
{
    int ret = 0;
    int i;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 16, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 16, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        for (i = 0; i < len - 3; i += 4) {
            ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 16, i,
                sk + i * 16, key->heap);
            if (ret != 0) {
                break;
            }
            ret = slhdsakey_chain_x4_16(sk + i * 16, pk_seed, addr, i,
                key->heap);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 16, i,
            sk + i * 16, key->heap);
        if (ret == 0) {
            ret = slhdsakey_chain_x4_16(sk + i * 16, pk_seed, addr, i,
                key->heap);
        }
    }
    if (ret == 0) {
        ret = HASH_T_UPDATE(key, sk, len * 16);
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
/* Generate WOTS+ public key, 24-byte hashes - 4 consecutive at a time.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *  ...
 *   4: for i from 0 to len - 1 do
 *   5:     skADRS.setChainAddress(i)
 *   6:     sk <- PRF(PK.seed, SK.seed, skADRS)
 *                                            > compute secret value for chain i
 *   7:     ADRS.setChainAddress(i)
 *   8:     tmp[i] <- chain(sk 0, w - 1, PK.seed, ADRS)
 *                                            > compute public value for chain i
 *   9: end for
 *  10: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  ...
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  ...
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] addr     Encoded HashAddress.
 * @param [in] sk_addr  Encoded WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_wots_pkgen_chain_x4_24(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, byte* addr, byte* sk_addr)
{
    int ret = 0;
    int i;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 24, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 24, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        for (i = 0; i < len - 3; i += 4) {
            ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 24, i,
                sk + i * 24, key->heap);
            if (ret != 0) {
                break;
            }
            ret = slhdsakey_chain_x4_24(sk + i * 24, pk_seed, addr, i,
                key->heap);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 24, i,
            sk + i * 24, key->heap);
        if (ret == 0) {
            ret = slhdsakey_chain_x4_24(sk + i * 24, pk_seed, addr, i,
                key->heap);
        }
    }
    if (ret == 0) {
        ret = HASH_T_UPDATE(key, sk, len * 24);
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
/* Generate WOTS+ public key, 32-byte hashes - 4 consecutive at a time.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *  ...
 *   4: for i from 0 to len - 1 do
 *   5:     skADRS.setChainAddress(i)
 *   6:     sk <- PRF(PK.seed, SK.seed, skADRS)
 *                                            > compute secret value for chain i
 *   7:     ADRS.setChainAddress(i)
 *   8:     tmp[i] <- chain(sk 0, w - 1, PK.seed, ADRS)
 *                                            > compute public value for chain i
 *   9: end for
 *  10: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  ...
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  ...
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] addr     Encoded HashAddress.
 * @param [in] sk_addr  Encoded WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_wots_pkgen_chain_x4_32(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, byte* addr, byte* sk_addr)
{
    int ret = 0;
    int i;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 32, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * 32, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        for (i = 0; i < len - 3; i += 4) {
            ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 32, i,
                sk + i * 32, key->heap);
            if (ret != 0) {
                break;
            }
            ret = slhdsakey_chain_x4_32(sk + i * 32, pk_seed, addr, i,
                key->heap);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        ret = slhdsakey_hash_prf_x4(pk_seed, sk_seed, sk_addr, 32, i,
            sk + i * 32, key->heap);
        if (ret == 0) {
            ret = slhdsakey_chain_x4_32(sk + i * 32, pk_seed, addr, i,
                key->heap);
        }
    }
    if (ret == 0) {
        ret = HASH_T_UPDATE(key, sk, len * 32);
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

/* Generate WOTS+ public key - 4 consecutive addresses at a time.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *  ...
 *   4: for i from 0 to len - 1 do
 *   5:     skADRS.setChainAddress(i)
 *   6:     sk <- PRF(PK.seed, SK.seed, skADRS)
 *                                            > compute secret value for chain i
 *   7:     ADRS.setChainAddress(i)
 *   8:     tmp[i] <- chain(sk 0, w - 1, PK.seed, ADRS)
 *                                            > compute public value for chain i
 *   9: end for
 *  10: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  ...
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  ...
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] adrs     HashAddress.
 * @param [in] sk_adrs  WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_wots_pkgen_chain_x4(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, word32* adrs, word32* sk_adrs)
{
    int ret = 0;
    byte sk_addr[SLHDSA_HA_SZ];
    byte addr[SLHDSA_HA_SZ];
    byte n = key->params->n;

    HA_SetHashAddress(sk_adrs, 0);
    HA_Encode(sk_adrs, sk_addr);
    HA_Encode(adrs, addr);

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
    if (n == WC_SLHDSA_N_128) {
        ret = slhdsakey_wots_pkgen_chain_x4_16(key, sk_seed, pk_seed, addr,
            sk_addr);
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    if (n == 24) {
        ret = slhdsakey_wots_pkgen_chain_x4_24(key, sk_seed, pk_seed, addr,
            sk_addr);
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
    if (n == 32) {
        ret = slhdsakey_wots_pkgen_chain_x4_32(key, sk_seed, pk_seed, addr,
            sk_addr);
    }
    else
#endif
    if (ret == 0) {
        ret = NOT_COMPILED_IN;
    }

    return ret;
}
#endif

/* Generate WOTS+ public key.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *  ...
 *   4: for i from 0 to len - 1 do
 *   5:     skADRS.setChainAddress(i)
 *   6:     sk <- PRF(PK.seed, SK.seed, skADRS)
 *                                            > compute secret value for chain i
 *   7:     ADRS.setChainAddress(i)
 *   8:     tmp[i] <- chain(sk 0, w - 1, PK.seed, ADRS)
 *                                            > compute public value for chain i
 *   9: end for
 *  10: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  ...
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  ...
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] adrs     HashAddress.
 * @param [in] sk_adrs  WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_pkgen_chain_c(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, word32* adrs, word32* sk_adrs)
{
    int ret = 0;
    int i;
    byte n = key->params->n;
    byte len = key->params->len;

#if !defined(WOLFSSL_WC_SLHDSA_SMALL_MEM)
    WC_DECLARE_VAR(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * SLHDSA_MAX_N, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, (SLHDSA_MAX_MSG_SZ + 3) * SLHDSA_MAX_N,
        key->heap, DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        /* Step 4. len consecutive addresses. */
        for (i = 0; i < len; i++) {
            /* Step 5. Set chain address for WOTS PRF. */
            HA_SetChainAddress(sk_adrs, i);
            /* Step 6. PRF hash seeds and chain address. */
            ret = HASH_PRF(key, pk_seed, sk_seed, sk_adrs, n,
                sk + i * n);
            if (ret != 0) {
                break;
            }
            /* Step 7. Set chain address for WOTS HASH. */
            HA_SetChainAddress(adrs, i);
            /* Step 8. Chain hashes for w-1 iterations. */
            ret = slhdsakey_chain(key, sk + i * n, 0, SLHDSA_WM1, pk_seed, adrs,
                sk + i * n);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        /* Step 13: Compress public key. */
        ret = HASH_T_UPDATE(key, sk, len * n);
    }
    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
#else
    /* Step 4. len consecutive addresses. */
    for (i = 0; i < len; i++) {
        byte sk[SLHDSA_MAX_N];

        /* Step 5. Set chain address for WOTS PRF. */
        HA_SetChainAddress(sk_adrs, i);
        /* Step 6. PRF hash seeds and chain address. */
        ret = HASH_PRF(key, pk_seed, sk_seed, sk_adrs, n, sk);
        if (ret != 0) {
            break;
        }
        /* Step 7. Set chain address for WOTS HASH. */
        HA_SetChainAddress(adrs, i);
        /* Step 8. Chain hashes for w-1 iterations. */
        ret = slhdsakey_chain(key, sk, 0, SLHDSA_WM1, pk_seed, adrs, sk);
        if (ret != 0) {
            break;
        }

        /* Step 13: Compress public key - for each tmp. */
        ret = HASH_T_UPDATE(key, sk, n);
        if (ret != 0) {
            break;
        }
    }
#endif

    return ret;
}

/* Generate WOTS+ public key.
 *
 * FIPS 205 Section 5.1. Algorithm 6.
 * wots_pkGen(SK.seed, PK.seed, ADRS)
 *   1: skADRS <- ADRS       > copy address to create key generation key address
 *   2: skADRS.setTypeAndClear(WOTS_PRF)
 *   3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  ...
 *  11: wotspkADRS.setTypeAndClear(WOTS_PK)
 *  12: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  13: pk <- Tlen(PK.seed, wotspkADRS, tmp)               > compress public key
 *  14: return pk
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] sk_seed  Private key seed.
 * @param [in] pk_seed  Public key seed.
 * @param [in] adrs     HashAddress.
 * @param [in] sk_adrs  WOTS PRF HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_pkgen(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    byte n = key->params->n;
    int hash_t_started = 0;

    {
        HashAddress wotspk_adrs;

        /* Steps 11-12. Copy address and set to WOTS PK. */
        HA_Copy(wotspk_adrs, adrs);
        HA_SetTypeAndClearNotKPA(wotspk_adrs, HA_WOTS_PK);
        /* Step 13. Start hash with public key seed and address. */
        ret = HASH_T_START_ADDR(key, pk_seed, wotspk_adrs, n);
    }
    if (ret == 0) {
        HashAddress sk_adrs;

        hash_t_started = 1;

        /* Steps 1-2. Copy address and set to WOTS PRF. */
        HA_Copy(sk_adrs, adrs);
        HA_SetTypeAndClearNotKPA(sk_adrs, HA_WOTS_PRF);
        /* Steps 4-10,13: Generate hashes and update the public key hash. */
#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
        if (!SLHDSA_IS_SHA2(key->params->param) &&
                IS_INTEL_AVX2(cpuid_flags) &&
                (SAVE_VECTOR_REGISTERS2() == 0)) {
            ret = slhdsakey_wots_pkgen_chain_x4(key, sk_seed, pk_seed, adrs,
                sk_adrs);
            RESTORE_VECTOR_REGISTERS();
        }
        else
#endif
        {
            ret = slhdsakey_wots_pkgen_chain_c(key, sk_seed, pk_seed, adrs,
                sk_adrs);
        }
    }
    if (ret == 0) {
        /* Step 13: Output hash of compressed public key. */
        ret = HASH_T_FINAL(key, node, n);
    }

    if (hash_t_started) {
        HASH_T_FREE(key);
    }

    return ret;
}

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
/* Generate a WOTS+ signature, 32-byte hashed, on msg - iterating 4 hashes.
 *
 * FIPS 205. Section 5.2. Algorithm 7
 * wots_sign(M, SK.seed, PK.seed, ADRS)
 *  ...
 *  11: for i from 0 to len - 1 do
 *  12:     skADRS.setChainAddress(i)
 *  13:     sk <- PRF(PK.seed, SK.seed, skADRS)   > compute chain i secret value
 *  14:     ADRS.setChainAddress(i)
 *  15:     sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
 *                                             > compute chain i signature value
 *  16: end for
 *  17: return sig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  sk_adrs  PRF HashAddress.
 * @param [out] sig      Signature - (2.n + 3) hashes of length n.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_sign_chain_x4_16(SlhDsaKey* key, const byte* msg,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, byte* addr,
    byte* sk_addr, byte* sig)
{
    int ret = 0;
    int i;
    sword8 j;
    byte ii;
    byte idx[4] = {0};
    byte n = key->params->n;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, 4 * 16, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, 4 * 16, key->heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        ii = 0;
        for (j = SLHDSA_WM1; j >= 0; j--) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed,
                            sk_addr, n, idx, sk, key->heap);
                        if (ret != 0) {
                            break;
                        }
                        ret = slhdsakey_chain_idx_16(key, sk, pk_seed, adrs,
                            addr, msg, idx, j, 4, sig);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed, sk_addr, n, idx, sk,
            key->heap);
    }
    if (ret == 0) {
        j = min(min(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
        ret = slhdsakey_chain_idx_16(key, sk, pk_seed, adrs, addr, msg, idx, j,
            3, sig);
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
/* Generate a WOTS+ signature, 32-byte hashed, on msg - iterating 4 hashes.
 *
 * FIPS 205. Section 5.2. Algorithm 7
 * wots_sign(M, SK.seed, PK.seed, ADRS)
 *  ...
 *  11: for i from 0 to len - 1 do
 *  12:     skADRS.setChainAddress(i)
 *  13:     sk <- PRF(PK.seed, SK.seed, skADRS)   > compute chain i secret value
 *  14:     ADRS.setChainAddress(i)
 *  15:     sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
 *                                             > compute chain i signature value
 *  16: end for
 *  17: return sig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  sk_adrs  PRF HashAddress.
 * @param [out] sig      Signature - (2.n + 3) hashes of length n.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_sign_chain_x4_24(SlhDsaKey* key, const byte* msg,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, byte* addr,
    byte* sk_addr, byte* sig)
{
    int ret = 0;
    int i;
    sword8 j;
    byte ii;
    byte idx[4] = {0};
    byte n = key->params->n;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, 4 * 24, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, 4 * 24, key->heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        ii = 0;
        for (j = SLHDSA_WM1; j >= 0; j--) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed,
                            sk_addr, n, idx, sk, key->heap);
                        if (ret != 0) {
                            break;
                        }
                        ret = slhdsakey_chain_idx_24(key, sk, pk_seed, adrs,
                            addr, msg, idx, j, 4, sig);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed, sk_addr, n, idx, sk,
            key->heap);
    }
    if (ret == 0) {
        j = min(min(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
        ret = slhdsakey_chain_idx_24(key, sk, pk_seed, adrs, addr,
            msg, idx, j, 3, sig);
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
/* Generate a WOTS+ signature, 32-byte hashed, on msg - iterating 4 hashes.
 *
 * FIPS 205. Section 5.2. Algorithm 7
 * wots_sign(M, SK.seed, PK.seed, ADRS)
 *  ...
 *  11: for i from 0 to len - 1 do
 *  12:     skADRS.setChainAddress(i)
 *  13:     sk <- PRF(PK.seed, SK.seed, skADRS)   > compute chain i secret value
 *  14:     ADRS.setChainAddress(i)
 *  15:     sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
 *                                             > compute chain i signature value
 *  16: end for
 *  17: return sig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  sk_adrs  PRF HashAddress.
 * @param [out] sig      Signature - (2.n + 3) hashes of length n.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_sign_chain_x4_32(SlhDsaKey* key, const byte* msg,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, byte* addr,
    byte* sk_addr, byte* sig)
{
    int ret = 0;
    int i;
    sword8 j;
    byte ii;
    byte idx[4] = {0};
    byte n = key->params->n;
    byte len = key->params->len;
    WC_DECLARE_VAR(sk, byte, 4 * 32, key->heap);

    WC_ALLOC_VAR_EX(sk, byte, 4 * 32, key->heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        ii = 0;
        for (j = SLHDSA_WM1; j >= 0; j--) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed,
                            sk_addr, n, idx, sk, key->heap);
                        if (ret != 0) {
                            break;
                        }
                        ret = slhdsakey_chain_idx_32(key, sk, pk_seed, adrs,
                            addr, msg, idx, j, 4, sig);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        ret = slhdsakey_hash_prf_idx_x4(pk_seed, sk_seed, sk_addr, n, idx, sk,
            key->heap);
    }
    if (ret == 0) {
        j = min(min(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
        ret = slhdsakey_chain_idx_32(key, sk, pk_seed, adrs, addr, msg, idx, j,
            3, sig);
    }
    if (ret == 0) {
        sig += len * n;
    }

    WC_FREE_VAR_EX(sk, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

/* Generate a WOTS+ signature on msg - iterating 4 hashes at a time.
 *
 * FIPS 205. Section 5.2. Algorithm 7
 * wots_sign(M, SK.seed, PK.seed, ADRS)
 *  ...
 *   8: skADRS <- ADRS       > copy address to create key generation key address
 *   9: skADRS.setTypeAndClear(WOTS_PRF)
 *  10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  11: for i from 0 to len - 1 do
 *  12:     skADRS.setChainAddress(i)
 *  13:     sk <- PRF(PK.seed, SK.seed, skADRS)   > compute chain i secret value
 *  14:     ADRS.setChainAddress(i)
 *  15:     sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
 *                                             > compute chain i signature value
 *  16: end for
 *  17: return sig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  sk_adrs  PRF HashAddress.
 * @param [out] sig      Signature - (2.n + 3) hashes of length n.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_sign_chain_x4(SlhDsaKey* key, const byte* msg,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, word32* sk_adrs,
    byte* sig)
{
    int ret = 0;
    byte sk_addr[SLHDSA_HA_SZ];
    byte addr[SLHDSA_HA_SZ];
    byte n = key->params->n;

    HA_SetHashAddress(sk_adrs, 0);
    HA_Encode(sk_adrs, sk_addr);
    HA_Encode(adrs, addr);

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
    if (n == WC_SLHDSA_N_128) {
        ret = slhdsakey_wots_sign_chain_x4_16(key, msg, sk_seed, pk_seed, adrs,
            addr, sk_addr, sig);
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    if (n == 24) {
        ret = slhdsakey_wots_sign_chain_x4_24(key, msg, sk_seed, pk_seed, adrs,
            addr, sk_addr, sig);
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
    if (n == 32) {
        ret = slhdsakey_wots_sign_chain_x4_32(key, msg, sk_seed, pk_seed, adrs,
             addr, sk_addr, sig);
    }
    else
#endif
    if (ret == 0) {
        ret = NOT_COMPILED_IN;
    }

    return ret;
}
#endif

/* Generate a WOTS+ signature on an n-byte message.
 *
 * FIPS 205. Section 5.2. Algorithm 7
 * wots_sign(M, SK.seed, PK.seed, ADRS)
 *   1: csum <- 0
 *   2: msg <- base_2b(M , lgw , len1 )              > convert message to base w
 *   3: for i from 0 to len1 - 1 do
 *   4:     csum <- csum + w - 1 - msg[i]
 *   5: end for                                               > compute checksum
 *   6: csum <- csum << ((8 - ((len2.lgw) mod 8)) mod 8)
 *                                                > for lgw = 4, left shift by 4
 *   7: msg <- msg || base_2b(toByte(csum, upper(len2.lgw/8)), lgw , len2)
 *                                                           > convert to base w
 *   8: skADRS <- ADRS       > copy address to create key generation key address
 *   9: skADRS.setTypeAndClear(WOTS_PRF)
 *  10: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  11: for i from 0 to len - 1 do
 *  12:     skADRS.setChainAddress(i)
 *  13:     sk <- PRF(PK.seed, SK.seed, skADRS)   > compute chain i secret value
 *  14:     ADRS.setChainAddress(i)
 *  15:     sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
 *                                             > compute chain i signature value
 *  16: end for
 *  17: return sig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  m        n-bytes message.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [out] sig      Signature - (2.n + 3) hashes of length n.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_sign(SlhDsaKey* key, const byte* m,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, byte* sig)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    word16 csum;
    HashAddress sk_adrs;
    byte n = key->params->n;
    byte len = key->params->len;
    int i;
    byte msg[SLHDSA_MAX_MSG_SZ];

    /* Step 1: Start csum at 0 */
    csum = 0;
    /* Step 3: For each byte in message. */
    for (i = 0; i < n * 2; i += 2) {
        /* Step 2: Append high order 4 bits to msg. */
        msg[i+0] = (m[i / 2] >> 4) & 0xf;
        /* Step 4: Calculate checksum with first lgw bits. */
        csum += SLHDSA_WM1 - msg[i + 0];
        /* Step 2: Append low order 4 bits to msg. */
        msg[i+1] =  m[i / 2]       & 0xf;
        /* Step 4: Calculate checksum with next lgw bits. */
        csum += SLHDSA_WM1 - msg[i + 1];
    }
    /* Steps 6-7: Encode bottom 12 bits of csum onto end of msg. */
    msg[i + 0] = (csum >> 8) & 0xf;
    msg[i + 1] = (csum >> 4) & 0xf;
    msg[i + 2] =  csum       & 0xf;

    /* Steps 8-10: Copy address for WOTS PRF. */
    HA_Copy(sk_adrs, adrs);
    HA_SetTypeAndClearNotKPA(sk_adrs, HA_WOTS_PRF);
#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
    /* Steps 11-17: Generate signature from msg. */
    if (!SLHDSA_IS_SHA2(key->params->param) &&
            IS_INTEL_AVX2(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = slhdsakey_wots_sign_chain_x4(key, msg, sk_seed, pk_seed, adrs,
            sk_adrs, sig);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        /* Step 11: For each value of msg. */
        for (i = 0; i < len; i++) {
            /* Step 12: Set chain address for WOTS PRF. */
            HA_SetChainAddress(sk_adrs, i);
            /* Step 13. PRF hash seeds and chain address. */
            ret = HASH_PRF(key, pk_seed, sk_seed, sk_adrs, n, sig);
            if (ret != 0) {
                break;
            }
            /* Step 14: Set chain address for WOTS HASH. */
            HA_SetChainAddress(adrs, i);
            /* Step 15. Chain hashes for msg value iterations. */
            ret = slhdsakey_chain(key, sig, 0, msg[i], pk_seed, adrs, sig);
            if (ret != 0) {
                break;
            }
            /* Step 15: Move to next hash in signature. */
            sig += n;
        }
    }

    return ret;
}
#endif

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
/* Computes 4 chains simultaneously from starts to w-1 when n=16.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *  10:     tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
 *  ...
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  idx      Indices of chains.
 * @param [in]  j        Shortest chain length already calculated.
 * @param [in]  cnt      Number of chains to complete.
 * @param [out] nodes    Buffer to place completed chains.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_to_max_16(SlhDsaKey* key, const byte* sig,
     const byte* pk_seed, word32* adrs, const byte* msg, byte* idx, int j,
     int cnt, byte* nodes)
{
    int ret = 0;
    byte node[4 * 16];
    byte addr[SLHDSA_HA_SZ];

    HA_SetChainAddress(adrs, idx[0]);
    HA_Encode(adrs, addr);

    XMEMCPY(node + 0 * 16, sig + idx[0] * 16, 16);
    if ((msg[idx[0]] != j) && (msg[idx[0]] != msg[idx[1]])) {
        ret = slhdsakey_chain(key, node, msg[idx[0]],
            msg[idx[1]] - msg[idx[0]], pk_seed, adrs, node);
    }
    if (ret == 0) {
        XMEMCPY(node + 1 * 16, sig + idx[1] * 16, 16);
        XMEMSET(node + 2 * 16, 0, sizeof(node) - 2 * 16);
        if ((msg[idx[1]] != j) && (msg[idx[1]] != msg[idx[2]])) {
            ret = slhdsakey_chain_idx_x4_16(node, msg[idx[1]],
                msg[idx[2]] - msg[idx[1]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(node + 2 * 16, sig + idx[2] * 16, 16);
        if ((cnt > 3) && (msg[idx[2]] != j)) {
            ret = slhdsakey_chain_idx_x4_16(node, msg[idx[2]],
                j - msg[idx[2]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        if (cnt > 3) {
            XMEMCPY(node + 3 * 16, sig + idx[3] * 16, 16);
        }
        if (j != SLHDSA_WM1) {
            ret = slhdsakey_chain_idx_x4_16(node, j, SLHDSA_WM1 - j, pk_seed,
                addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(nodes + idx[0] * 16, node + 0 * 16, 16);
        XMEMCPY(nodes + idx[1] * 16, node + 1 * 16, 16);
        XMEMCPY(nodes + idx[2] * 16, node + 2 * 16, 16);
        if (cnt > 3) {
            XMEMCPY(nodes + idx[3] * 16, node + 3 * 16, 16);
        }
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
/* Computes 4 chains simultaneously from starts to w-1 when n=24.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *  10:     tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
 *  ...
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  idx      Indices of chains.
 * @param [in]  j        Shortest chain length already calculated.
 * @param [in]  cnt      Number of chains to complete.
 * @param [out] nodes    Buffer to place completed chains.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_to_max_24(SlhDsaKey* key, const byte* sig,
     const byte* pk_seed, word32* adrs, const byte* msg, byte* idx, int j,
     int cnt, byte* nodes)
{
    int ret = 0;
    byte node[4 * 24];
    byte addr[SLHDSA_HA_SZ];

    HA_SetChainAddress(adrs, idx[0]);
    HA_Encode(adrs, addr);

    XMEMCPY(node + 0 * 24, sig + idx[0] * 24, 24);
    if ((msg[idx[0]] != j) && (msg[idx[0]] != msg[idx[1]])) {
        ret = slhdsakey_chain(key, node, msg[idx[0]],
            msg[idx[1]] - msg[idx[0]], pk_seed, adrs, node);
    }
    if (ret == 0) {
        XMEMCPY(node + 1 * 24, sig + idx[1] * 24, 24);
        XMEMSET(node + 2 * 24, 0, sizeof(node) - 2 * 24);
        if ((msg[idx[1]] != j) && (msg[idx[1]] != msg[idx[2]])) {
            ret = slhdsakey_chain_idx_x4_24(node, msg[idx[1]],
                msg[idx[2]] - msg[idx[1]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(node + 2 * 24, sig + idx[2] * 24, 24);
        if ((cnt > 3) && (msg[idx[2]] != j)) {
            ret = slhdsakey_chain_idx_x4_24(node, msg[idx[2]],
                j - msg[idx[2]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        if (cnt > 3) {
            XMEMCPY(node + 3 * 24, sig + idx[3] * 24, 24);
        }
        if (j != SLHDSA_WM1) {
            ret = slhdsakey_chain_idx_x4_24(node, j, SLHDSA_WM1 - j, pk_seed,
                addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(nodes + idx[0] * 24, node + 0 * 24, 24);
        XMEMCPY(nodes + idx[1] * 24, node + 1 * 24, 24);
        XMEMCPY(nodes + idx[2] * 24, node + 2 * 24, 24);
        if (cnt > 3) {
            XMEMCPY(nodes + idx[3] * 24, node + 3 * 24, 24);
        }
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
/* Computes 4 chains simultaneously from starts to w-1 when n=32.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *  10:     tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
 *  ...
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  idx      Indices of chains.
 * @param [in]  j        Shortest chain length already calculated.
 * parama [in]  cnt      Number of chains to complete.
 * @param [out] nodes    Buffer to place completed chains.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_chain_idx_to_max_32(SlhDsaKey* key, const byte* sig,
     const byte* pk_seed, word32* adrs, const byte* msg, byte* idx, int j,
     int cnt, byte* nodes)
{
    int ret = 0;
    byte node[4 * 32];
    byte addr[SLHDSA_HA_SZ];

    HA_SetChainAddress(adrs, idx[0]);
    HA_Encode(adrs, addr);

    XMEMCPY(node + 0 * 32, sig + idx[0] * 32, 32);
    if ((msg[idx[0]] != j) && (msg[idx[0]] != msg[idx[1]])) {
        ret = slhdsakey_chain(key, node, msg[idx[0]],
            msg[idx[1]] - msg[idx[0]], pk_seed, adrs, node);
    }
    if (ret == 0) {
        XMEMCPY(node + 1 * 32, sig + idx[1] * 32, 32);
        XMEMSET(node + 2 * 32, 0, sizeof(node) - 2 * 32);
        if ((msg[idx[1]] != j) && (msg[idx[1]] != msg[idx[2]])) {
            ret = slhdsakey_chain_idx_x4_32(node, msg[idx[1]],
                msg[idx[2]] - msg[idx[1]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(node + 2 * 32, sig + idx[2] * 32, 32);
        if ((cnt > 3) && (msg[idx[2]] != j)) {
            ret = slhdsakey_chain_idx_x4_32(node, msg[idx[2]],
                j - msg[idx[2]], pk_seed, addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        if (cnt > 3) {
            XMEMCPY(node + 3 * 32, sig + idx[3] * 32, 32);
        }
        if (j != SLHDSA_WM1) {
            ret = slhdsakey_chain_idx_x4_32(node, j, SLHDSA_WM1 - j, pk_seed,
                addr, idx, key->heap);
        }
    }
    if (ret == 0) {
        XMEMCPY(nodes + idx[0] * 32, node + 0 * 32, 32);
        XMEMCPY(nodes + idx[1] * 32, node + 1 * 32, 32);
        XMEMCPY(nodes + idx[2] * 32, node + 2 * 32, 32);
        if (cnt > 3) {
            XMEMCPY(nodes + idx[3] * 32, node + 3 * 32, 32);
        }
    }

    return ret;
}
#endif
#endif

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
/* Computes a WOTS+ public key from a message and its signature.
 *
 * Computes four iteration hashes simultaneously.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *   8: for i from 0 to len - 1 do
 *   9:     ADRS.setChainAddress(i)
 *  ...
 *  11: end for
 *  12: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  13: wotspkADRS.setTypeAndClear(WOTS_PK)
 *  14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  15: pksig <- Tlen (PK.seed, wotspkADRS, tmp)
 *  16: return pksig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [out] pk_sig   Root node - public key signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_wots_pk_from_sig_x4(SlhDsaKey* key, const byte* sig,
    const byte* msg, const byte* pk_seed, word32* adrs, byte* pk_sig)
{
    int ret = 0;
    HashAddress wotspk_adrs;
    byte n = key->params->n;
    byte len = key->params->len;
    WC_DECLARE_VAR(nodes, byte, SLHDSA_MAX_MSG_SZ * SLHDSA_MAX_N, key->heap);
    int hash_t_started = 0;

    WC_ALLOC_VAR_EX(nodes, byte, SLHDSA_MAX_MSG_SZ * SLHDSA_MAX_N, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_128)
    if ((ret == 0) && (n == WC_SLHDSA_N_128)) {
        int i;
        sword8 j;
        byte ii = 0;
        byte idx[4] = {0};
        for (j = 0; j <= SLHDSA_WM1; j++) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_chain_idx_to_max_16(key, sig,
                            pk_seed, adrs, msg, idx, j, 4, nodes);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }

        if (ret == 0) {
            j = max(max(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
            ret = slhdsakey_chain_idx_to_max_16(key, sig, pk_seed, adrs, msg,
                idx, j, 3, nodes);
        }
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_192)
    if ((ret == 0) && (n == 24)) {
        int i;
        sword8 j;
        byte ii = 0;
        byte idx[4] = {0};
        for (j = 0; j <= SLHDSA_WM1; j++) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_chain_idx_to_max_24(key, sig,
                            pk_seed, adrs, msg, idx, j, 4, nodes);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }

        if (ret == 0) {
            j = max(max(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
            ret = slhdsakey_chain_idx_to_max_24(key, sig, pk_seed, adrs, msg,
                idx, j, 3, nodes);
        }
    }
    else
#endif
#if !defined(WOLFSSL_SLHDSA_PARAM_NO_256)
    if ((ret == 0) && (n == 32)) {
        int i;
        sword8 j;
        byte ii = 0;
        byte idx[4] = {0};
        for (j = 0; j <= SLHDSA_WM1; j++) {
            for (i = 0; i < len; i++) {
                if ((sword8)msg[i] == j) {
                    idx[ii++] = i;
                    if (ii == 4) {
                        ret = slhdsakey_chain_idx_to_max_32(key, sig,
                            pk_seed, adrs, msg, idx, j, 4, nodes);
                        if (ret != 0) {
                            break;
                        }
                        ii = 0;
                    }
                }
            }
        }

        if (ret == 0) {
            j = max(max(msg[idx[0]], msg[idx[1]]), msg[idx[2]]);
            ret = slhdsakey_chain_idx_to_max_32(key, sig, pk_seed, adrs, msg,
                idx, j, 3, nodes);
        }
    }
    else
#endif
    {
        (void)msg;
        (void)key;
        if (ret == 0) {
            ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        HA_Copy(wotspk_adrs, adrs);
        HA_SetTypeAndClearNotKPA(wotspk_adrs, HA_WOTS_PK);
        ret = HASH_T_START_ADDR(key, pk_seed, wotspk_adrs, n);
    }
    if (ret == 0) {
        hash_t_started = 1;
        ret = HASH_T_UPDATE(key, nodes, len * n);
        sig += len * n;
    }
    if (ret == 0) {
        ret = HASH_T_FINAL(key, pk_sig, n);
    }
    if (hash_t_started) {
        HASH_T_FREE(key);
    }

    WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_WC_SLHDSA_SMALL_MEM)
/* Computes a WOTS+ public key from a message and its signature.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *   8: for i from 0 to len - 1 do
 *   9:     ADRS.setChainAddress(i)
 *  10:     tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
 *  11: end for
 *  12: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  13: wotspkADRS.setTypeAndClear(WOTS_PK)
 *  14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  15: pksig <- Tlen(PK.seed, wotspkADRS, tmp)
 *  16: return pksig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [out] pk_sig   Root node - public key signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_pk_from_sig_c(SlhDsaKey* key, const byte* sig,
    const byte* msg, const byte* pk_seed, word32* adrs, byte* pk_sig)
{
    int ret = 0;
    int i;
    byte n = key->params->n;
    byte len = key->params->len;
    HashAddress wotspk_adrs;
    WC_DECLARE_VAR(nodes, byte, SLHDSA_MAX_MSG_SZ * SLHDSA_MAX_N, key->heap);
    int hash_t_started = 0;

    WC_ALLOC_VAR_EX(nodes, byte, SLHDSA_MAX_MSG_SZ * SLHDSA_MAX_N, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        /* Step 8: For each value in msg. */
        for (i = 0; i < len; i++) {
            /* Step 9: Set chain address for WOTS HASH. */
            HA_SetChainAddress(adrs, i);
            /* Step 10: Chain the hash from the msg value to w-1. */
            ret = slhdsakey_chain(key, sig, msg[i], SLHDSA_WM1 - msg[i],
                pk_seed, adrs, nodes + i * n);
            if (ret != 0) {
                break;
            }
            /* Move on to next signature hash. */
            sig += n;
        }
    }
    if (ret == 0) {
        /* Step 12-14: Copy the address for WOTS PK. */
        HA_Copy(wotspk_adrs, adrs);
        HA_SetTypeAndClearNotKPA(wotspk_adrs, HA_WOTS_PK);
        /* Step 15: Hash the public key seed and WOTS PK address ... */
        ret = HASH_T_START_ADDR(key, pk_seed, wotspk_adrs, n);
    }
    if (ret == 0) {
        hash_t_started = 1;
        /* Step 15: Update with the nodes ... */
        ret = HASH_T_UPDATE(key, nodes, len * n);
    }
    if (ret == 0) {
        /* Step 15: Generate root node - public key signature. */
        ret = HASH_T_FINAL(key, pk_sig, n);
    }
    if (hash_t_started) {
        HASH_T_FREE(key);
    }

    WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#else
/* Computes a WOTS+ public key from a message and its signature.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *  ...
 *   8: for i from 0 to len - 1 do
 *   9:     ADRS.setChainAddress(i)
 *  10:     tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
 *  11: end for
 *  12: wotspkADRS <- ADRS     > copy address to create WOTS+ public key address
 *  13: wotspkADRS.setTypeAndClear(WOTS_PK)
 *  14: wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  15: pksig <- Tlen (PK.seed, wotspkADRS, tmp)
 *  16: return pksig
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  msg      Encoded message with checksum.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [out] pk_sig   Root node - public key signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_pk_from_sig_c(SlhDsaKey* key, const byte* sig,
    const byte* msg, const byte* pk_seed, word32* adrs, byte* pk_sig)
{
    int ret;
    int i;
    byte n = key->params->n;
    byte len = key->params->len;
    HashAddress wotspk_adrs;
    byte* node = pk_sig;
    int hash_t_started = 0;

    /* Step 12-14: Copy the address for WOTS PK. */
    HA_Copy(wotspk_adrs, adrs);
    HA_SetTypeAndClearNotKPA(wotspk_adrs, HA_WOTS_PK);
    /* Step 15: Hash the public key seed and WOTS PK address ... */
    ret = HASH_T_START_ADDR(key, pk_seed, wotspk_adrs, n);
    if (ret == 0) {
        hash_t_started = 1;
        /* Step 8: For each value in msg. */
        for (i = 0; i < len; i++) {
            /* Step 9: Set chain address for WOTS HASH. */
            HA_SetChainAddress(adrs, i);
            /* Step 10: Chain the hash from the msg value to w-1. */
            ret = slhdsakey_chain(key, sig, msg[i], SLHDSA_WM1 - msg[i],
                pk_seed, adrs, node);
            if (ret != 0) {
                break;
            }
            /* Step 15: Update with node ... */
            ret = HASH_T_UPDATE(key, node, n);
            if (ret != 0) {
                break;
            }
            /* Move on to next signature hash. */
            sig += n;
        }
    }
    if (ret == 0) {
        /* Step 15: Generate root node - public key signature. */
        ret = HASH_T_FINAL(key, pk_sig, n);
    }
    if (hash_t_started) {
        HASH_T_FREE(key);
    }

    return ret;
}
#endif

/* Computes a WOTS+ public key from a message and its signature.
 *
 * FIPS 205. Section 5.3. Algorithm 8.
 * wots_pkFromSig(sig, M, PK.seed, ADRS)
 *   1: csum <- 0
 *   2: msg <- base_2b(M , lgw , len1 )              > convert message to base w
 *   3: for i from 0 to len1 - 1 do
 *   4:     csum <- csum + w - 1 - msg[i]
 *   5: end for                                               > compute checksum
 *   6: csum <- csum << ((8 - ((len2.lgw) mod 8)) mod 8)
 *                                                > for lgw = 4, left shift by 4
 *   7: msg <- msg || base_2b(toByte(csum, upper(len2.lgw/8)), lgw , len2)
 *  ...
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sig      Signature - (2.n + 3) hashes of length n.
 * @param [in]  m        Message.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     WOTS HASH HashAddress.
 * @param [out] pk_sig   Root node - public key signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_wots_pk_from_sig(SlhDsaKey* key, const byte* sig,
    const byte* m, const byte* pk_seed, word32* adrs, byte* pk_sig)
{
    int ret;
    word16 csum;
    byte n = key->params->n;
    int i;
    byte msg[SLHDSA_MAX_MSG_SZ];

    /* Step 1: Start csum at 0 */
    csum = 0;
    /* Step 3: For each byte in message. */
    for (i = 0; i < n * 2; i += 2) {
        /* Step 2: Append high order 4 bits to msg. */
        msg[i+0] = (m[i / 2] >> 4) & 0xf;
        /* Step 4: Calculate checksum with first lgw bits. */
        csum += SLHDSA_WM1 - msg[i + 0];
        /* Step 2: Append low order 4 bits to msg. */
        msg[i+1] =  m[i / 2]       & 0xf;
        /* Step 4: Calculate checksum with next lgw bits. */
        csum += SLHDSA_WM1 - msg[i + 1];
    }
    /* Steps 6-7: Encode bottom 12 bits of csum onto end of msg. */
    msg[i + 0] = (csum >> 8) & 0xf;
    msg[i + 1] = (csum >> 4) & 0xf;
    msg[i + 2] =  csum       & 0xf;

    /* Steps 8-16. */
#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
    if (!SLHDSA_IS_SHA2(key->params->param) &&
            IS_INTEL_AVX2(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = slhdsakey_wots_pk_from_sig_x4(key, sig, msg, pk_seed, adrs,
            pk_sig);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
        ret = slhdsakey_wots_pk_from_sig_c(key, sig, msg, pk_seed, adrs,
            pk_sig);
    }

    return ret;
}

/******************************************************************************
 * XMSS
 ******************************************************************************/

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
#ifndef WOLFSSL_WC_SLHDSA_RECURSIVE
/* Compute the root node of Merkle subtree of WOTS+ public keys.
 *
 * Algorithm 9 xmss_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     ADRS.setTypeAndClear(WOTS_HASH)
 *   3:     ADRS.setKeyPairAddress(i)
 *   4:     node <- wots_pkGen(SK.seed, PK.seed, ADRS)
 *   5: else
 *   6:     lnode <- xmss_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   7:     rnode <- xmss_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   8:     ADRS.setTypeAndClear(TREE)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]       key      SLH-DSA key.
 * @param [in]       sk_seed  Private key seed.
 * @param [in]       i        Node index.
 * @param [in]       z        Node height.
 * @param [in]       pk_seed  Public key seed.
 * @param [in, out]  adrs     HashAddress - WOTS HASH.
 * @param [out]      node     Root node.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_xmss_node(SlhDsaKey* key, const byte* sk_seed, int i,
    int z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;

    /* Step 1: Are we at the bottom of the subtree. */
    if (z == 0) {
        /* Step 2: Copy the address for WOTS HASH. */
        HA_SetTypeAndClearNotKPA(adrs, HA_WOTS_HASH);
        /* Step 3: Set key pair address. */
        HA_SetKeyPairAddress(adrs, i);
        /* Step 4: Generate WOTS+ public key. */
        ret = slhdsakey_wots_pkgen(key, sk_seed, pk_seed, adrs, node);
    }
    else {
        WC_DECLARE_VAR(nodes, byte, (SLHDSA_MAX_H_M + 2) * SLHDSA_MAX_N,
            key->heap);
        word32 j;
        word32 k;
        word32 m = (word32)1 << z;
        byte n = key->params->n;

        WC_ALLOC_VAR_EX(nodes, byte, (SLHDSA_MAX_H_M + 2) * SLHDSA_MAX_N,
            key->heap, DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
        if (ret == 0) {
            /* For each node at bottom of tree. */
            for (j = 0; j < m; j++) {
                /* Step 2: Copy the address for WOTS HASH. */
                HA_SetTypeAndClearNotKPA(adrs, HA_WOTS_HASH);
                /* Step 3: Set key pair address. */
                HA_SetKeyPairAddress(adrs, m * i + j);
                /* Step 4: Generate WOTS+ public key. */
                ret = slhdsakey_wots_pkgen(key, sk_seed, pk_seed, adrs,
                    nodes + (z - 1 + (j & 1)) * n);
                if (ret != 0) {
                    break;
                }

                /* For intermediate nodes. */
                for (k = z-1; k > 0; k--) {
                    if (((j >> (z-1-k)) & 1) == 1) {
                        /* Step 6 and 7 have been done.  */
                        /* Steps 8-10: Step type, height and index for TREE. */
                        HA_SetTypeAndClear(adrs, HA_TREE);
                        HA_SetTreeHeight(adrs, z - k);
                        HA_SetTreeIndex(adrs, (m * i + j) >> (z - k));
                        /* Step 11: Calculate node from two below. */
                        ret = HASH_H(key, pk_seed, adrs, nodes + k * n,
                            n, nodes + (k - 1 + ((j >> (z-k)) & 1)) * n);
                        if (ret != 0) {
                            break;
                        }
                    }
                    else {
                        break;
                    }
                }
                if (ret != 0) {
                    break;
                }
            }
            if (ret == 0) {
                /* Root node into output. */
                /* Steps 8-10: Step type, height and index for TREE. */
                HA_SetTypeAndClear(adrs, HA_TREE);
                HA_SetTreeHeight(adrs, z);
                HA_SetTreeIndex(adrs, i);
                /* Step 11: Calculate node from two below. */
                ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
            }
        }

        WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}
#else
/* Compute the root node of Merkle subtree of WOTS+ public keys.
 *
 * FIPS 205. Section 6.1. Algorithm 9.
 * xmss_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     ADRS.setTypeAndClear(WOTS_HASH)
 *   3:     ADRS.setKeyPairAddress(i)
 *   4:     node <- wots_pkGen(SK.seed, PK.seed, ADRS)
 *   5: else
 *   6:     lnode <- xmss_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   7:     rnode <- xmss_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   8:     ADRS.setTypeAndClear(TREE)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]       key      SLH-DSA key.
 * @param [in]       sk_seed  Private key seed.
 * @param [in]       i        Node index.
 * @param [in]       z        Node height.
 * @param [in]       pk_seed  Public key seed.
 * @param [in, out]  adrs     HashAddress - WOTS HASH.
 * @param [out]      node     Root node.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_xmss_node(SlhDsaKey* key, const byte* sk_seed, int i,
    int z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    byte nodes[2 * SLHDSA_MAX_N];

    /* Step 1: Are we at the bottom of the subtree. */
    if (z == 0) {
        /* Step 2: Copy the address for WOTS HASH. */
        HA_SetTypeAndClearNotKPA(adrs, HA_WOTS_HASH);
        /* Step 3: Set key pair address. */
        HA_SetKeyPairAddress(adrs, i);
        /* Step 4: Generate WOTS+ public key. */
        ret = slhdsakey_wots_pkgen(key, sk_seed, pk_seed, adrs, node);
    }
    else {
        byte n = key->params->n;

        /* Step 6: Calculate left node recursively. */
        ret = slhdsakey_xmss_node(key, sk_seed, 2 * i, z - 1, pk_seed, adrs,
            nodes);
        if (ret == 0) {
            /* Step 7: Calculate right node recursively. */
            ret = slhdsakey_xmss_node(key, sk_seed, 2 * i + 1, z - 1, pk_seed,
                adrs, nodes + n);
        }
        if (ret == 0) {
            /* Steps 8-10: Step type, height and index for TREE. */
            HA_SetTypeAndClear(adrs, HA_TREE);
            HA_SetTreeHeight(adrs, z);
            HA_SetTreeIndex(adrs, i);
            /* Step 11: Calculate node from two below. */
            ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
        }
    }

    return ret;
}
#endif

/* Generate XMSS signature.
 *
 * FIPS 205. Section 6.2. Algorithm 10.
 * xmss_sign(M SK.seed, idx PK.seed, ADRS)
 *   1: for j from 0 to h' - 1 do                    > build authentication path
 *   2:     k <- lower(idx/2^j) XOR 1
 *   3:     AUTH[j] <- xmss_node(SK.seed, k, j, PK.seed, ADRS)
 *   4: end for
 *   5: ADRS.setTypeAndClear(WOTS_HASH)
 *   6: ADRS.setKeyPairAddress(idx)
 *   7: sig <- wots_sign(M , SK.seed, PK.seed, ADRS)
 *   8: SIGXMSS <- sig || AUTH
 *   9: return SIGXMSS
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  m         n-byte message.
 * @param [in]  sk_seed   Private key seed.
 * @param [in]  idx       Key pair address of WOTS hash.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  adrs      HashAddress.
 * @param [out] sig_xmss  XMSS signature.
 *                        len n-byte nodes and h' authentication nodes.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_xmss_sign(SlhDsaKey* key, const byte* m,
    const byte* sk_seed, word32 idx, const byte* pk_seed, word32* adrs,
    byte* sig_xmss)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    byte n = key->params->n;
    byte len = key->params->len;
    byte h_m = key->params->h_m;
    /* Step 8: Place authentication nodes after WOTS+ signature. */
    byte* auth = sig_xmss + (len * n);
    word32 i = idx;
    int j;

    /* Step 1: For each height of XMSS tree. */
    for (j = 0; j < h_m; j++) {
        /* Step 2: Calculate index of other node. */
        word32 k = i ^ 1;
        /* Step 3: Calculate authentication node. */
        ret = slhdsakey_xmss_node(key, sk_seed, k, j, pk_seed, adrs, auth);
        if (ret != 0) {
            break;
        }
        /* Step 3: Move to next authentication node. */
        auth += n;
        /* Step 2: Update index. */
        i >>= 1;
    }

    if (ret == 0) {
        /* Step 5: Set address of WOTS HASH. */
        HA_SetTypeAndClearNotKPA(adrs, HA_WOTS_HASH);
        /* Step 6: Set key pair address into address. */
        HA_SetKeyPairAddress(adrs, idx);
        /* Step 7: WOTS+ sign message. */
        ret = slhdsakey_wots_sign(key, m, sk_seed, pk_seed, adrs, sig_xmss);
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Compute XMSS public key from XMSS signature.
 *
 * FIPS 205. Section 6.3. Algorithm 11.
 * xmss_pkFromSig(idx, SIGXMSS, M PK.seed, ADRS)
 *   1: ADRS.setTypeAndClear(WOTS_HASH)        > compute WOTS+ pk from WOTS+ sig
 *   2: ADRS.setKeyPairAddress(idx)
 *   3: sig <- SIGXMSS.getWOTSSig()                      > SIGXMSS [0 : len . n]
 *   4: AUTH <- SIGXMSS.getXMSSAUTH()       > SIGXMSS [len . n : (len + h') . n]
 *   5: node[0] <- wots_pkFromSig(sig, M, PK.seed, ADRS)
 *   6: ADRS.setTypeAndClear(TREE)         > compute root from WOTS+ pk and AUTH
 *   7: ADRS.setTreeIndex(idx
 *   8: for k from 0 to h' - 1 do
 *   9:     ADRS.setTreeHeight(k + 1)
 *  10:     if lower(idx/2^k) is even then
 *  11:         ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
 *  12:         node[1] <- H(PK.seed, ADRS, node[0] || AUTH[k])
 *  13:     else
 *  14:         ADRS.setTreeIndex((ADRS.getTreeIndex() - 1)/2)
 *  15:         node[1] <- H(PK.seed, ADRS, AUTH[k] || node[0])
 *  16:     end if
 *  17:     node[0] <- node[1]
 *  18: end for
 *  19: return node[0]
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  idx       Key pair address of WOTS hash.
 * @param [in]  sig_xmss  XMSS signature.
 *                        len n-byte nodes and h' authentication nodes.
 * @param [in]  m         n-byte message.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  adrs      HashAddress.
 * @param [out] node      XMSS public key.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_xmss_pk_from_sig(SlhDsaKey* key, word32 idx,
    const byte* sig_xmss, const byte* m, const byte* pk_seed, word32* adrs,
    byte* node)
{
    int ret;
    byte n = key->params->n;
    byte h_m = key->params->h_m;
    byte len = key->params->len;
    /* Step  3: Set pointer to first signature node. */
    const byte* sig = sig_xmss;
    /* Step 4: Set pointer to first authentication node. */
    const byte* auth = sig_xmss + (len * n);
    int k;

    /* Step 1: Set address type to WOTS HASH. */
    HA_SetTypeAndClear(adrs, HA_WOTS_HASH);
    /* Step 2: Set key pair address. */
    HA_SetKeyPairAddress(adrs, idx);
    /* Step 5: Compute WOTS+ public key from signature. */
    ret = slhdsakey_wots_pk_from_sig(key, sig, m, pk_seed, adrs, node);
    if (ret == 0) {
        /* Step 6: Set address type to TREE. */
        HA_SetTypeAndClear(adrs, HA_TREE);
        /* Step 2: Set key pair address. */
        HA_SetTreeIndex(adrs, idx);
        /* Step 8: For each height of the XMSS tree. */
        for (k = 0; k < h_m; k++) {
            /* Calculate which side the current and authentication nodes are. */
            byte side = idx & 1;
            /* Update tree index. */
            idx >>= 1;

            /* Step 9: Set tree height. */
            HA_SetTreeHeight(adrs, k + 1);
            /* Steps 11 and 14: Set tree index. */
            HA_SetTreeIndex(adrs, idx);
            /* Step 10: Check which order to put nodes. */
            if (side == 0) {
                /* Steps 12,17: Calculate node with sig node on right. */
                ret = HASH_H_2(key, pk_seed, adrs, node, auth, n, node);
            }
            else {
                /* Steps 15,17: Calculate node with sig node on left. */
                ret = HASH_H_2(key, pk_seed, adrs, auth, node, n, node);
            }
            if (ret != 0) {
                break;
            }
            /* Next authentication node. */
            auth += n;
        }
    }

    return ret;
}

/******************************************************************************
 * HT - HyperTree
 ******************************************************************************/

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Generate hypertree signature.
 *
 * FIPS 205. Section 7.1. Algorithm 12.
 * ht_sign(M SK.seed, PK.seed, idxtree, idxleaf)
 *   1: ADRS <- toByte(0, 32)
 *   2: ADRS.setTreeAddress(idxtree)
 *   3: SIGtmp <- xmss_sign(x, SK.seed, idxleaf, PK.seed, ADRS)
 *   4: SIGHT <- SIGtmp
 *   5: root <- xmss_pkFromSig(idxleaf, SIGtmp, M, PK.seed, ADRS)
 *   6: for j from 1 to d - 1 do
 *   7:     idxleaf <- idxleaf mod 2^h'   > h' least significant bits of idxtree
 *   8:     idxtree <- idxtree >> h'
 *                               > remove least significant h' bits from idxtree
 *   9:     ADRS.setLayerAddress(j)
 *  10:    ADRS.setTreeAddress(idxtree)
 *  11:    SIGtmp <- xmss_sign(root, SK.seed, idxleaf, PK.seed, ADRS)
 *  12:    SIGHT <- SIGHT || SIGtmp
 *  13:    if j < d - 1 then
 *  14:        root <- xmss_pkFromSig(idxleaf, SIGtmp, root, PK.seed, ADRS)
 *  15:    end if
 *  16: end for
 *  17: return SIGHT
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  pk_fors   FORS public key.
 * @param [in]  sk_seed   Private key seed.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  idx_tree  Tree address.
 * @param [in]  idx_leaf  Key pair address.
 * @param [out] sig_ht    Hypertree signature - d x n-byte nodes.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_ht_sign(SlhDsaKey* key, const byte* pk_fors,
    const byte* sk_seed, const byte* pk_seed, word32* idx_tree, word32 idx_leaf,
    byte* sig_ht)
{
    int ret;
    HashAddress adrs;
    byte root[SLHDSA_MAX_N];
    byte n = key->params->n;
    byte h_m = key->params->h_m;
    byte len = key->params->len;
    byte d = key->params->d;
    int j;
    word32 mask = ((word32)1 << h_m) - 1;

    /* Step 1: Set address to all zeros. */
    HA_Init(adrs);
    /* Step 2: Set tree address. */
    HA_SetTreeAddress(adrs, idx_tree);
    /* Step 3: Compute XMSS signature. */
    ret = slhdsakey_xmss_sign(key, pk_fors, sk_seed, idx_leaf, pk_seed, adrs,
        sig_ht);
    if (ret == 0) {
        /* Step 5: Compute root/public key from signature. */
        ret = slhdsakey_xmss_pk_from_sig(key, idx_leaf, sig_ht, pk_fors,
            pk_seed, adrs, root);
        /* Step 4: Step hypertree signature over XMSS signature. */
        sig_ht += (h_m + len) * n;
    }
    if (ret == 0) {
        /* Step 6: For remaining depths. */
        for (j = 1; j < d; j++) {
            /* Step 7: Get bottom h' bits for index into tree. */
            idx_leaf = INDEX_TREE_MASK(idx_tree, mask);
            /* Step 8: Update tree index to exclude this subtree. */
            INDEX_TREE_SHIFT_DOWN(idx_tree, h_m);
            /* Step 9: Set layer address. */
            HA_SetLayerAddress(adrs, j);
            /* Step 10: Set tree index. */
            HA_SetTreeAddress(adrs, idx_tree);
            /* Step 11: Compute XMSS signature. */
            ret = slhdsakey_xmss_sign(key, root, sk_seed, idx_leaf, pk_seed,
                adrs, sig_ht);
            if (ret != 0) {
                break;
            }
            /* Step 13: Check if we need to calculate next root. */
            if (j < d) {
                /* Step 14: Compute root/public key from signature. */
                ret = slhdsakey_xmss_pk_from_sig(key, idx_leaf, sig_ht, root,
                    pk_seed, adrs, root);
                if (ret != 0) {
                    break;
                }
            }
            /* Step 12: Step hypertree signature over XMSS signature. */
            sig_ht += (h_m + len) * n;
        }
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Verify hypertree signature.
 *
 * FIPS 205. Section 7.2 Algorithm 13.
 * ht_verify(M SIGHT, PK.seed, idxtree, idxleaf, PK.root)
 *   1: ADRS <- toByte(0, 32)
 *   2: ADRS.setTreeAddress(idxtree)
 *   3: SIGtmp <- SIGHT.getXMSSSignature(0)          > SIGHT[0 : (h' + len) . n]
 *   4: node <- xmss_pkFromSig(idxleaf, SIGtmp, M, PK.seed, ADRS)
 *   5: for j from 1 to d - 1 do
 *   6:     idxleaf <- idxtree mod 2^h'   > h' least significant bits of idxtree
 *   7:     idxtree <- idxtree >> h'
 *                               > remove least significant h' bits from idxtree
 *   8:     ADRS.setLayerAddress(j)
 *   9:     ADRS.setTreeAddress(idxtree)
 *  10:     SIGtmp <- SIGHT .getXMSSSignature(j)
 *                            > SIGHT[h . (h' + len) . n : (j + 1)(h' + len . n]
 *  11:     node <- xmss_pkFromSig(idxleaf, SIGtmp, node, PK.seed, ADRS)
 *  12: end for
 *  13: if node = PK.root then
 *  14:     return true
 *  15: else
 *  16:     return false
 *  17: end if
 *
 * @param [in] key       SLH-DSA key.
 * @param [in] m         Message to verify.
 * @param [in] sig_ht    Hypertree signature.
 * @param [in] pk_seed   Public key seed.
 * @param [in] idx_tree  Tree address.
 * @param [in] idx_leaf  Key pair address.
 * @param [in] pk_root   Public key root node.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when calculated node doesn't match public key node.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_ht_verify(SlhDsaKey* key, const byte* m,
    const byte* sig_ht, const byte* pk_seed, word32* idx_tree, word32 idx_leaf,
    const byte* pk_root)
{
    int ret;
    HashAddress adrs;
    byte node[SLHDSA_MAX_N];
    byte n = key->params->n;
    byte h_m = key->params->h_m;
    byte len = key->params->len;
    byte d = key->params->d;
    int j;
    /* For Step 6. */
    word32 mask = ((word32)1 << h_m) - 1;

    /* Step 1: Set address to all zeros. */
    HA_Init(adrs);
    /* Step 2: Set tree address. */
    HA_SetTreeAddress(adrs, idx_tree);
    /* Step 4: Get public key node from XMSS signature. */
    ret = slhdsakey_xmss_pk_from_sig(key, idx_leaf, sig_ht, m, pk_seed, adrs,
        node);
    /* Step 3: Move over XMSS signature. */
    sig_ht += (h_m + len) * n;

    if (ret == 0) {
        /* Step 5: For remaining depths. */
        for (j = 1; j < d; j++) {
            /* Step 6: Get bottom h' bits for index into tree. */
            idx_leaf = INDEX_TREE_MASK(idx_tree, mask);
            /* Step 7: Update tree index to exclude this subtree. */
            INDEX_TREE_SHIFT_DOWN(idx_tree, h_m);
            /* Step 8: Set layer address. */
            HA_SetLayerAddress(adrs, j);
            /* Step 9: Set tree index. */
            HA_SetTreeAddress(adrs, idx_tree);
            /* Step 11: Get public key node from XMSS signature. */
            ret = slhdsakey_xmss_pk_from_sig(key, idx_leaf, sig_ht, node,
                pk_seed, adrs, node);
            if (ret != 0) {
                break;
            }
            /* Step 10: Move over XMSS signature. */
            sig_ht += (h_m + len) * n;
        }
    }
    /* Step 13: Compare computed node with public key root. */
    if ((ret == 0) && (XMEMCMP(node, pk_root, n) != 0)) {
        /* Step 16: Return signature verification failed. */
        ret = SIG_VERIFY_E;
    }

    return ret;
}

/******************************************************************************
 * FORS
 ******************************************************************************/

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Generate FORS private-key value.
 *
 * FIPS 205. Section 8.1. Algorithm 14
 * fors_skGen(SK.seed, PK.seed, ADRS, idx)
 *   1: skADRS <- ADRS           > copy address to create key generation address
 *   2: skADRS.setTypeAndClear(FORS_PRF)
 *   3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *   4: skADRS.setTreeIndex(idx)
 *   5: return PRF(PK.seed, SK.seed, skADRS)
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     HashAddress.
 * @param [in]  idx      Private key index.
 * @param [out] node     FORS private-key value.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_sk_gen(SlhDsaKey* key, const byte* sk_seed,
    const byte* pk_seed, word32* adrs, word32 idx, byte* node)
{
    HashAddress sk_adrs;

    /* Step 1: Copy address to FORS PRF. */
    HA_Copy(sk_adrs, adrs);
    /* Steps 2-3: Set type and keep key pair address. */
    HA_SetTypeAndClearNotKPA(sk_adrs, HA_FORS_PRF);
    /* Step 4: Set tree index. */
    HA_SetTreeIndex(sk_adrs, idx);
    /* Step 5: Hash seeds and address. */
    return HASH_PRF(key, pk_seed, sk_seed, sk_adrs, key->params->n,
        node);
}

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
/* PRF hash 4 simultaneously.
 *
 * Each hash varies by the tree index with the first value in sequence passed
 * in.
 *
 * FIPS 205. Section 4.1.
 *   PRF(PK.seed, SK.seed, ADRS) (Bn x Bn x B32 -> Bn) is a PRF that is used to
 *   generate the secret values in WOTS+ and FORS private keys.
 * FIPS 205. Section 11.1.
 *   PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
 *
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  n        Number of bytes in hash output.
 * @param [in]  ti       Tree index start value.
 * @param [out] node     Buffer to hold hash output.
 * @param [in]  heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_hash_prf_ti_x4(const byte* pk_seed, const byte* sk_seed,
    byte* addr, byte n, int ti, byte* node, void* heap)
{
    int ret = 0;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_hash_x4(state, pk_seed, addr,
            sk_seed, n);
        SHAKE256_SET_TREE_INDEX(state, o, ti);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, node, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

/* F hash 4 simultaneously.
 *
 * Each hash varies by the tree index with the first value in sequence passed
 * in.
 *
 * FIPS 205. Section 4.1.
 *   F(PK.seed, ADRS, M1) (Bn x B32 x Bn -> Bn) is a hash function that takes an
 *   n-byte message as input and produces an n-byte output.
 * FIPS 205. Section 11.1.
 *   F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1 , 8n)
 *
 * @param [in]      pk_seed  Public key seed.
 * @param [in]      addr     Encoded HashAddress.
 * @param [in, out] node     On in, n-byte messages. On out, n-byte outputs.
 * @param [in]      n        Number of bytes in hash output.
 * @param [in]      ti       Tree index start value.
 * @param [in]      heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_hash_f_ti_x4(const byte* pk_seed, byte* addr, byte* node,
    byte n, word32 ti, void* heap)
{
    int ret = 0;
    int i;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_x4(state, pk_seed, addr, n);
        SHAKE256_SET_TREE_INDEX(state, o, ti);
        for (i = 0; i < n / 8; i++) {
            state[o + 0] = ((word64*)(node + 0 * n))[i];
            state[o + 1] = ((word64*)(node + 1 * n))[i];
            state[o + 2] = ((word64*)(node + 2 * n))[i];
            state[o + 3] = ((word64*)(node + 3 * n))[i];
            o += 4;
        }
        SHAKE256_SET_END_X4(state, o);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, node, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

/* H hash 4 simultaneously.
 *
 * Each hash varies by the tree index with the first value in sequence passed
 * in.
 *
 * FIPS 205. Section 4.1.
 *   H(PK.seed, ADRS, M2) (Bn x B32 x B2n -> Bn) is a special case of Tl that
 *   takes a 2n-byte message as input.
 * FIPS 205. Section 11.1.
 *   H(PK.seed, ADRS, M2) = SHAKE256(PK.seed || ADRS || M2, 8n)
 *
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  addr     Encoded HashAddress.
 * @param [in]  m        2n-byte message.
 * @param [in]  n        Number of bytes in hash output.
 * @param [in]  ti       Tree index start value.
 * @param [out] hash     Buffer to hold hash output.
 * @param [in]  heap     Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_hash_h_ti_x4(const byte* pk_seed, byte* addr,
    const byte* m, byte n, word32 ti, byte* hash, void* heap)
{
    int ret = 0;
    int i;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_x4(state, pk_seed, addr, n);
        SHAKE256_SET_TREE_INDEX(state, o, ti);
        for (i = 0; i < 2 * n / 8; i++) {
            state[o + 0] = ((word64*)(m + 0 * n))[i];
            state[o + 1] = ((word64*)(m + 2 * n))[i];
            state[o + 2] = ((word64*)(m + 4 * n))[i];
            state[o + 3] = ((word64*)(m + 6 * n))[i];
            o += 4;
        }
        SHAKE256_SET_END_X4(state, o);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, hash, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

/* A ranges from 6-14. */
#if SLHDSA_MAX_A < 9
    /* Maximum node depth that determines the number of nodes stored and
     * hashed in one call. */
    #define SLHDSA_MAX_FORS_NODE_DEPTH      (SLHDSA_MAX_A-1)
#else
    /* Maximum node depth that determines the number of nodes stored and
     * hashed in one call. */
    #define SLHDSA_MAX_FORS_NODE_DEPTH      8
#endif
/* Maximum node depth that determines the number of nodes stored and
 * hashed in one call with an 8 depth tree below. */
#define SLHDSA_MAX_FORS_NODE_TOP_DEPTH  \
    (SLHDSA_MAX_A - SLHDSA_MAX_FORS_NODE_DEPTH)

/* Compute the root of a zero height Merkle subtree of FORS public values.
 *
 * Performs 4 hashes at the same time where possible.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *  ...
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_node_x4_z0(SlhDsaKey* key, const byte* sk_seed,
    word32 i, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    byte n = key->params->n;

    /* Step 2: Generate private key value for index. */
    ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs, i, node);
    if (ret == 0) {
        /* Step 3: Set tree height to zero. */
        HA_SetTreeHeight(adrs, 0);
        /* Step 4: Set tree index. */
        HA_SetTreeIndex(adrs, i);
        /* Step 5: Compute node from public key seed, address and value. */
        ret = HASH_F(key, pk_seed, adrs, node, n, node);
    }

    return ret;
}

/* Compute the root of a one height Merkle subtree of FORS public values.
 *
 * Performs 4 hashes at the same time where possible.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_node_x4_z1(SlhDsaKey* key, const byte* sk_seed,
    word32 i, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    byte n = key->params->n;
    byte nodes[2 * SLHDSA_MAX_N];

    /* Step 7: Compute left node. */
    /* Step 2: Generate private key value for index. */
    ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs, 2 * i + 0, nodes);
    if (ret == 0) {
        /* Step 3: Set tree height to zero. */
        HA_SetTreeHeight(adrs, 0);
        /* Step 4: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 0);
        /* Step 5: Compute node from public key seed, address and value. */
        ret = HASH_F(key, pk_seed, adrs, nodes, n, nodes);
    }
    /* Step 8: Compute right node. */
    if (ret == 0) {
        /* Step 2: Generate private key value for index. */
        ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs, 2 * i + 1,
            nodes + n);
    }
    if (ret == 0) {
        /* Step 4: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 1);
        /* Step 5: Compute node from public key seed, address and value. */
        ret = HASH_F(key, pk_seed, adrs, nodes + n, n, nodes + n);
    }
    if (ret == 0) {
        /* Step 9: Set tree height. */
        HA_SetTreeHeight(adrs, 1);
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, i);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
    }

    return ret;
}

/* Compute the root of a Merkle subtree of FORS public values.
 *
 * Performs 4 hashes at the same time where possible.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  z        Node height.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_node_x4_low(SlhDsaKey* key, const byte* sk_seed,
    word32 i, word32 z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;
    byte n = key->params->n;
    HashAddress sk_adrs;
    byte addr[SLHDSA_HA_SZ];
    int j;
    int m = 1 << z;
    WC_DECLARE_VAR(nodes, byte, (1 << SLHDSA_MAX_FORS_NODE_DEPTH) *
        SLHDSA_MAX_N, key->heap);

    WC_ALLOC_VAR_EX(nodes, byte, (1 << SLHDSA_MAX_FORS_NODE_DEPTH) *
        SLHDSA_MAX_N, key->heap, DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        byte sk_addr[SLHDSA_HA_SZ];

        HA_SetTreeHeight(adrs, 0);
        /* Copy address for FORS PRF. */
        HA_Copy(sk_adrs, adrs);
        /* Set type and keep key pair address. */
        HA_SetTypeAndClearNotKPA(sk_adrs, HA_FORS_PRF);
        /* Encode FORS PRF address for hashing. */
        HA_Encode(sk_adrs, sk_addr);
        /* Encode FORS tree address for hashing. */
        HA_Encode(adrs, addr);

        /* Step 2: Generate private key values for leaf indices. */
        for (j = 0; j < m; j += 4) {
            ret = slhdsakey_hash_prf_ti_x4(pk_seed, sk_seed, sk_addr, n,
                m * i + j, nodes + j * n, key->heap);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        /* Step 3: Set tree height to zero. */
        HA_SetTreeHeight((word32*)addr, 0);
        /* Step 4-5: Set tree indices and compute leaf node. */
        for (j = 0; j < m; j += 4) {
            ret = slhdsakey_hash_f_ti_x4(pk_seed, addr, nodes + j * n, n,
                m * i + j, key->heap);
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        word32 k;
        for (k = 1; k < z - 1; k++) {
            m >>= 1;
            /* Step 9: Set tree height. */
            HA_SetTreeHeightBE(addr, k);
            /* Step 10-11: Set tree index and compute nodes. */
            for (j = 0; j < m; j += 4) {
                ret = slhdsakey_hash_h_ti_x4(pk_seed, addr, nodes + 2 * j * n,
                    n, m * i + j, nodes + j * n, key->heap);
                if (ret != 0) {
                    break;
                }
            }
            if (ret != 0) {
                break;
            }
        }
    }
    /* Step 7: Compute left node. */
    if (ret == 0) {
        /* Step 9: Set tree height. */
        HA_SetTreeHeight(adrs, z - 1);
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 0);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes, n, nodes);
    }
    /* Step 8: Compute right node. */
    if (ret == 0) {
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 1);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes + 2 * n, n,
            nodes + 1 * n);
    }
    if (ret == 0) {
        /* Step 9: Set tree height. */
        HA_SetTreeHeight(adrs, z);
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, i);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
    }

    WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}

#if SLHDSA_MAX_FORS_NODE_DEPTH < SLHDSA_MAX_A-1
/* Compute the root of a Merkle subtree of FORS public values for large heights.
 *
 * Performs 4 hashes at the same time where possible.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  z        Node height.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_node_x4_high(SlhDsaKey* key, const byte* sk_seed,
    word32 i, word32 z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;
    byte n = key->params->n;
    int j;
    int z2 = z % SLHDSA_MAX_FORS_NODE_DEPTH;
    int m;
    WC_DECLARE_VAR(nodes, byte, (1 << SLHDSA_MAX_FORS_NODE_TOP_DEPTH) *
        SLHDSA_MAX_N, key->heap);

    WC_ALLOC_VAR_EX(nodes, byte, (1 << SLHDSA_MAX_FORS_NODE_TOP_DEPTH) *
        SLHDSA_MAX_N, key->heap, DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        if (z2 == 0) {
            z2 = SLHDSA_MAX_FORS_NODE_DEPTH;
        }
        m = 1 << z2;
        /* Steps 7-8: Compute left and right nodes. */
        for (j = 0; j < m; j++) {
            ret = slhdsakey_fors_node_x4_low(key, sk_seed, m * i + j, z - z2,
                pk_seed, adrs, nodes + j * n);
            if (ret != 0) {
                break;
            }
        }
    }
    if ((ret == 0) && (z2 > 2)) {
        word32 k;
        for (k = z - z2 + 1; k < z - 1; k++) {
            byte addr[SLHDSA_HA_SZ];

            m >>= 1;
            /* Step 9: Set tree height. */
            HA_SetTreeHeight(adrs, k);
            /* Encode FORS tree address for hashing. */
            HA_Encode(adrs, addr);
            /* Step 10-11: Set tree index and compute nodes. */
            for (j = 0; j < m; j += 4) {
                ret = slhdsakey_hash_h_ti_x4(pk_seed, addr, nodes + 2 * j * n,
                    n, m * i + j, nodes + j * n, key->heap);
                if (ret != 0) {
                    break;
                }
            }
            if (ret != 0) {
                break;
            }
        }
    }
    /* Step 7: Compute left node. */
    if ((ret == 0) && (z2 > 1)) {
        /* Step 9: Set tree height. */
        HA_SetTreeHeight(adrs, z - 1);
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 0);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes, n, nodes);
    }
    /* Step 8: Compute right node. */
    if ((ret == 0) && (z2 > 1)) {
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, 2 * i + 1);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes + 2 * n, n,
            nodes + 1 * n);
    }
    if (ret == 0) {
        /* Step 9: Set tree height. */
        HA_SetTreeHeight(adrs, z);
        /* Step 10: Set tree index. */
        HA_SetTreeIndex(adrs, i);
        /* Step 11: Compute node from public key seed, address and nodes. */
        ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
    }

    WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

/* Compute the root of a Merkle subtree of FORS public values.
 *
 * Performs 4 hashes at the same time where possible.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  z        Node height.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  SHAKE-256 error return code on digest failure.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_node_x4(SlhDsaKey* key, const byte* sk_seed, word32 i,
    word32 z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;

    /* Step 1: Check if we are at leaf node. */
    if (z == 0) {
        ret = slhdsakey_fors_node_x4_z0(key, sk_seed, i, pk_seed, adrs, node);
    }
    /* Step 6: 1 level above leaf node. */
    else if (z == 1) {
        ret = slhdsakey_fors_node_x4_z1(key, sk_seed, i, pk_seed, adrs, node);
    }
    /* Step 6: 2-MAX_DEPTH levels above leaf node. */
    else if ((z >= 2) && (z <= SLHDSA_MAX_FORS_NODE_DEPTH)) {
        ret = slhdsakey_fors_node_x4_low(key, sk_seed, i, z, pk_seed, adrs,
            node);
    }
#if SLHDSA_MAX_FORS_NODE_DEPTH < SLHDSA_MAX_A-1
    /* Step 6: More than MAX_DEPTH levels above leaf node. */
    else {
        ret = slhdsakey_fors_node_x4_high(key, sk_seed, i, z, pk_seed, adrs,
            node);
    }
#endif

    return ret;
}
#endif

#if !defined(WOLFSSL_WC_SLHDSA_RECURSIVE)
/* Compute the root of a Merkle subtree of FORS public values.
 *
 * Iterative implementation.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  z        Node height.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_node_c(SlhDsaKey* key, const byte* sk_seed, word32 i,
    word32 z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret = 0;
    byte n = key->params->n;

    /* Step 1: Check if we are at leaf node. */
    if (z == 0) {
        /* Step 2: Generate private key value for index. */
        ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs, i, node);
        if (ret == 0) {
            /* Step 3: Set tree height to zero. */
            HA_SetTreeHeight(adrs, 0);
            /* Step 4: Set tree index. */
            HA_SetTreeIndex(adrs, i);
            /* Step 5: Compute node from public key seed, address and value. */
            ret = HASH_F(key, pk_seed, adrs, node, n, node);
        }
    }
    /* Step 6: Non leaf node. */
    else {
        WC_DECLARE_VAR(nodes, byte, (SLHDSA_MAX_A + 1) * SLHDSA_MAX_N,
            key->heap);
        word32 j;
        word32 k;
        word32 m = (word32)1 << z;

        WC_ALLOC_VAR_EX(nodes, byte, (SLHDSA_MAX_A + 1) * SLHDSA_MAX_N,
            key->heap, DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
        if (ret == 0) {
            /* For all leaf nodes. */
            for (j = 0; j < m; j++) {
                int o = (z - 1 + (j & 1)) * n;
                /* Step 2: Generate private key value for index. */
                ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs,
                    m * i + j, nodes + o);
                if (ret != 0) {
                    break;
                }
                /* Step 3: Set tree height to zero. */
                HA_SetTreeHeight(adrs, 0);
                /* Step 4: Set tree index. */
                HA_SetTreeIndex(adrs, m * i + j);
                /* Step 5: Compute node from public key seed, address and value.
                 */
                ret = HASH_F(key, pk_seed, adrs, nodes + o, n,
                    nodes + o);
                if (ret != 0) {
                    break;
                }

                /* For each intermediate node as soon as left and right have
                 * been computed. */
                for (k = z-1; k > 0; k--) {
                    /* Check if this is the right node at a height. */
                    if (((j >> (z-1-k)) & 1) == 1) {
                        /* Step 9: Set tree height. */
                        HA_SetTreeHeight(adrs, z - k);
                        /* Step 10: Set tree index. */
                        HA_SetTreeIndex(adrs, (m * i + j) >> (z - k));
                        /* Step 11: Compute node from public key seed, address
                         * and left and right nodes. */
                        ret = HASH_H(key, pk_seed, adrs, nodes + k * n,
                            n, nodes + (k - 1 + ((j >> (z-k)) & 1)) * n);
                        if (ret != 0) {
                            break;
                        }
                    }
                    /* Left node - can go no higher. */
                    else {
                        break;
                    }
                }
            }
            if (ret == 0) {
                /* Step 9: Set tree height. */
                HA_SetTreeHeight(adrs, z);
                /* Step 10: Set tree index. */
                HA_SetTreeIndex(adrs, i);
                /* Step 11: Compute node from public key seed, address
                 * and nodes. */
                ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
            }
        }

        WC_FREE_VAR_EX(nodes, key->heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}
#else
/* Compute the root of a Merkle subtree of FORS public values.
 *
 * Recursive implementation.
 *
 * FIPS 205. Section 8.2. Algorithm 15.
 * fors_node(SK.seed, i, z, PK.seed, ADRS)
 *   1: if z = 0 then
 *   2:     sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
 *   3:     ADRS.setTreeHeight(0)
 *   4:     ADRS.setTreeIndex(i)
 *   5:     node <- F(PK.seed, ADRS, sk)
 *   6: else
 *   7:     lnode <- fors_node(SK.seed, 2i, z - 1, PK.seed, ADRS)
 *   8:     rnode <- fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
 *   9:     ADRS.setTreeHeight(z)
 *  10:     ADRS.setTreeIndex(i)
 *  11:     node <- H(PK.seed, ADRS, lnode || rnode)
 *  12: end if
 *  13: return node
 *
 * @param [in]  key      SLH-DSA key.
 * @param [in]  sk_seed  Private key seed.
 * @param [in]  i        Node index.
 * @param [in]  z        Node height.
 * @param [in]  pk_seed  Public key seed.
 * @param [in]  adrs     FORS tree HashAddress.
 * @param [out] node     n-byte root node.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_node_c(SlhDsaKey* key, const byte* sk_seed, word32 i,
    word32 z, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    byte n = key->params->n;

    /* Step 1: Check if we are at leaf node. */
    if (z == 0) {
        /* Step 2: Generate private key value for index. */
        ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs, i, node);
        if (ret == 0) {
            /* Step 3: Set tree height to zero. */
            HA_SetTreeHeight(adrs, 0);
            /* Step 4: Set tree index. */
            HA_SetTreeIndex(adrs, i);
            /* Step 5: Compute node from public key seed, address and value. */
            ret = HASH_F(key, pk_seed, adrs, node, n, node);
        }
    }
    else {
        byte nodes[2 * SLHDSA_MAX_N];

        /* Step 7: Compute left node. */
        ret = slhdsakey_fors_node_c(key, sk_seed, 2 * i + 0, z - 1, pk_seed,
            adrs, nodes);
        if (ret == 0) {
            /* Step 8: Compute right node. */
            ret = slhdsakey_fors_node_c(key, sk_seed, 2 * i + 1, z - 1, pk_seed,
                adrs, nodes + n);
        }
        if (ret == 0) {
            /* Step 9: Set tree height. */
            HA_SetTreeHeight(adrs, z);
            /* Step 10: Set tree index. */
            HA_SetTreeIndex(adrs, i);
            /* Step 11: Compute node from public key seed, address and nodes. */
            ret = HASH_H(key, pk_seed, adrs, nodes, n, node);
        }
    }

    return ret;
}
#endif

/* Generate FORS signature.
 *
 * FIPS 205. Section 8.3. Algorithm 16.
 * fors_sign(md SK.seed, PK.seed, ADRS)
 *   1: SIGFORS = NULL         > initialize SIGFORS as a zero-length byte string
 *   2: indices <- base_2b(md, a, k)
 *   3: for i from 0 to k - 1 do                    > compute signature elements
 *   4:     SIGFORS <- SIGFORS ||
 *                     fors_skGen(SK.seed, PK.seed, ADRS, i . 2^a + indices)
 *   5:     for j from 0 to a - 1 do                         > compute auth path
 *   6:         s <- lower(indices[i]/2^j) XOR 1
 *   7:         AUTH[j] <- fors_node(SK.seed, i . 2^(a-j) + s, j, PK.seed, ADRS)
 *   8:     end for
 *   9:     SIGFORS <- SIGFORS || AUTH
 *  10: end for
 *  11: return SIGFORS
 *
 * @param [in]       key       SLH-DSA key.
 * @param [in]       md        Message digest.
 * @param [in]       sk_seed   Private key seed.
 * @param [in]       pk_seed   Public key seed.
 * @param [inm out]  adrs      FORS tree HashAddress.
 * @param [out]      sig_fors  FORS signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_sign(SlhDsaKey* key, const byte* md,
    const byte* sk_seed, const byte* pk_seed, word32* adrs, byte* sig_fors)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    word16 indices[SLHDSA_MAX_INDICES_SZ];
    int i;
    int j;
    byte n = key->params->n;
    byte a = key->params->a;
    byte k = key->params->k;

    /* Step 2: Convert message digest to base 2^a. */
    slhdsakey_base_2b(md, a, k, indices);

    /* Step 3: For each index: */
    for (i = 0; i < k; i++) {
        /* Step 4: Generate FORS private key value into signature. */
        ret = slhdsakey_fors_sk_gen(key, sk_seed, pk_seed, adrs,
            ((word32)i << a) + indices[i], sig_fors);
        if (ret != 0) {
            break;
        }
        /* Step 4: Move over private key value. */
        sig_fors += n;

    #if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
        if (!SLHDSA_IS_SHA2(key->params->param) &&
                IS_INTEL_AVX2(cpuid_flags) &&
                CAN_SAVE_VECTOR_REGISTERS()) {
            word16 idx = indices[i];
            /* Step 5: For each bit: */
            for (j = 0; j < a; j++) {
                /* Calculate side. */
                word32 s = idx ^ 1;
                /* Step 7: Compute authentication node into signature. */
                ret = slhdsakey_fors_node_x4(key, sk_seed, (i << (a - j)) + s,
                    j, pk_seed, adrs, sig_fors);
                if (ret != 0) {
                    break;
                }
                /* Step 9: Move signature to after authentication node. */
                sig_fors += n;
                /* Update tree index. */
                idx >>= 1;
            }
        }
        else
    #endif
        {
            word16 idx = indices[i];
            /* Step 5: For each bit: */
            for (j = 0; j < a; j++) {
                /* Calculate side. */
                word32 s = idx ^ 1;
                /* Step 7: Compute authentication node into signature. */
                ret = slhdsakey_fors_node_c(key, sk_seed, (i << (a - j)) + s, j,
                    pk_seed, adrs, sig_fors);
                if (ret != 0) {
                    break;
                }
                /* Step 9: Move signature to after authentication node. */
                sig_fors += n;
                /* Update tree index. */
                idx >>= 1;
            }
        }
        if (ret != 0) {
            break;
        }
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
/* F hash 4 simultaneously.
 *
 * Each hash varies by the tree index with the values passed in.
 * Each n-byte message in sig_fors is offset by so x n bytes.
 *
 * FIPS 205. Section 4.1.
 *   F(PK.seed, ADRS, M1) (Bn x B32 x Bn -> Bn) is a hash function that takes an
 *   n-byte message as input and produces an n-byte output.
 * FIPS 205. Section 11.1.
 *   F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1 , 8n)
 *
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  addr      Encoded HashAddress.
 * @param [in]  sig_fors  n-byte messages.
 * @param [in]  so        Tree index start value.
 * @param [in]  n         Number of bytes in hash output.
 * @param [in]  ti        Tree index start value.
 * @param [out] node      n-byte hash outputs.
 * @param [in]  heap      Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_hash_f_ti4_x4(const byte* pk_seed, byte* addr,
    const byte* sig_fors, int so, byte n, word32* ti, byte* node, void* heap)
{
    int ret = 0;
    int i;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_x4(state, pk_seed, addr, n);
        SHAKE256_SET_TREE_INDEX_IDX(state, o, ti);
        for (i = 0; i < n / 8; i++) {
            state[o + 0] = ((word64*)(sig_fors + 0 * so * n))[i];
            state[o + 1] = ((word64*)(sig_fors + 1 * so * n))[i];
            state[o + 2] = ((word64*)(sig_fors + 2 * so * n))[i];
            state[o + 3] = ((word64*)(sig_fors + 3 * so * n))[i];
            o += 4;
        }
        SHAKE256_SET_END_X4(state, o);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, node, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

/* H hash 4 simultaneously with two buffers holding two halves of messages.
 *
 * Each hash varies by the tree index with the first value in sequence passed
 * in.
 * Each n-byte message in sig_fors is offset by so x n bytes.
 *
 * FIPS 205. Section 4.1.
 *   H(PK.seed, ADRS, M2) (Bn x B32 x B2n -> Bn) is a special case of Tl that
 *   takes a 2n-byte message as input.
 * FIPS 205. Section 11.1.
 *   H(PK.seed, ADRS, M2) = SHAKE256(PK.seed || ADRS || M2, 8n)
 *
 * @param [in]      pk_seed   Public key seed.
 * @param [in]      addr      Encoded HashAddress.
 * @param [in, out] node      On in, n-byte messages. On out, hash output.
 * @param [in]      sig_fors  n-byte messages.
 * @param [in]      so        Tree index start value.
 * @param [in]      bit       Bits to indicate which order of node/sig_fors.
 * @param [in]      n         Number of bytes in hash output.
 * @param [in]      ti        Tree index start value.
 * @param [in]      heap      Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_hash_h_2_x4(const byte* pk_seed, byte* addr, byte* node,
    const byte* sig_fors, int so, word32* bit, byte n, word32 th, word32* ti,
    void* heap)
{
    int ret = 0;
    int i;
    int j;
    word32 o = 0;
    WC_DECLARE_VAR(state, word64, 25 * 4, heap);

    (void)heap;

    WC_ALLOC_VAR_EX(state, word64, 25 * 4, heap, DYNAMIC_TYPE_SLHDSA,
        ret = MEMORY_E);
    if (ret == 0) {
        o = slhdsakey_shake256_set_seed_ha_x4(state, pk_seed, addr, n);
        SHAKE256_SET_TREE_HEIGHT(state, o, th);
        SHAKE256_SET_TREE_INDEX_IDX(state, o, ti);
        for (i = 0; i < n / 8; i++) {
            for (j = 0; j < 4; j++) {
                if (bit[j] == 0) {
                    state[o + j] = ((word64*)(node + j * n))[i];
                }
                else {
                    state[o + j] = ((word64*)(sig_fors + j * so * n))[i];
                }
            }
            o += 4;
        }
        for (i = 0; i < n / 8; i++) {
            for (j = 0; j < 4; j++) {
                if (bit[j] == 0) {
                    state[o + j] = ((word64*)(sig_fors + j * so * n))[i];
                }
                else {
                    state[o + j] = ((word64*)(node + j * n))[i];
                }
            }
            o += 4;
        }
        SHAKE256_SET_END_X4(state, o);
        ret = SAVE_VECTOR_REGISTERS2();
        if (ret == 0) {
            sha3_blocksx4_avx2(state);
            RESTORE_VECTOR_REGISTERS();
            slhdsakey_shake256_get_hash_x4(state, node, n);
        }

        WC_FREE_VAR_EX(state, heap, DYNAMIC_TYPE_SLHDSA);
    }

    return ret;
}

/* Compute ith FORS public key from ith FORS signature.
 *
 * 4 hashes computed simultaneously.
 *
 * FIPS 205. Section 8.4 Algorithm 17.
 * fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *  ...
 *   4:     ADRS.setTreeHeight(0)                                 > compute leaf
 *   5:     ADRS.setTreeIndex(i . 2^a + indices[i])
 *   6:     node[0] <- F(PK.seed, ADRS, sk)
 *   7:     auth <- SIGFORS.getAUTH(i)
 *                     > SIGFORS [(i . (a + 1) + 1) . n : (i + 1) . (a + 1) . n]
 *   8:     for j from 0 to a - 1 do           > compute root from leaf and AUTH
 *   9:         ADRS.setTreeHeight(j + 1)
 *  10:         if lower(indices[i]/(2^j)) is even then
 *  11:             ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
 *  12:             node[1] <- H(PK.seed, ADRS, node[0] || auth[i])
 *  13:         else
 *  14:             ADRS.setTreeIndex((ADRS.getTreeIndex() - 1)/2)
 *  15:             node[1] <- H(PK.seed, ADRS, auth[j] || node[0])
 *  16:         end if
 *  17:         node[0] <- node[1]
 *  18:     end for
 *  19:     root[i] <- node[0]
 *  ...
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  sig_fors  FORS signature.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  addr      Encoded HashAddress.
 * @param [in]  indices   Base 2^a values from message digest.
 * @param [in]  i         Index.
 * @param [out] node      Root node of ith tree.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int slhdsakey_fors_pk_from_sig_i_x4(SlhDsaKey* key, const byte* sig_fors,
    const byte* pk_seed, byte* addr, const word16* indices, int i, byte* node)
{
    int ret;
    int j;
    int k;
    byte n = key->params->n;
    byte a = key->params->a;
    word32 ti[4];
    word32 bit[4];

    /* Step 5: Calculate the index of each hash ... */
    ti[0] = ((word32)(i + 0) << a) + indices[i + 0];
    ti[1] = ((word32)(i + 1) << a) + indices[i + 1];
    ti[2] = ((word32)(i + 2) << a) + indices[i + 2];
    ti[3] = ((word32)(i + 3) << a) + indices[i + 3];
    /* Steps 4-6: Compute nodes.  */
    ret = slhdsakey_hash_f_ti4_x4(pk_seed, addr, sig_fors, 1 + a, n, ti, node,
        key->heap);
    if (ret == 0) {
        /* Step 7: Move on to authentication nodes. */
        sig_fors += n;
        /* Step 8: For each level: */
        for (j = 0; j < a; j++) {
            /* Calculate which order of node and sig_fors for each hash. */
            for (k = 0; k < 4; k++) {
                bit[k] = ti[k] & 1;
                ti[k] /= 2;
            }
            /* Steps 9-17: 4 hash with tree indices. */
            ret = slhdsakey_hash_h_2_x4(pk_seed, addr, node, sig_fors, 1 + a,
                bit, n, j + 1, ti, key->heap);
            if (ret != 0) {
                break;
            }
            /* Move on to next authentication node. */
            sig_fors += n;
        }
    }

    return ret;
}

/* Compute ith FORS public key from ith FORS signature.
 *
 * 4 hashes computed simultaneously.
 *
 * FIPS 205. Section 8.4 Algorithm 17.
 * fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *  ...
 *   2: for i from 0 to k - 1 do
 *   3:     sk <- SIGFORS.getSK(i)
 *                           > SIGFORS [i . (a + 1) . n : (i . (a + 1) + 1) . n]
 *   4:     ADRS.setTreeHeight(0)                                 > compute leaf
 *   5:     ADRS.setTreeIndex(i . 2^a + indices[i])
 *   6:     node[0] <- F(PK.seed, ADRS, sk)
 *   7:     auth <- SIGFORS.getAUTH(i)
 *                     > SIGFORS [(i . (a + 1) + 1) . n : (i + 1) . (a + 1) . n]
 *   8:     for j from 0 to a - 1 do           > compute root from leaf and AUTH
 *   9:         ADRS.setTreeHeight(j + 1)
 *  10:         if lower(indices[i]/(2^j)) is even then
 *  11:             ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
 *  12:             node[1] <- H(PK.seed, ADRS, node[0] || auth[i])
 *  13:         else
 *  14:             ADRS.setTreeIndex((ADRS.getTreeIndex() - 1)/2)
 *  15:             node[1] <- H(PK.seed, ADRS, auth[j] || node[0])
 *  16:         end if
 *  17:         node[0] <- node[1]
 *  18:     end for
 *  19:     root[i] <- node[0]
 *  20: end for
 * ...
 *  24: pk <- Tk(PK.seed, forspkADRS, root)        > compute the FORS public key
 * ...
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  sig_fors  FORS signature.
 * @param [in]  indices   Base 2^a values from message digest.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  adrs      Encoded HashAddress.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_pk_from_sig_x4(SlhDsaKey* key, const byte* sig_fors,
    const word16* indices, const byte* pk_seed, word32* adrs)
{
    int ret = 0;
    int i;
    int j;
    byte n = key->params->n;
    byte a = key->params->a;
    byte k = key->params->k;
    byte addr[SLHDSA_HA_SZ];
    WC_DECLARE_VAR(node, byte, SLHDSA_MAX_INDICES_SZ * SLHDSA_MAX_N, key->heap);

    WC_ALLOC_VAR_EX(node, byte, SLHDSA_MAX_INDICES_SZ * SLHDSA_MAX_N, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        /* Step 4: Set tree height for address.  */
        HA_SetTreeHeight(adrs, 0);
        /* Encode address for multiple hashing. */
        HA_Encode(adrs, addr);

        /* Step 2: Do multiple of 4 iterations. */
        for (i = 0; i < k-3; i += 4) {
            /* Steps 4-19: Compute public key root for signature at index. */
            ret = slhdsakey_fors_pk_from_sig_i_x4(key, sig_fors, pk_seed, addr,
                indices, i, node + i * n);
            if (ret != 0) {
                break;
            }
            /* Move on to next signatures. */
            sig_fors += 4 * (1 + a) * n;
        }
    }
    if (ret == 0) {
        /* Step 2: Do remaining iterations. */
        for (; i < k; i++) {
            /* Step 5: Calculate index ...  */
            word32 idx = ((word32)i << a) + indices[i];

            /* Step 4: Set tree height for address.  */
            HA_SetTreeHeight(adrs, 0);
            /* Step 5: Set tree index for address.  */
            HA_SetTreeIndex(adrs, idx);
            /* Step 6: Compute node from public key seed, address and value. */
            ret = HASH_F(key, pk_seed, adrs, sig_fors, n, node + i * n);
            if (ret != 0) {
                break;
            }
            /* Step 7: Move to authentication nodes. */
            sig_fors += n;

            /* Step 8: For all heights: */
            for (j = 0; j < a; j++) {
                /* Step 10: Calculate side ... */
                word32 side = idx & 1;

                /* Step 11/14: Update tree index value ... */
                idx >>= 1;
                /* Step 9: Set tree height. */
                HA_SetTreeHeight(adrs, j + 1);
                /* Step 11/14: Set tree index. */
                HA_SetTreeIndex(adrs, idx);
                /* Step 10: Check which side node is on. */
                if (side == 0) {
                    /* Step 12: Hash node || auth node. */
                    ret = HASH_H_2(key, pk_seed, adrs, node + i * n,
                        sig_fors, n, node + i * n);
                }
                else {
                    /* Step 15: Hash auth node || node. */
                    ret = HASH_H_2(key, pk_seed, adrs, sig_fors,
                        node + i * n, n, node + i * n);
                }
                if (ret != 0) {
                    break;
                }
                /* Move on to next authentication node. */
                sig_fors += n;
            }
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        /* Step 24: Add more root nodes to hash ... */
        ret = HASH_T_UPDATE(key, node, i * n);
    }

    WC_FREE_VAR_EX(node, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#endif

#if !defined(WOLFSSL_WC_SLHDSA_SMALL_MEM)
/* Compute FORS public key from FORS signature.
 *
 * 4 hashes computed simultaneously.
 *
 * FIPS 205. Section 8.4 Algorithm 17.
 * fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *  ...
 *   2: for i from 0 to k - 1 do
 *   3:     sk <- SIGFORS.getSK(i)
 *                           > SIGFORS [i . (a + 1) . n : (i . (a + 1) + 1) . n]
 *   4:     ADRS.setTreeHeight(0)                                 > compute leaf
 *   5:     ADRS.setTreeIndex(i . 2^a + indices[i])
 *   6:     node[0] <- F(PK.seed, ADRS, sk)
 *   7:     auth <- SIGFORS.getAUTH(i)
 *                     > SIGFORS [(i . (a + 1) + 1) . n : (i + 1) . (a + 1) . n]
 *   8:     for j from 0 to a - 1 do           > compute root from leaf and AUTH
 *   9:         ADRS.setTreeHeight(j + 1)
 *  10:         if lower(indices[i]/(2^j)) is even then
 *  11:             ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
 *  12:             node[1] <- H(PK.seed, ADRS, node[0] || auth[i])
 *  13:         else
 *  14:             ADRS.setTreeIndex((ADRS.getTreeIndex() - 1)/2)
 *  15:             node[1] <- H(PK.seed, ADRS, auth[j] || node[0])
 *  16:         end if
 *  17:         node[0] <- node[1]
 *  18:     end for
 *  19:     root[i] <- node[0]
 *  20: end for
 * ...
 *  24: pk <- Tk(PK.seed, forspkADRS, root)        > compute the FORS public key
 * ...
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  sig_fors  FORS signature.
 * @param [in]  indices   Base 2^a values from message digest.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  adrs      HashAddress.
 * @param [out] pk_fors   FORS public key from signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_pk_from_sig_c(SlhDsaKey* key, const byte* sig_fors,
    const word16* indices, const byte* pk_seed, word32* adrs, byte* pk_fors)
{
    int ret = 0;
    int i = 0;
    int j;
    byte n = key->params->n;
    byte a = key->params->a;
    byte k = key->params->k;
    WC_DECLARE_VAR(node, byte, SLHDSA_MAX_INDICES_SZ * SLHDSA_MAX_N, key->heap);

    (void)pk_fors;

    WC_ALLOC_VAR_EX(node, byte, SLHDSA_MAX_INDICES_SZ * SLHDSA_MAX_N, key->heap,
        DYNAMIC_TYPE_SLHDSA, ret = MEMORY_E);
    if (ret == 0) {
        /* Step 2: For all indices: */
        for (i = 0; i < k; i++) {
            /* Step 5: Calculate index ...  */
            word32 idx = ((word32)i << a) + indices[i];

            /* Step 4: Set tree height for address.  */
            HA_SetTreeHeight(adrs, 0);
            /* Step 5: Set tree index for address.  */
            HA_SetTreeIndex(adrs, idx);
            /* Step 6: Compute node from public key seed, address and value. */
            ret = HASH_F(key, pk_seed, adrs, sig_fors, n, node + i * n);
            if (ret != 0) {
                break;
            }
            /* Step 7: Move to authentication nodes. */
            sig_fors += n;

            /* Step 8: For all heights: */
            for (j = 0; j < a; j++) {
                /* Step 10: Calculate side ... */
                word32 bit = idx & 1;

                /* Step 11/14: Update tree index value ... */
                idx >>= 1;
                /* Step 9: Set tree height. */
                HA_SetTreeHeight(adrs, j + 1);
                /* Step 11/14: Set tree index. */
                HA_SetTreeIndex(adrs, idx);
                /* Step 10: Check which side node is on. */
                if (bit == 0) {
                    /* Step 12: Hash node || auth node. */
                    ret = HASH_H_2(key, pk_seed, adrs, node + i * n,
                        sig_fors, n, node + i * n);
                }
                else {
                    /* Step 15: Hash auth node || node. */
                    ret = HASH_H_2(key, pk_seed, adrs, sig_fors,
                        node + i * n, n, node + i * n);
                }
                if (ret != 0) {
                    break;
                }
                /* Move on to next authentication node. */
                sig_fors += n;
            }
            if (ret != 0) {
                break;
            }
        }
    }
    if (ret == 0) {
        /* Step 24: Add more root nodes to hash ... */
        ret = HASH_T_UPDATE(key, node, i * n);
    }

    WC_FREE_VAR_EX(node, key->heap, DYNAMIC_TYPE_SLHDSA);
    return ret;
}
#else
/* Compute FORS public key from FORS signature.
 *
 * Update hash one node at a time to save stack.
 *
 * FIPS 205. Section 8.4 Algorithm 17.
 * fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *  ...
 *   2: for i from 0 to k - 1 do
 *   3:     sk <- SIGFORS.getSK(i)
 *                           > SIGFORS [i . (a + 1) . n : (i . (a + 1) + 1) . n]
 *   4:     ADRS.setTreeHeight(0)                                 > compute leaf
 *   5:     ADRS.setTreeIndex(i . 2^a + indices[i])
 *   6:     node[0] <- F(PK.seed, ADRS, sk)
 *   7:     auth <- SIGFORS.getAUTH(i)
 *                     > SIGFORS [(i . (a + 1) + 1) . n : (i + 1) . (a + 1) . n]
 *   8:     for j from 0 to a - 1 do           > compute root from leaf and AUTH
 *   9:         ADRS.setTreeHeight(j + 1)
 *  10:         if lower(indices[i]/(2^j)) is even then
 *  11:             ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
 *  12:             node[1] <- H(PK.seed, ADRS, node[0] || auth[i])
 *  13:         else
 *  14:             ADRS.setTreeIndex((ADRS.getTreeIndex() - 1)/2)
 *  15:             node[1] <- H(PK.seed, ADRS, auth[j] || node[0])
 *  16:         end if
 *  17:         node[0] <- node[1]
 *  18:     end for
 *  19:     root[i] <- node[0]
 *  20: end for
 * ...
 *  24: pk <- Tk(PK.seed, forspkADRS, root)        > compute the FORS public key
 * ...
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  sig_fors  FORS signature.
 * @param [in]  indices   Base 2^a values from message digest.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  adrs      HashAddress.
 * @param [out] node      Root node of ith tree.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_pk_from_sig_c(SlhDsaKey* key, const byte* sig_fors,
    const word16* indices, const byte* pk_seed, word32* adrs, byte* node)
{
    int ret;
    int i;
    int j;
    byte n = key->params->n;
    byte a = key->params->a;
    byte k = key->params->k;

    /* Step 2: For all indices: */
    for (i = 0; i < k; i++) {
        /* Step 5: Calculate index ...  */
        word32 idx = ((word32)i << a) + indices[i];

        /* Step 4: Set tree height for address.  */
        HA_SetTreeHeight(adrs, 0);
        /* Step 5: Set tree index for address.  */
        HA_SetTreeIndex(adrs, idx);
        /* Step 6: Compute node from public key seed, address and value. */
        ret = HASH_F(key, pk_seed, adrs, sig_fors, n, node);
        if (ret != 0) {
            break;
        }
        /* Step 7: Move to authentication nodes. */
        sig_fors += n;

        /* Step 8: For all heights: */
        for (j = 0; j < a; j++) {
            /* Step 10: Calculate side ... */
            word32 bit = idx & 1;

            /* Step 11/14: Update tree index value ... */
            idx >>= 1;
            /* Step 9: Set tree height. */
            HA_SetTreeHeight(adrs, j + 1);
            /* Step 11/14: Set tree index. */
            HA_SetTreeIndex(adrs, idx);
            /* Step 10: Check which side node is on. */
            if (bit == 0) {
                /* Step 12: Hash node || auth node. */
                ret = HASH_H_2(key, pk_seed, adrs, node, sig_fors, n,
                    node);
            }
            else {
                /* Step 15: Hash auth node || node. */
                ret = HASH_H_2(key, pk_seed, adrs, sig_fors, node, n,
                    node);
            }
            if (ret != 0) {
                break;
            }
            /* Move on to next authentication node. */
            sig_fors += n;
        }
        if (ret == 0) {
            /* Step 24: Add root node to hash ... */
            ret = HASH_T_UPDATE(key, node, n);
        }
        if (ret != 0) {
            break;
        }
    }

    return ret;
}
#endif

/* Compute FORS public key from FORS signature.
 *
 * 4 hashes computed simultaneously.
 *
 * FIPS 205. Section 8.4 Algorithm 17.
 * fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *   1: indices <- base_2b(md, a, k)
 *  ...
 *  21: forspkADRS <- ADRS    > copy address to create a FORS public-key address
 *  22: forspkADRS.setTypeAndClear(FORS_ROOTS)
 *  23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
 *  24: pk <- Tk(PK.seed, forspkADRS, root)        > compute the FORS public key
 *  25: return pk
 *
 * @param [in]  key       SLH-DSA key.
 * @param [in]  sig_fors  FORS signature.
 * @param [in]  md        Message digest.
 * @param [in]  pk_seed   Public key seed.
 * @param [in]  addr      Encoded HashAddress.
 * @param [out] pk_fors   FORS public key form signature.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_fors_pk_from_sig(SlhDsaKey* key, const byte* sig_fors,
    const byte* md, const byte* pk_seed, word32* adrs, byte* pk_fors)
{
    int ret;
    word16 indices[SLHDSA_MAX_INDICES_SZ];
    HashAddress forspk_adrs;
    byte n = key->params->n;
    byte a = key->params->a;
    byte k = key->params->k;
    int hash_t_started = 0;

    /* Step 1: Get indices from byte array. */
    slhdsakey_base_2b(md, a, k, indices);

    /* Step 21: Create address to FORS roots */
    HA_Copy(forspk_adrs, adrs);
    /* Steps 22-23: Set type and clear all but key pair address. */
    HA_SetTypeAndClearNotKPA(forspk_adrs, HA_FORS_ROOTS);
    /* Step 24: Add public key seed and FORS roots address to hash ... */
    ret = HASH_T_START_ADDR(key, pk_seed, forspk_adrs, n);

    if (ret == 0) {
        hash_t_started = 1;
    }

    /* Steps 2-20: Compute roots and add to hash. */
#if defined(USE_INTEL_SPEEDUP) && !defined(WOLFSSL_WC_SLHDSA_SMALL)
    if ((ret == 0) && !SLHDSA_IS_SHA2(key->params->param) &&
            IS_INTEL_AVX2(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = slhdsakey_fors_pk_from_sig_x4(key, sig_fors, indices, pk_seed,
            adrs);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    if (ret == 0) {
        ret = slhdsakey_fors_pk_from_sig_c(key, sig_fors, indices, pk_seed,
            adrs, pk_fors);
    }

    if (ret == 0) {
        /* Step 24. Compute FORS public key. */
        ret = HASH_T_FINAL(key, pk_fors, n);
    }

    if (hash_t_started) {
        HASH_T_FREE(key);
    }

    return ret;
}

/******************************************************************************
 * SLH-DSA API
 ******************************************************************************/

/* Initialize an SLH-DSA key.
 *
 * @param [in] key    SLH-DSA key.
 * @param [in] param  SLH-DSA parameter set to use.
 * @param [in] heap   Dynamic memory allocation hint.
 * @param [in] devId  Device Id.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  NOT_COMPILED_IN when parameter set not compiled in.
 * @return  SHAKE-256 error return code on digest initialization failure.
 */
int wc_SlhDsaKey_Init(SlhDsaKey* key, enum SlhDsaParam param, void* heap,
    int devId)
{
    int ret = 0;
    int idx = -1;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        int i;

        /* Find parameters in available parameter list. */
        for (i = 0; i < SLHDSA_PARAM_LEN; i++) {
            if (param == SlhDsaParams[i].param) {
                idx = i;
                break;
            }
        }
        if (idx == -1) {
            /* Parameter set not compiled in.  */
            ret = NOT_COMPILED_IN;
        }
    }
    if (ret == 0) {
        /* Zeroize key. */
        XMEMSET(key, 0, sizeof(SlhDsaKey));

        /* Set the parameters into key early so SLHDSA_IS_SHA2 works. */
        key->params = &SlhDsaParams[idx];
        /* Set heap hint to use with all allocations. */
        key->heap = heap;
    #ifdef WOLF_CRYPTO_CB
        /* Set device id. */
        key->devId = devId;
    #endif

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(param)) {
            /* Initialize SHA2 hash objects. */
            ret = wc_InitSha256(&key->hash.sha2.sha256);
            if ((ret == 0) && (key->params->n > 16)) {
                ret = wc_InitSha512(&key->hash.sha2.sha512);
            }
        }
        else
#endif
        {
            /* Initialize SHAKE-256 objects. */
            ret = wc_InitShake256(&key->hash.shk.shake, key->heap,
                INVALID_DEVID);
            if (ret == 0) {
                ret = wc_InitShake256(&key->hash.shk.shake2, key->heap,
                    INVALID_DEVID);
            }
        }
    }
    (void)devId;

#if defined(USE_INTEL_SPEEDUP)
    /* Ensure the CPU features are known. */
    cpuid_get_flags_ex(&cpuid_flags);
#endif

    return ret;
}

/* Free the SLH-DSA key.
 *
 * @param [in] key  SLH-DSA key. Cannot be used after this call.
 */
void wc_SlhDsaKey_Free(SlhDsaKey* key)
{
    /* Check we have a valid key to free. */
    if ((key != NULL) && (key->params != NULL)) {
        /* Ensure the private key data is zeroized. */
        ForceZero(key->sk, key->params->n * 2);
#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* Dispose of the SHA2 hash objects. */
            wc_Sha256Free(&key->hash.sha2.sha256);
            wc_Sha256Free(&key->hash.sha2.sha256_2);
            wc_Sha256Free(&key->hash.sha2.sha256_mid);
            if (key->params->n > 16) {
                wc_Sha512Free(&key->hash.sha2.sha512);
                wc_Sha512Free(&key->hash.sha2.sha512_2);
                wc_Sha512Free(&key->hash.sha2.sha512_mid);
            }
        }
        else
#endif
        {
            /* Dispose of the SHAKE-256 objects. */
            wc_Shake256_Free(&key->hash.shk.shake2);
            wc_Shake256_Free(&key->hash.shk.shake);
        }
    }
}

/* Set the HashAddress based on message digest data.
 *
 * FIPS 205. Section 9.2. Algorithm 19.
 * slh_sign_internal(M, SK, addrnd)
 *   1: ADRS <- toByte(0, 32)
 *  ...
 *   7: tmp_idxtree <- digest [upper(k.a / 8) : upper(k.a / 8) +
 *                                              upper((h - h/d) / 8)]
 *                                             > next upper((h - h/d) / 8) bytes
 *   8: tmp_idxleaf <- digest [upper(k.a / 8) + upper((h - h/d) / 8) :
 *                             upper(k.a / 8) + upper((h - h/d) / 8) +
 *                             upper(h / 8d) ]
 *                                                    > next upper(h / 8d) bytes
 *   9: idxtree <- toInt(tmp_idxtree, upper((h-h/d) / 8)) mod 2^(h-h/d)
 *  10: idxleaf <- toInt(tmp_idxleaf, upper(h / 8d)) mode 2^(h/d)
 *  11: ADRS.setTreeAddress(idxtree)
 *  12: ADRS.setTypeAndClear(FORS_TREE)
 *  13: ADRS.setKeyPairAddress(idxleaf)
 *  ...
 *
 * FIPS 205. Section 9.3. Algorithm 20.
 * slh_verify_internal(M, SIG, PK)
 *   4: ADRS <- toByte(0, 32)
 *  ...
 *  10: tmp_idxtree <- digest [upper(k.a / 8) : upper(k.a / 8) +
 *                                              upper((h - h/d) / 8)]
 *                                             > next upper((h - h/d) / 8) bytes
 *  11: tmp_idxleaf <- digest [upper(k.a / 8) + upper((h - h/d) / 8) :
 *                             upper(k.a / 8) + upper((h - h/d) / 8) +
 *                             upper(h / 8d) ]
 *                                                    > next upper(h / 8d) bytes
 *  12: idxtree <- toInt(tmp_idxtree, upper((h-h/d) / 8)) mod 2^(h-h/d)
 *  13: idxleaf <- toInt(tmp_idxleaf, upper(h / 8d)) mode 2^(h/d)
 *  14: ADRS.setTreeAddress(idxtree)
 *  15: ADRS.setTypeAndClear(FORS_TREE)
 *  16: ADRS.setKeyPairAddress(idxleaf)
 *  ...
 *
 * @param [in]  key   SLH-DSA key.
 * @param [in]  md    Message digest.
 * @param [out] adrs  FORS tree HashAddress.
 * @param [out] t     Tree index as 3 32-bit integers.
 * @param [out] l     Tree leaf index.
 */
static void slhdsakey_set_ha_from_md(SlhDsaKey* key, const byte* md,
    HashAddress adrs, word32* t, word32* l)
{
    const byte* p;
    int bits;

    /* Step 1/4: Set address to all zeroes. */
    HA_Init(adrs);
    /* Step 7/10: Get pointer to tree index data. */
    p = md + key->params->dl1 + (key->params->dl2 - 8);
    /* Step 9/12: Convert tree index data to an integer ... */
    t[0] = 0;
    ato32(p + 0, &t[1]);
    ato32(p + 4, &t[2]);
    /* Step 9/12: Mask off any extra high bits. */
    bits = key->params->h  - (key->params->h / key->params->d);
    if (bits < 64) {
        t[1] &= ((word32)1 << (bits - 32)) - 1;
    }

    /* Step 8/11: Get pointer to tree leaf index data. */
    p = md + key->params->dl1 + key->params->dl2 + (key->params->dl3 - 4);
    /* Step 10/13: Convert tree leaf index data to an integer ... */
    ato32(p, l);
    /* Step 10/13: Mask off any extra high bits. */
    bits = key->params->h / key->params->d;
    *l &= ((word32)1 << bits) - 1;

    /* Step 11/14: Set the tree index into address. */
    HA_SetTreeAddress(adrs, t);
    /* Step 12/15: Set type of address and clear except key pair address. */
    HA_SetTypeAndClearNotKPA(adrs, HA_FORS_TREE);
    /* Step 13/16: Set key pair address. */
    HA_SetKeyPairAddress(adrs, *l);
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Generate an SLH-DSA key with a random number generator.
 *
 * FIPS 205. Section 10.1. Algorithm 21.
 * slh_keygen()
 *   1: SK.seed <-$- Bn     > set SK.seed, SK.prf, and PK.seed to random n-byte
 *   2: SK.prf <-$- Bn          > strings using an approved random bit generator
 *   3: PK.seed <-$- Bn
 *   4: if SK.seed = NULL or SK.prf = NULL or PK.seed = NULL then
 *   5:     return falsity
 *                 > return an error indication if random bit generation failed
 *   6: end if
 *   7: return slh_keygen_internal(SK.seed, SK.prf, PK.seed)
 *
 * @param [in] key  SLH-DSA key.
 * @param [in] rng  Random number generator.
 * @return  0 on success.
 * @return  RNG error code when random number generation fails.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_MakeKey(SlhDsaKey* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Steps 1-5: Generate the 3 random hashes. */
        ret = wc_RNG_GenerateBlock(rng, key->sk, 3 * key->params->n);
    }
    if (ret == 0) {
        byte n = key->params->n;

        /* Step 7: Make the key with the random  */
        ret = wc_SlhDsaKey_MakeKeyWithRandom(key, key->sk, n, key->sk + n, n,
            key->sk + 2 * n, n);
    }

    return ret;
}

/* Generate an SLH-DSA key pair.
 *
 * FIPS 205. Section 9.1. Algorithm 18.
 * slh_keygen_internal(SK.seed, SK.prf, PK.seed)
 *   1: ADRS <- toByte(0, 32)
 *                        > generate the public key for the top-level XMSS tree
 *   2: ADRS.setLayerAddress(d - 1)
 *   3: PK.root <- xmss_node(SK.seed, 0, h' , PK.seed, ADRS)
 *   4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
 *
 * @param [in] key          SLH-DSA key.
 * @param [in] sk_seed      Private key seed.
 * @param [in] sk_seed_len  Length of private key seed.
 * @param [in] sk_prf       Private key PRF seed.
 * @param [in] sk_prf_len   Length of private key PRF seed.
 * @param [in] pk_seed      Public key seed.
 * @param [in] pk_seed_len  Length of public key seed.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 * @return  BAD_FUNC_ARG when sk_seed is NULL or length is not n.
 * @return  BAD_FUNC_ARG when sk_prf is NULL or length is not n.
 * @return  BAD_FUNC_ARG when pk_seed is NULL or length is not n.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_MakeKeyWithRandom(SlhDsaKey* key, const byte* sk_seed,
    word32 sk_seed_len, const byte* sk_prf, word32 sk_prf_len,
    const byte* pk_seed, word32 pk_seed_len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure private key seed is passed in and is the right length. */
    else if ((sk_seed == NULL) || (sk_seed_len != key->params->n)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure public key PRF seed is passed in and is the right length. */
    else if ((sk_prf == NULL) || (sk_prf_len != key->params->n)) {
        ret = BAD_FUNC_ARG;
    }
    /* Ensure public key seed is passed in and is the right length. */
    else if ((pk_seed == NULL) || (pk_seed_len != key->params->n)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        byte n = key->params->n;
        HashAddress adrs;

        /* Step 4: Copy the seeds into the key if they didn't come from the key.
         */
        if (sk_seed != key->sk) {
            XMEMCPY(key->sk        , sk_seed, n);
            XMEMCPY(key->sk +     n, sk_prf , n);
            XMEMCPY(key->sk + 2 * n, pk_seed, n);
        }

#ifdef WOLFSSL_SLHDSA_SHA2
        /* Pre-compute SHA2 midstates now that PK.seed is set. */
        if (SLHDSA_IS_SHA2(key->params->param)) {
            ret = slhdsakey_precompute_sha2_midstates(key);
        }
        if (ret != 0) {
            return ret;
        }
#endif

        /* Step 1: Set address to all zeroes. */
        HA_Init(adrs);
        /* Step 2: Set the address layer to the top of the subtree. */
        HA_SetLayerAddress(adrs, key->params->d - 1);
        /* Step 3: Compute the root node. */
        ret = slhdsakey_xmss_node(key, sk_seed, 0, key->params->h_m, pk_seed,
             adrs, &key->sk[3 * n]);
        if (ret == 0) {
            key->flags = WC_SLHDSA_FLAG_BOTH_KEYS;
        }
    }

    return ret;
}

/* Generate an SLH-DSA signature.
 *
 * FIPS 205. Section 9.2. Algorithm 19.
 * slh_sign_internal(M, SK, addrnd)
 *  ...
 *                                              upper((h - h/d) / 8)]
 *                                             > next upper((h - h/d) / 8) bytes
 *   8: tmp_idxleaf <- digest [upper(k.a / 8) + upper((h - h/d) / 8) :
 *                             upper(k.a / 8) + upper((h - h/d) / 8) +
 *                             upper(h / 8d) ]
 *                                                    > next upper(h / 8d) bytes
 *   9: idxtree <- toInt(tmp_idxtree, upper((h-h/d) / 8)) mod 2^(h-h/d)
 *  10: idxleaf <- toInt(tmp_idxleaf, upper(h / 8d)) mode 2^(h/d)
 *  11: ADRS.setTreeAddress(idxtree)
 *  12: ADRS.setTypeAndClear(FORS_TREE)
 *  13: ADRS.setKeyPairAddress(idxleaf)
 *  14: SIGFORS <- fors_sign(md, SK.seed, PK.seed, ADRS)
 *  15: SIG <- SIG || SIGFORS
 *  16: PKFORS <- fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)      > get FORS key
 *  17: SIGHT <- ht_sign(PKFORS , SK.seed, PK.seed, idxtree , idxleaf )
 *  18: SIG <- SIG || SIGHT
 *  19: return SIG
 *
 * @param [in]  key  SLH-DSA key.
 * @param [in]  md   Message digest.
 * @param [out] sig  Signature buffer.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_sign(SlhDsaKey* key, byte* md, byte* sig)
{
    int ret;
    HashAddress adrs;
    word32 t[3];
    word32 l;
    byte pk_fors[SLHDSA_MAX_N];
    byte n = key->params->n;

    /* Steps 1, 7-13: Set address based on message digest. */
    slhdsakey_set_ha_from_md(key, md, adrs, t, &l);

    /* Step 14: FORS sign message. */
    ret = slhdsakey_fors_sign(key, md, key->sk, key->sk + 2 * n, adrs, sig);
    if (ret == 0) {
        /* Step 16: FORS public key from signature. */
        ret = slhdsakey_fors_pk_from_sig(key, sig, md, key->sk + 2 * n, adrs,
            pk_fors);
        /* Step 15: Move over signature data. */
        sig += key->params->k * (1 + key->params->a) * n;
    }
    if (ret == 0) {
        /* Steps 17-18: Hypertree sign FORS public key. */
        ret = slhdsakey_ht_sign(key, pk_fors, key->sk, key->sk + 2 * n, t, l,
            sig);
    }

    return ret;
}

/* Lower-level sign: slh_sign_internal(M, SK, addrnd).
 *
 * Takes M directly and performs PRF_msg, H_msg, and the FORS + hypertree
 * signing -- Algorithm 19 without the M' construction of Algorithm 22.
 *
 * FIPS 205. Section 9.2. Algorithm 19.
 * slh_sign_internal(M, SK, addrnd)
 *   2: opt_rand <- addrnd
 *   3: R <- PRFmsg(SK.prf, opt_rand, M)
 *   4: SIG <- R
 *   5: digest <- Hmsg(R, PK.seed, PK.root, M)
 *   6: md <- digest[0 : upper(k*a / 8)]
 *  ...
 *
 * @param [in]      key     SLH-DSA key (private key must be set).
 * @param [in]      m       Message (goes directly to PRF_msg and H_msg).
 * @param [in]      mSz     Length of message in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigSz   On in, buffer length. On out, signature length.
 * @param [in]      addRnd  opt_rand (PK.seed for deterministic).
 * @return  0 on success.
 */
static int slhdsakey_sign_internal_msg(SlhDsaKey* key, const byte* m,
    word32 mSz, byte* sig, word32* sigSz, const byte* addRnd)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (m == NULL) ||
            (sig == NULL) || (sigSz == NULL) || (addRnd == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (*sigSz < key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        byte md[SLHDSA_MAX_MD];
        byte n = key->params->n;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: PRF_msg = Trunc_n(HMAC(SK.prf, opt_rand || M)).
             * Internal interface: no M' header, pass whole M directly. */
            ret = slhdsakey_prf_msg_sha2(key, key->sk + n, addRnd,
                NULL, NULL, 0, m, mSz, n, sig);
            if (ret == 0) {
                /* SHA2: H_msg via MGF1. No header for internal interface. */
                ret = slhdsakey_h_msg_sha2(key, sig,
                    NULL, NULL, 0, m, mSz,
                    md, key->params->dl1 + key->params->dl2 +
                    key->params->dl3);
                sig += n;
            }
        }
        else
#endif
        {
            /* SHAKE: PRF_msg = SHAKE256(SK.prf || opt_rand || M, 8n). */
            {
                wc_Shake tmpShake;
                ret = wc_InitShake256(&tmpShake, NULL, INVALID_DEVID);
                if (ret == 0) ret = wc_Shake256_Update(&tmpShake, key->sk + n, n);
                if (ret == 0) ret = wc_Shake256_Update(&tmpShake, addRnd, n);
                if (ret == 0) ret = wc_Shake256_Update(&tmpShake, m, mSz);
                if (ret == 0) ret = wc_Shake256_Final(&tmpShake, sig, n);
                wc_Shake256_Free(&tmpShake);
            }
            /* SHAKE: H_msg = SHAKE256(R || PK.seed || PK.root || M, ...). */
            if (ret == 0) {
                ret = wc_InitShake256(&key->hash.shk.shake, NULL, INVALID_DEVID);
            }
            if (ret == 0) {
                ret = wc_Shake256_Update(&key->hash.shk.shake, sig, n);
                sig += n;
            }
            if (ret == 0) {
                ret = wc_Shake256_Update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = wc_Shake256_Update(&key->hash.shk.shake, m, mSz);
            }
            if (ret == 0) {
                ret = wc_Shake256_Final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            ret = slhdsakey_sign(key, md, sig);
        }
        if (ret == 0) {
            *sigSz = key->params->sigLen;
        }
    }

    return ret;
}

/* Upper-level sign: construct M' from ctx + msg, then call internal.
 *
 * FIPS 205. Section 10.2.2. Algorithm 22.
 * slh_sign(M, ctx, SK)
 *   8: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
 *   9: SIG <- slh_sign_internal(M', SK, addrnd)
 *
 * @param [in]      key    SLH-DSA key.
 * @param [in]      ctx    Context of signing.
 * @param [in]      ctxSz  Length of context in bytes.
 * @param [in]      msg    Message to sign.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [out]     sig    Buffer to hold signature.
 * @param [in, out] sigSz  On in, length of signature buffer.
 *                         On out, length of signature data.
 * @param [in]      addRnd opt_rand (PK.seed for deterministic, random otherwise).
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig, sigSz or addRnd
 *          is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_sign_external(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, byte* sig, word32* sigSz,
    const byte* addRnd)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) || (sig == NULL) ||
            (sigSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check sig buffer is large enough to hold generated signature. */
    else if (*sigSz < key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    /* Alg 22, Step 5: Check addrnd is not NULL. */
    else if (addRnd == NULL) {
        /* Alg 22, Step 6: Return error. */
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a private key to sign with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        byte md[SLHDSA_MAX_MD];
        byte hdr[2];
        byte n = key->params->n;

        /* Alg 22, Step 8: M' = toByte(0,1) || toByte(|ctx|,1) || ctx || M.
         * We stream the M' components into PRF_msg and H_msg. */
        hdr[0] = 0;
        hdr[1] = ctxSz;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: PRF_msg via HMAC. */
            ret = slhdsakey_prf_msg_sha2(key, key->sk + n, addRnd, hdr, ctx,
                ctxSz, msg, msgSz, n, sig);
            if (ret == 0) {
                /* SHA2: H_msg via MGF1. */
                ret = slhdsakey_h_msg_sha2(key, sig, hdr, ctx, ctxSz, msg,
                    msgSz, md, key->params->dl1 + key->params->dl2 +
                    key->params->dl3);
                /* Move over randomizer. */
                sig += n;
            }
        }
        else
#endif
        {
            /* SHAKE: PRF_msg streaming with M' = hdr || ctx || msg. */
            ret = slhdsakey_hash_start(&key->hash.shk.shake, key->sk + n, n);
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, addRnd, n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, msg, msgSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, sig, n);
            }
            /* SHAKE: H_msg streaming. */
            if (ret == 0) {
                ret = slhdsakey_hash_start(&key->hash.shk.shake, sig, n);
                sig += n;
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, msg, msgSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            /* Alg 19. Steps 7-19 */
            ret = slhdsakey_sign(key, md, sig);
        }
        if (ret == 0) {
            /* Return the signature size generated. */
            *sigSz = key->params->sigLen;
        }
    }

    return ret;
}

/* Generate a deterministic SLH-DSA signature.
 *
 * addrnd is the public key seed.
 *
 * @param [in]      key    SLH-DSA key.
 * @param [in]      ctx    Context of signing.
 * @param [in]      ctxSz  Length of context in bytes.
 * @param [in]      msg    Message to sign.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [out]     sig    Buffer to hold signature.
 * @param [in, out] sigSz  On in, length of signature buffer.
 *                         On out, length of signature data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg or sig is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_SignDeterministic(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, byte* sig, word32* sigSz)
{
    int ret;

    /* Validate parameters that will be used in this function. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Pure sign. */
        ret = slhdsakey_sign_external(key, ctx, ctxSz, msg, msgSz, sig, sigSz,
            key->sk + 2 * key->params->n);
    }

    return ret;
}

/* Generate a pure SLH-DSA signature.
 *
 * @param [in]      key     SLH-DSA key.
 * @param [in]      ctx     Context of signing.
 * @param [in]      ctxSz   Length of context in bytes.
 * @param [in]      msg     Message to sign.
 * @param [in]      msgSz   Length of message in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigSz   On in, length of signature buffer.
 *                          On out, length of signature data.
 * @param [in]      addRnd  Additional random for signature.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig or addrnd is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_SignWithRandom(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, byte* sig, word32* sigSz, const byte* addRnd)
{
    /* Pure sign. */
    return slhdsakey_sign_external(key, ctx, ctxSz, msg, msgSz, sig, sigSz,
        addRnd);
}

/* Generate a pure SLH-DSA signature with a random number generator.
 *
 * @param [in]      key     SLH-DSA key.
 * @param [in]      ctx     Context of signing.
 * @param [in]      ctxSz   Length of context in bytes.
 * @param [in]      msg     Message to sign.
 * @param [in]      msgSz   Length of message in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigSz   On in, length of signature buffer.
 *                          On out, length of signature data.
 * @param [in]      rng     Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig, sigSz or rng is
 *          NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_Sign(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, byte* sig, word32* sigSz, WC_RNG* rng)
{
    int ret = 0;
    byte addRnd[SLHDSA_MAX_N];

    /* Validate parameters before generating random. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) || (sig == NULL) ||
            (sigSz == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check sig buffer is large enough to hold generated signature. */
    else if (*sigSz < key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    /* Check we have a private key to sign with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        /* Generate n bytes of random. */
        ret = wc_RNG_GenerateBlock(rng, addRnd, key->params->n);
    }
    if (ret == 0) {
        /* Pure sign. */
        ret = wc_SlhDsaKey_SignWithRandom(key, ctx, ctxSz, msg, msgSz, sig,
            sigSz, addRnd);
    }

    return ret;
}

/* Sign using internal interface -- M' provided directly (deterministic).
 *
 * opt_rand = PK.seed for the deterministic variant.
 *
 * @param [in]      key       SLH-DSA key.
 * @param [in]      mprime    M' message (already in internal format).
 * @param [in]      mprimeSz  Length of M' in bytes.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, buffer length. On out, signature length.
 * @return  0 on success.
 */
int wc_SlhDsaKey_SignMsgDeterministic(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, byte* sig, word32* sigSz)
{
    int ret;

    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = slhdsakey_sign_internal_msg(key, mprime, mprimeSz, sig, sigSz,
            key->sk + 2 * key->params->n);
    }

    return ret;
}

/* Sign using internal interface -- M' provided directly (with explicit random).
 *
 * @param [in]      key       SLH-DSA key.
 * @param [in]      mprime    M' message (already in internal format).
 * @param [in]      mprimeSz  Length of M' in bytes.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, buffer length. On out, signature length.
 * @param [in]      addRnd    opt_rand value.
 * @return  0 on success.
 */
int wc_SlhDsaKey_SignMsgWithRandom(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, byte* sig, word32* sigSz, const byte* addRnd)
{
    return slhdsakey_sign_internal_msg(key, mprime, mprimeSz, sig, sigSz,
        addRnd);
}

#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Verify SLH-DSA signature.
 *
 * FIPS 205. Section 9.3. Algorithm 20.
 * slh_verify_internal(M, SIG, PK)
 *  ...
 *   6: SIGFORS <- SIG.getSIG_FORS()               > SIG[n : (1 + k(1 + a)) . n]
 *   7: SIGHT <- SIG.getSIG_HT()
 *                  > SIG[(1 + k(1 + a)) . n : (1 + k(1 + a) + h + d . len) . n]
 *  ...
 *  17: PKFORS <- fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
 *  18: return ht_verify(PKFORS, SIGHT, PK.seed, idxtree, idxleaf, PK.root)
 *
 * @param [in] key  SLH-DSA key.
 * @param [in] md   Message digest.
 * @param [in] sig  Signature data.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_verify(SlhDsaKey* key, byte* md, const byte* sig)
{
    int ret;
    HashAddress adrs;
    word32 t[3];
    word32 l;
    byte pk_fors[SLHDSA_MAX_N];
    byte n = key->params->n;

    /* Steps 4, 10-16: Set address based on message digest. */
    slhdsakey_set_ha_from_md(key, md, adrs, t, &l);

    /* Step 6: Move pointer to FORS signature. */
    sig += n;
    /* Step 17: Get FORS public key from FORS signature. */
    ret = slhdsakey_fors_pk_from_sig(key, sig, md, key->sk + 2 * n, adrs,
        pk_fors);
    /* Step 7: Move pointer to hypertree signature. */
    sig += key->params->k * (1 + key->params->a) * n;
    if (ret == 0) {
        /* Step 18: Verify hypertree signature. */
        ret = slhdsakey_ht_verify(key, pk_fors, sig, key->sk + 2 * n, t, l,
            key->sk + 3 * n);
    }

    return ret;
}

/* Verify SLH-DSA signature.
 *
 * FIPS 205. Section 9.3. Algorithm 20.
 * slh_verify_internal(M, SIG, PK)
 *   1: if |SIG| != (1 + k(1 + a) + h + d . len . n then
 *   2:     return false
 *   3: end if
 *  ...
 *   5: R <- SIG.getR()                                             > SIG[0 : n]
 *  ...
 *   8: digest <- Hmsg (R, PK.seed, PK.root, M)         > compute message digest
 *   9: md <- digest [0 : upper(k.a / 8)]           > first upper(k.a / 8) bytes
 *  ...
 *
 * FIPS 205. Section 10.3. Algorithm 23.
 * slh_verify(M, SIG, ctx, PK)
 *   1: if |ctx| > 255 then
 *   2:     return false
 *   3: end if
 *   4: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx
 *   5: return slh_verify_internal(M', SIG, PK)
 *
 * Note: ctx length is of type byte which means it can never be more than 255.
 *
 * @param [in] key    SLH-DSA key.
 * @param [in] ctx    Context of signing.
 * @param [in] ctxSz  Length of context in bytes.
 * @param [in] msg    Message to sign.
 * @param [in] msgSz  Length of message in bytes.
 * @param [in] sig    Signature data.
 * @param [in] sigSz  Length of signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg or sig is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctxSz is greater than 0.
 * @return  BAD_LENGTH_E when signature size does not match parameters.
 * @return  MISSING_KEY when public key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_Verify(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, const byte* sig, word32 sigSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) ||
            (sig == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Alg 20, Step 1: Check signature length is the expect length. */
    else if (sigSz != key->params->sigLen) {
        /* Alg 20, Step 2: Return error  */
        ret = BAD_LENGTH_E;
    }
    /* Check we have a public key to verify with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PUBLIC) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        byte md[SLHDSA_MAX_MD];
        byte n = key->params->n;
        byte hdr[2];

        /* Alg 23, Step 4: Make M' header. */
        hdr[0] = 0;
        hdr[1] = ctxSz;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: H_msg via MGF1 (no PRF_msg for verify). */
            ret = slhdsakey_h_msg_sha2(key, sig, hdr, ctx, ctxSz, msg, msgSz,
                md, key->params->dl1 + key->params->dl2 + key->params->dl3);
        }
        else
#endif
        {
            /* SHAKE: H_msg streaming. */
            ret = slhdsakey_hash_start(&key->hash.shk.shake, sig, n);
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, msg, msgSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            /* Alg 23, Step 5: Verify M'.
             * Alg 20, Steps 4,6-18: Verify digest. */
            ret = slhdsakey_verify(key, md, sig);
        }
    }

    return ret;
}

/* Verify SLH-DSA signature using internal interface -- M' provided directly.
 *
 * FIPS 205. Section 9.3. Algorithm 20.
 * slh_verify_internal(M', SIG, PK)
 *
 * @param [in] key       SLH-DSA key.
 * @param [in] mprime    M' message (already in internal format).
 * @param [in] mprimeSz  Length of M' in bytes.
 * @param [in] sig       Signature data.
 * @param [in] sigSz     Length of signature in bytes.
 * @return  0 on success.
 * @return  SIG_VERIFY_E on verification failure.
 */
int wc_SlhDsaKey_VerifyMsg(SlhDsaKey* key, const byte* mprime,
    word32 mprimeSz, const byte* sig, word32 sigSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (mprime == NULL) ||
            (sig == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (sigSz != key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    else if ((key->flags & WC_SLHDSA_FLAG_PUBLIC) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        byte md[SLHDSA_MAX_MD];
        byte n = key->params->n;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: H_msg. Internal interface: no M' header, pass whole
             * message directly. */
            ret = slhdsakey_h_msg_sha2(key, sig,
                NULL, NULL, 0, mprime, mprimeSz,
                md, key->params->dl1 + key->params->dl2 + key->params->dl3);
        }
        else
#endif
        {
            /* SHAKE: H_msg = SHAKE(R || PK.seed || PK.root || M). */
            ret = slhdsakey_hash_start(&key->hash.shk.shake, sig, n);
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    mprime, mprimeSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            ret = slhdsakey_verify(key, md, sig);
        }
    }

    return ret;
}

#ifdef WOLFSSL_SHA224
/* OID for SHA-224 for hash signing/verification. */
static const byte slhdsakey_oid_sha224[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};
#endif
#ifndef NO_SHA256
/* OID for SHA-256 for hash signing/verification. */
static const byte slhdsakey_oid_sha256[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
#endif
#ifdef WOLFSSL_SHA384
/* OID for SHA-384 for hash signing/verification. */
static const byte slhdsakey_oid_sha384[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
#endif
#ifdef WOLFSSL_SHA512
/* OID for SHA-512 for hash signing/verification. */
static const byte slhdsakey_oid_sha512[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
#ifndef WOLFSSL_NOSHA512_224
/* OID for SHA-512/224 for hash signing/verification. */
static const byte slhdsakey_oid_sha512_224[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05
};
#endif
#ifndef WOLFSSL_NOSHA512_256
/* OID for SHA-512/256 for hash signing/verification. */
static const byte slhdsakey_oid_sha512_256[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06
};
#endif
#endif
#ifdef WOLFSSL_SHAKE128
/* OID for SHAKE-128 for hash signing/verification. */
static const byte slhdsakey_oid_shake128[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b
};
#endif
#ifdef WOLFSSL_SHAKE256
/* OID for SHAKE-256 for hash signing/verification. */
static const byte slhdsakey_oid_shake256[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c
};
#endif
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_NOSHA3_224
/* OID for SHA3-224 for hash signing/verification. */
static const byte slhdsakey_oid_sha3_224[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07
};
#endif
#ifndef WOLFSSL_NOSHA3_256
/* OID for SHA3-256 for hash signing/verification. */
static const byte slhdsakey_oid_sha3_256[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
};
#endif
#ifndef WOLFSSL_NOSHA3_384
/* OID for SHA3-384 for hash signing/verification. */
static const byte slhdsakey_oid_sha3_384[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
};
#endif
#ifndef WOLFSSL_NOSHA3_512
/* OID for SHA3-512 for hash signing/verification. */
static const byte slhdsakey_oid_sha3_512[] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a
};
#endif
#endif

/* Pre-hash the message with the hash specified.
 *
 * @param [in]  msg       Message to hash.
 * @param [in]  msgSz     Length of message in bytes.
 * @param [in]  hashType  Hash algorithm.
 * @param [out] ph        Prehash buffer.
 * @param [out] phLen     Length of prehash data.
 * @param [out] oid       OID data for hash algorithm.
 * @param [out] oidLen    Length of OID data for hash algorithm.
 * @return  0 on success.
 * @return  NOT_COMPILED_IN when hash algorithm not supported.
 */
static int slhdsakey_prehash_msg(const byte* msg, word32 msgSz,
    enum wc_HashType hashType, byte* ph, byte* phLen, const byte** oid,
    byte* oidLen)
{
    int ret;

    switch ((int)hashType) {
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            *oid = slhdsakey_oid_sha224;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha224);
            *phLen = WC_SHA224_DIGEST_SIZE;
            ret = wc_Sha224Hash(msg, msgSz, ph);
            break;
    #endif
    #ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            *oid = slhdsakey_oid_sha256;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha256);
            *phLen = WC_SHA256_DIGEST_SIZE;
            ret = wc_Sha256Hash(msg, msgSz, ph);
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            *oid = slhdsakey_oid_sha384;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha384);
            *phLen = WC_SHA384_DIGEST_SIZE;
            ret = wc_Sha384Hash(msg, msgSz, ph);
            break;
    #endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            *oid = slhdsakey_oid_sha512;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha512);
            *phLen = WC_SHA512_DIGEST_SIZE;
            ret = wc_Sha512Hash(msg, msgSz, ph);
            break;
    #ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
            *oid = slhdsakey_oid_sha512_224;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha512_224);
            *phLen = WC_SHA512_224_DIGEST_SIZE;
            ret = wc_Sha512_224Hash(msg, msgSz, ph);
            break;
    #endif
    #ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
            *oid = slhdsakey_oid_sha512_256;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha512_256);
            *phLen = WC_SHA512_256_DIGEST_SIZE;
            ret = wc_Sha512_256Hash(msg, msgSz, ph);
            break;
    #endif
#endif
    #ifdef WOLFSSL_SHAKE128
        case WC_HASH_TYPE_SHAKE128:
            *oid = slhdsakey_oid_shake128;
            *oidLen = (byte)sizeof(slhdsakey_oid_shake128);
            *phLen = WC_SHA3_256_DIGEST_SIZE;
            ret = wc_Shake128Hash(msg, msgSz, ph, WC_SHA3_256_DIGEST_SIZE);
            break;
    #endif
    #ifdef WOLFSSL_SHAKE256
        case WC_HASH_TYPE_SHAKE256:
            *oid = slhdsakey_oid_shake256;
            *oidLen = (byte)sizeof(slhdsakey_oid_shake256);
            *phLen = WC_SHA3_512_DIGEST_SIZE;
            ret = wc_Shake256Hash(msg, msgSz, ph, WC_SHA3_512_DIGEST_SIZE);
            break;
    #endif
    #ifdef WOLFSSL_SHA3
    #ifndef WOLFSSL_NOSHA3_224
        case WC_HASH_TYPE_SHA3_224:
            *oid = slhdsakey_oid_sha3_224;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha3_224);
            *phLen = WC_SHA3_224_DIGEST_SIZE;
            ret = wc_Sha3_224Hash(msg, msgSz, ph);
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case WC_HASH_TYPE_SHA3_256:
            *oid = slhdsakey_oid_sha3_256;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha3_256);
            *phLen = WC_SHA3_256_DIGEST_SIZE;
            ret = wc_Sha3_256Hash(msg, msgSz, ph);
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case WC_HASH_TYPE_SHA3_384:
            *oid = slhdsakey_oid_sha3_384;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha3_384);
            *phLen = WC_SHA3_384_DIGEST_SIZE;
            ret = wc_Sha3_384Hash(msg, msgSz, ph);
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case WC_HASH_TYPE_SHA3_512:
            *oid = slhdsakey_oid_sha3_512;
            *oidLen = (byte)sizeof(slhdsakey_oid_sha3_512);
            *phLen = WC_SHA3_512_DIGEST_SIZE;
            ret = wc_Sha3_512Hash(msg, msgSz, ph);
            break;
    #endif
    #endif
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Generate pre-hash SLH-DSA signature.
 *
 * FIPS 205. Section 10.2.2. Algorithm 23.
 * hash_slh_sign(M, ctx, PH, SK)
 *   1: if |ctx| > 255 then
 *   2:  return falsity
 *                > return an error indication if the context string is too long
 *   3: end if
 *   4: addrnd <-$- Bn    > skip lines 4 through 7 for the deterministic variant
 *   5: if addrnd = NULL then
 *   6:     return falsity
 *                  > return an error indication if random bit generation failed
 *   7: end if
 *   8: switch PH do
 *   9:     case SHA-256:
 *  10:         OID <- toByte(0x0609608648016503040201, 11)
 *                                                      > 2.16.840.1.101.3.4.2.1
 *  11:         PHM <- SHA-256(M)
 *  12:     case SHA-512:
 *  13:         OID <- toByte(0x0609608648016503040203, 11)
 *                                                      > 2.16.840.1.101.3.4.2.3
 *  14:         PHM <- SHA-512(M)
 *  15:     case SHAKE128:
 *  16:         OID <- toByte(0x060960864801650304020B, 11)
 *                                                     > 2.16.840.1.101.3.4.2.11
 *  17:         PHM <- SHAKE128(M, 256)
 *  18:     case SHAKE256:
 *  19:         OID <- toByte(0x060960864801650304020C, 11)
 *                                                     > 2.16.840.1.101.3.4.2.12
 *  20:         PHM <- SHAKE256(M , 512)
 *  21:     case ...                     > other approved hash functions or XOFs
 *  22:         ...
 *  23: end switch
 *  24: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PHM
 *                                   > omit addrnd for the deterministic variant
 *  25: SIG <- slh_sign_internal(M', SK, addrnd)
 *  26: return SIG
 *
 * FIPS 205. Section 9.2. Algorithm 19.
 * slh_sign_internal(M, SK, addrnd)
 *  ...
 *   2: opt_rand <- addrnd
 *                > substitute opt_rand <- PK.seed for the deterministic variant
 *   3: R <- PRFmsg (SK.prf, opt_rand, M)                  > generate randomizer
 *   4: SIG <- R
 *   5: digest <- Hmsg(R, PK.seed, PK.root, M)          > compute message digest
 *   6: md <- digest [0 : upper(k.a / 8)]          > first upper(k.a / 8)] bytes
 *  ...
 *
 * Note: ctx length is of type byte which means it can never be more than 255.
 *
 * @param [in]      key       SLH-DSA key.
 * @param [in]      ctx       Context of signing.
 * @param [in]      ctxSz     Length of context in bytes.
 * @param [in]      msg       Message to sign.
 * @param [in]      msgSz     Length of message in bytes.
 * @param [in]      hashType  Hash algorithm to use in pre-hash.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, length of signature buffer.
 *                            On out, length of signature data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig, sigSz or addRnd
 *          is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  NOT_COMPILED in when hash algorithm is not supported.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
static int slhdsakey_signhash_external(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz, byte* addRnd)
{
    int ret = 0;
    byte ph[WC_MAX_DIGEST_SIZE];
    byte phLen = 0;
    const byte* oid = NULL;
    byte oidLen = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) || (sig == NULL) ||
            (sigSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check sig buffer is large enough to hold generated signature. */
    else if (*sigSz < key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    /* Alg 23, Step 5: Check addrnd is not NULL. */
    else if (addRnd == NULL) {
        /* Alg 23, Step 6: Return error. */
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Alg 23, Steps 8-23: Pre-hash message with hash algorithm specified.
         */
        ret = slhdsakey_prehash_msg(msg, msgSz, hashType, ph, &phLen, &oid,
            &oidLen);
    }
    if (ret == 0) {
        byte n = key->params->n;
        byte md[SLHDSA_MAX_MD];
        byte hdr[2];

        /* Alg 23, Step 24: Set first two bytes to pass to hash ... */
        hdr[0] = 1;
        hdr[1] = ctxSz;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: Build oid||ph as message for PRF_msg/H_msg. */
            byte phMsg[80]; /* Max: 11 byte OID + 64 byte hash */
            word32 phMsgLen = oidLen + phLen;

            XMEMCPY(phMsg, oid, oidLen);
            XMEMCPY(phMsg + oidLen, ph, phLen);

            ret = slhdsakey_prf_msg_sha2(key, key->sk + n, addRnd, hdr, ctx,
                ctxSz, phMsg, phMsgLen, n, sig);
            if (ret == 0) {
                ret = slhdsakey_h_msg_sha2(key, sig, hdr, ctx, ctxSz, phMsg,
                    phMsgLen, md, key->params->dl1 + key->params->dl2 +
                    key->params->dl3);
                sig += n;
            }
        }
        else
#endif
        {
            /* SHAKE: PRF_msg streaming. */
            ret = slhdsakey_hash_start(&key->hash.shk.shake, key->sk + n, n);
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, addRnd, n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, oid, oidLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ph, phLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, sig, n);
            }
            /* SHAKE: H_msg streaming. */
            if (ret == 0) {
                ret = slhdsakey_hash_start(&key->hash.shk.shake, sig, n);
                sig += n;
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, oid, oidLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ph, phLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            /* Alg 19. Steps 7-19 */
            ret = slhdsakey_sign(key, md, sig);
        }
        if (ret == 0) {
            /* Return the signature size generated. */
            *sigSz = key->params->sigLen;
        }
    }

    return ret;
}

/* Generate a deterministic pre-hash SLH-DSA signature.
 *
 * addrnd is the public key seed.
 *
 * @param [in]      key       SLH-DSA key.
 * @param [in]      ctx       Context of signing.
 * @param [in]      ctxSz     Length of context in bytes.
 * @param [in]      msg       Message to sign.
 * @param [in]      msgSz     Length of message in bytes.
 * @param [in]      hashType  Hash algorithm to use in pre-hash.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, length of signature buffer.
 *                            On out, length of signature data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig or sigSz is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_SignHashDeterministic(SlhDsaKey* key, const byte* ctx,
    byte ctxSz, const byte* msg, word32 msgSz, enum wc_HashType hashType,
    byte* sig, word32* sigSz)
{
    int ret;

    /* Validate parameters that will be used in this function. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a private key to sign with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    else {
        /* Pre-hash sign. */
        ret = slhdsakey_signhash_external(key, ctx, ctxSz, msg, msgSz, hashType,
            sig, sigSz, key->sk + 2 * key->params->n);
    }

    return ret;
}

/* Generate a pre-hash SLH-DSA signature.
 *
 * @param [in]      key       SLH-DSA key.
 * @param [in]      ctx       Context of signing.
 * @param [in]      ctxSz     Length of context in bytes.
 * @param [in]      msg       Message to sign.
 * @param [in]      msgSz     Length of message in bytes.
 * @param [in]      hashType  Hash algorithm to use in pre-hash.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, length of signature buffer.
 *                            On out, length of signature data.
 * @param [in]      addRnd    Additional random for signature.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig, sigSz or addrnd
 *          is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when sigSz is less than required signature length.
 * @return  MISSING_KEY when private key not set.
 * @return  NOT_COMPILED in when hash algorithm is not supported.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_SignHashWithRandom(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, enum wc_HashType hashType, byte* sig,
    word32* sigSz, byte* addRnd)
{
    /* Pre-hash sign */
    return slhdsakey_signhash_external(key, ctx, ctxSz, msg, msgSz, hashType,
        sig, sigSz, addRnd);
}

/* Generate a pre-hash SLH-DSA signature with a random number generator.
 *
 * @param [in]      key     SLH-DSA key.
 * @param [in]      ctx     Context of signing.
 * @param [in]      ctxSz   Length of context in bytes.
 * @param [in]      msg     Message to sign.
 * @param [in]      msgSz   Length of message in bytes.
 * @param [in]      hashType  Hash algorithm to use in pre-hash.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigSz   On in, length of signature buffer.
 *                          On out, length of signature data.
 * @param [in]      rng     Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg, sig, sigSz or rng is
 *          NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  MISSING_KEY when private key not set.
 * @return  NOT_COMPILED in when hash algorithm is not supported.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_SignHash(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, enum wc_HashType hashType, byte* sig,
    word32* sigSz, WC_RNG* rng)
{
    int ret = 0;
    byte addRnd[SLHDSA_MAX_N];

    /* Validate parameters before generating random. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) || (sig == NULL) ||
            (sigSz == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check sig buffer is large enough to hold generated signature. */
    else if (*sigSz < key->params->sigLen) {
        ret = BAD_LENGTH_E;
    }
    /* Check we have a private key to sign with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        /* Generate n bytes of random. */
        ret = wc_RNG_GenerateBlock(rng, addRnd, key->params->n);
    }
    if (ret == 0) {
        /* Pre-hash sign. */
        ret = wc_SlhDsaKey_SignHashWithRandom(key, ctx, ctxSz, msg, msgSz,
            hashType, sig, sigSz, addRnd);
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Verify SLH-DSA signature.
 *
 * FIPS 205. Section 9.3. Algorithm 20.
 * slh_verify_internal(M, SIG, PK)
 *   1: if |SIG| != (1 + k(1 + a) + h + d . len . n then
 *   2:     return false
 *   3: end if
 *  ...
 *   5: R <- SIG.getR()                                             > SIG[0 : n]
 *  ...
 *   8: digest <- Hmsg (R, PK.seed, PK.root, M)         > compute message digest
 *   9: md <- digest [0 : upper(k.a / 8)]           > first upper(k.a / 8) bytes
 * ...
 *
 * FIPS 205. Section 10.3. Algorithm 24.
 * hash_slh_verify(M, SIG, ctx, PH, PK)
 *   1: if |ctx| > 255 then
 *   2:     return false
 *   3: end if
 *   4: switch PH do
 *   5:     case SHA-256:
 *   6:         OID <- toByte(0x0609608648016503040201, 11)
 *                                                      > 2.16.840.1.101.3.4.2.1
 *   7:         PHM <- SHA-256(M)
 *   8:     case SHA-512:
 *   9:         OID <- toByte(0x0609608648016503040203, 11)
 *                                                      > 2.16.840.1.101.3.4.2.3
 *  10:         PHM <- SHA-512(M)
 *  11:     case SHAKE128:
 *  12:         OID <- toByte(0x060960864801650304020B, 11)
 *                                                     > 2.16.840.1.101.3.4.2.11
 *  13:         PHM <- SHAKE128(M, 256)
 *  14:     case SHAKE256:
 *  15:         OID <- toByte(0x060960864801650304020C, 11)
 *                                                     > 2.16.840.1.101.3.4.2.12
 *  16:         PHM <- SHAKE256(M , 512)
 *  17:     case ...                     > other approved hash functions or XOFs
 *  18:         ...
 *  19: end switch
 *  20: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PHM
 *  21: return slh_verify_internal(M', SIG, PK)
 *
 * @param [in] key       SLH-DSA key.
 * @param [in] ctx       Context of signing.
 * @param [in] ctxSz     Length of context in bytes.
 * @param [in] msg       Message to sign.
 * @param [in] msgSz     Length of message in bytes.
 * @param [in] hashType  Hash algorithm to use in pre-hash.
 * @param [in] sig       Signature data.
 * @param [in] sigSz     Length of signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, msg or sig is NULL.
 * @return  BAD_FUNC_ARG when ctx is NULL but ctx length is greater than 0.
 * @return  BAD_LENGTH_E when signature size does not match parameters.
 * @return  MISSING_KEY when public key not set.
 * @return  NOT_COMPILED in when hash algorithm is not supported.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_VerifyHash(SlhDsaKey* key, const byte* ctx, byte ctxSz,
    const byte* msg, word32 msgSz, enum wc_HashType hashType, const byte* sig,
    word32 sigSz)
{
    int ret = 0;
    byte ph[WC_MAX_DIGEST_SIZE];
    byte phLen = 0;
    const byte* oid = NULL;
    byte oidLen = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) ||
            ((ctx == NULL) && (ctxSz > 0)) || (msg == NULL) || (sig == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Alg 20, Step 1: Check signature length is the expect length. */
    else if (sigSz != key->params->sigLen) {
        /* Alg 20, Step 2: Return error  */
        ret = BAD_LENGTH_E;
    }
    /* Check we have a public key to verify with. */
    else if ((key->flags & WC_SLHDSA_FLAG_PUBLIC) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        /* Alg 24, Steps 4-19: Pre-hash message with hash algorithm specified.
         */
        ret = slhdsakey_prehash_msg(msg, msgSz, hashType, ph, &phLen, &oid,
            &oidLen);
    }
    if (ret == 0) {
        byte n = key->params->n;
        byte md[SLHDSA_MAX_MD];
        byte hdr[2];

        /* Alg 24, Step 20: Make M' header. */
        hdr[0] = 1;
        hdr[1] = ctxSz;

#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            /* SHA2: Build oid||ph as message for H_msg. */
            byte phMsg[80]; /* Max: 11 byte OID + 64 byte hash */
            word32 phMsgLen = oidLen + phLen;

            XMEMCPY(phMsg, oid, oidLen);
            XMEMCPY(phMsg + oidLen, ph, phLen);

            ret = slhdsakey_h_msg_sha2(key, sig, hdr, ctx, ctxSz, phMsg,
                phMsgLen, md, key->params->dl1 + key->params->dl2 +
                key->params->dl3);
        }
        else
#endif
        {
            /* SHAKE: H_msg streaming. */
            ret = slhdsakey_hash_start(&key->hash.shk.shake, sig, n);
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake,
                    key->sk + 2 * n, 2 * n);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, hdr,
                    sizeof(hdr));
            }
            if ((ret == 0) && (ctxSz > 0)) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ctx, ctxSz);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, oid, oidLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_update(&key->hash.shk.shake, ph, phLen);
            }
            if (ret == 0) {
                ret = slhdsakey_hash_final(&key->hash.shk.shake, md,
                    key->params->dl1 + key->params->dl2 + key->params->dl3);
            }
        }
        if (ret == 0) {
            /* Alg 24, Step 21: Verify M'.
             * Alg 20, Steps 4,6-18: Verify digest. */
            ret = slhdsakey_verify(key, md, sig);
        }
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Import private key from data.
 *
 * Includes the public key.
 *
 * @param [in] key      SLH-DSA key.
 * @param [in] priv     Private key data.
 * @param [in] privLen  Length of private key data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters or priv is NULL.
 * @return  BAD_LENGTH_E when inLen does not match parameters.
 */
int wc_SlhDsaKey_ImportPrivate(SlhDsaKey* key, const byte* priv, word32 privLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (priv == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check private key data length matches parameters. */
    else if ((privLen != 4 * key->params->n)) {
        ret = BAD_LENGTH_E;
    }
    else {
        /* Copy private and public key data into SLH-DSA key object. */
        XMEMCPY(key->sk, priv, 4 * key->params->n);
        key->flags = WC_SLHDSA_FLAG_BOTH_KEYS;
#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            ret = slhdsakey_precompute_sha2_midstates(key);
        }
#endif
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Import public key from data.
 *
 * @param [in] key     SLH-DSA key.
 * @param [in] pub     Public key data.
 * @param [in] pubLen  Length of public key data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters or in is NULL.
 * @return  BAD_LENGTH_E when inLen does not match parameters.
 */
int wc_SlhDsaKey_ImportPublic(SlhDsaKey* key, const byte* pub, word32 pubLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (pub == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check public key data length matches parameters. */
    else if ((pubLen != 2 * key->params->n)) {
        ret = BAD_LENGTH_E;
    }
    else {
        /* Copy public key data into SLH-DSA key object. */
        XMEMCPY(key->sk + 2 * key->params->n, pub, 2 * key->params->n);
        key->flags |= WC_SLHDSA_FLAG_PUBLIC;
#ifdef WOLFSSL_SLHDSA_SHA2
        if (SLHDSA_IS_SHA2(key->params->param)) {
            ret = slhdsakey_precompute_sha2_midstates(key);
        }
#endif
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Check that the private key is valid.
 *
 * @param [in] key  SLH-DSA key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 * @return  MISSING_KEY when private key not set.
 * @return  WC_KEY_MISMATCH_E when private key and public seed don't compute
 *          public key root.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  SHAKE-256 error return code on digest failure.
 */
int wc_SlhDsaKey_CheckKey(SlhDsaKey* key)
{
    int ret = 0;

    /* Validate parameter. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a private key to validate. */
    else if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        ret = MISSING_KEY;
    }
    if (ret == 0) {
        byte root[SLHDSA_MAX_N];
        byte n = key->params->n;

        /* Cache the public key root as making the key overwrites. */
        XMEMCPY(root, key->sk + 3 * n, n);
        ret = wc_SlhDsaKey_MakeKeyWithRandom(key, key->sk, n, key->sk + n, n,
                key->sk + 2 * n, n);
        /* Compare computed root with what was cached. */
        if ((ret == 0) && (XMEMCMP(root, key->sk + 3 * n, n) != 0)) {
            ret = WC_KEY_MISMATCH_E;
        }
    }

    return ret;
}

/* Export the private key.
 *
 * Includes the public key.
 *
 * @param [in]       key      SLH-DSA key.
 * @param [out]      priv     Buffer for private key data.
 * @param [in, out]  privLen  On in, length of buffer.
 *                            On out, length of private key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, priv or privLen is NULL.
 * @return  BAD_LENGTH_E when privLen is too small for private key.
 */
int wc_SlhDsaKey_ExportPrivate(SlhDsaKey* key, byte* priv, word32* privLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (priv == NULL) ||
            (privLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check private key buffer length. */
    else if (*privLen < key->params->n * 4) {
        ret = BAD_LENGTH_E;
    }
    else {
        int n = key->params->n;

        /* Copy data out and return length. */
        XMEMCPY(priv, key->sk, n * 4);
        *privLen = n * 4;
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Export the public key.
 *
 * @param [in]       key     SLH-DSA key.
 * @param [out]      pub     Buffer for public key data.
 * @param [in, out]  pubLen  On in, length of buffer.
 *                           On out, length of public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, key's parameters, pub or pubLen is NULL.
 * @return  BAD_LENGTH_E when pubLen is too small for public key.
 */
int wc_SlhDsaKey_ExportPublic(SlhDsaKey* key, byte* pub, word32* pubLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL) || (pub == NULL) ||
            (pubLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check public key buffer length. */
    else if (*pubLen < key->params->n * 2) {
        ret = BAD_LENGTH_E;
    }
    else {
        int n = key->params->n;

        /* Copy data out and return length. */
        XMEMCPY(pub, key->sk + n * 2, n * 2);
        *pubLen = n * 2;
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Return the size of the private key for the parameters.
 *
 * @param [in] key  SLH-DSA key.
 * @return  Private key data length in bytes on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 */
int wc_SlhDsaKey_PrivateSize(SlhDsaKey* key)
{
    int ret;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Length is of 3 seeds and a hash, all n bytes long.  */
        ret = key->params->n * 4;
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Return the size of the public key for the parameters.
 *
 * @param [in] key  SLH-DSA key.
 * @return  Public key data length in bytes on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 */
int wc_SlhDsaKey_PublicSize(SlhDsaKey* key)
{
    int ret;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Length is of a seed and a hash, both n bytes long.  */
        ret = key->params->n * 2;
    }

    return ret;
}

/* Return the size of a signature for the parameters.
 *
 * @param [in] key  SLH-DSA key.
 * @return  Signature length in bytes on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 */
int wc_SlhDsaKey_SigSize(SlhDsaKey* key)
{
    int ret;

    /* Validate parameters. */
    if ((key == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Length from the parameters. */
        ret = key->params->sigLen;
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Return the size of the private key for the parameters.
 *
 * @param [in] param  SLH-DSA parameters.
 * @return  Private key data length in bytes on success.
 * @return  NOT_COMPILED_IN when parameters not supported.
 */
int wc_SlhDsaKey_PrivateSizeFromParam(enum SlhDsaParam param)
{
    int ret;

    switch (param) {
        case SLHDSA_SHAKE128S:
            ret = WC_SLHDSA_SHAKE128S_PRIV_LEN;
            break;
        case SLHDSA_SHAKE128F:
            ret = WC_SLHDSA_SHAKE128F_PRIV_LEN;
            break;
        case SLHDSA_SHAKE192S:
            ret = WC_SLHDSA_SHAKE192S_PRIV_LEN;
            break;
        case SLHDSA_SHAKE192F:
            ret = WC_SLHDSA_SHAKE192F_PRIV_LEN;
            break;
        case SLHDSA_SHAKE256S:
            ret = WC_SLHDSA_SHAKE256S_PRIV_LEN;
            break;
        case SLHDSA_SHAKE256F:
            ret = WC_SLHDSA_SHAKE256F_PRIV_LEN;
            break;
#ifdef WOLFSSL_SLHDSA_SHA2
        case SLHDSA_SHA2_128S:
            ret = WC_SLHDSA_SHA2_128S_PRIV_LEN;
            break;
        case SLHDSA_SHA2_128F:
            ret = WC_SLHDSA_SHA2_128F_PRIV_LEN;
            break;
        case SLHDSA_SHA2_192S:
            ret = WC_SLHDSA_SHA2_192S_PRIV_LEN;
            break;
        case SLHDSA_SHA2_192F:
            ret = WC_SLHDSA_SHA2_192F_PRIV_LEN;
            break;
        case SLHDSA_SHA2_256S:
            ret = WC_SLHDSA_SHA2_256S_PRIV_LEN;
            break;
        case SLHDSA_SHA2_256F:
            ret = WC_SLHDSA_SHA2_256F_PRIV_LEN;
            break;
#endif
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Return the size of the public key for the parameters.
 *
 * @param [in] param  SLH-DSA parameters.
 * @return  Public key data length in bytes on success.
 * @return  NOT_COMPILED_IN when parameters not supported.
 */
int wc_SlhDsaKey_PublicSizeFromParam(enum SlhDsaParam param)
{
    int ret;

    switch (param) {
        case SLHDSA_SHAKE128S:
            ret = WC_SLHDSA_SHAKE128S_PUB_LEN;
            break;
        case SLHDSA_SHAKE128F:
            ret = WC_SLHDSA_SHAKE128F_PUB_LEN;
            break;
        case SLHDSA_SHAKE192S:
            ret = WC_SLHDSA_SHAKE192S_PUB_LEN;
            break;
        case SLHDSA_SHAKE192F:
            ret = WC_SLHDSA_SHAKE192F_PUB_LEN;
            break;
        case SLHDSA_SHAKE256S:
            ret = WC_SLHDSA_SHAKE256S_PUB_LEN;
            break;
        case SLHDSA_SHAKE256F:
            ret = WC_SLHDSA_SHAKE256F_PUB_LEN;
            break;
#ifdef WOLFSSL_SLHDSA_SHA2
        case SLHDSA_SHA2_128S:
            ret = WC_SLHDSA_SHA2_128S_PUB_LEN;
            break;
        case SLHDSA_SHA2_128F:
            ret = WC_SLHDSA_SHA2_128F_PUB_LEN;
            break;
        case SLHDSA_SHA2_192S:
            ret = WC_SLHDSA_SHA2_192S_PUB_LEN;
            break;
        case SLHDSA_SHA2_192F:
            ret = WC_SLHDSA_SHA2_192F_PUB_LEN;
            break;
        case SLHDSA_SHA2_256S:
            ret = WC_SLHDSA_SHA2_256S_PUB_LEN;
            break;
        case SLHDSA_SHA2_256F:
            ret = WC_SLHDSA_SHA2_256F_PUB_LEN;
            break;
#endif
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    return ret;
}

/* Return the size of a signature for the parameters.
 *
 * @param [in] param  SLH-DSA parameters.
 * @return  Signature length in bytes on success.
 * @return  NOT_COMPILED_IN when parameters not supported.
 */
int wc_SlhDsaKey_SigSizeFromParam(enum SlhDsaParam param)
{
    int ret;

    switch (param) {
        case SLHDSA_SHAKE128S:
            ret = WC_SLHDSA_SHAKE128S_SIG_LEN;
            break;
        case SLHDSA_SHAKE128F:
            ret = WC_SLHDSA_SHAKE128F_SIG_LEN;
            break;
        case SLHDSA_SHAKE192S:
            ret = WC_SLHDSA_SHAKE192S_SIG_LEN;
            break;
        case SLHDSA_SHAKE192F:
            ret = WC_SLHDSA_SHAKE192F_SIG_LEN;
            break;
        case SLHDSA_SHAKE256S:
            ret = WC_SLHDSA_SHAKE256S_SIG_LEN;
            break;
        case SLHDSA_SHAKE256F:
            ret = WC_SLHDSA_SHAKE256F_SIG_LEN;
            break;
#ifdef WOLFSSL_SLHDSA_SHA2
        case SLHDSA_SHA2_128S:
            ret = WC_SLHDSA_SHA2_128S_SIG_LEN;
            break;
        case SLHDSA_SHA2_128F:
            ret = WC_SLHDSA_SHA2_128F_SIG_LEN;
            break;
        case SLHDSA_SHA2_192S:
            ret = WC_SLHDSA_SHA2_192S_SIG_LEN;
            break;
        case SLHDSA_SHA2_192F:
            ret = WC_SLHDSA_SHA2_192F_SIG_LEN;
            break;
        case SLHDSA_SHA2_256S:
            ret = WC_SLHDSA_SHA2_256S_SIG_LEN;
            break;
        case SLHDSA_SHA2_256F:
            ret = WC_SLHDSA_SHA2_256F_SIG_LEN;
            break;
#endif
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    return ret;
}

/* Find SlhDsaParameters entry for a given param enum. */
static const SlhDsaParameters* slhdsa_find_params(enum SlhDsaParam param)
{
    int i;
    for (i = 0; i < SLHDSA_PARAM_LEN; i++) {
        if (SlhDsaParams[i].param == param) {
            return &SlhDsaParams[i];
        }
    }
    return NULL;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Decode a DER-encoded SLH-DSA private key (PKCS#8 / OneAsymmetricKey).
 *
 * RFC 9909 Section 6: The privateKey OCTET STRING contains the raw
 * concatenation SK.seed || SK.prf || PK.seed || PK.root (4*n bytes)
 * directly, without a nested OCTET STRING wrapper. This differs from
 * Ed25519/Ed448 which wrap the key in an additional OCTET STRING.
 *
 * The parameter set is detected from the AlgorithmIdentifier OID.
 * On success, key->params is updated to match the detected parameter set.
 *
 * @param [in]      input     DER-encoded key data.
 * @param [in, out] inOutIdx  Index into input, updated on return.
 * @param [in, out] key       SLH-DSA key. Parameter set is auto-detected.
 * @param [in]      inSz      Size of input in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx, or key is NULL.
 * @return  ASN_PARSE_E when the DER cannot be parsed as an SLH-DSA key.
 */
int wc_SlhDsaKey_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz)
{
    int ret = 0;
    int length;
    int version;
    word32 oid = 0;
    word32 seqEnd;
    word32 savedIdx;
    int privSz;
    int paramId;
    const SlhDsaParameters* params;

    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        return BAD_FUNC_ARG;
    }

    /* Snapshot the caller's index so failures restore it -- mirrors
     * wc_SlhDsaKey_PublicKeyDecode and lets callers chain parsers or
     * retry on the same buffer without recomputing the offset. */
    savedIdx = *inOutIdx;

    /* Parse PKCS#8 OneAsymmetricKey wrapper:
     * SEQUENCE { version, AlgorithmIdentifier { OID }, OCTET STRING { key },
     *            [0] attributes OPTIONAL, [1] publicKey OPTIONAL }
     */
    if (GetSequence(input, inOutIdx, &length, inSz) < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }
    seqEnd = *inOutIdx + (word32)length;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }
    if (version != 0 && version != 1) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    if (GetAlgoId(input, inOutIdx, &oid, oidKeyType, inSz) < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    /* Map the OID to an SLH-DSA parameter set.  Pass through NOT_COMPILED_IN
     * so callers can distinguish "variant present but not built in" from
     * "malformed DER". */
    paramId = wc_SlhDsaOidToParam((int)oid);
    if (paramId == WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
        *inOutIdx = savedIdx;
        return NOT_COMPILED_IN;
    }
    if (paramId < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }
    params = slhdsa_find_params((enum SlhDsaParam)paramId);
    if (params == NULL) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    /* RFC 9909: privateKey is a single OCTET STRING containing the raw key
     * (4*n bytes). Unlike Ed25519/Ed448, there is no nested inner OCTET
     * STRING wrapping. */
    if (GetOctetString(input, inOutIdx, &privSz, inSz) < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    if (privSz != params->n * 4) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    {
        const SlhDsaParameters* oldParams = key->params;
        byte oldFlags = key->flags;

        /* Update the key's parameter set to the detected one. */
        key->params = params;

        /* Import the raw private key: SK.seed || SK.prf || PK.seed || PK.root */
        ret = wc_SlhDsaKey_ImportPrivate(key, input + *inOutIdx,
                                         (word32)privSz);
        if (ret == 0) {
            /* Validate trailing fields per RFC 5958 OneAsymmetricKey:
             *   [0] IMPLICIT Attributes  OPTIONAL  -- at most once
             *   [1] IMPLICIT PublicKey   OPTIONAL  -- at most once,
             *                                        must follow [0]
             * Reject duplicates, out-of-order tags, and any other tag.
             * The previous code accepted any number of either tag in any
             * order. */
            const byte tagAttrs = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0;
            const byte tagPub   = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1;
            int seenAttrs = 0;
            int seenPub   = 0;
            *inOutIdx += (word32)privSz;
            while (ret == 0 && *inOutIdx < seqEnd) {
                byte tlvTag;
                int tlvLen;
                if (GetASNTag(input, inOutIdx, &tlvTag, inSz) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }
                if (tlvTag == tagAttrs) {
                    /* attributes must precede publicKey and appear once */
                    if (seenAttrs || seenPub) {
                        ret = ASN_PARSE_E;
                        break;
                    }
                    seenAttrs = 1;
                }
                else if (tlvTag == tagPub) {
                    /* publicKey may appear at most once */
                    if (seenPub) {
                        ret = ASN_PARSE_E;
                        break;
                    }
                    seenPub = 1;
                }
                else {
                    ret = ASN_PARSE_E;
                    break;
                }
                if (GetLength(input, inOutIdx, &tlvLen, inSz) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }
                /* Length must stay within the outer SEQUENCE. */
                if (*inOutIdx + (word32)tlvLen > seqEnd) {
                    ret = ASN_PARSE_E;
                    break;
                }
                *inOutIdx += (word32)tlvLen;
            }
            if (ret == 0 && *inOutIdx != seqEnd) {
                ret = ASN_PARSE_E;
            }
            if (ret != 0) {
                /* Trailing-field validation failed after ImportPrivate
                 * already populated key->sk. Scrub the imported material
                 * and roll back state so the caller sees the failure as
                 * if the import never happened. */
                ForceZero(key->sk, (word32)(4 * params->n));
                key->params = oldParams;
                key->flags = oldFlags;
                *inOutIdx = savedIdx;
            }
        }
        else {
            /* On failure, restore params/flags. ImportPrivate writes the
             * full sk[0..4*n] (private + public material) before any
             * SHA-2 precompute step, so a precompute failure can leave
             * the entire sk dirty -- clear it. BAD_LENGTH_E is detected
             * before any write, so no zeroing is needed in that case. */
            if (ret != WC_NO_ERR_TRACE(BAD_LENGTH_E)) {
                ForceZero(key->sk, (word32)(4 * params->n));
            }
            key->params = oldParams;
            key->flags = oldFlags;
            *inOutIdx = savedIdx;
        }
    }

    return ret;
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

/* Decode a DER-encoded SLH-DSA public key (SubjectPublicKeyInfo).
 *
 * The parameter set is detected from the AlgorithmIdentifier OID.
 * On success, key->params is updated to match the detected parameter set.
 *
 * @param [in]      input     DER-encoded key data.
 * @param [in, out] inOutIdx  Index into input, updated on return.
 * @param [in, out] key       SLH-DSA key. Parameter set is auto-detected.
 * @param [in]      inSz      Size of input in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx, or key is NULL.
 * @return  ASN_PARSE_E when the DER cannot be parsed as an SLH-DSA key.
 */
int wc_SlhDsaKey_PublicKeyDecode(const byte* input, word32* inOutIdx,
    SlhDsaKey* key, word32 inSz)
{
    int ret;
    int keytype = ANONk;
    int paramId;
    const SlhDsaParameters* params;
    const SlhDsaParameters* oldParams;
    const byte* pubKeyPtr = NULL;
    word32 pubKeyLen = 0;
    word32 savedIdx;
    byte oldFlags;

    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        return BAD_FUNC_ARG;
    }

    savedIdx = *inOutIdx;

    /* Fast path: if the caller initialised the key with a parameter set,
     * treat the entire window from *inOutIdx to inSz as a candidate raw
     * public key and let wc_SlhDsaKey_ImportPublic decide via its length
     * check. The window must contain exactly 2*n bytes for the configured
     * parameter set -- callers chaining decoders must pass inSz scoped to
     * just the public-key buffer or the import will reject the length and
     * fall through to SPKI parsing. Mirrors the raw-first fallback in
     * wc_Dilithium_PublicKeyDecode and wc_Falcon_PublicKeyDecode so all PQ
     * public-key decoders accept either raw bytes or SPKI.
     *
     * The length check in ImportPublic is the disambiguator: a real SPKI
     * for any SLH-DSA variant carries ~19 bytes of AlgorithmIdentifier and
     * BIT STRING overhead on top of the 2*n public bytes, so SPKI input
     * never collides with the 2*n raw length and falls through cleanly. */
    if (key->params != NULL && savedIdx < inSz) {
        word32 windowSz = inSz - savedIdx;
        int n = key->params->n;
        oldFlags = key->flags;
        ret = wc_SlhDsaKey_ImportPublic(key, input + savedIdx, windowSz);
        if (ret == 0) {
            *inOutIdx += windowSz;
            return 0;
        }
        /* Fall through to SPKI parsing. BAD_LENGTH_E is detected before
         * any write (typical SPKI input), so there is nothing to scrub.
         * On SHA-2 precompute failure ImportPublic has written only the
         * public half at sk[2*n .. 4*n] - leave the private half
         * sk[0 .. 2*n] untouched in case the caller imported it earlier. */
        if (ret != WC_NO_ERR_TRACE(BAD_LENGTH_E)) {
            ForceZero(key->sk + 2 * n, (word32)(2 * n));
        }
        key->flags = oldFlags;
    }

    /* Use ANONk to auto-detect the OID from the SPKI AlgorithmIdentifier
     * in a single parse. (PrivateKeyDecode parses each DER element
     * manually because the PKCS#8 OneAsymmetricKey layout differs from
     * SPKI and has no matching helper.) */
    ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz, &pubKeyPtr,
                                     &pubKeyLen, &keytype);
    if (ret != 0) {
        return ret;
    }

    /* Map the detected OID key type to an SLH-DSA parameter set.  Pass
     * through NOT_COMPILED_IN so callers see the specific reason
     * (unsupported variant) rather than a generic parse error. */
    paramId = wc_SlhDsaOidToParam(keytype);
    if (paramId == WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
        *inOutIdx = savedIdx;
        return NOT_COMPILED_IN;
    }
    if (paramId < 0) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }
    params = slhdsa_find_params((enum SlhDsaParam)paramId);
    if (params == NULL) {
        *inOutIdx = savedIdx;
        return ASN_PARSE_E;
    }

    oldFlags = key->flags;
    oldParams = key->params;
    key->params = params;
    ret = wc_SlhDsaKey_ImportPublic(key, pubKeyPtr, pubKeyLen);
    if (ret != 0) {
        /* Restore params/flags/inOutIdx. ImportPublic writes only the
         * public half (sk[2*n .. 4*n]) and only after the length check
         * passes; preserve any prior private bytes the caller may have
         * imported into sk[0 .. 2*n]. */
        if (ret != WC_NO_ERR_TRACE(BAD_LENGTH_E)) {
            ForceZero(key->sk + 2 * params->n, (word32)(2 * params->n));
        }
        key->params = oldParams;
        key->flags = oldFlags;
        *inOutIdx = savedIdx;
    }

    return ret;
}

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode an SLH-DSA public key to DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       SLH-DSA key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  inLen     Size of buffer in bytes.
 * @param [in]  withAlg   Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key/key->params is NULL or param is unknown.
 * @return  NOT_COMPILED_IN when key->params names a known SLH-DSA variant
 *          whose parameter set isn't compiled in. In practice unreachable
 *          because SlhDsaParams[] is itself gated on the build, but the
 *          contract matches wc_SlhDsaOidToParam for forward compatibility.
 */
int wc_SlhDsaKey_PublicKeyToDer(SlhDsaKey* key, byte* output, word32 inLen,
    int withAlg)
{
    int ret;
    byte pubKey[WC_SLHDSA_MAX_PUB_LEN];
    word32 pubKeyLen = (word32)sizeof(pubKey);
    int keytype;

    if ((key == NULL) || (key->params == NULL)) {
        return BAD_FUNC_ARG;
    }

    keytype = wc_SlhDsaParamToOid(key->params->param);
    if (keytype < 0) {
        return keytype;
    }

    ret = wc_SlhDsaKey_ExportPublic(key, pubKey, &pubKeyLen);
    if (ret == 0) {
        ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, output, inLen, keytype,
                                  withAlg);
    }

    return ret;
}

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
/* Encode an SLH-DSA private key to DER (PKCS#8 / OneAsymmetricKey).
 *
 * RFC 9909: The privateKey OCTET STRING contains the raw 4*n bytes
 * (SK.seed || SK.prf || PK.seed || PK.root) directly, without a nested
 * OCTET STRING wrapper. This differs from Ed25519/Ed448 which use a
 * double OCTET STRING wrapping.
 *
 * Pass NULL for output to get the required buffer size.
 *
 * @param [in]  key       SLH-DSA key object.
 * @param [out] output    Buffer to put encoded data in (or NULL for size).
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key/key->params is NULL or param is unknown.
 * @return  NOT_COMPILED_IN when key->params names a known SLH-DSA variant
 *          whose parameter set isn't compiled in (in practice unreachable;
 *          SlhDsaParams[] is itself gated on the build).
 * @return  MISSING_KEY when private key not set.
 * @return  BUFFER_E when output buffer is too small.
 */
int wc_SlhDsaKey_KeyToDer(SlhDsaKey* key, byte* output, word32 inLen)
{
    int keytype;
    int n;
    word32 privSz, algoSz, verSz, seqSz, sz;

    if ((key == NULL) || (key->params == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((key->flags & WC_SLHDSA_FLAG_PRIVATE) == 0) {
        return MISSING_KEY;
    }

    keytype = wc_SlhDsaParamToOid(key->params->param);
    if (keytype < 0) {
        return keytype;
    }

    n = key->params->n;
    /* RFC 9909: bare OCTET STRING containing 4*n raw key bytes */
    privSz = SetOctetString((word32)(n * 4), NULL) + (word32)(n * 4);
    algoSz = SetAlgoID(keytype, NULL, oidKeyType, 0);
    verSz  = 3; /* ASN_INTEGER(1) + length(1) + version_byte(1) */
    seqSz  = SetSequence(verSz + algoSz + privSz, NULL);
    sz     = seqSz + verSz + algoSz + privSz;

    if (output == NULL) {
        return (int)sz;
    }
    if (sz > inLen) {
        return BUFFER_E;
    }

    {
        word32 idx = 0;
        int actualVerSz;
        idx += SetSequence(verSz + algoSz + privSz, output + idx);
        actualVerSz = SetMyVersion(0, output + idx, FALSE);
        if (actualVerSz != (int)verSz) {
            return BUFFER_E;
        }
        idx += (word32)actualVerSz;
        idx += SetAlgoID(keytype, output + idx, oidKeyType, 0);
        idx += SetOctetString((word32)(n * 4), output + idx);
        XMEMCPY(output + idx, key->sk, (word32)(n * 4));
        idx += (word32)(n * 4);
        return (int)idx;
    }
}

/* Encode an SLH-DSA private key to DER (PKCS#8 / OneAsymmetricKey).
 *
 * For SLH-DSA, RFC 9909 packs SK.seed || SK.prf || PK.seed || PK.root into
 * a single OCTET STRING, so there is no separate "private-only" encoding.
 * This function is intentionally an alias of wc_SlhDsaKey_KeyToDer, kept
 * for API parity with Ed25519/Ed448 which do have a distinct private form.
 *
 * @param [in]  key       SLH-DSA key object.
 * @param [out] output    Buffer to put encoded data in (or NULL for size).
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MISSING_KEY when private key not set.
 * @return  BUFFER_E when output buffer is too small.
 */
int wc_SlhDsaKey_PrivateKeyToDer(SlhDsaKey* key, byte* output, word32 inLen)
{
    return wc_SlhDsaKey_KeyToDer(key, output, inLen);
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#endif /* WOLFSSL_HAVE_SLHDSA */

