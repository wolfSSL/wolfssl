/* aes.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/*

DESCRIPTION
This library provides the interfaces to the Advanced Encryption Standard (AES)
for encrypting and decrypting data. AES is the standard known for a symmetric
block cipher mechanism that uses n-bit binary string parameter key with 128-bits,
192-bits, and 256-bits of key sizes.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/aes.h>

#ifdef WOLFSSL_AESNI
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif /* WOLFSSL_AESNI */

#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef WOLFSSL_SECO_CAAM
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#endif

#ifdef WOLFSSL_IMXRT_DCP
    #include <wolfssl/wolfcrypt/port/nxp/dcp_port.h>
#endif
#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_CRYPT)
    #include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#endif

#if defined(WOLFSSL_AES_SIV)
    #include <wolfssl/wolfcrypt/cmac.h>
#endif /* WOLFSSL_AES_SIV */

#if defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_AES)
    #include <wolfssl/wolfcrypt/port/psa/psa.h>
#endif

#if defined(WOLFSSL_TI_CRYPT)
    #include <wolfcrypt/src/port/ti/ti-aes.c>
#else

#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
//    #include <wolfcrypt/src/misc.c>
#endif
/* This routine performs a left circular arithmetic shift of <x> by <y> value. */

#define rotlFixed(x, y) ( (x << y) | (x >> (sizeof(x) * 8 - y)) )

/* This routine performs a right circular arithmetic shift of <x> by <y> value. */
#define rotrFixed(x, y) ( (x >> y) | (x << (sizeof(x) * 8 - y)) )

#ifdef WC_RC2

/* This routine performs a left circular arithmetic shift of <x> by <y> value */
WC_MISC_STATIC WC_INLINE word16 rotlFixed16(word16 x, word16 y)
{
    return (x << y) | (x >> (sizeof(x) * 8 - y));
}


/* This routine performs a right circular arithmetic shift of <x> by <y> value */
WC_MISC_STATIC WC_INLINE word16 rotrFixed16(word16 x, word16 y)
{
    return (x >> y) | (x << (sizeof(x) * 8 - y));
}

#endif /* WC_RC2 */

/* This routine performs a byte swap of 32-bit word value. */
#if defined(__CCRX__) && !defined(NO_INLINE) /* shortest version for CC-RX */
    #define ByteReverseWord32(value, outRef) ( *outRef = _builtin_revl(value) )
#else
    #define ByteReverseWord32(value, outRef) ( *outRef = rotlFixed( ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8) , 16U) )
#endif /* ! (__CCRX__ && !NO_INLINE) */

#if defined(STM32_CRYPTO)
#elif defined(HAVE_COLDFIRE_SEC)
#elif defined(FREESCALE_LTC)
#elif defined(FREESCALE_MMCAU)
#elif defined(WOLFSSL_PIC32MZ_CRYPT)
#elif defined(WOLFSSL_NRF51_AES)
#elif defined(WOLFSSL_ESP32_CRYPT) && \
     !defined(NO_WOLFSSL_ESP32_CRYPT_AES)
#elif defined(WOLFSSL_AESNI)
#elif (defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_AES) \
        && !defined(WOLFSSL_QNX_CAAM)) || \
      ((defined(WOLFSSL_AFALG) || defined(WOLFSSL_DEVCRYPTO_AES)) && \
        defined(HAVE_AESCCM))
#elif defined(WOLFSSL_AFALG)
    /* implemented in wolfcrypt/src/port/af_alg/afalg_aes.c */

#elif defined(WOLFSSL_DEVCRYPTO_AES)
    /* implemented in wolfcrypt/src/port/devcrypto/devcrypto_aes.c */

#elif defined(WOLFSSL_SCE) && !defined(WOLFSSL_SCE_NO_AES)
#elif defined(WOLFSSL_KCAPI_AES)
#elif defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_AES)
/* implemented in wolfcrypt/src/port/psa/psa_aes.c */

#else

    /* using wolfCrypt software implementation */
    #define NEED_AES_TABLES
#endif

#if !defined(NO_AES) && !defined(WOLFSSL_TI_CRYPT) && !defined(WOLFSSL_ARMASM) && \
    defined(NEED_AES_TABLES) && (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM)) && \
    defined(HAVE_CUDA)

#define GETBYTE(x, y) (word32)((byte)((x) >> (8 * (y))))

#ifndef WC_CACHE_LINE_SZ
    #if defined(__x86_64__) || defined(_M_X64) || \
       (defined(__ILP32__) && (__ILP32__ >= 1))
        #define WC_CACHE_LINE_SZ 64
    #else
        /* default cache line size */
        #define WC_CACHE_LINE_SZ 32
    #endif
#endif

#ifndef WOLFSSL_AES_SMALL_TABLES
extern const FLASH_QUALIFIER word32 Te[4][256];
__global__
static word32 GetTable(const word32* t, byte o, word32 *e)
{
#if WC_CACHE_LINE_SZ == 64
  byte hi = o & 0xf0;
  byte lo = o & 0x0f;

  *e  = t[lo + 0x00] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x10] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x20] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x30] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x40] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x50] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x60] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x70] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x80] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0x90] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xa0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xb0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xc0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xd0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xe0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  *e |= t[lo + 0xf0] & ((word32)0 - (((word32)hi - 0x01) >> 31));
#else
  *e = 0;
  int i;
  byte hi = o & WC_CACHE_LINE_MASK_HI;
  byte lo = o & WC_CACHE_LINE_MASK_LO;

  for (i = 0; i < 256; i += (1 << WC_CACHE_LINE_BITS)) {
      *e |= t[lo + i] & ((word32)0 - (((word32)hi - 0x01) >> 31));
      hi -= WC_CACHE_LINE_ADD;
  }
#endif
}

__global__
static void GetTable_Multi(const word32* t, word32* t0, byte o0,
  word32* t1, byte o1, word32* t2, byte o2, word32* t3, byte o3)
{
  word32 e0 = 0;
  word32 e1 = 0;
  word32 e2 = 0;
  word32 e3 = 0;
  byte hi0 = o0 & WC_CACHE_LINE_MASK_HI;
  byte lo0 = o0 & WC_CACHE_LINE_MASK_LO;
  byte hi1 = o1 & WC_CACHE_LINE_MASK_HI;
  byte lo1 = o1 & WC_CACHE_LINE_MASK_LO;
  byte hi2 = o2 & WC_CACHE_LINE_MASK_HI;
  byte lo2 = o2 & WC_CACHE_LINE_MASK_LO;
  byte hi3 = o3 & WC_CACHE_LINE_MASK_HI;
  byte lo3 = o3 & WC_CACHE_LINE_MASK_LO;
  int i;

  for (i = 0; i < 256; i += (1 << WC_CACHE_LINE_BITS)) {
      e0 |= t[lo0 + i] & ((word32)0 - (((word32)hi0 - 0x01) >> 31));
      hi0 -= WC_CACHE_LINE_ADD;
      e1 |= t[lo1 + i] & ((word32)0 - (((word32)hi1 - 0x01) >> 31));
      hi1 -= WC_CACHE_LINE_ADD;
      e2 |= t[lo2 + i] & ((word32)0 - (((word32)hi2 - 0x01) >> 31));
      hi2 -= WC_CACHE_LINE_ADD;
      e3 |= t[lo3 + i] & ((word32)0 - (((word32)hi3 - 0x01) >> 31));
      hi3 -= WC_CACHE_LINE_ADD;
  }
  *t0 = e0;
  *t1 = e1;
  *t2 = e2;
  *t3 = e3;
}

/* load 4 Te Tables into cache by cache line stride */
static WARN_UNUSED_RESULT WC_INLINE word32 PreFetchTe(void)
{
#ifndef WOLFSSL_AES_TOUCH_LINES
    word32 x = 0;
    int i,j;

    for (i = 0; i < 4; i++) {
        /* 256 elements, each one is 4 bytes */
        for (j = 0; j < 256; j += WC_CACHE_LINE_SZ/4) {
            x &= Te[i][j];
        }
    }
    return x;
#else
    return 0;
#endif
}
#else
__device__ static const byte Tsbox[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U,
    0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U,
    0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU,
    0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU,
    0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U,
    0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU,
    0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U,
    0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U,
    0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U,
    0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U,
    0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU,
    0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U,
    0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U,
    0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU,
    0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U,
    0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U,
    0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

#define AES_XTIME(x)    ((byte)((byte)((x) << 1) ^ ((0 - ((x) >> 7)) & 0x1b)))

#define col_mul(t, i2, i3, ia, ib) \
  ( GETBYTE(t, ia) ^ GETBYTE(t, ib) ^ GETBYTE(t, i3) ^ AES_XTIME(GETBYTE(t, i2) ^ GETBYTE(t, i3)) )

#define GetTable(t, o)  t[o]
#define GetTable8(t, o) t[o]
#define GetTable_Multi(t, t0, o0, t1, o1, t2, o2, t3, o3)  \
  *(t0) = (t)[o0]; *(t1) = (t)[o1]; *(t2) = (t)[o2]; *(t3) = (t)[o3]
#define XorTable_Multi(t, t0, o0, t1, o1, t2, o2, t3, o3)  \
  *(t0) ^= (t)[o0]; *(t1) ^= (t)[o1]; *(t2) ^= (t)[o2]; *(t3) ^= (t)[o3]
#define GetTable8_4(t, o0, o1, o2, o3) \
  (((word32)(t)[o0] << 24) | ((word32)(t)[o1] << 16) |   \
   ((word32)(t)[o2] <<  8) | ((word32)(t)[o3] <<  0))

/* load sbox into cache by cache line stride */
#ifndef WOLFSSL_AES_TOUCH_LINES
    #define PreFetchSBox(x) { \
    x = 0; \
    int i; \
    for (i = 0; i < 256; i += WC_CACHE_LINE_SZ/4) { \
        x &= Tsbox[i]; \
    } \
    }
#else
    #define PreFetchSBox(x) ( x = 0 )
#endif
#endif

#if !defined(WC_AES_BITSLICED)
/* Encrypt a block using AES.
 *
 * @param [in]  aes       AES object.
 * @param [in]  inBlock   Block to encrypt.
 * @param [out] outBlock  Encrypted block.
 * @param [in]  r         Rounds divided by 2.
 */
__global__ void AesEncrypt_C_CUDA(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    word32 s0, s1, s2, s3;
    word32 t0, t1, t2, t3;
    word32 sBox;
    const word32* rk;

#ifdef WC_AES_C_DYNAMIC_FALLBACK
    rk = aes->key_C_fallback;
#else
    rk = aes->key;
#endif

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    XMEMCPY(&s0, inBlock,                  sizeof(s0));
    XMEMCPY(&s1, inBlock +     sizeof(s0), sizeof(s1));
    XMEMCPY(&s2, inBlock + 2 * sizeof(s0), sizeof(s2));
    XMEMCPY(&s3, inBlock + 3 * sizeof(s0), sizeof(s3));

#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWord32(s0,&s0);
    ByteReverseWord32(s1,&s1);
    ByteReverseWord32(s2,&s2);
    ByteReverseWord32(s3,&s3);
#endif

    /* AddRoundKey */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

#ifndef WOLFSSL_AES_SMALL_TABLES
#ifndef WC_NO_CACHE_RESISTANT
    s0 |= PreFetchTe();
#endif

#ifndef WOLFSSL_AES_TOUCH_LINES
#define ENC_ROUND_T_S(o)                                                       \
    t0 = GetTable<<<1,1>>>(Te[0], GETBYTE(s0, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(s1, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(s2, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(s3, 0)) ^   \
         rk[(o)+4];                                                            \
    t1 = GetTable<<<1,1>>>(Te[0], GETBYTE(s1, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(s2, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(s3, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(s0, 0)) ^   \
         rk[(o)+5];                                                            \
    t2 = GetTable<<<1,1>>>(Te[0], GETBYTE(s2, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(s3, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(s0, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(s1, 0)) ^   \
         rk[(o)+6];                                                            \
    t3 = GetTable<<<1,1>>>(Te[0], GETBYTE(s3, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(s0, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(s1, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(s2, 0)) ^   \
         rk[(o)+7]
#define ENC_ROUND_S_T(o)                                                       \
    s0 = GetTable<<<1,1>>>(Te[0], GETBYTE(t0, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(t1, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(t2, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(t3, 0)) ^   \
         rk[(o)+0];                                                            \
    s1 = GetTable<<<1,1>>>(Te[0], GETBYTE(t1, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(t2, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(t3, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(t0, 0)) ^   \
         rk[(o)+1];                                                            \
    s2 = GetTable<<<1,1>>>(Te[0], GETBYTE(t2, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(t3, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(t0, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(t1, 0)) ^   \
         rk[(o)+2];                                                            \
    s3 = GetTable<<<1,1>>>(Te[0], GETBYTE(t3, 3)) ^ GetTable<<<1,1>>>(Te[1], GETBYTE(t0, 2)) ^   \
         GetTable<<<1,1>>>(Te[2], GETBYTE(t1, 1)) ^ GetTable<<<1,1>>>(Te[3], GETBYTE(t2, 0)) ^   \
         rk[(o)+3]
#else
#define ENC_ROUND_T_S(o)                                                       \
    GetTable_Multi<<<1,1>>>(Te[0], &t0, GETBYTE(s0, 3), &t1, GETBYTE(s1, 3),            \
                          &t2, GETBYTE(s2, 3), &t3, GETBYTE(s3, 3));           \
    XorTable_Multi(Te[1], &t0, GETBYTE(s1, 2), &t1, GETBYTE(s2, 2),            \
                          &t2, GETBYTE(s3, 2), &t3, GETBYTE(s0, 2));           \
    XorTable_Multi(Te[2], &t0, GETBYTE(s2, 1), &t1, GETBYTE(s3, 1),            \
                          &t2, GETBYTE(s0, 1), &t3, GETBYTE(s1, 1));           \
    XorTable_Multi(Te[3], &t0, GETBYTE(s3, 0), &t1, GETBYTE(s0, 0),            \
                          &t2, GETBYTE(s1, 0), &t3, GETBYTE(s2, 0));           \
    t0 ^= rk[(o)+4]; t1 ^= rk[(o)+5]; t2 ^= rk[(o)+6]; t3 ^= rk[(o)+7];

#define ENC_ROUND_S_T(o)                                                       \
    GetTable_Multi<<<1,1>>>(Te[0], &s0, GETBYTE(t0, 3), &s1, GETBYTE(t1, 3),            \
                          &s2, GETBYTE(t2, 3), &s3, GETBYTE(t3, 3));           \
    XorTable_Multi(Te[1], &s0, GETBYTE(t1, 2), &s1, GETBYTE(t2, 2),            \
                          &s2, GETBYTE(t3, 2), &s3, GETBYTE(t0, 2));           \
    XorTable_Multi(Te[2], &s0, GETBYTE(t2, 1), &s1, GETBYTE(t3, 1),            \
                          &s2, GETBYTE(t0, 1), &s3, GETBYTE(t1, 1));           \
    XorTable_Multi(Te[3], &s0, GETBYTE(t3, 0), &s1, GETBYTE(t0, 0),            \
                          &s2, GETBYTE(t1, 0), &s3, GETBYTE(t2, 0));           \
    s0 ^= rk[(o)+0]; s1 ^= rk[(o)+1]; s2 ^= rk[(o)+2]; s3 ^= rk[(o)+3];
#endif

#ifndef WOLFSSL_AES_NO_UNROLL
/* Unroll the loop. */
                       ENC_ROUND_T_S( 0);
    ENC_ROUND_S_T( 8); ENC_ROUND_T_S( 8);
    ENC_ROUND_S_T(16); ENC_ROUND_T_S(16);
    ENC_ROUND_S_T(24); ENC_ROUND_T_S(24);
    ENC_ROUND_S_T(32); ENC_ROUND_T_S(32);
    if (r > 5) {
        ENC_ROUND_S_T(40); ENC_ROUND_T_S(40);
        if (r > 6) {
            ENC_ROUND_S_T(48); ENC_ROUND_T_S(48);
        }
    }
    rk += r * 8;
#else
    /*
     * Nr - 1 full rounds:
     */

    for (;;) {
        ENC_ROUND_T_S(0);

        rk += 8;
        if (--r == 0) {
            break;
        }

        ENC_ROUND_S_T(0);
    }
#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */

#ifndef WOLFSSL_AES_TOUCH_LINES
    s0 =
        (GetTable(Te[2], GETBYTE(t0, 3)) & 0xff000000) ^
        (GetTable(Te[3], GETBYTE(t1, 2)) & 0x00ff0000) ^
        (GetTable(Te[0], GETBYTE(t2, 1)) & 0x0000ff00) ^
        (GetTable(Te[1], GETBYTE(t3, 0)) & 0x000000ff) ^
        rk[0];
    s1 =
        (GetTable(Te[2], GETBYTE(t1, 3)) & 0xff000000) ^
        (GetTable(Te[3], GETBYTE(t2, 2)) & 0x00ff0000) ^
        (GetTable(Te[0], GETBYTE(t3, 1)) & 0x0000ff00) ^
        (GetTable(Te[1], GETBYTE(t0, 0)) & 0x000000ff) ^
        rk[1];
    s2 =
        (GetTable(Te[2], GETBYTE(t2, 3)) & 0xff000000) ^
        (GetTable(Te[3], GETBYTE(t3, 2)) & 0x00ff0000) ^
        (GetTable(Te[0], GETBYTE(t0, 1)) & 0x0000ff00) ^
        (GetTable(Te[1], GETBYTE(t1, 0)) & 0x000000ff) ^
        rk[2];
    s3 =
        (GetTable(Te[2], GETBYTE(t3, 3)) & 0xff000000) ^
        (GetTable(Te[3], GETBYTE(t0, 2)) & 0x00ff0000) ^
        (GetTable(Te[0], GETBYTE(t1, 1)) & 0x0000ff00) ^
        (GetTable(Te[1], GETBYTE(t2, 0)) & 0x000000ff) ^
        rk[3];
#else
{
    word32 u0;
    word32 u1;
    word32 u2;
    word32 u3;

    s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];
    GetTable_Multi(Te[2], &u0, GETBYTE(t0, 3), &u1, GETBYTE(t1, 3),
                          &u2, GETBYTE(t2, 3), &u3, GETBYTE(t3, 3));
    s0 ^= u0 & 0xff000000; s1 ^= u1 & 0xff000000;
    s2 ^= u2 & 0xff000000; s3 ^= u3 & 0xff000000;
    GetTable_Multi(Te[3], &u0, GETBYTE(t1, 2), &u1, GETBYTE(t2, 2),
                          &u2, GETBYTE(t3, 2), &u3, GETBYTE(t0, 2));
    s0 ^= u0 & 0x00ff0000; s1 ^= u1 & 0x00ff0000;
    s2 ^= u2 & 0x00ff0000; s3 ^= u3 & 0x00ff0000;
    GetTable_Multi(Te[0], &u0, GETBYTE(t2, 1), &u1, GETBYTE(t3, 1),
                          &u2, GETBYTE(t0, 1), &u3, GETBYTE(t1, 1));
    s0 ^= u0 & 0x0000ff00; s1 ^= u1 & 0x0000ff00;
    s2 ^= u2 & 0x0000ff00; s3 ^= u3 & 0x0000ff00;
    GetTable_Multi(Te[1], &u0, GETBYTE(t3, 0), &u1, GETBYTE(t0, 0),
                          &u2, GETBYTE(t1, 0), &u3, GETBYTE(t2, 0));
    s0 ^= u0 & 0x000000ff; s1 ^= u1 & 0x000000ff;
    s2 ^= u2 & 0x000000ff; s3 ^= u3 & 0x000000ff;
}
#endif
#else
#ifndef WC_NO_CACHE_RESISTANT
    PreFetchSBox(sBox);
    s0 |= sBox;
#endif

    r *= 2;
    /* Two rounds at a time */
    for (rk += 4; r > 1; r--, rk += 4) {
        t0 =
            ((word32)GetTable8(Tsbox, GETBYTE(s0, 3)) << 24) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s1, 2)) << 16) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s2, 1)) <<  8) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s3, 0)));
        t1 =
            ((word32)GetTable8(Tsbox, GETBYTE(s1, 3)) << 24) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s2, 2)) << 16) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s3, 1)) <<  8) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s0, 0)));
        t2 =
            ((word32)GetTable8(Tsbox, GETBYTE(s2, 3)) << 24) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s3, 2)) << 16) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s0, 1)) <<  8) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s1, 0)));
        t3 =
            ((word32)GetTable8(Tsbox, GETBYTE(s3, 3)) << 24) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s0, 2)) << 16) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s1, 1)) <<  8) ^
            ((word32)GetTable8(Tsbox, GETBYTE(s2, 0)));

        s0 =
            (col_mul(t0, 3, 2, 0, 1) << 24) ^
            (col_mul(t0, 2, 1, 0, 3) << 16) ^
            (col_mul(t0, 1, 0, 2, 3) <<  8) ^
            (col_mul(t0, 0, 3, 2, 1)      ) ^
            rk[0];
        s1 =
            (col_mul(t1, 3, 2, 0, 1) << 24) ^
            (col_mul(t1, 2, 1, 0, 3) << 16) ^
            (col_mul(t1, 1, 0, 2, 3) <<  8) ^
            (col_mul(t1, 0, 3, 2, 1)      ) ^
            rk[1];
        s2 =
            (col_mul(t2, 3, 2, 0, 1) << 24) ^
            (col_mul(t2, 2, 1, 0, 3) << 16) ^
            (col_mul(t2, 1, 0, 2, 3) <<  8) ^
            (col_mul(t2, 0, 3, 2, 1)      ) ^
            rk[2];
        s3 =
            (col_mul(t3, 3, 2, 0, 1) << 24) ^
            (col_mul(t3, 2, 1, 0, 3) << 16) ^
            (col_mul(t3, 1, 0, 2, 3) <<  8) ^
            (col_mul(t3, 0, 3, 2, 1)      ) ^
            rk[3];
    }

    t0 =
        ((word32)GetTable8(Tsbox, GETBYTE(s0, 3)) << 24) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s1, 2)) << 16) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s2, 1)) <<  8) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s3, 0)));
    t1 =
        ((word32)GetTable8(Tsbox, GETBYTE(s1, 3)) << 24) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s2, 2)) << 16) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s3, 1)) <<  8) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s0, 0)));
    t2 =
        ((word32)GetTable8(Tsbox, GETBYTE(s2, 3)) << 24) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s3, 2)) << 16) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s0, 1)) <<  8) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s1, 0)));
    t3 =
        ((word32)GetTable8(Tsbox, GETBYTE(s3, 3)) << 24) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s0, 2)) << 16) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s1, 1)) <<  8) ^
        ((word32)GetTable8(Tsbox, GETBYTE(s2, 0)));
    s0 = t0 ^ rk[0];
    s1 = t1 ^ rk[1];
    s2 = t2 ^ rk[2];
    s3 = t3 ^ rk[3];
#endif

    /* write out */
#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWord32(s0,&s0);
    ByteReverseWord32(s1,&s1);
    ByteReverseWord32(s2,&s2);
    ByteReverseWord32(s3,&s3);
#endif

    XMEMCPY(outBlock,                  &s0, sizeof(s0));
    XMEMCPY(outBlock +     sizeof(s0), &s1, sizeof(s1));
    XMEMCPY(outBlock + 2 * sizeof(s0), &s2, sizeof(s2));
    XMEMCPY(outBlock + 3 * sizeof(s0), &s3, sizeof(s3));
}

void AesEncrypt_C(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    AesEncrypt_C_CUDA<<<1,1>>>(aes, inBlock, outBlock, r);
}

#if defined(HAVE_AES_ECB) && !(defined(WOLFSSL_IMX6_CAAM) && \
    !defined(NO_IMX6_CAAM_AES) && !defined(WOLFSSL_QNX_CAAM))
/* Encrypt a number of blocks using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 * @param [in]  sz   Number of blocks to encrypt.
 */
void AesEncryptBlocks_C(Aes* aes, const byte* in, byte* out, word32 sz)
{
    word32 i;

    for (i = 0; i < sz; i += AES_BLOCK_SIZE) {
        AesEncrypt_C(aes, in, out, aes->rounds >> 1);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
    }
}
#endif

#else

/* Encrypt a block using AES.
 *
 * @param [in]  aes       AES object.
 * @param [in]  inBlock   Block to encrypt.
 * @param [out] outBlock  Encrypted block.
 * @param [in]  r         Rounds divided by 2.
 */
__global__
void AesEncrypt_C_CUDA(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    bs_word state[AES_BLOCK_BITS];

    (void)r;

    XMEMCPY(state, inBlock, AES_BLOCK_SIZE);
    XMEMSET(((byte*)state) + AES_BLOCK_SIZE, 0, sizeof(state) - AES_BLOCK_SIZE);

    bs_encrypt(state, aes->bs_key, aes->rounds);

    XMEMCPY(outBlock, state, AES_BLOCK_SIZE);
}

void AesEncrypt_C(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    AesEncrypt_C_CUDA<<<1,1>>>(aes, inBlock, outBlock, r);
}

#if defined(HAVE_AES_ECB) && !(defined(WOLFSSL_IMX6_CAAM) && \
    !defined(NO_IMX6_CAAM_AES) && !defined(WOLFSSL_QNX_CAAM))
/* Encrypt a number of blocks using AES.
 *
 * @param [in]  aes  AES object.
 * @param [in]  in   Block to encrypt.
 * @param [out] out  Encrypted block.
 * @param [in]  sz   Number of blocks to encrypt.
 */
void AesEncryptBlocks_C(Aes* aes, const byte* in, byte* out, word32 sz)
{
    bs_word state[AES_BLOCK_BITS];

    while (sz >= BS_BLOCK_SIZE) {
        XMEMCPY(state, in, BS_BLOCK_SIZE);
        bs_encrypt(state, aes->bs_key, aes->rounds);
        XMEMCPY(out, state, BS_BLOCK_SIZE);
        sz  -= BS_BLOCK_SIZE;
        in  += BS_BLOCK_SIZE;
        out += BS_BLOCK_SIZE;
    }
    if (sz > 0) {
        XMEMCPY(state, in, sz);
        XMEMSET(((byte*)state) + sz, 0, sizeof(state) - sz);
        bs_encrypt(state, aes->bs_key, aes->rounds);
        XMEMCPY(out, state, sz);
    }
}
#endif

#endif /* !WC_AES_BITSLICED */

#endif /* HAVE_CUDA */

#endif /* !WOLFSSL_TI_CRYPT */

