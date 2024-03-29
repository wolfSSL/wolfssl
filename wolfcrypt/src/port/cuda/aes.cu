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
    #include <wolfcrypt/src/misc.c>
#endif

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
extern __device__ const byte Tsbox[256];
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
static WARN_UNUSED_RESULT WC_INLINE word32 PreFetchSBox(void)
{
#ifndef WOLFSSL_AES_TOUCH_LINES
    word32 x = 0;
    int i;

    for (i = 0; i < 256; i += WC_CACHE_LINE_SZ/4) {
        x &= Tsbox[i];
    }
    return x;
#else
    return 0;
#endif
}
#endif

#if !defined(WC_AES_BITSLICED)
/* Encrypt a block using AES.
 *
 * @param [in]  aes       AES object.
 * @param [in]  inBlock   Block to encrypt.
 * @param [out] outBlock  Encrypted block.
 * @param [in]  r         Rounds divided by 2.
 */
__global__ void AesEncrypt_C(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    word32 s0, s1, s2, s3;
    word32 t0, t1, t2, t3;
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
    s0 = ByteReverseWord32(s0);
    s1 = ByteReverseWord32(s1);
    s2 = ByteReverseWord32(s2);
    s3 = ByteReverseWord32(s3);
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
    s0 |= PreFetchSBox();
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
    s0 = ByteReverseWord32(s0);
    s1 = ByteReverseWord32(s1);
    s2 = ByteReverseWord32(s2);
    s3 = ByteReverseWord32(s3);
#endif

    XMEMCPY(outBlock,                  &s0, sizeof(s0));
    XMEMCPY(outBlock +     sizeof(s0), &s1, sizeof(s1));
    XMEMCPY(outBlock + 2 * sizeof(s0), &s2, sizeof(s2));
    XMEMCPY(outBlock + 3 * sizeof(s0), &s3, sizeof(s3));
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
        AesEncrypt_C<<<1,1>>>(aes, in, out, aes->rounds >> 1);
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
void AesEncrypt_C(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    bs_word state[AES_BLOCK_BITS];

    (void)r;

    XMEMCPY(state, inBlock, AES_BLOCK_SIZE);
    XMEMSET(((byte*)state) + AES_BLOCK_SIZE, 0, sizeof(state) - AES_BLOCK_SIZE);

    bs_encrypt(state, aes->bs_key, aes->rounds);

    XMEMCPY(outBlock, state, AES_BLOCK_SIZE);
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

