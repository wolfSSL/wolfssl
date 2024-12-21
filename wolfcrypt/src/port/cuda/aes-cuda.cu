/* aes.cu
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


#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
/*    #include <wolfcrypt/src/misc.c> */
#endif
/* This routine performs a left circular arithmetic shift of <x> by <y> value. */

extern "C" {

#if !defined(WOLFSSL_TI_CRYPT)

#define rotlFixed(x, y) ( (x << y) | (x >> (sizeof(x) * 8 - y)) )

/* This routine performs a right circular arithmetic shift of <x> by <y> value. */
#define rotrFixed(x, y) ( (x >> y) | (x << (sizeof(x) * 8 - y)) )

#ifdef WC_RC2

/* This routine performs a left circular arithmetic shift of <x> by <y> value */
static WC_INLINE word16 rotlFixed16(word16 x, word16 y)
{
    return (x << y) | (x >> (sizeof(x) * 8 - y));
}


/* This routine performs a right circular arithmetic shift of <x> by <y> value */
static WC_INLINE word16 rotrFixed16(word16 x, word16 y)
{
    return (x >> y) | (x << (sizeof(x) * 8 - y));
}

#endif /* WC_RC2 */

/* This routine performs a byte swap of 32-bit word value. */
#if defined(__CCRX__) && !defined(NO_INLINE) /* shortest version for CC-RX */
    #define ByteReverseWord32(value, outRef) ( *outRef = _builtin_revl(value) )
#else
__device__
static WC_INLINE word32 ByteReverseWord32(word32 value)
{
#ifdef PPC_INTRINSICS
    /* PPC: load reverse indexed instruction */
    return (word32)__lwbrx(&value,0);
#elif defined(__ICCARM__)
    return (word32)__REV(value);
#elif defined(KEIL_INTRINSICS)
    return (word32)__rev(value);
#elif defined(__CCRX__)
    return (word32)_builtin_revl(value);
#elif defined(WOLF_ALLOW_BUILTIN) && \
        defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
    return (word32)__builtin_bswap32(value);
#elif defined(WOLFSSL_BYTESWAP32_ASM) && defined(__GNUC__) && \
      defined(__aarch64__)
    __asm__ volatile (
        "REV32 %0, %0  \n"
        : "+r" (value)
        :
    );
    return value;
#elif defined(WOLFSSL_BYTESWAP32_ASM) && defined(__GNUC__) && \
      (defined(__thumb__) || defined(__arm__))
    __asm__ volatile (
        "REV %0, %0  \n"
        : "+r" (value)
        :
    );
    return value;
#elif defined(FAST_ROTATE)
    /* 5 instructions with rotate instruction, 9 without */
    return (rotrFixed(value, 8U) & 0xff00ff00) |
           (rotlFixed(value, 8U) & 0x00ff00ff);
#else
    /* 6 instructions with rotate instruction, 8 without */
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return rotlFixed(value, 16U);
#endif
}
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

#if WC_CACHE_LINE_SZ == 128
    #define WC_CACHE_LINE_BITS      5
    #define WC_CACHE_LINE_MASK_HI   0xe0
    #define WC_CACHE_LINE_MASK_LO   0x1f
    #define WC_CACHE_LINE_ADD       0x20
#elif WC_CACHE_LINE_SZ == 64
    #define WC_CACHE_LINE_BITS      4
    #define WC_CACHE_LINE_MASK_HI   0xf0
    #define WC_CACHE_LINE_MASK_LO   0x0f
    #define WC_CACHE_LINE_ADD       0x10
#elif WC_CACHE_LINE_SZ == 32
    #define WC_CACHE_LINE_BITS      3
    #define WC_CACHE_LINE_MASK_HI   0xf8
    #define WC_CACHE_LINE_MASK_LO   0x07
    #define WC_CACHE_LINE_ADD       0x08
#elif WC_CACHE_LINE_SZ == 16
    #define WC_CACHE_LINE_BITS      2
    #define WC_CACHE_LINE_MASK_HI   0xfc
    #define WC_CACHE_LINE_MASK_LO   0x03
    #define WC_CACHE_LINE_ADD       0x04
#else
    #error Cache line size not supported
#endif

#ifndef WOLFSSL_AES_SMALL_TABLES
__device__
const FLASH_QUALIFIER word32 Te_CUDA[4][256] = {
{
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
},
{
    0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
    0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
    0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
    0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
    0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
    0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
    0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
    0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
    0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
    0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
    0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
    0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
    0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
    0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
    0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
    0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
    0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
    0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
    0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
    0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
    0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
    0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
    0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
    0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
    0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
    0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
    0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
    0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
    0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
    0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
    0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
    0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
    0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
    0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
    0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
    0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
    0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
    0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
    0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
    0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
    0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
    0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
    0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
    0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
    0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
    0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
    0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
    0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
    0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
    0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
    0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
    0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
    0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
    0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
    0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
    0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
    0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
    0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
    0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
    0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
    0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
    0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
    0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
    0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
},
{
    0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
    0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
    0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
    0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
    0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
    0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
    0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
    0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
    0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
    0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
    0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
    0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
    0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
    0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
    0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
    0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
    0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
    0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
    0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
    0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
    0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
    0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
    0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
    0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
    0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
    0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
    0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
    0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
    0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
    0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
    0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
    0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
    0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
    0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
    0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
    0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
    0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
    0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
    0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
    0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
    0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
    0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
    0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
    0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
    0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
    0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
    0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
    0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
    0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
    0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
    0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
    0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
    0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
    0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
    0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
    0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
    0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
    0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
    0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
    0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
    0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
    0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
    0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
    0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
},
{
    0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
    0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
    0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
    0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
    0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
    0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
    0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
    0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
    0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
    0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
    0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
    0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
    0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
    0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
    0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
    0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
    0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
    0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
    0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
    0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
    0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
    0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
    0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
    0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
    0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
    0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
    0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
    0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
    0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
    0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
    0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
    0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
    0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
    0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
    0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
    0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
    0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
    0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
    0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
    0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
    0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
    0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
    0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
    0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
    0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
    0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
    0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
    0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
    0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
    0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
    0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
    0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
    0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
    0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
    0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
    0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
    0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
    0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
    0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
    0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
    0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
    0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
    0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
    0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
}
};


__device__
static word32 GetTable(const word32* t, byte o)
{
    word32 e = 0;
#if WC_CACHE_LINE_SZ == 64
  byte hi = o & 0xf0;
  byte lo = o & 0x0f;

  e  = t[lo + 0x00] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x10] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x20] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x30] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x40] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x50] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x60] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x70] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x80] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0x90] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xa0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xb0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xc0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xd0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xe0] & ((word32)0 - (((word32)hi - 0x01) >> 31)); hi -= 0x10;
  e |= t[lo + 0xf0] & ((word32)0 - (((word32)hi - 0x01) >> 31));
#else
  int i;
  byte hi = o & WC_CACHE_LINE_MASK_HI;
  byte lo = o & WC_CACHE_LINE_MASK_LO;

  for (i = 0; i < 256; i += (1 << WC_CACHE_LINE_BITS)) {
      e |= t[lo + i] & ((word32)0 - (((word32)hi - 0x01) >> 31));
      hi -= WC_CACHE_LINE_ADD;
  }
#endif
  return e;
}

__device__
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
__device__
static WARN_UNUSED_RESULT WC_INLINE word32 PreFetchTe(void)
{
#ifndef WOLFSSL_AES_TOUCH_LINES
    word32 x = 0;
    int i,j;

    for (i = 0; i < 4; i++) {
        /* 256 elements, each one is 4 bytes */
        for (j = 0; j < 256; j += WC_CACHE_LINE_SZ/4) {
            x &= Te_CUDA[i][j];
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
 * @param [in]  sz        Number of blocks to encrypt
 */
__global__ void AesEncrypt_C_CUDA(word32* rkBase, const byte* inBlockBase, byte* outBlockBase,
        word32 r, word32 sz)
{
    word32 s0, s1, s2, s3;
    word32 t0, t1, t2, t3;
    word32 sBox;
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    int stride = blockDim.x * gridDim.x;
    const byte* inBlock = inBlockBase;
    byte* outBlock = outBlockBase;
    word32* rk;

    for (int i = index; i < sz; i += stride) {
        rk = rkBase;
        inBlock = inBlockBase + i * 4 * sizeof(s0);
        outBlock = outBlockBase + i * 4 * sizeof(s0);

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
        t0 = GetTable(Te_CUDA[0], GETBYTE(s0, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(s1, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(s2, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(s3, 0)) ^   \
             rk[(o)+4];                                                            \
        t1 = GetTable(Te_CUDA[0], GETBYTE(s1, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(s2, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(s3, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(s0, 0)) ^   \
             rk[(o)+5];                                                            \
        t2 = GetTable(Te_CUDA[0], GETBYTE(s2, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(s3, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(s0, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(s1, 0)) ^   \
             rk[(o)+6];                                                            \
        t3 = GetTable(Te_CUDA[0], GETBYTE(s3, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(s0, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(s1, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(s2, 0)) ^   \
             rk[(o)+7]
#define ENC_ROUND_S_T(o)                                                       \
        s0 = GetTable(Te_CUDA[0], GETBYTE(t0, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(t1, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(t2, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(t3, 0)) ^   \
             rk[(o)+0];                                                            \
        s1 = GetTable(Te_CUDA[0], GETBYTE(t1, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(t2, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(t3, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(t0, 0)) ^   \
             rk[(o)+1];                                                            \
        s2 = GetTable(Te_CUDA[0], GETBYTE(t2, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(t3, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(t0, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(t1, 0)) ^   \
             rk[(o)+2];                                                            \
        s3 = GetTable(Te_CUDA[0], GETBYTE(t3, 3)) ^ GetTable(Te_CUDA[1], GETBYTE(t0, 2)) ^   \
             GetTable(Te_CUDA[2], GETBYTE(t1, 1)) ^ GetTable(Te_CUDA[3], GETBYTE(t2, 0)) ^   \
             rk[(o)+3]
#else
#define ENC_ROUND_T_S(o)                                                       \
        GetTable_Multi(Te_CUDA[0], &t0, GETBYTE(s0, 3), &t1, GETBYTE(s1, 3),            \
                              &t2, GETBYTE(s2, 3), &t3, GETBYTE(s3, 3));           \
        XorTable_Multi(Te_CUDA[1], &t0, GETBYTE(s1, 2), &t1, GETBYTE(s2, 2),            \
                              &t2, GETBYTE(s3, 2), &t3, GETBYTE(s0, 2));           \
        XorTable_Multi(Te_CUDA[2], &t0, GETBYTE(s2, 1), &t1, GETBYTE(s3, 1),            \
                              &t2, GETBYTE(s0, 1), &t3, GETBYTE(s1, 1));           \
        XorTable_Multi(Te_CUDA[3], &t0, GETBYTE(s3, 0), &t1, GETBYTE(s0, 0),            \
                              &t2, GETBYTE(s1, 0), &t3, GETBYTE(s2, 0));           \
        t0 ^= rk[(o)+4]; t1 ^= rk[(o)+5]; t2 ^= rk[(o)+6]; t3 ^= rk[(o)+7];

#define ENC_ROUND_S_T(o)                                                       \
        GetTable_Multi(Te_CUDA[0], &s0, GETBYTE(t0, 3), &s1, GETBYTE(t1, 3),            \
                              &s2, GETBYTE(t2, 3), &s3, GETBYTE(t3, 3));           \
        XorTable_Multi(Te_CUDA[1], &s0, GETBYTE(t1, 2), &s1, GETBYTE(t2, 2),            \
                              &s2, GETBYTE(t3, 2), &s3, GETBYTE(t0, 2));           \
        XorTable_Multi(Te_CUDA[2], &s0, GETBYTE(t2, 1), &s1, GETBYTE(t3, 1),            \
                              &s2, GETBYTE(t0, 1), &s3, GETBYTE(t1, 1));           \
        XorTable_Multi(Te_CUDA[3], &s0, GETBYTE(t3, 0), &s1, GETBYTE(t0, 0),            \
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
            (GetTable(Te_CUDA[2], GETBYTE(t0, 3)) & 0xff000000) ^
            (GetTable(Te_CUDA[3], GETBYTE(t1, 2)) & 0x00ff0000) ^
            (GetTable(Te_CUDA[0], GETBYTE(t2, 1)) & 0x0000ff00) ^
            (GetTable(Te_CUDA[1], GETBYTE(t3, 0)) & 0x000000ff) ^
            rk[0];
        s1 =
            (GetTable(Te_CUDA[2], GETBYTE(t1, 3)) & 0xff000000) ^
            (GetTable(Te_CUDA[3], GETBYTE(t2, 2)) & 0x00ff0000) ^
            (GetTable(Te_CUDA[0], GETBYTE(t3, 1)) & 0x0000ff00) ^
            (GetTable(Te_CUDA[1], GETBYTE(t0, 0)) & 0x000000ff) ^
            rk[1];
        s2 =
            (GetTable(Te_CUDA[2], GETBYTE(t2, 3)) & 0xff000000) ^
            (GetTable(Te_CUDA[3], GETBYTE(t3, 2)) & 0x00ff0000) ^
            (GetTable(Te_CUDA[0], GETBYTE(t0, 1)) & 0x0000ff00) ^
            (GetTable(Te_CUDA[1], GETBYTE(t1, 0)) & 0x000000ff) ^
            rk[2];
        s3 =
            (GetTable(Te_CUDA[2], GETBYTE(t3, 3)) & 0xff000000) ^
            (GetTable(Te_CUDA[3], GETBYTE(t0, 2)) & 0x00ff0000) ^
            (GetTable(Te_CUDA[0], GETBYTE(t1, 1)) & 0x0000ff00) ^
            (GetTable(Te_CUDA[1], GETBYTE(t2, 0)) & 0x000000ff) ^
            rk[3];
#else
    {
        word32 u0;
        word32 u1;
        word32 u2;
        word32 u3;

        s0 = rk[0]; s1 = rk[1]; s2 = rk[2]; s3 = rk[3];
        GetTable_Multi(Te_CUDA[2], &u0, GETBYTE(t0, 3), &u1, GETBYTE(t1, 3),
                              &u2, GETBYTE(t2, 3), &u3, GETBYTE(t3, 3));
        s0 ^= u0 & 0xff000000; s1 ^= u1 & 0xff000000;
        s2 ^= u2 & 0xff000000; s3 ^= u3 & 0xff000000;
        GetTable_Multi(Te_CUDA[3], &u0, GETBYTE(t1, 2), &u1, GETBYTE(t2, 2),
                              &u2, GETBYTE(t3, 2), &u3, GETBYTE(t0, 2));
        s0 ^= u0 & 0x00ff0000; s1 ^= u1 & 0x00ff0000;
        s2 ^= u2 & 0x00ff0000; s3 ^= u3 & 0x00ff0000;
        GetTable_Multi(Te_CUDA[0], &u0, GETBYTE(t2, 1), &u1, GETBYTE(t3, 1),
                              &u2, GETBYTE(t0, 1), &u3, GETBYTE(t1, 1));
        s0 ^= u0 & 0x0000ff00; s1 ^= u1 & 0x0000ff00;
        s2 ^= u2 & 0x0000ff00; s3 ^= u3 & 0x0000ff00;
        GetTable_Multi(Te_CUDA[1], &u0, GETBYTE(t3, 0), &u1, GETBYTE(t0, 0),
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
}

void AesEncrypt_C(Aes* aes, const byte* inBlock, byte* outBlock,
        word32 r)
{
    byte *inBlock_GPU = NULL;
    byte *outBlock_GPU = NULL;
    word32* rk_GPU = NULL;
    cudaError_t ret = cudaSuccess;

#ifdef WC_C_DYNAMIC_FALLBACK
    if ( ret == cudaSuccess )
        ret = cudaMalloc(&rk_GPU, sizeof(aes->key_C_fallback));
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(rk_GPU, aes->key_C_fallback, sizeof(aes->key_C_fallback), cudaMemcpyDefault);
#else
    if ( ret == cudaSuccess )
        ret = cudaMalloc(&rk_GPU, sizeof(aes->key));
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(rk_GPU, aes->key, sizeof(aes->key), cudaMemcpyDefault);
#endif

    if ( ret == cudaSuccess )
        ret = cudaMalloc(&inBlock_GPU, WC_AES_BLOCK_SIZE);
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(inBlock_GPU, inBlock, WC_AES_BLOCK_SIZE, cudaMemcpyDefault);

    if ( ret == cudaSuccess )
        ret = cudaMalloc(&outBlock_GPU, WC_AES_BLOCK_SIZE);

    if ( ret == cudaSuccess )
        AesEncrypt_C_CUDA<<<1,1>>>(rk_GPU, inBlock_GPU, outBlock_GPU, r, 1);

    if ( ret == cudaSuccess )
        ret = cudaMemcpy(outBlock, outBlock_GPU, WC_AES_BLOCK_SIZE, cudaMemcpyDefault);

    cudaFree(inBlock_GPU);
    cudaFree(outBlock_GPU);
    cudaFree(rk_GPU);
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
    byte *in_GPU = NULL;
    byte *out_GPU = NULL;
    word32* rk_GPU = NULL;
    cudaError_t ret = cudaSuccess;

#ifdef WC_C_DYNAMIC_FALLBACK
    if ( ret == cudaSuccess )
        ret = cudaMalloc(&rk_GPU, sizeof(aes->key_C_fallback));
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(rk_GPU, aes->key_C_fallback, sizeof(aes->key_C_fallback), cudaMemcpyDefault);
#else
    if ( ret == cudaSuccess )
        ret = cudaMalloc(&rk_GPU, sizeof(aes->key));
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(rk_GPU, aes->key, sizeof(aes->key), cudaMemcpyDefault);
#endif

    if ( ret == cudaSuccess )
        ret = cudaMalloc(&in_GPU, sz);
    if ( ret == cudaSuccess )
        ret = cudaMemcpy(in_GPU, in, sz, cudaMemcpyDefault);

    if ( ret == cudaSuccess )
        ret = cudaMalloc(&out_GPU, sz);

    if ( ret == cudaSuccess ) {
        int blockSize = 256;
        int numBlocks = (sz / WC_AES_BLOCK_SIZE + blockSize - 1) / blockSize;
        AesEncrypt_C_CUDA<<<numBlocks,blockSize>>>(rk_GPU, in_GPU, out_GPU, aes->rounds >> 1, sz / WC_AES_BLOCK_SIZE);
    }

    if ( ret == cudaSuccess )
        ret = cudaMemcpy(out, out_GPU, sz, cudaMemcpyDefault);

    cudaFree(in_GPU);
    cudaFree(out_GPU);
    cudaFree(rk_GPU);
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

    XMEMCPY(state, inBlock, WC_AES_BLOCK_SIZE);
    XMEMSET(((byte*)state) + WC_AES_BLOCK_SIZE, 0, sizeof(state) - WC_AES_BLOCK_SIZE);

    bs_encrypt(state, aes->bs_key, aes->rounds);

    XMEMCPY(outBlock, state, WC_AES_BLOCK_SIZE);
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

} /* extern "C" */
