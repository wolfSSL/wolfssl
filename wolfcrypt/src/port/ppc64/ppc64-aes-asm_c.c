/* ppc64-aes-asm
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./aes/aes.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-aes-asm.c
 */
#ifdef WOLFSSL_PPC64_ASM
#include <stdint.h>
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#ifdef WOLFSSL_PPC64_ASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifdef __ghs__
#define __asm__        __asm
#define __volatile__
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __ghs__ */
#include <wolfssl/wolfcrypt/aes.h>

#if !defined(NO_AES) && defined(WOLFSSL_PPC64_ASM)
#ifdef HAVE_AES_DECRYPT
static const word32 L_AES_PPC64_td[] = {
    0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e,
    0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303,
    0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c,
    0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3,
    0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0,
    0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9,
    0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259,
    0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8,
    0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971,
    0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a,
    0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f,
    0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b,
    0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8,
    0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab,
    0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708,
    0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682,
    0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2,
    0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe,
    0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb,
    0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10,
    0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd,
    0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015,
    0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e,
    0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee,
    0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000,
    0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72,
    0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39,
    0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e,
    0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91,
    0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a,
    0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17,
    0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9,
    0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60,
    0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e,
    0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1,
    0xcad731dc, 0x10426385, 0x40139722, 0x2084c611,
    0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1,
    0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3,
    0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964,
    0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390,
    0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b,
    0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf,
    0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46,
    0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af,
    0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512,
    0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb,
    0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a,
    0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8,
    0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c,
    0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266,
    0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8,
    0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6,
    0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604,
    0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551,
    0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41,
    0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647,
    0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c,
    0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1,
    0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737,
    0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db,
    0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340,
    0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95,
    0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1,
    0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857,
};

#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
static const word32 L_AES_PPC64_te[] = {
    0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b,
    0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5,
    0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b,
    0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676,
    0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d,
    0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0,
    0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf,
    0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0,
    0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626,
    0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc,
    0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1,
    0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515,
    0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3,
    0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a,
    0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2,
    0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575,
    0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a,
    0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0,
    0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3,
    0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484,
    0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded,
    0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b,
    0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939,
    0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf,
    0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb,
    0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585,
    0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f,
    0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8,
    0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f,
    0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5,
    0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121,
    0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2,
    0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec,
    0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717,
    0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d,
    0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373,
    0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc,
    0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888,
    0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414,
    0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb,
    0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a,
    0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c,
    0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262,
    0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979,
    0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d,
    0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9,
    0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea,
    0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808,
    0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e,
    0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6,
    0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f,
    0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a,
    0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666,
    0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e,
    0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9,
    0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e,
    0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111,
    0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494,
    0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9,
    0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf,
    0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d,
    0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868,
    0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f,
    0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616,
};

#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
void AES_invert_key(unsigned char* ks, word32 rounds);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_invert_key(unsigned char* ks_p, word32 rounds_p)
#else
void AES_invert_key(unsigned char* ks, word32 rounds)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register unsigned char* ks asm ("3") = (unsigned char*)ks_p;
    register word32 rounds asm ("4") = (word32)rounds_p;
    register word32* L_AES_PPC64_te_c asm ("5") = (word32*)&L_AES_PPC64_te;
    register word32* L_AES_PPC64_td_c asm ("6") = (word32*)&L_AES_PPC64_td;
#else
    register word32* L_AES_PPC64_te_c = (word32*)&L_AES_PPC64_te;

    register word32* L_AES_PPC64_td_c = (word32*)&L_AES_PPC64_td;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      5, %[L_AES_PPC64_te]\n\t"
        "mr      6, %[L_AES_PPC64_td]\n\t"
        "addi    5, 5, 3\n\t"
        "sldi    16, %[rounds], 4\n\t"
        "add     16, 16, %[ks]\n\t"
        "srdi    0, %[rounds], 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_invert_key_loop_%=: \n\t"
        "ld      7, 0(%[ks])\n\t"
        "ld      8, 8(%[ks])\n\t"
        "ld      11, 0(16)\n\t"
        "ld      12, 8(16)\n\t"
        "std     7, 0(16)\n\t"
        "std     8, 8(16)\n\t"
        "std     11, 0(%[ks])\n\t"
        "std     12, 8(%[ks])\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "addi    16, 16, -16\n\t"
        "bdnz    L_AES_invert_key_loop_%=\n\t"
        "sldi    16, %[rounds], 3\n\t"
        "subf    %[ks], 16, %[ks]\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "addi    0, %[rounds], -1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_invert_key_mix_loop_%=: \n\t"
        "lwz     7, 0(%[ks])\n\t"
        "lwz     8, 4(%[ks])\n\t"
        "lwz     9, 8(%[ks])\n\t"
        "lwz     10, 12(%[ks])\n\t"
        "andi.   11, 7, 255\n\t"
        "rlwinm  12, 7, 24, 24, 31\n\t"
        "rlwinm  14, 7, 16, 24, 31\n\t"
        "rlwinm  15, 7, 8, 24, 31\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    11, 5, 11\n\t"
        "lbzx    12, 5, 12\n\t"
        "lbzx    14, 5, 14\n\t"
        "lbzx    15, 5, 15\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lwzx    11, 6, 11\n\t"
        "lwzx    12, 6, 12\n\t"
        "lwzx    14, 6, 14\n\t"
        "lwzx    15, 6, 15\n\t"
        "rlwimi  11, 11, 16, 0, 31\n\t"
        "rlwimi  12, 12, 24, 0, 31\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 11\n\t"
        "xor     14, 14, 12\n\t"
        "xor     14, 14, 15\n\t"
        "stw     14, 0(%[ks])\n\t"
        "addi    %[ks], %[ks], 4\n\t"
        "andi.   11, 8, 255\n\t"
        "rlwinm  12, 8, 24, 24, 31\n\t"
        "rlwinm  14, 8, 16, 24, 31\n\t"
        "rlwinm  15, 8, 8, 24, 31\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    11, 5, 11\n\t"
        "lbzx    12, 5, 12\n\t"
        "lbzx    14, 5, 14\n\t"
        "lbzx    15, 5, 15\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lwzx    11, 6, 11\n\t"
        "lwzx    12, 6, 12\n\t"
        "lwzx    14, 6, 14\n\t"
        "lwzx    15, 6, 15\n\t"
        "rlwimi  11, 11, 16, 0, 31\n\t"
        "rlwimi  12, 12, 24, 0, 31\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 11\n\t"
        "xor     14, 14, 12\n\t"
        "xor     14, 14, 15\n\t"
        "stw     14, 0(%[ks])\n\t"
        "addi    %[ks], %[ks], 4\n\t"
        "andi.   11, 9, 255\n\t"
        "rlwinm  12, 9, 24, 24, 31\n\t"
        "rlwinm  14, 9, 16, 24, 31\n\t"
        "rlwinm  15, 9, 8, 24, 31\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    11, 5, 11\n\t"
        "lbzx    12, 5, 12\n\t"
        "lbzx    14, 5, 14\n\t"
        "lbzx    15, 5, 15\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lwzx    11, 6, 11\n\t"
        "lwzx    12, 6, 12\n\t"
        "lwzx    14, 6, 14\n\t"
        "lwzx    15, 6, 15\n\t"
        "rlwimi  11, 11, 16, 0, 31\n\t"
        "rlwimi  12, 12, 24, 0, 31\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 11\n\t"
        "xor     14, 14, 12\n\t"
        "xor     14, 14, 15\n\t"
        "stw     14, 0(%[ks])\n\t"
        "addi    %[ks], %[ks], 4\n\t"
        "andi.   11, 10, 255\n\t"
        "rlwinm  12, 10, 24, 24, 31\n\t"
        "rlwinm  14, 10, 16, 24, 31\n\t"
        "rlwinm  15, 10, 8, 24, 31\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    11, 5, 11\n\t"
        "lbzx    12, 5, 12\n\t"
        "lbzx    14, 5, 14\n\t"
        "lbzx    15, 5, 15\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lwzx    11, 6, 11\n\t"
        "lwzx    12, 6, 12\n\t"
        "lwzx    14, 6, 14\n\t"
        "lwzx    15, 6, 15\n\t"
        "rlwimi  11, 11, 16, 0, 31\n\t"
        "rlwimi  12, 12, 24, 0, 31\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 11\n\t"
        "xor     14, 14, 12\n\t"
        "xor     14, 14, 15\n\t"
        "stw     14, 0(%[ks])\n\t"
        "addi    %[ks], %[ks], 4\n\t"
        "bdnz    L_AES_invert_key_mix_loop_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ks] "+r" (ks), [rounds] "+r" (rounds),
          [L_AES_PPC64_te] "+r" (L_AES_PPC64_te_c),
          [L_AES_PPC64_td] "+r" (L_AES_PPC64_td_c)
        :
#else
        :
        : [ks] "r" (ks), [rounds] "r" (rounds),
          [L_AES_PPC64_te] "r" (L_AES_PPC64_te_c),
          [L_AES_PPC64_td] "r" (L_AES_PPC64_td_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "7", "8", "9", "10", "11", "12", "14", "15",
            "16"
    );
}

#endif /* HAVE_AES_DECRYPT */
static const word32 L_AES_PPC64_rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
};

void AES_set_encrypt_key(const unsigned char* key, word32 len,
    unsigned char* ks);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_set_encrypt_key(const unsigned char* key_p, word32 len_p,
    unsigned char* ks_p)
#else
void AES_set_encrypt_key(const unsigned char* key, word32 len,
    unsigned char* ks)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* key asm ("3") = (const unsigned char*)key_p;
    register word32 len asm ("4") = (word32)len_p;
    register unsigned char* ks asm ("5") = (unsigned char*)ks_p;
    register word32* L_AES_PPC64_te_c asm ("6") = (word32*)&L_AES_PPC64_te;
    register word32* L_AES_PPC64_rcon_c asm ("7") = (word32*)&L_AES_PPC64_rcon;
#else
    register word32* L_AES_PPC64_te_c = (word32*)&L_AES_PPC64_te;

    register word32* L_AES_PPC64_rcon_c = (word32*)&L_AES_PPC64_rcon;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      6, %[L_AES_PPC64_te]\n\t"
        "mr      7, %[L_AES_PPC64_rcon]\n\t"
        "addi    6, 6, 3\n\t"
        "cmplwi  %[len], 0x80\n\t"
        "beq     L_AES_set_encrypt_key_start_128_%=\n\t"
        "cmplwi  %[len], 0xc0\n\t"
        "beq     L_AES_set_encrypt_key_start_192_%=\n\t"
        "ld      9, 0(%[key])\n\t"
        "ld      10, 8(%[key])\n\t"
        "ld      11, 16(%[key])\n\t"
        "ld      12, 24(%[key])\n\t"
        "std     9, 0(%[ks])\n\t"
        "std     10, 8(%[ks])\n\t"
        "std     11, 16(%[ks])\n\t"
        "std     12, 24(%[ks])\n\t"
        "li      8, 6\n\t"
        "mtctr   8\n\t"
        "\n"
    "L_AES_set_encrypt_key_loop_256_%=: \n\t"
        "andi.   9, 12, 255\n\t"
        "rlwinm  10, 12, 24, 24, 31\n\t"
        "rlwinm  11, 12, 16, 24, 31\n\t"
        "rlwinm  12, 12, 8, 24, 31\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 12\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "xor     9, 9, 0\n\t"
        "lwz     0, 0(7)\n\t"
        "addi    7, 7, 4\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "stw     9, 16(%[ks])\n\t"
        "stw     10, 20(%[ks])\n\t"
        "stw     11, 24(%[ks])\n\t"
        "stw     12, 28(%[ks])\n\t"
        "rlwinm  9, 12, 24, 24, 31\n\t"
        "rlwinm  10, 12, 16, 24, 31\n\t"
        "rlwinm  11, 12, 8, 24, 31\n\t"
        "andi.   12, 12, 255\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 12\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "stw     9, 16(%[ks])\n\t"
        "stw     10, 20(%[ks])\n\t"
        "stw     11, 24(%[ks])\n\t"
        "stw     12, 28(%[ks])\n\t"
        "bdnz    L_AES_set_encrypt_key_loop_256_%=\n\t"
        "andi.   9, 12, 255\n\t"
        "rlwinm  10, 12, 24, 24, 31\n\t"
        "rlwinm  11, 12, 16, 24, 31\n\t"
        "rlwinm  12, 12, 8, 24, 31\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 12\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "xor     9, 9, 0\n\t"
        "lwz     0, 0(7)\n\t"
        "addi    7, 7, 4\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "stw     9, 16(%[ks])\n\t"
        "stw     10, 20(%[ks])\n\t"
        "stw     11, 24(%[ks])\n\t"
        "stw     12, 28(%[ks])\n\t"
        "b       L_AES_set_encrypt_key_end_%=\n\t"
        "\n"
    "L_AES_set_encrypt_key_start_192_%=: \n\t"
        "ld      12, 0(%[key])\n\t"
        "ld      14, 8(%[key])\n\t"
        "ld      15, 16(%[key])\n\t"
        "std     12, 0(%[ks])\n\t"
        "std     14, 8(%[ks])\n\t"
        "std     15, 16(%[ks])\n\t"
        "li      8, 7\n\t"
        "mtctr   8\n\t"
        "\n"
    "L_AES_set_encrypt_key_loop_192_%=: \n\t"
        "andi.   9, 15, 255\n\t"
        "rlwinm  10, 15, 24, 24, 31\n\t"
        "rlwinm  11, 15, 16, 24, 31\n\t"
        "rlwinm  15, 15, 8, 24, 31\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 15\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "lwz     14, 16(%[ks])\n\t"
        "lwz     15, 20(%[ks])\n\t"
        "addi    %[ks], %[ks], 24\n\t"
        "xor     9, 9, 0\n\t"
        "lwz     0, 0(7)\n\t"
        "addi    7, 7, 4\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "xor     14, 14, 12\n\t"
        "xor     15, 15, 14\n\t"
        "stw     9, 0(%[ks])\n\t"
        "stw     10, 4(%[ks])\n\t"
        "stw     11, 8(%[ks])\n\t"
        "stw     12, 12(%[ks])\n\t"
        "stw     14, 16(%[ks])\n\t"
        "stw     15, 20(%[ks])\n\t"
        "bdnz    L_AES_set_encrypt_key_loop_192_%=\n\t"
        "andi.   9, 15, 255\n\t"
        "rlwinm  10, 15, 24, 24, 31\n\t"
        "rlwinm  11, 15, 16, 24, 31\n\t"
        "rlwinm  15, 15, 8, 24, 31\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 15\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "lwz     14, 16(%[ks])\n\t"
        "lwz     15, 20(%[ks])\n\t"
        "addi    %[ks], %[ks], 24\n\t"
        "xor     9, 9, 0\n\t"
        "lwz     0, 0(7)\n\t"
        "addi    7, 7, 4\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "stw     9, 0(%[ks])\n\t"
        "stw     10, 4(%[ks])\n\t"
        "stw     11, 8(%[ks])\n\t"
        "stw     12, 12(%[ks])\n\t"
        "b       L_AES_set_encrypt_key_end_%=\n\t"
        "\n"
    "L_AES_set_encrypt_key_start_128_%=: \n\t"
        "li      8, 0\n\t"
        "ld      11, 0(%[key])\n\t"
        "ld      12, 8(%[key])\n\t"
        "std     11, 0(%[ks])\n\t"
        "std     12, 8(%[ks])\n\t"
        "li      8, 10\n\t"
        "mtctr   8\n\t"
        "\n"
    "L_AES_set_encrypt_key_loop_128_%=: \n\t"
        "andi.   9, 12, 255\n\t"
        "rlwinm  10, 12, 24, 24, 31\n\t"
        "rlwinm  11, 12, 16, 24, 31\n\t"
        "rlwinm  12, 12, 8, 24, 31\n\t"
        "slwi    9, 9, 2\n\t"
        "slwi    10, 10, 2\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    12, 12, 2\n\t"
        "lbzx    9, 6, 9\n\t"
        "lbzx    10, 6, 10\n\t"
        "lbzx    11, 6, 11\n\t"
        "lbzx    0, 6, 12\n\t"
        "rlwimi  0, 9, 8, 16, 23\n\t"
        "rlwimi  0, 10, 16, 8, 15\n\t"
        "rlwimi  0, 11, 24, 0, 7\n\t"
        "lwz     9, 0(%[ks])\n\t"
        "lwz     10, 4(%[ks])\n\t"
        "lwz     11, 8(%[ks])\n\t"
        "lwz     12, 12(%[ks])\n\t"
        "addi    %[ks], %[ks], 16\n\t"
        "xor     9, 9, 0\n\t"
        "lwz     0, 0(7)\n\t"
        "addi    7, 7, 4\n\t"
        "xor     9, 9, 0\n\t"
        "xor     10, 10, 9\n\t"
        "xor     11, 11, 10\n\t"
        "xor     12, 12, 11\n\t"
        "stw     9, 0(%[ks])\n\t"
        "stw     10, 4(%[ks])\n\t"
        "stw     11, 8(%[ks])\n\t"
        "stw     12, 12(%[ks])\n\t"
        "bdnz    L_AES_set_encrypt_key_loop_128_%=\n\t"
        "\n"
    "L_AES_set_encrypt_key_end_%=: \n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [key] "+r" (key), [len] "+r" (len), [ks] "+r" (ks),
          [L_AES_PPC64_te] "+r" (L_AES_PPC64_te_c),
          [L_AES_PPC64_rcon] "+r" (L_AES_PPC64_rcon_c)
        :
#else
        :
        : [key] "r" (key), [len] "r" (len), [ks] "r" (ks),
          [L_AES_PPC64_te] "r" (L_AES_PPC64_te_c),
          [L_AES_PPC64_rcon] "r" (L_AES_PPC64_rcon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "8", "9", "10", "11", "12", "14", "15"
    );
}

static const word32 L_AES_PPC64_te4_0[] = {
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
    0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
    0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
    0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
    0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87,
    0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
    0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea,
    0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
    0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a,
    0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
    0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108,
    0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
    0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e,
    0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
    0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d,
    0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
    0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e,
    0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
    0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce,
    0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
    0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c,
    0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
    0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b,
    0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
    0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16,
    0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
    0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81,
    0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
    0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a,
    0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
    0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163,
    0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
    0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f,
    0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
    0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47,
    0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
    0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f,
    0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
    0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c,
    0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
    0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e,
    0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
    0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6,
    0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
    0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7,
    0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
    0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25,
    0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
    0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72,
    0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
    0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21,
    0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
    0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa,
    0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
    0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0,
    0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
    0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133,
    0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
    0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920,
    0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
    0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17,
    0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
    0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11,
    0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a,
    0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b,
    0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5,
    0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b,
    0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676,
    0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d,
    0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0,
    0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf,
    0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0,
    0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626,
    0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc,
    0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1,
    0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515,
    0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3,
    0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a,
    0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2,
    0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575,
    0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a,
    0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0,
    0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3,
    0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484,
    0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded,
    0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b,
    0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939,
    0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf,
    0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb,
    0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585,
    0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f,
    0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8,
    0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f,
    0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5,
    0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121,
    0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2,
    0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec,
    0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717,
    0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d,
    0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373,
    0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc,
    0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888,
    0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414,
    0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb,
    0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a,
    0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c,
    0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262,
    0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979,
    0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d,
    0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9,
    0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea,
    0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808,
    0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e,
    0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6,
    0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f,
    0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a,
    0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666,
    0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e,
    0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9,
    0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e,
    0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111,
    0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494,
    0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9,
    0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf,
    0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d,
    0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868,
    0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f,
    0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616,
    0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b,
    0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5,
    0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b,
    0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76,
    0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d,
    0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0,
    0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af,
    0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0,
    0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26,
    0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc,
    0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1,
    0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15,
    0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3,
    0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a,
    0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2,
    0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75,
    0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a,
    0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0,
    0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3,
    0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384,
    0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed,
    0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b,
    0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239,
    0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf,
    0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb,
    0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185,
    0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f,
    0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8,
    0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f,
    0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5,
    0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221,
    0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2,
    0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec,
    0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17,
    0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d,
    0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673,
    0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc,
    0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88,
    0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814,
    0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb,
    0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a,
    0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c,
    0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462,
    0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279,
    0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d,
    0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9,
    0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea,
    0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008,
    0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e,
    0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6,
    0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f,
    0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a,
    0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66,
    0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e,
    0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9,
    0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e,
    0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211,
    0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394,
    0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9,
    0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df,
    0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d,
    0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068,
    0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f,
    0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16,
    0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6,
    0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491,
    0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56,
    0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec,
    0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa,
    0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb,
    0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45,
    0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b,
    0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c,
    0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83,
    0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9,
    0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a,
    0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d,
    0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f,
    0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf,
    0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea,
    0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34,
    0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b,
    0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d,
    0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713,
    0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1,
    0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6,
    0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72,
    0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85,
    0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed,
    0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411,
    0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe,
    0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b,
    0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05,
    0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1,
    0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342,
    0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf,
    0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3,
    0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e,
    0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a,
    0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6,
    0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3,
    0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b,
    0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28,
    0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad,
    0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14,
    0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8,
    0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4,
    0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2,
    0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da,
    0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049,
    0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf,
    0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810,
    0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c,
    0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197,
    0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e,
    0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f,
    0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc,
    0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c,
    0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069,
    0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927,
    0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322,
    0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733,
    0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9,
    0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5,
    0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a,
    0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0,
    0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e,
    0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c,
};

#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB)
void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_ECB_encrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p)
#else
void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register word32* L_AES_PPC64_te4_0_c asm ("8") =
        (word32*)&L_AES_PPC64_te4_0;
#else
    register word32* L_AES_PPC64_te4_0_c = (word32*)&L_AES_PPC64_te4_0;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      8, %[L_AES_PPC64_te4_0]\n\t"
        "addi    9, 8, 0x400\n\t"
        "addi    10, 8, 0x800\n\t"
        "addi    11, 8, 0xc00\n\t"
        "\n"
    "L_AES_ECB_encrypt_loop_block_128_%=: \n\t"
        "addi    25, %[ks], 0\n\t"
        "ld      12, 0(%[in])\n\t"
        "ld      14, 8(%[in])\n\t"
        "ld      17, 0(25)\n\t"
        "ld      18, 8(25)\n\t"
        "addi    25, 25, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     12, 12, 17\n\t"
        "xor     14, 14, 18\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_ECB_encrypt_loop_nr_%=: \n\t"
        "rldicl  17, 12, 40, 56\n\t"
        "rldicl  19, 12, 8, 56\n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    17, 8, 17\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  21, 12, 16, 56\n\t"
        "rldicl  22, 14, 48, 56\n\t"
        "rldicl  23, 14, 16, 56\n\t"
        "rldicl  24, 12, 48, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "rldicl  21, 14, 56, 56\n\t"
        "rldicl  22, 14, 24, 56\n\t"
        "rldicl  23, 12, 56, 56\n\t"
        "rldicl  24, 12, 24, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 10, 21\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "rldicl  21, 14, 32, 56\n\t"
        "rldic   22, 12, 2, 54\n\t"
        "rldicl  23, 12, 32, 56\n\t"
        "rldic   24, 14, 2, 54\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "lwzx    21, 11, 21\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "ld      12, 0(25)\n\t"
        "ld      14, 8(25)\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "addi    25, 25, 16\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     17, 17, 12\n\t"
        "xor     18, 18, 14\n\t"
        "rldicl  12, 17, 40, 56\n\t"
        "rldicl  15, 17, 8, 56\n\t"
        "rldicl  14, 18, 40, 56\n\t"
        "rldicl  16, 18, 8, 56\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    16, 16, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    12, 8, 12\n\t"
        "lwzx    15, 8, 15\n\t"
        "lwzx    14, 8, 14\n\t"
        "lwzx    16, 8, 16\n\t"
        "rldicl  21, 17, 16, 56\n\t"
        "rldicl  22, 18, 48, 56\n\t"
        "rldicl  23, 18, 16, 56\n\t"
        "rldicl  24, 17, 48, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "xor     12, 12, 21\n\t"
        "xor     15, 15, 22\n\t"
        "xor     14, 14, 23\n\t"
        "xor     16, 16, 24\n\t"
        "rldicl  21, 18, 56, 56\n\t"
        "rldicl  22, 18, 24, 56\n\t"
        "rldicl  23, 17, 56, 56\n\t"
        "rldicl  24, 17, 24, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 10, 21\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "xor     12, 12, 21\n\t"
        "xor     15, 15, 22\n\t"
        "xor     14, 14, 23\n\t"
        "xor     16, 16, 24\n\t"
        "rldicl  21, 18, 32, 56\n\t"
        "rldic   22, 17, 2, 54\n\t"
        "rldicl  23, 17, 32, 56\n\t"
        "rldic   24, 18, 2, 54\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "lwzx    21, 11, 21\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "xor     12, 12, 21\n\t"
        "xor     15, 15, 22\n\t"
        "xor     14, 14, 23\n\t"
        "xor     16, 16, 24\n\t"
        "ld      17, 0(25)\n\t"
        "ld      18, 8(25)\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "addi    25, 25, 16\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     12, 12, 17\n\t"
        "xor     14, 14, 18\n\t"
        "bdnz    L_AES_ECB_encrypt_loop_nr_%=\n\t"
        "rldicl  17, 12, 40, 56\n\t"
        "rldicl  19, 12, 8, 56\n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
        "ld      24, 0(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    17, 8, 17\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  21, 12, 16, 56\n\t"
        "rldicl  22, 14, 48, 56\n\t"
        "rldicl  23, 14, 16, 56\n\t"
        "rldicl  24, 12, 48, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "rldicl  21, 14, 56, 56\n\t"
        "rldicl  22, 14, 24, 56\n\t"
        "rldicl  23, 12, 56, 56\n\t"
        "rldicl  24, 12, 24, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 10, 21\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "rldicl  21, 14, 32, 56\n\t"
        "rldic   22, 12, 2, 54\n\t"
        "rldicl  23, 12, 32, 56\n\t"
        "rldic   24, 14, 2, 54\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "lwzx    21, 11, 21\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "xor     17, 17, 21\n\t"
        "xor     19, 19, 22\n\t"
        "xor     18, 18, 23\n\t"
        "xor     20, 20, 24\n\t"
        "ld      12, 0(25)\n\t"
        "ld      14, 8(25)\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "addi    25, 25, 16\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     17, 17, 12\n\t"
        "xor     18, 18, 14\n\t"
        "rldicl  12, 18, 32, 56\n\t"
        "rldic   15, 17, 2, 54\n\t"
        "rldicl  14, 17, 32, 56\n\t"
        "rldic   16, 18, 2, 54\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
        "ld      24, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    12, 9, 12\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    16, 9, 16\n\t"
        "rldicl  21, 18, 56, 56\n\t"
        "rldicl  22, 18, 24, 56\n\t"
        "rldicl  23, 17, 56, 56\n\t"
        "rldicl  24, 17, 24, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "rlwimi  12, 21, 8, 16, 23\n\t"
        "rlwimi  15, 22, 8, 16, 23\n\t"
        "rlwimi  14, 23, 8, 16, 23\n\t"
        "rlwimi  16, 24, 8, 16, 23\n\t"
        "rldicl  21, 17, 16, 56\n\t"
        "rldicl  22, 18, 48, 56\n\t"
        "rldicl  23, 18, 16, 56\n\t"
        "rldicl  24, 17, 48, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "rlwimi  12, 21, 16, 8, 15\n\t"
        "rlwimi  15, 22, 16, 8, 15\n\t"
        "rlwimi  14, 23, 16, 8, 15\n\t"
        "rlwimi  16, 24, 16, 8, 15\n\t"
        "rldicl  21, 17, 40, 56\n\t"
        "rldicl  22, 17, 8, 56\n\t"
        "rldicl  23, 18, 40, 56\n\t"
        "rldicl  24, 18, 8, 56\n\t"
        "slwi    21, 21, 2\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    21, 9, 21\n\t"
        "lwzx    22, 9, 22\n\t"
        "lwzx    23, 9, 23\n\t"
        "lwzx    24, 9, 24\n\t"
        "rlwimi  12, 21, 24, 0, 7\n\t"
        "rlwimi  15, 22, 24, 0, 7\n\t"
        "rlwimi  14, 23, 24, 0, 7\n\t"
        "rlwimi  16, 24, 24, 0, 7\n\t"
        "ld      17, 0(25)\n\t"
        "ld      18, 8(25)\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "addi    25, 25, 16\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     12, 12, 17\n\t"
        "xor     14, 14, 18\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "std     12, 0(%[out])\n\t"
        "std     14, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_ECB_encrypt_loop_block_128_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [L_AES_PPC64_te4_0] "+r" (L_AES_PPC64_te4_0_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [L_AES_PPC64_te4_0] "r" (L_AES_PPC64_te4_0_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "9", "10", "11", "12", "14", "15", "16", "17",
            "18", "19", "20", "21", "22", "23", "24", "25"
    );
}

#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER || HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CBC_encrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p,
    unsigned char* iv_p)
#else
void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register unsigned char* iv asm ("8") = (unsigned char*)iv_p;
    register word32* L_AES_PPC64_te4_0_c asm ("9") =
        (word32*)&L_AES_PPC64_te4_0;
#else
    register word32* L_AES_PPC64_te4_0_c = (word32*)&L_AES_PPC64_te4_0;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      9, %[L_AES_PPC64_te4_0]\n\t"
        "ld      14, 0(%[iv])\n\t"
        "ld      15, 8(%[iv])\n\t"
        "addi    10, 9, 0x400\n\t"
        "addi    11, 9, 0x800\n\t"
        "addi    12, 9, 0xc00\n\t"
        "\n"
    "L_AES_CBC_encrypt_loop_block_%=: \n\t"
        "addi    26, %[ks], 0\n\t"
        "ld      18, 0(%[in])\n\t"
        "ld      19, 8(%[in])\n\t"
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "ld      18, 0(26)\n\t"
        "ld      19, 8(26)\n\t"
        "addi    26, 26, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_CBC_encrypt_loop_nr_%=: \n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  22, 14, 16, 56\n\t"
        "rldicl  23, 15, 48, 56\n\t"
        "rldicl  24, 15, 16, 56\n\t"
        "rldicl  25, 14, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 56, 56\n\t"
        "rldicl  23, 15, 24, 56\n\t"
        "rldicl  24, 14, 56, 56\n\t"
        "rldicl  25, 14, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 32, 56\n\t"
        "rldic   23, 14, 2, 54\n\t"
        "rldicl  24, 14, 32, 56\n\t"
        "rldic   25, 15, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "ld      14, 0(26)\n\t"
        "ld      15, 8(26)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    26, 26, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 18, 40, 56\n\t"
        "rldicl  16, 18, 8, 56\n\t"
        "rldicl  15, 19, 40, 56\n\t"
        "rldicl  17, 19, 8, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    16, 16, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    17, 17, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 9, 14\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    17, 9, 17\n\t"
        "rldicl  22, 18, 16, 56\n\t"
        "rldicl  23, 19, 48, 56\n\t"
        "rldicl  24, 19, 16, 56\n\t"
        "rldicl  25, 18, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "rldicl  22, 19, 56, 56\n\t"
        "rldicl  23, 19, 24, 56\n\t"
        "rldicl  24, 18, 56, 56\n\t"
        "rldicl  25, 18, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "rldicl  22, 19, 32, 56\n\t"
        "rldic   23, 18, 2, 54\n\t"
        "rldicl  24, 18, 32, 56\n\t"
        "rldic   25, 19, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "ld      18, 0(26)\n\t"
        "ld      19, 8(26)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    26, 26, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "bdnz    L_AES_CBC_encrypt_loop_nr_%=\n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  22, 14, 16, 56\n\t"
        "rldicl  23, 15, 48, 56\n\t"
        "rldicl  24, 15, 16, 56\n\t"
        "rldicl  25, 14, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 56, 56\n\t"
        "rldicl  23, 15, 24, 56\n\t"
        "rldicl  24, 14, 56, 56\n\t"
        "rldicl  25, 14, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 32, 56\n\t"
        "rldic   23, 14, 2, 54\n\t"
        "rldicl  24, 14, 32, 56\n\t"
        "rldic   25, 15, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "ld      14, 0(26)\n\t"
        "ld      15, 8(26)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    26, 26, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 19, 32, 56\n\t"
        "rldic   16, 18, 2, 54\n\t"
        "rldicl  15, 18, 32, 56\n\t"
        "rldic   17, 19, 2, 54\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 10, 14\n\t"
        "lwzx    16, 10, 16\n\t"
        "lwzx    15, 10, 15\n\t"
        "lwzx    17, 10, 17\n\t"
        "rldicl  22, 19, 56, 56\n\t"
        "rldicl  23, 19, 24, 56\n\t"
        "rldicl  24, 18, 56, 56\n\t"
        "rldicl  25, 18, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 8, 16, 23\n\t"
        "rlwimi  16, 23, 8, 16, 23\n\t"
        "rlwimi  15, 24, 8, 16, 23\n\t"
        "rlwimi  17, 25, 8, 16, 23\n\t"
        "rldicl  22, 18, 16, 56\n\t"
        "rldicl  23, 19, 48, 56\n\t"
        "rldicl  24, 19, 16, 56\n\t"
        "rldicl  25, 18, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 16, 8, 15\n\t"
        "rlwimi  16, 23, 16, 8, 15\n\t"
        "rlwimi  15, 24, 16, 8, 15\n\t"
        "rlwimi  17, 25, 16, 8, 15\n\t"
        "rldicl  22, 18, 40, 56\n\t"
        "rldicl  23, 18, 8, 56\n\t"
        "rldicl  24, 19, 40, 56\n\t"
        "rldicl  25, 19, 8, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 24, 0, 7\n\t"
        "rlwimi  16, 23, 24, 0, 7\n\t"
        "rlwimi  15, 24, 24, 0, 7\n\t"
        "rlwimi  17, 25, 24, 0, 7\n\t"
        "ld      18, 0(26)\n\t"
        "ld      19, 8(26)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    26, 26, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "std     14, 0(%[out])\n\t"
        "std     15, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_CBC_encrypt_loop_block_%=\n\t"
        "std     14, 0(%[iv])\n\t"
        "std     15, 8(%[iv])\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [iv] "+r" (iv),
          [L_AES_PPC64_te4_0] "+r" (L_AES_PPC64_te4_0_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [iv] "r" (iv),
          [L_AES_PPC64_te4_0] "r" (L_AES_PPC64_te4_0_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "10", "11", "12", "14", "15", "16", "17", "18",
            "19", "20", "21", "22", "23", "24", "25", "26"
    );
}

#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
void AES_CTR_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CTR_encrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p,
    unsigned char* ctr_p)
#else
void AES_CTR_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register unsigned char* ctr asm ("8") = (unsigned char*)ctr_p;
    register word32* L_AES_PPC64_te4_0_c asm ("9") =
        (word32*)&L_AES_PPC64_te4_0;
#else
    register word32* L_AES_PPC64_te4_0_c = (word32*)&L_AES_PPC64_te4_0;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      9, %[L_AES_PPC64_te4_0]\n\t"
        "ld      22, 0(%[ctr])\n\t"
        "ld      23, 8(%[ctr])\n\t"
        "addi    10, 9, 0x400\n\t"
        "addi    11, 9, 0x800\n\t"
        "addi    12, 9, 0xc00\n\t"
        "\n"
    "L_AES_CTR_encrypt_loop_block_128_%=: \n\t"
        "addi    28, %[ks], 0\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "addi    28, 28, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     14, 22, 18\n\t"
        "xor     15, 23, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_CTR_encrypt_loop_nr_%=: \n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  24, 14, 16, 56\n\t"
        "rldicl  25, 15, 48, 56\n\t"
        "rldicl  26, 15, 16, 56\n\t"
        "rldicl  27, 14, 48, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "rldicl  24, 15, 56, 56\n\t"
        "rldicl  25, 15, 24, 56\n\t"
        "rldicl  26, 14, 56, 56\n\t"
        "rldicl  27, 14, 24, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "lwzx    26, 11, 26\n\t"
        "lwzx    27, 11, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "rldicl  24, 15, 32, 56\n\t"
        "rldic   25, 14, 2, 54\n\t"
        "rldicl  26, 14, 32, 56\n\t"
        "rldic   27, 15, 2, 54\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "lwzx    26, 12, 26\n\t"
        "lwzx    27, 12, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "ld      14, 0(28)\n\t"
        "ld      15, 8(28)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 18, 40, 56\n\t"
        "rldicl  16, 18, 8, 56\n\t"
        "rldicl  15, 19, 40, 56\n\t"
        "rldicl  17, 19, 8, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    16, 16, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    17, 17, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 9, 14\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    17, 9, 17\n\t"
        "rldicl  24, 18, 16, 56\n\t"
        "rldicl  25, 19, 48, 56\n\t"
        "rldicl  26, 19, 16, 56\n\t"
        "rldicl  27, 18, 48, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "xor     14, 14, 24\n\t"
        "xor     16, 16, 25\n\t"
        "xor     15, 15, 26\n\t"
        "xor     17, 17, 27\n\t"
        "rldicl  24, 19, 56, 56\n\t"
        "rldicl  25, 19, 24, 56\n\t"
        "rldicl  26, 18, 56, 56\n\t"
        "rldicl  27, 18, 24, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "lwzx    26, 11, 26\n\t"
        "lwzx    27, 11, 27\n\t"
        "xor     14, 14, 24\n\t"
        "xor     16, 16, 25\n\t"
        "xor     15, 15, 26\n\t"
        "xor     17, 17, 27\n\t"
        "rldicl  24, 19, 32, 56\n\t"
        "rldic   25, 18, 2, 54\n\t"
        "rldicl  26, 18, 32, 56\n\t"
        "rldic   27, 19, 2, 54\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "lwzx    26, 12, 26\n\t"
        "lwzx    27, 12, 27\n\t"
        "xor     14, 14, 24\n\t"
        "xor     16, 16, 25\n\t"
        "xor     15, 15, 26\n\t"
        "xor     17, 17, 27\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "bdnz    L_AES_CTR_encrypt_loop_nr_%=\n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
        "ld      27, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  24, 14, 16, 56\n\t"
        "rldicl  25, 15, 48, 56\n\t"
        "rldicl  26, 15, 16, 56\n\t"
        "rldicl  27, 14, 48, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "rldicl  24, 15, 56, 56\n\t"
        "rldicl  25, 15, 24, 56\n\t"
        "rldicl  26, 14, 56, 56\n\t"
        "rldicl  27, 14, 24, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "lwzx    26, 11, 26\n\t"
        "lwzx    27, 11, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "rldicl  24, 15, 32, 56\n\t"
        "rldic   25, 14, 2, 54\n\t"
        "rldicl  26, 14, 32, 56\n\t"
        "rldic   27, 15, 2, 54\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "lwzx    26, 12, 26\n\t"
        "lwzx    27, 12, 27\n\t"
        "xor     18, 18, 24\n\t"
        "xor     20, 20, 25\n\t"
        "xor     19, 19, 26\n\t"
        "xor     21, 21, 27\n\t"
        "ld      14, 0(28)\n\t"
        "ld      15, 8(28)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 19, 32, 56\n\t"
        "rldic   16, 18, 2, 54\n\t"
        "rldicl  15, 18, 32, 56\n\t"
        "rldic   17, 19, 2, 54\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
        "ld      27, 0(10)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 10, 14\n\t"
        "lwzx    16, 10, 16\n\t"
        "lwzx    15, 10, 15\n\t"
        "lwzx    17, 10, 17\n\t"
        "rldicl  24, 19, 56, 56\n\t"
        "rldicl  25, 19, 24, 56\n\t"
        "rldicl  26, 18, 56, 56\n\t"
        "rldicl  27, 18, 24, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "rlwimi  14, 24, 8, 16, 23\n\t"
        "rlwimi  16, 25, 8, 16, 23\n\t"
        "rlwimi  15, 26, 8, 16, 23\n\t"
        "rlwimi  17, 27, 8, 16, 23\n\t"
        "rldicl  24, 18, 16, 56\n\t"
        "rldicl  25, 19, 48, 56\n\t"
        "rldicl  26, 19, 16, 56\n\t"
        "rldicl  27, 18, 48, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "rlwimi  14, 24, 16, 8, 15\n\t"
        "rlwimi  16, 25, 16, 8, 15\n\t"
        "rlwimi  15, 26, 16, 8, 15\n\t"
        "rlwimi  17, 27, 16, 8, 15\n\t"
        "rldicl  24, 18, 40, 56\n\t"
        "rldicl  25, 18, 8, 56\n\t"
        "rldicl  26, 19, 40, 56\n\t"
        "rldicl  27, 19, 8, 56\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "slwi    26, 26, 2\n\t"
        "slwi    27, 27, 2\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "lwzx    26, 10, 26\n\t"
        "lwzx    27, 10, 27\n\t"
        "rlwimi  14, 24, 24, 0, 7\n\t"
        "rlwimi  16, 25, 24, 0, 7\n\t"
        "rlwimi  15, 26, 24, 0, 7\n\t"
        "rlwimi  17, 27, 24, 0, 7\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "ld      18, 0(%[in])\n\t"
        "ld      19, 8(%[in])\n\t"
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "std     14, 0(%[out])\n\t"
        "std     15, 8(%[out])\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "addic   23, 23, 1\n\t"
        "addze   22, 22\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_CTR_encrypt_loop_block_128_%=\n\t"
        "std     22, 0(%[ctr])\n\t"
        "std     23, 8(%[ctr])\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [ctr] "+r" (ctr),
          [L_AES_PPC64_te4_0] "+r" (L_AES_PPC64_te4_0_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [ctr] "r" (ctr),
          [L_AES_PPC64_te4_0] "r" (L_AES_PPC64_te4_0_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "10", "11", "12", "14", "15", "16", "17", "18",
            "19", "20", "21", "22", "23", "24", "25", "26", "27", "28"
    );
}

#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESGCM
void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_GCM_encrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p,
    unsigned char* ctr_p)
#else
void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register unsigned char* ctr asm ("8") = (unsigned char*)ctr_p;
    register word32* L_AES_PPC64_te4_0_c asm ("9") =
        (word32*)&L_AES_PPC64_te4_0;
#else
    register word32* L_AES_PPC64_te4_0_c = (word32*)&L_AES_PPC64_te4_0;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      9, %[L_AES_PPC64_te4_0]\n\t"
        "ld      26, 0(%[ctr])\n\t"
        "ld      27, 8(%[ctr])\n\t"
        "addi    10, 9, 0x400\n\t"
        "addi    11, 9, 0x800\n\t"
        "addi    12, 9, 0xc00\n\t"
        "\n"
    "L_AES_GCM_encrypt_loop_block_%=: \n\t"
        "addi    28, %[ks], 0\n\t"
        "addi    17, 27, 1\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "addi    28, 28, 16\n\t"
        "rldimi  27, 17, 0, 32\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     14, 26, 18\n\t"
        "xor     15, 27, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_GCM_encrypt_loop_nr_%=: \n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  22, 14, 16, 56\n\t"
        "rldicl  23, 15, 48, 56\n\t"
        "rldicl  24, 15, 16, 56\n\t"
        "rldicl  25, 14, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 56, 56\n\t"
        "rldicl  23, 15, 24, 56\n\t"
        "rldicl  24, 14, 56, 56\n\t"
        "rldicl  25, 14, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 32, 56\n\t"
        "rldic   23, 14, 2, 54\n\t"
        "rldicl  24, 14, 32, 56\n\t"
        "rldic   25, 15, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "ld      14, 0(28)\n\t"
        "ld      15, 8(28)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 18, 40, 56\n\t"
        "rldicl  16, 18, 8, 56\n\t"
        "rldicl  15, 19, 40, 56\n\t"
        "rldicl  17, 19, 8, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    16, 16, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    17, 17, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 9, 14\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    17, 9, 17\n\t"
        "rldicl  22, 18, 16, 56\n\t"
        "rldicl  23, 19, 48, 56\n\t"
        "rldicl  24, 19, 16, 56\n\t"
        "rldicl  25, 18, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "rldicl  22, 19, 56, 56\n\t"
        "rldicl  23, 19, 24, 56\n\t"
        "rldicl  24, 18, 56, 56\n\t"
        "rldicl  25, 18, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "rldicl  22, 19, 32, 56\n\t"
        "rldic   23, 18, 2, 54\n\t"
        "rldicl  24, 18, 32, 56\n\t"
        "rldic   25, 19, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     14, 14, 22\n\t"
        "xor     16, 16, 23\n\t"
        "xor     15, 15, 24\n\t"
        "xor     17, 17, 25\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "bdnz    L_AES_GCM_encrypt_loop_nr_%=\n\t"
        "rldicl  18, 14, 40, 56\n\t"
        "rldicl  20, 14, 8, 56\n\t"
        "rldicl  19, 15, 40, 56\n\t"
        "rldicl  21, 15, 8, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
        "ld      25, 0(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  22, 14, 16, 56\n\t"
        "rldicl  23, 15, 48, 56\n\t"
        "rldicl  24, 15, 16, 56\n\t"
        "rldicl  25, 14, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 56, 56\n\t"
        "rldicl  23, 15, 24, 56\n\t"
        "rldicl  24, 14, 56, 56\n\t"
        "rldicl  25, 14, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 11, 22\n\t"
        "lwzx    23, 11, 23\n\t"
        "lwzx    24, 11, 24\n\t"
        "lwzx    25, 11, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "rldicl  22, 15, 32, 56\n\t"
        "rldic   23, 14, 2, 54\n\t"
        "rldicl  24, 14, 32, 56\n\t"
        "rldic   25, 15, 2, 54\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "lwzx    22, 12, 22\n\t"
        "lwzx    23, 12, 23\n\t"
        "lwzx    24, 12, 24\n\t"
        "lwzx    25, 12, 25\n\t"
        "xor     18, 18, 22\n\t"
        "xor     20, 20, 23\n\t"
        "xor     19, 19, 24\n\t"
        "xor     21, 21, 25\n\t"
        "ld      14, 0(28)\n\t"
        "ld      15, 8(28)\n\t"
        "rldimi  18, 20, 32, 0\n\t"
        "rldimi  19, 21, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     18, 18, 14\n\t"
        "xor     19, 19, 15\n\t"
        "rldicl  14, 19, 32, 56\n\t"
        "rldic   16, 18, 2, 54\n\t"
        "rldicl  15, 18, 32, 56\n\t"
        "rldic   17, 19, 2, 54\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
        "ld      25, 0(10)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lwzx    14, 10, 14\n\t"
        "lwzx    16, 10, 16\n\t"
        "lwzx    15, 10, 15\n\t"
        "lwzx    17, 10, 17\n\t"
        "rldicl  22, 19, 56, 56\n\t"
        "rldicl  23, 19, 24, 56\n\t"
        "rldicl  24, 18, 56, 56\n\t"
        "rldicl  25, 18, 24, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 8, 16, 23\n\t"
        "rlwimi  16, 23, 8, 16, 23\n\t"
        "rlwimi  15, 24, 8, 16, 23\n\t"
        "rlwimi  17, 25, 8, 16, 23\n\t"
        "rldicl  22, 18, 16, 56\n\t"
        "rldicl  23, 19, 48, 56\n\t"
        "rldicl  24, 19, 16, 56\n\t"
        "rldicl  25, 18, 48, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 16, 8, 15\n\t"
        "rlwimi  16, 23, 16, 8, 15\n\t"
        "rlwimi  15, 24, 16, 8, 15\n\t"
        "rlwimi  17, 25, 16, 8, 15\n\t"
        "rldicl  22, 18, 40, 56\n\t"
        "rldicl  23, 18, 8, 56\n\t"
        "rldicl  24, 19, 40, 56\n\t"
        "rldicl  25, 19, 8, 56\n\t"
        "slwi    22, 22, 2\n\t"
        "slwi    23, 23, 2\n\t"
        "slwi    24, 24, 2\n\t"
        "slwi    25, 25, 2\n\t"
        "lwzx    22, 10, 22\n\t"
        "lwzx    23, 10, 23\n\t"
        "lwzx    24, 10, 24\n\t"
        "lwzx    25, 10, 25\n\t"
        "rlwimi  14, 22, 24, 0, 7\n\t"
        "rlwimi  16, 23, 24, 0, 7\n\t"
        "rlwimi  15, 24, 24, 0, 7\n\t"
        "rlwimi  17, 25, 24, 0, 7\n\t"
        "ld      18, 0(28)\n\t"
        "ld      19, 8(28)\n\t"
        "rldimi  14, 16, 32, 0\n\t"
        "rldimi  15, 17, 32, 0\n\t"
        "addi    28, 28, 16\n\t"
        "rldicr  18, 18, 32, 63\n\t"
        "rldicr  19, 19, 32, 63\n\t"
        /*   XOR in Key Schedule */
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "rldicr  14, 14, 32, 63\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "ld      18, 0(%[in])\n\t"
        "ld      19, 8(%[in])\n\t"
        "xor     14, 14, 18\n\t"
        "xor     15, 15, 19\n\t"
        "std     14, 0(%[out])\n\t"
        "std     15, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_GCM_encrypt_loop_block_%=\n\t"
        "std     26, 0(%[ctr])\n\t"
        "std     27, 8(%[ctr])\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [ctr] "+r" (ctr),
          [L_AES_PPC64_te4_0] "+r" (L_AES_PPC64_te4_0_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [ctr] "r" (ctr),
          [L_AES_PPC64_te4_0] "r" (L_AES_PPC64_te4_0_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "10", "11", "12", "14", "15", "16", "17", "18",
            "19", "20", "21", "22", "23", "24", "25", "26", "27", "28"
    );
}

#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_XTS
#endif /* WOLFSSL_AES_XTS */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AES_ECB)
static const byte L_AES_PPC64_td4[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
        defined(HAVE_AES_ECB)
void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_ECB_decrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p)
#else
void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register word32* L_AES_PPC64_td_c asm ("8") = (word32*)&L_AES_PPC64_td;
    register byte* L_AES_PPC64_td4_c asm ("9") = (byte*)&L_AES_PPC64_td4;
#else
    register word32* L_AES_PPC64_td_c = (word32*)&L_AES_PPC64_td;

    register byte* L_AES_PPC64_td4_c = (byte*)&L_AES_PPC64_td4;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      8, %[L_AES_PPC64_td]\n\t"
        "mr      9, %[L_AES_PPC64_td4]\n\t"
        "\n"
    "L_AES_ECB_decrypt_loop_block_%=: \n\t"
        "addi    21, %[ks], 0\n\t"
        "ld      10, 0(%[in])\n\t"
        "ld      11, 8(%[in])\n\t"
        "ld      15, 0(21)\n\t"
        "ld      16, 8(21)\n\t"
        "addi    21, 21, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     10, 10, 15\n\t"
        "xor     11, 11, 16\n\t"
        "rldicr  10, 10, 32, 63\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_ECB_decrypt_loop_nr_%=: \n\t"
        "rldicl  15, 11, 16, 56\n\t"
        "rldicl  18, 10, 40, 56\n\t"
        "rldicl  19, 11, 56, 56\n\t"
        "rldicl  20, 10, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      12, 0(8)\n\t"
        "ld      12, 64(8)\n\t"
        "ld      12, 128(8)\n\t"
        "ld      12, 192(8)\n\t"
        "ld      12, 256(8)\n\t"
        "ld      12, 320(8)\n\t"
        "ld      12, 384(8)\n\t"
        "ld      12, 448(8)\n\t"
        "ld      12, 512(8)\n\t"
        "ld      12, 576(8)\n\t"
        "ld      12, 640(8)\n\t"
        "ld      12, 704(8)\n\t"
        "ld      12, 768(8)\n\t"
        "ld      12, 832(8)\n\t"
        "ld      12, 896(8)\n\t"
        "ld      12, 960(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    15, 15, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    15, 8, 15\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  16, 10, 48, 56\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     15, 15, 18\n\t"
        "rldicl  18, 10, 8, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     15, 15, 19\n\t"
        "rldicl  19, 11, 24, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     15, 15, 20\n\t"
        "andi.   20, 11, 255\n\t"
        "slwi    16, 16, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    16, 8, 16\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  17, 10, 16, 56\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     16, 16, 18\n\t"
        "rldicl  18, 11, 40, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 10, 56, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 11, 32, 56\n\t"
        "rldimi  15, 16, 32, 0\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    17, 8, 17\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "andi.   12, 10, 255\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     17, 17, 18\n\t"
        "rldicl  18, 11, 48, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     16, 17, 20\n\t"
        "rldicl  20, 10, 24, 56\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    12, 8, 12\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    20, 8, 20\n\t"
        "rlwimi  12, 12, 8, 0, 31\n\t"
        "xor     19, 19, 12\n\t"
        "ld      10, 0(21)\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "rldicr  10, 10, 32, 63\n\t"
        "xor     18, 18, 20\n\t"
        "ld      11, 8(21)\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     18, 18, 19\n\t"
        "addi    21, 21, 16\n\t"
        "rldimi  16, 18, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     15, 15, 10\n\t"
        "xor     16, 16, 11\n\t"
        "rldicl  10, 16, 16, 56\n\t"
        "rldicl  14, 15, 40, 56\n\t"
        "rldicl  19, 16, 56, 56\n\t"
        "rldicl  20, 15, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      17, 0(8)\n\t"
        "ld      17, 64(8)\n\t"
        "ld      17, 128(8)\n\t"
        "ld      17, 192(8)\n\t"
        "ld      17, 256(8)\n\t"
        "ld      17, 320(8)\n\t"
        "ld      17, 384(8)\n\t"
        "ld      17, 448(8)\n\t"
        "ld      17, 512(8)\n\t"
        "ld      17, 576(8)\n\t"
        "ld      17, 640(8)\n\t"
        "ld      17, 704(8)\n\t"
        "ld      17, 768(8)\n\t"
        "ld      17, 832(8)\n\t"
        "ld      17, 896(8)\n\t"
        "ld      17, 960(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    10, 10, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    10, 8, 10\n\t"
        "lwzx    14, 8, 14\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  11, 15, 48, 56\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     10, 10, 14\n\t"
        "rldicl  14, 15, 8, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     10, 10, 19\n\t"
        "rldicl  19, 16, 24, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     10, 10, 20\n\t"
        "andi.   20, 16, 255\n\t"
        "slwi    11, 11, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    11, 8, 11\n\t"
        "lwzx    14, 8, 14\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  12, 15, 16, 56\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     11, 11, 14\n\t"
        "rldicl  14, 16, 40, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     11, 11, 19\n\t"
        "rldicl  19, 15, 56, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     11, 11, 20\n\t"
        "rldicl  20, 16, 32, 56\n\t"
        "rldimi  10, 11, 32, 0\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    12, 8, 12\n\t"
        "lwzx    14, 8, 14\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "andi.   17, 15, 255\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     12, 12, 14\n\t"
        "rldicl  14, 16, 48, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     12, 12, 19\n\t"
        "rldicl  19, 16, 8, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     11, 12, 20\n\t"
        "rldicl  20, 15, 24, 56\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    17, 8, 17\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    14, 8, 14\n\t"
        "lwzx    20, 8, 20\n\t"
        "rlwimi  17, 17, 8, 0, 31\n\t"
        "xor     19, 19, 17\n\t"
        "ld      15, 0(21)\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "xor     14, 14, 20\n\t"
        "ld      16, 8(21)\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "xor     14, 14, 19\n\t"
        "addi    21, 21, 16\n\t"
        "rldimi  11, 14, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     10, 10, 15\n\t"
        "xor     11, 11, 16\n\t"
        "bdnz    L_AES_ECB_decrypt_loop_nr_%=\n\t"
        "rldicl  15, 11, 16, 56\n\t"
        "rldicl  18, 10, 40, 56\n\t"
        "rldicl  19, 11, 56, 56\n\t"
        "rldicl  20, 10, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      12, 0(8)\n\t"
        "ld      12, 64(8)\n\t"
        "ld      12, 128(8)\n\t"
        "ld      12, 192(8)\n\t"
        "ld      12, 256(8)\n\t"
        "ld      12, 320(8)\n\t"
        "ld      12, 384(8)\n\t"
        "ld      12, 448(8)\n\t"
        "ld      12, 512(8)\n\t"
        "ld      12, 576(8)\n\t"
        "ld      12, 640(8)\n\t"
        "ld      12, 704(8)\n\t"
        "ld      12, 768(8)\n\t"
        "ld      12, 832(8)\n\t"
        "ld      12, 896(8)\n\t"
        "ld      12, 960(8)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    15, 15, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    15, 8, 15\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  16, 10, 48, 56\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     15, 15, 18\n\t"
        "rldicl  18, 10, 8, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     15, 15, 19\n\t"
        "rldicl  19, 11, 24, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     15, 15, 20\n\t"
        "andi.   20, 11, 255\n\t"
        "slwi    16, 16, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    16, 8, 16\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "rldicl  17, 10, 16, 56\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     16, 16, 18\n\t"
        "rldicl  18, 11, 40, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 10, 56, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 11, 32, 56\n\t"
        "rldimi  15, 16, 32, 0\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    17, 8, 17\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    20, 8, 20\n\t"
        "andi.   12, 10, 255\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     17, 17, 18\n\t"
        "rldicl  18, 11, 48, 56\n\t"
        "rlwimi  19, 19, 24, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 16, 0, 31\n\t"
        "xor     16, 17, 20\n\t"
        "rldicl  20, 10, 24, 56\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "lwzx    12, 8, 12\n\t"
        "lwzx    19, 8, 19\n\t"
        "lwzx    18, 8, 18\n\t"
        "lwzx    20, 8, 20\n\t"
        "rlwimi  12, 12, 8, 0, 31\n\t"
        "xor     19, 19, 12\n\t"
        "ld      10, 0(21)\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "rldicr  10, 10, 32, 63\n\t"
        "xor     18, 18, 20\n\t"
        "ld      11, 8(21)\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     18, 18, 19\n\t"
        "addi    21, 21, 16\n\t"
        "rldimi  16, 18, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     15, 15, 10\n\t"
        "xor     16, 16, 11\n\t"
        "rldicl  10, 15, 32, 56\n\t"
        "rldicl  14, 16, 56, 56\n\t"
        "rldicl  19, 16, 16, 56\n\t"
        "rldicl  20, 15, 40, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      18, 0(9)\n\t"
        "ld      18, 64(9)\n\t"
        "ld      18, 128(9)\n\t"
        "ld      18, 192(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lbzx    10, 9, 10\n\t"
        "lbzx    14, 9, 14\n\t"
        "lbzx    19, 9, 19\n\t"
        "lbzx    20, 9, 20\n\t"
        "andi.   11, 16, 255\n\t"
        "rlwimi  10, 14, 8, 16, 23\n\t"
        "rldicl  14, 16, 24, 56\n\t"
        "rlwimi  10, 19, 16, 8, 15\n\t"
        "rldicl  19, 15, 48, 56\n\t"
        "rlwimi  10, 20, 24, 0, 7\n\t"
        "rldicl  20, 15, 8, 56\n\t"
        "lbzx    14, 9, 14\n\t"
        "lbzx    20, 9, 20\n\t"
        "lbzx    11, 9, 11\n\t"
        "lbzx    19, 9, 19\n\t"
        "rldicl  12, 16, 32, 56\n\t"
        "rlwimi  11, 14, 8, 16, 23\n\t"
        "rldicl  14, 15, 56, 56\n\t"
        "rlwimi  11, 19, 16, 8, 15\n\t"
        "rldicl  19, 15, 16, 56\n\t"
        "rlwimi  11, 20, 24, 0, 7\n\t"
        "rldicl  20, 16, 40, 56\n\t"
        "rldimi  10, 11, 32, 0\n\t"
        "lbzx    14, 9, 14\n\t"
        "lbzx    19, 9, 19\n\t"
        "lbzx    11, 9, 12\n\t"
        "lbzx    20, 9, 20\n\t"
        "rldicl  18, 16, 8, 56\n\t"
        "rlwimi  11, 14, 8, 16, 23\n\t"
        "andi.   14, 15, 255\n\t"
        "rlwimi  11, 19, 16, 8, 15\n\t"
        "rldicl  19, 15, 24, 56\n\t"
        "rlwimi  11, 20, 24, 0, 7\n\t"
        "rldicl  20, 16, 48, 56\n\t"
        "lbzx    18, 9, 18\n\t"
        "lbzx    19, 9, 19\n\t"
        "lbzx    14, 9, 14\n\t"
        "lbzx    20, 9, 20\n\t"
        "ld      15, 0(21)\n\t"
        "rlwimi  14, 18, 24, 0, 7\n\t"
        "rldicr  15, 15, 32, 63\n\t"
        "rlwimi  14, 20, 16, 8, 15\n\t"
        "ld      16, 8(21)\n\t"
        "rlwimi  14, 19, 8, 16, 23\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "rldimi  11, 14, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     10, 10, 15\n\t"
        "xor     11, 11, 16\n\t"
        "rldicr  10, 10, 32, 63\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "std     10, 0(%[out])\n\t"
        "std     11, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_ECB_decrypt_loop_block_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [L_AES_PPC64_td] "+r" (L_AES_PPC64_td_c),
          [L_AES_PPC64_td4] "+r" (L_AES_PPC64_td4_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [L_AES_PPC64_td] "r" (L_AES_PPC64_td_c),
          [L_AES_PPC64_td4] "r" (L_AES_PPC64_td4_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "10", "11", "12", "14", "15", "16", "17", "18",
            "19", "20", "21"
    );
}

#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || defined(HAVE_AES_ECB) */
#ifdef HAVE_AES_CBC
void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CBC_decrypt(const unsigned char* in_p, unsigned char* out_p,
    unsigned long len_p, const unsigned char* ks_p, int nr_p,
    unsigned char* iv_p)
#else
void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in asm ("3") = (const unsigned char*)in_p;
    register unsigned char* out asm ("4") = (unsigned char*)out_p;
    register unsigned long len asm ("5") = (unsigned long)len_p;
    register const unsigned char* ks asm ("6") = (const unsigned char*)ks_p;
    register int nr asm ("7") = (int)nr_p;
    register unsigned char* iv asm ("8") = (unsigned char*)iv_p;
    register word32* L_AES_PPC64_td_c asm ("9") = (word32*)&L_AES_PPC64_td;
    register byte* L_AES_PPC64_td4_c asm ("10") = (byte*)&L_AES_PPC64_td4;
#else
    register word32* L_AES_PPC64_td_c = (word32*)&L_AES_PPC64_td;

    register byte* L_AES_PPC64_td4_c = (byte*)&L_AES_PPC64_td4;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      10, %[L_AES_PPC64_td4]\n\t"
        "mr      9, %[L_AES_PPC64_td]\n\t"
        "\n"
    "L_AES_CBC_decrypt_loop_block_%=: \n\t"
        "addi    22, %[ks], 0\n\t"
        "ld      11, 0(%[in])\n\t"
        "ld      12, 8(%[in])\n\t"
        "std     11, 16(%[iv])\n\t"
        "std     12, 24(%[iv])\n\t"
        "ld      16, 0(22)\n\t"
        "ld      17, 8(22)\n\t"
        "addi    22, 22, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_CBC_decrypt_loop_nr_even_%=: \n\t"
        "rldicl  16, 12, 16, 56\n\t"
        "rldicl  19, 11, 40, 56\n\t"
        "rldicl  20, 12, 56, 56\n\t"
        "rldicl  21, 11, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      14, 0(9)\n\t"
        "ld      14, 64(9)\n\t"
        "ld      14, 128(9)\n\t"
        "ld      14, 192(9)\n\t"
        "ld      14, 256(9)\n\t"
        "ld      14, 320(9)\n\t"
        "ld      14, 384(9)\n\t"
        "ld      14, 448(9)\n\t"
        "ld      14, 512(9)\n\t"
        "ld      14, 576(9)\n\t"
        "ld      14, 640(9)\n\t"
        "ld      14, 704(9)\n\t"
        "ld      14, 768(9)\n\t"
        "ld      14, 832(9)\n\t"
        "ld      14, 896(9)\n\t"
        "ld      14, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    16, 16, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  17, 11, 48, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 12, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     16, 16, 21\n\t"
        "andi.   21, 12, 255\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    17, 9, 17\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  18, 11, 16, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 12, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     17, 17, 20\n\t"
        "rldicl  20, 11, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 17, 21\n\t"
        "rldicl  21, 12, 32, 56\n\t"
        "rldimi  16, 17, 32, 0\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   14, 11, 255\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     18, 18, 19\n\t"
        "rldicl  19, 12, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     18, 18, 20\n\t"
        "rldicl  20, 12, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 18, 21\n\t"
        "rldicl  21, 11, 24, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     20, 20, 14\n\t"
        "ld      11, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     19, 19, 21\n\t"
        "ld      12, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "xor     19, 19, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     16, 16, 11\n\t"
        "xor     17, 17, 12\n\t"
        "rldicl  11, 17, 16, 56\n\t"
        "rldicl  15, 16, 40, 56\n\t"
        "rldicl  20, 17, 56, 56\n\t"
        "rldicl  21, 16, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      18, 0(9)\n\t"
        "ld      18, 64(9)\n\t"
        "ld      18, 128(9)\n\t"
        "ld      18, 192(9)\n\t"
        "ld      18, 256(9)\n\t"
        "ld      18, 320(9)\n\t"
        "ld      18, 384(9)\n\t"
        "ld      18, 448(9)\n\t"
        "ld      18, 512(9)\n\t"
        "ld      18, 576(9)\n\t"
        "ld      18, 640(9)\n\t"
        "ld      18, 704(9)\n\t"
        "ld      18, 768(9)\n\t"
        "ld      18, 832(9)\n\t"
        "ld      18, 896(9)\n\t"
        "ld      18, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    11, 11, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    11, 9, 11\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  12, 16, 48, 56\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     11, 11, 15\n\t"
        "rldicl  15, 16, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     11, 11, 20\n\t"
        "rldicl  20, 17, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     11, 11, 21\n\t"
        "andi.   21, 17, 255\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    12, 9, 12\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  14, 16, 16, 56\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     12, 12, 15\n\t"
        "rldicl  15, 17, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     12, 12, 20\n\t"
        "rldicl  20, 16, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     12, 12, 21\n\t"
        "rldicl  21, 17, 32, 56\n\t"
        "rldimi  11, 12, 32, 0\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   18, 16, 255\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 15\n\t"
        "rldicl  15, 17, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     14, 14, 20\n\t"
        "rldicl  20, 17, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     12, 14, 21\n\t"
        "rldicl  21, 16, 24, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     20, 20, 18\n\t"
        "ld      16, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "xor     15, 15, 21\n\t"
        "ld      17, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "xor     15, 15, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "bdnz    L_AES_CBC_decrypt_loop_nr_even_%=\n\t"
        "rldicl  16, 12, 16, 56\n\t"
        "rldicl  19, 11, 40, 56\n\t"
        "rldicl  20, 12, 56, 56\n\t"
        "rldicl  21, 11, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      14, 0(9)\n\t"
        "ld      14, 64(9)\n\t"
        "ld      14, 128(9)\n\t"
        "ld      14, 192(9)\n\t"
        "ld      14, 256(9)\n\t"
        "ld      14, 320(9)\n\t"
        "ld      14, 384(9)\n\t"
        "ld      14, 448(9)\n\t"
        "ld      14, 512(9)\n\t"
        "ld      14, 576(9)\n\t"
        "ld      14, 640(9)\n\t"
        "ld      14, 704(9)\n\t"
        "ld      14, 768(9)\n\t"
        "ld      14, 832(9)\n\t"
        "ld      14, 896(9)\n\t"
        "ld      14, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    16, 16, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  17, 11, 48, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 12, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     16, 16, 21\n\t"
        "andi.   21, 12, 255\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    17, 9, 17\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  18, 11, 16, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 12, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     17, 17, 20\n\t"
        "rldicl  20, 11, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 17, 21\n\t"
        "rldicl  21, 12, 32, 56\n\t"
        "rldimi  16, 17, 32, 0\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   14, 11, 255\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     18, 18, 19\n\t"
        "rldicl  19, 12, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     18, 18, 20\n\t"
        "rldicl  20, 12, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 18, 21\n\t"
        "rldicl  21, 11, 24, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     20, 20, 14\n\t"
        "ld      11, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     19, 19, 21\n\t"
        "ld      12, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "xor     19, 19, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     16, 16, 11\n\t"
        "xor     17, 17, 12\n\t"
        "rldicl  11, 16, 32, 56\n\t"
        "rldicl  15, 17, 56, 56\n\t"
        "rldicl  20, 17, 16, 56\n\t"
        "rldicl  21, 16, 40, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      19, 0(10)\n\t"
        "ld      19, 64(10)\n\t"
        "ld      19, 128(10)\n\t"
        "ld      19, 192(10)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lbzx    11, 10, 11\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    21, 10, 21\n\t"
        "andi.   12, 17, 255\n\t"
        "rlwimi  11, 15, 8, 16, 23\n\t"
        "rldicl  15, 17, 24, 56\n\t"
        "rlwimi  11, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 48, 56\n\t"
        "rlwimi  11, 21, 24, 0, 7\n\t"
        "rldicl  21, 16, 8, 56\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    21, 10, 21\n\t"
        "lbzx    12, 10, 12\n\t"
        "lbzx    20, 10, 20\n\t"
        "rldicl  14, 17, 32, 56\n\t"
        "rlwimi  12, 15, 8, 16, 23\n\t"
        "rldicl  15, 16, 56, 56\n\t"
        "rlwimi  12, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 16, 56\n\t"
        "rlwimi  12, 21, 24, 0, 7\n\t"
        "rldicl  21, 17, 40, 56\n\t"
        "rldimi  11, 12, 32, 0\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    12, 10, 14\n\t"
        "lbzx    21, 10, 21\n\t"
        "rldicl  19, 17, 8, 56\n\t"
        "rlwimi  12, 15, 8, 16, 23\n\t"
        "andi.   15, 16, 255\n\t"
        "rlwimi  12, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 24, 56\n\t"
        "rlwimi  12, 21, 24, 0, 7\n\t"
        "rldicl  21, 17, 48, 56\n\t"
        "lbzx    19, 10, 19\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    21, 10, 21\n\t"
        "ld      16, 0(22)\n\t"
        "rlwimi  15, 19, 24, 0, 7\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "rlwimi  15, 21, 16, 8, 15\n\t"
        "ld      17, 8(22)\n\t"
        "rlwimi  15, 20, 8, 16, 23\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "ld      16, 0(%[iv])\n\t"
        "ld      17, 8(%[iv])\n\t"
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "std     11, 0(%[out])\n\t"
        "std     12, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "beq     L_AES_CBC_decrypt_end_dec_odd_%=\n\t"
        "addi    22, %[ks], 0\n\t"
        "ld      11, 0(%[in])\n\t"
        "ld      12, 8(%[in])\n\t"
        "std     11, 0(%[iv])\n\t"
        "std     12, 8(%[iv])\n\t"
        "ld      16, 0(22)\n\t"
        "ld      17, 8(22)\n\t"
        "addi    22, 22, 16\n\t"
        /* Round: 0 - XOR in key schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "addi    0, %[nr], -2\n\t"
        "srwi    0, 0, 1\n\t"
        "mtctr   0\n\t"
        "\n"
    "L_AES_CBC_decrypt_loop_nr_odd_%=: \n\t"
        "rldicl  16, 12, 16, 56\n\t"
        "rldicl  19, 11, 40, 56\n\t"
        "rldicl  20, 12, 56, 56\n\t"
        "rldicl  21, 11, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      14, 0(9)\n\t"
        "ld      14, 64(9)\n\t"
        "ld      14, 128(9)\n\t"
        "ld      14, 192(9)\n\t"
        "ld      14, 256(9)\n\t"
        "ld      14, 320(9)\n\t"
        "ld      14, 384(9)\n\t"
        "ld      14, 448(9)\n\t"
        "ld      14, 512(9)\n\t"
        "ld      14, 576(9)\n\t"
        "ld      14, 640(9)\n\t"
        "ld      14, 704(9)\n\t"
        "ld      14, 768(9)\n\t"
        "ld      14, 832(9)\n\t"
        "ld      14, 896(9)\n\t"
        "ld      14, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    16, 16, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  17, 11, 48, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 12, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     16, 16, 21\n\t"
        "andi.   21, 12, 255\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    17, 9, 17\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  18, 11, 16, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 12, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     17, 17, 20\n\t"
        "rldicl  20, 11, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 17, 21\n\t"
        "rldicl  21, 12, 32, 56\n\t"
        "rldimi  16, 17, 32, 0\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   14, 11, 255\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     18, 18, 19\n\t"
        "rldicl  19, 12, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     18, 18, 20\n\t"
        "rldicl  20, 12, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 18, 21\n\t"
        "rldicl  21, 11, 24, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     20, 20, 14\n\t"
        "ld      11, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     19, 19, 21\n\t"
        "ld      12, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "xor     19, 19, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     16, 16, 11\n\t"
        "xor     17, 17, 12\n\t"
        "rldicl  11, 17, 16, 56\n\t"
        "rldicl  15, 16, 40, 56\n\t"
        "rldicl  20, 17, 56, 56\n\t"
        "rldicl  21, 16, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      18, 0(9)\n\t"
        "ld      18, 64(9)\n\t"
        "ld      18, 128(9)\n\t"
        "ld      18, 192(9)\n\t"
        "ld      18, 256(9)\n\t"
        "ld      18, 320(9)\n\t"
        "ld      18, 384(9)\n\t"
        "ld      18, 448(9)\n\t"
        "ld      18, 512(9)\n\t"
        "ld      18, 576(9)\n\t"
        "ld      18, 640(9)\n\t"
        "ld      18, 704(9)\n\t"
        "ld      18, 768(9)\n\t"
        "ld      18, 832(9)\n\t"
        "ld      18, 896(9)\n\t"
        "ld      18, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    11, 11, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    11, 9, 11\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  12, 16, 48, 56\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     11, 11, 15\n\t"
        "rldicl  15, 16, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     11, 11, 20\n\t"
        "rldicl  20, 17, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     11, 11, 21\n\t"
        "andi.   21, 17, 255\n\t"
        "slwi    12, 12, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    12, 9, 12\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  14, 16, 16, 56\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     12, 12, 15\n\t"
        "rldicl  15, 17, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     12, 12, 20\n\t"
        "rldicl  20, 16, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     12, 12, 21\n\t"
        "rldicl  21, 17, 32, 56\n\t"
        "rldimi  11, 12, 32, 0\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   18, 16, 255\n\t"
        "rlwimi  15, 15, 8, 0, 31\n\t"
        "xor     14, 14, 15\n\t"
        "rldicl  15, 17, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     14, 14, 20\n\t"
        "rldicl  20, 17, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     12, 14, 21\n\t"
        "rldicl  21, 16, 24, 56\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    15, 15, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    15, 9, 15\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  18, 18, 8, 0, 31\n\t"
        "xor     20, 20, 18\n\t"
        "ld      16, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "xor     15, 15, 21\n\t"
        "ld      17, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "xor     15, 15, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "bdnz    L_AES_CBC_decrypt_loop_nr_odd_%=\n\t"
        "rldicl  16, 12, 16, 56\n\t"
        "rldicl  19, 11, 40, 56\n\t"
        "rldicl  20, 12, 56, 56\n\t"
        "rldicl  21, 11, 32, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      14, 0(9)\n\t"
        "ld      14, 64(9)\n\t"
        "ld      14, 128(9)\n\t"
        "ld      14, 192(9)\n\t"
        "ld      14, 256(9)\n\t"
        "ld      14, 320(9)\n\t"
        "ld      14, 384(9)\n\t"
        "ld      14, 448(9)\n\t"
        "ld      14, 512(9)\n\t"
        "ld      14, 576(9)\n\t"
        "ld      14, 640(9)\n\t"
        "ld      14, 704(9)\n\t"
        "ld      14, 768(9)\n\t"
        "ld      14, 832(9)\n\t"
        "ld      14, 896(9)\n\t"
        "ld      14, 960(9)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "slwi    16, 16, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    16, 9, 16\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  17, 11, 48, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     16, 16, 19\n\t"
        "rldicl  19, 11, 8, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     16, 16, 20\n\t"
        "rldicl  20, 12, 24, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     16, 16, 21\n\t"
        "andi.   21, 12, 255\n\t"
        "slwi    17, 17, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    17, 9, 17\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "rldicl  18, 11, 16, 56\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     17, 17, 19\n\t"
        "rldicl  19, 12, 40, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     17, 17, 20\n\t"
        "rldicl  20, 11, 56, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 17, 21\n\t"
        "rldicl  21, 12, 32, 56\n\t"
        "rldimi  16, 17, 32, 0\n\t"
        "slwi    18, 18, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    18, 9, 18\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    21, 9, 21\n\t"
        "andi.   14, 11, 255\n\t"
        "rlwimi  19, 19, 8, 0, 31\n\t"
        "xor     18, 18, 19\n\t"
        "rldicl  19, 12, 48, 56\n\t"
        "rlwimi  20, 20, 24, 0, 31\n\t"
        "xor     18, 18, 20\n\t"
        "rldicl  20, 12, 8, 56\n\t"
        "rlwimi  21, 21, 16, 0, 31\n\t"
        "xor     17, 18, 21\n\t"
        "rldicl  21, 11, 24, 56\n\t"
        "slwi    14, 14, 2\n\t"
        "slwi    20, 20, 2\n\t"
        "slwi    19, 19, 2\n\t"
        "slwi    21, 21, 2\n\t"
        "lwzx    14, 9, 14\n\t"
        "lwzx    20, 9, 20\n\t"
        "lwzx    19, 9, 19\n\t"
        "lwzx    21, 9, 21\n\t"
        "rlwimi  14, 14, 8, 0, 31\n\t"
        "xor     20, 20, 14\n\t"
        "ld      11, 0(22)\n\t"
        "rlwimi  21, 21, 24, 0, 31\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "xor     19, 19, 21\n\t"
        "ld      12, 8(22)\n\t"
        "rlwimi  20, 20, 8, 0, 31\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "xor     19, 19, 20\n\t"
        "addi    22, 22, 16\n\t"
        "rldimi  17, 19, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     16, 16, 11\n\t"
        "xor     17, 17, 12\n\t"
        "rldicl  11, 16, 32, 56\n\t"
        "rldicl  15, 17, 56, 56\n\t"
        "rldicl  20, 17, 16, 56\n\t"
        "rldicl  21, 16, 40, 56\n\t"
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
        "ld      19, 0(10)\n\t"
        "ld      19, 64(10)\n\t"
        "ld      19, 128(10)\n\t"
        "ld      19, 192(10)\n\t"
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
        "lbzx    11, 10, 11\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    21, 10, 21\n\t"
        "andi.   12, 17, 255\n\t"
        "rlwimi  11, 15, 8, 16, 23\n\t"
        "rldicl  15, 17, 24, 56\n\t"
        "rlwimi  11, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 48, 56\n\t"
        "rlwimi  11, 21, 24, 0, 7\n\t"
        "rldicl  21, 16, 8, 56\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    21, 10, 21\n\t"
        "lbzx    12, 10, 12\n\t"
        "lbzx    20, 10, 20\n\t"
        "rldicl  14, 17, 32, 56\n\t"
        "rlwimi  12, 15, 8, 16, 23\n\t"
        "rldicl  15, 16, 56, 56\n\t"
        "rlwimi  12, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 16, 56\n\t"
        "rlwimi  12, 21, 24, 0, 7\n\t"
        "rldicl  21, 17, 40, 56\n\t"
        "rldimi  11, 12, 32, 0\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    12, 10, 14\n\t"
        "lbzx    21, 10, 21\n\t"
        "rldicl  19, 17, 8, 56\n\t"
        "rlwimi  12, 15, 8, 16, 23\n\t"
        "andi.   15, 16, 255\n\t"
        "rlwimi  12, 20, 16, 8, 15\n\t"
        "rldicl  20, 16, 24, 56\n\t"
        "rlwimi  12, 21, 24, 0, 7\n\t"
        "rldicl  21, 17, 48, 56\n\t"
        "lbzx    19, 10, 19\n\t"
        "lbzx    20, 10, 20\n\t"
        "lbzx    15, 10, 15\n\t"
        "lbzx    21, 10, 21\n\t"
        "ld      16, 0(22)\n\t"
        "rlwimi  15, 19, 24, 0, 7\n\t"
        "rldicr  16, 16, 32, 63\n\t"
        "rlwimi  15, 21, 16, 8, 15\n\t"
        "ld      17, 8(22)\n\t"
        "rlwimi  15, 20, 8, 16, 23\n\t"
        "rldicr  17, 17, 32, 63\n\t"
        "rldimi  12, 15, 32, 0\n\t"
        /*   XOR in Key Schedule */
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "rldicr  11, 11, 32, 63\n\t"
        "rldicr  12, 12, 32, 63\n\t"
        "ld      16, 16(%[iv])\n\t"
        "ld      17, 24(%[iv])\n\t"
        "xor     11, 11, 16\n\t"
        "xor     12, 12, 17\n\t"
        "std     11, 0(%[out])\n\t"
        "std     12, 8(%[out])\n\t"
        "addi    %[in], %[in], 16\n\t"
        "addi    %[out], %[out], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "bne     L_AES_CBC_decrypt_loop_block_%=\n\t"
        "b       L_AES_CBC_decrypt_end_dec_%=\n\t"
        "\n"
    "L_AES_CBC_decrypt_end_dec_odd_%=: \n\t"
        "ld      16, 16(%[iv])\n\t"
        "ld      17, 24(%[iv])\n\t"
        "std     16, 0(%[iv])\n\t"
        "std     17, 8(%[iv])\n\t"
        "\n"
    "L_AES_CBC_decrypt_end_dec_%=: \n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks),
          [nr] "+r" (nr), [iv] "+r" (iv),
          [L_AES_PPC64_td] "+r" (L_AES_PPC64_td_c),
          [L_AES_PPC64_td4] "+r" (L_AES_PPC64_td4_c)
        :
#else
        :
        : [in] "r" (in), [out] "r" (out), [len] "r" (len), [ks] "r" (ks),
          [nr] "r" (nr), [iv] "r" (iv), [L_AES_PPC64_td] "r" (L_AES_PPC64_td_c),
          [L_AES_PPC64_td4] "r" (L_AES_PPC64_td4_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "11", "12", "14", "15", "16", "17", "18", "19",
            "20", "21", "22"
    );
}

#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC
        * HAVE_AES_ECB */
#ifdef WOLFSSL_AES_XTS
#endif /* WOLFSSL_AES_XTS */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
#ifdef GCM_TABLE_4BIT
static const word32 L_GCM_gmult_len_r[] = {
    0x00000000, 0x1c200000, 0x38400000, 0x24600000,
    0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
    0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
    0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000,
    0x00000000, 0x01c20000, 0x03840000, 0x02460000,
    0x07080000, 0x06ca0000, 0x048c0000, 0x054e0000,
    0x0e100000, 0x0fd20000, 0x0d940000, 0x0c560000,
    0x09180000, 0x08da0000, 0x0a9c0000, 0x0b5e0000,
};

void GCM_gmult_len(unsigned char* x, const unsigned char** m,
    const unsigned char* data, unsigned long len);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void GCM_gmult_len(unsigned char* x_p, const unsigned char** m_p,
    const unsigned char* data_p, unsigned long len_p)
#else
void GCM_gmult_len(unsigned char* x, const unsigned char** m,
    const unsigned char* data, unsigned long len)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register unsigned char* x asm ("3") = (unsigned char*)x_p;
    register const unsigned char** m asm ("4") = (const unsigned char**)m_p;
    register const unsigned char* data asm ("5") =
        (const unsigned char*)data_p;
    register unsigned long len asm ("6") = (unsigned long)len_p;
    register word32* L_GCM_gmult_len_r_c asm ("7") =
        (word32*)&L_GCM_gmult_len_r;
#else
    register word32* L_GCM_gmult_len_r_c = (word32*)&L_GCM_gmult_len_r;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "li      21, 0x100\n\t"
        "mr      18, %[L_GCM_gmult_len_r]\n\t"
        "add     21, 21, %[m]\n\t"
        "addi    20, %[m], 8\n\t"
        "addi    22, 21, 8\n\t"
        "addi    19, 18, 0x40\n\t"
        "\n"
    "L_GCM_gmult_len_start_block_%=: \n\t"
        "li      16, 8\n\t"
        "ldbrx   7, 0, %[x]\n\t"
        "ldbrx   8, 16, %[x]\n\t"
        "ldbrx   9, 0, %[data]\n\t"
        "ldbrx   10, 16, %[data]\n\t"
        "xor     7, 7, 9\n\t"
        "xor     8, 8, 10\n\t"
        "rldicr  25, 8, 32, 63\n\t"
        /* Byte 15 */
        "rlwinm  23, 25, 12, 24, 27\n\t"
        "rlwinm  24, 25, 8, 24, 27\n\t"
        "ldx     14, 23, %[m]\n\t"
        "ldx     15, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 14 */
        "rlwinm  23, 25, 20, 24, 27\n\t"
        "rlwinm  24, 25, 16, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 13 */
        "rlwinm  23, 25, 28, 24, 27\n\t"
        "rlwinm  24, 25, 24, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 12 */
        "rlwinm  23, 25, 4, 24, 27\n\t"
        "rlwinm  24, 25, 0, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 11 */
        "rlwinm  23, 8, 12, 24, 27\n\t"
        "rlwinm  24, 8, 8, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 10 */
        "rlwinm  23, 8, 20, 24, 27\n\t"
        "rlwinm  24, 8, 16, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 9 */
        "rlwinm  23, 8, 28, 24, 27\n\t"
        "rlwinm  24, 8, 24, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 8 */
        "rlwinm  23, 8, 4, 24, 27\n\t"
        "rlwinm  24, 8, 0, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        "rldicr  25, 7, 32, 63\n\t"
        /* Byte 7 */
        "rlwinm  23, 25, 12, 24, 27\n\t"
        "rlwinm  24, 25, 8, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 6 */
        "rlwinm  23, 25, 20, 24, 27\n\t"
        "rlwinm  24, 25, 16, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 5 */
        "rlwinm  23, 25, 28, 24, 27\n\t"
        "rlwinm  24, 25, 24, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 4 */
        "rlwinm  23, 25, 4, 24, 27\n\t"
        "rlwinm  24, 25, 0, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 3 */
        "rlwinm  23, 7, 12, 24, 27\n\t"
        "rlwinm  24, 7, 8, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 2 */
        "rlwinm  23, 7, 20, 24, 27\n\t"
        "rlwinm  24, 7, 16, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 1 */
        "rlwinm  23, 7, 28, 24, 27\n\t"
        "rlwinm  24, 7, 24, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, 21\n\t"
        "ldx     12, 24, 22\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 60, 60\n\t"
        "rldic   17, 15, 2, 58\n\t"
        "srdi    15, 15, 8\n\t"
        "addi    24, 24, -248\n\t"
        "rldimi  15, 14, 56, 0\n\t"
        "srdi    14, 14, 8\n\t"
        "lwzx    9, 17, 19\n\t"
        "ldx     10, 24, 21\n\t"
        "xor     16, 16, 10\n\t"
        "xor     14, 14, 11\n\t"
        "rlwinm  16, 16, 2, 26, 29\n\t"
        "xor     15, 15, 12\n\t"
        "sldi    9, 9, 32\n\t"
        "lwzx    10, 16, 18\n\t"
        "xor     14, 14, 9\n\t"
        "sldi    10, 10, 32\n\t"
        "xor     14, 14, 10\n\t"
        /* Byte 0 */
        "rlwinm  23, 7, 4, 24, 27\n\t"
        "rlwinm  24, 7, 0, 24, 27\n\t"
        "ldx     9, 23, %[m]\n\t"
        "ldx     10, 23, 20\n\t"
        "ldx     11, 24, %[m]\n\t"
        "ldx     12, 24, 20\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldic   16, 15, 2, 58\n\t"
        "srdi    15, 15, 4\n\t"
        "lwzx    9, 16, 18\n\t"
        "rldimi  15, 14, 60, 0\n\t"
        "srdi    14, 14, 4\n\t"
        "xor     8, 15, 12\n\t"
        "xor     14, 14, 11\n\t"
        "sldi    9, 9, 32\n\t"
        "xor     7, 14, 9\n\t"
        "addi    %[data], %[data], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "std     7, 0(%[x])\n\t"
        "std     8, 8(%[x])\n\t"
        "bne     L_GCM_gmult_len_start_block_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [m] "+r" (m), [data] "+r" (data), [len] "+r" (len),
          [L_GCM_gmult_len_r] "+r" (L_GCM_gmult_len_r_c)
        :
#else
        :
        : [x] "r" (x), [m] "r" (m), [data] "r" (data), [len] "r" (len),
          [L_GCM_gmult_len_r] "r" (L_GCM_gmult_len_r_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "8", "9", "10", "11", "12", "14", "15", "16",
            "17", "18", "19", "20", "21", "22", "23", "24", "25"
    );
}

#endif /* GCM_TABLE_4BIT */
#ifdef GCM_TABLE
static const byte L_GCM_gmult_len_r[] = {
    0x00, 0x00, 0xc2, 0x01, 0x84, 0x03, 0x46, 0x02,
    0x08, 0x07, 0xca, 0x06, 0x8c, 0x04, 0x4e, 0x05,
    0x10, 0x0e, 0xd2, 0x0f, 0x94, 0x0d, 0x56, 0x0c,
    0x18, 0x09, 0xda, 0x08, 0x9c, 0x0a, 0x5e, 0x0b,
    0x20, 0x1c, 0xe2, 0x1d, 0xa4, 0x1f, 0x66, 0x1e,
    0x28, 0x1b, 0xea, 0x1a, 0xac, 0x18, 0x6e, 0x19,
    0x30, 0x12, 0xf2, 0x13, 0xb4, 0x11, 0x76, 0x10,
    0x38, 0x15, 0xfa, 0x14, 0xbc, 0x16, 0x7e, 0x17,
    0x40, 0x38, 0x82, 0x39, 0xc4, 0x3b, 0x06, 0x3a,
    0x48, 0x3f, 0x8a, 0x3e, 0xcc, 0x3c, 0x0e, 0x3d,
    0x50, 0x36, 0x92, 0x37, 0xd4, 0x35, 0x16, 0x34,
    0x58, 0x31, 0x9a, 0x30, 0xdc, 0x32, 0x1e, 0x33,
    0x60, 0x24, 0xa2, 0x25, 0xe4, 0x27, 0x26, 0x26,
    0x68, 0x23, 0xaa, 0x22, 0xec, 0x20, 0x2e, 0x21,
    0x70, 0x2a, 0xb2, 0x2b, 0xf4, 0x29, 0x36, 0x28,
    0x78, 0x2d, 0xba, 0x2c, 0xfc, 0x2e, 0x3e, 0x2f,
    0x80, 0x70, 0x42, 0x71, 0x04, 0x73, 0xc6, 0x72,
    0x88, 0x77, 0x4a, 0x76, 0x0c, 0x74, 0xce, 0x75,
    0x90, 0x7e, 0x52, 0x7f, 0x14, 0x7d, 0xd6, 0x7c,
    0x98, 0x79, 0x5a, 0x78, 0x1c, 0x7a, 0xde, 0x7b,
    0xa0, 0x6c, 0x62, 0x6d, 0x24, 0x6f, 0xe6, 0x6e,
    0xa8, 0x6b, 0x6a, 0x6a, 0x2c, 0x68, 0xee, 0x69,
    0xb0, 0x62, 0x72, 0x63, 0x34, 0x61, 0xf6, 0x60,
    0xb8, 0x65, 0x7a, 0x64, 0x3c, 0x66, 0xfe, 0x67,
    0xc0, 0x48, 0x02, 0x49, 0x44, 0x4b, 0x86, 0x4a,
    0xc8, 0x4f, 0x0a, 0x4e, 0x4c, 0x4c, 0x8e, 0x4d,
    0xd0, 0x46, 0x12, 0x47, 0x54, 0x45, 0x96, 0x44,
    0xd8, 0x41, 0x1a, 0x40, 0x5c, 0x42, 0x9e, 0x43,
    0xe0, 0x54, 0x22, 0x55, 0x64, 0x57, 0xa6, 0x56,
    0xe8, 0x53, 0x2a, 0x52, 0x6c, 0x50, 0xae, 0x51,
    0xf0, 0x5a, 0x32, 0x5b, 0x74, 0x59, 0xb6, 0x58,
    0xf8, 0x5d, 0x3a, 0x5c, 0x7c, 0x5e, 0xbe, 0x5f,
    0x00, 0xe1, 0xc2, 0xe0, 0x84, 0xe2, 0x46, 0xe3,
    0x08, 0xe6, 0xca, 0xe7, 0x8c, 0xe5, 0x4e, 0xe4,
    0x10, 0xef, 0xd2, 0xee, 0x94, 0xec, 0x56, 0xed,
    0x18, 0xe8, 0xda, 0xe9, 0x9c, 0xeb, 0x5e, 0xea,
    0x20, 0xfd, 0xe2, 0xfc, 0xa4, 0xfe, 0x66, 0xff,
    0x28, 0xfa, 0xea, 0xfb, 0xac, 0xf9, 0x6e, 0xf8,
    0x30, 0xf3, 0xf2, 0xf2, 0xb4, 0xf0, 0x76, 0xf1,
    0x38, 0xf4, 0xfa, 0xf5, 0xbc, 0xf7, 0x7e, 0xf6,
    0x40, 0xd9, 0x82, 0xd8, 0xc4, 0xda, 0x06, 0xdb,
    0x48, 0xde, 0x8a, 0xdf, 0xcc, 0xdd, 0x0e, 0xdc,
    0x50, 0xd7, 0x92, 0xd6, 0xd4, 0xd4, 0x16, 0xd5,
    0x58, 0xd0, 0x9a, 0xd1, 0xdc, 0xd3, 0x1e, 0xd2,
    0x60, 0xc5, 0xa2, 0xc4, 0xe4, 0xc6, 0x26, 0xc7,
    0x68, 0xc2, 0xaa, 0xc3, 0xec, 0xc1, 0x2e, 0xc0,
    0x70, 0xcb, 0xb2, 0xca, 0xf4, 0xc8, 0x36, 0xc9,
    0x78, 0xcc, 0xba, 0xcd, 0xfc, 0xcf, 0x3e, 0xce,
    0x80, 0x91, 0x42, 0x90, 0x04, 0x92, 0xc6, 0x93,
    0x88, 0x96, 0x4a, 0x97, 0x0c, 0x95, 0xce, 0x94,
    0x90, 0x9f, 0x52, 0x9e, 0x14, 0x9c, 0xd6, 0x9d,
    0x98, 0x98, 0x5a, 0x99, 0x1c, 0x9b, 0xde, 0x9a,
    0xa0, 0x8d, 0x62, 0x8c, 0x24, 0x8e, 0xe6, 0x8f,
    0xa8, 0x8a, 0x6a, 0x8b, 0x2c, 0x89, 0xee, 0x88,
    0xb0, 0x83, 0x72, 0x82, 0x34, 0x80, 0xf6, 0x81,
    0xb8, 0x84, 0x7a, 0x85, 0x3c, 0x87, 0xfe, 0x86,
    0xc0, 0xa9, 0x02, 0xa8, 0x44, 0xaa, 0x86, 0xab,
    0xc8, 0xae, 0x0a, 0xaf, 0x4c, 0xad, 0x8e, 0xac,
    0xd0, 0xa7, 0x12, 0xa6, 0x54, 0xa4, 0x96, 0xa5,
    0xd8, 0xa0, 0x1a, 0xa1, 0x5c, 0xa3, 0x9e, 0xa2,
    0xe0, 0xb5, 0x22, 0xb4, 0x64, 0xb6, 0xa6, 0xb7,
    0xe8, 0xb2, 0x2a, 0xb3, 0x6c, 0xb1, 0xae, 0xb0,
    0xf0, 0xbb, 0x32, 0xba, 0x74, 0xb8, 0xb6, 0xb9,
    0xf8, 0xbc, 0x3a, 0xbd, 0x7c, 0xbf, 0xbe, 0xbe,
};

void GCM_gmult_len(unsigned char* x, const unsigned char** m,
    const unsigned char* data, unsigned long len);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void GCM_gmult_len(unsigned char* x_p, const unsigned char** m_p,
    const unsigned char* data_p, unsigned long len_p)
#else
void GCM_gmult_len(unsigned char* x, const unsigned char** m,
    const unsigned char* data, unsigned long len)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register unsigned char* x asm ("3") = (unsigned char*)x_p;
    register const unsigned char** m asm ("4") = (const unsigned char**)m_p;
    register const unsigned char* data asm ("5") =
        (const unsigned char*)data_p;
    register unsigned long len asm ("6") = (unsigned long)len_p;
    register byte* L_GCM_gmult_len_r_c asm ("7") = (byte*)&L_GCM_gmult_len_r;
#else
    register byte* L_GCM_gmult_len_r_c = (byte*)&L_GCM_gmult_len_r;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      17, %[L_GCM_gmult_len_r]\n\t"
        "\n"
    "L_GCM_gmult_len_start_block_%=: \n\t"
        "li      16, 8\n\t"
        "ldbrx   7, 0, %[x]\n\t"
        "ldbrx   8, 16, %[x]\n\t"
        "ldbrx   9, 0, %[data]\n\t"
        "ldbrx   10, 16, %[data]\n\t"
        "xor     7, 7, 9\n\t"
        "xor     8, 8, 10\n\t"
        "rldicr  20, 8, 32, 63\n\t"
        /* Byte 15 */
        "rlwinm  18, 20, 12, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     14, 18, %[m]\n\t"
        "ldx     15, 19, %[m]\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 14 */
        "rlwinm  18, 20, 20, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 13 */
        "rlwinm  18, 20, 28, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 12 */
        "rlwinm  18, 20, 4, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 11 */
        "rlwinm  18, 8, 12, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 10 */
        "rlwinm  18, 8, 20, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 9 */
        "rlwinm  18, 8, 28, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 8 */
        "rlwinm  18, 8, 4, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        "rldicr  20, 7, 32, 63\n\t"
        /* Byte 7 */
        "rlwinm  18, 20, 12, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 6 */
        "rlwinm  18, 20, 20, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 5 */
        "rlwinm  18, 20, 28, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 4 */
        "rlwinm  18, 20, 4, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 3 */
        "rlwinm  18, 7, 12, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 2 */
        "rlwinm  18, 7, 20, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 1 */
        "rlwinm  18, 7, 28, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     14, 14, 9\n\t"
        "xor     15, 15, 10\n\t"
        "rldicl  16, 15, 9, 55\n\t"
        "andi.   16, 16, 510\n\t"
        "lhzx    9, 16, 17\n\t"
        "rldicl  10, 14, 8, 56\n\t"
        "sldi    15, 15, 8\n\t"
        "sldi    14, 14, 8\n\t"
        "xor     15, 15, 10\n\t"
        "xor     14, 14, 9\n\t"
        /* Byte 0 */
        "rlwinm  18, 7, 4, 20, 27\n\t"
        "addi    19, 18, 8\n\t"
        "ldx     9, 18, %[m]\n\t"
        "ldx     10, 19, %[m]\n\t"
        "xor     7, 14, 9\n\t"
        "xor     8, 15, 10\n\t"
        "addi    %[data], %[data], 16\n\t"
        "addic.  %[len], %[len], -16\n\t"
        "li      16, 8\n\t"
        "stdbrx  7, 0, %[x]\n\t"
        "stdbrx  8, 16, %[x]\n\t"
        "bne     L_GCM_gmult_len_start_block_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [m] "+r" (m), [data] "+r" (data), [len] "+r" (len),
          [L_GCM_gmult_len_r] "+r" (L_GCM_gmult_len_r_c)
        :
#else
        :
        : [x] "r" (x), [m] "r" (m), [data] "r" (data), [len] "r" (len),
          [L_GCM_gmult_len_r] "r" (L_GCM_gmult_len_r_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "0", "8", "9", "10", "11", "12", "14", "15", "16",
            "17", "18", "19", "20"
    );
}

#endif /* GCM_TABLE */
#endif /* HAVE_AESGCM */
#endif /* !defined(NO_AES) && defined(WOLFSSL_PPC64_ASM) */
#endif /* WOLFSSL_PPC64_ASM */

#endif /* WOLFSSL_PPC64_ASM_INLINE */
