/* thumb2-aes-asm
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./aes/aes.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-aes-asm.c
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifdef WOLFSSL_ARMASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>

#ifdef HAVE_AES_DECRYPT
XALIGNED(16) static const word32 L_AES_Thumb2_td_data[] = {
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
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
XALIGNED(16) static const word32 L_AES_Thumb2_te_data[] = {
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

#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
static const word32* L_AES_Thumb2_td = L_AES_Thumb2_td_data;
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
static const word32* L_AES_Thumb2_te = L_AES_Thumb2_te_data;
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
void AES_invert_key(unsigned char* ks, word32 rounds);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_invert_key(unsigned char* ks_p, word32 rounds_p)
#else
void AES_invert_key(unsigned char* ks, word32 rounds)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register unsigned char* ks __asm__ ("r0") = (unsigned char*)ks_p;
    register word32 rounds __asm__ ("r1") = (word32)rounds_p;
    register word32* L_AES_Thumb2_te_c __asm__ ("r2") = (word32*)L_AES_Thumb2_te;
    register word32* L_AES_Thumb2_td_c __asm__ ("r3") = (word32*)L_AES_Thumb2_td;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "MOV	r12, %[L_AES_Thumb2_te]\n\t"
        "MOV	lr, %[L_AES_Thumb2_td]\n\t"
        "ADD	r10, %[ks], %[rounds], LSL #4\n\t"
        "MOV	r11, %[rounds]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_invert_key_loop:\n\t"
#else
    "L_AES_invert_key_loop_%=:\n\t"
#endif
        "LDM	%[ks], {r2, r3, r4, r5}\n\t"
        "LDM	r10, {r6, r7, r8, r9}\n\t"
        "STM	r10, {r2, r3, r4, r5}\n\t"
        "STM	%[ks]!, {r6, r7, r8, r9}\n\t"
        "SUBS	r11, r11, #0x2\n\t"
        "SUB	r10, r10, #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_invert_key_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_AES_invert_key_loop\n\t"
#else
        "BNE.N	L_AES_invert_key_loop_%=\n\t"
#endif
        "SUB	%[ks], %[ks], %[rounds], LSL #3\n\t"
        "ADD	%[ks], %[ks], #0x10\n\t"
        "SUB	r11, %[rounds], #0x1\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_invert_key_mix_loop:\n\t"
#else
    "L_AES_invert_key_mix_loop_%=:\n\t"
#endif
        "LDM	%[ks], {r2, r3, r4, r5}\n\t"
        "UBFX	r6, r2, #0, #8\n\t"
        "UBFX	r7, r2, #8, #8\n\t"
        "UBFX	r8, r2, #16, #8\n\t"
        "LSR	r9, r2, #24\n\t"
        "LDRB	r6, [r12, r6, LSL #2]\n\t"
        "LDRB	r7, [r12, r7, LSL #2]\n\t"
        "LDRB	r8, [r12, r8, LSL #2]\n\t"
        "LDRB	r9, [r12, r9, LSL #2]\n\t"
        "LDR	r6, [lr, r6, LSL #2]\n\t"
        "LDR	r7, [lr, r7, LSL #2]\n\t"
        "LDR	r8, [lr, r8, LSL #2]\n\t"
        "LDR	r9, [lr, r9, LSL #2]\n\t"
        "EOR	r8, r8, r6, ROR #16\n\t"
        "EOR	r8, r8, r7, ROR #8\n\t"
        "EOR	r8, r8, r9, ROR #24\n\t"
        "STR	r8, [%[ks]], #4\n\t"
        "UBFX	r6, r3, #0, #8\n\t"
        "UBFX	r7, r3, #8, #8\n\t"
        "UBFX	r8, r3, #16, #8\n\t"
        "LSR	r9, r3, #24\n\t"
        "LDRB	r6, [r12, r6, LSL #2]\n\t"
        "LDRB	r7, [r12, r7, LSL #2]\n\t"
        "LDRB	r8, [r12, r8, LSL #2]\n\t"
        "LDRB	r9, [r12, r9, LSL #2]\n\t"
        "LDR	r6, [lr, r6, LSL #2]\n\t"
        "LDR	r7, [lr, r7, LSL #2]\n\t"
        "LDR	r8, [lr, r8, LSL #2]\n\t"
        "LDR	r9, [lr, r9, LSL #2]\n\t"
        "EOR	r8, r8, r6, ROR #16\n\t"
        "EOR	r8, r8, r7, ROR #8\n\t"
        "EOR	r8, r8, r9, ROR #24\n\t"
        "STR	r8, [%[ks]], #4\n\t"
        "UBFX	r6, r4, #0, #8\n\t"
        "UBFX	r7, r4, #8, #8\n\t"
        "UBFX	r8, r4, #16, #8\n\t"
        "LSR	r9, r4, #24\n\t"
        "LDRB	r6, [r12, r6, LSL #2]\n\t"
        "LDRB	r7, [r12, r7, LSL #2]\n\t"
        "LDRB	r8, [r12, r8, LSL #2]\n\t"
        "LDRB	r9, [r12, r9, LSL #2]\n\t"
        "LDR	r6, [lr, r6, LSL #2]\n\t"
        "LDR	r7, [lr, r7, LSL #2]\n\t"
        "LDR	r8, [lr, r8, LSL #2]\n\t"
        "LDR	r9, [lr, r9, LSL #2]\n\t"
        "EOR	r8, r8, r6, ROR #16\n\t"
        "EOR	r8, r8, r7, ROR #8\n\t"
        "EOR	r8, r8, r9, ROR #24\n\t"
        "STR	r8, [%[ks]], #4\n\t"
        "UBFX	r6, r5, #0, #8\n\t"
        "UBFX	r7, r5, #8, #8\n\t"
        "UBFX	r8, r5, #16, #8\n\t"
        "LSR	r9, r5, #24\n\t"
        "LDRB	r6, [r12, r6, LSL #2]\n\t"
        "LDRB	r7, [r12, r7, LSL #2]\n\t"
        "LDRB	r8, [r12, r8, LSL #2]\n\t"
        "LDRB	r9, [r12, r9, LSL #2]\n\t"
        "LDR	r6, [lr, r6, LSL #2]\n\t"
        "LDR	r7, [lr, r7, LSL #2]\n\t"
        "LDR	r8, [lr, r8, LSL #2]\n\t"
        "LDR	r9, [lr, r9, LSL #2]\n\t"
        "EOR	r8, r8, r6, ROR #16\n\t"
        "EOR	r8, r8, r7, ROR #8\n\t"
        "EOR	r8, r8, r9, ROR #24\n\t"
        "STR	r8, [%[ks]], #4\n\t"
        "SUBS	r11, r11, #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_invert_key_mix_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_invert_key_mix_loop\n\t"
#else
        "BNE.W	L_AES_invert_key_mix_loop_%=\n\t"
#endif
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ks] "+r" (ks), [rounds] "+r" (rounds),
          [L_AES_Thumb2_te] "+r" (L_AES_Thumb2_te_c), [L_AES_Thumb2_td] "+r" (L_AES_Thumb2_td_c)
        :
        : "memory", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [ks] "+r" (ks), [rounds] "+r" (rounds)
        : [L_AES_Thumb2_te] "r" (L_AES_Thumb2_te), [L_AES_Thumb2_td] "r" (L_AES_Thumb2_td)
        : "memory", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#endif /* HAVE_AES_DECRYPT */
XALIGNED(16) static const word32 L_AES_Thumb2_rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
};

void AES_set_encrypt_key(const unsigned char* key, word32 len,
        unsigned char* ks);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_set_encrypt_key(const unsigned char* key_p, word32 len_p, unsigned char* ks_p)
#else
void AES_set_encrypt_key(const unsigned char* key, word32 len, unsigned char* ks)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* key __asm__ ("r0") = (const unsigned char*)key_p;
    register word32 len __asm__ ("r1") = (word32)len_p;
    register unsigned char* ks __asm__ ("r2") = (unsigned char*)ks_p;
    register word32* L_AES_Thumb2_te_c __asm__ ("r3") = (word32*)L_AES_Thumb2_te;
    register word32* L_AES_Thumb2_rcon_c __asm__ ("r4") = (word32*)&L_AES_Thumb2_rcon;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "MOV	r10, %[L_AES_Thumb2_te]\n\t"
        "MOV	lr, %[L_AES_Thumb2_rcon]\n\t"
        "CMP	%[len], #0x80\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_set_encrypt_key_start_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_set_encrypt_key_start_128\n\t"
#else
        "BEQ.W	L_AES_set_encrypt_key_start_128_%=\n\t"
#endif
        "CMP	%[len], #0xc0\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_set_encrypt_key_start_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_set_encrypt_key_start_192\n\t"
#else
        "BEQ.W	L_AES_set_encrypt_key_start_192_%=\n\t"
#endif
        "LDR	r4, [%[key]]\n\t"
        "LDR	r5, [%[key], #4]\n\t"
        "LDR	r6, [%[key], #8]\n\t"
        "LDR	r7, [%[key], #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "LDR	r4, [%[key], #16]\n\t"
        "LDR	r5, [%[key], #20]\n\t"
        "LDR	r6, [%[key], #24]\n\t"
        "LDR	r7, [%[key], #28]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "SUB	%[ks], %[ks], #0x10\n\t"
        "MOV	r12, #0x6\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_loop_256:\n\t"
#else
    "L_AES_set_encrypt_key_loop_256_%=:\n\t"
#endif
        "UBFX	r4, r7, #0, #8\n\t"
        "UBFX	r5, r7, #8, #8\n\t"
        "UBFX	r6, r7, #16, #8\n\t"
        "LSR	r7, r7, #24\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r7, [r10, r7, LSL #2]\n\t"
        "EOR	r3, r7, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r4, r4, r3\n\t"
        "LDM	lr!, {r3}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "ADD	%[ks], %[ks], #0x10\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "SUB	%[ks], %[ks], #0x10\n\t"
        "MOV	r3, r7\n\t"
        "UBFX	r4, r3, #8, #8\n\t"
        "UBFX	r5, r3, #16, #8\n\t"
        "LSR	r6, r3, #24\n\t"
        "UBFX	r3, r3, #0, #8\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r3, [r10, r3, LSL #2]\n\t"
        "EOR	r3, r3, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "ADD	%[ks], %[ks], #0x10\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "SUB	%[ks], %[ks], #0x10\n\t"
        "SUBS	r12, r12, #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_set_encrypt_key_loop_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_AES_set_encrypt_key_loop_256\n\t"
#else
        "BNE.N	L_AES_set_encrypt_key_loop_256_%=\n\t"
#endif
        "UBFX	r4, r7, #0, #8\n\t"
        "UBFX	r5, r7, #8, #8\n\t"
        "UBFX	r6, r7, #16, #8\n\t"
        "LSR	r7, r7, #24\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r7, [r10, r7, LSL #2]\n\t"
        "EOR	r3, r7, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r4, r4, r3\n\t"
        "LDM	lr!, {r3}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "ADD	%[ks], %[ks], #0x10\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "SUB	%[ks], %[ks], #0x10\n\t"
#if defined(__GNUC__)
        "B	L_AES_set_encrypt_key_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_set_encrypt_key_end\n\t"
#else
        "B.N	L_AES_set_encrypt_key_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_start_192:\n\t"
#else
    "L_AES_set_encrypt_key_start_192_%=:\n\t"
#endif
        "LDR	r4, [%[key]]\n\t"
        "LDR	r5, [%[key], #4]\n\t"
        "LDR	r6, [%[key], #8]\n\t"
        "LDR	r7, [%[key], #12]\n\t"
        "LDR	r8, [%[key], #16]\n\t"
        "LDR	r9, [%[key], #20]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "REV	r8, r8\n\t"
        "REV	r9, r9\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "STRD	r8, r9, [%[ks], #16]\n\t"
        "MOV	r7, r9\n\t"
        "MOV	r12, #0x7\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_loop_192:\n\t"
#else
    "L_AES_set_encrypt_key_loop_192_%=:\n\t"
#endif
        "UBFX	r4, r9, #0, #8\n\t"
        "UBFX	r5, r9, #8, #8\n\t"
        "UBFX	r6, r9, #16, #8\n\t"
        "LSR	r9, r9, #24\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r9, [r10, r9, LSL #2]\n\t"
        "EOR	r3, r9, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7, r8, r9}\n\t"
        "EOR	r4, r4, r3\n\t"
        "LDM	lr!, {r3}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "EOR	r8, r8, r7\n\t"
        "EOR	r9, r9, r8\n\t"
        "STM	%[ks], {r4, r5, r6, r7, r8, r9}\n\t"
        "SUBS	r12, r12, #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_set_encrypt_key_loop_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_AES_set_encrypt_key_loop_192\n\t"
#else
        "BNE.N	L_AES_set_encrypt_key_loop_192_%=\n\t"
#endif
        "UBFX	r4, r9, #0, #8\n\t"
        "UBFX	r5, r9, #8, #8\n\t"
        "UBFX	r6, r9, #16, #8\n\t"
        "LSR	r9, r9, #24\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r9, [r10, r9, LSL #2]\n\t"
        "EOR	r3, r9, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7, r8, r9}\n\t"
        "EOR	r4, r4, r3\n\t"
        "LDM	lr!, {r3}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
#if defined(__GNUC__)
        "B	L_AES_set_encrypt_key_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_set_encrypt_key_end\n\t"
#else
        "B.N	L_AES_set_encrypt_key_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_start_128:\n\t"
#else
    "L_AES_set_encrypt_key_start_128_%=:\n\t"
#endif
        "LDR	r4, [%[key]]\n\t"
        "LDR	r5, [%[key], #4]\n\t"
        "LDR	r6, [%[key], #8]\n\t"
        "LDR	r7, [%[key], #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "MOV	r12, #0xa\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_loop_128:\n\t"
#else
    "L_AES_set_encrypt_key_loop_128_%=:\n\t"
#endif
        "UBFX	r4, r7, #0, #8\n\t"
        "UBFX	r5, r7, #8, #8\n\t"
        "UBFX	r6, r7, #16, #8\n\t"
        "LSR	r7, r7, #24\n\t"
        "LDRB	r4, [r10, r4, LSL #2]\n\t"
        "LDRB	r5, [r10, r5, LSL #2]\n\t"
        "LDRB	r6, [r10, r6, LSL #2]\n\t"
        "LDRB	r7, [r10, r7, LSL #2]\n\t"
        "EOR	r3, r7, r4, LSL #8\n\t"
        "EOR	r3, r3, r5, LSL #16\n\t"
        "EOR	r3, r3, r6, LSL #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r4, r4, r3\n\t"
        "LDM	lr!, {r3}\n\t"
        "EOR	r4, r4, r3\n\t"
        "EOR	r5, r5, r4\n\t"
        "EOR	r6, r6, r5\n\t"
        "EOR	r7, r7, r6\n\t"
        "STM	%[ks], {r4, r5, r6, r7}\n\t"
        "SUBS	r12, r12, #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_set_encrypt_key_loop_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_AES_set_encrypt_key_loop_128\n\t"
#else
        "BNE.N	L_AES_set_encrypt_key_loop_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_set_encrypt_key_end:\n\t"
#else
    "L_AES_set_encrypt_key_end_%=:\n\t"
#endif
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [key] "+r" (key), [len] "+r" (len), [ks] "+r" (ks),
          [L_AES_Thumb2_te] "+r" (L_AES_Thumb2_te_c), [L_AES_Thumb2_rcon] "+r" (L_AES_Thumb2_rcon_c)
        :
        : "memory", "r12", "lr", "r5", "r6", "r7", "r8", "r9", "r10", "cc"
#else
        : [key] "+r" (key), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_te] "r" (L_AES_Thumb2_te), [L_AES_Thumb2_rcon] "r" (L_AES_Thumb2_rcon)
        : "memory", "r12", "lr", "r5", "r6", "r7", "r8", "r9", "r10", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

void AES_encrypt_block(const word32* te, int nr, int len, const word32* ks);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_encrypt_block(const word32* te_p, int nr_p, int len_p, const word32* ks_p)
#else
void AES_encrypt_block(const word32* te, int nr, int len, const word32* ks)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const word32* te __asm__ ("r0") = (const word32*)te_p;
    register int nr __asm__ ("r1") = (int)nr_p;
    register int len __asm__ ("r2") = (int)len_p;
    register const word32* ks __asm__ ("r3") = (const word32*)ks_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_encrypt_block_nr:\n\t"
#else
    "L_AES_encrypt_block_nr_%=:\n\t"
#endif
        "UBFX	r8, r5, #16, #8\n\t"
        "LSR	r11, r4, #24\n\t"
        "UBFX	lr, r6, #8, #8\n\t"
        "UBFX	r2, r7, #0, #8\n\t"
        "LDR	r8, [%[te], r8, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r9, r6, #16, #8\n\t"
        "EOR	r8, r8, r11, ROR #24\n\t"
        "LSR	r11, r5, #24\n\t"
        "EOR	r8, r8, lr, ROR #8\n\t"
        "UBFX	lr, r7, #8, #8\n\t"
        "EOR	r8, r8, r2, ROR #16\n\t"
        "UBFX	r2, r4, #0, #8\n\t"
        "LDR	r9, [%[te], r9, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r10, r7, #16, #8\n\t"
        "EOR	r9, r9, r11, ROR #24\n\t"
        "LSR	r11, r6, #24\n\t"
        "EOR	r9, r9, lr, ROR #8\n\t"
        "UBFX	lr, r4, #8, #8\n\t"
        "EOR	r9, r9, r2, ROR #16\n\t"
        "UBFX	r2, r5, #0, #8\n\t"
        "LDR	r10, [%[te], r10, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r6, r6, #0, #8\n\t"
        "EOR	r10, r10, r11, ROR #24\n\t"
        "UBFX	r11, r4, #16, #8\n\t"
        "EOR	r10, r10, lr, ROR #8\n\t"
        "LSR	lr, r7, #24\n\t"
        "EOR	r10, r10, r2, ROR #16\n\t"
        "UBFX	r2, r5, #8, #8\n\t"
        "LDR	r6, [%[te], r6, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "EOR	lr, lr, r6, ROR #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r11, r11, lr, ROR #24\n\t"
        "EOR	r11, r11, r2, ROR #8\n\t"
        /*   XOR in Key Schedule */
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "UBFX	r4, r9, #16, #8\n\t"
        "LSR	r7, r8, #24\n\t"
        "UBFX	lr, r10, #8, #8\n\t"
        "UBFX	r2, r11, #0, #8\n\t"
        "LDR	r4, [%[te], r4, LSL #2]\n\t"
        "LDR	r7, [%[te], r7, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r5, r10, #16, #8\n\t"
        "EOR	r4, r4, r7, ROR #24\n\t"
        "LSR	r7, r9, #24\n\t"
        "EOR	r4, r4, lr, ROR #8\n\t"
        "UBFX	lr, r11, #8, #8\n\t"
        "EOR	r4, r4, r2, ROR #16\n\t"
        "UBFX	r2, r8, #0, #8\n\t"
        "LDR	r5, [%[te], r5, LSL #2]\n\t"
        "LDR	r7, [%[te], r7, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r6, r11, #16, #8\n\t"
        "EOR	r5, r5, r7, ROR #24\n\t"
        "LSR	r7, r10, #24\n\t"
        "EOR	r5, r5, lr, ROR #8\n\t"
        "UBFX	lr, r8, #8, #8\n\t"
        "EOR	r5, r5, r2, ROR #16\n\t"
        "UBFX	r2, r9, #0, #8\n\t"
        "LDR	r6, [%[te], r6, LSL #2]\n\t"
        "LDR	r7, [%[te], r7, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r10, r10, #0, #8\n\t"
        "EOR	r6, r6, r7, ROR #24\n\t"
        "UBFX	r7, r8, #16, #8\n\t"
        "EOR	r6, r6, lr, ROR #8\n\t"
        "LSR	lr, r11, #24\n\t"
        "EOR	r6, r6, r2, ROR #16\n\t"
        "UBFX	r2, r9, #8, #8\n\t"
        "LDR	r10, [%[te], r10, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r7, [%[te], r7, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "EOR	lr, lr, r10, ROR #24\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "EOR	r7, r7, lr, ROR #24\n\t"
        "EOR	r7, r7, r2, ROR #8\n\t"
        /*   XOR in Key Schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "SUBS	%[nr], %[nr], #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_encrypt_block_nr_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_encrypt_block_nr\n\t"
#else
        "BNE.W	L_AES_encrypt_block_nr_%=\n\t"
#endif
        "UBFX	r8, r5, #16, #8\n\t"
        "LSR	r11, r4, #24\n\t"
        "UBFX	lr, r6, #8, #8\n\t"
        "UBFX	r2, r7, #0, #8\n\t"
        "LDR	r8, [%[te], r8, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r9, r6, #16, #8\n\t"
        "EOR	r8, r8, r11, ROR #24\n\t"
        "LSR	r11, r5, #24\n\t"
        "EOR	r8, r8, lr, ROR #8\n\t"
        "UBFX	lr, r7, #8, #8\n\t"
        "EOR	r8, r8, r2, ROR #16\n\t"
        "UBFX	r2, r4, #0, #8\n\t"
        "LDR	r9, [%[te], r9, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r10, r7, #16, #8\n\t"
        "EOR	r9, r9, r11, ROR #24\n\t"
        "LSR	r11, r6, #24\n\t"
        "EOR	r9, r9, lr, ROR #8\n\t"
        "UBFX	lr, r4, #8, #8\n\t"
        "EOR	r9, r9, r2, ROR #16\n\t"
        "UBFX	r2, r5, #0, #8\n\t"
        "LDR	r10, [%[te], r10, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r6, r6, #0, #8\n\t"
        "EOR	r10, r10, r11, ROR #24\n\t"
        "UBFX	r11, r4, #16, #8\n\t"
        "EOR	r10, r10, lr, ROR #8\n\t"
        "LSR	lr, r7, #24\n\t"
        "EOR	r10, r10, r2, ROR #16\n\t"
        "UBFX	r2, r5, #8, #8\n\t"
        "LDR	r6, [%[te], r6, LSL #2]\n\t"
        "LDR	lr, [%[te], lr, LSL #2]\n\t"
        "LDR	r11, [%[te], r11, LSL #2]\n\t"
        "LDR	r2, [%[te], r2, LSL #2]\n\t"
        "EOR	lr, lr, r6, ROR #24\n\t"
        "LDM	%[ks]!, {r4, r5, r6, r7}\n\t"
        "EOR	r11, r11, lr, ROR #24\n\t"
        "EOR	r11, r11, r2, ROR #8\n\t"
        /*   XOR in Key Schedule */
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "UBFX	r4, r11, #0, #8\n\t"
        "UBFX	r7, r10, #8, #8\n\t"
        "UBFX	lr, r9, #16, #8\n\t"
        "LSR	r2, r8, #24\n\t"
        "LDRB	r4, [%[te], r4, LSL #2]\n\t"
        "LDRB	r7, [%[te], r7, LSL #2]\n\t"
        "LDRB	lr, [%[te], lr, LSL #2]\n\t"
        "LDRB	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r5, r8, #0, #8\n\t"
        "EOR	r4, r4, r7, LSL #8\n\t"
        "UBFX	r7, r11, #8, #8\n\t"
        "EOR	r4, r4, lr, LSL #16\n\t"
        "UBFX	lr, r10, #16, #8\n\t"
        "EOR	r4, r4, r2, LSL #24\n\t"
        "LSR	r2, r9, #24\n\t"
        "LDRB	r5, [%[te], r5, LSL #2]\n\t"
        "LDRB	r7, [%[te], r7, LSL #2]\n\t"
        "LDRB	lr, [%[te], lr, LSL #2]\n\t"
        "LDRB	r2, [%[te], r2, LSL #2]\n\t"
        "UBFX	r6, r9, #0, #8\n\t"
        "EOR	r5, r5, r7, LSL #8\n\t"
        "UBFX	r7, r8, #8, #8\n\t"
        "EOR	r5, r5, lr, LSL #16\n\t"
        "UBFX	lr, r11, #16, #8\n\t"
        "EOR	r5, r5, r2, LSL #24\n\t"
        "LSR	r2, r10, #24\n\t"
        "LDRB	r6, [%[te], r6, LSL #2]\n\t"
        "LDRB	r7, [%[te], r7, LSL #2]\n\t"
        "LDRB	lr, [%[te], lr, LSL #2]\n\t"
        "LDRB	r2, [%[te], r2, LSL #2]\n\t"
        "LSR	r11, r11, #24\n\t"
        "EOR	r6, r6, r7, LSL #8\n\t"
        "UBFX	r7, r10, #0, #8\n\t"
        "EOR	r6, r6, lr, LSL #16\n\t"
        "UBFX	lr, r9, #8, #8\n\t"
        "EOR	r6, r6, r2, LSL #24\n\t"
        "UBFX	r2, r8, #16, #8\n\t"
        "LDRB	r11, [%[te], r11, LSL #2]\n\t"
        "LDRB	r7, [%[te], r7, LSL #2]\n\t"
        "LDRB	lr, [%[te], lr, LSL #2]\n\t"
        "LDRB	r2, [%[te], r2, LSL #2]\n\t"
        "EOR	lr, lr, r11, LSL #16\n\t"
        "LDM	%[ks], {r8, r9, r10, r11}\n\t"
        "EOR	r7, r7, lr, LSL #8\n\t"
        "EOR	r7, r7, r2, LSL #16\n\t"
        /*   XOR in Key Schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        : [te] "+r" (te), [nr] "+r" (nr), [len] "+r" (len), [ks] "+r" (ks)
        :
        : "memory", "lr", "cc"
    );
}

#if defined(HAVE_AES_CBC) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
static const word32* L_AES_Thumb2_te_ecb = L_AES_Thumb2_te_data;
#endif /* HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_ECB_encrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p)
#else
void AES_ECB_encrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register word32* L_AES_Thumb2_te_ecb_c __asm__ ("r5") = (word32*)L_AES_Thumb2_te_ecb;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_te_ecb]\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r12, r4\n\t"
#else
        "LDR	r12, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "PUSH	{%[ks]}\n\t"
        "CMP	r12, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_ECB_encrypt_start_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_ECB_encrypt_start_block_128\n\t"
#else
        "BEQ.W	L_AES_ECB_encrypt_start_block_128_%=\n\t"
#endif
        "CMP	r12, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_ECB_encrypt_start_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_ECB_encrypt_start_block_192\n\t"
#else
        "BEQ.W	L_AES_ECB_encrypt_start_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_loop_block_256:\n\t"
#else
    "L_AES_ECB_encrypt_loop_block_256_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_encrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_encrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_ECB_encrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_ECB_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_ECB_encrypt_end\n\t"
#else
        "B.N	L_AES_ECB_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_start_block_192:\n\t"
#else
    "L_AES_ECB_encrypt_start_block_192_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_loop_block_192:\n\t"
#else
    "L_AES_ECB_encrypt_loop_block_192_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_encrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_encrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_ECB_encrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_ECB_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_ECB_encrypt_end\n\t"
#else
        "B.N	L_AES_ECB_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_start_block_128:\n\t"
#else
    "L_AES_ECB_encrypt_start_block_128_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_loop_block_128:\n\t"
#else
    "L_AES_ECB_encrypt_loop_block_128_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_encrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_encrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_ECB_encrypt_loop_block_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_encrypt_end:\n\t"
#else
    "L_AES_ECB_encrypt_end_%=:\n\t"
#endif
        "POP	{%[ks]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr),
          [L_AES_Thumb2_te_ecb] "+r" (L_AES_Thumb2_te_ecb_c)
        :
        : "memory", "r12", "lr", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_te_ecb] "r" (L_AES_Thumb2_te_ecb)
        : "memory", "r12", "lr", "r4", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_CBC
void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CBC_encrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p, unsigned char* iv_p)
#else
void AES_CBC_encrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register unsigned char* iv __asm__ ("r5") = (unsigned char*)iv_p;
    register word32* L_AES_Thumb2_te_ecb_c __asm__ ("r6") = (word32*)L_AES_Thumb2_te_ecb;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r8, r4\n\t"
#else
        "LDR	r8, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r9, r5\n\t"
#else
        "LDR	r9, [sp, #40]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_te_ecb]\n\t"
        "LDM	r9, {r4, r5, r6, r7}\n\t"
        "PUSH	{%[ks], r9}\n\t"
        "CMP	r8, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_encrypt_start_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_encrypt_start_block_128\n\t"
#else
        "BEQ.W	L_AES_CBC_encrypt_start_block_128_%=\n\t"
#endif
        "CMP	r8, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_encrypt_start_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_encrypt_start_block_192\n\t"
#else
        "BEQ.W	L_AES_CBC_encrypt_start_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_loop_block_256:\n\t"
#else
    "L_AES_CBC_encrypt_loop_block_256_%=:\n\t"
#endif
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_encrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_encrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_CBC_encrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CBC_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_CBC_encrypt_end\n\t"
#else
        "B.N	L_AES_CBC_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_start_block_192:\n\t"
#else
    "L_AES_CBC_encrypt_start_block_192_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_loop_block_192:\n\t"
#else
    "L_AES_CBC_encrypt_loop_block_192_%=:\n\t"
#endif
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_encrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_encrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_CBC_encrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CBC_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_CBC_encrypt_end\n\t"
#else
        "B.N	L_AES_CBC_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_start_block_128:\n\t"
#else
    "L_AES_CBC_encrypt_start_block_128_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_loop_block_128:\n\t"
#else
    "L_AES_CBC_encrypt_loop_block_128_%=:\n\t"
#endif
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "PUSH	{r1, %[len], lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_encrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_encrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_CBC_encrypt_loop_block_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_encrypt_end:\n\t"
#else
    "L_AES_CBC_encrypt_end_%=:\n\t"
#endif
        "POP	{%[ks], r9}\n\t"
        "STM	r9, {r4, r5, r6, r7}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr), [iv] "+r" (iv),
          [L_AES_Thumb2_te_ecb] "+r" (L_AES_Thumb2_te_ecb_c)
        :
        : "memory", "r12", "lr", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_te_ecb] "r" (L_AES_Thumb2_te_ecb)
        : "memory", "r12", "lr", "r4", "r5", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)iv;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
void AES_CTR_encrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CTR_encrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p, unsigned char* ctr_p)
#else
void AES_CTR_encrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register unsigned char* ctr __asm__ ("r5") = (unsigned char*)ctr_p;
    register word32* L_AES_Thumb2_te_ecb_c __asm__ ("r6") = (word32*)L_AES_Thumb2_te_ecb;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r12, r4\n\t"
#else
        "LDR	r12, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r8, r5\n\t"
#else
        "LDR	r8, [sp, #40]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_te_ecb]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	r8, {r4, r5, r6, r7}\n\t"
        "PUSH	{%[ks], r8}\n\t"
        "CMP	r12, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CTR_encrypt_start_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CTR_encrypt_start_block_128\n\t"
#else
        "BEQ.W	L_AES_CTR_encrypt_start_block_128_%=\n\t"
#endif
        "CMP	r12, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CTR_encrypt_start_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CTR_encrypt_start_block_192\n\t"
#else
        "BEQ.W	L_AES_CTR_encrypt_start_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_loop_block_256:\n\t"
#else
    "L_AES_CTR_encrypt_loop_block_256_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADDS	r11, r7, #0x1\n\t"
        "ADCS	r10, r6, #0x0\n\t"
        "ADCS	r9, r5, #0x0\n\t"
        "ADC	r8, r4, #0x0\n\t"
        "STM	lr, {r8, r9, r10, r11}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CTR_encrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CTR_encrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_CTR_encrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CTR_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_CTR_encrypt_end\n\t"
#else
        "B.W	L_AES_CTR_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_start_block_192:\n\t"
#else
    "L_AES_CTR_encrypt_start_block_192_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_loop_block_192:\n\t"
#else
    "L_AES_CTR_encrypt_loop_block_192_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADDS	r11, r7, #0x1\n\t"
        "ADCS	r10, r6, #0x0\n\t"
        "ADCS	r9, r5, #0x0\n\t"
        "ADC	r8, r4, #0x0\n\t"
        "STM	lr, {r8, r9, r10, r11}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CTR_encrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CTR_encrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_CTR_encrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CTR_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_CTR_encrypt_end\n\t"
#else
        "B.W	L_AES_CTR_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_start_block_128:\n\t"
#else
    "L_AES_CTR_encrypt_start_block_128_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_loop_block_128:\n\t"
#else
    "L_AES_CTR_encrypt_loop_block_128_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADDS	r11, r7, #0x1\n\t"
        "ADCS	r10, r6, #0x0\n\t"
        "ADCS	r9, r5, #0x0\n\t"
        "ADC	r8, r4, #0x0\n\t"
        "STM	lr, {r8, r9, r10, r11}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CTR_encrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CTR_encrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_CTR_encrypt_loop_block_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CTR_encrypt_end:\n\t"
#else
    "L_AES_CTR_encrypt_end_%=:\n\t"
#endif
        "POP	{%[ks], r8}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	r8, {r4, r5, r6, r7}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr), [ctr] "+r" (ctr),
          [L_AES_Thumb2_te_ecb] "+r" (L_AES_Thumb2_te_ecb_c)
        :
        : "memory", "r12", "lr", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_te_ecb] "r" (L_AES_Thumb2_te_ecb)
        : "memory", "r12", "lr", "r4", "r5", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)ctr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_CBC)
void AES_decrypt_block(const word32* td, int nr, const byte* td4);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_decrypt_block(const word32* td_p, int nr_p, const byte* td4_p)
#else
void AES_decrypt_block(const word32* td, int nr, const byte* td4)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const word32* td __asm__ ("r0") = (const word32*)td_p;
    register int nr __asm__ ("r1") = (int)nr_p;
    register const byte* td4 __asm__ ("r2") = (const byte*)td4_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_decrypt_block_nr:\n\t"
#else
    "L_AES_decrypt_block_nr_%=:\n\t"
#endif
        "UBFX	r8, r7, #16, #8\n\t"
        "LSR	r11, r4, #24\n\t"
        "UBFX	r12, r6, #8, #8\n\t"
        "UBFX	lr, r5, #0, #8\n\t"
        "LDR	r8, [%[td], r8, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r9, r4, #16, #8\n\t"
        "EOR	r8, r8, r11, ROR #24\n\t"
        "LSR	r11, r5, #24\n\t"
        "EOR	r8, r8, r12, ROR #8\n\t"
        "UBFX	r12, r7, #8, #8\n\t"
        "EOR	r8, r8, lr, ROR #16\n\t"
        "UBFX	lr, r6, #0, #8\n\t"
        "LDR	r9, [%[td], r9, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r10, r5, #16, #8\n\t"
        "EOR	r9, r9, r11, ROR #24\n\t"
        "LSR	r11, r6, #24\n\t"
        "EOR	r9, r9, r12, ROR #8\n\t"
        "UBFX	r12, r4, #8, #8\n\t"
        "EOR	r9, r9, lr, ROR #16\n\t"
        "UBFX	lr, r7, #0, #8\n\t"
        "LDR	r10, [%[td], r10, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r4, r4, #0, #8\n\t"
        "EOR	r10, r10, r11, ROR #24\n\t"
        "UBFX	r11, r6, #16, #8\n\t"
        "EOR	r10, r10, r12, ROR #8\n\t"
        "LSR	r12, r7, #24\n\t"
        "EOR	r10, r10, lr, ROR #16\n\t"
        "UBFX	lr, r5, #8, #8\n\t"
        "LDR	r4, [%[td], r4, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "EOR	r12, r12, r4, ROR #24\n\t"
        "LDM	r3!, {r4, r5, r6, r7}\n\t"
        "EOR	r11, r11, lr, ROR #8\n\t"
        "EOR	r11, r11, r12, ROR #24\n\t"
        /*   XOR in Key Schedule */
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "UBFX	r4, r11, #16, #8\n\t"
        "LSR	r7, r8, #24\n\t"
        "UBFX	r12, r10, #8, #8\n\t"
        "UBFX	lr, r9, #0, #8\n\t"
        "LDR	r4, [%[td], r4, LSL #2]\n\t"
        "LDR	r7, [%[td], r7, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r5, r8, #16, #8\n\t"
        "EOR	r4, r4, r7, ROR #24\n\t"
        "LSR	r7, r9, #24\n\t"
        "EOR	r4, r4, r12, ROR #8\n\t"
        "UBFX	r12, r11, #8, #8\n\t"
        "EOR	r4, r4, lr, ROR #16\n\t"
        "UBFX	lr, r10, #0, #8\n\t"
        "LDR	r5, [%[td], r5, LSL #2]\n\t"
        "LDR	r7, [%[td], r7, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r6, r9, #16, #8\n\t"
        "EOR	r5, r5, r7, ROR #24\n\t"
        "LSR	r7, r10, #24\n\t"
        "EOR	r5, r5, r12, ROR #8\n\t"
        "UBFX	r12, r8, #8, #8\n\t"
        "EOR	r5, r5, lr, ROR #16\n\t"
        "UBFX	lr, r11, #0, #8\n\t"
        "LDR	r6, [%[td], r6, LSL #2]\n\t"
        "LDR	r7, [%[td], r7, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r8, r8, #0, #8\n\t"
        "EOR	r6, r6, r7, ROR #24\n\t"
        "UBFX	r7, r10, #16, #8\n\t"
        "EOR	r6, r6, r12, ROR #8\n\t"
        "LSR	r12, r11, #24\n\t"
        "EOR	r6, r6, lr, ROR #16\n\t"
        "UBFX	lr, r9, #8, #8\n\t"
        "LDR	r8, [%[td], r8, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	r7, [%[td], r7, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "EOR	r12, r12, r8, ROR #24\n\t"
        "LDM	r3!, {r8, r9, r10, r11}\n\t"
        "EOR	r7, r7, lr, ROR #8\n\t"
        "EOR	r7, r7, r12, ROR #24\n\t"
        /*   XOR in Key Schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "SUBS	%[nr], %[nr], #0x1\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_decrypt_block_nr_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_decrypt_block_nr\n\t"
#else
        "BNE.W	L_AES_decrypt_block_nr_%=\n\t"
#endif
        "UBFX	r8, r7, #16, #8\n\t"
        "LSR	r11, r4, #24\n\t"
        "UBFX	r12, r6, #8, #8\n\t"
        "UBFX	lr, r5, #0, #8\n\t"
        "LDR	r8, [%[td], r8, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r9, r4, #16, #8\n\t"
        "EOR	r8, r8, r11, ROR #24\n\t"
        "LSR	r11, r5, #24\n\t"
        "EOR	r8, r8, r12, ROR #8\n\t"
        "UBFX	r12, r7, #8, #8\n\t"
        "EOR	r8, r8, lr, ROR #16\n\t"
        "UBFX	lr, r6, #0, #8\n\t"
        "LDR	r9, [%[td], r9, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r10, r5, #16, #8\n\t"
        "EOR	r9, r9, r11, ROR #24\n\t"
        "LSR	r11, r6, #24\n\t"
        "EOR	r9, r9, r12, ROR #8\n\t"
        "UBFX	r12, r4, #8, #8\n\t"
        "EOR	r9, r9, lr, ROR #16\n\t"
        "UBFX	lr, r7, #0, #8\n\t"
        "LDR	r10, [%[td], r10, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "UBFX	r4, r4, #0, #8\n\t"
        "EOR	r10, r10, r11, ROR #24\n\t"
        "UBFX	r11, r6, #16, #8\n\t"
        "EOR	r10, r10, r12, ROR #8\n\t"
        "LSR	r12, r7, #24\n\t"
        "EOR	r10, r10, lr, ROR #16\n\t"
        "UBFX	lr, r5, #8, #8\n\t"
        "LDR	r4, [%[td], r4, LSL #2]\n\t"
        "LDR	r12, [%[td], r12, LSL #2]\n\t"
        "LDR	r11, [%[td], r11, LSL #2]\n\t"
        "LDR	lr, [%[td], lr, LSL #2]\n\t"
        "EOR	r12, r12, r4, ROR #24\n\t"
        "LDM	r3!, {r4, r5, r6, r7}\n\t"
        "EOR	r11, r11, lr, ROR #8\n\t"
        "EOR	r11, r11, r12, ROR #24\n\t"
        /*   XOR in Key Schedule */
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "UBFX	r4, r9, #0, #8\n\t"
        "UBFX	r7, r10, #8, #8\n\t"
        "UBFX	r12, r11, #16, #8\n\t"
        "LSR	lr, r8, #24\n\t"
        "LDRB	r4, [%[td4], r4]\n\t"
        "LDRB	r7, [%[td4], r7]\n\t"
        "LDRB	r12, [%[td4], r12]\n\t"
        "LDRB	lr, [%[td4], lr]\n\t"
        "UBFX	r5, r10, #0, #8\n\t"
        "EOR	r4, r4, r7, LSL #8\n\t"
        "UBFX	r7, r11, #8, #8\n\t"
        "EOR	r4, r4, r12, LSL #16\n\t"
        "UBFX	r12, r8, #16, #8\n\t"
        "EOR	r4, r4, lr, LSL #24\n\t"
        "LSR	lr, r9, #24\n\t"
        "LDRB	r7, [%[td4], r7]\n\t"
        "LDRB	lr, [%[td4], lr]\n\t"
        "LDRB	r5, [%[td4], r5]\n\t"
        "LDRB	r12, [%[td4], r12]\n\t"
        "UBFX	r6, r11, #0, #8\n\t"
        "EOR	r5, r5, r7, LSL #8\n\t"
        "UBFX	r7, r8, #8, #8\n\t"
        "EOR	r5, r5, r12, LSL #16\n\t"
        "UBFX	r12, r9, #16, #8\n\t"
        "EOR	r5, r5, lr, LSL #24\n\t"
        "LSR	lr, r10, #24\n\t"
        "LDRB	r7, [%[td4], r7]\n\t"
        "LDRB	lr, [%[td4], lr]\n\t"
        "LDRB	r6, [%[td4], r6]\n\t"
        "LDRB	r12, [%[td4], r12]\n\t"
        "LSR	r11, r11, #24\n\t"
        "EOR	r6, r6, r7, LSL #8\n\t"
        "UBFX	r7, r8, #0, #8\n\t"
        "EOR	r6, r6, r12, LSL #16\n\t"
        "UBFX	r12, r9, #8, #8\n\t"
        "EOR	r6, r6, lr, LSL #24\n\t"
        "UBFX	lr, r10, #16, #8\n\t"
        "LDRB	r11, [%[td4], r11]\n\t"
        "LDRB	r12, [%[td4], r12]\n\t"
        "LDRB	r7, [%[td4], r7]\n\t"
        "LDRB	lr, [%[td4], lr]\n\t"
        "EOR	r12, r12, r11, LSL #16\n\t"
        "LDM	r3, {r8, r9, r10, r11}\n\t"
        "EOR	r7, r7, r12, LSL #8\n\t"
        "EOR	r7, r7, lr, LSL #16\n\t"
        /*   XOR in Key Schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        : [td] "+r" (td), [nr] "+r" (nr), [td4] "+r" (td4)
        :
        : "memory", "lr", "cc"
    );
}

static const word32* L_AES_Thumb2_td_ecb = L_AES_Thumb2_td_data;
static const byte L_AES_Thumb2_td4[] = {
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

#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_ECB_decrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p)
#else
void AES_ECB_decrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register word32* L_AES_Thumb2_td_ecb_c __asm__ ("r5") = (word32*)L_AES_Thumb2_td_ecb;
    register byte* L_AES_Thumb2_td4_c __asm__ ("r6") = (byte*)&L_AES_Thumb2_td4;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r8, r4\n\t"
#else
        "LDR	r8, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_td_ecb]\n\t"
        "MOV	r12, %[len]\n\t"
        "MOV	r2, %[L_AES_Thumb2_td4]\n\t"
        "CMP	r8, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_ECB_decrypt_start_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_ECB_decrypt_start_block_128\n\t"
#else
        "BEQ.W	L_AES_ECB_decrypt_start_block_128_%=\n\t"
#endif
        "CMP	r8, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_ECB_decrypt_start_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_ECB_decrypt_start_block_192\n\t"
#else
        "BEQ.W	L_AES_ECB_decrypt_start_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_loop_block_256:\n\t"
#else
    "L_AES_ECB_decrypt_loop_block_256_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[ks], r12, lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_decrypt_block\n\t"
        "POP	{r1, %[ks], r12, lr}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_decrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_decrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_ECB_decrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_ECB_decrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_ECB_decrypt_end\n\t"
#else
        "B.N	L_AES_ECB_decrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_start_block_192:\n\t"
#else
    "L_AES_ECB_decrypt_start_block_192_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_loop_block_192:\n\t"
#else
    "L_AES_ECB_decrypt_loop_block_192_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[ks], r12, lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_decrypt_block\n\t"
        "POP	{r1, %[ks], r12, lr}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_decrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_decrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_ECB_decrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_ECB_decrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_ECB_decrypt_end\n\t"
#else
        "B.N	L_AES_ECB_decrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_start_block_128:\n\t"
#else
    "L_AES_ECB_decrypt_start_block_128_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_loop_block_128:\n\t"
#else
    "L_AES_ECB_decrypt_loop_block_128_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "PUSH	{r1, %[ks], r12, lr}\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_decrypt_block\n\t"
        "POP	{r1, %[ks], r12, lr}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_ECB_decrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_ECB_decrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_ECB_decrypt_loop_block_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_ECB_decrypt_end:\n\t"
#else
    "L_AES_ECB_decrypt_end_%=:\n\t"
#endif
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr),
          [L_AES_Thumb2_td_ecb] "+r" (L_AES_Thumb2_td_ecb_c), [L_AES_Thumb2_td4] "+r" (L_AES_Thumb2_td4_c)
        :
        : "memory", "r12", "lr", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_td_ecb] "r" (L_AES_Thumb2_td_ecb), [L_AES_Thumb2_td4] "r" (L_AES_Thumb2_td4)
        : "memory", "r12", "lr", "r4", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_CBC
void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr, unsigned char* iv);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_CBC_decrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p, unsigned char* iv_p)
#else
void AES_CBC_decrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register unsigned char* iv __asm__ ("r5") = (unsigned char*)iv_p;
    register word32* L_AES_Thumb2_td_ecb_c __asm__ ("r6") = (word32*)L_AES_Thumb2_td_ecb;
    register byte* L_AES_Thumb2_td4_c __asm__ ("r7") = (byte*)&L_AES_Thumb2_td4;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r8, r4\n\t"
#else
        "LDR	r8, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r4, r5\n\t"
#else
        "LDR	r4, [sp, #40]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_td_ecb]\n\t"
        "MOV	r12, %[len]\n\t"
        "MOV	r2, %[L_AES_Thumb2_td4]\n\t"
        "PUSH	{%[ks], r4}\n\t"
        "CMP	r8, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_decrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_decrypt_loop_block_128\n\t"
#else
        "BEQ.W	L_AES_CBC_decrypt_loop_block_128_%=\n\t"
#endif
        "CMP	r8, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_decrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_decrypt_loop_block_192\n\t"
#else
        "BEQ.W	L_AES_CBC_decrypt_loop_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_decrypt_loop_block_256:\n\t"
#else
    "L_AES_CBC_decrypt_loop_block_256_%=:\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr, #16]\n\t"
        "STRD	r6, r7, [lr, #24]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDM	lr, {r8, r9, r10, r11}\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_decrypt_end_odd_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_decrypt_end_odd\n\t"
#else
        "BEQ.W	L_AES_CBC_decrypt_end_odd_%=\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr]\n\t"
        "STRD	r6, r7, [lr, #8]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDRD	r8, r9, [lr, #16]\n\t"
        "LDRD	r10, r11, [lr, #24]\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_decrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_decrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_CBC_decrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CBC_decrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_CBC_decrypt_end\n\t"
#else
        "B.W	L_AES_CBC_decrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_decrypt_loop_block_192:\n\t"
#else
    "L_AES_CBC_decrypt_loop_block_192_%=:\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr, #16]\n\t"
        "STRD	r6, r7, [lr, #24]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDM	lr, {r8, r9, r10, r11}\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_decrypt_end_odd_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_decrypt_end_odd\n\t"
#else
        "BEQ.W	L_AES_CBC_decrypt_end_odd_%=\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr]\n\t"
        "STRD	r6, r7, [lr, #8]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDRD	r8, r9, [lr, #16]\n\t"
        "LDRD	r10, r11, [lr, #24]\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_decrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_decrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_CBC_decrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CBC_decrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_CBC_decrypt_end\n\t"
#else
        "B.W	L_AES_CBC_decrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_decrypt_loop_block_128:\n\t"
#else
    "L_AES_CBC_decrypt_loop_block_128_%=:\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr, #16]\n\t"
        "STRD	r6, r7, [lr, #24]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDM	lr, {r8, r9, r10, r11}\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_CBC_decrypt_end_odd_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_CBC_decrypt_end_odd\n\t"
#else
        "BEQ.W	L_AES_CBC_decrypt_end_odd_%=\n\t"
#endif
        "PUSH	{r1, r12, lr}\n\t"
        "LDR	r4, [lr]\n\t"
        "LDR	r5, [lr, #4]\n\t"
        "LDR	r6, [lr, #8]\n\t"
        "LDR	r7, [lr, #12]\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "STRD	r4, r5, [lr]\n\t"
        "STRD	r6, r7, [lr, #8]\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_decrypt_block\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDRD	r8, r9, [lr, #16]\n\t"
        "LDRD	r10, r11, [lr, #24]\n\t"
        "POP	{r1, r12, lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "SUBS	r12, r12, #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_CBC_decrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_CBC_decrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_CBC_decrypt_loop_block_128_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_CBC_decrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_AES_CBC_decrypt_end\n\t"
#else
        "B.N	L_AES_CBC_decrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_decrypt_end_odd:\n\t"
#else
    "L_AES_CBC_decrypt_end_odd_%=:\n\t"
#endif
        "LDR	r4, [sp, #4]\n\t"
        "LDRD	r8, r9, [r4, #16]\n\t"
        "LDRD	r10, r11, [r4, #24]\n\t"
        "STRD	r8, r9, [r4]\n\t"
        "STRD	r10, r11, [r4, #8]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_CBC_decrypt_end:\n\t"
#else
    "L_AES_CBC_decrypt_end_%=:\n\t"
#endif
        "POP	{%[ks], r4}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr), [iv] "+r" (iv),
          [L_AES_Thumb2_td_ecb] "+r" (L_AES_Thumb2_td_ecb_c), [L_AES_Thumb2_td4] "+r" (L_AES_Thumb2_td4_c)
        :
        : "memory", "r12", "lr", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_td_ecb] "r" (L_AES_Thumb2_td_ecb), [L_AES_Thumb2_td4] "r" (L_AES_Thumb2_td4)
        : "memory", "r12", "lr", "r4", "r5", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)iv;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
XALIGNED(16) static const word32 L_GCM_gmult_len_r[] = {
    0x00000000, 0x1c200000, 0x38400000, 0x24600000,
    0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
    0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
    0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000,
};

void GCM_gmult_len(unsigned char* x, const unsigned char** m,
        const unsigned char* data, unsigned long len);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void GCM_gmult_len(unsigned char* x_p, const unsigned char** m_p, const unsigned char* data_p, unsigned long len_p)
#else
void GCM_gmult_len(unsigned char* x, const unsigned char** m, const unsigned char* data, unsigned long len)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register unsigned char* x __asm__ ("r0") = (unsigned char*)x_p;
    register const unsigned char** m __asm__ ("r1") = (const unsigned char**)m_p;
    register const unsigned char* data __asm__ ("r2") = (const unsigned char*)data_p;
    register unsigned long len __asm__ ("r3") = (unsigned long)len_p;
    register word32* L_GCM_gmult_len_r_c __asm__ ("r4") = (word32*)&L_GCM_gmult_len_r;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "MOV	lr, %[L_GCM_gmult_len_r]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_GCM_gmult_len_start_block:\n\t"
#else
    "L_GCM_gmult_len_start_block_%=:\n\t"
#endif
        "PUSH	{r3}\n\t"
        "LDR	r12, [r0, #12]\n\t"
        "LDR	%[len], [r2, #12]\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "LSR	%[len], r12, #24\n\t"
        "AND	%[len], %[len], #0xf\n\t"
        "ADD	%[len], %[m], %[len], LSL #4\n\t"
        "LDM	%[len], {r8, r9, r10, r11}\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #28\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #16\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #20\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #8\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #12\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "AND	r4, r12, #0xf\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "LDR	r12, [r0, #8]\n\t"
        "LDR	%[len], [r2, #8]\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "LSR	%[len], r12, #24\n\t"
        "AND	%[len], %[len], #0xf\n\t"
        "ADD	%[len], %[m], %[len], LSL #4\n\t"
        "LDM	%[len], {r4, r5, r6, r7}\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #28\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #16\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #20\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #8\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #12\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "AND	r4, r12, #0xf\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "LDR	r12, [r0, #4]\n\t"
        "LDR	%[len], [r2, #4]\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "LSR	%[len], r12, #24\n\t"
        "AND	%[len], %[len], #0xf\n\t"
        "ADD	%[len], %[m], %[len], LSL #4\n\t"
        "LDM	%[len], {r4, r5, r6, r7}\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #28\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #16\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #20\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #8\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #12\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "AND	r4, r12, #0xf\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "LDR	r12, [r0]\n\t"
        "LDR	%[len], [r2]\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "LSR	%[len], r12, #24\n\t"
        "AND	%[len], %[len], #0xf\n\t"
        "ADD	%[len], %[m], %[len], LSL #4\n\t"
        "LDM	%[len], {r4, r5, r6, r7}\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #28\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #16\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #20\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #8\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #12\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "AND	r4, r12, #0xf\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "LSR	r6, r10, #4\n\t"
        "AND	%[len], r11, #0xf\n\t"
        "LSR	r11, r11, #4\n\t"
        "LSR	r4, r12, #4\n\t"
        "EOR	r11, r11, r10, LSL #28\n\t"
        "AND	r4, r4, #0xf\n\t"
        "LDR	%[len], [lr, r3, LSL #2]\n\t"
        "ADD	r4, %[m], r4, LSL #4\n\t"
        "EOR	r10, r6, r9, LSL #28\n\t"
        "LSR	r9, r9, #4\n\t"
        "LDM	r4, {r4, r5, r6, r7}\n\t"
        "EOR	r9, r9, r8, LSL #28\n\t"
        "EOR	r8, %[len], r8, LSR #4\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "REV	r8, r8\n\t"
        "REV	r9, r9\n\t"
        "REV	r10, r10\n\t"
        "REV	r11, r11\n\t"
        "STM	%[x], {r8, r9, r10, r11}\n\t"
        "POP	{r3}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	%[data], %[data], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_GCM_gmult_len_start_block_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_GCM_gmult_len_start_block\n\t"
#else
        "BNE.W	L_GCM_gmult_len_start_block_%=\n\t"
#endif
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [m] "+r" (m), [data] "+r" (data), [len] "+r" (len),
          [L_GCM_gmult_len_r] "+r" (L_GCM_gmult_len_r_c)
        :
        : "memory", "r12", "lr", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [x] "+r" (x), [m] "+r" (m), [data] "+r" (data), [len] "+r" (len)
        : [L_GCM_gmult_len_r] "r" (L_GCM_gmult_len_r)
        : "memory", "r12", "lr", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

static const word32* L_AES_Thumb2_te_gcm = L_AES_Thumb2_te_data;
void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
        unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void AES_GCM_encrypt(const unsigned char* in_p, unsigned char* out_p, unsigned long len_p, const unsigned char* ks_p, int nr_p, unsigned char* ctr_p)
#else
void AES_GCM_encrypt(const unsigned char* in, unsigned char* out, unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const unsigned char* in __asm__ ("r0") = (const unsigned char*)in_p;
    register unsigned char* out __asm__ ("r1") = (unsigned char*)out_p;
    register unsigned long len __asm__ ("r2") = (unsigned long)len_p;
    register const unsigned char* ks __asm__ ("r3") = (const unsigned char*)ks_p;
    register int nr __asm__ ("r4") = (int)nr_p;
    register unsigned char* ctr __asm__ ("r5") = (unsigned char*)ctr_p;
    register word32* L_AES_Thumb2_te_gcm_c __asm__ ("r6") = (word32*)L_AES_Thumb2_te_gcm;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r12, r4\n\t"
#else
        "LDR	r12, [sp, #36]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        "MOV	r8, r5\n\t"
#else
        "LDR	r8, [sp, #40]\n\t"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        "MOV	lr, %[in]\n\t"
        "MOV	r0, %[L_AES_Thumb2_te_gcm]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	r8, {r4, r5, r6, r7}\n\t"
        "PUSH	{%[ks], r8}\n\t"
        "CMP	r12, #0xa\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_GCM_encrypt_start_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_GCM_encrypt_start_block_128\n\t"
#else
        "BEQ.W	L_AES_GCM_encrypt_start_block_128_%=\n\t"
#endif
        "CMP	r12, #0xc\n\t"
#if defined(__GNUC__)
        "BEQ	L_AES_GCM_encrypt_start_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.W	L_AES_GCM_encrypt_start_block_192\n\t"
#else
        "BEQ.W	L_AES_GCM_encrypt_start_block_192_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_loop_block_256:\n\t"
#else
    "L_AES_GCM_encrypt_loop_block_256_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADD	r7, r7, #0x1\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "STR	r7, [lr, #12]\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x6\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_GCM_encrypt_loop_block_256_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_GCM_encrypt_loop_block_256\n\t"
#else
        "BNE.W	L_AES_GCM_encrypt_loop_block_256_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_GCM_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_GCM_encrypt_end\n\t"
#else
        "B.W	L_AES_GCM_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_start_block_192:\n\t"
#else
    "L_AES_GCM_encrypt_start_block_192_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_loop_block_192:\n\t"
#else
    "L_AES_GCM_encrypt_loop_block_192_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADD	r7, r7, #0x1\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "STR	r7, [lr, #12]\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x5\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_GCM_encrypt_loop_block_192_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_GCM_encrypt_loop_block_192\n\t"
#else
        "BNE.W	L_AES_GCM_encrypt_loop_block_192_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_AES_GCM_encrypt_end_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.W	L_AES_GCM_encrypt_end\n\t"
#else
        "B.W	L_AES_GCM_encrypt_end_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_start_block_128:\n\t"
#else
    "L_AES_GCM_encrypt_start_block_128_%=:\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_loop_block_128:\n\t"
#else
    "L_AES_GCM_encrypt_loop_block_128_%=:\n\t"
#endif
        "PUSH	{r1, %[len], lr}\n\t"
        "LDR	lr, [sp, #16]\n\t"
        "ADD	r7, r7, #0x1\n\t"
        "LDM	%[ks]!, {r8, r9, r10, r11}\n\t"
        "STR	r7, [lr, #12]\n\t"
        /* Round: 0 - XOR in key schedule */
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "MOV	r1, #0x4\n\t"
        "BL	AES_encrypt_block\n\t"
        "POP	{r1, %[len], lr}\n\t"
        "LDR	%[ks], [sp]\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "LDR	r8, [lr]\n\t"
        "LDR	r9, [lr, #4]\n\t"
        "LDR	r10, [lr, #8]\n\t"
        "LDR	r11, [lr, #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "LDR	r8, [sp, #4]\n\t"
        "STR	r4, [%[out]]\n\t"
        "STR	r5, [%[out], #4]\n\t"
        "STR	r6, [%[out], #8]\n\t"
        "STR	r7, [%[out], #12]\n\t"
        "LDM	r8, {r4, r5, r6, r7}\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "ADD	lr, lr, #0x10\n\t"
        "ADD	%[out], %[out], #0x10\n\t"
#if defined(__GNUC__)
        "BNE	L_AES_GCM_encrypt_loop_block_128_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.W	L_AES_GCM_encrypt_loop_block_128\n\t"
#else
        "BNE.W	L_AES_GCM_encrypt_loop_block_128_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_AES_GCM_encrypt_end:\n\t"
#else
    "L_AES_GCM_encrypt_end_%=:\n\t"
#endif
        "POP	{%[ks], r8}\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
        "REV	r7, r7\n\t"
        "STM	r8, {r4, r5, r6, r7}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks), [nr] "+r" (nr), [ctr] "+r" (ctr),
          [L_AES_Thumb2_te_gcm] "+r" (L_AES_Thumb2_te_gcm_c)
        :
        : "memory", "r12", "lr", "r7", "r8", "r9", "r10", "r11", "cc"
#else
        : [in] "+r" (in), [out] "+r" (out), [len] "+r" (len), [ks] "+r" (ks)
        : [L_AES_Thumb2_te_gcm] "r" (L_AES_Thumb2_te_gcm)
        : "memory", "r12", "lr", "r4", "r5", "r7", "r8", "r9", "r10", "r11", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)nr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)ctr;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
