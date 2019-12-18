/* sp.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

/* Implementation by Sean Parkinson. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH) || \
                                    defined(WOLFSSL_HAVE_SP_ECC)

#ifdef RSA_LOW_MEM
#ifndef SP_RSA_PRIVATE_EXP_D
#define SP_RSA_PRIVATE_EXP_D
#endif

#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifndef WOLFSSL_SP_ASM
#if SP_WORD_SIZE == 64
#if (defined(WOLFSSL_SP_CACHE_RESISTANT) || defined(WOLFSSL_SP_SMALL)) &&              (defined(WOLFSSL_HAVE_SP_ECC) || !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Mask for address to obfuscate which of the two address will be used. */
static const size_t addr_mask[2] = { 0, (size_t)-1 };
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)
#ifndef WOLFSSL_SP_NO_2048
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_2048_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 49U) {
            r[j] &= 0x1ffffffffffffffL;
            s = 57U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_2048_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 57
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 57
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1ffffffffffffffL;
        s = 57U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 57U) <= (word32)DIGIT_BIT) {
            s += 57U;
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = 0L;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 57) {
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 57 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 256
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_2048_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<35; i++) {
        r[i+1] += r[i] >> 57;
        r[i] &= 0x1ffffffffffffffL;
    }
    j = 2048 / 8 - 1;
    a[j] = 0;
    for (i=0; i<36 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); b += 8 - s; /*lint !e9033*/
        if (j < 0) {
            break;
        }
        while (b < 57) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 57);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int128_t t0   = ((int128_t)a[ 0]) * b[ 0];
    int128_t t1   = ((int128_t)a[ 0]) * b[ 1]
                 + ((int128_t)a[ 1]) * b[ 0];
    int128_t t2   = ((int128_t)a[ 0]) * b[ 2]
                 + ((int128_t)a[ 1]) * b[ 1]
                 + ((int128_t)a[ 2]) * b[ 0];
    int128_t t3   = ((int128_t)a[ 0]) * b[ 3]
                 + ((int128_t)a[ 1]) * b[ 2]
                 + ((int128_t)a[ 2]) * b[ 1]
                 + ((int128_t)a[ 3]) * b[ 0];
    int128_t t4   = ((int128_t)a[ 0]) * b[ 4]
                 + ((int128_t)a[ 1]) * b[ 3]
                 + ((int128_t)a[ 2]) * b[ 2]
                 + ((int128_t)a[ 3]) * b[ 1]
                 + ((int128_t)a[ 4]) * b[ 0];
    int128_t t5   = ((int128_t)a[ 0]) * b[ 5]
                 + ((int128_t)a[ 1]) * b[ 4]
                 + ((int128_t)a[ 2]) * b[ 3]
                 + ((int128_t)a[ 3]) * b[ 2]
                 + ((int128_t)a[ 4]) * b[ 1]
                 + ((int128_t)a[ 5]) * b[ 0];
    int128_t t6   = ((int128_t)a[ 0]) * b[ 6]
                 + ((int128_t)a[ 1]) * b[ 5]
                 + ((int128_t)a[ 2]) * b[ 4]
                 + ((int128_t)a[ 3]) * b[ 3]
                 + ((int128_t)a[ 4]) * b[ 2]
                 + ((int128_t)a[ 5]) * b[ 1]
                 + ((int128_t)a[ 6]) * b[ 0];
    int128_t t7   = ((int128_t)a[ 0]) * b[ 7]
                 + ((int128_t)a[ 1]) * b[ 6]
                 + ((int128_t)a[ 2]) * b[ 5]
                 + ((int128_t)a[ 3]) * b[ 4]
                 + ((int128_t)a[ 4]) * b[ 3]
                 + ((int128_t)a[ 5]) * b[ 2]
                 + ((int128_t)a[ 6]) * b[ 1]
                 + ((int128_t)a[ 7]) * b[ 0];
    int128_t t8   = ((int128_t)a[ 0]) * b[ 8]
                 + ((int128_t)a[ 1]) * b[ 7]
                 + ((int128_t)a[ 2]) * b[ 6]
                 + ((int128_t)a[ 3]) * b[ 5]
                 + ((int128_t)a[ 4]) * b[ 4]
                 + ((int128_t)a[ 5]) * b[ 3]
                 + ((int128_t)a[ 6]) * b[ 2]
                 + ((int128_t)a[ 7]) * b[ 1]
                 + ((int128_t)a[ 8]) * b[ 0];
    int128_t t9   = ((int128_t)a[ 1]) * b[ 8]
                 + ((int128_t)a[ 2]) * b[ 7]
                 + ((int128_t)a[ 3]) * b[ 6]
                 + ((int128_t)a[ 4]) * b[ 5]
                 + ((int128_t)a[ 5]) * b[ 4]
                 + ((int128_t)a[ 6]) * b[ 3]
                 + ((int128_t)a[ 7]) * b[ 2]
                 + ((int128_t)a[ 8]) * b[ 1];
    int128_t t10  = ((int128_t)a[ 2]) * b[ 8]
                 + ((int128_t)a[ 3]) * b[ 7]
                 + ((int128_t)a[ 4]) * b[ 6]
                 + ((int128_t)a[ 5]) * b[ 5]
                 + ((int128_t)a[ 6]) * b[ 4]
                 + ((int128_t)a[ 7]) * b[ 3]
                 + ((int128_t)a[ 8]) * b[ 2];
    int128_t t11  = ((int128_t)a[ 3]) * b[ 8]
                 + ((int128_t)a[ 4]) * b[ 7]
                 + ((int128_t)a[ 5]) * b[ 6]
                 + ((int128_t)a[ 6]) * b[ 5]
                 + ((int128_t)a[ 7]) * b[ 4]
                 + ((int128_t)a[ 8]) * b[ 3];
    int128_t t12  = ((int128_t)a[ 4]) * b[ 8]
                 + ((int128_t)a[ 5]) * b[ 7]
                 + ((int128_t)a[ 6]) * b[ 6]
                 + ((int128_t)a[ 7]) * b[ 5]
                 + ((int128_t)a[ 8]) * b[ 4];
    int128_t t13  = ((int128_t)a[ 5]) * b[ 8]
                 + ((int128_t)a[ 6]) * b[ 7]
                 + ((int128_t)a[ 7]) * b[ 6]
                 + ((int128_t)a[ 8]) * b[ 5];
    int128_t t14  = ((int128_t)a[ 6]) * b[ 8]
                 + ((int128_t)a[ 7]) * b[ 7]
                 + ((int128_t)a[ 8]) * b[ 6];
    int128_t t15  = ((int128_t)a[ 7]) * b[ 8]
                 + ((int128_t)a[ 8]) * b[ 7];
    int128_t t16  = ((int128_t)a[ 8]) * b[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_9(sp_digit* r, const sp_digit* a)
{
    int128_t t0   =  ((int128_t)a[ 0]) * a[ 0];
    int128_t t1   = (((int128_t)a[ 0]) * a[ 1]) * 2;
    int128_t t2   = (((int128_t)a[ 0]) * a[ 2]) * 2
                 +  ((int128_t)a[ 1]) * a[ 1];
    int128_t t3   = (((int128_t)a[ 0]) * a[ 3]
                 +  ((int128_t)a[ 1]) * a[ 2]) * 2;
    int128_t t4   = (((int128_t)a[ 0]) * a[ 4]
                 +  ((int128_t)a[ 1]) * a[ 3]) * 2
                 +  ((int128_t)a[ 2]) * a[ 2];
    int128_t t5   = (((int128_t)a[ 0]) * a[ 5]
                 +  ((int128_t)a[ 1]) * a[ 4]
                 +  ((int128_t)a[ 2]) * a[ 3]) * 2;
    int128_t t6   = (((int128_t)a[ 0]) * a[ 6]
                 +  ((int128_t)a[ 1]) * a[ 5]
                 +  ((int128_t)a[ 2]) * a[ 4]) * 2
                 +  ((int128_t)a[ 3]) * a[ 3];
    int128_t t7   = (((int128_t)a[ 0]) * a[ 7]
                 +  ((int128_t)a[ 1]) * a[ 6]
                 +  ((int128_t)a[ 2]) * a[ 5]
                 +  ((int128_t)a[ 3]) * a[ 4]) * 2;
    int128_t t8   = (((int128_t)a[ 0]) * a[ 8]
                 +  ((int128_t)a[ 1]) * a[ 7]
                 +  ((int128_t)a[ 2]) * a[ 6]
                 +  ((int128_t)a[ 3]) * a[ 5]) * 2
                 +  ((int128_t)a[ 4]) * a[ 4];
    int128_t t9   = (((int128_t)a[ 1]) * a[ 8]
                 +  ((int128_t)a[ 2]) * a[ 7]
                 +  ((int128_t)a[ 3]) * a[ 6]
                 +  ((int128_t)a[ 4]) * a[ 5]) * 2;
    int128_t t10  = (((int128_t)a[ 2]) * a[ 8]
                 +  ((int128_t)a[ 3]) * a[ 7]
                 +  ((int128_t)a[ 4]) * a[ 6]) * 2
                 +  ((int128_t)a[ 5]) * a[ 5];
    int128_t t11  = (((int128_t)a[ 3]) * a[ 8]
                 +  ((int128_t)a[ 4]) * a[ 7]
                 +  ((int128_t)a[ 5]) * a[ 6]) * 2;
    int128_t t12  = (((int128_t)a[ 4]) * a[ 8]
                 +  ((int128_t)a[ 5]) * a[ 7]) * 2
                 +  ((int128_t)a[ 6]) * a[ 6];
    int128_t t13  = (((int128_t)a[ 5]) * a[ 8]
                 +  ((int128_t)a[ 6]) * a[ 7]) * 2;
    int128_t t14  = (((int128_t)a[ 6]) * a[ 8]) * 2
                 +  ((int128_t)a[ 7]) * a[ 7];
    int128_t t15  = (((int128_t)a[ 7]) * a[ 8]) * 2;
    int128_t t16  =  ((int128_t)a[ 8]) * a[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[16] = a[16] + b[16];
    r[17] = a[17] + b[17];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[16] = a[16] - b[16];
    r[17] = a[17] - b[17];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_18(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit b1[9];
    sp_digit* z2 = r + 18;
    (void)sp_2048_add_9(a1, a, &a[9]);
    (void)sp_2048_add_9(b1, b, &b[9]);
    sp_2048_mul_9(z2, &a[9], &b[9]);
    sp_2048_mul_9(z0, a, b);
    sp_2048_mul_9(z1, a1, b1);
    (void)sp_2048_sub_18(z1, z1, z2);
    (void)sp_2048_sub_18(z1, z1, z0);
    (void)sp_2048_add_18(r + 9, r + 9, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_18(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 18;
    (void)sp_2048_add_9(a1, a, &a[9]);
    sp_2048_sqr_9(z2, &a[9]);
    sp_2048_sqr_9(z0, a);
    sp_2048_sqr_9(z1, a1);
    (void)sp_2048_sub_18(z1, z1, z2);
    (void)sp_2048_sub_18(z1, z1, z0);
    (void)sp_2048_add_18(r + 9, r + 9, z1);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[32] = a[32] + b[32];
    r[33] = a[33] + b[33];
    r[34] = a[34] + b[34];
    r[35] = a[35] + b[35];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[32] = a[32] - b[32];
    r[33] = a[33] - b[33];
    r[34] = a[34] - b[34];
    r[35] = a[35] - b[35];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_36(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[36];
    sp_digit* a1 = z1;
    sp_digit b1[18];
    sp_digit* z2 = r + 36;
    (void)sp_2048_add_18(a1, a, &a[18]);
    (void)sp_2048_add_18(b1, b, &b[18]);
    sp_2048_mul_18(z2, &a[18], &b[18]);
    sp_2048_mul_18(z0, a, b);
    sp_2048_mul_18(z1, a1, b1);
    (void)sp_2048_sub_36(z1, z1, z2);
    (void)sp_2048_sub_36(z1, z1, z0);
    (void)sp_2048_add_36(r + 18, r + 18, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_36(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[36];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 36;
    (void)sp_2048_add_18(a1, a, &a[18]);
    sp_2048_sqr_18(z2, &a[18]);
    sp_2048_sqr_18(z0, a);
    sp_2048_sqr_18(z1, a1);
    (void)sp_2048_sub_36(z1, z1, z2);
    (void)sp_2048_sub_36(z1, z1, z0);
    (void)sp_2048_add_36(r + 18, r + 18, z1);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_36(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[35]) * b[35];
    r[71] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 69; k >= 0; k--) {
        for (i = 35; i >= 0; i--) {
            j = k - i;
            if (j >= 36) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_36(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[35]) * a[35];
    r[71] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 69; k >= 0; k--) {
        for (i = 35; i >= 0; i--) {
            j = k - i;
            if (j >= 36 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_18(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[17]) * b[17];
    r[35] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 33; k >= 0; k--) {
        for (i = 17; i >= 0; i--) {
            j = k - i;
            if (j >= 18) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_18(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[17]) * a[17];
    r[35] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 33; k >= 0; k--) {
        for (i = 17; i >= 0; i--) {
            j = k - i;
            if (j >= 18 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_2048_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x, b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x1ffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = (1L << 57) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_36(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 36; i++) {
        t += tb * a[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[36] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1ffffffffffffffL;
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 57) + (t[4] & 0x1ffffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 57) + (t[5] & 0x1ffffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 57) + (t[6] & 0x1ffffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 57) + (t[7] & 0x1ffffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 57) + (t[0] & 0x1ffffffffffffffL);
    }
    t[1] = tb * a[33];
    r[33] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
    t[2] = tb * a[34];
    r[34] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
    t[3] = tb * a[35];
    r[35] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
    r[36] =  (sp_digit)(t[3] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_2048_mont_norm_18(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<17; i++) {
        r[i] = 0x1ffffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[16] = 0x1ffffffffffffffL;
#endif
    r[17] = 0x7fffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_18(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_18(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=17; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[17] - b[17]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[16] - b[16]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 8; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[16] = a[16] - (b[16] & m);
    r[17] = a[17] - (b[17] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 18; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[18] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 16; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[17]; r[17] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    r[18] +=  (sp_digit)(t[1] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 57.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_18(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 17; i++) {
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 16; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
        a[i+9] += a[i+8] >> 57; a[i+8] &= 0x1ffffffffffffffL;
    }
    a[16+1] += a[16] >> 57;
    a[16] &= 0x1ffffffffffffffL;
#endif
}

/* Shift the result in the high 1024 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_18(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    word64 n;

    n = a[17] >> 55;
    for (i = 0; i < 17; i++) {
        n += (word64)a[18 + i] << 2;
        r[i] = n & 0x1ffffffffffffffL;
        n >>= 57;
    }
    n += (word64)a[35] << 2;
    r[17] = n;
#else
    word64 n;
    int i;

    n  = (word64)a[17];
    n  = n >> 55U;
    for (i = 0; i < 16; i += 8) {
        n += (word64)a[i+18] << 2U; r[i+0] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+19] << 2U; r[i+1] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+20] << 2U; r[i+2] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+21] << 2U; r[i+3] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+22] << 2U; r[i+4] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+23] << 2U; r[i+5] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+24] << 2U; r[i+6] = n & 0x1ffffffffffffffUL; n >>= 57U;
        n += (word64)a[i+25] << 2U; r[i+7] = n & 0x1ffffffffffffffUL; n >>= 57U;
    }
    n += (word64)a[34] << 2U; r[16] = n & 0x1ffffffffffffffUL; n >>= 57U;
    n += (word64)a[35] << 2U; r[17] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[18], 0, sizeof(*r) * 18U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_18(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_2048_norm_18(a + 18);

    for (i=0; i<17; i++) {
        mu = (a[i] * mp) & 0x1ffffffffffffffL;
        sp_2048_mul_add_18(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = (a[i] * mp) & 0x7fffffffffffffL;
    sp_2048_mul_add_18(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;

    sp_2048_mont_shift_18(a, a);
    sp_2048_cond_sub_18(a, a, m, 0 - (((a[17] >> 55) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_2048_norm_18(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_mul_18(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_18(r, a, b);
    sp_2048_mont_reduce_18(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_sqr_18(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_2048_sqr_18(r, a);
    sp_2048_mont_reduce_18(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_18(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 18; i++) {
        t += tb * a[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[18] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1ffffffffffffffL;
    for (i = 0; i < 16; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 57) + (t[4] & 0x1ffffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 57) + (t[5] & 0x1ffffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 57) + (t[6] & 0x1ffffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 57) + (t[7] & 0x1ffffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 57) + (t[0] & 0x1ffffffffffffffL);
    }
    t[1] = tb * a[17];
    r[17] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
    r[18] =  (sp_digit)(t[1] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[16] = a[16] + (b[16] & m);
    r[17] = a[17] + (b[17] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif
#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 18; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif
#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_2048_div_word_18(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 29 bits. */
    dv = (div >> 28) + 1;
    /* All 57 bits from d1 and top 6 bits from d0. */
    d = (d1 << 6) | (d0 >> 51);
    r = d / dv;
    d -= r * dv;
    /* Up to 34 bits in r */
    /* Next 23 bits from d0. */
    d <<= 23;
    r <<= 23;
    d |= (d0 >> 28) & ((1 << 23) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 57 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 57) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 28) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_18(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[36], t2d[18 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 18 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 2 * 18;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[17];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 18U);
        for (i=17; i>=0; i--) {
            t1[18 + i] += t1[18 + i - 1] >> 57;
            t1[18 + i - 1] &= 0x1ffffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[18 + i];
            d1 <<= 57;
            d1 += t1[18 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_2048_div_word_18(t1[18 + i], t1[18 + i - 1], dv);
#endif

            sp_2048_mul_d_18(t2, d, r1);
            (void)sp_2048_sub_18(&t1[i], &t1[i], t2);
            t1[18 + i] -= t2[18];
            t1[18 + i] += t1[18 + i - 1] >> 57;
            t1[18 + i - 1] &= 0x1ffffffffffffffL;
            r1 = (((-t1[18 + i]) << 57) - t1[18 + i - 1]) / dv;
            r1++;
            sp_2048_mul_d_18(t2, d, r1);
            (void)sp_2048_add_18(&t1[i], &t1[i], t2);
            t1[18 + i] += t1[18 + i - 1] >> 57;
            t1[18 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[18 - 1] += t1[18 - 2] >> 57;
        t1[18 - 2] &= 0x1ffffffffffffffL;
        d1 = t1[18 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_2048_mul_d_18(t2, d, r1);
        (void)sp_2048_sub_18(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 18U);
        for (i=0; i<16; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_2048_cond_add_18(r, r, d, 0 - ((r[17] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_18(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_18(a, m, NULL, r);
}

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_2048_mod_exp_18(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 18 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 18U * 2U);

        norm = t[0] = td;
        t[1] = &td[18 * 2];
        t[2] = &td[2 * 18 * 2];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 18U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_18(t[1], t[1], norm);
        err = sp_2048_mod_18(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_2048_mont_mul_18(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 18 * 2);
            sp_2048_mont_sqr_18(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 18 * 2);
        }

        sp_2048_mont_reduce_18(t[0], m, mp);
        n = sp_2048_cmp_18(t[0], m);
        sp_2048_cond_sub_18(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 18 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][36];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 18 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[18 * 2];
        t[2] = &td[2 * 18 * 2];
#endif
        norm = t[0];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_18(t[1], t[1], norm);
                err = sp_2048_mod_18(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_18(t[1], a, norm);
            err = sp_2048_mod_18(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_2048_mont_mul_18(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_2048_mont_sqr_18(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_2048_mont_reduce_18(t[0], m, mp);
        n = sp_2048_cmp_18(t[0], m);
        sp_2048_cond_sub_18(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][36];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[36];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 36, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 36;
#endif
        norm = t[0];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_18(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_18(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_18(t[1], t[1], norm);
                err = sp_2048_mod_18(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_18(t[1], a, norm);
            err = sp_2048_mod_18(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_18(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_18(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_18(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_18(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_18(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_18(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_18(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_18(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_18(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_18(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_18(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_18(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_18(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_18(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_18(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_18(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_18(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_18(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_18(t[20], t[10], m, mp);
        sp_2048_mont_mul_18(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_18(t[22], t[11], m, mp);
        sp_2048_mont_mul_18(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_18(t[24], t[12], m, mp);
        sp_2048_mont_mul_18(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_18(t[26], t[13], m, mp);
        sp_2048_mont_mul_18(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_18(t[28], t[14], m, mp);
        sp_2048_mont_mul_18(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_18(t[30], t[15], m, mp);
        sp_2048_mont_mul_18(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 18) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);
            sp_2048_mont_sqr_18(rt, rt, m, mp);

            sp_2048_mont_mul_18(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_18(rt, m, mp);
        n = sp_2048_cmp_18(rt, m);
        sp_2048_cond_sub_18(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_2048_mont_norm_36(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<35; i++) {
        r[i] = 0x1ffffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[32] = 0x1ffffffffffffffL;
    r[33] = 0x1ffffffffffffffL;
    r[34] = 0x1ffffffffffffffL;
#endif
    r[35] = 0x1fffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_2048_sub_36(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_36(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=35; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[35] - b[35]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[34] - b[34]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[33] - b[33]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[32] - b[32]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 24; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[32] = a[32] - (b[32] & m);
    r[33] = a[33] - (b[33] & m);
    r[34] = a[34] - (b[34] & m);
    r[35] = a[35] - (b[35] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 36; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[36] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[33]; r[33] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[34]; r[34] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    t[3] = tb * a[35]; r[35] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
    r[36] +=  (sp_digit)(t[3] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 57.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_36(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 35; i++) {
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 32; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
        a[i+9] += a[i+8] >> 57; a[i+8] &= 0x1ffffffffffffffL;
    }
    a[32+1] += a[32] >> 57;
    a[32] &= 0x1ffffffffffffffL;
    a[33+1] += a[33] >> 57;
    a[33] &= 0x1ffffffffffffffL;
    a[34+1] += a[34] >> 57;
    a[34] &= 0x1ffffffffffffffL;
#endif
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_36(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_digit n, s;

    s = a[36];
    n = a[35] >> 53;
    for (i = 0; i < 35; i++) {
        n += (s & 0x1ffffffffffffffL) << 4;
        r[i] = n & 0x1ffffffffffffffL;
        n >>= 57;
        s = a[37 + i] + (s >> 57);
    }
    n += s << 4;
    r[35] = n;
#else
    sp_digit n, s;
    int i;

    s = a[36]; n = a[35] >> 53;
    for (i = 0; i < 32; i += 8) {
        n += (s & 0x1ffffffffffffffL) << 4; r[i+0] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+37] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+1] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+38] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+2] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+39] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+3] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+40] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+4] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+41] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+5] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+42] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+6] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+43] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 4; r[i+7] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+44] + (s >> 57);
    }
    n += (s & 0x1ffffffffffffffL) << 4; r[32] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[69] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 4; r[33] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[70] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 4; r[34] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[71] + (s >> 57);
    n += s << 4;              r[35] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[36], 0, sizeof(*r) * 36U);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_36(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_2048_norm_36(a + 36);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<35; i++) {
            mu = (a[i] * mp) & 0x1ffffffffffffffL;
            sp_2048_mul_add_36(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = (a[i] * mp) & 0x1fffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
    else {
        for (i=0; i<35; i++) {
            mu = a[i] & 0x1ffffffffffffffL;
            sp_2048_mul_add_36(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = a[i] & 0x1fffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    for (i=0; i<35; i++) {
        mu = (a[i] * mp) & 0x1ffffffffffffffL;
        sp_2048_mul_add_36(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = (a[i] * mp) & 0x1fffffffffffffL;
    sp_2048_mul_add_36(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
#endif

    sp_2048_mont_shift_36(a, a);
    sp_2048_cond_sub_36(a, a, m, 0 - (((a[35] >> 53) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_2048_norm_36(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_mul_36(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_36(r, a, b);
    sp_2048_mont_reduce_36(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_sqr_36(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_2048_sqr_36(r, a);
    sp_2048_mont_reduce_36(r, m, mp);
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[32] = a[32] + (b[32] & m);
    r[33] = a[33] + (b[33] & m);
    r[34] = a[34] + (b[34] & m);
    r[35] = a[35] + (b[35] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif
#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 36; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif
#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_2048_div_word_36(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 29 bits. */
    dv = (div >> 28) + 1;
    /* All 57 bits from d1 and top 6 bits from d0. */
    d = (d1 << 6) | (d0 >> 51);
    r = d / dv;
    d -= r * dv;
    /* Up to 34 bits in r */
    /* Next 23 bits from d0. */
    d <<= 23;
    r <<= 23;
    d |= (d0 >> 28) & ((1 << 23) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 57 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 57) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 28) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_36(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[72], t2d[36 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 36 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 2 * 36;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[35];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 36U);
        for (i=35; i>=0; i--) {
            t1[36 + i] += t1[36 + i - 1] >> 57;
            t1[36 + i - 1] &= 0x1ffffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[36 + i];
            d1 <<= 57;
            d1 += t1[36 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_2048_div_word_36(t1[36 + i], t1[36 + i - 1], dv);
#endif

            sp_2048_mul_d_36(t2, d, r1);
            (void)sp_2048_sub_36(&t1[i], &t1[i], t2);
            t1[36 + i] -= t2[36];
            t1[36 + i] += t1[36 + i - 1] >> 57;
            t1[36 + i - 1] &= 0x1ffffffffffffffL;
            r1 = (((-t1[36 + i]) << 57) - t1[36 + i - 1]) / dv;
            r1++;
            sp_2048_mul_d_36(t2, d, r1);
            (void)sp_2048_add_36(&t1[i], &t1[i], t2);
            t1[36 + i] += t1[36 + i - 1] >> 57;
            t1[36 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[36 - 1] += t1[36 - 2] >> 57;
        t1[36 - 2] &= 0x1ffffffffffffffL;
        d1 = t1[36 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_2048_mul_d_36(t2, d, r1);
        (void)sp_2048_sub_36(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 36U);
        for (i=0; i<34; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_2048_cond_add_36(r, r, d, 0 - ((r[35] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_36(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_36(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_2048_mod_exp_36(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 36 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 36U * 2U);

        norm = t[0] = td;
        t[1] = &td[36 * 2];
        t[2] = &td[2 * 36 * 2];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 36U);
        }
    }
    if (err == MP_OKAY) {
        sp_2048_mul_36(t[1], t[1], norm);
        err = sp_2048_mod_36(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_2048_mont_mul_36(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 36 * 2);
            sp_2048_mont_sqr_36(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 36 * 2);
        }

        sp_2048_mont_reduce_36(t[0], m, mp);
        n = sp_2048_cmp_36(t[0], m);
        sp_2048_cond_sub_36(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 36 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][72];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 36 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[36 * 2];
        t[2] = &td[2 * 36 * 2];
#endif
        norm = t[0];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(t[1], t[1], norm);
                err = sp_2048_mod_36(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_36(t[1], a, norm);
            err = sp_2048_mod_36(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_2048_mont_mul_36(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_2048_mont_sqr_36(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_2048_mont_reduce_36(t[0], m, mp);
        n = sp_2048_cmp_36(t[0], m);
        sp_2048_cond_sub_36(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][72];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[72];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 72, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 72;
#endif
        norm = t[0];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        if (reduceA != 0) {
            err = sp_2048_mod_36(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(t[1], t[1], norm);
                err = sp_2048_mod_36(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_36(t[1], a, norm);
            err = sp_2048_mod_36(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_36(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_36(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_36(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_36(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_36(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_36(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_36(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_36(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_36(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_36(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_36(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_36(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_36(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_36(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_36(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_36(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_36(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_36(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_36(t[20], t[10], m, mp);
        sp_2048_mont_mul_36(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_36(t[22], t[11], m, mp);
        sp_2048_mont_mul_36(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_36(t[24], t[12], m, mp);
        sp_2048_mont_mul_36(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_36(t[26], t[13], m, mp);
        sp_2048_mont_mul_36(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_36(t[28], t[14], m, mp);
        sp_2048_mont_mul_36(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_36(t[30], t[15], m, mp);
        sp_2048_mont_mul_36(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 36) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);
            sp_2048_mont_sqr_36(rt, rt, m, mp);

            sp_2048_mont_mul_36(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_36(rt, m, mp);
        n = sp_2048_cmp_36(rt, m);
        sp_2048_cond_sub_36(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D) && \
           !defined(RSA_LOW_MEM) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_18(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<18; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
    r[16] = a[16] & m;
    r[17] = a[17] & m;
#endif
}

#endif
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_2048(const byte* in, word32 inLen, mp_int* em, mp_int* mm,
    byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* d = NULL;
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit* norm;
    sp_digit e[1] = {0};
    sp_digit mp;
    int i;
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
            err = MP_READ_E;
        }
        if (inLen > 256U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 36 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 36 * 2;
        m = r + 36 * 2;
        norm = r;

        sp_2048_from_bin(a, 36, in, inLen);
#if DIGIT_BIT >= 57
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 36, mm);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_36(a, a, norm);
        err = sp_2048_mod_36(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=56; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 36 * 2);
        for (i--; i>=0; i--) {
            sp_2048_mont_sqr_36(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_2048_mont_mul_36(r, r, a, m, mp);
            }
        }
        sp_2048_mont_reduce_36(r, m, mp);
        mp = sp_2048_cmp_36(r, m);
        sp_2048_cond_sub_36(r, r, m, ((mp < 0) ?
                    (sp_digit)1 : (sp_digit)0)- 1);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit ad[72], md[36], rd[72];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
            err = MP_READ_E;
        }
        if (inLen > 256U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 36 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 36 * 2;
        m = r + 36 * 2;
    }
#else
    a = ad;
    m = md;
    r = rd;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 36, in, inLen);
#if DIGIT_BIT >= 57
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 36, mm);

        if (e[0] == 0x3) {
            sp_2048_sqr_36(r, a);
            err = sp_2048_mod_36(r, r, m);
            if (err == MP_OKAY) {
                sp_2048_mul_36(r, a, r);
                err = sp_2048_mod_36(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);
            sp_2048_mont_norm_36(norm, m);

            sp_2048_mul_36(a, a, norm);
            err = sp_2048_mod_36(a, a, m);

            if (err == MP_OKAY) {
                for (i=56; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 72U);
                for (i--; i>=0; i--) {
                    sp_2048_mont_sqr_36(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_2048_mont_mul_36(r, r, a, m, mp);
                    }
                }
                sp_2048_mont_reduce_36(r, m, mp);
                mp = sp_2048_cmp_36(r, m);
                sp_2048_cond_sub_36(r, r, m, ((mp < 0) ?
                           (sp_digit)1 : (sp_digit)0) - 1);
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }
#endif

    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_2048(const byte* in, word32 inLen, mp_int* dm,
    mp_int* pm, mp_int* qm, mp_int* dpm, mp_int* dqm, mp_int* qim, mp_int* mm,
    byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* a;
    sp_digit* d = NULL;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 2048) {
           err = MP_READ_E;
        }
        if (inLen > 256) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 36 * 4, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = d + 36;
        m = a + 36;
        r = a;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(d, 36, dm);
        sp_2048_from_mp(m, 36, mm);
        err = sp_2048_mod_exp_36(r, a, d, 2048, m, 0);
    }
    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 36);
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[72], d[36], m[36];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 2048) {
            err = MP_READ_E;
        }
        if (inLen > 256U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(d, 36, dm);
        sp_2048_from_mp(m, 36, mm);
        err = sp_2048_mod_exp_36(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    XMEMSET(d, 0, sizeof(sp_digit) * 36);

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#else
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* t = NULL;
    sp_digit* a;
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmp;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 256) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 18 * 11, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (t == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = t;
        p = a + 36 * 2;
        q = p + 18;
        qi = dq = dp = q + 18;
        tmpa = qi + 18;
        tmpb = tmpa + 36;

        tmp = t;
        r = tmp + 36;

        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(p, 18, pm);
        sp_2048_from_mp(q, 18, qm);
        sp_2048_from_mp(dp, 18, dpm);
        err = sp_2048_mod_exp_18(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(dq, 18, dqm);
        err = sp_2048_mod_exp_18(tmpb, a, dq, 1024, q, 1);
    }
    if (err == MP_OKAY) {
        (void)sp_2048_sub_18(tmpa, tmpa, tmpb);
        sp_2048_mask_18(tmp, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        (void)sp_2048_add_18(tmpa, tmpa, tmp);

        sp_2048_from_mp(qi, 18, qim);
        sp_2048_mul_18(tmpa, tmpa, qi);
        err = sp_2048_mod_18(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_18(tmpa, q, tmpa);
        (void)sp_2048_add_36(r, tmpb, tmpa);
        sp_2048_norm_36(r);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_digit) * 18 * 11);
        XFREE(t, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[36 * 2];
    sp_digit p[18], q[18], dp[18], dq[18], qi[18];
    sp_digit tmp[36], tmpa[36], tmpb[36];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 256U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 36, in, inLen);
        sp_2048_from_mp(p, 18, pm);
        sp_2048_from_mp(q, 18, qm);
        sp_2048_from_mp(dp, 18, dpm);
        sp_2048_from_mp(dq, 18, dqm);
        sp_2048_from_mp(qi, 18, qim);

        err = sp_2048_mod_exp_18(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_2048_mod_exp_18(tmpb, a, dq, 1024, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_2048_sub_18(tmpa, tmpa, tmpb);
        sp_2048_mask_18(tmp, p, 0 - ((sp_int_digit)tmpa[17] >> 63));
        (void)sp_2048_add_18(tmpa, tmpa, tmp);
        sp_2048_mul_18(tmpa, tmpa, qi);
        err = sp_2048_mod_18(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_18(tmpa, tmpa, q);
        (void)sp_2048_add_36(r, tmpb, tmpa);
        sp_2048_norm_36(r);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    XMEMSET(tmpa, 0, sizeof(tmpa));
    XMEMSET(tmpb, 0, sizeof(tmpb));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));
    XMEMSET(dp, 0, sizeof(dp));
    XMEMSET(dq, 0, sizeof(dq));
    XMEMSET(qi, 0, sizeof(qi));

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_2048_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (2048 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 57
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 36);
        r->used = 36;
        mp_clamp(r);
#elif DIGIT_BIT < 57
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 36; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 57) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = a[i] >> s;
                }
            }
            s = 57 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 36; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 57 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 57 - s;
            }
            else {
                s += 57;
            }
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_2048(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 36 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 36U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[72], ed[36], md[36];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 2048) {
            err = MP_READ_E;
        }
    }
    
    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 2048) {
            err = MP_READ_E;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 36 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 36 * 2;
        m = e + 36;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 36, base);
        sp_2048_from_mp(e, 36, exp);
        sp_2048_from_mp(m, 36, mod);

        err = sp_2048_mod_exp_36(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 36U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_2048
SP_NOINLINE static void sp_2048_lshift_36(sp_digit* r, sp_digit* a, byte n)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    r[36] = a[35] >> (57 - n);
    for (i=35; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (57 - n))) & 0x1ffffffffffffffL;
    }
#else
    sp_int_digit s, t;

    s = (sp_int_digit)a[35];
    r[36] = s >> (57U - n);
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
#endif
    r[0] = (a[0] << n) & 0x1ffffffffffffffL;
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_2048_mod_exp_2_36(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
#ifndef WOLFSSL_SMALL_STACK
    sp_digit nd[72];
    sp_digit td[37];
#else
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n, o;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 109, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        norm = td;
        tmp  = td + 72;
#else
        norm = nd;
        tmp  = td;
#endif

        XMEMSET(td, 0, sizeof(td));
        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_36(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 36) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        sp_2048_lshift_36(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);
            sp_2048_mont_sqr_36(r, r, m, mp);

            sp_2048_lshift_36(r, r, y);
            sp_2048_mul_d_36(tmp, norm, (r[36] << 4) + (r[35] >> 53));
            r[36] = 0;
            r[35] &= 0x1fffffffffffffL;
            (void)sp_2048_add_36(r, r, tmp);
            sp_2048_norm_36(r);
            o = sp_2048_cmp_36(r, m);
            sp_2048_cond_sub_36(r, r, m, ((o < 0) ?
                                          (sp_digit)1 : (sp_digit)0) - 1);
        }

        sp_2048_mont_reduce_36(r, m, mp);
        n = sp_2048_cmp_36(r, m);
        sp_2048_cond_sub_36(r, r, m, ((n < 0) ?
                                                (sp_digit)1 : (sp_digit)0) - 1);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

#endif /* HAVE_FFDHE_2048 */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 256 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_2048(mp_int* base, const byte* exp, word32 expLen,
    mp_int* mod, byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 256) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 2048) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 36 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 36 * 2;
        m = e + 36;
        r = b;

        sp_2048_from_mp(b, 36, base);
        sp_2048_from_bin(e, 36, exp, expLen);
        sp_2048_from_mp(m, 36, mod);

    #ifdef HAVE_FFDHE_2048
        if (base->used == 1 && base->dp[0] == 2 &&
                (m[35] >> 21) == 0xffffffffL) {
            err = sp_2048_mod_exp_2_36(r, e, expLen * 8, m);
        }
        else
    #endif
            err = sp_2048_mod_exp_36(r, b, e, expLen * 8, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
        for (i=0; i<256 && out[i] == 0; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 36U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[72], ed[36], md[36];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 2048) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 256U) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 2048) {
            err = MP_READ_E;
        }
    }
#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 36 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 36 * 2;
        m = e + 36;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 36, base);
        sp_2048_from_bin(e, 36, exp, expLen);
        sp_2048_from_mp(m, 36, mod);

    #ifdef HAVE_FFDHE_2048
        if (base->used == 1 && base->dp[0] == 2U &&
                (m[35] >> 21) == 0xffffffffL) {
            err = sp_2048_mod_exp_2_36(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_2048_mod_exp_36(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_2048
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
        for (i=0; i<256U && out[i] == 0U; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 36U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}
#endif /* WOLFSSL_HAVE_SP_DH */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_1024(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1024) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 1024) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 1024) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 18 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 18 * 2;
        m = e + 18;
        r = b;

        sp_2048_from_mp(b, 18, base);
        sp_2048_from_mp(e, 18, exp);
        sp_2048_from_mp(m, 18, mod);

        err = sp_2048_mod_exp_18(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 18, 0, sizeof(*r) * 18U);
        err = sp_2048_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 18U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[36], ed[18], md[18];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1024) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 1024) {
            err = MP_READ_E;
        }
    }
    
    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 1024) {
            err = MP_READ_E;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 18 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 18 * 2;
        m = e + 18;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 18, base);
        sp_2048_from_mp(e, 18, exp);
        sp_2048_from_mp(m, 18, mod);

        err = sp_2048_mod_exp_18(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 18, 0, sizeof(*r) * 18U);
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 18U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH || (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_2048 */

#ifndef WOLFSSL_SP_NO_3072
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_3072_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 49U) {
            r[j] &= 0x1ffffffffffffffL;
            s = 57U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_3072_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 57
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 57
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1ffffffffffffffL;
        s = 57U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 57U) <= (word32)DIGIT_BIT) {
            s += 57U;
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = 0L;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 57) {
            r[j] &= 0x1ffffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 57 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 384
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_3072_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<53; i++) {
        r[i+1] += r[i] >> 57;
        r[i] &= 0x1ffffffffffffffL;
    }
    j = 3072 / 8 - 1;
    a[j] = 0;
    for (i=0; i<54 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); b += 8 - s; /*lint !e9033*/
        if (j < 0) {
            break;
        }
        while (b < 57) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 57);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_9(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int128_t t0   = ((int128_t)a[ 0]) * b[ 0];
    int128_t t1   = ((int128_t)a[ 0]) * b[ 1]
                 + ((int128_t)a[ 1]) * b[ 0];
    int128_t t2   = ((int128_t)a[ 0]) * b[ 2]
                 + ((int128_t)a[ 1]) * b[ 1]
                 + ((int128_t)a[ 2]) * b[ 0];
    int128_t t3   = ((int128_t)a[ 0]) * b[ 3]
                 + ((int128_t)a[ 1]) * b[ 2]
                 + ((int128_t)a[ 2]) * b[ 1]
                 + ((int128_t)a[ 3]) * b[ 0];
    int128_t t4   = ((int128_t)a[ 0]) * b[ 4]
                 + ((int128_t)a[ 1]) * b[ 3]
                 + ((int128_t)a[ 2]) * b[ 2]
                 + ((int128_t)a[ 3]) * b[ 1]
                 + ((int128_t)a[ 4]) * b[ 0];
    int128_t t5   = ((int128_t)a[ 0]) * b[ 5]
                 + ((int128_t)a[ 1]) * b[ 4]
                 + ((int128_t)a[ 2]) * b[ 3]
                 + ((int128_t)a[ 3]) * b[ 2]
                 + ((int128_t)a[ 4]) * b[ 1]
                 + ((int128_t)a[ 5]) * b[ 0];
    int128_t t6   = ((int128_t)a[ 0]) * b[ 6]
                 + ((int128_t)a[ 1]) * b[ 5]
                 + ((int128_t)a[ 2]) * b[ 4]
                 + ((int128_t)a[ 3]) * b[ 3]
                 + ((int128_t)a[ 4]) * b[ 2]
                 + ((int128_t)a[ 5]) * b[ 1]
                 + ((int128_t)a[ 6]) * b[ 0];
    int128_t t7   = ((int128_t)a[ 0]) * b[ 7]
                 + ((int128_t)a[ 1]) * b[ 6]
                 + ((int128_t)a[ 2]) * b[ 5]
                 + ((int128_t)a[ 3]) * b[ 4]
                 + ((int128_t)a[ 4]) * b[ 3]
                 + ((int128_t)a[ 5]) * b[ 2]
                 + ((int128_t)a[ 6]) * b[ 1]
                 + ((int128_t)a[ 7]) * b[ 0];
    int128_t t8   = ((int128_t)a[ 0]) * b[ 8]
                 + ((int128_t)a[ 1]) * b[ 7]
                 + ((int128_t)a[ 2]) * b[ 6]
                 + ((int128_t)a[ 3]) * b[ 5]
                 + ((int128_t)a[ 4]) * b[ 4]
                 + ((int128_t)a[ 5]) * b[ 3]
                 + ((int128_t)a[ 6]) * b[ 2]
                 + ((int128_t)a[ 7]) * b[ 1]
                 + ((int128_t)a[ 8]) * b[ 0];
    int128_t t9   = ((int128_t)a[ 1]) * b[ 8]
                 + ((int128_t)a[ 2]) * b[ 7]
                 + ((int128_t)a[ 3]) * b[ 6]
                 + ((int128_t)a[ 4]) * b[ 5]
                 + ((int128_t)a[ 5]) * b[ 4]
                 + ((int128_t)a[ 6]) * b[ 3]
                 + ((int128_t)a[ 7]) * b[ 2]
                 + ((int128_t)a[ 8]) * b[ 1];
    int128_t t10  = ((int128_t)a[ 2]) * b[ 8]
                 + ((int128_t)a[ 3]) * b[ 7]
                 + ((int128_t)a[ 4]) * b[ 6]
                 + ((int128_t)a[ 5]) * b[ 5]
                 + ((int128_t)a[ 6]) * b[ 4]
                 + ((int128_t)a[ 7]) * b[ 3]
                 + ((int128_t)a[ 8]) * b[ 2];
    int128_t t11  = ((int128_t)a[ 3]) * b[ 8]
                 + ((int128_t)a[ 4]) * b[ 7]
                 + ((int128_t)a[ 5]) * b[ 6]
                 + ((int128_t)a[ 6]) * b[ 5]
                 + ((int128_t)a[ 7]) * b[ 4]
                 + ((int128_t)a[ 8]) * b[ 3];
    int128_t t12  = ((int128_t)a[ 4]) * b[ 8]
                 + ((int128_t)a[ 5]) * b[ 7]
                 + ((int128_t)a[ 6]) * b[ 6]
                 + ((int128_t)a[ 7]) * b[ 5]
                 + ((int128_t)a[ 8]) * b[ 4];
    int128_t t13  = ((int128_t)a[ 5]) * b[ 8]
                 + ((int128_t)a[ 6]) * b[ 7]
                 + ((int128_t)a[ 7]) * b[ 6]
                 + ((int128_t)a[ 8]) * b[ 5];
    int128_t t14  = ((int128_t)a[ 6]) * b[ 8]
                 + ((int128_t)a[ 7]) * b[ 7]
                 + ((int128_t)a[ 8]) * b[ 6];
    int128_t t15  = ((int128_t)a[ 7]) * b[ 8]
                 + ((int128_t)a[ 8]) * b[ 7];
    int128_t t16  = ((int128_t)a[ 8]) * b[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_9(sp_digit* r, const sp_digit* a)
{
    int128_t t0   =  ((int128_t)a[ 0]) * a[ 0];
    int128_t t1   = (((int128_t)a[ 0]) * a[ 1]) * 2;
    int128_t t2   = (((int128_t)a[ 0]) * a[ 2]) * 2
                 +  ((int128_t)a[ 1]) * a[ 1];
    int128_t t3   = (((int128_t)a[ 0]) * a[ 3]
                 +  ((int128_t)a[ 1]) * a[ 2]) * 2;
    int128_t t4   = (((int128_t)a[ 0]) * a[ 4]
                 +  ((int128_t)a[ 1]) * a[ 3]) * 2
                 +  ((int128_t)a[ 2]) * a[ 2];
    int128_t t5   = (((int128_t)a[ 0]) * a[ 5]
                 +  ((int128_t)a[ 1]) * a[ 4]
                 +  ((int128_t)a[ 2]) * a[ 3]) * 2;
    int128_t t6   = (((int128_t)a[ 0]) * a[ 6]
                 +  ((int128_t)a[ 1]) * a[ 5]
                 +  ((int128_t)a[ 2]) * a[ 4]) * 2
                 +  ((int128_t)a[ 3]) * a[ 3];
    int128_t t7   = (((int128_t)a[ 0]) * a[ 7]
                 +  ((int128_t)a[ 1]) * a[ 6]
                 +  ((int128_t)a[ 2]) * a[ 5]
                 +  ((int128_t)a[ 3]) * a[ 4]) * 2;
    int128_t t8   = (((int128_t)a[ 0]) * a[ 8]
                 +  ((int128_t)a[ 1]) * a[ 7]
                 +  ((int128_t)a[ 2]) * a[ 6]
                 +  ((int128_t)a[ 3]) * a[ 5]) * 2
                 +  ((int128_t)a[ 4]) * a[ 4];
    int128_t t9   = (((int128_t)a[ 1]) * a[ 8]
                 +  ((int128_t)a[ 2]) * a[ 7]
                 +  ((int128_t)a[ 3]) * a[ 6]
                 +  ((int128_t)a[ 4]) * a[ 5]) * 2;
    int128_t t10  = (((int128_t)a[ 2]) * a[ 8]
                 +  ((int128_t)a[ 3]) * a[ 7]
                 +  ((int128_t)a[ 4]) * a[ 6]) * 2
                 +  ((int128_t)a[ 5]) * a[ 5];
    int128_t t11  = (((int128_t)a[ 3]) * a[ 8]
                 +  ((int128_t)a[ 4]) * a[ 7]
                 +  ((int128_t)a[ 5]) * a[ 6]) * 2;
    int128_t t12  = (((int128_t)a[ 4]) * a[ 8]
                 +  ((int128_t)a[ 5]) * a[ 7]) * 2
                 +  ((int128_t)a[ 6]) * a[ 6];
    int128_t t13  = (((int128_t)a[ 5]) * a[ 8]
                 +  ((int128_t)a[ 6]) * a[ 7]) * 2;
    int128_t t14  = (((int128_t)a[ 6]) * a[ 8]) * 2
                 +  ((int128_t)a[ 7]) * a[ 7];
    int128_t t15  = (((int128_t)a[ 7]) * a[ 8]) * 2;
    int128_t t16  =  ((int128_t)a[ 8]) * a[ 8];

    t1   += t0  >> 57; r[ 0] = t0  & 0x1ffffffffffffffL;
    t2   += t1  >> 57; r[ 1] = t1  & 0x1ffffffffffffffL;
    t3   += t2  >> 57; r[ 2] = t2  & 0x1ffffffffffffffL;
    t4   += t3  >> 57; r[ 3] = t3  & 0x1ffffffffffffffL;
    t5   += t4  >> 57; r[ 4] = t4  & 0x1ffffffffffffffL;
    t6   += t5  >> 57; r[ 5] = t5  & 0x1ffffffffffffffL;
    t7   += t6  >> 57; r[ 6] = t6  & 0x1ffffffffffffffL;
    t8   += t7  >> 57; r[ 7] = t7  & 0x1ffffffffffffffL;
    t9   += t8  >> 57; r[ 8] = t8  & 0x1ffffffffffffffL;
    t10  += t9  >> 57; r[ 9] = t9  & 0x1ffffffffffffffL;
    t11  += t10 >> 57; r[10] = t10 & 0x1ffffffffffffffL;
    t12  += t11 >> 57; r[11] = t11 & 0x1ffffffffffffffL;
    t13  += t12 >> 57; r[12] = t12 & 0x1ffffffffffffffL;
    t14  += t13 >> 57; r[13] = t13 & 0x1ffffffffffffffL;
    t15  += t14 >> 57; r[14] = t14 & 0x1ffffffffffffffL;
    t16  += t15 >> 57; r[15] = t15 & 0x1ffffffffffffffL;
    r[17] = (sp_digit)(t16 >> 57);
                       r[16] = t16 & 0x1ffffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_9(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[16] = a[16] + b[16];
    r[17] = a[17] + b[17];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_18(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 16; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[16] = a[16] - b[16];
    r[17] = a[17] - b[17];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_18(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit b1[9];
    sp_digit* z2 = r + 18;
    (void)sp_3072_add_9(a1, a, &a[9]);
    (void)sp_3072_add_9(b1, b, &b[9]);
    sp_3072_mul_9(z2, &a[9], &b[9]);
    sp_3072_mul_9(z0, a, b);
    sp_3072_mul_9(z1, a1, b1);
    (void)sp_3072_sub_18(z1, z1, z2);
    (void)sp_3072_sub_18(z1, z1, z0);
    (void)sp_3072_add_18(r + 9, r + 9, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_18(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[18];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 18;
    (void)sp_3072_add_9(a1, a, &a[9]);
    sp_3072_sqr_9(z2, &a[9]);
    sp_3072_sqr_9(z0, a);
    sp_3072_sqr_9(z1, a1);
    (void)sp_3072_sub_18(z1, z1, z2);
    (void)sp_3072_sub_18(z1, z1, z0);
    (void)sp_3072_add_18(r + 9, r + 9, z1);
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[32] = a[32] - b[32];
    r[33] = a[33] - b[33];
    r[34] = a[34] - b[34];
    r[35] = a[35] - b[35];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_36(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[32] = a[32] + b[32];
    r[33] = a[33] + b[33];
    r[34] = a[34] + b[34];
    r[35] = a[35] + b[35];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_54(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[36];
    sp_digit p1[36];
    sp_digit p2[36];
    sp_digit p3[36];
    sp_digit p4[36];
    sp_digit p5[36];
    sp_digit t0[36];
    sp_digit t1[36];
    sp_digit t2[36];
    sp_digit a0[18];
    sp_digit a1[18];
    sp_digit a2[18];
    sp_digit b0[18];
    sp_digit b1[18];
    sp_digit b2[18];
    (void)sp_3072_add_18(a0, a, &a[18]);
    (void)sp_3072_add_18(b0, b, &b[18]);
    (void)sp_3072_add_18(a1, &a[18], &a[36]);
    (void)sp_3072_add_18(b1, &b[18], &b[36]);
    (void)sp_3072_add_18(a2, a0, &a[36]);
    (void)sp_3072_add_18(b2, b0, &b[36]);
    sp_3072_mul_18(p0, a, b);
    sp_3072_mul_18(p2, &a[18], &b[18]);
    sp_3072_mul_18(p4, &a[36], &b[36]);
    sp_3072_mul_18(p1, a0, b0);
    sp_3072_mul_18(p3, a1, b1);
    sp_3072_mul_18(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*54U);
    (void)sp_3072_sub_36(t0, p3, p2);
    (void)sp_3072_sub_36(t1, p1, p2);
    (void)sp_3072_sub_36(t2, p5, t0);
    (void)sp_3072_sub_36(t2, t2, t1);
    (void)sp_3072_sub_36(t0, t0, p4);
    (void)sp_3072_sub_36(t1, t1, p0);
    (void)sp_3072_add_36(r, r, p0);
    (void)sp_3072_add_36(&r[18], &r[18], t1);
    (void)sp_3072_add_36(&r[36], &r[36], t2);
    (void)sp_3072_add_36(&r[54], &r[54], t0);
    (void)sp_3072_add_36(&r[72], &r[72], p4);
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_54(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[36];
    sp_digit p1[36];
    sp_digit p2[36];
    sp_digit p3[36];
    sp_digit p4[36];
    sp_digit p5[36];
    sp_digit t0[36];
    sp_digit t1[36];
    sp_digit t2[36];
    sp_digit a0[18];
    sp_digit a1[18];
    sp_digit a2[18];
    (void)sp_3072_add_18(a0, a, &a[18]);
    (void)sp_3072_add_18(a1, &a[18], &a[36]);
    (void)sp_3072_add_18(a2, a0, &a[36]);
    sp_3072_sqr_18(p0, a);
    sp_3072_sqr_18(p2, &a[18]);
    sp_3072_sqr_18(p4, &a[36]);
    sp_3072_sqr_18(p1, a0);
    sp_3072_sqr_18(p3, a1);
    sp_3072_sqr_18(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*54U);
    (void)sp_3072_sub_36(t0, p3, p2);
    (void)sp_3072_sub_36(t1, p1, p2);
    (void)sp_3072_sub_36(t2, p5, t0);
    (void)sp_3072_sub_36(t2, t2, t1);
    (void)sp_3072_sub_36(t0, t0, p4);
    (void)sp_3072_sub_36(t1, t1, p0);
    (void)sp_3072_add_36(r, r, p0);
    (void)sp_3072_add_36(&r[18], &r[18], t1);
    (void)sp_3072_add_36(&r[36], &r[36], t2);
    (void)sp_3072_add_36(&r[54], &r[54], t0);
    (void)sp_3072_add_36(&r[72], &r[72], p4);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 54; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[48] = a[48] + b[48];
    r[49] = a[49] + b[49];
    r[50] = a[50] + b[50];
    r[51] = a[51] + b[51];
    r[52] = a[52] + b[52];
    r[53] = a[53] + b[53];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 54; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[48] = a[48] - b[48];
    r[49] = a[49] - b[49];
    r[50] = a[50] - b[50];
    r[51] = a[51] - b[51];
    r[52] = a[52] - b[52];
    r[53] = a[53] - b[53];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_54(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[53]) * b[53];
    r[107] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 105; k >= 0; k--) {
        for (i = 53; i >= 0; i--) {
            j = k - i;
            if (j >= 54) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_54(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[53]) * a[53];
    r[107] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 105; k >= 0; k--) {
        for (i = 53; i >= 0; i--) {
            j = k - i;
            if (j >= 54 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 27; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[24] = a[24] + b[24];
    r[25] = a[25] + b[25];
    r[26] = a[26] + b[26];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 27; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[24] = a[24] - b[24];
    r[25] = a[25] - b[25];
    r[26] = a[26] - b[26];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_27(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[26]) * b[26];
    r[53] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 51; k >= 0; k--) {
        for (i = 26; i >= 0; i--) {
            j = k - i;
            if (j >= 27) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_27(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j;
    int128_t t[54];

    XMEMSET(t, 0, sizeof(t));
    for (i=0; i<27; i++) {
        for (j=0; j<27; j++) {
            t[i+j] += ((int128_t)a[i]) * b[j];
        }
    }
    for (i=0; i<53; i++) {
        r[i] = t[i] & 0x1ffffffffffffffL;
        t[i+1] += t[i] >> 57;
    }
    r[53] = (sp_digit)t[53];
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_27(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[26]) * a[26];
    r[53] = (sp_digit)(c >> 57);
    c = (c & 0x1ffffffffffffffL) << 57;
    for (k = 51; k >= 0; k--) {
        for (i = 26; i >= 0; i--) {
            j = k - i;
            if (j >= 27 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 114;
        r[k + 1] = (c >> 57) & 0x1ffffffffffffffL;
        c = (c & 0x1ffffffffffffffL) << 57;
    }
    r[0] = (sp_digit)(c >> 57);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_27(sp_digit* r, const sp_digit* a)
{
    int i, j;
    int128_t t[54];

    XMEMSET(t, 0, sizeof(t));
    for (i=0; i<27; i++) {
        for (j=0; j<i; j++) {
            t[i+j] += (((int128_t)a[i]) * a[j]) * 2;
        }
        t[i+i] += ((int128_t)a[i]) * a[i];
    }
    for (i=0; i<53; i++) {
        r[i] = t[i] & 0x1ffffffffffffffL;
        t[i+1] += t[i] >> 57;
    }
    r[53] = (sp_digit)t[53];
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_3072_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x, b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x1ffffffffffffffL;

    /* rho = -1/m mod b */
    *rho = (1L << 57) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_54(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 54; i++) {
        t += tb * a[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[54] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1ffffffffffffffL;
    for (i = 0; i < 48; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 57) + (t[4] & 0x1ffffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 57) + (t[5] & 0x1ffffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 57) + (t[6] & 0x1ffffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 57) + (t[7] & 0x1ffffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 57) + (t[0] & 0x1ffffffffffffffL);
    }
    t[1] = tb * a[49];
    r[49] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
    t[2] = tb * a[50];
    r[50] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
    t[3] = tb * a[51];
    r[51] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
    t[4] = tb * a[52];
    r[52] = (sp_digit)(t[3] >> 57) + (t[4] & 0x1ffffffffffffffL);
    t[5] = tb * a[53];
    r[53] = (sp_digit)(t[4] >> 57) + (t[5] & 0x1ffffffffffffffL);
    r[54] =  (sp_digit)(t[5] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_3072_mont_norm_27(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<26; i++) {
        r[i] = 0x1ffffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[24] = 0x1ffffffffffffffL;
    r[25] = 0x1ffffffffffffffL;
#endif
    r[26] = 0x3fffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_27(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_27(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=26; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[26] - b[26]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[25] - b[25]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[24] - b[24]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 16; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 27; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[24] = a[24] - (b[24] & m);
    r[25] = a[25] - (b[25] & m);
    r[26] = a[26] - (b[26] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 27; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[27] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 24; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[25]; r[25] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[26]; r[26] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    r[27] +=  (sp_digit)(t[2] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 57.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_27(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 26; i++) {
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 24; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
        a[i+9] += a[i+8] >> 57; a[i+8] &= 0x1ffffffffffffffL;
    }
    a[24+1] += a[24] >> 57;
    a[24] &= 0x1ffffffffffffffL;
    a[25+1] += a[25] >> 57;
    a[25] &= 0x1ffffffffffffffL;
#endif
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_27(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_digit n, s;

    s = a[27];
    n = a[26] >> 54;
    for (i = 0; i < 26; i++) {
        n += (s & 0x1ffffffffffffffL) << 3;
        r[i] = n & 0x1ffffffffffffffL;
        n >>= 57;
        s = a[28 + i] + (s >> 57);
    }
    n += s << 3;
    r[26] = n;
#else
    sp_digit n, s;
    int i;

    s = a[27]; n = a[26] >> 54;
    for (i = 0; i < 24; i += 8) {
        n += (s & 0x1ffffffffffffffL) << 3; r[i+0] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+28] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+1] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+29] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+2] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+30] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+3] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+31] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+4] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+32] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+5] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+33] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+6] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+34] + (s >> 57);
        n += (s & 0x1ffffffffffffffL) << 3; r[i+7] = n & 0x1ffffffffffffffL;
        n >>= 57; s = a[i+35] + (s >> 57);
    }
    n += (s & 0x1ffffffffffffffL) << 3; r[24] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[52] + (s >> 57);
    n += (s & 0x1ffffffffffffffL) << 3; r[25] = n & 0x1ffffffffffffffL;
    n >>= 57; s = a[53] + (s >> 57);
    n += s << 3;              r[26] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[27], 0, sizeof(*r) * 27U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_27(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_3072_norm_27(a + 27);

    for (i=0; i<26; i++) {
        mu = (a[i] * mp) & 0x1ffffffffffffffL;
        sp_3072_mul_add_27(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = (a[i] * mp) & 0x3fffffffffffffL;
    sp_3072_mul_add_27(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;

    sp_3072_mont_shift_27(a, a);
    sp_3072_cond_sub_27(a, a, m, 0 - (((a[26] >> 54) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_3072_norm_27(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_mul_27(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_27(r, a, b);
    sp_3072_mont_reduce_27(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_sqr_27(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_3072_sqr_27(r, a);
    sp_3072_mont_reduce_27(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_27(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 27; i++) {
        t += tb * a[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[27] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1ffffffffffffffL;
    for (i = 0; i < 24; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 57) + (t[3] & 0x1ffffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 57) + (t[4] & 0x1ffffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 57) + (t[5] & 0x1ffffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 57) + (t[6] & 0x1ffffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 57) + (t[7] & 0x1ffffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 57) + (t[0] & 0x1ffffffffffffffL);
    }
    t[1] = tb * a[25];
    r[25] = (sp_digit)(t[0] >> 57) + (t[1] & 0x1ffffffffffffffL);
    t[2] = tb * a[26];
    r[26] = (sp_digit)(t[1] >> 57) + (t[2] & 0x1ffffffffffffffL);
    r[27] =  (sp_digit)(t[2] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_27(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 27; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[24] = a[24] + (b[24] & m);
    r[25] = a[25] + (b[25] & m);
    r[26] = a[26] + (b[26] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_3072_div_word_27(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 29 bits. */
    dv = (div >> 28) + 1;
    /* All 57 bits from d1 and top 6 bits from d0. */
    d = (d1 << 6) | (d0 >> 51);
    r = d / dv;
    d -= r * dv;
    /* Up to 34 bits in r */
    /* Next 23 bits from d0. */
    d <<= 23;
    r <<= 23;
    d |= (d0 >> 28) & ((1 << 23) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 57 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 57) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 28) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_27(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[54], t2d[27 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 27 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 2 * 27;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[26];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 27U);
        for (i=26; i>=0; i--) {
            t1[27 + i] += t1[27 + i - 1] >> 57;
            t1[27 + i - 1] &= 0x1ffffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[27 + i];
            d1 <<= 57;
            d1 += t1[27 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_3072_div_word_27(t1[27 + i], t1[27 + i - 1], dv);
#endif

            sp_3072_mul_d_27(t2, d, r1);
            (void)sp_3072_sub_27(&t1[i], &t1[i], t2);
            t1[27 + i] -= t2[27];
            t1[27 + i] += t1[27 + i - 1] >> 57;
            t1[27 + i - 1] &= 0x1ffffffffffffffL;
            r1 = (((-t1[27 + i]) << 57) - t1[27 + i - 1]) / dv;
            r1++;
            sp_3072_mul_d_27(t2, d, r1);
            (void)sp_3072_add_27(&t1[i], &t1[i], t2);
            t1[27 + i] += t1[27 + i - 1] >> 57;
            t1[27 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[27 - 1] += t1[27 - 2] >> 57;
        t1[27 - 2] &= 0x1ffffffffffffffL;
        d1 = t1[27 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_3072_mul_d_27(t2, d, r1);
        (void)sp_3072_sub_27(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 27U);
        for (i=0; i<25; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_3072_cond_add_27(r, r, d, 0 - ((r[26] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_27(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_27(a, m, NULL, r);
}

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_3072_mod_exp_27(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 27 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 27U * 2U);

        norm = t[0] = td;
        t[1] = &td[27 * 2];
        t[2] = &td[2 * 27 * 2];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 27U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_27(t[1], t[1], norm);
        err = sp_3072_mod_27(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_3072_mont_mul_27(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 27 * 2);
            sp_3072_mont_sqr_27(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 27 * 2);
        }

        sp_3072_mont_reduce_27(t[0], m, mp);
        n = sp_3072_cmp_27(t[0], m);
        sp_3072_cond_sub_27(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 27 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][54];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 27 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[27 * 2];
        t[2] = &td[2 * 27 * 2];
#endif
        norm = t[0];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_27(t[1], t[1], norm);
                err = sp_3072_mod_27(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_27(t[1], a, norm);
            err = sp_3072_mod_27(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_3072_mont_mul_27(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_3072_mont_sqr_27(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_3072_mont_reduce_27(t[0], m, mp);
        n = sp_3072_cmp_27(t[0], m);
        sp_3072_cond_sub_27(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][54];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[54];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 54, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 54;
#endif
        norm = t[0];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_27(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_27(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_27(t[1], t[1], norm);
                err = sp_3072_mod_27(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_27(t[1], a, norm);
            err = sp_3072_mod_27(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_27(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_27(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_27(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_27(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_27(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_27(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_27(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_27(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_27(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_27(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_27(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_27(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_27(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_27(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_27(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_27(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_27(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_27(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_27(t[20], t[10], m, mp);
        sp_3072_mont_mul_27(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_27(t[22], t[11], m, mp);
        sp_3072_mont_mul_27(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_27(t[24], t[12], m, mp);
        sp_3072_mont_mul_27(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_27(t[26], t[13], m, mp);
        sp_3072_mont_mul_27(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_27(t[28], t[14], m, mp);
        sp_3072_mont_mul_27(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_27(t[30], t[15], m, mp);
        sp_3072_mont_mul_27(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 27) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);
            sp_3072_mont_sqr_27(rt, rt, m, mp);

            sp_3072_mont_mul_27(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_27(rt, m, mp);
        n = sp_3072_cmp_27(rt, m);
        sp_3072_cond_sub_27(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_3072_mont_norm_54(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<53; i++) {
        r[i] = 0x1ffffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = 0x1ffffffffffffffL;
        r[i + 1] = 0x1ffffffffffffffL;
        r[i + 2] = 0x1ffffffffffffffL;
        r[i + 3] = 0x1ffffffffffffffL;
        r[i + 4] = 0x1ffffffffffffffL;
        r[i + 5] = 0x1ffffffffffffffL;
        r[i + 6] = 0x1ffffffffffffffL;
        r[i + 7] = 0x1ffffffffffffffL;
    }
    r[48] = 0x1ffffffffffffffL;
    r[49] = 0x1ffffffffffffffL;
    r[50] = 0x1ffffffffffffffL;
    r[51] = 0x1ffffffffffffffL;
    r[52] = 0x1ffffffffffffffL;
#endif
    r[53] = 0x7ffffffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_3072_sub_54(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_54(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=53; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[53] - b[53]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[52] - b[52]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[51] - b[51]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[50] - b[50]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[49] - b[49]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[48] - b[48]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 40; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 54; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[48] = a[48] - (b[48] & m);
    r[49] = a[49] - (b[49] & m);
    r[50] = a[50] - (b[50] & m);
    r[51] = a[51] - (b[51] & m);
    r[52] = a[52] - (b[52] & m);
    r[53] = a[53] - (b[53] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 54; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1ffffffffffffffL;
        t >>= 57;
    }
    r[54] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1ffffffffffffffL);
    for (i = 0; i < 48; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 57) + (t[6] & 0x1ffffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 57) + (t[7] & 0x1ffffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 57) + (t[0] & 0x1ffffffffffffffL));
    }
    t[1] = tb * a[49]; r[49] += (sp_digit)((t[0] >> 57) + (t[1] & 0x1ffffffffffffffL));
    t[2] = tb * a[50]; r[50] += (sp_digit)((t[1] >> 57) + (t[2] & 0x1ffffffffffffffL));
    t[3] = tb * a[51]; r[51] += (sp_digit)((t[2] >> 57) + (t[3] & 0x1ffffffffffffffL));
    t[4] = tb * a[52]; r[52] += (sp_digit)((t[3] >> 57) + (t[4] & 0x1ffffffffffffffL));
    t[5] = tb * a[53]; r[53] += (sp_digit)((t[4] >> 57) + (t[5] & 0x1ffffffffffffffL));
    r[54] +=  (sp_digit)(t[5] >> 57);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 57.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_54(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 53; i++) {
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 48; i += 8) {
        a[i+1] += a[i+0] >> 57; a[i+0] &= 0x1ffffffffffffffL;
        a[i+2] += a[i+1] >> 57; a[i+1] &= 0x1ffffffffffffffL;
        a[i+3] += a[i+2] >> 57; a[i+2] &= 0x1ffffffffffffffL;
        a[i+4] += a[i+3] >> 57; a[i+3] &= 0x1ffffffffffffffL;
        a[i+5] += a[i+4] >> 57; a[i+4] &= 0x1ffffffffffffffL;
        a[i+6] += a[i+5] >> 57; a[i+5] &= 0x1ffffffffffffffL;
        a[i+7] += a[i+6] >> 57; a[i+6] &= 0x1ffffffffffffffL;
        a[i+8] += a[i+7] >> 57; a[i+7] &= 0x1ffffffffffffffL;
        a[i+9] += a[i+8] >> 57; a[i+8] &= 0x1ffffffffffffffL;
    }
    a[48+1] += a[48] >> 57;
    a[48] &= 0x1ffffffffffffffL;
    a[49+1] += a[49] >> 57;
    a[49] &= 0x1ffffffffffffffL;
    a[50+1] += a[50] >> 57;
    a[50] &= 0x1ffffffffffffffL;
    a[51+1] += a[51] >> 57;
    a[51] &= 0x1ffffffffffffffL;
    a[52+1] += a[52] >> 57;
    a[52] &= 0x1ffffffffffffffL;
#endif
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_54(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int128_t n = a[53] >> 51;
    n += ((int128_t)a[54]) << 6;

    for (i = 0; i < 53; i++) {
        r[i] = n & 0x1ffffffffffffffL;
        n >>= 57;
        n += ((int128_t)a[55 + i]) << 6;
    }
    r[53] = (sp_digit)n;
#else
    int i;
    int128_t n = a[53] >> 51;
    n += ((int128_t)a[54]) << 6;
    for (i = 0; i < 48; i += 8) {
        r[i + 0] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 55]) << 6;
        r[i + 1] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 56]) << 6;
        r[i + 2] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 57]) << 6;
        r[i + 3] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 58]) << 6;
        r[i + 4] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 59]) << 6;
        r[i + 5] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 60]) << 6;
        r[i + 6] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 61]) << 6;
        r[i + 7] = n & 0x1ffffffffffffffL;
        n >>= 57; n += ((int128_t)a[i + 62]) << 6;
    }
    r[48] = n & 0x1ffffffffffffffL; n >>= 57; n += ((int128_t)a[103]) << 6;
    r[49] = n & 0x1ffffffffffffffL; n >>= 57; n += ((int128_t)a[104]) << 6;
    r[50] = n & 0x1ffffffffffffffL; n >>= 57; n += ((int128_t)a[105]) << 6;
    r[51] = n & 0x1ffffffffffffffL; n >>= 57; n += ((int128_t)a[106]) << 6;
    r[52] = n & 0x1ffffffffffffffL; n >>= 57; n += ((int128_t)a[107]) << 6;
    r[53] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[54], 0, sizeof(*r) * 54U);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_54(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_3072_norm_54(a + 54);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<53; i++) {
            mu = (a[i] * mp) & 0x1ffffffffffffffL;
            sp_3072_mul_add_54(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = (a[i] * mp) & 0x7ffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
    else {
        for (i=0; i<53; i++) {
            mu = a[i] & 0x1ffffffffffffffL;
            sp_3072_mul_add_54(a+i, m, mu);
            a[i+1] += a[i] >> 57;
        }
        mu = a[i] & 0x7ffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
        a[i] &= 0x1ffffffffffffffL;
    }
#else
    for (i=0; i<53; i++) {
        mu = (a[i] * mp) & 0x1ffffffffffffffL;
        sp_3072_mul_add_54(a+i, m, mu);
        a[i+1] += a[i] >> 57;
    }
    mu = (a[i] * mp) & 0x7ffffffffffffL;
    sp_3072_mul_add_54(a+i, m, mu);
    a[i+1] += a[i] >> 57;
    a[i] &= 0x1ffffffffffffffL;
#endif

    sp_3072_mont_shift_54(a, a);
    sp_3072_cond_sub_54(a, a, m, 0 - (((a[53] >> 51) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_3072_norm_54(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_mul_54(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_54(r, a, b);
    sp_3072_mont_reduce_54(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_sqr_54(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_3072_sqr_54(r, a);
    sp_3072_mont_reduce_54(r, m, mp);
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_54(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 54; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 48; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[48] = a[48] + (b[48] & m);
    r[49] = a[49] + (b[49] & m);
    r[50] = a[50] + (b[50] & m);
    r[51] = a[51] + (b[51] & m);
    r[52] = a[52] + (b[52] & m);
    r[53] = a[53] + (b[53] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_3072_div_word_54(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 29 bits. */
    dv = (div >> 28) + 1;
    /* All 57 bits from d1 and top 6 bits from d0. */
    d = (d1 << 6) | (d0 >> 51);
    r = d / dv;
    d -= r * dv;
    /* Up to 34 bits in r */
    /* Next 23 bits from d0. */
    d <<= 23;
    r <<= 23;
    d |= (d0 >> 28) & ((1 << 23) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 57 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 57) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 28) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_54(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[108], t2d[54 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 54 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 2 * 54;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[53];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 54U);
        for (i=53; i>=0; i--) {
            t1[54 + i] += t1[54 + i - 1] >> 57;
            t1[54 + i - 1] &= 0x1ffffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[54 + i];
            d1 <<= 57;
            d1 += t1[54 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_3072_div_word_54(t1[54 + i], t1[54 + i - 1], dv);
#endif

            sp_3072_mul_d_54(t2, d, r1);
            (void)sp_3072_sub_54(&t1[i], &t1[i], t2);
            t1[54 + i] -= t2[54];
            t1[54 + i] += t1[54 + i - 1] >> 57;
            t1[54 + i - 1] &= 0x1ffffffffffffffL;
            r1 = (((-t1[54 + i]) << 57) - t1[54 + i - 1]) / dv;
            r1++;
            sp_3072_mul_d_54(t2, d, r1);
            (void)sp_3072_add_54(&t1[i], &t1[i], t2);
            t1[54 + i] += t1[54 + i - 1] >> 57;
            t1[54 + i - 1] &= 0x1ffffffffffffffL;
        }
        t1[54 - 1] += t1[54 - 2] >> 57;
        t1[54 - 2] &= 0x1ffffffffffffffL;
        d1 = t1[54 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_3072_mul_d_54(t2, d, r1);
        (void)sp_3072_sub_54(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 54U);
        for (i=0; i<52; i++) {
            r[i+1] += r[i] >> 57;
            r[i] &= 0x1ffffffffffffffL;
        }
        sp_3072_cond_add_54(r, r, d, 0 - ((r[53] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_54(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_54(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_3072_mod_exp_54(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 54 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 54U * 2U);

        norm = t[0] = td;
        t[1] = &td[54 * 2];
        t[2] = &td[2 * 54 * 2];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 54U);
        }
    }
    if (err == MP_OKAY) {
        sp_3072_mul_54(t[1], t[1], norm);
        err = sp_3072_mod_54(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_3072_mont_mul_54(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 54 * 2);
            sp_3072_mont_sqr_54(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 54 * 2);
        }

        sp_3072_mont_reduce_54(t[0], m, mp);
        n = sp_3072_cmp_54(t[0], m);
        sp_3072_cond_sub_54(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 54 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][108];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 54 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[54 * 2];
        t[2] = &td[2 * 54 * 2];
#endif
        norm = t[0];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(t[1], t[1], norm);
                err = sp_3072_mod_54(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_54(t[1], a, norm);
            err = sp_3072_mod_54(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 57;
        c = bits % 57;
        n = e[i--] << (57 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 57;
            }

            y = (n >> 56) & 1;
            n <<= 1;

            sp_3072_mont_mul_54(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_3072_mont_sqr_54(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_3072_mont_reduce_54(t[0], m, mp);
        n = sp_3072_cmp_54(t[0], m);
        sp_3072_cond_sub_54(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][108];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[108];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 108, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 108;
#endif
        norm = t[0];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        if (reduceA != 0) {
            err = sp_3072_mod_54(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(t[1], t[1], norm);
                err = sp_3072_mod_54(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_54(t[1], a, norm);
            err = sp_3072_mod_54(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_54(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_54(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_54(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_54(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_54(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_54(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_54(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_54(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_54(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_54(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_54(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_54(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_54(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_54(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_54(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_54(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_54(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_54(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_54(t[20], t[10], m, mp);
        sp_3072_mont_mul_54(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_54(t[22], t[11], m, mp);
        sp_3072_mont_mul_54(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_54(t[24], t[12], m, mp);
        sp_3072_mont_mul_54(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_54(t[26], t[13], m, mp);
        sp_3072_mont_mul_54(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_54(t[28], t[14], m, mp);
        sp_3072_mont_mul_54(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_54(t[30], t[15], m, mp);
        sp_3072_mont_mul_54(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 54) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);
            sp_3072_mont_sqr_54(rt, rt, m, mp);

            sp_3072_mont_mul_54(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_54(rt, m, mp);
        n = sp_3072_cmp_54(rt, m);
        sp_3072_cond_sub_54(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D) && \
           !defined(RSA_LOW_MEM) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_27(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<27; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
    r[24] = a[24] & m;
    r[25] = a[25] & m;
    r[26] = a[26] & m;
#endif
}

#endif
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_3072(const byte* in, word32 inLen, mp_int* em, mp_int* mm,
    byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* d = NULL;
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit* norm;
    sp_digit e[1] = {0};
    sp_digit mp;
    int i;
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
            err = MP_READ_E;
        }
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 54 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 54 * 2;
        m = r + 54 * 2;
        norm = r;

        sp_3072_from_bin(a, 54, in, inLen);
#if DIGIT_BIT >= 57
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 54, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_54(a, a, norm);
        err = sp_3072_mod_54(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=56; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 54 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_54(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_3072_mont_mul_54(r, r, a, m, mp);
            }
        }
        sp_3072_mont_reduce_54(r, m, mp);
        mp = sp_3072_cmp_54(r, m);
        sp_3072_cond_sub_54(r, r, m, ((mp < 0) ?
                    (sp_digit)1 : (sp_digit)0)- 1);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit ad[108], md[54], rd[108];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 57) {
            err = MP_READ_E;
        }
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 54 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 54 * 2;
        m = r + 54 * 2;
    }
#else
    a = ad;
    m = md;
    r = rd;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 54, in, inLen);
#if DIGIT_BIT >= 57
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 54, mm);

        if (e[0] == 0x3) {
            sp_3072_sqr_54(r, a);
            err = sp_3072_mod_54(r, r, m);
            if (err == MP_OKAY) {
                sp_3072_mul_54(r, a, r);
                err = sp_3072_mod_54(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_54(norm, m);

            sp_3072_mul_54(a, a, norm);
            err = sp_3072_mod_54(a, a, m);

            if (err == MP_OKAY) {
                for (i=56; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 108U);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_54(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_3072_mont_mul_54(r, r, a, m, mp);
                    }
                }
                sp_3072_mont_reduce_54(r, m, mp);
                mp = sp_3072_cmp_54(r, m);
                sp_3072_cond_sub_54(r, r, m, ((mp < 0) ?
                           (sp_digit)1 : (sp_digit)0) - 1);
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }
#endif

    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_3072(const byte* in, word32 inLen, mp_int* dm,
    mp_int* pm, mp_int* qm, mp_int* dpm, mp_int* dqm, mp_int* qim, mp_int* mm,
    byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* a;
    sp_digit* d = NULL;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 3072) {
           err = MP_READ_E;
        }
        if (inLen > 384) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 54 * 4, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = d + 54;
        m = a + 54;
        r = a;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(d, 54, dm);
        sp_3072_from_mp(m, 54, mm);
        err = sp_3072_mod_exp_54(r, a, d, 3072, m, 0);
    }
    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 54);
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[108], d[54], m[54];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 3072) {
            err = MP_READ_E;
        }
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(d, 54, dm);
        sp_3072_from_mp(m, 54, mm);
        err = sp_3072_mod_exp_54(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    XMEMSET(d, 0, sizeof(sp_digit) * 54);

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#else
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* t = NULL;
    sp_digit* a;
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmp;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 27 * 11, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (t == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = t;
        p = a + 54 * 2;
        q = p + 27;
        qi = dq = dp = q + 27;
        tmpa = qi + 27;
        tmpb = tmpa + 54;

        tmp = t;
        r = tmp + 54;

        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(p, 27, pm);
        sp_3072_from_mp(q, 27, qm);
        sp_3072_from_mp(dp, 27, dpm);
        err = sp_3072_mod_exp_27(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(dq, 27, dqm);
        err = sp_3072_mod_exp_27(tmpb, a, dq, 1536, q, 1);
    }
    if (err == MP_OKAY) {
        (void)sp_3072_sub_27(tmpa, tmpa, tmpb);
        sp_3072_mask_27(tmp, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        (void)sp_3072_add_27(tmpa, tmpa, tmp);

        sp_3072_from_mp(qi, 27, qim);
        sp_3072_mul_27(tmpa, tmpa, qi);
        err = sp_3072_mod_27(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_27(tmpa, q, tmpa);
        (void)sp_3072_add_54(r, tmpb, tmpa);
        sp_3072_norm_54(r);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_digit) * 27 * 11);
        XFREE(t, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[54 * 2];
    sp_digit p[27], q[27], dp[27], dq[27], qi[27];
    sp_digit tmp[54], tmpa[54], tmpb[54];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 384U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 54, in, inLen);
        sp_3072_from_mp(p, 27, pm);
        sp_3072_from_mp(q, 27, qm);
        sp_3072_from_mp(dp, 27, dpm);
        sp_3072_from_mp(dq, 27, dqm);
        sp_3072_from_mp(qi, 27, qim);

        err = sp_3072_mod_exp_27(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_3072_mod_exp_27(tmpb, a, dq, 1536, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_3072_sub_27(tmpa, tmpa, tmpb);
        sp_3072_mask_27(tmp, p, 0 - ((sp_int_digit)tmpa[26] >> 63));
        (void)sp_3072_add_27(tmpa, tmpa, tmp);
        sp_3072_mul_27(tmpa, tmpa, qi);
        err = sp_3072_mod_27(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_27(tmpa, tmpa, q);
        (void)sp_3072_add_54(r, tmpb, tmpa);
        sp_3072_norm_54(r);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    XMEMSET(tmpa, 0, sizeof(tmpa));
    XMEMSET(tmpb, 0, sizeof(tmpb));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));
    XMEMSET(dp, 0, sizeof(dp));
    XMEMSET(dq, 0, sizeof(dq));
    XMEMSET(qi, 0, sizeof(qi));

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_3072_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (3072 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 57
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 54);
        r->used = 54;
        mp_clamp(r);
#elif DIGIT_BIT < 57
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 54; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 57) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = a[i] >> s;
                }
            }
            s = 57 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 54; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 57 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 57 - s;
            }
            else {
                s += 57;
            }
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_3072(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 54 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 54 * 2;
        m = e + 54;
        r = b;

        sp_3072_from_mp(b, 54, base);
        sp_3072_from_mp(e, 54, exp);
        sp_3072_from_mp(m, 54, mod);

        err = sp_3072_mod_exp_54(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 54U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[108], ed[54], md[54];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 3072) {
            err = MP_READ_E;
        }
    }
    
    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 3072) {
            err = MP_READ_E;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 54 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 54 * 2;
        m = e + 54;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 54, base);
        sp_3072_from_mp(e, 54, exp);
        sp_3072_from_mp(m, 54, mod);

        err = sp_3072_mod_exp_54(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 54U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_3072
SP_NOINLINE static void sp_3072_lshift_54(sp_digit* r, sp_digit* a, byte n)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    r[54] = a[53] >> (57 - n);
    for (i=53; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (57 - n))) & 0x1ffffffffffffffL;
    }
#else
    sp_int_digit s, t;

    s = (sp_int_digit)a[53];
    r[54] = s >> (57U - n);
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (57U - n))) & 0x1ffffffffffffffUL;
#endif
    r[0] = (a[0] << n) & 0x1ffffffffffffffL;
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_3072_mod_exp_2_54(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
#ifndef WOLFSSL_SMALL_STACK
    sp_digit nd[108];
    sp_digit td[55];
#else
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n, o;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 163, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        norm = td;
        tmp  = td + 108;
#else
        norm = nd;
        tmp  = td;
#endif

        XMEMSET(td, 0, sizeof(td));
        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_54(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 56) / 57) - 1;
        c = bits % 57;
        if (c == 0) {
            c = 57;
        }
        if (i < 54) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (7 - c);
            c += 57;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        sp_3072_lshift_54(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (7 - c);
                c += 57;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);
            sp_3072_mont_sqr_54(r, r, m, mp);

            sp_3072_lshift_54(r, r, y);
            sp_3072_mul_d_54(tmp, norm, (r[54] << 6) + (r[53] >> 51));
            r[54] = 0;
            r[53] &= 0x7ffffffffffffL;
            (void)sp_3072_add_54(r, r, tmp);
            sp_3072_norm_54(r);
            o = sp_3072_cmp_54(r, m);
            sp_3072_cond_sub_54(r, r, m, ((o < 0) ?
                                          (sp_digit)1 : (sp_digit)0) - 1);
        }

        sp_3072_mont_reduce_54(r, m, mp);
        n = sp_3072_cmp_54(r, m);
        sp_3072_cond_sub_54(r, r, m, ((n < 0) ?
                                                (sp_digit)1 : (sp_digit)0) - 1);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

#endif /* HAVE_FFDHE_3072 */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 384 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_3072(mp_int* base, const byte* exp, word32 expLen,
    mp_int* mod, byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 384) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 3072) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 54 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 54 * 2;
        m = e + 54;
        r = b;

        sp_3072_from_mp(b, 54, base);
        sp_3072_from_bin(e, 54, exp, expLen);
        sp_3072_from_mp(m, 54, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2 &&
                (m[53] >> 19) == 0xffffffffL) {
            err = sp_3072_mod_exp_2_54(r, e, expLen * 8, m);
        }
        else
    #endif
            err = sp_3072_mod_exp_54(r, b, e, expLen * 8, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
        for (i=0; i<384 && out[i] == 0; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 54U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[108], ed[54], md[54];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 3072) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 384U) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 3072) {
            err = MP_READ_E;
        }
    }
#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 54 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 54 * 2;
        m = e + 54;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 54, base);
        sp_3072_from_bin(e, 54, exp, expLen);
        sp_3072_from_mp(m, 54, mod);

    #ifdef HAVE_FFDHE_3072
        if (base->used == 1 && base->dp[0] == 2U &&
                (m[53] >> 19) == 0xffffffffL) {
            err = sp_3072_mod_exp_2_54(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_3072_mod_exp_54(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_3072
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
        for (i=0; i<384U && out[i] == 0U; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 54U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}
#endif /* WOLFSSL_HAVE_SP_DH */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_1536(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1536) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 1536) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 1536) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 27 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 27 * 2;
        m = e + 27;
        r = b;

        sp_3072_from_mp(b, 27, base);
        sp_3072_from_mp(e, 27, exp);
        sp_3072_from_mp(m, 27, mod);

        err = sp_3072_mod_exp_27(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 27, 0, sizeof(*r) * 27U);
        err = sp_3072_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 27U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[54], ed[27], md[27];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 1536) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 1536) {
            err = MP_READ_E;
        }
    }
    
    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 1536) {
            err = MP_READ_E;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 27 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 27 * 2;
        m = e + 27;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 27, base);
        sp_3072_from_mp(e, 27, exp);
        sp_3072_from_mp(m, 27, mod);

        err = sp_3072_mod_exp_27(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        XMEMSET(r + 27, 0, sizeof(*r) * 27U);
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 27U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH || (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_3072 */

#ifdef WOLFSSL_SP_4096
/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_4096_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 45U) {
            r[j] &= 0x1fffffffffffffL;
            s = 53U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_4096_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 53
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 53
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x1fffffffffffffL;
        s = 53U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 53U) <= (word32)DIGIT_BIT) {
            s += 53U;
            r[j] &= 0x1fffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = 0L;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 53) {
            r[j] &= 0x1fffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 53 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 512
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_4096_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<77; i++) {
        r[i+1] += r[i] >> 53;
        r[i] &= 0x1fffffffffffffL;
    }
    j = 4096 / 8 - 1;
    a[j] = 0;
    for (i=0; i<78 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); b += 8 - s; /*lint !e9033*/
        if (j < 0) {
            break;
        }
        while (b < 53) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 53);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_13(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int128_t t0   = ((int128_t)a[ 0]) * b[ 0];
    int128_t t1   = ((int128_t)a[ 0]) * b[ 1]
                 + ((int128_t)a[ 1]) * b[ 0];
    int128_t t2   = ((int128_t)a[ 0]) * b[ 2]
                 + ((int128_t)a[ 1]) * b[ 1]
                 + ((int128_t)a[ 2]) * b[ 0];
    int128_t t3   = ((int128_t)a[ 0]) * b[ 3]
                 + ((int128_t)a[ 1]) * b[ 2]
                 + ((int128_t)a[ 2]) * b[ 1]
                 + ((int128_t)a[ 3]) * b[ 0];
    int128_t t4   = ((int128_t)a[ 0]) * b[ 4]
                 + ((int128_t)a[ 1]) * b[ 3]
                 + ((int128_t)a[ 2]) * b[ 2]
                 + ((int128_t)a[ 3]) * b[ 1]
                 + ((int128_t)a[ 4]) * b[ 0];
    int128_t t5   = ((int128_t)a[ 0]) * b[ 5]
                 + ((int128_t)a[ 1]) * b[ 4]
                 + ((int128_t)a[ 2]) * b[ 3]
                 + ((int128_t)a[ 3]) * b[ 2]
                 + ((int128_t)a[ 4]) * b[ 1]
                 + ((int128_t)a[ 5]) * b[ 0];
    int128_t t6   = ((int128_t)a[ 0]) * b[ 6]
                 + ((int128_t)a[ 1]) * b[ 5]
                 + ((int128_t)a[ 2]) * b[ 4]
                 + ((int128_t)a[ 3]) * b[ 3]
                 + ((int128_t)a[ 4]) * b[ 2]
                 + ((int128_t)a[ 5]) * b[ 1]
                 + ((int128_t)a[ 6]) * b[ 0];
    int128_t t7   = ((int128_t)a[ 0]) * b[ 7]
                 + ((int128_t)a[ 1]) * b[ 6]
                 + ((int128_t)a[ 2]) * b[ 5]
                 + ((int128_t)a[ 3]) * b[ 4]
                 + ((int128_t)a[ 4]) * b[ 3]
                 + ((int128_t)a[ 5]) * b[ 2]
                 + ((int128_t)a[ 6]) * b[ 1]
                 + ((int128_t)a[ 7]) * b[ 0];
    int128_t t8   = ((int128_t)a[ 0]) * b[ 8]
                 + ((int128_t)a[ 1]) * b[ 7]
                 + ((int128_t)a[ 2]) * b[ 6]
                 + ((int128_t)a[ 3]) * b[ 5]
                 + ((int128_t)a[ 4]) * b[ 4]
                 + ((int128_t)a[ 5]) * b[ 3]
                 + ((int128_t)a[ 6]) * b[ 2]
                 + ((int128_t)a[ 7]) * b[ 1]
                 + ((int128_t)a[ 8]) * b[ 0];
    int128_t t9   = ((int128_t)a[ 0]) * b[ 9]
                 + ((int128_t)a[ 1]) * b[ 8]
                 + ((int128_t)a[ 2]) * b[ 7]
                 + ((int128_t)a[ 3]) * b[ 6]
                 + ((int128_t)a[ 4]) * b[ 5]
                 + ((int128_t)a[ 5]) * b[ 4]
                 + ((int128_t)a[ 6]) * b[ 3]
                 + ((int128_t)a[ 7]) * b[ 2]
                 + ((int128_t)a[ 8]) * b[ 1]
                 + ((int128_t)a[ 9]) * b[ 0];
    int128_t t10  = ((int128_t)a[ 0]) * b[10]
                 + ((int128_t)a[ 1]) * b[ 9]
                 + ((int128_t)a[ 2]) * b[ 8]
                 + ((int128_t)a[ 3]) * b[ 7]
                 + ((int128_t)a[ 4]) * b[ 6]
                 + ((int128_t)a[ 5]) * b[ 5]
                 + ((int128_t)a[ 6]) * b[ 4]
                 + ((int128_t)a[ 7]) * b[ 3]
                 + ((int128_t)a[ 8]) * b[ 2]
                 + ((int128_t)a[ 9]) * b[ 1]
                 + ((int128_t)a[10]) * b[ 0];
    int128_t t11  = ((int128_t)a[ 0]) * b[11]
                 + ((int128_t)a[ 1]) * b[10]
                 + ((int128_t)a[ 2]) * b[ 9]
                 + ((int128_t)a[ 3]) * b[ 8]
                 + ((int128_t)a[ 4]) * b[ 7]
                 + ((int128_t)a[ 5]) * b[ 6]
                 + ((int128_t)a[ 6]) * b[ 5]
                 + ((int128_t)a[ 7]) * b[ 4]
                 + ((int128_t)a[ 8]) * b[ 3]
                 + ((int128_t)a[ 9]) * b[ 2]
                 + ((int128_t)a[10]) * b[ 1]
                 + ((int128_t)a[11]) * b[ 0];
    int128_t t12  = ((int128_t)a[ 0]) * b[12]
                 + ((int128_t)a[ 1]) * b[11]
                 + ((int128_t)a[ 2]) * b[10]
                 + ((int128_t)a[ 3]) * b[ 9]
                 + ((int128_t)a[ 4]) * b[ 8]
                 + ((int128_t)a[ 5]) * b[ 7]
                 + ((int128_t)a[ 6]) * b[ 6]
                 + ((int128_t)a[ 7]) * b[ 5]
                 + ((int128_t)a[ 8]) * b[ 4]
                 + ((int128_t)a[ 9]) * b[ 3]
                 + ((int128_t)a[10]) * b[ 2]
                 + ((int128_t)a[11]) * b[ 1]
                 + ((int128_t)a[12]) * b[ 0];
    int128_t t13  = ((int128_t)a[ 1]) * b[12]
                 + ((int128_t)a[ 2]) * b[11]
                 + ((int128_t)a[ 3]) * b[10]
                 + ((int128_t)a[ 4]) * b[ 9]
                 + ((int128_t)a[ 5]) * b[ 8]
                 + ((int128_t)a[ 6]) * b[ 7]
                 + ((int128_t)a[ 7]) * b[ 6]
                 + ((int128_t)a[ 8]) * b[ 5]
                 + ((int128_t)a[ 9]) * b[ 4]
                 + ((int128_t)a[10]) * b[ 3]
                 + ((int128_t)a[11]) * b[ 2]
                 + ((int128_t)a[12]) * b[ 1];
    int128_t t14  = ((int128_t)a[ 2]) * b[12]
                 + ((int128_t)a[ 3]) * b[11]
                 + ((int128_t)a[ 4]) * b[10]
                 + ((int128_t)a[ 5]) * b[ 9]
                 + ((int128_t)a[ 6]) * b[ 8]
                 + ((int128_t)a[ 7]) * b[ 7]
                 + ((int128_t)a[ 8]) * b[ 6]
                 + ((int128_t)a[ 9]) * b[ 5]
                 + ((int128_t)a[10]) * b[ 4]
                 + ((int128_t)a[11]) * b[ 3]
                 + ((int128_t)a[12]) * b[ 2];
    int128_t t15  = ((int128_t)a[ 3]) * b[12]
                 + ((int128_t)a[ 4]) * b[11]
                 + ((int128_t)a[ 5]) * b[10]
                 + ((int128_t)a[ 6]) * b[ 9]
                 + ((int128_t)a[ 7]) * b[ 8]
                 + ((int128_t)a[ 8]) * b[ 7]
                 + ((int128_t)a[ 9]) * b[ 6]
                 + ((int128_t)a[10]) * b[ 5]
                 + ((int128_t)a[11]) * b[ 4]
                 + ((int128_t)a[12]) * b[ 3];
    int128_t t16  = ((int128_t)a[ 4]) * b[12]
                 + ((int128_t)a[ 5]) * b[11]
                 + ((int128_t)a[ 6]) * b[10]
                 + ((int128_t)a[ 7]) * b[ 9]
                 + ((int128_t)a[ 8]) * b[ 8]
                 + ((int128_t)a[ 9]) * b[ 7]
                 + ((int128_t)a[10]) * b[ 6]
                 + ((int128_t)a[11]) * b[ 5]
                 + ((int128_t)a[12]) * b[ 4];
    int128_t t17  = ((int128_t)a[ 5]) * b[12]
                 + ((int128_t)a[ 6]) * b[11]
                 + ((int128_t)a[ 7]) * b[10]
                 + ((int128_t)a[ 8]) * b[ 9]
                 + ((int128_t)a[ 9]) * b[ 8]
                 + ((int128_t)a[10]) * b[ 7]
                 + ((int128_t)a[11]) * b[ 6]
                 + ((int128_t)a[12]) * b[ 5];
    int128_t t18  = ((int128_t)a[ 6]) * b[12]
                 + ((int128_t)a[ 7]) * b[11]
                 + ((int128_t)a[ 8]) * b[10]
                 + ((int128_t)a[ 9]) * b[ 9]
                 + ((int128_t)a[10]) * b[ 8]
                 + ((int128_t)a[11]) * b[ 7]
                 + ((int128_t)a[12]) * b[ 6];
    int128_t t19  = ((int128_t)a[ 7]) * b[12]
                 + ((int128_t)a[ 8]) * b[11]
                 + ((int128_t)a[ 9]) * b[10]
                 + ((int128_t)a[10]) * b[ 9]
                 + ((int128_t)a[11]) * b[ 8]
                 + ((int128_t)a[12]) * b[ 7];
    int128_t t20  = ((int128_t)a[ 8]) * b[12]
                 + ((int128_t)a[ 9]) * b[11]
                 + ((int128_t)a[10]) * b[10]
                 + ((int128_t)a[11]) * b[ 9]
                 + ((int128_t)a[12]) * b[ 8];
    int128_t t21  = ((int128_t)a[ 9]) * b[12]
                 + ((int128_t)a[10]) * b[11]
                 + ((int128_t)a[11]) * b[10]
                 + ((int128_t)a[12]) * b[ 9];
    int128_t t22  = ((int128_t)a[10]) * b[12]
                 + ((int128_t)a[11]) * b[11]
                 + ((int128_t)a[12]) * b[10];
    int128_t t23  = ((int128_t)a[11]) * b[12]
                 + ((int128_t)a[12]) * b[11];
    int128_t t24  = ((int128_t)a[12]) * b[12];

    t1   += t0  >> 53; r[ 0] = t0  & 0x1fffffffffffffL;
    t2   += t1  >> 53; r[ 1] = t1  & 0x1fffffffffffffL;
    t3   += t2  >> 53; r[ 2] = t2  & 0x1fffffffffffffL;
    t4   += t3  >> 53; r[ 3] = t3  & 0x1fffffffffffffL;
    t5   += t4  >> 53; r[ 4] = t4  & 0x1fffffffffffffL;
    t6   += t5  >> 53; r[ 5] = t5  & 0x1fffffffffffffL;
    t7   += t6  >> 53; r[ 6] = t6  & 0x1fffffffffffffL;
    t8   += t7  >> 53; r[ 7] = t7  & 0x1fffffffffffffL;
    t9   += t8  >> 53; r[ 8] = t8  & 0x1fffffffffffffL;
    t10  += t9  >> 53; r[ 9] = t9  & 0x1fffffffffffffL;
    t11  += t10 >> 53; r[10] = t10 & 0x1fffffffffffffL;
    t12  += t11 >> 53; r[11] = t11 & 0x1fffffffffffffL;
    t13  += t12 >> 53; r[12] = t12 & 0x1fffffffffffffL;
    t14  += t13 >> 53; r[13] = t13 & 0x1fffffffffffffL;
    t15  += t14 >> 53; r[14] = t14 & 0x1fffffffffffffL;
    t16  += t15 >> 53; r[15] = t15 & 0x1fffffffffffffL;
    t17  += t16 >> 53; r[16] = t16 & 0x1fffffffffffffL;
    t18  += t17 >> 53; r[17] = t17 & 0x1fffffffffffffL;
    t19  += t18 >> 53; r[18] = t18 & 0x1fffffffffffffL;
    t20  += t19 >> 53; r[19] = t19 & 0x1fffffffffffffL;
    t21  += t20 >> 53; r[20] = t20 & 0x1fffffffffffffL;
    t22  += t21 >> 53; r[21] = t21 & 0x1fffffffffffffL;
    t23  += t22 >> 53; r[22] = t22 & 0x1fffffffffffffL;
    t24  += t23 >> 53; r[23] = t23 & 0x1fffffffffffffL;
    r[25] = (sp_digit)(t24 >> 53);
                       r[24] = t24 & 0x1fffffffffffffL;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_13(sp_digit* r, const sp_digit* a)
{
    int128_t t0   =  ((int128_t)a[ 0]) * a[ 0];
    int128_t t1   = (((int128_t)a[ 0]) * a[ 1]) * 2;
    int128_t t2   = (((int128_t)a[ 0]) * a[ 2]) * 2
                 +  ((int128_t)a[ 1]) * a[ 1];
    int128_t t3   = (((int128_t)a[ 0]) * a[ 3]
                 +  ((int128_t)a[ 1]) * a[ 2]) * 2;
    int128_t t4   = (((int128_t)a[ 0]) * a[ 4]
                 +  ((int128_t)a[ 1]) * a[ 3]) * 2
                 +  ((int128_t)a[ 2]) * a[ 2];
    int128_t t5   = (((int128_t)a[ 0]) * a[ 5]
                 +  ((int128_t)a[ 1]) * a[ 4]
                 +  ((int128_t)a[ 2]) * a[ 3]) * 2;
    int128_t t6   = (((int128_t)a[ 0]) * a[ 6]
                 +  ((int128_t)a[ 1]) * a[ 5]
                 +  ((int128_t)a[ 2]) * a[ 4]) * 2
                 +  ((int128_t)a[ 3]) * a[ 3];
    int128_t t7   = (((int128_t)a[ 0]) * a[ 7]
                 +  ((int128_t)a[ 1]) * a[ 6]
                 +  ((int128_t)a[ 2]) * a[ 5]
                 +  ((int128_t)a[ 3]) * a[ 4]) * 2;
    int128_t t8   = (((int128_t)a[ 0]) * a[ 8]
                 +  ((int128_t)a[ 1]) * a[ 7]
                 +  ((int128_t)a[ 2]) * a[ 6]
                 +  ((int128_t)a[ 3]) * a[ 5]) * 2
                 +  ((int128_t)a[ 4]) * a[ 4];
    int128_t t9   = (((int128_t)a[ 0]) * a[ 9]
                 +  ((int128_t)a[ 1]) * a[ 8]
                 +  ((int128_t)a[ 2]) * a[ 7]
                 +  ((int128_t)a[ 3]) * a[ 6]
                 +  ((int128_t)a[ 4]) * a[ 5]) * 2;
    int128_t t10  = (((int128_t)a[ 0]) * a[10]
                 +  ((int128_t)a[ 1]) * a[ 9]
                 +  ((int128_t)a[ 2]) * a[ 8]
                 +  ((int128_t)a[ 3]) * a[ 7]
                 +  ((int128_t)a[ 4]) * a[ 6]) * 2
                 +  ((int128_t)a[ 5]) * a[ 5];
    int128_t t11  = (((int128_t)a[ 0]) * a[11]
                 +  ((int128_t)a[ 1]) * a[10]
                 +  ((int128_t)a[ 2]) * a[ 9]
                 +  ((int128_t)a[ 3]) * a[ 8]
                 +  ((int128_t)a[ 4]) * a[ 7]
                 +  ((int128_t)a[ 5]) * a[ 6]) * 2;
    int128_t t12  = (((int128_t)a[ 0]) * a[12]
                 +  ((int128_t)a[ 1]) * a[11]
                 +  ((int128_t)a[ 2]) * a[10]
                 +  ((int128_t)a[ 3]) * a[ 9]
                 +  ((int128_t)a[ 4]) * a[ 8]
                 +  ((int128_t)a[ 5]) * a[ 7]) * 2
                 +  ((int128_t)a[ 6]) * a[ 6];
    int128_t t13  = (((int128_t)a[ 1]) * a[12]
                 +  ((int128_t)a[ 2]) * a[11]
                 +  ((int128_t)a[ 3]) * a[10]
                 +  ((int128_t)a[ 4]) * a[ 9]
                 +  ((int128_t)a[ 5]) * a[ 8]
                 +  ((int128_t)a[ 6]) * a[ 7]) * 2;
    int128_t t14  = (((int128_t)a[ 2]) * a[12]
                 +  ((int128_t)a[ 3]) * a[11]
                 +  ((int128_t)a[ 4]) * a[10]
                 +  ((int128_t)a[ 5]) * a[ 9]
                 +  ((int128_t)a[ 6]) * a[ 8]) * 2
                 +  ((int128_t)a[ 7]) * a[ 7];
    int128_t t15  = (((int128_t)a[ 3]) * a[12]
                 +  ((int128_t)a[ 4]) * a[11]
                 +  ((int128_t)a[ 5]) * a[10]
                 +  ((int128_t)a[ 6]) * a[ 9]
                 +  ((int128_t)a[ 7]) * a[ 8]) * 2;
    int128_t t16  = (((int128_t)a[ 4]) * a[12]
                 +  ((int128_t)a[ 5]) * a[11]
                 +  ((int128_t)a[ 6]) * a[10]
                 +  ((int128_t)a[ 7]) * a[ 9]) * 2
                 +  ((int128_t)a[ 8]) * a[ 8];
    int128_t t17  = (((int128_t)a[ 5]) * a[12]
                 +  ((int128_t)a[ 6]) * a[11]
                 +  ((int128_t)a[ 7]) * a[10]
                 +  ((int128_t)a[ 8]) * a[ 9]) * 2;
    int128_t t18  = (((int128_t)a[ 6]) * a[12]
                 +  ((int128_t)a[ 7]) * a[11]
                 +  ((int128_t)a[ 8]) * a[10]) * 2
                 +  ((int128_t)a[ 9]) * a[ 9];
    int128_t t19  = (((int128_t)a[ 7]) * a[12]
                 +  ((int128_t)a[ 8]) * a[11]
                 +  ((int128_t)a[ 9]) * a[10]) * 2;
    int128_t t20  = (((int128_t)a[ 8]) * a[12]
                 +  ((int128_t)a[ 9]) * a[11]) * 2
                 +  ((int128_t)a[10]) * a[10];
    int128_t t21  = (((int128_t)a[ 9]) * a[12]
                 +  ((int128_t)a[10]) * a[11]) * 2;
    int128_t t22  = (((int128_t)a[10]) * a[12]) * 2
                 +  ((int128_t)a[11]) * a[11];
    int128_t t23  = (((int128_t)a[11]) * a[12]) * 2;
    int128_t t24  =  ((int128_t)a[12]) * a[12];

    t1   += t0  >> 53; r[ 0] = t0  & 0x1fffffffffffffL;
    t2   += t1  >> 53; r[ 1] = t1  & 0x1fffffffffffffL;
    t3   += t2  >> 53; r[ 2] = t2  & 0x1fffffffffffffL;
    t4   += t3  >> 53; r[ 3] = t3  & 0x1fffffffffffffL;
    t5   += t4  >> 53; r[ 4] = t4  & 0x1fffffffffffffL;
    t6   += t5  >> 53; r[ 5] = t5  & 0x1fffffffffffffL;
    t7   += t6  >> 53; r[ 6] = t6  & 0x1fffffffffffffL;
    t8   += t7  >> 53; r[ 7] = t7  & 0x1fffffffffffffL;
    t9   += t8  >> 53; r[ 8] = t8  & 0x1fffffffffffffL;
    t10  += t9  >> 53; r[ 9] = t9  & 0x1fffffffffffffL;
    t11  += t10 >> 53; r[10] = t10 & 0x1fffffffffffffL;
    t12  += t11 >> 53; r[11] = t11 & 0x1fffffffffffffL;
    t13  += t12 >> 53; r[12] = t12 & 0x1fffffffffffffL;
    t14  += t13 >> 53; r[13] = t13 & 0x1fffffffffffffL;
    t15  += t14 >> 53; r[14] = t14 & 0x1fffffffffffffL;
    t16  += t15 >> 53; r[15] = t15 & 0x1fffffffffffffL;
    t17  += t16 >> 53; r[16] = t16 & 0x1fffffffffffffL;
    t18  += t17 >> 53; r[17] = t17 & 0x1fffffffffffffL;
    t19  += t18 >> 53; r[18] = t18 & 0x1fffffffffffffL;
    t20  += t19 >> 53; r[19] = t19 & 0x1fffffffffffffL;
    t21  += t20 >> 53; r[20] = t20 & 0x1fffffffffffffL;
    t22  += t21 >> 53; r[21] = t21 & 0x1fffffffffffffL;
    t23  += t22 >> 53; r[22] = t22 & 0x1fffffffffffffL;
    t24  += t23 >> 53; r[23] = t23 & 0x1fffffffffffffL;
    r[25] = (sp_digit)(t24 >> 53);
                       r[24] = t24 & 0x1fffffffffffffL;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_13(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];
    r[ 9] = a[ 9] + b[ 9];
    r[10] = a[10] + b[10];
    r[11] = a[11] + b[11];
    r[12] = a[12] + b[12];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[24] = a[24] - b[24];
    r[25] = a[25] - b[25];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_26(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[24] = a[24] + b[24];
    r[25] = a[25] + b[25];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_39(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[26];
    sp_digit p1[26];
    sp_digit p2[26];
    sp_digit p3[26];
    sp_digit p4[26];
    sp_digit p5[26];
    sp_digit t0[26];
    sp_digit t1[26];
    sp_digit t2[26];
    sp_digit a0[13];
    sp_digit a1[13];
    sp_digit a2[13];
    sp_digit b0[13];
    sp_digit b1[13];
    sp_digit b2[13];
    (void)sp_4096_add_13(a0, a, &a[13]);
    (void)sp_4096_add_13(b0, b, &b[13]);
    (void)sp_4096_add_13(a1, &a[13], &a[26]);
    (void)sp_4096_add_13(b1, &b[13], &b[26]);
    (void)sp_4096_add_13(a2, a0, &a[26]);
    (void)sp_4096_add_13(b2, b0, &b[26]);
    sp_4096_mul_13(p0, a, b);
    sp_4096_mul_13(p2, &a[13], &b[13]);
    sp_4096_mul_13(p4, &a[26], &b[26]);
    sp_4096_mul_13(p1, a0, b0);
    sp_4096_mul_13(p3, a1, b1);
    sp_4096_mul_13(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2U*39U);
    (void)sp_4096_sub_26(t0, p3, p2);
    (void)sp_4096_sub_26(t1, p1, p2);
    (void)sp_4096_sub_26(t2, p5, t0);
    (void)sp_4096_sub_26(t2, t2, t1);
    (void)sp_4096_sub_26(t0, t0, p4);
    (void)sp_4096_sub_26(t1, t1, p0);
    (void)sp_4096_add_26(r, r, p0);
    (void)sp_4096_add_26(&r[13], &r[13], t1);
    (void)sp_4096_add_26(&r[26], &r[26], t2);
    (void)sp_4096_add_26(&r[39], &r[39], t0);
    (void)sp_4096_add_26(&r[52], &r[52], p4);
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_39(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[26];
    sp_digit p1[26];
    sp_digit p2[26];
    sp_digit p3[26];
    sp_digit p4[26];
    sp_digit p5[26];
    sp_digit t0[26];
    sp_digit t1[26];
    sp_digit t2[26];
    sp_digit a0[13];
    sp_digit a1[13];
    sp_digit a2[13];
    (void)sp_4096_add_13(a0, a, &a[13]);
    (void)sp_4096_add_13(a1, &a[13], &a[26]);
    (void)sp_4096_add_13(a2, a0, &a[26]);
    sp_4096_sqr_13(p0, a);
    sp_4096_sqr_13(p2, &a[13]);
    sp_4096_sqr_13(p4, &a[26]);
    sp_4096_sqr_13(p1, a0);
    sp_4096_sqr_13(p3, a1);
    sp_4096_sqr_13(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2U*39U);
    (void)sp_4096_sub_26(t0, p3, p2);
    (void)sp_4096_sub_26(t1, p1, p2);
    (void)sp_4096_sub_26(t2, p5, t0);
    (void)sp_4096_sub_26(t2, t2, t1);
    (void)sp_4096_sub_26(t0, t0, p4);
    (void)sp_4096_sub_26(t1, t1, p0);
    (void)sp_4096_add_26(r, r, p0);
    (void)sp_4096_add_26(&r[13], &r[13], t1);
    (void)sp_4096_add_26(&r[26], &r[26], t2);
    (void)sp_4096_add_26(&r[39], &r[39], t0);
    (void)sp_4096_add_26(&r[52], &r[52], p4);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[32] = a[32] + b[32];
    r[33] = a[33] + b[33];
    r[34] = a[34] + b[34];
    r[35] = a[35] + b[35];
    r[36] = a[36] + b[36];
    r[37] = a[37] + b[37];
    r[38] = a[38] + b[38];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[72] = a[72] + b[72];
    r[73] = a[73] + b[73];
    r[74] = a[74] + b[74];
    r[75] = a[75] + b[75];
    r[76] = a[76] + b[76];
    r[77] = a[77] + b[77];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[72] = a[72] - b[72];
    r[73] = a[73] - b[73];
    r[74] = a[74] - b[74];
    r[75] = a[75] - b[75];
    r[76] = a[76] - b[76];
    r[77] = a[77] - b[77];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_78(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[78];
    sp_digit* a1 = z1;
    sp_digit b1[39];
    sp_digit* z2 = r + 78;
    (void)sp_4096_add_39(a1, a, &a[39]);
    (void)sp_4096_add_39(b1, b, &b[39]);
    sp_4096_mul_39(z2, &a[39], &b[39]);
    sp_4096_mul_39(z0, a, b);
    sp_4096_mul_39(z1, a1, b1);
    (void)sp_4096_sub_78(z1, z1, z2);
    (void)sp_4096_sub_78(z1, z1, z0);
    (void)sp_4096_add_78(r + 39, r + 39, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_78(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[78];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 78;
    (void)sp_4096_add_39(a1, a, &a[39]);
    sp_4096_sqr_39(z2, &a[39]);
    sp_4096_sqr_39(z0, a);
    sp_4096_sqr_39(z1, a1);
    (void)sp_4096_sub_78(z1, z1, z2);
    (void)sp_4096_sub_78(z1, z1, z0);
    (void)sp_4096_add_78(r + 39, r + 39, z1);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_78(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[77]) * b[77];
    r[155] = (sp_digit)(c >> 53);
    c = (c & 0x1fffffffffffffL) << 53;
    for (k = 153; k >= 0; k--) {
        for (i = 77; i >= 0; i--) {
            j = k - i;
            if (j >= 78) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 106;
        r[k + 1] = (c >> 53) & 0x1fffffffffffffL;
        c = (c & 0x1fffffffffffffL) << 53;
    }
    r[0] = (sp_digit)(c >> 53);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_78(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[77]) * a[77];
    r[155] = (sp_digit)(c >> 53);
    c = (c & 0x1fffffffffffffL) << 53;
    for (k = 153; k >= 0; k--) {
        for (i = 77; i >= 0; i--) {
            j = k - i;
            if (j >= 78 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 106;
        r[k + 1] = (c >> 53) & 0x1fffffffffffffL;
        c = (c & 0x1fffffffffffffL) << 53;
    }
    r[0] = (sp_digit)(c >> 53);
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 39; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 39; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[32] = a[32] - b[32];
    r[33] = a[33] - b[33];
    r[34] = a[34] - b[34];
    r[35] = a[35] - b[35];
    r[36] = a[36] - b[36];
    r[37] = a[37] - b[37];
    r[38] = a[38] - b[38];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_4096_mul_39(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[38]) * b[38];
    r[77] = (sp_digit)(c >> 53);
    c = (c & 0x1fffffffffffffL) << 53;
    for (k = 75; k >= 0; k--) {
        for (i = 38; i >= 0; i--) {
            j = k - i;
            if (j >= 39) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 106;
        r[k + 1] = (c >> 53) & 0x1fffffffffffffL;
        c = (c & 0x1fffffffffffffL) << 53;
    }
    r[0] = (sp_digit)(c >> 53);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_4096_sqr_39(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[38]) * a[38];
    r[77] = (sp_digit)(c >> 53);
    c = (c & 0x1fffffffffffffL) << 53;
    for (k = 75; k >= 0; k--) {
        for (i = 38; i >= 0; i--) {
            j = k - i;
            if (j >= 39 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 106;
        r[k + 1] = (c >> 53) & 0x1fffffffffffffL;
        c = (c & 0x1fffffffffffffL) << 53;
    }
    r[0] = (sp_digit)(c >> 53);
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_4096_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x, b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
    x &= 0x1fffffffffffffL;

    /* rho = -1/m mod b */
    *rho = (1L << 53) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_78(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 78; i++) {
        t += tb * a[i];
        r[i] = t & 0x1fffffffffffffL;
        t >>= 53;
    }
    r[78] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1fffffffffffffL;
    for (i = 0; i < 72; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 53) + (t[4] & 0x1fffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 53) + (t[5] & 0x1fffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 53) + (t[6] & 0x1fffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 53) + (t[7] & 0x1fffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 53) + (t[0] & 0x1fffffffffffffL);
    }
    t[1] = tb * a[73];
    r[73] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
    t[2] = tb * a[74];
    r[74] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
    t[3] = tb * a[75];
    r[75] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
    t[4] = tb * a[76];
    r[76] = (sp_digit)(t[3] >> 53) + (t[4] & 0x1fffffffffffffL);
    t[5] = tb * a[77];
    r[77] = (sp_digit)(t[4] >> 53) + (t[5] & 0x1fffffffffffffL);
    r[78] =  (sp_digit)(t[5] >> 53);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_4096_mont_norm_39(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<38; i++) {
        r[i] = 0x1fffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = 0x1fffffffffffffL;
        r[i + 1] = 0x1fffffffffffffL;
        r[i + 2] = 0x1fffffffffffffL;
        r[i + 3] = 0x1fffffffffffffL;
        r[i + 4] = 0x1fffffffffffffL;
        r[i + 5] = 0x1fffffffffffffL;
        r[i + 6] = 0x1fffffffffffffL;
        r[i + 7] = 0x1fffffffffffffL;
    }
    r[32] = 0x1fffffffffffffL;
    r[33] = 0x1fffffffffffffL;
    r[34] = 0x1fffffffffffffL;
    r[35] = 0x1fffffffffffffL;
    r[36] = 0x1fffffffffffffL;
    r[37] = 0x1fffffffffffffL;
#endif
    r[38] = 0x3ffffffffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_39(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_39(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=38; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[38] - b[38]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[37] - b[37]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[36] - b[36]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[35] - b[35]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[34] - b[34]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[33] - b[33]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[32] - b[32]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 24; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 39; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[32] = a[32] - (b[32] & m);
    r[33] = a[33] - (b[33] & m);
    r[34] = a[34] - (b[34] & m);
    r[35] = a[35] - (b[35] & m);
    r[36] = a[36] - (b[36] & m);
    r[37] = a[37] - (b[37] & m);
    r[38] = a[38] - (b[38] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 39; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1fffffffffffffL;
        t >>= 53;
    }
    r[39] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1fffffffffffffL);
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 53) + (t[7] & 0x1fffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 53) + (t[0] & 0x1fffffffffffffL));
    }
    t[1] = tb * a[33]; r[33] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
    t[2] = tb * a[34]; r[34] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
    t[3] = tb * a[35]; r[35] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
    t[4] = tb * a[36]; r[36] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
    t[5] = tb * a[37]; r[37] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
    t[6] = tb * a[38]; r[38] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
    r[39] +=  (sp_digit)(t[6] >> 53);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 53.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_39(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 38; i++) {
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 32; i += 8) {
        a[i+1] += a[i+0] >> 53; a[i+0] &= 0x1fffffffffffffL;
        a[i+2] += a[i+1] >> 53; a[i+1] &= 0x1fffffffffffffL;
        a[i+3] += a[i+2] >> 53; a[i+2] &= 0x1fffffffffffffL;
        a[i+4] += a[i+3] >> 53; a[i+3] &= 0x1fffffffffffffL;
        a[i+5] += a[i+4] >> 53; a[i+4] &= 0x1fffffffffffffL;
        a[i+6] += a[i+5] >> 53; a[i+5] &= 0x1fffffffffffffL;
        a[i+7] += a[i+6] >> 53; a[i+6] &= 0x1fffffffffffffL;
        a[i+8] += a[i+7] >> 53; a[i+7] &= 0x1fffffffffffffL;
        a[i+9] += a[i+8] >> 53; a[i+8] &= 0x1fffffffffffffL;
    }
    a[32+1] += a[32] >> 53;
    a[32] &= 0x1fffffffffffffL;
    a[33+1] += a[33] >> 53;
    a[33] &= 0x1fffffffffffffL;
    a[34+1] += a[34] >> 53;
    a[34] &= 0x1fffffffffffffL;
    a[35+1] += a[35] >> 53;
    a[35] &= 0x1fffffffffffffL;
    a[36+1] += a[36] >> 53;
    a[36] &= 0x1fffffffffffffL;
    a[37+1] += a[37] >> 53;
    a[37] &= 0x1fffffffffffffL;
#endif
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_39(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int128_t n = a[38] >> 34;
    n += ((int128_t)a[39]) << 19;

    for (i = 0; i < 38; i++) {
        r[i] = n & 0x1fffffffffffffL;
        n >>= 53;
        n += ((int128_t)a[40 + i]) << 19;
    }
    r[38] = (sp_digit)n;
#else
    int i;
    int128_t n = a[38] >> 34;
    n += ((int128_t)a[39]) << 19;
    for (i = 0; i < 32; i += 8) {
        r[i + 0] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 40]) << 19;
        r[i + 1] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 41]) << 19;
        r[i + 2] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 42]) << 19;
        r[i + 3] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 43]) << 19;
        r[i + 4] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 44]) << 19;
        r[i + 5] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 45]) << 19;
        r[i + 6] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 46]) << 19;
        r[i + 7] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 47]) << 19;
    }
    r[32] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[72]) << 19;
    r[33] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[73]) << 19;
    r[34] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[74]) << 19;
    r[35] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[75]) << 19;
    r[36] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[76]) << 19;
    r[37] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[77]) << 19;
    r[38] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[39], 0, sizeof(*r) * 39U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_39(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_4096_norm_39(a + 39);

    for (i=0; i<38; i++) {
        mu = (a[i] * mp) & 0x1fffffffffffffL;
        sp_4096_mul_add_39(a+i, m, mu);
        a[i+1] += a[i] >> 53;
    }
    mu = (a[i] * mp) & 0x3ffffffffL;
    sp_4096_mul_add_39(a+i, m, mu);
    a[i+1] += a[i] >> 53;
    a[i] &= 0x1fffffffffffffL;

    sp_4096_mont_shift_39(a, a);
    sp_4096_cond_sub_39(a, a, m, 0 - (((a[38] >> 34) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_4096_norm_39(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_4096_mont_mul_39(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_39(r, a, b);
    sp_4096_mont_reduce_39(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_4096_mont_sqr_39(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_4096_sqr_39(r, a);
    sp_4096_mont_reduce_39(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_39(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 39; i++) {
        t += tb * a[i];
        r[i] = t & 0x1fffffffffffffL;
        t >>= 53;
    }
    r[39] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1fffffffffffffL;
    for (i = 0; i < 32; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 53) + (t[4] & 0x1fffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 53) + (t[5] & 0x1fffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 53) + (t[6] & 0x1fffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 53) + (t[7] & 0x1fffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 53) + (t[0] & 0x1fffffffffffffL);
    }
    t[1] = tb * a[33];
    r[33] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
    t[2] = tb * a[34];
    r[34] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
    t[3] = tb * a[35];
    r[35] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
    t[4] = tb * a[36];
    r[36] = (sp_digit)(t[3] >> 53) + (t[4] & 0x1fffffffffffffL);
    t[5] = tb * a[37];
    r[37] = (sp_digit)(t[4] >> 53) + (t[5] & 0x1fffffffffffffL);
    t[6] = tb * a[38];
    r[38] = (sp_digit)(t[5] >> 53) + (t[6] & 0x1fffffffffffffL);
    r[39] =  (sp_digit)(t[6] >> 53);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_4096_cond_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 39; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[32] = a[32] + (b[32] & m);
    r[33] = a[33] + (b[33] & m);
    r[34] = a[34] + (b[34] & m);
    r[35] = a[35] + (b[35] & m);
    r[36] = a[36] + (b[36] & m);
    r[37] = a[37] + (b[37] & m);
    r[38] = a[38] + (b[38] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_39(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 39; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif
SP_NOINLINE static void sp_4096_rshift_39(sp_digit* r, sp_digit* a, byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<38; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (53 - n))) & 0x1fffffffffffffL;
    }
#else
    for (i=0; i<32; i += 8) {
        r[i+0] = ((a[i+0] >> n) | (a[i+1] << (53 - n))) & 0x1fffffffffffffL;
        r[i+1] = ((a[i+1] >> n) | (a[i+2] << (53 - n))) & 0x1fffffffffffffL;
        r[i+2] = ((a[i+2] >> n) | (a[i+3] << (53 - n))) & 0x1fffffffffffffL;
        r[i+3] = ((a[i+3] >> n) | (a[i+4] << (53 - n))) & 0x1fffffffffffffL;
        r[i+4] = ((a[i+4] >> n) | (a[i+5] << (53 - n))) & 0x1fffffffffffffL;
        r[i+5] = ((a[i+5] >> n) | (a[i+6] << (53 - n))) & 0x1fffffffffffffL;
        r[i+6] = ((a[i+6] >> n) | (a[i+7] << (53 - n))) & 0x1fffffffffffffL;
        r[i+7] = ((a[i+7] >> n) | (a[i+8] << (53 - n))) & 0x1fffffffffffffL;
    }
    r[32] = ((a[32] >> n) | (a[33] << (53 - n))) & 0x1fffffffffffffL;
    r[33] = ((a[33] >> n) | (a[34] << (53 - n))) & 0x1fffffffffffffL;
    r[34] = ((a[34] >> n) | (a[35] << (53 - n))) & 0x1fffffffffffffL;
    r[35] = ((a[35] >> n) | (a[36] << (53 - n))) & 0x1fffffffffffffL;
    r[36] = ((a[36] >> n) | (a[37] << (53 - n))) & 0x1fffffffffffffL;
    r[37] = ((a[37] >> n) | (a[38] << (53 - n))) & 0x1fffffffffffffL;
#endif
    r[38] = a[38] >> n;
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_4096_div_word_39(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 27 bits. */
    dv = (div >> 26) + 1;
    /* All 53 bits from d1 and top 10 bits from d0. */
    d = (d1 << 10) | (d0 >> 43);
    r = d / dv;
    d -= r * dv;
    /* Up to 36 bits in r */
    /* Next 17 bits from d0. */
    d <<= 17;
    r <<= 17;
    d |= (d0 >> 26) & ((1 << 17) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 53 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 53) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 26) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_39(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[78 + 1], t2d[39 + 1], sdd[39 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* sd;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 39 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    (void)m;

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 78 + 1;
        sd = t2 + 39 + 1;
#else
        t1 = t1d;
        t2 = t2d;
        sd = sdd;
#endif

        sp_4096_mul_d_39(sd, d, 1L << 19);
        sp_4096_mul_d_78(t1, a, 1L << 19);
        dv = sd[38];
        for (i=39; i>=0; i--) {
            t1[39 + i] += t1[39 + i - 1] >> 53;
            t1[39 + i - 1] &= 0x1fffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[39 + i];
            d1 <<= 53;
            d1 += t1[39 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_4096_div_word_39(t1[39 + i], t1[39 + i - 1], dv);
#endif

            sp_4096_mul_d_39(t2, sd, r1);
            (void)sp_4096_sub_39(&t1[i], &t1[i], t2);
            t1[39 + i] -= t2[39];
            t1[39 + i] += t1[39 + i - 1] >> 53;
            t1[39 + i - 1] &= 0x1fffffffffffffL;
            r1 = (((-t1[39 + i]) << 53) - t1[39 + i - 1]) / dv;
            r1 -= t1[39 + i];
            sp_4096_mul_d_39(t2, sd, r1);
            (void)sp_4096_add_39(&t1[i], &t1[i], t2);
            t1[39 + i] += t1[39 + i - 1] >> 53;
            t1[39 + i - 1] &= 0x1fffffffffffffL;
        }
        t1[39 - 1] += t1[39 - 2] >> 53;
        t1[39 - 2] &= 0x1fffffffffffffL;
        d1 = t1[39 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_4096_mul_d_39(t2, sd, r1);
        sp_4096_sub_39(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 39U);
        for (i=0; i<37; i++) {
            r[i+1] += r[i] >> 53;
            r[i] &= 0x1fffffffffffffL;
        }
        sp_4096_cond_add_39(r, r, sd, 0 - ((r[38] < 0) ?
                    (sp_digit)1 : (sp_digit)0));

        sp_4096_norm_39(r);
        sp_4096_rshift_39(r, r, 19);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_39(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_39(a, m, NULL, r);
}

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_4096_mod_exp_39(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 39 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 39U * 2U);

        norm = t[0] = td;
        t[1] = &td[39 * 2];
        t[2] = &td[2 * 39 * 2];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 39U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_39(t[1], t[1], norm);
        err = sp_4096_mod_39(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (n >> 52) & 1;
            n <<= 1;

            sp_4096_mont_mul_39(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 39 * 2);
            sp_4096_mont_sqr_39(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 39 * 2);
        }

        sp_4096_mont_reduce_39(t[0], m, mp);
        n = sp_4096_cmp_39(t[0], m);
        sp_4096_cond_sub_39(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 39 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][78];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 39 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[39 * 2];
        t[2] = &td[2 * 39 * 2];
#endif
        norm = t[0];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_39(t[1], t[1], norm);
                err = sp_4096_mod_39(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_39(t[1], a, norm);
            err = sp_4096_mod_39(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (n >> 52) & 1;
            n <<= 1;

            sp_4096_mont_mul_39(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_4096_mont_sqr_39(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_4096_mont_reduce_39(t[0], m, mp);
        n = sp_4096_cmp_39(t[0], m);
        sp_4096_cond_sub_39(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][78];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[78];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 78, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 78;
#endif
        norm = t[0];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_39(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_39(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_39(t[1], t[1], norm);
                err = sp_4096_mod_39(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_39(t[1], a, norm);
            err = sp_4096_mod_39(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_39(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_39(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_39(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_39(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_39(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_39(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_39(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_39(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_39(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_39(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_39(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_39(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_39(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_39(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_39(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_39(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_39(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_39(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_39(t[20], t[10], m, mp);
        sp_4096_mont_mul_39(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_39(t[22], t[11], m, mp);
        sp_4096_mont_mul_39(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_39(t[24], t[12], m, mp);
        sp_4096_mont_mul_39(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_39(t[26], t[13], m, mp);
        sp_4096_mont_mul_39(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_39(t[28], t[14], m, mp);
        sp_4096_mont_mul_39(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_39(t[30], t[15], m, mp);
        sp_4096_mont_mul_39(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 39) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (11 - c);
                c += 53;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);
            sp_4096_mont_sqr_39(rt, rt, m, mp);

            sp_4096_mont_mul_39(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_39(rt, m, mp);
        n = sp_4096_cmp_39(rt, m);
        sp_4096_cond_sub_39(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 4096 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_4096_mont_norm_78(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<77; i++) {
        r[i] = 0x1fffffffffffffL;
    }
#else
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = 0x1fffffffffffffL;
        r[i + 1] = 0x1fffffffffffffL;
        r[i + 2] = 0x1fffffffffffffL;
        r[i + 3] = 0x1fffffffffffffL;
        r[i + 4] = 0x1fffffffffffffL;
        r[i + 5] = 0x1fffffffffffffL;
        r[i + 6] = 0x1fffffffffffffL;
        r[i + 7] = 0x1fffffffffffffL;
    }
    r[72] = 0x1fffffffffffffL;
    r[73] = 0x1fffffffffffffL;
    r[74] = 0x1fffffffffffffL;
    r[75] = 0x1fffffffffffffL;
    r[76] = 0x1fffffffffffffL;
#endif
    r[77] = 0x7fffL;

    /* r = (2^n - 1) mod n */
    (void)sp_4096_sub_78(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_4096_cmp_78(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=77; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    int i;

    r |= (a[77] - b[77]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[76] - b[76]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[75] - b[75]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[74] - b[74]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[73] - b[73]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[72] - b[72]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    for (i = 64; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 6] - b[i + 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 5] - b[i + 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 4] - b[i + 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 3] - b[i + 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 2] - b[i + 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 1] - b[i + 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
        r |= (a[i + 0] - b[i + 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_4096_cond_sub_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[72] = a[72] - (b[72] & m);
    r[73] = a[73] - (b[73] & m);
    r[74] = a[74] - (b[74] & m);
    r[75] = a[75] - (b[75] & m);
    r[76] = a[76] - (b[76] & m);
    r[77] = a[77] - (b[77] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 78; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x1fffffffffffffL;
        t >>= 53;
    }
    r[78] += t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += (sp_digit)(t[0] & 0x1fffffffffffffL);
    for (i = 0; i < 72; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
        t[2] = tb * a[i+2];
        r[i+2] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
        t[3] = tb * a[i+3];
        r[i+3] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
        t[4] = tb * a[i+4];
        r[i+4] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
        t[5] = tb * a[i+5];
        r[i+5] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
        t[6] = tb * a[i+6];
        r[i+6] += (sp_digit)((t[5] >> 53) + (t[6] & 0x1fffffffffffffL));
        t[7] = tb * a[i+7];
        r[i+7] += (sp_digit)((t[6] >> 53) + (t[7] & 0x1fffffffffffffL));
        t[0] = tb * a[i+8];
        r[i+8] += (sp_digit)((t[7] >> 53) + (t[0] & 0x1fffffffffffffL));
    }
    t[1] = tb * a[73]; r[73] += (sp_digit)((t[0] >> 53) + (t[1] & 0x1fffffffffffffL));
    t[2] = tb * a[74]; r[74] += (sp_digit)((t[1] >> 53) + (t[2] & 0x1fffffffffffffL));
    t[3] = tb * a[75]; r[75] += (sp_digit)((t[2] >> 53) + (t[3] & 0x1fffffffffffffL));
    t[4] = tb * a[76]; r[76] += (sp_digit)((t[3] >> 53) + (t[4] & 0x1fffffffffffffL));
    t[5] = tb * a[77]; r[77] += (sp_digit)((t[4] >> 53) + (t[5] & 0x1fffffffffffffL));
    r[78] +=  (sp_digit)(t[5] >> 53);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 53.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_4096_norm_78(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 77; i++) {
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
#else
    int i;
    for (i = 0; i < 72; i += 8) {
        a[i+1] += a[i+0] >> 53; a[i+0] &= 0x1fffffffffffffL;
        a[i+2] += a[i+1] >> 53; a[i+1] &= 0x1fffffffffffffL;
        a[i+3] += a[i+2] >> 53; a[i+2] &= 0x1fffffffffffffL;
        a[i+4] += a[i+3] >> 53; a[i+3] &= 0x1fffffffffffffL;
        a[i+5] += a[i+4] >> 53; a[i+4] &= 0x1fffffffffffffL;
        a[i+6] += a[i+5] >> 53; a[i+5] &= 0x1fffffffffffffL;
        a[i+7] += a[i+6] >> 53; a[i+6] &= 0x1fffffffffffffL;
        a[i+8] += a[i+7] >> 53; a[i+7] &= 0x1fffffffffffffL;
        a[i+9] += a[i+8] >> 53; a[i+8] &= 0x1fffffffffffffL;
    }
    a[72+1] += a[72] >> 53;
    a[72] &= 0x1fffffffffffffL;
    a[73+1] += a[73] >> 53;
    a[73] &= 0x1fffffffffffffL;
    a[74+1] += a[74] >> 53;
    a[74] &= 0x1fffffffffffffL;
    a[75+1] += a[75] >> 53;
    a[75] &= 0x1fffffffffffffL;
    a[76+1] += a[76] >> 53;
    a[76] &= 0x1fffffffffffffL;
#endif
}

/* Shift the result in the high 4096 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_4096_mont_shift_78(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int128_t n = a[77] >> 15;
    n += ((int128_t)a[78]) << 38;

    for (i = 0; i < 77; i++) {
        r[i] = n & 0x1fffffffffffffL;
        n >>= 53;
        n += ((int128_t)a[79 + i]) << 38;
    }
    r[77] = (sp_digit)n;
#else
    int i;
    int128_t n = a[77] >> 15;
    n += ((int128_t)a[78]) << 38;
    for (i = 0; i < 72; i += 8) {
        r[i + 0] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 79]) << 38;
        r[i + 1] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 80]) << 38;
        r[i + 2] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 81]) << 38;
        r[i + 3] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 82]) << 38;
        r[i + 4] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 83]) << 38;
        r[i + 5] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 84]) << 38;
        r[i + 6] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 85]) << 38;
        r[i + 7] = n & 0x1fffffffffffffL;
        n >>= 53; n += ((int128_t)a[i + 86]) << 38;
    }
    r[72] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[151]) << 38;
    r[73] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[152]) << 38;
    r[74] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[153]) << 38;
    r[75] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[154]) << 38;
    r[76] = n & 0x1fffffffffffffL; n >>= 53; n += ((int128_t)a[155]) << 38;
    r[77] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[78], 0, sizeof(*r) * 78U);
}

/* Reduce the number back to 4096 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_4096_mont_reduce_78(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_4096_norm_78(a + 78);

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<77; i++) {
            mu = (a[i] * mp) & 0x1fffffffffffffL;
            sp_4096_mul_add_78(a+i, m, mu);
            a[i+1] += a[i] >> 53;
        }
        mu = (a[i] * mp) & 0x7fffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
    else {
        for (i=0; i<77; i++) {
            mu = a[i] & 0x1fffffffffffffL;
            sp_4096_mul_add_78(a+i, m, mu);
            a[i+1] += a[i] >> 53;
        }
        mu = a[i] & 0x7fffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
        a[i] &= 0x1fffffffffffffL;
    }
#else
    for (i=0; i<77; i++) {
        mu = (a[i] * mp) & 0x1fffffffffffffL;
        sp_4096_mul_add_78(a+i, m, mu);
        a[i+1] += a[i] >> 53;
    }
    mu = (a[i] * mp) & 0x7fffL;
    sp_4096_mul_add_78(a+i, m, mu);
    a[i+1] += a[i] >> 53;
    a[i] &= 0x1fffffffffffffL;
#endif

    sp_4096_mont_shift_78(a, a);
    sp_4096_cond_sub_78(a, a, m, 0 - (((a[77] >> 15) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_4096_norm_78(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_4096_mont_mul_78(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_4096_mul_78(r, a, b);
    sp_4096_mont_reduce_78(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_4096_mont_sqr_78(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_4096_sqr_78(r, a);
    sp_4096_mont_reduce_78(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_4096_mul_d_156(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 156; i++) {
        t += tb * a[i];
        r[i] = t & 0x1fffffffffffffL;
        t >>= 53;
    }
    r[156] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x1fffffffffffffL;
    for (i = 0; i < 152; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 53) + (t[4] & 0x1fffffffffffffL);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 53) + (t[5] & 0x1fffffffffffffL);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 53) + (t[6] & 0x1fffffffffffffL);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 53) + (t[7] & 0x1fffffffffffffL);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 53) + (t[0] & 0x1fffffffffffffL);
    }
    t[1] = tb * a[153];
    r[153] = (sp_digit)(t[0] >> 53) + (t[1] & 0x1fffffffffffffL);
    t[2] = tb * a[154];
    r[154] = (sp_digit)(t[1] >> 53) + (t[2] & 0x1fffffffffffffL);
    t[3] = tb * a[155];
    r[155] = (sp_digit)(t[2] >> 53) + (t[3] & 0x1fffffffffffffL);
    r[156] =  (sp_digit)(t[3] >> 53);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_4096_cond_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    int i;

    for (i = 0; i < 72; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[72] = a[72] + (b[72] & m);
    r[73] = a[73] + (b[73] & m);
    r[74] = a[74] + (b[74] & m);
    r[75] = a[75] + (b[75] & m);
    r[76] = a[76] + (b[76] & m);
    r[77] = a[77] + (b[77] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_sub_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#endif
#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_4096_add_78(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 78; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#endif
SP_NOINLINE static void sp_4096_rshift_78(sp_digit* r, sp_digit* a, byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<77; i++) {
        r[i] = ((a[i] >> n) | (a[i + 1] << (53 - n))) & 0x1fffffffffffffL;
    }
#else
    for (i=0; i<72; i += 8) {
        r[i+0] = ((a[i+0] >> n) | (a[i+1] << (53 - n))) & 0x1fffffffffffffL;
        r[i+1] = ((a[i+1] >> n) | (a[i+2] << (53 - n))) & 0x1fffffffffffffL;
        r[i+2] = ((a[i+2] >> n) | (a[i+3] << (53 - n))) & 0x1fffffffffffffL;
        r[i+3] = ((a[i+3] >> n) | (a[i+4] << (53 - n))) & 0x1fffffffffffffL;
        r[i+4] = ((a[i+4] >> n) | (a[i+5] << (53 - n))) & 0x1fffffffffffffL;
        r[i+5] = ((a[i+5] >> n) | (a[i+6] << (53 - n))) & 0x1fffffffffffffL;
        r[i+6] = ((a[i+6] >> n) | (a[i+7] << (53 - n))) & 0x1fffffffffffffL;
        r[i+7] = ((a[i+7] >> n) | (a[i+8] << (53 - n))) & 0x1fffffffffffffL;
    }
    r[72] = ((a[72] >> n) | (a[73] << (53 - n))) & 0x1fffffffffffffL;
    r[73] = ((a[73] >> n) | (a[74] << (53 - n))) & 0x1fffffffffffffL;
    r[74] = ((a[74] >> n) | (a[75] << (53 - n))) & 0x1fffffffffffffL;
    r[75] = ((a[75] >> n) | (a[76] << (53 - n))) & 0x1fffffffffffffL;
    r[76] = ((a[76] >> n) | (a[77] << (53 - n))) & 0x1fffffffffffffL;
#endif
    r[77] = a[77] >> n;
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_4096_div_word_78(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 27 bits. */
    dv = (div >> 26) + 1;
    /* All 53 bits from d1 and top 10 bits from d0. */
    d = (d1 << 10) | (d0 >> 43);
    r = d / dv;
    d -= r * dv;
    /* Up to 36 bits in r */
    /* Next 17 bits from d0. */
    d <<= 17;
    r <<= 17;
    d |= (d0 >> 26) & ((1 << 17) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 53 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 53) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 26) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_div_78(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[156 + 1], t2d[78 + 1], sdd[78 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* sd;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 78 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    (void)m;

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 156 + 1;
        sd = t2 + 78 + 1;
#else
        t1 = t1d;
        t2 = t2d;
        sd = sdd;
#endif

        sp_4096_mul_d_78(sd, d, 1L << 38);
        sp_4096_mul_d_156(t1, a, 1L << 38);
        dv = sd[77];
        for (i=78; i>=0; i--) {
            t1[78 + i] += t1[78 + i - 1] >> 53;
            t1[78 + i - 1] &= 0x1fffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[78 + i];
            d1 <<= 53;
            d1 += t1[78 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_4096_div_word_78(t1[78 + i], t1[78 + i - 1], dv);
#endif

            sp_4096_mul_d_78(t2, sd, r1);
            (void)sp_4096_sub_78(&t1[i], &t1[i], t2);
            t1[78 + i] -= t2[78];
            t1[78 + i] += t1[78 + i - 1] >> 53;
            t1[78 + i - 1] &= 0x1fffffffffffffL;
            r1 = (((-t1[78 + i]) << 53) - t1[78 + i - 1]) / dv;
            r1 -= t1[78 + i];
            sp_4096_mul_d_78(t2, sd, r1);
            (void)sp_4096_add_78(&t1[i], &t1[i], t2);
            t1[78 + i] += t1[78 + i - 1] >> 53;
            t1[78 + i - 1] &= 0x1fffffffffffffL;
        }
        t1[78 - 1] += t1[78 - 2] >> 53;
        t1[78 - 2] &= 0x1fffffffffffffL;
        d1 = t1[78 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_4096_mul_d_78(t2, sd, r1);
        sp_4096_sub_78(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 78U);
        for (i=0; i<76; i++) {
            r[i+1] += r[i] >> 53;
            r[i] &= 0x1fffffffffffffL;
        }
        sp_4096_cond_add_78(r, r, sd, 0 - ((r[77] < 0) ?
                    (sp_digit)1 : (sp_digit)0));

        sp_4096_norm_78(r);
        sp_4096_rshift_78(r, r, 38);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_4096_mod_78(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_4096_div_78(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_4096_mod_exp_78(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 78 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3U * 78U * 2U);

        norm = t[0] = td;
        t[1] = &td[78 * 2];
        t[2] = &td[2 * 78 * 2];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
        }
        else {
            XMEMCPY(t[1], a, sizeof(sp_digit) * 78U);
        }
    }
    if (err == MP_OKAY) {
        sp_4096_mul_78(t[1], t[1], norm);
        err = sp_4096_mod_78(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (n >> 52) & 1;
            n <<= 1;

            sp_4096_mont_mul_78(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 78 * 2);
            sp_4096_mont_sqr_78(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 78 * 2);
        }

        sp_4096_mont_reduce_78(t[0], m, mp);
        n = sp_4096_cmp_78(t[0], m);
        sp_4096_cond_sub_78(t[0], t[0], m, ((n < 0) ?
                    (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 78 * 2);

    }

    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[3][156];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 78 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        t[0] = td;
        t[1] = &td[78 * 2];
        t[2] = &td[2 * 78 * 2];
#endif
        norm = t[0];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(t[1], t[1], norm);
                err = sp_4096_mod_78(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_78(t[1], a, norm);
            err = sp_4096_mod_78(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 53;
        c = bits % 53;
        n = e[i--] << (53 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1) {
                    break;
                }

                n = e[i--];
                c = 53;
            }

            y = (n >> 52) & 1;
            n <<= 1;

            sp_4096_mont_mul_78(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_4096_mont_sqr_78(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_4096_mont_reduce_78(t[0], m, mp);
        n = sp_4096_cmp_78(t[0], m);
        sp_4096_cond_sub_78(t[0], t[0], m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit t[32][156];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[156];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 156, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        for (i=0; i<32; i++)
            t[i] = td + i * 156;
#endif
        norm = t[0];

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        if (reduceA != 0) {
            err = sp_4096_mod_78(t[1], a, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(t[1], t[1], norm);
                err = sp_4096_mod_78(t[1], t[1], m);
            }
        }
        else {
            sp_4096_mul_78(t[1], a, norm);
            err = sp_4096_mod_78(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_4096_mont_sqr_78(t[ 2], t[ 1], m, mp);
        sp_4096_mont_mul_78(t[ 3], t[ 2], t[ 1], m, mp);
        sp_4096_mont_sqr_78(t[ 4], t[ 2], m, mp);
        sp_4096_mont_mul_78(t[ 5], t[ 3], t[ 2], m, mp);
        sp_4096_mont_sqr_78(t[ 6], t[ 3], m, mp);
        sp_4096_mont_mul_78(t[ 7], t[ 4], t[ 3], m, mp);
        sp_4096_mont_sqr_78(t[ 8], t[ 4], m, mp);
        sp_4096_mont_mul_78(t[ 9], t[ 5], t[ 4], m, mp);
        sp_4096_mont_sqr_78(t[10], t[ 5], m, mp);
        sp_4096_mont_mul_78(t[11], t[ 6], t[ 5], m, mp);
        sp_4096_mont_sqr_78(t[12], t[ 6], m, mp);
        sp_4096_mont_mul_78(t[13], t[ 7], t[ 6], m, mp);
        sp_4096_mont_sqr_78(t[14], t[ 7], m, mp);
        sp_4096_mont_mul_78(t[15], t[ 8], t[ 7], m, mp);
        sp_4096_mont_sqr_78(t[16], t[ 8], m, mp);
        sp_4096_mont_mul_78(t[17], t[ 9], t[ 8], m, mp);
        sp_4096_mont_sqr_78(t[18], t[ 9], m, mp);
        sp_4096_mont_mul_78(t[19], t[10], t[ 9], m, mp);
        sp_4096_mont_sqr_78(t[20], t[10], m, mp);
        sp_4096_mont_mul_78(t[21], t[11], t[10], m, mp);
        sp_4096_mont_sqr_78(t[22], t[11], m, mp);
        sp_4096_mont_mul_78(t[23], t[12], t[11], m, mp);
        sp_4096_mont_sqr_78(t[24], t[12], m, mp);
        sp_4096_mont_mul_78(t[25], t[13], t[12], m, mp);
        sp_4096_mont_sqr_78(t[26], t[13], m, mp);
        sp_4096_mont_mul_78(t[27], t[14], t[13], m, mp);
        sp_4096_mont_sqr_78(t[28], t[14], m, mp);
        sp_4096_mont_mul_78(t[29], t[15], t[14], m, mp);
        sp_4096_mont_sqr_78(t[30], t[15], m, mp);
        sp_4096_mont_mul_78(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 78) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (11 - c);
                c += 53;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);
            sp_4096_mont_sqr_78(rt, rt, m, mp);

            sp_4096_mont_mul_78(rt, rt, t[y], m, mp);
        }

        sp_4096_mont_reduce_78(rt, m, mp);
        n = sp_4096_cmp_78(rt, m);
        sp_4096_cond_sub_78(rt, rt, m, ((n < 0) ?
                   (sp_digit)1 : (sp_digit)0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D) && \
           !defined(RSA_LOW_MEM) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_4096_mask_39(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<39; i++) {
        r[i] = a[i] & m;
    }
#else
    int i;

    for (i = 0; i < 32; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
    r[32] = a[32] & m;
    r[33] = a[33] & m;
    r[34] = a[34] & m;
    r[35] = a[35] & m;
    r[36] = a[36] & m;
    r[37] = a[37] & m;
    r[38] = a[38] & m;
#endif
}

#endif
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 512 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_4096(const byte* in, word32 inLen, mp_int* em, mp_int* mm,
    byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* d = NULL;
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit* norm;
    sp_digit e[1] = {0};
    sp_digit mp;
    int i;
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 53) {
            err = MP_READ_E;
        }
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 78 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 78 * 2;
        m = r + 78 * 2;
        norm = r;

        sp_4096_from_bin(a, 78, in, inLen);
#if DIGIT_BIT >= 53
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }

    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 78, mm);

        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);
    }
    if (err == MP_OKAY) {
        sp_4096_mul_78(a, a, norm);
        err = sp_4096_mod_78(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=52; i>=0; i--) {
            if ((e[0] >> i) != 0) {
                break;
            }
        }

        XMEMCPY(r, a, sizeof(sp_digit) * 78 * 2);
        for (i--; i>=0; i--) {
            sp_4096_mont_sqr_78(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1) {
                sp_4096_mont_mul_78(r, r, a, m, mp);
            }
        }
        sp_4096_mont_reduce_78(r, m, mp);
        mp = sp_4096_cmp_78(r, m);
        sp_4096_cond_sub_78(r, r, m, ((mp < 0) ?
                    (sp_digit)1 : (sp_digit)0)- 1);

        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit ad[156], md[78], rd[156];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit e[1] = {0};
    int err = MP_OKAY;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(em) > 53) {
            err = MP_READ_E;
        }
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 78 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 78 * 2;
        m = r + 78 * 2;
    }
#else
    a = ad;
    m = md;
    r = rd;
#endif

    if (err == MP_OKAY) {
        sp_4096_from_bin(a, 78, in, inLen);
#if DIGIT_BIT >= 53
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1) {
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
        }
#endif
        if (e[0] == 0) {
            err = MP_EXPTMOD_E;
        }
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(m, 78, mm);

        if (e[0] == 0x3) {
            sp_4096_sqr_78(r, a);
            err = sp_4096_mod_78(r, r, m);
            if (err == MP_OKAY) {
                sp_4096_mul_78(r, a, r);
                err = sp_4096_mod_78(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_4096_mont_setup(m, &mp);
            sp_4096_mont_norm_78(norm, m);

            sp_4096_mul_78(a, a, norm);
            err = sp_4096_mod_78(a, a, m);

            if (err == MP_OKAY) {
                for (i=52; i>=0; i--) {
                    if ((e[0] >> i) != 0) {
                        break;
                    }
                }

                XMEMCPY(r, a, sizeof(sp_digit) * 156U);
                for (i--; i>=0; i--) {
                    sp_4096_mont_sqr_78(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1) {
                        sp_4096_mont_mul_78(r, r, a, m, mp);
                    }
                }
                sp_4096_mont_reduce_78(r, m, mp);
                mp = sp_4096_cmp_78(r, m);
                sp_4096_cond_sub_78(r, r, m, ((mp < 0) ?
                           (sp_digit)1 : (sp_digit)0) - 1);
            }
        }
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }
#endif

    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 512 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_4096(const byte* in, word32 inLen, mp_int* dm,
    mp_int* pm, mp_int* qm, mp_int* dpm, mp_int* dqm, mp_int* qim, mp_int* mm,
    byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* a;
    sp_digit* d = NULL;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 4096) {
           err = MP_READ_E;
        }
        if (inLen > 512) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 78 * 4, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = d + 78;
        m = a + 78;
        r = a;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(d, 78, dm);
        sp_4096_from_mp(m, 78, mm);
        err = sp_4096_mod_exp_78(r, a, d, 4096, m, 0);
    }
    if (err == MP_OKAY) {
        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 78);
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[156], d[78], m[78];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (mp_count_bits(dm) > 4096) {
            err = MP_READ_E;
        }
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(d, 78, dm);
        sp_4096_from_mp(m, 78, mm);
        err = sp_4096_mod_exp_78(r, a, d, 4096, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

    XMEMSET(d, 0, sizeof(sp_digit) * 78);

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#else
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* t = NULL;
    sp_digit* a;
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmp;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 39 * 11, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (t == NULL) {
            err = MEMORY_E;
        }
    }
    if (err == MP_OKAY) {
        a = t;
        p = a + 78 * 2;
        q = p + 39;
        qi = dq = dp = q + 39;
        tmpa = qi + 39;
        tmpb = tmpa + 78;

        tmp = t;
        r = tmp + 78;

        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(p, 39, pm);
        sp_4096_from_mp(q, 39, qm);
        sp_4096_from_mp(dp, 39, dpm);
        err = sp_4096_mod_exp_39(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        sp_4096_from_mp(dq, 39, dqm);
        err = sp_4096_mod_exp_39(tmpb, a, dq, 2048, q, 1);
    }
    if (err == MP_OKAY) {
        (void)sp_4096_sub_39(tmpa, tmpa, tmpb);
        sp_4096_mask_39(tmp, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        (void)sp_4096_add_39(tmpa, tmpa, tmp);

        sp_4096_from_mp(qi, 39, qim);
        sp_4096_mul_39(tmpa, tmpa, qi);
        err = sp_4096_mod_39(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_39(tmpa, q, tmpa);
        (void)sp_4096_add_78(r, tmpb, tmpa);
        sp_4096_norm_78(r);

        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_digit) * 39 * 11);
        XFREE(t, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[78 * 2];
    sp_digit p[39], q[39], dp[39], dq[39], qi[39];
    sp_digit tmp[78], tmpa[78], tmpb[78];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 512U) {
        err = MP_TO_E;
    }
    if (err == MP_OKAY) {
        if (inLen > 512U) {
            err = MP_READ_E;
        }
        if (mp_count_bits(mm) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        sp_4096_from_bin(a, 78, in, inLen);
        sp_4096_from_mp(p, 39, pm);
        sp_4096_from_mp(q, 39, qm);
        sp_4096_from_mp(dp, 39, dpm);
        sp_4096_from_mp(dq, 39, dqm);
        sp_4096_from_mp(qi, 39, qim);

        err = sp_4096_mod_exp_39(tmpa, a, dp, 2048, p, 1);
    }
    if (err == MP_OKAY) {
        err = sp_4096_mod_exp_39(tmpb, a, dq, 2048, q, 1);
    }

    if (err == MP_OKAY) {
        (void)sp_4096_sub_39(tmpa, tmpa, tmpb);
        sp_4096_mask_39(tmp, p, 0 - ((sp_int_digit)tmpa[38] >> 63));
        (void)sp_4096_add_39(tmpa, tmpa, tmp);
        sp_4096_mul_39(tmpa, tmpa, qi);
        err = sp_4096_mod_39(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_4096_mul_39(tmpa, tmpa, q);
        (void)sp_4096_add_78(r, tmpb, tmpa);
        sp_4096_norm_78(r);

        sp_4096_to_bin(r, out);
        *outLen = 512;
    }

    XMEMSET(tmpa, 0, sizeof(tmpa));
    XMEMSET(tmpb, 0, sizeof(tmpb));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));
    XMEMSET(dp, 0, sizeof(dp));
    XMEMSET(dq, 0, sizeof(dq));
    XMEMSET(qi, 0, sizeof(qi));

    return err;
#endif /* WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK) */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_4096_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (4096 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 53
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 78);
        r->used = 78;
        mp_clamp(r);
#elif DIGIT_BIT < 53
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 78; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 53) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = a[i] >> s;
                }
            }
            s = 53 - s;
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 78; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 53 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 53 - s;
            }
            else {
                s += 53;
            }
        }
        r->used = (4096 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_4096(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 78 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 78 * 2;
        m = e + 78;
        r = b;

        sp_4096_from_mp(b, 78, base);
        sp_4096_from_mp(e, 78, exp);
        sp_4096_from_mp(m, 78, mod);

        err = sp_4096_mod_exp_78(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 78U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[156], ed[78], md[78];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expBits > 4096) {
            err = MP_READ_E;
        }
    }
    
    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 4096) {
            err = MP_READ_E;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 78 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 78 * 2;
        m = e + 78;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_4096_from_mp(b, 78, base);
        sp_4096_from_mp(e, 78, exp);
        sp_4096_from_mp(m, 78, mod);

        err = sp_4096_mod_exp_78(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_4096_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 78U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#ifdef WOLFSSL_HAVE_SP_DH

#ifdef HAVE_FFDHE_4096
SP_NOINLINE static void sp_4096_lshift_78(sp_digit* r, sp_digit* a, byte n)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    r[78] = a[77] >> (53 - n);
    for (i=77; i>0; i--) {
        r[i] = ((a[i] << n) | (a[i-1] >> (53 - n))) & 0x1fffffffffffffL;
    }
#else
    sp_int_digit s, t;

    s = (sp_int_digit)a[77];
    r[78] = s >> (53U - n);
    s = (sp_int_digit)(a[77]); t = (sp_int_digit)(a[76]);
    r[77] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[76]); t = (sp_int_digit)(a[75]);
    r[76] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[75]); t = (sp_int_digit)(a[74]);
    r[75] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[74]); t = (sp_int_digit)(a[73]);
    r[74] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[73]); t = (sp_int_digit)(a[72]);
    r[73] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[72]); t = (sp_int_digit)(a[71]);
    r[72] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[71]); t = (sp_int_digit)(a[70]);
    r[71] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[70]); t = (sp_int_digit)(a[69]);
    r[70] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[69]); t = (sp_int_digit)(a[68]);
    r[69] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[68]); t = (sp_int_digit)(a[67]);
    r[68] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[67]); t = (sp_int_digit)(a[66]);
    r[67] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[66]); t = (sp_int_digit)(a[65]);
    r[66] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[65]); t = (sp_int_digit)(a[64]);
    r[65] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[64]); t = (sp_int_digit)(a[63]);
    r[64] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[63]); t = (sp_int_digit)(a[62]);
    r[63] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[62]); t = (sp_int_digit)(a[61]);
    r[62] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[61]); t = (sp_int_digit)(a[60]);
    r[61] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[60]); t = (sp_int_digit)(a[59]);
    r[60] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[59]); t = (sp_int_digit)(a[58]);
    r[59] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[58]); t = (sp_int_digit)(a[57]);
    r[58] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[57]); t = (sp_int_digit)(a[56]);
    r[57] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[56]); t = (sp_int_digit)(a[55]);
    r[56] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[55]); t = (sp_int_digit)(a[54]);
    r[55] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[54]); t = (sp_int_digit)(a[53]);
    r[54] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[53]); t = (sp_int_digit)(a[52]);
    r[53] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[52]); t = (sp_int_digit)(a[51]);
    r[52] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[51]); t = (sp_int_digit)(a[50]);
    r[51] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[50]); t = (sp_int_digit)(a[49]);
    r[50] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[49]); t = (sp_int_digit)(a[48]);
    r[49] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[48]); t = (sp_int_digit)(a[47]);
    r[48] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[47]); t = (sp_int_digit)(a[46]);
    r[47] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[46]); t = (sp_int_digit)(a[45]);
    r[46] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[45]); t = (sp_int_digit)(a[44]);
    r[45] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[44]); t = (sp_int_digit)(a[43]);
    r[44] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[43]); t = (sp_int_digit)(a[42]);
    r[43] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[42]); t = (sp_int_digit)(a[41]);
    r[42] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[41]); t = (sp_int_digit)(a[40]);
    r[41] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[40]); t = (sp_int_digit)(a[39]);
    r[40] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[39]); t = (sp_int_digit)(a[38]);
    r[39] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[38]); t = (sp_int_digit)(a[37]);
    r[38] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[37]); t = (sp_int_digit)(a[36]);
    r[37] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[36]); t = (sp_int_digit)(a[35]);
    r[36] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[35]); t = (sp_int_digit)(a[34]);
    r[35] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[34]); t = (sp_int_digit)(a[33]);
    r[34] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[33]); t = (sp_int_digit)(a[32]);
    r[33] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[32]); t = (sp_int_digit)(a[31]);
    r[32] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[31]); t = (sp_int_digit)(a[30]);
    r[31] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[30]); t = (sp_int_digit)(a[29]);
    r[30] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[29]); t = (sp_int_digit)(a[28]);
    r[29] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[28]); t = (sp_int_digit)(a[27]);
    r[28] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[27]); t = (sp_int_digit)(a[26]);
    r[27] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[26]); t = (sp_int_digit)(a[25]);
    r[26] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[25]); t = (sp_int_digit)(a[24]);
    r[25] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[24]); t = (sp_int_digit)(a[23]);
    r[24] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[23]); t = (sp_int_digit)(a[22]);
    r[23] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[22]); t = (sp_int_digit)(a[21]);
    r[22] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[21]); t = (sp_int_digit)(a[20]);
    r[21] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[20]); t = (sp_int_digit)(a[19]);
    r[20] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[19]); t = (sp_int_digit)(a[18]);
    r[19] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[18]); t = (sp_int_digit)(a[17]);
    r[18] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[17]); t = (sp_int_digit)(a[16]);
    r[17] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[16]); t = (sp_int_digit)(a[15]);
    r[16] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[15]); t = (sp_int_digit)(a[14]);
    r[15] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[14]); t = (sp_int_digit)(a[13]);
    r[14] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[13]); t = (sp_int_digit)(a[12]);
    r[13] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[12]); t = (sp_int_digit)(a[11]);
    r[12] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[11]); t = (sp_int_digit)(a[10]);
    r[11] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[10]); t = (sp_int_digit)(a[9]);
    r[10] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[9]); t = (sp_int_digit)(a[8]);
    r[9] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[8]); t = (sp_int_digit)(a[7]);
    r[8] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[7]); t = (sp_int_digit)(a[6]);
    r[7] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[6]); t = (sp_int_digit)(a[5]);
    r[6] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[5]); t = (sp_int_digit)(a[4]);
    r[5] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[4]); t = (sp_int_digit)(a[3]);
    r[4] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[3]); t = (sp_int_digit)(a[2]);
    r[3] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[2]); t = (sp_int_digit)(a[1]);
    r[2] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
    s = (sp_int_digit)(a[1]); t = (sp_int_digit)(a[0]);
    r[1] = ((s << n) | (t >> (53U - n))) & 0x1fffffffffffffUL;
#endif
    r[0] = (a[0] << n) & 0x1fffffffffffffL;
}

/* Modular exponentiate 2 to the e mod m. (r = 2^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_4096_mod_exp_2_78(sp_digit* r, const sp_digit* e, int bits, const sp_digit* m)
{
#ifndef WOLFSSL_SMALL_STACK
    sp_digit nd[156];
    sp_digit td[79];
#else
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit* tmp;
    sp_digit mp = 1;
    sp_digit n, o;
    int i;
    int c, y;
    int err = MP_OKAY;

#ifdef WOLFSSL_SMALL_STACK
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 235, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
        norm = td;
        tmp  = td + 156;
#else
        norm = nd;
        tmp  = td;
#endif

        XMEMSET(td, 0, sizeof(td));
        sp_4096_mont_setup(m, &mp);
        sp_4096_mont_norm_78(norm, m);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 52) / 53) - 1;
        c = bits % 53;
        if (c == 0) {
            c = 53;
        }
        if (i < 78) {
            n = e[i--] << (64 - c);
        }
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (11 - c);
            c += 53;
        }
        y = (n >> 59) & 0x1f;
        n <<= 5;
        c -= 5;
        sp_4096_lshift_78(r, norm, y);
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (11 - c);
                c += 53;
            }
            y = (n >> 59) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);
            sp_4096_mont_sqr_78(r, r, m, mp);

            sp_4096_lshift_78(r, r, y);
            sp_4096_mul_d_78(tmp, norm, (r[78] << 38) + (r[77] >> 15));
            r[78] = 0;
            r[77] &= 0x7fffL;
            (void)sp_4096_add_78(r, r, tmp);
            sp_4096_norm_78(r);
            o = sp_4096_cmp_78(r, m);
            sp_4096_cond_sub_78(r, r, m, ((o < 0) ?
                                          (sp_digit)1 : (sp_digit)0) - 1);
        }

        sp_4096_mont_reduce_78(r, m, mp);
        n = sp_4096_cmp_78(r, m);
        sp_4096_cond_sub_78(r, r, m, ((n < 0) ?
                                                (sp_digit)1 : (sp_digit)0) - 1);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

#endif /* HAVE_FFDHE_4096 */

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base     Base.
 * exp      Array of bytes that is the exponent.
 * expLen   Length of data, in bytes, in exponent.
 * mod      Modulus.
 * out      Buffer to hold big-endian bytes of exponentiation result.
 *          Must be at least 512 bytes long.
 * outLen   Length, in bytes, of exponentiation result.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_DhExp_4096(mp_int* base, const byte* exp, word32 expLen,
    mp_int* mod, byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 512) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 4096) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 78 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 78 * 2;
        m = e + 78;
        r = b;

        sp_4096_from_mp(b, 78, base);
        sp_4096_from_bin(e, 78, exp, expLen);
        sp_4096_from_mp(m, 78, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2 &&
                ((m[77] << 17) | (m[76] >> 36)) == 0xffffffffL) {
            err = sp_4096_mod_exp_2_78(r, e, expLen * 8, m);
        }
        else
    #endif
            err = sp_4096_mod_exp_78(r, b, e, expLen * 8, m, 0);
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin(r, out);
        *outLen = 512;
        for (i=0; i<512 && out[i] == 0; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 78U);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#ifndef WOLFSSL_SMALL_STACK
    sp_digit bd[156], ed[78], md[78];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    word32 i;
    int err = MP_OKAY;

    if (mp_count_bits(base) > 4096) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        if (expLen > 512U) {
            err = MP_READ_E;
        }
    }

    if (err == MP_OKAY) {
        if (mp_count_bits(mod) != 4096) {
            err = MP_READ_E;
        }
    }
#ifdef WOLFSSL_SMALL_STACK
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 78 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 78 * 2;
        m = e + 78;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_4096_from_mp(b, 78, base);
        sp_4096_from_bin(e, 78, exp, expLen);
        sp_4096_from_mp(m, 78, mod);

    #ifdef HAVE_FFDHE_4096
        if (base->used == 1 && base->dp[0] == 2U &&
                ((m[77] << 17) | (m[76] >> 36)) == 0xffffffffL) {
            err = sp_4096_mod_exp_2_78(r, e, expLen * 8U, m);
        }
        else {
    #endif
            err = sp_4096_mod_exp_78(r, b, e, expLen * 8U, m, 0);
    #ifdef HAVE_FFDHE_4096
        }
    #endif
    }

    if (err == MP_OKAY) {
        sp_4096_to_bin(r, out);
        *outLen = 512;
        for (i=0; i<512U && out[i] == 0U; i++) {
        }
        *outLen -= i;
        XMEMMOVE(out, out + i, *outLen);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 78U);

#ifdef WOLFSSL_SMALL_STACK
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}
#endif /* WOLFSSL_HAVE_SP_DH */

#endif /* WOLFSSL_HAVE_SP_DH || (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* WOLFSSL_SP_4096 */

#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */
#ifdef WOLFSSL_HAVE_SP_ECC
#ifndef WOLFSSL_SP_NO_256

/* Point structure to use. */
typedef struct sp_point {
    sp_digit x[2 * 5];
    sp_digit y[2 * 5];
    sp_digit z[2 * 5];
    int infinity;
} sp_point;

/* The modulus (prime) of the curve P256. */
static const sp_digit p256_mod[5] = {
    0xfffffffffffffL,0x00fffffffffffL,0x0000000000000L,0x0001000000000L,
    0x0ffffffff0000L
};
/* The Montogmery normalizer for modulus of the curve P256. */
static const sp_digit p256_norm_mod[5] = {
    0x0000000000001L,0xff00000000000L,0xfffffffffffffL,0xfffefffffffffL,
    0x000000000ffffL
};
/* The Montogmery multiplier for modulus of the curve P256. */
static const sp_digit p256_mp_mod = 0x0000000000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P256. */
static const sp_digit p256_order[5] = {
    0x9cac2fc632551L,0xada7179e84f3bL,0xfffffffbce6faL,0x0000fffffffffL,
    0x0ffffffff0000L
};
#endif
/* The order of the curve P256 minus 2. */
static const sp_digit p256_order2[5] = {
    0x9cac2fc63254fL,0xada7179e84f3bL,0xfffffffbce6faL,0x0000fffffffffL,
    0x0ffffffff0000L
};
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery normalizer for order of the curve P256. */
static const sp_digit p256_norm_order[5] = {
    0x6353d039cdaafL,0x5258e8617b0c4L,0x0000000431905L,0xffff000000000L,
    0x000000000ffffL
};
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery multiplier for order of the curve P256. */
static const sp_digit p256_mp_order = 0x1c8aaee00bc4fL;
#endif
/* The base point of curve P256. */
static const sp_point p256_base = {
    /* X ordinate */
    {
        0x13945d898c296L,0x812deb33a0f4aL,0x3a440f277037dL,0x4247f8bce6e56L,
        0x06b17d1f2e12cL, 0L, 0L, 0L, 0L, 0L
    },
    /* Y ordinate */
    {
        0x6406837bf51f5L,0x576b315ececbbL,0xc0f9e162bce33L,0x7f9b8ee7eb4a7L,
        0x04fe342e2fe1aL, 0L, 0L, 0L, 0L, 0L
    },
    /* Z ordinate */
    {
        0x0000000000001L,0x0000000000000L,0x0000000000000L,0x0000000000000L,
        0x0000000000000L, 0L, 0L, 0L, 0L, 0L
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p256_b[5] = {
    0xe3c3e27d2604bL,0xb0cc53b0f63bcL,0x69886bc651d06L,0x93e7b3ebbd557L,
    0x05ac635d8aa3aL
};
#endif

static int sp_ecc_point_new_ex(void* heap, sp_point* sp, sp_point** p)
{
    int ret = MP_OKAY;
    (void)heap;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    (void)sp;
    *p = (sp_point*)XMALLOC(sizeof(sp_point), heap, DYNAMIC_TYPE_ECC);
#else
    *p = sp;
#endif
    if (p == NULL) {
        ret = MEMORY_E;
    }
    return ret;
}

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
/* Allocate memory for point and return error. */
#define sp_ecc_point_new(heap, sp, p) sp_ecc_point_new_ex((heap), NULL, &(p))
#else
/* Set pointer to data and return no error. */
#define sp_ecc_point_new(heap, sp, p) sp_ecc_point_new_ex((heap), &(sp), &(p))
#endif


static void sp_ecc_point_free(sp_point* p, int clear, void* heap)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
/* If valid pointer then clear point data if requested and free data. */
    if (p != NULL) {
        if (clear != 0) {
            XMEMSET(p, 0, sizeof(*p));
        }
        XFREE(p, heap, DYNAMIC_TYPE_ECC);
    }
#else
/* Clear point data if requested. */
    if (clear != 0) {
        XMEMSET(p, 0, sizeof(*p));
    }
#endif
    (void)heap;
}

/* Multiply a number by Montogmery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mod_mul_norm_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    int64_t* td;
#else
    int64_t td[8];
    int64_t a32d[8];
#endif
    int64_t* t;
    int64_t* a32;
    int64_t o;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (int64_t*)XMALLOC(sizeof(int64_t) * 2 * 8, NULL, DYNAMIC_TYPE_ECC);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t = td;
        a32 = td + 8;
#else
        t = td;
        a32 = a32d;
#endif

        a32[0] = (sp_digit)(a[0]) & 0xffffffffL;
        a32[1] = (sp_digit)(a[0] >> 32U);
        a32[1] |= a[1] << 20U;
        a32[1] &= 0xffffffffL;
        a32[2] = (sp_digit)(a[1] >> 12U) & 0xffffffffL;
        a32[3] = (sp_digit)(a[1] >> 44U);
        a32[3] |= a[2] << 8U;
        a32[3] &= 0xffffffffL;
        a32[4] = (sp_digit)(a[2] >> 24U);
        a32[4] |= a[3] << 28U;
        a32[4] &= 0xffffffffL;
        a32[5] = (sp_digit)(a[3] >> 4U) & 0xffffffffL;
        a32[6] = (sp_digit)(a[3] >> 36U);
        a32[6] |= a[4] << 16U;
        a32[6] &= 0xffffffffL;
        a32[7] = (sp_digit)(a[4] >> 16U) & 0xffffffffL;

        /*  1  1  0 -1 -1 -1 -1  0 */
        t[0] = 0 + a32[0] + a32[1] - a32[3] - a32[4] - a32[5] - a32[6];
        /*  0  1  1  0 -1 -1 -1 -1 */
        t[1] = 0 + a32[1] + a32[2] - a32[4] - a32[5] - a32[6] - a32[7];
        /*  0  0  1  1  0 -1 -1 -1 */
        t[2] = 0 + a32[2] + a32[3] - a32[5] - a32[6] - a32[7];
        /* -1 -1  0  2  2  1  0 -1 */
        t[3] = 0 - a32[0] - a32[1] + 2 * a32[3] + 2 * a32[4] + a32[5] - a32[7];
        /*  0 -1 -1  0  2  2  1  0 */
        t[4] = 0 - a32[1] - a32[2] + 2 * a32[4] + 2 * a32[5] + a32[6];
        /*  0  0 -1 -1  0  2  2  1 */
        t[5] = 0 - a32[2] - a32[3] + 2 * a32[5] + 2 * a32[6] + a32[7];
        /* -1 -1  0  0  0  1  3  2 */
        t[6] = 0 - a32[0] - a32[1] + a32[5] + 3 * a32[6] + 2 * a32[7];
        /*  1  0 -1 -1 -1 -1  0  3 */
        t[7] = 0 + a32[0] - a32[2] - a32[3] - a32[4] - a32[5] + 3 * a32[7];

        t[1] += t[0] >> 32U; t[0] &= 0xffffffffL;
        t[2] += t[1] >> 32U; t[1] &= 0xffffffffL;
        t[3] += t[2] >> 32U; t[2] &= 0xffffffffL;
        t[4] += t[3] >> 32U; t[3] &= 0xffffffffL;
        t[5] += t[4] >> 32U; t[4] &= 0xffffffffL;
        t[6] += t[5] >> 32U; t[5] &= 0xffffffffL;
        t[7] += t[6] >> 32U; t[6] &= 0xffffffffL;
        o     = t[7] >> 32U; t[7] &= 0xffffffffL;
        t[0] += o;
        t[3] -= o;
        t[6] -= o;
        t[7] += o;
        t[1] += t[0] >> 32U; t[0] &= 0xffffffffL;
        t[2] += t[1] >> 32U; t[1] &= 0xffffffffL;
        t[3] += t[2] >> 32U; t[2] &= 0xffffffffL;
        t[4] += t[3] >> 32U; t[3] &= 0xffffffffL;
        t[5] += t[4] >> 32U; t[4] &= 0xffffffffL;
        t[6] += t[5] >> 32U; t[5] &= 0xffffffffL;
        t[7] += t[6] >> 32U; t[6] &= 0xffffffffL;

        r[0] = t[0];
        r[0] |= t[1] << 32U;
        r[0] &= 0xfffffffffffffLL;
        r[1] = (sp_digit)(t[1] >> 20);
        r[1] |= t[2] << 12U;
        r[1] |= t[3] << 44U;
        r[1] &= 0xfffffffffffffLL;
        r[2] = (sp_digit)(t[3] >> 8);
        r[2] |= t[4] << 24U;
        r[2] &= 0xfffffffffffffLL;
        r[3] = (sp_digit)(t[4] >> 28);
        r[3] |= t[5] << 4U;
        r[3] |= t[6] << 36U;
        r[3] &= 0xfffffffffffffLL;
        r[4] = (sp_digit)(t[6] >> 16);
        r[4] |= t[7] << 16U;
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_256_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 52
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 52
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xfffffffffffffL;
        s = 52U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 52U) <= (word32)DIGIT_BIT) {
            s += 52U;
            r[j] &= 0xfffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = 0L;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 52) {
            r[j] &= 0xfffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 52 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Convert a point of type ecc_point to type sp_point.
 *
 * p   Point of type sp_point (result).
 * pm  Point of type ecc_point.
 */
static void sp_256_point_from_ecc_point_5(sp_point* p, const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_256_from_mp(p->x, 5, pm->x);
    sp_256_from_mp(p->y, 5, pm->y);
    sp_256_from_mp(p->z, 5, pm->z);
    p->infinity = 0;
}

/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_256_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (256 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 52
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 5);
        r->used = 5;
        mp_clamp(r);
#elif DIGIT_BIT < 52
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 5; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 52) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = a[i] >> s;
                }
            }
            s = 52 - s;
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 5; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 52 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 52 - s;
            }
            else {
                s += 52;
            }
        }
        r->used = (256 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Convert a point of type sp_point to type ecc_point.
 *
 * p   Point of type sp_point.
 * pm  Point of type ecc_point (result).
 * returns MEMORY_E when allocation of memory in ecc_point fails otherwise
 * MP_OKAY.
 */
static int sp_256_point_to_ecc_point_5(const sp_point* p, ecc_point* pm)
{
    int err;

    err = sp_256_to_mp(p->x, pm->x);
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, pm->y);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, pm->z);
    }

    return err;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_256_cmp_5(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=4; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    r |= (a[ 4] - b[ 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 3] - b[ 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 2] - b[ 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 1] - b[ 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 0] - b[ 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Normalize the values in each word to 52.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_256_norm_5(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 4; i++) {
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }
#else
    a[1] += a[0] >> 52; a[0] &= 0xfffffffffffffL;
    a[2] += a[1] >> 52; a[1] &= 0xfffffffffffffL;
    a[3] += a[2] >> 52; a[2] &= 0xfffffffffffffL;
    a[4] += a[3] >> 52; a[3] &= 0xfffffffffffffL;
#endif
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_256_cond_sub_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    r[ 0] = a[ 0] - (b[ 0] & m);
    r[ 1] = a[ 1] - (b[ 1] & m);
    r[ 2] = a[ 2] - (b[ 2] & m);
    r[ 3] = a[ 3] - (b[ 3] & m);
    r[ 4] = a[ 4] - (b[ 4] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#define sp_256_mont_reduce_order_5         sp_256_mont_reduce_5

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_add_5(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 5; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0xfffffffffffffL;
        t >>= 52;
    }
    r[5] += t;
#else
    int128_t tb = b;
    int128_t t[5];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    r[ 0] +=                 (sp_digit)(t[ 0] & 0xfffffffffffffL);
    r[ 1] += (sp_digit)((t[ 0] >> 52) + (t[ 1] & 0xfffffffffffffL));
    r[ 2] += (sp_digit)((t[ 1] >> 52) + (t[ 2] & 0xfffffffffffffL));
    r[ 3] += (sp_digit)((t[ 2] >> 52) + (t[ 3] & 0xfffffffffffffL));
    r[ 4] += (sp_digit)((t[ 3] >> 52) + (t[ 4] & 0xfffffffffffffL));
    r[ 5] +=  t[ 4] >> 52;
#endif /* WOLFSSL_SP_SMALL */
}

/* Shift the result in the high 256 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_256_mont_shift_5(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    word64 n;

    n = a[4] >> 48;
    for (i = 0; i < 4; i++) {
        n += (word64)a[5 + i] << 4;
        r[i] = n & 0xfffffffffffffL;
        n >>= 52;
    }
    n += (word64)a[9] << 4;
    r[4] = n;
#else
    word64 n;

    n  = a[4] >> 48;
    n += (word64)a[ 5] << 4U; r[ 0] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (word64)a[ 6] << 4U; r[ 1] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (word64)a[ 7] << 4U; r[ 2] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (word64)a[ 8] << 4U; r[ 3] = n & 0xfffffffffffffUL; n >>= 52U;
    n += (word64)a[ 9] << 4U; r[ 4] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[5], 0, sizeof(*r) * 5U);
}

/* Reduce the number back to 256 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_256_mont_reduce_5(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    if (mp != 1) {
        for (i=0; i<4; i++) {
            mu = (a[i] * mp) & 0xfffffffffffffL;
            sp_256_mul_add_5(a+i, m, mu);
            a[i+1] += a[i] >> 52;
        }
        mu = (a[i] * mp) & 0xffffffffffffL;
        sp_256_mul_add_5(a+i, m, mu);
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }
    else {
        for (i=0; i<4; i++) {
            mu = a[i] & 0xfffffffffffffL;
            sp_256_mul_add_5(a+i, p256_mod, mu);
            a[i+1] += a[i] >> 52;
        }
        mu = a[i] & 0xffffffffffffL;
        sp_256_mul_add_5(a+i, p256_mod, mu);
        a[i+1] += a[i] >> 52;
        a[i] &= 0xfffffffffffffL;
    }

    sp_256_mont_shift_5(a, a);
    sp_256_cond_sub_5(a, a, m, 0 - (((a[4] >> 48) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(a);
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_5(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[4]) * b[4];
    r[9] = (sp_digit)(c >> 52);
    c = (c & 0xfffffffffffffL) << 52;
    for (k = 7; k >= 0; k--) {
        for (i = 4; i >= 0; i--) {
            j = k - i;
            if (j >= 5) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 104;
        r[k + 1] = (c >> 52) & 0xfffffffffffffL;
        c = (c & 0xfffffffffffffL) << 52;
    }
    r[0] = (sp_digit)(c >> 52);
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_256_mul_5(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int128_t t0   = ((int128_t)a[ 0]) * b[ 0];
    int128_t t1   = ((int128_t)a[ 0]) * b[ 1]
                 + ((int128_t)a[ 1]) * b[ 0];
    int128_t t2   = ((int128_t)a[ 0]) * b[ 2]
                 + ((int128_t)a[ 1]) * b[ 1]
                 + ((int128_t)a[ 2]) * b[ 0];
    int128_t t3   = ((int128_t)a[ 0]) * b[ 3]
                 + ((int128_t)a[ 1]) * b[ 2]
                 + ((int128_t)a[ 2]) * b[ 1]
                 + ((int128_t)a[ 3]) * b[ 0];
    int128_t t4   = ((int128_t)a[ 0]) * b[ 4]
                 + ((int128_t)a[ 1]) * b[ 3]
                 + ((int128_t)a[ 2]) * b[ 2]
                 + ((int128_t)a[ 3]) * b[ 1]
                 + ((int128_t)a[ 4]) * b[ 0];
    int128_t t5   = ((int128_t)a[ 1]) * b[ 4]
                 + ((int128_t)a[ 2]) * b[ 3]
                 + ((int128_t)a[ 3]) * b[ 2]
                 + ((int128_t)a[ 4]) * b[ 1];
    int128_t t6   = ((int128_t)a[ 2]) * b[ 4]
                 + ((int128_t)a[ 3]) * b[ 3]
                 + ((int128_t)a[ 4]) * b[ 2];
    int128_t t7   = ((int128_t)a[ 3]) * b[ 4]
                 + ((int128_t)a[ 4]) * b[ 3];
    int128_t t8   = ((int128_t)a[ 4]) * b[ 4];

    t1   += t0  >> 52; r[ 0] = t0  & 0xfffffffffffffL;
    t2   += t1  >> 52; r[ 1] = t1  & 0xfffffffffffffL;
    t3   += t2  >> 52; r[ 2] = t2  & 0xfffffffffffffL;
    t4   += t3  >> 52; r[ 3] = t3  & 0xfffffffffffffL;
    t5   += t4  >> 52; r[ 4] = t4  & 0xfffffffffffffL;
    t6   += t5  >> 52; r[ 5] = t5  & 0xfffffffffffffL;
    t7   += t6  >> 52; r[ 6] = t6  & 0xfffffffffffffL;
    t8   += t7  >> 52; r[ 7] = t7  & 0xfffffffffffffL;
    r[9] = (sp_digit)(t8 >> 52);
                       r[8] = t8 & 0xfffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_256_mont_mul_5(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_256_mul_5(r, a, b);
    sp_256_mont_reduce_5(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_5(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[4]) * a[4];
    r[9] = (sp_digit)(c >> 52);
    c = (c & 0xfffffffffffffL) << 52;
    for (k = 7; k >= 0; k--) {
        for (i = 4; i >= 0; i--) {
            j = k - i;
            if (j >= 5 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += c >> 104;
        r[k + 1] = (c >> 52) & 0xfffffffffffffL;
        c = (c & 0xfffffffffffffL) << 52;
    }
    r[0] = (sp_digit)(c >> 52);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_sqr_5(sp_digit* r, const sp_digit* a)
{
    int128_t t0   =  ((int128_t)a[ 0]) * a[ 0];
    int128_t t1   = (((int128_t)a[ 0]) * a[ 1]) * 2;
    int128_t t2   = (((int128_t)a[ 0]) * a[ 2]) * 2
                 +  ((int128_t)a[ 1]) * a[ 1];
    int128_t t3   = (((int128_t)a[ 0]) * a[ 3]
                 +  ((int128_t)a[ 1]) * a[ 2]) * 2;
    int128_t t4   = (((int128_t)a[ 0]) * a[ 4]
                 +  ((int128_t)a[ 1]) * a[ 3]) * 2
                 +  ((int128_t)a[ 2]) * a[ 2];
    int128_t t5   = (((int128_t)a[ 1]) * a[ 4]
                 +  ((int128_t)a[ 2]) * a[ 3]) * 2;
    int128_t t6   = (((int128_t)a[ 2]) * a[ 4]) * 2
                 +  ((int128_t)a[ 3]) * a[ 3];
    int128_t t7   = (((int128_t)a[ 3]) * a[ 4]) * 2;
    int128_t t8   =  ((int128_t)a[ 4]) * a[ 4];

    t1   += t0  >> 52; r[ 0] = t0  & 0xfffffffffffffL;
    t2   += t1  >> 52; r[ 1] = t1  & 0xfffffffffffffL;
    t3   += t2  >> 52; r[ 2] = t2  & 0xfffffffffffffL;
    t4   += t3  >> 52; r[ 3] = t3  & 0xfffffffffffffL;
    t5   += t4  >> 52; r[ 4] = t4  & 0xfffffffffffffL;
    t6   += t5  >> 52; r[ 5] = t5  & 0xfffffffffffffL;
    t7   += t6  >> 52; r[ 6] = t6  & 0xfffffffffffffL;
    t8   += t7  >> 52; r[ 7] = t7  & 0xfffffffffffffL;
    r[9] = (sp_digit)(t8 >> 52);
                       r[8] = t8 & 0xfffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_256_mont_sqr_5(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_256_sqr_5(r, a);
    sp_256_mont_reduce_5(r, m, mp);
}

#if !defined(WOLFSSL_SP_SMALL) || defined(HAVE_COMP_KEY)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_256_mont_sqr_n_5(sp_digit* r, const sp_digit* a, int n,
        const sp_digit* m, sp_digit mp)
{
    sp_256_mont_sqr_5(r, a, m, mp);
    for (; n > 1; n--) {
        sp_256_mont_sqr_5(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL || HAVE_COMP_KEY */
#ifdef WOLFSSL_SP_SMALL
/* Mod-2 for the P256 curve. */
static const uint64_t p256_mod_2[4] = {
    0xfffffffffffffffdU,0x00000000ffffffffU,0x0000000000000000U,
    0xffffffff00000001U
};
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P256 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_5(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 5);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_5(t, t, p256_mod, p256_mp_mod);
        if (p256_mod_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_256_mont_mul_5(t, t, a, p256_mod, p256_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 5);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 5;
    sp_digit* t3 = td + 4 * 5;

    /* t = a^2 */
    sp_256_mont_sqr_5(t, a, p256_mod, p256_mp_mod);
    /* t = a^3 = t * a */
    sp_256_mont_mul_5(t, t, a, p256_mod, p256_mp_mod);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_5(t2, t, 2, p256_mod, p256_mp_mod);
    /* t3= a^d = t2 * a */
    sp_256_mont_mul_5(t3, t2, a, p256_mod, p256_mp_mod);
    /* t = a^f = t2 * t */
    sp_256_mont_mul_5(t, t2, t, p256_mod, p256_mp_mod);
    /* t2= a^f0 = t ^ 2 ^ 4 */
    sp_256_mont_sqr_n_5(t2, t, 4, p256_mod, p256_mp_mod);
    /* t3= a^fd = t2 * t3 */
    sp_256_mont_mul_5(t3, t2, t3, p256_mod, p256_mp_mod);
    /* t = a^ff = t2 * t */
    sp_256_mont_mul_5(t, t2, t, p256_mod, p256_mp_mod);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_5(t2, t, 8, p256_mod, p256_mp_mod);
    /* t3= a^fffd = t2 * t3 */
    sp_256_mont_mul_5(t3, t2, t3, p256_mod, p256_mp_mod);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_5(t, t2, t, p256_mod, p256_mp_mod);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_5(t2, t, 16, p256_mod, p256_mp_mod);
    /* t3= a^fffffffd = t2 * t3 */
    sp_256_mont_mul_5(t3, t2, t3, p256_mod, p256_mp_mod);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_5(t, t2, t, p256_mod, p256_mp_mod);
    /* t = a^ffffffff00000000 = t ^ 2 ^ 32  */
    sp_256_mont_sqr_n_5(t2, t, 32, p256_mod, p256_mp_mod);
    /* t2= a^ffffffffffffffff = t2 * t */
    sp_256_mont_mul_5(t, t2, t, p256_mod, p256_mp_mod);
    /* t2= a^ffffffff00000001 = t2 * a */
    sp_256_mont_mul_5(t2, t2, a, p256_mod, p256_mp_mod);
    /* t2= a^ffffffff000000010000000000000000000000000000000000000000
     *   = t2 ^ 2 ^ 160 */
    sp_256_mont_sqr_n_5(t2, t2, 160, p256_mod, p256_mp_mod);
    /* t2= a^ffffffff00000001000000000000000000000000ffffffffffffffff
     *   = t2 * t */
    sp_256_mont_mul_5(t2, t2, t, p256_mod, p256_mp_mod);
    /* t2= a^ffffffff00000001000000000000000000000000ffffffffffffffff00000000
     *   = t2 ^ 2 ^ 32 */
    sp_256_mont_sqr_n_5(t2, t2, 32, p256_mod, p256_mp_mod);
    /* r = a^ffffffff00000001000000000000000000000000fffffffffffffffffffffffd
     *   = t2 * t3 */
    sp_256_mont_mul_5(r, t2, t3, p256_mod, p256_mp_mod);
#endif /* WOLFSSL_SP_SMALL */
}

/* Map the Montgomery form projective co-ordinate point to an affine point.
 *
 * r  Resulting affine co-ordinate point.
 * p  Montgomery form projective co-ordinate point.
 * t  Temporary ordinate data.
 */
static void sp_256_map_5(sp_point* r, const sp_point* p, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    int64_t n;

    sp_256_mont_inv_5(t1, p->z, t + 2*5);

    sp_256_mont_sqr_5(t2, t1, p256_mod, p256_mp_mod);
    sp_256_mont_mul_5(t1, t2, t1, p256_mod, p256_mp_mod);

    /* x /= z^2 */
    sp_256_mont_mul_5(r->x, p->x, t2, p256_mod, p256_mp_mod);
    XMEMSET(r->x + 5, 0, sizeof(r->x) / 2U);
    sp_256_mont_reduce_5(r->x, p256_mod, p256_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_256_cmp_5(r->x, p256_mod);
    sp_256_cond_sub_5(r->x, r->x, p256_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r->x);

    /* y /= z^3 */
    sp_256_mont_mul_5(r->y, p->y, t1, p256_mod, p256_mp_mod);
    XMEMSET(r->y + 5, 0, sizeof(r->y) / 2U);
    sp_256_mont_reduce_5(r->y, p256_mod, p256_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_256_cmp_5(r->y, p256_mod);
    sp_256_cond_sub_5(r->y, r->y, p256_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r->y);

    XMEMSET(r->z, 0, sizeof(r->z));
    r->z[0] = 1;

}

#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_add_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_add_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montogmery form.
 * b   Second number to add in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_add_5(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_256_add_5(r, a, b);
    sp_256_norm_5(r);
    sp_256_cond_sub_5(r, r, m, 0 - (((r[4] >> 48) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_dbl_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    (void)sp_256_add_5(r, a, a);
    sp_256_norm_5(r);
    sp_256_cond_sub_5(r, r, m, 0 - (((r[4] >> 48) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_tpl_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    (void)sp_256_add_5(r, a, a);
    sp_256_norm_5(r);
    sp_256_cond_sub_5(r, r, m, 0 - (((r[4] >> 48) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r);
    (void)sp_256_add_5(r, r, a);
    sp_256_norm_5(r);
    sp_256_cond_sub_5(r, r, m, 0 - (((r[4] >> 48) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_256_norm_5(r);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_sub_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_256_sub_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] - b[ 0];
    r[ 1] = a[ 1] - b[ 1];
    r[ 2] = a[ 2] - b[ 2];
    r[ 3] = a[ 3] - b[ 3];
    r[ 4] = a[ 4] - b[ 4];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_256_cond_add_5(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 5; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    r[ 0] = a[ 0] + (b[ 0] & m);
    r[ 1] = a[ 1] + (b[ 1] & m);
    r[ 2] = a[ 2] + (b[ 2] & m);
    r[ 3] = a[ 3] + (b[ 3] & m);
    r[ 4] = a[ 4] + (b[ 4] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montogmery form.
 * b   Number to subtract with in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_256_mont_sub_5(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_256_sub_5(r, a, b);
    sp_256_cond_add_5(r, r, m, r[4] >> 48);
    sp_256_norm_5(r);
}

/* Shift number left one bit.
 * Bottom bit is lost.
 *
 * r  Result of shift.
 * a  Number to shift.
 */
SP_NOINLINE static void sp_256_rshift1_5(sp_digit* r, sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<4; i++) {
        r[i] = ((a[i] >> 1) | (a[i + 1] << 51)) & 0xfffffffffffffL;
    }
#else
    r[0] = ((a[0] >> 1) | (a[1] << 51)) & 0xfffffffffffffL;
    r[1] = ((a[1] >> 1) | (a[2] << 51)) & 0xfffffffffffffL;
    r[2] = ((a[2] >> 1) | (a[3] << 51)) & 0xfffffffffffffL;
    r[3] = ((a[3] >> 1) | (a[4] << 51)) & 0xfffffffffffffL;
#endif
    r[4] = a[4] >> 1;
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_256_div2_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_256_cond_add_5(r, a, m, 0 - (a[0] & 1));
    sp_256_norm_5(r);
    sp_256_rshift1_5(r, r);
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_5(sp_point* r, const sp_point* p, sp_digit* t)
{
    sp_point* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* When infinity don't double point passed in - constant time. */
    rp[0] = r;

    /*lint allow cast to different type of pointer*/
    rp[1] = (sp_point*)t; /*lint !e9087 !e740*/
    XMEMSET(rp[1], 0, sizeof(sp_point));
    x = rp[p->infinity]->x;
    y = rp[p->infinity]->y;
    z = rp[p->infinity]->z;
    /* Put point to double into result - good for infinty. */
    if (r != p) {
        for (i=0; i<5; i++) {
            r->x[i] = p->x[i];
        }
        for (i=0; i<5; i++) {
            r->y[i] = p->y[i];
        }
        for (i=0; i<5; i++) {
            r->z[i] = p->z[i];
        }
        r->infinity = p->infinity;
    }

    /* T1 = Z * Z */
    sp_256_mont_sqr_5(t1, z, p256_mod, p256_mp_mod);
    /* Z = Y * Z */
    sp_256_mont_mul_5(z, y, z, p256_mod, p256_mp_mod);
    /* Z = 2Z */
    sp_256_mont_dbl_5(z, z, p256_mod);
    /* T2 = X - T1 */
    sp_256_mont_sub_5(t2, x, t1, p256_mod);
    /* T1 = X + T1 */
    sp_256_mont_add_5(t1, x, t1, p256_mod);
    /* T2 = T1 * T2 */
    sp_256_mont_mul_5(t2, t1, t2, p256_mod, p256_mp_mod);
    /* T1 = 3T2 */
    sp_256_mont_tpl_5(t1, t2, p256_mod);
    /* Y = 2Y */
    sp_256_mont_dbl_5(y, y, p256_mod);
    /* Y = Y * Y */
    sp_256_mont_sqr_5(y, y, p256_mod, p256_mp_mod);
    /* T2 = Y * Y */
    sp_256_mont_sqr_5(t2, y, p256_mod, p256_mp_mod);
    /* T2 = T2/2 */
    sp_256_div2_5(t2, t2, p256_mod);
    /* Y = Y * X */
    sp_256_mont_mul_5(y, y, x, p256_mod, p256_mp_mod);
    /* X = T1 * T1 */
    sp_256_mont_mul_5(x, t1, t1, p256_mod, p256_mp_mod);
    /* X = X - Y */
    sp_256_mont_sub_5(x, x, y, p256_mod);
    /* X = X - Y */
    sp_256_mont_sub_5(x, x, y, p256_mod);
    /* Y = Y - X */
    sp_256_mont_sub_5(y, y, x, p256_mod);
    /* Y = Y * T1 */
    sp_256_mont_mul_5(y, y, t1, p256_mod, p256_mp_mod);
    /* Y = Y - T2 */
    sp_256_mont_sub_5(y, y, t2, p256_mod);

}

/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_256_cmp_equal_5(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) |
            (a[4] ^ b[4])) == 0;
}

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  Frist point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_5(sp_point* r, const sp_point* p, const sp_point* q,
        sp_digit* t)
{
    const sp_point* ap[2];
    sp_point* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_digit* t3 = t + 4*5;
    sp_digit* t4 = t + 6*5;
    sp_digit* t5 = t + 8*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point* a = p;
        p = q;
        q = a;
    }

    /* Check double */
    (void)sp_256_sub_5(t1, p256_mod, q->y);
    sp_256_norm_5(t1);
    if ((sp_256_cmp_equal_5(p->x, q->x) & sp_256_cmp_equal_5(p->z, q->z) &
        (sp_256_cmp_equal_5(p->y, q->y) | sp_256_cmp_equal_5(p->y, t1))) != 0) {
        sp_256_proj_point_dbl_5(r, p, t);
    }
    else {
        rp[0] = r;

        /*lint allow cast to different type of pointer*/
        rp[1] = (sp_point*)t; /*lint !e9087 !e740*/
        XMEMSET(rp[1], 0, sizeof(sp_point));
        x = rp[p->infinity | q->infinity]->x;
        y = rp[p->infinity | q->infinity]->y;
        z = rp[p->infinity | q->infinity]->z;

        ap[0] = p;
        ap[1] = q;
        for (i=0; i<5; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<5; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<5; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U1 = X1*Z2^2 */
        sp_256_mont_sqr_5(t1, q->z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t3, t1, q->z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t1, t1, x, p256_mod, p256_mp_mod);
        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_5(t2, z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t4, t2, z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t2, t2, q->x, p256_mod, p256_mp_mod);
        /* S1 = Y1*Z2^3 */
        sp_256_mont_mul_5(t3, t3, y, p256_mod, p256_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_5(t4, t4, q->y, p256_mod, p256_mp_mod);
        /* H = U2 - U1 */
        sp_256_mont_sub_5(t2, t2, t1, p256_mod);
        /* R = S2 - S1 */
        sp_256_mont_sub_5(t4, t4, t3, p256_mod);
        /* Z3 = H*Z1*Z2 */
        sp_256_mont_mul_5(z, z, q->z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(z, z, t2, p256_mod, p256_mp_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_256_mont_sqr_5(x, t4, p256_mod, p256_mp_mod);
        sp_256_mont_sqr_5(t5, t2, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(y, t1, t5, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t5, t5, t2, p256_mod, p256_mp_mod);
        sp_256_mont_sub_5(x, x, t5, p256_mod);
        sp_256_mont_dbl_5(t1, y, p256_mod);
        sp_256_mont_sub_5(x, x, t1, p256_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_256_mont_sub_5(y, y, x, p256_mod);
        sp_256_mont_mul_5(y, y, t4, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t5, t5, t3, p256_mod, p256_mp_mod);
        sp_256_mont_sub_5(y, y, t5, p256_mod);
    }
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_5(sp_point* r, const sp_point* g, const sp_digit* k,
        int map, void* heap)
{
    sp_point* td;
    sp_point* t[3];
    sp_digit* tmp;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    (void)heap;

    td = (sp_point*)XMALLOC(sizeof(sp_point) * 3, heap, DYNAMIC_TYPE_ECC);
    if (td == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
    if (tmp == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3);

        t[0] = &td[0];
        t[1] = &td[1];
        t[2] = &td[2];

        /* t[0] = {0, 0, 1} * norm */
        t[0]->infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_5(t[1]->x, g->x, p256_mod);
    }
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_5(t[1]->y, g->y, p256_mod);
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_5(t[1]->z, g->z, p256_mod);

    if (err == MP_OKAY) {
        i = 4;
        c = 48;
        n = k[i--] << (52 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 52;
            }

            y = (n >> 51) & 1;
            n <<= 1;

            sp_256_proj_point_add_5(t[y^1], t[0], t[1], tmp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(sp_point));
            sp_256_proj_point_dbl_5(t[2], t[2], tmp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(sp_point));
        }

        if (map != 0) {
            sp_256_map_5(r, t[0], tmp);
        }
        else {
            XMEMCPY(r, t[0], sizeof(sp_point));
        }
    }

    if (tmp != NULL) {
        XMEMSET(tmp, 0, sizeof(sp_digit) * 2 * 5 * 5);
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
    if (td != NULL) {
        XMEMSET(td, 0, sizeof(sp_point) * 3);
        XFREE(td, NULL, DYNAMIC_TYPE_ECC);
    }

    return err;
}

#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_5(sp_point* r, const sp_point* g, const sp_digit* k,
        int map, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point td[3];
    sp_digit tmpd[2 * 5 * 5];
#endif
    sp_point* t;
    sp_digit* tmp;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    (void)heap;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_point td[3];
    t = (sp_point*)XMALLOC(sizeof(*td) * 3, heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, heap,
                             DYNAMIC_TYPE_ECC);
    if (tmp == NULL)
        err = MEMORY_E;
#else
    t = td;
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        t[0] = &td[0];
        t[1] = &td[1];
        t[2] = &td[2];

        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_256_mod_mul_norm_5(t[1].x, g->x, p256_mod);
    }
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_5(t[1].y, g->y, p256_mod);
    if (err == MP_OKAY)
        err = sp_256_mod_mul_norm_5(t[1].z, g->z, p256_mod);

    if (err == MP_OKAY) {
        i = 4;
        c = 48;
        n = k[i--] << (52 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 52;
            }

            y = (n >> 51) & 1;
            n <<= 1;

            sp_256_proj_point_add_5(&t[y^1], &t[0], &t[1], tmp);

            XMEMCPY(&t[2], (void*)(((size_t)&t[0] & addr_mask[y^1]) +
                                 ((size_t)&t[1] & addr_mask[y])), sizeof(t[2]));
            sp_256_proj_point_dbl_5(&t[2], &t[2], tmp);
            XMEMCPY((void*)(((size_t)&t[0] & addr_mask[y^1]) +
                          ((size_t)&t[1] & addr_mask[y])), &t[2], sizeof(t[2]));
        }

        if (map != 0) {
            sp_256_map_5(r, &t[0], tmp);
        }
        else {
            XMEMCPY(r, &t[0], sizeof(sp_point));
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (tmp != NULL) {
        XMEMSET(tmp, 0, sizeof(sp_digit) * 2 * 5 * 5);
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    }
    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_point) * 3);
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    }
#else
    ForceZero(tmpd, sizeof(tmpd));
    ForceZero(td, sizeof(td));
#endif

    return err;
}

#else
/* A table entry for pre-computed points. */
typedef struct sp_table_entry {
    sp_digit x[5];
    sp_digit y[5];
} sp_table_entry;

/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_fast_5(sp_point* r, const sp_point* g, const sp_digit* k,
        int map, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point td[16];
    sp_point rtd;
    sp_digit tmpd[2 * 5 * 5];
#endif
    sp_point* t;
    sp_point* rt;
    sp_digit* tmp;
    sp_digit n;
    int i;
    int c, y;
    int err;

    (void)heap;

    err = sp_ecc_point_new(heap, rtd, rt);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    t = (sp_point*)XMALLOC(sizeof(sp_point) * 16, heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, heap,
                             DYNAMIC_TYPE_ECC);
    if (tmp == NULL)
        err = MEMORY_E;
#else
    t = td;
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        (void)sp_256_mod_mul_norm_5(t[1].x, g->x, p256_mod);
        (void)sp_256_mod_mul_norm_5(t[1].y, g->y, p256_mod);
        (void)sp_256_mod_mul_norm_5(t[1].z, g->z, p256_mod);
        t[1].infinity = 0;
        sp_256_proj_point_dbl_5(&t[ 2], &t[ 1], tmp);
        t[ 2].infinity = 0;
        sp_256_proj_point_add_5(&t[ 3], &t[ 2], &t[ 1], tmp);
        t[ 3].infinity = 0;
        sp_256_proj_point_dbl_5(&t[ 4], &t[ 2], tmp);
        t[ 4].infinity = 0;
        sp_256_proj_point_add_5(&t[ 5], &t[ 3], &t[ 2], tmp);
        t[ 5].infinity = 0;
        sp_256_proj_point_dbl_5(&t[ 6], &t[ 3], tmp);
        t[ 6].infinity = 0;
        sp_256_proj_point_add_5(&t[ 7], &t[ 4], &t[ 3], tmp);
        t[ 7].infinity = 0;
        sp_256_proj_point_dbl_5(&t[ 8], &t[ 4], tmp);
        t[ 8].infinity = 0;
        sp_256_proj_point_add_5(&t[ 9], &t[ 5], &t[ 4], tmp);
        t[ 9].infinity = 0;
        sp_256_proj_point_dbl_5(&t[10], &t[ 5], tmp);
        t[10].infinity = 0;
        sp_256_proj_point_add_5(&t[11], &t[ 6], &t[ 5], tmp);
        t[11].infinity = 0;
        sp_256_proj_point_dbl_5(&t[12], &t[ 6], tmp);
        t[12].infinity = 0;
        sp_256_proj_point_add_5(&t[13], &t[ 7], &t[ 6], tmp);
        t[13].infinity = 0;
        sp_256_proj_point_dbl_5(&t[14], &t[ 7], tmp);
        t[14].infinity = 0;
        sp_256_proj_point_add_5(&t[15], &t[ 8], &t[ 7], tmp);
        t[15].infinity = 0;

        i = 3;
        n = k[i+1] << 12;
        c = 44;
        y = n >> 56;
        XMEMCPY(rt, &t[y], sizeof(sp_point));
        n <<= 8;
        for (; i>=0 || c>=4; ) {
            if (c < 4) {
                n |= k[i--] << (12 - c);
                c += 52;
            }
            y = (n >> 60) & 0xf;
            n <<= 4;
            c -= 4;

            sp_256_proj_point_dbl_5(rt, rt, tmp);
            sp_256_proj_point_dbl_5(rt, rt, tmp);
            sp_256_proj_point_dbl_5(rt, rt, tmp);
            sp_256_proj_point_dbl_5(rt, rt, tmp);

            sp_256_proj_point_add_5(rt, rt, &t[y], tmp);
        }

        if (map != 0) {
            sp_256_map_5(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point));
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (tmp != NULL) {
        XMEMSET(tmp, 0, sizeof(sp_digit) * 2 * 5 * 5);
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
    }
    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_point) * 16);
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    }
#else
    ForceZero(tmpd, sizeof(tmpd));
    ForceZero(td, sizeof(td));
#endif
    sp_ecc_point_free(rt, 1, heap);

    return err;
}

#ifdef FP_ECC
/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_dbl_n_5(sp_point* r, const sp_point* p, int n,
        sp_digit* t)
{
    sp_point* rp[2];
    sp_digit* w = t;
    sp_digit* a = t + 2*5;
    sp_digit* b = t + 4*5;
    sp_digit* t1 = t + 6*5;
    sp_digit* t2 = t + 8*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    rp[0] = r;

    /*lint allow cast to different type of pointer*/
    rp[1] = (sp_point*)t; /*lint !e9087 !e740*/
    XMEMSET(rp[1], 0, sizeof(sp_point));
    x = rp[p->infinity]->x;
    y = rp[p->infinity]->y;
    z = rp[p->infinity]->z;
    if (r != p) {
        for (i=0; i<5; i++) {
            r->x[i] = p->x[i];
        }
        for (i=0; i<5; i++) {
            r->y[i] = p->y[i];
        }
        for (i=0; i<5; i++) {
            r->z[i] = p->z[i];
        }
        r->infinity = p->infinity;
    }

    /* Y = 2*Y */
    sp_256_mont_dbl_5(y, y, p256_mod);
    /* W = Z^4 */
    sp_256_mont_sqr_5(w, z, p256_mod, p256_mp_mod);
    sp_256_mont_sqr_5(w, w, p256_mod, p256_mp_mod);
    while (n-- > 0) {
        /* A = 3*(X^2 - W) */
        sp_256_mont_sqr_5(t1, x, p256_mod, p256_mp_mod);
        sp_256_mont_sub_5(t1, t1, w, p256_mod);
        sp_256_mont_tpl_5(a, t1, p256_mod);
        /* B = X*Y^2 */
        sp_256_mont_sqr_5(t2, y, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(b, t2, x, p256_mod, p256_mp_mod);
        /* X = A^2 - 2B */
        sp_256_mont_sqr_5(x, a, p256_mod, p256_mp_mod);
        sp_256_mont_dbl_5(t1, b, p256_mod);
        sp_256_mont_sub_5(x, x, t1, p256_mod);
        /* Z = Z*Y */
        sp_256_mont_mul_5(z, z, y, p256_mod, p256_mp_mod);
        /* t2 = Y^4 */
        sp_256_mont_sqr_5(t2, t2, p256_mod, p256_mp_mod);
        if (n != 0) {
            /* W = W*Y^4 */
            sp_256_mont_mul_5(w, w, t2, p256_mod, p256_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_256_mont_sub_5(y, b, x, p256_mod);
        sp_256_mont_mul_5(y, y, a, p256_mod, p256_mp_mod);
        sp_256_mont_dbl_5(y, y, p256_mod);
        sp_256_mont_sub_5(y, y, t2, p256_mod);
    }
    /* Y = Y/2 */
    sp_256_div2_5(y, y, p256_mod);
}

#endif /* FP_ECC */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  Frist point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_256_proj_point_add_qz1_5(sp_point* r, const sp_point* p,
        const sp_point* q, sp_digit* t)
{
    const sp_point* ap[2];
    sp_point* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*5;
    sp_digit* t3 = t + 4*5;
    sp_digit* t4 = t + 6*5;
    sp_digit* t5 = t + 8*5;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* Check double */
    (void)sp_256_sub_5(t1, p256_mod, q->y);
    sp_256_norm_5(t1);
    if ((sp_256_cmp_equal_5(p->x, q->x) & sp_256_cmp_equal_5(p->z, q->z) &
        (sp_256_cmp_equal_5(p->y, q->y) | sp_256_cmp_equal_5(p->y, t1))) != 0) {
        sp_256_proj_point_dbl_5(r, p, t);
    }
    else {
        rp[0] = r;

        /*lint allow cast to different type of pointer*/
        rp[1] = (sp_point*)t; /*lint !e9087 !e740*/
        XMEMSET(rp[1], 0, sizeof(sp_point));
        x = rp[p->infinity | q->infinity]->x;
        y = rp[p->infinity | q->infinity]->y;
        z = rp[p->infinity | q->infinity]->z;

        ap[0] = p;
        ap[1] = q;
        for (i=0; i<5; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<5; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<5; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U2 = X2*Z1^2 */
        sp_256_mont_sqr_5(t2, z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t4, t2, z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t2, t2, q->x, p256_mod, p256_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_256_mont_mul_5(t4, t4, q->y, p256_mod, p256_mp_mod);
        /* H = U2 - X1 */
        sp_256_mont_sub_5(t2, t2, x, p256_mod);
        /* R = S2 - Y1 */
        sp_256_mont_sub_5(t4, t4, y, p256_mod);
        /* Z3 = H*Z1 */
        sp_256_mont_mul_5(z, z, t2, p256_mod, p256_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_256_mont_sqr_5(t1, t4, p256_mod, p256_mp_mod);
        sp_256_mont_sqr_5(t5, t2, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t3, x, t5, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t5, t5, t2, p256_mod, p256_mp_mod);
        sp_256_mont_sub_5(x, t1, t5, p256_mod);
        sp_256_mont_dbl_5(t1, t3, p256_mod);
        sp_256_mont_sub_5(x, x, t1, p256_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_256_mont_sub_5(t3, t3, x, p256_mod);
        sp_256_mont_mul_5(t3, t3, t4, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(t5, t5, y, p256_mod, p256_mp_mod);
        sp_256_mont_sub_5(y, t3, t5, p256_mod);
    }
}

#ifdef FP_ECC
/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * a  Point to convert.
 * t  Temprorary data.
 */
static void sp_256_proj_to_affine_5(sp_point* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 5;
    sp_digit* tmp = t + 4 * 5;

    sp_256_mont_inv_5(t1, a->z, tmp);

    sp_256_mont_sqr_5(t2, t1, p256_mod, p256_mp_mod);
    sp_256_mont_mul_5(t1, t2, t1, p256_mod, p256_mp_mod);

    sp_256_mont_mul_5(a->x, a->x, t2, p256_mod, p256_mp_mod);
    sp_256_mont_mul_5(a->y, a->y, t1, p256_mod, p256_mp_mod);
    XMEMCPY(a->z, p256_norm_mod, sizeof(p256_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temprorary data.
 * heap  Heap to use for allocation.
 */
static int sp_256_gen_stripe_table_5(const sp_point* a,
        sp_table_entry* table, sp_digit* tmp, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point td, s1d, s2d;
#endif
    sp_point* t;
    sp_point* s1 = NULL;
    sp_point* s2 = NULL;
    int i, j;
    int err;

    (void)heap;

    err = sp_ecc_point_new(heap, td, t);
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, s1d, s1);
    }
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, s2d, s2);
    }

    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_5(t->x, a->x, p256_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_5(t->y, a->y, p256_mod);
    }
    if (err == MP_OKAY) {
        err = sp_256_mod_mul_norm_5(t->z, a->z, p256_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_256_proj_to_affine_5(t, tmp);

        XMEMCPY(s1->z, p256_norm_mod, sizeof(p256_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p256_norm_mod, sizeof(p256_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<8; i++) {
            sp_256_proj_point_dbl_n_5(t, t, 32, tmp);
            sp_256_proj_to_affine_5(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_256_proj_point_add_qz1_5(t, s1, s2, tmp);
                sp_256_proj_to_affine_5(t, tmp);
                XMEMCPY(table[j].x, t->x, sizeof(table->x));
                XMEMCPY(table[j].y, t->y, sizeof(table->y));
            }
        }
    }

    sp_ecc_point_free(s2, 0, heap);
    sp_ecc_point_free(s1, 0, heap);
    sp_ecc_point_free( t, 0, heap);

    return err;
}

#endif /* FP_ECC */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_stripe_5(sp_point* r, const sp_point* g,
        const sp_table_entry* table, const sp_digit* k, int map, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point rtd;
    sp_point pd;
    sp_digit td[2 * 5 * 5];
#endif
    sp_point* rt;
    sp_point* p = NULL;
    sp_digit* t;
    int i, j;
    int y, x;
    int err;

    (void)g;
    (void)heap;

    err = sp_ecc_point_new(heap, rtd, rt);
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, pd, p);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, heap,
                           DYNAMIC_TYPE_ECC);
    if (t == NULL) {
        err = MEMORY_E;
    }
#else
    t = td;
#endif

    if (err == MP_OKAY) {
        XMEMCPY(p->z, p256_norm_mod, sizeof(p256_norm_mod));
        XMEMCPY(rt->z, p256_norm_mod, sizeof(p256_norm_mod));

        y = 0;
        for (j=0,x=31; j<8; j++,x+=32) {
            y |= ((k[x / 52] >> (x % 52)) & 1) << j;
        }
        XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
        XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        rt->infinity = !y;
        for (i=30; i>=0; i--) {
            y = 0;
            for (j=0,x=i; j<8; j++,x+=32) {
                y |= ((k[x / 52] >> (x % 52)) & 1) << j;
            }

            sp_256_proj_point_dbl_5(rt, rt, t);
            XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            p->infinity = !y;
            sp_256_proj_point_add_qz1_5(rt, rt, p, t);
        }

        if (map != 0) {
            sp_256_map_5(r, rt, t);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point));
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (t != NULL) {
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(p, 0, heap);
    sp_ecc_point_free(rt, 0, heap);

    return err;
}

#ifdef FP_ECC
#ifndef FP_ENTRIES
    #define FP_ENTRIES 16
#endif

typedef struct sp_cache_t {
    sp_digit x[5];
    sp_digit y[5];
    sp_table_entry table[256];
    uint32_t cnt;
    int set;
} sp_cache_t;

static THREAD_LS_T sp_cache_t sp_cache[FP_ENTRIES];
static THREAD_LS_T int sp_cache_last = -1;
static THREAD_LS_T int sp_cache_inited = 0;

#ifndef HAVE_THREAD_LS
    static volatile int initCacheMutex = 0;
    static wolfSSL_Mutex sp_cache_lock;
#endif

static void sp_ecc_get_cache(const sp_point* g, sp_cache_t** cache)
{
    int i, j;
    uint32_t least;

    if (sp_cache_inited == 0) {
        for (i=0; i<FP_ENTRIES; i++) {
            sp_cache[i].set = 0;
        }
        sp_cache_inited = 1;
    }

    /* Compare point with those in cache. */
    for (i=0; i<FP_ENTRIES; i++) {
        if (!sp_cache[i].set)
            continue;

        if (sp_256_cmp_equal_5(g->x, sp_cache[i].x) &
                           sp_256_cmp_equal_5(g->y, sp_cache[i].y)) {
            sp_cache[i].cnt++;
            break;
        }
    }

    /* No match. */
    if (i == FP_ENTRIES) {
        /* Find empty entry. */
        i = (sp_cache_last + 1) % FP_ENTRIES;
        for (; i != sp_cache_last; i=(i+1)%FP_ENTRIES) {
            if (!sp_cache[i].set) {
                break;
            }
        }

        /* Evict least used. */
        if (i == sp_cache_last) {
            least = sp_cache[0].cnt;
            for (j=1; j<FP_ENTRIES; j++) {
                if (sp_cache[j].cnt < least) {
                    i = j;
                    least = sp_cache[i].cnt;
                }
            }
        }

        XMEMCPY(sp_cache[i].x, g->x, sizeof(sp_cache[i].x));
        XMEMCPY(sp_cache[i].y, g->y, sizeof(sp_cache[i].y));
        sp_cache[i].set = 1;
        sp_cache[i].cnt = 1;
    }

    *cache = &sp_cache[i];
    sp_cache_last = i;
}
#endif /* FP_ECC */

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_5(sp_point* r, const sp_point* g, const sp_digit* k,
        int map, void* heap)
{
#ifndef FP_ECC
    return sp_256_ecc_mulmod_fast_5(r, g, k, map, heap);
#else
    sp_digit tmp[2 * 5 * 5];
    sp_cache_t* cache;
    int err = MP_OKAY;

#ifndef HAVE_THREAD_LS
    if (initCacheMutex == 0) {
         wc_InitMutex(&sp_cache_lock);
         initCacheMutex = 1;
    }
    if (wc_LockMutex(&sp_cache_lock) != 0)
       err = BAD_MUTEX_E;
#endif /* HAVE_THREAD_LS */

    if (err == MP_OKAY) {
        sp_ecc_get_cache(g, &cache);
        if (cache->cnt == 2)
            sp_256_gen_stripe_table_5(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_256_ecc_mulmod_fast_5(r, g, k, map, heap);
        }
        else {
            err = sp_256_ecc_mulmod_stripe_5(r, g, cache->table, k,
                    map, heap);
        }
    }

    return err;
#endif
}

#endif
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * km    Scalar to multiply by.
 * p     Point to multiply.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_256(mp_int* km, ecc_point* gm, ecc_point* r, int map,
        void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point p;
    sp_digit kd[5];
#endif
    sp_point* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_ecc_point_new(heap, p, point);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, km);
        sp_256_point_from_ecc_point_5(point, gm);

            err = sp_256_ecc_mulmod_5(point, point, k, map, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, r);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(point, 0, heap);

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_5(sp_point* r, const sp_digit* k,
        int map, void* heap)
{
    /* No pre-computed values. */
    return sp_256_ecc_mulmod_5(r, &p256_base, k, map, heap);
}

#else
static const sp_table_entry p256_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x730d418a9143cL,0xfc5fedb60179eL,0x762251075ba95L,0x55c679fb732b7L,
        0x018905f76a537L },
      { 0x25357ce95560aL,0xe4ba19e45cddfL,0xd21f3258b4ab8L,0x5d85d2e88688dL,
        0x08571ff182588L } },
    /* 2 */
    { { 0x886024147519aL,0xac26b372f0202L,0x785ebc8d0981eL,0x58e9a9d4a7caaL,
        0x0d953c50ddbdfL },
      { 0x361ccfd590f8fL,0x6b44e6c9179d6L,0x2eb64cf72e962L,0x88f37fd961102L,
        0x0863ebb7e9eb2L } },
    /* 3 */
    { { 0x6b6235cdb6485L,0xa22f0a2f97785L,0xf7e300b808f0eL,0x80a03e68d9544L,
        0x000076055b5ffL },
      { 0x4eb9b838d2010L,0xbb3243708a763L,0x42a660654014fL,0x3ee0e0e47d398L,
        0x0830877613437L } },
    /* 4 */
    { { 0x22fc516a0d2bbL,0x6c1a6234994f9L,0x7c62c8b0d5cc1L,0x667f9241cf3a5L,
        0x02f5e6961fd1bL },
      { 0x5c70bf5a01797L,0x4d609561925c1L,0x71fdb523d20b4L,0x0f7b04911b370L,
        0x0f648f9168d6fL } },
    /* 5 */
    { { 0x66847e137bbbcL,0x9e8a6a0bec9e5L,0x9d73463e43446L,0x0015b1c427617L,
        0x05abe0285133dL },
      { 0xa837cc04c7dabL,0x4c43260c0792aL,0x8e6cc37573d9fL,0x73830c9315627L,
        0x094bb725b6b6fL } },
    /* 6 */
    { { 0x9b48f720f141cL,0xcd2df5bc74bbfL,0x11045c46199b3L,0xc4efdc3f61294L,
        0x0cdd6bbcb2f7dL },
      { 0x6700beaf436fdL,0x6db99326beccaL,0x14f25226f647fL,0xe5f60c0fa7920L,
        0x0a361bebd4bdaL } },
    /* 7 */
    { { 0xa2558597c13c7L,0x5f50b7c3e128aL,0x3c09d1dc38d63L,0x292c07039aecfL,
        0x0ba12ca09c4b5L },
      { 0x08fa459f91dfdL,0x66ceea07fb9e4L,0xd780b293af43bL,0xef4b1eceb0899L,
        0x053ebb99d701fL } },
    /* 8 */
    { { 0x7ee31b0e63d34L,0x72a9e54fab4feL,0x5e7b5a4f46005L,0x4831c0493334dL,
        0x08589fb9206d5L },
      { 0x0f5cc6583553aL,0x4ae25649e5aa7L,0x0044652087909L,0x1c4fcc9045071L,
        0x0ebb0696d0254L } },
    /* 9 */
    { { 0x6ca15ac1647c5L,0x47c4cf5799461L,0x64dfbacb8127dL,0x7da3dc666aa37L,
        0x0eb2820cbd1b2L },
      { 0x6f8d86a87e008L,0x9d922378f3940L,0x0ccecb2d87dfaL,0xda1d56ed2e428L,
        0x01f28289b55a7L } },
    /* 10 */
    { { 0xaa0c03b89da99L,0x9eb8284022abbL,0x81c05e8a6f2d7L,0x4d6327847862bL,
        0x0337a4b5905e5L },
      { 0x7500d21f7794aL,0xb77d6d7f613c6L,0x4cfd6e8207005L,0xfbd60a5a37810L,
        0x00d65e0d5f4c2L } },
    /* 11 */
    { { 0x09bbeb5275d38L,0x450be0a358d9dL,0x73eb2654268a7L,0xa232f0762ff49L,
        0x0c23da24252f4L },
      { 0x1b84f0b94520cL,0x63b05bd78e5daL,0x4d29ea1096667L,0xcff13a4dcb869L,
        0x019de3b8cc790L } },
    /* 12 */
    { { 0xa716c26c5fe04L,0x0b3bba1bdb183L,0x4cb712c3b28deL,0xcbfd7432c586aL,
        0x0e34dcbd491fcL },
      { 0x8d46baaa58403L,0x8682e97a53b40L,0x6aaa8af9a6974L,0x0f7f9e3901273L,
        0x0e7641f447b4eL } },
    /* 13 */
    { { 0x53941df64ba59L,0xec0b0242fc7d7L,0x1581859d33f10L,0x57bf4f06dfc6aL,
        0x04a12df57052aL },
      { 0x6338f9439dbd0L,0xd4bde53e1fbfaL,0x1f1b314d3c24bL,0xea46fd5e4ffa2L,
        0x06af5aa93bb5bL } },
    /* 14 */
    { { 0x0b69910c91999L,0x402a580491da1L,0x8cc20900a24b4L,0x40133e0094b4bL,
        0x05fe3475a66a4L },
      { 0x8cabdf93e7b4bL,0x1a7c23f91ab0fL,0xd1e6263292b50L,0xa91642e889aecL,
        0x0b544e308ecfeL } },
    /* 15 */
    { { 0x8c6e916ddfdceL,0x66f89179e6647L,0xd4e67e12c3291L,0xc20b4e8d6e764L,
        0x0e0b6b2bda6b0L },
      { 0x12df2bb7efb57L,0xde790c40070d3L,0x79bc9441aac0dL,0x3774f90336ad6L,
        0x071c023de25a6L } },
    /* 16 */
    { { 0x8c244bfe20925L,0xc38fdce86762aL,0xd38706391c19aL,0x24f65a96a5d5dL,
        0x061d587d421d3L },
      { 0x673a2a37173eaL,0x0853778b65e87L,0x5bab43e238480L,0xefbe10f8441e0L,
        0x0fa11fe124621L } },
    /* 17 */
    { { 0x91f2b2cb19ffdL,0x5bb1923c231c8L,0xac5ca8e01ba8dL,0xbedcb6d03d678L,
        0x0586eb04c1f13L },
      { 0x5c6e527e8ed09L,0x3c1819ede20c3L,0x6c652fa1e81a3L,0x4f11278fd6c05L,
        0x019d5ac087086L } },
    /* 18 */
    { { 0x9f581309a4e1fL,0x1be92700741e9L,0xfd28d20ab7de7L,0x563f26a5ef0beL,
        0x0e7c0073f7f9cL },
      { 0xd663a0ef59f76L,0x5420fcb0501f6L,0xa6602d4669b3bL,0x3c0ac08c1f7a7L,
        0x0e08504fec65bL } },
    /* 19 */
    { { 0x8f68da031b3caL,0x9ee6da6d66f09L,0x4f246e86d1cabL,0x96b45bfd81fa9L,
        0x078f018825b09L },
      { 0xefde43a25787fL,0x0d1dccac9bb7eL,0x35bfc368016f8L,0x747a0cea4877bL,
        0x043a773b87e94L } },
    /* 20 */
    { { 0x77734d2b533d5L,0xf6a1bdddc0625L,0x79ec293673b8aL,0x66b1577e7c9aaL,
        0x0bb6de651c3b2L },
      { 0x9303ab65259b3L,0xd3d03a7480e7eL,0xb3cfc27d6a0afL,0xb99bc5ac83d19L,
        0x060b4619a5d18L } },
    /* 21 */
    { { 0xa38e11ae5aa1cL,0x2b49e73658bd6L,0xe5f87edb8b765L,0xffcd0b130014eL,
        0x09d0f27b2aeebL },
      { 0x246317a730a55L,0x2fddbbc83aca9L,0xc019a719c955bL,0xc48d07c1dfe0aL,
        0x0244a566d356eL } },
    /* 22 */
    { { 0x0394aeacf1f96L,0xa9024c271c6dbL,0x2cbd3b99f2122L,0xef692626ac1b8L,
        0x045e58c873581L },
      { 0xf479da38f9dbcL,0x46e888a040d3fL,0x6e0bed7a8aaf1L,0xb7a4945adfb24L,
        0x0c040e21cc1e4L } },
    /* 23 */
    { { 0xaf0006f8117b6L,0xff73a35433847L,0xd9475eb651969L,0x6ec7482b35761L,
        0x01cdf5c97682cL },
      { 0x775b411f04839L,0xf448de16987dbL,0x70b32197dbeacL,0xff3db2921dd1bL,
        0x0046755f8a92dL } },
    /* 24 */
    { { 0xac5d2bce8ffcdL,0x8b2fe61a82cc8L,0x202d6c70d53c4L,0xa5f3f6f161727L,
        0x0046e5e113b83L },
      { 0x8ff64d8007f01L,0x125af43183e7bL,0x5e1a03c7fb1efL,0x005b045c5ea63L,
        0x06e0106c3303dL } },
    /* 25 */
    { { 0x7358488dd73b1L,0x8f995ed0d948cL,0x56a2ab7767070L,0xcf1f38385ea8cL,
        0x0442594ede901L },
      { 0xaa2c912d4b65bL,0x3b96c90c37f8fL,0xe978d1f94c234L,0xe68ed326e4a15L,
        0x0a796fa514c2eL } },
    /* 26 */
    { { 0xfb604823addd7L,0x83e56693b3359L,0xcbf3c809e2a61L,0x66e9f885b78e3L,
        0x0e4ad2da9c697L },
      { 0xf7f428e048a61L,0x8cc092d9a0357L,0x03ed8ef082d19L,0x5143fc3a1af4cL,
        0x0c5e94046c37bL } },
    /* 27 */
    { { 0xa538c2be75f9eL,0xe8cb123a78476L,0x109c04b6fd1a9L,0x4747d85e4df0bL,
        0x063283dafdb46L },
      { 0x28cf7baf2df15L,0x550ad9a7f4ce7L,0x834bcc3e592c4L,0xa938fab226adeL,
        0x068bd19ab1981L } },
    /* 28 */
    { { 0xead511887d659L,0xf4b359305ac08L,0xfe74fe33374d5L,0xdfd696986981cL,
        0x0495292f53c6fL },
      { 0x78c9e1acec896L,0x10ec5b44844a8L,0x64d60a7d964b2L,0x68376696f7e26L,
        0x00ec7530d2603L } },
    /* 29 */
    { { 0x13a05ad2687bbL,0x6af32e21fa2daL,0xdd4607ba1f83bL,0x3f0b390f5ef51L,
        0x00f6207a66486L },
      { 0x7e3bb0f138233L,0x6c272aa718bd6L,0x6ec88aedd66b9L,0x6dcf8ed004072L,
        0x0ff0db07208edL } },
    /* 30 */
    { { 0xfa1014c95d553L,0xfd5d680a8a749L,0xf3b566fa44052L,0x0ea3183b4317fL,
        0x0313b513c8874L },
      { 0x2e2ac08d11549L,0x0bb4dee21cb40L,0x7f2320e071ee1L,0x9f8126b987dd4L,
        0x02d3abcf986f1L } },
    /* 31 */
    { { 0x88501815581a2L,0x56632211af4c2L,0xcab2e999a0a6dL,0x8cdf19ba7a0f0L,
        0x0c036fa10ded9L },
      { 0xe08bac1fbd009L,0x9006d1581629aL,0xb9e0d8f0b68b1L,0x0194c2eb32779L,
        0x0a6b2a2c4b6d4L } },
    /* 32 */
    { { 0x3e50f6d3549cfL,0x6ffacd665ed43L,0xe11fcb46f3369L,0x9860695bfdaccL,
        0x0810ee252af7cL },
      { 0x50fe17159bb2cL,0xbe758b357b654L,0x69fea72f7dfbeL,0x17452b057e74dL,
        0x0d485717a9273L } },
    /* 33 */
    { { 0x41a8af0cb5a98L,0x931f3110bf117L,0xb382adfd3da8fL,0x604e1994e2cbaL,
        0x06a6045a72f9aL },
      { 0xc0d3fa2b2411dL,0x3e510e96e0170L,0x865b3ccbe0eb8L,0x57903bcc9f738L,
        0x0d3e45cfaf9e1L } },
    /* 34 */
    { { 0xf69bbe83f7669L,0x8272877d6bce1L,0x244278d09f8aeL,0xc19c9548ae543L,
        0x0207755dee3c2L },
      { 0xd61d96fef1945L,0xefb12d28c387bL,0x2df64aa18813cL,0xb00d9fbcd1d67L,
        0x048dc5ee57154L } },
    /* 35 */
    { { 0x790bff7e5a199L,0xcf989ccbb7123L,0xa519c79e0efb8L,0xf445c27a2bfe0L,
        0x0f2fb0aeddff6L },
      { 0x09575f0b5025fL,0xd740fa9f2241cL,0x80bfbd0550543L,0xd5258fa3c8ad3L,
        0x0a13e9015db28L } },
    /* 36 */
    { { 0x7a350a2b65cbcL,0x722a464226f9fL,0x23f07a10b04b9L,0x526f265ce241eL,
        0x02bf0d6b01497L },
      { 0x4dd3f4b216fb7L,0x67fbdda26ad3dL,0x708505cf7d7b8L,0xe89faeb7b83f6L,
        0x042a94a5a162fL } },
    /* 37 */
    { { 0x6ad0beaadf191L,0x9025a268d7584L,0x94dc1f60f8a48L,0xde3de86030504L,
        0x02c2dd969c65eL },
      { 0x2171d93849c17L,0xba1da250dd6d0L,0xc3a5485460488L,0x6dbc4810c7063L,
        0x0f437fa1f42c5L } },
    /* 38 */
    { { 0x0d7144a0f7dabL,0x931776e9ac6aaL,0x5f397860f0497L,0x7aa852c0a050fL,
        0x0aaf45b335470L },
      { 0x37c33c18d364aL,0x063e49716585eL,0x5ec5444d40b9bL,0x72bcf41716811L,
        0x0cdf6310df4f2L } },
    /* 39 */
    { { 0x3c6238ea8b7efL,0x1885bc2287747L,0xbda8e3408e935L,0x2ff2419567722L,
        0x0f0d008bada9eL },
      { 0x2671d2414d3b1L,0x85b019ea76291L,0x53bcbdbb37549L,0x7b8b5c61b96d4L,
        0x05bd5c2f5ca88L } },
    /* 40 */
    { { 0xf469ef49a3154L,0x956e2b2e9aef0L,0xa924a9c3e85a5L,0x471945aaec1eaL,
        0x0aa12dfc8a09eL },
      { 0x272274df69f1dL,0x2ca2ff5e7326fL,0x7a9dd44e0e4c8L,0xa901b9d8ce73bL,
        0x06c036e73e48cL } },
    /* 41 */
    { { 0xae12a0f6e3138L,0x0025ad345a5cfL,0x5672bc56966efL,0xbe248993c64b4L,
        0x0292ff65896afL },
      { 0x50d445e213402L,0x274392c9fed52L,0xa1c72e8f6580eL,0x7276097b397fdL,
        0x0644e0c90311bL } },
    /* 42 */
    { { 0x421e1a47153f0L,0x79920418c9e1eL,0x05d7672b86c3bL,0x9a7793bdce877L,
        0x0f25ae793cab7L },
      { 0x194a36d869d0cL,0x824986c2641f3L,0x96e945e9d55c8L,0x0a3e49fb5ea30L,
        0x039b8e65313dbL } },
    /* 43 */
    { { 0x54200b6fd2e59L,0x669255c98f377L,0xe2a573935e2c0L,0xdb06d9dab21a0L,
        0x039122f2f0f19L },
      { 0xce1e003cad53cL,0x0fe65c17e3cfbL,0xaa13877225b2cL,0xff8d72baf1d29L,
        0x08de80af8ce80L } },
    /* 44 */
    { { 0xea8d9207bbb76L,0x7c21782758afbL,0xc0436b1921c7eL,0x8c04dfa2b74b1L,
        0x0871949062e36L },
      { 0x928bba3993df5L,0xb5f3b3d26ab5fL,0x5b55050639d75L,0xfde1011aa78a8L,
        0x0fc315e6a5b74L } },
    /* 45 */
    { { 0xfd41ae8d6ecfaL,0xf61aec7f86561L,0x924741d5f8c44L,0x908898452a7b4L,
        0x0e6d4a7adee38L },
      { 0x52ed14593c75dL,0xa4dd271162605L,0xba2c7db70a70dL,0xae57d2aede937L,
        0x035dfaf9a9be2L } },
    /* 46 */
    { { 0x56fcdaa736636L,0x97ae2cab7e6b9L,0xf34996609f51dL,0x0d2bfb10bf410L,
        0x01da5c7d71c83L },
      { 0x1e4833cce6825L,0x8ff9573c3b5c4L,0x23036b815ad11L,0xb9d6a28552c7fL,
        0x07077c0fddbf4L } },
    /* 47 */
    { { 0x3ff8d46b9661cL,0x6b0d2cfd71bf6L,0x847f8f7a1dfd3L,0xfe440373e140aL,
        0x053a8632ee50eL },
      { 0x6ff68696d8051L,0x95c74f468a097L,0xe4e26bddaec0cL,0xfcc162994dc35L,
        0x0028ca76d34e1L } },
    /* 48 */
    { { 0xd47dcfc9877eeL,0x10801d0002d11L,0x4c260b6c8b362L,0xf046d002c1175L,
        0x004c17cd86962L },
      { 0xbd094b0daddf5L,0x7524ce55c06d9L,0x2da03b5bea235L,0x7474663356e67L,
        0x0f7ba4de9fed9L } },
    /* 49 */
    { { 0xbfa34ebe1263fL,0x3571ae7ce6d0dL,0x2a6f523557637L,0x1c41d24405538L,
        0x0e31f96005213L },
      { 0xb9216ea6b6ec6L,0x2e73c2fc44d1bL,0x9d0a29437a1d1L,0xd47bc10e7eac8L,
        0x0aa3a6259ce34L } },
    /* 50 */
    { { 0xf9df536f3dcd3L,0x50d2bf7360fbcL,0xf504f5b6cededL,0xdaee491710fadL,
        0x02398dd627e79L },
      { 0x705a36d09569eL,0xbb5149f769cf4L,0x5f6034cea0619L,0x6210ff9c03773L,
        0x05717f5b21c04L } },
    /* 51 */
    { { 0x229c921dd895eL,0x0040c284519feL,0xd637ecd8e5185L,0x28defa13d2391L,
        0x0660a2c560e3cL },
      { 0xa88aed67fcbd0L,0x780ea9f0969ccL,0x2e92b4dc84724L,0x245332b2f4817L,
        0x0624ee54c4f52L } },
    /* 52 */
    { { 0x49ce4d897ecccL,0xd93f9880aa095L,0x43a7c204d49d1L,0xfbc0723c24230L,
        0x04f392afb92bdL },
      { 0x9f8fa7de44fd9L,0xe457b32156696L,0x68ebc3cb66cfbL,0x399cdb2fa8033L,
        0x08a3e7977ccdbL } },
    /* 53 */
    { { 0x1881f06c4b125L,0x00f6e3ca8cddeL,0xc7a13e9ae34e3L,0x4404ef6999de5L,
        0x03888d02370c2L },
      { 0x8035644f91081L,0x615f015504762L,0x32cd36e3d9fcfL,0x23361827edc86L,
        0x0a5e62e471810L } },
    /* 54 */
    { { 0x25ee32facd6c8L,0x5454bcbc661a8L,0x8df9931699c63L,0x5adc0ce3edf79L,
        0x02c4768e6466aL },
      { 0x6ff8c90a64bc9L,0x20e4779f5cb34L,0xc05e884630a60L,0x52a0d949d064bL,
        0x07b5e6441f9e6L } },
    /* 55 */
    { { 0x9422c1d28444aL,0xd8be136a39216L,0xb0c7fcee996c5L,0x744a2387afe5fL,
        0x0b8af73cb0c8dL },
      { 0xe83aa338b86fdL,0x58a58a5cff5fdL,0x0ac9433fee3f1L,0x0895c9ee8f6f2L,
        0x0a036395f7f3fL } },
    /* 56 */
    { { 0x3c6bba10f7770L,0x81a12a0e248c7L,0x1bc2b9fa6f16dL,0xb533100df6825L,
        0x04be36b01875fL },
      { 0x6086e9fb56dbbL,0x8b07e7a4f8922L,0x6d52f20306fefL,0x00c0eeaccc056L,
        0x08cbc9a871bdcL } },
    /* 57 */
    { { 0x1895cc0dac4abL,0x40712ff112e13L,0xa1cee57a874a4L,0x35f86332ae7c6L,
        0x044e7553e0c08L },
      { 0x03fff7734002dL,0x8b0b34425c6d5L,0xe8738b59d35cbL,0xfc1895f702760L,
        0x0470a683a5eb8L } },
    /* 58 */
    { { 0x761dc90513482L,0x2a01e9276a81bL,0xce73083028720L,0xc6efcda441ee0L,
        0x016410690c63dL },
      { 0x34a066d06a2edL,0x45189b100bf50L,0xb8218c9dd4d77L,0xbb4fd914ae72aL,
        0x0d73479fd7abcL } },
    /* 59 */
    { { 0xefb165ad4c6e5L,0x8f5b06d04d7edL,0x575cb14262cf0L,0x666b12ed5bb18L,
        0x0816469e30771L },
      { 0xb9d79561e291eL,0x22c1de1661d7aL,0x35e0513eb9dafL,0x3f9cf49827eb1L,
        0x00a36dd23f0ddL } },
    /* 60 */
    { { 0xd32c741d5533cL,0x9e8684628f098L,0x349bd117c5f5aL,0xb11839a228adeL,
        0x0e331dfd6fdbaL },
      { 0x0ab686bcc6ed8L,0xbdef7a260e510L,0xce850d77160c3L,0x33899063d9a7bL,
        0x0d3b4782a492eL } },
    /* 61 */
    { { 0x9b6e8f3821f90L,0xed66eb7aada14L,0xa01311692edd9L,0xa5bd0bb669531L,
        0x07281275a4c86L },
      { 0x858f7d3ff47e5L,0xbc61016441503L,0xdfd9bb15e1616L,0x505962b0f11a7L,
        0x02c062e7ece14L } },
    /* 62 */
    { { 0xf996f0159ac2eL,0x36cbdb2713a76L,0x8e46047281e77L,0x7ef12ad6d2880L,
        0x0282a35f92c4eL },
      { 0x54b1ec0ce5cd2L,0xc91379c2299c3L,0xe82c11ecf99efL,0x2abd992caf383L,
        0x0c71cd513554dL } },
    /* 63 */
    { { 0x5de9c09b578f4L,0x58e3affa7a488L,0x9182f1f1884e2L,0xf3a38f76b1b75L,
        0x0c50f6740cf47L },
      { 0x4adf3374b68eaL,0x2369965fe2a9cL,0x5a53050a406f3L,0x58dc2f86a2228L,
        0x0b9ecb3a72129L } },
    /* 64 */
    { { 0x8410ef4f8b16aL,0xfec47b266a56fL,0xd9c87c197241aL,0xab1b0a406b8e6L,
        0x0803f3e02cd42L },
      { 0x309a804dbec69L,0xf73bbad05f7f0L,0xd8e197fa83b85L,0xadc1c6097273aL,
        0x0c097440e5067L } },
    /* 65 */
    { { 0xa56f2c379ab34L,0x8b841df8d1846L,0x76c68efa8ee06L,0x1f30203144591L,
        0x0f1af32d5915fL },
      { 0x375315d75bd50L,0xbaf72f67bc99cL,0x8d7723f837cffL,0x1c8b0613a4184L,
        0x023d0f130e2d4L } },
    /* 66 */
    { { 0xab6edf41500d9L,0xe5fcbeada8857L,0x97259510d890aL,0xfadd52fe86488L,
        0x0b0288dd6c0a3L },
      { 0x20f30650bcb08L,0x13695d6e16853L,0x989aa7671af63L,0xc8d231f520a7bL,
        0x0ffd3724ff408L } },
    /* 67 */
    { { 0x68e64b458e6cbL,0x20317a5d28539L,0xaa75f56992dadL,0x26df3814ae0b7L,
        0x0f5590f4ad78cL },
      { 0x24bd3cf0ba55aL,0x4a0c778bae0fcL,0x83b674a0fc472L,0x4a201ce9864f6L,
        0x018d6da54f6f7L } },
    /* 68 */
    { { 0x3e225d5be5a2bL,0x835934f3c6ed9L,0x2626ffc6fe799L,0x216a431409262L,
        0x050bbb4d97990L },
      { 0x191c6e57ec63eL,0x40181dcdb2378L,0x236e0f665422cL,0x49c341a8099b0L,
        0x02b10011801feL } },
    /* 69 */
    { { 0x8b5c59b391593L,0xa2598270fcfc6L,0x19adcbbc385f5L,0xae0c7144f3aadL,
        0x0dd55899983fbL },
      { 0x88b8e74b82ff4L,0x4071e734c993bL,0x3c0322ad2e03cL,0x60419a7a9eaf4L,
        0x0e6e4c551149dL } },
    /* 70 */
    { { 0x655bb1e9af288L,0x64f7ada93155fL,0xb2820e5647e1aL,0x56ff43697e4bcL,
        0x051e00db107edL },
      { 0x169b8771c327eL,0x0b4a96c2ad43dL,0xdeb477929cdb2L,0x9177c07d51f53L,
        0x0e22f42414982L } },
    /* 71 */
    { { 0x5e8f4635f1abbL,0xb568538874cd4L,0x5a8034d7edc0cL,0x48c9c9472c1fbL,
        0x0f709373d52dcL },
      { 0x966bba8af30d6L,0x4af137b69c401L,0x361c47e95bf5fL,0x5b113966162a9L,
        0x0bd52d288e727L } },
    /* 72 */
    { { 0x55c7a9c5fa877L,0x727d3a3d48ab1L,0x3d189d817dad6L,0x77a643f43f9e7L,
        0x0a0d0f8e4c8aaL },
      { 0xeafd8cc94f92dL,0xbe0c4ddb3a0bbL,0x82eba14d818c8L,0x6a0022cc65f8bL,
        0x0a56c78c7946dL } },
    /* 73 */
    { { 0x2391b0dd09529L,0xa63daddfcf296L,0xb5bf481803e0eL,0x367a2c77351f5L,
        0x0d8befdf8731aL },
      { 0x19d42fc0157f4L,0xd7fec8e650ab9L,0x2d48b0af51caeL,0x6478cdf9cb400L,
        0x0854a68a5ce9fL } },
    /* 74 */
    { { 0x5f67b63506ea5L,0x89a4fe0d66dc3L,0xe95cd4d9286c4L,0x6a953f101d3bfL,
        0x05cacea0b9884L },
      { 0xdf60c9ceac44dL,0xf4354d1c3aa90L,0xd5dbabe3db29aL,0xefa908dd3de8aL,
        0x0e4982d1235e4L } },
    /* 75 */
    { { 0x04a22c34cd55eL,0xb32680d132231L,0xfa1d94358695bL,0x0499fb345afa1L,
        0x08046b7f616b2L },
      { 0x3581e38e7d098L,0x8df46f0b70b53L,0x4cb78c4d7f61eL,0xaf5530dea9ea4L,
        0x0eb17ca7b9082L } },
    /* 76 */
    { { 0x1b59876a145b9L,0x0fc1bc71ec175L,0x92715bba5cf6bL,0xe131d3e035653L,
        0x0097b00bafab5L },
      { 0x6c8e9565f69e1L,0x5ab5be5199aa6L,0xa4fd98477e8f7L,0xcc9e6033ba11dL,
        0x0f95c747bafdbL } },
    /* 77 */
    { { 0xf01d3bebae45eL,0xf0c4bc6955558L,0xbc64fc6a8ebe9L,0xd837aeb705b1dL,
        0x03512601e566eL },
      { 0x6f1e1fa1161cdL,0xd54c65ef87933L,0x24f21e5328ab8L,0xab6b4757eee27L,
        0x00ef971236068L } },
    /* 78 */
    { { 0x98cf754ca4226L,0x38f8642c8e025L,0x68e17905eede1L,0xbc9548963f744L,
        0x0fc16d9333b4fL },
      { 0x6fb31e7c800caL,0x312678adaabe9L,0xff3e8b5138063L,0x7a173d6244976L,
        0x014ca4af1b95dL } },
    /* 79 */
    { { 0x771babd2f81d5L,0x6901f7d1967a4L,0xad9c9071a5f9dL,0x231dd898bef7cL,
        0x04057b063f59cL },
      { 0xd82fe89c05c0aL,0x6f1dc0df85bffL,0x35a16dbe4911cL,0x0b133befccaeaL,
        0x01c3b5d64f133L } },
    /* 80 */
    { { 0x14bfe80ec21feL,0x6ac255be825feL,0xf4a5d67f6ce11L,0x63af98bc5a072L,
        0x0fad27148db7eL },
      { 0x0b6ac29ab05b3L,0x3c4e251ae690cL,0x2aade7d37a9a8L,0x1a840a7dc875cL,
        0x077387de39f0eL } },
    /* 81 */
    { { 0xecc49a56c0dd7L,0xd846086c741e9L,0x505aecea5cffcL,0xc47e8f7a1408fL,
        0x0b37b85c0bef0L },
      { 0x6b6e4cc0e6a8fL,0xbf6b388f23359L,0x39cef4efd6d4bL,0x28d5aba453facL,
        0x09c135ac8f9f6L } },
    /* 82 */
    { { 0xa320284e35743L,0xb185a3cdef32aL,0xdf19819320d6aL,0x851fb821b1761L,
        0x05721361fc433L },
      { 0xdb36a71fc9168L,0x735e5c403c1f0L,0x7bcd8f55f98baL,0x11bdf64ca87e3L,
        0x0dcbac3c9e6bbL } },
    /* 83 */
    { { 0xd99684518cbe2L,0x189c9eb04ef01L,0x47feebfd242fcL,0x6862727663c7eL,
        0x0b8c1c89e2d62L },
      { 0x58bddc8e1d569L,0xc8b7d88cd051aL,0x11f31eb563809L,0x22d426c27fd9fL,
        0x05d23bbda2f94L } },
    /* 84 */
    { { 0xc729495c8f8beL,0x803bf362bf0a1L,0xf63d4ac2961c4L,0xe9009e418403dL,
        0x0c109f9cb91ecL },
      { 0x095d058945705L,0x96ddeb85c0c2dL,0xa40449bb9083dL,0x1ee184692b8d7L,
        0x09bc3344f2eeeL } },
    /* 85 */
    { { 0xae35642913074L,0x2748a542b10d5L,0x310732a55491bL,0x4cc1469ca665bL,
        0x029591d525f1aL },
      { 0xf5b6bb84f983fL,0x419f5f84e1e76L,0x0baa189be7eefL,0x332c1200d4968L,
        0x06376551f18efL } },
    /* 86 */
    { { 0x5f14e562976ccL,0xe60ef12c38bdaL,0xcca985222bca3L,0x987abbfa30646L,
        0x0bdb79dc808e2L },
      { 0xcb5c9cb06a772L,0xaafe536dcefd2L,0xc2b5db838f475L,0xc14ac2a3e0227L,
        0x08ee86001add3L } },
    /* 87 */
    { { 0x96981a4ade873L,0x4dc4fba48ccbeL,0xa054ba57ee9aaL,0xaa4b2cee28995L,
        0x092e51d7a6f77L },
      { 0xbafa87190a34dL,0x5bf6bd1ed1948L,0xcaf1144d698f7L,0xaaaad00ee6e30L,
        0x05182f86f0a56L } },
    /* 88 */
    { { 0x6212c7a4cc99cL,0x683e6d9ca1fbaL,0xac98c5aff609bL,0xa6f25dbb27cb5L,
        0x091dcab5d4073L },
      { 0x6cc3d5f575a70L,0x396f8d87fa01bL,0x99817360cb361L,0x4f2b165d4e8c8L,
        0x017a0cedb9797L } },
    /* 89 */
    { { 0x61e2a076c8d3aL,0x39210f924b388L,0x3a835d9701aadL,0xdf4194d0eae41L,
        0x02e8ce36c7f4cL },
      { 0x73dab037a862bL,0xb760e4c8fa912L,0x3baf2dd01ba9bL,0x68f3f96453883L,
        0x0f4ccc6cb34f6L } },
    /* 90 */
    { { 0xf525cf1f79687L,0x9592efa81544eL,0x5c78d297c5954L,0xf3c9e1231741aL,
        0x0ac0db4889a0dL },
      { 0xfc711df01747fL,0x58ef17df1386bL,0xccb6bb5592b93L,0x74a2e5880e4f5L,
        0x095a64a6194c9L } },
    /* 91 */
    { { 0x1efdac15a4c93L,0x738258514172cL,0x6cb0bad40269bL,0x06776a8dfb1c1L,
        0x0231e54ba2921L },
      { 0xdf9178ae6d2dcL,0x3f39112918a70L,0xe5b72234d6aa6L,0x31e1f627726b5L,
        0x0ab0be032d8a7L } },
    /* 92 */
    { { 0xad0e98d131f2dL,0xe33b04f101097L,0x5e9a748637f09L,0xa6791ac86196dL,
        0x0f1bcc8802cf6L },
      { 0x69140e8daacb4L,0x5560f6500925cL,0x77937a63c4e40L,0xb271591cc8fc4L,
        0x0851694695aebL } },
    /* 93 */
    { { 0x5c143f1dcf593L,0x29b018be3bde3L,0xbdd9d3d78202bL,0x55d8e9cdadc29L,
        0x08f67d9d2daadL },
      { 0x116567481ea5fL,0xe9e34c590c841L,0x5053fa8e7d2ddL,0x8b5dffdd43f40L,
        0x0f84572b9c072L } },
    /* 94 */
    { { 0xa7a7197af71c9L,0x447a7365655e1L,0xe1d5063a14494L,0x2c19a1b4ae070L,
        0x0edee2710616bL },
      { 0x034f511734121L,0x554a25e9f0b2fL,0x40c2ecf1cac6eL,0xd7f48dc148f3aL,
        0x09fd27e9b44ebL } },
    /* 95 */
    { { 0x7658af6e2cb16L,0x2cfe5919b63ccL,0x68d5583e3eb7dL,0xf3875a8c58161L,
        0x0a40c2fb6958fL },
      { 0xec560fedcc158L,0xc655f230568c9L,0xa307e127ad804L,0xdecfd93967049L,
        0x099bc9bb87dc6L } },
    /* 96 */
    { { 0x9521d927dafc6L,0x695c09cd1984aL,0x9366dde52c1fbL,0x7e649d9581a0fL,
        0x09abe210ba16dL },
      { 0xaf84a48915220L,0x6a4dd816c6480L,0x681ca5afa7317L,0x44b0c7d539871L,
        0x07881c25787f3L } },
    /* 97 */
    { { 0x99b51e0bcf3ffL,0xc5127f74f6933L,0xd01d9680d02cbL,0x89408fb465a2dL,
        0x015e6e319a30eL },
      { 0xd6e0d3e0e05f4L,0xdc43588404646L,0x4f850d3fad7bdL,0x72cebe61c7d1cL,
        0x00e55facf1911L } },
    /* 98 */
    { { 0xd9806f8787564L,0x2131e85ce67e9L,0x819e8d61a3317L,0x65776b0158cabL,
        0x0d73d09766fe9L },
      { 0x834251eb7206eL,0x0fc618bb42424L,0xe30a520a51929L,0xa50b5dcbb8595L,
        0x09250a3748f15L } },
    /* 99 */
    { { 0xf08f8be577410L,0x035077a8c6cafL,0xc0a63a4fd408aL,0x8c0bf1f63289eL,
        0x077414082c1ccL },
      { 0x40fa6eb0991cdL,0x6649fdc29605aL,0x324fd40c1ca08L,0x20b93a68a3c7bL,
        0x08cb04f4d12ebL } },
    /* 100 */
    { { 0x2d0556906171cL,0xcdb0240c3fb1cL,0x89068419073e9L,0x3b51db8e6b4fdL,
        0x0e4e429ef4712L },
      { 0xdd53c38ec36f4L,0x01ff4b6a270b8L,0x79a9a48f9d2dcL,0x65525d066e078L,
        0x037bca2ff3c6eL } },
    /* 101 */
    { { 0x2e3c7df562470L,0xa2c0964ac94cdL,0x0c793be44f272L,0xb22a7c6d5df98L,
        0x059913edc3002L },
      { 0x39a835750592aL,0x80e783de027a1L,0xa05d64f99e01dL,0xe226cf8c0375eL,
        0x043786e4ab013L } },
    /* 102 */
    { { 0x2b0ed9e56b5a6L,0xa6d9fc68f9ff3L,0x97846a70750d9L,0x9e7aec15e8455L,
        0x08638ca98b7e7L },
      { 0xae0960afc24b2L,0xaf4dace8f22f5L,0xecba78f05398eL,0xa6f03b765dd0aL,
        0x01ecdd36a7b3aL } },
    /* 103 */
    { { 0xacd626c5ff2f3L,0xc02873a9785d3L,0x2110d54a2d516L,0xf32dad94c9fadL,
        0x0d85d0f85d459L },
      { 0x00b8d10b11da3L,0x30a78318c49f7L,0x208decdd2c22cL,0x3c62556988f49L,
        0x0a04f19c3b4edL } },
    /* 104 */
    { { 0x924c8ed7f93bdL,0x5d392f51f6087L,0x21b71afcb64acL,0x50b07cae330a8L,
        0x092b2eeea5c09L },
      { 0xc4c9485b6e235L,0xa92936c0f085aL,0x0508891ab2ca4L,0x276c80faa6b3eL,
        0x01ee782215834L } },
    /* 105 */
    { { 0xa2e00e63e79f7L,0xb2f399d906a60L,0x607c09df590e7L,0xe1509021054a6L,
        0x0f3f2ced857a6L },
      { 0x510f3f10d9b55L,0xacd8642648200L,0x8bd0e7c9d2fcfL,0xe210e5631aa7eL,
        0x00f56a4543da3L } },
    /* 106 */
    { { 0x1bffa1043e0dfL,0xcc9c007e6d5b2L,0x4a8517a6c74b6L,0xe2631a656ec0dL,
        0x0bd8f17411969L },
      { 0xbbb86beb7494aL,0x6f45f3b8388a9L,0x4e5a79a1567d4L,0xfa09df7a12a7aL,
        0x02d1a1c3530ccL } },
    /* 107 */
    { { 0xe3813506508daL,0xc4a1d795a7192L,0xa9944b3336180L,0xba46cddb59497L,
        0x0a107a65eb91fL },
      { 0x1d1c50f94d639L,0x758a58b7d7e6dL,0xd37ca1c8b4af3L,0x9af21a7c5584bL,
        0x0183d760af87aL } },
    /* 108 */
    { { 0x697110dde59a4L,0x070e8bef8729dL,0xf2ebe78f1ad8dL,0xd754229b49634L,
        0x01d44179dc269L },
      { 0xdc0cf8390d30eL,0x530de8110cb32L,0xbc0339a0a3b27L,0xd26231af1dc52L,
        0x0771f9cc29606L } },
    /* 109 */
    { { 0x93e7785040739L,0xb98026a939999L,0x5f8fc2644539dL,0x718ecf40f6f2fL,
        0x064427a310362L },
      { 0xf2d8785428aa8L,0x3febfb49a84f4L,0x23d01ac7b7adcL,0x0d6d201b2c6dfL,
        0x049d9b7496ae9L } },
    /* 110 */
    { { 0x8d8bc435d1099L,0x4e8e8d1a08cc7L,0xcb68a412adbcdL,0x544502c2e2a02L,
        0x09037d81b3f60L },
      { 0xbac27074c7b61L,0xab57bfd72e7cdL,0x96d5352fe2031L,0x639c61ccec965L,
        0x008c3de6a7cc0L } },
    /* 111 */
    { { 0xdd020f6d552abL,0x9805cd81f120fL,0x135129156baffL,0x6b2f06fb7c3e9L,
        0x0c69094424579L },
      { 0x3ae9c41231bd1L,0x875cc5820517bL,0x9d6a1221eac6eL,0x3ac0208837abfL,
        0x03fa3db02cafeL } },
    /* 112 */
    { { 0xa3e6505058880L,0xef643943f2d75L,0xab249257da365L,0x08ff4147861cfL,
        0x0c5c4bdb0fdb8L },
      { 0x13e34b272b56bL,0x9511b9043a735L,0x8844969c8327eL,0xb6b5fd8ce37dfL,
        0x02d56db9446c2L } },
    /* 113 */
    { { 0x1782fff46ac6bL,0x2607a2e425246L,0x9a48de1d19f79L,0xba42fafea3c40L,
        0x00f56bd9de503L },
      { 0xd4ed1345cda49L,0xfc816f299d137L,0xeb43402821158L,0xb5f1e7c6a54aaL,
        0x04003bb9d1173L } },
    /* 114 */
    { { 0xe8189a0803387L,0xf539cbd4043b8L,0x2877f21ece115L,0x2f9e4297208ddL,
        0x053765522a07fL },
      { 0x80a21a8a4182dL,0x7a3219df79a49L,0xa19a2d4a2bbd0L,0x4549674d0a2e1L,
        0x07a056f586c5dL } },
    /* 115 */
    { { 0xb25589d8a2a47L,0x48c3df2773646L,0xbf0d5395b5829L,0x267551ec000eaL,
        0x077d482f17a1aL },
      { 0x1bd9587853948L,0xbd6cfbffeeb8aL,0x0681e47a6f817L,0xb0e4ab6ec0578L,
        0x04115012b2b38L } },
    /* 116 */
    { { 0x3f0f46de28cedL,0x609b13ec473c7L,0xe5c63921d5da7L,0x094661b8ce9e6L,
        0x0cdf04572fbeaL },
      { 0x3c58b6c53c3b0L,0x10447b843c1cbL,0xcb9780e97fe3cL,0x3109fb2b8ae12L,
        0x0ee703dda9738L } },
    /* 117 */
    { { 0x15140ff57e43aL,0xd3b1b811b8345L,0xf42b986d44660L,0xce212b3b5dff8L,
        0x02a0ad89da162L },
      { 0x4a6946bc277baL,0x54c141c27664eL,0xabf6274c788c9L,0x4659141aa64ccL,
        0x0d62d0b67ac2bL } },
    /* 118 */
    { { 0x5d87b2c054ac4L,0x59f27df78839cL,0x18128d6570058L,0x2426edf7cbf3bL,
        0x0b39a23f2991cL },
      { 0x84a15f0b16ae5L,0xb1a136f51b952L,0x27007830c6a05L,0x4cc51d63c137fL,
        0x004ed0092c067L } },
    /* 119 */
    { { 0x185d19ae90393L,0x294a3d64e61f4L,0x854fc143047b4L,0xc387ae0001a69L,
        0x0a0a91fc10177L },
      { 0xa3f01ae2c831eL,0x822b727e16ff0L,0xa3075b4bb76aeL,0x0c418f12c8a15L,
        0x0084cf9889ed2L } },
    /* 120 */
    { { 0x509defca6becfL,0x807dffb328d98L,0x778e8b92fceaeL,0xf77e5d8a15c44L,
        0x0d57955b273abL },
      { 0xda79e31b5d4f1L,0x4b3cfa7a1c210L,0xc27c20baa52f0L,0x41f1d4d12089dL,
        0x08e14ea4202d1L } },
    /* 121 */
    { { 0x50345f2897042L,0x1f43402c4aeedL,0x8bdfb218d0533L,0xd158c8d9c194cL,
        0x0597e1a372aa4L },
      { 0x7ec1acf0bd68cL,0xdcab024945032L,0x9fe3e846d4be0L,0x4dea5b9c8d7acL,
        0x0ca3f0236199bL } },
    /* 122 */
    { { 0xa10b56170bd20L,0xf16d3f5de7592L,0x4b2ade20ea897L,0x07e4a3363ff14L,
        0x0bde7fd7e309cL },
      { 0xbb6d2b8f5432cL,0xcbe043444b516L,0x8f95b5a210dc1L,0xd1983db01e6ffL,
        0x0b623ad0e0a7dL } },
    /* 123 */
    { { 0xbd67560c7b65bL,0x9023a4a289a75L,0x7b26795ab8c55L,0x137bf8220fd0dL,
        0x0d6aa2e4658ecL },
      { 0xbc00b5138bb85L,0x21d833a95c10aL,0x702a32e8c31d1L,0x513ab24ff00b1L,
        0x0111662e02dccL } },
    /* 124 */
    { { 0x14015efb42b87L,0x701b6c4dff781L,0x7d7c129bd9f5dL,0x50f866ecccd7aL,
        0x0db3ee1cb94b7L },
      { 0xf3db0f34837cfL,0x8bb9578d4fb26L,0xc56657de7eed1L,0x6a595d2cdf937L,
        0x0886a64425220L } },
    /* 125 */
    { { 0x34cfb65b569eaL,0x41f72119c13c2L,0x15a619e200111L,0x17bc8badc85daL,
        0x0a70cf4eb018aL },
      { 0xf97ae8c4a6a65L,0x270134378f224L,0xf7e096036e5cfL,0x7b77be3a609e4L,
        0x0aa4772abd174L } },
    /* 126 */
    { { 0x761317aa60cc0L,0x610368115f676L,0xbc1bb5ac79163L,0xf974ded98bb4bL,
        0x0611a6ddc30faL },
      { 0x78cbcc15ee47aL,0x824e0d96a530eL,0xdd9ed882e8962L,0x9c8836f35adf3L,
        0x05cfffaf81642L } },
    /* 127 */
    { { 0x54cff9b7a99cdL,0x9d843c45a1c0dL,0x2c739e17bf3b9L,0x994c038a908f6L,
        0x06e5a6b237dc1L },
      { 0xb454e0ba5db77L,0x7facf60d63ef8L,0x6608378b7b880L,0xabcce591c0c67L,
        0x0481a238d242dL } },
    /* 128 */
    { { 0x17bc035d0b34aL,0x6b8327c0a7e34L,0xc0362d1440b38L,0xf9438fb7262daL,
        0x02c41114ce0cdL },
      { 0x5cef1ad95a0b1L,0xa867d543622baL,0x1e486c9c09b37L,0x929726d6cdd20L,
        0x020477abf42ffL } },
    /* 129 */
    { { 0x5173c18d65dbfL,0x0e339edad82f7L,0xcf1001c77bf94L,0x96b67022d26bdL,
        0x0ac66409ac773L },
      { 0xbb36fc6261cc3L,0xc9190e7e908b0L,0x45e6c10213f7bL,0x2f856541cebaaL,
        0x0ce8e6975cc12L } },
    /* 130 */
    { { 0x21b41bc0a67d2L,0x0a444d248a0f1L,0x59b473762d476L,0xb4a80e044f1d6L,
        0x008fde365250bL },
      { 0xec3da848bf287L,0x82d3369d6eaceL,0x2449482c2a621L,0x6cd73582dfdc9L,
        0x02f7e2fd2565dL } },
    /* 131 */
    { { 0xb92dbc3770fa7L,0x5c379043f9ae4L,0x7761171095e8dL,0x02ae54f34e9d1L,
        0x0c65be92e9077L },
      { 0x8a303f6fd0a40L,0xe3bcce784b275L,0xf9767bfe7d822L,0x3b3a7ae4f5854L,
        0x04bff8e47d119L } },
    /* 132 */
    { { 0x1d21f00ff1480L,0x7d0754db16cd4L,0xbe0f3ea2ab8fbL,0x967dac81d2efbL,
        0x03e4e4ae65772L },
      { 0x8f36d3c5303e6L,0x4b922623977e1L,0x324c3c03bd999L,0x60289ed70e261L,
        0x05388aefd58ecL } },
    /* 133 */
    { { 0x317eb5e5d7713L,0xee75de49daad1L,0x74fb26109b985L,0xbe0e32f5bc4fcL,
        0x05cf908d14f75L },
      { 0x435108e657b12L,0xa5b96ed9e6760L,0x970ccc2bfd421L,0x0ce20e29f51f8L,
        0x0a698ba4060f0L } },
    /* 134 */
    { { 0xb1686ef748fecL,0xa27e9d2cf973dL,0xe265effe6e755L,0xad8d630b6544cL,
        0x0b142ef8a7aebL },
      { 0x1af9f17d5770aL,0x672cb3412fad3L,0xf3359de66af3bL,0x50756bd60d1bdL,
        0x0d1896a965851L } },
    /* 135 */
    { { 0x957ab33c41c08L,0xac5468e2e1ec5L,0xc472f6c87de94L,0xda3918816b73aL,
        0x0267b0e0b7981L },
      { 0x54e5d8e62b988L,0x55116d21e76e5L,0xd2a6f99d8ddc7L,0x93934610faf03L,
        0x0b54e287aa111L } },
    /* 136 */
    { { 0x122b5178a876bL,0xff085104b40a0L,0x4f29f7651ff96L,0xd4e6050b31ab1L,
        0x084abb28b5f87L },
      { 0xd439f8270790aL,0x9d85e3f46bd5eL,0xc1e22122d6cb5L,0x564075f55c1b6L,
        0x0e5436f671765L } },
    /* 137 */
    { { 0x9025e2286e8d5L,0xb4864453be53fL,0x408e3a0353c95L,0xe99ed832f5bdeL,
        0x00404f68b5b9cL },
      { 0x33bdea781e8e5L,0x18163c2f5bcadL,0x119caa33cdf50L,0xc701575769600L,
        0x03a4263df0ac1L } },
    /* 138 */
    { { 0x65ecc9aeb596dL,0xe7023c92b4c29L,0xe01396101ea03L,0xa3674704b4b62L,
        0x00ca8fd3f905eL },
      { 0x23a42551b2b61L,0x9c390fcd06925L,0x392a63e1eb7a8L,0x0c33e7f1d2be0L,
        0x096dca2644ddbL } },
    /* 139 */
    { { 0xbb43a387510afL,0xa8a9a36a01203L,0xf950378846feaL,0x59dcd23a57702L,
        0x04363e2123aadL },
      { 0x3a1c740246a47L,0xd2e55dd24dca4L,0xd8faf96b362b8L,0x98c4f9b086045L,
        0x0840e115cd8bbL } },
    /* 140 */
    { { 0x205e21023e8a7L,0xcdd8dc7a0bf12L,0x63a5ddfc808a8L,0xd6d4e292a2721L,
        0x05e0d6abd30deL },
      { 0x721c27cfc0f64L,0x1d0e55ed8807aL,0xd1f9db242eec0L,0xa25a26a7bef91L,
        0x07dea48f42945L } },
    /* 141 */
    { { 0xf6f1ce5060a81L,0x72f8f95615abdL,0x6ac268be79f9cL,0x16d1cfd36c540L,
        0x0abc2a2beebfdL },
      { 0x66f91d3e2eac7L,0x63d2dd04668acL,0x282d31b6f10baL,0xefc16790e3770L,
        0x04ea353946c7eL } },
    /* 142 */
    { { 0xa2f8d5266309dL,0xc081945a3eed8L,0x78c5dc10a51c6L,0xffc3cecaf45a5L,
        0x03a76e6891c94L },
      { 0xce8a47d7b0d0fL,0x968f584a5f9aaL,0xe697fbe963aceL,0x646451a30c724L,
        0x08212a10a465eL } },
    /* 143 */
    { { 0xc61c3cfab8caaL,0x840e142390ef7L,0xe9733ca18eb8eL,0xb164cd1dff677L,
        0x0aa7cab71599cL },
      { 0xc9273bc837bd1L,0xd0c36af5d702fL,0x423da49c06407L,0x17c317621292fL,
        0x040e38073fe06L } },
    /* 144 */
    { { 0x80824a7bf9b7cL,0x203fbe30d0f4fL,0x7cf9ce3365d23L,0x5526bfbe53209L,
        0x0e3604700b305L },
      { 0xb99116cc6c2c7L,0x08ba4cbee64dcL,0x37ad9ec726837L,0xe15fdcded4346L,
        0x06542d677a3deL } },
    /* 145 */
    { { 0x2b6d07b6c377aL,0x47903448be3f3L,0x0da8af76cb038L,0x6f21d6fdd3a82L,
        0x0a6534aee09bbL },
      { 0x1780d1035facfL,0x339dcb47e630aL,0x447f39335e55aL,0xef226ea50fe1cL,
        0x0f3cb672fdc9aL } },
    /* 146 */
    { { 0x719fe3b55fd83L,0x6c875ddd10eb3L,0x5cea784e0d7a4L,0x70e733ac9fa90L,
        0x07cafaa2eaae8L },
      { 0x14d041d53b338L,0xa0ef87e6c69b8L,0x1672b0fe0acc0L,0x522efb93d1081L,
        0x00aab13c1b9bdL } },
    /* 147 */
    { { 0xce278d2681297L,0xb1b509546addcL,0x661aaf2cb350eL,0x12e92dc431737L,
        0x04b91a6028470L },
      { 0xf109572f8ddcfL,0x1e9a911af4dcfL,0x372430e08ebf6L,0x1cab48f4360acL,
        0x049534c537232L } },
    /* 148 */
    { { 0xf7d71f07b7e9dL,0xa313cd516f83dL,0xc047ee3a478efL,0xc5ee78ef264b6L,
        0x0caf46c4fd65aL },
      { 0xd0c7792aa8266L,0x66913684bba04L,0xe4b16b0edf454L,0x770f56e65168aL,
        0x014ce9e5704c6L } },
    /* 149 */
    { { 0x45e3e965e8f91L,0xbacb0f2492994L,0x0c8a0a0d3aca1L,0x9a71d31cc70f9L,
        0x01bb708a53e4cL },
      { 0xa9e69558bdd7aL,0x08018a26b1d5cL,0xc9cf1ec734a05L,0x0102b093aa714L,
        0x0f9d126f2da30L } },
    /* 150 */
    { { 0xbca7aaff9563eL,0xfeb49914a0749L,0xf5f1671dd077aL,0xcc69e27a0311bL,
        0x0807afcb9729eL },
      { 0xa9337c9b08b77L,0x85443c7e387f8L,0x76fd8ba86c3a7L,0xcd8c85fafa594L,
        0x0751adcd16568L } },
    /* 151 */
    { { 0xa38b410715c0dL,0x718f7697f78aeL,0x3fbf06dd113eaL,0x743f665eab149L,
        0x029ec44682537L },
      { 0x4719cb50bebbcL,0xbfe45054223d9L,0xd2dedb1399ee5L,0x077d90cd5b3a8L,
        0x0ff9370e392a4L } },
    /* 152 */
    { { 0x2d69bc6b75b65L,0xd5266651c559aL,0xde9d7d24188f8L,0xd01a28a9f33e3L,
        0x09776478ba2a9L },
      { 0x2622d929af2c7L,0x6d4e690923885L,0x89a51e9334f5dL,0x82face6cc7e5aL,
        0x074a6313fac2fL } },
    /* 153 */
    { { 0x4dfddb75f079cL,0x9518e36fbbb2fL,0x7cd36dd85b07cL,0x863d1b6cfcf0eL,
        0x0ab75be150ff4L },
      { 0x367c0173fc9b7L,0x20d2594fd081bL,0x4091236b90a74L,0x59f615fdbf03cL,
        0x04ebeac2e0b44L } },
    /* 154 */
    { { 0xc5fe75c9f2c53L,0x118eae9411eb6L,0x95ac5d8d25220L,0xaffcc8887633fL,
        0x0df99887b2c1bL },
      { 0x8eed2850aaecbL,0x1b01d6a272bb7L,0x1cdbcac9d4918L,0x4058978dd511bL,
        0x027b040a7779fL } },
    /* 155 */
    { { 0x05db7f73b2eb2L,0x088e1b2118904L,0x962327ee0df85L,0xa3f5501b71525L,
        0x0b393dd37e4cfL },
      { 0x30e7b3fd75165L,0xc2bcd33554a12L,0xf7b5022d66344L,0x34196c36f1be0L,
        0x009588c12d046L } },
    /* 156 */
    { { 0x6093f02601c3bL,0xf8cf5c335fe08L,0x94aff28fb0252L,0x648b955cf2808L,
        0x081c879a9db9fL },
      { 0xe687cc6f56c51L,0x693f17618c040L,0x059353bfed471L,0x1bc444f88a419L,
        0x0fa0d48f55fc1L } },
    /* 157 */
    { { 0xe1c9de1608e4dL,0x113582822cbc6L,0x57ec2d7010ddaL,0x67d6f6b7ddc11L,
        0x08ea0e156b6a3L },
      { 0x4e02f2383b3b4L,0x943f01f53ca35L,0xde03ca569966bL,0xb5ac4ff6632b2L,
        0x03f5ab924fa00L } },
    /* 158 */
    { { 0xbb0d959739efbL,0xf4e7ebec0d337L,0x11a67d1c751b0L,0x256e2da52dd64L,
        0x08bc768872b74L },
      { 0xe3b7282d3d253L,0xa1f58d779fa5bL,0x16767bba9f679L,0xf34fa1cac168eL,
        0x0b386f19060fcL } },
    /* 159 */
    { { 0x3c1352fedcfc2L,0x6262f8af0d31fL,0x57288c25396bfL,0x9c4d9a02b4eaeL,
        0x04cb460f71b06L },
      { 0x7b4d35b8095eaL,0x596fc07603ae6L,0x614a16592bbf8L,0x5223e1475f66bL,
        0x052c0d50895efL } },
    /* 160 */
    { { 0xc210e15339848L,0xe870778c8d231L,0x956e170e87a28L,0x9c0b9d1de6616L,
        0x04ac3c9382bb0L },
      { 0xe05516998987dL,0xc4ae09f4d619bL,0xa3f933d8b2376L,0x05f41de0b7651L,
        0x0380d94c7e397L } },
    /* 161 */
    { { 0x355aa81542e75L,0xa1ee01b9b701aL,0x24d708796c724L,0x37af6b3a29776L,
        0x02ce3e171de26L },
      { 0xfeb49f5d5bc1aL,0x7e2777e2b5cfeL,0x513756ca65560L,0x4e4d4feaac2f9L,
        0x02e6cd8520b62L } },
    /* 162 */
    { { 0x5954b8c31c31dL,0x005bf21a0c368L,0x5c79ec968533dL,0x9d540bd7626e7L,
        0x0ca17754742c6L },
      { 0xedafff6d2dbb2L,0xbd174a9d18cc6L,0xa4578e8fd0d8cL,0x2ce6875e8793aL,
        0x0a976a7139cabL } },
    /* 163 */
    { { 0x51f1b93fb353dL,0x8b57fcfa720a6L,0x1b15281d75cabL,0x4999aa88cfa73L,
        0x08720a7170a1fL },
      { 0xe8d37693e1b90L,0x0b16f6dfc38c3L,0x52a8742d345dcL,0x893c8ea8d00abL,
        0x09719ef29c769L } },
    /* 164 */
    { { 0xeed8d58e35909L,0xdc33ddc116820L,0xe2050269366d8L,0x04c1d7f999d06L,
        0x0a5072976e157L },
      { 0xa37eac4e70b2eL,0x576890aa8a002L,0x45b2a5c84dcf6L,0x7725cd71bf186L,
        0x099389c9df7b7L } },
    /* 165 */
    { { 0xc08f27ada7a4bL,0x03fd389366238L,0x66f512c3abe9dL,0x82e46b672e897L,
        0x0a88806aa202cL },
      { 0x2044ad380184eL,0xc4126a8b85660L,0xd844f17a8cb78L,0xdcfe79d670c0aL,
        0x00043bffb4738L } },
    /* 166 */
    { { 0x9b5dc36d5192eL,0xd34590b2af8d5L,0x1601781acf885L,0x486683566d0a1L,
        0x052f3ef01ba6cL },
      { 0x6732a0edcb64dL,0x238068379f398L,0x040f3090a482cL,0x7e7516cbe5fa7L,
        0x03296bd899ef2L } },
    /* 167 */
    { { 0xaba89454d81d7L,0xef51eb9b3c476L,0x1c579869eade7L,0x71e9619a21cd8L,
        0x03b90febfaee5L },
      { 0x3023e5496f7cbL,0xd87fb51bc4939L,0x9beb5ce55be41L,0x0b1803f1dd489L,
        0x06e88069d9f81L } },
    /* 168 */
    { { 0x7ab11b43ea1dbL,0xa95259d292ce3L,0xf84f1860a7ff1L,0xad13851b02218L,
        0x0a7222beadefaL },
      { 0xc78ec2b0a9144L,0x51f2fa59c5a2aL,0x147ce385a0240L,0xc69091d1eca56L,
        0x0be94d523bc2aL } },
    /* 169 */
    { { 0x4945e0b226ce7L,0x47967e8b7072fL,0x5a6c63eb8afd7L,0xc766edea46f18L,
        0x07782defe9be8L },
      { 0xd2aa43db38626L,0x8776f67ad1760L,0x4499cdb460ae7L,0x2e4b341b86fc5L,
        0x003838567a289L } },
    /* 170 */
    { { 0xdaefd79ec1a0fL,0xfdceb39c972d8L,0x8f61a953bbcd6L,0xb420f5575ffc5L,
        0x0dbd986c4adf7L },
      { 0xa881415f39eb7L,0xf5b98d976c81aL,0xf2f717d6ee2fcL,0xbbd05465475dcL,
        0x08e24d3c46860L } },
    /* 171 */
    { { 0xd8e549a587390L,0x4f0cbec588749L,0x25983c612bb19L,0xafc846e07da4bL,
        0x0541a99c4407bL },
      { 0x41692624c8842L,0x2ad86c05ffdb2L,0xf7fcf626044c1L,0x35d1c59d14b44L,
        0x0c0092c49f57dL } },
    /* 172 */
    { { 0xc75c3df2e61efL,0xc82e1b35cad3cL,0x09f29f47e8841L,0x944dc62d30d19L,
        0x075e406347286L },
      { 0x41fc5bbc237d0L,0xf0ec4f01c9e7dL,0x82bd534c9537bL,0x858691c51a162L,
        0x05b7cb658c784L } },
    /* 173 */
    { { 0xa70848a28ead1L,0x08fd3b47f6964L,0x67e5b39802dc5L,0x97a19ae4bfd17L,
        0x07ae13eba8df0L },
      { 0x16ef8eadd384eL,0xd9b6b2ff06fd2L,0xbcdb5f30361a2L,0xe3fd204b98784L,
        0x0787d8074e2a8L } },
    /* 174 */
    { { 0x25d6b757fbb1cL,0xb2ca201debc5eL,0xd2233ffe47bddL,0x84844a55e9a36L,
        0x05c2228199ef2L },
      { 0xd4a8588315250L,0x2b827097c1773L,0xef5d33f21b21aL,0xf2b0ab7c4ea1dL,
        0x0e45d37abbaf0L } },
    /* 175 */
    { { 0xf1e3428511c8aL,0xc8bdca6cd3d2dL,0x27c39a7ebb229L,0xb9d3578a71a76L,
        0x0ed7bc12284dfL },
      { 0x2a6df93dea561L,0x8dd48f0ed1cf2L,0xbad23e85443f1L,0x6d27d8b861405L,
        0x0aac97cc945caL } },
    /* 176 */
    { { 0x4ea74a16bd00aL,0xadf5c0bcc1eb5L,0xf9bfc06d839e9L,0xdc4e092bb7f11L,
        0x0318f97b31163L },
      { 0x0c5bec30d7138L,0x23abc30220eccL,0x022360644e8dfL,0xff4d2bb7972fbL,
        0x0fa41faa19a84L } },
    /* 177 */
    { { 0x2d974a6642269L,0xce9bb783bd440L,0x941e60bc81814L,0xe9e2398d38e47L,
        0x038bb6b2c1d26L },
      { 0xe4a256a577f87L,0x53dc11fe1cc64L,0x22807288b52d2L,0x01a5ff336abf6L,
        0x094dd0905ce76L } },
    /* 178 */
    { { 0xcf7dcde93f92aL,0xcb89b5f315156L,0x995e750a01333L,0x2ae902404df9cL,
        0x092077867d25cL },
      { 0x71e010bf39d44L,0x2096bb53d7e24L,0xc9c3d8f5f2c90L,0xeb514c44b7b35L,
        0x081e8428bd29bL } },
    /* 179 */
    { { 0x9c2bac477199fL,0xee6b5ecdd96ddL,0xe40fd0e8cb8eeL,0xa4b18af7db3feL,
        0x01b94ab62dbbfL },
      { 0x0d8b3ce47f143L,0xfc63f4616344fL,0xc59938351e623L,0x90eef18f270fcL,
        0x006a38e280555L } },
    /* 180 */
    { { 0xb0139b3355b49L,0x60b4ebf99b2e5L,0x269f3dc20e265L,0xd4f8c08ffa6bdL,
        0x0a7b36c2083d9L },
      { 0x15c3a1b3e8830L,0xe1a89f9c0b64dL,0x2d16930d5fceaL,0x2a20cfeee4a2eL,
        0x0be54c6b4a282L } },
    /* 181 */
    { { 0xdb3df8d91167cL,0x79e7a6625ed6cL,0x46ac7f4517c3fL,0x22bb7105648f3L,
        0x0bf30a5abeae0L },
      { 0x785be93828a68L,0x327f3ef0368e7L,0x92146b25161c3L,0xd13ae11b5feb5L,
        0x0d1c820de2732L } },
    /* 182 */
    { { 0xe13479038b363L,0x546b05e519043L,0x026cad158c11fL,0x8da34fe57abe6L,
        0x0b7d17bed68a1L },
      { 0xa5891e29c2559L,0x765bfffd8444cL,0x4e469484f7a03L,0xcc64498de4af7L,
        0x03997fd5e6412L } },
    /* 183 */
    { { 0x746828bd61507L,0xd534a64d2af20L,0xa8a15e329e132L,0x13e8ffeddfb08L,
        0x00eeb89293c6cL },
      { 0x69a3ea7e259f8L,0xe6d13e7e67e9bL,0xd1fa685ce1db7L,0xb6ef277318f6aL,
        0x0228916f8c922L } },
    /* 184 */
    { { 0xae25b0a12ab5bL,0x1f957bc136959L,0x16e2b0ccc1117L,0x097e8058429edL,
        0x0ec05ad1d6e93L },
      { 0xba5beac3f3708L,0x3530b59d77157L,0x18234e531baf9L,0x1b3747b552371L,
        0x07d3141567ff1L } },
    /* 185 */
    { { 0x9c05cf6dfefabL,0x68dcb377077bdL,0xa38bb95be2f22L,0xd7a3e53ead973L,
        0x0e9ce66fc9bc1L },
      { 0xa15766f6a02a1L,0xdf60e600ed75aL,0x8cdc1b938c087L,0x0651f8947f346L,
        0x0d9650b017228L } },
    /* 186 */
    { { 0xb4c4a5a057e60L,0xbe8def25e4504L,0x7c1ccbdcbccc3L,0xb7a2a63532081L,
        0x014d6699a804eL },
      { 0xa8415db1f411aL,0x0bf80d769c2c8L,0xc2f77ad09fbafL,0x598ab4deef901L,
        0x06f4c68410d43L } },
    /* 187 */
    { { 0x6df4e96c24a96L,0x85fcbd99a3872L,0xb2ae30a534dbcL,0x9abb3c466ef28L,
        0x04c4350fd6118L },
      { 0x7f716f855b8daL,0x94463c38a1296L,0xae9334341a423L,0x18b5c37e1413eL,
        0x0a726d2425a31L } },
    /* 188 */
    { { 0x6b3ee948c1086L,0x3dcbd3a2e1daeL,0x3d022f3f1de50L,0xf3923f35ed3f0L,
        0x013639e82cc6cL },
      { 0x938fbcdafaa86L,0xfb2654a2589acL,0x5051329f45bc5L,0x35a31963b26e4L,
        0x0ca9365e1c1a3L } },
    /* 189 */
    { { 0x5ac754c3b2d20L,0x17904e241b361L,0xc9d071d742a54L,0x72a5b08521c4cL,
        0x09ce29c34970bL },
      { 0x81f736d3e0ad6L,0x9ef2f8434c8ccL,0xce862d98060daL,0xaf9835ed1d1a6L,
        0x048c4abd7ab42L } },
    /* 190 */
    { { 0x1b0cc40c7485aL,0xbbe5274dbfd22L,0x263d2e8ead455L,0x33cb493c76989L,
        0x078017c32f67bL },
      { 0x35769930cb5eeL,0x940c408ed2b9dL,0x72f1a4dc0d14eL,0x1c04f8b7bf552L,
        0x053cd0454de5cL } },
    /* 191 */
    { { 0x585fa5d28ccacL,0x56005b746ebcdL,0xd0123aa5f823eL,0xfa8f7c79f0a1cL,
        0x0eea465c1d3d7L },
      { 0x0659f0551803bL,0x9f7ce6af70781L,0x9288e706c0b59L,0x91934195a7702L,
        0x01b6e42a47ae6L } },
    /* 192 */
    { { 0x0937cf67d04c3L,0xe289eeb8112e8L,0x2594d601e312bL,0xbd3d56b5d8879L,
        0x00224da14187fL },
      { 0xbb8630c5fe36fL,0x604ef51f5f87aL,0x3b429ec580f3cL,0xff33964fb1bfbL,
        0x060838ef042bfL } },
    /* 193 */
    { { 0xcb2f27e0bbe99L,0xf304aa39ee432L,0xfa939037bda44L,0x16435f497c7a9L,
        0x0636eb2022d33L },
      { 0xd0e6193ae00aaL,0xfe31ae6d2ffcfL,0xf93901c875a00L,0x8bacf43658a29L,
        0x08844eeb63921L } },
    /* 194 */
    { { 0x171d26b3bae58L,0x7117e39f3e114L,0x1a8eada7db3dfL,0x789ecd37bc7f8L,
        0x027ba83dc51fbL },
      { 0xf439ffbf54de5L,0x0bb5fe1a71a7dL,0xb297a48727703L,0xa4ab42ee8e35dL,
        0x0adb62d3487f3L } },
    /* 195 */
    { { 0x168a2a175df2aL,0x4f618c32e99b1L,0x46b0916082aa0L,0xc8b2c9e4f2e71L,
        0x0b990fd7675e7L },
      { 0x9d96b4df37313L,0x79d0b40789082L,0x80877111c2055L,0xd18d66c9ae4a7L,
        0x081707ef94d10L } },
    /* 196 */
    { { 0x7cab203d6ff96L,0xfc0d84336097dL,0x042db4b5b851bL,0xaa5c268823c4dL,
        0x03792daead5a8L },
      { 0x18865941afa0bL,0x4142d83671528L,0xbe4e0a7f3e9e7L,0x01ba17c825275L,
        0x05abd635e94b0L } },
    /* 197 */
    { { 0xfa84e0ac4927cL,0x35a7c8cf23727L,0xadca0dfe38860L,0xb610a4bcd5ea4L,
        0x05995bf21846aL },
      { 0xf860b829dfa33L,0xae958fc18be90L,0x8630366caafe2L,0x411e9b3baf447L,
        0x044c32ca2d483L } },
    /* 198 */
    { { 0xa97f1e40ed80cL,0xb131d2ca82a74L,0xc2d6ad95f938cL,0xa54c53f2124b7L,
        0x01f2162fb8082L },
      { 0x67cc5720b173eL,0x66085f12f97e4L,0xc9d65dc40e8a6L,0x07c98cebc20e4L,
        0x08f1d402bc3e9L } },
    /* 199 */
    { { 0x92f9cfbc4058aL,0xb6292f56704f5L,0xc1d8c57b15e14L,0xdbf9c55cfe37bL,
        0x0b1980f43926eL },
      { 0x33e0932c76b09L,0x9d33b07f7898cL,0x63bb4611df527L,0x8e456f08ead48L,
        0x02828ad9b3744L } },
    /* 200 */
    { { 0x722c4c4cf4ac5L,0x3fdde64afb696L,0x0890832f5ac1aL,0xb3900551baa2eL,
        0x04973f1275a14L },
      { 0xd8335322eac5dL,0xf50bd9b568e59L,0x25883935e07eeL,0x8ac7ab36720faL,
        0x06dac8ed0db16L } },
    /* 201 */
    { { 0x545aeeda835efL,0xd21d10ed51f7bL,0x3741b094aa113L,0xde4c035a65e01L,
        0x04b23ef5920b9L },
      { 0xbb6803c4c7341L,0x6d3f58bc37e82L,0x51e3ee8d45770L,0x9a4e73527863aL,
        0x04dd71534ddf4L } },
    /* 202 */
    { { 0x4467295476cd9L,0x2fe31a725bbf9L,0xc4b67e0648d07L,0x4dbb1441c8b8fL,
        0x0fd3170002f4aL },
      { 0x43ff48995d0e1L,0xd10ef729aa1cbL,0x179898276e695L,0xf365e0d5f9764L,
        0x014fac58c9569L } },
    /* 203 */
    { { 0xa0065f312ae18L,0xc0fcc93fc9ad9L,0xa7d284651958dL,0xda50d9a142408L,
        0x0ed7c765136abL },
      { 0x70f1a25d4abbcL,0xf3f1a113ea462L,0xb51952f9b5dd8L,0x9f53c609b0755L,
        0x0fefcb7f74d2eL } },
    /* 204 */
    { { 0x9497aba119185L,0x30aac45ba4bd0L,0xa521179d54e8cL,0xd80b492479deaL,
        0x01801a57e87e0L },
      { 0xd3f8dfcafffb0L,0x0bae255240073L,0xb5fdfbc6cf33cL,0x1064781d763b5L,
        0x09f8fc11e1eadL } },
    /* 205 */
    { { 0x3a1715e69544cL,0x67f04b7813158L,0x78a4c320eaf85L,0x69a91e22a8fd2L,
        0x0a9d3809d3d3aL },
      { 0xc2c2c59a2da3bL,0xf61895c847936L,0x3d5086938ccbcL,0x8ef75e65244e6L,
        0x03006b9aee117L } },
    /* 206 */
    { { 0x1f2b0c9eead28L,0x5d89f4dfbc0bbL,0x2ce89397eef63L,0xf761074757fdbL,
        0x00ab85fd745f8L },
      { 0xa7c933e5b4549L,0x5c97922f21ecdL,0x43b80404be2bbL,0x42c2261a1274bL,
        0x0b122d67511e9L } },
    /* 207 */
    { { 0x607be66a5ae7aL,0xfa76adcbe33beL,0xeb6e5c501e703L,0xbaecaf9043014L,
        0x09f599dc1097dL },
      { 0x5b7180ff250edL,0x74349a20dc6d7L,0x0b227a38eb915L,0x4b78425605a41L,
        0x07d5528e08a29L } },
    /* 208 */
    { { 0x58f6620c26defL,0xea582b2d1ef0fL,0x1ce3881025585L,0x1730fbe7d79b0L,
        0x028ccea01303fL },
      { 0xabcd179644ba5L,0xe806fff0b8d1dL,0x6b3e17b1fc643L,0x13bfa60a76fc6L,
        0x0c18baf48a1d0L } },
    /* 209 */
    { { 0x638c85dc4216dL,0x67206142ac34eL,0x5f5064a00c010L,0x596bd453a1719L,
        0x09def809db7a9L },
      { 0x8642e67ab8d2cL,0x336237a2b641eL,0x4c4218bb42404L,0x8ce57d506a6d6L,
        0x00357f8b06880L } },
    /* 210 */
    { { 0xdbe644cd2cc88L,0x8df0b8f39d8e9L,0xd30a0c8cc61c2L,0x98874a309874cL,
        0x0e4a01add1b48L },
      { 0x1eeacf57cd8f9L,0x3ebd594c482edL,0xbd2f7871b767dL,0xcc30a7295c717L,
        0x0466d7d79ce10L } },
    /* 211 */
    { { 0x318929dada2c7L,0xc38f9aa27d47dL,0x20a59e14fa0a6L,0xad1a90e4fd288L,
        0x0c672a522451eL },
      { 0x07cc85d86b655L,0x3bf9ad4af1306L,0x71172a6f0235dL,0x751399a086805L,
        0x05e3d64faf2a6L } },
    /* 212 */
    { { 0x410c79b3b4416L,0x85eab26d99aa6L,0xb656a74cd8fcfL,0x42fc5ebff74adL,
        0x06c8a7a95eb8eL },
      { 0x60ba7b02a63bdL,0x038b8f004710cL,0x12d90b06b2f23L,0xca918c6c37383L,
        0x0348ae422ad82L } },
    /* 213 */
    { { 0x746635ccda2fbL,0xa18e0726d27f4L,0x92b1f2022accaL,0x2d2e85adf7824L,
        0x0c1074de0d9efL },
      { 0x3ce44ae9a65b3L,0xac05d7151bfcfL,0xe6a9788fd71e4L,0x4ffcd4711f50cL,
        0x0fbadfbdbc9e5L } },
    /* 214 */
    { { 0x3f1cd20a99363L,0x8f6cf22775171L,0x4d359b2b91565L,0x6fcd968175cd2L,
        0x0b7f976b48371L },
      { 0x8e24d5d6dbf74L,0xfd71c3af36575L,0x243dfe38d23baL,0xc80548f477600L,
        0x0f4d41b2ecafcL } },
    /* 215 */
    { { 0x1cf28fdabd48dL,0x3632c078a451fL,0x17146e9ce81beL,0x0f106ace29741L,
        0x0180824eae016L },
      { 0x7698b66e58358L,0x52ce6ca358038L,0xe41e6c5635687L,0x6d2582380e345L,
        0x067e5f63983cfL } },
    /* 216 */
    { { 0xccb8dcf4899efL,0xf09ebb44c0f89L,0x2598ec9949015L,0x1fc6546f9276bL,
        0x09fef789a04c1L },
      { 0x67ecf53d2a071L,0x7fa4519b096d3L,0x11e2eefb10e1aL,0x4e20ca6b3fb06L,
        0x0bc80c181a99cL } },
    /* 217 */
    { { 0x536f8e5eb82e6L,0xc7f56cb920972L,0x0b5da5e1a484fL,0xdf10c78e21715L,
        0x049270e629f8cL },
      { 0x9b7bbea6b50adL,0xc1a2388ffc1a3L,0x107197b9a0284L,0x2f7f5403eb178L,
        0x0d2ee52f96137L } },
    /* 218 */
    { { 0xcd28588e0362aL,0xa78fa5d94dd37L,0x434a526442fa8L,0xb733aff836e5aL,
        0x0dfb478bee5abL },
      { 0xf1ce7673eede6L,0xd42b5b2f04a91L,0x530da2fa5390aL,0x473a5e66f7bf5L,
        0x0d9a140b408dfL } },
    /* 219 */
    { { 0x221b56e8ea498L,0x293563ee090e0L,0x35d2ade623478L,0x4b1ae06b83913L,
        0x0760c058d623fL },
      { 0x9b58cc198aa79L,0xd2f07aba7f0b8L,0xde2556af74890L,0x04094e204110fL,
        0x07141982d8f19L } },
    /* 220 */
    { { 0xa0e334d4b0f45L,0x38392a94e16f0L,0x3c61d5ed9280bL,0x4e473af324c6bL,
        0x03af9d1ce89d5L },
      { 0xf798120930371L,0x4c21c17097fd8L,0xc42309beda266L,0x7dd60e9545dcdL,
        0x0b1f815c37395L } },
    /* 221 */
    { { 0xaa78e89fec44aL,0x473caa4caf84fL,0x1b6a624c8c2aeL,0xf052691c807dcL,
        0x0a41aed141543L },
      { 0x353997d5ffe04L,0xdf625b6e20424L,0x78177758bacb2L,0x60ef85d660be8L,
        0x0d6e9c1dd86fbL } },
    /* 222 */
    { { 0x2e97ec6853264L,0xb7e2304a0b3aaL,0x8eae9be771533L,0xf8c21b912bb7bL,
        0x09c9c6e10ae9bL },
      { 0x09a59e030b74cL,0x4d6a631e90a23L,0x49b79f24ed749L,0x61b689f44b23aL,
        0x0566bd59640faL } },
    /* 223 */
    { { 0xc0118c18061f3L,0xd37c83fc70066L,0x7273245190b25L,0x345ef05fc8e02L,
        0x0cf2c7390f525L },
      { 0xbceb410eb30cfL,0xba0d77703aa09L,0x50ff255cfd2ebL,0x0979e842c43a1L,
        0x002f517558aa2L } },
    /* 224 */
    { { 0xef794addb7d07L,0x4224455500396L,0x78aa3ce0b4fc7L,0xd97dfaff8eaccL,
        0x014e9ada5e8d4L },
      { 0x480a12f7079e2L,0xcde4b0800edaaL,0x838157d45baa3L,0x9ae801765e2d7L,
        0x0a0ad4fab8e9dL } },
    /* 225 */
    { { 0xb76214a653618L,0x3c31eaaa5f0bfL,0x4949d5e187281L,0xed1e1553e7374L,
        0x0bcd530b86e56L },
      { 0xbe85332e9c47bL,0xfeb50059ab169L,0x92bfbb4dc2776L,0x341dcdba97611L,
        0x0909283cf6979L } },
    /* 226 */
    { { 0x0032476e81a13L,0x996217123967bL,0x32e19d69bee1aL,0x549a08ed361bdL,
        0x035eeb7c9ace1L },
      { 0x0ae5a7e4e5bdcL,0xd3b6ceec6e128L,0xe266bc12dcd2cL,0xe86452e4224c6L,
        0x09a8b2cf4448aL } },
    /* 227 */
    { { 0x71bf209d03b59L,0xa3b65af2abf64L,0xbd5eec9c90e62L,0x1379ff7ff168eL,
        0x06bdb60f4d449L },
      { 0xafebc8a55bc30L,0x1610097fe0dadL,0xc1e3bddc79eadL,0x08a942e197414L,
        0x001ec3cfd94baL } },
    /* 228 */
    { { 0x277ebdc9485c2L,0x7922fb10c7ba6L,0x0a28d8a48cc9aL,0x64f64f61d60f7L,
        0x0d1acb1c04754L },
      { 0x902b126f36612L,0x4ee0618d8bd26L,0x08357ee59c3a4L,0x26c24df8a8133L,
        0x07dcd079d4056L } },
    /* 229 */
    { { 0x7d4d3f05a4b48L,0x52372307725ceL,0x12a915aadcd29L,0x19b8d18f79718L,
        0x00bf53589377dL },
      { 0xcd95a6c68ea73L,0xca823a584d35eL,0x473a723c7f3bbL,0x86fc9fb674c6fL,
        0x0d28be4d9e166L } },
    /* 230 */
    { { 0xb990638fa8e4bL,0x6e893fd8fc5d2L,0x36fb6fc559f18L,0x88ce3a6de2aa4L,
        0x0d76007aa510fL },
      { 0x0aab6523a4988L,0x4474dd02732d1L,0x3407278b455cfL,0xbb017f467082aL,
        0x0f2b52f68b303L } },
    /* 231 */
    { { 0x7eafa9835b4caL,0xfcbb669cbc0d5L,0x66431982d2232L,0xed3a8eeeb680cL,
        0x0d8dbe98ecc5aL },
      { 0x9be3fc5a02709L,0xe5f5ba1fa8cbaL,0x10ea85230be68L,0x9705febd43cdfL,
        0x0e01593a3ee55L } },
    /* 232 */
    { { 0x5af50ea75a0a6L,0xac57858033d3eL,0x0176406512226L,0xef066fe6d50fdL,
        0x0afec07b1aeb8L },
      { 0x9956780bb0a31L,0xcc37309aae7fbL,0x1abf3896f1af3L,0xbfdd9153a15a0L,
        0x0a71b93546e2dL } },
    /* 233 */
    { { 0xe12e018f593d2L,0x28a078122bbf8L,0xba4f2add1a904L,0x23d9150505db0L,
        0x053a2005c6285L },
      { 0x8b639e7f2b935L,0x5ac182961a07cL,0x518ca2c2bff97L,0x8e3d86bceea77L,
        0x0bf47d19b3d58L } },
    /* 234 */
    { { 0x967a7dd7665d5L,0x572f2f4de5672L,0x0d4903f4e3030L,0xa1b6144005ae8L,
        0x0001c2c7f39c9L },
      { 0xa801469efc6d6L,0xaa7bc7a724143L,0x78150a4c810bdL,0xb99b5f65670baL,
        0x0fdadf8e786ffL } },
    /* 235 */
    { { 0x8cb88ffc00785L,0x913b48eb67fd3L,0xf368fbc77fa75L,0x3c940454d055bL,
        0x03a838e4d5aa4L },
      { 0x663293e97bb9aL,0x63441d94d9561L,0xadb2a839eb933L,0x1da3515591a60L,
        0x03cdb8257873eL } },
    /* 236 */
    { { 0x140a97de77eabL,0x0d41648109137L,0xeb1d0dff7e1c5L,0x7fba762dcad2cL,
        0x05a60cc89f1f5L },
      { 0x3638240d45673L,0x195913c65580bL,0xd64b7411b82beL,0x8fc0057284b8dL,
        0x0922ff56fdbfdL } },
    /* 237 */
    { { 0x65deec9a129a1L,0x57cc284e041b2L,0xebfbe3ca5b1ceL,0xcd6204380c46cL,
        0x072919a7df6c5L },
      { 0xf453a8fb90f9aL,0x0b88e4031b298L,0x96f1856d719c0L,0x089ae32c0e777L,
        0x05e7917803624L } },
    /* 238 */
    { { 0x6ec557f63cdfbL,0x71f1cae4fd5c1L,0x60597ca8e6a35L,0x2fabfce26bea5L,
        0x04e0a5371e24cL },
      { 0xa40d3a5765357L,0x440d73a2b4276L,0x1d11a323c89afL,0x04eeb8f370ae4L,
        0x0f5ff7818d566L } },
    /* 239 */
    { { 0x3e3fe1a09df21L,0x8ee66e8e47fbfL,0x9c8901526d5d2L,0x5e642096bd0a2L,
        0x0e41df0e9533fL },
      { 0xfda40b3ba9e3fL,0xeb2604d895305L,0xf0367c7f2340cL,0x155f0866e1927L,
        0x08edd7d6eac4fL } },
    /* 240 */
    { { 0x1dc0e0bfc8ff3L,0x2be936f42fc9aL,0xca381ef14efd8L,0xee9667016f7ccL,
        0x01432c1caed8aL },
      { 0x8482970b23c26L,0x730735b273ec6L,0xaef0f5aa64fe8L,0xd2c6e389f6e5eL,
        0x0caef480b5ac8L } },
    /* 241 */
    { { 0x5c97875315922L,0x713063cca5524L,0x64ef2cbd82951L,0xe236f3ce60d0bL,
        0x0d0ba177e8efaL },
      { 0x9ae8fb1b3af60L,0xe53d2da20e53aL,0xf9eef281a796aL,0xae1601d63605dL,
        0x0f31c957c1c54L } },
    /* 242 */
    { { 0x58d5249cc4597L,0xb0bae0a028c0fL,0x34a814adc5015L,0x7c3aefc5fc557L,
        0x0013404cb96e1L },
      { 0xe2585c9a824bfL,0x5e001eaed7b29L,0x1ef68acd59318L,0x3e6c8d6ee6826L,
        0x06f377c4b9193L } },
    /* 243 */
    { { 0x3bad1a8333fd2L,0x025a2a95b89f9L,0xaf75acea89302L,0x9506211e5037eL,
        0x06dba3e4ed2d0L },
      { 0xef98cd04399cdL,0x6ee6b73adea48L,0x17ecaf31811c6L,0xf4a772f60752cL,
        0x0f13cf3423becL } },
    /* 244 */
    { { 0xb9ec0a919e2ebL,0x95f62c0f68ceeL,0xaba229983a9a1L,0xbad3cfba3bb67L,
        0x0c83fa9a9274bL },
      { 0xd1b0b62fa1ce0L,0xf53418efbf0d7L,0x2706f04e58b60L,0x2683bfa8ef9e5L,
        0x0b49d70f45d70L } },
    /* 245 */
    { { 0xc7510fad5513bL,0xecb1751e2d914L,0x9fb9d5905f32eL,0xf1cf6d850418dL,
        0x059cfadbb0c30L },
      { 0x7ac2355cb7fd6L,0xb8820426a3e16L,0x0a78864249367L,0x4b67eaeec58c9L,
        0x05babf362354aL } },
    /* 246 */
    { { 0x981d1ee424865L,0x78f2e5577f37cL,0x9e0c0588b0028L,0xc8f0702970f1bL,
        0x06188c6a79026L },
      { 0x9a19bd0f244daL,0x5cfb08087306fL,0xf2136371eccedL,0xb9d935470f9b9L,
        0x0993fe475df50L } },
    /* 247 */
    { { 0x31cdf9b2c3609L,0xc02c46d4ea68eL,0xa77510184eb19L,0x616b7ac9ec1a9L,
        0x081f764664c80L },
      { 0xc2a5a75fbe978L,0xd3f183b3561d7L,0x01dd2bf6743feL,0x060d838d1f045L,
        0x0564a812a5fe9L } },
    /* 248 */
    { { 0xa64f4fa817d1dL,0x44bea82e0f7a5L,0xd57f9aa55f968L,0x1d6cb5ff5a0fcL,
        0x0226bf3cf00e5L },
      { 0x1a9f92f2833cfL,0x5a4f4f89a8d6dL,0xf3f7f7720a0a3L,0x783611536c498L,
        0x068779f47ff25L } },
    /* 249 */
    { { 0x0c1c173043d08L,0x741fc020fa79bL,0xa6d26d0a54467L,0x2e0bd3767e289L,
        0x097bcb0d1eb09L },
      { 0x6eaa8f32ed3c3L,0x51b281bc482abL,0xfa178f3c8a4f1L,0x46554d1bf4f3bL,
        0x0a872ffe80a78L } },
    /* 250 */
    { { 0xb7935a32b2086L,0x0e8160f486b1aL,0xb6ae6bee1eb71L,0xa36a9bd0cd913L,
        0x002812bfcb732L },
      { 0xfd7cacf605318L,0x50fdfd6d1da63L,0x102d619646e5dL,0x96afa1d683982L,
        0x007391cc9fe53L } },
    /* 251 */
    { { 0x157f08b80d02bL,0xd162877f7fc50L,0x8d542ae6b8333L,0x2a087aca1af87L,
        0x0355d2adc7e6dL },
      { 0xf335a287386e1L,0x94f8e43275b41L,0x79989eafd272aL,0x3a79286ca2cdeL,
        0x03dc2b1e37c2aL } },
    /* 252 */
    { { 0x9d21c04581352L,0x25376782bed68L,0xfed701f0a00c8L,0x846b203bd5909L,
        0x0c47869103ccdL },
      { 0xa770824c768edL,0x026841f6575dbL,0xaccce0e72feeaL,0x4d3273313ed56L,
        0x0ccc42968d5bbL } },
    /* 253 */
    { { 0x50de13d7620b9L,0x8a5992a56a94eL,0x75487c9d89a5cL,0x71cfdc0076406L,
        0x0e147eb42aa48L },
      { 0xab4eeacf3ae46L,0xfb50350fbe274L,0x8c840eafd4936L,0x96e3df2afe474L,
        0x0239ac047080eL } },
    /* 254 */
    { { 0xd1f352bfee8d4L,0xcffa7b0fec481L,0xce9af3cce80b5L,0xe59d105c4c9e2L,
        0x0c55fa1a3f5f7L },
      { 0x6f14e8257c227L,0x3f342be00b318L,0xa904fb2c5b165L,0xb69909afc998aL,
        0x0094cd99cd4f4L } },
    /* 255 */
    { { 0x81c84d703bebaL,0x5032ceb2918a9L,0x3bd49ec8631d1L,0xad33a445f2c9eL,
        0x0b90a30b642abL },
      { 0x5404fb4a5abf9L,0xc375db7603b46L,0xa35d89f004750L,0x24f76f9a42cccL,
        0x0019f8b9a1b79L } },
};

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_256_ecc_mulmod_base_5(sp_point* r, const sp_digit* k,
        int map, void* heap)
{
    return sp_256_ecc_mulmod_stripe_5(r, &p256_base, p256_table,
                                      k, map, heap);
}

#endif

/* Multiply the base point of P256 by the scalar and return the result.
 * If map is true then convert result to affine co-ordinates.
 *
 * km    Scalar to multiply by.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_base_256(mp_int* km, ecc_point* r, int map, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point p;
    sp_digit kd[5];
#endif
    sp_point* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_ecc_point_new(heap, p, point);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, km);

            err = sp_256_ecc_mulmod_base_5(point, k, map, heap);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, r);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(point, 0, heap);

    return err;
}

#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                                        defined(HAVE_ECC_VERIFY)
/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_256_iszero_5(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4]) == 0;
}

#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN || HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
/* Add 1 to a. (a = a + 1)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_256_add_one_5(sp_digit* a)
{
    a[0]++;
    sp_256_norm_5(a);
}

/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_256_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 44U) {
            r[j] &= 0xfffffffffffffL;
            s = 52U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * rng  Random number generator.
 * k    Scalar value.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
static int sp_256_ecc_gen_k_5(WC_RNG* rng, sp_digit* k)
{
    int err;
    byte buf[32];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_256_from_bin(k, 5, buf, (int)sizeof(buf));
            if (sp_256_cmp_5(k, p256_order2) < 0) {
                sp_256_add_one_5(k);
                break;
            }
        }
    }
    while (err == 0);

    return err;
}

/* Makes a random EC key pair.
 *
 * rng   Random number generator.
 * priv  Generated private value.
 * pub   Generated public point.
 * heap  Heap to use for allocation.
 * returns ECC_INF_E when the point does not have the correct order, RNG
 * failures, MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_make_key_256(WC_RNG* rng, mp_int* priv, ecc_point* pub, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point p;
    sp_digit kd[5];
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point inf;
#endif
#endif
    sp_point* point;
    sp_digit* k = NULL;
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point* infinity;
#endif
    int err;

    (void)heap;

    err = sp_ecc_point_new(heap, p, point);
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, inf, infinity);
    }
#endif
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        err = sp_256_ecc_gen_k_5(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_base_5(point, k, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_5(infinity, point, p256_order, 1, NULL);
    }
    if (err == MP_OKAY) {
        if ((sp_256_iszero_5(point->x) == 0) || (sp_256_iszero_5(point->y) == 0)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_256_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_256_point_to_ecc_point_5(point, pub);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_ecc_point_free(infinity, 1, heap);
#endif
    sp_ecc_point_free(point, 1, heap);

    return err;
}

#ifdef HAVE_ECC_DHE
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 32
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_256_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<4; i++) {
        r[i+1] += r[i] >> 52;
        r[i] &= 0xfffffffffffffL;
    }
    j = 256 / 8 - 1;
    a[j] = 0;
    for (i=0; i<5 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); b += 8 - s; /*lint !e9033*/
        if (j < 0) {
            break;
        }
        while (b < 52) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 52);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

/* Multiply the point by the scalar and serialize the X ordinate.
 * The number is 0 padded to maximum size on output.
 *
 * priv    Scalar to multiply the point by.
 * pub     Point to multiply.
 * out     Buffer to hold X ordinate.
 * outLen  On entry, size of the buffer in bytes.
 *         On exit, length of data in buffer in bytes.
 * heap    Heap to use for allocation.
 * returns BUFFER_E if the buffer is to small for output size,
 * MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_secret_gen_256(mp_int* priv, ecc_point* pub, byte* out,
                          word32* outLen, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point p;
    sp_digit kd[5];
#endif
    sp_point* point = NULL;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    if (*outLen < 32U) {
        err = BUFFER_E;
    }

    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, p, point);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(k, 5, priv);
        sp_256_point_from_ecc_point_5(point, pub);
            err = sp_256_ecc_mulmod_5(point, point, k, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_256_to_bin(point->x, out);
        *outLen = 32;
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(point, 0, heap);

    return err;
}
#endif /* HAVE_ECC_DHE */

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_256_mul_d_5(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 5; i++) {
        t += tb * a[i];
        r[i] = t & 0xfffffffffffffL;
        t >>= 52;
    }
    r[5] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[5];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    r[ 0] =                           (t[ 0] & 0xfffffffffffffL);
    r[ 1] = (sp_digit)(t[ 0] >> 52) + (t[ 1] & 0xfffffffffffffL);
    r[ 2] = (sp_digit)(t[ 1] >> 52) + (t[ 2] & 0xfffffffffffffL);
    r[ 3] = (sp_digit)(t[ 2] >> 52) + (t[ 3] & 0xfffffffffffffL);
    r[ 4] = (sp_digit)(t[ 3] >> 52) + (t[ 4] & 0xfffffffffffffL);
    r[ 5] = (sp_digit)(t[ 4] >> 52);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_256_div_word_5(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t, dv;
    int128_t t0, t1;

    /* dv has 27 bits. */
    dv = (div >> 25) + 1;
    /* All 52 bits from d1 and top 11 bits from d0. */
    d = (d1 << 11) | (d0 >> 41);
    r = d / dv;
    d -= r * dv;
    /* Up to 36 bits in r */
    /* Next 16 bits from d0. */
    d <<= 16;
    r <<= 16;
    d |= (d0 >> 25) & ((1 << 16) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 52 bits in r */

    /* Handle rounding error with dv - top part */
    t0 = ((int128_t)d1 << 52) + d0;
    t1 = (int128_t)r * dv;
    t1 = t0 - t1;
    t = (sp_digit)(t1 >> 25) / dv;
    r += t;

    /* Handle rounding error with dv - bottom 64 bits */
    t1 = (sp_digit)t0 - (r * dv);
    t = (sp_digit)t1 / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_256_div_5(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* td;
#else
    sp_digit t1d[10], t2d[5 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 5 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = td;
        t2 = td + 2 * 5;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[4];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 5U);
        for (i=4; i>=0; i--) {
            t1[5 + i] += t1[5 + i - 1] >> 52;
            t1[5 + i - 1] &= 0xfffffffffffffL;
#ifndef WOLFSSL_SP_DIV_64
            d1 = t1[5 + i];
            d1 <<= 52;
            d1 += t1[5 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_256_div_word_5(t1[5 + i], t1[5 + i - 1], dv);
#endif

            sp_256_mul_d_5(t2, d, r1);
            (void)sp_256_sub_5(&t1[i], &t1[i], t2);
            t1[5 + i] -= t2[5];
            t1[5 + i] += t1[5 + i - 1] >> 52;
            t1[5 + i - 1] &= 0xfffffffffffffL;
            r1 = (((-t1[5 + i]) << 52) - t1[5 + i - 1]) / dv;
            r1++;
            sp_256_mul_d_5(t2, d, r1);
            (void)sp_256_add_5(&t1[i], &t1[i], t2);
            t1[5 + i] += t1[5 + i - 1] >> 52;
            t1[5 + i - 1] &= 0xfffffffffffffL;
        }
        t1[5 - 1] += t1[5 - 2] >> 52;
        t1[5 - 2] &= 0xfffffffffffffL;
        d1 = t1[5 - 1];
        r1 = (sp_digit)(d1 / dv);

        sp_256_mul_d_5(t2, d, r1);
        (void)sp_256_sub_5(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 5U);
        for (i=0; i<3; i++) {
            r[i+1] += r[i] >> 52;
            r[i] &= 0xfffffffffffffL;
        }
        sp_256_cond_add_5(r, r, d, 0 - ((r[4] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_256_mod_5(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_256_div_5(a, m, NULL, r);
}

#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#ifdef WOLFSSL_SP_SMALL
/* Order-2 for the P256 curve. */
static const uint64_t p256_order_2[4] = {
    0xf3b9cac2fc63254fU,0xbce6faada7179e84U,0xffffffffffffffffU,
    0xffffffff00000000U
};
#else
/* The low half of the order-2 of the P256 curve. */
static const uint64_t p256_order_low[2] = {
    0xf3b9cac2fc63254fU,0xbce6faada7179e84U
};
#endif /* WOLFSSL_SP_SMALL */

/* Multiply two number mod the order of P256 curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_256_mont_mul_order_5(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_256_mul_5(r, a, b);
    sp_256_mont_reduce_order_5(r, p256_order, p256_mp_order);
}

/* Square number mod the order of P256 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_order_5(sp_digit* r, const sp_digit* a)
{
    sp_256_sqr_5(r, a);
    sp_256_mont_reduce_order_5(r, p256_order, p256_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P256 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_256_mont_sqr_n_order_5(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_256_mont_sqr_order_5(r, a);
    for (i=1; i<n; i++) {
        sp_256_mont_sqr_order_5(r, r);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the order of the P256 curve.
 * (r = 1 / a mod order)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_256_mont_inv_order_5(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 5);
    for (i=254; i>=0; i--) {
        sp_256_mont_sqr_order_5(t, t);
        if ((p256_order_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_5(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 5U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 5;
    sp_digit* t3 = td + 4 * 5;
    int i;

    /* t = a^2 */
    sp_256_mont_sqr_order_5(t, a);
    /* t = a^3 = t * a */
    sp_256_mont_mul_order_5(t, t, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_256_mont_sqr_n_order_5(t2, t, 2);
    /* t3= a^f = t2 * t */
    sp_256_mont_mul_order_5(t3, t2, t);
    /* t2= a^f0 = t3 ^ 2 ^ 4 */
    sp_256_mont_sqr_n_order_5(t2, t3, 4);
    /* t = a^ff = t2 * t3 */
    sp_256_mont_mul_order_5(t, t2, t3);
    /* t3= a^ff00 = t ^ 2 ^ 8 */
    sp_256_mont_sqr_n_order_5(t2, t, 8);
    /* t = a^ffff = t2 * t */
    sp_256_mont_mul_order_5(t, t2, t);
    /* t2= a^ffff0000 = t ^ 2 ^ 16 */
    sp_256_mont_sqr_n_order_5(t2, t, 16);
    /* t = a^ffffffff = t2 * t */
    sp_256_mont_mul_order_5(t, t2, t);
    /* t2= a^ffffffff0000000000000000 = t ^ 2 ^ 64  */
    sp_256_mont_sqr_n_order_5(t2, t, 64);
    /* t2= a^ffffffff00000000ffffffff = t2 * t */
    sp_256_mont_mul_order_5(t2, t2, t);
    /* t2= a^ffffffff00000000ffffffff00000000 = t2 ^ 2 ^ 32  */
    sp_256_mont_sqr_n_order_5(t2, t2, 32);
    /* t2= a^ffffffff00000000ffffffffffffffff = t2 * t */
    sp_256_mont_mul_order_5(t2, t2, t);
    /* t2= a^ffffffff00000000ffffffffffffffffbce6 */
    for (i=127; i>=112; i--) {
        sp_256_mont_sqr_order_5(t2, t2);
        if (((sp_digit)p256_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_5(t2, t2, a);
        }
    }
    /* t2= a^ffffffff00000000ffffffffffffffffbce6f */
    sp_256_mont_sqr_n_order_5(t2, t2, 4);
    sp_256_mont_mul_order_5(t2, t2, t3);
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84 */
    for (i=107; i>=64; i--) {
        sp_256_mont_sqr_order_5(t2, t2);
        if (((sp_digit)p256_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_5(t2, t2, a);
        }
    }
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84f */
    sp_256_mont_sqr_n_order_5(t2, t2, 4);
    sp_256_mont_mul_order_5(t2, t2, t3);
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2 */
    for (i=59; i>=32; i--) {
        sp_256_mont_sqr_order_5(t2, t2);
        if (((sp_digit)p256_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_5(t2, t2, a);
        }
    }
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2f */
    sp_256_mont_sqr_n_order_5(t2, t2, 4);
    sp_256_mont_mul_order_5(t2, t2, t3);
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254 */
    for (i=27; i>=0; i--) {
        sp_256_mont_sqr_order_5(t2, t2);
        if (((sp_digit)p256_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_256_mont_mul_order_5(t2, t2, a);
        }
    }
    /* t2= a^ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632540 */
    sp_256_mont_sqr_n_order_5(t2, t2, 4);
    /* r = a^ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f */
    sp_256_mont_mul_order_5(r, t2, t3);
#endif /* WOLFSSL_SP_SMALL */
}

#endif /* HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
#ifdef HAVE_ECC_SIGN
#ifndef SP_ECC_MAX_SIG_GEN
#define SP_ECC_MAX_SIG_GEN  64
#endif

/* Sign the hash using the private key.
 *   e = [hash, 256 bits] from binary
 *   r = (k.G)->x mod order
 *   s = (r * x + e) / k mod order
 * The hash is truncated to the first 256 bits.
 *
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * rng      Random number generator.
 * priv     Private part of key - scalar.
 * rm       First part of result as an mp_int.
 * sm       Sirst part of result as an mp_int.
 * heap     Heap to use for allocation.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
int sp_ecc_sign_256(const byte* hash, word32 hashLen, WC_RNG* rng, mp_int* priv,
                    mp_int* rm, mp_int* sm, mp_int* km, void* heap)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* d = NULL;
#else
    sp_digit ed[2*5];
    sp_digit xd[2*5];
    sp_digit kd[2*5];
    sp_digit rd[2*5];
    sp_digit td[3 * 2*5];
    sp_point p;
#endif
    sp_digit* e = NULL;
    sp_digit* x = NULL;
    sp_digit* k = NULL;
    sp_digit* r = NULL;
    sp_digit* tmp = NULL;
    sp_point* point = NULL;
    sp_digit carry;
    sp_digit* s = NULL;
    sp_digit* kInv = NULL;
    int err = MP_OKAY;
    int64_t c;
    int i;

    (void)heap;

    err = sp_ecc_point_new(heap, p, point);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7 * 2 * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        e = d + 0 * 5;
        x = d + 2 * 5;
        k = d + 4 * 5;
        r = d + 6 * 5;
        tmp = d + 8 * 5;
#else
        e = ed;
        x = xd;
        k = kd;
        r = rd;
        tmp = td;
#endif
        s = e;
        kInv = k;

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(e, 5, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_256_from_mp(x, 5, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_256_ecc_gen_k_5(rng, k);
        }
        else {
            sp_256_from_mp(k, 5, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_256_ecc_mulmod_base_5(point, k, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = point->x mod order */
            XMEMCPY(r, point->x, sizeof(sp_digit) * 5U);
            sp_256_norm_5(r);
            c = sp_256_cmp_5(r, p256_order);
            sp_256_cond_sub_5(r, r, p256_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_5(r);

            /* Conv k to Montgomery form (mod order) */
                sp_256_mul_5(k, k, p256_norm_order);
            err = sp_256_mod_5(k, k, p256_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_5(k);
            /* kInv = 1/k mod order */
                sp_256_mont_inv_order_5(kInv, k, tmp);
            sp_256_norm_5(kInv);

            /* s = r * x + e */
                sp_256_mul_5(x, x, r);
            err = sp_256_mod_5(x, x, p256_order);
        }
        if (err == MP_OKAY) {
            sp_256_norm_5(x);
            carry = sp_256_add_5(s, e, x);
            sp_256_cond_sub_5(s, s, p256_order, 0 - carry);
            sp_256_norm_5(s);
            c = sp_256_cmp_5(s, p256_order);
            sp_256_cond_sub_5(s, s, p256_order, 0L - (sp_digit)(c >= 0));
            sp_256_norm_5(s);

            /* s = s * k^-1 mod order */
                sp_256_mont_mul_order_5(s, s, kInv);
            sp_256_norm_5(s);

            /* Check that signature is usable. */
            if (sp_256_iszero_5(s) == 0) {
                break;
            }
        }
    }

    if (i == 0) {
        err = RNG_FAILURE_E;
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(r, rm);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(s, sm);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 5);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 5U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 3U * 2U * 5U);
#endif
    sp_ecc_point_free(point, 1, heap);

    return err;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
/* Verify the signature values with the hash and public key.
 *   e = Truncate(hash, 256)
 *   u1 = e/s mod order
 *   u2 = r/s mod order
 *   r == (u1.G + u2.Q)->x mod order
 * Optimization: Leave point in projective form.
 *   (x, y, 1) == (x' / z'*z', y' / z'*z'*z', z' / z')
 *   (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x'
 * The hash is truncated to the first 256 bits.
 *
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * rng      Random number generator.
 * priv     Private part of key - scalar.
 * rm       First part of result as an mp_int.
 * sm       Sirst part of result as an mp_int.
 * heap     Heap to use for allocation.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
int sp_ecc_verify_256(const byte* hash, word32 hashLen, mp_int* pX,
    mp_int* pY, mp_int* pZ, mp_int* r, mp_int* sm, int* res, void* heap)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* d = NULL;
#else
    sp_digit u1d[2*5];
    sp_digit u2d[2*5];
    sp_digit sd[2*5];
    sp_digit tmpd[2*5 * 5];
    sp_point p1d;
    sp_point p2d;
#endif
    sp_digit* u1 = NULL;
    sp_digit* u2 = NULL;
    sp_digit* s = NULL;
    sp_digit* tmp = NULL;
    sp_point* p1;
    sp_point* p2 = NULL;
    sp_digit carry;
    int64_t c;
    int err;

    err = sp_ecc_point_new(heap, p1d, p1);
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, p2d, p2);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 16 * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        u1  = d + 0 * 5;
        u2  = d + 2 * 5;
        s   = d + 4 * 5;
        tmp = d + 6 * 5;
#else
        u1 = u1d;
        u2 = u2d;
        s  = sd;
        tmp = tmpd;
#endif

        if (hashLen > 32U) {
            hashLen = 32U;
        }

        sp_256_from_bin(u1, 5, hash, (int)hashLen);
        sp_256_from_mp(u2, 5, r);
        sp_256_from_mp(s, 5, sm);
        sp_256_from_mp(p2->x, 5, pX);
        sp_256_from_mp(p2->y, 5, pY);
        sp_256_from_mp(p2->z, 5, pZ);

        {
            sp_256_mul_5(s, s, p256_norm_order);
        }
        err = sp_256_mod_5(s, s, p256_order);
    }
    if (err == MP_OKAY) {
        sp_256_norm_5(s);
        {
            sp_256_mont_inv_order_5(s, s, tmp);
            sp_256_mont_mul_order_5(u1, u1, s);
            sp_256_mont_mul_order_5(u2, u2, s);
        }

            err = sp_256_ecc_mulmod_base_5(p1, u1, 0, heap);
    }
    if (err == MP_OKAY) {
            err = sp_256_ecc_mulmod_5(p2, p2, u2, 0, heap);
    }

    if (err == MP_OKAY) {
        {
            sp_256_proj_point_add_5(p1, p1, p2, tmp);
            if (sp_256_iszero_5(p1->z)) {
                if (sp_256_iszero_5(p1->x) && sp_256_iszero_5(p1->y)) {
                    sp_256_proj_point_dbl_5(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    p1->x[4] = 0;
                    XMEMCPY(p1->z, p256_norm_mod, sizeof(p256_norm_mod));
                }
            }
        }

        /* (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x' */
        /* Reload r and convert to Montgomery form. */
        sp_256_from_mp(u2, 5, r);
        err = sp_256_mod_mul_norm_5(u2, u2, p256_mod);
    }

    if (err == MP_OKAY) {
        /* u1 = r.z'.z' mod prime */
        sp_256_mont_sqr_5(p1->z, p1->z, p256_mod, p256_mp_mod);
        sp_256_mont_mul_5(u1, u2, p1->z, p256_mod, p256_mp_mod);
        *res = (int)(sp_256_cmp_5(p1->x, u1) == 0);
        if (*res == 0) {
            /* Reload r and add order. */
            sp_256_from_mp(u2, 5, r);
            carry = sp_256_add_5(u2, u2, p256_order);
            /* Carry means result is greater than mod and is not valid. */
            if (carry == 0) {
                sp_256_norm_5(u2);

                /* Compare with mod and if greater or equal then not valid. */
                c = sp_256_cmp_5(u2, p256_mod);
                if (c < 0) {
                    /* Convert to Montogomery form */
                    err = sp_256_mod_mul_norm_5(u2, u2, p256_mod);
                    if (err == MP_OKAY) {
                        /* u1 = (r + 1*order).z'.z' mod prime */
                        sp_256_mont_mul_5(u1, u2, p1->z, p256_mod,
                                                                  p256_mp_mod);
                        *res = (int)(sp_256_cmp_5(p1->x, u1) == 0);
                    }
                }
            }
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL)
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
#endif
    sp_ecc_point_free(p1, 0, heap);
    sp_ecc_point_free(p2, 0, heap);

    return err;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_CHECK_KEY
/* Check that the x and y oridinates are a valid point on the curve.
 *
 * point  EC point.
 * heap   Heap to use if dynamically allocating.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
static int sp_256_ecc_is_point_5(sp_point* point, void* heap)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* d = NULL;
#else
    sp_digit t1d[2*5];
    sp_digit t2d[2*5];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5 * 4, heap, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = d + 0 * 5;
        t2 = d + 2 * 5;
#else
        (void)heap;

        t1 = t1d;
        t2 = t2d;
#endif

        sp_256_sqr_5(t1, point->y);
        (void)sp_256_mod_5(t1, t1, p256_mod);
        sp_256_sqr_5(t2, point->x);
        (void)sp_256_mod_5(t2, t2, p256_mod);
        sp_256_mul_5(t2, t2, point->x);
        (void)sp_256_mod_5(t2, t2, p256_mod);
        (void)sp_256_sub_5(t2, p256_mod, t2);
        sp_256_mont_add_5(t1, t1, t2, p256_mod);

        sp_256_mont_add_5(t1, t1, point->x, p256_mod);
        sp_256_mont_add_5(t1, t1, point->x, p256_mod);
        sp_256_mont_add_5(t1, t1, point->x, p256_mod);

        if (sp_256_cmp_5(t1, p256_b) != 0) {
            err = MP_VAL;
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}

/* Check that the x and y oridinates are a valid point on the curve.
 *
 * pX  X ordinate of EC point.
 * pY  Y ordinate of EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
int sp_ecc_is_point_256(mp_int* pX, mp_int* pY)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_point pubd;
#endif
    sp_point* pub;
    byte one[1] = { 1 };
    int err;

    err = sp_ecc_point_new(NULL, pubd, pub);
    if (err == MP_OKAY) {
        sp_256_from_mp(pub->x, 5, pX);
        sp_256_from_mp(pub->y, 5, pY);
        sp_256_from_bin(pub->z, 5, one, (int)sizeof(one));

        err = sp_256_ecc_is_point_5(pub, NULL);
    }

    sp_ecc_point_free(pub, 0, NULL);

    return err;
}

/* Check that the private scalar generates the EC point (px, py), the point is
 * on the curve and the point has the correct order.
 *
 * pX     X ordinate of EC point.
 * pY     Y ordinate of EC point.
 * privm  Private scalar that generates EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve, ECC_INF_E if the point does not have the correct order,
 * ECC_PRIV_KEY_E when the private scalar doesn't generate the EC point and
 * MP_OKAY otherwise.
 */
int sp_ecc_check_key_256(mp_int* pX, mp_int* pY, mp_int* privm, void* heap)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit privd[5];
    sp_point pubd;
    sp_point pd;
#endif
    sp_digit* priv = NULL;
    sp_point* pub;
    sp_point* p = NULL;
    byte one[1] = { 1 };
    int err;

    err = sp_ecc_point_new(heap, pubd, pub);
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(heap, pd, p);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (priv == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if !(defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
        priv = privd;
#endif

        sp_256_from_mp(pub->x, 5, pX);
        sp_256_from_mp(pub->y, 5, pY);
        sp_256_from_bin(pub->z, 5, one, (int)sizeof(one));
        sp_256_from_mp(priv, 5, privm);

        /* Check point at infinitiy. */
        if ((sp_256_iszero_5(pub->x) != 0) &&
            (sp_256_iszero_5(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check range of X and Y */
        if (sp_256_cmp_5(pub->x, p256_mod) >= 0 ||
            sp_256_cmp_5(pub->y, p256_mod) >= 0) {
            err = ECC_OUT_OF_RANGE_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_256_ecc_is_point_5(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_256_ecc_mulmod_5(p, pub, p256_order, 1, heap);
    }
    if (err == MP_OKAY) {
        /* Check result is infinity */
        if ((sp_256_iszero_5(p->x) == 0) ||
            (sp_256_iszero_5(p->y) == 0)) {
            err = ECC_INF_E;
        }
    }

    if (err == MP_OKAY) {
        /* Base * private = point */
            err = sp_256_ecc_mulmod_base_5(p, priv, 1, heap);
    }
    if (err == MP_OKAY) {
        /* Check result is public key */
        if (sp_256_cmp_5(p->x, pub->x) != 0 ||
            sp_256_cmp_5(p->y, pub->y) != 0) {
            err = ECC_PRIV_KEY_E;
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (priv != NULL) {
        XFREE(priv, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(p, 0, heap);
    sp_ecc_point_free(pub, 0, heap);

    return err;
}
#endif
#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
/* Add two projective EC points together.
 * (pX, pY, pZ) + (qX, qY, qZ) = (rX, rY, rZ)
 *
 * pX   First EC point's X ordinate.
 * pY   First EC point's Y ordinate.
 * pZ   First EC point's Z ordinate.
 * qX   Second EC point's X ordinate.
 * qY   Second EC point's Y ordinate.
 * qZ   Second EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_add_point_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* qX, mp_int* qY, mp_int* qZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit tmpd[2 * 5 * 5];
    sp_point pd;
    sp_point qd;
#endif
    sp_digit* tmp;
    sp_point* p;
    sp_point* q = NULL;
    int err;

    err = sp_ecc_point_new(NULL, pd, p);
    if (err == MP_OKAY) {
        err = sp_ecc_point_new(NULL, qd, q);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 5, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);
        sp_256_from_mp(q->x, 5, qX);
        sp_256_from_mp(q->y, 5, qY);
        sp_256_from_mp(q->z, 5, qZ);

            sp_256_proj_point_add_5(p, p, q, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, rZ);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(q, 0, NULL);
    sp_ecc_point_free(p, 0, NULL);

    return err;
}

/* Double a projective EC point.
 * (pX, pY, pZ) + (pX, pY, pZ) = (rX, rY, rZ)
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_dbl_point_256(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit tmpd[2 * 5 * 2];
    sp_point pd;
#endif
    sp_digit* tmp;
    sp_point* p;
    int err;

    err = sp_ecc_point_new(NULL, pd, p);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 2, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);

            sp_256_proj_point_dbl_5(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, rZ);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(p, 0, NULL);

    return err;
}

/* Map a projective EC point to affine in place.
 * pZ will be one.
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_map_256(mp_int* pX, mp_int* pY, mp_int* pZ)
{
#if !defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)
    sp_digit tmpd[2 * 5 * 4];
    sp_point pd;
#endif
    sp_digit* tmp;
    sp_point* p;
    int err;

    err = sp_ecc_point_new(NULL, pd, p);
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 5 * 4, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif
    if (err == MP_OKAY) {
        sp_256_from_mp(p->x, 5, pX);
        sp_256_from_mp(p->y, 5, pY);
        sp_256_from_mp(p->z, 5, pZ);

        sp_256_map_5(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->x, pX);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->y, pY);
    }
    if (err == MP_OKAY) {
        err = sp_256_to_mp(p->z, pZ);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_ecc_point_free(p, 0, NULL);

    return err;
}
#endif /* WOLFSSL_PUBLIC_ECC_ADD_DBL */
#ifdef HAVE_COMP_KEY
/* Find the square root of a number mod the prime of the curve.
 *
 * y  The number to operate on and the result.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
static int sp_256_mont_sqrt_5(sp_digit* y)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* d;
#else
    sp_digit t1d[2 * 5];
    sp_digit t2d[2 * 5];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 5, NULL, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        t1 = d + 0 * 5;
        t2 = d + 2 * 5;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        {
            /* t2 = y ^ 0x2 */
            sp_256_mont_sqr_5(t2, y, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0x3 */
            sp_256_mont_mul_5(t1, t2, y, p256_mod, p256_mp_mod);
            /* t2 = y ^ 0xc */
            sp_256_mont_sqr_n_5(t2, t1, 2, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xf */
            sp_256_mont_mul_5(t1, t1, t2, p256_mod, p256_mp_mod);
            /* t2 = y ^ 0xf0 */
            sp_256_mont_sqr_n_5(t2, t1, 4, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xff */
            sp_256_mont_mul_5(t1, t1, t2, p256_mod, p256_mp_mod);
            /* t2 = y ^ 0xff00 */
            sp_256_mont_sqr_n_5(t2, t1, 8, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffff */
            sp_256_mont_mul_5(t1, t1, t2, p256_mod, p256_mp_mod);
            /* t2 = y ^ 0xffff0000 */
            sp_256_mont_sqr_n_5(t2, t1, 16, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffffffff */
            sp_256_mont_mul_5(t1, t1, t2, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffffffff00000000 */
            sp_256_mont_sqr_n_5(t1, t1, 32, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffffffff00000001 */
            sp_256_mont_mul_5(t1, t1, y, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffffffff00000001000000000000000000000000 */
            sp_256_mont_sqr_n_5(t1, t1, 96, p256_mod, p256_mp_mod);
            /* t1 = y ^ 0xffffffff00000001000000000000000000000001 */
            sp_256_mont_mul_5(t1, t1, y, p256_mod, p256_mp_mod);
            sp_256_mont_sqr_n_5(y, t1, 94, p256_mod, p256_mp_mod);
        }
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}

/* Uncompress the point given the X ordinate.
 *
 * xm    X ordinate.
 * odd   Whether the Y ordinate is odd.
 * ym    Calculated Y ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_uncompress_256(mp_int* xm, int odd, mp_int* ym)
{
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* d;
#else
    sp_digit xd[2 * 5];
    sp_digit yd[2 * 5];
#endif
    sp_digit* x = NULL;
    sp_digit* y = NULL;
    int err = MP_OKAY;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 5, NULL, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        x = d + 0 * 5;
        y = d + 2 * 5;
#else
        x = xd;
        y = yd;
#endif

        sp_256_from_mp(x, 5, xm);
        err = sp_256_mod_mul_norm_5(x, x, p256_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
        {
            sp_256_mont_sqr_5(y, x, p256_mod, p256_mp_mod);
            sp_256_mont_mul_5(y, y, x, p256_mod, p256_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_256_mont_sub_5(y, y, x, p256_mod);
        sp_256_mont_sub_5(y, y, x, p256_mod);
        sp_256_mont_sub_5(y, y, x, p256_mod);
        /* y = x^3 - 3x + b */
        err = sp_256_mod_mul_norm_5(x, p256_b, p256_mod);
    }
    if (err == MP_OKAY) {
        sp_256_mont_add_5(y, y, x, p256_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_256_mont_sqrt_5(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 5, 0, 5U * sizeof(sp_digit));
        sp_256_mont_reduce_5(y, p256_mod, p256_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_256_mont_sub_5(y, p256_mod, y, p256_mod);
        }

        err = sp_256_to_mp(y, ym);
    }

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}
#endif
#endif /* !WOLFSSL_SP_NO_256 */
#endif /* WOLFSSL_HAVE_SP_ECC */
#endif /* SP_WORD_SIZE == 64 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_ECC */
