/* casper_port.c
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

#ifdef WOLFSSL_NXP_CASPER

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/nxp/casper_port.h>
#include "fsl_casper.h"

int wc_casper_init(void)
{
    int ret;

    /* Required, not just defensive: wolfCrypt_Init() initializes only the
     * global crypt HW mutex and never the per-algorithm ones, so under
     * WOLFSSL_ALGO_HW_MUTEX this is the only place the PK mutex is set up
     * ahead of first use.  No-op when WOLFSSL_CRYPT_HW_MUTEX is off. */
    if ((ret = wolfSSL_HwPkMutexInit()) != 0)
        return ret;

    CASPER_Init(CASPER);

    return 0;
}

#if !defined(NO_RSA) && defined(WOLFSSL_NXP_CASPER_RSA_PUB_EXPTMOD)

#define CASPER_MAX_BUF_SZ   512
static uint8_t key_buf[CASPER_MAX_BUF_SZ];
static uint8_t sig_buf[CASPER_MAX_BUF_SZ];
static uint8_t out_buf[CASPER_MAX_BUF_SZ];

int casper_rsa_public_exptmod(
    const byte* in, word32 inLen, byte* out, word32* outLen, RsaKey* key
)
{
    int res;
    int sig_sz = inLen;
    int key_sz = mp_unsigned_bin_size(&key->n);
    int exp_sz = mp_unsigned_bin_size(&key->e);
    uint8_t exp_buf[sizeof(uint32_t)];
    uint32_t exp = 0;

    if (inLen > CASPER_MAX_BUF_SZ || *outLen > CASPER_MAX_BUF_SZ)
        return BAD_FUNC_ARG;

    /* casper only accepts a 32-bit public exponent */
    if (exp_sz <= 0 || exp_sz > (int)sizeof(exp_buf))
        return BAD_FUNC_ARG;

    if ((res = wolfSSL_HwPkMutexLock()) != 0)
        return res;

    /* casper requires little endian format for inputs/outputs */
    XMEMCPY(sig_buf, in, sig_sz);
    mp_reverse(sig_buf, sig_sz);

    if ((res = mp_to_unsigned_bin(&key->n, key_buf)) != MP_OKAY)
        goto unlock;
    mp_reverse(key_buf, key_sz);

    XMEMSET(exp_buf, 0, sizeof(exp_buf));
    if ((res = mp_to_unsigned_bin(&key->e,
                                  exp_buf + sizeof(exp_buf) - exp_sz))
        != MP_OKAY)
        goto unlock;
    exp = ((uint32_t)exp_buf[0] << 24) | ((uint32_t)exp_buf[1] << 16) |
          ((uint32_t)exp_buf[2] <<  8) | ((uint32_t)exp_buf[3]);

    CASPER_ModExp(CASPER, (void *)sig_buf, (void *)key_buf,
            key_sz / sizeof(uint32_t), exp, out_buf);

    mp_reverse(out_buf, sig_sz);
    XMEMCPY(out, out_buf, sig_sz);

    *outLen = inLen;
    res = 0;

unlock:
    wolfSSL_HwPkMutexUnLock();

    return res;
}
#endif /* !NO_RSA && WOLFSSL_NXP_CASPER_RSA_PUB_EXPTMOD */


/* 32 for 256 bits, 48 for 384 bits and 72 for 521 bits... */
#define CASPER_MAX_ECC_SIZE_BYTES (72)

#if defined(HAVE_ECC) && defined(WOLFSSL_NXP_CASPER_ECC_MULMOD)
/* calculates R = m*P[X, Y] */
int casper_ecc_mulmod(
    const mp_int *m, ecc_point *P, ecc_point *R, int curve_id
)
{
    uint32_t M[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    uint32_t X[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    uint32_t Y[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    int size;
    int ret;

    if (!m || !P || !R)
        return BAD_FUNC_ARG;

    /* Resolve the curve before taking the lock.  An unsupported curve_id is an
     * argument error, and should not have to wait out an in-flight CASPER
     * operation just to be rejected. */
    if (curve_id == ECC_SECP256R1)
        size = 32;
    else if (curve_id == ECC_SECP384R1)
        size = 48;
    else if (curve_id == ECC_SECP521R1)
        size = 66;
    else
        return BAD_FUNC_ARG;

    /* CASPER is a single shared peripheral; serialize against the RSA path
     * and against other ECC callers for the whole hardware sequence. */
    if ((ret = wolfSSL_HwPkMutexLock()) != 0)
        return ret;

    /* scalar */
    if (mp_to_unsigned_bin(m, (unsigned char *)&M[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&M[0], size);

    /* point */
    if (mp_to_unsigned_bin(P->x, (unsigned char *)&X[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&X[0], size);
    if (mp_to_unsigned_bin(P->y, (unsigned char *)&Y[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&Y[0], size);

    if (curve_id == ECC_SECP256R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P256);
        CASPER_ECC_SECP256R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P384);
        CASPER_ECC_SECP384R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P521);
        CASPER_ECC_SECP521R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }

    /* result */
    mp_reverse((unsigned char *)&X[0], size);
    if (mp_read_unsigned_bin(R->x, (unsigned char *)&X[0], size) != MP_OKAY)
    {
        ret = MP_READ_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&Y[0], size);
    if (mp_read_unsigned_bin(R->y, (unsigned char *)&Y[0], size) != MP_OKAY)
    {
        ret = MP_READ_E;
        goto unlock;
    }
    mp_set(R->z, 1);
    ret = 0;

unlock:
    wolfSSL_HwPkMutexUnLock();

    return ret;
}
#endif /* HAVE_ECC && WOLFSSL_NXP_CASPER_ECC_MULMOD */

#if defined(HAVE_ECC) && defined(WOLFSSL_NXP_CASPER_ECC_MUL2ADD)
/* calculates R = m*P[X, Y] + n*Q[X, Y] */
int casper_ecc_mul2add(
    const mp_int *m, ecc_point *P, const mp_int *n, ecc_point *Q,
    ecc_point *R, int curve_id
)
{
    uint32_t M[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)]  = { 0 };
    uint32_t X1[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    uint32_t Y1[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    uint32_t N[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)]  = { 0 };
    uint32_t X2[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    uint32_t Y2[CASPER_MAX_ECC_SIZE_BYTES / sizeof(uint32_t)] = { 0 };
    int size;
    int ret;

    if (!m || !P || !n || !Q || !R)
        return BAD_FUNC_ARG;

    /* Resolve the curve before taking the lock.  An unsupported curve_id is an
     * argument error, and should not have to wait out an in-flight CASPER
     * operation just to be rejected. */
    if (curve_id == ECC_SECP256R1)
        size = 32;
    else if (curve_id == ECC_SECP384R1)
        size = 48;
    else if (curve_id == ECC_SECP521R1)
        size = 66;
    else
        return BAD_FUNC_ARG;

    /* CASPER is a single shared peripheral; serialize against the RSA path
     * and against other ECC callers for the whole hardware sequence. */
    if ((ret = wolfSSL_HwPkMutexLock()) != 0)
        return ret;

    /* first scalar */
    if (mp_to_unsigned_bin(m, (unsigned char *)&M[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&M[0], size);

    /* first point */
    if (mp_to_unsigned_bin(P->x, (unsigned char *)&X1[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&X1[0], size);
    if (mp_to_unsigned_bin(P->y, (unsigned char *)&Y1[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&Y1[0], size);

    /* second scalar */
    if (mp_to_unsigned_bin(n, (unsigned char *)&N[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&N[0], size);

    /* second point */
    if (mp_to_unsigned_bin(Q->x, (unsigned char *)&X2[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&X2[0], size);
    if (mp_to_unsigned_bin(Q->y, (unsigned char *)&Y2[0]) != MP_OKAY)
    {
        ret = MP_TO_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&Y2[0], size);

    if (curve_id == ECC_SECP256R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P256);
        CASPER_ECC_SECP256R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P384);
        CASPER_ECC_SECP384R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        CASPER_ecc_init(kCASPER_ECC_P521);
        CASPER_ECC_SECP521R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }

    /* result */
    mp_reverse((unsigned char *)&X1[0], size);
    if (mp_read_unsigned_bin(R->x, (unsigned char *)&X1[0], size) != MP_OKAY)
    {
        ret = MP_READ_E;
        goto unlock;
    }
    mp_reverse((unsigned char *)&Y1[0], size);
    if (mp_read_unsigned_bin(R->y, (unsigned char *)&Y1[0], size) != MP_OKAY)
    {
        ret = MP_READ_E;
        goto unlock;
    }
    mp_set(R->z, 1);
    ret = 0;

unlock:
    wolfSSL_HwPkMutexUnLock();

    return ret;
}
#endif /* HAVE_ECC && WOLFSSL_NXP_CASPER_ECC_MUL2ADD */

#endif /* WOLFSSL_NXP_CASPER */
