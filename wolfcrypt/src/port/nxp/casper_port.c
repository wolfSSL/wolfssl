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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_NXP_CASPER

#if defined(WOLFSSL_CRYPT_HW_MUTEX) && WOLFSSL_CRYPT_HW_MUTEX > 0
    #error WOLFSSL_CRYPT_HW_MUTEX=1 not supported yet
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/nxp/casper_port.h>
#include "fsl_casper.h"

int wc_casper_init(void)
{
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
    word32 exp;

    if (inLen > CASPER_MAX_BUF_SZ || *outLen > CASPER_MAX_BUF_SZ)
        return BAD_FUNC_ARG;

    /* casper requires little endian format for inputs/outputs */
    XMEMCPY(sig_buf, in, sig_sz);
    mp_reverse(sig_buf, sig_sz);

    if ((res = mp_to_unsigned_bin(&key->n, key_buf)) != MP_OKAY)
        return res;
    mp_reverse(key_buf, key_sz);

    if ((res = mp_to_unsigned_bin(&key->e, (uint8_t *)&exp)) != MP_OKAY)
        return res;

    CASPER_ModExp(CASPER, (void *)sig_buf, (void *)key_buf,
            key_sz / sizeof(uint32_t), exp, out_buf);

    mp_reverse(out_buf, sig_sz);
    XMEMCPY(out, out_buf, sig_sz);

    *outLen = inLen;

    return 0;
}
#endif


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

    if (!m || !P || !R)
        return BAD_FUNC_ARG;

    if (curve_id == ECC_SECP256R1)
    {
        size = 32;
        CASPER_ecc_init(kCASPER_ECC_P256);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        size = 48;
        CASPER_ecc_init(kCASPER_ECC_P384);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        size = 66;
        CASPER_ecc_init(kCASPER_ECC_P521);
    }
    else
        return BAD_FUNC_ARG;

    /* scalar */
    if (mp_to_unsigned_bin(m, (unsigned char *)&M[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&M[0], size);

    /* point */
    if (mp_to_unsigned_bin(P->x, (unsigned char *)&X[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&X[0], size);
    if (mp_to_unsigned_bin(P->y, (unsigned char *)&Y[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&Y[0], size);

    if (curve_id == ECC_SECP256R1)
    {
        CASPER_ECC_SECP256R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        CASPER_ECC_SECP384R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        CASPER_ECC_SECP521R1_Mul(CASPER, X, Y, X, Y, (void *)M);
    }

    /* result */
    mp_reverse((unsigned char *)&X[0], size);
    if (mp_read_unsigned_bin(R->x, (unsigned char *)&X[0], size) != MP_OKAY)
        return MP_READ_E;
    mp_reverse((unsigned char *)&Y[0], size);
    if (mp_read_unsigned_bin(R->y, (unsigned char *)&Y[0], size) != MP_OKAY)
        return MP_READ_E;
    mp_set(R->z, 1);

    return 0;
}    
#endif

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

    if (!m || !P || !n || !Q || !R)
        return BAD_FUNC_ARG;

    if (curve_id == ECC_SECP256R1)
    {
        size = 32;
        CASPER_ecc_init(kCASPER_ECC_P256);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        size = 48;
        CASPER_ecc_init(kCASPER_ECC_P384);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        size = 66;
        CASPER_ecc_init(kCASPER_ECC_P521);
    }
    else
        return BAD_FUNC_ARG;

    /* first scalar */
    if (mp_to_unsigned_bin(m, (unsigned char *)&M[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&M[0], size);

    /* first point */
    if (mp_to_unsigned_bin(P->x, (unsigned char *)&X1[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&X1[0], size);
    if (mp_to_unsigned_bin(P->y, (unsigned char *)&Y1[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&Y1[0], size);

    /* second scalar */
    if (mp_to_unsigned_bin(n, (unsigned char *)&N[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&N[0], size);

    /* second point */
    if (mp_to_unsigned_bin(Q->x, (unsigned char *)&X2[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&X2[0], size);
    if (mp_to_unsigned_bin(Q->y, (unsigned char *)&Y2[0]) != MP_OKAY)
        return MP_TO_E;
    mp_reverse((unsigned char *)&Y2[0], size);

    if (curve_id == ECC_SECP256R1)
    {
        CASPER_ECC_SECP256R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }
    else if (curve_id == ECC_SECP384R1)
    {
        CASPER_ECC_SECP384R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }
    else if (curve_id == ECC_SECP521R1)
    {
        CASPER_ECC_SECP521R1_MulAdd(CASPER, &X1[0], &Y1[0], &X1[0], &Y1[0],
            (void *)M, &X2[0], &Y2[0], (void *)N);
    }

    /* result */
    mp_reverse((unsigned char *)&X1[0], size);
    if (mp_read_unsigned_bin(R->x, (unsigned char *)&X1[0], size) != MP_OKAY)
        return MP_READ_E;
    mp_reverse((unsigned char *)&Y1[0], size);
    if (mp_read_unsigned_bin(R->y, (unsigned char *)&Y1[0], size) != MP_OKAY)
        return MP_READ_E;
    mp_set(R->z, 1);

    return 0;
}    
#endif

#endif /* WOLFSSL_NXP_CASPER */
