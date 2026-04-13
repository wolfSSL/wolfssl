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
    const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key
)
{
    int res;
    int sig_sz = inLen;
    int key_sz = mp_unsigned_bin_size(&key->n);
    word32 exp;

    if (inLen > CASPER_MAX_BUF_SZ || outLen > CASPER_MAX_BUF_SZ)
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

    return 0;
}
#endif

#endif /* WOLFSSL_NXP_CASPER */
