/* cryptocb_provider.c
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
 *
 * External crypto callback provider implementation.
 * This file is compiled with user_settings.h that includes the main
 * library's options.h (for ABI compatibility) but undefines
 * WOLF_CRYPTO_CB_ONLY_* flags to enable software implementations.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Include algorithm headers as needed */
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#include "cryptocb_provider.h"

CRYPTOCB_PROVIDER_API int external_provider_callback(
    int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)ctx; /* unused */

    if (info == NULL)
        return BAD_FUNC_ARG;

    /* Handle public key operations */
    if (info->algo_type == WC_ALGO_TYPE_PK) {
#ifndef NO_RSA
        if (info->pk.type == WC_PK_TYPE_RSA) {
            /* Set devId to invalid to prevent recursive callback */
            info->pk.rsa.key->devId = INVALID_DEVID;

            /* Perform raw RSA operation (modular exponentiation) */
            ret = wc_RsaFunction(
                info->pk.rsa.in, info->pk.rsa.inLen,
                info->pk.rsa.out, info->pk.rsa.outLen,
                info->pk.rsa.type, info->pk.rsa.key,
                info->pk.rsa.rng);

            /* Restore devId */
            info->pk.rsa.key->devId = devIdArg;
        }
#ifdef WOLFSSL_KEY_GEN
        else if (info->pk.type == WC_PK_TYPE_RSA_KEYGEN) {
            info->pk.rsakg.key->devId = INVALID_DEVID;

            ret = wc_MakeRsaKey(info->pk.rsakg.key, info->pk.rsakg.size,
                                info->pk.rsakg.e, info->pk.rsakg.rng);

            info->pk.rsakg.key->devId = devIdArg;
        }
#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_RSA */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_DHE
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
            info->pk.eckg.key->devId = INVALID_DEVID;

            ret = wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
                                     info->pk.eckg.key, info->pk.eckg.curveId);

            info->pk.eckg.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
            info->pk.ecdh.private_key->devId = INVALID_DEVID;

            ret = wc_ecc_shared_secret(
                info->pk.ecdh.private_key, info->pk.ecdh.public_key,
                info->pk.ecdh.out, info->pk.ecdh.outlen);

            info->pk.ecdh.private_key->devId = devIdArg;
        }
#endif /* HAVE_ECC_DHE */
#ifdef HAVE_ECC_SIGN
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            info->pk.eccsign.key->devId = INVALID_DEVID;

            ret = wc_ecc_sign_hash(
                info->pk.eccsign.in, info->pk.eccsign.inlen,
                info->pk.eccsign.out, info->pk.eccsign.outlen,
                info->pk.eccsign.rng, info->pk.eccsign.key);

            info->pk.eccsign.key->devId = devIdArg;
        }
#endif /* HAVE_ECC_SIGN */
#ifdef HAVE_ECC_VERIFY
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            info->pk.eccverify.key->devId = INVALID_DEVID;

            ret = wc_ecc_verify_hash(
                info->pk.eccverify.sig, info->pk.eccverify.siglen,
                info->pk.eccverify.hash, info->pk.eccverify.hashlen,
                info->pk.eccverify.res, info->pk.eccverify.key);

            info->pk.eccverify.key->devId = devIdArg;
        }
#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC */
    }

    return ret;
}
