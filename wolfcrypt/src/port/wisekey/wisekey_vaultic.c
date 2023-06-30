/*
 * wisekey_vaultic.c
 *
 * Copyright (C) 2023 wolfSSL Inc.
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
 * Implementation of wolfCrypt devcrypto callbacks
 *
 * The wolfSSL port of the Wisekey VaultIC provides a wrapper library to allow
 * the VaultIC to be used as an external crypto provider.  This library depends
 * on the Wisekey-provided VaultIC interface libraries that have been statically
 * compiled in the proper hardware configuration.
 */

//XXX START REMOVE ME
#define HAVE_WISEKEY_VAULTIC
//XXX END REMOVE ME


#include <wolfssl/wolfcrypt/settings.h>

#ifdef haveconfig...
#endif

#if defined(HAVE_WISEKEY_VAULTIC)
#error "HERE"

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/wisekey/wisekey_vaultic.h>

/* Forward declarations */

static int HandlePkCallback(int devId, wc_CryptoInfo* info, void* ctx);
static int HandleHashCallback(int devId, wc_CryptoInfo* info, void* ctx);
static int HandleCipherCallback(int devId, wc_CryptoInfo* info, void* ctx);

/* Register this callback using:
 * int rc = wc_CryptoCb_RegisterDevice(WISEKEY_VAULTIC420_DEVID,
 *                      wolfSSL_WisekeyVaultIC_CryptoDevCb, NULL);
 *
 * Associate this device with your context using:
 * wc_
 *
 */
int wolfSSL_WisekeyVaultIC_CryptoDevCb(int devId,
                                       wc_CryptoInfo* info,
                                       void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    (void)devId;
    (void)ctx;

    if(!info) {
        /* Invalid info */
        return rc;
    }
    switch(info->algo_type) {
    case WC_ALGO_TYPE_NONE:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb NONE:\n");
#endif
        /* Nothing to do */
        break;

    case WC_ALGO_TYPE_HASH:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb HASH: Type:%d\n", info->hash.type);
#endif
#if !defined(NO_SHA) || !defined(NO_SHA256)
        /* Perform a hash */
        rc = HandleHashCallback(devId, info, ctx);
#endif
        break;

    case WC_ALGO_TYPE_CIPHER:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb CIPHER: Type:%d\n", info->cipher.type);
#endif
#if !defined(NO_AES)
        /* Perform a symmetric cipher */
        rc = HandleCipherCallback(devId, info, ctx);
#endif
        break;

    case WC_ALGO_TYPE_PK:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb PK: Type:%d\n", info->pk.type);
#endif
#if !defined(NO_RSA) || defined(HAVE_ECC)
        /* Perform a PKI operation */
        rc = HandlePkCallback(devId,info,ctx);
#endif /* !defined(NO_RSA) || defined(HAVE_ECC) */
        break;

    case WC_ALGO_TYPE_RNG:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb RNG: Out:%p Sz:%d\n", info->rng.out, info->rng.sz);
#endif
#if !defined(WC_NO_RNG)
        /* Put info->rng.sz random bytes into info->rng.out*/
        /* TODO rc = VaultIC_Random(); */
        rc = CRYPTOCB_UNAVAILABLE;
#endif
        break;

    case WC_ALGO_TYPE_SEED:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb SEED: Seed:%p Sz:%d\n", info->seed.seed,
                info->seed.sz);
#endif
#if !defined(WC_NO_RNG)
        /* Get info->seed.sz seed bytes from info->seed.seed*/
        /* TODO rc = VaultIC_Seed(); */
#endif
        break;

    case WC_ALGO_TYPE_HMAC:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb HMAC:\n");
#endif
        break;

    case WC_ALGO_TYPE_CMAC:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb CMAC:\n");
#endif
        break;

    default:
#if !defined(DEBUG_VAULTIC)
        printf(" CryptoDevCb UNKNOWN\n");
#endif
        break;
    }
    return rc;
}

static int HandlePkCallback(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    switch(info->pk.type) {
    case WC_PK_TYPE_NONE:
    #if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback NONE\n");
    #endif
        break;

    case WC_PK_TYPE_RSA:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback RSA\n");
#endif
        break;

    case WC_PK_TYPE_DH:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback DH\n");
#endif
        break;

    case WC_PK_TYPE_ECDH:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ECDH\n");
#endif
        break;

    case WC_PK_TYPE_ECDSA_SIGN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ECDSA_SIGN\n");
#endif
        break;

    case WC_PK_TYPE_ECDSA_VERIFY:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ECDSA_VERIFY\n");
#endif
        break;

    case WC_PK_TYPE_ED25519_SIGN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ED25519_SIGN\n");
#endif
        break;

    case WC_PK_TYPE_CURVE25519:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback CURVE25519\n");
#endif
        break;

    case WC_PK_TYPE_RSA_KEYGEN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback RSA_KEYGEN\n");
#endif
        break;

    case WC_PK_TYPE_EC_KEYGEN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback EC_KEYGEN\n");
#endif
        break;

    case WC_PK_TYPE_RSA_CHECK_PRIV_KEY:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback RSA_CHECK_PRIV_KEY\n");
#endif
        break;

    case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback EC_CHECK_PRIV_KEY\n");
#endif
        break;

    case WC_PK_TYPE_ED448:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ED448\n");
#endif
        break;

    case WC_PK_TYPE_CURVE448:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback CRUVE448\n");
#endif
        break;

    case WC_PK_TYPE_ED25519_VERIFY:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ED25519_VERIFY\n");
#endif
        break;

    case WC_PK_TYPE_ED25519_KEYGEN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback ED25519_KEYGEN\n");
#endif
        break;

    case WC_PK_TYPE_CURVE25519_KEYGEN:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback CURVE25519_KEYGEN\n");
#endif
        break;

    case WC_PK_TYPE_RSA_GET_SIZE:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback RSA_GET_SIZE\n");
#endif
        break;

    default:
#if !defined(DEBUG_VAULTIC)
        printf("  HandlePkCallback UNKNOWN\n");
#endif
        break;
    }
    return rc;
}

static int HandleHashCallback(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    switch(info->hash.type) {
    case WC_HASH_TYPE_NONE:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback NONE\n");
#endif
        break;
    case WC_HASH_TYPE_SHA:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback SHA\n");
#endif
        break;
    case WC_HASH_TYPE_SHA224:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback SHA224\n");
#endif
        break;
    case WC_HASH_TYPE_SHA256:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback SHA256\n");
#endif
        break;
    case WC_HASH_TYPE_SHA384:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback SHA384\n");
#endif
        break;
    case WC_HASH_TYPE_SHA512:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleHashCallback SHA512\n");
#endif
        break;
    default:
        break;
    }
    return rc;
}

static int HandleCipherCallback(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;
    switch(info->cipher.type) {
    case WC_CIPHER_NONE:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback NONE\n");
#endif
        break;

    case WC_CIPHER_AES:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES\n");
#endif
        break;

    case WC_CIPHER_AES_CBC:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_CBC\n");
#endif
        break;

    case WC_CIPHER_AES_GCM:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_GCM\n");
#endif
        break;

    case WC_CIPHER_AES_CTR:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_CTR\n");
#endif
        break;

    case WC_CIPHER_AES_XTS:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_XTS\n");
#endif
        break;

    case WC_CIPHER_AES_CFB:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_CFB\n");
#endif
        break;

    case WC_CIPHER_AES_CCM:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_CCM\n");
#endif
        break;

    case WC_CIPHER_AES_ECB:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback AES_ECB\n");
#endif
        break;

    default:
#if !defined(DEBUG_VAULTIC)
        printf("  HandleCipherCallback UNKNOWN\n");
#endif
        break;
    }
    return rc;
}

#endif /* defined(HAVE_WISEKEY_VAULTIC) */
