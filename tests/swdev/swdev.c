/* tests/swdev/swdev.c -- wc_swdev callback. */

#include "swdev.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#endif

static int swdev_initialized = 0;

static int swdev_ensure_init(void)
{
    if (!swdev_initialized) {
        int ret = wolfCrypt_Init();
        if (ret != 0)
            return ret;
        swdev_initialized = 1;
    }
    return 0;
}

#ifndef NO_RSA
static int swdev_rsa(wc_CryptoInfo* info)
{
    switch (info->pk.rsa.type) {
    case RSA_PUBLIC_ENCRYPT:
    case RSA_PUBLIC_DECRYPT:
    case RSA_PRIVATE_ENCRYPT:
    case RSA_PRIVATE_DECRYPT:
        return wc_RsaFunction(info->pk.rsa.in, info->pk.rsa.inLen,
            info->pk.rsa.out, info->pk.rsa.outLen, info->pk.rsa.type,
            info->pk.rsa.key, info->pk.rsa.rng);
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}

#ifdef WOLFSSL_KEY_GEN
static int swdev_rsa_keygen(wc_CryptoInfo* info)
{
    return wc_MakeRsaKey(info->pk.rsakg.key, info->pk.rsakg.size,
        info->pk.rsakg.e, info->pk.rsakg.rng);
}
#endif
#endif /* !NO_RSA */

#ifdef HAVE_ECC
static int swdev_ecc_keygen(wc_CryptoInfo* info)
{
#ifdef HAVE_ECC_DHE
    return wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
        info->pk.eckg.key, info->pk.eckg.curveId);
#else
    (void)info;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

static int swdev_ecdh(wc_CryptoInfo* info)
{
#ifdef HAVE_ECC_DHE
    return wc_ecc_shared_secret(info->pk.ecdh.private_key,
        info->pk.ecdh.public_key, info->pk.ecdh.out,
        info->pk.ecdh.outlen);
#else
    (void)info;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

static int swdev_ecc_sign(wc_CryptoInfo* info)
{
#ifdef HAVE_ECC_SIGN
    return wc_ecc_sign_hash(info->pk.eccsign.in, info->pk.eccsign.inlen,
        info->pk.eccsign.out, info->pk.eccsign.outlen,
        info->pk.eccsign.rng, info->pk.eccsign.key);
#else
    (void)info;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

static int swdev_ecc_verify(wc_CryptoInfo* info)
{
#ifdef HAVE_ECC_VERIFY
    return wc_ecc_verify_hash(info->pk.eccverify.sig,
        info->pk.eccverify.siglen, info->pk.eccverify.hash,
        info->pk.eccverify.hashlen, info->pk.eccverify.res,
        info->pk.eccverify.key);
#else
    (void)info;
    return CRYPTOCB_UNAVAILABLE;
#endif
}

static int swdev_ecc_get_size(wc_CryptoInfo* info)
{
    int sz = wc_ecc_size((ecc_key*)info->pk.ecc_get_size.key);
    if (sz <= 0)
        return sz; /* propagate negative error */
    *info->pk.ecc_get_size.keySize = sz;
    return 0;
}

static int swdev_ecc_get_sig_size(wc_CryptoInfo* info)
{
    int sz = wc_ecc_sig_size(info->pk.ecc_get_sig_size.key);
    if (sz <= 0)
        return sz;
    *info->pk.ecc_get_sig_size.sigSize = sz;
    return 0;
}
#endif /* HAVE_ECC */

WC_SWDEV_EXPORT int wc_SwDev_Callback(int devId, wc_CryptoInfo* info,
    void* ctx)
{
    int ret;

    (void)devId;
    (void)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

    ret = swdev_ensure_init();
    if (ret != 0)
        return ret;

    switch (info->algo_type) {
#if !defined(NO_RSA) || defined(HAVE_ECC)
    case WC_ALGO_TYPE_PK:
        switch (info->pk.type) {
    #ifndef NO_RSA
        case WC_PK_TYPE_RSA:
            return swdev_rsa(info);
        #ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
            return swdev_rsa_keygen(info);
        #endif
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            return swdev_ecc_keygen(info);
        case WC_PK_TYPE_ECDH:
            return swdev_ecdh(info);
        case WC_PK_TYPE_ECDSA_SIGN:
            return swdev_ecc_sign(info);
        case WC_PK_TYPE_ECDSA_VERIFY:
            return swdev_ecc_verify(info);
        case WC_PK_TYPE_EC_GET_SIZE:
            return swdev_ecc_get_size(info);
        case WC_PK_TYPE_EC_GET_SIG_SIZE:
            return swdev_ecc_get_sig_size(info);
    #endif /* HAVE_ECC */
        default:
            return CRYPTOCB_UNAVAILABLE;
        }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}
