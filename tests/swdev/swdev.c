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
#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
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

#ifndef NO_SHA256
/* Copy hash state between caller's wc_Sha256 and swdev's shadow, leaving
 * admin fields (heap, devId, devCtx, W, async, HW ctx) per-side. */
static void swdev_sha256_copy_state(wc_Sha256* dst, const wc_Sha256* src)
{
    XMEMCPY(dst->digest, src->digest, sizeof(dst->digest));
    XMEMCPY(dst->buffer, src->buffer, sizeof(dst->buffer));
    dst->buffLen = src->buffLen;
    dst->loLen   = src->loLen;
    dst->hiLen   = src->hiLen;
#ifdef WC_C_DYNAMIC_FALLBACK
    dst->sha_method = src->sha_method;
#endif
#ifdef WOLFSSL_HASH_FLAGS
    dst->flags = src->flags;
#endif
}

/* Run the op on a per-call shadow wc_Sha256 owned by swdev, copying state
 * in and out around it. The caller's struct, allocated by libwolfssl with
 * the software init stripped, can't be used directly. */
static int swdev_sha256(wc_CryptoInfo* info)
{
    wc_Sha256* sha256 = info->hash.sha256;
    wc_Sha256 shadow;
    int ret;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    ret = wc_InitSha256(&shadow);
    if (ret != 0)
        return ret;

    swdev_sha256_copy_state(&shadow, sha256);

    if (info->hash.in != NULL) {
        ret = wc_Sha256Update(&shadow, info->hash.in, info->hash.inSz);
        if (ret != 0)
            goto out;
    }

    if (info->hash.digest != NULL) {
        ret = wc_Sha256Final(&shadow, info->hash.digest);
        if (ret != 0)
            goto out;
    }

    swdev_sha256_copy_state(sha256, &shadow);

out:
    wc_Sha256Free(&shadow);
    return ret;
}
#endif /* !NO_SHA256 */

#ifndef NO_AES
/* Rebuild a software AES shadow from the caller's raw devKey, since the
 * caller's Aes has no software round-key schedule under CB_ONLY_AES. */
static int swdev_aes_shadow_init(Aes* shadow, const Aes* aes, int dir)
{
    int ret;

    if (shadow == NULL || aes == NULL)
        return BAD_FUNC_ARG;
    if (aes->keylen <= 0 || aes->keylen > (int)sizeof(aes->devKey))
        return BAD_FUNC_ARG;

    ret = wc_AesInit(shadow, aes->heap, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_AesSetKey(shadow, (const byte*)aes->devKey,
        (word32)aes->keylen, (const byte*)aes->reg, dir);
    if (ret != 0) {
        wc_AesFree(shadow);
        return ret;
    }

    XMEMCPY(shadow->tmp, aes->tmp, sizeof(shadow->tmp));
#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS) || \
    defined(WOLFSSL_AES_CTS)
    shadow->left = aes->left;
#endif

    return 0;
}

static void swdev_aes_shadow_sync(Aes* dst, const Aes* src)
{
    XMEMCPY(dst->reg, src->reg, sizeof(dst->reg));
    XMEMCPY(dst->tmp, src->tmp, sizeof(dst->tmp));
#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS) || \
    defined(WOLFSSL_AES_CTS)
    dst->left = src->left;
#endif
}

#ifdef HAVE_AES_CBC
static int swdev_aes_cbc(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aescbc.aes;
    byte* out = info->cipher.aescbc.out;
    const byte* in = info->cipher.aescbc.in;
    word32 sz = info->cipher.aescbc.sz;
    Aes shadow;
    int ret;

    ret = swdev_aes_shadow_init(&shadow, aes,
        info->cipher.enc ? AES_ENCRYPTION : AES_DECRYPTION);
    if (ret != 0)
        return ret;

    if (info->cipher.enc)
        ret = wc_AesCbcEncrypt(&shadow, out, in, sz);
#ifdef HAVE_AES_DECRYPT
    else
        ret = wc_AesCbcDecrypt(&shadow, out, in, sz);
#else
    else
        ret = CRYPTOCB_UNAVAILABLE;
#endif
    swdev_aes_shadow_sync(aes, &shadow);
    wc_AesFree(&shadow);
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
static int swdev_aes_ctr(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesctr.aes;
    Aes shadow;
    int ret;

    ret = swdev_aes_shadow_init(&shadow, aes, AES_ENCRYPTION);
    if (ret != 0)
        return ret;

    ret = wc_AesCtrEncrypt(&shadow, info->cipher.aesctr.out,
        info->cipher.aesctr.in, info->cipher.aesctr.sz);
    swdev_aes_shadow_sync(aes, &shadow);
    wc_AesFree(&shadow);
    return ret;
}
#endif

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
static int swdev_aes_ecb(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesecb.aes;
    byte* out = info->cipher.aesecb.out;
    const byte* in = info->cipher.aesecb.in;
    word32 sz = info->cipher.aesecb.sz;
    Aes shadow;
    int ret;

    ret = swdev_aes_shadow_init(&shadow, aes,
        info->cipher.enc ? AES_ENCRYPTION : AES_DECRYPTION);
    if (ret != 0)
        return ret;

#ifdef HAVE_AES_ECB
    if (info->cipher.enc)
        ret = wc_AesEcbEncrypt(&shadow, out, in, sz);
#ifdef HAVE_AES_DECRYPT
    else
        ret = wc_AesEcbDecrypt(&shadow, out, in, sz);
#else
    else
        ret = CRYPTOCB_UNAVAILABLE;
#endif
#elif defined(WOLFSSL_AES_DIRECT)
    if (sz != WC_AES_BLOCK_SIZE) {
        ret = CRYPTOCB_UNAVAILABLE;
    }
    else if (info->cipher.enc) {
        ret = wc_AesEncryptDirect(&shadow, out, in);
    }
#ifdef HAVE_AES_DECRYPT
    else {
        ret = wc_AesDecryptDirect(&shadow, out, in);
    }
#else
    else {
        ret = CRYPTOCB_UNAVAILABLE;
    }
#endif
#else
    (void)out;
    (void)in;
    (void)sz;
    ret = CRYPTOCB_UNAVAILABLE;
#endif

    wc_AesFree(&shadow);
    return ret;
}
#endif /* HAVE_AES_ECB || WOLFSSL_AES_DIRECT */

#ifdef HAVE_AESGCM
static int swdev_aes_gcm(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.enc ? info->cipher.aesgcm_enc.aes :
        info->cipher.aesgcm_dec.aes;
    Aes shadow;
    int ret;

    if (aes == NULL || aes->keylen <= 0 || aes->keylen > (int)sizeof(aes->devKey))
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&shadow, aes->heap, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_AesGcmSetKey(&shadow, (const byte*)aes->devKey, (word32)aes->keylen);
    if (ret != 0) {
        wc_AesFree(&shadow);
        return ret;
    }

    if (info->cipher.enc) {
        ret = wc_AesGcmEncrypt(&shadow,
            info->cipher.aesgcm_enc.out, info->cipher.aesgcm_enc.in,
            info->cipher.aesgcm_enc.sz,
            info->cipher.aesgcm_enc.iv, info->cipher.aesgcm_enc.ivSz,
            info->cipher.aesgcm_enc.authTag,
            info->cipher.aesgcm_enc.authTagSz,
            info->cipher.aesgcm_enc.authIn,
            info->cipher.aesgcm_enc.authInSz);
    }
    else {
        ret = wc_AesGcmDecrypt(&shadow, info->cipher.aesgcm_dec.out,
            info->cipher.aesgcm_dec.in, info->cipher.aesgcm_dec.sz,
            info->cipher.aesgcm_dec.iv, info->cipher.aesgcm_dec.ivSz,
            info->cipher.aesgcm_dec.authTag,
            info->cipher.aesgcm_dec.authTagSz,
            info->cipher.aesgcm_dec.authIn,
            info->cipher.aesgcm_dec.authInSz);
    }

    wc_AesFree(&shadow);
    return ret;
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
static int swdev_aes_ccm(wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.enc ? info->cipher.aesccm_enc.aes :
        info->cipher.aesccm_dec.aes;
    Aes shadow;
    int ret;

    if (aes == NULL || aes->keylen <= 0 || aes->keylen > (int)sizeof(aes->devKey))
        return BAD_FUNC_ARG;

    ret = wc_AesInit(&shadow, aes->heap, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_AesCcmSetKey(&shadow, (const byte*)aes->devKey, (word32)aes->keylen);
    if (ret != 0) {
        wc_AesFree(&shadow);
        return ret;
    }

    if (info->cipher.enc) {
        ret = wc_AesCcmEncrypt(&shadow,
            info->cipher.aesccm_enc.out, info->cipher.aesccm_enc.in,
            info->cipher.aesccm_enc.sz,
            info->cipher.aesccm_enc.nonce,
            info->cipher.aesccm_enc.nonceSz,
            info->cipher.aesccm_enc.authTag,
            info->cipher.aesccm_enc.authTagSz,
            info->cipher.aesccm_enc.authIn,
            info->cipher.aesccm_enc.authInSz);
    }
#ifdef HAVE_AES_DECRYPT
    else {
        ret = wc_AesCcmDecrypt(&shadow, info->cipher.aesccm_dec.out,
            info->cipher.aesccm_dec.in, info->cipher.aesccm_dec.sz,
            info->cipher.aesccm_dec.nonce,
            info->cipher.aesccm_dec.nonceSz,
            info->cipher.aesccm_dec.authTag,
            info->cipher.aesccm_dec.authTagSz,
            info->cipher.aesccm_dec.authIn,
            info->cipher.aesccm_dec.authInSz);
    }
#else
    else {
        ret = CRYPTOCB_UNAVAILABLE;
    }
#endif

    wc_AesFree(&shadow);
    return ret;
}
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */

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
#ifndef NO_SHA256
    case WC_ALGO_TYPE_HASH:
        switch (info->hash.type) {
        case WC_HASH_TYPE_SHA256:
            return swdev_sha256(info);
        default:
            return CRYPTOCB_UNAVAILABLE;
        }
#endif
#ifndef NO_AES
    case WC_ALGO_TYPE_CIPHER:
        switch (info->cipher.type) {
    #ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            return swdev_aes_cbc(info);
    #endif
    #ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            return swdev_aes_ctr(info);
    #endif
    #if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
        case WC_CIPHER_AES_ECB:
            return swdev_aes_ecb(info);
    #endif
    #ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            return swdev_aes_gcm(info);
    #endif
    #ifdef HAVE_AESCCM
        case WC_CIPHER_AES_CCM:
            return swdev_aes_ccm(info);
    #endif
        default:
            return CRYPTOCB_UNAVAILABLE;
        }
#endif /* !NO_AES */
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}
