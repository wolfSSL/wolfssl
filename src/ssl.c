/* ssl.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#if defined(OPENSSL_EXTRA) && !defined(_WIN32) && !defined(_GNU_SOURCE)
    /* turn on GNU extensions for XISASCII */
    #define _GNU_SOURCE 1
#endif

#if !defined(WOLFCRYPT_ONLY) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/kdf.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef HAVE_ERRNO_H
    #include <errno.h>
#endif


#if !defined(WOLFSSL_ALLOW_NO_SUITES) && !defined(WOLFCRYPT_ONLY)
    #if defined(NO_DH) && !defined(HAVE_ECC) && !defined(WOLFSSL_STATIC_RSA) \
                && !defined(WOLFSSL_STATIC_DH) && !defined(WOLFSSL_STATIC_PSK) \
                && !defined(HAVE_CURVE25519) && !defined(HAVE_CURVE448)
        #error "No cipher suites defined because DH disabled, ECC disabled, " \
               "and no static suites defined. Please see top of README"
    #endif
    #ifdef WOLFSSL_CERT_GEN
        /* need access to Cert struct for creating certificate */
        #include <wolfssl/wolfcrypt/asn_public.h>
    #endif
#endif

#if !defined(WOLFCRYPT_ONLY) && (defined(OPENSSL_EXTRA)     \
    || defined(OPENSSL_EXTRA_X509_SMALL)                    \
    || defined(HAVE_WEBSERVER) || defined(WOLFSSL_KEY_GEN))
    #include <wolfssl/openssl/evp.h>
    /* openssl headers end, wolfssl internal headers next */
#endif

#include <wolfssl/wolfcrypt/wc_encrypt.h>

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

#ifdef OPENSSL_EXTRA
    /* openssl headers begin */
    #include <wolfssl/openssl/ssl.h>
    #include <wolfssl/openssl/aes.h>
#ifndef WOLFCRYPT_ONLY
    #include <wolfssl/openssl/hmac.h>
    #include <wolfssl/openssl/cmac.h>
#endif
    #include <wolfssl/openssl/crypto.h>
    #include <wolfssl/openssl/des.h>
    #include <wolfssl/openssl/bn.h>
    #include <wolfssl/openssl/buffer.h>
    #include <wolfssl/openssl/dh.h>
    #include <wolfssl/openssl/rsa.h>
    #include <wolfssl/openssl/fips_rand.h>
    #include <wolfssl/openssl/pem.h>
    #include <wolfssl/openssl/ec.h>
    #include <wolfssl/openssl/ec25519.h>
    #include <wolfssl/openssl/ed25519.h>
    #include <wolfssl/openssl/ec448.h>
    #include <wolfssl/openssl/ed448.h>
    #include <wolfssl/openssl/ecdsa.h>
    #include <wolfssl/openssl/ecdh.h>
    #include <wolfssl/openssl/err.h>
    #include <wolfssl/openssl/modes.h>
    #include <wolfssl/openssl/opensslv.h>
    #include <wolfssl/openssl/rc4.h>
    #include <wolfssl/openssl/stack.h>
    #include <wolfssl/openssl/x509_vfy.h>
    /* openssl headers end, wolfssl internal headers next */
    #include <wolfssl/wolfcrypt/hmac.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <wolfssl/wolfcrypt/des3.h>
    #include <wolfssl/wolfcrypt/ecc.h>
    #include <wolfssl/wolfcrypt/md4.h>
    #include <wolfssl/wolfcrypt/md5.h>
    #include <wolfssl/wolfcrypt/arc4.h>
    #include <wolfssl/wolfcrypt/curve25519.h>
    #include <wolfssl/wolfcrypt/ed25519.h>
    #include <wolfssl/wolfcrypt/curve448.h>
    #if defined(HAVE_FALCON)
        #include <wolfssl/wolfcrypt/falcon.h>
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        #include <wolfssl/wolfcrypt/dilithium.h>
    #endif /* HAVE_DILITHIUM */
    #if defined(HAVE_SPHINCS)
        #include <wolfssl/wolfcrypt/sphincs.h>
    #endif /* HAVE_SPHINCS */
    #if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL)
        #ifdef HAVE_OCSP
            #include <wolfssl/openssl/ocsp.h>
        #endif
        #include <wolfssl/openssl/lhash.h>
        #include <wolfssl/openssl/txt_db.h>
    #endif /* WITH_STUNNEL */
    #if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
        #include <wolfssl/wolfcrypt/sha512.h>
    #endif
    #if defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA256) \
        && !defined(WC_NO_RNG)
        #include <wolfssl/wolfcrypt/srp.h>
    #endif
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    #include <wolfssl/openssl/x509v3.h>
    int wolfssl_bn_get_value(WOLFSSL_BIGNUM* bn, mp_int* mpi);
    int wolfssl_bn_set_value(WOLFSSL_BIGNUM** bn, mp_int* mpi);
#endif

#if defined(WOLFSSL_QT)
    #include <wolfssl/wolfcrypt/sha.h>
#endif

#ifdef NO_ASN
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#endif /* !WOLFCRYPT_ONLY || OPENSSL_EXTRA */

/*
 * OPENSSL_COMPATIBLE_DEFAULTS:
 *     Enable default behaviour that is compatible with OpenSSL. For example
 *     SSL_CTX by default doesn't verify the loaded certs. Enabling this
 *     should make porting to new projects easier.
 * WOLFSSL_CHECK_ALERT_ON_ERR:
 *     Check for alerts during the handshake in the event of an error.
 * NO_SESSION_CACHE_REF:
 *     wolfSSL_get_session on a client will return a reference to the internal
 *     ClientCache by default for backwards compatibility. This define will
 *     make wolfSSL_get_session return a reference to ssl->session. The returned
 *     pointer will be freed with the related WOLFSSL object.
 * SESSION_CACHE_DYNAMIC_MEM:
 *     Dynamically allocate sessions for the session cache from the heap, as
 *     opposed to the default which allocates from the stack.  Allocates
 *     memory only when a session is added to the cache, frees memory after the
 *     session is no longer being used.  Recommended for memory-constrained
 *     systems.
 * WOLFSSL_SYS_CA_CERTS
 *     Enables ability to load system CA certs from the OS via
 *     wolfSSL_CTX_load_system_CA_certs.
 */

#define WOLFSSL_SSL_MISC_INCLUDED
#include "src/ssl_misc.c"

#define WOLFSSL_EVP_INCLUDED
#include "wolfcrypt/src/evp.c"

/* Crypto code uses EVP APIs. */
#define WOLFSSL_SSL_CRYPTO_INCLUDED
#include "src/ssl_crypto.c"

#ifndef WOLFCRYPT_ONLY
#define WOLFSSL_SSL_CERTMAN_INCLUDED
#include "src/ssl_certman.c"

#define WOLFSSL_SSL_SESS_INCLUDED
#include "src/ssl_sess.c"
#endif

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)
/* Convert shortname to NID.
 *
 * For OpenSSL compatibility.
 *
 * This function shouldn't exist!
 * Uses defines in wolfssl/openssl/evp.h.
 * Uses EccEnumToNID which uses defines in wolfssl/openssl/ec.h.
 *
 * @param [in] sn  Short name of OID.
 * @return  NID corresponding to shortname on success.
 * @return  WC_NID_undef when not recognized.
 */
int wc_OBJ_sn2nid(const char *sn)
{
    const struct {
        const char *sn;
        int  nid;
    } sn2nid[] = {
#ifndef NO_CERTS
        {WOLFSSL_COMMON_NAME, WC_NID_commonName},
        {WOLFSSL_COUNTRY_NAME, WC_NID_countryName},
        {WOLFSSL_LOCALITY_NAME, WC_NID_localityName},
        {WOLFSSL_STATE_NAME, WC_NID_stateOrProvinceName},
        {WOLFSSL_ORG_NAME, WC_NID_organizationName},
        {WOLFSSL_ORGUNIT_NAME, WC_NID_organizationalUnitName},
    #ifdef WOLFSSL_CERT_NAME_ALL
        {WOLFSSL_NAME, WC_NID_name},
        {WOLFSSL_INITIALS, WC_NID_initials},
        {WOLFSSL_GIVEN_NAME, WC_NID_givenName},
        {WOLFSSL_DNQUALIFIER, WC_NID_dnQualifier},
    #endif
        {WOLFSSL_EMAIL_ADDR, WC_NID_emailAddress},
#endif
        {"SHA1", WC_NID_sha1},
        {NULL, -1}};
    int i;
#ifdef HAVE_ECC
    char curveName[ECC_MAXNAME + 1];
    int eccEnum;
#endif

    WOLFSSL_ENTER("wc_OBJ_sn2nid");

    for(i=0; sn2nid[i].sn != NULL; i++) {
        if (XSTRCMP(sn, sn2nid[i].sn) == 0) {
            return sn2nid[i].nid;
        }
    }

#ifdef HAVE_ECC
    if (XSTRLEN(sn) > ECC_MAXNAME)
        return WC_NID_undef;

    /* Nginx uses this OpenSSL string. */
    if (XSTRCMP(sn, "prime256v1") == 0)
        sn = "SECP256R1";
    /* OpenSSL allows lowercase curve names */
    for (i = 0; i < (int)(sizeof(curveName) - 1) && *sn; i++) {
        curveName[i] = (char)XTOUPPER((unsigned char) *sn++);
    }
    curveName[i] = '\0';
    /* find based on name and return NID */
    for (i = 0;
#ifndef WOLFSSL_ECC_CURVE_STATIC
         ecc_sets[i].size != 0 && ecc_sets[i].name != NULL;
#else
         ecc_sets[i].size != 0;
#endif
         i++) {
        if (XSTRCMP(curveName, ecc_sets[i].name) == 0) {
            eccEnum = ecc_sets[i].id;
            /* Convert enum value in ecc_curve_id to OpenSSL NID */
            return EccEnumToNID(eccEnum);
        }
    }
#endif /* HAVE_ECC */

    return WC_NID_undef;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifndef WOLFCRYPT_ONLY


#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
/* The system wide crypto-policy. Configured by wolfSSL_crypto_policy_enable.
 * */
static struct SystemCryptoPolicy crypto_policy;
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

#if !defined(NO_RSA) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && !defined(NO_DSA))

#define HAVE_GLOBAL_RNG /* consolidate flags for using globalRNG */
static WC_RNG globalRNG;
static volatile int initGlobalRNG = 0;

static WC_MAYBE_UNUSED wolfSSL_Mutex globalRNGMutex
    WOLFSSL_MUTEX_INITIALIZER_CLAUSE(globalRNGMutex);
#ifndef WOLFSSL_MUTEX_INITIALIZER
static int globalRNGMutex_valid = 0;
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_HASHDRBG)
static WOLFSSL_DRBG_CTX* gDrbgDefCtx = NULL;
#endif

WC_RNG* wolfssl_get_global_rng(void)
{
    WC_RNG* ret = NULL;

    if (initGlobalRNG == 0)
        WOLFSSL_MSG("Global RNG no Init");
    else
        ret = &globalRNG;

    return ret;
}

/* Make a global RNG and return.
 *
 * @return  Global RNG on success.
 * @return  NULL on error.
 */
WC_RNG* wolfssl_make_global_rng(void)
{
    WC_RNG* ret;

#ifdef HAVE_GLOBAL_RNG
    /* Get the global random number generator instead. */
    ret = wolfssl_get_global_rng();
#ifdef OPENSSL_EXTRA
    if (ret == NULL) {
        /* Create a global random if possible. */
        (void)wolfSSL_RAND_Init();
        ret = wolfssl_get_global_rng();
    }
#endif
#else
    WOLFSSL_ERROR_MSG("Bad RNG Init");
    ret = NULL;
#endif

    return ret;
}

/* Too many defines to check explicitly - prototype it and always include
 * for RSA, DH, ECC and DSA for BN. */
WC_RNG* wolfssl_make_rng(WC_RNG* rng, int* local);

/* Make a random number generator or get global if possible.
 *
 * Global may not be available and NULL will be returned.
 *
 * @param [in, out] rng    Local random number generator.
 * @param [out]     local  Local random number generator returned.
 * @return  NULL on failure.
 * @return  A random number generator object.
 */
WC_RNG* wolfssl_make_rng(WC_RNG* rng, int* local)
{
    WC_RNG* ret = NULL;

    /* Assume not local until one created. */
    *local = 0;

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate RNG object . */
    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
#endif
    /* Check we have a local RNG object and initialize. */
    if ((rng != NULL) && (wc_InitRng(rng) == 0)) {
        ret = rng;
        *local = 1;
    }
    if (ret == NULL) {
    #ifdef HAVE_GLOBAL_RNG
        WOLFSSL_MSG("Bad RNG Init, trying global");
    #endif
        ret = wolfssl_make_global_rng();
    }

    if (ret != rng) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(rng, NULL, DYNAMIC_TYPE_RNG);
#endif
    }

    return ret;
}
#endif

#ifdef OPENSSL_EXTRA
    /* WOLFSSL_NO_OPENSSL_RAND_CB: Allows way to reduce code size for
     *                OPENSSL_EXTRA where RAND callbacks are not used */
    #ifndef WOLFSSL_NO_OPENSSL_RAND_CB
        static const WOLFSSL_RAND_METHOD* gRandMethods = NULL;
        static wolfSSL_Mutex gRandMethodMutex
            WOLFSSL_MUTEX_INITIALIZER_CLAUSE(gRandMethodMutex);
        #ifndef WOLFSSL_MUTEX_INITIALIZER
        static int gRandMethodsInit = 0;
        #endif
    #endif /* !WOLFSSL_NO_OPENSSL_RAND_CB */
#endif /* OPENSSL_EXTRA */

#define WOLFSSL_SSL_BN_INCLUDED
#include "src/ssl_bn.c"

#ifndef OPENSSL_EXTRA_NO_ASN1
#define WOLFSSL_SSL_ASN1_INCLUDED
#include "src/ssl_asn1.c"
#endif /* OPENSSL_EXTRA_NO_ASN1 */

#define WOLFSSL_PK_INCLUDED
#include "src/pk.c"

#include <wolfssl/wolfcrypt/hpke.h>

#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH)
/* create the hpke key and ech config to send to clients */
int wolfSSL_CTX_GenerateEchConfig(WOLFSSL_CTX* ctx, const char* publicName,
    word16 kemId, word16 kdfId, word16 aeadId)
{
    int ret = 0;
    word16 encLen = DHKEM_X25519_ENC_LEN;
#ifdef WOLFSSL_SMALL_STACK
    Hpke* hpke = NULL;
    WC_RNG* rng;
#else
    Hpke hpke[1];
    WC_RNG rng[1];
#endif

    if (ctx == NULL || publicName == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), ctx->heap, DYNAMIC_TYPE_RNG);
    if (rng == NULL)
        return MEMORY_E;
#endif
    ret = wc_InitRng(rng);
    if (ret != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(rng, ctx->heap, DYNAMIC_TYPE_RNG);
    #endif
        return ret;
    }

    ctx->echConfigs = (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
        ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx->echConfigs == NULL)
        ret = MEMORY_E;
    else
        XMEMSET(ctx->echConfigs, 0, sizeof(WOLFSSL_EchConfig));

    /* set random config id */
    if (ret == 0)
        ret = wc_RNG_GenerateByte(rng, &ctx->echConfigs->configId);

    /* if 0 is selected for algorithms use default, may change with draft */
    if (kemId == 0)
        kemId = DHKEM_X25519_HKDF_SHA256;

    if (kdfId == 0)
        kdfId = HKDF_SHA256;

    if (aeadId == 0)
        aeadId = HPKE_AES_128_GCM;

    if (ret == 0) {
        /* set the kem id */
        ctx->echConfigs->kemId = kemId;

        /* set the cipher suite, only 1 for now */
        ctx->echConfigs->numCipherSuites = 1;
        ctx->echConfigs->cipherSuites = (EchCipherSuite*)XMALLOC(
            sizeof(EchCipherSuite), ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);

        if (ctx->echConfigs->cipherSuites == NULL) {
            ret = MEMORY_E;
        }
        else {
            ctx->echConfigs->cipherSuites[0].kdfId = kdfId;
            ctx->echConfigs->cipherSuites[0].aeadId = aeadId;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        hpke = (Hpke*)XMALLOC(sizeof(Hpke), ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (hpke == NULL)
            ret = MEMORY_E;
    }
#endif

    if (ret == 0)
        ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, ctx->heap);

    /* generate the receiver private key */
    if (ret == 0)
        ret = wc_HpkeGenerateKeyPair(hpke, &ctx->echConfigs->receiverPrivkey,
            rng);

    /* done with RNG */
    wc_FreeRng(rng);

    /* serialize the receiver key */
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(hpke, ctx->echConfigs->receiverPrivkey,
            ctx->echConfigs->receiverPubkey, &encLen);

    if (ret == 0) {
        ctx->echConfigs->publicName = (char*)XMALLOC(XSTRLEN(publicName) + 1,
            ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx->echConfigs->publicName == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(ctx->echConfigs->publicName, publicName,
                XSTRLEN(publicName) + 1);
        }
    }

    if (ret != 0) {
        if (ctx->echConfigs) {
            XFREE(ctx->echConfigs->cipherSuites, ctx->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(ctx->echConfigs->publicName, ctx->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(ctx->echConfigs, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
            /* set to null to avoid double free in cleanup */
            ctx->echConfigs = NULL;
        }
    }

    if (ret == 0)
        ret = WOLFSSL_SUCCESS;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(hpke, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(rng, ctx->heap, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}

/* get the ech configs that the server context is using */
int wolfSSL_CTX_GetEchConfigs(WOLFSSL_CTX* ctx, byte* output,
    word32* outputLen) {
    if (ctx == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    /* if we don't have ech configs */
    if (ctx->echConfigs == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    return GetEchConfigsEx(ctx->echConfigs, output, outputLen);
}

void wolfSSL_CTX_SetEchEnable(WOLFSSL_CTX* ctx, byte enable)
{
    if (ctx != NULL) {
        ctx->disableECH = !enable;
        if (ctx->disableECH) {
            TLSX_Remove(&ctx->extensions, TLSX_ECH, ctx->heap);
            FreeEchConfigs(ctx->echConfigs, ctx->heap);
            ctx->echConfigs = NULL;
        }
    }
}

/* set the ech config from base64 for our client ssl object, base64 is the
 * format ech configs are sent using dns records */
int wolfSSL_SetEchConfigsBase64(WOLFSSL* ssl, char* echConfigs64,
    word32 echConfigs64Len)
{
    int ret = 0;
    word32 decodedLen = echConfigs64Len * 3 / 4 + 1;
    byte* decodedConfigs;

    if (ssl == NULL || echConfigs64 == NULL || echConfigs64Len == 0)
        return BAD_FUNC_ARG;

    /* already have ech configs */
    if (ssl->options.useEch == 1) {
        return WOLFSSL_FATAL_ERROR;
    }

    decodedConfigs = (byte*)XMALLOC(decodedLen, ssl->heap,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (decodedConfigs == NULL)
        return MEMORY_E;

    decodedConfigs[decodedLen - 1] = 0;

    /* decode the echConfigs */
    ret = Base64_Decode((byte*)echConfigs64, echConfigs64Len,
      decodedConfigs, &decodedLen);

    if (ret != 0) {
        XFREE(decodedConfigs, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wolfSSL_SetEchConfigs(ssl, decodedConfigs, decodedLen);

    XFREE(decodedConfigs, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* set the ech config from a raw buffer, this is the format ech configs are
 * sent using retry_configs from the ech server */
int wolfSSL_SetEchConfigs(WOLFSSL* ssl, const byte* echConfigs,
  word32 echConfigsLen)
{
    int ret = 0;
    int i;
    int j;
    word16 totalLength;
    word16 version;
    word16 length;
    word16 hpkePubkeyLen;
    word16 cipherSuitesLen;
    word16 publicNameLen;
    WOLFSSL_EchConfig* configList = NULL;
    WOLFSSL_EchConfig* workingConfig = NULL;
    WOLFSSL_EchConfig* lastConfig = NULL;
    byte* echConfig = NULL;

    if (ssl == NULL || echConfigs == NULL || echConfigsLen == 0)
        return BAD_FUNC_ARG;

    /* already have ech configs */
    if (ssl->options.useEch == 1) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* check that the total length is well formed */
    ato16(echConfigs, &totalLength);

    if (totalLength != echConfigsLen - 2) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* skip the total length uint16_t */
    i = 2;

    do {
        echConfig = (byte*)echConfigs + i;
        ato16(echConfig, &version);
        ato16(echConfig + 2, &length);

        /* if the version does not match */
        if (version != TLSX_ECH) {
            /* we hit the end of the configs */
            if ( (word32)i + 2 >= echConfigsLen ) {
                break;
            }

            /* skip this config, +4 for version and length */
            i += length + 4;
            continue;
        }

        /* check if the length will overrun the buffer */
        if ((word32)i + length + 4 > echConfigsLen) {
            break;
        }

        if (workingConfig == NULL) {
            workingConfig =
                (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
                ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            configList = workingConfig;
            if (workingConfig != NULL) {
                workingConfig->next = NULL;
            }
        }
        else {
            lastConfig = workingConfig;
            workingConfig->next =
                (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
                ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            workingConfig = workingConfig->next;
        }

        if (workingConfig == NULL) {
            ret = MEMORY_E;
            break;
        }

        XMEMSET(workingConfig, 0, sizeof(WOLFSSL_EchConfig));

        /* rawLen */
        workingConfig->rawLen = length + 4;

        /* raw body */
        workingConfig->raw = (byte*)XMALLOC(workingConfig->rawLen,
            ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->raw == NULL) {
            ret = MEMORY_E;
            break;
        }

        XMEMCPY(workingConfig->raw, echConfig, workingConfig->rawLen);

        /* skip over version and length */
        echConfig += 4;

        /* configId, 1 byte */
        workingConfig->configId = *(echConfig);
        echConfig++;
        /* kemId, 2 bytes */
        ato16(echConfig, &workingConfig->kemId);
        echConfig += 2;
        /* hpke public_key length, 2 bytes */
        ato16(echConfig, &hpkePubkeyLen);
        echConfig += 2;
        /* hpke public_key */
        XMEMCPY(workingConfig->receiverPubkey, echConfig, hpkePubkeyLen);
        echConfig += hpkePubkeyLen;
        /* cipherSuitesLen */
        ato16(echConfig, &cipherSuitesLen);

        workingConfig->cipherSuites = (EchCipherSuite*)XMALLOC(cipherSuitesLen,
            ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->cipherSuites == NULL) {
            ret = MEMORY_E;
            break;
        }

        echConfig += 2;
        workingConfig->numCipherSuites = cipherSuitesLen / 4;
        /* cipherSuites */
        for (j = 0; j < workingConfig->numCipherSuites; j++) {
            ato16(echConfig + j * 4, &workingConfig->cipherSuites[j].kdfId);
            ato16(echConfig + j * 4 + 2,
                &workingConfig->cipherSuites[j].aeadId);
        }
        echConfig += cipherSuitesLen;
        /* publicNameLen */
        ato16(echConfig, &publicNameLen);
        workingConfig->publicName = (char*)XMALLOC(publicNameLen + 1,
            ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->publicName == NULL) {
            ret = MEMORY_E;
            break;
        }

        echConfig += 2;
        /* publicName */
        XMEMCPY(workingConfig->publicName, echConfig, publicNameLen);
        /* null terminated */
        workingConfig->publicName[publicNameLen] = 0;

        /* add length to go to next config, +4 for version and length */
        i += length + 4;

        /* check that we support this config */
        for (j = 0; j < HPKE_SUPPORTED_KEM_LEN; j++) {
            if (hpkeSupportedKem[j] == workingConfig->kemId)
                break;
        }

        /* if we don't support the kem or at least one cipher suite */
        if (j >= HPKE_SUPPORTED_KEM_LEN ||
            EchConfigGetSupportedCipherSuite(workingConfig) < 0)
        {
            XFREE(workingConfig->cipherSuites, ssl->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(workingConfig->publicName, ssl->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(workingConfig->raw, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            workingConfig = lastConfig;
        }
    } while ((word32)i < echConfigsLen);

    /* if we found valid configs */
    if (ret == 0 && configList != NULL) {
        ssl->options.useEch = 1;
        ssl->echConfigs = configList;

        return WOLFSSL_SUCCESS;
    }

    workingConfig = configList;

    while (workingConfig != NULL) {
        lastConfig = workingConfig;
        workingConfig = workingConfig->next;

        XFREE(lastConfig->cipherSuites, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(lastConfig->publicName, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(lastConfig->raw, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

        XFREE(lastConfig, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret == 0)
        return WOLFSSL_FATAL_ERROR;

    return ret;
}

/* get the raw ech config from our struct */
int GetEchConfig(WOLFSSL_EchConfig* config, byte* output, word32* outputLen)
{
    int i;
    word16 totalLen = 0;

    if (config == NULL || (output == NULL && outputLen == NULL))
        return BAD_FUNC_ARG;

    /* 2 for version */
    totalLen += 2;
    /* 2 for length */
    totalLen += 2;
    /* 1 for configId */
    totalLen += 1;
    /* 2 for kemId */
    totalLen += 2;
    /* 2 for hpke_len */
    totalLen += 2;

    /* hpke_pub_key */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            totalLen += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            totalLen += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            totalLen += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            totalLen += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            totalLen += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuitesLen */
    totalLen += 2;
    /* cipherSuites */
    totalLen += config->numCipherSuites * 4;
    /* public name len */
    totalLen += 2;

    /* public name */
    totalLen += XSTRLEN(config->publicName);
    /* trailing zeros */
    totalLen += 2;

    if (output == NULL) {
        *outputLen = totalLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* version */
    c16toa(TLSX_ECH, output);
    output += 2;

    /* length - 4 for version and length itself */
    c16toa(totalLen - 4, output);
    output += 2;

    /* configId */
    *output = config->configId;
    output++;
    /* kemId */
    c16toa(config->kemId, output);
    output += 2;

    /* length and key itself */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            c16toa(DHKEM_P256_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P256_ENC_LEN);
            output += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            c16toa(DHKEM_P384_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P384_ENC_LEN);
            output += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            c16toa(DHKEM_P521_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P521_ENC_LEN);
            output += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            c16toa(DHKEM_X25519_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X25519_ENC_LEN);
            output += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            c16toa(DHKEM_X448_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X448_ENC_LEN);
            output += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuites len */
    c16toa(config->numCipherSuites * 4, output);
    output += 2;

    /* cipherSuites */
    for (i = 0; i < config->numCipherSuites; i++) {
        c16toa(config->cipherSuites[i].kdfId, output);
        output += 2;
        c16toa(config->cipherSuites[i].aeadId, output);
        output += 2;
    }

    /* publicName len */
    c16toa(XSTRLEN(config->publicName), output);
    output += 2;

    /* publicName */
    XMEMCPY(output, config->publicName,
        XSTRLEN(config->publicName));
    output += XSTRLEN(config->publicName);

    /* terminating zeros */
    c16toa(0, output);
    /* output += 2; */

    *outputLen = totalLen;

    return 0;
}

/* wrapper function to get ech configs from application code */
int wolfSSL_GetEchConfigs(WOLFSSL* ssl, byte* output, word32* outputLen)
{
    if (ssl == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    /* if we don't have ech configs */
    if (ssl->options.useEch != 1) {
        return WOLFSSL_FATAL_ERROR;
    }

    return GetEchConfigsEx(ssl->echConfigs, output, outputLen);
}

void wolfSSL_SetEchEnable(WOLFSSL* ssl, byte enable)
{
    if (ssl != NULL) {
        ssl->options.disableECH = !enable;
        if (ssl->options.disableECH) {
            TLSX_Remove(&ssl->extensions, TLSX_ECH, ssl->heap);
            FreeEchConfigs(ssl->echConfigs, ssl->heap);
            ssl->echConfigs = NULL;
        }
    }
}

/* get the raw ech configs from our linked list of ech config structs */
int GetEchConfigsEx(WOLFSSL_EchConfig* configs, byte* output, word32* outputLen)
{
    int ret = 0;
    WOLFSSL_EchConfig* workingConfig = NULL;
    byte* outputStart = output;
    word32 totalLen = 2;
    word32 workingOutputLen;

    if (configs == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    workingOutputLen = *outputLen - totalLen;

    /* skip over total length which we fill in later */
    if (output != NULL)
        output += 2;

    workingConfig = configs;

    while (workingConfig != NULL) {
        /* get this config */
        ret = GetEchConfig(workingConfig, output, &workingOutputLen);

        if (output != NULL)
            output += workingOutputLen;

        /* add this config's length to the total length */
        totalLen += workingOutputLen;

        if (totalLen > *outputLen)
            workingOutputLen = 0;
        else
            workingOutputLen = *outputLen - totalLen;

        /* only error we break on, other 2 we need to keep finding length */
        if (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG))
            return BAD_FUNC_ARG;

        workingConfig = workingConfig->next;
    }

    if (output == NULL) {
        *outputLen = totalLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* total size -2 for size itself */
    c16toa(totalLen - 2, outputStart);

    *outputLen = totalLen;

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TLS13 && HAVE_ECH */

#ifdef OPENSSL_EXTRA
static int wolfSSL_parse_cipher_list(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
        Suites* suites, const char* list);
#endif

#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

/* prevent multiple mutex initializations */
static volatile WC_THREADSHARED int initRefCount = 0;
/* init ref count mutex */
static WC_THREADSHARED wolfSSL_Mutex inits_count_mutex
    WOLFSSL_MUTEX_INITIALIZER_CLAUSE(inits_count_mutex);
#ifndef WOLFSSL_MUTEX_INITIALIZER
static WC_THREADSHARED volatile int inits_count_mutex_valid = 0;
#endif

#ifdef NO_TLS
static const WOLFSSL_METHOD gNoTlsMethod;
#endif

/* Create a new WOLFSSL_CTX struct and return the pointer to created struct.
   WOLFSSL_METHOD pointer passed in is given to ctx to manage.
   This function frees the passed in WOLFSSL_METHOD struct on failure and on
   success is freed when ctx is freed.
 */
WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap)
{
    WOLFSSL_CTX* ctx = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_new_ex");

    if (initRefCount == 0) {
        /* user no longer forced to call Init themselves */
        int ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_Init failed");
            WOLFSSL_LEAVE("wolfSSL_CTX_new_ex", 0);
            XFREE(method, heap, DYNAMIC_TYPE_METHOD);
            return NULL;
        }
    }

#ifndef NO_TLS
    if (method == NULL)
        return ctx;
#else
    /* a blank TLS method */
    method = (WOLFSSL_METHOD*)&gNoTlsMethod;
#endif

    ctx = (WOLFSSL_CTX*)XMALLOC(sizeof(WOLFSSL_CTX), heap, DYNAMIC_TYPE_CTX);
    if (ctx) {
        int ret;

        ret = InitSSL_Ctx(ctx, method, heap);
    #ifdef WOLFSSL_STATIC_MEMORY
        if (heap != NULL) {
            ctx->onHeapHint = 1; /* free the memory back to heap when done */
        }
    #endif
        if (ret < 0) {
            WOLFSSL_MSG("Init CTX failed");
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
#if defined(OPENSSL_EXTRA) && defined(WOLFCRYPT_HAVE_SRP) \
                           && !defined(NO_SHA256) && !defined(WC_NO_RNG)
        else {
            ctx->srp = (Srp*)XMALLOC(sizeof(Srp), heap, DYNAMIC_TYPE_SRP);
            if (ctx->srp == NULL){
                WOLFSSL_MSG("Init CTX failed");
                wolfSSL_CTX_free(ctx);
                return NULL;
            }
            XMEMSET(ctx->srp, 0, sizeof(Srp));
        }
#endif
    }
    else {
        WOLFSSL_MSG("Alloc CTX failed, method freed");
        XFREE(method, heap, DYNAMIC_TYPE_METHOD);
    }

#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    if (ctx) {
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        wolfSSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        if (wolfSSL_CTX_set_min_proto_version(ctx,
                (method->version.major == DTLS_MAJOR) ?
                DTLS1_VERSION : SSL3_VERSION) != WOLFSSL_SUCCESS ||
#ifdef HAVE_ANON
                wolfSSL_CTX_allow_anon_cipher(ctx) != WOLFSSL_SUCCESS ||
#endif
                wolfSSL_CTX_set_group_messages(ctx) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Setting OpenSSL CTX defaults failed");
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }
#endif

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    /* Load the crypto-policy ciphers if configured. */
    if (ctx && wolfSSL_crypto_policy_is_enabled()) {
        const char * list = wolfSSL_crypto_policy_get_ciphers();
        int          ret = 0;

        if (list != NULL && *list != '\0') {
            if (AllocateCtxSuites(ctx) != 0) {
                WOLFSSL_MSG("allocate ctx suites failed");
                wolfSSL_CTX_free(ctx);
                ctx = NULL;
            }
            else {
                ret = wolfSSL_parse_cipher_list(ctx, NULL, ctx->suites, list);
                if (ret != WOLFSSL_SUCCESS) {
                    WOLFSSL_MSG("parse cipher list failed");
                    wolfSSL_CTX_free(ctx);
                    ctx = NULL;
                }
            }
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    WOLFSSL_LEAVE("wolfSSL_CTX_new_ex", 0);
    return ctx;
}


WOLFSSL_ABI
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
#ifdef WOLFSSL_HEAP_TEST
    /* if testing the heap hint then set top level CTX to have test value */
    return wolfSSL_CTX_new_ex(method, (void*)WOLFSSL_HEAP_TEST);
#else
    return wolfSSL_CTX_new_ex(method, NULL);
#endif
}

/* increases CTX reference count to track proper time to "free" */
int wolfSSL_CTX_up_ref(WOLFSSL_CTX* ctx)
{
    int ret;
    wolfSSL_RefWithMutexInc(&ctx->ref, &ret);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    return ((ret == 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE);
#else
    (void)ret;
    return WOLFSSL_SUCCESS;
#endif
}

WOLFSSL_ABI
void wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_free");
    if (ctx) {
#if defined(OPENSSL_EXTRA) && defined(WOLFCRYPT_HAVE_SRP) \
&& !defined(NO_SHA256) && !defined(WC_NO_RNG)
        if (ctx->srp != NULL) {
            XFREE(ctx->srp_password, ctx->heap, DYNAMIC_TYPE_SRP);
            ctx->srp_password = NULL;
            wc_SrpTerm(ctx->srp);
            XFREE(ctx->srp, ctx->heap, DYNAMIC_TYPE_SRP);
            ctx->srp = NULL;
        }
#endif
        FreeSSL_Ctx(ctx);
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_free", 0);
}


#ifdef HAVE_ENCRYPT_THEN_MAC
/**
 * Sets whether Encrypt-Then-MAC extension can be negotiated against context.
 * The default value: enabled.
 *
 * ctx  SSL/TLS context.
 * set  Whether to allow or not: 1 is allow and 0 is disallow.
 * returns WOLFSSL_SUCCESS
 */
int wolfSSL_CTX_AllowEncryptThenMac(WOLFSSL_CTX *ctx, int set)
{
    ctx->disallowEncThenMac = !set;
    return WOLFSSL_SUCCESS;
}

/**
 * Sets whether Encrypt-Then-MAC extension can be negotiated against context.
 * The default value comes from context.
 *
 * ctx  SSL/TLS context.
 * set  Whether to allow or not: 1 is allow and 0 is disallow.
 * returns WOLFSSL_SUCCESS
 */
int wolfSSL_AllowEncryptThenMac(WOLFSSL *ssl, int set)
{
    ssl->options.disallowEncThenMac = !set;
    return WOLFSSL_SUCCESS;
}
#endif

#ifdef SINGLE_THREADED
/* no locking in single threaded mode, allow a CTX level rng to be shared with
 * WOLFSSL objects, WOLFSSL_SUCCESS on ok */
int wolfSSL_CTX_new_rng(WOLFSSL_CTX* ctx)
{
    WC_RNG* rng;
    int     ret;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), ctx->heap, DYNAMIC_TYPE_RNG);
    if (rng == NULL) {
        return MEMORY_E;
    }

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(rng, ctx->heap, ctx->devId);
#else
    ret = wc_InitRng(rng);
#endif
    if (ret != 0) {
        XFREE(rng, ctx->heap, DYNAMIC_TYPE_RNG);
        return ret;
    }

    ctx->rng = rng;
    return WOLFSSL_SUCCESS;
}
#endif


WOLFSSL_ABI
WOLFSSL* wolfSSL_new(WOLFSSL_CTX* ctx)
{
    WOLFSSL* ssl = NULL;
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_new");

    if (ctx == NULL) {
        WOLFSSL_MSG("wolfSSL_new ctx is null");
        return NULL;
    }

    ssl = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), ctx->heap, DYNAMIC_TYPE_SSL);

    if (ssl == NULL) {
        WOLFSSL_MSG_EX("ssl xmalloc failed to allocate %d bytes",
                        (int)sizeof(WOLFSSL));
    }
    else {
        ret = InitSSL(ssl, ctx, 0);
        if (ret < 0) {
            WOLFSSL_MSG_EX("wolfSSL_new failed during InitSSL. err = %d", ret);
            FreeSSL(ssl, ctx->heap);
            ssl = NULL;
        }
        else if (ret == 0) {
            WOLFSSL_MSG("wolfSSL_new InitSSL success");
        }
        else {
            /* Only success (0) or negative values should ever be seen. */
            WOLFSSL_MSG_EX("WARNING: wolfSSL_new unexpected InitSSL return"
                           " value = %d", ret);
        } /* InitSSL check */
    } /* ssl XMALLOC success */

    WOLFSSL_LEAVE("wolfSSL_new InitSSL =", ret);
    (void)ret;

    return ssl;
}


WOLFSSL_ABI
void wolfSSL_free(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_free");

    if (ssl) {
        WOLFSSL_MSG_EX("Free SSL: %p", (wc_ptr_t)ssl);
        FreeSSL(ssl, ssl->ctx->heap);
    }
    else {
        WOLFSSL_MSG("Free SSL: wolfSSL_free already null");
    }
    WOLFSSL_LEAVE("wolfSSL_free", 0);
}


int wolfSSL_is_server(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    return ssl->options.side == WOLFSSL_SERVER_END;
}

#ifdef HAVE_WRITE_DUP

/*
 * Release resources around WriteDup object
 *
 * ssl WOLFSSL object
 *
 * no return, destruction so make best attempt
*/
void FreeWriteDup(WOLFSSL* ssl)
{
    int doFree = 0;

    WOLFSSL_ENTER("FreeWriteDup");

    if (ssl->dupWrite) {
        if (wc_LockMutex(&ssl->dupWrite->dupMutex) == 0) {
            ssl->dupWrite->dupCount--;
            if (ssl->dupWrite->dupCount == 0) {
                doFree = 1;
            } else {
                WOLFSSL_MSG("WriteDup count not zero, no full free");
            }
            wc_UnLockMutex(&ssl->dupWrite->dupMutex);
        }
    }

    if (doFree) {
        WOLFSSL_MSG("Doing WriteDup full free, count to zero");
        wc_FreeMutex(&ssl->dupWrite->dupMutex);
        XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
    }
}


/*
 * duplicate existing ssl members into dup needed for writing
 *
 * dup write only WOLFSSL
 * ssl existing WOLFSSL
 *
 * 0 on success
*/
static int DupSSL(WOLFSSL* dup, WOLFSSL* ssl)
{
    word16 tmp_weOwnRng;

    /* shared dupWrite setup */
    ssl->dupWrite = (WriteDup*)XMALLOC(sizeof(WriteDup), ssl->heap,
                                       DYNAMIC_TYPE_WRITEDUP);
    if (ssl->dupWrite == NULL) {
        return MEMORY_E;
    }
    XMEMSET(ssl->dupWrite, 0, sizeof(WriteDup));

    if (wc_InitMutex(&ssl->dupWrite->dupMutex) != 0) {
        XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
        ssl->dupWrite = NULL;
        return BAD_MUTEX_E;
    }
    ssl->dupWrite->dupCount = 2;    /* both sides have a count to start */
    dup->dupWrite = ssl->dupWrite; /* each side uses */

    tmp_weOwnRng = dup->options.weOwnRng;

    /* copy write parts over to dup writer */
    XMEMCPY(&dup->specs,   &ssl->specs,   sizeof(CipherSpecs));
    XMEMCPY(&dup->options, &ssl->options, sizeof(Options));
    XMEMCPY(&dup->keys,    &ssl->keys,    sizeof(Keys));
    XMEMCPY(&dup->encrypt, &ssl->encrypt, sizeof(Ciphers));
    XMEMCPY(&dup->version, &ssl->version, sizeof(ProtocolVersion));
    XMEMCPY(&dup->chVersion, &ssl->chVersion, sizeof(ProtocolVersion));

#ifdef HAVE_ONE_TIME_AUTH
#ifdef HAVE_POLY1305
    if (ssl->auth.setup && ssl->auth.poly1305 != NULL) {
        dup->auth.poly1305 = (Poly1305*)XMALLOC(sizeof(Poly1305), dup->heap,
            DYNAMIC_TYPE_CIPHER);
        if (dup->auth.poly1305 == NULL)
            return MEMORY_E;
        dup->auth.setup = 1;
    }
#endif
#endif

    /* dup side now owns encrypt/write ciphers */
    XMEMSET(&ssl->encrypt, 0, sizeof(Ciphers));

    dup->IOCB_WriteCtx = ssl->IOCB_WriteCtx;
    dup->CBIOSend = ssl->CBIOSend;
#ifdef OPENSSL_EXTRA
    dup->cbioFlag = ssl->cbioFlag;
#endif
    dup->wfd    = ssl->wfd;
    dup->wflags = ssl->wflags;
#ifndef WOLFSSL_AEAD_ONLY
    dup->hmac   = ssl->hmac;
#endif
#ifdef HAVE_TRUNCATED_HMAC
    dup->truncated_hmac = ssl->truncated_hmac;
#endif

    /* Restore rng option */
    dup->options.weOwnRng = tmp_weOwnRng;

    /* unique side dup setup */
    dup->dupSide = WRITE_DUP_SIDE;
    ssl->dupSide = READ_DUP_SIDE;

    return 0;
}


/*
 * duplicate a WOLFSSL object post handshake for writing only
 * turn existing object into read only.  Allows concurrent access from two
 * different threads.
 *
 * ssl existing WOLFSSL object
 *
 * return dup'd WOLFSSL object on success
*/
WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl)
{
    WOLFSSL* dup = NULL;
    int ret = 0;

    (void)ret;
    WOLFSSL_ENTER("wolfSSL_write_dup");

    if (ssl == NULL) {
        return ssl;
    }

    if (ssl->options.handShakeDone == 0) {
        WOLFSSL_MSG("wolfSSL_write_dup called before handshake complete");
        return NULL;
    }

    if (ssl->dupWrite) {
        WOLFSSL_MSG("wolfSSL_write_dup already called once");
        return NULL;
    }

    dup = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), ssl->ctx->heap, DYNAMIC_TYPE_SSL);
    if (dup) {
        if ( (ret = InitSSL(dup, ssl->ctx, 1)) < 0) {
            FreeSSL(dup, ssl->ctx->heap);
            dup = NULL;
        } else if ( (ret = DupSSL(dup, ssl)) < 0) {
            FreeSSL(dup, ssl->ctx->heap);
            dup = NULL;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_write_dup", ret);

    return dup;
}


/*
 * Notify write dup side of fatal error or close notify
 *
 * ssl WOLFSSL object
 * err Notify err
 *
 * 0 on success
*/
int NotifyWriteSide(WOLFSSL* ssl, int err)
{
    int ret;

    WOLFSSL_ENTER("NotifyWriteSide");

    ret = wc_LockMutex(&ssl->dupWrite->dupMutex);
    if (ret == 0) {
        ssl->dupWrite->dupErr = err;
        ret = wc_UnLockMutex(&ssl->dupWrite->dupMutex);
    }

    return ret;
}


#endif /* HAVE_WRITE_DUP */


#ifdef HAVE_POLY1305
/* set if to use old poly 1 for yes 0 to use new poly */
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value)
{
    (void)ssl;
    (void)value;

#ifndef WOLFSSL_NO_TLS12
    WOLFSSL_ENTER("wolfSSL_use_old_poly");
    WOLFSSL_MSG("Warning SSL connection auto detects old/new and this function"
            "is depreciated");
    ssl->options.oldPoly = (word16)value;
    WOLFSSL_LEAVE("wolfSSL_use_old_poly", 0);
#endif
    return 0;
}
#endif


WOLFSSL_ABI
int wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_set_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_set_read_fd(ssl, fd);
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_set_write_fd(ssl, fd);
    }

    return ret;
}

#ifdef WOLFSSL_DTLS
int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_set_dtls_fd_connected");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_set_fd(ssl, fd);
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.connected = 1;

    return ret;
}
#endif


int wolfSSL_set_read_fd(WOLFSSL* ssl, int fd)
{
    WOLFSSL_ENTER("wolfSSL_set_read_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->rfd = fd;      /* not used directly to allow IO callbacks */
    ssl->IOCB_ReadCtx  = &ssl->rfd;

    #ifdef WOLFSSL_DTLS
        ssl->buffers.dtlsCtx.connected = 0;
        if (ssl->options.dtls) {
            ssl->IOCB_ReadCtx = &ssl->buffers.dtlsCtx;
            ssl->buffers.dtlsCtx.rfd = fd;
        }
    #endif

    WOLFSSL_LEAVE("wolfSSL_set_read_fd", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}


int wolfSSL_set_write_fd(WOLFSSL* ssl, int fd)
{
    WOLFSSL_ENTER("wolfSSL_set_write_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->wfd = fd;      /* not used directly to allow IO callbacks */
    ssl->IOCB_WriteCtx  = &ssl->wfd;

    #ifdef WOLFSSL_DTLS
        ssl->buffers.dtlsCtx.connected = 0;
        if (ssl->options.dtls) {
            ssl->IOCB_WriteCtx = &ssl->buffers.dtlsCtx;
            ssl->buffers.dtlsCtx.wfd = fd;
        }
    #endif

    WOLFSSL_LEAVE("wolfSSL_set_write_fd", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}


/**
  * Get the name of cipher at priority level passed in.
  */
char* wolfSSL_get_cipher_list(int priority)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();

    if (priority >= GetCipherNamesSize() || priority < 0) {
        return 0;
    }

    return (char*)ciphers[priority].name;
}


/**
  * Get the name of cipher at priority level passed in.
  */
char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority)
{

    if (ssl == NULL) {
        return NULL;
    }
    else {
        const char* cipher;

        if ((cipher = wolfSSL_get_cipher_name_internal(ssl)) != NULL) {
            if (priority == 0) {
                return (char*)cipher;
            }
            else {
                return NULL;
            }
        }
        else {
            return wolfSSL_get_cipher_list(priority);
        }
    }
}


int wolfSSL_get_ciphers(char* buf, int len)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();
    int ciphersSz = GetCipherNamesSize();
    int i;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimited by a : */
    for (i = 0; i < ciphersSz; i++) {
        int cipherNameSz = (int)XSTRLEN(ciphers[i].name);
        if (cipherNameSz + 1 < len) {
            XSTRNCPY(buf, ciphers[i].name, len);
            buf += cipherNameSz;

            if (i < ciphersSz - 1)
                *buf++ = ':';
            *buf = 0;

            len -= cipherNameSz + 1;
        }
        else
            return BUFFER_E;
    }
    return WOLFSSL_SUCCESS;
}


#ifndef NO_ERROR_STRINGS
/* places a list of all supported cipher suites in TLS_* format into "buf"
 * return WOLFSSL_SUCCESS on success */
int wolfSSL_get_ciphers_iana(char* buf, int len)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();
    int ciphersSz = GetCipherNamesSize();
    int i;
    int cipherNameSz;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimited by a : */
    for (i = 0; i < ciphersSz; i++) {
#ifndef NO_CIPHER_SUITE_ALIASES
        if (ciphers[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS)
            continue;
#endif
        cipherNameSz = (int)XSTRLEN(ciphers[i].name_iana);
        if (cipherNameSz + 1 < len) {
            XSTRNCPY(buf, ciphers[i].name_iana, len);
            buf += cipherNameSz;

            if (i < ciphersSz - 1)
                *buf++ = ':';
            *buf = 0;

            len -= cipherNameSz + 1;
        }
        else
            return BUFFER_E;
    }
    return WOLFSSL_SUCCESS;
}
#endif /* NO_ERROR_STRINGS */


const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf, int len)
{
    const char* cipher;

    if (ssl == NULL)
        return NULL;

    cipher = wolfSSL_get_cipher_name_iana(ssl);
    len = (int)min((word32)len, (word32)(XSTRLEN(cipher) + 1));
    XMEMCPY(buf, cipher, len);
    return buf;
}

int wolfSSL_get_fd(const WOLFSSL* ssl)
{
    int fd = -1;
    WOLFSSL_ENTER("wolfSSL_get_fd");
    if (ssl) {
        fd = ssl->rfd;
    }
    WOLFSSL_LEAVE("wolfSSL_get_fd", fd);
    return fd;
}

int wolfSSL_get_wfd(const WOLFSSL* ssl)
{
    int fd = -1;
    WOLFSSL_ENTER("wolfSSL_get_fd");
    if (ssl) {
        fd = ssl->wfd;
    }
    WOLFSSL_LEAVE("wolfSSL_get_fd", fd);
    return fd;
}


int wolfSSL_dtls(WOLFSSL* ssl)
{
    int dtlsOpt = 0;
    if (ssl)
        dtlsOpt = ssl->options.dtls;
    return dtlsOpt;
}

#if !defined(NO_CERTS)
/* Set whether mutual authentication is required for connections.
 * Server side only.
 *
 * ctx  The SSL/TLS CTX object.
 * req  1 to indicate required and 0 when not.
 * returns BAD_FUNC_ARG when ctx is NULL, SIDE_ERROR when not a server and
 * 0 on success.
 */
int wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (ctx->method->side == WOLFSSL_CLIENT_END)
        return SIDE_ERROR;

    ctx->mutualAuth = (byte)req;

    return 0;
}

/* Set whether mutual authentication is required for the connection.
 * Server side only.
 *
 * ssl  The SSL/TLS object.
 * req  1 to indicate required and 0 when not.
 * returns BAD_FUNC_ARG when ssl is NULL, or not using TLS v1.3,
 * SIDE_ERROR when not a client and 0 on success.
 */
int wolfSSL_mutual_auth(WOLFSSL* ssl, int req)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    if (ssl->options.side == WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    ssl->options.mutualAuth = (word16)req;

    return 0;
}
#endif /* NO_CERTS */

#ifdef WOLFSSL_WOLFSENTRY_HOOKS

int wolfSSL_CTX_set_AcceptFilter(
    WOLFSSL_CTX *ctx,
    NetworkFilterCallback_t AcceptFilter,
    void *AcceptFilter_arg)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    ctx->AcceptFilter = AcceptFilter;
    ctx->AcceptFilter_arg = AcceptFilter_arg;
    return 0;
}

int wolfSSL_set_AcceptFilter(
    WOLFSSL *ssl,
    NetworkFilterCallback_t AcceptFilter,
    void *AcceptFilter_arg)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    ssl->AcceptFilter = AcceptFilter;
    ssl->AcceptFilter_arg = AcceptFilter_arg;
    return 0;
}

int wolfSSL_CTX_set_ConnectFilter(
    WOLFSSL_CTX *ctx,
    NetworkFilterCallback_t ConnectFilter,
    void *ConnectFilter_arg)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    ctx->ConnectFilter = ConnectFilter;
    ctx->ConnectFilter_arg = ConnectFilter_arg;
    return 0;
}

int wolfSSL_set_ConnectFilter(
    WOLFSSL *ssl,
    NetworkFilterCallback_t ConnectFilter,
    void *ConnectFilter_arg)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    ssl->ConnectFilter = ConnectFilter;
    ssl->ConnectFilter_arg = ConnectFilter_arg;
    return 0;
}

#endif /* WOLFSSL_WOLFSENTRY_HOOKS */

#ifndef WOLFSSL_LEANPSK
#if defined(WOLFSSL_DTLS) && defined(XINET_PTON) && \
    !defined(WOLFSSL_NO_SOCK) && defined(HAVE_SOCKADDR)
void* wolfSSL_dtls_create_peer(int port, char* ip)
{
    SOCKADDR_IN *addr;
    addr = (SOCKADDR_IN*)XMALLOC(sizeof(*addr), NULL,
            DYNAMIC_TYPE_SOCKADDR);
    if (addr == NULL) {
        return NULL;
    }

    addr->sin_family = AF_INET;
    addr->sin_port = XHTONS((word16)port);
    if (XINET_PTON(AF_INET, ip, &addr->sin_addr) < 1) {
        XFREE(addr, NULL, DYNAMIC_TYPE_SOCKADDR);
        return NULL;
    }

    return addr;
}

int wolfSSL_dtls_free_peer(void* addr)
{
    XFREE(addr, NULL, DYNAMIC_TYPE_SOCKADDR);
    return WOLFSSL_SUCCESS;
}
#endif

#ifdef WOLFSSL_DTLS
static int SockAddrSet(WOLFSSL_SOCKADDR* sockAddr, void* peer,
                       unsigned int peerSz, void* heap)
{
    if (peer == NULL || peerSz == 0) {
        if (sockAddr->sa != NULL)
            XFREE(sockAddr->sa, heap, DYNAMIC_TYPE_SOCKADDR);
        sockAddr->sa = NULL;
        sockAddr->sz = 0;
        sockAddr->bufSz = 0;
        return WOLFSSL_SUCCESS;
    }

    if (peerSz > sockAddr->bufSz) {
        if (sockAddr->sa != NULL)
            XFREE(sockAddr->sa, heap, DYNAMIC_TYPE_SOCKADDR);
        sockAddr->sa =
                (void*)XMALLOC(peerSz, heap, DYNAMIC_TYPE_SOCKADDR);
        if (sockAddr->sa == NULL) {
            sockAddr->sz = 0;
            sockAddr->bufSz = 0;
            return WOLFSSL_FAILURE;
        }
        sockAddr->bufSz = peerSz;
    }
    XMEMCPY(sockAddr->sa, peer, peerSz);
    sockAddr->sz = peerSz;
    return WOLFSSL_SUCCESS;
}
#endif

int wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Wr(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    ret = SockAddrSet(&ssl->buffers.dtlsCtx.peer, peer, peerSz, ssl->heap);
    if (ret == WOLFSSL_SUCCESS && !(peer == NULL || peerSz == 0))
        ssl->buffers.dtlsCtx.userSet = 1;
    else
        ssl->buffers.dtlsCtx.userSet = 0;
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}

#if defined(WOLFSSL_DTLS_CID) && !defined(WOLFSSL_NO_SOCK)
int wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Rd(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    if (ssl->buffers.dtlsCtx.peer.sa != NULL &&
            ssl->buffers.dtlsCtx.peer.sz == peerSz &&
            sockAddrEqual((SOCKADDR_S*)ssl->buffers.dtlsCtx.peer.sa,
                    (XSOCKLENT)ssl->buffers.dtlsCtx.peer.sz, (SOCKADDR_S*)peer,
                    (XSOCKLENT)peerSz)) {
        /* Already the current peer. */
        if (ssl->buffers.dtlsCtx.pendingPeer.sa != NULL) {
            /* Clear any other pendingPeer */
            XFREE(ssl->buffers.dtlsCtx.pendingPeer.sa, ssl->heap,
                  DYNAMIC_TYPE_SOCKADDR);
            ssl->buffers.dtlsCtx.pendingPeer.sa = NULL;
            ssl->buffers.dtlsCtx.pendingPeer.sz = 0;
            ssl->buffers.dtlsCtx.pendingPeer.bufSz = 0;
        }
        ret = WOLFSSL_SUCCESS;
    }
    else {
        ret = SockAddrSet(&ssl->buffers.dtlsCtx.pendingPeer, peer, peerSz,
                ssl->heap);
    }
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.processingPendingRecord = 0;
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}
#endif /* WOLFSSL_DTLS_CID && !WOLFSSL_NO_SOCK */

int wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Rd(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    if (peer != NULL && peerSz != NULL
            && *peerSz >= ssl->buffers.dtlsCtx.peer.sz
            && ssl->buffers.dtlsCtx.peer.sa != NULL) {
        *peerSz = ssl->buffers.dtlsCtx.peer.sz;
        XMEMCPY(peer, ssl->buffers.dtlsCtx.peer.sa, *peerSz);
        ret = WOLFSSL_SUCCESS;
    }
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}

int wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                           unsigned int* peerSz)
{
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_RW_THREADED)
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    if (peer == NULL || peerSz == NULL)
        return WOLFSSL_FAILURE;

    *peer = ssl->buffers.dtlsCtx.peer.sa;
    *peerSz = ssl->buffers.dtlsCtx.peer.sz;
    return WOLFSSL_SUCCESS;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}


#if defined(WOLFSSL_SCTP) && defined(WOLFSSL_DTLS)

int wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_dtls_set_sctp");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->dtlsSctp = 1;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_dtls_set_sctp(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_dtls_set_sctp");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.dtlsSctp = 1;
    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_DTLS && WOLFSSL_SCTP */

#if (defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)) && \
                                                           defined(WOLFSSL_DTLS)

int wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX* ctx, word16 newMtu)
{
    if (ctx == NULL || newMtu > MAX_RECORD_SIZE)
        return BAD_FUNC_ARG;

    ctx->dtlsMtuSz = newMtu;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (newMtu > MAX_RECORD_SIZE) {
        ssl->error = BAD_FUNC_ARG;
        return WOLFSSL_FAILURE;
    }

    ssl->dtlsMtuSz = newMtu;
    return WOLFSSL_SUCCESS;
}

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
int wolfSSL_set_mtu_compat(WOLFSSL* ssl, unsigned short mtu) {
    if (wolfSSL_dtls_set_mtu(ssl, mtu) == 0)
        return WOLFSSL_SUCCESS;
    else
        return WOLFSSL_FAILURE;
}
#endif /* OPENSSL_ALL || OPENSSL_EXTRA */

#endif /* WOLFSSL_DTLS && (WOLFSSL_SCTP || WOLFSSL_DTLS_MTU) */

#ifdef WOLFSSL_SRTP

static const WOLFSSL_SRTP_PROTECTION_PROFILE gSrtpProfiles[] = {
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 80-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_80", SRTP_AES128_CM_SHA1_80,
     (((128 + 112) * 2) / 8) },
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 32-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_32", SRTP_AES128_CM_SHA1_32,
     (((128 + 112) * 2) / 8) },
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 80-bits */
    {"SRTP_NULL_SHA1_80", SRTP_NULL_SHA1_80, ((112 * 2) / 8)},
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 32-bits */
    {"SRTP_NULL_SHA1_32", SRTP_NULL_SHA1_32, ((112 * 2) / 8)},
    /* AES GCM 128, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:128bits + master_salt:96bits) * 2 = 448 bits (56) */
    {"SRTP_AEAD_AES_128_GCM", SRTP_AEAD_AES_128_GCM, (((128 + 96) * 2) / 8) },
    /* AES GCM 256, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:256bits + master_salt:96bits) * 2 = 704 bits (88) */
    {"SRTP_AEAD_AES_256_GCM", SRTP_AEAD_AES_256_GCM, (((256 + 96) * 2) / 8) },
};

static const WOLFSSL_SRTP_PROTECTION_PROFILE* DtlsSrtpFindProfile(
    const char* profile_str, word32 profile_str_len, unsigned long id)
{
    int i;
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    for (i=0;
         i<(int)(sizeof(gSrtpProfiles)/sizeof(WOLFSSL_SRTP_PROTECTION_PROFILE));
         i++) {
        if (profile_str != NULL) {
            word32 srtp_profile_len = (word32)XSTRLEN(gSrtpProfiles[i].name);
            if (srtp_profile_len == profile_str_len &&
                XMEMCMP(gSrtpProfiles[i].name, profile_str, profile_str_len)
                                                                         == 0) {
                profile = &gSrtpProfiles[i];
                break;
            }
        }
        else if (id != 0 && gSrtpProfiles[i].id == id) {
            profile = &gSrtpProfiles[i];
            break;
        }
    }
    return profile;
}

/* profile_str: accepts ":" colon separated list of SRTP profiles */
static int DtlsSrtpSelProfiles(word16* id, const char* profile_str)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile;
    const char *current, *next = NULL;
    word32 length = 0, current_length;

    *id = 0; /* reset destination ID's */

    if (profile_str == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* loop on end of line or colon ":" */
    next = profile_str;
    length = (word32)XSTRLEN(profile_str);
    do {
        current = next;
        next = XSTRSTR(current, ":");
        if (next) {
            current_length = (word32)(next - current);
            ++next; /* ++ needed to skip ':' */
        } else {
            current_length = (word32)XSTRLEN(current);
        }
        if (current_length < length)
            length = current_length;
        profile = DtlsSrtpFindProfile(current, current_length, 0);
        if (profile != NULL) {
            *id |= (1 << profile->id); /* selected bit based on ID */
        }
    } while (next != NULL);
    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_set_tlsext_use_srtp(WOLFSSL_CTX* ctx, const char* profile_str)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL) {
        ret = DtlsSrtpSelProfiles(&ctx->dtlsSrtpProfiles, profile_str);
    }

    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
        ret = 1;
    } else {
        ret = 0;
    }

    return ret;
}
int wolfSSL_set_tlsext_use_srtp(WOLFSSL* ssl, const char* profile_str)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ssl != NULL) {
        ret = DtlsSrtpSelProfiles(&ssl->dtlsSrtpProfiles, profile_str);
    }

    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
        ret = 1;
    } else {
        ret = 0;
    }

    return ret;
}

const WOLFSSL_SRTP_PROTECTION_PROFILE* wolfSSL_get_selected_srtp_profile(
    WOLFSSL* ssl)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    if (ssl) {
        profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    }
    return profile;
}
#ifndef NO_WOLFSSL_STUB
WOLF_STACK_OF(WOLFSSL_SRTP_PROTECTION_PROFILE)* wolfSSL_get_srtp_profiles(
    WOLFSSL* ssl)
{
    /* Not yet implemented - should return list of available SRTP profiles
     * ssl->dtlsSrtpProfiles */
    (void)ssl;
    return NULL;
}
#endif

#define DTLS_SRTP_KEYING_MATERIAL_LABEL "EXTRACTOR-dtls_srtp"

int wolfSSL_export_dtls_srtp_keying_material(WOLFSSL* ssl,
    unsigned char* out, size_t* olen)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;

    if (ssl == NULL || olen == NULL) {
        return BAD_FUNC_ARG;
    }

    profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    if (profile == NULL) {
        WOLFSSL_MSG("Not using DTLS SRTP");
        return EXT_MISSING;
    }
    if (out == NULL) {
        *olen = (size_t)profile->kdfBits;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (*olen < (size_t)profile->kdfBits) {
        return BUFFER_E;
    }

    return wolfSSL_export_keying_material(ssl, out, profile->kdfBits,
            DTLS_SRTP_KEYING_MATERIAL_LABEL,
            XSTR_SIZEOF(DTLS_SRTP_KEYING_MATERIAL_LABEL), NULL, 0, 0);
}

#endif /* WOLFSSL_SRTP */


#ifdef WOLFSSL_DTLS_DROP_STATS

int wolfSSL_dtls_get_drop_stats(WOLFSSL* ssl,
                                word32* macDropCount, word32* replayDropCount)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_dtls_get_drop_stats");

    if (ssl == NULL)
        ret = BAD_FUNC_ARG;
    else {
        ret = WOLFSSL_SUCCESS;
        if (macDropCount != NULL)
            *macDropCount = ssl->macDropCount;
        if (replayDropCount != NULL)
            *replayDropCount = ssl->replayDropCount;
    }

    WOLFSSL_LEAVE("wolfSSL_dtls_get_drop_stats", ret);
    return ret;
}

#endif /* WOLFSSL_DTLS_DROP_STATS */


#if defined(WOLFSSL_MULTICAST)

int wolfSSL_CTX_mcast_set_member_id(WOLFSSL_CTX* ctx, word16 id)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_mcast_set_member_id");

    if (ctx == NULL || id > WOLFSSL_MAX_8BIT)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        ctx->haveEMS = 0;
        ctx->haveMcast = 1;
        ctx->mcastID = (byte)id;
#ifndef WOLFSSL_USER_IO
        ctx->CBIORecv = EmbedReceiveFromMcast;
#endif /* WOLFSSL_USER_IO */

        ret = WOLFSSL_SUCCESS;
    }
    WOLFSSL_LEAVE("wolfSSL_CTX_mcast_set_member_id", ret);
    return ret;
}

int wolfSSL_mcast_get_max_peers(void)
{
    return WOLFSSL_MULTICAST_PEERS;
}

#ifdef WOLFSSL_DTLS
static WC_INLINE word32 UpdateHighwaterMark(word32 cur, word32 first,
                                         word32 second, word32 high)
{
    word32 newCur = 0;

    if (cur < first)
        newCur = first;
    else if (cur < second)
        newCur = second;
    else if (cur < high)
        newCur = high;

    return newCur;
}
#endif /* WOLFSSL_DTLS */


int wolfSSL_set_secret(WOLFSSL* ssl, word16 epoch,
                       const byte* preMasterSecret, word32 preMasterSz,
                       const byte* clientRandom, const byte* serverRandom,
                       const byte* suite)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_set_secret");

    if (ssl == NULL || preMasterSecret == NULL ||
        preMasterSz == 0 || preMasterSz > ENCRYPT_LEN ||
        clientRandom == NULL || serverRandom == NULL || suite == NULL) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && ssl->arrays->preMasterSecret == NULL) {
        ssl->arrays->preMasterSz = ENCRYPT_LEN;
        ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN, ssl->heap,
            DYNAMIC_TYPE_SECRET);
        if (ssl->arrays->preMasterSecret == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMCPY(ssl->arrays->preMasterSecret, preMasterSecret, preMasterSz);
        XMEMSET(ssl->arrays->preMasterSecret + preMasterSz, 0,
            ENCRYPT_LEN - preMasterSz);
        ssl->arrays->preMasterSz = preMasterSz;
        XMEMCPY(ssl->arrays->clientRandom, clientRandom, RAN_LEN);
        XMEMCPY(ssl->arrays->serverRandom, serverRandom, RAN_LEN);
        ssl->options.cipherSuite0 = suite[0];
        ssl->options.cipherSuite = suite[1];

        ret = SetCipherSpecs(ssl);
    }

    if (ret == 0)
        ret = MakeTlsMasterSecret(ssl);

    if (ret == 0) {
        ssl->keys.encryptionOn = 1;
        ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE);
    }

    if (ret == 0) {
        if (ssl->options.dtls) {
        #ifdef WOLFSSL_DTLS
            WOLFSSL_DTLS_PEERSEQ* peerSeq;
            int i;

            ssl->keys.dtls_epoch = epoch;
            for (i = 0, peerSeq = ssl->keys.peerSeq;
                 i < WOLFSSL_DTLS_PEERSEQ_SZ;
                 i++, peerSeq++) {

                peerSeq->nextEpoch = epoch;
                peerSeq->prevSeq_lo = peerSeq->nextSeq_lo;
                peerSeq->prevSeq_hi = peerSeq->nextSeq_hi;
                peerSeq->nextSeq_lo = 0;
                peerSeq->nextSeq_hi = 0;
                XMEMCPY(peerSeq->prevWindow, peerSeq->window, DTLS_SEQ_SZ);
                XMEMSET(peerSeq->window, 0, DTLS_SEQ_SZ);
                peerSeq->highwaterMark = UpdateHighwaterMark(0,
                        ssl->ctx->mcastFirstSeq,
                        ssl->ctx->mcastSecondSeq,
                        ssl->ctx->mcastMaxSeq);
            }
        #else
            (void)epoch;
        #endif
        }
        FreeHandshakeResources(ssl);
        ret = WOLFSSL_SUCCESS;
    }
    else {
        if (ssl)
            ssl->error = ret;
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_set_secret", ret);
    return ret;
}


#ifdef WOLFSSL_DTLS

int wolfSSL_mcast_peer_add(WOLFSSL* ssl, word16 peerId, int sub)
{
    WOLFSSL_DTLS_PEERSEQ* p = NULL;
    int ret = WOLFSSL_SUCCESS;
    int i;

    WOLFSSL_ENTER("wolfSSL_mcast_peer_add");
    if (ssl == NULL || peerId > WOLFSSL_MAX_8BIT)
        return BAD_FUNC_ARG;

    if (!sub) {
        /* Make sure it isn't already present, while keeping the first
         * open spot. */
        for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
            if (ssl->keys.peerSeq[i].peerId == INVALID_PEER_ID)
                p = &ssl->keys.peerSeq[i];
            if (ssl->keys.peerSeq[i].peerId == peerId) {
                WOLFSSL_MSG("Peer ID already in multicast peer list.");
                p = NULL;
            }
        }

        if (p != NULL) {
            XMEMSET(p, 0, sizeof(WOLFSSL_DTLS_PEERSEQ));
            p->peerId = peerId;
            p->highwaterMark = UpdateHighwaterMark(0,
                ssl->ctx->mcastFirstSeq,
                ssl->ctx->mcastSecondSeq,
                ssl->ctx->mcastMaxSeq);
        }
        else {
            WOLFSSL_MSG("No room in peer list.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
            if (ssl->keys.peerSeq[i].peerId == peerId)
                p = &ssl->keys.peerSeq[i];
        }

        if (p != NULL) {
            p->peerId = INVALID_PEER_ID;
        }
        else {
            WOLFSSL_MSG("Peer not found in list.");
        }
    }

    WOLFSSL_LEAVE("wolfSSL_mcast_peer_add", ret);
    return ret;
}


/* If peerId is in the list of peers and its last sequence number is non-zero,
 * return 1, otherwise return 0. */
int wolfSSL_mcast_peer_known(WOLFSSL* ssl, unsigned short peerId)
{
    int known = 0;
    int i;

    WOLFSSL_ENTER("wolfSSL_mcast_peer_known");

    if (ssl == NULL || peerId > WOLFSSL_MAX_8BIT) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
        if (ssl->keys.peerSeq[i].peerId == peerId) {
            if (ssl->keys.peerSeq[i].nextSeq_hi ||
                ssl->keys.peerSeq[i].nextSeq_lo) {

                known = 1;
            }
            break;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_mcast_peer_known", known);
    return known;
}


int wolfSSL_CTX_mcast_set_highwater_cb(WOLFSSL_CTX* ctx, word32 maxSeq,
                                       word32 first, word32 second,
                                       CallbackMcastHighwater cb)
{
    if (ctx == NULL || (second && first > second) ||
        first > maxSeq || second > maxSeq || cb == NULL) {

        return BAD_FUNC_ARG;
    }

    ctx->mcastHwCb = cb;
    ctx->mcastFirstSeq = first;
    ctx->mcastSecondSeq = second;
    ctx->mcastMaxSeq = maxSeq;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_mcast_set_highwater_ctx(WOLFSSL* ssl, void* ctx)
{
    if (ssl == NULL || ctx == NULL)
        return BAD_FUNC_ARG;

    ssl->mcastHwCbCtx = ctx;

    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_DTLS */

#endif /* WOLFSSL_MULTICAST */


#endif /* WOLFSSL_LEANPSK */

#ifndef NO_TLS
/* return underlying connect or accept, WOLFSSL_SUCCESS on ok */
int wolfSSL_negotiate(WOLFSSL* ssl)
{
    int err = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    WOLFSSL_ENTER("wolfSSL_negotiate");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

#ifndef NO_WOLFSSL_SERVER
    if (ssl->options.side == WOLFSSL_SERVER_END) {
#ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            err = wolfSSL_accept_TLSv13(ssl);
        else
#endif
            err = wolfSSL_accept(ssl);
    }
#endif

#ifndef NO_WOLFSSL_CLIENT
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
#ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            err = wolfSSL_connect_TLSv13(ssl);
        else
#endif
            err = wolfSSL_connect(ssl);
    }
#endif

    (void)ssl;

    WOLFSSL_LEAVE("wolfSSL_negotiate", err);

    return err;
}
#endif /* !NO_TLS */

WOLFSSL_ABI
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl)
{
    if (ssl) {
        return ssl->rng;
    }

    return NULL;
}


#ifndef WOLFSSL_LEANPSK
/* object size based on build */
int wolfSSL_GetObjectSize(void)
{
#ifdef SHOW_SIZES
    printf("sizeof suites           = %lu\n", (unsigned long)sizeof(Suites));
    printf("sizeof ciphers(2)       = %lu\n", (unsigned long)sizeof(Ciphers));
#ifndef NO_RC4
    printf("\tsizeof arc4         = %lu\n", (unsigned long)sizeof(Arc4));
#endif
    printf("\tsizeof aes          = %lu\n", (unsigned long)sizeof(Aes));
#ifndef NO_DES3
    printf("\tsizeof des3         = %lu\n", (unsigned long)sizeof(Des3));
#endif
#ifdef HAVE_CHACHA
    printf("\tsizeof chacha       = %lu\n", (unsigned long)sizeof(ChaCha));
#endif
#ifdef WOLFSSL_SM4
    printf("\tsizeof sm4          = %lu\n", (unsigned long)sizeof(Sm4));
#endif
    printf("sizeof cipher specs     = %lu\n", (unsigned long)
        sizeof(CipherSpecs));
    printf("sizeof keys             = %lu\n", (unsigned long)sizeof(Keys));
    printf("sizeof Hashes(2)        = %lu\n", (unsigned long)sizeof(Hashes));
#ifndef NO_MD5
    printf("\tsizeof MD5          = %lu\n", (unsigned long)sizeof(wc_Md5));
#endif
#ifndef NO_SHA
    printf("\tsizeof SHA          = %lu\n", (unsigned long)sizeof(wc_Sha));
#endif
#ifdef WOLFSSL_SHA224
    printf("\tsizeof SHA224       = %lu\n", (unsigned long)sizeof(wc_Sha224));
#endif
#ifndef NO_SHA256
    printf("\tsizeof SHA256       = %lu\n", (unsigned long)sizeof(wc_Sha256));
#endif
#ifdef WOLFSSL_SHA384
    printf("\tsizeof SHA384       = %lu\n", (unsigned long)sizeof(wc_Sha384));
#endif
#ifdef WOLFSSL_SHA384
    printf("\tsizeof SHA512       = %lu\n", (unsigned long)sizeof(wc_Sha512));
#endif
#ifdef WOLFSSL_SM3
    printf("\tsizeof sm3          = %lu\n", (unsigned long)sizeof(Sm3));
#endif
    printf("sizeof Buffers          = %lu\n", (unsigned long)sizeof(Buffers));
    printf("sizeof Options          = %lu\n", (unsigned long)sizeof(Options));
    printf("sizeof Arrays           = %lu\n", (unsigned long)sizeof(Arrays));
#ifndef NO_RSA
    printf("sizeof RsaKey           = %lu\n", (unsigned long)sizeof(RsaKey));
#endif
#ifdef HAVE_ECC
    printf("sizeof ecc_key          = %lu\n", (unsigned long)sizeof(ecc_key));
#endif
    printf("sizeof WOLFSSL_CIPHER    = %lu\n", (unsigned long)
        sizeof(WOLFSSL_CIPHER));
    printf("sizeof WOLFSSL_SESSION   = %lu\n", (unsigned long)
        sizeof(WOLFSSL_SESSION));
    printf("sizeof WOLFSSL           = %lu\n", (unsigned long)sizeof(WOLFSSL));
    printf("sizeof WOLFSSL_CTX       = %lu\n", (unsigned long)
        sizeof(WOLFSSL_CTX));
#endif

    return sizeof(WOLFSSL);
}

int wolfSSL_CTX_GetObjectSize(void)
{
    return sizeof(WOLFSSL_CTX);
}

int wolfSSL_METHOD_GetObjectSize(void)
{
    return sizeof(WOLFSSL_METHOD);
}
#endif


#ifdef WOLFSSL_STATIC_MEMORY

int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
    wolfSSL_method_func method, unsigned char* buf, unsigned int sz, int flag,
    int maxSz)
{
    WOLFSSL_HEAP_HINT* hint = NULL;

    if (ctx == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    if (*ctx == NULL && method == NULL) {
        return BAD_FUNC_ARG;
    }

    /* If there is a heap already, capture it in hint. */
    if (*ctx && (*ctx)->heap != NULL) {
        hint = (*ctx)->heap;
    }

    if (wc_LoadStaticMemory(&hint, buf, sz, flag, maxSz)) {
        WOLFSSL_MSG("Error loading static memory");
        return WOLFSSL_FAILURE;
    }

    if (*ctx) {
        if ((*ctx)->heap == NULL) {
            (*ctx)->heap = (void*)hint;
        }
    }
    else {
        /* create ctx if needed */
        *ctx = wolfSSL_CTX_new_ex(method(hint), hint);
        if (*ctx == NULL) {
            WOLFSSL_MSG("Error creating ctx");
            return WOLFSSL_FAILURE;
        }
    }

    return WOLFSSL_SUCCESS;
}


int wolfSSL_is_static_memory(WOLFSSL* ssl, WOLFSSL_MEM_CONN_STATS* mem_stats)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    WOLFSSL_ENTER("wolfSSL_is_static_memory");

#ifndef WOLFSSL_STATIC_MEMORY_LEAN
    /* fill out statistics if wanted and WOLFMEM_TRACK_STATS flag */
    if (mem_stats != NULL && ssl->heap != NULL) {
        WOLFSSL_HEAP_HINT* hint = ((WOLFSSL_HEAP_HINT*)(ssl->heap));
        WOLFSSL_HEAP* heap      = hint->memory;
        if (heap->flag & WOLFMEM_TRACK_STATS && hint->stats != NULL) {
            XMEMCPY(mem_stats, hint->stats, sizeof(WOLFSSL_MEM_CONN_STATS));
        }
    }
#endif

    (void)mem_stats;
    return (ssl->heap) ? 1 : 0;
}


int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx, WOLFSSL_MEM_STATS* mem_stats)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    WOLFSSL_ENTER("wolfSSL_CTX_is_static_memory");

#ifndef WOLFSSL_STATIC_MEMORY_LEAN
    /* fill out statistics if wanted */
    if (mem_stats != NULL && ctx->heap != NULL) {
        WOLFSSL_HEAP* heap = ((WOLFSSL_HEAP_HINT*)(ctx->heap))->memory;
        if (wolfSSL_GetMemStats(heap, mem_stats) != 1) {
            return MEMORY_E;
        }
    }
#endif

    (void)mem_stats;
    return (ctx->heap) ? 1 : 0;
}

#endif /* WOLFSSL_STATIC_MEMORY */

#ifndef NO_TLS
/* return max record layer size plaintext input size */
int wolfSSL_GetMaxOutputSize(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_GetMaxOutputSize");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        WOLFSSL_MSG("Handshake not complete yet");
        return BAD_FUNC_ARG;
    }

    return wolfSSL_GetMaxFragSize(ssl, OUTPUT_RECORD_SIZE);
}


/* return record layer size of plaintext input size */
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz)
{
    int maxSize;

    WOLFSSL_ENTER("wolfSSL_GetOutputSize");

    if (inSz < 0)
        return BAD_FUNC_ARG;

    maxSize = wolfSSL_GetMaxOutputSize(ssl);
    if (maxSize < 0)
        return maxSize;   /* error */
    if (inSz > maxSize)
        return INPUT_SIZE_E;

    return BuildMessage(ssl, NULL, 0, NULL, inSz, application_data, 0, 1, 0,
        CUR_ORDER);
}


#ifdef HAVE_ECC
int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ctx, short keySz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetMinEccKey_Sz");
    if (ctx == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ctx was null");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ctx->minEccKeySz > (keySz / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ctx->minEccKeySz     = keySz / 8;
#ifndef NO_CERTS
    ctx->cm->minEccKeySz = keySz / 8;
#endif
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz)
{
    WOLFSSL_ENTER("wolfSSL_SetMinEccKey_Sz");
    if (ssl == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ssl was null");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ssl->options.minEccKeySz > (keySz / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ssl->options.minEccKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_ECC */

#ifndef NO_RSA
int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz)
{
    if (ctx == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ctx was null");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ctx->minRsaKeySz > (keySz / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ctx->minRsaKeySz     = keySz / 8;
    ctx->cm->minRsaKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz)
{
    if (ssl == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ssl was null");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ssl->options.minRsaKeySz > (keySz / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ssl->options.minRsaKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}
#endif /* !NO_RSA */

#ifndef NO_DH

#if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
/* Enables or disables the session's DH key prime test. */
int wolfSSL_SetEnableDhKeyTest(WOLFSSL* ssl, int enable)
{
    WOLFSSL_ENTER("wolfSSL_SetEnableDhKeyTest");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (!enable)
        ssl->options.dhDoKeyTest = 0;
    else
        ssl->options.dhDoKeyTest = 1;

    WOLFSSL_LEAVE("wolfSSL_SetEnableDhKeyTest", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif

int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits)
{
    if (ctx == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ctx->minDhKeySz > (keySz_bits / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ctx->minDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits)
{
    if (ssl == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ssl->options.minDhKeySz > (keySz_bits / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ssl->options.minDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits)
{
    if (ctx == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ctx->minDhKeySz > (keySz_bits / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ctx->maxDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits)
{
    if (ssl == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        if (ssl->options.minDhKeySz > (keySz_bits / 8)) {
            return CRYPTO_POLICY_FORBIDDEN;
        }
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    ssl->options.maxDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_GetDhKey_Sz(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return (ssl->options.dhKeySz * 8);
}

#endif /* !NO_DH */


WOLFSSL_ABI
int wolfSSL_write(WOLFSSL* ssl, const void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_write");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("SSL_write() on QUIC not allowed");
        return BAD_FUNC_ARG;
    }
#endif

#ifdef HAVE_WRITE_DUP
    { /* local variable scope */
        int dupErr = 0;   /* local copy */

        ret = 0;

        if (ssl->dupWrite && ssl->dupSide == READ_DUP_SIDE) {
            WOLFSSL_MSG("Read dup side cannot write");
            return WRITE_DUP_WRITE_E;
        }
        if (ssl->dupWrite) {
            if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0) {
                return BAD_MUTEX_E;
            }
            dupErr = ssl->dupWrite->dupErr;
            ret = wc_UnLockMutex(&ssl->dupWrite->dupMutex);
        }

        if (ret != 0) {
            ssl->error = ret;  /* high priority fatal error */
            return WOLFSSL_FATAL_ERROR;
        }
        if (dupErr != 0) {
            WOLFSSL_MSG("Write dup error from other side");
            ssl->error = dupErr;
            return WOLFSSL_FATAL_ERROR;
        }
    }
#endif

#ifdef HAVE_ERRNO_H
    errno = 0;
#endif

    #ifdef OPENSSL_EXTRA
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, WOLFSSL_CB_WRITE, WOLFSSL_SUCCESS);
        ssl->cbmode = WOLFSSL_CB_WRITE;
    }
    #endif
    ret = SendData(ssl, data, sz);

    WOLFSSL_LEAVE("wolfSSL_write", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}

int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz)
{
    int maxLength;
    int usedLength;

    WOLFSSL_ENTER("wolfSSL_inject");

    if (ssl == NULL || data == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    usedLength = (int)(ssl->buffers.inputBuffer.length -
                       ssl->buffers.inputBuffer.idx);
    maxLength  = (int)(ssl->buffers.inputBuffer.bufferSize -
                       (word32)usedLength);

    if (sz > maxLength) {
        /* Need to make space */
        int ret;
        if (ssl->buffers.clearOutputBuffer.length > 0) {
            /* clearOutputBuffer points into so reallocating inputBuffer will
             * invalidate clearOutputBuffer and lose app data */
            WOLFSSL_MSG("Can't inject while there is application data to read");
            return APP_DATA_READY;
        }
        ret = GrowInputBuffer(ssl, sz, usedLength);
        if (ret < 0)
            return ret;
    }

    XMEMCPY(ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
            data, sz);
    ssl->buffers.inputBuffer.length += sz;

    return WOLFSSL_SUCCESS;
}

static int wolfSSL_read_internal(WOLFSSL* ssl, void* data, int sz, int peek)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_read_internal");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("SSL_read() on QUIC not allowed");
        return BAD_FUNC_ARG;
    }
#endif
#if defined(WOLFSSL_ERROR_CODE_OPENSSL) && defined(OPENSSL_EXTRA)
    /* This additional logic is meant to simulate following openSSL behavior:
     * After bidirectional SSL_shutdown complete, SSL_read returns 0 and
     * SSL_get_error_code returns SSL_ERROR_ZERO_RETURN.
     * This behavior is used to know the disconnect of the underlying
     * transport layer.
     *
     * In this logic, CBIORecv is called with a read size of 0 to check the
     * transport layer status. It also returns WOLFSSL_FAILURE so that
     * SSL_read does not return a positive number on failure.
     */

    /* make sure bidirectional TLS shutdown completes */
    if (ssl->error == WOLFSSL_ERROR_SYSCALL || ssl->options.shutdownDone) {
        /* ask the underlying transport the connection is closed */
        if (ssl->CBIORecv(ssl, (char*)data, 0, ssl->IOCB_ReadCtx)
            == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_CONN_CLOSE))
        {
            ssl->options.isClosed = 1;
            ssl->error = WOLFSSL_ERROR_ZERO_RETURN;
        }
        return WOLFSSL_FAILURE;
    }
#endif

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite && ssl->dupSide == WRITE_DUP_SIDE) {
        WOLFSSL_MSG("Write dup side cannot read");
        return WRITE_DUP_READ_E;
    }
#endif

#ifdef HAVE_ERRNO_H
        errno = 0;
#endif

    ret = ReceiveData(ssl, (byte*)data, sz, peek);

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite) {
        if (ssl->error != 0 && ssl->error != WC_NO_ERR_TRACE(WANT_READ)
        #ifdef WOLFSSL_ASYNC_CRYPT
            && ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E)
        #endif
        ) {
            int notifyErr;

            WOLFSSL_MSG("Notifying write side of fatal read error");
            notifyErr  = NotifyWriteSide(ssl, ssl->error);
            if (notifyErr < 0) {
                ret = ssl->error = notifyErr;
            }
        }
    }
#endif

    WOLFSSL_LEAVE("wolfSSL_read_internal", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}


int wolfSSL_peek(WOLFSSL* ssl, void* data, int sz)
{
    WOLFSSL_ENTER("wolfSSL_peek");

    return wolfSSL_read_internal(ssl, data, sz, TRUE);
}


WOLFSSL_ABI
int wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    WOLFSSL_ENTER("wolfSSL_read");

    #ifdef OPENSSL_EXTRA
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, WOLFSSL_CB_READ, WOLFSSL_SUCCESS);
        ssl->cbmode = WOLFSSL_CB_READ;
    }
    #endif
    return wolfSSL_read_internal(ssl, data, sz, FALSE);
}


#ifdef WOLFSSL_MULTICAST

int wolfSSL_mcast_read(WOLFSSL* ssl, word16* id, void* data, int sz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_mcast_read");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ret = wolfSSL_read_internal(ssl, data, sz, FALSE);
    if (ssl->options.dtls && ssl->options.haveMcast && id != NULL)
        *id = ssl->keys.curPeerId;
    return ret;
}

#endif /* WOLFSSL_MULTICAST */
#endif /* !NO_TLS */

/* helpers to set the device id, WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_SetDevId(WOLFSSL* ssl, int devId)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->devId = devId;

    return WOLFSSL_SUCCESS;
}

WOLFSSL_ABI
int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->devId = devId;

    return WOLFSSL_SUCCESS;
}

/* helpers to get device id and heap */
WOLFSSL_ABI
int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    int devId = INVALID_DEVID;
    if (ssl != NULL)
        devId = ssl->devId;
    if (ctx != NULL && devId == INVALID_DEVID)
        devId = ctx->devId;
    return devId;
}
void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    void* heap = NULL;
    if (ctx != NULL)
        heap = ctx->heap;
    else if (ssl != NULL)
        heap = ssl->heap;
    return heap;
}


#ifndef NO_TLS
#ifdef HAVE_SNI

WOLFSSL_ABI
int wolfSSL_UseSNI(WOLFSSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size, ssl->heap);
}


WOLFSSL_ABI
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, byte type, const void* data,
                                                                    word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size, ctx->heap);
}

#ifndef NO_WOLFSSL_SERVER

void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, byte type, byte options)
{
    if (ssl && ssl->extensions)
        TLSX_SNI_SetOptions(ssl->extensions, type, options);
}


void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx, byte type, byte options)
{
    if (ctx && ctx->extensions)
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
}


byte wolfSSL_SNI_Status(WOLFSSL* ssl, byte type)
{
    return TLSX_SNI_Status(ssl ? ssl->extensions : NULL, type);
}


word16 wolfSSL_SNI_GetRequest(WOLFSSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data, 0);

    return 0;
}


int wolfSSL_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz,
                              byte type, byte* sni, word32* inOutSz)
{
    if (clientHello && helloSz > 0 && sni && inOutSz && *inOutSz > 0)
        return TLSX_SNI_GetFromBuffer(clientHello, helloSz, type, sni, inOutSz);

    return BAD_FUNC_ARG;
}

#endif /* !NO_WOLFSSL_SERVER */

#endif /* HAVE_SNI */


#ifdef HAVE_TRUSTED_CA

int wolfSSL_UseTrustedCA(WOLFSSL* ssl, byte type,
    const byte* certId, word32 certIdSz)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (type == WOLFSSL_TRUSTED_CA_PRE_AGREED) {
        if (certId != NULL || certIdSz != 0)
            return BAD_FUNC_ARG;
    }
    else if (type == WOLFSSL_TRUSTED_CA_X509_NAME) {
        if (certId == NULL || certIdSz == 0)
            return BAD_FUNC_ARG;
    }
    #ifndef NO_SHA
    else if (type == WOLFSSL_TRUSTED_CA_KEY_SHA1 ||
            type == WOLFSSL_TRUSTED_CA_CERT_SHA1) {
        if (certId == NULL || certIdSz != WC_SHA_DIGEST_SIZE)
            return BAD_FUNC_ARG;
    }
    #endif
    else
        return BAD_FUNC_ARG;

    return TLSX_UseTrustedCA(&ssl->extensions,
            type, certId, certIdSz, ssl->heap);
}

#endif /* HAVE_TRUSTED_CA */


#ifdef HAVE_MAX_FRAGMENT
#ifndef NO_WOLFSSL_CLIENT

int wolfSSL_UseMaxFragment(WOLFSSL* ssl, byte mfl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_ALLOW_MAX_FRAGMENT_ADJUST
    /* The following is a non-standard way to reconfigure the max packet size
        post-handshake for wolfSSL_write/wolfSSL_read */
    if (ssl->options.handShakeState == HANDSHAKE_DONE) {
        switch (mfl) {
            case WOLFSSL_MFL_2_8 : ssl->max_fragment =  256; break;
            case WOLFSSL_MFL_2_9 : ssl->max_fragment =  512; break;
            case WOLFSSL_MFL_2_10: ssl->max_fragment = 1024; break;
            case WOLFSSL_MFL_2_11: ssl->max_fragment = 2048; break;
            case WOLFSSL_MFL_2_12: ssl->max_fragment = 4096; break;
            case WOLFSSL_MFL_2_13: ssl->max_fragment = 8192; break;
            default: ssl->max_fragment = MAX_RECORD_SIZE; break;
        }
        return WOLFSSL_SUCCESS;
    }
#endif /* WOLFSSL_MAX_FRAGMENT_ADJUST */

    /* This call sets the max fragment TLS extension, which gets sent to server.
        The server_hello response is what sets the `ssl->max_fragment` in
        TLSX_MFL_Parse */
    return TLSX_UseMaxFragment(&ssl->extensions, mfl, ssl->heap);
}


int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, byte mfl)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ctx->extensions, mfl, ctx->heap);
}

#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT

int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ssl->extensions, ssl->heap);
}


int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ctx->extensions, ctx->heap);
}

#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_TRUNCATED_HMAC */

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST

int wolfSSL_UseOCSPStapling(WOLFSSL* ssl, byte status_type, byte options)
{
    WOLFSSL_ENTER("wolfSSL_UseOCSPStapling");

    if (ssl == NULL || ssl->options.side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequest(&ssl->extensions, status_type,
                                          options, NULL, ssl->heap, ssl->devId);
}


int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_UseOCSPStapling");

    if (ctx == NULL || ctx->method->side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequest(&ctx->extensions, status_type,
                                          options, NULL, ctx->heap, ctx->devId);
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl, byte status_type, byte options)
{
    if (ssl == NULL || ssl->options.side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ssl->extensions, status_type,
                                                options, ssl->heap, ssl->devId);
}


int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    if (ctx == NULL || ctx->method->side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ctx->extensions, status_type,
                                                options, ctx->heap, ctx->devId);
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

/* Elliptic Curves */
#if defined(HAVE_SUPPORTED_CURVES)

static int isValidCurveGroup(word16 name)
{
    switch (name) {
        case WOLFSSL_ECC_SECP160K1:
        case WOLFSSL_ECC_SECP160R1:
        case WOLFSSL_ECC_SECP160R2:
        case WOLFSSL_ECC_SECP192K1:
        case WOLFSSL_ECC_SECP192R1:
        case WOLFSSL_ECC_SECP224K1:
        case WOLFSSL_ECC_SECP224R1:
        case WOLFSSL_ECC_SECP256K1:
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
        case WOLFSSL_ECC_SECP521R1:
        case WOLFSSL_ECC_BRAINPOOLP256R1:
        case WOLFSSL_ECC_BRAINPOOLP384R1:
        case WOLFSSL_ECC_BRAINPOOLP512R1:
        case WOLFSSL_ECC_SM2P256V1:
        case WOLFSSL_ECC_X25519:
        case WOLFSSL_ECC_X448:

        case WOLFSSL_FFDHE_2048:
        case WOLFSSL_FFDHE_3072:
        case WOLFSSL_FFDHE_4096:
        case WOLFSSL_FFDHE_6144:
        case WOLFSSL_FFDHE_8192:

#ifdef WOLFSSL_HAVE_KYBER
#ifndef WOLFSSL_NO_ML_KEM
        case WOLFSSL_ML_KEM_512:
        case WOLFSSL_ML_KEM_768:
        case WOLFSSL_ML_KEM_1024:
    #if defined(WOLFSSL_WC_KYBER) || defined(HAVE_LIBOQS)
        case WOLFSSL_P256_ML_KEM_512:
        case WOLFSSL_P384_ML_KEM_768:
        case WOLFSSL_P521_ML_KEM_1024:
    #endif
#endif /* !WOLFSSL_NO_ML_KEM */
#ifdef WOLFSSL_KYBER_ORIGINAL
        case WOLFSSL_KYBER_LEVEL1:
        case WOLFSSL_KYBER_LEVEL3:
        case WOLFSSL_KYBER_LEVEL5:
    #if defined(WOLFSSL_WC_KYBER) || defined(HAVE_LIBOQS)
        case WOLFSSL_P256_KYBER_LEVEL1:
        case WOLFSSL_P384_KYBER_LEVEL3:
        case WOLFSSL_P521_KYBER_LEVEL5:
    #endif
#endif /* WOLFSSL_KYBER_ORIGINAL */
#endif
            return 1;

        default:
            return 0;
    }
}

int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name)
{
    if (ssl == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ssl->options.userCurves = 1;
#if defined(NO_TLS)
    return WOLFSSL_FAILURE;
#else
    return TLSX_UseSupportedCurve(&ssl->extensions, name, ssl->heap);
#endif /* NO_TLS */
}


int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx, word16 name)
{
    if (ctx == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ctx->userCurves = 1;
#if defined(NO_TLS)
    return WOLFSSL_FAILURE;
#else
    return TLSX_UseSupportedCurve(&ctx->extensions, name, ctx->heap);
#endif /* NO_TLS */
}

#if defined(OPENSSL_EXTRA)
int  wolfSSL_CTX_set1_groups(WOLFSSL_CTX* ctx, int* groups,
                                        int count)
{
    int i;
    int _groups[WOLFSSL_MAX_GROUP_COUNT];
    WOLFSSL_ENTER("wolfSSL_CTX_set1_groups");
    if (count == 0) {
        WOLFSSL_MSG("Group count is zero");
        return WOLFSSL_FAILURE;
    }
    for (i = 0; i < count; i++) {
        if (isValidCurveGroup((word16)groups[i])) {
            _groups[i] = groups[i];
        }
#ifdef HAVE_ECC
        else {
            /* groups may be populated with curve NIDs */
            int oid = (int)nid2oid(groups[i], oidCurveType);
            int name = (int)GetCurveByOID(oid);
            if (name == 0) {
                WOLFSSL_MSG("Invalid group name");
                return WOLFSSL_FAILURE;
            }
            _groups[i] = name;
        }
#else
        else {
            WOLFSSL_MSG("Invalid group name");
            return WOLFSSL_FAILURE;
        }
#endif
    }
    return wolfSSL_CTX_set_groups(ctx, _groups, count) == WOLFSSL_SUCCESS ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

int  wolfSSL_set1_groups(WOLFSSL* ssl, int* groups, int count)
{
    int i;
    int _groups[WOLFSSL_MAX_GROUP_COUNT];
    WOLFSSL_ENTER("wolfSSL_CTX_set1_groups");
    if (count == 0) {
        WOLFSSL_MSG("Group count is zero");
        return WOLFSSL_FAILURE;
    }
    for (i = 0; i < count; i++) {
        if (isValidCurveGroup((word16)groups[i])) {
            _groups[i] = groups[i];
        }
#ifdef HAVE_ECC
        else {
            /* groups may be populated with curve NIDs */
            int oid = (int)nid2oid(groups[i], oidCurveType);
            int name = (int)GetCurveByOID(oid);
            if (name == 0) {
                WOLFSSL_MSG("Invalid group name");
                return WOLFSSL_FAILURE;
            }
            _groups[i] = name;
        }
#else
        else {
            WOLFSSL_MSG("Invalid group name");
            return WOLFSSL_FAILURE;
        }
#endif
    }
    return wolfSSL_set_groups(ssl, _groups, count) == WOLFSSL_SUCCESS ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA */
#endif /* HAVE_SUPPORTED_CURVES */

/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN

WOLFSSL_ABI
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                    word32 protocol_name_listSz, byte options)
{
    char    *list, *ptr, **token;
    word16  len;
    int     idx = 0;
    int     ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    WOLFSSL_ENTER("wolfSSL_UseALPN");

    if (ssl == NULL || protocol_name_list == NULL)
        return BAD_FUNC_ARG;

    if (protocol_name_listSz > (WOLFSSL_MAX_ALPN_NUMBER *
                                WOLFSSL_MAX_ALPN_PROTO_NAME_LEN +
                                WOLFSSL_MAX_ALPN_NUMBER)) {
        WOLFSSL_MSG("Invalid arguments, protocol name list too long");
        return BAD_FUNC_ARG;
    }

    if (!(options & WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) &&
        !(options & WOLFSSL_ALPN_FAILED_ON_MISMATCH)) {
            WOLFSSL_MSG("Invalid arguments, options not supported");
            return BAD_FUNC_ARG;
        }


    list = (char *)XMALLOC(protocol_name_listSz+1, ssl->heap,
                           DYNAMIC_TYPE_ALPN);
    if (list == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_ERROR;
    }

    token = (char **)XMALLOC(sizeof(char *) * (WOLFSSL_MAX_ALPN_NUMBER+1),
        ssl->heap, DYNAMIC_TYPE_ALPN);
    if (token == NULL) {
        XFREE(list, ssl->heap, DYNAMIC_TYPE_ALPN);
        WOLFSSL_MSG("Memory failure");
        return MEMORY_ERROR;
    }
    XMEMSET(token, 0, sizeof(char *) * (WOLFSSL_MAX_ALPN_NUMBER+1));

    XSTRNCPY(list, protocol_name_list, protocol_name_listSz);
    list[protocol_name_listSz] = '\0';

    /* read all protocol name from the list */
    token[idx] = XSTRTOK(list, ",", &ptr);
    while (idx < WOLFSSL_MAX_ALPN_NUMBER && token[idx] != NULL)
        token[++idx] = XSTRTOK(NULL, ",", &ptr);

    /* add protocol name list in the TLS extension in reverse order */
    while ((idx--) > 0) {
        len = (word16)XSTRLEN(token[idx]);

        ret = TLSX_UseALPN(&ssl->extensions, token[idx], len, options,
                                                                     ssl->heap);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("TLSX_UseALPN failure");
            break;
        }
    }

    XFREE(token, ssl->heap, DYNAMIC_TYPE_ALPN);
    XFREE(list, ssl->heap, DYNAMIC_TYPE_ALPN);

    return ret;
}

int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name, word16 *size)
{
    return TLSX_ALPN_GetRequest(ssl ? ssl->extensions : NULL,
                               (void **)protocol_name, size);
}

int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list, word16 *listSz)
{
    int i, len;
    char *p;
    byte *s;

    if (ssl == NULL || list == NULL || listSz == NULL)
        return BAD_FUNC_ARG;

    if (ssl->alpn_peer_requested == NULL
        || ssl->alpn_peer_requested_length == 0)
        return BUFFER_ERROR;

    /* ssl->alpn_peer_requested are the original bytes sent in a ClientHello,
     * formatted as (len-byte chars+)+. To turn n protocols into a
     * comma-separated C string, one needs (n-1) commas and a final 0 byte
     * which has the same length as the original.
     * The returned length is the strlen() of the C string, so -1 of that. */
    *listSz = ssl->alpn_peer_requested_length-1;
    *list = p = (char *)XMALLOC(ssl->alpn_peer_requested_length, ssl->heap,
                                DYNAMIC_TYPE_TLSX);
    if (p == NULL)
        return MEMORY_ERROR;

    for (i = 0, s = ssl->alpn_peer_requested;
         i < ssl->alpn_peer_requested_length;
         p += len, i += len)
    {
        if (i)
            *p++ = ',';
        len = s[i++];
        /* guard against bad length bytes. */
        if (i + len > ssl->alpn_peer_requested_length) {
            XFREE(*list, ssl->heap, DYNAMIC_TYPE_TLSX);
            *list = NULL;
            return WOLFSSL_FAILURE;
        }
        XMEMCPY(p, s + i, len);
    }
    *p = 0;

    return WOLFSSL_SUCCESS;
}


/* used to free memory allocated by wolfSSL_ALPN_GetPeerProtocol */
int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    XFREE(*list, ssl->heap, DYNAMIC_TYPE_TLSX);
    *list = NULL;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_ALPN */

/* Secure Renegotiation */
#ifdef HAVE_SERVER_RENEGOTIATION_INFO

/* user is forcing ability to use secure renegotiation, we discourage it */
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
#if defined(NO_TLS)
    (void)ssl;
#else
    if (ssl)
        ret = TLSX_UseSecureRenegotiation(&ssl->extensions, ssl->heap);
    else
        ret = BAD_FUNC_ARG;

    if (ret == WOLFSSL_SUCCESS) {
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_RENEGOTIATION_INFO);

        if (extension)
            ssl->secure_renegotiation = (SecureRenegotiation*)extension->data;
    }
#endif /* !NO_TLS */
    return ret;
}

int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->useSecureReneg = 1;
    return WOLFSSL_SUCCESS;
}

#ifdef HAVE_SECURE_RENEGOTIATION
/* do a secure renegotiation handshake, user forced, we discourage */
static int _Rehandshake(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (IsAtLeastTLSv1_3(ssl->version)) {
        WOLFSSL_MSG("Secure Renegotiation not supported in TLS 1.3");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation == NULL) {
        WOLFSSL_MSG("Secure Renegotiation not forced on by user");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation->enabled == 0) {
        WOLFSSL_MSG("Secure Renegotiation not enabled at extension level");
        return SECURE_RENEGOTIATION_E;
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls && ssl->keys.dtls_epoch == 0xFFFF) {
        WOLFSSL_MSG("Secure Renegotiation not allowed. Epoch would wrap");
        return SECURE_RENEGOTIATION_E;
    }
#endif

    /* If the client started the renegotiation, the server will already
     * have processed the client's hello. */
    if (ssl->options.side != WOLFSSL_SERVER_END ||
        ssl->options.acceptState != ACCEPT_FIRST_REPLY_DONE) {

        if (ssl->options.handShakeState != HANDSHAKE_DONE) {
            if (!ssl->options.handShakeDone) {
                WOLFSSL_MSG("Can't renegotiate until initial "
                            "handshake complete");
                return SECURE_RENEGOTIATION_E;
            }
            else {
                WOLFSSL_MSG("Renegotiation already started. "
                            "Moving it forward.");
                ret = wolfSSL_negotiate(ssl);
                if (ret == WOLFSSL_SUCCESS)
                    ssl->secure_rene_count++;
                return ret;
            }
        }

        /* reset handshake states */
        ssl->options.sendVerify = 0;
        ssl->options.serverState = NULL_STATE;
        ssl->options.clientState = NULL_STATE;
        ssl->options.connectState  = CONNECT_BEGIN;
        ssl->options.acceptState   = ACCEPT_BEGIN_RENEG;
        ssl->options.handShakeState = NULL_STATE;
        ssl->options.processReply  = 0;  /* TODO, move states in internal.h */

        XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

        ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;

#if !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12)
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            ret = SendHelloRequest(ssl);
            if (ret != 0) {
                ssl->error = ret;
                return WOLFSSL_FATAL_ERROR;
            }
        }
#endif /* !NO_WOLFSSL_SERVER && !WOLFSSL_NO_TLS12 */

        ret = InitHandshakeHashes(ssl);
        if (ret != 0) {
            ssl->error = ret;
            return WOLFSSL_FATAL_ERROR;
        }
    }
    ret = wolfSSL_negotiate(ssl);
    if (ret == WOLFSSL_SUCCESS)
        ssl->secure_rene_count++;
    return ret;
}


/* do a secure renegotiation handshake, user forced, we discourage */
int wolfSSL_Rehandshake(WOLFSSL* ssl)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_Rehandshake");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

#ifdef HAVE_SESSION_TICKET
    ret = WOLFSSL_SUCCESS;
#endif

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* Reset option to send certificate verify. */
        ssl->options.sendVerify = 0;
        /* Reset resuming flag to do full secure handshake. */
        ssl->options.resuming = 0;
    }
    else {
        /* Reset resuming flag to do full secure handshake. */
        ssl->options.resuming = 0;
        #if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_CLIENT)
            /* Clearing the ticket. */
            ret = wolfSSL_UseSessionTicket(ssl);
        #endif
    }
    /* CLIENT/SERVER: Reset peer authentication for full secure handshake. */
    ssl->options.peerAuthGood = 0;

#ifdef HAVE_SESSION_TICKET
    if (ret == WOLFSSL_SUCCESS)
#endif
        ret = _Rehandshake(ssl);

    return ret;
}


#ifndef NO_WOLFSSL_CLIENT

/* do a secure resumption handshake, user forced, we discourage */
int wolfSSL_SecureResume(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SecureResume");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->error = SIDE_ERROR;
        return WOLFSSL_FATAL_ERROR;
    }

    return _Rehandshake(ssl);
}

#endif /* NO_WOLFSSL_CLIENT */

#endif /* HAVE_SECURE_RENEGOTIATION */

long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_secure_renegotiation_support");

    if (!ssl || !ssl->secure_renegotiation)
        return WOLFSSL_FAILURE;
    return ssl->secure_renegotiation->enabled;
}

#endif /* HAVE_SECURE_RENEGOTIATION_INFO */

#if defined(HAVE_SESSION_TICKET)
/* Session Ticket */

#if !defined(NO_WOLFSSL_SERVER)
int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->noTicketTls12 = 1;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.noTicketTls12 = 1;

    return WOLFSSL_SUCCESS;
}

/* WOLFSSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx, SessionTicketEncCb cb)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCb = cb;

    return WOLFSSL_SUCCESS;
}

/* set hint interval, WOLFSSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int hint)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketHint = hint;

    return WOLFSSL_SUCCESS;
}

/* set user context, WOLFSSL_SUCCESS on ok */
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCtx = userCtx;

    return WOLFSSL_SUCCESS;
}

/* get user context - returns userCtx on success, NULL on failure */
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->ticketEncCtx;
}

#ifdef WOLFSSL_TLS13
/* set the maximum number of tickets to send
 * return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on fail
 */
int wolfSSL_CTX_set_num_tickets(WOLFSSL_CTX* ctx, size_t mxTickets)
{
    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    ctx->maxTicketTls13 = (unsigned int)mxTickets;
    return WOLFSSL_SUCCESS;
}

/* get the maximum number of tickets to send
 * return number of tickets set to be sent
 */
size_t wolfSSL_CTX_get_num_tickets(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return 0;

    return (size_t)ctx->maxTicketTls13;
}
#endif /* WOLFSSL_TLS13 */
#endif /* !NO_WOLFSSL_SERVER */

#if !defined(NO_WOLFSSL_CLIENT)
int wolfSSL_UseSessionTicket(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ssl->extensions, NULL, ssl->heap);
}

int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ctx->extensions, NULL, ctx->heap);
}

int wolfSSL_get_SessionTicket(WOLFSSL* ssl, byte* buf, word32* bufSz)
{
    if (ssl == NULL || buf == NULL || bufSz == NULL || *bufSz == 0)
        return BAD_FUNC_ARG;

    if (ssl->session->ticketLen <= *bufSz) {
        XMEMCPY(buf, ssl->session->ticket, ssl->session->ticketLen);
        *bufSz = ssl->session->ticketLen;
    }
    else
        *bufSz = 0;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const byte* buf,
                                          word32 bufSz)
{
    if (ssl == NULL || (buf == NULL && bufSz > 0))
        return BAD_FUNC_ARG;

    if (bufSz > 0) {
        /* Ticket will fit into static ticket */
        if (bufSz <= SESSION_TICKET_LEN) {
            if (ssl->session->ticketLenAlloc > 0) {
                XFREE(ssl->session->ticket, ssl->session->heap,
                      DYNAMIC_TYPE_SESSION_TICK);
                ssl->session->ticketLenAlloc = 0;
                ssl->session->ticket = ssl->session->staticTicket;
            }
        }
        else { /* Ticket requires dynamic ticket storage */
            /* is dyn buffer big enough */
            if (ssl->session->ticketLen < bufSz) {
                if (ssl->session->ticketLenAlloc > 0) {
                    XFREE(ssl->session->ticket, ssl->session->heap,
                          DYNAMIC_TYPE_SESSION_TICK);
                }
                ssl->session->ticket = (byte*)XMALLOC(bufSz, ssl->session->heap,
                        DYNAMIC_TYPE_SESSION_TICK);
                if(ssl->session->ticket == NULL) {
                    ssl->session->ticket = ssl->session->staticTicket;
                    ssl->session->ticketLenAlloc = 0;
                    return MEMORY_ERROR;
                }
                ssl->session->ticketLenAlloc = (word16)bufSz;
            }
        }
        XMEMCPY(ssl->session->ticket, buf, bufSz);
    }
    ssl->session->ticketLen = (word16)bufSz;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->session_ticket_cb = cb;
    ssl->session_ticket_ctx = ctx;

    return WOLFSSL_SUCCESS;
}
#endif /* !NO_WOLFSSL_CLIENT */

#endif /* HAVE_SESSION_TICKET */


#ifdef HAVE_EXTENDED_MASTER
#ifndef NO_WOLFSSL_CLIENT

int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->haveEMS = 0;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.haveEMS = 0;

    return WOLFSSL_SUCCESS;
}

#endif
#endif


#ifndef WOLFSSL_LEANPSK

int wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_send");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->wflags;

    ssl->wflags = flags;
    ret = wolfSSL_write(ssl, data, sz);
    ssl->wflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_send", ret);

    return ret;
}


int wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_recv");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->rflags;

    ssl->rflags = flags;
    ret = wolfSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_recv", ret);

    return ret;
}
#endif

int wolfSSL_SendUserCanceled(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_recv");

    if (ssl != NULL) {
        ssl->error = SendAlert(ssl, alert_warning, user_canceled);
        if (ssl->error < 0) {
            WOLFSSL_ERROR(ssl->error);
        }
        else {
            ret = wolfSSL_shutdown(ssl);
        }
    }

    WOLFSSL_LEAVE("wolfSSL_SendUserCanceled", ret);

    return ret;
}

/* WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_shutdown(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    WOLFSSL_ENTER("wolfSSL_shutdown");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        WOLFSSL_MSG("quiet shutdown, no close notify sent");
        ret = WOLFSSL_SUCCESS;
    }
    else {
        /* try to send close notify, not an error if can't */
        if (!ssl->options.isClosed && !ssl->options.connReset &&
                                      !ssl->options.sentNotify) {
            ssl->error = SendAlert(ssl, alert_warning, close_notify);
            if (ssl->error < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.sentNotify = 1;  /* don't send close_notify twice */
            if (ssl->options.closeNotify) {
                ret = WOLFSSL_SUCCESS;
                ssl->options.shutdownDone = 1;
            }
            else {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                return ret;
            }
        }

#ifdef WOLFSSL_SHUTDOWNONCE
        if (ssl->options.isClosed || ssl->options.connReset) {
            /* Shutdown has already occurred.
             * Caller is free to ignore this error. */
            return SSL_SHUTDOWN_ALREADY_DONE_E;
        }
#endif

        /* call wolfSSL_shutdown again for bidirectional shutdown */
        if (ssl->options.sentNotify && !ssl->options.closeNotify) {
            ret = ProcessReply(ssl);
            if ((ret == WC_NO_ERR_TRACE(ZERO_RETURN)) ||
                (ret == WC_NO_ERR_TRACE(SOCKET_ERROR_E))) {
                /* simulate OpenSSL behavior */
                ssl->options.shutdownDone = 1;
                /* Clear error */
                ssl->error = WOLFSSL_ERROR_NONE;
                ret = WOLFSSL_SUCCESS;
            } else if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
                ret = WOLFSSL_FATAL_ERROR;
            } else if (ssl->error == WOLFSSL_ERROR_NONE) {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
            } else {
                WOLFSSL_ERROR(ssl->error);
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    /* reset WOLFSSL structure state for possible reuse */
    if (ret == WOLFSSL_SUCCESS) {
        if (wolfSSL_clear(ssl) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("could not clear WOLFSSL");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif

    WOLFSSL_LEAVE("wolfSSL_shutdown", ret);

    return ret;
}
#endif /* !NO_TLS */

/* get current error state value */
int wolfSSL_state(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    return ssl->error;
}


WOLFSSL_ABI
int wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    WOLFSSL_ENTER("wolfSSL_get_error");

    if (ret > 0)
        return WOLFSSL_ERROR_NONE;
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    WOLFSSL_LEAVE("wolfSSL_get_error", ssl->error);

    /* make sure converted types are handled in SetErrorString() too */
    if (ssl->error == WC_NO_ERR_TRACE(WANT_READ))
        return WOLFSSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
        return WOLFSSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    else if (ssl->error == WC_NO_ERR_TRACE(ZERO_RETURN) ||
             ssl->options.shutdownDone)
        return WOLFSSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
#ifdef OPENSSL_EXTRA
    else if (ssl->error == WC_NO_ERR_TRACE(MATCH_SUITE_ERROR))
        return WOLFSSL_ERROR_SYSCALL;           /* convert to OpenSSL type */
    else if (ssl->error == WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E))
        return WOLFSSL_ERROR_SYSCALL;           /* convert to OpenSSL type */
#endif
    return ssl->error;
}


/* retrieve alert history, WOLFSSL_SUCCESS on ok */
int wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h)
{
    if (ssl && h) {
        *h = ssl->alert_history;
    }
    return WOLFSSL_SUCCESS;
}

#ifdef OPENSSL_EXTRA
/* returns SSL_WRITING, SSL_READING or SSL_NOTHING */
int wolfSSL_want(WOLFSSL* ssl)
{
    int rw_state = WOLFSSL_NOTHING;
    if (ssl) {
        if (ssl->error == WC_NO_ERR_TRACE(WANT_READ))
            rw_state = WOLFSSL_READING;
        else if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
            rw_state = WOLFSSL_WRITING;
    }
    return rw_state;
}
#endif

/* return TRUE if current error is want read */
int wolfSSL_want_read(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_want_read");
    if (ssl->error == WC_NO_ERR_TRACE(WANT_READ))
        return 1;

    return 0;
}

/* return TRUE if current error is want write */
int wolfSSL_want_write(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_want_write");
    if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
        return 1;

    return 0;
}

char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string");
    if (data) {
        SetErrorString((int)errNumber, data);
        return data;
    }
    else {
        static char tmp[WOLFSSL_MAX_ERROR_SZ] = {0};
        SetErrorString((int)errNumber, tmp);
        return tmp;
    }
}


void wolfSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string_n");
    if (len >= WOLFSSL_MAX_ERROR_SZ)
        wolfSSL_ERR_error_string(e, buf);
    else {
        WOLFSSL_MSG("Error buffer too short, truncating");
        if (len) {
            char tmp[WOLFSSL_MAX_ERROR_SZ];
            wolfSSL_ERR_error_string(e, tmp);
            XMEMCPY(buf, tmp, len-1);
            buf[len-1] = '\0';
        }
    }
}


/* don't free temporary arrays at end of handshake */
void wolfSSL_KeepArrays(WOLFSSL* ssl)
{
    if (ssl)
        ssl->options.saveArrays = 1;
}


/* user doesn't need temporary arrays anymore, Free */
void wolfSSL_FreeArrays(WOLFSSL* ssl)
{
    if (ssl && ssl->options.handShakeState == HANDSHAKE_DONE) {
        ssl->options.saveArrays = 0;
        FreeArrays(ssl, 1);
    }
}

/* Set option to indicate that the resources are not to be freed after
 * handshake.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.keepResources = 1;

    return 0;
}

/* Free the handshake resources after handshake.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    FreeHandshakeResources(ssl);

    return 0;
}

/* Use the client's order of preference when matching cipher suites.
 *
 * ssl  The SSL/TLS context object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->useClientOrder = 1;

    return 0;
}

/* Use the client's order of preference when matching cipher suites.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_UseClientSuites(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.useClientOrder = 1;

    return 0;
}

#ifdef WOLFSSL_DTLS
const byte* wolfSSL_GetDtlsMacSecret(WOLFSSL* ssl, int verify, int epochOrder)
{
#ifndef WOLFSSL_AEAD_ONLY
    Keys* keys = NULL;

    (void)epochOrder;

    if (ssl == NULL)
        return NULL;

#ifdef HAVE_SECURE_RENEGOTIATION
    switch (epochOrder) {
    case PEER_ORDER:
        if (IsDtlsMsgSCRKeys(ssl))
            keys = &ssl->secure_renegotiation->tmp_keys;
        else
            keys = &ssl->keys;
        break;
    case PREV_ORDER:
        keys = &ssl->keys;
        break;
    case CUR_ORDER:
        if (DtlsUseSCRKeys(ssl))
            keys = &ssl->secure_renegotiation->tmp_keys;
        else
            keys = &ssl->keys;
        break;
    default:
        WOLFSSL_MSG("Unknown epoch order");
        return NULL;
    }
#else
    keys = &ssl->keys;
#endif

    if ( (ssl->options.side == WOLFSSL_CLIENT_END && !verify) ||
         (ssl->options.side == WOLFSSL_SERVER_END &&  verify) )
        return keys->client_write_MAC_secret;
    else
        return keys->server_write_MAC_secret;
#else
    (void)ssl;
    (void)verify;
    (void)epochOrder;

    return NULL;
#endif
}
#endif /* WOLFSSL_DTLS */

const byte* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify)
{
#ifndef WOLFSSL_AEAD_ONLY
    if (ssl == NULL)
        return NULL;

    if ( (ssl->options.side == WOLFSSL_CLIENT_END && !verify) ||
         (ssl->options.side == WOLFSSL_SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
#else
    (void)ssl;
    (void)verify;

    return NULL;
#endif
}

int wolfSSL_GetSide(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->options.side;

    return BAD_FUNC_ARG;
}

#ifdef ATOMIC_USER

void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypt cb)
{
    if (ctx)
        ctx->MacEncryptCb = cb;
}


void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->MacEncryptCtx = ctx;
}


void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->MacEncryptCtx;

    return NULL;
}


void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx, CallbackDecryptVerify cb)
{
    if (ctx)
        ctx->DecryptVerifyCb = cb;
}


void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->DecryptVerifyCtx = ctx;
}


void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->DecryptVerifyCtx;

    return NULL;
}

#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
/**
 * Set the callback, against the context, that encrypts then MACs.
 *
 * ctx  SSL/TLS context.
 * cb   Callback function to use with Encrypt-Then-MAC.
 */
void  wolfSSL_CTX_SetEncryptMacCb(WOLFSSL_CTX* ctx, CallbackEncryptMac cb)
{
    if (ctx)
        ctx->EncryptMacCb = cb;
}

/**
 * Set the context to use with callback that encrypts then MACs.
 *
 * ssl  SSL/TLS object.
 * ctx  Callback function's context.
 */
void  wolfSSL_SetEncryptMacCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EncryptMacCtx = ctx;
}

/**
 * Get the context being used with callback that encrypts then MACs.
 *
 * ssl  SSL/TLS object.
 * returns callback function's context or NULL if SSL/TLS object is NULL.
 */
void* wolfSSL_GetEncryptMacCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EncryptMacCtx;

    return NULL;
}


/**
 * Set the callback, against the context, that MAC verifies then decrypts.
 *
 * ctx  SSL/TLS context.
 * cb   Callback function to use with Encrypt-Then-MAC.
 */
void  wolfSSL_CTX_SetVerifyDecryptCb(WOLFSSL_CTX* ctx, CallbackVerifyDecrypt cb)
{
    if (ctx)
        ctx->VerifyDecryptCb = cb;
}

/**
 * Set the context to use with callback that MAC verifies then decrypts.
 *
 * ssl  SSL/TLS object.
 * ctx  Callback function's context.
 */
void  wolfSSL_SetVerifyDecryptCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->VerifyDecryptCtx = ctx;
}

/**
 * Get the context being used with callback that MAC verifies then decrypts.
 *
 * ssl  SSL/TLS object.
 * returns callback function's context or NULL if SSL/TLS object is NULL.
 */
void* wolfSSL_GetVerifyDecryptCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->VerifyDecryptCtx;

    return NULL;
}
#endif /* HAVE_ENCRYPT_THEN_MAC !WOLFSSL_AEAD_ONLY */



const byte* wolfSSL_GetClientWriteKey(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_key;

    return NULL;
}


const byte* wolfSSL_GetClientWriteIV(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.client_write_IV;

    return NULL;
}


const byte* wolfSSL_GetServerWriteKey(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_key;

    return NULL;
}


const byte* wolfSSL_GetServerWriteIV(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->keys.server_write_IV;

    return NULL;
}

int wolfSSL_GetKeySize(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.key_size;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetIVSize(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.iv_size;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetBulkCipher(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->specs.bulk_cipher_algorithm;

    return BAD_FUNC_ARG;
}


int wolfSSL_GetCipherType(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_AEAD_ONLY
    if (ssl->specs.cipher_type == block)
        return WOLFSSL_BLOCK_TYPE;
    if (ssl->specs.cipher_type == stream)
        return WOLFSSL_STREAM_TYPE;
#endif
    if (ssl->specs.cipher_type == aead)
        return WOLFSSL_AEAD_TYPE;

    return WOLFSSL_FATAL_ERROR;
}


int wolfSSL_GetCipherBlockSize(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.block_size;
}


int wolfSSL_GetAeadMacSize(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->specs.aead_mac_size;
}


int wolfSSL_IsTLSv1_1(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.tls1_1)
        return 1;

    return 0;
}



int wolfSSL_GetHmacSize(WOLFSSL* ssl)
{
    /* AEAD ciphers don't have HMAC keys */
    if (ssl)
        return (ssl->specs.cipher_type != aead) ? ssl->specs.hash_size : 0;

    return BAD_FUNC_ARG;
}

#ifdef WORD64_AVAILABLE
int wolfSSL_GetPeerSequenceNumber(WOLFSSL* ssl, word64 *seq)
{
    if ((ssl == NULL) || (seq == NULL))
        return BAD_FUNC_ARG;

    *seq = ((word64)ssl->keys.peer_sequence_number_hi << 32) |
                    ssl->keys.peer_sequence_number_lo;
    return !(*seq);
}

int wolfSSL_GetSequenceNumber(WOLFSSL* ssl, word64 *seq)
{
    if ((ssl == NULL) || (seq == NULL))
        return BAD_FUNC_ARG;

    *seq = ((word64)ssl->keys.sequence_number_hi << 32) |
                    ssl->keys.sequence_number_lo;
    return !(*seq);
}
#endif

#endif /* ATOMIC_USER */

#ifndef NO_CERTS
WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;
    if (ctx)
        cm = ctx->cm;
    return cm;
}
#endif /* NO_CERTS */

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) \
    && defined(XFPRINTF)

void wolfSSL_ERR_print_errors_fp(XFILE fp, int err)
{
    char data[WOLFSSL_MAX_ERROR_SZ + 1];

    WOLFSSL_ENTER("wolfSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    if (XFPRINTF(fp, "%s", data) < 0)
        WOLFSSL_MSG("fprintf failed in wolfSSL_ERR_print_errors_fp");
}

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
void wolfSSL_ERR_dump_errors_fp(XFILE fp)
{
    wc_ERR_print_errors_fp(fp);
}

void wolfSSL_ERR_print_errors_cb (int (*cb)(const char *str, size_t len,
                                            void *u), void *u)
{
    wc_ERR_print_errors_cb(cb, u);
}
#endif
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM && XFPRINTF */

/*
 * TODO This ssl parameter needs to be changed to const once our ABI checker
 *      stops flagging qualifier additions as ABI breaking.
 */
WOLFSSL_ABI
int wolfSSL_pending(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return (int)ssl->buffers.clearOutputBuffer.length;
}

int wolfSSL_has_pending(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_has_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return ssl->buffers.clearOutputBuffer.length > 0;
}

#ifndef WOLFSSL_LEANPSK
/* turn on handshake group messages for context */
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 1;

    return WOLFSSL_SUCCESS;
}
#endif


#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/* connect enough to get peer cert chain */
int wolfSSL_connect_cert(WOLFSSL* ssl)
{
    int  ret;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->options.certOnly = 1;
    ret = wolfSSL_connect(ssl);
    ssl->options.certOnly   = 0;

    return ret;
}
#endif


#ifndef WOLFSSL_LEANPSK
/* turn on handshake group messages for ssl object */
int wolfSSL_set_group_messages(WOLFSSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return WOLFSSL_SUCCESS;
}


/* make minVersion the internal equivalent SSL version */
static int SetMinVersionHelper(byte* minVersion, int version)
{
    (void)minVersion;

    switch (version) {
#if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
        case WOLFSSL_SSLV3:
            *minVersion = SSLv3_MINOR;
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        #ifdef WOLFSSL_ALLOW_TLSV10
        case WOLFSSL_TLSV1:
            *minVersion = TLSv1_MINOR;
            break;
        #endif

        case WOLFSSL_TLSV1_1:
            *minVersion = TLSv1_1_MINOR;
            break;
    #endif
    #ifndef WOLFSSL_NO_TLS12
        case WOLFSSL_TLSV1_2:
            *minVersion = TLSv1_2_MINOR;
            break;
    #endif
#endif
    #ifdef WOLFSSL_TLS13
        case WOLFSSL_TLSV1_3:
            *minVersion = TLSv1_3_MINOR;
            break;
    #endif

#ifdef WOLFSSL_DTLS
        case WOLFSSL_DTLSV1:
            *minVersion = DTLS_MINOR;
            break;
        case WOLFSSL_DTLSV1_2:
            *minVersion = DTLSv1_2_MINOR;
            break;
#ifdef WOLFSSL_DTLS13
        case WOLFSSL_DTLSV1_3:
            *minVersion = DTLSv1_3_MINOR;
            break;
#endif /* WOLFSSL_DTLS13 */
#endif /* WOLFSSL_DTLS */

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    return WOLFSSL_SUCCESS;
}


/* Set minimum downgrade version allowed, WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetMinVersion");

    if (ctx == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        return CRYPTO_POLICY_FORBIDDEN;
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    return SetMinVersionHelper(&ctx->minDowngrade, version);
}


/* Set minimum downgrade version allowed, WOLFSSL_SUCCESS on ok */
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version)
{
    WOLFSSL_ENTER("wolfSSL_SetMinVersion");

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (crypto_policy.enabled) {
        return CRYPTO_POLICY_FORBIDDEN;
    }
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    return SetMinVersionHelper(&ssl->options.minDowngrade, version);
}


/* Function to get version as WOLFSSL_ enum value for wolfSSL_SetVersion */
int wolfSSL_GetVersion(const WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->version.major == SSLv3_MAJOR) {
        switch (ssl->version.minor) {
            case SSLv3_MINOR :
                return WOLFSSL_SSLV3;
            case TLSv1_MINOR :
                return WOLFSSL_TLSV1;
            case TLSv1_1_MINOR :
                return WOLFSSL_TLSV1_1;
            case TLSv1_2_MINOR :
                return WOLFSSL_TLSV1_2;
            case TLSv1_3_MINOR :
                return WOLFSSL_TLSV1_3;
            default:
                break;
        }
    }
#ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR) {
        switch (ssl->version.minor) {
            case DTLS_MINOR :
                return WOLFSSL_DTLSV1;
            case DTLSv1_2_MINOR :
                return WOLFSSL_DTLSV1_2;
            case DTLSv1_3_MINOR :
                return WOLFSSL_DTLSV1_3;
            default:
                break;
        }
    }
#endif /* WOLFSSL_DTLS */

    return VERSION_ERROR;
}

int wolfSSL_SetVersion(WOLFSSL* ssl, int version)
{
    word16 haveRSA = 1;
    word16 havePSK = 0;
    int    keySz   = 0;

    WOLFSSL_ENTER("wolfSSL_SetVersion");

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
        case WOLFSSL_SSLV3:
            ssl->version = MakeSSLv3();
            break;
#endif

#ifndef NO_TLS
    #ifndef NO_OLD_TLS
        #ifdef WOLFSSL_ALLOW_TLSV10
        case WOLFSSL_TLSV1:
            ssl->version = MakeTLSv1();
            break;
        #endif

        case WOLFSSL_TLSV1_1:
            ssl->version = MakeTLSv1_1();
            break;
    #endif
    #ifndef WOLFSSL_NO_TLS12
        case WOLFSSL_TLSV1_2:
            ssl->version = MakeTLSv1_2();
            break;
    #endif

    #ifdef WOLFSSL_TLS13
        case WOLFSSL_TLSV1_3:
            ssl->version = MakeTLSv1_3();
            break;
    #endif /* WOLFSSL_TLS13 */
#endif

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    #ifdef NO_RSA
        haveRSA = 0;
    #endif
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif
    #ifndef NO_CERTS
        keySz = ssl->buffers.keySz;
    #endif

    if (AllocateSuites(ssl) != 0)
        return WOLFSSL_FAILURE;
    InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
               ssl->options.haveDH, ssl->options.haveECDSAsig,
               ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
               ssl->options.useAnon, TRUE, TRUE, TRUE, TRUE, ssl->options.side);
    return WOLFSSL_SUCCESS;
}
#endif /* !leanpsk */

#ifndef NO_CERTS

/* hash is the SHA digest of name, just use first 32 bits as hash */
static WC_INLINE word32 HashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % CA_TABLE_SIZE;
}


/* does CA already exist on signer list */
int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash)
{
    Signer* signers;
    int     ret = 0;
    word32  row;

    if (cm == NULL || hash == NULL) {
        return ret;
    }

    row = HashSigner(hash);

    if (wc_LockMutex(&cm->caLock) != 0) {
        return ret;
    }
    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;

    #ifndef NO_SKID
        subjectHash = signers->subjectKeyIdHash;
    #else
        subjectHash = signers->subjectNameHash;
    #endif

        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = 1; /* success */
            break;
        }
        signers = signers->next;
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}


#ifdef WOLFSSL_TRUST_PEER_CERT
/* hash is the SHA digest of name, just use first 32 bits as hash */
static WC_INLINE word32 TrustedPeerHashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % TP_TABLE_SIZE;
}

/* does trusted peer already exist on signer list */
int AlreadyTrustedPeer(WOLFSSL_CERT_MANAGER* cm, DecodedCert* cert)
{
    TrustedPeerCert* tp;
    int     ret = 0;
    word32  row = TrustedPeerHashSigner(cert->subjectHash);

    if (wc_LockMutex(&cm->tpLock) != 0)
        return  ret;
    tp = cm->tpTable[row];
    while (tp) {
        if ((XMEMCMP(cert->subjectHash, tp->subjectNameHash,
                SIGNER_DIGEST_SIZE) == 0)
    #ifndef WOLFSSL_NO_ISSUERHASH_TDPEER
         && (XMEMCMP(cert->issuerHash, tp->issuerHash,
                SIGNER_DIGEST_SIZE) == 0)
    #endif
        )
            ret = 1;
    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet) {
            /* Compare SKID as well if available */
            if (ret == 1 && XMEMCMP(cert->extSubjKeyId, tp->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE) != 0)
                ret = 0;
        }
    #endif
        if (ret == 1)
            break;
        tp = tp->next;
    }
    wc_UnLockMutex(&cm->tpLock);

    return ret;
}


/* return Trusted Peer if found, otherwise NULL
    type is what to match on
 */
TrustedPeerCert* GetTrustedPeer(void* vp, DecodedCert* cert)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    TrustedPeerCert* ret = NULL;
    TrustedPeerCert* tp  = NULL;
    word32  row;

    if (cm == NULL || cert == NULL)
        return NULL;

    row = TrustedPeerHashSigner(cert->subjectHash);

    if (wc_LockMutex(&cm->tpLock) != 0)
        return ret;

    tp = cm->tpTable[row];
    while (tp) {
        if ((XMEMCMP(cert->subjectHash, tp->subjectNameHash,
                SIGNER_DIGEST_SIZE) == 0)
        #ifndef WOLFSSL_NO_ISSUERHASH_TDPEER
             && (XMEMCMP(cert->issuerHash, tp->issuerHash,
                SIGNER_DIGEST_SIZE) == 0)
        #endif
            )
            ret = tp;
    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet) {
            /* Compare SKID as well if available */
            if (ret != NULL && XMEMCMP(cert->extSubjKeyId, tp->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE) != 0)
                ret = NULL;
        }
    #endif
        if (ret != NULL)
            break;
        tp = tp->next;
    }
    wc_UnLockMutex(&cm->tpLock);

    return ret;
}


int MatchTrustedPeer(TrustedPeerCert* tp, DecodedCert* cert)
{
    if (tp == NULL || cert == NULL)
        return BAD_FUNC_ARG;

    /* subject key id or subject hash has been compared when searching
       tpTable for the cert from function GetTrustedPeer */

    /* compare signatures */
    if (tp->sigLen == cert->sigLength) {
        if (XMEMCMP(tp->sig, cert->signature, cert->sigLength)) {
            return WOLFSSL_FAILURE;
        }
    }
    else {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


/* return CA if found, otherwise NULL */
Signer* GetCA(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row = 0;

    if (cm == NULL || hash == NULL)
        return NULL;

    row = HashSigner(hash);

    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;

    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;
        #ifndef NO_SKID
            subjectHash = signers->subjectKeyIdHash;
        #else
            subjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}

#if defined(HAVE_OCSP)
Signer* GetCAByKeyHash(void* vp, const byte* keyHash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    int row;

    if (cm == NULL || keyHash == NULL)
        return NULL;

    /* try lookup using keyHash as subjKeyID first */
    ret = GetCA(vp, (byte*)keyHash);
    if (ret != NULL && XMEMCMP(ret->subjectKeyHash, keyHash, KEYID_SIZE) == 0) {
        return ret;
    }

    /* if we can't find the cert, we have to scan the full table */
    if (wc_LockMutex(&cm->caLock) != 0)
        return NULL;

    /* Unfortunately we need to look through the entire table */
    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        for (signers = cm->caTable[row]; signers != NULL;
                signers = signers->next) {
            if (XMEMCMP(signers->subjectKeyHash, keyHash, KEYID_SIZE) == 0) {
                ret = signers;
                break;
            }
        }
    }

    wc_UnLockMutex(&cm->caLock);
    return ret;
}
#endif
#ifdef WOLFSSL_AKID_NAME
Signer* GetCAByAKID(void* vp, const byte* issuer, word32 issuerSz,
        const byte* serial, word32 serialSz)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    byte nameHash[SIGNER_DIGEST_SIZE];
    byte serialHash[SIGNER_DIGEST_SIZE];
    word32 row;

    if (cm == NULL || issuer == NULL || issuerSz == 0 ||
            serial == NULL || serialSz == 0)
        return NULL;

    if (CalcHashId(issuer, issuerSz, nameHash) != 0 ||
            CalcHashId(serial, serialSz, serialHash) != 0)
        return NULL;

    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;

    /* Unfortunately we need to look through the entire table */
    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        for (signers = cm->caTable[row]; signers != NULL;
                signers = signers->next) {
            if (XMEMCMP(signers->subjectNameHash, nameHash, SIGNER_DIGEST_SIZE)
                    == 0 && XMEMCMP(signers->serialHash, serialHash,
                                    SIGNER_DIGEST_SIZE) == 0) {
                ret = signers;
                break;
            }
        }
    }

    wc_UnLockMutex(&cm->caLock);

    return ret;
}
#endif

#ifndef NO_SKID
/* return CA if found, otherwise NULL. Walk through hash table. */
Signer* GetCAByName(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row;

    if (cm == NULL)
        return NULL;

    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;

    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        signers = cm->caTable[row];
        while (signers && ret == NULL) {
            if (XMEMCMP(hash, signers->subjectNameHash,
                        SIGNER_DIGEST_SIZE) == 0) {
                ret = signers;
            }
            signers = signers->next;
        }
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}
#endif


#ifdef WOLFSSL_TRUST_PEER_CERT
/* add a trusted peer cert to linked list */
int AddTrustedPeer(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int verify)
{
    int ret = 0;
    int row = 0;
    TrustedPeerCert* peerCert;
    DecodedCert* cert;
    DerBuffer*   der = *pDer;

    WOLFSSL_MSG("Adding a Trusted Peer Cert");

    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), cm->heap,
                                 DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        FreeDer(&der);
        return MEMORY_E;
    }

    InitDecodedCert(cert, der->buffer, der->length, cm->heap);
    if ((ret = ParseCert(cert, TRUSTED_PEER_TYPE, verify, cm)) != 0) {
        FreeDecodedCert(cert);
        XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
        FreeDer(&der);
        return ret;
    }
    WOLFSSL_MSG("\tParsed new trusted peer cert");

    peerCert = (TrustedPeerCert*)XMALLOC(sizeof(TrustedPeerCert), cm->heap,
                                                             DYNAMIC_TYPE_CERT);
    if (peerCert == NULL) {
        FreeDecodedCert(cert);
        XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
        FreeDer(&der);
        return MEMORY_E;
    }
    XMEMSET(peerCert, 0, sizeof(TrustedPeerCert));

    #ifndef IGNORE_NAME_CONSTRAINTS
        if (peerCert->permittedNames)
            FreeNameSubtrees(peerCert->permittedNames, cm->heap);
        if (peerCert->excludedNames)
            FreeNameSubtrees(peerCert->excludedNames, cm->heap);
    #endif

    if (AlreadyTrustedPeer(cm, cert)) {
        WOLFSSL_MSG("\tAlready have this CA, not adding again");
        FreeTrustedPeer(peerCert, cm->heap);
        (void)ret;
    }
    else {
        /* add trusted peer signature */
        peerCert->sigLen = cert->sigLength;
        peerCert->sig = (byte *)XMALLOC(cert->sigLength, cm->heap,
                                                        DYNAMIC_TYPE_SIGNATURE);
        if (peerCert->sig == NULL) {
            FreeDecodedCert(cert);
            XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
            FreeTrustedPeer(peerCert, cm->heap);
            FreeDer(&der);
            return MEMORY_E;
        }
        XMEMCPY(peerCert->sig, cert->signature, cert->sigLength);

        /* add trusted peer name */
        peerCert->nameLen = cert->subjectCNLen;
        peerCert->name    = cert->subjectCN;
        #ifndef IGNORE_NAME_CONSTRAINTS
            peerCert->permittedNames = cert->permittedNames;
            peerCert->excludedNames  = cert->excludedNames;
        #endif

        /* add SKID when available and hash of name */
        #ifndef NO_SKID
            XMEMCPY(peerCert->subjectKeyIdHash, cert->extSubjKeyId,
                    SIGNER_DIGEST_SIZE);
        #endif
            XMEMCPY(peerCert->subjectNameHash, cert->subjectHash,
                    SIGNER_DIGEST_SIZE);
        #ifndef WOLFSSL_NO_ISSUERHASH_TDPEER
            XMEMCPY(peerCert->issuerHash, cert->issuerHash,
                    SIGNER_DIGEST_SIZE);
        #endif
            /* If Key Usage not set, all uses valid. */
            peerCert->next    = NULL;
            cert->subjectCN = 0;
        #ifndef IGNORE_NAME_CONSTRAINTS
            cert->permittedNames = NULL;
            cert->excludedNames = NULL;
        #endif

            row = (int)TrustedPeerHashSigner(peerCert->subjectNameHash);

            if (wc_LockMutex(&cm->tpLock) == 0) {
                peerCert->next = cm->tpTable[row];
                cm->tpTable[row] = peerCert;   /* takes ownership */
                wc_UnLockMutex(&cm->tpLock);
            }
            else {
                WOLFSSL_MSG("\tTrusted Peer Cert Mutex Lock failed");
                FreeDecodedCert(cert);
                XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
                FreeTrustedPeer(peerCert, cm->heap);
                FreeDer(&der);
                return BAD_MUTEX_E;
            }
        }

    WOLFSSL_MSG("\tFreeing parsed trusted peer cert");
    FreeDecodedCert(cert);
    XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
    WOLFSSL_MSG("\tFreeing der trusted peer cert");
    FreeDer(&der);
    WOLFSSL_MSG("\t\tOK Freeing der trusted peer cert");
    WOLFSSL_LEAVE("AddTrustedPeer", ret);

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */

int AddSigner(WOLFSSL_CERT_MANAGER* cm, Signer *s)
{
    byte*   subjectHash;
    Signer* signers;
    word32  row;

    if (cm == NULL || s == NULL)
        return BAD_FUNC_ARG;

#ifndef NO_SKID
    subjectHash = s->subjectKeyIdHash;
#else
    subjectHash = s->subjectNameHash;
#endif

    if (AlreadySigner(cm, subjectHash)) {
        FreeSigner(s, cm->heap);
        return 0;
    }

    row = HashSigner(subjectHash);

    if (wc_LockMutex(&cm->caLock) != 0)
        return BAD_MUTEX_E;

    signers = cm->caTable[row];
    s->next = signers;
    cm->caTable[row] = s;

    wc_UnLockMutex(&cm->caLock);
    return 0;
}

/* owns der, internal now uses too */
/* type flag ids from user or from chain received during verify
   don't allow chain ones to be added w/o isCA extension */
int AddCA(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int type, int verify)
{
    int         ret;
    Signer*     signer = NULL;
    word32      row;
    byte*       subjectHash;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif
    DerBuffer*   der = *pDer;

    WOLFSSL_MSG("Adding a CA");

    if (cm == NULL) {
        FreeDer(pDer);
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                 DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        FreeDer(pDer);
        return MEMORY_E;
    }
#endif

    InitDecodedCert(cert, der->buffer, der->length, cm->heap);

#ifdef WC_ASN_UNKNOWN_EXT_CB
    if (cm->unknownExtCallback != NULL) {
        wc_SetUnknownExtCallback(cert, cm->unknownExtCallback);
    }
#endif

    ret = ParseCert(cert, CA_TYPE, verify, cm);
    WOLFSSL_MSG("\tParsed new CA");

#ifndef NO_SKID
    subjectHash = cert->extSubjKeyId;
#else
    subjectHash = cert->subjectHash;
#endif

    /* check CA key size */
    if (verify) {
        switch (cert->keyOID) {
        #ifndef NO_RSA
            #ifdef WC_RSA_PSS
            case RSAPSSk:
            #endif
            case RSAk:
                if (cm->minRsaKeySz < 0 ||
                                   cert->pubKeySize < (word16)cm->minRsaKeySz) {
                    ret = RSA_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA RSA key size error");
                }
                break;
        #endif /* !NO_RSA */
            #ifdef HAVE_ECC
            case ECDSAk:
                if (cm->minEccKeySz < 0 ||
                                   cert->pubKeySize < (word16)cm->minEccKeySz) {
                    ret = ECC_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA ECC key size error");
                }
                break;
            #endif /* HAVE_ECC */
            #ifdef HAVE_ED25519
            case ED25519k:
                if (cm->minEccKeySz < 0 ||
                                   ED25519_KEY_SIZE < (word16)cm->minEccKeySz) {
                    ret = ECC_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA ECC key size error");
                }
                break;
            #endif /* HAVE_ED25519 */
            #ifdef HAVE_ED448
            case ED448k:
                if (cm->minEccKeySz < 0 ||
                                     ED448_KEY_SIZE < (word16)cm->minEccKeySz) {
                    ret = ECC_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA ECC key size error");
                }
                break;
            #endif /* HAVE_ED448 */
            #if defined(HAVE_FALCON)
            case FALCON_LEVEL1k:
                if (cm->minFalconKeySz < 0 ||
                          FALCON_LEVEL1_KEY_SIZE < (word16)cm->minFalconKeySz) {
                    ret = FALCON_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA Falcon level 1 key size error");
                }
                break;
            case FALCON_LEVEL5k:
                if (cm->minFalconKeySz < 0 ||
                          FALCON_LEVEL5_KEY_SIZE < (word16)cm->minFalconKeySz) {
                    ret = FALCON_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA Falcon level 5 key size error");
                }
                break;
            #endif /* HAVE_FALCON */
            #if defined(HAVE_DILITHIUM)
            case DILITHIUM_LEVEL2k:
                if (cm->minDilithiumKeySz < 0 ||
                    DILITHIUM_LEVEL2_KEY_SIZE < (word16)cm->minDilithiumKeySz) {
                    ret = DILITHIUM_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA Dilithium level 2 key size error");
                }
                break;
            case DILITHIUM_LEVEL3k:
                if (cm->minDilithiumKeySz < 0 ||
                    DILITHIUM_LEVEL3_KEY_SIZE < (word16)cm->minDilithiumKeySz) {
                    ret = DILITHIUM_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA Dilithium level 3 key size error");
                }
                break;
            case DILITHIUM_LEVEL5k:
                if (cm->minDilithiumKeySz < 0 ||
                    DILITHIUM_LEVEL5_KEY_SIZE < (word16)cm->minDilithiumKeySz) {
                    ret = DILITHIUM_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA Dilithium level 5 key size error");
                }
                break;
            #endif /* HAVE_DILITHIUM */

            default:
                WOLFSSL_MSG("\tNo key size check done on CA");
                break; /* no size check if key type is not in switch */
        }
    }

    if (ret == 0 && cert->isCA == 0 && type != WOLFSSL_USER_CA &&
        type != WOLFSSL_TEMP_CA) {
        WOLFSSL_MSG("\tCan't add as CA if not actually one");
        ret = NOT_CA_ERROR;
    }
#ifndef ALLOW_INVALID_CERTSIGN
    else if (ret == 0 && cert->isCA == 1 && type != WOLFSSL_USER_CA &&
        type != WOLFSSL_TEMP_CA && !cert->selfSigned &&
        (cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
        /* Intermediate CA certs are required to have the keyCertSign
        * extension set. User loaded root certs are not. */
        WOLFSSL_MSG("\tDoesn't have key usage certificate signing");
        ret = NOT_CA_ERROR;
    }
#endif
    else if (ret == 0 && AlreadySigner(cm, subjectHash)) {
        WOLFSSL_MSG("\tAlready have this CA, not adding again");
        (void)ret;
    }
    else if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner(cm->heap);
        if (!signer)
            ret = MEMORY_ERROR;
    }
    if (ret == 0 && signer != NULL) {
        ret = FillSigner(signer, cert, type, der);

    #ifndef NO_SKID
        row = HashSigner(signer->subjectKeyIdHash);
    #else
        row = HashSigner(signer->subjectNameHash);
    #endif

    #if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
        /* Verify CA by TSIP so that generated tsip key is going to          */
        /* be able to be used for peer's cert verification                   */
        /* TSIP is only able to handle USER CA, and only one CA.             */
        /* Therefore, it doesn't need to call TSIP again if there is already */
        /* verified CA.                                                      */
        if ( ret == 0 && signer != NULL ) {
            signer->cm_idx = row;
            if (type == WOLFSSL_USER_CA) {
                if ((ret = wc_Renesas_cmn_RootCertVerify(cert->source,
                        cert->maxIdx,
                        cert->sigCtx.CertAtt.pubkey_n_start,
                        cert->sigCtx.CertAtt.pubkey_n_len - 1,
                        cert->sigCtx.CertAtt.pubkey_e_start,
                        cert->sigCtx.CertAtt.pubkey_e_len - 1,
                     row/* cm index */))
                    < 0)
                    WOLFSSL_MSG("Renesas_RootCertVerify() failed");
                else
                    WOLFSSL_MSG("Renesas_RootCertVerify() succeed or skipped");
            }
        }
    #endif /* TSIP or SCE */

        if (ret == 0 && wc_LockMutex(&cm->caLock) == 0) {
            signer->next = cm->caTable[row];
            cm->caTable[row] = signer;   /* takes ownership */
            wc_UnLockMutex(&cm->caLock);
            if (cm->caCacheCallback)
                cm->caCacheCallback(der->buffer, (int)der->length, type);
        }
        else {
            WOLFSSL_MSG("\tCA Mutex Lock failed");
            ret = BAD_MUTEX_E;
        }
    }

    WOLFSSL_MSG("\tFreeing Parsed CA");
    FreeDecodedCert(cert);
    if (ret != 0 && signer != NULL)
        FreeSigner(signer, cm->heap);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
#endif
    WOLFSSL_MSG("\tFreeing der CA");
    FreeDer(pDer);
    WOLFSSL_MSG("\t\tOK Freeing der CA");

    WOLFSSL_LEAVE("AddCA", ret);

    return ret == 0 ? WOLFSSL_SUCCESS : ret;
}

#endif /* !NO_CERTS */


#if defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_OPENSSL_RAND_CB)
static int wolfSSL_RAND_InitMutex(void);
#endif

/* If we don't have static mutex initializers, but we do have static atomic
 * initializers, activate WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS to leverage
 * the latter.
 *
 * See further explanation below in wolfSSL_Init().
 */
#ifndef WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
    #if !defined(WOLFSSL_MUTEX_INITIALIZER) && !defined(SINGLE_THREADED) && \
            defined(WOLFSSL_ATOMIC_OPS) && defined(WOLFSSL_ATOMIC_INITIALIZER)
        #define WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS 1
    #else
        #define WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS 0
    #endif
#elif defined(WOLFSSL_MUTEX_INITIALIZER) || defined(SINGLE_THREADED)
    #undef WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
    #define WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS 0
#endif

#if WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
    #ifndef WOLFSSL_ATOMIC_OPS
        #error WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS requires WOLFSSL_ATOMIC_OPS
    #endif
    #ifndef WOLFSSL_ATOMIC_INITIALIZER
        #error WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS requires WOLFSSL_ATOMIC_INITIALIZER
    #endif
    static wolfSSL_Atomic_Int inits_count_mutex_atomic_initing_flag =
        WOLFSSL_ATOMIC_INITIALIZER(0);
#endif /* WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS && !WOLFSSL_MUTEX_INITIALIZER */

#if defined(OPENSSL_EXTRA) && defined(HAVE_ATEXIT)
static void AtExitCleanup(void)
{
    if (initRefCount > 0) {
        initRefCount = 1;
        (void)wolfSSL_Cleanup();
#if WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
        if (inits_count_mutex_valid == 1) {
            (void)wc_FreeMutex(&inits_count_mutex);
            inits_count_mutex_valid = 0;
            inits_count_mutex_atomic_initing_flag = 0;
        }
#endif
    }
}
#endif

WOLFSSL_ABI
int wolfSSL_Init(void)
{
    int ret = WOLFSSL_SUCCESS;
#if !defined(NO_SESSION_CACHE) && defined(ENABLE_SESSION_CACHE_ROW_LOCK)
    int i;
#endif

    WOLFSSL_ENTER("wolfSSL_Init");

#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (inits_count_mutex_valid == 0) {
    #if WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS

        /* Without this mitigation, if two threads enter wolfSSL_Init() at the
         * same time, and both see zero inits_count_mutex_valid, then both will
         * run wc_InitMutex(&inits_count_mutex), leading to process corruption
         * or (best case) a resource leak.
         *
         * When WOLFSSL_ATOMIC_INITIALIZER() is available, we can mitigate this
         * by use an atomic counting int as a mutex.
         */

        if (wolfSSL_Atomic_Int_FetchAdd(&inits_count_mutex_atomic_initing_flag,
                                        1) != 0)
        {
            (void)wolfSSL_Atomic_Int_FetchSub(
                &inits_count_mutex_atomic_initing_flag, 1);
            return DEADLOCK_AVERTED_E;
        }
    #endif /* WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS */
        if (wc_InitMutex(&inits_count_mutex) != 0) {
            WOLFSSL_MSG("Bad Init Mutex count");
    #if WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
            (void)wolfSSL_Atomic_Int_FetchSub(
                &inits_count_mutex_atomic_initing_flag, 1);
    #endif
            return BAD_MUTEX_E;
        }
        else {
            inits_count_mutex_valid = 1;
        }
    }
#endif /* !WOLFSSL_MUTEX_INITIALIZER */

    if (wc_LockMutex(&inits_count_mutex) != 0) {
        WOLFSSL_MSG("Bad Lock Mutex count");
        return BAD_MUTEX_E;
    }

#if FIPS_VERSION_GE(5,1)
    if ((ret == WOLFSSL_SUCCESS) && (initRefCount == 0)) {
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
        if (ret == 0)
            ret = WOLFSSL_SUCCESS;
    }
#endif

    if ((ret == WOLFSSL_SUCCESS) && (initRefCount == 0)) {
        /* Initialize crypto for use with TLS connection */

        if (wolfCrypt_Init() != 0) {
            WOLFSSL_MSG("Bad wolfCrypt Init");
            ret = WC_INIT_E;
        }

#if defined(HAVE_GLOBAL_RNG) && !defined(WOLFSSL_MUTEX_INITIALIZER)
        if (ret == WOLFSSL_SUCCESS) {
            if (wc_InitMutex(&globalRNGMutex) != 0) {
                WOLFSSL_MSG("Bad Init Mutex rng");
                ret = BAD_MUTEX_E;
            }
            else {
                globalRNGMutex_valid = 1;
            }
        }
#endif

    #ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
    #endif

#ifdef OPENSSL_EXTRA
    #ifndef WOLFSSL_NO_OPENSSL_RAND_CB
        if ((ret == WOLFSSL_SUCCESS) && (wolfSSL_RAND_InitMutex() != 0)) {
            ret = BAD_MUTEX_E;
        }
    #endif
        if ((ret == WOLFSSL_SUCCESS) &&
            (wolfSSL_RAND_seed(NULL, 0) != WOLFSSL_SUCCESS)) {
            WOLFSSL_MSG("wolfSSL_RAND_seed failed");
            ret = WC_INIT_E;
        }
#endif

#ifndef NO_SESSION_CACHE
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        for (i = 0; i < SESSION_ROWS; ++i) {
            SessionCache[i].lock_valid = 0;
        }
        for (i = 0; (ret == WOLFSSL_SUCCESS) && (i < SESSION_ROWS); ++i) {
            if (wc_InitRwLock(&SessionCache[i].row_lock) != 0) {
                WOLFSSL_MSG("Bad Init Mutex session");
                ret = BAD_MUTEX_E;
            }
            else {
                SessionCache[i].lock_valid = 1;
            }
        }
    #else
        if (ret == WOLFSSL_SUCCESS) {
            if (wc_InitRwLock(&session_lock) != 0) {
                WOLFSSL_MSG("Bad Init Mutex session");
                ret = BAD_MUTEX_E;
            }
            else {
                session_lock_valid = 1;
            }
        }
    #endif
    #ifndef NO_CLIENT_CACHE
        #ifndef WOLFSSL_MUTEX_INITIALIZER
        if (ret == WOLFSSL_SUCCESS) {
            if (wc_InitMutex(&clisession_mutex) != 0) {
                WOLFSSL_MSG("Bad Init Mutex session");
                ret = BAD_MUTEX_E;
            }
            else {
                clisession_mutex_valid = 1;
            }
        }
        #endif
    #endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_ATEXIT)
        /* OpenSSL registers cleanup using atexit */
        if ((ret == WOLFSSL_SUCCESS) && (atexit(AtExitCleanup) != 0)) {
            WOLFSSL_MSG("Bad atexit registration");
            ret = WC_INIT_E;
        }
#endif
    }

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    /* System wide crypto policy disabled by default. */
    XMEMSET(&crypto_policy, 0, sizeof(crypto_policy));
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

    if (ret == WOLFSSL_SUCCESS) {
        initRefCount++;
    }
    else {
        initRefCount = 1; /* Force cleanup */
    }

    wc_UnLockMutex(&inits_count_mutex);

    if (ret != WOLFSSL_SUCCESS) {
        (void)wolfSSL_Cleanup(); /* Ignore any error from cleanup */
    }

    return ret;
}

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
/* Helper function for wolfSSL_crypto_policy_enable and
 * wolfSSL_crypto_policy_enable_buffer.
 *
 * Parses the crypto policy string, verifies values,
 * and sets in global crypto policy struct. Not thread
 * safe. String length has already been verified.
 *
 * Returns WOLFSSL_SUCCESS on success.
 * Returns CRYPTO_POLICY_FORBIDDEN if already enabled.
 * Returns < 0 on misc error.
 * */
static int crypto_policy_parse(void)
{
    const char * hdr = WOLFSSL_SECLEVEL_STR;
    int          sec_level = 0;
    size_t       i = 0;

    /* All policies should begin with "@SECLEVEL=<N>" (N={0..5}) followed
     * by bulk cipher list. */
    if (XMEMCMP(crypto_policy.str, hdr, strlen(hdr)) != 0) {
        WOLFSSL_MSG("error: crypto policy: invalid header");
        return WOLFSSL_BAD_FILE;
    }

    {
        /* Extract the security level. */
        char *       policy_mem = crypto_policy.str;
        policy_mem += strlen(hdr);
        sec_level = (int) (*policy_mem - '0');
    }

    if (sec_level < MIN_WOLFSSL_SEC_LEVEL ||
        sec_level > MAX_WOLFSSL_SEC_LEVEL) {
        WOLFSSL_MSG_EX("error: invalid SECLEVEL: %d", sec_level);
        return WOLFSSL_BAD_FILE;
    }

    /* Remove trailing '\r' or '\n'. */
    for (i = 0; i < MAX_WOLFSSL_CRYPTO_POLICY_SIZE; ++i) {
        if (crypto_policy.str[i] == '\0') {
            break;
        }

        if (crypto_policy.str[i] == '\r' || crypto_policy.str[i] == '\n') {
            crypto_policy.str[i] = '\0';
            break;
        }
    }

    #if defined(DEBUG_WOLFSSL_VERBOSE)
    WOLFSSL_MSG_EX("info: SECLEVEL=%d", sec_level);
    WOLFSSL_MSG_EX("info: using crypto-policy file: %s, %ld", policy_file, sz);
    #endif /* DEBUG_WOLFSSL_VERBOSE */

    crypto_policy.secLevel = sec_level;
    crypto_policy.enabled = 1;

    return WOLFSSL_SUCCESS;
}

#ifndef NO_FILESYSTEM
/* Enables wolfSSL system wide crypto-policy, using the given policy
 * file arg. If NULL is passed, then the default system crypto-policy
 * file that was set at configure time will be used instead.
 *
 * While enabled:
 *   - TLS methods, min key sizes, and cipher lists are all configured
 *     automatically by the policy.
 *   - Attempting to use lesser strength parameters will fail with
 *     error CRYPTO_POLICY_FORBIDDEN.
 *
 * Disable with wolfSSL_crypto_policy_disable.
 *
 * Note: the wolfSSL_crypto_policy_X API are not thread safe, and should
 * only be called at program init time.
 *
 * Returns WOLFSSL_SUCCESS on success.
 * Returns CRYPTO_POLICY_FORBIDDEN if already enabled.
 * Returns < 0 on misc error.
 * */
int wolfSSL_crypto_policy_enable(const char * policy_file)
{
    XFILE   file;
    long    sz = 0;
    size_t  n_read = 0;

    WOLFSSL_ENTER("wolfSSL_crypto_policy_enable");

    if (wolfSSL_crypto_policy_is_enabled()) {
        WOLFSSL_MSG_EX("error: crypto policy already enabled: %s",
                       policy_file);
        return CRYPTO_POLICY_FORBIDDEN;
    }

    if (policy_file == NULL) {
        /* Use the configure-time default if NULL passed. */
        policy_file = WC_STRINGIFY(WOLFSSL_CRYPTO_POLICY_FILE);
    }

    if (policy_file == NULL || *policy_file == '\0') {
        WOLFSSL_MSG("error: crypto policy empty file");
        return BAD_FUNC_ARG;
    }

    XMEMSET(&crypto_policy, 0, sizeof(crypto_policy));

    file = XFOPEN(policy_file, "rb");

    if (file == XBADFILE) {
        WOLFSSL_MSG_EX("error: crypto policy file open failed: %s",
                       policy_file);
        return WOLFSSL_BAD_FILE;
    }

    if (XFSEEK(file, 0, XSEEK_END) != 0) {
        WOLFSSL_MSG_EX("error: crypto policy file seek end failed: %s",
                       policy_file);
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    sz = XFTELL(file);

    if (XFSEEK(file, 0, XSEEK_SET) != 0) {
        WOLFSSL_MSG_EX("error: crypto policy file seek failed: %s",
                       policy_file);
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    if (sz <= 0 || sz > MAX_WOLFSSL_CRYPTO_POLICY_SIZE) {
        WOLFSSL_MSG_EX("error: crypto policy file %s, invalid size: %ld",
                       policy_file, sz);
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    n_read = XFREAD(crypto_policy.str, 1, sz, file);
    XFCLOSE(file);

    if (n_read != (size_t) sz) {
        WOLFSSL_MSG_EX("error: crypto policy file %s: read %zu, "
                       "expected %ld", policy_file, n_read, sz);
        return WOLFSSL_BAD_FILE;
    }

    crypto_policy.str[n_read] = '\0';

    return crypto_policy_parse();
}
#endif /* ! NO_FILESYSTEM */

/* Same behavior as wolfSSL_crypto_policy_enable, but loads
 * via memory buf instead of file.
 *
 * Returns WOLFSSL_SUCCESS on success.
 * Returns CRYPTO_POLICY_FORBIDDEN if already enabled.
 * Returns < 0 on misc error.
 * */
int wolfSSL_crypto_policy_enable_buffer(const char * buf)
{
    size_t sz = 0;

    WOLFSSL_ENTER("wolfSSL_crypto_policy_enable_buffer");

    if (wolfSSL_crypto_policy_is_enabled()) {
        WOLFSSL_MSG_EX("error: crypto policy already enabled");
        return CRYPTO_POLICY_FORBIDDEN;
    }

    if (buf == NULL || *buf == '\0') {
        return BAD_FUNC_ARG;
    }

    sz = XSTRLEN(buf);

    if (sz == 0 || sz > MAX_WOLFSSL_CRYPTO_POLICY_SIZE) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&crypto_policy, 0, sizeof(crypto_policy));
    XMEMCPY(crypto_policy.str, buf, sz);

    return crypto_policy_parse();
}

/* Returns whether the system wide crypto-policy is enabled.
 *
 * Returns 1 if enabled.
 *         0 if disabled.
 * */
int wolfSSL_crypto_policy_is_enabled(void)
{
    WOLFSSL_ENTER("wolfSSL_crypto_policy_is_enabled");

    return crypto_policy.enabled == 1;
}

/* Disables the system wide crypto-policy.
 * note: SSL and CTX structures already instantiated will
 * keep their security policy parameters. This will only
 * affect new instantiations.
 * */
void wolfSSL_crypto_policy_disable(void)
{
    WOLFSSL_ENTER("wolfSSL_crypto_policy_disable");
    crypto_policy.enabled = 0;
    XMEMSET(&crypto_policy, 0, sizeof(crypto_policy));
    return;
}

/* Get the crypto-policy bulk cipher list string.
 * String is not owned by caller, should not be freed.
 *
 * Returns pointer to bulk cipher list string.
 * Returns NULL if NOT enabled, or on error.
 * */
const char * wolfSSL_crypto_policy_get_ciphers(void)
{
    WOLFSSL_ENTER("wolfSSL_crypto_policy_get_ciphers");

    if (crypto_policy.enabled == 1) {
        /* The crypto policy config will have
         * this form:
         *   "@SECLEVEL=2:kEECDH:kRSA..." */
        return crypto_policy.str;
    }

    return NULL;
}

/* Get the configured crypto-policy security level.
 * A security level of 0 does not impose any additional
 * restrictions.
 *
 * Returns 1 - 5 if enabled.
 * Returns 0 if NOT enabled.
 * */
int wolfSSL_crypto_policy_get_level(void)
{
    if (crypto_policy.enabled == 1) {
        return crypto_policy.secLevel;
    }

    return 0;
}

/* Get security level from ssl structure.
 * @param ssl  a pointer to WOLFSSL structure
 */
int wolfSSL_get_security_level(const WOLFSSL * ssl)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    return ssl->secLevel;
}

#ifndef NO_WOLFSSL_STUB
/*
 * Set security level (wolfSSL doesn't support setting the security level).
 *
 * The security level can only be set through a system wide crypto-policy
 * with wolfSSL_crypto_policy_enable().
 *
 * @param ssl  a pointer to WOLFSSL structure
 * @param level security level
 */
void wolfSSL_set_security_level(WOLFSSL * ssl, int level)
{
    WOLFSSL_ENTER("wolfSSL_set_security_level");
    (void)ssl;
    (void)level;
}
#endif /* !NO_WOLFSSL_STUB */

#endif /* WOLFSSL_SYS_CRYPTO_POLICY */


#define WOLFSSL_SSL_LOAD_INCLUDED
#include <src/ssl_load.c>

#ifndef NO_CERTS

#ifdef HAVE_CRL

int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                              long sz, int type)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRLBuffer");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return wolfSSL_CertManagerLoadCRLBuffer(ctx->cm, buff, sz, type);
}


int wolfSSL_LoadCRLBuffer(WOLFSSL* ssl, const unsigned char* buff,
                          long sz, int type)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRLBuffer");

    if (ssl == NULL || ssl->ctx == NULL)
        return BAD_FUNC_ARG;

    SSL_CM_WARNING(ssl);
    return wolfSSL_CertManagerLoadCRLBuffer(SSL_CM(ssl), buff, sz, type);
}

#endif /* HAVE_CRL */

#ifdef HAVE_OCSP
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER("wolfSSL_EnableOCSP");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_DisableOCSP(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableOCSP");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableOCSP(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_EnableOCSPStapling");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableOCSPStapling(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableOCSPStapling");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableOCSPStapling(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_OverrideURL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url);
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        ssl->ocspIOCtx = ioCbCtx; /* use SSL specific ioCbCtx */
        return wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl),
                                             ioCb, respFreeCb, NULL);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSP");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSP(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSP");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSP(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_OverrideURL");
    if (ctx)
        return wolfSSL_CertManagerSetOCSPOverrideURL(ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx, CbOCSPIO ioCb,
                           CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetOCSP_Cb");
    if (ctx)
        return wolfSSL_CertManagerSetOCSP_Cb(ctx->cm, ioCb,
                                             respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPStapling");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPStapling");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSPStapling(ctx->cm);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPMustStaple");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSPMustStaple(ctx->cm);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPMustStaple");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSPMustStaple(ctx->cm);
    else
        return BAD_FUNC_ARG;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST || \
        * HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

#endif /* HAVE_OCSP */

#ifdef HAVE_CRL

int wolfSSL_EnableCRL(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER("wolfSSL_EnableCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableCRL(SSL_CM(ssl), options);
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_DisableCRL(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableCRL(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}

#ifndef NO_FILESYSTEM
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRLFile");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerLoadCRLFile(SSL_CM(ssl), file, type);
    }
    else
        return BAD_FUNC_ARG;
}
#endif

int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_SetCRL_ErrorCb(WOLFSSL* ssl, crlErrorCb cb, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_ErrorCb(SSL_CM(ssl), cb, ctx);
    }
    else
        return BAD_FUNC_ARG;
}

#ifdef HAVE_CRL_IO
int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_IOCb(SSL_CM(ssl), cb);
    }
    else
        return BAD_FUNC_ARG;
}
#endif

int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableCRL");
    if (ctx)
        return wolfSSL_CertManagerEnableCRL(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableCRL");
    if (ctx)
        return wolfSSL_CertManagerDisableCRL(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


#ifndef NO_FILESYSTEM
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path,
                        int type, int monitor)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRL");
    if (ctx)
        return wolfSSL_CertManagerLoadCRL(ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* file,
                        int type)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRL");
    if (ctx)
        return wolfSSL_CertManagerLoadCRLFile(ctx->cm, file, type);
    else
        return BAD_FUNC_ARG;
}
#endif


int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_Cb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_SetCRL_ErrorCb(WOLFSSL_CTX* ctx, crlErrorCb cb, void* cbCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_ErrorCb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_ErrorCb(ctx->cm, cb, cbCtx);
    else
        return BAD_FUNC_ARG;
}

#ifdef HAVE_CRL_IO
int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_IOCb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_IOCb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}
#endif


#endif /* HAVE_CRL */


/* Sets the max chain depth when verifying a certificate chain. Default depth
 * is set to MAX_CHAIN_DEPTH.
 *
 * ctx   WOLFSSL_CTX structure to set depth in
 * depth max depth
 */
void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx, int depth) {
    WOLFSSL_ENTER("wolfSSL_CTX_set_verify_depth");

    if (ctx == NULL || depth < 0 || depth > MAX_CHAIN_DEPTH) {
        WOLFSSL_MSG("Bad depth argument, too large or less than 0");
        return;
    }

    ctx->verifyDepth = (byte)depth;
}


/* get cert chaining depth using ssl struct */
long wolfSSL_get_verify_depth(WOLFSSL* ssl)
{
    if(ssl == NULL) {
        return BAD_FUNC_ARG;
    }
#ifndef OPENSSL_EXTRA
    return MAX_CHAIN_DEPTH;
#else
    return ssl->options.verifyDepth;
#endif
}


/* get cert chaining depth using ctx struct */
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
#ifndef OPENSSL_EXTRA
    return MAX_CHAIN_DEPTH;
#else
    return ctx->verifyDepth;
#endif
}

#ifndef NO_CHECK_PRIVATE_KEY

#ifdef WOLF_PRIVATE_KEY_ID
/* Check private against public in certificate for match using external
 * device with given devId */
static int check_cert_key_dev(word32 keyOID, byte* privKey, word32 privSz,
    const byte* pubKey, word32 pubSz, int label, int id, void* heap, int devId)
{
    int ret = 0;
    int type = 0;
    void *pkey = NULL;

    if (privKey == NULL) {
        return MISSING_KEY;
    }

#ifndef NO_RSA
    if (keyOID == RSAk) {
        type = DYNAMIC_TYPE_RSA;
    }
#ifdef WC_RSA_PSS
    if (keyOID == RSAPSSk) {
        type = DYNAMIC_TYPE_RSA;
    }
#endif
#endif
#ifdef HAVE_ECC
    if (keyOID == ECDSAk) {
        type = DYNAMIC_TYPE_ECC;
    }
#endif
#if defined(HAVE_DILITHIUM)
    if ((keyOID == DILITHIUM_LEVEL2k) ||
        (keyOID == DILITHIUM_LEVEL3k) ||
        (keyOID == DILITHIUM_LEVEL5k)) {
        type = DYNAMIC_TYPE_DILITHIUM;
    }
#endif
#if defined(HAVE_FALCON)
    if ((keyOID == FALCON_LEVEL1k) ||
        (keyOID == FALCON_LEVEL5k)) {
        type = DYNAMIC_TYPE_FALCON;
    }
#endif

    ret = CreateDevPrivateKey(&pkey, privKey, privSz, type, label, id,
                              heap, devId);
    #ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
        #ifndef NO_RSA
        if (keyOID == RSAk
        #ifdef WC_RSA_PSS
            || keyOID == RSAPSSk
        #endif
            ) {
            ret = wc_CryptoCb_RsaCheckPrivKey((RsaKey*)pkey, pubKey, pubSz);
        }
        #endif
        #ifdef HAVE_ECC
        if (keyOID == ECDSAk) {
            ret = wc_CryptoCb_EccCheckPrivKey((ecc_key*)pkey, pubKey, pubSz);
        }
        #endif
        #if defined(HAVE_DILITHIUM)
        if ((keyOID == DILITHIUM_LEVEL2k) ||
            (keyOID == DILITHIUM_LEVEL3k) ||
            (keyOID == DILITHIUM_LEVEL5k)) {
            ret = wc_CryptoCb_PqcSignatureCheckPrivKey(pkey,
                                        WC_PQC_SIG_TYPE_DILITHIUM,
                                        pubKey, pubSz);
        }
        #endif
        #if defined(HAVE_FALCON)
        if ((keyOID == FALCON_LEVEL1k) ||
            (keyOID == FALCON_LEVEL5k)) {
            ret = wc_CryptoCb_PqcSignatureCheckPrivKey(pkey,
                                        WC_PQC_SIG_TYPE_FALCON,
                                        pubKey, pubSz);
        }
        #endif
    }
    #else
        /* devId was set, don't check, for now */
        /* TODO: Add callback for private key check? */
        (void) pubKey;
        (void) pubSz;
    #endif
    if (pkey != NULL) {
    #ifndef NO_RSA
        if (keyOID == RSAk
        #ifdef WC_RSA_PSS
            || keyOID == RSAPSSk
        #endif
            ) {
            wc_FreeRsaKey((RsaKey*)pkey);
        }
    #endif
    #ifdef HAVE_ECC
        if (keyOID == ECDSAk) {
            wc_ecc_free((ecc_key*)pkey);
        }
    #endif
    #if defined(HAVE_DILITHIUM)
        if ((keyOID == DILITHIUM_LEVEL2k) ||
            (keyOID == DILITHIUM_LEVEL3k) ||
            (keyOID == DILITHIUM_LEVEL5k)) {
            wc_dilithium_free((dilithium_key*)pkey);
        }
    #endif
    #if defined(HAVE_FALCON)
        if ((keyOID == FALCON_LEVEL1k) ||
            (keyOID == FALCON_LEVEL5k)) {
            wc_falcon_free((falcon_key*)pkey);
        }
    #endif
        XFREE(pkey, heap, type);
    }

    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID */

/* Check private against public in certificate for match
 *
 * Returns WOLFSSL_SUCCESS on good private key
 *         WOLFSSL_FAILURE if mismatched */
static int check_cert_key(DerBuffer* cert, DerBuffer* key, DerBuffer* altKey,
    void* heap, int devId, int isKeyLabel, int isKeyId, int altDevId,
    int isAltKeyLabel, int isAltKeyId)
{
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* der = NULL;
#else
    DecodedCert  der[1];
#endif
    word32 size;
    byte*  buff;
    int    ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    WOLFSSL_ENTER("check_cert_key");

    if (cert == NULL || key == NULL) {
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    der = (DecodedCert*)XMALLOC(sizeof(DecodedCert), heap, DYNAMIC_TYPE_DCERT);
    if (der == NULL)
        return MEMORY_E;
#endif

    size = cert->length;
    buff = cert->buffer;
    InitDecodedCert_ex(der, buff, size, heap, devId);
    if (ParseCertRelative(der, CERT_TYPE, NO_VERIFY, NULL, NULL) != 0) {
        FreeDecodedCert(der);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(der, heap, DYNAMIC_TYPE_DCERT);
    #endif
        return WOLFSSL_FAILURE;
    }

    size = key->length;
    buff = key->buffer;
#ifdef WOLF_PRIVATE_KEY_ID
    if (devId != INVALID_DEVID) {
        ret = check_cert_key_dev(der->keyOID, buff, size, der->publicKey,
                                 der->pubKeySize, isKeyLabel, isKeyId, heap,
                                 devId);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            ret = (ret == 0) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
        }
    }
    else {
        /* fall through if unavailable */
        ret = CRYPTOCB_UNAVAILABLE;
    }

    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
#endif /* WOLF_PRIVATE_KEY_ID */
    {
        ret = wc_CheckPrivateKeyCert(buff, size, der, 0, heap);
        ret = (ret == 1) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_DUAL_ALG_CERTS
    if (ret == WOLFSSL_SUCCESS && der->extSapkiSet && der->sapkiDer != NULL) {
        /* Certificate contains an alternative public key. Hence, we also
         * need an alternative private key. */
        if (altKey == NULL) {
            ret = MISSING_KEY;
            buff = NULL;
            size = 0;
        }
        else {
            size = altKey->length;
            buff = altKey->buffer;
        }
#ifdef WOLF_PRIVATE_KEY_ID
        if (ret == WOLFSSL_SUCCESS && altDevId != INVALID_DEVID) {
            /* We have to decode the public key first */
            word32 idx = 0;
            /* Dilithium has the largest public key at the moment */
            word32 pubKeyLen = DILITHIUM_MAX_PUB_KEY_SIZE;
            byte* decodedPubKey = (byte*)XMALLOC(pubKeyLen, heap,
                                            DYNAMIC_TYPE_PUBLIC_KEY);
            if (decodedPubKey == NULL) {
                ret = MEMORY_E;
            }
            if (ret == WOLFSSL_SUCCESS) {
                if (der->sapkiOID == RSAk || der->sapkiOID == ECDSAk) {
                    /* Simply copy the data */
                    XMEMCPY(decodedPubKey, der->sapkiDer, der->sapkiLen);
                    pubKeyLen = der->sapkiLen;
                    ret = 0;
                }
                else {
                    ret = DecodeAsymKeyPublic(der->sapkiDer, &idx,
                                              der->sapkiLen, decodedPubKey,
                                              &pubKeyLen, der->sapkiOID);
                }
            }
            if (ret == 0) {
                ret = check_cert_key_dev(der->sapkiOID, buff, size,
                                         decodedPubKey, pubKeyLen,
                                         isAltKeyLabel, isAltKeyId,
                                         heap, altDevId);
            }
            XFREE(decodedPubKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                ret = (ret == 0) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
            }
        }
        else {
            /* fall through if unavailable */
            ret = CRYPTOCB_UNAVAILABLE;
        }

        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
#endif /* WOLF_PRIVATE_KEY_ID */
        {
            ret = wc_CheckPrivateKeyCert(buff, size, der, 1, heap);
            ret = (ret == 1) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
        }
    }
#endif /* WOLFSSL_DUAL_ALG_CERTS */
    FreeDecodedCert(der);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(der, heap, DYNAMIC_TYPE_DCERT);
#endif

    (void)devId;
    (void)isKeyLabel;
    (void)isKeyId;
    (void)altKey;
    (void)altDevId;
    (void)isAltKeyLabel;
    (void)isAltKeyId;

    return ret;
}

/* Check private against public in certificate for match
 *
 * ctx  WOLFSSL_CTX structure to check private key in
 *
 * Returns WOLFSSL_SUCCESS on good private key
 *         WOLFSSL_FAILURE if mismatched. */
int wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx)
{
    int res;

    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_DUAL_ALG_CERTS
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    wolfssl_priv_der_unblind(ctx->privateKey, ctx->privateKeyMask);
    wolfssl_priv_der_unblind(ctx->altPrivateKey, ctx->altPrivateKeyMask);
#endif
    res = check_cert_key(ctx->certificate, ctx->privateKey, ctx->altPrivateKey,
            ctx->heap, ctx->privateKeyDevId, ctx->privateKeyLabel,
            ctx->privateKeyId, ctx->altPrivateKeyDevId, ctx->altPrivateKeyLabel,
            ctx->altPrivateKeyId) != 0;
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    {
        int ret;
        ret = wolfssl_priv_der_blind(NULL, ctx->privateKey,
            (DerBuffer**)&ctx->privateKeyMask);
        if (ret == 0) {
            ret = wolfssl_priv_der_blind(NULL, ctx->altPrivateKey,
                (DerBuffer**)&ctx->altPrivateKeyMask);
        }
        if (ret != 0) {
            res = WOLFSSL_FAILURE;
        }
    }
#endif
#else
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    wolfssl_priv_der_unblind(ctx->privateKey, ctx->privateKeyMask);
#endif
    res = check_cert_key(ctx->certificate, ctx->privateKey, NULL, ctx->heap,
            ctx->privateKeyDevId, ctx->privateKeyLabel, ctx->privateKeyId,
            INVALID_DEVID, 0, 0);
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    {
        int ret = wolfssl_priv_der_blind(NULL, ctx->privateKey,
            (DerBuffer**)&ctx->privateKeyMask);
        if (ret != 0) {
            res = WOLFSSL_FAILURE;
        }
    }
#endif
#endif

    return res;
}
#endif /* !NO_CHECK_PRIVATE_KEY */

#ifdef OPENSSL_ALL
/**
 * Return the private key of the WOLFSSL_CTX struct
 * @return WOLFSSL_EVP_PKEY* The caller doesn *NOT*` free the returned object.
 */
WOLFSSL_EVP_PKEY* wolfSSL_CTX_get0_privatekey(const WOLFSSL_CTX* ctx)
{
    WOLFSSL_EVP_PKEY* res;
    const unsigned char *key;
    int type;

    WOLFSSL_ENTER("wolfSSL_CTX_get0_privatekey");

    if (ctx == NULL || ctx->privateKey == NULL ||
            ctx->privateKey->buffer == NULL) {
        WOLFSSL_MSG("Bad parameter or key not set");
        return NULL;
    }

    switch (ctx->privateKeyType) {
#ifndef NO_RSA
        case rsa_sa_algo:
            type = WC_EVP_PKEY_RSA;
            break;
#endif
#ifdef HAVE_ECC
        case ecc_dsa_sa_algo:
            type = WC_EVP_PKEY_EC;
            break;
#endif
#ifdef WOLFSSL_SM2
        case sm2_sa_algo:
            type = WC_EVP_PKEY_EC;
            break;
#endif
        default:
            /* Other key types not supported either as ssl private keys
             * or in the EVP layer */
            WOLFSSL_MSG("Unsupported key type");
            return NULL;
    }

    key = ctx->privateKey->buffer;

    if (ctx->privateKeyPKey != NULL) {
        res = ctx->privateKeyPKey;
    }
    else {
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        wolfssl_priv_der_unblind(ctx->privateKey, ctx->privateKeyMask);
    #endif
        res = wolfSSL_d2i_PrivateKey(type,
                (WOLFSSL_EVP_PKEY**)&ctx->privateKeyPKey, &key,
                (long)ctx->privateKey->length);
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        wolfssl_priv_der_unblind(ctx->privateKey, ctx->privateKeyMask);
    #endif
    }

    return res;
}
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

#if !defined(NO_RSA)
static int d2iTryRsaKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    word32 keyIdx = 0;
    int isRsaKey;
    int ret = 1;
#ifndef WOLFSSL_SMALL_STACK
    RsaKey rsa[1];
#else
    RsaKey *rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA);
    if (rsa == NULL)
        return 0;
#endif

    XMEMSET(rsa, 0, sizeof(RsaKey));

    if (wc_InitRsaKey(rsa, NULL) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(rsa, NULL, DYNAMIC_TYPE_RSA);
    #endif
        return 0;
    }
    /* test if RSA key */
    if (priv) {
        isRsaKey =
            (wc_RsaPrivateKeyDecode(mem, &keyIdx, rsa, (word32)memSz) == 0);
    }
    else {
        isRsaKey =
            (wc_RsaPublicKeyDecode(mem, &keyIdx, rsa, (word32)memSz) == 0);
    }
    wc_FreeRsaKey(rsa);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(rsa, NULL, DYNAMIC_TYPE_RSA);
#endif

    if (!isRsaKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("RSA wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    pkey->pkey_sz = (int)keyIdx;
    pkey->pkey.ptr = (char*)XMALLOC(memSz, NULL,
            priv ? DYNAMIC_TYPE_PRIVATE_KEY :
                   DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        XMEMCPY(pkey->pkey.ptr, mem, keyIdx);
        pkey->type = WC_EVP_PKEY_RSA;

        pkey->ownRsa = 1;
        pkey->rsa = wolfssl_rsa_d2i(NULL, mem, memSz,
            priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC);
        if (pkey->rsa == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        *out = pkey;
    }

    if ((ret == 0) && (*out == NULL)) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    return ret;
}
#endif /* !NO_RSA */

#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA)
static int d2iTryEccKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    word32  keyIdx = 0;
    int     isEccKey;
    int     ret = 1;
#ifndef WOLFSSL_SMALL_STACK
    ecc_key ecc[1];
#else
    ecc_key *ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
        DYNAMIC_TYPE_ECC);
    if (ecc == NULL)
        return 0;
#endif

    XMEMSET(ecc, 0, sizeof(ecc_key));

    if (wc_ecc_init(ecc) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(ecc, NULL, DYNAMIC_TYPE_ECC);
    #endif
        return 0;
    }

    if (priv) {
        isEccKey =
            (wc_EccPrivateKeyDecode(mem, &keyIdx, ecc, (word32)memSz) == 0);
    }
    else {
        isEccKey =
            (wc_EccPublicKeyDecode(mem, &keyIdx, ecc, (word32)memSz) == 0);
    }
    wc_ecc_free(ecc);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(ecc, NULL, DYNAMIC_TYPE_ECC);
#endif

    if (!isEccKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("ECC wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    pkey->pkey_sz = (int)keyIdx;
    pkey->pkey.ptr = (char*)XMALLOC(keyIdx, NULL,
            priv ? DYNAMIC_TYPE_PRIVATE_KEY :
                   DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        XMEMCPY(pkey->pkey.ptr, mem, keyIdx);
        pkey->type = WC_EVP_PKEY_EC;

        pkey->ownEcc = 1;
        pkey->ecc = wolfSSL_EC_KEY_new();
        if (pkey->ecc == NULL) {
            ret = 0;
        }
    }
    if ((ret == 1) && (wolfSSL_EC_KEY_LoadDer_ex(pkey->ecc,
            (const unsigned char*)pkey->pkey.ptr,
            pkey->pkey_sz, priv ? WOLFSSL_RSA_LOAD_PRIVATE
                                : WOLFSSL_RSA_LOAD_PUBLIC) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
        *out = pkey;
    }

    if ((ret == 0) && (*out == NULL)) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    return ret;
}
#endif /* HAVE_ECC && OPENSSL_EXTRA */

#if !defined(NO_DSA)
static int d2iTryDsaKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    word32 keyIdx = 0;
    int     isDsaKey;
    int     ret = 1;
#ifndef WOLFSSL_SMALL_STACK
    DsaKey dsa[1];
#else
    DsaKey *dsa = (DsaKey*)XMALLOC(sizeof(DsaKey), NULL, DYNAMIC_TYPE_DSA);
    if (dsa == NULL)
        return 0;
#endif

    XMEMSET(dsa, 0, sizeof(DsaKey));

    if (wc_InitDsaKey(dsa) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(dsa, NULL, DYNAMIC_TYPE_DSA);
    #endif
        return 0;
    }

    if (priv) {
        isDsaKey =
            (wc_DsaPrivateKeyDecode(mem, &keyIdx, dsa, (word32)memSz) == 0);
    }
    else {
        isDsaKey =
            (wc_DsaPublicKeyDecode(mem, &keyIdx, dsa, (word32)memSz) == 0);
    }
    wc_FreeDsaKey(dsa);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(dsa, NULL, DYNAMIC_TYPE_DSA);
#endif

    /* test if DSA key */
    if (!isDsaKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("DSA wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    pkey->pkey_sz = (int)keyIdx;
    pkey->pkey.ptr = (char*)XMALLOC(memSz, NULL,
            priv ? DYNAMIC_TYPE_PRIVATE_KEY :
                   DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        XMEMCPY(pkey->pkey.ptr, mem, keyIdx);
        pkey->type = WC_EVP_PKEY_DSA;

        pkey->ownDsa = 1;
        pkey->dsa = wolfSSL_DSA_new();
        if (pkey->dsa == NULL) {
            ret = 0;
        }
    }

    if ((ret == 1) && (wolfSSL_DSA_LoadDer_ex(pkey->dsa,
            (const unsigned char*)pkey->pkey.ptr,
            pkey->pkey_sz, priv ? WOLFSSL_RSA_LOAD_PRIVATE
                                : WOLFSSL_RSA_LOAD_PUBLIC) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
        *out = pkey;
    }

    if ((ret == 0) && (*out == NULL)) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    return ret;
}
#endif /* NO_DSA */

#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
static int d2iTryDhKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    int isDhKey;
    word32 keyIdx = 0;
    int ret = 1;
#ifndef WOLFSSL_SMALL_STACK
    DhKey dh[1];
#else
    DhKey *dh = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (dh == NULL)
        return 0;
#endif

    XMEMSET(dh, 0, sizeof(DhKey));

    if (wc_InitDhKey(dh) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
    #endif
        return 0;
    }

    isDhKey = (wc_DhKeyDecode(mem, &keyIdx, dh, (word32)memSz) == 0);
    wc_FreeDhKey(dh);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(dh, NULL, DYNAMIC_TYPE_DH);
#endif

    /* test if DH key */
    if (!isDhKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("DH wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    pkey->pkey_sz = (int)memSz;
    pkey->pkey.ptr = (char*)XMALLOC(memSz, NULL,
            priv ? DYNAMIC_TYPE_PRIVATE_KEY :
                   DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        XMEMCPY(pkey->pkey.ptr, mem, memSz);
        pkey->type = WC_EVP_PKEY_DH;

        pkey->ownDh = 1;
        pkey->dh = wolfSSL_DH_new();
        if (pkey->dh == NULL) {
            ret = 0;
        }
    }

    if ((ret == 1) && (wolfSSL_DH_LoadDer(pkey->dh,
                (const unsigned char*)pkey->pkey.ptr,
                pkey->pkey_sz) != WOLFSSL_SUCCESS)) {
        ret = 0;
    }
    if (ret == 1) {
        *out = pkey;
    }

    if ((ret == 0) && (*out == NULL)) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    return ret;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */

#if !defined(NO_DH) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_DH_EXTRA)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION > 2))
static int d2iTryAltDhKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    word32  keyIdx = 0;
    DhKey*  key = NULL;
    int elements;
    int ret;
#ifndef WOLFSSL_SMALL_STACK
    DhKey  dh[1];
#else
    DhKey* dh = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (dh == NULL)
        return 0;
#endif
    XMEMSET(dh, 0, sizeof(DhKey));

    /* test if DH-public key */
    if (wc_InitDhKey(dh) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
#endif
        return 0;
    }

    ret = wc_DhKeyDecode(mem, &keyIdx, dh, (word32)memSz);
    wc_FreeDhKey(dh);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(dh, NULL, DYNAMIC_TYPE_DH);
#endif

    if (ret != 0) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            return 0;
        }
    }

    ret = 1;
    pkey->type     = WC_EVP_PKEY_DH;
    pkey->pkey_sz  = (int)memSz;
    pkey->pkey.ptr = (char*)XMALLOC(memSz, NULL,
            priv ? DYNAMIC_TYPE_PRIVATE_KEY :
                   DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        XMEMCPY(pkey->pkey.ptr, mem, memSz);
        pkey->ownDh = 1;
        pkey->dh = wolfSSL_DH_new();
        if (pkey->dh == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        key = (DhKey*)pkey->dh->internal;

        keyIdx = 0;
        if (wc_DhKeyDecode(mem, &keyIdx, key, (word32)memSz) != 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        elements = ELEMENT_P | ELEMENT_G | ELEMENT_Q | ELEMENT_PUB;
        if (priv) {
            elements |= ELEMENT_PRV;
        }
        if (SetDhExternal_ex(pkey->dh, elements) != WOLFSSL_SUCCESS ) {
            ret = 0;
        }
    }
    if (ret == 1) {
        *out = pkey;
    }

    if ((ret == 0) && (*out == NULL)) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    return ret;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH &&  OPENSSL_EXTRA && WOLFSSL_DH_EXTRA */

#ifdef HAVE_FALCON
static int d2iTryFalconKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    int isFalcon = 0;
#ifndef WOLFSSL_SMALL_STACK
    falcon_key falcon[1];
#else
    falcon_key *falcon = (falcon_key *)XMALLOC(sizeof(falcon_key), NULL,
                                              DYNAMIC_TYPE_FALCON);
    if (falcon == NULL) {
        return 0;
    }
#endif

    if (wc_falcon_init(falcon) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(falcon, NULL, DYNAMIC_TYPE_FALCON);
    #endif
        return 0;
    }

    /* test if Falcon key */
    if (priv) {
        /* Try level 1 */
        isFalcon = ((wc_falcon_set_level(falcon, 1) == 0) &&
                    (wc_falcon_import_private_only(mem, (word32)memSz,
                                                   falcon) == 0));
        if (!isFalcon) {
            /* Try level 5 */
            isFalcon = ((wc_falcon_set_level(falcon, 5) == 0) &&
                        (wc_falcon_import_private_only(mem, (word32)memSz,
                                                       falcon) == 0));
        }
    }
    else {
        /* Try level 1 */
        isFalcon = ((wc_falcon_set_level(falcon, 1) == 0) &&
                    (wc_falcon_import_public(mem, (word32)memSz, falcon) == 0));

        if (!isFalcon) {
            /* Try level 5 */
            isFalcon = ((wc_falcon_set_level(falcon, 5) == 0) &&
                        (wc_falcon_import_public(mem, (word32)memSz,
                                                 falcon) == 0));
        }
    }
    wc_falcon_free(falcon);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(falcon, NULL, DYNAMIC_TYPE_FALCON);
#endif

    if (!isFalcon) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        /* Create a fake Falcon EVP_PKEY. In the future, we might integrate
         * Falcon into the compatibility layer. */
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("Falcon wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }
    pkey->type = WC_EVP_PKEY_FALCON;
    pkey->pkey.ptr = NULL;
    pkey->pkey_sz = 0;

    *out = pkey;
    return 1;

}
#endif /* HAVE_FALCON */

#ifdef HAVE_DILITHIUM
static int d2iTryDilithiumKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey;
    int isDilithium = 0;
#ifndef WOLFSSL_SMALL_STACK
    dilithium_key dilithium[1];
#else
    dilithium_key *dilithium = (dilithium_key *)
        XMALLOC(sizeof(dilithium_key), NULL, DYNAMIC_TYPE_DILITHIUM);
    if (dilithium == NULL) {
        return 0;
    }
#endif

    if (wc_dilithium_init(dilithium) != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(dilithium, NULL, DYNAMIC_TYPE_DILITHIUM);
    #endif
        return 0;
    }

    /* Test if Dilithium key. Try all levels. */
    if (priv) {
        isDilithium = ((wc_dilithium_set_level(dilithium, 2) == 0) &&
                       (wc_dilithium_import_private(mem,
                          (word32)memSz, dilithium) == 0));
        if (!isDilithium) {
            isDilithium = ((wc_dilithium_set_level(dilithium, 3) == 0) &&
                           (wc_dilithium_import_private(mem,
                              (word32)memSz, dilithium) == 0));
        }
        if (!isDilithium) {
            isDilithium = ((wc_dilithium_set_level(dilithium, 5) == 0) &&
                           (wc_dilithium_import_private(mem,
                              (word32)memSz, dilithium) == 0));
        }
    }
    else {
        isDilithium = ((wc_dilithium_set_level(dilithium, 2) == 0) &&
                       (wc_dilithium_import_public(mem, (word32)memSz,
                          dilithium) == 0));
        if (!isDilithium) {
            isDilithium = ((wc_dilithium_set_level(dilithium, 3) == 0) &&
                           (wc_dilithium_import_public(mem, (word32)memSz,
                              dilithium) == 0));
        }
        if (!isDilithium) {
            isDilithium = ((wc_dilithium_set_level(dilithium, 5) == 0) &&
                           (wc_dilithium_import_public(mem, (word32)memSz,
                              dilithium) == 0));
        }
    }
    wc_dilithium_free(dilithium);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(dilithium, NULL, DYNAMIC_TYPE_DILITHIUM);
#endif

    if (!isDilithium) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out != NULL) {
        pkey = *out;
    }
    else {
        /* Create a fake Dilithium EVP_PKEY. In the future, we might
         * integrate Dilithium into the compatibility layer. */
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("Dilithium wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }
    pkey->type = WC_EVP_PKEY_DILITHIUM;
    pkey->pkey.ptr = NULL;
    pkey->pkey_sz = 0;

    *out = pkey;
    return 1;
}
#endif /* HAVE_DILITHIUM */

static WOLFSSL_EVP_PKEY* d2iGenericKey(WOLFSSL_EVP_PKEY** out,
    const unsigned char** in, long inSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey = NULL;

    WOLFSSL_ENTER("d2iGenericKey");

    if (in == NULL || *in == NULL || inSz < 0) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if ((out != NULL) && (*out != NULL)) {
        pkey = *out;
    }

#if !defined(NO_RSA)
    if (d2iTryRsaKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* NO_RSA */
#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA)
    if (d2iTryEccKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_ECC && OPENSSL_EXTRA */
#if !defined(NO_DSA)
    if (d2iTryDsaKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* NO_DSA */
#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
    if (d2iTryDhKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */

#if !defined(NO_DH) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_DH_EXTRA)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION > 2))
    if (d2iTryAltDhKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH &&  OPENSSL_EXTRA && WOLFSSL_DH_EXTRA */

#ifdef HAVE_FALCON
    if (d2iTryFalconKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    if (d2iTryDilithiumKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_DILITHIUM */
    {
        WOLFSSL_MSG("wolfSSL_d2i_PUBKEY couldn't determine key type");
    }

    if ((pkey != NULL) && (out != NULL)) {
        *out = pkey;
    }
    return pkey;
}
#endif /* OPENSSL_EXTRA || WPA_SMALL */

#ifdef OPENSSL_EXTRA

WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY(
    WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey, const unsigned char** keyBuf,
    long keyLen)
{
    WOLFSSL_PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
#ifdef WOLFSSL_PEM_TO_DER
    int ret;
    DerBuffer* pkcs8Der = NULL;
    DerBuffer rawDer;
    EncryptedInfo info;
    int advanceLen = 0;

    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&rawDer, 0, sizeof(rawDer));

    if (keyBuf == NULL || *keyBuf == NULL || keyLen <= 0) {
        WOLFSSL_MSG("Bad key PEM/DER args");
        return NULL;
    }

    ret = PemToDer(*keyBuf, keyLen, PRIVATEKEY_TYPE, &pkcs8Der, NULL, &info,
                   NULL);
    if (ret < 0) {
        WOLFSSL_MSG("Not PEM format");
        ret = AllocDer(&pkcs8Der, (word32)keyLen, PRIVATEKEY_TYPE, NULL);
        if (ret == 0) {
            XMEMCPY(pkcs8Der->buffer, *keyBuf, keyLen);
        }
    }
    else {
        advanceLen = (int)info.consumed;
    }

    if (ret == 0) {
        /* Verify this is PKCS8 Key */
        word32 inOutIdx = 0;
        word32 algId;
        ret = ToTraditionalInline_ex(pkcs8Der->buffer, &inOutIdx,
                pkcs8Der->length, &algId);
        if (ret >= 0) {
            if (advanceLen == 0) /* Set only if not PEM */
                advanceLen = inOutIdx + ret;
            if (algId == DHk) {
                /* Special case for DH as we expect the DER buffer to be always
                 * be in PKCS8 format */
                rawDer.buffer = pkcs8Der->buffer;
                rawDer.length = inOutIdx + ret;
            }
            else {
                rawDer.buffer = pkcs8Der->buffer + inOutIdx;
                rawDer.length = ret;
            }
            ret = 0; /* good DER */
        }
    }

    if (ret == 0) {
        pkcs8 = wolfSSL_EVP_PKEY_new();
        if (pkcs8 == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        pkcs8->pkey.ptr = (char*)XMALLOC(rawDer.length, NULL,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (pkcs8->pkey.ptr == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        XMEMCPY(pkcs8->pkey.ptr, rawDer.buffer, rawDer.length);
        pkcs8->pkey_sz = (int)rawDer.length;
    }

    FreeDer(&pkcs8Der);
    if (ret != 0) {
        wolfSSL_EVP_PKEY_free(pkcs8);
        pkcs8 = NULL;
    }
    else {
        *keyBuf += advanceLen;
    }
    if (pkey != NULL) {
        *pkey = pkcs8;
    }

#else
    (void)bio;
    (void)pkey;
#endif /* WOLFSSL_PEM_TO_DER */

    return pkcs8;
}

#ifdef OPENSSL_ALL
int wolfSSL_i2d_PKCS8_PKEY(WOLFSSL_PKCS8_PRIV_KEY_INFO* key, unsigned char** pp)
{
    word32 keySz = 0;
    unsigned char* out;
    int len;

    WOLFSSL_ENTER("wolfSSL_i2d_PKCS8_PKEY");

    if (key == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (pkcs8_encode(key, NULL, &keySz) != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
        return WOLFSSL_FATAL_ERROR;
    len = (int)keySz;

    if (pp == NULL)
        return len;

    if (*pp == NULL) {
        out = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_ASN1);
        if (out == NULL)
            return WOLFSSL_FATAL_ERROR;
    }
    else {
        out = *pp;
    }

    if (pkcs8_encode(key, out, &keySz) != len) {
        if (*pp == NULL)
            XFREE(out, NULL, DYNAMIC_TYPE_ASN1);
        return WOLFSSL_FATAL_ERROR;
    }

    if (*pp == NULL)
        *pp = out;
    else
        *pp += len;

    return len;
}
#endif

#ifndef NO_BIO
/* put SSL type in extra for now, not very common */

/* Converts a DER format key read from "bio" to a PKCS8 structure.
 *
 * bio  input bio to read DER from
 * pkey If not NULL then this pointer will be overwritten with a new PKCS8
 *      structure.
 *
 * returns a WOLFSSL_PKCS8_PRIV_KEY_INFO pointer on success and NULL in fail
 *         case.
 */
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY_bio(WOLFSSL_BIO* bio,
        WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey)
{
    WOLFSSL_PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
#ifdef WOLFSSL_PEM_TO_DER
    unsigned char* mem = NULL;
    int memSz;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS8_PKEY_bio");

    if (bio == NULL) {
        return NULL;
    }

    if ((memSz = wolfSSL_BIO_get_mem_data(bio, &mem)) < 0) {
        return NULL;
    }

    pkcs8 = wolfSSL_d2i_PKCS8_PKEY(pkey, (const unsigned char**)&mem, memSz);
#else
    (void)bio;
    (void)pkey;
#endif /* WOLFSSL_PEM_TO_DER */

    return pkcs8;
}


/* expecting DER format public key
 *
 * bio  input bio to read DER from
 * out  If not NULL then this pointer will be overwritten with a new
 * WOLFSSL_EVP_PKEY pointer
 *
 * returns a WOLFSSL_EVP_PKEY pointer on success and NULL in fail case.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY_bio(WOLFSSL_BIO* bio,
                                         WOLFSSL_EVP_PKEY** out)
{
    unsigned char* mem;
    long memSz;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PUBKEY_bio");

    if (bio == NULL) {
        return NULL;
    }
    (void)out;

    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        return NULL;
    }

    mem = (unsigned char*)XMALLOC(memSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        return NULL;
    }

    if (wolfSSL_BIO_read(bio, mem, (int)memSz) == memSz) {
        pkey = wolfSSL_d2i_PUBKEY(NULL, (const unsigned char**)&mem, memSz);
        if (out != NULL && pkey != NULL) {
            *out = pkey;
        }
    }

    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return pkey;
}

#endif /* !NO_BIO */


/* Converts a DER encoded public key to a WOLFSSL_EVP_PKEY structure.
 *
 * out  pointer to new WOLFSSL_EVP_PKEY structure. Can be NULL
 * in   DER buffer to convert
 * inSz size of in buffer
 *
 * returns a pointer to a new WOLFSSL_EVP_PKEY structure on success and NULL
 *         on fail
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY(WOLFSSL_EVP_PKEY** out,
                                     const unsigned char** in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PUBKEY");
    return d2iGenericKey(out, in, inSz, 0);
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_ASN) && \
    !defined(NO_PWDBASED)

/* helper function to get raw pointer to DER buffer from WOLFSSL_EVP_PKEY */
static int wolfSSL_EVP_PKEY_get_der(const WOLFSSL_EVP_PKEY* key,
    unsigned char** der)
{
    int sz;
    word16 pkcs8HeaderSz;

    if (!key || !key->pkey_sz)
        return WOLFSSL_FATAL_ERROR;

    /* return the key without PKCS8 for compatibility */
    /* if pkcs8HeaderSz is invalid, use 0 and return all of pkey */
    pkcs8HeaderSz = 0;
    if (key->pkey_sz > key->pkcs8HeaderSz)
        pkcs8HeaderSz = key->pkcs8HeaderSz;
    sz = key->pkey_sz - pkcs8HeaderSz;
    if (der) {
        unsigned char* pt = (unsigned char*)key->pkey.ptr;
        if (*der) {
            /* since this function signature has no size value passed in it is
             * assumed that the user has allocated a large enough buffer */
            XMEMCPY(*der, pt + pkcs8HeaderSz, sz);
            *der += sz;
        }
        else {
            *der = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_OPENSSL);
            if (*der == NULL) {
                return WOLFSSL_FATAL_ERROR;
            }
            XMEMCPY(*der, pt + pkcs8HeaderSz, sz);
        }
    }
    return sz;
}

int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY *key, unsigned char **der)
{
    return wolfSSL_i2d_PublicKey(key, der);
}

#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_ASN && !NO_PWDBASED */

static WOLFSSL_EVP_PKEY* _d2i_PublicKey(int type, WOLFSSL_EVP_PKEY** out,
    const unsigned char **in, long inSz, int priv)
{
    int ret = 0;
    word32 idx = 0, algId;
    word16 pkcs8HeaderSz = 0;
    WOLFSSL_EVP_PKEY* local;
    int opt = 0;

    (void)opt;

    if (in == NULL || inSz < 0) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if (priv == 1) {
        /* Check if input buffer has PKCS8 header. In the case that it does not
         * have a PKCS8 header then do not error out. */
        if ((ret = ToTraditionalInline_ex((const byte*)(*in), &idx,
                                          (word32)inSz, &algId)) > 0) {
            WOLFSSL_MSG("Found PKCS8 header");
            pkcs8HeaderSz = (word16)idx;

            if ((type == WC_EVP_PKEY_RSA && algId != RSAk
            #ifdef WC_RSA_PSS
                 && algId != RSAPSSk
            #endif
                 ) ||
                (type == WC_EVP_PKEY_EC && algId != ECDSAk) ||
                (type == WC_EVP_PKEY_DSA && algId != DSAk) ||
                (type == WC_EVP_PKEY_DH && algId != DHk)) {
                WOLFSSL_MSG("PKCS8 does not match EVP key type");
                return NULL;
            }

            (void)idx; /* not used */
        }
        else {
            if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
                WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 "
                    "header");
                return NULL;
            }
        }
    }

    if (out != NULL && *out != NULL) {
        wolfSSL_EVP_PKEY_free(*out);
        *out = NULL;
    }
    local = wolfSSL_EVP_PKEY_new();
    if (local == NULL) {
        return NULL;
    }

    local->type     = type;
    local->pkey_sz  = (int)inSz;
    local->pkcs8HeaderSz = pkcs8HeaderSz;
    local->pkey.ptr = (char*)XMALLOC(inSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (local->pkey.ptr == NULL) {
        wolfSSL_EVP_PKEY_free(local);
        local = NULL;
        return NULL;
    }
    else {
        XMEMCPY(local->pkey.ptr, *in, inSz);
    }

    switch (type) {
#ifndef NO_RSA
        case WC_EVP_PKEY_RSA:
            opt = priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC;
            local->ownRsa = 1;
            local->rsa = wolfssl_rsa_d2i(NULL,
                (const unsigned char*)local->pkey.ptr, local->pkey_sz, opt);
            if (local->rsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* NO_RSA */
#ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
            local->ownEcc = 1;
            local->ecc = wolfSSL_EC_KEY_new();
            if (local->ecc == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            opt = priv ? WOLFSSL_EC_KEY_LOAD_PRIVATE :
                         WOLFSSL_EC_KEY_LOAD_PUBLIC;
            if (wolfSSL_EC_KEY_LoadDer_ex(local->ecc,
                      (const unsigned char*)local->pkey.ptr, local->pkey_sz,
                      opt)
                      != WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_ECC */
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH)
#ifndef NO_DSA
        case WC_EVP_PKEY_DSA:
            local->ownDsa = 1;
            local->dsa = wolfSSL_DSA_new();
            if (local->dsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            opt = priv ? WOLFSSL_DSA_LOAD_PRIVATE : WOLFSSL_DSA_LOAD_PUBLIC;
            if (wolfSSL_DSA_LoadDer_ex(local->dsa,
                    (const unsigned char*)local->pkey.ptr, local->pkey_sz,
                    opt)
                    != WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* NO_DSA */
#ifndef NO_DH
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        case WC_EVP_PKEY_DH:
            local->ownDh = 1;
            local->dh = wolfSSL_DH_new();
            if (local->dh == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            if (wolfSSL_DH_LoadDer(local->dh,
                      (const unsigned char*)local->pkey.ptr, local->pkey_sz)
                      != WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* HAVE_DH */
#endif /* WOLFSSL_QT || OPENSSL_ALL || WOLFSSL_OPENSSH */
        default:
            WOLFSSL_MSG("Unsupported key type");
            wolfSSL_EVP_PKEY_free(local);
            return NULL;
    }

    /* advance pointer with success */
    if (local != NULL) {
        if (local->pkey_sz <= (int)inSz) {
            *in += local->pkey_sz;
        }

        if (out != NULL) {
            *out = local;
        }
    }

    return local;
}

WOLFSSL_EVP_PKEY* wolfSSL_d2i_PublicKey(int type, WOLFSSL_EVP_PKEY** out,
        const unsigned char **in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PublicKey");

    return _d2i_PublicKey(type, out, in, inSz, 0);
}
/* Reads in a DER format key. If PKCS8 headers are found they are stripped off.
 *
 * type  type of key
 * out   newly created WOLFSSL_EVP_PKEY structure
 * in    pointer to input key DER
 * inSz  size of in buffer
 *
 * On success a non null pointer is returned and the pointer in is advanced the
 * same number of bytes read.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type, WOLFSSL_EVP_PKEY** out,
        const unsigned char **in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey");

    return _d2i_PublicKey(type, out, in, inSz, 1);
}

#ifdef WOLF_PRIVATE_KEY_ID
/* Create an EVP structure for use with crypto callbacks */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_id(int type, WOLFSSL_EVP_PKEY** out,
    void* heap, int devId)
{
    WOLFSSL_EVP_PKEY* local;

    if (out != NULL && *out != NULL) {
        wolfSSL_EVP_PKEY_free(*out);
        *out = NULL;
    }

    local = wolfSSL_EVP_PKEY_new_ex(heap);
    if (local == NULL) {
        return NULL;
    }

    local->type     = type;
    local->pkey_sz  = 0;
    local->pkcs8HeaderSz = 0;

    switch (type) {
#ifndef NO_RSA
        case WC_EVP_PKEY_RSA:
        {
            RsaKey* key;
            local->ownRsa = 1;
            local->rsa = wolfSSL_RSA_new_ex(heap, devId);
            if (local->rsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            key = (RsaKey*)local->rsa->internal;
        #ifdef WOLF_CRYPTO_CB
            key->devId = devId;
        #endif
            (void)key;
            local->rsa->inSet = 1;
            break;
        }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
        {
            ecc_key* key;
            local->ownEcc = 1;
            local->ecc = wolfSSL_EC_KEY_new_ex(heap, devId);
            if (local->ecc == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            key = (ecc_key*)local->ecc->internal;
        #ifdef WOLF_CRYPTO_CB
            key->devId = devId;
        #endif
            key->type = ECC_PRIVATEKEY;
            /* key is required to have a key size / curve set, although
             * actual one used is determined by devId callback function */
            wc_ecc_set_curve(key, ECDHE_SIZE, ECC_CURVE_DEF);

            local->ecc->inSet = 1;
            break;
        }
#endif /* HAVE_ECC */
        default:
            WOLFSSL_MSG("Unsupported private key id type");
            wolfSSL_EVP_PKEY_free(local);
            return NULL;
    }

    if (local != NULL && out != NULL) {
        *out = local;
    }

    return local;
}
#endif /* WOLF_PRIVATE_KEY_ID */

#ifndef NO_CERTS /* // NOLINT(readability-redundant-preprocessor) */

#ifndef NO_CHECK_PRIVATE_KEY
/* Check private against public in certificate for match
 *
 * ssl  WOLFSSL structure to check private key in
 *
 * Returns WOLFSSL_SUCCESS on good private key
 *         WOLFSSL_FAILURE if mismatched. */
int wolfSSL_check_private_key(const WOLFSSL* ssl)
{
    int res = WOLFSSL_SUCCESS;

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }
#ifdef WOLFSSL_DUAL_ALG_CERTS
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    wolfssl_priv_der_unblind(ssl->buffers.key, ssl->buffers.keyMask);
    wolfssl_priv_der_unblind(ssl->buffers.altKey, ssl->buffers.altKeyMask);
#endif
    res = check_cert_key(ssl->buffers.certificate, ssl->buffers.key,
        ssl->buffers.altKey, ssl->heap, ssl->buffers.keyDevId,
        ssl->buffers.keyLabel, ssl->buffers.keyId, ssl->buffers.altKeyDevId,
        ssl->buffers.altKeyLabel, ssl->buffers.altKeyId);
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    if (res == WOLFSSL_SUCCESS) {
        int ret;
        ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.key,
            (DerBuffer**)&ssl->buffers.keyMask);
        if (ret == 0) {
            ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.altKey,
                (DerBuffer**)&ssl->buffers.altKeyMask);
        }
        if (ret != 0) {
            res = WOLFSSL_FAILURE;
        }
    }
#endif
#else
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    wolfssl_priv_der_unblind(ssl->buffers.key, ssl->buffers.keyMask);
#endif
    res = check_cert_key(ssl->buffers.certificate, ssl->buffers.key, NULL,
        ssl->heap, ssl->buffers.keyDevId, ssl->buffers.keyLabel,
        ssl->buffers.keyId, INVALID_DEVID, 0, 0);
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    if (res == WOLFSSL_SUCCESS) {
        int ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.key,
            (DerBuffer**)&ssl->buffers.keyMask);
        if (ret != 0) {
            res = WOLFSSL_FAILURE;
        }
    }
#endif
#endif

    return res;
}
#endif /* !NO_CHECK_PRIVATE_KEY */

#endif /* !NO_CERTS */

#endif /* OPENSSL_EXTRA */

#if defined(HAVE_RPK)
/* Confirm that all the byte data in the buffer is unique.
 * return 1 if all the byte data in the buffer is unique, otherwise 0.
 */
static int isArrayUnique(const char* buf, size_t len)
{
    size_t i, j;
    /* check the array is unique */
    for (i = 0; i < len -1; ++i) {
        for (j = i+ 1; j < len; ++j) {
            if (buf[i] == buf[j]) {
                return 0;
            }
        }
    }
    return 1;
}

/* Set user preference for the client_cert_type exetnsion.
 * Takes byte array containing cert types the caller can provide to its peer.
 * Cert types are in preferred order in the array.
 */
WOLFSSL_API int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx,
                                          const char* buf, int bufLen)
{
    int i;

    if (ctx == NULL || bufLen > MAX_CLIENT_CERT_TYPE_CNT) {
        return BAD_FUNC_ARG;
    }

    /* if buf is set to NULL or bufLen is set to zero, it defaults the setting*/
    if (buf == NULL || bufLen == 0) {
        ctx->rpkConfig.preferred_ClientCertTypeCnt = 1;
        ctx->rpkConfig.preferred_ClientCertTypes[0]= WOLFSSL_CERT_TYPE_X509;
        ctx->rpkConfig.preferred_ClientCertTypes[1]= WOLFSSL_CERT_TYPE_X509;
        return WOLFSSL_SUCCESS;
    }

    if (!isArrayUnique(buf, (size_t)bufLen))
        return BAD_FUNC_ARG;

    for (i = 0; i < bufLen; i++){
        if (buf[i] != WOLFSSL_CERT_TYPE_RPK && buf[i] != WOLFSSL_CERT_TYPE_X509)
            return BAD_FUNC_ARG;

        ctx->rpkConfig.preferred_ClientCertTypes[i] = (byte)buf[i];
    }
    ctx->rpkConfig.preferred_ClientCertTypeCnt = bufLen;

    return WOLFSSL_SUCCESS;
}

/* Set user preference for the server_cert_type exetnsion.
 * Takes byte array containing cert types the caller can provide to its peer.
 * Cert types are in preferred order in the array.
 */
WOLFSSL_API int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx,
                                                const char* buf, int bufLen)
{
    int i;

    if (ctx == NULL || bufLen > MAX_SERVER_CERT_TYPE_CNT) {
        return BAD_FUNC_ARG;
    }

    /* if buf is set to NULL or bufLen is set to zero, it defaults the setting*/
    if (buf == NULL || bufLen == 0) {
        ctx->rpkConfig.preferred_ServerCertTypeCnt = 1;
        ctx->rpkConfig.preferred_ServerCertTypes[0]= WOLFSSL_CERT_TYPE_X509;
        ctx->rpkConfig.preferred_ServerCertTypes[1]= WOLFSSL_CERT_TYPE_X509;
        return WOLFSSL_SUCCESS;
    }

    if (!isArrayUnique(buf, (size_t)bufLen))
        return BAD_FUNC_ARG;

    for (i = 0; i < bufLen; i++){
        if (buf[i] != WOLFSSL_CERT_TYPE_RPK && buf[i] != WOLFSSL_CERT_TYPE_X509)
            return BAD_FUNC_ARG;

        ctx->rpkConfig.preferred_ServerCertTypes[i] = (byte)buf[i];
    }
    ctx->rpkConfig.preferred_ServerCertTypeCnt = bufLen;

    return WOLFSSL_SUCCESS;
}

/* Set user preference for the client_cert_type exetnsion.
 * Takes byte array containing cert types the caller can provide to its peer.
 * Cert types are in preferred order in the array.
 */
WOLFSSL_API int wolfSSL_set_client_cert_type(WOLFSSL* ssl,
                                          const char* buf, int bufLen)
{
    int i;

    if (ssl == NULL || bufLen > MAX_CLIENT_CERT_TYPE_CNT) {
        return BAD_FUNC_ARG;
    }

    /* if buf is set to NULL or bufLen is set to zero, it defaults the setting*/
    if (buf == NULL || bufLen == 0) {
        ssl->options.rpkConfig.preferred_ClientCertTypeCnt = 1;
        ssl->options.rpkConfig.preferred_ClientCertTypes[0]
                                                    = WOLFSSL_CERT_TYPE_X509;
        ssl->options.rpkConfig.preferred_ClientCertTypes[1]
                                                    = WOLFSSL_CERT_TYPE_X509;
        return WOLFSSL_SUCCESS;
    }

    if (!isArrayUnique(buf, (size_t)bufLen))
        return BAD_FUNC_ARG;

    for (i = 0; i < bufLen; i++){
        if (buf[i] != WOLFSSL_CERT_TYPE_RPK && buf[i] != WOLFSSL_CERT_TYPE_X509)
            return BAD_FUNC_ARG;

        ssl->options.rpkConfig.preferred_ClientCertTypes[i] = (byte)buf[i];
    }
    ssl->options.rpkConfig.preferred_ClientCertTypeCnt = bufLen;

    return WOLFSSL_SUCCESS;
}

/* Set user preference for the server_cert_type exetnsion.
 * Takes byte array containing cert types the caller can provide to its peer.
 * Cert types are in preferred order in the array.
 */
WOLFSSL_API int wolfSSL_set_server_cert_type(WOLFSSL* ssl,
                                          const char* buf, int bufLen)
{
    int i;

    if (ssl == NULL || bufLen > MAX_SERVER_CERT_TYPE_CNT) {
        return BAD_FUNC_ARG;
    }

    /* if buf is set to NULL or bufLen is set to zero, it defaults the setting*/
    if (buf == NULL || bufLen == 0) {
        ssl->options.rpkConfig.preferred_ServerCertTypeCnt = 1;
        ssl->options.rpkConfig.preferred_ServerCertTypes[0]
                                                    = WOLFSSL_CERT_TYPE_X509;
        ssl->options.rpkConfig.preferred_ServerCertTypes[1]
                                                    = WOLFSSL_CERT_TYPE_X509;
        return WOLFSSL_SUCCESS;
    }

    if (!isArrayUnique(buf, (size_t)bufLen))
        return BAD_FUNC_ARG;

    for (i = 0; i < bufLen; i++){
        if (buf[i] != WOLFSSL_CERT_TYPE_RPK && buf[i] != WOLFSSL_CERT_TYPE_X509)
            return BAD_FUNC_ARG;

        ssl->options.rpkConfig.preferred_ServerCertTypes[i] = (byte)buf[i];
    }
    ssl->options.rpkConfig.preferred_ServerCertTypeCnt = bufLen;

    return WOLFSSL_SUCCESS;
}

/* get negotiated certificate type value and return it to the second parameter.
 * cert type value:
 * -1: WOLFSSL_CERT_TYPE_UNKNOWN
 *  0: WOLFSSL_CERT_TYPE_X509
 *  2: WOLFSSL_CERT_TYPE_RPK
 * return WOLFSSL_SUCCESS on success, otherwise negative value.
 * in case no negotiation performed, it returns WOLFSSL_SUCCESS and -1 is for
 * cert type.
 */
WOLFSSL_API int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp)
{
    int ret = WOLFSSL_SUCCESS;

    if (ssl == NULL || tp == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        if (ssl->options.rpkState.received_ClientCertTypeCnt == 1)
            *tp = ssl->options.rpkState.received_ClientCertTypes[0];
        else
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }
    else {
        if (ssl->options.rpkState.sending_ClientCertTypeCnt == 1)
            *tp = ssl->options.rpkState.sending_ClientCertTypes[0];
        else
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }
    return ret;
}

/* get negotiated certificate type value and return it to the second parameter.
 * cert type value:
 * -1: WOLFSSL_CERT_TYPE_UNKNOWN
 *  0: WOLFSSL_CERT_TYPE_X509
 *  2: WOLFSSL_CERT_TYPE_RPK
 * return WOLFSSL_SUCCESS on success, otherwise negative value.
 * in case no negotiation performed, it returns WOLFSSL_SUCCESS and -1 is for
 * cert type.
 */
WOLFSSL_API int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp)
{
    int ret = WOLFSSL_SUCCESS;

    if (ssl == NULL || tp == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        if (ssl->options.rpkState.received_ServerCertTypeCnt == 1)
            *tp = ssl->options.rpkState.received_ServerCertTypes[0];
        else
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }
    else {
        if (ssl->options.rpkState.sending_ServerCertTypeCnt == 1)
            *tp = ssl->options.rpkState.sending_ServerCertTypes[0];
        else
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }
    return ret;
}

#endif /* HAVE_RPK */

#ifdef HAVE_ECC

/* Set Temp CTX EC-DHE size in octets, can be 14 - 66 (112 - 521 bit) */
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetTmpEC_DHE_Sz");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* if 0 then get from loaded private key */
    if (sz == 0) {
        /* applies only to ECDSA */
        if (ctx->privateKeyType != ecc_dsa_sa_algo)
            return WOLFSSL_SUCCESS;

        if (ctx->privateKeySz == 0) {
            WOLFSSL_MSG("Must set private key/cert first");
            return BAD_FUNC_ARG;
        }

        sz = (word16)ctx->privateKeySz;
    }

    /* check size */
#if ECC_MIN_KEY_SZ > 0
    if (sz < ECC_MINSIZE)
        return BAD_FUNC_ARG;
#endif
    if (sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ctx->eccTempKeySz = sz;

    return WOLFSSL_SUCCESS;
}


/* Set Temp SSL EC-DHE size in octets, can be 14 - 66 (112 - 521 bit) */
int wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz)
{
    WOLFSSL_ENTER("wolfSSL_SetTmpEC_DHE_Sz");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    /* check size */
#if ECC_MIN_KEY_SZ > 0
    if (sz < ECC_MINSIZE)
        return BAD_FUNC_ARG;
#endif
    if (sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ssl->eccTempKeySz = sz;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_ECC */


typedef struct {
    byte verifyPeer:1;
    byte verifyNone:1;
    byte failNoCert:1;
    byte failNoCertxPSK:1;
    byte verifyPostHandshake:1;
} SetVerifyOptions;

static SetVerifyOptions ModeToVerifyOptions(int mode)
{
    SetVerifyOptions opts;
    XMEMSET(&opts, 0, sizeof(SetVerifyOptions));

    if (mode != WOLFSSL_VERIFY_DEFAULT) {
        opts.verifyNone = (mode == WOLFSSL_VERIFY_NONE);
        if (!opts.verifyNone) {
            opts.verifyPeer =
                    (mode & WOLFSSL_VERIFY_PEER) != 0;
            opts.failNoCertxPSK =
                    (mode & WOLFSSL_VERIFY_FAIL_EXCEPT_PSK) != 0;
            opts.failNoCert =
                    (mode & WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
            opts.verifyPostHandshake =
                    (mode & WOLFSSL_VERIFY_POST_HANDSHAKE) != 0;
#endif
        }
    }

    return opts;
}

WOLFSSL_ABI
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode, VerifyCallback vc)
{
    SetVerifyOptions opts;

    WOLFSSL_ENTER("wolfSSL_CTX_set_verify");
    if (ctx == NULL)
        return;

    opts = ModeToVerifyOptions(mode);

    ctx->verifyNone     = opts.verifyNone;
    ctx->verifyPeer     = opts.verifyPeer;
    ctx->failNoCert     = opts.failNoCert;
    ctx->failNoCertxPSK = opts.failNoCertxPSK;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    ctx->verifyPostHandshake = opts.verifyPostHandshake;
#endif

    ctx->verifyCallback = vc;
}

#ifdef OPENSSL_ALL
void wolfSSL_CTX_set_cert_verify_callback(WOLFSSL_CTX* ctx,
    CertVerifyCallback cb, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cert_verify_callback");
    if (ctx == NULL)
        return;

    ctx->verifyCertCb = cb;
    ctx->verifyCertCbArg = arg;
}
#endif


void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback vc)
{
    SetVerifyOptions opts;

    WOLFSSL_ENTER("wolfSSL_set_verify");
    if (ssl == NULL)
        return;

    opts = ModeToVerifyOptions(mode);

    ssl->options.verifyNone = opts.verifyNone;
    ssl->options.verifyPeer = opts.verifyPeer;
    ssl->options.failNoCert = opts.failNoCert;
    ssl->options.failNoCertxPSK = opts.failNoCertxPSK;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    ssl->options.verifyPostHandshake = opts.verifyPostHandshake;
#endif

    ssl->verifyCallback = vc;
}

void wolfSSL_set_verify_result(WOLFSSL *ssl, long v)
{
    WOLFSSL_ENTER("wolfSSL_set_verify_result");

    if (ssl == NULL)
        return;

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(OPENSSL_ALL)
    ssl->peerVerifyRet = (unsigned long)v;
#else
    (void)v;
    WOLFSSL_STUB("wolfSSL_set_verify_result");
#endif
}

#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
/* For TLS v1.3 send handshake messages after handshake completes. */
/* Returns 1=WOLFSSL_SUCCESS or 0=WOLFSSL_FAILURE */
int wolfSSL_verify_client_post_handshake(WOLFSSL* ssl)
{
    int ret = wolfSSL_request_certificate(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        if (!IsAtLeastTLSv1_3(ssl->version)) {
            /* specific error of wrong version expected */
            WOLFSSL_ERROR(UNSUPPORTED_PROTO_VERSION);

        }
        else {
            WOLFSSL_ERROR(ret); /* log the error in the error queue */
        }
    }
    return (ret == WOLFSSL_SUCCESS) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX* ctx, int val)
{
    int ret = wolfSSL_CTX_allow_post_handshake_auth(ctx);
    if (ret == 0) {
        ctx->postHandshakeAuth = (val != 0);
    }
    return (ret == 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
int wolfSSL_set_post_handshake_auth(WOLFSSL* ssl, int val)
{
    int ret = wolfSSL_allow_post_handshake_auth(ssl);
    if (ret == 0) {
        ssl->options.postHandshakeAuth = (val != 0);
    }
    return (ret == 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA && !NO_CERTS && WOLFSSL_TLS13 &&
        * WOLFSSL_POST_HANDSHAKE_AUTH */

/* store user ctx for verify callback */
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCertCbCtx");
    if (ssl)
        ssl->verifyCbCtx = ctx;
}


/* store user ctx for verify callback */
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCertCbCtx");
    if (ctx)
        ctx->verifyCbCtx = userCtx;
}


/* store context CA Cache addition callback */
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb)
{
    if (ctx && ctx->cm)
        ctx->cm->caCacheCallback = cb;
}


#if defined(PERSIST_CERT_CACHE)

#if !defined(NO_FILESYSTEM)

/* Persist cert cache to file */
int wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER("wolfSSL_CTX_save_cert_cache");

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_SaveCertCache(ctx->cm, fname);
}


/* Persist cert cache from file */
int wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER("wolfSSL_CTX_restore_cert_cache");

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_RestoreCertCache(ctx->cm, fname);
}

#endif /* NO_FILESYSTEM */

/* Persist cert cache to memory */
int wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem,
                                   int sz, int* used)
{
    WOLFSSL_ENTER("wolfSSL_CTX_memsave_cert_cache");

    if (ctx == NULL || mem == NULL || used == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    return CM_MemSaveCertCache(ctx->cm, mem, sz, used);
}


/* Restore cert cache from memory */
int wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_memrestore_cert_cache");

    if (ctx == NULL || mem == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    return CM_MemRestoreCertCache(ctx->cm, mem, sz);
}


/* get how big the the cert cache save buffer needs to be */
int wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_cert_cache_memsize");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return CM_GetCertCacheMemSize(ctx->cm);
}

#endif /* PERSIST_CERT_CACHE */
#endif /* !NO_CERTS */


void wolfSSL_load_error_strings(void)
{
    /* compatibility only */
}


int wolfSSL_library_init(void)
{
    WOLFSSL_ENTER("wolfSSL_library_init");
    if (wolfSSL_Init() == WOLFSSL_SUCCESS)
        return WOLFSSL_SUCCESS;
    else
        return WOLFSSL_FATAL_ERROR;
}


#ifdef HAVE_SECRET_CALLBACK

int wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_set_session_secret_cb");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->sessionSecretCb = cb;
    ssl->sessionSecretCtx = ctx;
    if (cb != NULL) {
        /* If using a pre-set key, assume session resumption. */
        ssl->session->sessionIDSz = 0;
        ssl->options.resuming = 1;
    }

    return WOLFSSL_SUCCESS;
}

int wolfSSL_set_session_ticket_ext_cb(WOLFSSL* ssl, TicketParseCb cb,
        void *ctx)
{
    WOLFSSL_ENTER("wolfSSL_set_session_ticket_ext_cb");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->ticketParseCb = cb;
    ssl->ticketParseCtx = ctx;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_set_secret_cb(WOLFSSL* ssl, TlsSecretCb cb, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_set_secret_cb");
    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    ssl->tlsSecretCb = cb;
    ssl->tlsSecretCtx = ctx;

    return WOLFSSL_SUCCESS;
}

#ifdef SHOW_SECRETS
int tlsShowSecrets(WOLFSSL* ssl, void* secret, int secretSz,
        void* ctx)
{
    /* Wireshark Pre-Master-Secret Format:
     *  CLIENT_RANDOM <clientrandom> <mastersecret>
     */
    const char* CLIENT_RANDOM_LABEL = "CLIENT_RANDOM";
    int i, pmsPos = 0;
    char pmsBuf[13 + 1 + 64 + 1 + 96 + 1 + 1];
    byte clientRandom[RAN_LEN];
    int clientRandomSz;

    (void)ctx;

    clientRandomSz = (int)wolfSSL_get_client_random(ssl, clientRandom,
        sizeof(clientRandom));

    if (clientRandomSz <= 0) {
        printf("Error getting server random %d\n", clientRandomSz);
        return BAD_FUNC_ARG;
    }

    XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%s ",
        CLIENT_RANDOM_LABEL);
    pmsPos += XSTRLEN(CLIENT_RANDOM_LABEL) + 1;
    for (i = 0; i < clientRandomSz; i++) {
        XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%02x",
            clientRandom[i]);
        pmsPos += 2;
    }
    XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, " ");
    pmsPos += 1;
    for (i = 0; i < secretSz; i++) {
        XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%02x",
            ((byte*)secret)[i]);
        pmsPos += 2;
    }
    XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "\n");
    pmsPos += 1;

    /* print master secret */
    puts(pmsBuf);

    #if !defined(NO_FILESYSTEM) && defined(WOLFSSL_SSLKEYLOGFILE)
    {
        FILE* f = XFOPEN(WOLFSSL_SSLKEYLOGFILE_OUTPUT, "a");
        if (f != XBADFILE) {
            XFWRITE(pmsBuf, 1, pmsPos, f);
            XFCLOSE(f);
        }
    }
    #endif
    return 0;
}
#endif /* SHOW_SECRETS */

#endif


#ifdef OPENSSL_EXTRA

/*
 * check if the list has TLS13 and pre-TLS13 suites
 * @param list cipher suite list that user want to set
 *         (caller required to check for NULL)
 * @return mixed: 0, only pre-TLS13: 1, only TLS13: 2
 */
static int CheckcipherList(const char* list)
{
    int ret;
    int findTLSv13Suites = 0;
    int findbeforeSuites = 0;
    byte cipherSuite0;
    byte cipherSuite1;
    int flags;
    char* next = (char*)list;

    do {
        char*  current = next;
        char   name[MAX_SUITE_NAME + 1];
        word32 length = MAX_SUITE_NAME;
        word32 current_length;
        byte major = INVALID_BYTE;
        byte minor = INVALID_BYTE;

        next   = XSTRSTR(next, ":");

        current_length = (!next) ? (word32)XSTRLEN(current)
                                 : (word32)(next - current);
        if (current_length == 0) {
            break;
        }

        if (current_length < length) {
            length = current_length;
        }
        XMEMCPY(name, current, length);
        name[length] = 0;

        if (XSTRCMP(name, "ALL") == 0 ||
            XSTRCMP(name, "DEFAULT") == 0 ||
            XSTRCMP(name, "HIGH") == 0)
        {
            findTLSv13Suites = 1;
            findbeforeSuites = 1;
            break;
        }

        ret = GetCipherSuiteFromName(name, &cipherSuite0,
                &cipherSuite1, &major, &minor, &flags);
        if (ret == 0) {
            if (cipherSuite0 == TLS13_BYTE || minor == TLSv1_3_MINOR) {
                /* TLSv13 suite */
                findTLSv13Suites = 1;
            }
            else {
                findbeforeSuites = 1;
            }
        }

    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
        /* check if mixed due to names like RSA:ECDHE+AESGCM etc. */
        if (ret != 0) {
            char* subStr = name;
            char* subStrNext;

            do {
                subStrNext = XSTRSTR(subStr, "+");

                if ((XSTRCMP(subStr, "ECDHE") == 0) ||
                    (XSTRCMP(subStr, "RSA") == 0)) {
                    return 0;
                }

                if (subStrNext && (XSTRLEN(subStrNext) > 0)) {
                    subStr = subStrNext + 1; /* +1 to skip past '+' */
                }
            } while (subStrNext != NULL);
        }
    #endif

        if (findTLSv13Suites == 1 && findbeforeSuites == 1) {
            /* list has mixed suites */
            return 0;
        }
    }
    while (next++); /* increment to skip ':' */

    if (findTLSv13Suites == 0 && findbeforeSuites == 1) {
        ret = 1;/* only before TLSv13 suites */
    }
    else if (findTLSv13Suites == 1 && findbeforeSuites == 0) {
        ret = 2;/* only TLSv13 suties */
    }
    else {
        ret = 0;/* handle as mixed */
    }
    return ret;
}

/* parse some bulk lists like !eNULL / !aNULL
 *
 * returns WOLFSSL_SUCCESS on success and sets the cipher suite list
 */
static int wolfSSL_parse_cipher_list(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
        Suites* suites, const char* list)
{
    int     ret = 0;
    int     listattribute = 0;
    int     tls13Only = 0;
#ifndef WOLFSSL_SMALL_STACK
    byte    suitesCpy[WOLFSSL_MAX_SUITE_SZ];
#else
    byte*   suitesCpy = NULL;
#endif
    word16  suitesCpySz = 0;
    word16  i = 0;
    word16  j = 0;

    if (suites == NULL || list == NULL) {
        WOLFSSL_MSG("NULL argument");
        return WOLFSSL_FAILURE;
    }

    listattribute = CheckcipherList(list);

    if (listattribute == 0) {
       /* list has mixed(pre-TLSv13 and TLSv13) suites
        * update cipher suites the same as before
        */
        return (SetCipherList_ex(ctx, ssl, suites, list)) ? WOLFSSL_SUCCESS :
        WOLFSSL_FAILURE;
    }
    else if (listattribute == 1) {
       /* list has only pre-TLSv13 suites.
        * Only update before TLSv13 suites.
        */
        tls13Only = 0;
    }
    else if (listattribute == 2) {
       /* list has only TLSv13 suites. Only update TLv13 suites
        * simulate set_ciphersuites() compatibility layer API
        */
        tls13Only = 1;
        if ((ctx != NULL && !IsAtLeastTLSv1_3(ctx->method->version)) ||
                (ssl != NULL && !IsAtLeastTLSv1_3(ssl->version))) {
            /* Silently ignore TLS 1.3 ciphers if we don't support it. */
            return WOLFSSL_SUCCESS;
        }
    }

    /* list contains ciphers either only for TLS 1.3 or <= TLS 1.2 */
#ifdef WOLFSSL_SMALL_STACK
    if (suites->suiteSz > 0) {
        suitesCpy = (byte*)XMALLOC(suites->suiteSz, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (suitesCpy == NULL) {
            return WOLFSSL_FAILURE;
        }

        XMEMSET(suitesCpy, 0, suites->suiteSz);
    }
#else
        XMEMSET(suitesCpy, 0, sizeof(suitesCpy));
#endif

    if (suites->suiteSz > 0)
        XMEMCPY(suitesCpy, suites->suites, suites->suiteSz);
    suitesCpySz = suites->suiteSz;

    ret = SetCipherList_ex(ctx, ssl, suites, list);
    if (ret != 1) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(suitesCpy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return WOLFSSL_FAILURE;
    }

    /* The idea in this section is that OpenSSL has two API to set ciphersuites.
     *   - SSL_CTX_set_cipher_list for setting TLS <= 1.2 suites
     *   - SSL_CTX_set_ciphersuites for setting TLS 1.3 suites
     * Since we direct both API here we attempt to provide API compatibility. If
     * we only get suites from <= 1.2 or == 1.3 then we will only update those
     * suites and keep the suites from the other group. */
    for (i = 0; i < suitesCpySz &&
                suites->suiteSz <= (WOLFSSL_MAX_SUITE_SZ - SUITE_LEN); i += 2) {
        /* Check for duplicates */
        int duplicate = 0;
        for (j = 0; j < suites->suiteSz; j += 2) {
            if (suitesCpy[i] == suites->suites[j] &&
                    suitesCpy[i+1] == suites->suites[j+1]) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            if (tls13Only) {
                /* Updating TLS 1.3 ciphers */
                if (suitesCpy[i] != TLS13_BYTE) {
                    /* Only copy over <= TLS 1.2 ciphers */
                    /* TLS 1.3 ciphers take precedence */
                    suites->suites[suites->suiteSz++] = suitesCpy[i];
                    suites->suites[suites->suiteSz++] = suitesCpy[i+1];
                }
            }
            else {
                /* Updating <= TLS 1.2 ciphers */
                if (suitesCpy[i] == TLS13_BYTE) {
                    /* Only copy over TLS 1.3 ciphers */
                    /* TLS 1.3 ciphers take precedence */
                    XMEMMOVE(suites->suites + SUITE_LEN, suites->suites,
                             suites->suiteSz);
                    suites->suites[0] = suitesCpy[i];
                    suites->suites[1] = suitesCpy[i+1];
                    suites->suiteSz += 2;
                }
            }
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(suitesCpy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

#endif


int wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cipher_list");

    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    if (AllocateCtxSuites(ctx) != 0)
        return WOLFSSL_FAILURE;

#ifdef OPENSSL_EXTRA
    return wolfSSL_parse_cipher_list(ctx, NULL, ctx->suites, list);
#else
    return (SetCipherList(ctx, ctx->suites, list)) ?
        WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
#endif
}

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
int wolfSSL_CTX_set_cipher_list_bytes(WOLFSSL_CTX* ctx, const byte* list,
                                      const int listSz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cipher_list_bytes");

    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    if (AllocateCtxSuites(ctx) != 0)
        return WOLFSSL_FAILURE;

    return (SetCipherListFromBytes(ctx, ctx->suites, list, listSz)) ?
        WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_SET_CIPHER_BYTES */

int wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list)
{
    WOLFSSL_ENTER("wolfSSL_set_cipher_list");

    if (ssl == NULL || ssl->ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (AllocateSuites(ssl) != 0)
        return WOLFSSL_FAILURE;

#ifdef OPENSSL_EXTRA
    return wolfSSL_parse_cipher_list(NULL, ssl, ssl->suites, list);
#else
    return (SetCipherList_ex(NULL, ssl, ssl->suites, list)) ?
        WOLFSSL_SUCCESS :
        WOLFSSL_FAILURE;
#endif
}

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
int wolfSSL_set_cipher_list_bytes(WOLFSSL* ssl, const byte* list,
                                  const int listSz)
{
    WOLFSSL_ENTER("wolfSSL_set_cipher_list_bytes");

    if (ssl == NULL || ssl->ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (AllocateSuites(ssl) != 0)
        return WOLFSSL_FAILURE;

    return (SetCipherListFromBytes(ssl->ctx, ssl->suites, list, listSz))
           ? WOLFSSL_SUCCESS
           : WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_SET_CIPHER_BYTES */


#ifdef HAVE_KEYING_MATERIAL

#define TLS_PRF_LABEL_CLIENT_FINISHED     "client finished"
#define TLS_PRF_LABEL_SERVER_FINISHED     "server finished"
#define TLS_PRF_LABEL_MASTER_SECRET       "master secret"
#define TLS_PRF_LABEL_EXT_MASTER_SECRET   "extended master secret"
#define TLS_PRF_LABEL_KEY_EXPANSION       "key expansion"

static const struct ForbiddenLabels {
    const char* label;
    size_t labelLen;
} forbiddenLabels[] = {
    {TLS_PRF_LABEL_CLIENT_FINISHED, XSTR_SIZEOF(TLS_PRF_LABEL_CLIENT_FINISHED)},
    {TLS_PRF_LABEL_SERVER_FINISHED, XSTR_SIZEOF(TLS_PRF_LABEL_SERVER_FINISHED)},
    {TLS_PRF_LABEL_MASTER_SECRET, XSTR_SIZEOF(TLS_PRF_LABEL_MASTER_SECRET)},
    {TLS_PRF_LABEL_EXT_MASTER_SECRET,
     XSTR_SIZEOF(TLS_PRF_LABEL_EXT_MASTER_SECRET)},
    {TLS_PRF_LABEL_KEY_EXPANSION, XSTR_SIZEOF(TLS_PRF_LABEL_KEY_EXPANSION)},
    {NULL, 0},
};

/**
 * Implement RFC 5705
 * TLS 1.3 uses a different exporter definition (section 7.5 of RFC 8446)
 * @return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on error
 */
int wolfSSL_export_keying_material(WOLFSSL *ssl,
        unsigned char *out, size_t outLen,
        const char *label, size_t labelLen,
        const unsigned char *context, size_t contextLen,
        int use_context)
{
    byte*  seed = NULL;
    word32 seedLen;
    const struct ForbiddenLabels* fl;

    WOLFSSL_ENTER("wolfSSL_export_keying_material");

    if (ssl == NULL || out == NULL || label == NULL ||
            (use_context && contextLen && context == NULL)) {
        WOLFSSL_MSG("Bad argument");
        return WOLFSSL_FAILURE;
    }

    /* clientRandom + serverRandom
     * OR
     * clientRandom + serverRandom + ctx len encoding + ctx */
    seedLen = !use_context ? (word32)SEED_LEN :
                             (word32)SEED_LEN + 2 + (word32)contextLen;

    if (ssl->options.saveArrays == 0 || ssl->arrays == NULL) {
        WOLFSSL_MSG("To export keying material wolfSSL needs to keep handshake "
                    "data. Call wolfSSL_KeepArrays before attempting to "
                    "export keyid material.");
        return WOLFSSL_FAILURE;
    }

    /* check forbidden labels */
    for (fl = &forbiddenLabels[0]; fl->label != NULL; fl++) {
        if (labelLen >= fl->labelLen &&
                XMEMCMP(label, fl->label, fl->labelLen) == 0) {
            WOLFSSL_MSG("Forbidden label");
            return WOLFSSL_FAILURE;
        }
    }

#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        /* Path for TLS 1.3 */
        if (!use_context) {
            contextLen = 0;
            context = (byte*)""; /* Give valid pointer for 0 length memcpy */
        }

        if (Tls13_Exporter(ssl, out, (word32)outLen, label, labelLen,
                context, contextLen) != 0) {
            WOLFSSL_MSG("Tls13_Exporter error");
            return WOLFSSL_FAILURE;
        }
        return WOLFSSL_SUCCESS;
    }
#endif

    /* Path for <=TLS 1.2 */
    seed = (byte*)XMALLOC(seedLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (seed == NULL) {
        WOLFSSL_MSG("malloc error");
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(seed,           ssl->arrays->clientRandom, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, ssl->arrays->serverRandom, RAN_LEN);

    if (use_context) {
        /* Encode len in big endian */
        seed[SEED_LEN    ] = (contextLen >> 8) & 0xFF;
        seed[SEED_LEN + 1] = (contextLen) & 0xFF;
        if (contextLen) {
            /* 0 length context is allowed */
            XMEMCPY(seed + SEED_LEN + 2, context, contextLen);
        }
    }

    PRIVATE_KEY_UNLOCK();
    if (wc_PRF_TLS(out, (word32)outLen, ssl->arrays->masterSecret, SECRET_LEN,
            (byte*)label, (word32)labelLen, seed, seedLen,
            IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm, ssl->heap,
            ssl->devId) != 0) {
        WOLFSSL_MSG("wc_PRF_TLS error");
        PRIVATE_KEY_LOCK();
        XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }
    PRIVATE_KEY_LOCK();

    XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_KEYING_MATERIAL */

int wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl)
{
    int useNb = 0;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_dtls_get_using_nonblock");
    if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
        useNb = ssl->options.dtlsUseNonblock;
#endif
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_get_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
    return useNb;
}


#ifndef WOLFSSL_LEANPSK

void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock)
{
    (void)nonblock;

    WOLFSSL_ENTER("wolfSSL_dtls_set_using_nonblock");

    if (ssl == NULL)
        return;

    if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
        ssl->options.dtlsUseNonblock = (nonblock != 0);
#endif
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_set_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
}


#ifdef WOLFSSL_DTLS

int wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl)
{
    int timeout = 0;
    if (ssl)
        timeout = ssl->dtls_timeout;

    WOLFSSL_LEAVE("wolfSSL_dtls_get_current_timeout", timeout);
    return timeout;
}

#ifdef WOLFSSL_DTLS13

/*
 * This API returns 1 when the user should set a short timeout for receiving
 * data. It is recommended that it is at most 1/4 the value returned by
 * wolfSSL_dtls_get_current_timeout().
 */
int wolfSSL_dtls13_use_quick_timeout(WOLFSSL* ssl)
{
    return ssl->dtls13FastTimeout;
}

/*
 * When this is set, a DTLS 1.3 connection will send acks immediately when a
 * disruption is detected to shortcut timeouts. This results in potentially
 * more traffic but may make the handshake quicker.
 */
void wolfSSL_dtls13_set_send_more_acks(WOLFSSL* ssl, int value)
{
    if (ssl != NULL)
        ssl->options.dtls13SendMoreAcks = !!value;
}
#endif /* WOLFSSL_DTLS13 */

int wolfSSL_DTLSv1_get_timeout(WOLFSSL* ssl, WOLFSSL_TIMEVAL* timeleft)
{
    if (ssl && timeleft) {
        XMEMSET(timeleft, 0, sizeof(WOLFSSL_TIMEVAL));
        timeleft->tv_sec = ssl->dtls_timeout;
    }
    return 0;
}

#ifndef NO_WOLFSSL_STUB
int wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl)
{
    WOLFSSL_STUB("SSL_DTLSv1_handle_timeout");
    (void)ssl;
    return 0;
}
#endif

#ifndef NO_WOLFSSL_STUB
void wolfSSL_DTLSv1_set_initial_timeout_duration(WOLFSSL* ssl,
    word32 duration_ms)
{
    WOLFSSL_STUB("SSL_DTLSv1_set_initial_timeout_duration");
    (void)ssl;
    (void)duration_ms;
}
#endif

/* user may need to alter init dtls recv timeout, WOLFSSL_SUCCESS on ok */
int wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout > ssl->dtls_timeout_max) {
        WOLFSSL_MSG("Can't set dtls timeout init greater than dtls timeout "
                    "max");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_init = timeout;
    ssl->dtls_timeout = timeout;

    return WOLFSSL_SUCCESS;
}


/* user may need to alter max dtls recv timeout, WOLFSSL_SUCCESS on ok */
int wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout < ssl->dtls_timeout_init) {
        WOLFSSL_MSG("Can't set dtls timeout max less than dtls timeout init");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_max = timeout;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_dtls_got_timeout(WOLFSSL* ssl)
{
    int result = WOLFSSL_SUCCESS;
    WOLFSSL_ENTER("wolfSSL_dtls_got_timeout");

    if (ssl == NULL || !ssl->options.dtls)
        return WOLFSSL_FATAL_ERROR;

#ifdef WOLFSSL_DTLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        result = Dtls13RtxTimeout(ssl);
        if (result < 0) {
            if (result == WC_NO_ERR_TRACE(WANT_WRITE))
                ssl->dtls13SendingAckOrRtx = 1;
            ssl->error = result;
            WOLFSSL_ERROR(result);
            return WOLFSSL_FATAL_ERROR;
        }

        return WOLFSSL_SUCCESS;
    }
#endif /* WOLFSSL_DTLS13 */

    /* Do we have any 1.2 messages stored? */
    if (ssl->dtls_tx_msg_list != NULL || ssl->dtls_tx_msg != NULL) {
        if (DtlsMsgPoolTimeout(ssl) < 0){
            ssl->error = SOCKET_ERROR_E;
            WOLFSSL_ERROR(ssl->error);
            result = WOLFSSL_FATAL_ERROR;
        }
        else if ((result = DtlsMsgPoolSend(ssl, 0)) < 0)  {
            ssl->error = result;
            WOLFSSL_ERROR(result);
            result = WOLFSSL_FATAL_ERROR;
        }
        else {
            /* Reset return value to success */
            result = WOLFSSL_SUCCESS;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_dtls_got_timeout", result);
    return result;
}


/* retransmit all the saves messages, WOLFSSL_SUCCESS on ok */
int wolfSSL_dtls_retransmit(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_dtls_retransmit");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (!ssl->options.handShakeDone) {
        int result;
#ifdef WOLFSSL_DTLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            result = Dtls13DoScheduledWork(ssl);
        else
#endif
            result = DtlsMsgPoolSend(ssl, 0);
        if (result < 0) {
            ssl->error = result;
            WOLFSSL_ERROR(result);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    return WOLFSSL_SUCCESS;
}

#endif /* DTLS */
#endif /* LEANPSK */


#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)

/* Not an SSL function, return 0 for success, error code otherwise */
/* Prereq: ssl's RNG needs to be initialized. */
int wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                 const byte* secret, word32 secretSz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_DTLS_SetCookieSecret");

    if (ssl == NULL) {
        WOLFSSL_MSG("need a SSL object");
        return BAD_FUNC_ARG;
    }

    if (secret != NULL && secretSz == 0) {
        WOLFSSL_MSG("can't have a new secret without a size");
        return BAD_FUNC_ARG;
    }

    /* If secretSz is 0, use the default size. */
    if (secretSz == 0)
        secretSz = COOKIE_SECRET_SZ;

    if (secretSz != ssl->buffers.dtlsCookieSecret.length) {
        byte* newSecret;

        if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
            ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
                      ssl->buffers.dtlsCookieSecret.length);
            XFREE(ssl->buffers.dtlsCookieSecret.buffer,
                  ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
        }

        newSecret = (byte*)XMALLOC(secretSz, ssl->heap,DYNAMIC_TYPE_COOKIE_PWD);
        if (newSecret == NULL) {
            ssl->buffers.dtlsCookieSecret.buffer = NULL;
            ssl->buffers.dtlsCookieSecret.length = 0;
            WOLFSSL_MSG("couldn't allocate new cookie secret");
            return MEMORY_ERROR;
        }
        ssl->buffers.dtlsCookieSecret.buffer = newSecret;
        ssl->buffers.dtlsCookieSecret.length = secretSz;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("wolfSSL_DTLS_SetCookieSecret secret",
            ssl->buffers.dtlsCookieSecret.buffer,
            ssl->buffers.dtlsCookieSecret.length);
    #endif
    }

    /* If the supplied secret is NULL, randomly generate a new secret. */
    if (secret == NULL) {
        ret = wc_RNG_GenerateBlock(ssl->rng,
                             ssl->buffers.dtlsCookieSecret.buffer, secretSz);
    }
    else
        XMEMCPY(ssl->buffers.dtlsCookieSecret.buffer, secret, secretSz);

    WOLFSSL_LEAVE("wolfSSL_DTLS_SetCookieSecret", 0);
    return ret;
}

#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */


/* EITHER SIDE METHODS */
#if !defined(NO_TLS) && (defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE))
    WOLFSSL_METHOD* wolfSSLv23_method(void)
    {
        return wolfSSLv23_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv23_method_ex(void* heap)
    {
        WOLFSSL_METHOD* m = NULL;
        WOLFSSL_ENTER("wolfSSLv23_method");
    #if !defined(NO_WOLFSSL_CLIENT)
        m = wolfSSLv23_client_method_ex(heap);
    #elif !defined(NO_WOLFSSL_SERVER)
        m = wolfSSLv23_server_method_ex(heap);
    #else
        (void)heap;
    #endif
        if (m != NULL) {
            m->side = WOLFSSL_NEITHER_END;
        }

        return m;
    }

    #ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
    WOLFSSL_METHOD* wolfSSLv3_method(void)
    {
        return wolfSSLv3_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv3_method_ex(void* heap)
    {
        WOLFSSL_METHOD* m = NULL;
        WOLFSSL_ENTER("wolfSSLv3_method_ex");
    #if !defined(NO_WOLFSSL_CLIENT)
        m = wolfSSLv3_client_method_ex(heap);
    #elif !defined(NO_WOLFSSL_SERVER)
        m = wolfSSLv3_server_method_ex(heap);
    #endif
        if (m != NULL) {
            m->side = WOLFSSL_NEITHER_END;
        }

        return m;
    }
    #endif
    #endif
#endif /* !NO_TLS && (OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE) */

/* client only parts */
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)

    #if defined(OPENSSL_EXTRA) && !defined(NO_OLD_TLS)
    WOLFSSL_METHOD* wolfSSLv2_client_method(void)
    {
        WOLFSSL_STUB("wolfSSLv2_client_method");
        return NULL;
    }
    #endif

    #if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
    WOLFSSL_METHOD* wolfSSLv3_client_method(void)
    {
        return wolfSSLv3_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv3_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("wolfSSLv3_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeSSLv3());
        return method;
    }
    #endif /* WOLFSSL_ALLOW_SSLV3 && !NO_OLD_TLS */


    WOLFSSL_METHOD* wolfSSLv23_client_method(void)
    {
        return wolfSSLv23_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv23_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("wolfSSLv23_client_method_ex");
        if (method) {
    #if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || \
        defined(WOLFSSL_SHA512)
        #if defined(WOLFSSL_TLS13)
            InitSSL_Method(method, MakeTLSv1_3());
        #elif !defined(WOLFSSL_NO_TLS12)
            InitSSL_Method(method, MakeTLSv1_2());
        #elif !defined(NO_OLD_TLS)
            InitSSL_Method(method, MakeTLSv1_1());
        #endif
    #else
        #ifndef NO_OLD_TLS
            InitSSL_Method(method, MakeTLSv1_1());
        #endif
    #endif
    #if !defined(NO_OLD_TLS) || defined(WOLFSSL_TLS13)
            method->downgrade = 1;
    #endif
        }
        return method;
    }

    /* please see note at top of README if you get an error from connect */
    WOLFSSL_ABI
    int wolfSSL_connect(WOLFSSL* ssl)
    {
    #if !(defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
          defined(WOLFSSL_TLS13))
        int neededState;
        byte advanceState;
    #endif
        int ret = 0;

        (void)ret;

        #ifdef HAVE_ERRNO_H
            errno = 0;
        #endif

        if (ssl == NULL)
            return BAD_FUNC_ARG;

    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE)
        if (ssl->options.side == WOLFSSL_NEITHER_END) {
            ssl->error = InitSSL_Side(ssl, WOLFSSL_CLIENT_END);
            if (ssl->error != WOLFSSL_SUCCESS) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->error = 0; /* expected to be zero here */
        }

    #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, WOLFSSL_ST_CONNECT, WOLFSSL_SUCCESS);
            ssl->cbmode = WOLFSSL_CB_WRITE;
        }
    #endif
    #endif /* OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE */

    #if defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
        defined(WOLFSSL_TLS13)
        return wolfSSL_connect_TLSv13(ssl);
    #else
        #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            WOLFSSL_MSG("TLS 1.3");
            return wolfSSL_connect_TLSv13(ssl);
        }
        #endif

        WOLFSSL_MSG("TLS 1.2 or lower");
        WOLFSSL_ENTER("wolfSSL_connect");

        /* make sure this wolfSSL object has arrays and rng setup. Protects
         * case where the WOLFSSL object is reused via wolfSSL_clear() */
        if ((ret = ReinitSSL(ssl, ssl->ctx, 0)) != 0) {
            return ret;
        }

#ifdef WOLFSSL_WOLFSENTRY_HOOKS
        if ((ssl->ConnectFilter != NULL) &&
            (ssl->options.connectState == CONNECT_BEGIN)) {
            wolfSSL_netfilter_decision_t res;
            if ((ssl->ConnectFilter(ssl, ssl->ConnectFilter_arg, &res) ==
                 WOLFSSL_SUCCESS) &&
                (res == WOLFSSL_NETFILTER_REJECT)) {
                ssl->error = SOCKET_FILTERED_E;
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
#endif /* WOLFSSL_WOLFSENTRY_HOOKS */

        if (ssl->options.side != WOLFSSL_CLIENT_END) {
            ssl->error = SIDE_ERROR;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

        #ifdef WOLFSSL_DTLS
        if (ssl->version.major == DTLS_MAJOR) {
            ssl->options.dtls   = 1;
            ssl->options.tls    = 1;
            ssl->options.tls1_1 = 1;
            ssl->options.dtlsStateful = 1;
        }
        #endif

        /* fragOffset is non-zero when sending fragments. On the last
         * fragment, fragOffset is zero again, and the state can be
         * advanced. */
        advanceState = ssl->fragOffset == 0 &&
            (ssl->options.connectState == CONNECT_BEGIN ||
             ssl->options.connectState == HELLO_AGAIN ||
             (ssl->options.connectState >= FIRST_REPLY_DONE &&
              ssl->options.connectState <= FIRST_REPLY_FOURTH));

#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version))
            advanceState = advanceState && !ssl->dtls13SendingAckOrRtx;
#endif /* WOLFSSL_DTLS13 */

        if (ssl->buffers.outputBuffer.length > 0
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* do not send buffered or advance state if last error was an
                async pending operation */
            && ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E)
        #endif
        ) {
            ret = SendBuffered(ssl);
            if (ret == 0) {
                if (ssl->fragOffset == 0 && !ssl->options.buildingMsg) {
                    if (advanceState) {
                        ssl->options.connectState++;
                        WOLFSSL_MSG("connect state: Advanced from last "
                                    "buffered fragment send");
                    #ifdef WOLFSSL_ASYNC_IO
                        /* Cleanup async */
                        FreeAsyncCtx(ssl, 0);
                    #endif
                    }
                }
                else {
                    WOLFSSL_MSG("connect state: "
                                "Not advanced, more fragments to send");
                }
            }
            else {
                ssl->error = ret;
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls)
                ssl->dtls13SendingAckOrRtx = 0;
#endif /* WOLFSSL_DTLS13 */
        }

        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

        switch (ssl->options.connectState) {

        case CONNECT_BEGIN :
            /* always send client hello first */
            if ( (ssl->error = SendClientHello(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.connectState = CLIENT_HELLO_SENT;
            WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");
            FALL_THROUGH;

        case CLIENT_HELLO_SENT :
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                          SERVER_HELLODONE_COMPLETE;
            #ifdef WOLFSSL_DTLS
                /* In DTLS, when resuming, we can go straight to FINISHED,
                 * or do a cookie exchange and then skip to FINISHED, assume
                 * we need the cookie exchange first. */
                if (IsDtlsNotSctpMode(ssl))
                    neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
            #endif
            /* get response */
            WOLFSSL_MSG("Server state up to needed state.");
            while (ssl->options.serverState < neededState) {
                WOLFSSL_MSG("Progressing server state...");
                #ifdef WOLFSSL_TLS13
                    if (ssl->options.tls1_3)
                        return wolfSSL_connect_TLSv13(ssl);
                #endif
                WOLFSSL_MSG("ProcessReply...");
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state */
                else if (neededState == SERVER_FINISHED_COMPLETE) {
                    if (!ssl->options.resuming) {
                    #ifdef WOLFSSL_DTLS
                        if (IsDtlsNotSctpMode(ssl))
                            neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
                        else
                    #endif
                            neededState = SERVER_HELLODONE_COMPLETE;
                    }
                }
                WOLFSSL_MSG("ProcessReply done.");

#ifdef WOLFSSL_DTLS13
                if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)
                    && ssl->dtls13Rtx.sendAcks == 1
                    && ssl->options.seenUnifiedHdr) {
                    /* we aren't negotiated the version yet, so we aren't sure
                     * the other end can speak v1.3. On the other side we have
                     * received a unified records, assuming that the
                     * ServerHello got lost, we will send an empty ACK. In case
                     * the server is a DTLS with version less than 1.3, it
                     * should just ignore the message */
                    ssl->dtls13Rtx.sendAcks = 0;
                    if ((ssl->error = SendDtls13Ack(ssl)) < 0) {
                        if (ssl->error == WC_NO_ERR_TRACE(WANT_WRITE))
                            ssl->dtls13SendingAckOrRtx = 1;
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
#endif /* WOLFSSL_DTLS13 */
            }

            ssl->options.connectState = HELLO_AGAIN;
            WOLFSSL_MSG("connect state: HELLO_AGAIN");
            FALL_THROUGH;

        case HELLO_AGAIN :

        #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3)
                return wolfSSL_connect_TLSv13(ssl);
        #endif

            #ifdef WOLFSSL_DTLS
            if (ssl->options.serverState ==
                    SERVER_HELLOVERIFYREQUEST_COMPLETE) {
                if (IsDtlsNotSctpMode(ssl)) {
                    /* re-init hashes, exclude first hello and verify request */
                    if ((ssl->error = InitHandshakeHashes(ssl)) != 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                    if ( (ssl->error = SendClientHello(ssl)) != 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
            }
            #endif

            ssl->options.connectState = HELLO_AGAIN_REPLY;
            WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");
            FALL_THROUGH;

        case HELLO_AGAIN_REPLY :
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    neededState = ssl->options.resuming ?
                           SERVER_FINISHED_COMPLETE : SERVER_HELLODONE_COMPLETE;

                    /* get response */
                    while (ssl->options.serverState < neededState) {
                        if ( (ssl->error = ProcessReply(ssl)) < 0) {
                            WOLFSSL_ERROR(ssl->error);
                            return WOLFSSL_FATAL_ERROR;
                        }
                        /* if resumption failed, reset needed state */
                        if (neededState == SERVER_FINISHED_COMPLETE) {
                            if (!ssl->options.resuming)
                                neededState = SERVER_HELLODONE_COMPLETE;
                        }
                    }
                }
            #endif

            ssl->options.connectState = FIRST_REPLY_DONE;
            WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
            FALL_THROUGH;

        case FIRST_REPLY_DONE :
            if (ssl->options.certOnly)
                return WOLFSSL_SUCCESS;
            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
                #ifdef WOLFSSL_TLS13
                    if (ssl->options.tls1_3)
                        return wolfSSL_connect_TLSv13(ssl);
                #endif
                if (ssl->options.sendVerify) {
                    if ( (ssl->error = SendCertificate(ssl)) != 0) {
                    #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                        ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                    #endif
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                    WOLFSSL_MSG("sent: certificate");
                }

            #endif
            ssl->options.connectState = FIRST_REPLY_FIRST;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");
            FALL_THROUGH;

        case FIRST_REPLY_FIRST :
        #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3)
                return wolfSSL_connect_TLSv13(ssl);
        #endif
            if (!ssl->options.resuming) {
                if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
                #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                    ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                #endif
#ifdef WOLFSSL_EXTRA_ALERTS
                    if (ssl->error == WC_NO_ERR_TRACE(NO_PEER_KEY) ||
                        ssl->error == WC_NO_ERR_TRACE(PSK_KEY_ERROR)) {
                        SendAlert(ssl, alert_fatal, handshake_failure);
                    }
#endif
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                WOLFSSL_MSG("sent: client key exchange");
            }

            ssl->options.connectState = FIRST_REPLY_SECOND;
            WOLFSSL_MSG("connect state: FIRST_REPLY_SECOND");
            FALL_THROUGH;

    #if !defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS)
        case FIRST_REPLY_SECOND :
            /* CLIENT: Fail-safe for Server Authentication. */
            if (!ssl->options.peerAuthGood) {
                WOLFSSL_MSG("Server authentication did not happen");
                ssl->error = NO_PEER_VERIFY;
                return WOLFSSL_FATAL_ERROR;
            }

            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
                if (ssl->options.sendVerify) {
                    if ( (ssl->error = SendCertificateVerify(ssl)) != 0) {
                    #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                        ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                    #endif
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                    WOLFSSL_MSG("sent: certificate verify");
                }
            #endif /* !NO_CERTS && !WOLFSSL_NO_CLIENT_AUTH */
            ssl->options.connectState = FIRST_REPLY_THIRD;
            WOLFSSL_MSG("connect state: FIRST_REPLY_THIRD");
            FALL_THROUGH;

        case FIRST_REPLY_THIRD :
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: change cipher spec");
            ssl->options.connectState = FIRST_REPLY_FOURTH;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FOURTH");
            FALL_THROUGH;

        case FIRST_REPLY_FOURTH :
            if ( (ssl->error = SendFinished(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: finished");
            ssl->options.connectState = FINISHED_DONE;
            WOLFSSL_MSG("connect state: FINISHED_DONE");
            FALL_THROUGH;

#ifdef WOLFSSL_DTLS13
        case WAIT_FINISHED_ACK:
            ssl->options.connectState = FINISHED_DONE;
            FALL_THROUGH;
#endif /* WOLFSSL_DTLS13 */

        case FINISHED_DONE :
            /* get response */
            while (ssl->options.serverState < SERVER_FINISHED_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }

            ssl->options.connectState = SECOND_REPLY_DONE;
            WOLFSSL_MSG("connect state: SECOND_REPLY_DONE");
            FALL_THROUGH;

        case SECOND_REPLY_DONE:
        #ifndef NO_HANDSHAKE_DONE_CB
            if (ssl->hsDoneCb) {
                int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
                if (cbret < 0) {
                    ssl->error = cbret;
                    WOLFSSL_MSG("HandShake Done Cb don't continue error");
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        #endif /* NO_HANDSHAKE_DONE_CB */

            if (!ssl->options.dtls) {
                if (!ssl->options.keepResources) {
                    FreeHandshakeResources(ssl);
                }
            }
        #ifdef WOLFSSL_DTLS
            else {
                ssl->options.dtlsHsRetain = 1;
            }
        #endif /* WOLFSSL_DTLS */

        #if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_SECURE_RENEGOTIATION)
            /* This may be necessary in async so that we don't try to
             * renegotiate again */
            if (ssl->secure_renegotiation &&
                    ssl->secure_renegotiation->startScr) {
                ssl->secure_renegotiation->startScr = 0;
            }
        #endif /* WOLFSSL_ASYNC_CRYPT && HAVE_SECURE_RENEGOTIATION */
        #if defined(WOLFSSL_ASYNC_IO) && !defined(WOLFSSL_ASYNC_CRYPT)
            /* Free the remaining async context if not using it for crypto */
            FreeAsyncCtx(ssl, 1);
        #endif

            ssl->error = 0; /* clear the error */

            WOLFSSL_LEAVE("wolfSSL_connect", WOLFSSL_SUCCESS);
            return WOLFSSL_SUCCESS;
    #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS */

        default:
            WOLFSSL_MSG("Unknown connect state ERROR");
            return WOLFSSL_FATAL_ERROR; /* unknown connect state */
        }
    #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS || !WOLFSSL_TLS13 */
    }

#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS */
/* end client only parts */

/* server only parts */
#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)

    #if defined(OPENSSL_EXTRA) && !defined(NO_OLD_TLS)
    WOLFSSL_METHOD* wolfSSLv2_server_method(void)
    {
        WOLFSSL_STUB("wolfSSLv2_server_method");
        return 0;
    }
    #endif

    #if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
    WOLFSSL_METHOD* wolfSSLv3_server_method(void)
    {
        return wolfSSLv3_server_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv3_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("wolfSSLv3_server_method_ex");
        if (method) {
            InitSSL_Method(method, MakeSSLv3());
            method->side = WOLFSSL_SERVER_END;
        }
        return method;
    }
    #endif /* WOLFSSL_ALLOW_SSLV3 && !NO_OLD_TLS */

    WOLFSSL_METHOD* wolfSSLv23_server_method(void)
    {
        return wolfSSLv23_server_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfSSLv23_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("wolfSSLv23_server_method_ex");
        if (method) {
    #if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || \
        defined(WOLFSSL_SHA512)
        #ifdef WOLFSSL_TLS13
            InitSSL_Method(method, MakeTLSv1_3());
        #elif !defined(WOLFSSL_NO_TLS12)
            InitSSL_Method(method, MakeTLSv1_2());
        #elif !defined(NO_OLD_TLS)
            InitSSL_Method(method, MakeTLSv1_1());
        #endif
    #else
        #ifndef NO_OLD_TLS
            InitSSL_Method(method, MakeTLSv1_1());
        #else
            #error Must have SHA256, SHA384 or SHA512 enabled for TLS 1.2
        #endif
    #endif
    #if !defined(NO_OLD_TLS) || defined(WOLFSSL_TLS13)
            method->downgrade = 1;
    #endif
            method->side      = WOLFSSL_SERVER_END;
        }
        return method;
    }


    WOLFSSL_ABI
    int wolfSSL_accept(WOLFSSL* ssl)
    {
#if !(defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
    defined(WOLFSSL_TLS13))
        word16 havePSK = 0;
        word16 haveAnon = 0;
        word16 haveMcast = 0;
#endif
        int ret = 0;

        (void)ret;

        if (ssl == NULL)
            return WOLFSSL_FATAL_ERROR;

    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE)
        if (ssl->options.side == WOLFSSL_NEITHER_END) {
            WOLFSSL_MSG("Setting WOLFSSL_SSL to be server side");
            ssl->error = InitSSL_Side(ssl, WOLFSSL_SERVER_END);
            if (ssl->error != WOLFSSL_SUCCESS) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->error = 0; /* expected to be zero here */
        }
    #endif /* OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE */

#if defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && defined(WOLFSSL_TLS13)
        return wolfSSL_accept_TLSv13(ssl);
#else
    #ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3)
            return wolfSSL_accept_TLSv13(ssl);
    #endif
        WOLFSSL_ENTER("wolfSSL_accept");

        /* make sure this wolfSSL object has arrays and rng setup. Protects
         * case where the WOLFSSL object is reused via wolfSSL_clear() */
        if ((ret = ReinitSSL(ssl, ssl->ctx, 0)) != 0) {
            return ret;
        }

#ifdef WOLFSSL_WOLFSENTRY_HOOKS
        if ((ssl->AcceptFilter != NULL) &&
            ((ssl->options.acceptState == ACCEPT_BEGIN)
#ifdef HAVE_SECURE_RENEGOTIATION
             || (ssl->options.acceptState == ACCEPT_BEGIN_RENEG)
#endif
                ))
        {
            wolfSSL_netfilter_decision_t res;
            if ((ssl->AcceptFilter(ssl, ssl->AcceptFilter_arg, &res) ==
                 WOLFSSL_SUCCESS) &&
                (res == WOLFSSL_NETFILTER_REJECT)) {
                ssl->error = SOCKET_FILTERED_E;
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }
#endif /* WOLFSSL_WOLFSENTRY_HOOKS */

        #ifdef HAVE_ERRNO_H
            errno = 0;
        #endif

        #ifndef NO_PSK
            havePSK = ssl->options.havePSK;
        #endif
        (void)havePSK;

        #ifdef HAVE_ANON
            haveAnon = ssl->options.useAnon;
        #endif
        (void)haveAnon;

        #ifdef WOLFSSL_MULTICAST
            haveMcast = ssl->options.haveMcast;
        #endif
        (void)haveMcast;

        if (ssl->options.side != WOLFSSL_SERVER_END) {
            ssl->error = SIDE_ERROR;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

    #ifndef NO_CERTS
        /* in case used set_accept_state after init */
        if (!havePSK && !haveAnon && !haveMcast) {
        #ifdef OPENSSL_EXTRA
            if (ssl->ctx->certSetupCb != NULL) {
                WOLFSSL_MSG("CertSetupCb set. server cert and "
                            "key not checked");
            }
            else
        #endif
            {
                if (!ssl->buffers.certificate ||
                    !ssl->buffers.certificate->buffer) {

                    WOLFSSL_MSG("accept error: server cert required");
                    ssl->error = NO_PRIVATE_KEY;
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }

                if (!ssl->buffers.key || !ssl->buffers.key->buffer) {
                    /* allow no private key if using existing key */
                #ifdef WOLF_PRIVATE_KEY_ID
                    if (ssl->devId != INVALID_DEVID
                    #ifdef HAVE_PK_CALLBACKS
                        || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
                    #endif
                    ) {
                        WOLFSSL_MSG("Allowing no server private key "
                                    "(external)");
                    }
                    else
                #endif
                    {
                        WOLFSSL_MSG("accept error: server key required");
                        ssl->error = NO_PRIVATE_KEY;
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
            }
        }
    #endif

    #ifdef WOLFSSL_DTLS
        if (ssl->version.major == DTLS_MAJOR) {
            ssl->options.dtls   = 1;
            ssl->options.tls    = 1;
            ssl->options.tls1_1 = 1;
            if (!IsDtlsNotSctpMode(ssl) || !IsDtlsNotSrtpMode(ssl) ||
                    IsSCR(ssl))
                ssl->options.dtlsStateful = 1;
        }
    #endif

        if (ssl->buffers.outputBuffer.length > 0
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* do not send buffered or advance state if last error was an
                async pending operation */
            && ssl->error != WC_NO_ERR_TRACE(WC_PENDING_E)
        #endif
        ) {
            ret = SendBuffered(ssl);
            if (ret == 0) {
                /* fragOffset is non-zero when sending fragments. On the last
                 * fragment, fragOffset is zero again, and the state can be
                 * advanced. */
                if (ssl->fragOffset == 0 && !ssl->options.buildingMsg) {
                    if (ssl->options.acceptState == ACCEPT_FIRST_REPLY_DONE ||
                        ssl->options.acceptState == SERVER_HELLO_SENT ||
                        ssl->options.acceptState == CERT_SENT ||
                        ssl->options.acceptState == CERT_STATUS_SENT ||
                        ssl->options.acceptState == KEY_EXCHANGE_SENT ||
                        ssl->options.acceptState == CERT_REQ_SENT ||
                        ssl->options.acceptState == ACCEPT_SECOND_REPLY_DONE ||
                        ssl->options.acceptState == TICKET_SENT ||
                        ssl->options.acceptState == CHANGE_CIPHER_SENT) {
                        ssl->options.acceptState++;
                        WOLFSSL_MSG("accept state: Advanced from last "
                                    "buffered fragment send");
                    #ifdef WOLFSSL_ASYNC_IO
                        /* Cleanup async */
                        FreeAsyncCtx(ssl, 0);
                    #endif
                    }
                }
                else {
                    WOLFSSL_MSG("accept state: "
                                "Not advanced, more fragments to send");
                }
            }
            else {
                ssl->error = ret;
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls)
                ssl->dtls13SendingAckOrRtx = 0;
#endif /* WOLFSSL_DTLS13 */
        }

        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

        switch (ssl->options.acceptState) {

        case ACCEPT_BEGIN :
#ifdef HAVE_SECURE_RENEGOTIATION
        case ACCEPT_BEGIN_RENEG:
#endif
            /* get response */
            while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
#ifdef WOLFSSL_TLS13
            ssl->options.acceptState = ACCEPT_CLIENT_HELLO_DONE;
            WOLFSSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");
            FALL_THROUGH;

        case ACCEPT_CLIENT_HELLO_DONE :
            if (ssl->options.tls1_3) {
                return wolfSSL_accept_TLSv13(ssl);
            }
#endif

            ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");
            FALL_THROUGH;

        case ACCEPT_FIRST_REPLY_DONE :
            if ( (ssl->error = SendServerHello(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.acceptState = SERVER_HELLO_SENT;
            WOLFSSL_MSG("accept state SERVER_HELLO_SENT");
            FALL_THROUGH;

        case SERVER_HELLO_SENT :
        #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3) {
                return wolfSSL_accept_TLSv13(ssl);
            }
        #endif
            #ifndef NO_CERTS
                if (!ssl->options.resuming)
                    if ( (ssl->error = SendCertificate(ssl)) != 0) {
                    #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                        ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                    #endif
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
            #endif
            ssl->options.acceptState = CERT_SENT;
            WOLFSSL_MSG("accept state CERT_SENT");
            FALL_THROUGH;

        case CERT_SENT :
            #ifndef NO_CERTS
            if (!ssl->options.resuming)
                if ( (ssl->error = SendCertificateStatus(ssl)) != 0) {
                #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                    ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                #endif
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            #endif
            ssl->options.acceptState = CERT_STATUS_SENT;
            WOLFSSL_MSG("accept state CERT_STATUS_SENT");
            FALL_THROUGH;

        case CERT_STATUS_SENT :
        #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3) {
                return wolfSSL_accept_TLSv13(ssl);
            }
        #endif
            if (!ssl->options.resuming)
                if ( (ssl->error = SendServerKeyExchange(ssl)) != 0) {
                #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                    ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                #endif
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            ssl->options.acceptState = KEY_EXCHANGE_SENT;
            WOLFSSL_MSG("accept state KEY_EXCHANGE_SENT");
            FALL_THROUGH;

        case KEY_EXCHANGE_SENT :
            #ifndef NO_CERTS
                if (!ssl->options.resuming) {
                    if (ssl->options.verifyPeer) {
                        if ( (ssl->error = SendCertificateRequest(ssl)) != 0) {
                        #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                            /* See if an alert was sent. */
                            ProcessReplyEx(ssl, 1);
                        #endif
                            WOLFSSL_ERROR(ssl->error);
                            return WOLFSSL_FATAL_ERROR;
                        }
                    }
                    else {
                        /* SERVER: Peer auth good if not verifying client. */
                        ssl->options.peerAuthGood = 1;
                    }
                }
            #endif
            ssl->options.acceptState = CERT_REQ_SENT;
            WOLFSSL_MSG("accept state CERT_REQ_SENT");
            FALL_THROUGH;

        case CERT_REQ_SENT :
            if (!ssl->options.resuming)
                if ( (ssl->error = SendServerHelloDone(ssl)) != 0) {
                #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                    ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                #endif
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            ssl->options.acceptState = SERVER_HELLO_DONE;
            WOLFSSL_MSG("accept state SERVER_HELLO_DONE");
            FALL_THROUGH;

        case SERVER_HELLO_DONE :
            if (!ssl->options.resuming) {
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
            }
            ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
            WOLFSSL_MSG("accept state  ACCEPT_SECOND_REPLY_DONE");
            FALL_THROUGH;

        case ACCEPT_SECOND_REPLY_DONE :
        #ifndef NO_CERTS
            /* SERVER: When not resuming and verifying peer but no certificate
             * received and not failing when not received then peer auth good.
             */
            if (!ssl->options.resuming && ssl->options.verifyPeer &&
                !ssl->options.havePeerCert && !ssl->options.failNoCert) {
                ssl->options.peerAuthGood = 1;
            }
        #endif /* !NO_CERTS  */
        #ifdef WOLFSSL_NO_CLIENT_AUTH
            if (!ssl->options.resuming) {
                ssl->options.peerAuthGood = 1;
            }
        #endif

#ifdef HAVE_SESSION_TICKET
            if (ssl->options.createTicket && !ssl->options.noTicketTls12) {
                if ( (ssl->error = SendTicket(ssl)) != 0) {
                #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                    ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                #endif
                    WOLFSSL_MSG("Thought we need ticket but failed");
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
#endif /* HAVE_SESSION_TICKET */
            ssl->options.acceptState = TICKET_SENT;
            WOLFSSL_MSG("accept state  TICKET_SENT");
            FALL_THROUGH;

        case TICKET_SENT:
            /* SERVER: Fail-safe for CLient Authentication. */
            if (!ssl->options.peerAuthGood) {
                WOLFSSL_MSG("Client authentication did not happen");
                return WOLFSSL_FATAL_ERROR;
            }

            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.acceptState = CHANGE_CIPHER_SENT;
            WOLFSSL_MSG("accept state  CHANGE_CIPHER_SENT");
            FALL_THROUGH;

        case CHANGE_CIPHER_SENT :
            if ( (ssl->error = SendFinished(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }

            ssl->options.acceptState = ACCEPT_FINISHED_DONE;
            WOLFSSL_MSG("accept state ACCEPT_FINISHED_DONE");
            FALL_THROUGH;

        case ACCEPT_FINISHED_DONE :
            if (ssl->options.resuming) {
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE) {
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                }
            }
            ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");
            FALL_THROUGH;

        case ACCEPT_THIRD_REPLY_DONE :
#ifndef NO_HANDSHAKE_DONE_CB
            if (ssl->hsDoneCb) {
                int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
                if (cbret < 0) {
                    ssl->error = cbret;
                    WOLFSSL_MSG("HandShake Done Cb don't continue error");
                    return WOLFSSL_FATAL_ERROR;
                }
            }
#endif /* NO_HANDSHAKE_DONE_CB */

            if (!ssl->options.dtls) {
                if (!ssl->options.keepResources) {
                    FreeHandshakeResources(ssl);
                }
            }
#ifdef WOLFSSL_DTLS
            else {
                ssl->options.dtlsHsRetain = 1;
            }
#endif /* WOLFSSL_DTLS */

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_SECURE_RENEGOTIATION)
            /* This may be necessary in async so that we don't try to
             * renegotiate again */
            if (ssl->secure_renegotiation &&
                    ssl->secure_renegotiation->startScr) {
                ssl->secure_renegotiation->startScr = 0;
            }
#endif /* WOLFSSL_ASYNC_CRYPT && HAVE_SECURE_RENEGOTIATION */
#if defined(WOLFSSL_ASYNC_IO) && !defined(WOLFSSL_ASYNC_CRYPT)
            /* Free the remaining async context if not using it for crypto */
            FreeAsyncCtx(ssl, 1);
#endif

#if defined(WOLFSSL_SESSION_EXPORT) && defined(WOLFSSL_DTLS)
            if (ssl->dtls_export) {
                if ((ssl->error = wolfSSL_send_session(ssl)) != 0) {
                    WOLFSSL_MSG("Export DTLS session error");
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
#endif
            ssl->error = 0; /* clear the error */

            WOLFSSL_LEAVE("wolfSSL_accept", WOLFSSL_SUCCESS);
            return WOLFSSL_SUCCESS;

        default:
            WOLFSSL_MSG("Unknown accept state ERROR");
            return WOLFSSL_FATAL_ERROR;
        }
#endif /* !WOLFSSL_NO_TLS12 */
    }

#endif /* !NO_WOLFSSL_SERVER && !NO_TLS */
/* end server only parts */


#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
struct chGoodDisableReadCbCtx {
    ClientHelloGoodCb userCb;
    void*             userCtx;
};

static int chGoodDisableReadCB(WOLFSSL* ssl, void* ctx)
{
    struct chGoodDisableReadCbCtx* cb = (struct chGoodDisableReadCbCtx*)ctx;
    int ret = 0;
    if (cb->userCb != NULL)
        ret = cb->userCb(ssl, cb->userCtx);
    if (ret >= 0)
        wolfSSL_SSLDisableRead(ssl);
    return ret;
}

/**
 * Statelessly listen for a connection
 * @param ssl The ssl object to use for listening to connections
 * @return WOLFSSL_SUCCESS - ClientHello containing a valid cookie was received
 *                           The connection can be continued with wolfSSL_accept
 *         WOLFSSL_FAILURE - The I/O layer returned WANT_READ. This is either
 *                           because there is no data to read and we are using
 *                           non-blocking sockets or we sent a cookie request
 *                           and we are waiting for a reply. The user should
 *                           call wolfDTLS_accept_stateless again after data
 *                           becomes available in the I/O layer.
 *         WOLFSSL_FATAL_ERROR - A fatal error occurred. The ssl object should
 *                           be free'd and allocated again to continue.
 */
int wolfDTLS_accept_stateless(WOLFSSL* ssl)
{
    byte disableRead;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    struct chGoodDisableReadCbCtx cb;

    WOLFSSL_ENTER("wolfDTLS_SetChGoodCb");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    /* Save this to restore it later */
    disableRead = (byte)ssl->options.disableRead;
    cb.userCb = ssl->chGoodCb;
    cb.userCtx = ssl->chGoodCtx;

    /* Register our own callback so that we can disable reading */
    if (wolfDTLS_SetChGoodCb(ssl, chGoodDisableReadCB, &cb) != WOLFSSL_SUCCESS)
        return WOLFSSL_FATAL_ERROR;

    ret = wolfSSL_accept(ssl);
    /* restore user options */
    ssl->options.disableRead = disableRead;
    (void)wolfDTLS_SetChGoodCb(ssl, cb.userCb, cb.userCtx);
    if (ret == WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("should not happen. maybe the user called "
                    "wolfDTLS_accept_stateless instead of wolfSSL_accept");
    }
    else if (ssl->error == WC_NO_ERR_TRACE(WANT_READ)) {
        if (ssl->options.dtlsStateful)
            ret = WOLFSSL_SUCCESS;
        else
            ret = WOLFSSL_FAILURE;
    }
    else {
        ret = WOLFSSL_FATAL_ERROR;
    }
    return ret;
}

int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx)
{
    WOLFSSL_ENTER("wolfDTLS_SetChGoodCb");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->chGoodCb  = cb;
    ssl->chGoodCtx = user_ctx;

    return WOLFSSL_SUCCESS;
}
#endif

#ifndef NO_HANDSHAKE_DONE_CB

int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetHsDoneCb");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->hsDoneCb  = cb;
    ssl->hsDoneCtx = user_ctx;

    return WOLFSSL_SUCCESS;
}

#endif /* NO_HANDSHAKE_DONE_CB */

WOLFSSL_ABI
int wolfSSL_Cleanup(void)
{
    int ret = WOLFSSL_SUCCESS; /* Only the first error will be returned */
    int release = 0;
#if !defined(NO_SESSION_CACHE)
    int i;
    int j;
#endif

    WOLFSSL_ENTER("wolfSSL_Cleanup");

#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (inits_count_mutex_valid == 1) {
#endif
        if (wc_LockMutex(&inits_count_mutex) != 0) {
            WOLFSSL_MSG("Bad Lock Mutex count");
            return BAD_MUTEX_E;
        }
#ifndef WOLFSSL_MUTEX_INITIALIZER
    }
#endif

    if (initRefCount > 0) {
        --initRefCount;
        if (initRefCount == 0)
            release = 1;
    }

#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (inits_count_mutex_valid == 1) {
#endif
        wc_UnLockMutex(&inits_count_mutex);
#ifndef WOLFSSL_MUTEX_INITIALIZER
    }
#endif

    if (!release)
        return ret;

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    wolfSSL_crypto_policy_disable();
#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

#ifdef OPENSSL_EXTRA
    wolfSSL_BN_free_one();
#endif

#ifndef NO_SESSION_CACHE
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
    for (i = 0; i < SESSION_ROWS; ++i) {
        if ((SessionCache[i].lock_valid == 1) &&
            (wc_FreeRwLock(&SessionCache[i].row_lock) != 0)) {
            if (ret == WOLFSSL_SUCCESS)
                ret = BAD_MUTEX_E;
        }
        SessionCache[i].lock_valid = 0;
    }
    #else
    if ((session_lock_valid == 1) && (wc_FreeRwLock(&session_lock) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    session_lock_valid = 0;
    #endif
    for (i = 0; i < SESSION_ROWS; i++) {
        for (j = 0; j < SESSIONS_PER_ROW; j++) {
    #ifdef SESSION_CACHE_DYNAMIC_MEM
            if (SessionCache[i].Sessions[j]) {
                EvictSessionFromCache(SessionCache[i].Sessions[j]);
                XFREE(SessionCache[i].Sessions[j], SessionCache[i].heap,
                      DYNAMIC_TYPE_SESSION);
                SessionCache[i].Sessions[j] = NULL;
            }
    #else
            EvictSessionFromCache(&SessionCache[i].Sessions[j]);
    #endif
        }
    }
    #ifndef NO_CLIENT_CACHE
    #ifndef WOLFSSL_MUTEX_INITIALIZER
    if ((clisession_mutex_valid == 1) &&
        (wc_FreeMutex(&clisession_mutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    clisession_mutex_valid = 0;
    #endif
    #endif
#endif /* !NO_SESSION_CACHE */

#if !defined(WOLFSSL_MUTEX_INITIALIZER) && \
      !WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS
    if ((inits_count_mutex_valid == 1) &&
            (wc_FreeMutex(&inits_count_mutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    inits_count_mutex_valid = 0;
#endif

#ifdef OPENSSL_EXTRA
    wolfSSL_RAND_Cleanup();
#endif

    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
        if (ret == WOLFSSL_SUCCESS)
            ret = WC_CLEANUP_E;
    }

#if FIPS_VERSION_GE(5,1)
    if (wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL) < 0) {
        if (ret == WOLFSSL_SUCCESS)
            ret = WC_CLEANUP_E;
    }
#endif

#ifdef HAVE_GLOBAL_RNG
#ifndef WOLFSSL_MUTEX_INITIALIZER
    if ((globalRNGMutex_valid == 1) && (wc_FreeMutex(&globalRNGMutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    globalRNGMutex_valid = 0;
#endif /* !WOLFSSL_MUTEX_INITIALIZER */

    #if defined(OPENSSL_EXTRA) && defined(HAVE_HASHDRBG)
    wolfSSL_FIPS_drbg_free(gDrbgDefCtx);
    gDrbgDefCtx = NULL;
    #endif
#endif

#ifdef HAVE_EX_DATA_CRYPTO
    crypto_ex_cb_free(crypto_ex_cb_ctx_session);
    crypto_ex_cb_ctx_session = NULL;
#endif

#ifdef WOLFSSL_MEM_FAIL_COUNT
    wc_MemFailCount_Free();
#endif

    return ret;
}


/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
WOLFSSL_ABI
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn)
{
    WOLFSSL_ENTER("wolfSSL_check_domain_name");

    if (ssl == NULL || dn == NULL) {
        WOLFSSL_MSG("Bad function argument: NULL");
        return WOLFSSL_FAILURE;
    }

    if (ssl->buffers.domainName.buffer)
        XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    ssl->buffers.domainName.length = (word32)XSTRLEN(dn);
    ssl->buffers.domainName.buffer = (byte*)XMALLOC(
            ssl->buffers.domainName.length + 1, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    if (ssl->buffers.domainName.buffer) {
        unsigned char* domainName = ssl->buffers.domainName.buffer;
        XMEMCPY(domainName, dn, ssl->buffers.domainName.length);
        domainName[ssl->buffers.domainName.length] = '\0';
        return WOLFSSL_SUCCESS;
    }
    else {
        ssl->error = MEMORY_ERROR;
        return WOLFSSL_FAILURE;
    }
}

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
const char *wolfSSL_get0_peername(WOLFSSL *ssl) {
    if (ssl == NULL) {
        return NULL;
    }

    if (ssl->buffers.domainName.buffer)
        return (const char *)ssl->buffers.domainName.buffer;
    else if (ssl->session && ssl->session->peer)
        return ssl->session->peer->subjectCN;
    else if (ssl->peerCert.subjectCN[0])
        return ssl->peerCert.subjectCN;
    else {
        ssl->error = NO_PEER_CERT;
        return NULL;
    }
}

#endif /* SESSION_CERTS && OPENSSL_EXTRA */

/* turn on wolfSSL zlib compression
   returns WOLFSSL_SUCCESS for success, else error (not built in)
*/
int wolfSSL_set_compression(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_set_compression");
    (void)ssl;
#ifdef HAVE_LIBZ
    ssl->options.usingCompression = 1;
    return WOLFSSL_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}


#ifndef USE_WINDOWS_API
    #if !defined(NO_WRITEV) && !defined(NO_TLS)

        /* simulate writev semantics, doesn't actually do block at a time though
           because of SSL_write behavior and because front adds may be small */
        int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov, int iovcnt)
        {
        #ifdef WOLFSSL_SMALL_STACK
            byte   staticBuffer[1]; /* force heap usage */
        #else
            byte   staticBuffer[FILE_BUFFER_SIZE];
        #endif
            byte* myBuffer  = staticBuffer;
            int   dynamic   = 0;
            int   sending   = 0;
            int   idx       = 0;
            int   i;
            int   ret;

            WOLFSSL_ENTER("wolfSSL_writev");

            for (i = 0; i < iovcnt; i++)
                sending += (int)iov[i].iov_len;

            if (sending > (int)sizeof(staticBuffer)) {
                myBuffer = (byte*)XMALLOC((size_t)sending, ssl->heap,
                                                           DYNAMIC_TYPE_WRITEV);
                if (!myBuffer)
                    return MEMORY_ERROR;

                dynamic = 1;
            }

            for (i = 0; i < iovcnt; i++) {
                XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
                idx += (int)iov[i].iov_len;
            }

           /* myBuffer may not be initialized fully, but the span up to the
            * sending length will be.
            */
            PRAGMA_GCC_DIAG_PUSH
            PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
            ret = wolfSSL_write(ssl, myBuffer, sending);
            PRAGMA_GCC_DIAG_POP

            if (dynamic)
                XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);

            return ret;
        }
    #endif
#endif


#ifdef WOLFSSL_CALLBACKS

    typedef struct itimerval Itimerval;

    /* don't keep calling simple functions while setting up timer and signals
       if no inlining these are the next best */

    #define AddTimes(a, b, c)                       \
        do {                                        \
            (c).tv_sec  = (a).tv_sec + (b).tv_sec;  \
            (c).tv_usec = (a).tv_usec + (b).tv_usec;\
            if ((c).tv_usec >=  1000000) {          \
                (c).tv_sec++;                       \
                (c).tv_usec -= 1000000;             \
            }                                       \
        } while (0)


    #define SubtractTimes(a, b, c)                  \
        do {                                        \
            (c).tv_sec  = (a).tv_sec - (b).tv_sec;  \
            (c).tv_usec = (a).tv_usec - (b).tv_usec;\
            if ((c).tv_usec < 0) {                  \
                (c).tv_sec--;                       \
                (c).tv_usec += 1000000;             \
            }                                       \
        } while (0)

    #define CmpTimes(a, b, cmp)                     \
        (((a).tv_sec  ==  (b).tv_sec) ?             \
            ((a).tv_usec cmp (b).tv_usec) :         \
            ((a).tv_sec  cmp (b).tv_sec))           \


    /* do nothing handler */
    static void myHandler(int signo)
    {
        (void)signo;
        return;
    }


    static int wolfSSL_ex_wrapper(WOLFSSL* ssl, HandShakeCallBack hsCb,
                                 TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
    {
        int       ret        = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
        int       oldTimerOn = 0;   /* was timer already on */
        WOLFSSL_TIMEVAL startTime;
        WOLFSSL_TIMEVAL endTime;
        WOLFSSL_TIMEVAL totalTime;
        Itimerval myTimeout;
        Itimerval oldTimeout; /* if old timer adjust from total time to reset */
        struct sigaction act, oact;

        #define ERR_OUT(x) { ssl->hsInfoOn = 0; ssl->toInfoOn = 0; return x; }

        if (hsCb) {
            ssl->hsInfoOn = 1;
            InitHandShakeInfo(&ssl->handShakeInfo, ssl);
        }
        if (toCb) {
            ssl->toInfoOn = 1;
            InitTimeoutInfo(&ssl->timeoutInfo);

            if (gettimeofday(&startTime, 0) < 0)
                ERR_OUT(GETTIME_ERROR);

            /* use setitimer to simulate getitimer, init 0 myTimeout */
            myTimeout.it_interval.tv_sec  = 0;
            myTimeout.it_interval.tv_usec = 0;
            myTimeout.it_value.tv_sec     = 0;
            myTimeout.it_value.tv_usec    = 0;
            if (setitimer(ITIMER_REAL, &myTimeout, &oldTimeout) < 0)
                ERR_OUT(SETITIMER_ERROR);

            if (oldTimeout.it_value.tv_sec || oldTimeout.it_value.tv_usec) {
                oldTimerOn = 1;

                /* is old timer going to expire before ours */
                if (CmpTimes(oldTimeout.it_value, timeout, <)) {
                    timeout.tv_sec  = oldTimeout.it_value.tv_sec;
                    timeout.tv_usec = oldTimeout.it_value.tv_usec;
                }
            }
            myTimeout.it_value.tv_sec  = timeout.tv_sec;
            myTimeout.it_value.tv_usec = timeout.tv_usec;

            /* set up signal handler, don't restart socket send/recv */
            act.sa_handler = myHandler;
            sigemptyset(&act.sa_mask);
            act.sa_flags = 0;
#ifdef SA_INTERRUPT
            act.sa_flags |= SA_INTERRUPT;
#endif
            if (sigaction(SIGALRM, &act, &oact) < 0)
                ERR_OUT(SIGACT_ERROR);

            if (setitimer(ITIMER_REAL, &myTimeout, 0) < 0)
                ERR_OUT(SETITIMER_ERROR);
        }

        /* do main work */
#ifndef NO_WOLFSSL_CLIENT
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            ret = wolfSSL_connect(ssl);
#endif
#ifndef NO_WOLFSSL_SERVER
        if (ssl->options.side == WOLFSSL_SERVER_END)
            ret = wolfSSL_accept(ssl);
#endif

        /* do callbacks */
        if (toCb) {
            if (oldTimerOn) {
                if (gettimeofday(&endTime, 0) < 0)
                    ERR_OUT(SYSLIB_FAILED_E);
                SubtractTimes(endTime, startTime, totalTime);
                /* adjust old timer for elapsed time */
                if (CmpTimes(totalTime, oldTimeout.it_value, <))
                    SubtractTimes(oldTimeout.it_value, totalTime,
                                  oldTimeout.it_value);
                else {
                    /* reset value to interval, may be off */
                    oldTimeout.it_value.tv_sec = oldTimeout.it_interval.tv_sec;
                    oldTimeout.it_value.tv_usec =oldTimeout.it_interval.tv_usec;
                }
                /* keep iter the same whether there or not */
            }
            /* restore old handler */
            if (sigaction(SIGALRM, &oact, 0) < 0)
                ret = SIGACT_ERROR;    /* more pressing error, stomp */
            else
                /* use old settings which may turn off (expired or not there) */
                if (setitimer(ITIMER_REAL, &oldTimeout, 0) < 0)
                    ret = SETITIMER_ERROR;

            /* if we had a timeout call callback */
            if (ssl->timeoutInfo.timeoutName[0]) {
                ssl->timeoutInfo.timeoutValue.tv_sec  = timeout.tv_sec;
                ssl->timeoutInfo.timeoutValue.tv_usec = timeout.tv_usec;
                (toCb)(&ssl->timeoutInfo);
            }
            ssl->toInfoOn = 0;
        }

        /* clean up buffers allocated by AddPacketInfo */
        FreeTimeoutInfo(&ssl->timeoutInfo, ssl->heap);

        if (hsCb) {
            FinishHandShakeInfo(&ssl->handShakeInfo);
            (hsCb)(&ssl->handShakeInfo);
            ssl->hsInfoOn = 0;
        }
        return ret;
    }


#ifndef NO_WOLFSSL_CLIENT

    int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                          TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
    {
        WOLFSSL_ENTER("wolfSSL_connect_ex");
        return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
    }

#endif


#ifndef NO_WOLFSSL_SERVER

    int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                         TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout)
    {
        WOLFSSL_ENTER("wolfSSL_accept_ex");
        return wolfSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
    }

#endif

#endif /* WOLFSSL_CALLBACKS */


#ifndef NO_PSK

    void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                         wc_psk_client_callback cb)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_psk_client_callback");

        if (ctx == NULL)
            return;

        ctx->havePSK = 1;
        ctx->client_psk_cb = cb;
    }

    void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,wc_psk_client_callback cb)
    {
        byte haveRSA = 1;
        int  keySz   = 0;

        WOLFSSL_ENTER("wolfSSL_set_psk_client_callback");

        if (ssl == NULL)
            return;

        ssl->options.havePSK = 1;
        ssl->options.client_psk_cb = cb;

        #ifdef NO_RSA
            haveRSA = 0;
        #endif
        #ifndef NO_CERTS
            keySz = ssl->buffers.keySz;
        #endif
        if (AllocateSuites(ssl) != 0)
            return;
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, TRUE,
                   ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                   ssl->options.useAnon, TRUE, TRUE, TRUE, TRUE, ssl->options.side);
    }
    #ifdef OPENSSL_EXTRA
    /**
     * set call back function for psk session use
     * @param ssl  a pointer to WOLFSSL structure
     * @param cb   a function pointer to wc_psk_use_session_cb
     * @return none
     */
    void wolfSSL_set_psk_use_session_callback(WOLFSSL* ssl,
                                                wc_psk_use_session_cb_func cb)
    {
        WOLFSSL_ENTER("wolfSSL_set_psk_use_session_callback");

        if (ssl != NULL) {
            ssl->options.havePSK = 1;
            ssl->options.session_psk_cb = cb;
        }

        WOLFSSL_LEAVE("wolfSSL_set_psk_use_session_callback", WOLFSSL_SUCCESS);
    }
    #endif

    void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx,
                                         wc_psk_server_callback cb)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_psk_server_callback");
        if (ctx == NULL)
            return;
        ctx->havePSK = 1;
        ctx->server_psk_cb = cb;
    }

    void wolfSSL_set_psk_server_callback(WOLFSSL* ssl,wc_psk_server_callback cb)
    {
        byte haveRSA = 1;
        int  keySz   = 0;

        WOLFSSL_ENTER("wolfSSL_set_psk_server_callback");
        if (ssl == NULL)
            return;

        ssl->options.havePSK = 1;
        ssl->options.server_psk_cb = cb;

        #ifdef NO_RSA
            haveRSA = 0;
        #endif
        #ifndef NO_CERTS
            keySz = ssl->buffers.keySz;
        #endif
        if (AllocateSuites(ssl) != 0)
            return;
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, TRUE,
                   ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                   ssl->options.useAnon, TRUE, TRUE, TRUE, TRUE, ssl->options.side);
    }

    const char* wolfSSL_get_psk_identity_hint(const WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_get_psk_identity_hint");

        if (ssl == NULL || ssl->arrays == NULL)
            return NULL;

        return ssl->arrays->server_hint;
    }


    const char* wolfSSL_get_psk_identity(const WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_get_psk_identity");

        if (ssl == NULL || ssl->arrays == NULL)
            return NULL;

        return ssl->arrays->client_identity;
    }

    int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_use_psk_identity_hint");
        if (hint == 0)
            ctx->server_hint[0] = '\0';
        else {
            /* Qt does not call CTX_set_*_psk_callbacks where havePSK is set */
            #ifdef WOLFSSL_QT
            ctx->havePSK=1;
            #endif
            XSTRNCPY(ctx->server_hint, hint, MAX_PSK_ID_LEN);
            ctx->server_hint[MAX_PSK_ID_LEN] = '\0'; /* null term */
        }
        return WOLFSSL_SUCCESS;
    }

    int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint)
    {
        WOLFSSL_ENTER("wolfSSL_use_psk_identity_hint");

        if (ssl == NULL || ssl->arrays == NULL)
            return WOLFSSL_FAILURE;

        if (hint == 0)
            ssl->arrays->server_hint[0] = 0;
        else {
            XSTRNCPY(ssl->arrays->server_hint, hint,
                                            sizeof(ssl->arrays->server_hint)-1);
            ssl->arrays->server_hint[sizeof(ssl->arrays->server_hint)-1] = '\0';
        }
        return WOLFSSL_SUCCESS;
    }

    void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl)
    {
        return ssl ? ssl->options.psk_ctx : NULL;
    }
    void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx)
    {
        return ctx ? ctx->psk_ctx : NULL;
    }
    int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx)
    {
        if (ssl == NULL)
            return WOLFSSL_FAILURE;
        ssl->options.psk_ctx = psk_ctx;
        return WOLFSSL_SUCCESS;
    }
    int wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx)
    {
        if (ctx == NULL)
            return WOLFSSL_FAILURE;
        ctx->psk_ctx = psk_ctx;
        return WOLFSSL_SUCCESS;
    }
#endif /* NO_PSK */


#ifdef HAVE_ANON

    int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_allow_anon_cipher");

        if (ctx == NULL)
            return WOLFSSL_FAILURE;

        ctx->useAnon = 1;

        return WOLFSSL_SUCCESS;
    }

#endif /* HAVE_ANON */

#ifndef NO_CERTS

    /* unload any certs or keys that SSL owns, leave CTX as is
       WOLFSSL_SUCCESS on ok */
    int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl)
    {
        if (ssl == NULL) {
            WOLFSSL_MSG("Null function arg");
            return BAD_FUNC_ARG;
        }

        if (ssl->buffers.weOwnCert && !ssl->keepCert) {
            WOLFSSL_MSG("Unloading cert");
            FreeDer(&ssl->buffers.certificate);
            #ifdef KEEP_OUR_CERT
            wolfSSL_X509_free(ssl->ourCert);
            ssl->ourCert = NULL;
            #endif
            ssl->buffers.weOwnCert = 0;
        }

        if (ssl->buffers.weOwnCertChain) {
            WOLFSSL_MSG("Unloading cert chain");
            FreeDer(&ssl->buffers.certChain);
            ssl->buffers.weOwnCertChain = 0;
        }

        if (ssl->buffers.weOwnKey) {
            WOLFSSL_MSG("Unloading key");
            ForceZero(ssl->buffers.key->buffer, ssl->buffers.key->length);
            FreeDer(&ssl->buffers.key);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.keyMask);
        #endif
            ssl->buffers.weOwnKey = 0;
        }

#ifdef WOLFSSL_DUAL_ALG_CERTS
        if (ssl->buffers.weOwnAltKey) {
            WOLFSSL_MSG("Unloading alt key");
            ForceZero(ssl->buffers.altKey->buffer, ssl->buffers.altKey->length);
            FreeDer(&ssl->buffers.altKey);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.altKeyMask);
        #endif
            ssl->buffers.weOwnAltKey = 0;
        }
#endif /* WOLFSSL_DUAL_ALG_CERTS */

        return WOLFSSL_SUCCESS;
    }


    int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_UnloadCAs");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnloadCAs(ctx->cm);
    }

    int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx)
    {
        int ret;

        WOLFSSL_ENTER("wolfSSL_CTX_UnloadIntermediateCerts");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        ret = wolfSSL_RefWithMutexLock(&ctx->ref);
        if (ret < 0)
            return ret;

        if (ctx->ref.count > 1) {
            WOLFSSL_MSG("ctx object must have a ref count of 1 before "
                        "unloading intermediate certs");
            ret = BAD_STATE_E;
        }
        else {
            ret = wolfSSL_CertManagerUnloadIntermediateCerts(ctx->cm);
        }

        if (wolfSSL_RefWithMutexUnlock(&ctx->ref) != 0)
            WOLFSSL_MSG("Failed to unlock mutex!");

        return ret;
    }


#ifdef WOLFSSL_TRUST_PEER_CERT
    int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnload_trust_peers(ctx->cm);
    }

#ifdef WOLFSSL_LOCAL_X509_STORE
    int wolfSSL_Unload_trust_peers(WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

        if (ssl == NULL)
            return BAD_FUNC_ARG;

        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerUnload_trust_peers(SSL_CM(ssl));
    }
#endif /* WOLFSSL_LOCAL_X509_STORE */
#endif /* WOLFSSL_TRUST_PEER_CERT */
/* old NO_FILESYSTEM end */
#endif /* !NO_CERTS */


#ifdef OPENSSL_EXTRA

    int wolfSSL_add_all_algorithms(void)
    {
        WOLFSSL_ENTER("wolfSSL_add_all_algorithms");
        if (initRefCount != 0 || wolfSSL_Init() == WOLFSSL_SUCCESS)
            return WOLFSSL_SUCCESS;
        else
            return WOLFSSL_FATAL_ERROR;
    }

    int wolfSSL_OpenSSL_add_all_algorithms_noconf(void)
    {
        WOLFSSL_ENTER("wolfSSL_OpenSSL_add_all_algorithms_noconf");

        if  (wolfSSL_add_all_algorithms() ==
             WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR))
        {
            return WOLFSSL_FATAL_ERROR;
        }

        return  WOLFSSL_SUCCESS;
    }

    int wolfSSL_OpenSSL_add_all_algorithms_conf(void)
    {
        WOLFSSL_ENTER("wolfSSL_OpenSSL_add_all_algorithms_conf");
        /* This function is currently the same as
        wolfSSL_OpenSSL_add_all_algorithms_noconf since we do not employ
        the use of a wolfssl.cnf type configuration file and is only used for
        OpenSSL compatibility. */

        if (wolfSSL_add_all_algorithms() ==
            WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR))
        {
            return WOLFSSL_FATAL_ERROR;
        }
        return WOLFSSL_SUCCESS;
    }

#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(WOLFSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX* ctx, int mode)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_quiet_shutdown");
        if (mode)
            ctx->quietShutdown = 1;
    }


    void wolfSSL_set_quiet_shutdown(WOLFSSL* ssl, int mode)
    {
        WOLFSSL_ENTER("wolfSSL_set_quiet_shutdown");
        if (mode)
            ssl->options.quietShutdown = 1;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL ||
          WOLFSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA
#ifndef NO_BIO
    static void ssl_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr, int flags)
    {
        WOLFSSL_ENTER("wolfSSL_set_bio");

        if (ssl == NULL) {
            WOLFSSL_MSG("Bad argument, ssl was NULL");
            return;
        }

        /* free any existing WOLFSSL_BIOs in use but don't free those in
         * a chain */
        if ((flags & WOLFSSL_BIO_FLAG_READ) && (ssl->biord != NULL)) {
            if ((flags & WOLFSSL_BIO_FLAG_WRITE) && (ssl->biord != ssl->biowr)) {
                if (ssl->biowr != NULL && ssl->biowr->prev != NULL)
                    wolfSSL_BIO_free(ssl->biowr);
                ssl->biowr = NULL;
            }
            if (ssl->biord->prev != NULL)
                wolfSSL_BIO_free(ssl->biord);
            ssl->biord = NULL;
        }
        else if ((flags & WOLFSSL_BIO_FLAG_WRITE) && (ssl->biowr != NULL)) {
            if (ssl->biowr->prev != NULL)
                wolfSSL_BIO_free(ssl->biowr);
            ssl->biowr = NULL;
        }

        /* set flag obviously */
        if (rd && !(rd->flags & WOLFSSL_BIO_FLAG_READ))
            rd->flags |= WOLFSSL_BIO_FLAG_READ;
        if (wr && !(wr->flags & WOLFSSL_BIO_FLAG_WRITE))
            wr->flags |= WOLFSSL_BIO_FLAG_WRITE;

        if (flags & WOLFSSL_BIO_FLAG_READ)
            ssl->biord = rd;
        if (flags & WOLFSSL_BIO_FLAG_WRITE)
            ssl->biowr = wr;

        /* set SSL to use BIO callbacks instead */
        if ((flags & WOLFSSL_BIO_FLAG_READ) &&
            (((ssl->cbioFlag & WOLFSSL_CBIO_RECV) == 0)))
        {
            ssl->CBIORecv = SslBioReceive;
        }
        if ((flags & WOLFSSL_BIO_FLAG_WRITE) &&
            (((ssl->cbioFlag & WOLFSSL_CBIO_SEND) == 0)))
        {
            ssl->CBIOSend = SslBioSend;
        }

        /* User programs should always retry reading from these BIOs */
        if (rd) {
            /* User writes to rd */
            wolfSSL_BIO_set_retry_write(rd);
        }
        if (wr) {
            /* User reads from wr */
            wolfSSL_BIO_set_retry_read(wr);
        }
    }

    void wolfSSL_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr)
    {
        ssl_set_bio(ssl, rd, wr, WOLFSSL_BIO_FLAG_READ | WOLFSSL_BIO_FLAG_WRITE);
    }

    void wolfSSL_set_rbio(WOLFSSL* ssl, WOLFSSL_BIO* rd)
    {
        ssl_set_bio(ssl, rd, NULL, WOLFSSL_BIO_FLAG_READ);
    }

    void wolfSSL_set_wbio(WOLFSSL* ssl, WOLFSSL_BIO* wr)
    {
        ssl_set_bio(ssl, NULL, wr, WOLFSSL_BIO_FLAG_WRITE);
    }

#endif /* !NO_BIO */
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA)
    void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                       WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_client_CA_list");
        if (ctx != NULL) {
            wolfSSL_sk_X509_NAME_pop_free(ctx->client_ca_names, NULL);
            ctx->client_ca_names = names;
        }
    }

    void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
                                       WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
    {
        WOLFSSL_ENTER("wolfSSL_set_client_CA_list");
        if (ssl != NULL) {
            if (ssl->client_ca_names != ssl->ctx->client_ca_names)
                wolfSSL_sk_X509_NAME_pop_free(ssl->client_ca_names, NULL);
            ssl->client_ca_names = names;
        }
    }

    #ifdef OPENSSL_EXTRA
    /* registers client cert callback, called during handshake if server
       requests client auth but user has not loaded client cert/key */
    void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_client_cert_cb");

        if (ctx != NULL) {
            ctx->CBClientCert = cb;
        }
    }

    void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
        CertSetupCallback cb, void *arg)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_cert_cb");
        if (ctx == NULL)
            return;

        ctx->certSetupCb = cb;
        ctx->certSetupCbArg = arg;
    }

    int wolfSSL_get_client_suites_sigalgs(const WOLFSSL* ssl,
            const byte** suites, word16* suiteSz,
            const byte** hashSigAlgo, word16* hashSigAlgoSz)
    {
        WOLFSSL_ENTER("wolfSSL_get_client_suites_sigalgs");

        if (suites != NULL)
            *suites = NULL;
        if (suiteSz != NULL)
            *suiteSz = 0;
        if (hashSigAlgo != NULL)
            *hashSigAlgo = NULL;
        if (hashSigAlgoSz != NULL)
            *hashSigAlgoSz = 0;

        if (ssl != NULL && ssl->clSuites != NULL) {
            if (suites != NULL && suiteSz != NULL) {
                *suites = ssl->clSuites->suites;
                *suiteSz = ssl->clSuites->suiteSz;
            }
            if (hashSigAlgo != NULL && hashSigAlgoSz != NULL) {
                *hashSigAlgo = ssl->clSuites->hashSigAlgo;
                *hashSigAlgoSz = ssl->clSuites->hashSigAlgoSz;
            }
            return WOLFSSL_SUCCESS;
        }
        return WOLFSSL_FAILURE;
    }

#ifndef NO_TLS
    WOLFSSL_CIPHERSUITE_INFO wolfSSL_get_ciphersuite_info(byte first,
            byte second)
    {
        WOLFSSL_CIPHERSUITE_INFO info;
        info.rsaAuth = (byte)(CipherRequires(first, second, REQUIRES_RSA) ||
                CipherRequires(first, second, REQUIRES_RSA_SIG));
        info.eccAuth = (byte)(CipherRequires(first, second, REQUIRES_ECC) ||
                /* Static ECC ciphers may require RSA for authentication */
                (CipherRequires(first, second, REQUIRES_ECC_STATIC) &&
                        !CipherRequires(first, second, REQUIRES_RSA_SIG)));
        info.eccStatic =
                (byte)CipherRequires(first, second, REQUIRES_ECC_STATIC);
        info.psk = (byte)CipherRequires(first, second, REQUIRES_PSK);
        return info;
    }
#endif

    /**
     * @param first First byte of the hash and signature algorithm
     * @param second Second byte of the hash and signature algorithm
     * @param hashAlgo The enum wc_HashType of the MAC algorithm
     * @param sigAlgo The enum Key_Sum of the authentication algorithm
     */
    int wolfSSL_get_sigalg_info(byte first, byte second,
            int* hashAlgo, int* sigAlgo)
    {
        byte input[2];
        byte hashType;
        byte sigType;

        if (hashAlgo == NULL || sigAlgo == NULL)
            return BAD_FUNC_ARG;

        input[0] = first;
        input[1] = second;
        DecodeSigAlg(input, &hashType, &sigType);

        /* cast so that compiler reminds us of unimplemented values */
        switch ((enum SignatureAlgorithm)sigType) {
        case anonymous_sa_algo:
            *sigAlgo = ANONk;
            break;
        case rsa_sa_algo:
            *sigAlgo = RSAk;
            break;
        case dsa_sa_algo:
            *sigAlgo = DSAk;
            break;
        case ecc_dsa_sa_algo:
            *sigAlgo = ECDSAk;
            break;
        case rsa_pss_sa_algo:
            *sigAlgo = RSAPSSk;
            break;
        case ed25519_sa_algo:
            *sigAlgo = ED25519k;
            break;
        case rsa_pss_pss_algo:
            *sigAlgo = RSAPSSk;
            break;
        case ed448_sa_algo:
            *sigAlgo = ED448k;
            break;
        case falcon_level1_sa_algo:
            *sigAlgo = FALCON_LEVEL1k;
            break;
        case falcon_level5_sa_algo:
            *sigAlgo = FALCON_LEVEL5k;
            break;
        case dilithium_level2_sa_algo:
            *sigAlgo = DILITHIUM_LEVEL2k;
            break;
        case dilithium_level3_sa_algo:
            *sigAlgo = DILITHIUM_LEVEL3k;
            break;
        case dilithium_level5_sa_algo:
            *sigAlgo = DILITHIUM_LEVEL5k;
            break;
        case sm2_sa_algo:
            *sigAlgo = SM2k;
            break;
        case invalid_sa_algo:
        default:
            *hashAlgo = WC_HASH_TYPE_NONE;
            *sigAlgo = 0;
            return BAD_FUNC_ARG;
        }

        /* cast so that compiler reminds us of unimplemented values */
        switch((enum wc_MACAlgorithm)hashType) {
        case no_mac:
        case rmd_mac: /* Don't have a RIPEMD type in wc_HashType */
            *hashAlgo = WC_HASH_TYPE_NONE;
            break;
        case md5_mac:
            *hashAlgo = WC_HASH_TYPE_MD5;
            break;
        case sha_mac:
            *hashAlgo = WC_HASH_TYPE_SHA;
            break;
        case sha224_mac:
            *hashAlgo = WC_HASH_TYPE_SHA224;
            break;
        case sha256_mac:
            *hashAlgo = WC_HASH_TYPE_SHA256;
            break;
        case sha384_mac:
            *hashAlgo = WC_HASH_TYPE_SHA384;
            break;
        case sha512_mac:
            *hashAlgo = WC_HASH_TYPE_SHA512;
            break;
        case blake2b_mac:
            *hashAlgo = WC_HASH_TYPE_BLAKE2B;
            break;
        case sm3_mac:
#ifdef WOLFSSL_SM3
            *hashAlgo = WC_HASH_TYPE_SM3;
#else
            *hashAlgo = WC_HASH_TYPE_NONE;
#endif
            break;
        default:
            *hashAlgo = WC_HASH_TYPE_NONE;
            *sigAlgo = 0;
            return BAD_FUNC_ARG;
        }
        return 0;
    }

    /**
     * Internal wrapper for calling certSetupCb
     * @param ssl The SSL/TLS Object
     * @return 0 on success
     */
    int CertSetupCbWrapper(WOLFSSL* ssl)
    {
        int ret = 0;
        if (ssl->ctx->certSetupCb != NULL) {
            WOLFSSL_MSG("Calling user cert setup callback");
            ret = ssl->ctx->certSetupCb(ssl, ssl->ctx->certSetupCbArg);
            if (ret == 1) {
                WOLFSSL_MSG("User cert callback returned success");
                ret = 0;
            }
            else if (ret == 0) {
                SendAlert(ssl, alert_fatal, internal_error);
                ret = CLIENT_CERT_CB_ERROR;
            }
            else if (ret < 0) {
                ret = WOLFSSL_ERROR_WANT_X509_LOOKUP;
            }
            else {
                WOLFSSL_MSG("Unexpected user callback return");
                ret = CLIENT_CERT_CB_ERROR;
            }
        }
        return ret;
    }
    #endif /* OPENSSL_EXTRA */

#endif /* OPENSSL_EXTRA || WOLFSSL_EXTRA || HAVE_WEBSERVER */

#ifndef WOLFSSL_NO_CA_NAMES
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_CTX_get_client_CA_list(
            const WOLFSSL_CTX *ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_get_client_CA_list");

        if (ctx == NULL) {
            WOLFSSL_MSG("Bad argument passed to "
                        "wolfSSL_CTX_get_client_CA_list");
            return NULL;
        }

        return ctx->client_ca_names;
    }

    /* returns the CA's set on server side or the CA's sent from server when
     * on client side */
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_get_client_CA_list");

        if (ssl == NULL) {
            WOLFSSL_MSG("Bad argument passed to wolfSSL_get_client_CA_list");
            return NULL;
        }

        return SSL_CA_NAMES(ssl);
    }

    #if !defined(NO_CERTS)
    int wolfSSL_CTX_add_client_CA(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
    {
        WOLFSSL_X509_NAME *nameCopy = NULL;

        WOLFSSL_ENTER("wolfSSL_CTX_add_client_CA");

        if (ctx == NULL || x509 == NULL){
            WOLFSSL_MSG("Bad argument");
            return WOLFSSL_FAILURE;
        }

        if (ctx->client_ca_names == NULL) {
            ctx->client_ca_names = wolfSSL_sk_X509_NAME_new(NULL);
            if (ctx->client_ca_names == NULL) {
                WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
                return WOLFSSL_FAILURE;
            }
        }

        nameCopy = wolfSSL_X509_NAME_dup(wolfSSL_X509_get_subject_name(x509));
        if (nameCopy == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_NAME_dup error");
            return WOLFSSL_FAILURE;
        }

        if (wolfSSL_sk_X509_NAME_push(ctx->client_ca_names, nameCopy) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_push error");
            wolfSSL_X509_NAME_free(nameCopy);
            return WOLFSSL_FAILURE;
        }

        return WOLFSSL_SUCCESS;
    }
    #endif

    #ifndef NO_BIO
        #if !defined(NO_RSA) && !defined(NO_CERTS)
        WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(
            const char* fname)
        {
            /* The webserver build is using this to load a CA into the server
             * for client authentication as an option. Have this return NULL in
             * that case. If OPENSSL_EXTRA is enabled, go ahead and include
             * the function. */
        #ifdef OPENSSL_EXTRA
            WOLFSSL_STACK *list = NULL;
            WOLFSSL_BIO* bio = NULL;
            WOLFSSL_X509 *cert = NULL;
            WOLFSSL_X509_NAME *nameCopy = NULL;
            unsigned long err = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

            WOLFSSL_ENTER("wolfSSL_load_client_CA_file");

            bio = wolfSSL_BIO_new_file(fname, "rb");
            if (bio == NULL) {
                WOLFSSL_MSG("wolfSSL_BIO_new_file error");
                goto cleanup;
            }

            list = wolfSSL_sk_X509_NAME_new(NULL);
            if (list == NULL) {
                WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
                goto cleanup;
            }

            /* Read each certificate in the chain out of the file. */
            while (wolfSSL_PEM_read_bio_X509(bio, &cert, NULL, NULL) != NULL) {
                /* Need a persistent copy of the subject name. */
                nameCopy = wolfSSL_X509_NAME_dup(
                        wolfSSL_X509_get_subject_name(cert));
                if (nameCopy == NULL) {
                    WOLFSSL_MSG("wolfSSL_X509_NAME_dup error");
                    goto cleanup;
                }
                /*
                * Original cert will be freed so make sure not to try to access
                * it in the future.
                */
                nameCopy->x509 = NULL;

                if (wolfSSL_sk_X509_NAME_push(list, nameCopy) <= 0) {
                    WOLFSSL_MSG("wolfSSL_sk_X509_NAME_push error");
                    /* Do free in loop because nameCopy is now responsibility
                     * of list to free and adding jumps to cleanup after this
                     * might result in a double free. */
                    wolfSSL_X509_NAME_free(nameCopy);
                    goto cleanup;
                }

                wolfSSL_X509_free(cert);
                cert = NULL;
            }

            CLEAR_ASN_NO_PEM_HEADER_ERROR(err);

            err = WOLFSSL_SUCCESS;
cleanup:
            wolfSSL_X509_free(cert);
            wolfSSL_BIO_free(bio);
            if (err != WOLFSSL_SUCCESS) {
                /* We failed so return NULL */
                wolfSSL_sk_X509_NAME_pop_free(list, NULL);
                list = NULL;
            }
            return list;
        #else
            (void)fname;
            return NULL;
        #endif
        }
        #endif
    #endif /* !NO_BIO */
#endif /* OPENSSL_EXTRA || WOLFSSL_EXTRA */

#ifdef OPENSSL_EXTRA

    #if defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA256) \
        && !defined(WC_NO_RNG)
    static const byte srp_N[] = {
        0xEE, 0xAF, 0x0A, 0xB9, 0xAD, 0xB3, 0x8D, 0xD6, 0x9C, 0x33, 0xF8,
        0x0A, 0xFA, 0x8F, 0xC5, 0xE8, 0x60, 0x72, 0x61, 0x87, 0x75, 0xFF,
        0x3C, 0x0B, 0x9E, 0xA2, 0x31, 0x4C, 0x9C, 0x25, 0x65, 0x76, 0xD6,
        0x74, 0xDF, 0x74, 0x96, 0xEA, 0x81, 0xD3, 0x38, 0x3B, 0x48, 0x13,
        0xD6, 0x92, 0xC6, 0xE0, 0xE0, 0xD5, 0xD8, 0xE2, 0x50, 0xB9, 0x8B,
        0xE4, 0x8E, 0x49, 0x5C, 0x1D, 0x60, 0x89, 0xDA, 0xD1, 0x5D, 0xC7,
        0xD7, 0xB4, 0x61, 0x54, 0xD6, 0xB6, 0xCE, 0x8E, 0xF4, 0xAD, 0x69,
        0xB1, 0x5D, 0x49, 0x82, 0x55, 0x9B, 0x29, 0x7B, 0xCF, 0x18, 0x85,
        0xC5, 0x29, 0xF5, 0x66, 0x66, 0x0E, 0x57, 0xEC, 0x68, 0xED, 0xBC,
        0x3C, 0x05, 0x72, 0x6C, 0xC0, 0x2F, 0xD4, 0xCB, 0xF4, 0x97, 0x6E,
        0xAA, 0x9A, 0xFD, 0x51, 0x38, 0xFE, 0x83, 0x76, 0x43, 0x5B, 0x9F,
        0xC6, 0x1D, 0x2F, 0xC0, 0xEB, 0x06, 0xE3
    };
    static const byte srp_g[] = {
        0x02
    };

    int wolfSSL_CTX_set_srp_username(WOLFSSL_CTX* ctx, char* username)
    {
        int r = 0;
        SrpSide srp_side = SRP_CLIENT_SIDE;
        byte salt[SRP_SALT_SIZE];

        WOLFSSL_ENTER("wolfSSL_CTX_set_srp_username");
        if (ctx == NULL || ctx->srp == NULL || username==NULL)
            return WOLFSSL_FAILURE;

        if (ctx->method->side == WOLFSSL_SERVER_END){
            srp_side = SRP_SERVER_SIDE;
        } else if (ctx->method->side == WOLFSSL_CLIENT_END){
            srp_side = SRP_CLIENT_SIDE;
        } else {
            WOLFSSL_MSG("Init CTX failed");
            return WOLFSSL_FAILURE;
        }

        if (wc_SrpInit(ctx->srp, SRP_TYPE_SHA256, srp_side) < 0) {
            WOLFSSL_MSG("Init SRP CTX failed");
            XFREE(ctx->srp, ctx->heap, DYNAMIC_TYPE_SRP);
            ctx->srp = NULL;
            return WOLFSSL_FAILURE;
        }
        r = wc_SrpSetUsername(ctx->srp, (const byte*)username,
                              (word32)XSTRLEN(username));
        if (r < 0) {
            WOLFSSL_MSG("fail to set srp username.");
            return WOLFSSL_FAILURE;
        }

        /* if wolfSSL_CTX_set_srp_password has already been called, */
        /* execute wc_SrpSetPassword here */
        if (ctx->srp_password != NULL) {
            WC_RNG rng;
            if (wc_InitRng(&rng) < 0){
                WOLFSSL_MSG("wc_InitRng failed");
                return WOLFSSL_FAILURE;
            }
            XMEMSET(salt, 0, sizeof(salt)/sizeof(salt[0]));
            r = wc_RNG_GenerateBlock(&rng, salt, sizeof(salt)/sizeof(salt[0]));
            wc_FreeRng(&rng);
            if (r <  0) {
                WOLFSSL_MSG("wc_RNG_GenerateBlock failed");
                return WOLFSSL_FAILURE;
            }

            if (wc_SrpSetParams(ctx->srp, srp_N, sizeof(srp_N)/sizeof(srp_N[0]),
                                srp_g, sizeof(srp_g)/sizeof(srp_g[0]),
                                salt, sizeof(salt)/sizeof(salt[0])) < 0) {
                WOLFSSL_MSG("wc_SrpSetParam failed");
                return WOLFSSL_FAILURE;
            }
            r = wc_SrpSetPassword(ctx->srp,
                     (const byte*)ctx->srp_password,
                     (word32)XSTRLEN((char *)ctx->srp_password));
            if (r < 0) {
                WOLFSSL_MSG("fail to set srp password.");
                return WOLFSSL_FAILURE;
            }

            XFREE(ctx->srp_password, ctx->heap, DYNAMIC_TYPE_SRP);
            ctx->srp_password = NULL;
        }

        return WOLFSSL_SUCCESS;
    }

    int wolfSSL_CTX_set_srp_password(WOLFSSL_CTX* ctx, char* password)
    {
        int r;
        byte salt[SRP_SALT_SIZE];

        WOLFSSL_ENTER("wolfSSL_CTX_set_srp_password");
        if (ctx == NULL || ctx->srp == NULL || password == NULL)
            return WOLFSSL_FAILURE;

        if (ctx->srp->user != NULL) {
            WC_RNG rng;
            if (wc_InitRng(&rng) < 0) {
                WOLFSSL_MSG("wc_InitRng failed");
                return WOLFSSL_FAILURE;
            }
            XMEMSET(salt, 0, sizeof(salt)/sizeof(salt[0]));
            r = wc_RNG_GenerateBlock(&rng, salt, sizeof(salt)/sizeof(salt[0]));
            wc_FreeRng(&rng);
            if (r <  0) {
                WOLFSSL_MSG("wc_RNG_GenerateBlock failed");
                return WOLFSSL_FAILURE;
            }
            if (wc_SrpSetParams(ctx->srp, srp_N, sizeof(srp_N)/sizeof(srp_N[0]),
                                srp_g, sizeof(srp_g)/sizeof(srp_g[0]),
                                salt, sizeof(salt)/sizeof(salt[0])) < 0){
                WOLFSSL_MSG("wc_SrpSetParam failed");
                wc_FreeRng(&rng);
                return WOLFSSL_FAILURE;
            }
            r = wc_SrpSetPassword(ctx->srp, (const byte*)password,
                                  (word32)XSTRLEN(password));
            if (r < 0) {
                WOLFSSL_MSG("wc_SrpSetPassword failed.");
                wc_FreeRng(&rng);
                return WOLFSSL_FAILURE;
            }
            XFREE(ctx->srp_password, NULL, DYNAMIC_TYPE_SRP);
            ctx->srp_password = NULL;
            wc_FreeRng(&rng);
        } else {
            /* save password for wolfSSL_set_srp_username */
            XFREE(ctx->srp_password, ctx->heap, DYNAMIC_TYPE_SRP);

            ctx->srp_password = (byte*)XMALLOC(XSTRLEN(password) + 1, ctx->heap,
                                               DYNAMIC_TYPE_SRP);
            if (ctx->srp_password == NULL){
                WOLFSSL_MSG("memory allocation error");
                return WOLFSSL_FAILURE;
            }
            XMEMCPY(ctx->srp_password, password, XSTRLEN(password) + 1);
        }
        return WOLFSSL_SUCCESS;
    }

    /**
     * The modulus passed to wc_SrpSetParams in ssl.c is constant so check
     * that the requested strength is less than or equal to the size of the
     * static modulus size.
     * @param ctx Not used
     * @param strength Minimum number of bits for the modulus
     * @return 1 if strength is less than or equal to static modulus
     *         0 if strength is greater than static modulus
     */
    int  wolfSSL_CTX_set_srp_strength(WOLFSSL_CTX *ctx, int strength)
    {
        (void)ctx;
        WOLFSSL_ENTER("wolfSSL_CTX_set_srp_strength");
        if (strength > (int)(sizeof(srp_N)*8)) {
            WOLFSSL_MSG("Bad Parameter");
            return WOLFSSL_FAILURE;
        }
        return WOLFSSL_SUCCESS;
    }

    char* wolfSSL_get_srp_username(WOLFSSL *ssl)
    {
        if (ssl && ssl->ctx && ssl->ctx->srp) {
            return (char*) ssl->ctx->srp->user;
        }
        return NULL;
    }
    #endif /* WOLFCRYPT_HAVE_SRP && !NO_SHA256 && !WC_NO_RNG */

    /* keyblock size in bytes or -1 */
    int wolfSSL_get_keyblock_size(WOLFSSL* ssl)
    {
        if (ssl == NULL)
            return WOLFSSL_FATAL_ERROR;

        return 2 * (ssl->specs.key_size + ssl->specs.iv_size +
                    ssl->specs.hash_size);
    }

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL)

    /* store keys returns WOLFSSL_SUCCESS or -1 on error */
    int wolfSSL_get_keys(WOLFSSL* ssl, unsigned char** ms, unsigned int* msLen,
                                     unsigned char** sr, unsigned int* srLen,
                                     unsigned char** cr, unsigned int* crLen)
    {
        if (ssl == NULL || ssl->arrays == NULL)
            return WOLFSSL_FATAL_ERROR;

        *ms = ssl->arrays->masterSecret;
        *sr = ssl->arrays->serverRandom;
        *cr = ssl->arrays->clientRandom;

        *msLen = SECRET_LEN;
        *srLen = RAN_LEN;
        *crLen = RAN_LEN;

        return WOLFSSL_SUCCESS;
    }

    void wolfSSL_set_accept_state(WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_set_accept_state");

        if (ssl == NULL)
            return;

        if (ssl->options.side == WOLFSSL_CLIENT_END) {
    #ifdef HAVE_ECC
        #ifdef WOLFSSL_SMALL_STACK
            ecc_key* key = NULL;
        #else
            ecc_key key[1];
        #endif
            word32 idx = 0;

        #ifdef WOLFSSL_SMALL_STACK
            key = (ecc_key*)XMALLOC(sizeof(ecc_key), ssl->heap,
                                    DYNAMIC_TYPE_ECC);
            if (key == NULL) {
                WOLFSSL_MSG("Error allocating memory for ecc_key");
            }
        #endif
            if (ssl->options.haveStaticECC && ssl->buffers.key != NULL) {
                if (wc_ecc_init(key) >= 0) {
                    if (wc_EccPrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                            key, ssl->buffers.key->length) != 0) {
                        ssl->options.haveECDSAsig = 0;
                        ssl->options.haveECC = 0;
                        ssl->options.haveStaticECC = 0;
                    }
                    wc_ecc_free(key);
                }
            }
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(key, ssl->heap, DYNAMIC_TYPE_ECC);
        #endif
    #endif

    #ifndef NO_DH
            if (!ssl->options.haveDH && ssl->ctx->haveDH) {
                ssl->buffers.serverDH_P = ssl->ctx->serverDH_P;
                ssl->buffers.serverDH_G = ssl->ctx->serverDH_G;
                ssl->options.haveDH = 1;
            }
    #endif
        }

        if (InitSSL_Side(ssl, WOLFSSL_SERVER_END) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error initializing server side");
        }
    }

#endif /* OPENSSL_EXTRA || WOLFSSL_EXTRA || WOLFSSL_WPAS_SMALL */

    /* return true if connection established */
    int wolfSSL_is_init_finished(const WOLFSSL* ssl)
    {
        if (ssl == NULL)
            return 0;

        /* Can't use ssl->options.connectState and ssl->options.acceptState
         * because they differ in meaning for TLS <=1.2 and 1.3 */
        if (ssl->options.handShakeState == HANDSHAKE_DONE)
            return 1;

        return 0;
    }

#ifdef OPENSSL_EXTRA
    void wolfSSL_CTX_set_tmp_rsa_callback(WOLFSSL_CTX* ctx,
                                      WOLFSSL_RSA*(*f)(WOLFSSL*, int, int))
    {
        /* wolfSSL verifies all these internally */
        (void)ctx;
        (void)f;
    }


    void wolfSSL_set_shutdown(WOLFSSL* ssl, int opt)
    {
        WOLFSSL_ENTER("wolfSSL_set_shutdown");
        if(ssl==NULL) {
            WOLFSSL_MSG("Shutdown not set. ssl is null");
            return;
        }

        ssl->options.sentNotify =  (opt&WOLFSSL_SENT_SHUTDOWN) > 0;
        ssl->options.closeNotify = (opt&WOLFSSL_RECEIVED_SHUTDOWN) > 0;
    }
#endif

    long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_get_options");
        WOLFSSL_MSG("wolfSSL options are set through API calls and macros");
        if(ctx == NULL)
            return BAD_FUNC_ARG;
        return (long)ctx->mask;
    }

    /* forward declaration */
    static long wolf_set_options(long old_op, long op);

    long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_options");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        ctx->mask = (unsigned long)wolf_set_options((long)ctx->mask, opt);
#if defined(HAVE_SESSION_TICKET) && (defined(OPENSSL_EXTRA) \
        || defined(HAVE_WEBSERVER) || defined(WOLFSSL_WPAS_SMALL))
        if ((ctx->mask & WOLFSSL_OP_NO_TICKET) == WOLFSSL_OP_NO_TICKET) {
          ctx->noTicketTls12 = 1;
        }
        /* This code is here for documentation purpose. You must not turn off
         * session tickets with the WOLFSSL_OP_NO_TICKET option for TLSv1.3.
         * Because we need to support both stateful and stateless tickets.
        #ifdef WOLFSSL_TLS13
            if ((ctx->mask & WOLFSSL_OP_NO_TICKET) == WOLFSSL_OP_NO_TICKET) {
                ctx->noTicketTls13 = 1;
            }
        #endif
        */
#endif
        return (long)ctx->mask;
    }

    long wolfSSL_CTX_clear_options(WOLFSSL_CTX* ctx, long opt)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_clear_options");
        if(ctx == NULL)
            return BAD_FUNC_ARG;
        ctx->mask &= (unsigned long)~opt;
        return (long)ctx->mask;
    }

#ifdef OPENSSL_EXTRA

    int wolfSSL_set_rfd(WOLFSSL* ssl, int rfd)
    {
        WOLFSSL_ENTER("wolfSSL_set_rfd");
        ssl->rfd = rfd;      /* not used directly to allow IO callbacks */

        ssl->IOCB_ReadCtx  = &ssl->rfd;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            ssl->IOCB_ReadCtx = &ssl->buffers.dtlsCtx;
            ssl->buffers.dtlsCtx.rfd = rfd;
        }
    #endif

        return WOLFSSL_SUCCESS;
    }


    int wolfSSL_set_wfd(WOLFSSL* ssl, int wfd)
    {
        WOLFSSL_ENTER("wolfSSL_set_wfd");
        ssl->wfd = wfd;      /* not used directly to allow IO callbacks */

        ssl->IOCB_WriteCtx  = &ssl->wfd;

        return WOLFSSL_SUCCESS;
    }
#endif /* OPENSSL_EXTRA */

#if !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL))

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    /**
     * Implemented in a similar way that ngx_ssl_ocsp_validate does it when
     * SSL_get0_verified_chain is not available.
     * @param ssl WOLFSSL object to extract certs from
     * @return Stack of verified certs
     */
    WOLF_STACK_OF(WOLFSSL_X509) *wolfSSL_get0_verified_chain(const WOLFSSL *ssl)
    {
        WOLF_STACK_OF(WOLFSSL_X509)* chain = NULL;
        WOLFSSL_X509_STORE_CTX* storeCtx = NULL;
        WOLFSSL_X509* peerCert = NULL;

        WOLFSSL_ENTER("wolfSSL_get0_verified_chain");

        if (ssl == NULL || ssl->ctx == NULL) {
            WOLFSSL_MSG("Bad parameter");
            return NULL;
        }

        peerCert = wolfSSL_get_peer_certificate((WOLFSSL*)ssl);
        if (peerCert == NULL) {
            WOLFSSL_MSG("wolfSSL_get_peer_certificate error");
            return NULL;
        }
        /* wolfSSL_get_peer_certificate returns a copy. We want the internal
         * member so that we don't have to worry about free'ing it. We call
         * wolfSSL_get_peer_certificate so that we don't have to worry about
         * setting up the internal pointer. */
        wolfSSL_X509_free(peerCert);
        peerCert = (WOLFSSL_X509*)&ssl->peerCert;
        chain = wolfSSL_get_peer_cert_chain(ssl);
        if (chain == NULL) {
            WOLFSSL_MSG("wolfSSL_get_peer_cert_chain error");
            return NULL;
        }
        storeCtx = wolfSSL_X509_STORE_CTX_new();
        if (storeCtx == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_new error");
            return NULL;
        }
        if (wolfSSL_X509_STORE_CTX_init(storeCtx, SSL_STORE(ssl),
                peerCert, chain) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_init error");
            wolfSSL_X509_STORE_CTX_free(storeCtx);
            return NULL;
        }
        if (wolfSSL_X509_verify_cert(storeCtx) <= 0) {
            WOLFSSL_MSG("wolfSSL_X509_verify_cert error");
            wolfSSL_X509_STORE_CTX_free(storeCtx);
            return NULL;
        }
        wolfSSL_X509_STORE_CTX_free(storeCtx);
        return chain;
    }
#endif /* SESSION_CERTS && OPENSSL_EXTRA */

    WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(const WOLFSSL_CTX* ctx)
    {
        if (ctx == NULL) {
            return NULL;
        }

        if (ctx->x509_store_pt != NULL)
            return ctx->x509_store_pt;
        return &((WOLFSSL_CTX*)ctx)->x509_store;
    }

    void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx, WOLFSSL_X509_STORE* str)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_cert_store");
        if (ctx == NULL || str == NULL || ctx->cm == str->cm) {
            return;
        }

        if (wolfSSL_CertManager_up_ref(str->cm) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_CertManager_up_ref error");
            return;
        }
        /* free cert manager if have one */
        if (ctx->cm != NULL) {
            wolfSSL_CertManagerFree(ctx->cm);
        }
        ctx->cm               = str->cm;
        ctx->x509_store.cm    = str->cm;

        /* free existing store if it exists */
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
        ctx->x509_store.cache = str->cache;
        ctx->x509_store_pt    = str; /* take ownership of store and free it
                                        with CTX free */
        ctx->cm->x509_store_p = ctx->x509_store_pt;/* CTX has ownership
                                                    and free it with CTX free*/
    }

#ifdef OPENSSL_ALL
    int wolfSSL_CTX_set1_verify_cert_store(WOLFSSL_CTX* ctx,
        WOLFSSL_X509_STORE* str)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set1_verify_cert_store");

        if (ctx == NULL || str == NULL) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        /* NO-OP when setting existing store */
        if (str == CTX_STORE(ctx))
            return WOLFSSL_SUCCESS;

        if (wolfSSL_X509_STORE_up_ref(str) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
            return WOLFSSL_FAILURE;
        }

        /* free existing store if it exists */
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
        ctx->x509_store_pt = str; /* take ownership of store and free it
                                     with CTX free */
        return WOLFSSL_SUCCESS;
    }
#endif

    int wolfSSL_set0_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str)
    {
        WOLFSSL_ENTER("wolfSSL_set0_verify_cert_store");

        if (ssl == NULL || str == NULL) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        /* NO-OP when setting existing store */
        if (str == SSL_STORE(ssl))
            return WOLFSSL_SUCCESS;

        /* free existing store if it exists */
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
        if (str == ssl->ctx->x509_store_pt)
            ssl->x509_store_pt = NULL; /* if setting ctx store then just revert
                                          to using that instead */
        else
            ssl->x509_store_pt = str; /* take ownership of store and free it
                                         with SSL free */
        return WOLFSSL_SUCCESS;
    }


    int wolfSSL_set1_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str)
    {
        WOLFSSL_ENTER("wolfSSL_set1_verify_cert_store");

        if (ssl == NULL || str == NULL) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        /* NO-OP when setting existing store */
        if (str == SSL_STORE(ssl))
            return WOLFSSL_SUCCESS;

        if (wolfSSL_X509_STORE_up_ref(str) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
            return WOLFSSL_FAILURE;
        }

        /* free existing store if it exists */
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
        if (str == ssl->ctx->x509_store_pt)
            ssl->x509_store_pt = NULL; /* if setting ctx store then just revert
                                          to using that instead */
        else
            ssl->x509_store_pt = str; /* take ownership of store and free it
                                         with SSL free */
        return WOLFSSL_SUCCESS;
    }
#endif /* !NO_CERTS && (OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL) */

#ifdef WOLFSSL_ENCRYPTED_KEYS

    void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                   void* userdata)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_default_passwd_cb_userdata");
        if (ctx)
            ctx->passwd_userdata = userdata;
    }


    void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx, wc_pem_password_cb*
                                           cb)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_default_passwd_cb");
        if (ctx)
            ctx->passwd_cb = cb;
    }

    wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX *ctx)
    {
        if (ctx == NULL || ctx->passwd_cb == NULL) {
            return NULL;
        }

        return ctx->passwd_cb;
    }


    void* wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx)
    {
        if (ctx == NULL) {
            return NULL;
        }

        return ctx->passwd_userdata;
    }

#endif /* WOLFSSL_ENCRYPTED_KEYS */


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
    unsigned long wolfSSL_ERR_get_error(void)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_get_error");
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
        return wc_GetErrorNodeErr();
#else
        return (unsigned long)(0 - NOT_COMPILED_IN);
#endif
    }
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

    int wolfSSL_num_locks(void)
    {
        return 0;
    }

    void wolfSSL_set_locking_callback(mutex_cb* f)
    {
        WOLFSSL_ENTER("wolfSSL_set_locking_callback");

        if (wc_SetMutexCb(f) != 0) {
            WOLFSSL_MSG("Error when setting mutex call back");
        }
    }

    mutex_cb* wolfSSL_get_locking_callback(void)
    {
        WOLFSSL_ENTER("wolfSSL_get_locking_callback");

        return wc_GetMutexCb();
    }


    typedef unsigned long (idCb)(void);
    static idCb* inner_idCb = NULL;

    unsigned long wolfSSL_thread_id(void)
    {
        if (inner_idCb != NULL) {
            return inner_idCb();
        }
        else {
            return 0;
        }
    }


    void wolfSSL_set_id_callback(unsigned long (*f)(void))
    {
        inner_idCb = f;
    }

#ifdef WOLFSSL_HAVE_ERROR_QUEUE
#ifndef NO_BIO
    /* print out and clear all errors */
    void wolfSSL_ERR_print_errors(WOLFSSL_BIO* bio)
    {
        const char* file = NULL;
        const char* reason = NULL;
        int ret;
        int line = 0;
        char buf[WOLFSSL_MAX_ERROR_SZ * 2];

        WOLFSSL_ENTER("wolfSSL_ERR_print_errors");

        if (bio == NULL) {
            WOLFSSL_MSG("BIO passed in was null");
            return;
        }

        do {
        ret = wc_PeekErrorNode(0, &file, &reason, &line);
        if (ret >= 0) {
            const char* r = wolfSSL_ERR_reason_error_string(0 - ret);
            if (XSNPRINTF(buf, sizeof(buf),
                          "error:%d:wolfSSL library:%s:%s:%d\n",
                          ret, r, file, line)
                >= (int)sizeof(buf))
            {
                WOLFSSL_MSG("Buffer overrun formatting error message");
            }
            wolfSSL_BIO_write(bio, buf, (int)XSTRLEN(buf));
            wc_RemoveErrorNode(0);
        }
        } while (ret >= 0);
        if (wolfSSL_BIO_write(bio, "", 1) != 1) {
            WOLFSSL_MSG("Issue writing final string terminator");
        }
    }
#endif /* !NO_BIO */
#endif /* WOLFSSL_HAVE_ERROR_QUEUE */

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_SECRET_CALLBACK)
#if !defined(NO_WOLFSSL_SERVER)
/* Return the amount of random bytes copied over or error case.
 * ssl : ssl struct after handshake
 * out : buffer to hold random bytes
 * outSz : either 0 (return max buffer sz) or size of out buffer
 */
size_t wolfSSL_get_server_random(const WOLFSSL *ssl, unsigned char *out,
                                                                   size_t outSz)
{
    size_t size;

    /* return max size of buffer */
    if (outSz == 0) {
        return RAN_LEN;
    }

    if (ssl == NULL || out == NULL) {
        return 0;
    }

    if (ssl->arrays == NULL) {
        WOLFSSL_MSG("Arrays struct not saved after handshake");
        return 0;
    }

    if (outSz > RAN_LEN) {
        size = RAN_LEN;
    }
    else {
        size = outSz;
    }

    XMEMCPY(out, ssl->arrays->serverRandom, size);
    return size;
}
#endif /* !NO_WOLFSSL_SERVER */
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || HAVE_SECRET_CALLBACK */

#ifdef OPENSSL_EXTRA
#if !defined(NO_WOLFSSL_SERVER)
/* Used to get the peer ephemeral public key sent during the connection
 * NOTE: currently wolfSSL_KeepHandshakeResources(WOLFSSL* ssl) must be called
 *       before the ephemeral key is stored.
 * return WOLFSSL_SUCCESS on success */
int wolfSSL_get_peer_tmp_key(const WOLFSSL* ssl, WOLFSSL_EVP_PKEY** pkey)
{
    WOLFSSL_EVP_PKEY* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_get_server_tmp_key");

    if (ssl == NULL || pkey == NULL) {
        WOLFSSL_MSG("Bad argument passed in");
        return WOLFSSL_FAILURE;
    }

#ifdef HAVE_ECC
    if (ssl->peerEccKey != NULL) {
        unsigned char* der;
        const unsigned char* pt;
        unsigned int   derSz = 0;
        int sz;

        PRIVATE_KEY_UNLOCK();
        if (wc_ecc_export_x963(ssl->peerEccKey, NULL, &derSz)
              != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
        {
            WOLFSSL_MSG("get ecc der size failed");
            PRIVATE_KEY_LOCK();
            return WOLFSSL_FAILURE;
        }
        PRIVATE_KEY_LOCK();

        derSz += MAX_SEQ_SZ + (2 * MAX_ALGO_SZ) + MAX_SEQ_SZ + TRAILING_ZERO;
        der = (unsigned char*)XMALLOC(derSz, ssl->heap, DYNAMIC_TYPE_KEY);
        if (der == NULL) {
            WOLFSSL_MSG("Memory error");
            return WOLFSSL_FAILURE;
        }

        if ((sz = wc_EccPublicKeyToDer(ssl->peerEccKey, der, derSz, 1)) <= 0) {
            WOLFSSL_MSG("get ecc der failed");
            XFREE(der, ssl->heap, DYNAMIC_TYPE_KEY);
            return WOLFSSL_FAILURE;
        }
        pt = der; /* in case pointer gets advanced */
        ret = wolfSSL_d2i_PUBKEY(NULL, &pt, sz);
        XFREE(der, ssl->heap, DYNAMIC_TYPE_KEY);
    }
#endif

    *pkey = ret;
#ifdef HAVE_ECC
    if (ret != NULL)
        return WOLFSSL_SUCCESS;
    else
#endif
        return WOLFSSL_FAILURE;
}

#endif /* !NO_WOLFSSL_SERVER */

/**
 * This function checks if any compiled in protocol versions are
 * left enabled after calls to set_min or set_max API.
 * @param major The SSL/TLS major version
 * @return WOLFSSL_SUCCESS on valid settings and WOLFSSL_FAILURE when no
 *         protocol versions are left enabled.
 */
static int CheckSslMethodVersion(byte major, unsigned long options)
{
    int sanityConfirmed = 0;

    (void)options;

    switch (major) {
    #ifndef NO_TLS
        case SSLv3_MAJOR:
            #ifdef WOLFSSL_ALLOW_SSLV3
                if (!(options & WOLFSSL_OP_NO_SSLv3)) {
                    sanityConfirmed = 1;
                }
            #endif
            #ifndef NO_OLD_TLS
                if (!(options & WOLFSSL_OP_NO_TLSv1))
                    sanityConfirmed = 1;
                if (!(options & WOLFSSL_OP_NO_TLSv1_1))
                    sanityConfirmed = 1;
            #endif
            #ifndef WOLFSSL_NO_TLS12
                if (!(options & WOLFSSL_OP_NO_TLSv1_2))
                    sanityConfirmed = 1;
            #endif
            #ifdef WOLFSSL_TLS13
                if (!(options & WOLFSSL_OP_NO_TLSv1_3))
                    sanityConfirmed = 1;
            #endif
            break;
    #endif
    #ifdef WOLFSSL_DTLS
        case DTLS_MAJOR:
            sanityConfirmed = 1;
            break;
    #endif
        default:
            WOLFSSL_MSG("Invalid major version");
            return WOLFSSL_FAILURE;
    }
    if (!sanityConfirmed) {
        WOLFSSL_MSG("All compiled in TLS versions disabled");
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
}

/**
 * protoVerTbl holds (D)TLS version numbers in ascending order.
 * Except DTLS versions, the newer version is located in the latter part of
 * the table. This table is referred by wolfSSL_CTX_set_min_proto_version and
 * wolfSSL_CTX_set_max_proto_version.
 */
static const int protoVerTbl[] = {
    SSL3_VERSION,
    TLS1_VERSION,
    TLS1_1_VERSION,
    TLS1_2_VERSION,
    TLS1_3_VERSION,
    DTLS1_VERSION,
    DTLS1_2_VERSION
};
/* number of protocol versions listed in protoVerTbl */
#define NUMBER_OF_PROTOCOLS (sizeof(protoVerTbl)/sizeof(int))

/**
 * wolfSSL_CTX_set_min_proto_version attempts to set the minimum protocol
 * version to use by SSL objects created from this WOLFSSL_CTX.
 * This API guarantees that a version of SSL/TLS lower than specified
 * here will not be allowed. If the version specified is not compiled in
 * then this API sets the lowest compiled in protocol version.
 * This API also accept 0 as version, to set the minimum version automatically.
 * CheckSslMethodVersion() is called to check if any remaining protocol versions
 * are enabled.
 * @param ctx The wolfSSL CONTEXT factory for spawning SSL/TLS objects
 * @param version Any of the following
 *          * 0
 *          * SSL3_VERSION
 *          * TLS1_VERSION
 *          * TLS1_1_VERSION
 *          * TLS1_2_VERSION
 *          * TLS1_3_VERSION
 *          * DTLS1_VERSION
 *          * DTLS1_2_VERSION
 * @return WOLFSSL_SUCCESS on valid settings and WOLFSSL_FAILURE when no
 *         protocol versions are left enabled.
 */
static int Set_CTX_min_proto_version(WOLFSSL_CTX* ctx, int version)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_min_proto_version_ex");

    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    switch (version) {
#ifndef NO_TLS
        case SSL3_VERSION:
#if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
            ctx->minDowngrade = SSLv3_MINOR;
            break;
#endif
        case TLS1_VERSION:
        #ifdef WOLFSSL_ALLOW_TLSV10
            ctx->minDowngrade = TLSv1_MINOR;
            break;
        #endif
        case TLS1_1_VERSION:
        #ifndef NO_OLD_TLS
            ctx->minDowngrade = TLSv1_1_MINOR;
            break;
        #endif
        case TLS1_2_VERSION:
        #ifndef WOLFSSL_NO_TLS12
            ctx->minDowngrade = TLSv1_2_MINOR;
            break;
        #endif
        case TLS1_3_VERSION:
        #ifdef WOLFSSL_TLS13
            ctx->minDowngrade = TLSv1_3_MINOR;
            break;
        #endif
#endif
#ifdef WOLFSSL_DTLS
        case DTLS1_VERSION:
    #ifndef NO_OLD_TLS
            ctx->minDowngrade = DTLS_MINOR;
            break;
    #endif
        case DTLS1_2_VERSION:
            ctx->minDowngrade = DTLSv1_2_MINOR;
            break;
#endif
        default:
            WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
            return WOLFSSL_FAILURE;
    }

    switch (version) {
#ifndef NO_TLS
    case TLS1_3_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_2);
        FALL_THROUGH;
    case TLS1_2_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_1);
        FALL_THROUGH;
    case TLS1_1_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1);
        FALL_THROUGH;
    case TLS1_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_SSLv3);
        break;
    case SSL3_VERSION:
    case SSL2_VERSION:
        /* Nothing to do here */
        break;
#endif
#ifdef WOLFSSL_DTLS
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
        break;
#endif
    default:
        WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
        return WOLFSSL_FAILURE;
    }

    return CheckSslMethodVersion(ctx->method->version.major, ctx->mask);
}

/* Sets the min protocol version allowed with WOLFSSL_CTX
 * returns WOLFSSL_SUCCESS on success */
int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX* ctx, int version)
{
    int ret;
    int proto    = 0;
    int maxProto = 0;
    int i;
    int idx = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_set_min_proto_version");

    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (version != 0) {
        proto = version;
        ctx->minProto = 0; /* turn min proto flag off */
        for (i = 0; (unsigned)i < NUMBER_OF_PROTOCOLS; i++) {
            if (protoVerTbl[i] == version) {
                break;
            }
        }
    }
    else {
        /* when 0 is specified as version, try to find out the min version */
        for (i = 0; (unsigned)i < NUMBER_OF_PROTOCOLS; i++) {
            ret = Set_CTX_min_proto_version(ctx, protoVerTbl[i]);
            if (ret == WOLFSSL_SUCCESS) {
                proto = protoVerTbl[i];
                ctx->minProto = 1; /* turn min proto flag on */
                break;
            }
        }
    }

    /* check case where max > min , if so then clear the NO_* options
     * i is the index into the table for proto version used, see if the max
     * proto version index found is smaller */
    maxProto = wolfSSL_CTX_get_max_proto_version(ctx);
    for (idx = 0; (unsigned)idx < NUMBER_OF_PROTOCOLS; idx++) {
        if (protoVerTbl[idx] == maxProto) {
            break;
        }
    }
    if (idx < i) {
        wolfSSL_CTX_clear_options(ctx, WOLFSSL_OP_NO_TLSv1 |
                WOLFSSL_OP_NO_TLSv1_1 | WOLFSSL_OP_NO_TLSv1_2 |
                WOLFSSL_OP_NO_TLSv1_3);
    }

    ret = Set_CTX_min_proto_version(ctx, proto);
    return ret;
}

/**
 * wolfSSL_CTX_set_max_proto_version attempts to set the maximum protocol
 * version to use by SSL objects created from this WOLFSSL_CTX.
 * This API guarantees that a version of SSL/TLS higher than specified
 * here will not be allowed. If the version specified is not compiled in
 * then this API sets the highest compiled in protocol version.
 * This API also accept 0 as version, to set the maximum version automatically.
 * CheckSslMethodVersion() is called to check if any remaining protocol versions
 * are enabled.
 * @param ctx The wolfSSL CONTEXT factory for spawning SSL/TLS objects
 * @param ver Any of the following
 *          * 0
 *          * SSL3_VERSION
 *          * TLS1_VERSION
 *          * TLS1_1_VERSION
 *          * TLS1_2_VERSION
 *          * TLS1_3_VERSION
 *          * DTLS1_VERSION
 *          * DTLS1_2_VERSION
 * @return WOLFSSL_SUCCESS on valid settings and WOLFSSL_FAILURE when no
 *         protocol versions are left enabled.
 */
static int Set_CTX_max_proto_version(WOLFSSL_CTX* ctx, int ver)
{
    int ret;
    WOLFSSL_ENTER("Set_CTX_max_proto_version");

    if (!ctx || !ctx->method) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    switch (ver) {
    case SSL2_VERSION:
        WOLFSSL_MSG("wolfSSL does not support SSLv2");
        return WOLFSSL_FAILURE;
#ifndef NO_TLS
    case SSL3_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1);
        FALL_THROUGH;
    case TLS1_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_1);
        FALL_THROUGH;
    case TLS1_1_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_2);
        FALL_THROUGH;
    case TLS1_2_VERSION:
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_3);
        FALL_THROUGH;
    case TLS1_3_VERSION:
        /* Nothing to do here */
        break;
#endif
#ifdef WOLFSSL_DTLS
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
        break;
#endif
    default:
        WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
        return WOLFSSL_FAILURE;
    }

    ret = CheckSslMethodVersion(ctx->method->version.major, ctx->mask);
    if (ret == WOLFSSL_SUCCESS) {
        /* Check the major */
        switch (ver) {
    #ifndef NO_TLS
        case SSL3_VERSION:
        case TLS1_VERSION:
        case TLS1_1_VERSION:
        case TLS1_2_VERSION:
        case TLS1_3_VERSION:
            if (ctx->method->version.major != SSLv3_MAJOR) {
                WOLFSSL_MSG("Mismatched protocol version");
                return WOLFSSL_FAILURE;
            }
            break;
    #endif
    #ifdef WOLFSSL_DTLS
        case DTLS1_VERSION:
        case DTLS1_2_VERSION:
            if (ctx->method->version.major != DTLS_MAJOR) {
                WOLFSSL_MSG("Mismatched protocol version");
                return WOLFSSL_FAILURE;
            }
            break;
    #endif
        }
        /* Update the method */
        switch (ver) {
        case SSL2_VERSION:
            WOLFSSL_MSG("wolfSSL does not support SSLv2");
            return WOLFSSL_FAILURE;
    #ifndef NO_TLS
        case SSL3_VERSION:
            ctx->method->version.minor = SSLv3_MINOR;
            break;
        case TLS1_VERSION:
            ctx->method->version.minor = TLSv1_MINOR;
            break;
        case TLS1_1_VERSION:
            ctx->method->version.minor = TLSv1_1_MINOR;
            break;
        case TLS1_2_VERSION:
            ctx->method->version.minor = TLSv1_2_MINOR;
            break;
        case TLS1_3_VERSION:
            ctx->method->version.minor = TLSv1_3_MINOR;
            break;
    #endif
    #ifdef WOLFSSL_DTLS
        case DTLS1_VERSION:
            ctx->method->version.minor = DTLS_MINOR;
            break;
        case DTLS1_2_VERSION:
            ctx->method->version.minor = DTLSv1_2_MINOR;
            break;
    #endif
        default:
            WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
            return WOLFSSL_FAILURE;
        }
    }
    return ret;
}


/* Sets the max protocol version allowed with WOLFSSL_CTX
 * returns WOLFSSL_SUCCESS on success */
int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX* ctx, int version)
{
    int i;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    int minProto;

    WOLFSSL_ENTER("wolfSSL_CTX_set_max_proto_version");

    if (ctx == NULL) {
        return ret;
    }

    /* clear out flags and reset min protocol version */
    minProto = wolfSSL_CTX_get_min_proto_version(ctx);
    wolfSSL_CTX_clear_options(ctx,
            WOLFSSL_OP_NO_TLSv1 | WOLFSSL_OP_NO_TLSv1_1 |
            WOLFSSL_OP_NO_TLSv1_2 | WOLFSSL_OP_NO_TLSv1_3);
    wolfSSL_CTX_set_min_proto_version(ctx, minProto);
    if (version != 0) {
        ctx->maxProto = 0; /* turn max proto flag off */
        return Set_CTX_max_proto_version(ctx, version);
    }

    /* when 0 is specified as version, try to find out the min version from
     * the bottom to top of the protoverTbl.
     */
    for (i = NUMBER_OF_PROTOCOLS -1; i >= 0; i--) {
        ret = Set_CTX_max_proto_version(ctx, protoVerTbl[i]);
        if (ret == WOLFSSL_SUCCESS) {
            ctx->maxProto = 1; /* turn max proto flag on */
            break;
        }
    }

    return ret;
}


static int Set_SSL_min_proto_version(WOLFSSL* ssl, int ver)
{
    WOLFSSL_ENTER("Set_SSL_min_proto_version");

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    switch (ver) {
#ifndef NO_TLS
        case SSL3_VERSION:
#if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)
            ssl->options.minDowngrade = SSLv3_MINOR;
            break;
#endif
        case TLS1_VERSION:
        #ifdef WOLFSSL_ALLOW_TLSV10
            ssl->options.minDowngrade = TLSv1_MINOR;
            break;
        #endif
        case TLS1_1_VERSION:
        #ifndef NO_OLD_TLS
            ssl->options.minDowngrade = TLSv1_1_MINOR;
            break;
        #endif
        case TLS1_2_VERSION:
        #ifndef WOLFSSL_NO_TLS12
            ssl->options.minDowngrade = TLSv1_2_MINOR;
            break;
        #endif
        case TLS1_3_VERSION:
        #ifdef WOLFSSL_TLS13
            ssl->options.minDowngrade = TLSv1_3_MINOR;
            break;
        #endif
#endif
#ifdef WOLFSSL_DTLS
        case DTLS1_VERSION:
    #ifndef NO_OLD_TLS
            ssl->options.minDowngrade = DTLS_MINOR;
            break;
    #endif
        case DTLS1_2_VERSION:
            ssl->options.minDowngrade = DTLSv1_2_MINOR;
            break;
#endif
        default:
            WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
            return WOLFSSL_FAILURE;
    }

    switch (ver) {
#ifndef NO_TLS
    case TLS1_3_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1_2;
        FALL_THROUGH;
    case TLS1_2_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1_1;
        FALL_THROUGH;
    case TLS1_1_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1;
        FALL_THROUGH;
    case TLS1_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_SSLv3;
        break;
    case SSL3_VERSION:
    case SSL2_VERSION:
        /* Nothing to do here */
        break;
#endif
#ifdef WOLFSSL_DTLS
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
        break;
#endif
    default:
        WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
        return WOLFSSL_FAILURE;
    }

    return CheckSslMethodVersion(ssl->version.major, ssl->options.mask);
}

int wolfSSL_set_min_proto_version(WOLFSSL* ssl, int version)
{
    int i;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);;

    WOLFSSL_ENTER("wolfSSL_set_min_proto_version");

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (version != 0) {
        return Set_SSL_min_proto_version(ssl, version);
    }

    /* when 0 is specified as version, try to find out the min version */
    for (i= 0; (unsigned)i < NUMBER_OF_PROTOCOLS; i++) {
        ret = Set_SSL_min_proto_version(ssl, protoVerTbl[i]);
        if (ret == WOLFSSL_SUCCESS)
            break;
    }

    return ret;
}

static int Set_SSL_max_proto_version(WOLFSSL* ssl, int ver)
{

    WOLFSSL_ENTER("Set_SSL_max_proto_version");

    if (!ssl) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    switch (ver) {
    case SSL2_VERSION:
        WOLFSSL_MSG("wolfSSL does not support SSLv2");
        return WOLFSSL_FAILURE;
#ifndef NO_TLS
    case SSL3_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1;
        FALL_THROUGH;
    case TLS1_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1_1;
        FALL_THROUGH;
    case TLS1_1_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1_2;
        FALL_THROUGH;
    case TLS1_2_VERSION:
        ssl->options.mask |= WOLFSSL_OP_NO_TLSv1_3;
        FALL_THROUGH;
    case TLS1_3_VERSION:
        /* Nothing to do here */
        break;
#endif
#ifdef WOLFSSL_DTLS
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
        break;
#endif
    default:
        WOLFSSL_MSG("Unrecognized protocol version or not compiled in");
        return WOLFSSL_FAILURE;
    }

    return CheckSslMethodVersion(ssl->version.major, ssl->options.mask);
}

int wolfSSL_set_max_proto_version(WOLFSSL* ssl, int version)
{
    int i;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);;

    WOLFSSL_ENTER("wolfSSL_set_max_proto_version");

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (version != 0) {
        return Set_SSL_max_proto_version(ssl, version);
    }

    /* when 0 is specified as version, try to find out the min version from
     * the bottom to top of the protoverTbl.
     */
    for (i = NUMBER_OF_PROTOCOLS -1; i >= 0; i--) {
        ret = Set_SSL_max_proto_version(ssl, protoVerTbl[i]);
        if (ret == WOLFSSL_SUCCESS)
            break;
    }

    return ret;
}

static int GetMinProtoVersion(int minDowngrade)
{
    int ret;

    switch (minDowngrade) {
#ifndef NO_OLD_TLS
    #ifdef WOLFSSL_ALLOW_SSLV3
        case SSLv3_MINOR:
            ret = SSL3_VERSION;
            break;
    #endif
    #ifdef WOLFSSL_ALLOW_TLSV10
        case TLSv1_MINOR:
            ret = TLS1_VERSION;
            break;
    #endif
        case TLSv1_1_MINOR:
            ret = TLS1_1_VERSION;
            break;
#endif
#ifndef WOLFSSL_NO_TLS12
        case TLSv1_2_MINOR:
            ret = TLS1_2_VERSION;
            break;
#endif
#ifdef WOLFSSL_TLS13
        case TLSv1_3_MINOR:
            ret = TLS1_3_VERSION;
            break;
#endif
        default:
            ret = 0;
            break;
    }

    return ret;
}

int wolfSSL_CTX_get_min_proto_version(WOLFSSL_CTX* ctx)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_get_min_proto_version");

    if (ctx != NULL) {
        if (ctx->minProto) {
            ret = 0;
        }
        else {
            ret = GetMinProtoVersion(ctx->minDowngrade);
        }
    }
    else {
        ret = GetMinProtoVersion(WOLFSSL_MIN_DOWNGRADE);
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_get_min_proto_version", ret);

    return ret;
}


/* returns the maximum allowed protocol version given the 'options' used
 * returns WOLFSSL_FATAL_ERROR on no match */
static int GetMaxProtoVersion(long options)
{
#ifndef NO_TLS
#ifdef WOLFSSL_TLS13
    if (!(options & WOLFSSL_OP_NO_TLSv1_3))
        return TLS1_3_VERSION;
#endif
#ifndef WOLFSSL_NO_TLS12
    if (!(options & WOLFSSL_OP_NO_TLSv1_2))
        return TLS1_2_VERSION;
#endif
#ifndef NO_OLD_TLS
    if (!(options & WOLFSSL_OP_NO_TLSv1_1))
        return TLS1_1_VERSION;
    #ifdef WOLFSSL_ALLOW_TLSV10
    if (!(options & WOLFSSL_OP_NO_TLSv1))
        return TLS1_VERSION;
    #endif
    #ifdef WOLFSSL_ALLOW_SSLV3
    if (!(options & WOLFSSL_OP_NO_SSLv3))
        return SSL3_VERSION;
    #endif
#endif
#else
    (void)options;
#endif /* NO_TLS */
    return WOLFSSL_FATAL_ERROR;
}


/* returns the maximum protocol version for 'ctx' */
int wolfSSL_CTX_get_max_proto_version(WOLFSSL_CTX* ctx)
{
    int ret = 0;
    long options = 0; /* default to nothing set */

    WOLFSSL_ENTER("wolfSSL_CTX_get_max_proto_version");

    if (ctx != NULL) {
        options = wolfSSL_CTX_get_options(ctx);
    }

    if ((ctx != NULL) && ctx->maxProto) {
        ret = 0;
    }
    else {
        ret = GetMaxProtoVersion(options);
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_get_max_proto_version", ret);

    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
        WOLFSSL_MSG("Error getting max proto version");
        ret = 0; /* setting ret to 0 to match compat return */
    }
    return ret;
}
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_SECRET_CALLBACK)
#if !defined(NO_WOLFSSL_CLIENT)
/* Return the amount of random bytes copied over or error case.
 * ssl : ssl struct after handshake
 * out : buffer to hold random bytes
 * outSz : either 0 (return max buffer sz) or size of out buffer
 */
size_t wolfSSL_get_client_random(const WOLFSSL* ssl, unsigned char* out,
                                                                   size_t outSz)
{
    size_t size;

    /* return max size of buffer */
    if (outSz == 0) {
        return RAN_LEN;
    }

    if (ssl == NULL || out == NULL) {
        return 0;
    }

    if (ssl->arrays == NULL) {
        WOLFSSL_MSG("Arrays struct not saved after handshake");
        return 0;
    }

    if (outSz > RAN_LEN) {
        size = RAN_LEN;
    }
    else {
        size = outSz;
    }

    XMEMCPY(out, ssl->arrays->clientRandom, size);
    return size;
}
#endif /* !NO_WOLFSSL_CLIENT */
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || HAVE_SECRET_CALLBACK */

#ifdef OPENSSL_EXTRA

    unsigned long wolfSSLeay(void)
    {
#ifdef SSLEAY_VERSION_NUMBER
        return SSLEAY_VERSION_NUMBER;
#else
        return OPENSSL_VERSION_NUMBER;
#endif
    }

    unsigned long wolfSSL_OpenSSL_version_num(void)
    {
        return OPENSSL_VERSION_NUMBER;
    }

    const char* wolfSSLeay_version(int type)
    {
        (void)type;
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        return wolfSSL_OpenSSL_version(type);
#else
        return wolfSSL_OpenSSL_version();
#endif
    }
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA
    void wolfSSL_ERR_free_strings(void)
    {
        /* handled internally */
    }

    void wolfSSL_cleanup_all_ex_data(void)
    {
        /* nothing to do here */
    }

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || \
    defined(HAVE_CURL)
    void wolfSSL_ERR_clear_error(void)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_clear_error");
    #if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
        wc_ClearErrorNodes();
    #endif
    }
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    int wolfSSL_clear(WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_clear");

        if (ssl == NULL) {
            return WOLFSSL_FAILURE;
        }

        if (!ssl->options.handShakeDone) {
            /* Only reset the session if we didn't complete a handshake */
            wolfSSL_FreeSession(ssl->ctx, ssl->session);
            ssl->session = wolfSSL_NewSession(ssl->heap);
            if (ssl->session == NULL) {
                return WOLFSSL_FAILURE;
            }
        }

        /* reset error */
        ssl->error = 0;

        /* reset option bits */
        ssl->options.isClosed = 0;
        ssl->options.connReset = 0;
        ssl->options.sentNotify = 0;
        ssl->options.closeNotify = 0;
        ssl->options.sendVerify = 0;
        ssl->options.serverState = NULL_STATE;
        ssl->options.clientState = NULL_STATE;
        ssl->options.connectState = CONNECT_BEGIN;
        ssl->options.acceptState  = ACCEPT_BEGIN;
        ssl->options.handShakeState  = NULL_STATE;
        ssl->options.handShakeDone = 0;
        ssl->options.processReply = 0; /* doProcessInit */
        ssl->options.havePeerVerify = 0;
        ssl->options.havePeerCert = 0;
        ssl->options.peerAuthGood = 0;
        ssl->options.tls1_3 = 0;
        ssl->options.haveSessionId = 0;
        ssl->options.tls = 0;
        ssl->options.tls1_1 = 0;
    #ifdef WOLFSSL_DTLS
        ssl->options.dtlsStateful = 0;
    #endif
    #if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
        ssl->options.noPskDheKe = 0;
      #ifdef HAVE_SUPPORTED_CURVES
        ssl->options.onlyPskDheKe = 0;
      #endif
    #endif
    #ifdef HAVE_SESSION_TICKET
        #ifdef WOLFSSL_TLS13
        ssl->options.ticketsSent = 0;
        #endif
        ssl->options.rejectTicket = 0;
    #endif
    #ifdef WOLFSSL_EARLY_DATA
        ssl->earlyData = no_early_data;
        ssl->earlyDataSz = 0;
    #endif

    #if defined(HAVE_TLS_EXTENSIONS) && !defined(NO_TLS)
        TLSX_FreeAll(ssl->extensions, ssl->heap);
        ssl->extensions = NULL;
    #endif

        if (ssl->keys.encryptionOn) {
            ForceZero(ssl->buffers.inputBuffer.buffer -
                ssl->buffers.inputBuffer.offset,
                ssl->buffers.inputBuffer.bufferSize);
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(ssl->buffers.inputBuffer.buffer -
                ssl->buffers.inputBuffer.offset,
                ssl->buffers.inputBuffer.bufferSize);
        #endif
        }
        ssl->keys.encryptionOn = 0;
        XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

        FreeCiphers(ssl);
        InitCiphers(ssl);
        InitCipherSpecs(&ssl->specs);

        if (InitSSL_Suites(ssl) != WOLFSSL_SUCCESS)
            return WOLFSSL_FAILURE;

        if (InitHandshakeHashes(ssl) != 0)
            return WOLFSSL_FAILURE;

#ifdef KEEP_PEER_CERT
        FreeX509(&ssl->peerCert);
        InitX509(&ssl->peerCert, 0, ssl->heap);
#endif

#ifdef WOLFSSL_QUIC
        wolfSSL_quic_clear(ssl);
#endif
#ifdef HAVE_OCSP
#if defined(WOLFSSL_TLS13) && defined(HAVE_CERTIFICATE_STATUS_REQUEST)
        ssl->response_idx = 0;
#endif
#endif
        return WOLFSSL_SUCCESS;
    }

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
    long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode)
    {
        /* WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is wolfSSL default mode */

        WOLFSSL_ENTER("wolfSSL_CTX_set_mode");
        switch(mode) {
            case WOLFSSL_MODE_ENABLE_PARTIAL_WRITE:
                ctx->partialWrite = 1;
                break;
            #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            case SSL_MODE_RELEASE_BUFFERS:
                WOLFSSL_MSG("SSL_MODE_RELEASE_BUFFERS not implemented.");
                break;
            #endif
            case WOLFSSL_MODE_AUTO_RETRY:
                ctx->autoRetry = 1;
                break;
            default:
                WOLFSSL_MSG("Mode Not Implemented");
        }

        /* WOLFSSL_MODE_AUTO_RETRY
         * Should not return WOLFSSL_FATAL_ERROR with renegotiation on read/write */

        return mode;
    }

    long wolfSSL_CTX_clear_mode(WOLFSSL_CTX* ctx, long mode)
    {
        /* WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is wolfSSL default mode */

        WOLFSSL_ENTER("wolfSSL_CTX_clear_mode");
        switch(mode) {
            case WOLFSSL_MODE_ENABLE_PARTIAL_WRITE:
                ctx->partialWrite = 0;
                break;
            #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            case SSL_MODE_RELEASE_BUFFERS:
                WOLFSSL_MSG("SSL_MODE_RELEASE_BUFFERS not implemented.");
                break;
            #endif
            case WOLFSSL_MODE_AUTO_RETRY:
                ctx->autoRetry = 0;
                break;
            default:
                WOLFSSL_MSG("Mode Not Implemented");
        }

        /* WOLFSSL_MODE_AUTO_RETRY
         * Should not return WOLFSSL_FATAL_ERROR with renegotiation on read/write */

        return 0;
    }
#endif

#ifdef OPENSSL_EXTRA

    #ifndef NO_WOLFSSL_STUB
    long wolfSSL_SSL_get_mode(WOLFSSL* ssl)
    {
        /* TODO: */
        (void)ssl;
        WOLFSSL_STUB("SSL_get_mode");
        return 0;
    }
    #endif

    #ifndef NO_WOLFSSL_STUB
    long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx)
    {
        /* TODO: */
        (void)ctx;
        WOLFSSL_STUB("SSL_CTX_get_mode");
        return 0;
    }
    #endif

    #ifndef NO_WOLFSSL_STUB
    void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m)
    {
        /* TODO: maybe? */
        (void)ctx;
        (void)m;
        WOLFSSL_STUB("SSL_CTX_set_default_read_ahead");
    }
    #endif


    /* returns the unsigned error value and increments the pointer into the
     * error queue.
     *
     * file  pointer to file name
     * line  gets set to line number of error when not NULL
     */
    unsigned long wolfSSL_ERR_get_error_line(const char** file, int* line)
    {
    #ifdef WOLFSSL_HAVE_ERROR_QUEUE
        int ret = wc_PullErrorNode(file, NULL, line);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(BAD_STATE_E))
                return 0; /* no errors in queue */
            WOLFSSL_MSG("Issue getting error node");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error_line", ret);
            ret = 0 - ret; /* return absolute value of error */

            /* panic and try to clear out nodes */
            wc_ClearErrorNodes();
        }
        return (unsigned long)ret;
    #else
        (void)file;
        (void)line;

        return 0;
    #endif
    }


#if (defined(DEBUG_WOLFSSL) || defined(OPENSSL_EXTRA)) && \
    (!defined(_WIN32) && !defined(NO_ERROR_QUEUE))
    static const char WOLFSSL_SYS_ACCEPT_T[]  = "accept";
    static const char WOLFSSL_SYS_BIND_T[]    = "bind";
    static const char WOLFSSL_SYS_CONNECT_T[] = "connect";
    static const char WOLFSSL_SYS_FOPEN_T[]   = "fopen";
    static const char WOLFSSL_SYS_FREAD_T[]   = "fread";
    static const char WOLFSSL_SYS_GETADDRINFO_T[] = "getaddrinfo";
    static const char WOLFSSL_SYS_GETSOCKOPT_T[]  = "getsockopt";
    static const char WOLFSSL_SYS_GETSOCKNAME_T[] = "getsockname";
    static const char WOLFSSL_SYS_GETHOSTBYNAME_T[] = "gethostbyname";
    static const char WOLFSSL_SYS_GETNAMEINFO_T[]   = "getnameinfo";
    static const char WOLFSSL_SYS_GETSERVBYNAME_T[] = "getservbyname";
    static const char WOLFSSL_SYS_IOCTLSOCKET_T[]   = "ioctlsocket";
    static const char WOLFSSL_SYS_LISTEN_T[]        = "listen";
    static const char WOLFSSL_SYS_OPENDIR_T[]       = "opendir";
    static const char WOLFSSL_SYS_SETSOCKOPT_T[]    = "setsockopt";
    static const char WOLFSSL_SYS_SOCKET_T[]        = "socket";

    /* switch with int mapped to function name for compatibility */
    static const char* wolfSSL_ERR_sys_func(int fun)
    {
        switch (fun) {
            case WOLFSSL_SYS_ACCEPT:      return WOLFSSL_SYS_ACCEPT_T;
            case WOLFSSL_SYS_BIND:        return WOLFSSL_SYS_BIND_T;
            case WOLFSSL_SYS_CONNECT:     return WOLFSSL_SYS_CONNECT_T;
            case WOLFSSL_SYS_FOPEN:       return WOLFSSL_SYS_FOPEN_T;
            case WOLFSSL_SYS_FREAD:       return WOLFSSL_SYS_FREAD_T;
            case WOLFSSL_SYS_GETADDRINFO: return WOLFSSL_SYS_GETADDRINFO_T;
            case WOLFSSL_SYS_GETSOCKOPT:  return WOLFSSL_SYS_GETSOCKOPT_T;
            case WOLFSSL_SYS_GETSOCKNAME: return WOLFSSL_SYS_GETSOCKNAME_T;
            case WOLFSSL_SYS_GETHOSTBYNAME: return WOLFSSL_SYS_GETHOSTBYNAME_T;
            case WOLFSSL_SYS_GETNAMEINFO: return WOLFSSL_SYS_GETNAMEINFO_T;
            case WOLFSSL_SYS_GETSERVBYNAME: return WOLFSSL_SYS_GETSERVBYNAME_T;
            case WOLFSSL_SYS_IOCTLSOCKET: return WOLFSSL_SYS_IOCTLSOCKET_T;
            case WOLFSSL_SYS_LISTEN:      return WOLFSSL_SYS_LISTEN_T;
            case WOLFSSL_SYS_OPENDIR:     return WOLFSSL_SYS_OPENDIR_T;
            case WOLFSSL_SYS_SETSOCKOPT:  return WOLFSSL_SYS_SETSOCKOPT_T;
            case WOLFSSL_SYS_SOCKET:      return WOLFSSL_SYS_SOCKET_T;
            default:
                return "NULL";
        }
    }
#endif /* DEBUG_WOLFSSL */


    void wolfSSL_ERR_put_error(int lib, int fun, int err, const char* file,
            int line)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_put_error");

        #if !defined(DEBUG_WOLFSSL) && !defined(OPENSSL_EXTRA)
        (void)fun;
        (void)err;
        (void)file;
        (void)line;
        WOLFSSL_MSG("Not compiled in debug mode");
        #elif defined(OPENSSL_EXTRA) && \
                (defined(_WIN32) || defined(NO_ERROR_QUEUE))
        (void)fun;
        (void)file;
        (void)line;
        WOLFSSL_ERROR(err);
        #else
        WOLFSSL_ERROR_LINE(err, wolfSSL_ERR_sys_func(fun), (unsigned int)line,
            file, NULL);
        #endif
        (void)lib;
    }


    /* Similar to wolfSSL_ERR_get_error_line but takes in a flags argument for
     * more flexibility.
     *
     * file  output pointer to file where error happened
     * line  output to line number of error
     * data  output data. Is a string if WOLFSSL_ERR_TXT_STRING flag is used
     * flags output format of output
     *
     * Returns the error value or 0 if no errors are in the queue
     */
    unsigned long wolfSSL_ERR_get_error_line_data(const char** file, int* line,
                                                  const char** data, int *flags)
    {
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
        int ret;

        WOLFSSL_ENTER("wolfSSL_ERR_get_error_line_data");

        if (flags != NULL)
            *flags = WOLFSSL_ERR_TXT_STRING; /* Clear the flags */

        ret = wc_PullErrorNode(file, data, line);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(BAD_STATE_E))
                return 0; /* no errors in queue */
            WOLFSSL_MSG("Error with pulling error node!");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error_line_data", ret);
            ret = 0 - ret; /* return absolute value of error */

            /* panic and try to clear out nodes */
            wc_ClearErrorNodes();
        }

        return (unsigned long)ret;
#else
        WOLFSSL_ENTER("wolfSSL_ERR_get_error_line_data");
        WOLFSSL_MSG("Error queue turned off, can not get error line");
        (void)file;
        (void)line;
        (void)data;
        (void)flags;
        return 0;
#endif
    }

#endif /* OPENSSL_EXTRA */


#if (defined(KEEP_PEER_CERT) && defined(SESSION_CERTS)) || \
    (defined(OPENSSL_EXTRA) && defined(SESSION_CERTS))
    /* Decode the X509 DER encoded certificate into a WOLFSSL_X509 object.
     *
     * x509  WOLFSSL_X509 object to decode into.
     * in    X509 DER data.
     * len   Length of the X509 DER data.
     * returns the new certificate on success, otherwise NULL.
     */
    static int DecodeToX509(WOLFSSL_X509* x509, const byte* in, int len)
    {
        int          ret;
    #ifdef WOLFSSL_SMALL_STACK
        DecodedCert* cert;
    #else
        DecodedCert  cert[1];
    #endif
        if (x509 == NULL || in == NULL || len <= 0)
            return BAD_FUNC_ARG;

    #ifdef WOLFSSL_SMALL_STACK
        cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                     DYNAMIC_TYPE_DCERT);
        if (cert == NULL)
            return MEMORY_E;
    #endif

        /* Create a DecodedCert object and copy fields into WOLFSSL_X509 object.
         */
        InitDecodedCert(cert, (byte*)in, (word32)len, NULL);
        if ((ret = ParseCertRelative(cert, CERT_TYPE, 0, NULL, NULL)) == 0) {
        /* Check if x509 was not previously initialized by wolfSSL_X509_new() */
            if (x509->dynamicMemory != TRUE)
                InitX509(x509, 0, NULL);
            ret = CopyDecodedToX509(x509, cert);
        }
        FreeDecodedCert(cert);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
    #endif

        return ret;
    }
#endif /* (KEEP_PEER_CERT & SESSION_CERTS) || (OPENSSL_EXTRA & SESSION_CERTS) */


#ifdef KEEP_PEER_CERT
    WOLFSSL_ABI
    WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl)
    {
        WOLFSSL_X509* ret = NULL;
        WOLFSSL_ENTER("wolfSSL_get_peer_certificate");
        if (ssl != NULL) {
            if (ssl->peerCert.issuer.sz)
                ret = wolfSSL_X509_dup(&ssl->peerCert);
#ifdef SESSION_CERTS
            else if (ssl->session->chain.count > 0) {
                if (DecodeToX509(&ssl->peerCert,
                        ssl->session->chain.certs[0].buffer,
                        ssl->session->chain.certs[0].length) == 0) {
                    ret = wolfSSL_X509_dup(&ssl->peerCert);
                }
            }
#endif
        }
        WOLFSSL_LEAVE("wolfSSL_get_peer_certificate", ret != NULL);
        return ret;
    }

#endif /* KEEP_PEER_CERT */

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
/* Return stack of peer certs.
 * Caller does not need to free return. The stack is Free'd when WOLFSSL* ssl
 * is.
 */
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_peer_cert_chain");

    if (ssl == NULL)
        return NULL;

    /* Try to populate if NULL or empty */
    if (ssl->peerCertChain == NULL ||
            wolfSSL_sk_X509_num(ssl->peerCertChain) == 0)
        wolfSSL_set_peer_cert_chain((WOLFSSL*) ssl);
    return ssl->peerCertChain;
}

#ifndef WOLFSSL_QT
static int x509GetIssuerFromCM(WOLFSSL_X509 **issuer, WOLFSSL_CERT_MANAGER* cm,
        WOLFSSL_X509 *x);
/**
 * Recursively push the issuer CA chain onto the stack
 * @param cm The cert manager that is queried for the issuer
 * @param x  This cert's issuer will be queried in cm
 * @param sk The issuer is pushed onto this stack
 * @return WOLFSSL_SUCCESS on success
 *         WOLFSSL_FAILURE on no issuer found
 *         WOLFSSL_FATAL_ERROR on a fatal error
 */
static int PushCAx509Chain(WOLFSSL_CERT_MANAGER* cm,
        WOLFSSL_X509 *x, WOLFSSL_STACK* sk)
{
    WOLFSSL_X509* issuer[MAX_CHAIN_DEPTH];
    int i;
    int push = 1;
    int ret = WOLFSSL_SUCCESS;

    for (i = 0; i < MAX_CHAIN_DEPTH; i++) {
        if (x509GetIssuerFromCM(&issuer[i], cm, x)
                != WOLFSSL_SUCCESS)
            break;
        x = issuer[i];
    }
    if (i == 0) /* No further chain found */
        return WOLFSSL_FAILURE;
    i--;
    for (; i >= 0; i--) {
        if (push) {
            if (wolfSSL_sk_X509_push(sk, issuer[i]) <= 0) {
                wolfSSL_X509_free(issuer[i]);
                ret = WOLFSSL_FATAL_ERROR;
                push = 0; /* Free the rest of the unpushed certs */
            }
        }
        else {
            wolfSSL_X509_free(issuer[i]);
        }
    }
    return ret;
}
#endif /* !WOLFSSL_QT */

/* Builds up and creates a stack of peer certificates for ssl->peerCertChain
    based off of the ssl session chain. Attempts to place CA certificates
    at the bottom of the stack. Returns stack of WOLFSSL_X509 certs or
    NULL on failure */
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_set_peer_cert_chain(WOLFSSL* ssl)
{
    WOLFSSL_STACK* sk;
    WOLFSSL_X509* x509;
    int i = 0;
    int ret;

    WOLFSSL_ENTER("wolfSSL_set_peer_cert_chain");
    if ((ssl == NULL) || (ssl->session->chain.count == 0))
        return NULL;

    sk = wolfSSL_sk_X509_new_null();
    i = ssl->session->chain.count-1;
    for (; i >= 0; i--) {
        x509 = wolfSSL_X509_new_ex(ssl->heap);
        if (x509 == NULL) {
            WOLFSSL_MSG("Error Creating X509");
            wolfSSL_sk_X509_pop_free(sk, NULL);
            return NULL;
        }
        ret = DecodeToX509(x509, ssl->session->chain.certs[i].buffer,
                             ssl->session->chain.certs[i].length);
#if !defined(WOLFSSL_QT)
        if (ret == 0 && i == ssl->session->chain.count-1) {
            /* On the last element in the chain try to add the CA chain
             * first if we have one for this cert */
            SSL_CM_WARNING(ssl);
            if (PushCAx509Chain(SSL_CM(ssl), x509, sk)
                    == WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
#endif

        if (ret != 0 || wolfSSL_sk_X509_push(sk, x509) <= 0) {
            WOLFSSL_MSG("Error decoding cert");
            wolfSSL_X509_free(x509);
            wolfSSL_sk_X509_pop_free(sk, NULL);
            return NULL;
        }
    }

    if (sk == NULL) {
        WOLFSSL_MSG("Null session chain");
    }
#if defined(OPENSSL_ALL)
    else if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* to be compliant with openssl
           first element is kept as peer cert on server side.*/
        wolfSSL_sk_X509_pop(sk);
    }
#endif
    if (ssl->peerCertChain != NULL)
        wolfSSL_sk_X509_pop_free(ssl->peerCertChain, NULL);
    /* This is Free'd when ssl is Free'd */
    ssl->peerCertChain = sk;
    return sk;
}
#endif /* SESSION_CERTS && OPENSSL_EXTRA */

#ifndef NO_CERTS
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

/* create a generic wolfSSL stack node
 * returns a new WOLFSSL_STACK structure on success */
WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap)
{
    WOLFSSL_STACK* sk;
    WOLFSSL_ENTER("wolfSSL_sk_new_node");

    sk = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), heap,
                                                          DYNAMIC_TYPE_OPENSSL);
    if (sk != NULL) {
        XMEMSET(sk, 0, sizeof(*sk));
        sk->heap = heap;
    }

    return sk;
}

/* free's node but does not free internal data such as in->data.x509 */
void wolfSSL_sk_free_node(WOLFSSL_STACK* in)
{
    if (in != NULL) {
        XFREE(in, in->heap, DYNAMIC_TYPE_OPENSSL);
    }
}

/* pushes node "in" onto "stack" and returns pointer to the new stack on success
 * also handles internal "num" for number of nodes on stack
 * return WOLFSSL_SUCCESS on success
 */
int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in)
{
    if (stack == NULL || in == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (*stack == NULL) {
        in->num = 1;
        *stack = in;
        return WOLFSSL_SUCCESS;
    }

    in->num  = (*stack)->num + 1;
    in->next = *stack;
    *stack   = in;
    return WOLFSSL_SUCCESS;
}

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
static WC_INLINE int compare_WOLFSSL_CIPHER(
    WOLFSSL_CIPHER *a,
    WOLFSSL_CIPHER *b)
{
    if ((a->cipherSuite0 == b->cipherSuite0) &&
        (a->cipherSuite == b->cipherSuite) &&
        (a->ssl == b->ssl) &&
        (XMEMCMP(a->description, b->description, sizeof a->description) == 0) &&
        (a->offset == b->offset) &&
        (a->in_stack == b->in_stack) &&
        (a->bits == b->bits))
        return 0;
    else
        return WOLFSSL_FATAL_ERROR;
}
#endif /* OPENSSL_ALL || WOLFSSL_QT */


/* return number of elements on success 0 on fail */
int wolfSSL_sk_push(WOLFSSL_STACK* sk, const void *data)
{
    WOLFSSL_ENTER("wolfSSL_sk_push");

    return wolfSSL_sk_insert(sk, data, 0);
}

/* return number of elements on success 0 on fail */
int wolfSSL_sk_insert(WOLFSSL_STACK *sk, const void *data, int idx)
{
    WOLFSSL_STACK* node;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    WOLFSSL_CIPHER ciph;
#endif
    WOLFSSL_ENTER("wolfSSL_sk_insert");

    if (!sk)
        return WOLFSSL_FATAL_ERROR;
    if (!data)
        return WOLFSSL_FAILURE;

    if (idx == 0 || sk->num == 0) {
        /* Check if empty data */
        switch (sk->type) {
            case STACK_TYPE_CIPHER:
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
                /* check if entire struct is zero */
                XMEMSET(&ciph, 0, sizeof(WOLFSSL_CIPHER));
                if (compare_WOLFSSL_CIPHER(&sk->data.cipher, &ciph) == 0) {
                    sk->data.cipher = *(WOLFSSL_CIPHER*)data;
                    sk->num = 1;
                    if (sk->hash_fn) {
                        sk->hash = sk->hash_fn(&sk->data.cipher);
                    }
                    return (int)sk->num;
                }
                if (sk->num == 0)
                    sk->num = 1; /* confirmed at least one element */
                break;
#endif
            case STACK_TYPE_X509:
            case STACK_TYPE_GEN_NAME:
            case STACK_TYPE_BIO:
            case STACK_TYPE_OBJ:
            case STACK_TYPE_STRING:
            case STACK_TYPE_ACCESS_DESCRIPTION:
            case STACK_TYPE_X509_EXT:
            case STACK_TYPE_X509_REQ_ATTR:
            case STACK_TYPE_NULL:
            case STACK_TYPE_X509_NAME:
            case STACK_TYPE_X509_NAME_ENTRY:
            case STACK_TYPE_CONF_VALUE:
            case STACK_TYPE_X509_INFO:
            case STACK_TYPE_BY_DIR_entry:
            case STACK_TYPE_BY_DIR_hash:
            case STACK_TYPE_X509_OBJ:
            case STACK_TYPE_DIST_POINT:
            case STACK_TYPE_X509_CRL:
            default:
                /* All other types are pointers */
                if (!sk->data.generic) {
                    sk->data.generic = (void*)data;
                    sk->num = 1;
#ifdef OPENSSL_ALL
                    if (sk->hash_fn)
                        sk->hash = sk->hash_fn(sk->data.generic);
#endif
                    return (int)sk->num;
                }
                if (sk->num == 0)
                    sk->num = 1; /* confirmed at least one element */
                break;
        }
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(sk->heap);
    if (!node) {
        WOLFSSL_MSG("Memory error");
        return WOLFSSL_FAILURE;
    }
    node->type      = sk->type;
    sk->num        += 1;
#ifdef OPENSSL_ALL
    node->hash_fn = sk->hash_fn;
#endif

    if (idx == 0) {
        /* Special case where we need to change the values in the head element
         * to avoid changing the initial pointer. */
        /* push new item onto head of stack */
        node->next      = sk->next;
        sk->next        = node;
#ifdef OPENSSL_ALL
        node->hash = sk->hash;
        sk->hash = 0;
#endif
        switch (sk->type) {
            case STACK_TYPE_CIPHER:
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
                node->data.cipher = sk->data.cipher;
                sk->data.cipher = *(WOLFSSL_CIPHER*)data;
                if (sk->hash_fn) {
                    sk->hash = sk->hash_fn(&sk->data.cipher);
                }
                break;
#endif
            case STACK_TYPE_X509:
            case STACK_TYPE_GEN_NAME:
            case STACK_TYPE_BIO:
            case STACK_TYPE_OBJ:
            case STACK_TYPE_STRING:
            case STACK_TYPE_ACCESS_DESCRIPTION:
            case STACK_TYPE_X509_EXT:
            case STACK_TYPE_X509_REQ_ATTR:
            case STACK_TYPE_NULL:
            case STACK_TYPE_X509_NAME:
            case STACK_TYPE_X509_NAME_ENTRY:
            case STACK_TYPE_CONF_VALUE:
            case STACK_TYPE_X509_INFO:
            case STACK_TYPE_BY_DIR_entry:
            case STACK_TYPE_BY_DIR_hash:
            case STACK_TYPE_X509_OBJ:
            case STACK_TYPE_DIST_POINT:
            case STACK_TYPE_X509_CRL:
            default:
                /* All other types are pointers */
                node->data.generic = sk->data.generic;
                sk->data.generic = (void*)data;
#ifdef OPENSSL_ALL
                if (sk->hash_fn)
                    sk->hash = sk->hash_fn(sk->data.generic);
#endif
                break;
        }

        return (int)sk->num;
    }

    /* populate node */
    switch (sk->type) {
        case STACK_TYPE_CIPHER:
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            node->data.cipher = *(WOLFSSL_CIPHER*)data;
            if (node->hash_fn)
                node->hash = node->hash_fn(&node->data.cipher);
            break;
#endif
        case STACK_TYPE_X509:
        case STACK_TYPE_GEN_NAME:
        case STACK_TYPE_BIO:
        case STACK_TYPE_OBJ:
        case STACK_TYPE_STRING:
        case STACK_TYPE_ACCESS_DESCRIPTION:
        case STACK_TYPE_X509_EXT:
        case STACK_TYPE_X509_REQ_ATTR:
        case STACK_TYPE_NULL:
        case STACK_TYPE_X509_NAME:
        case STACK_TYPE_X509_NAME_ENTRY:
        case STACK_TYPE_CONF_VALUE:
        case STACK_TYPE_X509_INFO:
        case STACK_TYPE_BY_DIR_entry:
        case STACK_TYPE_BY_DIR_hash:
        case STACK_TYPE_X509_OBJ:
        case STACK_TYPE_DIST_POINT:
        case STACK_TYPE_X509_CRL:
        default:
            /* All other types are pointers */
            node->data.generic = (void*)data;
#ifdef OPENSSL_ALL
            if (node->hash_fn)
                node->hash = node->hash_fn(node->data.generic);
#endif
            break;
    }
    {
        /* insert node into stack. not using sk since we return sk->num after */
        WOLFSSL_STACK* prev_node = sk;
        while (idx != 0 && prev_node->next != NULL) {
            prev_node = prev_node->next;
            idx--;
        }
        node->next = prev_node->next;
        prev_node->next = node;
    }

    return (int)sk->num;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA

/* returns the node at index "idx", NULL if not found */
WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx)
{
    int i;
    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK* current;

    current = sk;
    for (i = 0; i <= idx && current != NULL; i++) {
        if (i == idx) {
            ret = current;
            break;
        }
        current = current->next;
    }
    return ret;
}


#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA

#if defined(OPENSSL_ALL)

void *wolfSSL_lh_retrieve(WOLFSSL_STACK *sk, void *data)
{
    unsigned long hash;

    WOLFSSL_ENTER("wolfSSL_lh_retrieve");

    if (!sk || !data) {
        WOLFSSL_MSG("Bad parameters");
        return NULL;
    }

    if (!sk->hash_fn) {
        WOLFSSL_MSG("No hash function defined");
        return NULL;
    }

    hash = sk->hash_fn(data);

    while (sk) {
        /* Calc hash if not done so yet */
        if (!sk->hash) {
            switch (sk->type) {
                case STACK_TYPE_CIPHER:
                    sk->hash = sk->hash_fn(&sk->data.cipher);
                    break;
                case STACK_TYPE_X509:
                case STACK_TYPE_GEN_NAME:
                case STACK_TYPE_BIO:
                case STACK_TYPE_OBJ:
                case STACK_TYPE_STRING:
                case STACK_TYPE_ACCESS_DESCRIPTION:
                case STACK_TYPE_X509_EXT:
                case STACK_TYPE_X509_REQ_ATTR:
                case STACK_TYPE_NULL:
                case STACK_TYPE_X509_NAME:
                case STACK_TYPE_X509_NAME_ENTRY:
                case STACK_TYPE_CONF_VALUE:
                case STACK_TYPE_X509_INFO:
                case STACK_TYPE_BY_DIR_entry:
                case STACK_TYPE_BY_DIR_hash:
                case STACK_TYPE_X509_OBJ:
                case STACK_TYPE_DIST_POINT:
                case STACK_TYPE_X509_CRL:
                default:
                    sk->hash = sk->hash_fn(sk->data.generic);
                    break;
            }
        }
        if (sk->hash == hash) {
            switch (sk->type) {
                case STACK_TYPE_CIPHER:
                    return &sk->data.cipher;
                case STACK_TYPE_X509:
                case STACK_TYPE_GEN_NAME:
                case STACK_TYPE_BIO:
                case STACK_TYPE_OBJ:
                case STACK_TYPE_STRING:
                case STACK_TYPE_ACCESS_DESCRIPTION:
                case STACK_TYPE_X509_EXT:
                case STACK_TYPE_X509_REQ_ATTR:
                case STACK_TYPE_NULL:
                case STACK_TYPE_X509_NAME:
                case STACK_TYPE_X509_NAME_ENTRY:
                case STACK_TYPE_CONF_VALUE:
                case STACK_TYPE_X509_INFO:
                case STACK_TYPE_BY_DIR_entry:
                case STACK_TYPE_BY_DIR_hash:
                case STACK_TYPE_X509_OBJ:
                case STACK_TYPE_DIST_POINT:
                case STACK_TYPE_X509_CRL:
                default:
                    return sk->data.generic;
            }
        }
        sk = sk->next;
    }

    return NULL;
}

#endif /* OPENSSL_ALL */

#endif /* OPENSSL_EXTRA */

/* OPENSSL_EXTRA is needed for wolfSSL_X509_d21 function
   KEEP_OUR_CERT is to insure ability for returning ssl certificate */
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    defined(KEEP_OUR_CERT)
WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }

    if (ssl->buffers.weOwnCert) {
        if (ssl->ourCert == NULL) {
            if (ssl->buffers.certificate == NULL) {
                WOLFSSL_MSG("Certificate buffer not set!");
                return NULL;
            }
            #ifndef WOLFSSL_X509_STORE_CERTS
            ssl->ourCert = wolfSSL_X509_d2i_ex(NULL,
                                              ssl->buffers.certificate->buffer,
                                              ssl->buffers.certificate->length,
                                              ssl->heap);
            #endif
        }
        return ssl->ourCert;
    }
    else { /* if cert not owned get parent ctx cert or return null */
        if (ssl->ctx) {
            if (ssl->ctx->ourCert == NULL) {
                if (ssl->ctx->certificate == NULL) {
                    WOLFSSL_MSG("Ctx Certificate buffer not set!");
                    return NULL;
                }
                #ifndef WOLFSSL_X509_STORE_CERTS
                ssl->ctx->ourCert = wolfSSL_X509_d2i_ex(NULL,
                                               ssl->ctx->certificate->buffer,
                                               ssl->ctx->certificate->length,
                                               ssl->heap);
                #endif
                ssl->ctx->ownOurCert = 1;
            }
            return ssl->ctx->ourCert;
        }
    }

    return NULL;
}

WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx)
{
    if (ctx) {
        if (ctx->ourCert == NULL) {
            if (ctx->certificate == NULL) {
                WOLFSSL_MSG("Ctx Certificate buffer not set!");
                return NULL;
            }
            #ifndef WOLFSSL_X509_STORE_CERTS
            ctx->ourCert = wolfSSL_X509_d2i_ex(NULL,
                                           ctx->certificate->buffer,
                                           ctx->certificate->length, ctx->heap);
            #endif
            ctx->ownOurCert = 1;
        }
        return ctx->ourCert;
    }
    return NULL;
}
#endif /* OPENSSL_EXTRA && KEEP_OUR_CERT */
#endif /* NO_CERTS */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
void wolfSSL_set_connect_state(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_set_connect_state");
    if (ssl == NULL) {
        WOLFSSL_MSG("WOLFSSL struct pointer passed in was null");
        return;
    }

    #ifndef NO_DH
    /* client creates its own DH parameters on handshake */
    if (ssl->buffers.serverDH_P.buffer && ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
    }
    ssl->buffers.serverDH_P.buffer = NULL;
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
    }
    ssl->buffers.serverDH_G.buffer = NULL;
    #endif

    if (InitSSL_Side(ssl, WOLFSSL_CLIENT_END) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error initializing client side");
    }
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */


int wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    int isShutdown = 0;

    WOLFSSL_ENTER("wolfSSL_get_shutdown");

    if (ssl) {
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
        if (ssl->options.shutdownDone) {
            /* The SSL object was possibly cleared with wolfSSL_clear after
             * a successful shutdown. Simulate a response for a full
             * bidirectional shutdown. */
            isShutdown = WOLFSSL_SENT_SHUTDOWN | WOLFSSL_RECEIVED_SHUTDOWN;
        }
        else
#endif
        {
            /* in OpenSSL, WOLFSSL_SENT_SHUTDOWN = 1, when closeNotifySent   *
             * WOLFSSL_RECEIVED_SHUTDOWN = 2, from close notify or fatal err */
            if (ssl->options.sentNotify)
                isShutdown |= WOLFSSL_SENT_SHUTDOWN;
            if (ssl->options.closeNotify||ssl->options.connReset)
                isShutdown |= WOLFSSL_RECEIVED_SHUTDOWN;
        }

    }

    WOLFSSL_LEAVE("wolfSSL_get_shutdown", isShutdown);
    return isShutdown;
}


int wolfSSL_session_reused(WOLFSSL* ssl)
{
    int resuming = 0;
    WOLFSSL_ENTER("wolfSSL_session_reused");
    if (ssl) {
#ifndef HAVE_SECURE_RENEGOTIATION
        resuming = ssl->options.resuming;
#else
        resuming = ssl->options.resuming || ssl->options.resumed;
#endif
    }
    WOLFSSL_LEAVE("wolfSSL_session_reused", resuming);
    return resuming;
}

/* helper function that takes in a protocol version struct and returns string */
static const char* wolfSSL_internal_get_version(const ProtocolVersion* version)
{
    WOLFSSL_ENTER("wolfSSL_get_version");

    if (version == NULL) {
        return "Bad arg";
    }

    if (version->major == SSLv3_MAJOR) {
        switch (version->minor) {
            case SSLv3_MINOR :
                return "SSLv3";
            case TLSv1_MINOR :
                return "TLSv1";
            case TLSv1_1_MINOR :
                return "TLSv1.1";
            case TLSv1_2_MINOR :
                return "TLSv1.2";
            case TLSv1_3_MINOR :
                return "TLSv1.3";
            default:
                return "unknown";
        }
    }
#ifdef WOLFSSL_DTLS
    else if (version->major == DTLS_MAJOR) {
        switch (version->minor) {
            case DTLS_MINOR :
                return "DTLS";
            case DTLSv1_2_MINOR :
                return "DTLSv1.2";
            case DTLSv1_3_MINOR :
                return "DTLSv1.3";
            default:
                return "unknown";
        }
    }
#endif /* WOLFSSL_DTLS */
    return "unknown";
}


const char* wolfSSL_get_version(const WOLFSSL* ssl)
{
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad argument");
        return "unknown";
    }

    return wolfSSL_internal_get_version(&ssl->version);
}


/* current library version */
const char* wolfSSL_lib_version(void)
{
    return LIBWOLFSSL_VERSION_STRING;
}

#ifdef OPENSSL_EXTRA
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
const char* wolfSSL_OpenSSL_version(int a)
{
    (void)a;
    return "wolfSSL " LIBWOLFSSL_VERSION_STRING;
}
#else
const char* wolfSSL_OpenSSL_version(void)
{
    return "wolfSSL " LIBWOLFSSL_VERSION_STRING;
}
#endif /* WOLFSSL_QT */
#endif


/* current library version in hex */
word32 wolfSSL_lib_version_hex(void)
{
    return LIBWOLFSSL_VERSION_HEX;
}


int wolfSSL_get_current_cipher_suite(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_current_cipher_suite");
    if (ssl)
        return (ssl->options.cipherSuite0 << 8) | ssl->options.cipherSuite;
    return 0;
}

WOLFSSL_CIPHER* wolfSSL_get_current_cipher(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_current_cipher");
    if (ssl) {
        ssl->cipher.cipherSuite0 = ssl->options.cipherSuite0;
        ssl->cipher.cipherSuite  = ssl->options.cipherSuite;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        ssl->cipher.bits = ssl->specs.key_size * 8;
#endif
        return &ssl->cipher;
    }
    else
        return NULL;
}


const char* wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("wolfSSL_CIPHER_get_name");

    if (cipher == NULL) {
        return NULL;
    }

    #if !defined(WOLFSSL_CIPHER_INTERNALNAME) && !defined(NO_ERROR_STRINGS) && \
        !defined(WOLFSSL_QT)
        return GetCipherNameIana(cipher->cipherSuite0, cipher->cipherSuite);
    #else
        return wolfSSL_get_cipher_name_from_suite(cipher->cipherSuite0,
                cipher->cipherSuite);
    #endif
}

const char*  wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("wolfSSL_CIPHER_get_version");

    if (cipher == NULL || cipher->ssl == NULL) {
        return NULL;
    }

    return wolfSSL_get_version(cipher->ssl);
}

const char* wolfSSL_get_cipher(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_cipher");
    return wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(ssl));
}

/* gets cipher name in the format DHE-RSA-... rather then TLS_DHE... */
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl)
{
    /* get access to cipher_name_idx in internal.c */
    return wolfSSL_get_cipher_name_internal(ssl);
}

const char* wolfSSL_get_cipher_name_from_suite(byte cipherSuite0,
    byte cipherSuite)
{
    return GetCipherNameInternal(cipherSuite0, cipherSuite);
}

const char* wolfSSL_get_cipher_name_iana_from_suite(byte cipherSuite0,
        byte cipherSuite)
{
    return GetCipherNameIana(cipherSuite0, cipherSuite);
}

int wolfSSL_get_cipher_suite_from_name(const char* name, byte* cipherSuite0,
                                       byte* cipherSuite, int *flags) {
    if ((name == NULL) ||
        (cipherSuite0 == NULL) ||
        (cipherSuite == NULL) ||
        (flags == NULL))
        return BAD_FUNC_ARG;
    return GetCipherSuiteFromName(name, cipherSuite0, cipherSuite, NULL, NULL,
                                  flags);
}


#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
/* Creates and returns a new WOLFSSL_CIPHER stack. */
WOLFSSL_STACK* wolfSSL_sk_new_cipher(void)
{
    WOLFSSL_STACK* sk;
    WOLFSSL_ENTER("wolfSSL_sk_new_cipher");

    sk = wolfSSL_sk_new_null();
    if (sk == NULL)
        return NULL;
    sk->type = STACK_TYPE_CIPHER;

    return sk;
}

/* return 1 on success 0 on fail */
int wolfSSL_sk_CIPHER_push(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk,
                                                      WOLFSSL_CIPHER* cipher)
{
    return wolfSSL_sk_push(sk, cipher);
}

#ifndef NO_WOLFSSL_STUB
WOLFSSL_CIPHER* wolfSSL_sk_CIPHER_pop(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk)
{
    WOLFSSL_STUB("wolfSSL_sk_CIPHER_pop");
    (void)sk;
    return NULL;
}
#endif /* NO_WOLFSSL_STUB */
#endif /* WOLFSSL_QT || OPENSSL_ALL */

word32 wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher)
{
    word16 cipher_id = 0;

    WOLFSSL_ENTER("wolfSSL_CIPHER_get_id");

    if (cipher && cipher->ssl) {
        cipher_id = (word16)(cipher->ssl->options.cipherSuite0 << 8) |
                     cipher->ssl->options.cipherSuite;
    }

    return cipher_id;
}

const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value)
{
    const WOLFSSL_CIPHER* cipher = NULL;
    byte cipherSuite0, cipherSuite;
    WOLFSSL_ENTER("wolfSSL_get_cipher_by_value");

    /* extract cipher id information */
    cipherSuite =   (value       & 0xFF);
    cipherSuite0 = ((value >> 8) & 0xFF);

    /* TODO: lookup by cipherSuite0 / cipherSuite */
    (void)cipherSuite0;
    (void)cipherSuite;

    return cipher;
}


#if defined(OPENSSL_EXTRA)
/* Free the structure for WOLFSSL_CIPHER stack
 *
 * sk  stack to free nodes in
 */
void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_CIPHER_free");

    wolfSSL_sk_free(sk);
}
#endif /* OPENSSL_ALL */

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448) || \
                                                                 !defined(NO_DH)
#ifdef HAVE_FFDHE
static const char* wolfssl_ffdhe_name(word16 group)
{
    const char* str = NULL;
    switch (group) {
        case WOLFSSL_FFDHE_2048:
            str = "FFDHE_2048";
            break;
        case WOLFSSL_FFDHE_3072:
            str = "FFDHE_3072";
            break;
        case WOLFSSL_FFDHE_4096:
            str = "FFDHE_4096";
            break;
        case WOLFSSL_FFDHE_6144:
            str = "FFDHE_6144";
            break;
        case WOLFSSL_FFDHE_8192:
            str = "FFDHE_8192";
            break;
        default:
            break;
    }
    return str;
}
#endif
/* Return the name of the curve used for key exchange as a printable string.
 *
 * ssl  The SSL/TLS object.
 * returns NULL if ECDH was not used, otherwise the name as a string.
 */
const char* wolfSSL_get_curve_name(WOLFSSL* ssl)
{
    const char* cName = NULL;

    WOLFSSL_ENTER("wolfSSL_get_curve_name");

    if (ssl == NULL)
        return NULL;

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_HAVE_KYBER)
    /* Check for post-quantum groups. Return now because we do not want the ECC
     * check to override this result in the case of a hybrid. */
    if (IsAtLeastTLSv1_3(ssl->version)) {
        switch (ssl->namedGroup) {
#ifndef WOLFSSL_NO_ML_KEM
#ifdef HAVE_LIBOQS
        case WOLFSSL_ML_KEM_512:
            return "ML_KEM_512";
        case WOLFSSL_ML_KEM_768:
            return "ML_KEM_768";
        case WOLFSSL_ML_KEM_1024:
            return "ML_KEM_1024";
        case WOLFSSL_P256_ML_KEM_512:
            return "P256_ML_KEM_512";
        case WOLFSSL_P384_ML_KEM_768:
            return "P384_ML_KEM_768";
        case WOLFSSL_P521_ML_KEM_1024:
            return "P521_ML_KEM_1024";
#elif defined(WOLFSSL_WC_KYBER)
    #ifndef WOLFSSL_NO_ML_KEM_512
        case WOLFSSL_ML_KEM_512:
            return "ML_KEM_512";
        case WOLFSSL_P256_ML_KEM_512:
            return "P256_ML_KEM_512";
    #endif
    #ifndef WOLFSSL_NO_ML_KEM_768
        case WOLFSSL_ML_KEM_768:
            return "ML_KEM_768";
        case WOLFSSL_P384_ML_KEM_768:
            return "P384_ML_KEM_768";
    #endif
    #ifndef WOLFSSL_NO_ML_KEM_1024
        case WOLFSSL_ML_KEM_1024:
            return "ML_KEM_1024";
        case WOLFSSL_P521_ML_KEM_1024:
            return "P521_ML_KEM_1024";
    #endif
#endif
#endif
#ifdef WOLFSSL_KYBER_ORIGINAL
#ifdef HAVE_LIBOQS
        case WOLFSSL_KYBER_LEVEL1:
            return "KYBER_LEVEL1";
        case WOLFSSL_KYBER_LEVEL3:
            return "KYBER_LEVEL3";
        case WOLFSSL_KYBER_LEVEL5:
            return "KYBER_LEVEL5";
        case WOLFSSL_P256_KYBER_LEVEL1:
            return "P256_KYBER_LEVEL1";
        case WOLFSSL_P384_KYBER_LEVEL3:
            return "P384_KYBER_LEVEL3";
        case WOLFSSL_P521_KYBER_LEVEL5:
            return "P521_KYBER_LEVEL5";
#elif defined(WOLFSSL_WC_KYBER)
    #ifndef WOLFSSL_NO_KYBER512
        case WOLFSSL_KYBER_LEVEL1:
            return "KYBER_LEVEL1";
        case WOLFSSL_P256_KYBER_LEVEL1:
            return "P256_KYBER_LEVEL1";
    #endif
    #ifndef WOLFSSL_NO_KYBER768
        case WOLFSSL_KYBER_LEVEL3:
            return "KYBER_LEVEL3";
        case WOLFSSL_P384_KYBER_LEVEL3:
            return "P384_KYBER_LEVEL3";
    #endif
    #ifndef WOLFSSL_NO_KYBER1024
        case WOLFSSL_KYBER_LEVEL5:
            return "KYBER_LEVEL5";
        case WOLFSSL_P521_KYBER_LEVEL5:
            return "P521_KYBER_LEVEL5";
    #endif
#endif
#endif
        }
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_HAVE_KYBER */

#ifdef HAVE_FFDHE
    if (ssl->namedGroup != 0) {
        cName = wolfssl_ffdhe_name(ssl->namedGroup);
    }
#endif

#ifdef HAVE_CURVE25519
    if (ssl->ecdhCurveOID == ECC_X25519_OID && cName == NULL) {
        cName = "X25519";
    }
#endif

#ifdef HAVE_CURVE448
    if (ssl->ecdhCurveOID == ECC_X448_OID && cName == NULL) {
        cName = "X448";
    }
#endif

#ifdef HAVE_ECC
    if (ssl->ecdhCurveOID != 0 && cName == NULL) {
        cName = wc_ecc_get_name(wc_ecc_get_oid(ssl->ecdhCurveOID, NULL,
                                NULL));
    }
#endif

    return cName;
}
#endif

#ifdef OPENSSL_EXTRA
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
/* return authentication NID corresponding to cipher suite
 * @param cipher a pointer to WOLFSSL_CIPHER
 * return NID if found, WC_NID_undef if not found
 */
int wolfSSL_CIPHER_get_auth_nid(const WOLFSSL_CIPHER* cipher)
{
    static const struct authnid {
        const char* alg_name;
        const int  nid;
    } authnid_tbl[] = {
        {"RSA",     WC_NID_auth_rsa},
        {"PSK",     WC_NID_auth_psk},
        {"SRP",     WC_NID_auth_srp},
        {"ECDSA",   WC_NID_auth_ecdsa},
        {"None",    WC_NID_auth_null},
        {NULL,      WC_NID_undef}
    };

    const char* authStr;
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};

    if (GetCipherSegment(cipher, n) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WC_NID_undef;
    }

    authStr = GetCipherAuthStr(n);

    if (authStr != NULL) {
        const struct authnid* sa;
        for(sa = authnid_tbl; sa->alg_name != NULL; sa++) {
            if (XSTRCMP(sa->alg_name, authStr) == 0) {
                return sa->nid;
            }
        }
    }

    return WC_NID_undef;
}
/* return cipher NID corresponding to cipher suite
 * @param cipher a pointer to WOLFSSL_CIPHER
 * return NID if found, WC_NID_undef if not found
 */
int wolfSSL_CIPHER_get_cipher_nid(const WOLFSSL_CIPHER* cipher)
{
    static const struct ciphernid {
        const char* alg_name;
        const int  nid;
    } ciphernid_tbl[] = {
        {"AESGCM(256)",             WC_NID_aes_256_gcm},
        {"AESGCM(128)",             WC_NID_aes_128_gcm},
        {"AESCCM(128)",             WC_NID_aes_128_ccm},
        {"AES(128)",                WC_NID_aes_128_cbc},
        {"AES(256)",                WC_NID_aes_256_cbc},
        {"CAMELLIA(256)",           WC_NID_camellia_256_cbc},
        {"CAMELLIA(128)",           WC_NID_camellia_128_cbc},
        {"RC4",                     WC_NID_rc4},
        {"3DES",                    WC_NID_des_ede3_cbc},
        {"CHACHA20/POLY1305(256)",  WC_NID_chacha20_poly1305},
        {"None",                    WC_NID_undef},
        {NULL,                      WC_NID_undef}
    };

    const char* encStr;
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};

    WOLFSSL_ENTER("wolfSSL_CIPHER_get_cipher_nid");

    if (GetCipherSegment(cipher, n) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WC_NID_undef;
    }

    encStr = GetCipherEncStr(n);

    if (encStr != NULL) {
        const struct ciphernid* c;
        for(c = ciphernid_tbl; c->alg_name != NULL; c++) {
            if (XSTRCMP(c->alg_name, encStr) == 0) {
                return c->nid;
            }
        }
    }

    return WC_NID_undef;
}
/* return digest NID corresponding to cipher suite
 * @param cipher a pointer to WOLFSSL_CIPHER
 * return NID if found, WC_NID_undef if not found
 */
int wolfSSL_CIPHER_get_digest_nid(const WOLFSSL_CIPHER* cipher)
{
    static const struct macnid {
        const char* alg_name;
        const int  nid;
    } macnid_tbl[] = {
        {"SHA1",    WC_NID_sha1},
        {"SHA256",  WC_NID_sha256},
        {"SHA384",  WC_NID_sha384},
        {NULL,      WC_NID_undef}
    };

    const char* name;
    const char* macStr;
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};
    (void)name;

    WOLFSSL_ENTER("wolfSSL_CIPHER_get_digest_nid");

    if ((name = GetCipherSegment(cipher, n)) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WC_NID_undef;
    }

    /* in MD5 case, NID will be WC_NID_md5 */
    if (XSTRSTR(name, "MD5") != NULL) {
        return WC_NID_md5;
    }

    macStr = GetCipherMacStr(n);

    if (macStr != NULL) {
        const struct macnid* mc;
        for(mc = macnid_tbl; mc->alg_name != NULL; mc++) {
            if (XSTRCMP(mc->alg_name, macStr) == 0) {
                return mc->nid;
            }
        }
    }

    return WC_NID_undef;
}
/* return key exchange NID corresponding to cipher suite
 * @param cipher a pointer to WOLFSSL_CIPHER
 * return NID if found, WC_NID_undef if not found
 */
int wolfSSL_CIPHER_get_kx_nid(const WOLFSSL_CIPHER* cipher)
{
    static const struct kxnid {
        const char* name;
        const int  nid;
    } kxnid_table[] = {
        {"ECDHEPSK",  WC_NID_kx_ecdhe_psk},
        {"ECDH",      WC_NID_kx_ecdhe},
        {"DHEPSK",    WC_NID_kx_dhe_psk},
        {"DH",        WC_NID_kx_dhe},
        {"RSAPSK",    WC_NID_kx_rsa_psk},
        {"SRP",       WC_NID_kx_srp},
        {"EDH",       WC_NID_kx_dhe},
        {"RSA",       WC_NID_kx_rsa},
        {NULL,        WC_NID_undef}
    };

    const char* keaStr;
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};

    WOLFSSL_ENTER("wolfSSL_CIPHER_get_kx_nid");

    if (GetCipherSegment(cipher, n) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WC_NID_undef;
    }

    /* in TLS 1.3 case, NID will be WC_NID_kx_any */
    if (XSTRCMP(n[0], "TLS13") == 0) {
        return WC_NID_kx_any;
    }

    keaStr = GetCipherKeaStr(n);

    if (keaStr != NULL) {
        const struct kxnid* k;
        for(k = kxnid_table; k->name != NULL; k++) {
            if (XSTRCMP(k->name, keaStr) == 0) {
                return k->nid;
            }
        }
    }

    return WC_NID_undef;
}
/* check if cipher suite is AEAD
 * @param cipher a pointer to WOLFSSL_CIPHER
 * return 1 if cipher is AEAD, 0 otherwise
 */
int wolfSSL_CIPHER_is_aead(const WOLFSSL_CIPHER* cipher)
{
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};

    WOLFSSL_ENTER("wolfSSL_CIPHER_is_aead");

    if (GetCipherSegment(cipher, n) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WC_NID_undef;
    }

    return IsCipherAEAD(n);
}
/* Creates cipher->description based on cipher->offset
 * cipher->offset is set in wolfSSL_get_ciphers_compat when it is added
 * to a stack of ciphers.
 * @param [in] cipher: A cipher from a stack of ciphers.
 * return WOLFSSL_SUCCESS if cipher->description is set, else WOLFSSL_FAILURE
 */
int wolfSSL_sk_CIPHER_description(WOLFSSL_CIPHER* cipher)
{
    int strLen;
    unsigned long offset;
    char* dp;
    const char* name;
    const char *keaStr, *authStr, *encStr, *macStr, *protocol;
    char n[MAX_SEGMENTS][MAX_SEGMENT_SZ] = {{0}};
    int len = MAX_DESCRIPTION_SZ-1;
    const CipherSuiteInfo* cipher_names;
    ProtocolVersion pv;
    WOLFSSL_ENTER("wolfSSL_sk_CIPHER_description");

    if (cipher == NULL)
        return WOLFSSL_FAILURE;

    dp = cipher->description;
    if (dp == NULL)
        return WOLFSSL_FAILURE;

    cipher_names = GetCipherNames();

    offset = cipher->offset;
    if (offset >= (unsigned long)GetCipherNamesSize())
        return WOLFSSL_FAILURE;
    pv.major = cipher_names[offset].major;
    pv.minor = cipher_names[offset].minor;
    protocol = wolfSSL_internal_get_version(&pv);

    if ((name = GetCipherSegment(cipher, n)) == NULL) {
        WOLFSSL_MSG("no suitable cipher name found");
        return WOLFSSL_FAILURE;
    }

    /* keaStr */
    keaStr = GetCipherKeaStr(n);
    /* authStr */
    authStr = GetCipherAuthStr(n);
    /* encStr */
    encStr = GetCipherEncStr(n);
    if ((cipher->bits = SetCipherBits(encStr)) ==
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE))
    {
       WOLFSSL_MSG("Cipher Bits Not Set.");
    }
    /* macStr */
    macStr = GetCipherMacStr(n);


    /* Build up the string by copying onto the end. */
    XSTRNCPY(dp, name, len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " ", len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, protocol, len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Kx=", len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, keaStr, len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Au=", len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, authStr, len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Enc=", len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, encStr, len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Mac=", len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, macStr, len);
    dp[len-1] = '\0';

    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_ALL || WOLFSSL_QT */

static WC_INLINE const char* wolfssl_kea_to_string(int kea)
{
    const char* keaStr;

    switch (kea) {
        case no_kea:
            keaStr = "None";
            break;
#ifndef NO_RSA
        case rsa_kea:
            keaStr = "RSA";
            break;
#endif
#ifndef NO_DH
        case diffie_hellman_kea:
            keaStr = "DHE";
            break;
#endif
        case fortezza_kea:
            keaStr = "FZ";
            break;
#ifndef NO_PSK
        case psk_kea:
            keaStr = "PSK";
            break;
    #ifndef NO_DH
        case dhe_psk_kea:
            keaStr = "DHEPSK";
            break;
    #endif
    #ifdef HAVE_ECC
        case ecdhe_psk_kea:
            keaStr = "ECDHEPSK";
            break;
    #endif
#endif
#ifdef HAVE_ECC
        case ecc_diffie_hellman_kea:
            keaStr = "ECDHE";
            break;
        case ecc_static_diffie_hellman_kea:
            keaStr = "ECDH";
            break;
#endif
        default:
            keaStr = "unknown";
            break;
    }

    return keaStr;
}

static WC_INLINE const char* wolfssl_sigalg_to_string(int sig_algo)
{
    const char* authStr;

    switch (sig_algo) {
        case anonymous_sa_algo:
            authStr = "None";
            break;
#ifndef NO_RSA
        case rsa_sa_algo:
            authStr = "RSA";
            break;
    #ifdef WC_RSA_PSS
        case rsa_pss_sa_algo:
            authStr = "RSA-PSS";
            break;
    #endif
#endif
#ifndef NO_DSA
        case dsa_sa_algo:
            authStr = "DSA";
            break;
#endif
#ifdef HAVE_ECC
        case ecc_dsa_sa_algo:
            authStr = "ECDSA";
            break;
#endif
#ifdef WOLFSSL_SM2
        case sm2_sa_algo:
            authStr = "SM2";
            break;
#endif
#ifdef HAVE_ED25519
        case ed25519_sa_algo:
            authStr = "Ed25519";
            break;
#endif
#ifdef HAVE_ED448
        case ed448_sa_algo:
            authStr = "Ed448";
            break;
#endif
        default:
            authStr = "unknown";
            break;
    }

    return authStr;
}

static WC_INLINE const char* wolfssl_cipher_to_string(int cipher, int key_size)
{
    const char* encStr;

    (void)key_size;

    switch (cipher) {
        case wolfssl_cipher_null:
            encStr = "None";
            break;
#ifndef NO_RC4
        case wolfssl_rc4:
            encStr = "RC4(128)";
            break;
#endif
#ifndef NO_DES3
        case wolfssl_triple_des:
            encStr = "3DES(168)";
            break;
#endif
#ifndef NO_AES
        case wolfssl_aes:
            if (key_size == 128)
                encStr = "AES(128)";
            else if (key_size == 256)
                encStr = "AES(256)";
            else
                encStr = "AES(?)";
            break;
    #ifdef HAVE_AESGCM
        case wolfssl_aes_gcm:
            if (key_size == 128)
                encStr = "AESGCM(128)";
            else if (key_size == 256)
                encStr = "AESGCM(256)";
            else
                encStr = "AESGCM(?)";
            break;
    #endif
    #ifdef HAVE_AESCCM
        case wolfssl_aes_ccm:
            if (key_size == 128)
                encStr = "AESCCM(128)";
            else if (key_size == 256)
                encStr = "AESCCM(256)";
            else
                encStr = "AESCCM(?)";
            break;
    #endif
#endif
#ifdef HAVE_CHACHA
        case wolfssl_chacha:
            encStr = "CHACHA20/POLY1305(256)";
            break;
#endif
#ifdef HAVE_ARIA
        case wolfssl_aria_gcm:
            if (key_size == 128)
                encStr = "Aria(128)";
            else if (key_size == 192)
                encStr = "Aria(192)";
            else if (key_size == 256)
                encStr = "Aria(256)";
            else
                encStr = "Aria(?)";
            break;
#endif
#ifdef HAVE_CAMELLIA
        case wolfssl_camellia:
            if (key_size == 128)
                encStr = "Camellia(128)";
            else if (key_size == 256)
                encStr = "Camellia(256)";
            else
                encStr = "Camellia(?)";
            break;
#endif
        default:
            encStr = "unknown";
            break;
    }

    return encStr;
}

static WC_INLINE const char* wolfssl_mac_to_string(int mac)
{
    const char* macStr;

    switch (mac) {
        case no_mac:
            macStr = "None";
            break;
#ifndef NO_MD5
        case md5_mac:
            macStr = "MD5";
            break;
#endif
#ifndef NO_SHA
        case sha_mac:
            macStr = "SHA1";
            break;
#endif
#ifdef WOLFSSL_SHA224
        case sha224_mac:
            macStr = "SHA224";
            break;
#endif
#ifndef NO_SHA256
        case sha256_mac:
            macStr = "SHA256";
            break;
#endif
#ifdef WOLFSSL_SHA384
        case sha384_mac:
            macStr = "SHA384";
            break;
#endif
#ifdef WOLFSSL_SHA512
        case sha512_mac:
            macStr = "SHA512";
            break;
#endif
        default:
            macStr = "unknown";
            break;
    }

    return macStr;
}

char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER* cipher, char* in,
                                 int len)
{
    char *ret = in;
    const char *keaStr, *authStr, *encStr, *macStr;
    size_t strLen;
    WOLFSSL_ENTER("wolfSSL_CIPHER_description");

    if (cipher == NULL || in == NULL)
        return NULL;

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
    /* if cipher is in the stack from wolfSSL_get_ciphers_compat then
     * Return the description based on cipher_names[cipher->offset]
     */
    if (cipher->in_stack == TRUE) {
        wolfSSL_sk_CIPHER_description((WOLFSSL_CIPHER*)cipher);
        XSTRNCPY(in,cipher->description,len);
        return ret;
    }
#endif

    /* Get the cipher description based on the SSL session cipher */
    keaStr = wolfssl_kea_to_string(cipher->ssl->specs.kea);
    authStr = wolfssl_sigalg_to_string(cipher->ssl->specs.sig_algo);
    encStr = wolfssl_cipher_to_string(cipher->ssl->specs.bulk_cipher_algorithm,
                                      cipher->ssl->specs.key_size);
    macStr = wolfssl_mac_to_string(cipher->ssl->specs.mac_algorithm);

    /* Build up the string by copying onto the end. */
    XSTRNCPY(in, wolfSSL_CIPHER_get_name(cipher), len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " ", len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, wolfSSL_get_version(cipher->ssl), len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Kx=", len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, keaStr, len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Au=", len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, authStr, len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Enc=", len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, encStr, len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Mac=", len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, macStr, len);
    in[len-1] = '\0';

    return ret;
}

int wolfSSL_OCSP_parse_url(const char* url, char** host, char** port,
        char** path, int* ssl)
{
    const char* u = url;
    const char* upath; /* path in u */
    const char* uport; /* port in u */
    const char* hostEnd;

    WOLFSSL_ENTER("OCSP_parse_url");

    *host = NULL;
    *port = NULL;
    *path = NULL;
    *ssl = 0;

    if (*(u++) != 'h') goto err;
    if (*(u++) != 't') goto err;
    if (*(u++) != 't') goto err;
    if (*(u++) != 'p') goto err;
    if (*u == 's') {
        *ssl = 1;
        u++;
        *port = CopyString("443", -1, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    else if (*u == ':') {
        *ssl = 0;
        *port = CopyString("80", -1, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    else
        goto err;
    if (*port == NULL)
        goto err;
    if (*(u++) != ':') goto err;
    if (*(u++) != '/') goto err;
    if (*(u++) != '/') goto err;

    /* Look for path */
    upath = XSTRSTR(u, "/");
    *path = CopyString(upath == NULL ? "/" : upath, -1, NULL,
                       DYNAMIC_TYPE_OPENSSL);

    /* Look for port */
    uport = XSTRSTR(u, ":");
    if (uport != NULL) {
        if (*(++uport) == '\0')
            goto err;
        /* port must be before path */
        if (upath != NULL && uport >= upath)
            goto err;
        XFREE(*port, NULL, DYNAMIC_TYPE_OPENSSL);
        *port = CopyString(uport, upath != NULL ? (int)(upath - uport) : -1,
                           NULL, DYNAMIC_TYPE_OPENSSL);
        if (*port == NULL)
            goto err;
        hostEnd = uport - 1;
    }
    else
        hostEnd = upath;

    *host = CopyString(u, hostEnd != NULL ? (int)(hostEnd - u) : -1, NULL,
                       DYNAMIC_TYPE_OPENSSL);
    if (*host == NULL)
        goto err;

    return WOLFSSL_SUCCESS;
err:
    XFREE(*host, NULL, DYNAMIC_TYPE_OPENSSL);
    *host = NULL;
    XFREE(*port, NULL, DYNAMIC_TYPE_OPENSSL);
    *port = NULL;
    XFREE(*path, NULL, DYNAMIC_TYPE_OPENSSL);
    *path = NULL;
    return WOLFSSL_FAILURE;
}

#ifndef NO_WOLFSSL_STUB
WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void)
{
    WOLFSSL_STUB("COMP_zlib");
    return 0;
}

WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void)
{
    WOLFSSL_STUB("COMP_rle");
    return 0;
}

int wolfSSL_COMP_add_compression_method(int method, void* data)
{
    (void)method;
    (void)data;
    WOLFSSL_STUB("COMP_add_compression_method");
    return 0;
}

const WOLFSSL_COMP_METHOD* wolfSSL_get_current_compression(const WOLFSSL *ssl) {
    (void)ssl;
    return NULL;
}

const WOLFSSL_COMP_METHOD* wolfSSL_get_current_expansion(const WOLFSSL *ssl) {
    (void)ssl;
    return NULL;
}

const char* wolfSSL_COMP_get_name(const WOLFSSL_COMP_METHOD *comp)
{
    static const char ret[] = "not supported";

    (void)comp;
    WOLFSSL_STUB("wolfSSL_COMP_get_name");
    return ret;
}
#endif

/*  wolfSSL_set_dynlock_create_callback
 *  CRYPTO_set_dynlock_create_callback has been deprecated since openSSL 1.0.1.
 *  This function exists for compatibility purposes because wolfSSL satisfies
 *  thread safety without relying on the callback.
 */
void wolfSSL_set_dynlock_create_callback(WOLFSSL_dynlock_value* (*f)(
                                                          const char*, int))
{
    WOLFSSL_STUB("CRYPTO_set_dynlock_create_callback");
    (void)f;
}
/*  wolfSSL_set_dynlock_lock_callback
 *  CRYPTO_set_dynlock_lock_callback has been deprecated since openSSL 1.0.1.
 *  This function exists for compatibility purposes because wolfSSL satisfies
 *  thread safety without relying on the callback.
 */
void wolfSSL_set_dynlock_lock_callback(
             void (*f)(int, WOLFSSL_dynlock_value*, const char*, int))
{
    WOLFSSL_STUB("CRYPTO_set_set_dynlock_lock_callback");
    (void)f;
}
/*  wolfSSL_set_dynlock_destroy_callback
 *  CRYPTO_set_dynlock_destroy_callback has been deprecated since openSSL 1.0.1.
 *  This function exists for compatibility purposes because wolfSSL satisfies
 *  thread safety without relying on the callback.
 */
void wolfSSL_set_dynlock_destroy_callback(
                  void (*f)(WOLFSSL_dynlock_value*, const char*, int))
{
    WOLFSSL_STUB("CRYPTO_set_set_dynlock_destroy_callback");
    (void)f;
}


#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA
#ifndef NO_CERTS

#if !defined(NO_ASN) && !defined(NO_PWDBASED)
/* Copies unencrypted DER key buffer into "der". If "der" is null then the size
 * of buffer needed is returned. If *der == NULL then it allocates a buffer.
 * NOTE: This also advances the "der" pointer to be at the end of buffer.
 *
 * Returns size of key buffer on success
 */
int wolfSSL_i2d_PrivateKey(const WOLFSSL_EVP_PKEY* key, unsigned char** der)
{
    return wolfSSL_EVP_PKEY_get_der(key, der);
}

int wolfSSL_i2d_PublicKey(const WOLFSSL_EVP_PKEY *key, unsigned char **der)
{
#if !defined(NO_RSA) || defined(HAVE_ECC)
#ifdef HAVE_ECC
    unsigned char *local_der = NULL;
    word32 local_derSz = 0;
    unsigned char *pub_der = NULL;
    ecc_key *eccKey = NULL;
    word32 inOutIdx = 0;
#endif
    word32 pub_derSz = 0;
    int ret;
    int key_type = 0;

    if (key == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    key_type = key->type;
    if ((key_type != WC_EVP_PKEY_EC) && (key_type != WC_EVP_PKEY_RSA)) {
        return WOLFSSL_FATAL_ERROR;
    }

#ifndef NO_RSA
    if (key_type == WC_EVP_PKEY_RSA) {
        return wolfSSL_i2d_RSAPublicKey(key->rsa, der);
    }
#endif

    /* Now that RSA is taken care of, we only need to consider the ECC case. */

#ifdef HAVE_ECC

    /* We need to get the DER, then convert it to a public key. But what we get
     * might be a buffered private key so we need to decode it and then encode
     * the public part. */
    ret = wolfSSL_EVP_PKEY_get_der(key, &local_der);
    if (ret <= 0) {
        /* In this case, there was no buffered DER at all. This could be the
         * case where the key that was passed in was generated. So now we
         * have to create the local DER. */
        local_derSz = (word32)wolfSSL_i2d_ECPrivateKey(key->ecc, &local_der);
        if (local_derSz == 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    } else {
        local_derSz = (word32)ret;
        ret = 0;
    }

    if (ret == 0) {
        eccKey = (ecc_key *)XMALLOC(sizeof(*eccKey), NULL, DYNAMIC_TYPE_ECC);
        if (eccKey == NULL) {
            WOLFSSL_MSG("Failed to allocate key buffer.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init(eccKey);
    }

    if (ret == 0) {
        ret = wc_EccPublicKeyDecode(local_der, &inOutIdx, eccKey, local_derSz);
        if (ret < 0) {
            /* We now try again as x.963 [point type][x][opt y]. */
            ret = wc_ecc_import_x963(local_der, local_derSz, eccKey);
        }
    }

    if (ret == 0) {
        pub_derSz = (word32)wc_EccPublicKeyDerSize(eccKey, 0);
        if ((int)pub_derSz <= 0) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == 0) {
        pub_der = (unsigned char*)XMALLOC(pub_derSz, NULL,
                                          DYNAMIC_TYPE_PUBLIC_KEY);
        if (pub_der == NULL) {
            WOLFSSL_MSG("Failed to allocate output buffer.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        pub_derSz = (word32)wc_EccPublicKeyToDer(eccKey, pub_der, pub_derSz, 0);
        if ((int)pub_derSz <= 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    /* This block is for actually returning the DER of the public key */
    if ((ret == 0) && (der != NULL)) {
        if (*der == NULL) {
            *der = (unsigned char*)XMALLOC(pub_derSz, NULL,
                                           DYNAMIC_TYPE_PUBLIC_KEY);
            if (*der == NULL) {
                WOLFSSL_MSG("Failed to allocate output buffer.");
                ret = WOLFSSL_FATAL_ERROR;
            }

            if (ret == 0) {
                XMEMCPY(*der, pub_der, pub_derSz);
            }
        }
        else {
            XMEMCPY(*der, pub_der, pub_derSz);
            *der += pub_derSz;
        }
    }

    XFREE(pub_der, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(local_der, NULL, DYNAMIC_TYPE_PUBLIC_KEY);

    wc_ecc_free(eccKey);
    XFREE(eccKey, NULL, DYNAMIC_TYPE_ECC);

#else
    ret = WOLFSSL_FATAL_ERROR;
#endif /* HAVE_ECC */

    if (ret == 0) {
        return (int)pub_derSz;
    }

    return ret;
#else
    return WOLFSSL_FATAL_ERROR;
#endif /* !NO_RSA || HAVE_ECC */
}
#endif /* !NO_ASN && !NO_PWDBASED */

#endif /* !NO_CERTS */
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA

/* Sets the DNS hostname to name.
 * Hostname is cleared if name is NULL or empty. */
int wolfSSL_set1_host(WOLFSSL * ssl, const char* name)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    return wolfSSL_X509_VERIFY_PARAM_set1_host(ssl->param, name, 0);
}

/******************************************************************************
* wolfSSL_CTX_set1_param - set a pointer to the SSL verification parameters
*
* RETURNS:
*   WOLFSSL_SUCCESS on success, otherwise returns WOLFSSL_FAILURE
*   Note: Returns WOLFSSL_SUCCESS, in case either parameter is NULL,
*   same as openssl.
*/
int wolfSSL_CTX_set1_param(WOLFSSL_CTX* ctx, WOLFSSL_X509_VERIFY_PARAM *vpm)
{
    if (ctx == NULL || vpm == NULL)
        return WOLFSSL_SUCCESS;

    return wolfSSL_X509_VERIFY_PARAM_set1(ctx->param, vpm);
}

/******************************************************************************
* wolfSSL_CTX/_get0_param - return a pointer to the SSL verification parameters
*
* RETURNS:
* returns pointer to the SSL verification parameters on success,
* otherwise returns NULL
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_CTX_get0_param(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->param;
}

WOLFSSL_X509_VERIFY_PARAM* wolfSSL_get0_param(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }
    return ssl->param;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Gets an index to store SSL structure at.
 *
 * Returns positive index on success and negative values on failure
 */
int wolfSSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    WOLFSSL_ENTER("wolfSSL_get_ex_data_X509_STORE_CTX_idx");

    /* store SSL at index 0 */
    return 0;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA
/* Sets a function callback that will send information about the state of all
 * WOLFSSL objects that have been created by the WOLFSSL_CTX structure passed
 * in.
 *
 * ctx WOLFSSL_CTX structure to set callback function in
 * f   callback function to use
 */
void wolfSSL_CTX_set_info_callback(WOLFSSL_CTX* ctx,
       void (*f)(const WOLFSSL* ssl, int type, int val))
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_info_callback");
    if (ctx == NULL) {
        WOLFSSL_MSG("Bad function argument");
    }
    else {
        ctx->CBIS = f;
    }
}

void wolfSSL_set_info_callback(WOLFSSL* ssl,
       void (*f)(const WOLFSSL* ssl, int type, int val))
{
    WOLFSSL_ENTER("wolfSSL_set_info_callback");
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
    }
    else {
        ssl->CBIS = f;
    }
}


unsigned long wolfSSL_ERR_peek_error(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_error");

    return wolfSSL_ERR_peek_error_line_data(NULL, NULL, NULL, NULL);
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES_H
#include <wolfssl/debug-untrace-error-codes.h>
#endif

int wolfSSL_ERR_GET_LIB(unsigned long err)
{
    unsigned long value;

    value = (err & 0xFFFFFFL);
    switch (value) {
    case -PARSE_ERROR:
        return WOLFSSL_ERR_LIB_SSL;
    case -ASN_NO_PEM_HEADER:
    case -WOLFSSL_PEM_R_NO_START_LINE_E:
    case -WOLFSSL_PEM_R_PROBLEMS_GETTING_PASSWORD_E:
    case -WOLFSSL_PEM_R_BAD_PASSWORD_READ_E:
    case -WOLFSSL_PEM_R_BAD_DECRYPT_E:
        return WOLFSSL_ERR_LIB_PEM;
    case -WOLFSSL_EVP_R_BAD_DECRYPT_E:
    case -WOLFSSL_EVP_R_BN_DECODE_ERROR:
    case -WOLFSSL_EVP_R_DECODE_ERROR:
    case -WOLFSSL_EVP_R_PRIVATE_KEY_DECODE_ERROR:
        return WOLFSSL_ERR_LIB_EVP;
    case -WOLFSSL_ASN1_R_HEADER_TOO_LONG_E:
        return WOLFSSL_ERR_LIB_ASN1;
    default:
        return 0;
    }
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
#include <wolfssl/debug-trace-error-codes.h>
#endif

/* This function is to find global error values that are the same through out
 * all library version. With wolfSSL having only one set of error codes the
 * return value is pretty straight forward. The only thing needed is all wolfSSL
 * error values are typically negative.
 *
 * Returns the error reason
 */
int wolfSSL_ERR_GET_REASON(unsigned long err)
{
    int ret = (int)err;

    WOLFSSL_ENTER("wolfSSL_ERR_GET_REASON");

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
    /* Nginx looks for this error to know to stop parsing certificates.
     * Same for HAProxy. */
    if (err == ((ERR_LIB_PEM << 24) | PEM_R_NO_START_LINE) ||
       ((err & 0xFFFFFFL) == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER)) ||
       ((err & 0xFFFL) == PEM_R_NO_START_LINE ))
        return PEM_R_NO_START_LINE;
    if (err == ((ERR_LIB_SSL << 24) | -SSL_R_HTTP_REQUEST))
        return SSL_R_HTTP_REQUEST;
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
    if (err == ((ERR_LIB_ASN1 << 24) | ASN1_R_HEADER_TOO_LONG))
        return ASN1_R_HEADER_TOO_LONG;
#endif

    /* check if error value is in range of wolfCrypt or wolfSSL errors */
    ret = 0 - ret; /* setting as negative value */

    if ((ret <= WC_SPAN1_FIRST_E && ret >= WC_SPAN1_LAST_E) ||
        (ret <= WC_SPAN2_FIRST_E && ret >= WC_SPAN2_LAST_E) ||
        (ret <= WOLFSSL_FIRST_E && ret >= WOLFSSL_LAST_E))
    {
        return ret;
    }
    else {
        WOLFSSL_MSG("Not in range of typical error values");
        ret = (int)err;
    }

    return ret;
}

#ifndef NO_TLS
/* returns a string that describes the alert
 *
 * alertID the alert value to look up
 */
const char* wolfSSL_alert_type_string_long(int alertID)
{
    WOLFSSL_ENTER("wolfSSL_alert_type_string_long");

    return AlertTypeToString(alertID);
}

const char* wolfSSL_alert_desc_string_long(int alertID)
{
    WOLFSSL_ENTER("wolfSSL_alert_desc_string_long");

    return AlertTypeToString(alertID);
}
#endif /* !NO_TLS */

#define STATE_STRINGS_PROTO(s) \
    {                          \
        {"SSLv3 " s,           \
         "SSLv3 " s,           \
         "SSLv3 " s},          \
        {"TLSv1 " s,           \
         "TLSv1 " s,           \
         "TLSv1 " s},          \
        {"TLSv1_1 " s,         \
         "TLSv1_1 " s,         \
         "TLSv1_1 " s},        \
        {"TLSv1_2 " s,         \
         "TLSv1_2 " s,         \
         "TLSv1_2 " s},        \
        {"TLSv1_3 " s,         \
         "TLSv1_3 " s,         \
         "TLSv1_3 " s},        \
        {"DTLSv1 " s,          \
         "DTLSv1 " s,          \
         "DTLSv1 " s},         \
        {"DTLSv1_2 " s,        \
         "DTLSv1_2 " s,        \
         "DTLSv1_2 " s},       \
        {"DTLSv1_3 " s,        \
         "DTLSv1_3 " s,        \
         "DTLSv1_3 " s},       \
    }

#define STATE_STRINGS_PROTO_RW(s) \
    {                             \
        {"SSLv3 read " s,         \
         "SSLv3 write " s,        \
         "SSLv3 " s},             \
        {"TLSv1 read " s,         \
         "TLSv1 write " s,        \
         "TLSv1 " s},             \
        {"TLSv1_1 read " s,       \
         "TLSv1_1 write " s,      \
         "TLSv1_1 " s},           \
        {"TLSv1_2 read " s,       \
         "TLSv1_2 write " s,      \
         "TLSv1_2 " s},           \
        {"TLSv1_3 read " s,       \
         "TLSv1_3 write " s,      \
         "TLSv1_3 " s},           \
        {"DTLSv1 read " s,        \
         "DTLSv1 write " s,       \
         "DTLSv1 " s},            \
        {"DTLSv1_2 read " s,      \
         "DTLSv1_2 write " s,     \
         "DTLSv1_2 " s},          \
        {"DTLSv1_3 read " s,      \
         "DTLSv1_3 write " s,     \
         "DTLSv1_3 " s},          \
    }

/* Gets the current state of the WOLFSSL structure
 *
 * ssl WOLFSSL structure to get state of
 *
 * Returns a human readable string of the WOLFSSL structure state
 */
const char* wolfSSL_state_string_long(const WOLFSSL* ssl)
{

    static const char* OUTPUT_STR[24][8][3] = {
        STATE_STRINGS_PROTO("Initialization"),
        STATE_STRINGS_PROTO_RW("Server Hello Request"),
        STATE_STRINGS_PROTO_RW("Server Hello Verify Request"),
        STATE_STRINGS_PROTO_RW("Server Hello Retry Request"),
        STATE_STRINGS_PROTO_RW("Server Hello"),
        STATE_STRINGS_PROTO_RW("Server Certificate Status"),
        STATE_STRINGS_PROTO_RW("Server Encrypted Extensions"),
        STATE_STRINGS_PROTO_RW("Server Session Ticket"),
        STATE_STRINGS_PROTO_RW("Server Certificate Request"),
        STATE_STRINGS_PROTO_RW("Server Cert"),
        STATE_STRINGS_PROTO_RW("Server Key Exchange"),
        STATE_STRINGS_PROTO_RW("Server Hello Done"),
        STATE_STRINGS_PROTO_RW("Server Change CipherSpec"),
        STATE_STRINGS_PROTO_RW("Server Finished"),
        STATE_STRINGS_PROTO_RW("server Key Update"),
        STATE_STRINGS_PROTO_RW("Client Hello"),
        STATE_STRINGS_PROTO_RW("Client Key Exchange"),
        STATE_STRINGS_PROTO_RW("Client Cert"),
        STATE_STRINGS_PROTO_RW("Client Change CipherSpec"),
        STATE_STRINGS_PROTO_RW("Client Certificate Verify"),
        STATE_STRINGS_PROTO_RW("Client End Of Early Data"),
        STATE_STRINGS_PROTO_RW("Client Finished"),
        STATE_STRINGS_PROTO_RW("Client Key Update"),
        STATE_STRINGS_PROTO("Handshake Done"),
    };
    enum ProtocolVer {
        SSL_V3 = 0,
        TLS_V1,
        TLS_V1_1,
        TLS_V1_2,
        TLS_V1_3,
        DTLS_V1,
        DTLS_V1_2,
        DTLS_V1_3,
        UNKNOWN = 100
    };

    enum IOMode {
        SS_READ = 0,
        SS_WRITE,
        SS_NEITHER
    };

    enum SslState {
        ss_null_state = 0,
        ss_server_hellorequest,
        ss_server_helloverify,
        ss_server_helloretryrequest,
        ss_server_hello,
        ss_server_certificatestatus,
        ss_server_encryptedextensions,
        ss_server_sessionticket,
        ss_server_certrequest,
        ss_server_cert,
        ss_server_keyexchange,
        ss_server_hellodone,
        ss_server_changecipherspec,
        ss_server_finished,
        ss_server_keyupdate,
        ss_client_hello,
        ss_client_keyexchange,
        ss_client_cert,
        ss_client_changecipherspec,
        ss_client_certverify,
        ss_client_endofearlydata,
        ss_client_finished,
        ss_client_keyupdate,
        ss_handshake_done
    };

    int protocol = 0;
    int cbmode = 0;
    int state = 0;

    WOLFSSL_ENTER("wolfSSL_state_string_long");
    if (ssl == NULL) {
        WOLFSSL_MSG("Null argument passed in");
        return NULL;
    }

    /* Get state of callback */
    if (ssl->cbmode == WOLFSSL_CB_MODE_WRITE) {
        cbmode =  SS_WRITE;
    }
    else if (ssl->cbmode == WOLFSSL_CB_MODE_READ) {
        cbmode =  SS_READ;
    }
    else {
        cbmode =  SS_NEITHER;
    }

    /* Get protocol version */
    switch (ssl->version.major) {
        case SSLv3_MAJOR:
            switch (ssl->version.minor) {
                case SSLv3_MINOR:
                    protocol = SSL_V3;
                    break;
                case TLSv1_MINOR:
                    protocol = TLS_V1;
                    break;
                case TLSv1_1_MINOR:
                    protocol = TLS_V1_1;
                    break;
                case TLSv1_2_MINOR:
                    protocol = TLS_V1_2;
                    break;
                case TLSv1_3_MINOR:
                    protocol = TLS_V1_3;
                    break;
                default:
                    protocol = UNKNOWN;
            }
            break;
        case DTLS_MAJOR:
            switch (ssl->version.minor) {
                case DTLS_MINOR:
                    protocol = DTLS_V1;
                    break;
                case DTLSv1_2_MINOR:
                    protocol = DTLS_V1_2;
                    break;
                case DTLSv1_3_MINOR:
                    protocol = DTLS_V1_3;
                    break;
                default:
                    protocol = UNKNOWN;
            }
            break;
    default:
        protocol = UNKNOWN;
    }

    /* accept process */
    if (ssl->cbmode == WOLFSSL_CB_MODE_READ) {
        state = ssl->cbtype;
        switch (state) {
            case hello_request:
                state = ss_server_hellorequest;
                break;
            case client_hello:
                state = ss_client_hello;
                break;
            case server_hello:
                state = ss_server_hello;
                break;
            case hello_verify_request:
                state = ss_server_helloverify;
                break;
            case session_ticket:
                state = ss_server_sessionticket;
                break;
            case end_of_early_data:
                state = ss_client_endofearlydata;
                break;
            case hello_retry_request:
                state = ss_server_helloretryrequest;
                break;
            case encrypted_extensions:
                state = ss_server_encryptedextensions;
                break;
            case certificate:
                if (ssl->options.side == WOLFSSL_SERVER_END)
                    state = ss_client_cert;
                else if (ssl->options.side == WOLFSSL_CLIENT_END)
                    state = ss_server_cert;
                else {
                    WOLFSSL_MSG("Unknown State");
                    state = ss_null_state;
                }
                break;
            case server_key_exchange:
                state = ss_server_keyexchange;
                break;
            case certificate_request:
                state = ss_server_certrequest;
                break;
            case server_hello_done:
                state = ss_server_hellodone;
                break;
            case certificate_verify:
                state = ss_client_certverify;
                break;
            case client_key_exchange:
                state = ss_client_keyexchange;
                break;
            case finished:
                if (ssl->options.side == WOLFSSL_SERVER_END)
                    state = ss_client_finished;
                else if (ssl->options.side == WOLFSSL_CLIENT_END)
                    state = ss_server_finished;
                else {
                    WOLFSSL_MSG("Unknown State");
                    state = ss_null_state;
                }
                break;
            case certificate_status:
                state = ss_server_certificatestatus;
                break;
            case key_update:
                if (ssl->options.side == WOLFSSL_SERVER_END)
                    state = ss_client_keyupdate;
                else if (ssl->options.side == WOLFSSL_CLIENT_END)
                    state = ss_server_keyupdate;
                else {
                    WOLFSSL_MSG("Unknown State");
                    state = ss_null_state;
                }
                break;
            case change_cipher_hs:
                if (ssl->options.side == WOLFSSL_SERVER_END)
                    state = ss_client_changecipherspec;
                else if (ssl->options.side == WOLFSSL_CLIENT_END)
                    state = ss_server_changecipherspec;
                else {
                    WOLFSSL_MSG("Unknown State");
                    state = ss_null_state;
                }
                break;
            default:
                WOLFSSL_MSG("Unknown State");
                state = ss_null_state;
        }
    }
    else {
        /* Send process */
        if (ssl->options.side == WOLFSSL_SERVER_END)
            state = ssl->options.serverState;
        else
            state = ssl->options.clientState;

        switch (state) {
            case SERVER_HELLOVERIFYREQUEST_COMPLETE:
                state = ss_server_helloverify;
                break;
            case SERVER_HELLO_RETRY_REQUEST_COMPLETE:
                state = ss_server_helloretryrequest;
                break;
            case SERVER_HELLO_COMPLETE:
                state = ss_server_hello;
                break;
            case SERVER_ENCRYPTED_EXTENSIONS_COMPLETE:
                state = ss_server_encryptedextensions;
                break;
            case SERVER_CERT_COMPLETE:
                state = ss_server_cert;
                break;
            case SERVER_KEYEXCHANGE_COMPLETE:
                state = ss_server_keyexchange;
                break;
            case SERVER_HELLODONE_COMPLETE:
                state = ss_server_hellodone;
                break;
            case SERVER_CHANGECIPHERSPEC_COMPLETE:
                state = ss_server_changecipherspec;
                break;
            case SERVER_FINISHED_COMPLETE:
                state = ss_server_finished;
                break;
            case CLIENT_HELLO_RETRY:
            case CLIENT_HELLO_COMPLETE:
                state = ss_client_hello;
                break;
            case CLIENT_KEYEXCHANGE_COMPLETE:
                state = ss_client_keyexchange;
                break;
            case CLIENT_CHANGECIPHERSPEC_COMPLETE:
                state = ss_client_changecipherspec;
                break;
            case CLIENT_FINISHED_COMPLETE:
                state = ss_client_finished;
                break;
            case HANDSHAKE_DONE:
                state = ss_handshake_done;
                break;
            default:
                WOLFSSL_MSG("Unknown State");
                state = ss_null_state;
        }
    }

    if (protocol == UNKNOWN) {
        WOLFSSL_MSG("Unknown protocol");
        return "";
    }
    else {
        return OUTPUT_STR[state][protocol][cbmode];
    }
}

#endif /* OPENSSL_EXTRA */

static long wolf_set_options(long old_op, long op)
{
    /* if SSL_OP_ALL then turn all bug workarounds on */
    if ((op & WOLFSSL_OP_ALL) == WOLFSSL_OP_ALL) {
        WOLFSSL_MSG("\tSSL_OP_ALL");
    }

    /* by default cookie exchange is on with DTLS */
    if ((op & WOLFSSL_OP_COOKIE_EXCHANGE) == WOLFSSL_OP_COOKIE_EXCHANGE) {
        WOLFSSL_MSG("\tSSL_OP_COOKIE_EXCHANGE : on by default");
    }

    if ((op & WOLFSSL_OP_NO_SSLv2) == WOLFSSL_OP_NO_SSLv2) {
        WOLFSSL_MSG("\tWOLFSSL_OP_NO_SSLv2 : wolfSSL does not support SSLv2");
    }

#ifdef SSL_OP_NO_TLSv1_3
    if ((op & WOLFSSL_OP_NO_TLSv1_3) == WOLFSSL_OP_NO_TLSv1_3) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_3");
    }
#endif

    if ((op & WOLFSSL_OP_NO_TLSv1_2) == WOLFSSL_OP_NO_TLSv1_2) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_2");
    }

    if ((op & WOLFSSL_OP_NO_TLSv1_1) == WOLFSSL_OP_NO_TLSv1_1) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_1");
    }

    if ((op & WOLFSSL_OP_NO_TLSv1) == WOLFSSL_OP_NO_TLSv1) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1");
    }

    if ((op & WOLFSSL_OP_NO_SSLv3) == WOLFSSL_OP_NO_SSLv3) {
        WOLFSSL_MSG("\tSSL_OP_NO_SSLv3");
    }

    if ((op & WOLFSSL_OP_CIPHER_SERVER_PREFERENCE) ==
            WOLFSSL_OP_CIPHER_SERVER_PREFERENCE) {
        WOLFSSL_MSG("\tWOLFSSL_OP_CIPHER_SERVER_PREFERENCE");
    }

    if ((op & WOLFSSL_OP_NO_COMPRESSION) == WOLFSSL_OP_NO_COMPRESSION) {
    #ifdef HAVE_LIBZ
        WOLFSSL_MSG("SSL_OP_NO_COMPRESSION");
    #else
        WOLFSSL_MSG("SSL_OP_NO_COMPRESSION: compression not compiled in");
    #endif
    }

    return old_op | op;
}

static int FindHashSig(const Suites* suites, byte first, byte second)
{
    word16 i;

    if (suites == NULL || suites->hashSigAlgoSz == 0) {
        WOLFSSL_MSG("Suites pointer error or suiteSz 0");
        return SUITES_ERROR;
    }

    for (i = 0; i < suites->hashSigAlgoSz-1; i += 2) {
        if (suites->hashSigAlgo[i]   == first &&
            suites->hashSigAlgo[i+1] == second )
            return i;
    }

    return MATCH_SUITE_ERROR;
}

long wolfSSL_set_options(WOLFSSL* ssl, long op)
{
    word16 haveRSA = 1;
    word16 havePSK = 0;
    int    keySz   = 0;

    WOLFSSL_ENTER("wolfSSL_set_options");

    if (ssl == NULL) {
        return 0;
    }

    ssl->options.mask = (unsigned long)wolf_set_options((long)ssl->options.mask, op);

    if ((ssl->options.mask & WOLFSSL_OP_NO_TLSv1_3) == WOLFSSL_OP_NO_TLSv1_3) {
        WOLFSSL_MSG("Disabling TLS 1.3");
        if (ssl->version.minor == TLSv1_3_MINOR)
            ssl->version.minor = TLSv1_2_MINOR;
    }

    if ((ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2) == WOLFSSL_OP_NO_TLSv1_2) {
        WOLFSSL_MSG("Disabling TLS 1.2");
        if (ssl->version.minor == TLSv1_2_MINOR)
            ssl->version.minor = TLSv1_1_MINOR;
    }

    if ((ssl->options.mask & WOLFSSL_OP_NO_TLSv1_1) == WOLFSSL_OP_NO_TLSv1_1) {
        WOLFSSL_MSG("Disabling TLS 1.1");
        if (ssl->version.minor == TLSv1_1_MINOR)
            ssl->version.minor = TLSv1_MINOR;
    }

    if ((ssl->options.mask & WOLFSSL_OP_NO_TLSv1) == WOLFSSL_OP_NO_TLSv1) {
        WOLFSSL_MSG("Disabling TLS 1.0");
        if (ssl->version.minor == TLSv1_MINOR)
            ssl->version.minor = SSLv3_MINOR;
    }

    if ((ssl->options.mask & WOLFSSL_OP_NO_COMPRESSION)
        == WOLFSSL_OP_NO_COMPRESSION) {
    #ifdef HAVE_LIBZ
        ssl->options.usingCompression = 0;
    #endif
    }

#if defined(HAVE_SESSION_TICKET) && (defined(OPENSSL_EXTRA) \
        || defined(HAVE_WEBSERVER) || defined(WOLFSSL_WPAS_SMALL))
    if ((ssl->options.mask & WOLFSSL_OP_NO_TICKET) == WOLFSSL_OP_NO_TICKET) {
      ssl->options.noTicketTls12 = 1;
    }
#endif


    /* in the case of a version change the cipher suites should be reset */
#ifndef NO_PSK
    havePSK = ssl->options.havePSK;
#endif
#ifdef NO_RSA
    haveRSA = 0;
#endif
#ifndef NO_CERTS
    keySz = ssl->buffers.keySz;
#endif

    if (ssl->options.side != WOLFSSL_NEITHER_END) {
        if (AllocateSuites(ssl) != 0)
            return 0;
        if (!ssl->suites->setSuites) {
            InitSuites(ssl->suites, ssl->version, keySz, haveRSA,
                       havePSK, ssl->options.haveDH, ssl->options.haveECDSAsig,
                       ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                       ssl->options.useAnon,
                       TRUE, TRUE, TRUE, TRUE, ssl->options.side);
        }
        else {
            /* Only preserve overlapping suites */
            Suites tmpSuites;
            word16 in, out;
            word16 haveECDSAsig, haveStaticECC;
#ifdef NO_RSA
            haveECDSAsig = 1;
            haveStaticECC = 1;
#else
            haveECDSAsig = 0;
            haveStaticECC = ssl->options.haveStaticECC;
#endif
            XMEMSET(&tmpSuites, 0, sizeof(Suites));
            /* Get all possible ciphers and sigalgs for the version. Following
             * options limit the allowed ciphers so let's try to get as many as
             * possible.
             * - haveStaticECC turns off haveRSA
             * - haveECDSAsig turns off haveRSAsig */
            InitSuites(&tmpSuites, ssl->version, 0, 1, 1, 1, haveECDSAsig, 1, 1,
                    haveStaticECC, 1, 1, 1, 1, 1, ssl->options.side);
            for (in = 0, out = 0; in < ssl->suites->suiteSz; in += SUITE_LEN) {
                if (FindSuite(&tmpSuites, ssl->suites->suites[in],
                        ssl->suites->suites[in+1]) >= 0) {
                    ssl->suites->suites[out] = ssl->suites->suites[in];
                    ssl->suites->suites[out+1] = ssl->suites->suites[in+1];
                    out += SUITE_LEN;
                }
            }
            ssl->suites->suiteSz = out;
            for (in = 0, out = 0; in < ssl->suites->hashSigAlgoSz; in += 2) {
                if (FindHashSig(&tmpSuites, ssl->suites->hashSigAlgo[in],
                    ssl->suites->hashSigAlgo[in+1]) >= 0) {
                    ssl->suites->hashSigAlgo[out] =
                            ssl->suites->hashSigAlgo[in];
                    ssl->suites->hashSigAlgo[out+1] =
                            ssl->suites->hashSigAlgo[in+1];
                    out += 2;
                }
            }
            ssl->suites->hashSigAlgoSz = out;
        }
    }

    return (long)ssl->options.mask;
}


long wolfSSL_get_options(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_options");
    if(ssl == NULL)
        return WOLFSSL_FAILURE;
    return (long)ssl->options.mask;
}

#if defined(HAVE_SECURE_RENEGOTIATION) \
        || defined(HAVE_SERVER_RENEGOTIATION_INFO)
/* clears the counter for number of renegotiations done
 * returns the current count before it is cleared */
long wolfSSL_clear_num_renegotiations(WOLFSSL *s)
{
    long total;

    WOLFSSL_ENTER("wolfSSL_clear_num_renegotiations");
    if (s == NULL)
        return 0;

    total = s->secure_rene_count;
    s->secure_rene_count = 0;
    return total;
}


/* return the number of renegotiations since wolfSSL_new */
long wolfSSL_total_renegotiations(WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_total_renegotiations");
    return wolfSSL_num_renegotiations(s);
}


/* return the number of renegotiations since wolfSSL_new */
long wolfSSL_num_renegotiations(WOLFSSL* s)
{
    if (s == NULL) {
        return 0;
    }

    return s->secure_rene_count;
}


/* Is there a renegotiation currently in progress? */
int  wolfSSL_SSL_renegotiate_pending(WOLFSSL *s)
{
    return s && s->options.handShakeDone &&
            s->options.handShakeState != HANDSHAKE_DONE ? 1 : 0;
}
#endif /* HAVE_SECURE_RENEGOTIATION || HAVE_SERVER_RENEGOTIATION_INFO */

#ifdef OPENSSL_EXTRA

long wolfSSL_clear_options(WOLFSSL* ssl, long opt)
{
    WOLFSSL_ENTER("wolfSSL_clear_options");
    if(ssl == NULL)
        return WOLFSSL_FAILURE;
    ssl->options.mask &= ~opt;
    return ssl->options.mask;
}

#ifdef HAVE_PK_CALLBACKS
long wolfSSL_set_tlsext_debug_arg(WOLFSSL* ssl, void *arg)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    ssl->loggingCtx = arg;
    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_PK_CALLBACKS */

/*** TBD ***/
#ifndef NO_WOLFSSL_STUB
int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* st)
{
    (void)st;
    WOLFSSL_STUB("wolfSSL_sk_SSL_COMP_zero");
    /* wolfSSL_set_options(ssl, SSL_OP_NO_COMPRESSION); */
    return WOLFSSL_FAILURE;
}
#endif

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type)
{
    WOLFSSL_ENTER("wolfSSL_set_tlsext_status_type");

    if (s == NULL){
        return BAD_FUNC_ARG;
    }

    if (type == WOLFSSL_TLSEXT_STATUSTYPE_ocsp){
        int r = TLSX_UseCertificateStatusRequest(&s->extensions, (byte)type, 0,
            s, s->heap, s->devId);
        return (long)r;
    } else {
        WOLFSSL_MSG(
       "SSL_set_tlsext_status_type only supports TLSEXT_STATUSTYPE_ocsp type.");
        return WOLFSSL_FAILURE;
    }

}

long wolfSSL_get_tlsext_status_type(WOLFSSL *s)
{
    TLSX* extension;

    if (s == NULL)
        return WOLFSSL_FATAL_ERROR;
    extension = TLSX_Find(s->extensions, TLSX_STATUS_REQUEST);
    return extension != NULL ? WOLFSSL_TLSEXT_STATUSTYPE_ocsp : WOLFSSL_FATAL_ERROR;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */

#ifndef NO_WOLFSSL_STUB
long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_get_tlsext_status_exts");
    return WOLFSSL_FAILURE;
}
#endif

/*** TBD ***/
#ifndef NO_WOLFSSL_STUB
long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_set_tlsext_status_exts");
    return WOLFSSL_FAILURE;
}
#endif

/*** TBD ***/
#ifndef NO_WOLFSSL_STUB
long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_get_tlsext_status_ids");
    return WOLFSSL_FAILURE;
}
#endif

/*** TBD ***/
#ifndef NO_WOLFSSL_STUB
long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_set_tlsext_status_ids");
    return WOLFSSL_FAILURE;
}
#endif

#ifndef NO_WOLFSSL_STUB
/*** TBD ***/
WOLFSSL_EVP_PKEY *wolfSSL_get_privatekey(const WOLFSSL *ssl)
{
    (void)ssl;
    WOLFSSL_STUB("SSL_get_privatekey");
    return NULL;
}
#endif

#ifndef NO_WOLFSSL_STUB
/*** TBD ***/
void WOLFSSL_CTX_set_tmp_dh_callback(WOLFSSL_CTX *ctx,
    WOLFSSL_DH *(*dh) (WOLFSSL *ssl, int is_export, int keylength))
{
    (void)ctx;
    (void)dh;
    WOLFSSL_STUB("WOLFSSL_CTX_set_tmp_dh_callback");
}
#endif

#ifndef NO_WOLFSSL_STUB
/*** TBD ***/
WOLF_STACK_OF(WOLFSSL_COMP) *WOLFSSL_COMP_get_compression_methods(void)
{
    WOLFSSL_STUB("WOLFSSL_COMP_get_compression_methods");
    return NULL;
}
#endif


int wolfSSL_sk_SSL_CIPHER_num(const WOLF_STACK_OF(WOLFSSL_CIPHER)* p)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_num");
    if (p == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }
    return (int)p->num;
}

WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(WOLFSSL_STACK* sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_value");
    return (WOLFSSL_CIPHER*)wolfSSL_sk_value(sk, i);
}

#if !defined(NETOS)
void wolfSSL_ERR_load_SSL_strings(void)
{

}
#endif

#ifdef HAVE_OCSP
long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char **resp)
{
    if (s == NULL || resp == NULL)
        return 0;

    *resp = s->ocspResp;
    return s->ocspRespSz;
}

long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *s, unsigned char *resp,
    int len)
{
    if (s == NULL)
        return WOLFSSL_FAILURE;

    s->ocspResp   = resp;
    s->ocspRespSz = len;

    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_OCSP */

#ifdef HAVE_MAX_FRAGMENT
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/**
 * Set max fragment tls extension
 * @param c a pointer to WOLFSSL_CTX object
 * @param mode maximum fragment length mode
 * @return 1 on success, otherwise 0 or negative error code
 */
int wolfSSL_CTX_set_tlsext_max_fragment_length(WOLFSSL_CTX *c,
                                               unsigned char mode)
{
    if (c == NULL || (mode < WOLFSSL_MFL_2_9 || mode > WOLFSSL_MFL_2_12 ))
        return BAD_FUNC_ARG;

    return wolfSSL_CTX_UseMaxFragment(c, mode);
}
/**
 * Set max fragment tls extension
 * @param c a pointer to WOLFSSL object
 * @param mode maximum fragment length mode
 * @return 1 on success, otherwise 0 or negative error code
 */
int wolfSSL_set_tlsext_max_fragment_length(WOLFSSL *s, unsigned char mode)
{
    if (s == NULL || (mode < WOLFSSL_MFL_2_9 || mode > WOLFSSL_MFL_2_12 ))
        return BAD_FUNC_ARG;

    return wolfSSL_UseMaxFragment(s, mode);
}
#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS */
#endif /* HAVE_MAX_FRAGMENT */

#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_HAVE_TLS_UNIQUE
size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;

    WOLFSSL_ENTER("wolfSSL_get_finished");

    if (!ssl || !buf || count < TLS_FINISHED_SZ) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        len = ssl->serverFinished_len;
        XMEMCPY(buf, ssl->serverFinished, len);
    }
    else {
        len = ssl->clientFinished_len;
        XMEMCPY(buf, ssl->clientFinished, len);
    }
    return len;
}

size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;
    WOLFSSL_ENTER("wolfSSL_get_peer_finished");

    if (!ssl || !buf || count < TLS_FINISHED_SZ) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        len = ssl->serverFinished_len;
        XMEMCPY(buf, ssl->serverFinished, len);
    }
    else {
        len = ssl->clientFinished_len;
        XMEMCPY(buf, ssl->clientFinished, len);
    }

    return len;
}
#endif /* WOLFSSL_HAVE_TLS_UNIQUE */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(OPENSSL_ALL)
long wolfSSL_get_verify_result(const WOLFSSL *ssl)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    return ssl->peerVerifyRet;
}
#endif

#ifdef OPENSSL_EXTRA

#ifndef NO_WOLFSSL_STUB
/* shows the number of accepts attempted by CTX in it's lifetime */
long wolfSSL_CTX_sess_accept(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_accept");
    (void)ctx;
    return 0;
}
#endif

#ifndef NO_WOLFSSL_STUB
/* shows the number of connects attempted CTX in it's lifetime */
long wolfSSL_CTX_sess_connect(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_connect");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
/* shows the number of accepts completed by CTX in it's lifetime */
long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_accept_good");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
/* shows the number of connects completed by CTX in it's lifetime */
long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_connect_good");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
/* shows the number of renegotiation accepts attempted by CTX */
long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_accept_renegotiate");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
/* shows the number of renegotiation accepts attempted by CTX */
long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_connect_renegotiate");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_sess_hits(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_hits");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_cb_hits");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_cache_full");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_sess_misses(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_misses");
    (void)ctx;
    return 0;
}
#endif


#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX* ctx)
{
    WOLFSSL_STUB("wolfSSL_CTX_sess_timeouts");
    (void)ctx;
    return 0;
}
#endif

#ifndef NO_CERTS

long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg)
{
    if (ctx == NULL || ctx->cm == NULL) {
        return WOLFSSL_FAILURE;
    }

    ctx->cm->ocspIOCtx = arg;
    return WOLFSSL_SUCCESS;
}

#endif /* !NO_CERTS */

int wolfSSL_get_read_ahead(const WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    return ssl->readAhead;
}


int wolfSSL_set_read_ahead(WOLFSSL* ssl, int v)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    ssl->readAhead = (byte)v;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    return ctx->readAhead;
}


int wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v)
{
    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    ctx->readAhead = (byte)v;

    return WOLFSSL_SUCCESS;
}


long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(WOLFSSL_CTX* ctx,
        void* arg)
{
    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }

    ctx->userPRFArg = arg;
    return WOLFSSL_SUCCESS;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
int wolfSSL_sk_num(const WOLFSSL_STACK* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_num");
    if (sk == NULL)
        return 0;
    return (int)sk->num;
}

void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_value");

    for (; sk != NULL && i > 0; i--)
        sk = sk->next;
    if (sk == NULL)
        return NULL;

    switch (sk->type) {
        case STACK_TYPE_X509:
            return (void*)sk->data.x509;
        case STACK_TYPE_GEN_NAME:
            return (void*)sk->data.gn;
        case STACK_TYPE_BIO:
            return (void*)sk->data.bio;
        case STACK_TYPE_OBJ:
            return (void*)sk->data.obj;
        case STACK_TYPE_STRING:
            return (void*)sk->data.string;
        case STACK_TYPE_CIPHER:
            return (void*)&sk->data.cipher;
        case STACK_TYPE_ACCESS_DESCRIPTION:
            return (void*)sk->data.access;
        case STACK_TYPE_X509_EXT:
            return (void*)sk->data.ext;
        case STACK_TYPE_X509_REQ_ATTR:
            return (void*)sk->data.generic;
        case STACK_TYPE_NULL:
            return (void*)sk->data.generic;
        case STACK_TYPE_X509_NAME:
            return (void*)sk->data.name;
        case STACK_TYPE_X509_NAME_ENTRY:
            return (void*)sk->data.name_entry;
        case STACK_TYPE_CONF_VALUE:
    #ifdef OPENSSL_EXTRA
            return (void*)sk->data.conf;
    #else
            return NULL;
    #endif
        case STACK_TYPE_X509_INFO:
            return (void*)sk->data.info;
        case STACK_TYPE_BY_DIR_entry:
            return (void*)sk->data.dir_entry;
        case STACK_TYPE_BY_DIR_hash:
            return (void*)sk->data.dir_hash;
        case STACK_TYPE_X509_OBJ:
            return (void*)sk->data.x509_obj;
        case STACK_TYPE_DIST_POINT:
            return (void*)sk->data.dp;
        case STACK_TYPE_X509_CRL:
            return (void*)sk->data.crl;
        default:
            return (void*)sk->data.generic;
    }
}

/* copies over data of "in" to "out" */
static void wolfSSL_CIPHER_copy(WOLFSSL_CIPHER* in, WOLFSSL_CIPHER* out)
{
    if (in == NULL || out == NULL)
        return;

    *out = *in;
}

WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* sk)
{

    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK* last = NULL;

    WOLFSSL_ENTER("wolfSSL_sk_dup");

    while (sk) {
        WOLFSSL_STACK* cur = wolfSSL_sk_new_node(sk->heap);

        if (!cur) {
            WOLFSSL_MSG("wolfSSL_sk_new_node error");
            goto error;
        }

        if (!ret) {
            /* Set first node */
            ret = cur;
        }

        if (last) {
            last->next = cur;
        }

        XMEMCPY(cur, sk, sizeof(WOLFSSL_STACK));

        /* We will allocate new memory for this */
        XMEMSET(&cur->data, 0, sizeof(cur->data));
        cur->next = NULL;

        switch (sk->type) {
            case STACK_TYPE_X509:
                if (!sk->data.x509)
                    break;
                cur->data.x509 = wolfSSL_X509_dup(sk->data.x509);
                if (!cur->data.x509) {
                    WOLFSSL_MSG("wolfSSL_X509_dup error");
                    goto error;
                }
                break;
            case STACK_TYPE_CIPHER:
                wolfSSL_CIPHER_copy(&sk->data.cipher, &cur->data.cipher);
                break;
            case STACK_TYPE_GEN_NAME:
                if (!sk->data.gn)
                    break;
                cur->data.gn = wolfSSL_GENERAL_NAME_dup(sk->data.gn);
                if (!cur->data.gn) {
                    WOLFSSL_MSG("wolfSSL_GENERAL_NAME_new error");
                    goto error;
                }
                break;
            case STACK_TYPE_OBJ:
                if (!sk->data.obj)
                    break;
                cur->data.obj = wolfSSL_ASN1_OBJECT_dup(sk->data.obj);
                if (!cur->data.obj) {
                    WOLFSSL_MSG("wolfSSL_ASN1_OBJECT_dup error");
                    goto error;
                }
                break;
            case STACK_TYPE_BIO:
            case STACK_TYPE_STRING:
            case STACK_TYPE_ACCESS_DESCRIPTION:
            case STACK_TYPE_X509_EXT:
            case STACK_TYPE_X509_REQ_ATTR:
            case STACK_TYPE_NULL:
            case STACK_TYPE_X509_NAME:
            case STACK_TYPE_X509_NAME_ENTRY:
            case STACK_TYPE_CONF_VALUE:
            case STACK_TYPE_X509_INFO:
            case STACK_TYPE_BY_DIR_entry:
            case STACK_TYPE_BY_DIR_hash:
            case STACK_TYPE_X509_OBJ:
            case STACK_TYPE_DIST_POINT:
            case STACK_TYPE_X509_CRL:
            default:
                WOLFSSL_MSG("Unsupported stack type");
                goto error;
        }

        sk = sk->next;
        last = cur;
    }
    return ret;

error:
    if (ret) {
        wolfSSL_sk_GENERAL_NAME_free(ret);
    }
    return NULL;
}


WOLFSSL_STACK* wolfSSL_shallow_sk_dup(WOLFSSL_STACK* sk)
{

    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK** prev = &ret;

    WOLFSSL_ENTER("wolfSSL_shallow_sk_dup");

    for (; sk != NULL; sk = sk->next) {
        WOLFSSL_STACK* cur = wolfSSL_sk_new_node(sk->heap);

        if (!cur) {
            WOLFSSL_MSG("wolfSSL_sk_new_node error");
            goto error;
        }

        XMEMCPY(cur, sk, sizeof(WOLFSSL_STACK));
        cur->next = NULL;

        *prev = cur;
        prev = &cur->next;
    }
    return ret;

error:
    if (ret) {
        wolfSSL_sk_free(ret);
    }
    return NULL;
}

/* Free the just the stack structure */
void wolfSSL_sk_free(WOLFSSL_STACK* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_free");

    while (sk != NULL) {
        WOLFSSL_STACK* next = sk->next;
        XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
        sk = next;
    }
}

/* Frees each node in the stack and frees the stack.
 */
void wolfSSL_sk_GENERIC_pop_free(WOLFSSL_STACK* sk,
    void (*f) (void*))
{
    WOLFSSL_ENTER("wolfSSL_sk_GENERIC_pop_free");
    wolfSSL_sk_pop_free(sk, (wolfSSL_sk_freefunc)f);
}

/* return 1 on success 0 on fail */
int wolfSSL_sk_GENERIC_push(WOLFSSL_STACK* sk, void* generic)
{
    WOLFSSL_ENTER("wolfSSL_sk_GENERIC_push");

    return wolfSSL_sk_push(sk, generic);
}
void wolfSSL_sk_GENERIC_free(WOLFSSL_STACK* sk)
{
    wolfSSL_sk_free(sk);
}

/* Pop off data from the stack. Checks that the type matches the stack type.
 *
 * @param [in, out] sk    Stack of objects.
 * @param [in]      type  Type of stack.
 * @return  Object on success.
 * @return  NULL when stack is NULL or no nodes left in stack.
 */
void* wolfssl_sk_pop_type(WOLFSSL_STACK* sk, WOLF_STACK_TYPE type)
{
    WOLFSSL_STACK* node;
    void* data = NULL;

    /* Check we have a stack passed in of the right type. */
    if ((sk != NULL) && (sk->type == type)) {
        /* Get the next node to become the new first node. */
        node = sk->next;
        /* Get the ASN.1 OBJECT_ID object in the first node. */
        data = sk->data.generic;

        /* Check whether there is a next node. */
        if (node != NULL) {
            /* Move content out of next node into current node. */
            sk->data.obj = node->data.obj;
            sk->next = node->next;
            /* Dispose of node. */
            XFREE(node, NULL, DYNAMIC_TYPE_ASN1);
        }
        else {
            /* No more nodes - clear out data. */
            sk->data.obj = NULL;
        }

        /* Decrement count as long as we thought we had nodes. */
        if (sk->num > 0) {
            sk->num -= 1;
        }
    }

    return data;
}

/* Free all nodes in a stack including the pushed objects */
void wolfSSL_sk_pop_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
                                                       wolfSSL_sk_freefunc func)
{
    WOLFSSL_ENTER("wolfSSL_sk_pop_free");

    if (sk == NULL) {
        /* pop_free can be called with NULL, do not print bad argument */
        return;
    }
    #if defined(WOLFSSL_QT)
    /* In Qt v15.5, it calls OPENSSL_sk_free(xxx, OPENSSL_sk_free).
    *  By using OPENSSL_sk_free for free causes access violation.
    *  Therefore, switching free func to wolfSSL_ACCESS_DESCRIPTION_free
    *  is needed even the func isn't NULL.
    */
    if (sk->type == STACK_TYPE_ACCESS_DESCRIPTION) {
        func = (wolfSSL_sk_freefunc)wolfSSL_ACCESS_DESCRIPTION_free;
    }
    #endif
    if (func == NULL) {
        switch(sk->type) {
            case STACK_TYPE_ACCESS_DESCRIPTION:
            #if defined(OPENSSL_ALL)
                func = (wolfSSL_sk_freefunc)wolfSSL_ACCESS_DESCRIPTION_free;
            #endif
                break;
            case STACK_TYPE_X509:
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_free;
                break;
            case STACK_TYPE_X509_OBJ:
            #ifdef OPENSSL_ALL
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_OBJECT_free;
            #endif
                break;
            case STACK_TYPE_OBJ:
                func = (wolfSSL_sk_freefunc)wolfSSL_ASN1_OBJECT_free;
                break;
            case STACK_TYPE_DIST_POINT:
            #ifdef OPENSSL_EXTRA
                func = (wolfSSL_sk_freefunc)wolfSSL_DIST_POINT_free;
            #endif
                break;
            case STACK_TYPE_GEN_NAME:
                func = (wolfSSL_sk_freefunc)wolfSSL_GENERAL_NAME_free;
                break;
            case STACK_TYPE_STRING:
            #if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
                defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
                func = (wolfSSL_sk_freefunc)wolfSSL_WOLFSSL_STRING_free;
            #endif
                break;
            case STACK_TYPE_X509_NAME:
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
                && !defined(WOLFCRYPT_ONLY)
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_NAME_free;
            #endif
                break;
            case STACK_TYPE_X509_NAME_ENTRY:
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
                && !defined(WOLFCRYPT_ONLY)
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_NAME_ENTRY_free;
            #endif
                break;
            case STACK_TYPE_X509_EXT:
            #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_EXTENSION_free;
            #endif
                break;
            case STACK_TYPE_X509_REQ_ATTR:
            #if defined(OPENSSL_ALL) && \
                (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_REQ))
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_ATTRIBUTE_free;
            #endif
                break;
            case STACK_TYPE_CONF_VALUE:
            #if defined(OPENSSL_ALL)
                func = (wolfSSL_sk_freefunc)wolfSSL_X509V3_conf_free;
            #endif
                break;
            case STACK_TYPE_X509_INFO:
            #if defined(OPENSSL_ALL)
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_INFO_free;
            #endif
                break;
            case STACK_TYPE_BIO:
#if !defined(NO_BIO) && defined(OPENSSL_EXTRA)
                func = (wolfSSL_sk_freefunc)wolfSSL_BIO_vfree;
#endif
                break;
            case STACK_TYPE_BY_DIR_entry:
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
                func = (wolfSSL_sk_freefunc)wolfSSL_BY_DIR_entry_free;
#endif
                break;
            case STACK_TYPE_BY_DIR_hash:
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
                func = (wolfSSL_sk_freefunc)wolfSSL_BY_DIR_HASH_free;
#endif
                break;
            case STACK_TYPE_X509_CRL:
#if defined(HAVE_CRL) && (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL))
                func = (wolfSSL_sk_freefunc)wolfSSL_X509_CRL_free;
#endif
                break;
            case STACK_TYPE_CIPHER:
            case STACK_TYPE_NULL:
            default:
                break;
        }
    }

    while (sk != NULL) {
        WOLFSSL_STACK* next = sk->next;

        if (func != NULL) {
            if (sk->type != STACK_TYPE_CIPHER)
                func(sk->data.generic);
        }
        XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
        sk = next;
    }
}

/* Creates a new stack of the requested type.
 *
 * @param [in] type  Type of stack.
 * @return  Empty stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfssl_sk_new_type(WOLF_STACK_TYPE type)
{
    WOLFSSL_STACK* sk;

    /* Allocate a new stack - first node. */
    sk = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (sk == NULL) {
        WOLFSSL_MSG("WOLFSSL_STACK memory error");
    }
    else {
        /* Clear node and set type. */
        XMEMSET(sk, 0, sizeof(WOLFSSL_STACK));
        sk->type = type;
    }

    return sk;
}

/* Creates and returns a new null stack. */
WOLFSSL_STACK* wolfSSL_sk_new_null(void)
{
    WOLFSSL_ENTER("wolfSSL_sk_new_null");

    return wolfssl_sk_new_type(STACK_TYPE_NULL);
}

int wolfSSL_sk_SSL_COMP_num(WOLF_STACK_OF(WOLFSSL_COMP)* sk)
{
    if (sk == NULL)
        return 0;
    return (int)sk->num;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA

#if defined(HAVE_EX_DATA) && !defined(NO_FILESYSTEM)
int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char *fname)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    WOLFSSL_ENTER("wolfSSL_cmp_peer_cert_to_file");
    if (ssl != NULL && fname != NULL)
    {
    #ifdef WOLFSSL_SMALL_STACK
        byte           staticBuffer[1]; /* force heap usage */
    #else
        byte           staticBuffer[FILE_BUFFER_SIZE];
    #endif
        byte*          myBuffer  = staticBuffer;
        int            dynamic   = 0;
        XFILE          file;
        long           sz        = 0;
        WOLFSSL_CTX*   ctx       = ssl->ctx;
        WOLFSSL_X509*  peer_cert = &ssl->peerCert;
        DerBuffer*     fileDer = NULL;

        file = XFOPEN(fname, "rb");
        if (file == XBADFILE)
            return WOLFSSL_BAD_FILE;

        if (XFSEEK(file, 0, XSEEK_END) != 0) {
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }
        sz = XFTELL(file);
        if (XFSEEK(file, 0, XSEEK_SET) != 0) {
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }

        if (sz > MAX_WOLFSSL_FILE_SIZE || sz < 0) {
            WOLFSSL_MSG("cmp_peer_cert_to_file size error");
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }

        if (sz > (long)sizeof(staticBuffer)) {
            WOLFSSL_MSG("Getting dynamic buffer");
            myBuffer = (byte*)XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
            dynamic = 1;
        }

        if ((myBuffer != NULL) &&
            (sz > 0) &&
            (XFREAD(myBuffer, 1, (size_t)sz, file) == (size_t)sz) &&
            (PemToDer(myBuffer, (long)sz, CERT_TYPE,
                      &fileDer, ctx->heap, NULL, NULL) == 0) &&
            (fileDer->length != 0) &&
            (fileDer->length == peer_cert->derCert->length) &&
            (XMEMCMP(peer_cert->derCert->buffer, fileDer->buffer,
                                                fileDer->length) == 0))
        {
            ret = 0;
        }

        FreeDer(&fileDer);

        if (dynamic)
            XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

        XFCLOSE(file);
    }

    return ret;
}
#endif
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
const WOLFSSL_ObjectInfo wolfssl_object_info[] = {
#ifndef NO_CERTS
    /* oidCertExtType */
    { WC_NID_basic_constraints, BASIC_CA_OID, oidCertExtType, "basicConstraints",
      "X509v3 Basic Constraints"},
    { WC_NID_subject_alt_name, ALT_NAMES_OID, oidCertExtType, "subjectAltName",
      "X509v3 Subject Alternative Name"},
    { WC_NID_crl_distribution_points, CRL_DIST_OID, oidCertExtType,
      "crlDistributionPoints", "X509v3 CRL Distribution Points"},
    { WC_NID_info_access, AUTH_INFO_OID, oidCertExtType, "authorityInfoAccess",
      "Authority Information Access"},
    { WC_NID_authority_key_identifier, AUTH_KEY_OID, oidCertExtType,
      "authorityKeyIdentifier", "X509v3 Authority Key Identifier"},
    { WC_NID_subject_key_identifier, SUBJ_KEY_OID, oidCertExtType,
      "subjectKeyIdentifier", "X509v3 Subject Key Identifier"},
    { WC_NID_key_usage, KEY_USAGE_OID, oidCertExtType, "keyUsage",
      "X509v3 Key Usage"},
    { WC_NID_inhibit_any_policy, INHIBIT_ANY_OID, oidCertExtType,
      "inhibitAnyPolicy", "X509v3 Inhibit Any Policy"},
    { WC_NID_ext_key_usage, EXT_KEY_USAGE_OID, oidCertExtType,
      "extendedKeyUsage", "X509v3 Extended Key Usage"},
    { WC_NID_name_constraints, NAME_CONS_OID, oidCertExtType,
      "nameConstraints", "X509v3 Name Constraints"},
    { WC_NID_certificate_policies, CERT_POLICY_OID, oidCertExtType,
      "certificatePolicies", "X509v3 Certificate Policies"},

    /* oidCertAuthInfoType */
    { WC_NID_ad_OCSP, AIA_OCSP_OID, oidCertAuthInfoType, "OCSP",
      "OCSP"},
    { WC_NID_ad_ca_issuers, AIA_CA_ISSUER_OID, oidCertAuthInfoType,
      "caIssuers", "CA Issuers"},

    /* oidCertPolicyType */
    { WC_NID_any_policy, CP_ANY_OID, oidCertPolicyType, "anyPolicy",
      "X509v3 Any Policy"},

    /* oidCertAltNameType */
    { WC_NID_hw_name_oid, HW_NAME_OID, oidCertAltNameType, "Hardware name",""},

    /* oidCertKeyUseType */
    { WC_NID_anyExtendedKeyUsage, EKU_ANY_OID, oidCertKeyUseType,
      "anyExtendedKeyUsage", "Any Extended Key Usage"},
    { EKU_SERVER_AUTH_OID, EKU_SERVER_AUTH_OID, oidCertKeyUseType,
      "serverAuth", "TLS Web Server Authentication"},
    { EKU_CLIENT_AUTH_OID, EKU_CLIENT_AUTH_OID, oidCertKeyUseType,
      "clientAuth", "TLS Web Client Authentication"},
    { EKU_OCSP_SIGN_OID, EKU_OCSP_SIGN_OID, oidCertKeyUseType,
      "OCSPSigning", "OCSP Signing"},

    /* oidCertNameType */
    { WC_NID_commonName, WC_NID_commonName, oidCertNameType, "CN", "commonName"},
#if !defined(WOLFSSL_CERT_REQ)
    { WC_NID_surname, WC_NID_surname, oidCertNameType, "SN", "surname"},
#endif
    { WC_NID_serialNumber, WC_NID_serialNumber, oidCertNameType, "serialNumber",
      "serialNumber"},
    { WC_NID_userId, WC_NID_userId, oidCertNameType, "UID", "userid"},
    { WC_NID_countryName, WC_NID_countryName, oidCertNameType, "C", "countryName"},
    { WC_NID_localityName, WC_NID_localityName, oidCertNameType, "L", "localityName"},
    { WC_NID_stateOrProvinceName, WC_NID_stateOrProvinceName, oidCertNameType, "ST",
      "stateOrProvinceName"},
    { WC_NID_streetAddress, WC_NID_streetAddress, oidCertNameType, "street",
      "streetAddress"},
    { WC_NID_organizationName, WC_NID_organizationName, oidCertNameType, "O",
      "organizationName"},
    { WC_NID_organizationalUnitName, WC_NID_organizationalUnitName, oidCertNameType,
      "OU", "organizationalUnitName"},
    { WC_NID_emailAddress, WC_NID_emailAddress, oidCertNameType, "emailAddress",
      "emailAddress"},
    { WC_NID_domainComponent, WC_NID_domainComponent, oidCertNameType, "DC",
      "domainComponent"},
    { WC_NID_rfc822Mailbox, WC_NID_rfc822Mailbox, oidCertNameType, "rfc822Mailbox",
      "rfc822Mailbox"},
    { WC_NID_favouriteDrink, WC_NID_favouriteDrink, oidCertNameType, "favouriteDrink",
      "favouriteDrink"},
    { WC_NID_businessCategory, WC_NID_businessCategory, oidCertNameType,
      "businessCategory", "businessCategory"},
    { WC_NID_jurisdictionCountryName, WC_NID_jurisdictionCountryName, oidCertNameType,
      "jurisdictionC", "jurisdictionCountryName"},
    { WC_NID_jurisdictionStateOrProvinceName, WC_NID_jurisdictionStateOrProvinceName,
      oidCertNameType, "jurisdictionST", "jurisdictionStateOrProvinceName"},
    { WC_NID_postalCode, WC_NID_postalCode, oidCertNameType, "postalCode",
      "postalCode"},
    { WC_NID_userId, WC_NID_userId, oidCertNameType, "UID", "userId"},

#if defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_NAME_ALL)
    { WC_NID_pkcs9_challengePassword, CHALLENGE_PASSWORD_OID,
            oidCsrAttrType, "challengePassword", "challengePassword"},
    { WC_NID_pkcs9_contentType, PKCS9_CONTENT_TYPE_OID,
        oidCsrAttrType, "contentType", "contentType" },
    { WC_NID_pkcs9_unstructuredName, UNSTRUCTURED_NAME_OID,
        oidCsrAttrType, "unstructuredName", "unstructuredName" },
    { WC_NID_name, NAME_OID, oidCsrAttrType, "name", "name" },
    { WC_NID_surname, SURNAME_OID,
        oidCsrAttrType, "surname", "surname" },
    { WC_NID_givenName, GIVEN_NAME_OID,
        oidCsrAttrType, "givenName", "givenName" },
    { WC_NID_initials, INITIALS_OID,
        oidCsrAttrType, "initials", "initials" },
    { WC_NID_dnQualifier, DNQUALIFIER_OID,
        oidCsrAttrType, "dnQualifer", "dnQualifier" },
#endif
#endif
#ifdef OPENSSL_EXTRA /* OPENSSL_EXTRA_X509_SMALL only needs the above */
        /* oidHashType */
    #ifdef WOLFSSL_MD2
        { WC_NID_md2, MD2h, oidHashType, "MD2", "md2"},
    #endif
    #ifndef NO_MD5
        { WC_NID_md5, MD5h, oidHashType, "MD5", "md5"},
    #endif
    #ifndef NO_SHA
        { WC_NID_sha1, SHAh, oidHashType, "SHA1", "sha1"},
    #endif
    #ifdef WOLFSSL_SHA224
        { WC_NID_sha224, SHA224h, oidHashType, "SHA224", "sha224"},
    #endif
    #ifndef NO_SHA256
        { WC_NID_sha256, SHA256h, oidHashType, "SHA256", "sha256"},
    #endif
    #ifdef WOLFSSL_SHA384
        { WC_NID_sha384, SHA384h, oidHashType, "SHA384", "sha384"},
    #endif
    #ifdef WOLFSSL_SHA512
        { WC_NID_sha512, SHA512h, oidHashType, "SHA512", "sha512"},
    #endif
    #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_sha3_224, SHA3_224h, oidHashType, "SHA3-224", "sha3-224"},
        #endif
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_sha3_256, SHA3_256h, oidHashType, "SHA3-256", "sha3-256"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_sha3_384, SHA3_384h, oidHashType, "SHA3-384", "sha3-384"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_sha3_512, SHA3_512h, oidHashType, "SHA3-512", "sha3-512"},
        #endif
    #endif /* WOLFSSL_SHA3 */
    #ifdef WOLFSSL_SM3
        { WC_NID_sm3, SM3h, oidHashType, "SM3", "sm3"},
    #endif
        /* oidSigType */
    #ifndef NO_DSA
        #ifndef NO_SHA
        { WC_NID_dsaWithSHA1, CTC_SHAwDSA, oidSigType, "DSA-SHA1", "dsaWithSHA1"},
        { WC_NID_dsa_with_SHA256, CTC_SHA256wDSA, oidSigType, "dsa_with_SHA256",
          "dsa_with_SHA256"},
        #endif
    #endif /* NO_DSA */
    #ifndef NO_RSA
        #ifdef WOLFSSL_MD2
        { WC_NID_md2WithRSAEncryption, CTC_MD2wRSA, oidSigType, "RSA-MD2",
          "md2WithRSAEncryption"},
        #endif
        #ifndef NO_MD5
        { WC_NID_md5WithRSAEncryption, CTC_MD5wRSA, oidSigType, "RSA-MD5",
          "md5WithRSAEncryption"},
        #endif
        #ifndef NO_SHA
        { WC_NID_sha1WithRSAEncryption, CTC_SHAwRSA, oidSigType, "RSA-SHA1",
          "sha1WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA224
        { WC_NID_sha224WithRSAEncryption, CTC_SHA224wRSA, oidSigType, "RSA-SHA224",
          "sha224WithRSAEncryption"},
        #endif
        #ifndef NO_SHA256
        { WC_NID_sha256WithRSAEncryption, CTC_SHA256wRSA, oidSigType, "RSA-SHA256",
          "sha256WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA384
        { WC_NID_sha384WithRSAEncryption, CTC_SHA384wRSA, oidSigType, "RSA-SHA384",
          "sha384WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA512
        { WC_NID_sha512WithRSAEncryption, CTC_SHA512wRSA, oidSigType, "RSA-SHA512",
          "sha512WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_RSA_SHA3_224, CTC_SHA3_224wRSA, oidSigType, "RSA-SHA3-224",
          "sha3-224WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_RSA_SHA3_256, CTC_SHA3_256wRSA, oidSigType, "RSA-SHA3-256",
          "sha3-256WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_RSA_SHA3_384, CTC_SHA3_384wRSA, oidSigType, "RSA-SHA3-384",
          "sha3-384WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_RSA_SHA3_512, CTC_SHA3_512wRSA, oidSigType, "RSA-SHA3-512",
          "sha3-512WithRSAEncryption"},
        #endif
        #endif
        #ifdef WC_RSA_PSS
        { WC_NID_rsassaPss, CTC_RSASSAPSS, oidSigType, "RSASSA-PSS", "rsassaPss" },
        #endif
    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        #ifndef NO_SHA
        { WC_NID_ecdsa_with_SHA1, CTC_SHAwECDSA, oidSigType, "ecdsa-with-SHA1",
          "shaWithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA224
        { WC_NID_ecdsa_with_SHA224, CTC_SHA224wECDSA, oidSigType,
          "ecdsa-with-SHA224","sha224WithECDSA"},
        #endif
        #ifndef NO_SHA256
        { WC_NID_ecdsa_with_SHA256, CTC_SHA256wECDSA, oidSigType,
          "ecdsa-with-SHA256","sha256WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA384
        { WC_NID_ecdsa_with_SHA384, CTC_SHA384wECDSA, oidSigType,
          "ecdsa-with-SHA384","sha384WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA512
        { WC_NID_ecdsa_with_SHA512, CTC_SHA512wECDSA, oidSigType,
          "ecdsa-with-SHA512","sha512WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_ecdsa_with_SHA3_224, CTC_SHA3_224wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-224", "ecdsa_with_SHA3-224"},
        #endif
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_ecdsa_with_SHA3_256, CTC_SHA3_256wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-256", "ecdsa_with_SHA3-256"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_ecdsa_with_SHA3_384, CTC_SHA3_384wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-384", "ecdsa_with_SHA3-384"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_ecdsa_with_SHA3_512, CTC_SHA3_512wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-512", "ecdsa_with_SHA3-512"},
        #endif
        #endif
    #endif /* HAVE_ECC */

        /* oidKeyType */
    #ifndef NO_DSA
        { WC_NID_dsa, DSAk, oidKeyType, "DSA", "dsaEncryption"},
    #endif /* NO_DSA */
    #ifndef NO_RSA
        { WC_NID_rsaEncryption, RSAk, oidKeyType, "rsaEncryption",
          "rsaEncryption"},
    #ifdef WC_RSA_PSS
        { WC_NID_rsassaPss, RSAPSSk, oidKeyType, "RSASSA-PSS", "rsassaPss"},
    #endif
    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        { WC_NID_X9_62_id_ecPublicKey, ECDSAk, oidKeyType, "id-ecPublicKey",
                                                        "id-ecPublicKey"},
    #endif /* HAVE_ECC */
    #ifndef NO_DH
        { WC_NID_dhKeyAgreement, DHk, oidKeyType, "dhKeyAgreement",
          "dhKeyAgreement"},
    #endif
    #ifdef HAVE_ED448
        { WC_NID_ED448, ED448k,  oidKeyType, "ED448", "ED448"},
    #endif
    #ifdef HAVE_ED25519
        { WC_NID_ED25519, ED25519k,  oidKeyType, "ED25519", "ED25519"},
    #endif
    #ifdef HAVE_FALCON
        { CTC_FALCON_LEVEL1, FALCON_LEVEL1k,  oidKeyType, "Falcon Level 1",
                                                          "Falcon Level 1"},
        { CTC_FALCON_LEVEL5, FALCON_LEVEL5k,  oidKeyType, "Falcon Level 5",
                                                          "Falcon Level 5"},
    #endif /* HAVE_FALCON */
    #ifdef HAVE_DILITHIUM
        { CTC_DILITHIUM_LEVEL2, DILITHIUM_LEVEL2k,  oidKeyType,
          "Dilithium Level 2", "Dilithium Level 2"},
        { CTC_DILITHIUM_LEVEL3, DILITHIUM_LEVEL3k,  oidKeyType,
          "Dilithium Level 3", "Dilithium Level 3"},
        { CTC_DILITHIUM_LEVEL5, DILITHIUM_LEVEL5k,  oidKeyType,
          "Dilithium Level 5", "Dilithium Level 5"},
    #endif /* HAVE_DILITHIUM */

        /* oidCurveType */
    #ifdef HAVE_ECC
        { WC_NID_X9_62_prime192v1, ECC_SECP192R1_OID, oidCurveType, "prime192v1",
          "prime192v1"},
        { WC_NID_X9_62_prime192v2, ECC_PRIME192V2_OID, oidCurveType, "prime192v2",
          "prime192v2"},
        { WC_NID_X9_62_prime192v3, ECC_PRIME192V3_OID, oidCurveType, "prime192v3",
          "prime192v3"},

        { WC_NID_X9_62_prime239v1, ECC_PRIME239V1_OID, oidCurveType, "prime239v1",
          "prime239v1"},
        { WC_NID_X9_62_prime239v2, ECC_PRIME239V2_OID, oidCurveType, "prime239v2",
          "prime239v2"},
        { WC_NID_X9_62_prime239v3, ECC_PRIME239V3_OID, oidCurveType, "prime239v3",
          "prime239v3"},

        { WC_NID_X9_62_prime256v1, ECC_SECP256R1_OID, oidCurveType, "prime256v1",
          "prime256v1"},

        { WC_NID_secp112r1, ECC_SECP112R1_OID,  oidCurveType, "secp112r1",
          "secp112r1"},
        { WC_NID_secp112r2, ECC_SECP112R2_OID,  oidCurveType, "secp112r2",
          "secp112r2"},

        { WC_NID_secp128r1, ECC_SECP128R1_OID,  oidCurveType, "secp128r1",
          "secp128r1"},
        { WC_NID_secp128r2, ECC_SECP128R2_OID,  oidCurveType, "secp128r2",
          "secp128r2"},

        { WC_NID_secp160r1, ECC_SECP160R1_OID,  oidCurveType, "secp160r1",
          "secp160r1"},
        { WC_NID_secp160r2, ECC_SECP160R2_OID,  oidCurveType, "secp160r2",
          "secp160r2"},

        { WC_NID_secp224r1, ECC_SECP224R1_OID,  oidCurveType, "secp224r1",
          "secp224r1"},
        { WC_NID_secp384r1, ECC_SECP384R1_OID,  oidCurveType, "secp384r1",
          "secp384r1"},
        { WC_NID_secp521r1, ECC_SECP521R1_OID,  oidCurveType, "secp521r1",
          "secp521r1"},

        { WC_NID_secp160k1, ECC_SECP160K1_OID,  oidCurveType, "secp160k1",
          "secp160k1"},
        { WC_NID_secp192k1, ECC_SECP192K1_OID,  oidCurveType, "secp192k1",
          "secp192k1"},
        { WC_NID_secp224k1, ECC_SECP224K1_OID,  oidCurveType, "secp224k1",
          "secp224k1"},
        { WC_NID_secp256k1, ECC_SECP256K1_OID,  oidCurveType, "secp256k1",
          "secp256k1"},

        { WC_NID_brainpoolP160r1, ECC_BRAINPOOLP160R1_OID,  oidCurveType,
          "brainpoolP160r1", "brainpoolP160r1"},
        { WC_NID_brainpoolP192r1, ECC_BRAINPOOLP192R1_OID,  oidCurveType,
          "brainpoolP192r1", "brainpoolP192r1"},
        { WC_NID_brainpoolP224r1, ECC_BRAINPOOLP224R1_OID,  oidCurveType,
          "brainpoolP224r1", "brainpoolP224r1"},
        { WC_NID_brainpoolP256r1, ECC_BRAINPOOLP256R1_OID,  oidCurveType,
          "brainpoolP256r1", "brainpoolP256r1"},
        { WC_NID_brainpoolP320r1, ECC_BRAINPOOLP320R1_OID,  oidCurveType,
          "brainpoolP320r1", "brainpoolP320r1"},
        { WC_NID_brainpoolP384r1, ECC_BRAINPOOLP384R1_OID,  oidCurveType,
          "brainpoolP384r1", "brainpoolP384r1"},
        { WC_NID_brainpoolP512r1, ECC_BRAINPOOLP512R1_OID,  oidCurveType,
          "brainpoolP512r1", "brainpoolP512r1"},

    #ifdef WOLFSSL_SM2
        { WC_NID_sm2, ECC_SM2P256V1_OID, oidCurveType, "sm2", "sm2"},
    #endif
    #endif /* HAVE_ECC */

        /* oidBlkType */
    #ifdef WOLFSSL_AES_128
        { AES128CBCb, AES128CBCb, oidBlkType, "AES-128-CBC", "aes-128-cbc"},
    #endif
    #ifdef WOLFSSL_AES_192
        { AES192CBCb, AES192CBCb, oidBlkType, "AES-192-CBC", "aes-192-cbc"},
    #endif
    #ifdef WOLFSSL_AES_256
        { AES256CBCb, AES256CBCb, oidBlkType, "AES-256-CBC", "aes-256-cbc"},
    #endif
    #ifndef NO_DES3
        { WC_NID_des, DESb, oidBlkType, "DES-CBC", "des-cbc"},
        { WC_NID_des3, DES3b, oidBlkType, "DES-EDE3-CBC", "des-ede3-cbc"},
    #endif /* !NO_DES3 */
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        { WC_NID_chacha20_poly1305, WC_NID_chacha20_poly1305, oidBlkType,
          "ChaCha20-Poly1305", "chacha20-poly1305"},
    #endif

        /* oidOcspType */
    #ifdef HAVE_OCSP
        { WC_NID_id_pkix_OCSP_basic, OCSP_BASIC_OID, oidOcspType,
          "basicOCSPResponse", "Basic OCSP Response"},
        { OCSP_NONCE_OID, OCSP_NONCE_OID, oidOcspType, "Nonce", "OCSP Nonce"},
    #endif /* HAVE_OCSP */

    #ifndef NO_PWDBASED
        /* oidKdfType */
        { PBKDF2_OID, PBKDF2_OID, oidKdfType, "PBKDFv2", "PBKDF2"},

        /* oidPBEType */
        { PBE_SHA1_RC4_128, PBE_SHA1_RC4_128, oidPBEType,
          "PBE-SHA1-RC4-128", "pbeWithSHA1And128BitRC4"},
        { PBE_SHA1_DES, PBE_SHA1_DES, oidPBEType, "PBE-SHA1-DES",
          "pbeWithSHA1AndDES-CBC"},
        { PBE_SHA1_DES3, PBE_SHA1_DES3, oidPBEType, "PBE-SHA1-3DES",
          "pbeWithSHA1And3-KeyTripleDES-CBC"},
    #endif

        /* oidKeyWrapType */
    #ifdef WOLFSSL_AES_128
        { AES128_WRAP, AES128_WRAP, oidKeyWrapType, "AES-128 wrap",
          "aes128-wrap"},
    #endif
    #ifdef WOLFSSL_AES_192
        { AES192_WRAP, AES192_WRAP, oidKeyWrapType, "AES-192 wrap",
          "aes192-wrap"},
    #endif
    #ifdef WOLFSSL_AES_256
        { AES256_WRAP, AES256_WRAP, oidKeyWrapType, "AES-256 wrap",
          "aes256-wrap"},
    #endif

    #ifndef NO_PKCS7
        #ifndef NO_DH
        /* oidCmsKeyAgreeType */
            #ifndef NO_SHA
        { dhSinglePass_stdDH_sha1kdf_scheme, dhSinglePass_stdDH_sha1kdf_scheme,
          oidCmsKeyAgreeType, "dhSinglePass-stdDH-sha1kdf-scheme",
          "dhSinglePass-stdDH-sha1kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA224
        { dhSinglePass_stdDH_sha224kdf_scheme,
          dhSinglePass_stdDH_sha224kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha224kdf-scheme",
          "dhSinglePass-stdDH-sha224kdf-scheme"},
            #endif
            #ifndef NO_SHA256
        { dhSinglePass_stdDH_sha256kdf_scheme,
          dhSinglePass_stdDH_sha256kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha256kdf-scheme",
          "dhSinglePass-stdDH-sha256kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA384
        { dhSinglePass_stdDH_sha384kdf_scheme,
          dhSinglePass_stdDH_sha384kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha384kdf-scheme",
          "dhSinglePass-stdDH-sha384kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA512
        { dhSinglePass_stdDH_sha512kdf_scheme,
          dhSinglePass_stdDH_sha512kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha512kdf-scheme",
          "dhSinglePass-stdDH-sha512kdf-scheme"},
            #endif
        #endif
    #endif
    #if defined(WOLFSSL_APACHE_HTTPD)
        /* "1.3.6.1.5.5.7.8.7" */
        { WC_NID_id_on_dnsSRV, WC_NID_id_on_dnsSRV, oidCertNameType,
            WOLFSSL_SN_DNS_SRV, WOLFSSL_LN_DNS_SRV },

        /* "1.3.6.1.4.1.311.20.2.3" */
        { WC_NID_ms_upn, WOLFSSL_MS_UPN_SUM, oidCertExtType, WOLFSSL_SN_MS_UPN,
            WOLFSSL_LN_MS_UPN },

        /* "1.3.6.1.5.5.7.1.24" */
        { WC_NID_tlsfeature, WOLFSSL_TLS_FEATURE_SUM, oidTlsExtType,
            WOLFSSL_SN_TLS_FEATURE, WOLFSSL_LN_TLS_FEATURE },
    #endif
#endif /* OPENSSL_EXTRA */
};

#define WOLFSSL_OBJECT_INFO_SZ \
                (sizeof(wolfssl_object_info) / sizeof(*wolfssl_object_info))
const size_t wolfssl_object_info_sz = WOLFSSL_OBJECT_INFO_SZ;
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Free the dynamically allocated data.
 *
 * p  Pointer to dynamically allocated memory.
 */
void wolfSSL_OPENSSL_free(void* p)
{
    WOLFSSL_MSG("wolfSSL_OPENSSL_free");

    XFREE(p, NULL, DYNAMIC_TYPE_OPENSSL);
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA

void *wolfSSL_OPENSSL_malloc(size_t a)
{
    return (void *)XMALLOC(a, NULL, DYNAMIC_TYPE_OPENSSL);
}

int wolfSSL_OPENSSL_hexchar2int(unsigned char c)
{
    /* 'char' is unsigned on some platforms. */
    return (int)(signed char)HexCharToByte((char)c);
}

unsigned char *wolfSSL_OPENSSL_hexstr2buf(const char *str, long *len)
{
    unsigned char* targetBuf;
    int srcDigitHigh = 0;
    int srcDigitLow = 0;
    size_t srcLen;
    size_t srcIdx = 0;
    long targetIdx = 0;

    srcLen = XSTRLEN(str);
    targetBuf = (unsigned char*)XMALLOC(srcLen / 2, NULL, DYNAMIC_TYPE_OPENSSL);
    if (targetBuf == NULL) {
        return NULL;
    }

    while (srcIdx < srcLen) {
        if (str[srcIdx] == ':') {
            srcIdx++;
            continue;
        }

        srcDigitHigh = wolfSSL_OPENSSL_hexchar2int((unsigned char)str[srcIdx++]);
        srcDigitLow = wolfSSL_OPENSSL_hexchar2int((unsigned char)str[srcIdx++]);
        if (srcDigitHigh < 0 || srcDigitLow < 0) {
            WOLFSSL_MSG("Invalid hex character.");
            XFREE(targetBuf, NULL, DYNAMIC_TYPE_OPENSSL);
            return NULL;
        }

        targetBuf[targetIdx++] = (unsigned char)((srcDigitHigh << 4) |
                                                  srcDigitLow       );
    }

    if (len != NULL)
        *len = targetIdx;

    return targetBuf;
}

int wolfSSL_OPENSSL_init_ssl(word64 opts, const WOLFSSL_INIT_SETTINGS *settings)
{
    (void)opts;
    (void)settings;
    return wolfSSL_library_init();
}

int wolfSSL_OPENSSL_init_crypto(word64 opts,
    const WOLFSSL_INIT_SETTINGS* settings)
{
    (void)opts;
    (void)settings;
    return wolfSSL_library_init();
}

/* Colon separated list of <public key>+<digest> algorithms.
 * Replaces list in context.
 */
int wolfSSL_CTX_set1_sigalgs_list(WOLFSSL_CTX* ctx, const char* list)
{
    WOLFSSL_MSG("wolfSSL_CTX_set1_sigalg_list");

    if (ctx == NULL || list == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (AllocateCtxSuites(ctx) != 0)
        return WOLFSSL_FAILURE;

    return SetSuitesHashSigAlgo(ctx->suites, list);
}

/* Colon separated list of <public key>+<digest> algorithms.
 * Replaces list in SSL.
 */
int wolfSSL_set1_sigalgs_list(WOLFSSL* ssl, const char* list)
{
    WOLFSSL_MSG("wolfSSL_set1_sigalg_list");

    if (ssl == NULL || list == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (AllocateSuites(ssl) != 0)
        return WOLFSSL_FAILURE;

    return SetSuitesHashSigAlgo(ssl->suites, list);
}

static int HashToNid(byte hashAlgo, int* nid)
{
    int ret = WOLFSSL_SUCCESS;

    /* Cast for compiler to check everything is implemented */
    switch ((enum wc_MACAlgorithm)hashAlgo) {
        case no_mac:
        case rmd_mac:
            *nid = WC_NID_undef;
            break;
        case md5_mac:
            *nid = WC_NID_md5;
            break;
        case sha_mac:
            *nid = WC_NID_sha1;
            break;
        case sha224_mac:
            *nid = WC_NID_sha224;
            break;
        case sha256_mac:
            *nid = WC_NID_sha256;
            break;
        case sha384_mac:
            *nid = WC_NID_sha384;
            break;
        case sha512_mac:
            *nid = WC_NID_sha512;
            break;
        case blake2b_mac:
            *nid = WC_NID_blake2b512;
            break;
        case sm3_mac:
            *nid = WC_NID_sm3;
            break;
        default:
            ret = WOLFSSL_FAILURE;
            break;
    }

    return ret;
}

static int SaToNid(byte sa, int* nid)
{
    int ret = WOLFSSL_SUCCESS;
    /* Cast for compiler to check everything is implemented */
    switch ((enum SignatureAlgorithm)sa) {
        case anonymous_sa_algo:
            *nid = WC_NID_undef;
            break;
        case rsa_sa_algo:
            *nid = WC_NID_rsaEncryption;
            break;
        case dsa_sa_algo:
            *nid = WC_NID_dsa;
            break;
        case ecc_dsa_sa_algo:
            *nid = WC_NID_X9_62_id_ecPublicKey;
            break;
        case rsa_pss_sa_algo:
            *nid = WC_NID_rsassaPss;
            break;
        case ed25519_sa_algo:
#ifdef HAVE_ED25519
            *nid = WC_NID_ED25519;
#else
            ret = WOLFSSL_FAILURE;
#endif
            break;
        case rsa_pss_pss_algo:
            *nid = WC_NID_rsassaPss;
            break;
        case ed448_sa_algo:
#ifdef HAVE_ED448
            *nid = WC_NID_ED448;
#else
            ret = WOLFSSL_FAILURE;
#endif
            break;
        case falcon_level1_sa_algo:
            *nid = CTC_FALCON_LEVEL1;
            break;
        case falcon_level5_sa_algo:
            *nid = CTC_FALCON_LEVEL5;
            break;
        case dilithium_level2_sa_algo:
            *nid = CTC_DILITHIUM_LEVEL2;
            break;
        case dilithium_level3_sa_algo:
            *nid = CTC_DILITHIUM_LEVEL3;
            break;
        case dilithium_level5_sa_algo:
            *nid = CTC_DILITHIUM_LEVEL5;
            break;
        case sm2_sa_algo:
            *nid = WC_NID_sm2;
            break;
        case invalid_sa_algo:
        default:
            ret = WOLFSSL_FAILURE;
            break;
    }
    return ret;
}

/* This API returns the hash selected. */
int wolfSSL_get_signature_nid(WOLFSSL *ssl, int* nid)
{
    WOLFSSL_MSG("wolfSSL_get_signature_nid");

    if (ssl == NULL || nid == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    return HashToNid(ssl->options.hashAlgo, nid);
}

/* This API returns the signature selected. */
int wolfSSL_get_signature_type_nid(const WOLFSSL* ssl, int* nid)
{
    WOLFSSL_MSG("wolfSSL_get_signature_type_nid");

    if (ssl == NULL || nid == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    return SaToNid(ssl->options.sigAlgo, nid);
}

int wolfSSL_get_peer_signature_nid(WOLFSSL* ssl, int* nid)
{
    WOLFSSL_MSG("wolfSSL_get_peer_signature_nid");

    if (ssl == NULL || nid == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    return HashToNid(ssl->options.peerHashAlgo, nid);
}

int wolfSSL_get_peer_signature_type_nid(const WOLFSSL* ssl, int* nid)
{
    WOLFSSL_MSG("wolfSSL_get_peer_signature_type_nid");

    if (ssl == NULL || nid == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    return SaToNid(ssl->options.peerSigAlgo, nid);
}

#ifdef HAVE_ECC

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
int wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, const char *list)
{
    if (!ctx || !list) {
        return WOLFSSL_FAILURE;
    }

    return set_curves_list(NULL, ctx, list, 0);
}

int wolfSSL_set1_groups_list(WOLFSSL *ssl, const char *list)
{
    if (!ssl || !list) {
        return WOLFSSL_FAILURE;
    }

    return set_curves_list(ssl, NULL, list, 0);
}
#endif /* WOLFSSL_TLS13 */

#endif /* HAVE_ECC */

#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_ALT_CERT_CHAINS
int wolfSSL_is_peer_alt_cert_chain(const WOLFSSL* ssl)
{
    int isUsing = 0;
    if (ssl)
        isUsing = ssl->options.usingAltCertChain;
    return isUsing;
}
#endif /* WOLFSSL_ALT_CERT_CHAINS */


#ifdef SESSION_CERTS

#ifdef WOLFSSL_ALT_CERT_CHAINS
/* Get peer's alternate certificate chain */
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_alt_chain(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_peer_alt_chain");
    if (ssl)
        return &ssl->session->altChain;

    return 0;
}
#endif /* WOLFSSL_ALT_CERT_CHAINS */


/* Get peer's certificate chain */
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_peer_chain");
    if (ssl)
        return &ssl->session->chain;

    return 0;
}


/* Get peer's certificate chain total count */
int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain)
{
    WOLFSSL_ENTER("wolfSSL_get_chain_count");
    if (chain)
        return chain->count;

    return 0;
}


/* Get peer's ASN.1 DER certificate at index (idx) length in bytes */
int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx)
{
    WOLFSSL_ENTER("wolfSSL_get_chain_length");
    if (chain)
        return chain->certs[idx].length;

    return 0;
}


/* Get peer's ASN.1 DER certificate at index (idx) */
byte* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx)
{
    WOLFSSL_ENTER("wolfSSL_get_chain_cert");
    if (chain)
        return chain->certs[idx].buffer;

    return 0;
}


/* Get peer's wolfSSL X509 certificate at index (idx) */
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx)
{
    int          ret = 0;
    WOLFSSL_X509* x509 = NULL;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    WOLFSSL_ENTER("wolfSSL_get_chain_X509");
    if (chain != NULL && idx < MAX_CHAIN_DEPTH) {
    #ifdef WOLFSSL_SMALL_STACK
        cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_DCERT);
        if (cert != NULL)
    #endif
        {
            InitDecodedCert(cert, chain->certs[idx].buffer,
                                  chain->certs[idx].length, NULL);

            if ((ret = ParseCertRelative(cert, CERT_TYPE, 0, NULL, NULL)) != 0) {
                WOLFSSL_MSG("Failed to parse cert");
            }
            else {
                x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                             DYNAMIC_TYPE_X509);
                if (x509 == NULL) {
                    WOLFSSL_MSG("Failed alloc X509");
                }
                else {
                    InitX509(x509, 1, NULL);

                    if ((ret = CopyDecodedToX509(x509, cert)) != 0) {
                        WOLFSSL_MSG("Failed to copy decoded");
                        wolfSSL_X509_free(x509);
                        x509 = NULL;
                    }
                }
            }

            FreeDecodedCert(cert);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
        #endif
        }
    }
    (void)ret;

    return x509;
}


/* Get peer's PEM certificate at index (idx), output to buffer if inLen big
   enough else return error (-1). If buffer is NULL only calculate
   outLen. Output length is in *outLen WOLFSSL_SUCCESS on ok */
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                               unsigned char* buf, int inLen, int* outLen)
{
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    const char* header = NULL;
    const char* footer = NULL;
    int headerLen;
    int footerLen;
    int i;
    int err;
    word32 szNeeded = 0;

    WOLFSSL_ENTER("wolfSSL_get_chain_cert_pem");
    if (!chain || !outLen || idx < 0 || idx >= wolfSSL_get_chain_count(chain))
        return BAD_FUNC_ARG;

    err = wc_PemGetHeaderFooter(CERT_TYPE, &header, &footer);
    if (err != 0)
        return err;

    headerLen = (int)XSTRLEN(header);
    footerLen = (int)XSTRLEN(footer);

    /* Null output buffer return size needed in outLen */
    if(!buf) {
        if(Base64_Encode(chain->certs[idx].buffer, chain->certs[idx].length,
                    NULL, &szNeeded) != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
            return WOLFSSL_FAILURE;
        *outLen = szNeeded + headerLen + footerLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    /* don't even try if inLen too short */
    if (inLen < headerLen + footerLen + chain->certs[idx].length)
        return BAD_FUNC_ARG;

    /* header */
    if (XMEMCPY(buf, header, headerLen) == NULL)
        return WOLFSSL_FATAL_ERROR;

    i = headerLen;

    /* body */
    *outLen = inLen;  /* input to Base64_Encode */
    if ( (err = Base64_Encode(chain->certs[idx].buffer,
                       chain->certs[idx].length, buf + i, (word32*)outLen)) < 0)
        return err;
    i += *outLen;

    /* footer */
    if ( (i + footerLen) > inLen)
        return BAD_FUNC_ARG;
    if (XMEMCPY(buf + i, footer, footerLen) == NULL)
        return WOLFSSL_FATAL_ERROR;
    *outLen += headerLen + footerLen;

    return WOLFSSL_SUCCESS;
#else
    (void)chain;
    (void)idx;
    (void)buf;
    (void)inLen;
    (void)outLen;
    return WOLFSSL_FAILURE;
#endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */
}

#endif /* SESSION_CERTS */

#ifdef HAVE_FUZZER
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx)
{
    if (ssl) {
        ssl->fuzzerCb  = cbf;
        ssl->fuzzerCtx = fCtx;
    }
}
#endif

#ifndef NO_CERTS
#ifdef  HAVE_PK_CALLBACKS

#ifdef HAVE_ECC
void  wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX* ctx, CallbackEccKeyGen cb)
{
    if (ctx)
        ctx->EccKeyGenCb = cb;
}
void  wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccKeyGenCtx = ctx;
}
void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccKeyGenCtx;

    return NULL;
}
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx)
{
    if (ctx)
        ctx->EccSignCtx = userCtx;
}
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx)
{
    if (ctx)
        return ctx->EccSignCtx;

    return NULL;
}

WOLFSSL_ABI
void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb)
{
    if (ctx)
        ctx->EccSignCb = cb;
}
void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccSignCtx = ctx;
}
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccSignCtx;

    return NULL;
}

void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb)
{
    if (ctx)
        ctx->EccVerifyCb = cb;
}
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccVerifyCtx = ctx;
}
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccVerifyCtx;

    return NULL;
}

void wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx,
    CallbackEccSharedSecret cb)
{
    if (ctx)
        ctx->EccSharedSecretCb = cb;
}
void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EccSharedSecretCtx = ctx;
}
void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EccSharedSecretCtx;

    return NULL;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
void  wolfSSL_CTX_SetEd25519SignCb(WOLFSSL_CTX* ctx, CallbackEd25519Sign cb)
{
    if (ctx)
        ctx->Ed25519SignCb = cb;
}
void  wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->Ed25519SignCtx = ctx;
}
void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->Ed25519SignCtx;

    return NULL;
}

void  wolfSSL_CTX_SetEd25519VerifyCb(WOLFSSL_CTX* ctx, CallbackEd25519Verify cb)
{
    if (ctx)
        ctx->Ed25519VerifyCb = cb;
}
void  wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->Ed25519VerifyCtx = ctx;
}
void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->Ed25519VerifyCtx;

    return NULL;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
void wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX* ctx,
        CallbackX25519KeyGen cb)
{
    if (ctx)
        ctx->X25519KeyGenCb = cb;
}
void  wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->X25519KeyGenCtx = ctx;
}
void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->X25519KeyGenCtx;

    return NULL;
}

void wolfSSL_CTX_SetX25519SharedSecretCb(WOLFSSL_CTX* ctx,
        CallbackX25519SharedSecret cb)
{
    if (ctx)
        ctx->X25519SharedSecretCb = cb;
}
void  wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->X25519SharedSecretCtx = ctx;
}
void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->X25519SharedSecretCtx;

    return NULL;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED448
void  wolfSSL_CTX_SetEd448SignCb(WOLFSSL_CTX* ctx, CallbackEd448Sign cb)
{
    if (ctx)
        ctx->Ed448SignCb = cb;
}
void  wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->Ed448SignCtx = ctx;
}
void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->Ed448SignCtx;

    return NULL;
}

void  wolfSSL_CTX_SetEd448VerifyCb(WOLFSSL_CTX* ctx, CallbackEd448Verify cb)
{
    if (ctx)
        ctx->Ed448VerifyCb = cb;
}
void  wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->Ed448VerifyCtx = ctx;
}
void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->Ed448VerifyCtx;

    return NULL;
}
#endif /* HAVE_ED448 */

#ifdef HAVE_CURVE448
void wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX* ctx,
        CallbackX448KeyGen cb)
{
    if (ctx)
        ctx->X448KeyGenCb = cb;
}
void  wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->X448KeyGenCtx = ctx;
}
void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->X448KeyGenCtx;

    return NULL;
}

void wolfSSL_CTX_SetX448SharedSecretCb(WOLFSSL_CTX* ctx,
        CallbackX448SharedSecret cb)
{
    if (ctx)
        ctx->X448SharedSecretCb = cb;
}
void  wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->X448SharedSecretCtx = ctx;
}
void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->X448SharedSecretCtx;

    return NULL;
}
#endif /* HAVE_CURVE448 */

#ifndef NO_RSA
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb)
{
    if (ctx)
        ctx->RsaSignCb = cb;
}
void  wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb)
{
    if (ctx)
        ctx->RsaSignCheckCb = cb;
}
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaSignCtx = ctx;
}
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaSignCtx;

    return NULL;
}


void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb)
{
    if (ctx)
        ctx->RsaVerifyCb = cb;
}
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaVerifyCtx = ctx;
}
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaVerifyCtx;

    return NULL;
}

#ifdef WC_RSA_PSS
void  wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX* ctx, CallbackRsaPssSign cb)
{
    if (ctx)
        ctx->RsaPssSignCb = cb;
}
void  wolfSSL_CTX_SetRsaPssSignCheckCb(WOLFSSL_CTX* ctx,
    CallbackRsaPssVerify cb)
{
    if (ctx)
        ctx->RsaPssSignCheckCb = cb;
}
void  wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaPssSignCtx = ctx;
}
void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaPssSignCtx;

    return NULL;
}

void  wolfSSL_CTX_SetRsaPssVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaPssVerify cb)
{
    if (ctx)
        ctx->RsaPssVerifyCb = cb;
}
void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaPssVerifyCtx = ctx;
}
void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaPssVerifyCtx;

    return NULL;
}
#endif /* WC_RSA_PSS */

void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb)
{
    if (ctx)
        ctx->RsaEncCb = cb;
}
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaEncCtx = ctx;
}
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaEncCtx;

    return NULL;
}

void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb)
{
    if (ctx)
        ctx->RsaDecCb = cb;
}
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->RsaDecCtx = ctx;
}
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->RsaDecCtx;

    return NULL;
}
#endif /* NO_RSA */

/* callback for premaster secret generation */
void  wolfSSL_CTX_SetGenPreMasterCb(WOLFSSL_CTX* ctx, CallbackGenPreMaster cb)
{
    if (ctx)
        ctx->GenPreMasterCb = cb;
}
/* Set premaster secret generation callback context */
void  wolfSSL_SetGenPreMasterCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->GenPreMasterCtx = ctx;
}
/* Get premaster secret generation callback context */
void* wolfSSL_GetGenPreMasterCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->GenPreMasterCtx;

    return NULL;
}

/* callback for master secret generation */
void  wolfSSL_CTX_SetGenMasterSecretCb(WOLFSSL_CTX* ctx,
    CallbackGenMasterSecret cb)
{
    if (ctx)
        ctx->GenMasterCb = cb;
}
/* Set master secret generation callback context */
void  wolfSSL_SetGenMasterSecretCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->GenMasterCtx = ctx;
}
/* Get master secret generation callback context */
void* wolfSSL_GetGenMasterSecretCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->GenMasterCtx;

    return NULL;
}

/* callback for session key generation */
void  wolfSSL_CTX_SetGenSessionKeyCb(WOLFSSL_CTX* ctx, CallbackGenSessionKey cb)
{
    if (ctx)
        ctx->GenSessionKeyCb = cb;
}
/* Set session key generation callback context */
void  wolfSSL_SetGenSessionKeyCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->GenSessionKeyCtx = ctx;
}
/* Get session key generation callback context */
void* wolfSSL_GetGenSessionKeyCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->GenSessionKeyCtx;

    return NULL;
}

/* callback for setting encryption keys */
void  wolfSSL_CTX_SetEncryptKeysCb(WOLFSSL_CTX* ctx, CallbackEncryptKeys cb)
{
    if (ctx)
        ctx->EncryptKeysCb = cb;
}
/* Set encryption keys callback context */
void  wolfSSL_SetEncryptKeysCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->EncryptKeysCtx = ctx;
}
/* Get encryption keys callback context */
void* wolfSSL_GetEncryptKeysCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->EncryptKeysCtx;

    return NULL;
}

/* callback for Tls finished */
/* the callback can be used to build TLS Finished message if enabled */
void  wolfSSL_CTX_SetTlsFinishedCb(WOLFSSL_CTX* ctx, CallbackTlsFinished cb)
{
    if (ctx)
        ctx->TlsFinishedCb = cb;
}
/* Set Tls finished callback context */
void  wolfSSL_SetTlsFinishedCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->TlsFinishedCtx = ctx;
}
/* Get Tls finished callback context */
void* wolfSSL_GetTlsFinishedCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->TlsFinishedCtx;

    return NULL;
}
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
/* callback for verify data */
void  wolfSSL_CTX_SetVerifyMacCb(WOLFSSL_CTX* ctx, CallbackVerifyMac cb)
{
    if (ctx)
        ctx->VerifyMacCb = cb;
}

/* Set set keys callback context */
void  wolfSSL_SetVerifyMacCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->VerifyMacCtx = ctx;
}
/* Get set  keys callback context */
void* wolfSSL_GetVerifyMacCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->VerifyMacCtx;

    return NULL;
}
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

void wolfSSL_CTX_SetHKDFExpandLabelCb(WOLFSSL_CTX* ctx,
                                      CallbackHKDFExpandLabel cb)
{
    if (ctx)
        ctx->HKDFExpandLabelCb = cb;
}
#ifdef WOLFSSL_PUBLIC_ASN
void wolfSSL_CTX_SetProcessPeerCertCb(WOLFSSL_CTX* ctx,
                                        CallbackProcessPeerCert cb)
{
    if (ctx)
        ctx->ProcessPeerCertCb = cb;
}
#endif /* WOLFSSL_PUBLIC_ASN */
void wolfSSL_CTX_SetProcessServerSigKexCb(WOLFSSL_CTX* ctx,
                                       CallbackProcessServerSigKex cb)
{
    if (ctx)
        ctx->ProcessServerSigKexCb = cb;
}
void wolfSSL_CTX_SetPerformTlsRecordProcessingCb(WOLFSSL_CTX* ctx,
                                          CallbackPerformTlsRecordProcessing cb)
{
    if (ctx)
        ctx->PerformTlsRecordProcessingCb = cb;
}
#endif /* HAVE_PK_CALLBACKS */
#endif /* NO_CERTS */

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_DH)
void wolfSSL_CTX_SetDhGenerateKeyPair(WOLFSSL_CTX* ctx,
                                      CallbackDhGenerateKeyPair cb) {
    if (ctx)
        ctx->DhGenerateKeyPairCb = cb;
}
void wolfSSL_CTX_SetDhAgreeCb(WOLFSSL_CTX* ctx, CallbackDhAgree cb)
{
    if (ctx)
        ctx->DhAgreeCb = cb;
}
void wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->DhAgreeCtx = ctx;
}
void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->DhAgreeCtx;

    return NULL;
}
#endif /* HAVE_PK_CALLBACKS && !NO_DH */

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_HKDF)

void wolfSSL_CTX_SetHKDFExtractCb(WOLFSSL_CTX* ctx, CallbackHKDFExtract cb)
{
    if (ctx)
        ctx->HkdfExtractCb = cb;
}

void wolfSSL_SetHKDFExtractCtx(WOLFSSL* ssl, void *ctx)
{
    if (ssl)
        ssl->HkdfExtractCtx = ctx;
}

void* wolfSSL_GetHKDFExtractCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->HkdfExtractCtx;

    return NULL;
}
#endif /* HAVE_PK_CALLBACKS && HAVE_HKDF */

#ifdef WOLFSSL_HAVE_WOLFSCEP
    /* Used by autoconf to see if wolfSCEP is available */
    void wolfSSL_wolfSCEP(void) {}
#endif


#ifdef WOLFSSL_HAVE_CERT_SERVICE
    /* Used by autoconf to see if cert service is available */
    void wolfSSL_cert_service(void) {}
#endif

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)

    /* NID variables are dependent on compatibility header files currently
     *
     * returns a pointer to a new WOLFSSL_ASN1_OBJECT struct on success and NULL
     *         on fail
     */

    WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int id)
    {
        return wolfSSL_OBJ_nid2obj_ex(id, NULL);
    }


    WOLFSSL_LOCAL WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj_ex(int id,
                                                WOLFSSL_ASN1_OBJECT* arg_obj)
    {
        word32 oidSz = 0;
        int nid = 0;
        const byte* oid;
        word32 type = 0;
        WOLFSSL_ASN1_OBJECT* obj = arg_obj;
        byte objBuf[MAX_OID_SZ + MAX_LENGTH_SZ + 1]; /* +1 for object tag */
        word32 objSz = 0;
        const char* sName = NULL;
        int i;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2obj");
#endif

        for (i = 0; i < (int)WOLFSSL_OBJECT_INFO_SZ; i++) {
            if (wolfssl_object_info[i].nid == id) {
                nid = id;
                id = wolfssl_object_info[i].id;
                sName = wolfssl_object_info[i].sName;
                type = wolfssl_object_info[i].type;
                break;
            }
        }
        if (i == (int)WOLFSSL_OBJECT_INFO_SZ) {
            WOLFSSL_MSG("NID not in table");
        #ifdef WOLFSSL_QT
            sName = NULL;
            type = (word32)id;
        #else
            return NULL;
        #endif
        }

    #ifdef HAVE_ECC
         if (type == 0 && wc_ecc_get_oid((word32)id, &oid, &oidSz) > 0) {
             type = oidCurveType;
         }
    #endif /* HAVE_ECC */

        if (sName != NULL) {
            if (XSTRLEN(sName) > WOLFSSL_MAX_SNAME - 1) {
                WOLFSSL_MSG("Attempted short name is too large");
                return NULL;
            }
        }

        oid = OidFromId((word32)id, type, &oidSz);

        /* set object ID to buffer */
        if (obj == NULL){
            obj = wolfSSL_ASN1_OBJECT_new();
            if (obj == NULL) {
                WOLFSSL_MSG("Issue creating WOLFSSL_ASN1_OBJECT struct");
                return NULL;
            }
        }
        obj->nid     = nid;
        obj->type    = id;
        obj->grp     = (int)type;

        obj->sName[0] = '\0';
        if (sName != NULL) {
            XMEMCPY(obj->sName, (char*)sName, XSTRLEN((char*)sName));
        }

        objBuf[0] = ASN_OBJECT_ID; objSz++;
        objSz += SetLength(oidSz, objBuf + 1);
        if (oidSz) {
            XMEMCPY(objBuf + objSz, oid, oidSz);
            objSz     += oidSz;
        }

        if (obj->objSz == 0 || objSz != obj->objSz) {
            obj->objSz = objSz;
            if(((obj->dynamic & WOLFSSL_ASN1_DYNAMIC_DATA) != 0) ||
                                                           (obj->obj == NULL)) {
                if (obj->obj != NULL)
                    XFREE((byte*)obj->obj, NULL, DYNAMIC_TYPE_ASN1);
                obj->obj = (byte*)XMALLOC(obj->objSz, NULL, DYNAMIC_TYPE_ASN1);
                if (obj->obj == NULL) {
                    wolfSSL_ASN1_OBJECT_free(obj);
                    return NULL;
                }
                obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
            }
            else {
                obj->dynamic &= ~WOLFSSL_ASN1_DYNAMIC_DATA;
            }
        }
        XMEMCPY((byte*)obj->obj, objBuf, obj->objSz);

        (void)type;

        return obj;
    }

    static const char* oid_translate_num_to_str(const char* oid)
    {
        const struct oid_dict {
            const char* num;
            const char* desc;
        } oid_dict[] = {
            { "2.5.29.37.0",       "Any Extended Key Usage" },
            { "1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication" },
            { "1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication" },
            { "1.3.6.1.5.5.7.3.3", "Code Signing" },
            { "1.3.6.1.5.5.7.3.4", "E-mail Protection" },
            { "1.3.6.1.5.5.7.3.8", "Time Stamping" },
            { "1.3.6.1.5.5.7.3.9", "OCSP Signing" },
            { NULL, NULL }
        };
        const struct oid_dict* idx;

        for (idx = oid_dict; idx->num != NULL; idx++) {
            if (!XSTRCMP(oid, idx->num)) {
                return idx->desc;
            }
        }
        return NULL;
    }

    static int wolfssl_obj2txt_numeric(char *buf, int bufLen,
                                       const WOLFSSL_ASN1_OBJECT *a)
    {
        int bufSz;
        int    length;
        word32 idx = 0;
        byte   tag;

        if (GetASNTag(a->obj, &idx, &tag, a->objSz) != 0) {
            return WOLFSSL_FAILURE;
        }

        if (tag != ASN_OBJECT_ID) {
            WOLFSSL_MSG("Bad ASN1 Object");
            return WOLFSSL_FAILURE;
        }

        if (GetLength((const byte*)a->obj, &idx, &length,
                       a->objSz) < 0 || length < 0) {
            return ASN_PARSE_E;
        }

        if (bufLen < MAX_OID_STRING_SZ) {
            bufSz = bufLen - 1;
        }
        else {
            bufSz = MAX_OID_STRING_SZ;
        }

        if ((bufSz = DecodePolicyOID(buf, (word32)bufSz, a->obj + idx,
                    (word32)length)) <= 0) {
            WOLFSSL_MSG("Error decoding OID");
            return WOLFSSL_FAILURE;
        }

        buf[bufSz] = '\0';

        return bufSz;
    }

    /* If no_name is one then use numerical form, otherwise short name.
     *
     * Returns the buffer size on success, WOLFSSL_FAILURE on error
     */
    int wolfSSL_OBJ_obj2txt(char *buf, int bufLen, const WOLFSSL_ASN1_OBJECT *a,
                            int no_name)
    {
        int bufSz;
        const char* desc;
        const char* name;

        WOLFSSL_ENTER("wolfSSL_OBJ_obj2txt");

        if (buf == NULL || bufLen <= 1 || a == NULL) {
            WOLFSSL_MSG("Bad input argument");
            return WOLFSSL_FAILURE;
        }

        if (no_name == 1) {
            return wolfssl_obj2txt_numeric(buf, bufLen, a);
        }

        /* return long name unless using x509small, then return short name */
#if defined(OPENSSL_EXTRA_X509_SMALL) && !defined(OPENSSL_EXTRA)
        name = a->sName;
#else
        name = wolfSSL_OBJ_nid2ln(wolfSSL_OBJ_obj2nid(a));
#endif

        if (name == NULL) {
            WOLFSSL_MSG("Name not found");
            bufSz = 0;
        }
        else if (XSTRLEN(name) + 1 < (word32)bufLen - 1) {
            bufSz = (int)XSTRLEN(name);
        }
        else {
            bufSz = bufLen - 1;
        }
        if (bufSz) {
            XMEMCPY(buf, name, bufSz);
        }
        else if (a->type == WOLFSSL_GEN_DNS || a->type == WOLFSSL_GEN_EMAIL ||
                 a->type == WOLFSSL_GEN_URI) {
            bufSz = (int)XSTRLEN((const char*)a->obj);
            XMEMCPY(buf, a->obj, min((word32)bufSz, (word32)bufLen));
        }
        else if ((bufSz = wolfssl_obj2txt_numeric(buf, bufLen, a)) > 0) {
            if ((desc = oid_translate_num_to_str(buf))) {
                bufSz = (int)XSTRLEN(desc);
                bufSz = (int)min((word32)bufSz,(word32) bufLen - 1);
                XMEMCPY(buf, desc, bufSz);
            }
        }
        else {
            bufSz = 0;
        }

        buf[bufSz] = '\0';

        return bufSz;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS_SMALL)
    /* Returns the long name that corresponds with an ASN1_OBJECT nid value.
     *  n : NID value of ASN1_OBJECT to search */
    const char* wolfSSL_OBJ_nid2ln(int n)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2ln");
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->lName;
            }
        }
        WOLFSSL_MSG("NID not found in table");
        return NULL;
    }
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY, WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)
    /* Return the corresponding short name for the nid <n>.
     * or NULL if short name can't be found.
     */
    const char * wolfSSL_OBJ_nid2sn(int n) {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2sn");

        if (n == WC_NID_md5) {
            /* WC_NID_surname == WC_NID_md5 and WC_NID_surname comes before WC_NID_md5 in
             * wolfssl_object_info. As a result, the loop below will incorrectly
             * return "SN" instead of "MD5." WC_NID_surname isn't the true OpenSSL
             * NID, but other functions rely on this table and modifying it to
             * conform with OpenSSL's NIDs isn't trivial. */
             return "MD5";
        }
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->sName;
            }
        }
        WOLFSSL_MSG_EX("SN not found (nid:%d)",n);
        return NULL;
    }

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    int wolfSSL_OBJ_sn2nid(const char *sn) {
        WOLFSSL_ENTER("wolfSSL_OBJ_sn2nid");
        if (sn == NULL)
            return WC_NID_undef;
        return wc_OBJ_sn2nid(sn);
    }
#endif

    size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o)
    {
        size_t ret = 0;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_length");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = (size_t)len;
        }

        WOLFSSL_LEAVE("wolfSSL_OBJ_length", (int)ret);

        return ret;
    }

    const unsigned char* wolfSSL_OBJ_get0_data(const WOLFSSL_ASN1_OBJECT* o)
    {
        const unsigned char* ret = NULL;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_get0_data");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = o->obj + idx;
        }

        return ret;
    }


    /* Gets the NID value that corresponds with the ASN1 object.
     *
     * o ASN1 object to get NID of
     *
     * Return NID on success and a negative value on failure
     */
    int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o)
    {
        word32 oid = 0;
        word32 idx = 0;
        int ret;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_OBJ_obj2nid");
#endif

        if (o == NULL) {
            return WOLFSSL_FATAL_ERROR;
        }

        #ifdef WOLFSSL_QT
        if (o->grp == oidCertExtType) {
            /* If nid is an unknown extension, return WC_NID_undef */
            if (wolfSSL_OBJ_nid2sn(o->nid) == NULL)
                return WC_NID_undef;
        }
        #endif

        if (o->nid > 0)
            return o->nid;
        if ((ret = GetObjectId(o->obj, &idx, &oid, o->grp, o->objSz)) < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_OBJECT_ID_E)) {
                /* Put ASN object tag in front and try again */
                int len = SetObjectId(o->objSz, NULL) + o->objSz;
                byte* buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (!buf) {
                    WOLFSSL_MSG("malloc error");
                    return WOLFSSL_FATAL_ERROR;
                }
                idx = SetObjectId(o->objSz, buf);
                XMEMCPY(buf + idx, o->obj, o->objSz);
                idx = 0;
                ret = GetObjectId(buf, &idx, &oid, o->grp, len);
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret < 0) {
                    WOLFSSL_MSG("Issue getting OID of object");
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            else {
                WOLFSSL_MSG("Issue getting OID of object");
                return WOLFSSL_FATAL_ERROR;
            }
        }

        return oid2nid(oid, o->grp);
    }

    /* Return the corresponding NID for the long name <ln>
     * or WC_NID_undef if NID can't be found.
     */
    int wolfSSL_OBJ_ln2nid(const char *ln)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t lnlen;
        WOLFSSL_ENTER("wolfSSL_OBJ_ln2nid");
        if (ln && (lnlen = XSTRLEN(ln)) > 0) {
            /* Accept input like "/commonName=" */
            if (ln[0] == '/') {
                ln++;
                lnlen--;
            }
            if (lnlen) {
                size_t i;

                if (ln[lnlen-1] == '=') {
                    lnlen--;
                }
                for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
                    if (lnlen == XSTRLEN(obj_info->lName) &&
                            XSTRNCMP(ln, obj_info->lName, lnlen) == 0) {
                        return obj_info->nid;
                    }
                }
            }
        }
        return WC_NID_undef;
    }

    /* compares two objects, return 0 if equal */
    int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
                        const WOLFSSL_ASN1_OBJECT* b)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cmp");

        if (a && b && a->obj && b->obj) {
            if (a->objSz == b->objSz) {
                return XMEMCMP(a->obj, b->obj, a->objSz);
            }
            else if (a->type == EXT_KEY_USAGE_OID ||
                     b->type == EXT_KEY_USAGE_OID) {
                /* Special case for EXT_KEY_USAGE_OID so that
                 * cmp will be treated as a substring search */
                /* Used in libest to check for id-kp-cmcRA in
                 * EXT_KEY_USAGE extension */
                unsigned int idx;
                const byte* s; /* shorter */
                unsigned int sLen;
                const byte* l; /* longer */
                unsigned int lLen;
                if (a->objSz > b->objSz) {
                    s = b->obj; sLen = b->objSz;
                    l = a->obj; lLen = a->objSz;
                }
                else {
                    s = a->obj; sLen = a->objSz;
                    l = b->obj; lLen = b->objSz;
                }
                for (idx = 0; idx <= lLen - sLen; idx++) {
                    if (XMEMCMP(l + idx, s, sLen) == 0) {
                        /* Found substring */
                        return 0;
                    }
                }
            }
        }

        return WOLFSSL_FATAL_ERROR;
    }
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_MYSQL_COMPATIBLE) || \
    defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_POCO_LIB) || defined(WOLFSSL_HAPROXY)
    /* Gets the NID value that is related to the OID string passed in. Example
     * string would be "2.5.29.14" for subject key ID.
     *
     * returns NID value on success and WC_NID_undef on error
     */
    int wolfSSL_OBJ_txt2nid(const char* s)
    {
        unsigned int i;
    #ifdef WOLFSSL_CERT_EXT
        int ret;
        unsigned int sum = 0;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];
    #endif

        WOLFSSL_ENTER("wolfSSL_OBJ_txt2nid");

        if (s == NULL) {
            return WC_NID_undef;
        }

    #ifdef WOLFSSL_CERT_EXT
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0) {
            /* sum OID */
            for (i = 0; i < outSz; i++) {
                sum += out[i];
            }
        }
    #endif /* WOLFSSL_CERT_EXT */

        /* get the group that the OID's sum is in
         * @TODO possible conflict with multiples */
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++) {
            int len;
        #ifdef WOLFSSL_CERT_EXT
            if (ret == 0) {
                if (wolfssl_object_info[i].id == (int)sum) {
                    return wolfssl_object_info[i].nid;
                }
            }
        #endif

            /* try as a short name */
            len = (int)XSTRLEN(s);
            if ((int)XSTRLEN(wolfssl_object_info[i].sName) == len &&
                XSTRNCMP(wolfssl_object_info[i].sName, s, len) == 0) {
                return wolfssl_object_info[i].nid;
            }

            /* try as a long name */
            if ((int)XSTRLEN(wolfssl_object_info[i].lName) == len &&
                XSTRNCMP(wolfssl_object_info[i].lName, s, len) == 0) {
                return wolfssl_object_info[i].nid;
            }
        }

        return WC_NID_undef;
    }
#endif
#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)

    /* Creates new ASN1_OBJECT from short name, long name, or text
     * representation of oid. If no_name is 0, then short name, long name, and
     * numerical value of oid are interpreted. If no_name is 1, then only the
     * numerical value of the oid is interpreted.
     *
     * Returns pointer to ASN1_OBJECT on success, or NULL on error.
     */
#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name)
    {
        int i, ret;
        int nid = WC_NID_undef;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];
        WOLFSSL_ASN1_OBJECT* obj;

        WOLFSSL_ENTER("wolfSSL_OBJ_txt2obj");

        if (s == NULL)
            return NULL;

        /* If s is numerical value, try to sum oid */
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0 && outSz > 0) {
            /* If numerical encode succeeded then just
             * create object from that because sums are
             * not unique and can cause confusion. */
            obj = wolfSSL_ASN1_OBJECT_new();
            if (obj == NULL) {
                WOLFSSL_MSG("Issue creating WOLFSSL_ASN1_OBJECT struct");
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC;
            obj->obj = (byte*)XMALLOC(1 + MAX_LENGTH_SZ + outSz, NULL,
                    DYNAMIC_TYPE_ASN1);
            if (obj->obj == NULL) {
                wolfSSL_ASN1_OBJECT_free(obj);
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
            i = SetObjectId((int)outSz, (byte*)obj->obj);
            XMEMCPY((byte*)obj->obj + i, out, outSz);
            obj->objSz = i + outSz;
            return obj;
        }

        /* TODO: update short names in wolfssl_object_info and check OID sums
           are correct */
        for (i = 0; i < (int)WOLFSSL_OBJECT_INFO_SZ; i++) {
            /* Short name, long name, and numerical value are interpreted */
            if (no_name == 0 &&
                ((XSTRCMP(s, wolfssl_object_info[i].sName) == 0) ||
                 (XSTRCMP(s, wolfssl_object_info[i].lName) == 0)))
            {
                    nid = wolfssl_object_info[i].nid;
            }
        }

        if (nid != WC_NID_undef)
            return wolfSSL_OBJ_nid2obj(nid);

        return NULL;
    }
#endif

    /* compatibility function. Its intended use is to remove OID's from an
     * internal table that have been added with OBJ_create. wolfSSL manages its
     * own internal OID values and does not currently support OBJ_create. */
    void wolfSSL_OBJ_cleanup(void)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cleanup");
    }

    #ifndef NO_WOLFSSL_STUB
    int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln)
    {
        (void)oid;
        (void)sn;
        (void)ln;
        WOLFSSL_STUB("wolfSSL_OBJ_create");
        return WOLFSSL_FAILURE;
    }
    #endif

    void wolfSSL_set_verify_depth(WOLFSSL *ssl, int depth)
    {
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        WOLFSSL_ENTER("wolfSSL_set_verify_depth");
        ssl->options.verifyDepth = (byte)depth;
    #endif
    }

#endif /* OPENSSL_ALL || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
    HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */

#ifdef OPENSSL_EXTRA

/* wolfSSL uses negative values for error states. This function returns an
 * unsigned type so the value returned is the absolute value of the error.
 */
unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_last_error");

    (void)line;
    (void)file;
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
    {
        int ret;

        if ((ret = wc_PeekErrorNode(-1, file, NULL, line)) < 0) {
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) \
        || defined(WOLFSSL_HAPROXY)
        if (ret == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
            return (ERR_LIB_PEM << 24) | PEM_R_NO_START_LINE;
    #endif
    #if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
        if (ret == WC_NO_ERR_TRACE(ASN1_R_HEADER_TOO_LONG)) {
            return (ERR_LIB_ASN1 << 24) | ASN1_R_HEADER_TOO_LONG;
        }
    #endif
        return (unsigned long)ret;
    }
#else
    return (unsigned long)(0 - NOT_COMPILED_IN);
#endif
}

#endif /* OPENSSL_EXTRA */

#ifdef HAVE_EX_DATA_CRYPTO
CRYPTO_EX_cb_ctx* crypto_ex_cb_ctx_session = NULL;

static int crypto_ex_cb_new(CRYPTO_EX_cb_ctx** dst, long ctx_l, void* ctx_ptr,
        WOLFSSL_CRYPTO_EX_new* new_func, WOLFSSL_CRYPTO_EX_dup* dup_func,
        WOLFSSL_CRYPTO_EX_free* free_func)
{
    CRYPTO_EX_cb_ctx* new_ctx = (CRYPTO_EX_cb_ctx*)XMALLOC(
            sizeof(CRYPTO_EX_cb_ctx), NULL, DYNAMIC_TYPE_OPENSSL);
    if (new_ctx == NULL)
        return WOLFSSL_FATAL_ERROR;
    new_ctx->ctx_l = ctx_l;
    new_ctx->ctx_ptr = ctx_ptr;
    new_ctx->new_func = new_func;
    new_ctx->free_func = free_func;
    new_ctx->dup_func = dup_func;
    new_ctx->next = NULL;
    /* Push to end of list */
    while (*dst != NULL)
        dst = &(*dst)->next;
    *dst = new_ctx;
    return 0;
}

void crypto_ex_cb_free(CRYPTO_EX_cb_ctx* cb_ctx)
{
    while (cb_ctx != NULL) {
        CRYPTO_EX_cb_ctx* next = cb_ctx->next;
        XFREE(cb_ctx, NULL, DYNAMIC_TYPE_OPENSSL);
        cb_ctx = next;
    }
}

void crypto_ex_cb_setup_new_data(void *new_obj, CRYPTO_EX_cb_ctx* cb_ctx,
        WOLFSSL_CRYPTO_EX_DATA* ex_data)
{
    int idx = 0;
    for (; cb_ctx != NULL; idx++, cb_ctx = cb_ctx->next) {
        if (cb_ctx->new_func != NULL)
            cb_ctx->new_func(new_obj, NULL, ex_data, idx, cb_ctx->ctx_l,
                    cb_ctx->ctx_ptr);
    }
}

int crypto_ex_cb_dup_data(const WOLFSSL_CRYPTO_EX_DATA *in,
        WOLFSSL_CRYPTO_EX_DATA *out, CRYPTO_EX_cb_ctx* cb_ctx)
{
    int idx = 0;
    for (; cb_ctx != NULL; idx++, cb_ctx = cb_ctx->next) {
        if (cb_ctx->dup_func != NULL) {
            void* ptr = wolfSSL_CRYPTO_get_ex_data(in, idx);
            if (!cb_ctx->dup_func(out, in,
                    &ptr, idx,
                    cb_ctx->ctx_l, cb_ctx->ctx_ptr)) {
                return WOLFSSL_FAILURE;
            }
            wolfSSL_CRYPTO_set_ex_data(out, idx, ptr);
        }
    }
    return WOLFSSL_SUCCESS;
}

void crypto_ex_cb_free_data(void *obj, CRYPTO_EX_cb_ctx* cb_ctx,
        WOLFSSL_CRYPTO_EX_DATA* ex_data)
{
    int idx = 0;
    for (; cb_ctx != NULL; idx++, cb_ctx = cb_ctx->next) {
        if (cb_ctx->free_func != NULL)
            cb_ctx->free_func(obj, NULL, ex_data, idx, cb_ctx->ctx_l,
                    cb_ctx->ctx_ptr);
    }
}

/**
 * get_ex_new_index is a helper function for the following
 * xx_get_ex_new_index functions:
 *  - wolfSSL_CRYPTO_get_ex_new_index
 *  - wolfSSL_CTX_get_ex_new_index
 *  - wolfSSL_get_ex_new_index
 * Issues a unique index number for the specified class-index.
 * Returns an index number greater or equal to zero on success,
 * -1 on failure.
 */
int wolfssl_get_ex_new_index(int class_index, long ctx_l, void* ctx_ptr,
        WOLFSSL_CRYPTO_EX_new* new_func, WOLFSSL_CRYPTO_EX_dup* dup_func,
        WOLFSSL_CRYPTO_EX_free* free_func)
{
    /* index counter for each class index*/
    static int ctx_idx = 0;
    static int ssl_idx = 0;
    static int ssl_session_idx = 0;
    static int x509_idx = 0;

    int idx = -1;

    switch(class_index) {
        case WOLF_CRYPTO_EX_INDEX_SSL:
            WOLFSSL_CRYPTO_EX_DATA_IGNORE_PARAMS(ctx_l, ctx_ptr, new_func,
                    dup_func, free_func);
            idx = ssl_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_SSL_CTX:
            WOLFSSL_CRYPTO_EX_DATA_IGNORE_PARAMS(ctx_l, ctx_ptr, new_func,
                    dup_func, free_func);
            idx = ctx_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_X509:
            WOLFSSL_CRYPTO_EX_DATA_IGNORE_PARAMS(ctx_l, ctx_ptr, new_func,
                    dup_func, free_func);
            idx = x509_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_SSL_SESSION:
            if (crypto_ex_cb_new(&crypto_ex_cb_ctx_session, ctx_l, ctx_ptr,
                    new_func, dup_func, free_func) != 0)
                return WOLFSSL_FATAL_ERROR;
            idx = ssl_session_idx++;
            break;

        /* following class indexes are not supoprted */
        case WOLF_CRYPTO_EX_INDEX_X509_STORE:
        case WOLF_CRYPTO_EX_INDEX_X509_STORE_CTX:
        case WOLF_CRYPTO_EX_INDEX_DH:
        case WOLF_CRYPTO_EX_INDEX_DSA:
        case WOLF_CRYPTO_EX_INDEX_EC_KEY:
        case WOLF_CRYPTO_EX_INDEX_RSA:
        case WOLF_CRYPTO_EX_INDEX_ENGINE:
        case WOLF_CRYPTO_EX_INDEX_UI:
        case WOLF_CRYPTO_EX_INDEX_BIO:
        case WOLF_CRYPTO_EX_INDEX_APP:
        case WOLF_CRYPTO_EX_INDEX_UI_METHOD:
        case WOLF_CRYPTO_EX_INDEX_DRBG:
        default:
            break;
    }
    if (idx >= MAX_EX_DATA)
        return WOLFSSL_FATAL_ERROR;
    return idx;
}
#endif /* HAVE_EX_DATA_CRYPTO */

#ifdef HAVE_EX_DATA_CRYPTO
int wolfSSL_CTX_get_ex_new_index(long idx, void* arg,
                                 WOLFSSL_CRYPTO_EX_new* new_func,
                                 WOLFSSL_CRYPTO_EX_dup* dup_func,
                                 WOLFSSL_CRYPTO_EX_free* free_func)
{

    WOLFSSL_ENTER("wolfSSL_CTX_get_ex_new_index");

    return wolfssl_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_CTX, idx, arg,
                                    new_func, dup_func, free_func);
}

/* Return the index that can be used for the WOLFSSL structure to store
 * application data.
 *
 */
int wolfSSL_get_ex_new_index(long argValue, void* arg,
        WOLFSSL_CRYPTO_EX_new* cb1, WOLFSSL_CRYPTO_EX_dup* cb2,
        WOLFSSL_CRYPTO_EX_free* cb3)
{
    WOLFSSL_ENTER("wolfSSL_get_ex_new_index");

    return wolfssl_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL, argValue, arg,
            cb1, cb2, cb3);
}
#endif /* HAVE_EX_DATA_CRYPTO */

#ifdef OPENSSL_EXTRA
void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int idx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_ex_data");
#ifdef HAVE_EX_DATA
    if (ctx != NULL) {
        return wolfSSL_CRYPTO_get_ex_data(&ctx->ex_data, idx);
    }
#else
    (void)ctx;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int idx, void* data)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_ex_data");
#ifdef HAVE_EX_DATA
    if (ctx != NULL) {
        return wolfSSL_CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
    }
#else
    (void)ctx;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
int wolfSSL_CTX_set_ex_data_with_cleanup(
    WOLFSSL_CTX* ctx,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_ex_data_with_cleanup");
    if (ctx != NULL) {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&ctx->ex_data, idx, data,
                                                       cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

/* Returns char* to app data stored in ex[0].
 *
 * ssl WOLFSSL structure to get app data from
 */
void* wolfSSL_get_app_data(const WOLFSSL *ssl)
{
    /* checkout exdata stuff... */
    WOLFSSL_ENTER("wolfSSL_get_app_data");

    return wolfSSL_get_ex_data(ssl, 0);
}


/* Set ex array 0 to have app data
 *
 * ssl WOLFSSL struct to set app data in
 * arg data to be stored
 *
 * Returns WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on failure
 */
int wolfSSL_set_app_data(WOLFSSL *ssl, void* arg) {
    WOLFSSL_ENTER("wolfSSL_set_app_data");

    return wolfSSL_set_ex_data(ssl, 0, arg);
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

int wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data)
{
    WOLFSSL_ENTER("wolfSSL_set_ex_data");
#ifdef HAVE_EX_DATA
    if (ssl != NULL) {
        return wolfSSL_CRYPTO_set_ex_data(&ssl->ex_data, idx, data);
    }
#else
    WOLFSSL_MSG("HAVE_EX_DATA macro is not defined");
    (void)ssl;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
int wolfSSL_set_ex_data_with_cleanup(
    WOLFSSL* ssl,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_set_ex_data_with_cleanup");
    if (ssl != NULL)
    {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&ssl->ex_data, idx, data,
                                                       cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx)
{
    WOLFSSL_ENTER("wolfSSL_get_ex_data");
#ifdef HAVE_EX_DATA
    if (ssl != NULL) {
        return wolfSSL_CRYPTO_get_ex_data(&ssl->ex_data, idx);
    }
#else
    WOLFSSL_MSG("HAVE_EX_DATA macro is not defined");
    (void)ssl;
    (void)idx;
#endif
    return 0;
}

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA)

/* returns the enum value associated with handshake state
 *
 * ssl the WOLFSSL structure to get state of
 */
int wolfSSL_get_state(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_state");

    if (ssl == NULL) {
        WOLFSSL_MSG("Null argument passed in");
        return WOLFSSL_FAILURE;
    }

    return ssl->options.handShakeState;
}
#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE */

#ifdef OPENSSL_EXTRA
void wolfSSL_certs_clear(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_certs_clear");

    if (ssl == NULL)
        return;

    /* ctx still owns certificate, certChain, key, dh, and cm */
    if (ssl->buffers.weOwnCert) {
        FreeDer(&ssl->buffers.certificate);
        ssl->buffers.weOwnCert = 0;
    }
    ssl->buffers.certificate = NULL;
    if (ssl->buffers.weOwnCertChain) {
        FreeDer(&ssl->buffers.certChain);
        ssl->buffers.weOwnCertChain = 0;
    }
    ssl->buffers.certChain = NULL;
#ifdef WOLFSSL_TLS13
    ssl->buffers.certChainCnt = 0;
#endif
    if (ssl->buffers.weOwnKey) {
        FreeDer(&ssl->buffers.key);
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        FreeDer(&ssl->buffers.keyMask);
    #endif
        ssl->buffers.weOwnKey = 0;
    }
    ssl->buffers.key      = NULL;
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    ssl->buffers.keyMask  = NULL;
#endif
    ssl->buffers.keyType  = 0;
    ssl->buffers.keyId    = 0;
    ssl->buffers.keyLabel = 0;
    ssl->buffers.keySz    = 0;
    ssl->buffers.keyDevId = 0;
#ifdef WOLFSSL_DUAL_ALG_CERTS
    if (ssl->buffers.weOwnAltKey) {
        FreeDer(&ssl->buffers.altKey);
    #ifdef WOLFSSL_BLIND_PRIVATE_KEY
        FreeDer(&ssl->buffers.altKeyMask);
    #endif
        ssl->buffers.weOwnAltKey = 0;
    }
    ssl->buffers.altKey     = NULL;
#ifdef WOLFSSL_BLIND_PRIVATE_KEY
    ssl->buffers.altKeyMask = NULL;
#endif
#endif /* WOLFSSL_DUAL_ALG_CERTS */
}
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)

long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt)
{
    WOLFSSL_ENTER("wolfSSL_ctrl");
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (cmd) {
        #if defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT) || \
            defined(OPENSSL_ALL)
        #ifdef HAVE_SNI
        case SSL_CTRL_SET_TLSEXT_HOSTNAME:
            WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TLSEXT_HOSTNAME.");
            if (pt == NULL) {
                WOLFSSL_MSG("Passed in NULL Host Name.");
                break;
            }
            return wolfSSL_set_tlsext_host_name(ssl, (const char*) pt);
        #endif /* HAVE_SNI */
        #endif /* WOLFSSL_NGINX || WOLFSSL_QT || OPENSSL_ALL */
        default:
            WOLFSSL_MSG("Case not implemented.");
    }
    (void)opt;
    (void)pt;
    return WOLFSSL_FAILURE;
}

long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt, void* pt)
{
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    long ctrl_opt;
#endif
    long ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_CTX_ctrl");
    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    switch (cmd) {
    case SSL_CTRL_CHAIN:
#ifdef SESSION_CERTS
    {
        /*
         * We don't care about opt here because a copy of the certificate is
         * stored anyway so increasing the reference counter is not necessary.
         * Just check to make sure that it is set to one of the correct values.
         */
        WOLF_STACK_OF(WOLFSSL_X509)* sk = (WOLF_STACK_OF(WOLFSSL_X509)*) pt;
        WOLFSSL_X509* x509;
        int i;
        if (opt != 0 && opt != 1) {
            ret = WOLFSSL_FAILURE;
            break;
        }
        /* Clear certificate chain */
        FreeDer(&ctx->certChain);
        if (sk) {
            for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
                x509 = wolfSSL_sk_X509_value(sk, i);
                /* Prevent wolfSSL_CTX_add_extra_chain_cert from freeing cert */
                if (wolfSSL_X509_up_ref(x509) != 1) {
                    WOLFSSL_MSG("Error increasing reference count");
                    continue;
                }
                if (wolfSSL_CTX_add_extra_chain_cert(ctx, x509) !=
                        WOLFSSL_SUCCESS) {
                    WOLFSSL_MSG("Error adding certificate to context");
                    /* Decrease reference count on failure */
                    wolfSSL_X509_free(x509);
                }
            }
        }
        /* Free previous chain */
        wolfSSL_sk_X509_pop_free(ctx->x509Chain, NULL);
        ctx->x509Chain = sk;
        if (sk && opt == 1) {
            /* up all refs when opt == 1 */
            for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
                x509 = wolfSSL_sk_X509_value(sk, i);
                if (wolfSSL_X509_up_ref(x509) != 1) {
                    WOLFSSL_MSG("Error increasing reference count");
                    continue;
                }
            }
        }
    }
#else
        WOLFSSL_MSG("Session certificates not compiled in");
        ret = WOLFSSL_FAILURE;
#endif
        break;

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    case SSL_CTRL_OPTIONS:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_OPTIONS.");
        ctrl_opt = wolfSSL_CTX_set_options(ctx, opt);

        #ifdef WOLFSSL_QT
        /* Set whether to use client or server cipher preference */
        if ((ctrl_opt & WOLFSSL_OP_CIPHER_SERVER_PREFERENCE)
                     == WOLFSSL_OP_CIPHER_SERVER_PREFERENCE) {
            WOLFSSL_MSG("Using Server's Cipher Preference.");
            ctx->useClientOrder = 0;
        } else {
            WOLFSSL_MSG("Using Client's Cipher Preference.");
            ctx->useClientOrder = 1;
        }
        #endif /* WOLFSSL_QT */

        return ctrl_opt;
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */
    case SSL_CTRL_EXTRA_CHAIN_CERT:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_EXTRA_CHAIN_CERT.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in x509 pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_CTX_add_extra_chain_cert(ctx, (WOLFSSL_X509*)pt);

#ifndef NO_DH
    case SSL_CTRL_SET_TMP_DH:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TMP_DH.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in DH pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_CTX_set_tmp_dh(ctx, (WOLFSSL_DH*)pt);
#endif

#ifdef HAVE_ECC
    case SSL_CTRL_SET_TMP_ECDH:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TMP_ECDH.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in ECDH pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_SSL_CTX_set_tmp_ecdh(ctx, (WOLFSSL_EC_KEY*)pt);
#endif
    case SSL_CTRL_MODE:
        wolfSSL_CTX_set_mode(ctx,opt);
        break;
    case SSL_CTRL_SET_MIN_PROTO_VERSION:
        WOLFSSL_MSG("set min proto version");
        return wolfSSL_CTX_set_min_proto_version(ctx, (int)opt);
    case SSL_CTRL_SET_MAX_PROTO_VERSION:
        WOLFSSL_MSG("set max proto version");
        return wolfSSL_CTX_set_max_proto_version(ctx, (int)opt);
    case SSL_CTRL_GET_MIN_PROTO_VERSION:
        WOLFSSL_MSG("get min proto version");
        return wolfSSL_CTX_get_min_proto_version(ctx);
    case SSL_CTRL_GET_MAX_PROTO_VERSION:
        WOLFSSL_MSG("get max proto version");
        return wolfSSL_CTX_get_max_proto_version(ctx);
    default:
        WOLFSSL_MSG("CTX_ctrl cmd not implemented");
        ret = WOLFSSL_FAILURE;
        break;
    }

    (void)ctx;
    (void)cmd;
    (void)opt;
    (void)pt;
    WOLFSSL_LEAVE("wolfSSL_CTX_ctrl", (int)ret);
    return ret;
}

#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_callback_ctrl(WOLFSSL_CTX* ctx, int cmd, void (*fp)(void))
{
    (void) ctx;
    (void) cmd;
    (void) fp;
    WOLFSSL_STUB("wolfSSL_CTX_callback_ctrl");
    return WOLFSSL_FAILURE;

}
#endif /* NO_WOLFSSL_STUB */

#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx)
{
    return wolfSSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0L, NULL);
}
#endif

/* Returns the verifyCallback from the ssl structure if successful.
Returns NULL otherwise. */
VerifyCallback wolfSSL_get_verify_callback(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_verify_callback");
    if (ssl) {
        return ssl->verifyCallback;
    }
    return NULL;
}

#ifndef NO_BIO
/* Converts EVP_PKEY data from a bio buffer to a WOLFSSL_EVP_PKEY structure.
Returns pointer to private EVP_PKEY struct upon success, NULL if there
is a failure.*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO* bio,
                                                         WOLFSSL_EVP_PKEY** out)
{
    unsigned char* mem = NULL;
    int memSz = 0;
    WOLFSSL_EVP_PKEY* key = NULL;
    unsigned char* extraBioMem = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_bio");

    if (bio == NULL) {
        return NULL;
    }
    (void)out;

    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_get_len() failure");
        return NULL;
    }

    mem = (unsigned char*)XMALLOC(memSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return NULL;
    }

    if (wolfSSL_BIO_read(bio, (unsigned char*)mem, memSz) == memSz) {
        int extraBioMemSz;
        int derLength;

        /* Determines key type and returns the new private EVP_PKEY object */
        if ((key = wolfSSL_d2i_PrivateKey_EVP(NULL, &mem, (long)memSz)) ==
                NULL) {
            WOLFSSL_MSG("wolfSSL_d2i_PrivateKey_EVP() failure");
            XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* Write extra data back into bio object if necessary. */
        derLength = key->pkey_sz;
        extraBioMemSz = (memSz - derLength);
        if (extraBioMemSz > 0) {
            int i;
            int j = 0;

            extraBioMem = (unsigned char *)XMALLOC(extraBioMemSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (extraBioMem == NULL) {
                WOLFSSL_MSG("Malloc failure");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }

            for (i = derLength; i < memSz; i++) {
                *(extraBioMem + j) = *(mem + i);
                j++;
            }

            wolfSSL_BIO_write(bio, extraBioMem, extraBioMemSz);
            if (wolfSSL_BIO_get_len(bio) <= 0) {
                WOLFSSL_MSG("Failed to write memory to bio");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
            XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        }

        if (out != NULL) {
            *out = key;
        }
    }
    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */


#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_QT) || defined(WOLFSSL_WPAS_SMALL)

/* Converts a DER encoded private key to a WOLFSSL_EVP_PKEY structure.
 * returns a pointer to a new WOLFSSL_EVP_PKEY structure on success and NULL
 * on fail */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** out,
                                                  unsigned char** in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_EVP");
    return d2iGenericKey(out, (const unsigned char**)in, inSz, 1);
}

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT ||
        * WOLFSSL_WPAS_SMALL*/


/* stunnel compatibility functions*/
#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
     defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
     defined(WOLFSSL_OPENSSH)))
void wolfSSL_ERR_remove_thread_state(void* pid)
{
    (void) pid;
    return;
}

#ifndef NO_FILESYSTEM
/***TBD ***/
void wolfSSL_print_all_errors_fp(XFILE fp)
{
    (void)fp;
}
#endif /* !NO_FILESYSTEM */

#endif /* OPENSSL_ALL || OPENSSL_EXTRA || HAVE_STUNNEL || WOLFSSL_NGINX ||
    HAVE_LIGHTY || WOLFSSL_HAPROXY || WOLFSSL_OPENSSH */

/* Note: This is a huge section of API's - through
 *       wolfSSL_X509_OBJECT_get0_X509_CRL */
#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))

#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY)
static wolfSSL_OSSL_Malloc_cb  ossl_malloc  = NULL;
static wolfSSL_OSSL_Free_cb    ossl_free    = NULL;
static wolfSSL_OSSL_Realloc_cb ossl_realloc = NULL;

static void* OSSL_Malloc(size_t size)
{
    if (ossl_malloc != NULL)
        return ossl_malloc(size, NULL, 0);
    else
        return NULL;
}

static void  OSSL_Free(void *ptr)
{
    if (ossl_free != NULL)
        ossl_free(ptr, NULL, 0);
}

static void* OSSL_Realloc(void *ptr, size_t size)
{
    if (ossl_realloc != NULL)
        return ossl_realloc(ptr, size, NULL, 0);
    else
        return NULL;
}
#endif /* USE_WOLFSSL_MEMORY && !WOLFSSL_DEBUG_MEMORY &&
        * !WOLFSSL_STATIC_MEMORY */

int wolfSSL_CRYPTO_set_mem_functions(
        wolfSSL_OSSL_Malloc_cb  m,
        wolfSSL_OSSL_Realloc_cb r,
        wolfSSL_OSSL_Free_cb    f)
{
#if defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY)
#ifdef WOLFSSL_DEBUG_MEMORY
    WOLFSSL_MSG("mem functions will receive function name instead of "
                "file name");
    if (wolfSSL_SetAllocators((wolfSSL_Malloc_cb)m, (wolfSSL_Free_cb)f,
            (wolfSSL_Realloc_cb)r) == 0)
        return WOLFSSL_SUCCESS;
#else
    WOLFSSL_MSG("wolfSSL was compiled without WOLFSSL_DEBUG_MEMORY mem "
                "functions will receive a NULL file name and 0 for the "
                "line number.");
    if (wolfSSL_SetAllocators((wolfSSL_Malloc_cb)OSSL_Malloc,
           (wolfSSL_Free_cb)OSSL_Free, (wolfSSL_Realloc_cb)OSSL_Realloc) == 0) {
        ossl_malloc = m;
        ossl_free = f;
        ossl_realloc = r;
        return WOLFSSL_SUCCESS;
    }
#endif
    else
        return WOLFSSL_FAILURE;
#else
    (void)m;
    (void)r;
    (void)f;
    WOLFSSL_MSG("wolfSSL allocator callback functions not compiled in");
    return WOLFSSL_FAILURE;
#endif
}

int wolfSSL_ERR_load_ERR_strings(void)
{
    return WOLFSSL_SUCCESS;
}

void wolfSSL_ERR_load_crypto_strings(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_load_crypto_strings");
    /* Do nothing */
    return;
}

int wolfSSL_FIPS_mode(void)
{
#ifdef HAVE_FIPS
    return 1;
#else
    return 0;
#endif
}

int wolfSSL_FIPS_mode_set(int r)
{
#ifdef HAVE_FIPS
    if (r == 0) {
        WOLFSSL_MSG("Cannot disable FIPS at runtime.");
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
#else
    if (r == 0) {
        return WOLFSSL_SUCCESS;
    }
    WOLFSSL_MSG("Cannot enable FIPS. This isn't the wolfSSL FIPS code.");
    return WOLFSSL_FAILURE;
#endif
}

int wolfSSL_CIPHER_get_bits(const WOLFSSL_CIPHER *c, int *alg_bits)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_CIPHER_get_bits");

    #if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
    (void)alg_bits;
    if (c!= NULL)
        ret = c->bits;
    #else
    if (c != NULL && c->ssl != NULL) {
        ret = 8 * c->ssl->specs.key_size;
        if (alg_bits != NULL) {
            *alg_bits = ret;
        }
    }
    #endif
    return ret;
}

/* returns value less than 0 on fail to match
 * On a successful match the priority level found is returned
 */
int wolfSSL_sk_SSL_CIPHER_find(
        WOLF_STACK_OF(WOLFSSL_CIPHER)* sk, const WOLFSSL_CIPHER* toFind)
{
    WOLFSSL_STACK* next;
    int i, sz;

    if (sk == NULL || toFind == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    sz   = wolfSSL_sk_SSL_CIPHER_num(sk);
    next = sk;
    for (i = 0; i < sz && next != NULL; i++) {
        if (next->data.cipher.cipherSuite0 == toFind->cipherSuite0 &&
                next->data.cipher.cipherSuite == toFind->cipherSuite) {
            return sz - i; /* reverse because stack pushed highest on first */
        }
        next = next->next;
    }
    return WOLFSSL_FATAL_ERROR;
}

/* free's all nodes in the stack and there data */
void wolfSSL_sk_SSL_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_free");
    wolfSSL_sk_free(sk);
}

#ifdef HAVE_SNI
int wolfSSL_set_tlsext_host_name(WOLFSSL* ssl, const char* host_name)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_set_tlsext_host_name");
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
            host_name, (word16)XSTRLEN(host_name));
    WOLFSSL_LEAVE("wolfSSL_set_tlsext_host_name", ret);
    return ret;
}

/* May be called by server to get the requested accepted name and by the client
 * to get the requested name. */
const char * wolfSSL_get_servername(WOLFSSL* ssl, byte type)
{
    void * serverName = NULL;
    if (ssl == NULL)
        return NULL;
    TLSX_SNI_GetRequest(ssl->extensions, type, &serverName,
            !wolfSSL_is_server(ssl));
    return (const char *)serverName;
}
#endif /* HAVE_SNI */

WOLFSSL_CTX* wolfSSL_set_SSL_CTX(WOLFSSL* ssl, WOLFSSL_CTX* ctx)
{
    int ret;
    /* This method requires some explanation. Its sibling is
     *   int SetSSL_CTX(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
     * which re-inits the WOLFSSL* with all settings in the new CTX.
     * That one is the right one to use *before* a handshake is started.
     *
     * This method was added by OpenSSL to be used *during* the handshake, e.g.
     * when a server inspects the SNI in a ClientHello callback and
     * decides which set of certificates to use.
     *
     * Since, at the time the SNI callback is run, some decisions on
     * Extensions or the ServerHello might already have been taken, this
     * method is very restricted in what it does:
     * - changing the server certificate(s)
     * - changing the server id for session handling
     * and everything else in WOLFSSL* needs to remain untouched.
     */
    WOLFSSL_ENTER("wolfSSL_set_SSL_CTX");
    if (ssl == NULL || ctx == NULL)
        return NULL;
    if (ssl->ctx == ctx)
        return ssl->ctx;

    if (ctx->suites == NULL) {
        /* suites */
        if (AllocateCtxSuites(ctx) != 0)
            return NULL;
        InitSSL_CTX_Suites(ctx);
    }

    wolfSSL_RefWithMutexInc(&ctx->ref, &ret);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    if (ret != 0) {
        /* can only fail on serious stuff, like mutex not working
         * or ctx refcount out of whack. */
        return NULL;
    }
#else
    (void)ret;
#endif
    if (ssl->ctx != NULL)
        wolfSSL_CTX_free(ssl->ctx);
    ssl->ctx = ctx;

#ifndef NO_CERTS
#ifdef WOLFSSL_COPY_CERT
    /* If WOLFSSL_COPY_CERT defined, always make new copy of cert from ctx */
    if (ctx->certificate != NULL) {
        if (ssl->buffers.certificate != NULL) {
            FreeDer(&ssl->buffers.certificate);
            ssl->buffers.certificate = NULL;
        }
        ret = AllocCopyDer(&ssl->buffers.certificate, ctx->certificate->buffer,
            ctx->certificate->length, ctx->certificate->type,
            ctx->certificate->heap);
        if (ret != 0) {
            ssl->buffers.weOwnCert = 0;
            return NULL;
        }

        ssl->buffers.weOwnCert = 1;
    }
    if (ctx->certChain != NULL) {
        if (ssl->buffers.certChain != NULL) {
            FreeDer(&ssl->buffers.certChain);
            ssl->buffers.certChain = NULL;
        }
        ret = AllocCopyDer(&ssl->buffers.certChain, ctx->certChain->buffer,
            ctx->certChain->length, ctx->certChain->type,
            ctx->certChain->heap);
        if (ret != 0) {
            ssl->buffers.weOwnCertChain = 0;
            return NULL;
        }

        ssl->buffers.weOwnCertChain = 1;
    }
#else
    /* ctx owns certificate, certChain and key */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.certChain = ctx->certChain;
#endif
#ifdef WOLFSSL_TLS13
    ssl->buffers.certChainCnt = ctx->certChainCnt;
#endif
#ifndef WOLFSSL_BLIND_PRIVATE_KEY
#ifdef WOLFSSL_COPY_KEY
    if (ctx->privateKey != NULL) {
        if (ssl->buffers.key != NULL) {
            FreeDer(&ssl->buffers.key);
            ssl->buffers.key = NULL;
        }
        ret = AllocCopyDer(&ssl->buffers.key, ctx->privateKey->buffer,
            ctx->privateKey->length, ctx->privateKey->type,
            ctx->privateKey->heap);
        if (ret != 0) {
            ssl->buffers.weOwnKey = 0;
            return NULL;
        }
        ssl->buffers.weOwnKey = 1;
    }
    else {
        ssl->buffers.key      = ctx->privateKey;
    }
#else
    ssl->buffers.key      = ctx->privateKey;
#endif
#else
    if (ctx->privateKey != NULL) {
        ret = AllocCopyDer(&ssl->buffers.key, ctx->privateKey->buffer,
            ctx->privateKey->length, ctx->privateKey->type,
            ctx->privateKey->heap);
        if (ret != 0) {
            return NULL;
        }
        /* Blind the private key for the SSL with new random mask. */
        wolfssl_priv_der_unblind(ssl->buffers.key, ctx->privateKeyMask);
        ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.key,
            &ssl->buffers.keyMask);
        if (ret != 0) {
            return NULL;
        }
    }
#endif
    ssl->buffers.keyType  = ctx->privateKeyType;
    ssl->buffers.keyId    = ctx->privateKeyId;
    ssl->buffers.keyLabel = ctx->privateKeyLabel;
    ssl->buffers.keySz    = ctx->privateKeySz;
    ssl->buffers.keyDevId = ctx->privateKeyDevId;
    /* flags indicating what certs/keys are available */
    ssl->options.haveRSA          = ctx->haveRSA;
    ssl->options.haveDH           = ctx->haveDH;
    ssl->options.haveECDSAsig     = ctx->haveECDSAsig;
    ssl->options.haveECC          = ctx->haveECC;
    ssl->options.haveStaticECC    = ctx->haveStaticECC;
    ssl->options.haveFalconSig    = ctx->haveFalconSig;
    ssl->options.haveDilithiumSig = ctx->haveDilithiumSig;
#ifdef WOLFSSL_DUAL_ALG_CERTS
#ifndef WOLFSSL_BLIND_PRIVATE_KEY
    ssl->buffers.altKey   = ctx->altPrivateKey;
#else
    if (ctx->altPrivateKey != NULL) {
        ret = AllocCopyDer(&ssl->buffers.altkey, ctx->altPrivateKey->buffer,
            ctx->altPrivateKey->length, ctx->altPrivateKey->type,
            ctx->altPrivateKey->heap);
        if (ret != 0) {
            return NULL;
        }
        /* Blind the private key for the SSL with new random mask. */
        wolfssl_priv_der_unblind(ssl->buffers.altKey, ctx->altPrivateKeyMask);
        ret = wolfssl_priv_der_blind(ssl->rng, ssl->buffers.altKey,
            &ssl->buffers.altKeyMask);
        if (ret != 0) {
            return NULL;
        }
    }
#endif
    ssl->buffers.altKeySz   = ctx->altPrivateKeySz;
    ssl->buffers.altKeyType = ctx->altPrivateKeyType;
#endif /* WOLFSSL_DUAL_ALG_CERTS */
#endif

#ifdef WOLFSSL_SESSION_ID_CTX
    /* copy over application session context ID */
    ssl->sessionCtxSz = ctx->sessionCtxSz;
    XMEMCPY(ssl->sessionCtx, ctx->sessionCtx, ctx->sessionCtxSz);
#endif

    return ssl->ctx;
}


VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_verify_callback");
    if(ctx)
        return ctx->verifyCallback;
    return NULL;
}

#ifdef HAVE_SNI
/* this is a compatibility function, consider using
 * wolfSSL_CTX_set_servername_callback */
int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX* ctx,
                                               CallbackSniRecv cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_tlsext_servername_callback");
    if (ctx) {
        ctx->sniRecvCb = cb;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* HAVE_SNI */

#ifndef NO_BIO
void wolfSSL_ERR_load_BIO_strings(void) {
    WOLFSSL_ENTER("wolfSSL_ERR_load_BIO_strings");
    /* do nothing */
}
#endif

#ifndef NO_WOLFSSL_STUB
/* Set THREADID callback, return 1 on success, 0 on error */
int wolfSSL_THREADID_set_callback(
        void(*threadid_func)(WOLFSSL_CRYPTO_THREADID*))
{
    WOLFSSL_ENTER("wolfSSL_THREADID_set_callback");
    WOLFSSL_STUB("CRYPTO_THREADID_set_callback");
    (void)threadid_func;
    return 1;
}
#endif

#ifndef NO_WOLFSSL_STUB
void wolfSSL_THREADID_set_numeric(void* id, unsigned long val)
{
    WOLFSSL_ENTER("wolfSSL_THREADID_set_numeric");
    WOLFSSL_STUB("CRYPTO_THREADID_set_numeric");
    (void)id;
    (void)val;
    return;
}
#endif

#endif /* OPENSSL_ALL || (OPENSSL_EXTRA && (HAVE_STUNNEL || WOLFSSL_NGINX ||
        * HAVE_LIGHTY || WOLFSSL_HAPROXY || WOLFSSL_OPENSSH ||
        * HAVE_SBLIM_SFCB)) */

#ifdef HAVE_SNI

void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX* ctx, CallbackSniRecv cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_callback");
    if (ctx)
        ctx->sniRecvCb = cb;
}


int wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX* ctx, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_arg");
    if (ctx) {
        ctx->sniRecvCbArg = arg;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* HAVE_SNI */

#if defined(OPENSSL_EXTRA)

int wolfSSL_CRYPTO_memcmp(const void *a, const void *b, size_t size)
{
    if (!a || !b)
        return 0;
    return ConstantCompare((const byte*)a, (const byte*)b, (int)size);
}

unsigned long wolfSSL_ERR_peek_last_error(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_last_error");

#ifdef WOLFSSL_HAVE_ERROR_QUEUE
    {
        int ret;

        if ((ret = wc_PeekErrorNode(-1, NULL, NULL, NULL)) < 0) {
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
        if (ret == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
            return (WOLFSSL_ERR_LIB_PEM << 24) | -WC_NO_ERR_TRACE(WOLFSSL_PEM_R_NO_START_LINE_E);
    #if defined(WOLFSSL_PYTHON)
        if (ret == WC_NO_ERR_TRACE(ASN1_R_HEADER_TOO_LONG))
            return (WOLFSSL_ERR_LIB_ASN1 << 24) | -WC_NO_ERR_TRACE(WOLFSSL_ASN1_R_HEADER_TOO_LONG_E);
    #endif
        return (unsigned long)ret;
    }
#else
    return (unsigned long)(0 - NOT_COMPILED_IN);
#endif
}

#endif /* OPENSSL_EXTRA */

int wolfSSL_version(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_version");
    if (ssl->version.major == SSLv3_MAJOR) {
        switch (ssl->version.minor) {
            case SSLv3_MINOR :
                return SSL3_VERSION;
            case TLSv1_MINOR :
                return TLS1_VERSION;
            case TLSv1_1_MINOR :
                return TLS1_1_VERSION;
            case TLSv1_2_MINOR :
                return TLS1_2_VERSION;
            case TLSv1_3_MINOR :
                return TLS1_3_VERSION;
            default:
                return WOLFSSL_FAILURE;
        }
    }
    else if (ssl->version.major == DTLS_MAJOR) {
        switch (ssl->version.minor) {
            case DTLS_MINOR :
                return DTLS1_VERSION;
            case DTLSv1_2_MINOR :
                return DTLS1_2_VERSION;
            case DTLSv1_3_MINOR:
                return DTLS1_3_VERSION;
            default:
                return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_FAILURE;
}

WOLFSSL_CTX* wolfSSL_get_SSL_CTX(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_SSL_CTX");
    return ssl->ctx;
}

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX)

/* TODO: Doesn't currently track SSL_VERIFY_CLIENT_ONCE */
int wolfSSL_get_verify_mode(const WOLFSSL* ssl)
{
    int mode = 0;
    WOLFSSL_ENTER("wolfSSL_get_verify_mode");

    if (!ssl) {
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.verifyNone) {
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        if (ssl->options.verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ssl->options.failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ssl->options.failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        if (ssl->options.verifyPostHandshake) {
            mode |= WOLFSSL_VERIFY_POST_HANDSHAKE;
        }
#endif
    }

    WOLFSSL_LEAVE("wolfSSL_get_verify_mode", mode);
    return mode;
}

int wolfSSL_CTX_get_verify_mode(const WOLFSSL_CTX* ctx)
{
    int mode = 0;
    WOLFSSL_ENTER("wolfSSL_CTX_get_verify_mode");

    if (!ctx) {
        return WOLFSSL_FAILURE;
    }

    if (ctx->verifyNone) {
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        if (ctx->verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ctx->failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ctx->failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        if (ctx->verifyPostHandshake) {
            mode |= WOLFSSL_VERIFY_POST_HANDSHAKE;
        }
#endif
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_get_verify_mode", mode);
    return mode;
}

#endif

#ifdef WOLFSSL_JNI

int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr)
{
    WOLFSSL_ENTER("wolfSSL_set_jobject");
    if (ssl != NULL)
    {
        ssl->jObjectRef = objPtr;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

void* wolfSSL_get_jobject(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_jobject");
    if (ssl != NULL)
        return ssl->jObjectRef;
    return NULL;
}

#endif /* WOLFSSL_JNI */


#ifdef WOLFSSL_ASYNC_CRYPT
int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents,
    WOLF_EVENT_FLAG flags, int* eventCount)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    return wolfAsync_EventQueuePoll(&ctx->event_queue, NULL,
                                        events, maxEvents, flags, eventCount);
}

int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags)
{
    int ret, eventCount = 0;
    WOLF_EVENT* events[1];

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfAsync_EventQueuePoll(&ssl->ctx->event_queue, ssl,
        events, sizeof(events)/sizeof(events[0]), flags, &eventCount);
    if (ret == 0) {
        ret = eventCount;
    }

    return ret;
}
#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef OPENSSL_EXTRA

static int peek_ignore_err(int err)
{
  switch(err) {
    case -WC_NO_ERR_TRACE(WANT_READ):
    case -WC_NO_ERR_TRACE(WANT_WRITE):
    case -WC_NO_ERR_TRACE(ZERO_RETURN):
    case -WOLFSSL_ERROR_ZERO_RETURN:
    case -WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E):
    case -WC_NO_ERR_TRACE(SOCKET_ERROR_E):
      return 1;
    default:
      return 0;
  }
}

unsigned long wolfSSL_ERR_peek_error_line_data(const char **file, int *line,
                                               const char **data, int *flags)
{
  unsigned long err;

    WOLFSSL_ENTER("wolfSSL_ERR_peek_error_line_data");
    err = wc_PeekErrorNodeLineData(file, line, data, flags, peek_ignore_err);

    if (err == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
        return (WOLFSSL_ERR_LIB_PEM << 24) | -WC_NO_ERR_TRACE(WOLFSSL_PEM_R_NO_START_LINE_E);
#ifdef OPENSSL_ALL
    /* PARSE_ERROR is returned if an HTTP request is detected. */
    else if (err == -WC_NO_ERR_TRACE(PARSE_ERROR))
        return (WOLFSSL_ERR_LIB_SSL << 24) | -WC_NO_ERR_TRACE(PARSE_ERROR) /* SSL_R_HTTP_REQUEST */;
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
    else if (err == WC_NO_ERR_TRACE(ASN1_R_HEADER_TOO_LONG))
        return (WOLFSSL_ERR_LIB_ASN1 << 24) | -WC_NO_ERR_TRACE(WOLFSSL_ASN1_R_HEADER_TOO_LONG_E);
#endif
  return err;
}
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

#if !defined(WOLFSSL_USER_IO)
/* converts an IPv6 or IPv4 address into an octet string for use with rfc3280
 * example input would be "127.0.0.1" and the returned value would be 7F000001
 */
WOLFSSL_ASN1_STRING* wolfSSL_a2i_IPADDRESS(const char* ipa)
{
    int ipaSz = WOLFSSL_IP4_ADDR_LEN;
    char buf[WOLFSSL_IP6_ADDR_LEN + 1]; /* plus 1 for terminator */
    int  af = WOLFSSL_IP4;
    WOLFSSL_ASN1_STRING *ret = NULL;

    if (ipa == NULL)
        return NULL;

    if (XSTRSTR(ipa, ":") != NULL) {
        af = WOLFSSL_IP6;
        ipaSz = WOLFSSL_IP6_ADDR_LEN;
    }

    buf[WOLFSSL_IP6_ADDR_LEN] = '\0';
    if (XINET_PTON(af, ipa, (void*)buf) != 1) {
        WOLFSSL_MSG("Error parsing IP address");
        return NULL;
    }

    ret = wolfSSL_ASN1_STRING_new();
    if (ret != NULL) {
        if (wolfSSL_ASN1_STRING_set(ret, buf, ipaSz) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error setting the string");
            wolfSSL_ASN1_STRING_free(ret);
            ret = NULL;
        }
    }

    return ret;
}
#endif /* !WOLFSSL_USER_IO */

/* Is the specified cipher suite a fake one used an an extension proxy? */
static WC_INLINE int SCSV_Check(byte suite0, byte suite)
{
    (void)suite0;
    (void)suite;
#ifdef HAVE_RENEGOTIATION_INDICATION
    if (suite0 == CIPHER_BYTE && suite == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        return 1;
#endif
    return 0;
}

static WC_INLINE int sslCipherMinMaxCheck(const WOLFSSL *ssl, byte suite0,
        byte suite)
{
    const CipherSuiteInfo* cipher_names = GetCipherNames();
    int cipherSz = GetCipherNamesSize();
    int i;
    for (i = 0; i < cipherSz; i++)
        if (cipher_names[i].cipherSuite0 == suite0 &&
                cipher_names[i].cipherSuite == suite)
            break;
    if (i == cipherSz)
        return 1;
    /* Check min version */
    if (cipher_names[i].minor < ssl->options.minDowngrade) {
        if (ssl->options.minDowngrade <= TLSv1_2_MINOR &&
                cipher_names[i].minor >= TLSv1_MINOR)
            /* 1.0 ciphersuites are in general available in 1.1 and
             * 1.1 ciphersuites are in general available in 1.2 */
            return 0;
        return 1;
    }
    /* Check max version */
    switch (cipher_names[i].minor) {
    case SSLv3_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_SSLv3;
    case TLSv1_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1;
    case TLSv1_1_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_1;
    case TLSv1_2_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2;
    case TLSv1_3_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_3;
    default:
        WOLFSSL_MSG("Unrecognized minor version");
        return 1;
    }
}

/* returns a pointer to internal cipher suite list. Should not be free'd by
 * caller.
 */
WOLF_STACK_OF(WOLFSSL_CIPHER) *wolfSSL_get_ciphers_compat(const WOLFSSL *ssl)
{
    WOLF_STACK_OF(WOLFSSL_CIPHER)* ret = NULL;
    const Suites* suites;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    const CipherSuiteInfo* cipher_names = GetCipherNames();
    int cipherSz = GetCipherNamesSize();
#endif

    WOLFSSL_ENTER("wolfSSL_get_ciphers_compat");
    if (ssl == NULL)
        return NULL;

    suites = WOLFSSL_SUITES(ssl);
    if (suites == NULL)
        return NULL;

    /* check if stack needs populated */
    if (ssl->suitesStack == NULL) {
        int i;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        int j;

        /* higher priority of cipher suite will be on top of stack */
        for (i = suites->suiteSz - 2; i >=0; i-=2) {
#else
        for (i = 0; i < suites->suiteSz; i+=2) {
#endif
            WOLFSSL_STACK* add;

            /* A couple of suites are placeholders for special options,
             * skip those. */
            if (SCSV_Check(suites->suites[i], suites->suites[i+1])
                    || sslCipherMinMaxCheck(ssl, suites->suites[i],
                                            suites->suites[i+1])) {
                continue;
            }

            add = wolfSSL_sk_new_node(ssl->heap);
            if (add != NULL) {
                add->type = STACK_TYPE_CIPHER;
                add->data.cipher.cipherSuite0 = suites->suites[i];
                add->data.cipher.cipherSuite  = suites->suites[i+1];
                add->data.cipher.ssl          = ssl;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
                for (j = 0; j < cipherSz; j++) {
                    if (cipher_names[j].cipherSuite0 ==
                            add->data.cipher.cipherSuite0 &&
                            cipher_names[j].cipherSuite ==
                                    add->data.cipher.cipherSuite) {
                        add->data.cipher.offset = (unsigned long)j;
                        break;
                    }
                }
#endif
                #if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
                /* in_stack is checked in wolfSSL_CIPHER_description */
                add->data.cipher.in_stack     = 1;
                #endif

                add->next = ret;
                if (ret != NULL) {
                    add->num = ret->num + 1;
                }
                else {
                    add->num = 1;
                }
                ret = add;
            }
        }
        ((WOLFSSL*)ssl)->suitesStack = ret;
    }
    return ssl->suitesStack;
}
#endif /* OPENSSL_EXTRA || OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#if defined(OPENSSL_EXTRA) || defined(HAVE_SECRET_CALLBACK)
long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx)
{
    WOLFSSL_ENTER("wolfSSL_SSL_CTX_get_timeout");

    if (ctx == NULL)
        return 0;

    return ctx->timeout;
}


/* returns the time in seconds of the current timeout */
long wolfSSL_get_timeout(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_timeout");

    if (ssl == NULL)
        return 0;
    return ssl->timeout;
}
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#ifdef HAVE_ECC
int wolfSSL_SSL_CTX_set_tmp_ecdh(WOLFSSL_CTX *ctx, WOLFSSL_EC_KEY *ecdh)
{
    WOLFSSL_ENTER("wolfSSL_SSL_CTX_set_tmp_ecdh");

    if (ctx == NULL || ecdh == NULL)
        return BAD_FUNC_ARG;

    ctx->ecdhCurveOID = (word32)ecdh->group->curve_oid;

    return WOLFSSL_SUCCESS;
}
#endif
#ifndef NO_BIO
WOLFSSL_BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_rbio");
    /* Nginx sets the buffer size if the read BIO is different to write BIO.
     * The setting buffer size doesn't do anything so return NULL for both.
     */
    if (s == NULL)
        return NULL;

    return s->biord;
}
WOLFSSL_BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_wbio");
    (void)s;
    /* Nginx sets the buffer size if the read BIO is different to write BIO.
     * The setting buffer size doesn't do anything so return NULL for both.
     */
    if (s == NULL)
        return NULL;

    return s->biowr;
}
#endif /* !NO_BIO */

#ifndef NO_TLS
int wolfSSL_SSL_do_handshake_internal(WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_do_handshake_internal");
    if (s == NULL)
        return WOLFSSL_FAILURE;

    if (s->options.side == WOLFSSL_CLIENT_END) {
    #ifndef NO_WOLFSSL_CLIENT
        return wolfSSL_connect(s);
    #else
        WOLFSSL_MSG("Client not compiled in");
        return WOLFSSL_FAILURE;
    #endif
    }

#ifndef NO_WOLFSSL_SERVER
    return wolfSSL_accept(s);
#else
    WOLFSSL_MSG("Server not compiled in");
    return WOLFSSL_FAILURE;
#endif
}

int wolfSSL_SSL_do_handshake(WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_do_handshake");
#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(s)) {
        return wolfSSL_quic_do_handshake(s);
    }
#endif
    return wolfSSL_SSL_do_handshake_internal(s);
}
#endif /* !NO_TLS */

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
int wolfSSL_SSL_in_init(const WOLFSSL *ssl)
#else
int wolfSSL_SSL_in_init(WOLFSSL *ssl)
#endif
{
    WOLFSSL_ENTER("wolfSSL_SSL_in_init");

    return !wolfSSL_is_init_finished(ssl);
}

int wolfSSL_SSL_in_before(const WOLFSSL *ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_in_before");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return ssl->options.handShakeState == NULL_STATE;
}

int wolfSSL_SSL_in_connect_init(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_in_connect_init");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        return ssl->options.connectState > CONNECT_BEGIN &&
            ssl->options.connectState < SECOND_REPLY_DONE;
    }

    return ssl->options.acceptState > ACCEPT_BEGIN &&
        ssl->options.acceptState < ACCEPT_THIRD_REPLY_DONE;
}

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
/* Expected return values from implementations of OpenSSL ticket key callback.
 */
#define TICKET_KEY_CB_RET_FAILURE    (-1)
#define TICKET_KEY_CB_RET_NOT_FOUND   0
#define TICKET_KEY_CB_RET_OK          1
#define TICKET_KEY_CB_RET_RENEW       2

/* Implementation of session ticket encryption/decryption using OpenSSL
 * callback to initialize the cipher and HMAC.
 *
 * ssl           The SSL/TLS object.
 * keyName       The key name - used to identify the key to be used.
 * iv            The IV to use.
 * mac           The MAC of the encrypted data.
 * enc           Encrypt ticket.
 * encTicket     The ticket data.
 * encTicketLen  The length of the ticket data.
 * encLen        The encrypted/decrypted ticket length - output length.
 * ctx           Ignored. Application specific data.
 * returns WOLFSSL_TICKET_RET_OK to indicate success,
 *         WOLFSSL_TICKET_RET_CREATE if a new ticket is required and
 *         WOLFSSL_TICKET_RET_FATAL on error.
 */
static int wolfSSL_TicketKeyCb(WOLFSSL* ssl,
        unsigned char keyName[WOLFSSL_TICKET_NAME_SZ],
        unsigned char iv[WOLFSSL_TICKET_IV_SZ],
        unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
        int enc, unsigned char* encTicket,
        int encTicketLen, int* encLen, void* ctx)
{
    byte                    digest[WC_MAX_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    WOLFSSL_EVP_CIPHER_CTX  *evpCtx;
#else
    WOLFSSL_EVP_CIPHER_CTX  evpCtx[1];
#endif
    WOLFSSL_HMAC_CTX        hmacCtx;
    unsigned int            mdSz = 0;
    int                     len = 0;
    int                     ret = WOLFSSL_TICKET_RET_FATAL;
    int                     res;
    int                     totalSz = 0;

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_TicketKeyCb");

    if (ssl == NULL || ssl->ctx == NULL || ssl->ctx->ticketEncWrapCb == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_TICKET_RET_FATAL;
    }

#ifdef WOLFSSL_SMALL_STACK
    evpCtx = (WOLFSSL_EVP_CIPHER_CTX *)XMALLOC(sizeof(*evpCtx), ssl->heap,
                                               DYNAMIC_TYPE_TMP_BUFFER);
    if (evpCtx == NULL) {
        WOLFSSL_MSG("out of memory");
        return WOLFSSL_TICKET_RET_FATAL;
    }
#endif

    /* Initialize the cipher and HMAC. */
    wolfSSL_EVP_CIPHER_CTX_init(evpCtx);
    if (wolfSSL_HMAC_CTX_Init(&hmacCtx) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_HMAC_CTX_Init error");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(evpCtx, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return WOLFSSL_TICKET_RET_FATAL;
    }
    res = ssl->ctx->ticketEncWrapCb(ssl, keyName,
            iv, evpCtx, &hmacCtx, enc);
    if (res != TICKET_KEY_CB_RET_OK && res != TICKET_KEY_CB_RET_RENEW) {
        WOLFSSL_MSG("Ticket callback error");
        ret = WOLFSSL_TICKET_RET_FATAL;
        goto end;
    }

    if (wolfSSL_HMAC_size(&hmacCtx) > WOLFSSL_TICKET_MAC_SZ) {
        WOLFSSL_MSG("Ticket cipher MAC size error");
        goto end;
    }

    if (enc)
    {
        /* Encrypt in place. */
        if (!wolfSSL_EVP_CipherUpdate(evpCtx, encTicket, &len,
                                      encTicket, encTicketLen))
            goto end;
        totalSz = len;
        if (totalSz > *encLen)
            goto end;
        if (!wolfSSL_EVP_EncryptFinal(evpCtx, &encTicket[len], &len))
            goto end;
        /* Total length of encrypted data. */
        totalSz += len;
        if (totalSz > *encLen)
            goto end;

        /* HMAC the encrypted data into the parameter 'mac'. */
        if (!wolfSSL_HMAC_Update(&hmacCtx, encTicket, totalSz))
            goto end;
        if (!wolfSSL_HMAC_Final(&hmacCtx, mac, &mdSz))
            goto end;
    }
    else
    {
        /* HMAC the encrypted data and compare it to the passed in data. */
        if (!wolfSSL_HMAC_Update(&hmacCtx, encTicket, encTicketLen))
            goto end;
        if (!wolfSSL_HMAC_Final(&hmacCtx, digest, &mdSz))
            goto end;
        if (XMEMCMP(mac, digest, mdSz) != 0)
            goto end;

        /* Decrypt the ticket data in place. */
        if (!wolfSSL_EVP_CipherUpdate(evpCtx, encTicket, &len,
                                      encTicket, encTicketLen))
            goto end;
        totalSz = len;
        if (totalSz > encTicketLen)
            goto end;
        if (!wolfSSL_EVP_DecryptFinal(evpCtx, &encTicket[len], &len))
            goto end;
        /* Total length of decrypted data. */
        totalSz += len;
        if (totalSz > encTicketLen)
            goto end;
    }
    *encLen = totalSz;

    if (res == TICKET_KEY_CB_RET_RENEW && !IsAtLeastTLSv1_3(ssl->version)
            && !enc)
        ret = WOLFSSL_TICKET_RET_CREATE;
    else
        ret = WOLFSSL_TICKET_RET_OK;
end:

    (void)wc_HmacFree(&hmacCtx.hmac);
    (void)wolfSSL_EVP_CIPHER_CTX_cleanup(evpCtx);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(evpCtx, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

/* Set the callback to use when encrypting/decrypting tickets.
 *
 * ctx  The SSL/TLS context object.
 * cb   The OpenSSL session ticket callback.
 * returns WOLFSSL_SUCCESS to indicate success.
 */
int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX *ctx, ticketCompatCb cb)
{

    /* Set the ticket encryption callback to be a wrapper around OpenSSL
     * callback.
     */
    ctx->ticketEncCb = wolfSSL_TicketKeyCb;
    ctx->ticketEncWrapCb = cb;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_SESSION_TICKET */

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_WOLFSSL_SERVER)
/* Serialize the session ticket encryption keys.
 *
 * @param [in]  ctx     SSL/TLS context object.
 * @param [in]  keys    Buffer to hold session ticket keys.
 * @param [in]  keylen  Length of buffer.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL, keys is NULL or keylen is not the
 *          correct length.
 */
long wolfSSL_CTX_get_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     unsigned char *keys, int keylen)
{
    if (ctx == NULL || keys == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (keylen != WOLFSSL_TICKET_KEYS_SZ) {
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(keys, ctx->ticketKeyCtx.name, WOLFSSL_TICKET_NAME_SZ);
    keys += WOLFSSL_TICKET_NAME_SZ;
    XMEMCPY(keys, ctx->ticketKeyCtx.key[0], WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    XMEMCPY(keys, ctx->ticketKeyCtx.key[1], WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    c32toa(ctx->ticketKeyCtx.expirary[0], keys);
    keys += OPAQUE32_LEN;
    c32toa(ctx->ticketKeyCtx.expirary[1], keys);

    return WOLFSSL_SUCCESS;
}

/* Deserialize the session ticket encryption keys.
 *
 * @param [in]  ctx     SSL/TLS context object.
 * @param [in]  keys    Session ticket keys.
 * @param [in]  keylen  Length of data.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL, keys is NULL or keylen is not the
 *          correct length.
 */
long wolfSSL_CTX_set_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     const void *keys_vp, int keylen)
{
    const byte* keys = (const byte*)keys_vp;
    if (ctx == NULL || keys == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (keylen != WOLFSSL_TICKET_KEYS_SZ) {
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(ctx->ticketKeyCtx.name, keys, WOLFSSL_TICKET_NAME_SZ);
    keys += WOLFSSL_TICKET_NAME_SZ;
    XMEMCPY(ctx->ticketKeyCtx.key[0], keys, WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    XMEMCPY(ctx->ticketKeyCtx.key[1], keys, WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    ato32(keys, &ctx->ticketKeyCtx.expirary[0]);
    keys += OPAQUE32_LEN;
    ato32(keys, &ctx->ticketKeyCtx.expirary[1]);

    return WOLFSSL_SUCCESS;
}
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
#ifdef HAVE_OCSP
/* Not an OpenSSL API. */
int wolfSSL_get_ocsp_response(WOLFSSL* ssl, byte** response)
{
    *response = ssl->ocspResp;
    return ssl->ocspRespSz;
}

/* Not an OpenSSL API. */
char* wolfSSL_get_ocsp_url(WOLFSSL* ssl)
{
    return ssl->url;
}

/* Not an OpenSSL API. */
int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url)
{
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->url = url;
    return WOLFSSL_SUCCESS;
}
#endif /* OCSP */
#endif /* OPENSSL_ALL || WOLFSSL_NGINX  || WOLFSSL_HAPROXY */

#if defined(HAVE_OCSP) && !defined(NO_ASN_TIME)
int wolfSSL_get_ocsp_producedDate(
    WOLFSSL *ssl,
    byte *producedDate,
    size_t producedDate_space,
    int *producedDateFormat)
{
    if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
        (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME))
        return BAD_FUNC_ARG;

    if ((producedDate == NULL) || (producedDateFormat == NULL))
        return BAD_FUNC_ARG;

    if (XSTRLEN((char *)ssl->ocspProducedDate) >= producedDate_space)
        return BUFFER_E;

    XSTRNCPY((char *)producedDate, (const char *)ssl->ocspProducedDate,
        producedDate_space);
    *producedDateFormat = ssl->ocspProducedDateFormat;

    return 0;
}

int wolfSSL_get_ocsp_producedDate_tm(WOLFSSL *ssl, struct tm *produced_tm) {
    int idx = 0;

    if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
        (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME))
        return BAD_FUNC_ARG;

    if (produced_tm == NULL)
        return BAD_FUNC_ARG;

    if (ExtractDate(ssl->ocspProducedDate,
            (unsigned char)ssl->ocspProducedDateFormat, produced_tm, &idx))
        return 0;
    else
        return ASN_PARSE_E;
}
#endif


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(X509)** chain)
{
    word32         idx;
    word32         length;
    WOLFSSL_STACK* node;
    WOLFSSL_STACK* last = NULL;

    if (ctx == NULL || chain == NULL) {
        chain = NULL;
        return WOLFSSL_FAILURE;
    }
    if (ctx->x509Chain != NULL) {
        *chain = ctx->x509Chain;
        return WOLFSSL_SUCCESS;
    }

    /* If there are no chains then success! */
    *chain = NULL;
    if (ctx->certChain == NULL || ctx->certChain->length == 0) {
        return WOLFSSL_SUCCESS;
    }

    /* Create a new stack of WOLFSSL_X509 object from chain buffer. */
    for (idx = 0; idx < ctx->certChain->length; ) {
        node = wolfSSL_sk_X509_new_null();
        if (node == NULL)
            return WOLFSSL_FAILURE;
        node->next = NULL;

        /* 3 byte length | X509 DER data */
        ato24(ctx->certChain->buffer + idx, &length);
        idx += 3;

        /* Create a new X509 from DER encoded data. */
        node->data.x509 = wolfSSL_X509_d2i_ex(NULL,
            ctx->certChain->buffer + idx, (int)length, ctx->heap);
        if (node->data.x509 == NULL) {
            XFREE(node, NULL, DYNAMIC_TYPE_OPENSSL);
            /* Return as much of the chain as we created. */
            ctx->x509Chain = *chain;
            return WOLFSSL_FAILURE;
        }
        idx += length;

        /* Add object to the end of the stack. */
        if (last == NULL) {
            node->num = 1;
            *chain = node;
        }
        else {
            (*chain)->num++;
            last->next = node;
        }

        last = node;
    }

    ctx->x509Chain = *chain;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb)
{
    if (ctx == NULL || ctx->cm == NULL || cb == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               ||  defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    if (ctx->cm->ocsp_stapling == NULL)
        return WOLFSSL_FAILURE;

    *cb = ctx->cm->ocsp_stapling->statusCb;
#else
    (void)cb;
    *cb = NULL;
#endif

    return WOLFSSL_SUCCESS;

}

int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb)
{
    if (ctx == NULL || ctx->cm == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               ||  defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    /* Ensure stapling is on for callback to be used. */
    wolfSSL_CTX_EnableOCSPStapling(ctx);

    if (ctx->cm->ocsp_stapling == NULL)
        return WOLFSSL_FAILURE;

    ctx->cm->ocsp_stapling->statusCb = cb;
#else
    (void)cb;
#endif

    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_get0_chain_certs(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get0_chain_certs");
    if (ctx == NULL || sk == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    /* This function should return ctx->x509Chain if it is populated, otherwise
       it should be populated from ctx->certChain.  This matches the behavior of
       wolfSSL_CTX_get_extra_chain_certs, so it is used directly. */
    return wolfSSL_CTX_get_extra_chain_certs(ctx, sk);
}

#ifdef KEEP_OUR_CERT
int wolfSSL_get0_chain_certs(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    WOLFSSL_ENTER("wolfSSL_get0_chain_certs");
    if (ssl == NULL || sk == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }
    *sk = ssl->ourCertChain;
    return WOLFSSL_SUCCESS;
}
#endif

WOLF_STACK_OF(WOLFSSL_STRING)* wolfSSL_sk_WOLFSSL_STRING_new(void)
{
    WOLF_STACK_OF(WOLFSSL_STRING)* ret = wolfSSL_sk_new_node(NULL);

    if (ret) {
        ret->type = STACK_TYPE_STRING;
    }

    return ret;
}

void wolfSSL_WOLFSSL_STRING_free(WOLFSSL_STRING s)
{
    WOLFSSL_ENTER("wolfSSL_WOLFSSL_STRING_free");

    XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);
}

void wolfSSL_sk_WOLFSSL_STRING_free(WOLF_STACK_OF(WOLFSSL_STRING)* sk)
{
    WOLFSSL_STACK* tmp;
    WOLFSSL_ENTER("wolfSSL_sk_WOLFSSL_STRING_free");

    if (sk == NULL)
        return;

    /* parse through stack freeing each node */
    while (sk) {
        tmp = sk->next;
        XFREE(sk->data.string, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
        sk = tmp;
    }
}

WOLFSSL_STRING wolfSSL_sk_WOLFSSL_STRING_value(
    WOLF_STACK_OF(WOLFSSL_STRING)* strings, int idx)
{
    for (; idx > 0 && strings != NULL; idx--)
        strings = strings->next;
    if (strings == NULL)
        return NULL;
    return strings->data.string;
}

int wolfSSL_sk_WOLFSSL_STRING_num(WOLF_STACK_OF(WOLFSSL_STRING)* strings)
{
    if (strings)
        return (int)strings->num;
    return 0;
}

#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_QUIC)
#ifdef HAVE_ALPN
void wolfSSL_get0_alpn_selected(const WOLFSSL *ssl, const unsigned char **data,
                                unsigned int *len)
{
    word16 nameLen;

    if (ssl != NULL && data != NULL && len != NULL) {
        TLSX_ALPN_GetRequest(ssl->extensions, (void **)data, &nameLen);
        *len = nameLen;
    }
}

int wolfSSL_select_next_proto(unsigned char **out, unsigned char *outLen,
                              const unsigned char *in, unsigned int inLen,
                              const unsigned char *clientNames,
                              unsigned int clientLen)
{
    unsigned int i, j;
    byte lenIn, lenClient;

    if (out == NULL || outLen == NULL || in == NULL || clientNames == NULL)
        return WOLFSSL_NPN_UNSUPPORTED;

    for (i = 0; i < inLen; i += lenIn) {
        lenIn = in[i++];
        for (j = 0; j < clientLen; j += lenClient) {
            lenClient = clientNames[j++];

            if (lenIn != lenClient)
                continue;

            if (XMEMCMP(in + i, clientNames + j, lenIn) == 0) {
                *out = (unsigned char *)(in + i);
                *outLen = lenIn;
                return WOLFSSL_NPN_NEGOTIATED;
            }
        }
    }

    *out = (unsigned char *)clientNames + 1;
    *outLen = clientNames[0];
    return WOLFSSL_NPN_NO_OVERLAP;
}

void wolfSSL_set_alpn_select_cb(WOLFSSL *ssl,
                                int (*cb) (WOLFSSL *ssl,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg), void *arg)
{
    if (ssl != NULL) {
        ssl->alpnSelect = cb;
        ssl->alpnSelectArg = arg;
    }
}

void wolfSSL_CTX_set_alpn_select_cb(WOLFSSL_CTX *ctx,
                                    int (*cb) (WOLFSSL *ssl,
                                               const unsigned char **out,
                                               unsigned char *outlen,
                                               const unsigned char *in,
                                               unsigned int inlen,
                                               void *arg), void *arg)
{
    if (ctx != NULL) {
        ctx->alpnSelect = cb;
        ctx->alpnSelectArg = arg;
    }
}

void wolfSSL_CTX_set_next_protos_advertised_cb(WOLFSSL_CTX *s,
                                           int (*cb) (WOLFSSL *ssl,
                                                      const unsigned char
                                                      **out,
                                                      unsigned int *outlen,
                                                      void *arg), void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_protos_advertised_cb");
}

void wolfSSL_CTX_set_next_proto_select_cb(WOLFSSL_CTX *s,
                                      int (*cb) (WOLFSSL *ssl,
                                                 unsigned char **out,
                                                 unsigned char *outlen,
                                                 const unsigned char *in,
                                                 unsigned int inlen,
                                                 void *arg), void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_proto_select_cb");
}

void wolfSSL_get0_next_proto_negotiated(const WOLFSSL *s,
    const unsigned char **data, unsigned *len)
{
    (void)s;
    (void)data;
    (void)len;
    WOLFSSL_STUB("wolfSSL_get0_next_proto_negotiated");
}
#endif /* HAVE_ALPN */

#endif /* WOLFSSL_NGINX  / WOLFSSL_HAPROXY */

#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)
int wolfSSL_curve_is_disabled(const WOLFSSL* ssl, word16 curve_id)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_curve_is_disabled");
    WOLFSSL_MSG_EX("wolfSSL_curve_is_disabled checking for %d", curve_id);

    /* (curve_id >= WOLFSSL_FFDHE_START) - DH parameters are never disabled. */
    if (curve_id < WOLFSSL_FFDHE_START) {
        if (curve_id > WOLFSSL_ECC_MAX_AVAIL) {
            WOLFSSL_MSG("Curve id out of supported range");
            /* Disabled if not in valid range. */
            ret = 1;
        }
        else if (curve_id >= 32) {
            /* 0 is for invalid and 1-14 aren't used otherwise. */
            ret = (ssl->disabledCurves & (1U << (curve_id - 32))) != 0;
        }
        else {
            ret = (ssl->disabledCurves & (1U << curve_id)) != 0;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_curve_is_disabled", ret);
    return ret;
}

#if (defined(HAVE_ECC) || \
    defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))
#define CURVE_NAME(c) XSTR_SIZEOF((c)), (c)

const WOLF_EC_NIST_NAME kNistCurves[] = {
#ifdef HAVE_ECC
    {CURVE_NAME("P-160"),   WC_NID_secp160r1, WOLFSSL_ECC_SECP160R1},
    {CURVE_NAME("P-160-2"), WC_NID_secp160r2, WOLFSSL_ECC_SECP160R2},
    {CURVE_NAME("P-192"),   WC_NID_X9_62_prime192v1, WOLFSSL_ECC_SECP192R1},
    {CURVE_NAME("P-224"),   WC_NID_secp224r1, WOLFSSL_ECC_SECP224R1},
    {CURVE_NAME("P-256"),   WC_NID_X9_62_prime256v1, WOLFSSL_ECC_SECP256R1},
    {CURVE_NAME("P-384"),   WC_NID_secp384r1, WOLFSSL_ECC_SECP384R1},
    {CURVE_NAME("P-521"),   WC_NID_secp521r1, WOLFSSL_ECC_SECP521R1},
    {CURVE_NAME("K-160"),   WC_NID_secp160k1, WOLFSSL_ECC_SECP160K1},
    {CURVE_NAME("K-192"),   WC_NID_secp192k1, WOLFSSL_ECC_SECP192K1},
    {CURVE_NAME("K-224"),   WC_NID_secp224k1, WOLFSSL_ECC_SECP224R1},
    {CURVE_NAME("K-256"),   WC_NID_secp256k1, WOLFSSL_ECC_SECP256K1},
    {CURVE_NAME("B-256"),   WC_NID_brainpoolP256r1, WOLFSSL_ECC_BRAINPOOLP256R1},
    {CURVE_NAME("B-384"),   WC_NID_brainpoolP384r1, WOLFSSL_ECC_BRAINPOOLP384R1},
    {CURVE_NAME("B-512"),   WC_NID_brainpoolP512r1, WOLFSSL_ECC_BRAINPOOLP512R1},
#endif
#ifdef HAVE_CURVE25519
    {CURVE_NAME("X25519"),  WC_NID_X25519, WOLFSSL_ECC_X25519},
#endif
#ifdef HAVE_CURVE448
    {CURVE_NAME("X448"),    WC_NID_X448, WOLFSSL_ECC_X448},
#endif
#ifdef WOLFSSL_HAVE_KYBER
#ifndef WOLFSSL_NO_ML_KEM
    {CURVE_NAME("ML_KEM_512"), WOLFSSL_ML_KEM_512, WOLFSSL_ML_KEM_512},
    {CURVE_NAME("ML_KEM_768"), WOLFSSL_ML_KEM_768, WOLFSSL_ML_KEM_768},
    {CURVE_NAME("ML_KEM_1024"), WOLFSSL_ML_KEM_1024, WOLFSSL_ML_KEM_1024},
#if (defined(WOLFSSL_WC_KYBER) || defined(HAVE_LIBOQS)) && defined(HAVE_ECC)
    {CURVE_NAME("P256_ML_KEM_512"), WOLFSSL_P256_ML_KEM_512,
     WOLFSSL_P256_ML_KEM_512},
    {CURVE_NAME("P384_ML_KEM_768"), WOLFSSL_P384_ML_KEM_768,
     WOLFSSL_P384_ML_KEM_768},
    {CURVE_NAME("P521_ML_KEM_1024"), WOLFSSL_P521_ML_KEM_1024,
     WOLFSSL_P521_ML_KEM_1024},
#endif
#endif /* !WOLFSSL_NO_ML_KEM */
#ifdef WOLFSSL_KYBER_ORIGINAL
    {CURVE_NAME("KYBER_LEVEL1"), WOLFSSL_KYBER_LEVEL1, WOLFSSL_KYBER_LEVEL1},
    {CURVE_NAME("KYBER_LEVEL3"), WOLFSSL_KYBER_LEVEL3, WOLFSSL_KYBER_LEVEL3},
    {CURVE_NAME("KYBER_LEVEL5"), WOLFSSL_KYBER_LEVEL5, WOLFSSL_KYBER_LEVEL5},
#if (defined(WOLFSSL_WC_KYBER) || defined(HAVE_LIBOQS)) && defined(HAVE_ECC)
    {CURVE_NAME("P256_KYBER_LEVEL1"), WOLFSSL_P256_KYBER_LEVEL1, WOLFSSL_P256_KYBER_LEVEL1},
    {CURVE_NAME("P384_KYBER_LEVEL3"), WOLFSSL_P384_KYBER_LEVEL3, WOLFSSL_P384_KYBER_LEVEL3},
    {CURVE_NAME("P521_KYBER_LEVEL5"), WOLFSSL_P521_KYBER_LEVEL5, WOLFSSL_P521_KYBER_LEVEL5},
#endif
#endif /* WOLFSSL_KYBER_ORIGINAL */
#endif /* WOLFSSL_HAVE_KYBER */
#ifdef WOLFSSL_SM2
    {CURVE_NAME("SM2"),     WC_NID_sm2, WOLFSSL_ECC_SM2P256V1},
#endif
#ifdef HAVE_ECC
    /* Alternative curve names */
    {CURVE_NAME("prime256v1"), WC_NID_X9_62_prime256v1, WOLFSSL_ECC_SECP256R1},
    {CURVE_NAME("secp256r1"),  WC_NID_X9_62_prime256v1, WOLFSSL_ECC_SECP256R1},
    {CURVE_NAME("secp384r1"),  WC_NID_secp384r1, WOLFSSL_ECC_SECP384R1},
    {CURVE_NAME("secp521r1"),  WC_NID_secp521r1, WOLFSSL_ECC_SECP521R1},
#endif
#ifdef WOLFSSL_SM2
    {CURVE_NAME("sm2p256v1"),  WC_NID_sm2, WOLFSSL_ECC_SM2P256V1},
#endif
    {0, NULL, 0, 0},
};

int set_curves_list(WOLFSSL* ssl, WOLFSSL_CTX *ctx, const char* names,
        byte curves_only)
{
    int idx, start = 0, len, i, ret = WOLFSSL_FAILURE;
    word16 curve;
    word32 disabled;
    char name[MAX_CURVE_NAME_SZ];
    byte groups_len = 0;
#ifdef WOLFSSL_SMALL_STACK
    void *heap = ssl? ssl->heap : ctx ? ctx->heap : NULL;
    int *groups;
#else
    int groups[WOLFSSL_MAX_GROUP_COUNT];
#endif
    const WOLF_EC_NIST_NAME* nist_name;

#ifdef WOLFSSL_SMALL_STACK
    groups = (int*)XMALLOC(sizeof(int)*WOLFSSL_MAX_GROUP_COUNT,
                           heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (groups == NULL) {
        ret = MEMORY_E;
        goto leave;
    }
#endif

    for (idx = 1; names[idx-1] != '\0'; idx++) {
        if (names[idx] != ':' && names[idx] != '\0')
            continue;

        len = idx - start;
        if (len > MAX_CURVE_NAME_SZ - 1)
            goto leave;

        XMEMCPY(name, names + start, len);
        name[len] = 0;
        curve = WOLFSSL_NAMED_GROUP_INVALID;

        for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
            if (len == nist_name->name_len &&
                    XSTRNCMP(name, nist_name->name, len) == 0) {
                curve = nist_name->curve;
                break;
            }
        }

        if (curve == WOLFSSL_NAMED_GROUP_INVALID) {
        #if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && defined(HAVE_ECC)
            int   nret;
            const ecc_set_type *eccSet;

            nret = wc_ecc_get_curve_idx_from_name(name);
            if (nret < 0) {
                WOLFSSL_MSG("Could not find name in set");
                goto leave;
            }

            eccSet = wc_ecc_get_curve_params(ret);
            if (eccSet == NULL) {
                WOLFSSL_MSG("NULL set returned");
                goto leave;
            }

            curve = GetCurveByOID(eccSet->oidSum);
        #else
            WOLFSSL_MSG("API not present to search farther using name");
            goto leave;
        #endif
        }

        if ((curves_only && curve >= WOLFSSL_ECC_MAX_AVAIL) ||
                curve == WOLFSSL_NAMED_GROUP_INVALID) {
            WOLFSSL_MSG("curve value is not supported");
            goto leave;
        }

        for (i = 0; i < groups_len; ++i) {
            if (groups[i] == curve) {
                /* silently drop duplicates */
                break;
            }
        }
        if (i >= groups_len) {
            if (groups_len >= WOLFSSL_MAX_GROUP_COUNT) {
                WOLFSSL_MSG_EX("setting %d or more supported "
                               "curves is not permitted", groups_len);
                goto leave;
            }
            groups[groups_len++] = (int)curve;
        }

        start = idx + 1;
    }

    /* Disable all curves so that only the ones the user wants are enabled. */
    disabled = 0xFFFFFFFFUL;
    for (i = 0; i < groups_len; ++i) {
        /* Switch the bit to off and therefore is enabled. */
        curve = (word16)groups[i];
        if (curve >= 64) {
            WC_DO_NOTHING;
        }
        else if (curve >= 32) {
            /* 0 is for invalid and 1-14 aren't used otherwise. */
            disabled &= ~(1U << (curve - 32));
        }
        else {
            disabled &= ~(1U << curve);
        }
    #if defined(HAVE_SUPPORTED_CURVES) && !defined(NO_TLS)
    #if !defined(WOLFSSL_OLD_SET_CURVES_LIST)
        /* using the wolfSSL API to set the groups, this will populate
         * (ssl|ctx)->groups and reset any TLSX_SUPPORTED_GROUPS.
         * The order in (ssl|ctx)->groups will then be respected
         * when TLSX_KEY_SHARE needs to be established */
        if ((ssl && wolfSSL_set_groups(ssl, groups, groups_len)
                        != WOLFSSL_SUCCESS)
            || (ctx && wolfSSL_CTX_set_groups(ctx, groups, groups_len)
                           != WOLFSSL_SUCCESS)) {
            WOLFSSL_MSG("Unable to set supported curve");
            goto leave;
        }
    #elif !defined(NO_WOLFSSL_CLIENT)
        /* set the supported curve so client TLS extension contains only the
         * desired curves */
        if ((ssl && wolfSSL_UseSupportedCurve(ssl, curve) != WOLFSSL_SUCCESS)
            || (ctx && wolfSSL_CTX_UseSupportedCurve(ctx, curve)
                           != WOLFSSL_SUCCESS)) {
            WOLFSSL_MSG("Unable to set supported curve");
            goto leave;
        }
    #endif
    #endif /* HAVE_SUPPORTED_CURVES && !NO_TLS */
    }

    if (ssl != NULL)
        ssl->disabledCurves = disabled;
    else if (ctx != NULL)
        ctx->disabledCurves = disabled;
    ret = WOLFSSL_SUCCESS;

leave:
#ifdef WOLFSSL_SMALL_STACK
    if (groups)
        XFREE((void*)groups, heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, const char* names)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set1_curves_list");
    if (ctx == NULL || names == NULL) {
        WOLFSSL_MSG("ctx or names was NULL");
        return WOLFSSL_FAILURE;
    }
    return set_curves_list(NULL, ctx, names, 1);
}

int wolfSSL_set1_curves_list(WOLFSSL* ssl, const char* names)
{
    WOLFSSL_ENTER("wolfSSL_set1_curves_list");
    if (ssl == NULL || names == NULL) {
        WOLFSSL_MSG("ssl or names was NULL");
        return WOLFSSL_FAILURE;
    }
    return set_curves_list(ssl, NULL, names, 1);
}
#endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) */
#endif /* OPENSSL_EXTRA || HAVE_CURL */


#ifdef OPENSSL_EXTRA
/* Sets a callback for when sending and receiving protocol messages.
 * This callback is copied to all WOLFSSL objects created from the ctx.
 *
 * ctx WOLFSSL_CTX structure to set callback in
 * cb  callback to use
 *
 * return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE with error case
 */
int wolfSSL_CTX_set_msg_callback(WOLFSSL_CTX *ctx, SSL_Msg_Cb cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_msg_callback");
    if (ctx == NULL) {
        WOLFSSL_MSG("Null ctx passed in");
        return WOLFSSL_FAILURE;
    }

    ctx->protoMsgCb = cb;
    return WOLFSSL_SUCCESS;
}


/* Sets a callback for when sending and receiving protocol messages.
 *
 * ssl WOLFSSL structure to set callback in
 * cb  callback to use
 *
 * return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE with error case
 */
int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb)
{
    WOLFSSL_ENTER("wolfSSL_set_msg_callback");

    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (cb != NULL) {
        ssl->toInfoOn = 1;
    }

    ssl->protoMsgCb = cb;
    return WOLFSSL_SUCCESS;
}


/* set the user argument to pass to the msg callback when called
 * return WOLFSSL_SUCCESS on success */
int wolfSSL_CTX_set_msg_callback_arg(WOLFSSL_CTX *ctx, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_msg_callback_arg");
    if (ctx == NULL) {
        WOLFSSL_MSG("Null WOLFSSL_CTX passed in");
        return WOLFSSL_FAILURE;
    }

    ctx->protoMsgCtx = arg;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_set_msg_callback_arg");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->protoMsgCtx = arg;
    return WOLFSSL_SUCCESS;
}

void *wolfSSL_OPENSSL_memdup(const void *data, size_t siz, const char* file,
    int line)
{
    void *ret;
    (void)file;
    (void)line;

    if (data == NULL || siz >= INT_MAX)
        return NULL;

    ret = wolfSSL_OPENSSL_malloc(siz);
    if (ret == NULL) {
        return NULL;
    }
    return XMEMCPY(ret, data, siz);
}

void wolfSSL_OPENSSL_cleanse(void *ptr, size_t len)
{
    if (ptr)
        ForceZero(ptr, (word32)len);
}

int wolfSSL_CTX_set_alpn_protos(WOLFSSL_CTX *ctx, const unsigned char *p,
                            unsigned int p_len)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_alpn_protos");
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (ctx->alpn_cli_protos != NULL) {
        XFREE((void*)ctx->alpn_cli_protos, ctx->heap, DYNAMIC_TYPE_OPENSSL);
    }

    ctx->alpn_cli_protos = (const unsigned char*)XMALLOC(p_len,
        ctx->heap, DYNAMIC_TYPE_OPENSSL);
    if (ctx->alpn_cli_protos == NULL) {
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
        /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
         * the function reverses the return value convention.
         */
        return 1;
#else
        return WOLFSSL_FAILURE;
#endif
    }
    XMEMCPY((void*)ctx->alpn_cli_protos, p, p_len);
    ctx->alpn_cli_protos_len = p_len;

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
     * the function reverses the return value convention.
     */
    return 0;
#else
    return WOLFSSL_SUCCESS;
#endif
}


#ifdef HAVE_ALPN
#ifndef NO_BIO
/* Sets the ALPN extension protos
 *
 * example format is
 * unsigned char p[] = {
 *      8, 'h', 't', 't', 'p', '/', '1', '.', '1'
 * };
 *
 * returns WOLFSSL_SUCCESS on success */
int wolfSSL_set_alpn_protos(WOLFSSL* ssl,
        const unsigned char* p, unsigned int p_len)
{
    WOLFSSL_BIO* bio;
    char* pt = NULL;

    unsigned int sz;
    unsigned int idx = 0;
    int alpn_opt = WOLFSSL_ALPN_CONTINUE_ON_MISMATCH;
    WOLFSSL_ENTER("wolfSSL_set_alpn_protos");

    if (ssl == NULL || p_len <= 1) {
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
        /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
         * the function reverses the return value convention.
         */
        return 1;
#else
        return WOLFSSL_FAILURE;
#endif
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
        /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
         * the function reverses the return value convention.
         */
        return 1;
#else
        return WOLFSSL_FAILURE;
#endif
    }

    /* convert into comma separated list */
    while (idx < p_len - 1) {
        unsigned int i;

        sz = p[idx++];
        if (idx + sz > p_len) {
            WOLFSSL_MSG("Bad list format");
            wolfSSL_BIO_free(bio);
    #if defined(WOLFSSL_ERROR_CODE_OPENSSL)
            /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
             * the function reverses the return value convention.
             */
            return 1;
    #else
            return WOLFSSL_FAILURE;
    #endif
        }
        if (sz > 0) {
            for (i = 0; i < sz; i++) {
                wolfSSL_BIO_write(bio, &p[idx++], 1);
            }
            if (idx < p_len - 1)
                wolfSSL_BIO_write(bio, ",", 1);
        }
    }
    wolfSSL_BIO_write(bio, "\0", 1);

    /* clears out all current ALPN extensions set */
    TLSX_Remove(&ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL, ssl->heap);

    if ((sz = (unsigned int)wolfSSL_BIO_get_mem_data(bio, &pt)) > 0) {
        wolfSSL_UseALPN(ssl, pt, sz, (byte) alpn_opt);
    }
    wolfSSL_BIO_free(bio);
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
     * the function reverses the return value convention.
     */
    return 0;
#else
    return WOLFSSL_SUCCESS;
#endif
}
#endif /* !NO_BIO */
#endif /* HAVE_ALPN */
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA)

#ifndef NO_BIO
#define WOLFSSL_BIO_INCLUDED
#include "src/bio.c"
#endif

word32 nid2oid(int nid, int grp)
{
    /* get OID type */
    switch (grp) {
        /* oidHashType */
        case oidHashType:
            switch (nid) {
            #ifdef WOLFSSL_MD2
                case WC_NID_md2:
                    return MD2h;
            #endif
            #ifndef NO_MD5
                case WC_NID_md5:
                    return MD5h;
            #endif
            #ifndef NO_SHA
                case WC_NID_sha1:
                    return SHAh;
            #endif
                case WC_NID_sha224:
                    return SHA224h;
            #ifndef NO_SHA256
                case WC_NID_sha256:
                    return SHA256h;
            #endif
            #ifdef WOLFSSL_SHA384
                case WC_NID_sha384:
                    return SHA384h;
            #endif
            #ifdef WOLFSSL_SHA512
                case WC_NID_sha512:
                    return SHA512h;
            #endif
            #ifndef WOLFSSL_NOSHA3_224
                case WC_NID_sha3_224:
                    return SHA3_224h;
            #endif
            #ifndef WOLFSSL_NOSHA3_256
                case WC_NID_sha3_256:
                    return SHA3_256h;
            #endif
            #ifndef WOLFSSL_NOSHA3_384
                case WC_NID_sha3_384:
                    return SHA3_384h;
            #endif
            #ifndef WOLFSSL_NOSHA3_512
                case WC_NID_sha3_512:
                    return SHA3_512h;
            #endif
            }
            break;

        /*  oidSigType */
        case oidSigType:
            switch (nid) {
            #ifndef NO_DSA
                case WC_NID_dsaWithSHA1:
                    return CTC_SHAwDSA;
                case WC_NID_dsa_with_SHA256:
                    return CTC_SHA256wDSA;
            #endif /* NO_DSA */
            #ifndef NO_RSA
                case WC_NID_md2WithRSAEncryption:
                    return CTC_MD2wRSA;
                case WC_NID_md5WithRSAEncryption:
                    return CTC_MD5wRSA;
                case WC_NID_sha1WithRSAEncryption:
                    return CTC_SHAwRSA;
                case WC_NID_sha224WithRSAEncryption:
                    return CTC_SHA224wRSA;
                case WC_NID_sha256WithRSAEncryption:
                    return CTC_SHA256wRSA;
                case WC_NID_sha384WithRSAEncryption:
                    return CTC_SHA384wRSA;
                case WC_NID_sha512WithRSAEncryption:
                    return CTC_SHA512wRSA;
                #ifdef WOLFSSL_SHA3
                case WC_NID_RSA_SHA3_224:
                    return CTC_SHA3_224wRSA;
                case WC_NID_RSA_SHA3_256:
                    return CTC_SHA3_256wRSA;
                case WC_NID_RSA_SHA3_384:
                    return CTC_SHA3_384wRSA;
                case WC_NID_RSA_SHA3_512:
                    return CTC_SHA3_512wRSA;
                #endif
            #endif /* NO_RSA */
            #ifdef HAVE_ECC
                case WC_NID_ecdsa_with_SHA1:
                    return CTC_SHAwECDSA;
                case WC_NID_ecdsa_with_SHA224:
                    return CTC_SHA224wECDSA;
                case WC_NID_ecdsa_with_SHA256:
                    return CTC_SHA256wECDSA;
                case WC_NID_ecdsa_with_SHA384:
                    return CTC_SHA384wECDSA;
                case WC_NID_ecdsa_with_SHA512:
                    return CTC_SHA512wECDSA;
                #ifdef WOLFSSL_SHA3
                case WC_NID_ecdsa_with_SHA3_224:
                    return CTC_SHA3_224wECDSA;
                case WC_NID_ecdsa_with_SHA3_256:
                    return CTC_SHA3_256wECDSA;
                case WC_NID_ecdsa_with_SHA3_384:
                    return CTC_SHA3_384wECDSA;
                case WC_NID_ecdsa_with_SHA3_512:
                    return CTC_SHA3_512wECDSA;
                #endif
            #endif /* HAVE_ECC */
            }
            break;

        /* oidKeyType */
        case oidKeyType:
            switch (nid) {
            #ifndef NO_DSA
                case WC_NID_dsa:
                    return DSAk;
            #endif /* NO_DSA */
            #ifndef NO_RSA
                case WC_NID_rsaEncryption:
                    return RSAk;
            #endif /* NO_RSA */
            #ifdef HAVE_ECC
                case WC_NID_X9_62_id_ecPublicKey:
                    return ECDSAk;
            #endif /* HAVE_ECC */
            }
            break;


    #ifdef HAVE_ECC
        case oidCurveType:
            switch (nid) {
            case WC_NID_X9_62_prime192v1:
                return ECC_SECP192R1_OID;
            case WC_NID_X9_62_prime192v2:
                return ECC_PRIME192V2_OID;
            case WC_NID_X9_62_prime192v3:
                return ECC_PRIME192V3_OID;
            case WC_NID_X9_62_prime239v1:
                return ECC_PRIME239V1_OID;
            case WC_NID_X9_62_prime239v2:
                return ECC_PRIME239V2_OID;
            case WC_NID_X9_62_prime239v3:
                return ECC_PRIME239V3_OID;
            case WC_NID_X9_62_prime256v1:
                return ECC_SECP256R1_OID;
            case WC_NID_secp112r1:
                return ECC_SECP112R1_OID;
            case WC_NID_secp112r2:
                return ECC_SECP112R2_OID;
            case WC_NID_secp128r1:
                return ECC_SECP128R1_OID;
            case WC_NID_secp128r2:
                return ECC_SECP128R2_OID;
            case WC_NID_secp160r1:
                return ECC_SECP160R1_OID;
            case WC_NID_secp160r2:
                return ECC_SECP160R2_OID;
            case WC_NID_secp224r1:
                return ECC_SECP224R1_OID;
            case WC_NID_secp384r1:
                return ECC_SECP384R1_OID;
            case WC_NID_secp521r1:
                return ECC_SECP521R1_OID;
            case WC_NID_secp160k1:
                return ECC_SECP160K1_OID;
            case WC_NID_secp192k1:
                return ECC_SECP192K1_OID;
            case WC_NID_secp224k1:
                return ECC_SECP224K1_OID;
            case WC_NID_secp256k1:
                return ECC_SECP256K1_OID;
            case WC_NID_brainpoolP160r1:
                return ECC_BRAINPOOLP160R1_OID;
            case WC_NID_brainpoolP192r1:
                return ECC_BRAINPOOLP192R1_OID;
            case WC_NID_brainpoolP224r1:
                return ECC_BRAINPOOLP224R1_OID;
            case WC_NID_brainpoolP256r1:
                return ECC_BRAINPOOLP256R1_OID;
            case WC_NID_brainpoolP320r1:
                return ECC_BRAINPOOLP320R1_OID;
            case WC_NID_brainpoolP384r1:
                return ECC_BRAINPOOLP384R1_OID;
            case WC_NID_brainpoolP512r1:
                return ECC_BRAINPOOLP512R1_OID;
            }
            break;
    #endif /* HAVE_ECC */

        /* oidBlkType */
        case oidBlkType:
            switch (nid) {
            #ifdef WOLFSSL_AES_128
                case AES128CBCb:
                    return AES128CBCb;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192CBCb:
                    return AES192CBCb;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256CBCb:
                    return AES256CBCb;
            #endif
            #ifndef NO_DES3
                case WC_NID_des:
                    return DESb;
                case WC_NID_des3:
                    return DES3b;
            #endif
            }
            break;

    #ifdef HAVE_OCSP
        case oidOcspType:
            switch (nid) {
                case WC_NID_id_pkix_OCSP_basic:
                    return OCSP_BASIC_OID;
                case OCSP_NONCE_OID:
                    return OCSP_NONCE_OID;
            }
            break;
    #endif /* HAVE_OCSP */

        /* oidCertExtType */
        case oidCertExtType:
            switch (nid) {
                case WC_NID_basic_constraints:
                    return BASIC_CA_OID;
                case WC_NID_subject_alt_name:
                    return ALT_NAMES_OID;
                case WC_NID_crl_distribution_points:
                    return CRL_DIST_OID;
                case WC_NID_info_access:
                    return AUTH_INFO_OID;
                case WC_NID_authority_key_identifier:
                    return AUTH_KEY_OID;
                case WC_NID_subject_key_identifier:
                    return SUBJ_KEY_OID;
                case WC_NID_inhibit_any_policy:
                    return INHIBIT_ANY_OID;
                case WC_NID_key_usage:
                    return KEY_USAGE_OID;
                case WC_NID_name_constraints:
                    return NAME_CONS_OID;
                case WC_NID_certificate_policies:
                    return CERT_POLICY_OID;
                case WC_NID_ext_key_usage:
                    return EXT_KEY_USAGE_OID;
            }
            break;

        /* oidCertAuthInfoType */
        case oidCertAuthInfoType:
            switch (nid) {
                case WC_NID_ad_OCSP:
                    return AIA_OCSP_OID;
                case WC_NID_ad_ca_issuers:
                    return AIA_CA_ISSUER_OID;
            }
            break;

        /* oidCertPolicyType */
        case oidCertPolicyType:
            switch (nid) {
                case WC_NID_any_policy:
                    return CP_ANY_OID;
            }
            break;

        /* oidCertAltNameType */
        case oidCertAltNameType:
            switch (nid) {
                case WC_NID_hw_name_oid:
                    return HW_NAME_OID;
            }
            break;

        /* oidCertKeyUseType */
        case oidCertKeyUseType:
            switch (nid) {
                case WC_NID_anyExtendedKeyUsage:
                    return EKU_ANY_OID;
                case EKU_SERVER_AUTH_OID:
                    return EKU_SERVER_AUTH_OID;
                case EKU_CLIENT_AUTH_OID:
                    return EKU_CLIENT_AUTH_OID;
                case EKU_OCSP_SIGN_OID:
                    return EKU_OCSP_SIGN_OID;
            }
            break;

        /* oidKdfType */
        case oidKdfType:
            switch (nid) {
                case PBKDF2_OID:
                    return PBKDF2_OID;
            }
            break;

        /* oidPBEType */
        case oidPBEType:
            switch (nid) {
                case PBE_SHA1_RC4_128:
                    return PBE_SHA1_RC4_128;
                case PBE_SHA1_DES:
                    return PBE_SHA1_DES;
                case PBE_SHA1_DES3:
                    return PBE_SHA1_DES3;
            }
            break;

        /* oidKeyWrapType */
        case oidKeyWrapType:
            switch (nid) {
            #ifdef WOLFSSL_AES_128
                case AES128_WRAP:
                    return AES128_WRAP;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192_WRAP:
                    return AES192_WRAP;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256_WRAP:
                    return AES256_WRAP;
            #endif
            }
            break;

        /* oidCmsKeyAgreeType */
        case oidCmsKeyAgreeType:
            switch (nid) {
                #ifndef NO_SHA
                case dhSinglePass_stdDH_sha1kdf_scheme:
                    return dhSinglePass_stdDH_sha1kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA224
                case dhSinglePass_stdDH_sha224kdf_scheme:
                    return dhSinglePass_stdDH_sha224kdf_scheme;
                #endif
                #ifndef NO_SHA256
                case dhSinglePass_stdDH_sha256kdf_scheme:
                    return dhSinglePass_stdDH_sha256kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA384
                case dhSinglePass_stdDH_sha384kdf_scheme:
                    return dhSinglePass_stdDH_sha384kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA512
                case dhSinglePass_stdDH_sha512kdf_scheme:
                    return dhSinglePass_stdDH_sha512kdf_scheme;
                #endif
            }
            break;

        /* oidCmsKeyAgreeType */
    #ifdef WOLFSSL_CERT_REQ
        case oidCsrAttrType:
            switch (nid) {
                case WC_NID_pkcs9_contentType:
                    return PKCS9_CONTENT_TYPE_OID;
                case WC_NID_pkcs9_challengePassword:
                    return CHALLENGE_PASSWORD_OID;
                case WC_NID_serialNumber:
                    return SERIAL_NUMBER_OID;
                case WC_NID_userId:
                    return USER_ID_OID;
                case WC_NID_surname:
                    return SURNAME_OID;
            }
            break;
    #endif

        default:
            WOLFSSL_MSG("NID not in table");
            /* MSVC warns without the cast */
            return (word32)-1;
    }

    /* MSVC warns without the cast */
    return (word32)-1;
}

int oid2nid(word32 oid, int grp)
{
    size_t i;
    /* get OID type */
    switch (grp) {
        /* oidHashType */
        case oidHashType:
            switch (oid) {
            #ifdef WOLFSSL_MD2
                case MD2h:
                    return WC_NID_md2;
            #endif
            #ifndef NO_MD5
                case MD5h:
                    return WC_NID_md5;
            #endif
            #ifndef NO_SHA
                case SHAh:
                    return WC_NID_sha1;
            #endif
                case SHA224h:
                    return WC_NID_sha224;
            #ifndef NO_SHA256
                case SHA256h:
                    return WC_NID_sha256;
            #endif
            #ifdef WOLFSSL_SHA384
                case SHA384h:
                    return WC_NID_sha384;
            #endif
            #ifdef WOLFSSL_SHA512
                case SHA512h:
                    return WC_NID_sha512;
            #endif
            }
            break;

        /*  oidSigType */
        case oidSigType:
            switch (oid) {
            #ifndef NO_DSA
                case CTC_SHAwDSA:
                    return WC_NID_dsaWithSHA1;
                case CTC_SHA256wDSA:
                    return WC_NID_dsa_with_SHA256;
            #endif /* NO_DSA */
            #ifndef NO_RSA
                case CTC_MD2wRSA:
                    return WC_NID_md2WithRSAEncryption;
                case CTC_MD5wRSA:
                    return WC_NID_md5WithRSAEncryption;
                case CTC_SHAwRSA:
                    return WC_NID_sha1WithRSAEncryption;
                case CTC_SHA224wRSA:
                    return WC_NID_sha224WithRSAEncryption;
                case CTC_SHA256wRSA:
                    return WC_NID_sha256WithRSAEncryption;
                case CTC_SHA384wRSA:
                    return WC_NID_sha384WithRSAEncryption;
                case CTC_SHA512wRSA:
                    return WC_NID_sha512WithRSAEncryption;
                #ifdef WOLFSSL_SHA3
                case CTC_SHA3_224wRSA:
                    return WC_NID_RSA_SHA3_224;
                case CTC_SHA3_256wRSA:
                    return WC_NID_RSA_SHA3_256;
                case CTC_SHA3_384wRSA:
                    return WC_NID_RSA_SHA3_384;
                case CTC_SHA3_512wRSA:
                    return WC_NID_RSA_SHA3_512;
                #endif
                #ifdef WC_RSA_PSS
                case CTC_RSASSAPSS:
                    return WC_NID_rsassaPss;
                #endif
            #endif /* NO_RSA */
            #ifdef HAVE_ECC
                case CTC_SHAwECDSA:
                    return WC_NID_ecdsa_with_SHA1;
                case CTC_SHA224wECDSA:
                    return WC_NID_ecdsa_with_SHA224;
                case CTC_SHA256wECDSA:
                    return WC_NID_ecdsa_with_SHA256;
                case CTC_SHA384wECDSA:
                    return WC_NID_ecdsa_with_SHA384;
                case CTC_SHA512wECDSA:
                    return WC_NID_ecdsa_with_SHA512;
                #ifdef WOLFSSL_SHA3
                case CTC_SHA3_224wECDSA:
                    return WC_NID_ecdsa_with_SHA3_224;
                case CTC_SHA3_256wECDSA:
                    return WC_NID_ecdsa_with_SHA3_256;
                case CTC_SHA3_384wECDSA:
                    return WC_NID_ecdsa_with_SHA3_384;
                case CTC_SHA3_512wECDSA:
                    return WC_NID_ecdsa_with_SHA3_512;
                #endif
            #endif /* HAVE_ECC */
            }
            break;

        /* oidKeyType */
        case oidKeyType:
            switch (oid) {
            #ifndef NO_DSA
                case DSAk:
                    return WC_NID_dsa;
            #endif /* NO_DSA */
            #ifndef NO_RSA
                case RSAk:
                    return WC_NID_rsaEncryption;
                #ifdef WC_RSA_PSS
                case RSAPSSk:
                    return WC_NID_rsassaPss;
                #endif
            #endif /* NO_RSA */
            #ifdef HAVE_ECC
                case ECDSAk:
                    return WC_NID_X9_62_id_ecPublicKey;
            #endif /* HAVE_ECC */
            }
            break;


    #ifdef HAVE_ECC
        case oidCurveType:
            switch (oid) {
            case ECC_SECP192R1_OID:
                return WC_NID_X9_62_prime192v1;
            case ECC_PRIME192V2_OID:
                return WC_NID_X9_62_prime192v2;
            case ECC_PRIME192V3_OID:
                return WC_NID_X9_62_prime192v3;
            case ECC_PRIME239V1_OID:
                return WC_NID_X9_62_prime239v1;
            case ECC_PRIME239V2_OID:
                return WC_NID_X9_62_prime239v2;
            case ECC_PRIME239V3_OID:
                return WC_NID_X9_62_prime239v3;
            case ECC_SECP256R1_OID:
                return WC_NID_X9_62_prime256v1;
            case ECC_SECP112R1_OID:
                return WC_NID_secp112r1;
            case ECC_SECP112R2_OID:
                return WC_NID_secp112r2;
            case ECC_SECP128R1_OID:
                return WC_NID_secp128r1;
            case ECC_SECP128R2_OID:
                return WC_NID_secp128r2;
            case ECC_SECP160R1_OID:
                return WC_NID_secp160r1;
            case ECC_SECP160R2_OID:
                return WC_NID_secp160r2;
            case ECC_SECP224R1_OID:
                return WC_NID_secp224r1;
            case ECC_SECP384R1_OID:
                return WC_NID_secp384r1;
            case ECC_SECP521R1_OID:
                return WC_NID_secp521r1;
            case ECC_SECP160K1_OID:
                return WC_NID_secp160k1;
            case ECC_SECP192K1_OID:
                return WC_NID_secp192k1;
            case ECC_SECP224K1_OID:
                return WC_NID_secp224k1;
            case ECC_SECP256K1_OID:
                return WC_NID_secp256k1;
            case ECC_BRAINPOOLP160R1_OID:
                return WC_NID_brainpoolP160r1;
            case ECC_BRAINPOOLP192R1_OID:
                return WC_NID_brainpoolP192r1;
            case ECC_BRAINPOOLP224R1_OID:
                return WC_NID_brainpoolP224r1;
            case ECC_BRAINPOOLP256R1_OID:
                return WC_NID_brainpoolP256r1;
            case ECC_BRAINPOOLP320R1_OID:
                return WC_NID_brainpoolP320r1;
            case ECC_BRAINPOOLP384R1_OID:
                return WC_NID_brainpoolP384r1;
            case ECC_BRAINPOOLP512R1_OID:
                return WC_NID_brainpoolP512r1;
            }
            break;
    #endif /* HAVE_ECC */

        /* oidBlkType */
        case oidBlkType:
            switch (oid) {
            #ifdef WOLFSSL_AES_128
                case AES128CBCb:
                    return AES128CBCb;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192CBCb:
                    return AES192CBCb;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256CBCb:
                    return AES256CBCb;
            #endif
            #ifndef NO_DES3
                case DESb:
                    return WC_NID_des;
                case DES3b:
                    return WC_NID_des3;
            #endif
            }
            break;

    #ifdef HAVE_OCSP
        case oidOcspType:
            switch (oid) {
                case OCSP_BASIC_OID:
                    return WC_NID_id_pkix_OCSP_basic;
                case OCSP_NONCE_OID:
                    return OCSP_NONCE_OID;
            }
            break;
    #endif /* HAVE_OCSP */

        /* oidCertExtType */
        case oidCertExtType:
            switch (oid) {
                case BASIC_CA_OID:
                    return WC_NID_basic_constraints;
                case ALT_NAMES_OID:
                    return WC_NID_subject_alt_name;
                case CRL_DIST_OID:
                    return WC_NID_crl_distribution_points;
                case AUTH_INFO_OID:
                    return WC_NID_info_access;
                case AUTH_KEY_OID:
                    return WC_NID_authority_key_identifier;
                case SUBJ_KEY_OID:
                    return WC_NID_subject_key_identifier;
                case INHIBIT_ANY_OID:
                    return WC_NID_inhibit_any_policy;
                case KEY_USAGE_OID:
                    return WC_NID_key_usage;
                case NAME_CONS_OID:
                    return WC_NID_name_constraints;
                case CERT_POLICY_OID:
                    return WC_NID_certificate_policies;
                case EXT_KEY_USAGE_OID:
                    return WC_NID_ext_key_usage;
            }
            break;

        /* oidCertAuthInfoType */
        case oidCertAuthInfoType:
            switch (oid) {
                case AIA_OCSP_OID:
                    return WC_NID_ad_OCSP;
                case AIA_CA_ISSUER_OID:
                    return WC_NID_ad_ca_issuers;
            }
            break;

        /* oidCertPolicyType */
        case oidCertPolicyType:
            switch (oid) {
                case CP_ANY_OID:
                    return WC_NID_any_policy;
            }
            break;

        /* oidCertAltNameType */
        case oidCertAltNameType:
            switch (oid) {
                case HW_NAME_OID:
                    return WC_NID_hw_name_oid;
            }
            break;

        /* oidCertKeyUseType */
        case oidCertKeyUseType:
            switch (oid) {
                case EKU_ANY_OID:
                    return WC_NID_anyExtendedKeyUsage;
                case EKU_SERVER_AUTH_OID:
                    return EKU_SERVER_AUTH_OID;
                case EKU_CLIENT_AUTH_OID:
                    return EKU_CLIENT_AUTH_OID;
                case EKU_OCSP_SIGN_OID:
                    return EKU_OCSP_SIGN_OID;
            }
            break;

        /* oidKdfType */
        case oidKdfType:
            switch (oid) {
                case PBKDF2_OID:
                    return PBKDF2_OID;
            }
            break;

        /* oidPBEType */
        case oidPBEType:
            switch (oid) {
                case PBE_SHA1_RC4_128:
                    return PBE_SHA1_RC4_128;
                case PBE_SHA1_DES:
                    return PBE_SHA1_DES;
                case PBE_SHA1_DES3:
                    return PBE_SHA1_DES3;
            }
            break;

        /* oidKeyWrapType */
        case oidKeyWrapType:
            switch (oid) {
            #ifdef WOLFSSL_AES_128
                case AES128_WRAP:
                    return AES128_WRAP;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192_WRAP:
                    return AES192_WRAP;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256_WRAP:
                    return AES256_WRAP;
            #endif
            }
            break;

        /* oidCmsKeyAgreeType */
        case oidCmsKeyAgreeType:
            switch (oid) {
                #ifndef NO_SHA
                case dhSinglePass_stdDH_sha1kdf_scheme:
                    return dhSinglePass_stdDH_sha1kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA224
                case dhSinglePass_stdDH_sha224kdf_scheme:
                    return dhSinglePass_stdDH_sha224kdf_scheme;
                #endif
                #ifndef NO_SHA256
                case dhSinglePass_stdDH_sha256kdf_scheme:
                    return dhSinglePass_stdDH_sha256kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA384
                case dhSinglePass_stdDH_sha384kdf_scheme:
                    return dhSinglePass_stdDH_sha384kdf_scheme;
                #endif
                #ifdef WOLFSSL_SHA512
                case dhSinglePass_stdDH_sha512kdf_scheme:
                    return dhSinglePass_stdDH_sha512kdf_scheme;
                #endif
            }
            break;

#ifdef WOLFSSL_CERT_REQ
        case oidCsrAttrType:
            switch (oid) {
                case PKCS9_CONTENT_TYPE_OID:
                    return WC_NID_pkcs9_contentType;
                case CHALLENGE_PASSWORD_OID:
                    return WC_NID_pkcs9_challengePassword;
                case SERIAL_NUMBER_OID:
                    return WC_NID_serialNumber;
                case USER_ID_OID:
                    return WC_NID_userId;
            }
            break;
#endif

        default:
            WOLFSSL_MSG("OID not in table");
    }
    /* If not found in above switch then try the table */
    for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++) {
        if (wolfssl_object_info[i].id == (int)oid) {
            return wolfssl_object_info[i].nid;
        }
    }

    return WOLFSSL_FATAL_ERROR;
}

/* frees all nodes in the current threads error queue
 *
 * id  thread id. ERR_remove_state is depreciated and id is ignored. The
 *     current threads queue will be free'd.
 */
void wolfSSL_ERR_remove_state(unsigned long id)
{
    WOLFSSL_ENTER("wolfSSL_ERR_remove_state");
    (void)id;
    if (wc_ERR_remove_state() != 0) {
        WOLFSSL_MSG("Error with removing the state");
    }
}

#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_ALL

#if !defined(NO_BIO) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)

static int bio_get_data(WOLFSSL_BIO* bio, byte** data)
{
    int ret = 0;
    byte* mem = NULL;

    ret = wolfSSL_BIO_get_len(bio);
    if (ret > 0) {
        mem = (byte*)XMALLOC(ret, bio->heap, DYNAMIC_TYPE_OPENSSL);
        if (mem == NULL) {
            WOLFSSL_MSG("Memory error");
            ret = MEMORY_E;
        }
        if (ret >= 0) {
            if ((ret = wolfSSL_BIO_read(bio, mem, ret)) <= 0) {
                XFREE(mem, bio->heap, DYNAMIC_TYPE_OPENSSL);
                ret = MEMORY_E;
                mem = NULL;
            }
        }
    }

    *data = mem;

    return ret;
}

/* DER data is PKCS#8 encrypted. */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PKCS8PrivateKey_bio(WOLFSSL_BIO* bio,
                                                  WOLFSSL_EVP_PKEY** pkey,
                                                  wc_pem_password_cb* cb,
                                                  void* ctx)
{
    int ret;
    byte* der;
    int len;
    byte* p;
    word32 algId;
    WOLFSSL_EVP_PKEY* key;

    if ((len = bio_get_data(bio, &der)) < 0)
        return NULL;

    if (cb != NULL) {
        char password[NAME_SZ];
        int passwordSz = cb(password, sizeof(password), PEM_PASS_READ, ctx);
        if (passwordSz < 0) {
            XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
            return NULL;
        }
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("wolfSSL_d2i_PKCS8PrivateKey_bio password", password,
            passwordSz);
    #endif

        ret = ToTraditionalEnc(der, (word32)len, password, passwordSz, &algId);
        if (ret < 0) {
            XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
            return NULL;
        }

        ForceZero(password, (word32)passwordSz);
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(password, passwordSz);
    #endif
    }

    p = der;
    key = wolfSSL_d2i_PrivateKey_EVP(pkey, &p, len);
    XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
    return key;
}

#endif /* !NO_BIO && !NO_PWDBASED && HAVE_PKCS8 */

/* Detect which type of key it is before decoding. */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_AutoPrivateKey(WOLFSSL_EVP_PKEY** pkey,
                                             const unsigned char** pp,
                                             long length)
{
    int ret;
    WOLFSSL_EVP_PKEY* key = NULL;
    const byte* der = *pp;
    word32 idx = 0;
    int len = 0;
    int cnt = 0;
    word32 algId;
    word32 keyLen = (word32)length;

    /* Take off PKCS#8 wrapper if found. */
    if ((len = ToTraditionalInline_ex(der, &idx, keyLen, &algId)) >= 0) {
        der += idx;
        keyLen = (word32)len;
    }
    idx = 0;
    len = 0;

    /* Use the number of elements in the outer sequence to determine key type.
     */
    ret = GetSequence(der, &idx, &len, keyLen);
    if (ret >= 0) {
        word32 end = idx + len;
        while (ret >= 0 && idx < end) {
            /* Skip type */
            idx++;
            /* Get length and skip over - keeping count */
            len = 0;
            ret = GetLength(der, &idx, &len, keyLen);
            if (ret >= 0) {
                if (idx + len > end)
                    ret = ASN_PARSE_E;
                else {
                    idx += len;
                    cnt++;
                }
            }
        }
    }

    if (ret >= 0) {
        int type;
        /* ECC includes version, private[, curve][, public key] */
        if (cnt >= 2 && cnt <= 4)
            type = WC_EVP_PKEY_EC;
        else
            type = WC_EVP_PKEY_RSA;

        key = wolfSSL_d2i_PrivateKey(type, pkey, &der, keyLen);
        *pp = der;
    }

    return key;
}
#endif /* OPENSSL_ALL */

#ifdef WOLFSSL_STATIC_EPHEMERAL
int wolfSSL_StaticEphemeralKeyLoad(WOLFSSL* ssl, int keyAlgo, void* keyPtr)
{
    int ret;
    word32 idx = 0;
    DerBuffer* der = NULL;

    if (ssl == NULL || ssl->ctx == NULL || keyPtr == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef SINGLE_THREADED
    if (!ssl->ctx->staticKELockInit) {
        return BUFFER_E; /* no keys set */
    }
    ret = wc_LockMutex(&ssl->ctx->staticKELock);
    if (ret != 0) {
        return ret;
    }
#endif

    ret = BUFFER_E; /* set default error */
    switch (keyAlgo) {
    #ifndef NO_DH
        case WC_PK_TYPE_DH:
            if (ssl != NULL)
                der = ssl->staticKE.dhKey;
            if (der == NULL)
                der = ssl->ctx->staticKE.dhKey;
            if (der != NULL) {
                DhKey* key = (DhKey*)keyPtr;
                WOLFSSL_MSG("Using static DH key");
                ret = wc_DhKeyDecode(der->buffer, &idx, key, der->length);
            }
            break;
    #endif
    #ifdef HAVE_ECC
        case WC_PK_TYPE_ECDH:
            if (ssl != NULL)
                der = ssl->staticKE.ecKey;
            if (der == NULL)
                der = ssl->ctx->staticKE.ecKey;
            if (der != NULL) {
                ecc_key* key = (ecc_key*)keyPtr;
                WOLFSSL_MSG("Using static ECDH key");
                ret = wc_EccPrivateKeyDecode(der->buffer, &idx, key,
                    der->length);
            }
            break;
    #endif
    #ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519:
            if (ssl != NULL)
                der = ssl->staticKE.x25519Key;
            if (der == NULL)
                der = ssl->ctx->staticKE.x25519Key;
            if (der != NULL) {
                curve25519_key* key = (curve25519_key*)keyPtr;
                WOLFSSL_MSG("Using static X25519 key");
                ret = wc_Curve25519PrivateKeyDecode(der->buffer, &idx, key,
                    der->length);
            }
            break;
    #endif
    #ifdef HAVE_CURVE448
        case WC_PK_TYPE_CURVE448:
            if (ssl != NULL)
                der = ssl->staticKE.x448Key;
            if (der == NULL)
                der = ssl->ctx->staticKE.x448Key;
            if (der != NULL) {
                curve448_key* key = (curve448_key*)keyPtr;
                WOLFSSL_MSG("Using static X448 key");
                ret = wc_Curve448PrivateKeyDecode(der->buffer, &idx, key,
                    der->length);
            }
            break;
    #endif
        default:
            /* not supported */
            ret = NOT_COMPILED_IN;
            break;
    }

#ifndef SINGLE_THREADED
    wc_UnLockMutex(&ssl->ctx->staticKELock);
#endif
    return ret;
}

static int SetStaticEphemeralKey(WOLFSSL_CTX* ctx,
    StaticKeyExchangeInfo_t* staticKE, int keyAlgo, const char* key,
    unsigned int keySz, int format, void* heap)
{
    int ret = 0;
    DerBuffer* der = NULL;
    byte* keyBuf = NULL;
#ifndef NO_FILESYSTEM
    const char* keyFile = NULL;
#endif

    /* allow empty key to free buffer */
    if (staticKE == NULL || (key == NULL && keySz > 0)) {
        return BAD_FUNC_ARG;
    }

    WOLFSSL_ENTER("SetStaticEphemeralKey");

    /* if just free'ing key then skip loading */
    if (key != NULL) {
    #ifndef NO_FILESYSTEM
        /* load file from filesystem */
        if (key != NULL && keySz == 0) {
            size_t keyBufSz = 0;
            keyFile = (const char*)key;
            ret = wc_FileLoad(keyFile, &keyBuf, &keyBufSz, heap);
            if (ret != 0) {
                return ret;
            }
            keySz = (unsigned int)keyBufSz;
        }
        else
    #endif
        {
            /* use as key buffer directly */
            keyBuf = (byte*)key;
        }

        if (format == WOLFSSL_FILETYPE_PEM) {
        #ifdef WOLFSSL_PEM_TO_DER
            int keyFormat = 0;
            ret = PemToDer(keyBuf, keySz, PRIVATEKEY_TYPE, &der,
                heap, NULL, &keyFormat);
            /* auto detect key type */
            if (ret == 0 && keyAlgo == WC_PK_TYPE_NONE) {
                if (keyFormat == ECDSAk)
                    keyAlgo = WC_PK_TYPE_ECDH;
                else if (keyFormat == X25519k)
                    keyAlgo = WC_PK_TYPE_CURVE25519;
                else
                    keyAlgo = WC_PK_TYPE_DH;
            }
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
        else {
            /* Detect PK type (if required) */
        #ifdef HAVE_ECC
            if (keyAlgo == WC_PK_TYPE_NONE) {
                word32 idx = 0;
                ecc_key eccKey;
                ret = wc_ecc_init_ex(&eccKey, heap, INVALID_DEVID);
                if (ret == 0) {
                    ret = wc_EccPrivateKeyDecode(keyBuf, &idx, &eccKey, keySz);
                    if (ret == 0)
                        keyAlgo = WC_PK_TYPE_ECDH;
                    wc_ecc_free(&eccKey);
                }
            }
        #endif
        #if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
            if (keyAlgo == WC_PK_TYPE_NONE) {
                word32 idx = 0;
                DhKey dhKey;
                ret = wc_InitDhKey_ex(&dhKey, heap, INVALID_DEVID);
                if (ret == 0) {
                    ret = wc_DhKeyDecode(keyBuf, &idx, &dhKey, keySz);
                    if (ret == 0)
                        keyAlgo = WC_PK_TYPE_DH;
                    wc_FreeDhKey(&dhKey);
                }
            }
        #endif
        #ifdef HAVE_CURVE25519
            if (keyAlgo == WC_PK_TYPE_NONE) {
                word32 idx = 0;
                curve25519_key x25519Key;
                ret = wc_curve25519_init_ex(&x25519Key, heap, INVALID_DEVID);
                if (ret == 0) {
                    ret = wc_Curve25519PrivateKeyDecode(keyBuf, &idx,
                        &x25519Key, keySz);
                    if (ret == 0)
                        keyAlgo = WC_PK_TYPE_CURVE25519;
                    wc_curve25519_free(&x25519Key);
                }
            }
        #endif
        #ifdef HAVE_CURVE448
            if (keyAlgo == WC_PK_TYPE_NONE) {
                word32 idx = 0;
                curve448_key x448Key;
                ret = wc_curve448_init(&x448Key);
                if (ret == 0) {
                    ret = wc_Curve448PrivateKeyDecode(keyBuf, &idx, &x448Key,
                        keySz);
                    if (ret == 0)
                        keyAlgo = WC_PK_TYPE_CURVE448;
                    wc_curve448_free(&x448Key);
                }
            }
        #endif

            if (keyAlgo != WC_PK_TYPE_NONE) {
                ret = AllocDer(&der, keySz, PRIVATEKEY_TYPE, heap);
                if (ret == 0) {
                    XMEMCPY(der->buffer, keyBuf, keySz);
                }
            }
        }
    }

#ifndef NO_FILESYSTEM
    /* done with keyFile buffer */
    if (keyFile && keyBuf) {
        XFREE(keyBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

#ifndef SINGLE_THREADED
    if (ret == 0 && !ctx->staticKELockInit) {
        ret = wc_InitMutex(&ctx->staticKELock);
        if (ret == 0) {
            ctx->staticKELockInit = 1;
        }
    }
#endif
    if (ret == 0
    #ifndef SINGLE_THREADED
        && (ret = wc_LockMutex(&ctx->staticKELock)) == 0
    #endif
    ) {
        switch (keyAlgo) {
        #ifndef NO_DH
            case WC_PK_TYPE_DH:
                FreeDer(&staticKE->dhKey);
                staticKE->dhKey = der; der = NULL;
                break;
        #endif
        #ifdef HAVE_ECC
            case WC_PK_TYPE_ECDH:
                FreeDer(&staticKE->ecKey);
                staticKE->ecKey = der; der = NULL;
                break;
        #endif
        #ifdef HAVE_CURVE25519
            case WC_PK_TYPE_CURVE25519:
                FreeDer(&staticKE->x25519Key);
                staticKE->x25519Key = der; der = NULL;
                break;
        #endif
        #ifdef HAVE_CURVE448
            case WC_PK_TYPE_CURVE448:
                FreeDer(&staticKE->x448Key);
                staticKE->x448Key = der; der = NULL;
                break;
        #endif
            default:
                /* not supported */
                ret = NOT_COMPILED_IN;
                break;
        }

    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&ctx->staticKELock);
    #endif
    }

    if (ret != 0) {
        FreeDer(&der);
    }

    (void)ctx; /* not used for single threaded */

    WOLFSSL_LEAVE("SetStaticEphemeralKey", ret);

    return ret;
}

int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const char* key, unsigned int keySz, int format)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    return SetStaticEphemeralKey(ctx, &ctx->staticKE, keyAlgo,
        key, keySz, format, ctx->heap);
}
int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const char* key, unsigned int keySz, int format)
{
    if (ssl == NULL || ssl->ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    return SetStaticEphemeralKey(ssl->ctx, &ssl->staticKE, keyAlgo,
        key, keySz, format, ssl->heap);
}

static int GetStaticEphemeralKey(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    int keyAlgo, const unsigned char** key, unsigned int* keySz)
{
    int ret = 0;
    DerBuffer* der = NULL;

    if (key)   *key = NULL;
    if (keySz) *keySz = 0;

#ifndef SINGLE_THREADED
    if (ctx->staticKELockInit &&
        (ret = wc_LockMutex(&ctx->staticKELock)) != 0) {
        return ret;
    }
#endif

    switch (keyAlgo) {
    #ifndef NO_DH
        case WC_PK_TYPE_DH:
            if (ssl != NULL)
                der = ssl->staticKE.dhKey;
            if (der == NULL)
                der = ctx->staticKE.dhKey;
            break;
    #endif
    #ifdef HAVE_ECC
        case WC_PK_TYPE_ECDH:
            if (ssl != NULL)
                der = ssl->staticKE.ecKey;
            if (der == NULL)
                der = ctx->staticKE.ecKey;
            break;
    #endif
    #ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519:
            if (ssl != NULL)
                der = ssl->staticKE.x25519Key;
            if (der == NULL)
                der = ctx->staticKE.x25519Key;
            break;
    #endif
    #ifdef HAVE_CURVE448
        case WC_PK_TYPE_CURVE448:
            if (ssl != NULL)
                der = ssl->staticKE.x448Key;
            if (der == NULL)
                der = ctx->staticKE.x448Key;
            break;
    #endif
        default:
            /* not supported */
            ret = NOT_COMPILED_IN;
            break;
    }

    if (der) {
        if (key)
            *key = der->buffer;
        if (keySz)
            *keySz = der->length;
    }

#ifndef SINGLE_THREADED
    wc_UnLockMutex(&ctx->staticKELock);
#endif

    return ret;
}

/* returns pointer to currently loaded static ephemeral as ASN.1 */
/* this can be converted to PEM using wc_DerToPem */
int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    return GetStaticEphemeralKey(ctx, NULL, keyAlgo, key, keySz);
}
int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz)
{
    if (ssl == NULL || ssl->ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    return GetStaticEphemeralKey(ssl->ctx, ssl, keyAlgo, key, keySz);
}

#endif /* WOLFSSL_STATIC_EPHEMERAL */

#if defined(OPENSSL_EXTRA)
/* wolfSSL_THREADID_current is provided as a compat API with
 * CRYPTO_THREADID_current to register current thread id into given id object.
 * However, CRYPTO_THREADID_current API has been deprecated and no longer
 * exists in the OpenSSL 1.0.0 or later.This API only works as a stub
 * like as existing wolfSSL_THREADID_set_numeric.
 */
void wolfSSL_THREADID_current(WOLFSSL_CRYPTO_THREADID* id)
{
    (void)id;
    return;
}
/* wolfSSL_THREADID_hash is provided as a compatible API with
 * CRYPTO_THREADID_hash which returns a hash value calculated from the
 * specified thread id. However, CRYPTO_THREADID_hash API has been
 * deprecated and no longer exists in the OpenSSL 1.0.0 or later.
 * This API only works as a stub to returns 0. This behavior is
 * equivalent to the latest OpenSSL CRYPTO_THREADID_hash.
 */
unsigned long wolfSSL_THREADID_hash(const WOLFSSL_CRYPTO_THREADID* id)
{
    (void)id;
    return 0UL;
}
/* wolfSSL_set_ecdh_auto is provided as compatible API with
 * SSL_set_ecdh_auto to enable auto ecdh curve selection functionality.
 * Since this functionality is enabled by default in wolfSSL,
 * this API exists as a stub.
 */
int wolfSSL_set_ecdh_auto(WOLFSSL* ssl, int onoff)
{
    (void)ssl;
    (void)onoff;
    return WOLFSSL_SUCCESS;
}
/* wolfSSL_CTX_set_ecdh_auto is provided as compatible API with
 * SSL_CTX_set_ecdh_auto to enable auto ecdh curve selection functionality.
 * Since this functionality is enabled by default in wolfSSL,
 * this API exists as a stub.
 */
int wolfSSL_CTX_set_ecdh_auto(WOLFSSL_CTX* ctx, int onoff)
{
    (void)ctx;
    (void)onoff;
    return WOLFSSL_SUCCESS;
}

/* wolfSSL_CTX_set_dh_auto is provided as compatible API with
 * SSL_CTX_set_dh_auto to enable auto dh selection functionality.
 * Since this functionality is enabled by default in wolfSSL,
 * this API exists as a stub.
 */
int wolfSSL_CTX_set_dh_auto(WOLFSSL_CTX* ctx, int onoff)
{
    (void)ctx;
    (void)onoff;
    return WOLFSSL_SUCCESS;
}

/**
 * Set security level (wolfSSL doesn't support setting the security level).
 *
 * The security level can only be set through a system wide crypto-policy
 * with wolfSSL_crypto_policy_enable().
 *
 * @param ctx  a pointer to WOLFSSL_CTX structure
 * @param level security level
 */
void wolfSSL_CTX_set_security_level(WOLFSSL_CTX* ctx, int level)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_security_level");
    (void)ctx;
    (void)level;
}

int wolfSSL_CTX_get_security_level(const WOLFSSL_CTX * ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_security_level");
    #if defined(WOLFSSL_SYS_CRYPTO_POLICY)
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    return ctx->secLevel;
    #else
    (void)ctx;
    return 0;
    #endif /* WOLFSSL_SYS_CRYPTO_POLICY */
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_SECRET_CALLBACK)
/*
 * This API accepts a user callback which puts key-log records into
 * a KEY LOGFILE. The callback is stored into a CTX and propagated to
 * each SSL object on its creation timing.
 */
void wolfSSL_CTX_set_keylog_callback(WOLFSSL_CTX* ctx,
    wolfSSL_CTX_keylog_cb_func cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_keylog_callback");
    /* stores the callback into WOLFSSL_CTX */
    if (ctx != NULL) {
        ctx->keyLogCb = cb;
    }
}
wolfSSL_CTX_keylog_cb_func wolfSSL_CTX_get_keylog_callback(
    const WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_keylog_callback");
    if (ctx != NULL)
        return ctx->keyLogCb;
    return NULL;
}
#endif /* OPENSSL_EXTRA && HAVE_SECRET_CALLBACK */

#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_THREADED_CRYPT
int wolfSSL_AsyncEncryptReady(WOLFSSL* ssl, int idx)
{
    ThreadCrypt* encrypt;

    if (ssl == NULL) {
        return 0;
    }

    encrypt = &ssl->buffers.encrypt[idx];
    return (encrypt->avail == 0) && (encrypt->done == 0);
}

int wolfSSL_AsyncEncryptStop(WOLFSSL* ssl, int idx)
{
    ThreadCrypt* encrypt;

    if (ssl == NULL) {
        return 1;
    }

    encrypt = &ssl->buffers.encrypt[idx];
    return encrypt->stop;
}

int wolfSSL_AsyncEncrypt(WOLFSSL* ssl, int idx)
{
    int ret = WC_NO_ERR_TRACE(NOT_COMPILED_IN);
    ThreadCrypt* encrypt = &ssl->buffers.encrypt[idx];

    if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
        unsigned char* out = encrypt->buffer.buffer + encrypt->offset;
        unsigned char* input = encrypt->buffer.buffer + encrypt->offset;
        word32 encSz = encrypt->buffer.length - encrypt->offset;

        ret =
#if !defined(NO_GCM_ENCRYPT_EXTRA) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
              wc_AesGcmEncrypt_ex
#else
              wc_AesGcmEncrypt
#endif
              (encrypt->encrypt.aes,
               out + AESGCM_EXP_IV_SZ, input + AESGCM_EXP_IV_SZ,
               encSz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
               encrypt->nonce, AESGCM_NONCE_SZ,
               out + encSz - ssl->specs.aead_mac_size,
               ssl->specs.aead_mac_size,
               encrypt->additional, AEAD_AUTH_DATA_SZ);
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
        XMEMCPY(out, encrypt->nonce + AESGCM_IMP_IV_SZ, AESGCM_EXP_IV_SZ);
#endif
        encrypt->done = 1;
    }

    return ret;
}

int wolfSSL_AsyncEncryptSetSignal(WOLFSSL* ssl, int idx,
    WOLFSSL_THREAD_SIGNAL signal, void* ctx)
{
    int ret = 0;

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ssl->buffers.encrypt[idx].signal = signal;
        ssl->buffers.encrypt[idx].signalCtx = ctx;
    }

    return ret;
}
#endif


#ifndef NO_CERT
#define WOLFSSL_X509_INCLUDED
#include "src/x509.c"
#endif

/*******************************************************************************
 * START OF standard C library wrapping APIs
 ******************************************************************************/
#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
     defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
     defined(WOLFSSL_OPENSSH)))
#ifndef NO_WOLFSSL_STUB
int wolfSSL_CRYPTO_set_mem_ex_functions(void *(*m) (size_t, const char *, int),
                                void *(*r) (void *, size_t, const char *,
                                            int), void (*f) (void *))
{
    (void) m;
    (void) r;
    (void) f;
    WOLFSSL_ENTER("wolfSSL_CRYPTO_set_mem_ex_functions");
    WOLFSSL_STUB("CRYPTO_set_mem_ex_functions");

    return WOLFSSL_FAILURE;
}
#endif
#endif

#if defined(OPENSSL_EXTRA)

/**
 * free allocated memory resource
 * @param str  a pointer to resource to be freed
 * @param file dummy argument
 * @param line dummy argument
 */
void wolfSSL_CRYPTO_free(void *str, const char *file, int line)
{
    (void)file;
    (void)line;
    XFREE(str, 0, DYNAMIC_TYPE_TMP_BUFFER);
}
/**
 * allocate memory with size of num
 * @param num  size of memory allocation to be malloced
 * @param file dummy argument
 * @param line dummy argument
 * @return a pointer to allocated memory on succssesful, otherwise NULL
 */
void *wolfSSL_CRYPTO_malloc(size_t num, const char *file, int line)
{
    (void)file;
    (void)line;
    return XMALLOC(num, 0, DYNAMIC_TYPE_TMP_BUFFER);
}

#endif

/*******************************************************************************
 * END OF standard C library wrapping APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF EX_DATA APIs
 ******************************************************************************/
#ifdef HAVE_EX_DATA
void wolfSSL_CRYPTO_cleanup_all_ex_data(void)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_cleanup_all_ex_data");
}

void* wolfSSL_CRYPTO_get_ex_data(const WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_get_ex_data");
#ifdef MAX_EX_DATA
    if (ex_data && idx < MAX_EX_DATA && idx >= 0) {
        return ex_data->ex_data[idx];
    }
#else
    (void)ex_data;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_CRYPTO_set_ex_data(WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx,
    void *data)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_set_ex_data");
#ifdef MAX_EX_DATA
    if (ex_data && idx < MAX_EX_DATA && idx >= 0) {
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
        if (ex_data->ex_data_cleanup_routines[idx]) {
            /* call cleanup then remove cleanup callback,
             * since different value is being set */
            if (ex_data->ex_data[idx])
                ex_data->ex_data_cleanup_routines[idx](ex_data->ex_data[idx]);
            ex_data->ex_data_cleanup_routines[idx] = NULL;
        }
#endif
        ex_data->ex_data[idx] = data;
        return WOLFSSL_SUCCESS;
    }
#else
    (void)ex_data;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
int wolfSSL_CRYPTO_set_ex_data_with_cleanup(
    WOLFSSL_CRYPTO_EX_DATA* ex_data,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_set_ex_data_with_cleanup");
    if (ex_data && idx < MAX_EX_DATA && idx >= 0) {
        if (ex_data->ex_data_cleanup_routines[idx] && ex_data->ex_data[idx])
            ex_data->ex_data_cleanup_routines[idx](ex_data->ex_data[idx]);
        ex_data->ex_data[idx] = data;
        ex_data->ex_data_cleanup_routines[idx] = cleanup_routine;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */
#endif /* HAVE_EX_DATA */

#ifdef HAVE_EX_DATA_CRYPTO
/**
 * Issues unique index for the class specified by class_index.
 * Other parameter except class_index are ignored.
 * Currently, following class_index are accepted:
 *  - WOLF_CRYPTO_EX_INDEX_SSL
 *  - WOLF_CRYPTO_EX_INDEX_SSL_CTX
 *  - WOLF_CRYPTO_EX_INDEX_X509
 * @param class_index index one of CRYPTO_EX_INDEX_xxx
 * @param argp  parameters to be saved
 * @param argl  parameters to be saved
 * @param new_func a pointer to WOLFSSL_CRYPTO_EX_new
 * @param dup_func a pointer to WOLFSSL_CRYPTO_EX_dup
 * @param free_func a pointer to WOLFSSL_CRYPTO_EX_free
 * @return index value grater or equal to zero on success, -1 on failure.
 */
int wolfSSL_CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                                           WOLFSSL_CRYPTO_EX_new* new_func,
                                           WOLFSSL_CRYPTO_EX_dup* dup_func,
                                           WOLFSSL_CRYPTO_EX_free* free_func)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_get_ex_new_index");

    return wolfssl_get_ex_new_index(class_index, argl, argp, new_func,
            dup_func, free_func);
}
#endif /* HAVE_EX_DATA_CRYPTO */

/*******************************************************************************
 * END OF EX_DATA APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF BUF_MEM API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA)

/* Begin functions for openssl/buffer.h */
WOLFSSL_BUF_MEM* wolfSSL_BUF_MEM_new(void)
{
    WOLFSSL_BUF_MEM* buf;
    buf = (WOLFSSL_BUF_MEM*)XMALLOC(sizeof(WOLFSSL_BUF_MEM), NULL,
                                                        DYNAMIC_TYPE_OPENSSL);
    if (buf) {
        XMEMSET(buf, 0, sizeof(WOLFSSL_BUF_MEM));
    }
    return buf;
}

/* non-compat API returns length of buffer on success */
int wolfSSL_BUF_MEM_grow_ex(WOLFSSL_BUF_MEM* buf, size_t len,
        char zeroFill)
{

    int len_int = (int)len;
    int mx;
    char* tmp;

    /* verify provided arguments */
    if (buf == NULL || len_int < 0) {
        return 0; /* BAD_FUNC_ARG; */
    }

    /* check to see if fits in existing length */
    if (buf->length > len) {
        buf->length = len;
        return len_int;
    }

    /* check to see if fits in max buffer */
    if (buf->max >= len) {
        if (buf->data != NULL && zeroFill) {
            XMEMSET(&buf->data[buf->length], 0, len - buf->length);
        }
        buf->length = len;
        return len_int;
    }

    /* expand size, to handle growth */
    mx = (len_int + 3) / 3 * 4;

    /* use realloc */
    tmp = (char*)XREALLOC(buf->data, mx, NULL, DYNAMIC_TYPE_OPENSSL);
    if (tmp == NULL) {
        return 0; /* ERR_R_MALLOC_FAILURE; */
    }
    buf->data = tmp;

    buf->max = (size_t)mx;
    if (zeroFill)
        XMEMSET(&buf->data[buf->length], 0, len - buf->length);
    buf->length = len;

    return len_int;

}

/* returns length of buffer on success */
int wolfSSL_BUF_MEM_grow(WOLFSSL_BUF_MEM* buf, size_t len)
{
    return wolfSSL_BUF_MEM_grow_ex(buf, len, 1);
}

/* non-compat API returns length of buffer on success */
int wolfSSL_BUF_MEM_resize(WOLFSSL_BUF_MEM* buf, size_t len)
{
    char* tmp;
    int mx;

    /* verify provided arguments */
    if (buf == NULL || len == 0 || (int)len <= 0) {
        return 0; /* BAD_FUNC_ARG; */
    }

    if (len == buf->length)
        return (int)len;

    if (len > buf->length)
        return wolfSSL_BUF_MEM_grow_ex(buf, len, 0);

    /* expand size, to handle growth */
    mx = ((int)len + 3) / 3 * 4;

    /* We want to shrink the internal buffer */
    tmp = (char*)XREALLOC(buf->data, mx, NULL, DYNAMIC_TYPE_OPENSSL);
    if (tmp == NULL)
        return 0;

    buf->data = tmp;
    buf->length = len;
    buf->max = (size_t)mx;

    return (int)len;
}

void wolfSSL_BUF_MEM_free(WOLFSSL_BUF_MEM* buf)
{
    if (buf) {
        XFREE(buf->data, NULL, DYNAMIC_TYPE_OPENSSL);
        buf->data = NULL;
        buf->max = 0;
        buf->length = 0;
        XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}
/* End Functions for openssl/buffer.h */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF BUF_MEM API
 ******************************************************************************/

#define WOLFSSL_CONF_INCLUDED
#include <src/conf.c>

/*******************************************************************************
 * START OF RAND API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_OPENSSL_RAND_CB)
static int wolfSSL_RAND_InitMutex(void)
{
#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (gRandMethodsInit == 0) {
        if (wc_InitMutex(&gRandMethodMutex) != 0) {
            WOLFSSL_MSG("Bad Init Mutex rand methods");
            return BAD_MUTEX_E;
        }
        gRandMethodsInit = 1;
    }
#endif
    return 0;
}
#endif

#ifdef OPENSSL_EXTRA

/* Checks if the global RNG has been created. If not then one is created.
 *
 * Returns WOLFSSL_SUCCESS when no error is encountered.
 */
int wolfSSL_RAND_Init(void)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
#ifdef HAVE_GLOBAL_RNG
    if (wc_LockMutex(&globalRNGMutex) == 0) {
        if (initGlobalRNG == 0) {
            ret = wc_InitRng(&globalRNG);
            if (ret == 0) {
                initGlobalRNG = 1;
                ret = WOLFSSL_SUCCESS;
            }
        }
        else {
            /* GlobalRNG is already initialized */
            ret = WOLFSSL_SUCCESS;
        }

        wc_UnLockMutex(&globalRNGMutex);
    }
#endif
    return ret;
}


/* WOLFSSL_SUCCESS on ok */
int wolfSSL_RAND_seed(const void* seed, int len)
{
#ifndef WOLFSSL_NO_OPENSSL_RAND_CB
    if (wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex) == 0) {
        if (gRandMethods && gRandMethods->seed) {
            int ret = gRandMethods->seed(seed, len);
            wc_UnLockMutex(&gRandMethodMutex);
            return ret;
        }
        wc_UnLockMutex(&gRandMethodMutex);
    }
#else
    (void)seed;
    (void)len;
#endif

    /* Make sure global shared RNG (globalRNG) is initialized */
    return wolfSSL_RAND_Init();
}


/* Returns the path for reading seed data from.
 * Uses the env variable $RANDFILE first if set, if not then used $HOME/.rnd
 *
 * Note uses stdlib by default unless XGETENV macro is overwritten
 *
 * fname buffer to hold path
 * len   length of fname buffer
 *
 * Returns a pointer to fname on success and NULL on failure
 */
const char* wolfSSL_RAND_file_name(char* fname, unsigned long len)
{
#if !defined(NO_FILESYSTEM) && defined(XGETENV) && !defined(NO_GETENV)
    char* rt;

    WOLFSSL_ENTER("wolfSSL_RAND_file_name");

    if (fname == NULL) {
        return NULL;
    }

    XMEMSET(fname, 0, len);

/* // NOLINTBEGIN(concurrency-mt-unsafe) */
    if ((rt = XGETENV("RANDFILE")) != NULL) {
        if (len > XSTRLEN(rt)) {
            XMEMCPY(fname, rt, XSTRLEN(rt));
        }
        else {
            WOLFSSL_MSG("RANDFILE too large for buffer");
            rt = NULL;
        }
    }
/* // NOLINTEND(concurrency-mt-unsafe) */

    /* $RANDFILE was not set or is too large, check $HOME */
    if (rt == NULL) {
        const char ap[] = "/.rnd";

        WOLFSSL_MSG("Environment variable RANDFILE not set");

/* // NOLINTBEGIN(concurrency-mt-unsafe) */
        if ((rt = XGETENV("HOME")) == NULL) {
            #ifdef XALTHOMEVARNAME
            if ((rt = XGETENV(XALTHOMEVARNAME)) == NULL) {
                WOLFSSL_MSG("Environment variable HOME and " XALTHOMEVARNAME
                            " not set");
                return NULL;
            }
            #else
            WOLFSSL_MSG("Environment variable HOME not set");
            return NULL;
            #endif
        }
/* // NOLINTEND(concurrency-mt-unsafe) */

        if (len > XSTRLEN(rt) + XSTRLEN(ap)) {
            fname[0] = '\0';
            XSTRNCAT(fname, rt, len);
            XSTRNCAT(fname, ap, len - XSTRLEN(rt));
            return fname;
        }
        else {
            WOLFSSL_MSG("Path too large for buffer");
            return NULL;
        }
    }

    return fname;
#else
    WOLFSSL_ENTER("wolfSSL_RAND_file_name");
    WOLFSSL_MSG("RAND_file_name requires filesystem and getenv support, "
                "not compiled in");
    (void)fname;
    (void)len;
    return NULL;
#endif
}


/* Writes 1024 bytes from the RNG to the given file name.
 *
 * fname name of file to write to
 *
 * Returns the number of bytes written
 */
int wolfSSL_RAND_write_file(const char* fname)
{
    int bytes = 0;

    WOLFSSL_ENTER("wolfSSL_RAND_write_file");

    if (fname == NULL) {
        return WOLFSSL_FAILURE;
    }

#ifndef NO_FILESYSTEM
    {
    #ifndef WOLFSSL_SMALL_STACK
        unsigned char buf[1024];
    #else
        unsigned char* buf = (unsigned char *)XMALLOC(1024, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            WOLFSSL_MSG("malloc failed");
            return WOLFSSL_FAILURE;
        }
    #endif
        bytes = 1024; /* default size of buf */

        if (initGlobalRNG == 0 && wolfSSL_RAND_Init() != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("No RNG to use");
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return 0;
        }

        if (wc_RNG_GenerateBlock(&globalRNG, buf, (word32)bytes) != 0) {
            WOLFSSL_MSG("Error generating random buffer");
            bytes = 0;
        }
        else {
            XFILE f;

        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Add("wolfSSL_RAND_write_file buf", buf, bytes);
        #endif

            f = XFOPEN(fname, "wb");
            if (f == XBADFILE) {
                WOLFSSL_MSG("Error opening the file");
                bytes = 0;
            }
            else {
                size_t bytes_written = XFWRITE(buf, 1, (size_t)bytes, f);
                bytes = (int)bytes_written;
                XFCLOSE(f);
            }
        }
        ForceZero(buf, (word32)bytes);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #elif defined(WOLFSSL_CHECK_MEM_ZERO)
        wc_MemZero_Check(buf, sizeof(buf));
    #endif
    }
#endif

    return bytes;
}

#ifndef FREERTOS_TCP

/* These constant values are protocol values made by egd */
#if defined(USE_WOLFSSL_IO) && !defined(USE_WINDOWS_API) && \
    !defined(HAVE_FIPS) && defined(HAVE_HASHDRBG) && !defined(NETOS) && \
    defined(HAVE_SYS_UN_H)
    #define WOLFSSL_EGD_NBLOCK 0x01
    #include <sys/un.h>
#endif

/* This collects entropy from the path nm and seeds the global PRNG with it.
 *
 * nm is the file path to the egd server
 *
 * Returns the number of bytes read.
 */
int wolfSSL_RAND_egd(const char* nm)
{
#ifdef WOLFSSL_EGD_NBLOCK
    struct sockaddr_un rem;
    int fd;
    int ret = WOLFSSL_SUCCESS;
    word32 bytes = 0;
    word32 idx   = 0;
#ifndef WOLFSSL_SMALL_STACK
    unsigned char buf[256];
#else
    unsigned char* buf;
    buf = (unsigned char*)XMALLOC(256, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        WOLFSSL_MSG("Not enough memory");
        return WOLFSSL_FATAL_ERROR;
    }
#endif

    XMEMSET(&rem, 0, sizeof(struct sockaddr_un));
    if (nm == NULL) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return WOLFSSL_FATAL_ERROR;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        WOLFSSL_MSG("Error creating socket");
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return WOLFSSL_FATAL_ERROR;
    }
    rem.sun_family = AF_UNIX;
    XSTRNCPY(rem.sun_path, nm, sizeof(rem.sun_path) - 1);
    rem.sun_path[sizeof(rem.sun_path)-1] = '\0';

    /* connect to egd server */
    if (connect(fd, (struct sockaddr*)&rem, sizeof(struct sockaddr_un)) == -1) {
        WOLFSSL_MSG("error connecting to egd server");
        ret = WOLFSSL_FATAL_ERROR;
    }

#ifdef WOLFSSL_CHECK_MEM_ZERO
    if (ret == WOLFSSL_SUCCESS) {
        wc_MemZero_Add("wolfSSL_RAND_egd buf", buf, 256);
    }
#endif
    while (ret == WOLFSSL_SUCCESS && bytes < 255 && idx + 2 < 256) {
        buf[idx]     = WOLFSSL_EGD_NBLOCK;
        buf[idx + 1] = 255 - bytes; /* request 255 bytes from server */
        ret = (int)write(fd, buf + idx, 2);
        if (ret != 2) {
            if (errno == EAGAIN) {
                ret = WOLFSSL_SUCCESS;
                continue;
            }
            WOLFSSL_MSG("error requesting entropy from egd server");
            ret = WOLFSSL_FATAL_ERROR;
            break;
        }

        /* attempting to read */
        buf[idx] = 0;
        ret = (int)read(fd, buf + idx, 256 - bytes);
        if (ret == 0) {
            WOLFSSL_MSG("error reading entropy from egd server");
            ret = WOLFSSL_FATAL_ERROR;
            break;
        }
        if (ret > 0 && buf[idx] > 0) {
            bytes += buf[idx]; /* egd stores amount sent in first byte */
            if (bytes + idx > 255 || buf[idx] > ret) {
                WOLFSSL_MSG("Buffer error");
                ret = WOLFSSL_FATAL_ERROR;
                break;
            }
            XMEMMOVE(buf + idx, buf + idx + 1, buf[idx]);
            idx = bytes;
            ret = WOLFSSL_SUCCESS;
            if (bytes >= 255) {
                break;
            }
        }
        else {
            if (errno == EAGAIN || errno == EINTR) {
                WOLFSSL_MSG("EGD would read");
                ret = WOLFSSL_SUCCESS; /* try again */
            }
            else if (buf[idx] == 0) {
                /* if egd returned 0 then there is no more entropy to be had.
                   Do not try more reads. */
                ret = WOLFSSL_SUCCESS;
                break;
            }
            else {
                WOLFSSL_MSG("Error with read");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }

    if (bytes > 0 && ret == WOLFSSL_SUCCESS) {
        /* call to check global RNG is created */
        if (wolfSSL_RAND_Init() != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error with initializing global RNG structure");
            ret = WOLFSSL_FATAL_ERROR;
        }
        else if (wc_RNG_DRBG_Reseed(&globalRNG, (const byte*) buf, bytes)
                != 0) {
            WOLFSSL_MSG("Error with reseeding DRBG structure");
            ret = WOLFSSL_FATAL_ERROR;
        }
        #ifdef SHOW_SECRETS
        else { /* print out entropy found only when no error occurred */
            word32 i;
            printf("EGD Entropy = ");
            for (i = 0; i < bytes; i++) {
                printf("%02X", buf[i]);
            }
            printf("\n");
        }
        #endif
    }

    ForceZero(buf, bytes);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(buf, 256);
#endif
    close(fd);

    if (ret == WOLFSSL_SUCCESS) {
        return (int)bytes;
    }
    else {
        return ret;
    }
#else
    WOLFSSL_MSG("Type of socket needed is not available");
    WOLFSSL_MSG("\tor using mode where DRBG API is not available");
    (void)nm;

    return WOLFSSL_FATAL_ERROR;
#endif /* WOLFSSL_EGD_NBLOCK */
}

#endif /* !FREERTOS_TCP */

void wolfSSL_RAND_Cleanup(void)
{
#ifndef WOLFSSL_NO_OPENSSL_RAND_CB
    if (wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex) == 0) {
        if (gRandMethods && gRandMethods->cleanup)
            gRandMethods->cleanup();
        wc_UnLockMutex(&gRandMethodMutex);
    }

    #ifndef WOLFSSL_MUTEX_INITIALIZER
    if (wc_FreeMutex(&gRandMethodMutex) == 0)
        gRandMethodsInit = 0;
    #endif
#endif
#ifdef HAVE_GLOBAL_RNG
    if (wc_LockMutex(&globalRNGMutex) == 0) {
        if (initGlobalRNG) {
            wc_FreeRng(&globalRNG);
            initGlobalRNG = 0;
        }
        wc_UnLockMutex(&globalRNGMutex);
    }
#endif
}

/* returns WOLFSSL_SUCCESS if the bytes generated are valid otherwise
 * WOLFSSL_FAILURE */
int wolfSSL_RAND_pseudo_bytes(unsigned char* buf, int num)
{
    int ret;
    int hash;
    byte secret[DRBG_SEED_LEN]; /* secret length arbitrarily chosen */

#ifndef WOLFSSL_NO_OPENSSL_RAND_CB
    if (wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex) == 0) {
        if (gRandMethods && gRandMethods->pseudorand) {
            ret = gRandMethods->pseudorand(buf, num);
            wc_UnLockMutex(&gRandMethodMutex);
            return ret;
        }
        wc_UnLockMutex(&gRandMethodMutex);
    }
#endif

#ifdef WOLFSSL_HAVE_PRF
    #ifndef NO_SHA256
    hash = WC_SHA256;
    #elif defined(WOLFSSL_SHA384)
    hash = WC_SHA384;
    #elif !defined(NO_SHA)
    hash = WC_SHA;
    #elif !defined(NO_MD5)
    hash = WC_MD5;
    #endif

    /* get secret value from source of entropy */
    ret = wolfSSL_RAND_bytes(secret, DRBG_SEED_LEN);

    /* uses input buffer to seed for pseudo random number generation, each
     * thread will potentially have different results this way */
    if (ret == WOLFSSL_SUCCESS) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_PRF(buf, num, secret, DRBG_SEED_LEN, (const byte*)buf, num,
                hash, NULL, INVALID_DEVID);
        PRIVATE_KEY_LOCK();
        ret = (ret == 0) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
    }
#else
    /* fall back to just doing wolfSSL_RAND_bytes if PRF not avialbale */
    ret = wolfSSL_RAND_bytes(buf, num);
    (void)hash;
    (void)secret;
#endif
    return ret;
}

/* returns WOLFSSL_SUCCESS if the bytes generated are valid otherwise
 * WOLFSSL_FAILURE */
int wolfSSL_RAND_bytes(unsigned char* buf, int num)
{
    int     ret = 0;
    WC_RNG* rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  tmpRNG[1];
#endif
    int initTmpRng = 0;
#ifdef HAVE_GLOBAL_RNG
    int used_global = 0;
#endif

    WOLFSSL_ENTER("wolfSSL_RAND_bytes");
    /* sanity check */
    if (buf == NULL || num < 0)
        /* return code compliant with OpenSSL */
        return 0;

    /* if a RAND callback has been set try and use it */
#ifndef WOLFSSL_NO_OPENSSL_RAND_CB
    if (wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex) == 0) {
        if (gRandMethods && gRandMethods->bytes) {
            ret = gRandMethods->bytes(buf, num);
            wc_UnLockMutex(&gRandMethodMutex);
            return ret;
        }
        wc_UnLockMutex(&gRandMethodMutex);
    }
#endif
#ifdef HAVE_GLOBAL_RNG
    if (initGlobalRNG) {
        if (wc_LockMutex(&globalRNGMutex) != 0) {
            WOLFSSL_MSG("Bad Lock Mutex rng");
            return ret;
        }
        /* the above access to initGlobalRNG is racey -- recheck it now that we
         * have the lock.
         */
        if (initGlobalRNG) {
            rng = &globalRNG;
            used_global = 1;
        }
        else {
            wc_UnLockMutex(&globalRNGMutex);
        }
    }

    if (used_global == 0)
#endif
    {
    #ifdef WOLFSSL_SMALL_STACK
        tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (tmpRNG == NULL)
            return ret;
    #endif
        if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
        }
    }
    if (rng) {
        /* handles size greater than RNG_MAX_BLOCK_LEN */
        int blockCount = num / RNG_MAX_BLOCK_LEN;

        while (blockCount--) {
            ret = wc_RNG_GenerateBlock(rng, buf, RNG_MAX_BLOCK_LEN);
            if (ret != 0) {
                WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
                break;
            }
            num -= RNG_MAX_BLOCK_LEN;
            buf += RNG_MAX_BLOCK_LEN;
        }

        if (ret == 0 && num)
            ret = wc_RNG_GenerateBlock(rng, buf, (word32)num);

        if (ret != 0)
            WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        else
            ret = WOLFSSL_SUCCESS;
    }

#ifdef HAVE_GLOBAL_RNG
    if (used_global == 1)
        wc_UnLockMutex(&globalRNGMutex);
#endif
    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}


int wolfSSL_RAND_poll(void)
{
    byte  entropy[16];
    int  ret = 0;
    word32 entropy_sz = 16;

    WOLFSSL_ENTER("wolfSSL_RAND_poll");
    if (initGlobalRNG == 0){
        WOLFSSL_MSG("Global RNG no Init");
        return  WOLFSSL_FAILURE;
    }
    ret = wc_GenerateSeed(&globalRNG.seed, entropy, entropy_sz);
    if (ret != 0){
        WOLFSSL_MSG("Bad wc_RNG_GenerateBlock");
        ret = WOLFSSL_FAILURE;
    }else
        ret = WOLFSSL_SUCCESS;

    return ret;
}

    /* If a valid struct is provided with function pointers, will override
       RAND_seed, bytes, cleanup, add, pseudo_bytes and status.  If a NULL
       pointer is passed in, it will cancel any previous function overrides.

       Returns WOLFSSL_SUCCESS on success, WOLFSSL_FAILURE on failure. */
    int wolfSSL_RAND_set_rand_method(const WOLFSSL_RAND_METHOD *methods)
    {
    #ifndef WOLFSSL_NO_OPENSSL_RAND_CB
        if (wolfSSL_RAND_InitMutex() == 0 &&
                wc_LockMutex(&gRandMethodMutex) == 0) {
            gRandMethods = methods;
            wc_UnLockMutex(&gRandMethodMutex);
            return WOLFSSL_SUCCESS;
        }
    #else
        (void)methods;
    #endif
        return WOLFSSL_FAILURE;
    }

    /* Returns WOLFSSL_SUCCESS if the RNG has been seeded with enough data */
    int wolfSSL_RAND_status(void)
    {
        int ret = WOLFSSL_SUCCESS;
    #ifndef WOLFSSL_NO_OPENSSL_RAND_CB
        if (wolfSSL_RAND_InitMutex() == 0 &&
                wc_LockMutex(&gRandMethodMutex) == 0) {
            if (gRandMethods && gRandMethods->status)
                ret = gRandMethods->status();
            wc_UnLockMutex(&gRandMethodMutex);
        }
        else {
            ret = WOLFSSL_FAILURE;
        }
    #else
        /* wolfCrypt provides enough seed internally, so return success */
    #endif
        return ret;
    }

    void wolfSSL_RAND_add(const void* add, int len, double entropy)
    {
    #ifndef WOLFSSL_NO_OPENSSL_RAND_CB
        if (wolfSSL_RAND_InitMutex() == 0 &&
                wc_LockMutex(&gRandMethodMutex) == 0) {
            if (gRandMethods && gRandMethods->add) {
                /* callback has return code, but RAND_add does not */
                (void)gRandMethods->add(add, len, entropy);
            }
            wc_UnLockMutex(&gRandMethodMutex);
        }
    #else
        /* wolfSSL seeds/adds internally, use explicit RNG if you want
           to take control */
        (void)add;
        (void)len;
        (void)entropy;
    #endif
    }


#ifndef NO_WOLFSSL_STUB
void wolfSSL_RAND_screen(void)
{
    WOLFSSL_STUB("RAND_screen");
}
#endif

int wolfSSL_RAND_load_file(const char* fname, long len)
{
    (void)fname;
    /* wolfCrypt provides enough entropy internally or will report error */
    if (len == -1)
        return 1024;
    else
        return (int)len;
}

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF RAND API
 ******************************************************************************/

/*******************************************************************************
 * START OF EVP_CIPHER API
 ******************************************************************************/

#ifdef OPENSSL_EXTRA

    /* store for external read of iv, WOLFSSL_SUCCESS on success */
    int  wolfSSL_StoreExternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_StoreExternalIV");

        if (ctx == NULL) {
            WOLFSSL_MSG("Bad function argument");
            return WOLFSSL_FATAL_ERROR;
        }

        switch (ctx->cipherType) {
#ifndef NO_AES
#if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
            case WC_AES_128_CBC_TYPE :
            case WC_AES_192_CBC_TYPE :
            case WC_AES_256_CBC_TYPE :
                WOLFSSL_MSG("AES CBC");
                XMEMCPY(ctx->iv, &ctx->cipher.aes.reg, ctx->ivSz);
                break;
#endif
#ifdef HAVE_AESGCM
            case WC_AES_128_GCM_TYPE :
            case WC_AES_192_GCM_TYPE :
            case WC_AES_256_GCM_TYPE :
                WOLFSSL_MSG("AES GCM");
                XMEMCPY(ctx->iv, &ctx->cipher.aes.reg, ctx->ivSz);
                break;
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
            case WC_AES_128_CCM_TYPE :
            case WC_AES_192_CCM_TYPE :
            case WC_AES_256_CCM_TYPE :
                WOLFSSL_MSG("AES CCM");
                XMEMCPY(ctx->iv, &ctx->cipher.aes.reg, ctx->ivSz);
                break;
#endif /* HAVE_AESCCM */
#ifdef HAVE_AES_ECB
            case WC_AES_128_ECB_TYPE :
            case WC_AES_192_ECB_TYPE :
            case WC_AES_256_ECB_TYPE :
                WOLFSSL_MSG("AES ECB");
                break;
#endif
#ifdef WOLFSSL_AES_COUNTER
            case WC_AES_128_CTR_TYPE :
            case WC_AES_192_CTR_TYPE :
            case WC_AES_256_CTR_TYPE :
                WOLFSSL_MSG("AES CTR");
                XMEMCPY(ctx->iv, &ctx->cipher.aes.reg, WC_AES_BLOCK_SIZE);
                break;
#endif /* WOLFSSL_AES_COUNTER */
#ifdef WOLFSSL_AES_CFB
#if !defined(HAVE_SELFTEST) && !defined(HAVE_FIPS)
            case WC_AES_128_CFB1_TYPE:
            case WC_AES_192_CFB1_TYPE:
            case WC_AES_256_CFB1_TYPE:
                WOLFSSL_MSG("AES CFB1");
                break;
            case WC_AES_128_CFB8_TYPE:
            case WC_AES_192_CFB8_TYPE:
            case WC_AES_256_CFB8_TYPE:
                WOLFSSL_MSG("AES CFB8");
                break;
#endif /* !HAVE_SELFTEST && !HAVE_FIPS */
            case WC_AES_128_CFB128_TYPE:
            case WC_AES_192_CFB128_TYPE:
            case WC_AES_256_CFB128_TYPE:
                WOLFSSL_MSG("AES CFB128");
                break;
#endif /* WOLFSSL_AES_CFB */
#if defined(WOLFSSL_AES_OFB)
            case WC_AES_128_OFB_TYPE:
            case WC_AES_192_OFB_TYPE:
            case WC_AES_256_OFB_TYPE:
                WOLFSSL_MSG("AES OFB");
                break;
#endif /* WOLFSSL_AES_OFB */
#ifdef WOLFSSL_AES_XTS
            case WC_AES_128_XTS_TYPE:
            case WC_AES_256_XTS_TYPE:
                WOLFSSL_MSG("AES XTS");
                break;
#endif /* WOLFSSL_AES_XTS */
#endif /* NO_AES */

#ifdef HAVE_ARIA
            case WC_ARIA_128_GCM_TYPE :
            case WC_ARIA_192_GCM_TYPE :
            case WC_ARIA_256_GCM_TYPE :
                WOLFSSL_MSG("ARIA GCM");
                XMEMCPY(ctx->iv, &ctx->cipher.aria.nonce, ARIA_BLOCK_SIZE);
                break;
#endif /* HAVE_ARIA */

#ifndef NO_DES3
            case WC_DES_CBC_TYPE :
                WOLFSSL_MSG("DES CBC");
                XMEMCPY(ctx->iv, &ctx->cipher.des.reg, DES_BLOCK_SIZE);
                break;

            case WC_DES_EDE3_CBC_TYPE :
                WOLFSSL_MSG("DES EDE3 CBC");
                XMEMCPY(ctx->iv, &ctx->cipher.des3.reg, DES_BLOCK_SIZE);
                break;
#endif
#ifdef WOLFSSL_DES_ECB
            case WC_DES_ECB_TYPE :
                WOLFSSL_MSG("DES ECB");
                break;
            case WC_DES_EDE3_ECB_TYPE :
                WOLFSSL_MSG("DES3 ECB");
                break;
#endif
            case WC_ARC4_TYPE :
                WOLFSSL_MSG("ARC4");
                break;

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WC_CHACHA20_POLY1305_TYPE:
                break;
#endif

#ifdef HAVE_CHACHA
            case WC_CHACHA20_TYPE:
                break;
#endif

#ifdef WOLFSSL_SM4_ECB
            case WC_SM4_ECB_TYPE:
                break;
#endif
#ifdef WOLFSSL_SM4_CBC
            case WC_SM4_CBC_TYPE:
                WOLFSSL_MSG("SM4 CBC");
                XMEMCPY(&ctx->cipher.sm4.iv, ctx->iv, SM4_BLOCK_SIZE);
                break;
#endif
#ifdef WOLFSSL_SM4_CTR
            case WC_SM4_CTR_TYPE:
                WOLFSSL_MSG("SM4 CTR");
                XMEMCPY(&ctx->cipher.sm4.iv, ctx->iv, SM4_BLOCK_SIZE);
                break;
#endif
#ifdef WOLFSSL_SM4_GCM
            case WC_SM4_GCM_TYPE:
                WOLFSSL_MSG("SM4 GCM");
                XMEMCPY(&ctx->cipher.sm4.iv, ctx->iv, SM4_BLOCK_SIZE);
                break;
#endif
#ifdef WOLFSSL_SM4_CCM
            case WC_SM4_CCM_TYPE:
                WOLFSSL_MSG("SM4 CCM");
                XMEMCPY(&ctx->cipher.sm4.iv, ctx->iv, SM4_BLOCK_SIZE);
                break;
#endif

            case WC_NULL_CIPHER_TYPE :
                WOLFSSL_MSG("NULL");
                break;

            default: {
                WOLFSSL_MSG("bad type");
                return WOLFSSL_FATAL_ERROR;
            }
        }
        return WOLFSSL_SUCCESS;
    }

    /* set internal IV from external, WOLFSSL_SUCCESS on success */
    int  wolfSSL_SetInternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx)
    {

        WOLFSSL_ENTER("wolfSSL_SetInternalIV");

        if (ctx == NULL) {
            WOLFSSL_MSG("Bad function argument");
            return WOLFSSL_FATAL_ERROR;
        }

        switch (ctx->cipherType) {

#ifndef NO_AES
#if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
            case WC_AES_128_CBC_TYPE :
            case WC_AES_192_CBC_TYPE :
            case WC_AES_256_CBC_TYPE :
                WOLFSSL_MSG("AES CBC");
                XMEMCPY(&ctx->cipher.aes.reg, ctx->iv, WC_AES_BLOCK_SIZE);
                break;
#endif
#ifdef HAVE_AESGCM
            case WC_AES_128_GCM_TYPE :
            case WC_AES_192_GCM_TYPE :
            case WC_AES_256_GCM_TYPE :
                WOLFSSL_MSG("AES GCM");
                XMEMCPY(&ctx->cipher.aes.reg, ctx->iv, WC_AES_BLOCK_SIZE);
                break;
#endif
#ifdef HAVE_AES_ECB
            case WC_AES_128_ECB_TYPE :
            case WC_AES_192_ECB_TYPE :
            case WC_AES_256_ECB_TYPE :
                WOLFSSL_MSG("AES ECB");
                break;
#endif
#ifdef WOLFSSL_AES_COUNTER
            case WC_AES_128_CTR_TYPE :
            case WC_AES_192_CTR_TYPE :
            case WC_AES_256_CTR_TYPE :
                WOLFSSL_MSG("AES CTR");
                XMEMCPY(&ctx->cipher.aes.reg, ctx->iv, WC_AES_BLOCK_SIZE);
                break;
#endif

#endif /* NO_AES */

#ifdef HAVE_ARIA
            case WC_ARIA_128_GCM_TYPE :
            case WC_ARIA_192_GCM_TYPE :
            case WC_ARIA_256_GCM_TYPE :
                WOLFSSL_MSG("ARIA GCM");
                XMEMCPY(&ctx->cipher.aria.nonce, ctx->iv, ARIA_BLOCK_SIZE);
                break;
#endif /* HAVE_ARIA */

#ifndef NO_DES3
            case WC_DES_CBC_TYPE :
                WOLFSSL_MSG("DES CBC");
                XMEMCPY(&ctx->cipher.des.reg, ctx->iv, DES_BLOCK_SIZE);
                break;

            case WC_DES_EDE3_CBC_TYPE :
                WOLFSSL_MSG("DES EDE3 CBC");
                XMEMCPY(&ctx->cipher.des3.reg, ctx->iv, DES_BLOCK_SIZE);
                break;
#endif
#ifdef WOLFSSL_DES_ECB
            case WC_DES_ECB_TYPE :
                WOLFSSL_MSG("DES ECB");
                break;
            case WC_DES_EDE3_ECB_TYPE :
                WOLFSSL_MSG("DES3 ECB");
                break;
#endif

            case WC_ARC4_TYPE :
                WOLFSSL_MSG("ARC4");
                break;

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
            case WC_CHACHA20_POLY1305_TYPE:
                break;
#endif

#ifdef HAVE_CHACHA
            case WC_CHACHA20_TYPE:
                break;
#endif

#ifdef WOLFSSL_SM4_ECB
            case WC_SM4_ECB_TYPE:
                break;
#endif
#ifdef WOLFSSL_SM4_CBC
            case WC_SM4_CBC_TYPE:
                WOLFSSL_MSG("SM4 CBC");
                XMEMCPY(ctx->iv, &ctx->cipher.sm4.iv, ctx->ivSz);
                break;
#endif
#ifdef WOLFSSL_SM4_CTR
            case WC_SM4_CTR_TYPE:
                WOLFSSL_MSG("SM4 CTR");
                XMEMCPY(ctx->iv, &ctx->cipher.sm4.iv, ctx->ivSz);
                break;
#endif
#ifdef WOLFSSL_SM4_GCM
            case WC_SM4_GCM_TYPE:
                WOLFSSL_MSG("SM4 GCM");
                XMEMCPY(ctx->iv, &ctx->cipher.sm4.iv, ctx->ivSz);
                break;
#endif
#ifdef WOLFSSL_SM4_CCM
            case WC_SM4_CCM_TYPE:
                WOLFSSL_MSG("SM4 CCM");
                XMEMCPY(ctx->iv, &ctx->cipher.sm4.iv, ctx->ivSz);
                break;
#endif

            case WC_NULL_CIPHER_TYPE :
                WOLFSSL_MSG("NULL");
                break;

            default: {
                WOLFSSL_MSG("bad type");
                return WOLFSSL_FATAL_ERROR;
            }
        }
        return WOLFSSL_SUCCESS;
    }

#ifndef NO_DES3

void wolfSSL_3des_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                            unsigned char* iv, int len)
{
    (void)len;

    WOLFSSL_MSG("wolfSSL_3des_iv");

    if (ctx == NULL || iv == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return;
    }

    if (doset)
        wc_Des3_SetIV(&ctx->cipher.des3, iv);  /* OpenSSL compat, no ret */
    else
        XMEMCPY(iv, &ctx->cipher.des3.reg, DES_BLOCK_SIZE);
}

#endif /* NO_DES3 */


#ifndef NO_AES

void wolfSSL_aes_ctr_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                      unsigned char* iv, int len)
{
    (void)len;

    WOLFSSL_MSG("wolfSSL_aes_ctr_iv");

    if (ctx == NULL || iv == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return;
    }

    if (doset)
       (void)wc_AesSetIV(&ctx->cipher.aes, iv);  /* OpenSSL compat, no ret */
    else
        XMEMCPY(iv, &ctx->cipher.aes.reg, WC_AES_BLOCK_SIZE);
}

#endif /* NO_AES */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF EVP_CIPHER API
 ******************************************************************************/

#ifndef NO_CERTS

#define WOLFSSL_X509_STORE_INCLUDED
#include <src/x509_str.c>

#define WOLFSSL_SSL_P7P12_INCLUDED
#include <src/ssl_p7p12.c>

#endif /* !NO_CERTS */


/*******************************************************************************
 * BEGIN OPENSSL FIPS DRBG APIs
 ******************************************************************************/
#if defined(OPENSSL_EXTRA) && !defined(WC_NO_RNG) && defined(HAVE_HASHDRBG)
int wolfSSL_FIPS_drbg_init(WOLFSSL_DRBG_CTX *ctx, int type, unsigned int flags)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(WOLFSSL_DRBG_CTX));
        ctx->type = type;
        ctx->xflags = (int)flags;
        ctx->status = DRBG_STATUS_UNINITIALISED;
        ret = WOLFSSL_SUCCESS;
    }
    return ret;
}
WOLFSSL_DRBG_CTX* wolfSSL_FIPS_drbg_new(int type, unsigned int flags)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_DRBG_CTX* ctx = (WOLFSSL_DRBG_CTX*)XMALLOC(sizeof(WOLFSSL_DRBG_CTX),
        NULL, DYNAMIC_TYPE_OPENSSL);
    ret = wolfSSL_FIPS_drbg_init(ctx, type, flags);
    if (ret == WOLFSSL_SUCCESS && type != 0) {
        ret = wolfSSL_FIPS_drbg_instantiate(ctx, NULL, 0);
    }
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_ERROR(ret);
        wolfSSL_FIPS_drbg_free(ctx);
        ctx = NULL;
    }
    return ctx;
}
int wolfSSL_FIPS_drbg_instantiate(WOLFSSL_DRBG_CTX* ctx,
    const unsigned char* pers, size_t perslen)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL && ctx->rng == NULL) {
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS) && FIPS_VERSION_GE(5,0)))
        ctx->rng = wc_rng_new((byte*)pers, (word32)perslen, NULL);
    #else
        ctx->rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (ctx->rng != NULL) {
        #if defined(HAVE_FIPS) && FIPS_VERSION_GE(2,0)
            ret = wc_InitRngNonce(ctx->rng, (byte*)pers, (word32)perslen);
        #else
            ret = wc_InitRng(ctx->rng);
            (void)pers;
            (void)perslen;
        #endif
            if (ret != 0) {
                WOLFSSL_ERROR(ret);
                XFREE(ctx->rng, NULL, DYNAMIC_TYPE_RNG);
                ctx->rng = NULL;
            }
        }
    #endif
    }
    if (ctx != NULL && ctx->rng != NULL) {
        ctx->status = DRBG_STATUS_READY;
        ret = WOLFSSL_SUCCESS;
    }
    return ret;
}
int wolfSSL_FIPS_drbg_set_callbacks(WOLFSSL_DRBG_CTX* ctx,
    drbg_entropy_get entropy_get, drbg_entropy_clean entropy_clean,
    size_t entropy_blocklen,
    drbg_nonce_get none_get, drbg_nonce_clean nonce_clean)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL) {
        ctx->entropy_get = entropy_get;
        ctx->entropy_clean = entropy_clean;
        ctx->entropy_blocklen = entropy_blocklen;
        ctx->none_get = none_get;
        ctx->nonce_clean = nonce_clean;
        ret = WOLFSSL_SUCCESS;
    }
    return ret;
}
void wolfSSL_FIPS_rand_add(const void* buf, int num, double entropy)
{
    /* not implemented */
    (void)buf;
    (void)num;
    (void)entropy;
}
int wolfSSL_FIPS_drbg_reseed(WOLFSSL_DRBG_CTX* ctx, const unsigned char* adin,
    size_t adinlen)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL && ctx->rng != NULL) {
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS) && FIPS_VERSION_GE(2,0)))
        if (wc_RNG_DRBG_Reseed(ctx->rng, adin, (word32)adinlen) == 0) {
            ret = WOLFSSL_SUCCESS;
        }
    #else
        ret = WOLFSSL_SUCCESS;
        (void)adin;
        (void)adinlen;
    #endif
    }
    return ret;
}
int wolfSSL_FIPS_drbg_generate(WOLFSSL_DRBG_CTX* ctx, unsigned char* out,
    size_t outlen, int prediction_resistance, const unsigned char* adin,
    size_t adinlen)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL && ctx->rng != NULL) {
        ret = wc_RNG_GenerateBlock(ctx->rng, out, (word32)outlen);
        if (ret == 0) {
            ret = WOLFSSL_SUCCESS;
        }
    }
    (void)prediction_resistance;
    (void)adin;
    (void)adinlen;
    return ret;
}
int wolfSSL_FIPS_drbg_uninstantiate(WOLFSSL_DRBG_CTX *ctx)
{
    if (ctx != NULL && ctx->rng != NULL) {
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS) && FIPS_VERSION_GE(5,0)))
        wc_rng_free(ctx->rng);
    #else
        wc_FreeRng(ctx->rng);
        XFREE(ctx->rng, NULL, DYNAMIC_TYPE_RNG);
    #endif
        ctx->rng = NULL;
        ctx->status = DRBG_STATUS_UNINITIALISED;
    }
    return WOLFSSL_SUCCESS;
}
void wolfSSL_FIPS_drbg_free(WOLFSSL_DRBG_CTX *ctx)
{
    if (ctx != NULL) {
        /* As safety check if free'ing the default drbg, then mark global NULL.
         * Technically the user should not call free on the default drbg. */
        if (ctx == gDrbgDefCtx) {
            gDrbgDefCtx = NULL;
        }
        wolfSSL_FIPS_drbg_uninstantiate(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}
WOLFSSL_DRBG_CTX* wolfSSL_FIPS_get_default_drbg(void)
{
    if (gDrbgDefCtx == NULL) {
        gDrbgDefCtx = wolfSSL_FIPS_drbg_new(0, 0);
    }
    return gDrbgDefCtx;
}
void wolfSSL_FIPS_get_timevec(unsigned char* buf, unsigned long* pctr)
{
    /* not implemented */
    (void)buf;
    (void)pctr;
}
void* wolfSSL_FIPS_drbg_get_app_data(WOLFSSL_DRBG_CTX *ctx)
{
    if (ctx != NULL) {
        return ctx->app_data;
    }
    return NULL;
}
void wolfSSL_FIPS_drbg_set_app_data(WOLFSSL_DRBG_CTX *ctx, void *app_data)
{
    if (ctx != NULL) {
        ctx->app_data = app_data;
    }
}
#endif
/*******************************************************************************
 * END OF OPENSSL FIPS DRBG APIs
 ******************************************************************************/


#endif /* !WOLFCRYPT_ONLY */

