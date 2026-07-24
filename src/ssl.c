/* ssl.c
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

#if defined(OPENSSL_EXTRA) && !defined(_WIN32) && !defined(_GNU_SOURCE)
    /* turn on GNU extensions for XISASCII */
    #define _GNU_SOURCE 1
#endif

#if !defined(WOLFCRYPT_ONLY) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
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
    #if defined(WOLFSSL_HAVE_MLDSA)
        #include <wolfssl/wolfcrypt/wc_mldsa.h>
    #endif /* WOLFSSL_HAVE_MLDSA */
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

#if !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_SYS_CRYPTO_POLICY)
/* The system wide crypto-policy. Configured by wolfSSL_crypto_policy_enable.
 * */
static struct SystemCryptoPolicy crypto_policy;
#endif /* !WOLFCRYPT_ONLY && WOLFSSL_SYS_CRYPTO_POLICY */

/*
 * ssl.c Build Options:
 *
 * See also: tls.c for TLS extension/protocol options, tls13.c for TLS 1.3,
 *           internal.c for handshake internals, wc_port.c for platform/memory.
 *
 * OpenSSL Compatibility:
 * OPENSSL_EXTRA:              Enable OpenSSL compatibility API        default: off
 * OPENSSL_ALL:                Enable all OpenSSL compat APIs          default: off
 * OPENSSL_EXTRA_X509_SMALL:   Minimal OpenSSL X509 compat APIs       default: off
 * OPENSSL_EXTRA_NO_ASN1:      OpenSSL extra without ASN1 objects      default: off
 * OPENSSL_COMPATIBLE_DEFAULTS:
 *                  Default behavior compatible with OpenSSL           default: off
 * NO_WOLFSSL_STUB:            Disable stubs for unimplemented funcs   default: off
 * WOLFSSL_DEBUG_OPENSSL:      Debug logging for OpenSSL compat layer  default: off
 * WOLFSSL_HAVE_ERROR_QUEUE:   OpenSSL-compatible error queue          default: off
 * WOLFSSL_ERROR_CODE_OPENSSL: Use OpenSSL-compatible error codes      default: off
 * WOLFSSL_CIPHER_INTERNALNAME:
 *                  Use wolfSSL internal cipher suite names             default: off
 * NO_CIPHER_SUITE_ALIASES:    Disable cipher suite name aliases       default: off
 * WOLFSSL_SET_CIPHER_BYTES:   Set cipher suites by raw byte values    default: off
 * WOLFSSL_OLD_SET_CURVES_LIST:
 *                  Old-style curve list parsing for compat             default: off
 * WOLFSSL_NO_OPENSSL_RAND_CB: Disable OpenSSL RAND callback compat   default: off
 * NO_ERROR_STRINGS:           Disable human-readable error strings    default: off
 * WOLFSSL_PUBLIC_ASN:         Make ASN parsing functions public        default: off
 *
 * Extra Data / BIO:
 * HAVE_EX_DATA:               Enable ex_data on SSL/CTX/X509 objects  default: off
 * HAVE_EX_DATA_CLEANUP_HOOKS: Cleanup callbacks for ex_data           default: off
 * HAVE_EX_DATA_CRYPTO:        ex_data support for wolfCrypt objects   default: off
 * MAX_EX_DATA:                Max ex_data entries per object           default: 5
 * NO_BIO:                     Disable BIO abstraction layer           default: off
 *
 * Session & Cache:
 * NO_SESSION_CACHE:           Disable server session cache            default: off
 * NO_SESSION_CACHE_REF:       wolfSSL_get_session returns ssl->session
 *                             reference instead of ClientCache ref    default: off
 * SESSION_CACHE_DYNAMIC_MEM:  Dynamically allocate session cache      default: off
 * NO_CLIENT_CACHE:            Disable client-side session cache       default: off
 * SESSION_CERTS:              Store full cert chain in session         default: off
 * WOLFSSL_SESSION_ID_CTX:     Session ID context for cache sharing    default: off
 *
 * I/O & Transport:
 * USE_WOLFSSL_IO:             Use built-in I/O callbacks              default: on
 * WOLFSSL_USER_IO:            Application provides custom I/O         default: off
 * WOLFSSL_NO_SOCK:            Build without socket support            default: off
 * NO_WRITEV:                  Disable writev() scatter/gather I/O     default: off
 * WOLFSSL_DTLS_MTU:           Enable DTLS MTU management APIs         default: off
 * WOLFSSL_DTLS_DROP_STATS:    Track DTLS packet drop statistics       default: off
 * WOLFSSL_MULTICAST:          Enable DTLS multicast support           default: off
 *
 * Callbacks & Features:
 * WOLFSSL_CHECK_ALERT_ON_ERR: Check alerts on handshake error         default: off
 * ATOMIC_USER:                User-defined record layer callbacks      default: off
 * HAVE_WRITE_DUP:             Separate threads for SSL read/write     default: off
 * WOLFSSL_CALLBACKS:          Handshake monitoring callbacks           default: off
 * NO_HANDSHAKE_DONE_CB:       Disable handshake completion callback   default: off
 * WOLFSSL_SHUTDOWNONCE:       Send close_notify only once             default: off
 * WOLFSSL_COPY_CERT:          Copy certificate buffer (own copy)      default: off
 * WOLFSSL_COPY_KEY:           Copy private key buffer (own copy)      default: off
 * WOLF_PRIVATE_KEY_ID:        Reference private keys by ID            default: off
 * WOLFSSL_REFCNT_ERROR_RETURN:
 *                  Return errors on ref counting failures             default: off
 * WOLFSSL_ALLOW_MAX_FRAGMENT_ADJUST:
 *                  Allow runtime max fragment size adjustment          default: off
 * WOLFSSL_ALLOW_NO_SUITES:    Allow SSL objects with no cipher suites default: off
 *
 * Certificates & Keys:
 * KEEP_PEER_CERT:             Keep peer cert after handshake          default: off
 * KEEP_OUR_CERT:              Keep our cert after handshake           default: off
 * WOLFSSL_STATIC_RSA:         Enable static RSA key exchange          default: off
 * WOLFSSL_HAVE_CERT_SERVICE:  Certificate service callbacks           default: off
 * WOLFSSL_SYS_CA_CERTS:       Load system CA certs from OS            default: off
 *
 * Application Compatibility:
 * HAVE_CURL:                  APIs for libcurl compatibility          default: off
 * HAVE_LIGHTY:                APIs for lighttpd compatibility         default: off
 * HAVE_MEMCACHED:             APIs for memcached compatibility        default: off
 * WOLFSSL_APACHE_HTTPD:       APIs for Apache httpd compatibility     default: off
 * WOLFSSL_NGINX:              APIs for nginx compatibility            default: off
 * WOLFSSL_HAPROXY:            APIs for HAProxy compatibility          default: off
 * WOLFSSL_ASIO:               APIs for Boost.Asio compatibility       default: off
 * WOLFSSL_PYTHON:             APIs for Python module compatibility    default: off
 * WOLFSSL_QT:                 APIs for Qt framework compatibility     default: off
 * WOLFSSL_JNI:                APIs for Java JNI/JSSE compatibility    default: off
 *
 * Protocol Features:
 * WOLFSSL_HAVE_WOLFSCEP:      Enable wolfSCEP protocol support        default: off
 * WOLFCRYPT_HAVE_SRP:         Enable SRP protocol support             default: off
 * HAVE_LIBZ:                  Enable zlib TLS compression             default: off
 * WOLFSSL_EXTRA:              Extra SSL session info APIs              default: off
 * WOLFSSL_WPAS_SMALL:         Minimal wpa_supplicant/hostapd APIs     default: off
 * HAVE_FUZZER:                Fuzzing callback support                 default: off
 *
 * Memory & Threading:
 * WOLFSSL_STATIC_MEMORY_LEAN: Lean static memory allocation           default: off
 * WOLFSSL_THREADED_CRYPT:     Multi-threaded crypto operations         default: off
 * WOLFSSL_CLEANUP_THREADSAFE_BY_ATOMIC_OPS:
 *                  Thread-safe cleanup via atomics                     default: off
 * WOLFSSL_ATOMIC_INITIALIZER: Static init for atomic variables        default: off
 * WOLFSSL_DEBUG_MEMORY:       Log malloc/free with file/line info     default: off
 * WOLFSSL_NO_REALLOC:         Disable realloc, use malloc+copy+free   default: off
 * WOLFSSL_HEAP_TEST:          Heap-related testing utilities           default: off
 *
 * Debugging & Build:
 * SHOW_SIZES:                 Display struct sizes at init             default: off
 * WOLFSSL_DEBUG_TRACE_ERROR_CODES:
 *                  Trace error code origins for debugging              default: off
 * HAVE_ATEXIT:                Register wolfSSL_Cleanup via atexit     default: off
 * WOLFSSL_SYS_CRYPTO_POLICY:  Honor system crypto policy settings     default: off
 *
 * Hardware TLS:
 * WOLFSSL_RENESAS_TSIP_TLS:   Renesas TSIP hardware crypto for TLS   default: off
 * WOLFSSL_RENESAS_FSPSM_TLS:  Renesas FSP Security Module for TLS    default: off
 * WOLFSSL_EGD_NBLOCK:         Non-blocking EGD entropy support        default: off
 */

#ifndef WOLFCRYPT_ONLY

#if !defined(NO_RSA) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && !defined(NO_DSA))

#define HAVE_GLOBAL_RNG /* consolidate flags for using globalRNG */
static WC_RNG globalRNG;
static volatile int initGlobalRNG = 0;

#if defined(OPENSSL_EXTRA) || !defined(WOLFSSL_MUTEX_INITIALIZER)
static WC_MAYBE_UNUSED wolfSSL_Mutex globalRNGMutex
    WOLFSSL_MUTEX_INITIALIZER_CLAUSE(globalRNGMutex);
#endif
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
#ifdef WOLFSSL_SMALL_STACK
    int freeRng = 0;

    /* Allocate RNG object . */
    if (rng == NULL) {
        rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        freeRng = 1;
    }
#endif

    if (rng != NULL) {
        if (wc_InitRng(rng) == 0) {
            ret = rng;
            *local = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init");
#ifdef WOLFSSL_SMALL_STACK
            if (freeRng) {
                XFREE(rng, NULL, DYNAMIC_TYPE_RNG);
                rng = NULL;
            }
#endif
        }
    }
    if (ret == NULL) {
#ifdef HAVE_GLOBAL_RNG
        WOLFSSL_MSG("trying global RNG");
#endif
        ret = wolfssl_make_global_rng();
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

#endif /* !WOLFCRYPT_ONLY */

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

#define WOLFSSL_SSL_API_CERT_INCLUDED
#include "src/ssl_api_cert.c"

#define WOLFSSL_SSL_API_PK_INCLUDED
#include "src/ssl_api_pk.c"
#endif


#ifndef WOLFCRYPT_ONLY



#define WOLFSSL_SSL_BN_INCLUDED
#include "src/ssl_bn.c"

#define WOLFSSL_SSL_ASN1_INCLUDED
#include "src/ssl_asn1.c"

#define WOLFSSL_SSL_TSP_INCLUDED
#include "src/ssl_tsp.c"

#define WOLFSSL_PK_INCLUDED
#include "src/pk.c"

#define WOLFSSL_EVP_PK_INCLUDED
#include "wolfcrypt/src/evp_pk.c"

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* copies over data of "in" to "out" */
static void wolfSSL_CIPHER_copy(WOLFSSL_CIPHER* in, WOLFSSL_CIPHER* out)
{
    if (in == NULL || out == NULL)
        return;

    *out = *in;
}


#if defined(OPENSSL_ALL)
static WOLFSSL_X509_OBJECT* wolfSSL_X509_OBJECT_dup(WOLFSSL_X509_OBJECT* obj)
{
    WOLFSSL_X509_OBJECT* ret = NULL;
    if (obj) {
        ret = wolfSSL_X509_OBJECT_new();
        if (ret) {
            ret->type = obj->type;
            switch (ret->type) {
                case WOLFSSL_X509_LU_NONE:
                    break;
                case WOLFSSL_X509_LU_X509:
                    ret->data.x509 = wolfSSL_X509_dup(obj->data.x509);
                    break;
                case WOLFSSL_X509_LU_CRL:
            #if defined(HAVE_CRL)
                    ret->data.crl = wolfSSL_X509_CRL_dup(obj->data.crl);
            #endif
                    break;
            }
        }
    }
    return ret;
}
#endif /* OPENSSL_ALL */

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#define WOLFSSL_SSL_SK_INCLUDED
#include "src/ssl_sk.c"


#include <wolfssl/wolfcrypt/hpke.h>

#define WOLFSSL_SSL_ECH_INCLUDED
#include "src/ssl_ech.c"

#ifdef OPENSSL_EXTRA
static int wolfSSL_parse_cipher_list(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
        Suites* suites, const char* list);
#endif

#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

/* prevent multiple mutex initializations */

/* note, initRefCount is not used for thread synchronization, only for
 * bookkeeping while inits_count_mutex is held.
 */
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
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        wolfSSL_CTX_set_mode(ctx, WOLFSSL_MODE_AUTO_RETRY);
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
#ifdef WOLFSSL_DTLS13
        struct Dtls13RecordNumber* rn = ssl->dupWrite->sendAckList;
        while (rn != NULL) {
            struct Dtls13RecordNumber* next = rn->next;
            XFREE(rn, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
            rn = next;
        }
#endif
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        Free_HS_Hashes(ssl->dupWrite->postHandshakeHashState, ssl->heap);
        Free_HS_Hashes(ssl->dupWrite->postHandshakeSyncedHashState, ssl->heap);
        {
            CertReqCtx* ctx = ssl->dupWrite->postHandshakeCertReqCtx;
            while (ctx != NULL) {
                CertReqCtx* nxt = ctx->next;
                XFREE(ctx, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
                ctx = nxt;
            }
        }
#endif /* WOLFSSL_TLS13 && WOLFSSL_POST_HANDSHAKE_AUTH */
        wc_FreeMutex(&ssl->dupWrite->dupMutex);
        XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
        ssl->dupWrite = NULL;
        WOLFSSL_MSG("Did WriteDup full free, count to zero");
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
#ifdef HAVE_ONE_TIME_AUTH
#ifdef HAVE_POLY1305
    Poly1305* tmp_poly1305 = NULL;
#endif
#endif

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

    /* Pre-allocate any objects that can fail BEFORE performing destructive
     * state mutations on ssl, so an allocation failure cannot leave ssl
     * with a zeroed encrypt context and a poisoned dupWrite.
     * dup->heap == ssl->heap here because dup was initialised with ssl->ctx;
     * use ssl->heap consistently for cleanup symmetry. */
#ifdef HAVE_ONE_TIME_AUTH
#ifdef HAVE_POLY1305
    if (ssl->auth.setup && ssl->auth.poly1305 != NULL) {
        tmp_poly1305 = (Poly1305*)XMALLOC(sizeof(Poly1305), ssl->heap,
            DYNAMIC_TYPE_CIPHER);
        if (tmp_poly1305 == NULL) {
            wc_FreeMutex(&ssl->dupWrite->dupMutex);
            XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
            ssl->dupWrite = NULL;
            return MEMORY_E;
        }
    }
#endif
#endif

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

    /* dup side now owns encrypt/write ciphers */
    XMEMSET(&ssl->encrypt, 0, sizeof(Ciphers));

#ifdef HAVE_ONE_TIME_AUTH
#ifdef HAVE_POLY1305
    if (tmp_poly1305 != NULL) {
        dup->auth.poly1305 = tmp_poly1305;
        dup->auth.setup = 1;
    }
#endif
#endif

#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        /* Copy TLS 1.3 application traffic secrets so the write side can
         * derive updated keys when wolfSSL_update_keys() is called. */
        XMEMCPY(dup->clientSecret, ssl->clientSecret, SECRET_LEN);
        XMEMCPY(dup->serverSecret, ssl->serverSecret, SECRET_LEN);

#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls) {
            /* Copy epoch array (contains only value types -- safe to memcpy). */
            XMEMCPY(dup->dtls13Epochs, ssl->dtls13Epochs,
                    sizeof(ssl->dtls13Epochs));

            /* Re-point dtls13EncryptEpoch into dup's own epoch array. */
            if (ssl->dtls13EncryptEpoch != NULL) {
                dup->dtls13EncryptEpoch =
                    &dup->dtls13Epochs[ssl->dtls13EncryptEpoch -
                                       ssl->dtls13Epochs];
            }

            /* Copy current write epoch number. */
            dup->dtls13Epoch = ssl->dtls13Epoch;

            /* Transfer record-number encryption cipher ownership to dup. */
            XMEMCPY(&dup->dtlsRecordNumberEncrypt,
                    &ssl->dtlsRecordNumberEncrypt, sizeof(RecordNumberCiphers));
            XMEMSET(&ssl->dtlsRecordNumberEncrypt,
                    0, sizeof(RecordNumberCiphers));
        }
#endif /* WOLFSSL_DTLS13 */
    }
#endif /* WOLFSSL_TLS13 */


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
        #ifdef USE_WOLFSSL_IO
            ssl->buffers.dtlsCtx.rfdIsDGram =
                (byte)(wolfIO_SockIsDGram(fd) != 0);
        #endif
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
        #ifdef USE_WOLFSSL_IO
            ssl->buffers.dtlsCtx.wfdIsDGram =
                (byte)(wolfIO_SockIsDGram(fd) != 0);
        #endif
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
            XSTRNCPY(buf, ciphers[i].name, (size_t)len);
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
            XSTRNCPY(buf, ciphers[i].name_iana, (size_t)len);
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

    if (ssl == NULL || buf == NULL || len <= 0)
        return NULL;

    cipher = wolfSSL_get_cipher_name_iana(ssl);
    if (cipher == NULL)
        return NULL;
    len = (int)min((word32)len, (word32)(XSTRLEN(cipher) + 1));
    XMEMCPY(buf, cipher, (size_t)len);
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

    return min(OUTPUT_RECORD_SIZE, wolfssl_local_GetMaxPlaintextSize(ssl));
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

    return wolfssl_local_GetRecordSize(ssl, inSz, 1);
}


#endif /* !NO_TLS */

#define WOLFSSL_SSL_API_RW_INCLUDED
#include "src/ssl_api_rw.c"

#define WOLFSSL_SSL_API_DTLS_INCLUDED
#include "src/ssl_api_dtls.c"

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
#ifdef WOLFSSL_ASYNC_CRYPT
    else if (ssl->error == WC_NO_ERR_TRACE(MP_WOULDBLOCK))
        return WC_PENDING_E;                    /* map non-blocking crypto */
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


#define WOLFSSL_SSL_ERR_INCLUDED
#include "src/ssl_err.c"


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

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) \
    && defined(XFPRINTF)


#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
#endif
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM && XFPRINTF */


#ifndef WOLFSSL_LEANPSK
/* turn on handshake group messages for context */
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 1;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_clear_group_messages(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 0;

    return WOLFSSL_SUCCESS;
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

int wolfSSL_clear_group_messages(WOLFSSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 0;

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

    ssl->options.downgrade = 0;

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

#if defined(LIBWOLFSSL_CMAKE_OUTPUT)
    WOLFSSL_MSG(LIBWOLFSSL_CMAKE_OUTPUT);
#else
    WOLFSSL_MSG("No extra wolfSSL cmake messages found");
#endif

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

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)
        /* Calculate the index of OID groups in wolfssl_object_info[]. */
        wolfssl_object_info_slice_init();
#endif

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
        wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
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
        initRefCount = initRefCount + 1;
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

#define WOLFSSL_SSL_API_CRL_OCSP_INCLUDED
#include "src/ssl_api_crl_ocsp.c"


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
        const char* keyLogFile = WOLFSSL_SSLKEYLOGFILE_OUTPUT;
        FILE* f;
    #ifdef WOLFSSL_SSLKEYLOGFILE_USE_ENV
        /* RFC 9850: prefer the SSLKEYLOGFILE environment variable so other
         * tools can share the path, else use the compile-time path. XGETENV is
         * NULL where environment access is unavailable. Opt-in so a build with
         * the variable exported for other applications is not affected. */
        const char* keyLogEnv = XGETENV("SSLKEYLOGFILE");
        if (keyLogEnv != NULL && keyLogEnv[0] != '\0')
            keyLogFile = keyLogEnv;
    #endif
        f = XFOPEN(keyLogFile, "a");
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

        if (next) {
            current_length = (word32)(next - current);
            ++next; /* increment to skip ':' */
        }
        else {
            current_length = (word32)XSTRLEN(current);
        }

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
    } while (next);

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
    WC_DECLARE_VAR(suitesCpy, byte, WOLFSSL_MAX_SUITE_SZ, 0);
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
        WC_FREE_VAR_EX(suitesCpy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* The idea in this section is that OpenSSL has two API to set ciphersuites.
     *   - SSL_CTX_set_cipher_list for setting TLS <= 1.2 suites
     *   - SSL_CTX_set_ciphersuites for setting TLS 1.3 suites
     * Since we direct both API here we attempt to provide API compatibility. If
     * we only get suites from <= 1.2 or == 1.3 then we will only update those
     * suites and keep the suites from the other group.
     * If downgrade is disabled, skip preserving the other group's suites. */
    if ((ssl != NULL && !ssl->options.downgrade) ||
        (ctx != NULL && !ctx->method->downgrade)) {
        /* Downgrade disabled - don't preserve other group's suites */
        WC_FREE_VAR_EX(suitesCpy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

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

    WC_FREE_VAR_EX(suitesCpy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
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

    /* Sanity check contextLen to prevent integer overflow when cast to word32
     * and to ensure it fits in the 2-byte length encoding (max 65535). */
    if (use_context && contextLen > WOLFSSL_MAX_16BIT) {
        WOLFSSL_MSG("contextLen too large");
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



#endif /* !NO_WOLFSSL_SERVER && !NO_TLS */
/* end server only parts */

#define WOLFSSL_SSL_API_HS_INCLUDED
#include "src/ssl_api_hs.c"



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
        initRefCount = initRefCount - 1;
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

/* Returns 1 if name is a syntactically valid DNS FQDN per RFC 952/1123.
 *
 * Rules enforced:
 *   - Total effective length (excluding optional trailing dot) in [1, 253]
 *   - Each label is 1-63 octets of [a-zA-Z0-9-], with _ allowed in all but
 *     the last label.
 *   - No label starts or ends with '-'
 *   - At least two labels (single-label names are not "fully qualified")
 *   - Final label (TLD) contains at least one letter (rejects all-numeric
 *     strings that could be confused with IPv4 literals, and matches the
 *     ICANN constraint that TLDs are alphabetic)
 *   - Optional trailing dot is accepted (absolute FQDN form)
 *   - Internationalized names are valid in their ACE/punycode (xn--) form
 */
int wolfssl_local_IsValidFQDN(const char* name, word32 nameSz)
{
    word32 i;
    int labelLen = 0;
    int labelCount = 0;
    int curLabelHasAlpha = 0;
    int curLabelHasUnderscore = 0;

    if (name == NULL || nameSz == 0)
        return 0;

    /* Strip a single optional trailing dot before measuring.  "example.com."
     * is the absolute form of the same FQDN.
     */
    if (name[nameSz - 1] == '.')
        --nameSz;

    if (nameSz < 1 || nameSz > 253)
        return 0;

    for (i = 0; i < nameSz; i++) {
        byte c = (byte)name[i];

        if (c == '.') {
            if (labelLen == 0 || name[i - 1] == '-')
                return 0;
            ++labelCount;
            labelLen = 0;
            curLabelHasAlpha = 0;
            curLabelHasUnderscore = 0;
            continue;
        }

        if (++labelLen > 63)
            return 0;

        if (c == '-') {
            if (labelLen == 1)
                return 0;
        }
        else if (((c | 0x20) >= 'a') && ((c | 0x20) <= 'z')) {
            curLabelHasAlpha = 1;
        }
        else if (c == '_') {
            curLabelHasUnderscore = 1;
        }
        else if ((c < '0') || (c > '9')) {
            return 0;
        }
    }

    /* Final label (no trailing dot in the effective range to close it) */
    if ((labelLen == 0) || (name[nameSz - 1] == '-') || curLabelHasUnderscore)
        return 0;
    ++labelCount;

    return ((labelCount > 1) && curLabelHasAlpha);
}

/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
WOLFSSL_ABI
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn)
{
    size_t dn_len;

    WOLFSSL_ENTER("wolfSSL_check_domain_name");

    if (ssl == NULL || dn == NULL) {
        WOLFSSL_MSG("Bad function argument: NULL");
        return WOLFSSL_FAILURE;
    }

    dn_len = XSTRLEN(dn);

    if ((! wolfssl_local_IsValidFQDN(dn, (word32)dn_len)) &&
        (XSTRCMP(dn, "localhost") != 0))
    {
        WOLFSSL_MSG("Bad function argument: fails wolfssl_local_IsValidFQDN");
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

/* call before SSL_connect, if verifying will add IP SAN check to
   date check and signature check */
WOLFSSL_ABI
int wolfSSL_check_ip_address(WOLFSSL* ssl, const char* ipaddr)
{
    WOLFSSL_ENTER("wolfSSL_check_ip_address");

    if (ssl == NULL || ipaddr == NULL) {
        WOLFSSL_MSG("Bad function argument: NULL");
        return WOLFSSL_FAILURE;
    }

    if (ssl->buffers.ipasc.buffer != NULL) {
        XFREE(ssl->buffers.ipasc.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);
        ssl->buffers.ipasc.buffer = NULL;
        ssl->buffers.ipasc.length = 0;
    }

    ssl->buffers.ipasc.length = (word32)XSTRLEN(ipaddr);
    ssl->buffers.ipasc.buffer = (byte*)XMALLOC(ssl->buffers.ipasc.length + 1,
                                               ssl->heap, DYNAMIC_TYPE_DOMAIN);
    if (ssl->buffers.ipasc.buffer == NULL) {
        ssl->error = MEMORY_ERROR;
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(ssl->buffers.ipasc.buffer, ipaddr, ssl->buffers.ipasc.length);
    ssl->buffers.ipasc.buffer[ssl->buffers.ipasc.length] = '\0';

#ifdef OPENSSL_EXTRA
    if (ssl->param == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(ssl->param, ipaddr) !=
            WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }
#endif

    return WOLFSSL_SUCCESS;
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
#ifdef KEEP_PEER_CERT
    else if (ssl->peerCert.subjectCN[0])
        return ssl->peerCert.subjectCN;
#endif
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

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_CERT_WITH_EXTERN_PSK)
    int wolfSSL_CTX_set_cert_with_extern_psk(WOLFSSL_CTX* ctx, int state)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_cert_with_extern_psk");
        if (ctx == NULL)
            return WOLFSSL_FAILURE;
        ctx->certWithExternPsk = (byte)(state != 0);
        return WOLFSSL_SUCCESS;
    }

    int wolfSSL_set_cert_with_extern_psk(WOLFSSL* ssl, int state)
    {
        WOLFSSL_ENTER("wolfSSL_set_cert_with_extern_psk");
        if (ssl == NULL)
            return WOLFSSL_FAILURE;
        ssl->options.certWithExternPsk = (word16)(state != 0);
        return WOLFSSL_SUCCESS;
    }
#endif

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
                if (ssl->biowr != NULL && ssl->biowr->prev == NULL)
                    wolfSSL_BIO_free(ssl->biowr);
                ssl->biowr = NULL;
            }
            if (ssl->biord->prev == NULL)
                wolfSSL_BIO_free(ssl->biord);
            ssl->biord = NULL;
        }
        else if ((flags & WOLFSSL_BIO_FLAG_WRITE) && (ssl->biowr != NULL)) {
            if (ssl->biowr->prev == NULL)
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

#ifdef WOLFSSL_CERT_SETUP_CB
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
        case ecc_brainpool_sa_algo:
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
        case mldsa_44_sa_algo:
            *sigAlgo = ML_DSA_44k;
            break;
        case mldsa_65_sa_algo:
            *sigAlgo = ML_DSA_65k;
            break;
        case mldsa_87_sa_algo:
            *sigAlgo = ML_DSA_87k;
            break;
        case sm2_sa_algo:
            *sigAlgo = SM2k;
            break;
        case invalid_sa_algo:
        case any_sa_algo:
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
#endif /* WOLFSSL_CERT_SETUP_CB */

#ifdef OPENSSL_EXTRA

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


#endif /* OPENSSL_EXTRA || WOLFSSL_EXTRA || WOLFSSL_WPAS_SMALL */


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
        #ifdef USE_WOLFSSL_IO
            ssl->buffers.dtlsCtx.rfdIsDGram =
                (byte)(wolfIO_SockIsDGram(rfd) != 0);
        #endif
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
#ifndef NO_TLS
#ifndef NO_OLD_TLS
    case SSL2_VERSION:
        WOLFSSL_MSG("wolfSSL does not support SSLv2");
        return WOLFSSL_FAILURE;
#endif
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

    void wolfSSL_cleanup_all_ex_data(void)
    {
        /* nothing to do here */
    }

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || \
    defined(HAVE_CURL)
#endif

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
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLFSSL_ASYNC_CERT_YIELD)
        /* A per-certificate yield (WOLFSSL_ASYNC_CERT_YIELD) sets this and it is
         * normally cleared on the next ProcessPeerCerts re-entry. Clear it here
         * so reusing this object after abandoning a yielded handshake cannot
         * skip the ProcessPeerCerts state reset on the next fresh entry. */
        ssl->options.certYieldPending = 0;
#endif
        ssl->recordSzOverhead = 0;
        ssl->options.processReply = 0; /* doProcessInit */
        ssl->options.havePeerVerify = 0;
        ssl->options.havePeerCert = 0;
        ssl->options.peerAuthGood = 0;
        ssl->options.tls1_3 = 0;
        ssl->options.haveSessionId = 0;
        ssl->options.tls = 0;
        ssl->options.tls1_1 = 0;
    #ifdef WOLFSSL_TLS13
    #ifdef WOLFSSL_SEND_HRR_COOKIE
        ssl->options.hrrSentCookie = 0;
    #endif
        ssl->options.hrrSentKeyShare = 0;
    #endif
    #ifdef WOLFSSL_DTLS
        ssl->options.dtlsStateful = 0;
    #endif
    #ifdef WOLFSSL_TLS13
    #if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
        ssl->options.noPskDheKe = ssl->ctx->noPskDheKe;
        #ifdef HAVE_SUPPORTED_CURVES
        ssl->options.onlyPskDheKe = ssl->ctx->onlyPskDheKe;
        #endif
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
      #if defined(HAVE_SECURE_RENEGOTIATION) \
       || defined(HAVE_SERVER_RENEGOTIATION_INFO)
        ssl->secure_renegotiation = NULL;
      #endif
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

        /* Discard any partial handshake-message reassembly on reuse. */
        XFREE(ssl->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
        ssl->pendingMsg = NULL;
        ssl->pendingMsgSz = 0;
        ssl->pendingMsgOffset = 0;
        ssl->pendingMsgType = 0;

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





#endif /* OPENSSL_EXTRA */







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


#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448) || \
    !defined(NO_DH) || (defined(WOLFSSL_TLS13) && defined(WOLFSSL_HAVE_MLKEM))
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

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_HAVE_MLKEM)
    /* Check for post-quantum groups. Return now because we do not want the ECC
     * check to override this result in the case of a hybrid. */
    if (IsAtLeastTLSv1_3(ssl->version)) {
        switch (ssl->namedGroup) {
#ifndef WOLFSSL_NO_ML_KEM
    #ifndef WOLFSSL_NO_ML_KEM_512
        case WOLFSSL_ML_KEM_512:
            return "ML_KEM_512";
        #ifdef WOLFSSL_EXTRA_PQC_HYBRIDS
        #ifdef WOLFSSL_ML_KEM_USE_OLD_IDS
        case WOLFSSL_P256_ML_KEM_512_OLD:
            return "P256_ML_KEM_512_OLD";
        #endif /* WOLFSSL_ML_KEM_USE_OLD_IDS */
        case WOLFSSL_SECP256R1MLKEM512:
            return "SecP256r1MLKEM512";
        #ifdef HAVE_CURVE25519
        case WOLFSSL_X25519MLKEM512:
            return "X25519MLKEM512";
        #endif /* HAVE_CURVE25519 */
        #endif /* WOLFSSL_EXTRA_PQC_HYBRIDS */
    #endif /* WOLFSSL_NO_ML_KEM_512 */
    #ifndef WOLFSSL_NO_ML_KEM_768
        case WOLFSSL_ML_KEM_768:
            return "ML_KEM_768";
        #ifdef WOLFSSL_PQC_HYBRIDS
        case WOLFSSL_SECP256R1MLKEM768:
            return "SecP256r1MLKEM768";
        #ifdef HAVE_CURVE25519
        case WOLFSSL_X25519MLKEM768:
            return "X25519MLKEM768";
        #endif
        #endif /* WOLFSSL_PQC_HYBRIDS */
        #ifdef WOLFSSL_EXTRA_PQC_HYBRIDS
        #ifdef WOLFSSL_ML_KEM_USE_OLD_IDS
        case WOLFSSL_P384_ML_KEM_768_OLD:
            return "P384_ML_KEM_768_OLD";
        #endif /* WOLFSSL_ML_KEM_USE_OLD_IDS */
        case WOLFSSL_SECP384R1MLKEM768:
            return "SecP384r1MLKEM768";
        #ifdef HAVE_CURVE448
        case WOLFSSL_X448MLKEM768:
            return "X448MLKEM768";
        #endif /* HAVE_CURVE448 */
        #endif /* WOLFSSL_EXTRA_PQC_HYBRIDS */
    #endif /* WOLFSSL_NO_ML_KEM_768 */
    #ifndef WOLFSSL_NO_ML_KEM_1024
        case WOLFSSL_ML_KEM_1024:
            return "ML_KEM_1024";
        #ifdef WOLFSSL_PQC_HYBRIDS
        case WOLFSSL_SECP384R1MLKEM1024:
            return "SecP384r1MLKEM1024";
        #endif /* WOLFSSL_PQC_HYBRIDS */
        #ifdef WOLFSSL_EXTRA_PQC_HYBRIDS
        #ifdef WOLFSSL_ML_KEM_USE_OLD_IDS
        case WOLFSSL_P521_ML_KEM_1024_OLD:
            return "P521_ML_KEM_1024_OLD";
        #endif /* WOLFSSL_ML_KEM_USE_OLD_IDS */
        case WOLFSSL_SECP521R1MLKEM1024:
            return "SecP521r1MLKEM1024";
        #endif /* WOLFSSL_EXTRA_PQC_HYBRIDS */
    #endif /* WOLFSSL_NO_ML_KEM_1024 */
#endif /* WOLFSSL_NO_ML_KEM */
#ifdef WOLFSSL_MLKEM_KYBER
    #ifndef WOLFSSL_NO_KYBER512
        case WOLFSSL_KYBER_LEVEL1:
            return "KYBER_LEVEL1";
        case WOLFSSL_P256_KYBER_LEVEL1:
            return "P256_KYBER_LEVEL1";
        #ifdef HAVE_CURVE25519
        case WOLFSSL_X25519_KYBER_LEVEL1:
            return "X25519_KYBER_LEVEL1";
        #endif
    #endif
    #ifndef WOLFSSL_NO_KYBER768
        case WOLFSSL_KYBER_LEVEL3:
            return "KYBER_LEVEL3";
        case WOLFSSL_P384_KYBER_LEVEL3:
            return "P384_KYBER_LEVEL3";
        case WOLFSSL_P256_KYBER_LEVEL3:
            return "P256_KYBER_LEVEL3";
        #ifdef HAVE_CURVE25519
        case WOLFSSL_X25519_KYBER_LEVEL3:
            return "X25519_KYBER_LEVEL3";
        #endif
        #ifdef HAVE_CURVE448
        case WOLFSSL_X448_KYBER_LEVEL3:
            return "X448_KYBER_LEVEL3";
        #endif
    #endif
    #ifndef WOLFSSL_NO_KYBER1024
        case WOLFSSL_KYBER_LEVEL5:
            return "KYBER_LEVEL5";
        case WOLFSSL_P521_KYBER_LEVEL5:
            return "P521_KYBER_LEVEL5";
    #endif
#endif /* WOLFSSL_MLKEM_KYBER */
        }
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_HAVE_MLKEM */

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
        {"PSK",       WC_NID_kx_psk},
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
    XSTRNCPY(dp, name, (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " ", (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, protocol, (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Kx=", (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, keaStr, (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Au=", (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, authStr, (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Enc=", (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;
    XSTRNCPY(dp, encStr, (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += strLen;

    XSTRNCPY(dp, " Mac=", (size_t)len);
    dp[len-1] = '\0'; strLen = (int)XSTRLEN(dp);
    len -= strLen; dp += (size_t)strLen;
    XSTRNCPY(dp, macStr, (size_t)len);
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
        case any_kea:
            keaStr = "any";
            break;
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
        case any_sa_algo:
            authStr = "any";
            break;
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
            if (key_size == AES_128_KEY_SIZE)
                encStr = "AES(128)";
            else if (key_size == AES_256_KEY_SIZE)
                encStr = "AES(256)";
            else
                encStr = "AES(?)";
            break;
    #ifdef HAVE_AESGCM
        case wolfssl_aes_gcm:
            if (key_size == AES_128_KEY_SIZE)
                encStr = "AESGCM(128)";
            else if (key_size == AES_256_KEY_SIZE)
                encStr = "AESGCM(256)";
            else
                encStr = "AESGCM(?)";
            break;
    #endif
    #ifdef HAVE_AESCCM
        case wolfssl_aes_ccm:
            if (key_size == AES_128_KEY_SIZE)
                encStr = "AESCCM(128)";
            else if (key_size == AES_256_KEY_SIZE)
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
            if (key_size == ARIA_128_KEY_SIZE)
                encStr = "Aria(128)";
            else if (key_size == ARIA_192_KEY_SIZE)
                encStr = "Aria(192)";
            else if (key_size == ARIA_256_KEY_SIZE)
                encStr = "Aria(256)";
            else
                encStr = "Aria(?)";
            break;
#endif
#ifdef HAVE_CAMELLIA
        case wolfssl_camellia:
            if (key_size == CAMELLIA_128_KEY_SIZE)
                encStr = "Camellia(128)";
            else if (key_size == CAMELLIA_256_KEY_SIZE)
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
        XSTRNCPY(in,cipher->description,(size_t)len);
        return ret;
    }
#endif

    /* Get the cipher description based on the SSL session cipher */
    keaStr = wolfssl_kea_to_string(cipher->ssl->specs.kea);
    authStr = wolfssl_sigalg_to_string(cipher->ssl->specs.sig_algo);
    encStr = wolfssl_cipher_to_string(cipher->ssl->specs.bulk_cipher_algorithm,
                                      cipher->ssl->specs.key_size);
    if (cipher->ssl->specs.cipher_type == aead)
        macStr = "AEAD";
    else
        macStr = wolfssl_mac_to_string(cipher->ssl->specs.mac_algorithm);

    /* Build up the string by copying onto the end. */
    XSTRNCPY(in, wolfSSL_CIPHER_get_name(cipher), (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " ", (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, wolfSSL_get_version(cipher->ssl), (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Kx=", (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, keaStr, (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Au=", (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, authStr, (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Enc=", (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, encStr, (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;

    XSTRNCPY(in, " Mac=", (size_t)len);
    in[len-1] = '\0'; strLen = XSTRLEN(in); len -= (int)strLen; in += strLen;
    XSTRNCPY(in, macStr, (size_t)len);
    in[len-1] = '\0';

    return ret;
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

const char* wolfSSL_alert_type_string(int alertID)
{
    WOLFSSL_ENTER("wolfSSL_alert_type_string");

    switch (alertID) {
        case alert_warning:
            return "W";
        case alert_fatal:
            return "F";
        default:
            return "U";
    }
}

const char* wolfSSL_alert_desc_string_long(int alertID)
{
    WOLFSSL_ENTER("wolfSSL_alert_desc_string_long");

    return AlertTypeToString(alertID);
}

const char* wolfSSL_alert_desc_string(int alertID)
{
    WOLFSSL_ENTER("wolfSSL_alert_desc_string");

    switch (alertID) {
        case close_notify:
            return "CN";
        case unexpected_message:
            return "UM";
        case bad_record_mac:
            return "BM";
        case record_overflow:
            return "RO";
        case decompression_failure:
            return "DF";
        case handshake_failure:
            return "HF";
        case no_certificate:
            return "NC";
        case bad_certificate:
            return "BC";
        case unsupported_certificate:
            return "UC";
        case certificate_revoked:
            return "CR";
        case certificate_expired:
            return "CE";
        case certificate_unknown:
            return "CU";
        case illegal_parameter:
            return "IP";
        case unknown_ca:
            return "CA";
        case access_denied:
            return "AD";
        case decode_error:
            return "DE";
        case decrypt_error:
            return "DC";
        case wolfssl_alert_protocol_version:
            return "PV";
        case insufficient_security:
            return "IS";
        case internal_error:
            return "IE";
        case inappropriate_fallback:
            return "IF";
        case user_canceled:
            return "US";
        case no_renegotiation:
            return "NR";
        case missing_extension:
            return "ME";
        case unsupported_extension:
            return "UE";
        case unrecognized_name:
            return "UN";
        case bad_certificate_status_response:
            return "BR";
        case unknown_psk_identity:
            return "UP";
        case certificate_required:
            return "CQ";
        case no_application_protocol:
            return "AP";
        default:
            return "UK";
    }
}
#endif /* !NO_TLS */


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
            /* Client side won't set DH params, so it needs haveDH set to TRUE. */
            if (ssl->options.side == WOLFSSL_CLIENT_END)
                InitSuites(ssl->suites, ssl->version, keySz, haveRSA,
                       havePSK, TRUE, ssl->options.haveECDSAsig,
                       ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                       ssl->options.useAnon,
                       TRUE, TRUE, TRUE, TRUE, ssl->options.side);
            else
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
    ssl->options.mask &= (unsigned long)~opt;
    return (long)ssl->options.mask;
}


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


#if !defined(NETOS)
#endif


#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_HAVE_TLS_UNIQUE
size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;
    byte const * src;

    WOLFSSL_ENTER("wolfSSL_get_finished");

    if (!ssl || !buf) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        src = ssl->serverFinished;
        len = ssl->serverFinished_len;
    }
    else {
        src = ssl->clientFinished;
        len = ssl->clientFinished_len;
    }

    if (count < len) {
        WOLFSSL_MSG("Buffer too small");
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(buf, src, len);

    return len;
}

size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;
    byte const * src;

    WOLFSSL_ENTER("wolfSSL_get_peer_finished");

    if (!ssl || !buf) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        src = ssl->serverFinished;
        len = ssl->serverFinished_len;
    }
    else {
        src = ssl->clientFinished;
        len = ssl->clientFinished_len;
    }

    if (count < len) {
        WOLFSSL_MSG("Buffer too small");
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(buf, src, len);

    return len;
}
#endif /* WOLFSSL_HAVE_TLS_UNIQUE */


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

#endif /* OPENSSL_EXTRA */


#ifdef HAVE_FUZZER
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx)
{
    if (ssl) {
        ssl->fuzzerCb  = cbf;
        ssl->fuzzerCtx = fCtx;
    }
}
#endif


#ifdef WOLFSSL_HAVE_WOLFSCEP
    /* Used by autoconf to see if wolfSCEP is available */
    void wolfSSL_wolfSCEP(void) {}
#endif


#ifdef WOLFSSL_HAVE_CERT_SERVICE
    /* Used by autoconf to see if cert service is available */
    void wolfSSL_cert_service(void) {}
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)

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
 * wolfssl_local_get_ex_new_index is a helper function for the following
 * xx_get_ex_new_index functions:
 *  - wolfSSL_CRYPTO_get_ex_new_index
 *  - wolfSSL_CTX_get_ex_new_index
 *  - wolfSSL_get_ex_new_index
 * Issues a unique index number for the specified class-index.
 * Returns an index number greater or equal to zero on success,
 * -1 on failure.
 */
int wolfssl_local_get_ex_new_index(int class_index, long ctx_l, void* ctx_ptr,
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

    return wolfssl_local_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_CTX, idx,
                                    arg, new_func, dup_func, free_func);
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

    return wolfssl_local_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL, argValue,
            arg, cb1, cb2, cb3);
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
                    x509 = NULL;
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


#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */


/* stunnel compatibility functions*/
#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
     defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
     defined(WOLFSSL_OPENSSH)))

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
#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)

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
     *
     * SECURITY: swapping ssl->ctx switches cm-resolved settings (CA store,
     * CRL, OCSP) to the new CTX but leaves ssl-cached ones (verify mode and
     * callback, minDowngrade, key-size minimums, suites, version bounds)
     * pinned to the original. SNI callbacks must re-apply those ssl-level
     * settings explicitly; CRL/OCSP isolation requires an SSL-local store.
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
    if (ssl->buffers.key != NULL && ssl->buffers.weOwnKey) {
        FreeDer(&ssl->buffers.key);
    }
    if (ctx->privateKey != NULL) {
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
        if (ssl->buffers.key != NULL && ssl->buffers.weOwnKey) {
            FreeDer(&ssl->buffers.key);
        }
        ret = AllocCopyDer(&ssl->buffers.key, ctx->privateKey->buffer,
            ctx->privateKey->length, ctx->privateKey->type,
            ctx->privateKey->heap);
        if (ret != 0) {
            return NULL;
        }
        /* Blind the private key for the SSL with new random mask. */
        wolfssl_priv_der_blind_toggle(ssl->buffers.key, ctx->privateKeyMask);
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
    ssl->options.haveMlDsaSig = ctx->haveMlDsaSig;
#ifdef WOLFSSL_DUAL_ALG_CERTS
#ifndef WOLFSSL_BLIND_PRIVATE_KEY
    ssl->buffers.altKey   = ctx->altPrivateKey;
#else
    if (ctx->altPrivateKey != NULL) {
        ret = AllocCopyDer(&ssl->buffers.altKey, ctx->altPrivateKey->buffer,
            ctx->altPrivateKey->length, ctx->altPrivateKey->type,
            ctx->altPrivateKey->heap);
        if (ret != 0) {
            return NULL;
        }
        /* Blind the private key for the SSL with new random mask. */
        wolfssl_priv_der_blind_toggle(ssl->buffers.altKey,
                                      ctx->altPrivateKeyMask);
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


#ifndef NO_BIO
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

#endif /* OPENSSL_ALL || OPENSSL_EXTRA */


#if defined(OPENSSL_EXTRA)

int wolfSSL_CRYPTO_memcmp(const void *a, const void *b, size_t size)
{
    int ret = 0;
    int chunk;
    const byte* pa = (const byte*)a;
    const byte* pb = (const byte*)b;

    if (!a || !b)
        return -1;
    /* ConstantCompare takes an int length. Compare in chunks of at most
     * INT_MAX so a size that does not fit in an int is not narrowed into a
     * negative or truncated length, which could wrongly report equality. */
    while (size > 0) {
        chunk = (size > (size_t)INT_MAX) ? INT_MAX : (int)size;
        ret |= ConstantCompare(pa, pb, chunk);
        pa += chunk;
        pb += chunk;
        size -= (size_t)chunk;
    }
    return ret;
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
#ifdef FREESCALE_MQX
    if (XINET_PTON(af, ipa, (void*)buf, sizeof(buf)) != RTCS_OK) {
#else
    if (XINET_PTON(af, ipa, (void*)buf) != 1) {
#endif
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
    const Suites* suites;
#if defined(OPENSSL_ALL)
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

        ((WOLFSSL*)ssl)->suitesStack =
                wolfssl_sk_new_type_ex(STACK_TYPE_CIPHER, ssl->heap);
        if (ssl->suitesStack == NULL)
            return NULL;

        /* higher priority of cipher suite will be on top of stack */
#if defined(OPENSSL_ALL)
        for (i = suites->suiteSz - 2; i >=0; i-=2)
#else
        for (i = 0; i < suites->suiteSz; i+=2)
#endif
        {
            struct WOLFSSL_CIPHER cipher;

            /* A couple of suites are placeholders for special options,
             * skip those. */
            if (SCSV_Check(suites->suites[i], suites->suites[i+1])
                    || sslCipherMinMaxCheck(ssl, suites->suites[i],
                                            suites->suites[i+1])) {
                continue;
            }

            XMEMSET(&cipher, 0, sizeof(cipher));
            cipher.cipherSuite0 = suites->suites[i];
            cipher.cipherSuite  = suites->suites[i+1];
            cipher.ssl          = ssl;
#if defined(OPENSSL_ALL)
            cipher.in_stack     = 1;
            {
                int j;
                for (j = 0; j < cipherSz; j++) {
                    if (cipher_names[j].cipherSuite0 == cipher.cipherSuite0 &&
                            cipher_names[j].cipherSuite == cipher.cipherSuite) {
                        cipher.offset = (unsigned long)j;
                        break;
                    }
                }
            }
#endif
            if (wolfSSL_sk_insert(ssl->suitesStack, &cipher, 0) <= 0) {
                WOLFSSL_MSG("Error inserting cipher onto stack");
                wolfSSL_sk_CIPHER_free(ssl->suitesStack);
                ((WOLFSSL*)ssl)->suitesStack = NULL;
                break;
            }
        }

        /* If no ciphers were added, free empty stack and return NULL */
        if (ssl->suitesStack != NULL && wolfSSL_sk_num(ssl->suitesStack) == 0) {
            wolfSSL_sk_CIPHER_free(ssl->suitesStack);
            ((WOLFSSL*)ssl)->suitesStack = NULL;
        }
    }
    return ssl->suitesStack;
}
#endif /* OPENSSL_EXTRA || OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */
#ifdef OPENSSL_ALL
/* returned pointer is to an internal element in WOLFSSL struct and should not
 * be free'd. It gets free'd when the WOLFSSL struct is free'd. */
WOLF_STACK_OF(WOLFSSL_CIPHER)*  wolfSSL_get_client_ciphers(WOLFSSL* ssl)
{
    WOLF_STACK_OF(WOLFSSL_CIPHER)* ret = NULL;
    const CipherSuiteInfo* cipher_names = GetCipherNames();
    int cipherSz = GetCipherNamesSize();
    const Suites* suites;

    WOLFSSL_ENTER("wolfSSL_get_client_ciphers");

    if (ssl == NULL) {
        return NULL;
    }

    /* return NULL if is client side */
    if (wolfSSL_is_server(ssl) == 0) {
        return NULL;
    }

    suites = ssl->clSuites;
    if (suites == NULL) {
        WOLFSSL_MSG("No client suites stored");
    }
    else if (ssl->clSuitesStack != NULL) {
        ret = ssl->clSuitesStack;
    }
    else { /* generate cipher suites stack if not already done */
        int i;
        int j;

        ret = wolfSSL_sk_new_node(ssl->heap);
        if (ret != NULL) {
            ret->type = STACK_TYPE_CIPHER;

            /* higher priority of cipher suite will be on top of stack */
            for (i = suites->suiteSz - 2; i >= 0; i -= 2) {
                WOLFSSL_CIPHER cipher;

                /* A couple of suites are placeholders for special options,
                 * skip those. */
                if (SCSV_Check(suites->suites[i], suites->suites[i+1])
                        || sslCipherMinMaxCheck(ssl, suites->suites[i],
                                                suites->suites[i+1])) {
                    continue;
                }

                cipher.cipherSuite0 = suites->suites[i];
                cipher.cipherSuite  = suites->suites[i+1];
                cipher.ssl          = ssl;
                for (j = 0; j < cipherSz; j++) {
                    if (cipher_names[j].cipherSuite0 ==
                            cipher.cipherSuite0 &&
                            cipher_names[j].cipherSuite ==
                                    cipher.cipherSuite) {
                        cipher.offset = (unsigned long)j;
                        break;
                    }
                }

                /* in_stack is checked in wolfSSL_CIPHER_description */
                cipher.in_stack     = 1;

                if (wolfSSL_sk_CIPHER_push(ret, &cipher) <= 0) {
                    WOLFSSL_MSG("Error pushing client cipher onto stack");
                    wolfSSL_sk_CIPHER_free(ret);
                    ret = NULL;
                    break;
                }
            }
        }
        ssl->clSuitesStack = ret;
    }
    return ret;
}
#endif /* OPENSSL_ALL */

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



#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)


void wolfSSL_WOLFSSL_STRING_free(WOLFSSL_STRING s)
{
    WOLFSSL_ENTER("wolfSSL_WOLFSSL_STRING_free");

    XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);
}

#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */


#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)

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
    {CURVE_NAME("K-224"),   WC_NID_secp224k1, WOLFSSL_ECC_SECP224K1},
    {CURVE_NAME("K-256"),   WC_NID_secp256k1, WOLFSSL_ECC_SECP256K1},
    {CURVE_NAME("B-256"),   WC_NID_brainpoolP256r1,
     WOLFSSL_ECC_BRAINPOOLP256R1},
    {CURVE_NAME("B-384"),   WC_NID_brainpoolP384r1,
     WOLFSSL_ECC_BRAINPOOLP384R1},
    {CURVE_NAME("B-512"),   WC_NID_brainpoolP512r1,
     WOLFSSL_ECC_BRAINPOOLP512R1},
#endif
#ifdef HAVE_CURVE25519
    {CURVE_NAME("X25519"),  WC_NID_X25519, WOLFSSL_ECC_X25519},
#endif
#ifdef HAVE_CURVE448
    {CURVE_NAME("X448"),    WC_NID_X448, WOLFSSL_ECC_X448},
#endif
#ifdef WOLFSSL_HAVE_MLKEM
#ifndef WOLFSSL_NO_ML_KEM
    {CURVE_NAME("ML_KEM_512"), WOLFSSL_ML_KEM_512, WOLFSSL_ML_KEM_512},
    {CURVE_NAME("ML_KEM_768"), WOLFSSL_ML_KEM_768, WOLFSSL_ML_KEM_768},
    {CURVE_NAME("ML_KEM_1024"), WOLFSSL_ML_KEM_1024, WOLFSSL_ML_KEM_1024},
    /* Aliases accepting the OpenSSL/IANA spelling without underscores. */
    {CURVE_NAME("MLKEM512"), WOLFSSL_ML_KEM_512, WOLFSSL_ML_KEM_512},
    {CURVE_NAME("MLKEM768"), WOLFSSL_ML_KEM_768, WOLFSSL_ML_KEM_768},
    {CURVE_NAME("MLKEM1024"), WOLFSSL_ML_KEM_1024, WOLFSSL_ML_KEM_1024},
#if defined(HAVE_ECC)
    #ifdef WOLFSSL_PQC_HYBRIDS
    {CURVE_NAME("SecP256r1MLKEM768"), WOLFSSL_SECP256R1MLKEM768,
     WOLFSSL_SECP256R1MLKEM768},
    {CURVE_NAME("SecP384r1MLKEM1024"), WOLFSSL_SECP384R1MLKEM1024,
     WOLFSSL_SECP384R1MLKEM1024},
    {CURVE_NAME("X25519MLKEM768"), WOLFSSL_X25519MLKEM768,
     WOLFSSL_X25519MLKEM768},
    #endif /* WOLFSSL_PQC_HYBRIDS */
    #ifdef WOLFSSL_EXTRA_PQC_HYBRIDS
    {CURVE_NAME("SecP256r1MLKEM512"), WOLFSSL_SECP256R1MLKEM512,
     WOLFSSL_SECP256R1MLKEM512},
    {CURVE_NAME("SecP384r1MLKEM768"), WOLFSSL_SECP384R1MLKEM768,
     WOLFSSL_SECP384R1MLKEM768},
    {CURVE_NAME("SecP521r1MLKEM1024"), WOLFSSL_SECP521R1MLKEM1024,
     WOLFSSL_SECP521R1MLKEM1024},
    {CURVE_NAME("X25519MLKEM512"), WOLFSSL_X25519MLKEM512,
     WOLFSSL_X25519MLKEM512},
    {CURVE_NAME("X448MLKEM768"), WOLFSSL_X448MLKEM768,
     WOLFSSL_X448MLKEM768},
    #endif /* WOLFSSL_EXTRA_PQC_HYBRIDS */
#endif
#endif /* !WOLFSSL_NO_ML_KEM */
#ifdef WOLFSSL_MLKEM_KYBER
    {CURVE_NAME("KYBER_LEVEL1"), WOLFSSL_KYBER_LEVEL1, WOLFSSL_KYBER_LEVEL1},
    {CURVE_NAME("KYBER_LEVEL3"), WOLFSSL_KYBER_LEVEL3, WOLFSSL_KYBER_LEVEL3},
    {CURVE_NAME("KYBER_LEVEL5"), WOLFSSL_KYBER_LEVEL5, WOLFSSL_KYBER_LEVEL5},
#if defined(HAVE_ECC)
    {CURVE_NAME("P256_KYBER_LEVEL1"), WOLFSSL_P256_KYBER_LEVEL1,
     WOLFSSL_P256_KYBER_LEVEL1},
    {CURVE_NAME("P384_KYBER_LEVEL3"), WOLFSSL_P384_KYBER_LEVEL3,
     WOLFSSL_P384_KYBER_LEVEL3},
    {CURVE_NAME("P256_KYBER_LEVEL3"), WOLFSSL_P256_KYBER_LEVEL3,
     WOLFSSL_P256_KYBER_LEVEL3},
    {CURVE_NAME("P521_KYBER_LEVEL5"), WOLFSSL_P521_KYBER_LEVEL5,
     WOLFSSL_P521_KYBER_LEVEL5},
    {CURVE_NAME("X25519_KYBER_LEVEL1"), WOLFSSL_X25519_KYBER_LEVEL1,
     WOLFSSL_X25519_KYBER_LEVEL1},
    {CURVE_NAME("X448_KYBER_LEVEL3"), WOLFSSL_X448_KYBER_LEVEL3,
     WOLFSSL_X448_KYBER_LEVEL3},
    {CURVE_NAME("X25519_KYBER_LEVEL3"), WOLFSSL_X25519_KYBER_LEVEL3,
     WOLFSSL_X25519_KYBER_LEVEL3},
#endif
#endif /* WOLFSSL_MLKEM_KYBER */
#endif /* WOLFSSL_HAVE_MLKEM */
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

    WC_ALLOC_VAR_EX(groups, int, WOLFSSL_MAX_GROUP_COUNT, heap,
        DYNAMIC_TYPE_TMP_BUFFER,
    {
        ret=MEMORY_E;
        goto leave;
    });

    for (idx = 1; names[idx-1] != '\0'; idx++) {
        if (names[idx] != ':' && names[idx] != '\0')
            continue;

        len = idx - start;
        if (len > MAX_CURVE_NAME_SZ - 1)
            goto leave;

        XMEMCPY(name, names + start, (size_t)len);
        name[len] = 0;
        curve = WOLFSSL_NAMED_GROUP_INVALID;

        for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
            if (len == nist_name->name_len &&
                    XSTRNCASECMP(name, nist_name->name, (size_t)len) == 0) {
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

            eccSet = wc_ecc_get_curve_params(nret);
            if (eccSet == NULL) {
                WOLFSSL_MSG("NULL set returned");
                goto leave;
            }

            curve = GetCurveByOID((int)eccSet->oidSum);
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

#endif /* OPENSSL_EXTRA */

#define WOLFSSL_SSL_API_EXT_INCLUDED
#include "src/ssl_api_ext.c"

#if defined(OPENSSL_EXTRA)

#ifndef NO_BIO
#define WOLFSSL_BIO_INCLUDED
#include "src/bio.c"
#endif

#endif /* OPENSSL_EXTRA */


#if defined(OPENSSL_EXTRA)

/* frees all nodes in the current threads error queue
 *
 * id  thread id. ERR_remove_state is depreciated and id is ignored. The
 *     current threads queue will be free'd.
 */

#endif /* OPENSSL_EXTRA */


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

    return wolfssl_local_get_ex_new_index(class_index, argl, argp, new_func,
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
    size_t mx;
    char* tmp;

    /* verify provided arguments. The return value is an int holding the
     * resulting length, so reject any len that cannot be represented as a
     * non-negative int. This also prevents truncating size_t to int. */
    if (buf == NULL || len > (size_t)WC_MAX_SINT_OF(int)) {
        return 0; /* BAD_FUNC_ARG; */
    }

    /* check to see if fits in existing length */
    if (buf->length > len) {
        buf->length = len;
        return (int)len;
    }

    /* check to see if fits in max buffer */
    if (buf->max >= len) {
        if (buf->data != NULL && zeroFill) {
            XMEMSET(&buf->data[buf->length], 0, len - buf->length);
        }
        buf->length = len;
        return (int)len;
    }

    /* expand size, to handle growth */
    mx = (len + 3) / 3 * 4;

#ifdef WOLFSSL_NO_REALLOC
    tmp = (char*)XMALLOC(mx, NULL, DYNAMIC_TYPE_OPENSSL);
    if (tmp != NULL && buf->data != NULL) {
       /* only the existing content is valid in the old buffer; copying
        * len_int (the new, larger size) would read past buf->max */
       XMEMCPY(tmp, buf->data, buf->length);
       XFREE(buf->data, NULL, DYNAMIC_TYPE_OPENSSL);
       buf->data = NULL;
    }
#else
    /* use realloc */
    tmp = (char*)XREALLOC(buf->data, mx, NULL, DYNAMIC_TYPE_OPENSSL);
#endif

    if (tmp == NULL) {
        return 0; /* ERR_R_MALLOC_FAILURE; */
    }
    buf->data = tmp;

    buf->max = mx;
    if (zeroFill)
        XMEMSET(&buf->data[buf->length], 0, len - buf->length);
    buf->length = len;

    return (int)len;

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
    size_t mx;

    /* verify provided arguments. The return value is an int, so reject any
     * len that cannot be represented as a positive int. */
    if (buf == NULL || len == 0 || len > (size_t)WC_MAX_SINT_OF(int)) {
        return 0; /* BAD_FUNC_ARG; */
    }

    if (len == buf->length)
        return (int)len;

    if (len > buf->length)
        return wolfSSL_BUF_MEM_grow_ex(buf, len, 0);

    /* expand size, to handle growth */
    mx = (len + 3) / 3 * 4;

    /* We want to shrink the internal buffer */
#ifdef WOLFSSL_NO_REALLOC
    tmp = (char*)XMALLOC(mx, NULL, DYNAMIC_TYPE_OPENSSL);
    if (tmp != NULL && buf->data != NULL)
    {
        XMEMCPY(tmp, buf->data, len);
        XFREE(buf->data,NULL,DYNAMIC_TYPE_OPENSSL);
        buf->data = NULL;
    }
#else
    tmp = (char*)XREALLOC(buf->data, mx, NULL, DYNAMIC_TYPE_OPENSSL);
#endif

    if (tmp == NULL)
        return 0;

    buf->data = tmp;
    buf->length = len;
    buf->max = mx;

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
