/* wolfkmod.c -- wolfssl FreeBSD kernel module.
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

#ifdef WOLFSSL_BSDKM

/* freebsd system includes */
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>

#if defined(BSDKM_CRYPTO_REGISTER)
    #include <opencrypto/cryptodev.h>
    #include <sys/bus.h>
    #include "cryptodev_if.h"
#endif

/* wolf includes */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif

#ifdef HAVE_FIPS
    #ifdef USE_CONTESTMUTEX
        #error USE_CONTESTMUTEX is incompatible with WOLFSSL_BSDKM
    #endif
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif /* HAVE_FIPS */

#if !defined(NO_CRYPT_TEST)
    #include <wolfcrypt/test/test.h>
#endif
#if defined(WOLFSSL_KERNEL_BENCHMARKS)
    #include <wolfcrypt/benchmark/benchmark.h>
#endif

#include <wolfssl/wolfcrypt/random.h>

MALLOC_DEFINE(M_WOLFSSL, "libwolfssl", "wolfSSL kernel memory");

#if defined(BSDKM_CRYPTO_REGISTER)
    #include "bsdkm/wolfkmod_aes.c"
#endif

/* common functions. */
static int  wolfkmod_init(void);
static int  wolfkmod_cleanup(void);
#if !defined(BSDKM_CRYPTO_REGISTER)
/* functions specific to a pure kernel module library build. */
static int  wolfkmod_load(void);
static int  wolfkmod_unload(void);
#else
/* functions specific to a kernel crypto driver module build. */
static void wolfkdriv_identify(driver_t * driver, device_t parent);
static int  wolfkdriv_probe(device_t dev);
static int  wolfkdriv_attach(device_t dev);
static int  wolfkdriv_detach(device_t dev);
static int  wolfkdriv_probesession(device_t dev,
                                   const struct crypto_session_params *csp);
static int  wolfkdriv_newsession(device_t dev, crypto_session_t cses,
                                 const struct crypto_session_params *csp);
static void wolfkdriv_freesession(device_t dev, crypto_session_t cses);
static int  wolfkdriv_process(device_t dev, struct cryptop *crp, int hint);
#endif /* !BSDKM_CRYPTO_REGISTER */

#if defined(WOLFSSL_AESNI) || defined(WOLFSSL_KERNEL_BENCHMARKS)
    #include "bsdkm/x86_vecreg.c"
#endif /* WOLFSSL_AESNI || WOLFSSL_KERNEL_BENCHMARKS*/

#ifdef HAVE_FIPS
    #define WOLFKMOD_FIPS_ERR_MSG(hash) ({                                   \
        printf("In-core integrity hash check failure.\n");                   \
        if ((hash))                                                          \
            printf("Rebuild with \"WOLFCRYPT_FIPS_CORE_HASH_VALUE=%s\".\n",  \
                   hash);                                                    \
        else                                                                 \
            printf("error: could not compute new hash. "                     \
                   "Contact customer support.\n");                           \
    })

    static void wolfkmod_fips_cb(int ok, int err, const char * hash)
    {
        if ((!ok) || (err != 0)) {
            printf("error: libwolfssl FIPS error: %s\n",
                   wc_GetErrorString(err));
        }

        if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            WOLFKMOD_FIPS_ERR_MSG(hash);
        }
    }
#endif /* HAVE_FIPS */

static int wolfkmod_init(void)
{
    int error = 0;

    #if defined(WOLFSSL_AESNI) || defined(WOLFSSL_KERNEL_BENCHMARKS)
    error = wolfkmod_vecreg_init();
    if (error != 0) {
        printf("error: wolfkmod_vecreg_init: %d\n", error);
        return (ECANCELED);
    }
    #endif /* WOLFSSL_AESNI || WOLFSSL_KERNEL_BENCHMARKS*/

    #ifdef HAVE_FIPS
    error = wolfCrypt_SetCb_fips(wolfkmod_fips_cb);
    if (error != 0) {
        printf("error: wolfCrypt_SetCb_fips failed: %s\n",
               wc_GetErrorString(error));
        return (ECANCELED);
    }

    fipsEntry();

    error = wolfCrypt_GetStatus_fips();
    if (error != 0) {
        printf("error: wolfCrypt_GetStatus_fips failed: %d: %s\n",
               error, wc_GetErrorString(error));
        if (error == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            WOLFKMOD_FIPS_ERR_MSG(newhash);
        }
        return (ECANCELED);
    }
    #endif /* HAVE_FIPS */

    #ifdef WC_RNG_SEED_CB
    error = wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
    if (error < 0) {
        printf("error: wc_SetSeed_Cb failed: %d\n", error);
        return (ECANCELED);
    }
    #endif /* WC_RNG_SEED_CB */

    #ifdef WOLFCRYPT_ONLY
    error = wolfCrypt_Init();
    if (error != 0) {
        printf("error: wolfCrypt_Init failed: %s\n", wc_GetErrorString(error));
        return (ECANCELED);
    }
    #else
    error = wolfSSL_Init();
    if (error != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Init failed: %s\n", wc_GetErrorString(error));
        return (ECANCELED);
    }
    #endif /* WOLFCRYPT_ONLY */

    #ifdef HAVE_FIPS
    error = wc_RunAllCast_fips();
    if (error != 0) {
        printf("error: wc_RunAllCast_fips failed with "
               "return value %d\n", error);
        return (ECANCELED);
    }
    else {
        printf("info: FIPS 140-3 wolfCrypt-fips v%d.%d.%d%s%s startup "
               "self-test succeeded.\n",
    #ifdef HAVE_FIPS_VERSION_MAJOR
            HAVE_FIPS_VERSION_MAJOR,
    #else
            HAVE_FIPS_VERSION,
    #endif
    #ifdef HAVE_FIPS_VERSION_MINOR
            HAVE_FIPS_VERSION_MINOR,
    #else
            0,
    #endif
    #ifdef HAVE_FIPS_VERSION_PATCH
            HAVE_FIPS_VERSION_PATCH,
    #else
            0,
    #endif
    #ifdef HAVE_FIPS_VERSION_PORT
            "-",
            HAVE_FIPS_VERSION_PORT
    #else
            "",
            ""
    #endif
        );
    }
    #endif /* HAVE_FIPS */

    return (0);
}

static int wolfkmod_cleanup(void)
{
    int error = 0;

    #ifdef WOLFCRYPT_ONLY
    error = wolfCrypt_Cleanup();
    if (error != 0) {
        printf("error: wolfCrypt_Cleanup failed: %s\n",
               wc_GetErrorString(error));
        error = ECANCELED;
        goto wolfkmod_cleanup_out;
    }
    #else
    error = wolfSSL_Cleanup();
    if (error != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_Cleanup failed: %s\n",
               wc_GetErrorString(error));
        error = ECANCELED;
        goto wolfkmod_cleanup_out;
    }
    #endif /* WOLFCRYPT_ONLY */

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: libwolfssl " LIBWOLFSSL_VERSION_STRING
           " cleanup complete.\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    error = 0;

wolfkmod_cleanup_out:
    #if defined(WOLFSSL_AESNI) || defined(WOLFSSL_KERNEL_BENCHMARKS)
    wolfkmod_vecreg_exit();
    #endif /* WOLFSSL_AESNI || WOLFSSL_KERNEL_BENCHMARKS*/

    return (error);
}

#if !defined(BSDKM_CRYPTO_REGISTER)
static int wolfkmod_load(void)
{
    int error = 0;

    error = wolfkmod_init();
    if (error != 0) {
        return (ECANCELED);
    }

    #ifndef NO_CRYPT_TEST
    error = wolfcrypt_test(NULL);
    if (error != 0) {
        printf("error: wolfcrypt test failed: %d\n", error);
        (void)wolfkmod_cleanup();
        return (ECANCELED);
    }
    printf("info: wolfCrypt self-test passed.\n");
    #endif /* NO_CRYPT_TEST */

    #ifdef WOLFSSL_KERNEL_BENCHMARKS
    error = benchmark_test(NULL);
    if (error != 0) {
        printf("error: wolfcrypt benchmark failed: %d\n", error);
        (void)wolfkmod_cleanup();
        return (ECANCELED);
    }
    printf("info: wolfCrypt benchmark passed.\n");
    #endif /* WOLFSSL_KERNEL_BENCHMARKS */

    printf("info: libwolfssl loaded\n");

    return (0);
}

static int wolfkmod_unload(void)
{
    int error = 0;

    #ifdef HAVE_FIPS
    error = wc_RunAllCast_fips();
    if (error != 0) {
        printf("error: wc_RunAllCast_fips failed at shutdown with "
               "return value %d\n", error);
    }
    else
        printf("info: wolfCrypt FIPS re-self-test succeeded at unload: "
               "all algorithms re-verified.\n");
    #endif

    error = wolfkmod_cleanup();

    if (error == 0) {
        printf("info: libwolfssl unloaded\n");
    }

    return (error);
}

#if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
static const char * wolfkmod_event_to_str(modeventtype_t what)
{
    switch (what) {
    case MOD_LOAD:
        return "MOD_LOAD";
    case MOD_UNLOAD:
        return "MOD_UNLOAD";
    case MOD_SHUTDOWN:
        return "MOD_SHUTDOWN";
    case MOD_QUIESCE:
        return "MOD_QUIESCE";
    }
}
#endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

/* see /usr/include/sys/module.h for more info. */
static int
wolfkmod_event(struct module * m, int what, void * arg)
{
    int error = 0;
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: wolfkmod_event: %s\n", wolfkmod_event_to_str(what));
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    switch (what) {
    case MOD_LOAD:
        error = wolfkmod_load();
        break;
    case MOD_UNLOAD:
        error = wolfkmod_unload();
        break;
    case MOD_SHUTDOWN:
    case MOD_QUIESCE:
    default:
        error = EOPNOTSUPP;
    }

    (void)m;
    (void)arg;

    return (error);
}
#endif /* !BSDKM_CRYPTO_REGISTER */

#if defined(BSDKM_CRYPTO_REGISTER)
/* wolfkdriv device driver software context. */
struct wolfkdriv_softc {
    int32_t  crid;
    device_t dev;
};

struct km_aes_ctx {
    Aes aes_encrypt;
    Aes aes_decrypt;
};

typedef struct km_aes_ctx km_aes_ctx;

struct wolfkdriv_session {
    km_aes_ctx aes_ctx;
    int32_t    crid;
    int        type;
    int        ivlen;
    int        klen;
};

typedef struct wolfkdriv_session wolfkdriv_session_t;

static void km_AesFree(Aes * aes) {
    if (aes == NULL) {
        return;
    }
    wc_AesFree(aes);
    #if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    ForceZero(aes, sizeof(*aes));
    #endif
}

static void wolfkdriv_aes_ctx_clear(km_aes_ctx * ctx)
{
    if (ctx != NULL) {
        km_AesFree(&ctx->aes_encrypt);
        km_AesFree(&ctx->aes_decrypt);
    }

    #ifdef WOLFKM_DEBUG_AES
    printf("info: exiting km_AesExitCommon\n");
    #endif /* WOLFKM_DEBUG_AES */
}

static void wolfkdriv_identify(driver_t * driver, device_t parent)
{
    (void)driver;

    /* don't double add wolfkdriv child. */
    if (device_find_child(parent, "libwolf", -1) != NULL) {
        return;
    }

    BUS_ADD_CHILD(parent, 10, "libwolf", -1);
}

static int wolfkdriv_probe(device_t dev)
{
    device_set_desc(dev, "wolfSSL crypto");
    return (BUS_PROBE_DEFAULT);
}

/*
 * unregister libwolfssl crypto driver
 */
static void wolfkdriv_unregister(struct wolfkdriv_softc * softc)
{
    if (softc && softc->crid >= 0) {
        crypto_unregister_all(softc->crid);
        device_printf(softc->dev, "info: crid unregistered: %d\n", softc->crid);
        softc->crid = -1;
    }

    return;
}

static int wolfkdriv_attach(device_t dev)
{
    struct wolfkdriv_softc * softc = NULL;
    int flags = CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC |
                CRYPTOCAP_F_ACCEL_SOFTWARE | CRYPTOCAP_F_HARDWARE;
    int ret = 0;
    int crid = 0;
    int error = 0;

    ret = wolfkmod_init();
    if (ret != 0) {
        return (ECANCELED);
    }

    /**
     * register wolfcrypt algs here with crypto_get_driverid.
     *
     * The crid is the literal index into the kernel crypto_drivers array:
     *   - crid >= 0 is valid.
     *   - crid <  0 is error.
     * */
    softc = device_get_softc(dev);
    softc->dev = dev;

    softc->crid = crypto_get_driverid(dev, sizeof(wolfkdriv_session_t), flags);
    if (softc->crid < 0) {
        device_printf(dev, "error: crypto_get_driverid failed: %d\n",
               softc->crid);
        return (ENXIO);
    }

    /*
     * various sanity checks
     */

    /* 1. we should find ourself by name */
    crid = crypto_find_driver("libwolf");

    if (crid != softc->crid) {
        device_printf(dev, "error: attach: got crid %d, expected %d\n", crid,
               softc->crid);
        error = ENXIO;
        goto attach_out;
    }

    /* 2. test various algs */
    error = wolfkdriv_test_aes(dev, crid);

    if (error) {
        device_printf(dev, "error: attach: test_aes: %d\n", error);
        error = ENXIO;
        goto attach_out;
    }

    device_printf(dev, "info: driver loaded: %d\n", crid);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting attach\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

attach_out:
    if (error) {
        wolfkdriv_unregister(softc);
        error = ENXIO;
    }

    return (error);
}

static int wolfkdriv_detach(device_t dev)
{
    struct wolfkdriv_softc * softc = NULL;
    int ret = 0;

    ret = wolfkmod_cleanup();

    if (ret == 0) {
        /* unregister wolfcrypt algs */
        softc = device_get_softc(dev);
        wolfkdriv_unregister(softc);
    }

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting detach\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (0);
}

static int wolfkdriv_probesession(device_t dev,
                                  const struct crypto_session_params *csp)
{
    struct wolfkdriv_softc * softc = NULL;
    int error = CRYPTODEV_PROBE_ACCEL_SOFTWARE;

    softc = device_get_softc(dev);

    switch (csp->csp_mode) {
    case CSP_MODE_CIPHER:
        switch (csp->csp_cipher_alg) {
        case CRYPTO_AES_CBC:
            break;
        default:
            error = EINVAL;
            break;
        }
        break;

    case CSP_MODE_AEAD:
        switch (csp->csp_cipher_alg) {
        case CRYPTO_AES_NIST_GCM_16:
            break;
        default:
            error = EINVAL;
            break;
        }
        break;
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
    default:
        error = EINVAL;
        break;
    }

    (void)softc;
    (void)csp;

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: probesession: mode=%d, cipher_alg=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    return (error);
}

static int wolfkdriv_newsession_aes(device_t dev,
                                    wolfkdriv_session_t * session,
                                    const struct crypto_session_params *csp)
{
    int error = 0;
    int klen = csp->csp_cipher_klen; /* key len in bytes */

    switch (csp->csp_cipher_alg) {
    case CRYPTO_AES_NIST_GCM_16:
        session->type = CRYPTO_AES_NIST_GCM_16;
        break;
    case CRYPTO_AES_CBC:
        session->type = CRYPTO_AES_CBC;
        break;
    default:
        return (EOPNOTSUPP);
    }

    if (klen != 16 && klen != 24 && klen != 32) {
        device_printf(dev, "info: newsession_cipher: invalid klen: %d\n", klen);
        return (EINVAL);
    }

    session->klen = klen;
    session->ivlen = csp->csp_ivlen;

    /* encrypt */
    error = wc_AesInit(&session->aes_ctx.aes_encrypt, NULL, INVALID_DEVID);
    if (error) {
        device_printf(dev, "error: newsession_cipher: aes init: %d\n", error);
        goto newsession_cipher_out;
    }

    if (session->type == CRYPTO_AES_CBC) {
        /* Need a separate decrypt structure for aes-cbc. */
        error = wc_AesInit(&session->aes_ctx.aes_decrypt, NULL, INVALID_DEVID);
        if (error) {
            device_printf(dev, "error: newsession_cipher: aes init: %d\n",
                          error);
            goto newsession_cipher_out;
        }
    }

newsession_cipher_out:

    if (error != 0) {
        wolfkdriv_aes_ctx_clear(&session->aes_ctx);
        return (EINVAL);
    }

    return (error);
}

static int wolfkdriv_newsession(device_t dev, crypto_session_t cses,
                                const struct crypto_session_params *csp)
{
    wolfkdriv_session_t * session = NULL;
    int error = 0;

    /* get the wolfkdriv_session_t context */
    session = crypto_get_driver_session(cses);

    switch (csp->csp_mode) {
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
        device_printf(dev, "info: not supported: %d\n", csp->csp_mode);
        error = EOPNOTSUPP;
        break;
    case CSP_MODE_CIPHER:
    case CSP_MODE_AEAD:
        error = wolfkdriv_newsession_aes(dev, session, csp);
        break;
    default:
        __assert_unreachable();
    }

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: newsession: mode=%d, cipher_alg=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (error);
}

static void
wolfkdriv_freesession(device_t dev, crypto_session_t cses)
{
    wolfkdriv_session_t * session = NULL;
    (void)dev;

    /* get the wolfkdriv_session_t context */
    session = crypto_get_driver_session(cses);

    /* clean it up */
    wolfkdriv_aes_ctx_clear(&session->aes_ctx);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: exiting freesession\n");
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */
    return;
}

static int wolfkdriv_cbc_work(device_t dev, wolfkdriv_session_t * session,
                              struct cryptop * crp,
                              const struct crypto_session_params * csp)
{
    struct crypto_buffer_cursor cc_in;
    struct crypto_buffer_cursor cc_out;
    const unsigned char * in_block = NULL;
    const unsigned char * in_seg = NULL;
    unsigned char *       out_block = NULL;
    unsigned char *       out_seg = NULL;
    Aes     aes;
    uint8_t iv[WC_AES_BLOCK_SIZE];
    uint8_t block[EALG_MAX_BLOCK_LEN];
    size_t  data_len = 0;
    size_t  seg_len = 0;
    size_t  in_len = 0;
    size_t  out_len = 0;
    int     error = 0;
    int     is_encrypt = 0;
    int     type = AES_ENCRYPTION;

    if (csp->csp_cipher_alg != CRYPTO_AES_CBC) {
        error = EINVAL;
        goto cbc_work_out;
    }

    data_len = crp->crp_payload_length;
    if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
        is_encrypt = 1;
        type = AES_ENCRYPTION;
        memcpy(&aes, &session->aes_ctx.aes_encrypt, sizeof(aes));
    }
    else {
        is_encrypt = 0;
        type = AES_DECRYPTION;
        memcpy(&aes, &session->aes_ctx.aes_decrypt, sizeof(aes));
    }

    /* must be multiple of block size */
    if (data_len % WC_AES_BLOCK_SIZE) {
        error = EINVAL;
        goto cbc_work_out;
    }

    crypto_read_iv(crp, iv);
    error = wc_AesSetKey(&aes, csp->csp_cipher_key,
                         csp->csp_cipher_klen, iv, type);
    if (error) {
        device_printf(dev, "error: wc_AesSetKey: %d\n", error);
        goto cbc_work_out;
    }

    /* set up the crypto buffers */
    crypto_cursor_init(&cc_in, &crp->crp_buf);
    crypto_cursor_advance(&cc_in, crp->crp_payload_start);

    in_seg = crypto_cursor_segment(&cc_in, &in_len);

    /* handle if the user supplied a separate out buffer. */
    if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
        crypto_cursor_init(&cc_out, &crp->crp_obuf);
        crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);
    }
    else {
        cc_out = cc_in;
    }

    out_seg = crypto_cursor_segment(&cc_out, &out_len);

    while (data_len) {
        /* set up input buffers */
        if (in_len < WC_AES_BLOCK_SIZE) {
            /* less than a block in segment */
            crypto_cursor_copydata(&cc_in, WC_AES_BLOCK_SIZE, block);
            in_block = block;
            in_len = WC_AES_BLOCK_SIZE;
        }
        else {
            in_block = in_seg;
        }

        /* set up output buffers */
        if (out_len < WC_AES_BLOCK_SIZE) {
            out_block = block;
            out_len = WC_AES_BLOCK_SIZE;
        }
        else {
            out_block = out_seg;
        }

        /* choose which of data_len, in_len, out_len, is shorter.
         * round down to multiple of aes block size. */
        seg_len = rounddown(MIN(data_len, MIN(in_len, out_len)),
                            WC_AES_BLOCK_SIZE);

        if (is_encrypt) {
            error = wc_AesCbcEncrypt(&aes, out_block, in_block, seg_len);
            if (error) {
                device_printf(dev, "error: wc_AesCbcEncrypt: %d\n", error);
                goto cbc_work_out;
            }
        }
        else {
            error = wc_AesCbcDecrypt(&aes, out_block, in_block, seg_len);
            if (error) {
                device_printf(dev, "error: wc_AesCbcEncrypt: %d\n", error);
                goto cbc_work_out;
            }
        }

        if (out_block == block) {
            /* we used the block as local output buffer. copy to cc_out,
             * and grab the next out cursor segment. */
            crypto_cursor_copyback(&cc_out, WC_AES_BLOCK_SIZE, block);
            out_seg = crypto_cursor_segment(&cc_out, &out_len);
        } else {
            /* we worked directly in cc_out. advance the cursor. */
            crypto_cursor_advance(&cc_out, seg_len);
            out_seg += seg_len;
            out_len -= seg_len;
        }

        if (in_block == block) {
            /* grab a new in cursor segment. */
            in_seg = crypto_cursor_segment(&cc_in, &in_len);
        } else {
            /* else advance existing in cursor. */
            crypto_cursor_advance(&cc_in, seg_len);
            in_seg += seg_len;
            in_len -= seg_len;
        }

        data_len -= seg_len;
    }

cbc_work_out:
    /* cleanup. */
    wc_ForceZero(iv, sizeof(iv));
    wc_ForceZero(block, sizeof(block));

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: cbc_work: mode=%d, cipher_alg=%d, "
                  "payload_length=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, crp->crp_payload_length,
                  error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (error);
}

static int wolfkdriv_gcm_work(device_t dev, wolfkdriv_session_t * session,
                              struct cryptop * crp,
                              const struct crypto_session_params * csp)
{
    struct crypto_buffer_cursor cc_in;
    struct crypto_buffer_cursor cc_out;
    const unsigned char *       in_seg = NULL;
    unsigned char *             out_seg = NULL;
    Aes     aes;
    uint8_t iv[WC_AES_BLOCK_SIZE];
    uint8_t auth_tag[WC_AES_BLOCK_SIZE];
    size_t  data_len = 0;
    size_t  seg_len = 0;
    size_t  in_len = 0;
    size_t  out_len = 0;
    int     error = 0;
    int     is_encrypt = 0;

    memcpy(&aes, &session->aes_ctx.aes_encrypt, sizeof(aes));

    if (csp->csp_cipher_alg != CRYPTO_AES_NIST_GCM_16) {
        error = EINVAL;
        goto gcm_work_out;
    }

    data_len = crp->crp_payload_length;
    if (CRYPTO_OP_IS_ENCRYPT(crp->crp_op)) {
        is_encrypt = 1;
    }
    else {
        is_encrypt = 0;
    }

    error = wc_AesGcmSetKey(&aes, csp->csp_cipher_key,
                            csp->csp_cipher_klen);
    if (error) {
        device_printf(dev, "error: wc_AesGcmSetKey: %d\n", error);
        goto gcm_work_out;
    }

    crypto_read_iv(crp, iv);
    error = wc_AesGcmInit(&aes, NULL /* key */, 0 /* keylen */,
                          iv, csp->csp_ivlen);
    if (error) {
        device_printf(dev, "error: wc_AesGcmInit: %d\n", error);
        goto gcm_work_out;
    }

    /* process aad first */
    if (crp->crp_aad != NULL) {
        /* they passed aad in separate buffer. */
        if (is_encrypt) {
            error = wc_AesGcmEncryptUpdate(&aes, NULL, NULL, 0,
                                           crp->crp_aad, crp->crp_aad_length);
        }
        else {
            error = wc_AesGcmDecryptUpdate(&aes, NULL, NULL, 0,
                                           crp->crp_aad, crp->crp_aad_length);
        }

        if (error) {
            error = EINVAL;
        }
    }
    else {
        /* we need to pull aad out of crp->crp_buf from crp_aad_start. */
        size_t aad_len = 0;

        crypto_cursor_init(&cc_in, &crp->crp_buf);
        crypto_cursor_advance(&cc_in, crp->crp_aad_start);

        for (aad_len = crp->crp_aad_length; aad_len > 0; aad_len -= seg_len) {
            in_seg = crypto_cursor_segment(&cc_in, &in_len);
            seg_len = MIN(aad_len, in_len);

            if (is_encrypt) {
                error = wc_AesGcmEncryptUpdate(&aes, NULL, NULL, 0,
                                               in_seg, seg_len);
            }
            else {
                error = wc_AesGcmDecryptUpdate(&aes, NULL, NULL, 0,
                                               in_seg, seg_len);
            }

            if (error) {
                error = EINVAL;
                goto gcm_work_out;
            }

            crypto_cursor_advance(&cc_in, seg_len);
        }
    }

    /*
     * process cipher/plaintext next
     */

    /* set up the crypto buffers */
    crypto_cursor_init(&cc_in, &crp->crp_buf);
    crypto_cursor_advance(&cc_in, crp->crp_payload_start);

    in_seg = crypto_cursor_segment(&cc_in, &in_len);

    /* handle if the user supplied a separate out buffer. */
    if (CRYPTO_HAS_OUTPUT_BUFFER(crp)) {
        crypto_cursor_init(&cc_out, &crp->crp_obuf);
        crypto_cursor_advance(&cc_out, crp->crp_payload_output_start);
    }
    else {
        cc_out = cc_in;
    }

    out_seg = crypto_cursor_segment(&cc_out, &out_len);

    while (data_len) {
        /* process through the available segments. */
        in_seg = crypto_cursor_segment(&cc_in, &in_len);
        out_seg = crypto_cursor_segment(&cc_out, &out_len);
        seg_len = MIN(data_len, MIN(in_len, out_len));

        if (is_encrypt) {
            error = wc_AesGcmEncryptUpdate(&aes, out_seg, in_seg, seg_len,
                                           NULL, 0);
            if (error) {
                device_printf(dev, "error: wc_AesGcmEncrypt: %d\n", error);
                goto gcm_work_out;
            }
        }
        else {
            error = wc_AesGcmDecryptUpdate(&aes, out_seg, in_seg, seg_len,
                                           NULL, 0);
            if (error) {
                device_printf(dev, "error: wc_AesGcmDecrypt: %d\n", error);
                goto gcm_work_out;
            }
        }

        /* advance the cursors by amount processed */
        crypto_cursor_advance(&cc_in, seg_len);
        crypto_cursor_advance(&cc_out, seg_len);

        data_len -= seg_len;
    }

    /* process auth tag finally */
    if (is_encrypt) {
        error = wc_AesGcmEncryptFinal(&aes, auth_tag, WC_AES_BLOCK_SIZE);
        if (error == 0) {
            crypto_copyback(crp, crp->crp_digest_start, WC_AES_BLOCK_SIZE,
                            auth_tag);
        }
    }
    else {
        crypto_copydata(crp, crp->crp_digest_start, WC_AES_BLOCK_SIZE,
                        auth_tag);
        error = wc_AesGcmDecryptFinal(&aes, auth_tag, WC_AES_BLOCK_SIZE);
        if (error) {
            error = EBADMSG;
        }
    }

gcm_work_out:
    /* cleanup. */
    wc_ForceZero(iv, sizeof(iv));
    wc_ForceZero(auth_tag, sizeof(auth_tag));

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: gcm_work: mode=%d, cipher_alg=%d, "
                  "payload_length=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, crp->crp_payload_length,
                  error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (error);
}

static int wolfkdriv_process(device_t dev, struct cryptop * crp, int hint)
{
    const struct crypto_session_params * csp = NULL;
    wolfkdriv_session_t * session = NULL;
    int error = 0;
    (void)hint;

    session = crypto_get_driver_session(crp->crp_session);
    csp = crypto_get_params(crp->crp_session);

    switch (csp->csp_mode) {
    case CSP_MODE_CIPHER:
        error = wolfkdriv_cbc_work(dev, session, crp, csp);
        break;
    case CSP_MODE_DIGEST:
    case CSP_MODE_ETA:
        error = EINVAL;
        break;
    case CSP_MODE_AEAD:
        error = wolfkdriv_gcm_work(dev, session, crp, csp);
        break;
    default:
        __assert_unreachable();
    }

    crp->crp_etype = error;
    crypto_done(crp);

    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: process: mode=%d, cipher_alg=%d, error=%d\n",
                  csp->csp_mode, csp->csp_cipher_alg, error);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    return (error);
}

/*
 * wolfkmod as a crypto device driver.
 */
static device_method_t wolfkdriv_methods[] = {
    /* device interface methods: called during device setup, etc. */
    DEVMETHOD(device_identify, wolfkdriv_identify),
    DEVMETHOD(device_probe, wolfkdriv_probe),
    DEVMETHOD(device_attach, wolfkdriv_attach),
    DEVMETHOD(device_detach, wolfkdriv_detach),

    /* crypto device session methods: called during crypto session setup,
     * work, etc. */
    DEVMETHOD(cryptodev_probesession, wolfkdriv_probesession),
    DEVMETHOD(cryptodev_newsession, wolfkdriv_newsession),
    DEVMETHOD(cryptodev_freesession, wolfkdriv_freesession),
    DEVMETHOD(cryptodev_process, wolfkdriv_process),

    DEVMETHOD_END
};

static driver_t wolfkdriv_driver = {
    .name = "libwolf",
    .methods = wolfkdriv_methods,
    .size = sizeof(struct wolfkdriv_softc),
};

/* on x86, software-only drivers usually attach to nexus bus. */
DRIVER_MODULE(libwolfssl, nexus, wolfkdriv_driver, NULL, NULL);
#endif /* BSDKM_CRYPTO_REGISTER */

#if !defined(BSDKM_CRYPTO_REGISTER)
/*
 * wolfkmod as a pure kernel module.
 */
static moduledata_t libwolfmod = {
    #ifdef HAVE_FIPS
    "libwolfssl_fips",   /* module name */
    #else
    "libwolfssl",   /* module name */
    #endif /* HAVE_FIPS */
    wolfkmod_event, /* module event handler */
    NULL            /* extra data, unused */
};

DECLARE_MODULE(libwolfssl, libwolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* !BSDKM_CRYPTO_REGISTER */

MODULE_VERSION(libwolfssl, 1);
#endif /* WOLFSSL_BSDKM */
