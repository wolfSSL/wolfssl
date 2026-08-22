/* lkcapi_lms_glue.c -- glue logic to register LMS/HSS (RFC 8554, SP 800-208)
 * wolfCrypt implementations with the Linux Kernel Cryptosystem
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

/* included by linuxkm/lkcapi_glue.c */
#ifndef WC_SKIP_INCLUDED_C_FILES

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_lms_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

/* LMS/HSS (RFC 8554, NIST SP 800-208) glue.  VERIFY-ONLY, deliberately:
 * LMS is a stateful hash-based signature scheme -- each signing operation
 * consumes a one-time-signature key, and reusing one voids all security.
 * Safe signing therefore requires durable, synchronized private-key state
 * (wc_LmsKey signing requires read/write state callbacks), for which the
 * kernel crypto API has no contract, and mismanaged state in-kernel would
 * be an OTS-reuse hazard.  SP 800-208 confines signing to controlled
 * (hardware) modules; verification has no state.  The sign/set_priv_key
 * callbacks are -EOPNOTSUPP stubs, following the convention of the
 * in-tree ML-DSA implementation (crypto/mldsa.c) for unsupported
 * operations.
 *
 * The kernel has no in-tree LMS implementation on any version, hence no
 * CONFIG_CRYPTO_LMS to pivot on for LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG,
 * and no config-conflict check either -- the alg is registered for
 * LINUXKM_LKCAPI_REGISTER_ALL, or by explicit request only.
 *
 * Calling conventions (wolfSSL-defined -- no in-tree or OpenSSL
 * precedent for kernel LMS):
 *   - the cra_name is "lms"; the key and signature formats are the HSS
 *     forms of RFC 8554 (a 1-level HSS key/signature wraps a plain LMS
 *     key/signature), which self-describe the parameter set: set_pub_key
 *     takes the raw HSS public key (levels || lms_type || ots_type ||
 *     I || T[root]), from which the parameters are derived and
 *     validated by wc_LmsKey_ImportPubRaw().
 *   - verify takes the raw HSS signature as src and the raw unhashed
 *     message, of any length, as the "digest" argument.  Signature size
 *     mismatches and verification failures both return -EBADMSG,
 *     following the convention of the in-tree ML-DSA.
 *   - key_size returns the public key size in BYTES on all kernel
 *     versions, and digest_size is not set, both mirroring the in-tree
 *     ML-DSA conventions for the PQC signature family.
 *
 * Because the "lms" cra_name is unknown to crypto/testmgr.c, alg_test()
 * takes its "notest" path and returns success at registration time, with
 * or without fips_enabled.  KATs are instead supplied by
 * linuxkm_test_lms() below.
 */

#if defined(WOLFSSL_HAVE_LMS)
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL) &&       \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_LMS) && \
        !defined(LINUXKM_LKCAPI_REGISTER_LMS)
        #define LINUXKM_LKCAPI_REGISTER_LMS
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_LMS
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_LMS

#include <wolfssl/wolfcrypt/wc_lms.h>

/* The LMS acceleration qualifier is borrowed from that of the underlying hash
 * functions.
 */
#if defined(USE_INTEL_SPEEDUP)
    #ifndef NO_AVX2_SUPPORT
        #define WOLFKM_LMS_DRIVER_ISA_EXT "-avx2"
    #else
        #define WOLFKM_LMS_DRIVER_ISA_EXT "-avx"
    #endif
#else
    #define WOLFKM_LMS_DRIVER_ISA_EXT ""
#endif

#define WOLFKM_LMS_DRIVER_SUFFIX \
    WOLFKM_LMS_DRIVER_ISA_EXT WOLFKM_DRIVER_SUFFIX_BASE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
    /* as with ecdsa (see lkcapi_ecdsa_glue.c), registered as struct
     * sig_alg on linux 6.13+, and as a verify-capable struct
     * akcipher_alg on earlier kernels. */
    #define LINUXKM_LMS_SIG_ALG
#endif

#ifdef LINUXKM_LMS_SIG_ALG
    #define lms_tfm_type   crypto_sig
    #define lms_tfm_ctx_cb crypto_sig_ctx
#else
    #define lms_tfm_type   crypto_akcipher
    #define lms_tfm_ctx_cb akcipher_tfm_ctx
#endif /* !LINUXKM_LMS_SIG_ALG */

#define WOLFKM_LMS_NAME   ("lms")
#define WOLFKM_LMS_DRIVER ("lms" WOLFKM_LMS_DRIVER_SUFFIX)

static int linuxkm_test_lms(void);

static int lms_loaded = 0;

/* wc_LmsKey_Verify() is read-only on the key -- it allocates and frees
 * its own transient working state (LmsState) internally -- so a single
 * imported key per tfm is safe under the kernel crypto API's concurrent
 * use of a tfm, and no per-operation key reconstruction is needed. */
struct km_lms_ctx {
    LmsKey * key;
    int      pub_set;
};

static void         km_lms_exit(struct lms_tfm_type *tfm);
static int          km_lms_init(struct lms_tfm_type *tfm);
static int          km_lms_set_pub(struct lms_tfm_type *tfm,
                                   const void *key, unsigned int keylen);
static int          km_lms_set_priv(struct lms_tfm_type *tfm,
                                    const void *key, unsigned int keylen);
#ifdef LINUXKM_LMS_SIG_ALG
static unsigned int km_lms_key_size(struct crypto_sig *tfm);
static unsigned int km_lms_max_size(struct crypto_sig *tfm);
static int          km_lms_verify(struct crypto_sig *tfm,
                                  const void *src, unsigned int slen,
                                  const void *digest, unsigned int dlen);
static int          km_lms_sign(struct crypto_sig *tfm,
                                const void *src, unsigned int slen,
                                void *dst, unsigned int dlen);
#else
static unsigned int km_lms_max_size(struct crypto_akcipher *tfm);
static int          km_lms_verify(struct akcipher_request *req);
static int          km_lms_sign(struct akcipher_request *req);
#endif /* !LINUXKM_LMS_SIG_ALG */

#ifdef LINUXKM_LMS_SIG_ALG
static struct sig_alg lms = {
    .base.cra_name        = WOLFKM_LMS_NAME,
    .base.cra_driver_name = WOLFKM_LMS_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_lms_ctx),
    .sign                 = km_lms_sign,
    .verify               = km_lms_verify,
    .set_pub_key          = km_lms_set_pub,
    .set_priv_key         = km_lms_set_priv,
    .key_size             = km_lms_key_size,
    /* no .digest_size: crypto/sig.c defaults it (key_size on
     * < 6.15.3; keysize-bits/8 on >= 6.15.3) -- pub bytes in
     * both eras given km_lms_key_size() above. */
    .max_size             = km_lms_max_size,
    .init                 = km_lms_init,
    .exit                 = km_lms_exit,
};
#else /* !LINUXKM_LMS_SIG_ALG */
static struct akcipher_alg lms = {
    .base.cra_name        = WOLFKM_LMS_NAME,
    .base.cra_driver_name = WOLFKM_LMS_DRIVER,
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,
    .base.cra_module      = THIS_MODULE,
    .base.cra_ctxsize     = sizeof(struct km_lms_ctx),
    .sign                 = km_lms_sign,
    .verify               = km_lms_verify,
    .set_pub_key          = km_lms_set_pub,
    .set_priv_key         = km_lms_set_priv,
    .max_size             = km_lms_max_size,
    .init                 = km_lms_init,
    .exit                 = km_lms_exit,
};
#endif /* !LINUXKM_LMS_SIG_ALG */

static int km_lms_init(struct lms_tfm_type *tfm)
{
    struct km_lms_ctx *ctx = lms_tfm_ctx_cb(tfm);
    int ret;

    XMEMSET(ctx, 0, sizeof(struct km_lms_ctx));

    ctx->key = (LmsKey *)malloc(sizeof(LmsKey));
    if (! ctx->key)
        return -ENOMEM;

    ret = wc_LmsKey_Init(ctx->key, NULL /* heap */, INVALID_DEVID);
    if (ret < 0) {
        free(ctx->key);
        ctx->key = NULL;
        return -ENOMEM;
    }

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: exiting km_lms_init\n");
    #endif
    return 0;
}

static void km_lms_exit(struct lms_tfm_type *tfm)
{
    struct km_lms_ctx *ctx = lms_tfm_ctx_cb(tfm);

    if (ctx->key) {
        wc_LmsKey_Free(ctx->key);
        free(ctx->key);
        ctx->key = NULL;
    }

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: exiting km_lms_exit\n");
    #endif
    return;
}

/*
 * Sets the LMS/HSS public key.
 *
 * tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * key     raw RFC 8554 HSS public key (levels || lms_type ||
 *         ots_type || I || T[root]); the parameter set is derived
 *         from, and validated against, the encoded fields
 * keylen  key length
 */
static int km_lms_set_pub(struct lms_tfm_type *tfm, const void *key,
                          unsigned int keylen)
{
    struct km_lms_ctx * ctx = lms_tfm_ctx_cb(tfm);
    int                 err;

    if (key == NULL)
        return -EINVAL;

    if (ctx->key == NULL)
        return -EINVAL;

    /* Reset the key for (re)import. */
    wc_LmsKey_Free(ctx->key);
    ctx->pub_set = 0;
    err = wc_LmsKey_Init(ctx->key, NULL /* heap */, INVALID_DEVID);
    if (err != 0)
        return -ENOMEM;

    /* Derives and validates the parameter set from the raw key
     * (NOT_COMPILED_IN if the set isn't built in). */
    err = wc_LmsKey_ImportPubRaw(ctx->key, (const byte *)key, keylen);
    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_LMS
        pr_err("%s: wc_LmsKey_ImportPubRaw failed: %d\n",
               WOLFKM_LMS_DRIVER, err);
        #endif
        return -EINVAL;
    }

    ctx->pub_set = 1;

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: exiting km_lms_set_pub %d\n", keylen);
    #endif
    return 0;
}

/* LMS signing is stateful and unsupported here -- see the header
 * comment.  Stub convention per the in-tree ML-DSA (crypto/mldsa.c).
 */
static int km_lms_set_priv(struct lms_tfm_type *tfm, const void *key,
                           unsigned int keylen)
{
    (void)tfm;
    (void)key;
    (void)keylen;
    return -EOPNOTSUPP;
}

#ifdef LINUXKM_LMS_SIG_ALG
/* The public key size (0 before set_pub_key): BYTES on kernels
 * < 6.15.3, BITS on >= 6.15.3 (crypto_sig_keysize() semantics changed;
 * crypto_sig_digestsize() then derives bytes as keysize/8 -- see
 * lkcapi_ed_glue.c). */
static unsigned int km_lms_key_size(struct crypto_sig *tfm)
{
    struct km_lms_ctx *ctx = crypto_sig_ctx(tfm);
    word32             len = 0;

    if ((! ctx->pub_set) ||
        (wc_LmsKey_GetPubLen(ctx->key, &len) != 0))
    {
        return 0;
    }
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
    return (unsigned int)len * 8U; /* bits */
    #else
    return (unsigned int)len;      /* bytes */
    #endif
}

static unsigned int km_lms_max_size(struct crypto_sig *tfm)
{
    struct km_lms_ctx *ctx = crypto_sig_ctx(tfm);
    word32             len = 0;

    if ((! ctx->pub_set) ||
        (wc_LmsKey_GetSigLen(ctx->key, &len) != 0))
    {
        return 0;
    }
    return len;
}
#else /* !LINUXKM_LMS_SIG_ALG */
static unsigned int km_lms_max_size(struct crypto_akcipher *tfm)
{
    struct km_lms_ctx *ctx = akcipher_tfm_ctx(tfm);
    word32             len = 0;

    if ((! ctx->pub_set) ||
        (wc_LmsKey_GetSigLen(ctx->key, &len) != 0))
    {
        return 0;
    }
    return len;
}
#endif /* !LINUXKM_LMS_SIG_ALG */

/* Shared verify core.  returns 0, -EBADMSG (size mismatch or
 * verification failure, per the in-tree ML-DSA convention), or
 * -EINVAL.
 */
static int km_lms_verify_common(struct km_lms_ctx *ctx,
                                const byte *sig, word32 sig_len,
                                const byte *msg, word32 msg_len)
{
    word32 exp_sig_len = 0;
    int    err;

    if (! ctx->pub_set)
        return -EINVAL;

    if (wc_LmsKey_GetSigLen(ctx->key, &exp_sig_len) != 0)
        return -EINVAL;

    if (sig_len != exp_sig_len)
        return -EBADMSG;

    /* wc_LmsKey_Verify()'s message length parameter is an int. */
    if (msg_len > (word32)INT_MAX)
        return -EINVAL;

    err = wc_LmsKey_Verify(ctx->key, sig, sig_len, msg, (int)msg_len);

    if (err) {
        #ifdef WOLFKM_DEBUG_LMS
        pr_err("error: %s: lms verify returned: %d\n",
               WOLFKM_LMS_DRIVER, err);
        #endif
        return -EBADMSG;
    }
    return 0;
}

#ifdef LINUXKM_LMS_SIG_ALG

/*
 * Verify an LMS/HSS signature (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw RFC 8554 HSS signature; slen must equal the signature
 *     size for the imported public key's parameter set.
 *
 * digest:
 *   - the raw message; no prehashing occurs, and dlen is unrestricted
 *     (up to INT_MAX).
 */
static int km_lms_verify(struct crypto_sig *tfm,
                         const void *src, unsigned int slen,
                         const void *digest, unsigned int dlen)
{
    struct km_lms_ctx *ctx = crypto_sig_ctx(tfm);
    int                err;

    if (src == NULL || digest == NULL)
        return -EINVAL;

    err = km_lms_verify_common(ctx, (const byte *)src, (word32)slen,
                               (const byte *)digest, (word32)dlen);

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: exiting km_lms_verify dlen %d, slen %d, err %d\n",
            dlen, slen, err);
    #endif
    return err;
}

/* LMS signing is stateful and unsupported here -- see the header
 * comment. */
static int km_lms_sign(struct crypto_sig *tfm,
                       const void *src, unsigned int slen,
                       void *dst, unsigned int dlen)
{
    (void)tfm;
    (void)src;
    (void)slen;
    (void)dst;
    (void)dlen;
    return -EOPNOTSUPP;
}

#else /* !LINUXKM_LMS_SIG_ALG */

/*
 * Verify an LMS/HSS signature.
 *
 * The total size of req->src is src_len + dst_len:
 *   - src_len: signature (raw RFC 8554 HSS form, exact size for the
 *     imported public key's parameter set)
 *   - dst_len: message (raw, unhashed, any length up to INT_MAX)
 *
 * dst should be null.
 */
static int km_lms_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_lms_ctx *      ctx = NULL;
    byte *                   sig = NULL;
    word32                   sig_len = 0;
    byte *                   msg = NULL;
    word32                   msg_len = 0;
    int                      err = -1;

    if (req->src == NULL || req->dst != NULL)
        return -EINVAL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    sig_len = req->src_len;
    msg_len = req->dst_len;

    /* Reject a wrong-size signature before allocating from the
     * caller-supplied lengths (km_lms_verify_common() re-checks); a bare
     * overflow check still admits a multi-GB allocation driven by
     * req->src_len.
     */
    {
        word32 exp_sig_len = 0;
        if (wc_LmsKey_GetSigLen(ctx->key, &exp_sig_len) != 0)
            return -EINVAL;
        if (sig_len != exp_sig_len)
            return -EBADMSG;
    }

    if ((sig_len + msg_len) != ((word64)sig_len + (word64)msg_len))
        return -EINVAL;

    sig = malloc(sig_len + msg_len);
    if (unlikely(sig == NULL))
        return -ENOMEM;

    msg = sig + sig_len;

    XMEMSET(sig, 0, sig_len + msg_len);

    scatterwalk_map_and_copy(sig, req->src, 0, sig_len + msg_len, 0);

    err = km_lms_verify_common(ctx, sig, sig_len, msg, msg_len);

    free(sig);

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: exiting km_lms_verify msg_len %d, sig_len %d, "
            "err %d\n", msg_len, sig_len, err);
    #endif
    return err;
}

/* LMS signing is stateful and unsupported here -- see the header
 * comment.
 */
static int km_lms_sign(struct akcipher_request *req)
{
    (void)req;
    return -EOPNOTSUPP;
}

#endif /* !LINUXKM_LMS_SIG_ALG */

#ifdef LINUXKM_LMS_SIG_ALG

static int linuxkm_test_lms_driver(const char * driver,
                                   const byte * pub, word32 pub_len,
                                   const byte * sig, word32 sig_len,
                                   const byte * msg, word32 msg_len)
{
    int                 test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                 ret = 0;
    struct crypto_sig * tfm = NULL;
    byte *              sig_copy = NULL;
    byte                dummy[1] = { 0 };

    sig_copy = (byte *)malloc(sig_len);
    if (! sig_copy) {
        pr_err("error: allocating sig_copy buffer failed.\n");
        test_rc = MEMORY_E;
        goto test_lms_end;
    }
    XMEMCPY(sig_copy, sig, sig_len);

    tfm = crypto_alloc_sig(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating sig algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_lms_end;
    }

    ret = crypto_sig_set_pubkey(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_sig_set_pubkey returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    {
        /* keysize is bits on >= 6.15.3, bytes before (see
         * km_lms_key_size()); digestsize resolves to the pub key
         * size in bytes in both eras (no digest_size callback). */
        unsigned int maxsize = crypto_sig_maxsize(tfm);
        unsigned int keysize = crypto_sig_keysize(tfm);
        unsigned int digestsize = crypto_sig_digestsize(tfm);
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
        unsigned int exp_keysize = pub_len * 8U;
        #else
        unsigned int exp_keysize = pub_len;
        #endif

        if ((keysize != exp_keysize) || (maxsize != sig_len) ||
            (digestsize != pub_len))
        {
            pr_err("error: crypto_sig_{max, key, digest}size returned "
                   "{%u, %u, %u}, expected {%u, %u, %u}\n",
                   maxsize, keysize, digestsize, sig_len, exp_keysize,
                   pub_len);
            test_rc = BAD_FUNC_ARG;
            goto test_lms_end;
        }
    }

    ret = crypto_sig_verify(tfm, sig_copy, sig_len, msg, msg_len);
    if (ret) {
        pr_err("error: crypto_sig_verify returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    /* corrupt the signature -- verify should now fail. */
    sig_copy[sig_len / 2] ^= 1U;

    ret = crypto_sig_verify(tfm, sig_copy, sig_len, msg, msg_len);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_sig_verify returned %d, expected %d\n",
               ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }
    sig_copy[sig_len / 2] ^= 1U;

    /* a wrong-size signature must also fail with -EBADMSG. */
    ret = crypto_sig_verify(tfm, sig_copy, sig_len - 1, msg, msg_len);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_sig_verify (short sig) returned %d, "
               "expected %d\n", ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    /* signing is stateful and unsupported -- the stubs must report
     * -EOPNOTSUPP. */
    ret = crypto_sig_set_privkey(tfm, dummy, sizeof(dummy));
    if (ret != -EOPNOTSUPP) {
        pr_err("error: crypto_sig_set_privkey returned %d, "
               "expected %d\n", ret, -EOPNOTSUPP);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }
    ret = crypto_sig_sign(tfm, msg, msg_len, sig_copy, sig_len);
    if (ret != -EOPNOTSUPP) {
        pr_err("error: crypto_sig_sign returned %d, expected %d\n",
               ret, -EOPNOTSUPP);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    test_rc = 0;
test_lms_end:
    if (tfm)
        crypto_free_sig(tfm);
    free(sig_copy);

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#else /* !LINUXKM_LMS_SIG_ALG */

static int linuxkm_test_lms_driver(const char * driver,
                                   const byte * pub, word32 pub_len,
                                   const byte * sig, word32 sig_len,
                                   const byte * msg, word32 msg_len)
{
    int                       test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                       ret = 0;
    struct crypto_akcipher *  tfm = NULL;
    struct akcipher_request * req = NULL;
    struct scatterlist        src_tab[2];
    byte *                    param_copy = NULL;
    byte *                    bad_sig = NULL;
    byte                      dummy[1] = { 0 };

    param_copy = (byte *)malloc(sig_len + msg_len);
    if (! param_copy) {
        pr_err("error: allocating param_copy buffer failed.\n");
        test_rc = MEMORY_E;
        goto test_lms_end;
    }
    XMEMCPY(param_copy, sig, sig_len);
    sig = param_copy;
    XMEMCPY(param_copy + sig_len, msg, msg_len);
    msg = param_copy + sig_len;

    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_lms_end;
    }

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (! req) {
        test_rc = -ENOMEM;
        pr_err("error: allocating akcipher request %s failed\n",
               driver);
        goto test_lms_end;
    }

    ret = crypto_akcipher_set_pub_key(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    {
        unsigned int maxsize = crypto_akcipher_maxsize(tfm);
        if (maxsize != sig_len) {
            pr_err("error: crypto_akcipher_maxsize returned %u, "
                   "expected %u\n", maxsize, sig_len);
            test_rc = BAD_FUNC_ARG;
            goto test_lms_end;
        }
    }

    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], sig, sig_len);
    sg_set_buf(&src_tab[1], msg, msg_len);
    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, msg_len);

    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    bad_sig = malloc(sig_len);
    if (bad_sig == NULL) {
        pr_err("error: alloc sig failed\n");
        test_rc = MEMORY_E;
        goto test_lms_end;
    }

    XMEMCPY(bad_sig, sig, sig_len);
    bad_sig[sig_len / 2] ^= 1;

    sg_init_table(src_tab, 2);
    sg_set_buf(&src_tab[0], bad_sig, sig_len);
    sg_set_buf(&src_tab[1], msg, msg_len);
    akcipher_request_set_crypt(req, src_tab, NULL, sig_len, msg_len);

    ret = crypto_akcipher_verify(req);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_akcipher_verify returned %d, expected "
               "%d\n", ret, -EBADMSG);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    /* signing is stateful and unsupported -- the stubs must report
     * -EOPNOTSUPP. */
    ret = crypto_akcipher_set_priv_key(tfm, dummy, sizeof(dummy));
    if (ret != -EOPNOTSUPP) {
        pr_err("error: crypto_akcipher_set_priv_key returned %d, "
               "expected %d\n", ret, -EOPNOTSUPP);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }
    ret = crypto_akcipher_sign(req);
    if (ret != -EOPNOTSUPP) {
        pr_err("error: crypto_akcipher_sign returned %d, expected %d\n",
               ret, -EOPNOTSUPP);
        test_rc = BAD_FUNC_ARG;
        goto test_lms_end;
    }

    test_rc = 0;
test_lms_end:
    if (req) { akcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_akcipher(tfm); tfm = NULL; }
    if (param_copy) { free(param_copy); }
    if (bad_sig) { free(bad_sig); bad_sig = NULL; }

    #ifdef WOLFKM_DEBUG_LMS
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#endif /* !LINUXKM_LMS_SIG_ALG */

static int linuxkm_test_lms(void)
{
    /* reference vectors from wolfcrypt/test/test.c (lms_L1H10W8_*):
     * HSS with levels=1, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8. */
    static const byte lms_pub[] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x04, 0xa1, 0x26, 0x76, 0xf8,
        0xbb, 0x0b, 0xc0, 0x82, 0x21, 0x71, 0x0b, 0x2e,
        0x8c, 0xa6, 0xef, 0x12, 0xed, 0x41, 0x0e, 0x8c,
        0xaf, 0x11, 0x93, 0x34, 0x7b, 0x49, 0x79, 0xb7,
        0xde, 0x63, 0x1c, 0xfe, 0x1f, 0xd1, 0x17, 0x49,
        0xcd, 0x5c, 0xd4, 0x26, 0xa0, 0x53, 0x26, 0x1a,
        0xc5, 0xb4, 0x8f, 0x23
    };

    static const byte lms_msg_a[] = {
        0x77, 0x6f, 0x6c, 0x66, 0x53, 0x53, 0x4c, 0x20,
        0x4c, 0x4d, 0x53, 0x20, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x73,
        0x61, 0x67, 0x65, 0x21
    };

    static const byte lms_sig[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x04, 0x18, 0x70, 0x09, 0x2e,
        0x21, 0xc9, 0x6a, 0xc9, 0x5c, 0xb6, 0xb0, 0xaa,
        0xc3, 0xed, 0x6e, 0x66, 0x2f, 0xcc, 0x45, 0x81,
        0xbc, 0xba, 0x44, 0x96, 0x1c, 0xbf, 0x4e, 0xfb,
        0x7a, 0x46, 0xfb, 0xbe, 0x9a, 0x0c, 0xe4, 0x50,
        0x90, 0xc7, 0x92, 0xac, 0x53, 0xae, 0x53, 0x76,
        0x29, 0xa6, 0x65, 0xf1, 0x09, 0xed, 0x1a, 0x8e,
        0x03, 0x2e, 0x5a, 0x06, 0x51, 0xe3, 0x1e, 0xe6,
        0xf6, 0xfe, 0x3a, 0x6e, 0xd1, 0x92, 0x31, 0x1d,
        0xa1, 0x6a, 0x5c, 0x30, 0x3a, 0xc7, 0xfd, 0x5b,
        0xfe, 0x71, 0x2c, 0x5c, 0x2f, 0x5b, 0x5b, 0xcf,
        0xbc, 0x7f, 0xbf, 0x6c, 0xaf, 0x44, 0x8a, 0xae,
        0x14, 0x60, 0xab, 0x88, 0xed, 0x0e, 0x4f, 0xf8,
        0xc7, 0x1b, 0x74, 0x28, 0x72, 0xb3, 0x96, 0xa6,
        0xe6, 0x46, 0x22, 0x82, 0xcf, 0x1f, 0x4d, 0xa6,
        0xea, 0x22, 0x06, 0x07, 0x52, 0xf5, 0x26, 0x16,
        0x0b, 0x90, 0xe3, 0xff, 0x64, 0xa9, 0xe4, 0x61,
        0x1e, 0x9c, 0x12, 0x9c, 0xf6, 0xd4, 0x63, 0x29,
        0xea, 0x02, 0xf7, 0x18, 0x52, 0x79, 0x6c, 0x43,
        0xdc, 0xcf, 0x43, 0x23, 0xb9, 0xcc, 0x4a, 0x25,
        0x9d, 0x10, 0xaf, 0xa3, 0xe6, 0x47, 0x5a, 0x1c,
        0xfe, 0x68, 0x89, 0xaf, 0x1b, 0x2d, 0x88, 0x3e,
        0xca, 0xdc, 0x70, 0xea, 0xac, 0x11, 0x00, 0x8a,
        0x6e, 0xe0, 0xc7, 0xd0, 0xd2, 0x1a, 0x36, 0x18,
        0x97, 0xb3, 0x5f, 0x0e, 0x75, 0x48, 0x28, 0xf8,
        0xa8, 0xf5, 0x90, 0xd1, 0xa1, 0x84, 0xfb, 0xa4,
        0xad, 0x50, 0xbe, 0xe9, 0x39, 0x8c, 0xc5, 0xa1,
        0x67, 0x51, 0xa1, 0x8c, 0xd6, 0x6b, 0x97, 0x1f,
        0x47, 0x99, 0xee, 0xe0, 0x70, 0x01, 0xc7, 0x07,
        0x50, 0xf3, 0x5e, 0x3f, 0xe7, 0x06, 0xd6, 0x8d,
        0x26, 0xd6, 0x5a, 0x59, 0x18, 0x72, 0x6b, 0x12,
        0xd2, 0xaf, 0x9b, 0xb4, 0x2b, 0xd0, 0xb2, 0xf2,
        0x96, 0x2f, 0x40, 0xea, 0xbe, 0xe6, 0xac, 0x1f,
        0xb8, 0x33, 0xc2, 0x76, 0xdc, 0x8c, 0xac, 0xc1,
        0x46, 0x5e, 0x04, 0x84, 0x1b, 0xc8, 0xb9, 0x65,
        0x8d, 0xad, 0x96, 0xb5, 0xb1, 0xf6, 0x17, 0x4a,
        0x19, 0x87, 0xe7, 0xbf, 0x29, 0xc7, 0x9b, 0xb9,
        0xd6, 0x11, 0x2c, 0x92, 0x2f, 0xb7, 0x24, 0xd5,
        0x01, 0x1d, 0x80, 0x37, 0x54, 0xed, 0x33, 0x32,
        0xab, 0x7a, 0x12, 0xd4, 0x02, 0x1d, 0x27, 0x52,
        0x89, 0xdb, 0x32, 0xbf, 0x61, 0xd4, 0xbb, 0xb4,
        0x46, 0x78, 0x1b, 0x64, 0x17, 0x84, 0x4b, 0x8a,
        0xba, 0xc6, 0xc1, 0xcf, 0xc7, 0x5d, 0x8f, 0x93,
        0xc5, 0x9a, 0x27, 0x90, 0xac, 0x17, 0x98, 0xff,
        0xc8, 0x22, 0x59, 0x55, 0x90, 0xb2, 0x29, 0x39,
        0xa0, 0xbe, 0x00, 0x23, 0x55, 0x6b, 0xda, 0x83,
        0xd8, 0x5b, 0x57, 0x7c, 0x67, 0x1b, 0xc3, 0x6b,
        0x6d, 0xc7, 0x9b, 0x2b, 0x9e, 0xb7, 0x95, 0xb3,
        0xf0, 0x1b, 0x89, 0x5a, 0xd7, 0x4b, 0x67, 0xaf,
        0xdc, 0x9e, 0xcf, 0x7e, 0x1a, 0xba, 0x1b, 0xb9,
        0x3b, 0x7a, 0xdd, 0x3f, 0x0d, 0xee, 0x4c, 0x0b,
        0xd1, 0x4f, 0x34, 0xf2, 0x93, 0xf7, 0x21, 0x64,
        0x2c, 0x07, 0x00, 0x15, 0x4f, 0xe3, 0x6a, 0x9f,
        0x08, 0x52, 0xc2, 0x65, 0x47, 0x1f, 0x34, 0x64,
        0x66, 0x07, 0xbc, 0xea, 0xaf, 0x9b, 0xaa, 0x39,
        0x15, 0x8b, 0x08, 0x8c, 0x24, 0x41, 0x9b, 0x46,
        0x1b, 0x5b, 0x91, 0x11, 0xc4, 0xfd, 0xa9, 0x88,
        0x35, 0x0e, 0x7d, 0xaf, 0xfd, 0xb7, 0x90, 0x7e,
        0xd7, 0x29, 0x02, 0x0a, 0xdc, 0xc8, 0x3f, 0xc0,
        0xfd, 0x97, 0xaf, 0x50, 0x49, 0xa6, 0x5e, 0x12,
        0xc1, 0xcd, 0xec, 0x52, 0xc5, 0x51, 0xf2, 0x80,
        0x17, 0x61, 0xc7, 0x7e, 0xbe, 0xd1, 0x1b, 0x65,
        0xa4, 0xab, 0x92, 0x8d, 0x89, 0xb2, 0xc5, 0x8f,
        0xff, 0xa5, 0x6f, 0xfa, 0x62, 0x75, 0xe4, 0xa1,
        0xd4, 0x22, 0xa8, 0x9e, 0x40, 0x04, 0x27, 0x1f,
        0xcc, 0x81, 0xba, 0x28, 0x67, 0xa0, 0x1c, 0x80,
        0xeb, 0xca, 0xb0, 0x61, 0xa5, 0x48, 0xd0, 0x8a,
        0x25, 0xeb, 0x9e, 0x67, 0x8c, 0x8e, 0x9b, 0xd1,
        0xad, 0xbb, 0xc3, 0xea, 0xd3, 0xd4, 0xc5, 0x12,
        0x7b, 0xdd, 0x00, 0x57, 0x7f, 0xf6, 0xf7, 0xf6,
        0x3c, 0x05, 0xcf, 0xfc, 0x12, 0xe1, 0x93, 0x05,
        0xe5, 0x9b, 0x79, 0x87, 0x69, 0xd8, 0x82, 0xd9,
        0xd7, 0x1d, 0x41, 0x73, 0xe4, 0x52, 0x1d, 0x3e,
        0xe5, 0x8c, 0x8d, 0x34, 0xe1, 0x75, 0xa9, 0xf1,
        0x9d, 0x09, 0xa2, 0x5b, 0xef, 0xda, 0x96, 0x6e,
        0x76, 0x3d, 0xea, 0x50, 0xd9, 0xcf, 0x4f, 0xac,
        0xad, 0x1d, 0x35, 0x72, 0x1b, 0x88, 0x8b, 0xcd,
        0x8c, 0x8a, 0x8a, 0xe0, 0x96, 0x04, 0xd8, 0xbb,
        0x28, 0x43, 0x16, 0x77, 0x60, 0x98, 0x63, 0xf9,
        0xb9, 0x71, 0x46, 0xb7, 0xe1, 0xa7, 0xa9, 0x84,
        0xc3, 0x65, 0x82, 0xe1, 0x1b, 0x67, 0x04, 0x2d,
        0x55, 0x6b, 0xf9, 0xc0, 0x79, 0x09, 0x09, 0xe7,
        0xfd, 0x06, 0x4d, 0x09, 0x9b, 0x1a, 0xce, 0x35,
        0xfa, 0x27, 0x6f, 0x2f, 0x01, 0x65, 0x0d, 0xa0,
        0x97, 0x59, 0x11, 0xf0, 0x48, 0xd2, 0xe7, 0x46,
        0xbe, 0xb4, 0x0a, 0xa3, 0xe2, 0x75, 0x0e, 0x09,
        0x94, 0xd9, 0x69, 0x28, 0xd4, 0xda, 0x64, 0xba,
        0xfe, 0xa4, 0xb9, 0xf0, 0xba, 0xeb, 0xba, 0xac,
        0xa8, 0xf9, 0xd3, 0x82, 0x4c, 0x36, 0x80, 0xfa,
        0xe5, 0xf6, 0x76, 0xc3, 0x80, 0xfa, 0x90, 0x29,
        0xf4, 0x85, 0xa4, 0xc6, 0x25, 0x22, 0x79, 0x7e,
        0x39, 0x1e, 0x30, 0xb8, 0x65, 0x72, 0xcf, 0xe1,
        0x99, 0xf0, 0x75, 0xe8, 0x09, 0xb4, 0x92, 0x96,
        0x1b, 0x68, 0x50, 0x88, 0xf1, 0x2c, 0x97, 0xe3,
        0x2d, 0x26, 0x8f, 0xc5, 0x30, 0xcf, 0x24, 0xcb,
        0xb2, 0x60, 0x77, 0xdc, 0x02, 0x72, 0x0d, 0xd9,
        0x2e, 0xf2, 0x52, 0xea, 0x00, 0xf6, 0x32, 0x65,
        0xa5, 0xc6, 0x43, 0x29, 0x29, 0x69, 0xab, 0x27,
        0x0c, 0x39, 0xdf, 0x76, 0x3e, 0x93, 0x95, 0xb1,
        0x2c, 0xa2, 0x0d, 0x18, 0xce, 0xa0, 0x97, 0x10,
        0x3c, 0x90, 0xc0, 0xef, 0x0e, 0x04, 0xa6, 0xc8,
        0xa0, 0x21, 0x3c, 0x0b, 0x22, 0x77, 0x7a, 0x66,
        0xa5, 0x90, 0x25, 0xa4, 0x09, 0x3e, 0xd5, 0x27,
        0x1f, 0x6c, 0x99, 0x85, 0x5c, 0xa2, 0x99, 0x7a,
        0x25, 0xee, 0x8d, 0x32, 0x3d, 0xd3, 0xdc, 0xf5,
        0x00, 0x5a, 0x34, 0x61, 0xb6, 0xcd, 0x4e, 0xbc,
        0x26, 0x36, 0xfb, 0x44, 0x97, 0x35, 0xbd, 0x06,
        0x7d, 0x2e, 0x4a, 0xa2, 0xdc, 0x24, 0xfe, 0x70,
        0x0a, 0xf9, 0x57, 0xe3, 0xee, 0xab, 0xd1, 0x17,
        0xf3, 0x7c, 0xd6, 0x37, 0x26, 0xfa, 0x83, 0x9f,
        0xdd, 0xb2, 0xe1, 0xd7, 0xf9, 0xc7, 0x0e, 0x15,
        0x01, 0xa6, 0x58, 0x32, 0x98, 0x04, 0x32, 0xd4,
        0xde, 0xb9, 0xef, 0x09, 0xfa, 0xe4, 0x5a, 0xd7,
        0xdd, 0x09, 0x1c, 0xc9, 0xac, 0xb8, 0x6a, 0xf5,
        0x00, 0x5d, 0x6b, 0x95, 0x12, 0x8c, 0x2f, 0xcc,
        0xd8, 0xb9, 0x50, 0x3a, 0xeb, 0x74, 0x86, 0xd2,
        0x3f, 0xa1, 0x05, 0x8f, 0x6e, 0xef, 0xf5, 0xa4,
        0xd6, 0x6e, 0x53, 0xfa, 0x9e, 0xfa, 0xce, 0xdb,
        0x99, 0x46, 0xe7, 0xc5, 0xda, 0x92, 0x51, 0x4f,
        0x22, 0x07, 0xf3, 0xa5, 0x38, 0x26, 0xd3, 0xec,
        0xd6, 0x01, 0xdd, 0x31, 0x3a, 0x48, 0x93, 0xf6,
        0x69, 0x4f, 0xd8, 0xf6, 0xc2, 0x91, 0xa5, 0x7c,
        0xdf, 0x51, 0x64, 0xf1, 0x3b, 0x79, 0xbc, 0x0a,
        0x2c, 0xdc, 0x33, 0x5a, 0x29, 0xf6, 0xb2, 0x09,
        0x66, 0xca, 0x24, 0x9f, 0x1a, 0x18, 0xf3, 0x76,
        0x4c, 0x5e, 0x0b, 0x81, 0x7f, 0x29, 0x84, 0xd8,
        0x7a, 0xa8, 0xd6, 0x11, 0xac, 0xec, 0xd9, 0x07,
        0x91, 0xec, 0xb6, 0x6d, 0xec, 0xdb, 0xbe, 0x6f,
        0x9f, 0xc5, 0x19, 0x5e, 0x56, 0x87, 0x20, 0x80,
        0x75, 0xd5, 0x64, 0xe9, 0x80, 0xbf, 0x2d, 0xd5,
        0x94, 0x9f, 0x8c, 0xa4, 0x54, 0x41, 0xab, 0xb1,
        0x8e, 0xad, 0x51, 0xe4, 0x3c, 0x24, 0xf7, 0x1d,
        0xfe, 0x02, 0x48, 0x7c, 0x6d, 0xed, 0xf1, 0xac,
        0xd9, 0x79, 0x42, 0xe5, 0x3a, 0xcf, 0x6a, 0x4c,
        0x6d, 0xe2, 0x13, 0xd2, 0x2b, 0x9d, 0xab, 0x1f,
        0x70, 0xd3, 0xc0, 0x6f, 0x81, 0xe9, 0x9a, 0x86,
        0x33, 0x39, 0x60, 0xe7, 0x6a, 0x00, 0x1f, 0x97,
        0xeb, 0xe5, 0x1d, 0x0d, 0x66, 0x15, 0xc9, 0xa2,
        0xb1, 0xc0, 0xf0, 0x2e, 0xf4, 0x07, 0xa2, 0x2e,
        0x49, 0x92, 0x95, 0x13, 0xa3, 0x18, 0x46, 0x25,
        0xb9, 0x3c, 0xa1, 0x4b, 0x00, 0x00, 0x00, 0x06,
        0xab, 0xaa, 0xf9, 0x3f, 0x7e, 0x21, 0xf4, 0x0e,
        0xce, 0xfd, 0xe0, 0x44, 0xac, 0xc7, 0x1a, 0x30,
        0x22, 0x9d, 0x0a, 0xd7, 0x96, 0x2d, 0x8f, 0x9a,
        0x99, 0x1f, 0x40, 0x75, 0x7f, 0x62, 0xf9, 0xc1,
        0x81, 0x7b, 0x4a, 0x1b, 0xfa, 0xd6, 0x87, 0xb9,
        0xef, 0x58, 0x48, 0xe4, 0x5c, 0x79, 0xe5, 0xb1,
        0x2c, 0x59, 0xa4, 0x42, 0xdb, 0xa6, 0x53, 0x70,
        0x80, 0x61, 0x17, 0xd4, 0xd3, 0x77, 0xbd, 0x53,
        0x26, 0x7c, 0x0e, 0x0e, 0xff, 0x30, 0x4b, 0xd0,
        0x86, 0xfc, 0x02, 0x20, 0x24, 0x46, 0x5b, 0xf5,
        0xe3, 0x99, 0x73, 0x85, 0x60, 0x00, 0x36, 0x47,
        0x17, 0xee, 0x0c, 0xd2, 0x80, 0x71, 0x46, 0x0e,
        0x2b, 0xb0, 0xef, 0x7f, 0xfe, 0x3b, 0xe5, 0xe1,
        0x87, 0xc2, 0xaf, 0x1a, 0x6f, 0x63, 0xf4, 0x5a,
        0xc4, 0x16, 0xf7, 0xad, 0x07, 0x70, 0x71, 0x85,
        0x7d, 0x3d, 0x67, 0x08, 0xb8, 0xd8, 0xe2, 0xf0,
        0xa1, 0xac, 0xd2, 0x94, 0x7d, 0x93, 0x03, 0xdd,
        0x54, 0xf9, 0x64, 0x19, 0xb3, 0xed, 0x24, 0x22,
        0x01, 0xd7, 0x12, 0x5e, 0xc1, 0x2b, 0x39, 0x10,
        0x13, 0xe2, 0x56, 0x1c, 0xee, 0xf4, 0x2a, 0x49,
        0x7b, 0xfb, 0x36, 0x8d, 0xf8, 0xaf, 0x60, 0xdf,
        0x10, 0xf0, 0x72, 0xa2, 0xed, 0xb6, 0x53, 0x88,
        0xa9, 0x0c, 0xed, 0x9c, 0x18, 0x33, 0x7d, 0x65,
        0x9b, 0xb2, 0x9c, 0x3e, 0xe9, 0x1e, 0x43, 0x51,
        0x7e, 0xbe, 0x01, 0x95, 0xf6, 0x60, 0x65, 0xbe,
        0xd1, 0xf4, 0xe2, 0x83, 0x6b, 0xca, 0x7a, 0x70,
        0x41, 0x83, 0x72, 0xc0, 0x23, 0x51, 0x13, 0x11,
        0x2d, 0xf9, 0xc0, 0x0d, 0x7d, 0x73, 0x76, 0xa5,
        0x30, 0x83, 0x68, 0x10, 0x35, 0xa2, 0x18, 0x22,
        0x4e, 0x21, 0x93, 0x27, 0x6a, 0x19, 0x28, 0x83,
        0x7f, 0xdd, 0xdd, 0xff, 0xc3, 0x8a, 0x64, 0x00,
        0x5f, 0x1c, 0x0d, 0xf8, 0xbb, 0xd7, 0x15, 0xb9,
        0xef, 0xe0, 0x07, 0x62, 0x05, 0x9e, 0xcf, 0xfc,
        0x08, 0x52, 0x1e, 0x65, 0x41, 0x56, 0x6a, 0xeb,
        0x81, 0x53, 0x30, 0x7b, 0xf2, 0xfd, 0x65, 0xff,
        0xa2, 0x14, 0xf5, 0x62, 0x1e, 0x24, 0x48, 0x47,
        0xa5, 0x41, 0x80, 0xb4, 0xc5, 0xdc, 0xb2, 0xb4,
        0x2d, 0x17, 0xe7, 0xbe, 0x49, 0x53, 0x7a, 0x25,
        0xc5, 0x0d, 0x19, 0x59, 0xf4, 0x88, 0x59, 0xed,
        0x92, 0x13, 0xee, 0x7a, 0x4f, 0x12, 0x98, 0x4c
    };

    return linuxkm_test_lms_driver(WOLFKM_LMS_DRIVER,
                                   lms_pub, (word32)sizeof(lms_pub),
                                   lms_sig, (word32)sizeof(lms_sig),
                                   lms_msg_a, (word32)sizeof(lms_msg_a));
}

#endif /* LINUXKM_LKCAPI_REGISTER_LMS */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
