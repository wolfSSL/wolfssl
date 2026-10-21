/* lkcapi_falcon_glue.c -- glue logic to register Falcon signature
 * algorithms with the Linux Kernel Crypto API (LKCAPI).
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* included by linuxkm/lkcapi_glue.c */

#ifndef WC_SKIP_INCLUDED_C_FILES

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_falcon_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

/* Conventions, following lkcapi_mldsa_glue.c except as noted:
 *
 *   - cra_names are "falcon512" and "falcon1024".  There is no in-tree
 *     Falcon implementation and no crypto/testmgr.c entry on any kernel
 *     version, so these names are wolfSSL-defined; alg_test() takes its
 *     "notest" path for them and passes them, with or without
 *     fips_enabled.  KATs are instead supplied by
 *     linuxkm_test_falcon512()/linuxkm_test_falcon1024() below, which
 *     generate a keypair at test time (wolfCrypt Falcon has
 *     wc_falcon_make_key(), so no key material need be embedded, as in
 *     lkcapi_slhdsa_glue.c's sign-capable testers).  If/when testmgr
 *     vectors land upstream, registration will transparently become
 *     subject to them.
 *
 *   - key_size returns the public key size, in bytes below kernel
 *     6.15.3 and in bits from 6.15.3 (when crypto_sig_keysize() moved
 *     to bits); digest_size is not set, so crypto/sig.c defaults it to
 *     the public key size in bytes in both eras.
 *
 *   - signature sizes are the fixed padded encodings (666/1280 bytes):
 *     wc_falcon_sign_msg() always emits exactly the level's size, so
 *     the exact-size conventions of the ML-DSA glue carry over
 *     unchanged: a verify size mismatch and a verification failure both
 *     return -EBADMSG.
 *
 *   - signing is randomized; rng is drawn from the module's default RNG
 *     (LKCAPI_INITRNG).  A short sign dst returns -EOVERFLOW (following
 *     rsassa_pkcs1_sign()); the sig_alg edition returns the signature
 *     size on success, the akcipher edition returns 0 and updates
 *     dst_len.
 *
 *   - wolfCrypt Falcon has no verify-only build variant, so unlike the
 *     ML-DSA glue there is no stub arm: LINUXKM_FALCON_SIGN is defined
 *     unconditionally, and is kept as a macro only for structural
 *     parity with the sibling glues.
 *
 *   - Falcon is not yet standardized: FIPS 206 (FN-DSA) remains in
 *     draft.  The wire formats here are those of the Falcon
 *     specification v1.2 (2020-10-01), as implemented by wolfCrypt.
 */

#if defined(HAVE_FALCON)
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL) && \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_FALCON) && \
        !defined(LINUXKM_LKCAPI_REGISTER_FALCON)
        #define LINUXKM_LKCAPI_REGISTER_FALCON
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_FALCON
#endif

/* No LINUXKM_LKCAPI_REGISTER_ALL_KCONFIG arm: mainline has no Falcon
 * implementation on any kernel version (cf. the SLH-DSA glue, same
 * rationale). */

#ifdef LINUXKM_LKCAPI_REGISTER_FALCON

#include <wolfssl/wolfcrypt/falcon.h>

/* wolfCrypt compiles both levels whenever HAVE_FALCON; per-level macros
 * are kept for structural parity with the sibling glues. */
#define LINUXKM_FALCON512
#define LINUXKM_FALCON1024

/* wolfCrypt Falcon has no verify-only build variant (see above). */
#define LINUXKM_FALCON_SIGN

/* No ISA-extension suffix: the Falcon asm acceleration (when built) is
 * dispatched internally by wolfCrypt, not reflected in the driver
 * name. */
#define WOLFKM_FALCON_DRIVER_SUFFIX WOLFKM_DRIVER_SUFFIX_BASE

#if defined(LINUX_VERSION_CODE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0))
    /* As with ecdsa, eddsa, and mldsa, the Falcon algs are registered
     * as struct sig_alg on linux 6.13+, and as verify/sign-capable
     * struct akcipher_alg on earlier kernels.
     */
    #define LINUXKM_FALCON_SIG_ALG
#endif

#ifdef LINUXKM_FALCON_SIG_ALG
    #define falcon_tfm_type   crypto_sig
    #define falcon_tfm_ctx_cb crypto_sig_ctx
#else
    #define falcon_tfm_type   crypto_akcipher
    #define falcon_tfm_ctx_cb akcipher_tfm_ctx
#endif

#define WOLFKM_FALCON512_NAME    ("falcon512")
#define WOLFKM_FALCON512_DRIVER  ("falcon512" WOLFKM_FALCON_DRIVER_SUFFIX)
#define WOLFKM_FALCON1024_NAME   ("falcon1024")
#define WOLFKM_FALCON1024_DRIVER ("falcon1024" WOLFKM_FALCON_DRIVER_SUFFIX)

static int  linuxkm_test_falcon_driver(const char * driver, byte level);

#ifdef LINUXKM_FALCON512
static int falcon512_loaded = 0;
#endif
#ifdef LINUXKM_FALCON1024
static int falcon1024_loaded = 0;
#endif

/* The tfm context is a plain-old-data struct holding the raw key
 * octets, mirroring the ML-DSA glue.  A transient falcon_key is built
 * on the heap for each operation, because falcon_key embeds live hash
 * state that wolfCrypt advances during both sign and verify, while
 * callers of the kernel crypto API are entitled to issue concurrent
 * operations on a single tfm.  The per-operation setup cost is noise
 * against the algorithm itself.
 */
struct km_falcon_ctx {
    byte   level;      /* FALCON_LEVEL1 (Falcon-512) or FALCON_LEVEL5
                        * (Falcon-1024) */
    byte   pub_set;
    byte   priv_set;
    byte   pub[FALCON_MAX_PUB_KEY_SIZE];
    /* raw Falcon private key (the specification's sk encoding). */
    byte   priv[FALCON_MAX_KEY_SIZE];
};

/* Fixed sizes for the level; returns 0 or -EINVAL. */
static int km_falcon_sizes(byte level, word32 *pub_len, word32 *sig_len,
                           word32 *priv_len)
{
    word32 pub_l, sig_l, priv_l;

    switch (level) {
    case FALCON_LEVEL1:
        pub_l = FALCON_LEVEL1_PUB_KEY_SIZE;
        sig_l = FALCON_LEVEL1_SIG_SIZE;
        priv_l = FALCON_LEVEL1_KEY_SIZE;
        break;
    case FALCON_LEVEL5:
        pub_l = FALCON_LEVEL5_PUB_KEY_SIZE;
        sig_l = FALCON_LEVEL5_SIG_SIZE;
        priv_l = FALCON_LEVEL5_KEY_SIZE;
        break;
    default:
        return -EINVAL;
    }
    if (pub_len)
        *pub_len = pub_l;
    if (sig_len)
        *sig_len = sig_l;
    if (priv_len)
        *priv_len = priv_l;
    return 0;
}

/* Build a transient falcon_key for one operation.  Returns the key, or
 * NULL.  The caller must pass it to km_falcon_del_key() when done. */
static falcon_key *km_falcon_new_key(byte level)
{
    falcon_key *key = (falcon_key *)malloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    if (wc_falcon_init(key) != 0) {
        free(key);
        return NULL;
    }
    if (wc_falcon_set_level(key, level) != 0) {
        wc_falcon_free(key);
        free(key);
        return NULL;
    }
    return key;
}

/* wc_falcon_free() zeroizes the key material it owns; the additional
 * ForceZero covers embedded hash state and any residue, and is noise
 * against the operation cost. */
static void km_falcon_del_key(falcon_key *key)
{
    if (key == NULL)
        return;
    wc_falcon_free(key);
    ForceZero(key, sizeof(*key));
    free(key);
}

/* falcon callbacks (shared by both levels; the level is taken from the
 * tfm context, set at init time by the per-level init callbacks
 * below). */

static void         km_falcon_exit(struct falcon_tfm_type *tfm);
#ifdef LINUXKM_FALCON512
static int          km_falcon512_init(struct falcon_tfm_type *tfm);
#endif
#ifdef LINUXKM_FALCON1024
static int          km_falcon1024_init(struct falcon_tfm_type *tfm);
#endif
static int          km_falcon_set_pub(struct falcon_tfm_type *tfm,
                                      const void *key, unsigned int keylen);
static int          km_falcon_set_priv(struct falcon_tfm_type *tfm,
                                       const void *key, unsigned int keylen);
#ifdef LINUXKM_FALCON_SIG_ALG
static unsigned int km_falcon_key_size(struct crypto_sig *tfm);
static unsigned int km_falcon_max_size(struct crypto_sig *tfm);
static int          km_falcon_verify(struct crypto_sig *tfm,
                                     const void *src, unsigned int slen,
                                     const void *digest, unsigned int dlen);
static int          km_falcon_sign(struct crypto_sig *tfm,
                                   const void *src, unsigned int slen,
                                   void *dst, unsigned int dlen);
#else /* !LINUXKM_FALCON_SIG_ALG */
static unsigned int km_falcon_max_size(struct crypto_akcipher *tfm);
static int          km_falcon_verify(struct akcipher_request *req);
static int          km_falcon_sign(struct akcipher_request *req);
#endif /* !LINUXKM_FALCON_SIG_ALG */

#ifdef LINUXKM_FALCON_SIG_ALG

#define KM_FALCON_SIG_ALG_DEF(level_tag)                             \
static struct sig_alg falcon ## level_tag = {                        \
    .base.cra_name        = WOLFKM_FALCON ## level_tag ## _NAME,     \
    .base.cra_driver_name = WOLFKM_FALCON ## level_tag ## _DRIVER,   \
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,         \
    .base.cra_module      = THIS_MODULE,                             \
    .base.cra_ctxsize     = sizeof(struct km_falcon_ctx),            \
    .sign                 = km_falcon_sign,                          \
    .verify               = km_falcon_verify,                       \
    .set_pub_key          = km_falcon_set_pub,                      \
    .set_priv_key         = km_falcon_set_priv,                     \
    .key_size             = km_falcon_key_size,                     \
    /* no .digest_size: crypto/sig.c defaults it (key_size on        \
     * < 6.15.3; keysize-bits/8 on >= 6.15.3): pub bytes both eras   \
     * given km_falcon_key_size() above. */                          \
    .max_size             = km_falcon_max_size,                     \
    .init                 = km_falcon ## level_tag ## _init,        \
    .exit                 = km_falcon_exit,                         \
}

#else /* !LINUXKM_FALCON_SIG_ALG */

#define KM_FALCON_SIG_ALG_DEF(level_tag)                             \
static struct akcipher_alg falcon ## level_tag = {                   \
    .base.cra_name        = WOLFKM_FALCON ## level_tag ## _NAME,     \
    .base.cra_driver_name = WOLFKM_FALCON ## level_tag ## _DRIVER,   \
    .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,         \
    .base.cra_module      = THIS_MODULE,                             \
    .base.cra_ctxsize     = sizeof(struct km_falcon_ctx),            \
    .sign                 = km_falcon_sign,                          \
    .verify               = km_falcon_verify,                       \
    .set_pub_key          = km_falcon_set_pub,                      \
    .set_priv_key         = km_falcon_set_priv,                     \
    .max_size             = km_falcon_max_size,                     \
    .init                 = km_falcon ## level_tag ## _init,        \
    .exit                 = km_falcon_exit,                         \
}

#endif /* !LINUXKM_FALCON_SIG_ALG */

#ifdef LINUXKM_FALCON512
KM_FALCON_SIG_ALG_DEF(512);
#endif
#ifdef LINUXKM_FALCON1024
KM_FALCON_SIG_ALG_DEF(1024);
#endif

static int km_falcon_init_common(struct falcon_tfm_type *tfm, byte level)
{
    struct km_falcon_ctx *ctx = falcon_tfm_ctx_cb(tfm);

    XMEMSET(ctx, 0, sizeof(struct km_falcon_ctx));
    ctx->level = level;

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_init_common (level %d)\n", level);
    #endif
    return 0;
}

#ifdef LINUXKM_FALCON512
static int km_falcon512_init(struct falcon_tfm_type *tfm)
{
    return km_falcon_init_common(tfm, FALCON_LEVEL1);
}
#endif /* LINUXKM_FALCON512 */
#ifdef LINUXKM_FALCON1024
static int km_falcon1024_init(struct falcon_tfm_type *tfm)
{
    return km_falcon_init_common(tfm, FALCON_LEVEL5);
}
#endif /* LINUXKM_FALCON1024 */

static void km_falcon_exit(struct falcon_tfm_type *tfm)
{
    struct km_falcon_ctx *ctx = falcon_tfm_ctx_cb(tfm);

    /* The context may hold raw private key material. */
    ForceZero(ctx, sizeof(struct km_falcon_ctx));

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_exit\n");
    #endif
    return;
}

/*
 * Sets the Falcon public key.
 *
 * tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * key     raw Falcon public key, exact length for the level
 *         (897/1793 bytes)
 * keylen  key length
 */
static int km_falcon_set_pub(struct falcon_tfm_type *tfm, const void *key,
                             unsigned int keylen)
{
    struct km_falcon_ctx * ctx = falcon_tfm_ctx_cb(tfm);
    word32                 pub_len = 0;

    if (key == NULL)
        return -EINVAL;

    /* Per kernel setkey semantics (cf. rsa_set_pub_key(), which frees the
     * entire old key before parsing the new one), destroy the resident key
     * state up front -- a rejected key must leave the transform keyless,
     * not verifying against the previously installed key, and installing a
     * public key invalidates any resident private key (signing requires an
     * explicit set_priv_key after any set_pub_key). */
    ctx->pub_set = 0;
    ForceZero(ctx->pub, sizeof(ctx->pub));
    ctx->priv_set = 0;
    ForceZero(ctx->priv, sizeof(ctx->priv));

    if (km_falcon_sizes(ctx->level, &pub_len, NULL, NULL) != 0)
        return -EINVAL;

    if (keylen != pub_len) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("%s: falcon_set_pub: invalid pub len: got %d, expected %d\n",
               "falcon", keylen, pub_len);
        #endif /* WOLFKM_DEBUG_FALCON */
        return -EINVAL;
    }

    /* The raw public key is opaque bytes at this point; it's
     * interpreted by wc_falcon_import_public() per operation. */
    XMEMCPY(ctx->pub, key, keylen);
    ctx->pub_set = 1;

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_set_pub %d\n", keylen);
    #endif
    return 0;
}

/*
 * Sets the Falcon private key.
 *
 * tfm     the crypto_akcipher (crypto_sig on linux 6.13+) transform
 * key     the raw Falcon private key (the specification's sk
 *         encoding), exact length for the level (1281/2305 bytes)
 * keylen  key length
 *
 * The public key is not derivable through the wolfCrypt API from the
 * raw private key, so a resident public key is invalidated rather than
 * left as a possibly mismatched pair; verify requires an explicit
 * set_pub_key after set_priv_key.
 */
static int km_falcon_set_priv(struct falcon_tfm_type *tfm, const void *key,
                              unsigned int keylen)
{
    struct km_falcon_ctx * ctx = falcon_tfm_ctx_cb(tfm);
    falcon_key *           tmp_key = NULL;
    word32                 priv_len = 0;
    int                    err = -1;

    if (key == NULL)
        return -EINVAL;

    /* Destroy the resident key state up front (see km_falcon_set_pub()
     * for the rationale). */
    ctx->pub_set = 0;
    ForceZero(ctx->pub, sizeof(ctx->pub));
    ctx->priv_set = 0;
    ForceZero(ctx->priv, sizeof(ctx->priv));

    if (km_falcon_sizes(ctx->level, NULL, NULL, &priv_len) != 0)
        return -EINVAL;

    if (keylen != priv_len) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("%s: falcon_set_priv: invalid priv len: got %d, "
               "expected %d\n", "falcon", keylen, priv_len);
        #endif
        return -EINVAL;
    }

    /* Import to validate the encoding, then store the raw bytes. */
    tmp_key = km_falcon_new_key(ctx->level);
    if (tmp_key == NULL)
        return -ENOMEM;

    err = wc_falcon_import_private_only((const byte *)key, keylen, tmp_key);
    if (err == 0) {
        XMEMCPY(ctx->priv, key, keylen);
        ctx->priv_set = 1;
    }

    km_falcon_del_key(tmp_key);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("%s: falcon_set_priv failed: %d\n", "falcon", err);
        #endif
        ForceZero(ctx->priv, sizeof(ctx->priv));
        ctx->priv_set = 0;
        return -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_set_priv %d\n", keylen);
    #endif
    return 0;
}

#ifdef LINUXKM_FALCON_SIG_ALG
static unsigned int km_falcon_key_size(struct crypto_sig *tfm)
{
    struct km_falcon_ctx *ctx = crypto_sig_ctx(tfm);
    word32                pub_len = 0;

    if (km_falcon_sizes(ctx->level, &pub_len, NULL, NULL) != 0)
        return 0;
    /* crypto_sig_keysize() reports bits from kernel 6.15.3, bytes
     * before (crypto/sig.h kdoc; sig.c's digest_size default divides
     * by 8 from 6.15.3).  Follow the contract in both eras. */
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
    return pub_len * 8;
    #else
    return pub_len;
    #endif
}

static unsigned int km_falcon_max_size(struct crypto_sig *tfm)
{
    struct km_falcon_ctx *ctx = crypto_sig_ctx(tfm);
    word32                sig_len = 0;

    if (km_falcon_sizes(ctx->level, NULL, &sig_len, NULL) != 0)
        return 0;
    return sig_len;
}
#else /* !LINUXKM_FALCON_SIG_ALG */
static unsigned int km_falcon_max_size(struct crypto_akcipher *tfm)
{
    struct km_falcon_ctx *ctx = akcipher_tfm_ctx(tfm);
    word32                sig_len = 0;

    if (km_falcon_sizes(ctx->level, NULL, &sig_len, NULL) != 0)
        return 0;
    return sig_len;
}
#endif /* !LINUXKM_FALCON_SIG_ALG */

/* Shared verify core: raw sig + raw msg against the tfm's stored raw
 * public key, on a transient falcon_key.
 * returns:
 * 0 -- success
 * -EBADMSG -- size mismatch or verification failure (mldsa-glue
 *             convention)
 * -ENOMEM -- heap failure
 * -EINVAL -- any other failure
 */
static int km_falcon_verify_common(struct km_falcon_ctx *ctx,
                                   const byte *sig, word32 sig_len,
                                   const byte *msg, word32 msg_len)
{
    falcon_key * key = NULL;
    word32       pub_len = 0;
    word32       exp_sig_len = 0;
    int          result = 0;
    int          err = -1;

    if (! ctx->pub_set)
        return -EINVAL;

    if (km_falcon_sizes(ctx->level, &pub_len, &exp_sig_len, NULL) != 0)
        return -EINVAL;

    /* exact signature size: wc_falcon_sign_msg() always emits the
     * fixed padded encoding for the level (-EBADMSG on mismatch). */
    if (sig_len != exp_sig_len)
        return -EBADMSG;

    key = km_falcon_new_key(ctx->level);
    if (key == NULL)
        return -ENOMEM;

    err = wc_falcon_import_public(ctx->pub, pub_len, key);

    if (err == 0) {
        err = wc_falcon_verify_msg(sig, sig_len, msg, msg_len,
                                   &result, key);
    }

    km_falcon_del_key(key);

    if (err) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("error: falcon verify: verify_msg returned: %d\n", err);
        #endif
        return -EBADMSG;
    }
    if (result != 1) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("info: falcon verify: verify fail: %d\n", result);
        #endif
        return -EBADMSG;
    }
    return 0;
}

/* Shared sign core: raw msg in, raw sig out, on a transient falcon_key
 * built from the tfm's stored raw private key.  Randomized, with rng
 * drawn from the module's default RNG.
 * returns:
 * 0 -- success
 * -ENOMEM -- heap failure
 * -EINVAL -- any other failure.
 *
 * *out_len is set to the signature size.
 */
static int km_falcon_sign_common(struct km_falcon_ctx *ctx,
                                 const byte *msg, word32 msg_len,
                                 byte *sig, word32 *out_len)
{
    falcon_key * key = NULL;
    WC_RNG       rng;
    int          rng_inited = 0;
    word32       priv_len = 0;
    word32       exp_sig_len = 0;
    int          err = -1;

    if (! ctx->priv_set)
        return -EINVAL;

    if (km_falcon_sizes(ctx->level, NULL, &exp_sig_len, &priv_len) != 0)
        return -EINVAL;

    key = km_falcon_new_key(ctx->level);
    if (key == NULL)
        return -ENOMEM;

    err = wc_falcon_import_private_only(ctx->priv, priv_len, key);

    if (err == 0) {
        err = LKCAPI_INITRNG(&rng);
        if (err == 0)
            rng_inited = 1;
    }

    if (err == 0) {
        *out_len = exp_sig_len;
        err = wc_falcon_sign_msg(msg, msg_len, sig, out_len, key, &rng);
    }

    if (rng_inited)
        wc_FreeRng(&rng);

    km_falcon_del_key(key);

    if (err || (*out_len != exp_sig_len)) {
        #ifdef WOLFKM_DEBUG_FALCON
        pr_err("error: falcon sign: sign_msg returned: %d, out_len %u\n",
               err, *out_len);
        #endif
        return -EINVAL;
    }
    return 0;
}

#ifdef LINUXKM_FALCON_SIG_ALG

/*
 * Verify a Falcon signature (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw Falcon signature (padded encoding); slen must equal the
 *     signature size for the level (666/1280).
 *
 * digest:
 *   - the raw message; no prehashing occurs, and dlen is unrestricted.
 *
 * Both a size mismatch and a verification failure return -EBADMSG.
 */
static int km_falcon_verify(struct crypto_sig *tfm,
                            const void *src, unsigned int slen,
                            const void *digest, unsigned int dlen)
{
    struct km_falcon_ctx *ctx = crypto_sig_ctx(tfm);
    int                   err;

    /* a NULL digest is tolerated for dlen == 0 (the empty message);
     * wolfCrypt canonicalizes it (see falcon.c). */
    if ((src == NULL) || ((digest == NULL) && (dlen != 0)))
        return -EINVAL;

    err = km_falcon_verify_common(ctx, (const byte *)src, (word32)slen,
                                  (const byte *)digest, (word32)dlen);

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_verify dlen %d, slen %d, err %d\n",
            dlen, slen, err);
    #endif
    return err;
}

/*
 * Sign a message with Falcon (linux 6.13+ struct sig_alg edition).
 *
 * src:
 *   - the raw message; no prehashing occurs, and slen is unrestricted.
 *
 * dst:
 *   - receives the raw Falcon signature (padded encoding).
 *   - dlen must be >= the signature size for the level, else -EOVERFLOW
 *     (following the convention of rsassa_pkcs1_sign()).
 *
 * Returns the signature size on success, per the crypto_sig_sign()
 * contract.  Signing is randomized, with rng drawn from the module's
 * default RNG.
 */
static int km_falcon_sign(struct crypto_sig *tfm,
                          const void *src, unsigned int slen,
                          void *dst, unsigned int dlen)
{
    struct km_falcon_ctx *ctx = crypto_sig_ctx(tfm);
    word32                sig_len = 0;
    word32                out_len = 0;
    int                   err;

    /* a NULL src is tolerated for slen == 0 (the empty message) --
     * "slen is unrestricted", per the contract above; wolfCrypt
     * canonicalizes it (see falcon.c). */
    if (((src == NULL) && (slen != 0)) || (dst == NULL))
        return -EINVAL;

    if (km_falcon_sizes(ctx->level, NULL, &sig_len, NULL) != 0)
        return -EINVAL;

    if (dlen < sig_len)
        return -EOVERFLOW;

    err = km_falcon_sign_common(ctx, (const byte *)src, (word32)slen,
                                (byte *)dst, &out_len);

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_sign slen %d, err %d\n", slen, err);
    #endif
    if (err)
        return err;
    return (int)out_len;
}

#else /* !LINUXKM_FALCON_SIG_ALG */

/*
 * Verify a Falcon signature (pre-6.13 akcipher edition).
 *
 * req->src:
 *   - src_len: signature (exact size for the level, 666/1280),
 *     immediately followed by the message (raw, unhashed, any length).
 *   - the signature and message segment lengths are req->src_len and
 *     req->dst_len respectively, per the legacy akcipher verify
 *     convention.
 * req->dst: must be NULL (verify produces no output).
 */
static int km_falcon_verify(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_falcon_ctx *   ctx = NULL;
    byte *                   sig = NULL;
    byte *                   msg = NULL;
    word32                   sig_len = 0;
    word32                   msg_len = 0;
    word32                   exp_sig_len = 0;
    int                      err = -1;

    if (req->src == NULL || req->dst != NULL)
        return -EINVAL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    sig_len = req->src_len;
    msg_len = req->dst_len;

    if (km_falcon_sizes(ctx->level, NULL, &exp_sig_len, NULL) != 0)
        return -EINVAL;

    if (sig_len != exp_sig_len)
        return -EBADMSG;

    /* Guard the allocation-size addition against overflow of the
     * caller-supplied lengths (km_falcon_verify_common() re-checks). */
    if ((sig_len + msg_len) != ((word64)sig_len + (word64)msg_len))
        return -EINVAL;

    /* one buffer for the contiguous signature and message copies; the
     * signature's nonzero length assures a valid msg pointer for
     * zero-length messages (msg_len 0 is legal). */
    sig = malloc(sig_len + msg_len);
    if (unlikely(sig == NULL))
        return -ENOMEM;
    msg = sig + sig_len;

    XMEMSET(sig, 0, sig_len + msg_len);

    /* copy sig and msg from req->src to sig and contiguous msg buffer. */
    scatterwalk_map_and_copy(sig, req->src, 0, sig_len + msg_len, 0);

    err = km_falcon_verify_common(ctx, sig, sig_len, msg, msg_len);

    free(sig);

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_verify msg_len %d, err %d\n",
            msg_len, err);
    #endif
    return err;
}

/*
 * Sign a message with Falcon (pre-6.13 akcipher edition).
 *
 * req->src:
 *   - src_len: message (raw, unhashed, any length)
 * req->dst:
 *   - dst_len: receives the raw Falcon signature (padded encoding);
 *     must be >= the signature size for the level, else -EOVERFLOW
 *     with dst_len set to the required size.
 *
 * On success, returns 0 and updates req->dst_len to the signature
 * size.  Signing is randomized, with rng drawn from the module's
 * default RNG.
 */
static int km_falcon_sign(struct akcipher_request *req)
{
    struct crypto_akcipher * tfm = NULL;
    struct km_falcon_ctx *   ctx = NULL;
    byte *                   msg = NULL;
    byte *                   sig = NULL;
    word32                   msg_len = 0;
    word32                   sig_len = 0;
    word32                   out_len = 0;
    int                      err = -1;

    /* a NULL src sg is tolerated for src_len == 0 (the empty message);
     * scatterwalk_map_and_copy() is a no-op at nbytes == 0, so a NULL sg
     * is never walked. */
    if (((req->src == NULL) && (req->src_len != 0)) || (req->dst == NULL))
        return -EINVAL;

    tfm = crypto_akcipher_reqtfm(req);
    ctx = akcipher_tfm_ctx(tfm);

    if (km_falcon_sizes(ctx->level, NULL, &sig_len, NULL) != 0)
        return -EINVAL;

    if (req->dst_len < sig_len) {
        req->dst_len = sig_len;
        return -EOVERFLOW;
    }

    msg_len = req->src_len;

    /* Guard the allocation-size addition, as km_falcon_verify() does.
     * The (msg_len ? msg_len : 1) below never exceeds max(msg_len, 1),
     * so this bound covers it. */
    if ((msg_len + sig_len) != ((word64)msg_len + (word64)sig_len))
        return -EINVAL;

    /* one buffer for the contiguous message copy and the signature;
     * allocate at least 1 message byte, to assure well-defined pointer
     * arithmetic for zero-length messages (msg_len 0 is legal). */
    msg = malloc((msg_len ? msg_len : 1) + sig_len);
    if (unlikely(msg == NULL))
        return -ENOMEM;
    sig = msg + (msg_len ? msg_len : 1);

    /* copy the message from req->src to the contiguous msg buffer. */
    scatterwalk_map_and_copy(msg, req->src, 0, msg_len, 0);

    err = km_falcon_sign_common(ctx, msg, msg_len, sig, &out_len);

    if (err == 0) {
        /* copy the signature out to req->dst. */
        scatterwalk_map_and_copy(sig, req->dst, 0, out_len, 1);
        req->dst_len = out_len;
    }

    free(msg);

    #ifdef WOLFKM_DEBUG_FALCON
    pr_info("info: exiting km_falcon_sign msg_len %d, err %d\n",
            msg_len, err);
    #endif
    return err;
}

#endif /* !LINUXKM_FALCON_SIG_ALG */


/* 16 byte test message shared by both levels. */
static const byte linuxkm_falcon_test_msg[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* Self-test: as in the sign-capable arms of the SLH-DSA glue's testers,
 * no key material is embedded -- wolfCrypt Falcon has
 * wc_falcon_make_key(), so the tester generates a keypair at test time
 * and drives it through the registered algorithm's setkey/sign/verify
 * plumbing, including the empty-message and rejected-setkey semantics.
 * The underlying implementation's KATs are supplied by
 * wolfcrypt/test/test.c's falcon_test(), which is built into the module
 * whenever LINUXKM_LKCAPI_REGISTER. */
static int linuxkm_test_falcon_driver(const char * driver, byte level)
{
    int              test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    falcon_key *     gen_key = NULL;
    WC_RNG           rng;
    int              rng_inited = 0;
    byte *           pub = NULL;
    byte *           priv = NULL;
    byte *           sig_buf = NULL;
    byte *           sig_empty = NULL;
    word32           pub_len = 0;
    word32           sig_len = 0;
    word32           priv_len = 0;
    word32           out_len = 0;
    const byte *     msg = linuxkm_falcon_test_msg;
    word32           msg_len = (word32)sizeof(linuxkm_falcon_test_msg);
    int              ret;
#ifdef LINUXKM_FALCON_SIG_ALG
    struct crypto_sig *      tfm = NULL;
#else
    struct crypto_akcipher * tfm = NULL;
    struct akcipher_request * req = NULL;
    struct scatterlist        src_sg[2];
    struct scatterlist        dst_sg;
#endif

    if (km_falcon_sizes(level, &pub_len, &sig_len, &priv_len) != 0)
        return WC_NO_ERR_TRACE(WC_FAILURE);

    pub = (byte *)malloc(pub_len);
    priv = (byte *)malloc(priv_len);
    sig_buf = (byte *)malloc(sig_len);
    sig_empty = (byte *)malloc(sig_len);
    if ((pub == NULL) || (priv == NULL) || (sig_buf == NULL) ||
        (sig_empty == NULL))
    {
        pr_err("error: allocating falcon test buffers failed.\n");
        goto test_falcon_end;
    }

    /* generate a keypair for the test. */
    gen_key = km_falcon_new_key(level);
    if (gen_key == NULL) {
        pr_err("error: allocating falcon test key failed.\n");
        goto test_falcon_end;
    }
    ret = LKCAPI_INITRNG(&rng);
    if (ret) {
        pr_err("error: falcon test rng init returned: %d\n", ret);
        goto test_falcon_end;
    }
    rng_inited = 1;
    ret = wc_falcon_make_key(gen_key, &rng);
    if (ret) {
        pr_err("error: wc_falcon_make_key returned: %d\n", ret);
        goto test_falcon_end;
    }
    out_len = pub_len;
    ret = wc_falcon_export_public(gen_key, pub, &out_len);
    if ((ret != 0) || (out_len != pub_len)) {
        pr_err("error: wc_falcon_export_public returned: %d, %u\n",
               ret, out_len);
        goto test_falcon_end;
    }
    out_len = priv_len;
    PRIVATE_KEY_UNLOCK();
    ret = wc_falcon_export_private_only(gen_key, priv, &out_len);
    PRIVATE_KEY_LOCK();
    if ((ret != 0) || (out_len != priv_len)) {
        pr_err("error: wc_falcon_export_private_only returned: %d, %u\n",
               ret, out_len);
        goto test_falcon_end;
    }

#ifdef LINUXKM_FALCON_SIG_ALG

    tfm = crypto_alloc_sig(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating sig algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        tfm = NULL;
        goto test_falcon_end;
    }

    /* sign with the generated private key. */
    ret = crypto_sig_set_privkey(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_sig_set_privkey returned: %d\n", ret);
        goto test_falcon_end;
    }
    ret = crypto_sig_sign(tfm, msg, msg_len, sig_buf, sig_len);
    if (ret != (int)sig_len) {
        pr_err("error: crypto_sig_sign returned %d, expected %d\n",
               ret, (int)sig_len);
        goto test_falcon_end;
    }
    /* empty message, passed as (NULL, 0). */
    ret = crypto_sig_sign(tfm, NULL, 0, sig_empty, sig_len);
    if (ret != (int)sig_len) {
        pr_err("error: crypto_sig_sign (empty msg) returned %d, "
               "expected %d\n", ret, (int)sig_len);
        goto test_falcon_end;
    }
    /* a short dst must be rejected with -EOVERFLOW. */
    ret = crypto_sig_sign(tfm, msg, msg_len, sig_buf, sig_len - 1);
    if (ret != -EOVERFLOW) {
        pr_err("error: crypto_sig_sign (short dst) returned %d, "
               "expected %d\n", ret, -EOVERFLOW);
        goto test_falcon_end;
    }
    /* regenerate a good signature clobbered by the short-dst check
     * being reached with a partially-written buffer.  (it isn't --
     * -EOVERFLOW precedes any write -- but don't depend on that.) */
    ret = crypto_sig_sign(tfm, msg, msg_len, sig_buf, sig_len);
    if (ret != (int)sig_len) {
        pr_err("error: crypto_sig_sign (regen) returned %d, expected %d\n",
               ret, (int)sig_len);
        goto test_falcon_end;
    }

    /* install the public key (destroys the resident private key, per
     * kernel setkey semantics) and verify both signatures. */
    ret = crypto_sig_set_pubkey(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_sig_set_pubkey returned: %d\n", ret);
        goto test_falcon_end;
    }

    /* size sanity: crypto_sig_keysize() reports bits from 6.15.3,
     * bytes before; digest size defaults to pub bytes in both eras;
     * max size is the signature size. */
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 3)
    if (crypto_sig_keysize(tfm) != pub_len * 8) {
        pr_err("error: crypto_sig_keysize returned %u, expected %u\n",
               crypto_sig_keysize(tfm), pub_len * 8);
        goto test_falcon_end;
    }
    #else
    if (crypto_sig_keysize(tfm) != pub_len) {
        pr_err("error: crypto_sig_keysize returned %u, expected %u\n",
               crypto_sig_keysize(tfm), pub_len);
        goto test_falcon_end;
    }
    #endif
    if (crypto_sig_digestsize(tfm) != pub_len) {
        pr_err("error: crypto_sig_digestsize returned %u, expected %u\n",
               crypto_sig_digestsize(tfm), pub_len);
        goto test_falcon_end;
    }
    if (crypto_sig_maxsize(tfm) != sig_len) {
        pr_err("error: crypto_sig_maxsize returned %u, expected %u\n",
               crypto_sig_maxsize(tfm), sig_len);
        goto test_falcon_end;
    }

    ret = crypto_sig_verify(tfm, sig_buf, sig_len, msg, msg_len);
    if (ret) {
        pr_err("error: crypto_sig_verify returned: %d\n", ret);
        goto test_falcon_end;
    }
    /* empty message, passed as (NULL, 0). */
    ret = crypto_sig_verify(tfm, sig_empty, sig_len, NULL, 0);
    if (ret) {
        pr_err("error: crypto_sig_verify (empty msg) returned: %d\n", ret);
        goto test_falcon_end;
    }
    /* a corrupted signature must be rejected with -EBADMSG. */
    sig_buf[sig_len / 2] ^= 1;
    ret = crypto_sig_verify(tfm, sig_buf, sig_len, msg, msg_len);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_sig_verify (corrupted) returned %d, "
               "expected %d\n", ret, -EBADMSG);
        goto test_falcon_end;
    }
    sig_buf[sig_len / 2] ^= 1;
    /* a short signature must be rejected with -EBADMSG. */
    ret = crypto_sig_verify(tfm, sig_buf, sig_len - 1, msg, msg_len);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_sig_verify (short sig) returned %d, "
               "expected %d\n", ret, -EBADMSG);
        goto test_falcon_end;
    }
    /* a rejected set_pub_key must leave the transform keyless -- no
     * verification against the previously installed key. */
    ret = crypto_sig_set_pubkey(tfm, pub, pub_len - 1);
    if (ret != -EINVAL) {
        pr_err("error: crypto_sig_set_pubkey (short) returned %d, "
               "expected %d\n", ret, -EINVAL);
        goto test_falcon_end;
    }
    ret = crypto_sig_verify(tfm, sig_buf, sig_len, msg, msg_len);
    if (ret != -EINVAL) {
        pr_err("error: crypto_sig_verify after rejected set_pubkey "
               "returned %d, expected %d\n", ret, -EINVAL);
        goto test_falcon_end;
    }
    ret = crypto_sig_set_pubkey(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_sig_set_pubkey (restore) returned: %d\n",
               ret);
        goto test_falcon_end;
    }
    ret = crypto_sig_verify(tfm, sig_buf, sig_len, msg, msg_len);
    if (ret) {
        pr_err("error: crypto_sig_verify after restored set_pubkey "
               "returned: %d\n", ret);
        goto test_falcon_end;
    }

#else /* !LINUXKM_FALCON_SIG_ALG */

    tfm = crypto_alloc_akcipher(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating akcipher algorithm %s failed: %ld\n",
               driver, PTR_ERR(tfm));
        tfm = NULL;
        goto test_falcon_end;
    }
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating akcipher request %s failed\n", driver);
        req = NULL;
        goto test_falcon_end;
    }

    /* sign with the generated private key. */
    ret = crypto_akcipher_set_priv_key(tfm, priv, priv_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_priv_key returned: %d\n", ret);
        goto test_falcon_end;
    }
    if (crypto_akcipher_maxsize(tfm) != sig_len) {
        pr_err("error: crypto_akcipher_maxsize returned %u, "
               "expected %u\n", crypto_akcipher_maxsize(tfm), sig_len);
        goto test_falcon_end;
    }
    sg_init_one(&src_sg[0], msg, msg_len);
    sg_init_one(&dst_sg, sig_buf, sig_len);
    akcipher_request_set_crypt(req, &src_sg[0], &dst_sg, msg_len, sig_len);
    ret = crypto_akcipher_sign(req);
    if (ret) {
        pr_err("error: crypto_akcipher_sign returned: %d\n", ret);
        goto test_falcon_end;
    }
    if (req->dst_len != sig_len) {
        pr_err("error: crypto_akcipher_sign dst_len %u, expected %u\n",
               req->dst_len, sig_len);
        goto test_falcon_end;
    }

    /* install the public key (destroys the resident private key, per
     * kernel setkey semantics) and verify: src is sig || msg, with the
     * segment lengths in src_len and dst_len respectively, and dst
     * NULL, per the legacy akcipher verify convention. */
    ret = crypto_akcipher_set_pub_key(tfm, pub, pub_len);
    if (ret) {
        pr_err("error: crypto_akcipher_set_pub_key returned: %d\n", ret);
        goto test_falcon_end;
    }
    sg_init_table(src_sg, 2);
    sg_set_buf(&src_sg[0], sig_buf, sig_len);
    sg_set_buf(&src_sg[1], msg, msg_len);
    akcipher_request_set_crypt(req, src_sg, NULL, sig_len, msg_len);
    ret = crypto_akcipher_verify(req);
    if (ret) {
        pr_err("error: crypto_akcipher_verify returned: %d\n", ret);
        goto test_falcon_end;
    }
    /* a corrupted signature must be rejected with -EBADMSG. */
    sig_buf[sig_len / 2] ^= 1;
    ret = crypto_akcipher_verify(req);
    if (ret != -EBADMSG) {
        pr_err("error: crypto_akcipher_verify (corrupted) returned %d, "
               "expected %d\n", ret, -EBADMSG);
        goto test_falcon_end;
    }
    sig_buf[sig_len / 2] ^= 1;

#endif /* !LINUXKM_FALCON_SIG_ALG */

    test_rc = 0;

test_falcon_end:

#ifdef LINUXKM_FALCON_SIG_ALG
    if (tfm != NULL)
        crypto_free_sig(tfm);
#else
    if (req != NULL)
        akcipher_request_free(req);
    if (tfm != NULL)
        crypto_free_akcipher(tfm);
#endif
    km_falcon_del_key(gen_key);
    if (rng_inited)
        wc_FreeRng(&rng);
    if (priv != NULL) {
        ForceZero(priv, priv_len);
        free(priv);
    }
    free(pub);
    free(sig_buf);
    free(sig_empty);

    if (test_rc == 0)
        pr_info("info: self-test for %s succeeded\n", driver);
    else
        pr_err("error: self-test for %s FAILED\n", driver);

    return test_rc;
}

#ifdef LINUXKM_FALCON512
static int linuxkm_test_falcon512(void)
{
    return linuxkm_test_falcon_driver(WOLFKM_FALCON512_DRIVER,
                                      FALCON_LEVEL1);
}
#endif /* LINUXKM_FALCON512 */

#ifdef LINUXKM_FALCON1024
static int linuxkm_test_falcon1024(void)
{
    return linuxkm_test_falcon_driver(WOLFKM_FALCON1024_DRIVER,
                                      FALCON_LEVEL5);
}
#endif /* LINUXKM_FALCON1024 */

#endif /* LINUXKM_LKCAPI_REGISTER_FALCON */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
