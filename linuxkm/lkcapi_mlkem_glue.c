/* lkcapi_mlkem_glue.c -- glue logic to register ML-KEM (FIPS 203) wolfCrypt
 * implementations with the Linux Kernel Cryptosystem, as kpp
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
    #error lkcapi_mlkem_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

/* EXPERIMENTAL: full ML-KEM (FIPS 203) glue -- decapsulation AND
 * encapsulation -- registered as struct kpp_alg.
 *
 * The kernel has no KEM algorithm type (and no in-tree ML-KEM); kpp
 * models symmetric key agreement (DH/ECDH), in which every operation is
 * one-input/one-output and deterministic given set_secret state, and
 * every in-tree kpp implementation keeps its tfm ctx read-only during
 * request operations.  ML-KEM encapsulation is a randomized
 * one-input/TWO-output operation (ek -> ciphertext + shared secret,
 * with the secret bound to fresh internal randomness), so it cannot be
 * expressed as a single read-only kpp op.
 *
 * It CAN, however, be expressed as two, using the strategy of
 * lkcapi_sha_glue.c's SHA-3/HMAC state-overflow machinery (a lock and
 * list_heads in the persistent transform context, dynamically
 * allocated per-operation state nodes, and garbage collection of
 * abandoned nodes at .exit) -- with the association handle adapted to
 * kpp's handleless request model: the pairing key is the ciphertext
 * itself, which the caller necessarily round-trips.
 *
 * Roles.  A tfm takes its role from set_secret():
 *   - DECAPSULATION (responder): set_secret is the raw FIPS 203 dk
 *     (exact size for the set), the 64-byte d||z keygen seed, or
 *     NULL/empty to generate a fresh key (the empty-secret-keygen
 *     convention follows ecdh_set_secret()).  generate_public_key
 *     emits the raw encapsulation key ek.  compute_shared_secret takes
 *     the peer's ciphertext as src and emits ss by decapsulation.
 *   - ENCAPSULATION (initiator): set_secret is the peer's raw ek
 *     (exact size for the set; all four accepted set_secret lengths
 *     are pairwise distinct for every parameter set, so the length
 *     dictates the role unambiguously).  Note this means that the
 *     peer's public ek appears where the local private key appears
 *     in a DH/ECDH KEM exchange.  The inversion is intentional so the
 *     subsequent generate_public_key / compute_shared_secret ops
 *     retain the same "emit what you transmit / combine peer material
 *     -> ss" shape.
 *     generate_public_key runs a
 *     fresh encapsulation: the ciphertext is written to req->dst (the
 *     op's output is "your transmissible public contribution", which
 *     for an encapsulator IS the ciphertext), and a pending node
 *     {SHA-256(ct), ss} is parked on a lock-guarded list in the tfm
 *     ctx.  compute_shared_secret takes that ciphertext as src, looks
 *     up the pending node by ciphertext digest, and CLAIMS it: the
 *     shared secret is emitted and the node destroyed (one-shot; a
 *     second claim of the same ciphertext fails -ENOKEY).
 * Note the symmetry: in both roles, generate_public_key emits the
 * value you transmit to the peer, and compute_shared_secret combines
 * the peer-associated ciphertext with local secret state to yield ss
 * -- the same shape those ops have in DH.
 *
 * Bookkeeping (per the lkcapi_sha_glue.c HMAC export-list design):
 *   - the pending list is BOUNDED (WC_LINUXKM_MLKEM_PENDING_MAX,
 *     default 16): at capacity, the oldest unclaimed node is evicted,
 *     and a later claim of its ciphertext degrades to a graceful
 *     -ENOKEY, never corruption.  Encapsulations should be claimed
 *     promptly.
 *   - claim lookup and shared-secret copyout happen under a single
 *     lock hold; eviction unlinks under the lock and frees outside it
 *     -- so a concurrent evictor and claimant cannot race a node into
 *     use-after-free.
 *   - nodes hold live shared secrets: every teardown path (claim,
 *     eviction, role switch, .exit reaper) ForceZero()s the node.
 *   - any set_secret() resets the role and reaps all pending nodes.
 *
 * Association-by-digest has no ABA hazard: ciphertexts from fresh
 * encapsulation randomness are unique with overwhelming probability,
 * and nodes are destroyed on claim.
 *
 * Per FIPS 203 implicit rejection, decapsulation of any
 * correctly-sized ciphertext SUCCEEDS; an invalid ciphertext yields a
 * pseudorandom shared secret rather than an error.  Only malformed
 * lengths fail.  (This applies to the decapsulation role;
 * encapsulation-role claims of unknown ciphertexts fail -ENOKEY.)
 *
 * Because the mlkem* cra_names are unknown to crypto/testmgr.c,
 * alg_test() takes its "notest" path and returns success at
 * registration time, with or without fips_enabled.  Self-tests are
 * supplied by the linuxkm_test_mlkem*() functions below (zero KAT
 * rodata: vectors are generated at test time from a fixed keygen
 * seed); algorithm-correctness KATs live in wolfcrypt/test/test.c
 * and, in full FIPS embodiment, in wolfcrypt/src/fips_test.c.
 */

#if defined(WOLFSSL_HAVE_MLKEM)
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL) &&         \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_MLKEM) && \
        !defined(LINUXKM_LKCAPI_REGISTER_MLKEM)
        #define LINUXKM_LKCAPI_REGISTER_MLKEM
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_MLKEM
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_MLKEM

#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef NO_SHA256
    #error lkcapi_mlkem_glue.c encapsulation support requires SHA-256 \
for pending-node association.
#endif

#ifdef WOLFSSL_WC_ML_KEM_512
    #define LINUXKM_MLKEM512
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    #define LINUXKM_MLKEM768
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    #define LINUXKM_MLKEM1024
#endif

#if defined(USE_INTEL_SPEEDUP)
    #ifdef WOLFSSL_MLKEM_HAVE_INTEL_AVX512
        #define WOLFKM_MLKEM_DRIVER_ISA_EXT "-avx512"
    #else
        #define WOLFKM_MLKEM_DRIVER_ISA_EXT "-avx2"
    #endif
#else
    #define WOLFKM_MLKEM_DRIVER_ISA_EXT ""
#endif

#define WOLFKM_MLKEM_DRIVER_SUFFIX \
    WOLFKM_MLKEM_DRIVER_ISA_EXT WOLFKM_DRIVER_SUFFIX_BASE

/* max_size() reports the encapsulation key size for both roles, which
 * is correct only because ct <= ek for every ML-KEM parameter set.
 * Check that assumption. */
#ifdef WOLFSSL_WC_ML_KEM_512
wc_static_assert(WC_ML_KEM_512_CIPHER_TEXT_SIZE <=
                 WC_ML_KEM_512_PUBLIC_KEY_SIZE);
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
wc_static_assert(WC_ML_KEM_768_CIPHER_TEXT_SIZE <=
                 WC_ML_KEM_768_PUBLIC_KEY_SIZE);
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
wc_static_assert(WC_ML_KEM_1024_CIPHER_TEXT_SIZE <=
                 WC_ML_KEM_1024_PUBLIC_KEY_SIZE);
#endif

/* Bound on unclaimed encapsulations per tfm; oldest evicted at
 * capacity. */
#ifdef WC_LINUXKM_MLKEM_PENDING_MAX
    wc_static_assert_if_const(WC_LINUXKM_MLKEM_PENDING_MAX > 0);
#else
    #define WC_LINUXKM_MLKEM_PENDING_MAX 16
#endif

/* The kernel list macros provoke "pointer of type `void *' used in arithmetic",
 * and on older kernels, "nested extern declaration of
 * `__compiletime_assert_foo'".
 */
PRAGMA_DIAG_PUSH
PRAGMA("GCC diagnostic ignored \"-Wpointer-arith\"");
PRAGMA("GCC diagnostic ignored \"-Wnested-externs\"");

#include <linux/list.h>

/* An unclaimed encapsulation: SHA-256 of the emitted ciphertext, and
 * the shared secret awaiting claim. */
struct km_mlkem_pending_node {
    struct list_head ent;
    byte             ct_digest[WC_SHA256_DIGEST_SIZE];
    byte             ss[WC_ML_KEM_SS_SZ];
};

/* struct MlKemKey embeds working state mutated during operations, so,
 * as with slh-dsa (see lkcapi_slhdsa_glue.c), the tfm ctx stores only
 * raw key octets and each operation runs on a transient
 * heap-allocated MlKemKey.  The pending list and its lock are the one
 * deliberate exception to read-only-ctx-during-ops -- see the header
 * comment. */
struct km_mlkem_ctx {
    int              type;      /* WC_ML_KEM_512 / _768 / _1024 */
    int              dk_set;    /* decapsulation role */
    int              ek_set;    /* encapsulation role */
    byte             dk[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    byte             ek[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    wolfSSL_Mutex    pending_lock;
    struct list_head pending_list;
    unsigned int     pending_count;
};

static MlKemKey * km_mlkem_new_wc_key(int type)
{
    MlKemKey *key = (MlKemKey *)malloc(sizeof(MlKemKey));
    if (key) {
        if (wc_MlKemKey_Init(key, type, NULL /* heap */,
                             INVALID_DEVID) != 0)
        {
            free(key);
            key = NULL;
        }
    }
    return key;
}

static void km_mlkem_del_wc_key(MlKemKey *key)
{
    if (key) {
        wc_MlKemKey_Free(key);
        ForceZero(key, sizeof(MlKemKey));
        free(key);
    }
}

/* Reap every pending node.  Caller must not hold pending_lock. */
static void km_mlkem_reap_pending(struct km_mlkem_ctx *ctx)
{
    struct list_head reaped;
    struct km_mlkem_pending_node *node, *tmp;

    INIT_LIST_HEAD(&reaped);

    if (wc_LockMutex(&ctx->pending_lock) == 0) {
        list_for_each_entry_safe(node, tmp, &ctx->pending_list, ent) {
            list_del(&node->ent);
            list_add(&node->ent, &reaped);
        }
        ctx->pending_count = 0;
        wc_UnLockMutex(&ctx->pending_lock);
    }

    list_for_each_entry_safe(node, tmp, &reaped, ent) {
        list_del(&node->ent);
        ForceZero(node, sizeof(*node));
        free(node);
    }
}

static int km_mlkem_init_common(struct crypto_kpp *tfm, int type)
{
    struct km_mlkem_ctx *ctx = kpp_tfm_ctx(tfm);

    XMEMSET(ctx, 0, sizeof(struct km_mlkem_ctx));
    ctx->type = type;
    if (wc_InitMutex(&ctx->pending_lock) != 0)
        return -ENOMEM;
    INIT_LIST_HEAD(&ctx->pending_list);

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: exiting km_mlkem_init_common (type %d)\n", type);
    #endif /* WOLFKM_DEBUG_MLKEM */
    return 0;
}

static void km_mlkem_exit(struct crypto_kpp *tfm)
{
    struct km_mlkem_ctx *ctx = kpp_tfm_ctx(tfm);

    km_mlkem_reap_pending(ctx);
    wc_FreeMutex(&ctx->pending_lock);
    ForceZero(ctx, sizeof(struct km_mlkem_ctx));

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: exiting km_mlkem_exit\n");
    #endif /* WOLFKM_DEBUG_MLKEM */
    return;
}

/*
 * Sets the key, and thereby the role -- see the header comment.
 *
 * tfm     The crypto_kpp transform
 * buffer  The raw FIPS 203 dk, the 64-byte d||z keygen seed, or
 *         NULL/empty to generate a fresh key (all: decapsulation
 *         role); or the peer's raw ek (encapsulation role).  The
 *         four lengths are pairwise distinct for every set.
 * len     Buffer length
 */
static int km_mlkem_set_secret(struct crypto_kpp *tfm, const void *buffer,
                               unsigned int len)
{
    struct km_mlkem_ctx * ctx = kpp_tfm_ctx(tfm);
    MlKemKey *            wc_key = NULL;
    word32                dk_len = 0;
    word32                ek_len = 0;
    int                   err;

    /* Any (re)key resets the role and reaps pending encapsulations. */
    if (ctx->dk_set) {
        ForceZero(ctx->dk, sizeof ctx->dk);
        ctx->dk_set = 0;
    }
    if (ctx->ek_set) {
        XMEMSET(ctx->ek, 0, sizeof ctx->ek);
        ctx->ek_set = 0;
    }
    km_mlkem_reap_pending(ctx);

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_MlKemKey_PrivateKeySize(wc_key, &dk_len);
    if (err == 0)
        err = wc_MlKemKey_PublicKeySize(wc_key, &ek_len);
    if (err != 0) {
        km_mlkem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if ((buffer == NULL) || (len == 0)) {
        /* Decapsulation role: generate a fresh key. */
        WC_RNG rng;
        err = LKCAPI_INITRNG(&rng);
        if (err == 0) {
            err = wc_MlKemKey_MakeKey(wc_key, &rng);
            wc_FreeRng(&rng);
        }
        else {
            err = -ENODEV;
            goto out;
        }
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_MlKemKey_EncodePrivateKey(wc_key, ctx->dk, dk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->dk_set = 1;
    }
    else if (len == (unsigned int)WC_ML_KEM_MAKEKEY_RAND_SZ) {
        /* Decapsulation role: deterministic keygen from the d||z seed. */
        err = wc_MlKemKey_MakeKeyWithRandom(wc_key, (const byte *)buffer,
                                            (int)len);
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_MlKemKey_EncodePrivateKey(wc_key, ctx->dk, dk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->dk_set = 1;
    }
    else if (len == (unsigned int)dk_len) {
        /* Decapsulation role: import dk. */
        err = wc_MlKemKey_DecodePrivateKey(wc_key, (const byte *)buffer,
                                           len);
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_MlKemKey_EncodePrivateKey(wc_key, ctx->dk, dk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->dk_set = 1;
    }
    else if (len == (unsigned int)ek_len) {
        /* Encapsulation role: import the peer's ek (validated by decode). */
        err = wc_MlKemKey_DecodePublicKey(wc_key, (const byte *)buffer,
                                          len);
        if (err == 0) {
            XMEMCPY(ctx->ek, buffer, ek_len);
            ctx->ek_set = 1;
        }
    }
    else {
        err = BAD_FUNC_ARG;
    }

out:
    km_mlkem_del_wc_key(wc_key);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_MLKEM
        pr_err("error: km_mlkem_set_secret (len %u): %d\n", len, err);
        #endif
        return (err < -1000 || err > 0) ? err : -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: exiting km_mlkem_set_secret %u (role %s)\n", len,
            ctx->ek_set ? "encap" : "decap");
    #endif
    return 0;
}

/* The largest kpp output for this tfm.  ek for the decapsulation role;
 * ct for the encapsulation role -- but ct <= ek for every parameter
 * set (statically asserted above), so ek covers both.
 */
static unsigned int km_mlkem_max_size(struct crypto_kpp *tfm)
{
    struct km_mlkem_ctx * ctx = kpp_tfm_ctx(tfm);
    MlKemKey *            wc_key;
    word32                len = 0;

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return 0;
    if (wc_MlKemKey_PublicKeySize(wc_key, &len) != 0)
        len = 0;
    km_mlkem_del_wc_key(wc_key);
    return len;
}

/* Decapsulation role: emit the raw FIPS 203 ek to req->dst. */
static int km_mlkem_generate_ek(struct km_mlkem_ctx *ctx,
                                struct kpp_request *req)
{
    MlKemKey * wc_key = NULL;
    byte *     ek = NULL;
    word32     ek_len = 0;
    word32     dk_len = 0;
    int        err;

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_MlKemKey_PublicKeySize(wc_key, &ek_len);
    if (err == 0)
        err = wc_MlKemKey_PrivateKeySize(wc_key, &dk_len);
    if (err != 0) {
        km_mlkem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->dst_len < ek_len) {
        km_mlkem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    ek = (byte *)malloc(ek_len);
    if (! ek) {
        km_mlkem_del_wc_key(wc_key);
        return -ENOMEM;
    }

    /* The FIPS 203 dk contains ek; DecodePrivateKey recovers it. */
    err = wc_MlKemKey_DecodePrivateKey(wc_key, ctx->dk, dk_len);
    if (err == 0)
        err = wc_MlKemKey_EncodePublicKey(wc_key, ek, ek_len);

    if (err == 0) {
        scatterwalk_map_and_copy(ek, req->dst, 0, ek_len, 1);
        req->dst_len = ek_len;
    }

    free(ek);
    km_mlkem_del_wc_key(wc_key);
    return err ? -EINVAL : 0;
}

/* Encapsulation role: run a fresh encapsulation against the installed
 * peer ek.  The ciphertext goes to req->dst; the shared secret is
 * parked on the pending list, keyed by SHA-256(ct), awaiting claim by
 * compute_shared_secret.
 */
static int km_mlkem_generate_ct(struct km_mlkem_ctx *ctx,
                                struct kpp_request *req)
{
    MlKemKey *                     wc_key = NULL;
    struct km_mlkem_pending_node * node = NULL;
    struct km_mlkem_pending_node * evicted = NULL;
    byte *                         ct = NULL;
    word32                         ct_len = 0;
    word32                         ek_len = 0;
    int                            err;

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_MlKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_MlKemKey_PublicKeySize(wc_key, &ek_len);
    if (err != 0) {
        km_mlkem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->dst_len < ct_len) {
        km_mlkem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    ct = (byte *)malloc(ct_len);
    node = (struct km_mlkem_pending_node *)
        malloc(sizeof(struct km_mlkem_pending_node));
    if ((! ct) || (! node)) {
        err = -ENOMEM;
        goto out;
    }
    XMEMSET(node, 0, sizeof(*node));

    err = wc_MlKemKey_DecodePublicKey(wc_key, ctx->ek, ek_len);

    if (err == 0) {
        WC_RNG rng;
        err = LKCAPI_INITRNG(&rng);
        if (err == 0) {
            err = wc_MlKemKey_Encapsulate(wc_key, ct, node->ss, &rng);
            wc_FreeRng(&rng);
        }
        else {
            err = -ENODEV;
            goto out;
        }
    }

    if (err == 0)
        err = wc_Sha256Hash(ct, ct_len, node->ct_digest);

    if (err != 0)
        goto out;

    /* Publish the pending node; at capacity, evict the oldest
     * (list_add prepends, so the oldest is the tail).  Unlink under
     * the lock, free outside it.
     */
    if (wc_LockMutex(&ctx->pending_lock) != 0) {
        err = -EINVAL;
        goto out;
    }
    if (ctx->pending_count >= WC_LINUXKM_MLKEM_PENDING_MAX) {
        evicted = list_last_entry(&ctx->pending_list,
                                  struct km_mlkem_pending_node, ent);
        list_del(&evicted->ent);
        ctx->pending_count--;
    }
    list_add(&node->ent, &ctx->pending_list);
    ctx->pending_count++;
    wc_UnLockMutex(&ctx->pending_lock);
    node = NULL; /* Owned by the list now. */

    scatterwalk_map_and_copy(ct, req->dst, 0, ct_len, 1);
    req->dst_len = ct_len;

out:
    if (evicted) {
        ForceZero(evicted, sizeof(*evicted));
        free(evicted);
    }
    if (node) {
        ForceZero(node, sizeof(*node));
        free(node);
    }
    if (ct) {
        ForceZero(ct, ct_len);
        free(ct);
    }
    km_mlkem_del_wc_key(wc_key);
    return (err > 0) ? -EINVAL : err;
}

static int km_mlkem_generate_public_key(struct kpp_request *req)
{
    struct crypto_kpp *   tfm = crypto_kpp_reqtfm(req);
    struct km_mlkem_ctx * ctx = kpp_tfm_ctx(tfm);
    int                   err;

    if (req->dst == NULL)
        return -EINVAL;

    if (ctx->dk_set)
        err = km_mlkem_generate_ek(ctx, req);
    else if (ctx->ek_set)
        err = km_mlkem_generate_ct(ctx, req);
    else
        err = -EINVAL;

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: exiting km_mlkem_generate_public_key (role %s), "
            "err %d\n", ctx->ek_set ? "encap" : "decap", err);
    #endif
    return err;
}

/* Decapsulation role: req->src is the peer's ciphertext (exact size);
 * ss to req->dst.  Per FIPS 203 implicit rejection, any
 * correctly-sized ciphertext decapsulates successfully.
 */
static int km_mlkem_ss_decap(struct km_mlkem_ctx *ctx,
                             struct kpp_request *req)
{
    MlKemKey * wc_key = NULL;
    byte *     work = NULL;
    byte *     ct;
    byte *     ss;
    word32     ct_len = 0;
    word32     ss_len = 0;
    word32     dk_len = 0;
    int        err;

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_MlKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_MlKemKey_SharedSecretSize(wc_key, &ss_len);
    if (err == 0)
        err = wc_MlKemKey_PrivateKeySize(wc_key, &dk_len);
    if (err != 0) {
        km_mlkem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->src_len != ct_len) {
        km_mlkem_del_wc_key(wc_key);
        return -EINVAL;
    }
    if (req->dst_len < ss_len) {
        km_mlkem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    work = (byte *)malloc(ct_len + ss_len);
    if (! work) {
        km_mlkem_del_wc_key(wc_key);
        return -ENOMEM;
    }
    ct = work;
    ss = work + ct_len;

    scatterwalk_map_and_copy(ct, req->src, 0, ct_len, 0);

    err = wc_MlKemKey_DecodePrivateKey(wc_key, ctx->dk, dk_len);
    if (err == 0) {
        PRIVATE_KEY_UNLOCK();
        err = wc_MlKemKey_Decapsulate(wc_key, ss, ct, ct_len);
        PRIVATE_KEY_LOCK();
    }

    if (err == 0) {
        scatterwalk_map_and_copy(ss, req->dst, 0, ss_len, 1);
        req->dst_len = ss_len;
    }

    ForceZero(work, ct_len + ss_len);
    free(work);
    km_mlkem_del_wc_key(wc_key);
    return err ? -EINVAL : 0;
}

/* Encapsulation role: claim the pending shared secret for the
 * ciphertext in req->src.  Lookup and secret copyout happen under one
 * lock hold; the node is destroyed on claim (one-shot).  Unknown
 * (never-generated, already-claimed, or evicted) ciphertexts fail
 * with -ENOKEY.
 */
static int km_mlkem_ss_claim(struct km_mlkem_ctx *ctx,
                             struct kpp_request *req)
{
    MlKemKey *                     wc_key = NULL;
    struct km_mlkem_pending_node * node = NULL;
    struct km_mlkem_pending_node * found = NULL;
    byte *                         ct = NULL;
    byte                           digest[WC_SHA256_DIGEST_SIZE];
    byte                           ss[WC_ML_KEM_SS_SZ];
    word32                         ct_len = 0;
    word32                         ss_len = 0;
    int                            err;

    wc_key = km_mlkem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_MlKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_MlKemKey_SharedSecretSize(wc_key, &ss_len);
    km_mlkem_del_wc_key(wc_key);
    wc_key = NULL;
    if ((err != 0) || (ss_len > (word32)sizeof(ss)))
        return -EINVAL;

    if (req->src_len != ct_len)
        return -EINVAL;
    /* Check dst space BEFORE claiming, so a short dst doesn't consume
     * the node.
     */
    if (req->dst_len < ss_len)
        return -EOVERFLOW;

    ct = (byte *)malloc(ct_len);
    if (! ct)
        return -ENOMEM;

    scatterwalk_map_and_copy(ct, req->src, 0, ct_len, 0);

    err = wc_Sha256Hash(ct, ct_len, digest);
    free(ct);
    ct = NULL;
    if (err != 0)
        return -EINVAL;

    if (wc_LockMutex(&ctx->pending_lock) != 0)
        return -EINVAL;
    list_for_each_entry(node, &ctx->pending_list, ent) {
        if (XMEMCMP(node->ct_digest, digest,
                    WC_SHA256_DIGEST_SIZE) == 0)
        {
            found = node;
            break;
        }
    }
    if (found) {
        XMEMCPY(ss, found->ss, ss_len);
        list_del(&found->ent);
        ctx->pending_count--;
    }
    wc_UnLockMutex(&ctx->pending_lock);

    if (! found)
        return -ENOKEY;

    ForceZero(found, sizeof(*found));
    free(found);

    scatterwalk_map_and_copy(ss, req->dst, 0, ss_len, 1);
    req->dst_len = ss_len;
    ForceZero(ss, sizeof(ss));
    return 0;
}

PRAGMA_DIAG_POP /* -Wno-pointer-arith -Wno-nested-externs, for linux/list.h */

static int km_mlkem_compute_shared_secret(struct kpp_request *req)
{
    struct crypto_kpp *   tfm = crypto_kpp_reqtfm(req);
    struct km_mlkem_ctx * ctx = kpp_tfm_ctx(tfm);
    int                   err;

    if ((req->src == NULL) || (req->dst == NULL))
        return -EINVAL;

    if (ctx->dk_set)
        err = km_mlkem_ss_decap(ctx, req);
    else if (ctx->ek_set)
        err = km_mlkem_ss_claim(ctx, req);
    else
        err = -EINVAL;

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: exiting km_mlkem_compute_shared_secret (role %s), "
            "err %d\n", ctx->ek_set ? "encap" : "decap", err);
    #endif
    return err;
}

#define KM_MLKEM_DEFINE_ALG(stem, cra_name_str, type_enum)              \
    static int km_ ## stem ## _init(struct crypto_kpp *tfm)             \
    {                                                                   \
        return km_mlkem_init_common(tfm, (int)(type_enum));             \
    }                                                                   \
    static int stem ## _loaded = 0;                                     \
    static struct kpp_alg stem = {                                      \
        .base.cra_name        = (cra_name_str),                         \
        .base.cra_driver_name = cra_name_str WOLFKM_MLKEM_DRIVER_SUFFIX,\
        .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,        \
        .base.cra_module      = THIS_MODULE,                            \
        .base.cra_ctxsize     = sizeof(struct km_mlkem_ctx),            \
        .set_secret           = km_mlkem_set_secret,                    \
        .generate_public_key  = km_mlkem_generate_public_key,           \
        .compute_shared_secret = km_mlkem_compute_shared_secret,        \
        .max_size             = km_mlkem_max_size,                      \
        .init                 = km_ ## stem ## _init,                   \
        .exit                 = km_mlkem_exit,                          \
    }

#ifdef LINUXKM_MLKEM512
KM_MLKEM_DEFINE_ALG(mlkem512, "mlkem512", WC_ML_KEM_512);
static int linuxkm_test_mlkem512(void);
#endif
#ifdef LINUXKM_MLKEM768
KM_MLKEM_DEFINE_ALG(mlkem768, "mlkem768", WC_ML_KEM_768);
static int linuxkm_test_mlkem768(void);
#endif
#ifdef LINUXKM_MLKEM1024
KM_MLKEM_DEFINE_ALG(mlkem1024, "mlkem1024", WC_ML_KEM_1024);
static int linuxkm_test_mlkem1024(void);
#endif

/* self-test, zero KAT rodata: a fixed d||z seed drives deterministic
 * keygen both through the glue (decapsulation role) and in a local
 * wolfCrypt key, so the two provably hold the same keypair; each side
 * then encapsulates for the other:
 *   - decap direction: wolfCrypt encapsulates against the
 *     glue-exported ek; the glue decapsulates; secrets must match.
 *   - encap direction: the tfm is re-keyed with the ek (role switch),
 *     the glue encapsulates; wolfCrypt decapsulates the emitted
 *     ciphertext; the claimed and decapsulated secrets must match.
 * plus negatives: length checks, one-shot claim, unknown-ct claim,
 * pending-list eviction at capacity, and role-switch reaping.
 */
static int linuxkm_test_mlkem_driver(const char * driver, int type)
{
    int                  test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                  ret = 0;
    struct crypto_kpp *  tfm = NULL;
    struct kpp_request * req = NULL;
    MlKemKey *           wc_key = NULL;
    byte *               work = NULL;
    byte *               ek;
    byte *               ct;
    byte *               ct_first;
    byte *               ss_a;
    byte *               ss_b;
    word32               ek_len = 0;
    word32               ct_len = 0;
    word32               ss_len = 0;
    struct scatterlist   src_sg;
    struct scatterlist   dst_sg;
    byte                 seed[WC_ML_KEM_MAKEKEY_RAND_SZ];
    word32               i;

    /* Fixed test seed for keygen. */
    for (i = 0; i < (word32)sizeof(seed); i++)
        seed[i] = (byte)(0xa0U ^ i);

    wc_key = km_mlkem_new_wc_key(type);
    if (! wc_key) {
        test_rc = MEMORY_E;
        goto test_mlkem_end;
    }
    if ((wc_MlKemKey_PublicKeySize(wc_key, &ek_len) != 0) ||
        (wc_MlKemKey_CipherTextSize(wc_key, &ct_len) != 0) ||
        (wc_MlKemKey_SharedSecretSize(wc_key, &ss_len) != 0))
    {
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* The local wolfCrypt keypair, from the same seed the glue will use. */
    ret = wc_MlKemKey_MakeKeyWithRandom(wc_key, seed,
                                        (int)sizeof(seed));
    if (ret != 0) {
        pr_err("error: wc_MlKemKey_MakeKeyWithRandom returned: %d\n",
               ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    work = (byte *)malloc(ek_len + (2 * ct_len) + (2 * ss_len));
    if (! work) {
        test_rc = MEMORY_E;
        goto test_mlkem_end;
    }
    ek = work;
    ct = work + ek_len;
    ct_first = work + ek_len + ct_len;
    ss_a = work + ek_len + (2 * ct_len);
    ss_b = work + ek_len + (2 * ct_len) + ss_len;

    tfm = crypto_alloc_kpp(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating kpp algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_mlkem_end;
    }

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (! req) {
        test_rc = -ENOMEM;
        pr_err("error: allocating kpp request %s failed\n", driver);
        goto test_mlkem_end;
    }

    /* ==== decapsulation role ==== */

    ret = crypto_kpp_set_secret(tfm, seed, (unsigned int)sizeof(seed));
    if (ret) {
        pr_err("error: crypto_kpp_set_secret (seed, %u) returned: %d\n",
               (unsigned int)sizeof(seed), ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    {
        unsigned int maxsize = crypto_kpp_maxsize(tfm);
        if (maxsize != ek_len) {
            pr_err("error: crypto_kpp_maxsize returned %u, expected "
                   "%u\n", maxsize, ek_len);
            test_rc = BAD_FUNC_ARG;
            goto test_mlkem_end;
        }
    }

    sg_init_one(&dst_sg, ek, ek_len);
    kpp_request_set_output(req, &dst_sg, ek_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        pr_err("error: crypto_kpp_generate_public_key returned: %d\n",
               ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* the glue's seed-derived ek must equal the local one. */
    {
        byte *ek_chk = (byte *)malloc(ek_len);
        if (! ek_chk) {
            test_rc = MEMORY_E;
            goto test_mlkem_end;
        }
        ret = wc_MlKemKey_EncodePublicKey(wc_key, ek_chk, ek_len);
        if ((ret != 0) || (XMEMCMP(ek, ek_chk, ek_len) != 0)) {
            pr_err("error: glue ek != wolfCrypt ek (ret %d)\n", ret);
            free(ek_chk);
            test_rc = BAD_FUNC_ARG;
            goto test_mlkem_end;
        }
        free(ek_chk);
    }

    /* short ek dst must fail with -EOVERFLOW. */
    sg_init_one(&dst_sg, ek, ek_len - 1);
    kpp_request_set_output(req, &dst_sg, ek_len - 1);
    ret = crypto_kpp_generate_public_key(req);
    if (ret != -EOVERFLOW) {
        pr_err("error: crypto_kpp_generate_public_key (short dst) "
               "returned %d, expected %d\n", ret, -EOVERFLOW);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* wolfCrypt encapsulates; the glue decapsulates. */
    {
        WC_RNG rng;
        ret = LKCAPI_INITRNG(&rng);
        if (ret != 0) {
            test_rc = BAD_FUNC_ARG;
            goto test_mlkem_end;
        }
        ret = wc_MlKemKey_Encapsulate(wc_key, ct, ss_a, &rng);
        wc_FreeRng(&rng);
        if (ret != 0) {
            pr_err("error: wc_MlKemKey_Encapsulate returned: %d\n",
                   ret);
            test_rc = BAD_FUNC_ARG;
            goto test_mlkem_end;
        }
    }

    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret) {
        pr_err("error: crypto_kpp_compute_shared_secret returned: "
               "%d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) != 0) {
        pr_err("error: decapsulated secret != encapsulated secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* implicit rejection: a corrupted ciphertext must decapsulate
     * SUCCESSFULLY, to a different secret.
     */
    ct[ct_len / 2] ^= 1U;
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret) {
        pr_err("error: crypto_kpp_compute_shared_secret (corrupt ct) "
               "returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) == 0) {
        pr_err("error: corrupt ct decapsulated to the SAME secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    ct[ct_len / 2] ^= 1U;

    /* wrong-size ct must fail with -EINVAL. */
    sg_init_one(&src_sg, ct, ct_len - 1);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len - 1);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -EINVAL) {
        pr_err("error: crypto_kpp_compute_shared_secret (short ct) "
               "returned %d, expected %d\n", ret, -EINVAL);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* ==== encapsulation role (role switch by ek-length secret) ==== */

    ret = crypto_kpp_set_secret(tfm, ek, ek_len);
    if (ret) {
        pr_err("error: crypto_kpp_set_secret (ek, %u) returned: %d\n",
               ek_len, ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* glue encapsulates; wolfCrypt decapsulates. */
    sg_init_one(&dst_sg, ct, ct_len);
    kpp_request_set_output(req, &dst_sg, ct_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        pr_err("error: crypto_kpp_generate_public_key (encap) "
               "returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_MlKemKey_Decapsulate(wc_key, ss_a, ct, ct_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        pr_err("error: wc_MlKemKey_Decapsulate returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* short ss dst must fail with -EOVERFLOW, without consuming the
     * pending node.
     */
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len - 1);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len - 1);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -EOVERFLOW) {
        pr_err("error: crypto_kpp_compute_shared_secret (short ss "
               "dst) returned %d, expected %d\n", ret, -EOVERFLOW);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* claim: the pending secret must match wolfCrypt's decapsulation. */
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret) {
        pr_err("error: crypto_kpp_compute_shared_secret (claim) "
               "returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) != 0) {
        pr_err("error: claimed secret != decapsulated secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* one-shot: a second claim of the same ciphertext must fail. */
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -ENOKEY) {
        pr_err("error: double-claim returned %d, expected %d\n", ret,
               -ENOKEY);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* unknown ct must fail. */
    ct[0] ^= 1U;
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -ENOKEY) {
        pr_err("error: unknown-ct claim returned %d, expected %d\n",
               ret, -ENOKEY);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    ct[0] ^= 1U;

    /* eviction: overfill the pending list; the first ciphertext's node
     * must be evicted, the last still claimable.
     */
    for (i = 0; i <= (word32)WC_LINUXKM_MLKEM_PENDING_MAX; i++) {
        byte *dst = (i == 0) ? ct_first : ct;
        sg_init_one(&dst_sg, dst, ct_len);
        kpp_request_set_output(req, &dst_sg, ct_len);
        ret = crypto_kpp_generate_public_key(req);
        if (ret) {
            pr_err("error: generate #%u returned: %d\n", i, ret);
            test_rc = BAD_FUNC_ARG;
            goto test_mlkem_end;
        }
    }
    sg_init_one(&src_sg, ct_first, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -ENOKEY) {
        pr_err("error: evicted-ct claim returned %d, expected %d\n",
               ret, -ENOKEY);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    PRIVATE_KEY_UNLOCK();
    ret = wc_MlKemKey_Decapsulate(wc_key, ss_a, ct, ct_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if ((ret != 0) || (XMEMCMP(ss_a, ss_b, ss_len) != 0)) {
        pr_err("error: newest-ct claim after eviction failed (ret "
               "%d)\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    /* role-switch reaping: park an encapsulation, switch roles away
     * and back; the pending node must be gone.
     */
    sg_init_one(&dst_sg, ct, ct_len);
    kpp_request_set_output(req, &dst_sg, ct_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    ret = crypto_kpp_set_secret(tfm, seed, (unsigned int)sizeof(seed));
    if (ret == 0)
        ret = crypto_kpp_set_secret(tfm, ek, ek_len);
    if (ret) {
        pr_err("error: role-switch set_secret returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }
    sg_init_one(&src_sg, ct, ct_len);
    sg_init_one(&dst_sg, ss_b, ss_len);
    kpp_request_set_input(req, &src_sg, ct_len);
    kpp_request_set_output(req, &dst_sg, ss_len);
    ret = crypto_kpp_compute_shared_secret(req);
    if (ret != -ENOKEY) {
        pr_err("error: claim after role-switch reap returned %d, "
               "expected %d\n", ret, -ENOKEY);
        test_rc = BAD_FUNC_ARG;
        goto test_mlkem_end;
    }

    test_rc = 0;
test_mlkem_end:
    if (req) { kpp_request_free(req); req = NULL; }
    if (tfm) { crypto_free_kpp(tfm); tfm = NULL; }
    if (wc_key) { km_mlkem_del_wc_key(wc_key); wc_key = NULL; }
    if (work) { ForceZero(work, ek_len + (2 * ct_len) + (2 * ss_len));
                free(work); work = NULL; }

    #ifdef WOLFKM_DEBUG_MLKEM
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#ifdef LINUXKM_MLKEM512
static int linuxkm_test_mlkem512(void)
{
    return linuxkm_test_mlkem_driver("mlkem512" WOLFKM_MLKEM_DRIVER_SUFFIX,
                                     (int)WC_ML_KEM_512);
}
#endif
#ifdef LINUXKM_MLKEM768
static int linuxkm_test_mlkem768(void)
{
    return linuxkm_test_mlkem_driver("mlkem768" WOLFKM_MLKEM_DRIVER_SUFFIX,
                                     (int)WC_ML_KEM_768);
}
#endif
#ifdef LINUXKM_MLKEM1024
static int linuxkm_test_mlkem1024(void)
{
    return linuxkm_test_mlkem_driver("mlkem1024" WOLFKM_MLKEM_DRIVER_SUFFIX,
                                     (int)WC_ML_KEM_1024);
}
#endif

#endif /* LINUXKM_LKCAPI_REGISTER_MLKEM */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
