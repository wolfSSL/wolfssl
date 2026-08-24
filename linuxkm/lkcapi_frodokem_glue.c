/* lkcapi_frodokem_glue.c -- glue logic to register FrodoKEM (ISO/IEC 18033-2
 * amendment track, draft-longa-cfrg-frodokem) with the LKCAPI (as kpp)
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
    #error lkcapi_frodokem_glue.c included in non-LINUXKM_LKCAPI_REGISTER \
project.
#endif

/* EXPERIMENTAL: full FrodoKEM glue -- decapsulation AND encapsulation --
 * registered as struct kpp_alg, following lkcapi_mlkem_glue.c in every
 * particular of the architecture (see that file's header comment for the
 * full rationale; only the FrodoKEM-specific deltas are described here).
 *
 * FrodoKEM is not a FIPS algorithm: it is on the ISO/IEC 18033-2 amendment
 * track, and the wolfCrypt implementation is itself gated behind
 * --enable-experimental.  These registrations sit outside any FIPS
 * boundary.
 *
 * Like ML-KEM, FrodoKEM is an FO-transform KEM (KeyGen/Encaps/Decaps,
 * randomized one-input/two-output encapsulation, implicit rejection), so
 * the ML-KEM kpp mapping transfers wholesale:
 *
 * Roles.  A tfm takes its role from set_secret():
 *   - DECAPSULATION (responder): set_secret is the raw FrodoKEM sk
 *     (s || seedA || b || S^T || pkh, exact size for the type), the
 *     s || seedSE || z keygen randomness (length varies by type; see
 *     km_frodokem_keygen_rand_len()), or NULL/empty to generate a fresh
 *     key (the empty-secret-keygen convention follows ecdh_set_secret()).
 *     generate_public_key emits the raw public key pk = seedA || b.
 *     compute_shared_secret takes the peer's ciphertext as src and emits
 *     ss by decapsulation.
 *   - ENCAPSULATION (initiator): set_secret is the peer's raw pk (exact
 *     size for the type; all four accepted set_secret lengths are
 *     pairwise distinct for every type, so the length dictates the role
 *     unambiguously).  generate_public_key runs a fresh encapsulation:
 *     the ciphertext is written to req->dst, and a pending node
 *     {SHA-256(ct), ss} is parked on a lock-guarded list in the tfm ctx.
 *     compute_shared_secret takes that ciphertext as src, looks up the
 *     pending node by ciphertext digest, and CLAIMS it (one-shot; a
 *     second claim of the same ciphertext fails -ENOKEY).
 *
 * Bookkeeping (bounded pending list, oldest-eviction, claim under a
 * single lock hold, ForceZero on every teardown, role-switch reaping) is
 * identical to lkcapi_mlkem_glue.c.
 *
 * Per FrodoKEM implicit rejection, decapsulation of any correctly-sized
 * ciphertext SUCCEEDS; an invalid ciphertext yields a pseudorandom
 * shared secret (constant-time selection of the sk's s value) rather
 * than an error.  Only malformed lengths fail.
 *
 * FrodoKEM-specific deltas from the ML-KEM glue:
 *   - Twelve types rather than three: {640, 976, 1344} x {SHAKE-128,
 *     AES-128 matrix-A generation} x {standard (salted), eFrodoKEM
 *     (ephemeral, salt-less)}, each a distinct wire format and so a
 *     distinct cra_name ("frodokem640shake" ... "efrodokem1344aes").
 *   - The ct <= pk size relation INVERTS: every FrodoKEM ciphertext is
 *     larger than its public key (by d*nbar bytes plus the salt, less
 *     the 16-byte seedA), so max_size() reports the CIPHERTEXT size for
 *     both roles (statically asserted below).
 *   - The keygen-randomness length varies by type (s || seedSE || z,
 *     with |seedSE| halved for the ephemeral types) rather than being a
 *     single WC_ML_KEM_MAKEKEY_RAND_SZ constant.
 *   - Keys are big (sk up to ~43 KB), so the tfm ctx stores sk and pk in
 *     ONE buffer rather than two: the roles are mutually exclusive and
 *     any set_secret() resets the role, so the buffer never needs to
 *     hold both (statically asserted below that pk fits).
 *
 * Because the frodokem* and efrodokem* cra_names are unknown to
 * crypto/testmgr.c, alg_test() takes its "notest" path and returns
 * success at registration time, with or without fips_enabled.
 * Self-tests are supplied by the linuxkm_test_*frodokem*() functions
 * below (zero KAT rodata: vectors are generated at test time from a
 * fixed keygen seed); algorithm-correctness KATs live in
 * wolfcrypt/test/test.c.
 */

#if defined(WOLFSSL_HAVE_FRODOKEM) &&              \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) &&      \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) &&   \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    /* The role model needs all three operations: keygen for the
     * decapsulation-role set_secret forms and the self-tests,
     * encapsulation for the encapsulation role, decapsulation for the
     * decapsulation role.  Partial-operation builds are for constrained
     * userspace targets and get no kernel registration. */
    #if defined(LINUXKM_LKCAPI_REGISTER_ALL) &&            \
        !defined(LINUXKM_LKCAPI_DONT_REGISTER_FRODOKEM) && \
        !defined(LINUXKM_LKCAPI_REGISTER_FRODOKEM)
        #define LINUXKM_LKCAPI_REGISTER_FRODOKEM
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_FRODOKEM
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_FRODOKEM

#include <wolfssl/wolfcrypt/wc_frodokem.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef NO_SHA256
    #error lkcapi_frodokem_glue.c encapsulation support requires SHA-256 \
for pending-node association.
#endif

/* Per-type registration gates.  wc_frodokem.h guarantees at least one
 * parameter set and one matrix-A generation method are enabled. */
#ifdef WOLFSSL_WC_FRODOKEM_640
    #ifdef WOLFSSL_FRODOKEM_SHAKE
        #define LINUXKM_FRODOKEM640SHAKE
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM640SHAKE
        #endif
    #endif
    #ifdef WOLFSSL_FRODOKEM_AES
        #define LINUXKM_FRODOKEM640AES
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM640AES
        #endif
    #endif
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    #ifdef WOLFSSL_FRODOKEM_SHAKE
        #define LINUXKM_FRODOKEM976SHAKE
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM976SHAKE
        #endif
    #endif
    #ifdef WOLFSSL_FRODOKEM_AES
        #define LINUXKM_FRODOKEM976AES
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM976AES
        #endif
    #endif
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    #ifdef WOLFSSL_FRODOKEM_SHAKE
        #define LINUXKM_FRODOKEM1344SHAKE
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM1344SHAKE
        #endif
    #endif
    #ifdef WOLFSSL_FRODOKEM_AES
        #define LINUXKM_FRODOKEM1344AES
        #ifdef WOLFSSL_FRODOKEM_EPHEMERAL
            #define LINUXKM_EFRODOKEM1344AES
        #endif
    #endif
#endif

#if defined(USE_INTEL_SPEEDUP)
    /* Mirrors the FRODOKEM_HAVE_MATRIX_ASM_AVX512 condition in
     * wc_frodokem_mat.h. */
    #ifndef NO_AVX512_SUPPORT
        #define WOLFKM_FRODOKEM_DRIVER_ISA_EXT "-avx512"
    #else
        #define WOLFKM_FRODOKEM_DRIVER_ISA_EXT "-avx2"
    #endif
#else
    #define WOLFKM_FRODOKEM_DRIVER_ISA_EXT ""
#endif

#define WOLFKM_FRODOKEM_DRIVER_SUFFIX \
    WOLFKM_FRODOKEM_DRIVER_ISA_EXT WOLFKM_DRIVER_SUFFIX_BASE

/* max_size() reports the ciphertext size for both roles, which is
 * correct only because pk <= ct for every FrodoKEM type -- NOTE this is
 * the opposite of the ML-KEM relation (ct <= ek there).  Check that
 * assumption, for the standard (salted) and ephemeral (salt-less)
 * ciphertext of each enabled parameter set. */
#ifdef WOLFSSL_WC_FRODOKEM_640
wc_static_assert(WC_FRODOKEM_640_PUBLIC_KEY_SIZE <=
                 WC_FRODOKEM_640_CIPHER_TEXT_SIZE);
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
wc_static_assert(WC_FRODOKEM_640_PUBLIC_KEY_SIZE <=
                 FRODOKEM_CT_SZ(WC_FRODOKEM_640_N, WC_FRODOKEM_640_D, 0));
#endif
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
wc_static_assert(WC_FRODOKEM_976_PUBLIC_KEY_SIZE <=
                 WC_FRODOKEM_976_CIPHER_TEXT_SIZE);
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
wc_static_assert(WC_FRODOKEM_976_PUBLIC_KEY_SIZE <=
                 FRODOKEM_CT_SZ(WC_FRODOKEM_976_N, WC_FRODOKEM_976_D, 0));
#endif
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
wc_static_assert(WC_FRODOKEM_1344_PUBLIC_KEY_SIZE <=
                 WC_FRODOKEM_1344_CIPHER_TEXT_SIZE);
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
wc_static_assert(WC_FRODOKEM_1344_PUBLIC_KEY_SIZE <=
                 FRODOKEM_CT_SZ(WC_FRODOKEM_1344_N, WC_FRODOKEM_1344_D, 0));
#endif
#endif

/* The tfm ctx stores the encoded sk (decapsulation role) or the peer's
 * pk (encapsulation role) in one buffer sized for the sk; the roles are
 * mutually exclusive.  Check that a pk fits. */
wc_static_assert(FRODOKEM_MAX_PUBLIC_KEY_SIZE <=
                 FRODOKEM_MAX_PRIVATE_KEY_SIZE);

/* Bound on unclaimed encapsulations per tfm; oldest evicted at
 * capacity. */
#ifdef WC_LINUXKM_FRODOKEM_PENDING_MAX
    wc_static_assert_if_const(WC_LINUXKM_FRODOKEM_PENDING_MAX > 0,
        "WC_LINUXKM_FRODOKEM_PENDING_MAX must be positive.");
#else
    #define WC_LINUXKM_FRODOKEM_PENDING_MAX 16
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
struct km_frodokem_pending_node {
    struct list_head ent;
    byte             ct_digest[WC_SHA256_DIGEST_SIZE];
    byte             ss[FRODOKEM_MAX_LENSEC];
};

/* struct FrodoKemKey embeds working state mutated during operations
 * (the reusable SHAKE object, and the reusable AES object under
 * WOLFSSL_FRODOKEM_AES), so, as with ML-KEM (see lkcapi_mlkem_glue.c),
 * the tfm ctx stores only raw key octets and each operation runs on a
 * transient heap-allocated FrodoKemKey.  The pending list and its lock
 * are the one deliberate exception to read-only-ctx-during-ops -- see
 * the header comment.
 *
 * key_octets holds the encoded sk (decapsulation role, sk_set) or the
 * peer's raw pk (encapsulation role, pk_set) -- never both, since any
 * set_secret() resets the role; a single sk-sized buffer (pk < sk for
 * every type, statically asserted above) keeps the ctx to ~43 KB
 * instead of ~65 KB. */
struct km_frodokem_ctx {
    int              type;      /* WC_[E]FRODOKEM_{640,976,1344}_{SHAKE,AES} */
    int              sk_set;    /* decapsulation role */
    int              pk_set;    /* encapsulation role */
    byte             key_octets[FRODOKEM_MAX_PRIVATE_KEY_SIZE];
    wolfSSL_Mutex    pending_lock;
    struct list_head pending_list;
    unsigned int     pending_count;
};

static FrodoKemKey * km_frodokem_new_wc_key(int type)
{
    FrodoKemKey *key = (FrodoKemKey *)malloc(sizeof(FrodoKemKey));
    if (key) {
        if (wc_FrodoKemKey_Init(key, type, NULL /* heap */,
                                INVALID_DEVID) != 0)
        {
            free(key);
            key = NULL;
        }
    }
    return key;
}

static void km_frodokem_del_wc_key(FrodoKemKey *key)
{
    if (key) {
        wc_FrodoKemKey_Free(key);
        ForceZero(key, sizeof(FrodoKemKey));
        free(key);
    }
}

/* Reap every pending node.  Caller must not hold pending_lock. */
static void km_frodokem_reap_pending(struct km_frodokem_ctx *ctx)
{
    struct list_head reaped;
    struct km_frodokem_pending_node *node, *tmp;

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

static int km_frodokem_init_common(struct crypto_kpp *tfm, int type)
{
    struct km_frodokem_ctx *ctx = kpp_tfm_ctx(tfm);

    XMEMSET(ctx, 0, sizeof(struct km_frodokem_ctx));
    ctx->type = type;
    if (wc_InitMutex(&ctx->pending_lock) != 0)
        return -ENOMEM;
    INIT_LIST_HEAD(&ctx->pending_list);

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: exiting km_frodokem_init_common (type %d)\n", type);
    #endif /* WOLFKM_DEBUG_FRODOKEM */
    return 0;
}

static void km_frodokem_exit(struct crypto_kpp *tfm)
{
    struct km_frodokem_ctx *ctx = kpp_tfm_ctx(tfm);

    km_frodokem_reap_pending(ctx);
    wc_FreeMutex(&ctx->pending_lock);
    ForceZero(ctx, sizeof(struct km_frodokem_ctx));

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: exiting km_frodokem_exit\n");
    #endif /* WOLFKM_DEBUG_FRODOKEM */
    return;
}

/* The length of the FrodoKEM.KeyGenInternal randomness s || seedSE || z
 * for a type: |s| = lenSec, |seedSE| = lenSE, |z| = lenA / 8 = 16.  The
 * standard (salted) types use lenSE = 2 * lenSec; the ephemeral
 * (eFrodoKEM) types use lenSE = lenSec (see the parameter tables in
 * wc_frodokem.c).  Must agree with the length check in
 * wc_FrodoKemKey_MakeKeyWithRandom() (a mismatch fails fast: the
 * self-test's first set_secret() takes this length).
 */
static word32 km_frodokem_keygen_rand_len(int type)
{
    word32 len_sec;
    word32 len_se;

    switch (type & FRODOKEM_BASE_MASK) {
    case WC_FRODOKEM_640:
        len_sec = WC_FRODOKEM_640_LENSEC;
        len_se  = WC_FRODOKEM_640_LENSE;
        break;
    case WC_FRODOKEM_976:
        len_sec = WC_FRODOKEM_976_LENSEC;
        len_se  = WC_FRODOKEM_976_LENSE;
        break;
    case WC_FRODOKEM_1344:
        len_sec = WC_FRODOKEM_1344_LENSEC;
        len_se  = WC_FRODOKEM_1344_LENSE;
        break;
    default:
        return 0;
    }

    if (type & FRODOKEM_EPHEMERAL)
        len_se = len_sec;

    return len_sec + len_se + FRODOKEM_SEEDA_SZ;
}

/*
 * Sets the key, and thereby the role -- see the header comment.
 *
 * tfm     The crypto_kpp transform
 * buffer  The raw FrodoKEM sk, the s || seedSE || z keygen randomness,
 *         or NULL/empty to generate a fresh key (all: decapsulation
 *         role); or the peer's raw pk (encapsulation role).  The four
 *         lengths are pairwise distinct for every type.
 * len     Buffer length
 */
static int km_frodokem_set_secret(struct crypto_kpp *tfm, const void *buffer,
                                  unsigned int len)
{
    struct km_frodokem_ctx * ctx = kpp_tfm_ctx(tfm);
    FrodoKemKey *            wc_key = NULL;
    word32                   sk_len = 0;
    word32                   pk_len = 0;
    int                      err;

    /* Any (re)key resets the role and reaps pending encapsulations.
     * key_octets may hold an sk, so zeroization is unconditional. */
    if (ctx->sk_set || ctx->pk_set) {
        ForceZero(ctx->key_octets, sizeof ctx->key_octets);
        ctx->sk_set = 0;
        ctx->pk_set = 0;
    }
    km_frodokem_reap_pending(ctx);

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_FrodoKemKey_PrivateKeySize(wc_key, &sk_len);
    if (err == 0)
        err = wc_FrodoKemKey_PublicKeySize(wc_key, &pk_len);
    if (err != 0) {
        km_frodokem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if ((buffer == NULL) || (len == 0)) {
        /* Decapsulation role: generate a fresh key. */
        WC_RNG rng;
        err = LKCAPI_INITRNG(&rng);
        if (err == 0) {
            err = wc_FrodoKemKey_MakeKey(wc_key, &rng);
            wc_FreeRng(&rng);
        }
        else {
            err = -ENODEV;
            goto out;
        }
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_FrodoKemKey_EncodePrivateKey(wc_key, ctx->key_octets,
                                                  sk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->sk_set = 1;
    }
    else if (len == (unsigned int)km_frodokem_keygen_rand_len(ctx->type)) {
        /* Decapsulation role: deterministic keygen from the
         * s || seedSE || z randomness. */
        err = wc_FrodoKemKey_MakeKeyWithRandom(wc_key, (const byte *)buffer,
                                               (int)len);
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_FrodoKemKey_EncodePrivateKey(wc_key, ctx->key_octets,
                                                  sk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->sk_set = 1;
    }
    else if (len == (unsigned int)sk_len) {
        /* Decapsulation role: import sk (validated by decode against the
         * embedded public-key hash). */
        err = wc_FrodoKemKey_DecodePrivateKey(wc_key, (const byte *)buffer,
                                              len);
        if (err == 0) {
            PRIVATE_KEY_UNLOCK();
            err = wc_FrodoKemKey_EncodePrivateKey(wc_key, ctx->key_octets,
                                                  sk_len);
            PRIVATE_KEY_LOCK();
        }
        if (err == 0)
            ctx->sk_set = 1;
    }
    else if (len == (unsigned int)pk_len) {
        /* Encapsulation role: import the peer's pk (validated by decode). */
        err = wc_FrodoKemKey_DecodePublicKey(wc_key, (const byte *)buffer,
                                             len);
        if (err == 0) {
            XMEMCPY(ctx->key_octets, buffer, pk_len);
            ctx->pk_set = 1;
        }
    }
    else {
        err = BAD_FUNC_ARG;
    }

out:
    km_frodokem_del_wc_key(wc_key);

    if (unlikely(err)) {
        #ifdef WOLFKM_DEBUG_FRODOKEM
        pr_err("error: km_frodokem_set_secret (len %u): %d\n", len, err);
        #endif
        return (err < -1000 || err > 0) ? err : -EINVAL;
    }

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: exiting km_frodokem_set_secret %u (role %s)\n", len,
            ctx->pk_set ? "encap" : "decap");
    #endif
    return 0;
}

/* The largest kpp output for this tfm.  pk for the decapsulation role;
 * ct for the encapsulation role -- but pk <= ct for every type
 * (statically asserted above; NOTE the inversion relative to ML-KEM),
 * so ct covers both.
 */
static unsigned int km_frodokem_max_size(struct crypto_kpp *tfm)
{
    struct km_frodokem_ctx * ctx = kpp_tfm_ctx(tfm);
    FrodoKemKey *            wc_key;
    word32                   len = 0;

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return 0;
    if (wc_FrodoKemKey_CipherTextSize(wc_key, &len) != 0)
        len = 0;
    km_frodokem_del_wc_key(wc_key);
    return len;
}

/* Decapsulation role: emit the raw public key pk to req->dst. */
static int km_frodokem_generate_pk(struct km_frodokem_ctx *ctx,
                                   struct kpp_request *req)
{
    FrodoKemKey * wc_key = NULL;
    byte *        pk = NULL;
    word32        pk_len = 0;
    word32        sk_len = 0;
    int           err;

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_FrodoKemKey_PublicKeySize(wc_key, &pk_len);
    if (err == 0)
        err = wc_FrodoKemKey_PrivateKeySize(wc_key, &sk_len);
    if (err != 0) {
        km_frodokem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->dst_len < pk_len) {
        km_frodokem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    pk = (byte *)malloc(pk_len);
    if (! pk) {
        km_frodokem_del_wc_key(wc_key);
        return -ENOMEM;
    }

    /* The FrodoKEM sk contains pk (seedA || b); DecodePrivateKey
     * recovers it. */
    err = wc_FrodoKemKey_DecodePrivateKey(wc_key, ctx->key_octets, sk_len);
    if (err == 0)
        err = wc_FrodoKemKey_EncodePublicKey(wc_key, pk, pk_len);

    if (err == 0) {
        scatterwalk_map_and_copy(pk, req->dst, 0, pk_len, 1);
        req->dst_len = pk_len;
    }

    free(pk);
    km_frodokem_del_wc_key(wc_key);
    return err ? -EINVAL : 0;
}

/* Encapsulation role: run a fresh encapsulation against the installed
 * peer pk.  The ciphertext goes to req->dst; the shared secret is
 * parked on the pending list, keyed by SHA-256(ct), awaiting claim by
 * compute_shared_secret.
 */
static int km_frodokem_generate_ct(struct km_frodokem_ctx *ctx,
                                   struct kpp_request *req)
{
    FrodoKemKey *                     wc_key = NULL;
    struct km_frodokem_pending_node * node = NULL;
    struct km_frodokem_pending_node * evicted = NULL;
    byte *                            ct = NULL;
    word32                            ct_len = 0;
    word32                            pk_len = 0;
    int                               err;

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_FrodoKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_FrodoKemKey_PublicKeySize(wc_key, &pk_len);
    if (err != 0) {
        km_frodokem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->dst_len < ct_len) {
        km_frodokem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    ct = (byte *)malloc(ct_len);
    node = (struct km_frodokem_pending_node *)
        malloc(sizeof(struct km_frodokem_pending_node));
    if ((! ct) || (! node)) {
        err = -ENOMEM;
        goto out;
    }
    XMEMSET(node, 0, sizeof(*node));

    err = wc_FrodoKemKey_DecodePublicKey(wc_key, ctx->key_octets, pk_len);

    if (err == 0) {
        WC_RNG rng;
        err = LKCAPI_INITRNG(&rng);
        if (err == 0) {
            err = wc_FrodoKemKey_Encapsulate(wc_key, ct, node->ss, &rng);
            wc_FreeRng(&rng);
        }
        else {
            err = -ENODEV;
            goto out;
        }
    }

    if (err == 0)
        err = wc_Sha256Hash(ct, ct_len, node->ct_digest);

    if (err != 0) {
        /* Normalize wolfCrypt failure codes to a kernel errno; the kernel
         * errnos this function sets itself (-ENOMEM, -ENODEV) take their
         * own paths to out.  Matches km_frodokem_generate_pk(). */
        err = -EINVAL;
        goto out;
    }

    /* Publish the pending node; at capacity, evict the oldest
     * (list_add prepends, so the oldest is the tail).  Unlink under
     * the lock, free outside it.
     */
    if (wc_LockMutex(&ctx->pending_lock) != 0) {
        err = -EINVAL;
        goto out;
    }
    if (ctx->pending_count >= WC_LINUXKM_FRODOKEM_PENDING_MAX) {
        evicted = list_last_entry(&ctx->pending_list,
                                  struct km_frodokem_pending_node, ent);
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
    km_frodokem_del_wc_key(wc_key);
    return (err > 0) ? -EINVAL : err;
}

static int km_frodokem_generate_public_key(struct kpp_request *req)
{
    struct crypto_kpp *      tfm = crypto_kpp_reqtfm(req);
    struct km_frodokem_ctx * ctx = kpp_tfm_ctx(tfm);
    int                      err;

    if (req->dst == NULL)
        return -EINVAL;

    if (ctx->sk_set)
        err = km_frodokem_generate_pk(ctx, req);
    else if (ctx->pk_set)
        err = km_frodokem_generate_ct(ctx, req);
    else
        err = -EINVAL;

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: exiting km_frodokem_generate_public_key (role %s), "
            "err %d\n", ctx->pk_set ? "encap" : "decap", err);
    #endif
    return err;
}

/* Decapsulation role: req->src is the peer's ciphertext (exact size);
 * ss to req->dst.  Per FrodoKEM implicit rejection, any correctly-sized
 * ciphertext decapsulates successfully.
 */
static int km_frodokem_ss_decap(struct km_frodokem_ctx *ctx,
                                struct kpp_request *req)
{
    FrodoKemKey * wc_key = NULL;
    byte *        work = NULL;
    byte *        ct;
    byte *        ss;
    word32        ct_len = 0;
    word32        ss_len = 0;
    word32        sk_len = 0;
    int           err;

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_FrodoKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_FrodoKemKey_SharedSecretSize(wc_key, &ss_len);
    if (err == 0)
        err = wc_FrodoKemKey_PrivateKeySize(wc_key, &sk_len);
    if (err != 0) {
        km_frodokem_del_wc_key(wc_key);
        return -EINVAL;
    }

    if (req->src_len != ct_len) {
        km_frodokem_del_wc_key(wc_key);
        return -EINVAL;
    }
    if (req->dst_len < ss_len) {
        km_frodokem_del_wc_key(wc_key);
        return -EOVERFLOW;
    }

    work = (byte *)malloc(ct_len + ss_len);
    if (! work) {
        km_frodokem_del_wc_key(wc_key);
        return -ENOMEM;
    }
    ct = work;
    ss = work + ct_len;

    scatterwalk_map_and_copy(ct, req->src, 0, ct_len, 0);

    err = wc_FrodoKemKey_DecodePrivateKey(wc_key, ctx->key_octets, sk_len);
    if (err == 0) {
        PRIVATE_KEY_UNLOCK();
        err = wc_FrodoKemKey_Decapsulate(wc_key, ss, ct, ct_len);
        PRIVATE_KEY_LOCK();
    }

    if (err == 0) {
        scatterwalk_map_and_copy(ss, req->dst, 0, ss_len, 1);
        req->dst_len = ss_len;
    }

    ForceZero(work, ct_len + ss_len);
    free(work);
    km_frodokem_del_wc_key(wc_key);
    return err ? -EINVAL : 0;
}

/* Encapsulation role: claim the pending shared secret for the
 * ciphertext in req->src.  Lookup and secret copyout happen under one
 * lock hold; the node is destroyed on claim (one-shot).  Unknown
 * (never-generated, already-claimed, or evicted) ciphertexts fail
 * with -ENOKEY.
 */
static int km_frodokem_ss_claim(struct km_frodokem_ctx *ctx,
                                struct kpp_request *req)
{
    FrodoKemKey *                     wc_key = NULL;
    struct km_frodokem_pending_node * node = NULL;
    struct km_frodokem_pending_node * found = NULL;
    byte *                            ct = NULL;
    byte                              digest[WC_SHA256_DIGEST_SIZE];
    byte                              ss[FRODOKEM_MAX_LENSEC];
    word32                            ct_len = 0;
    word32                            ss_len = 0;
    int                               err;

    wc_key = km_frodokem_new_wc_key(ctx->type);
    if (! wc_key)
        return -ENOMEM;

    err = wc_FrodoKemKey_CipherTextSize(wc_key, &ct_len);
    if (err == 0)
        err = wc_FrodoKemKey_SharedSecretSize(wc_key, &ss_len);
    km_frodokem_del_wc_key(wc_key);
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

static int km_frodokem_compute_shared_secret(struct kpp_request *req)
{
    struct crypto_kpp *      tfm = crypto_kpp_reqtfm(req);
    struct km_frodokem_ctx * ctx = kpp_tfm_ctx(tfm);
    int                      err;

    if ((req->src == NULL) || (req->dst == NULL))
        return -EINVAL;

    if (ctx->sk_set)
        err = km_frodokem_ss_decap(ctx, req);
    else if (ctx->pk_set)
        err = km_frodokem_ss_claim(ctx, req);
    else
        err = -EINVAL;

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: exiting km_frodokem_compute_shared_secret (role %s), "
            "err %d\n", ctx->pk_set ? "encap" : "decap", err);
    #endif
    return err;
}

/* Note: the cra_driver_name use of cra_name_str must remain
 * unparenthesized, for string-literal concatenation with the suffix
 * macro. */
#define KM_FRODOKEM_DEFINE_ALG(stem, cra_name_str, type_enum)             \
    static int km_ ## stem ## _init(struct crypto_kpp *tfm)               \
    {                                                                     \
        return km_frodokem_init_common(tfm, (int)(type_enum));            \
    }                                                                     \
    static int stem ## _loaded = 0;                                       \
    static struct kpp_alg stem = {                                        \
        .base.cra_name        = (cra_name_str),                           \
        .base.cra_driver_name = cra_name_str                              \
                                WOLFKM_FRODOKEM_DRIVER_SUFFIX,            \
        .base.cra_priority    = WOLFSSL_LINUXKM_LKCAPI_PRIORITY,          \
        .base.cra_module      = THIS_MODULE,                              \
        .base.cra_ctxsize     = sizeof(struct km_frodokem_ctx),           \
        .set_secret           = km_frodokem_set_secret,                   \
        .generate_public_key  = km_frodokem_generate_public_key,          \
        .compute_shared_secret = km_frodokem_compute_shared_secret,       \
        .max_size             = km_frodokem_max_size,                     \
        .init                 = km_ ## stem ## _init,                     \
        .exit                 = km_frodokem_exit,                         \
    }

#ifdef LINUXKM_FRODOKEM640SHAKE
KM_FRODOKEM_DEFINE_ALG(frodokem640shake, "frodokem640shake",
                       WC_FRODOKEM_640_SHAKE);
static int linuxkm_test_frodokem640shake(void);
#endif
#ifdef LINUXKM_FRODOKEM640AES
KM_FRODOKEM_DEFINE_ALG(frodokem640aes, "frodokem640aes",
                       WC_FRODOKEM_640_AES);
static int linuxkm_test_frodokem640aes(void);
#endif
#ifdef LINUXKM_FRODOKEM976SHAKE
KM_FRODOKEM_DEFINE_ALG(frodokem976shake, "frodokem976shake",
                       WC_FRODOKEM_976_SHAKE);
static int linuxkm_test_frodokem976shake(void);
#endif
#ifdef LINUXKM_FRODOKEM976AES
KM_FRODOKEM_DEFINE_ALG(frodokem976aes, "frodokem976aes",
                       WC_FRODOKEM_976_AES);
static int linuxkm_test_frodokem976aes(void);
#endif
#ifdef LINUXKM_FRODOKEM1344SHAKE
KM_FRODOKEM_DEFINE_ALG(frodokem1344shake, "frodokem1344shake",
                       WC_FRODOKEM_1344_SHAKE);
static int linuxkm_test_frodokem1344shake(void);
#endif
#ifdef LINUXKM_FRODOKEM1344AES
KM_FRODOKEM_DEFINE_ALG(frodokem1344aes, "frodokem1344aes",
                       WC_FRODOKEM_1344_AES);
static int linuxkm_test_frodokem1344aes(void);
#endif
#ifdef LINUXKM_EFRODOKEM640SHAKE
KM_FRODOKEM_DEFINE_ALG(efrodokem640shake, "efrodokem640shake",
                       WC_EFRODOKEM_640_SHAKE);
static int linuxkm_test_efrodokem640shake(void);
#endif
#ifdef LINUXKM_EFRODOKEM640AES
KM_FRODOKEM_DEFINE_ALG(efrodokem640aes, "efrodokem640aes",
                       WC_EFRODOKEM_640_AES);
static int linuxkm_test_efrodokem640aes(void);
#endif
#ifdef LINUXKM_EFRODOKEM976SHAKE
KM_FRODOKEM_DEFINE_ALG(efrodokem976shake, "efrodokem976shake",
                       WC_EFRODOKEM_976_SHAKE);
static int linuxkm_test_efrodokem976shake(void);
#endif
#ifdef LINUXKM_EFRODOKEM976AES
KM_FRODOKEM_DEFINE_ALG(efrodokem976aes, "efrodokem976aes",
                       WC_EFRODOKEM_976_AES);
static int linuxkm_test_efrodokem976aes(void);
#endif
#ifdef LINUXKM_EFRODOKEM1344SHAKE
KM_FRODOKEM_DEFINE_ALG(efrodokem1344shake, "efrodokem1344shake",
                       WC_EFRODOKEM_1344_SHAKE);
static int linuxkm_test_efrodokem1344shake(void);
#endif
#ifdef LINUXKM_EFRODOKEM1344AES
KM_FRODOKEM_DEFINE_ALG(efrodokem1344aes, "efrodokem1344aes",
                       WC_EFRODOKEM_1344_AES);
static int linuxkm_test_efrodokem1344aes(void);
#endif

/* The largest keygen-randomness length over the enabled types (the
 * standard forms are the longest; see km_frodokem_keygen_rand_len()). */
#define KM_FRODOKEM_MAX_KEYGEN_RAND_SZ \
    (FRODOKEM_MAX_LENSEC + FRODOKEM_MAX_LENSE + FRODOKEM_SEEDA_SZ)

/* self-test, zero KAT rodata: fixed s || seedSE || z randomness drives
 * deterministic keygen both through the glue (decapsulation role) and
 * in a local wolfCrypt key, so the two provably hold the same keypair;
 * each side then encapsulates for the other:
 *   - decap direction: wolfCrypt encapsulates against the glue-exported
 *     pk; the glue decapsulates; secrets must match.
 *   - encap direction: the tfm is re-keyed with the pk (role switch),
 *     the glue encapsulates; wolfCrypt decapsulates the emitted
 *     ciphertext; the claimed and decapsulated secrets must match.
 * plus negatives: length checks, one-shot claim, unknown-ct claim,
 * pending-list eviction at capacity, and role-switch reaping.  (The
 * eviction check's WC_LINUXKM_FRODOKEM_PENDING_MAX + 1 encapsulations
 * dominate the self-test cost.)
 */
static int linuxkm_test_frodokem_driver(const char * driver, int type)
{
    int                  test_rc = WC_NO_ERR_TRACE(WC_FAILURE);
    int                  ret = 0;
    struct crypto_kpp *  tfm = NULL;
    struct kpp_request * req = NULL;
    FrodoKemKey *        wc_key = NULL;
    byte *               work = NULL;
    byte *               pk;
    byte *               ct;
    byte *               ct_first;
    byte *               ss_a;
    byte *               ss_b;
    word32               pk_len = 0;
    word32               ct_len = 0;
    word32               ss_len = 0;
    struct scatterlist   src_sg;
    struct scatterlist   dst_sg;
    byte                 seed[KM_FRODOKEM_MAX_KEYGEN_RAND_SZ];
    word32               seed_len;
    word32               i;

    seed_len = km_frodokem_keygen_rand_len(type);
    if ((seed_len == 0) || (seed_len > (word32)sizeof(seed))) {
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    /* Fixed test randomness for keygen. */
    for (i = 0; i < seed_len; i++)
        seed[i] = (byte)(0xa0U ^ i);

    wc_key = km_frodokem_new_wc_key(type);
    if (! wc_key) {
        test_rc = MEMORY_E;
        goto test_frodokem_end;
    }
    if ((wc_FrodoKemKey_PublicKeySize(wc_key, &pk_len) != 0) ||
        (wc_FrodoKemKey_CipherTextSize(wc_key, &ct_len) != 0) ||
        (wc_FrodoKemKey_SharedSecretSize(wc_key, &ss_len) != 0))
    {
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    /* The local wolfCrypt keypair, from the same randomness the glue
     * will use. */
    ret = wc_FrodoKemKey_MakeKeyWithRandom(wc_key, seed, (int)seed_len);
    if (ret != 0) {
        pr_err("error: wc_FrodoKemKey_MakeKeyWithRandom returned: %d\n",
               ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    work = (byte *)malloc(pk_len + (2 * ct_len) + (2 * ss_len));
    if (! work) {
        test_rc = MEMORY_E;
        goto test_frodokem_end;
    }
    pk = work;
    ct = work + pk_len;
    ct_first = work + pk_len + ct_len;
    ss_a = work + pk_len + (2 * ct_len);
    ss_b = work + pk_len + (2 * ct_len) + ss_len;

    tfm = crypto_alloc_kpp(driver, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating kpp algorithm %s failed: %d\n",
               driver, (int)PTR_ERR(tfm));
        if (PTR_ERR(tfm) == -ENOMEM)
            test_rc = MEMORY_E;
        else
            test_rc = BAD_FUNC_ARG;
        tfm = NULL;
        goto test_frodokem_end;
    }

    req = kpp_request_alloc(tfm, GFP_KERNEL);
    if (! req) {
        test_rc = -ENOMEM;
        pr_err("error: allocating kpp request %s failed\n", driver);
        goto test_frodokem_end;
    }

    /* ==== decapsulation role ==== */

    ret = crypto_kpp_set_secret(tfm, seed, (unsigned int)seed_len);
    if (ret) {
        pr_err("error: crypto_kpp_set_secret (seed, %u) returned: %d\n",
               (unsigned int)seed_len, ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    {
        unsigned int maxsize = crypto_kpp_maxsize(tfm);
        /* ct, not pk -- see km_frodokem_max_size(). */
        if (maxsize != ct_len) {
            pr_err("error: crypto_kpp_maxsize returned %u, expected "
                   "%u\n", maxsize, ct_len);
            test_rc = BAD_FUNC_ARG;
            goto test_frodokem_end;
        }
    }

    sg_init_one(&dst_sg, pk, pk_len);
    kpp_request_set_output(req, &dst_sg, pk_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        pr_err("error: crypto_kpp_generate_public_key returned: %d\n",
               ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    /* the glue's seed-derived pk must equal the local one. */
    {
        byte *pk_chk = (byte *)malloc(pk_len);
        if (! pk_chk) {
            test_rc = MEMORY_E;
            goto test_frodokem_end;
        }
        ret = wc_FrodoKemKey_EncodePublicKey(wc_key, pk_chk, pk_len);
        if ((ret != 0) || (XMEMCMP(pk, pk_chk, pk_len) != 0)) {
            pr_err("error: glue pk != wolfCrypt pk (ret %d)\n", ret);
            free(pk_chk);
            test_rc = BAD_FUNC_ARG;
            goto test_frodokem_end;
        }
        free(pk_chk);
    }

    /* short pk dst must fail with -EOVERFLOW. */
    sg_init_one(&dst_sg, pk, pk_len - 1);
    kpp_request_set_output(req, &dst_sg, pk_len - 1);
    ret = crypto_kpp_generate_public_key(req);
    if (ret != -EOVERFLOW) {
        pr_err("error: crypto_kpp_generate_public_key (short dst) "
               "returned %d, expected %d\n", ret, -EOVERFLOW);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    /* wolfCrypt encapsulates; the glue decapsulates. */
    {
        WC_RNG rng;
        ret = LKCAPI_INITRNG(&rng);
        if (ret != 0) {
            test_rc = BAD_FUNC_ARG;
            goto test_frodokem_end;
        }
        ret = wc_FrodoKemKey_Encapsulate(wc_key, ct, ss_a, &rng);
        wc_FreeRng(&rng);
        if (ret != 0) {
            pr_err("error: wc_FrodoKemKey_Encapsulate returned: %d\n",
                   ret);
            test_rc = BAD_FUNC_ARG;
            goto test_frodokem_end;
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
        goto test_frodokem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) != 0) {
        pr_err("error: decapsulated secret != encapsulated secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) == 0) {
        pr_err("error: corrupt ct decapsulated to the SAME secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }

    /* ==== encapsulation role (role switch by pk-length secret) ==== */

    ret = crypto_kpp_set_secret(tfm, pk, pk_len);
    if (ret) {
        pr_err("error: crypto_kpp_set_secret (pk, %u) returned: %d\n",
               pk_len, ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    /* glue encapsulates; wolfCrypt decapsulates. */
    sg_init_one(&dst_sg, ct, ct_len);
    kpp_request_set_output(req, &dst_sg, ct_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        pr_err("error: crypto_kpp_generate_public_key (encap) "
               "returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }

    PRIVATE_KEY_UNLOCK();
    ret = wc_FrodoKemKey_Decapsulate(wc_key, ss_a, ct, ct_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        pr_err("error: wc_FrodoKemKey_Decapsulate returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }
    if (XMEMCMP(ss_a, ss_b, ss_len) != 0) {
        pr_err("error: claimed secret != decapsulated secret\n");
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }
    ct[0] ^= 1U;

    /* eviction: overfill the pending list; the first ciphertext's node
     * must be evicted, the last still claimable.
     */
    for (i = 0; i <= (word32)WC_LINUXKM_FRODOKEM_PENDING_MAX; i++) {
        byte *dst = (i == 0) ? ct_first : ct;
        sg_init_one(&dst_sg, dst, ct_len);
        kpp_request_set_output(req, &dst_sg, ct_len);
        ret = crypto_kpp_generate_public_key(req);
        if (ret) {
            pr_err("error: generate #%u returned: %d\n", i, ret);
            test_rc = BAD_FUNC_ARG;
            goto test_frodokem_end;
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
        goto test_frodokem_end;
    }
    PRIVATE_KEY_UNLOCK();
    ret = wc_FrodoKemKey_Decapsulate(wc_key, ss_a, ct, ct_len);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }

    /* role-switch reaping: park an encapsulation, switch roles away
     * and back; the pending node must be gone.
     */
    sg_init_one(&dst_sg, ct, ct_len);
    kpp_request_set_output(req, &dst_sg, ct_len);
    ret = crypto_kpp_generate_public_key(req);
    if (ret) {
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
    }
    ret = crypto_kpp_set_secret(tfm, seed, (unsigned int)seed_len);
    if (ret == 0)
        ret = crypto_kpp_set_secret(tfm, pk, pk_len);
    if (ret) {
        pr_err("error: role-switch set_secret returned: %d\n", ret);
        test_rc = BAD_FUNC_ARG;
        goto test_frodokem_end;
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
        goto test_frodokem_end;
    }

    test_rc = 0;
test_frodokem_end:
    if (req) { kpp_request_free(req); req = NULL; }
    if (tfm) { crypto_free_kpp(tfm); tfm = NULL; }
    if (wc_key) { km_frodokem_del_wc_key(wc_key); wc_key = NULL; }
    if (work) { ForceZero(work, pk_len + (2 * ct_len) + (2 * ss_len));
                free(work); work = NULL; }

    #ifdef WOLFKM_DEBUG_FRODOKEM
    pr_info("info: %s: self test returned: %d\n", driver, test_rc);
    #endif
    return test_rc;
}

#ifdef LINUXKM_FRODOKEM640SHAKE
static int linuxkm_test_frodokem640shake(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem640shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_640_SHAKE);
}
#endif
#ifdef LINUXKM_FRODOKEM640AES
static int linuxkm_test_frodokem640aes(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem640aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_640_AES);
}
#endif
#ifdef LINUXKM_FRODOKEM976SHAKE
static int linuxkm_test_frodokem976shake(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem976shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_976_SHAKE);
}
#endif
#ifdef LINUXKM_FRODOKEM976AES
static int linuxkm_test_frodokem976aes(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem976aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_976_AES);
}
#endif
#ifdef LINUXKM_FRODOKEM1344SHAKE
static int linuxkm_test_frodokem1344shake(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem1344shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_1344_SHAKE);
}
#endif
#ifdef LINUXKM_FRODOKEM1344AES
static int linuxkm_test_frodokem1344aes(void)
{
    return linuxkm_test_frodokem_driver(
        "frodokem1344aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_FRODOKEM_1344_AES);
}
#endif
#ifdef LINUXKM_EFRODOKEM640SHAKE
static int linuxkm_test_efrodokem640shake(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem640shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_640_SHAKE);
}
#endif
#ifdef LINUXKM_EFRODOKEM640AES
static int linuxkm_test_efrodokem640aes(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem640aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_640_AES);
}
#endif
#ifdef LINUXKM_EFRODOKEM976SHAKE
static int linuxkm_test_efrodokem976shake(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem976shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_976_SHAKE);
}
#endif
#ifdef LINUXKM_EFRODOKEM976AES
static int linuxkm_test_efrodokem976aes(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem976aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_976_AES);
}
#endif
#ifdef LINUXKM_EFRODOKEM1344SHAKE
static int linuxkm_test_efrodokem1344shake(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem1344shake" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_1344_SHAKE);
}
#endif
#ifdef LINUXKM_EFRODOKEM1344AES
static int linuxkm_test_efrodokem1344aes(void)
{
    return linuxkm_test_frodokem_driver(
        "efrodokem1344aes" WOLFKM_FRODOKEM_DRIVER_SUFFIX,
        (int)WC_EFRODOKEM_1344_AES);
}
#endif

#endif /* LINUXKM_LKCAPI_REGISTER_FRODOKEM */

#endif /* !WC_SKIP_INCLUDED_C_FILES */
