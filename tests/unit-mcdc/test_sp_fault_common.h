/* test_sp_fault_common.h
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

/*
 * Shared body for the SP backend heap-fault white-boxes.
 *
 * WHY
 * ---
 * Every SP backend carries hundreds of decisions shaped
 *
 *     if ((err == MP_OKAY) && <next step>)
 *
 * whose `err == MP_OKAY` operand has no false side in the campaign's builds.
 * The reason is not that the failure is hard to produce, it is that nothing in
 * the compiled code can produce it: SP_ALLOC_VAR is
 *
 *     #ifdef WOLFSSL_SP_SMALL_STACK
 *         if (err == MP_OKAY) {
 *             (NAME) = XMALLOC(...);
 *             if ((NAME) == NULL) { err = MEMORY_E; }
 *         }
 *     #else
 *         WC_DO_NOTHING
 *
 * so without WOLFSSL_SP_SMALL_STACK the variables are plain stack arrays, err
 * stays MP_OKAY from entry to exit, and the operand is dead by construction.
 *
 * This driver therefore only does useful work in a variant built with
 * WOLFSSL_SP_SMALL_STACK. Elsewhere it runs the same operations with the
 * injector never armed, which costs one quick pass and keeps the file building
 * in every variant of the module (a white-box that fails to build is a silent
 * skip, and the campaign has lost a module's evidence to that twice).
 *
 * HOW
 * ---
 * mcdc_fault_alloc.h fails the n-th and every later allocation. Sweeping n
 * across the allocation sites of an operation walks the MEMORY_E failure down
 * the whole success chain, so each `(err == MP_OKAY)` checkpoint sees both a
 * run where it holds and a run where it does not.
 *
 * The operations are the public SP entry points, driven with valid operands so
 * that an unarmed pass completes normally: the only thing under test is where
 * the failure lands, not the arithmetic.
 *
 * The including TU defines SP_FAULT_LABEL and includes the wolfCrypt .c under
 * test before including this header.
 */

#ifndef SP_FAULT_LABEL
    #error "define SP_FAULT_LABEL before including test_sp_fault_common.h"
#endif

#include "mcdc_fault_alloc.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Sweep depth. SP entry points allocate a handful of temporaries each, so the
 * failure index only has to walk a little past the deepest chain. Kept low on
 * purpose: every index repeats a full keygen/sign/verify, TEST_TIMEOUT is wall
 * clock, and variants run concurrently under MAXPAR -- a driver that finishes
 * alone can still be killed under load, and a killed driver is a silent skip. */
#ifndef SP_FAULT_MAX_N
    #define SP_FAULT_MAX_N 24
#endif

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    !defined(MCDC_FA_UNAVAILABLE)
/* ECC. One armed region per operation, not one around the whole chain: the
 * injector fails the n-th allocation AND every later one, so an arming that
 * spans make_key + sign + verify + ECDH loses the failure inside make_key and
 * the later three never run at all. Each operation therefore gets its own
 * sweep, with its inputs built while disarmed. */
static void wb_fault_ecc(int curveId, int fieldSz)
{
    int n;

    /* make_key: the failure walks this operation's own allocation sites. */
    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        ecc_key key;
        WC_RNG  rng;

        if (wc_InitRng(&rng) != 0) {
            return;
        }
        if (wc_ecc_init(&key) == 0) {
            mcdc_fa_arm(n);
            (void)wc_ecc_make_key_ex(&rng, fieldSz, &key, curveId);
            mcdc_fa_disarm();
            wc_ecc_free(&key);
        }
        wc_FreeRng(&rng);
    }

    /* sign / verify / ECDH: each off a key built with the injector disarmed,
     * so the operation under test starts from a valid state and the failure
     * lands inside it rather than in its setup. */
    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        ecc_key key;
        WC_RNG  rng;
        byte    sig[144];
        byte    secret[80];
        byte    digest[32];
        word32  sigLen;
        word32  secretLen;
        int     res = 0;

        XMEMSET(digest, 0x5a, sizeof(digest));

        if (wc_InitRng(&rng) != 0) {
            return;
        }
        if (wc_ecc_init(&key) != 0) {
            wc_FreeRng(&rng);
            return;
        }
        if (wc_ecc_make_key_ex(&rng, fieldSz, &key, curveId) == 0) {
            sigLen = (word32)sizeof(sig);
            mcdc_fa_arm(n);
            (void)wc_ecc_sign_hash(digest, (word32)sizeof(digest), sig,
                &sigLen, &rng, &key);
            mcdc_fa_disarm();

            /* A real signature to verify, made while disarmed. */
            sigLen = (word32)sizeof(sig);
            if (wc_ecc_sign_hash(digest, (word32)sizeof(digest), sig, &sigLen,
                    &rng, &key) == 0) {
                mcdc_fa_arm(n);
                (void)wc_ecc_verify_hash(sig, sigLen, digest,
                    (word32)sizeof(digest), &res, &key);
                mcdc_fa_disarm();
            }

            secretLen = (word32)sizeof(secret);
            PRIVATE_KEY_UNLOCK();
            mcdc_fa_arm(n);
            (void)wc_ecc_shared_secret(&key, &key, secret, &secretLen);
            mcdc_fa_disarm();
            PRIVATE_KEY_LOCK();

            mcdc_fa_arm(n);
            (void)wc_ecc_check_key(&key);
            mcdc_fa_disarm();
        }
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
    }
}
#else
static void wb_fault_ecc(int curveId, int fieldSz)
{
    (void)curveId;
    (void)fieldSz;
}
#endif

#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC) && \
    !defined(MCDC_FA_UNAVAILABLE)
/* -------------------------------------------------------------------- *
 * The multi-condition `err` chains this module still owes are NOT in the
 * wc_* API's call graph.
 *
 * Shapes like
 *
 *     if ((err == MP_OKAY) && (!inMont)) { ... }
 *     if ((err == MP_OKAY) && sp_<n>_iszero_<n>(p1->z)) { ... }
 *     if ((err == MP_OKAY) && ((sp_<n>_cmp_<n>(p->x, pub->x) != 0) || ...))
 *
 * live in sp_ecc_mulmod_add_<n>, sp_ecc_mulmod_base_add_<n>,
 * sp_ecc_check_key_<n>, sp_ecc_verify_<n> and sp_ecc_sign_<n>. Some of
 * those entry points nothing in wc_* reaches at all on this
 * configuration; the ones it does reach it reaches through wrappers that
 * allocate first, so a sweep aimed at the wrapper lands its failure
 * before the callee is entered.
 *
 * So each entry point is called DIRECTLY, with its own arming hugging
 * the one call and every input built while disarmed. The depth only has
 * to walk a couple of SP_ALLOC_VARs past the start of each function --
 * the injector fails allocation n and every later one, so a shallow
 * sweep already puts `err` on the wrong side of every checkpoint in the
 * function.
 * -------------------------------------------------------------------- */
#ifndef SP_FAULT_DIRECT_N
    #define SP_FAULT_DIRECT_N 6
#endif

#define SP_FAULT_DEFINE_DIRECT(BITS, SZ, CURVE_ID)                          \
static void wb_fault_direct_##BITS(void)                                    \
{                                                                           \
    ecc_key     key;                                                        \
    WC_RNG      rng;                                                        \
    ecc_point*  rp = NULL;                                                  \
    mp_int      k;                                                          \
    mp_int      one;                                                        \
    mp_int      rmv;                                                        \
    mp_int      smv;                                                        \
    mp_int      rmv2;                                                       \
    mp_int      smv2;                                                       \
    byte        digest[32];                                                 \
    int         res = 0;                                                    \
    int         n;                                                          \
    int         haveSig = 0;                                                \
                                                                            \
    XMEMSET(&key, 0, sizeof(key));                                          \
    XMEMSET(&rng, 0, sizeof(rng));                                          \
    XMEMSET(digest, 0x5a, sizeof(digest));                                  \
                                                                            \
    if (wc_InitRng(&rng) != 0) {                                            \
        return;                                                             \
    }                                                                       \
    if (wc_ecc_init(&key) != 0) {                                           \
        wc_FreeRng(&rng);                                                   \
        return;                                                             \
    }                                                                       \
    if (mp_init_multi(&k, &one, &rmv, &smv, &rmv2, &smv2) != MP_OKAY) {     \
        wc_ecc_free(&key);                                                  \
        wc_FreeRng(&rng);                                                   \
        return;                                                             \
    }                                                                       \
    (void)mp_set(&k, 5);                                                    \
    (void)mp_set(&one, 1);                                                  \
    rp = wc_ecc_new_point();                                                \
                                                                            \
    if ((rp != NULL) &&                                                     \
            (wc_ecc_make_key_ex(&rng, SZ, &key, CURVE_ID) == 0)) {          \
        SP_FAULT_SIGN_SETUP(BITS)                                           \
        for (n = 1; n <= SP_FAULT_DIRECT_N; n++) {                          \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_mulmod_add_##BITS(&k, &key.pubkey, &key.pubkey,    \
                0, rp, 1, NULL);                                            \
            mcdc_fa_disarm();                                               \
                                                                            \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_mulmod_base_add_##BITS(&k, &key.pubkey, 0, rp, 1,  \
                NULL);                                                      \
            mcdc_fa_disarm();                                               \
                                                                            \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_mulmod_##BITS(&k, &key.pubkey, rp, 1, NULL);       \
            mcdc_fa_disarm();                                               \
                                                                            \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_mulmod_base_##BITS(&k, rp, 1, NULL);               \
            mcdc_fa_disarm();                                               \
                                                                            \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_is_point_##BITS(key.pubkey.x, key.pubkey.y);       \
            mcdc_fa_disarm();                                               \
                                                                            \
            SP_FAULT_CHECK_KEY_ARM(BITS)                                    \
            SP_FAULT_SIGNVFY_ARM(BITS)                                      \
        }                                                                   \
    }                                                                       \
                                                                            \
    if (rp != NULL) {                                                       \
        wc_ecc_del_point(rp);                                               \
    }                                                                       \
    mp_clear(&smv2);                                                        \
    mp_clear(&rmv2);                                                        \
    mp_clear(&smv);                                                         \
    mp_clear(&rmv);                                                         \
    mp_clear(&one);                                                         \
    mp_clear(&k);                                                           \
    wc_ecc_free(&key);                                                      \
    wc_FreeRng(&rng);                                                       \
    (void)res;                                                              \
    (void)haveSig;                                                          \
}

#if defined(HAVE_ECC_CHECK_KEY) || !defined(NO_ECC_CHECK_PUBKEY_ORDER)
#define SP_FAULT_CHECK_KEY_ARM(BITS)                                        \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_check_key_##BITS(key.pubkey.x, key.pubkey.y,       \
                ecc_get_k(&key), NULL);                                     \
            mcdc_fa_disarm();
#else
#define SP_FAULT_CHECK_KEY_ARM(BITS) /* not compiled in this config */
#endif

#if defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
/* A real signature, made disarmed, so the armed verify below starts from
 * valid inputs and the failure lands inside the verify. */
#define SP_FAULT_SIGN_SETUP(BITS)                                           \
        haveSig = (sp_ecc_sign_##BITS(digest, 32, &rng, ecc_get_k(&key),    \
            &rmv, &smv, NULL, NULL) == 0);
#define SP_FAULT_SIGNVFY_ARM(BITS)                                          \
            mcdc_fa_arm(n);                                                 \
            (void)sp_ecc_sign_##BITS(digest, 32, &rng, ecc_get_k(&key),     \
                &rmv2, &smv2, NULL, NULL);                                  \
            mcdc_fa_disarm();                                               \
            if (haveSig) {                                                  \
                mcdc_fa_arm(n);                                             \
                (void)sp_ecc_verify_##BITS(digest, 32, key.pubkey.x,        \
                    key.pubkey.y, &one, &rmv, &smv, &res, NULL);            \
                mcdc_fa_disarm();                                           \
            }
#else
#define SP_FAULT_SIGN_SETUP(BITS)    /* needs HAVE_ECC_SIGN/VERIFY */
#define SP_FAULT_SIGNVFY_ARM(BITS)   /* needs HAVE_ECC_SIGN/VERIFY */
#endif

#ifndef WOLFSSL_SP_NO_256
SP_FAULT_DEFINE_DIRECT(256, 32, ECC_SECP256R1)
#endif
#ifdef WOLFSSL_SP_384
SP_FAULT_DEFINE_DIRECT(384, 48, ECC_SECP384R1)
#endif
#ifdef WOLFSSL_SP_521
SP_FAULT_DEFINE_DIRECT(521, 66, ECC_SECP521R1)
#endif

static void wb_fault_direct_all(void)
{
#ifndef WOLFSSL_SP_NO_256
    wb_fault_direct_256();
#endif
#ifdef WOLFSSL_SP_384
    wb_fault_direct_384();
#endif
#ifdef WOLFSSL_SP_521
    wb_fault_direct_521();
#endif
}
#else
static void wb_fault_direct_all(void)
{
}
#endif /* WOLFSSL_HAVE_SP_ECC && HAVE_ECC && !MCDC_FA_UNAVAILABLE */

#if defined(WOLFSSL_HAVE_SP_DH) && !defined(NO_DH) && \
    !defined(MCDC_FA_UNAVAILABLE)
/* DH: key agreement over a compiled-in FFDHE group. */
static void wb_fault_dh(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        DhKey  key;
        WC_RNG rng;
        byte   priv[384];
        byte   pub[384];
        byte   agree[384];
        word32 privSz = (word32)sizeof(priv);
        word32 pubSz = (word32)sizeof(pub);
        word32 agreeSz = (word32)sizeof(agree);

        if (wc_InitRng(&rng) != 0) {
            return;
        }
        if (wc_InitDhKey(&key) != 0) {
            wc_FreeRng(&rng);
            return;
        }

        if (wc_DhSetNamedKey(&key, WC_FFDHE_2048) == 0) {
            mcdc_fa_arm(n);
            (void)wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
            mcdc_fa_disarm();

            privSz = (word32)sizeof(priv);
            pubSz = (word32)sizeof(pub);
            if (wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub,
                    &pubSz) == 0) {
                mcdc_fa_arm(n);
                (void)wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub,
                    pubSz);
                mcdc_fa_disarm();
            }
        }

        wc_FreeDhKey(&key);
        wc_FreeRng(&rng);
    }
}
#else
static void wb_fault_dh(void)
{
}
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(NO_RSA) && \
    !defined(MCDC_FA_UNAVAILABLE)
/* RSA: public/private operations off a decoded key, under the sweep. */
static void wb_fault_rsa(void)
{
    int n;

    for (n = 1; n <= SP_FAULT_MAX_N; n++) {
        RsaKey key;
        WC_RNG rng;
        byte   out[256];
        byte   plain[256];
        word32 idx = 0;

        if (wc_InitRng(&rng) != 0) {
            return;
        }
        if (wc_InitRsaKey(&key, NULL) != 0) {
            wc_FreeRng(&rng);
            return;
        }
        if (wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &key,
                (word32)sizeof_client_key_der_2048) == 0) {
            mcdc_fa_arm(n);
            (void)wc_RsaPublicEncrypt((const byte*)"mcdc", 4, out,
                (word32)sizeof(out), &key, &rng);
            mcdc_fa_disarm();

            if (wc_RsaPublicEncrypt((const byte*)"mcdc", 4, out,
                    (word32)sizeof(out), &key, &rng) > 0) {
                mcdc_fa_arm(n);
                (void)wc_RsaPrivateDecrypt(out, (word32)sizeof(out), plain,
                    (word32)sizeof(plain), &key);
                mcdc_fa_disarm();
            }
        }

        wc_FreeRsaKey(&key);
        wc_FreeRng(&rng);
    }
}
#else
static void wb_fault_rsa(void)
{
}
#endif

int main(void)
{
    /* Unbuffered: on a timeout the process is killed and anything still
     * buffered is lost, which reads as an empty log. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("%s heap-fault white-box supplement\n", SP_FAULT_LABEL);

#ifdef MCDC_FA_UNAVAILABLE
    WB_NOTE("allocator hooks unavailable in this config; nothing to sweep");
#else
    #ifndef WOLFSSL_SP_SMALL_STACK
    WB_NOTE("WOLFSSL_SP_SMALL_STACK off: SP temporaries are stack arrays and "
            "err cannot leave MP_OKAY; sweep runs but cannot fail an SP alloc");
    #endif
    mcdc_fa_install();

    #ifndef WOLFSSL_SP_NO_256
    wb_fault_ecc(ECC_SECP256R1, 32);
    #endif
    #ifdef WOLFSSL_SP_384
    wb_fault_ecc(ECC_SECP384R1, 48);
    #endif
    #ifdef WOLFSSL_SP_521
    wb_fault_ecc(ECC_SECP521R1, 66);
    #endif

    wb_fault_dh();
    wb_fault_rsa();

    /* Direct SP entry points, one arming per call: the multi-condition
     * `err` chains this module still owes are all behind entry points the
     * wc_* API either never takes or only reaches through a wrapper that
     * allocates first. */
    wb_fault_direct_all();

    mcdc_fa_disarm();
    mcdc_fa_restore();
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
