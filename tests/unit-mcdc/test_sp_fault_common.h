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

    mcdc_fa_disarm();
    mcdc_fa_restore();
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
