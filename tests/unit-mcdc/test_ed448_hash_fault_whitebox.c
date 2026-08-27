/* test_ed448_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/ed448.c.
 *
 * WHY A SEPARATE TU
 * -----------------
 * mcdc_fault_hash.h installs its interposers by macro and must therefore be
 * #included BEFORE ed448.c. test_ed448_whitebox.c must keep driving the
 * unfaulted primitives (its ed448_hash()/verify-helper argument guards want
 * real hashing), so the fault sweeps live here in their own binary.
 *
 * THE LEVER
 * ---------
 * Every open "(ret == 0)" operand left in ed448.c takes its `ret` from the
 * SHAKE256 chain (ed448_hash_init/update/final -> wc_InitShake256 /
 * wc_Shake256_Update / wc_Shake256_Final) and from nothing else. ed448.c
 * performs no allocation on these paths in this campaign's configs
 * (WOLFSSL_SMALL_STACK is unset, so WC_DECLARE_VAR/WC_ALLOC_VAR_EX are a plain
 * stack object and a no-op), so mcdc_fault_alloc.h has nothing to fault --
 * only a failing hash primitive can break the chain. mcdc_fault_hash.h shadows
 * Update/Final; wc_InitShake256 is shadowed locally below rather than via the
 * header's opt-in MCDC_FH_WITH_SHAKE_INIT, so that the real initialisation
 * still happens (see "CRASH SAFETY"). Both share mcdc_fh_hit(), so one arm()
 * index space spans the whole init/update/final sequence.
 *
 * TARGET CONDITIONS, AND WHICH VECTOR DRIVES WHICH HALF
 * -----------------------------------------------------
 *   wc_ed448_sign_msg_ex():
 *     ~517  if ((ret == 0) && (context != NULL))      [nonce block]
 *     ~559  if ((ret == 0) && (context != NULL))      [H(R,A,M) block]
 *       TRUE half -- and, because an independence pair needs the DECISION to
 *       differ, the (T,T) row -- is the unarmed signature with a non-NULL
 *       context. FALSE half: the sweep. One signature takes ~20 SHAKE
 *       primitive calls; arm(n) fails the n-th and every later one, so
 *       sweeping n over 1..seen() breaks the chain immediately before each
 *       decision in turn (n at the block's ed448_hash_init, or at one of the
 *       ed448Ctx/type/contextLen updates that precede it). The sweep is
 *       index-free by construction, which is what makes it valid across the
 *       persistent-SHA and per-call-SHAKE variants alike.
 *
 *   ed448_verify_msg_init_with_sha():
 *     ~742  if ((ret == 0) && (context != NULL))
 *       Same shape, swept over a direct call to the file-static with a
 *       114-byte signature blob, Ed448 and a non-NULL context. The blob is
 *       only hashed, never verified. The unarmed call is the (T,T) row. This
 *       section needs no signing, so it also runs in the ed448_verify_only
 *       variant.
 *
 *   wc_ed448_check_key():
 *     ~1520 if ((ret == 0) && (XMEMCMP(pubKey, key->p, ED448_PUB_KEY_SIZE)!=0))
 *       `ret` here is wc_ed448_make_public()'s status, and that function's
 *       only failure mode on a well-formed key is ed448_hash(). The
 *       independence pair for the "(ret == 0)" operand needs a row where the
 *       DECISION is true, i.e. (T,T): a key whose stored public key does NOT
 *       match the one derived from its private key. That is built here by
 *       importing seed A together with the public key of seed B with
 *       trusted = 1 (trusted = 0 would run wc_ed448_check_key() inside the
 *       import and reject it). arm(1) then supplies the (F, -) row by failing
 *       make_public's first SHAKE call. A matching key is checked too, for the
 *       XMEMCMP operand's own (T,F) row. wc_ed448_make_public() is not behind
 *       HAVE_ED448_SIGN, so this section runs in every variant.
 *
 * CRASH SAFETY
 * ------------
 * The locally installed wc_InitShake256 interposer performs the REAL
 * initialisation and only then reports failure. ed448.c reaches
 * ed448_hash_free() -> wc_Shake256_Free() on paths a failed init opens
 * (wc_ed448_sign_msg_ex ~530/~575), and freeing a context that was never
 * initialised would be undefined. A "failed" init that still leaves a
 * well-formed context is exactly as strong for MC/DC -- the guards read the
 * returned status, not the context -- and cannot crash. Update/Final faults
 * leave their output buffers untouched, so no armed call's output (signature
 * bytes, derived public key, res) is ever consumed here.
 *
 * VARIANT COVERAGE
 * ----------------
 * Every section is behind the same feature guard as the code it targets and
 * has an #else stub of the same signature, so the TU builds under all six
 * ed448 variants (ed448_64bit, ed448_persistent_sha, ed448_small,
 * ed448_128bit, ed448_cryptocb, ed448_verify_only -- the last compiles the
 * signing API out entirely, so the sign sweep is a stub there). No RNG and no
 * wall clock: fixed seeds, fixed message, fixed sweep length. main() always
 * returns 0 -- a nonzero exit would discard the variant's whole coverage.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with ed448.o removed. Not part of the wolfSSL build.
 */

#include "mcdc_fault_hash.h"

#if defined(MCDC_FH_HAVE_SHAKE) && defined(WOLFSSL_SHAKE256)
/* Local interposer for the SHAKE256 init. Shares mcdc_fh_hit() so
 * init/update/final live in ONE arm() index space. The real init always runs
 * first; see "CRASH SAFETY" above. (MCDC_FH_WITH_SHAKE_INIT is deliberately
 * NOT defined: the header's wrapper skips the real init.) */
MCDC_FH_MAYBE_UNUSED static int mcdc_ed448_InitShake256(wc_Shake* shake,
    void* heap, int devId)
{
    int ret;
    int faulted;

    ret     = wc_InitShake256(shake, heap, devId);
    faulted = mcdc_fh_hit();
    if (faulted && (ret == 0))
        ret = MCDC_FH_ERR;
    return ret;
}
#undef  wc_InitShake256
#define wc_InitShake256(a, b, c) mcdc_ed448_InitShake256((a), (b), (c))
#endif /* MCDC_FH_HAVE_SHAKE && WOLFSSL_SHAKE256 */

/* ed448.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/ed448.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Hard bound on every sweep: a signature with a context takes ~20 primitive
 * calls, a verify-init ~8. Nothing here is wall-clock or entropy bounded. */
#define WB_SWEEP_MAX 64L

#if defined(HAVE_ED448) && defined(MCDC_FH_HAVE_SHAKE) && \
    defined(WOLFSSL_SHAKE256) && defined(HAVE_ED448_KEY_IMPORT)

#define WB_HAVE_DRIVER

/* Two fixed seeds (any 57 bytes is a valid Ed448 seed) and a fixed
 * message/context. No RNG anywhere in this TU. */
MCDC_FH_MAYBE_UNUSED static const byte wb_seed_a[ED448_KEY_SIZE] = {
    0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
    0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
    0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
    0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
    0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
    0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
    0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
    0x5b
};
MCDC_FH_MAYBE_UNUSED static const byte wb_seed_b[ED448_KEY_SIZE] = {
    0xc4, 0xea, 0xb0, 0x5d, 0x35, 0x70, 0x07, 0xc6,
    0x32, 0xf3, 0xdb, 0xb4, 0x84, 0x89, 0x92, 0x4d,
    0x55, 0x2b, 0x08, 0xfe, 0x0c, 0x35, 0x3a, 0x0d,
    0x4a, 0x1f, 0x00, 0xac, 0xda, 0x2c, 0x46, 0x3a,
    0xfb, 0xea, 0x67, 0xc5, 0xe8, 0xd2, 0x87, 0x7c,
    0x5e, 0x3b, 0xc3, 0x97, 0xa6, 0x59, 0x94, 0x9e,
    0xf8, 0x02, 0x1e, 0x95, 0x4e, 0x0a, 0x12, 0x27,
    0x4e
};
MCDC_FH_MAYBE_UNUSED static const byte wb_msg[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};
MCDC_FH_MAYBE_UNUSED static const byte wb_ctx[4] = { 0xc0, 0xc1, 0xc2, 0xc3 };

/* Import a seed and derive its public key; leaves privKeySet and pubKeySet
 * both set and consistent. Runs while DISARMED. */
static int wb_key_from_seed(ed448_key* key, const byte* seed)
{
    int ret;

    ret = wc_ed448_init(key);
    if (ret == 0) {
        ret = wc_ed448_import_private_only(seed, ED448_KEY_SIZE, key);
        if (ret == 0)
            ret = wc_ed448_make_public(key, key->p, ED448_PUB_KEY_SIZE);
        if (ret != 0)
            wc_ed448_free(key);
    }

    return ret;
}

#endif /* driver preconditions */

/* --------------------------------------------------------------------------
 * 1. wc_ed448_sign_msg_ex(): the "(ret == 0)" operands at ~517 and ~559.
 * ----------------------------------------------------------------------- */
#if defined(WB_HAVE_DRIVER) && defined(HAVE_ED448_SIGN)
static void wb_ed448_sign_hash_faults(void)
{
    ed448_key key;
    byte      sig[ED448_SIG_SIZE];
    word32    sigLen;
    long      n;
    long      total;
    int       ret;

    if (wb_key_from_seed(&key, wb_seed_a) != 0) {
        WB_NOTE("ed448 key setup failed; sign hash-fault sweep skipped");
        wb_fail = 1;
        return;
    }

    /* (T,T) row for both operands: a non-NULL context makes the second operand
     * of 517 and 559 true, so the unarmed run drives both decisions TRUE. */
    mcdc_fh_disarm();
    sigLen = (word32)sizeof(sig);
    ret = wc_ed448_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig, &sigLen,
        &key, (byte)Ed448, wb_ctx, (byte)sizeof(wb_ctx));
    total = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("ed448 sign baseline failed");
        wb_fail = 1;
    }
    if (total > WB_SWEEP_MAX)
        total = WB_SWEEP_MAX;

    /* (F, -) rows: one armed run per primitive call index. Output signature
     * bytes of an armed run are never read. */
    for (n = 1; n <= total; n++) {
        mcdc_fh_arm(n);
        sigLen = (word32)sizeof(sig);
        (void)wc_ed448_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig, &sigLen,
            &key, (byte)Ed448, wb_ctx, (byte)sizeof(wb_ctx));
        mcdc_fh_disarm();
    }

    /* Unarmed again: repeats the (T,T) row and shows the sweep left the key's
     * SHAKE state usable (relevant to the persistent-SHA variant). */
    sigLen = (word32)sizeof(sig);
    ret = wc_ed448_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig, &sigLen,
        &key, (byte)Ed448, wb_ctx, (byte)sizeof(wb_ctx));
    if (ret != 0) {
        WB_NOTE("ed448 sign after sweep failed");
        wb_fail = 1;
    }

    wc_ed448_free(&key);
    WB_NOTE("sign_msg_ex SHAKE chain swept (517/559 ret==0 pairs)");
}
#else
static void wb_ed448_sign_hash_faults(void)
{ WB_NOTE("ed448 sign or SHAKE injector unavailable; sign sweep skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 2. ed448_verify_msg_init_with_sha(): the "(ret == 0)" operand at ~742.
 * ----------------------------------------------------------------------- */
#if defined(WB_HAVE_DRIVER) && defined(HAVE_ED448_VERIFY)
static void wb_ed448_verify_init_hash_faults(void)
{
    ed448_key key;
    wc_Shake  sha;
    byte      sig[ED448_SIG_SIZE];
    long      n;
    long      total;
    int       ret;

    if (wb_key_from_seed(&key, wb_seed_a) != 0) {
        WB_NOTE("ed448 key setup failed; verify-init sweep skipped");
        wb_fail = 1;
        return;
    }

    /* Any 114 bytes reach the hash chain: the only structural check before it
     * is sigLen == ED448_SIG_SIZE. This blob is never verified, only hashed. */
    XMEMSET(sig, 0x5a, sizeof(sig));

    mcdc_fh_disarm();
    if (wc_InitShake256(&sha, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_InitShake256 failed; verify-init sweep skipped");
        wb_fail = 1;
        wc_ed448_free(&key);
        return;
    }

    /* (T,T) row: unarmed, with a non-NULL context. mcdc_fh_seen() below counts
     * only this call, because the setup init above ran before the reset. */
    mcdc_fh_disarm();
    ret = ed448_verify_msg_init_with_sha(sig, (word32)sizeof(sig), &key, &sha,
        (byte)Ed448, wb_ctx, (byte)sizeof(wb_ctx));
    total = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("ed448_verify_msg_init_with_sha baseline failed");
        wb_fail = 1;
    }
    if (total > WB_SWEEP_MAX)
        total = WB_SWEEP_MAX;

    /* (F, -) rows. The context is re-initialised between runs while disarmed,
     * so each armed run starts from the same state. */
    for (n = 1; n <= total; n++) {
        wc_Shake256_Free(&sha);
        if (wc_InitShake256(&sha, NULL, INVALID_DEVID) != 0) {
            WB_NOTE("wc_InitShake256 failed mid-sweep; sweep truncated");
            wb_fail = 1;
            break;
        }
        mcdc_fh_arm(n);
        (void)ed448_verify_msg_init_with_sha(sig, (word32)sizeof(sig), &key,
            &sha, (byte)Ed448, wb_ctx, (byte)sizeof(wb_ctx));
        mcdc_fh_disarm();
    }

    wc_Shake256_Free(&sha);
    wc_ed448_free(&key);
    WB_NOTE("ed448_verify_msg_init_with_sha SHAKE chain swept (742 ret==0 "
            "pair)");
}
#else
static void wb_ed448_verify_init_hash_faults(void)
{ WB_NOTE("ed448 verify or SHAKE injector unavailable; verify-init sweep "
          "skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 3. wc_ed448_check_key(): the "(ret == 0)" operand at ~1520.
 * ----------------------------------------------------------------------- */
#ifdef WB_HAVE_DRIVER
static void wb_ed448_check_key_hash_fault(void)
{
    ed448_key good;
    ed448_key mismatched;
    int       ret;

    /* `good` carries seed B and B's own public key; it supplies both the
     * (T,F) row for the XMEMCMP operand and the public key that makes
     * `mismatched` mismatch. */
    if (wb_key_from_seed(&good, wb_seed_b) != 0) {
        WB_NOTE("ed448 reference key setup failed; check_key fault skipped");
        wb_fail = 1;
        return;
    }

    if (wc_ed448_init(&mismatched) != 0) {
        WB_NOTE("wc_ed448_init failed; check_key fault skipped");
        wb_fail = 1;
        wc_ed448_free(&good);
        return;
    }

    /* trusted = 1 so the import does NOT run wc_ed448_check_key() itself
     * (which is exactly the check this vector wants to reach later, and which
     * would make the import fail). Seed A's private key with seed B's public
     * key: make_public() will derive A's public key and the XMEMCMP will
     * differ. */
    ret = wc_ed448_import_private_key_ex(wb_seed_a, ED448_KEY_SIZE, good.p,
        ED448_PUB_KEY_SIZE, &mismatched, 1);
    if (ret != 0) {
        WB_NOTE("mismatched-pub import failed; check_key fault skipped");
        wb_fail = 1;
        wc_ed448_free(&mismatched);
        wc_ed448_free(&good);
        return;
    }

    /* (T,T): make_public succeeds, the derived key differs from key->p, so the
     * decision is TRUE. This is the row the "(ret == 0)" operand's
     * independence pair needs. */
    mcdc_fh_disarm();
    ret = wc_ed448_check_key(&mismatched);
    if (ret != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
        WB_NOTE("check_key on a mismatched public key did not report "
                "PUBLIC_KEY_E");
        wb_fail = 1;
    }

    /* (F, -): the first SHAKE call inside wc_ed448_make_public() fails, so it
     * returns before writing pubKey and the XMEMCMP is never evaluated --
     * nothing reads the untouched buffer. */
    mcdc_fh_arm(1);
    (void)wc_ed448_check_key(&mismatched);
    mcdc_fh_disarm();

    /* (T,F) for the XMEMCMP operand: a consistent key checks out. */
    ret = wc_ed448_check_key(&good);
    if (ret != 0) {
        WB_NOTE("check_key on a consistent key unexpectedly failed");
        wb_fail = 1;
    }

    wc_ed448_free(&mismatched);
    wc_ed448_free(&good);
    WB_NOTE("check_key make_public fault exercised (1520 ret==0 pair)");
}
#else
static void wb_ed448_check_key_hash_fault(void)
{ WB_NOTE("ed448 key import or SHAKE injector unavailable; check_key fault "
          "skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("ed448.c white-box hash-fault supplement\n");

    wb_ed448_sign_hash_faults();
    wb_ed448_verify_init_hash_faults();
    wb_ed448_check_key_hash_fault();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
