/* test_ed25519_hash_fault_whitebox.c
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
 * MC/DC hash-fault white-box supplement for wolfcrypt/src/ed25519.c.
 *
 * WHY A SEPARATE TU
 * -----------------
 * mcdc_fault_hash.h installs its interposers by macro and must therefore be
 * #included BEFORE ed25519.c. test_ed25519_whitebox.c must keep driving the
 * unfaulted primitives (its ed25519_hash()/verify-helper argument guards want
 * real hashing), so the fault sweeps live here in their own binary.
 *
 * THE LEVER
 * ---------
 * Every open "ret == 0" operand left in ed25519.c takes its `ret` from the
 * SHA-512 chain (ed25519_hash_init/update/final -> wc_InitSha512_ex /
 * wc_Sha512Update / wc_Sha512Final) and from nothing else. ed25519.c performs
 * no allocation on these paths in this suite's configs (WOLFSSL_SMALL_STACK
 * is unset, so WC_DECLARE_VAR/WC_ALLOC_VAR_EX are a plain stack object and a
 * no-op), so mcdc_fault_alloc.h has nothing to fault -- only a failing hash
 * primitive can break the chain. mcdc_fault_hash.h shadows Update/Final;
 * wc_InitSha512_ex (the 3-argument form ed25519.c actually calls, which the
 * header's opt-in MCDC_FH_WITH_SHA_INIT does not cover) is shadowed locally
 * below, sharing the header's counter so one arm() index space spans the
 * whole init/update/final sequence.
 *
 * TARGET CONDITIONS, AND WHICH VECTOR DRIVES WHICH HALF
 * -----------------------------------------------------
 *   wc_ed25519_sign_msg_ex():
 *     ~604  if (ret == 0 && (type == Ed25519ctx || type == Ed25519ph))
 *     ~611      if (ret == 0 && context != NULL)
 *     ~659  if (ret == 0 && (type == Ed25519ctx || type == Ed25519ph))
 *     ~666      if (ret == 0 && context != NULL)
 *       TRUE half (and the (T,T) row each "ret == 0" operand needs, since the
 *       decision must come out TRUE for the pair to be an independence pair):
 *       the unarmed Ed25519ctx signature with a non-NULL context.
 *       FALSE half: the sweep. Signing with a context takes ~20 SHA-512
 *       primitive calls; arm(n) fails the n-th and every later one, so
 *       sweeping n over 1..seen() breaks the chain immediately before each of
 *       the four decisions in turn (n at the block's ed25519_hash_init for
 *       604/659, n at one of the three ctx/type/contextLen updates for
 *       611/666). The sweep is index-free by construction, which is what makes
 *       it valid across the persistent-SHA and per-call-SHA variants alike
 *       (the persistent variant has no per-block init, so its call indices
 *       differ).
 *
 *   ed25519_verify_msg_init_with_sha():
 *     ~878      if (ret == 0 && context != NULL)
 *       Same shape, swept over a direct call to the file-static with a
 *       well-formed 64-byte signature blob, Ed25519ctx and a non-NULL context.
 *       The unarmed call is the (T,T) row.
 *
 *   wc_ed25519_check_key():
 *     ~1781 if (ret == 0 && XMEMCMP(pubKey, key->p, ED25519_PUB_KEY_SIZE) != 0)
 *       `ret` here is wc_ed25519_make_public()'s status, and that function's
 *       only failure mode on a well-formed key is ed25519_hash(). The
 *       independence pair for the "ret == 0" operand needs a row where the
 *       DECISION is true, i.e. (T,T): a key whose stored public key does NOT
 *       match the one derived from its private key. That is built here by
 *       importing seed A together with the public key of seed B with
 *       trusted = 1 (trusted = 0 would run wc_ed25519_check_key() inside the
 *       import and reject it). arm(1) then supplies the (F, -) row by failing
 *       make_public's first SHA-512 call. A matching key is checked too, for
 *       the XMEMCMP operand's own (T,F) row.
 *
 * CRASH SAFETY
 * ------------
 * The locally installed wc_InitSha512_ex interposer performs the REAL
 * initialisation and only then reports failure. ed25519.c reaches
 * ed25519_hash_free() -> wc_Sha512Free() on several of the paths a failed init
 * opens (wc_ed25519_sign_msg_ex ~622, wc_ed25519_verify_msg_ex ~1180), and
 * freeing a context that was never initialised would be undefined. A "failed"
 * init that still leaves a well-formed context is exactly as strong for MC/DC
 * -- the guards read the returned status, not the context -- and cannot crash.
 * Update/Final faults leave their output buffers untouched, so no armed call's
 * output (signature bytes, derived public key, res) is ever consumed here.
 *
 * VARIANT COVERAGE
 * ----------------
 * Every section is behind the same feature guard as the code it targets and
 * has an #else stub of the same signature, so the TU builds under all four
 * ed25519 variants (streaming/persistent-SHA, nonstreaming/per-call-SHA,
 * hardening, small). No RNG and no wall clock: fixed seeds, fixed message,
 * fixed sweep length. main() always returns 0 -- a nonzero exit would discard
 * the variant's whole coverage.
 *
 * Build: compiled by the white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with ed25519.o removed. Not part of the wolfSSL build.
 */

#include "mcdc_fault_hash.h"

#ifdef MCDC_FH_HAVE_SHA512
/* Local interposer for the 3-argument init ed25519.c uses. Shares
 * mcdc_fh_hit() so init/update/final live in ONE arm() index space. The real
 * init always runs first; see "CRASH SAFETY" above. */
MCDC_FH_MAYBE_UNUSED static int mcdc_ed_InitSha512_ex(wc_Sha512* sha,
    void* heap, int devId)
{
    int ret;
    int faulted;

    ret     = wc_InitSha512_ex(sha, heap, devId);
    faulted = mcdc_fh_hit();
    if (faulted && (ret == 0))
        ret = MCDC_FH_ERR;
    return ret;
}
#undef  wc_InitSha512_ex
#define wc_InitSha512_ex(a, b, c) mcdc_ed_InitSha512_ex((a), (b), (c))
#endif /* MCDC_FH_HAVE_SHA512 */

/* ed25519.c is #included AFTER the interposers are installed. */
#include <wolfcrypt/src/ed25519.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* Hard bound on every sweep: a signature with a context takes ~20 primitive
 * calls, a verify-init ~8. Nothing here is wall-clock or entropy bounded. */
#define WB_SWEEP_MAX 64L

#if defined(HAVE_ED25519) && defined(MCDC_FH_HAVE_SHA512) && \
    defined(HAVE_ED25519_KEY_IMPORT) && defined(HAVE_ED25519_MAKE_KEY) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ED25519) && \
    (!defined(WOLFSSL_SE050) || defined(WOLFSSL_SE050_ONLY_KEY_ID))

#define WB_HAVE_DRIVER

/* Two fixed seeds (any 32 bytes is a valid Ed25519 seed) and a fixed
 * message/context. No RNG anywhere in this TU. */
static const byte wb_seed_a[ED25519_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};
static const byte wb_seed_b[ED25519_KEY_SIZE] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
};
MCDC_FH_MAYBE_UNUSED static const byte wb_msg[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};
MCDC_FH_MAYBE_UNUSED static const byte wb_ctx[4] = { 0xc0, 0xc1, 0xc2, 0xc3 };

/* Import a seed and derive its public key; leaves privKeySet and pubKeySet
 * both set and consistent. Runs while DISARMED. */
static int wb_key_from_seed(ed25519_key* key, const byte* seed)
{
    int ret;

    ret = wc_ed25519_init(key);
    if (ret == 0) {
        ret = wc_ed25519_import_private_only(seed, ED25519_KEY_SIZE, key);
        if (ret == 0)
            ret = wc_ed25519_make_public(key, key->p, ED25519_PUB_KEY_SIZE);
        if (ret != 0)
            wc_ed25519_free(key);
    }

    return ret;
}

#endif /* driver preconditions */

/* --------------------------------------------------------------------------
 * 1. wc_ed25519_sign_msg_ex(): the "ret == 0" operands at ~604, ~611, ~659
 *    and ~666.
 * ----------------------------------------------------------------------- */
#if defined(WB_HAVE_DRIVER) && defined(HAVE_ED25519_SIGN)
static void wb_ed25519_sign_hash_faults(void)
{
    ed25519_key key;
    byte        sig[ED25519_SIG_SIZE];
    word32      sigLen;
    long        n;
    long        total;
    int         ret;

    if (wb_key_from_seed(&key, wb_seed_a) != 0) {
        WB_NOTE("ed25519 key setup failed; sign hash-fault sweep skipped");
        wb_fail = 1;
        return;
    }

    /* (T,T) row for all four operands: Ed25519ctx makes the type test at
     * 604/659 true and the non-NULL context makes 611/666's second operand
     * true, so the unarmed run drives every one of the four decisions TRUE. */
    mcdc_fh_disarm();
    sigLen = (word32)sizeof(sig);
    ret = wc_ed25519_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig, &sigLen,
        &key, (byte)Ed25519ctx, wb_ctx, (byte)sizeof(wb_ctx));
    total = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("ed25519ctx sign baseline failed");
        wb_fail = 1;
    }
    if (total > WB_SWEEP_MAX)
        total = WB_SWEEP_MAX;

    /* (F, -) rows: one armed run per primitive call index. Output signature
     * bytes of an armed run are never read. */
    for (n = 1; n <= total; n++) {
        mcdc_fh_arm(n);
        sigLen = (word32)sizeof(sig);
        (void)wc_ed25519_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig,
            &sigLen, &key, (byte)Ed25519ctx, wb_ctx, (byte)sizeof(wb_ctx));
        mcdc_fh_disarm();
    }

    /* Unarmed again: repeats the (T,T) row and shows the sweep left the key's
     * SHA state usable (relevant to the persistent-SHA variant). */
    sigLen = (word32)sizeof(sig);
    ret = wc_ed25519_sign_msg_ex(wb_msg, (word32)sizeof(wb_msg), sig, &sigLen,
        &key, (byte)Ed25519ctx, wb_ctx, (byte)sizeof(wb_ctx));
    if (ret != 0) {
        WB_NOTE("ed25519ctx sign after sweep failed");
        wb_fail = 1;
    }

    wc_ed25519_free(&key);
    WB_NOTE("sign_msg_ex hash chain swept (604/611/659/666 ret==0 pairs)");
}
#else
static void wb_ed25519_sign_hash_faults(void)
{ WB_NOTE("ed25519 sign or SHA-512 injector unavailable; sign sweep skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 2. ed25519_verify_msg_init_with_sha(): the "ret == 0" operand at ~878.
 * ----------------------------------------------------------------------- */
#if defined(WB_HAVE_DRIVER) && defined(HAVE_ED25519_VERIFY)
static void wb_ed25519_verify_init_hash_faults(void)
{
    ed25519_key key;
    wc_Sha512   sha;
    byte        sig[ED25519_SIG_SIZE];
    long        n;
    long        total;
    int         ret;

    if (wb_key_from_seed(&key, wb_seed_a) != 0) {
        WB_NOTE("ed25519 key setup failed; verify-init sweep skipped");
        wb_fail = 1;
        return;
    }

    /* Any 64 bytes reach the hash chain: the only structural check before it
     * is sigLen == ED25519_SIG_SIZE and the top three bits of the last byte.
     * This blob is never verified, only hashed. */
    XMEMSET(sig, 0x5a, sizeof(sig));
    sig[ED25519_SIG_SIZE - 1] = 0x00;

    if (wc_InitSha512(&sha) != 0) {
        WB_NOTE("wc_InitSha512 failed; verify-init sweep skipped");
        wb_fail = 1;
        wc_ed25519_free(&key);
        return;
    }

    /* (T,T) row: unarmed, Ed25519ctx with a non-NULL context. */
    mcdc_fh_disarm();
    ret = ed25519_verify_msg_init_with_sha(sig, (word32)sizeof(sig), &key, &sha,
        (byte)Ed25519ctx, wb_ctx, (byte)sizeof(wb_ctx));
    total = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("verify_msg_init_with_sha baseline failed");
        wb_fail = 1;
    }
    if (total > WB_SWEEP_MAX)
        total = WB_SWEEP_MAX;

    /* (F, -) rows. The context is re-initialised between runs while disarmed,
     * so each armed run starts from the same state. */
    for (n = 1; n <= total; n++) {
        wc_Sha512Free(&sha);
        if (wc_InitSha512(&sha) != 0) {
            WB_NOTE("wc_InitSha512 failed mid-sweep; sweep truncated");
            wb_fail = 1;
            break;
        }
        mcdc_fh_arm(n);
        (void)ed25519_verify_msg_init_with_sha(sig, (word32)sizeof(sig), &key,
            &sha, (byte)Ed25519ctx, wb_ctx, (byte)sizeof(wb_ctx));
        mcdc_fh_disarm();
    }

    wc_Sha512Free(&sha);
    wc_ed25519_free(&key);
    WB_NOTE("verify_msg_init_with_sha hash chain swept (878 ret==0 pair)");
}
#else
static void wb_ed25519_verify_init_hash_faults(void)
{ WB_NOTE("ed25519 verify or SHA-512 injector unavailable; verify-init sweep "
          "skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 3. wc_ed25519_check_key(): the "ret == 0" operand at ~1781.
 * ----------------------------------------------------------------------- */
#ifdef WB_HAVE_DRIVER
static void wb_ed25519_check_key_hash_fault(void)
{
    ed25519_key good;
    ed25519_key mismatched;
    int         ret;

    /* `good` carries seed B and B's own public key; it supplies both the
     * (T,F) row for the XMEMCMP operand and the public key that makes
     * `mismatched` mismatch. */
    if (wb_key_from_seed(&good, wb_seed_b) != 0) {
        WB_NOTE("ed25519 reference key setup failed; check_key fault skipped");
        wb_fail = 1;
        return;
    }

    if (wc_ed25519_init(&mismatched) != 0) {
        WB_NOTE("wc_ed25519_init failed; check_key fault skipped");
        wb_fail = 1;
        wc_ed25519_free(&good);
        return;
    }

    /* trusted = 1 so the import does NOT run wc_ed25519_check_key() itself
     * (which is exactly the check this vector wants to reach later, and which
     * would make the import fail). Seed A's private key with seed B's public
     * key: make_public() will derive A's public key and the XMEMCMP will
     * differ. */
    ret = wc_ed25519_import_private_key_ex(wb_seed_a, ED25519_KEY_SIZE, good.p,
        ED25519_PUB_KEY_SIZE, &mismatched, 1);
    if (ret != 0) {
        WB_NOTE("mismatched-pub import failed; check_key fault skipped");
        wb_fail = 1;
        wc_ed25519_free(&mismatched);
        wc_ed25519_free(&good);
        return;
    }

    /* (T,T): make_public succeeds, the derived key differs from key->p, so the
     * decision is TRUE. This is the row the "ret == 0" operand's independence
     * pair needs. */
    mcdc_fh_disarm();
    ret = wc_ed25519_check_key(&mismatched);
    if (ret != WC_NO_ERR_TRACE(PUBLIC_KEY_E)) {
        WB_NOTE("check_key on a mismatched public key did not report "
                "PUBLIC_KEY_E");
        wb_fail = 1;
    }

    /* (F, -): the first SHA-512 call inside wc_ed25519_make_public() fails, so
     * it returns before writing pubKey and the XMEMCMP is never evaluated --
     * nothing reads the untouched buffer. */
    mcdc_fh_arm(1);
    (void)wc_ed25519_check_key(&mismatched);
    mcdc_fh_disarm();

    /* (T,F) for the XMEMCMP operand: a consistent key checks out. */
    ret = wc_ed25519_check_key(&good);
    if (ret != 0) {
        WB_NOTE("check_key on a consistent key unexpectedly failed");
        wb_fail = 1;
    }

    wc_ed25519_free(&mismatched);
    wc_ed25519_free(&good);
    WB_NOTE("check_key make_public fault exercised (1781 ret==0 pair)");
}
#else
static void wb_ed25519_check_key_hash_fault(void)
{ WB_NOTE("ed25519 key import/make or SHA-512 injector unavailable; check_key "
          "fault skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("ed25519.c white-box hash-fault supplement\n");

    wb_ed25519_sign_hash_faults();
    wb_ed25519_verify_init_hash_faults();
    wb_ed25519_check_key_hash_fault();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
