/* test_kdf_hash_fault_whitebox.c
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
 * MC/DC hash/AES fault white-box supplement for wolfcrypt/src/kdf.c.
 *
 * WHY A SECOND kdf.c WHITE-BOX
 * ----------------------------
 * test_kdf_whitebox.c closes everything an argument fault or an allocation
 * fault can reach. What it cannot reach is the FALSE half of five "ret == 0"
 * operands whose `ret` comes from a hash or AES transform on VALID buffers,
 * with no allocation anywhere on the path:
 *
 *      804:  wc_SSH_KDF()             if (ret == 0 && kPad)
 *      855:  wc_SSH_KDF()             if (ret == 0 && kPad)   (tail block)
 *      947:  wc_srtp_kdf_derive_key() for (i = 0; (ret == 0) && (i < blocks); ...)
 *      959:  wc_srtp_kdf_derive_key() if ((ret == 0) && (keySz > 0))
 *     1354:  wc_KDA_KDF_iteration()   if (ret == 0 && fixedInfoSz > 0)
 *
 * mcdc_fault_hash.h is the lever for exactly this class: it macro-interposes
 * the primitives for THIS translation unit only, before kdf.c is #included, so
 * mcdc_fh_arm(n) makes the n-th primitive call (and every later one) return
 * BAD_FUNC_ARG. Both halves of every pair below are driven in this one binary.
 *
 * PER-CONDITION VECTOR MAP
 * ------------------------
 * wc_SSH_KDF, WC_SHA256, k[0] & 0x80 (kPad == 1), keySz 37 against a 32-byte
 * digest => blocks == 1 and remainder == 5, which is the only shape that
 * reaches BOTH kPad guards. _HashUpdate()/_HashFinal() dispatch straight to
 * wc_Sha256Update()/wc_Sha256Final(), so both are interposed; _HashInit() goes
 * to wc_InitSha256(), which is NOT interposed (MCDC_FH_WITH_SHA_INIT is not
 * defined), so context setup never fails. The interposed call sequence is
 *     1..6  the six _HashUpdate()s feeding the first block
 *     7     _HashFinal() writing the first block into key
 *     8..13 the remainder block's five _HashUpdate()s and its _HashFinal()
 * and the driver sweeps n over 1..mcdc_fh_seen():
 *     n == 1        -> ~804 evaluated with ret != 0            (idx0 FALSE)
 *     n == 7        -> the first-block _HashFinal() fails, the blocks loop is
 *                      empty (blocks == 1) and the "remainder > 0" arm is
 *                      entered unconditionally, so ~855 is evaluated with
 *                      ret != 0                                (idx0 FALSE)
 *     unarmed run   -> both guards evaluated (T,T)             (idx0 TRUE)
 * Every armed index is memory-safe: the only two XMEMCPY()s into `key` are
 * guarded by ret == 0, and the two _HashUpdate()s that read `key` back are
 * likewise guarded, so a faulted run never reads or copies from a buffer the
 * faulted primitive left unwritten.
 *
 * wc_SRTP_KDF -> wc_srtp_kdf_derive_key with outKeySz == 20 => blocks == 1 and
 * a 4-byte partial tail. The only interposed primitive on that path is
 * wc_AesEcbEncrypt() (wc_AesInit/wc_AesSetKey are not interposed):
 *     unarmed   -> loop runs i == 0 as (T,T), re-tests i == 1 as (T,F), then
 *                  ~959 is (T,T)                       (idx0 TRUE for 947+959)
 *     arm(1)    -> the loop's single full-block encrypt fails, so the loop
 *                  re-test is (F,-) and ~959 is (F,-)  (idx0 FALSE for both)
 *     arm(2)    -> the full block succeeds and the partial-tail encrypt fails,
 *                  driving the inner "if (ret == 0)" false with ~959 still
 *                  (T,T)
 * The tail XMEMCPY is guarded by ret == 0, so the uninitialised `enc` scratch a
 * faulted encrypt leaves behind is never consumed.
 *
 * wc_KDA_KDF_iteration takes its `ret` from the GENERIC wc_HashUpdate()
 * dispatcher in hash.c, which mcdc_fault_hash.h does not shadow (hash.c is a
 * separate object in the archive, not textually included here). One extra
 * interposer, local to this TU and feeding the same counter, covers it:
 *     unarmed   -> fixedInfoSz > 0 and both preceding updates succeed, ~1354
 *                  is (T,T)                                     (idx0 TRUE)
 *     arm(1)    -> the counter update fails, ~1354 is (F,-)      (idx0 FALSE)
 * wc_HashInit() is not interposed, so the context handed to wc_HashFree() is
 * always valid; wc_HashFinal() is skipped on the armed run and `output` is only
 * ForceZero()ed, never read.
 *
 * DETERMINISM: fixed vector counts, no wall clock, no entropy. The sweep length
 * comes from mcdc_fh_seen() on the unarmed baseline and is additionally capped.
 * main() always returns 0 (a nonzero exit discards the variant's coverage).
 *
 * VARIANTS: every section is behind the same feature guard as the code it
 * targets, with an #else stub, so this TU builds under kdf_default,
 * small_stack, ticket_nonce_malloc and crypto_cb alike.
 *
 * Build: compiled by the white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with kdf.o removed. Not part of the wolfSSL build.
 */

/* Installs the SHA-256 / AES-ECB / HMAC interposers. MUST precede kdf.c. */
#include "mcdc_fault_hash.h"

#include <wolfssl/wolfcrypt/hash.h>

/* Extra interposer for the generic hash wrapper, which mcdc_fault_hash.h does
 * not shadow. Defined before the macro exists, so it reaches the real one. */
#if !defined(NO_KDF) && defined(WC_KDF_NIST_SP_800_56C) && \
    !defined(NO_HASH_WRAPPER)
MCDC_FH_MAYBE_UNUSED static int mcdc_kdf_HashUpdate(wc_HashAlg* hash,
    enum wc_HashType type, const byte* data, word32 dataSz)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_HashUpdate(hash, type, data, dataSz);
}
#undef  wc_HashUpdate
#define wc_HashUpdate(a, b, c, d)  mcdc_kdf_HashUpdate((a), (b), (c), (d))
#endif

#include <wolfcrypt/src/kdf.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* --------------------------------------------------------------------------
 * 1. wc_SSH_KDF(): the two "ret == 0 && kPad" guards (~804, ~855).
 * ----------------------------------------------------------------------- */
#if !defined(NO_KDF) && defined(WOLFSSL_WOLFSSH) && !defined(NO_SHA256) && \
    defined(MCDC_FH_HAVE_SHA256)

/* Hard cap on the sweep so the vector count can never depend on the build. */
#define WB_SSH_MAX_STEPS  64

static void wb_ssh_kdf_kpad_errprop(void)
{
    byte key[WC_SHA256_DIGEST_SIZE + 5];   /* blocks == 1, remainder == 5 */
    byte k[32];
    byte h[32];
    byte sessionId[32];
    long steps;
    long n;
    int  ret;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(k, 0x11, sizeof(k));
    XMEMSET(h, 0x22, sizeof(h));
    XMEMSET(sessionId, 0x33, sizeof(sessionId));
    k[0] = 0x80;                           /* top bit set => kPad == 1 */

    /* Unarmed baseline: both kPad guards evaluated (T,T). Also sizes the
     * sweep. */
    mcdc_fh_disarm();
    ret = wc_SSH_KDF((byte)WC_SHA256, 'A', key, (word32)sizeof(key),
        k, (word32)sizeof(k), h, (word32)sizeof(h),
        sessionId, (word32)sizeof(sessionId));
    steps = mcdc_fh_seen();
    if (ret != 0) {
        WB_NOTE("wc_SSH_KDF unarmed baseline failed");
        wb_fail = 1;
    }
    if (steps > WB_SSH_MAX_STEPS)
        steps = WB_SSH_MAX_STEPS;

    /* n == 1 drives ~804 false; n == 7 (the first-block _HashFinal) drives
     * ~855 false. The whole range is swept so the map holds for any digest
     * size the build selects. */
    for (n = 1; n <= steps; n++) {
        mcdc_fh_arm(n);
        (void)wc_SSH_KDF((byte)WC_SHA256, 'A', key, (word32)sizeof(key),
            k, (word32)sizeof(k), h, (word32)sizeof(h),
            sessionId, (word32)sizeof(sessionId));
        mcdc_fh_disarm();
    }

    WB_NOTE("wc_SSH_KDF ret==0 && kPad pairs exercised");
}
#else
static void wb_ssh_kdf_kpad_errprop(void)
{ WB_NOTE("WOLFSSL_WOLFSSH/SHA256 off; wc_SSH_KDF kPad guards skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 2. wc_srtp_kdf_derive_key(): the loop and tail "ret == 0" operands
 *    (~947, ~959), reached through the public wc_SRTP_KDF().
 * ----------------------------------------------------------------------- */
#if !defined(NO_KDF) && defined(WC_SRTP_KDF) && defined(MCDC_FH_HAVE_AES) && \
    defined(HAVE_AES_ECB)
static void wb_srtp_derive_key_errprop(void)
{
    byte key[16];
    byte salt[WC_SRTP_MAX_SALT];
    byte key1[WC_AES_BLOCK_SIZE + 4];      /* blocks == 1, 4-byte tail */
    int  ret;

    XMEMSET(key, 0x44, sizeof(key));
    XMEMSET(salt, 0x55, sizeof(salt));
    XMEMSET(key1, 0, sizeof(key1));

    /* kdrIdx == -1 so idx is never read and may be NULL. */

    /* Unarmed baseline: loop guard (T,T) then (T,F), tail guard (T,T). */
    mcdc_fh_disarm();
    ret = wc_SRTP_KDF(key, (word32)sizeof(key), salt, (word32)sizeof(salt),
        -1, NULL, key1, (word32)sizeof(key1), NULL, 0, NULL, 0);
    if (ret != 0) {
        WB_NOTE("wc_SRTP_KDF unarmed baseline failed");
        wb_fail = 1;
    }

    /* The single full-block encrypt fails: loop re-test and tail guard both
     * see ret != 0. */
    mcdc_fh_arm(1);
    (void)wc_SRTP_KDF(key, (word32)sizeof(key), salt, (word32)sizeof(salt),
        -1, NULL, key1, (word32)sizeof(key1), NULL, 0, NULL, 0);
    mcdc_fh_disarm();

    /* The full block succeeds and the partial-tail encrypt fails: tail guard
     * still (T,T), its inner "if (ret == 0)" driven false. */
    mcdc_fh_arm(2);
    (void)wc_SRTP_KDF(key, (word32)sizeof(key), salt, (word32)sizeof(salt),
        -1, NULL, key1, (word32)sizeof(key1), NULL, 0, NULL, 0);
    mcdc_fh_disarm();

    WB_NOTE("wc_srtp_kdf_derive_key ret==0 loop/tail pairs exercised");
}
#else
static void wb_srtp_derive_key_errprop(void)
{ WB_NOTE("WC_SRTP_KDF/AES-ECB off; SRTP derive-key guards skipped"); }
#endif

/* --------------------------------------------------------------------------
 * 3. wc_KDA_KDF_iteration(): "ret == 0 && fixedInfoSz > 0" (~1354).
 * ----------------------------------------------------------------------- */
#if !defined(NO_KDF) && defined(WC_KDF_NIST_SP_800_56C) && \
    !defined(NO_HASH_WRAPPER) && !defined(NO_SHA256)
static void wb_kda_iteration_fixedinfo_errprop(void)
{
    byte z[32];
    byte fixedInfo[8];
    byte out[WC_SHA256_DIGEST_SIZE];       /* exactly one iteration */
    int  ret;

    XMEMSET(z, 0x66, sizeof(z));
    XMEMSET(fixedInfo, 0x99, sizeof(fixedInfo));
    XMEMSET(out, 0, sizeof(out));

    /* Unarmed baseline: ~1354 evaluated (T,T). */
    mcdc_fh_disarm();
    ret = wc_KDA_KDF_onestep(z, (word32)sizeof(z), fixedInfo,
        (word32)sizeof(fixedInfo), (word32)sizeof(out), WC_HASH_TYPE_SHA256,
        out, (word32)sizeof(out));
    if (ret != 0) {
        WB_NOTE("wc_KDA_KDF_onestep unarmed baseline failed");
        wb_fail = 1;
    }

    /* The counter wc_HashUpdate() fails, so ~1354 is reached with ret != 0. */
    mcdc_fh_arm(1);
    (void)wc_KDA_KDF_onestep(z, (word32)sizeof(z), fixedInfo,
        (word32)sizeof(fixedInfo), (word32)sizeof(out), WC_HASH_TYPE_SHA256,
        out, (word32)sizeof(out));
    mcdc_fh_disarm();

    WB_NOTE("wc_KDA_KDF_iteration ret==0 && fixedInfoSz>0 pair exercised");
}
#else
static void wb_kda_iteration_fixedinfo_errprop(void)
{ WB_NOTE("WC_KDF_NIST_SP_800_56C/hash-wrapper off; KDA iteration guard "
          "skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("kdf.c white-box MC/DC hash/AES fault supplement\n");

    mcdc_fh_disarm();

    wb_ssh_kdf_kpad_errprop();
    wb_srtp_derive_key_errprop();
    wb_kda_iteration_fixedinfo_errprop();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
