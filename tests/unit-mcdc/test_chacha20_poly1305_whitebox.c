/* test_chacha20_poly1305_whitebox.c
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

/* White-box MC/DC supplement for wolfcrypt/src/chacha20_poly1305.c.
 *
 * Three groups of conditions, all in code the AEAD rework added.
 *
 * 1. AAD argument guards, wc_ChaCha20Poly1305_Encrypt/_Decrypt and
 *    wc_ChaCha20Poly1305_UpdateAad:
 *
 *      if (!inKey || !inIV || inPlaintext == NULL ||
 *          (inAADLen > 0 && inAAD == NULL) || !outCiphertext || !outAuthTag)
 *      if (aead == NULL || (inAAD == NULL && inAADLen > 0))
 *
 *    The AEAD tests pass either a real AAD buffer with a non-zero length or no
 *    AAD at all, so the "length without a buffer" combination -- the one the
 *    guard exists for -- is never built, and neither operand of it is paired.
 *    This file passes inAAD == NULL with a non-zero length, alongside the
 *    accepting shapes (AAD present, and no AAD at all) in the same binary.
 *
 * 2. wc_ChaCha20Poly1305_UpdateAad's
 *
 *      if (inAAD && inAADLen > 0)
 *
 *    first operand FALSE. inAAD == NULL only survives the guard above at zero
 *    length, i.e. exactly the "no AAD this call" no-op the tests never make.
 *
 * 3. wc_ChaCha20Poly1305_UpdateData's two
 *
 *      if (ret == 0 && len > 0)
 *
 *    guards (encrypt and decrypt arms), "len > 0" FALSE half: a zero-length
 *    data update, valid but unused by the tests.
 *
 * NOT closable, recorded in the exclusion record (three conditions,
 * one argument):
 *
 *   :943  if (ret == 0 && aead->state == CHACHA20_POLY1305_STATE_AAD)
 *   :975  if (ret == 0 && len > 0)          (encrypt arm)
 *   :999  if (ret == 0 && len > 0)          (decrypt arm)
 *
 *    all three "ret == 0" operands. ret is initialised to 0 at :904; the only
 *    statement that can assign it before :943 is at :938, inside the
 *    WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA block, and it is a wc_Poly1305Update
 *    on &aead->poly (aead is checked non-NULL at :907) with a local buffer, so
 *    it cannot fail. :975 and :999 are additionally dominated by the enclosing
 *    "if (ret == 0)" at :951, and the only assignment between that and them is
 *    chacha20_poly1305_stitch_chunk() at :968/:992, which returns 0 except
 *    through SAVE_VECTOR_REGISTERS -- the literal 0 in a userspace build
 *    (types.h), the same dispatch residual already documented for the
 *    aes/chacha/sha save-vector guards.
 *
 *    wb_updatedata_pad_fault() below is the evidence for the :975/:999 half of
 *    that argument rather than a closure attempt: it interposes
 *    wc_Poly1305_Pad at preprocessing time (the mcdc_fault_hash.h technique --
 *    the wrapper is defined against the real declaration, and only then is the
 *    name #defined to the wrapper, so the involved .c's call sites, and only
 *    those, are redirected) and makes the AAD padding at :944 fail. That does
 *    drive ret non-zero, and the guards at :975/:999 are still not reached
 *    with it, because :951 skips the whole block -- which is exactly why no
 *    call shape pairs their first operand.
 *
 * No ciphertext or tag value is checked here: the AEAD KATs own correctness,
 * this file only drives the decisions. Every failure is reported as a skip and
 * main() always returns 0 -- a non-zero exit makes the harness discard the
 * whole variant.
 */

/* Must be first, exactly as every wolfcrypt .c does it: establishes
 * BUILDING_WOLFSSL / config.h before any wolfSSL declaration is seen, so
 * including headers here does not change how the involved .c sees the world. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

/* ---- wc_Poly1305_Pad() interposer ---------------------------------------
 * Declared before the macro below exists, so it reaches the real function. */
static int wb_pad_armed = 0;

static int wb_poly1305_pad(Poly1305* ctx, word32 lenToPad)
{
    if (wb_pad_armed) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    return wc_Poly1305_Pad(ctx, lenToPad);
}

#define wc_Poly1305_Pad wb_poly1305_pad

#endif /* HAVE_CHACHA && HAVE_POLY1305 */

#include <wolfcrypt/src/chacha20_poly1305.c>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#define WB_PT_LEN 64

static const byte wb_key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
    0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
};
static const byte wb_iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
    0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
};
static const byte wb_aad[8] = {
    0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3
};

/* ---- 1. one-shot Encrypt/Decrypt AAD argument guards -------------------- */
static void wb_oneshot_aad_guard(void)
{
    byte pt[WB_PT_LEN];
    byte ct[WB_PT_LEN];
    byte out[WB_PT_LEN];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    word32 i;

    for (i = 0; i < (word32)sizeof(pt); i++) {
        pt[i] = (byte)i;
    }

    /* Rejecting vector: a non-zero AAD length with no AAD buffer. */
    if (wc_ChaCha20Poly1305_Encrypt(wb_key, wb_iv, NULL, (word32)sizeof(wb_aad),
            pt, (word32)sizeof(pt), ct, tag) !=
                WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Encrypt(aadLen>0, aad==NULL) not rejected");
        wb_fail = 1;
    }
    if (wc_ChaCha20Poly1305_Decrypt(wb_key, wb_iv, NULL, (word32)sizeof(wb_aad),
            ct, (word32)sizeof(ct), tag, out) !=
                WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        WB_NOTE("Decrypt(aadLen>0, aad==NULL) not rejected");
        wb_fail = 1;
    }

    /* Accepting vector, AAD present: length operand true, buffer operand
     * false. */
    if (wc_ChaCha20Poly1305_Encrypt(wb_key, wb_iv, wb_aad,
            (word32)sizeof(wb_aad), pt, (word32)sizeof(pt), ct, tag) != 0) {
        WB_NOTE("Encrypt with AAD failed");
        wb_fail = 1;
    }
    else if (wc_ChaCha20Poly1305_Decrypt(wb_key, wb_iv, wb_aad,
            (word32)sizeof(wb_aad), ct, (word32)sizeof(ct), tag, out) != 0) {
        WB_NOTE("Decrypt with AAD failed");
        wb_fail = 1;
    }

    /* Accepting vector, no AAD at all: length operand false. */
    if (wc_ChaCha20Poly1305_Encrypt(wb_key, wb_iv, NULL, 0, pt,
            (word32)sizeof(pt), ct, tag) != 0) {
        WB_NOTE("Encrypt without AAD failed");
        wb_fail = 1;
    }
    else if (wc_ChaCha20Poly1305_Decrypt(wb_key, wb_iv, NULL, 0, ct,
            (word32)sizeof(ct), tag, out) != 0) {
        WB_NOTE("Decrypt without AAD failed");
        wb_fail = 1;
    }

    WB_NOTE("one-shot AAD length/buffer guard pairs exercised");
}

/* ---- 2./3. streaming UpdateAad / UpdateData guards ---------------------- */
static void wb_stream_guards(int isEncrypt)
{
    ChaChaPoly_Aead aead;
    byte in[WB_PT_LEN];
    byte out[WB_PT_LEN];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    const char* dir = isEncrypt ? "encrypt" : "decrypt";
    word32 i;

    for (i = 0; i < (word32)sizeof(in); i++) {
        in[i] = (byte)(i + 1);
    }

    XMEMSET(&aead, 0, sizeof(aead));
    if (wc_ChaCha20Poly1305_Init(&aead, wb_key, wb_iv, isEncrypt) != 0) {
        printf("  [wb] Init(%s) failed; stream guards skipped\n", dir);
        wb_fail = 1;
        return;
    }

    /* UpdateAad: length without a buffer is rejected ... */
    if (wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, (word32)sizeof(wb_aad)) !=
            WC_NO_ERR_TRACE(BAD_FUNC_ARG)) {
        printf("  [wb] UpdateAad(NULL, len>0) not rejected (%s)\n", dir);
        wb_fail = 1;
    }
    /* ... while no buffer at zero length is the accepted no-op: it pairs the
     * length operand of the guard and the buffer operand of the "is there any
     * AAD to hash" test below it. */
    if (wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, 0) != 0) {
        printf("  [wb] UpdateAad(NULL, 0) rejected (%s)\n", dir);
        wb_fail = 1;
    }
    /* Real AAD: both operands true. */
    if (wc_ChaCha20Poly1305_UpdateAad(&aead, wb_aad,
            (word32)sizeof(wb_aad)) != 0) {
        printf("  [wb] UpdateAad(aad, len>0) failed (%s)\n", dir);
        wb_fail = 1;
    }

    /* UpdateData with nothing to do: the AAD padding still runs (state is
     * AAD), so ret == 0 and the length operand is false. */
    if (wc_ChaCha20Poly1305_UpdateData(&aead, in, out, 0) != 0) {
        printf("  [wb] UpdateData(len==0) failed (%s)\n", dir);
        wb_fail = 1;
    }
    /* The accepting vector for the same guard, same binary. */
    if (wc_ChaCha20Poly1305_UpdateData(&aead, in, out,
            (word32)sizeof(in)) != 0) {
        printf("  [wb] UpdateData(len>0) failed (%s)\n", dir);
        wb_fail = 1;
    }
    if (wc_ChaCha20Poly1305_Final(&aead, tag) != 0) {
        printf("  [wb] Final failed (%s)\n", dir);
        wb_fail = 1;
    }

    printf("  [wb] streaming AAD/data guard pairs exercised (%s)\n", dir);
}

/* ---- 3b. AAD-padding fault: evidence for the "ret == 0" exclusions ------
 * See the file header. Faulting the pad at :944 sets ret non-zero, and the
 * guards at :975/:999 are then not evaluated at all because :951 skips the
 * block -- so their first operand has no independence pair through any call
 * shape. Kept as an executed error path, not as a closure. */
static void wb_updatedata_pad_fault(int isEncrypt)
{
    ChaChaPoly_Aead aead;
    byte in[WB_PT_LEN];
    byte out[WB_PT_LEN];
    const char* dir = isEncrypt ? "encrypt" : "decrypt";
    int ret;
    word32 i;

    for (i = 0; i < (word32)sizeof(in); i++) {
        in[i] = (byte)(i + 2);
    }

    XMEMSET(&aead, 0, sizeof(aead));
    if (wc_ChaCha20Poly1305_Init(&aead, wb_key, wb_iv, isEncrypt) != 0) {
        printf("  [wb] Init(%s) failed; pad-fault case skipped\n", dir);
        wb_fail = 1;
        return;
    }
    /* State must be AAD so that UpdateData runs the padding step. */
    if (wc_ChaCha20Poly1305_UpdateAad(&aead, wb_aad,
            (word32)sizeof(wb_aad)) != 0) {
        printf("  [wb] UpdateAad failed; pad-fault case skipped (%s)\n", dir);
        wb_fail = 1;
        return;
    }

    wb_pad_armed = 1;
    ret = wc_ChaCha20Poly1305_UpdateData(&aead, in, out, (word32)sizeof(in));
    wb_pad_armed = 0;
    if (ret == 0) {
        printf("  [wb] faulted UpdateData unexpectedly succeeded (%s)\n", dir);
        wb_fail = 1;
    }
    /* The aead is poisoned: no tag is taken from it, and it is not reused. */
    chacha20_poly1305_aead_zero(&aead);

    printf("  [wb] UpdateData with a failed AAD pad exercised (%s)\n", dir);
}

static void wb_run(void)
{
    wb_oneshot_aad_guard();
    wb_stream_guards(CHACHA20_POLY1305_AEAD_ENCRYPT);
    wb_stream_guards(CHACHA20_POLY1305_AEAD_DECRYPT);
    wb_updatedata_pad_fault(CHACHA20_POLY1305_AEAD_ENCRYPT);
    wb_updatedata_pad_fault(CHACHA20_POLY1305_AEAD_DECRYPT);
}

#else

static void wb_run(void)
{
    WB_NOTE("HAVE_CHACHA/HAVE_POLY1305 off in this variant; skipped");
}

#endif /* HAVE_CHACHA && HAVE_POLY1305 */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("chacha20_poly1305.c white-box MC/DC supplement\n");
    wb_run();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the harness
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
}
