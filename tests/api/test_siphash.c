/* test_siphash.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/siphash.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_siphash.h>

/*
 * MC/DC: argument/length-validation decisions in wolfcrypt/src/siphash.c.
 *
 * wc_InitSipHash()'s guard (siphash.c ~line 155):
 *     (sipHash == NULL) || (key == NULL) ||
 *         ((outSz != SIPHASH_MAC_SIZE_8) && (outSz != SIPHASH_MAC_SIZE_16))
 *   c0 = sipHash == NULL
 *   c1 = key == NULL
 *   c2 = outSz != SIPHASH_MAC_SIZE_8
 *   c3 = outSz != SIPHASH_MAC_SIZE_16
 *
 * wc_SipHashUpdate()'s guard (siphash.c ~line 248):
 *     (sipHash == NULL) || ((in == NULL) && (inSz != 0))
 *   c0 = sipHash == NULL
 *   c1 = in == NULL
 *   c2 = inSz != 0
 *
 * wc_SipHashFinal()'s guard (siphash.c ~line 325):
 *     (sipHash == NULL) || (out == NULL) || (outSz != sipHash->outSz)
 *   c0 = sipHash == NULL
 *   c1 = out == NULL
 *   c2 = outSz != sipHash->outSz
 *
 * wc_SipHash()'s guard (siphash.c ~line 862 portable C path; the same
 * guard is duplicated ahead of the GCC/x86_64 (~line 409) and
 * GCC/Aarch64 (~line 638) inline-asm variants -- whichever is compiled
 * for this target, the C-level decision and its operands are identical):
 *     (key == NULL) || ((in == NULL) && (inSz != 0)) || (out == NULL) ||
 *         ((outSz != SIPHASH_MAC_SIZE_8) && (outSz != SIPHASH_MAC_SIZE_16))
 *   c0 = key == NULL
 *   c1 = in == NULL
 *   c2 = inSz != 0
 *   c3 = out == NULL
 *   c4 = outSz != SIPHASH_MAC_SIZE_8
 *   c5 = outSz != SIPHASH_MAC_SIZE_16
 *
 * All four guards return BAD_FUNC_ARG.
 */
int test_wc_SipHash_DecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SIPHASH
    SipHash sipHash;
    byte key[SIPHASH_KEY_SIZE];
    byte in[5];
    byte out[SIPHASH_MAC_SIZE_16];

    XMEMSET(&sipHash, 0, sizeof(sipHash));
    XMEMSET(key, 0, sizeof(key));
    XMEMSET(in, 0, sizeof(in));
    XMEMSET(out, 0, sizeof(out));
    key[0] = 0x01;
    in[0] = 0x02;

    /* --- wc_InitSipHash() --- */

    /* c0 true, isolates this leaf: c1/c2/c3 all false. */
    ExpectIntEQ(wc_InitSipHash(NULL, key, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c1 true, c0 false, (c2 && c3) false: isolates c1. */
    ExpectIntEQ(wc_InitSipHash(&sipHash, NULL, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Baseline: c0/c1 false, outSz == 8 so c2 false (c2 && c3 false). */
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);

    /* outSz == 16: c2 true, c3 false (c2 && c3 still false). Paired
     * against the outSz == 7 case below to isolate c3. */
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_16), 0);

    /* outSz == 7 (neither 8 nor 16): c2 && c3 both true.
     * - vs the outSz==8 case: c3 held true, c2 toggles false->true,
     *   result toggles 0 -> BAD_FUNC_ARG (isolates c2).
     * - vs the outSz==16 case: c2 held true, c3 toggles false->true,
     *   result toggles 0 -> BAD_FUNC_ARG (isolates c3). */
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, 7),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_SipHashUpdate() --- */

    /* c0 true: c1 false (in valid) so (c1 && c2) is false regardless of
     * inSz -- isolates c0 when paired against the baseline below. */
    ExpectIntEQ(wc_SipHashUpdate(NULL, in, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c0 false, c1 true, c2 true (inSz != 0): (c1 && c2) true. */
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, NULL, sizeof(in)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c1 held true, c2 toggles true->false (inSz == 0): (c1 && c2)
     * toggles true->false, result toggles BAD_FUNC_ARG -> 0. Isolates
     * c2. A NULL buffer with a zero length is a legitimate no-op. */
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, NULL, 0), 0);

    /* c2 held true (inSz != 0), c1 toggles true->false (in valid):
     * (c1 && c2) toggles true->false, result toggles BAD_FUNC_ARG -> 0.
     * Isolates c1. Also pairs against the c0-true case above (c1 && c2
     * held false in both) to isolate c0. */
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, in, sizeof(in)), 0);

    /* --- wc_SipHashFinal() --- */

    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);

    /* c0 true: c1/c2 do not matter (short-circuited); pairs against the
     * baseline below (c1/c2 both false there) to isolate c0. */
    ExpectIntEQ(wc_SipHashFinal(NULL, out, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c0 false, c1 true: c2 does not matter (short-circuited, and would
     * be false here since outSz matches the stored value). Pairs
     * against the baseline to isolate c1. */
    ExpectIntEQ(wc_SipHashFinal(&sipHash, NULL, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c0/c1 false, c2 true (outSz != sipHash->outSz, 16 vs the 8 stored
     * at init): pairs against the baseline to isolate c2. */
    ExpectIntEQ(wc_SipHashFinal(&sipHash, out, SIPHASH_MAC_SIZE_16),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Baseline: c0/c1/c2 all false -- outSz matches the stored value. */
    ExpectIntEQ(wc_SipHashFinal(&sipHash, out, SIPHASH_MAC_SIZE_8), 0);

    /* --- wc_SipHash() (one-shot) --- */

    /* c0 true: c1 false (in valid) so (c1 && c2) false, c3 false,
     * (c4 && c5) false (outSz == 8). Pairs against the baseline below
     * to isolate c0. */
    ExpectIntEQ(wc_SipHash(NULL, in, 0, out, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c0 false, c1 true, c2 true (inSz != 0): (c1 && c2) true, c3/c4/c5
     * (via c4 && c5) false. */
    ExpectIntEQ(wc_SipHash(key, NULL, sizeof(in), out, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* c1 held true, c2 toggles true->false (inSz == 0): (c1 && c2)
     * toggles true->false, result toggles BAD_FUNC_ARG -> 0. Isolates
     * c2. NULL input with zero length is a legitimate empty message. */
    ExpectIntEQ(wc_SipHash(key, NULL, 0, out, SIPHASH_MAC_SIZE_8), 0);

    /* Baseline: c0/c1/c3 false, c2 true but masked (c1 false), c4/c5
     * both false (outSz == 8) so (c4 && c5) false. */
    ExpectIntEQ(wc_SipHash(key, in, sizeof(in), out, SIPHASH_MAC_SIZE_8), 0);

    /* c3 true, all else as in the baseline: pairs against the baseline
     * to isolate c3. */
    ExpectIntEQ(wc_SipHash(key, in, sizeof(in), NULL, SIPHASH_MAC_SIZE_8),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* outSz == 7 (neither 8 nor 16): c4 && c5 both true.
     * - vs the baseline (outSz==8): c5 held true, c4 toggles
     *   false->true, result toggles 0 -> BAD_FUNC_ARG (isolates c4).
     */
    ExpectIntEQ(wc_SipHash(key, in, sizeof(in), out, 7),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* outSz == 16: c4 true, c5 false (c4 && c5 false) -- a valid,
     * successful call. Paired against the outSz==7 case above: c4 held
     * true, c5 toggles true->false, result toggles BAD_FUNC_ARG -> 0
     * (isolates c5). */
    ExpectIntEQ(wc_SipHash(key, in, sizeof(in), out, SIPHASH_MAC_SIZE_16), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Positive/streaming coverage: wc_InitSipHash() -> one or more
 * wc_SipHashUpdate() calls (including multi-chunk input that crosses the
 * 8-byte block boundary and input that is an exact multiple of the block
 * size) -> wc_SipHashFinal(), cross-checked against the one-shot
 * wc_SipHash() API on the same key/message, for both the 8-byte and
 * 16-byte MAC output sizes that SipHash supports.
 */
int test_wc_SipHash_FeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_SIPHASH
    SipHash sipHash;
    byte key[SIPHASH_KEY_SIZE];
    byte msg[20];
    byte blockMsg[24];
    byte streamed8[SIPHASH_MAC_SIZE_8];
    byte oneshot8[SIPHASH_MAC_SIZE_8];
    byte streamed16[SIPHASH_MAC_SIZE_16];
    byte oneshot16[SIPHASH_MAC_SIZE_16];
    byte streamedBlock[SIPHASH_MAC_SIZE_8];
    byte oneshotBlock[SIPHASH_MAC_SIZE_8];
    byte emptyStreamed8[SIPHASH_MAC_SIZE_8];
    byte emptyOneshot8[SIPHASH_MAC_SIZE_8];
    byte emptyStreamed16[SIPHASH_MAC_SIZE_16];
    byte emptyOneshot16[SIPHASH_MAC_SIZE_16];
    int i;

    XMEMSET(&sipHash, 0, sizeof(sipHash));
    XMEMSET(key, 0, sizeof(key));
    XMEMSET(msg, 0, sizeof(msg));
    XMEMSET(blockMsg, 0, sizeof(blockMsg));
    XMEMSET(streamed8, 0, sizeof(streamed8));
    XMEMSET(oneshot8, 0, sizeof(oneshot8));
    XMEMSET(streamed16, 0, sizeof(streamed16));
    XMEMSET(oneshot16, 0, sizeof(oneshot16));
    XMEMSET(streamedBlock, 0, sizeof(streamedBlock));
    XMEMSET(oneshotBlock, 0, sizeof(oneshotBlock));
    XMEMSET(emptyStreamed8, 0, sizeof(emptyStreamed8));
    XMEMSET(emptyOneshot8, 0, sizeof(emptyOneshot8));
    XMEMSET(emptyStreamed16, 0, sizeof(emptyStreamed16));
    XMEMSET(emptyOneshot16, 0, sizeof(emptyOneshot16));

    for (i = 0; i < (int)sizeof(key); i++) {
        key[i] = (byte)(i * 3 + 1);
    }
    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (byte)i;
    }
    for (i = 0; i < (int)sizeof(blockMsg); i++) {
        blockMsg[i] = (byte)(i + 0x40);
    }

    /* Streaming, 8-byte MAC: three Update() calls (3 + 8 + 9 bytes) that
     * cross the 8-byte block boundary via the cache-fill-then-flush
     * path, cross-checked against the one-shot API on the same
     * message. */
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, msg, 3), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, msg + 3, 8), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, msg + 11, 9), 0);
    ExpectIntEQ(wc_SipHashFinal(&sipHash, streamed8, SIPHASH_MAC_SIZE_8), 0);
    ExpectIntEQ(wc_SipHash(key, msg, sizeof(msg), oneshot8,
        SIPHASH_MAC_SIZE_8), 0);
    ExpectBufEQ(streamed8, oneshot8, SIPHASH_MAC_SIZE_8);

    /* Streaming, 16-byte MAC: same message with a different chunking (7
     * + 13 bytes) and output size, to exercise the two-half SipHashOut()
     * path in wc_SipHashFinal(). */
    XMEMSET(&sipHash, 0, sizeof(sipHash));
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_16), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, msg, 7), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, msg + 7, 13), 0);
    ExpectIntEQ(wc_SipHashFinal(&sipHash, streamed16, SIPHASH_MAC_SIZE_16),
        0);
    ExpectIntEQ(wc_SipHash(key, msg, sizeof(msg), oneshot16,
        SIPHASH_MAC_SIZE_16), 0);
    ExpectBufEQ(streamed16, oneshot16, SIPHASH_MAC_SIZE_16);

    /* Streaming with input that is an exact multiple of the block size,
     * supplied in a single Update() call with an empty cache on entry:
     * drives wc_SipHashUpdate()'s direct block-processing loop rather
     * than the cache path, leaving no bytes cached on return. */
    XMEMSET(&sipHash, 0, sizeof(sipHash));
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, blockMsg, sizeof(blockMsg)), 0);
    ExpectIntEQ(wc_SipHashFinal(&sipHash, streamedBlock, SIPHASH_MAC_SIZE_8),
        0);
    ExpectIntEQ(wc_SipHash(key, blockMsg, sizeof(blockMsg), oneshotBlock,
        SIPHASH_MAC_SIZE_8), 0);
    ExpectBufEQ(streamedBlock, oneshotBlock, SIPHASH_MAC_SIZE_8);

    /* Empty message via both APIs, both MAC sizes: wc_SipHashUpdate()
     * accepts a NULL/zero-length update as a legitimate no-op. */
    XMEMSET(&sipHash, 0, sizeof(sipHash));
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_8), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, NULL, 0), 0);
    ExpectIntEQ(wc_SipHashFinal(&sipHash, emptyStreamed8, SIPHASH_MAC_SIZE_8),
        0);
    ExpectIntEQ(wc_SipHash(key, NULL, 0, emptyOneshot8, SIPHASH_MAC_SIZE_8),
        0);
    ExpectBufEQ(emptyStreamed8, emptyOneshot8, SIPHASH_MAC_SIZE_8);

    XMEMSET(&sipHash, 0, sizeof(sipHash));
    ExpectIntEQ(wc_InitSipHash(&sipHash, key, SIPHASH_MAC_SIZE_16), 0);
    ExpectIntEQ(wc_SipHashUpdate(&sipHash, NULL, 0), 0);
    ExpectIntEQ(wc_SipHashFinal(&sipHash, emptyStreamed16,
        SIPHASH_MAC_SIZE_16), 0);
    ExpectIntEQ(wc_SipHash(key, NULL, 0, emptyOneshot16,
        SIPHASH_MAC_SIZE_16), 0);
    ExpectBufEQ(emptyStreamed16, emptyOneshot16, SIPHASH_MAC_SIZE_16);
#endif
    return EXPECT_RESULT();
}
