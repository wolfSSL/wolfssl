/* mcdc_der_edit.h
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
 * mcdc_der_edit.h -- structural DER edits for the per-module MC/DC suite.
 *
 * PURPOSE
 * -------
 * Several asn.c decisions are only reachable when a *nested* ASN.1 item has a
 * length the encoder would never produce -- for example a validity UTCTime
 * whose length is below MIN_DATE_SIZE, which is what makes CheckDate() fail
 * for a structural reason rather than because the date is out of range. (The
 * out-of-range failure is suppressed by AsnSkipDateCheck, so it cannot drive
 * the operands that sit *inside* the `if (CheckDate(...) < 0)` body.)
 *
 * Producing that shape by patching bytes in place is not possible: changing an
 * item's length invalidates every enclosing SEQUENCE length. This header does
 * the fixup. It walks the encoding from the root, collects the chain of items
 * whose content contains the edit point, applies the size delta to each of
 * their length fields, and then moves the bytes.
 *
 * SCOPE AND DELIBERATE LIMITS
 * ---------------------------
 *  - Single-byte tags only (no high-tag-number form). Every tag in a
 *    certificate, CRL or attribute certificate is single-byte.
 *  - Definite lengths only. BER indefinite lengths have no length field to fix.
 *  - The length encoding must keep the same width after the edit (a content
 *    length crossing 127, 255, 65535 ... would need the header itself to grow,
 *    which would move the edit point). This is reported as a failure rather
 *    than handled, so a fixture that trips it fails loudly instead of
 *    producing a subtly wrong buffer.
 *  - Signatures are invalidated by construction. Every caller must therefore
 *    be a parse path, not a verify path.
 *
 * USAGE
 *     byte buf[4096];
 *     word32 sz = <original size>;
 *     XMEMCPY(buf, orig, sz);
 *     if (mcdc_der_shrink(buf, &sz, at, 2) == 0) { ...parse buf... }
 */

#ifndef MCDC_DER_EDIT_H
#define MCDC_DER_EDIT_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#define MCDC_DER_MAX_DEPTH 24

/* Decode the TLV header at `off`.
 *
 * @param [out] contentOff  Offset of the item's content.
 * @param [out] contentLen  Length of the item's content.
 * @param [out] lenOff      Offset of the item's length field.
 * @param [out] lenWidth    Number of bytes the length field occupies.
 * @return  Header size in bytes, or 0 when the header is malformed or the
 *          item runs past the end of the buffer.
 */
static word32 mcdc_der_hdr(const byte* der, word32 sz, word32 off,
        word32* contentOff, word32* contentLen, word32* lenOff,
        word32* lenWidth)
{
    word32 i = off;
    word32 len;
    word32 lo;
    word32 lw;

    if ((der == NULL) || (off + 2U > sz)) {
        return 0;
    }
    i++;                                        /* single-byte tag */
    lo = i;
    if (der[i] < 0x80U) {
        len = der[i];
        lw = 1;
        i++;
    }
    else {
        word32 n = (word32)(der[i] & 0x7FU);
        i++;
        if ((n == 0U) || (n > 4U) || (i + n > sz)) {
            return 0;                           /* indefinite or absurd */
        }
        lw = n + 1U;
        len = 0;
        while (n-- > 0U) {
            len = (len << 8) | der[i];
            i++;
        }
    }
    if (i + len > sz) {
        return 0;
    }
    *contentOff = i;
    *contentLen = len;
    *lenOff = lo;
    *lenWidth = lw;
    return i - off;
}

/* Rewrite the length field at `lenOff`/`lenWidth` to `len`, refusing to change
 * the encoding width. Returns 0 on success. */
static int mcdc_der_setlen(byte* der, word32 lenOff, word32 lenWidth,
        word32 len)
{
    if (lenWidth == 1U) {
        if (len > 0x7FU) {
            return -1;
        }
        der[lenOff] = (byte)len;
    }
    else {
        word32 n = lenWidth - 1U;
        word32 i;
        /* The value must still need exactly n bytes. */
        if ((n < 4U) && (len >= (1U << (8U * n)))) {
            return -1;
        }
        for (i = 0; i < n; i++) {
            der[lenOff + n - i] = (byte)(len >> (8U * i));
        }
    }
    return 0;
}

/* Collect, from the root, the chain of items whose content contains `at`.
 * Descends into constructed items only; a primitive item whose content
 * contains `at` terminates the chain and is included in it.
 *
 * @return  Number of items collected, or -1 when `at` is not inside the
 *          encoding or the encoding is malformed.
 */
static int mcdc_der_chain(const byte* der, word32 sz, word32 at,
        word32* chain, int maxChain)
{
    word32 off = 0;
    int n = 0;

    for (;;) {
        word32 co, cl, lo, lw, hs;
        word32 c;
        int descend = -1;

        hs = mcdc_der_hdr(der, sz, off, &co, &cl, &lo, &lw);
        if (hs == 0) {
            return -1;
        }
        if ((at < co) || (at > co + cl)) {
            return -1;
        }
        if (n == maxChain) {
            return -1;
        }
        chain[n++] = off;

        if ((der[off] & ASN_CONSTRUCTED) == 0) {
            break;                              /* primitive leaf */
        }
        /* Find the child that strictly contains `at`. A hit exactly on a
         * child boundary means the edit belongs to this level. */
        c = co;
        while (c < co + cl) {
            word32 cco, ccl, clo, clw, chs;
            chs = mcdc_der_hdr(der, sz, c, &cco, &ccl, &clo, &clw);
            if (chs == 0) {
                return -1;
            }
            if ((at > c) && (at < cco + ccl)) {
                descend = 0;
                off = c;
                break;
            }
            c = cco + ccl;
        }
        if (descend != 0) {
            break;
        }
    }
    return n;
}

/* Apply a size delta at `at` to every enclosing item's length field. */
static int mcdc_der_relength(byte* der, word32 sz, word32 at, int delta)
{
    word32 chain[MCDC_DER_MAX_DEPTH];
    int n;
    int i;

    n = mcdc_der_chain(der, sz, at, chain, MCDC_DER_MAX_DEPTH);
    if (n <= 0) {
        return -1;
    }
    /* Check every length first so a refusal leaves the buffer untouched. */
    for (i = 0; i < n; i++) {
        word32 co, cl, lo, lw;
        if (mcdc_der_hdr(der, sz, chain[i], &co, &cl, &lo, &lw) == 0) {
            return -1;
        }
        if ((delta < 0) && (cl < (word32)(-delta))) {
            return -1;
        }
        if (mcdc_der_setlen(der, lo, lw, (word32)((int)cl + delta)) != 0) {
            /* Undo the ones already written. On the grow path the widened
             * outer lengths can make mcdc_der_hdr() fail its bounds check,
             * which leaves its outputs unset - skip those rather than write
             * at an uninitialised offset. */
            while (--i >= 0) {
                word32 co2, cl2, lo2, lw2;
                if (mcdc_der_hdr(der, sz, chain[i], &co2, &cl2, &lo2,
                        &lw2) == 0) {
                    continue;
                }
                (void)mcdc_der_setlen(der, lo2, lw2,
                        (word32)((int)cl2 - delta));
            }
            return -1;
        }
    }
    return 0;
}

/* Remove `n` bytes starting at `at`, shrinking every enclosing item.
 * Returns 0 on success and leaves *sz updated. */
static int mcdc_der_shrink(byte* der, word32* sz, word32 at, word32 n)
{
    if ((der == NULL) || (sz == NULL) || (n == 0U) || (at + n > *sz)) {
        return -1;
    }
    if (mcdc_der_relength(der, *sz, at, -(int)n) != 0) {
        return -1;
    }
    XMEMMOVE(der + at, der + at + n, (size_t)(*sz - at - n));
    *sz -= n;
    return 0;
}

/* Insert `n` bytes from `ins` at `at`, growing every enclosing item.
 * `cap` is the capacity of `der`. Returns 0 on success. */
static int mcdc_der_grow(byte* der, word32* sz, word32 cap, word32 at,
        const byte* ins, word32 n)
{
    if ((der == NULL) || (sz == NULL) || (n == 0U) || (at > *sz) ||
            (*sz + n > cap)) {
        return -1;
    }
    if (mcdc_der_relength(der, *sz, at, (int)n) != 0) {
        return -1;
    }
    XMEMMOVE(der + at + n, der + at, (size_t)(*sz - at));
    XMEMCPY(der + at, ins, n);
    *sz += n;
    return 0;
}

/* Offset of the first item with the given tag and content length, searched
 * linearly over the encoding. Returns the item's offset, or 0 when absent
 * (offset 0 is always the outer SEQUENCE, so it is never a valid hit). */
static word32 mcdc_der_find(const byte* der, word32 sz, byte tag,
        word32 contentLen)
{
    word32 i;

    for (i = 1; i + 2U <= sz; i++) {
        word32 co, cl, lo, lw;
        if (der[i] != tag) {
            continue;
        }
        if (mcdc_der_hdr(der, sz, i, &co, &cl, &lo, &lw) == 0) {
            continue;
        }
        if (cl == contentLen) {
            return i;
        }
    }
    return 0;
}

#endif /* MCDC_DER_EDIT_H */
