/* argon2.c
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

/* Implementation of the Argon2 memory-hard password hashing function as
 * specified in RFC 9106, "Argon2 Memory-Hard Function for Password Hashing
 * and Proof-of-Work Applications". All three variants are supported:
 * Argon2d, Argon2i and Argon2id.
 *
 * Only version number 0x13 is implemented. The earlier 0x10 encoding differs
 * in that a pass r > 0 overwrites a block rather than XOR-ing into it. It is
 * superseded and is deliberately not offered here.
 *
 * Notation follows the RFC:
 *   p  - degree of parallelism, the number of lanes.
 *   m  - requested memory size in KiB.
 *   m' - memory size in 1 KiB blocks after rounding down to equal segments.
 *   q  - blocks per lane, m' / p. Also called the lane length.
 *   t  - number of passes over the memory.
 *   T  - tag (output) length in bytes.
 *   B[i][j] - block j of lane i.
 *
 * Each pass is split into 4 slices, giving 4 * p segments per pass. The
 * segments of one slice are independent of one another, so they may be filled
 * at the same time. Built with WOLFSSL_ARGON2_THREADS, wc_Argon2SetThreads()
 * spreads them over that many threads, joining at every slice boundary;
 * without it, or at a thread count of 1, they are filled one after another.
 * Those slice boundaries are the synchronization points the RFC requires, and
 * they make the result identical either way: the tag never depends on how
 * many threads produced it.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_ARGON2

#include <wolfssl/wolfcrypt/argon2.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef HAVE_BLAKE2B
    #error "Argon2 requires BLAKE2b - build with --enable-blake2"
#endif

#ifndef WORD64_AVAILABLE
    #error "Argon2 requires 64-bit word support"
#endif

/* Length in bytes of H0, the pre-hash digest of RFC 9106 section 3.2. */
#define ARGON2_PREHASH_LEN          64
/* Length in bytes of the seed H0 || LE32(j) || LE32(lane) that is hashed to
 * produce the first two blocks of each lane. */
#define ARGON2_PREHASH_SEED_LEN     (ARGON2_PREHASH_LEN + 8)

/* Number of pseudo-random values one Argon2i address block holds. */
#define ARGON2_ADDRESSES_IN_BLOCK   WC_ARGON2_WORDS_IN_BLOCK

/* Number of 64-bit words in a row of a block when treated as an 8x8 matrix
 * of 16-byte cells. */
#define ARGON2_WORDS_IN_ROW         16

/* Number of rows, and of columns, when a block is treated as a matrix. */
#define ARGON2_MATRIX_DIM           8

/* Indexes of the working scratch blocks. Each worker has its own set, so
 * that the segments of a slice can be filled at the same time. */
#define ARGON2_SCRATCH_R            0
#define ARGON2_SCRATCH_TMP          1
#define ARGON2_SCRATCH_ADDR         2
#define ARGON2_SCRATCH_INPUT        3
#define ARGON2_SCRATCH_ZERO         4
/* Number of scratch blocks one worker needs. */
#define ARGON2_SCRATCH_BLOCKS       5

/* Get one of a worker's scratch blocks.
 *
 * @param [in] w  Worker filling a segment.
 * @param [in] n  Index of the scratch block, an ARGON2_SCRATCH_* value.
 *
 * @return  Address of the scratch block.
 */
#define ARGON2_SCRATCH(w, n)        (&(w)->scratch[n])



/* Store a 32-bit value into a byte array in little-endian order.
 *
 * @param [out] out  Byte array of at least 4 bytes.
 * @param [in]  v    Value to store.
 */
static WC_INLINE void Argon2Store32(byte* out, word32 v)
{
    out[0] = (byte)( v        & 0xff);
    out[1] = (byte)((v >>  8) & 0xff);
    out[2] = (byte)((v >> 16) & 0xff);
    out[3] = (byte)((v >> 24) & 0xff);
}

#ifdef BIG_ENDIAN_ORDER
/* Convert a block between its little-endian byte form and host word order.
 *
 * Blocks are hashed as little-endian byte strings but computed on as native
 * 64-bit words. The conversion is its own inverse. On a little-endian target
 * the two forms are the same bytes and this is compiled out.
 *
 * @param [in, out] b  Block to byte swap in place.
 */
static void Argon2BlockSwap(Argon2Block* b)
{
    word32 i;

    for (i = 0; i < WC_ARGON2_WORDS_IN_BLOCK; i++) {
        b->v[i] = ByteReverseWord64(b->v[i]);
    }
}
#else
/* Byte swapping a block is not required on a little-endian target.
 *
 * @param [in, out] b  Block that would be byte swapped.
 */
#define Argon2BlockSwap(b) WC_DO_NOTHING
#endif


/* Hash a message with BLAKE2b.
 *
 * out may be the same buffer as in: the message is fully absorbed by the
 * update before the final writes the digest.
 *
 * Algorithm:
 *  1. Initialize the state for a digest of outSz bytes
 *  2. Absorb the message
 *  3. Write the digest to out
 *
 * @param [in]  b2b    BLAKE2b state to use as scratch.
 * @param [out] out    Buffer to hold the digest.
 * @param [in]  outSz  Length of digest to produce in bytes, at most 64.
 * @param [in]  in     Message to hash.
 * @param [in]  inSz   Length of message in bytes.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2Blake2b(Blake2b* b2b, byte* out, word32 outSz,
    const byte* in, word32 inSz)
{
    int ret;

    /* 1. Initialize the state for a digest of outSz bytes. */
    ret = wc_InitBlake2b(b2b, outSz);
    /* 2. Absorb the message. */
    if (ret == 0) {
        ret = wc_Blake2bUpdate(b2b, in, inSz);
    }
    /* 3. Write the digest to out. */
    if (ret == 0) {
        ret = wc_Blake2bFinal(b2b, out, outSz);
    }

    return ret;
}

/* Hash a 32-bit length and then a message with BLAKE2b.
 *
 * The length hashed is not necessarily the length of this digest: H' prefixes
 * the total requested output length to every hash in its chain, whatever the
 * size of the individual digest.
 *
 * Algorithm:
 *  1. Initialize the state for a digest of outSz bytes
 *  2. Absorb len as a little-endian 32-bit value
 *  3. Absorb the message
 *  4. Write the digest to out
 *
 * @param [in]  b2b    BLAKE2b state to use as scratch.
 * @param [out] out    Buffer to hold the digest.
 * @param [in]  outSz  Length of digest to produce in bytes, at most 64.
 * @param [in]  len    Value to hash ahead of the message.
 * @param [in]  in     Message to hash.
 * @param [in]  inSz   Length of message in bytes.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2Blake2bLen(Blake2b* b2b, byte* out, word32 outSz, word32 len,
    const byte* in, word32 inSz)
{
    byte lenBytes[4];
    int  ret;

    Argon2Store32(lenBytes, len);

    /* 1. Initialize the state for a digest of outSz bytes. */
    ret = wc_InitBlake2b(b2b, outSz);
    /* 2. Absorb len as a little-endian 32-bit value. */
    if (ret == 0) {
        ret = wc_Blake2bUpdate(b2b, lenBytes, (word32)sizeof(lenBytes));
    }
    /* 3. Absorb the message. */
    if (ret == 0) {
        ret = wc_Blake2bUpdate(b2b, in, inSz);
    }
    /* 4. Write the digest to out. */
    if (ret == 0) {
        ret = wc_Blake2bFinal(b2b, out, outSz);
    }

    return ret;
}

/* Variable length hash function H' of RFC 9106 section 3.3.
 *
 * Produces an arbitrary length digest from BLAKE2b, whose own output is at
 * most 64 bytes. Up to 64 bytes the length is simply prefixed to the message.
 * Beyond that, a chain of 64-byte digests is computed and the first 32 bytes
 * of each is emitted, with the last digest emitted whole.
 *
 * Algorithm:
 *  1. If T <= 64 then H'(X) = BLAKE2b-T(LE32(T) || X)
 *  2. Otherwise:
 *   2.1. V1 = BLAKE2b-64(LE32(T) || X)
 *   2.2. Vi = BLAKE2b-64(V(i-1)) for each subsequent digest
 *   2.3. Emit the first 32 bytes of each Vi while more than 64 bytes remain
 *   2.4. Emit the final digest, of the remaining length, whole
 *
 * @param [in]  b2b    BLAKE2b state to use as scratch.
 * @param [out] out    Buffer to hold the digest.
 * @param [in]  outSz  Length of digest to produce in bytes.
 * @param [in]  in     Message to hash.
 * @param [in]  inSz   Length of message in bytes.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2HashLong(Blake2b* b2b, byte* out, word32 outSz,
    const byte* in, word32 inSz)
{
    byte   buf[64];
    word32 toProduce;
    int    ret;

    /* 1. If T <= 64 then H'(X) = BLAKE2b-T(LE32(T) || X). buf is untouched on
     * this path, so it is registered below rather than here. */
    if (outSz <= 64) {
        return Argon2Blake2bLen(b2b, out, outSz, outSz, in, inSz);
    }

#ifdef WOLFSSL_CHECK_MEM_ZERO
    /* Poison so that a path which leaves without wiping is caught. */
    XMEMSET(buf, 0xff, sizeof(buf));
    wc_MemZero_Add("Argon2HashLong buf", buf, sizeof(buf));
#endif

    /* 2.1. V1 = BLAKE2b-64(LE32(T) || X) */
    ret = Argon2Blake2bLen(b2b, buf, 64, outSz, in, inSz);
    if (ret == 0) {
        /* 2.3. Emit the first 32 bytes of V1. */
        XMEMCPY(out, buf, 32);
        out += 32;
        toProduce = outSz - 32;

        while ((ret == 0) && (toProduce > 64)) {
            /* 2.2. Vi = BLAKE2b-64(V(i-1)) */
            ret = Argon2Blake2b(b2b, buf, 64, buf, 64);
            if (ret != 0)
                break;

            /* 2.3. Emit the first 32 bytes of Vi. */
            XMEMCPY(out, buf, 32);
            out += 32;
            toProduce -= 32;
        }

        /* 2.4. Emit the final digest, of the remaining length, whole. */
        if (ret == 0) {
            ret = Argon2Blake2b(b2b, out, toProduce, buf, 64);
        }
    }

    /* buf held digest material on every path that reaches here. */
    ForceZero(buf, sizeof(buf));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(buf, sizeof(buf));
#endif

    return ret;
}


/* Latin square operation fBlaMka of RFC 9106 section 3.4.1.
 *
 * A 64-bit addition with the 64-bit product of the low halves of the two
 * operands folded in twice. The multiplication is what makes the round
 * non-linear, and is the reason a time-memory trade-off is expensive.
 *
 * Computes x + y + 2 * lo32(x) * lo32(y), modulo 2^64.
 *
 * @param [in] x  First operand.
 * @param [in] y  Second operand.
 *
 * @return  The combined value.
 */
#define ARGON2_FBLAMKA(x, y)                                               \
    ((x) + (y) + 2 * (((x) & W64LIT(0xffffffff)) *                         \
        ((y) & W64LIT(0xffffffff))))

/* Quarter-round G of the BLAKE2b permutation, with fBlaMka in place of the
 * plain modular addition. RFC 9106 section 3.4.1.
 *
 * Algorithm:
 *  1. a = fBlaMka(a, b), d = (d XOR a) >>> 32
 *  2. c = fBlaMka(c, d), b = (b XOR c) >>> 24
 *  3. a = fBlaMka(a, b), d = (d XOR a) >>> 16
 *  4. c = fBlaMka(c, d), b = (b XOR c) >>> 63
 *
 * @param [in, out] a  First word.
 * @param [in, out] b  Second word.
 * @param [in, out] c  Third word.
 * @param [in, out] d  Fourth word.
 */
#define ARGON2_G(a, b, c, d)                                               \
    do {                                                                   \
        /* 1. a = fBlaMka(a, b), d = (d XOR a) >>> 32 */                   \
        (a) = ARGON2_FBLAMKA((a), (b));                                    \
        (d) = rotrFixed64((d) ^ (a), 32);                                  \
        /* 2. c = fBlaMka(c, d), b = (b XOR c) >>> 24 */                   \
        (c) = ARGON2_FBLAMKA((c), (d));                                    \
        (b) = rotrFixed64((b) ^ (c), 24);                                  \
        /* 3. a = fBlaMka(a, b), d = (d XOR a) >>> 16 */                   \
        (a) = ARGON2_FBLAMKA((a), (b));                                    \
        (d) = rotrFixed64((d) ^ (a), 16);                                  \
        /* 4. c = fBlaMka(c, d), b = (b XOR c) >>> 63 */                   \
        (c) = ARGON2_FBLAMKA((c), (d));                                    \
        (b) = rotrFixed64((b) ^ (c), 63);                                  \
    } while (0)

/* Permutation P of RFC 9106 section 3.4.1, applied to 16 words.
 *
 * The BLAKE2b round with no message input: four applications of G down the
 * columns of the 4x4 arrangement of the words, then four along its
 * diagonals.
 *
 * Algorithm:
 *  1. Columns: G on (v0,v4,v8,v12), (v1,v5,v9,v13), (v2,v6,v10,v14),
 *     (v3,v7,v11,v15)
 *  2. Diagonals: G on (v0,v5,v10,v15), (v1,v6,v11,v12), (v2,v7,v8,v13),
 *     (v3,v4,v9,v14)
 *
 * @param [in, out] v0   First word.
 * @param [in, out] v1   Second word.
 * @param [in, out] v2   Third word.
 * @param [in, out] v3   Fourth word.
 * @param [in, out] v4   Fifth word.
 * @param [in, out] v5   Sixth word.
 * @param [in, out] v6   Seventh word.
 * @param [in, out] v7   Eighth word.
 * @param [in, out] v8   Ninth word.
 * @param [in, out] v9   Tenth word.
 * @param [in, out] v10  Eleventh word.
 * @param [in, out] v11  Twelfth word.
 * @param [in, out] v12  Thirteenth word.
 * @param [in, out] v13  Fourteenth word.
 * @param [in, out] v14  Fifteenth word.
 * @param [in, out] v15  Sixteenth word.
 */
#define ARGON2_ROUND(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,     \
    v12, v13, v14, v15)                                                    \
    do {                                                                   \
        /* 1. Columns. */                                                  \
        ARGON2_G(v0, v4,  v8, v12);                                        \
        ARGON2_G(v1, v5,  v9, v13);                                        \
        ARGON2_G(v2, v6, v10, v14);                                        \
        ARGON2_G(v3, v7, v11, v15);                                        \
        /* 2. Diagonals. */                                                \
        ARGON2_G(v0, v5, v10, v15);                                        \
        ARGON2_G(v1, v6, v11, v12);                                        \
        ARGON2_G(v2, v7,  v8, v13);                                        \
        ARGON2_G(v3, v4,  v9, v14);                                        \
    } while (0)

/* Compression function G of RFC 9106 section 3.4.1.
 *
 * Computes next = G(prev, ref), or next = G(prev, ref) XOR next when withXor
 * is set. Passes after the first XOR into the existing block, which is the
 * behaviour that distinguishes version 0x13 from 0x10.
 *
 * The 1 KiB block is treated as an 8x8 matrix of 16-byte cells. The
 * permutation P is applied to each row and then to each column, which is what
 * diffuses every input word into every output word.
 *
 * next may alias ref: ref is fully consumed into the worker's R scratch block
 * before next is written. The Argon2i address generator relies on this.
 *
 * Algorithm:
 *  1. R = prev XOR ref
 *  2. Q = P applied to each of the 8 rows of R
 *  3. Z = P applied to each of the 8 columns of Q
 *  4. next = Z XOR R, and XOR the old next as well when withXor
 *
 * @param [in, out] w        Worker filling the segment, for its scratch
 *                           blocks.
 * @param [in]      prev     Previous block, B[i][j-1].
 * @param [in]      ref      Reference block, B[l][z].
 * @param [in, out] next     Block to write. Read as well when withXor is set.
 * @param [in]      withXor  Whether to XOR into next rather than overwrite.
 */
static void Argon2FillBlock(Argon2Worker* w, const Argon2Block* prev,
    const Argon2Block* ref, Argon2Block* next, int withXor)
{
    Argon2Block* r = ARGON2_SCRATCH(w, ARGON2_SCRATCH_R);
    Argon2Block* t = ARGON2_SCRATCH(w, ARGON2_SCRATCH_TMP);
    word32 i;

    /* 1. R = prev XOR ref, kept in t as well for step 4. */
    for (i = 0; i < WC_ARGON2_WORDS_IN_BLOCK; i++) {
        r->v[i] = ref->v[i] ^ prev->v[i];
        t->v[i] = r->v[i];
    }

    if (withXor) {
        for (i = 0; i < WC_ARGON2_WORDS_IN_BLOCK; i++) {
            t->v[i] ^= next->v[i];
        }
    }

    /* 2. Q = P applied to each of the 8 rows of R. */
    for (i = 0; i < ARGON2_MATRIX_DIM; i++) {
        word64* p = &r->v[ARGON2_WORDS_IN_ROW * i];

        ARGON2_ROUND(p[0], p[1], p[2],  p[3],  p[4],  p[5],  p[6],  p[7],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }

    /* 3. Z = P applied to each of the 8 columns of Q. A column is a pair of
     * adjacent words taken from every row. */
    for (i = 0; i < ARGON2_MATRIX_DIM; i++) {
        word64* p = &r->v[2 * i];

        ARGON2_ROUND(p[0], p[1], p[16], p[17], p[32], p[33], p[48], p[49],
            p[64], p[65], p[80], p[81], p[96], p[97], p[112], p[113]);
    }

    /* 4. next = Z XOR R, with the old next folded in when withXor. */
    for (i = 0; i < WC_ARGON2_WORDS_IN_BLOCK; i++) {
        next->v[i] = t->v[i] ^ r->v[i];
    }
}


/* Map a pseudo-random value to the index of a reference block within a lane.
 * RFC 9106 section 3.4.1.2.
 *
 * The set of blocks that may be referenced, W, is everything finished so far
 * in the chosen lane, excluding the immediately preceding block. Its size
 * depends on whether this is the first pass and whether the chosen lane is
 * the one being filled. The mapping onto W is quadratic, which biases the
 * choice towards recently computed blocks.
 *
 * Algorithm:
 *  1. Compute |W|, the number of blocks that may be referenced:
 *   1.1. Pass 0, slice 0: only this segment exists, so index - 1
 *   1.2. Pass 0, same lane: slice * segmentLength + index - 1
 *   1.3. Pass 0, other lane: slice * segmentLength, less 1 at a segment start
 *   1.4. Later pass, same lane: q - segmentLength + index - 1
 *   1.5. Later pass, other lane: q - segmentLength, less 1 at a segment start
 *  2. x = J1 * J1 / 2^32
 *  3. y = |W| * x / 2^32
 *  4. zz = |W| - 1 - y
 *  5. start = 0 on pass 0, otherwise the block after this slice
 *  6. Return (start + zz) mod q
 *
 * @param [in] a           Argon2 context.
 * @param [in] pos         Position of the block being computed.
 * @param [in] pseudoRand  J1, the low 32 bits of the pseudo-random value.
 * @param [in] sameLane    Whether the reference lane is the current lane.
 *
 * @return  Index of the reference block within its lane.
 */
static word32 Argon2IndexAlpha(const Argon2Ctx* a, const Argon2Pos* pos,
    word32 pseudoRand, int sameLane)
{
    word64 refAreaSize;
    word64 relPos;
    word32 startPos;

    /* 1. Compute |W|, the number of blocks that may be referenced. */
    if (pos->pass == 0) {
        if (pos->slice == 0) {
            /* 1.1. Pass 0, slice 0: only this segment exists. */
            refAreaSize = pos->index - 1;
        }
        else if (sameLane) {
            /* 1.2. Pass 0, same lane: finished slices plus this segment. */
            refAreaSize = (word64)pos->slice * a->segmentLength +
                pos->index - 1;
        }
        else {
            /* 1.3. Pass 0, other lane: its finished slices only, and the
             * very last of those is off limits at a segment start. */
            refAreaSize = (word64)pos->slice * a->segmentLength -
                ((pos->index == 0) ? 1 : 0);
        }
    }
    else if (sameLane) {
        /* 1.4. Later pass, same lane. */
        refAreaSize = (word64)a->laneLength - a->segmentLength + pos->index - 1;
    }
    else {
        /* 1.5. Later pass, other lane. */
        refAreaSize = (word64)a->laneLength - a->segmentLength -
            ((pos->index == 0) ? 1 : 0);
    }

    /* 2. x = J1 * J1 / 2^32 */
    relPos = pseudoRand;
    relPos = (relPos * relPos) >> 32;
    /* 3. y = |W| * x / 2^32, and 4. zz = |W| - 1 - y */
    relPos = refAreaSize - 1 - ((refAreaSize * relPos) >> 32);

    /* 5. start = 0 on pass 0, otherwise the block after this slice. */
    startPos = 0;
    if (pos->pass != 0) {
        startPos = (pos->slice == WC_ARGON2_SYNC_POINTS - 1) ?
            0 : (pos->slice + 1) * a->segmentLength;
    }

    /* 6. Return (start + zz) mod q. */
    return (word32)((startPos + relPos) % a->laneLength);
}

/* Generate the next block of Argon2i addresses. RFC 9106 section 3.4.1.1.
 *
 * Argon2i must not let the reference index depend on the password, so the
 * addresses are produced by running the compression function over a counter
 * block instead of over the previous memory block. Two applications of G are
 * used so that the addresses are as well distributed as memory contents.
 *
 * Algorithm:
 *  1. Increment the counter in word 6 of the input block
 *  2. addr = G(ZERO, input)
 *  3. addr = G(ZERO, addr)
 *
 * @param [in, out] w    Worker filling the segment, holding the input and
 *                       address blocks.
 */
static void Argon2NextAddresses(Argon2Worker* w)
{
    Argon2Block* zero = ARGON2_SCRATCH(w, ARGON2_SCRATCH_ZERO);
    Argon2Block* input = ARGON2_SCRATCH(w, ARGON2_SCRATCH_INPUT);
    Argon2Block* addr = ARGON2_SCRATCH(w, ARGON2_SCRATCH_ADDR);

    /* 1. Increment the counter in word 6 of the input block. */
    input->v[6]++;
    /* 2. addr = G(ZERO, input) */
    Argon2FillBlock(w, zero, input, addr, 0);
    /* 3. addr = G(ZERO, addr) */
    Argon2FillBlock(w, zero, addr, addr, 0);
}

/* Fill one segment: the part of one lane that lies within one slice.
 * RFC 9106 section 3.4.
 *
 * Argon2d takes the reference index from the previous block, which is fast
 * but leaks memory access patterns. Argon2i takes it from a generated
 * address block, which is data independent. Argon2id uses the Argon2i rule
 * for the first half of the first pass and the Argon2d rule thereafter.
 *
 * Algorithm:
 *  1. Decide between data-independent and data-dependent addressing
 *  2. For data-independent addressing, set up the address generator input
 *  3. Skip the two blocks already seeded from H0 when in pass 0, slice 0
 *  4. For each remaining index j in the segment:
 *   4.1. Take the pseudo-random value J1 | J2, regenerating the address
 *        block every 128 indices when addressing is data independent
 *   4.2. l = J2 mod p, except in pass 0 slice 0 where it is the current lane
 *   4.3. z = index of the reference block within lane l
 *   4.4. B[i][j] = G(B[i][j-1], B[l][z]), XOR-ing into B[i][j] when pass > 0
 *
 * @param [in, out] w  Worker holding the context and the position of the
 *                     segment to fill.
 */
static void Argon2FillSegment(Argon2Worker* w)
{
    Argon2Ctx* a = w->a;
    Argon2Pos pos = w->pos;
    word64 pseudoRand;
    word32 refIndex, refLane;
    word32 prevOffset, currOffset;
    word32 startingIndex;
    word32 i;
    int    dataIndependent;

    /* 1. Decide between data-independent and data-dependent addressing.
     * Argon2id is Argon2i for the first two slices of the first pass only. */
    dataIndependent = (a->type == WC_ARGON2_I) || ((a->type == WC_ARGON2_ID) &&
        (pos.pass == 0) && (pos.slice < WC_ARGON2_SYNC_POINTS / 2));

    /* 2. For data-independent addressing, set up the generator input. */
    if (dataIndependent) {
        Argon2Block* in = ARGON2_SCRATCH(w, ARGON2_SCRATCH_INPUT);

        XMEMSET(ARGON2_SCRATCH(w, ARGON2_SCRATCH_ZERO), 0,
            sizeof(Argon2Block));
        XMEMSET(in, 0, sizeof(Argon2Block));
        in->v[0] = pos.pass;
        in->v[1] = pos.lane;
        in->v[2] = pos.slice;
        in->v[3] = a->memoryBlocks;
        in->v[4] = a->passes;
        in->v[5] = (word64)a->type;
    }

    /* 3. Skip the two blocks already seeded from H0. */
    startingIndex = 0;
    if ((pos.pass == 0) && (pos.slice == 0)) {
        startingIndex = 2;
        if (dataIndependent) {
            Argon2NextAddresses(w);
        }
    }

    currOffset = pos.lane * a->laneLength +
        pos.slice * a->segmentLength + startingIndex;

    if (currOffset % a->laneLength == 0) {
        /* At the start of a lane the predecessor is its last block. */
        prevOffset = currOffset + a->laneLength - 1;
    }
    else {
        prevOffset = currOffset - 1;
    }

    /* 4. Compute each remaining block of the segment. */
    for (i = startingIndex; i < a->segmentLength;
         i++, currOffset++, prevOffset++) {
        if (currOffset % a->laneLength == 1) {
            prevOffset = currOffset - 1;
        }

        /* 4.1. Take the pseudo-random value J1 | J2. */
        if (dataIndependent) {
            if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                Argon2NextAddresses(w);
            }
            pseudoRand = ARGON2_SCRATCH(w, ARGON2_SCRATCH_ADDR)->v[
                i % ARGON2_ADDRESSES_IN_BLOCK];
        }
        else {
            pseudoRand = a->memory[prevOffset].v[0];
        }

        /* 4.2. l = J2 mod p. */
        refLane = (word32)((pseudoRand >> 32) % a->lanes);
        if ((pos.pass == 0) && (pos.slice == 0)) {
            /* No other lane has produced anything to reference yet. */
            refLane = pos.lane;
        }

        /* 4.3. z = index of the reference block within lane l. */
        pos.index = i;
        refIndex = Argon2IndexAlpha(a, &pos,
            (word32)(pseudoRand & 0xffffffffU), refLane == pos.lane);

        /* 4.4. B[i][j] = G(B[i][j-1], B[l][z]). */
        Argon2FillBlock(w, &a->memory[prevOffset],
            &a->memory[(size_t)refLane * a->laneLength + refIndex],
            &a->memory[currOffset], pos.pass != 0);
    }
}


#ifdef WOLFSSL_ARGON2_THREADS
/* Thread entry point: fill the one segment described by the worker.
 *
 * Nothing is returned: a segment fill cannot fail, so there is no error to
 * propagate back to the thread that joins this one.
 *
 * @param [in, out] arg  Argon2Worker for the segment to fill.
 *
 * @return  0 always, through the platform's thread return convention.
 */
static THREAD_RETURN WOLFSSL_THREAD Argon2SegmentThread(void* arg)
{
    Argon2FillSegment((Argon2Worker*)arg);

    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif /* WOLFSSL_ARGON2_THREADS */

/* Fill every segment of one slice.
 *
 * The p segments of a slice are independent of one another, so they may be
 * filled at the same time. Each worker has its own scratch blocks and writes
 * only to the blocks of its own segment, so no locking is needed; the join
 * at the end of the slice is the synchronization point the RFC requires.
 *
 * Lanes are taken in batches of at most a->workerCnt. One segment of each
 * batch is filled by the calling thread rather than a spawned one, so a
 * thread count of 1 costs nothing and a batch of n needs only n-1 threads.
 * A thread that cannot be created is not an error: that segment is filled
 * inline instead.
 *
 * Algorithm:
 *  1. For each batch of at most 'threads' lanes:
 *   1.1. Start a thread for every lane of the batch but the first
 *   1.2. Fill the first lane's segment on this thread
 *   1.3. Join the threads started for this batch
 *
 * @param [in, out] a      Argon2 context.
 * @param [in]      pass   Pass number.
 * @param [in]      slice  Slice number.
 */
static void Argon2FillSlice(Argon2Ctx* a, word32 pass, word32 slice)
{
    word32 lane = 0;

    /* 1. For each batch of at most 'threads' lanes. */
    while (lane < a->lanes) {
        word32 n = a->lanes - lane;
        word32 k;
    #ifdef WOLFSSL_ARGON2_THREADS
        word32 started = 0;
    #endif

        if (n > a->workerCnt) {
            n = a->workerCnt;
        }

        for (k = 0; k < n; k++) {
            Argon2Worker* w = &a->workers[k];

            w->a = a;
            w->scratch = &a->scratch[(size_t)k * ARGON2_SCRATCH_BLOCKS];
            w->pos.pass = pass;
            w->pos.lane = lane + k;
            w->pos.slice = slice;
            w->pos.index = 0;
        }

    #ifdef WOLFSSL_ARGON2_THREADS
        /* 1.1. Start a thread for every lane of the batch but the first.
         * Handles are packed into the front of the array as they are
         * created, so tids[0] up to tids[started-1] are the only entries
         * ever written and the join below cannot reach an entry that no
         * thread was started for. Recording them at index k instead would
         * leave a gap on any failure, and a failure part way through a
         * batch would then join whatever that slot happened to hold. */
        for (k = 1; k < n; k++) {
            if (wolfSSL_NewThread(&a->tids[started], Argon2SegmentThread,
                    &a->workers[k]) == 0) {
                started++;
            }
            else {
                /* No thread available; fill it here instead. */
                Argon2FillSegment(&a->workers[k]);
            }
        }
    #else
        for (k = 1; k < n; k++) {
            Argon2FillSegment(&a->workers[k]);
        }
    #endif

        /* 1.2. Fill the first lane's segment on this thread. */
        Argon2FillSegment(&a->workers[0]);

    #ifdef WOLFSSL_ARGON2_THREADS
        /* 1.3. Join the threads started for this batch, and only those. */
        for (k = 0; k < started; k++) {
            (void)wolfSSL_JoinThread(a->tids[k]);
        }
    #endif

        lane += n;
    }
}

/* Compute H0, the pre-hash digest. RFC 9106 section 3.2, step 1.
 *
 * H0 commits to every parameter and every input, so that changing any of them
 * changes the whole memory array.
 *
 * The m hashed is the value the caller asked for rather than the one rounded
 * down to whole segments, which is why the context keeps memCost separately
 * from memoryBlocks.
 *
 * Algorithm:
 *  1. Hash the six fixed parameters as LE32 values, in the order
 *     p, T, m, t, v, y
 *  2. Hash each of P, S, K and X, every one preceded by its length as LE32
 *  3. H0 = the resulting 64-byte digest
 *
 * @param [in, out] a     Argon2 context, holding the parameters and the
 *                        BLAKE2b state used as scratch.
 * @param [out] h0        Buffer of ARGON2_PREHASH_LEN bytes for the digest.
 * @param [in]  outSz     T, the tag length in bytes.
 * @param [in]  pwd       P, the password.
 * @param [in]  pwdSz     Length of password in bytes.
 * @param [in]  salt      S, the salt.
 * @param [in]  saltSz    Length of salt in bytes.
 * @param [in]  secret    K, the optional secret value.
 * @param [in]  secretSz  Length of secret in bytes, 0 when unused.
 * @param [in]  ad        X, the optional associated data.
 * @param [in]  adSz      Length of associated data in bytes, 0 when unused.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2InitialHash(Argon2Ctx* a, byte* h0, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz)
{
    Blake2b* b2b = &a->b2b;
    byte   value[4];
    int    ret;
    word32 i;
    /* The fixed parameters, in the order the RFC hashes them. */
    word32 p[6];

    p[0] = a->lanes;
    p[1] = outSz;
    p[2] = a->memCost;
    p[3] = a->passes;
    p[4] = WC_ARGON2_VERSION_13;
    p[5] = (word32)a->type;

    ret = wc_InitBlake2b(b2b, ARGON2_PREHASH_LEN);

    /* 1. Hash the six fixed parameters as LE32 values. */
    for (i = 0; (ret == 0) && (i < 6); i++) {
        Argon2Store32(value, p[i]);
        ret = wc_Blake2bUpdate(b2b, value, (word32)sizeof(value));
    }

    /* 2. Hash P, S, K and X, each preceded by its length. */
    if (ret == 0) {
        Argon2Store32(value, pwdSz);
        ret = wc_Blake2bUpdate(b2b, value, (word32)sizeof(value));
    }
    if ((ret == 0) && (pwdSz > 0))
        ret = wc_Blake2bUpdate(b2b, pwd, pwdSz);

    if (ret == 0) {
        Argon2Store32(value, saltSz);
        ret = wc_Blake2bUpdate(b2b, value, (word32)sizeof(value));
    }
    if ((ret == 0) && (saltSz > 0))
        ret = wc_Blake2bUpdate(b2b, salt, saltSz);

    if (ret == 0) {
        Argon2Store32(value, secretSz);
        ret = wc_Blake2bUpdate(b2b, value, (word32)sizeof(value));
    }
    if ((ret == 0) && (secretSz > 0))
        ret = wc_Blake2bUpdate(b2b, secret, secretSz);

    if (ret == 0) {
        Argon2Store32(value, adSz);
        ret = wc_Blake2bUpdate(b2b, value, (word32)sizeof(value));
    }
    if ((ret == 0) && (adSz > 0))
        ret = wc_Blake2bUpdate(b2b, ad, adSz);

    /* 3. H0 = the resulting 64-byte digest. */
    if (ret == 0)
        ret = wc_Blake2bFinal(b2b, h0, ARGON2_PREHASH_LEN);

    return ret;
}

/* Seed the first two blocks of every lane. RFC 9106 section 3.2, step 3.
 *
 * The seed buffer already holds H0 in its first ARGON2_PREHASH_LEN bytes. The
 * two LE32 values that follow are written here for each block in turn.
 *
 * Algorithm:
 *  1. For each lane i:
 *   1.1. B[i][0] = H'(1024, H0 || LE32(0) || LE32(i))
 *   1.2. B[i][1] = H'(1024, H0 || LE32(1) || LE32(i))
 *
 * @param [in, out] a     Argon2 context, with memory allocated.
 * @param [in, out] seed  Buffer of ARGON2_PREHASH_SEED_LEN bytes holding H0.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2FillFirstBlocks(Argon2Ctx* a, byte* seed)
{
    Blake2b* b2b = &a->b2b;
    word32 lane;
    int    ret = 0;

    /* 1. For each lane i. */
    for (lane = 0; (lane < a->lanes) && (ret == 0); lane++) {
        Argon2Block* block;

        /* 1.1. B[i][0] = H'(1024, H0 || LE32(0) || LE32(i)) */
        Argon2Store32(seed + ARGON2_PREHASH_LEN, 0);
        Argon2Store32(seed + ARGON2_PREHASH_LEN + 4, lane);
        block = &a->memory[(size_t)lane * a->laneLength];
        ret = Argon2HashLong(b2b, (byte*)block, WC_ARGON2_BLOCK_SIZE, seed,
            ARGON2_PREHASH_SEED_LEN);
        if (ret != 0)
            break;
        Argon2BlockSwap(block);

        /* 1.2. B[i][1] = H'(1024, H0 || LE32(1) || LE32(i)) */
        Argon2Store32(seed + ARGON2_PREHASH_LEN, 1);
        block = &a->memory[(size_t)lane * a->laneLength + 1];
        ret = Argon2HashLong(b2b, (byte*)block, WC_ARGON2_BLOCK_SIZE, seed,
            ARGON2_PREHASH_SEED_LEN);
        if (ret != 0)
            break;
        Argon2BlockSwap(block);
    }

    return ret;
}

/* Produce the tag from the finished memory array. RFC 9106 section 3.2,
 * steps 6 and 7.
 *
 * Algorithm:
 *  1. C = B[0][q-1]
 *  2. C = C XOR B[i][q-1] for each remaining lane i
 *  3. Tag = H'(T, C)
 *
 * @param [in, out] a      Argon2 context, with the memory filled. The tmp
 *                         scratch block is used as the accumulator.
 * @param [out]     out    Buffer to hold the tag.
 * @param [in]      outSz  T, the tag length in bytes.
 *
 * @return  0 on success.
 * @return  Negative value from the BLAKE2b implementation on failure.
 */
static int Argon2Finalize(Argon2Ctx* a, byte* out, word32 outSz)
{
    Blake2b* b2b = &a->b2b;
    Argon2Block* acc = &a->scratch[ARGON2_SCRATCH_TMP];
    word32 lane, i;
    int    ret;

    /* 1. C = B[0][q-1] */
    XMEMCPY(acc, &a->memory[a->laneLength - 1], sizeof(*acc));

    /* 2. C = C XOR B[i][q-1] for each remaining lane. */
    for (lane = 1; lane < a->lanes; lane++) {
        const Argon2Block* last =
            &a->memory[(size_t)lane * a->laneLength + a->laneLength - 1];

        for (i = 0; i < WC_ARGON2_WORDS_IN_BLOCK; i++) {
            acc->v[i] ^= last->v[i];
        }
    }

    /* 3. Tag = H'(T, C) */
    Argon2BlockSwap(acc);
    ret = Argon2HashLong(b2b, out, outSz, (const byte*)acc,
        WC_ARGON2_BLOCK_SIZE);

    ForceZero(acc, sizeof(*acc));

    return ret;
}

/* Release the per-thread working state.
 *
 * The scratch blocks hold intermediate block values, so they are wiped before
 * being returned to the allocator.
 *
 * @param [in, out] a  Argon2 context.
 */
static void Argon2FreeWorkers(Argon2Ctx* a)
{
    if (a->scratch != NULL) {
        ForceZero(a->scratch, (size_t)a->workerCnt * ARGON2_SCRATCH_BLOCKS *
            sizeof(Argon2Block));
        XFREE(a->scratch, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
        a->scratch = NULL;
    }
    XFREE(a->workers, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
    a->workers = NULL;
#ifdef WOLFSSL_ARGON2_THREADS
    XFREE(a->tids, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
    a->tids = NULL;
#endif
    a->workerCnt = 0;
}

/* Allocate the per-thread working state: scratch blocks, workers and, when
 * threading is compiled in, thread handles.
 *
 * Sized for a->threads, capped at the lane count when the parameters are
 * known: a slice has only p segments, so a worker beyond the p-th could never
 * be given any.
 *
 * The new state is built up in full before any of the old state is released,
 * so a failed allocation leaves the context exactly as it was rather than
 * stripping a working context of the arrays it needs to derive.
 *
 * Algorithm:
 *  1. Work out how many workers are wanted
 *  2. Allocate all three arrays
 *  3. On any failure, release just the new arrays and leave the context alone
 *  4. Otherwise release the old state and adopt the new
 *
 * @param [in, out] a  Argon2 context with threads set.
 *
 * @return  0 on success.
 * @return  BAD_STATE_E when the context was never initialized, so no thread
 *          count has been set.
 * @return  MEMORY_E when an allocation fails.
 */
static int Argon2AllocWorkers(Argon2Ctx* a)
{
    Argon2Block* scratch;
    Argon2Worker* workers;
#ifdef WOLFSSL_ARGON2_THREADS
    THREAD_TYPE* tids;
#endif
    /* 1. Work out how many workers are wanted. */
    size_t n = a->threads;

    /* wc_Argon2Init() sets threads to 1, so zero here means the context was
     * never initialized. Allocating nothing would succeed and then fault on
     * the first derivation, so refuse instead. */
    if (n == 0) {
        return BAD_STATE_E;
    }
    if ((a->lanes > 0) && (n > a->lanes)) {
        n = a->lanes;
    }

    /* 2. Allocate all three arrays. */
    scratch = (Argon2Block*)XMALLOC(
        n * ARGON2_SCRATCH_BLOCKS * sizeof(Argon2Block), a->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    workers = (Argon2Worker*)XMALLOC(n * sizeof(Argon2Worker), a->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_ARGON2_THREADS
    tids = (THREAD_TYPE*)XMALLOC(n * sizeof(THREAD_TYPE), a->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* 3. On any failure, release just the new arrays and leave the context
     * as it was. */
    if ((scratch == NULL) || (workers == NULL)
#ifdef WOLFSSL_ARGON2_THREADS
            || (tids == NULL)
#endif
       ) {
        XFREE(scratch, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(workers, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_ARGON2_THREADS
        XFREE(tids, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }

    /* 4. Release the old state and adopt the new. */
    Argon2FreeWorkers(a);
    a->scratch = scratch;
    a->workers = workers;
#ifdef WOLFSSL_ARGON2_THREADS
    a->tids = tids;
#endif
    a->workerCnt = (word32)n;

    return 0;
}

/* Initialize an Argon2 context.
 *
 * No memory is allocated here: the block array is sized by the cost
 * parameters and is allocated by wc_Argon2SetParams(). Every context must be
 * released with wc_Argon2Free() whether or not parameters were ever set.
 *
 * @param [out] a      Argon2 context to initialize.
 * @param [in]  heap   Heap hint for dynamic allocation. May be NULL.
 * @param [in]  devId  Device identifier. Reserved for future use.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a is NULL.
 */
int wc_Argon2Init(Argon2Ctx* a, void* heap, int devId)
{
    if (a == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(a, 0, sizeof(Argon2Ctx));
    a->heap = heap;
    a->devId = devId;
    /* Sequential until the caller asks for more. */
    a->threads = 1;

    return 0;
}

/* Release the resources held by an Argon2 context.
 *
 * The block array holds the whole of the secret state, so it is wiped before
 * being returned to the allocator. Safe to call on a context that never had
 * parameters set, and safe to call more than once.
 *
 * @param [in, out] a  Argon2 context to free. May be NULL.
 */
void wc_Argon2Free(Argon2Ctx* a)
{
    if (a == NULL) {
        return;
    }

    if (a->memory != NULL) {
        ForceZero(a->memory, (size_t)a->memoryBlocks * sizeof(Argon2Block));
        XFREE(a->memory, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
        a->memory = NULL;
    }

    Argon2FreeWorkers(a);

    ForceZero(&a->b2b, sizeof(a->b2b));
    a->memoryBlocks = 0;
    a->memCost = 0;
    a->laneLength = 0;
    a->segmentLength = 0;
    a->lanes = 0;
    a->passes = 0;
}

#ifndef WC_NO_CONSTRUCTORS
/* Create a new Argon2 context.
 *
 * The returned context has been initialized but has no parameters set; call
 * wc_Argon2SetParams() before wc_Argon2DeriveTag(). Release it with
 * wc_Argon2Delete().
 *
 * @param [in]  heap         Heap hint for dynamic allocation. May be NULL.
 * @param [in]  devId        Device identifier. Reserved for future use.
 * @param [out] result_code  Result of the operation. May be NULL.
 *
 * @return  Allocated and initialized Argon2 context on success.
 * @return  NULL when dynamic memory allocation fails, with result_code set to
 *          MEMORY_E when it is not NULL.
 */
Argon2Ctx* wc_Argon2New(void* heap, int devId, int* result_code)
{
    int ret = 0;
    Argon2Ctx* a = (Argon2Ctx*)XMALLOC(sizeof(Argon2Ctx), heap,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (a == NULL) {
        ret = MEMORY_E;
    }
    else {
        ret = wc_Argon2Init(a, heap, devId);
        if (ret != 0) {
            XFREE(a, heap, DYNAMIC_TYPE_TMP_BUFFER);
            a = NULL;
        }
    }

    if (result_code != NULL) {
        *result_code = ret;
    }

    return a;
}

/* Delete and free an Argon2 context created with wc_Argon2New().
 *
 * @param [in]      a    Argon2 context to delete.
 * @param [in, out] a_p  Pointer to the context pointer, set to NULL. May be
 *                       NULL.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a is NULL.
 */
int wc_Argon2Delete(Argon2Ctx* a, Argon2Ctx** a_p)
{
    void* heap;

    if (a == NULL) {
        return BAD_FUNC_ARG;
    }

    heap = a->heap;
    wc_Argon2Free(a);
    XFREE(a, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (a_p != NULL) {
        *a_p = NULL;
    }

    return 0;
}
#endif /* !WC_NO_CONSTRUCTORS */

/* Set the variant and cost parameters, and allocate the block array.
 *
 * May be called again on the same context to change the parameters. The
 * existing allocation is kept when the new parameters need a block array of
 * the same size, so repeating the same call is cheap.
 *
 * Algorithm:
 *  1. Validate the variant and the cost parameters
 *  2. m' = 4 * p * floor(m / 4p), q = m' / p
 *  3. Allocate m' blocks, if the current allocation is not the right size
 *  4. Allocate the per-thread working state if it is not already there
 *
 * @param [in, out] a         Argon2 context.
 * @param [in]      type      Variant: WC_ARGON2_D, WC_ARGON2_I or
 *                            WC_ARGON2_ID.
 * @param [in]      parallel  p, the number of lanes.
 * @param [in]      memCost   m, the memory size in KiB. At least
 *                            8 * parallel.
 * @param [in]      timeCost  t, the number of passes. At least 1.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a is NULL, when type is not a known variant, or
 *          when a cost parameter is out of range.
 * @return  MEMORY_E when the block array cannot be allocated.
 */
int wc_Argon2SetParams(Argon2Ctx* a, int type, word32 parallel,
    word32 memCost, word32 timeCost)
{
    word32 memoryBlocks;
    word32 want;

    /* 1. Validate the variant and the cost parameters. */
    if (a == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((type != WC_ARGON2_D) && (type != WC_ARGON2_I) &&
            (type != WC_ARGON2_ID)) {
        return BAD_FUNC_ARG;
    }
    if ((parallel < WC_ARGON2_MIN_LANES) || (parallel > WC_ARGON2_MAX_LANES)) {
        return BAD_FUNC_ARG;
    }
    if (timeCost < WC_ARGON2_MIN_TIME) {
        return BAD_FUNC_ARG;
    }
    /* m must be at least 8p KiB. 8 * parallel cannot overflow because
     * parallel is bounded by 2^24 - 1, and it already implies the absolute
     * floor of WC_ARGON2_MIN_MEMORY because parallel is at least 1. */
    if (memCost < 8 * parallel) {
        return BAD_FUNC_ARG;
    }

    /* 2. m' = 4 * p * floor(m / 4p). Rounding down makes every segment the
     * same length. The H0 hash still commits to the requested m. */
    memoryBlocks = (memCost / (parallel * WC_ARGON2_SYNC_POINTS)) *
        (parallel * WC_ARGON2_SYNC_POINTS);

    /* Refuse rather than truncate when the allocation cannot be expressed in
     * a size_t. Only reachable on targets where size_t is under 64 bits; the
     * arithmetic is done in word64 so the comparison stays in range (and so
     * -Wtype-limits stays quiet) on the ones where it is not. */
    if ((word64)memoryBlocks * sizeof(Argon2Block) > (word64)(size_t)-1) {
        return MEMORY_E;
    }

    /* 3. Allocate, reusing an allocation that is already the right size. */
    if ((a->memory != NULL) && (a->memoryBlocks != memoryBlocks)) {
        ForceZero(a->memory, (size_t)a->memoryBlocks * sizeof(Argon2Block));
        XFREE(a->memory, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
        a->memory = NULL;
    }
    if (a->memory == NULL) {
        a->memory = (Argon2Block*)XMALLOC(
            (size_t)memoryBlocks * sizeof(Argon2Block), a->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (a->memory == NULL) {
            a->memoryBlocks = 0;
            return MEMORY_E;
        }
    }

    a->type          = type;
    a->lanes         = parallel;
    a->passes        = timeCost;
    a->memCost       = memCost;
    a->memoryBlocks  = memoryBlocks;
    /* q / 4, and q = m' / p. */
    a->segmentLength = memoryBlocks / (parallel * WC_ARGON2_SYNC_POINTS);
    a->laneLength    = a->segmentLength * WC_ARGON2_SYNC_POINTS;

    /* 4. Allocate the per-thread working state. It is capped by the lane
     * count, which has just been set, so this is redone when the lanes
     * change even though the thread count did not. */
    want = a->threads;
    if (want > a->lanes) {
        want = a->lanes;
    }
    if ((a->workers == NULL) || (a->workerCnt != want)) {
        int ret = Argon2AllocWorkers(a);

        if (ret != 0) {
            /* The block array on its own is not a usable context, and the
             * parameters have already been overwritten, so there is nothing
             * to roll back to. Release it so the context is consistently
             * unset rather than half built. */
            ForceZero(a->memory,
                (size_t)a->memoryBlocks * sizeof(Argon2Block));
            XFREE(a->memory, a->heap, DYNAMIC_TYPE_TMP_BUFFER);
            a->memory = NULL;
            a->memoryBlocks = 0;
            return ret;
        }
    }

    return 0;
}

#ifdef WOLFSSL_ARGON2_THREADS
/* Set the number of threads used to fill the segments of a slice.
 *
 * The p segments of a slice are independent, so up to p of them can be filled
 * at once. A count above the lane count therefore buys nothing and is not an
 * error: the extra threads simply never have work. One of each batch is
 * filled by the calling thread, so a count of 1 spawns nothing at all.
 *
 * Changing the count reallocates the per-thread working state, so prefer to
 * set it once before deriving.
 *
 * This does not change the tag: the synchronization point at the end of every
 * slice makes the result the same however many threads fill it.
 *
 * @param [in, out] a        Argon2 context.
 * @param [in]      threads  Number of threads, at least 1.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a is NULL, or threads is 0 or above
 *          WC_ARGON2_MAX_THREADS.
 * @return  MEMORY_E when the per-thread working state cannot be allocated.
 */
int wc_Argon2SetThreads(Argon2Ctx* a, word32 threads)
{
    if (a == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((threads < 1) || (threads > WC_ARGON2_MAX_THREADS)) {
        return BAD_FUNC_ARG;
    }

    /* A no-op only when this count is already in force: it matches and the
     * working state for it exists. */
    if ((threads == a->threads) && (a->workers != NULL)) {
        return 0;
    }

    /* Only resize now if there is state to resize; otherwise the allocation
     * happens when the parameters are set. The count is committed only once
     * the state for it exists, so that a failure here leaves the previous
     * count in place and a retry with the same value tries again rather
     * than taking the no-op above. */
    if (a->workers != NULL) {
        word32 prev = a->threads;
        int    ret;

        a->threads = threads;
        ret = Argon2AllocWorkers(a);
        if (ret != 0) {
            a->threads = prev;
            return ret;
        }
    }
    else {
        a->threads = threads;
    }

    return 0;
}
#endif /* WOLFSSL_ARGON2_THREADS */

/* Derive a tag using the parameters already set on the context. RFC 9106.
 *
 * wc_Argon2SetParams() must have been called first. The context may be used
 * for any number of derivations; the block array is reused and no allocation
 * is performed here.
 *
 * Algorithm:
 *  1. H0 = pre-hash of the parameters and inputs
 *  2. Seed the first two blocks of every lane from H0
 *  3. For each pass, each slice and each lane, fill the segment
 *  4. C = B[0][q-1] XOR ... XOR B[p-1][q-1]
 *  5. Tag = H'(T, C)
 *
 * @param [in, out] a         Argon2 context with parameters set.
 * @param [out]     out       Buffer to hold the tag.
 * @param [in]      outSz     T, the tag length in bytes. At least
 *                            WC_ARGON2_MIN_OUTLEN.
 * @param [in]      pwd       P, the password. May be NULL only when pwdSz
 *                            is 0.
 * @param [in]      pwdSz     Length of password in bytes.
 * @param [in]      salt      S, the salt.
 * @param [in]      saltSz    Length of salt in bytes. At least
 *                            WC_ARGON2_MIN_SALT_LEN.
 * @param [in]      secret    K, the optional secret value. NULL when unused.
 * @param [in]      secretSz  Length of secret in bytes, 0 when unused.
 * @param [in]      ad        X, the optional associated data. NULL when
 *                            unused.
 * @param [in]      adSz      Length of associated data in bytes, 0 when
 *                            unused.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a or a required pointer is NULL, or when a
 *          pointer is NULL and its length is not 0.
 * @return  BAD_STATE_E when parameters have not been set on the context.
 * @return  BAD_LENGTH_E when outSz or saltSz is below its minimum.
 */
int wc_Argon2DeriveTag(Argon2Ctx* a, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz)
{
    byte   seed[ARGON2_PREHASH_SEED_LEN];
    word32 pass, slice;
    int    ret;

    if ((a == NULL) || (out == NULL) || (salt == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((pwd == NULL) && (pwdSz > 0)) {
        return BAD_FUNC_ARG;
    }
    if ((secret == NULL) && (secretSz > 0)) {
        return BAD_FUNC_ARG;
    }
    if ((ad == NULL) && (adSz > 0)) {
        return BAD_FUNC_ARG;
    }
    /* Every part of the working state must be present. wc_Argon2SetParams()
     * builds the block array before the per-thread state, so a failure in
     * the latter used to leave a->memory set with the rest NULL - which got
     * as far as dereferencing a->workers[0] in Argon2FillSlice(). That is
     * repaired at the source as well, but the guard covers the whole state
     * rather than one member of it. */
    if ((a->memory == NULL) || (a->workers == NULL) || (a->scratch == NULL) ||
            (a->workerCnt == 0)) {
        return BAD_STATE_E;
    }
    if (outSz < WC_ARGON2_MIN_OUTLEN) {
        return BAD_LENGTH_E;
    }
    if (saltSz < WC_ARGON2_MIN_SALT_LEN) {
        return BAD_LENGTH_E;
    }

#ifdef WOLFSSL_CHECK_MEM_ZERO
    /* Everything below is derived from the password. The block array and the
     * scratch blocks are written in full by the derivation, so they are not
     * poisoned - registering them is enough for the check to catch a wipe
     * that goes missing. */
    XMEMSET(seed, 0xff, sizeof(seed));
    wc_MemZero_Add("wc_Argon2DeriveTag seed", seed, sizeof(seed));
    wc_MemZero_Add("wc_Argon2DeriveTag b2b", &a->b2b, sizeof(a->b2b));
    wc_MemZero_Add("wc_Argon2DeriveTag memory", a->memory,
        (size_t)a->memoryBlocks * sizeof(Argon2Block));
    wc_MemZero_Add("wc_Argon2DeriveTag scratch", a->scratch,
        (size_t)a->workerCnt * ARGON2_SCRATCH_BLOCKS * sizeof(Argon2Block));
#endif

    /* 1. H0 = pre-hash of the parameters and inputs. */
    ret = Argon2InitialHash(a, seed, outSz, pwd, pwdSz, salt, saltSz,
        secret, secretSz, ad, adSz);

    /* 2. Seed the first two blocks of every lane from H0. */
    if (ret == 0) {
        ret = Argon2FillFirstBlocks(a, seed);
    }

    /* 3. For each pass and each slice, fill every segment of the slice. */
    if (ret == 0) {
        for (pass = 0; pass < a->passes; pass++) {
            for (slice = 0; slice < WC_ARGON2_SYNC_POINTS; slice++) {
                Argon2FillSlice(a, pass, slice);
            }
        }

        /* 4. C = B[0][q-1] XOR ... XOR B[p-1][q-1], and 5. Tag = H'(T, C). */
        ret = Argon2Finalize(a, out, outSz);
    }

    /* blake2b_final() leaves the digest in the state's chaining words and the
     * tail of the last message in its buffer, and nothing re-initializes it
     * after the final hash. On a little-endian host the leading bytes of the
     * state are therefore the derived tag itself, and on the error path out
     * of Argon2InitialHash() they are the password. The context outlives the
     * derivation, so wipe here rather than leaving it to wc_Argon2Free(). */
    ForceZero(&a->b2b, sizeof(a->b2b));
    ForceZero(seed, sizeof(seed));

    /* The block array is the whole of the memory-hard state and the scratch
     * blocks hold intermediate block values, both derived from the password.
     * A context is meant to be reused, so wipe them now rather than leaving
     * a derivation's worth of state sitting there until the context is
     * freed. wc_scrypt() clears its working state per derivation likewise. */
    ForceZero(a->memory, (size_t)a->memoryBlocks * sizeof(Argon2Block));
    ForceZero(a->scratch, (size_t)a->workerCnt * ARGON2_SCRATCH_BLOCKS *
        sizeof(Argon2Block));

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(seed, sizeof(seed));
    wc_MemZero_Check(&a->b2b, sizeof(a->b2b));
    wc_MemZero_Check(a->memory,
        (size_t)a->memoryBlocks * sizeof(Argon2Block));
    wc_MemZero_Check(a->scratch,
        (size_t)a->workerCnt * ARGON2_SCRATCH_BLOCKS * sizeof(Argon2Block));
#endif

    return ret;
}

/* Derive a tag from a password using Argon2. RFC 9106.
 *
 * Accepts the optional secret value K and associated data X, and a heap hint
 * for the block array allocation.
 *
 * A one-shot wrapper: the context it uses is created and destroyed on each
 * call. An application deriving many tags with the same cost parameters
 * should use wc_Argon2Init(), wc_Argon2SetParams() and wc_Argon2DeriveTag()
 * instead so that the block array is allocated only once.
 *
 * Built with WOLFSSL_ARGON2_THREADS this fills the segments of a slice on
 * one thread per lane. The tag is unchanged either way; use the context API
 * and wc_Argon2SetThreads() to ask for a different number.
 *
 * Algorithm:
 *  1. Initialize a context
 *  2. Use a thread per lane, when threading is compiled in
 *  3. Set the variant and cost parameters, allocating the block array
 *  4. Derive the tag
 *  5. Free the context, wiping the block array
 *
 * @param [in]  type      Variant: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID.
 * @param [out] out       Buffer to hold the tag.
 * @param [in]  outSz     T, the tag length in bytes. At least
 *                        WC_ARGON2_MIN_OUTLEN.
 * @param [in]  pwd       P, the password. May be NULL only when pwdSz is 0.
 * @param [in]  pwdSz     Length of password in bytes.
 * @param [in]  salt      S, the salt.
 * @param [in]  saltSz    Length of salt in bytes. At least
 *                        WC_ARGON2_MIN_SALT_LEN.
 * @param [in]  secret    K, the optional secret value. NULL when unused.
 * @param [in]  secretSz  Length of secret in bytes, 0 when unused.
 * @param [in]  ad        X, the optional associated data. NULL when unused.
 * @param [in]  adSz      Length of associated data in bytes, 0 when unused.
 * @param [in]  parallel  p, the number of lanes.
 * @param [in]  memCost   m, the memory size in KiB. At least 8 * parallel.
 * @param [in]  timeCost  t, the number of passes. At least 1.
 * @param [in]  heap      Heap hint for dynamic allocation. May be NULL.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL and its length is not 0, when
 *          type is not a known variant, or when a cost parameter is out of
 *          range.
 * @return  BAD_LENGTH_E when outSz or saltSz is below its minimum.
 * @return  MEMORY_E when a dynamic memory allocation fails.
 */
int wc_Argon2_ex(int type, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz,
    word32 parallel, word32 memCost, word32 timeCost, void* heap)
{
    int ret;
    /* Argon2Ctx is well over 100 bytes, so it goes on the heap when the
     * build asks for a small stack. */
    WC_DECLARE_VAR(a, Argon2Ctx, 1, heap);

    WC_ALLOC_VAR_EX(a, Argon2Ctx, 1, heap, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    /* 1. Initialize a context. */
    ret = wc_Argon2Init(a, heap, INVALID_DEVID);
#ifdef WOLFSSL_ARGON2_THREADS
    /* 2. Use a thread per lane. A context starts sequential, so without this
     * the worker count is capped at 1 and a threaded build derives no faster
     * than an unthreaded one. Set before the parameters so the working state
     * is allocated once at the final size rather than for one worker and
     * then again. */
    if (ret == 0) {
        ret = wc_Argon2SetThreads(a, parallel);
    }
#endif
    /* 3. Set the variant and cost parameters, allocating the block array. */
    if (ret == 0) {
        ret = wc_Argon2SetParams(a, type, parallel, memCost, timeCost);
    }
    /* 4. Derive the tag. */
    if (ret == 0) {
        ret = wc_Argon2DeriveTag(a, out, outSz, pwd, pwdSz, salt, saltSz,
            secret, secretSz, ad, adSz);
    }

    /* 5. Free the context, wiping the block array. */
    wc_Argon2Free(a);
    WC_FREE_VAR_EX(a, heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Derive a tag from a password using Argon2. RFC 9106.
 *
 * Equivalent to wc_Argon2_ex() with no secret value, no associated data and
 * no heap hint. See wc_Argon2_ex() for the algorithm.
 *
 * @param [in]  type      Variant: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID.
 * @param [out] out       Buffer to hold the tag.
 * @param [in]  outSz     T, the tag length in bytes. At least
 *                        WC_ARGON2_MIN_OUTLEN.
 * @param [in]  pwd       P, the password. May be NULL only when pwdSz is 0.
 * @param [in]  pwdSz     Length of password in bytes.
 * @param [in]  salt      S, the salt.
 * @param [in]  saltSz    Length of salt in bytes. At least
 *                        WC_ARGON2_MIN_SALT_LEN.
 * @param [in]  parallel  p, the number of lanes.
 * @param [in]  memCost   m, the memory size in KiB. At least 8 * parallel.
 * @param [in]  timeCost  t, the number of passes. At least 1.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a pointer is NULL and its length is not 0, when
 *          type is not a known variant, or when a cost parameter is out of
 *          range.
 * @return  BAD_LENGTH_E when outSz or saltSz is below its minimum.
 * @return  MEMORY_E when a dynamic memory allocation fails.
 */
int wc_Argon2(int type, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    word32 parallel, word32 memCost, word32 timeCost)
{
    return wc_Argon2_ex(type, out, outSz, pwd, pwdSz, salt, saltSz,
        NULL, 0, NULL, 0, parallel, memCost, timeCost, NULL);
}

#endif /* HAVE_ARGON2 */
