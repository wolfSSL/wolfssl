/* argon2.h
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

/*!
    \file wolfssl/wolfcrypt/argon2.h
*/

#ifndef WOLF_CRYPT_ARGON2_H
#define WOLF_CRYPT_ARGON2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_ARGON2

#include <wolfssl/wolfcrypt/blake2.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Argon2 as specified in RFC 9106.
 *
 * Only version number 0x13 (19, "version 1.3") is implemented. The earlier
 * 0x10 encoding is deliberately not supported: it is superseded, and RFC 9106
 * defines 0x13 as the version for all three variants.
 */
#define WC_ARGON2_VERSION_13        0x13

/* Argon2 variants. Values are the "type" field hashed into H0 by RFC 9106
 * section 3.2, so they must not be renumbered. */
enum wc_Argon2Type {
    WC_ARGON2_D  = 0,  /* data-dependent addressing */
    WC_ARGON2_I  = 1,  /* data-independent addressing */
    WC_ARGON2_ID = 2   /* Argon2i for the first half-pass, then Argon2d */
};

/* Memory block size in bytes, and the number of 64-bit words in one. */
#define WC_ARGON2_BLOCK_SIZE        1024
#define WC_ARGON2_WORDS_IN_BLOCK    (WC_ARGON2_BLOCK_SIZE / 8)

/* Synchronization points (slices) per pass. */
#define WC_ARGON2_SYNC_POINTS       4

/* Parameter limits. The upper bounds are those of RFC 9106 section 3.1 where
 * they are representable in a word32; memory is additionally bounded at run
 * time by what the allocator can supply. */
#define WC_ARGON2_MIN_OUTLEN        4
#define WC_ARGON2_MIN_SALT_LEN      8
#define WC_ARGON2_MIN_LANES         1
#define WC_ARGON2_MAX_LANES         0xFFFFFFU
#define WC_ARGON2_MIN_TIME          1
/* Minimum memory is 8*p KiB; this is the floor for p == 1. */
#define WC_ARGON2_MIN_MEMORY        (2 * WC_ARGON2_SYNC_POINTS)

#if defined(WOLFSSL_ARGON2_THREADS) && defined(SINGLE_THREADED)
    #error "WOLFSSL_ARGON2_THREADS requires a multi-threaded build"
#endif

/* Maximum number of threads that may be used to fill a slice. The RFC places
 * no bound on it beyond the lane count; this is a sanity limit on the worker
 * and scratch arrays. */
#define WC_ARGON2_MAX_THREADS       0xFFFFFFU

/* One 1 KiB memory block, held as 128 64-bit words in host byte order. */
typedef struct Argon2Block {
    /* Words of the block. */
    word64 v[WC_ARGON2_WORDS_IN_BLOCK];
} Argon2Block;

/* Position of the block currently being computed. */
typedef struct Argon2Pos {
    /* Pass number, 0 to t-1. */
    word32 pass;
    /* Lane number, 0 to p-1. */
    word32 lane;
    /* Slice number, 0 to 3. */
    word32 slice;
    /* Index of the block within its segment. */
    word32 index;
} Argon2Pos;

/* One segment of work: the state needed to fill the part of one lane that
 * lies within one slice.
 *
 * The context is shared and read-only for the duration; everything written
 * is either this worker's scratch blocks or the blocks of its own segment,
 * which no other worker of the same slice touches.
 */
typedef struct Argon2Worker {
    /* Argon2 context being worked on. */
    struct Argon2Ctx* a;
    /* This worker's scratch blocks. */
    Argon2Block* scratch;
    /* Position of the segment to fill. */
    Argon2Pos pos;
} Argon2Worker;

/* State for Argon2 operations.
 *
 * Holding the block array in the object lets an application that derives many
 * tags with the same cost parameters pay for the allocation once. The
 * parameters are set with wc_Argon2SetParams() and each derivation is then a
 * call to wc_Argon2DeriveTag().
 */
typedef struct Argon2Ctx {
    /* Block array of m' blocks. NULL until wc_Argon2SetParams() has been
     * called. */
    Argon2Block* memory;
    /* Working blocks, one set for each thread. Held apart from the block
     * array so that the thread count and the cost parameters can be changed
     * independently of one another. */
    Argon2Block* scratch;
    /* One worker for each thread, describing the segment it is to fill. */
    Argon2Worker* workers;
#ifdef WOLFSSL_ARGON2_THREADS
    /* Handles of the threads spawned for the current batch, packed from
     * index 0. At most workerCnt-1 are live at once: the calling thread
     * fills one segment of every batch itself. */
    THREAD_TYPE* tids;
#endif
    /* Heap hint for dynamic allocations. */
    void* heap;
    /* BLAKE2b state used for H and H'. */
    Blake2b b2b;
    /* m': number of blocks, after rounding down to equal segments. */
    word32 memoryBlocks;
    /* m: memory as requested in KiB. Hashed into H0. */
    word32 memCost;
    /* q: number of blocks in a lane. */
    word32 laneLength;
    /* Number of blocks in a segment, q / 4. */
    word32 segmentLength;
    /* p: number of lanes. */
    word32 lanes;
    /* t: number of passes. */
    word32 passes;
    /* Number of threads the caller asked for. Always 1 when threading is not
     * compiled in. */
    word32 threads;
    /* Number of workers actually allocated: threads, capped at the lane
     * count once that is known. More workers than lanes can never be given
     * work, so allocating them would only waste memory. */
    word32 workerCnt;
    /* Variant: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID. */
    int type;
    /* Device identifier. Reserved; Argon2 has no crypto callback support. */
    int devId;
} Argon2Ctx;

WOLFSSL_API int wc_Argon2Init(Argon2Ctx* a, void* heap, int devId);
WOLFSSL_API void wc_Argon2Free(Argon2Ctx* a);

#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API Argon2Ctx* wc_Argon2New(void* heap, int devId, int* result_code);
WOLFSSL_API int wc_Argon2Delete(Argon2Ctx* a, Argon2Ctx** a_p);
#endif /* !WC_NO_CONSTRUCTORS */

WOLFSSL_API int wc_Argon2SetParams(Argon2Ctx* a, int type, word32 parallel,
    word32 memCost, word32 timeCost);

#ifdef WOLFSSL_ARGON2_THREADS
WOLFSSL_API int wc_Argon2SetThreads(Argon2Ctx* a, word32 threads);
#endif /* WOLFSSL_ARGON2_THREADS */

WOLFSSL_API int wc_Argon2DeriveTag(Argon2Ctx* a, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz);

WOLFSSL_API int wc_Argon2(int type, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    word32 parallel, word32 memCost, word32 timeCost);
WOLFSSL_API int wc_Argon2_ex(int type, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz,
    word32 parallel, word32 memCost, word32 timeCost, void* heap);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_ARGON2 */
#endif /* WOLF_CRYPT_ARGON2_H */
