/* test_memory_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/memory.c.
 *
 * memory.c's multi-condition decisions are split behind two build axes that
 * do not both fit in one binary:
 *
 *  (A) WOLFSSL_STATIC_MEMORY (the static-pool allocator: wc_LoadStaticMemory,
 *      wc_partition_static_memory, wolfSSL_StaticBufferSz_ex, and the
 *      static-memory wolfSSL_Malloc/Free/Realloc). This is the LARGER
 *      surface (14 distinct compound decisions) and is what this file
 *      compiles: `#define WOLFSSL_STATIC_MEMORY` + `#define
 *      WOLFSSL_MEM_FAIL_COUNT` before `#include`.
 *
 *  (B) !WOLFSSL_STATIC_MEMORY, i.e. the *default* (non-static) allocator.
 *      Two compound decisions live only there and are structurally
 *      unreachable in this binary:
 *        - memory.c ~:294 wc_MemZero_Check()'s
 *          `(memZero[i].addr < addr) || ((size_t)memZero[i].addr >=
 *          (size_t)addr + len)` -- the whole WOLFSSL_CHECK_MEM_ZERO block
 *          (memory.c ~:182-327) is wrapped in `#ifndef WOLFSSL_STATIC_MEMORY`.
 *        - memory.c ~:396 the WOLFSSL_FORCE_MALLOC_FAIL_TEST
 *          `res && --gMemFailCount == 0` inside the *non-static*
 *          wolfSSL_Malloc() (memory.c ~:330), which only exists in the
 *          `#ifndef WOLFSSL_STATIC_MEMORY` half of the file -- the
 *          static-memory build has a completely different wolfSSL_Malloc()
 *          (memory.c ~:995) with no such check.
 *      A second white-box variant (`#define WOLFSSL_CHECK_MEM_ZERO` +
 *      `#define WOLFSSL_FORCE_MALLOC_FAIL_TEST`, *no* WOLFSSL_STATIC_MEMORY)
 *      is needed to close these two; not attempted here.
 *
 * Config compiled by THIS file (set below, before the #include):
 *      WOLFSSL_STATIC_MEMORY
 *      WOLFSSL_MEM_FAIL_COUNT
 * Verified against a throwaway library built with:
 *      ./configure --enable-usersettings --enable-static --disable-shared \
 *          --enable-staticmemory
 *      (CC=clang, CFLAGS/LDFLAGS carrying the campaign's
 *      -fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc, plus
 *      -Wno-error=unused-function: wc_MemFailCount_AllocMem/FreeMem (memory.c
 *      :150/:165) are `static` helpers whose only OTHER caller is the
 *      non-static wolfSSL_Malloc/Free, which this variant does not compile;
 *      this white-box file calls them directly instead, which is why they
 *      are not truly dead here even though the plain library build alone
 *      would warn.)
 *
 * Decisions covered in this binary (memory.c line numbers as of this
 * writing; both/all MC/DC independence pairs driven in-binary unless noted):
 *   :155  wc_MemFailCount_AllocMem(): (mem_fail_cnt>0) && (mem_fail_cnt <=
 *         mem_fail_allocs+1) -- called directly (WOLFSSL_MEM_FAIL_COUNT is
 *         compiled unconditionally, independent of WOLFSSL_STATIC_MEMORY).
 *   :621  wc_partition_static_memory() alignment
 *         `(wc_ptr_t)pt % WOLFSSL_STATIC_ALIGN && pt < (buffer+sz)`.
 *   :635  wc_partition_static_memory() `flag & WOLFMEM_IO_POOL ||
 *         flag & WOLFMEM_IO_POOL_FIXED`.
 *   :717  wc_LoadStaticMemory_ex() `pHint==NULL || buf==NULL ||
 *         sizeList==NULL || distList==NULL` (4-way OR, 5 vectors).
 *   :767  wc_LoadStaticMemory_ex() `(flag & WOLFMEM_IO_POOL) ||
 *         (flag & WOLFMEM_IO_POOL_FIXED)`.
 *   :801  wc_UnloadStaticMemory() `heap != NULL && heap->memory != NULL`.
 *   :833  wolfSSL_StaticBufferSz_ex() `buffer==NULL || sizeList==NULL ||
 *         distList==NULL` (3-way OR, 4 vectors).
 *   :844  wolfSSL_StaticBufferSz_ex() same alignment pattern as :621.
 *   :851  wolfSSL_StaticBufferSz_ex() same IO_POOL/IO_POOL_FIXED OR as :635.
 *   :867  wolfSSL_StaticBufferSz_ex() `(ava >= sizeList[0]+padSz+memSz) &&
 *         (ava > 0)` -- see RESIDUAL note below; only the first operand's
 *         independence is satisfiable.
 *   :1013 wolfSSL_Malloc() `heap==NULL && globalHeapHint==NULL`.
 *   :1068 wolfSSL_Malloc() `mem->flag & WOLFMEM_IO_POOL_FIXED &&
 *         (type==DYNAMIC_TYPE_OUT_BUFFER || type==DYNAMIC_TYPE_IN_BUFFER)`.
 *   :1083 wolfSSL_Malloc() `mem->flag & WOLFMEM_IO_POOL &&
 *         (type==DYNAMIC_TYPE_OUT_BUFFER || type==DYNAMIC_TYPE_IN_BUFFER)`.
 *   :1201 wolfSSL_Free() `heap==NULL && globalHeapHint==NULL`.
 *   :1257 wolfSSL_Free() IO_POOL_FIXED && (OUT||IN), same shape as :1068.
 *   :1263 wolfSSL_Free() `mem->flag & WOLFMEM_IO_POOL && pt->sz==WOLFMEM_IO_SZ
 *         && (type==OUT||type==IN)`.
 *   :1348 wolfSSL_Realloc() `heap==NULL && globalHeapHint==NULL`.
 *   :1387 wolfSSL_Realloc() `((mem->flag & WOLFMEM_IO_POOL) ||
 *         (mem->flag & WOLFMEM_IO_POOL_FIXED)) && (type==OUT||type==IN)`.
 *   :1414 wolfSSL_Realloc() `pt != NULL && res == NULL` -- see RESIDUAL note.
 *
 * RESIDUALS (structurally dead operand, provably unsatisfiable -- not a gap
 * in this test, a property of the source):
 *   - :867 `ava > 0`: every bucket size in sizeList[] is a positive value
 *     (callers only ever pass positive bucket sizes), so
 *     `ava >= sizeList[0]+padSz+memSz` being true always implies `ava > 0`
 *     (padSz+memSz >= 0, sizeList[0] > 0). The pair that would show `ava>0`
 *     independently (first operand true, second false) requires
 *     `sizeList[0]+padSz+memSz <= 0`, which cannot happen. Only the first
 *     operand's independence pair is driven here.
 *   - :1414 `res == NULL`: this check is reached solely via the `else`
 *     branch of the IO-pool `if` immediately above it (memory.c ~:1387-1400
 *     in this same function). Every route into that `else` branch leaves
 *     `res` at its function-entry initial value of 0/NULL (the only other
 *     place `res` is assigned in wolfSSL_Realloc is inside the sibling `if`
 *     branch, which is mutually exclusive with reaching this line). So
 *     `res==NULL` is always true when this line executes; only `pt!=NULL`'s
 *     independence pair is driven here.
 *
 * Crash-safety: every static-memory API here is called with a genuinely
 * dereferenceable buffer (real stack/static arrays, generously sized) or a
 * cleanly-NULL argument that the target function is documented to reject
 * before touching anything else (verified by reading the source above each
 * call). The one intentionally "irregular" trick used for :1257/:1263's
 * MC/DC pairs is freeing a pointer obtained from one static-memory pool
 * while passing a *different* pool's heap-hint as the `heap` argument to
 * wolfSSL_Free(); this is safe because wolfSSL_Free() derives the `wc_Memory`
 * header purely from pointer arithmetic on the `ptr` argument (real,
 * valid memory either way) and only uses the `heap` argument's flags/
 * sizeList for bookkeeping -- never for a dereference through `ptr`. All
 * pools share the same sizeList/distList so the bookkeeping is
 * self-consistent (no out-of-bounds `mem->sizeList[i]` compare). The one
 * pool whose mutex is destroyed (via wc_UnloadStaticMemory) is unloaded
 * only once, last, after every other use of it.
 */

#ifndef WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY
#endif
#ifndef WOLFSSL_MEM_FAIL_COUNT
#define WOLFSSL_MEM_FAIL_COUNT
#endif

#include <wolfcrypt/src/memory.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* Shared bucket description used by every "real" static-memory pool below,
 * so cross-pool bookkeeping (Section 8) always compares against a value
 * that is genuinely present in every pool's sizeList[]. */
static const word32 s_sizeList[3] = { 64, 128, 256 };
static const word32 s_distList[3] = { 4, 4, 4 };

/* Scratch region used only for the direct wc_partition_static_memory() /
 * wolfSSL_StaticBufferSz_ex() alignment + flag-OR vectors (Sections 2/3). */
static byte s_scratch[8192];

/* "Real" pools used for the public-API Malloc/Free/Realloc exercise
 * (Sections 4/5/7/8/9). Sized generously: >= 2x WOLFMEM_IO_SZ for the IO
 * pools so at least two IO buckets are created (one for outBuf, one for
 * inBuf / one to Malloc and Free again). */
static byte s_bufGeneral[8192];
static byte s_bufIOPool[45000];
static byte s_bufIOFixed[45000];
static byte s_bufScratchLoad[512]; /* used only for the NULL-arg vectors */

int main(void)
{
    printf("memory.c white-box supplement\n");
#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_STATIC_MEMORY)
    WOLFSSL_HEAP_HINT* hintGeneral = NULL;
    WOLFSSL_HEAP_HINT* hintIOPool  = NULL;
    WOLFSSL_HEAP_HINT* hintIOFixed = NULL;
    int ret;
    void* p;

    XMEMSET(s_scratch, 0, sizeof(s_scratch));
    XMEMSET(s_bufGeneral, 0, sizeof(s_bufGeneral));
    XMEMSET(s_bufIOPool, 0, sizeof(s_bufIOPool));
    XMEMSET(s_bufIOFixed, 0, sizeof(s_bufIOFixed));
    XMEMSET(s_bufScratchLoad, 0, sizeof(s_bufScratchLoad));

    /* ==================================================================
     * Section 1 -- wc_MemFailCount_AllocMem() :155
     * (mem_fail_cnt > 0) && (mem_fail_cnt <= mem_fail_allocs + 1)
     * Both operands read mem_fail_cnt, so each pair below holds one
     * operand's *value* fixed (by choosing mem_fail_allocs to compensate)
     * while only the other operand's truth value changes.
     * ================================================================== */
    WB_NOTE("wc_MemFailCount_AllocMem(): cnt>0 && cnt<=allocs+1 [:155]");
    wc_MemFailCount_Init();

    /* A-independence pair: allocs held at 100 in both; cnt 0->1 flips A
     * false->true while B (cnt<=allocs+1) stays true either way. */
    mem_fail_cnt = 0; mem_fail_allocs = 100;
    WB_CHECK(wc_MemFailCount_AllocMem() == 1, "cnt=0 (A false) -> success");
    mem_fail_cnt = 1; mem_fail_allocs = 100;
    WB_CHECK(wc_MemFailCount_AllocMem() == 0, "cnt=1,allocs=100 (A,B true) -> fail");

    /* B-independence pair: cnt held at 5 in both (A true both times);
     * allocs 10->0 flips B true->false. */
    mem_fail_cnt = 5; mem_fail_allocs = 10;
    WB_CHECK(wc_MemFailCount_AllocMem() == 0, "cnt=5,allocs=10 (A,B true) -> fail");
    mem_fail_cnt = 5; mem_fail_allocs = 0;
    WB_CHECK(wc_MemFailCount_AllocMem() == 1, "cnt=5,allocs=0 (A true,B false) -> success");

    wc_MemFailCount_FreeMem();
    wc_MemFailCount_Free();
    /* Restore harmless defaults before anything else in this binary runs. */
    mem_fail_cnt = 0; mem_fail_allocs = 0; mem_fail_frees = 0;

    /* ==================================================================
     * Section 2/3 -- wc_partition_static_memory() alignment (:621) and
     * IO_POOL/IO_POOL_FIXED OR (:635), driven directly (it is file-static
     * but visible here via #include).
     * ================================================================== */
    {
        WOLFSSL_HEAP heapDirect;
        byte* aligned;
        byte* misaligned;

        WB_NOTE("wc_partition_static_memory() align-while [:621] + IO-flag OR [:635]");

        aligned = s_scratch;
        while (((wc_ptr_t)aligned) % WOLFSSL_STATIC_ALIGN != 0)
            aligned++;
        misaligned = aligned + 1; /* guaranteed non-aligned since aligned is aligned */

        /* align-while "F" vector: already aligned -> first operand false,
         * loop body never runs (short circuit). */
        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_GENERAL, &heapDirect);
        WB_CHECK(ret == 1, "align-while F vector (already aligned) succeeds");

        /* align-while "TT" vector: misaligned, ample room -> loop iterates
         * (both operands true) until aligned, then partitions normally. */
        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(misaligned,
                (word32)(sizeof(s_scratch) - (misaligned - s_scratch)),
                WOLFMEM_GENERAL, &heapDirect);
        WB_CHECK(ret == 1, "align-while TT vector (misaligned, ample room) succeeds");

        /* align-while "TF" vector: misaligned, tiny logical size -> loop
         * exits via the *second* operand (pt reaches buffer+sz) while the
         * pointer is still misaligned (first operand stays true). Logical
         * size is deliberately smaller than the real backing array so the
         * `*pt = 0x00` writes inside the align loop stay physically
         * in-bounds regardless. */
        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(misaligned, 3, WOLFMEM_GENERAL,
                &heapDirect);
        WB_CHECK(ret == 1, "align-while TF vector (misaligned, tiny logical sz)");

        /* IO-flag OR vectors: aligned start so the align-while above is
         * trivially false and does not interfere; only `flag` varies. */
        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_GENERAL, &heapDirect);
        WB_CHECK(ret == 1, "IO-flag OR: both false (WOLFMEM_GENERAL)");

        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_IO_POOL, &heapDirect);
        WB_CHECK(ret == 1, "IO-flag OR: first true (WOLFMEM_IO_POOL)");

        XMEMSET(&heapDirect, 0, sizeof(heapDirect));
        wc_init_memory_heap(&heapDirect, 3, s_sizeList, s_distList);
        ret = wc_partition_static_memory(aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_IO_POOL_FIXED, &heapDirect);
        WB_CHECK(ret == 1, "IO-flag OR: second true (WOLFMEM_IO_POOL_FIXED)");
    }

    /* ==================================================================
     * Section 4a -- wolfSSL_StaticBufferSz_ex() [:833 NULL-OR, :844
     * align-while, :851 IO-flag OR, :867 ava&&ava>0].
     * ================================================================== */
    {
        int sz;
        byte* aligned;
        byte* misaligned;

        WB_NOTE("wolfSSL_StaticBufferSz_ex(): NULL-arg OR [:833]");
        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList,
                s_bufGeneral, sizeof(s_bufGeneral), WOLFMEM_GENERAL);
        WB_CHECK(sz > 0, "baseline valid args succeeds (all-false vector)");

        ret = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList,
                NULL, sizeof(s_bufGeneral), WOLFMEM_GENERAL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buffer==NULL vector");

        ret = wolfSSL_StaticBufferSz_ex(3, NULL, s_distList,
                s_bufGeneral, sizeof(s_bufGeneral), WOLFMEM_GENERAL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sizeList==NULL vector");

        ret = wolfSSL_StaticBufferSz_ex(3, s_sizeList, NULL,
                s_bufGeneral, sizeof(s_bufGeneral), WOLFMEM_GENERAL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "distList==NULL vector");

        WB_NOTE("wolfSSL_StaticBufferSz_ex(): align-while [:844] + IO-flag OR [:851]");
        aligned = s_scratch;
        while (((wc_ptr_t)aligned) % WOLFSSL_STATIC_ALIGN != 0)
            aligned++;
        misaligned = aligned + 1;

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_GENERAL);
        WB_CHECK(sz > 0, "align-while F vector (already aligned)");

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, misaligned,
                (word32)(sizeof(s_scratch) - (misaligned - s_scratch)),
                WOLFMEM_GENERAL);
        WB_CHECK(sz > 0, "align-while TT vector (misaligned, ample room)");

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, misaligned,
                3, WOLFMEM_GENERAL);
        WB_CHECK(sz >= 0, "align-while TF vector (misaligned, tiny logical sz)");

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_IO_POOL);
        WB_CHECK(sz >= 0, "IO-flag OR: first true (WOLFMEM_IO_POOL)");

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_IO_POOL_FIXED);
        WB_CHECK(sz >= 0, "IO-flag OR: second true (WOLFMEM_IO_POOL_FIXED)");

        /* :867 `ava >= sizeList[0]+padSz+memSz && ava > 0` -- only the
         * first operand's independence is satisfiable (see RESIDUAL note
         * in the header comment): "true" vector (loop iterates, ample
         * buffer) and "false" vector (buffer smaller than one bucket). */
        WB_NOTE("wolfSSL_StaticBufferSz_ex(): ava-loop [:867] (residual: ava>0 dead, see header)");
        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, aligned,
                (word32)(sizeof(s_scratch) - (aligned - s_scratch)),
                WOLFMEM_GENERAL);
        WB_CHECK(sz > 0, "ava-loop first-operand true vector (reused)");

        sz = wolfSSL_StaticBufferSz_ex(3, s_sizeList, s_distList, aligned,
                4 /* smaller than sizeList[0]=64 + overhead */, WOLFMEM_GENERAL);
        WB_CHECK(sz == 0, "ava-loop first-operand false vector (buffer too small)");
    }

    /* ==================================================================
     * Section 4b -- wc_LoadStaticMemory_ex() NULL-arg OR [:717] and
     * IO-flag OR [:767]. The all-valid vectors below also build the three
     * "real" pools used for the rest of the file.
     * ================================================================== */
    WB_NOTE("wc_LoadStaticMemory_ex(): NULL-arg OR [:717] + IO-flag OR [:767]");

    ret = wc_LoadStaticMemory_ex(&hintGeneral, 3, s_sizeList, s_distList,
            s_bufGeneral, (unsigned int)sizeof(s_bufGeneral), WOLFMEM_GENERAL, 0);
    WB_CHECK(ret == 0, "Heap_General load (all-valid, IO-flag OR both-false)");

    ret = wc_LoadStaticMemory_ex(&hintIOPool, 3, s_sizeList, s_distList,
            s_bufIOPool, (unsigned int)sizeof(s_bufIOPool), WOLFMEM_IO_POOL, 0);
    WB_CHECK(ret == 0, "Heap_IOPool load (IO-flag OR first-true)");

    ret = wc_LoadStaticMemory_ex(&hintIOFixed, 3, s_sizeList, s_distList,
            s_bufIOFixed, (unsigned int)sizeof(s_bufIOFixed),
            WOLFMEM_IO_POOL_FIXED, 0);
    WB_CHECK(ret == 0, "Heap_IOFixed load (IO-flag OR second-true)");

    ret = wc_LoadStaticMemory_ex(NULL, 3, s_sizeList, s_distList,
            s_bufScratchLoad, (unsigned int)sizeof(s_bufScratchLoad),
            WOLFMEM_GENERAL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "pHint==NULL vector");

    {
        WOLFSSL_HEAP_HINT* hintScratch = NULL;
        ret = wc_LoadStaticMemory_ex(&hintScratch, 3, s_sizeList, s_distList,
                NULL, (unsigned int)sizeof(s_bufScratchLoad), WOLFMEM_GENERAL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buf==NULL vector");

        ret = wc_LoadStaticMemory_ex(&hintScratch, 3, NULL, s_distList,
                s_bufScratchLoad, (unsigned int)sizeof(s_bufScratchLoad),
                WOLFMEM_GENERAL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "sizeList==NULL vector");

        ret = wc_LoadStaticMemory_ex(&hintScratch, 3, s_sizeList, NULL,
                s_bufScratchLoad, (unsigned int)sizeof(s_bufScratchLoad),
                WOLFMEM_GENERAL, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "distList==NULL vector");
    }

    /* ==================================================================
     * Section 7 -- heap==NULL && globalHeapHint==NULL, driven identically
     * in wolfSSL_Malloc [:1013], wolfSSL_Free [:1201], wolfSSL_Realloc
     * [:1348]. Vectors: (heap=NULL,ghh=NULL)=TT ; (heap=NULL,ghh=pool)=TF ;
     * (heap=pool,ghh=NULL)=F (A independence pair vs the first vector).
     * ================================================================== */
    WB_NOTE("wolfSSL_Malloc/Free/Realloc: heap==NULL&&globalHeapHint==NULL [:1013,:1201,:1348]");

    (void)wolfSSL_SetGlobalHeapHint(NULL);
    WB_CHECK(wolfSSL_GetGlobalHeapHint() == NULL, "global heap hint reset");

    /* Malloc TT: native heap fallback. */
    p = wolfSSL_Malloc(32, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Malloc heap=NULL,ghh=NULL (TT) -> native malloc");
    /* Free TT (matching heap/ghh state): native heap fallback. */
    wolfSSL_Free(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Realloc TT: ptr==NULL short-circuits to native malloc(size) inside
     * the "ptr==NULL" pre-check, but only after evaluating :1348. */
    p = wolfSSL_Realloc(NULL, 48, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Realloc heap=NULL,ghh=NULL (TT)");
    wolfSSL_Free(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* TF vectors: heap=NULL, globalHeapHint=Heap_General -> false, routes
     * through the pool via the global hint. */
    (void)wolfSSL_SetGlobalHeapHint(hintGeneral);
    p = wolfSSL_Malloc(48, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Malloc heap=NULL,ghh=pool (TF) -> pool via global hint");
    wolfSSL_Free(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    p = wolfSSL_Realloc(NULL, 48, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Realloc heap=NULL,ghh=pool (TF)");
    wolfSSL_Free(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* A-independence companion: heap=Heap_General explicit, ghh reset to
     * NULL -> A false outright (heap!=NULL), same ghh state as the very
     * first (TT) vector above. */
    (void)wolfSSL_SetGlobalHeapHint(NULL);
    p = wolfSSL_Malloc(48, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Malloc heap=pool,ghh=NULL (F, A-independence) -> pool");
    wolfSSL_Free(p, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);

    p = wolfSSL_Realloc(NULL, 48, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(p != NULL, "Realloc heap=pool,ghh=NULL (F, A-independence)");
    wolfSSL_Free(p, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);

    /* ==================================================================
     * Section 8 -- IO_POOL_FIXED/IO_POOL && (OUT||IN) in Malloc [:1068,
     * :1083] and Free [:1257,:1263], and the combined OR in Realloc
     * [:1387].
     * ================================================================== */
    WB_NOTE("wolfSSL_Malloc/Free: IO_POOL_FIXED/IO_POOL && (OUT||IN) [:1068,:1083,:1257,:1263]");

    /* Wire up fixed IO buffers for Heap_IOFixed (needs >=2 IO buckets in
     * heap->io, guaranteed by the >=2x WOLFMEM_IO_SZ buffer size above). */
    WB_CHECK(SetFixedIO(hintIOFixed->memory, &hintIOFixed->outBuf) == 1,
            "SetFixedIO(outBuf) grabs a bucket");
    WB_CHECK(SetFixedIO(hintIOFixed->memory, &hintIOFixed->inBuf) == 1,
            "SetFixedIO(inBuf) grabs a bucket");

    /* :1068 IO_POOL_FIXED && (OUT||IN): true via OUT, true via IN (also
     * demonstrates the nested OR's two true arms), and true-outer/false-OR
     * via a third type on the same fixed-IO heap. */
    {
        void* outP = wolfSSL_Malloc(64, hintIOFixed, DYNAMIC_TYPE_OUT_BUFFER);
        void* inP  = wolfSSL_Malloc(64, hintIOFixed, DYNAMIC_TYPE_IN_BUFFER);
        void* tmpP = wolfSSL_Malloc(64, hintIOFixed, DYNAMIC_TYPE_TMP_BUFFER);

        WB_CHECK(outP == hintIOFixed->outBuf->buffer,
                ":1068 true via OUT_BUFFER (fixed IO)");
        WB_CHECK(inP == hintIOFixed->inBuf->buffer,
                ":1068 true via IN_BUFFER (fixed IO)");
        WB_CHECK(tmpP == NULL,
                ":1068 outer-true/nested-OR-false (TMP on fixed-IO heap, "
                "no general buckets exist there) -- also drives :1083 "
                "false (no WOLFMEM_IO_POOL bit set on this heap)");

        /* :1013's F vector reused Heap_General for alloc/free above; now
         * exercise the analogous "outer false" vector for :1068/:1083 on a
         * heap with neither IO bit set. */
        {
            void* genP = wolfSSL_Malloc(64, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
            WB_CHECK(genP != NULL,
                    ":1068/:1083 outer-false vector (WOLFMEM_GENERAL heap, "
                    "type==OUT) -- falls through to general bucket search");
            wolfSSL_Free(genP, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
        }

        /* :1083 true via OUT/IN on a heap flagged WOLFMEM_IO_POOL (not
         * FIXED), using Heap_IOPool's own io list (mem->io, not
         * outBuf/inBuf). */
        {
            void* ioOutP = wolfSSL_Malloc(64, hintIOPool, DYNAMIC_TYPE_OUT_BUFFER);
            void* ioInP  = wolfSSL_Malloc(64, hintIOPool, DYNAMIC_TYPE_IN_BUFFER);
            void* ioTmpP = wolfSSL_Malloc(64, hintIOPool, DYNAMIC_TYPE_TMP_BUFFER);

            WB_CHECK(ioOutP != NULL, ":1083 true via OUT_BUFFER (IO_POOL heap)");
            WB_CHECK(ioInP != NULL, ":1083 true via IN_BUFFER (IO_POOL heap)");
            WB_CHECK(ioTmpP == NULL,
                    ":1083 outer-true/nested-OR-false (TMP on IO_POOL heap)");

            /* -------------------------------------------------------
             * :1257/:1263 (wolfSSL_Free): reuse the pointers above. The
             * TF vectors deliberately pass a *different* pool's heap
             * hint than the one the pointer was allocated from -- see
             * the crash-safety note in the file header comment for why
             * this is safe (pt is derived from ptr's own arithmetic,
             * never from the heap argument).
             * ------------------------------------------------------- */
            WB_NOTE("wolfSSL_Free: IO_POOL_FIXED/IO_POOL&&sz==IO_SZ&&(OUT||IN) [:1257,:1263]");

            /* :1257 true via OUT, true via IN (fixed-IO heap, real
             * fixed-IO pointers). */
            wolfSSL_Free(outP, hintIOFixed, DYNAMIC_TYPE_OUT_BUFFER);
            wolfSSL_Free(inP, hintIOFixed, DYNAMIC_TYPE_IN_BUFFER);

            /* :1257 outer-true/nested-OR-false: fixed-IO heap flag, but a
             * TMP-typed pointer genuinely allocated from Heap_General
             * (safe: real memory, just re-labelled via the heap arg). */
            {
                void* genP2 = wolfSSL_Malloc(64, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
                WB_CHECK(genP2 != NULL, "general alloc for :1257/:1263 residual vectors");
                wolfSSL_Free(genP2, hintIOFixed, DYNAMIC_TYPE_TMP_BUFFER);
            }

            /* :1263 true via OUT, true via IN (IO_POOL heap, real IO
             * pointers with pt->sz == WOLFMEM_IO_SZ). */
            wolfSSL_Free(ioOutP, hintIOPool, DYNAMIC_TYPE_OUT_BUFFER);
            wolfSSL_Free(ioInP, hintIOPool, DYNAMIC_TYPE_IN_BUFFER);

            /* :1263 first-operand-false vector: IO_POOL heap flag clear
             * (use Heap_General instead), type==OUT. */
            {
                void* genP3 = wolfSSL_Malloc(64, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
                WB_CHECK(genP3 != NULL, "general alloc for :1263 first-operand vector");
                wolfSSL_Free(genP3, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
            }

            /* :1263 second-operand-false vector (pt->sz != WOLFMEM_IO_SZ):
             * IO_POOL heap flag set, but a general-sized (64-byte)
             * pointer, again borrowed from Heap_General -- sizeList is
             * shared across all three pools so the bookkeeping compare
             * against hintIOPool's sizeList[] is self-consistent. */
            {
                void* genP4 = wolfSSL_Malloc(64, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
                WB_CHECK(genP4 != NULL, "general alloc for :1263 second-operand vector");
                wolfSSL_Free(genP4, hintIOPool, DYNAMIC_TYPE_TMP_BUFFER);
            }

            /* :1263 third-operand-false vector (nested type OR false):
             * IO_POOL heap flag set, sz==IO_SZ (a real IO pointer), but
             * type is neither OUT nor IN -- allocate one more IO buffer
             * from Heap_IOPool's remaining io list first. */
            {
                void* ioP2 = wolfSSL_Malloc(64, hintIOPool, DYNAMIC_TYPE_OUT_BUFFER);
                if (ioP2 != NULL) {
                    wolfSSL_Free(ioP2, hintIOPool, DYNAMIC_TYPE_TMP_BUFFER);
                }
                else {
                    WB_NOTE("skip :1263 nested-OR-false vector: IO_POOL "
                            "bucket list exhausted in this run");
                }
            }
        }
    }

    /* :1387 wolfSSL_Realloc(): (C1=IO_POOL || C2=IO_POOL_FIXED) &&
     * (C3=OUT || C4=IN). wolfSSL_Malloc()'s IO_POOL_FIXED path
     * (`pt = hint->outBuf;` / `inBuf`) is idempotent -- it always hands
     * back the same fixed buffer rather than consuming it -- and
     * wolfSSL_Free()'s matching branch is a documented no-op ("fixed IO
     * pools are free'd at the end of SSL lifetime"), so hintIOFixed's
     * outBuf/inBuf pointers stay valid and reusable for every vector here.
     * All three vectors below are taken on the *same* heap (C1=F,C2=T
     * fixed) so C3/C4 can each be isolated while the other, and the outer
     * OR, stay constant: OUT(C3=T,C4=F)=true vs TMP(C3=F,C4=F)=false
     * isolates C3; IN(C3=F,C4=T)=true vs TMP(C3=F,C4=F)=false isolates C4.
     * A fourth vector (Heap_General, neither IO bit set) isolates
     * C1||C2 itself. */
    WB_NOTE("wolfSSL_Realloc: (IO_POOL||IO_POOL_FIXED)&&(OUT||IN) [:1387]");
    {
        void* outP = wolfSSL_Malloc(64, hintIOFixed, DYNAMIC_TYPE_OUT_BUFFER);
        void* inP  = wolfSSL_Malloc(64, hintIOFixed, DYNAMIC_TYPE_IN_BUFFER);
        WB_CHECK(outP != NULL && inP != NULL,
                "fixed-IO buffers available for :1387 vectors");

        {
            /* C3=T,C4=F (true): reallocing the OUT-typed fixed buffer. */
            void* r = wolfSSL_Realloc(outP, WOLFMEM_IO_SZ, hintIOFixed,
                    DYNAMIC_TYPE_OUT_BUFFER);
            WB_CHECK(r != NULL, ":1387 true via C2(IO_POOL_FIXED) + C3(OUT)");
        }
        {
            /* C3=F,C4=T (true): same heap, IN type instead of OUT. */
            void* r = wolfSSL_Realloc(inP, WOLFMEM_IO_SZ, hintIOFixed,
                    DYNAMIC_TYPE_IN_BUFFER);
            WB_CHECK(r != NULL, ":1387 true via C2(IO_POOL_FIXED) + C4(IN)");
        }
        {
            /* C3=F,C4=F (false): same heap, real pointer (outP), type
             * mismatched to neither OUT nor IN -- isolates both C3 and C4
             * against the two true vectors above (same C1,C2). Falls
             * through to the general-bucket search; whether that search
             * finds a candidate (it may, e.g. the 64-byte node the
             * :1257 residual vector above deliberately linked into
             * hintIOFixed->ava[]) is immaterial to *this* decision -- the
             * point is only that the (C1||C2)&&(C3||C4) AND evaluated
             * false and control reached the `else` branch, not what that
             * branch subsequently does. */
            void* r = wolfSSL_Realloc(outP, 64, hintIOFixed,
                    DYNAMIC_TYPE_TMP_BUFFER);
            WB_NOTE(":1387 false via nested-OR (C2 true, C3=C4=false) reached");
            if (r != NULL)
                wolfSSL_Free(r, hintIOFixed, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* C1||C2 both false (Heap_General): isolates C2 (and, paired with
         * the C1=T vector below, gives C1 a second independence witness). */
        {
            void* genP = wolfSSL_Malloc(64, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
            WB_CHECK(genP != NULL, "general alloc for :1387 outer-false vector");
            {
                void* r = wolfSSL_Realloc(genP, 100, hintGeneral,
                        DYNAMIC_TYPE_OUT_BUFFER);
                WB_CHECK(r != NULL, ":1387 false vector (WOLFMEM_GENERAL heap)");
                if (r != NULL)
                    wolfSSL_Free(r, hintGeneral, DYNAMIC_TYPE_OUT_BUFFER);
            }
        }

        /* C1=T,C2=F (Heap_IOPool, OUT type): pairs against the
         * C1=F,C2=F outer-false vector above (same C2=F) with C1 flipping
         * false->true and the outcome flipping false->true -- the
         * missing C1-independence pair. */
        {
            void* ioP = wolfSSL_Malloc(64, hintIOPool, DYNAMIC_TYPE_OUT_BUFFER);
            WB_CHECK(ioP != NULL, "IO_POOL alloc for :1387 C1 vector");
            if (ioP != NULL) {
                void* r = wolfSSL_Realloc(ioP, WOLFMEM_IO_SZ, hintIOPool,
                        DYNAMIC_TYPE_OUT_BUFFER);
                WB_CHECK(r != NULL, ":1387 true via C1(IO_POOL) + C3(OUT)");
                if (r != NULL)
                    wolfSSL_Free(r, hintIOPool, DYNAMIC_TYPE_OUT_BUFFER);
            }
        }
    }

    /* ==================================================================
     * Section 9 -- wolfSSL_Realloc() `pt != NULL && res == NULL` :1414.
     * Only the first operand's independence is satisfiable in the general
     * (non-IO) path -- see the RESIDUAL note in the header comment.
     * ================================================================== */
    WB_NOTE("wolfSSL_Realloc: pt!=NULL&&res==NULL [:1414] (residual: res==NULL always true here, see header)");
    {
        /* True vector: a same-or-larger bucket is available (fits the
         * 128-byte bucket), general path, res stays NULL, pt found. */
        void* genP = wolfSSL_Malloc(48, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
        WB_CHECK(genP != NULL, "alloc for :1414 true vector");
        {
            void* r = wolfSSL_Realloc(genP, 100, hintGeneral,
                    DYNAMIC_TYPE_TMP_BUFFER);
            WB_CHECK(r != NULL, ":1414 true vector (pt found, res stays NULL)");
            if (r != NULL)
                wolfSSL_Free(r, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* False vector (pt==NULL): request a size larger than every
         * bucket in sizeList[] (max 256) so the search loop never finds a
         * candidate. */
        {
            void* genP2 = wolfSSL_Malloc(48, hintGeneral, DYNAMIC_TYPE_TMP_BUFFER);
            WB_CHECK(genP2 != NULL, "alloc for :1414 false vector");
            {
                void* r = wolfSSL_Realloc(genP2, 100000, hintGeneral,
                        DYNAMIC_TYPE_TMP_BUFFER);
                WB_CHECK(r == NULL,
                        ":1414 false vector (pt==NULL, size exceeds all buckets)");
                /* genP2 itself was never handed back a new block (r==NULL
                 * per the pt==NULL path leaving `res` untouched), and the
                 * original allocation is still owned by the pool's
                 * bookkeeping (never unlinked since no matching bucket was
                 * found) -- nothing to free here without risking a double
                 * use of a still-"allocated" node. */
            }
        }
    }

    /* ==================================================================
     * Section 5 -- wc_UnloadStaticMemory() `heap != NULL &&
     * heap->memory != NULL` :801. Heap_IOFixed's mutex is destroyed by the
     * TT vector, so it is exercised last and hintIOFixed is not touched
     * again afterward.
     * ================================================================== */
    WB_NOTE("wc_UnloadStaticMemory(): heap!=NULL && heap->memory!=NULL [:801]");

    wc_UnloadStaticMemory(NULL); /* F vector: heap==NULL, short circuit */

    {
        WOLFSSL_HEAP_HINT fakeHint;
        XMEMSET(&fakeHint, 0, sizeof(fakeHint));
        fakeHint.memory = NULL;
        wc_UnloadStaticMemory(&fakeHint); /* TF vector: heap!=NULL, memory==NULL */
    }

    wc_UnloadStaticMemory(hintIOFixed); /* TT vector: real, initialized mutex */

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
#else
    printf("  USE_WOLFSSL_MEMORY / WOLFSSL_STATIC_MEMORY not defined; "
           "nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
