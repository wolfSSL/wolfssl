/* quickassist_mem.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_INTEL_QA
#include <wolfssl/wolfcrypt/types.h>

#include <wolfssl/wolfcrypt/port/intel/quickassist_mem.h>
#include <wolfssl/wolfcrypt/async.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* use thread local for QAE variables (removing mutex requirement) */
#include <pthread.h> /* for threadId tracking */
#ifdef USE_QAE_THREAD_LS
    #define QAE_THREAD_LS THREAD_LS_T
#else
    #define QAE_THREAD_LS
#endif

/* these are used to align memory to a byte boundary */
#define ALIGNMENT_BASE     (16ul)
#define ALIGNMENT_HW       (64ul)
#define WOLF_MAGIC_NUM      0xA576F6C6641736EBUL /* (0xA)WolfAsyn(0xB) */
#define WOLF_HEADER_ALIGN   ALIGNMENT_BASE

#ifndef QAT_V2
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#ifdef SAL_IOMMU_CODE
    #include <icp_sal_iommu.h>
#endif

/* enable fixed static memory instead of dynamic list */
#ifdef USE_QAE_STATIC_MEM
    /* adjustable parameter for the maximum memory allocations */
    #ifndef QAE_USER_MEM_MAX_COUNT
        #define QAE_USER_MEM_MAX_COUNT  16000
    #endif
    #define MEM_INVALID_IDX -1
#endif

#define QAE_MEM             "/dev/qae_mem"
#define PAGE_SHIFT          13
#define PAGE_SIZE           (1UL << PAGE_SHIFT)
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define SYSTEM_PAGE_SHIFT   12
#define SYSTEM_PAGE_SIZE    (1UL << SYSTEM_PAGE_SHIFT)
#define SYSTEM_PAGE_MASK    (~(SYSTEM_PAGE_SIZE-1))
#define USER_MEM_OFFSET     (128)
#define QAEM_MAGIC_NUM      0xABCD12345678ECDFUL

/* define types which need to vary between 32 and 64 bit */
#ifdef __x86_64__
    #define QAE_UINT  Cpa64U
    #define QAE_INT   Cpa64S
#else
    #define QAE_UINT  Cpa32U
    #define QAE_INT   Cpa32S
#endif

/* IOCTL number for use between the kernel and the user space application */
#define DEV_MEM_MAGIC               'q'
#define DEV_MEM_CMD_MEMALLOC        (0)
#define DEV_MEM_CMD_MEMFREE         (1)

/* IOCTL commands for requesting kernel memory */
#define DEV_MEM_IOC_MEMALLOC \
        _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMALLOC, qae_dev_mem_info_t)

#define DEV_MEM_IOC_MEMFREE \
        _IOWR(DEV_MEM_MAGIC, DEV_MEM_CMD_MEMFREE, qae_dev_mem_info_t)


/* local structures */
#pragma pack(push)
#pragma pack(1)
typedef struct qae_dev_mem_info_s {
    union {
        struct qae_dev_mem_info_s *pPrev;
        uint64_t padding_pPrev;
    };
    union {
        struct qae_dev_mem_info_s *pNext;
        uint64_t padding_pNext;
    };
    uint32_t id;
    /* Id of this block */
    uint32_t nodeId;
    /* Node id for NUMA */
    uint32_t size;
    /* Size of this block (bytes) */
    uint32_t available_size;
    /* Available size remained on the page */
    uint16_t allocations;
    /* Counter keeping track of number of allocations */
    union {
        void *kmalloc_ptr;
        uint64_t padding_kmalloc_ptr;
    };
    /* Pointer to mem originally returned by kmalloc */
    union {
        int32_t *kmalloc_area;
        uint64_t padding_kamalloc_area;
    };
    /* Pointer to kmalloc'd area rounded up to a page boundary */
    uint64_t phy_addr;
    /* Physical address of the kmalloc area */
    union {
        void *virt_addr;
        uint64_t padding_virt_addr;
    };
    /* Base address in user space - i.e. virtual address */
} qae_dev_mem_info_t;

#ifdef USE_QAE_STATIC_MEM
    typedef struct qae_dev_mem_info_ex_s {
        qae_dev_mem_info_t mem_info;
        int index; /* Index into g_pUserMemList */
    } qae_dev_mem_info_ex_t;
#else
    typedef qae_dev_mem_info_t qae_dev_mem_info_ex_t;
#endif

#pragma pack(pop)

#endif /* QAT_V2 */


#define QAE_NOT_NUMA_PAGE 0xFFFF
typedef struct qaeMemHeader {
#ifdef WOLFSSL_TRACK_MEMORY
    struct qaeMemHeader* next;
    struct qaeMemHeader* prev;
    #ifdef WOLFSSL_DEBUG_MEMORY
        const char* func;
        unsigned int line;
    #endif
#endif
    uint64_t magic;
    void* heap;
#ifdef USE_QAE_THREAD_LS
    pthread_t threadId;
#endif
    size_t size;
    word16 count;
    word16 isNuma:1;
    word16 reservedBits:15; /* use for future bits */
    word16 type;
    word16 numa_page_offset; /* use QAE_NOT_NUMA_PAGE if not NUMA */
} ALIGN16 qaeMemHeader;

#ifdef WOLFSSL_TRACK_MEMORY
    typedef struct qaeMemStats {
        long totalAllocs;     /* number of allocations */
        long totalDeallocs;   /* number of deallocations */
        long totalBytes;      /* total number of bytes allocated */
        long peakBytes;       /* concurrent max bytes */
        long currentBytes;    /* total current bytes in use */
    } qaeMemStats;

    /* track allocations and report at end */
    typedef struct qaeMemList {
        qaeMemHeader* head;
        qaeMemHeader* tail;
        uint32_t count;
    } qaeMemList;
#endif /* WOLFSSL_TRACK_MEMORY */


/* local variables */
#ifndef USE_QAE_THREAD_LS
    static pthread_mutex_t g_memLock = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifndef QAT_V2
#ifdef USE_QAE_STATIC_MEM
    /* Use an array instead of a list */
    static QAE_THREAD_LS qae_dev_mem_info_ex_t*
        g_pUserMemList[QAE_USER_MEM_MAX_COUNT];
    /* cache the available sizes to improve userMemLookupBySize performance */
    static QAE_THREAD_LS uint16_t g_avail_size[QAE_USER_MEM_MAX_COUNT];
    /* Count of items in g_pUserMemList and g_avail_size */
    static QAE_THREAD_LS int g_userMemListCount = 0;
    static QAE_THREAD_LS int g_lastIndexBySize = 0;
#else
    static QAE_THREAD_LS qae_dev_mem_info_t *g_pUserMemList = NULL;
    static QAE_THREAD_LS qae_dev_mem_info_t *g_pUserMemListHead = NULL;
#endif

static int g_qaeMemFd = -1;
#endif /* !QAT_V2 */

#ifdef WOLFSSL_TRACK_MEMORY
    static qaeMemStats g_memStats;
    static qaeMemList g_memList;
    static pthread_mutex_t g_memStatLock = PTHREAD_MUTEX_INITIALIZER;
#endif

/* forward declarations */
#ifndef QAT_V2
static void* qaeMemAllocNUMA(Cpa32U size, Cpa32U node, Cpa32U alignment,
    word16* p_page_offset);
static void qaeMemFreeNUMA(void** ptr, word16 page_offset);
#endif

static WC_INLINE int qaeMemTypeIsNuma(int type)
{
    int isNuma = 0;

    switch (type) {
        case DYNAMIC_TYPE_ASYNC_NUMA:
        case DYNAMIC_TYPE_ASYNC_NUMA64:
        case DYNAMIC_TYPE_WOLF_BIGINT:
        case DYNAMIC_TYPE_PRIVATE_KEY:
        case DYNAMIC_TYPE_PUBLIC_KEY:
        case DYNAMIC_TYPE_AES_BUFFER:
        case DYNAMIC_TYPE_RSA_BUFFER:
        case DYNAMIC_TYPE_ECC_BUFFER:
        case DYNAMIC_TYPE_SIGNATURE:
        case DYNAMIC_TYPE_DIGEST:
        case DYNAMIC_TYPE_SECRET:
        case DYNAMIC_TYPE_SEED:
        case DYNAMIC_TYPE_SALT:
        {
            isNuma = 1;
            break;
        }
        case DYNAMIC_TYPE_OUT_BUFFER:
        case DYNAMIC_TYPE_IN_BUFFER:
        {
        #if !defined(WC_ASYNC_NO_CRYPT) && !defined(WC_ASYNC_NO_HASH)
            isNuma = 1;
        #else
            isNuma = 0;
        #endif
            break;
        }
        default:
            isNuma = 0;
            break;
    }
    return isNuma;
}


static void _qaeMemFree(void *ptr, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
)
{
    qaeMemHeader* header = NULL;
    size_t size;
    void* origPtr = ptr;

    if (ptr == NULL)
        return;

    /* adjust for header and align */
    ptr = (byte*)(((size_t)ptr - ((size_t)ptr % WOLF_HEADER_ALIGN)) -
        sizeof(qaeMemHeader));
    header = (qaeMemHeader*)ptr;

    /* check for header magic */
    if (header->magic != WOLF_MAGIC_NUM) {
        printf("Free: Header magic not found! %p\n", ptr);
        return;
    }

    /* cache values for later */
    size = header->size;

#ifdef WOLFSSL_DEBUG_MEMORY
#ifdef WOLFSSL_DEBUG_MEMORY_PRINT
    printf("Free: %p (%u) at %s:%d, heap %p, type %d, count %d\n",
        origPtr, (unsigned int)size, func, line, heap, type, header->count);
#else
    (void)func;
    (void)line;
#endif
#endif
    (void)type;

    /* adjust free count */
    header->count--;

    /* check header count */
    if (header->count > 0) {
        /* go ahead and return if still in use */
        return;
    }

#ifdef WOLFSSL_TRACK_MEMORY
    if (pthread_mutex_lock(&g_memStatLock) == 0) {
        g_memStats.currentBytes -= size;
        g_memStats.totalDeallocs++;

        if (header == g_memList.head && header == g_memList.tail) {
            g_memList.head = NULL;
            g_memList.tail = NULL;
        }
        else if (header == g_memList.head) {
            g_memList.head = header->next;
            g_memList.head->prev = NULL;
        }
        else if (header == g_memList.tail) {
            g_memList.tail = header->prev;
            g_memList.tail->next = NULL;
        }
        else {
            qaeMemHeader* next = header->next;
            qaeMemHeader* prev = header->prev;
            if (next)
                next->prev = prev;
            if (prev)
                prev->next = next;
        }
        g_memList.count--;

        pthread_mutex_unlock(&g_memStatLock);
    }
#endif

    (void)heap;
    (void)size;
    (void)origPtr;

#ifdef WOLFSSL_DEBUG_MEMORY
    /* make sure magic is gone */
    header->magic = 0;
#endif

    /* free type */
    if (header->isNuma && header->numa_page_offset != QAE_NOT_NUMA_PAGE) {
    #ifdef QAT_V2
        qaeMemFreeNUMA(&ptr);
    #else
        qaeMemFreeNUMA(&ptr, header->numa_page_offset);
    #endif
    }
    else {
        free(ptr);
    }
}


static void* _qaeMemAlloc(size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
)
{
    void* ptr = NULL;
    qaeMemHeader* header = NULL;
    int isNuma;
    int alignment = ALIGNMENT_BASE;
    word16 page_offset = QAE_NOT_NUMA_PAGE;

    /* make sure all allocations are aligned */
    if ((size % WOLF_HEADER_ALIGN) != 0) {
        size += (WOLF_HEADER_ALIGN - (size % WOLF_HEADER_ALIGN));
    }

    isNuma = qaeMemTypeIsNuma(type);
    if (type == DYNAMIC_TYPE_ASYNC_NUMA64)
        alignment = ALIGNMENT_HW;

    /* allocate type */
    if (isNuma) {
        /* Node is typically 0 */
    #ifdef QAT_V2
        page_offset = 0;
        ptr = qaeMemAllocNUMA((Cpa32U)(size + sizeof(qaeMemHeader)), 0,
            alignment);
    #else
        ptr = qaeMemAllocNUMA((Cpa32U)(size + sizeof(qaeMemHeader)), 0,
            alignment, &page_offset);
    #endif
    }
    else {
        isNuma = 0;
        ptr = malloc(size + sizeof(qaeMemHeader));
    }

    /* add header */
    if (ptr) {
        header = (qaeMemHeader*)ptr;
        ptr = (byte*)ptr + sizeof(qaeMemHeader);
        header->magic = WOLF_MAGIC_NUM;
        header->heap = heap;
        header->size = size;
        header->type = type;
        header->count = 1;
        header->isNuma = isNuma;
        header->numa_page_offset = page_offset;
    #ifdef USE_QAE_THREAD_LS
        header->threadId = pthread_self();
    #endif

    #ifdef WOLFSSL_TRACK_MEMORY
        if (pthread_mutex_lock(&g_memStatLock) == 0) {
            g_memStats.totalAllocs++;
            g_memStats.totalBytes   += size;
            g_memStats.currentBytes += size;
            if (g_memStats.currentBytes > g_memStats.peakBytes)
                g_memStats.peakBytes = g_memStats.currentBytes;

        #ifdef WOLFSSL_DEBUG_MEMORY
            header->func = func;
            header->line = line;
        #endif

            /* Setup event */
            header->next = NULL;
            if (g_memList.tail == NULL)  {
                g_memList.head = header;
            }
            else {
                g_memList.tail->next = header;
                header->prev = g_memList.tail;
            }
            g_memList.tail = header;      /* add to the end either way */
            g_memList.count++;

            pthread_mutex_unlock(&g_memStatLock);
        }
    #endif
    }

#ifdef WOLFSSL_DEBUG_MEMORY
#ifdef WOLFSSL_DEBUG_MEMORY_PRINT
    printf("Alloc: %p (%u) at %s:%d, heap %p, type %d\n",
        ptr, (unsigned int)size, func, line, heap, type);
#else
    (void)func;
    (void)line;
#endif
#endif

    (void)heap;

    return ptr;
}

/* Public Functions */
void* IntelQaMalloc(size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
)
{
    void* ptr;

#ifndef USE_QAE_THREAD_LS
    int ret = pthread_mutex_lock(&g_memLock);
    if (ret != 0) {
        printf("Alloc: Error(%d) on mutex lock\n", ret);
        return NULL;
    }
#endif

    ptr = _qaeMemAlloc(size, heap, type
    #ifdef WOLFSSL_DEBUG_MEMORY
        , func, line
    #endif
    );

#ifndef USE_QAE_THREAD_LS
    pthread_mutex_unlock(&g_memLock);
#endif

    return ptr;
}

void IntelQaFree(void *ptr, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
)
{
#ifndef USE_QAE_THREAD_LS
    int ret = pthread_mutex_lock(&g_memLock);
    if (ret != 0) {
        printf("Free: Error(%d) on mutex lock\n", ret);
        return;
    }
#endif

    _qaeMemFree(ptr, heap, type
    #ifdef WOLFSSL_DEBUG_MEMORY
        , func, line
    #endif
    );

#ifndef USE_QAE_THREAD_LS
    pthread_mutex_unlock(&g_memLock);
#endif
}

void* IntelQaRealloc(void *ptr, size_t size, void* heap, int type
#ifdef WOLFSSL_DEBUG_MEMORY
    , const char* func, unsigned int line
#endif
)
{
    void* newPtr = NULL;
    void* origPtr = ptr;
    qaeMemHeader* header = NULL;
    byte allocNew = 1;
    int newIsNuma = -1, ptrIsNuma = -1;
    size_t copySize = 0;

#ifndef USE_QAE_THREAD_LS
    int ret = pthread_mutex_lock(&g_memLock);
    if (ret != 0) {
        printf("Realloc: Error(%d) on mutex lock\n", ret);
        return NULL;
    }
#endif

    (void)heap;

    if (ptr) {
        /* get header pointer and align */
        header = (qaeMemHeader*)(((size_t)ptr -
            ((size_t)ptr % WOLF_HEADER_ALIGN)) - sizeof(qaeMemHeader));
        if (header->magic == WOLF_MAGIC_NUM) {
            newIsNuma = qaeMemTypeIsNuma(type);
            ptrIsNuma = (header->numa_page_offset != QAE_NOT_NUMA_PAGE) ? 1 : 0;

            /* for non-NUMA, treat as normal REALLOC */
            if (newIsNuma == 0 && ptrIsNuma == 0) {
                allocNew = 1;
            }
            /* confirm input is aligned, otherwise allocate new */
            else if (((size_t)ptr % WOLF_HEADER_ALIGN) != 0) {
                allocNew = 1;
            }
            /* if matching NUMA type and size fits, use existing */
            else if (newIsNuma == ptrIsNuma && header->size >= size) {

            #ifdef USE_QAE_THREAD_LS
                if (header->threadId != pthread_self()) {
                    allocNew = 1;
                #if 0
                    printf("Realloc %p from different thread! "
                           "orig %lx this %lx\n",
                        origPtr, header->threadId, pthread_self());
                #endif
                }
                else
            #endif
                {
                    /* use existing pointer and increment counter */
                    header->count++;
                    newPtr = origPtr;
                    allocNew = 0;
                }
            }

            copySize = header->size;
        }
        else {
            copySize = size;
        }
    }

    if (allocNew) {
        newPtr = _qaeMemAlloc(size, heap, type
        #ifdef WOLFSSL_DEBUG_MEMORY
            , func, line
        #endif
        );
        if (newPtr && ptr) {
            /* only copy min of new and old size to new pointer */
            if (copySize > size)
                copySize = size;
            XMEMCPY(newPtr, ptr, copySize);

            if (newIsNuma == 0 && ptrIsNuma == 0) {
                /* for non-NUMA, treat as normal REALLOC and free old pointer */
                _qaeMemFree(ptr, heap, type
                #ifdef WOLFSSL_DEBUG_MEMORY
                    , func, line
                #endif
                );
            }
        }
    }

#ifndef USE_QAE_THREAD_LS
    pthread_mutex_unlock(&g_memLock);
#endif

#ifdef WOLFSSL_DEBUG_MEMORY
#ifdef WOLFSSL_DEBUG_MEMORY_PRINT
    if (allocNew) {
        printf("Realloc: New %p -> %p (%u) at %s:%d, heap %p, type %d\n",
            origPtr, newPtr, (unsigned int)size, func, line, heap, type);
    }
    else {
        printf("Realloc: Reuse %p (%u) at %s:%d, heap %p, type %d, count %d\n",
             origPtr, (unsigned int)size, func, line,
             header->heap, header->type, header->count);
    }
#else
    (void)func;
    (void)line;
#endif
#endif

    return newPtr;
}


#ifdef WOLFSSL_TRACK_MEMORY
int InitMemoryTracker(void)
{
    if (pthread_mutex_lock(&g_memStatLock) == 0) {
        g_memStats.totalAllocs  = 0;
        g_memStats.totalDeallocs= 0;
        g_memStats.totalBytes   = 0;
        g_memStats.peakBytes    = 0;
        g_memStats.currentBytes = 0;

        XMEMSET(&g_memList, 0, sizeof(g_memList));

        pthread_mutex_unlock(&g_memStatLock);
    }

    return 0;
}

void ShowMemoryTracker(void)
{
    if (pthread_mutex_lock(&g_memStatLock) == 0) {
        printf("total   Allocs = %9ld\n", g_memStats.totalAllocs);
        printf("total Deallocs = %9ld\n", g_memStats.totalDeallocs);
        printf("total    Bytes = %9ld\n", g_memStats.totalBytes);
        printf("peak     Bytes = %9ld\n", g_memStats.peakBytes);
        printf("current  Bytes = %9ld\n", g_memStats.currentBytes);

        if (g_memList.count > 0) {

            /* print list of allocations */
            qaeMemHeader* header;
            for (header = g_memList.head;
                 header != NULL;
                 header = header->next) {
                printf("Leak: Ptr %p, Size %u, Type %d, Heap %p"
                #ifdef WOLFSSL_DEBUG_MEMORY
                    ", Func %s, Line %d"
                #endif
                    "\n",
                    (byte*)header + sizeof(qaeMemHeader),
                    (unsigned int)header->size,
                    header->type, header->heap
                #ifdef WOLFSSL_DEBUG_MEMORY
                    , header->func, header->line
                #endif
                );
            }
        }

        pthread_mutex_unlock(&g_memStatLock);

        /* cleanup lock */
        pthread_mutex_destroy(&g_memStatLock);
    }
}
#endif /* WOLFSSL_TRACK_MEMORY */



/**************************************
 * Memory functions
 *************************************/

#ifndef QAT_V2

CpaStatus qaeMemInit(void)
{
    if (g_qaeMemFd < 0) {
    #ifndef QAT_V2
        g_qaeMemFd = open(QAE_MEM, O_RDWR);
        if (g_qaeMemFd < 0) {
            printf("unable to open %s %d\n", QAE_MEM, g_qaeMemFd);
            return CPA_STATUS_FAIL;
        }
    #endif
    }

    return CPA_STATUS_SUCCESS;
}

void qaeMemDestroy(void)
{
    close(g_qaeMemFd);
    g_qaeMemFd = -1;
}

#ifdef USE_QAE_STATIC_MEM

static CpaStatus userMemListAdd(qae_dev_mem_info_t *pMemInfo)
{
    qae_dev_mem_info_ex_t* pMemInfoEx =
        (qae_dev_mem_info_ex_t*)pMemInfo->virt_addr;

    if (g_userMemListCount >= QAE_USER_MEM_MAX_COUNT) {
        return MEM_INVALID_IDX;
    }
    g_pUserMemList[g_userMemListCount] = pMemInfoEx;
    g_avail_size[g_userMemListCount] = pMemInfoEx->mem_info.available_size;
    g_lastIndexBySize = g_userMemListCount;
    g_userMemListCount++;
    return CPA_STATUS_SUCCESS;
}

static void userMemListFree(qae_dev_mem_info_t *pMemInfo, int memIdx)
{
    if (memIdx < 0 || memIdx >= g_userMemListCount ||
            g_userMemListCount >= QAE_USER_MEM_MAX_COUNT) {
        return;
    }

    if (memIdx < g_userMemListCount - 1) {
        /* Replace the deleted index with the last one */
        g_pUserMemList[memIdx] = g_pUserMemList[g_userMemListCount - 1];
        g_avail_size[memIdx] = g_avail_size[g_userMemListCount - 1];

        g_pUserMemList[memIdx]->index = memIdx;
    }
    g_userMemListCount--;
    (void)pMemInfo;
}

static qae_dev_mem_info_t* userMemLookupBySize(Cpa32U size, int* pMemIdx)
{
    int memIdx;
    int count = g_userMemListCount;
    int lastIndex = g_lastIndexBySize;
    uint16_t *available_size = g_avail_size;

    for (memIdx = lastIndex; memIdx < count; memIdx++) {
        if (available_size[memIdx] >= size) {
            g_lastIndexBySize = memIdx;
            if (pMemIdx)
                *pMemIdx = memIdx;
            return (qae_dev_mem_info_t *)g_pUserMemList[memIdx];
        }
    }
    for (memIdx = 0; memIdx < lastIndex && memIdx < count; memIdx++) {
        if (available_size[memIdx] >= size) {
            g_lastIndexBySize = memIdx;
            if (pMemIdx)
                *pMemIdx = memIdx;
            return (qae_dev_mem_info_t *)g_pUserMemList[memIdx];
        }
    }

    return NULL;
}

static qae_dev_mem_info_t* userMemLookupByVirtAddr(void* virt_addr,
    uint32_t page_offset, int* pMemIdx)
{
    qae_dev_mem_info_ex_t *pMemInfoEx = NULL;
    void *pageVirtAddr;
    int memIdx;

    /* Find the base page virtual address */
    pageVirtAddr = (void *)(((QAE_UINT)virt_addr & SYSTEM_PAGE_MASK) -
        (page_offset << SYSTEM_PAGE_SHIFT));
    pMemInfoEx = (qae_dev_mem_info_ex_t*)pageVirtAddr;

    /* Find the index in g_pUserMemList stored directly in
     * qae_dev_mem_info_ex_t */
    memIdx = pMemInfoEx->index;
    if (memIdx < 0 || memIdx >= g_userMemListCount) {
        printf("userMemIndex out of bounds: %d\n", memIdx);
        return NULL;
    }

    if (g_pUserMemList[memIdx] != pMemInfoEx) {
        printf("userMemIndex virtual address mismatch (memIdx = %d, %p)\n",
            memIdx, pageVirtAddr);
        return NULL;
    }

    if (pMemIdx)
        *pMemIdx = memIdx;

    return (qae_dev_mem_info_t*)pMemInfoEx;
}

#else

static CpaStatus userMemListAdd(qae_dev_mem_info_t *pMemInfo)
{
    if (g_pUserMemList == NULL) {
        g_pUserMemList = pMemInfo;
        pMemInfo->pNext = NULL;
        pMemInfo->pPrev = NULL;
        g_pUserMemListHead = g_pUserMemList;
    }
    else {
        pMemInfo->pPrev = g_pUserMemList;
        g_pUserMemList->pNext = pMemInfo;
        pMemInfo->pNext = NULL;
        g_pUserMemList = pMemInfo;
    }

    return CPA_STATUS_SUCCESS;
}

static void userMemListFree(qae_dev_mem_info_t *pMemInfo)
{
    qae_dev_mem_info_t *pCurr = NULL;
    for (pCurr = g_pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext) {
        if (pCurr == pMemInfo) {
            /* If the previous pointer is not NULL */
            if (pCurr->pPrev != NULL) {
                pCurr->pPrev->pNext = pCurr->pNext;
                if (pCurr->pNext) {
                    pCurr->pNext->pPrev = pCurr->pPrev;
                } else {
                    g_pUserMemList = pCurr->pPrev;
                }
            } else if (pCurr->pNext != NULL) {
                pCurr->pNext->pPrev = NULL;
                g_pUserMemListHead = pCurr->pNext;
            } else {
                g_pUserMemList = NULL;
                g_pUserMemListHead = NULL;
            }
            break;
        }
    }
}


static qae_dev_mem_info_t* userMemLookupBySize(Cpa32U size)
{
    qae_dev_mem_info_t *pCurr = NULL;
    for (pCurr = g_pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext) {
        if (pCurr->available_size >= size) {
            return pCurr;
        }
    }
    return NULL;
}

static qae_dev_mem_info_t* userMemLookupByVirtAddr(void* virt_addr,
    uint32_t page_offset)
{
    qae_dev_mem_info_t *pCurr = NULL;
    for (pCurr = g_pUserMemListHead; pCurr != NULL; pCurr = pCurr->pNext) {
        if ((QAE_UINT)pCurr->virt_addr <= (QAE_UINT)virt_addr &&
           ((QAE_UINT)pCurr->virt_addr + pCurr->size) > (QAE_UINT)virt_addr) {
            return pCurr;
        }
    }
    (void)page_offset;
    return NULL;
}

#endif


static void* qaeMemAllocNUMA(Cpa32U size, Cpa32U node, Cpa32U alignment,
    word16* p_page_offset)
{
    int ret = 0;
    qae_dev_mem_info_t* pMemInfo = NULL;
    void* pVirtAddress = NULL;
    void* pOriginalAddress = NULL;
    QAE_UINT padding = 0;
    QAE_UINT aligned_address = 0;
    const uint64_t magic = QAEM_MAGIC_NUM;
#ifdef USE_QAE_STATIC_MEM
    int memIdx;
    qae_dev_mem_info_t memInfo;
    qae_dev_mem_info_ex_t* pMemInfoEx;
#endif

    if (size == 0 || alignment == 0) {
        printf("Invalid size or alignment parameter\n");
        return NULL;
    }
    if (g_qaeMemFd < 0) {
        qaeMemInit();
    }

    if ( (pMemInfo = userMemLookupBySize(size + alignment
        #ifdef USE_QAE_STATIC_MEM
            , &memIdx
        #endif
        )) != NULL)
    {
        /* calculate address */
        pOriginalAddress = (void*)((QAE_UINT)pMemInfo->virt_addr +
            (QAE_UINT)(pMemInfo->size - pMemInfo->available_size));
        /* calculate aligned address */
        padding = (QAE_UINT)pOriginalAddress % alignment;
        aligned_address = ((QAE_UINT)pOriginalAddress) - padding + alignment;

        /* reduce available size */
        pMemInfo->available_size -= (size + (aligned_address -
            (QAE_UINT)pOriginalAddress));
        pMemInfo->allocations += 1;

    #ifdef USE_QAE_STATIC_MEM
        /* cache index's available size */
        g_avail_size[memIdx] = pMemInfo->available_size;
    #endif

        *p_page_offset = (word16)(
             (QAE_UINT)aligned_address >> SYSTEM_PAGE_SHIFT) -
            ((QAE_UINT)pMemInfo->virt_addr >> SYSTEM_PAGE_SHIFT);

        return (void*)aligned_address;
    }

#ifdef USE_QAE_STATIC_MEM
    pMemInfo = &memInfo;
#else
    pMemInfo = malloc(sizeof(qae_dev_mem_info_t));
    if (pMemInfo == NULL) {
        printf("unable to allocate pMemInfo buffer\n");
        return NULL;
    }
#endif

    pMemInfo->allocations = 0;
    pMemInfo->size = USER_MEM_OFFSET + size;
    pMemInfo->size = pMemInfo->size % PAGE_SIZE ?
            ((pMemInfo->size / PAGE_SIZE) + 1) * PAGE_SIZE :
            pMemInfo->size;
#ifdef SAL_IOMMU_CODE
    pMemInfo->size = icp_sal_iommu_get_remap_size(pMemInfo->size);
#endif
    pMemInfo->nodeId = node;

    ret = ioctl(g_qaeMemFd, DEV_MEM_IOC_MEMALLOC, pMemInfo);
    if (ret != 0) {
        printf("ioctl call failed: ret %d, errno %d (%s)\n",
            ret, errno, strerror(errno));
        return NULL;
    }

    pMemInfo->virt_addr = mmap((caddr_t)0, pMemInfo->size,
            PROT_READ|PROT_WRITE, MAP_SHARED, g_qaeMemFd,
            (pMemInfo->id * getpagesize()));

    if (pMemInfo->virt_addr == (caddr_t)MAP_FAILED) {
        printf("mmap failed\n");
        ret = ioctl(g_qaeMemFd, DEV_MEM_IOC_MEMFREE, pMemInfo);
        if (ret != 0) {
            printf("ioctl call failed: ret %d, errno %d (%s)\n",
                ret, errno, strerror(errno));
        }
    #ifndef USE_QAE_STATIC_MEM
        free(pMemInfo);
    #endif
        return NULL;
    }

    pMemInfo->available_size = pMemInfo->size - size - USER_MEM_OFFSET;
    pMemInfo->allocations = 1;
    memcpy(pMemInfo->virt_addr, pMemInfo, sizeof(qae_dev_mem_info_t));
#ifdef USE_QAE_STATIC_MEM
    pMemInfoEx = (qae_dev_mem_info_ex_t *)pMemInfo->virt_addr;
    pMemInfoEx->index = g_userMemListCount;
#endif
    memcpy(pMemInfo->virt_addr, &magic, sizeof(uint64_t));
    pVirtAddress = (void *)((QAE_UINT)pMemInfo->virt_addr
            + USER_MEM_OFFSET);

    if (userMemListAdd(pMemInfo) != CPA_STATUS_SUCCESS) {
        printf("Error on mem list add\n");
    #ifndef USE_QAE_STATIC_MEM
        free(pMemInfo);
    #endif
        return NULL;
    }

    *p_page_offset = 0;
    return pVirtAddress;
}

static void qaeMemFreeNUMA(void** ptr, word16 page_offset)
{
    int ret = 0;
    qae_dev_mem_info_t *pMemInfo = NULL;
    void* pVirtAddress = NULL;
#ifdef USE_QAE_STATIC_MEM
    qae_dev_mem_info_t memInfo; /* temp buffer */
    int memIdx;
#endif

    if (ptr == NULL)
        return;

    pVirtAddress = *ptr;
    if (pVirtAddress == NULL) {
        printf("qaeMemFreeNUMA: Invalid virtual address\n");
        return;
    }

    if ((pMemInfo = userMemLookupByVirtAddr(pVirtAddress, page_offset
        #ifdef USE_QAE_STATIC_MEM
            , &memIdx
        #endif
       )) != NULL)
    {
        pMemInfo->allocations -= 1;

    #ifdef USE_QAE_STATIC_MEM
        if (memIdx < QAE_USER_MEM_MAX_COUNT && pMemInfo->allocations == 0) {
            pMemInfo->available_size = pMemInfo->size - USER_MEM_OFFSET;
            g_avail_size[memIdx] = pMemInfo->available_size;
        }
    #endif

        if (pMemInfo->allocations != 0
            #ifdef USE_QAE_STATIC_MEM
                || memIdx < QAE_USER_MEM_MAX_COUNT
            #endif
        ) {
            *ptr = NULL;
            return;
        }
    }
    else {
        printf("userMemLookupByVirtAddr failed\n");
        return;
    }

#ifdef USE_QAE_STATIC_MEM
    /* use a temp copy of memory info */
    memInfo = *pMemInfo;
    userMemListFree(pMemInfo->virt_addr, memIdx);
    pMemInfo = &memInfo;
#endif

    ret = munmap(pMemInfo->virt_addr, pMemInfo->size);
    if (ret != 0) {
        printf("munmap failed, ret = %d\n",ret);
    }

    ret = ioctl(g_qaeMemFd, DEV_MEM_IOC_MEMFREE, pMemInfo);
    if (ret != 0) {
        printf("ioctl call failed, ret = %d\n",ret);
    }

#ifndef USE_QAE_STATIC_MEM
    userMemListFree(pMemInfo);
    free(pMemInfo);
#endif

    *ptr = NULL;

    return;
}

QAE_PHYS_ADDR qaeVirtToPhysNUMA(void* pVirtAddress)
{
    qae_dev_mem_info_t *pMemInfo = NULL;
    void *pVirtPageAddress = NULL;
    QAE_UINT offset = 0;
    uint64_t  *magic;

    if (pVirtAddress == NULL) {
        printf("qaeVirtToPhysNUMA: Null virtual address pointer\n");
        return (QAE_PHYS_ADDR)0;
    }

    pVirtPageAddress = ((int *)(((
        (QAE_UINT)pVirtAddress)) & (SYSTEM_PAGE_MASK)));

    offset = (QAE_UINT)pVirtAddress - (QAE_UINT)pVirtPageAddress;
    do {
        pMemInfo = (qae_dev_mem_info_t *)pVirtPageAddress;
        magic  = (uint64_t *)pMemInfo;
        if ((QAEM_MAGIC_NUM ==  *magic) &&
            (pMemInfo->virt_addr == pVirtPageAddress)) {
            break;
        }
        pVirtPageAddress = (void*)(
            (QAE_UINT)pVirtPageAddress - SYSTEM_PAGE_SIZE);

        offset += SYSTEM_PAGE_SIZE;
     } while (pMemInfo->virt_addr != pVirtPageAddress);

     return (QAE_PHYS_ADDR)(pMemInfo->phy_addr + offset);
}
#endif /* !QAT_V2 */

#endif /* HAVE_INTEL_QA */
