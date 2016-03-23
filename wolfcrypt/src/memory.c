/* memory.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* check old macros @wc_fips */
#if defined(USE_CYASSL_MEMORY) && !defined(USE_WOLFSSL_MEMORY)
    #define USE_WOLFSSL_MEMORY
#endif
#if defined(CYASSL_MALLOC_CHECK) && !defined(WOLFSSL_MALLOC_CHECK)
    #define WOLFSSL_MALLOC_CHECK
#endif

#ifdef USE_WOLFSSL_MEMORY

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if defined(WOLFSSL_MALLOC_CHECK) || defined(WOLFSSL_TRACK_MEMORY_FULL)
    #include <stdio.h>
#endif


/* Set these to default values initially. */
static wolfSSL_Malloc_cb  malloc_function = 0;
static wolfSSL_Free_cb    free_function = 0;
static wolfSSL_Realloc_cb realloc_function = 0;

int wolfSSL_SetAllocators(wolfSSL_Malloc_cb  mf,
                          wolfSSL_Free_cb    ff,
                          wolfSSL_Realloc_cb rf)
{
    int res = 0;

    if (mf)
        malloc_function = mf;
    else
        res = BAD_FUNC_ARG;

    if (ff)
        free_function = ff;
    else
        res = BAD_FUNC_ARG;

    if (rf)
        realloc_function = rf;
    else
        res = BAD_FUNC_ARG;

    return res;
}

#ifdef WOLFSSL_DEBUG_MEMORY
void* wolfSSL_Malloc(size_t size, const char* func, unsigned int line)
#else
void* wolfSSL_Malloc(size_t size)
#endif
{
    void* res = 0;

    if (malloc_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        res = malloc_function(size, func, line);
    #else
        res = malloc_function(size);
    #endif
    }
    else {
        res = malloc(size);
    }

    #ifdef WOLFSSL_MALLOC_CHECK
        if (res == NULL)
            puts("wolfSSL_malloc failed");
    #endif

    return res;
}

#ifdef WOLFSSL_DEBUG_MEMORY
void wolfSSL_Free(void *ptr, const char* func, unsigned int line)
#else
void wolfSSL_Free(void *ptr)
#endif
{
    if (free_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        free_function(ptr, func, line);
    #else
        free_function(ptr);
    #endif
    }
    else {
        free(ptr);
    }
}

#ifdef WOLFSSL_DEBUG_MEMORY
void* wolfSSL_Realloc(void *ptr, size_t size, const char* func, unsigned int line)
#else
void* wolfSSL_Realloc(void *ptr, size_t size)
#endif
{
    void* res = 0;

    if (realloc_function) {
    #ifdef WOLFSSL_DEBUG_MEMORY
        res = realloc_function(ptr, size, func, line);
    #else
        res = realloc_function(ptr, size);
    #endif
    }
    else {
        res = realloc(ptr, size);
    }

    return res;
}

#ifdef WOLFSSL_STATIC_MEMORY

typedef struct wc_Memory {
    word32 sz;
    byte*  buffer;
    byte   kill;
    struct wc_Memory* next;
} wc_Memory;
#if WC_STATIC_ALIGN < 10
    #error Alignment is less than wc_Memory struct
#endif

/* size of chunks of memory to seperate into */
#define WC_MAX_BUCKETS 9
static word32 bucket[] = { 64, 128, 256, 512, 1024, 2400, 3408, 4544, 16000 };
static word32 bucketDist[] = { 8, 4, 4, 12, 4, 5, 2, 1, 1 };
static wc_Memory* available[WC_MAX_BUCKETS];
static word32 inUse = 0; /* amount of static memory in use by wolfSSL */
static byte   useStaticMemory = 1;
static volatile byte   createMutex = 1;
static wolfSSL_Mutex memory_mutex;


/* returns amount of memory used on success. On error returns negative value
   wc_Memory** list is the list that new buckets are prepended to
 */
static int create_memory_buckets(byte* buffer, word32 bufSz,
                              word32 buckSz, word32 buckNum, wc_Memory** list) {
    word32 i;
    byte*  pt  = buffer;
    int    ret = 0;

    /* if not enough space available for bucket size then do not try */
    if (buckSz + WC_STATIC_ALIGN > bufSz) {
        return ret;
    }

    if (LockMutex(&memory_mutex) != 0) {
        return BAD_MUTEX_E;
    }

    for (i = 0; i < buckNum; i++) {
        if ((buckSz + WC_STATIC_ALIGN) <= (bufSz - ret)) {
            /* create a new struct and set its values */
            wc_Memory* mem = (struct wc_Memory*)pt;
            mem->sz = buckSz;
            mem->buffer = (byte*)pt + WC_STATIC_ALIGN;
            mem->kill = 0;
            mem->next = NULL;

            /* add the newly created struct to front of list */
            if (*list == NULL) {
                *list = mem;
            } else {
                mem->next = *list;
                *list = mem;
            }

            /* advance pointer and keep track of memory used */
            ret += buckSz + WC_STATIC_ALIGN;
            pt  += WC_STATIC_ALIGN + buckSz;
        }
        else {
            break; /* not enough space left for more buckets of this size */
        }
    }

    UnLockMutex(&memory_mutex);

    return ret;
}



/* Starts at left most address and free until either used memory is encounterd
   or end of buffer is.
   Returns amount of buffer freed on success and a negative value on fail.
 */
int wolfSSL_unload_static_memory(byte* buffer, word32 sz, word32* amt)
{
    wc_Memory* cur = NULL;
    wc_Memory* fre = NULL;
    wc_Memory* prv = NULL;
    int i;
    word32 idx = 0;

    WOLFSSL_ENTER("wolfSSL_unload_static_memory");

    if (buffer == NULL || sz == 0 || amt == NULL) {
        return BAD_FUNC_ARG;
    }

    if (LockMutex(&memory_mutex) != 0) {
        return BAD_MUTEX_E;
    }

    /* too small of memory to be placed as a bucket */
    if (sz < bucket[0] + WC_STATIC_ALIGN) {
        *amt = sz;
        return 1;
    }

    /* advance past alignment padding */
    while ((word64)(buffer + idx) % WC_STATIC_ALIGN && idx < sz) { idx++; }

    /* buffer should be already divided up into wc_Memory structs */
    while (idx < (sz - bucket[0] - WC_STATIC_ALIGN)) {
        cur = (struct wc_Memory*)(buffer + idx);
        prv = NULL;

        for (i = 0; i < WC_MAX_BUCKETS; i++) {
            if (bucket[i] >= cur->sz) break;
        }
        fre = available[i];

        /* find the matching address of the memory in available stack */
        while (fre != NULL && (cur != fre)) {
            prv = fre;
            fre = fre->next;
        }

        if (fre == NULL) {
            WOLFSSL_MSG("Could not find static memory address to free");
            break;
        }

        /* fix linked list to jump over the link to free */
        if (prv) {
            prv->next = fre->next;
        }

        /* case if memory is head of stack */
        if (available[i] == fre) {
            available[i] = fre->next;
        }

        idx += WC_STATIC_ALIGN + fre->sz;
        fre = NULL;
    }

    UnLockMutex(&memory_mutex);

    /* account for some left over memory that could not be used for a bucket */
    if (idx > (sz - (bucket[0] + WC_STATIC_ALIGN))) {
        *amt = sz; /* all posssible was freed */
        return 1;
    }
    else {
        *amt = idx;
        return 0;
    }
}


int wolfSSL_load_static_memory(byte* buffer, word32 sz)
{
    word32 ava = sz;
    byte*  pt  = buffer;
    int    ret = 0;

    #ifdef WOLFSSL_TRACK_MEMORY_FULL
        word32 created_buckets[WC_MAX_BUCKETS];
        int    j;
        XMEMSET(created_buckets, 0, sizeof(created_buckets));
    #endif

    WOLFSSL_ENTER("wolfSSL_load_static_memory");

    if (buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    #ifdef WOLFSSL_TRACK_MEMORY_FULL
        printf("\t%u bytes passed in\n", sz);
        printf("\tAddress %p - %p\n", buffer, buffer + sz);
    #endif

    /* align pt */
    while ((word64)pt % WC_STATIC_ALIGN && pt < (buffer + sz)) {
        *pt = 0x00;
        pt++;
    }

    if (createMutex) {
        if (InitMutex(&memory_mutex) != 0) {
            WOLFSSL_MSG("Bad mutex init");
            return BAD_MUTEX_E;
        }
        createMutex = 0;
    }

    /* devide into chunks of memory and add them to available list */
    while (ava >= (bucket[0] + WC_STATIC_ALIGN)) {
        int i;
        /* start at largest and move to smaller buckets */
        for (i = (WC_MAX_BUCKETS - 1); i >= 0; i--) {
            if ((bucket[i] + WC_STATIC_ALIGN) <= ava) {
                if ((ret = create_memory_buckets(pt, ava,
                               bucket[i], bucketDist[i], &available[i])) < 0) {
                    WOLFSSL_LEAVE("wolfSSL_load_static_memory", ret);
                    return ret;
                }
                #ifdef WOLFSSL_TRACK_MEMORY_FULL
                /* if defined keep track of buckets created for printing stats*/
                    for (j = 0; (j + bucket[i] + WC_STATIC_ALIGN) <=(word32)ret;
                                             j += bucket[i] + WC_STATIC_ALIGN) {
                        created_buckets[i]++;
                    }
                #endif

                /* advance pointer in buffer for next buckets and keep track
                   of how much memory is left available */
                pt  += ret;
                ava -= ret;
            }
        }
    }

    #ifdef WOLFSSL_TRACK_MEMORY_FULL
    /* if defined print out stats of number of buckets created */
        printf("Created Memory Buckets :\n");
        for (j = 0; j < WC_MAX_BUCKETS; j++) {
            printf("Created %d\tof bucket size %d\n", created_buckets[j],
                                                                    bucket[j]);
        }
    #endif

    return 1;
}


int wolfSSL_use_static_memory(byte flag)
{

    WOLFSSL_ENTER("wolfSSL_use_static_memory");

    useStaticMemory = flag;

    return 0;
}


word32 wolfSSL_static_memory_inUse()
{

    WOLFSSL_ENTER("wolfSSL_static_memory_inUse");

    return inUse;
}


void* wolfSSL_Malloc_Static(size_t size)
{
    void* res = 0;
    wc_Memory* pt = NULL;
    int   i;

    if (useStaticMemory == 0) {
        pt = malloc(size + WC_STATIC_ALIGN);
        pt->buffer = (byte*)pt + WC_STATIC_ALIGN;
        pt->sz     = (word32)size;
        pt->kill   = 1;
        pt->next   = NULL;
        res = pt->buffer;
    }
    else {

        if (LockMutex(&memory_mutex) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
            return NULL;
        }

        for (i = 0; i < WC_MAX_BUCKETS; i++) {
            if ((word32)size < bucket[i]) {
                if (available[i] != NULL) {
                    pt = available[i];
                    available[i] = pt->next;
                    res = pt->buffer;
                    inUse += pt->sz + WC_STATIC_ALIGN;
                #ifdef WOLFSSL_TRACK_MEMORY_FULL
                    printf("used bucket at address %p size of %d for size"
                           " req %d\n", res, bucket[i], (word32)size);
                #endif
                    break;
                }
            }
        }

        UnLockMutex(&memory_mutex);

        /* case when no memory size is available */
        if (pt == NULL) {

            #ifdef WOLFSSL_TRACK_MEMORY_FULL
                {
                    int k, j;
                    printf("\tRequested size %lu\n\tAvailable memory "
                            "buckets\n", size);
                    for (k = 0; k < WC_MAX_BUCKETS; k++) {
                        pt = available[k];
                        j = 0;
                        while (pt) {
                            j++;
                            pt = pt->next;
                        }
                        printf("\t%d of bucket %d\n", j, bucket[k]);
                    }
                }
            #endif

            /* check if too large and never going to get memory needed */
            if ((word32)size > bucket[WC_MAX_BUCKETS-1]) {
                WOLFSSL_MSG("Size of malloc is too large");
                return NULL;
            }

            /* wait then try again if set to */
            if (WOLFSSL_STATIC_TIMEOUT > 0) {
                WOLFSSL_MSG("Waiting for available memory bucket");
                XSLEEP(WOLFSSL_STATIC_TIMEOUT);


                if (LockMutex(&memory_mutex) != 0) {
                    WOLFSSL_MSG("Bad memory_mutex lock");
                    return NULL;
                }

                for (i = 0; i < WC_MAX_BUCKETS; i++) {
                    if ((word32)size < bucket[i]) {
                        if (available[i] != NULL) {
                            pt = available[i];
                            available[i] = pt->next;
                            res = pt->buffer;
                            inUse += pt->sz + WC_STATIC_ALIGN;
                        #ifdef WOLFSSL_TRACK_MEMORY_FULL
                            printf("used bucket at address %p size of %d"
                                   " for size req %d\n", res, bucket[i],
                                   (word32)size);
                        #endif
                            break;
                        }
                    }
                }

                UnLockMutex(&memory_mutex);
            }

            if (pt == NULL) {
                WOLFSSL_MSG("No available memory bucket");
            }
        }
    }

    #ifdef WOLFSSL_MALLOC_CHECK
        if (res == NULL)
            puts("wolfSSL_malloc failed");
    #endif

    (void)i;
    (void)pt;

    return res;
}

void wolfSSL_Free_Static(void *ptr)
{
    int i;
    wc_Memory* pt;

    if (ptr) {
        /* get memory struct and add it to available list */
        pt = (wc_Memory*)((byte*)ptr - WC_STATIC_ALIGN);

        if (pt->kill) {
            free(pt);
        }
        else {
            LockMutex(&memory_mutex);

            for (i = 0; i < WC_MAX_BUCKETS; i++) {
                if (pt->sz == bucket[i]) {
                    inUse -= WC_STATIC_ALIGN + pt->sz;
                    pt->next = available[i];
                    available[i] = pt;
                    #ifdef WOLFSSL_TRACK_MEMORY_FULL
                        printf("\tfreed %p bucket size of %d\n"
                                                            ,pt, bucket[i]);
                    #endif
                    break;
                }
            }
            UnLockMutex(&memory_mutex);
        }
    }

    (void)i;
    (void)pt;
}


void* wolfSSL_Realloc_Static(void *ptr, size_t size)
{
    void* res = 0;
    wc_Memory* pt = NULL;
    int   i;

    if (useStaticMemory == 0) {
        pt = realloc(ptr, size + WC_STATIC_ALIGN);
        pt->buffer = (byte*)pt + WC_STATIC_ALIGN;
        pt->sz     = (word32)size;
        pt->kill   = 1;
        pt->next   = NULL;
        res = pt->buffer;
    }
    else {

        if (LockMutex(&memory_mutex) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
            return NULL;
        }

        for (i = 0; i < WC_MAX_BUCKETS; i++) {
            if ((word32)size < bucket[i]) {
                if (available[i] != NULL) {
                    word32 prvSz;

                    pt = available[i];
                    available[i] = pt->next;
                    res = pt->buffer;

                    /* copy over original information and free ptr */
                    prvSz = ((wc_Memory*)((byte*)ptr -WC_STATIC_ALIGN))->sz;
                    prvSz = (prvSz > bucket[i])? bucket[i]: prvSz;
                    XMEMCPY(pt->buffer, ptr, prvSz);

                    /* free memory that was previously being used */
                    UnLockMutex(&memory_mutex);
                    wolfSSL_Free_Static(ptr);
                    if (LockMutex(&memory_mutex) != 0) {
                        WOLFSSL_MSG("Bad memory_mutex lock");
                        return NULL;
                    }

                    inUse += pt->sz + WC_STATIC_ALIGN;
                #ifdef WOLFSSL_TRACK_MEMORY_FULL
                    printf("realloc used a bucket of %d for size req %d\n",
                                                   bucket[i], (word32)size);
                #endif
                    break;
                }
            }
        }

        UnLockMutex(&memory_mutex);

        /* case when no memory size is available */
        if (pt == NULL) {

            #ifdef WOLFSSL_TRACK_MEMORY_FULL
                {
                    int k, j;
                    printf("\tRequested size %lu\n\tAvailable memory "
                            "buckets\n", size);
                    for (k = 0; k < WC_MAX_BUCKETS; k++) {
                        pt = available[k];
                        j = 0;
                        while (pt) {
                            j++;
                            pt = pt->next;
                        }
                        printf("\t%d of bucket %d\n", j, bucket[k]);
                    }
                }
            #endif

            /* check if too large and never going to get memory needed */
            if ((word32)size > bucket[WC_MAX_BUCKETS-1]) {
                WOLFSSL_MSG("Size of malloc is too large");
                return NULL;
            }

            if (WOLFSSL_STATIC_TIMEOUT > 0) {
                WOLFSSL_MSG("Waiting for available memory bucket");
                XSLEEP(WOLFSSL_STATIC_TIMEOUT);

                if (LockMutex(&memory_mutex) != 0) {
                    WOLFSSL_MSG("Bad memory_mutex lock");
                    return NULL;
                }

                for (i = 0; i < WC_MAX_BUCKETS; i++) {
                    if ((word32)size < bucket[i]) {
                        if (available[i] != NULL) {
                            word32 prvSz;

                            pt = available[i];
                            available[i] = pt->next;
                            res = pt->buffer;

                            /* copy over original information and free ptr*/
                            prvSz = ((wc_Memory*)((byte*)ptr -
                                                      WC_STATIC_ALIGN))->sz;
                            prvSz = (prvSz > bucket[i])? bucket[i]: prvSz;
                            XMEMCPY(pt->buffer, ptr, prvSz);

                            /* free memory that was previously being used */
                            UnLockMutex(&memory_mutex);
                            wolfSSL_Free_Static(ptr);
                            if (LockMutex(&memory_mutex) != 0) {
                                WOLFSSL_MSG("Bad memory_mutex lock");
                                return NULL;
                            }

                            inUse += pt->sz + WC_STATIC_ALIGN;
                        #ifdef WOLFSSL_TRACK_MEMORY_FULL
                            printf("realloc used a bucket of %d for size"
                                   " req %d\n", bucket[i], (word32)size);
                        #endif
                            break;
                        }
                    }
                }
                UnLockMutex(&memory_mutex);
            }

            if (pt == NULL) {
                WOLFSSL_MSG("No available memory bucket");
            }
        }
    }

    (void)i;
    (void)pt;

    return res;
}
#endif /* WOLFSSL_STATIC_MEMORY */

#endif /* USE_WOLFSSL_MEMORY */


#ifdef HAVE_IO_POOL

/* Example for user io pool, shared build may need definitions in lib proper */

#include <wolfssl/wolfcrypt/types.h>
#include <stdlib.h>

#ifndef HAVE_THREAD_LS
    #error "Oops, simple I/O pool example needs thread local storage"
#endif


/* allow simple per thread in and out pools */
/* use 17k size sense max record size is 16k plus overhead */
static THREAD_LS_T byte pool_in[17*1024];
static THREAD_LS_T byte pool_out[17*1024];


void* XMALLOC(size_t n, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER) {
        if (n < sizeof(pool_in))
            return pool_in;
        else
            return NULL;
    }

    if (type == DYNAMIC_TYPE_OUT_BUFFER) {
        if (n < sizeof(pool_out))
            return pool_out;
        else
            return NULL;
    }

    return malloc(n);
}

void* XREALLOC(void *p, size_t n, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER) {
        if (n < sizeof(pool_in))
            return pool_in;
        else
            return NULL;
    }

    if (type == DYNAMIC_TYPE_OUT_BUFFER) {
        if (n < sizeof(pool_out))
            return pool_out;
        else
            return NULL;
    }

    return realloc(p, n);
}


/* unit api calls, let's make sure visible with WOLFSSL_API */
WOLFSSL_API void XFREE(void *p, void* heap, int type)
{
    (void)heap;

    if (type == DYNAMIC_TYPE_IN_BUFFER)
        return;  /* do nothing, static pool */

    if (type == DYNAMIC_TYPE_OUT_BUFFER)
        return;  /* do nothing, static pool */

    free(p);
}

#endif /* HAVE_IO_POOL */

