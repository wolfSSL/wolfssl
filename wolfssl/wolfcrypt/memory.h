/* memory.h
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

/* submitted by eof */


#ifndef WOLFSSL_MEMORY_H
#define WOLFSSL_MEMORY_H

#include <stdlib.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    #ifdef WOLFSSL_DEBUG_MEMORY
        typedef void *(*wolfSSL_Malloc_cb)(size_t size, void* heap, int type, const char* func, unsigned int line);
        typedef void (*wolfSSL_Free_cb)(void *ptr, void* heap, int type, const char* func, unsigned int line);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size, void* heap, int type, const char* func, unsigned int line);
/*!
    \ingroup Memory
    
    \brief This function calls the custom malloc function, if one has been defined, or simply calls the default C malloc function if no custom function exists. It is not called directly by wolfSSL, but instead generally called by using XMALLOC, which may be replaced by wolfSSL_Malloc during preprocessing.
    
    \return Success On successfully allocating the desired memory, returns a void* to that location
    \return NULL Returned when there is a failure to allocate memory
    
    \param size size, in bytes, of the memory to allocate
    
    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    \endcode
    
    \sa wolfSSL_Free
    \sa wolfSSL_Realloc
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
        WOLFSSL_API void* wolfSSL_Malloc(size_t size, void* heap, int type, const char* func, unsigned int line);
/*!
    \ingroup Memory
    
    \brief This function calls a custom free function, if one has been defined, or simply calls the default C free function if no custom function exists. It is not called directly by wolfSSL, but instead generally called by using XFREE, which may be replaced by wolfSSL_Free during preprocessing.
    
    \return none No returns.
    
    \param ptr pointer to the memory to free
    
    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    // process data as desired
    ...
    if(tenInts) {
    	wolfSSL_Free(tenInts);
    }
    \endcode

    \sa wolfSSL_Malloc
    \sa wolfSSL_Realloc
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
        WOLFSSL_API void  wolfSSL_Free(void *ptr, void* heap, int type, const char* func, unsigned int line);
/*!
    \ingroup Memory
    
    \brief This function calls a custom realloc function, if one has been defined, or simply calls the default C realloc function if no custom function exists. It is not called directly by wolfSSL, but instead generally called by using XREALLOC, which may be replaced by wolfSSL_Realloc during preprocessing.
    
    \return Success On successfully reallocating the desired memory, returns a void* to that location
    \return NULL Returned when there is a failure to reallocate memory
    
    \param ptr pointer to the memory to the memory to reallocate
    \param size desired size after reallocation

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    int* twentyInts = (int*)realloc(tenInts, sizeof(tenInts)*2);
    \endcode
    
    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type, const char* func, unsigned int line);
    #else
        typedef void *(*wolfSSL_Malloc_cb)(size_t size, void* heap, int type);
        typedef void (*wolfSSL_Free_cb)(void *ptr, void* heap, int type);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size, void* heap, int type);
/*!
    \ingroup Memory
    
    \brief This function is similar to malloc(), but calls the memory allocation function which wolfSSL has been configured to use.  By default, wolfSSL uses malloc().  This can be changed using the wolfSSL memory abstraction layer - see wolfSSL_SetAllocators().
    
    \return pointer If successful, this function returns a pointer to allocated memory.
    \return error If there is an error, NULL will be returned.
    \return other Specific return values may be dependent on the underlying memory allocation function being used (if not using the default malloc()).
    
    \param size number of bytes to allocate.
    
    _Example_
    \code
    char* buffer;
    buffer = (char*) wolfSSL_Malloc(20);
    if (buffer == NULL) {
	    // failed to allocate memory
    }
    \endcode
    
    \sa wolfSSL_Free
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
*/
        WOLFSSL_API void* wolfSSL_Malloc(size_t size, void* heap, int type);
        WOLFSSL_API void  wolfSSL_Free(void *ptr, void* heap, int type);
/*!
    \ingroup Memory
    
    \brief This function is similar to realloc(), but calls the memory re-allocation function which wolfSSL has been configured to use.  By default, wolfSSL uses realloc().  This can be changed using the wolfSSL memory abstraction layer - see wolfSSL_SetAllocators().
    
    \return pointer If successful, this function returns a pointer to re-allocated memory. This may be the same pointer as ptr, or a new pointer location.
    \return Null If there is an error, NULL will be returned.
    \return other Specific return values may be dependent on the underlying memory re-allocation function being used (if not using the default realloc()).
    
    \param ptr pointer to the previously-allocated memory, to be reallocated.
    \param size number of bytes to allocate.
    
    _Example_
    \code
    char* buffer;

    buffer = (char*) wolfSSL_Realloc(30);
    if (buffer == NULL) {
    	// failed to re-allocate memory
    }
    \endcode
    
    \sa wolfSSL_Free
    \sa wolfSSL_Malloc
    \sa wolfSSL_SetAllocators
*/
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type);
    #endif /* WOLFSSL_DEBUG_MEMORY */
#else
    #ifdef WOLFSSL_DEBUG_MEMORY
        typedef void *(*wolfSSL_Malloc_cb)(size_t size, const char* func, unsigned int line);
        typedef void (*wolfSSL_Free_cb)(void *ptr, const char* func, unsigned int line);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size, const char* func, unsigned int line);

        /* Public in case user app wants to use XMALLOC/XFREE */
        WOLFSSL_API void* wolfSSL_Malloc(size_t size, const char* func, unsigned int line);
/*!
    \ingroup Memory
    
    \brief This function is similar to free(), but calls the memory free function which wolfSSL has been configured to use. By default, wolfSSL uses free(). This can be changed using the wolfSSL memory abstraction layer - see wolfSSL_SetAllocators().
    
    \return none No returns.
    
    \param ptr pointer to the memory to be freed.
    
    _Example_
    \code
    char* buffer;
    ...
    wolfSSL_Free(buffer);
    \endcode
    
    \sa wolfSSL_Alloc
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
*/
        WOLFSSL_API void  wolfSSL_Free(void *ptr, const char* func, unsigned int line);
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size, const char* func, unsigned int line);
    #else
        typedef void *(*wolfSSL_Malloc_cb)(size_t size);
        typedef void (*wolfSSL_Free_cb)(void *ptr);
        typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);
        /* Public in case user app wants to use XMALLOC/XFREE */
        WOLFSSL_API void* wolfSSL_Malloc(size_t size);
        WOLFSSL_API void  wolfSSL_Free(void *ptr);
        WOLFSSL_API void* wolfSSL_Realloc(void *ptr, size_t size);
    #endif /* WOLFSSL_DEBUG_MEMORY */
#endif /* WOLFSSL_STATIC_MEMORY */

/* Public get/set functions */
/*!
    \ingroup Memory
    
    \brief This function registers the allocation functions used by wolfSSL. By default, if the system supports it, malloc/free and realloc are used. Using this function allows the user at runtime to install their own memory handlers.
    
    \return Success If successful this function will return 0.
    \return BAD_FUNC_ARG is the error that will be returned if a function pointer is not provided.
    
    \param malloc_function memory allocation function for wolfSSL to use.  Function signature must match wolfSSL_Malloc_cb prototype, above.
    \param free_function memory free function for wolfSSL to use.  Function signature must match wolfSSL_Free_cb prototype, above.
    \param realloc_function memory re-allocation function for wolfSSL to use.  Function signature must match wolfSSL_Realloc_cb prototype, above.
    
    _Example_
    \code
    int ret = 0;
    // Memory function prototypes
    void* MyMalloc(size_t size);
    void  MyFree(void* ptr);
    void* MyRealloc(void* ptr, size_t size);

    // Register custom memory functions with wolfSSL
    ret = wolfSSL_SetAllocators(MyMalloc, MyFree, MyRealloc);
    if (ret != 0) {
    	// failed to set memory functions
    }

    void* MyMalloc(size_t size)
    {
    	// custom malloc function
    }

    void MyFree(void* ptr)
    {
    	// custom free function
    }

    void* MyRealloc(void* ptr, size_t size)
    {
    	// custom realloc function
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API int wolfSSL_SetAllocators(wolfSSL_Malloc_cb,
                                      wolfSSL_Free_cb,
                                      wolfSSL_Realloc_cb);

WOLFSSL_API int wolfSSL_GetAllocators(wolfSSL_Malloc_cb*,
                                      wolfSSL_Free_cb*,
                                      wolfSSL_Realloc_cb*);

#ifdef WOLFSSL_STATIC_MEMORY
    #define WOLFSSL_STATIC_TIMEOUT 1
    #ifndef WOLFSSL_STATIC_ALIGN
        #define WOLFSSL_STATIC_ALIGN 16
    #endif
    #ifndef WOLFMEM_MAX_BUCKETS
        #define WOLFMEM_MAX_BUCKETS  9
    #endif
    #define WOLFMEM_DEF_BUCKETS  9     /* number of default memory blocks */
    #define WOLFMEM_IO_SZ        16992 /* 16 byte aligned */
    #ifndef WOLFMEM_BUCKETS
        /* default size of chunks of memory to seperate into
         * having session certs enabled makes a 21k SSL struct */
        #ifndef SESSION_CERTS
            #define WOLFMEM_BUCKETS 64,128,256,512,1024,2432,3456,4544,16128
        #else
            #define WOLFMEM_BUCKETS 64,128,256,512,1024,2432,3456,4544,21056
        #endif
    #endif
    #ifndef WOLFMEM_DIST
        #define WOLFMEM_DIST    8,4,4,12,4,5,8,1,1
    #endif

    /* flags for loading static memory (one hot bit) */
    #define WOLFMEM_GENERAL       0x01
    #define WOLFMEM_IO_POOL       0x02
    #define WOLFMEM_IO_POOL_FIXED 0x04
    #define WOLFMEM_TRACK_STATS   0x08

    #ifndef WOLFSSL_MEM_GUARD
    #define WOLFSSL_MEM_GUARD
        typedef struct WOLFSSL_MEM_STATS      WOLFSSL_MEM_STATS;
        typedef struct WOLFSSL_MEM_CONN_STATS WOLFSSL_MEM_CONN_STATS;
    #endif

    struct WOLFSSL_MEM_CONN_STATS {
        word32 peakMem;   /* peak memory usage    */
        word32 curMem;    /* current memory usage */
        word32 peakAlloc; /* peak memory allocations */
        word32 curAlloc;  /* current memory allocations */
        word32 totalAlloc;/* total memory allocations for lifetime */
        word32 totalFr;   /* total frees for lifetime */
    };

    struct WOLFSSL_MEM_STATS {
        word32 curAlloc;  /* current memory allocations */
        word32 totalAlloc;/* total memory allocations for lifetime */
        word32 totalFr;   /* total frees for lifetime */
        word32 totalUse;  /* total amount of memory used in blocks */
        word32 avaIO;     /* available IO specific pools */
        word32 maxHa;     /* max number of concurent handshakes allowed */
        word32 maxIO;     /* max number of concurent IO connections allowed */
        word32 blockSz[WOLFMEM_MAX_BUCKETS]; /* block sizes in stacks */
        word32 avaBlock[WOLFMEM_MAX_BUCKETS];/* ava block sizes */
        word32 usedBlock[WOLFMEM_MAX_BUCKETS];
        int    flag; /* flag used */
    };

    typedef struct wc_Memory wc_Memory; /* internal structure for mem bucket */
    typedef struct WOLFSSL_HEAP {
        wc_Memory* ava[WOLFMEM_MAX_BUCKETS];
        wc_Memory* io;                  /* list of buffers to use for IO */
        word32     maxHa;               /* max concurent handshakes */
        word32     curHa;
        word32     maxIO;               /* max concurrent IO connections */
        word32     curIO;
        word32     sizeList[WOLFMEM_MAX_BUCKETS];/* memory sizes in ava list */
        word32     distList[WOLFMEM_MAX_BUCKETS];/* general distribution */
        word32     inUse; /* amount of memory currently in use */
        word32     ioUse;
        word32     alloc; /* total number of allocs */
        word32     frAlc; /* total number of frees  */
        int        flag;
        wolfSSL_Mutex memory_mutex;
    } WOLFSSL_HEAP;

    /* structure passed into XMALLOC as heap hint
     * having this abstraction allows tracking statistics of individual ssl's
     */
    typedef struct WOLFSSL_HEAP_HINT {
        WOLFSSL_HEAP*           memory;
        WOLFSSL_MEM_CONN_STATS* stats;  /* hold individual connection stats */
        wc_Memory*  outBuf; /* set if using fixed io buffers */
        wc_Memory*  inBuf;
        byte        haFlag; /* flag used for checking handshake count */
    } WOLFSSL_HEAP_HINT;

    WOLFSSL_API int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT** pHint,
            unsigned char* buf, unsigned int sz, int flag, int max);

    WOLFSSL_LOCAL int wolfSSL_init_memory_heap(WOLFSSL_HEAP* heap);
    WOLFSSL_LOCAL int wolfSSL_load_static_memory(byte* buffer, word32 sz,
                                                  int flag, WOLFSSL_HEAP* heap);
    WOLFSSL_LOCAL int wolfSSL_GetMemStats(WOLFSSL_HEAP* heap,
                                                      WOLFSSL_MEM_STATS* stats);
    WOLFSSL_LOCAL int SetFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io);
    WOLFSSL_LOCAL int FreeFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io);

/*!
    \ingroup Memory
    
    \brief This function is available when static memory feature is used (--enable-staticmemory). It gives the optimum buffer size for memory “buckets”. This allows for a way to compute buffer size so that no extra unused memory is left at the end after it has been partitioned. The returned value, if positive, is the computed buffer size to use. 
    
    \return Success On successfully completing buffer size calculations a positive value is returned. This returned value is for optimum buffer size.
    \return Failure All negative values are considered to be error cases.
    
    \param buffer pointer to buffer
    \param size size of buffer
    \param type desired type of memory ie WOLFMEM_GENERAL or WOLFMEM_IO_POOL
    
    _Example_
    \code
    byte buffer[1000];
    word32 size = sizeof(buffer);
    int optimum;
    optimum = wolfSSL_StaticBufferSz(buffer, size, WOLFMEM_GENERAL);
    if (optimum < 0) { //handle error case }
    printf(“The optimum buffer size to make use of all memory is %d\n”, optimum);
    ...
    \endcode
    
    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
    WOLFSSL_API int wolfSSL_StaticBufferSz(byte* buffer, word32 sz, int flag);
/*!
    \ingroup Memory
    
    \brief This function is available when static memory feature is used (--enable-staticmemory). It gives the size of padding needed for each partition of memory. This padding size will be the size needed to contain a memory management structure along with any extra for memory alignment.
    
    \return On successfully memory padding calculation the return value will be a positive value
    \return All negative values are considered error cases. 
    
    \param none No parameters.
    
    _Example_
    \code
    int padding;
    padding = wolfSSL_MemoryPaddingSz();
    if (padding < 0) { //handle error case }
    printf(“The padding size needed for each \”bucket\” of memory is %d\n”, padding);
    // calculation of buffer for IO POOL size is number of buckets times (padding + WOLFMEM_IO_SZ)
    ...
    \endcode
    
    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
    WOLFSSL_API int wolfSSL_MemoryPaddingSz(void);
#endif /* WOLFSSL_STATIC_MEMORY */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_MEMORY_H */

