/*!
    \ingroup Memory

    \brief This function is similar to malloc(), but calls the memory
    allocation function which wolfSSL has been configured to use. By default,
    wolfSSL uses malloc().  This can be changed using the wolfSSL memory
    abstraction layer - see wolfSSL_SetAllocators(). Note wolfSSL_Malloc is not
    called directly by wolfSSL, but instead called by macro XMALLOC.
    For the default build only the size argument exists. If using
    WOLFSSL_STATIC_MEMORY build then heap and type arguments are included.

    \return pointer If successful, this function returns a pointer to
    allocated memory.
    \return error If there is an error, NULL will be returned.

    \param size size, in bytes, of the memory to allocate
    \param heap heap hint to use for memory. Can be NULL
    \param type dynamic type (see DYNAMIC_TYPE_ list in types.h)

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    \endcode

    \sa wolfSSL_Free
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void* wolfSSL_Malloc(size_t size, void* heap, int type);

/*!
    \ingroup Memory

    \brief This function is similar to free(), but calls the memory free
    function which wolfSSL has been configured to use. By default, wolfSSL
    uses free(). This can be changed using the wolfSSL memory abstraction
    layer - see wolfSSL_SetAllocators(). Note wolfSSL_Free is not
    called directly by wolfSSL, but instead called by macro XFREE.
    For the default build only the ptr argument exists. If using
    WOLFSSL_STATIC_MEMORY build then heap and type arguments are included.

    \return none No returns.

    \param ptr pointer to the memory to be freed.
    \param heap heap hint to use for memory. Can be NULL
    \param type dynamic type (see DYNAMIC_TYPE_ list in types.h)

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    // process data as desired
    ...
    if(tenInts) {
    	wolfSSL_Free(tenInts);
    }
    \endcode

    \sa wolfSSL_Alloc
    \sa wolfSSL_Realloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void  wolfSSL_Free(void *ptr, void* heap, int type);

/*!
    \ingroup Memory

    \brief This function is similar to realloc(), but calls the memory
    re-allocation function which wolfSSL has been configured to use.
    By default, wolfSSL uses realloc().  This can be changed using the
    wolfSSL memory abstraction layer - see wolfSSL_SetAllocators().
    Note wolfSSL_Realloc is not called directly by wolfSSL, but instead called
    by macro XREALLOC. For the default build only the size argument exists.
    If using WOLFSSL_STATIC_MEMORY build then heap and type arguments are included.

    \return pointer If successful, this function returns a pointer to
    re-allocated memory. This may be the same pointer as ptr, or a
    new pointer location.
    \return Null If there is an error, NULL will be returned.

    \param ptr pointer to the previously-allocated memory, to be reallocated.
    \param size number of bytes to allocate.
    \param heap heap hint to use for memory. Can be NULL
    \param type dynamic type (see DYNAMIC_TYPE_ list in types.h)

    _Example_
    \code
    int* tenInts = (int*)wolfSSL_Malloc(sizeof(int)*10);
    int* twentyInts = (int*)wolfSSL_Realloc(tenInts, sizeof(int)*20);
    \endcode

    \sa wolfSSL_Free
    \sa wolfSSL_Malloc
    \sa wolfSSL_SetAllocators
    \sa XMALLOC
    \sa XFREE
    \sa XREALLOC
*/
void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type);

/*!
    \ingroup Memory

    \brief This function registers the allocation functions used by wolfSSL.
    By default, if the system supports it, malloc/free and realloc are used.
    Using this function allows the user at runtime to install their own
    memory handlers.

    \return Success If successful this function will return 0.
    \return BAD_FUNC_ARG is the error that will be returned if a
    function pointer is not provided.

    \param malloc_function memory allocation function for wolfSSL to use.
    Function signature must match wolfSSL_Malloc_cb prototype, above.
    \param free_function memory free function for wolfSSL to use.  Function
    signature must match wolfSSL_Free_cb prototype, above.
    \param realloc_function memory re-allocation function for wolfSSL to use.
    Function signature must match wolfSSL_Realloc_cb prototype, above.

    _Example_
    \code
    static void* MyMalloc(size_t size)
    {
    	// custom malloc function
    }

    static void MyFree(void* ptr)
    {
    	// custom free function
    }

    static void* MyRealloc(void* ptr, size_t size)
    {
    	// custom realloc function
    }

    // Register custom memory functions with wolfSSL
    int ret = wolfSSL_SetAllocators(MyMalloc, MyFree, MyRealloc);
    if (ret != 0) {
    	// failed to set memory functions
    }
    \endcode

    \sa none
*/
int wolfSSL_SetAllocators(wolfSSL_Malloc_cb,
                                      wolfSSL_Free_cb,
                                      wolfSSL_Realloc_cb);

/*!
    \ingroup Memory

    \brief This function is available when static memory feature is used
    (--enable-staticmemory). It gives the optimum buffer size for memory
    “buckets”. This allows for a way to compute buffer size so that no
    extra unused memory is left at the end after it has been partitioned.
    For the none _ex version of this function the default bucket and
    distribution list set during compile time is used.
    The returned value, if positive, is the computed buffer size to use.

    \return Success On successfully completing buffer size calculations a
    positive value is returned. This returned value is for optimum buffer size.
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
    printf(“The optimum buffer size to make use of all memory is %d\n”,
    optimum);
    ...
    \endcode

    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
int wolfSSL_StaticBufferSz(byte* buffer, word32 sz, int flag);

/*!
    \ingroup Memory

    \brief This function is available when static memory feature is used
    (--enable-staticmemory). It gives the size of padding needed for each
    partition of memory. This padding size will be the size needed to
    contain a memory management structure along with any extra for
    memory alignment.

    \return On successfully memory padding calculation the return value will
    be a positive value
    \return All negative values are considered error cases.

    \param none No parameters.

    _Example_
    \code
    int padding;
    padding = wolfSSL_MemoryPaddingSz();
    if (padding < 0) { //handle error case }
    printf(“The padding size needed for each \”bucket\” of memory is %d\n”,
    padding);
    // calculation of buffer for IO POOL size is number of buckets
    // times (padding + WOLFMEM_IO_SZ)
    ...
    \endcode

    \sa wolfSSL_Malloc
    \sa wolfSSL_Free
*/
int wolfSSL_MemoryPaddingSz(void);

/*!
    \ingroup Memory

    \brief This function is used to set aside static memory for a CTX.
    Memory set aside is then used for the CTX’s lifetime and for any SSL objects created
    from the CTX. By passing in a NULL ctx pointer and a wolfSSL_method_func function the creation
    of the CTX itself will also use static memory. wolfSSL_method_func has the function signature
    of WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);.
    Passing in 0 for max makes it behave as if not set and no max concurrent use restrictions
    is in place.
    The flag value passed in determines how the memory is used and behavior while operating.
    Available flags are the following.

    0 - default general memory

    WOLFMEM_IO_POOL - used for input/output buffer when sending receiving messages.
    Overrides general memory, so all memory in buffer passed in is used for IO.
    WOLFMEM_IO_FIXED - same as WOLFMEM_IO_POOL but each SSL now keeps two
    buffers to themselves for their lifetime.
    WOLFMEM_TRACK_STATS - each SSL keeps track of memory stats while running.

    \return If successful, SSL_SUCCESS will be returned.
    \return All unsuccessful return values will be less than 0 or equal to SSL_FAILURE.

    \param ctx address of pointer to a WOLFSSL_CTX structure.
    \param method function to create protocol. (should be NULL if ctx is not also NULL)
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // create ctx also using static memory, start with general memory to use
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex, memory, memorySz, 0,
    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    // load in memory for use with IO
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag, MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx, wolfSSL_method_func method,
        unsigned char* buf, unsigned int sz, int flag, int max);

/*!
    \ingroup Memory

    \brief This function does not change any of the connections behavior and is used only for
    gathering information about the static memory usage.

    \return A value of 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param mem_stats structure to hold information about staic memory usage.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //get information about static memory with CTX

    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);

    if (ret == 1) {
        // handle case of is using static memory
        // print out or inspect elements of mem_stats
    }

    if (ret == 0) {
        //handle case of ctx not using static memory
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx, WOLFSSL_MEM_STATS* mem_stats);

/*!
    \ingroup Memory

    \brief wolfSSL_is_static_memory is used to gather information about a SSL’s static
    memory usage. The return value indicates if static memory is being used and
    WOLFSSL_MEM_CONN_STATS will be filled out if and only if the flag WOLFMEM_TRACK_STATS was
    passed to the parent CTX when loading in static memory.

    \return A value of 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param mem_stats structure to contain static memory usage

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;

    ...

    ret = wolfSSL_is_static_memory(ssl, mem_stats);

    if (ret == 1) {
        // handle case when is static memory
        // investigate elements in mem_stats if WOLFMEM_TRACK_STATS flag
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
int wolfSSL_is_static_memory(WOLFSSL* ssl, WOLFSSL_MEM_CONN_STATS* mem_stats);

/*!
    \ingroup Memory

    \brief This function is used to set aside static memory for wolfCrypt use. Memory can be
    used by passing the created heap hint into functions. An example of this is when calling
    wc_InitRng_ex. The flag value passed in determines how the memory is used and behavior
    while operating, in general wolfCrypt operations will use memory from a WOLFMEM_GENERAL pool.
    Available flags are the following.

    WOLFMEM_GENERAL - default general memory

    WOLFMEM_IO_POOL - used for input/output buffer when sending receiving messages.
        Overrides general memory, so all memory in buffer passed in is used for IO.
    WOLFMEM_IO_FIXED - same as WOLFMEM_IO_POOL but each SSL now keeps two
        buffers to themselves for their lifetime.
    WOLFMEM_TRACK_STATS - each SSL keeps track of memory stats while running

    \return If successful, 0 will be returned.
    \return All unsuccessful return values will be less than 0.

    \param hint WOLFSSL_HEAP_HINT structure to use
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations (handshakes, IO).

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    int flag = WOLFMEM_GENERAL | WOLFMEM_TRACK_STATS;
    ...

    // load in memory for use

    ret = wc_LoadStaticMemory(&hint, memory, memorySz, flag, 0);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...

    ret = wc_InitRng_ex(&rng, hint, 0);

    // check ret value
    \endcode

    \sa none
*/
int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT* hint, unsigned char* buf, unsigned int sz,
                int flag, int max);

/*!
    \ingroup Memory

    \brief This function is used to set aside static memory for wolfCrypt use with custom
    bucket sizes and distributions. Memory can be used by passing the created heap hint
    into functions. This extended version allows for custom bucket sizes and distributions
    instead of using the default predefined sizes.

    \return If successful, 0 will be returned.
    \return All unsuccessful return values will be less than 0.

    \param hint WOLFSSL_HEAP_HINT structure to use
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations (handshakes, IO).
    \param bucket_sizes array of bucket sizes to use
    \param bucket_count number of bucket sizes in the array

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    int flag = WOLFMEM_GENERAL | WOLFMEM_TRACK_STATS;
    word16 bucket_sizes[] = {64, 128, 256, 512, 1024};
    int bucket_count = 5;
    ...

    // load in memory for use with custom bucket sizes

    ret = wc_LoadStaticMemory_ex(&hint, memory, memorySz, flag, 0,
                                 bucket_sizes, bucket_count);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...

    ret = wc_InitRng_ex(&rng, hint, 0);

    // check ret value
    \endcode

    \sa wc_LoadStaticMemory
    \sa wc_UnloadStaticMemory
*/
int wc_LoadStaticMemory_ex(WOLFSSL_HEAP_HINT* hint, unsigned char* buf, unsigned int sz,
                int flag, int max, word16* bucket_sizes, int bucket_count);

/*!
    \ingroup Memory

    \brief This function sets a global heap hint that will be used when NULL heap hint
    is passed to memory allocation functions. This allows for setting a default heap
    hint that will be used across the entire application.

    \return Returns the previous global heap hint that was set.

    \param hint WOLFSSL_HEAP_HINT structure to use as the global heap hint

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    WOLFSSL_HEAP_HINT* prev_hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    ...

    // load in memory for use
    ret = wc_LoadStaticMemory(&hint, memory, memorySz, WOLFMEM_GENERAL, 0);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }

    // set as global heap hint
    prev_hint = wolfSSL_SetGlobalHeapHint(&hint);
    if (prev_hint != NULL) {
        // there was a previous global heap hint
    }
    \endcode

    \sa wolfSSL_GetGlobalHeapHint
    \sa wc_LoadStaticMemory
*/
WOLFSSL_HEAP_HINT* wolfSSL_SetGlobalHeapHint(WOLFSSL_HEAP_HINT* hint);

/*!
    \ingroup Memory

    \brief This function gets the current global heap hint that is used when NULL
    heap hint is passed to memory allocation functions.

    \return Returns the current global heap hint, or NULL if none is set.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_HEAP_HINT* current_hint;
    ...

    current_hint = wolfSSL_GetGlobalHeapHint();
    if (current_hint != NULL) {
        // there is a global heap hint set
        // can use current_hint for operations
    }
    \endcode

    \sa wolfSSL_SetGlobalHeapHint
    \sa wc_LoadStaticMemory
*/
WOLFSSL_HEAP_HINT* wolfSSL_GetGlobalHeapHint(void);

/*!
    \ingroup Memory

    \brief This function sets a debug callback function for static memory allocation
    tracking. Used with WOLFSSL_STATIC_MEMORY_DEBUG_CALLBACK build option. The callback
    function will be called during memory allocation and deallocation operations to
    provide debugging information.

    \return If successful, 0 will be returned.
    \return All unsuccessful return values will be less than 0.

    \param cb debug callback function to set

    _Example_
    \code
    static void debug_memory_cb(const char* func, const char* file, int line,
                                void* ptr, size_t size, int type)
    {
        printf("Memory %s: %s:%d ptr=%p size=%zu type=%d\n",
               func, file, line, ptr, size, type);
    }
    ...

    // set debug callback
    int ret = wolfSSL_SetDebugMemoryCb(debug_memory_cb);
    if (ret != 0) {
        // handle error case
    }
    \endcode

    \sa none
*/
int wolfSSL_SetDebugMemoryCb(wolfSSL_DebugMemoryCb cb);

/*!
    \ingroup Memory

    \brief This function frees static memory heap and associated mutex. Should be
    called when done using static memory allocation to properly clean up resources.

    \return If successful, 0 will be returned.
    \return All unsuccessful return values will be less than 0.

    \param hint WOLFSSL_HEAP_HINT structure to unload

    _Example_
    \code
    WOLFSSL_HEAP_HINT hint;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    ...

    // load in memory for use
    ret = wc_LoadStaticMemory(&hint, memory, memorySz, WOLFMEM_GENERAL, 0);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }

    // use memory for operations
    ...

    // cleanup when done
    ret = wc_UnloadStaticMemory(&hint);
    if (ret != 0) {
        // handle error case
    }
    \endcode

    \sa wc_LoadStaticMemory
    \sa wc_LoadStaticMemory_ex
*/
int wc_UnloadStaticMemory(WOLFSSL_HEAP_HINT* hint);

/*!
    \ingroup Memory

    \brief This function calculates the required buffer size for static memory allocation
    with custom bucket sizes and distributions. This extended version allows for custom
    bucket sizes instead of using the default predefined sizes.

    \return On successfully completing buffer size calculations a positive value is returned.
    \return All negative values are considered to be error cases.

    \param bucket_sizes array of bucket sizes to use
    \param bucket_count number of bucket sizes in the array
    \param flag desired type of memory ie WOLFMEM_GENERAL or WOLFMEM_IO_POOL

    _Example_
    \code
    word32 sizeList[] = {64, 128, 256, 512, 1024};
    word32 distList[] = {1, 2, 1, 1, 1};
    int listSz = 5;
    int optimum;

    optimum = wolfSSL_StaticBufferSz_ex(listSz, sizeList, distList, NULL, 0,
        WOLFMEM_GENERAL);
    if (optimum < 0) { //handle error case }
    printf("The optimum buffer size with custom buckets is %d\n", optimum);
    ...
    \endcode

    \sa wolfSSL_StaticBufferSz
    \sa wc_LoadStaticMemory_ex
*/
int wolfSSL_StaticBufferSz_ex(unsigned int listSz,
            const word32 *sizeList, const word32 *distList,
            byte* buffer, word32 sz, int flag);

