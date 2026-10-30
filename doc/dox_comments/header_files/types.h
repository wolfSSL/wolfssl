/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which allows the user to substitute in their own malloc, realloc, and free
    functions in place of the standard C memory functions.
    To use external memory functions, define XMALLOC_USER. This will cause the
    memory functions to be replaced by external functions of the form:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    To use the basic C memory functions in place of wolfSSL_Malloc,
    wolfSSL_Realloc, wolfSSL_Free, define NO_WOLFSSL_MEMORY. This
    will replace the memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
    #define XREALLOC(p, n, h, t) realloc((p), (n))
    If none of these options are selected, the system will default to use
    the wolfSSL memory functions. A user can set custom memory functions
    through callback hooks, (see wolfSSL_Malloc,
    wolfSSL_Realloc, wolfSSL_Free). This option will replace the
    memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return pointer Return a pointer to allocated memory on success
	\return NULL on failure

	\param s size of memory to allocate
	\param h (used by custom XMALLOC function) pointer to the heap to use
	\param t memory allocation types for user hints. See enum in types.h

	_Example_
	\code
	int* tenInts = XMALLOC(sizeof(int)*10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tenInts == NULL) {
	    // error allocating space
	    return MEMORY_E;
    }
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void* XMALLOC(size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which allows the user to substitute in their own malloc, realloc, and
    free functions in place of the standard C memory functions.
    To use external memory functions, define XMALLOC_USER. This will cause the
    memory functions to be replaced by external functions of the form:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    To use the basic C memory functions in place of wolfSSL_Malloc,
    wolfSSL_Realloc, wolfSSL_Free, define NO_WOLFSSL_MEMORY. This will
    replace the memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
   	#define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
   	#define XREALLOC(p, n, h, t) realloc((p), (n))
    If none of these options are selected, the system will default to
    use the wolfSSL memory functions. A user can set custom memory
    functions through callback hooks, (see wolfSSL_Malloc,
    wolfSSL_Realloc, wolfSSL_Free). This option will replace
    the memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return Return a pointer to allocated memory on success
	\return NULL on failure

	\param p pointer to the address to reallocate
	\param n size of memory to allocate
	\param h (used by custom XREALLOC function) pointer to the heap to use
	\param t memory allocation types for user hints. See enum in types.h

	_Example_
	\code
	int* tenInts = (int*)XMALLOC(sizeof(int)*10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    int* twentyInts = (int*)XREALLOC(tenInts, sizeof(int)*20, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void* XREALLOC(void *p, size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which allows the user to substitute in their own malloc, realloc, and
    free functions in place of the standard C memory functions.
    To use external memory functions, define XMALLOC_USER. This will cause
    the memory functions to be replaced by external functions of the form:
    extern void *XMALLOC(size_t n, void* heap, int type);
    extern void *XREALLOC(void *p, size_t n, void* heap, int type);
    extern void XFREE(void *p, void* heap, int type);
    To use the basic C memory functions in place of wolfSSL_Malloc,
    wolfSSL_Realloc, wolfSSL_Free, define NO_WOLFSSL_MEMORY. This
    will replace the memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) free((xp));}
    #define XREALLOC(p, n, h, t) realloc((p), (n))
    If none of these options are selected, the system will default to use
    the wolfSSL memory functions. A user can set custom memory functions
    through callback hooks, (see wolfSSL_Malloc, wolfSSL_Realloc,
    wolfSSL_Free). This option will replace the memory functions with:
    #define XMALLOC(s, h, t) 	((void)h, (void)t, wolfSSL_Malloc((s)))
    #define XFREE(p, h, t)   	{void* xp = (p); if((xp)) wolfSSL_Free((xp));}
    #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n))

    \return none No returns.

    \param p pointer to the address to free
	\param h (used by custom XFREE function) pointer to the heap to use
	\param t memory allocation types for user hints. See enum in types.h

	_Example_
	\code
	int* tenInts = XMALLOC(sizeof(int) * 10, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tenInts == NULL) {
	    // error allocating space
	    return MEMORY_E;
    }
	\endcode

	\sa wolfSSL_Malloc
	\sa wolfSSL_Realloc
	\sa wolfSSL_Free
	\sa wolfSSL_SetAllocators
*/
void XFREE(void *p, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which allocates memory aligned to a given boundary. By default it maps to
    wc_MallocAlign(), which over-allocates through XMALLOC() and stores a
    small header just below the returned pointer, so heap and type reach
    every allocator (static memory, wolfSSL_SetAllocators() callbacks,
    XMALLOC_USER, ports). A port or user may supply its own implementation,
    but XMALLOCALIGN, XFREEALIGN, XREALLOCALIGN and XREALLOCALIGN_SCRUBBED
    must then all be defined together.
    Memory from XMALLOCALIGN must be released with XFREEALIGN, never XFREE,
    and XFREEALIGN must not be used on memory from XMALLOC.

    \return pointer to n bytes aligned to a on success.
    \return NULL if a is not 0 or a power of 2, or the allocation fails.

    \param a alignment: 0 or a power of 2. Values below 2*sizeof(size_t)
    (including 0) are raised to it.
    \param n size, in bytes, of the memory to allocate
    \param h pointer to the heap to use
    \param t memory allocation type for user hints. See enum in types.h

    _Example_
    \code
    byte* buf = (byte*)XMALLOCALIGN(64, 1024, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MEMORY_E;
    }
    ...
    XFREEALIGN(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    \endcode

    \sa XFREEALIGN
    \sa XREALLOCALIGN
    \sa wc_MallocAlign
*/
void* XMALLOCALIGN(size_t a, size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which frees memory from XMALLOCALIGN, XREALLOCALIGN or
    XREALLOCALIGN_SCRUBBED. By default it maps to wc_FreeAlign().

    \return none No returns.

    \param p aligned pointer to free. NULL is a no-op.
    \param h pointer to the heap used for the allocation
    \param t memory allocation type used for the allocation

    \sa XMALLOCALIGN
    \sa wc_FreeAlign
*/
void XFREEALIGN(void *p, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which reallocates memory from XMALLOCALIGN. It never reallocates in
    place: a new block aligned to a is allocated, the leading
    min(old size, n) bytes are copied, and p is freed. By default it maps to
    wc_ReallocAlign().

    \return pointer to the new aligned block on success.
    \return NULL when n is 0 (p is freed), or on failure (p is left intact,
    including when a is rejected).

    \param p NULL, or memory from XMALLOCALIGN/XREALLOCALIGN*. A NULL p
    behaves as XMALLOCALIGN.
    \param a alignment, as for XMALLOCALIGN
    \param n new size in bytes
    \param h pointer to the heap to use
    \param t memory allocation type for user hints. See enum in types.h

    _Example_
    \code
    byte* buf = (byte*)XMALLOCALIGN(64, 128, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    byte* tmp;
    ...
    tmp = (byte*)XREALLOCALIGN(buf, 64, 256, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp != NULL)
        buf = tmp;
    \endcode

    \sa XREALLOCALIGN_SCRUBBED
    \sa XMALLOCALIGN
    \sa wc_ReallocAlign
*/
void* XREALLOCALIGN(void *p, size_t a, size_t n, void* heap, int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro.
    As XREALLOCALIGN, but the old block is zeroized before it is freed,
    including when n is 0. On failure the old block is left intact and not
    zeroized. Use for buffers holding sensitive data. By default it maps to
    wc_ReallocAlignScrubbed().

    \return pointer to the new aligned block on success.
    \return NULL when n is 0 (p is zeroized and freed), or on failure.

    \param p NULL, or memory from XMALLOCALIGN/XREALLOCALIGN*
    \param a alignment, as for XMALLOCALIGN
    \param n new size in bytes
    \param h pointer to the heap to use
    \param t memory allocation type for user hints. See enum in types.h

    \sa XREALLOCALIGN
    \sa wc_ReallocAlignScrubbed
*/
void* XREALLOCALIGN_SCRUBBED(void *p, size_t a, size_t n, void* heap,
                             int type);

/*!
    \ingroup Memory

    \brief This is not actually a function, but rather a preprocessor macro,
    which reallocates memory from XMALLOC and zeroizes the old block before
    it is freed. It never reallocates in place: a new block is allocated with
    XMALLOC, the leading min(old_size, n) bytes are copied, old_size bytes of
    p are zeroized, and p is freed with XFREE. By default it maps to
    wc_ReallocScrubbed().

    \return pointer to the new block on success.
    \return NULL when n is 0 (p is zeroized and freed), or on failure (p is
    left intact and not zeroized).

    \param p NULL, or memory from XMALLOC/XREALLOC. A NULL p behaves as
    XMALLOC.
    \param old_size current size of p in bytes. Must not exceed the real
    allocation size, or the copy and zeroization overrun it.
    \param n new size in bytes
    \param h pointer to the heap to use
    \param t memory allocation type for user hints. See enum in types.h

    \sa XREALLOCALIGN_SCRUBBED
    \sa wc_ReallocScrubbed
*/
void* XREALLOC_SCRUBBED(void *p, size_t old_size, size_t n, void* heap,
                        int type);

/*!
    \ingroup Math

    \brief This function checks the compile time class settings. It is
    important when a user is using a wolfCrypt library independently, as
    the settings must match between libraries for math to work correctly.
    This check is defined as CheckCtcSettings(), which simply compares
    CheckRunTimeSettings and CTC_SETTINGS, returning 0 if there is a
    mismatch, or 1 if they match.

    \return settings Returns the runtime CTC_SETTINGS (Compile Time Settings)

    \param none No Parameters.

    _Example_
    \code
    if (CheckCtcSettings() != 1) {
	    return err_sys("Build vs. runtime math mismatch\n");
    }
    // This is converted by the preprocessor to:
    // if ( (CheckCtcSettings() == CTC_SETTINGS) != 1) {
    // and will compare whether the compile time class settings
    // match the current settings
    \endcode

    \sa CheckRunTimeFastMath
*/
word32 CheckRunTimeSettings(void);

/*!
    \ingroup String
    \brief Thread-safe string tokenization.

    \return Pointer to next token or NULL

    \param str String to tokenize (NULL for continuation)
    \param delim Delimiter characters
    \param nextp Pointer to save position

    _Example_
    \code
    char str[] = "one,two,three";
    char* saveptr;
    char* token = wc_strtok(str, ",", &saveptr);
    \endcode

    \sa wc_strsep
*/
char* wc_strtok(char *str, const char *delim, char **nextp);

/*!
    \ingroup String
    \brief Separates string by delimiter.

    \return Pointer to token or NULL

    \param stringp Pointer to string pointer
    \param delim Delimiter characters

    _Example_
    \code
    char str[] = "one,two,three";
    char* ptr = str;
    char* token = wc_strsep(&ptr, ",");
    \endcode

    \sa wc_strtok
*/
char* wc_strsep(char **stringp, const char *delim);

/*!
    \ingroup String
    \brief Safely copies string with size limit.

    \return Length of source string

    \param dst Destination buffer
    \param src Source string
    \param dstSize Destination buffer size

    _Example_
    \code
    char dst[10];
    size_t len = wc_strlcpy(dst, "hello", sizeof(dst));
    \endcode

    \sa wc_strlcat
*/
size_t wc_strlcpy(char *dst, const char *src, size_t dstSize);

/*!
    \ingroup wolfCrypt
    \brief Expands a packed octet stream into the one-octet-per-byte-cell form
    every wolfCrypt byte* API expects. Declared only when WOLFSSL_WIDE_BYTE is
    set (CHAR_BIT != 8); elsewhere the two layouts coincide and no conversion
    is needed.

    \return 0 on success
    \return BAD_FUNC_ARG when out or in is NULL
    \return BUFFER_E when out is smaller than octetSz, or in smaller than
    WC_PACKED_CELLS(octetSz)

    \param out Destination, one octet per cell
    \param outSz Size of out in byte cells
    \param in Packed source, WC_OCTETS_PER_BYTE octets per cell, low octet
    first, and must not overlap out
    \param inSz Size of in in byte cells; must be at least
    WC_PACKED_CELLS(octetSz)
    \param octetSz Number of octets to expand

    _Example_
    \code
    byte sig[WC_MLDSA_65_SIG_SIZE];
    int ret = wc_UnpackOctets(sig, (word32)sizeof(sig), sigPacked,
                              (word32)sizeof(sigPacked),
                              WC_MLDSA_65_SIG_SIZE);
    \endcode

    \sa wc_PackOctets
*/
int wc_UnpackOctets(byte* out, word32 outSz, const byte* in, word32 inSz,
                    word32 octetSz);

/*!
    \ingroup wolfCrypt
    \brief Packs a one-octet-per-byte-cell buffer into an octet stream, for
    storing to flash or handing to a byte-oriented peripheral. Inverse of
    wc_UnpackOctets(); requires WOLFSSL_WIDE_BYTE.

    \return 0 on success
    \return BAD_FUNC_ARG when out or in is NULL
    \return BUFFER_E when out is smaller than WC_PACKED_CELLS(octetSz), or
    in smaller than octetSz

    \param out Destination for the packed stream
    \param outSz Size of out in byte cells
    \param in Source, one octet per cell, and must not overlap out
    \param inSz Size of in in byte cells; must be at least octetSz
    \param octetSz Number of octets to pack

    _Example_
    \code
    byte packed[WC_PACKED_CELLS(sizeof(sig))];
    int ret = wc_PackOctets(packed, (word32)sizeof(packed), sig,
                            (word32)sizeof(sig), (word32)sizeof(sig));
    \endcode

    \sa wc_UnpackOctets
*/
int wc_PackOctets(byte* out, word32 outSz, const byte* in, word32 inSz,
                  word32 octetSz);

/*!
    \ingroup String
    \brief Safely concatenates strings with size limit.

    \return Total length attempted

    \param dst Destination buffer
    \param src Source string
    \param dstSize Destination buffer size

    _Example_
    \code
    char dst[20] = "hello";
    size_t len = wc_strlcat(dst, " world", sizeof(dst));
    \endcode

    \sa wc_strlcpy
*/
size_t wc_strlcat(char *dst, const char *src, size_t dstSize);

/*!
    \ingroup String
    \brief Case-insensitive string comparison.

    \return 0 if equal, non-zero otherwise

    \param s1 First string
    \param s2 Second string

    _Example_
    \code
    if (wc_strcasecmp("Hello", "hello") == 0) {
        // strings are equal
    }
    \endcode

    \sa wc_strncasecmp
*/
int wc_strcasecmp(const char *s1, const char *s2);

/*!
    \ingroup String
    \brief Case-insensitive string comparison with length limit.

    \return 0 if equal, non-zero otherwise

    \param s1 First string
    \param s2 Second string
    \param n Maximum characters to compare

    _Example_
    \code
    if (wc_strncasecmp("Hello", "hello", 5) == 0) {
        // strings are equal
    }
    \endcode

    \sa wc_strcasecmp
*/
int wc_strncasecmp(const char *s1, const char *s2, size_t n);

/*!
    \ingroup Threading
    \brief Creates a new thread.

    \return 0 on success
    \return negative on error

    \param thread Thread handle pointer
    \param cb Thread callback function
    \param arg Argument to pass to callback

    _Example_
    \code
    THREAD_TYPE thread;
    int ret = wolfSSL_NewThread(&thread, myCallback, NULL);
    \endcode

    \sa wolfSSL_JoinThread
*/
int wolfSSL_NewThread(THREAD_TYPE* thread, THREAD_CB cb, void* arg);

/*!
    \ingroup Threading
    \brief Creates a detached thread.

    \return 0 on success
    \return negative on error

    \param cb Thread callback function
    \param arg Argument to pass to callback

    _Example_
    \code
    int ret = wolfSSL_NewThreadNoJoin(myCallback, NULL);
    \endcode

    \sa wolfSSL_NewThread
*/
int wolfSSL_NewThreadNoJoin(THREAD_CB_NOJOIN cb, void* arg);

/*!
    \ingroup Threading
    \brief Waits for thread to complete.

    \return 0 on success
    \return negative on error

    \param thread Thread handle

    _Example_
    \code
    THREAD_TYPE thread;
    wolfSSL_NewThread(&thread, myCallback, NULL);
    int ret = wolfSSL_JoinThread(thread);
    \endcode

    \sa wolfSSL_NewThread
*/
int wolfSSL_JoinThread(THREAD_TYPE thread);

/*!
    \ingroup Threading
    \brief Initializes condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    int ret = wolfSSL_CondInit(&cond);
    \endcode

    \sa wolfSSL_CondFree
*/
int wolfSSL_CondInit(COND_TYPE* cond);

/*!
    \ingroup Threading
    \brief Frees condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    wolfSSL_CondInit(&cond);
    int ret = wolfSSL_CondFree(&cond);
    \endcode

    \sa wolfSSL_CondInit
*/
int wolfSSL_CondFree(COND_TYPE* cond);

/*!
    \ingroup Threading
    \brief Signals condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    int ret = wolfSSL_CondSignal(&cond);
    \endcode

    \sa wolfSSL_CondWait
*/
int wolfSSL_CondSignal(COND_TYPE* cond);

/*!
    \ingroup Threading
    \brief Waits on condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    int ret = wolfSSL_CondWait(&cond);
    \endcode

    \sa wolfSSL_CondSignal
*/
int wolfSSL_CondWait(COND_TYPE* cond);

/*!
    \ingroup Threading
    \brief Starts condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    int ret = wolfSSL_CondStart(&cond);
    \endcode

    \sa wolfSSL_CondEnd
*/
int wolfSSL_CondStart(COND_TYPE* cond);

/*!
    \ingroup Threading
    \brief Ends condition variable.

    \return 0 on success
    \return negative on error

    \param cond Condition variable pointer

    _Example_
    \code
    COND_TYPE cond;
    wolfSSL_CondStart(&cond);
    int ret = wolfSSL_CondEnd(&cond);
    \endcode

    \sa wolfSSL_CondStart
*/
int wolfSSL_CondEnd(COND_TYPE* cond);
