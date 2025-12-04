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
