/*!
    \ingroup wolfCrypt

    \brief Used to initialize resources used by wolfCrypt.

    \return 0 upon success.
    \return <0 upon failure of init resources.

    \param none No parameters.

    _Example_
    \code
    ...
    if (wolfCrypt_Init() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Init call");
    }
    \endcode

    \sa wolfCrypt_Cleanup
*/
int wolfCrypt_Init(void);

/*!
    \ingroup wolfCrypt

    \brief Used to clean up resources used by wolfCrypt.

    \return 0 upon success.
    \return <0 upon failure of cleaning up resources.

    \param none No parameters.

    _Example_
    \code
    ...
    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
    }
    \endcode

    \sa wolfCrypt_Init
*/
int wolfCrypt_Cleanup(void);

/*!
    \ingroup Atomic
    \brief Initializes atomic integer.

    \return none No returns

    \param c Atomic integer pointer
    \param i Initial value

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    wolfSSL_Atomic_Int_Init(&counter, 0);
    \endcode

    \sa wolfSSL_Atomic_Int_FetchAdd
*/
void wolfSSL_Atomic_Int_Init(wolfSSL_Atomic_Int* c, int i);

/*!
    \ingroup Atomic
    \brief Initializes atomic unsigned integer.

    \return none No returns

    \param c Atomic unsigned integer pointer
    \param i Initial value

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    wolfSSL_Atomic_Uint_Init(&counter, 0);
    \endcode

    \sa wolfSSL_Atomic_Uint_FetchAdd
*/
void wolfSSL_Atomic_Uint_Init(wolfSSL_Atomic_Uint* c, unsigned int i);

/*!
    \ingroup Atomic
    \brief Atomically adds to integer and returns old value.

    \return Old value before addition

    \param c Atomic integer pointer
    \param i Value to add

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    int old = wolfSSL_Atomic_Int_FetchAdd(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Int_AddFetch
*/
int wolfSSL_Atomic_Int_FetchAdd(wolfSSL_Atomic_Int* c, int i);

/*!
    \ingroup Atomic
    \brief Atomically subtracts from integer and returns old value.

    \return Old value before subtraction

    \param c Atomic integer pointer
    \param i Value to subtract

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    int old = wolfSSL_Atomic_Int_FetchSub(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Int_SubFetch
*/
int wolfSSL_Atomic_Int_FetchSub(wolfSSL_Atomic_Int* c, int i);

/*!
    \ingroup Atomic
    \brief Atomically adds to integer and returns new value.

    \return New value after addition

    \param c Atomic integer pointer
    \param i Value to add

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    int new_val = wolfSSL_Atomic_Int_AddFetch(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Int_FetchAdd
*/
int wolfSSL_Atomic_Int_AddFetch(wolfSSL_Atomic_Int* c, int i);

/*!
    \ingroup Atomic
    \brief Atomically subtracts from integer and returns new value.

    \return New value after subtraction

    \param c Atomic integer pointer
    \param i Value to subtract

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    int new_val = wolfSSL_Atomic_Int_SubFetch(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Int_FetchSub
*/
int wolfSSL_Atomic_Int_SubFetch(wolfSSL_Atomic_Int* c, int i);

/*!
    \ingroup Atomic
    \brief Atomically compares and exchanges integer.

    \return 1 if exchange occurred, 0 otherwise

    \param c Atomic integer pointer
    \param expected_i Pointer to expected value
    \param new_i New value to set

    _Example_
    \code
    wolfSSL_Atomic_Int counter;
    int expected = 0;
    int ret = wolfSSL_Atomic_Int_CompareExchange(&counter, &expected, 1);
    \endcode

    \sa wolfSSL_Atomic_Int_FetchAdd
*/
int wolfSSL_Atomic_Int_CompareExchange(wolfSSL_Atomic_Int* c,
                                       int *expected_i, int new_i);

/*!
    \ingroup Atomic
    \brief Atomically adds to unsigned integer and returns old value.

    \return Old value before addition

    \param c Atomic unsigned integer pointer
    \param i Value to add

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    unsigned int old = wolfSSL_Atomic_Uint_FetchAdd(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Uint_AddFetch
*/
unsigned int wolfSSL_Atomic_Uint_FetchAdd(wolfSSL_Atomic_Uint* c,
                                          unsigned int i);

/*!
    \ingroup Atomic
    \brief Atomically subtracts from unsigned integer, returns old value.

    \return Old value before subtraction

    \param c Atomic unsigned integer pointer
    \param i Value to subtract

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    unsigned int old = wolfSSL_Atomic_Uint_FetchSub(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Uint_SubFetch
*/
unsigned int wolfSSL_Atomic_Uint_FetchSub(wolfSSL_Atomic_Uint* c,
                                          unsigned int i);

/*!
    \ingroup Atomic
    \brief Atomically adds to unsigned integer, returns new value.

    \return New value after addition

    \param c Atomic unsigned integer pointer
    \param i Value to add

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    unsigned int new_val = wolfSSL_Atomic_Uint_AddFetch(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Uint_FetchAdd
*/
unsigned int wolfSSL_Atomic_Uint_AddFetch(wolfSSL_Atomic_Uint* c,
                                          unsigned int i);

/*!
    \ingroup Atomic
    \brief Atomically subtracts from unsigned integer, returns new value.

    \return New value after subtraction

    \param c Atomic unsigned integer pointer
    \param i Value to subtract

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    unsigned int new_val = wolfSSL_Atomic_Uint_SubFetch(&counter, 1);
    \endcode

    \sa wolfSSL_Atomic_Uint_FetchSub
*/
unsigned int wolfSSL_Atomic_Uint_SubFetch(wolfSSL_Atomic_Uint* c,
                                          unsigned int i);

/*!
    \ingroup Atomic
    \brief Atomically compares and exchanges unsigned integer.

    \return 1 if exchange occurred, 0 otherwise

    \param c Atomic unsigned integer pointer
    \param expected_i Pointer to expected value
    \param new_i New value to set

    _Example_
    \code
    wolfSSL_Atomic_Uint counter;
    unsigned int expected = 0;
    int ret = wolfSSL_Atomic_Uint_CompareExchange(&counter, &expected, 1);
    \endcode

    \sa wolfSSL_Atomic_Uint_FetchAdd
*/
int wolfSSL_Atomic_Uint_CompareExchange(wolfSSL_Atomic_Uint* c,
                                        unsigned int *expected_i,
                                        unsigned int new_i);

/*!
    \ingroup Atomic
    \brief Atomically compares and exchanges pointer.

    \return 1 if exchange occurred, 0 otherwise

    \param c Pointer to pointer
    \param expected_ptr Pointer to expected pointer value
    \param new_ptr New pointer value

    _Example_
    \code
    void* ptr = NULL;
    void* expected = NULL;
    void* new_val = malloc(100);
    int ret = wolfSSL_Atomic_Ptr_CompareExchange(&ptr, &expected, new_val);
    \endcode

    \sa wolfSSL_Atomic_Int_CompareExchange
*/
int wolfSSL_Atomic_Ptr_CompareExchange(void** c, void **expected_ptr,
                                       void *new_ptr);

/*!
    \ingroup Mutex
    \brief Initializes mutex.

    \return 0 on success
    \return negative on error

    \param m Mutex pointer

    _Example_
    \code
    wolfSSL_Mutex mutex;
    int ret = wc_InitMutex(&mutex);
    \endcode

    \sa wc_FreeMutex
*/
int wc_InitMutex(wolfSSL_Mutex* m);

/*!
    \ingroup Mutex
    \brief Frees mutex resources.

    \return 0 on success
    \return negative on error

    \param m Mutex pointer

    _Example_
    \code
    wolfSSL_Mutex mutex;
    wc_InitMutex(&mutex);
    int ret = wc_FreeMutex(&mutex);
    \endcode

    \sa wc_InitMutex
*/
int wc_FreeMutex(wolfSSL_Mutex* m);

/*!
    \ingroup Mutex
    \brief Locks mutex.

    \return 0 on success
    \return negative on error

    \param m Mutex pointer

    _Example_
    \code
    wolfSSL_Mutex mutex;
    int ret = wc_LockMutex(&mutex);
    \endcode

    \sa wc_UnLockMutex
*/
int wc_LockMutex(wolfSSL_Mutex* m);

/*!
    \ingroup Mutex
    \brief Unlocks mutex.

    \return 0 on success
    \return negative on error

    \param m Mutex pointer

    _Example_
    \code
    wolfSSL_Mutex mutex;
    wc_LockMutex(&mutex);
    int ret = wc_UnLockMutex(&mutex);
    \endcode

    \sa wc_LockMutex
*/
int wc_UnLockMutex(wolfSSL_Mutex* m);

/*!
    \ingroup Mutex
    \brief Initializes and allocates mutex.

    \return Pointer to mutex on success
    \return NULL on error

    \param none No parameters

    _Example_
    \code
    wolfSSL_Mutex* mutex = wc_InitAndAllocMutex();
    if (mutex != NULL) {
        wc_LockMutex(mutex);
    }
    \endcode

    \sa wc_InitMutex
*/
wolfSSL_Mutex* wc_InitAndAllocMutex(void);

/*!
    \ingroup RwLock
    \brief Initializes read-write lock.

    \return 0 on success
    \return negative on error

    \param m Read-write lock pointer

    _Example_
    \code
    wolfSSL_RwLock lock;
    int ret = wc_InitRwLock(&lock);
    \endcode

    \sa wc_FreeRwLock
*/
int wc_InitRwLock(wolfSSL_RwLock* m);

/*!
    \ingroup RwLock
    \brief Frees read-write lock resources.

    \return 0 on success
    \return negative on error

    \param m Read-write lock pointer

    _Example_
    \code
    wolfSSL_RwLock lock;
    wc_InitRwLock(&lock);
    int ret = wc_FreeRwLock(&lock);
    \endcode

    \sa wc_InitRwLock
*/
int wc_FreeRwLock(wolfSSL_RwLock* m);

/*!
    \ingroup RwLock
    \brief Locks read-write lock for writing.

    \return 0 on success
    \return negative on error

    \param m Read-write lock pointer

    _Example_
    \code
    wolfSSL_RwLock lock;
    int ret = wc_LockRwLock_Wr(&lock);
    \endcode

    \sa wc_UnLockRwLock
*/
int wc_LockRwLock_Wr(wolfSSL_RwLock* m);

/*!
    \ingroup RwLock
    \brief Locks read-write lock for reading.

    \return 0 on success
    \return negative on error

    \param m Read-write lock pointer

    _Example_
    \code
    wolfSSL_RwLock lock;
    int ret = wc_LockRwLock_Rd(&lock);
    \endcode

    \sa wc_UnLockRwLock
*/
int wc_LockRwLock_Rd(wolfSSL_RwLock* m);

/*!
    \ingroup RwLock
    \brief Unlocks read-write lock.

    \return 0 on success
    \return negative on error

    \param m Read-write lock pointer

    _Example_
    \code
    wolfSSL_RwLock lock;
    wc_LockRwLock_Rd(&lock);
    int ret = wc_UnLockRwLock(&lock);
    \endcode

    \sa wc_LockRwLock_Rd
*/
int wc_UnLockRwLock(wolfSSL_RwLock* m);

/*!
    \ingroup Mutex
    \brief Locks mutex with debug info.

    \return 0 on success
    \return negative on error

    \param flag Lock flag
    \param type Lock type
    \param file Source file name
    \param line Source line number

    _Example_
    \code
    int ret = wc_LockMutex_ex(0, 0, __FILE__, __LINE__);
    \endcode

    \sa wc_LockMutex
*/
int wc_LockMutex_ex(int flag, int type, const char* file, int line);

/*!
    \ingroup Mutex
    \brief Sets mutex callback.

    \return 0 on success
    \return negative on error

    \param cb Mutex callback pointer

    _Example_
    \code
    mutex_cb cb;
    int ret = wc_SetMutexCb(&cb);
    \endcode

    \sa wc_GetMutexCb
*/
int wc_SetMutexCb(mutex_cb* cb);

/*!
    \ingroup Mutex
    \brief Gets mutex callback.

    \return Pointer to mutex callback

    \param none No parameters

    _Example_
    \code
    mutex_cb* cb = wc_GetMutexCb();
    \endcode

    \sa wc_SetMutexCb
*/
mutex_cb* wc_GetMutexCb(void);

/*!
    \ingroup Memory
    \brief Checkpoints peak heap allocations.

    \return Peak allocation count

    \param none No parameters

    _Example_
    \code
    long peak = wolfCrypt_heap_peakAllocs_checkpoint();
    \endcode

    \sa wolfCrypt_heap_peakBytes_checkpoint
*/
long wolfCrypt_heap_peakAllocs_checkpoint(void);

/*!
    \ingroup Memory
    \brief Checkpoints peak heap bytes.

    \return Peak bytes allocated

    \param none No parameters

    _Example_
    \code
    long peak = wolfCrypt_heap_peakBytes_checkpoint();
    \endcode

    \sa wolfCrypt_heap_peakAllocs_checkpoint
*/
long wolfCrypt_heap_peakBytes_checkpoint(void);

/*!
    \ingroup File
    \brief Loads file into buffer.

    \return 0 on success
    \return negative on error

    \param fname File name
    \param buf Buffer pointer
    \param bufLen Buffer length pointer
    \param heap Heap hint

    _Example_
    \code
    unsigned char* buf = NULL;
    size_t len = 0;
    int ret = wc_FileLoad("file.txt", &buf, &len, NULL);
    \endcode

    \sa wc_FileExists
*/
int wc_FileLoad(const char* fname, unsigned char** buf, size_t* bufLen,
                void* heap);

/*!
    \ingroup File
    \brief Reads first entry in directory.

    \return 0 on success
    \return negative on error

    \param ctx Directory context
    \param path Directory path
    \param name Pointer to store entry name

    _Example_
    \code
    ReadDirCtx ctx;
    char* name;
    int ret = wc_ReadDirFirst(&ctx, "/path", &name);
    \endcode

    \sa wc_ReadDirNext
*/
int wc_ReadDirFirst(ReadDirCtx* ctx, const char* path, char** name);

/*!
    \ingroup File
    \brief Reads next entry in directory.

    \return 0 on success
    \return negative on error

    \param ctx Directory context
    \param path Directory path
    \param name Pointer to store entry name

    _Example_
    \code
    ReadDirCtx ctx;
    char* name;
    int ret = wc_ReadDirNext(&ctx, "/path", &name);
    \endcode

    \sa wc_ReadDirFirst
*/
int wc_ReadDirNext(ReadDirCtx* ctx, const char* path, char** name);

/*!
    \ingroup File
    \brief Closes directory reading.

    \return none No returns

    \param ctx Directory context

    _Example_
    \code
    ReadDirCtx ctx;
    wc_ReadDirClose(&ctx);
    \endcode

    \sa wc_ReadDirFirst
*/
void wc_ReadDirClose(ReadDirCtx* ctx);

/*!
    \ingroup File
    \brief Checks if file exists.

    \return 1 if file exists
    \return 0 if file does not exist

    \param fname File name

    _Example_
    \code
    if (wc_FileExists("file.txt")) {
        // file exists
    }
    \endcode

    \sa wc_FileLoad
*/
int wc_FileExists(const char* fname);

/*!
    \ingroup Callback
    \brief Checks if handle callback is set.

    \return 1 if set
    \return 0 if not set

    \param none No parameters

    _Example_
    \code
    if (wolfSSL_GetHandleCbSet()) {
        // callback is set
    }
    \endcode

    \sa wolfSSL_SetHandleCb
*/
int wolfSSL_GetHandleCbSet(void);

/*!
    \ingroup Callback
    \brief Sets handle callback.

    \return 0 on success
    \return negative on error

    \param in Handle callback

    _Example_
    \code
    int ret = wolfSSL_SetHandleCb(myHandleCallback);
    \endcode

    \sa wolfSSL_GetHandleCbSet
*/
int wolfSSL_SetHandleCb(wolfSSL_DSP_Handle_cb in);
