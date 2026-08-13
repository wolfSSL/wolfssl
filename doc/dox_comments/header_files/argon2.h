/*!
    \ingroup ARGON2

    \brief This function initializes an Argon2 context. No memory is
    allocated: the block array is sized by the cost parameters and is
    allocated by wc_Argon2SetParams(). Every context must be released with
    wc_Argon2Free().

    Use the context API in preference to wc_Argon2() when deriving many tags
    with the same cost parameters, so that the block array - which may be
    tens or hundreds of megabytes - is allocated only once.

    \return 0 on success.
    \return BAD_FUNC_ARG if a is NULL.

    \param a pointer to the Argon2 context to initialize.
    \param heap heap hint passed to XMALLOC; may be NULL.
    \param devId device identifier; reserved for future use, pass
    INVALID_DEVID.

    _Example_
    \code
    Argon2Ctx a;
    byte key[32];

    if (wc_Argon2Init(&a, NULL, INVALID_DEVID) != 0)
        // handle error
    if (wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 65536, 3) != 0)
        // handle error
    if (wc_Argon2DeriveTag(&a, key, sizeof(key), pwd, pwdSz, salt, saltSz,
                        NULL, 0, NULL, 0) != 0)
        // handle error
    wc_Argon2Free(&a);
    \endcode

    \sa wc_Argon2Free
    \sa wc_Argon2SetParams
    \sa wc_Argon2DeriveTag
*/
int wc_Argon2Init(Argon2Ctx* a, void* heap, int devId);

/*!
    \ingroup ARGON2

    \brief This function releases the resources held by an Argon2 context.
    The block array holds the whole of the secret state and is wiped before
    being returned to the allocator. Safe to call on a context whose
    parameters were never set, and safe to call more than once.

    \return none No returns.

    \param a pointer to the Argon2 context to free; may be NULL.

    _Example_
    \code
    Argon2Ctx a;

    if (wc_Argon2Init(&a, NULL, INVALID_DEVID) != 0)
        // handle error
    ...
    wc_Argon2Free(&a);
    \endcode

    \sa wc_Argon2Init
*/
void wc_Argon2Free(Argon2Ctx* a);

/*!
    \ingroup ARGON2

    \brief This function allocates and initializes a new Argon2 context. The
    returned context has no parameters set; call wc_Argon2SetParams() before
    wc_Argon2DeriveTag(). Release it with wc_Argon2Delete().

    Only available when WC_NO_CONSTRUCTORS is not defined.

    \return pointer to the new Argon2 context on success.
    \return NULL if the allocation fails, with result_code set to MEMORY_E
    when it is not NULL.

    \param heap heap hint passed to XMALLOC; may be NULL.
    \param devId device identifier; reserved for future use, pass
    INVALID_DEVID.
    \param result_code pointer to hold the result of the operation; may be
    NULL.

    _Example_
    \code
    Argon2Ctx* a;
    int ret;

    a = wc_Argon2New(NULL, INVALID_DEVID, &ret);
    if (a == NULL)
        // handle error, ret holds the reason
    if (wc_Argon2SetParams(a, WC_ARGON2_ID, 4, 65536, 3) != 0)
        // handle error
    ...
    wc_Argon2Delete(a, &a);
    \endcode

    \sa wc_Argon2Delete
    \sa wc_Argon2Init
*/
Argon2Ctx* wc_Argon2New(void* heap, int devId, int* result_code);

/*!
    \ingroup ARGON2

    \brief This function frees an Argon2 context created with
    wc_Argon2New(), wiping the block array, and sets the caller's pointer to
    NULL.

    Only available when WC_NO_CONSTRUCTORS is not defined.

    \return 0 on success.
    \return BAD_FUNC_ARG if a is NULL.

    \param a pointer to the Argon2 context to delete.
    \param a_p pointer to the context pointer, set to NULL; may be NULL.

    _Example_
    \code
    Argon2Ctx* a = wc_Argon2New(NULL, INVALID_DEVID, NULL);

    ...
    if (wc_Argon2Delete(a, &a) != 0)
        // handle error
    // a is now NULL
    \endcode

    \sa wc_Argon2New
*/
int wc_Argon2Delete(Argon2Ctx* a, Argon2Ctx** a_p);

/*!
    \ingroup ARGON2

    \brief This function sets the variant and cost parameters on an Argon2
    context and allocates the block array. It may be called again to change
    the parameters; the existing allocation is kept when the new parameters
    need a block array of the same size.

    See wc_Argon2() for guidance on choosing the variant and the cost
    parameters.

    \return 0 on success.
    \return BAD_FUNC_ARG if a is NULL, if type is not one of the three
    variants, if parallel or timeCost is zero, if parallel exceeds
    WC_ARGON2_MAX_LANES, or if memCost is below 8 * parallel.
    \return MEMORY_E if the block array could not be allocated.

    \param a pointer to the Argon2 context.
    \param type variant to use: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID.
    \param parallel degree of parallelism p (number of lanes).
    \param memCost memory size m in KiB; must be at least 8 * parallel. It
    is rounded down internally to a multiple of 4 * parallel.
    \param timeCost number of passes t over the memory, at least 1.

    _Example_
    \code
    Argon2Ctx a;

    if (wc_Argon2Init(&a, NULL, INVALID_DEVID) != 0)
        // handle error
    // Argon2id, p = 4 lanes, m = 64 MiB, t = 3 passes
    if (wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 65536, 3) != 0)
        // handle error
    \endcode

    \sa wc_Argon2Init
    \sa wc_Argon2DeriveTag
*/
int wc_Argon2SetParams(Argon2Ctx* a, int type, word32 parallel,
    word32 memCost, word32 timeCost);

/*!
    \ingroup ARGON2

    \brief This function sets the number of threads used to fill the segments
    of a slice. Only available when WOLFSSL_ARGON2_THREADS is defined, which
    the --enable-argon2-threads configure option does.

    The p segments of a slice are independent, so up to p of them can be
    filled at once. A count above the lane count is accepted but allocates no
    more workers than there are lanes, since the extra ones could never be
    given work. A count of 1 spawns no threads at all: one segment of every
    batch is always filled by the calling thread.

    This does not change the tag. The synchronization point at the end of
    every slice makes the result the same however many threads fill it, so a
    tag derived with one thread and the same tag derived with eight are
    identical.

    Changing the count reallocates the per-thread working state, so prefer to
    set it once before deriving.

    \return 0 on success.
    \return BAD_FUNC_ARG if a is NULL, or threads is 0 or above
    WC_ARGON2_MAX_THREADS.
    \return MEMORY_E if the per-thread working state could not be allocated.

    \param a pointer to the Argon2 context.
    \param threads number of threads to use, at least 1.

    _Example_
    \code
    Argon2Ctx a;
    byte key[32];

    if (wc_Argon2Init(&a, NULL, INVALID_DEVID) != 0)
        // handle error
    // Argon2id, p = 4 lanes, m = 64 MiB, t = 3 passes, filled by 4 threads
    if (wc_Argon2SetThreads(&a, 4) != 0)
        // handle error
    if (wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 65536, 3) != 0)
        // handle error
    if (wc_Argon2DeriveTag(&a, key, sizeof(key), pwd, pwdSz, salt, saltSz,
                           NULL, 0, NULL, 0) != 0)
        // handle error
    wc_Argon2Free(&a);
    \endcode

    \sa wc_Argon2SetParams
    \sa wc_Argon2DeriveTag
*/
int wc_Argon2SetThreads(Argon2Ctx* a, word32 threads);

/*!
    \ingroup ARGON2

    \brief This function derives a key using the parameters already set on
    the context with wc_Argon2SetParams(). The context may be reused for any
    number of derivations; no allocation is performed here.

    The optional secret K (secret/secretSz) and associated data X (ad/adSz)
    of RFC 9106 are accepted, as for wc_Argon2_ex(). Pass NULL and 0 when
    they are unused.

    \return 0 on success.
    \return BAD_FUNC_ARG if a, out or salt is NULL, or if pwd, secret or ad
    is NULL while its length is non-zero.
    \return BAD_STATE_E if wc_Argon2SetParams() has not been called.
    \return BAD_LENGTH_E if outSz is below WC_ARGON2_MIN_OUTLEN or saltSz is
    below WC_ARGON2_MIN_SALT_LEN.

    \param a pointer to the Argon2 context with parameters set.
    \param out buffer to hold the derived key (the "tag").
    \param outSz length of out in bytes, at least WC_ARGON2_MIN_OUTLEN.
    \param pwd password to derive from; may be NULL only when pwdSz is 0.
    \param pwdSz length of pwd in bytes.
    \param salt salt to derive with; should be unique per password.
    \param saltSz length of salt in bytes, at least WC_ARGON2_MIN_SALT_LEN.
    \param secret optional secret value K; NULL when unused.
    \param secretSz length of secret in bytes, 0 when unused.
    \param ad optional associated data X; NULL when unused.
    \param adSz length of ad in bytes, 0 when unused.

    _Example_
    \code
    Argon2Ctx a;
    byte key[32];
    int i;

    if (wc_Argon2Init(&a, NULL, INVALID_DEVID) != 0)
        // handle error
    if (wc_Argon2SetParams(&a, WC_ARGON2_ID, 4, 65536, 3) != 0)
        // handle error

    // The block array is allocated once and reused for every password.
    for (i = 0; i < numPasswords; i++) {
        if (wc_Argon2DeriveTag(&a, key, sizeof(key), pwd[i], pwdSz[i],
                            salt[i], saltSz[i], NULL, 0, NULL, 0) != 0)
            // handle error
    }

    wc_Argon2Free(&a);
    \endcode

    \sa wc_Argon2SetParams
    \sa wc_Argon2Init
    \sa wc_Argon2_ex
*/
int wc_Argon2DeriveTag(Argon2Ctx* a, byte* out, word32 outSz,
    const byte* pwd, word32 pwdSz, const byte* salt, word32 saltSz,
    const byte* secret, word32 secretSz, const byte* ad, word32 adSz);

/*!
    \ingroup ARGON2

    \brief This function derives a key from a password using Argon2, the
    memory-hard password hashing function specified in RFC 9106. Version
    0x13 is used; the superseded 0x10 encoding is not supported.

    Pick the variant to suit the threat model: WC_ARGON2_ID is the choice
    RFC 9106 recommends when there is no reason to prefer another, since it
    resists both side-channel and time-memory trade-off attacks.
    WC_ARGON2_I resists side-channel attacks but is weaker against
    trade-off attacks, and WC_ARGON2_D the reverse; WC_ARGON2_D should not
    be used where an attacker may observe memory access patterns.

    RFC 9106 section 4 recommends t=3 and p=4 with m=65536 (64 MiB) if 64
    MiB is available, or t=1 and p=4 with m=2097152 (2 GiB) for the
    highest-security setting. Cost parameters should be raised to the most
    the application can tolerate.

    \return 0 on success.
    \return BAD_FUNC_ARG if out or salt is NULL, if pwd is NULL while pwdSz
    is non-zero, if type is not one of the three variants, if parallel or
    timeCost is zero, if parallel exceeds WC_ARGON2_MAX_LANES, or if memCost
    is below 8 * parallel.
    \return BAD_LENGTH_E if outSz is below WC_ARGON2_MIN_OUTLEN or saltSz is
    below WC_ARGON2_MIN_SALT_LEN.
    \return MEMORY_E if the memory block array could not be allocated.

    \param type variant to use: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID.
    \param out buffer to hold the derived key (the "tag").
    \param outSz length of out in bytes, at least WC_ARGON2_MIN_OUTLEN.
    \param pwd password to derive from; may be NULL only when pwdSz is 0.
    \param pwdSz length of pwd in bytes.
    \param salt salt to derive with; should be unique per password.
    \param saltSz length of salt in bytes, at least WC_ARGON2_MIN_SALT_LEN.
    \param parallel degree of parallelism p (number of lanes).
    \param memCost memory size m in KiB; must be at least 8 * parallel. It is
    rounded down internally to a multiple of 4 * parallel.
    \param timeCost number of passes t over the memory, at least 1.

    _Example_
    \code
    byte key[32];
    byte salt[16];
    const char* password = "correct horse battery staple";

    if (wc_RNG_GenerateBlock(&rng, salt, sizeof(salt)) != 0)
        // handle error

    // Argon2id, p = 4 lanes, m = 64 MiB, t = 3 passes
    if (wc_Argon2(WC_ARGON2_ID, key, sizeof(key),
                  (const byte*)password, (word32)XSTRLEN(password),
                  salt, sizeof(salt), 4, 65536, 3) != 0)
        // handle error
    \endcode

    When built with WOLFSSL_ARGON2_THREADS this fills the segments of a
    slice on one thread per lane, which does not change the derived key. Use
    the context API with wc_Argon2SetThreads() to choose a different number
    of threads.

    \sa wc_Argon2_ex
    \sa wc_Argon2DeriveTag
*/
int wc_Argon2(int type, byte* out, word32 outSz,
              const byte* pwd, word32 pwdSz,
              const byte* salt, word32 saltSz,
              word32 parallel, word32 memCost, word32 timeCost);

/*!
    \ingroup ARGON2

    \brief This function derives a key from a password using Argon2, as
    wc_Argon2() does, additionally accepting the optional secret value K and
    associated data X of RFC 9106, and a heap hint for the memory
    allocation.

    The secret K is a key not stored alongside the hash — often called a
    pepper — which prevents an attacker who has stolen only the hash
    database from mounting an offline guessing attack. The associated data X
    binds the tag to extra context, such as a user name.

    \return 0 on success.
    \return BAD_FUNC_ARG on the same conditions as wc_Argon2(), or if secret
    or ad is NULL while its length is non-zero.
    \return BAD_LENGTH_E if outSz is below WC_ARGON2_MIN_OUTLEN or saltSz is
    below WC_ARGON2_MIN_SALT_LEN.
    \return MEMORY_E if the memory block array could not be allocated.

    \param type variant to use: WC_ARGON2_D, WC_ARGON2_I or WC_ARGON2_ID.
    \param out buffer to hold the derived key (the "tag").
    \param outSz length of out in bytes, at least WC_ARGON2_MIN_OUTLEN.
    \param pwd password to derive from; may be NULL only when pwdSz is 0.
    \param pwdSz length of pwd in bytes.
    \param salt salt to derive with; should be unique per password.
    \param saltSz length of salt in bytes, at least WC_ARGON2_MIN_SALT_LEN.
    \param secret optional secret value K; NULL when unused.
    \param secretSz length of secret in bytes, 0 when unused.
    \param ad optional associated data X; NULL when unused.
    \param adSz length of ad in bytes, 0 when unused.
    \param parallel degree of parallelism p (number of lanes).
    \param memCost memory size m in KiB; must be at least 8 * parallel.
    \param timeCost number of passes t over the memory, at least 1.
    \param heap heap hint passed to XMALLOC; may be NULL.

    _Example_
    \code
    byte key[32];
    byte salt[16];
    byte pepper[16];
    const char* password = "correct horse battery staple";
    const char* user = "alice";

    // Argon2id, p = 4 lanes, m = 64 MiB, t = 3 passes
    if (wc_Argon2_ex(WC_ARGON2_ID, key, sizeof(key),
                     (const byte*)password, (word32)XSTRLEN(password),
                     salt, sizeof(salt),
                     pepper, sizeof(pepper),
                     (const byte*)user, (word32)XSTRLEN(user),
                     4, 65536, 3, NULL) != 0)
        // handle error
    \endcode

    When built with WOLFSSL_ARGON2_THREADS this fills the segments of a
    slice on one thread per lane, which does not change the derived key. Use
    the context API with wc_Argon2SetThreads() to choose a different number
    of threads.

    \sa wc_Argon2
    \sa wc_Argon2DeriveTag
*/
int wc_Argon2_ex(int type, byte* out, word32 outSz,
                 const byte* pwd, word32 pwdSz,
                 const byte* salt, word32 saltSz,
                 const byte* secret, word32 secretSz,
                 const byte* ad, word32 adSz,
                 word32 parallel, word32 memCost, word32 timeCost,
                 void* heap);
