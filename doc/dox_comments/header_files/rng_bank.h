/*!
    \ingroup Random

    \brief Allocate and initialize a bank of n_rngs pre-instantiated WC_RNG
    instances, checked out and back in by consumers (wc_rng_bank_checkout()
    et al.).  The bank is allocated from heap; release with
    wc_rng_bank_free().  Bank-level flags (WC_RNG_BANK_FLAG_*) fix the
    bank's posture at initialization: e.g. _CAN_WAIT admits sleeping,
    _QUIET suppresses seeding-degradation warnings,
    _NO_CHECKOUT_REFCOUNTING suppresses per-checkout refcount traffic for
    container-guaranteed lifetimes, _PREDICTION_RESISTANCE imposes a
    bank-wide fresh-reseed posture on every sleepable lease.

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null or n_rngs is out of range.
    \return MEMORY_E Allocation failed.
    \return RNG_FAILURE_E No instance could be seeded within timeout_secs.

    \param ctx Receives the allocated bank.
    \param n_rngs Number of instances.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* bank-posture flags.
    \param timeout_secs Seeding timeout budget.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.

    _Example_
    \code
    struct wc_rng_bank *bank = NULL;
    if (wc_rng_bank_new(&bank, 4, WC_RNG_BANK_FLAG_CAN_WAIT, 10,
                        NULL, INVALID_DEVID) == 0) {
        // ... checkout/checkin traffic ...
        wc_rng_bank_free(&bank);
    }
    \endcode

    \sa wc_rng_bank_init
    \sa wc_rng_bank_checkout
    \sa wc_rng_bank_free
*/
int wc_rng_bank_new(struct wc_rng_bank **ctx, int n_rngs, word32 flags,
                    int timeout_secs, void *heap, int devId);

/*!
    \ingroup Random

    \brief Initialize a caller-provided bank object.  Semantics of
    wc_rng_bank_new(), without the allocation; release with
    wc_rng_bank_fini().

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null or n_rngs is out of range.
    \return BAD_LENGTH_E n_rngs exceeds the static capacity
    (WC_RNG_BANK_STATIC builds).
    \return RNG_FAILURE_E No instance could be seeded within timeout_secs.

    \param ctx The bank object to initialize.
    \param n_rngs Number of instances.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* bank-posture flags.
    \param timeout_secs Seeding timeout budget.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.

    \sa wc_rng_bank_new
    \sa wc_rng_bank_init_nonce
    \sa wc_rng_bank_fini
*/
int wc_rng_bank_init(struct wc_rng_bank *ctx, int n_rngs, word32 flags,
                     int timeout_secs, void *heap, int devId);

/*!
    \ingroup Random

    \brief The nonce-bearing form of wc_rng_bank_init(): the nonce is used
    as additional instantiation input for each instance.

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null, n_rngs is out of range, or nonce is
    null with nonceSz nonzero.
    \return RNG_FAILURE_E No instance could be seeded within timeout_secs.
    \return BAD_LENGTH_E nonceSz exceeds the supported maximum.
    \return MEMORY_E Allocation failed.
    \return WC_TIMEOUT_E Instance seeding exceeded timeout_secs.

    \param ctx The bank object to initialize.
    \param n_rngs Number of instances.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* bank-posture flags.
    \param timeout_secs Seeding timeout budget.
    \param heap Heap hint for dynamic allocation.
    \param devId Device id, or INVALID_DEVID.
    \param nonce Additional instantiation input.
    \param nonceSz Length of nonce in bytes.

    \sa wc_rng_bank_init
*/
int wc_rng_bank_init_nonce(struct wc_rng_bank *ctx, int n_rngs, word32 flags,
                           int timeout_secs, void *heap, int devId,
                           const byte *nonce, word32 nonceSz);

/*!
    \ingroup Random

    \brief Designate the first instance of the failover pool: checkouts
    without a targeted preference rotate through instances at and above
    first_failover_inst, reserving the lower offsets for targeted
    (affinity or daemon) use.

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null or first_failover_inst is out of range.

    \param ctx The bank to configure.
    \param first_failover_inst The first failover-eligible instance offset.

    \sa wc_rng_bank_checkout
*/
int wc_rng_bank_first_failover_inst_set(struct wc_rng_bank *ctx,
                                        int first_failover_inst);

/*!
    \ingroup Random

    \brief Install affinity handlers: callbacks that pin the caller to an
    execution context (e.g. disable preemption or migration), report its id
    for instance affinity, and unpin.  With handlers installed,
    WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST checkouts prefer the instance
    matching the caller's affinity id, and WC_RNG_BANK_FLAG_AFFINITY_LOCK
    holds the pin across the lease.

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null.
    \return BUSY_E The bank is in service; handlers must be set before use.

    \param ctx The bank to configure.
    \param affinity_lock_cb Pin the caller; may be null.
    \param affinity_get_id_cb Report the caller's affinity id.
    \param affinity_unlock_cb Unpin the caller; may be null.
    \param cb_arg Opaque argument passed to the callbacks.

    \sa wc_rng_bank_checkout
*/
int wc_rng_bank_set_affinity_handlers(struct wc_rng_bank *ctx,
                                      wc_affinity_lock_fn_t affinity_lock_cb,
                                      wc_affinity_get_id_fn_t affinity_get_id_cb,
                                      wc_affinity_unlock_fn_t affinity_unlock_cb,
                                      void *cb_arg);

/*!
    \ingroup Random

    \brief Tear down a bank initialized with wc_rng_bank_init(): once the
    refcount and per-instance lease gates pass, fires any registered free
    hook and frees every instance.  Never waits: a referenced or leased
    bank is refused with BUSY_E, and the caller quiesces its consumers and
    retries.

    \return 0 Success
    \return BAD_FUNC_ARG ctx is null.
    \return BUSY_E The bank is still referenced, or an instance lease is
    outstanding.
    \return BAD_STATE_E The refcount is below its initialization baseline
    (teardown of an uninitialized or corrupted bank).

    \param ctx The bank to tear down.

    \sa wc_rng_bank_init
    \sa wc_rng_bank_free
    \sa wc_rng_bank_register_free_hook
*/
int wc_rng_bank_fini(struct wc_rng_bank *ctx);

/*!
    \ingroup Random

    \brief Tear down and release a bank allocated with wc_rng_bank_new().

    \return 0 Success
    \return BAD_FUNC_ARG ctx or *ctx is null.
    \return BAD_STATE_E The bank is still referenced.

    \param ctx The bank to release; nulled on success.

    \sa wc_rng_bank_new
    \sa wc_rng_bank_fini
*/
int wc_rng_bank_free(struct wc_rng_bank **ctx);

/*!
    \ingroup Random

    \brief Register bank as the process-default bank, retrievable with
    wc_rng_bank_default_checkout().

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.
    \return BAD_STATE_E A default bank is already registered.
    \return BUSY_E Registration is contended; retry.

    \param bank The bank to register.

    \sa wc_rng_bank_default_checkout
    \sa wc_rng_bank_default_clear
*/
int wc_rng_bank_default_set(struct wc_rng_bank *bank);

/*!
    \ingroup Random

    \brief Take a reference on the process-default bank.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.
    \return BAD_STATE_E No default bank is registered.
    \return NO_DEFAULT_FOUND_E No default bank is registered.

    \param bank Receives the default bank.

    \sa wc_rng_bank_default_set
    \sa wc_rng_bank_default_checkin
*/
int wc_rng_bank_default_checkout(struct wc_rng_bank **bank);

/*!
    \ingroup Random

    \brief Release a reference taken with wc_rng_bank_default_checkout().

    \return 0 Success
    \return BAD_FUNC_ARG bank or *bank is null.

    \param bank The reference to release; nulled on success.

    \sa wc_rng_bank_default_checkout
*/
int wc_rng_bank_default_checkin(struct wc_rng_bank **bank);

/*!
    \ingroup Random

    \brief Unregister the process-default bank.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null or is not the registered default.
    \return BUSY_E Unregistration is contended; retry.

    \param bank The bank to unregister.

    \sa wc_rng_bank_default_set
*/
int wc_rng_bank_default_clear(struct wc_rng_bank *bank);

/*!
    \ingroup Random

    \brief Lease an in-service instance from the bank: either the preferred
    (or affinity-matched) instance, or -- with
    WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST -- the first available failover
    instance.  On success the caller owns the instance's lock; access the
    WC_RNG with WC_RNG_BANK_INST_TO_RNG() and return the lease with
    wc_rng_bank_inst_checkin().  WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED consumes
    a ready banked next seed in an immediate source-free credited reseed
    before returning; WC_RNG_BANK_FLAG_PREDICTION_RESISTANCE (per-call,
    requires _CAN_WAIT) freshly credited-reseeds the lease before the
    caller's first draw.

    \details Out-of-service instances: a targeted (non-failover) checkout
    admits them; failover checkouts divert around them.
    WC_RNG_BANK_FLAG_FOR_RECOVERY makes the targeted admission explicit and
    interaction-safe (recovery machinery and patrols): out-of-service
    status is expected, the _CONSUME_NEXT_SEED arm is suppressed (a consume
    would fail on exactly the instances recovery targets), and failover and
    affinity selection are rejected in combination.
    WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED gives the opposite guarantee:
    either a lease on an in-service instance, or an error with no lease --
    never a lease on an out-of-service instance; under _CAN_WAIT an
    out-of-service instance is retried within the timeout budget (allowing
    a patrol to restore it), and the distinguished error for a lap or wait
    that found only out-of-service instances is BAD_STATE_E.

    Entropy-invalidated (quarantined) instances refuse ordinary leases with
    NEEDS_RECOVERY_E, with two admissions.  First, when the quarantined
    instance holds a READY banked next seed, any claimant is admitted and
    the consume-at-checkout reseed runs unconditionally: the invalidation
    purge guarantees READY banked material post-dates the invalidation
    event, so admitting the claimant is completing the recovery.  Second,
    WC_RNG_BANK_FLAG_MAYBE_FOR_RECOVERY admits the caller to a quarantined
    instance with no banked material, transferring the recovery obligation:
    checkout then returns NEEDS_RECOVERY_E with the checkout otherwise
    complete -- *rng_inst set; instance lock, affinity locks, and any
    vector-inhibit state held.  This is the robust-mutex (EOWNERDEAD)
    pattern: an error return with the acquisition complete and persistent,
    because "this resource needs consistency recovery" is only safely
    reportable to a caller that already holds it.  The caller must either
    recover the instance (a credited reseed, e.g. wc_RNG_DRBG_Reseed_Now(),
    clears the quarantine) or check it back in.  Ordinary consumers that
    cannot complete a recovery must not pass this flag.

    \return 0 Success; *rng_inst holds the lease.
    \return BAD_FUNC_ARG bank or rng_inst is null, or the flags are
    contradictory.
    \return NEEDS_RECOVERY_E Quarantined: refused without a lease
    (ordinary checkout), or lease held with recovery owed
    (_MAYBE_FOR_RECOVERY; see \details).
    \return BAD_STATE_E (_ERROR_ON_RNG_FAILED) only out-of-service
    instances were found.
    \return WC_TIMEOUT_E The wait budget expired.
    \return RNG_FAILURE_E No serviceable instance.
    \return BAD_INDEX_E preferred_inst_offset is out of range.
    \return BUSY_E The selected instance is contended (without _CAN_WAIT).

    \param bank The bank to lease from.
    \param rng_inst Receives the leased instance.
    \param preferred_inst_offset The preferred instance, or 0.
    \param timeout_secs Wait budget (with _CAN_WAIT).
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* per-call flags.

    _Example_
    \code
    struct wc_rng_bank_inst *inst = NULL;
    if (wc_rng_bank_checkout(bank, &inst, 0, 10,
                             WC_RNG_BANK_FLAG_CAN_WAIT |
                             WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST) == 0) {
        ret = wc_RNG_GenerateBlock(WC_RNG_BANK_INST_TO_RNG(inst),
                                   out, sizeof(out));
        wc_rng_bank_inst_checkin(&inst);
    }
    \endcode

    \sa wc_rng_bank_inst_checkin
    \sa wc_rng_bank_recover_inst
    \sa wc_rng_bank_spawn
*/
int wc_rng_bank_checkout(struct wc_rng_bank *bank,
                         struct wc_rng_bank_inst **rng_inst,
                         int preferred_inst_offset, int timeout_secs,
                         word32 flags);

/*!
    \ingroup Random

    \brief Return a lease through the bank object, validating that rng_inst
    belongs to bank.  Prefer wc_rng_bank_inst_checkin() when only the
    instance pointer is at hand.

    \return 0 Success
    \return BAD_FUNC_ARG bank or rng_inst is null, or the instance does not
    belong to bank.
    \return OBJECT_NOT_LOCKED_E The instance's lease is not held (e.g. a
    stale duplicate check-in).
    \return NEEDS_RECOVERY_E Checked in successfully; informational
    notice that the instance is entropy-invalidated.

    \param bank The bank the instance belongs to.
    \param rng_inst The lease to return; nulled on success.

    \sa wc_rng_bank_inst_checkin
    \sa wc_rng_bank_checkout
*/
int wc_rng_bank_checkin(struct wc_rng_bank *bank,
                        struct wc_rng_bank_inst **rng_inst);

/*!
    \ingroup Random

    \brief Return a lease by instance pointer alone.

    \return 0 Success
    \return BAD_FUNC_ARG rng_inst or *rng_inst is null.
    \return OBJECT_NOT_LOCKED_E The instance's lease is not held.
    \return NEEDS_RECOVERY_E Checked in successfully; informational
    notice that the instance is entropy-invalidated.

    \param rng_inst The lease to return; nulled on success.

    \sa wc_rng_bank_checkout
    \sa wc_rng_bank_checkin
*/
int wc_rng_bank_inst_checkin(struct wc_rng_bank_inst **rng_inst);

/*!
    \ingroup Random

    \brief Report the instance's offset within its bank.

    \return n The instance offset, non-negative.
    \return BAD_FUNC_ARG rng_inst is null.

    \param rng_inst The instance to interrogate.

    \sa wc_rng_bank_checkout
*/
int wc_rng_bank_get_inst_id(struct wc_rng_bank_inst *rng_inst);

/*!
    \ingroup Random

    \brief Bank next-seed material for the instance at inst_offset --
    wc_RNG_DRBG_NextSeedGenerate() through the bank, without taking the
    instance lock; the daemon-side serialization word arbitrates against
    concurrent whole-instance reinitialization.

    \return 0 Bytes were banked.
    \return ALREADY_E The instance's bank is ready or being consumed.
    \return NOT_READY_E The health test could not run; simply retry.
    \return BAD_FUNC_ARG bank is null, inst_offset is out of range, or n
    is 0.

    \param bank The bank.
    \param inst_offset The instance to bank for.
    \param n Maximum bytes to bank this call.

    \sa wc_RNG_DRBG_NextSeedGenerate
    \sa wc_rng_bank_next_seed_generate_rbgc
    \details The daemon-side serialization word (not the instance lock)
    excludes a concurrent wc_rng_bank_inst_reinit() from freeing the DRBG
    out from under the gather; lease-holders never consult it, since
    instance-lock exclusion already covers every lease-holder interaction.
    The caller must hold a bank reference (e.g. per the daemon association)
    for the duration of the call.  Return taxonomy for a banking rotation:
    BUSY_E, the gate is held by a reinit -- skip this turn; ALREADY_E,
    sleep until the bank is consumed; MISSING_RNG_E, the instance has no
    DRBG (RDRAND et al.) and can be retired from the rotation permanently;
    other errors are transient gather or health-test failures -- skip the
    turn, and alarm if persistent.

*/
int wc_rng_bank_next_seed_generate(struct wc_rng_bank *bank, int inst_offset,
                                   word32 n);

/*!
    \ingroup Random

    \brief The chain-sourced form of wc_rng_bank_next_seed_generate(): the
    banked material is drawn from root's generate function and tagged with
    its provenance.

    \return 0 Bytes were banked.
    \return ALREADY_E The instance's bank is ready or being consumed.
    \return NOT_READY_E The health test could not run; simply retry.
    \return BAD_FUNC_ARG bank or root is null, inst_offset is out of range,
    or n is 0.

    \param bank The bank.
    \param inst_offset The instance to bank for.
    \param n Maximum bytes to bank this call.
    \param root The chain parent to draw material from.

    \sa wc_rng_bank_next_seed_generate
    \sa wc_RNG_DRBG_NextSeedGenerate_RBGC
*/
int wc_rng_bank_next_seed_generate_rbgc(struct wc_rng_bank *bank,
                                        int inst_offset, word32 n,
                                        WC_RNG *root);

/*!
    \ingroup Random

    \brief Free and reinstantiate a leased instance in place.  The caller
    must hold the lease; the daemon-side serialization word excludes
    concurrent lockless banking during the cycle.

    \return 0 Success
    \return BAD_FUNC_ARG bank or rng_inst is null.
    \return RNG_FAILURE_E Reinstantiation could not be seeded within
    timeout_secs.
    \return BUSY_E The whole-instance-operation gate is held (daemon banking in
    progress); retry.

    \param bank The bank the instance belongs to.
    \param rng_inst The leased instance to reinitialize.
    \param timeout_secs Seeding timeout budget.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    \sa wc_rng_bank_recover_inst
*/
int wc_rng_bank_inst_reinit(struct wc_rng_bank *bank,
                            struct wc_rng_bank_inst *rng_inst,
                            int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief Patrol helper: check out the instance at inst_offset with
    WC_RNG_BANK_FLAG_FOR_RECOVERY, recover it iff it needs recovery, and
    check it back in.  Two recovery arms: an out-of-service instance
    (wc_RNG_GetStatus() != WC_DRBG_OK) is reinitialized in place; an
    in-service but entropy-invalidated (quarantined) instance takes one
    credited reseed, which clears the quarantine while preserving instance
    identity.  A healthy instance is a success no-op, so callers can
    invoke this unconditionally on state observed locklessly.

    \return 0 Success (recovered, or nothing to recover).
    \return BAD_FUNC_ARG bank is null, inst_offset is out of range, or the
    flags are contradictory.
    \return RNG_FAILURE_E Recovery could not be seeded within timeout_secs.
    \return BUSY_E The instance lock or whole-instance-operation gate is
    contended; retry on a later patrol turn.

    \param bank The bank.
    \param inst_offset The instance to patrol.
    \param timeout_secs Seeding timeout budget.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    _Example_
    \code
    // after a VM duplication event has invalidated the bank:
    for (i = 0; i < n_rngs; i++)
        (void)wc_rng_bank_recover_inst(bank, i, 10,
                                       WC_RNG_BANK_FLAG_CAN_WAIT);
    \endcode

    \sa wc_rng_bank_invalidate_entropy
    \sa wc_rng_bank_checkout
    \details A stale lockless status observation costs one harmless round
    trip.  BUSY_E reports contention on the instance lock or the
    whole-instance-operation gate: retry on a later patrol turn.  flags may
    include WC_RNG_BANK_FLAG_CAN_WAIT and WC_RNG_BANK_FLAG_AFFINITY_LOCK,
    which are passed through.

*/
int wc_rng_bank_recover_inst(struct wc_rng_bank *bank, int inst_offset,
                             int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief Spawn an SP 800-90C chain RNG from a bank instance: check out a
    parent instance (honoring the usual selection flags), instantiate
    child_rng as its chain child (wc_InitRngNonceRBGC()), and check the
    parent back in.  The child's lifetime is thereafter decoupled from the
    parent and its bank; release it with wc_FreeRng() (or wc_rng_free() for
    the heap form, wc_rng_bank_spawn_new()).  The child's RBGC stratum is
    one plus the parent's stratum at instantiation.

    \details A recommended nonce, when available, is a racy read of a
    high-resolution timer (e.g. Linux kernel random_get_entropy()).
    WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED composes: a ready banked seed is
    redeemed on the parent before the spawn draw.
    WC_RNG_BANK_FLAG_STIR and WC_RNG_BANK_FLAG_FOR_RECOVERY are
    rejected.  WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED is implied: the parent
    is guaranteed in-service, or an error is returned with no lease and no
    child.

    \return 0 Success
    \return BAD_FUNC_ARG bank or child_rng is null, or the flags are
    contradictory (uncredited or recovery seeding contradict a spawn).
    \return RNG_FAILURE_E No serviceable parent within the timeout budget.

    \param bank The bank to spawn from.
    \param child_rng The caller-provided WC_RNG to instantiate.
    \param nonce Optional additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param preferred_inst_offset The preferred parent instance, or 0.
    \param timeout_secs Wait budget (with _CAN_WAIT).
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* per-call flags.

    \sa wc_rng_bank_spawn_new
    \sa wc_InitRngNonceRBGC
*/
int wc_rng_bank_spawn(struct wc_rng_bank *bank, WC_RNG *child_rng,
                      byte *nonce, word32 nonceSz, int preferred_inst_offset,
                      int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief The allocating form of wc_rng_bank_spawn(): the child is
    allocated from the bank's heap and returned through child_rng; release
    with wc_rng_free().

    \return 0 Success
    \return BAD_FUNC_ARG bank or child_rng is null.
    \return MEMORY_E Allocation failed.
    \return RNG_FAILURE_E No serviceable parent within the timeout budget.

    \param bank The bank to spawn from.
    \param child_rng Receives the allocated, instantiated WC_RNG.
    \param nonce Optional additional instantiation input.
    \param nonceSz Length of nonce in bytes.
    \param preferred_inst_offset The preferred parent instance, or 0.
    \param timeout_secs Wait budget (with _CAN_WAIT).
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* per-call flags.

    \sa wc_rng_bank_spawn
*/
int wc_rng_bank_spawn_new(struct wc_rng_bank *bank, WC_RNG **child_rng,
                          byte *nonce, word32 nonceSz,
                          int preferred_inst_offset, int timeout_secs,
                          word32 flags);

/*!
    \ingroup Random

    \brief Reseed every instance with caller-supplied seed material.
    WC_RNG_BANK_FLAG_STIR mixes the material in without
    crediting it.

    \return 0 Success
    \return BAD_FUNC_ARG bank or seed is null.
    \return RNG_FAILURE_E An instance could not be reseeded within
    timeout_secs.

    \param bank The bank to seed.
    \param seed Seed material.
    \param seedSz Length of seed in bytes.
    \param timeout_secs Wait budget per instance.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    \sa wc_rng_bank_seed_range
    \sa wc_rng_bank_reseed
*/
int wc_rng_bank_seed(struct wc_rng_bank *bank, const byte* seed,
                     word32 seedSz, int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief The range form of wc_rng_bank_seed(): seed instances first_inst
    through last_inst inclusive.

    \return 0 Success
    \return BAD_FUNC_ARG bank or seed is null, or the range is out of
    bounds.
    \return RNG_FAILURE_E An instance could not be reseeded within
    timeout_secs.
    \return BAD_INDEX_E The instance range is invalid.
    \return BAD_STATE_E The bank is not initialized.
    \return NO_DEFAULT_FOUND_E bank is null and no default bank is registered.

    \param bank The bank to seed.
    \param first_inst The first instance offset.
    \param last_inst The last instance offset.
    \param seed Seed material.
    \param seedSz Length of seed in bytes.
    \param timeout_secs Wait budget per instance.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    \sa wc_rng_bank_seed
*/
int wc_rng_bank_seed_range(struct wc_rng_bank *bank, int first_inst,
                           int last_inst, const byte* seed, word32 seedSz,
                           int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief Reseed every instance from the module's seed source.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.
    \return RNG_FAILURE_E An instance could not be reseeded within
    timeout_secs.

    \param bank The bank to reseed.
    \param timeout_secs Wait budget per instance.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    \sa wc_rng_bank_reseed_range
    \sa wc_rng_bank_seed
*/
int wc_rng_bank_reseed(struct wc_rng_bank *bank, int timeout_secs,
                       word32 flags);

/*!
    \ingroup Random

    \brief The range form of wc_rng_bank_reseed().

    \return 0 Success
    \return BAD_FUNC_ARG bank is null, or the range is out of bounds.
    \return RNG_FAILURE_E An instance could not be reseeded within
    timeout_secs.
    \return BAD_INDEX_E The instance range is invalid.
    \return BAD_STATE_E The bank is not initialized.
    \return WC_TIMEOUT_E The walk exceeded timeout_secs.

    \param bank The bank to reseed.
    \param first_inst The first instance offset.
    \param last_inst The last instance offset.
    \param timeout_secs Wait budget per instance.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    \sa wc_rng_bank_reseed
*/
int wc_rng_bank_reseed_range(struct wc_rng_bank *bank, int first_inst,
                             int last_inst, int timeout_secs, word32 flags);

/*!
    \ingroup Random

    \brief Set the entropy-invalidated latch on every instance (see
    wc_RNG_invalidate_entropy()): cached entropy products are discarded,
    and each instance is forced through a credited reseed before its next
    generate serves output.  Lock-free and constant-time per instance; safe
    from a state-invalidation event context (VM fork/resume).

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.
    \return BAD_STATE_E The bank is not initialized.

    \param bank The bank to invalidate.
    \param flags Bitwise-or of WC_RNG_BANK_FLAG_* flags.

    _Example_
    \code
    // VM-resume notifier
    (void)wc_rng_bank_invalidate_entropy(bank, WC_RNG_BANK_FLAG_NONE);
    // instances recover on next checkout, or by patrol:
    //   wc_rng_bank_recover_inst()
    \endcode

    \sa wc_RNG_invalidate_entropy
    \sa wc_rng_bank_recover_inst
    \details Also purges each instance's banked next-seed apertures: the
    purge is the provenance guarantee that a READY bank observed after the
    event holds post-event material (see wc_rng_bank_checkout()'s recovery
    admissions).  Walks every instance even on error, returning the first
    error.  flags must be 0.

*/
int wc_rng_bank_invalidate_entropy(struct wc_rng_bank *bank, word32 flags);

/*!
    \ingroup Random

    \brief Reserve the bank's daemon slot with a caller-chosen nonzero
    magic word, admitting exactly one scheduling daemon per bank.  The
    lifecycle is strictly ordered: _reserve, then _register, then
    _unregister, then _release.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null or magic is the free sentinel.
    \return BUSY_E The slot is claimed, or claiming is contended.

    \param bank The bank to claim.
    \param magic The daemon's magic word.

    \sa wc_rng_bank_daemon_register
    \sa wc_rng_bank_daemon_release
*/
int wc_rng_bank_daemon_reserve(struct wc_rng_bank *bank,
                               WC_ATOMIC_UINT_ARG magic);

/*!
    \ingroup Random

    \brief Register the daemon object in a slot reserved with the same
    magic word.

    \return 0 Success
    \return BAD_FUNC_ARG bank or daemon is null.
    \return ALREADY_E The slot is already in the requested state.
    \return WRONG_TYPE_OBJECT_E magic does not match the claim.
    \return BUSY_E The slot transition is contended; retry.

    \param bank The bank.
    \param daemon The daemon object to register.
    \param magic The daemon's magic word.

    \sa wc_rng_bank_daemon_reserve
    \sa wc_rng_bank_daemon_unregister
*/
int wc_rng_bank_daemon_register(struct wc_rng_bank *bank, void *daemon,
                                WC_ATOMIC_UINT_ARG magic);

/*!
    \ingroup Random

    \brief Unregister the daemon object, returning it through daemon.

    \return 0 Success
    \return BAD_FUNC_ARG bank or daemon is null.
    \return ALREADY_E The slot is already in the requested state.
    \return WRONG_TYPE_OBJECT_E magic does not match the claim.
    \return BUSY_E The slot transition is contended; retry.

    \param bank The bank.
    \param daemon Receives the registered daemon object.
    \param magic The daemon's magic word.

    \sa wc_rng_bank_daemon_register
    \sa wc_rng_bank_daemon_release
*/
int wc_rng_bank_daemon_unregister(struct wc_rng_bank *bank, void **daemon,
                                  WC_ATOMIC_UINT_ARG magic);

/*!
    \ingroup Random

    \brief Release the daemon slot claimed with magic, returning it to the
    free sentinel.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.
    \return ALREADY_E The slot is already in the requested state.
    \return WRONG_TYPE_OBJECT_E magic does not match the claim.
    \return BUSY_E The slot transition is contended; retry.

    \param bank The bank.
    \param magic The daemon's magic word.

    \sa wc_rng_bank_daemon_reserve
*/
int wc_rng_bank_daemon_release(struct wc_rng_bank *bank,
                               WC_ATOMIC_UINT_ARG magic);

/*!
    \ingroup Random

    \brief Bind the daemon's RBG-chain root to the bank, for chain-sourced
    banking (wc_rng_bank_next_seed_generate_rbgc()) and harvest deposit
    (wc_RNG_DRBG_NextStirStore() on the root).

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.

    \param bank The bank.
    \param daemon_root The daemon's root WC_RNG, or null to unbind.

    \sa wc_rng_bank_daemon_root_get
    \sa wc_rng_bank_daemon_reserve
    \details The caller (the daemon) owns the ordering: bind after
    successful root initialization, unbind before root teardown.

*/
int wc_rng_bank_daemon_root_set(struct wc_rng_bank *bank,
                                WC_RNG *daemon_root);

/*!
    \ingroup Random

    \brief Report the bank's bound daemon root.

    \return The daemon root, or null when none is bound or bank is null.

    \param bank The bank to interrogate.

    \sa wc_rng_bank_daemon_root_set
*/
WC_RNG *wc_rng_bank_daemon_root_get(struct wc_rng_bank *bank);

/*!
    \ingroup Random

    \brief Register a callback fired by wc_rng_bank_fini() once its
    refcount and leak gates pass -- i.e. once teardown is committed -- for
    external registries that must drop their reference when the bank dies.
    One-shot: the hook is cleared before firing.  A null free_hook
    unregisters.

    \return 0 Success
    \return BAD_FUNC_ARG bank is null.

    \param bank The bank to hook.
    \param free_hook The callback.
    \param arg Opaque argument passed to the callback.

    \sa wc_rng_bank_fini
    \sa wc_RNG_register_free_hook
*/
int wc_rng_bank_register_free_hook(struct wc_rng_bank *bank,
                                   wc_rng_bank_free_hook_cb_t free_hook,
                                   void *arg);

/*!
    \ingroup Random

    \brief Initialize rng as a bank reference: a WC_RNG with no DRBG of its
    own, whose wc_RNG_GenerateBlock() transparently checks an instance out
    of bank, generates, and checks it back in.  Release with wc_FreeRng().

    \return 0 Success
    \return BAD_FUNC_ARG bank or rng is null.

    \param bank The bank to reference.
    \param rng The WC_RNG to initialize as a reference.

    _Example_
    \code
    WC_RNG rng;
    if (wc_InitRng_BankRef(bank, &rng) == 0) {
        // rng now serves through the bank
        ret = wc_RNG_GenerateBlock(&rng, out, sizeof(out));
        wc_FreeRng(&rng);
    }
    \endcode

    \sa wc_BankRef_Release
    \sa wc_rng_new_bankref
*/
int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng);

/*!
    \ingroup Random

    \brief Release a bank reference.  wc_FreeRng() calls this
    automatically for bank references; direct use is rarely needed.

    \return 0 Success
    \return BAD_FUNC_ARG rng is null or is not a bank reference.

    \param rng The bank reference to release.

    \sa wc_InitRng_BankRef
*/
int wc_BankRef_Release(WC_RNG *rng);

/*!
    \ingroup Random

    \brief The allocating form of wc_InitRng_BankRef(): the reference is
    allocated from the bank's heap; release with wc_rng_free().

    \return 0 Success
    \return BAD_FUNC_ARG bank or rng is null.
    \return MEMORY_E Allocation failed.

    \param bank The bank to reference.
    \param rng Receives the allocated bank reference.

    \sa wc_InitRng_BankRef
*/
int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng);

/*!
    \ingroup Random

    \brief Snapshot the RNG debug counters (WC_RNG_DEBUG_STATS) with
    bank-level context.

    \return 0 Success
    \return BAD_FUNC_ARG s is null.

    \param s Receives the snapshot.
    \param bank Optional bank for context, or null.

    \sa wc_rng_debug_stats_snap
*/
int wc_rng_bank_debug_stats_snap(struct wc_rng_debug_stats_snapshot *s,
                                 struct wc_rng_bank *bank);
